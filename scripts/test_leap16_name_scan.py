#!/usr/bin/env python3
"""Unit tests for _scan_binary_names in generate-distro-configs.py.

Simulates zstd -dc pipe reads with small chunks so every <name> tag,
including ones much longer than the old 512-byte re-scan overlap, is
forced to straddle chunk boundaries.
"""

import importlib.util
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "generate_distro_configs",
    Path(__file__).with_name("generate-distro-configs.py"),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


class ShortReadPipe:
    """File-like object that returns at most max_chunk bytes per read."""

    def __init__(self, data, max_chunk):
        self._data = data
        self._pos = 0
        self._max_chunk = max_chunk

    def read(self, n):
        if self._pos >= len(self._data):
            return b""
        end = min(len(self._data), self._pos + min(n, self._max_chunk))
        out = self._data[self._pos : end]
        self._pos = end
        return out


def build_stream(names):
    xml = b"<metadata>" + b"".join(
        b"<package><name>" + n + b"</name></package>" for n in names
    )
    return xml + b"</metadata>"


class ScanBinaryNamesTest(unittest.TestCase):
    def run_scan(self, names, max_chunk):
        stream = build_stream(names)
        pipe = ShortReadPipe(stream, max_chunk)
        return _mod._scan_binary_names(pipe)

    def test_names_across_chunk_boundaries(self):
        names = [
            b"aaa",
            b"b" * 700,  # longer than the old 512-byte overlap
            b"c" * 70000,  # longer than one 64 KiB read
            b"\xff\xfe-invalid-utf8",  # decoded with errors="replace"
            b"zzz",
        ]
        for max_chunk in (1, 7, 63, 511, 512, 513, 70000):
            with self.subTest(max_chunk=max_chunk):
                got = self.run_scan(names, max_chunk)
                want = {n.decode("utf-8", "replace") for n in names}
                self.assertEqual(got, want)

    def test_split_opening_tag(self):
        # Chunk boundary falls inside the opening <name> tag itself.
        names = [b"alpha", b"beta", b"gamma"]
        stream = build_stream(names)
        idx = stream.index(b"<name>beta") + 3  # split after "<na"

        class SegmentedPipe:
            def __init__(self, segments):
                self._segments = list(segments)

            def read(self, n):
                if not self._segments:
                    return b""
                return self._segments.pop(0)[:n]

        # One-byte reads after the split force every tag to straddle.
        rest = stream[idx:]
        segments = [stream[:idx]] + [rest[i : i + 1] for i in range(len(rest))]
        got = _mod._scan_binary_names(SegmentedPipe(segments))
        self.assertEqual(got, {n.decode() for n in names})


if __name__ == "__main__":
    unittest.main()
