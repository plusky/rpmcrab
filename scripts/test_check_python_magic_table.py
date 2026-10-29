#!/usr/bin/env python3
"""Unit tests for check-python-magic-table.py."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "check_python_magic_table",
    Path(__file__).with_name("check-python-magic-table.py"),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

BOOTSTRAP_312 = (
    "# some header\n"
    "MAGIC_NUMBER = (3531).to_bytes(2, 'little') + b'\\r\\n'\n"
)
HEADER_314 = (
    "/* history */\n"
    "#define PYC_MAGIC_NUMBER 3627\n"
)


def fake_fetch(mapping):
    """A fetch callable serving mapping[url], else BranchMissing."""

    def fetch(url):
        if url in mapping:
            return mapping[url]
        raise _mod.BranchMissing(url)

    return fetch


def bootstrap_url(version):
    return (
        f"{_mod.BASE_URL}/{version}/Lib/importlib/_bootstrap_external.py"
    )


def header_url(version):
    return (
        f"{_mod.BASE_URL}/{version}/Include/internal/pycore_magic_number.h"
    )


class DeriveMagicTest(unittest.TestCase):
    def test_to_bytes_spelling(self):
        fetch = fake_fetch({bootstrap_url("3.12"): BOOTSTRAP_312})
        self.assertEqual(_mod.derive_magic("3.12", fetch), 3531)

    def test_pyc_define_spelling(self):
        fetch = fake_fetch(
            {
                bootstrap_url("3.14"): "MAGIC_NUMBER = _imp.pyc_magic_number_token.to_bytes(4, 'little')\n",
                header_url("3.14"): HEADER_314,
            }
        )
        self.assertEqual(_mod.derive_magic("3.14", fetch), 3627)

    def test_missing_branch_propagates(self):
        with self.assertRaises(_mod.BranchMissing):
            _mod.derive_magic("3.99", fake_fetch({}))

    def test_unrecognised_layout_is_fetch_error(self):
        fetch = fake_fetch(
            {
                bootstrap_url("3.20"): "nothing magic here\n",
                header_url("3.20"): "nothing magic here either\n",
            }
        )
        with self.assertRaises(_mod.FetchError):
            _mod.derive_magic("3.20", fetch)


class ProbeVersionsTest(unittest.TestCase):
    def test_stops_at_first_missing_branch(self):
        fetch = fake_fetch(
            {
                bootstrap_url("3.8"): "MAGIC_NUMBER = (3413).to_bytes(2, 'little') + b'\\r\\n'\n",
                bootstrap_url("3.9"): "MAGIC_NUMBER = (3425).to_bytes(2, 'little') + b'\\r\\n'\n",
            }
        )
        probed = _mod.probe_versions(fetch, from_minor=8)
        self.assertEqual(probed, [("3.8", 3413), ("3.9", 3425)])

    def test_cap_bounds_the_sweep(self):
        fetch = fake_fetch(
            {
                bootstrap_url(f"3.{minor}"): (
                    f"MAGIC_NUMBER = ({3400 + minor}).to_bytes(2, 'little') + b'\\r\\n'\n"
                )
                for minor in range(8, 80)
            }
        )
        probed = _mod.probe_versions(fetch, from_minor=8, cap_minor=10)
        self.assertEqual([v for v, _m in probed], ["3.8", "3.9", "3.10"])


class CheckTest(unittest.TestCase):
    def test_missing_version_reported(self):
        findings = _mod.check({"3.8": [3413]}, [("3.8", 3413), ("3.9", 3425)])
        self.assertEqual(
            findings,
            [("3.9", "MISSING", "no table entry for this version")],
        )

    def test_stale_value_reported(self):
        findings = _mod.check({"3.12": [3500]}, [("3.12", 3531)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][1], "STALE-VALUE")
        self.assertIn("3531", findings[0][2])

    def test_head_value_among_several_passes(self):
        # A version's list may hold several magics; only the
        # branch-head value is required to be present.
        findings = _mod.check({"3.7": [3390, 3391, 3394]}, [("3.7", 3394)])
        self.assertEqual(findings, [])

    def test_unprobed_entries_never_flagged(self):
        # The table is cumulative: old entries without a branch are
        # carried, never reported for removal.
        findings = _mod.check(
            {"2.7": [62211], "3.8": [3413]}, [("3.8", 3413)]
        )
        self.assertEqual(findings, [])

    def test_clean_check(self):
        findings = _mod.check(
            {"3.8": [3413], "3.9": [3425]},
            [("3.8", 3413), ("3.9", 3425)],
        )
        self.assertEqual(findings, [])


class LoadTableTest(unittest.TestCase):
    def test_loads_version_arrays(self):
        text = (
            'as_of = "2026-10-29"\n'
            '\n'
            '[[version]]\n'
            'version = "3.6"\n'
            'magics = [3379]\n'
            '\n'
            '[[version]]\n'
            'version = "3.7"\n'
            'magics = [3390, 3394]\n'
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".toml", delete=False
        ) as fh:
            fh.write(text)
            path = fh.name
        table = _mod.load_table(path)
        self.assertEqual(table, {"3.6": [3379], "3.7": [3390, 3394]})


if __name__ == "__main__":
    unittest.main()
