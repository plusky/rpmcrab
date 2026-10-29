#!/usr/bin/env python3
"""Unit tests for check-python-module-stems.py."""

import gzip
import importlib.util
import io
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "check_python_module_stems",
    Path(__file__).with_name("check-python-module-stems.py"),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

PRIMARY = """<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="4">
<package type="rpm">
<name>python313-gobject</name><arch>noarch</arch>
<version epoch="0" ver="3.50.0" rel="1.1"/>
<format>
<rpm:provides>
<rpm:entry name="python3.13dist(gobject)"/>
<rpm:entry name="python313-gobject" flags="EQ" ver="3.50.0"/>
</rpm:provides>
<rpm:requires>
<rpm:entry name="python313-base" flags="GE" ver="3.13"/>
</rpm:requires>
</format>
</package>
<package type="rpm">
<name>cinnamon</name><arch>x86_64</arch>
<version epoch="0" ver="6.0.0" rel="1.1"/>
<format>
<rpm:provides>
<rpm:entry name="python3.13dist(cinnamon)"/>
</rpm:provides>
<rpm:requires>
<rpm:entry name="python313-gobject" flags="GE" ver="1.0"/>
<rpm:entry name="python313"/>
</rpm:requires>
<rpm:conflicts>
<rpm:entry name="python313-ghoststem"/>
</rpm:conflicts>
<rpm:obsoletes>
<rpm:entry name="python313-ghoststem2"/>
</rpm:obsoletes>
</format>
</package>
<package type="rpm">
<name>python313-dateutil</name><arch>noarch</arch>
<version epoch="0" ver="2.9.0" rel="1.1"/>
<format>
<rpm:provides>
<rpm:entry name="python3.13dist(dateutil)"/>
</rpm:provides>
</format>
</package>
<package type="rpm">
<name>unrelated</name><arch>x86_64</arch>
<version epoch="0" ver="1.0" rel="1.1"/>
<format>
<rpm:provides>
<rpm:entry name="unrelated"/>
</rpm:provides>
<rpm:requires>
<rpm:entry name="libc.so.6()(64bit)"/>
</rpm:requires>
</format>
</package>
</metadata>
"""


def write_fixture(directory, gzipped=False, text=PRIMARY):
    path = Path(directory) / ("primary.xml.gz" if gzipped else "primary.xml")
    if gzipped:
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write(text)
    else:
        path.write_text(text, encoding="utf-8")
    return str(path)


# Same shape as PRIMARY, but the gobject stem is entirely absent: the
# pygobject package still provides its own dist(), so the module side
# stays live while the stem side dies.
PRIMARY_STEM_DEAD = """<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1">
<package type="rpm">
<name>python313-pygobject</name><arch>noarch</arch>
<version epoch="0" ver="3.50.0" rel="1.1"/>
<format>
<rpm:provides>
<rpm:entry name="python3.13dist(pygobject)"/>
</rpm:provides>
</format>
</package>
</metadata>
"""


class RepodataParsingTest(unittest.TestCase):
    def test_capability_strings(self):
        with tempfile.TemporaryDirectory() as tmp:
            caps = set(_mod.repodata_capabilities(write_fixture(tmp)))
        # dist() provides (module side) and dash requires (stem side).
        self.assertIn("python3.13dist(gobject)", caps)
        self.assertIn("python3.13dist(cinnamon)", caps)
        self.assertIn("python3.13dist(dateutil)", caps)
        # Version reconstruction keeps the name/op/ver shape.
        self.assertIn("python313-gobject = 3.50.0", caps)
        self.assertIn("python313-gobject >= 1.0", caps)
        self.assertIn("python313-base >= 3.13", caps)
        # Unversioned requires stay bare.
        self.assertIn("python313", caps)
        # Conflicts and obsoletes are excluded: only provides +
        # requires are read.
        self.assertNotIn("python313-ghoststem", caps)
        self.assertNotIn("python313-ghoststem2", caps)

    def test_gzip_fixture_parses_identically(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = set(_mod.repodata_capabilities(write_fixture(tmp)))
            gzipped = set(_mod.repodata_capabilities(write_fixture(tmp, True)))
        self.assertEqual(plain, gzipped)
        self.assertTrue(plain)

    @unittest.skipUnless(shutil.which("zstd"), "zstd binary required")
    def test_zst_fixture_parses_identically(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = set(_mod.repodata_capabilities(write_fixture(tmp)))
            zst_path = Path(tmp) / "primary.xml.zst"
            subprocess.run(["zstd", "-q", "-f", write_fixture(tmp),
                            "-o", str(zst_path)], check=True)
            zstded = set(_mod.repodata_capabilities(str(zst_path)))
        self.assertEqual(plain, zstded)
        self.assertTrue(plain)


class VerdictTest(unittest.TestCase):
    def pool(self, text=PRIMARY):
        with tempfile.TemporaryDirectory() as tmp:
            caps = _mod.repodata_capabilities(write_fixture(tmp, text=text))
            return _mod.pool_from_lines(caps)

    def run_report(self, entries, text=PRIMARY):
        provided, joined = self.pool(text)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = _mod.report(entries, provided, joined, "test fixture")
        return rc, buf.getvalue()

    def test_live_entry_returns_zero(self):
        rc, out = self.run_report([("gobject", ["gobject"])])
        self.assertEqual(rc, 0)
        self.assertIn("OK     gobject -> ['gobject']", out)

    def test_dead_stem_reports_stale(self):
        # pygobject's dist() is provided, but the gobject stem has
        # neither its own dist() nor any dash-require carrier.
        rc, out = self.run_report(
            [("pygobject", ["gobject"])], text=PRIMARY_STEM_DEAD)
        self.assertEqual(rc, 1)
        self.assertIn("STALE  pygobject -> ['gobject']", out)
        self.assertIn("stem(s) ['gobject']", out)
        self.assertNotIn("module (no dist() reference", out)

    def test_dead_module_reports_stale(self):
        # Nothing references the vanished module at all.
        rc, out = self.run_report([("vanished", ["vanished"])])
        self.assertEqual(rc, 1)
        self.assertIn("STALE  vanished -> ['vanished']", out)
        self.assertIn("module (no dist() reference in repodata)", out)

    def test_mixed_entries_report_counts(self):
        rc, out = self.run_report([
            ("gobject", ["gobject"]),
            ("vanished", ["vanished"]),
        ])
        self.assertEqual(rc, 1)
        self.assertIn("1/2 entries live (test fixture)", out)


if __name__ == "__main__":
    unittest.main()
