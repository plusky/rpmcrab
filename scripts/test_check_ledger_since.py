#!/usr/bin/env python3
"""Unit tests for check-ledger-since.py."""

import importlib.util
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "check_ledger_since",
    Path(__file__).with_name("check-ledger-since.py"),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

RELEASED = (0, 4, 0)


def entry(check, since, reason="r", kind="behaviour"):
    return {
        "case": "global",
        "check": check,
        "kind": kind,
        "reason": reason,
        "since": since,
    }


class LatestReleaseTest(unittest.TestCase):
    def test_picks_highest_bare_tag(self):
        tags = ["v0.2.1", "v0.10.0", "v0.4.0", "v0.11.0-rc1", "latest", "0.12.0"]
        self.assertEqual(_mod.latest_release(tags), (0, 10, 0))

    def test_no_tags(self):
        self.assertIsNone(_mod.latest_release([]))


class ViolationsTest(unittest.TestCase):
    def check(self, base, head):
        return _mod.violations(base, head, RELEASED)

    def test_new_entry_claiming_the_shipped_version_fails(self):
        bad = entry("no-binary", "0.4.0")
        self.assertEqual(self.check([], [bad]), [bad])

    def test_new_entry_claiming_an_older_version_fails(self):
        bad = entry("no-binary", "0.3.1")
        self.assertEqual(self.check([], [bad]), [bad])

    def test_new_entry_naming_the_next_release_passes(self):
        self.assertEqual(self.check([], [entry("no-binary", "0.4.1")]), [])
        self.assertEqual(self.check([], [entry("no-binary", "0.5.0")]), [])

    def test_unchanged_entries_pass(self):
        old = entry("zero-length", "0.3.0")
        self.assertEqual(self.check([old], [old]), [])

    def test_reason_edit_keeping_since_passes(self):
        old = entry("zero-length", "0.3.0", reason="old wording")
        new = entry("zero-length", "0.3.0", reason="new wording")
        self.assertEqual(self.check([old], [new]), [])

    def test_since_correction_on_an_existing_entry_passes(self):
        # #916 backdated an entry to the release that really shipped it.
        old = entry("TagsCheck", "0.3.1")
        new = entry("TagsCheck", "0.1.0")
        self.assertEqual(self.check([old], [new]), [])

    def test_added_entry_beside_a_since_correction_fails(self):
        old = entry("TagsCheck", "0.3.1")
        fixed = entry("TagsCheck", "0.1.0")
        bad = entry("no-binary", "0.4.0")
        self.assertEqual(self.check([old], [fixed, bad]), [bad])

    def test_release_prep_retargeting_passes(self):
        # The 0.4.0 bump rewrote unshipped 0.3.1 entries to 0.4.0 while
        # v0.3.0 was the latest tag.
        old = entry("prereq-use", "0.3.1")
        new = entry("prereq-use", "0.4.0")
        self.assertEqual(_mod.violations([old], [new], (0, 3, 0)), [])

    def test_new_entry_sharing_key_and_since_with_an_old_one_fails(self):
        old = entry("BinariesCheck", "0.4.0", reason="shipped")
        new = entry("BinariesCheck", "0.4.0", reason="added after the tag")
        self.assertEqual(self.check([old], [old, new]), [new])

    def test_unrelated_entry_replacing_one_in_place_fails(self):
        # Deleting X and adding an unrelated Y at the same spot is not a
        # since correction of X.
        gone = entry("zero-length", "0.3.0", kind="missing")
        bad = entry("no-binary", "0.4.0")
        self.assertEqual(self.check([gone], [bad]), [bad])

    def test_added_entry_is_reported_not_the_correction_beside_it(self):
        old = entry("TagsCheck", "0.3.1")
        bad = entry("no-binary", "0.4.0")
        fixed = entry("TagsCheck", "0.1.0")
        self.assertEqual(self.check([old], [bad, fixed]), [bad])

    def test_rekeyed_entry_keeping_since_passes(self):
        old = entry("missing-mandatory-optflags", "0.1.0", kind="detail")
        new = entry("forbidden-optflags", "0.1.0", kind="detail")
        self.assertEqual(self.check([old], [new]), [])

    def test_reordered_entries_pass(self):
        a, b, c = (entry(n, "0.1.0", reason=n) for n in ("a", "b", "c"))
        self.assertEqual(self.check([a, b, c], [c, a, b]), [])

    def test_malformed_since_fails(self):
        for since in ["next", 123, "0.4.²"]:
            bad = entry("no-binary", since)
            self.assertEqual(self.check([], [bad]), [bad])

    def test_no_release_means_nothing_to_check(self):
        self.assertEqual(_mod.violations([], [entry("no-binary", "0.0.1")], None), [])


if __name__ == "__main__":
    unittest.main()
