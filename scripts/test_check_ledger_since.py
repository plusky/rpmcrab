#!/usr/bin/env python3
"""Unit tests for check-ledger-since.py."""

import importlib.util
import tempfile
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


class EntriesTest(unittest.TestCase):
    def test_table_instead_of_array_is_rejected(self):
        with self.assertRaises(ValueError):
            _mod._entries('[divergence]\ncheck = "x"\n')

    def test_missing_key_is_rejected(self):
        with self.assertRaises(ValueError):
            _mod._entries('[other]\ncheck = "x"\n')

    def test_non_scalar_value_is_rejected(self):
        with self.assertRaises(TypeError):
            _mod._entries('[[divergence]]\ncheck = ["x", "y"]\n')


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

    def test_correction_before_a_reworded_neighbour_passes(self):
        # The correction claims its own entry, not the neighbour's `since`.
        old_t, old_u = entry("TagsCheck", "0.3.1"), entry("FilesCheck", "0.1.0")
        new_t = entry("TagsCheck", "0.1.0")
        new_u = entry("FilesCheck", "0.1.0", reason="reworded")
        self.assertEqual(self.check([old_t, old_u], [new_t, new_u]), [])

    def test_crossing_corrections_pass(self):
        base = [entry("a-check", "0.3.1"), entry("b-check", "0.1.0")]
        head = [entry("a-check", "0.1.0"), entry("b-check", "0.3.0")]
        self.assertEqual(self.check(base, head), [])

    def test_forward_moved_entry_does_not_free_its_old_since(self):
        # I1 moved to an unreleased since is I1's successor; a new entry
        # copying I1's old shipped since is still new.
        old = entry("i1-check", "0.1.0")
        moved = entry("i1-check", "0.5.0")
        bad = entry("i2-check", "0.1.0")
        self.assertEqual(self.check([old], [moved, bad]), [bad])

    def test_reworded_entry_beside_a_new_sibling_passes(self):
        # The new same-identity sibling is not the old entry's successor.
        old = entry("BinariesCheck", "0.4.0", reason="x")
        reworded = entry("BinariesCheck", "0.4.0", reason="x, reworded")
        sibling = entry("BinariesCheck", "0.4.1", reason="y")
        self.assertEqual(self.check([old], [reworded, sibling]), [])
        self.assertEqual(self.check([old], [sibling, reworded]), [])

    def test_correction_beside_a_new_sibling_passes(self):
        old = entry("BinariesCheck", "0.4.0", reason="x")
        fixed = entry("BinariesCheck", "0.3.0", reason="x")
        sibling = entry("BinariesCheck", "0.4.1", reason="y")
        self.assertEqual(self.check([old], [fixed, sibling]), [])

    def test_malformed_since_is_not_a_correction(self):
        old = entry("a-check", "0.3.0")
        bad = entry("a-check", "next")
        self.assertEqual(self.check([old], [bad]), [bad])

    def test_duplicate_identities_match_regardless_of_order(self):
        base = [
            entry("i-check", "0.1.0", reason="x"),
            entry("i-check", "0.2.0", reason="y"),
        ]
        head = [
            entry("i-check", "0.3.0", reason="x"),
            entry("j-check", "0.1.0", reason="y"),
        ]
        self.assertEqual(self.check(base, head), [])

    def test_crossed_renames_beat_a_greedy_correction(self):
        # a/0.3.1 is b renamed (same since); c/0.1.0 is a renamed.
        base = [entry("a-check", "0.1.0"), entry("b-check", "0.3.1")]
        head = [entry("a-check", "0.3.1"), entry("c-check", "0.1.0")]
        self.assertEqual(self.check(base, head), [])

    def test_rekeyed_entry_keeping_since_passes(self):
        old = entry("missing-mandatory-optflags", "0.1.0", kind="detail")
        new = entry("forbidden-optflags", "0.1.0", kind="detail")
        self.assertEqual(self.check([old], [new]), [])

    def test_verbatim_duplicate_ahead_of_its_original_fails(self):
        # base [X, A] -> head [A, X, A]: the leading A is added, not moved.
        x = entry("x-check", "0.1.0", reason="x")
        a = entry("a-check", "0.3.0", reason="a")
        self.assertEqual(self.check([x, a], [dict(a), x, a]), [a])

    def test_reordered_entries_pass(self):
        a, b, c = (entry(n, "0.1.0", reason=n) for n in ("a", "b", "c"))
        self.assertEqual(self.check([a, b, c], [c, a, b]), [])

    def test_malformed_since_fails(self):
        for since in ["next", 123, "0.4.²"]:
            bad = entry("no-binary", since)
            self.assertEqual(self.check([], [bad]), [bad])

    def test_no_release_means_nothing_to_check(self):
        self.assertEqual(_mod.violations([], [entry("no-binary", "0.0.1")], None), [])


class OwnerFileTest(unittest.TestCase):
    """The aggregate is generated from per-owner sources; a violation
    is edited in the source that holds the entry, so the gate must be
    able to name it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.src = Path(self.tmp.name) / "divergences"
        self.src.mkdir()

    def write(self, name, check, since, reason, kind="behaviour"):
        (self.src / name).write_text(
            f'[[divergence]]\ncase = "global"\ncheck = "{check}"\n'
            f'kind = "{kind}"\nreason = "{reason}"\nsince = "{since}"\n',
            encoding="utf-8",
        )

    def test_finds_the_source_holding_the_entry(self):
        self.write("AlphaCheck.toml", "alpha-finding", "0.1.0", "alpha reason")
        self.write("BetaCheck.toml", "beta-finding", "0.2.0", "beta reason",
                   kind="missing")
        held = entry("alpha-finding", "0.1.0", reason="alpha reason")
        self.assertEqual(
            _mod._owner_file(held, self.src), self.src / "AlphaCheck.toml")

    def test_unknown_entry_has_no_owner(self):
        self.write("AlphaCheck.toml", "alpha-finding", "0.1.0", "alpha reason")
        self.assertIsNone(_mod._owner_file(entry("nope", "0.1.0"), self.src))

    def test_unparsable_source_is_skipped(self):
        (self.src / "Broken.toml").write_text(
            "this is not = [ toml\n", encoding="utf-8")
        self.write("AlphaCheck.toml", "alpha-finding", "0.1.0", "alpha reason")
        held = entry("alpha-finding", "0.1.0", reason="alpha reason")
        self.assertEqual(
            _mod._owner_file(held, self.src), self.src / "AlphaCheck.toml")

    def test_missing_source_dir_has_no_owner(self):
        gone = Path(self.tmp.name) / "absent"
        self.assertIsNone(_mod._owner_file(entry("x", "0.1.0"), gone))


if __name__ == "__main__":
    unittest.main()
