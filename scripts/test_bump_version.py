#!/usr/bin/env python3
"""Tests for scripts/bump-version.sh.

Each test runs the script against a throwaway detached worktree of HEAD,
so the checkout under test is never touched. The full bump runs `make
gen`, which builds rpmcrab-gen: it needs the RPM development headers and
reuses the main checkout's target directory unless CARGO_TARGET_DIR is set.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().with_name("bump-version.sh")
REPO = SCRIPT.parent.parent

# Exact (added, removed) line counts per file, as in a manual bump: any
# extra edit -- a historical "**X.Y.Z**" in DESIGN §9, a third-party lock
# entry -- changes a count.
EXPECTED_NUMSTAT = {
    "Cargo.lock": (2, 2),
    "Cargo.toml": (1, 1),
    "README.md": (1, 1),
    "crates/rpmcrab/Cargo.toml": (1, 1),
    "crates/rpmcrab/man/rpmcrab.1": (2, 2),
    "docs/DESIGN.md": (1, 1),
}


def git(cwd, *args):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


def workspace_version(root):
    text = (Path(root) / "Cargo.toml").read_text()
    table = text.split("[workspace.package]", 1)[1].split("\n[", 1)[0]
    return re.search(r'^version = "([^"]+)"$', table, re.MULTILINE).group(1)


class BumpVersionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.tree = Path(tmp.name) / "tree"
        git(REPO, "worktree", "add", "--detach", str(cls.tree), "HEAD")
        cls.addClassCleanup(git, REPO, "worktree", "remove", "--force", str(cls.tree))
        cls.env = dict(os.environ)
        cls.env.setdefault("CARGO_TARGET_DIR", str(REPO / "target"))
        cls.old = workspace_version(cls.tree)

    def setUp(self):
        git(self.tree, "reset", "--hard", "-q")
        git(self.tree, "clean", "-fdq")

    def bump(self, version):
        return subprocess.run(
            ["bash", str(SCRIPT), version],
            cwd=self.tree,
            check=False,
            env=self.env,
            capture_output=True,
            text=True,
        )

    def assert_untouched(self):
        self.assertEqual(git(self.tree, "status", "--porcelain"), "")

    def test_malformed_version_is_rejected(self):
        for bad in ["", "1.2", "v1.2.3", "1.2.3-rc1", "1.2.3.4", "01.2.3", "1.02.3"]:
            res = self.bump(bad)
            self.assertEqual(res.returncode, 2, bad)
            self.assert_untouched()

    def test_version_never_moves_backwards(self):
        major, minor, patch = (int(p) for p in self.old.split("."))
        for stale in {self.old, f"{major}.{minor}.{max(patch - 1, 0)}", "0.0.0"}:
            res = self.bump(stale)
            self.assertEqual(res.returncode, 1, stale)
            self.assertIn("only moves forward", res.stderr)
            self.assert_untouched()

    def test_bump_moves_every_surface_and_nothing_else(self):
        major, minor, patch = (int(p) for p in self.old.split("."))
        new = f"{major}.{minor}.{patch + 1}"
        res = self.bump(new)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(f"versions: ok ({new})", res.stdout)

        numstat = {}
        for line in git(self.tree, "diff", "--numstat").splitlines():
            added, removed, path = line.split("\t")
            numstat[path] = (int(added), int(removed))
        self.assertEqual(numstat, EXPECTED_NUMSTAT)
        untracked = git(self.tree, "ls-files", "--others", "--exclude-standard")
        self.assertEqual(untracked, "")


if __name__ == "__main__":
    unittest.main()
