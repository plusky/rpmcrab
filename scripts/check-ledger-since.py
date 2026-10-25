#!/usr/bin/env python3
"""Ledger `since` gate: a newly ledgered divergence must not claim a
version that has already shipped.

Between a release tag and the post-release bump, main still carries the
just-released version, so a new entry copying it would claim the change
shipped in a release that predates it. This compares the ledger against a
base revision and fails when an added entry -- or an existing entry whose
`since` changed -- carries a `since` at or below the latest `vX.Y.Z` tag.
Entries edited without touching `since` (a reason fix on an old entry)
keep the version they describe and pass.

Usage: check-ledger-since.py [BASE_REV]   (default: origin/main)
"""

import subprocess
import sys
import tomllib
from collections import defaultdict
from pathlib import Path

LEDGER = "tests/parity/divergences.toml"


def parse_version(text):
    """`X.Y.Z` (optionally `vX.Y.Z`) as an int tuple, or None."""
    parts = text.removeprefix("v").split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def latest_release(tags):
    """The highest bare `vX.Y.Z` tag, or None when there is none."""
    versions = [v for t in tags if t.startswith("v") and (v := parse_version(t))]
    return max(versions, default=None)


def _key(entry):
    return (entry.get("case"), entry.get("check"), entry.get("kind"))


def _frozen(entry):
    return tuple(sorted(entry.items()))


def violations(base_entries, head_entries, released):
    """Entries in head whose `since` is new and not after `released`."""
    if released is None:
        return []
    base_exact = {_frozen(e) for e in base_entries}
    base_since = defaultdict(set)
    for entry in base_entries:
        base_since[_key(entry)].add(entry.get("since"))
    found = []
    for entry in head_entries:
        if _frozen(entry) in base_exact:
            continue
        since = entry.get("since", "")
        if since in base_since.get(_key(entry), set()):
            continue
        version = parse_version(since)
        if version is None or version <= released:
            found.append(entry)
    return found


def _git(*args):
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout


def main(argv):
    base = argv[1] if len(argv) > 1 else "origin/main"
    released = latest_release(_git("tag", "--list", "v*").split())
    if released is None:
        print("ledger since: no vX.Y.Z tag found; nothing to compare")
        return 0
    head_entries = tomllib.loads(Path(LEDGER).read_text(encoding="utf-8"))["divergence"]
    base_entries = tomllib.loads(_git("show", f"{base}:{LEDGER}"))["divergence"]
    shipped = ".".join(map(str, released))
    bad = violations(base_entries, head_entries, released)
    for entry in bad:
        print(
            f"ledger since: {entry.get('check')} ({entry.get('kind')}) claims "
            f"since = {entry.get('since')!r}, but v{shipped} has already shipped; "
            "a new entry names the next release",
            file=sys.stderr,
        )
    if bad:
        return 1
    print(f"ledger since: ok (latest release v{shipped})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
