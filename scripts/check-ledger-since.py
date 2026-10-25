#!/usr/bin/env python3
"""Ledger `since` gate: a newly ledgered divergence must not claim a
version that has already shipped.

Between a release tag and the post-release bump, main still carries the
just-released version, so a new entry copying it would claim the change
shipped in a release that predates it. This compares the ledger against a
base revision and fails when an added entry carries a `since` at or below
the latest `vX.Y.Z` tag. Entries edited in place -- reason, check, kind, or
a `since` corrected to the release that really shipped them -- pass.

Usage: check-ledger-since.py [BASE_REV]
  (default: the merge-base of origin/main and HEAD; CI passes the PR merge
  commit's first parent, the exact main the merge was built on)
"""

import subprocess
import sys
import tomllib
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path

LEDGER = "tests/parity/divergences.toml"


def parse_version(text):
    """`X.Y.Z` (optionally `vX.Y.Z`) as an int tuple, or None."""
    if not isinstance(text, str):
        return None
    parts = text.removeprefix("v").split(".")
    if len(parts) != 3 or not all(p.isascii() and p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def latest_release(tags):
    """The highest bare `vX.Y.Z` tag, or None when there is none."""
    versions = [v for t in tags if t.startswith("v") and (v := parse_version(t))]
    return max(versions, default=None)


def _frozen(entry):
    return tuple(sorted(entry.items()))


def violations(base_entries, head_entries, released):
    """Added entries in head whose `since` is not after `released`.

    Entries are aligned by position, as in the diff a reviewer reads; one found
    verbatim elsewhere in base merely moved. Within a changed run an entry
    reusing a replaced entry's `since` is an in-place edit (reason, check,
    kind), and each replaced entry left over may be a `since` correction, so
    only shipped-`since` entries beyond those count as added.
    """
    if released is None:
        return []
    base = [_frozen(e) for e in base_entries]
    head = [_frozen(e) for e in head_entries]
    moved = Counter(base) & Counter(head)
    moved_out, moved_in = moved.copy(), moved.copy()
    matcher = SequenceMatcher(None, base, head, autojunk=False)
    found = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for f in head[j1:j2]:
                moved_out[f] -= 1
                moved_in[f] -= 1
            continue
        kept = Counter()
        for f, entry in zip(base[i1:i2], base_entries[i1:i2]):
            if moved_out[f] > 0:
                moved_out[f] -= 1
            else:
                kept[entry.get("since", "")] += 1
        shipped = []
        for f, entry in zip(head[j1:j2], head_entries[j1:j2]):
            since = entry.get("since", "")
            if moved_in[f] > 0:
                moved_in[f] -= 1
            elif kept[since] > 0:
                kept[since] -= 1
            elif (v := parse_version(since)) is None or v <= released:
                shipped.append(entry)
        found.extend(shipped[sum(kept.values()) :])
    return found


def _git(*args):
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout


def main(argv):
    try:
        # A branch behind main would misalign against main's tip, so the
        # default base is where the branch left main.
        base = (
            argv[1]
            if len(argv) > 1
            else _git("merge-base", "origin/main", "HEAD").strip()
        )
        released = latest_release(_git("tag", "--list", "v*").split())
        if released is None:
            print("ledger since: no vX.Y.Z tag found; nothing to compare")
            return 0
        base_text = _git("show", f"{base}:{LEDGER}")
    except subprocess.CalledProcessError as err:
        print(
            f"ledger since: {' '.join(err.cmd)} failed: {err.stderr.strip()}",
            file=sys.stderr,
        )
        return 2
    head_entries = tomllib.loads(Path(LEDGER).read_text(encoding="utf-8"))["divergence"]
    base_entries = tomllib.loads(base_text)["divergence"]
    shipped = ".".join(map(str, released))
    bad = violations(base_entries, head_entries, released)
    for entry in bad:
        since = entry.get("since")
        why = (
            f"v{shipped} has already shipped; a new entry names the next release"
            if parse_version(since)
            else "it is not X.Y.Z"
        )
        print(
            f"ledger since: new {entry.get('check')} ({entry.get('kind')}) entry "
            f"[{str(entry.get('reason', ''))[:60]}...] claims since = {since!r}, but {why}",
            file=sys.stderr,
        )
    if bad:
        return 1
    print(f"ledger since: ok (latest release v{shipped})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
