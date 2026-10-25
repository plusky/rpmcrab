#!/usr/bin/env python3
"""Ledger `since` gate: a newly ledgered divergence must not claim a
version that has already shipped.

Between a release tag and the post-release bump, main still carries the
just-released version, so a new entry copying it would claim the change
shipped in a release that predates it. This compares the ledger against a
base revision and fails when an added entry carries a `since` at or below
the latest `vX.Y.Z` tag. Entries edited in place -- reason, check, kind, or
a `since` corrected to the release that really shipped them -- pass.

The ledger is assembled from the per-owner sources in
`crates/rpmcrab-core/data/divergences/`; a violation names the source
file that holds the entry, which is where the entry is edited.

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
SRC_DIR = Path("crates/rpmcrab-core/data/divergences")


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


def _ident(entry):
    return (entry.get("case"), entry.get("check"), entry.get("kind"))


def _sans_since(entry):
    return {k: v for k, v in entry.items() if k != "since"}


def _max_matching(left, right, edge):
    """Maximum bipartite matching (augmenting paths): returns the set of
    matched `left` indices. Its size, and so the pass/fail verdict, does
    not depend on order; which entry is left unmatched may."""
    owner = [None] * len(right)

    def augment(i, seen):
        for j in range(len(right)):
            if j in seen or not edge(left[i], right[j]):
                continue
            seen.add(j)
            if owner[j] is None or augment(owner[j], seen):
                owner[j] = i
                return True
        return False

    return {i for i in range(len(left)) if augment(i, set())}


def _excuses(head_entry, base_entry):
    """A replaced base entry explains a head entry as an in-place edit: the
    same `since` (reason, check or kind rewritten), or the same identity with
    a well-formed `since` (a `since` correction)."""
    since = head_entry.get("since")
    if since == base_entry.get("since"):
        return True
    return _ident(head_entry) == _ident(base_entry) and parse_version(since) is not None


def violations(base_entries, head_entries, released):
    """Added entries in head whose `since` is not after `released`.

    Entries are aligned by position, as in the diff a reviewer reads; one found
    verbatim elsewhere in base merely moved. Within a changed run, an entry
    whose only change is a `since` moved forward to an unreleased version
    first claims the replaced entry it came from -- its successor -- so the
    old `since` is not free for another. Every remaining head entry whose
    `since` is shipped or malformed must then be explained by a distinct
    replaced entry (see `_excuses`); a maximum matching decides, so the
    outcome does not depend on order. Unexplained entries are added.
    """
    if released is None:
        return []
    base = [_frozen(e) for e in base_entries]
    head = [_frozen(e) for e in head_entries]
    moved = Counter(base) & Counter(head)
    moved_out, moved_in = moved.copy(), moved.copy()
    opcodes = SequenceMatcher(None, base, head, autojunk=False).get_opcodes()
    # Aligned entries reserve their share first: a verbatim duplicate added
    # ahead of an unchanged run must not pass as "moved".
    for tag, _i1, _i2, j1, j2 in opcodes:
        if tag == "equal":
            for f in head[j1:j2]:
                moved_out[f] -= 1
                moved_in[f] -= 1
    found = []
    for tag, i1, i2, j1, j2 in opcodes:
        if tag == "equal":
            continue
        replaced = []
        for f, entry in zip(base[i1:i2], base_entries[i1:i2]):
            if moved_out[f] > 0:
                moved_out[f] -= 1
            else:
                replaced.append(entry)
        needy = []
        for f, entry in zip(head[j1:j2], head_entries[j1:j2]):
            if moved_in[f] > 0:
                moved_in[f] -= 1
                continue
            version = parse_version(entry.get("since"))
            if version is not None and version > released:
                # Only a pure `since` move is a successor: a new sibling of the
                # same identity must not take a reworded entry's base.
                rest = _sans_since(entry)
                pred = next((b for b in replaced if _sans_since(b) == rest), None)
                if pred is not None:
                    replaced.remove(pred)
                continue
            needy.append(entry)
        explained = _max_matching(needy, replaced, _excuses)
        found.extend(e for i, e in enumerate(needy) if i not in explained)
    return found


def _entries(text):
    """The ledger's `[[divergence]]` entries, or ValueError when the text
    does not hold a list of tables under that key."""
    entries = tomllib.loads(text).get("divergence")
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise ValueError("no [[divergence]] array of tables")
    # Entries are compared as hashable tuples: only scalar values fit.
    for entry in entries:
        for key, value in entry.items():
            if not isinstance(value, (str, int, float, bool)):
                raise TypeError(f"divergence field {key!r} is not a scalar")
    return entries


def _owner_file(entry, src_dir=SRC_DIR):
    """The per-owner source file holding `entry`, or None.

    The aggregate is assembled from the sources in `src_dir`, and the
    entry a violation names is edited in its source, not in the
    aggregate. A source that does not parse is skipped -- assembling
    the ledger is what reports it.
    """
    if not src_dir.is_dir():
        return None
    target = _frozen(entry)
    for path in sorted(src_dir.glob("*.toml")):
        try:
            entries = _entries(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        if any(_frozen(candidate) == target for candidate in entries):
            return path
    return None


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
    try:
        head_entries = _entries(Path(LEDGER).read_text(encoding="utf-8"))
        base_entries = _entries(base_text)
    except (OSError, ValueError, TypeError) as err:
        # Exit 2 like the git failures: a broken ledger is not a violation.
        # (TOMLDecodeError and UnicodeDecodeError are ValueErrors.)
        print(f"ledger since: cannot read the ledger: {err}", file=sys.stderr)
        return 2
    shipped = ".".join(map(str, released))
    bad = violations(base_entries, head_entries, released)
    for entry in bad:
        since = entry.get("since")
        why = (
            f"v{shipped} has already shipped; a new entry names the next release"
            if parse_version(since)
            else "it is not X.Y.Z"
        )
        reason = str(entry.get("reason", ""))
        if len(reason) > 60:
            reason = reason[:60] + "..."
        owner = _owner_file(entry)
        where = f"; edit {owner} and regenerate the ledger" if owner else ""
        print(
            f"ledger since: new {entry.get('check')} ({entry.get('kind')}) entry "
            f"[{reason}] claims since = {since!r}, but {why}{where}",
            file=sys.stderr,
        )
    if bad:
        return 1
    print(f"ledger since: ok (latest release v{shipped})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
