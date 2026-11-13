#!/usr/bin/env python3
"""Mine spelling corrections into crates/rpmcrab-core/data/spelling-corrections.txt.

Usage:
    mine-spelling-corrections.py --lintian <lintian/data/spelling/corrections>
        [--codespell <codespell/codespell_lib/data/dictionary.txt>]
        --wordlist <crates/rpmcrab-core/data/spelling-wordlist.txt>
        --output <spelling-corrections.txt>

Sources (shallow clones are enough):
    lintian:  https://salsa.debian.org/lintian/lintian.git
              (data/spelling/corrections: misspellings observed in the
              wild in package descriptions -- exactly the prose the
              spellchecker reads, so this is the prime source)
    codespell: https://github.com/codespell-project/codespell.git
              (codespell_lib/data/dictionary.txt: general code typos;
              optional -- its entries are not shipped yet, held for a
              follow-up quality pass)

Formats: lintian lines are `mistake||correction`; codespell lines are
`mistake->correction`, a comma-separated right side meaning several
alternatives.

Rules:
  * Both sides must be a single lowercase ASCII word: no digits,
    hyphens, apostrophes, underscores, spaces or capitals.
  * Misspelling and correction must differ, and their Levenshtein
    distance must be at most 3: genuine typos sit a keystroke or two
    from the intended word, while far-apart pairs are usually a wrong
    mapping (e.g. lintian's unscubscribe -> subscribe).
  * A codespell line with several alternatives is ambiguous and is
    skipped.
  * On a conflict (same misspelling, different correction in the two
    sources) the closer correction wins; a tie goes to lintian.
  * A misspelling that is a stem of the shipped supplementary
    wordlist is dropped: the wordlist accepts it, so it is never
    flagged and a correction for it is dead.
  * A handful of entries whose source correction is flatly wrong are
    dropped by name (DROPPED_WRONG): the intended word is obvious and
    different, so shipping the source's correction would mislead.

Dictionary verification is NOT done here: there is no hunspell binary
on every machine, so the live check is the Rust test
`corrections_are_live_against_the_pinned_dictionary` in
crates/rpmcrab-core/src/spellcheck.rs, which asserts every shipped
misspelling is rejected by, and every correction accepted by, the
pinned en_US dictionary. Entries that fail it are dropped from the
data file, never from the test.
"""
import argparse
import re
import sys

WORD = re.compile(r"^[a-z]+$")
MAX_DISTANCE = 3

# Misspellings whose source correction is flatly wrong (the intended word
# is obvious and different): suggesting them would mislead, and no
# mechanical rule catches them, so they are dropped by name.
DROPPED_WRONG = {
    # The intended word is unsubscribe, not subscribe.
    "unscubscribe": "subscribe",
    "unscubscribed": "subscribed",
}


def levenshtein(a, b):
    if a == b:
        return 0
    if abs(len(a) - len(b)) > MAX_DISTANCE:
        return MAX_DISTANCE + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        best = cur[0]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
            best = min(best, cur[j])
        if best > MAX_DISTANCE:
            return MAX_DISTANCE + 1
        prev = cur
    return prev[-1]


def wordlist_stems(path):
    stems = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            stems.add(line.split("/")[0])
    return stems


def parse(path, sep):
    out = {}
    skipped = {"multi": 0, "shape": 0, "same": 0, "distance": 0}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(sep)
            if len(parts) != 2:
                skipped["multi"] += 1
                continue
            wrong, right = parts
            if sep == "->" and "," in right:
                # Several alternatives: no single right answer.
                skipped["multi"] += 1
                continue
            if not WORD.match(wrong) or not WORD.match(right):
                skipped["shape"] += 1
                continue
            if wrong == right:
                skipped["same"] += 1
                continue
            if levenshtein(wrong, right) > MAX_DISTANCE:
                skipped["distance"] += 1
                continue
            out[wrong] = right
    return out, skipped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lintian", required=True)
    parser.add_argument("--codespell")
    parser.add_argument("--wordlist", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    lintian, lintian_skipped = parse(args.lintian, "||")
    merged = dict(lintian)
    codespell = {}
    codespell_skipped = {}
    conflicts = []
    if args.codespell:
        codespell, codespell_skipped = parse(args.codespell, "->")
        for wrong, right in codespell.items():
            if wrong in merged:
                if merged[wrong] != right:
                    conflicts.append((wrong, merged[wrong], right))
                    if levenshtein(wrong, right) < levenshtein(wrong, merged[wrong]):
                        merged[wrong] = right
                continue
            merged[wrong] = right

    stems = wordlist_stems(args.wordlist)
    in_wordlist = sorted(w for w in merged if w in stems)
    for w in in_wordlist:
        del merged[w]

    wrongly_corrected = sorted(
        w for w, right in DROPPED_WRONG.items() if merged.get(w) == right
    )
    for w in wrongly_corrected:
        del merged[w]

    with open(args.output, "w", encoding="utf-8") as f:
        for wrong in sorted(merged):
            f.write(f"{wrong} -> {merged[wrong]}\n")

    print(f"lintian: {len(lintian)} kept, skipped {lintian_skipped}", file=sys.stderr)
    if args.codespell:
        print(f"codespell: {len(codespell)} kept, skipped {codespell_skipped}", file=sys.stderr)
        print(f"  conflicts: {len(conflicts)}", file=sys.stderr)
        for wrong, lint, code in conflicts:
            print(
                f"    conflict: {wrong}: lintian {lint} (d={levenshtein(wrong, lint)}) "
                f"vs codespell {code} (d={levenshtein(wrong, code)}) -> {merged[wrong]}",
                file=sys.stderr,
            )
    print(f"merged: {len(merged)} entries", file=sys.stderr)
    print(f"  dropped as wordlist stems: {len(in_wordlist)}", file=sys.stderr)
    print(f"  dropped as wrongly corrected: {len(wrongly_corrected)}", file=sys.stderr)
    print(f"wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
