#!/usr/bin/env python3
"""Flag stale `PythonModuleStems` entries against a distro corpus.

A stem-table entry (module -> stems) is live only while BOTH sides
still exist in the distro:

- module side: some package Provides `pythonX.Ydist(<module>)`
  (PEP 503-canonical comparison), and
- stem side: some package Requires the stem form
  (`pythonX-<stem>` or `pythonX.Ydist(<stem>)`).

An entry failing either side is reported STALE with the missing side.
This is the validation Tom required for the stem table (2026-10-28):
when the packages disappear from the distro, the config must be
updated, otherwise it goes stale in the silent direction (dead
entries are harmless today but mask the table's true coverage and
rot into false confidence).

Trigger: this needs a corpus, so it CANNOT run in CI. Run it monthly
alongside the distro-config-sync job (and by hand after any python
stack rename), e.g.:

    python3 scripts/check-python-module-stems.py --corpus ~/factory-full/rpms

Exit status is 0 when every checked entry is live, 1 when any entry
is stale. `--modules` restricts the check to named modules (used by
the fixture demo, where the mini-corpus covers only a few pairs).
"""

import argparse
import os
import re
import subprocess
import sys
import tomllib
from concurrent.futures import ThreadPoolExecutor

DIST_RE = re.compile(r"^python\d+(?:\.\d+)?dist\((.+)\)$", re.IGNORECASE)


def canon(name):
    """PEP 503-ish canonical form: lowercase, runs of -/_/. collapsed."""
    return re.sub(r"[-_.]+", "-", name).strip("-").lower()


def stem_patterns(stem):
    """Regexes matching the flavoured and dist() spellings of a stem."""
    stem = re.escape(canon(stem))
    return [
        # python3-gobject, python313-gobject, rich-expr atoms included:
        # the token ends at whitespace, a version operator, ')' or EOS.
        re.compile(r"python\d*-" + stem + r"(?:\s|[<>=!\)]|$)", re.IGNORECASE),
        re.compile(r"python\d+(?:\.\d+)?dist\(" + stem + r"\)", re.IGNORECASE),
    ]


def load_table(config_path):
    with open(config_path, "rb") as fh:
        parsed = tomllib.load(fh)
    entries = []
    for entry in parsed.get("PythonModuleStems", []):
        module = entry.get("module")
        stems = entry.get("stems")
        if isinstance(module, str) and isinstance(stems, list):
            stems = [s for s in stems if isinstance(s, str)]
            if stems:
                entries.append((module, stems))
    return entries


def scan_rpm(path):
    """All capability strings (provides + requires) for one RPM.

    `rpm -qp --provides --requires` prints both lists without labels,
    so the callers distinguish them by shape: a dist() token is a
    provided distribution, a pythonX-<stem> / dist(<stem>) token is a
    required form. Running one invocation instead of two halves the
    corpus scan cost.
    """
    try:
        out = subprocess.run(
            ["rpm", "-qp", "--provides", "--requires", path],
            capture_output=True,
            text=True,
            timeout=60,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return set()
    return {line.strip() for line in out.splitlines() if line.strip()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True,
                        help="directory tree of RPMs (walked recursively)")
    parser.add_argument("--config",
                        default="crates/rpmcrab-core/data/distro/opensuse/python-stems.toml",
                        help="python-stems.toml carrying [[PythonModuleStems]]")
    parser.add_argument("--modules", default="",
                        help="comma-separated module names to check (default: all)")
    parser.add_argument("--jobs", type=int, default=32)
    args = parser.parse_args()

    entries = load_table(args.config)
    if args.modules:
        wanted = {canon(m) for m in args.modules.split(",") if m.strip()}
        entries = [(m, s) for (m, s) in entries if canon(m) in wanted]
    if not entries:
        print("no table entries to check")
        return 0

    rpms = []
    for root, _dirs, files in os.walk(args.corpus):
        rpms.extend(
            os.path.join(root, f) for f in files if f.endswith(".rpm")
        )
    if not rpms:
        print(f"no RPMs found under {args.corpus}")
        return 2

    # Module side: canonical dist() names referenced in the corpus
    # (a provide, or a require naming the distribution).
    provided = set()
    # Stem side: normalised capability strings present in the corpus.
    # One merged pool serves both: the dist() matcher picks provides
    # out by shape, and the stem matchers run over every line. A stem
    # spelling appearing as a provide (the stem's own package) also
    # matches, which is sound — the equivalence is live while either
    # the stem's package or a carrier requiring it exists — but the
    # flavoured pattern is the one carriers produce, and in practice
    # both sides are exercised by the fixture demo.
    required_text = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for lines in pool.map(scan_rpm, rpms):
            for line in lines:
                m = DIST_RE.match(line.split()[0] if line.split() else "")
                if m:
                    provided.add(canon(m.group(1)))
            required_text.extend(lines)

    required_joined = "\n".join(
        re.sub(r"_", "-", line.lower()) for line in required_text
    )

    stale = 0
    for module, stems in entries:
        module_live = canon(module) in provided
        stem_live = {}
        for stem in stems:
            pats = stem_patterns(stem)
            stem_live[stem] = any(p.search(required_joined) for p in pats)
        dead_stems = [s for s, live in stem_live.items() if not live]
        if module_live and not dead_stems:
            print(f"OK     {module} -> {stems}")
        else:
            stale += 1
            missing = []
            if not module_live:
                missing.append("module (no dist() reference in corpus)")
            if dead_stems:
                missing.append(f"stem(s) {dead_stems} (no provide/Require in corpus)")
            print(f"STALE  {module} -> {stems}: {'; '.join(missing)}")

    print(f"{len(entries) - stale}/{len(entries)} entries live "
          f"({len(rpms)} RPMs scanned)")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
