#!/usr/bin/env python3
"""Flag stale `PythonModuleStems` entries against Tumbleweed repodata.

A stem-table entry (module -> stems) is live only while BOTH sides
still exist in the distro:

- module side: some package Provides `pythonX.Ydist(<module>)`
  (PEP 503-canonical comparison), and
- stem side: some package Requires the stem form
  (`pythonX-<stem>` or `pythonX.Ydist(<stem>)`).

An entry failing either side is reported STALE with the missing side.
When packages disappear from the distro, the config must be updated,
otherwise it goes stale in the silent direction (dead entries are
harmless today but mask the table's true coverage and rot into false
confidence).

Input is one or more Tumbleweed primary.xml[.gz|.zst] files: the
provides/requires they carry form one merged pool (a dist() name
counts as a reference whether it appears as a provide or a require).
This is the input the monthly staleness CI job uses: it fetches the
repo set's primary.xml files and fails on STALE, so the check needs
no manual run. Zstd-compressed primaries need the `zstd` binary.

Exit status is 0 when every checked entry is live, 1 when any entry
is stale. `--modules` restricts the check to named modules.
"""

import argparse
import gzip
import io
import re
import shutil
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET

DIST_RE = re.compile(r"^python\d+(?:\.\d+)?dist\((.+)\)$", re.IGNORECASE)
COMMON_NS = "http://linux.duke.edu/metadata/common"
RPM_NS = "http://linux.duke.edu/metadata/rpm"
FLAG_OPS = {"EQ": "=", "GE": ">=", "LE": "<=", "GT": ">", "LT": "<"}


def canon(name):
    """PEP 503-ish canonical form: lowercase, surrounding whitespace
    stripped, runs of -/_/. collapsed."""
    return re.sub(r"[-_.]+", "-", name.strip()).strip("-").lower()


def stem_patterns(stem):
    """Regexes matching the flavoured and dist() spellings of a stem,
    over canon-collapsed capability lines: the dotted flavour
    (python3.13-gobject) arrives dash-digitized (python3-13-gobject),
    so the version group is a dash-digit group, not a dot group."""
    stem = re.escape(canon(stem))
    return [
        # python3-gobject, python313-gobject, python3-13-gobject,
        # rich-expr atoms included: the token ends at whitespace, a
        # version operator, ')' or EOS.
        re.compile(r"python\d*(?:-\d+)?-" + stem + r"(?:\s|[<>=!\)]|$)", re.IGNORECASE),
        re.compile(r"python\d+(?:-\d+)?dist\(" + stem + r"\)", re.IGNORECASE),
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


def capability_string(entry):
    """One repodata entry as a capability line.

    Provides/requires entries carry name + optional flags/ver; the
    reconstruction (`name`, or `name <op> <ver>`) keeps the dist()
    matcher (first token) and the stem matchers (token boundary at
    whitespace or an operator) behaving identically over both sides.
    """
    name = entry.get("name")
    ver = entry.get("ver")
    if ver:
        op = FLAG_OPS.get(entry.get("flags"), "=")
        return f"{name} {op} {ver}"
    return name


def open_primary(path):
    """Read stream for a primary.xml file (plain, gzip, or zstd)."""
    if path.endswith(".zst"):
        if shutil.which("zstd") is None:
            raise SystemExit("zstd binary required to read .xml.zst repodata")
        proc = subprocess.run(["zstd", "-dc", path], capture_output=True)
        if proc.returncode != 0:
            raise SystemExit(
                f"zstd failed on {path}: {proc.stderr.decode()[:200]}")
        return io.BytesIO(proc.stdout)
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, "rt", encoding="utf-8")


def parse_repodata(path):
    """(capability lines, package count) from one primary.xml[.gz|.zst].

    Conflicts and obsoletes are excluded: only provides + requires
    feed the merged pool.
    """
    lines = []
    npackages = 0
    stream = open_primary(path)
    try:
        for _event, pkg in ET.iterparse(stream, events=("end",)):
            if pkg.tag != f"{{{COMMON_NS}}}package":
                continue
            npackages += 1
            fmt = pkg.find(f"{{{COMMON_NS}}}format")
            if fmt is not None:
                for section in ("provides", "requires"):
                    sec = fmt.find(f"{{{RPM_NS}}}{section}")
                    if sec is None:
                        continue
                    for entry in sec.findall(f"{{{RPM_NS}}}entry"):
                        lines.append(capability_string(entry))
            pkg.clear()
    finally:
        stream.close()
    return lines, npackages


def repodata_capabilities(path):
    """Capability strings (provides + requires) from one primary.xml."""
    lines, _npackages = parse_repodata(path)
    return lines


def pool_from_lines(lines):
    """Merged capability pool: dist() names + joined capability text.

    Module side: canonical dist() names referenced anywhere in the
    pool (a provide, or a require naming the distribution).
    Stem side: normalised capability strings present in the pool.
    One merged pool serves both: the dist() matcher picks provides
    out by shape, and the stem matchers run over every line. A stem
    spelling appearing as a provide (the stem's own package) also
    matches, which is sound — the equivalence is live while either
    the stem's package or a carrier requiring it exists.
    """
    provided = set()
    required_text = []
    for line in lines:
        tokens = line.split()
        m = DIST_RE.match(tokens[0]) if tokens else None
        if m:
            provided.add(canon(m.group(1)))
        required_text.append(line)
    # Canon-collapse every line: the stem patterns match the collapsed
    # form, so dotted-flavour spellings and separator variants in the
    # stem position collapse to the canon form the patterns expect.
    required_joined = "\n".join(canon(line) for line in required_text)
    return provided, required_joined


def report(entries, provided, required_joined, scanned_label):
    """Print OK/STALE per entry; return 1 if any entry is stale."""
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
                missing.append("module (no dist() reference in repodata)")
            if dead_stems:
                missing.append(f"stem(s) {dead_stems} (no provide/Require in repodata)")
            print(f"STALE  {module} -> {stems}: {'; '.join(missing)}")

    print(f"{len(entries) - stale}/{len(entries)} entries live ({scanned_label})")
    return 1 if stale else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repodata", nargs="+",
                        help="primary.xml[.gz|.zst] files (provides + requires)")
    parser.add_argument("--config",
                        default="crates/rpmcrab-core/data/distro/opensuse/opensuse.toml",
                        help="opensuse.toml carrying [[PythonModuleStems]]")
    parser.add_argument("--modules", default="",
                        help="comma-separated module names to check (default: all)")
    args = parser.parse_args()

    entries = load_table(args.config)
    if args.modules:
        wanted = {canon(m) for m in args.modules.split(",") if m.strip()}
        entries = [(m, s) for (m, s) in entries if canon(m) in wanted]
    if not entries:
        print("no table entries to check")
        return 0

    npackages = 0
    lines = []
    for path in args.repodata:
        path_lines, path_packages = parse_repodata(path)
        lines.extend(path_lines)
        npackages += path_packages
    if not lines:
        print(f"no capabilities found in {args.repodata}")
        return 2
    provided, required_joined = pool_from_lines(lines)
    return report(entries, provided, required_joined,
                  f"{npackages} packages in {len(args.repodata)} repodata files")


if __name__ == "__main__":
    sys.exit(main())
