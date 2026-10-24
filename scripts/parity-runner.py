#!/usr/bin/env python3
"""Run the parity corpus: the reference rpmlint and rpmcrab over every case in
tests/parity/manifest.toml, judged against the frozen captures and the
divergence ledger.

For each case the runner:

  1. verifies the case inputs against the sha256 pins in meta.toml and
     fails on any input file meta.toml does not pin;
  2. runs the pinned reference (scripts/setup-rpmlint-ref.sh's environment)
     with the case's recorded argv and requires its normalized output to
     reproduce the frozen expected/ triple byte-for-byte;
  3. runs rpmcrab with the same argv under the reproduction invocation
     (empty XDG_CONFIG_HOME, so the vendored distro layer loads exactly
     once; RUST_LOG=off; --no-time-report --jobs 1) and diffs its output
     against the live reference output;
  4. attributes every difference to a divergences.toml entry. A difference
     no entry accounts for fails the case and is printed as a readable diff.

Normalization is the capture script's (scripts/capture-parity.sh): venv /
XDG / ref-dir / home / case-dir paths become <VENV>/<XDG>/<REF>/<HOME>/
<CASE>, `has taken X s` becomes `has taken <DURATION> s`, and the
host-dependent `unable to init enchant` line is dropped from stderr.

Both subprocesses run with HOME set to a scratch home whose .rpmmacros
pins %{_unitdir} to /usr/lib/systemd/system, the value the frozen
captures were taken under: the reference expands %{_unitdir} at import
time (SystemdInstallCheck) and matches no unit files on a host whose
rpm leaves the macro undefined.

A case whose inputs carry device nodes needs an environment that can create
device nodes: the reference extracts payloads with rpm2archive, which calls
mknod. In an environment whose mknod probe fails, such a case is reported
SKIPPED with that cause and the run stays green; where the probe succeeds
the case runs in full.

Usage:
  scripts/parity-runner.py [--case NAME]... [--bin PATH] [--ref-dir DIR] [-v]

Environment:
  RPMLINT_REF   reference env dir (default: .parity-ref/ in the repo root)
  RPMCRAB_BIN   rpmcrab binary (default: target/release/rpmcrab in
                the repo root)
"""

import argparse
import collections
import difflib
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES_DIR = os.path.join(REPO_ROOT, "tests", "parity", "cases")
MANIFEST = os.path.join(REPO_ROOT, "tests", "parity", "manifest.toml")
LEDGER = os.path.join(REPO_ROOT, "tests", "parity", "divergences.toml")
PORT_DESCRIPTIONS = os.path.join(
    REPO_ROOT, "crates", "rpmcrab-core", "data", "descriptions")

FINDING_RE = re.compile(
    r"^(?P<subject>\S+): (?P<level>[EWI]): (?P<name>[^ ]+)"
    r"(?: \(Badness: \d+\))?(?: (?P<detail>.*))?$")
FOOTER_RE = re.compile(
    r"^\s*(?P<pkgs>\d+) packages and (?P<specs>\d+) specfiles checked; "
    r"(?P<errors>\d+) errors, (?P<warnings>\d+) warnings, "
    r"(?P<filtered>\d+) filtered(?:, (?P<badness>\d+) badness)?; "
    r"has taken <DURATION> s\s*$")
DURATION_RE = re.compile(r"has taken [0-9.]* s")
ENCHANT_MARK = "unable to init enchant"
RUN_TIMEOUT = 600


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def load_toml(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sanitize(text, subs):
    """The capture script's normalization, in its application order."""
    for old, new in subs:
        text = text.replace(old, new)
    return DURATION_RE.sub("has taken <DURATION> s", text)


def strip_enchant(text):
    """Drop `unable to init enchant` lines, preserving all other bytes."""
    kept = [ln for ln in text.splitlines(keepends=True)
            if ENCHANT_MARK not in ln]
    return "".join(kept)


# --------------------------------------------------------------------------
# output parsing
# --------------------------------------------------------------------------

class Parsed:
    def __init__(self):
        self.header = []          # lines through the `checks:` line
        self.findings = []        # (subject, level, name, detail)
        self.footer = None        # raw footer line, stripped
        self.footer_counts = None  # (errors, warnings)
        self.banner = False       # badness-threshold abort banner present
        self.other = []           # body lines that are none of the above


def parse_output(text):
    p = Parsed()
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        p.header.append(lines[i])
        i += 1
        if lines[i - 1].startswith("checks:"):
            break
    else:
        # No session header at all (an early fatal run): everything is body.
        p.header = []
        i = 0
    if i < len(lines) and lines[i] == "":
        i += 1  # the blank line separating header from findings
    for ln in lines[i:]:
        if not ln:
            continue
        m = FOOTER_RE.match(ln)
        if m:
            p.footer = ln.strip()
            p.footer_counts = (int(m.group("errors")),
                               int(m.group("warnings")))
        elif "Badness" in ln and "aborting" in ln:
            p.banner = True
        else:
            m = FINDING_RE.match(ln)
            if m:
                p.findings.append((m.group("subject"), m.group("level"),
                                    m.group("name"),
                                    m.group("detail") or ""))
            else:
                p.other.append(ln)
    return p


def render(finding):
    subject, level, name, detail = finding
    line = f"{subject}: {level}: {name}"
    if detail:
        line += f" {detail}"
    return line


# --------------------------------------------------------------------------
# the divergence ledger and finding -> check-module resolution
# --------------------------------------------------------------------------

def family_stem(name):
    """The ledger names templated findings by family: the finding
    `daemon-activation-in-%post` belongs to the family `daemon-activation-in`.
    """
    if "-%" in name:
        return name.split("-%", 1)[0]
    return name


class Ledger:
    def __init__(self, entries, module_of):
        self.entries = entries
        self.module_of = module_of  # finding name -> check module
        self.known_findings = set(module_of)

    def applicable(self, case):
        return [e for e in self.entries
                if e.get("case") in ("global", case)]

    def candidates(self, case, name):
        """Entries that can account for a difference on finding `name`:
        an entry naming the finding, its family stem, or its emitting check
        module — or an entry whose reason names the finding or its stem.
        Reason mentions count only from entries whose `check` is a module
        or area label: an entry scoped to a different finding does not
        account for this one merely by naming it in passing."""
        stem = family_stem(name)
        module = self.module_of.get(name) or self.module_of.get(stem)
        out = []
        for e in self.applicable(case):
            check = e.get("check")
            if not check:
                # An entry with no check name accounts for nothing: a
                # None check would compare equal to a None module and
                # attribute any finding the module map does not know.
                continue
            if (check in (name, stem)
                    or (module is not None and check == module)):
                out.append(e)
            elif (check not in self.known_findings
                    and family_stem(check or "") not in self.known_findings
                    and self._mentions(e.get("reason", ""), name, stem)):
                out.append(e)
        return out

    @staticmethod
    def _mentions(reason, name, stem):
        for token in {name, stem}:
            if len(token) < 8:
                continue
            pat = r"(?<![a-z0-9\-])" + re.escape(token) + r"(?![a-z0-9])"
            if re.search(pat, reason):
                return True
        return False

    def area_entry(self, case, checks):
        for e in self.applicable(case):
            if e.get("check") in checks:
                return e
        return None


def build_module_map(ref_dir, port_descriptions):
    """finding name -> emitting check module, from the reference's staged
    descriptions and check sources and from the port's staged descriptions
    (the port's descriptions also cover port-only findings)."""
    module_of = {}

    def from_descriptions(directory):
        if not os.path.isdir(directory):
            return
        for fn in sorted(os.listdir(directory)):
            if fn.endswith(".toml"):
                # A description that cannot be read or parsed fails the
                # run: skipping it drops the check's findings from the
                # module map, and their differences then surface
                # unattributed with no pointer at the cause. A missing
                # directory is the only tolerated absence (the isdir
                # guard above); read and parse failures — OSError,
                # TOMLDecodeError — propagate.
                keys = load_toml(os.path.join(directory, fn))
                for key in keys:
                    module_of.setdefault(key, fn[:-len(".toml")])

    def from_ref_sources(directory):
        if not os.path.isdir(directory):
            return
        literal = re.compile(r"""['"]([a-z][a-z0-9]*(?:-[a-z0-9%]+)+)['"]""")
        for fn in sorted(os.listdir(directory)):
            if fn.endswith(".py"):
                try:
                    with open(os.path.join(directory, fn),
                              encoding="utf-8") as f:
                        text = f.read()
                except OSError:
                    continue
                for m in literal.finditer(text):
                    module_of.setdefault(m.group(1), fn[:-len(".py")])

    # The installed reference package travels with the venv that runs it.
    pkg_dirs = []
    venv_lib = os.path.join(ref_dir, "venv", "lib")
    if os.path.isdir(venv_lib):
        for py in sorted(os.listdir(venv_lib)):
            cand = os.path.join(venv_lib, py, "site-packages", "rpmlint")
            if os.path.isdir(cand):
                pkg_dirs.append(cand)
    src = os.path.join(ref_dir, "rpmlint-src", "rpmlint")
    if os.path.isdir(src):
        pkg_dirs.append(src)
    for pkg in pkg_dirs:
        from_descriptions(os.path.join(pkg, "descriptions"))
        from_ref_sources(os.path.join(pkg, "checks"))
    from_descriptions(port_descriptions)
    return module_of


# --------------------------------------------------------------------------
# the differ
# --------------------------------------------------------------------------

class Diff:
    """One difference unit. `entry` is the ledger entry accounting for it,
    or None when the difference is unattributed."""

    def __init__(self, text, entry=None):
        self.text = text
        self.entry = entry

    @property
    def attributed(self):
        return self.entry is not None


def _entry_label(entry):
    return f"ledger check={entry.get('check')} kind={entry.get('kind')}"


def diff_outputs(case, ref, port, ref_exit, port_exit, ledger):
    """All difference units between the two parsed runs of one case."""
    diffs = []

    def by_kind(entries, kinds):
        for e in entries:
            if e.get("kind") in kinds:
                return e
        return None

    # -- session header ----------------------------------------------------
    if ref.header != port.header:
        e = ledger.area_entry(case, {"session-header", "config"})
        diffs.append(Diff("session header differs", e))

    # -- findings ----------------------------------------------------------
    rc = collections.Counter(ref.findings)
    pc = collections.Counter(port.findings)
    rem_r = list((rc - pc).elements())
    rem_p = list((pc - rc).elements())

    # severity pairing: same subject, name and detail at another level.
    def pair_up(rem_r, rem_p, keyfn):
        groups_r, groups_p = collections.defaultdict(list), \
            collections.defaultdict(list)
        for f in rem_r:
            groups_r[keyfn(f)].append(f)
        for f in rem_p:
            groups_p[keyfn(f)].append(f)
        pairs, left_r, left_p = [], [], []
        for key in sorted(set(groups_r) | set(groups_p)):
            gr, gp = groups_r.get(key, []), groups_p.get(key, [])
            n = min(len(gr), len(gp))
            pairs.extend(zip(gr[:n], gp[:n]))
            left_r.extend(gr[n:])
            left_p.extend(gp[n:])
        return pairs, left_r, left_p

    sev_pairs, rem_r, rem_p = pair_up(
        rem_r, rem_p, lambda f: (f[0], f[2], f[3]))
    for rf, pf in sev_pairs:
        e = by_kind(ledger.candidates(case, rf[2]), {"severity"})
        diffs.append(Diff(
            f"severity: {rf[0]}: {rf[1]} (reference) vs {pf[1]} (rpmcrab): "
            f"{rf[2]} {rf[3]}".rstrip(), e))

    det_pairs, rem_r, rem_p = pair_up(
        rem_r, rem_p, lambda f: (f[0], f[2], f[1]))
    det_groups = collections.defaultdict(lambda: ([], []))
    for rf, pf in det_pairs:
        det_groups[(rf[0], rf[2])][0].append(rf[3])
        det_groups[(rf[0], rf[2])][1].append(pf[3])
    for (subject, name), (rd, pd) in sorted(det_groups.items()):
        e = by_kind(ledger.candidates(case, name), {"detail", "behaviour"})
        diffs.append(Diff(
            f"detail: {subject}: {name}: reference {sorted(rd)} vs "
            f"rpmcrab {sorted(pd)}", e))

    for f in sorted(rem_r):
        e = by_kind(ledger.candidates(case, f[2]),
                    {"missing", "behaviour", "limitation"})
        diffs.append(Diff(f"only in reference: {render(f)}", e))
    for f in sorted(rem_p):
        # A `missing` entry records that the port does not emit the
        # finding; it cannot account for the finding appearing in the
        # port's output.
        e = by_kind(ledger.candidates(case, f[2]),
                    {"behaviour", "limitation"})
        diffs.append(Diff(f"only in rpmcrab: {render(f)}", e))

    # -- unparsed body lines -------------------------------------------------
    ro = collections.Counter(ref.other)
    po = collections.Counter(port.other)
    for ln in sorted((ro - po).elements()):
        diffs.append(Diff(f"unparsed line only in reference: {ln}"))
    for ln in sorted((po - ro).elements()):
        diffs.append(Diff(f"unparsed line only in rpmcrab: {ln}"))

    # -- footer and abort banner ---------------------------------------------
    if ref.banner and not port.banner:
        e = ledger.area_entry(case, {"report"})
        diffs.append(Diff(
            "reference aborts at its badness threshold; rpmcrab reports "
            "the full session", e))
    if port.banner:
        diffs.append(Diff("rpmcrab printed the badness abort banner"))
    if ref.footer != port.footer:
        e = ledger.area_entry(case, {"report", "time-report"})
        diffs.append(Diff(
            f"footer differs: reference {ref.footer!r} vs "
            f"rpmcrab {port.footer!r}", e))

    # -- exit code -------------------------------------------------------------
    if ref_exit != port_exit:
        e = ledger.area_entry(case, {"report", "cli"})
        diffs.append(Diff(
            f"exit code: reference {ref_exit} vs rpmcrab {port_exit}", e))

    return diffs


def port_contract_diffs(port, port_exit):
    """rpmcrab's own output contract (DESIGN §4.6): the exit code is a pure
    function of the emitted severities, and the footer counts the findings
    the session emitted. Violations are unattributed by construction."""
    diffs = []
    errors = sum(1 for f in port.findings if f[1] == "E")
    warnings = sum(1 for f in port.findings if f[1] == "W")
    if port_exit not in (0, 64):
        diffs.append(Diff(f"rpmcrab exit code {port_exit} is outside "
                          "the {0, 64} contract"))
    elif (port_exit == 64) != (errors > 0):
        diffs.append(Diff(
            f"rpmcrab exit code {port_exit} disagrees with its "
            f"{errors} error findings"))
    if port.footer_counts is None:
        diffs.append(Diff("rpmcrab printed no session footer"))
    elif port.footer_counts != (errors, warnings):
        diffs.append(Diff(
            f"rpmcrab footer counts {port.footer_counts} disagree with "
            f"its findings ({errors} errors, {warnings} warnings)"))
    config_lines = []
    in_config = False
    for ln in port.header:
        if ln == "configuration:":
            in_config = True
        elif ln.startswith("checks:"):
            in_config = False
        elif in_config:
            config_lines.append(ln.strip())
    dupes = [c for c, n in collections.Counter(config_lines).items() if n > 1]
    if dupes:
        diffs.append(Diff(
            f"rpmcrab session header loads configs more than once: {dupes}"))
    return diffs


PROGRESS_RE = re.compile(r"^checking \S+ \(\d+ of \d+\)$")


def diff_stderr(case, ref_stderr, port_stderr, ledger):
    """stderr differences. The worker/report ledger entry accounts for the
    per-package progress lines of a multi-package run; every other stderr
    difference is unattributed."""
    diffs = []
    rc = collections.Counter(ref_stderr.splitlines())
    pc = collections.Counter(port_stderr.splitlines())
    e = ledger.area_entry(case, {"worker/report"})
    for ln in sorted((rc - pc).elements()):
        entry = e if PROGRESS_RE.match(ln) else None
        diffs.append(Diff(f"stderr only in reference: {ln!r}", entry))
    for ln in sorted((pc - rc).elements()):
        entry = e if PROGRESS_RE.match(ln) else None
        diffs.append(Diff(f"stderr only in rpmcrab: {ln!r}", entry))
    return diffs


# --------------------------------------------------------------------------
# running the two implementations
# --------------------------------------------------------------------------

class Runner:
    def __init__(self, ref_dir, port_bin, scratch):
        self.ref_dir = ref_dir
        self.venv = os.path.join(ref_dir, "venv")
        self.xdg = os.path.join(ref_dir, "xdg")
        self.rpmlint = os.path.join(self.venv, "bin", "rpmlint")
        self.port_bin = port_bin
        self.home = os.path.join(scratch, "home")
        self.empty_xdg = os.path.join(scratch, "empty-xdg")
        os.makedirs(self.home, exist_ok=True)
        os.makedirs(self.empty_xdg, exist_ok=True)
        # The capture environment pins %{_unitdir}: the reference
        # expands it at import time (SystemdInstallCheck) and matches
        # no unit files where the host rpm leaves it undefined, which
        # silently degrades the reference. Both subprocesses run with
        # HOME=self.home, and librpm reads ~/.rpmmacros from it.
        with open(os.path.join(self.home, ".rpmmacros"), "w") as fh:
            fh.write("%_unitdir /usr/lib/systemd/system\n")

    def subs(self, work):
        # The capture script's substitution order: the venv and the XDG dir
        # live under the ref dir, so they are replaced before it.
        return [(self.venv, "<VENV>"), (self.xdg, "<XDG>"),
                (self.ref_dir, "<REF>"), (self.home, "<HOME>"),
                (work, "<CASE>")]

    def run(self, case_dir, argv, work):
        """Run both implementations for one case in `work` (a fresh dir
        holding copies of the case inputs). Returns
        (ref_triple, port_triple) of (stdout, stderr, exit)."""
        os.makedirs(work, exist_ok=True)
        for fn in sorted(os.listdir(os.path.join(case_dir, "input"))):
            shutil.copy2(os.path.join(case_dir, "input", fn),
                         os.path.join(work, fn))
        subs = self.subs(work)

        env = dict(os.environ, XDG_CONFIG_HOME=self.xdg, HOME=self.home)
        ref = subprocess.run([self.rpmlint, *argv], cwd=work, env=env,
                             capture_output=True, text=True,
                             timeout=RUN_TIMEOUT)
        env = dict(os.environ, XDG_CONFIG_HOME=self.empty_xdg,
                   HOME=self.home, RUST_LOG="off")
        port = subprocess.run(
            [self.port_bin, "--no-time-report", "--jobs", "1", *argv],
            cwd=work, env=env, capture_output=True, text=True,
            timeout=RUN_TIMEOUT)

        def triple(proc):
            return (sanitize(proc.stdout, subs),
                    strip_enchant(sanitize(proc.stderr, subs)),
                    proc.returncode)

        return triple(ref), triple(port)


def expected_triple(case_dir):
    exp = os.path.join(case_dir, "expected")
    with open(os.path.join(exp, "stdout"), encoding="utf-8") as f:
        stdout = f.read()
    with open(os.path.join(exp, "stderr"), encoding="utf-8") as f:
        stderr = f.read()
    with open(os.path.join(exp, "exit"), encoding="utf-8") as f:
        code = int(f.read().strip())
    return stdout, stderr, code


def unified(want, got, want_name, got_name):
    out = list(difflib.unified_diff(
        want.splitlines(), got.splitlines(),
        fromfile=want_name, tofile=got_name, lineterm=""))
    if len(out) > 44:
        out = out[:44] + [f"... ({len(out) - 44} more diff lines)"]
    return out


# --------------------------------------------------------------------------
# device-node cases: the reference extracts payloads with rpm2archive,
# which creates device nodes with mknod.
# --------------------------------------------------------------------------

def mknod_capable():
    try:
        with tempfile.TemporaryDirectory() as d:
            os.mknod(os.path.join(d, "probe"), stat.S_IFCHR | 0o644,
                     os.makedev(1, 3))
        return True
    except OSError:
        return False


def case_has_device_payload(case_dir, meta):
    """True when any .rpm input ships a block or character device node,
    read from the RPM header dump."""
    for inp in meta.get("input", []):
        path = os.path.join(case_dir, "input", inp["file"])
        if not inp["file"].endswith(".rpm") or not os.path.exists(path):
            continue
        try:
            out = subprocess.run(["rpm", "-qp", "--dump", path],
                                 capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            continue
        for ln in out.stdout.splitlines():
            fields = ln.split()
            if len(fields) > 4:
                try:
                    mode = int(fields[4], 8)
                except ValueError:
                    continue
                if stat.S_IFMT(mode) in (stat.S_IFCHR, stat.S_IFBLK):
                    return True
    return False


def extraction_aborted(ref_triple):
    return ("fatal error while reading" in ref_triple[1]
            and "rpm2archive" in ref_triple[1])


# --------------------------------------------------------------------------
# per-case driver
# --------------------------------------------------------------------------

class Result:
    def __init__(self, name):
        self.name = name
        self.status = "PASS"      # PASS | FAIL | SKIPPED
        self.attributed = []      # Diff objects
        self.unattributed = []    # Diff objects
        self.notes = []           # extra report lines (diffs, causes)


def check_case(name, runner, ledger, scratch):
    res = Result(name)
    case_dir = os.path.join(CASES_DIR, name)
    meta = load_toml(os.path.join(case_dir, "meta.toml"))

    # 1. Input pins: every file a run consumes is pinned by sha256 in
    #    meta.toml, and the input directory holds nothing else — the
    #    runner copies the whole directory into both runs, so an
    #    unpinned file would otherwise influence them unverified.
    for inp in meta.get("input", []):
        path = os.path.join(case_dir, "input", inp["file"])
        if not os.path.exists(path):
            res.status = "FAIL"
            res.unattributed.append(Diff(f"input missing: {inp['file']}"))
            return res
        if sha256_of(path) != inp["sha256"]:
            res.status = "FAIL"
            res.unattributed.append(Diff(
                f"input sha256 drift: {inp['file']} does not match "
                "meta.toml"))
            return res
    input_dir = os.path.join(case_dir, "input")
    on_disk = (set(os.listdir(input_dir))
               if os.path.isdir(input_dir) else set())
    unpinned = sorted(on_disk
                      - {inp["file"] for inp in meta.get("input", [])})
    if unpinned:
        res.status = "FAIL"
        res.unattributed.append(Diff(
            "unpinned input file(s) not in meta.toml: "
            + ", ".join(unpinned)))
        return res

    work = os.path.join(scratch, "case-" + name)
    try:
        ref_live, port_live = runner.run(case_dir, list(meta["argv"]), work)
    except subprocess.TimeoutExpired:
        res.status = "FAIL"
        res.unattributed.append(Diff("a run exceeded the timeout"))
        return res
    expected = expected_triple(case_dir)

    # 2. Reference fidelity: the live reference reproduces the frozen
    #    triple byte-for-byte, or the environment has drifted.
    if ref_live != expected:
        # A device case in a mknod-less environment: the probe fails, the
        # inputs carry device nodes, and the reference's own run shows its
        # extraction abort. All three together are the skip signature;
        # anything else is reference drift and fails below.
        if (not mknod_capable()
                and extraction_aborted(ref_live)
                and case_has_device_payload(case_dir, meta)):
            res.status = "SKIPPED"
            res.notes.append(
                "environment cannot create device nodes (mknod probe "
                "failed): the reference aborts extracting this case's "
                "device payload here; the case runs where mknod is "
                "available")
            return res
        res.status = "FAIL"
        res.unattributed.append(Diff(
            "reference output does not reproduce the frozen capture"))
        for stream, want, got in (
                ("stdout", expected[0], ref_live[0]),
                ("stderr", expected[1], ref_live[1])):
            if want != got:
                res.notes.extend(unified(want, got, f"expected/{stream}",
                                         f"live-reference/{stream}"))
        if expected[2] != ref_live[2]:
            res.notes.append(
                f"exit: expected {expected[2]}, live reference "
                f"{ref_live[2]}")
        return res

    # 3. The differ: live reference vs live rpmcrab, judged by the ledger,
    #    plus rpmcrab's own output contract.
    ref_parsed = parse_output(ref_live[0])
    port_parsed = parse_output(port_live[0])
    diffs = diff_outputs(name, ref_parsed, port_parsed,
                         ref_live[2], port_live[2], ledger)
    diffs += diff_stderr(name, ref_live[1], port_live[1], ledger)
    diffs += port_contract_diffs(port_parsed, port_live[2])
    res.attributed = [d for d in diffs if d.attributed]
    res.unattributed = [d for d in diffs if not d.attributed]
    if res.unattributed:
        res.status = "FAIL"
        res.notes.extend(unified(ref_live[0], port_live[0],
                                 "reference/stdout", "rpmcrab/stdout"))
    return res


def default_port_bin():
    """The default binary under test: the just-built release binary.
    A debug build is never a fallback — it can be a stale artefact of
    an older tree and would silently test the wrong code."""
    path = os.path.join(REPO_ROOT, "target", "release", "rpmcrab")
    if os.path.isfile(path) and os.access(path, os.X_OK):
        return path
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--case", action="append", default=[],
                    help="run only this case (repeatable)")
    ap.add_argument("--bin", default=None,
                    help="rpmcrab binary (default: $RPMCRAB_BIN or "
                         "target/release/rpmcrab)")
    ap.add_argument("--ref-dir", default=None,
                    help="reference env dir (default: $RPMLINT_REF or "
                         ".parity-ref/)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="list every attributed difference")
    args = ap.parse_args(argv)

    ref_dir = os.path.abspath(args.ref_dir or os.environ.get(
        "RPMLINT_REF", os.path.join(REPO_ROOT, ".parity-ref")))
    port_bin = args.bin or os.environ.get("RPMCRAB_BIN")
    if not port_bin:
        port_bin = default_port_bin()
    if not port_bin or not os.path.isfile(port_bin):
        print("no rpmcrab binary: build one (cargo build --release) or "
              "pass --bin / $RPMCRAB_BIN", file=sys.stderr)
        return 2
    if not os.path.isfile(os.path.join(ref_dir, "venv", "bin", "rpmlint")):
        print(f"no reference rpmlint under {ref_dir}: run "
              "scripts/setup-rpmlint-ref.sh", file=sys.stderr)
        return 2

    manifest = load_toml(MANIFEST)
    names = [c["name"] for c in manifest["case"]]
    on_disk = sorted(d for d in os.listdir(CASES_DIR)
                     if os.path.isdir(os.path.join(CASES_DIR, d)))
    if sorted(names) != on_disk:
        print(f"manifest.toml and cases/ disagree: manifest "
              f"{sorted(names)} vs on-disk {on_disk}", file=sys.stderr)
        return 2
    if args.case:
        unknown = [c for c in args.case if c not in names]
        if unknown:
            print(f"unknown case(s): {unknown}", file=sys.stderr)
            return 2
        names = [n for n in names if n in set(args.case)]

    ledger = Ledger(load_toml(LEDGER)["divergence"],
                    build_module_map(ref_dir, PORT_DESCRIPTIONS))
    print(f"parity: {len(names)} case(s); reference env {ref_dir}; "
          f"rpmcrab {port_bin}")

    counts = collections.Counter()
    total_attributed = 0
    with tempfile.TemporaryDirectory(prefix="parity-runner-") as scratch:
        runner = Runner(ref_dir, port_bin, scratch)
        for name in names:
            res = check_case(name, runner, ledger, scratch)
            counts[res.status] += 1
            total_attributed += len(res.attributed)
            if res.status == "PASS":
                print(f"{name}: PASS ({len(res.attributed)} attributed "
                      "difference(s))")
            elif res.status == "SKIPPED":
                print(f"{name}: SKIPPED")
            else:
                print(f"{name}: FAIL")
            if args.verbose:
                for d in res.attributed:
                    print(f"  attributed: {d.text} "
                          f"[{_entry_label(d.entry)}]")
            for d in res.unattributed:
                print(f"  unattributed: {d.text}")
            for note in res.notes:
                print(f"  {note}")
    print(f"summary: {counts['PASS']} passed, {counts['SKIPPED']} "
          f"skipped, {counts['FAIL']} failed; {total_attributed} "
          "attributed difference(s)")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
