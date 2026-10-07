#!/usr/bin/env python3
"""Vendor upstream distro configs (openSUSE + SLFO) into rpmcrab.

Copies ``configs/openSUSE/*.toml`` from the pinned upstream rpmlint commits
into ``crates/rpmcrab-core/data/distro/<flavor>/``, prunes ``Filters`` /
``BlockedFilters`` entries that reference findings rpmcrab no longer emits,
and stamps provenance.

The checked-in files are the build's source of truth; this script runs by hand
and in CI (drift check + monthly refresh), never at build time.

Upstream remains the owner of these configs until rpmlint is fully superseded:
the monthly ``distro-config-sync`` CI job opens a refresh PR when upstream
moves, and the ``distro-config-drift`` CI job fails when the vendored copies
diverge from what this script produces at the pinned SHAs.

Usage:
    scripts/generate-distro-configs.py [--check] [--ref-dir DIR]
        [--pin opensuse=SHA:DATE] [--pin slfo=SHA:DATE]

    --check      regenerate into a temp dir and diff against the repo;
                 exit 1 with a unified diff on any divergence.
    --ref-dir    use a local rpmlint checkout instead of fetching from
                 GitHub (both pinned SHAs must exist in it).
    --pin        override a pinned SHA for the refresh workflow; DATE is the
                 commit date (YYYY-MM-DD) used for the provenance stamp.
"""

import argparse
import difflib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DISTRO_DIR = REPO / "crates/rpmcrab-core/data/distro"
GENERATED_RS = REPO / "crates/rpmcrab-core/src/distro_files_generated.rs"
DESCRIPTIONS_DIR = REPO / "crates/rpmcrab-core/data/descriptions"
CHECKS_DIR = REPO / "crates/rpmcrab-core/src/checks"

UPSTREAM_REPO = "rpm-software-management/rpmlint"

# Pinned upstream commits. Bumped by the monthly distro-config-sync job.
PINS = {
    # flavor: (sha, date, branch, config_subdir)
    "opensuse": (
        "84848c05c5571c22274a55ff9afdfe6d88c67dc9",
        "2026-09-28",
        "main",
    ),
    "slfo": (
        "5c758cf12f9be87e9487bb60b023397f1e97115e",
        "2026-06-09",
        "opensuse-slfo-main",
    ),
}

# The vendored file sets, per flavor (configs/openSUSE/*.toml at the pinned
# SHAs; SLFO dropped varlink-whitelist.toml).
FILES = {
    "opensuse": [
        "cron-whitelist.toml",
        "dbus-services.toml",
        "device-files-whitelist.toml",
        "licenses.toml",
        "opensuse.toml",
        "pam-modules.toml",
        "permissions-whitelist.toml",
        "pie-executables.toml",
        "polkit-rules-whitelist.toml",
        "scoring-strict.override.toml",
        "scoring.toml",
        "security.toml",
        "sudoers-whitelist.toml",
        "sysctl-whitelist.toml",
        "systemd-tmpfiles.toml",
        "users-groups.toml",
        "varlink-whitelist.toml",
        "world-writable-whitelist.toml",
        "zypper-plugins.toml",
    ],
}
FILES["slfo"] = [f for f in FILES["opensuse"] if f != "varlink-whitelist.toml"]

# Findings rpmcrab deliberately killed (see tests/parity/divergences.toml).
# A Filters/BlockedFilters entry that references *only* one of these findings
# is pruned — but ONLY when the finding is actually gone from the tree, so the
# vendored config always matches head reality regardless of merge order.
PRUNE_CANDIDATES = {
    # finding: reason
    "%ifarch-applied-patch": "killed: conditional patch application is legitimate",
    "unversioned-explicit-provides": "killed: negligible value, openSUSE filters it",
    "unversioned-explicit-obsoletes": "killed: negligible value, openSUSE filters it",
    "no-buildroot-tag": "killed: BuildRoot: is obsolete/ignored",
    "hardcoded-path-in-buildroot-tag": "killed: policing an obsolete tag",
    "non-standard-group": "killed: openSUSE dropped the Group tag",
    "setup-not-quiet": "killed: spec-cleaner adds -q",
    "not-standard-release-extension": "killed: autobuild redundancy, suppressed by openSUSE and Fedora",
    "executable-in-library-package": "killed: autobuild redundancy, suppressed by openSUSE and Fedora",
    "non-versioned-file-in-library-package": "killed: autobuild redundancy, suppressed by openSUSE and Fedora",
    "no-packager-tag": "killed: autobuild redundancy, suppressed by openSUSE and Fedora",
    "no-signature": "killed: autobuild redundancy, suppressed by openSUSE and Fedora",
    "module-without-depmod-postin": "killed: KMP macro template calls depmod (bnc#456048)",
    "module-without-depmod-postun": "killed: KMP macro template calls depmod (bnc#456048)",
    "postin-with-wrong-depmod": "killed: no manual depmod in scriptlets (bnc#456048)",
    "postun-with-wrong-depmod": "killed: no manual depmod in scriptlets (bnc#456048)",
    # InitScriptCheck was deliberately deleted (issue #214): SysV init is gone,
    # so every finding it emitted is dead. Verified absent from the tree.
    "without-chkconfig": "killed: InitScriptCheck deleted (issue #214)",
    "no-chkconfig": "killed: InitScriptCheck deleted (issue #214)",
    "subsys-not-used": "killed: InitScriptCheck deleted (issue #214)",
    "init-script-name-with-dot": "killed: InitScriptCheck deleted (issue #214)",
    "init-script-without-chkconfig-postin": "killed: InitScriptCheck deleted (issue #214)",
    "init-script-without-chkconfig-preun": "killed: InitScriptCheck deleted (issue #214)",
    "postin-without-chkconfig": "killed: InitScriptCheck deleted (issue #214)",
    "preun-without-chkconfig": "killed: InitScriptCheck deleted (issue #214)",
    "no-default-runlevel": "killed: InitScriptCheck deleted (issue #214)",
    "service-default-enabled": "killed: InitScriptCheck deleted (issue #214)",
}

# (finding, scope) -> reason: Filters entries scoped to dead paths. The finding
# itself stays (its general form is live); only the listed scope is pruned.
# Unlike PRUNE_CANDIDATES these are unconditional: the scope paths are dead
# (SysV init removed), verified by hand when listed here.
PRUNE_SCOPED = {
    ("subdir-in-bin", "/sbin/conf.d/"): "dead SysV scope",
    ("conffile-without-noreplace-flag", "/etc/init.d"): "dead SysV scope",
}

LIST_KEYS = ("Filters", "BlockedFilters")


def fetch_github(sha, filename):
    url = (
        f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/{sha}"
        f"/configs/openSUSE/{filename}"
    )
    with urllib.request.urlopen(url, timeout=60) as resp:
        return resp.read().decode("utf-8")


def fetch_local(ref_dir, sha, filename):
    out = subprocess.run(
        ["git", "-C", str(ref_dir), "show", f"{sha}:configs/openSUSE/{filename}"],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(f"git show failed for {sha}:{filename}: {out.stderr.strip()}")
    return out.stdout


def latest_upstream_sha(branch):
    """Resolve the latest commit SHA and date for an upstream branch."""
    url = f"https://api.github.com/repos/{UPSTREAM_REPO}/commits/{branch}"
    req = urllib.request.Request(url, headers={"User-Agent": "rpmcrab-distro-config-sync"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.load(resp)
    return data["sha"], data["commit"]["committer"]["date"][:10]


def known_findings():
    """Finding names rpmcrab can emit: staged description keys plus in-code
    set_error_detail registrations."""
    findings = set()
    key_re = re.compile(r'^(?:"([^"]+)"|([A-Za-z0-9_.\-%]+))\s*=')
    for toml_file in DESCRIPTIONS_DIR.glob("*.toml"):
        for line in toml_file.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("["):
                continue
            m = key_re.match(s)
            if m:
                findings.add(m.group(1) or m.group(2))
    detail_re = re.compile(r'set_error_detail\(\s*"([^"]+)"')
    for rs_file in CHECKS_DIR.glob("*.rs"):
        findings.update(detail_re.findall(rs_file.read_text(encoding="utf-8")))
    return findings


def pure_finding_pattern(entry):
    """If a Filters entry references exactly one finding name, return it.

    Strips quotes, trailing commas/comments, and the common '.*' wrappers plus
    surrounding whitespace: '.*no-buildroot-tag.*' -> 'no-buildroot-tag',
    ' prereq-use' -> 'prereq-use'. Returns None for compound patterns
    (package anchors, paths, alternations) which are never pruned.
    """
    s = entry.strip().split("#", 1)[0].strip().rstrip(",").strip()
    if (s.startswith("'") and s.endswith("'")) or (
        s.startswith('"') and s.endswith('"')
    ):
        s = s[1:-1]
    else:
        return None
    s = s.strip()
    while s.startswith(".*"):
        s = s[2:]
    while s.endswith(".*"):
        s = s[:-2]
    s = s.strip()
    # A pure finding filter names one finding and nothing else.
    if re.fullmatch(r"[A-Za-z0-9_.\-%]+", s):
        return s
    return None


def scoped_entry(entry):
    """If a Filters entry is 'finding scope' form, return (finding, scope).

    Handles path-scoped entries like 'subdir-in-bin /sbin/conf.d/' where the
    finding itself is live but the scope is dead. Returns None otherwise.
    """
    s = entry.strip().split("#", 1)[0].strip().rstrip(",").strip()
    if (s.startswith("'") and s.endswith("'")) or (
        s.startswith('"') and s.endswith('"')
    ):
        s = s[1:-1]
    else:
        return None
    parts = s.strip().split(None, 1)
    if len(parts) == 2 and re.fullmatch(r"[A-Za-z0-9_.\-%]+", parts[0]):
        return (parts[0], parts[1].strip())
    return None


def prune_stale_filters(text, known, pruned_log):
    """Drop Filters/BlockedFilters lines referencing killed findings or dead scopes."""
    lines = text.splitlines(keepends=True)
    out = []
    in_list = None
    for line in lines:
        stripped = line.strip()
        m = re.match(r"^(Filters|BlockedFilters)\s*=\s*\[", stripped)
        if m:
            in_list = m.group(1)
            out.append(line)
            continue
        if in_list and stripped.startswith("]"):
            in_list = None
            out.append(line)
            continue
        if in_list:
            finding = pure_finding_pattern(line)
            if (
                finding is not None
                and finding in PRUNE_CANDIDATES
                and finding not in known
            ):
                pruned_log.append(
                    f"{in_list}: dropped {finding!r} ({PRUNE_CANDIDATES[finding]})"
                )
                continue
            scoped = scoped_entry(line)
            if scoped is not None and scoped in PRUNE_SCOPED:
                pruned_log.append(
                    f"{in_list}: dropped {scoped[0]!r} scoped to {scoped[1]!r} "
                    f"({PRUNE_SCOPED[scoped]})"
                )
                continue
        out.append(line)
    return "".join(out)


def assert_no_flavor_key(flavor, filename, text):
    """Fail if a vendored file sets a top-level ``Flavor`` key.

    ``load_inner``'s pre-pass scans only ``Layer::File`` when selecting the
    vendored distro set; a vendored ``Flavor`` would make the pre-pass and
    ``finalize`` silently disagree on which set to load. Only top-level keys
    count (a ``Flavor`` inside a ``[table]`` is inert).
    """
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            break
        if re.match(r"^Flavor\s*=", stripped):
            raise SystemExit(
                f"vendored file sets Flavor: {flavor}/{filename} "
                "(pre-pass/finalize would disagree)"
            )


def generate(ref_dir=None, pins=None):
    """Return {flavor: {filename: text}} and the provenance text."""
    pins = pins or {}
    result = {}
    for flavor, (sha, date, branch) in PINS.items():
        if flavor in pins:
            sha, date = pins[flavor]
        files = {}
        for filename in FILES[flavor]:
            if ref_dir:
                text = fetch_local(ref_dir, sha, filename)
            else:
                text = fetch_github(sha, filename)
            files[filename] = text
        result[flavor] = {"sha": sha, "date": date, "branch": branch, "files": files}

    known = known_findings()
    pruned_log = []
    for flavor, data in result.items():
        for filename, text in data["files"].items():
            assert_no_flavor_key(flavor, filename, text)
            data["files"][filename] = prune_stale_filters(text, known, pruned_log)

    # Dedupe: an SLFO file byte-identical to its openSUSE counterpart (after
    # pruning) is not vendored twice; the generated Rust consts fall back to
    # the openSUSE copy. This is self-maintaining across syncs: a diverged
    # file is re-materialized, a converged one is dropped by write_all's
    # stale-file removal. Absence stays meaningful — FILES["slfo"] never
    # contains varlink-whitelist.toml, which SLFO deleted upstream.
    deduped = []
    opensuse_files = result["opensuse"]["files"]
    slfo_files = result["slfo"]["files"]
    for filename in list(slfo_files):
        if slfo_files[filename] == opensuse_files[filename]:
            del slfo_files[filename]
            deduped.append(filename)

    provenance = [
        "# Generated by scripts/generate-distro-configs.py — do not edit by hand.",
        "# Upstream owns these configs until rpmlint is fully superseded;",
        "# the monthly distro-config-sync CI job refreshes them.",
        f"# upstream_repo = https://github.com/{UPSTREAM_REPO}",
    ]
    for flavor, data in result.items():
        provenance.append(f"# {flavor}: {data['branch']} @ {data['sha']} ({data['date']})")
    if pruned_log:
        provenance.append("#")
        provenance.append("# Pruned Filters entries (findings rpmcrab killed):")
        for entry in pruned_log:
            provenance.append(f"#   {entry}")
    else:
        provenance.append("# No Filters entries pruned: all referenced findings exist.")
    if deduped:
        provenance.append("#")
        provenance.append("# SLFO files byte-identical to openSUSE (not vendored twice;")
        provenance.append("# the generated Rust consts fall back to the openSUSE copy):")
        for filename in deduped:
            provenance.append(f"#   slfo/{filename}")
    else:
        provenance.append("# No SLFO files deduplicated: every SLFO file differs.")
    provenance.append("")
    return result, "\n".join(provenance), pruned_log, deduped


def emit_rs(deduped):
    """Render the generated Rust consts wiring the vendored files into the binary.

    The manifest is the full FILES[flavor] set, so a deduped SLFO entry keeps
    its `<distro:slfo>/` identity in conf_files while its content comes from
    the openSUSE copy.
    """
    lines = [
        "// Generated by scripts/generate-distro-configs.py — do not edit by hand.",
        "//",
        "// (filename, content) pairs, merged in order after the bundled defaults",
        "// and before XDG-discovered configs — mirroring how the distro",
        "// package's `/etc/xdg/rpmlint/*.toml` layer upstream.",
        "//",
        "// SLFO entries byte-identical to openSUSE fall back to the openSUSE",
        "// copy (see data/distro/PROVENANCE); absence from DISTRO_SLFO_FILES is",
        "// meaningful (SLFO deleted varlink-whitelist.toml).",
        "",
        '/// Vendored openSUSE distro configs (upstream `main` branch).',
        '/// Selected by default (`Flavor = "opensuse"`).',
        "const DISTRO_OPENSUSE_FILES: &[(&str, &str)] = &[",
    ]
    for filename in FILES["opensuse"]:
        lines.extend(
            [
                "    (",
                f'        "{filename}",',
                f'        include_str!("../data/distro/opensuse/{filename}"),',
                "    ),",
            ]
        )
    lines.extend(
        [
            "];",
            "",
            "/// Vendored SLFO distro configs (upstream `opensuse-slfo-main` branch).",
            '/// Selected when `Flavor = "slfo"`.',
            "const DISTRO_SLFO_FILES: &[(&str, &str)] = &[",
        ]
    )
    for filename in FILES["slfo"]:
        src = "opensuse" if filename in deduped else "slfo"
        lines.extend(
            [
                "    (",
                f'        "{filename}",',
                f'        include_str!("../data/distro/{src}/{filename}"),',
                "    ),",
            ]
        )
    lines.append("];")
    return "\n".join(lines) + "\n"


def write_all(result, provenance, deduped):
    for flavor, data in result.items():
        flavor_dir = DISTRO_DIR / flavor
        flavor_dir.mkdir(parents=True, exist_ok=True)
        # Remove files that are no longer vendored (stale).
        for existing in flavor_dir.glob("*.toml"):
            if existing.name not in data["files"]:
                existing.unlink()
        for filename, text in data["files"].items():
            (flavor_dir / filename).write_text(text, encoding="utf-8")
    (DISTRO_DIR / "PROVENANCE").write_text(provenance, encoding="utf-8")
    GENERATED_RS.write_text(emit_rs(deduped), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="diff against the repo")
    ap.add_argument("--ref-dir", help="local rpmlint checkout instead of GitHub")
    ap.add_argument(
        "--pin",
        action="append",
        default=[],
        metavar="FLAVOR=SHA:DATE",
        help="override a pinned SHA (refresh workflow)",
    )
    ap.add_argument(
        "--refresh",
        action="store_true",
        help="resolve pins to the latest upstream commits via the GitHub API",
    )
    args = ap.parse_args()

    pins = {}
    if args.refresh:
        for flavor, (_, _, branch) in PINS.items():
            sha, date = latest_upstream_sha(branch)
            pins[flavor] = (sha, date)
            print(f"{flavor}: {branch} -> {sha[:12]} ({date})", file=sys.stderr)
    for pin in args.pin:
        m = re.fullmatch(r"([a-z]+)=([0-9a-f]{40}):(\d{4}-\d{2}-\d{2})", pin)
        if not m or m.group(1) not in PINS:
            ap.error(f"bad --pin {pin!r}, want FLAVOR=SHA:DATE")
        pins[m.group(1)] = (m.group(2), m.group(3))

    ref_dir = Path(args.ref_dir) if args.ref_dir else None
    result, provenance, pruned_log, deduped = generate(ref_dir=ref_dir, pins=pins)

    if args.check:
        failures = []
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            for flavor, data in result.items():
                for filename, text in data["files"].items():
                    (tmpdir / flavor).mkdir(exist_ok=True)
                    (tmpdir / flavor / filename).write_text(text, encoding="utf-8")
            (tmpdir / "PROVENANCE").write_text(provenance, encoding="utf-8")
            if not GENERATED_RS.exists() or (
                GENERATED_RS.read_text(encoding="utf-8") != emit_rs(deduped)
            ):
                failures.append("drift: src/distro_files_generated.rs")
            for flavor, data in result.items():
                for filename in data["files"]:
                    want = tmpdir / flavor / filename
                    have = DISTRO_DIR / flavor / filename
                    if not have.exists():
                        failures.append(f"missing vendored file: {flavor}/{filename}")
                    elif want.read_text() != have.read_text():
                        failures.append(f"drift: {flavor}/{filename}")
            want_prov = tmpdir / "PROVENANCE"
            have_prov = DISTRO_DIR / "PROVENANCE"
            if not have_prov.exists():
                failures.append("missing vendored file: PROVENANCE")
            elif want_prov.read_text() != have_prov.read_text():
                failures.append("drift: PROVENANCE")
        if failures:
            print("distro config drift detected:", file=sys.stderr)
            for f in failures:
                print(f"  {f}", file=sys.stderr)
            return 1
        print("distro configs match the pinned upstream (plus documented prunes).")
        return 0

    write_all(result, provenance, deduped)
    for entry in pruned_log:
        print(f"pruned: {entry}")
    print(f"wrote {sum(len(d['files']) for d in result.values())} files + PROVENANCE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
