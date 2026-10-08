#!/usr/bin/env python3
"""Vendor upstream distro configs (openSUSE + SLFO) into rpmcrab.

Copies ``configs/openSUSE/*.toml`` from the pinned upstream rpmlint commits
into ``crates/rpmcrab-core/data/distro/<flavor>/``, prunes ``Filters`` /
``BlockedFilters`` entries that reference findings rpmcrab no longer emits,
drops whitelist stanzas for packages gone from Tumbleweed/SLE 16 and stale
pie-executables paths, and stamps provenance.

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
import urllib.error
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
    "postin-without-install-info": "killed: file triggers handle info-dir updates",
    "info-files-without-install-info-postin": "killed: file triggers handle info-dir updates",
    "info-files-without-install-info-postun": "killed: file triggers handle info-dir updates",
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
    "invalid-ldconfig-symlink": "killed: openSUSE config says 'Doesn't seem to make sense'",
    "only-non-binary-in-usr-lib": "killed: openSUSE config says 'Doesn't seem to make sense'",
    "outside-libdir-files": "killed: openSUSE config says 'Doesn't seem to make sense'",
    "invalid-build-requires": "killed: Mandriva-specific, openSUSE doesn't want it",
    "no-provides": "killed: Mandriva-specific, openSUSE doesn't want it",
    "hardcoded-prefix-tag": "killed: Prefix: tag obsolete/ignored",
    "jar-not-indexed": "killed: negligible value",
    "uncompressed-zip": "killed: negligible value",
    "spurious-bracket-in-": "killed: PostCheck stylistic nit",
    "one-line-command-in-": "killed: PostCheck stylistic nit",
}

# (finding, scope) -> reason: Filters entries scoped to dead paths. The finding
# itself stays (its general form is live); only the listed scope is pruned.
# Unlike PRUNE_CANDIDATES these are unconditional: the scope paths are dead
# (SysV init removed), verified by hand when listed here.
PRUNE_SCOPED = {
    ("subdir-in-bin", "/sbin/conf.d/"): "dead SysV scope",
    ("conffile-without-noreplace-flag", "/etc/init.d"): "dead SysV scope",
}

# Packages gone from the distros: whitelist stanzas naming them are pruned.
# A stanza is pruned only when the package is actually absent from the
# flavor's codebase (openSUSE:Factory for the opensuse flavor,
# openSUSE:Leap:16.0 for the slfo flavor — checked live at generation time),
# so the vendored config always matches reality. A package that reappears is
# kept and logged — reintroduced software gets a fresh audit, never a silent
# free pass on a stale stanza.
PRUNE_PACKAGES = {
    # package: reason
    "snapd": "removed from Factory (bsc#1256175, bsc#1248682, bsc#1261739)",
    "lxd": "removed from Factory after the Canonical license change (replaced by incus); still in SLE 16, kept there",
    "nscd": "removed from Factory and SLE 16 (use the system resolver)",
    "foomuuri": "removed from Factory (bsc#1254385)",
    "foomuuri-firewalld": "removed from Factory (bsc#1254385)",
    "sddm-kalpa": "removed from Factory (bsc#1232647)",
    "txnupd-maintenance-tools": "removed from Factory (bsc#1268577)",
    "pam-ssh-agent": "removed from Factory (bsc#1274633)",
    "pam_userpass": "removed from Factory; legacy: not audited",
    "deepin-api": "removed from Factory (security removal); not in SLE 16",
    "kcm_sddm": "removed from Factory; renamed to sddm-kcm6, not in SLE 16 under the old name",
    "passim": "removed from Factory; not in SLE 16",
    "scmon": "removed from Factory; legacy: not audited",
    "pam_csync": "removed from Factory; legacy: not audited",
    "pcfclock": "removed from Factory; not in SLE 16",
}

# Stale pie-executables paths: each entry is (owning package, kind, reason),
# carrying per-entry evidence like PRUNE_PACKAGES does. kind "removed" means
# the owning package is gone from openSUSE:Factory (OBS source API 404);
# kind "moved" means the package still ships but relocated the binary. The
# package is checked live at generation time: a reintroduced "removed"
# package - or a vanished "moved" package, whose relocation evidence is then
# stale - keeps the path and logs loudly, so the drift check fails for a
# fresh audit instead of the path staying silently pruned.
# Verified 2026-10-07 against the openSUSE:Factory filelists (97 paths shipped
# by no TW package). Pruning is scoped to the opensuse flavor: the evidence
# is Factory-only, and the SLE 16 codebase behind the slfo flavor has no
# public per-package query to verify against.
PRUNE_PIE_PATHS = {
    "/usr/bin/achfile": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/bin/adv1tov2": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/bin/aecho": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/bin/afile": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/bin/afppasswd": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/bin/cnid_index": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/bin/dund": ("bluez", "moved", "BlueZ 4 tool, removed in BlueZ 5"),
    "/usr/bin/finger": ("finger", "removed", "finger removed from Factory"),
    "/usr/bin/getzones": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/bin/hidd": ("bluez", "moved", "BlueZ 4 tool, removed in BlueZ 5"),
    "/usr/bin/lppasswd": ("cups", "moved", "cups dropped the 1.x tools"),
    "/usr/bin/megatron": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/bin/nbplkup": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/bin/nbprgstr": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/bin/nbpunrgstr": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/bin/ncplogin": ("ncpfs", "removed", "ncpfs removed from Factory"),
    "/usr/bin/ncpmap": ("ncpfs", "removed", "ncpfs removed from Factory"),
    "/usr/bin/nwsfind": ("ncpfs", "removed", "ncpfs removed from Factory"),
    "/usr/bin/pand": ("bluez", "moved", "BlueZ 4 tool, removed in BlueZ 5"),
    "/usr/bin/pap": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/bin/papstatus": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/bin/psorder": ("cups", "moved", "cups dropped the 1.x tools"),
    "/usr/bin/rcp": ("rsh", "removed", "rsh removed from Factory"),
    "/usr/bin/rexec": ("rsh", "removed", "rsh removed from Factory"),
    "/usr/bin/rlogin": ("rsh", "removed", "rsh removed from Factory"),
    "/usr/bin/rsh": ("rsh", "removed", "rsh removed from Factory"),
    "/usr/bin/showppd": ("cups", "moved", "cups dropped the 1.x tools"),
    "/usr/bin/testprns": ("cups", "moved", "cups dropped the 1.x tools"),
    "/usr/lib/mit/bin/gss-client": ("krb5", "moved", "krb5 installs to /usr/bin, not /usr/lib/mit"),
    "/usr/lib/mit/bin/kdestroy": ("krb5", "moved", "krb5 installs to /usr/bin, not /usr/lib/mit"),
    "/usr/lib/mit/bin/kinit": ("krb5", "moved", "krb5 installs to /usr/bin, not /usr/lib/mit"),
    "/usr/lib/mit/bin/klist": ("krb5", "moved", "krb5 installs to /usr/bin, not /usr/lib/mit"),
    "/usr/lib/mit/bin/kpasswd": ("krb5", "moved", "krb5 installs to /usr/bin, not /usr/lib/mit"),
    "/usr/lib/mit/bin/krb524init": ("krb5", "moved", "krb5 installs to /usr/bin, not /usr/lib/mit"),
    "/usr/lib/mit/bin/ksu": ("krb5", "moved", "krb5 installs to /usr/bin, not /usr/lib/mit"),
    "/usr/lib/mit/bin/kvno": ("krb5", "moved", "krb5 installs to /usr/bin, not /usr/lib/mit"),
    "/usr/lib/mit/bin/sclient": ("krb5", "moved", "krb5 installs to /usr/bin, not /usr/lib/mit"),
    "/usr/lib/mit/bin/sim_client": ("krb5", "moved", "krb5 installs to /usr/bin, not /usr/lib/mit"),
    "/usr/lib/mit/bin/uuclient": ("krb5", "moved", "krb5 installs to /usr/bin, not /usr/lib/mit"),
    "/usr/lib/mit/bin/v4rcp": ("krb5", "moved", "krb5 installs to /usr/bin, not /usr/lib/mit"),
    "/usr/lib/mit/sbin/gss-server": ("krb5", "moved", "krb5 installs to /usr/sbin, not /usr/lib/mit"),
    "/usr/lib/mit/sbin/kadmin": ("krb5", "moved", "krb5 installs to /usr/sbin, not /usr/lib/mit"),
    "/usr/lib/mit/sbin/kadmin.local": ("krb5", "moved", "krb5 installs to /usr/sbin, not /usr/lib/mit"),
    "/usr/lib/mit/sbin/kadmind": ("krb5", "moved", "krb5 installs to /usr/sbin, not /usr/lib/mit"),
    "/usr/lib/mit/sbin/kdb5_util": ("krb5", "moved", "krb5 installs to /usr/sbin, not /usr/lib/mit"),
    "/usr/lib/mit/sbin/kprop": ("krb5", "moved", "krb5 installs to /usr/sbin, not /usr/lib/mit"),
    "/usr/lib/mit/sbin/kpropd": ("krb5", "moved", "krb5 installs to /usr/sbin, not /usr/lib/mit"),
    "/usr/lib/mit/sbin/krb524d": ("krb5", "moved", "krb5 installs to /usr/sbin, not /usr/lib/mit"),
    "/usr/lib/mit/sbin/krb5kdc": ("krb5", "moved", "krb5 installs to /usr/sbin, not /usr/lib/mit"),
    "/usr/lib/mit/sbin/ktutil": ("krb5", "moved", "krb5 installs to /usr/sbin, not /usr/lib/mit"),
    "/usr/lib/mit/sbin/sim_server": ("krb5", "moved", "krb5 installs to /usr/sbin, not /usr/lib/mit"),
    "/usr/lib/mit/sbin/sserver": ("krb5", "moved", "krb5 installs to /usr/sbin, not /usr/lib/mit"),
    "/usr/lib/mit/sbin/uuserver": ("krb5", "moved", "krb5 installs to /usr/sbin, not /usr/lib/mit"),
    "/usr/lib/news/bin/innbind": ("inn", "moved", "inn moved to /usr/libexec"),
    "/usr/lib/news/bin/innd": ("inn", "moved", "inn moved to /usr/libexec"),
    "/usr/lib/news/bin/rnews": ("inn", "moved", "inn moved to /usr/libexec"),
    "/usr/lib/openldap/slapd": ("openldap2", "moved", "openldap2 ships the slapd binary at /usr/lib64/slapd"),
    "/usr/lib/sudo/sesh": ("sudo", "moved", "sesh moved to /usr/libexec/sudo/sesh"),
    "/usr/sbin/afpd": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/sbin/amdd": ("amd", "removed", "amd removed from Factory"),
    "/usr/sbin/arping": ("iputils", "moved", "iputils moved to /usr/bin/arping"),
    "/usr/sbin/atalkd": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/sbin/bluetoothd": ("bluez", "moved", "moved to /usr/libexec/bluetooth/bluetoothd in BlueZ 5"),
    "/usr/sbin/clockdiff": ("iputils", "moved", "iputils moved to /usr/bin/clockdiff"),
    "/usr/sbin/cnid_dbd": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/sbin/cnid_metad": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/sbin/dnssec-keygen": ("bind", "moved", "bind moved to /usr/bin/dnssec-keygen"),
    "/usr/sbin/dnssec-signzone": ("bind", "moved", "bind moved to /usr/bin/dnssec-signzone"),
    "/usr/sbin/hciattach": ("bluez", "moved", "moved to /usr/bin/hciattach in BlueZ 5"),
    "/usr/sbin/hciconfig": ("bluez", "moved", "moved to /usr/bin/hciconfig in BlueZ 5"),
    "/usr/sbin/hid2hci": ("bluez", "moved", "moved to /usr/lib/udev/hid2hci in BlueZ 5"),
    "/usr/sbin/httpd2": ("apache2", "moved", "apache 2.2 name, renamed in 2.4"),
    "/usr/sbin/httpd2-prefork": ("apache2", "moved", "apache 2.2 name, renamed in 2.4"),
    "/usr/sbin/httpd2-worker": ("apache2", "moved", "apache 2.2 name, renamed in 2.4"),
    "/usr/sbin/in.fingerd": ("finger", "removed", "fingerd removed from Factory"),
    "/usr/sbin/in.rexecd": ("rsh", "removed", "rsh removed from Factory"),
    "/usr/sbin/in.rlogind": ("rsh", "removed", "rsh removed from Factory"),
    "/usr/sbin/in.rshd": ("rsh", "removed", "rsh removed from Factory"),
    "/usr/sbin/lwresd": ("bind", "moved", "lwresd dropped in bind 9.16; ships nowhere in TW"),
    "/usr/sbin/named-checkconf": ("bind", "moved", "bind moved to /usr/bin/named-checkconf"),
    "/usr/sbin/named-checkzone": ("bind", "moved", "bind moved to /usr/bin/named-checkzone"),
    "/usr/sbin/nscd": ("nscd", "removed", "nscd removed from Factory"),
    "/usr/sbin/ntlm_auth": ("samba", "moved", "samba moved to /usr/bin/ntlm_auth"),
    "/usr/sbin/papd": ("netatalk", "removed", "netatalk removed from Factory"),
    "/usr/sbin/praliases": ("sendmail", "moved", "sendmail moved to /usr/bin/praliases"),
    "/usr/sbin/rarpd": ("rarpd", "removed", "rarpd removed from Factory"),
    "/usr/sbin/rotatelogs2": ("apache2", "moved", "apache 2.2 name, renamed in 2.4"),
    "/usr/sbin/rpc.rwalld": ("rwalld", "removed", "rwalld removed from Factory"),
    "/usr/sbin/rpc.yppasswdd": ("ypserv", "removed", "ypserv removed from Factory"),
    "/usr/sbin/rpc.ypxfrd": ("ypserv", "removed", "ypserv removed from Factory"),
    "/usr/sbin/squidclient": ("squid", "moved", "squid does not ship squidclient"),
    "/usr/sbin/suexec2": ("apache2", "moved", "apache 2.2 name, renamed in 2.4"),
    "/usr/sbin/tracepath": ("iputils", "moved", "iputils moved to /usr/bin/tracepath"),
    "/usr/sbin/tracepath6": ("iputils", "moved", "tracepath6 folded into tracepath (/usr/bin/tracepath); the name ships nowhere in TW"),
    "/usr/sbin/utempter": ("libutempter", "removed", "libutempter removed from Factory"),
    "/usr/sbin/yppush": ("ypserv", "removed", "ypserv removed from Factory"),
    "/usr/sbin/ypserv": ("ypserv", "removed", "ypserv removed from Factory"),
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


WHITELIST_TABLES = {
    "FileDigestGroup",
    "WorldWritableWhitelist",
    "SystemdTmpfilesWhitelist",
    "DeviceFilesWhitelist",
}

_package_presence_cache = {}

# Project checked per flavor: the opensuse flavor tracks Tumbleweed, the
# slfo flavor tracks the SLE 16 codebase (openSUSE:Leap:16.0 is built on it).
FLAVOR_PROJECTS = {
    "opensuse": ("openSUSE:Factory",),
    "slfo": ("openSUSE:Leap:16.0",),
}


def package_present(pkg, flavor):
    """True if the package exists in the flavor's distro codebase."""
    key = (pkg, flavor)
    if key not in _package_presence_cache:
        present = False
        for project in FLAVOR_PROJECTS[flavor]:
            url = f"https://api.opensuse.org/public/source/{project}/{pkg}"
            req = urllib.request.Request(
                url, headers={"User-Agent": "rpmcrab-distro-config-sync"}
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    if resp.status == 200:
                        present = True
                        break
            except urllib.error.HTTPError as e:
                if e.code != 404:
                    raise
        _package_presence_cache[key] = present
    return _package_presence_cache[key]


_package_re = re.compile(r'^package\s*=\s*"([^"]+)"', re.MULTILINE)
_packages_re = re.compile(r"^packages\s*=\s*\[(.*?)\]", re.MULTILINE | re.DOTALL)


def split_stanzas(text):
    """Split TOML text at top-level [[Table]] lines; sub-tables stay attached."""
    marks = [
        (m.start(), m.group(1))
        for m in re.finditer(r"^\[\[([A-Za-z]+)\]\]$", text, re.MULTILINE)
    ]
    if not marks:
        return [("preamble", text)]
    chunks = []
    if marks[0][0] > 0:
        chunks.append(("preamble", text[: marks[0][0]]))
    for i, (pos, table) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        chunks.append((table, text[pos:end]))
    return chunks


def prune_stale_packages(text, pruned_log, flavor):
    """Drop whitelist stanzas whose package(s) are all gone from the flavor's distro."""
    out = []
    for table, block in split_stanzas(text):
        if table not in WHITELIST_TABLES:
            out.append(block)
            continue
        pkgs = []
        m = _package_re.search(block)
        if m:
            pkgs = [m.group(1)]
        else:
            m = _packages_re.search(block)
            if m:
                pkgs = re.findall(r'"([^"]+)"', m.group(1))
        if pkgs and all(p in PRUNE_PACKAGES for p in pkgs):
            if all(not package_present(p, flavor) for p in pkgs):
                pruned_log.append(
                    "whitelist: dropped [[%s]] stanza for %s"
                    % (
                        table,
                        ", ".join("%r (%s)" % (p, PRUNE_PACKAGES[p]) for p in pkgs),
                    )
                )
                continue
            pruned_log.append(
                "whitelist: KEPT [[%s]] stanza for %s — package present in the "
                "flavor's distro, needs a fresh audit before any allowance "
                "is trusted" % (table, ", ".join(pkgs))
            )
        out.append(block)
    return "".join(out)


def _usrmerge_norm(path):
    if path.startswith("/sbin/"):
        return "/usr/sbin/" + path[len("/sbin/") :]
    if path.startswith("/bin/"):
        return "/usr/bin/" + path[len("/bin/") :]
    return path


def prune_pie_paths(text, pruned_log, flavor):
    """Drop pie-executables.toml entries for paths no distro package ships.

    Each entry names its owning package, checked live against the flavor's
    distro (OBS source API, like PRUNE_PACKAGES): a reintroduced "removed"
    package - or a vanished "moved" package, whose relocation evidence is
    then stale - keeps the path and logs loudly, so the drift check fails
    for a fresh audit instead of the path staying silently pruned.
    """
    out = []
    for line in text.splitlines(keepends=True):
        m = re.fullmatch(r'"([^"]+)",?', line.strip())
        norm = _usrmerge_norm(m.group(1)) if m else None
        if m and norm in PRUNE_PIE_PATHS:
            pkg, kind, reason = PRUNE_PIE_PATHS[norm]
            present = package_present(pkg, flavor)
            if (kind == "removed" and present) or (kind == "moved" and not present):
                pruned_log.append(
                    "pie-executables: KEPT stale path %r - owning package %r "
                    "changed state in the flavor's distro (%s), needs a fresh "
                    "audit" % (m.group(1), pkg, reason)
                )
                out.append(line)
                continue
            pruned_log.append(
                "pie-executables: dropped stale path %r (%s)"
                % (m.group(1), reason)
            )
            continue
        out.append(line)
    return "".join(out)


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
    pkg_pruned_log = []
    pie_pruned_log = []
    for flavor, data in result.items():
        for filename, text in data["files"].items():
            assert_no_flavor_key(flavor, filename, text)
            text = prune_stale_filters(text, known, pruned_log)
            text = prune_stale_packages(text, pkg_pruned_log, flavor)
            if filename == "pie-executables.toml" and flavor == "opensuse":
                # Factory-only evidence (see PRUNE_PIE_PATHS): the SLE 16
                # codebase behind the slfo flavor has no public
                # per-package query, so slfo keeps the upstream entries.
                text = prune_pie_paths(text, pie_pruned_log, flavor)
            data["files"][filename] = text

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
        seen = set()
        for entry in pruned_log:
            if entry not in seen:
                seen.add(entry)
                provenance.append(f"#   {entry}")
    else:
        provenance.append("# No Filters entries pruned: all referenced findings exist.")
    if pkg_pruned_log:
        provenance.append("#")
        provenance.append(
            "# Pruned whitelist stanzas (packages gone from Tumbleweed/SLE 16):"
        )
        for entry in pkg_pruned_log:
            provenance.append(f"#   {entry}")
    if pie_pruned_log:
        provenance.append("#")
        provenance.append(
            "# Pruned pie-executables paths (shipped by no Tumbleweed package):"
        )
        for entry in pie_pruned_log:
            provenance.append(f"#   {entry}")
    if deduped:
        provenance.append("#")
        provenance.append("# SLFO files byte-identical to openSUSE (not vendored twice;")
        provenance.append("# the generated Rust consts fall back to the openSUSE copy):")
        for filename in deduped:
            provenance.append(f"#   slfo/{filename}")
    else:
        provenance.append("# No SLFO files deduplicated: every SLFO file differs.")
    provenance.append("")
    return (
        result,
        "\n".join(provenance),
        pruned_log,
        pkg_pruned_log,
        pie_pruned_log,
        deduped,
    )


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
    result, provenance, pruned_log, pkg_pruned_log, pie_pruned_log, deduped = generate(
        ref_dir=ref_dir, pins=pins
    )

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
    for entry in pruned_log + pkg_pruned_log + pie_pruned_log:
        print(f"pruned: {entry}")
    print(f"wrote {sum(len(d['files']) for d in result.values())} files + PROVENANCE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
