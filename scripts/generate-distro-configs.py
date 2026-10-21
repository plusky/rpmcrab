#!/usr/bin/env python3
"""Vendor the upstream distro configs (the SUSE flavor) into rpmcrab.

Copies ``configs/openSUSE/*.toml`` from the pinned upstream rpmlint commit
into ``crates/rpmcrab-core/data/distro/opensuse/``, prunes ``Filters`` /
``BlockedFilters`` entries that reference findings rpmcrab no longer emits,
drops ``Filters`` entries for live findings rpmcrab deliberately surfaces
(see DROP_LIVE_FILTERS), drops duplicate ``Filters`` lines and lines
subsumed by a broader line for the same finding (see dedupe_filters),
drops whitelist stanzas for packages gone from
Tumbleweed and stale pie-executables paths, retargets ``Filters``
entries whose target path moved (see RETARGET_FILTERS), appends the extra
Filters/Checks rpmcrab carries on top of upstream, removes the Checks
the flavor deliberately does not run, strips the
``BadnessThreshold`` line from the flavor config (see
strip_badness_threshold; upstream's ``scoring.toml`` is not vendored
at all — issue #699), applies the Factory-adjudicated digest records
(see DIGEST_ADJUDICATIONS), and stamps provenance.

The checked-in files are the build's source of truth; this script runs by hand
and in CI (drift check + monthly refresh), never at build time.

Upstream remains the owner of these configs until rpmlint is fully superseded:
the monthly ``distro-config-sync`` CI job opens a refresh PR when upstream
moves, and the ``distro-config-drift`` CI job fails when the vendored copies
diverge from what this script produces at the pinned SHAs.

Usage:
    scripts/generate-distro-configs.py [--check] [--ref-dir DIR]
        [--pin opensuse=SHA:DATE] [--refresh]

    --check      regenerate into a temp dir and diff against the repo;
                 exit 1 with a unified diff on any divergence.
                 Sync-managed whitelist files and their PROVENANCE pins
                 are owned by the daily sync job and skipped here.
    --refresh    resolve PINS to the latest upstream commits, persist them
                 into the PINS constant above, and regenerate (monthly job).
    --ref-dir    use a local rpmlint checkout instead of fetching from
                 GitHub (the pinned SHA must exist in it).
    --pin        override a pinned SHA for the refresh workflow; DATE is the
                 commit date (YYYY-MM-DD) used for the provenance stamp.

Refresh procedure:
    The vendored files are generator output end to end: a change to a
    shipped file is made in this script (the delta tables or the
    emission code) and regenerated, so the tree always matches what the
    generator produces at the pins. The monthly distro-config-sync job
    performs the refresh as a PR — it resolves the pins to the latest
    upstream commits, regenerates, and opens the PR with the provenance
    (old and new SHAs, prune log). A manual refresh runs the same steps
    by hand:

        scripts/generate-distro-configs.py --refresh
        scripts/test_generate_distro_configs.py
        UPDATE_SEVERITY_INVENTORY=1 cargo test -p rpmcrab-core \
            --test severity_inventory

    The generator test suite runs because a refresh re-derives the
    vendored set from new upstream data; the severity inventory
    regenerates because the vendored configs carry [Scoring] and
    [SeverityOverrides] tables the inventory derives from. The weekly
    upstream-config-watch job reports upstream movement between
    refreshes — the upstream commits in the pin range and the vendored
    files a refresh rewrites — on a tracking issue.
"""

import argparse
import difflib
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
import http.client
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
        "513f17e8aad7d0bece1be4e46316dc8e97bd1d65",
        "2026-10-20",
        "opensuse",
    ),
}

# The vendored file set (configs/openSUSE/*.toml at the pinned SHA).
# Upstream's scoring.toml and scoring-strict.override.toml are deliberately
# not vendored (issue #699): shipped configs carry no badness — severity is
# decided at the emission sites. Users who want a [Scoring] table can still
# drop one into their XDG config dir or pass it with -c.
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

# Whitelist files that carry per-package stanzas. The daily
# sync-upstream-whitelists job advances these day-to-day at branch TIPs while
# this script regenerates everything else at the monthly PINS, so --check
# skips them (and the whitelist pin below): a successful daily
# sync must never read as drift. Canonical home of this list (the sync tool
# loads it from here; guarded by test_sync_sets_match_generator).
SYNC_MANAGED_FILES = [
    "cron-whitelist.toml",
    "dbus-services.toml",
    "device-files-whitelist.toml",
    "pam-modules.toml",
    "permissions-whitelist.toml",
    "polkit-rules-whitelist.toml",
    "sudoers-whitelist.toml",
    "sysctl-whitelist.toml",
    "systemd-tmpfiles.toml",
    "varlink-whitelist.toml",
    "world-writable-whitelist.toml",
    "zypper-plugins.toml",
]

# Digest records adjudicated from Factory content (issue #760, decision
# D7 of the single-flavor programme): for these (file, stanza packages,
# path) records the acceptable sha256 set is the set the Factory corpus
# actually ships for the path, measured over the full corpus — not the
# set either upstream branch recorded. Upstream's openSUSE branch records
# a stale hash for cups' cups.conf (013f81b3…) while Factory ships the
# file whose xml digest is 1bbed8c1…; the record below carries the
# Factory hash so the shipped file verifies. Applied by generate() when
# vendoring and by the daily sync's plan_merge to both sides of a merge,
# so neither path can silently restore the stale record. Keys are
# (filename, frozenset(packages), path); the value is the full
# replacement hash list for that record.
DIGEST_ADJUDICATIONS = {
    (
        "dbus-services.toml",
        frozenset({"cups"}),
        "/usr/share/dbus-1/system.d/cups.conf",
    ): ["1bbed8c1ecac00e546a3659235855aa2e88ec1142b3908b3d662e68ad4e664fe"],
}


def apply_digest_adjudications(text, filename):
    """Rewrite digest records named in DIGEST_ADJUDICATIONS to the
    adjudicated hash sets. Returns (text, log lines).

    A record is identified by its file, the owning stanza's package
    set and the digest entry's path. Digest entries are
    ``[[<Group>.digests]]`` sub-tables carrying ``path =`` and
    ``hash =`` lines; the entries for an adjudicated path are rebuilt
    to carry exactly the adjudicated hashes. Text with no adjudicated
    record in it passes through byte-identical.
    """
    log = []
    targets = {}
    for (fn, pkgs, path), hashes in DIGEST_ADJUDICATIONS.items():
        if fn == filename:
            targets.setdefault(pkgs, {})[path] = hashes
    if not targets:
        return text, log

    lines = text.splitlines(keepends=True)
    # Segment the text: ("raw", lines) spans and ("entry", lines,
    # packages, path) digest-entry blocks. `packages` is the package
    # set of the stanza that owns the entry.
    segments = []
    raw = []
    packages = set()
    i = 0
    while i < len(lines):
        ln = lines[i]
        hdr = re.match(r"\s*\[\[([A-Za-z0-9_.]+)\]\]\s*$", ln)
        if hdr and hdr.group(1).endswith(".digests"):
            block = [ln]
            path = None
            i += 1
            while i < len(lines) and not re.match(r"\s*\[", lines[i]):
                block.append(lines[i])
                pm = re.match(r'\s*path\s*=\s*"([^"]+)"', lines[i])
                if pm:
                    path = pm.group(1)
                i += 1
            if raw:
                segments.append(("raw", raw))
                raw = []
            segments.append(("entry", block, frozenset(packages), path))
            continue
        if hdr:
            packages = set()
            raw.append(ln)
            i += 1
            continue
        if re.match(r"\s*\[", ln):
            packages = set()
            raw.append(ln)
            i += 1
            continue
        pm = re.match(r'\s*package\s*=\s*"([^"]+)"', ln)
        if pm:
            packages.add(pm.group(1))
        pm = re.match(r"\s*packages\s*=\s*\[([^\]]*)\]", ln)
        if pm:
            packages.update(re.findall(r'"([^"]+)"', pm.group(1)))
        raw.append(ln)
        i += 1
    if raw:
        segments.append(("raw", raw))

    # Group entry segments by (packages, path); rebuild adjudicated ones.
    by_record = {}
    for idx, seg in enumerate(segments):
        if seg[0] == "entry":
            by_record.setdefault((seg[2], seg[3]), []).append(idx)
    drop = set()
    replace = {}
    for (pkgs, path), idxs in by_record.items():
        hashes = targets.get(pkgs, {}).get(path)
        if hashes is None:
            continue
        first = idxs[0]
        block = segments[first][1]
        hash_idx = next(
            (j for j, l in enumerate(block) if re.match(r"\s*hash\s*=", l)),
            None,
        )
        if hash_idx is None:
            continue
        rebuilt_first = list(block)
        newline = "\n" if block[hash_idx].endswith("\n") else ""
        indent = re.match(r"(\s*)hash\s*=", block[hash_idx]).group(1)
        rebuilt_first[hash_idx] = f'{indent}hash = "{hashes[0]}"{newline}'
        changed = rebuilt_first != block
        replace[first] = rebuilt_first
        # Extra hashes get cloned blocks right after the first entry.
        clones = []
        for h in hashes[1:]:
            clone = list(block)
            clone[hash_idx] = f'{indent}hash = "{h}"{newline}'
            clones.append(clone)
            changed = True
        if clones:
            replace[first] = rebuilt_first + [
                line for clone in clones for line in clone
            ]
        for j in idxs[1:]:
            drop.add(j)
            changed = True
        if changed:
            log.append(
                f"digest: adjudicated {filename} record for "
                f"{', '.join(sorted(pkgs))} path {path} to the "
                "Factory-shipped hash set (issue #760)"
            )
    out = []
    for idx, seg in enumerate(segments):
        if idx in drop:
            continue
        if idx in replace:
            out.extend(replace[idx])
        elif seg[0] == "entry":
            out.extend(seg[1])
        else:
            out.extend(seg[1])
    return "".join(out), log


# PROVENANCE lines owned by the daily sync (the TIP it merged).
# Stripped before --check comparison; the sync keeps them accurate.
SYNC_OWNED_PROVENANCE_PREFIXES = (
    "# opensuse-whitelists:",
)


def strip_sync_owned_provenance(text):
    """Drop sync-influenced lines for drift comparison.

    The whitelist pin follows the daily TIP and is owned day-to-day by
    sync-upstream-whitelists, whose own tests guard it.
    """
    lines = [
        line
        for line in text.splitlines()
        if not line.startswith(SYNC_OWNED_PROVENANCE_PREFIXES)
    ]
    return "\n".join(lines)


def check_rs_files(regen_files):
    """File set for the --check manifest comparison.

    The regenerated set is the manifest, so the comparison is direct.
    """
    return list(regen_files)

# The openSUSE config's spelling-error jargon filter. The words are
# RPM-ecosystem technical terms the hunspell en_US dictionary lacks, in
# both the system dictionary and the LibreOffice dictionaries pinned by
# scripts/install-hunspell-dicts.sh, so a provisioned reference flags
# them too; issue #778 has the evidence (the rpm 6.1.0 package set flags
# all four in the Summary(C) and %description -l C detail shapes).
# Fedora's rpmlint config carries the same kind of spelling-error
# jargon list, citing
# https://bugzilla.redhat.com/show_bug.cgi?id=1424684#c9, and its list
# includes namespace. The word list itself lives in a line-itemized
# TOML next to this script so it stays reviewable as it grows; the
# filter pattern is built from it here.
SPELLING_JARGON_TOML = (
    Path(__file__).resolve().parent / "opensuse-spelling-jargon.toml"
)


def load_spelling_jargon(path=SPELLING_JARGON_TOML):
    """Load the spelling-error jargon words from their TOML file.

    Returns the words sorted. The TOML is the reviewable source of the
    list, so duplicates and non-string entries fail loudly instead of
    silently warping the built filter.
    """
    try:
        import tomllib
    except ModuleNotFoundError:
        sys.stderr.write(
            "error: generate-distro-configs.py needs Python 3.11+ (tomllib)\n"
        )
        raise
    with open(path, "rb") as f:
        data = tomllib.load(f)
    words = data["words"]
    if not all(isinstance(word, str) for word in words):
        raise ValueError(f"{path}: 'words' must be a list of strings")
    if len(set(words)) != len(words):
        raise ValueError(f"{path}: 'words' contains duplicates")
    return sorted(words)


def _spelling_jargon_word_pattern(word):
    """One jargon word as a regex alternative.

    The spelling check reports words as written, so the first letter
    is case-flexible (a jargon word at the start of a sentence arrives
    capitalised) and a trailing plural s is optional (the plural of a
    jargon term is the same jargon). The rest of the word is
    regex-escaped.
    """
    first = word[0]
    if first.isascii() and first.isalpha():
        head = f"[{first.upper()}{first.lower()}]"
    else:
        head = re.escape(first)
    return head + re.escape(word[1:]) + "s?"


def spelling_jargon_filter(words):
    """Build the spelling-error Filters pattern for the jargon words.

    One alternative per word (see _spelling_jargon_word_pattern),
    closed by a word boundary so a word merely starting with a jargon
    word still surfaces; the two detail shapes are the ones the
    spelling check renders (Summary(<lang>) and %description
    -l <lang>), and the locale class also carries the digits and
    hyphen of real locales such as C.UTF-8 and de_DE.UTF-8.
    """
    alternation = "|".join(_spelling_jargon_word_pattern(word) for word in words)
    return (
        r"^.*spelling-error (Summary\([A-Za-z0-9_@.-]+\)|%description -l [A-Za-z0-9_@.-]+) ("
        + alternation
        + r")\b"
    )


SPELLING_JARGON_WORDS = load_spelling_jargon()

# Extra Filters appended to the openSUSE config that do not come from upstream
# rpmlint's configs/openSUSE/*.toml. Each entry pairs the filter pattern
# with the reason the generator logs for it in data/distro/PROVENANCE.
# The reference loads the mingw entries from
# /opt/testing/share/rpmlint/mingw32.toml and mingw64.toml, which are shipped
# by the mingw32-filesystem and mingw64-filesystem packages (converted from
# their mingw{32,64}-rpmlintrc sources at package build time). They are part
# of the reference's effective distro config for mingw packages, so rpmcrab
# vendors them here to match. Kept minimal: only the filters for findings
# rpmcrab actually emits are included; the rest (e.g. devel-file-in-non-devel,
# mono-versioned-deps-missing) are added if their findings start diverging.
EXTRA_FILTERS = [
    # *.dll.a and *.a files are permitted arch-independent objects
    # (mingw32-filesystem's mingw32-rpmlintrc).
    (
        r"^mingw32-.*arch-independent-package-contains-binary-or-object.*\.a$",
        "mingw -filesystem packages' rpmlintrc",
    ),
    # Same for mingw64 (mingw64-filesystem's mingw64-rpmlintrc).
    (
        r"^mingw64-.*arch-independent-package-contains-binary-or-object.*\.a$",
        "mingw -filesystem packages' rpmlintrc",
    ),
    # Spelling-error filter for the jargon word list in
    # scripts/opensuse-spelling-jargon.toml, built by
    # spelling_jargon_filter (see SPELLING_JARGON_TOML above).
    (
        spelling_jargon_filter(SPELLING_JARGON_WORDS),
        "RPM-ecosystem jargon the hunspell en_US dictionary lacks"
        " (issue #778); the words are itemised in"
        " scripts/opensuse-spelling-jargon.toml",
    ),
]

# Extra Checks enabled in the openSUSE config that upstream rpmlint lists in
# no shipped config (neither its configdefaults.toml nor the openSUSE branch's
# opensuse.toml), so the checks never run there. XinetdDepCheck is implemented
# and its deprecation message is the point of the check, so rpmcrab enables
# it deliberately. PAMModulesCheck is listed in rpmlint main's opensuse.toml
# but not in the shipping opensuse branch config, and upstream main pairs it
# with a flat PAMAuthorizedModules list that no longer matches Factory
# (measured 2026-10-13: it would flag 16 legitimate modules, e.g.
# pam_systemd_home.so). rpmcrab enables the check and derives the authorized
# modules from the FileDigestGroup data instead (see PAMModulesCheck).
# Ledgered in tests/parity/divergences.toml.
EXTRA_CHECKS = [
    "XinetdDepCheck",
    "PAMModulesCheck",
]

# Checks upstream lists in the openSUSE config that rpmcrab deliberately
# does NOT run under the flavor. Currently empty: the snapshot
# layout AtomicUpdateCheck enforces is a transactional-update requirement
# that binds every flavor (issue #698), so the check runs in the bundled
# default config and in the vendored flavor config and nothing is
# excluded here. Config list merging appends, so a check listed here must
# also stay out of the bundled default config
# (crates/rpmcrab-core/data/configdefaults.toml).
EXCLUDED_CHECKS = []

# Packages the vendored distro config names in the `SystemdPresetPackages`
# key: the distribution's preset packages, the only packages allowed to
# ship systemd preset files (the `systemd-preset-packaged` finding exempts
# exactly these names). The key is rpmcrab-only; upstream configs carry
# no such list, so the vendored opensuse.toml carries the set. The set is
# the union of the preset shippers verified in openSUSE Factory and in
# SLFO:Main: the openSUSE branding packages and
# `systemd-presets-common-SUSE` ship in Factory, the SLE/Elemental
# branding packages ship in SLFO:Main, and a name shipped by only one
# product is inert in the other. `systemd` and `systemd-mini` ship
# systemd's own fallback presets in both products; `systemd-mini` is not
# a standalone source package in either — it is the `mini` multibuild
# flavor of the `systemd` source package, and its binary ships the same
# preset files as `systemd`.
SYSTEMD_PRESET_PACKAGES = [
    "systemd",
    "systemd-mini",
    "systemd-presets-branding-Aeon",
    "systemd-presets-branding-Kalpa",
    "systemd-presets-branding-MicroOS",
    "systemd-presets-branding-openSUSE",
    "systemd-presets-branding-transactional-server",
    "systemd-presets-common-SUSE",
    "systemd-presets-branding-SLE",
    "systemd-presets-branding-SLE_immutable",
    "systemd-presets-branding-Elemental",
    "systemd-presets-branding-SLE-SAP",
    "systemd-presets-branding-SLE-SAP_immutable",
]

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
    "devel-package-with-non-devel-group": "killed: openSUSE dropped the Group tag",
    "no-group-tag": "killed: openSUSE dropped the Group tag",
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
    # upstream: https://github.com/rpm-software-management/rpmlint/blob/main/rpmlint/checks/BinariesCheck.py
    "invalid-ldconfig-symlink": "killed: openSUSE config says 'Doesn't seem to make sense'",
    # upstream: https://github.com/rpm-software-management/rpmlint/blob/main/rpmlint/checks/FilesCheck.py
    "only-non-binary-in-usr-lib": "killed: openSUSE config says 'Doesn't seem to make sense'",
    # upstream: https://github.com/rpm-software-management/rpmlint/blob/main/rpmlint/checks/FilesCheck.py
    "outside-libdir-files": "killed: openSUSE config says 'Doesn't seem to make sense'",
    # upstream: https://github.com/rpm-software-management/rpmlint/blob/main/rpmlint/checks/TagsCheck.py
    "invalid-build-requires": "killed: Mandriva-specific, openSUSE doesn't want it",
    # upstream: https://github.com/rpm-software-management/rpmlint/blob/main/rpmlint/checks/TagsCheck.py
    "no-provides": "killed: Mandriva-specific, openSUSE doesn't want it",
    # upstream: https://github.com/rpm-software-management/rpmlint/blob/main/rpmlint/checks/TagsCheck.py
    "no-major-in-name": "killed: Mandriva-specific, openSUSE doesn't want it",
    # upstream: https://github.com/rpm-software-management/rpmlint/blob/main/rpmlint/checks/SpecCheck.py
    "lib-package-without-%mklibname": "killed: Mandriva-specific, openSUSE doesn't want it",
    # upstream: https://github.com/rpm-software-management/rpmlint/blob/main/rpmlint/checks/TagsCheck.py
    "hardcoded-prefix-tag": "killed: Prefix: tag obsolete/ignored",
    # upstream: https://github.com/rpm-software-management/rpmlint/blob/main/rpmlint/checks/ZipCheck.py
    "jar-not-indexed": "killed: negligible value",
    # upstream: https://github.com/rpm-software-management/rpmlint/blob/main/rpmlint/checks/ZipCheck.py
    "uncompressed-zip": "killed: negligible value",
    # upstream: https://github.com/rpm-software-management/rpmlint/blob/main/rpmlint/checks/PostCheck.py
    "spurious-bracket-in-": "killed: PostCheck stylistic nit",
    # upstream: https://github.com/rpm-software-management/rpmlint/blob/main/rpmlint/checks/PostCheck.py
    "one-line-command-in-": "killed: PostCheck stylistic nit",
    # upstream: https://github.com/rpm-software-management/rpmlint/blob/main/rpmlint/checks/PostCheck.py
    "postin-without-ghost-file-creation": "killed: check dropped (issue #562); literal-substring model predates tmpfiles/update-alternatives, fires on 97.9% of %ghost declarations",
    # Filtered by both upstream distro configs but emitted by no check,
    # upstream or here (the name survives only in those configs): the port
    # never had this finding — a non-UTF-8 header tag aborts the read.
    "tag-not-utf8": "never ported: non-UTF-8 header tags abort the read; no finding is emitted",
}

# Filters dropped for findings that are still live: upstream's distro
# config hides the finding entirely, but the port deliberately surfaces
# it, so the filter goes. Unlike PRUNE_CANDIDATES these are unconditional
# (the finding being present in the tree is the point, not a stale-filter
# smell). Each entry is a deliberate divergence from the reference,
# ledgered in tests/parity/divergences.toml.
DROP_LIVE_FILTERS = {
    # finding: reason
    "no-manual-page-for-binary": "demoted to Info (rpmcrab#484): a missing manpage is upstream debt; surfaced as info instead of filtered away",
    # Not surfaced-versus-hidden like the entry above: the check is
    # gated off by KernelModuleRPMsOK = true, the default in both
    # implementations' configdefaults, and no vendored config overrides
    # it, so under the shipped flavours the filter can never match
    # (verified on real KMP packages: leancrypto-kmp/vhba-kmp produce
    # zero emissions). The filter only hid that gating; the drop was
    # ruled in the config-filters follow-through (issue #538) and is
    # ledgered in tests/parity/divergences.toml.
    "kernel-modules-not-in-kernel-packages": "config-dead: KernelModuleRPMsOK defaults to true in both implementations and nothing overrides it, so the check never emits (issue #538)",
    "dangling-relative-symlink": "check is session-aware (rpmcrab#547): sibling-resolved links stay quiet, genuinely dangling ones surface; the blanket filter's 'we check for that already' rationale is stale",
    # Blanket hide inherited verbatim from upstream's openSUSE config
    # (upstream's Fedora config has the same line commented out and
    # lets the finding fire). The check is a verbatim port and sound;
    # measured over the Factory corpus (issue #557) the filter
    # suppresses 137 E lines in 44 srcpkgs, 24 of them genuine
    # accidental markings (rear's whole-tree %config(noreplace),
    # postfix-bdb's glob, pcp's generated lists, build's helper).
    # Ruled in the config-filters follow-through (issue #538) and
    # ledgered in tests/parity/divergences.toml.
    "executable-marked-as-config-file": "blanket filter dropped by ruling (issue #557): the Factory set it suppresses (137 E lines, 44 srcpkgs) includes 24 genuine accidental markings no other check covers; deliberate shapes belong in per-package rpmlintrc",
    # Ruled in the config-filters follow-through (issue #538, ruling
    # item 1): upstream hides the tag purely as policy; the check is
    # sound and the residual /etc main-config findings it emits have no
    # other coverage. Measured over the Factory snapshot corpus, the
    # filter hides 4,261 lines in 649 srcpkgs, ~78% of them deliberate
    # bulk-glob corpora and structural non-configs. The tag's
    # --explain text is reworded alongside (see divergences.toml).
    "conffile-without-noreplace-flag": "upstream hides it as policy; the port surfaces it so the residual /etc main-config findings are visible (issue #556)",
    # Ruled in the config-filters follow-through (issue #538, ruling
    # item 5): the bare line sits in upstream's bnc#456048 kernel-module
    # block, but measured over the Factory corpus (issue #578) the KMP
    # class is 14 lines (0.28%) of ordinary hand-written prose and the
    # three actual *-kmp srcpkgs (vhba-kmp, leancrypto-kmp,
    # virtualbox-kmp) contribute none; the suppressed set is 5,089
    # genuine findings in 2,041 srcpkgs. Fedora does not filter the tag
    # at all. Ledgered in tests/parity/divergences.toml.
    "description-line-too-long": "blanket filter dropped by ruling (issue #578): the KMP rationale measures empty (14 ordinary prose lines, 0.28% of the suppressed set; the three *-kmp srcpkgs contribute none); the suppressed set is 5,089 genuine lines in 2,041 srcpkgs",
    # The bare 'use-tmp-in-' pattern is the pattern itself, trailing dash
    # included: pure_finding_pattern returns it verbatim, so the key must
    # carry the dash. The check now fires only on literal paths (templates
    # and glob patterns are not predictable paths), so the blanket filter
    # would only hide genuine uses.
    "use-tmp-in-": "check tightened to literal paths (rpmcrab#558): mktemp templates and glob patterns no longer fire; the blanket filter would only hide genuine predictable-path uses (issue #538)",
    # Ruled in the config-filters follow-through (issue #538, ruling
    # item 8, the last): upstream's line is one of the three carrying
    # the 1.x-era fossil comment 'handled by CheckFilelist.py', and
    # the claim does not survive measurement -- FilelistCheck's
    # pattern rules cover 0 of the 45 suppressed lines. The check is
    # a port of FilesCheck and measured over the Factory corpus
    # (issue #583) misfires on 0 of those 45 lines; the whole
    # suppressed set is 45 E lines in 2 srcpkgs, both deliberate
    # carriers (filesystem's %ghost /usr/local skeleton tree,
    # reproducible-faketools' /usr/local/bin PATH-shadowing
    # wrappers). Since the %ghost exemption (issue #643) the
    # filesystem carrier no longer fires: 25 E lines in 1 srcpkg
    # remain (re-measured 2026-10-18, issue #654). Deliberate
    # per-package placements belong in per-package rpmlintrc;
    # Fedora ships the line commented out and lets the finding
    # fire. Ledgered in tests/parity/divergences.toml.
    "dir-or-file-in-usr-local": "blanket filter dropped by ruling (issue #583): FilesCheck port with a %ghost exemption (issue #643), 0/45 measured misfires; the suppressed set is 45 E lines in 2 srcpkgs, both deliberate carriers (filesystem's %ghost /usr/local skeleton, reproducible-faketools' PATH-shadowing wrappers) whose exceptions belong in per-package rpmlintrc; since the exemption only reproducible-faketools' 25 real-payload lines still fire (re-measured 2026-10-18, issue #654); Fedora ships the line commented out",
    # item 7): upstream's line is one of the three carrying the
    # 1.x-era fossil comment 'handled by CheckFilelist.py'. The
    # FHSCheck fix (issue #582) whitelists in the check itself
    # everything sanctioned the blanket suppressed -- /usr/etc, the
    # MinGW sysroots and X11R6, all modelled as good by
    # FilelistCheck's GoodPrefixes, plus the measured
    # cross-toolchain target sysroots -- so the blanket's measured
    # set (416 W lines over the Factory corpus) is sanctioned
    # practice at the source, and each cross sysroot is already
    # reported by FilelistCheck as a filelist-forbidden-fhs23 error
    # in the same run. What the tag can still fire on is a genuinely
    # novel /usr top-level directory -- exactly what it exists to
    # catch -- so it fires unsuppressed. Ledgered in
    # tests/parity/divergences.toml.
    "non-standard-dir-in-usr": "blanket filter dropped by ruling (issue #582): FHSCheck whitelists /usr/etc, the MinGW sysroots, X11R6 and the measured cross-toolchain target sysroots in the check itself, so the set the blanket suppressed (416 W lines over the Factory corpus: 213 /usr/etc, 92 MinGW sysroots, 111 cross-toolchain sysroots) is sanctioned practice at the source; the tag now fires only on genuinely novel /usr top-level directories, unsuppressed",
}

# (finding, scope) -> reason: Filters entries scoped to dead paths. The finding
# itself stays (its general form is live); only the listed scope is pruned.
# Unlike PRUNE_CANDIDATES these are unconditional: the scope paths are dead
# (SysV init removed), verified by hand when listed here.
PRUNE_SCOPED = {
    ("subdir-in-bin", "/sbin/conf.d/"): "dead SysV scope",
    ("conffile-without-noreplace-flag", "/etc/init.d"): "dead SysV scope",
    ("no-dependency-on", "locales"): "dead scope: the I18NCheck locales-* dependency rule is removed (issue #534); the finding stays live from FilesCheck",
}

# Exact Filters lines pruned verbatim: pattern -> reason. PRUNE_CANDIDATES
# matches a whole finding name and PRUNE_SCOPED a (finding, scope) pair;
# neither can express a compound pattern (package anchor + finding +
# detail). A raw entry prunes only a byte-exact pattern, so when upstream
# rewords the line the entry stops matching and the monthly sync surfaces
# the line again for a fresh audit — a raw prune can never silently widen.
PRUNE_RAW = {
    # Written for rpmlint's original severity-first output format
    # ("W: nss_db non-standard-dir-in-var db", Filter.py as of the 1999
    # first version): it demands the package name and the finding be
    # separated by a single space. Every later format — rpmlint >= 1.4 and
    # rpmcrab alike — renders "nss_db.<arch>: W: non-standard-dir-in-var
    # db", inserting ".<arch>: W:" exactly there, so the line has matched
    # nothing for decades; it survives verbatim in upstream's current
    # configs, which mention nss_db nowhere else. The finding stays live.
    ".* nss_db non-standard-dir-in-var db": "dead pattern: written for rpmlint's severity-first output format; the current 'name.arch: sev: tag' layout breaks its adjacency (issue #538)",
    # Same usr-merge fossil shape, one line down in the upstream config:
    # init ships as the /usr/sbin/init symlink to systemd, which carries
    # no ELF payload for the check to flag (a symlink has no readelf
    # data), and the full Factory sweep (17,241 srcpkgs,
    # run-20261014-6013f789) contains zero statically-linked-binary
    # emissions for any /sbin/ path at all.
    ".* statically-linked-binary /sbin/init": "dead pattern: init is a symlink to systemd on usr-merged Factory; zero emissions in the Factory sweep (issue #538)",
    # glibc 2.44 dropped the post-upgrade helper: the current glibc
    # package ships only iconvconfig and ldconfig in /usr/sbin, and the
    # Factory sweep contains zero mentions of the name.
    r"glibc\.\S+: \w: statically-linked-binary /usr/sbin/glibc_post_upgrade": "dead pattern: glibc 2.44 no longer ships glibc_post_upgrade; zero emissions in the Factory sweep (issue #538)",
}

# Filters lines whose exemption is still wanted but whose target moved:
# old pattern -> (new pattern, reason). The PRUNE_* tables drop lines
# whose finding or scope is gone; these lines name a live finding scoped
# to a path the distro relocated (usr-merge, /etc/skel -> /usr/etc/skel),
# so the scope is rewritten instead. Matching is byte-exact like
# PRUNE_RAW: when upstream rewords the line the entry stops matching and
# the monthly sync surfaces the upstream text for a fresh audit — a
# retarget can never silently widen.
RETARGET_FILTERS = {
    # Skeleton dotdirs moved from /etc/skel to /usr/etc/skel. The check
    # excludes the /etc/skel/ prefix in code (the reference does the
    # same), so the old patterns could never match, while the
    # /usr/etc/skel dotdirs fire visibly today (filesystem in the Factory
    # sweep: .cache/.config/.local print unsuppressed; .config and
    # .local are the ones these lines cover). Config-only fix: restores
    # the intended exemption in both implementations.
    r"^filesystem\..*: hidden-file-or-dir /etc/skel/.config": (
        r"^filesystem\..*: hidden-file-or-dir /usr/etc/skel/.config",
        "skeleton dotdirs moved to /usr/etc/skel; the check excludes the /etc/skel/ prefix in code, so the old pattern could never match (issue #538)",
    ),
    r"^filesystem\..*: hidden-file-or-dir /etc/skel/.local": (
        r"^filesystem\..*: hidden-file-or-dir /usr/etc/skel/.local",
        "skeleton dotdirs moved to /usr/etc/skel; the check excludes the /etc/skel/ prefix in code, so the old pattern could never match (issue #538)",
    ),
    r"^filesystem\..*: hidden-file-or-dir /etc/skel/.fonts": (
        r"^filesystem\..*: hidden-file-or-dir /usr/etc/skel/.fonts",
        "skeleton dotdirs moved to /usr/etc/skel; the check excludes the /etc/skel/ prefix in code, so the old pattern could never match (issue #538)",
    ),
    # usr-merge: ldconfig ships as /usr/sbin/ldconfig and the rendered
    # finding names that path, so the /sbin/ anchor right after the
    # finding could never match and glibc's statically-linked error
    # prints unsuppressed today. ldconfig is static by design — the
    # exemption is wanted, at the path the distro actually ships.
    ".* statically-linked-binary /sbin/ldconfig": (
        ".* statically-linked-binary /usr/sbin/ldconfig",
        "usr-merge: ldconfig ships as /usr/sbin/ldconfig, so the /sbin/ anchor could never match (issue #538)",
    ),
    # The check emits the plural tag (checks/files.rs); the pattern names
    # the singular, which matches only because filter matching is an
    # unanchored regex search and the singular is a prefix of the tag.
    # Any future anchoring or rename would break the exemption silently,
    # so spell the tag in full; the rest of the pattern is unchanged.
    r"^filesystem\..*: missing-dependency-to-cron": (
        r"^filesystem\..*: missing-dependency-to-crontabs",
        "the emitted tag is missing-dependency-to-crontabs (plural); the singular matched only as a substring prefix of the tag (issue #538)",
    ),
}

# Filters entries whose exemption is wanted but that upstream does not
# ship at all: anchor pattern -> (added pattern, reason). There is no
# upstream line to rewrite the way RETARGET_FILTERS does, so the added
# line is inserted immediately after the byte-exact anchor line inside
# Filters, keeping the family it belongs to adjacent in the vendored
# output. When upstream rewords or drops the anchor the insertion
# raises instead of landing in the wrong place, and when upstream ships
# the added line itself the insertion is skipped -- a monthly sync can
# never silently duplicate or misplace an exemption. Each entry is a
# deliberate divergence from the upstream distro config, ledgered in
# tests/parity/divergences.toml.
ADD_FILTERS = {
    # filesystem ships /usr/etc/skel/.cache as one of the deliberate
    # 0700 XDG skeleton dotdirs, alongside .config and .local.
    # Upstream's config filters the siblings (retargeted to
    # /usr/etc/skel above) but carries no .cache line, so this one
    # member of the set fired while the rest stayed quiet.
    r"^filesystem\..*: hidden-file-or-dir /usr/etc/skel/.local": (
        r"^filesystem\..*: hidden-file-or-dir /usr/etc/skel/.cache",
        "filesystem ships /usr/etc/skel/.cache in the same deliberate 0700 XDG skeleton set as .config/.local; upstream filters the siblings but carries no .cache line (issue #739)",
    ),
}

# Filters entries narrowed to the scope their recorded rationale covers:
# {bare pattern: (scoped pattern, reason)}. The finding stays live and the
# filter stays, but only for the shape the rationale justifies; everywhere
# else the finding becomes visible again. Applied by scope_filters() to
# Filters lines whose entire pattern is the bare entry, and
# logged for PROVENANCE. Unconditional like PRUNE_SCOPED: if upstream drops
# or rewords the bare entry the rewrite stops firing and the drift check
# shows upstream's text. Each entry is a deliberate divergence from the
# upstream distro config, ledgered in tests/parity/divergences.toml.
SCOPE_FILTERS = {
    "no-ldconfig-symlink": (
        r"^\S*-kmp-\S+\.\S+: \w: no-ldconfig-symlink",
        "scoped to kernel-module packages: the block's only recorded "
        "rationale is the KMP one (bnc#456048) \u2014 shared libraries in KMPs "
        "are private; elsewhere a missing ldconfig symlink is a real "
        "packaging bug and stays visible",
    ),
    "read-error": (
        r"^\S+\.\S+: \w: read-error No such file or directory",
        "narrowed to the ENOENT class measured in issue #579: all "
        "1,932 lines the blanket filter suppresses are ENOENT — 1,925 "
        "symlinks to %ghost placeholders under /etc/alternatives/ and "
        "7 to install/runtime-generated files — with zero "
        "unreadable-payload, corrupt-package or parser-failure lines; "
        "a read failure with any other errno is a genuine tool or "
        "package defect and surfaces again. The pattern keys on the "
        "detail format ledgered in issue #72 and must be re-cut if "
        "that divergence is fixed",
    ),
    "symlink-should-be-relative": (
        r"^\S+: \w: symlink-should-be-relative \S+ /etc/alternatives/",
        "scoped to update-alternatives targets: 1,937 of the 1,954 "
        "Factory lines the blanket filter suppresses are alternatives "
        "endpoint links \u2014 tool-owned artefacts generated by packaging "
        "macros (%python_alternative and kin) or %ghost declarations; "
        "the 17 hand-authored lines in 8 srcpkgs surface again, gavl's "
        "stale automake-1.18 link among them (issue #573)",
    ),
}

# Packages gone from the distro: whitelist stanzas naming them are pruned.
# A stanza is pruned only when the package is actually absent from
# openSUSE:Factory (checked live at generation time),
# so the vendored config always matches reality. A package that reappears is
# kept and logged — reintroduced software gets a fresh audit, never a silent
# free pass on a stale stanza.
# Entries name binary packages: that is the namespace whitelist `package =`
# entries match against at lint time. Presence is checked live (see
# package_present()): via the OBS source-package API for openSUSE:Factory
# and the published Tumbleweed binary repodata. An entry
# whose source package has a different name would wrongly prune on the Factory
# side, so keep entries to packages where both names agree. (All entries
# below were verified absent in both namespaces.)
PRUNE_PACKAGES = {
    # package: reason
    "snapd": "removed from Factory (bsc#1256175, bsc#1248682, bsc#1261739)",
    "lxd": "removed from Factory after the Canonical license change (replaced by incus); not in SLE 16",
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
    "rpmlint-integration-test": "rpmlint’s own synthetic integration-test package; not real distro policy, not shipped in Factory or Leap",
}

# Historical prunes: deliberate removals that must always be documented in
# PROVENANCE, even when the stanza is absent from the current upstream files
# (e.g. rpmlint-integration-test was never in upstream; nscd was removed
# upstream long ago). Each entry is (table, package, reason).
HISTORICAL_PRUNES = [
    ("DeviceFilesWhitelist", "rpmlint-integration-test",
     "rpmlint\u2019s own synthetic integration-test package; not real distro policy, not shipped in Factory or Leap"),
    ("SystemdTmpfilesWhitelist", "rpmlint-integration-test",
     "rpmlint\u2019s own synthetic integration-test package; not real distro policy, not shipped in Factory or Leap"),
    ("WorldWritableWhitelist", "rpmlint-integration-test",
     "rpmlint\u2019s own synthetic integration-test package; not real distro policy, not shipped in Factory or Leap"),
    ("WorldWritableWhitelist", "nscd",
     "removed from Factory and SLE 16 (use the system resolver)"),
]

# Stale pie-executables paths: each entry is (owning package, kind, reason),
# carrying per-entry evidence like PRUNE_PACKAGES does. kind "removed" means
# the owning package is gone from openSUSE:Factory (OBS source API 404);
# kind "moved" means the package still ships but relocated the binary. The
# package is checked live at generation time: a reintroduced "removed"
# package - or a vanished "moved" package, whose relocation evidence is then
# stale - keeps the path and logs loudly, so the drift check fails for a
# fresh audit instead of the path staying silently pruned. "moved" entries are
# additionally checked at filelist level at generation time: an old path that
# still ships in the current Factory filelist is kept with a loud log.
# Verified 2026-10-07 against the openSUSE:Factory filelists (97 paths shipped
# by no TW package). Each entry's owning package is checked live against
# Factory at generation time (OBS source API for openSUSE:Factory, published
# binary repodata for Tumbleweed — see package_present()).
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
    "/usr/bin/uniconv": ("uniconv", "removed", "uniconv removed from Factory and Leap 16.0"),
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


def raw_filter_pattern(entry):
    """The pattern text of a Filters entry with its quotes stripped.

    Returns None for lines that are not a single quoted pattern. Unlike
    pure_finding_pattern the pattern is kept intact: PRUNE_RAW matches it
    byte-for-byte.
    """
    s = entry.strip().split("#", 1)[0].strip().rstrip(",").strip()
    if (s.startswith("'") and s.endswith("'")) or (
        s.startswith('"') and s.endswith('"')
    ):
        return s[1:-1]
    return None


def prune_stale_filters(text, known, pruned_log, dropped_log, retargeted_log):
    """Drop Filters/BlockedFilters lines referencing killed findings or dead
    scopes, and rewrite lines whose target path moved (RETARGET_FILTERS)."""
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
            raw = raw_filter_pattern(line)
            if raw is not None and raw in PRUNE_RAW:
                pruned_log.append(
                    f"{in_list}: dropped {raw!r} ({PRUNE_RAW[raw]})"
                )
                continue
            if raw is not None and raw in RETARGET_FILTERS:
                new_pattern, reason = RETARGET_FILTERS[raw]
                retargeted_log.append(
                    f"{in_list}: retargeted {raw!r} to {new_pattern!r} ({reason})"
                )
                out.append(line.replace(raw, new_pattern, 1))
                continue
            if finding is not None and finding in DROP_LIVE_FILTERS:
                dropped_log.append(
                    f"{in_list}: dropped {finding!r} ({DROP_LIVE_FILTERS[finding]})"
                )
                continue
        out.append(line)
    return "".join(out)


def scope_filters(text, scoped_log):
    """Rewrite bare Filters entries listed in SCOPE_FILTERS.

    Only a line whose entire pattern is the bare entry is rewritten; the
    replacement keeps the line's indentation, quote style and trailing
    comma. Anything else (already-scoped entries, compound patterns, the
    bare entry embedded in a larger pattern) is left untouched.
    BlockedFilters is never rewritten: its entries are matched by exact
    string equality, not as regex patterns, so a scoped pattern there
    would never match and would silently drop the guard it names.
    """
    lines = text.splitlines(keepends=True)
    out = []
    in_list = None
    for line in lines:
        stripped = line.strip()
        m = re.match(r"^Filters\s*=\s*\[", stripped)
        if m:
            in_list = "Filters"
            out.append(line)
            continue
        if in_list and stripped.startswith("]"):
            in_list = None
            out.append(line)
            continue
        if in_list:
            raw = raw_filter_pattern(line)
            pattern = raw.strip() if raw is not None else None
            if pattern is not None and pattern in SCOPE_FILTERS:
                scoped, reason = SCOPE_FILTERS[pattern]
                indent = line[: len(line) - len(line.lstrip())]
                quote = stripped[:1] if stripped[:1] in ("'", '"') else "'"
                eol = "\n" if line.endswith("\n") else ""
                out.append(f"{indent}{quote}{scoped}{quote},{eol}")
                scoped_log.append(
                    f"{in_list}: scoped {pattern!r} to {scoped!r} ({reason})"
                )
                continue
        out.append(line)
    return "".join(out)


def add_filters(text, added_log):
    """Insert Filters entries listed in ADD_FILTERS after their anchors.

    ADD_FILTERS covers exemptions upstream does not ship at all, so there
    is no upstream line to rewrite the way RETARGET_FILTERS does; each
    entry names the byte-exact Filters pattern it belongs behind and is
    inserted immediately after that line, in the anchor line's
    indentation and quote style. Filters only: BlockedFilters entries
    are matched by exact string equality, so an inserted line there
    would be a guard, not an exemption. A missing anchor raises --
    upstream rewording or dropping the anchor must surface at generation
    time, never silently strand the exemption. A pattern upstream has
    started shipping itself is not duplicated.
    """
    lines = text.splitlines(keepends=True)
    present = set()
    in_list = False
    for line in lines:
        stripped = line.strip()
        if re.match(r"^Filters\s*=\s*\[", stripped):
            in_list = True
            continue
        if in_list and stripped.startswith("]"):
            in_list = False
            continue
        if in_list:
            raw = raw_filter_pattern(line)
            if raw is not None:
                present.add(raw)
    pending = {
        anchor: entry
        for anchor, entry in ADD_FILTERS.items()
        if entry[0] not in present
    }
    out = []
    in_list = False
    done = set()
    for line in lines:
        stripped = line.strip()
        if re.match(r"^Filters\s*=\s*\[", stripped):
            in_list = True
            out.append(line)
            continue
        if in_list and stripped.startswith("]"):
            in_list = False
            out.append(line)
            continue
        out.append(line)
        if in_list:
            raw = raw_filter_pattern(line)
            if raw is not None and raw in pending and raw not in done:
                pattern, reason = pending[raw]
                indent = line[: len(line) - len(line.lstrip())]
                quote = stripped[:1] if stripped[:1] in ("'", '"') else "'"
                eol = "\n" if line.endswith("\n") else ""
                out.append(f"{indent}{quote}{pattern}{quote},{eol}")
                added_log.append(
                    f"Filters: added {pattern!r} after {raw!r} ({reason})"
                )
                done.add(raw)
    missing = [anchor for anchor in pending if anchor not in done]
    if missing:
        raise AssertionError(
            f"ADD_FILTERS anchor(s) not found in Filters: {missing!r}"
        )
    return "".join(out)


# Regex metacharacters. A Filters pattern containing none of these is a
# plain literal: the filter engine runs an unanchored regex search, so a
# literal matches exactly the strings that contain it as a substring.
_REGEX_META = frozenset("\\.^$|?*+()[]{}")


def _literal_pattern(entry):
    """The pattern of a Filters entry if it is a plain literal, else None.

    Only literals take part in subsumption (see dedupe_filters): for
    literals, one pattern's match set contains another's exactly when its
    text is a substring of the other's. A regex pattern's match set is
    not substring-ordered, so regexes are only ever deduplicated
    byte-for-byte, never subsumption-checked.
    """
    raw = raw_filter_pattern(entry)
    if raw is None or any(c in _REGEX_META for c in raw):
        return None
    return raw


def dedupe_filters(text, deduped_log):
    """Drop redundant lines from Filters lists; output-neutral hygiene.

    The filter engine suppresses a finding when ANY Filters pattern
    matches the rendered line, so a line is redundant when another line
    in the same list matches everything it does. Two such cases:

    - exact duplicates: a pattern byte-identical to an earlier entry in
      the same list matches the very same strings;
    - subsumed literals: a plain-literal pattern whose text strictly
      contains another literal pattern in the same list naming the SAME
      finding (see pure_finding_pattern) — every string the longer
      pattern matches contains the shorter one, so the broader line
      already suppresses everything the narrower one would.

    The same-finding condition keeps package-scoped lines safe:
    'ibcs2 non-standard-dir-in-usr ...' textually contains the blanket
    ' non-standard-dir-in-usr ' but names a compound scope, not the bare
    finding, so it is never dropped — it stays as the recorded exception
    for if the blanket line is ever revisited. BlockedFilters is not
    touched: its entries are matched as exact finding names, not
    patterns, so neither rule applies there.

    Deterministic: first occurrences stay, positions never change, and
    the drop set is computed over the whole list before any line is
    removed, so which lines go never depends on processing order. A
    second pass over the output drops nothing (idempotent).
    """
    lines = text.splitlines(keepends=True)
    drop = set()
    i = 0
    while i < len(lines):
        if not re.match(r"^Filters\s*=\s*\[", lines[i].strip()):
            i += 1
            continue
        # One Filters list: collect (line index, pattern, literal,
        # finding) for every quoted entry until the closing bracket.
        entries = []
        j = i + 1
        while j < len(lines) and not lines[j].strip().startswith("]"):
            raw = raw_filter_pattern(lines[j])
            if raw is not None:
                literal = _literal_pattern(lines[j])
                finding = (
                    pure_finding_pattern(lines[j]) if literal is not None else None
                )
                entries.append((j, raw, literal, finding))
            j += 1
        seen = set()
        for idx, raw, literal, finding in entries:
            if raw in seen:
                drop.add(idx)
                deduped_log.append(
                    f"Filters: dropped duplicate {raw!r} "
                    "(byte-identical to an earlier Filters entry)"
                )
                continue
            seen.add(raw)
            if literal is None or finding is None:
                continue
            for _, other_raw, other_literal, other_finding in entries:
                if (
                    other_literal is not None
                    and other_finding == finding
                    and other_raw != raw
                    and other_literal in literal
                ):
                    drop.add(idx)
                    deduped_log.append(
                        f"Filters: dropped {raw!r} (subsumed by {other_raw!r}: "
                        f"both name {finding!r} and the broader literal "
                        "matches everything it does)"
                    )
                    break
        i = j
    return "".join(line for n, line in enumerate(lines) if n not in drop)


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

# Project checked for package presence: the flavor tracks Tumbleweed.
FACTORY_PROJECTS = ("openSUSE:Factory",)


TW_OSS_REPOMD_URL = (
    "https://download.opensuse.org/tumbleweed/repo/oss/repodata/repomd.xml"
)
TW_OSS_REPO_BASE = "https://download.opensuse.org/tumbleweed/repo/oss/"
_tw_binary_names_cache = None


def _scan_binary_names(stdout):
    """Collect <name> tag values from a zstd -dc pipe.

    A tag may span chunk boundaries no matter how long it is: the tail is
    kept from the last tag start instead of a fixed byte count.
    """
    name_re = re.compile(rb"<name>([^<]*)</name>")
    names = set()
    buf = b""
    while True:
        chunk = stdout.read(1 << 16)
        data = buf + chunk if chunk else buf
        end = len(data)
        for match in name_re.finditer(data):
            if chunk and match.end() == end:
                # Tag may be split across chunks; re-scan it with the
                # next chunk (kept in the tail).
                continue
            names.add(match.group(1).decode("utf-8", "replace"))
        if not chunk:
            break
        idx = data.rfind(b"<name")
        if idx < 0:
            # Chunk split landed inside the opening tag itself.
            idx = data.rfind(b"<")
        buf = data[idx:] if idx >= 0 else b""
    return names


# Full repomd -> primary fetch cycles before giving up when the primary
# download fails; mirrors _FILELIST_CYCLES/_FILELIST_BACKOFF below for
# the same stale-mirror reason: a mirror can serve repomd.xml fine while
# the primary archive it references 404s because it has not synced yet,
# and each cycle's fresh repomd fetch gets its own MirrorBrain redirect
# that may land on a synced mirror.
_PRIMARY_CYCLES = 3
# Backoff sleeps between primary fetch cycles (seconds); no sleep after
# the final cycle.
_PRIMARY_BACKOFF = [30, 60]


def _primary_location(repomd, repo_base, label):
    """(sha512, primary.xml URL) from a repomd.xml body."""
    m = re.search(
        r'<data type="primary">.*?<checksum type="sha512">([0-9a-f]+)</checksum>'
        r'.*?<location href="([^"]*primary\.xml\.[^"]*)"',
        repomd,
        re.DOTALL,
    )
    if not m:
        raise RuntimeError(
            "primary.xml location/sha512 not found in %s repomd.xml" % label
        )
    return m.group(1), repo_base + m.group(2)


def _download_primary_names(primary_url, expected_sha512, zstd, label):
    """Download one primary.xml archive, verify it, and scan the names.

    Raises RuntimeError on any failure: a mirror error (a stale mirror
    404s the archive its repomd references), a truncated download
    (sha512 mismatch) or a decompression failure are all conditions a
    fresh mirror may not reproduce, so the caller retries them over
    fresh repomd fetches.
    """
    req = urllib.request.Request(
        primary_url, headers={"User-Agent": "rpmcrab-distro-config-sync"}
    )
    # The download is tens of MB: keep it out of TMPDIR, which is a
    # small tmpfs on some build machines.
    with tempfile.NamedTemporaryFile(suffix=".xml.zst", dir=".") as tmp:
        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                shutil.copyfileobj(resp, tmp)
        except (
            urllib.error.URLError,
            TimeoutError,
            http.client.IncompleteRead,
            ConnectionResetError,
        ) as e:
            raise RuntimeError(
                "primary.xml download failed for %s: %s" % (label, e)
            ) from e
        tmp.flush()
        # Hash in chunks: no need to hold the whole archive in memory.
        # A truncated download must fail loudly, never silently prune
        # packages absent from the partial data.
        hasher = hashlib.sha512()
        with open(tmp.name, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                hasher.update(chunk)
        if hasher.hexdigest() != expected_sha512:
            raise RuntimeError(
                f"sha512 mismatch on {primary_url} (truncated download?)"
            )
        proc = subprocess.Popen([zstd, "-dc", tmp.name], stdout=subprocess.PIPE)
        try:
            names = _scan_binary_names(proc.stdout)
        finally:
            proc.stdout.close()
            proc.wait()
        if proc.returncode != 0:
            raise RuntimeError(f"zstd -dc failed on {primary_url}")
    return names


def _binary_names(repomd_url, repo_base, label):
    """Binary package names shipped in a repo's published repodata.

    Mirrors _filelist_hits: the repomd -> primary fetch runs in cycles
    because a stale mirror serves repomd.xml fine but 404s the primary
    archive it references (not synced yet). Each cycle re-fetches
    repomd.xml, so a fresh MirrorBrain redirect can land on a synced
    mirror; if every cycle fails, one final cycle runs against the
    fallback mirror. Raises RuntimeError once every attempt is
    exhausted: an unverifiable repo must fail loudly, never prune
    against partial data.
    """
    zstd = shutil.which("zstd")
    if zstd is None:
        raise RuntimeError(
            "the 'zstd' CLI is required to read the %s repodata "
            "(install zstd and re-run)" % label
        )
    names = None
    last_err = None
    attempts = 0
    for cycle in range(_PRIMARY_CYCLES):
        repomd = _fetch_repomd_xml(repomd_url, label)
        attempts += 1
        expected_sha512, primary_url = _primary_location(
            repomd, repo_base, label)
        try:
            names = _download_primary_names(
                primary_url, expected_sha512, zstd, label)
            break
        except RuntimeError as e:
            last_err = e
            if cycle + 1 < _PRIMARY_CYCLES:
                time.sleep(_PRIMARY_BACKOFF[cycle])
    if names is None:
        fb_repomd_url, fb_repo_base = _fallback_mirror_urls(
            repomd_url, repo_base)
        if fb_repomd_url is not None:
            fb_label = label + " (fallback mirror)"
            repomd = _fetch_repomd_xml(fb_repomd_url, fb_label)
            attempts += 1
            expected_sha512, primary_url = _primary_location(
                repomd, fb_repo_base, fb_label)
            try:
                names = _download_primary_names(
                    primary_url, expected_sha512, zstd, fb_label)
            except RuntimeError as e:
                last_err = e
    if names is None:
        raise RuntimeError(
            "primary.xml download failed for %s after %d attempts: %s"
            % (label, attempts, last_err)
        )
    return names


def _tw_binary_names():
    """Binary package names shipped in Tumbleweed (oss), fetched once, cached.

    Whitelist `package =` entries name the binary being linted, but the
    OBS source API 404s on binary-only names (e.g. udev-mini,
    libcgroup-tools are subpackages of another source). The published
    repodata is the ground truth for binary presence.
    """
    global _tw_binary_names_cache
    if _tw_binary_names_cache is None:
        _tw_binary_names_cache = _binary_names(
            TW_OSS_REPOMD_URL, TW_OSS_REPO_BASE, "Tumbleweed"
        )
    return _tw_binary_names_cache



def package_present(pkg):
    """True if the package exists in the distro codebase.

    This queries the OBS source-package API (openSUSE:Factory hosts all
    its sources), falling back to the Tumbleweed binary repodata:
    whitelist `package =` entries name the binary being linted, and the
    source API 404s on binary-only names (e.g. udev-mini,
    libcgroup-tools are subpackages of another source).
    """
    key = pkg
    if key not in _package_presence_cache:
        present = False
        for project in FACTORY_PROJECTS:
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
        if not present:
            # Binary-only name (subpackage of another source): the
            # source API 404s, so check the published binary repodata.
            present = pkg in _tw_binary_names()
        _package_presence_cache[key] = present
    return _package_presence_cache[key]


_filelist_cache_tw = {}

# Attempts for the repomd.xml fetch before giving up.
_REPOMD_ATTEMPTS = 4
# Backoff sleeps between repomd fetch attempts (seconds); no sleep after
# the final attempt.
_REPOMD_BACKOFF = [15, 30, 45]

# Full repomd -> filelist verification cycles before giving up when the
# filelist download fails. Each cycle re-fetches repomd.xml, so a fresh
# MirrorBrain redirect can land on a healthy mirror when the previous one
# was stale (its repomd referenced filelists not yet synced to it).
_FILELIST_CYCLES = 3
# Backoff sleeps between filelist cycles (seconds); no sleep after the
# final cycle.
_FILELIST_BACKOFF = [30, 60]

# Direct mirror used as a last resort when every MirrorBrain cycle fails:
# retrying cannot help if each fresh redirect lands on the same stale
# mirror. GWDG mirrors download.opensuse.org's path layout verbatim, so
# the fallback is a pure prefix swap of both URLs.
_DOWNLOAD_O_O = "https://download.opensuse.org/"
_FALLBACK_MIRROR = "https://ftp.gwdg.de/pub/opensuse/"


def _fallback_mirror_urls(repomd_url, repo_base):
    """(repomd_url, repo_base) on the fallback mirror, or (None, None).

    Only download.opensuse.org URLs have a known-good fallback layout;
    anything else keeps the old raise-after-cycles behavior.
    """
    if not (repomd_url.startswith(_DOWNLOAD_O_O)
            and repo_base.startswith(_DOWNLOAD_O_O)):
        return None, None
    return (
        repomd_url.replace(_DOWNLOAD_O_O, _FALLBACK_MIRROR, 1),
        repo_base.replace(_DOWNLOAD_O_O, _FALLBACK_MIRROR, 1),
    )


def _filelist_url(repomd, repo_base, label):
    """Filelist archive URL from a repomd.xml body."""
    m = re.search(
        r'<data type="filelists">.*?<location href="([^"]+)"', repomd, re.S
    )
    if not m:
        raise RuntimeError(
            "filelists entry not found in %s repomd.xml" % label
        )
    return repo_base + m.group(1)


def _fetch_repomd_xml(repomd_url, label):
    """Fetch and return a repo's repomd.xml as text.

    Transient mirror failures (5xx, network errors, timeouts) are retried:
    a single failed fetch must not fail the whole run when the mirror is
    briefly down. The backoff sleeps only between attempts - the last
    attempt raises immediately instead of sleeping pointlessly before the
    error. Client errors (4xx) raise immediately: the URL itself is wrong
    and retrying cannot help. Raises RuntimeError when the attempts are
    exhausted.
    """
    req = urllib.request.Request(
        repomd_url, headers={"User-Agent": "rpmcrab-distro-config-sync"}
    )
    repomd = None
    last_err = None
    for attempt in range(_REPOMD_ATTEMPTS):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                repomd = resp.read().decode("utf-8")
            break
        except urllib.error.HTTPError as e:
            if e.code < 500:
                raise
            last_err = e
        except (
            urllib.error.URLError,
            TimeoutError,
            http.client.IncompleteRead,
            ConnectionResetError,
        ) as e:
            last_err = e
        if attempt + 1 < _REPOMD_ATTEMPTS:
            time.sleep(_REPOMD_BACKOFF[attempt])
    if repomd is None:
        raise RuntimeError(
            "repomd.xml fetch failed for %s after retries: %s" % (label, last_err)
        )
    return repomd


class GrepError(Exception):
    """The grep stage of the filelist pipeline failed deterministically.

    Deliberately not a RuntimeError: the stale-mirror retry loop in
    _filelist_hits retries RuntimeError (transient curl/zstd conditions
    that a fresh mirror may fix), so a deterministic grep failure - e.g.
    rc=2, which no retry can fix - raises through immediately instead of
    burning the 30s/60s backoff on a certain failure.
    """


def _download_filelist_hits(fl_url, args, label):
    """Download a filelists archive, grep it, and return the hit set.

    Streams the file through one ``curl | zstd -dc | grep`` pass, matching
    ``>path<`` against ``<file>path</file>`` entries so only exact paths
    hit. Raises RuntimeError on download/decompression failure, GrepError
    on grep failure.
    """
    # Every stage must succeed: checking only grep's return code lets a
    # failed download prune everything this guard verifies. -f makes
    # HTTP errors catchable; --show-error keeps the message (captured
    # below) diagnosable. The speed-limit/speed-time pair stalls out a
    # hung mirror instead of hanging the job: a transfer under 50KB/s
    # for 60s aborts and retries, while a merely slow mirror is allowed
    # to finish - a hard --max-time would kill legitimate slow
    # downloads (100KB/s observed from a mirror).
    curl = subprocess.Popen(
        [
            "curl",
            "-fsSL",
            "--show-error",
            "--connect-timeout",
            "60",
            "--retry",
            "3",
            "--retry-all-errors",
            "--speed-limit",
            "50000",
            "--speed-time",
            "60",
            fl_url,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    zstd = subprocess.Popen(
        ["zstd", "-dc"],
        stdin=curl.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    curl.stdout.close()
    grep = subprocess.run(
        ["grep", "-F", "-o"] + args,
        stdin=zstd.stdout,
        capture_output=True,
        text=True,
    )
    zstd.stdout.close()
    curl_rc = curl.wait()
    zstd_rc = zstd.wait()
    curl_err = curl.stderr.read().decode("utf-8", "replace").strip()
    zstd_err = zstd.stderr.read().decode("utf-8", "replace").strip()
    if curl_rc != 0:
        raise RuntimeError(
            "filelist download failed (curl rc=%d) for %s: %s"
            % (curl_rc, label, curl_err[:300])
        )
    if zstd_rc != 0:
        raise RuntimeError(
            "filelist decompression failed (zstd rc=%d) for %s: %s"
            % (zstd_rc, label, zstd_err[:300])
        )
    if grep.returncode not in (0, 1):
        # GrepError, not RuntimeError: deterministic, so the stale-mirror
        # retry loop lets it raise through without backoff.
        raise GrepError(
            "filelist grep failed (rc=%d): %s"
            % (grep.returncode, grep.stderr[:200])
        )
    return {
        line[1:-1]
        for line in grep.stdout.splitlines()
        if line.startswith(">") and line.endswith("<")
    }


def _filelist_hits(paths, repomd_url, repo_base, cache, label):
    """Subset of `paths` still shipped by some package in a repo's filelists.

    Raises on download/decompression/grep failure: an unverifiable guard
    must fail loudly, never prune silently. A stale mirror - repomd.xml
    fetched fine but the filelists it references 404 because the mirror
    has not synced them yet - is retried with backoff over fresh repomd
    fetches, each with its own MirrorBrain redirect that may land on a
    healthy mirror. If every cycle still fails, one final cycle runs
    against a hardcoded fallback mirror, since retries cannot help when
    MirrorBrain keeps redirecting to the same broken host. Only raises
    once the fallback is exhausted too. A deterministic grep failure
    (GrepError) is not retried: it raises through immediately, since
    backoff cannot fix it.
    """
    paths = sorted(set(paths))
    missing = [p for p in paths if p not in cache]
    if missing:
        args = []
        for q in missing:
            args += ["-e", ">%s<" % q]
        hits = None
        last_err = None
        attempts = 0
        for cycle in range(_FILELIST_CYCLES):
            repomd = _fetch_repomd_xml(repomd_url, label)
            attempts += 1
            fl_url = _filelist_url(repomd, repo_base, label)
            try:
                hits = _download_filelist_hits(fl_url, args, label)
                break
            except RuntimeError as e:
                # GrepError is not a RuntimeError: deterministic grep
                # failures raise through here without burning the backoff.
                last_err = e
                if cycle + 1 < _FILELIST_CYCLES:
                    time.sleep(_FILELIST_BACKOFF[cycle])
        if hits is None:
            fb_repomd_url, fb_repo_base = _fallback_mirror_urls(
                repomd_url, repo_base)
            if fb_repomd_url is not None:
                fb_label = label + " (fallback mirror)"
                repomd = _fetch_repomd_xml(fb_repomd_url, fb_label)
                attempts += 1
                fl_url = _filelist_url(repomd, fb_repo_base, fb_label)
                try:
                    hits = _download_filelist_hits(fl_url, args, fb_label)
                except RuntimeError as e:
                    last_err = e
        if hits is None:
            raise RuntimeError(
                "filelist download failed for %s after %d attempts: %s"
                % (label, attempts, last_err)
            )
        for q in missing:
            cache[q] = q in hits
    return {p for p in paths if cache[p]}


def factory_filelist_hits(paths):
    """Subset of `paths` still shipped by some openSUSE:Factory package.

    Streams the Tumbleweed oss filelists - the same source the original
    pie-path verification used.
    """
    return _filelist_hits(
        paths,
        "https://download.opensuse.org/tumbleweed/repo/oss/repodata/repomd.xml",
        "https://download.opensuse.org/tumbleweed/repo/oss/",
        _filelist_cache_tw,
        "Tumbleweed",
    )


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


def prune_stale_packages(text, pruned_log):
    """Drop whitelist stanzas whose package(s) are all gone from the distro."""
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
        prune_dict = PRUNE_PACKAGES
        if pkgs and all(p in prune_dict for p in pkgs):
            if all(not package_present(p) for p in pkgs):
                pruned_log.append(
                    "whitelist: dropped [[%s]] stanza for %s"
                    % (
                        table,
                        ", ".join("%r (%s)" % (p, prune_dict[p]) for p in pkgs),
                    )
                )
                continue
            pruned_log.append(
                "whitelist: KEPT [[%s]] stanza for %s — package present in "
                "Factory, needs a fresh audit before any allowance "
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


def prune_pie_paths(text, pruned_log):
    """Drop pie-executables.toml entries for paths no distro package ships.

    Each entry names its owning package, checked live against Factory
    (OBS source API, like PRUNE_PACKAGES): a reintroduced "removed"
    package - or a vanished "moved" package, whose relocation evidence is
    then stale - keeps the path and logs loudly, so the drift check fails
    for a fresh audit instead of the path staying silently pruned.

    "moved" entries get a second, filelist-level check against the
    Tumbleweed filelists: the old path must not still be shipped there.
    A reappearing old path is kept with a loud log for the same reason.
    """
    entries = []
    moved_paths = []
    for line in text.splitlines(keepends=True):
        m = re.fullmatch(r'"([^"]+)",?', line.strip())
        norm = _usrmerge_norm(m.group(1)) if m else None
        if m and norm in PRUNE_PIE_PATHS:
            pkg, kind, reason = PRUNE_PIE_PATHS[norm]
            entries.append((line, m.group(1), norm, pkg, kind, reason))
            if kind == "moved":
                moved_paths.append(norm)
        else:
            entries.append((line, None, None, None, None, None))
    shipped = {}
    for path in factory_filelist_hits(moved_paths):
        shipped.setdefault(path, "Factory")
    out = []
    for line, raw, norm, pkg, kind, reason in entries:
        if raw is None:
            out.append(line)
            continue
        present = package_present(pkg)
        if (kind == "removed" and present) or (kind == "moved" and not present):
            pruned_log.append(
                "pie-executables: KEPT stale path %r - owning package %r "
                "changed state in Factory (%s), needs a fresh "
                "audit" % (raw, pkg, reason)
            )
            out.append(line)
            continue
        if kind == "moved" and norm in shipped:
            pruned_log.append(
                "pie-executables: KEPT stale path %r - old path still shipped "
                "in %s, needs a fresh audit" % (raw, shipped[norm])
            )
            out.append(line)
            continue
        pruned_log.append(
            "pie-executables: dropped stale path %r (%s)" % (raw, reason)
        )
    return "".join(out)


def append_extra_filters(text, filters):
    """Append regexes to the `Filters = [...]` list in a TOML document.

    Used for distro-config filters that do not come from upstream rpmlint
    (see EXTRA_FILTERS). Inserted before the list's closing bracket
    so the monthly sync re-emits them deterministically.
    """
    lines = text.splitlines(keepends=True)
    out = []
    in_list = False
    done = False
    for line in lines:
        stripped = line.strip()
        if not done and re.match(r"^Filters\s*=\s*\[", stripped):
            in_list = True
            out.append(line)
            continue
        if in_list and stripped.startswith("]"):
            out.append("\n")
            out.append("    # Extra: *.dll.a and *.a files are permitted arch-independent objects.\n")
            out.append("    # From mingw{32,64}-filesystem's mingw{32,64}-rpmlintrc (shipped as\n")
            out.append("    # /opt/testing/share/rpmlint/mingw{32,64}.toml); see EXTRA_FILTERS\n")
            out.append("    # in scripts/generate-distro-configs.py.\n")
            for f in filters:
                out.append(f"    '{f}',\n")
            in_list = False
            done = True
            out.append(line)
            continue
        out.append(line)
    assert done, "no Filters list found to append to"
    return "".join(out)


def append_extra_checks(text, checks):
    """Append check names to the `Checks = [...]` list in a TOML document.

    Used for checks rpmcrab enables in the distro config that upstream does
    not list in any shipped config (see EXTRA_CHECKS). Inserted
    before the list's closing bracket so the monthly sync re-emits them
    deterministically.
    """
    lines = text.splitlines(keepends=True)
    out = []
    in_list = False
    done = False
    for line in lines:
        stripped = line.strip()
        if not done and re.match(r"^Checks\s*=\s*\[", stripped):
            in_list = True
            out.append(line)
            continue
        if in_list and stripped.startswith("]"):
            out.append("\n")
            out.append("    # Extra: enabled by rpmcrab; upstream lists these checks in no\n")
            out.append("    # shipped config (deliberate, ledgered divergence); see\n")
            out.append("    # EXTRA_CHECKS in scripts/generate-distro-configs.py.\n")
            for c in checks:
                out.append(f'    "{c}",\n')
            in_list = False
            done = True
            out.append(line)
            continue
        out.append(line)
    assert done, "no Checks list found to append to"
    return "".join(out)


def append_systemd_preset_packages(text, packages):
    """Insert the `SystemdPresetPackages` key into a TOML document.

    Used for the distro preset packages rpmcrab exempts from the
    `systemd-preset-packaged` finding (see SYSTEMD_PRESET_PACKAGES).
    The key goes at the end of the top-level preamble, before the first
    table header, so it stays a top-level key: at the end of the
    document it would fall inside the trailing [Descriptions] table and
    never reach the check. The monthly sync re-emits it deterministically.
    """
    block = "\n"
    block += "# Packages allowed to ship systemd preset files (not from upstream;\n"
    block += "# see SYSTEMD_PRESET_PACKAGES in scripts/generate-distro-configs.py).\n"
    block += "SystemdPresetPackages = [\n"
    for pkg in packages:
        block += "    %s,\n" % json.dumps(pkg)
    block += "]\n"
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.startswith("["):
            if i and lines[i - 1] == "\n":
                block = block[1:]
            lines.insert(i, block)
            return "".join(lines)
    out = text if text.endswith("\n") else text + "\n"
    return out + block


def remove_excluded_checks(text, checks):
    """Remove check names from the `Checks = [...]` list in a TOML document.

    Used for checks upstream lists in the openSUSE config that rpmcrab
    deliberately does not run under the flavor (see
    EXCLUDED_CHECKS). Each removed entry is replaced by an
    explanation comment at the same spot so the vendored config itself
    records the absence; the monthly sync re-emits it deterministically.
    A listed check missing from the list fails loudly: silently passing
    would ship the check enabled, the exact outcome the exclusion exists
    to prevent.
    """
    wanted = {'"%s",' % c: c for c in checks}
    lines = text.splitlines(keepends=True)
    out = []
    in_list = False
    for line in lines:
        stripped = line.strip()
        if re.match(r"^Checks\s*=\s*\[", stripped):
            in_list = True
            out.append(line)
            continue
        if in_list and stripped.startswith("]"):
            in_list = False
            out.append(line)
            continue
        if in_list and stripped in wanted:
            name = wanted.pop(stripped)
            out.append(
                '    # Excluded: "%s" is not run under the flavor\n' % name
            )
            out.append("    # (deliberate, ledgered divergence); see\n")
            out.append(
                "    # EXCLUDED_CHECKS in scripts/generate-distro-configs.py.\n"
            )
            continue
        out.append(line)
    assert not wanted, "excluded checks not in Checks list: %s" % sorted(
        wanted.values()
    )
    return "".join(out)


def strip_badness_threshold(text, flavor, threshold_log):
    """Drop the ``BadnessThreshold`` line from a vendored flavor config.

    rpmcrab has no badness threshold (issue #699): severity decides the
    exit code, so upstream's ``BadnessThreshold = 999`` in opensuse.toml
    is not carried. Only the key line is removed; every other line
    survives byte-exact. Idempotent.
    """
    out = []
    for line in text.splitlines(keepends=True):
        if re.match(r"^BadnessThreshold\s*=", line):
            threshold_log.append(
                f"BadnessThreshold: dropped {line.strip()!r} from {flavor}/opensuse.toml"
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
    dropped_log = []
    retargeted_log = []
    scoped_log = []
    deduped_filters_log = []
    threshold_log = []
    added_log = []
    adjudicated_log = []
    for flavor, data in result.items():
        for filename, text in data["files"].items():
            assert_no_flavor_key(flavor, filename, text)
            text = prune_stale_filters(
                text, known, pruned_log, dropped_log, retargeted_log
            )
            text = scope_filters(text, scoped_log)
            text = dedupe_filters(text, deduped_filters_log)
            text = prune_stale_packages(text, pkg_pruned_log)
            if filename == "pie-executables.toml":
                # The owning package is checked live against Factory
                # (see PRUNE_PIE_PATHS).
                text = prune_pie_paths(text, pie_pruned_log)
            if filename == "opensuse.toml":
                text = strip_badness_threshold(text, flavor, threshold_log)
                text = append_systemd_preset_packages(
                    text, SYSTEMD_PRESET_PACKAGES
                )
                # Exemptions upstream does not ship (see ADD_FILTERS).
                text = add_filters(text, added_log)
                text = append_extra_filters(
                    text, [pattern for pattern, _reason in EXTRA_FILTERS]
                )
                text = append_extra_checks(text, EXTRA_CHECKS)
                text = remove_excluded_checks(text, EXCLUDED_CHECKS)
            text, adj_log = apply_digest_adjudications(text, filename)
            adjudicated_log.extend(adj_log)
            data["files"][filename] = text

    files_out = list(FILES["opensuse"])

    provenance = [
        "# Generated by scripts/generate-distro-configs.py — do not edit by hand.",
        "# Upstream owns these configs until rpmlint is fully superseded;",
        "# the monthly distro-config-sync CI job refreshes them.",
        f"# upstream_repo = https://github.com/{UPSTREAM_REPO}",
    ]
    for flavor, data in result.items():
        provenance.append(f"# {flavor}: {data['branch']} @ {data['sha']} ({data['date']})")
    for flavor, data in result.items():
        provenance.append(
            f"# {flavor}-whitelists: {data['branch']} @ {data['sha']} ({data['date']})"
        )
    provenance.append("#")
    provenance.append("# Extra Filters appended (not from upstream; see EXTRA_FILTERS):")
    for filter_pattern, reason in EXTRA_FILTERS:
        provenance.append(f"#   Filters: added {filter_pattern!r} ({reason})")
    provenance.append("#")
    provenance.append("# Extra Checks appended (not from upstream; see EXTRA_CHECKS):")
    for c in EXTRA_CHECKS:
        provenance.append(
            f"#   Checks: added {c!r} (deliberate rpmcrab divergence, ledgered in"
            " tests/parity/divergences.toml)"
        )
    provenance.append("#")
    provenance.append(
        "# SystemdPresetPackages appended (not from upstream; see SYSTEMD_PRESET_PACKAGES):"
    )
    for p in SYSTEMD_PRESET_PACKAGES:
        provenance.append(f"#   SystemdPresetPackages: added {p!r}")
    provenance.append("#")
    provenance.append("# Excluded Checks (removed from the flavor; see EXCLUDED_CHECKS):")
    for c in EXCLUDED_CHECKS:
        provenance.append(
            f"#   Checks: removed {c!r} from the flavor (deliberate"
            " rpmcrab divergence, ledgered in tests/parity/divergences.toml)"
        )
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
    if retargeted_log:
        provenance.append("#")
        provenance.append("# Retargeted Filters entries (exemption kept, its target")
        provenance.append("# moved; see RETARGET_FILTERS):")
        seen_retargeted = set()
        for entry in retargeted_log:
            if entry not in seen_retargeted:
                seen_retargeted.add(entry)
                provenance.append(f"#   {entry}")
    if added_log:
        provenance.append("#")
        provenance.append("# Added Filters entries (exemption upstream does not")
        provenance.append("# ship; see ADD_FILTERS):")
        seen_added = set()
        for entry in added_log:
            if entry not in seen_added:
                seen_added.add(entry)
                provenance.append(f"#   {entry}")
    if dropped_log:
        provenance.append("#")
        provenance.append(
            "# Dropped Filters entries (live findings rpmcrab deliberately"
        )
        provenance.append("# surfaces; see DROP_LIVE_FILTERS):")
        seen_dropped = set()
        for entry in dropped_log:
            if entry not in seen_dropped:
                seen_dropped.add(entry)
                provenance.append(f"#   {entry}")
    if scoped_log:
        provenance.append("#")
        provenance.append(
            "# Scoped Filters entries (narrowed to their recorded rationale;"
        )
        provenance.append("# see SCOPE_FILTERS):")
        seen_scoped = set()
        for entry in scoped_log:
            if entry not in seen_scoped:
                seen_scoped.add(entry)
                provenance.append(f"#   {entry}")
    if deduped_filters_log:
        provenance.append("#")
        provenance.append("# Deduped Filters entries (exact duplicates and")
        provenance.append("# same-finding lines subsumed by a broader literal;")
        provenance.append("# output-neutral, see dedupe_filters):")
        seen_deduped_filters = set()
        for entry in deduped_filters_log:
            if entry not in seen_deduped_filters:
                seen_deduped_filters.add(entry)
                provenance.append(f"#   {entry}")
    if pkg_pruned_log or HISTORICAL_PRUNES:
        provenance.append("#")
        provenance.append(
            "# Pruned whitelist stanzas (packages gone from Tumbleweed):"
        )
        seen_pkg = set()
        for entry in pkg_pruned_log:
            if entry not in seen_pkg:
                seen_pkg.add(entry)
                provenance.append(f"#   {entry}")
        # Historical deliberate removals: always documented even when the
        # stanza is absent from current upstream files.
        for table, pkg, reason in HISTORICAL_PRUNES:
            entry = f"whitelist: dropped [[{table}]] stanza for {pkg!r} ({reason})"
            if entry not in seen_pkg:
                seen_pkg.add(entry)
                provenance.append(f"#   {entry}")
    if pie_pruned_log:
        provenance.append("#")
        provenance.append("# Pruned pie-executables paths (shipped by no package in")
        provenance.append("# Factory):")
        for entry in pie_pruned_log:
            provenance.append(f"#   {entry}")
    if threshold_log:
        provenance.append("#")
        provenance.append("# Removed BadnessThreshold lines (rpmcrab has no badness")
        provenance.append("# threshold: severity decides the exit code; issue #699):")
        seen_threshold = set()
        for entry in threshold_log:
            if entry not in seen_threshold:
                seen_threshold.add(entry)
                provenance.append(f"#   {entry}")
    if adjudicated_log:
        provenance.append("#")
        provenance.append("# Adjudicated digest records (Factory content decides;")
        provenance.append("# see DIGEST_ADJUDICATIONS):")
        seen_adjudicated = set()
        for entry in adjudicated_log:
            if entry not in seen_adjudicated:
                seen_adjudicated.add(entry)
                provenance.append(f"#   {entry}")
    provenance.append("")
    return (
        result,
        "\n".join(provenance),
        pruned_log,
        pkg_pruned_log,
        pie_pruned_log,
        files_out,
        dropped_log,
        retargeted_log,
        scoped_log,
        deduped_filters_log,
        threshold_log,
        added_log,
        adjudicated_log,
    )


def emit_rs(files):
    """Render the generated Rust consts wiring the vendored files into the binary.

    The manifest is the full FILES set for the single vendored flavor.
    """
    lines = [
        "// Generated by scripts/generate-distro-configs.py — do not edit by hand.",
        "//",
        "// (filename, content) pairs, merged in order after the bundled defaults",
        "// and before XDG-discovered configs — mirroring how the distro",
        "// package's `/etc/xdg/rpmlint/*.toml` layer upstream.",
        "",
        '/// Vendored distro configs (upstream `opensuse` branch): the SUSE flavor.',
        '/// Selected by default (`Flavor = "opensuse"`) and for every other',
        "/// `Flavor` value the flavour key takes.",
        "const DISTRO_OPENSUSE_FILES: &[(&str, &str)] = &[",
    ]
    for filename in files:
        lines.extend(
            [
                "    (",
                f'        "{filename}",',
                f'        include_str!("../data/distro/opensuse/{filename}"),',
                "    ),",
            ]
        )
    lines.append("];")
    return "\n".join(lines) + "\n"


def write_all(result, provenance, files):
    for flavor, data in result.items():
        flavor_dir = DISTRO_DIR / flavor
        flavor_dir.mkdir(parents=True, exist_ok=True)
        # Remove files that are no longer vendored (stale).
        for existing in flavor_dir.glob("*.toml"):
            if existing.name not in data["files"]:
                existing.unlink()
        for filename, text in data["files"].items():
            (flavor_dir / filename).write_text(text, encoding="utf-8")
    # Remove flavor directories that are no longer vendored (stale).
    for existing in DISTRO_DIR.iterdir():
        if (
            existing.is_dir()
            and existing.name not in result
            and not (existing / "PROVENANCE").exists()
        ):
            shutil.rmtree(existing)
    (DISTRO_DIR / "PROVENANCE").write_text(provenance, encoding="utf-8")
    GENERATED_RS.write_text(emit_rs(files), encoding="utf-8")


DIFF_MAX_LINES = 50


def _diff_text(have_label, have_text, want_label, want_text, max_lines=DIFF_MAX_LINES):
    """Unified diff of have -> want, truncated to max_lines lines."""
    lines = list(
        difflib.unified_diff(
            have_text.splitlines(),
            want_text.splitlines(),
            fromfile=have_label,
            tofile=want_label,
            lineterm="",
        )
    )
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [
            f"... (truncated, {len(lines) - max_lines} more lines)"
        ]
    return "\n".join(lines)


def rewrite_pins(script_path, pins):
    """Persist refreshed (sha, date) per flavor into the PINS constant.

    Without this, --refresh would resolve new SHAs in-memory only while PINS
    stays stale, and the refresh PR would fail its own --check drift gate
    (which regenerates from PINS). Raises if a flavor entry is not found:
    a silent no-op here is a stale-pin guarantee.
    """
    text = script_path.read_text(encoding="utf-8")
    for flavor, (sha, date) in pins.items():
        pat = re.compile(
            r'("%s": \(\s*")[0-9a-f]{40}(",\s*")\d{4}-\d{2}-\d{2}(",)'
            % re.escape(flavor)
        )

        def _sub(m, sha=sha, date=date):
            return f"{m.group(1)}{sha}{m.group(2)}{date}{m.group(3)}"

        text, n = pat.subn(_sub, text, count=1)
        if n != 1:
            raise RuntimeError(f"could not rewrite PINS[{flavor!r}] in {script_path}")
    script_path.write_text(text, encoding="utf-8")


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
    if args.refresh:
        # The refresh PR must carry the final pins: --check regenerates from
        # PINS, so file-only pins would fail the PR's own drift gate.
        # Rewritten after --pin overrides so combined flags cannot diverge
        # the file from the in-memory pins used below.
        rewrite_pins(Path(__file__).resolve(), pins)

    ref_dir = Path(args.ref_dir) if args.ref_dir else None
    result, provenance, pruned_log, pkg_pruned_log, pie_pruned_log, files_out, dropped_log, retargeted_log, scoped_log, deduped_filters_log, threshold_log, added_log, adjudicated_log = generate(
        ref_dir=ref_dir, pins=pins
    )

    if args.check:
        failures = []
        diffs = []  # (label, unified-diff text) for drifted files
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            for flavor, data in result.items():
                for filename, text in data["files"].items():
                    (tmpdir / flavor).mkdir(exist_ok=True)
                    (tmpdir / flavor / filename).write_text(text, encoding="utf-8")
            (tmpdir / "PROVENANCE").write_text(provenance, encoding="utf-8")
            want_rs = emit_rs(check_rs_files(files_out))
            have_rs = (
                GENERATED_RS.read_text(encoding="utf-8")
                if GENERATED_RS.exists()
                else ""
            )
            if have_rs != want_rs:
                failures.append("drift: src/distro_files_generated.rs")
                diffs.append(
                    (
                        "src/distro_files_generated.rs",
                        _diff_text(
                            "vendored/src/distro_files_generated.rs",
                            have_rs,
                            "generated/src/distro_files_generated.rs",
                            want_rs,
                        ),
                    )
                )
            for flavor, data in result.items():
                for filename in data["files"]:
                    want = tmpdir / flavor / filename
                    have = DISTRO_DIR / flavor / filename
                    if filename in SYNC_MANAGED_FILES:
                        # Owned by the daily sync-upstream-whitelists job
                        # (advanced at branch TIPs between monthly refreshes);
                        # comparing them against the monthly PINS would flag
                        # every successful daily sync as drift.
                        if not have.exists():
                            failures.append(
                                f"missing vendored file: {flavor}/{filename}"
                            )
                        continue
                    if not have.exists():
                        failures.append(f"missing vendored file: {flavor}/{filename}")
                    elif want.read_text() != have.read_text():
                        failures.append(f"drift: {flavor}/{filename}")
                        diffs.append(
                            (
                                f"{flavor}/{filename}",
                                _diff_text(
                                    f"vendored/{flavor}/{filename}",
                                    have.read_text(encoding="utf-8"),
                                    f"generated/{flavor}/{filename}",
                                    want.read_text(encoding="utf-8"),
                                ),
                            )
                        )
            want_prov = tmpdir / "PROVENANCE"
            have_prov = DISTRO_DIR / "PROVENANCE"
            if not have_prov.exists():
                failures.append("missing vendored file: PROVENANCE")
            elif strip_sync_owned_provenance(
                want_prov.read_text()
            ) != strip_sync_owned_provenance(have_prov.read_text()):
                failures.append("drift: PROVENANCE")
                diffs.append(
                    (
                        "PROVENANCE",
                        _diff_text(
                            "vendored/PROVENANCE",
                            strip_sync_owned_provenance(
                                have_prov.read_text(encoding="utf-8")
                            ),
                            "generated/PROVENANCE",
                            strip_sync_owned_provenance(
                                want_prov.read_text(encoding="utf-8")
                            ),
                        ),
                    )
                )
        if failures:
            print("distro config drift detected:", file=sys.stderr)
            for f in failures:
                print(f"  {f}", file=sys.stderr)
            for label, diff in diffs:
                print(
                    f"\n--- diff: {label} (first {DIFF_MAX_LINES} lines) ---",
                    file=sys.stderr,
                )
                print(diff, file=sys.stderr)
            return 1
        print("distro configs match the pinned upstream (plus documented prunes).")
        return 0

    write_all(result, provenance, files_out)
    for entry in pruned_log + pkg_pruned_log + pie_pruned_log + dropped_log:
        print(f"pruned: {entry}")
    for entry in retargeted_log:
        print(f"retargeted: {entry}")
    for entry in added_log:
        print(f"added: {entry}")
    for entry in adjudicated_log:
        print(f"adjudicated: {entry}")
    for entry in deduped_filters_log:
        print(f"deduped: {entry}")
    for entry in threshold_log:
        print(f"threshold: {entry}")
    print(f"wrote {sum(len(d['files']) for d in result.values())} files + PROVENANCE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
