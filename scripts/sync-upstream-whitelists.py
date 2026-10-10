#!/usr/bin/env python3
"""Sync whitelist/config stanzas from upstream rpmlint branches into rpmcrab.

Fetches the TOML whitelist files from the given upstream rpmlint branch
(default: opensuse) and merges genuinely new stanzas into rpmcrab's copies
under crates/rpmcrab-core/data/distro/<flavor>/.

This is a SMART merge, not a blind copy:
- New stanzas (by `package = "..."`) not present locally are appended.
- Stanzas naming blocklisted packages (.github/whitelist-blocklist.txt)
  are never (re)introduced.
- Flavor-specific prunes (e.g. packages absent from Leap 16.0) are respected.
- rpmcrab-specific stanzas are never deleted.
- Existing stanzas are never modified (upstream hash updates come through
  the monthly distro-config-sync generator, not this job).

Usage:
    scripts/sync-upstream-whitelists.py [--branch opensuse] [--dry-run]

Exit 0 when nothing changed, 1 when files were modified (or would be
modified with --dry-run).
"""

import argparse
import re
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DISTRO_DIR = REPO / "crates/rpmcrab-core/data/distro"
BLOCKLIST_FILE = REPO / ".github/whitelist-blocklist.txt"

UPSTREAM_REPO = "rpm-software-management/rpmlint"
UPSTREAM_CONFIG_DIR = "configs/openSUSE"

# flavor -> upstream branch to sync from
BRANCHES = {
    "opensuse": "opensuse",
    "slfo": "opensuse-slfo-main",
}

# Whitelist files that carry per-package stanzas (others are full-file
# configs handled by the monthly generator).
WHITELIST_FILES = [
    "cron-whitelist.toml",
    "dbus-services.toml",
    "device-files-whitelist.toml",
    "permissions-whitelist.toml",
    "polkit-rules-whitelist.toml",
    "sudoers-whitelist.toml",
    "sysctl-whitelist.toml",
    "varlink-whitelist.toml",
    "world-writable-whitelist.toml",
]

# Packages absent from Leap 16.0: pruned from the slfo flavor only.
# (Mirrors the "not shipped in Leap 16.0" section of PRUNE_PACKAGES in
# scripts/generate-distro-configs.py. Keep in sync.)
SLFO_ONLY_PRUNES = {
    "pulseaudio",
    "pommed",
    "neard",
    "xpra",
    "iwd",
    "udev-mini",
    "low-memory-monitor",
    "transactional-update-notifier",
    "libgpiod-manager",
    "pam_ccreds",
    "nss-pam-ldapd",
    "pam_passwdqc",
    "pam_mktemp",
    "pam_chroot",
    "pam_yubico",
    "pam_saslauthd",
    "libcgroup-pam",
    "libcgroup-tools",
    "gnome-branding-Aeon",
    "plasma-branding-Kalpa",
    "monitoring-plugins-smart",
    "cscreen",
    "leafnode",
    "soapy-remote-server",
    "rubygem-passenger",
    "parallel-printer-support",
}

# Matches the start of a stanza: [[FileDigestGroup]] etc.
STANZA_RE = re.compile(r"^\[\[([A-Za-z0-9_]+)\]\]\s*$", re.M)
PACKAGE_RE = re.compile(r'^package\s*=\s*"([^"]+)"\s*$', re.M)


def load_blocklist():
    """Return the set of blocklisted package names."""
    blocklist = set()
    if BLOCKLIST_FILE.exists():
        for line in BLOCKLIST_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                blocklist.add(line)
    return blocklist


def resolve_branch_sha(branch):
    """Resolve a branch name to its tip commit SHA and date via the GitHub API."""
    import json
    url = f"https://api.github.com/repos/{UPSTREAM_REPO}/commits/{branch}"
    req = urllib.request.Request(url, headers={"User-Agent": "rpmcrab-whitelist-sync"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    return data["sha"], data["commit"]["committer"]["date"][:10]


def fetch_upstream(ref, filename):
    """Fetch a TOML file from the upstream repo at a branch or SHA. Returns text or None."""
    url = (
        f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/{ref}/"
        f"{UPSTREAM_CONFIG_DIR}/{filename}"
    )
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - network fetch, log and continue
        print(f"warning: could not fetch {url}: {exc}", file=sys.stderr)
        return None


def split_stanzas(text):
    """Split TOML text into (package, stanza_text) pairs."""
    stanzas = []
    matches = list(STANZA_RE.finditer(text))
    if not matches:
        return stanzas
    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        stanza_text = text[start:end].rstrip() + "\n"
        pkg_match = PACKAGE_RE.search(stanza_text)
        package = pkg_match.group(1) if pkg_match else None
        stanzas.append((package, stanza_text))
    return stanzas


def sync_file(local_path, upstream_text, blocklist, flavor, dry_run):
    """Merge upstream stanzas into the local file. Returns (added, skipped)."""
    local_text = local_path.read_text()
    local_packages = {
        pkg for pkg, _ in split_stanzas(local_text) if pkg is not None
    }

    # Flavor-specific prunes apply on top of the global blocklist
    effective_blocklist = set(blocklist)
    if flavor == "slfo":
        effective_blocklist |= SLFO_ONLY_PRUNES

    added = []
    skipped_blocklisted = []
    for package, stanza_text in split_stanzas(upstream_text):
        if package is None:
            continue
        if package in effective_blocklist:
            skipped_blocklisted.append(package)
            continue
        if package in local_packages:
            continue
        added.append((package, stanza_text))
        local_packages.add(package)

    if added and not dry_run:
        with local_path.open("a") as f:
            for _, stanza_text in added:
                f.write("\n" + stanza_text)

    return [p for p, _ in added], skipped_blocklisted


PROVENANCE_FILE = DISTRO_DIR / "PROVENANCE"


def update_provenance_pins(flavor_shas):
    """Update the opensuse-whitelists pin in PROVENANCE to the synced SHAs."""
    import re
    text = PROVENANCE_FILE.read_text()
    for flavor, (branch, sha, date) in flavor_shas.items():
        if flavor == "opensuse":
            pin_line = "# opensuse-whitelists: " + branch + " @ " + sha + " (" + date + ")\n"
            new_text, n = re.subn(r"^# opensuse-whitelists:.*$\n", pin_line, text, flags=re.M)
            if n == 0:
                new_text = text.replace("# slfo: ", pin_line + "# slfo: ", 1)
            text = new_text
    PROVENANCE_FILE.write_text(text)
    print("PROVENANCE whitelist pins refreshed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--branch", default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    blocklist = load_blocklist()
    print(f"blocklist: {len(blocklist)} entries (+ flavor-specific)")

    total_added = []
    total_skipped = []
    changed_files = []

    flavor_shas = {}
    for flavor, default_branch in BRANCHES.items():
        branch = args.branch or default_branch
        try:
            sha, date = resolve_branch_sha(branch)
        except Exception as exc:
            print(f"warning: could not resolve {branch}: {exc}", file=sys.stderr)
            continue
        flavor_shas[flavor] = (branch, sha, date)
        print(f"{flavor}: {branch} @ {sha[:12]} ({date})")

    for flavor, default_branch in BRANCHES.items():
        if flavor not in flavor_shas:
            continue
        branch, sha, date = flavor_shas[flavor]
        flavor_dir = DISTRO_DIR / flavor
        if not flavor_dir.is_dir():
            print(f"warning: {flavor_dir} not found, skipping", file=sys.stderr)
            continue
        for filename in WHITELIST_FILES:
            local_path = flavor_dir / filename
            if not local_path.exists():
                continue
            upstream_text = fetch_upstream(sha, filename)
            if upstream_text is None:
                continue
            added, skipped = sync_file(
                local_path, upstream_text, blocklist, flavor, args.dry_run
            )
            if added:
                changed_files.append(str(local_path.relative_to(REPO)))
                total_added.extend(f"{flavor}/{filename}: {p}" for p in added)
            total_skipped.extend(f"{flavor}/{filename}: {p}" for p in skipped)

    if changed_files and not args.dry_run:
        update_provenance_pins(flavor_shas)

    print(f"\nadded {len(total_added)} stanzas in {len(changed_files)} files:")
    for entry in total_added:
        print(f"  + {entry}")
    if total_skipped:
        print(f"\nskipped {len(total_skipped)} blocklisted:")
        for entry in sorted(set(total_skipped)):
            print(f"  - {entry} (blocklisted)")

    return 1 if changed_files else 0


if __name__ == "__main__":
    sys.exit(main())
