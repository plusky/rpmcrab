#!/usr/bin/env python3
"""Sync whitelist/config stanzas from upstream rpmlint branches into rpmcrab.

Fetches the TOML whitelist files from the given upstream rpmlint branch
(default: opensuse) and merges genuinely new stanzas into rpmcrab's copies
under crates/rpmcrab-core/data/distro/<flavor>/.

This is a SMART merge, not a blind copy:
- New stanzas not present locally are added in their upstream position.
- Stanzas naming blocklisted packages (.github/whitelist-blocklist.txt)
  are never (re)introduced.
- Flavor-specific prunes (e.g. packages absent from Leap 16.0) are respected.
- Existing stanzas are updated in place when upstream changes them
  (matched by full normalized stanza text).
- Stanzas upstream deleted are removed (unless blocklisted logic applies).

Usage:
    scripts/sync-upstream-whitelists.py [--branch opensuse] [--dry-run]

Exit 0 always. Signals change via stdout (CHANGED=true/false) and
$GITHUB_OUTPUT (changed=true/false) for workflow consumption.
"""

import argparse
import os
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

# Import the Leap-only prune set from the generator instead of duplicating.
# The generator is the source of truth for PRUNE_PACKAGES_LEAP_ONLY.
def _load_leap_only_prunes():
    """Import PRUNE_PACKAGES_LEAP_ONLY from generate-distro-configs.py."""
    import importlib.util
    gen_path = REPO / "scripts" / "generate-distro-configs.py"
    spec = importlib.util.spec_from_file_location("gen_distro", gen_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return set(mod.PRUNE_PACKAGES_LEAP_ONLY)

# Matches the start of a stanza: [[FileDigestGroup]] etc.
STANZA_RE = re.compile(r"^\[\[([A-Za-z0-9_]+)\]\]\s*$", re.M)
PACKAGE_RE = re.compile(r'^package\s*=\s*"([^"]+)"\s*$', re.M)
PACKAGES_RE = re.compile(r'^packages\s*=\s*\[(.*?)\]\s*$', re.M)


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
    """Resolve a branch name to its tip commit SHA and date via the GitHub API.

    Raises RuntimeError on failure — a network blip must fail the job,
    not produce a green run with nothing synced.
    """
    import json
    url = f"https://api.github.com/repos/{UPSTREAM_REPO}/commits/{branch}"
    req = urllib.request.Request(url, headers={"User-Agent": "rpmcrab-whitelist-sync"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
    except Exception as exc:
        raise RuntimeError(f"could not resolve branch {branch}: {exc}") from exc
    return data["sha"], data["commit"]["committer"]["date"][:10]


def fetch_upstream(ref, filename):
    """Fetch a TOML file from the upstream repo at a branch or SHA.

    Raises RuntimeError on failure — a network blip must fail the job.
    """
    url = (
        f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/{ref}/"
        f"{UPSTREAM_CONFIG_DIR}/{filename}"
    )
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except Exception as exc:
        raise RuntimeError(f"could not fetch {url}: {exc}") from exc


def split_stanzas(text):
    """Split TOML text into (packages, stanza_text) pairs.

    packages is a tuple of package names. Handles both
    `package = "foo"` and `packages = ["foo", "bar"]`.
    Returns (None, stanza_text) if no package key is found.
    """
    stanzas = []
    matches = list(STANZA_RE.finditer(text))
    if not matches:
        return stanzas
    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        stanza_text = text[start:end].rstrip() + "\n"
        packages = None
        pkg_match = PACKAGE_RE.search(stanza_text)
        if pkg_match:
            packages = (pkg_match.group(1),)
        else:
            pkgs_match = PACKAGES_RE.search(stanza_text)
            if pkgs_match:
                packages = tuple(re.findall(r'"([^"]+)"', pkgs_match.group(1)))
        stanzas.append((packages, stanza_text))
    return stanzas


def normalize_stanza(text):
    """Normalize stanza text for dedup: collapse whitespace, sort lines.

    Keys on the FULL stanza text so upstream hash updates are detected.
    """
    # Remove trailing whitespace from each line, collapse multiple blank lines
    lines = [line.rstrip() for line in text.strip().split("\n")]
    # Remove empty lines for comparison (formatting differences shouldn't matter)
    lines = [l for l in lines if l]
    return "\n".join(sorted(lines))


def sync_file(local_path, upstream_text, blocklist, flavor, dry_run, leap_only_prunes):
    """Merge upstream stanzas into the local file, rewriting in place.

    Returns (changed, added_count, removed_count).
    - New stanzas are inserted in upstream order.
    - Changed stanzas (same packages, different content) are updated in place.
    - Deleted upstream stanzas are removed.
    - Blocklisted packages are never (re)introduced.
    """
    local_text = local_path.read_text()

    # Split header (everything before first stanza) from stanzas
    m = STANZA_RE.search(local_text)
    if not m:
        # No stanzas in local file; treat entire file as header
        local_header = local_text
        local_stanzas = []
    else:
        local_header = local_text[:m.start()]
        local_stanzas = split_stanzas(local_text)

    upstream_stanzas = split_stanzas(upstream_text)

    # Flavor-specific prunes apply on top of the global blocklist
    effective_blocklist = set(blocklist)
    if flavor == "slfo":
        effective_blocklist |= leap_only_prunes

    # Build map of normalized local stanzas for dedup
    # Key: normalized text -> (packages, original_text, index)
    local_by_norm = {}
    for idx, (pkgs, text) in enumerate(local_stanzas):
        if pkgs is None:
            continue
        norm = normalize_stanza(text)
        # Keep first occurrence if duplicates exist
        if norm not in local_by_norm:
            local_by_norm[norm] = (pkgs, text, idx)

    # Process upstream stanzas in order, building the new stanza list
    new_stanzas = []  # List of (packages, text) in upstream order
    seen_norms = set()
    added = 0
    skipped_blocklisted = []

    for packages, stanza_text in upstream_stanzas:
        if packages is None:
            # Keep stanzas without package info (shouldn't happen, but be safe)
            norm = normalize_stanza(stanza_text)
            if norm not in seen_norms:
                new_stanzas.append((packages, stanza_text))
                seen_norms.add(norm)
            continue
        if any(p in effective_blocklist for p in packages):
            skipped_blocklisted.extend(packages)
            continue
        norm = normalize_stanza(stanza_text)
        if norm in seen_norms:
            continue  # Duplicate in upstream itself
        seen_norms.add(norm)
        # Check if this exact stanza already exists locally
        if norm in local_by_norm:
            # Exists, keep the local version (preserve formatting)
            _, local_text_orig, _ = local_by_norm[norm]
            new_stanzas.append((packages, local_text_orig))
        else:
            # New or changed stanza; use upstream version
            new_stanzas.append((packages, stanza_text))
            added += 1

    # Check if anything changed
    old_norms = {normalize_stanza(t) for _, t in local_stanzas if t}
    new_norms = {normalize_stanza(t) for _, t in new_stanzas if t}
    changed = (old_norms != new_norms)

    if changed and not dry_run:
        # Rewrite the file in place with upstream ordering
        new_text = local_header
        if not new_text.endswith("\n") and new_text:
            new_text += "\n"
        for _, stanza_text in new_stanzas:
            # Ensure exactly one blank line between stanzas
            if new_text and not new_text.endswith("\n\n"):
                new_text = new_text.rstrip("\n") + "\n\n"
            new_text += stanza_text.rstrip("\n") + "\n"
        local_path.write_text(new_text)

    return changed, added, skipped_blocklisted


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--branch", default=None,
                        help="Branch override. Format: 'branch' (applies to opensuse only) "
                             "or 'opensuse=branch1,slfo=branch2' for per-flavor.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    # Parse per-flavor branch overrides
    branch_overrides = {}
    if args.branch:
        if "=" in args.branch:
            # Per-flavor: "opensuse=foo,slfo=bar"
            for part in args.branch.split(","):
                flavor, branch = part.split("=", 1)
                branch_overrides[flavor.strip()] = branch.strip()
        else:
            # Single branch applies to opensuse only (not slfo)
            # to avoid syncing Tumbleweed stanzas into slfo/
            branch_overrides["opensuse"] = args.branch

    blocklist = load_blocklist()
    leap_only_prunes = _load_leap_only_prunes()
    print(f"blocklist: {len(blocklist)} entries (+ {len(leap_only_prunes)} leap-only)")

    total_added = 0
    total_skipped = []
    changed_files = []

    flavor_shas = {}
    for flavor, default_branch in BRANCHES.items():
        branch = branch_overrides.get(flavor, default_branch)
        # Raises on failure — fail fast, don't silently skip
        sha, date = resolve_branch_sha(branch)
        flavor_shas[flavor] = (branch, sha, date)
        print(f"{flavor}: {branch} @ {sha[:12]} ({date})")

    for flavor, default_branch in BRANCHES.items():
        branch, sha, date = flavor_shas[flavor]
        flavor_dir = DISTRO_DIR / flavor
        if not flavor_dir.is_dir():
            print(f"warning: {flavor_dir} not found, skipping", file=sys.stderr)
            continue
        for filename in WHITELIST_FILES:
            local_path = flavor_dir / filename
            if not local_path.exists():
                continue
            # Raises on failure — fail fast
            upstream_text = fetch_upstream(sha, filename)
            changed, added, skipped = sync_file(
                local_path, upstream_text, blocklist, flavor,
                args.dry_run, leap_only_prunes
            )
            if changed:
                changed_files.append(str(local_path.relative_to(REPO)))
                total_added += added
            total_skipped.extend(f"{flavor}/{filename}: {p}" for p in skipped)

    changed_str = "true" if changed_files else "false"
    print(f"\nCHANGED={changed_str}")
    print(f"added {total_added} stanzas in {len(changed_files)} files:")
    for f in changed_files:
        print(f"  + {f}")
    if total_skipped:
        print(f"\nskipped {len(total_skipped)} blocklisted:")
        for entry in sorted(set(total_skipped)):
            print(f"  - {entry} (blocklisted)")

    # Signal via GITHUB_OUTPUT for workflow consumption
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"changed={changed_str}\n")

    # Always exit 0; signal change via stdout/GITHUB_OUTPUT
    # (exit 1 on change would kill the workflow under set -euo pipefail
    # before the PR creation step)
    return 0


if __name__ == "__main__":
    sys.exit(main())
