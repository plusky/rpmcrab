#!/usr/bin/env python3
"""Sync whitelist/config stanzas from upstream rpmlint branches into rpmcrab.

Fetches the TOML whitelist files from the given upstream rpmlint branch
(default: opensuse) and merges genuinely new stanzas into rpmcrab's copies
under crates/rpmcrab-core/data/distro/<flavor>/.

This is a SMART merge, not a blind copy:
- New stanzas not present locally are added in their upstream position.
- Stanzas naming blocklisted packages (.github/whitelist-blocklist.txt)
  are never (re)introduced.
- Flavor-specific prunes (e.g. packages absent from Leap 16.0) are respected,
  except entries the generator deliberately keeps for that flavor (lxd for
  slfo: still shipped in SLE 16, see PRUNE_PACKAGES).
- Existing stanzas are updated in place when upstream changes them
  (matched by full normalized stanza text).
- Stanzas upstream deleted are removed and reported (never silently).

Ownership split with scripts/generate-distro-configs.py: the generator owns
every vendored file's content at the monthly PINS, except the SYNC_MANAGED
whitelist files below, which this tool advances day-to-day at branch TIPs.
The generator's --check skips those files (and the per-flavor whitelist pins
in PROVENANCE this tool maintains), so a successful daily sync can never fail
the drift gate.

Usage:
    scripts/sync-upstream-whitelists.py [--branch opensuse] [--dry-run]

Exit 0 always. Signals change via stdout (CHANGED=true/false) and
$GITHUB_OUTPUT (changed=true/false) for workflow consumption.
"""

import argparse
import bisect
import os
import re
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DISTRO_DIR = REPO / "crates/rpmcrab-core/data/distro"
BLOCKLIST_FILE = REPO / ".github/whitelist-blocklist.txt"
PROVENANCE_FILE = DISTRO_DIR / "PROVENANCE"

UPSTREAM_REPO = "rpm-software-management/rpmlint"
UPSTREAM_CONFIG_DIR = "configs/openSUSE"

# flavor -> upstream branch to sync from
BRANCHES = {
    "opensuse": "opensuse",
    "slfo": "opensuse-slfo-main",
}


def _load_generator_module():
    """Import the generator module (source of truth for prune/file sets)."""
    import importlib.util
    gen_path = REPO / "scripts" / "generate-distro-configs.py"
    spec = importlib.util.spec_from_file_location("gen_distro", gen_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_generator_sets():
    """Import the generator's prune set, managed-file set and file sets.

    The generator is the source of truth for all three; duplicating them
    here caused the #417 data loss (a hand-copied prune list drifting).
    """
    mod = _load_generator_module()
    return (
        set(mod.PRUNE_PACKAGES_LEAP_ONLY),
        list(mod.SYNC_MANAGED_FILES),
        {flavor: set(files) for flavor, files in mod.FILES.items()},
    )


# Whitelist files that carry per-package stanzas (others are full-file
# configs handled by the monthly generator). Loaded from the generator at
# startup; must stay identical (guarded by test_sync_sets_match_generator).
WHITELIST_FILES = []

# Matches the start of a stanza: [[FileDigestGroup]] etc.
STANZA_RE = re.compile(r"^\[\[([A-Za-z0-9_]+)\]\]\s*$", re.M)
# Same shapes as the generator's _package_re/_packages_re (a stricter sync
# copy once bypassed the blocklist on trailing comments and multiline
# arrays, silently reintroducing blocklisted packages).
PACKAGE_RE = re.compile(r'^package\s*=\s*"([^"]+)"', re.M)
PACKAGES_RE = re.compile(r"^packages\s*=\s*\[(.*?)\]", re.M | re.S)

# Blocklist entries the generator deliberately keeps for the slfo flavor
# (removed from Factory, still shipped in SLE 16 / Leap 16.0). The daily
# sync must not strip them or the two tools flap forever.
BLOCKLIST_SLFO_KEEP = {"lxd"}


def load_blocklist():
    """Return the set of blocklisted package names.

    Fails closed: the blocklist file must exist. Running without it would
    silently skip enforcement, so a missing file is a hard error, not an
    empty blocklist.
    """
    if not BLOCKLIST_FILE.exists():
        raise RuntimeError(
            f"blocklist file missing: {BLOCKLIST_FILE} -- "
            "sync refuses to run without it (fail closed)"
        )
    blocklist = set()
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


def _stanza_boundaries(text):
    """Return [(table, start, end)] per stanza.

    Comment/blank lines preceding a stanza attach to the FOLLOWING stanza,
    so updating or deleting one stanza never eats its neighbor's comment.
    The file header (everything before the first stanza match) is never
    absorbed: stanza 0 always starts at its own match.
    """
    matches = list(STANZA_RE.finditer(text))
    if not matches:
        return []
    starts = [0]
    for nl in re.finditer("\n", text):
        starts.append(nl.end())
    lines = text.split("\n")

    def backtrack(pos):
        ln = bisect.bisect_right(starts, pos) - 1
        while ln > 0 and (
            lines[ln - 1].strip() == "" or lines[ln - 1].strip().startswith("#")
        ):
            ln -= 1
        return starts[ln]

    bounds = [matches[0].start()]
    bounds.extend(backtrack(m.start()) for m in matches[1:])
    spans = []
    for i, m in enumerate(matches):
        end = bounds[i + 1] if i + 1 < len(matches) else len(text)
        spans.append((m.group(1), bounds[i], end))
    return spans


def _stanza_packages(stanza_text):
    """Package names named by a stanza, ignoring commented-out keys."""
    code = "\n".join(
        line
        for line in stanza_text.splitlines()
        if not line.strip().startswith("#")
    )
    pkg_match = PACKAGE_RE.search(code)
    if pkg_match:
        return (pkg_match.group(1),)
    pkgs_match = PACKAGES_RE.search(code)
    if pkgs_match:
        return tuple(re.findall(r'"([^"]+)"', pkgs_match.group(1)))
    return None


def split_stanzas(text):
    """Split TOML text into (table, packages, stanza_text) triples.

    packages is a tuple of package names. Handles both
    `package = "foo"` and `packages = ["foo", "bar"]`.
    packages is None when the stanza names no package.
    """
    return [
        (table, _stanza_packages(text[start:end]), text[start:end].rstrip() + "\n")
        for table, start, end in _stanza_boundaries(text)
    ]


def normalize_stanza(text):
    """Normalize stanza text for dedup: collapse whitespace, sort lines.

    Keys on the FULL stanza text so upstream hash updates are detected.
    Comment lines are ignored for comparison (they travel with their
    stanza via _stanza_boundaries): a comment-only difference must neither
    count as an update nor drop the local comment.
    """
    # Remove trailing whitespace from each line, collapse multiple blank lines
    lines = [line.rstrip() for line in text.strip().split("\n")]
    # Remove empty lines for comparison (formatting differences shouldn't matter)
    lines = [
        line
        for line in lines
        if line and not line.strip().startswith("#")
    ]
    return "\n".join(sorted(lines))


def plan_merge(local_text, upstream_text, blocklist, flavor, leap_only_prunes):
    """Pure stanza merge.

    Returns (changed, new_text, added, updated, removed, skipped):
    - added: genuinely new stanzas (new identity),
    - updated: same (table, packages) identity, new content (e.g. hash bump),
    - removed: descriptions of stanzas gone upstream (identity also gone),
    - skipped: only the actually-blocklisted packages.
    new_text is None when nothing changed.
    Raises RuntimeError on an empty upstream response: zero stanzas must
    never read as "delete everything".
    """
    if not upstream_text.strip():
        raise RuntimeError(
            "empty upstream response -- refusing to delete every stanza"
        )
    m = STANZA_RE.search(local_text)
    local_header = local_text[: m.start()] if m else local_text
    local_stanzas = split_stanzas(local_text)
    upstream_stanzas = split_stanzas(upstream_text)
    if not upstream_stanzas:
        raise RuntimeError(
            "no stanzas in upstream response -- refusing to delete everything"
        )

    # Flavor-specific prunes apply on top of the global blocklist, except
    # entries the generator deliberately keeps for this flavor.
    effective_blocklist = set(blocklist)
    if flavor == "slfo":
        effective_blocklist |= leap_only_prunes
        effective_blocklist -= BLOCKLIST_SLFO_KEEP

    local_by_norm = {}
    for _, _, text in local_stanzas:
        norm = normalize_stanza(text)
        # Keep first occurrence if duplicates exist
        if norm not in local_by_norm:
            local_by_norm[norm] = text

    # Process upstream stanzas in order, building the new stanza list
    new_stanzas = []  # List of (table, packages, text) in upstream order
    seen_norms = set()
    added = 0
    updated = []
    skipped_blocklisted = []

    for table, packages, stanza_text in upstream_stanzas:
        if packages is None:
            # Stanzas without package info still dedup and count; they
            # just never match the blocklist.
            norm = normalize_stanza(stanza_text)
            if norm in seen_norms:
                continue
            seen_norms.add(norm)
            if norm in local_by_norm:
                new_stanzas.append((table, packages, local_by_norm[norm]))
            else:
                new_stanzas.append((table, packages, stanza_text))
                added += 1
            continue
        if packages and all(p in effective_blocklist for p in packages):
            # Only the actually-blocklisted members are reported; innocent
            # siblings of a skipped stanza must not read as blocklisted.
            skipped_blocklisted.extend(
                p for p in packages if p in effective_blocklist
            )
            continue
        norm = normalize_stanza(stanza_text)
        if norm in seen_norms:
            continue  # Duplicate in upstream itself
        seen_norms.add(norm)
        # Check if this exact stanza already exists locally
        if norm in local_by_norm:
            # Exists, keep the local version (preserve formatting)
            new_stanzas.append((table, packages, local_by_norm[norm]))
        else:
            # New or changed stanza; use upstream version
            new_stanzas.append((table, packages, stanza_text))
            added += 1

    old_by_norm = {}
    for table, pkgs, text in local_stanzas:
        if text:
            old_by_norm.setdefault(normalize_stanza(text), (table, pkgs))
    new_norms = {normalize_stanza(t) for _, _, t in new_stanzas if t}
    new_idents = {(t, p) for t, p, _ in new_stanzas}
    removed = []
    for norm, (table, pkgs) in old_by_norm.items():
        if norm in new_norms:
            continue
        # Same identity with new content is an update, not a deletion.
        desc = "[[%s]] for %s" % (table, ", ".join(pkgs) if pkgs else "<no package>")
        if (table, pkgs) in new_idents:
            updated.append(desc + " (content updated)")
        else:
            removed.append(desc)
    if set(old_by_norm) == new_norms:
        return False, None, 0, [], removed, skipped_blocklisted

    # Rewrite the file in place with upstream ordering
    new_text = local_header
    if not new_text.endswith("\n") and new_text:
        new_text += "\n"
    for _, _, stanza_text in new_stanzas:
        # Ensure exactly one blank line between stanzas (stanzas may carry
        # leading blank lines from comment attribution; strip those too).
        if new_text and not new_text.endswith("\n\n"):
            new_text = new_text.rstrip("\n") + "\n\n"
        new_text += stanza_text.strip("\n") + "\n"
    return True, new_text, added, updated, removed, skipped_blocklisted


def sync_file(local_path, upstream_text, blocklist, flavor, dry_run,
              leap_only_prunes):
    """Merge upstream stanzas into the file at local_path, rewriting in place.

    Returns (changed, added_count, updated, removed, skipped_blocklisted).
    """
    changed, new_text, added, updated, removed, skipped = plan_merge(
        local_path.read_text(), upstream_text, blocklist, flavor,
        leap_only_prunes,
    )
    if changed and not dry_run:
        local_path.write_text(new_text)
    return changed, added, updated, removed, skipped


def update_provenance_pins(flavor_pins):
    """Record the per-flavor sync SHAs in PROVENANCE.

    flavor_pins maps flavor -> (branch, sha, date). Owned by this tool; the
    generator mints these lines on write but its --check ignores them, so a
    daily pin advance never reads as drift.
    """
    want = {
        flavor: f"# {flavor}-whitelists: {branch} @ {sha} ({date})"
        for flavor, (branch, sha, date) in flavor_pins.items()
    }
    lines = PROVENANCE_FILE.read_text(encoding="utf-8").splitlines()
    out = []
    seen = set()
    for line in lines:
        replaced = False
        for flavor, newline in want.items():
            if line.startswith(f"# {flavor}-whitelists:"):
                out.append(newline)
                seen.add(flavor)
                replaced = True
                break
        if not replaced:
            out.append(line)
    for flavor, newline in want.items():
        if flavor not in seen:
            out.append(newline)
    PROVENANCE_FILE.write_text("\n".join(out) + "\n", encoding="utf-8")


def regenerate_rs(gen_mod, distro_dir):
    """Regenerate the Rust manifest when the sync toggled slfo dedup.

    Materializing a diverged slfo file (or deleting a reconverged one) flips
    which include_str! path DISTRO_SLFO_FILES must reference. The deduped set
    is recomputed from on-disk bytes: missing-or-identical means fallback to
    the opensuse copy, exactly the generator's rule. Returns True when the
    manifest changed.
    """
    deduped = [
        filename
        for filename in gen_mod.FILES["slfo"]
        if not (distro_dir / "slfo" / filename).exists()
        or (distro_dir / "slfo" / filename).read_bytes()
        == (distro_dir / "opensuse" / filename).read_bytes()
    ]
    want_rs = gen_mod.emit_rs(deduped)
    if gen_mod.GENERATED_RS.read_text(encoding="utf-8") != want_rs:
        gen_mod.GENERATED_RS.write_text(want_rs, encoding="utf-8")
        return True
    return False


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
                if "=" not in part:
                    parser.error(
                        f"bad --branch {args.branch!r}, "
                        "want BRANCH or flavor=branch,..."
                    )
                flavor, branch = part.split("=", 1)
                flavor, branch = flavor.strip(), branch.strip()
                if flavor not in BRANCHES:
                    parser.error(
                        f"bad --branch flavor {flavor!r}, "
                        f"want one of {sorted(BRANCHES)}"
                    )
                branch_overrides[flavor] = branch
        else:
            # Single branch applies to opensuse only (not slfo)
            # to avoid syncing Tumbleweed stanzas into slfo/
            branch_overrides["opensuse"] = args.branch

    blocklist = load_blocklist()
    gen_mod = _load_generator_module()
    leap_only_prunes = set(gen_mod.PRUNE_PACKAGES_LEAP_ONLY)
    whitelist_files = list(gen_mod.SYNC_MANAGED_FILES)
    files_by_flavor = {
        flavor: set(files) for flavor, files in gen_mod.FILES.items()
    }
    global WHITELIST_FILES
    WHITELIST_FILES = whitelist_files
    print(f"blocklist: {len(blocklist)} entries (+ {len(leap_only_prunes)} leap-only)")

    total_added = 0
    total_updated = []
    total_removed = []
    total_skipped = []
    changed_files = []
    changed_flavors = set()

    flavor_shas = {}
    for flavor, default_branch in BRANCHES.items():
        branch = branch_overrides.get(flavor, default_branch)
        # Raises on failure — fail fast, don't silently skip
        sha, date = resolve_branch_sha(branch)
        flavor_shas[flavor] = (branch, sha, date)
        print(f"{flavor}: {branch} @ {sha[:12]} ({date})")

    for flavor in BRANCHES:
        _, sha, _ = flavor_shas[flavor]
        flavor_dir = DISTRO_DIR / flavor
        if not flavor_dir.is_dir():
            raise RuntimeError(
                f"flavor dir missing: {flavor_dir} -- refusing silent skip"
            )
        for filename in WHITELIST_FILES:
            if filename not in files_by_flavor.get(flavor, set()):
                # E.g. varlink-whitelist.toml, which SLFO deleted upstream:
                # not vendored for this flavor, nothing to sync.
                print(f"skip {flavor}/{filename} (not vendored for flavor)")
                continue
            local_path = flavor_dir / filename
            # Raises on failure — fail fast
            upstream_text = fetch_upstream(sha, filename)
            if not local_path.exists():
                # Deduped files are absent while byte-identical to the
                # opensuse copy (the generated Rust consts fall back to it).
                # Merge against that copy and materialize only on divergence.
                if flavor == "opensuse":
                    raise RuntimeError(
                        f"missing managed file: {local_path} -- "
                        "opensuse files must always exist"
                    )
                base_path = DISTRO_DIR / "opensuse" / filename
                if not base_path.exists():
                    raise RuntimeError(
                        f"missing managed file: {local_path} (and no "
                        f"{base_path} fallback) -- refusing silent skip"
                    )
                changed, new_text, added, updated, removed, skipped = plan_merge(
                    base_path.read_text(), upstream_text, blocklist, flavor,
                    leap_only_prunes,
                )
                if changed and new_text != base_path.read_text():
                    if not args.dry_run:
                        local_path.write_text(new_text)
                    changed_files.append(str(local_path.relative_to(REPO)))
                    changed_flavors.add(flavor)
                    total_added += added
                    total_updated.extend(
                        f"{local_path.relative_to(REPO)}: {u}" for u in updated
                    )
                    total_removed.extend(
                        f"{local_path.relative_to(REPO)}: {r}" for r in removed
                    )
                total_skipped.extend(f"{flavor}/{filename}: {p}" for p in skipped)
                continue
            changed, added, updated, removed, skipped = sync_file(
                local_path, upstream_text, blocklist, flavor,
                args.dry_run, leap_only_prunes,
            )
            if changed:
                # A reconverged slfo file is left in place (byte-identical to
                # the opensuse copy); the monthly generator's write_all drops
                # it again via stale-file removal. Deleting here would flip
                # the generated manifest's include_str! path outside the
                # regeneration below.
                changed_files.append(str(local_path.relative_to(REPO)))
                changed_flavors.add(flavor)
                total_added += added
                total_updated.extend(
                    f"{local_path.relative_to(REPO)}: {u}" for u in updated
                )
                total_removed.extend(
                    f"{local_path.relative_to(REPO)}: {r}" for r in removed
                )
            total_skipped.extend(f"{flavor}/{filename}: {p}" for p in skipped)

    if changed_files and not args.dry_run:
        # Materializing a diverged slfo file flips its manifest entry from
        # the opensuse fallback to the slfo copy; regenerate atomically.
        if regenerate_rs(gen_mod, DISTRO_DIR):
            changed_files.append(str(gen_mod.GENERATED_RS.relative_to(REPO)))

    if changed_flavors and not args.dry_run:
        update_provenance_pins(
            {f: flavor_shas[f] for f in sorted(changed_flavors)}
        )
        changed_files.append(str(PROVENANCE_FILE.relative_to(REPO)))

    changed_str = "true" if changed_files else "false"
    print(f"\nCHANGED={changed_str}")
    print(
        f"sync-summary: added={total_added} "
        f"updated={len(total_updated)} removed={len(total_removed)} "
        f"files={len(changed_files)}"
    )
    print(f"added {total_added} stanzas in {len(changed_files)} files:")
    for f in changed_files:
        print(f"  + {f}")
    if total_updated:
        print(f"\nupdated {len(total_updated)} stanzas in place:")
        for entry in total_updated:
            print(f"  ~ {entry}")
    if total_removed:
        print(f"\nremoved {len(total_removed)} stanzas:")
        for entry in total_removed:
            print(f"  x {entry}")
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
