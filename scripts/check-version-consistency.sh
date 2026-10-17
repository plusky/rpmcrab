#!/usr/bin/env bash
# Version consistency gate.
#
# [workspace.package] version in Cargo.toml is the single source of truth
# (docs/DESIGN.md §9). Every other place that restates the release version
# must agree with it, so a bump that touches only some of the surfaces
# fails here, on the PR that introduces the drift, instead of surfacing
# later when a tag, a reader or a packaged man page disagrees. Historical
# mentions are not restatements and are deliberately not checked: the
# parity ledger's `since =` fields and §9's per-release notes keep the
# version they describe forever.
set -euo pipefail

failures=0

report() { # surface found
  echo "version mismatch: $1 is $2, expected $version (Cargo.toml [workspace.package])" >&2
  failures=$((failures + 1))
}

missing() { # surface
  echo "version surface not found: $1" >&2
  failures=$((failures + 1))
}

# Same extraction as .github/workflows/release.yml: scope to the
# [workspace.package] table and anchor at the closing quote, so a
# `version =` in any earlier table cannot win and a trailing comment
# cannot leak into the value.
version=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
if [ -z "$version" ]; then
  echo "no [workspace.package] version found in Cargo.toml" >&2
  exit 1
fi

members="rpmcrab rpmcrab-core"

# Member manifests: the [package] version either inherits the workspace
# version or restates it literally and must then agree.
for member in $members; do
  manifest="crates/$member/Cargo.toml"
  line=$(awk '/^\[package\]/{inpkg=1; next} /^\[/{inpkg=0} inpkg && /^version/{print; exit}' "$manifest")
  case "$line" in
    "version.workspace = true") ;;
    'version = "'*'"')
      found=$(printf '%s' "$line" | sed -e 's/^version = "//' -e 's/"$//')
      [ "$found" = "$version" ] || report "$manifest [package] version" "$found"
      ;;
    *) missing "$manifest [package] version" ;;
  esac
done

# Path-dependency version strings between workspace members (the root
# Cargo.toml explains why these are explicit: cargo-deny wildcards).
for manifest in crates/rpmcrab/Cargo.toml crates/rpmcrab-core/Cargo.toml; do
  for dep in $members; do
    found=$(sed -n "s/^${dep} = { version = \"\([^\"]*\)\".*/\1/p" "$manifest")
    if [ -n "$found" ] && [ "$found" != "$version" ]; then
      report "$manifest ($dep dependency)" "$found"
    fi
  done
done

# Cargo.lock: the [[package]] entry of each workspace member.
for member in $members; do
  found=$(awk -v pkg="$member" '
    /^\[\[package\]\]/ { name="" }
    /^name = / { n=$3; gsub(/"/, "", n); name=n }
    /^version = / && name == pkg { v=$3; gsub(/"/, "", v); print v; exit }
  ' Cargo.lock)
  if [ -z "$found" ]; then
    missing "Cargo.lock ($member)"
  elif [ "$found" != "$version" ]; then
    report "Cargo.lock ($member)" "$found"
  fi
done

# The "current release" sentence in the two documents that carry it.
for doc in README.md docs/DESIGN.md; do
  found=$(sed -n 's/.*current release is \*\*\([^*]*\)\*\*.*/\1/p' "$doc" | head -1)
  if [ -z "$found" ]; then
    missing "$doc (current release sentence)"
  elif [ "$found" != "$version" ]; then
    report "$doc" "$found"
  fi
done

# The checked-in man page: the .TH header and the VERSION section. The
# assets-drift CI job already proves the page matches what rpmcrab-gen
# generates from the manifest; this proves the manifest side of the bump
# actually moved.
man="crates/rpmcrab/man/rpmcrab.1"
found=$(sed -n 's/^\.TH rpmcrab 1 *"rpmcrab \([^"]*\)".*/\1/p' "$man" | head -1)
if [ -z "$found" ]; then
  missing "$man (.TH header)"
elif [ "$found" != "$version" ]; then
  report "$man (.TH header)" "$found"
fi
found=$(awk '/^\.SH VERSION/{getline; print; exit}' "$man")
found=${found#v}
if [ -z "$found" ]; then
  missing "$man (VERSION section)"
elif [ "$found" != "$version" ]; then
  report "$man (VERSION section)" "$found"
fi

if [ "$failures" -ne 0 ]; then
  echo "version consistency: $failures divergent surface(s); a release bump must move every surface together" >&2
  exit 1
fi

echo "versions: ok ($version)"
