#!/usr/bin/env bash
# Move every release-version surface to a new version in one step.
#
# Usage: scripts/bump-version.sh X.Y.Z
#
# Rewrites exactly the surfaces scripts/check-version-consistency.sh
# enforces — the [workspace.package] version, the path-dependency
# floors, Cargo.lock, the "current release" sentences and the generated
# man page — and runs that gate last, so a half-applied bump fails here.
# Historical mentions (ledger `since =`, §9 release notes) are left
# alone, as the gate leaves them. `make gen` builds rpmcrab-gen, so the
# RPM development headers must be installed.
set -euo pipefail

new="${1:-}"
if ! [[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 X.Y.Z" >&2
  exit 2
fi

cd "$(git rev-parse --show-toplevel)"

old=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
if [ -z "$old" ]; then
  echo "no [workspace.package] version found in Cargo.toml" >&2
  exit 1
fi
if [ "$old" = "$new" ] || [ "$(printf '%s\n%s\n' "$old" "$new" | sort -V | tail -1)" != "$new" ]; then
  echo "refusing to move $old to $new: the version only moves forward" >&2
  exit 1
fi

old_re=${old//./\\.}

sed -i "/^\[workspace\.package\]/,/^\[/s/^version = \"$old_re\"$/version = \"$new\"/" Cargo.toml
for manifest in crates/rpmcrab/Cargo.toml crates/rpmcrab-core/Cargo.toml; do
  for dep in rpmcrab rpmcrab-core; do
    sed -i "s/^${dep} = { version = \"$old_re\"/${dep} = { version = \"$new\"/" "$manifest"
  done
done
for doc in README.md docs/DESIGN.md; do
  sed -i "s/current release is \*\*$old_re\*\*/current release is **$new**/" "$doc"
done

# Only the workspace members' lock entries move; dependencies stay put.
cargo update --workspace --quiet
make gen

bash scripts/check-version-consistency.sh
