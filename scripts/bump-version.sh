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

# No leading zeros: Cargo rejects them, and only after the tree is edited.
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

new="${1:-}"
if ! [[ "$new" =~ $semver ]]; then
  echo "usage: $0 X.Y.Z" >&2
  exit 2
fi

cd "$(git rev-parse --show-toplevel)"

old=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
if ! [[ "$old" =~ $semver ]]; then
  echo "no X.Y.Z [workspace.package] version found in Cargo.toml (got '$old')" >&2
  exit 1
fi

# Numeric X.Y.Z comparison (10# keeps leading zeros decimal); portable,
# unlike sort -V.
IFS=. read -r o1 o2 o3 <<<"$old"
IFS=. read -r n1 n2 n3 <<<"$new"
if ((10#$n1 != 10#$o1)); then
  forward=$((10#$n1 > 10#$o1))
elif ((10#$n2 != 10#$o2)); then
  forward=$((10#$n2 > 10#$o2))
else
  forward=$((10#$n3 > 10#$o3))
fi
if [ "$forward" -ne 1 ]; then
  echo "refusing to move $old to $new: the version only moves forward" >&2
  echo "(a half-applied earlier run is undone with: git checkout -- .)" >&2
  exit 1
fi

# In-place edit without GNU sed -i; `cat >` keeps the file's mode.
subst() { # sed-script file
  local tmp
  tmp=$(mktemp)
  sed "$1" "$2" >"$tmp"
  cat "$tmp" >"$2"
  rm -f "$tmp"
}

old_re=${old//./\\.}

subst "/^\[workspace\.package\]/,/^\[/s/^version = \"$old_re\"$/version = \"$new\"/" Cargo.toml
for manifest in crates/rpmcrab/Cargo.toml crates/rpmcrab-core/Cargo.toml; do
  for dep in rpmcrab rpmcrab-core; do
    subst "s/^${dep} = { version = \"$old_re\"/${dep} = { version = \"$new\"/" "$manifest"
  done
done
for doc in README.md docs/DESIGN.md; do
  subst "s/current release is \*\*$old_re\*\*/current release is **$new**/" "$doc"
done

# --workspace updates only the workspace members' lock entries;
# dependencies stay put. Anything more (a newer cargo rewriting the lock
# format, say) does not belong in a version bump.
cargo update --workspace --quiet
if [ "$(git diff --numstat -- Cargo.lock | cut -f1-2)" != "$(printf '2\t2')" ]; then
  echo "Cargo.lock changed beyond the two workspace version lines:" >&2
  git diff -- Cargo.lock >&2
  exit 1
fi
make gen

bash scripts/check-version-consistency.sh
