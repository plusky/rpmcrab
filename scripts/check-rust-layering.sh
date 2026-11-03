#!/usr/bin/env bash
# Architectural layering gate.
#
# The dependency direction is one-way: rpmcrab -> rpmcrab-core. rpmcrab-core
# must not depend on the binary crate or on any CLI concern (clap,
# tracing-subscriber), so that the renderer and every check are testable
# without a terminal. This script fails if a forbidden edge appears.
set -euo pipefail

core_manifest="crates/rpmcrab-core/Cargo.toml"

# Fail closed, not vacuous: a missing manifest makes grep exit 2,
# which the `if grep ... || grep ...` form reads as no-match, so the
# script would print "ok" with exit 0. Check the file first, and
# below distinguish a grep error (exit 2) from no match (exit 1).
if [[ ! -r "$core_manifest" ]]; then
  echo "layering: cannot read $core_manifest" >&2
  exit 1
fi

# A forbidden dependency can also be spelled as a dotted key
# (`clap.workspace = true`) or as a dependency-table header
# (`[dependencies.clap]`, `[dev-dependencies.clap]`, or a target-qualified
# `[target.<triple>.dependencies.clap]`): both are valid Cargo syntax
# the plain `name =` form misses. TOML allows whitespace around the dot
# (`[dependencies . clap]`), so the table pattern tolerates it, and a
# dependency can be renamed (`alias = { package = "clap", ... }` or a
# `[dependencies.alias]` table with a `package = "clap"` line), so a
# `package =` line naming a forbidden crate fails too; a `package =` line
# in a comment is not a dependency, so comment lines are filtered from
# that grep only.
forbidden_name='clap|clap_complete|clap_mangen|tracing-subscriber|rpmcrab'
forbidden_key='^\s*('"$forbidden_name"')(\s*\.[^=]*)?\s*='
forbidden_table='^\s*\[[^]]*dependencies\s*\.\s*('"$forbidden_name"')\s*\]'
forbidden_package="(^|[{,])\s*package\s*=\s*[\"']($forbidden_name)[\"']"

# Each grep runs in an `||` list so its exit status can be captured
# without `set -e` aborting on the no-match (1) case: 0 is a violation,
# 1 is a clean manifest, 2 is a read error and fails loud like a
# missing manifest instead of passing vacuously.
key_rc=0
grep -nE "$forbidden_key" "$core_manifest" || key_rc=$?
table_rc=0
grep -nE "$forbidden_table" "$core_manifest" || table_rc=$?
package_rc=0
grep -nE "$forbidden_package" "$core_manifest" | grep -vE '^[0-9]+:\s*#' || package_rc=$?
if [[ $key_rc -eq 2 || $table_rc -eq 2 ]]; then
  echo "layering: error reading $core_manifest" >&2
  exit 1
fi
if [[ $key_rc -eq 0 || $table_rc -eq 0 || $package_rc -eq 0 ]]; then
  echo "layering violation: rpmcrab-core must not depend on CLI concerns or the binary crate" >&2
  exit 1
fi

echo "layering: ok"
