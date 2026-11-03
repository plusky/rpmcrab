#!/usr/bin/env bash
# Architectural layering gate.
#
# The dependency direction is one-way: rpmcrab -> rpmcrab-core. rpmcrab-core
# must not depend on the binary crate or on any CLI concern (clap,
# tracing-subscriber), so that the renderer and every check are testable
# without a terminal. This script fails if a forbidden edge appears.
set -euo pipefail

core_manifest="crates/rpmcrab-core/Cargo.toml"

# A forbidden dependency can also be spelled as a dotted key
# (`clap.workspace = true`) or as a dependency-table header
# (`[dependencies.clap]`, `[dev-dependencies.clap]`, or a target-qualified
# `[target.<triple>.dependencies.clap]`): both are valid Cargo syntax
# the plain `name =` form misses.
forbidden_name='clap|clap_complete|clap_mangen|tracing-subscriber|rpmcrab'
forbidden_key='^\s*('"$forbidden_name"')(\s*\.[^=]*)?\s*='
forbidden_table='^\s*\[[^]]*dependencies\.('"$forbidden_name"')\s*\]'

if grep -nE "$forbidden_key" "$core_manifest" || grep -nE "$forbidden_table" "$core_manifest"; then
  echo "layering violation: rpmcrab-core must not depend on CLI concerns or the binary crate" >&2
  exit 1
fi

echo "layering: ok"
