#!/usr/bin/env bash
# Architectural layering gate.
#
# The dependency direction is one-way: rpmcrab -> rpmcrab-core. rpmcrab-core
# must not depend on the binary crate or on any CLI concern (clap,
# tracing-subscriber), so that the renderer and every check are testable
# without a terminal. This script fails if a forbidden edge appears.
set -euo pipefail

core_manifest="crates/rpmcrab-core/Cargo.toml"

forbidden='^\s*(clap|clap_complete|clap_mangen|tracing-subscriber|rpmcrab)\s*='

if grep -nE "$forbidden" "$core_manifest"; then
  echo "layering violation: rpmcrab-core must not depend on CLI concerns or the binary crate" >&2
  exit 1
fi

echo "layering: ok"
