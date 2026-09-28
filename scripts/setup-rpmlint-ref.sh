#!/usr/bin/env bash
# Build the reference rpmlint environment used to capture parity cases.
#
# The parity contract is openSUSE-flavour rpmlint 2.10.0 (checks: 43), so the
# reference is built from the rpmlint `opensuse` branch (which carries the 15
# openSUSE-only checks and the openSUSE config), not from PyPI (upstream, 28
# checks). The librpm Python binding is NOT on PyPI, so the venv is created
# with --system-site-packages against a python3 that already has `import rpm`
# (the distro python3-rpm), and rpmlint is installed --no-deps.
#
# Idempotent. Safe to re-run; it rebuilds the venv and config.
#
# Usage: scripts/setup-rpmlint-ref.sh [REF_DIR]
#   REF_DIR defaults to .parity-ref/ in the repo root (gitignored).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ref_dir="${1:-$repo_root/.parity-ref}"
venv="$ref_dir/venv"
xdg="$ref_dir/xdg"
src="$ref_dir/rpmlint-src"

# --- 1. A python3 that has the real librpm binding ---------------------------
# Resolve to an ABSOLUTE path: `uv venv --python python3` would resolve the bare
# name to uv's own managed interpreter (e.g. 3.14), which cannot load the
# distro's python3.13 rpm C extension.
py=""
for cand in python3 /usr/bin/python3.13 /usr/bin/python3; do
  if "$cand" -c 'import rpm' 2>/dev/null; then py="$(command -v "$cand")"; break; fi
done
[ -n "$py" ] || { echo "no python3 with 'import rpm' (install python3-rpm)" >&2; exit 1; }
echo "reference python: $py ($("$py" -c 'import rpm; print(rpm.__version__)'))"

# --- 2. rpmlint opensuse branch checkout, pinned to an exact commit ----------
# The reference is only "frozen" if it is pinned: a floating `--branch opensuse`
# clone silently captures different references over time. Pin the blessed
# commit, verify the checkout matches, and record the SHA for the corpus
# (capture-parity.sh writes it into each case's meta.toml).
REF_SHA="84848c05c5571c22274a55ff9afdfe6d88c67dc9"
if [ -d "$src/.git" ] && [ "$(git -C "$src" rev-parse HEAD 2>/dev/null || true)" = "$REF_SHA" ]; then
  : # already at the pinned commit
else
  rm -rf "$src"
  git init -q "$src"
  git -C "$src" remote add origin https://github.com/rpm-software-management/rpmlint
  git -C "$src" fetch -q --depth 1 origin "$REF_SHA"
  git -C "$src" checkout -q FETCH_HEAD
fi
echo "$REF_SHA" > "$ref_dir/REF_SHA"

# --- 3. venv with the system rpm binding -------------------------------------
rm -rf "$venv"
uv venv --python "$py" --system-site-packages "$venv" >/dev/null
uv pip install --python "$venv/bin/python" --no-deps --quiet "$src"
uv pip install --python "$venv/bin/python" --quiet \
  pybeam pyxdg zstandard tomli-w python-magic

# --- 4. openSUSE config, minus the rpmlint-strict override -------------------
# The main rpmlint package excludes scoring-strict.override.toml (that is the
# rpmlint-strict subpackage); loading it would apply strict scoring.
rm -rf "$xdg"
mkdir -p "$xdg/rpmlint"
find "$src/configs/openSUSE" -name '*.toml' ! -name '*.override.toml' \
  -exec cp {} "$xdg/rpmlint/" \;

# --- 5. External tool prerequisites (fail closed) ----------------------------
# rpmlint shells out to these; a check that needs a missing tool is skipped or
# fails at init, so a capture taken with an incomplete tool set silently
# records DEGRADED output as the expected contract. Fail closed: refuse to set
# up until the full tool set is present, so a degraded capture can never enter
# the corpus. checkbashisms and dash are required by BashismsCheck at import
# time. enchant is optional (its absence only prints a warning, which
# capture-parity.sh normalizes out of expected stderr).
missing=0
for t in checkbashisms dash desktop-file-validate readelf objdump ldd file; do
  command -v "$t" >/dev/null 2>&1 || { echo "MISSING tool: $t" >&2; missing=1; }
done
if [ "$missing" -ne 0 ]; then
  echo "refusing to set up a degraded reference: install the missing tools" >&2
  exit 1
fi

cat <<EOF

Reference rpmlint ready.
  rpmlint:  $venv/bin/rpmlint
  config:   XDG_CONFIG_HOME=$xdg

Capture a case with:
  XDG_CONFIG_HOME=$xdg scripts/capture-parity.sh <case> <input.rpm|spec> [extra rpmlint args]
EOF
