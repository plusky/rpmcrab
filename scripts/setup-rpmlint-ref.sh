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

# --- 2. rpmlint opensuse branch checkout -------------------------------------
if [ ! -d "$src/.git" ]; then
  rm -rf "$src"
  git clone --quiet --depth 1 --branch opensuse \
    https://github.com/rpm-software-management/rpmlint "$src"
fi

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

# --- 5. External tool prerequisites ------------------------------------------
# rpmlint shells out to these; the checks that need a missing tool are skipped
# or fail at init. checkbashisms and dash are required by BashismsCheck at
# import time, so their absence is fatal, not graceful.
missing=0
for t in checkbashisms dash desktop-file-validate readelf objdump ldd file; do
  command -v "$t" >/dev/null 2>&1 || { echo "MISSING tool: $t" >&2; missing=1; }
done
[ "$missing" -eq 0 ] || echo "install the missing tools before capturing" >&2

cat <<EOF

Reference rpmlint ready.
  rpmlint:  $venv/bin/rpmlint
  config:   XDG_CONFIG_HOME=$xdg

Capture a case with:
  XDG_CONFIG_HOME=$xdg scripts/capture-parity.sh <case> <input.rpm|spec> [extra rpmlint args]
EOF
