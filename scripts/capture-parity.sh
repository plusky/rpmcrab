#!/usr/bin/env bash
# Capture one parity case: run the reference rpmlint on the given input(s) and
# record the sanitized expected output plus provenance.
#
# Expected output is NORMALIZED at capture time so it is stable across hosts
# and runs; the parity runner (M1+) applies the same normalization to actual
# output before diffing. The rules (see tests/parity/README.md):
#   - `has taken X s` and any time-report durations are masked (wall-clock).
#   - The reference venv / XDG config paths in the header become <VENV>/<XDG>.
#   - No host path, build root, home dir or username may survive (leak gate).
#
# Usage:
#   scripts/capture-parity.sh <case> <input.rpm|spec> [more inputs] [-- extra rpmlint args]
# Environment:
#   RPMLINT_REF   reference env dir (default: .parity-ref/ in repo root)
#   XDG_CONFIG_HOME  must point at the reference config (default: $RPMLINT_REF/xdg)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ref_dir="${RPMLINT_REF:-$repo_root/.parity-ref}"
venv="$ref_dir/venv"
# The reference env's own openSUSE config is the default. Do NOT inherit the
# ambient XDG_CONFIG_HOME (that points at the operator's real user config and
# would silently drop the openSUSE checks). Override only via RPMLINT_XDG.
# Absolutize: the script cd's into the input dir before running rpmlint, so a
# relative path would resolve to nothing after the cd.
xdg="$(cd "${RPMLINT_XDG:-$ref_dir/xdg}" && pwd)"
rpmlint="$venv/bin/rpmlint"
[ -x "$rpmlint" ] || { echo "no reference rpmlint; run scripts/setup-rpmlint-ref.sh" >&2; exit 1; }

[ $# -ge 2 ] || { echo "usage: $0 <case> <input> [more inputs] [-- extra args]" >&2; exit 2; }
case_name="$1"; shift
# The case name becomes a directory under cases/; reject anything that escapes
# it (path traversal by typo).
case "$case_name" in
  */*|*..*|"") { echo "invalid case name: '$case_name'" >&2; exit 2; } ;;
esac

# Split inputs from any extra rpmlint args after `--`.
inputs=(); extra=()
while [ $# -gt 0 ]; do
  if [ "$1" = "--" ]; then shift; extra=("$@"); break; fi
  inputs+=("$1"); shift
done

case_dir="$repo_root/tests/parity/cases/$case_name"
[ ! -e "$case_dir" ] || { echo "case already exists: $case_dir" >&2; exit 1; }
mkdir -p "$case_dir/input" "$case_dir/expected"

# Stage inputs under stable basenames and record sha256.
declare -a sha_lines=()
basenames=()
for f in "${inputs[@]}"; do
  [ -f "$f" ] || { echo "input not found: $f" >&2; exit 2; }
  base="$(basename "$f")"
  cp "$f" "$case_dir/input/$base"
  basenames+=("$base")
  sha_lines+=("[[input]]"$'\n'"file = \"$base\""$'\n'"sha256 = \"$(sha256sum "$case_dir/input/$base" | cut -d' ' -f1)\"")
done

# Run from inside the input dir so no working-directory path leaks into output.
# rpmlint findings name the package (from its header), not the file path.
set +e
(
  cd "$case_dir/input"
  XDG_CONFIG_HOME="$xdg" "$rpmlint" "${extra[@]}" "${basenames[@]}" \
    >"$case_dir/expected/stdout.raw" 2>"$case_dir/expected/stderr.raw"
  echo $? >"$case_dir/expected/exit"
)
set -e

# --- normalize ---------------------------------------------------------------
# sed-escape a path for use as the LHS (regex) or RHS (replacement) pattern, so
# a path containing `|`, `&` or a regex metachar cannot break the expression.
sed_lhs() { printf '%s' "$1" | sed -e 's/[][\.*^$/|]/\\&/g'; }
sed_rhs() { printf '%s' "$1" | sed -e 's/[&|]/\\&/g'; }
sanitize() {
  local raw="$1" out="$2"
  sed -e "s|$(sed_lhs "$venv")|$(sed_rhs '<VENV>')|g" \
      -e "s|$(sed_lhs "$xdg")|$(sed_rhs '<XDG>')|g" \
      -e "s|$(sed_lhs "$ref_dir")|$(sed_rhs '<REF>')|g" \
      -e "s|$(sed_lhs "$HOME")|$(sed_rhs '<HOME>')|g" \
      -e "s|$(sed_lhs "$case_dir")|$(sed_rhs '<CASE>')|g" \
      -e 's/has taken [0-9.]* s/has taken <DURATION> s/' \
      "$raw" > "$out"
}
sanitize "$case_dir/expected/stdout.raw" "$case_dir/expected/stdout"
# stderr additionally drops the enchant-availability warning: it depends on
# whether the optional enchant backend is installed on the capture host, not on
# rpmcrab. The parity runner drops it from actual output the same way.
sanitize "$case_dir/expected/stderr.raw" "$case_dir/expected/stderr.tmp"
grep -v 'unable to init enchant' "$case_dir/expected/stderr.tmp" > "$case_dir/expected/stderr" || true
rm -f "$case_dir/expected/stdout.raw" "$case_dir/expected/stderr.raw" "$case_dir/expected/stderr.tmp"

# --- leak gate ---------------------------------------------------------------
# A captured case must be free of host-specific paths and identities. If any
# survive normalization, the capture is unusable and must be fixed, not committed.
if grep -RInE "$venv|$xdg|$ref_dir|$HOME|/home/[^ ]+|/var/tmp/[^ ]+|$(id -un)" \
     "$case_dir/expected/stdout" "$case_dir/expected/stderr"; then
  echo "LEAK: host path/identity survived sanitization in $case_name" >&2
  exit 1
fi

# --- provenance ---------------------------------------------------------------
version="$("$rpmlint" --version 2>/dev/null | head -1)"
# The pinned reference commit this capture came from (set by setup-rpmlint-ref.sh).
ref_sha="$(cat "$ref_dir/REF_SHA" 2>/dev/null || echo UNKNOWN)"
# Record which external tools were present, so a degraded capture is detectable
# after the fact (missing tools change findings — see setup-rpmlint-ref.sh).
present_tools=()
for t in checkbashisms dash desktop-file-validate readelf objdump ldd file appstreamcli; do
  command -v "$t" >/dev/null 2>&1 && present_tools+=("\"$t\"")
done
tools_joined="$(IFS=', '; echo "${present_tools[*]}")"
{
    echo 'kind = "captured"'
    echo "rpmlint = \"$version\""
    echo "reference_sha = \"$ref_sha\""
    # The reference's own flavour (its config), recorded at capture time.
    # Distinct from the rpmcrab `Flavor` TOML key (the flavor selector).
    echo 'flavour = "openSUSE"'
    # The reference check count under the openSUSE overlay at capture time
    # (see tests/parity/README.md "The overlay trap"). A port-side runner
    # must reproduce this check set; update the number if the overlay's
    # check list changes.
    echo 'checks = 43'
    # argv: extra args then input basenames, each quoted, joined by ", ".
    argv_items=()
    for a in ${extra[@]+"${extra[@]}"}; do argv_items+=("\"$a\""); done
    for b in "${basenames[@]}"; do argv_items+=("\"$b\""); done
    printf -v argv_joined '%s, ' "${argv_items[@]}"
    echo "argv = [${argv_joined%, }]"
    echo "captured = \"$(date +%F)\""
  echo
  echo '[source]'
  echo 'description = ""'
  echo
  echo '[tools]'
  echo "present = [$tools_joined]"
  echo
  for l in "${sha_lines[@]}"; do echo "$l"; echo; done
} > "$case_dir/meta.toml"

echo "captured $case_name (exit $(cat "$case_dir/expected/exit"), rpmlint $version)"
echo "  -> $case_dir"
