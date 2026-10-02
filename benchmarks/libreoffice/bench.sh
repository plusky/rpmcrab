#!/bin/bash
# LibreOffice lint benchmark: rpmcrab vs reference rpmlint.
#
# Repeatable by design: the RPM set is pinned in manifest.tsv
# (name, repo-relative path, size, sha256). Re-running downloads
# only missing/corrupt files and verifies every hash.
#
# Usage:
#   bench.sh download [RPMS_DIR]   fetch + sha256-verify all RPMs
#   bench.sh rpmcrab [RPMS_DIR]    time rpmcrab over the set, print JSON
#   bench.sh rpmlint [RPMS_DIR]    time reference rpmlint over the set, print JSON
#   bench.sh all [RPMS_DIR]        download + both runs, print combined JSON
#
# Environment:
#   RPMCRAB_BIN     rpmcrab binary (default: rpmcrab on PATH)
#   RPMLINT_REF_DIR reference rpmlint checkout dir (default: ./rpmlint-ref)
#   RPMLINT_PYTHON  python with rpmlint's deps (python3-rpm etc.)
#                   (default: python3). For containers, point this at a
#                   wrapper script, e.g.:
#                     #!/bin/sh
#                     exec podman run --rm -v "$REF:/ref:ro" -v "$RPMS:/rpms:ro" \
#                       opensuse/tumbleweed python3 "$@"
#                   (wrapper must translate host paths to container paths)
#   MIRROR          base URL for downloads
#                   (default: https://download.opensuse.org/tumbleweed/repo/oss/)
#   RESULTS_DIR     where run JSON/logs go (default: ./results)
#
# Output: one JSON object on stdout with wall-clock seconds, finding
# counts and corpus metadata. Human summary goes to stderr.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$HERE/manifest.tsv"
MIRROR="${MIRROR:-https://download.opensuse.org/tumbleweed/repo/oss/}"
RPMCRAB_BIN="${RPMCRAB_BIN:-rpmcrab}"
RPMLINT_REF_DIR="${RPMLINT_REF_DIR:-$HERE/rpmlint-ref}"
RPMLINT_PYTHON="${RPMLINT_PYTHON:-python3}"
RESULTS_DIR="${RESULTS_DIR:-$HERE/results}"
REF_CONFIG="${RPMLINT_REF_CONFIG:-$RPMLINT_REF_DIR/configs/openSUSE}"

die() { echo "bench.sh: $*" >&2; exit 1; }

cmd_download() {
    local dir="${1:-$HERE/rpms}"
    mkdir -p "$dir"
    python3 - "$MANIFEST" "$dir" "$MIRROR" <<'EOF'
import hashlib, os, sys, urllib.request
manifest, dest, mirror = sys.argv[1], sys.argv[2], sys.argv[3]
ok = skip = fail = 0
total = 0
for line in open(manifest):
    line = line.rstrip("\n")
    if not line or line.startswith("#"):
        continue
    name, relpath, size, ctype, sha = line.split("\t")
    size = int(size)
    total += 1
    fn = os.path.join(dest, os.path.basename(relpath))
    digest = lambda f: hashlib.new(ctype, open(f, "rb").read()).hexdigest()
    if os.path.exists(fn) and os.path.getsize(fn) == size:
        if digest(fn) == sha:
            skip += 1
            continue
    try:
        urllib.request.urlretrieve(mirror + relpath, fn)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL download {relpath}: {e}", file=sys.stderr)
        fail += 1
        continue
    if digest(fn) == sha:
        ok += 1
    else:
        print(f"FAIL {ctype} {relpath}", file=sys.stderr)
        fail += 1
print(f"download: {ok} fetched, {skip} already present, {fail} failed "
      f"of {total}", file=sys.stderr)
sys.exit(1 if fail else 0)
EOF
}

# run_tool <name> <rpms...> -> prints "<seconds> <logfile>" and leaves the
# tool's raw output in $RESULTS_DIR/<name>.log
run_tool() {
    local name="$1"; shift
    local log="$RESULTS_DIR/$name.log"
    mkdir -p "$RESULTS_DIR"
    local start end
    start=$(date +%s.%N)
    if [ "$name" = "rpmcrab" ]; then
        "$RPMCRAB_BIN" "$@" >"$log" 2>&1
    else
        PYTHONPATH="$RPMLINT_REF_DIR" "$RPMLINT_PYTHON" -c \
            "import sys; from rpmlint.cli import lint; sys.exit(lint())" \
            -c "$REF_CONFIG" "$@" >"$log" 2>&1
    fi
    local rc=$?
    end=$(date +%s.%N)
    python3 -c "print(f'{$end - $start:.3f}')"
    echo "$log $rc"
}

# Count findings from a saved log: prefer the "<N> errors, <M> warnings"
# summary line both tools print; fall back to per-line counting.
summarize() {
    local name="$1" log="$2"
    python3 - "$name" "$log" <<'EOF'
import json, re, sys
name, log = sys.argv[1], open(sys.argv[2], errors="replace").read()
m = re.search(r"(\d+) errors?, (\d+) warnings?", log)
if m:
    errors, warnings = int(m.group(1)), int(m.group(2))
else:  # fall back to line counting ("pkg.arch: E: tag")
    errors = len(re.findall(r"(?m): E: ", log))
    warnings = len(re.findall(r"(?m): W: ", log))
print(json.dumps({"errors": errors, "warnings": warnings}))
EOF
}

cmd_run() {
    local name="$1"
    local dir="${2:-$HERE/rpms}"
    local rpms=( "$dir"/*.rpm )
    [ -e "${rpms[0]}" ] || die "no RPMs in $dir (run 'bench.sh download' first)"
    [ -x "$(command -v "$RPMCRAB_BIN")" ] || [ -x "$RPMCRAB_BIN" ] || \
        { [ "$name" = "rpmlint" ] || die "rpmcrab not found: $RPMCRAB_BIN"; }
    if [ "$name" = "rpmlint" ]; then
        [ -f "$REF_CONFIG" ] || die "reference config missing: $REF_CONFIG"
    fi
    read -r seconds log rc < <(run_tool "$name" "${rpms[@]}")
    local counts
    counts=$(summarize "$name" "$log")
    local total_mb
    total_mb=$(python3 -c "
import glob, os
fs = glob.glob('$dir/*.rpm')
print(f'{sum(os.path.getsize(f) for f in fs)/1024/1024:.1f}')")
    python3 - "$name" "$seconds" "$counts" "${#rpms[@]}" "$total_mb" "$rc" <<'EOF'
import json, sys
name, seconds, counts, n, mb, rc = sys.argv[1:]
print(json.dumps({
    "tool": name,
    "rpms": int(n),
    "total_mb": float(mb),
    "wall_seconds": float(seconds),
    "exit_code": int(rc),
    **json.loads(counts),
}))
EOF
    echo "[$name] ${#rpms[@]} rpms, ${total_mb} MB, ${seconds}s, rc=$rc" >&2
}

cmd_all() {
    local dir="${1:-$HERE/rpms}"
    cmd_download "$dir"
    local a b
    a=$(cmd_run rpmcrab "$dir")
    b=$(cmd_run rpmlint "$dir")
    python3 - "$a" "$b" <<'EOF'
import json, sys
a, b = json.loads(sys.argv[1]), json.loads(sys.argv[2])
speedup = b["wall_seconds"] / a["wall_seconds"] if a["wall_seconds"] else 0
print(json.dumps({
    "corpus": {"rpms": a["rpms"], "total_mb": a["total_mb"],
               "manifest": "manifest.tsv"},
    "rpmcrab": a, "rpmlint": b,
    "speedup_rpmcrab_vs_rpmlint": round(speedup, 2),
}, indent=2))
EOF
}

case "${1:-}" in
    download) cmd_download "${2:-}" ;;
    rpmcrab)  cmd_run rpmcrab "${2:-}" ;;
    rpmlint)  cmd_run rpmlint "${2:-}" ;;
    all)      cmd_all "${2:-}" ;;
    *) die "usage: bench.sh {download|rpmcrab|rpmlint|all} [RPMS_DIR]" ;;
esac
