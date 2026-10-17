#!/bin/bash
# Release corpus benchmark: end-to-end rpmcrab timing on a pinned RPM set.
#
# The corpus is pinned in manifest.toml (name, URL, size, sha512). Downloads
# are verified against the manifest; a stale URL fails loudly instead of
# silently benchmarking a different corpus.
#
# Usage:
#   bench.sh download [RPMS_DIR]   fetch + sha512-verify all RPMs
#   bench.sh run [RPMS_DIR]        time rpmcrab 3x, print summary JSON
#   bench.sh all [RPMS_DIR]        download + run, print summary JSON
#
# Environment:
#   RPMCRAB_BIN   rpmcrab binary (default: cargo-built release binary)
#
# Output: one JSON object on stdout with median wall-clock seconds over
# 3 runs, corpus metadata, and runner metadata (CPU, OS, date).
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$HERE/manifest.toml"
RPMCRAB_BIN="${RPMCRAB_BIN:-$HERE/../../target/release/rpmcrab}"
RUNS=3

die() { echo "bench.sh: $*" >&2; exit 1; }

# Parse manifest.toml with python3 (no external deps).
manifest_packages() {
    python3 - "$MANIFEST" <<'EOF'
import re, sys
text = open(sys.argv[1]).read()
for m in re.finditer(r'\[\[package\]\]\n(.*?)(?=\n\[\[package\]\]|\Z)', text, re.S):
    block = m.group(1)
    d = dict(re.findall(r'^(\w+) = "(.*)"$', block, re.M))
    d['size'] = int(re.search(r'^size = (\d+)$', block, re.M).group(1))
    print(f"{d['name']}\t{d['filename']}\t{d['url']}\t{d['size']}\t{d['sha512']}")
EOF
}

# Write the parsed manifest to $1, failing closed: a generator error or an
# empty result never reaches downstream code, where it would be read as a
# corpus of 0 RPMs.
write_manifest() {
    local dest="$1"
    if ! manifest_packages > "$dest"; then
        echo "bench.sh: failed to parse $MANIFEST" >&2
        return 1
    fi
    if [ ! -s "$dest" ]; then
        echo "bench.sh: empty manifest parsed from $MANIFEST" >&2
        return 1
    fi
}

cmd_download() {
    local dir="${1:-$HERE/rpms}"
    mkdir -p "$dir"
    write_manifest "$dir/.manifest.tsv" || die "manifest generation failed"
    python3 - "$dir" "$dir/.manifest.tsv" <<'EOF'
import hashlib, os, sys, urllib.request
dest = sys.argv[1]
manifest = sys.argv[2]
ok = skip = fail = total = 0
for line in open(manifest):
    name, filename, url, size, sha512 = line.rstrip("\n").split("\t")
    size = int(size)
    total += 1
    fn = os.path.join(dest, os.path.basename(filename))
    def digest(f):
        return hashlib.sha512(open(f, "rb").read()).hexdigest()
    if os.path.exists(fn) and os.path.getsize(fn) == size and digest(fn) == sha512:
        skip += 1
        continue
    try:
        urllib.request.urlretrieve(url, fn)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL download {filename}: {e}", file=sys.stderr)
        fail += 1
        continue
    if os.path.getsize(fn) == size and digest(fn) == sha512:
        ok += 1
    else:
        print(f"FAIL sha512 {filename}", file=sys.stderr)
        fail += 1
print(f"download: {ok} fetched, {skip} already present, {fail} failed of {total}",
      file=sys.stderr)
sys.exit(1 if fail else 0)
EOF
}

# Verify the corpus in $1 against the manifest: every entry present with
# matching size and sha512, and no .rpm files beyond the manifest. The run
# path verifies the same way download does, so a stale, truncated or
# tampered directory fails loudly instead of benchmarking garbage.
verify_corpus() {
    local dir="$1"
    local tsv rc
    tsv=$(mktemp)
    if ! write_manifest "$tsv"; then
        rm -f "$tsv"
        return 1
    fi
    python3 - "$dir" "$tsv" <<'EOF'
import hashlib, os, sys
dest, manifest = sys.argv[1], sys.argv[2]
entries = []
for line in open(manifest):
    _name, filename, _url, size, sha512 = line.rstrip("\n").split("\t")
    entries.append((os.path.basename(filename), int(size), sha512))
fail = 0
expected = {fn for fn, _size, _sha in entries}
try:
    actual = {f for f in os.listdir(dest) if f.endswith(".rpm")}
except OSError:
    actual = set()
for fn in sorted(expected - actual):
    print(f"verify: missing {fn}", file=sys.stderr)
    fail = 1
for fn in sorted(actual - expected):
    print(f"verify: unexpected {fn} (not in manifest)", file=sys.stderr)
    fail = 1
for fn, size, sha512 in entries:
    path = os.path.join(dest, fn)
    if not os.path.exists(path):
        continue
    if os.path.getsize(path) != size:
        print(f"verify: size mismatch {fn}", file=sys.stderr)
        fail = 1
    elif hashlib.sha512(open(path, "rb").read()).hexdigest() != sha512:
        print(f"verify: sha512 mismatch {fn}", file=sys.stderr)
        fail = 1
if not fail:
    print(f"verify: {len(entries)} RPMs match the manifest", file=sys.stderr)
sys.exit(1 if fail else 0)
EOF
    rc=$?
    rm -f "$tsv"
    return $rc
}

# Time one rpmcrab run over all RPMs; prints seconds.
time_run() {
    local dir="$1"
    local start end
    start=$(date +%s.%N)
    # rpmcrab exits nonzero when findings exist; that is not a benchmark failure.
    "$RPMCRAB_BIN" "$dir"/*.rpm >/dev/null 2>&1
    end=$(date +%s.%N)
    python3 -c "print(f'{$end - $start:.3f}')"
}

cmd_run() {
    local dir="${1:-$HERE/rpms}"
    [ -x "$RPMCRAB_BIN" ] || die "rpmcrab not found: $RPMCRAB_BIN"
    verify_corpus "$dir" || die "corpus in $dir does not match manifest.toml (run 'bench.sh download' first)"
    local rpms=( "$dir"/*.rpm )
    local times=()
    local i t
    for i in $(seq 1 $RUNS); do
        t=$(time_run "$dir")
        times+=("$t")
        echo "run $i/$RUNS: ${t}s" >&2
    done
    local total_mb n
    n=${#rpms[@]}
    total_mb=$(python3 -c "
import glob, os, sys
fs = glob.glob(glob.escape(sys.argv[1]) + '/*.rpm')
print(f'{sum(os.path.getsize(f) for f in fs)/1024/1024:.1f}')" "$dir")
    # Median of the runs + runner metadata.
    python3 - "$n" "$total_mb" "${times[@]}" <<'EOF'
import json, platform, subprocess, sys, datetime
n, total_mb, *times = sys.argv[1:]
times = sorted(float(t) for t in times)
median = times[len(times) // 2]
def cpu():
    try:
        with open('/proc/cpuinfo') as f:
            for line in f:
                if line.startswith('model name'):
                    return line.split(':', 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"
try:
    git = subprocess.run(['git', 'rev-parse', '--short', 'HEAD'],
                         capture_output=True, text=True, cwd='.').stdout.strip()
except Exception:  # noqa: BLE001
    git = "unknown"
print(json.dumps({
    "benchmark": "release-corpus",
    "date": datetime.date.today().isoformat(),
    "rpmcrab_git": git,
    "corpus": {
        "manifest": "benchmarks/release-corpus/manifest.toml",
        "rpms": int(n),
        "total_mb": float(total_mb),
    },
    "runs": len(times),
    "wall_seconds": times,
    "wall_seconds_median": round(median, 3),
    "runner": {
        "os": f"{platform.system()} {platform.release()}",
        "cpu": cpu(),
        "ncpus": __import__('os').cpu_count(),
    },
}, indent=2))
EOF
}

case "${1:-}" in
    download) cmd_download "${2:-}" ;;
    run)      cmd_run "${2:-}" ;;
    all)      cmd_download "${2:-}" && cmd_run "${2:-}" ;;
    *) die "usage: bench.sh {download|run|all} [RPMS_DIR]" ;;
esac
