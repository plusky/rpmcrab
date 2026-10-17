#!/bin/bash
# Tests for bench.sh's RPMLINT_PYTHON preflight: a bare name that
# resolves via PATH is accepted, an explicit path is accepted, and a
# name that resolves nowhere dies naming RPMLINT_PYTHON instead of
# surfacing as a bare rc=127 inside the run's JSON.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/rpms"
printf '#!/bin/sh\nexit 0\n' > "$TMP/bin/faux-python"
chmod +x "$TMP/bin/faux-python"

fail() { echo "test-bench.sh: $*" >&2; exit 1; }

# Bare name resolving via PATH: the preflight passes and the run stops
# at the next check (the empty RPM dir), not at the preflight.
out="$(PATH="$TMP/bin:$PATH" RPMLINT_PYTHON=faux-python bash "$HERE/bench.sh" rpmlint "$TMP/rpms" 2>&1)" && \
    fail "PATH-name run unexpectedly succeeded: $out"
case "$out" in
    *"RPMLINT_PYTHON is not executable"*) fail "bare PATH name rejected by the preflight: $out" ;;
    *"no RPMs in"*) ;;
    *) fail "unexpected PATH-name failure: $out" ;;
esac

# Explicit path: same acceptance.
out="$(RPMLINT_PYTHON="$TMP/bin/faux-python" bash "$HERE/bench.sh" rpmlint "$TMP/rpms" 2>&1)" && \
    fail "explicit-path run unexpectedly succeeded: $out"
case "$out" in
    *"RPMLINT_PYTHON is not executable"*) fail "explicit path rejected by the preflight: $out" ;;
    *"no RPMs in"*) ;;
    *) fail "unexpected explicit-path failure: $out" ;;
esac

# A name that resolves nowhere: the preflight dies naming the variable.
out="$(PATH="$TMP/bin:$PATH" RPMLINT_PYTHON=faux-python-missing bash "$HERE/bench.sh" rpmlint "$TMP/rpms" 2>&1)" && \
    fail "missing-interpreter run unexpectedly succeeded: $out"
case "$out" in
    *"RPMLINT_PYTHON is not executable: faux-python-missing"*) ;;
    *) fail "missing interpreter did not die naming RPMLINT_PYTHON: $out" ;;
esac

echo "test-bench.sh: ok"
