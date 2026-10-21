#!/usr/bin/env bash
# Build the SignatureCheck fixtures for the RPM v6 signature form:
# signatures stored in the signature header's OPENPGP entry (tag 278,
# a STRING_ARRAY whose strings are base64-encoded signature packets),
# which rpmsign from rpm 6.x writes.
#
# Outputs (all in this directory):
#   signature-openpgp-1.0-1.noarch.rpm         v6 package, OPENPGP entry
#                                              only, signed with key 1
#   signature-openpgp-classic-1.0-1.noarch.rpm v4 package, classic RSA
#                                              header-signature tag only,
#                                              signed with key 1 (control)
#   signature-openpgp-mixed-1.0-1.noarch.rpm   v6 package carrying the
#                                              same signature packet in
#                                              the classic RSA tag and
#                                              in the OPENPGP entry
#                                              (rpmsign --rpmv4 output)
#   signature-openpgp-dual-1.0-1.noarch.rpm    v6 package, OPENPGP entry
#                                              with two signatures
#                                              (keys 1 and 2)
#   signature-openpgp-testkey.asc / .gpg       key 1 public half
#   signature-openpgp-testkey2.asc / .gpg      key 2 public half
#
# The signing keys are throwaway test keys ("rpmcrab openpgp test key
# (DO NOT TRUST)"); only their public halves are committed. The
# private halves are generated inside the workdir. A successful
# run removes the workdir; a failed run preserves it and prints
# its path, so the rpmbuild and rpmsign logs under its logs/
# subdirectory survive for inspection.
#
# Unlike build-signature-fixtures.sh, this script does not run in a
# container: producing the v6 signature form needs an rpm >= 6.0
# toolchain (rpmbuild and rpmsign), e.g. Homebrew's rpm on macOS. It
# refuses to run against an older rpmsign.
#
# The script also runs the `rpm -Kv` matrix over the variants (empty
# rpmdb, rpmdb holding key 1, rpmdb holding both keys) and the
# structural assertions on each variant's signature header, and fails
# if any cell deviates. Outputs are staged in the workdir and copied
# into this directory only after every check passes, so a failed run
# never clobbers the committed fixtures. It prints the key IDs the
# SignatureCheck tests expect in EXPECTED_OPENPGP_KEY_ID and
# EXPECTED_OPENPGP_KEY2_ID (crates/rpmcrab-core/src/checks/
# signature.rs).
#
# Usage: bash tests/parity/pkg/inputs/build-signature-openpgp-fixtures.sh
# Needs: rpmbuild, rpmsign (both >= 6.0), gpg, python3.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"

die() {
    echo "error: $*" >&2
    exit 1
}

for tool in rpmbuild rpmsign gpg gpgconf python3; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool not found"
done
# The signing below uses --rpmv4 for the mixed fixture and the v6
# form (rpmsign's default on an rpm >= 6.0 toolchain) for the rest;
# gate on both flags.
for flag in --rpmv4 --rpmv6; do
    rpmsign --help 2>&1 | grep -q -- "$flag" \
        || die "rpmsign lacks $flag: an rpm >= 6.0 toolchain is required"
done
[ -f "$here/signature-fixture.spec" ] \
    || die "missing fixture spec: $here/signature-fixture.spec"

# The workdir must sit on a short path: gpg-agent creates its IPC
# socket inside GNUPGHOME (under the workdir), and socket paths are
# length-limited -- the macOS per-user TMPDIR is too long.
work="$(mktemp -d "/tmp/rpmbuild-openpgp-work.XXXXXX")"
# GNUPGHOME is set up before the EXIT trap is installed: the trap's
# agent shutdown then targets the scratch home from the start, and a
# failure in between could otherwise shut down the caller's own
# gpg agent.
export GNUPGHOME="$work/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
cleanup() {
    local rc=$?
    # The agent for the scratch GNUPGHOME must not outlive the
    # workdir it serves.
    gpgconf --kill agent >/dev/null 2>&1 || true
    if [ "$rc" -ne 0 ]; then
        echo "failed run: workdir preserved for inspection: $work" >&2
        echo "  rpmbuild log: $work/logs/rpmbuild.log" >&2
        echo "  rpmsign log: $work/logs/rpmsign.log" >&2
    else
        rm -rf "$work"
    fi
}
trap cleanup EXIT
mkdir -p "$work/staged" "$work/tmp" "$work/logs"
# The logs exist from the start, so the paths a failed run prints
# resolve even when the failure precedes the first build or sign.
touch "$work/logs/rpmbuild.log" "$work/logs/rpmsign.log"
export TMPDIR="$work/tmp"

gen_key() {
    # gen_key <real-name> <email>
    cat > "$work/keyparams" <<EOF
Key-Type: RSA
Key-Length: 2048
Name-Real: $1
Name-Email: $2
Expire-Date: 0
%no-protection
%commit
EOF
    gpg --batch --gen-key "$work/keyparams"
}

primary_fingerprints() {
    # One fingerprint per key in the keyring: the fingerprint
    # record of each pub record. The fingerprint records of
    # subkeys are skipped, so a key with subkeys still contributes
    # exactly its primary fingerprint.
    gpg --list-keys --with-colons | awk -F: '
        /^pub/ { primary = 1; next }
        /^sub/ { primary = 0; next }
        /^fpr/ && primary { print $10; primary = 0 }
    '
}

only_fingerprint() {
    local fprs
    fprs="$(primary_fingerprints)"
    [ "$(printf '%s\n' "$fprs" | grep -c .)" = "1" ] \
        || die "expected exactly one key in the keyring, found: $fprs"
    printf '%s' "$fprs"
}

gen_key "rpmcrab openpgp test key (DO NOT TRUST)" \
    "rpmcrab-openpgp-testkey@example.invalid"
FINGERPRINT1="$(only_fingerprint)"
gen_key "rpmcrab openpgp test key 2 (DO NOT TRUST)" \
    "rpmcrab-openpgp-testkey2@example.invalid"
FINGERPRINT2="$(primary_fingerprints | grep -vFx "$FINGERPRINT1")" \
    || die "second key fingerprint not found"
[ "$(printf '%s\n' "$FINGERPRINT2" | grep -c .)" = "1" ] \
    || die "expected exactly one second key fingerprint, found: $FINGERPRINT2"

for fingerprint in "$FINGERPRINT1" "$FINGERPRINT2"; do
    [[ "$fingerprint" =~ ^[0-9A-F]{40}$ ]] \
        || die "generated key fingerprint is not 40 hex digits: '$fingerprint'"
done
# `rpm -Kv` prints the issuer key ID (the low 64 bits of the
# fingerprint: its last sixteen hex digits, lowercase); the check
# reports the key ID's low 32 bits (the last eight digits).
KEYID1="$(printf '%s' "${FINGERPRINT1: -16}" | tr 'A-F' 'a-f')"
KEYID2="$(printf '%s' "${FINGERPRINT2: -16}" | tr 'A-F' 'a-f')"
PRINTED1="$(printf '%s' "${FINGERPRINT1: -8}" | tr 'A-F' 'a-f')"
PRINTED2="$(printf '%s' "${FINGERPRINT2: -8}" | tr 'A-F' 'a-f')"
FINGERPRINT1_LOWER="$(printf '%s' "$FINGERPRINT1" | tr 'A-F' 'a-f')"
FINGERPRINT2_LOWER="$(printf '%s' "$FINGERPRINT2" | tr 'A-F' 'a-f')"

gpg --armor --export "$FINGERPRINT1" > "$work/staged/signature-openpgp-testkey.asc"
gpg --export "$FINGERPRINT1" > "$work/staged/signature-openpgp-testkey.gpg"
gpg --armor --export "$FINGERPRINT2" > "$work/staged/signature-openpgp-testkey2.asc"
gpg --export "$FINGERPRINT2" > "$work/staged/signature-openpgp-testkey2.gpg"

mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp "$here/signature-fixture.spec" "$work/rpmbuild/SPECS/fixture.spec"
build_variant() {
    # build_variant <dest> <extra rpmbuild defines...> -> path of the
    # built rpm, copied to <dest>: both variants share one filename
    # under RPMS/, and the next build wipes that tree. The build
    # must produce exactly one rpm; its output goes to the rpmbuild
    # log, which a failed run preserves.
    local dest="$1" built
    shift
    rm -rf "$work/rpmbuild/BUILD"/* "$work/rpmbuild/RPMS"/*
    echo "== rpmbuild $*" >> "$work/logs/rpmbuild.log"
    rpmbuild -bb --define "_topdir $work/rpmbuild" \
        --define "_tmppath $work/tmp" "$@" \
        "$work/rpmbuild/SPECS/fixture.spec" >>"$work/logs/rpmbuild.log" 2>&1
    built="$(find "$work/rpmbuild/RPMS" -name '*.rpm')"
    if [ "$(printf '%s\n' "$built" | grep -c . || true)" != "1" ]; then
        echo "error: expected exactly one built rpm, found: ${built:-none}" >&2
        return 1
    fi
    # The callers invoke build_variant under ||, a context where
    # errexit is off inside the function: a cp failure must return
    # explicitly instead of falling through to the printf.
    cp "$built" "$dest" || return 1
    printf '%s' "$dest"
}
UNSIGNED_V4="$(build_variant "$work/unsigned-v4.rpm" --define "_rpmformat 4")" \
    || die "v4 build produced no rpm"
UNSIGNED_V6="$(build_variant "$work/unsigned-v6.rpm")" \
    || die "v6 build produced no rpm"

sign() {
    # sign <key-fingerprint> <file> [extra rpmsign options...]
    # Output goes to the rpmsign log, which a failed run preserves.
    local fingerprint="$1" file="$2"
    shift 2
    echo "== rpmsign $file $*" >> "$work/logs/rpmsign.log"
    rpmsign --define "__gpg $(command -v gpg)" \
        --define "_gpg_name $fingerprint" --addsign "$@" "$file" \
        >>"$work/logs/rpmsign.log" 2>&1
}

cp "$UNSIGNED_V4" "$work/staged/signature-openpgp-classic-1.0-1.noarch.rpm"
sign "$FINGERPRINT1" "$work/staged/signature-openpgp-classic-1.0-1.noarch.rpm"
cp "$UNSIGNED_V6" "$work/staged/signature-openpgp-1.0-1.noarch.rpm"
sign "$FINGERPRINT1" "$work/staged/signature-openpgp-1.0-1.noarch.rpm"
cp "$UNSIGNED_V6" "$work/staged/signature-openpgp-mixed-1.0-1.noarch.rpm"
sign "$FINGERPRINT1" "$work/staged/signature-openpgp-mixed-1.0-1.noarch.rpm" --rpmv4
cp "$UNSIGNED_V6" "$work/staged/signature-openpgp-dual-1.0-1.noarch.rpm"
sign "$FINGERPRINT1" "$work/staged/signature-openpgp-dual-1.0-1.noarch.rpm"
sign "$FINGERPRINT2" "$work/staged/signature-openpgp-dual-1.0-1.noarch.rpm"

# Structural assertions on the staged fixtures: which signature forms
# each signature header actually carries.
python3 - "$work/staged" <<'PYEOF'
import base64
import struct
import sys

staged = sys.argv[1]
CLASSIC = (267, 268, 1002, 1005, 1006)


def sig_entries(path):
    data = open(path, "rb").read()
    assert data[:4] == b"\xed\xab\xee\xdb", f"{path}: lead magic"
    nindex, hsize = struct.unpack(">II", data[104:112])
    store_off = 96 + 16 + nindex * 16
    store = data[store_off:store_off + hsize]
    entries = []
    for i in range(nindex):
        tag, typ, off, cnt = struct.unpack(
            ">IIII", data[112 + i * 16:112 + (i + 1) * 16])
        entries.append((tag, typ, off, cnt, store))
    return entries


def classic_blobs(entries):
    return [store[off:off + cnt]
            for (tag, typ, off, cnt, store) in entries
            if tag in CLASSIC and typ == 7]


def container_packets(entries):
    packets = []
    for (tag, typ, off, cnt, store) in entries:
        if tag == 278 and typ == 8:
            pos = off
            for _ in range(cnt):
                end = store.index(b"\x00", pos)
                packets.append(base64.b64decode(store[pos:end], validate=True))
                pos = end + 1
    return packets


def check(name, want_classic, want_container):
    entries = sig_entries(f"{staged}/{name}")
    blobs = classic_blobs(entries)
    packets = container_packets(entries)
    assert len(blobs) == want_classic, (
        f"{name}: {len(blobs)} classic signature blobs, want {want_classic}")
    assert len(packets) == want_container, (
        f"{name}: {len(packets)} container packets, want {want_container}")
    return blobs, packets


_, packets = check("signature-openpgp-1.0-1.noarch.rpm", 0, 1)
check("signature-openpgp-classic-1.0-1.noarch.rpm", 1, 0)
blobs, packets = check("signature-openpgp-mixed-1.0-1.noarch.rpm", 1, 1)
assert blobs[0] == packets[0], (
    "mixed fixture: the classic blob and the container packet differ")
_, packets = check("signature-openpgp-dual-1.0-1.noarch.rpm", 0, 2)
assert packets[0] != packets[1], "dual fixture: container packets identical"
print("structural assertions passed")
PYEOF

mkdir -p "$work/db-empty" "$work/db-key1" "$work/db-both"
rpm --dbpath "$work/db-empty" --initdb
rpm --dbpath "$work/db-key1" --initdb
rpm --dbpath "$work/db-both" --initdb
rpm --dbpath "$work/db-key1" --import "$work/staged/signature-openpgp-testkey.asc"
rpm --dbpath "$work/db-both" --import \
    "$work/staged/signature-openpgp-testkey.asc" \
    "$work/staged/signature-openpgp-testkey2.asc"

expect() {
    # expect <file> <db> <pattern>
    local out
    out="$(LC_ALL=C rpm --dbpath "$2" -Kv "$work/staged/$1" 2>&1 || true)"
    if ! grep -qF -- "$3" <<<"$out"; then
        echo "PARITY FAILURE: $1 (db $2) lacks '$3':" >&2
        echo "$out" >&2
        exit 1
    fi
}
expect_count() {
    # expect_count <file> <db> <pattern> <count>
    local out n
    out="$(LC_ALL=C rpm --dbpath "$2" -Kv "$work/staged/$1" 2>&1 || true)"
    n="$(grep -cF -- "$3" <<<"$out" || true)"
    if [ "$n" != "$4" ]; then
        echo "PARITY FAILURE: $1 (db $2) has $n x '$3', want $4:" >&2
        echo "$out" >&2
        exit 1
    fi
}

for f in signature-openpgp-1.0-1.noarch.rpm \
         signature-openpgp-classic-1.0-1.noarch.rpm \
         signature-openpgp-mixed-1.0-1.noarch.rpm; do
    expect "$f" "$work/db-empty" "key ID $KEYID1: NOKEY"
    expect "$f" "$work/db-key1" "key fingerprint: $FINGERPRINT1_LOWER: OK"
    expect_count "$f" "$work/db-empty" "NOKEY" 1
done
expect signature-openpgp-dual-1.0-1.noarch.rpm "$work/db-empty" \
    "key ID $KEYID1: NOKEY"
expect signature-openpgp-dual-1.0-1.noarch.rpm "$work/db-empty" \
    "key ID $KEYID2: NOKEY"
expect_count signature-openpgp-dual-1.0-1.noarch.rpm "$work/db-empty" "NOKEY" 2
expect signature-openpgp-dual-1.0-1.noarch.rpm "$work/db-both" \
    "key fingerprint: $FINGERPRINT1_LOWER: OK"
expect signature-openpgp-dual-1.0-1.noarch.rpm "$work/db-both" \
    "key fingerprint: $FINGERPRINT2_LOWER: OK"
expect_count signature-openpgp-dual-1.0-1.noarch.rpm "$work/db-both" "signature, key fingerprint:" 2

expected_outputs=(
    signature-openpgp-1.0-1.noarch.rpm
    signature-openpgp-classic-1.0-1.noarch.rpm
    signature-openpgp-mixed-1.0-1.noarch.rpm
    signature-openpgp-dual-1.0-1.noarch.rpm
    signature-openpgp-testkey.asc
    signature-openpgp-testkey.gpg
    signature-openpgp-testkey2.asc
    signature-openpgp-testkey2.gpg
)
for f in "${expected_outputs[@]}"; do
    [ -s "$work/staged/$f" ] || die "did not produce staged output: $f"
    cp "$work/staged/$f" "$here/$f"
done

echo "fixtures built; test key fingerprints $FINGERPRINT1 / $FINGERPRINT2"
echo "EXPECTED_OPENPGP_KEY_ID for signature.rs tests: $PRINTED1"
echo "EXPECTED_OPENPGP_KEY2_ID for signature.rs tests: $PRINTED2"
ls "$here"/signature-openpgp-*
