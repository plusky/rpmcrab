#!/usr/bin/env bash
# Build the SignatureCheck fixture RPMs and the fixture signing key.
#
# Outputs (all in this directory):
#   signature-unsigned-1.0-1.noarch.rpm       plain rpmbuild output
#   signature-signed-1.0-1.noarch.rpm         signed with the test key
#   signature-corrupt-1.0-1.noarch.rpm        first byte of the signature
#                                             packet flipped (unparsable)
#   signature-badsig-1.0-1.noarch.rpm          one byte inside the RSA MPI
#                                             flipped (parses, fails verify)
#   signature-brokenpayload-1.0-1.noarch.rpm  one payload byte flipped
#                                             (digests break, sig intact)
#   signature-baddigest-1.0-1.noarch.rpm      one hex digit of the stored
#                                             header SHA256 flipped (digest
#                                             breaks, sig intact)
#   signature-testkey.asc / signature-testkey.gpg
#                                             the test key's public half
#
# The signing key is a throwaway test key ("rpmcrab test key (DO NOT
# TRUST)"); only its public half is committed. The private half is
# generated inside the build container and discarded with the workdir.
#
# The script also runs the `rpm -Kv` matrix over the variants (empty
# rpmdb vs rpmdb holding the test key) and fails if any cell deviates,
# so the fixtures are parity-checked against the reference tool at
# generation time. For the two digest-breakage variants the matrix
# additionally asserts a digest failure in `rpm -Kvv` output: the
# signature verdict alone is identical for an intact signed package,
# so without that assert an ineffective payload flip or hex mutation
# would pass generation and the fixtures could not exercise digest
# masking. Outputs are staged in the workdir and copied into this
# directory only after the whole matrix passes, so a failed run never
# clobbers the committed fixtures. It prints the key ID the
# SignatureCheck tests expect in EXPECTED_KEY_ID
# (crates/rpmcrab-core/src/checks/signature.rs).
#
# Usage: bash tests/parity/pkg/inputs/build-signature-fixtures.sh
# Needs: podman (or PODMAN=/path/to/podman), the pinned openSUSE
# container image below (or IMAGE=<ref> to override it)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"

die() {
    echo "error: $*" >&2
    exit 1
}

podman_bin="${PODMAN:-podman}"
command -v "$podman_bin" >/dev/null 2>&1 \
    || die "podman not found (set PODMAN=/path/to/podman)"
[ -f "$here/signature-fixture.spec" ] \
    || die "missing fixture spec: $here/signature-fixture.spec"

# Pinned by dated tag and digest: regeneration must not drift with
# whatever `latest` happens to point at.
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:20261017@sha256:27f4a56bc6d26069f53734810848ddc0d42ea37bb684369ba85d2db6acda67f8}"

work="$(mktemp -d "${TMPDIR:-/tmp}/rpmbuild-signature-work.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/staged"

cat > "$work/mutate.py" <<'PYEOF'
import struct
import sys

src, outdir = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()


def header(buf, off):
    assert buf[off:off + 3] == b"\x8e\xad\xe8", "header magic"
    nindex, store_size = struct.unpack(">II", buf[off + 8:off + 16])
    entries = []
    for i in range(nindex):
        e = buf[off + 16 + i * 16: off + 32 + i * 16]
        entries.append(struct.unpack(">IIII", e))
    return entries, off + 16 + nindex * 16, store_size


sig_entries, sig_store, sig_store_size = header(data, 96)
sig_tags = (267, 268, 1002, 1005, 1006)
# Type 7 is BIN; only BIN entries carry a signature blob (a same-tag
# entry of another type is header data, not a signature).
sig_blobs = [(t, o, c) for (t, ty, o, c) in sig_entries if t in sig_tags and ty == 7]
assert len(sig_blobs) == 1, (
    f"expected exactly one BIN signature entry, found {len(sig_blobs)}"
)
tag, blob_off, blob_len = sig_blobs[0]
sha256_matches = [o for (t, _ty, o, _c) in sig_entries if t == 273]
assert len(sha256_matches) == 1, (
    f"expected exactly one stored header SHA256 entry, found {len(sha256_matches)}"
)
sha256_off = sha256_matches[0]
assert blob_len > 300, f"signature blob unexpectedly short: {blob_len}"

variant = bytearray(data)
variant[sig_store + blob_off] ^= 0xFF
open(f"{outdir}/signature-corrupt-1.0-1.noarch.rpm", "wb").write(variant)

variant = bytearray(data)
variant[sig_store + blob_off + min(250, blob_len - 30)] ^= 0x01
open(f"{outdir}/signature-badsig-1.0-1.noarch.rpm", "wb").write(variant)

variant = bytearray(data)
pos = sig_store + sha256_off
variant[pos] = ord("0") if variant[pos] != ord("0") else ord("1")
open(f"{outdir}/signature-baddigest-1.0-1.noarch.rpm", "wb").write(variant)

sig_total = (sig_store - 96) + sig_store_size
main_off = 96 + sig_total
main_off += (8 - main_off % 8) % 8
_, main_store, main_store_size = header(data, main_off)
payload_off = main_store + main_store_size
variant = bytearray(data)
variant[payload_off + 40] ^= 0x01
open(f"{outdir}/signature-brokenpayload-1.0-1.noarch.rpm", "wb").write(variant)
print(f"mutated: sig tag {tag}, blob {blob_len} bytes, payload at {payload_off}")
PYEOF

cat > "$work/build-inside.sh" <<'SHEOF'
set -euo pipefail
if ! zypper -n in rpm-build gpg2 python3 >/dev/null; then
    echo "error: zypper failed to install rpm-build, gpg2, python3" >&2
    exit 1
fi

export GNUPGHOME=/work/gnupg
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
cat > /work/keyparams <<'EOF'
Key-Type: RSA
Key-Length: 2048
Name-Real: rpmcrab test key (DO NOT TRUST)
Name-Email: rpmcrab-testkey@example.invalid
Expire-Date: 0
%no-protection
%commit
EOF
gpg --batch --gen-key /work/keyparams
# The key ID derivation below takes the FIRST fingerprint gpg lists;
# guard it: the keyring must hold exactly one key, and the fingerprint
# must be a full 40-hex-digit fingerprint.
key_count="$(gpg --list-keys --with-colons | awk -F: '/^fpr/{n++} END{print n+0}')"
if [ "$key_count" != "1" ]; then
    echo "error: expected exactly one generated key, found $key_count" >&2
    exit 1
fi
FINGERPRINT="$(gpg --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')"
if ! [[ "$FINGERPRINT" =~ ^[0-9A-F]{40}$ ]]; then
    echo "error: generated key fingerprint is not 40 hex digits: '$FINGERPRINT'" >&2
    exit 1
fi
# `rpm -Kv` prints the low 32 bits of the issuer key ID: the last eight
# hex digits of the fingerprint, lowercase.
PRINTED="$(printf '%s' "${FINGERPRINT: -8}" | tr 'A-F' 'a-f')"
if ! [[ "$PRINTED" =~ ^[0-9a-f]{8}$ ]]; then
    echo "error: derived key ID is not 8 lowercase hex digits: '$PRINTED'" >&2
    exit 1
fi
gpg --armor --export "$FINGERPRINT" > /work/staged/signature-testkey.asc
gpg --export "$FINGERPRINT" > /work/staged/signature-testkey.gpg

mkdir -p /work/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp /inputs/signature-fixture.spec /work/rpmbuild/SPECS/fixture.spec
rpmbuild -bb --define "_topdir /work/rpmbuild" /work/rpmbuild/SPECS/fixture.spec
mapfile -t built_rpms < <(find /work/rpmbuild/RPMS -name '*.rpm')
if [ "${#built_rpms[@]}" -ne 1 ]; then
    echo "error: expected exactly one built RPM, found ${#built_rpms[@]}" >&2
    exit 1
fi
UNSIGNED="${built_rpms[0]}"
cp "$UNSIGNED" /work/staged/signature-unsigned-1.0-1.noarch.rpm
cp "$UNSIGNED" /work/signed.rpm
rpmsign --define "_gpg_name $FINGERPRINT" --addsign /work/signed.rpm
cp /work/signed.rpm /work/staged/signature-signed-1.0-1.noarch.rpm
# mutate.py asserts the signed RPM carries exactly one BIN signature
# entry before it mutates anything.
python3 /work/mutate.py /work/signed.rpm /work/staged

mkdir -p /work/db-empty /work/db-key
rpm --dbpath /work/db-empty --initdb
rpm --dbpath /work/db-key --initdb
rpm --dbpath /work/db-key --import /work/staged/signature-testkey.asc

expect() {
    # expect <file> <db> <pattern>
    local out
    out="$(LC_ALL=C rpm --dbpath "$2" -Kv "/work/staged/$1" 2>&1 || true)"
    if ! grep -qF -- "$3" <<<"$out"; then
        echo "PARITY FAILURE: $1 (db $2) lacks '$3':" >&2
        echo "$out" >&2
        exit 1
    fi
}
expect_absent() {
    # expect_absent <file> <db> <pattern>
    local out
    out="$(LC_ALL=C rpm --dbpath "$2" -Kv "/work/staged/$1" 2>&1 || true)"
    if grep -qF -- "$3" <<<"$out"; then
        echo "PARITY FAILURE: $1 (db $2) unexpectedly has '$3':" >&2
        echo "$out" >&2
        exit 1
    fi
}
expect_digest_failure() {
    # expect_digest_failure <file> <db>
    # The signature verdict cannot pin digest breakage on its own: an
    # intact signed package prints the same OK/NOKEY signature line.
    # The verbose verify must also carry a digest BAD / NOT OK line,
    # which only a genuinely broken digest produces.
    local out
    out="$(LC_ALL=C rpm --dbpath "$2" -Kvv "/work/staged/$1" 2>&1 || true)"
    if ! grep -Eq 'digest: (BAD|NOT OK)' <<<"$out"; then
        echo "PARITY FAILURE: $1 (db $2) shows no digest failure in -Kvv output:" >&2
        echo "$out" >&2
        exit 1
    fi
}

expect signature-signed-1.0-1.noarch.rpm /work/db-empty "key ID $PRINTED: NOKEY"
expect signature-signed-1.0-1.noarch.rpm /work/db-key "key ID $PRINTED: OK"
expect signature-corrupt-1.0-1.noarch.rpm /work/db-key "invalid OpenPGP signature"
expect signature-corrupt-1.0-1.noarch.rpm /work/db-empty "invalid OpenPGP signature"
expect signature-badsig-1.0-1.noarch.rpm /work/db-key "key ID $PRINTED: BAD"
expect signature-badsig-1.0-1.noarch.rpm /work/db-empty "key ID $PRINTED: NOKEY"
expect signature-brokenpayload-1.0-1.noarch.rpm /work/db-key "key ID $PRINTED: OK"
expect signature-brokenpayload-1.0-1.noarch.rpm /work/db-empty "key ID $PRINTED: NOKEY"
expect_digest_failure signature-brokenpayload-1.0-1.noarch.rpm /work/db-key
expect_digest_failure signature-brokenpayload-1.0-1.noarch.rpm /work/db-empty
expect signature-baddigest-1.0-1.noarch.rpm /work/db-key "key ID $PRINTED: OK"
expect signature-baddigest-1.0-1.noarch.rpm /work/db-empty "key ID $PRINTED: NOKEY"
expect_digest_failure signature-baddigest-1.0-1.noarch.rpm /work/db-key
expect_digest_failure signature-baddigest-1.0-1.noarch.rpm /work/db-empty
expect_absent signature-unsigned-1.0-1.noarch.rpm /work/db-empty "Signature"

echo "fixtures built; test key fingerprint $FINGERPRINT"
echo "EXPECTED_KEY_ID for signature.rs tests: $PRINTED"
SHEOF

"$podman_bin" run --rm \
    -v "$work:/work:z" \
    -v "$here:/inputs:z" \
    "$image" \
    bash /work/build-inside.sh

expected_outputs=(
    signature-unsigned-1.0-1.noarch.rpm
    signature-signed-1.0-1.noarch.rpm
    signature-corrupt-1.0-1.noarch.rpm
    signature-badsig-1.0-1.noarch.rpm
    signature-brokenpayload-1.0-1.noarch.rpm
    signature-baddigest-1.0-1.noarch.rpm
    signature-testkey.asc
    signature-testkey.gpg
)
for f in "${expected_outputs[@]}"; do
    [ -s "$work/staged/$f" ] || die "container did not produce staged output: $f"
    cp "$work/staged/$f" "$here/$f"
done

echo "built in $here:"
ls "$here"/signature-*.rpm "$here"/signature-testkey.*
