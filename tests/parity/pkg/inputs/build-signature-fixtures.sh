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
# generation time. It prints the key ID the SignatureCheck tests expect
# in EXPECTED_KEY_ID (crates/rpmcrab-core/src/checks/signature.rs).
#
# Usage: bash tests/parity/pkg/inputs/build-signature-fixtures.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-signature-work"
rm -rf "$work"
mkdir -p "$work"

podman_bin="${PODMAN:-podman}"
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}"

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
tag, blob_off, blob_len = next(
    (t, o, c) for (t, _ty, o, c) in sig_entries if t in sig_tags
)
sha256_off = next(o for (t, _ty, o, _c) in sig_entries if t == 273)
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
zypper -n in rpm-build gpg2 python3 >/dev/null

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
FINGERPRINT="$(gpg --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')"
# `rpm -Kv` prints the low 32 bits of the issuer key ID: the last eight
# hex digits of the fingerprint, lowercase.
PRINTED="$(printf '%s' "${FINGERPRINT: -8}" | tr 'A-F' 'a-f')"
gpg --armor --export "$FINGERPRINT" > /inputs/signature-testkey.asc
gpg --export "$FINGERPRINT" > /inputs/signature-testkey.gpg

mkdir -p /work/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp /inputs/signature-fixture.spec /work/rpmbuild/SPECS/fixture.spec
rpmbuild -bb --define "_topdir /work/rpmbuild" /work/rpmbuild/SPECS/fixture.spec
UNSIGNED="$(find /work/rpmbuild/RPMS -name '*.rpm')"
cp "$UNSIGNED" /inputs/signature-unsigned-1.0-1.noarch.rpm
cp "$UNSIGNED" /work/signed.rpm
rpmsign --define "_gpg_name $FINGERPRINT" --addsign /work/signed.rpm
cp /work/signed.rpm /inputs/signature-signed-1.0-1.noarch.rpm
python3 /work/mutate.py /work/signed.rpm /inputs

mkdir -p /work/db-empty /work/db-key
rpm --dbpath /work/db-key --import /inputs/signature-testkey.asc

expect() {
    # expect <file> <db> <pattern>
    local out
    out="$(rpm --dbpath "$2" -Kv "/inputs/$1" 2>&1 || true)"
    if ! grep -q "$3" <<<"$out"; then
        echo "PARITY FAILURE: $1 (db $2) lacks '$3':" >&2
        echo "$out" >&2
        exit 1
    fi
}
expect_absent() {
    # expect_absent <file> <db> <pattern>
    local out
    out="$(rpm --dbpath "$2" -Kv "/inputs/$1" 2>&1 || true)"
    if grep -q "$3" <<<"$out"; then
        echo "PARITY FAILURE: $1 (db $2) unexpectedly has '$3':" >&2
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
expect signature-baddigest-1.0-1.noarch.rpm /work/db-key "key ID $PRINTED: OK"
expect signature-baddigest-1.0-1.noarch.rpm /work/db-empty "key ID $PRINTED: NOKEY"
expect_absent signature-unsigned-1.0-1.noarch.rpm /work/db-empty "Signature"

echo "fixtures built; test key fingerprint $FINGERPRINT"
echo "EXPECTED_KEY_ID for signature.rs tests: $PRINTED"
SHEOF

"$podman_bin" run --rm \
    -v "$work:/work:z" \
    -v "$here:/inputs:z" \
    "$image" \
    bash /work/build-inside.sh

echo "built in $here:"
ls "$here"/signature-*.rpm "$here"/signature-testkey.*
