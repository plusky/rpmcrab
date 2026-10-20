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
#   signature-stacked-1.0-1.noarch.rpm        signed with the test key,
#                                             then signed again with a
#                                             second test key (two
#                                             signatures, two issuers)
#   signature-testkey.asc / signature-testkey.gpg
#                                             the test key's public half
#   signature-testkey2.asc / signature-testkey2.gpg
#                                             the second test key's
#                                             public half
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
# clobbers the committed fixtures. It prints the key IDs the
# SignatureCheck tests expect in EXPECTED_KEY_ID and
# EXPECTED_KEY_ID_2 (crates/rpmcrab-core/src/checks/signature.rs).
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

cat > "$work/stack.py" <<'PYEOF'
# Transplant a raw OpenPGP signature packet into a signed RPM's
# signature header as the tag-1002 (legacy PGP) entry, in the
# canonical layout dual-signed packages carry: entries in tag
# order, per-type alignment, the reserved space (tag 1008) just
# before the trailer entry (tag 62) absorbing the size difference,
# so the store size — and everything the signatures and digests
# cover — stays byte-identical.
import struct
import sys

src1, packet_path, out = sys.argv[1], sys.argv[2], sys.argv[3]
data1 = open(src1, "rb").read()
packet = open(packet_path, "rb").read()

# RPM header entry alignment by type.
ALIGN = {0: 1, 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 1, 9: 1}


def header(buf, off):
    assert buf[off:off + 3] == b"\x8e\xad\xe8", "header magic"
    nindex, store_size = struct.unpack(">II", buf[off + 8:off + 16])
    entries = []
    for i in range(nindex):
        e = buf[off + 16 + i * 16: off + 32 + i * 16]
        entries.append(list(struct.unpack(">IIII", e)))
    return entries, off + 16 + nindex * 16, store_size


def split_file(buf):
    entries, store, ss = header(buf, 96)
    main_off = store + ss
    while buf[main_off:main_off + 3] != b"\x8e\xad\xe8":
        main_off += 1
        assert main_off - (store + ss) < 8, "main header not within alignment padding"
    return entries, store, ss, buf[main_off:]


e1, store1, ss1, tail1 = split_file(data1)

packet2 = packet
assert len(packet2) < 4096, "signature packet unexpectedly large"

# Each original entry's store region: from its offset to the next
# entry's offset (or the store end), in offset order.
by_offset = sorted(e1, key=lambda e: e[2])
regions = {}
for i, e in enumerate(by_offset):
    end = by_offset[i + 1][2] if i + 1 < len(by_offset) else ss1
    regions[e[0]] = data1[store1 + e[2]: store1 + end]

reserved = [e for e in e1 if e[0] == 1008 and e[1] == 7]
assert len(reserved) == 1, "no reserved-space entry"
assert not any(e[0] == 1002 for e in e1), "tag 1002 already present"
trailer = [e for e in e1 if e[0] == 62]
assert len(trailer) == 1, "no trailer entry"

# The data plan in layout order — index (tag) order, with the
# second signature's entry right after tag 1000 as in the corpus
# shape (tags 268 and 1002), the reserved space just before the
# trailer entry (tag 62), whose data closes the store.
plan = []  # (tag, type, count, bytes or None for the reserved space)
for e in sorted(e1, key=lambda x: x[0]):
    tag, ty, _off, count = e
    if tag in (62, 1008):
        continue
    plan.append((tag, ty, count, regions[tag]))
    if tag == 1000:
        plan.append((1002, 7, len(packet2), packet2))
plan.append((1008, 7, None, None))
# The trailer blob is a copy of the region index entry with its
# offset negated over the index: -(16 + (nindex - 1) * 16) for the
# new index size (one entry more than the source header). Readers
# verify it against the index, so it is rebuilt, not copied.
trailer_blob = struct.pack(
    ">IIiI", 62, 7, -(16 + len(e1) * 16), 16)
plan.append((62, trailer[0][1], trailer[0][3], trailer_blob))

# Pass 1: offsets with per-type alignment; the reserved space
# absorbs whatever room the new entry and the padding took.
cursor = 0
laid = []
for tag, ty, count, blob in plan:
    if tag in (62, 1008):
        continue  # placed after the loop
    align = ALIGN[ty]
    cursor += (align - cursor % align) % align
    laid.append((tag, ty, cursor, blob))
    cursor += len(blob)
res_off = cursor
trailer_len = len(trailer_blob)
keep = ss1 - res_off - trailer_len
assert 0 <= keep <= len(regions[1008]), f"reserved keep {keep} out of range"
laid.append((1008, 7, res_off, regions[1008][:keep]))
laid.append((62, trailer[0][1], res_off + keep, trailer_blob))

# Pass 2: emit the store and the index (tag order).
store = bytearray(ss1)
new_entries = []
for tag, ty, off, blob in laid:
    store[off:off + len(blob)] = blob
    new_entries.append([tag, ty, off, blob])
# Counts: BIN entries count bytes; others keep their original count.
orig_count = {e[0]: e[3] for e in e1}
final_entries = []
for tag, ty, off, blob in new_entries:
    if tag == 1002:
        final_entries.append([tag, ty, off, len(packet2)])
    elif tag == 1008:
        final_entries.append([tag, ty, off, len(blob)])
    elif ty == 7:
        final_entries.append([tag, ty, off, len(blob)])
    else:
        final_entries.append([tag, ty, off, orig_count[tag]])
final_entries.sort(key=lambda e: e[0])

out_buf = bytearray()
out_buf += data1[:96]
preamble = bytearray(data1[96:112])
preamble[8:12] = struct.pack(">I", len(final_entries))
out_buf += preamble
for (t, ty, o, c) in final_entries:
    out_buf += struct.pack(">IIII", t, ty, o, c)
out_buf += store
pad = (8 - len(out_buf) % 8) % 8
out_buf += b"\x00" * pad
out_buf += tail1
open(out, "wb").write(out_buf)
print(f"stacked: tag 1002 at offset {[e[2] for e in final_entries if e[0] == 1002][0]}, reserved keeps {keep} bytes")
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

# A second, distinct test key: the stacked fixture carries one
# signature from each key, and the per-issuer test runs against a
# keyring holding neither.
cat > /work/keyparams2 <<'EOF'
Key-Type: RSA
Key-Length: 2048
Name-Real: rpmcrab test key 2 (DO NOT TRUST)
Name-Email: rpmcrab-testkey2@example.invalid
Expire-Date: 0
%no-protection
%commit
EOF
gpg --batch --gen-key /work/keyparams2
key_count2="$(gpg --list-keys --with-colons | awk -F: '/^fpr/{n++} END{print n+0}')"
if [ "$key_count2" != "2" ]; then
    echo "error: expected exactly two generated keys, found $key_count2" >&2
    exit 1
fi
FINGERPRINT2="$(gpg --list-keys --with-colons | awk -F: -v first="$FINGERPRINT" '/^fpr/ && $10 != first {print $10; exit}')"
if ! [[ "$FINGERPRINT2" =~ ^[0-9A-F]{40}$ ]]; then
    echo "error: second key fingerprint is not 40 hex digits: '$FINGERPRINT2'" >&2
    exit 1
fi
PRINTED2="$(printf '%s' "${FINGERPRINT2: -8}" | tr 'A-F' 'a-f')"
if ! [[ "$PRINTED2" =~ ^[0-9a-f]{8}$ ]]; then
    echo "error: derived second key ID is not 8 lowercase hex digits: '$PRINTED2'" >&2
    exit 1
fi
if [ "$PRINTED2" = "$PRINTED" ]; then
    echo "error: the two test keys share a printed key ID: $PRINTED" >&2
    exit 1
fi
gpg --armor --export "$FINGERPRINT2" > /work/staged/signature-testkey2.asc
gpg --export "$FINGERPRINT2" > /work/staged/signature-testkey2.gpg

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
# The stacked variant carries both keys' signatures. rpmsign
# keeps a single header-signature slot (a second --addsign
# replaces the first signature), so the second signature is made
# for the legacy PGP slot (tag 1002), which signs the header and
# payload together: gpg signs those bytes of the unsigned package
# detached with the second key, and stack.py transplants the
# packet into the signed file's reserved space under tag 1002 —
# the shape the Factory corpus' dual-signed packages carry
# (signature entries at tags 268 and 1002). The parity matrix
# below verifies both signatures: each key's line reads NOKEY
# against the empty rpmdb and the first key's reads OK once it is
# imported.
python3 - "$UNSIGNED" <<'HPEOF'
import struct
import sys

data = open(sys.argv[1], "rb").read()


def hdr_end(buf, off):
    assert buf[off:off + 3] == b"\x8e\xad\xe8", "header magic"
    nindex, store_size = struct.unpack(">II", buf[off + 8:off + 16])
    return off + 16 + nindex * 16 + store_size


sig_end = hdr_end(data, 96)
main_off = sig_end + (8 - sig_end % 8) % 8
open("/work/hp.bin", "wb").write(data[main_off:])
HPEOF
gpg --batch --yes --pinentry-mode loopback --passphrase '' --digest-algo SHA256 -u "$FINGERPRINT2" --detach-sign -o /work/sig2.pgp /work/hp.bin
python3 /work/stack.py /work/signed.rpm /work/sig2.pgp /work/staged/signature-stacked-1.0-1.noarch.rpm
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
expect signature-stacked-1.0-1.noarch.rpm /work/db-empty "key ID $PRINTED: NOKEY"
expect signature-stacked-1.0-1.noarch.rpm /work/db-empty "key ID $PRINTED2: NOKEY"
expect signature-stacked-1.0-1.noarch.rpm /work/db-key "key ID $PRINTED: OK"
expect signature-stacked-1.0-1.noarch.rpm /work/db-key "key ID $PRINTED2: NOKEY"
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
echo "second test key fingerprint $FINGERPRINT2"
echo "EXPECTED_KEY_ID_2 for signature.rs tests: $PRINTED2"
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
    signature-stacked-1.0-1.noarch.rpm
    signature-testkey.asc
    signature-testkey.gpg
    signature-testkey2.asc
    signature-testkey2.gpg
)
for f in "${expected_outputs[@]}"; do
    [ -s "$work/staged/$f" ] || die "container did not produce staged output: $f"
    cp "$work/staged/$f" "$here/$f"
done

echo "built in $here:"
ls "$here"/signature-*.rpm "$here"/signature-testkey*.*
