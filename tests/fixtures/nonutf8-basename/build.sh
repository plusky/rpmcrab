#!/usr/bin/env bash
# Rebuild the non-UTF-8-basename robustness fixture.
#
# rpmbuild refuses to put a non-UTF-8 name in a package ("invalid utf-8
# encoding in Basenames"), so the package is built clean and the name is
# rewritten in place afterwards. The rewrite is the same length, so every
# offset in the header stays valid, and the header digests are recomputed and
# patched so the package is internally consistent.
#
# Usage: bash tests/fixtures/nonutf8-basename/build.sh
# Needs: rpmbuild, python3, rpm. Rewrites input/ in place.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
topdir="$work/topdir"
mkdir -p "$work/SPECS" "$topdir"

cat >"$work/SPECS/fixture.spec" <<'SPEC'
Name:           rpmcrab-nonutf8
Version:        1
Release:        1
Summary:        Fixture with a non-UTF-8 file name
License:        MIT
Group:          Development/Libraries
URL:            https://example.invalid/rpmcrab
BuildArch:      noarch

%description
A fixture whose file list contains a base name that is not valid UTF-8. librpm's
decoders panic on such a header; the reference decodes it leniently.

%install
mkdir -p %{buildroot}/usr/share/rpmcrab-fixture
echo hi > %{buildroot}/usr/share/rpmcrab-fixture/placeholder.txt

%files
/usr/share/rpmcrab-fixture
SPEC

# Unsigned, so the signature region holds only the header digests and patching
# them leaves nothing else inconsistent.
rpmbuild --define "_topdir $topdir" --nosignature -bb "$work/SPECS/fixture.spec" >/dev/null

built="$(find "$topdir/RPMS" -name 'rpmcrab-nonutf8-*.noarch.rpm' -print -quit)"
[ -n "$built" ] || { echo "rpmbuild produced no package" >&2; exit 1; }

python3 - "$built" "$here/input/rpmcrab-nonutf8-1-1.noarch.rpm" <<'PY'
import hashlib, struct, sys

src, dst = sys.argv[1], sys.argv[2]
pristine = open(src, 'rb').read()

# RPM v4: lead(96) | signature blob | (8-byte aligned) header blob | payload.
nindex, hsize = struct.unpack('>II', pristine[96 + 8:96 + 16])
sig_end = 96 + 16 + nindex * 16 + hsize
header = sig_end + ((8 - sig_end % 8) % 8)
hn, hh = struct.unpack('>II', pristine[header + 8:header + 16])
header_end = header + 16 + hn * 16 + hh

# The signature region stores the digests as lowercase hex text.
stale = {}
for name in ('sha256', 'sha1', 'md5'):
    h = getattr(hashlib, name)(pristine[header:header_end]).hexdigest().encode()
    if pristine.count(h) == 1:
        stale[name] = h

data = bytearray(pristine)
# 0xff never forms valid UTF-8; same length, so no offset moves.
old, new = b'placeholder.txt', b'placeh\xfflder.txt'
assert len(old) == len(new)
data = bytearray(bytes(data).replace(old, new))

region = bytes(data[header:header_end])
for name, h in stale.items():
    fresh = getattr(hashlib, name)(region).hexdigest().encode()
    at = bytes(data).find(h)
    data[at:at + len(h)] = fresh
    print(f'repatched {name} at {at}')

open(dst, 'wb').write(bytes(data))
PY

rpm -K "$here/input/rpmcrab-nonutf8-1-1.noarch.rpm" || true
echo "wrote $here/input/rpmcrab-nonutf8-1-1.noarch.rpm"
echo "note: 'DIGESTS NOT OK' is expected - the package-level digest covers the"
echo "      whole file and the header was rewritten after it was computed."
