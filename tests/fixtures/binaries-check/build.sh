#!/usr/bin/env bash
# Rebuild the BinariesCheck test fixture.
#
# Builds a tiny RPM containing prebuilt ELF binaries with known properties:
# - libbad.so.1: executable stack, no SONAME (triggers executable-stack, no-soname)
# - libgood.so.1: non-executable stack, proper SONAME (absence assertions)
# - setuidbin: setuid-root binary calling setuid() without setgroups()
#   (triggers missing-call-to-setgroups-before-setuid at Error severity)
# - rpathbin: binary with RUNPATH (triggers binary-or-shlib-defines-rpath)
# - truncated: 64-byte truncated ELF (triggers readelf-failed)
#
# Usage: bash tests/fixtures/binaries-check/build.sh
# Needs: podman (or docker), rpmbuild
# Output: input/rpmcrab-binaries-fixture-1.0-1.<arch>.rpm
#
# The binaries are compiled for Linux (aarch64 via the container, but any
# arch works — goblin parses all ELF types). The container approach ensures
# genuine ELF output regardless of the host OS.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Compile the test binaries in an openSUSE container
mkdir -p "$work/src"
cat >"$work/src/libbad.c" <<'EOF'
int bad_function(void) { return 42; }
EOF
cat >"$work/src/libgood.c" <<'EOF'
int good_function(void) { return 42; }
EOF
cat >"$work/src/setuidbin.c" <<'EOF'
#include <unistd.h>
int main(void) { setuid(0); return 0; }
EOF
cat >"$work/src/rpathbin.c" <<'EOF'
int main(void) { return 0; }
EOF

podman run --rm -v "$work/src:/src:z" registry.opensuse.org/opensuse/tumbleweed:latest bash -c "
    zypper -n in -y gcc >/dev/null 2>&1
    cd /src
    gcc -shared -fPIC -z execstack -o libbad.so.1 libbad.c
    gcc -shared -fPIC -z noexecstack -Wl,-soname,libgood.so.1 -o libgood.so.1 libgood.c
    gcc -o setuidbin setuidbin.c
    gcc -Wl,-rpath,/opt/custom/lib -o rpathbin rpathbin.c
"

# Build the RPM
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp "$work"/src/{libbad.so.1,libgood.so.1,setuidbin,rpathbin} "$work/rpmbuild/SOURCES/"

cat >"$work/rpmbuild/SPECS/fixture.spec" <<'EOF'
Name:           rpmcrab-binaries-fixture
Version:        1.0
Release:        1
Summary:        Fixture for BinariesCheck tests
License:        MIT
BuildArch:      aarch64

%description
Test fixture for rpmcrab BinariesCheck.

%install
mkdir -p %{buildroot}/usr/lib64 %{buildroot}/usr/bin
cp %{_sourcedir}/libbad.so.1 %{buildroot}/usr/lib64/
cp %{_sourcedir}/libgood.so.1 %{buildroot}/usr/lib64/
cp %{_sourcedir}/setuidbin %{buildroot}/usr/bin/
cp %{_sourcedir}/rpathbin %{buildroot}/usr/bin/
head -c 64 %{_sourcedir}/setuidbin > %{buildroot}/usr/bin/truncated
chmod 755 %{buildroot}/usr/bin/truncated

%files
/usr/lib64/libbad.so.1
/usr/lib64/libgood.so.1
%attr(4755,root,root) /usr/bin/setuidbin
/usr/bin/rpathbin
/usr/bin/truncated
EOF

rpmbuild --define "_topdir $work/rpmbuild" --nosignature -bb "$work/rpmbuild/SPECS/fixture.spec" >/dev/null

built="$(find "$work/rpmbuild/RPMS" -name 'rpmcrab-binaries-fixture-*.rpm' -print -quit)"
[ -n "$built" ] || { echo "rpmbuild produced no package" >&2; exit 1; }

cp "$built" "$here/input/"
echo "Wrote $here/input/$(basename "$built")"
