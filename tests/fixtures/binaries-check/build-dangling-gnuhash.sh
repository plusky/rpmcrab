#!/usr/bin/env bash
# Rebuild the dangling-DT_GNU_HASH BinariesCheck test fixture.
#
# Builds a tiny RPM containing one shared library whose .hash and .gnu.hash
# sections were stripped with objcopy, leaving the DT_GNU_HASH (and DT_HASH)
# dynamic entries dangling. goblin's strict parse rejects such files; the
# port retries permissively so the sections read as missing and both
# hash-section findings are emitted, like the reference.
#
# Usage: bash tests/fixtures/binaries-check/build-dangling-gnuhash.sh
# Needs: podman (or PODMAN=/path/to/podman)
# Output: input/rpmcrab-binaries-dangling-gnuhash-1.0-1.<arch>.rpm
#
# Everything (compile, strip, package) happens in the digest-pinned
# Tumbleweed image built from the shared Dockerfile, so the fixture is a
# genuine Linux RPM regardless of host OS.
# (Unlike build.sh, rpmbuild also runs in the container: the host rpmbuild
# on some machines cannot create its build directories.)

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

podman_bin="${PODMAN:-podman}"

# The container-side build runs from a file to avoid nested shell quoting.
cat >"$work/inner.sh" <<'INNER_EOF'
set -e
# The toolchain (gcc, binutils, rpm-build) comes from the digest-pinned image
# built from the shared Dockerfile; nothing is installed in the container.
cat > /work/libdangling.c <<'EOF'
int dangling_answer(void) { return 42; }
EOF
cd /work
gcc -shared -fPIC -o libdangling.so.1 libdangling.c
objcopy --remove-section=.hash --remove-section=.gnu.hash libdangling.so.1 libdangling-stripped.so.1
mkdir -p /work/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp /work/libdangling-stripped.so.1 /work/rpmbuild/SOURCES/
cat > /work/rpmbuild/SPECS/fixture.spec <<'EOF'
Name:           rpmcrab-binaries-dangling-gnuhash
Version:        1.0
Release:        1
Summary:        Fixture: shared lib with stripped hash sections (dangling DT_GNU_HASH)
License:        MIT
BuildArch:      %{_target_cpu}

%description
Test fixture for the dangling DT_GNU_HASH parity case.

%install
mkdir -p %{buildroot}/usr/lib64
cp %{_sourcedir}/libdangling-stripped.so.1 %{buildroot}/usr/lib64/

%files
/usr/lib64/libdangling-stripped.so.1
EOF
rpmbuild --define "_topdir /work/rpmbuild" --nosignature -bb /work/rpmbuild/SPECS/fixture.spec >/dev/null
INNER_EOF

# The image reference (digest-pinned base) lives in Dockerfile so Dependabot's
# docker ecosystem can bump the pin monthly; this script only names the built tag.
"$podman_bin" build -f "$here/Dockerfile" -t rpmcrab-binaries-check-fixture "$here"

"$podman_bin" run --rm -v "$work:/work:z" rpmcrab-binaries-check-fixture bash /work/inner.sh

built="$(find "$work/rpmbuild/RPMS" -name 'rpmcrab-binaries-dangling-gnuhash-*.rpm' -print -quit)"
[ -n "$built" ] || { echo "rpmbuild produced no package" >&2; exit 1; }

cp "$built" "$here/input/"
echo "Wrote $here/input/$(basename "$built")"
