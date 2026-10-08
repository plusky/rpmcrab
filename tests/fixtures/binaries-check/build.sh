#!/usr/bin/env bash
# Rebuild the BinariesCheck test fixture.
#
# Builds a tiny RPM containing prebuilt ELF binaries with known properties:
# - libbad.so.1: executable stack, no SONAME (triggers executable-stack, no-soname)
# - libgood.so.1: non-executable stack, proper SONAME (absence assertions)
# - setuidbin: setuid-root binary calling setgid() and setuid() without setgroups()
#   (triggers missing-call-to-setgroups-before-setuid at Error severity)
# - rpathbin: binary with RUNPATH (triggers binary-or-shlib-defines-rpath)
# - truncated: 64-byte truncated ELF (triggers readelf-failed)
# - cryptobad: stripped shared lib with undefined SSL_CTX_set_cipher_list
#   import (triggers crypto-policy-non-compliance-openssl via WarnOnFunction)
# - gnutlswaived: stripped shared lib calling gnutls_priority_init whose
#   strings contain the waiver ("SYSLOG"), so the finding is suppressed
#
# Usage: bash tests/fixtures/binaries-check/build.sh
# Needs: podman (or PODMAN=/path/to/podman)
# Output: input/rpmcrab-binaries-fixture-1.0-1.<arch>.rpm
#
# Everything (compilation and rpmbuild) runs in an openSUSE container: it
# produces genuine ELF output regardless of the host OS, and host rpmbuild
# is unreliable on macOS.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/src" "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"

cat >"$work/src/libbad.c" <<'EOF'
int bad_function(void) { return 42; }
EOF
cat >"$work/src/libgood.c" <<'EOF'
int good_function(void) { return 42; }
EOF
cat >"$work/src/setuidbin.c" <<'EOF'
#include <unistd.h>
int main(void) { setgid(0); setuid(0); return 0; }
EOF
cat >"$work/src/rpathbin.c" <<'EOF'
int main(void) { return 0; }
EOF
cat >"$work/src/cryptobad.c" <<'EOF'
typedef struct ssl_ctx_st SSL_CTX;
extern int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
/* Modern GCC emits undefined imports as NOTYPE; the reference fixture
   (arbitron) carries them as FUNC, which is what the check scans for.
   Do not remove this directive: if a future toolchain ignores it, the
   symbol reverts to NOTYPE, the port stops matching it, and the
   forbidden-function tests would still go green. */
__asm__(".type SSL_CTX_set_cipher_list, @function");
int set_ciphers(SSL_CTX *ctx) { return SSL_CTX_set_cipher_list(ctx, "DEFAULT"); }
EOF
cat >"$work/src/gnutlswaived.c" <<'EOF'
extern int gnutls_priority_init(void *session, const char *priority, const char **err_pos);
__asm__(".type gnutls_priority_init, @function");
static const char waiver_note[] = "SYSLOG priority approved by policy";
int init_priority(void *session) { return gnutls_priority_init(session, waiver_note, 0); }
EOF

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
cp %{_sourcedir}/libcryptobad.so %{buildroot}/usr/lib64/
cp %{_sourcedir}/libgnutlswaived.so %{buildroot}/usr/lib64/
head -c 64 %{_sourcedir}/setuidbin > %{buildroot}/usr/bin/truncated
chmod 755 %{buildroot}/usr/bin/truncated

%files
/usr/lib64/libbad.so.1
/usr/lib64/libgood.so.1
/usr/lib64/libcryptobad.so
/usr/lib64/libgnutlswaived.so
%attr(4755,root,root) /usr/bin/setuidbin
/usr/bin/rpathbin
/usr/bin/truncated
EOF

# The container-side build runs from a file to avoid nested shell quoting:
# a stray double quote inside `bash -c "..."` silently truncates the payload
# while the container still exits 0, leaving the stale RPM behind unnoticed.
# Same idiom as build-dangling-gnuhash.sh.
cat >"$work/inner.sh" <<'INNER_EOF'
set -e
cd /work/src
gcc -shared -fPIC -z execstack -o libbad.so.1 libbad.c
gcc -shared -fPIC -z noexecstack -Wl,-soname,libgood.so.1 -o libgood.so.1 libgood.c
gcc -o setuidbin setuidbin.c
gcc -Wl,-rpath,/opt/custom/lib -o rpathbin rpathbin.c
gcc -shared -fPIC -z noexecstack -Wl,-soname,libcryptobad.so -o libcryptobad.so cryptobad.c
gcc -shared -fPIC -z noexecstack -Wl,-soname,libgnutlswaived.so -o libgnutlswaived.so gnutlswaived.c
strip libcryptobad.so libgnutlswaived.so
# The __asm__(".type ..., @function") directives in cryptobad.c /
# gnutlswaived.c are load-bearing: modern GCC emits undefined imports as
# NOTYPE, which the forbidden-function scan does not match. If a future
# toolchain ignores the directives, the fixture silently stops exercising
# the check and the tests still go green -- fail the build loudly instead.
readelf --dyn-syms -W libcryptobad.so | grep -q "FUNC.*SSL_CTX_set_cipher_list" \
    || { echo "fixture broken: SSL_CTX_set_cipher_list is not FUNC" >&2; exit 1; }
readelf --dyn-syms -W libgnutlswaived.so | grep -q "FUNC.*gnutls_priority_init" \
    || { echo "fixture broken: gnutls_priority_init is not FUNC" >&2; exit 1; }
cp /work/src/libbad.so.1 /work/src/libgood.so.1 /work/src/setuidbin /work/src/rpathbin /work/src/libcryptobad.so /work/src/libgnutlswaived.so /work/rpmbuild/SOURCES/
rpmbuild --define '_topdir /work/rpmbuild' --nosignature -bb /work/rpmbuild/SPECS/fixture.spec
INNER_EOF

# The image reference (digest-pinned base) lives in Dockerfile so Dependabot's
# docker ecosystem can bump the pin monthly; build.sh only names the built tag.
"$podman_bin" build -f "$here/Dockerfile" -t rpmcrab-binaries-check-fixture "$here"

"$podman_bin" run --rm -v "$work:/work:z" rpmcrab-binaries-check-fixture bash /work/inner.sh

built="$(find "$work/rpmbuild/RPMS" -name 'rpmcrab-binaries-fixture-*.rpm' -print -quit)"
[ -n "$built" ] || { echo "rpmbuild produced no package" >&2; exit 1; }

cp "$built" "$here/input/"
echo "Wrote $here/input/$(basename "$built")"
