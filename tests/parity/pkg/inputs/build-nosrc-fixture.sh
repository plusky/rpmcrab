#!/usr/bin/env bash
# Build the nosrc-fixture RPM: a genuine .nosrc.rpm — a complete header
# plus a payload holding only the spec. Source0 is marked NoSource, so
# the tarball is recorded in the header but absent from the payload by
# construction.
#
# Usage: bash tests/parity/pkg/inputs/build-nosrc-fixture.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/parity/pkg/inputs/nosrc-fixture-1.0-1.nosrc.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/rpmbuild"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} "$work/src/secret-sauce-1.0"

podman_bin="${PODMAN:-podman}"
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}"

echo "non-redistributable fixture source" > "$work/src/secret-sauce-1.0/README"
tar -czf "$work/rpmbuild/SOURCES/secret-sauce.tar.gz" -C "$work/src" secret-sauce-1.0
cp "$here/nosrc-fixture.spec" "$work/rpmbuild/SPECS/nosrc-fixture.spec"

"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'zypper -n in -y rpm-build >/dev/null && rpmbuild -bs --define "_topdir /rpmbuild" /rpmbuild/SPECS/nosrc-fixture.spec'

built="$(find "$work/rpmbuild/SRPMS" -name '*.nosrc.rpm' -print -quit)"
[ -n "$built" ] || { echo "rpmbuild produced no package" >&2; exit 1; }

cp "$built" "$here/"
echo "built: $here/$(basename "$built")"
