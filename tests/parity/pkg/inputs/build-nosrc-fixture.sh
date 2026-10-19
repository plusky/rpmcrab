#!/usr/bin/env bash
# Build the nosrc-fixture RPM: a genuine .nosrc.rpm — a complete header
# plus a payload holding only the spec. Source0 is marked NoSource, so
# the tarball is recorded in the header but absent from the payload by
# construction.
#
# Usage: bash tests/parity/pkg/inputs/build-nosrc-fixture.sh
# Needs: rpmbuild on the host (openSUSE: the rpm-build package)
# Output: tests/parity/pkg/inputs/nosrc-fixture-1.0-1.nosrc.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-nosrc-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} "$work/src/secret-sauce-1.0"

echo "non-redistributable fixture source" > "$work/src/secret-sauce-1.0/README"
tar -czf "$work/rpmbuild/SOURCES/secret-sauce.tar.gz" -C "$work/src" secret-sauce-1.0
cp "$here/nosrc-fixture.spec" "$work/rpmbuild/SPECS/nosrc-fixture.spec"
rpmbuild -bs --define "_topdir $work/rpmbuild" "$work/rpmbuild/SPECS/nosrc-fixture.spec"
cp "$work/rpmbuild/SRPMS/nosrc-fixture-1.0-1.nosrc.rpm" "$here/"
echo "built: $here/nosrc-fixture-1.0-1.nosrc.rpm"
