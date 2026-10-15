#!/usr/bin/env bash
# Build the no-documentation session fixture RPMs (issue #539).
#
# nodoc-session-main + nodoc-session-data come from one spec, so they
# share a SOURCERPM: the main package ships %doc files, the data
# subpackage ships none. nodoc-lone is a single doc-less package from
# its own spec. Together they pin the session-aware decision: sibling
# covered by the main package's docs stays quiet, lone package fires.
#
# Usage: bash tests/parity/pkg/inputs/build-nodoc-session-fixtures.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: nodoc-session-main-1.0-1.noarch.rpm,
#         nodoc-session-data-1.0-1.noarch.rpm,
#         nodoc-lone-1.0-1.noarch.rpm (all in this directory)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}"

cp "$here/nodoc-session.spec" "$work/rpmbuild/SPECS/"
cp "$here/nodoc-lone.spec" "$work/rpmbuild/SPECS/"

"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'zypper -n in -y rpm-build >/dev/null && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/nodoc-session.spec && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/nodoc-lone.spec'

find "$work/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$here/" \;
echo "built: $(ls "$here"/nodoc-*.rpm)"
