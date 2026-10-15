#!/usr/bin/env bash
# Build the dangling-relative-symlink session fixture RPMs (issue #547).
#
# dangling-session-main + dangling-session-lang come from one spec:
# the main package ships the figure, the -lang subpackage links to it
# relatively, so the pair pins the session-aware decision (quiet
# together, firing alone). dangling-lone is a single package from its
# own spec whose links stay dangling in any run.
#
# Usage: bash tests/parity/pkg/inputs/build-dangling-session-fixtures.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: dangling-session-main-1.0-1.noarch.rpm,
#         dangling-session-lang-1.0-1.noarch.rpm,
#         dangling-lone-1.0-1.noarch.rpm (all in this directory)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}"

cp "$here/dangling-session.spec" "$work/rpmbuild/SPECS/"
cp "$here/dangling-lone.spec" "$work/rpmbuild/SPECS/"

"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'zypper -n in -y rpm-build >/dev/null && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/dangling-session.spec && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/dangling-lone.spec'

find "$work/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$here/" \;
echo "built: $(ls "$here"/dangling-*.rpm)"
