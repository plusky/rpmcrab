#!/usr/bin/env bash
# Build the w6-alternatives-named-link fixture RPM (alternative-link-missing).
#
# w6-alternatives-named-link: registrations whose alternative name differs
# from the generic link's basename, shipping the /etc/alternatives link as
# %ghost under the registered name (a renamed master link and a renamed
# slave link), next to two renamed links that keep firing (no
# /etc/alternatives entry at all; an entry shipped as a regular file) and
# a standard name == basename control.
#
# Usage: bash tests/parity/pkg/inputs/build-w6-alternatives-named-link.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/parity/pkg/inputs/w6-alternatives-named-link-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-w6-alternatives-named-link-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}"

cp "$here/w6-alternatives-named-link.spec" "$work/rpmbuild/SPECS/fixture.spec"

"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'zypper -n in rpm-build >/dev/null && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/fixture.spec'

find "$work/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$here/" \;
echo "built: $(ls "$here"/w6-alternatives-named-link-*.rpm)"
