#!/usr/bin/env bash
# Build the w6-alternatives-template fixture RPM (alternative-generic-name-missing).
#
# w6-alternatives-template: a %post registering alternatives from a shell
# loop, so the extracted link still carries the loop variable
# (/usr/bin/w6tpl_$i), next to a literal registration whose generic name
# is not shipped (/usr/bin/w6literal, the still-firing control). The
# loop's concrete expansions ship their generic symlinks and
# /etc/alternatives ghosts.
#
# Usage: bash tests/parity/pkg/inputs/build-w6-alternatives-template.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/parity/pkg/inputs/w6-alternatives-template-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-w6-alternatives-template-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}"

cp "$here/w6-alternatives-template.spec" "$work/rpmbuild/SPECS/fixture.spec"

"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'zypper -n in rpm-build >/dev/null && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/fixture.spec'

find "$work/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$here/" \;
echo "built: $(ls "$here"/w6-alternatives-template-*.rpm)"
