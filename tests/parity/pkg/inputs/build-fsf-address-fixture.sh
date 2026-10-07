#!/usr/bin/env bash
# Build the fsf-address-fixture RPM (incorrect-fsf-address whole-file scan).
#
# fsf-address-fixture: three doc files exercising the FSF address check end
# to end through a real RPM payload --
#   LICENSE-early: wrong FSF address inside the first 2048 bytes,
#   LICENSE-late:  wrong FSF address past byte 2048 (upstream rpmlint#40),
#   LICENSE-ok:    GPL mention with no street address (must stay silent).
#
# Usage: bash tests/parity/pkg/inputs/build-fsf-address-fixture.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/parity/pkg/inputs/fsf-address-fixture-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-fsf-address-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}"

cp "$here/fsf-address-fixture.spec" "$work/rpmbuild/SPECS/fixture.spec"

"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'zypper -n in rpm-build >/dev/null && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/fixture.spec'

find "$work/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$here/" \;
echo "built: $(ls "$here"/fsf-address-fixture-*.rpm)"
