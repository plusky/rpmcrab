#!/usr/bin/env bash
# Build the pem-private-key-fixture RPM (pem-private-key whole-content scan).
#
# pem-private-key-fixture: five .pem files exercising the whole-content
# pem-private-key scan end to end through a real RPM payload --
#   genuine.pem:   well-formed five-dash private-key header (must fire),
#   cert.pem:      certificate header (fires only pem-certificate),
#   malformed.pem: reference's four-dash header (must stay silent),
#   text.pem:      non-PEM text (must stay silent),
#   multiline.pem: full header-plus-body-plus-footer key (must stay
#     silent, pinning the whole-content anchor).
#
# Usage: bash tests/parity/pkg/inputs/build-pem-private-key-fixture.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/parity/pkg/inputs/pem-private-key-fixture-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-pem-private-key-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}"

cp "$here/pem-private-key-fixture.spec" "$work/rpmbuild/SPECS/fixture.spec"

"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'zypper -n in rpm-build >/dev/null && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/fixture.spec'

find "$work/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$here/" \;
echo "built: $(ls "$here"/pem-private-key-fixture-*.rpm)"
