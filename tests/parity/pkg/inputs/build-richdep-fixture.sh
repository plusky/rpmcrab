#!/usr/bin/env bash
# Build the richdep-fixture RPM (rich/boolean dependencies + qualifiers).
#
# richdep-fixture: Requires exercising pkg::dep expression parsing end to
# end through a real RPM header --
#   (foo or bar), (baz >= 1.0 with baz < 2.0),
#   (outer and (inner1 or inner2)), qux(meta)
#
# Usage: bash tests/parity/pkg/inputs/build-richdep-fixture.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/parity/pkg/inputs/richdep-fixture-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-richdep-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}"

cp "$here/richdep-fixture.spec" "$work/rpmbuild/SPECS/fixture.spec"

"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'zypper -n in rpm-build >/dev/null && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/fixture.spec'

find "$work/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$here/" \;
echo "built: $(ls "$here"/richdep-fixture-*.rpm)"
