#!/usr/bin/env bash
# Build the w6-sourced-script fixture RPM (sourced-script-with-shebang).
#
# w6-sourced-script: sourced scripts under /etc/profile.d exercising the
# sourced-script analysis end to end through a real RPM payload --
#   w6-shebang.sh: shebang, not executable (sourced-script-with-shebang),
#   w6-exec.sh:    shebang and executable (both sourced-script findings),
#   w6-clean.sh:   no shebang (silent control),
#   w6module.pm:   shebang ignored via the perl-module exception (silent).
#
# Usage: bash tests/parity/pkg/inputs/build-w6-sourced-script.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/parity/pkg/inputs/w6-sourced-script-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-w6-sourced-script-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}"

cp "$here/w6-sourced-script.spec" "$work/rpmbuild/SPECS/fixture.spec"

"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'zypper -n in rpm-build >/dev/null && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/fixture.spec'

find "$work/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$here/" \;
echo "built: $(ls "$here"/w6-sourced-script-*.rpm)"
