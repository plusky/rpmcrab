#!/usr/bin/env bash
# Build the build-env severity-cap fixtures.
#
# Four packages with identical E-earning payloads (an .htaccess file
# for FilesCheck, a bogus License for TagsCheck), differing only in
# the build-env marker on their own header:
#   marked    -- Requires: this-is-only-for-build-envs (capped at W)
#   unmarked  -- no marker (control; findings keep native levels)
#   provides  -- Provides: this-is-only-for-build-envs (near miss)
#   typo      -- Requires: this-is-only-for-build-env (near miss)
#
# Usage: bash tests/parity/pkg/inputs/build-buildenv-cap-fixtures.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/parity/pkg/inputs/buildenv-cap-{marked,unmarked,provides,typo}-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-buildenv-cap-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}"

cp "$here"/buildenv-cap-*.spec "$work/rpmbuild/SPECS/"

"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'zypper -n in rpm-build >/dev/null && for s in /rpmbuild/SPECS/*.spec; do rpmbuild -bb --define "_topdir /rpmbuild" "$s"; done'

find "$work/rpmbuild/RPMS" -name 'buildenv-cap-*.rpm' -exec cp {} "$here/" \;
echo "built: $(ls "$here"/buildenv-cap-*.rpm)"
