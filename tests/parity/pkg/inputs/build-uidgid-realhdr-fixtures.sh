#!/usr/bin/env bash
# Build the real-header non-standard-uid/gid fixture RPMs (issue #827).
#
# Three packages from three specs, so each has its own SOURCERPM:
# uidgid-realhdr-main ships payload files owned by hdruser/hdrgroup
# and declares the accounts through no route (its header carries only
# rpm's generator stamps for them); uidgid-realhdr-handwritten ships
# the same payload and declares both accounts with packager-written
# Requires(pre) capabilities; uidgid-realhdr-control ships the same
# payload plus a sysusers.d snippet declaring both accounts.
#
# Usage: bash tests/parity/pkg/inputs/build-uidgid-realhdr-fixtures.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: uidgid-realhdr-main-1.0-1.noarch.rpm,
#         uidgid-realhdr-handwritten-1.0-1.noarch.rpm,
#         uidgid-realhdr-control-1.0-1.noarch.rpm (all in this directory)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"
# Pinned by digest (issue #797): the fixture RPMs must rebuild with
# the same shape; a floating tag would let a regenerated fixture
# silently change as rpm's generators evolve. Refresh the digest
# deliberately when the base image is meant to move.
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed@sha256:7f2cd9ec1fb4d18b83a110dd379a5e387b6cb21c05b6908792038b430e69b0e3}"

cp "$here"/uidgid-realhdr.spec "$here"/uidgid-realhdr-handwritten.spec \
   "$here"/uidgid-realhdr-control.spec "$work/rpmbuild/SPECS/"

"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'set -e
        zypper -n in -y rpm-build >/dev/null
        groupadd -g 12348 hdrgroup
        useradd -u 12347 -g hdrgroup -M -d /nonexistent -s /usr/sbin/nologin hdruser
        for spec in uidgid-realhdr uidgid-realhdr-handwritten uidgid-realhdr-control; do
            rpmbuild -bb --define "_topdir /rpmbuild" "/rpmbuild/SPECS/$spec.spec"
        done'

expected=(uidgid-realhdr-main-1.0-1.noarch.rpm uidgid-realhdr-handwritten-1.0-1.noarch.rpm uidgid-realhdr-control-1.0-1.noarch.rpm)

# Fail loudly on a zero or misnamed build (issue #797), validating
# this run's outputs in the build tree before the committed fixtures
# are touched (issue #804): a failed build leaves the previous
# fixtures in place. `ls` inside $(...) masks its own failure under
# `set -e` and would happily list a previous run's files, so the
# build tree is probed with `find` per expected name.
for name in "${expected[@]}"; do
    if [ -z "$(find "$work/rpmbuild/RPMS" -name "$name" -print)" ]; then
        echo "error: expected fixture $name was not built" >&2
        exit 1
    fi
done

for name in "${expected[@]}"; do
    rm -f "$here/$name"
done
find "$work/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$here/" \;
echo "built: ${expected[*]}"
