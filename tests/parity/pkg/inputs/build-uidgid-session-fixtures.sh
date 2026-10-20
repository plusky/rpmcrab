#!/usr/bin/env bash
# Build the non-standard-uid/gid session fixture RPMs (issue #756).
#
# uidgid-session-main + uidgid-session-sysusers come from one spec, so
# they share a SOURCERPM: the sysusers subpackage ships the sysusers.d
# snippet declaring svcfoo/svcbar, the main subpackage ships the
# payload. Together they pin the session-aware decision: accounts a
# sibling package declares stay quiet.
#
# Usage: bash tests/parity/pkg/inputs/build-uidgid-session-fixtures.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: uidgid-session-main-1.0-1.noarch.rpm,
#         uidgid-session-sysusers-1.0-1.noarch.rpm (all in this directory)
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
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed@sha256:1a7032dc8d017b2b8e8c63656ca53e625b9b591a5e856ba0c546c8c503dd42a8}"

cp "$here/uidgid-session.spec" "$work/rpmbuild/SPECS/"

"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'zypper -n in -y rpm-build >/dev/null && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/uidgid-session.spec'

rm -f "$here/uidgid-session-main-1.0-1.noarch.rpm" "$here/uidgid-session-sysusers-1.0-1.noarch.rpm"
find "$work/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$here/" \;

# Fail loudly on a zero or misnamed build (issue #797): `ls` inside
# $(...) masks its own failure under `set -e` and would happily list
# a previous run's files, so assert the two expected outputs of this
# run exist (the stale copies were removed above).
for expected in uidgid-session-main-1.0-1.noarch.rpm uidgid-session-sysusers-1.0-1.noarch.rpm; do
    if [ ! -f "$here/$expected" ]; then
        echo "error: expected fixture $expected was not built" >&2
        exit 1
    fi
done
echo "built: uidgid-session-main-1.0-1.noarch.rpm uidgid-session-sysusers-1.0-1.noarch.rpm"
