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
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}"

cp "$here/uidgid-session.spec" "$work/rpmbuild/SPECS/"

"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'zypper -n in -y rpm-build >/dev/null && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/uidgid-session.spec'

find "$work/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$here/" \;
echo "built: $(ls "$here"/uidgid-session-*.rpm)"
