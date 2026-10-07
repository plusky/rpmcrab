#!/usr/bin/env bash
# Build the ReleaseExtension changelog-strip fixture RPMs.
#
# distrelease:        Release 3.fc42, changelog entry "1.15.1-3" (no dist
#                     suffix) -> the configured ReleaseExtension strip makes
#                     the changelog comparison tolerate the suffix.
# distrelease-badver: Release 3.fc42, changelog entry "1.15.2-3" -> still
#                     incoherent-version-in-changelog (the version itself
#                     differs, not just the suffix).
# distrelease-weird:  Release 3.weird9 (suffix unknown to the catalog),
#                     changelog entry "1.15.1-3" -> still
#                     incoherent-version-in-changelog (nothing is stripped).
#
# Usage: bash tests/parity/pkg/inputs/build-distrelease-parity.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/parity/pkg/inputs/distrelease-1.15.1-3.fc42.noarch.rpm
#         tests/parity/pkg/inputs/distrelease-badver-1.15.1-3.fc42.noarch.rpm
#         tests/parity/pkg/inputs/distrelease-weird-1.15.1-3.weird9.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-distrelease-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"

make_spec() {
  local name="$1" release="$2" clver="$3"
  cat >"$work/rpmbuild/SPECS/$name.spec" <<EOF
Name:           $name
Version:        1.15.1
Release:        $release
Summary:        ReleaseExtension changelog fixture
License:        MIT
BuildArch:      noarch

%description
Fixture for the ReleaseExtension changelog strip.

%changelog
* Mon Sep 05 2022 Someone <someone@example.com> - $clver
- test changelog entry

%files
EOF
}

make_spec distrelease 3.fc42 1.15.1-3
make_spec distrelease-badver 3.fc42 1.15.2-3
make_spec distrelease-weird 3.weird9 1.15.1-3

"$podman_bin" run --rm \
  -v "$work/rpmbuild:/rpmbuild:z" \
  registry.opensuse.org/opensuse/tumbleweed:latest \
  bash -c "zypper -n in -y rpm-build >/dev/null 2>&1; rpmbuild --define '_topdir /rpmbuild' --nosignature -bb /rpmbuild/SPECS/distrelease.spec /rpmbuild/SPECS/distrelease-badver.spec /rpmbuild/SPECS/distrelease-weird.spec" >/dev/null

for f in distrelease-1.15.1-3.fc42 distrelease-badver-1.15.1-3.fc42 distrelease-weird-1.15.1-3.weird9; do
  built="$work/rpmbuild/RPMS/noarch/$f.noarch.rpm"
  cp "$built" "$here/"
  echo "wrote $here/$f.noarch.rpm"
done
