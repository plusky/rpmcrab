#!/usr/bin/env bash
# Build the AtomicUpdateCheck scriptlet wiring fixtures.
#
# atomic-post-restart: a %post body that restarts a service directly;
# AtomicUpdateCheck must report exactly one scriptlet-service-restart
# for it through the check entry point.
#
# atomic-verify-restart: the same restart in a %verifyscript body;
# %verifyscript runs on demand against the live system and is excluded
# from the scan, so the check must stay quiet. Together the pair pins
# the exclusion at the wiring: dropping the guard makes the verify
# fixture fire.
#
# Usage: bash tests/parity/pkg/inputs/build-atomic-scriptlet-fixtures.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/parity/pkg/inputs/atomic-post-restart-1.0-1.noarch.rpm
#         tests/parity/pkg/inputs/atomic-verify-restart-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-atomic-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"

cat >"$work/rpmbuild/SPECS/post.spec" <<'EOF'
Name:           atomic-post-restart
Version:        1.0
Release:        1
Summary:        AtomicUpdateCheck %post restart wiring fixture
License:        MIT
BuildArch:      noarch

%description
Fixture.

%post -p /bin/sh
systemctl restart foo.service

%files
EOF

cat >"$work/rpmbuild/SPECS/verify.spec" <<'EOF'
Name:           atomic-verify-restart
Version:        1.0
Release:        1
Summary:        AtomicUpdateCheck %verifyscript exclusion wiring fixture
License:        MIT
BuildArch:      noarch

%description
Fixture.

%verifyscript -p /bin/sh
systemctl restart foo.service

%files
EOF

"$podman_bin" run --rm \
  -v "$work/rpmbuild:/rpmbuild:z" \
  registry.opensuse.org/opensuse/tumbleweed:latest \
  bash -c "zypper -n in -y rpm-build >/dev/null 2>&1; rpmbuild --define '_topdir /rpmbuild' --nosignature -bb /rpmbuild/SPECS/post.spec /rpmbuild/SPECS/verify.spec" >/dev/null

for n in atomic-post-restart atomic-verify-restart; do
  built="$(find "$work/rpmbuild/RPMS" -name "$n-*.rpm" -print -quit)"
  [ -n "$built" ] || { echo "rpmbuild produced no $n package" >&2; exit 1; }
  cp "$built" "$here/"
  echo "Wrote $here/$(basename "$built")"
done
