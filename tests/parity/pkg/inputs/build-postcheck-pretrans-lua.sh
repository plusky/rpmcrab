#!/usr/bin/env bash
# Build the pretrans-not-lua lua-silence fixture.
#
# A noarch RPM with `%pretrans -p <lua>`: the only interpreter RPM
# guarantees for %pretrans (upstream rpmlint#396, rationale rpm#714).
# PostCheck must stay silent on it — pinning the "<lua>" prog path
# through check_binary (the shell-pretrans warn path is pinned by the
# postcheck-parity fixture vector).
#
# Usage: bash tests/parity/pkg/inputs/build-postcheck-pretrans-lua.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/parity/pkg/inputs/postcheck-pretrans-lua-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-pretrans-lua-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"

cat >"$work/rpmbuild/SPECS/fixture.spec" <<'EOF'
Name:           postcheck-pretrans-lua
Version:        1.0
Release:        1
Summary:        Fixture for pretrans-not-lua lua-silence case
License:        MIT
BuildArch:      noarch

%description
Fixture.

%pretrans -p <lua>
print('hello from pretrans')

%files
EOF

"$podman_bin" run --rm \
  -v "$work/rpmbuild:/rpmbuild:z" \
  registry.opensuse.org/opensuse/tumbleweed:latest \
  bash -c "zypper -n in -y rpm-build >/dev/null 2>&1; rpmbuild --define '_topdir /rpmbuild' --nosignature -bb /rpmbuild/SPECS/fixture.spec" >/dev/null

built="$(find "$work/rpmbuild/RPMS" -name 'postcheck-pretrans-lua-*.rpm' -print -quit)"
[ -n "$built" ] || { echo "rpmbuild produced no package" >&2; exit 1; }

cp "$built" "$here/"
echo "Wrote $here/$(basename "$built")"
