#!/usr/bin/env bash
# Build the script_body_or_prog regression-test fixture.
#
# A noarch RPM with a present-but-empty %post body and `-p /bin/sh`:
# exercises the `pkg[tag] or pkg.scriptprog(tagprog)` fallthrough
# (an empty body must fall back to the interpreter string).
# Also carries a non-empty %preun to pin the body-wins case.
#
# Usage: bash tests/parity/pkg/inputs/build-scriptlet-empty-post.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image with rpm-build
# Output: tests/parity/pkg/inputs/scriptlet-empty-post-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-fixture-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"

# NOTE: no blank line or comment between %post and %preun — the body
# must be a truly empty string, not whitespace.
cat >"$work/rpmbuild/SPECS/fixture.spec" <<'EOF'
Name:           scriptlet-empty-post
Version:        1.0
Release:        1
Summary:        Fixture for script_body_or_prog empty-body fallthrough
License:        MIT
BuildArch:      noarch

%description
Fixture.

%post -p /bin/sh
%preun -p /bin/sh
echo preun-body

%files
EOF

"$podman_bin" run --rm \
  -v "$work/rpmbuild:/rpmbuild:z" \
  registry.opensuse.org/opensuse/tumbleweed:latest \
  bash -c "zypper -n in -y rpm-build >/dev/null 2>&1; rpmbuild --define '_topdir /rpmbuild' --nosignature -bb /rpmbuild/SPECS/fixture.spec" >/dev/null

built="$(find "$work/rpmbuild/RPMS" -name 'scriptlet-empty-post-*.rpm' -print -quit)"
[ -n "$built" ] || { echo "rpmbuild produced no package" >&2; exit 1; }

cp "$built" "$here/"
echo "Wrote $here/$(basename "$built")"
