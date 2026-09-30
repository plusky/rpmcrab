#!/usr/bin/env bash
# Build the PostCheck parity-case RPM: scriptlets exercising the finding
# families, all 10 SCRIPT_TAGS entries, and the B3 regex edge cases
# (braceless %macro, single-word vs multi-word commands).
#
# Usage: bash tests/parity/pkg/inputs/build-postcheck-parity.sh
# Needs: podman, an openSUSE container image with rpm-build
# Output: tests/parity/pkg/inputs/postcheck-parity-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-postcheck-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

cat >"$work/rpmbuild/SPECS/fixture.spec" <<'EOF'
Name:           postcheck-parity
Version:        1.0
Release:        1
Summary:        PostCheck parity fixture
License:        MIT
BuildArch:      noarch

%description
Fixture.

%pre -p /bin/sh
echo pre %foo

%post -p /bin/sh
/usr/bin/update-foo --bar

%preun -p /bin/sh
echo preun
echo more

%postun -p /bin/sh
echo %bar

%triggerin -p /bin/sh -- foo
echo triggerin

%pretrans -p /bin/sh
echo pretrans

%posttrans -p /bin/sh
echo posttrans

%verifyscript -p /bin/sh
echo verifyscript

%filetriggerin -p /bin/sh -- /usr/bin/foo
echo filetriggerin

%transfiletriggerin -p /bin/sh -- /usr/bin/foo
echo transfiletriggerin

%files
EOF

/opt/homebrew/bin/podman run --rm \
  -v "$work/rpmbuild:/rpmbuild:z" \
  registry.opensuse.org/opensuse/tumbleweed:latest \
  bash -c "zypper -n in -y rpm-build >/dev/null 2>&1; rpmbuild --define '_topdir /rpmbuild' --nosignature -bb /rpmbuild/SPECS/fixture.spec" >/dev/null

built="$(find "$work/rpmbuild/RPMS" -name 'postcheck-parity-*.rpm' -print -quit)"
[ -n "$built" ] || { echo "rpmbuild produced no package" >&2; exit 1; }

cp "$built" "$here/"
echo "Wrote $here/$(basename "$built")"
