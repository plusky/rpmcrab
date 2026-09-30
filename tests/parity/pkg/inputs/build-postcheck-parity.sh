#!/usr/bin/env bash
# Build the PostCheck parity-case RPMs.
#
# postcheck-parity: scriptlets exercising the finding families, all 10
# SCRIPT_TAGS entries, and the B3 regex edge cases (braceless %macro,
# single-word vs multi-word commands). The three %triggerin entries form a
# 3-element trigger array whose bodies each trip a different finding family,
# pinning the parallel-array walk (B2); %post is empty to pin empty-%post
# through check_binary; %filetriggerin/%transfiletriggerin carry findings so
# a rename of the tag-table entries changes the name vector.
#
# postcheck-ghost-parity: ghost file with no %pre/%post at all, pinning
# ghost-files-without-postin and postin-without-ghost-file-creation.
#
# Usage: bash tests/parity/pkg/inputs/build-postcheck-parity.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/parity/pkg/inputs/postcheck-parity-1.0-1.noarch.rpm
#         tests/parity/pkg/inputs/postcheck-ghost-parity-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-postcheck-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"

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

%preun -p /bin/sh
echo preun
echo more

%postun -p /bin/sh
echo %bar

%triggerin -p /bin/sh -- foo
echo %trigone

%triggerin -p /bin/sh -- bar
rm -rf /trigtwo

%triggerin -p /bin/sh -- baz
echo hi > /tmp/trigthree

%pretrans -p /bin/sh
echo pretrans

%posttrans -p /bin/sh
echo posttrans

%verifyscript -p /bin/sh
echo verifyscript

%filetriggerin -p /bin/sh -- /usr/bin/foo
echo %filetrig

%transfiletriggerin -p /bin/sh -- /usr/bin/foo
rm -rf /transfiletrig

%files
%ghost /etc/postcheck-parity-ghost
EOF

cat >"$work/rpmbuild/SPECS/ghost.spec" <<'EOF'
Name:           postcheck-ghost-parity
Version:        1.0
Release:        1
Summary:        PostCheck ghost parity fixture
License:        MIT
BuildArch:      noarch

%description
Ghost fixture.

%files
%ghost /etc/postcheck-ghost-parity-ghost
EOF

"$podman_bin" run --rm \
  -v "$work/rpmbuild:/rpmbuild:z" \
  registry.opensuse.org/opensuse/tumbleweed:latest \
  bash -c "zypper -n in -y rpm-build >/dev/null 2>&1; rpmbuild --define '_topdir /rpmbuild' --nosignature -bb /rpmbuild/SPECS/fixture.spec /rpmbuild/SPECS/ghost.spec" >/dev/null

for n in postcheck-parity postcheck-ghost-parity; do
  built="$(find "$work/rpmbuild/RPMS" -name "$n-*.rpm" -print -quit)"
  [ -n "$built" ] || { echo "rpmbuild produced no $n package" >&2; exit 1; }
  cp "$built" "$here/"
  echo "Wrote $here/$(basename "$built")"
done
