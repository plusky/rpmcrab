#!/usr/bin/env bash
# Build the PostCheck ghost-credit fixture RPMs (local rpmbuild, no container).
#
# postcheck-ghost-posttrans: two %ghost files, no %pre/%post; %posttrans
# creates one of them (ln -sf) and never mentions the other.
# postcheck-ghost-tmpfiles: four %ghost files, no %pre/%post; a shipped
# tmpfiles.d fragment declares two of them (a trailing-slash directory
# line and a file line), carries a glob line matching a third, and never
# mentions the fourth.
#
# Usage: bash tests/parity/pkg/inputs/build-postcheck-ghost-credits.sh
# Needs: rpm-build
# Output: tests/parity/pkg/inputs/postcheck-ghost-posttrans-1.0-1.noarch.rpm
#         tests/parity/pkg/inputs/postcheck-ghost-tmpfiles-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-ghost-credits-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

cat >"$work/rpmbuild/SPECS/posttrans.spec" <<'EOF'
Name:           postcheck-ghost-posttrans
Version:        1.0
Release:        1
Summary:        PostCheck ghost posttrans fixture
License:        MIT
BuildArch:      noarch

%description
Ghost posttrans fixture.

%posttrans -p /bin/sh
ln -sf postcheck-ghost-posttrans-target /etc/postcheck-ghost-posttrans-created

%files
%ghost /etc/postcheck-ghost-posttrans-created
%ghost /etc/postcheck-ghost-posttrans-unmentioned
EOF

cat >"$work/rpmbuild/SOURCES/postcheck-tmpfiles.conf" <<'EOF'
d /run/postcheck-tmpfiles/ 0755 root root -
f /var/lib/postcheck-tmpfiles/state 0644 root root -
d /var/lib/postcheck-tmpfiles/glob* 0755 root root -
EOF

cat >"$work/rpmbuild/SPECS/tmpfiles.spec" <<'EOF'
Name:           postcheck-ghost-tmpfiles
Version:        1.0
Release:        1
Summary:        PostCheck ghost tmpfiles fixture
License:        MIT
BuildArch:      noarch
Source0:        postcheck-tmpfiles.conf

%description
Ghost tmpfiles fixture.

%install
mkdir -p %{buildroot}/usr/lib/tmpfiles.d
cp %{SOURCE0} %{buildroot}/usr/lib/tmpfiles.d/postcheck-tmpfiles.conf

%files
/usr/lib/tmpfiles.d/postcheck-tmpfiles.conf
%dir %ghost /run/postcheck-tmpfiles
%ghost /var/lib/postcheck-tmpfiles/state
%ghost /var/lib/postcheck-tmpfiles/globfile
%ghost /var/lib/postcheck-tmpfiles/unmentioned
EOF

rpmbuild --define "_topdir $work/rpmbuild" --nosignature -bb \
  "$work/rpmbuild/SPECS/posttrans.spec" "$work/rpmbuild/SPECS/tmpfiles.spec"

for n in postcheck-ghost-posttrans postcheck-ghost-tmpfiles; do
  built="$(find "$work/rpmbuild/RPMS" -name "$n-*.rpm" -print -quit)"
  [ -n "$built" ] || { echo "rpmbuild produced no $n package" >&2; exit 1; }
  cp "$built" "$here/"
  echo "Wrote $here/$(basename "$built")"
done
