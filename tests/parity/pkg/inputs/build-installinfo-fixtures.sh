#!/usr/bin/env bash
# Build the install-info scriptlet fixtures.
#
# Two noarch RPMs, each shipping /usr/share/info/foo.info:
#   filescheck-installinfo-nopostin  - no %post scriptlet at all
#       (expects E info-files-without-install-info-postin);
#       carries a %postun with an install-info call so the postun
#       finding stays silent.
#   filescheck-installinfo-nopostun  - %post with an install-info call,
#       but neither %postun nor %preun
#       (expects E info-files-without-install-info-postun).
#
# Usage: bash tests/parity/pkg/inputs/build-installinfo-fixtures.sh
# Needs: podman, an openSUSE container image with rpm-build
# Output: tests/parity/pkg/inputs/filescheck-installinfo-nopostin-1.0-1.noarch.rpm
#         tests/parity/pkg/inputs/filescheck-installinfo-nopostun-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-fixture-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

build_one() {
    local name="$1" post="$2" postun="$3"
    cat >"$work/rpmbuild/SPECS/fixture.spec" <<EOF
Name:           $name
Version:        1.0
Release:        1
Summary:        Fixture for install-info scriptlet checks
License:        MIT
BuildArch:      noarch
# Keep the info file uncompressed: __os_install_post runs brp-compress,
# which would rename it to foo.info.gz and the %files entry would miss.
%define __os_install_post %{nil}

%description
Fixture.

$post
$postun

%install
mkdir -p %{buildroot}/usr/share/info
echo "dummy info file" > %{buildroot}/usr/share/info/foo.info

%files
/usr/share/info/foo.info
EOF
    podman() { /opt/homebrew/bin/podman "$@"; }
    podman run --rm \
        -v "$work/rpmbuild:/rpmbuild:z" \
        registry.opensuse.org/opensuse/tumbleweed:latest \
        bash -c "zypper -n in -y rpm-build >/dev/null 2>&1; rpmbuild --define '_topdir /rpmbuild' --nosignature -bb /rpmbuild/SPECS/fixture.spec" >/dev/null
    local built
    built="$(find "$work/rpmbuild/RPMS" -name "$name-*.rpm" -print -quit)"
    [ -n "$built" ] || { echo "rpmbuild produced no package for $name" >&2; exit 1; }
    cp "$built" "$here/"
    echo "Wrote $here/$(basename "$built")"
    rm -rf "$work/rpmbuild"/{BUILD,RPMS}/*
}

post_with_install_info='%post
/sbin/install-info /usr/share/info/foo.info /usr/share/info/dir || :'
postun_with_install_info='%postun
/sbin/install-info --delete /usr/share/info/foo.info /usr/share/info/dir || :'

build_one filescheck-installinfo-nopostin "" "$postun_with_install_info"
build_one filescheck-installinfo-nopostun "$post_with_install_info" ""
