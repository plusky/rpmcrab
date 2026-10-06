#!/usr/bin/env bash
# Build the two-locale i18n fixture.
#
# A minimal noarch RPM whose header carries a multi-entry HEADERI18NTABLE
# (locales "C" and "de"): the Summary(de): entry and the %description -l de
# section make rpmbuild store SUMMARY and DESCRIPTION as two-element
# I18NSTRING arrays. The tag_i18n_str unit test in
# crates/rpmcrab-core/src/pkg/mod.rs pins the lang != "C" branch and the
# index mapping from the locale table into the raw i18n array against this
# fixture (plusky's #248 review: the corpus never exercises a multi-locale
# package, so this is the missing piece).
#
# Usage: bash tests/fixtures/i18n-two-locale/build.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/fixtures/i18n-two-locale/input/rpmcrab-i18n-two-locale-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-i18n-two-locale-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"

cat >"$work/rpmbuild/SPECS/fixture.spec" <<'EOF'
Name:           rpmcrab-i18n-two-locale
Version:        1.0
Release:        1
Summary:        English summary of the two-locale fixture
Summary(de):    Deutsche Zusammenfassung des Zwei-Sprachen-Fixtures
License:        MIT
BuildArch:      noarch

%description
English description of the two-locale fixture.

%description -l de
Deutsche Beschreibung des Zwei-Sprachen-Fixtures.

%install
mkdir -p %{buildroot}/usr/share/rpmcrab-i18n
echo fixture > %{buildroot}/usr/share/rpmcrab-i18n/placeholder.txt

%files
/usr/share/rpmcrab-i18n
EOF

"$podman_bin" run --rm \
  -v "$work/rpmbuild:/rpmbuild:z" \
  registry.opensuse.org/opensuse/tumbleweed:latest \
  bash -c "zypper -n in -y rpm-build >/dev/null 2>&1; rpmbuild --define '_topdir /rpmbuild' --nosignature -bb /rpmbuild/SPECS/fixture.spec" >/dev/null

built="$(find "$work/rpmbuild/RPMS" -name 'rpmcrab-i18n-two-locale-*.noarch.rpm' -print -quit)"
[ -n "$built" ] || { echo "rpmbuild produced no package" >&2; exit 1; }
mkdir -p "$here/input"
cp "$built" "$here/input/"
echo "Wrote $here/input/$(basename "$built")"
