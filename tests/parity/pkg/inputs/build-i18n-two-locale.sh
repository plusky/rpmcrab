#!/usr/bin/env bash
# Build the i18n-two-locale fixture RPM (Pkg::tag_i18n_str two-locale case).
#
# i18n-two-locale: SUMMARY and DESCRIPTION in two locales (C and de), so the
# header carries a two-entry HEADERI18NTABLE. Exercises tag_i18n_str's
# lang != "C" branch and the i18n-table index mapping over a real package
# header (follow-up to #248; the corpus had no multi-locale package).
#
# Usage: bash tests/parity/pkg/inputs/build-i18n-two-locale.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/parity/pkg/inputs/i18n-two-locale-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}"

cp "$here/i18n-two-locale.spec" "$work/rpmbuild/SPECS/fixture.spec"

"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'zypper -n in -y rpm-build >/dev/null && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/fixture.spec'

find "$work/rpmbuild/RPMS" -name '*.rpm' -exec cp {} "$here/" \;
echo "built: $(ls "$here"/i18n-two-locale-*.rpm)"
