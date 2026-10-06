#!/usr/bin/env bash
# Build the tags-emission-pins fixture RPMs (per-finding emission-path tests
# for TagsCheck: one subpackage per mechanically-emitted tag finding).
#
# tags-emission-pins: main package plus subpackages exercising
#   devel-package-with-non-devel-group, no-group-tag, summary-too-long,
#   summary-not-capitalized, summary-ended-with-dot, no-description-tag,
#   description-line-too-long, tag-in-description, spelling-error,
#   obsolete-not-provided, no-pkg-config-provides, summary-on-multiple-lines
#   (via a carriage return in the spec, which rpmbuild preserves and the
#   port treats as a line break). rpmbuild already writes
#   RPMTAG_HEADERI18NTABLE=["C"], which TagsCheck (like the reference)
#   requires before running Summary/Description content checks.
# tags-badversion:   Version 0pre -> invalid-version.
# tags-highepoch:    Epoch 100   -> unreasonable-epoch.
# tags-badchangelog: control character in %changelog ->
#   forbidden-controlchar-found (built from a spec with a literal \x01).
#
# Usage: bash tests/parity/pkg/inputs/build-tags-emission-pins.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image
# Output: tests/parity/pkg/inputs/tags-*.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-tags-emission-pins-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-/opt/homebrew/bin/podman}"
image="${IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}"

for spec in tags-emission-pins tags-badversion tags-highepoch; do
    cp "$here/$spec.spec" "$work/rpmbuild/SPECS/fixture.spec"
    "$podman_bin" run --rm \
        -v "$work/rpmbuild:/rpmbuild:z" \
        "$image" \
        bash -c 'zypper -n in rpm-build >/dev/null && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/fixture.spec'
    find "$work/rpmbuild/RPMS" -name "$spec-*.rpm" -exec cp {} "$here/" \;
    rm -rf "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SRPMS}/*
done

# tags-badchangelog: the spec keeps Name: tags-emission-pins (same name/tags
# as the main package); build it separately and rename the output file.
cp "$here/tags-badchangelog.spec" "$work/rpmbuild/SPECS/fixture.spec"
"$podman_bin" run --rm \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$image" \
    bash -c 'zypper -n in rpm-build >/dev/null && rpmbuild -bb --define "_topdir /rpmbuild" /rpmbuild/SPECS/fixture.spec'
find "$work/rpmbuild/RPMS" -name "tags-emission-pins-1.0-1.noarch.rpm" -exec cp {} "$here/tags-emission-pins-badchangelog-1.0-1.noarch.rpm" \;
rm -rf "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SRPMS}/*
echo "built:"
ls "$here"/tags-emission-pins-*.rpm "$here"/tags-badversion-*.rpm "$here"/tags-highepoch-*.rpm
