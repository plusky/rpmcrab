#!/usr/bin/env bash
# Build the tags-emission-pins fixture RPMs reproducibly (per-finding
# emission-path tests for TagsCheck: one subpackage per mechanically-emitted
# tag finding).
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
# Reproducibility contract -- re-running this script yields byte-identical
# RPMs:
# - IMAGE_PIN: the container image is pinned by digest (immutable); the
#   script pulls that exact digest, failing loudly if it ever disappears.
# - rpm-build and libfaketime are pinned to exact versions; zypper fails
#   loudly if a pinned version ever leaves the Leap 16.0 GA repos, so a
#   rebuild can never silently pick up a different toolchain.
# - The build clock is frozen at BUILD_EPOCH via libfaketime: rpmbuild
#   hardcodes time(NULL) into RPMTAG_BUILDTIME and rpm 4.20 honors neither
#   SOURCE_DATE_EPOCH nor RPM_BUILD_TIME for it. Only rpmbuild runs under
#   faketime -- zypper keeps real time so TLS stays valid. libfaketime does
#   not fake stat() mtimes, so the spec clamps payload mtimes explicitly
#   (see the build_epoch conditional in %install).
# - The container hostname is fixed: rpmbuild records gethostname() in
#   RPMTAG_BUILDHOST.
# - optflags is pinned to "-O2 -g" via %define in each spec file: the
#   arch-specific platform macros shipped by rpm-build differ by
#   architecture (x86_64 gains -m64 and the SUSE hardening flags), which
#   would otherwise leak into RPMTAG_OPTFLAGS. Neither a command-line
#   --define nor /etc/rpm/macros.d nor ~/.rpmmacros overrides it for the
#   header (verified 2026-10-06); only a %define in the spec itself wins.
# - The payload compressor is pinned to single-threaded zstd
#   (_binary_payload w19T1.zstdio): multithreaded zstd framing can vary
#   with the build environment.
# - Provenance: tags-emission-pins.provenance records the pins plus the
#   sha256 of every fixture RPM, so drift is detectable by rebuilding.
#
# Usage: bash tests/parity/pkg/inputs/build-tags-emission-pins.sh [--check]
#   --check: rebuild into a temp dir and diff against the checked-in
#            fixtures instead of replacing them (CI drift check).
# Needs: podman (or PODMAN=/path/to/podman)
# Output: tests/parity/pkg/inputs/tags-*.rpm (+ .provenance unless --check)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
provenance="$here/tags-emission-pins.provenance"

IMAGE_PIN="registry.opensuse.org/opensuse/leap:16.0@sha256:cd9aac11608afabc96a10074619cf2a65ccf60ff4b72d09d4e4e125af409035d"
RPMBUILD_VERSION="4.20.1-160000.3.1"
FAKETIME_VERSION="0.9.10-bp160.1.10"
BUILD_EPOCH="1791216052" # 2026-10-05 16:00:52 UTC, when the fixtures were first built
BUILD_DATE="2026-10-05 16:00:52" # UTC rendering of BUILD_EPOCH, libfaketime format
BUILD_HOSTNAME="fixture-build"

check_only=0
if [ "${1:-}" = "--check" ]; then
    check_only=1
fi

podman_bin="${PODMAN:-$(command -v podman 2>/dev/null || echo /opt/homebrew/bin/podman)}"
# Extra podman args, e.g. PODMAN_ARCH="--arch amd64" to verify the
# fixtures are byte-identical across architectures (default: host arch).
podman_arch="${PODMAN_ARCH:-}"

work="$(mktemp -d "${TMPDIR:-/tmp}/rpmbuild-tags-emission-pins.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
outdir="$here"
if [ "$check_only" -eq 1 ]; then
    outdir="$work/out"
    mkdir -p "$outdir"
fi

"$podman_bin" pull "$IMAGE_PIN" >/dev/null

# The container-side build snippet. Built via heredoc so the local pins
# expand here while the container-side $ft reference stays literal.
# Kept in one variable so all four build sites stay identical.
container_build="$(cat <<EOF
set -e
zypper -n -q in 'rpm-build = $RPMBUILD_VERSION' 'libfaketime = $FAKETIME_VERSION' >/dev/null
ft=/usr/lib64/libfaketime/libfaketime.so.1
test -f "\$ft"
LD_PRELOAD="\$ft" FAKETIME="$BUILD_DATE" DONT_FAKE_MONOTONIC=1 FAKETIME_NO_CACHE=1 \\
    rpmbuild -bb --define "_topdir /rpmbuild" --define "build_epoch $BUILD_EPOCH" --define "_binary_payload w19T1.zstdio" \\
    /rpmbuild/SPECS/fixture.spec
EOF
)"

build_one() { # $1 = spec basename (without .spec)
    local spec="$1"
    cp "$here/$spec.spec" "$work/rpmbuild/SPECS/fixture.spec"
    "$podman_bin" run --rm \
        ${podman_arch} \
        --hostname "$BUILD_HOSTNAME" \
        -v "$work/rpmbuild:/rpmbuild:z" \
        "$IMAGE_PIN" \
        bash -c "$container_build"
    find "$work/rpmbuild/RPMS" -name "$spec-*.rpm" -exec cp {} "$outdir/" \;
    rm -rf "$work/rpmbuild"/BUILD/* "$work/rpmbuild"/RPMS/* \
           "$work/rpmbuild"/SOURCES/* "$work/rpmbuild"/SRPMS/*
}

build_one tags-emission-pins
build_one tags-badversion
build_one tags-highepoch
# tags-badchangelog: the spec keeps Name: tags-emission-pins (same name/tags
# as the main package); build it separately and rename the output file.
cp "$here/tags-badchangelog.spec" "$work/rpmbuild/SPECS/fixture.spec"
"$podman_bin" run --rm \
    ${podman_arch} \
    --hostname "$BUILD_HOSTNAME" \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$IMAGE_PIN" \
    bash -c "$container_build"
find "$work/rpmbuild/RPMS" -name "tags-emission-pins-1.0-1.noarch.rpm" \
    -exec cp {} "$outdir/tags-emission-pins-badchangelog-1.0-1.noarch.rpm" \;

if [ "$check_only" -eq 1 ]; then
    # Drift check: every rebuilt RPM must match the provenance hashes.
    fails=0
    while read -r hash file; do
        case "$hash" in \#*|"") continue ;; esac
        if [ ! -f "$outdir/$file" ]; then
            echo "MISSING: $file was not rebuilt"; fails=1; continue
        fi
        actual="$(sha256sum "$outdir/$file" | cut -d' ' -f1)"
        if [ "$actual" != "$hash" ]; then
            echo "DRIFT: $file"
            echo "  provenance: $hash"
            echo "  rebuilt:    $actual"
            fails=1
        fi
    done < <(sed -n '/^sha256:$/,$p' "$provenance" | tail -n +2)
    if [ "$fails" -eq 0 ]; then
        echo "fixture drift check: all RPMs byte-identical to provenance"
    else
        echo "fixture drift check: FAILED" >&2
        exit 1
    fi
    exit 0
fi

{
    echo "# Provenance for the tags-emission-pins fixture RPMs."
    echo "# Rebuild byte-identical copies with:"
    echo "#   bash tests/parity/pkg/inputs/build-tags-emission-pins.sh"
    echo "# Verify with:"
    echo "#   bash tests/parity/pkg/inputs/build-tags-emission-pins.sh --check"
    echo "image: $IMAGE_PIN"
    echo "rpm-build: $RPMBUILD_VERSION"
    echo "libfaketime: $FAKETIME_VERSION"
    echo "build_epoch: $BUILD_EPOCH"
    echo "build_hostname: $BUILD_HOSTNAME"
    echo "sha256:"
    ( cd "$here" && sha256sum tags-emission-pins-1.0-1.noarch.rpm \
        tags-emission-pins-badchangelog-1.0-1.noarch.rpm \
        tags-emission-pins-badsummary-1.0-1.noarch.rpm \
        tags-emission-pins-devel-1.0-1.noarch.rpm \
        tags-emission-pins-longdesc-1.0-1.noarch.rpm \
        tags-emission-pins-longsummary-1.0-1.noarch.rpm \
        tags-emission-pins-multiline-1.0-1.noarch.rpm \
        tags-emission-pins-nodesc-1.0-1.noarch.rpm \
        tags-emission-pins-nogroup-1.0-1.noarch.rpm \
        tags-emission-pins-obsolete-1.0-1.noarch.rpm \
        tags-emission-pins-pcreq-devel-1.0-1.noarch.rpm \
        tags-emission-pins-spell-1.0-1.noarch.rpm \
        tags-emission-pins-tagdesc-1.0-1.noarch.rpm \
        tags-badversion-0pre-1.noarch.rpm \
        tags-highepoch-1.0-1.noarch.rpm )
} > "$provenance"
echo "built:"
ls "$here"/tags-emission-pins-*.rpm "$here"/tags-badversion-*.rpm "$here"/tags-highepoch-*.rpm
