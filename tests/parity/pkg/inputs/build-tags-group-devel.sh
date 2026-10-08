#!/usr/bin/env bash
# Build the tags-group-devel fixture RPM reproducibly: a -devel package
# outside any Development/ group, for the stays-quiet pin on the deleted
# devel-package-with-non-devel-group finding.
#
# Reproducibility contract -- re-running this script yields a byte-identical
# RPM (same pins as build-tags-emission-pins.sh):
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
# - optflags is pinned to "-O2 -g" via %define in the spec file: the
#   arch-specific platform macros shipped by rpm-build differ by
#   architecture (x86_64 gains -m64 and the SUSE hardening flags), which
#   would otherwise leak into RPMTAG_OPTFLAGS. Neither a command-line
#   --define nor /etc/rpm/macros.d nor ~/.rpmmacros overrides it for the
#   header (verified 2026-10-06); only a %define in the spec itself wins.
# - The payload compressor is pinned to single-threaded zstd
#   (_binary_payload w19T1.zstdio): multithreaded zstd framing can vary
#   with the build environment.
# - Provenance: tags-group-devel.provenance records the pins plus the
#   sha256 of the fixture RPM, so drift is detectable by rebuilding.
#
# Usage: bash tests/parity/pkg/inputs/build-tags-group-devel.sh [--check]
#   --check: rebuild into a temp dir and diff against the checked-in
#            fixture instead of replacing it (CI drift check).
# Needs: podman (or PODMAN=/path/to/podman)
# Output: tests/parity/pkg/inputs/tags-group-devel-1.0-1.noarch.rpm
#         (+ .provenance unless --check)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
provenance="$here/tags-group-devel.provenance"

IMAGE_PIN="registry.opensuse.org/opensuse/leap:16.0@sha256:cd9aac11608afabc96a10074619cf2a65ccf60ff4b72d09d4e4e125af409035d"
RPMBUILD_VERSION="4.20.1-160000.3.1"
FAKETIME_VERSION="0.9.10-bp160.1.10"
BUILD_EPOCH="1791216052" # 2026-10-05 16:00:52 UTC, matching the tags-emission-pins fixtures
BUILD_DATE="2026-10-05 16:00:52" # UTC rendering of BUILD_EPOCH, libfaketime format
BUILD_HOSTNAME="fixture-build"

check_only=0
if [ "${1:-}" = "--check" ]; then
    check_only=1
fi

podman_bin="${PODMAN:-$(command -v podman 2>/dev/null || echo /opt/homebrew/bin/podman)}"
podman_arch="${PODMAN_ARCH:-}"

work="$(mktemp -d "${TMPDIR:-/tmp}/rpmbuild-tags-group-devel.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
outdir="$here"
if [ "$check_only" -eq 1 ]; then
    outdir="$work/out"
    mkdir -p "$outdir"
fi

"$podman_bin" pull "$IMAGE_PIN" >/dev/null

cp "$here/tags-group-devel.spec" "$work/rpmbuild/SPECS/fixture.spec"
"$podman_bin" run --rm \
    ${podman_arch} \
    --hostname "$BUILD_HOSTNAME" \
    -v "$work/rpmbuild:/rpmbuild:z" \
    "$IMAGE_PIN" \
    bash -c "set -e
zypper -n -q in 'rpm-build = $RPMBUILD_VERSION' 'libfaketime = $FAKETIME_VERSION' >/dev/null
ft=/usr/lib64/libfaketime/libfaketime.so.1
test -f \"\$ft\"
LD_PRELOAD=\"\$ft\" FAKETIME=\"$BUILD_DATE\" DONT_FAKE_MONOTONIC=1 FAKETIME_NO_CACHE=1 \\
    rpmbuild -bb --define \"_topdir /rpmbuild\" --define \"build_epoch $BUILD_EPOCH\" --define \"_binary_payload w19T1.zstdio\" \\
    /rpmbuild/SPECS/fixture.spec"
rpm="tags-group-devel-1.0-1.noarch.rpm"
find "$work/rpmbuild/RPMS" -name "$rpm" -exec cp {} "$outdir/" \;

if [ "$check_only" -eq 1 ]; then
    expected="$(sed -n 's/^sha256: //p' "$provenance" | tail -n 1)"
    actual="$(sha256sum "$outdir/$rpm" | cut -d' ' -f1)"
    if [ "$actual" = "$expected" ]; then
        echo "fixture drift check: $rpm byte-identical to provenance"
    else
        echo "fixture drift check: FAILED" >&2
        echo "  provenance: $expected" >&2
        echo "  rebuilt:    $actual" >&2
        exit 1
    fi
    exit 0
fi

{
    echo "# Provenance for the tags-group-devel fixture RPM."
    echo "# Rebuild a byte-identical copy with:"
    echo "#   bash tests/parity/pkg/inputs/build-tags-group-devel.sh"
    echo "# Verify with:"
    echo "#   bash tests/parity/pkg/inputs/build-tags-group-devel.sh --check"
    echo "image: $IMAGE_PIN"
    echo "rpm-build: $RPMBUILD_VERSION"
    echo "libfaketime: $FAKETIME_VERSION"
    echo "build_epoch: $BUILD_EPOCH"
    echo "build_hostname: $BUILD_HOSTNAME"
    echo "sha256: $(cd "$here" && sha256sum "$rpm" | cut -d' ' -f1)"
} > "$provenance"
echo "built: $here/$rpm"
