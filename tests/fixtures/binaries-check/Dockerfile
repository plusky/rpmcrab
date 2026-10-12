# Fixture image for the BinariesCheck test fixture rebuild.
#
# Deliberately NOT pinned: openSUSE re-pushes the snapshot tags in place —
# the 20261003 tag was re-pushed four days after its digest was pinned on
# 2026-10-08 (garbage-collecting the old digest), and the re-pushed tag
# ships no amd64 image at all. Neither a digest pin nor a date tag is a
# stable reference, so use floating tumbleweed:latest; Tumbleweed is rolling
# anyway, and any fixture drift from base-image updates is caught by the
# rebuild-and-compare step.
FROM registry.opensuse.org/opensuse/tumbleweed:latest

RUN zypper -n in -y gcc binutils rpm-build && zypper -n clean -a
