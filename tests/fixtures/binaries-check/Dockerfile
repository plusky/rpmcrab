# Fixture image for the BinariesCheck test fixture rebuild.
#
# The digest pin is the multi-arch manifest list of
# registry.opensuse.org/opensuse/tumbleweed, resolved 2026-10-06 via the
# registry API (Docker-Content-Digest), so fixture rebuilds do not drift with
# tumbleweed:latest. Dependabot's docker ecosystem (.github/dependabot.yml)
# bumps this digest monthly; rebuild the fixture against a newer toolchain
# only when desired.
FROM registry.opensuse.org/opensuse/tumbleweed@sha256:a605105aa6647af79bf377259aa5c1e7fbe17850bc9b955b8e6950753d2481b8

RUN zypper -n in -y gcc binutils rpm-build && zypper -n clean -a
