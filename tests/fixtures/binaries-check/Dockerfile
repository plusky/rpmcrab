# Fixture image for the BinariesCheck test fixture rebuild.
#
# The digest pin is the multi-arch manifest list behind the 20261003
# snapshot tag, resolved 2026-10-08 via the registry API
# (Docker-Content-Digest). It must stay a tag-referenced list: a digest
# resolved from floating tumbleweed:latest goes unreferenced when latest
# moves and the registry garbage-collects it, breaking rebuilds.
# Dependabot's docker ecosystem (.github/dependabot.yml) bumps this digest
# monthly; rebuild the fixture against a newer toolchain only when desired.
FROM registry.opensuse.org/opensuse/tumbleweed@sha256:e1f12ceed5df529634484933b3fa837869d981e5081e1fbba47dda5a585367f7

RUN zypper -n in -y gcc binutils rpm-build && zypper -n clean -a
