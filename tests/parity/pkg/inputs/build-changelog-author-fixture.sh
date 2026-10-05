#!/usr/bin/env bash
# Build the changelog-author-fixture RPM (bot/invalid changelog authors).
#
# changelog-author-fixture: %changelog exercising TagsCheck's
# invalid-changelog-author (upstream rpmlint#180) end to end through a real
# RPM header --
#   * openSUSE Packaging <opensuse-packaging@opensuse.org> (must warn)
#   * Example Bot <bot@example.com> (must warn, .*@example\\.com default)
#   * Tomas Chvatal <tomas.chvatal@gmail.com> (must stay quiet)
#
# Usage: bash tests/parity/pkg/inputs/build-changelog-author-fixture.sh
# Needs: rpmbuild (Mac: /opt/homebrew/bin/rpmbuild). The homebrew rpmbuild
# needs an explicit writable _tmppath: its default %{_var}/tmp is not
# writable on macOS.
# Output: tests/parity/pkg/inputs/changelog-author-fixture-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-changelog-author-work"
rm -rf "$work"
mkdir -p "$work"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,tmp}

cp "$here/changelog-author-fixture.spec" "$work/SPECS/fixture.spec"

rpmbuild -bb \
    --define "_topdir $work" \
    --define "_tmppath $work/tmp" \
    "$work/SPECS/fixture.spec"

find "$work/RPMS" -name '*.rpm' -exec cp {} "$here/" \;
echo "built: $(ls "$here"/changelog-author-fixture-*.rpm)"
