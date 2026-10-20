#!/usr/bin/env bash
# Build the AtomicUpdateCheck scriptlet-scan fixtures (issue #708).
#
# atomic-scriptlet-fires: install scriptlets whose literal write targets
# are outside the snapshot, one firing class per slot (mkdir, redirect,
# install -d, quoted mkdir, rm, cp destination). Ships one allowed file
# so the payload findings stay quiet and only the scriptlet finding
# fires.
#
# atomic-scriptlet-clean: the near-miss negatives -- a lua scriptlet
# whose body is a bare shell write line (only the interpreter gate
# keeps it quiet), a prog-only ldconfig scriptlet,
# commented/quoted/heredoc lookalikes, transient targets
# (/var/run is /run, /var/lock is /run/lock), an inside destination
# fed from an outside source, and dynamic targets (a variable target
# and an absolute path with a dynamic suffix). Must produce no
# findings at all.
#
# Usage: bash tests/parity/pkg/inputs/build-atomic-scriptlet-parity.sh
# Needs: podman (or PODMAN=/path/to/podman), an openSUSE container image with rpm-build
# Output: tests/parity/pkg/inputs/atomic-scriptlet-fires-1.0-1.noarch.rpm
#         tests/parity/pkg/inputs/atomic-scriptlet-clean-1.0-1.noarch.rpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/.rpmbuild-atomic-scriptlet-work"
rm -rf "$work"
mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

podman_bin="${PODMAN:-podman}"

cat >"$work/rpmbuild/SPECS/fires.spec" <<'EOF'
Name:           atomic-scriptlet-fires
Version:        1.0
Release:        1
Summary:        AtomicUpdateCheck scriptlet-scan firing fixture
License:        MIT
BuildArch:      noarch

%description
Fixture.

%install
mkdir -p %{buildroot}/usr/share/atomic-fixture
echo default > %{buildroot}/usr/share/atomic-fixture/default

%pre
mkdir -p /var/lib/atomic-fixture

%post
echo seed > /srv/atomic-fixture/seed.conf
install -d /var/cache/atomic-fixture
mkdir "/var/lib/atomic-fixture/quoted"

%postun
rm -f /var/lib/atomic-fixture/state

%posttrans
cp /usr/share/atomic-fixture/default /opt/atomic-fixture.conf

%files
/usr/share/atomic-fixture/default
EOF

cat >"$work/rpmbuild/SPECS/clean.spec" <<'EOF'
Name:           atomic-scriptlet-clean
Version:        1.0
Release:        1
Summary:        AtomicUpdateCheck scriptlet-scan near-miss fixture
License:        MIT
BuildArch:      noarch

%description
Fixture.

%install
mkdir -p %{buildroot}/usr/share/atomic-fixture
echo default > %{buildroot}/usr/share/atomic-fixture/default

%pre -p /usr/bin/lua
mkdir /var/lib/lua-target

%post
# mkdir /var/lib/commented
echo 'write > /var/lib/quoted-text by hand'
cat > /etc/atomic-fixture.conf <<'INNER'
mkdir /var/lib/heredoc-target
INNER
mkdir -p /usr/share/atomic-fixture
echo ok > /dev/null
touch /var/run/atomic-fixture.flag
touch /var/lock/atomic-fixture.lock
echo note > /var/adm/update-messages/atomic-fixture-1.0-1-notify
/usr/bin/systemd-tmpfiles --create /usr/lib/tmpfiles.d/atomic-fixture.conf || :
cp /var/lib/upstream-source /usr/share/atomic-fixture/dest
DEST=/var/lib/dynamic
mkdir $DEST/sub
mkdir /var/lib/$SUFFIX

%preun
rm -f /var/run/atomic-fixture.flag

%postun -p /sbin/ldconfig

%files
/usr/share/atomic-fixture/default
EOF

# Both specs build in a single container run (one zypper install).
"$podman_bin" run --rm \
  -v "$work/rpmbuild:/rpmbuild:z" \
  registry.opensuse.org/opensuse/tumbleweed:latest \
  bash -c "zypper -n in -y rpm-build >/dev/null 2>&1; rpmbuild --define '_topdir /rpmbuild' --nosignature -bb /rpmbuild/SPECS/fires.spec; rpmbuild --define '_topdir /rpmbuild' --nosignature -bb /rpmbuild/SPECS/clean.spec" >/dev/null
for spec in fires clean; do
  built="$(find "$work/rpmbuild/RPMS" -name "atomic-scriptlet-$spec-*.rpm" -print -quit)"
  [ -n "$built" ] || { echo "rpmbuild produced no package for $spec" >&2; exit 1; }
  cp "$built" "$here/"
  echo "Wrote $here/$(basename "$built")"
done
