Name:           w6-systemd-alias
Version:        1.0
Release:        1
Summary:        Fixture for SystemdInstallCheck alias handling (rpmcrab #720)
License:        MIT
BuildArch:      noarch

%description
Fixture shaped like wpa_supplicant: a real unit whose scriptlets carry all
four systemd-update-helper calls, plus two D-Bus activation alias symlinks
pointing at it. The aliases are not independent units and must not draw
systemd-service-without-service_* findings.

%pre -p /bin/sh
# register the unit on install
systemd-update-helper mark-install-system-units w720.service

%post -p /bin/sh
# enable the unit on install
systemd-update-helper install-system-units w720.service

%preun -p /bin/sh
# remove the unit on uninstall
systemd-update-helper remove-system-units w720.service

%postun -p /bin/sh
# mark the unit for restart on uninstall
systemd-update-helper mark-restart-system-units w720.service

%install
mkdir -p %{buildroot}/usr/lib/systemd/system
cat > %{buildroot}/usr/lib/systemd/system/w720.service <<'EOF'
[Unit]
Description=W720 systemd alias fixture

[Service]
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
EOF
ln -s w720.service %{buildroot}/usr/lib/systemd/system/dbus-fi.w720.W720One.service
ln -s w720.service %{buildroot}/usr/lib/systemd/system/dbus-org.w720.W720Two.service

%files
%defattr(-,root,root,-)
/usr/lib/systemd/system/w720.service
/usr/lib/systemd/system/dbus-fi.w720.W720One.service
/usr/lib/systemd/system/dbus-org.w720.W720Two.service

%changelog
* Sun Oct 18 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for SystemdInstallCheck alias handling.
