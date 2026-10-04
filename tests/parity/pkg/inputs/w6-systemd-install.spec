Name:           w6-systemd-install
Version:        1.0
Release:        1
Summary:        Fixture for SystemdInstallCheck parity case (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Parity fixture exercising SystemdInstallCheck: a unit file whose install
scriptlets call the systemd-update-helper add macros while the preun and
postun scriptlets are absent.

%pre -p /bin/sh
# register the unit on install
systemd-update-helper mark-install-system-units w6si.service

%post -p /bin/sh
# enable the unit on install
systemd-update-helper install-system-units w6si.service

%install
mkdir -p %{buildroot}/usr/lib/systemd/system
cat > %{buildroot}/usr/lib/systemd/system/w6si.service <<'EOF'
[Unit]
Description=W6 systemd-install fixture

[Service]
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
EOF

%files
%defattr(-,root,root,-)
/usr/lib/systemd/system/w6si.service

%changelog
* Sat Oct 03 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for SystemdInstallCheck parity case.
