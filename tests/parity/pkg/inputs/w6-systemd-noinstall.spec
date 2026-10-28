Name:           w6-systemd-noinstall
Version:        1.0
Release:        1
Summary:        Fixture for SystemdInstallCheck del_preun credits
License:        MIT
BuildArch:      noarch

%description
Fixture for the del_preun-only credits: w6ni.service ships no
[Install] section and w6wi.service ships one; both have their add
macros in %pre/%post while %preun/%postun are absent.

%pre -p /bin/sh
systemd-update-helper mark-install-system-units w6ni.service w6wi.service

%post -p /bin/sh
systemd-update-helper install-system-units w6ni.service w6wi.service

%install
mkdir -p %{buildroot}/usr/lib/systemd/system
cat > %{buildroot}/usr/lib/systemd/system/w6ni.service <<'EOF'
[Unit]
Description=W6 no-install fixture unit

[Service]
Type=oneshot
ExecStart=/bin/true
EOF
cat > %{buildroot}/usr/lib/systemd/system/w6wi.service <<'EOF'
[Unit]
Description=W6 with-install fixture unit

[Service]
Type=oneshot
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
EOF

%files
%defattr(-,root,root,-)
/usr/lib/systemd/system/w6ni.service
/usr/lib/systemd/system/w6wi.service

%changelog
* Wed Oct 28 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for SystemdInstallCheck del_preun credits.
