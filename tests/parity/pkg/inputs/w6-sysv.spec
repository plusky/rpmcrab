Name:           w6-sysv
Version:        1.0
Release:        1
Summary:        Fixture for SysVInitOnSystemdCheck (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Fixture: an /etc/init.d initscript (deprecated-init-script) shadowed by a
systemd unit of the same basename (systemd-shadowed-initscript).

%install
mkdir -p %{buildroot}/etc/init.d %{buildroot}/usr/lib/systemd/system
cat > %{buildroot}/etc/init.d/w6sysv <<'EOF'
#!/bin/sh
# sysv initscript without LSB header
case "$1" in
  start) echo starting ;;
  stop) echo stopping ;;
esac
EOF
chmod 755 %{buildroot}/etc/init.d/w6sysv
cat > %{buildroot}/usr/lib/systemd/system/w6sysv.service <<'EOF'
[Unit]
Description=w6sysv
[Service]
ExecStart=/bin/true
[Install]
WantedBy=multi-user.target
EOF

%files
%defattr(-,root,root,-)
/etc/init.d/w6sysv
/usr/lib/systemd/system/w6sysv.service

%changelog
* Thu Oct 01 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for SysVInitOnSystemdCheck.
