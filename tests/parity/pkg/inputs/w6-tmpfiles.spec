Name:           w6-tmpfiles
Version:        1.0
Release:        1
Summary:        Fixture for SystemdTmpfilesCheck (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Fixture: a tmpfiles.d drop-in with entries the reference flags.

%install
mkdir -p %{buildroot}/usr/lib/tmpfiles.d
cat > %{buildroot}/usr/lib/tmpfiles.d/w6.conf <<'EOF'
d /run/w6tmp 0755 root root -
f /run/w6tmp/file 0644 root root - some content
EOF

%files
%defattr(-,root,root,-)
/usr/lib/tmpfiles.d/w6.conf

%changelog
* Thu Oct 01 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for SystemdTmpfilesCheck.
