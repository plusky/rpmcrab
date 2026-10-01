Name:           w6-menu
Version:        1.0
Release:        1
Summary:        Fixture for MenuXDGCheck (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Fixture: a desktop file whose Exec points at a binary not shipped in the
package (desktopfile-without-binary).

%install
mkdir -p %{buildroot}/usr/share/applications
cat > %{buildroot}/usr/share/applications/w6.desktop <<'EOF'
[Desktop Entry]
Name=w6menu
Exec=/usr/bin/w6-missing-binary
Type=Application
EOF

%files
%defattr(-,root,root,-)
/usr/share/applications/w6.desktop

%changelog
* Thu Oct 01 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for MenuXDGCheck.
