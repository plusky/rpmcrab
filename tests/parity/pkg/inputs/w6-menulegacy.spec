Name:           w6-menulegacy
Version:        1.0
Release:        1
Summary:        Fixture for MenuCheck (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Fixture: a legacy window-manager menu file.

%install
mkdir -p %{buildroot}/usr/share/applnk
cat > %{buildroot}/usr/share/applnk/w6legacy.desktop <<'EOF'
[Desktop Entry]
Name=w6legacy
Exec=/usr/bin/w6legacy
Type=Application
Icon=
EOF

%files
%defattr(-,root,root,-)
/usr/share/applnk/w6legacy.desktop

%changelog
* Thu Oct 01 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for MenuCheck.
