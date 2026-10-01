Name:           w6-appdata
Version:        1.0
Release:        1
Summary:        Fixture for AppDataCheck (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Fixture: one valid and one malformed AppStream metadata file.

%install
mkdir -p %{buildroot}/usr/share/appdata
cat > %{buildroot}/usr/share/appdata/w6valid.appdata.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>w6.valid</id>
  <name>W6 Valid</name>
  <summary>Fixture application</summary>
  <description><p>Fixture for AppDataCheck.</p></description>
</component>
EOF
cat > %{buildroot}/usr/share/appdata/w6broken.appdata.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<component><name>Oops</component>
EOF

%files
%defattr(-,root,root,-)
/usr/share/appdata/w6valid.appdata.xml
/usr/share/appdata/w6broken.appdata.xml

%changelog
* Thu Oct 01 2026 rpmcrab fixture - 1.0-1
- Fixture for AppDataCheck.
