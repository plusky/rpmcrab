Name:           w6-alternatives
Version:        1.0
Release:        1
Summary:        Fixture for AlternativesCheck (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Fixture: a post scriptlet installing an alternative whose binary is not in
the file list.

%install
mkdir -p %{buildroot}/usr/bin
cat > %{buildroot}/usr/bin/w6alt <<'EOF'
#!/bin/sh
echo w6alt
EOF
chmod 755 %{buildroot}/usr/bin/w6alt

%post
update-alternatives --install /usr/bin/w6cmd w6cmd /usr/bin/w6alt 10

%files
%defattr(-,root,root,-)
/usr/bin/w6alt

%changelog
* Thu Oct 01 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for AlternativesCheck.
