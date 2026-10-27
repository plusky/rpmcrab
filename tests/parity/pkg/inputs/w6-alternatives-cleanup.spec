Name:           w6-alternatives-cleanup
Version:        1.0
Release:        1
Summary:        Fixture for AlternativesCheck cleanup-only scriptlets (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Fixture: a package whose scriptlets only remove legacy
update-alternatives registrations (the post-libalternatives cleanup
shape). It registers nothing and ships no /etc/alternatives entry, so
the package-supports-update-alternatives marker must not fire, while
the error findings for the missing registration still do.

%install
mkdir -p %{buildroot}/usr/bin
cat > %{buildroot}/usr/bin/w6gone-1.0 <<'EOF'
#!/bin/sh
echo w6gone
EOF
chmod 755 %{buildroot}/usr/bin/w6gone-1.0

%post
if [ -x /usr/sbin/update-alternatives ]; then
  update-alternatives --display w6gone >/dev/null 2>&1 && update-alternatives --remove-all w6gone
fi

%postun
update-alternatives --remove w6gone /usr/bin/w6gone-1.0

%files
%defattr(-,root,root,-)
/usr/bin/w6gone-1.0

%changelog
* Tue Oct 27 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for AlternativesCheck cleanup-only scriptlets.
