Name:           w6-bashisms
Version:        1.0
Release:        1
Summary:        Fixture for BashismsCheck (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Fixture: a /bin/sh script using [[ ]] (potential-bashisms) and a clean
POSIX script.

%install
mkdir -p %{buildroot}/usr/bin
cat > %{buildroot}/usr/bin/w6bashism <<'EOF'
#!/bin/sh
# w6 fixture: [[ ]] is a bashism, not POSIX sh
if [[ -n "$HOME" ]]; then
    echo "home is set"
fi
EOF
chmod 755 %{buildroot}/usr/bin/w6bashism
cat > %{buildroot}/usr/bin/w6clean <<'EOF'
#!/bin/sh
# w6 fixture: clean POSIX shell
echo "clean"
EOF
chmod 755 %{buildroot}/usr/bin/w6clean

%files
%defattr(-,root,root,-)
/usr/bin/w6bashism
/usr/bin/w6clean

%changelog
* Thu Oct 01 2026 rpmcrab fixture - 1.0-1
- Fixture for BashismsCheck.
