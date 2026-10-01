Name:           w6-filelist
Version:        1.0
Release:        1
Summary:        Fixture for FilelistCheck (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Fixture: files in FHS-discouraged locations matching the absolute Bad patterns
/usr/local/man/*/* and /var/lib/games/*.

%install
mkdir -p %{buildroot}/usr/local/man/man1
cat > %{buildroot}/usr/local/man/man1/w6.1 <<'EOF'
.TH W6 1
.SH NAME
w6 \- fixture manual page
EOF
mkdir -p %{buildroot}/var/lib/games
cat > %{buildroot}/var/lib/games/w6.scores <<'EOF'
fixture
EOF

%files
%defattr(-,root,root,-)
/usr/local/man/man1/w6.1
/var/lib/games/w6.scores

%changelog
* Thu Oct 01 2026 rpmcrab fixture - 1.0-1
- Fixture for FilelistCheck.
