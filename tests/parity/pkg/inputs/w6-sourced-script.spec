Name:           w6-sourced-script
Version:        1.0
Release:        1
Summary:        Fixture for sourced-script-with-shebang (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Fixture: sourced scripts under /etc/profile.d exercising the
sourced-script analysis --
  w6-shebang.sh: shebang, not executable (sourced-script-with-shebang),
  w6-exec.sh:    shebang and executable (both sourced-script findings),
  w6-clean.sh:   no shebang (silent control),
  w6module.pm:   shebang ignored via the perl-module exception (silent).

%install
mkdir -p %{buildroot}/etc/profile.d
cat > %{buildroot}/etc/profile.d/w6-shebang.sh <<EOF
#!/bin/sh
# w6 fixture: sourced script carrying a shebang
export W6_SOURCED=1
EOF
chmod 644 %{buildroot}/etc/profile.d/w6-shebang.sh
cat > %{buildroot}/etc/profile.d/w6-exec.sh <<EOF
#!/bin/sh
# w6 fixture: executable sourced script carrying a shebang
export W6_EXEC=1
EOF
chmod 755 %{buildroot}/etc/profile.d/w6-exec.sh
cat > %{buildroot}/etc/profile.d/w6-clean.sh <<EOF
# w6 fixture: sourced script without a shebang (control)
export W6_CLEAN=1
EOF
chmod 644 %{buildroot}/etc/profile.d/w6-clean.sh
cat > %{buildroot}/etc/profile.d/w6module.pm <<EOF
#!/usr/bin/perl
# w6 fixture: .pm shebang is ignored (control)
1;
EOF
chmod 644 %{buildroot}/etc/profile.d/w6module.pm

%files
%defattr(-,root,root,-)
/etc/profile.d/w6-shebang.sh
/etc/profile.d/w6-exec.sh
/etc/profile.d/w6-clean.sh
/etc/profile.d/w6module.pm

%changelog
* Mon Oct 05 2026 rpmcrab fixture - 1.0-1
- Fixture for sourced-script-with-shebang.
