Name:           w6-systemd-tmpfiles
Version:        1.0
Release:        1
Summary:        Fixture for SystemdTmpfilesCheck (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Fixture: a tmpfiles.d drop-in creating a world-writable directory outside
the well-known safe locations (systemd-tmpfile-entry-unauthorized).

%install
mkdir -p %{buildroot}/usr/lib/tmpfiles.d
cat > %{buildroot}/usr/lib/tmpfiles.d/w6st.conf <<'EOF'
d /etc/w6st 0777 root root -
EOF

%files
%defattr(-,root,root,-)
/usr/lib/tmpfiles.d/w6st.conf

%changelog
* Thu Oct 01 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for SystemdTmpfilesCheck.
