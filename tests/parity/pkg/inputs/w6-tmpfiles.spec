Name:           w6-tmpfiles
Version:        1.0
Release:        1
Summary:        Fixture for TmpFilesCheck parity case (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Parity fixture for TmpFilesCheck: a tmpfiles.d drop-in with entries the
reference flags (tmpfile-not-in-filelist) plus one clean entry.

%install
mkdir -p %{buildroot}/usr/lib/tmpfiles.d
cat > %{buildroot}/usr/lib/tmpfiles.d/test.conf <<'EOF'
d /run/w6tmp 0755 root root -
f /run/w6tmp/file 0644 root root - some content
r /run/w6clean -
EOF

%files
%defattr(-,root,root,-)
/usr/lib/tmpfiles.d/test.conf

%changelog
* Sat Oct 03 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for TmpFilesCheck parity case.
