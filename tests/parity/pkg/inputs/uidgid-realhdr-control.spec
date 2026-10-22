Name:           uidgid-realhdr-control
Version:        1.0
Release:        1
Summary:        Real-header non-standard-uid/gid fixture (sysusers control)
License:        MIT
Url:            https://example.org/uidgid-realhdr
BuildArch:      noarch

%description
Control fixture for the non-standard-uid / non-standard-gid decision
through a real RPM header (issue #827): the payload files are owned
by the hdruser user and the hdrgroup group, and the package ships
/usr/lib/sysusers.d/uidgid-realhdr.conf declaring both accounts, so
both findings stay quiet.

%install
mkdir -p %{buildroot}/usr/share/uidgid-realhdr
echo "uid payload" > %{buildroot}/usr/share/uidgid-realhdr/uidfile
echo "gid payload" > %{buildroot}/usr/share/uidgid-realhdr/gidfile
mkdir -p %{buildroot}/usr/lib/sysusers.d
printf '%s\n' \
  '# Accounts declared by the uidgid-realhdr control fixture (issue #827).' \
  'g hdrgroup 12348' \
  'u hdruser 12347:12348 "uidgid-realhdr fixture user" /var/lib/hdruser -' \
  > %{buildroot}/usr/lib/sysusers.d/uidgid-realhdr.conf

%files
%defattr(-,root,root,-)
%attr(0644,hdruser,root) /usr/share/uidgid-realhdr/uidfile
%attr(0644,root,hdrgroup) /usr/share/uidgid-realhdr/gidfile
/usr/lib/sysusers.d/uidgid-realhdr.conf

%changelog
* Thu Oct 22 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Real-header control fixture for the sysusers crediting route.
