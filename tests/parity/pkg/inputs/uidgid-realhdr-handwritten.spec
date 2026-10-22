Name:           uidgid-realhdr-handwritten
Version:        1.0
Release:        1
Summary:        Real-header non-standard-uid/gid fixture (packager Requires)
License:        MIT
Url:            https://example.org/uidgid-realhdr
BuildArch:      noarch
Requires(pre):  user(hdruser)
Requires(pre):  group(hdrgroup)

%description
Fixture for the non-standard-uid / non-standard-gid decision through
a real RPM header (issue #827): the payload files are owned by the
hdruser user and the hdrgroup group, and the spec declares both
accounts with packager-written Requires(pre) capabilities (the
gromox shape: the accounts are created by a separate provider
package). The header additionally carries rpm's generator stamps
for the same accounts, derived from the file ownership.

%install
mkdir -p %{buildroot}/usr/share/uidgid-realhdr
echo "uid payload" > %{buildroot}/usr/share/uidgid-realhdr/uidfile
echo "gid payload" > %{buildroot}/usr/share/uidgid-realhdr/gidfile

%files
%defattr(-,root,root,-)
%attr(0644,hdruser,root) /usr/share/uidgid-realhdr/uidfile
%attr(0644,root,hdrgroup) /usr/share/uidgid-realhdr/gidfile

%changelog
* Thu Oct 22 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Real-header fixture for the packager-Requires crediting route.
