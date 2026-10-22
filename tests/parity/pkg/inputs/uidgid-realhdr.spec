Name:           uidgid-realhdr-main
Version:        1.0
Release:        1
Summary:        Real-header non-standard-uid/gid fixture (uncredited owners)
License:        MIT
Url:            https://example.org/uidgid-realhdr
BuildArch:      noarch

%description
Fixture for the non-standard-uid / non-standard-gid decision through
a real RPM header (issue #827): the payload files are owned by the
hdruser user and the hdrgroup group, and no route declares either
account -- no sysusers.d snippet, no user()/group() Provides, no
packager-written Requires. The only account Requires in the header
are the ones rpm's dependency generator derives from the file
ownership itself.

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
- Real-header fixture for the uncredited-owner decision.
