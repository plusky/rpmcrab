Name:           dangling-lone
Version:        1.0
Release:        1
Summary:        Session-aware dangling-relative-symlink fixture (lone package)
License:        MIT
BuildArch:      noarch

%description
Fixture for the session-aware dangling-relative-symlink decision
(issue #547): a single package whose relative symlinks stay dangling
in any run. One link carries a build-host target (the gfxboot shape:
the intended in-package target ships alongside, the link points at a
/home/abuild path instead). One link's target matches the
consolehelper DanglingSymlinkExceptions entry. One link points at a
directory shipped by the same package (quiet), and one root-level
link points at the same directory (the class-F parity shape: the
normalised target keeps a double leading slash and never matches).

%build
echo "logo payload" > logo.txt
echo "data payload" > data.txt

%install
mkdir -p %{buildroot}/usr/share/dangling-lone/themes/openSUSE/links
cp logo.txt %{buildroot}/usr/share/dangling-lone/themes/openSUSE/logo.txt
ln -s ../../../../../../home/abuild/rpmbuild/BUILD/dangling-lone/themes/openSUSE/logo.txt %{buildroot}/usr/share/dangling-lone/themes/openSUSE/links/logo.txt
mkdir -p %{buildroot}/usr/bin
ln -s ../sbin/consolehelper %{buildroot}/usr/bin/dangling-lone-helper
mkdir -p %{buildroot}/usr/share/dangling-lone/sub
cp data.txt %{buildroot}/usr/share/dangling-lone/sub/data.txt
ln -s sub %{buildroot}/usr/share/dangling-lone/dir-link
ln -s usr/share/dangling-lone/sub %{buildroot}/lone-root-link

%files
%defattr(-,root,root,-)
/usr/share/dangling-lone/themes/openSUSE/logo.txt
/usr/share/dangling-lone/themes/openSUSE/links/logo.txt
/usr/bin/dangling-lone-helper
/usr/share/dangling-lone/sub/data.txt
%dir /usr/share/dangling-lone/sub
/usr/share/dangling-lone/dir-link
/lone-root-link

%changelog
* Thu Oct 15 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Lone fixture for the dangling-relative-symlink session decision.
