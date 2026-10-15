Name:           dangling-session-main
Version:        1.0
Release:        1
Summary:        Session-aware dangling-relative-symlink fixture (main package)
License:        MIT
BuildArch:      noarch

%description
Fixture for the session-aware dangling-relative-symlink decision
(issue #547): the main package ships the figure file, the -lang
subpackage links to it relatively. Both are built from this one spec,
so the link must stay quiet when the two are linted in one run and
fire when the -lang package is linted alone.

%package -n dangling-session-lang
Summary:        Session-aware dangling-relative-symlink fixture (lang subpackage)

%description -n dangling-session-lang
Lang subpackage of the dangling-relative-symlink session fixture:
its only payload is a relative symlink to a figure shipped by the
main package.

%build
echo "figure payload" > figure.txt

%install
mkdir -p %{buildroot}/usr/share/dangling-session/C
cp figure.txt %{buildroot}/usr/share/dangling-session/C/figure.txt
mkdir -p %{buildroot}/usr/share/dangling-session/de
ln -s ../C/figure.txt %{buildroot}/usr/share/dangling-session/de/figure.txt

%files
%defattr(-,root,root,-)
/usr/share/dangling-session/C/figure.txt

%files -n dangling-session-lang
%defattr(-,root,root,-)
/usr/share/dangling-session/de/figure.txt

%changelog
* Thu Oct 15 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Session fixture for the dangling-relative-symlink sibling resolution.
