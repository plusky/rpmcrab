Name:           w6-post
Version:        1.0
Release:        1
Summary:        Fixture for PostCheck parity case (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Parity fixture exercising PostCheck finding families: an invalid shell in
the pre scriptlet, a braced macro percent in the post scriptlet, a single
one-line command in the preun scriptlet, and a braceless percent in the
postun scriptlet.

%pre -p /bin/zsh
echo pre-line-one
echo pre-line-two

%post -p /bin/sh
echo %%{postmacro}
echo done

%preun -p /bin/sh
/bin/true

%postun -p /bin/sh
echo %PATH

%install
mkdir -p %{buildroot}/usr/share/doc/w6-post
echo fixture > %{buildroot}/usr/share/doc/w6-post/README

%files
%defattr(-,root,root,-)
/usr/share/doc/w6-post/README

%changelog
* Sat Oct 03 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for PostCheck parity case.
