Name:           uidgid-session-main
Version:        1.0
Release:        1
Summary:        Session-aware non-standard-uid/gid fixture (main package)
License:        MIT
BuildArch:      noarch

%description
Fixture for the session-aware non-standard-uid / non-standard-gid
decision (issue #756): the -sysusers subpackage ships the sysusers.d
snippet declaring the accounts this source's payload files are owned
by. Both packages are built from this one spec, so they share a
SOURCERPM and the main package's files stay quiet when the two are
linted in one run.

%package -n uidgid-session-sysusers
Summary:        Session-aware non-standard-uid/gid fixture (sysusers subpackage)

%description -n uidgid-session-sysusers
Sysusers subpackage of the non-standard-uid/gid session fixture:
ships /usr/lib/sysusers.d/uidgid-session.conf, which declares the
svcfoo user (and its like-named primary group) and the svcbar group.

%install
mkdir -p %{buildroot}/usr/share/uidgid-session
echo "payload" > %{buildroot}/usr/share/uidgid-session/data.txt
mkdir -p %{buildroot}/usr/lib/sysusers.d
printf '%s\n' \
  '# Accounts declared by the uidgid-session source (issue #756 fixture).' \
  'u svcfoo - "svcfoo service user" /var/lib/svcfoo -' \
  'g svcbar - -' \
  'm svcfoo svcbar' \
  > %{buildroot}/usr/lib/sysusers.d/uidgid-session.conf

%files
%defattr(-,root,root,-)
/usr/share/uidgid-session/data.txt

%files -n uidgid-session-sysusers
%defattr(-,root,root,-)
/usr/lib/sysusers.d/uidgid-session.conf

%changelog
* Mon Oct 19 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Session fixture for the declared-account crediting.
