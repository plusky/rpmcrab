Name:           nodoc-session-main
Version:        1.0
Release:        1
Summary:        Session-aware no-documentation fixture (main package)
License:        MIT
BuildArch:      noarch

%description
Fixture for the session-aware no-documentation decision (issue #539):
the main package ships %doc files, the -data subpackage ships none.
Both are built from this one spec, so they share a SOURCERPM and the
data subpackage must stay quiet when the two are linted in one run.

%package -n nodoc-session-data
Summary:        Session-aware no-documentation fixture (data subpackage)

%description -n nodoc-session-data
Data subpackage of the no-documentation session fixture: payload
files only, no documentation of its own.

%build
echo "Documentation for the whole nodoc-session source." > README

%install
mkdir -p %{buildroot}/usr/share/nodoc-session-data
echo "payload" > %{buildroot}/usr/share/nodoc-session-data/data.txt

%files
%defattr(-,root,root,-)
%doc README

%files -n nodoc-session-data
%defattr(-,root,root,-)
/usr/share/nodoc-session-data/data.txt

%changelog
* Thu Oct 15 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Session fixture for the no-documentation sibling suppression.
