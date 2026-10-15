Name:           nodoc-lone
Version:        1.0
Release:        1
Summary:        Lone doc-less package fixture
License:        MIT
BuildArch:      noarch

%description
Fixture for the session-aware no-documentation decision (issue #539):
a single package with no %doc files, built from its own source, so it
has no sibling that could ship documentation for it and the finding
still fires.

%install
mkdir -p %{buildroot}/usr/share/nodoc-lone
echo "payload" > %{buildroot}/usr/share/nodoc-lone/data.txt

%files
%defattr(-,root,root,-)
/usr/share/nodoc-lone/data.txt

%changelog
* Thu Oct 15 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Lone doc-less fixture for the no-documentation session decision.
