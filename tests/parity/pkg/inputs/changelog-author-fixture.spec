Name:           changelog-author-fixture
Version:        1.0
Release:        1
Summary:        Fixture for invalid-changelog-author (rpmcrab)
License:        MIT
BuildArch:      noarch

%description
Hand-built fixture: bot changelog entries (opensuse-packaging@opensuse.org,
bot@example.com) and one human entry, for the invalid-changelog-author
check (upstream rpmlint#180).

%prep

%build

%install
mkdir -p %{buildroot}/usr/share/doc/changelog-author-fixture
echo fixture > %{buildroot}/usr/share/doc/changelog-author-fixture/README

%files
/usr/share/doc/changelog-author-fixture/README

%changelog
* Mon Oct 05 2026 openSUSE Packaging <opensuse-packaging@opensuse.org> - 1.0-1
- Bot entry: must warn invalid-changelog-author.
* Sun Oct 04 2026 Example Bot <bot@example.com> - 1.0-1
- Example-domain entry: must warn invalid-changelog-author.
* Sat Oct 03 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Human entry: must stay quiet.
