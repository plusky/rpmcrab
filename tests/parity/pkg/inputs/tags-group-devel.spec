%define optflags -O2 -g
# Pinned for reproducible fixture builds (see build-tags-group-devel.sh).
Name:           tags-group-devel-base
Version:        1.0
Release:        1
Summary:        Group devel pin fixture (base)
License:        MIT
BuildArch:      noarch

%description
Base package for the group devel pin fixture.

%package -n tags-group-devel
Summary:        Group devel pin fixture
Group:          System/Libraries
%description -n tags-group-devel
Fixture: a -devel package outside any Development/ group, for the
stays-quiet pin on the deleted devel-package-with-non-devel-group finding.

%prep

%build

%install

%{?build_epoch:find %{buildroot} -exec touch -h -d "@%{build_epoch}" {} +}
%files

%files -n tags-group-devel

%changelog
* Mon Oct 05 2026 Tester <tester@example.com> - 1.0-1
- Test changelog entry.
