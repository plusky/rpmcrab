%define optflags -O2 -g
# Pinned for reproducible fixture builds (see build-tags-emission-pins.sh).
Name:           tags-badversion
Version:        0pre
Release:        1
Summary:        Invalid version test package
License:        MIT
Group:          Development/Tools
URL:            https://example.com
Packager:       Tester <tester@example.com>
BuildArch:      noarch

%description
Invalid version test package.

%prep

%build

%install

%{?build_epoch:find %{buildroot} -exec touch -h -d "@%{build_epoch}" {} +}
%files

%changelog
* Mon Oct 05 2026 Tester <tester@example.com> - 0pre-1
- Test changelog entry.
