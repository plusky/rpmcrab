%define optflags -O2 -g
# Pinned for reproducible fixture builds (see build-tags-emission-pins.sh).
Name:           tags-highepoch
Version:        1.0
Release:        1
Epoch:          100
Summary:        Unreasonable epoch test package
License:        MIT
Group:          Development/Tools
URL:            https://example.com
Packager:       Tester <tester@example.com>
BuildArch:      noarch

%description
Unreasonable epoch test package.

%prep

%build

%install

%{?build_epoch:find %{buildroot} -exec touch -h -d "@%{build_epoch}" {} +}
%files

%changelog
* Mon Oct 05 2026 Tester <tester@example.com> - 100:1.0-1
- Test changelog entry.
