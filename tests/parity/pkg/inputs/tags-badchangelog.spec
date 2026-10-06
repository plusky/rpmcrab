%define optflags -O2 -g
# Pinned for reproducible fixture builds (see build-tags-emission-pins.sh).
Name:           tags-emission-pins
Version:        1.0
Release:        1
Summary:        Test package for tags emission pins
License:        MIT
URL:            https://example.com
Packager:       Tester <tester@example.com>
Group:          Development/Tools
BuildArch:      noarch

%description
Test package.

%files

%changelog
* Mon Oct 05 2026 Tester <tester@example.com> - 1.0-1
- Bad changelog entry with control character
