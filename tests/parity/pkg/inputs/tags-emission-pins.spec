%define optflags -O2 -g
# Pinned for reproducible fixture builds (see build-tags-emission-pins.sh).
Name:           tags-emission-pins
Version:        1.0
Release:        1
Summary:        Tags emission pins fixture
License:        MIT
URL:            https://example.com
Packager:       Tester <tester@example.com>
BuildArch:      noarch

%description
Tags emission pins fixture.

%package -n tags-emission-pins-devel
Summary:        Devel group test package
Group:          Games
%description -n tags-emission-pins-devel
Devel group test package.

%package -n tags-emission-pins-nogroup
Summary:        No group test package
%description -n tags-emission-pins-nogroup
No group test package.

%package -n tags-emission-pins-longsummary
Summary:        This is a deliberately overlong summary that stretches well past seventy nine characters
Group:          Development/Tools
%description -n tags-emission-pins-longsummary
Long summary test package.

%package -n tags-emission-pins-badsummary
Summary:        lowercase summary that ends with a dot.
Group:          Development/Tools
%description -n tags-emission-pins-badsummary
Bad summary test package.

%package -n tags-emission-pins-multiline
Summary:        First line of summaryrest of summary
Group:          Development/Tools
%description -n tags-emission-pins-multiline
Multiline summary test package.

%package -n tags-emission-pins-nodesc
Summary:        No description test package
Group:          Development/Tools
%description -n tags-emission-pins-nodesc

%package -n tags-emission-pins-longdesc
Summary:        Long description test package
Group:          Development/Tools
%description -n tags-emission-pins-longdesc
Short line.
This is a ridiculously long description line that definitely exceeds seventy nine characters.

%package -n tags-emission-pins-tagdesc
Summary:        Tag in description test package
Group:          Development/Tools
%description -n tags-emission-pins-tagdesc
Some text.
Name: something

%package -n tags-emission-pins-spell
Summary:        Hello world test package
Group:          Development/Tools
%description -n tags-emission-pins-spell
hello world test packag check

%package -n tags-emission-pins-obsolete
Summary:        Obsolete test package
Group:          Development/Tools
Obsoletes:      tags-old-pin
%description -n tags-emission-pins-obsolete
Obsolete test package.

%package -n tags-emission-pins-pcreq-devel
Summary:        Pkg-config provides test package
Group:          Development/Tools
%description -n tags-emission-pins-pcreq-devel
Pkg-config test package.

%prep

%build

%install
mkdir -p %{buildroot}/usr/lib64/pkgconfig
cat > %{buildroot}/usr/lib64/pkgconfig/tags-emission-pins.pc <<'EOF'
prefix=/usr
Name: tags-emission-pins
Description: test
Version: 1.0
EOF

%{?build_epoch:find %{buildroot} -exec touch -h -d "@%{build_epoch}" {} +}
%files

%files -n tags-emission-pins-devel

%files -n tags-emission-pins-nogroup

%files -n tags-emission-pins-longsummary

%files -n tags-emission-pins-badsummary

%files -n tags-emission-pins-multiline

%files -n tags-emission-pins-nodesc

%files -n tags-emission-pins-longdesc

%files -n tags-emission-pins-tagdesc

%files -n tags-emission-pins-spell

%files -n tags-emission-pins-obsolete

%files -n tags-emission-pins-pcreq-devel
/usr/lib64/pkgconfig/tags-emission-pins.pc

%changelog
* Mon Oct 05 2026 Tester <tester@example.com> - 1.0-1
- Test changelog entry.
