# vim: set sw=4 ts=4 et nu:

# Copyright (c) 2013 Pascal Bleser <pascal.bleser@opensuse.org>
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/

Name:               codequery
Version:            0.08
Release:            0
Summary:            Tool for Indexing and Querying C, C++, Java and Python Sources
# https://github.com/ruben2020/codequery/archive/v%{version}.tar.gz
Source:             codequery-%{version}.tar.gz
URL:                http://ruben2020.github.io/codequery/
Group:              Development/Tools/Navigators
License:            GPL-3.0+
BuildRoot:          %{_tmppath}/build-%{name}-%{version}
BuildRequires:      cscope
BuildRequires:      ctags
# BuildRequires:      pycscope
BuildRequires:      libqt4-devel
BuildRequires:      sqlite3-devel
BuildRequires:      cmake >= 2.8
BuildRequires:      gcc-c++ make glibc-devel pkgconfig
BuildRequires:      update-desktop-files
Requires:           cscope
Requires:           ctags
Recommends:         pycscope

%description
CodeQuery is a tool for indexing and then querying or searching C, C++, Java,
and Python source code. It builds upon the databases of cscope and ctags, which
are processed by the cqmakedb tool to generate a CodeQuery database file. This
can be viewed and queried with a GUI tool. The features include auto-completion
of search terms and visualization of function call graphs and class
inheritance. The following queries can be made: Symbol, Function or macro,
Class or struct, Functions calling this function, Functions called by this
function, Class which owns this member or method, Members and methods of this
class, Parent of this class (inheritance), Children of this class
(inheritance), Files including this file, and full path for file.

%prep
%setup -q

%build
%__install -d build
pushd build
cmake \
    -DCMAKE_VERBOSE_MAKEFILE=TRUE \
    -DCMAKE_INSTALL_PREFIX="%{_prefix}" \
    -DCMAKE_SKIP_RPATH=TRUE \
    -DCMAKE_BUILD_WITH_INSTALL_RPATH=FALSE \
    ..
%__make %{?_smp_mflags}
popd

%install
pushd build
%makeinstall
popd

%__install -D -m0644 gui/images/logo.png "%{buildroot}%{_datadir}/pixmaps/%{name}.png"
%suse_update_desktop_file -c "%{name}" CodeQuery "Tool for Indexing and Querying C, C++, Java and Python Sources" codequery "%{name}.png" Development IDE

%clean
%{?buildroot:%__rm -rf "%{buildroot}"}

%files
%defattr(-,root,root)
%doc NEWS.txt LICENSE.md README.md
%{_bindir}/codequery
%{_bindir}/cqmakedb
%{_bindir}/cqsearch
%{_datadir}/applications/%{name}.desktop
%{_datadir}/pixmaps/%{name}.png

%changelog
