Name:           nosrc-fixture
Version:        1.0
Release:        1
Summary:        Fixture package with a non-redistributable source
License:        Proprietary
Source0:        secret-sauce.tar.gz
NoSource:       0
BuildArch:      noarch

%description
Fixture for the .nosrc.rpm placeholder case: the header is complete,
the NoSource tarball is absent from the payload by construction.

%prep
%setup -q -n secret-sauce-1.0

%build

%install

%files
