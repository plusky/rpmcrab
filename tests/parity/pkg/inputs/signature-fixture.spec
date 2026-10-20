Name:           signature-fixture
Version:        1.0
Release:        1
Summary:        SignatureCheck fixture package
License:        MIT
BuildArch:      noarch

%description
Fixture for SignatureCheck. Built unsigned by rpmbuild, then signed
with the rpmcrab test key and byte-flipped into the corrupt variants
by build-signature-fixtures.sh.

%install
mkdir -p %{buildroot}/usr/bin
printf '#!/bin/sh\necho signature-fixture\n' > %{buildroot}/usr/bin/signature-fixture
chmod +x %{buildroot}/usr/bin/signature-fixture

%files
/usr/bin/signature-fixture
