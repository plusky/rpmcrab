Name:           pem-private-key-fixture
Version:        1.0
Release:        1
Summary:        pem-private-key whole-content scan fixture
License:        MIT
BuildArch:      noarch

%description
Hand-built fixture for the pem-private-key whole-content scan. The
check matches a .pem file whose whole content is a BEGIN line, so each
fixture file holds exactly one header line: genuine.pem carries a
well-formed five-dash private-key header and must fire, cert.pem
carries a certificate header and must fire only pem-certificate,
malformed.pem carries the reference's four-dash header and must stay
silent, text.pem carries non-PEM text and must stay silent.

%install
mkdir -p %{buildroot}%{_docdir}/%{name}
printf '%s\n' '-----BEGIN PRIVATE KEY-----' > %{buildroot}%{_docdir}/%{name}/genuine.pem
printf '%s\n' '-----BEGIN CERTIFICATE-----' > %{buildroot}%{_docdir}/%{name}/cert.pem
printf '%s\n' '----BEGIN PRIVATE KEY-----' > %{buildroot}%{_docdir}/%{name}/malformed.pem
printf '%s\n' 'This is not a PEM file.' > %{buildroot}%{_docdir}/%{name}/text.pem

%files
%{_docdir}/%{name}/
