Name:           buildenv-cap-typo
Version:        1.0
Release:        1
Summary:        Build-env severity-cap fixture (misspelled marker)
License:        NotARealLicense
BuildArch:      noarch
Requires:       this-is-only-for-build-env

%description
Near-miss for the build-env severity cap: the Requires name is a
misspelling of the marker (missing the final s). Only the exact
marker counts, so this package's findings must keep their native
levels.

%install
mkdir -p %{buildroot}%{_datadir}/buildenv-cap
printf 'Require all denied\n' > %{buildroot}%{_datadir}/buildenv-cap/.htaccess

%files
%{_datadir}/buildenv-cap/.htaccess
