Name:           buildenv-cap-provides
Version:        1.0
Release:        1
Summary:        Build-env severity-cap fixture (marker as Provides)
License:        NotARealLicense
BuildArch:      noarch
Provides:       this-is-only-for-build-envs

%description
Near-miss for the build-env severity cap: the marker name appears as
a Provides, not a Requires. A Provides does not block installation,
so the package is not build-env-only and its findings must keep
their native levels.

%install
mkdir -p %{buildroot}%{_datadir}/buildenv-cap
printf 'Require all denied\n' > %{buildroot}%{_datadir}/buildenv-cap/.htaccess

%files
%{_datadir}/buildenv-cap/.htaccess
