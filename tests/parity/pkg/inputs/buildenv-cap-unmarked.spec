Name:           buildenv-cap-unmarked
Version:        1.0
Release:        1
Summary:        Build-env severity-cap fixture (unmarked control)
License:        NotARealLicense
BuildArch:      noarch

%description
Control for the build-env severity cap fixtures: the same payload as
buildenv-cap-marked but WITHOUT the
Requires: this-is-only-for-build-envs marker, so its findings keep
their native levels.

%install
mkdir -p %{buildroot}%{_datadir}/buildenv-cap
printf 'Require all denied\n' > %{buildroot}%{_datadir}/buildenv-cap/.htaccess

%files
%{_datadir}/buildenv-cap/.htaccess
