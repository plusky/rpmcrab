Name:           buildenv-cap-marked
Version:        1.0
Release:        1
Summary:        Build-env severity-cap fixture (marked package)
License:        NotARealLicense
BuildArch:      noarch
Requires:       this-is-only-for-build-envs

%description
Fixture for the build-env severity cap: the package carries the
Requires: this-is-only-for-build-envs marker, so every finding it
earns must print capped at W. The payload earns E findings from two
unrelated checks on purpose: an .htaccess file (FilesCheck) and a
bogus License (TagsCheck).

%install
mkdir -p %{buildroot}%{_datadir}/buildenv-cap
printf 'Require all denied\n' > %{buildroot}%{_datadir}/buildenv-cap/.htaccess

%files
%{_datadir}/buildenv-cap/.htaccess
