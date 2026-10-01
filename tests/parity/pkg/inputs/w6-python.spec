Name:           w6-python
Version:        1.0
Release:        1
Summary:        Fixture for PythonCheck (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Fixture: an egg-info directory whose requires.txt names a distribution the
package does not Require (python-require-not-provided), plus the site-packages
tests/ and doc/ directories PythonCheck reports on.

%install
mkdir -p %{buildroot}/usr/lib/python3.13/site-packages/w6python-1.0.egg-info
cat > %{buildroot}/usr/lib/python3.13/site-packages/w6python-1.0.egg-info/requires.txt <<'EOF'
w6-missing-dep
EOF
cat > %{buildroot}/usr/lib/python3.13/site-packages/w6python-1.0.egg-info/PKG-INFO <<'EOF'
Metadata-Version: 1.0
Name: w6python
Version: 1.0
EOF

# Site-packages tests/ and doc/ are what PythonCheck reports on
# (python-tests-in-site-packages, python-doc-in-site-packages); without them a
# ghost-filtering regression has nothing to show.
mkdir -p %{buildroot}/usr/lib/python3.13/site-packages/tests
mkdir -p %{buildroot}/usr/lib/python3.13/site-packages/doc

%files
%defattr(-,root,root,-)
/usr/lib/python3.13/site-packages/w6python-1.0.egg-info
/usr/lib/python3.13/site-packages/tests
/usr/lib/python3.13/site-packages/doc

%changelog
* Thu Oct 01 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for PythonCheck.
