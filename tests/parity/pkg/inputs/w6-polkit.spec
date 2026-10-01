Name:           w6-polkit
Version:        1.0
Release:        1
Summary:        Fixture for PolkitCheck (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch

%description
Fixture: polkit policy files covering user-privilege, untracked-privilege,
xml-exception and ghost-file findings.

%install
mkdir -p %{buildroot}/usr/share/polkit-1/actions
cat > %{buildroot}/usr/share/polkit-1/actions/w6.policy <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<policyconfig>
  <action id="org.w6.unprivileged">
    <description>Fixture</description>
    <message>Authenticate</message>
    <defaults>
      <allow_any>yes</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
  </action>
  <action id="org.w6.locked">
    <description>Fixture</description>
    <message>Authenticate</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>no</allow_active>
    </defaults>
  </action>
  <action id="org.w6.whitelisted">
    <description>Fixture</description>
    <message>Authenticate</message>
    <defaults>
      <allow_any>yes</allow_any>
    </defaults>
  </action>
</policyconfig>
EOF
cat > %{buildroot}/usr/share/polkit-1/actions/w6broken.policy <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<policyconfig><action id="org.w6.broken"><defaults>
EOF

%files
%defattr(-,root,root,-)
/usr/share/polkit-1/actions/w6.policy
/usr/share/polkit-1/actions/w6broken.policy
%ghost /usr/share/polkit-1/actions/w6ghost.policy

%changelog
* Thu Oct 01 2026 rpmcrab fixture - 1.0-1
- Fixture for PolkitCheck.
