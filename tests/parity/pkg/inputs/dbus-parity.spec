Name:           dbus-parity
Version:        1.0
Release:        1
Summary:        Parity fixture for DBusPolicyCheck (rpmcrab issue #58 B1/B3)
License:        MIT
BuildArch:      noarch

%description
Two <policy> elements: one with a send-allow (one bare allow plus one
with a destination), one deny-only. Reference rpmlint 2.10.0 (opensuse
branch @ 84848c0) emits exactly one finding for this file:
E dbus-policy-allow-without-destination with the minidom toxml() detail.
A per-policy (instead of per-file) send_policy_seen scope would add a
false-positive E dbus-policy-missing-allow for the deny-only policy.

%install
mkdir -p %{buildroot}/etc/dbus-1/system.d
cat > %{buildroot}/etc/dbus-1/system.d/dbus-parity.conf <<'EOF'
<busconfig>
  <policy user="root">
    <allow send_destination="org.parity.Service"/>
    <allow send_interface="org.parity.If"/>
  </policy>
  <policy context="default">
    <deny send_interface="org.parity.Private" send_destination="org.parity.Service"/>
  </policy>
</busconfig>
EOF

%files
%defattr(-,root,root,-)
/etc/dbus-1/system.d/dbus-parity.conf

%changelog
* Wed Sep 30 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Parity fixture for DBusPolicyCheck.
