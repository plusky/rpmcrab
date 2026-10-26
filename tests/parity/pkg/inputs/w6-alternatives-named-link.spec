Name:           w6-alternatives-named-link
Version:        1.0
Release:        1
Summary:        Fixture for AlternativesCheck name-keyed links (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch
Requires(post): update-alternatives
Requires(postun): update-alternatives

%description
Fixture: registrations whose alternative name differs from the generic
link's basename. update-alternatives keys the /etc/alternatives link by
the registration name, so the package ships it as %ghost under that
name. Groups: a renamed master link and a renamed slave link, both
shipped as %ghost under the registered name (credited); a renamed link
with no /etc/alternatives entry at all and one shipped as a regular
file (both keep firing alternative-link-missing); a standard
name == basename control.

%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/usr/lib64/w6named %{buildroot}/usr/share/sip
cat > %{buildroot}/usr/lib64/w6named/libw6named.so.3 <<'EOF'
w6named target
EOF
for t in w6tool-real w6gone-real w6plain-real w6std-real; do
  printf '#!/bin/sh\necho %s\n' "$t" > %{buildroot}/usr/bin/$t
  chmod 755 %{buildroot}/usr/bin/$t
done
cat > %{buildroot}/usr/share/sip/W6Slave-real <<'EOF'
w6slave target
EOF
ln -s /etc/alternatives/libw6named.so.3_x86_64 %{buildroot}/usr/lib64/libw6named.so.3
ln -s /etc/alternatives/w6tool %{buildroot}/usr/bin/w6tool
ln -s /etc/alternatives/w6slave %{buildroot}/usr/share/sip/W6Slave
ln -s /etc/alternatives/w6gone-renamed %{buildroot}/usr/bin/w6gone
ln -s /etc/alternatives/w6plain-renamed %{buildroot}/usr/bin/w6plain
ln -s /etc/alternatives/w6std %{buildroot}/usr/bin/w6std
mkdir -p %{buildroot}/etc/alternatives
cat > %{buildroot}/etc/alternatives/w6plain-renamed <<'EOF'
shipped as a regular file, not a %ghost
EOF

%post
update-alternatives --install /usr/lib64/libw6named.so.3 libw6named.so.3_x86_64 /usr/lib64/w6named/libw6named.so.3 50
update-alternatives --install /usr/bin/w6tool w6tool /usr/bin/w6tool-real 10 --slave /usr/share/sip/W6Slave w6slave /usr/share/sip/W6Slave-real
update-alternatives --install /usr/bin/w6gone w6gone-renamed /usr/bin/w6gone-real 10
update-alternatives --install /usr/bin/w6plain w6plain-renamed /usr/bin/w6plain-real 10
update-alternatives --install /usr/bin/w6std w6std /usr/bin/w6std-real 10

%postun
update-alternatives --remove libw6named.so.3_x86_64 /usr/lib64/w6named/libw6named.so.3
update-alternatives --remove w6tool /usr/bin/w6tool-real
update-alternatives --remove w6gone-renamed /usr/bin/w6gone-real
update-alternatives --remove w6plain-renamed /usr/bin/w6plain-real
update-alternatives --remove w6std /usr/bin/w6std-real

%files
%defattr(-,root,root,-)
/usr/lib64/w6named/libw6named.so.3
/usr/lib64/libw6named.so.3
/usr/bin/w6tool-real
/usr/bin/w6tool
/usr/share/sip/W6Slave-real
/usr/share/sip/W6Slave
/usr/bin/w6gone-real
/usr/bin/w6gone
/usr/bin/w6plain-real
/usr/bin/w6plain
/etc/alternatives/w6plain-renamed
/usr/bin/w6std-real
/usr/bin/w6std
%ghost /etc/alternatives/libw6named.so.3_x86_64
%ghost /etc/alternatives/w6tool
%ghost /etc/alternatives/w6slave
%ghost /etc/alternatives/w6std

%changelog
* Mon Oct 26 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for AlternativesCheck name-keyed links.
