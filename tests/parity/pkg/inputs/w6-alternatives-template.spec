Name:           w6-alternatives-template
Version:        1.0
Release:        1
Summary:        Fixture for AlternativesCheck template links (rpmcrab wave 6)
License:        MIT
BuildArch:      noarch
Requires(post): update-alternatives
Requires(postun): update-alternatives

%description
Fixture: a post scriptlet registering alternatives from a shell loop, so
the extracted link still carries the loop variable, next to a literal
registration whose generic name is not shipped. The loop's concrete
expansions ship their generic symlinks and /etc/alternatives ghosts.

%install
mkdir -p %{buildroot}/usr/bin
cat > %{buildroot}/usr/bin/w6tpl-real <<'EOF'
#!/bin/sh
echo w6tpl
EOF
cat > %{buildroot}/usr/bin/w6lit-real <<'EOF'
#!/bin/sh
echo w6lit
EOF
chmod 755 %{buildroot}/usr/bin/w6tpl-real %{buildroot}/usr/bin/w6lit-real
ln -s /etc/alternatives/w6tpl_a %{buildroot}/usr/bin/w6tpl_a
ln -s /etc/alternatives/w6tpl_b %{buildroot}/usr/bin/w6tpl_b

%post
for i in a b; do
  update-alternatives --install /usr/bin/w6tpl_$i w6tpl_$i /usr/bin/w6tpl-real 10
done
update-alternatives --install /usr/bin/w6literal w6literal /usr/bin/w6lit-real 10

%postun
for i in a b; do
  update-alternatives --remove w6tpl_$i /usr/bin/w6tpl-real
done
update-alternatives --remove w6literal /usr/bin/w6lit-real

%files
%defattr(-,root,root,-)
/usr/bin/w6tpl-real
/usr/bin/w6lit-real
/usr/bin/w6tpl_a
/usr/bin/w6tpl_b
%ghost /etc/alternatives/w6tpl_a
%ghost /etc/alternatives/w6tpl_b

%changelog
* Thu Oct 01 2026 Tomas Chvatal <tomas.chvatal@gmail.com> - 1.0-1
- Fixture for AlternativesCheck template links.
