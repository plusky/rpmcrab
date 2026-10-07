Name:           fsf-address-fixture
Version:        1.0
Release:        1
Summary:        incorrect-fsf-address whole-file scan fixture
License:        MIT
BuildArch:      noarch

%description
Hand-built fixture for the whole-file incorrect-fsf-address scan
(upstream rpmlint#40). LICENSE-early carries the wrong FSF address inside
the first 2048 bytes, LICENSE-late carries it past byte 2048,
LICENSE-ok mentions the GPL with no street address and must stay silent.

%install
mkdir -p %{buildroot}%{_docdir}/%{name}
cat > %{buildroot}%{_docdir}/%{name}/LICENSE-early <<'EOF'
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
EOF
{
echo "This program is free software; you can redistribute it and/or"
echo "modify it under the terms of the GNU General Public License as"
echo "published by the Free Software Foundation."
echo ""
echo "The full license text follows after this padding block."
echo ""
head -c 3000 /dev/zero | tr '\0' 'x'
echo ""
echo ""
echo "You should have received a copy of the GNU General Public License"
echo "along with this program; if not, write to the Free Software"
echo "Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA."
} > %{buildroot}%{_docdir}/%{name}/LICENSE-late
cat > %{buildroot}%{_docdir}/%{name}/LICENSE-ok <<'EOF'
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version. See <https://www.gnu.org/licenses/>
for the full license text.
EOF

%files
%{_docdir}/%{name}/
