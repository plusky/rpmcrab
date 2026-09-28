# Security Policy

## Reporting a vulnerability

Please report vulnerabilities through GitHub Private Security Advisories on
this repository, not in a public issue. If the issue also affects SUSE/openSUSE
maintenance, you may additionally contact the SUSE QA Maintenance team.

## Scope

The sensitive surface of rpmcrab is:

- RPM header and payload (cpio) parsing of untrusted packages.
- Subprocess execution of external tools (`readelf`, `objdump`, `ldd`,
  `checkbashisms`, `desktop-file-validate`, `file`, `rpm -q`) on paths derived
  from package contents.
- `unsafe_code = "forbid"` everywhere in the workspace; the CI gates
  (`cargo-deny` advisories + licence + source policy, CodeQL) enforce the
  dependency and code-quality floor.

## Supported versions

Only the latest release is supported with security fixes.
