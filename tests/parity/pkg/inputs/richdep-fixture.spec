Name:           richdep-fixture
Version:        1.0
Release:        1
Summary:        Rich (boolean) dependency fixture
License:        MIT
BuildArch:      noarch

Requires:       (foo or bar)
Requires:       (baz >= 1.0 with baz < 2.0)
Requires:       (outer and (inner1 or inner2))
Requires:       qux(meta)

%description
Hand-built fixture for rich (boolean) dependency parsing (RPM >= 4.13)
and dependency qualifiers (RPM >= 4.16, #429). Exercises pkg::dep
expression parsing end to end through a real RPM header.

%files
