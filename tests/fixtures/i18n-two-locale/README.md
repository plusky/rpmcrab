# Two-locale i18n fixture

A minimal noarch RPM whose header carries a multi-entry `HEADERI18NTABLE`
(`["C", "de"]`): the `Summary(de):` entry and the `%description -l de`
section make rpmbuild store `SUMMARY` and `DESCRIPTION` as two-element
`I18NSTRING` arrays.

Used by the `tag_i18n_str_two_locale` unit test in
`crates/rpmcrab-core/src/pkg/mod.rs`, which pins the `lang != "C"` branch of
`Pkg::tag_i18n_str` and the index mapping from the locale table into the raw
i18n string array. Per plusky's review on #248, the parity corpus never
exercises a multi-locale package — no case has a multi-entry
`HEADERI18NTABLE` — so this fixture is the missing piece. It is deliberately
not in `tests/parity/cases/`: it is a unit-test fixture for the accessor,
not a lint finding case.

## How it was made

`build.sh` writes a minimal spec with English defaults plus German
`Summary(de):` / `%description -l de` sections and builds it with `rpmbuild`
inside an openSUSE Tumbleweed container (the
`podman_bin="${PODMAN:-podman}"` idiom), unsigned via `--nosignature`.

Regenerate with `bash tests/fixtures/i18n-two-locale/build.sh`. Rebuilds are
functionally identical but not byte-identical (rpmbuild embeds build times),
so re-check the sha256 below after regenerating.

## Provenance

```toml
kind = "synthetic"
flavour = "openSUSE"
captured = "2026-10-06"

[[input]]
file = "rpmcrab-i18n-two-locale-1.0-1.noarch.rpm"
sha256 = "be6b25890133f62869686c18c9927ee62ff0a9c018e45eb2e60b8896a52692ae"
```
