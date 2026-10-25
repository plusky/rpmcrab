# rpmcrab

<img src="https://raw.githubusercontent.com/plusky/rpmcrab/main/docs/assets/logo.svg"
     align="right" width="130" alt="rpmcrab logo">

[![CI](https://github.com/plusky/rpmcrab/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/plusky/rpmcrab/actions/workflows/ci.yml)
[![License: GPL-2.0-or-later](https://img.shields.io/badge/License-GPL--2.0--or--later-blue.svg)](LICENSE)
[![rustc 1.88+](https://img.shields.io/badge/rustc-1.88+-orange.svg)](https://www.rust-lang.org)

A drop-in replacement for [`rpmlint`](https://github.com/rpm-software-management/rpmlint)
(2.10.0, openSUSE flavour, `checks: 43`), rewritten in Rust.

**0.2.0 was the parity milestone:** rpmcrab matches rpmlint 2.10.0 — same
command-line flags, same TOML configuration, same `rpmlintrc` filters, and the
same output and exit-code contract that external tooling (OBS build summaries,
openQA) already consumes — except for the
deliberate divergences recorded in the machine-enforced ledger
([`tests/parity/divergences.toml`](tests/parity/divergences.toml)). It is not
a bug-for-bug port: upstream false positives and never-firing checks are
fixed, and every fix is in the ledger. After 0.2.0 the project deliberately
diverges wherever rpmlint is wrong, with every departure recorded in the
ledger. The current release is **0.4.0**.

- **The compatibility contract** — what is frozen and what may diverge — lives
  in [`docs/DESIGN.md`](docs/DESIGN.md).
- **The roadmap** lives in the milestones and the umbrella RFC issue; the spec
  lives in `docs/DESIGN.md`, never the reverse.

## Status

Pre-1.0, post-parity: 43 checks matching rpmlint 2.10.0 (openSUSE flavour),
packaged for OBS, with deliberate divergences from the reference recorded in
the ledger. Versioning carries no parity claim: a minor bump may change
behaviour substantially, and a major bump is reserved for an utter
breaking change (see `docs/DESIGN.md` §9).

## Building

Requires a stable Rust toolchain (see `rust-toolchain.toml`), plus the RPM
development headers (`rpm-devel` on openSUSE, `librpm-dev` on Debian/Ubuntu
— `pkg-config` must find `rpm.pc`). The default build enables librpm's
`build` feature for spec parsing, whose bindgen step also needs `popt.h`:
add `popt-devel` (openSUSE) / `libpopt-dev` (Debian/Ubuntu); on
Debian/Ubuntu `librpm-dev` already pulls popt in.

```sh
cargo build --workspace --locked
```

The local gate (fmt, clippy, tests, cargo-deny, layering) is:

```sh
make check
```

## License

GPL-2.0-or-later, matching rpmlint. See [`LICENSE`](LICENSE).
