# rpmcrab

<img src="https://raw.githubusercontent.com/plusky/rpmcrab/main/docs/assets/logo.svg"
     align="right" width="130" alt="rpmcrab logo">

[![CI](https://github.com/plusky/rpmcrab/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/plusky/rpmcrab/actions/workflows/ci.yml)
[![License: GPL-2.0-or-later](https://img.shields.io/badge/License-GPL--2.0--or--later-blue.svg)](LICENSE)
[![rustc 1.88+](https://img.shields.io/badge/rustc-1.88+-orange.svg)](https://www.rust-lang.org)

A drop-in replacement for [`rpmlint`](https://github.com/rpm-software-management/rpmlint)
(2.10.0, openSUSE flavour, `checks: 43`), rewritten in Rust.

rpmcrab runs identically to rpmlint: same command-line flags, same TOML
configuration, same `rpmlintrc` filters, and the **same frozen output and
exit-code contract** that external tooling (OBS build summaries, openQA, the
openSUSE badness-999 gate) already consumes. It is not a bug-for-bug port:
upstream false positives and never-firing checks are fixed, and every fix is
recorded in a machine-enforced ledger. Behavioural divergence is deferred to a
later major version.

- **The compatibility contract** — what is frozen and what may diverge — lives
  in [`docs/DESIGN.md`](docs/DESIGN.md).
- **The roadmap** lives in the milestones and the umbrella RFC issue; the spec
  lives in `docs/DESIGN.md`, never the reverse.

## Status

Pre-1.0. The crate layout and the report-rendering pipeline land first (M1);
byte-identical output is proven against a synthetic check set before any real
check exists. See the milestones for sequencing.

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
