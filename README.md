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
openQA) already consumes — except for the deliberate divergences recorded in
the machine-enforced ledger
([`tests/parity/divergences.toml`](tests/parity/divergences.toml)). It is not
a bug-for-bug port: upstream false positives and never-firing checks are
fixed. The current version is **0.4.1**.

## Validation and security tightening

The reference checker's output was hard to act on in both directions: noisy enough that real defects drowned in false positives, and silent on genuine defects that deserved a report. Since parity, rpmcrab tightens the checks to decidable predicates — a finding fires when the evidence for it is actually present, and a legitimate pattern stays silent. That matters because these packages ship to millions of systems, and the defects in question sit at privilege boundaries: setuid and setgid files, systemd units, and files a daemon or the installer runs. A defect missed there is a vulnerability, not a nit.

The hardening covers the places where a packaging defect becomes a security problem. Insecure temporary files and unbounded input, where a predictable name or an unchecked read hands an attacker the next step. Legacy resolver calls in exposed or privileged contexts, where an old lookup mechanism weakens a process that runs with more rights than the user who invoked it. Weak randomness and privilege drops, where a guessable value or a privilege left half-dropped widens what an attacker can reach. Outdated toolchains, where a binary carries known weaknesses from the tools that built it. And build flags that trade security or reproducibility for speed, where a package quietly stops behaving the same way twice. Where a legitimate pattern should stay silent, the exemption is itself decidable: it applies only when the evidence for it is present, never as a blanket filter.

The details live in the machine-enforced ledger and the commit history: [`tests/parity/divergences.toml`](tests/parity/divergences.toml).

- **The compatibility contract** — what is frozen and what may diverge — lives
  in [`docs/DESIGN.md`](docs/DESIGN.md).
- **The roadmap** lives in the milestones and the umbrella RFC issue.

## Status

Pre-1.0, post-parity, packaged for OBS. Versioning carries no parity claim:
a minor bump may change behaviour substantially, and a major bump is
reserved for an utter breaking change (see `docs/DESIGN.md` §9).

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
