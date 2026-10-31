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

Since parity, the checks are tightened to decidable predicates: genuine
defects fire at the right severity, while providers and legitimate patterns
stay silent.

- **Insecure temporary files and unbounded input (BinariesCheck).**
  `call-to-mktemp` charges an undefined reference only — the caller exposed
  to the name race — while a library that defines mktemp stays silent
  (glibc, fakechroot, ksh). New findings with no reference counterpart:
  `call-to-gets` (CWE-242: unbounded read into a caller buffer, removed from
  C11) and `call-to-tmpnam` (CWE-377: the name-to-open race), both Error.
- **Legacy resolver calls in exposed context (BinariesCheck).**
  `binary-or-shlib-calls-gethostbyname` reports at Error when the file is
  privileged (setuid/setgid bits or file capabilities) or its package ships
  systemd units, and at Warning otherwise.
- **Weak randomness and privilege drops (BinariesCheck).**
  `binary-or-shlib-calls-weak-prng` fires at Warning only for privileged
  files or binaries a systemd unit actually starts (ExecStart resolved
  through in-package symlinks; unresolvable units fail open), while
  seeder-only calls stay silent. `missing-call-to-setgroups-before-setuid`
  credits an LD_PRELOAD-style interposer — an object that defines
  setuid/setgid and forwards through dlsym — but still fires on an object
  that both defines and calls.
- **Outdated Go toolchains (BinariesCheck).** `go-toolchain-outdated`
  warns on Go binaries built with a toolchain below the floor
  (`data/go-toolchain-floor.toml`, anchored on CVE-2025-22871), including a
  toolchain package's own tools on an end-of-life line.
- **Forbidden compiler flags (BinariesCheck).** A populated
  ForbiddenOptflags list (`-march=native`/`-mtune=native`, the
  `-Ofast`/fast-math family, `-funroll-loops`) fires where the reference's
  empty default list stays silent.
- **Decidable exemptions, not blind filters.**
  `shlib-policy-etc-payload` fires only when a sibling SONAME generation
  ships the exact same `/etc` or `/usr/etc` path in the same run and on the
  same architecture; text-only patterns packages are exempt from
  `no-binary`.

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
