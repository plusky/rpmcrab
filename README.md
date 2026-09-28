# rpmcrab

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

Requires a stable Rust toolchain (see `rust-toolchain.toml`).

```sh
cargo build --workspace --locked
```

The local gate (fmt, clippy, tests, cargo-deny, layering) is:

```sh
make check
```

## License

GPL-2.0-or-later, matching rpmlint. See [`LICENSE`](LICENSE).
