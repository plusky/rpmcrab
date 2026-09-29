# AGENTS.md

Guidance for AI agents and contributors working in this repository. It is the
contributor document; there is no separate `CONTRIBUTING.md`.

## Workspace Commands

The local gate is `make check`. Its parts, as copy-pasteable commands:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features gen --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo deny check
bash scripts/check-rust-layering.sh
```

The second clippy line is **not optional**: `--all-targets` silently skips the
feature-gated `rpmcrab-gen` bin, so it must be built explicitly with the `gen`
feature on.

The build needs the RPM development headers, because `librpm-sys` runs bindgen
(`pkg-config` must find `rpm.pc`): install `rpm-devel` (openSUSE) or
`librpm-dev` (Debian/Ubuntu) first, and note that `librpm` is **Linux-only** —
there is no macOS build. The tests additionally need the RPM runtime tools
(`rpm2archive`/`rpm2cpio`), `cpio` and `file` (libmagic), which the parity
harness and the payload-extraction tests invoke.

The toolchain lives in `rust-toolchain.toml`; the MSRV is declared once in the
root `Cargo.toml` (`rust-version`) and enforced by a dedicated CI job. Use
`--locked` for verification. Regenerate the man pages and completions with
`make gen` and commit the result — CI fails on drift.

## Workspace Architecture

Two crates, one direction of dependency:

```
rpmcrab  ──depends on──▶  rpmcrab-core
```

- `rpmcrab-core` is the domain: the RPM model, the TOML config loader and
  merger, the filter/suppress engine, scoring, the report renderer, the check
  registry and all checks, and the external-tool probes. It must **not** depend
  on the binary crate, on `clap`, on `tracing-subscriber`, or on any CLI
  concern — the renderer and every check are testable without a terminal.
- `rpmcrab` is the binary: the clap CLI replicating every rpmlint flag, the
  exit-code mapping, and the feature-gated `rpmcrab-gen` generator. It must not
  re-implement command algorithms that belong in `-core`.

The layering rule is enforced by `scripts/check-rust-layering.sh` in the gate.

## The Python Implementation Is a Specification, Not an Authority

rpmlint (the CPython project at `rpm-software-management/rpmlint`) is the
**specification** rpmcrab is written against. Read it to learn what the output
must be. Do not treat it as an authority on what is *correct*.

- Matching rpmlint's behaviour is a goal **only** for the frozen surface
  (see `docs/DESIGN.md`). "Python did X" is a justification for a frozen byte
  shape; it is never a justification for a finding, a severity, or a bug.
- Never preserve an upstream bug or false positive for parity. Fix it, in its
  own commit, and record it in `tests/parity/divergences.toml` with the linked
  upstream issue. Retiring a rationale is prose; changing the behaviour is
  not, and the two must not ride in the same commit.
- First check whether an odd upstream shape is a **contract in disguise** — a
  byte sequence an external consumer already greps. The `exceeds threshold,
  aborting.` banner is the canonical example: it is grepped verbatim by build
  tooling, so it is frozen no matter how it reads.
- A note recording a deliberate departure is a guard-rail and stays. State it
  positively ("rpmcrab does X"), not comparatively ("unlike rpmlint…").

## Output and Wire Contracts

These byte shapes have external consumers. Changing any of them is a breaking
change, whatever a nearby comment says about where it came from. The normative,
machine-enforceable list is `docs/DESIGN.md`; the headline items are:

- The finding line `{file}{arch}:{line} {L}: {check}{ (Badness: N)}{details}`.
- The de-coloured filter-match string (no badness, no colour) that `Filters`
  regexes run against.
- The footer template and the `exceeds threshold, aborting.` banner (grepped
  verbatim by build tooling).
- The exit-code set `0/2/3/4/64/65/66/130`, including the `64`-vs-`65` strict
  split.
- The sort order (check name reverse-alphabetical, then severity reverse).
- The TOML config merge order and the `rpmlintrc` two-directive scraper.

## Rust Style and APIs

rustfmt. Idiomatic ownership over cloning. Public items need rustdoc on
purpose, errors and behavioural constraints. Typed errors with actionable
context in `-core`; `anyhow` stays in the binary crate. No `unwrap`/`expect`/
panic in recoverable production paths. `unsafe_code` is forbidden workspace-wide
and the lint config is never weakened to silence a warning. Use exhaustive
`match` for externally meaningful enums (severity, exit reason).

Module docs live in the module's own `//!`, never as a `///` on the `mod`
declaration: one outer line there makes rustdoc resolve the whole merged
block's intra-doc links in the parent scope, and the `unresolved link` error
prints no file or line.

## Security

Never weaken a guard to fix a build or a test. Subprocess invocations of
external tools on paths derived from package contents must go through the
shared quoting/path helpers and their golden tests. Never log secrets. Keep the
dependency floor enforced: `cargo-deny` advisories + licence + source policy,
and CodeQL.

## Tests and Dependencies

Inline `#[cfg(test)] mod tests` beside the changed module is the default, plus
per-crate `tests/`. The **parity corpus** under `tests/parity/` is normative:
`captured` cases get their expected output only from running real rpmlint,
never hand-edited; `synthetic` cases may hand-write expectations. Every
behavioural difference from rpmlint must have an entry in
`tests/parity/divergences.toml` with a reason and a linked upstream issue —
the CI `parity` job fails otherwise. Dependency changes must update
`Cargo.lock`, preserve the MSRV, pass `cargo deny check`, and must not run a
broad `cargo update` as part of an unrelated change.

## Commits and Pull Requests

Conventional Commits: `type(scope): imperative lowercase subject`, ~72 cols.
One concern per PR. Rebase-only merges for bisectability. The PR title is the
primary commit subject. Every PR requests review from both maintainers (see
`CODEOWNERS`). Review the branch diff **before** opening the merge request — an
open-code-review pass (`ocr delegate`) is recommended, but any substantive
review (AI or human) satisfies this. Keep the PR description to one or two
sentences.
