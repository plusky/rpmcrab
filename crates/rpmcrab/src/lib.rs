//! Library target for the rpmcrab binary.
//!
//! This target exists so the CLI surface and the linting pipeline can be
//! driven end-to-end by integration tests; a binary-only crate would leave the
//! argument-parsing and exit-code gates untestable as a unit. `main.rs` is a
//! thin shim over [`run`].

#![forbid(unsafe_code)]

/// Parse arguments and run the linter, returning the process exit code.
///
/// Exit-code semantics are part of the frozen compatibility contract (see
/// `docs/DESIGN.md`); do not change the mapping without a ledger entry.
pub fn run() -> std::process::ExitCode {
    // TODO(M1): parse the rpmlint-compatible CLI and drive rpmcrab-core.
    std::process::ExitCode::SUCCESS
}
