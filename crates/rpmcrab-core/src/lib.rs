//! Domain library for rpmcrab.
//!
//! This crate holds everything that is independent of the command line: the
//! RPM model, the TOML config loader and merger, the filter/suppress engine,
//! scoring, the report renderer, the check registry and all checks, and the
//! external-tool probes. It contains no CLI concern — no clap, no
//! tracing-subscriber, no exit-code policy — so the whole linting pipeline is
//! testable without a terminal.
//!
//! The compatibility contract this crate implements — what is frozen
//! byte-for-byte against openSUSE rpmlint 2.10.0 and what is allowed to diverge
//! — is specified in `docs/DESIGN.md`. Read that before changing the renderer
//! or the filter engine.

#![forbid(unsafe_code)]

pub mod check;
pub mod checks;
pub mod color;
pub mod config;
pub mod filter;
pub mod finding;
pub mod level;
pub mod lint;
pub mod pkg;
pub mod report;
pub mod spellcheck;
pub mod term;
pub mod worker;

/// The crate version, used for the program's version line.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
