//! Library target for the rpmcrab binary.
//!
//! This target exists so the CLI surface and the linting pipeline can be
//! driven end-to-end by integration tests; a binary-only crate would leave the
//! argument-parsing and exit-code gates untestable as a unit. `main.rs` is a
//! thin shim over [`run`].
//!
//! The flag set and exit codes are the frozen contract in `docs/DESIGN.md`
//! §4.10, §4.6.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rpmcrab_core::config;
use rpmcrab_core::lint::Lint;
use rpmcrab_core::{color::Color, term};

/// `rpmcrab` — a drop-in replacement for rpmlint 2.10.0.
#[derive(Parser, Debug)]
#[command(
    name = "rpmcrab",
    version,
    about = "Check for common problems in rpm packages",
    disable_version_flag = true,
    arg_required_else_help = false
)]
struct Cli {
    /// RPMs / specfiles / directories to check.
    #[arg(value_name = "rpmfile")]
    files: Vec<PathBuf>,

    /// Print version and exit.
    #[arg(short = 'V', long = "version", action = clap::ArgAction::Version)]
    version: (),

    /// Config file or directory of `*.toml` (repeatable).
    #[arg(short = 'c', long = "config", value_name = "path")]
    config: Vec<PathBuf>,

    /// Print the description for a message id and exit.
    #[arg(short = 'e', long = "explain", value_name = "id", num_args = 1..)]
    explain: Vec<String>,

    /// A rpmlintrc file (repeatable).
    #[arg(short = 'r', long = "rpmlintrc", alias = "file", value_name = "path")]
    rpmlintrc: Vec<PathBuf>,

    /// Inline explanations (and re-raise internal errors).
    #[arg(short = 'v', long = "verbose", alias = "info", action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Dump the merged configuration as TOML and exit.
    #[arg(short = 'p', long = "print-config", action = clap::ArgAction::SetTrue)]
    print_config: bool,

    /// Check installed RPM DB packages.
    #[arg(short = 'i', long = "installed", value_name = "name", num_args = 1..)]
    installed: Vec<String>,

    /// Per-check timing report.
    #[arg(short = 't', long = "time-report", action = clap::ArgAction::SetTrue)]
    time_report: bool,

    /// Profiling report (accepted; rpmlint uses cProfile).
    #[arg(short = 'T', long = "profile", action = clap::ArgAction::SetTrue)]
    profile: bool,

    /// Suppress the `unused-rpmlintrc-filter` audit.
    #[arg(long = "ignore-unused-rpmlintrc", action = clap::ArgAction::SetTrue)]
    ignore_unused_rpmlintrc: bool,

    /// Run only these checks (debug).
    #[arg(long = "checks", value_name = "a,b,c")]
    checks: Option<String>,

    /// Treat all messages as errors.
    #[arg(short = 's', long = "strict", action = clap::ArgAction::SetTrue, conflicts_with = "permissive")]
    strict: bool,

    /// Treat individual errors as non-fatal.
    #[arg(short = 'P', long = "permissive", action = clap::ArgAction::SetTrue, conflicts_with = "strict")]
    permissive: bool,

    /// Called from the rpmlint-mini wrapper (SUSE-only).
    #[arg(short = 'm', long = "mini-mode", action = clap::ArgAction::SetTrue)]
    mini_mode: bool,
}

/// Parse arguments and run the linter, returning the process exit code.
///
/// Exit-code semantics are part of the frozen compatibility contract (see
/// `docs/DESIGN.md` §4.6); do not change the mapping without a ledger entry.
pub fn run() -> ExitCode {
    // Bare invocation prints help and exits 0 (rpmlint `cli.py:92-94`). clap's
    // `arg_required_else_help` would exit 2, so handle it before parsing.
    if std::env::args_os().count() == 1 {
        use clap::CommandFactory;
        let _ = Cli::command().print_help();
        println!();
        return ExitCode::SUCCESS;
    }
    let cli = Cli::parse();

    // Load configuration. A nonexistent -c path is a usage error (exit 2).
    for path in &cli.config {
        if !path.exists() {
            eprintln!(
                "(none): E: error locating user requested configuration: {}",
                path.display()
            );
            return ExitCode::from(2);
        }
    }
    let mut cfg = config::load(&cli.config);

    // Apply mode flags.
    cfg.strict = cli.strict;
    cfg.info = cli.verbose;
    cfg.permissive = cli.permissive || !cli.strict; // openSUSE forces permissive unless -s

    if cli.print_config {
        print!(
            "{}",
            toml::to_string_pretty(&cfg.configuration).unwrap_or_default()
        );
        return ExitCode::SUCCESS;
    }
    if !cli.explain.is_empty() {
        // Explanations come from descriptions (M2 wires the description corpus).
        return ExitCode::SUCCESS;
    }

    // Validate positional paths (missing -> exit 2).
    for f in &cli.files {
        if !f.exists() {
            eprintln!(
                "(none): E: fatal error, no such file or directory: {}",
                f.display()
            );
            return ExitCode::from(2);
        }
    }

    // rpmlintrc: explicit -r files. Auto-discovery is wired at M3.
    for rc in &cli.rpmlintrc {
        if let Err(e) = config::load_rpmlintrc(&mut cfg, rc) {
            eprintln!("(none): E: error loading rpmlintrc {}: {e}", rc.display());
            return ExitCode::from(2);
        }
    }

    // M1: no real checks are registered yet (they arrive at M3). The Lint still
    // renders the full header/footer so the pipeline is exercised end to end.
    let color = Color::for_tty(false);
    let width = term::terminal_width();
    let mut lint = Lint::new(cfg, Vec::new(), color, width);
    lint.run_checks();
    let out = lint.render(rpmcrab_core::VERSION, cli.files.len(), 0.0);
    print!("{out}");
    ExitCode::from(u8::try_from(lint.exit_code()).unwrap_or(1))
}
