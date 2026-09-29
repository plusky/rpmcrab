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

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rpmcrab_core::config;
use rpmcrab_core::lint::Lint;
use rpmcrab_core::{color::Color, term};

/// The rpmlint version rpmcrab emulates in the session banner. The banner is
/// frozen (`rpmlint: X.Y.Z`); the version shown is the reference version, not
/// the crate version (`docs/DESIGN.md` §4.5). The crate's own version is
/// separate (`rpmcrab --version`).
const RPMLINT_VERSION: &str = "2.10.0";

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

    // Load configuration. A nonexistent -c path is a usage error (exit 2) with
    // the reference's exact message (`cli.py:_validate_conf_location`).
    for path in &cli.config {
        if !path.exists() {
            eprintln!(
                "File or dir with user specified configuration '{}' does not exist",
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
    cfg.mini_mode = cli.mini_mode;

    if cli.print_config {
        print!(
            "{}",
            toml::to_string_pretty(&cfg.configuration).unwrap_or_default()
        );
        return ExitCode::SUCCESS;
    }
    if !cli.explain.is_empty() {
        // TODO(M2): print the explanation from the description corpus.
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
    // TODO(M3): rpmlintrc auto-discovery (OBS SOURCES dirs + single-positional).
    for rc in &cli.rpmlintrc {
        if let Err(e) = config::load_rpmlintrc(&mut cfg, rc) {
            eprintln!("(none): E: error loading rpmlintrc {}: {e}", rc.display());
            return ExitCode::from(2);
        }
    }

    // -i/--installed: resolve the rpmdb names now (rpmlint `_load_installed_rpms`)
    // and emit the no-such-rpm warning. Only the headers come back: building a
    // `Pkg` walks every file of every match, and no check runs until M3, so a
    // wide glob would stat the whole system for nothing.
    if !cli.installed.is_empty() {
        match rpmcrab_core::pkg::installed::find_installed(&cli.installed) {
            Ok((_headers, missing)) => {
                for name in &missing {
                    eprintln!("(none): E: there is no installed rpm \"{name}\".");
                }
            }
            // Deliberate divergence: the reference lets a failed `rpmtsOpenDB`
            // raise, so it dies with a Python traceback. One line and exit 1
            // carries the same information to a shell user.
            Err(e) => {
                eprintln!("(none): E: fatal error reading the rpmdb: {e}");
                return ExitCode::from(1);
            }
        }
    }

    // TODO(M3): -t time-report, -T profile, --checks filtering are parsed and
    // currently no-ops.

    // M1: no real checks are registered yet (they arrive at M3). The Lint still
    // renders the full header/footer so the pipeline is exercised end to end.
    let color = Color::for_tty(std::io::stdout().is_terminal());
    let width = term::terminal_width();
    let mut lint = match Lint::new(cfg, Vec::new(), color, width) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("(none): E: fatal error in configuration filters: {e}");
            return ExitCode::from(1);
        }
    };
    lint.run_checks();
    // The header counts CLI args (files + installed); the footer counts
    // validated inputs. M1 registers no checks, so nothing is validated yet.
    let arg_count = cli.files.len() + cli.installed.len();
    let out = lint.render(RPMLINT_VERSION, arg_count, 0, 0, 0.0);
    print!("{out}");
    ExitCode::from(u8::try_from(lint.exit_code()).unwrap_or(1))
}
