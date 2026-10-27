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

use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::Parser;
use rpmcrab_core::config;
use rpmcrab_core::lint::Lint;
use rpmcrab_core::{color::Color, term};

/// The version printed in the session banner's version line. The banner
/// identifies rpmcrab itself (`rpmcrab: X.Y.Z`) with the crate's own version;
/// reference emulation no longer applies to it (`docs/DESIGN.md` §4.5).
/// `rpmcrab --version` reports the same version.
const RPMLINT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `helpers.print_warning`: the message in red, on stderr. The reference's
/// `Color` table is chosen by **stdout**'s tty-ness even for stderr writes, so
/// this shares the report's colour table.
macro_rules! warn {
    ($color:expr, $($arg:tt)*) => {
        eprintln!("{}{}{}", $color.red, format_args!($($arg)*), $color.reset)
    };
}

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
    #[arg(short = 'r', long = "rpmlintrc", value_name = "path")]
    rpmlintrc: Vec<PathBuf>,

    /// Inline explanations (and re-raise internal errors).
    #[arg(short = 'v', long = "verbose", visible_alias = "info", action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Dump the merged configuration as TOML and exit.
    #[arg(short = 'p', long = "print-config", action = clap::ArgAction::SetTrue)]
    print_config: bool,

    /// Check installed RPM DB packages.
    #[arg(short = 'i', long = "installed", value_name = "name", num_args = 1..)]
    installed: Vec<String>,

    /// Per-check timing report (on by default).
    #[arg(short = 't', long = "time-report", action = clap::ArgAction::SetTrue, conflicts_with = "no_time_report")]
    time_report: bool,

    /// Disable the per-check timing report.
    #[arg(long = "no-time-report", action = clap::ArgAction::SetTrue, conflicts_with = "time_report")]
    no_time_report: bool,

    /// Number of parallel worker threads for checking packages; 1 is
    /// sequential. Defaults to the machine's parallelism.
    // `hide_default_value` is deliberate: the default is a runtime CPU count,
    // so rendering it would make --help and the generated man page
    // machine-dependent, and the committed assets unreproducible.
    #[arg(
        short = 'j',
        long = "jobs",
        value_name = "n",
        default_value_t = default_jobs(),
        hide_default_value = true
    )]
    jobs: i32,

    /// Suppress the `unused-rpmlintrc-filter` audit.
    #[arg(long = "ignore-unused-rpmlintrc", action = clap::ArgAction::SetTrue)]
    ignore_unused_rpmlintrc: bool,

    /// Run only these checks (debug).
    #[arg(long = "checks", value_name = "a,b,c")]
    checks: Option<String>,

    /// Treat all messages as errors.
    #[arg(short = 's', long = "strict", action = clap::ArgAction::SetTrue, conflicts_with = "permissive")]
    strict: bool,

    /// Skip warning-only checks entirely (upstream rpmlint#134). A static
    /// pre-scoring bound on each check's declared max severity; disabled
    /// under --strict.
    #[arg(long = "errors-only", action = clap::ArgAction::SetTrue)]
    errors_only: bool,

    /// Treat individual errors as non-fatal.
    #[arg(short = 'P', long = "permissive", action = clap::ArgAction::SetTrue, conflicts_with = "strict")]
    permissive: bool,

    /// Called from the rpmlint-mini wrapper (SUSE-only).
    #[arg(short = 'm', long = "mini-mode", action = clap::ArgAction::SetTrue)]
    mini_mode: bool,

    /// Report output format: human-readable text (default) or
    /// machine-readable JSON (upstream rpmlint#1156). Overrides the
    /// `OutputFormat` config key.
    #[arg(long = "format", value_name = "format", value_parser = ["text", "json"])]
    format: Option<String>,

    /// Hand-back file of a diverted JSON run; set only by the parent's
    /// re-exec (see `divert_json_run`). Hidden: not a user interface.
    #[arg(long = "__diverted-json", value_name = "path", hide = true)]
    diverted_json: Option<PathBuf>,
}

/// `-j/--jobs` default: the reference uses `os.cpu_count() or 1`
/// (`cli.py`), so this is the machine's parallelism with a fallback of 1.
fn default_jobs() -> i32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(1)
}

/// Resolve the effective output format: the CLI `--format` wins outright,
/// otherwise the `OutputFormat` config key decides (`"text"` default).
fn resolve_output_format(cli_format: Option<&str>, config_format: &str) -> String {
    cli_format.unwrap_or(config_format).to_string()
}

/// Tracing filter for the binary: `RUST_LOG` wins when set and valid;
/// otherwise this crate and `rpmcrab-core` log at `info` (the progress
/// lines) and everything else at `warn`, so a normal run gains no noise.
/// An invalid `RUST_LOG` warns on stderr and falls back to the default, so a
/// typo is visible instead of silently ignored.
fn tracing_filter() -> tracing_subscriber::EnvFilter {
    match std::env::var("RUST_LOG") {
        Ok(directives) => match directives.parse() {
            Ok(filter) => filter,
            Err(e) => {
                eprintln!("warning: ignoring invalid RUST_LOG={directives:?}: {e}");
                default_tracing_filter()
            }
        },
        Err(_) => default_tracing_filter(),
    }
}

fn default_tracing_filter() -> tracing_subscriber::EnvFilter {
    "warn,rpmcrab=info,rpmcrab_core=info"
        .parse()
        .expect("the default tracing directives are valid")
}

/// The clap `Command` for the `rpmcrab` binary, shared by `main.rs` and the
/// `rpmcrab-gen` asset generator so the man page and shell completions can
/// never drift from the shipped CLI.
pub fn cli_command() -> clap::Command {
    use clap::CommandFactory;
    Cli::command()
}

/// Run a `--format json` report through a child process so the document
/// is the only thing that reaches this process's stdout (#703).
///
/// librpm parses specs in-process, and a spec can print to the process's
/// stdout while it is parsed -- `%{echo:...}` prints there by definition
/// and macro lua `print` does the same -- ahead of the rendered document,
/// corrupting it for any JSON consumer (the Factory sweep captured
/// exactly that for the `bash` and `rspamd` specs). The crate forbids
/// unsafe code, so the fd cannot be redirected in-process; instead the
/// run re-executes itself with the hidden `--__diverted-json` flag, the
/// child's stdout is forwarded to stderr (the prints stay visible as
/// diagnostics), and the child writes the rendered report to the file
/// named by the flag, which this parent copies to its own stdout once
/// the child finishes. The child's exit code becomes the run's.
///
/// The hand-back file is a [`tempfile::NamedTempFile`]: created
/// exclusively under an unpredictable name with owner-only permissions,
/// so nothing can pre-create, redirect or pre-read it, and dropping it
/// removes it. The child half is keyed off the hidden flag alone -- no
/// environment variable steers the diversion, so an ambient variable
/// can neither skip the diversion nor redirect the report.
///
/// Returns `None` only when the diversion could not be set up at all
/// (no child exists; the caller then runs in-process with a warning, as
/// it did before the diversion existed). After the child has spawned, a
/// failure of the child itself is carried by the child's own stderr and
/// exit code, which the parent forwards without adding noise; a
/// failure of the hand-off (the pipe, the wait, or a child that claimed
/// success but delivered no document) is loud instead: a message on
/// stderr and a failure code, never a silent empty stdout.
fn divert_json_run() -> Option<ExitCode> {
    let report = tempfile::NamedTempFile::new().ok()?;
    let exe = std::env::current_exe().ok()?;
    // Forward the user's arguments verbatim, with the hidden flag
    // inserted before any `--` separator (after it, clap would treat
    // the flag as a positional file).
    let mut args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let insert_at = args
        .iter()
        .position(|a| a.as_os_str() == "--")
        .unwrap_or(args.len());
    args.insert(insert_at, std::ffi::OsString::from("--__diverted-json"));
    args.insert(insert_at + 1, report.path().as_os_str().to_os_string());
    let mut child = match std::process::Command::new(exe)
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return None,
    };
    // No path past this point may leave the child behind: every failure
    // path kills and reaps it before reporting.
    let Some(mut pipe) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        eprintln!("(none): E: the diverted JSON run lost its output pipe");
        return Some(ExitCode::from(1));
    };
    let forwarder = std::thread::spawn(move || {
        // Forward the child's stdout to stderr. If that write fails (a
        // broken pipe downstream, a full device), keep draining the
        // pipe into a sink instead of abandoning it: an unread pipe
        // fills, the child wedges mid-print, and the `wait` below
        // never returns.
        if std::io::copy(&mut pipe, &mut std::io::stderr()).is_err() {
            let _ = std::io::copy(&mut pipe, &mut std::io::sink());
        }
    });
    let status = match child.wait() {
        Ok(status) => status,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = forwarder.join();
            eprintln!("(none): E: waiting for the diverted JSON run failed: {e}");
            return Some(ExitCode::from(1));
        }
    };
    let _ = forwarder.join();
    let code = exit_code_of(&status);
    match std::fs::read(report.path()) {
        // A delivered document is copied out whatever the child's
        // verdict: a non-zero code is the normal lint outcome (errors
        // found), not a hand-off failure.
        Ok(bytes) if !bytes.is_empty() => {
            use std::io::Write;
            match std::io::stdout().write_all(&bytes) {
                Ok(()) => Some(code),
                Err(e) => {
                    eprintln!("(none): E: writing the JSON report to stdout failed: {e}");
                    Some(ExitCode::from(1))
                }
            }
        }
        // No document and a failed child: the child has already
        // explained itself on the forwarded stderr (it died before
        // rendering), so the parent stays silent and forwards the
        // child's code. Only a child that claimed success yet
        // delivered nothing is a hand-off failure of the parent's
        // own, and that one stays loud.
        Ok(_) if !status.success() => Some(code),
        Ok(_) => {
            eprintln!("(none): E: the diverted JSON run left an empty report");
            Some(ExitCode::from(1))
        }
        Err(_) if !status.success() => Some(code),
        Err(e) => {
            eprintln!("(none): E: the diverted JSON run left no readable report: {e}");
            Some(ExitCode::from(1))
        }
    }
}

/// The exit code a diverted run's parent reports for its child: the
/// child's own code where it has one; for a signal death, the shell
/// convention `128 + signal` on Unix, so the two stay distinguishable.
fn exit_code_of(status: &std::process::ExitStatus) -> ExitCode {
    if let Some(code) = status.code() {
        return ExitCode::from(u8::try_from(code).unwrap_or(1));
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return ExitCode::from(128u8.saturating_add(u8::try_from(signal).unwrap_or(0)));
        }
    }
    ExitCode::from(1)
}

/// Write the rendered report to the hand-back file named by the hidden
/// `--__diverted-json` flag (the child half of [`divert_json_run`]).
///
/// The flag alone does not entitle a run to write anywhere: the named
/// path must be the parent's hand-back file, which the parent created
/// as a [`tempfile::NamedTempFile`] -- an already-existing, empty,
/// regular file that is not a symlink and, on Unix, has owner-only
/// permissions. Anything else is a forged flag (a hand-typed or copied
/// command line naming a real file such as `~/.bashrc`), and writing
/// with create+truncate would destroy the named file, so the write is
/// refused before the file is opened: the target is inspected with
/// `symlink_metadata` and no step creates, truncates or follows
/// through a symlink at the target path.
///
/// The document itself is staged in a sibling temporary file in the
/// target's directory and renamed over the target once complete, so
/// the target holds either nothing or the whole document: a writer
/// that fails or dies mid-write leaves the target empty, and the
/// parent copies out only complete documents. The rename replaces
/// the target directory entry itself, so a target swapped after the
/// inspection is replaced rather than followed.
///
/// # Errors
/// Returns a description of the refusal or write failure; the caller
/// renders it as a loud stderr diagnostic with a failure code.
fn write_diverted_report(path: &Path, report: &str) -> Result<(), String> {
    let refuse = |why: String| {
        format!(
            "refusing the diverted report target {}: {why}",
            path.display()
        )
    };
    let md = std::fs::symlink_metadata(path).map_err(|e| {
        refuse(format!(
            "it cannot be inspected ({e}); the hand-back file exists"
        ))
    })?;
    let file_type = md.file_type();
    if file_type.is_symlink() {
        return Err(refuse(
            "it is a symlink, not the hand-back file".to_string(),
        ));
    }
    if !file_type.is_file() {
        return Err(refuse("it is not a regular file".to_string()));
    }
    if md.len() != 0 {
        return Err(refuse(format!(
            "it already holds {} bytes; the hand-back file starts empty",
            md.len()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if md.permissions().mode() & 0o077 != 0 {
            return Err(refuse(format!(
                "its permissions {:#o} are not owner-only; the hand-back file is",
                md.permissions().mode() & 0o777
            )));
        }
    }
    // Stage the document beside the target and rename it over: the
    // staging file is a `NamedTempFile` in the target's directory (so
    // the rename stays on one filesystem), created exclusively under
    // an unpredictable name with owner-only permissions, and removed
    // on drop whenever it was not renamed away.
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staging = tempfile::NamedTempFile::new_in(dir).map_err(|e| {
        format!(
            "staging the diverted report beside {} failed: {e}",
            path.display()
        )
    })?;
    use std::io::Write;
    staging.write_all(report.as_bytes()).map_err(|e| {
        format!(
            "writing the diverted report for {} failed: {e}",
            path.display()
        )
    })?;
    let (_file, staging_path) = staging.keep().map_err(|e| {
        format!(
            "staging the diverted report beside {} failed: {e}",
            path.display()
        )
    })?;
    std::fs::rename(&staging_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&staging_path);
        format!(
            "delivering the diverted report to {} failed: {e}",
            path.display()
        )
    })
}

/// Parse arguments and run the linter, returning the process exit code.
///
/// Exit-code semantics are part of the frozen compatibility contract (see
/// `docs/DESIGN.md` §4.6); do not change the mapping without a ledger entry.
pub fn run() -> ExitCode {
    // Bare invocation prints help and exits 0 (rpmlint `cli.py:92-94`). clap's
    // `arg_required_else_help` would exit 2, so handle it before parsing.
    if std::env::args_os().count() == 1 {
        let _ = cli_command().print_help();
        println!();
        return ExitCode::SUCCESS;
    }
    let cli = Cli::parse();

    // The reference picks its colour table from stdout's tty-ness and uses it
    // for stderr diagnostics too, so it is needed before the first warning.
    // The child half of a diverted JSON run (#703) has the diversion pipe
    // for stdout, never a terminal, so its table comes from stderr -- the
    // inherited terminal its diagnostics land on -- which reproduces the
    // parent's own decision exactly.
    let color = if cli.diverted_json.is_some() {
        Color::for_tty(std::io::stderr().is_terminal())
    } else {
        Color::for_tty(std::io::stdout().is_terminal())
    };

    // A `--format json` run whose format is settled by the command line
    // alone diverts into its child here, before anything else can print:
    // the parent stays silent, so no diagnostic is emitted twice (#703;
    // see `divert_json_run`). The meta modes (`--print-config`,
    // `--explain`) print to stdout themselves and never divert. A run
    // whose format comes from the config file diverts at the second
    // point in `run`, once the configuration has been loaded.
    if cli.diverted_json.is_none()
        && cli.format.as_deref() == Some("json")
        && !cli.print_config
        && cli.explain.is_empty()
    {
        match divert_json_run() {
            Some(code) => return code,
            None => warn!(
                color,
                "warning: the JSON run could not be diverted; spec output may corrupt the report"
            ),
        }
    }

    // Load configuration. A nonexistent -c path is a usage error (exit 2) with
    // the reference's exact message (`cli.py:_validate_conf_location`).
    for path in &cli.config {
        if !path.exists() {
            warn!(
                color,
                "File or dir with user specified configuration '{}' does not exist",
                path.display()
            );
            return ExitCode::from(2);
        }
    }
    // The load warnings are collected, not printed: if the run diverts
    // at the second point below, the child loads the same configuration
    // and prints its own copies, so printing here as well would double
    // every diagnostic (#703). They are flushed right after the
    // diversion decision, ahead of every later diagnostic, in a run
    // that stays in-process.
    let (mut cfg, load_warnings) = match config::load_with_warnings(&cli.config) {
        Ok(pair) => pair,
        Err((e, warnings)) => {
            // The warnings collected before the failure travel with
            // the error (see `load_with_warnings`): flush them here,
            // ahead of the fatal line, in emission order. This run
            // stays in-process on this path -- a parent that diverted
            // never loads the configuration itself, and a diverted
            // child flushes its own copies the same way.
            for warning in &warnings {
                eprintln!("{warning}");
            }
            warn!(color, "(none): E: fatal error in configuration: {e}");
            return ExitCode::from(1);
        }
    };

    // Second diversion point (#703): the format came from the config
    // file, so it is only known now. The meta modes (`--print-config`,
    // `--explain`) print to stdout themselves and never divert; they
    // return further below, so the decision can sit ahead of them. The
    // parent has printed nothing of its own yet -- no tracing init, no
    // load warnings -- so everything the child prints for this run is
    // emitted exactly once, by the child. (A command-line `--format
    // json` run diverted earlier, before the configuration was even
    // loaded.)
    let format = resolve_output_format(cli.format.as_deref(), &cfg.output_format);
    let mut diversion_fell_through = false;
    if cli.diverted_json.is_none()
        && cli.format.is_none()
        && format == "json"
        && !cli.print_config
        && cli.explain.is_empty()
    {
        match divert_json_run() {
            Some(code) => return code,
            None => diversion_fell_through = true,
        }
    }
    for warning in &load_warnings {
        eprintln!("{warning}");
    }
    if diversion_fell_through {
        warn!(
            color,
            "warning: the JSON run could not be diverted; spec output may corrupt the report"
        );
    }

    // Progress reporting (upstream rpmlint#255): `tracing` events render on
    // stderr, so finding output on stdout is never perturbed. `RUST_LOG`
    // overrides the default filter (see `tracing_filter`). The init sits
    // below both diversion points on purpose: a diverted run's parent
    // never initialises a subscriber (nor prints the invalid-`RUST_LOG`
    // warning in `tracing_filter`), so the child is the only process
    // that can emit those diagnostics for the run (#703).
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(tracing_filter())
        .try_init();

    // Apply mode flags.
    cfg.strict = cli.strict;
    cfg.info = cli.verbose;
    cfg.errors_only = cli.errors_only;
    // Issue #699: permissive is an explicit opt-in only — no config
    // default forces it, so errors fail the run unless `-P` was passed.
    cfg.permissive = cli.permissive;
    cfg.mini_mode = cli.mini_mode;

    if cli.print_config {
        print!(
            "{}",
            toml::to_string_pretty(&cfg.configuration).unwrap_or_default()
        );
        return ExitCode::SUCCESS;
    }
    // `--explain`: print the description for each message id and exit 0
    // without linting anything. The reference loads its checks before
    // explaining, so the check `__init__` descriptions are installed first.
    if !cli.explain.is_empty() {
        let mut filter = match rpmcrab_core::filter::Filter::new(&cfg, color) {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    color,
                    "(none): E: fatal error in configuration filters: {e}"
                );
                return ExitCode::from(1);
            }
        };
        rpmcrab_core::check::register_error_details(&cfg, &mut filter);
        for id in &cli.explain {
            // The reference `print(f'{message}:\n{explanation}')` appends one
            // trailing newline after the block.
            println!("{}", filter.explanation(id, &cfg));
        }
        return ExitCode::SUCCESS;
    }

    // Validate positional paths (missing -> exit 2). This is `cli.py`'s job and
    // it runs before `Lint` is built, which is why an rpmlint package on a
    // non-existent path exits 2 rather than taking the skip path below.
    let files = dedup_files(&cli.files);
    if files.iter().any(|f| !f.exists()) {
        for f in files.iter().filter(|f| !f.exists()) {
            warn!(
                color,
                "The file or directory '{}' does not exist",
                f.display()
            );
        }
        return ExitCode::from(2);
    }

    // rpmlintrc: explicit `-r` files win outright; with none, auto-discovery
    // looks in the configured `RpmlintrcSearchPaths` and then beside every
    // positional argument (rpmlint#1592; issue #830).
    let rc_files = discover_rpmlintrc_files(&cli.rpmlintrc, &cfg.rpmlintrc_search_paths, &files);
    if rc_files.len() > 1 {
        warn!(
            color,
            "There are multiple items to be loaded: {}.",
            rc_files
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    for rc in &rc_files {
        let loaded = config::load_rpmlintrc(&mut cfg, rc);
        // `load_rpmlintrc` re-derives the typed fields (`finalize`), so
        // it can collect fresh load warnings; show this file's before
        // any error it returned, as they were emitted in that order.
        for warning in cfg.take_load_warnings() {
            eprintln!("{warning}");
        }
        if let Err(e) = loaded {
            warn!(
                color,
                "(none): E: error loading rpmlintrc {}: {e}",
                rc.display()
            );
            return ExitCode::from(2);
        }
    }
    // The header's `rpmlintrc:` block lists what was loaded, auto-discovered
    // files included.
    cfg.rpmlintrc_display = rc_files.iter().map(|p| p.display().to_string()).collect();

    // `SkipPackagePatterns` (rpmlint#1592): never lint a matching package,
    // which uses a modified configuration and crashes the old rpmlint-mini.
    let skip = match rpmcrab_core::config::SkipPatterns::new(&cfg) {
        Ok(s) => s,
        Err(e) => {
            warn!(color, "(none): E: fatal error in SkipPackagePatterns: {e}");
            return ExitCode::from(1);
        }
    };
    let mut skip_hit = false;
    for f in &files {
        match skip.matches(&f.to_string_lossy()) {
            Ok(true) => {
                skip_hit = true;
                break;
            }
            Ok(false) => {}
            // A regex engine failure must not quietly un-skip the package.
            Err(e) => {
                warn!(color, "(none): E: fatal error in SkipPackagePatterns: {e}");
                return ExitCode::from(1);
            }
        }
    }
    if skip_hit {
        println!("Skipping rpmlint for rpmlint package!");
        return ExitCode::SUCCESS;
    }

    let start = Instant::now();
    let width = term::terminal_width();
    let checks = rpmcrab_core::check::load(&cfg, cli.checks.as_deref());
    // `--errors-only` (upstream rpmlint#134): an all-warning-only selection
    // would silently run nothing at exit 0; warn instead of staying quiet.
    if checks.is_empty()
        && rpmcrab_core::check::errors_only_dropped(&cfg, cli.checks.as_deref()) > 0
    {
        warn!(
            color,
            "(none): W: --errors-only skipped every selected check, nothing to run"
        );
    }
    let mut lint = match Lint::new(cfg, checks, color, width) {
        Ok(l) => l,
        Err(e) => {
            warn!(
                color,
                "(none): E: fatal error in configuration filters: {e}"
            );
            return ExitCode::from(1);
        }
    };
    lint.set_audit_rpmlintrc(!cli.ignore_unused_rpmlintrc);

    // `-j` coerces non-positive values to 1 (`rpmlint#1595`).
    let jobs = cli.jobs.max(1) as usize;
    // Each worker builds its own check set from the same selection. The
    // config is cloned once here so the factory does not borrow `lint`.
    let worker_config = lint.config().clone();
    let selected = cli.checks.clone();
    let make_checks = move || rpmcrab_core::check::load(&worker_config, selected.as_deref());

    // `Lint.validate_files`: expand the arguments, then sort so the output is
    // stable regardless of the order they were given in.
    let mut inputs = expand_filelist(&files);
    inputs.sort();
    let file_tasks: Vec<rpmcrab_core::worker::Task> = inputs
        .into_iter()
        .map(rpmcrab_core::worker::Task::File)
        .collect();

    // Installed packages are enumerated once up front; each becomes a task
    // holding its opened `Pkg` (`_installed_tasks`, `rpmlint#1595`).
    let mut installed_tasks = Vec::new();
    // `Lint.validate_installed_packages` runs the post-checks for the
    // installed batch only when there are no plain rpm/spec arguments
    // (`lint.py:248`).
    let mut installed_post_checks = false;
    if !cli.installed.is_empty() {
        installed_post_checks = files.is_empty();
        // Enumerated once up front for the missing-name warnings; each
        // worker re-queries per name (cached) because the rpmdb handle cannot
        // cross threads (`_installed_tasks`, `rpmlint#1595`).
        for name in &cli.installed {
            match rpmcrab_core::pkg::installed::find_installed(std::slice::from_ref(name)) {
                Ok((headers, missing)) => {
                    for missing in &missing {
                        warn!(color, "(none): E: there is no installed rpm \"{missing}\".");
                    }
                    for (index, _) in headers.iter().enumerate() {
                        installed_tasks.push(rpmcrab_core::worker::Task::Installed {
                            name: name.clone(),
                            index,
                        });
                    }
                }
                // Deliberate divergence: the reference lets a failed
                // `rpmtsOpenDB` raise, so it dies with a Python traceback.
                // One line and exit 1 carries the same information to a shell
                // user.
                Err(e) => {
                    warn!(color, "(none): E: fatal error reading the rpmdb: {e}");
                    return ExitCode::from(1);
                }
            }
        }
    }

    // Check installed packages first and then files; `after_checks` runs once
    // per batch so post checks see a consistent state (`rpmlint#1595`).
    // A fatal per-package error is reported and the run continues, failing
    // with exit code 3 only after everything is reported.
    lint.check_batch(installed_tasks, jobs, &make_checks, installed_post_checks);
    for fatal in lint.take_fatals() {
        warn!(color, "{fatal}");
    }
    lint.check_batch(file_tasks, jobs, &make_checks, true);
    for fatal in lint.take_fatals() {
        warn!(color, "{fatal}");
    }

    // The `setBadness` occurrences recorded at rpmlintrc load are
    // reported once, after all batches, on the last processed package.
    // The report is not gated by `--ignore-unused-rpmlintrc`: that flag
    // suppresses only the unused-filter audit below.
    lint.report_rpmlintrc_setbadness();

    // The unused-rpmlintrc-filter audit runs once, after all batches, on the
    // last processed package.
    lint.audit_unused_filters();

    // A `[SeverityOverrides]` name that never matched an emitted finding is
    // almost certainly a typo. Warned on stderr, not as a finding, so a typo
    // cannot perturb the findings or the exit code.
    for name in lint.unused_severity_overrides() {
        warn!(
            color,
            "warning: unused [SeverityOverrides] entry {name:?}: no finding with that name was emitted"
        );
    }

    // `Lint.validate_files`: with no file arguments and nothing validated from
    // `-i`, there is nothing to do (`lint.py:257-262`).
    if files.is_empty() && lint.packages_checked() == 0 {
        warn!(
            color,
            "There are no files to process nor additional arguments."
        );
        warn!(color, "Nothing to do, aborting.");
    }

    // The header counts CLI args (files + installed); the footer counts the
    // inputs that were actually validated.
    let arg_count = files.len() + cli.installed.len();
    let duration = start.elapsed().as_secs_f64();
    // The session banner identifies rpmcrab itself, not the emulated
    // reference (docs/DESIGN.md §4.5).
    let prog = "rpmcrab";
    // `--format` dispatches through the pluggable renderers (text/json);
    // the text wire format is untouched, and the time report stays a
    // text-mode section. It is on by default (`-t`/`--time-report` remain
    // as explicit opt-ins); `--no-time-report` disables it. The two flags
    // conflict, so the opt-out alone decides.
    let show_time_report = !cli.no_time_report;
    let out = lint.render_report(
        &format,
        prog,
        RPMLINT_VERSION,
        arg_count,
        show_time_report,
        duration,
    );
    // The child half of a diverted JSON run (#703) writes the document
    // to the hand-back file named by `--__diverted-json` instead of
    // stdout; the parent copies it to the real stdout once the run is
    // over. A failed write is loud -- an error on stderr and a failure
    // code -- never a fallback print into the diverted stream, which
    // would silently deliver no document at all.
    if let Some(path) = &cli.diverted_json
        && format == "json"
    {
        return match write_diverted_report(path, &out) {
            Ok(()) => ExitCode::from(u8::try_from(lint.exit_code()).unwrap_or(1)),
            Err(e) => {
                eprintln!("(none): E: writing the JSON report failed: {e}");
                ExitCode::from(1)
            }
        };
    }
    print!("{out}");
    ExitCode::from(u8::try_from(lint.exit_code()).unwrap_or(1))
}

/// `Lint._find_rpmlintrc_files`: `*.rpmlintrc` first, then `*-rpmlintrc`, each
/// group sorted. Both patterns are a bare suffix in a single directory, which
/// `fnmatch` and `Path.glob` reduce to.
/// Auto-discover rpmlintrc files: explicit `-r` files win outright; with
/// none, look in each configured `RpmlintrcSearchPaths` directory
/// (rpmlint#1592), then beside every positional argument: a file argument
/// contributes its directory (a bare file name the current directory), a
/// directory argument contributes itself. The beside-argument lookup runs
/// only when the search paths found nothing; each directory is listed
/// once, however many arguments name it and however it is spelled, and
/// the results are deduplicated by path, so an rpmlintrc shared by
/// several arguments loads once. Looking beside every argument diverges
/// from the reference's lone-argument lookup (`lint.py:198-224`); the
/// divergence is recorded in `tests/parity/divergences.toml` (#830).
fn discover_rpmlintrc_files(
    explicit: &[PathBuf],
    search_paths: &[String],
    positional: &[PathBuf],
) -> Vec<PathBuf> {
    let mut rc_files: Vec<PathBuf> = explicit.to_vec();
    if rc_files.is_empty() {
        for dir in search_paths {
            rc_files.extend(find_rpmlintrc_files(Path::new(dir)));
        }
        // Every positional argument also looks next to itself, so that
        // `rpmlint foo.spec bar.spec` picks up both `foo.rpmlintrc` and
        // `bar.rpmlintrc`.
        if rc_files.is_empty() {
            let mut visited: Vec<PathBuf> = Vec::new();
            for arg in positional {
                let mut dir = arg.clone();
                if !dir.is_dir() {
                    dir.pop();
                }
                if dir.as_os_str().is_empty() {
                    dir = PathBuf::from(".");
                }
                // Equivalent spellings of a directory (a bare name
                // beside `./name`, a path through a symlink)
                // canonicalise to the same visited key, so the
                // directory is listed once.
                let key = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
                if visited.contains(&key) {
                    continue;
                }
                visited.push(key);
                for rc in find_rpmlintrc_files(&dir) {
                    if !rc_files.contains(&rc) {
                        rc_files.push(rc);
                    }
                }
            }
        }
    }
    rc_files
}

fn find_rpmlintrc_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let names: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    let mut out = Vec::new();
    for suffix in [".rpmlintrc", "-rpmlintrc"] {
        let mut group: Vec<PathBuf> = names
            .iter()
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().ends_with(suffix))
            })
            .cloned()
            .collect();
        group.sort();
        out.extend(group);
    }
    out
}

/// `cli.process_lint_args`: deduplicate the positional arguments, as the
/// reference's `set` does, so naming the same package twice validates it once.
///
/// The reference also expands a `*`/`?` glob in any path component before this
/// (`cli.py:103-120`); rpmcrab takes such an argument literally, which is
/// recorded in `tests/parity/divergences.toml`. `Path::glob` is nightly-only
/// and hand-rolling `**`/`[...]`/escaping is a parsing surface that deserves
/// its own change with golden tests.
fn dedup_files(files: &[PathBuf]) -> Vec<PathBuf> {
    files
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// `Lint._expand_filelist`: a directory expands to the packages beneath it, and
/// only `.rpm`, `.spm` and `.spec` files are kept.
fn expand_filelist(files: &[PathBuf]) -> Vec<PathBuf> {
    let mut packages = Vec::new();
    for path in files {
        if path.is_file() && has_package_suffix(path) {
            packages.push(path.clone());
        } else if path.is_dir() {
            let Ok(entries) = std::fs::read_dir(path) else {
                continue;
            };
            let nested: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
            packages.extend(expand_filelist(&nested));
        }
    }
    packages
}

fn has_package_suffix(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| matches!(e.to_string_lossy().as_ref(), "rpm" | "spm" | "spec"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_rpmlintrc_reads_configured_search_paths() {
        // Production code must READ `RpmlintrcSearchPaths`: an rpmlintrc
        // file in a configured directory is discovered without `-r`.
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join("test.rpmlintrc");
        std::fs::write(&rc, "addFilter('x')\n").unwrap();
        let found =
            discover_rpmlintrc_files(&[], &[dir.path().to_string_lossy().into_owned()], &[]);
        assert_eq!(found, vec![rc]);
    }

    #[test]
    fn discover_rpmlintrc_explicit_wins_over_search_paths() {
        // Explicit `-r` files win outright; search paths are not consulted.
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join("test.rpmlintrc");
        std::fs::write(&rc, "addFilter('x')\n").unwrap();
        let explicit = PathBuf::from("/nonexistent/explicit.rpmlintrc");
        let found = discover_rpmlintrc_files(
            std::slice::from_ref(&explicit),
            &[dir.path().to_string_lossy().into_owned()],
            &[],
        );
        assert_eq!(found, vec![explicit]);
    }

    #[test]
    fn discover_rpmlintrc_falls_back_to_positional_dir() {
        // No explicit files and empty search paths: look beside the
        // positional argument.
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("foo.spec");
        std::fs::write(&pkg, "Name: foo\n").unwrap();
        let rc = dir.path().join("foo.rpmlintrc");
        std::fs::write(&rc, "addFilter('x')\n").unwrap();
        let found = discover_rpmlintrc_files(&[], &[], &[pkg]);
        assert_eq!(found, vec![rc]);
    }

    #[test]
    fn discover_rpmlintrc_looks_beside_every_positional() {
        // Issue #830: with several positional arguments, each one's
        // directory is consulted, in argument order.
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let pkg_a = dir_a.path().join("aaa.spec");
        let pkg_b = dir_b.path().join("bbb.spec");
        std::fs::write(&pkg_a, "Name: aaa\n").unwrap();
        std::fs::write(&pkg_b, "Name: bbb\n").unwrap();
        let rc_a = dir_a.path().join("aaa.rpmlintrc");
        let rc_b = dir_b.path().join("bbb-rpmlintrc");
        std::fs::write(&rc_a, "addFilter('x')\n").unwrap();
        std::fs::write(&rc_b, "addFilter('y')\n").unwrap();
        let found = discover_rpmlintrc_files(&[], &[], &[pkg_b, pkg_a]);
        assert_eq!(found, vec![rc_b, rc_a]);
    }

    #[test]
    fn discover_rpmlintrc_deduplicates_equivalent_dir_spellings() {
        // The same directory spelled two ways -- a plain argument path
        // and the `./`-spelled path of a sibling argument -- is listed
        // once: the shared rpmlintrc comes back once, so it loads once.
        let dir = tempfile::tempdir().unwrap();
        let pkg_a = dir.path().join("aaa.spec");
        let pkg_b = dir.path().join("./bbb.spec");
        std::fs::write(&pkg_a, "Name: aaa\n").unwrap();
        std::fs::write(dir.path().join("bbb.spec"), "Name: bbb\n").unwrap();
        let rc = dir.path().join("shared.rpmlintrc");
        std::fs::write(&rc, "addFilter('x')\n").unwrap();
        let found = discover_rpmlintrc_files(&[], &[], &[pkg_a, pkg_b]);
        assert_eq!(found, vec![rc]);
    }

    #[test]
    fn discover_rpmlintrc_deduplicates_a_shared_rc() {
        // Two arguments in one directory share its rpmlintrc files: each
        // discovered file is returned once, so it loads once.
        let dir = tempfile::tempdir().unwrap();
        let pkg_a = dir.path().join("aaa.spec");
        let pkg_b = dir.path().join("bbb.spec");
        std::fs::write(&pkg_a, "Name: aaa\n").unwrap();
        std::fs::write(&pkg_b, "Name: bbb\n").unwrap();
        let rc = dir.path().join("shared.rpmlintrc");
        std::fs::write(&rc, "addFilter('x')\n").unwrap();
        let found = discover_rpmlintrc_files(&[], &[], &[pkg_a, pkg_b]);
        assert_eq!(found, vec![rc]);
    }

    #[test]
    fn discover_rpmlintrc_beside_a_directory_argument_reads_inside_it() {
        // A directory argument contributes itself: the rpmlintrc files
        // inside it are discovered, for any number of arguments.
        let dir = tempfile::tempdir().unwrap();
        let inner = dir.path().join("tree");
        std::fs::create_dir(&inner).unwrap();
        let rc = inner.join("tree.rpmlintrc");
        std::fs::write(&rc, "addFilter('x')\n").unwrap();
        let other = dir.path().join("other.spec");
        std::fs::write(&other, "Name: other\n").unwrap();
        let found = discover_rpmlintrc_files(&[], &[], &[other, inner]);
        assert_eq!(found, vec![rc]);
    }

    #[test]
    fn discover_rpmlintrc_search_paths_win_over_positional_dirs() {
        // A search-path hit suppresses the beside-argument lookup
        // entirely, however many positional arguments there are.
        let search = tempfile::tempdir().unwrap();
        let search_rc = search.path().join("search.rpmlintrc");
        std::fs::write(&search_rc, "addFilter('x')\n").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("foo.spec");
        std::fs::write(&pkg, "Name: foo\n").unwrap();
        let beside_rc = dir.path().join("foo.rpmlintrc");
        std::fs::write(&beside_rc, "addFilter('y')\n").unwrap();
        let found =
            discover_rpmlintrc_files(&[], &[search.path().to_string_lossy().into_owned()], &[pkg]);
        assert_eq!(found, vec![search_rc]);
    }

    #[test]
    fn resolve_output_format_matrix() {
        // The CLI flag wins outright; otherwise the config key decides.
        assert_eq!(resolve_output_format(Some("json"), "text"), "json");
        assert_eq!(resolve_output_format(Some("text"), "json"), "text");
        assert_eq!(resolve_output_format(None, "json"), "json");
        assert_eq!(resolve_output_format(None, "text"), "text");
    }

    /// `Lint._expand_filelist` keeps only the three package suffixes and
    /// recurses into directories, in `readdir` order.
    #[test]
    fn expand_filelist_walks_directories_and_keeps_package_suffixes() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        for name in ["a.rpm", "b.spec", "c.spm", "notes.txt", "Makefile"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        std::fs::write(nested.join("deep.rpm"), b"x").unwrap();

        let found = expand_filelist(&[dir.path().to_path_buf()]);
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 4, "got {names:?}");
        for expected in ["a.rpm", "b.spec", "c.spm", "deep.rpm"] {
            assert!(
                names.iter().any(|n| n == expected),
                "missing {expected} in {names:?}"
            );
        }
        assert!(!names.iter().any(|n| n == "notes.txt" || n == "Makefile"));
    }

    #[test]
    fn a_file_that_is_not_a_package_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let txt = dir.path().join("notes.txt");
        std::fs::write(&txt, b"x").unwrap();
        assert!(expand_filelist(&[txt]).is_empty());
    }

    /// `SkipPackagePatterns`: `re.search` semantics — unanchored, and `\d`
    /// Unicode-aware exactly as in Python (fancy-regex). Every case here was
    /// checked against CPython `re.search`.
    #[test]
    fn skip_package_patterns_match_the_rpmlint_package() {
        use rpmcrab_core::config::{Config, SkipPatterns};
        let cfg = Config {
            skip_package_patterns: vec![
                r"/home/abuild/rpmbuild/RPMS/noarch/rpmlint-\d".to_string(),
            ],
            ..Config::default()
        };
        let skip = SkipPatterns::new(&cfg).expect("pattern compiles");
        for hit in [
            "/mnt/home/abuild/rpmbuild/RPMS/noarch/rpmlint-2.10.0.noarch.rpm",
            "./home/abuild/rpmbuild/RPMS/noarch/rpmlint-3.noarch.rpm",
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-2.10.0.noarch.rpm.bak",
            // `\d` is Unicode-aware in Python; `\u{0661}` is an Arabic-Indic digit.
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-\u{0661}.noarch.rpm",
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-2.10.0.noarch.rpm",
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-1.x86_64.rpm",
        ] {
            assert!(skip.matches(hit).expect("match"), "{hit} should match");
        }
        for miss in [
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-.noarch.rpm",
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-noarch.rpm",
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-x.noarch.rpm",
            "/home/abuild/rpmbuild/RPMS/x86_64/rpmlint-2.rpm",
            "/srv/rpms/rpmlint-2.10.0.noarch.rpm",
            "/home/abuild/rpmbuild/RPMS/noarch/foo-2.rpm",
            // The old `is_numeric` superset skipped this; the reference lints
            // it, because Python `\d` matches decimal digits only.
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-\u{b2}.noarch.rpm",
        ] {
            assert!(
                !skip.matches(miss).expect("match"),
                "{miss} should not match"
            );
        }
    }

    /// A bad `SkipPackagePatterns` entry is a fatal configuration error, as
    /// the reference's bare `re.compile` raises.
    #[test]
    fn skip_package_patterns_reject_a_bad_pattern() {
        use rpmcrab_core::config::{Config, SkipPatterns};
        let cfg = Config {
            skip_package_patterns: vec!["([".to_string()],
            ..Config::default()
        };
        assert!(SkipPatterns::new(&cfg).is_err());
    }

    /// An empty `SkipPackagePatterns` entry would match every path, turning
    /// the run into a no-op that prints the skip message and exits 0.
    #[test]
    fn skip_package_patterns_reject_an_empty_pattern() {
        use rpmcrab_core::config::{Config, SkipPatterns};
        let cfg = Config {
            skip_package_patterns: vec!["".to_string()],
            ..Config::default()
        };
        match SkipPatterns::new(&cfg) {
            Ok(_) => panic!("empty pattern must fail"),
            Err(e) => assert!(e.contains("empty"), "got {e}"),
        }
    }

    /// The bundled `SkipPackagePatterns` default must be the reference's
    /// `\d` (decimal digits only), not the old `is_numeric` superset.
    /// Guards against a regression to `\p{N}` in configdefaults.toml.
    #[test]
    fn bundled_skip_pattern_matches_the_reference_semantics() {
        use rpmcrab_core::config::{self, SkipPatterns};
        let cfg = config::load_bundled();
        let skip = SkipPatterns::new(&cfg).expect("bundled pattern compiles");
        // The reference lints these (\d is decimal-digits-only).
        assert!(
            skip.matches("/home/abuild/rpmbuild/RPMS/noarch/rpmlint-2.10.0.noarch.rpm")
                .expect("match"),
            "bundled default must skip rpmlint-2..."
        );
        // The old is_numeric superset skipped these; the reference lints them.
        assert!(
            !skip
                .matches("/home/abuild/rpmbuild/RPMS/noarch/rpmlint-\u{b2}.noarch.rpm")
                .expect("match"),
            "bundled default must NOT skip rpmlint-\u{b2} (superscript two)"
        );
    }
}

#[cfg(test)]
mod rpmlintrc_tests {
    use super::*;

    /// `*.rpmlintrc` then `*-rpmlintrc`, each group sorted, so the order is
    /// stable and the two groups do not interleave.
    #[test]
    fn rpmlintrc_discovery_orders_the_two_patterns_separately() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "zeta.rpmlintrc",
            "alpha.rpmlintrc",
            "b-rpmlintrc",
            "a-rpmlintrc",
            "unrelated.toml",
            "rpmlintrc",
        ] {
            std::fs::write(dir.path().join(name), b"addFilter(r\"x\")\n").unwrap();
        }
        let found = find_rpmlintrc_files(dir.path());
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                "alpha.rpmlintrc",
                "zeta.rpmlintrc",
                "a-rpmlintrc",
                "b-rpmlintrc"
            ]
        );
    }

    #[test]
    fn rpmlintrc_discovery_of_a_missing_directory_is_empty() {
        assert!(find_rpmlintrc_files(Path::new("/no/such/dir")).is_empty());
    }

    /// A directory called `foo.rpmlintrc` is not a file, so it is skipped.
    #[test]
    fn rpmlintrc_discovery_skips_directories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("trap.rpmlintrc")).unwrap();
        assert!(find_rpmlintrc_files(dir.path()).is_empty());
    }

    /// Naming a package twice validates it once: the reference collects the
    /// arguments into a `set` (`cli.py:101,117`).
    #[test]
    fn repeated_arguments_are_deduplicated() {
        let files = vec![
            PathBuf::from("a.rpm"),
            PathBuf::from("b.rpm"),
            PathBuf::from("a.rpm"),
        ];
        assert_eq!(
            dedup_files(&files),
            vec![PathBuf::from("a.rpm"), PathBuf::from("b.rpm")]
        );
        assert!(dedup_files(&[]).is_empty());
    }

    /// A glob is not expanded yet (ledgered), so it is carried through and then
    /// rejected as a missing path, exactly as a literal would be.
    #[test]
    fn a_glob_argument_is_taken_literally_for_now() {
        let files = vec![PathBuf::from("*.rpm")];
        assert_eq!(dedup_files(&files), vec![PathBuf::from("*.rpm")]);
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::Parser;

    // --info is the reference rpmlint long name for --verbose; rpmcrab must
    // accept it as a drop-in replacement (OBS invokes rpmlint --info).
    #[test]
    fn info_alias_sets_verbose() {
        let cli = Cli::try_parse_from(["rpmcrab", "--info", "x.rpm"]).unwrap();
        assert!(cli.verbose);
    }

    // --verbose keeps working alongside the new alias.
    #[test]
    fn verbose_long_still_sets_verbose() {
        let cli = Cli::try_parse_from(["rpmcrab", "--verbose", "x.rpm"]).unwrap();
        assert!(cli.verbose);
    }

    // The short flag is unaffected.
    #[test]
    fn verbose_short_still_sets_verbose() {
        let cli = Cli::try_parse_from(["rpmcrab", "-v", "x.rpm"]).unwrap();
        assert!(cli.verbose);
    }
}
