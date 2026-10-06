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

/// The rpmlint version rpmcrab emulates in the session banner. The banner is
/// frozen (`rpmlint: X.Y.Z`); the version shown is the reference version, not
/// the crate version (`docs/DESIGN.md` §4.5). The crate's own version is
/// separate (`rpmcrab --version`).
const RPMLINT_VERSION: &str = "2.10.0";

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
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::SetTrue)]
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
}

/// `-j/--jobs` default: the reference uses `os.cpu_count() or 1`
/// (`cli.py`), so this is the machine's parallelism with a fallback of 1.
fn default_jobs() -> i32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(1)
}

/// Resolve effective permissive mode from CLI flags and the
/// `PermissiveByDefault` config key (rpmlint#1592).
///
/// `--permissive` wins outright; otherwise permissive applies unless
/// `--strict` was passed and the config default is off. This is the
/// production expression previously inline in `run()`; the
/// `render_llvm21_gold` test re-derived it by hand, so it gets its own
/// unit tests here.
fn resolve_permissive(cli_permissive: bool, cli_strict: bool, permissive_by_default: bool) -> bool {
    cli_permissive || (!cli_strict && permissive_by_default)
}

/// Resolve the effective output format: the CLI `--format` wins outright,
/// otherwise the `OutputFormat` config key decides (`"text"` default).
fn resolve_output_format(cli_format: Option<&str>, config_format: &str) -> String {
    cli_format.unwrap_or(config_format).to_string()
}

/// The clap `Command` for the `rpmcrab` binary, shared by `main.rs` and the
/// `rpmcrab-gen` asset generator so the man page and shell completions can
/// never drift from the shipped CLI.
pub fn cli_command() -> clap::Command {
    use clap::CommandFactory;
    Cli::command()
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
    let color = Color::for_tty(std::io::stdout().is_terminal());

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
    let mut cfg = config::load(&cli.config);

    // Apply mode flags.
    cfg.strict = cli.strict;
    cfg.info = cli.verbose;
    cfg.errors_only = cli.errors_only;
    // rpmlint#1592: `--permissive` only when asked; otherwise the
    // `PermissiveByDefault` config key decides (openSUSE runs permissive).
    cfg.permissive = resolve_permissive(cli.permissive, cli.strict, cfg.permissive_by_default);
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
        let mut filter =
            rpmcrab_core::filter::Filter::new(&cfg, color).expect("filter regexes are valid");
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
    // looks in the configured `RpmlintrcSearchPaths` and then beside a
    // single positional argument (`lint.py:198-224`, rpmlint#1592).
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
        if let Err(e) = config::load_rpmlintrc(&mut cfg, rc) {
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
    // The session banner is parameterized by argv[0]'s basename so the
    // binary can be installed as `rpmlint` (docs/DESIGN.md §5).
    let prog = std::env::args_os()
        .next()
        .and_then(|p| {
            Path::new(&p)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "rpmlint".to_string());
    let format = resolve_output_format(cli.format.as_deref(), &lint.config().output_format);
    // `--format` dispatches through the pluggable renderers (text/json);
    // the text wire format is untouched, and `--time-report` stays a
    // text-mode section.
    let out = lint.render_report(
        &format,
        &prog,
        RPMLINT_VERSION,
        arg_count,
        cli.time_report,
        duration,
    );
    print!("{out}");
    ExitCode::from(u8::try_from(lint.exit_code()).unwrap_or(1))
}

/// `Lint._find_rpmlintrc_files`: `*.rpmlintrc` first, then `*-rpmlintrc`, each
/// group sorted. Both patterns are a bare suffix in a single directory, which
/// `fnmatch` and `Path.glob` reduce to.
/// Auto-discover rpmlintrc files: explicit `-r` files win outright; with
/// none, look in each configured `RpmlintrcSearchPaths` directory
/// (rpmlint#1592), then beside a lone positional argument
/// (`lint.py:198-224`).
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
        // A lone positional argument also looks next to itself, so that
        // `rpmlint foo.spec` picks up `foo.rpmlintrc`.
        if rc_files.is_empty() && positional.len() == 1 {
            let mut arg = positional[0].clone();
            if arg.is_file() {
                arg.pop();
            }
            rc_files.extend(find_rpmlintrc_files(&arg));
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
        // No explicit files and empty search paths: look beside the lone
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
    fn resolve_output_format_matrix() {
        // The CLI flag wins outright; otherwise the config key decides.
        assert_eq!(resolve_output_format(Some("json"), "text"), "json");
        assert_eq!(resolve_output_format(Some("text"), "json"), "text");
        assert_eq!(resolve_output_format(None, "json"), "json");
        assert_eq!(resolve_output_format(None, "text"), "text");
    }

    #[test]
    fn resolve_permissive_matrix() {
        // (cli_permissive, cli_strict, permissive_by_default) -> effective.
        // `--permissive` always wins; `--strict` beats the config default;
        // otherwise the default decides.
        let cases = [
            (false, false, false, false),
            (false, false, true, true),
            (false, true, false, false),
            (false, true, true, false),
            (true, false, false, true),
            (true, false, true, true),
            (true, true, false, true),
            (true, true, true, true),
        ];
        for (cli_p, cli_s, def, expected) in cases {
            assert_eq!(
                resolve_permissive(cli_p, cli_s, def),
                expected,
                "cli_permissive={cli_p} cli_strict={cli_s} default={def}"
            );
        }
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
