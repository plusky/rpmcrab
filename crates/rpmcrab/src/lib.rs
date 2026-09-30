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
    // looks in the two OBS SOURCES directories and then beside a single
    // positional argument (`lint.py:198-224`).
    let mut rc_files = cli.rpmlintrc.clone();
    if rc_files.is_empty() {
        for dir in ["/home/abuild/rpmbuild/SOURCES", "/usr/src/packages/SOURCES"] {
            rc_files.extend(find_rpmlintrc_files(Path::new(dir)));
        }
        // A lone positional argument also looks next to itself, so that
        // `rpmlint foo.spec` picks up `foo.rpmlintrc`.
        if rc_files.is_empty() && files.len() == 1 {
            let mut arg = files[0].clone();
            if arg.is_file() {
                arg.pop();
            }
            rc_files.extend(find_rpmlintrc_files(&arg));
        }
    }
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

    // `Lint.rpmlint_package`: never lint an rpmlint package, which uses a
    // modified configuration and crashes the old rpmlint-mini (`lint.py:26,63-66`).
    if files.iter().any(|f| is_rpmlint_package(f)) {
        println!("Skipping rpmlint for rpmlint package!");
        return ExitCode::SUCCESS;
    }

    let start = Instant::now();
    let width = term::terminal_width();
    let checks = rpmcrab_core::check::load(&cfg, cli.checks.as_deref());
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
    let extract_dir = lint.config().extract_dir();

    // `Lint.validate_files`: expand the arguments, then sort so the output is
    // stable regardless of the order they were given in.
    let mut inputs = expand_filelist(&files);
    inputs.sort();

    // `Lint.validate_installed_packages` runs the installed packages in
    // argument order, and only runs the post-checks when there are no plain
    // rpm/spec arguments (`lint.py:248`).
    if !cli.installed.is_empty() {
        match rpmcrab_core::pkg::installed::find_installed(&cli.installed) {
            Ok((headers, missing)) => {
                for name in &missing {
                    warn!(color, "(none): E: there is no installed rpm \"{name}\".");
                }
                // The plain-file run owns the `is_last` pass when there is one.
                // `not bool(self.options['rpmfile'])` — the positional
                // arguments, not the packages they expanded to
                // (`lint.py:248`).
                let run_post_checks = files.is_empty();
                let last = headers.len().saturating_sub(1);
                // One `Pkg` at a time: building one walks every file it
                // declares, so a glob like `lib*` would otherwise hold
                // hundreds of fully-expanded packages at once.
                for (i, header) in headers.into_iter().enumerate() {
                    // An installed package is read the same way as a file, so a
                    // header that will not decode fails here too. The
                    // reference has no guard around installed packages and
                    // dies with a traceback, so the status is 1 rather than
                    // the 3 a file gets.
                    let pkg = match rpmcrab_core::pkg::Pkg::installed(header) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(color, "(none): E: fatal error reading the rpmdb: {e}");
                            return ExitCode::from(1);
                        }
                    };
                    lint.run_package(
                        &mut rpmcrab_core::pkg::Package::Rpm(Box::new(pkg)),
                        run_post_checks && i == last,
                    );
                }
            }
            // Deliberate divergence: the reference lets a failed `rpmtsOpenDB`
            // raise, so it dies with a Python traceback. One line and exit 1
            // carries the same information to a shell user.
            Err(e) => {
                warn!(color, "(none): E: fatal error reading the rpmdb: {e}");
                return ExitCode::from(1);
            }
        }
    }

    let last = inputs.len().saturating_sub(1);
    for (i, path) in inputs.iter().enumerate() {
        // `Lint.validate_file`: a `.spec` input is read through `FakePkg`
        // and runs each check's `check_spec` (`lint.py:289-291,300-304`).
        let mut package = if path.extension().is_some_and(|e| e == "spec") {
            match rpmcrab_core::pkg::spec::SpecPkg::open(path) {
                Ok(p) => rpmcrab_core::pkg::Package::Spec(p),
                Err(e) => {
                    warn!(
                        color,
                        "(none): E: fatal error while reading {}: {e}",
                        path.display()
                    );
                    if cli.verbose {
                        print_error_chain(&color, &e);
                        return ExitCode::from(1);
                    }
                    return ExitCode::from(3);
                }
            }
        } else {
            // `Lint.validate_file`: any failure to read the package is fatal, and
            // `-v` re-raises, so the user sees the whole cause chain the way a
            // Python traceback would (`lint.py:293-297`).
            match rpmcrab_core::pkg::Pkg::open(path, &extract_dir) {
                Ok(p) => rpmcrab_core::pkg::Package::Rpm(Box::new(p)),
                Err(e) => {
                    warn!(
                        color,
                        "(none): E: fatal error while reading {}: {e}",
                        path.display()
                    );
                    if cli.verbose {
                        print_error_chain(&color, &e);
                        return ExitCode::from(1);
                    }
                    return ExitCode::from(3);
                }
            }
        };
        lint.run_package(&mut package, i == last);
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
    let out = lint.render(
        &prog,
        RPMLINT_VERSION,
        arg_count,
        cli.time_report,
        cli.profile,
        duration,
    );
    print!("{out}");
    ExitCode::from(u8::try_from(lint.exit_code()).unwrap_or(1))
}

/// `Lint._find_rpmlintrc_files`: `*.rpmlintrc` first, then `*-rpmlintrc`, each
/// group sorted. Both patterns are a bare suffix in a single directory, which
/// `fnmatch` and `Path.glob` reduce to.
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

/// The cause chain, deepest last, as a re-raised Python exception would print
/// it. `-v` uses this instead of a bare exit code, so the underlying error is
/// visible rather than swallowed.
fn print_error_chain(color: &Color, err: &dyn std::error::Error) {
    let mut current = err.source();
    while let Some(cause) = current {
        warn!(color, "caused by: {cause}");
        current = cause.source();
    }
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

/// `Lint.rpmlint_package`: `re.search(r'/home/abuild/rpmbuild/RPMS/noarch/rpmlint-\d')`.
///
/// The search is **unanchored**, so the pattern matches anywhere in the path,
/// and Python's `\d` is Unicode-aware, so the digit test is too. Python's `\d`
/// matches only decimal digits while `is_numeric` accepts every Unicode
/// numeric, so this is a deliberate superset: `rpmlint-².rpm` is guard-skipped
/// here and linted by the reference. std has no precise decimal-digit
/// predicate, and the difference cannot occur in a real package path.
fn is_rpmlint_package(path: &Path) -> bool {
    let s = path.to_string_lossy();
    const PATTERN: &str = "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-";
    s.match_indices(PATTERN).any(|(i, m)| {
        s[i + m.len()..]
            .chars()
            .next()
            .is_some_and(|c| c.is_numeric())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// `re.search(r'/home/abuild/rpmbuild/RPMS/noarch/rpmlint-\d')` — the
    /// search is unanchored, so any path containing the pattern matches, and
    /// `\d` is Unicode-aware, so a non-ASCII decimal digit counts. Every case
    /// here was checked against CPython `re.search`.
    #[test]
    fn rpmlint_package_pattern() {
        for hit in [
            // Unanchored: the guard exists for unexpected layouts, so a match
            // anywhere in the path counts, not only at the start.
            "/mnt/home/abuild/rpmbuild/RPMS/noarch/rpmlint-2.10.0.noarch.rpm",
            "./home/abuild/rpmbuild/RPMS/noarch/rpmlint-3.noarch.rpm",
            // The pattern is not anchored at the end either: a suffix after the
            // digit is fine, because the regex only needs the first digit.
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-2.10.0.noarch.rpm.bak",
            // `\d` is Unicode-aware in Python; `١` is an Arabic-Indic digit.
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-\u{0661}.noarch.rpm",
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-2.10.0.noarch.rpm",
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-1.x86_64.rpm",
        ] {
            assert!(is_rpmlint_package(Path::new(hit)), "{hit} should match");
        }
        for miss in [
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-.noarch.rpm",
            // The pattern must be followed by a digit, not merely present.
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-noarch.rpm",
            "/home/abuild/rpmbuild/RPMS/noarch/rpmlint-x.noarch.rpm",
            "/home/abuild/rpmbuild/RPMS/x86_64/rpmlint-2.rpm",
            "/srv/rpms/rpmlint-2.10.0.noarch.rpm",
            "/home/abuild/rpmbuild/RPMS/noarch/foo-2.rpm",
        ] {
            assert!(
                !is_rpmlint_package(Path::new(miss)),
                "{miss} should not match"
            );
        }
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
