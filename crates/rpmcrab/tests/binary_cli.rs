//! Exit-code gates for the `rpmcrab` binary (`docs/DESIGN.md` §4.6). These
//! drive the real executable so the CLI parsing and the process exit code are
//! proven as a unit.

use std::path::Path;
use std::process::Command;

fn rpmcrab(args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rpmcrab"));
    cmd.args(args)
        // Hermetic: no XDG auto-load, no colour, no ambient COLUMNS.
        .env("CONFIG_DISABLE_AUTOLOADING", "1")
        .env_remove("COLUMNS")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR");
    cmd.output().expect("spawn rpmcrab")
}

#[test]
fn bare_invocation_prints_help_and_exits_zero() {
    let out = rpmcrab(&[]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Check for common problems in rpm packages") || stdout.contains("Usage")
    );
}

#[test]
fn version_exits_zero() {
    let out = rpmcrab(&["--version"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("rpmcrab"));
}

/// The reference prints this exact line and exits 2 (`cli.py:115`).
#[test]
fn nonexistent_positional_exits_two() {
    let out = rpmcrab(&["/no/such/file.rpm"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "The file or directory '/no/such/file.rpm' does not exist"
    );
}

#[test]
fn nonexistent_config_exits_two() {
    let out = rpmcrab(&["-c", "/no/such.toml", "x.rpm"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn print_config_exits_zero() {
    let out = rpmcrab(&["-p"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Checks"));
}

/// The non-UTF-8-basename fixture. librpm panics on such a header, so this
/// pins that the panic is contained into the reference's read-error path rather
/// than unwinding past the report. See
/// `tests/fixtures/nonutf8-basename/README.md`.
fn nonutf8_fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/nonutf8-basename/input/rpmcrab-nonutf8-1-1.noarch.rpm")
        .canonicalize()
        .expect("non-UTF-8 fixture is committed")
}

/// A header that will not decode is a fatal read: one stderr line and exit 3,
/// which is what the reference emits for a package it cannot read. Before the
/// containment this was a Rust panic and status 101, with no report at all.
#[test]
fn an_undecodable_header_is_a_fatal_read_not_a_panic() {
    let out = rpmcrab(&[nonutf8_fixture().to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "expected the reference's fatal-read status, not a panic (101)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "the guarded read must print one diagnostic, not a backtrace: {stderr}"
    );
    assert!(
        lines[0].contains("(none): E: fatal error while reading"),
        "{stderr}"
    );
    assert!(
        lines[0].contains("could not decode the package"),
        "the message should name the cause: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("panicked"),
        "no panic may reach the user: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// A package that will not decode is a fatal result: one line on stderr,
/// exit 3 (`rpmlint#1595`). The `-v` re-raise is gone, so there is no cause
/// chain and no Rust panic message either way.
#[test]
fn verbose_reports_the_decode_cause_without_a_backtrace() {
    let out = rpmcrab(&["-v", nonutf8_fixture().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3), "fatal result exits 3");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("file path is not UTF-8"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("panicked at"), "stderr: {stderr}");
}

/// The corpus RPM, so the loop has a real package to read.
fn corpus_rpm() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity/cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm")
        .canonicalize()
        .expect("corpus rpm is committed")
}

/// An unreadable package is fatal: exit 3 with the reference's message
/// (`lint.py:293-297`).
#[test]
fn unreadable_package_exits_three() {
    let dir = tempfile::tempdir().unwrap();
    let bogus = dir.path().join("not-an-rpm.rpm");
    std::fs::write(&bogus, b"definitely not an rpm").unwrap();
    let out = rpmcrab(&[bogus.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("(none): E: fatal error while reading"),
        "unexpected stderr: {stderr}"
    );
    assert!(stderr.contains("not-an-rpm.rpm"), "stderr: {stderr}");
}

/// A `.spec` input is linted through `check_spec`: no check is ported yet, so
/// it reports nothing, exits 0, and the footer counts it as a specfile.
#[test]
fn spec_input_is_linted_and_counted() {
    let dir = tempfile::tempdir().unwrap();
    let spec = dir.path().join("thing.spec");
    std::fs::write(&spec, b"Name: thing\n").unwrap();
    let out = rpmcrab(&[spec.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("0 packages and 1 specfiles checked"),
        "stdout: {stdout}"
    );
}

/// The package loop runs: a real corpus RPM is opened, checked (no check is
/// ported yet, so it reports nothing) and counted in the footer.
#[test]
fn a_real_package_is_counted_in_the_footer() {
    let rpm = corpus_rpm();
    let out = rpmcrab(&[rpm.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 packages and 0 specfiles checked"),
        "stdout: {stdout}"
    );
    // The header counts the configured checks, not the implemented ones.
    assert!(stdout.contains("checks: "), "stdout: {stdout}");
}

/// Directory arguments expand to the packages beneath them.
#[test]
fn a_directory_argument_expands_to_its_packages() {
    let dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/parity/cases/llvm21-gold/input");
    let out = rpmcrab(&[dir.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 packages and 0 specfiles checked"),
        "stdout: {stdout}"
    );
}

/// `-t` prints the time report between the results and the footer.
#[test]
fn time_report_flag_prints_the_report() {
    let rpm = corpus_rpm();
    let out = rpmcrab(&["-t", rpm.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Check time report (>1% & >0.1s):"),
        "{stdout}"
    );
    assert!(stdout.contains("Checked files"), "{stdout}");
}

/// `-T/--profile` is gone: the reference removed it (rpmlint#1595) because
/// cProfile only ever covered the main process and misled; `--time-report`
/// aggregates per-check timings instead.
#[test]
fn profile_flag_is_rejected() {
    let out = rpmcrab(&["-T"]);
    assert_eq!(out.status.code(), Some(2));
    let out2 = rpmcrab(&["--profile"]);
    assert_eq!(out2.status.code(), Some(2));
}

/// The straightened aliases are gone: `-r/--rpmlintrc` and `-v/--verbose` keep
/// their canonical flags, but the illogical `--file`/`--info` synonyms are
/// rejected.
#[test]
fn straightened_aliases_are_rejected() {
    assert_eq!(rpmcrab(&["--file", "x"]).status.code(), Some(2));
    assert_eq!(rpmcrab(&["--info"]).status.code(), Some(2));
}

/// `-j/--jobs` is accepted and defaults to the machine's parallelism.
#[test]
fn jobs_flag_is_accepted() {
    let rpm = corpus_rpm();
    for args in [&["-j1"][..], &["--jobs", "2"][..]] {
        let mut full: Vec<&str> = args.to_vec();
        full.push(rpm.to_str().unwrap());
        let out = rpmcrab(&full);
        assert_eq!(out.status.code(), Some(0), "args: {args:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("1 packages and 0 specfiles checked"),
            "args: {args:?}"
        );
    }
}

/// `--checks` narrows the run; naming a check that exists in the config but is
/// not ported yet selects nothing rather than failing.
#[test]
fn checks_flag_selects_without_error() {
    let rpm = corpus_rpm();
    let out = rpmcrab(&["--checks", "FilesCheck", rpm.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 packages and 0 specfiles checked"),
        "{stdout}"
    );
}

/// The rpmlint-on-rpmlint guard only ever sees paths that exist, because the
/// reference validates existence in `cli.py` before `Lint` is built. Exercising
/// the skip end to end would mean creating a file under /home/abuild, so here
/// we only prove a non-existent rpmlint path is a plain exit 2.
#[test]
fn nonexistent_rpmlint_package_path_is_a_plain_exit_two() {
    let out = rpmcrab(&["/home/abuild/rpmbuild/RPMS/noarch/rpmlint-2.10.0.noarch.rpm"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("Skipping rpmlint"));
}

/// With no inputs at all, the reference warns twice and still exits 0. A bare
/// invocation prints help instead, so the run is reached with a flag.
#[test]
fn no_inputs_warns_and_exits_zero() {
    let out = rpmcrab(&["-t"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "There are no files to process nor additional arguments.\nNothing to do, aborting."
    );
}

/// A bogus file is a fatal result: one line on stderr, exit 3. The `-v`
/// re-raise is gone, so the cause chain is not printed.
#[test]
fn verbose_prints_the_cause_chain_and_exits_one() {
    let dir = tempfile::tempdir().unwrap();
    let bogus = dir.path().join("not-an-rpm.rpm");
    std::fs::write(&bogus, b"definitely not an rpm").unwrap();
    let out = rpmcrab(&["-v", bogus.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("fatal error while reading"),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("caused by:"),
        "no cause chain without the re-raise: {stderr}"
    );
}

/// Naming the same package twice validates it once, so the footer counts one.
#[test]
fn a_repeated_argument_is_counted_once() {
    let rpm = corpus_rpm();
    let arg = rpm.to_str().unwrap();
    let out = rpmcrab(&[arg, arg]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 packages and 0 specfiles checked"),
        "duplicate argument counted twice: {stdout}"
    );
}

/// `-j1` and `-j4` produce byte-identical output over several packages,
/// footer included: the worker pool is a scheduling detail, not a behavior
/// change (`rpmlint#1595` `test_parallel_output_matches_sequential`). Only
/// the wall-clock duration in the footer is normalized; the package counts
/// are compared, so the footer cannot be silently dropped.
#[test]
fn parallel_output_matches_sequential() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity/cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm");
    let dir = tempfile::tempdir().unwrap();
    // Distinct file names defeat duplicate-argument collapsing, so each copy
    // is its own task; identical content means the findings share sort keys,
    // which is exactly what a reassembly defect would reorder.
    let args: Vec<String> = (0..4)
        .map(|i| {
            let dst = dir.path().join(format!("pkg{i}.rpm"));
            std::fs::copy(&src, &dst).unwrap();
            dst.to_str().unwrap().to_string()
        })
        .collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let seq_args: Vec<&str> = std::iter::once("-j1").chain(refs.iter().copied()).collect();
    let par_args: Vec<&str> = std::iter::once("-j4").chain(refs.iter().copied()).collect();
    let seq = rpmcrab(&seq_args);
    let par = rpmcrab(&par_args);
    assert_eq!(seq.status.code(), par.status.code(), "exit codes differ");
    fn normalized(out: &std::process::Output) -> String {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut s = stdout.into_owned();
        // Footer: "...; has taken 0.3 s". Normalize the duration only.
        if let Some(i) = s.rfind("; has taken ") {
            let num_start = i + "; has taken ".len();
            if let Some(num_end) = s[num_start..].find(" s") {
                s.replace_range(num_start..num_start + num_end, "N.N");
            }
        }
        s
    }
    let seq_out = normalized(&seq);
    let par_out = normalized(&par);
    assert!(
        seq_out.contains("4 packages and 0 specfiles checked"),
        "footer counts missing from sequential output"
    );
    assert_eq!(seq_out, par_out, "stdout differs");
    assert_eq!(
        String::from_utf8_lossy(&seq.stderr),
        String::from_utf8_lossy(&par.stderr),
        "stderr differs"
    );
}

/// A fatal per-package error does not stop the run: the broken package is
/// reported on stderr, the healthy one is still checked, and the exit code is
/// 3 (`rpmlint#1595`).
#[test]
fn fatal_package_does_not_stop_the_run() {
    let dir = tempfile::tempdir().unwrap();
    let bogus = dir.path().join("not-an-rpm.rpm");
    std::fs::write(&bogus, b"definitely not an rpm").unwrap();
    let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity/cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm");
    let out = rpmcrab(&[bogus.to_str().unwrap(), rpm.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3), "fatal result exits 3");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("fatal error while reading"),
        "broken package reported: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 packages and 0 specfiles checked"),
        "healthy package still checked: {stdout}"
    );
}

/// The permissive expression (`lib.rs:173`):
/// `cfg.permissive = cli.permissive || (!cli.strict && cfg.permissive_by_default)`.
/// The parity RPM has 2 errors; the builtin defaults are permissive.

#[test]
fn strict_flag_disables_permissive_default() {
    // `-s` with errors -> exit 64 (not permissive).
    let out = rpmcrab(&[
        "-s",
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(64));
}

#[test]
fn permissive_flag_explicit() {
    // `-P` with errors -> exit 0 (permissive).
    let out = rpmcrab(&[
        "-P",
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn permissive_by_default_false_in_config() {
    // Config with `PermissiveByDefault = false` -> exit 64.
    let dir = std::env::temp_dir().join("rpmcrab-permissive-test");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("test.toml");
    std::fs::write(&cfg, "PermissiveByDefault = false\n").unwrap();
    let out = rpmcrab(&[
        "-c",
        cfg.to_str().unwrap(),
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(64));
}

#[test]
fn permissive_by_default_string_true_is_a_fatal_config_error() {
    // `PermissiveByDefault = "true"` (a string) is not a bool: the run must
    // fail loudly with the config diagnostic, not silently accept it.
    let dir = std::env::temp_dir().join("rpmcrab-permissive-test");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("test-str.toml");
    std::fs::write(&cfg, "PermissiveByDefault = \"true\"\n").unwrap();
    let out = rpmcrab(&[
        "-c",
        cfg.to_str().unwrap(),
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("PermissiveByDefault"), "got {stderr}");
    assert!(stderr.contains("must be a bool"), "got {stderr}");
}
