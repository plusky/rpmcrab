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

/// A `.spec` input is reported as unreadable until FakePkg/SpecCheck land, and
/// it is not silently ignored.
#[test]
fn spec_input_is_reported_not_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let spec = dir.path().join("thing.spec");
    std::fs::write(&spec, b"Name: thing\n").unwrap();
    let out = rpmcrab(&[spec.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(".spec support is not implemented yet"),
        "{stderr}"
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

/// `-T` prints rpmcrab's own profile report, clearly labelled as not a CPython
/// cProfile dump.
#[test]
fn profile_flag_prints_the_rust_report() {
    let rpm = corpus_rpm();
    let out = rpmcrab(&["-T", rpm.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("rpmcrab profile report (per-check wall time"),
        "stdout: {stdout}"
    );
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

/// `-v` re-raises, so the cause chain is printed rather than the run ending on
/// a bare exit code.
#[test]
fn verbose_prints_the_cause_chain_and_exits_one() {
    let dir = tempfile::tempdir().unwrap();
    let bogus = dir.path().join("not-an-rpm.rpm");
    std::fs::write(&bogus, b"definitely not an rpm").unwrap();
    let out = rpmcrab(&["-v", bogus.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("fatal error while reading"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("caused by:"), "no cause chain: {stderr}");
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
