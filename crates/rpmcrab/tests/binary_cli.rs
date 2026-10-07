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

/// The straightened `--file` alias is gone: `-r/--rpmlintrc` keeps its
/// canonical flag, but the illogical `--file` synonym is rejected.
/// (`--info` is the exception: kept as a visible alias for `-v/--verbose`
/// because build infrastructure invokes `rpmlint --info`.)
#[test]
fn straightened_file_alias_is_rejected() {
    assert_eq!(rpmcrab(&["--file", "x"]).status.code(), Some(2));
}

/// `--info` is accepted as the reference's long name for `--verbose`.
#[test]
fn info_alias_is_accepted() {
    let rpm = corpus_rpm();
    let out = rpmcrab(&["--info", rpm.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
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

/// `--format json` (upstream rpmlint#1156): the run emits a JSON document
/// with the findings and a summary, parseable by machines.
#[test]
fn format_json_emits_parseable_report() {
    let out = rpmcrab(&[
        "--format",
        "json",
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let doc: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be a JSON document");
    assert_eq!(doc["program"], "rpmcrab");
    let findings = doc["findings"].as_array().expect("findings array");
    assert!(!findings.is_empty(), "expected findings");
    for f in findings {
        assert!(
            f["level"]
                .as_str()
                .is_some_and(|l| ["E", "W", "I"].contains(&l))
        );
        assert!(f["check"].as_str().is_some());
        assert!(f["package"].as_str().is_some());
    }
    let summary = &doc["summary"];
    assert!(summary["errors"].as_u64().is_some());
    assert!(summary["warnings"].as_u64().is_some());
    assert_eq!(
        summary["exit_code"].as_i64(),
        Some(0),
        "summary exit code matches the process"
    );
}

/// The findings in JSON mode are the same multiset as in text mode.
#[test]
fn format_json_matches_text_findings() {
    let rpm = "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm";
    let json_out = rpmcrab(&["--format", "json", rpm]);
    let text_out = rpmcrab(&["--format", "text", rpm]);
    assert_eq!(json_out.status.code(), text_out.status.code());
    let doc: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&json_out.stdout)).expect("JSON");
    let mut json_findings: Vec<(String, String, String)> = doc["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|f| {
            (
                f["check"].as_str().expect("check").to_string(),
                f["level"].as_str().expect("level").to_string(),
                f["details"]
                    .as_array()
                    .expect("details")
                    .iter()
                    .map(|d| d.as_str().expect("detail"))
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        })
        .collect();
    // Text finding lines render as `<pkg>: L: check details...`; split on
    // the ` L: ` separator to recover the (check, level, details) triple.
    let text = String::from_utf8_lossy(&text_out.stdout);
    let mut text_findings: Vec<(String, String, String)> = Vec::new();
    for line in text.lines() {
        let mut found: Option<(&str, &str)> = None;
        for level in ["E", "W", "I"] {
            let sep = format!(" {level}: ");
            if let Some((_, rest)) = line.split_once(&sep) {
                found = Some((level, rest));
                break;
            }
        }
        let Some((level, mut rest)) = found else {
            continue;
        };
        // Strip the badness suffix the text renderer appends.
        if let Some((det, _)) = rest.rsplit_once(" (Badness: ") {
            rest = det;
        }
        let mut parts = rest.splitn(2, " ");
        let check = parts.next().unwrap_or("").to_string();
        let details = parts.next().unwrap_or("").trim().to_string();
        text_findings.push((check, level.to_string(), details));
    }
    json_findings.sort();
    text_findings.sort();
    assert_eq!(
        json_findings.len(),
        text_findings.len(),
        "JSON/text finding count differs",
    );
    assert_eq!(json_findings, text_findings, "finding multisets differ");
}

/// An unknown --format value is a CLI usage error, like any other bad
/// clap value.
#[test]
fn format_unknown_value_exits_two() {
    let out = rpmcrab(&[
        "--format",
        "yaml",
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid value"), "got: {stderr}");
}

/// `OutputFormat = "json"` in config selects JSON without the flag; the
/// flag still wins when both are given.
#[test]
fn output_format_config_selects_json() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("format.toml");
    std::fs::write(&cfg, "OutputFormat = \"json\"\n").unwrap();
    let rpm = "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm";
    let out = rpmcrab(&["-c", cfg.to_str().unwrap(), rpm]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        serde_json::from_str::<serde_json::Value>(&stdout).is_ok(),
        "config OutputFormat=json must emit JSON, got: {stdout:.200}"
    );
    // The CLI flag overrides the config key.
    let out = rpmcrab(&["-c", cfg.to_str().unwrap(), "--format", "text", rpm]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.trim_start().starts_with('{'),
        "CLI --format text must win over config, got: {stdout:.200}"
    );
}

/// `--explain`: port of `test_lint.py::test_explain_unknown` — an unknown id
/// prints the reference's `Unknown message` text and exits 0.
#[test]
fn explain_unknown_id() {
    let out = rpmcrab(&["-e", "bullcrap"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "bullcrap:\nUnknown message, please report a bug if the description should be present.\n\n\n",
        "exact --explain stdout"
    );
    assert!(
        out.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `--explain`: port of `test_lint.py::test_explain_known`.
#[test]
fn explain_known_id() {
    let out = rpmcrab(&["-e", "infopage-not-compressed"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "infopage-not-compressed:\nThis info page is not compressed with the bz2 compression method (does not\nhave the bz2 extension). If the compression does not happen automatically when\nthe package is rebuilt, make sure that you have the appropriate rpm helper\nand/or config packages for your target distribution installed and try\nrebuilding again; if it still does not happen automatically, you can compress\nthis file in the %install section of the spec file.\n\n\n",
        "exact --explain stdout"
    );
    assert!(out.stderr.is_empty());
}

/// --explain for useless-provides: the staged description carries the
/// upstream rpmlint#427 reword ahead of the reference (the reference
/// versioned-and-unversioned claim is not always accurate).
#[test]
fn explain_useless_provides_reworded() {
    let out = rpmcrab(&["-e", "useless-provides"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "useless-provides:
This package provides multiple times the same capacity. Identical automated
and manual provides exist, so the redundant manual provide is useless: the
same provide name is listed more than once (e.g. 'foo' together with 'foo =
1.0').


",
        "exact --explain stdout"
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: port of `test_lint.py::test_explain_with_unknown`.
#[test]
fn explain_known_and_unknown_ids() {
    let out = rpmcrab(&["-e", "infopage-not-compressed", "blablablabla"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "infopage-not-compressed:\nThis info page is not compressed with the bz2 compression method (does not\nhave the bz2 extension). If the compression does not happen automatically when\nthe package is rebuilt, make sure that you have the appropriate rpm helper\nand/or config packages for your target distribution installed and try\nrebuilding again; if it still does not happen automatically, you can compress\nthis file in the %install section of the spec file.\n\n\nblablablabla:\nUnknown message, please report a bug if the description should be present.\n\n\n",
        "exact --explain stdout"
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: port of `test_lint.py::test_explain_known_warn_on_function`.
/// The `WarnOnFunction` description resolves the id; without that config the
/// same id is unknown.
#[test]
fn explain_warn_on_function_id() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("warn-on-functions.toml");
    std::fs::write(
        &cfg,
        "[WarnOnFunction.crypto-policy-non-compliance-openssl]\n\
         f_name = \"SSL_CTX_set_cipher_list\"\n\
         good_param = \"PROFILE=SYSTEM\"\n\
         description = \"\"\"\n\
         This application package calls a function to explicitly set crypto ciphers.\n\
         \"\"\"\n",
    )
    .unwrap();
    let out = rpmcrab(&[
        "-c",
        cfg.to_str().unwrap(),
        "-e",
        "crypto-policy-non-compliance-openssl",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "crypto-policy-non-compliance-openssl:\nThis application package calls a function to explicitly set crypto ciphers.\n\n",
        "exact --explain stdout"
    );

    let out = rpmcrab(&["-e", "crypto-policy-non-compliance-openssl"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "crypto-policy-non-compliance-openssl:\nUnknown message, please report a bug if the description should be present.\n\n\n",
        "exact --explain stdout"
    );
}

/// `--explain`: port of `test_lint.py::test_explain_no_binary_from_cfg` — a
/// `[Descriptions]` entry overrides the staged text.
#[test]
fn explain_description_override_from_config() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("descriptions.toml");
    std::fs::write(
        &cfg,
        "[Descriptions]\nno-binary = \"\"\"\nA new text for no-binary error.\n\"\"\"\n",
    )
    .unwrap();
    let out = rpmcrab(&["-c", cfg.to_str().unwrap(), "-e", "no-binary"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "no-binary:\nA new text for no-binary error.\n\n\n",
        "exact --explain stdout"
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: port of `test_lint.py::test_explain_non_standard_dir_from_cfg`.
/// `non-standard-dir-in-usr` is special: its base description is built by
/// `FHSCheck`, not staged, and the config override replaces it.
#[test]
fn explain_fhs_description_override_from_config() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("descriptions.toml");
    std::fs::write(
        &cfg,
        "[Descriptions]\nnon-standard-dir-in-usr = \"\"\"\nA new text for non-standard-dir-in-usr error.\n\"\"\"\n",
    )
    .unwrap();
    let out = rpmcrab(&["-c", cfg.to_str().unwrap(), "-e", "non-standard-dir-in-usr"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "non-standard-dir-in-usr:\nA new text for non-standard-dir-in-usr error.\n\n\n",
        "exact --explain stdout"
    );
    assert!(out.stderr.is_empty());
}

fn binaries_fixture_rpm() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(
            "../../tests/fixtures/binaries-check/input/rpmcrab-binaries-fixture-1.0-1.aarch64.rpm",
        )
        .canonicalize()
        .expect("binaries fixture is committed")
}

/// End-to-end `[SeverityOverrides]` through the real binary: the fixture RPM
/// fires `executable-stack` at Error; the override rewrites it to Warning on
/// stdout, proving the TOML key flows through config load into the filter.
#[test]
fn severity_override_rewrites_finding_level_end_to_end() {
    let rpm = binaries_fixture_rpm();
    let baseline = rpmcrab(&[rpm.to_str().unwrap()]);
    let baseline_out = String::from_utf8_lossy(&baseline.stdout);
    assert!(
        baseline_out.contains("E: executable-stack"),
        "baseline must fire executable-stack at E: {baseline_out}"
    );

    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("overrides.toml");
    std::fs::write(&cfg, "[SeverityOverrides]\nexecutable-stack = \"W\"\n").unwrap();
    let out = rpmcrab(&["-c", cfg.to_str().unwrap(), rpm.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("W: executable-stack"),
        "override must rewrite the level: {stdout}"
    );
    assert!(
        !stdout.contains("E: executable-stack"),
        "no E: executable-stack may remain: {stdout}"
    );
}

/// An override name that never matches a finding warns on stderr (not as a
/// finding): no static registry of finding tags exists, so a never-matched
/// name is the typo signal.
#[test]
fn unused_severity_override_warns_on_stderr() {
    let rpm = binaries_fixture_rpm();
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("overrides.toml");
    std::fs::write(&cfg, "[SeverityOverrides]\nno-such-finding = \"E\"\n").unwrap();
    let out = rpmcrab(&["-c", cfg.to_str().unwrap(), rpm.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unused [SeverityOverrides] entry \"no-such-finding\""),
        "stderr: {stderr}"
    );
}

/// A non-table `SeverityOverrides` is a fatal configuration error (exit 1),
/// not a silent empty map.
#[test]
fn non_table_severity_overrides_is_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("bad.toml");
    std::fs::write(&cfg, "SeverityOverrides = \"nope\"\n").unwrap();
    let out = rpmcrab(&["-c", cfg.to_str().unwrap(), "-p"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("fatal error in configuration"),
        "stderr: {stderr}"
    );
}

/// The exit code follows the overridden levels end to end (DESIGN \u00a74.6):
/// in strict mode every native error-level finding (enumerated from a
/// non-strict `--format json` baseline) is overridden to W, so the only
/// remaining errors are strict promotions of the non-overridden native
/// warnings/infos -- every printed error is a promotion, so the run exits
/// 65, not 64.
#[test]
fn severity_override_exit_code_follows_rewritten_levels() {
    use std::collections::HashSet;
    let rpm = binaries_fixture_rpm();
    // Non-strict baseline: permissive by default, so exit 0; the JSON
    // findings give the native levels.
    let baseline = rpmcrab(&["--format", "json", rpm.to_str().unwrap()]);
    assert_eq!(baseline.status.code(), Some(0));
    let doc: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&baseline.stdout)).expect("JSON");
    let findings: Vec<serde_json::Value> = doc["findings"].as_array().expect("findings").to_vec();
    // Strict promotes warnings and infos alike; a finding whose check is
    // overridden never counts as promoted, even when it would promote.
    let overridden: HashSet<&str> = findings
        .iter()
        .filter(|f| f["level"] == "E")
        .map(|f| f["check"].as_str().expect("check"))
        .collect();
    let promoted: Vec<&str> = findings
        .iter()
        .filter(|f| {
            (f["level"] == "W" || f["level"] == "I")
                && !overridden.contains(f["check"].as_str().expect("check"))
        })
        .map(|f| f["check"].as_str().expect("check"))
        .collect();
    assert!(!overridden.is_empty(), "baseline must fire error findings");
    assert!(!promoted.is_empty(), "baseline must fire warnings");

    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("overrides.toml");
    let mut toml = String::from("[SeverityOverrides]\n");
    let mut overridden_sorted: Vec<&str> = overridden.iter().copied().collect();
    overridden_sorted.sort_unstable();
    for check in &overridden_sorted {
        // Quoted key: finding names are arbitrary strings, never dotted tables.
        toml.push_str(&format!("{check:?} = \"W\"\n"));
    }
    std::fs::write(&cfg, toml).unwrap();

    let out = rpmcrab(&[
        "--format",
        "json",
        "-s",
        "-c",
        cfg.to_str().unwrap(),
        rpm.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(65));
    let rerun: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("JSON");
    assert_eq!(rerun["summary"]["errors"], promoted.len() as u64);
    for f in rerun["findings"].as_array().expect("findings") {
        let check = f["check"].as_str().expect("check");
        match f["level"].as_str().expect("level") {
            "E" => assert!(
                !overridden.contains(check),
                "every printed error must be a strict promotion: {f}"
            ),
            "W" => assert!(
                overridden.contains(check),
                "every warning must be an overridden native error: {f}"
            ),
            other => panic!("unexpected level {other} for {check}"),
        }
    }
}

/// `--format json` reports the overridden level end to end: the JSON `level`
/// wire letter follows the `[SeverityOverrides]` rewrite through the real
/// binary.
#[test]
fn severity_override_json_reports_overridden_level() {
    let rpm = binaries_fixture_rpm();
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("overrides.toml");
    std::fs::write(&cfg, "[SeverityOverrides]\nexecutable-stack = \"W\"\n").unwrap();
    let out = rpmcrab(&[
        "--format",
        "json",
        "-c",
        cfg.to_str().unwrap(),
        rpm.to_str().unwrap(),
    ]);
    let doc: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("JSON");
    let levels: Vec<&str> = doc["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter(|f| f["check"] == "executable-stack")
        .map(|f| f["level"].as_str().expect("level"))
        .collect();
    assert!(!levels.is_empty(), "fixture must fire executable-stack");
    assert!(
        levels.iter().all(|l| *l == "W"),
        "overridden levels: {levels:?}"
    );
}
/// `--errors-only` (upstream rpmlint#134) end-to-end: the header still reports
/// the configured check count (`docs/DESIGN.md` §4.5 — the reference's
/// `lint.py:272`), even though only 39 checks run.
#[test]
fn errors_only_header_reports_configured_check_count() {
    let out = rpmcrab(&[
        "--errors-only",
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("checks: 43, packages: 1"),
        "header reports the configured count, not the run count: {stdout}"
    );
}

/// `--checks TmpFilesCheck --errors-only`: the only selected check is
/// warning-only, so the run is empty — it must warn on stderr instead of
/// silently exiting 0.
#[test]
fn errors_only_empty_selection_warns_instead_of_silently_exiting_zero() {
    let out = rpmcrab(&[
        "--errors-only",
        "--checks",
        "TmpFilesCheck",
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--errors-only skipped every selected check, nothing to run"),
        "stderr: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("0 errors, 0 warnings"), "footer: {stdout}");
}

/// `--strict` promotes every finding to E at emit time, so under
/// `--strict --errors-only` the warning-only check runs: no empty-run
/// warning. Mutation proof for the strict guard in `errors_only_skips` —
/// without it, this run warns.
#[test]
fn strict_reenables_warning_only_checks_under_errors_only() {
    let out = rpmcrab(&[
        "--strict",
        "--errors-only",
        "--checks",
        "TmpFilesCheck",
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("nothing to run"),
        "strict must disable the filter; stderr: {stderr}"
    );
}

/// `--format json --errors-only`: the finding multiset matches the full run
/// (the four skipped checks fire nothing on this fixture), no finding names
/// a warning-only check, the JSON `checks` field reports the configured
/// count, and the summary exit code matches the process.
#[test]
fn errors_only_json_finding_set_matches_full_run() {
    let rpm = "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm";
    let full = rpmcrab(&["--format", "json", rpm]);
    let eo = rpmcrab(&["--format", "json", "--errors-only", rpm]);
    assert_eq!(eo.status.code(), full.status.code());
    let full_doc: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&full.stdout)).expect("JSON");
    let eo_doc: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&eo.stdout)).expect("JSON");
    assert_eq!(full_doc["findings"], eo_doc["findings"]);
    for f in eo_doc["findings"].as_array().expect("findings") {
        let check = f["check"].as_str().expect("check");
        assert!(
            ![
                "BashismsCheck",
                "ConfigFilesCheck",
                "FHSCheck",
                "TmpFilesCheck"
            ]
            .contains(&check),
            "warning-only check ran: {check}"
        );
    }
    assert_eq!(eo_doc["checks"], 43);
    assert_eq!(
        eo_doc["summary"]["exit_code"].as_i64(),
        eo.status.code().map(i64::from)
    );
}

/// Under `--errors-only` the `unused-rpmlintrc-filter` audit only sees
/// findings that ran: a pattern naming a skipped check's finding reports as
/// unused (documented in `docs/DESIGN.md` §4.10).
#[test]
fn errors_only_unused_rpmlintrc_filter_names_skipped_check_finding() {
    let dir = std::env::temp_dir().join("rpmcrab-errors-only-rpmlintrc");
    std::fs::create_dir_all(&dir).unwrap();
    let rc = dir.join("test.rc");
    std::fs::write(&rc, "addFilter(\"tmpfile-not-in-filelist\")\n").unwrap();
    let out = rpmcrab(&[
        "-r",
        rc.to_str().unwrap(),
        "--errors-only",
        "--checks",
        "TmpFilesCheck",
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("unused-rpmlintrc-filter"),
        "the skipped check's filter must audit as unused: {stdout}"
    );
}
/// `--explain`: staged `alternatives_check.toml` resolves `alternative-generic-name-not-symlink` instead of "Unknown message".
#[test]
fn explain_staged_alternatives_check() {
    let out = rpmcrab(&["-e", "alternative-generic-name-not-symlink"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "alternative-generic-name-not-symlink:\nThe update-alternative generic-name is not a symlink pointing to\n%{_sysconfdir}/alternatives/$(basename generic-name).\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `appdata_check.toml` resolves `invalid-appdata-file` instead of "Unknown message".
#[test]
fn explain_staged_appdata_check() {
    let out = rpmcrab(&["-e", "invalid-appdata-file"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "invalid-appdata-file:\nAppdata file is not valid. Check the validity with appstream-util.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `bashisms_check.toml` resolves `bin-sh-syntax-error` instead of "Unknown message".
#[test]
fn explain_staged_bashisms_check() {
    let out = rpmcrab(&["-e", "bin-sh-syntax-error"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "bin-sh-syntax-error:\nA /bin/sh shell script contains a POSIX shell syntax error. This might\nindicate a potential bash-specific feature being used, try dash -n <file> for\nmore detailed error message.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `branding_policy_check.toml` resolves `branding-conflicts-missing` instead of "Unknown message".
#[test]
fn explain_staged_branding_policy_check() {
    let out = rpmcrab(&["-e", "branding-conflicts-missing"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "branding-conflicts-missing:\nBranding packages should conflict with other flavors of the branding package\nby using: 'Conflicts: pkg-branding = brandingversion' and not directly by\nlisting all the alternative brandings in it.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `build_root_and_date_check.toml` resolves `file-contains-current-date` instead of "Unknown message".
#[test]
fn explain_staged_build_root_and_date_check() {
    let out = rpmcrab(&["-e", "file-contains-current-date"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "file-contains-current-date:\nYour file contains the current date, this may cause the package to rebuild in\nexcess.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `check_for_xinetd.toml` resolves `obsolete-xinetd-requirement` instead of "Unknown message".
#[test]
fn explain_staged_check_for_xinetd() {
    let out = rpmcrab(&["-e", "obsolete-xinetd-requirement"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "obsolete-xinetd-requirement:\nXinetd is obsolete by systemd socket activated services. Please stop using\nxinetd and switch to socket activation from systemd.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `dbus_policy_check.toml` resolves `dbus-policy-allow-without-destination` instead of "Unknown message".
#[test]
fn explain_staged_dbus_policy_check() {
    let out = rpmcrab(&["-e", "dbus-policy-allow-without-destination"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "dbus-policy-allow-without-destination:\n'allow' directives must always specify a 'send_destination'.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `doc_check.toml` resolves `executable-docs` instead of "Unknown message".
#[test]
fn explain_staged_doc_check() {
    let out = rpmcrab(&["-e", "executable-docs"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "executable-docs:\nDocumentation should not be executable.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `duplicates_check.toml` resolves `files-duplicate` instead of "Unknown message".
#[test]
fn explain_staged_duplicates_check() {
    let out = rpmcrab(&["-e", "files-duplicate"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "files-duplicate:\nYour package contains duplicated files that are not hard- or symlinks. You\nshould use the %fdupes macro to link the files to one.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `erlang_check.toml` resolves `beam-compile-info-missed` instead of "Unknown message".
#[test]
fn explain_staged_erlang_check() {
    let out = rpmcrab(&["-e", "beam-compile-info-missed"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "beam-compile-info-missed:\nYour beam file has missed compile info chunk.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `file_digest_check.toml` resolves `cron-file-unauthorized` instead of "Unknown message".
#[test]
fn explain_staged_file_digest_check() {
    let out = rpmcrab(&["-e", "cron-file-unauthorized"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "cron-file-unauthorized:\nPackaging cron jobs requires a review and whitelisting by the SUSE security\nteam. If the package is intended for inclusion in any SUSE product please open\na bug report to request review of the package by the security team. Please\nrefer to\nhttps://en.opensuse.org/openSUSE:Package_security_guidelines#audit_bugs for\nmore information.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `file_metadata_check.toml` resolves `device-unauthorized-file` instead of "Unknown message".
#[test]
fn explain_staged_file_metadata_check() {
    let out = rpmcrab(&["-e", "device-unauthorized-file"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "device-unauthorized-file:\nPackaging device files requires a review and whitelisting by the SUSE security\nteam. If the package is intended for inclusion in any SUSE product please open\na bug report to request review of the package by the security team. Please\nrefer to\nhttps://en.opensuse.org/openSUSE:Package_security_guidelines#audit_bugs for\nmore information.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `filelist_check.toml` resolves `filelist-forbidden` instead of "Unknown message".
#[test]
fn explain_staged_filelist_check() {
    let out = rpmcrab(&["-e", "filelist-forbidden"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "filelist-forbidden:\nFile is not allowed at the location.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `files_check.toml` resolves `no-documentation` instead of "Unknown message".
#[test]
fn explain_staged_files_check() {
    let out = rpmcrab(&["-e", "no-documentation"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "no-documentation:\nThe package contains no documentation (README, doc, etc). You have to include\ndocumentation files.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `kmp_policy_check.toml` resolves `kmp-missing-requires` instead of "Unknown message".
#[test]
fn explain_staged_kmp_policy_check() {
    let out = rpmcrab(&["-e", "kmp-missing-requires"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "kmp-missing-requires:\nMake sure you have extended '%kernel_module_package' by '-p\n%_sourcedir/preamble', a file named 'preamble' as source and there specified\n'Requires: kernel-%1'.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `lsb_check.toml` resolves `non-lsb-compliant-package-name` instead of "Unknown message".
#[test]
fn explain_staged_lsb_check() {
    let out = rpmcrab(&["-e", "non-lsb-compliant-package-name"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "non-lsb-compliant-package-name:\nYour package name contains an illegal character that is not LSB-compliant. Use\nonly lowercase letters, numbers, '.', '+' or '-' characters.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `logrotate_check.toml` resolves `logrotate-log-dir-not-packaged` instead of "Unknown message".
#[test]
fn explain_staged_logrotate_check() {
    let out = rpmcrab(&["-e", "logrotate-log-dir-not-packaged"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "logrotate-log-dir-not-packaged:\nPlease add the specified directory to the file list to be able to check\npermissions.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `menu_check.toml` resolves `non-file-in-menu-dir` instead of "Unknown message".
#[test]
fn explain_staged_menu_check() {
    let out = rpmcrab(&["-e", "non-file-in-menu-dir"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "non-file-in-menu-dir:\nThe directory /usr/lib/menu must not contain anything else than normal files.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `menu_xdg_check.toml` resolves `invalid-desktopfile` instead of "Unknown message".
#[test]
fn explain_staged_menu_xdg_check() {
    let out = rpmcrab(&["-e", "invalid-desktopfile"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "invalid-desktopfile:\nThe .desktop file is not valid, check with desktop-file-validate\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `pkg_config_check.toml` resolves `invalid-pkgconfig-file` instead of "Unknown message".
#[test]
fn explain_staged_pkg_config_check() {
    let out = rpmcrab(&["-e", "invalid-pkgconfig-file"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "invalid-pkgconfig-file:\nYour .pc file appears to be invalid. Possible causes are: - it contains traces\nof $RPM_BUILD_ROOT or $RPM_BUILD_DIR. - it contains unreplaced macros\n(@have_foo@) - it references invalid paths (e.g. /home or /tmp)\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `polkit_check.toml` resolves `polkit-user-privilege` instead of "Unknown message".
#[test]
fn explain_staged_polkit_check() {
    let out = rpmcrab(&["-e", "polkit-user-privilege"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "polkit-user-privilege:\nThe package allows unprivileged users to carry out privileged operations\nwithout root authentication. This could cause security problems if not done\ncarefully. If the package is intended for inclusion in any SUSE product please\nopen a bug report to request review of the package by the security team.\nPlease refer to\nhttps://en.opensuse.org/openSUSE:Package_security_guidelines#audit_bugs for\nmore information.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `python_check.toml` resolves `python-doc-in-package` instead of "Unknown message".
#[test]
fn explain_staged_python_check() {
    let out = rpmcrab(&["-e", "python-doc-in-package"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "python-doc-in-package:\ndoc/ or docs/ directory in Python package directory. Documentation should go\ninto %{docdir}, not %{python_sitelib}/<pkgname>\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `selinux_independent_module_check.toml` resolves `selinux-incorrect-if-file-location` instead of "Unknown message".
#[test]
fn explain_staged_selinux_independent_module_check() {
    let out = rpmcrab(&["-e", "selinux-incorrect-if-file-location"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "selinux-incorrect-if-file-location:\nSELinux interface (.if) files must be installed in\n/usr/share/selinux/devel/include/distributed/ as per Fedora and openSUSE\nindependent module packaging guidelines. Files found elsewhere are packaging\nerrors.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `suid_permissions_check.toml` resolves `permissions-symlink` instead of "Unknown message".
#[test]
fn explain_staged_suid_permissions_check() {
    let out = rpmcrab(&["-e", "permissions-symlink"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "permissions-symlink:\npermissions handling for symlinks is useless. Please contact security@suse.de\nto remove the entry. Please refer to\nhttps://en.opensuse.org/openSUSE:Package_security_guidelines#audit_bugs for\nmore information.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `shared_library_policy_check.toml` resolves `shlib-policy-missing-lib` instead of "Unknown message".
#[test]
fn explain_staged_shared_library_policy_check() {
    let out = rpmcrab(&["-e", "shlib-policy-missing-lib"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "shlib-policy-missing-lib:\nYour package name looks like it is based on soname, but the package does not\nprovide any libraries.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `signature_check.toml` resolves `no-signature` instead of "Unknown message".
#[test]
fn explain_staged_signature_check() {
    let out = rpmcrab(&["-e", "no-signature"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "no-signature:\nYou have to include your pgp or gpg signature in your package.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `spec_check.toml` resolves `no-spec-file` instead of "Unknown message".
#[test]
fn explain_staged_spec_check() {
    let out = rpmcrab(&["-e", "no-spec-file"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "no-spec-file:\nNo spec file was specified in your RPM metadata. Please specify a valid SPEC\nfile to build a valid RPM package.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `sysv_init_on_systemd_check.toml` resolves `obsolete-insserv-requirement` instead of "Unknown message".
#[test]
fn explain_staged_sysv_init_on_systemd_check() {
    let out = rpmcrab(&["-e", "obsolete-insserv-requirement"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "obsolete-insserv-requirement:\nIn systemd based distributions insserv is obsolete. Please remove dependencies\non insserv.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `systemd_install_check.toml` resolves `systemd-service-without-service_add_pre` instead of "Unknown message".
#[test]
fn explain_staged_systemd_install_check() {
    let out = rpmcrab(&["-e", "systemd-service-without-service_add_pre"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "systemd-service-without-service_add_pre:\nThe package contains a systemd service but doesn't contain a %pre with a call\nto service_add_pre.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `systemd_tmpfiles_check.toml` resolves `systemd-tmpfile-ghost` instead of "Unknown message".
#[test]
fn explain_staged_systemd_tmpfiles_check() {
    let out = rpmcrab(&["-e", "systemd-tmpfile-ghost"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "systemd-tmpfile-ghost:\nThis package installs a systemd-tmpfiles drop-in configuration file as %ghost\nfile. This is not allowed, since it is impossible to review. Please refer to\nhttps://en.opensuse.org/openSUSE:Package_security_guidelines#audit_bugs for\nmore information\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `tags_check.toml` resolves `invalid-version` instead of "Unknown message".
#[test]
fn explain_staged_tags_check() {
    let out = rpmcrab(&["-e", "invalid-version"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "invalid-version:\nThe version string must not contain the pre, alpha, beta or rc suffixes\nbecause when the final version will be out, you will have to use an Epoch tag\nto make the package upgradable. Instead put it in the release tag, prefixed\nwith something you have control over.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `tmpfiles_check.toml` resolves `pre-with-tmpfile-creation` instead of "Unknown message".
#[test]
fn explain_staged_tmpfiles_check() {
    let out = rpmcrab(&["-e", "pre-with-tmpfile-creation"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "pre-with-tmpfile-creation:\n%pre section contains %tmpfiles_create macro that should be in the %post\nsection instead.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `AlternativesCheck.toml` entry `update-alternatives-postun-call-missing` pins the fixed wording.
#[test]
fn explain_reworded_update_alternatives_postun_call_missing() {
    let out = rpmcrab(&["-e", "update-alternatives-postun-call-missing"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "update-alternatives-postun-call-missing:\nThe package does not call update-alternatives --remove in postun phase to\nremove all the configuration for each individual --install binary that was\ndone in post.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `KMPPolicyCheck.toml` entry `kmp-missing-supplements` pins the fixed wording.
#[test]
fn explain_reworded_kmp_missing_supplements() {
    let out = rpmcrab(&["-e", "kmp-missing-supplements"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "kmp-missing-supplements:\nMake sure you have extended '%kernel_module_package' by '-p\n%_sourcedir/preamble', a file named 'preamble' as source and there specified\n'Supplements: packageand(kernel-%1:%name)'.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `SpecCheck.toml` entry `%ifarch-applied-patch` pins the fixed wording.
#[test]
fn explain_reworded_ifarch_applied_patch() {
    let out = rpmcrab(&["-e", "%ifarch-applied-patch"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "%ifarch-applied-patch:\nA patch is applied inside an %ifarch block. Patches must be applied on all\narchitectures. If the fix is only needed on a given arch, put the\narch-specific condition inside the patch (configure or code) instead of\nguarding the %patch directive.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `SharedLibraryPolicyCheck.toml` entry `shlib-fixed-dependency` pins the fixed wording.
#[test]
fn explain_reworded_shlib_fixed_dependency() {
    let out = rpmcrab(&["-e", "shlib-fixed-dependency"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "shlib-fixed-dependency:\nYour shared library package requires a fixed version of another package. The\nintention of the Shared Library Policy is to allow parallel installation of\nmultiple versions of the same shared library, hard dependencies likely make\nthat impossible. Please remove this dependency and instead add it to the\npackages that use your library at runtime.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `TagsCheck.toml` entry `invalid-packager` pins the fixed wording.
#[test]
fn explain_reworded_invalid_packager() {
    let out = rpmcrab(&["-e", "invalid-packager"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "invalid-packager:\nThe Packager tag does not match the pattern configured in the Packager option\nof the rpmlint configuration. Please change it and rebuild your package.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `MenuXDGCheck.toml` entry `desktopfile-without-binary` pins the fixed wording.
#[test]
fn explain_reworded_desktopfile_without_binary() {
    let out = rpmcrab(&["-e", "desktopfile-without-binary"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "desktopfile-without-binary:\nThe .desktop file refers to a binary that is not present in the package. You\nshould check the Requires or see if this is not an error.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `MenuCheck.toml` entry `use-of-launcher-in-menu-but-no-requires-on` pins the fixed wording.
#[test]
fn explain_reworded_use_of_launcher_in_menu_but_no_requires_on() {
    let out = rpmcrab(&["-e", "use-of-launcher-in-menu-but-no-requires-on"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "use-of-launcher-in-menu-but-no-requires-on:\nThe menu command uses a launcher, but the package has no dependency on the\npackage that provides the launcher.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `PythonCheck.toml` entry `python-leftover-require` pins the fixed wording.
#[test]
fn explain_reworded_python_leftover_require() {
    let out = rpmcrab(&["-e", "python-leftover-require"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "python-leftover-require:\nSome python module Requires are missing from the python package's requirements\ndeclaration. Please verify that all dependencies are really needed.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `FilesCheck.toml` entry `zero-perms` pins the fixed wording.
#[test]
fn explain_reworded_zero_perms() {
    let out = rpmcrab(&["-e", "zero-perms"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "zero-perms:\nYour package contains a file with no permissions. This is usually an error\nbecause the file won't be accessible by any user. You should check the file\npermissions, ensure they are correct, or fix them in the %install section.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `FilesCheck.toml` entry `perl-temp-file` pins the fixed wording.
#[test]
fn explain_reworded_perl_temp_file() {
    let out = rpmcrab(&["-e", "perl-temp-file"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "perl-temp-file:\nYou have a perl temporary file in your package. Usually, this file begins with\na dot (.) and contains 'perl' in its name.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `FilelistCheck.toml` entry `filelist-forbidden-perl-dir` pins the fixed wording.
#[test]
fn explain_reworded_filelist_forbidden_perl_dir() {
    let out = rpmcrab(&["-e", "filelist-forbidden-perl-dir"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "filelist-forbidden-perl-dir:\nPerl files are installed in a non-vendor path.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `AlternativesCheck.toml` entry `libalternatives-conf-not-found` pins the fixed wording.
#[test]
fn explain_reworded_libalternatives_conf_not_found() {
    let out = rpmcrab(&["-e", "libalternatives-conf-not-found"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "libalternatives-conf-not-found:\nThe libalternatives configuration file defined in the package file section was\nnot found. This does not have to be an error if the file has been tagged as a\nghost file.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `PythonCheck.toml` entry `python-sphinx-doctrees-leftover` pins the fixed wording.
#[test]
fn explain_reworded_python_sphinx_doctrees_leftover() {
    let out = rpmcrab(&["-e", "python-sphinx-doctrees-leftover"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "python-sphinx-doctrees-leftover:\nA cached Sphinx build folder (\".doctrees\") was found in the package. Please\nmake sure not to include any build files in the final package.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `FilesCheck.toml` entry `missing-dependency-to-crontabs` pins the fixed wording.
#[test]
fn explain_reworded_missing_dependency_to_crontabs() {
    let out = rpmcrab(&["-e", "missing-dependency-to-crontabs"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "missing-dependency-to-crontabs:\nThis package installs a file in /etc/cron.*/ but doesn't require crontabs to\nbe installed. As crontabs is not part of the essential packages, your package\nshould explicitly require crontabs to make sure that your cron job is\nexecuted. If it is an optional feature of your package, recommend or suggest\ncrontabs.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `FilesCheck.toml` entry `missing-dependency-to-logrotate` pins the fixed wording.
#[test]
fn explain_reworded_missing_dependency_to_logrotate() {
    let out = rpmcrab(&["-e", "missing-dependency-to-logrotate"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "missing-dependency-to-logrotate:\nThis package installs a file in /etc/logrotate.d/ but doesn't require\nlogrotate to be installed. Because logrotate is not part of the essential\npackages, your package should explicitly depend on logrotate to make sure that\nyour logrotate job is executed. If it is an optional feature of your package,\nrecommend or suggest logrotate.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `FilesCheck.toml` entry `pem-private-key` pins the fixed wording.
#[test]
fn explain_reworded_pem_private_key() {
    let out = rpmcrab(&["-e", "pem-private-key"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "pem-private-key:\nPrivate key in a .pem file should not be shipped in a rpm, unless this is for\ntesting purpose ( ie, run by the test suite ). Shipping it as part of the\nexample documentation means that someone will sooner or later use it and setup\nan insecure configuration.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `FilelistCheck.toml` entry `filelist-forbidden-xinetd-configuration` pins the fixed wording.
#[test]
fn explain_reworded_filelist_forbidden_xinetd_configuration() {
    let out = rpmcrab(&["-e", "filelist-forbidden-xinetd-configuration"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "filelist-forbidden-xinetd-configuration:\nXinetd configuration files are deprecated. Please migrate to systemd socket\nactivated unit files. http://0pointer.de/blog/projects/socket-activation.html\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `FileDigestCheck.toml` entry `dbus-file-parse-error` pins the fixed wording.
#[test]
fn explain_reworded_dbus_file_parse_error() {
    let out = rpmcrab(&["-e", "dbus-file-parse-error"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "dbus-file-parse-error:\nA digest of a D-Bus XML file could not be computed, because of an XML parsing\nerror\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `SpecCheck.toml` entry `macro-in-comment` pins the fixed wording.
#[test]
fn explain_reworded_macro_in_comment() {
    let out = rpmcrab(&["-e", "macro-in-comment"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "macro-in-comment:\nThere is an unescaped macro after a shell style comment in the specfile.\nMacros are expanded everywhere, so check if it can cause a problem in this\ncase and escape the macro with another leading % if appropriate.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `SpecCheck.toml` entry `patch-fuzz-is-changed` pins the fixed wording.
#[test]
fn explain_reworded_patch_fuzz_is_changed() {
    let out = rpmcrab(&["-e", "patch-fuzz-is-changed"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "patch-fuzz-is-changed:\nThe internal patch fuzz value was changed, and could hide patch's issues, or\ncould lead to applying a patch at the wrong location. Usually, this is often\nthe sign that someone didn't check if a patch is still needed and does not\nwant to rediff it. It is usually better to rediff the patch and try to send it\nupstream.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `SpecCheck.toml` entry `unversioned-explicit-obsoletes` pins the fixed wording.
#[test]
fn explain_reworded_unversioned_explicit_obsoletes() {
    let out = rpmcrab(&["-e", "unversioned-explicit-obsoletes"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "unversioned-explicit-obsoletes:\nThe specfile contains an unversioned Obsoletes: token, which will match all\nolder, equal and newer versions of the obsoleted thing.  This may cause update\nproblems, restrict future package/provides naming, and may match something it\nwas originally not intended to match -- make the Obsoletes versioned if\npossible.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `SpecCheck.toml` entry `shared-dir-glob-in-files` pins the fixed wording.
#[test]
fn explain_reworded_shared_dir_glob_in_files() {
    let out = rpmcrab(&["-e", "shared-dir-glob-in-files"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "shared-dir-glob-in-files:\nThe %files section contains \"%{_bindir}/*\", \"%{_datadir}/*\", \"%{_docdir}/*\",\n\"%{_includedir}/*\" or \"%{_mandir}/*\".  These can lead to packagers not\nnoticing when upstream adds new and possibly conflicting files in these\ndirectories. Therefore, files in these directories should be explicitly listed\nlike \"%{_bindir}/foobar\" or \"%{_includedir}/foobar.h\".\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `MenuCheck.toml` entry `version-in-menu-longtitle` pins the fixed wording.
#[test]
fn explain_reworded_version_in_menu_longtitle() {
    let out = rpmcrab(&["-e", "version-in-menu-longtitle"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "version-in-menu-longtitle:\nThe longtitle field of the menu entry contains a version. This is bad because\nit will be prone to error when the version of the package changes.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `MenuCheck.toml` entry `version-in-menu-title` pins the fixed wording.
#[test]
fn explain_reworded_version_in_menu_title() {
    let out = rpmcrab(&["-e", "version-in-menu-title"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "version-in-menu-title:\nThe title field of the menu entry contains a version. This is bad because it\nwill be prone to error when the version of the package changes.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `LogrotateCheck.toml` entry `logrotate-duplicate` pins the fixed wording.
#[test]
fn explain_reworded_logrotate_duplicate() {
    let out = rpmcrab(&["-e", "logrotate-duplicate"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "logrotate-duplicate:\nThere are duplicated logrotate entries with different settings for the\nspecified file.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `KMPPolicyCheck.toml` entry `kmp-excessive-supplements` pins the fixed wording.
#[test]
fn explain_reworded_kmp_excessive_supplements() {
    let out = rpmcrab(&["-e", "kmp-excessive-supplements"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "kmp-excessive-supplements:\nThere is more than one flavor of kernel specified in Supplements field.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `SystemdTmpfilesCheck.toml` entry `systemd-tmpfile-parse-error` pins the fixed wording.
#[test]
fn explain_reworded_systemd_tmpfile_parse_error() {
    let out = rpmcrab(&["-e", "systemd-tmpfile-parse-error"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "systemd-tmpfile-parse-error:\nA warning occurred trying to parse a systemd-tmpfiles drop-in configuration\nfile line. Either the configuration file is inconsistent or this rpmlint check\nhas issues. Please refer to\nhttps://en.opensuse.org/openSUSE:Package_security_guidelines#audit_bugs for\nmore information\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `PythonCheck.toml` entry `python-missing-require` pins the fixed wording.
#[test]
fn explain_reworded_python_missing_require() {
    let out = rpmcrab(&["-e", "python-missing-require"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "python-missing-require:\nThe python package declares some requirement that's not detected in the rpm\npackage. Please, verify that all dependencies are added as Requires.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `PythonCheck.toml` entry `python-pyc-multiple-versions` pins the fixed wording.
#[test]
fn explain_reworded_python_pyc_multiple_versions() {
    let out = rpmcrab(&["-e", "python-pyc-multiple-versions"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "python-pyc-multiple-versions:\nThere are .pyc files in the rpm that are from different Python interpreters.\nPlease, verify that all files are needed for this package.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `SharedLibraryPolicyCheck.toml` entry `shlib-policy-excessive-dependency` pins the fixed wording.
#[test]
fn explain_reworded_shlib_policy_excessive_dependency() {
    let out = rpmcrab(&["-e", "shlib-policy-excessive-dependency"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "shlib-policy-excessive-dependency:\nYour package starts with 'lib' as part of its name, but also contains binaries\nthat have more dependencies than those already required by the libraries.\nThose binaries should probably not be part of the library package, but split\ninto a separate one to reduce the additional dependencies for other users of\nthis library.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: reworded `TagsCheck.toml` entry `no-changelogname-tag` pins the fixed wording.
#[test]
fn explain_reworded_no_changelogname_tag() {
    let out = rpmcrab(&["-e", "no-changelogname-tag"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "no-changelogname-tag:\nThere is no %changelog tag in your spec file(or it's empty). To fix it,\nplease insert a '%changelog' section in your spec file and add an entry change\nbelow it.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}
