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
