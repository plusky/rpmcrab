//! Exit-code gates for the `rpmcrab` binary (`docs/DESIGN.md` §4.6). These
//! drive the real executable so the CLI parsing and the process exit code are
//! proven as a unit.

use std::path::Path;
use std::process::Command;

/// The spawn command every harness helper starts from: the binary
/// under test, with the ambient terminal variables removed, so a
/// developer's shell cannot leak width or colour settings into a
/// run. Each helper layers its own environment policy on top.
fn rpmcrab_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rpmcrab"));
    cmd.env_remove("COLUMNS")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR");
    cmd
}

fn rpmcrab(args: &[&str]) -> std::process::Output {
    let mut cmd = rpmcrab_command();
    cmd.args(args)
        // Hermetic: no XDG auto-load, no colour, no ambient COLUMNS.
        .env("CONFIG_DISABLE_AUTOLOADING", "1")
        // Spelling suggestions must be reproducible across spawned
        // processes: spellbook's ngram candidate set is not (issue
        // #688), so the harness disables the ngram suggester in the
        // spawned checker. Production runs leave the variable unset
        // and keep the full suggestions.
        .env("RPMCRAB_DISABLE_NGRAM_SUGGESTIONS", "1");
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

/// A committed fixture RPM from the parity pkg inputs, by file name.
fn pkg_input_fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity/pkg/inputs")
        .join(name)
        .canonicalize()
        .expect("pkg fixture is committed")
}

/// The uid/gid decision through the shipped binary on a real header
/// (issue #827): the fixture's payload is owned by hdruser/hdrgroup
/// and its header declares the accounts through no route -- the only
/// account Requires present are the ones rpm's generator derived
/// from the file ownership. Both findings render at E and the run
/// exits 64.
#[test]
fn non_standard_uid_gid_fire_on_uncredited_real_header() {
    let rpm = pkg_input_fixture("uidgid-realhdr-main-1.0-1.noarch.rpm");
    let out = rpmcrab(&[rpm.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(64));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("E: non-standard-uid"),
        "non-standard-uid must render at E: stdout: {stdout}"
    );
    assert!(
        stdout.contains("E: non-standard-gid"),
        "non-standard-gid must render at E: stdout: {stdout}"
    );
}

/// The credited real-header fixtures stay quiet through the shipped
/// binary (issue #827): one declares both owners with
/// packager-written `Requires(pre)` capabilities, the other ships a
/// sysusers.d snippet declaring them.
#[test]
fn non_standard_uid_gid_quiet_on_credited_real_headers() {
    for name in [
        "uidgid-realhdr-handwritten-1.0-1.noarch.rpm",
        "uidgid-realhdr-control-1.0-1.noarch.rpm",
    ] {
        let rpm = pkg_input_fixture(name);
        let out = rpmcrab(&[rpm.to_str().unwrap()]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !stdout.contains("non-standard-uid"),
            "{name} must not draw non-standard-uid: stdout: {stdout}"
        );
        assert!(
            !stdout.contains("non-standard-gid"),
            "{name} must not draw non-standard-gid: stdout: {stdout}"
        );
    }
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

/// A `.spec` input is linted through `check_spec` and counted in the
/// footer as a specfile. A bare `Name:`-only spec fails to parse, which
/// draws the specfile-error finding; that finding is temporarily W
/// (issue #699 levelling, pending #702), so the run exits 0 while the
/// levelling stands.
#[test]
fn spec_input_is_linted_and_counted() {
    let dir = tempfile::tempdir().unwrap();
    let spec = dir.path().join("thing.spec");
    std::fs::write(&spec, b"Name: thing\n").unwrap();
    let out = rpmcrab(&[spec.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("W: specfile-error"),
        "specfile-error must render on stdout at its temporary W level: stdout: {stdout}"
    );
    assert!(
        stdout.contains("0 packages and 1 specfiles checked"),
        "stdout: {stdout}"
    );
}

/// The package loop runs: a real corpus RPM is opened, checked and
/// counted in the footer. The corpus RPM carries error findings, so the
/// run exits 64 (issue #699).
#[test]
fn a_real_package_is_counted_in_the_footer() {
    let rpm = corpus_rpm();
    let out = rpmcrab(&[rpm.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(64));
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
    assert_eq!(out.status.code(), Some(64));
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
    assert_eq!(out.status.code(), Some(64));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Check time report (>1% & >0.1s):"),
        "{stdout}"
    );
    assert!(stdout.contains("Checked files"), "{stdout}");
}

/// The time report is on by default: no `-t` needed.
#[test]
fn time_report_on_by_default() {
    let rpm = corpus_rpm();
    let out = rpmcrab(&[rpm.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(64));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Check time report (>1% & >0.1s):"),
        "{stdout}"
    );
    assert!(stdout.contains("Checked files"), "{stdout}");
}

/// `--no-time-report` disables the default-on time report.
#[test]
fn no_time_report_flag_disables() {
    let rpm = corpus_rpm();
    let out = rpmcrab(&["--no-time-report", rpm.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(64));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("Check time report"), "{stdout}");
}

/// `--time-report` and `--no-time-report` are mutually exclusive: passing
/// both is a usage error, never a silent precedence pick.
#[test]
fn time_report_flags_conflict() {
    let rpm = corpus_rpm();
    let out = rpmcrab(&["--time-report", "--no-time-report", rpm.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"), "{stderr}");
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
    assert_eq!(out.status.code(), Some(64));
}

/// `-j/--jobs` is accepted and defaults to the machine's parallelism.
#[test]
fn jobs_flag_is_accepted() {
    let rpm = corpus_rpm();
    for args in [&["-j1"][..], &["--jobs", "2"][..]] {
        let mut full: Vec<&str> = args.to_vec();
        full.push(rpm.to_str().unwrap());
        let out = rpmcrab(&full);
        assert_eq!(out.status.code(), Some(64), "args: {args:?}");
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
    assert_eq!(out.status.code(), Some(64));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 packages and 0 specfiles checked"),
        "duplicate argument counted twice: {stdout}"
    );
}

/// Progress lines (`checking … (n of m)`, rpmcrab#286) are emitted in
/// worker-pickup order, so a parallel run orders them differently than a
/// sequential one, and each carries a wall-clock timestamp; the set of
/// lines is identical. Strip the timestamp (like the footer duration below)
/// and sort before comparing.
fn strip_timestamp(line: &str) -> &str {
    // tracing's default fmt layer renders `{timestamp} {LEVEL} {target}: message`.
    // Cut before the level token, whatever the level, so neither the timestamp
    // nor a level change breaks the comparison.
    let mut cut = None;
    for level in ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"] {
        let token = format!(" {level} ");
        if let Some(i) = line.find(token.as_str()) {
            cut = Some(cut.map_or(i, |c: usize| c.min(i)));
        }
    }
    match cut {
        Some(i) => &line[i + 1..],
        None => line,
    }
}

fn sorted_lines(s: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = s.lines().map(strip_timestamp).collect();
    lines.sort_unstable();
    lines
}

/// `-j1` and `-j4` produce byte-identical output over several packages,
/// footer included: the worker pool is a scheduling detail, not a behavior
/// change (`rpmlint#1595` `test_parallel_output_matches_sequential`). Only
/// wall-clock durations are normalized — the footer's and the time report's
/// numbers. The time report's per-check rows are dropped: which checks pass
/// its (>1% & >0.1s) filter is timing-dependent and legitimately differs
/// between -j1 and -j4. The section frame (header lines + TOTAL row) is
/// compared exactly, so the section cannot be silently dropped.
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
        // The time report is on by default now; per-check durations — and
        // hence which checks pass the report's (>1% & >0.1s) filter —
        // legitimately differ between -j1 and -j4, so normalize the numbers
        // in place and drop the per-check rows: the section frame (headers
        // + TOTAL row) must still match exactly, so the section cannot be
        // silently dropped.
        normalize_time_report(&mut s);
        s
    }

    /// Scrub every decimal number in the time-report section to `N.N` and
    /// drop the per-check rows, keeping the header lines and the TOTAL row.
    /// Row presence follows the (>1% & >0.1s) filter, which is timing
    /// dependent and legitimately differs between -j1 and -j4; the frame
    /// must not. A missing section or a section not ending in TOTAL means
    /// the report was dropped or truncated: panic, because normalizing
    /// around the damage would pass vacuously or flake on the surviving
    /// timing-dependent rows instead of failing deterministically.
    fn normalize_time_report(s: &mut String) {
        let Some(start) = s.find("Check time report") else {
            panic!("time-report section missing from output");
        };
        let mut end = start;
        for line in s[start..].split_inclusive('\n') {
            end += line.len();
            if line.trim_start().starts_with("TOTAL") {
                break;
            }
        }
        let trailing_nl = s[..end].ends_with('\n');
        let mut lines: Vec<String> = s[start..end].lines().map(scrub_numbers).collect();
        // Two header lines, then the per-check rows, then the TOTAL row:
        // drop only the rows.
        let n = lines.len();
        assert!(
            n >= 3 && lines[n - 1].trim_start().starts_with("TOTAL"),
            "time report does not end with a TOTAL row: {lines:?}"
        );
        lines.drain(2..n - 1);
        let mut section = lines.join("\n");
        if trailing_nl {
            section.push('\n');
        }
        s.replace_range(start..end, &section);
    }

    /// Replace every `<digits>.<digits>` token with `N.N`. The report
    /// right-aligns numbers in fixed-width fields (`{duration:15.1}`), so
    /// the padding before a number shrinks as its digit count grows:
    /// absorb the padding and emit a single space instead, giving the
    /// scrubbed token a canonical width regardless of digit count.
    fn scrub_numbers(line: &str) -> String {
        let mut out = String::with_capacity(line.len());
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if c.is_ascii_digit() {
                let mut num = String::from(c);
                while chars.peek().is_some_and(|d| d.is_ascii_digit()) {
                    num.push(chars.next().unwrap());
                }
                let mut ahead = chars.clone();
                if ahead.next() == Some('.') && ahead.peek().is_some_and(|d| d.is_ascii_digit()) {
                    chars.next(); // the dot
                    while chars.peek().is_some_and(|d| d.is_ascii_digit()) {
                        chars.next();
                    }
                    let unpadded = out.trim_end_matches(' ').len();
                    if unpadded < out.len() {
                        out.truncate(unpadded);
                        if !out.is_empty() {
                            out.push(' ');
                        }
                    }
                    out.push_str("N.N");
                } else {
                    out.push_str(&num);
                }
            } else {
                out.push(c);
            }
        }
        out
    }
    let seq_out = normalized(&seq);
    let par_out = normalized(&par);
    assert!(
        seq_out.contains("4 packages and 0 specfiles checked"),
        "footer counts missing from sequential output"
    );
    assert_eq!(seq_out, par_out, "stdout differs");
    assert_eq!(
        sorted_lines(&String::from_utf8_lossy(&seq.stderr)),
        sorted_lines(&String::from_utf8_lossy(&par.stderr)),
        "stderr differs"
    );
}

/// Progress reporting (upstream rpmlint#255, rpmcrab#286): a multi-package
/// run logs one `checking <pkg> (n of m)` line per package on stderr, so a
/// stuck run shows where it stopped. `-j1` keeps pickup order deterministic.
#[test]
fn progress_lines_appear_for_multi_package_run() {
    let src = corpus_rpm();
    let dir = tempfile::tempdir().unwrap();
    let args: Vec<String> = (0..2)
        .map(|i| {
            let dst = dir.path().join(format!("pkg{i}.rpm"));
            std::fs::copy(&src, &dst).unwrap();
            dst.to_str().unwrap().to_string()
        })
        .collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let seq_args: Vec<&str> = std::iter::once("-j1").chain(refs.iter().copied()).collect();
    let out = rpmcrab(&seq_args);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("checking "),
        "progress lines must stay on stderr: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    for (i, r) in refs.iter().enumerate() {
        let line = format!("checking {r} ({} of 2)", i + 1);
        assert!(
            stderr.contains(&line),
            "missing progress line {line:?}: {stderr}"
        );
    }
}

/// Progress reporting stays quiet for a single package: no new noise in
/// normal output (rpmcrab#286).
#[test]
fn no_progress_line_for_single_package_run() {
    let arg = corpus_rpm().to_str().unwrap().to_string();
    let out = rpmcrab(&[arg.as_str()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("checking "),
        "single-package run must not log progress: {stderr}"
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

/// Issue #699: errors fail the run by default. Permissive mode is the
/// explicit `-P` opt-in only; no config key forces it. The parity RPM
/// has 2 errors.

#[test]
fn errors_fail_by_default() {
    // No flags: errors -> exit 64.
    let out = rpmcrab(&["../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm"]);
    assert_eq!(out.status.code(), Some(64));
}

#[test]
fn strict_flag_also_exits_64() {
    // `-s` changes printed levels, not the failing code.
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
fn permissive_by_default_key_is_inert() {
    // `PermissiveByDefault` is no longer read: neither value changes the
    // outcome — errors fail the run unless `-P` is passed. Its presence
    // warns on stderr instead of going silently inert.
    let dir = tempfile::tempdir().unwrap();
    for (name, value) in [("test.toml", "false"), ("test-true.toml", "true")] {
        let cfg = dir.path().join(name);
        std::fs::write(&cfg, format!("PermissiveByDefault = {value}\n")).unwrap();
        let out = rpmcrab(&[
            "-c",
            cfg.to_str().unwrap(),
            "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
        ]);
        assert_eq!(out.status.code(), Some(64), "PermissiveByDefault = {value}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("'PermissiveByDefault' has no effect since #699; ignoring it"),
            "got {stderr}"
        );
    }
}

#[test]
fn permissive_by_default_string_value_is_inert() {
    // A string `PermissiveByDefault` used to be a fatal config error via
    // the bool read; the key is not read at all now, so the run proceeds
    // and the parity RPM's errors fail it with 64.
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("test-str.toml");
    std::fs::write(&cfg, "PermissiveByDefault = \"true\"\n").unwrap();
    let out = rpmcrab(&[
        "-c",
        cfg.to_str().unwrap(),
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("fatal error in configuration"),
        "got {stderr}"
    );
    assert!(
        stderr.contains("'PermissiveByDefault' has no effect since #699; ignoring it"),
        "got {stderr}"
    );
}

#[test]
fn non_table_scoring_warns_on_stderr_and_is_ignored() {
    // `Scoring = 5` is not a table: the value is ignored (the run proceeds
    // with no scoring) but the ignore leaves a warning on stderr.
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("scoring-int.toml");
    std::fs::write(&cfg, "Scoring = 5\n").unwrap();
    let out = rpmcrab(&[
        "-c",
        cfg.to_str().unwrap(),
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("'Scoring' must be a table, found an integer; ignoring it"),
        "got {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("packages and 0 specfiles checked"),
        "the lint itself is unaffected, got {stdout}"
    );
}

#[test]
fn string_scoring_warns_on_stderr_and_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("scoring-str.toml");
    std::fs::write(&cfg, "Scoring = \"abc\"\n").unwrap();
    let out = rpmcrab(&[
        "-c",
        cfg.to_str().unwrap(),
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("'Scoring' must be a table, found a string; ignoring it"),
        "got {stderr}"
    );
}

#[test]
fn badness_threshold_key_is_inert() {
    // Issue #699: there is no badness threshold. The key may still appear
    // in a user config; it is read by nothing — no abort — and the parity
    // RPM's errors fail the run with 64. Its presence warns on stderr
    // instead of going silently inert.
    let dir = tempfile::tempdir().unwrap();
    // The string value and the integer 999 — the openSUSE flavour's
    // real-world abort threshold — are both inert: no abort (the
    // reference exits 66 over the threshold), and the parity RPM's
    // errors fail the run with 64 either way.
    for (name, value) in [
        ("threshold-str.toml", "\"abc\""),
        ("threshold-999.toml", "999"),
    ] {
        let cfg = dir.path().join(name);
        std::fs::write(&cfg, format!("BadnessThreshold = {value}\n")).unwrap();
        let out = rpmcrab(&[
            "-c",
            cfg.to_str().unwrap(),
            "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
        ]);
        assert_eq!(out.status.code(), Some(64), "BadnessThreshold = {value}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("'BadnessThreshold' has no effect since #699; ignoring it"),
            "got {stderr}"
        );
        assert!(
            !stderr.contains("exceeds threshold"),
            "no threshold abort may fire, got {stderr}"
        );
    }
}

#[test]
fn valid_scoring_table_produces_no_notice() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("scoring-ok.toml");
    std::fs::write(&cfg, "[Scoring]\n\"no-%check-section\" = 50\n").unwrap();
    let out = rpmcrab(&[
        "-c",
        cfg.to_str().unwrap(),
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("ignoring it"), "got {stderr}");
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
    assert_eq!(out.status.code(), Some(64));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let doc: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be a JSON document");
    assert_eq!(doc["program"], "rpmcrab");
    assert_eq!(doc["version"], env!("CARGO_PKG_VERSION"));
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
        assert!(f.get("badness").is_none(), "no badness field: {f}");
    }
    let summary = &doc["summary"];
    assert!(summary["errors"].as_u64().is_some());
    assert!(summary["warnings"].as_u64().is_some());
    assert_eq!(
        summary["exit_code"].as_i64(),
        Some(64),
        "summary exit code matches the process"
    );
    assert!(
        summary.get("score").is_none(),
        "no badness score: {summary}"
    );
    assert!(summary.get("aborted").is_none(), "no abort flag: {summary}");
}

/// The `%{echo:...}` probe spec shared by the JSON-diversion tests: the
/// echo expands while librpm parses the spec in-process, printing to the
/// process's stdout.
fn write_echo_spec(dir: &Path) -> std::path::PathBuf {
    let spec = dir.join("json-stdout-probe.spec");
    std::fs::write(
        &spec,
        "%global json_stdout_probe %{echo:RPMCRAB-JSON-STDOUT-PROBE}\n\
         Name: json-stdout-probe\n\
         Version: 1.0\n\
         Release: 1\n\
         Summary: probe\n\
         License: MIT\n\
         \n\
         %description\n\
         probe\n\
         \n\
         %prep\n\
         %{echo:RPMCRAB-JSON-STDOUT-PROBE-PREP}\n\
         \n\
         %files\n",
    )
    .unwrap();
    spec
}

/// A spec whose parse prints far more than a pipe buffer holds: one
/// `%global` per line, each expanding an `%{echo:...}` while librpm
/// parses it in-process. Proves the diverted run's stdout forwarder
/// keeps draining even when its own writes to stderr fail.
fn write_loud_echo_spec(dir: &Path) -> std::path::PathBuf {
    let mut text = String::from(
        "Name: json-stdout-loud-probe\n\
         Version: 1.0\n\
         Release: 1\n\
         Summary: probe\n\
         License: MIT\n",
    );
    for i in 0..2000 {
        text.push_str(&format!(
            "%global loud_probe_{i} %{{echo:RPMCRAB-LOUD-{i}-aaaaaaaaaaaaaaaaaaaaaaaa}}\n"
        ));
    }
    text.push_str("\n%description\nprobe\n\n%files\n");
    let spec = dir.join("json-stdout-loud-probe.spec");
    std::fs::write(&spec, text).unwrap();
    spec
}

/// `rpmcrab` with extra environment variables, for tests that must prove
/// the binary ignores (or honours) a specific ambient variable.
fn rpmcrab_env(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = rpmcrab_command();
    cmd.args(args).env("CONFIG_DISABLE_AUTOLOADING", "1");
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output().expect("spawn rpmcrab")
}

/// A spec can print to stdout while librpm parses it in-process:
/// `%{echo:...}` prints there by definition (and macro lua `print` does
/// the same). In JSON mode those prints must not corrupt the document --
/// stdout stays a single parseable JSON document (#703; the Factory
/// sweep captured the corruption for the real `bash` and `rspamd`
/// specs). Whether the platform's librpm expands the echo during this
/// parse at all is platform-dependent, so nothing here asserts where
/// the prints land -- only that they never reach stdout, and that the
/// run's exit code and the document's summary agree.
#[test]
fn format_json_is_not_polluted_by_spec_echo() {
    let dir = tempfile::tempdir().unwrap();
    let spec = write_echo_spec(dir.path());
    let out = rpmcrab(&["--format", "json", spec.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let doc: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be a single JSON document");
    assert_eq!(doc["program"], "rpmcrab");
    assert!(
        !stdout.contains("RPMCRAB-JSON-STDOUT-PROBE"),
        "spec prints leaked into the JSON stream: {stdout}"
    );
    assert_eq!(
        doc["summary"]["exit_code"].as_i64(),
        out.status.code().map(i64::from),
        "summary exit code matches the process"
    );
}

/// The diversion is keyed off the hidden `--__diverted-json` flag, never
/// the environment: a preset `RPMCRAB_JSON_REPORT_FILE` must neither
/// skip the diversion nor redirect the report -- the document still
/// lands on stdout and the named file is left untouched.
#[test]
fn format_json_ignores_ambient_report_file_env() {
    let dir = tempfile::tempdir().unwrap();
    let spec = write_echo_spec(dir.path());
    let sentinel = dir.path().join("sentinel.json");
    std::fs::write(&sentinel, "do not touch").unwrap();
    let out = rpmcrab_env(
        &["--format", "json", spec.to_str().unwrap()],
        &[("RPMCRAB_JSON_REPORT_FILE", sentinel.to_str().unwrap())],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let doc: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be a single JSON document");
    assert_eq!(doc["program"], "rpmcrab");
    assert!(
        !stdout.contains("RPMCRAB-JSON-STDOUT-PROBE"),
        "spec prints leaked into the JSON stream: {stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(&sentinel).unwrap(),
        "do not touch",
        "the ambient path must not be written"
    );
}

/// JSON selected by the config file (no `--format` flag) diverts too:
/// the echo-bearing spec's prints stay out of stdout.
#[test]
fn format_json_from_config_is_diverted() {
    let dir = tempfile::tempdir().unwrap();
    let spec = write_echo_spec(dir.path());
    let cfg = dir.path().join("format.toml");
    std::fs::write(&cfg, "OutputFormat = \"json\"\n").unwrap();
    let out = rpmcrab(&["-c", cfg.to_str().unwrap(), spec.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let doc: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be a single JSON document");
    assert_eq!(doc["program"], "rpmcrab");
    assert!(
        !stdout.contains("RPMCRAB-JSON-STDOUT-PROBE"),
        "spec prints leaked into the JSON stream: {stdout}"
    );
}

/// The child half of a diversion whose hand-back write fails is loud:
/// a failure code, an error on stderr, and no document on stdout --
/// never a silent empty success.
#[test]
fn diverted_json_write_failure_is_loud() {
    let dir = tempfile::tempdir().unwrap();
    let bad_path = dir.path().join("missing").join("report.json");
    let out = rpmcrab(&[
        "--format",
        "json",
        "--__diverted-json",
        bad_path.to_str().unwrap(),
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        out.stdout.is_empty(),
        "no document may be delivered when the hand-back write fails, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("writing the JSON report failed"),
        "the failure must be reported on stderr, got: {stderr}"
    );
}

/// A forged `--__diverted-json` naming a populated file (the
/// `~/.bashrc` case) must not write to it: the hand-back target has to
/// be the parent's fresh hand-back file -- existing, empty, a regular
/// file, not a symlink -- so the run refuses loudly and the named file
/// stays byte-identical.
#[test]
fn diverted_json_refuses_a_populated_target() {
    let dir = tempfile::tempdir().unwrap();
    let precious = dir.path().join("precious.txt");
    std::fs::write(&precious, "do not overwrite\n").unwrap();
    let out = rpmcrab(&[
        "--format",
        "json",
        "--__diverted-json",
        precious.to_str().unwrap(),
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        out.stdout.is_empty(),
        "no document may be delivered when the hand-back is refused, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("writing the JSON report failed")
            && stderr.contains("refusing the diverted report target"),
        "the refusal must be reported on stderr, got: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&precious).unwrap(),
        "do not overwrite\n",
        "the forged target must stay byte-identical"
    );
}

/// A forged flag naming a symlink is refused the same way: the write
/// must never follow the link into a real file.
#[test]
#[cfg(unix)]
fn diverted_json_refuses_a_symlink_target() {
    let dir = tempfile::tempdir().unwrap();
    let precious = dir.path().join("precious.txt");
    std::fs::write(&precious, "do not overwrite\n").unwrap();
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&precious, &link).unwrap();
    let out = rpmcrab(&[
        "--format",
        "json",
        "--__diverted-json",
        link.to_str().unwrap(),
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing the diverted report target") && stderr.contains("symlink"),
        "the refusal must be reported on stderr, got: {stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&precious).unwrap(),
        "do not overwrite\n",
        "the link target must stay byte-identical"
    );
}

/// A forged flag naming a path that does not exist must not create
/// it: the hand-back file is always created by the parent, so there
/// is no implicit creation on the write side.
#[test]
fn diverted_json_does_not_create_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("report.json");
    let out = rpmcrab(&[
        "--format",
        "json",
        "--__diverted-json",
        missing.to_str().unwrap(),
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("writing the JSON report failed"),
        "the refusal must be reported on stderr, got: {stderr}"
    );
    assert!(
        !missing.exists(),
        "a forged flag must not create its target file"
    );
}

/// Even an empty regular file is refused when it is not owner-only:
/// the parent's hand-back file is, so anything looser is not it.
#[test]
#[cfg(unix)]
fn diverted_json_refuses_a_shared_empty_target() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let shared = dir.path().join("shared.json");
    std::fs::write(&shared, "").unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = rpmcrab(&[
        "--format",
        "json",
        "--__diverted-json",
        shared.to_str().unwrap(),
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing the diverted report target") && stderr.contains("owner-only"),
        "the refusal must be reported on stderr, got: {stderr}"
    );
}

/// The genuine hand-back shape -- an empty, owner-only regular file,
/// exactly what the parent creates -- is accepted: the document lands
/// in the file and stdout stays empty.
#[test]
#[cfg(unix)]
fn diverted_json_accepts_a_fresh_handoff_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let handoff = dir.path().join("handoff.json");
    std::fs::write(&handoff, "").unwrap();
    std::fs::set_permissions(&handoff, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = rpmcrab(&[
        "--format",
        "json",
        "--__diverted-json",
        handoff.to_str().unwrap(),
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert!(
        out.stdout.is_empty(),
        "the document goes to the hand-back file, not stdout, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let written = std::fs::read_to_string(&handoff).unwrap();
    let doc: serde_json::Value =
        serde_json::from_str(&written).expect("the hand-back file holds the JSON document");
    assert_eq!(doc["program"], "rpmcrab");
}

/// The hand-back write replaces the target instead of writing into
/// it: the document is staged in a sibling file and renamed over the
/// target, so the target's inode changes across a successful write.
/// Writing into the validated file directly would keep the inode --
/// and a writer dying mid-write would leave a partial prefix in it
/// for the parent to copy out as the document.
#[test]
#[cfg(unix)]
fn diverted_json_handoff_write_replaces_the_target() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let handoff = dir.path().join("handoff.json");
    std::fs::write(&handoff, "").unwrap();
    std::fs::set_permissions(&handoff, std::fs::Permissions::from_mode(0o600)).unwrap();
    let inode_before = std::fs::metadata(&handoff).unwrap().ino();
    let out = rpmcrab(&[
        "--format",
        "json",
        "--__diverted-json",
        handoff.to_str().unwrap(),
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert!(out.stdout.is_empty());
    assert_ne!(
        std::fs::metadata(&handoff).unwrap().ino(),
        inode_before,
        "the staged document is renamed over the target, replacing it"
    );
    let written = std::fs::read_to_string(&handoff).unwrap();
    let doc: serde_json::Value =
        serde_json::from_str(&written).expect("the hand-back file holds the JSON document");
    assert_eq!(doc["program"], "rpmcrab");
}

/// A configuration that both warns and fails fatally still shows its
/// warnings: they are collected (not printed) while loading so a
/// diverted run can dedup them, and the fatal path flushes the
/// collected copies ahead of the fatal line instead of dropping
/// them with the failed load.
#[test]
fn config_fatal_still_prints_load_warnings() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("fatal.toml");
    std::fs::write(&cfg, "BadnessThreshold = 999\nSeverityOverrides = 42\n").unwrap();
    let spec = write_echo_spec(dir.path());
    let out = rpmcrab(&["-c", cfg.to_str().unwrap(), spec.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("'BadnessThreshold' has no effect"),
        "the load warning survives the fatal load: {stderr}"
    );
    assert!(
        stderr.contains("fatal error in configuration"),
        "the fatal error is reported: {stderr}"
    );
    let warning_at = stderr.find("'BadnessThreshold' has no effect").unwrap();
    let fatal_at = stderr.find("fatal error in configuration").unwrap();
    assert!(
        warning_at < fatal_at,
        "the warning is flushed ahead of the fatal line: {stderr}"
    );
}

/// The same flush happens in a diverted run's child: a
/// command-line `--format json` run diverts before the configuration
/// is loaded, so the child's fatal load is the only place the
/// warnings can be printed -- exactly once, on the forwarded stderr.
#[test]
fn diverted_config_fatal_still_prints_load_warnings_once() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("fatal.toml");
    std::fs::write(&cfg, "BadnessThreshold = 999\nSeverityOverrides = 42\n").unwrap();
    let spec = write_echo_spec(dir.path());
    let out = rpmcrab(&[
        "--format",
        "json",
        "-c",
        cfg.to_str().unwrap(),
        spec.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        out.stdout.is_empty(),
        "no document may be delivered when the load fails, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr.matches("'BadnessThreshold' has no effect").count(),
        1,
        "the load warning survives the child's fatal load, once: {stderr}"
    );
    assert!(
        stderr.contains("fatal error in configuration"),
        "the child's fatal error is forwarded: {stderr}"
    );
}

/// A config-selected JSON run emits each load warning exactly once:
/// the parent holds its copies back when it hands the run to the
/// child, and the child prints its own.
#[test]
fn format_json_from_config_prints_load_warnings_once() {
    let dir = tempfile::tempdir().unwrap();
    let spec = write_echo_spec(dir.path());
    let cfg = dir.path().join("warn.toml");
    std::fs::write(&cfg, "OutputFormat = \"json\"\nFlavor = \"bogus\"\n").unwrap();
    let out = rpmcrab(&["-c", cfg.to_str().unwrap(), spec.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let doc: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be a single JSON document");
    assert_eq!(doc["program"], "rpmcrab");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr.matches("unknown Flavor").count(),
        1,
        "each load warning must be emitted once, got: {stderr}"
    );
}

/// The invalid-`RUST_LOG` warning likewise comes from the child
/// alone: a command-line-diverted run's parent never initialises its
/// tracing subscriber, so it cannot print a first copy.
#[test]
fn format_json_prints_the_rust_log_warning_once() {
    let dir = tempfile::tempdir().unwrap();
    let spec = write_echo_spec(dir.path());
    let out = rpmcrab_env(
        &["--format", "json", spec.to_str().unwrap()],
        &[("RUST_LOG", "!!")],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let doc: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be a single JSON document");
    assert_eq!(doc["program"], "rpmcrab");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr.matches("ignoring invalid RUST_LOG").count(),
        1,
        "the warning must be emitted once, got: {stderr}"
    );
}

/// A diverted run delivers its document whatever the child's
/// verdict: a non-zero exit is the ordinary lint outcome (here,
/// `--strict` promotions), not a failed child, so the parent copies
/// the report out and forwards the code unchanged.
#[test]
fn diverted_run_delivers_the_document_on_a_nonzero_verdict() {
    let rpm = binaries_fixture_rpm();
    let out = rpmcrab(&["--format", "json", "-s", rpm.to_str().unwrap()]);
    assert_ne!(
        out.status.code(),
        Some(0),
        "the strict run must report a non-zero verdict"
    );
    let doc: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout))
        .expect("the document is delivered on a non-zero verdict");
    assert_eq!(doc["program"], "rpmcrab");
    assert_eq!(
        doc["summary"]["exit_code"].as_i64(),
        out.status.code().map(i64::from),
        "summary exit code matches the process"
    );
}

/// A diverted child that fails has already explained itself on the
/// forwarded stderr (here: a positional path that does not exist);
/// the parent forwards its exit code without adding a hand-off
/// complaint of its own.
#[test]
fn diverted_child_failure_adds_no_parent_noise() {
    let out = rpmcrab(&["--format", "json", "/no/such/package.rpm"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not exist"),
        "the child's own explanation is forwarded, got: {stderr}"
    );
    // The parent's hand-off diagnostics all share the one stem;
    // none of them may appear here, not just the empty-report one.
    assert!(
        !stderr.contains("the diverted JSON run"),
        "the parent must not add noise to a child-explained failure, got: {stderr}"
    );
}

/// If the diverted run's stderr fails mid-forward (the pipe
/// below has no reader, so every write to it fails at once), the
/// parent keeps draining the child's stdout instead of abandoning
/// the pipe: otherwise the pipe fills, the child wedges mid-print
/// and the run hangs. The document must still land on stdout.
#[test]
#[cfg(unix)]
fn diverted_run_survives_a_broken_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let spec = write_loud_echo_spec(dir.path());
    // A stderr that rejects every write: a pipe whose read end is
    // dropped before the spawn, so the first forwarded write fails
    // with EPIPE (the runtime ignores SIGPIPE) -- the broken
    // downstream the forwarder must survive, on any Unix.
    let (reader, writer) = std::io::pipe().expect("pipe for the broken stderr");
    drop(reader);
    let mut cmd = rpmcrab_command();
    cmd.args(["--format", "json", spec.to_str().unwrap()])
        .env("CONFIG_DISABLE_AUTOLOADING", "1")
        .stderr(std::process::Stdio::from(writer))
        .stdout(std::process::Stdio::piped());
    let out = cmd.output().expect("spawn rpmcrab");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let doc: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be a single JSON document");
    assert_eq!(doc["program"], "rpmcrab");
    assert_eq!(
        doc["summary"]["exit_code"].as_i64(),
        out.status.code().map(i64::from),
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
        let Some((level, rest)) = found else {
            continue;
        };
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
/// versioned-and-unversioned claim is not always accurate), extended by
/// the 2026-10-27 reword: no claim that the redundant provide is manual
/// (dependency-generator pairs have no manual provide), and the warning
/// split for generator pairs is documented.
#[test]
fn explain_useless_provides_reworded() {
    let out = rpmcrab(&["-e", "useless-provides"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "useless-provides:
This package provides the same capacity more than once: the same provide name
appears in both unversioned and versioned form (e.g. 'foo' together with 'foo
= 1.0'), so one of the two forms is redundant. When both forms are produced by
a dependency generator (e.g. a Perl module declared in several shipped files,
carrying a version in one of them and none in another), the duplication is the
generator's doing: the finding is a warning. When a hand-written provide
duplicates the other form, the finding is an error: remove the redundant
manual provide.


",
        "exact --explain stdout"
    );
    assert!(out.stderr.is_empty());
}

/// `--explain` for the port-only `obsolete-tmpfiles-macro` finding: the
/// description is registered in code (like the reference's other SpecCheck
/// descriptions), pinned byte-exact.
#[test]
fn explain_obsolete_tmpfiles_macro() {
    let out = rpmcrab(&["-e", "obsolete-tmpfiles-macro"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "obsolete-tmpfiles-macro:\nThe %tmpfiles_create and %tmpfiles_create_package macros are no-ops:\ntmpfiles.d entries are created by the systemd package's file triggers at\ninstall time. Remove the macro call from the scriptlet.\n\n\n",
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

/// A config file that merges a scalar into a list key set by an earlier
/// file is a fatal configuration error (exit 1), not a panic: the
/// reference dies with a TypeError on the same merge, and crash-parity is
/// out (#494).
#[test]
fn scalar_merged_into_list_config_is_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.toml");
    std::fs::write(&base, "Checks = [\"TagsCheck\"]\n").unwrap();
    let bad = dir.path().join("bad.toml");
    std::fs::write(&bad, "Checks = 42\n").unwrap();
    let out = rpmcrab(&[
        "-c",
        base.to_str().unwrap(),
        "-c",
        bad.to_str().unwrap(),
        "-p",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("fatal error in configuration"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("'Checks'"), "stderr: {stderr}");
    assert!(!stderr.contains("panicked"), "stderr: {stderr}");
}

/// The exit code follows the overridden levels end to end (DESIGN \u00a74.6):
/// in strict mode every native error-level finding (enumerated from a
/// non-strict `--format json` baseline) is overridden to W, so the only
/// remaining errors are strict promotions of the non-overridden native
/// warnings/infos — and the run exits 64, like any run with errors
/// (issue #699: there is no separate all-promotions code).
#[test]
fn severity_override_exit_code_follows_rewritten_levels() {
    use std::collections::HashSet;
    let rpm = binaries_fixture_rpm();
    // Non-strict baseline: the fixture's errors fail the run (exit 64);
    // the JSON findings give the native levels.
    let baseline = rpmcrab(&["--format", "json", rpm.to_str().unwrap()]);
    assert_eq!(baseline.status.code(), Some(64));
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
    assert_eq!(out.status.code(), Some(64));
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
/// `lint.py:272`), even though only 40 checks run.
#[test]
fn errors_only_header_reports_configured_check_count() {
    let out = rpmcrab(&[
        "--errors-only",
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(64));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("checks: 45, packages: 1"),
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

/// `--checks SystemdInstallCheck --errors-only`: SystemdInstallCheck is
/// warning-only (its only emission site passes `Level::Warning`), so the
/// run is empty and warns like any other warning-only selection.
#[test]
fn errors_only_skips_systemd_install_check() {
    let out = rpmcrab(&[
        "--errors-only",
        "--checks",
        "SystemdInstallCheck",
        "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--errors-only skipped every selected check, nothing to run"),
        "stderr: {stderr}"
    );
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
/// (the six skipped checks fire nothing on this fixture), no finding names
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
                "SourceCheck",
                "SystemdInstallCheck",
                "TmpFilesCheck"
            ]
            .contains(&check),
            "warning-only check ran: {check}"
        );
    }
    assert_eq!(eo_doc["checks"], 45);
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

/// An rpmlintrc `setBadness` line is reported as
/// `rpmlintrc-uses-setbadness` at W, once per occurrence, with and
/// without `--ignore-unused-rpmlintrc` (that flag gates only the
/// unused-filter audit). Comment mentions and `addFilter` lines in
/// the same file stay quiet. The warning alone does not fail the run.
#[test]
fn rpmlintrc_setbadness_is_reported_with_and_without_ignore_unused() {
    let dir = std::env::temp_dir().join("rpmcrab-setbadness-report");
    std::fs::create_dir_all(&dir).unwrap();
    let rc = dir.join("test.rc");
    std::fs::write(
        &rc,
        "# setBadness in a comment stays quiet\naddFilter(\"some-check\")\nsetBadness('first-check', 0)\n  setBadness('second-check', 10)\n",
    )
    .unwrap();
    let rpm = "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm";
    for extra in [[].as_slice(), ["--ignore-unused-rpmlintrc"].as_slice()] {
        let mut args = vec!["-r", rc.to_str().unwrap()];
        args.extend_from_slice(extra);
        args.push(rpm);
        let out = rpmcrab(&args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            stdout.matches("W: rpmlintrc-uses-setbadness").count(),
            2,
            "one warning per occurrence (extra args {extra:?}): {stdout}"
        );
        assert!(
            stdout.contains("line 3: setBadness('first-check', 0)"),
            "the detail names the occurrence: {stdout}"
        );
        assert!(
            stdout.contains("line 4: setBadness('second-check', 10)"),
            "the detail names the occurrence: {stdout}"
        );
    }
}

/// The apparmor shape (#816): an rpmlintrc whose only unmatched pattern is
/// reported by the audit while every error the package itself draws is
/// filtered. The matching patterns cover the fixture's own errors: the
/// three it draws intrinsically, plus `spelling-error` for the errors its
/// prose summary and description draw wherever a system hunspell
/// dictionary is installed (CI installs the en_US pair; a bare
/// development machine has none, and the run must behave the same in
/// both). A run whose only error would be the audit finding exits 0 in
/// default mode — the reference exits 0 on it in every non-strict run —
/// and the finding prints at W. `--strict` promotes it to E like every
/// other finding and the run exits 64.
#[test]
fn unused_rpmlintrc_filter_alone_does_not_fail_the_run() {
    let dir = std::env::temp_dir().join("rpmcrab-unused-filter-exit");
    std::fs::create_dir_all(&dir).unwrap();
    let rc = dir.join("test.rc");
    std::fs::write(
        &rc,
        "addFilter(\"deprecated-init-script\")\naddFilter(\"daemon-activation-in-%post\")\naddFilter(\"invalid-license\")\naddFilter(\"spelling-error\")\naddFilter(\"hidden-file-or-dir /usr/share/apparmor/cache/[0-9a-f]*.0/.features\")\n",
    )
    .unwrap();
    let rpm = "../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm";

    let out = rpmcrab(&["-r", rc.to_str().unwrap(), rpm]);
    assert_eq!(out.status.code(), Some(0), "default run must exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(
            "W: unused-rpmlintrc-filter \"hidden-file-or-dir /usr/share/apparmor/cache/[0-9a-f]*.0/.features\""
        ),
        "the audit reports the stale pattern at W: {stdout}"
    );

    let out = rpmcrab(&["-r", rc.to_str().unwrap(), "-s", rpm]);
    assert_eq!(out.status.code(), Some(64), "strict run must exit 64");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("E: unused-rpmlintrc-filter"),
        "strict promotion prints the audit at E: {stdout}"
    );
}

/// A spec that draws `no-license-file-in-spec` (issue #821): an archive
/// source, a `License:` tag that is not public-domain-only, and a
/// `%files` section whose only entry ships a program, so no section
/// marks a licence file.
fn write_unlicensed_spec(dir: &Path, name: &str) -> std::path::PathBuf {
    let spec = dir.join(format!("{name}.spec"));
    std::fs::write(
        &spec,
        format!(
            "Name: {name}\n\
             Version: 1.0\n\
             Release: 1\n\
             Summary: probe\n\
             License: MIT\n\
             Source: {name}-1.0.tar.gz\n\
             \n\
             %description\n\
             probe\n\
             \n\
             %files\n\
             %{{_bindir}}/{name}\n"
        ),
    )
    .unwrap();
    spec
}

/// The session header's `rpmlintrc:` block: the loaded files, in load
/// order, one per line, indented four spaces. No block prints when
/// nothing was loaded.
fn loaded_rpmlintrcs(stdout: &str) -> Vec<&str> {
    let mut lines = stdout.lines();
    if lines.by_ref().find(|l| *l == "rpmlintrc:").is_none() {
        return Vec::new();
    }
    lines
        .take_while(|l| l.starts_with("    "))
        .map(|l| l.trim())
        .collect()
}

/// The run summary's filtered count (the `N filtered` field).
fn filtered_count(stdout: &str) -> u64 {
    let idx = stdout.find(" filtered;").expect("summary line present");
    let digits: String = stdout[..idx]
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    digits.parse().expect("filtered count is numeric")
}

/// Issue #830: an rpmlintrc beside a spec is discovered however many
/// positional arguments the run has, so its name-scoped filters apply
/// identically standalone and in a multi-spec run, in either order.
/// (The reference discovers beside a lone argument only, so the
/// filtered spec's error surfaces there in every multi-spec run.)
#[test]
fn rpmlintrc_discovery_beside_every_argument_830() {
    let dir = tempfile::tempdir().unwrap();
    let eagle_dir = dir.path().join("a");
    let partner_dir = dir.path().join("b");
    std::fs::create_dir(&eagle_dir).unwrap();
    std::fs::create_dir(&partner_dir).unwrap();
    let eagle = write_unlicensed_spec(&eagle_dir, "eagleprobe");
    std::fs::write(
        eagle_dir.join("eagleprobe-rpmlintrc"),
        "addFilter(\"eagleprobe.* *.*\")\n",
    )
    .unwrap();
    let partner = write_unlicensed_spec(&partner_dir, "partnerprobe");
    let rc_display = eagle_dir.join("eagleprobe-rpmlintrc").display().to_string();
    let eagle_arg = eagle.to_str().unwrap();
    let partner_arg = partner.to_str().unwrap();

    // Standalone: the rc is discovered and the blanket filter applies.
    let out = rpmcrab(&[eagle_arg]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        loaded_rpmlintrcs(&stdout),
        vec![rc_display.as_str()],
        "stdout: {stdout}"
    );
    assert_eq!(
        stdout.matches("no-license-file-in-spec").count(),
        0,
        "stdout: {stdout}"
    );
    let standalone_filtered = filtered_count(&stdout);
    assert!(standalone_filtered > 0, "stdout: {stdout}");

    // In a pair, either order: the same file loads, the filtered spec
    // stays filtered (the identical filtered count), and the partner's
    // own error surfaces.
    for args in [[eagle_arg, partner_arg], [partner_arg, eagle_arg]] {
        let out = rpmcrab(&args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            loaded_rpmlintrcs(&stdout),
            vec![rc_display.as_str()],
            "stdout: {stdout}"
        );
        assert_eq!(
            stdout.matches("no-license-file-in-spec").count(),
            1,
            "stdout: {stdout}"
        );
        assert!(
            stdout.contains("partnerprobe.spec: E: no-license-file-in-spec"),
            "stdout: {stdout}"
        );
        assert_eq!(
            filtered_count(&stdout),
            standalone_filtered,
            "stdout: {stdout}"
        );
    }
}

/// Issue #874: a bare file name argument (`rpmcrab foo.spec` from
/// inside its directory) still discovers the rpmlintrc beside it --
/// the name's directory is the current directory.
#[test]
fn rpmlintrc_discovery_beside_a_bare_filename_874() {
    let dir = tempfile::tempdir().unwrap();
    write_unlicensed_spec(dir.path(), "bareprobe");
    std::fs::write(
        dir.path().join("bareprobe-rpmlintrc"),
        "addFilter(\"bareprobe.* *.*\")\n",
    )
    .unwrap();
    let mut cmd = rpmcrab_command();
    cmd.args(["bareprobe.spec"])
        .current_dir(dir.path())
        .env("CONFIG_DISABLE_AUTOLOADING", "1")
        .env("RPMCRAB_DISABLE_NGRAM_SUGGESTIONS", "1");
    let out = cmd.output().expect("spawn rpmcrab");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        loaded_rpmlintrcs(&stdout),
        vec!["./bareprobe-rpmlintrc"],
        "stdout: {stdout}"
    );
    assert_eq!(
        stdout.matches("no-license-file-in-spec").count(),
        0,
        "stdout: {stdout}"
    );
    assert!(filtered_count(&stdout) > 0, "stdout: {stdout}");
}

/// Issue #830: two arguments in different directories each contribute
/// their own beside rpmlintrc; both load, so both specs' name-scoped
/// filters apply.
#[test]
fn rpmlintrc_discovery_loads_each_arguments_rc_830() {
    let dir = tempfile::tempdir().unwrap();
    let a_dir = dir.path().join("adir");
    let b_dir = dir.path().join("bdir");
    std::fs::create_dir(&a_dir).unwrap();
    std::fs::create_dir(&b_dir).unwrap();
    let aaa = write_unlicensed_spec(&a_dir, "aaaprobe");
    std::fs::write(
        a_dir.join("aaaprobe-rpmlintrc"),
        "addFilter(\"aaaprobe.* *.*\")\n",
    )
    .unwrap();
    let bbb = write_unlicensed_spec(&b_dir, "bbbprobe");
    std::fs::write(
        b_dir.join("bbbprobe-rpmlintrc"),
        "addFilter(\"bbbprobe.* *.*\")\n",
    )
    .unwrap();

    let out = rpmcrab(&[aaa.to_str().unwrap(), bbb.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        loaded_rpmlintrcs(&stdout),
        vec![
            a_dir
                .join("aaaprobe-rpmlintrc")
                .display()
                .to_string()
                .as_str(),
            b_dir
                .join("bbbprobe-rpmlintrc")
                .display()
                .to_string()
                .as_str(),
        ],
        "stdout: {stdout}"
    );
    // Both filters apply: nothing either spec drew is printed, so the
    // run exits 0. Loading only one rc would leave the other spec's
    // error standing and exit 64.
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}");
    assert_eq!(
        stdout.matches("no-license-file-in-spec").count(),
        0,
        "stdout: {stdout}"
    );
}

/// Issue #830: explicit `-r` files still win outright in a multi-spec
/// run — no auto-discovery happens beside any argument, and the
/// explicit file's patterns are the ones the audit accounts.
#[test]
fn rpmlintrc_discovery_explicit_r_still_wins_830() {
    let dir = tempfile::tempdir().unwrap();
    let eagle = write_unlicensed_spec(dir.path(), "eagleprobe");
    std::fs::write(
        dir.path().join("eagleprobe-rpmlintrc"),
        "addFilter(\"eagleprobe.* *.*\")\n",
    )
    .unwrap();
    let partner = write_unlicensed_spec(dir.path(), "partnerprobe");
    let explicit = dir.path().join("explicit.rc");
    std::fs::write(&explicit, "addFilter(\"explicit-only-pattern-830\")\n").unwrap();

    let out = rpmcrab(&[
        "-r",
        explicit.to_str().unwrap(),
        eagle.to_str().unwrap(),
        partner.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        loaded_rpmlintrcs(&stdout),
        vec![explicit.display().to_string().as_str()],
        "stdout: {stdout}"
    );
    // The beside file never loaded, so the error it would have filtered
    // surfaces.
    assert!(
        stdout.contains("eagleprobe.spec: E: no-license-file-in-spec"),
        "stdout: {stdout}"
    );
    // The explicit file's unmatched pattern is audited, once.
    assert_eq!(
        stdout.matches("unused-rpmlintrc-filter").count(),
        1,
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("unused-rpmlintrc-filter \"explicit-only-pattern-830\""),
        "stdout: {stdout}"
    );
}

/// Issue #830: a hit in the configured `RpmlintrcSearchPaths` still
/// suppresses the beside-argument lookup, however many arguments the
/// run has.
#[test]
fn rpmlintrc_discovery_search_paths_still_win_830() {
    let dir = tempfile::tempdir().unwrap();
    let search_dir = dir.path().join("search");
    std::fs::create_dir(&search_dir).unwrap();
    std::fs::write(
        search_dir.join("search.rpmlintrc"),
        "addFilter(\"search-path-only-pattern-830\")\n",
    )
    .unwrap();
    let config = dir.path().join("probe.toml");
    std::fs::write(
        &config,
        format!("RpmlintrcSearchPaths = ['{}']\n", search_dir.display()),
    )
    .unwrap();
    let eagle = write_unlicensed_spec(dir.path(), "eagleprobe");
    std::fs::write(
        dir.path().join("eagleprobe-rpmlintrc"),
        "addFilter(\"eagleprobe.* *.*\")\n",
    )
    .unwrap();
    let partner = write_unlicensed_spec(dir.path(), "partnerprobe");

    let out = rpmcrab(&[
        "-c",
        config.to_str().unwrap(),
        eagle.to_str().unwrap(),
        partner.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        loaded_rpmlintrcs(&stdout),
        vec![
            search_dir
                .join("search.rpmlintrc")
                .display()
                .to_string()
                .as_str()
        ],
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("eagleprobe.spec: E: no-license-file-in-spec"),
        "stdout: {stdout}"
    );
    assert_eq!(
        stdout.matches("unused-rpmlintrc-filter").count(),
        1,
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("unused-rpmlintrc-filter \"search-path-only-pattern-830\""),
        "stdout: {stdout}"
    );
}

/// Issue #830: two specs sharing one directory share its rpmlintrc —
/// the file loads once, and the audit reports its unmatched pattern
/// once, not once per argument that discovered it.
#[test]
fn rpmlintrc_discovery_shared_rc_loads_and_audits_once_830() {
    let dir = tempfile::tempdir().unwrap();
    let ccc = write_unlicensed_spec(dir.path(), "cccprobe");
    let ddd = write_unlicensed_spec(dir.path(), "dddprobe");
    let shared = dir.path().join("shared.rpmlintrc");
    std::fs::write(
        &shared,
        "addFilter(\"cccprobe.* *.*\")\naddFilter(\"never-matches-830\")\n",
    )
    .unwrap();

    let out = rpmcrab(&[ccc.to_str().unwrap(), ddd.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        loaded_rpmlintrcs(&stdout),
        vec![shared.display().to_string().as_str()],
        "stdout: {stdout}"
    );
    // The used pattern filtered its spec; the other spec's error
    // surfaces; the unused pattern is reported exactly once.
    assert!(
        !stdout.contains("cccprobe.spec: E: no-license-file-in-spec"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("dddprobe.spec: E: no-license-file-in-spec"),
        "stdout: {stdout}"
    );
    assert_eq!(
        stdout.matches("unused-rpmlintrc-filter").count(),
        1,
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("unused-rpmlintrc-filter \"never-matches-830\""),
        "stdout: {stdout}"
    );
}

/// Issue #830 control: with no rpmlintrc beside any argument, a
/// multi-spec run loads none and every spec's error surfaces — the
/// fixture specs the discovery pins rely on do fire unfiltered.
#[test]
fn rpmlintrc_discovery_without_any_rc_is_a_no_op_830() {
    let dir = tempfile::tempdir().unwrap();
    let eagle = write_unlicensed_spec(dir.path(), "eagleprobe");
    let partner = write_unlicensed_spec(dir.path(), "partnerprobe");

    let out = rpmcrab(&[eagle.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(loaded_rpmlintrcs(&stdout).is_empty(), "stdout: {stdout}");
    assert_eq!(
        stdout.matches("no-license-file-in-spec").count(),
        1,
        "stdout: {stdout}"
    );

    let out = rpmcrab(&[eagle.to_str().unwrap(), partner.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(loaded_rpmlintrcs(&stdout).is_empty(), "stdout: {stdout}");
    assert_eq!(
        stdout.matches("no-license-file-in-spec").count(),
        2,
        "stdout: {stdout}"
    );
    assert_eq!(out.status.code(), Some(64), "stdout: {stdout}");
}

/// `--explain`: staged `AlternativesCheck.toml` resolves `alternative-generic-name-not-symlink` instead of "Unknown message".
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

/// `--explain`: staged `AppDataCheck.toml` resolves `invalid-appdata-file` instead of "Unknown message".
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

/// `--explain`: staged `BashismsCheck.toml` resolves `bin-sh-syntax-error` instead of "Unknown message".
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

/// `--explain`: staged `BrandingPolicyCheck.toml` resolves `branding-conflicts-missing` instead of "Unknown message".
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

/// `--explain`: `branding-requires-unversioned` description (#953) also covers
/// branding on a different version train, whose versioned requirement cannot
/// be satisfied, directing such packages to suppress the warning in rpmlintrc.
#[test]
fn explain_branding_requires_unversioned() {
    let out = rpmcrab(&["-e", "branding-requires-unversioned"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "branding-requires-unversioned:\nPlease make sure that your requires entry is similar to: 'Requires:\n%name-branding = <versionnumber>' Where the branding is versioned on a\ndifferent train than the package, so its version does not track the package\nversion, a versioned requirement cannot be satisfied; suppress this warning in\nthe package's rpmlintrc instead.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `BuildRootAndDateCheck.toml` resolves `file-contains-current-date` instead of "Unknown message".
#[test]
fn explain_staged_build_root_and_date_check() {
    let out = rpmcrab(&["-e", "file-contains-current-date"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "file-contains-current-date:\nYour file contains the current date. Its content therefore changes with the\nbuild date, so rebuilding the same sources may not produce the same package.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `CheckForXinetd.toml` resolves `obsolete-xinetd-requirement` instead of "Unknown message".
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

/// `--explain`: staged `DBusPolicyCheck.toml` resolves `dbus-policy-allow-without-destination` instead of "Unknown message".
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

/// `--explain`: staged `DocCheck.toml` resolves `executable-docs` instead of "Unknown message".
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

/// `--explain`: staged `DuplicatesCheck.toml` resolves `files-duplicate` instead of "Unknown message".
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

/// `--explain`: staged `ErlangCheck.toml` resolves `beam-compile-info-missed` instead of "Unknown message".
#[test]
fn explain_staged_erlang_check() {
    let out = rpmcrab(&["-e", "beam-compile-info-missed"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "beam-compile-info-missed:\nYour beam file is missing the compile_info chunk.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `FileDigestCheck.toml` resolves `cron-file-unauthorized` instead of "Unknown message".
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

/// `--explain`: staged `FileMetadataCheck.toml` resolves `device-unauthorized-file` instead of "Unknown message".
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

/// `--explain`: staged `FilelistCheck.toml` resolves `filelist-forbidden` instead of "Unknown message".
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

/// `--explain`: staged `FilesCheck.toml` resolves the port-only `sysconfig-fillup-usage` instead of "Unknown message".
#[test]
fn explain_staged_sysconfig_fillup_usage() {
    let out = rpmcrab(&["-e", "sysconfig-fillup-usage"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "sysconfig-fillup-usage:\nThe package uses the legacy sysconfig/fillup configuration scheme: it ships a\nfile below /etc/sysconfig or a fillup template, calls fillup from a scriptlet,\nor points a systemd unit's EnvironmentFile into /etc/sysconfig. Migrate to\ndaemon-native configuration, or to systemd drop-ins and an EnvironmentFile\npointing at a package-owned path, instead of configuration merged into\n/etc/sysconfig by fillup.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `FilesCheck.toml` resolves `non-ghost-file` instead of "Unknown message".
#[test]
fn explain_staged_files_check() {
    let out = rpmcrab(&["-e", "non-ghost-file"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "non-ghost-file:\nFile should be tagged %ghost.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `KMPPolicyCheck.toml` resolves `kmp-missing-requires` instead of "Unknown message".
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

/// `--explain`: staged `LogrotateCheck.toml` resolves `logrotate-log-dir-not-packaged` instead of "Unknown message".
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

/// `--explain`: staged `MenuCheck.toml` resolves `non-file-in-menu-dir` instead of "Unknown message".
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

/// `--explain`: staged `MenuXDGCheck.toml` resolves `invalid-desktopfile` instead of "Unknown message".
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

/// `--explain`: staged `PkgConfigCheck.toml` resolves `invalid-pkgconfig-file` instead of "Unknown message".
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

/// `--explain`: staged `PolkitCheck.toml` resolves `polkit-user-privilege` instead of "Unknown message".
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

/// `--explain`: staged `PythonCheck.toml` resolves `python-doc-in-package` instead of "Unknown message".
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

/// `--explain`: staged `SELinuxIndependentModuleCheck.toml` resolves `selinux-incorrect-if-file-location` instead of "Unknown message".
#[test]
fn explain_staged_selinux_independent_module_check() {
    let out = rpmcrab(&["-e", "selinux-incorrect-if-file-location"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "selinux-incorrect-if-file-location:\nSELinux interface (.if) files must be installed in the policy devel include\ntree, /usr/share/selinux/devel/include/ — in distributed/ for independent\nmodules, or directly in one of its layer directories, which the policy devel\nMakefile collects when building consuming modules, as per Fedora and openSUSE\nindependent module packaging guidelines. Files found elsewhere are packaging\nerrors.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `SUIDPermissionsCheck.toml` resolves `permissions-symlink` instead of "Unknown message".
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

/// `--explain`: staged `SharedLibraryPolicyCheck.toml` resolves `shlib-policy-missing-lib` instead of "Unknown message".
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

/// `--explain`: staged `SharedLibraryPolicyCheck.toml` resolves `shlib-policy-obsoletes-sibling` instead of "Unknown message".
#[test]
fn explain_staged_shlib_policy_obsoletes_sibling() {
    let out = rpmcrab(&["-e", "shlib-policy-obsoletes-sibling"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "shlib-policy-obsoletes-sibling:\nYour package name follows the Shared Library Policy naming scheme, but it\nobsoletes a package for another SONAME generation of the same library. The\nversioned package names exist so that several SONAME generations can be\ninstalled in parallel; obsoleting one generation breaks that. Remove the\nobsoletes so both generations can be installed together.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `SharedLibraryPolicyCheck.toml` resolves the port-only `shlib-policy-etc-payload` instead of "Unknown message".
#[test]
fn explain_staged_shlib_policy_etc_payload() {
    let out = rpmcrab(&["-e", "shlib-policy-etc-payload"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "shlib-policy-etc-payload:\nYour package name follows the Shared Library Policy naming scheme, but it\nships files under /etc or /usr/etc. Only the libraries themselves may be part\nof a versioned shared library package: a file shipped under the same\nunversioned path by the package for the next SONAME generation conflicts with\nthis one at file level, so the two generations cannot be installed in\nparallel. Move the files into a separate package.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `SharedLibraryPolicyCheck.toml` resolves the port-only `shlib-devel-unversioned-requires` instead of "Unknown message".
#[test]
fn explain_staged_shlib_devel_unversioned_requires() {
    let out = rpmcrab(&["-e", "shlib-devel-unversioned-requires"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout,
        "shlib-devel-unversioned-requires:\nYour library -devel package does not require the shared library package with a\nversion constraint. The Shared Library Policy asks for a properly versioned\nrequires on the shared library package, so that installing the -devel package\ncannot pull in a library generation it was not built against.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `SpecCheck.toml` resolves `no-spec-file` instead of "Unknown message".
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

/// `--explain`: staged `SysVInitOnSystemdCheck.toml` resolves `obsolete-insserv-requirement` instead of "Unknown message".
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

/// `--explain`: staged `SystemdInstallCheck.toml` resolves `systemd-service-without-service_add_pre` instead of "Unknown message".
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

/// `--explain`: staged `SystemdTmpfilesCheck.toml` resolves `systemd-tmpfile-ghost` instead of "Unknown message".
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

/// `--explain`: staged `TagsCheck.toml` resolves `summary-ended-with-dot` instead of "Unknown message".
#[test]
fn explain_staged_tags_check() {
    let out = rpmcrab(&["-e", "summary-ended-with-dot"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "summary-ended-with-dot:\nSummary ends with a dot.\n\n\n",
        "exact --explain stdout",
    );
    assert!(out.stderr.is_empty());
}

/// `--explain`: staged `TmpFilesCheck.toml` resolves `pre-with-tmpfile-creation` instead of "Unknown message".
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
        "update-alternatives-postun-call-missing:\nThe package does not call update-alternatives --remove in the %postun phase\nfor each --install that was done in %post.\n\n\n",
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
        "kmp-missing-supplements:\nMake sure you have extended '%kernel_module_package' by '-p\n%_sourcedir/preamble', a file named 'preamble' as source and there specified\n'Supplements: (kernel-%1 and %name)'.\n\n\n",
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
        "macro-in-comment:\nThere is an effectful macro expansion after a shell style comment in the\nspecfile. Shell (%(...)), Lua (%{lua:...}), macro file (%{load:...}) and macro\ndirectives (%define, %global, %undefine, %lua, %load and the braced\n%{define:...}, %{global:...}, %{undefine:...} and %{error:...} forms) are\nperformed by rpm while the specfile is parsed, even inside comments, so check\nif it can cause a problem in this case and escape the macro with another\nleading % if appropriate.\n\n\n",
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

/// Spawn the binary with autoloading enabled so the vendored distro layer
/// loads (the shipped flavour config), but with the XDG dirs pointed at an
/// empty temp dir: nothing ambient leaks in. `CONFIG_DISABLE_AUTOLOADING`
/// must NOT be set here — it would skip the vendored layer entirely.
fn rpmcrab_flavoured(args: &[&str]) -> std::process::Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    std::fs::create_dir_all(xdg.path().join("home")).expect("xdg home");
    std::fs::create_dir_all(xdg.path().join("dirs")).expect("xdg dirs");
    let mut cmd = rpmcrab_command();
    cmd.args(args)
        .env("XDG_CONFIG_HOME", xdg.path().join("home"))
        .env("XDG_CONFIG_DIRS", xdg.path().join("dirs"))
        // Mirror the plain harness's explicit ngram switch, so an
        // ambient value cannot leak into flavoured runs.
        .env("RPMCRAB_DISABLE_NGRAM_SUGGESTIONS", "1")
        .env_remove("CONFIG_DISABLE_AUTOLOADING")
        .env_remove("PYTEST_XDIST_TESTRUNUID");
    cmd.output().expect("spawn rpmcrab")
}

#[test]
fn no_manual_page_for_binary_surfaces_as_info_under_opensuse_flavour() {
    // rpmcrab#484: the finding is Info in code and the vendored openSUSE
    // flavour no longer filters it, so a manpage-less binary produces
    // exactly one I-level line. (Before: the flavour filtered it away
    // entirely, and the bare baseline reported it at W.)
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity/cases/w6-menu/input/w6-menu-1.0-1.noarch.rpm")
        .canonicalize()
        .expect("w6-menu fixture is committed");
    let out = rpmcrab_flavoured(&[fixture.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let hits: Vec<&str> = stdout
        .lines()
        .filter(|l| l.contains("no-manual-page-for-binary"))
        .collect();
    assert_eq!(hits.len(), 1, "one surfaced finding: {stdout}");
    assert!(
        hits[0].contains(": I: no-manual-page-for-binary w6menu"),
        "info level, detail is the exe name: {}",
        hits[0]
    );
}

/// Whether the system hunspell en_US pair the spellchecker loads is
/// installed. CI installs the pinned pair; where it is absent the
/// spelling check degrades to silence and there is no output to pin.
fn system_dictionary_installed() -> bool {
    [
        "/usr/share/hunspell",
        "/usr/share/myspell",
        "/opt/homebrew/share/hunspell",
    ]
    .iter()
    .any(|dir| {
        let dir = Path::new(dir);
        dir.join("en_US.aff").exists() && dir.join("en_US.dic").exists()
    })
}

/// Run the binary without the harness's ngram switch, for the runs
/// that pin the production default (ngram suggester on) end to end.
fn rpmcrab_default_env(args: &[&str]) -> std::process::Output {
    let mut cmd = rpmcrab_command();
    cmd.args(args)
        .env("CONFIG_DISABLE_AUTOLOADING", "1")
        .env_remove("RPMCRAB_DISABLE_NGRAM_SUGGESTIONS");
    cmd.output().expect("spawn rpmcrab")
}

#[test]
fn spelling_suggestions_are_reproducible_across_spawns() {
    if !system_dictionary_installed() {
        // No dictionary: the spelling check is silent, so there is
        // nothing to compare. CI installs the pinned pair.
        return;
    }
    // The committed fixture whose %description misspells "package" as
    // "packag" (the tags emission pins use it with an inline
    // dictionary). A bare .spec will not do: the binary spellchecks
    // binary packages, not spec files.
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity/pkg/inputs/tags-emission-pins-spell-1.0-1.noarch.rpm")
        .canonicalize()
        .expect("spelling fixture is committed");
    let fixture = fixture.to_str().unwrap();
    let spelling_lines = |out: &std::process::Output| -> Vec<String> {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| l.contains("spelling-error"))
            .map(str::to_string)
            .collect()
    };
    // The harness sets RPMCRAB_DISABLE_NGRAM_SUGGESTIONS, so two
    // spawns must print identical suggestion lines for the misspelled
    // fixture (issue #688: the ngram candidate set is not
    // reproducible across processes).
    let first = spelling_lines(&rpmcrab(&[fixture]));
    assert_eq!(first.len(), 1, "one spelling finding expected: {first:?}");
    assert!(
        first[0].contains("packag ->"),
        "the misspelling is flagged with suggestions: {}",
        first[0]
    );
    let second = spelling_lines(&rpmcrab(&[fixture]));
    assert_eq!(first, second, "suggestion lines differ across spawns");
    // With the variable removed the production default runs: the
    // misspelling is still flagged with suggestions. The ngram set
    // itself is not reproducible, so only its presence is pinned.
    let default = spelling_lines(&rpmcrab_default_env(&[fixture]));
    assert_eq!(
        default.len(),
        1,
        "the default run flags the misspelling: {default:?}"
    );
    assert!(default[0].contains("packag"), "{}", default[0]);
}
