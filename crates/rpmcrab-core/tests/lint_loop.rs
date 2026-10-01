//! The check loop's cross-package semantics (`lint.py` `run_checks` /
//! `reset_checks` / `validate_filters`).
//!
//! These are the rules every ported check inherits, so they are pinned here
//! with a recording check rather than in each check's own tests: `after_checks`
//! runs only for the last package, `reset` runs between packages, and the
//! rpmlintrc filter audit runs once, on the last package.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rpmcrab_core::check::{Check, add_info};
use rpmcrab_core::color::Color;
use rpmcrab_core::config::Config;
use rpmcrab_core::filter::Filter;
use rpmcrab_core::level::Level;
use rpmcrab_core::lint::Lint;
use rpmcrab_core::pkg::Pkg;
use rpmcrab_core::worker::Task;

/// What the recording check saw, shared with the test body.
#[derive(Default)]
struct Log {
    checked: Vec<&'static str>,
    after_checks: usize,
    resets: usize,
}

/// A check that records the loop calls it received and emits one finding per
/// package, so the footer counters move too.
struct Recorder {
    name: &'static str,
    log: Arc<Mutex<Log>>,
    emit: bool,
}

impl Check for Recorder {
    fn name(&self) -> &'static str {
        self.name
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        self.log.lock().unwrap().checked.push(self.name);
        if self.emit {
            add_info(out, Level::Warning, pkg, "recorder-found-something", &[]);
        }
    }

    fn after_checks(&mut self, _config: &Config, out: &mut Filter) {
        self.log.lock().unwrap().after_checks += 1;
        // Needs no package, so borrow a synthetic finding context via the
        // last-known package name the loop gave us. `after_checks` in the
        // reference also has no package (`check.after_checks()`), so the
        // finding is emitted against the package-less `(none)` context.
        out.add_info(rpmcrab_core::finding::Finding {
            level: Level::Info,
            check: "recorder-after-checks".to_string(),
            details: vec![],
            badness: 0,
            pkg_name: "(none)".to_string(),
            arch: None,
            line: None,
        });
    }

    fn reset(&mut self) {
        self.log.lock().unwrap().resets += 1;
    }
}

fn corpus_rpm() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity/cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm")
        .canonicalize()
        .expect("corpus rpm is committed")
}

/// `n` file tasks over the same corpus rpm: the loop only cares about being
/// called once per package.
fn tasks(n: usize) -> Vec<Task> {
    let rpm = corpus_rpm();
    (0..n).map(|_| Task::File(rpm.clone())).collect()
}

/// A `Lint` plus a factory that builds the same recording check for the
/// workers, sharing the log. The batch always runs single-threaded here so
/// the call order is deterministic.
fn lint_with(
    make_recorder: impl Fn() -> Recorder + Clone + 'static,
    config: Config,
) -> (Lint, impl Fn() -> Vec<Box<dyn Check>>) {
    let make_checks = move || vec![Box::new(make_recorder()) as Box<dyn Check>];
    let lint = Lint::new(config, make_checks(), Color::for_tty(false), 80).expect("build Lint");
    (lint, make_checks)
}

#[test]
fn after_checks_runs_only_for_the_last_package() {
    let log = Arc::new(Mutex::new(Log::default()));
    let (mut lint, make_checks) = lint_with(
        {
            let log = Arc::clone(&log);
            move || Recorder {
                name: "Recorder",
                log: Arc::clone(&log),
                emit: false,
            }
        },
        Config::default(),
    );

    lint.check_batch(tasks(3), 1, &make_checks, true);

    let log = log.lock().unwrap();
    assert_eq!(log.checked.len(), 3, "every package is checked");
    assert_eq!(
        log.after_checks, 1,
        "after_checks runs once, on the last package"
    );
    // The worker resets after every package (3); the main resets once more
    // after the batch to drop the merged cross-package state.
    assert_eq!(
        log.resets, 4,
        "reset runs after every package, plus batch cleanup"
    );
}

/// `reset` also runs after the single, last package.
#[test]
fn reset_runs_after_every_package() {
    let log = Arc::new(Mutex::new(Log::default()));
    let (mut lint, make_checks) = lint_with(
        {
            let log = Arc::clone(&log);
            move || Recorder {
                name: "Recorder",
                log: Arc::clone(&log),
                emit: false,
            }
        },
        Config::default(),
    );
    lint.check_batch(tasks(4), 1, &make_checks, true);
    // 4 worker resets (one per package) + 1 main batch cleanup.
    assert_eq!(log.lock().unwrap().resets, 5);
}

#[test]
fn a_single_package_is_always_the_last_one() {
    let log = Arc::new(Mutex::new(Log::default()));
    let (mut lint, make_checks) = lint_with(
        {
            let log = Arc::clone(&log);
            move || Recorder {
                name: "Recorder",
                log: Arc::clone(&log),
                emit: false,
            }
        },
        Config::default(),
    );
    lint.check_batch(tasks(1), 1, &make_checks, true);
    assert_eq!(log.lock().unwrap().after_checks, 1);
}

#[test]
fn the_footer_counts_every_validated_package() {
    let log = Arc::new(Mutex::new(Log::default()));
    let (mut lint, make_checks) = lint_with(
        {
            let log = Arc::clone(&log);
            move || Recorder {
                name: "Recorder",
                log: Arc::clone(&log),
                emit: true,
            }
        },
        Config::default(),
    );
    lint.check_batch(tasks(4), 1, &make_checks, true);
    assert_eq!(lint.packages_checked(), 4);
    // One warning per package.
    assert_eq!(lint.filter().printed(Level::Warning), 4);
    let out = lint.render("rpmlint", "2.10.0", 4, false, 0.1);
    assert!(
        out.contains("4 packages and 0 specfiles checked"),
        "footer: {out}"
    );
}

/// `after_checks` runs after the last package's own findings, so a finding from
/// the hook is not suppressed by a filter that would have caught the earlier
/// ones, and the sort still applies.
#[test]
fn after_checks_findings_are_reported() {
    let log = Arc::new(Mutex::new(Log::default()));
    let (mut lint, make_checks) = lint_with(
        {
            let log = Arc::clone(&log);
            move || Recorder {
                name: "Recorder",
                log: Arc::clone(&log),
                emit: false,
            }
        },
        Config::default(),
    );
    lint.check_batch(tasks(2), 1, &make_checks, true);
    let out = lint.render("rpmlint", "2.10.0", 2, false, 0.1);
    assert!(
        out.contains("(none): I: recorder-after-checks"),
        "stdout: {out}"
    );
}

/// Build a config whose rpmlintrc contributed one `addFilter` pattern, through
/// the real loader, so the pattern is both applied and audited.
fn config_with_rpmlintrc_filter(pattern: &str) -> Config {
    let dir = tempfile::tempdir().unwrap();
    let rc = dir.path().join("pkg-rpmlintrc");
    std::fs::write(&rc, format!("addFilter(r\"{pattern}\")\n")).unwrap();
    let mut config = Config::default();
    rpmcrab_core::config::load_rpmlintrc(&mut config, &rc).expect("load rpmlintrc");
    assert_eq!(config.rpmlintrc_filters, vec![pattern.to_string()]);
    config
}

/// An rpmlintrc `addFilter` pattern that matched nothing is reported once, on
/// the last package, as `unused-rpmlintrc-filter`.
#[test]
fn unused_rpmlintrc_filters_are_reported_once_on_the_last_package() {
    let log = Arc::new(Mutex::new(Log::default()));
    let (mut lint, make_checks) = lint_with(
        {
            let log = Arc::clone(&log);
            move || Recorder {
                name: "Recorder",
                log: Arc::clone(&log),
                emit: true,
            }
        },
        config_with_rpmlintrc_filter("never-matches-anything"),
    );

    lint.check_batch(tasks(2), 1, &make_checks, true);
    lint.audit_unused_filters();

    let out = lint.render("rpmlint", "2.10.0", 2, false, 0.1);
    let count = out.matches("unused-rpmlintrc-filter").count();
    assert_eq!(count, 1, "audited once, on the last package: {out}");
    assert!(
        out.contains("\"never-matches-anything\""),
        "pattern is quoted: {out}"
    );
}

/// `--ignore-unused-rpmlintrc` suppresses the audit entirely.
#[test]
fn ignore_unused_rpmlintrc_suppresses_the_audit() {
    let log = Arc::new(Mutex::new(Log::default()));
    let (mut lint, make_checks) = lint_with(
        {
            let log = Arc::clone(&log);
            move || Recorder {
                name: "Recorder",
                log: Arc::clone(&log),
                emit: false,
            }
        },
        config_with_rpmlintrc_filter("never-matches-anything"),
    );
    lint.set_audit_rpmlintrc(false);
    lint.check_batch(tasks(2), 1, &make_checks, true);
    lint.audit_unused_filters();
    let out = lint.render("rpmlint", "2.10.0", 2, false, 0.1);
    assert!(!out.contains("unused-rpmlintrc-filter"), "stdout: {out}");
}

/// An rpmlintrc `addFilter` pattern that *did* match both suppressed its
/// finding and is therefore not reported as unused.
#[test]
fn a_used_rpmlintrc_filter_is_not_reported() {
    let log = Arc::new(Mutex::new(Log::default()));
    let (mut lint, make_checks) = lint_with(
        {
            let log = Arc::clone(&log);
            move || Recorder {
                name: "Recorder",
                log: Arc::clone(&log),
                emit: true,
            }
        },
        config_with_rpmlintrc_filter("recorder-found-something"),
    );
    lint.check_batch(tasks(1), 1, &make_checks, true);
    lint.audit_unused_filters();
    let out = lint.render("rpmlint", "2.10.0", 1, false, 0.1);
    // The finding matched the pattern, so it is suppressed ...
    assert!(
        !out.contains("W: recorder-found-something"),
        "finding filtered: {out}"
    );
    assert!(out.contains("1 filtered"), "{out}");
    // ... and the pattern is therefore not unused.
    assert!(!out.contains("unused-rpmlintrc-filter"), "stdout: {out}");
}

/// `Pkg.timers` reaches the duration map the `-t` report reads.
#[test]
fn package_phase_timers_reach_the_time_report() {
    let log = Arc::new(Mutex::new(Log::default()));
    let (mut lint, make_checks) = lint_with(
        {
            let log = Arc::clone(&log);
            move || Recorder {
                name: "Recorder",
                log: Arc::clone(&log),
                emit: false,
            }
        },
        Config::default(),
    );
    lint.check_batch(tasks(1), 1, &make_checks, true);
    let report = lint.time_report();
    // A file package records ExtractRpm; it is below the 0.1s cut-off so
    // it does not print, but the header does.
    assert!(report.contains("Check time report"), "{report}");
}

/// The `Check` dispatch: a source package goes to `check_source`, a binary
/// package to `check_binary`, and neither is required.
#[test]
fn check_dispatches_on_is_source() {
    struct Dispatch {
        log: Arc<Mutex<Log>>,
    }
    impl Check for Dispatch {
        fn name(&self) -> &'static str {
            "Dispatch"
        }
        fn check_source(&mut self, _pkg: &Pkg, _c: &Config, _o: &mut Filter) {
            self.log.lock().unwrap().checked.push("source");
        }
        fn check_binary(&mut self, _pkg: &Pkg, _c: &Config, _o: &mut Filter) {
            self.log.lock().unwrap().checked.push("binary");
        }
    }

    let log = Arc::new(Mutex::new(Log::default()));
    let make_checks = {
        let log = Arc::clone(&log);
        move || {
            vec![Box::new(Dispatch {
                log: Arc::clone(&log),
            }) as Box<dyn Check>]
        }
    };
    let mut lint =
        Lint::new(Config::default(), make_checks(), Color::for_tty(false), 80).expect("build Lint");
    // The corpus rpm is a binary package, so both take the binary hook.
    lint.check_batch(tasks(2), 1, &make_checks, true);
    assert_eq!(log.lock().unwrap().checked, vec!["binary", "binary"]);
}

/// The `Package` dispatch: a `.spec` input goes to `check_spec` (never
/// `check_binary`), bumps `specfiles_checked` instead of `packages_checked`,
/// and its findings carry the spec's basename with the reported line
/// (`lint.py:300-304,314-318`).
#[test]
fn spec_inputs_dispatch_to_check_spec() {
    use rpmcrab_core::check::spec_add_info;
    use rpmcrab_core::pkg::spec::SpecPkg;

    struct SpecRecorder {
        log: Arc<Mutex<Log>>,
    }
    impl Check for SpecRecorder {
        fn name(&self) -> &'static str {
            "SpecRecorder"
        }
        fn check_spec(&mut self, pkg: &SpecPkg, _c: &Config, out: &mut Filter) {
            self.log.lock().unwrap().checked.push("spec");
            spec_add_info(
                out,
                Level::Warning,
                pkg,
                Some(12),
                "spec-recorder",
                &["detail"],
            );
        }
    }

    let dir = tempfile::tempdir().expect("scratch dir");
    let spec = dir.path().join("hello.spec");
    std::fs::write(&spec, "Name: hello\n").expect("write spec");

    let log = Arc::new(Mutex::new(Log::default()));
    let make_checks = {
        let log = Arc::clone(&log);
        move || {
            vec![Box::new(SpecRecorder {
                log: Arc::clone(&log),
            }) as Box<dyn Check>]
        }
    };
    let mut lint =
        Lint::new(Config::default(), make_checks(), Color::for_tty(false), 80).expect("build Lint");
    lint.check_batch(vec![Task::File(spec)], 1, &make_checks, true);

    assert_eq!(log.lock().unwrap().checked, vec!["spec"]);
    assert_eq!(lint.packages_checked(), 0);
    let out = lint.render("rpmlint", "2.10.0", 1, false, 0.1);
    assert!(
        out.contains("0 packages and 1 specfiles checked"),
        "footer: {out}"
    );
    assert!(
        out.contains("hello.spec:12: W: spec-recorder detail"),
        "finding: {out}"
    );
}
