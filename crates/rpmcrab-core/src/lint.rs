//! The `Lint` orchestrator: run checks over the inputs, render the report, and
//! compute the exit code.
//!
//! Exit-code *computation* is domain logic (it is the frozen contract in
//! `docs/DESIGN.md` §4.6); the binary crate maps the returned value to a
//! process exit. This crate never calls `std::process::exit`.
//!
//! Packages are checked in batches (`_check_packages`, `rpmlint#1595`):
//! worker threads check one package each and the main thread replays the
//! results in task order. `after_checks` runs once per batch; the
//! unused-rpmlintrc-filter audit runs once after all batches.

use std::collections::BTreeMap;

use crate::check::{Check, basename};
use crate::color::Color;
use crate::config::Config;
use crate::filter::Filter;
use crate::finding::Finding;
use crate::level::Level;
use crate::report;
use crate::worker::{self, TaskResult};

/// Per-check accumulated wall time, keyed by the check's registry name. Holds
/// the `Pkg` phases (`ExtractRpm`, `libmagic`) too, as in the reference's
/// single `check_duration` map.
///
/// Insertion-ordered rather than a `BTreeMap`: the reference reports equal
/// durations in the order the phases and checks first ran, and a sorted map
/// would alphabetise them instead. There are at most one entry per check plus
/// two phases, so the linear lookup costs nothing.
#[derive(Debug, Clone, Default)]
pub struct Durations(Vec<(String, f64)>);

impl Durations {
    /// Add `secs` to `key`, keeping the position `key` first occupied.
    pub fn add(&mut self, key: &str, secs: f64) {
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some((_, v)) => *v += secs,
            None => self.0.push((key.to_string(), secs)),
        }
    }

    /// The accumulated `(name, seconds)` pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, f64)> + '_ {
        self.0.iter().map(|(k, v)| (k.as_str(), *v))
    }

    /// The seconds across every entry.
    pub fn total(&self) -> f64 {
        self.0.iter().map(|(_, v)| *v).sum()
    }

    /// The `(name, seconds)` pairs, for the report functions.
    pub fn as_slice(&self) -> &[(String, f64)] {
        &self.0
    }
}

/// Drives a set of checks over the inputs and renders the report.
pub struct Lint {
    config: Config,
    filter: Filter,
    checks: Vec<Box<dyn Check>>,
    color: Color,
    width: usize,
    check_duration: Durations,
    packages_checked: usize,
    /// How many `.spec` inputs have been validated. The footer's `specfiles`
    /// column is part of the frozen output (`lint.py:114`).
    specfiles_checked: usize,
    /// `Filter.validate_filters` is skipped with `--ignore-unused-rpmlintrc`.
    audit_rpmlintrc: bool,
    /// Set when any package hit a fatal error; the run continues but still
    /// fails with exit code 3 at the end (`rpmlint#1595`).
    had_fatal_error: bool,
    /// Formatted `(none): E: fatal error ...` lines, in replay order, for the
    /// caller to print to stderr.
    fatals: Vec<String>,
    /// The last processed package's audit context (`_last_pkg`): name, arch,
    /// whether it is a spec.
    last_pkg: Option<(String, Option<String>, bool)>,
}

impl Lint {
    /// Build a `Lint`. rpmlint constructs the config (including any rpmlintrc)
    /// **before** the `Filter` (`Lint.__init__` calls `_load_rpmlintrc()` then
    /// `Filter(self.config)`), so `config` must already have rpmlintrc applied.
    ///
    /// # Errors
    /// Returns the `fancy-regex` error if any `Filters` pattern does not
    /// compile — rpmlint uses a bare `re.compile(f)`, which raises on a bad
    /// pattern at Filter construction.
    pub fn new(
        config: Config,
        checks: Vec<Box<dyn Check>>,
        color: Color,
        width: usize,
    ) -> Result<Self, fancy_regex::Error> {
        let filter = Filter::new(&config, color)?;
        let audit_rpmlintrc = true;
        Ok(Self {
            config,
            filter,
            checks,
            color,
            width,
            check_duration: Durations::default(),
            packages_checked: 0,
            specfiles_checked: 0,
            audit_rpmlintrc,
            had_fatal_error: false,
            fatals: Vec::new(),
            last_pkg: None,
        })
    }

    /// `Lint.__init__` honours `--ignore-unused-rpmlintrc` by not auditing the
    /// rpmlintrc filters at the end of the run.
    pub fn set_audit_rpmlintrc(&mut self, audit: bool) {
        self.audit_rpmlintrc = audit;
    }

    /// Check a batch of tasks (`_check_packages`, `rpmlint#1595`):
    /// optionally on `jobs` worker threads, replaying each result through the
    /// run's filter in task order, then `after_checks` when asked.
    ///
    /// `make_checks` builds each worker's check set; the main thread keeps its
    /// own instances for `after_checks`. A fatal per-package error is
    /// recorded and the run continues; [`Lint::take_fatals`] drains the
    /// diagnostics for stderr.
    pub fn check_batch(
        &mut self,
        tasks: Vec<worker::Task>,
        jobs: usize,
        make_checks: &dyn Fn() -> Vec<Box<dyn Check>>,
        run_after_checks: bool,
    ) {
        if tasks.is_empty() {
            return;
        }
        for result in worker::run_tasks(tasks, jobs, &self.config, make_checks, self.color) {
            self.replay(result);
        }
        if run_after_checks {
            for check in &mut self.checks {
                check.after_checks(&self.config, &mut self.filter);
            }
        }
        // Drop the merged cross-package state so batches stay independent.
        for check in &mut self.checks {
            check.reset();
        }
    }

    /// Feed one worker result through the run's filter, in task order
    /// (`_replay_result`).
    fn replay(&mut self, result: TaskResult) {
        let is_fatal = result.fatal.is_some();
        if let Some(fatal) = result.fatal {
            // The message already reads `fatal error while reading <pkg>: ...`.
            self.fatals.push(format!("(none): E: {fatal}"));
            self.had_fatal_error = true;
        }
        self.filter.merge_from(result.filter);
        for (name, state) in result.states {
            if let Some(check) = self.checks.iter_mut().find(|c| c.name() == name) {
                check.import_state(state);
            }
        }
        for (name, secs) in result.durations.iter() {
            self.check_duration.add(name, secs);
        }
        for (name, n) in result.checked_files {
            if let Some(check) = self.checks.iter_mut().find(|c| c.name() == name) {
                check.add_checked_files(n);
            }
        }
        // A fatal package was not checked, so it does not move the footer
        // counters (`rpmlint#1595`).
        if !is_fatal {
            if result.is_spec {
                self.specfiles_checked += 1;
            } else {
                self.packages_checked += 1;
            }
        }
        self.last_pkg = Some((result.pkg_name, result.pkg_arch, result.is_spec));
    }

    /// Drain the fatal-error diagnostics collected since the last call, in
    /// replay order, for the caller to print to stderr.
    pub fn take_fatals(&mut self) -> Vec<String> {
        std::mem::take(&mut self.fatals)
    }

    /// `Filter.validate_filters`: every rpmlintrc `Filters` pattern that
    /// never matched becomes an `unused-rpmlintrc-filter` error. Runs once
    /// after all batches, on the last processed package (`_run`).
    pub fn audit_unused_filters(&mut self) {
        if !self.audit_rpmlintrc {
            return;
        }
        let Some((pkg_name, arch, is_spec)) = self.last_pkg.clone() else {
            return;
        };
        let unused: Vec<String> = self
            .filter
            .unused_filters(&self.config.rpmlintrc_filters)
            .into_iter()
            .map(str::to_string)
            .collect();
        for pattern in unused {
            let detail = format!("\"{pattern}\"");
            self.filter.add_info(Finding {
                level: Level::Error,
                check: "unused-rpmlintrc-filter".to_string(),
                details: vec![detail],
                // Scoring decides the real badness at emit time.
                badness: 0,
                // `Path(package.name).name`, as for binary findings; specs
                // carry no arch, like the reference's `FakePkg`.
                pkg_name: basename(&pkg_name).to_string(),
                arch: if is_spec {
                    None
                } else {
                    arch.clone().filter(|a| !a.is_empty())
                },
                line: None,
            });
        }
    }

    /// The abort condition: badness score over a positive threshold.
    fn aborted(&self) -> bool {
        self.config.badness_threshold > 0 && self.filter.score > self.config.badness_threshold
    }

    /// The process exit code (`docs/DESIGN.md` §4.6). Badness-over-threshold
    /// (66) is evaluated before the permissive error branch (64/65); a fatal
    /// per-package error fails the run with 3, but only after everything else
    /// has been processed and reported (`rpmlint#1595`).
    pub fn exit_code(&self) -> i32 {
        let code = if self.aborted() {
            66
        } else if self.filter.printed(Level::Error) > 0 && !self.config.permissive {
            if self.filter.printed(Level::Error) == self.filter.promoted_to_error {
                65
            } else {
                64
            }
        } else {
            0
        };
        if self.had_fatal_error { 3 } else { code }
    }

    /// The `-t` time report: per-check accumulated seconds and how many files
    /// each check walked.
    pub fn time_report(&self) -> String {
        let files: BTreeMap<String, usize> = self
            .checks
            .iter()
            .filter_map(|c| c.checked_files().map(|n| (c.name().to_string(), n)))
            .filter(|(_, n)| *n > 0)
            .collect();
        report::time_report(self.check_duration.as_slice(), &files, &self.color)
    }

    /// The report: header, sorted findings, abort banner (if over threshold),
    /// and — when requested — the time report, then the footer.
    ///
    /// The order is the reference's: results, banner, reports, footer
    /// (`lint.py:94-118`). The header and footer count different things:
    /// `header_packages` is the CLI *argument* count (`len(installed) +
    /// len(rpmfile)`, `lint.py:242`), while the footer counts the packages
    /// actually validated.
    pub fn render(
        &self,
        prog: &str,
        version: &str,
        header_packages: usize,
        time_report: bool,
        duration_secs: f64,
    ) -> String {
        let mut out = String::new();
        out.push_str(&report::header(&report::HeaderParams {
            prog,
            version,
            conf_files: &self.config.conf_files,
            rpmlintrc: &self.config.rpmlintrc_display,
            no_checks: self.config.checks.len(),
            no_packages: header_packages,
            color: &self.color,
            width: self.width,
        }));
        out.push_str(&self.filter.render_results(&self.config));
        if self.aborted() {
            out.push_str(&report::abort_banner(
                self.filter.score,
                self.config.badness_threshold,
                &self.color,
                self.width,
            ));
        }
        if time_report {
            out.push_str(&self.time_report());
        }
        out.push_str(&report::footer(&report::FooterParams {
            packages: self.packages_checked,
            specfiles: self.specfiles_checked,
            errors: self.filter.printed(Level::Error),
            warnings: self.filter.printed(Level::Warning),
            filtered: self.filter.filtered_out,
            score: self.filter.score,
            duration_secs,
            aborted: self.aborted(),
            color: &self.color,
            width: self.width,
        }));
        out
    }

    /// The `--format json` report (upstream rpmlint#1156): the same
    /// findings as [`Lint::render`], as a machine-readable JSON document.
    /// New surface — the text format is untouched.
    ///
    /// Findings are sorted by `(check, level)` descending, mirroring the
    /// text report's order; the summary carries the footer's counters and
    /// the process exit code.
    ///
    /// `duration_secs` is wall-clock time and varies between runs; golden
    /// tests should ignore or redact it. Fatal per-package diagnostics are
    /// printed to stderr (exit code 3) and never appear in the document.
    pub fn render_json(
        &self,
        prog: &str,
        version: &str,
        header_packages: usize,
        duration_secs: f64,
    ) -> String {
        let mut findings: Vec<&Finding> = self.filter.findings().iter().collect();
        findings.sort_by_key(|f| std::cmp::Reverse((f.check.clone(), f.level.letter())));
        let doc = serde_json::json!({
            "program": prog,
            "version": version,
            "packages": header_packages,
            "checks": self.config.checks.len(),
            "duration_secs": duration_secs,
            "findings": findings.iter().map(|f| f.json_value()).collect::<Vec<_>>(),
            "summary": {
                "errors": self.filter.printed(Level::Error),
                "warnings": self.filter.printed(Level::Warning),
                "filtered": self.filter.filtered_out,
                "score": self.filter.score,
                "aborted": self.aborted(),
                "exit_code": self.exit_code(),
            },
        });
        let mut out = serde_json::to_string_pretty(&doc).expect("findings are JSON-serializable");
        out.push('\n');
        out
    }

    /// Access the filter (tests inspect counters).
    pub fn filter(&self) -> &Filter {
        &self.filter
    }

    /// The merged configuration, for the caller's input handling (the
    /// extraction directory comes from here).
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// How many packages have been validated. `Lint.validate_files` warns about
    /// having nothing to do only when this is still zero.
    pub fn packages_checked(&self) -> usize {
        self.packages_checked
    }
}

#[cfg(test)]
mod panic_tests {
    use super::*;
    use crate::pkg::spec::SpecPkg;

    struct Panics;
    impl Check for Panics {
        fn name(&self) -> &'static str {
            "Panics"
        }
        fn check(&mut self, _pkg: &crate::pkg::Pkg, _config: &Config, _out: &mut Filter) {
            panic!("boom");
        }
        fn check_spec(&mut self, _pkg: &SpecPkg, _config: &Config, _out: &mut Filter) {
            panic!("boom");
        }
    }

    /// A panicking check becomes a fatal result, not a dead worker: the run
    /// continues and fails with exit code 3 at the end.
    #[test]
    fn a_panicking_check_is_a_fatal_result_not_a_dead_worker() {
        let dir = tempfile::tempdir().unwrap();
        let spec = dir.path().join("test.spec");
        std::fs::write(&spec, b"Name: test\n").unwrap();
        let config = Config::default();
        let mut lint =
            Lint::new(config, vec![Box::new(Panics)], Color::for_tty(false), 80).unwrap();
        lint.check_batch(
            vec![worker::Task::File(spec)],
            1,
            &|| vec![Box::new(Panics) as Box<dyn Check>],
            true,
        );
        let fatals = lint.take_fatals();
        assert_eq!(fatals.len(), 1, "{fatals:?}");
        assert!(
            fatals[0].contains("fatal error while reading"),
            "{}",
            fatals[0]
        );
        assert_eq!(lint.exit_code(), 3);
    }
}

#[cfg(test)]
mod exit_code_tests {
    use super::*;
    use crate::finding::Finding;
    use crate::level::Level;

    /// Two warnings + BadnessThreshold=1 + --strict → exit 66.
    ///
    /// The reference (filter.py:139-140) computes default badness AFTER strict
    /// promotion, so each strict-promoted warning scores 1. With threshold 1,
    /// score 2 > 1 triggers the badness abort (exit 66), not the permissive
    /// error path (64/65). This pins the score > threshold → 66 interaction
    /// that unit tests on Filter.score alone do not cover.
    #[test]
    fn strict_warnings_cross_badness_threshold() {
        let config = Config {
            strict: true,
            badness_threshold: 1,
            ..Default::default()
        };
        let mut lint = Lint::new(config, vec![], Color::for_tty(false), 80).unwrap();
        for check in ["first-warning", "second-warning"] {
            lint.filter.add_info(Finding {
                level: Level::Warning,
                check: check.to_string(),
                details: vec![],
                badness: 0,
                pkg_name: "testpkg".to_string(),
                arch: None,
                line: None,
            });
        }
        assert_eq!(lint.filter.score, 2);
        assert_eq!(lint.exit_code(), 66);
    }

    #[test]
    fn render_json_sorts_findings_like_text_and_reports_summary() {
        let config = Config::default();
        let mut lint = Lint::new(config, vec![], Color::for_tty(false), 80).unwrap();
        for (check, level) in [
            ("aaa", Level::Warning),
            ("zzz", Level::Error),
            ("mmm", Level::Warning),
        ] {
            lint.filter.add_info(Finding {
                level,
                check: check.to_string(),
                details: vec!["d".to_string()],
                badness: 0,
                pkg_name: "testpkg".to_string(),
                arch: None,
                line: None,
            });
        }
        let doc: serde_json::Value =
            serde_json::from_str(&lint.render_json("rpmcrab", "2.10.0", 1, 0.5)).expect("JSON");
        let checks: Vec<&str> = doc["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .map(|f| f["check"].as_str().expect("check"))
            .collect();
        // (check, level) descending, mirroring the text report's order.
        assert_eq!(checks, vec!["zzz", "mmm", "aaa"]);
        assert_eq!(doc["program"], "rpmcrab");
        assert_eq!(doc["packages"], 1);
        assert_eq!(doc["summary"]["errors"], 1);
        assert_eq!(doc["summary"]["warnings"], 2);
        assert_eq!(doc["summary"]["exit_code"], lint.exit_code());
    }
}
