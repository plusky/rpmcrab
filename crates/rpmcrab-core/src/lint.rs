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
//! unused-rpmlintrc-filter audit and the rpmlintrc `setBadness` report
//! run once after all batches.

use std::collections::BTreeMap;

use crate::check::{Check, basename};
use crate::color::Color;
use crate::config::Config;
use crate::filter::{Filter, FilterError};
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
    pub(crate) color: Color,
    pub(crate) width: usize,
    check_duration: Durations,
    packages_checked: usize,
    /// How many `.spec` inputs have been validated. The footer's `specfiles`
    /// column is part of the frozen output (`lint.py:114`).
    pub(crate) specfiles_checked: usize,
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
    /// Returns a [`FilterError`] if any `Filters` pattern does not compile
    /// or a `[Scoring]` value is invalid — rpmlint uses a bare
    /// `re.compile(f)`, which raises on a bad pattern at Filter construction.
    pub fn new(
        config: Config,
        checks: Vec<Box<dyn Check>>,
        color: Color,
        width: usize,
    ) -> Result<Self, FilterError> {
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
    /// never matched becomes an `unused-rpmlintrc-filter` warning. Runs once
    /// after all batches, on the last processed package (`_run`). The
    /// reference reports the audit at E with the default badness 1 (it is in
    /// no scoring table) and exits 0 on it in every non-strict run, so the
    /// warning is the level that carries that build behaviour in the
    /// severity-only exit model (#816; ledgered in
    /// `tests/parity/divergences.toml`).
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
                level: Level::Warning,
                check: "unused-rpmlintrc-filter".to_string(),
                details: vec![detail],
                // `Path(package.name).name`, as for binary findings; specs
                // carry no arch, like the reference's `FakePkg`.
                pkg_name: basename(&pkg_name).to_string(),
                arch: if is_spec {
                    None
                } else {
                    arch.clone().filter(|a| !a.is_empty())
                },
                line: None,
                filter_alias: None,
                class: None,
            });
        }
    }

    /// Every `setBadness` occurrence recorded while loading the
    /// rpmlintrc files (`Config::rpmlintrc_setbadness`) becomes an
    /// `rpmlintrc-uses-setbadness` warning, once per occurrence, on the
    /// last processed package. This report is not the unused-filter
    /// audit: it runs even under `--ignore-unused-rpmlintrc`, which
    /// suppresses only that audit.
    pub fn report_rpmlintrc_setbadness(&mut self) {
        let Some((pkg_name, arch, is_spec)) = self.last_pkg.clone() else {
            return;
        };
        let occurrences = self.config.rpmlintrc_setbadness.clone();
        for occurrence in occurrences {
            self.filter.add_info(Finding {
                level: Level::Warning,
                check: "rpmlintrc-uses-setbadness".to_string(),
                details: vec![occurrence],
                // `Path(package.name).name`, as for binary findings; specs
                // carry no arch, like the reference's `FakePkg`.
                pkg_name: basename(&pkg_name).to_string(),
                arch: if is_spec {
                    None
                } else {
                    arch.clone().filter(|a| !a.is_empty())
                },
                line: None,
                filter_alias: None,
                class: None,
            });
        }
    }

    /// `[SeverityOverrides]` names that never matched an emitted finding.
    /// No static registry of finding tags exists (checks emit tags ad hoc,
    /// and the staged descriptions corpus lacks runtime-registered ones), so
    /// a name that matches nothing is the only honest typo signal. Warned
    /// on stderr by the caller, not as a finding, so a typo cannot perturb
    /// the exit code.
    pub fn unused_severity_overrides(&self) -> Vec<String> {
        self.config
            .severity_overrides
            .keys()
            .filter(|k| !self.filter.used_overrides().contains(*k))
            .cloned()
            .collect()
    }

    /// The process exit code (`docs/DESIGN.md` §4.6): any printed error
    /// fails the run with 64, unless `--permissive` was passed explicitly.
    /// A fatal per-package error fails the run with 3, dominating the
    /// error branch, but only after everything else has been processed
    /// and reported (`rpmlint#1595`).
    pub fn exit_code(&self) -> i32 {
        let code = if self.filter.printed(Level::Error) > 0 && !self.config.permissive {
            64
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

    /// Render the finished run in the requested `--format` (upstream
    /// rpmlint#109): `text` (default, byte-frozen) or `json`. JSON is the
    /// only machine format; unknown formats fall back to text, like the
    /// config loader.
    pub fn render_report(
        &self,
        format: &str,
        prog: &str,
        version: &str,
        header_packages: usize,
        time_report: bool,
        duration_secs: f64,
    ) -> String {
        use crate::render::Renderer;
        use crate::render::{RenderContext, TextRenderer, renderer_for};
        let ctx = RenderContext {
            lint: self,
            prog,
            version,
            header_packages,
            time_report,
            duration_secs,
        };
        match renderer_for(format) {
            Some(r) => r.render(&ctx),
            None => TextRenderer.render(&ctx),
        }
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

    /// Two warnings under --strict print as errors and exit 64 — the
    /// same code as genuine errors (issue #699: the 64/65 split and the
    /// badness-threshold exit are gone).
    #[test]
    fn strict_warnings_exit_64() {
        let config = Config {
            strict: true,
            ..Default::default()
        };
        let mut lint = Lint::new(config, vec![], Color::for_tty(false), 80).unwrap();
        for check in ["first-warning", "second-warning"] {
            lint.filter.add_info(Finding {
                level: Level::Warning,
                check: check.to_string(),
                details: vec![],
                pkg_name: "testpkg".to_string(),
                arch: None,
                line: None,
                filter_alias: None,
                class: None,
            });
        }
        assert_eq!(lint.filter.printed(Level::Error), 2);
        assert_eq!(lint.exit_code(), 64);
    }

    /// An error fails the run in the default mode: no flags, no config —
    /// a single printed E is exit 64 (issue #699).
    #[test]
    fn error_exits_64_by_default() {
        let config = Config::default();
        let mut lint = Lint::new(config, vec![], Color::for_tty(false), 80).unwrap();
        add(&mut lint, "genuine-error", Level::Error);
        assert_eq!(lint.exit_code(), 64);
    }

    /// Explicit `--permissive` is the only way errors print without
    /// failing the run.
    #[test]
    fn permissive_errors_exit_zero() {
        let config = Config {
            permissive: true,
            ..Default::default()
        };
        let mut lint = Lint::new(config, vec![], Color::for_tty(false), 80).unwrap();
        add(&mut lint, "genuine-error", Level::Error);
        assert_eq!(lint.filter.printed(Level::Error), 1);
        assert_eq!(lint.exit_code(), 0);
    }

    /// Two strict-promoted warnings with one overridden back: the
    /// remaining printed error fails the run with 64.
    #[test]
    fn strict_promotion_with_override_back_exits_64() {
        let config = Config {
            strict: true,
            permissive: false,
            severity_overrides: [("second-warning".to_string(), Level::Warning)]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let mut lint = Lint::new(config, vec![], Color::for_tty(false), 80).unwrap();
        for check in ["first-warning", "second-warning"] {
            lint.filter.add_info(Finding {
                level: Level::Warning,
                check: check.to_string(),
                details: vec![],
                pkg_name: "testpkg".to_string(),
                arch: None,
                line: None,
                filter_alias: None,
                class: None,
            });
        }
        assert_eq!(lint.filter.printed(Level::Error), 1);
        assert_eq!(lint.filter.printed(Level::Warning), 1);
        assert_eq!(lint.exit_code(), 64);
        // The typo audit sees the used name and stays silent.
        assert!(lint.unused_severity_overrides().is_empty());
    }

    /// The W+Scoring(50) interaction (DESIGN §4.9): a warning promoted by
    /// scoring and overridden back prints as W, so the run has no errors
    /// and exits 0 — the override is the final word on the level.
    #[test]
    fn scoring_override_back_to_warning_exits_zero() {
        let config = Config {
            scoring: [("some-check".to_string(), toml::Value::Integer(50))]
                .into_iter()
                .collect(),
            severity_overrides: [("some-check".to_string(), Level::Warning)]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let mut lint = Lint::new(config, vec![], Color::for_tty(false), 80).unwrap();
        lint.filter.add_info(Finding {
            level: Level::Warning,
            check: "some-check".to_string(),
            details: vec![],
            pkg_name: "testpkg".to_string(),
            arch: None,
            line: None,
            filter_alias: None,
            class: None,
        });
        assert_eq!(lint.filter.printed(Level::Warning), 1);
        assert_eq!(lint.filter.printed(Level::Error), 0);
        assert_eq!(lint.exit_code(), 0);
    }

    fn add(lint: &mut Lint, check: &str, level: Level) {
        lint.filter.add_info(Finding {
            level,
            check: check.to_string(),
            details: vec![],
            pkg_name: "testpkg".to_string(),
            arch: None,
            line: None,
            filter_alias: None,
            class: None,
        });
    }

    /// Info findings alone never fail a run: no printed errors means the
    /// error branch is never reached. This pins the post-recalibration
    /// shape — the tags the buckets pass demoted to I (e.g.
    /// `no-%check-section`, #593) cannot fail a build outside `--strict`.
    #[test]
    fn info_findings_alone_exit_zero() {
        let config = Config {
            permissive: false,
            ..Default::default()
        };
        let mut lint = Lint::new(config, vec![], Color::for_tty(false), 80).unwrap();
        add(&mut lint, "no-%check-section", Level::Info);
        assert_eq!(lint.filter.printed(Level::Info), 1);
        assert_eq!(lint.filter.printed(Level::Error), 0);
        assert_eq!(lint.exit_code(), 0);
    }

    /// --strict promotion applies to Info findings too (filter.py:134-140).
    /// A run whose only printed error is a strict-promoted info exits 64,
    /// like any other error (issue #699).
    #[test]
    fn strict_promoted_info_exits_64() {
        let config = Config {
            strict: true,
            permissive: false,
            ..Default::default()
        };
        let mut lint = Lint::new(config, vec![], Color::for_tty(false), 80).unwrap();
        add(&mut lint, "no-%check-section", Level::Info);
        assert_eq!(lint.filter.printed(Level::Error), 1);
        assert_eq!(lint.exit_code(), 64);
    }

    /// A genuine error beside a strict-promoted info: both print as
    /// errors, exit 64.
    #[test]
    fn genuine_error_beside_promoted_info_exits_64() {
        let config = Config {
            strict: true,
            permissive: false,
            ..Default::default()
        };
        let mut lint = Lint::new(config, vec![], Color::for_tty(false), 80).unwrap();
        add(&mut lint, "genuine-error", Level::Error);
        add(&mut lint, "no-%check-section", Level::Info);
        assert_eq!(lint.filter.printed(Level::Error), 2);
        assert_eq!(lint.exit_code(), 64);
    }

    #[test]
    fn unused_severity_override_is_reported() {
        let config = Config {
            severity_overrides: [("no-such-finding".to_string(), Level::Error)]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let lint = Lint::new(config, vec![], Color::for_tty(false), 80).unwrap();
        assert_eq!(
            lint.unused_severity_overrides(),
            vec!["no-such-finding".to_string()]
        );
    }

    /// JSON carries the overridden level: the override rewrites the finding
    /// before it is retained, so `--format json` reports the final level.
    #[test]
    fn json_reports_the_overridden_level() {
        let config = Config {
            severity_overrides: [("downgraded".to_string(), Level::Warning)]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let mut lint = Lint::new(config, vec![], Color::for_tty(false), 80).unwrap();
        lint.filter.add_info(Finding {
            level: Level::Error,
            check: "downgraded".to_string(),
            details: vec![],
            pkg_name: "testpkg".to_string(),
            arch: None,
            line: None,
            filter_alias: None,
            class: None,
        });
        use crate::render::{JsonRenderer, RenderContext, Renderer};
        let ctx = RenderContext {
            lint: &lint,
            prog: "rpmcrab",
            version: "2.10.0",
            header_packages: 1,
            time_report: false,
            duration_secs: 0.5,
        };
        let doc: serde_json::Value =
            serde_json::from_str(&JsonRenderer.render(&ctx)).expect("JSON");
        let levels: Vec<&str> = doc["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .map(|f| f["level"].as_str().expect("level"))
            .collect();
        assert_eq!(levels, vec!["W"]);
    }

    #[test]
    fn render_report_dispatches_to_json_and_falls_back_to_text() {
        use crate::render::{RenderContext, Renderer, TextRenderer, renderer_for};
        let config = Config::default();
        let lint = Lint::new(config, vec![], Color::for_tty(false), 80).unwrap();
        let ctx = RenderContext {
            lint: &lint,
            prog: "rpmcrab",
            version: "2.10.0",
            header_packages: 1,
            time_report: false,
            duration_secs: 0.5,
        };
        assert_eq!(
            lint.render_report("json", "rpmcrab", "2.10.0", 1, false, 0.5),
            renderer_for("json").unwrap().render(&ctx),
        );
        assert_eq!(
            lint.render_report("text", "rpmcrab", "2.10.0", 1, false, 0.5),
            TextRenderer.render(&ctx),
        );
        assert_eq!(
            lint.render_report("yaml", "rpmcrab", "2.10.0", 1, false, 0.5),
            TextRenderer.render(&ctx),
            "unknown format falls back to text"
        );
    }

    #[test]
    fn render_json_sorts_findings_like_text_and_reports_summary() {
        use crate::render::{JsonRenderer, RenderContext, Renderer};
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
                pkg_name: "testpkg".to_string(),
                arch: None,
                line: None,
                filter_alias: None,
                class: None,
            });
        }
        let ctx = RenderContext {
            lint: &lint,
            prog: "rpmcrab",
            version: "2.10.0",
            header_packages: 1,
            time_report: false,
            duration_secs: 0.5,
        };
        let doc: serde_json::Value =
            serde_json::from_str(&JsonRenderer.render(&ctx)).expect("JSON");
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

#[cfg(test)]
mod durations_tests {
    use super::*;

    /// Pins `Durations::add`: repeats accumulate under the first position.
    #[test]
    fn add_accumulates_under_the_first_position() {
        let mut d = Durations::default();
        d.add("ExtractRpm", 1.5);
        d.add("TagsCheck", 0.5);
        d.add("ExtractRpm", 0.5);
        assert_eq!(
            d.iter().collect::<Vec<_>>(),
            vec![("ExtractRpm", 2.0), ("TagsCheck", 0.5)]
        );
        assert_eq!(d.total(), 2.5);
        assert_eq!(d.as_slice().len(), 2);
    }
}
