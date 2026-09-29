//! The `Lint` orchestrator: run checks over the inputs, render the report, and
//! compute the exit code.
//!
//! Exit-code *computation* is domain logic (it is the frozen contract in
//! `docs/DESIGN.md` §4.6); the binary crate maps the returned value to a
//! process exit. This crate never calls `std::process::exit`.
//!
//! The per-package loop mirrors rpmlint's `Lint.run_checks` /
//! `validate_file` (`lint.py:282-318`): each check is timed, and only after the
//! **last** package do the `after_checks` hooks and the rpmlintrc filter audit
//! run.

use std::collections::BTreeMap;
use std::time::Instant;

use crate::check::{Check, add_info};
use crate::color::Color;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::report;

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
    /// Always 0 until the `.spec` (FakePkg) support lands; the footer's
    /// `specfiles` column is part of the frozen output either way.
    specfiles_checked: usize,
    /// `Filter.validate_filters` is skipped with `--ignore-unused-rpmlintrc`.
    audit_rpmlintrc: bool,
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
        })
    }

    /// `Lint.__init__` honours `--ignore-unused-rpmlintrc` by not auditing the
    /// rpmlintrc filters at the end of the run.
    pub fn set_audit_rpmlintrc(&mut self, audit: bool) {
        self.audit_rpmlintrc = audit;
    }

    /// `Lint.run_checks(pkg, is_last)`: run every check over one package,
    /// timing each, then — for the last package — the `after_checks` hooks and
    /// the unused-rpmlintrc-filter audit.
    ///
    /// The package's own phase timings (`ExtractRpm`, `libmagic`) are folded
    /// into the same duration map, which is what the `-t` report reads.
    pub fn run_package(&mut self, pkg: &mut Pkg, is_last: bool) {
        for (phase, secs) in pkg.timers.iter() {
            self.check_duration.add(phase, secs);
        }
        for check in &mut self.checks {
            let start = Instant::now();
            check.check(pkg, &self.config, &mut self.filter);
            let secs = start.elapsed().as_secs_f64();
            self.check_duration.add(check.name(), secs);
        }

        if is_last {
            for check in &mut self.checks {
                check.after_checks(&self.config, &mut self.filter);
            }
            if self.audit_rpmlintrc {
                self.audit_unused_filters(pkg);
            }
        }
        // `Lint.reset_checks()` runs after *every* package, the last one
        // included (`lint.py:251,271`), so per-run state cannot leak into the
        // next package.
        for check in &mut self.checks {
            check.reset();
        }
        self.packages_checked += 1;
    }

    /// `Filter.validate_filters(pkg)`: every rpmlintrc `Filters` pattern that
    /// never matched becomes an `unused-rpmlintrc-filter` error. The pattern is
    /// quoted, as the reference does.
    ///
    /// The patterns are collected first because each finding is emitted while
    /// borrowing the filter mutably.
    fn audit_unused_filters(&mut self, pkg: &Pkg) {
        let unused: Vec<String> = self
            .filter
            .unused_filters(&self.config.rpmlintrc_filters)
            .into_iter()
            .map(str::to_string)
            .collect();
        for pattern in unused {
            let detail = format!("\"{pattern}\"");
            add_info(
                &mut self.filter,
                Level::Error,
                pkg,
                "unused-rpmlintrc-filter",
                &[&detail],
            );
        }
    }

    /// The abort condition: badness score over a positive threshold.
    fn aborted(&self) -> bool {
        self.config.badness_threshold > 0 && self.filter.score > self.config.badness_threshold
    }

    /// The process exit code (`docs/DESIGN.md` §4.6). Badness-over-threshold
    /// (66) is evaluated before the permissive error branch (64/65).
    pub fn exit_code(&self) -> i32 {
        if self.aborted() {
            66
        } else if self.filter.printed(Level::Error) > 0 && !self.config.permissive {
            if self.filter.printed(Level::Error) == self.filter.promoted_to_error {
                65
            } else {
                64
            }
        } else {
            0
        }
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

    /// The `-T` profile report: rpmcrab's own per-check wall time.
    pub fn profile_report(&self) -> String {
        report::profile_report(self.check_duration.as_slice(), &self.color)
    }

    /// The report: header, sorted findings, abort banner (if over threshold),
    /// and — when requested — the time and profile reports, then the footer.
    ///
    /// The order is the reference's: results, banner, reports, footer
    /// (`lint.py:94-118`). The header and footer count different things:
    /// `header_packages` is the CLI *argument* count (`len(installed) +
    /// len(rpmfile)`, `lint.py:242`), while the footer counts the packages
    /// actually validated.
    #[allow(clippy::too_many_arguments)]
    pub fn render(
        &self,
        version: &str,
        header_packages: usize,
        time_report: bool,
        profile: bool,
        duration_secs: f64,
    ) -> String {
        let mut out = String::new();
        out.push_str(&report::header(
            version,
            &self.config.conf_files,
            &self.config.rpmlintrc_display,
            self.config.checks.len(),
            header_packages,
            &self.color,
            self.width,
        ));
        out.push_str(&self.filter.render_results());
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
        if profile {
            out.push_str(&self.profile_report());
        }
        out.push_str(&report::footer(
            self.packages_checked,
            self.specfiles_checked,
            self.filter.printed(Level::Error),
            self.filter.printed(Level::Warning),
            self.filter.filtered_out,
            self.filter.score,
            duration_secs,
            self.aborted(),
            &self.color,
            self.width,
        ));
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
