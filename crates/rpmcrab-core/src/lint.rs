//! The `Lint` orchestrator: run checks through the filter, render the report,
//! and compute the exit code.
//!
//! Exit-code *computation* is domain logic (it is the frozen contract in
//! `docs/DESIGN.md` §4.6); the binary crate maps the returned value to a
//! process exit. This crate never calls `std::process::exit`.

use crate::check::Check;
use crate::color::Color;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::report;

/// Drives a set of checks over the inputs and renders the report.
pub struct Lint {
    config: Config,
    filter: Filter,
    checks: Vec<Box<dyn Check>>,
    color: Color,
    width: usize,
}

impl Lint {
    pub fn new(config: Config, checks: Vec<Box<dyn Check>>, color: Color, width: usize) -> Self {
        let filter = Filter::new(&config, color);
        Self {
            config,
            filter,
            checks,
            color,
            width,
        }
    }

    /// Run every check, emitting findings into the filter.
    pub fn run_checks(&mut self) {
        for check in &self.checks {
            check.run(&mut self.filter);
        }
    }

    /// The abort condition: badness score over a positive threshold.
    fn aborted(&self) -> bool {
        self.config.badness_threshold > 0
            && self.filter.score > self.config.badness_threshold as u64
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

    /// The full report: header, sorted findings, abort banner (if over
    /// threshold), footer. `duration_secs` is supplied by the caller (the
    /// binary measures wall-clock; tests pass a fixed value).
    pub fn render(&self, version: &str, no_packages: usize, duration_secs: f64) -> String {
        let mut out = String::new();
        out.push_str(&report::header(
            version,
            &self.config.conf_files,
            &[], // rpmlintrc block: M1b wires rpmlintrc loading
            self.config.checks.len(),
            no_packages,
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
        out.push_str(&report::footer(
            no_packages,
            0, // specfiles: M1b distinguishes spec inputs
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
}
