//! The configuration model the filter engine and renderer consume.
//!
//! This is the parsed shape. The TOML loader + merger (search order, the
//! 3-way stable sort, union-vs-override list semantics) lands in M1b; for now
//! tests construct this directly. Field semantics are the frozen contract in
//! `docs/DESIGN.md` §4.7.

use std::collections::HashMap;

/// Parsed rpmlint configuration relevant to emission and rendering.
#[derive(Debug, Default, Clone)]
pub struct Config {
    /// `Checks` — the check names to run, in order. The header prints its length.
    pub checks: Vec<String>,
    /// The config files that were loaded, in load order (printed in the header).
    pub conf_files: Vec<String>,
    /// `[Scoring]` — check name → badness.
    pub scoring: HashMap<String, u64>,
    /// `Filters` — regex strings matched (unanchored) against the de-coloured line.
    pub filters: Vec<String>,
    /// `FilterErrorTitles` — exact check names that are always suppressed.
    pub filter_titles: Vec<String>,
    /// `BlockedFilters` — exact check names that are never suppressible.
    pub blocked_filters: Vec<String>,
    /// `BadnessThreshold` (default -1 upstream; 999 on openSUSE).
    pub badness_threshold: i64,
    /// `-s/--strict`: promote every finding to `E`.
    pub strict: bool,
    /// `-v/--verbose`/`--info`: inline explanations.
    pub info: bool,
    /// `-P/--permissive`: never fail on errors/badness. On openSUSE this is
    /// forced on unless `--strict` (see `docs/DESIGN.md` §4.6).
    pub permissive: bool,
}
