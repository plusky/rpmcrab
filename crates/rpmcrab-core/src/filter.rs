//! The suppression engine — `Filter` mirrors rpmlint's `filter.py`.
//!
//! The single most important behaviour: **suppression is applied at emit time**
//! (`add_info`), before the per-level counters are
//! incremented, so a suppressed finding is invisible to the footer and the exit
//! code, not merely hidden from stdout.

use std::collections::{HashMap, HashSet};
use std::fmt;

use fancy_regex::Regex;

use crate::color::Color;
use crate::config::Config;
use crate::describe;
use crate::finding::Finding;
use crate::level::Level;

/// Accumulates findings, applies scoring promotion/strict/suppression, and
/// renders the sorted result block.
pub struct Filter {
    strict: bool,
    scoring: HashMap<String, i64>,
    severity_overrides: HashMap<String, Level>,
    filter_titles: HashSet<String>,
    blocked_filters: HashSet<String>,
    filters: Vec<Regex>,
    used_filters: HashSet<String>,
    /// `[SeverityOverrides]` names that matched at least one emitted finding.
    used_overrides: HashSet<String>,
    info: bool,
    color: Color,
    /// `(check_name, rendered line)` pairs in emission order. The check name is
    /// kept clean (no colour suffix) so `-v` description lookup never has to
    /// re-parse it off the rendered line.
    results: Vec<(String, String)>,
    /// Levels parallel to `results`, in emission order.
    levels: Vec<Level>,
    /// The structured findings parallel to `results`, in emission order.
    /// Retained for `--format json` (upstream rpmlint#1156).
    findings: Vec<Finding>,
    /// `check` -> long explanation, for `-v`.
    error_details: HashMap<String, String>,

    pub filtered_out: u64,
    printed_errors: u64,
    printed_warnings: u64,
    printed_infos: u64,
}

/// Why a [`Filter`] could not be built from the configuration.
#[derive(Debug)]
pub enum FilterError {
    /// A `Filters` pattern does not compile.
    Pattern(fancy_regex::Error),
    /// A `[Scoring]` value cannot be coerced to an integer badness.
    Scoring { check: String, value: toml::Value },
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterError::Pattern(e) => write!(f, "{e}"),
            FilterError::Scoring { check, value } => write!(
                f,
                "invalid Scoring value {value} for {check:?} (want an integer badness)"
            ),
        }
    }
}

impl std::error::Error for FilterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FilterError::Pattern(e) => Some(e),
            FilterError::Scoring { .. } => None,
        }
    }
}

impl From<fancy_regex::Error> for FilterError {
    fn from(e: fancy_regex::Error) -> Self {
        FilterError::Pattern(e)
    }
}

/// Coerce a `[Scoring]` value exactly as Python `int()` does (`filter.py:101`):
/// integers pass through, strings are parsed, floats truncate toward zero,
/// booleans become 1/0. A value `int()` would reject (a garbage string, a
/// non-finite float, an array, a table) is a configuration error instead of
/// a crash, as is a finite float whose truncated value does not fit in an
/// `i64` (Python ints are unbounded, an `i64` is not).
fn coerce_scoring(check: &str, v: &toml::Value) -> Result<i64, FilterError> {
    let invalid = || FilterError::Scoring {
        check: check.to_string(),
        value: v.clone(),
    };
    match v {
        toml::Value::Integer(i) => Ok(*i),
        toml::Value::String(s) => s.trim().parse::<i64>().map_err(|_| invalid()),
        toml::Value::Float(f) => {
            // Rust `as` saturates on float-to-int conversion (NaN becomes
            // 0, infinities and out-of-range values clamp to the extremes),
            // while Python `int()` rejects non-finite floats. Guard the
            // truncated value explicitly: `i64::MAX as f64` rounds to
            // 2^63, so it is the exclusive upper bound, and `i64::MIN as
            // f64` is exactly the inclusive lower bound.
            let truncated = f.trunc();
            if !f.is_finite() || truncated < i64::MIN as f64 || truncated >= i64::MAX as f64 {
                Err(invalid())
            } else {
                Ok(truncated as i64)
            }
        }
        toml::Value::Boolean(b) => Ok(i64::from(*b)),
        _ => Err(invalid()),
    }
}

impl Filter {
    /// Build a filter from the parsed config. The `Filters` strings are compiled
    /// with `fancy-regex` because rpmlint uses Python `re`, which supports
    /// lookahead/lookbehind/backreferences that the `regex` crate rejects.
    ///
    /// rpmlint compiles each pattern with a bare `re.compile(f)` and **no**
    /// try/except (`filter.py:37`), so a bad `Filters` pattern raises `re.error`
    /// at Filter construction. This returns `Err` to match — it does not
    /// silently drop the pattern.
    ///
    /// `[Scoring]` values are coerced and validated here too, so a value
    /// Python `int()` would reject is a configuration error at load rather
    /// than a crash when the scored finding is emitted.
    pub fn new(config: &Config, color: Color) -> Result<Self, FilterError> {
        let mut filters = Vec::with_capacity(config.filters.len());
        for f in &config.filters {
            filters.push(Regex::new(f)?);
        }
        let mut scoring = HashMap::with_capacity(config.scoring.len());
        for (check, raw) in &config.scoring {
            scoring.insert(check.clone(), coerce_scoring(check, raw)?);
        }
        Ok(Self {
            strict: config.strict,
            scoring,
            severity_overrides: config.severity_overrides.clone(),
            filter_titles: config.filter_titles.iter().cloned().collect(),
            blocked_filters: config.blocked_filters.iter().cloned().collect(),
            filters,
            used_filters: HashSet::new(),
            used_overrides: HashSet::new(),
            info: config.info,
            color,
            results: Vec::new(),
            levels: Vec::new(),
            findings: Vec::new(),
            // The staged `data/descriptions/*.toml` corpus, exactly as
            // `filter.py` loads `descriptions/*.toml` in `Filter.__init__`.
            error_details: describe::staged_descriptions(),
            filtered_out: 0,
            printed_errors: 0,
            printed_warnings: 0,
            printed_infos: 0,
        })
    }

    /// The exit-code-relevant counters.
    pub fn printed(&self, level: Level) -> u64 {
        match level {
            Level::Error => self.printed_errors,
            Level::Warning => self.printed_warnings,
            Level::Info => self.printed_infos,
        }
    }

    /// Record a finding, applying scoring promotion, strict promotion, and
    /// suppression — in the order of `filter.py` `add_info`.
    pub fn add_info(&mut self, mut finding: Finding) {
        assert!(
            !finding.check.contains(' '),
            "space cannot be part of an issue name: {:?}",
            finding.check
        );

        // Scoring is a promotion-only override (issue #699): a positive
        // configured value raises the finding to E. A configured value never
        // lowers a level — in particular a badness of 0 does not downgrade
        // an error to a warning. The value was coerced with Python `int()`
        // semantics at construction.
        if let Some(&b) = self.scoring.get(&finding.check)
            && b > 0
        {
            finding.level = Level::Error;
        }
        // Strict promotes everything to error.
        if self.strict {
            finding.level = Level::Error;
        }
        // Per-finding severity overrides (upstream rpmlint#1335): explicit
        // user policy, applied after scoring and strict promotion — the
        // override is the final word on the finding's level.
        if let Some(level) = self.severity_overrides.get(&finding.check) {
            self.used_overrides.insert(finding.check.clone());
            finding.level = *level;
        }

        // Suppression at emit time, on the de-coloured match string.
        if finding.check != "unused-rpmlintrc-filter"
            && !self.blocked_filters.contains(&finding.check)
        {
            if self.filter_titles.contains(&finding.check) {
                self.filtered_out += 1;
                return;
            }
            let match_string = finding.match_string();
            // A renamed finding is also matched rendered under its former
            // name (`filter_alias`), so a filter written against the
            // reference tag keeps suppressing it — and counts as used.
            let alias_string = finding
                .filter_alias
                .map(|alias| finding.match_string_as(alias));
            for re in &self.filters {
                let matched = matches!(re.find(&match_string), Ok(Some(_)))
                    || alias_string
                        .as_ref()
                        .is_some_and(|s| matches!(re.find(s), Ok(Some(_))));
                if matched {
                    self.used_filters.insert(re.as_str().to_string());
                    self.filtered_out += 1;
                    return;
                }
            }
        }

        match finding.level {
            Level::Error => self.printed_errors += 1,
            Level::Warning => self.printed_warnings += 1,
            Level::Info => self.printed_infos += 1,
        }
        self.results
            .push((finding.check.clone(), finding.line(&self.color)));
        self.levels.push(finding.level);
        self.findings.push(finding);
    }

    /// Register a long explanation for `-v`/`--explain`, for the checks that
    /// compute theirs at runtime instead of shipping a staged description
    /// (`FHSCheck`, `FilesCheck`, `I18NCheck`, `PostCheck`, `SourceCheck`,
    /// `SpecCheck`, `TagsCheck` — the reference installs these in each check's `__init__`).
    pub fn set_error_detail(&mut self, check: &str, text: String) {
        self.error_details.insert(check.to_string(), text);
    }

    /// The findings that survived suppression, in emission order.
    pub fn results(&self) -> &[(String, String)] {
        &self.results
    }

    /// The level of each finding in `results()`, in the same order.
    /// Test plumbing: `results()` discards the level, and recovering it
    /// by re-parsing the rendered line would couple tests to the line
    /// format.
    pub fn result_levels(&self) -> &[Level] {
        &self.levels
    }

    /// The structured findings that survived suppression, in emission
    /// order, parallel to `results()`. Feeds `--format json`.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// The description for a check (`-v`/`--explain`), textwrap-filled to 78
    /// and followed by a blank line. A config `[Descriptions]` entry overrides
    /// the staged text, but only for an id that has one — the reference
    /// applies the override inside `if rpmlint_issue in self.error_details`.
    /// Empty when there is no description.
    pub fn get_description(&self, check: &str, config: &Config) -> String {
        let mut text = self.error_details.get(check).cloned();
        if text.is_some()
            && let Some(overridden) = config
                .configuration
                .get("Descriptions")
                .and_then(|t| t.get(check))
                .and_then(toml::Value::as_str)
            && !overridden.is_empty()
        {
            text = Some(overridden.to_string());
        }
        match text {
            Some(text) => format!("{}\n\n", crate::term::textwrap_fill(&text, 78)),

            None => String::new(),
        }
    }

    /// One `--explain` block (`lint.py:326 print_explanation`): `{id}:\n` plus
    /// the description, the `WarnOnFunction` description for configured
    /// forbidden functions, or `Unknown message` — the reference's exact
    /// wording — when neither exists. The caller prints it with a trailing
    /// newline, matching the reference's `print(f'{message}:\n{explanation}')`.
    pub fn explanation(&self, message: &str, config: &Config) -> String {
        let mut explanation = self.get_description(message, config);
        if explanation.is_empty() {
            // `lint.py:333-336`: the WarnOnFunction description is printed
            // raw, without the textwrap fill the corpus descriptions get.
            explanation = config
                .configuration
                .get("WarnOnFunction")
                .and_then(|t| t.get(message))
                .and_then(|v| v.get("description"))
                .and_then(toml::Value::as_str)
                .map(str::to_string)
                .unwrap_or_default();
        }
        if explanation.is_empty() {
            explanation =
                "Unknown message, please report a bug if the description should be present.\n\n"
                    .to_string();
        }
        format!("{message}:\n{explanation}")
    }

    /// Sort and render the result block, exactly as `filter.py` `print_results`:
    /// sorted by `(check, level_token)` descending (stable), and under `-v` each
    /// check's description is emitted after that check's findings block. The
    /// config carries `[Descriptions]` overrides, which the reference applies
    /// in `-v` output too (`print_results` -> `get_description(..., config)`).
    pub fn render_results(&self, config: &Config) -> String {
        let mut results = self.results.clone();
        sort_results(&mut results);
        let mut output = String::new();
        let mut last_issue = String::new();
        for (check, line) in &results {
            if self.info && *check != last_issue {
                if !last_issue.is_empty() {
                    output += &self.get_description(&last_issue, config);
                }
                last_issue = check.clone();
            }
            output += line;
            output.push('\n');
        }
        if self.info && !last_issue.is_empty() {
            output += &self.get_description(&last_issue, config);
        }
        output
    }

    /// Merge a per-package worker filter into the run's filter, in package
    /// input order (`_replay_result`). Suppression, scoring promotion and
    /// strict promotion are deterministic per finding, so concatenating the
    /// results and summing the counters equals the sequential run exactly.
    pub fn merge_from(&mut self, other: Filter) {
        self.results.extend(other.results);
        self.levels.extend(other.levels);
        self.findings.extend(other.findings);
        self.filtered_out += other.filtered_out;
        self.printed_errors += other.printed_errors;
        self.printed_warnings += other.printed_warnings;
        self.printed_infos += other.printed_infos;
        self.used_filters.extend(other.used_filters);
        self.used_overrides.extend(other.used_overrides);
        self.error_details.extend(other.error_details);
    }

    /// The `[SeverityOverrides]` names that matched at least one emitted
    /// finding, for the post-run typo audit.
    pub fn used_overrides(&self) -> &HashSet<String> {
        &self.used_overrides
    }

    /// The rpmlintrc filter patterns that never matched (for the
    /// `unused-rpmlintrc-filter` audit; TOML `Filters` are never audited).
    pub fn unused_filters<'a>(&self, rpmlintrc_filters: &'a [String]) -> Vec<&'a str> {
        rpmlintrc_filters
            .iter()
            .filter(|f| !self.used_filters.contains(*f))
            .map(String::as_str)
            .collect()
    }
}

/// The sort key: `(check_name, level_token)`, the second and third
/// whitespace-separated fields of the rendered line. Reads the *rendered*
/// line, so the tty-vs-piped colour difference is reproduced for free.
fn diag_sortkey(line: &str) -> (String, String) {
    let mut it = line.split_whitespace();
    let _pkg = it.next();
    let level = it.next().unwrap_or("");
    let check = it.next().unwrap_or("");
    (check.to_string(), level.to_string())
}

/// Sort rendered findings exactly as rpmlint does: `sort(key=diag_sortkey,
/// reverse=True)`. The key is read off the rendered line (so the tty-vs-piped
/// colour difference is reproduced). Rust's `sort_by` is stable, matching
/// Python's `list.sort`, so equal keys keep package insertion order.
pub fn sort_results(results: &mut [(String, String)]) {
    results.sort_by_key(|(_, line)| std::cmp::Reverse(diag_sortkey(line)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(check: &str, level: Level) -> Finding {
        Finding {
            level,
            check: check.to_string(),
            details: vec![],
            pkg_name: "pkg".to_string(),
            arch: Some("src".to_string()),
            line: None,
            filter_alias: None,
        }
    }

    fn cfg() -> Config {
        Config::default()
    }

    #[test]
    fn suppressed_findings_are_invisible_to_counters() {
        let mut c = cfg();
        c.filters = vec!["no-soname".to_string()];
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("no-soname", Level::Warning));
        assert_eq!(f.printed(Level::Warning), 0);
        assert_eq!(f.filtered_out, 1);
        assert!(f.results().is_empty());
    }

    #[test]
    fn scoring_zero_badness_never_downgrades_an_error() {
        // Issue #699: the reference remaps E -> W at a configured badness
        // of 0; rpmcrab removes that escape hatch outright. Zero and
        // negative values are inert, in both directions.
        for value in [0, -5] {
            let mut c = cfg();
            c.scoring
                .insert("some-check".to_string(), toml::Value::Integer(value));
            let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
            f.add_info(finding("some-check", Level::Error));
            assert_eq!(f.printed(Level::Error), 1, "value {value}");
            assert_eq!(f.printed(Level::Warning), 0, "value {value}");
            f.add_info(finding("some-check", Level::Warning));
            assert_eq!(f.printed(Level::Warning), 1, "value {value}");
            assert_eq!(f.printed(Level::Error), 1, "value {value}");
        }
    }

    #[test]
    fn scoring_positive_badness_forces_error() {
        let mut c = cfg();
        c.scoring
            .insert("some-check".to_string(), toml::Value::Integer(50));
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("some-check", Level::Warning));
        assert_eq!(f.printed(Level::Error), 1);
    }

    #[test]
    fn scoring_garbage_string_is_a_config_error_not_a_panic() {
        let mut c = cfg();
        c.scoring.insert(
            "some-check".to_string(),
            toml::Value::String("abc".to_string()),
        );
        let err = match Filter::new(&c, Color::for_tty(false)) {
            Ok(_) => panic!("garbage Scoring must be rejected at construction"),
            Err(e) => e,
        };
        assert!(
            matches!(&err, FilterError::Scoring { check, .. } if check == "some-check"),
            "unexpected error: {err:?}"
        );
        // The rendered message names the offending value and its check.
        let msg = err.to_string();
        assert!(msg.contains("\"abc\""), "message lacks the value: {msg}");
        assert!(msg.contains("some-check"), "message lacks the check: {msg}");
    }

    #[test]
    fn scoring_wrong_type_is_a_config_error() {
        let mut c = cfg();
        c.scoring.insert(
            "some-check".to_string(),
            toml::Value::Array(vec![toml::Value::Integer(1)]),
        );
        assert!(matches!(
            Filter::new(&c, Color::for_tty(false)),
            Err(FilterError::Scoring { .. })
        ));
    }

    #[test]
    fn scoring_numeric_string_still_applies() {
        // A `[Scoring]` value written as a TOML string is coerced with
        // Python `int()` semantics, like every other value shape.
        let mut c = cfg();
        c.scoring.insert(
            "some-check".to_string(),
            toml::Value::String("50".to_string()),
        );
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("some-check", Level::Warning));
        assert_eq!(f.printed(Level::Error), 1);
    }

    #[test]
    fn scoring_non_finite_float_is_a_config_error() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut c = cfg();
            c.scoring
                .insert("some-check".to_string(), toml::Value::Float(value));
            assert!(
                matches!(
                    Filter::new(&c, Color::for_tty(false)),
                    Err(FilterError::Scoring { .. })
                ),
                "float {value} must be rejected at construction"
            );
            assert!(
                coerce_scoring("some-check", &toml::Value::Float(value)).is_err(),
                "float {value} must fail coercion"
            );
        }
    }

    #[test]
    fn scoring_out_of_range_float_is_a_config_error() {
        // Python int() would produce an unbounded integer for these; the
        // i64 badness cannot hold them, so they are configuration errors
        // rather than saturated extremes.
        for value in [1e20, -1e20, 1e100, 9_223_372_036_854_776_000.0] {
            let mut c = cfg();
            c.scoring
                .insert("some-check".to_string(), toml::Value::Float(value));
            assert!(
                matches!(
                    Filter::new(&c, Color::for_tty(false)),
                    Err(FilterError::Scoring { .. })
                ),
                "float {value} must be rejected at construction"
            );
        }
    }

    #[test]
    fn scoring_valid_floats_truncate_toward_zero() {
        let cases = [
            (2.9, 2),
            (-2.9, -2),
            (0.0, 0),
            (-0.9, 0),
            (50.0, 50),
            // The largest f64 below 2^63 and i64::MIN itself both fit.
            (9_223_372_036_854_774_784.0, 9_223_372_036_854_774_784),
            (i64::MIN as f64, i64::MIN),
        ];
        for (input, want) in cases {
            assert_eq!(
                coerce_scoring("some-check", &toml::Value::Float(input)).unwrap(),
                want,
                "float {input} must truncate to {want}"
            );
        }
    }

    #[test]
    fn scoring_float_and_bool_keep_int_semantics() {
        let mut c = cfg();
        c.scoring
            .insert("float-check".to_string(), toml::Value::Float(2.9));
        c.scoring
            .insert("bool-check".to_string(), toml::Value::Boolean(true));
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("float-check", Level::Warning));
        f.add_info(finding("bool-check", Level::Warning));
        // 2.9 truncates to 2 and `true` coerces to 1: both positive, so
        // both findings are promoted to error.
        assert_eq!(f.printed(Level::Error), 2);
    }

    #[test]
    fn strict_promotes_warning_to_error() {
        let mut c = cfg();
        c.strict = true;
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("a-warning", Level::Warning));
        assert_eq!(f.printed(Level::Error), 1);
        assert_eq!(f.printed(Level::Warning), 0);
    }

    #[test]
    fn strict_promotes_info_findings() {
        // --strict promotion applies to every level, Info included
        // (filter.py:134-140): the finding prints as an error.
        let mut c = cfg();
        c.strict = true;
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("no-%check-section", Level::Info));
        assert_eq!(f.printed(Level::Error), 1);
        assert_eq!(f.printed(Level::Info), 0);
    }

    #[test]
    fn severity_override_downgrades_error_to_warning() {
        let mut c = cfg();
        c.severity_overrides
            .insert("spelling-error".to_string(), Level::Warning);
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("spelling-error", Level::Error));
        assert_eq!(f.printed(Level::Warning), 1);
        assert_eq!(f.printed(Level::Error), 0);
        assert!(f.results()[0].1.starts_with("pkg.src: W: spelling-error"));
    }

    #[test]
    fn severity_override_upgrades_warning_to_error() {
        let mut c = cfg();
        c.severity_overrides
            .insert("no-soname".to_string(), Level::Error);
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("no-soname", Level::Warning));
        assert_eq!(f.printed(Level::Error), 1);
        assert!(f.results()[0].1.starts_with("pkg.src: E: no-soname"));
    }

    #[test]
    fn severity_override_beats_strict_promotion() {
        let mut c = cfg();
        c.strict = true;
        c.severity_overrides
            .insert("spelling-error".to_string(), Level::Warning);
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("spelling-error", Level::Warning));
        // Strict promotes, then the override downgrades back: the table is
        // the final word on the finding's level.
        assert_eq!(f.printed(Level::Warning), 1);
        assert_eq!(f.printed(Level::Error), 0);
    }

    #[test]
    fn strict_with_override_back_prints_one_error_one_warning() {
        let mut c = cfg();
        c.strict = true;
        c.severity_overrides
            .insert("second-warning".to_string(), Level::Warning);
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("first-warning", Level::Warning));
        f.add_info(finding("second-warning", Level::Warning));
        assert_eq!(f.printed(Level::Error), 1);
        assert_eq!(f.printed(Level::Warning), 1);
        assert_eq!(f.used_overrides().len(), 1);
        assert!(f.used_overrides().contains("second-warning"));
    }

    #[test]
    fn severity_override_beats_scoring_promotion() {
        let mut c = cfg();
        c.scoring
            .insert("some-check".to_string(), toml::Value::Integer(50));
        c.severity_overrides
            .insert("some-check".to_string(), Level::Warning);
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("some-check", Level::Warning));
        // Scoring promotes to E, the override returns it to W: the
        // override is the final word on the level.
        assert_eq!(f.printed(Level::Warning), 1);
        assert_eq!(f.printed(Level::Error), 0);
    }

    #[test]
    fn severity_override_to_error_with_zero_scoring() {
        // `Scoring(0)` is inert (issue #699); the override alone raises
        // the finding to a genuine error.
        let mut c = cfg();
        c.scoring
            .insert("zero-scored".to_string(), toml::Value::Integer(0));
        c.severity_overrides
            .insert("zero-scored".to_string(), Level::Error);
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("zero-scored", Level::Warning));
        assert_eq!(f.printed(Level::Error), 1);
        assert_eq!(f.printed(Level::Warning), 0);
    }

    #[test]
    fn filters_match_the_overridden_level() {
        // Suppression runs after the override (DESIGN §4.9): a `Filters`
        // regex matching the post-override level letter filters the finding,
        // while one matching the pre-override letter does not.
        let mut c = cfg();
        c.severity_overrides
            .insert("downgraded".to_string(), Level::Warning);
        c.filters = vec!["W: downgraded".to_string()];
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("downgraded", Level::Error));
        assert_eq!(f.filtered_out, 1);
        assert_eq!(f.printed(Level::Warning), 0);

        let mut c = cfg();
        c.severity_overrides
            .insert("downgraded".to_string(), Level::Warning);
        c.filters = vec!["E: downgraded".to_string()];
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("downgraded", Level::Error));
        assert_eq!(f.filtered_out, 0);
        assert_eq!(f.printed(Level::Warning), 1);
    }

    #[test]
    fn aliased_finding_matches_filters_under_its_former_name() {
        // #524: a finding whose tag was renamed for one emission path
        // carries the old name as its filter alias. A filter written
        // against the old name suppresses it and counts as used; the same
        // finding without the alias is not matched.
        let mut c = cfg();
        c.filters = vec!["script-without-shebang".to_string()];
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        let mut aliased = finding("spurious-executable-perm", Level::Warning);
        aliased.filter_alias = Some("script-without-shebang");
        f.add_info(aliased);
        assert_eq!(f.filtered_out, 1);
        assert_eq!(f.printed(Level::Warning), 0);
        assert!(f.unused_filters(&c.filters).is_empty());

        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("spurious-executable-perm", Level::Warning));
        assert_eq!(f.filtered_out, 0);
        assert_eq!(f.printed(Level::Warning), 1);
        assert_eq!(f.unused_filters(&c.filters), vec!["script-without-shebang"]);
    }

    #[test]
    fn blocked_filter_is_unfilterable() {
        let mut c = cfg();
        c.filters = vec!["no-soname".to_string()];
        c.blocked_filters = vec!["no-soname".to_string()];
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("no-soname", Level::Warning));
        assert_eq!(f.printed(Level::Warning), 1);
        assert_eq!(f.filtered_out, 0);
    }

    #[test]
    fn verbose_interleaves_description_after_check_block() {
        // Mirrors the captured `-v` run: the two suse-zypp-packageand findings,
        // then that check's description, then a blank line, then no-soname
        // with its staged `BinariesCheck.toml` description.
        let mut c = cfg();
        c.info = true;
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.set_error_detail(
            "suse-zypp-packageand",
            "The 'packageand(package1:package2)' syntax is obsolete, please use boolean\ndependencies like:\n'Supplements: (package1 and package2)'\n".to_string(),
        );
        f.add_info({
            let mut d = finding("suse-zypp-packageand", Level::Error);
            d.pkg_name = "llvm21-gold".to_string();
            d.arch = Some("aarch64".to_string());
            d.details = vec!["packageand(clang21:binutils)".to_string()];
            d
        });
        f.add_info({
            let mut d = finding("no-soname", Level::Warning);
            d.pkg_name = "llvm21-gold".to_string();
            d.arch = Some("aarch64".to_string());
            d.details = vec!["/usr/lib64/LLVMgold.so".to_string()];
            d
        });
        let out = f.render_results(&c);
        let expected = "llvm21-gold.aarch64: E: suse-zypp-packageand packageand(clang21:binutils)\nThe 'packageand(package1:package2)' syntax is obsolete, please use boolean\ndependencies like: 'Supplements: (package1 and package2)'\n\nllvm21-gold.aarch64: W: no-soname /usr/lib64/LLVMgold.so\nThe library has no soname.\n\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn description_from_toml() {
        // `test_filter.py:83 test_description_from_toml`: a staged
        // description resolves to the filled text plus a blank line.
        let c = cfg();
        let f = Filter::new(&c, Color::for_tty(false)).unwrap();
        assert_eq!(
            f.get_description("bad-crc-in-zip", &c),
            "The reported file in the zip fails the CRC check. Usually this is a sign of a\ncorrupt zip file.\n\n"
        );
        assert_eq!(f.get_description("suse-other-error", &c), "");
    }

    #[test]
    fn description_from_config() {
        // `test_filter.py:93 test_description_from_conf`: `[Descriptions]`
        // overrides the staged text; an override for an id with no staged
        // description is ignored, exactly like the reference.
        let mut c = cfg();
        let mut descriptions = toml::map::Map::new();
        descriptions.insert(
            "no-binary".to_string(),
            toml::Value::String("A new text for no-binary error.\n".to_string()),
        );
        descriptions.insert(
            "suse-other-error".to_string(),
            toml::Value::String("No staged base, override must not apply.\n".to_string()),
        );
        c.configuration
            .insert("Descriptions".to_string(), toml::Value::Table(descriptions));
        let f = Filter::new(&c, Color::for_tty(false)).unwrap();
        assert_eq!(
            f.get_description("no-binary", &c),
            "A new text for no-binary error.\n\n"
        );
        assert_eq!(f.get_description("suse-other-error", &c), "");
    }

    #[test]
    fn sort_groups_by_check_reverse_then_severity_tty() {
        // On a tty the level tokens carry ANSI codes, so within a check the
        // descending order is W > E > I (the F4 quirk, docs/DESIGN.md §4.4).
        // The findings are rendered with the tty colour table, and the sort
        // reads the level token off the rendered line.
        let c = Color::for_tty(true);
        let render = |level: Level, check: &str| {
            let f = Finding {
                level,
                check: check.to_string(),
                details: vec![],
                pkg_name: "pkg".to_string(),
                arch: Some("src".to_string()),
                line: None,
                filter_alias: None,
            };
            (check.to_string(), f.line(&c))
        };
        let mut lines = vec![
            render(Level::Error, "zeta-check"),
            render(Level::Info, "zeta-check"),
            render(Level::Warning, "zeta-check"),
        ];
        sort_results(&mut lines);
        // Decode the level letter out of each rendered line's second field.
        // The level letter is the char before the token's trailing ':'.
        let letters: Vec<char> = lines
            .iter()
            .map(|(_, l)| {
                l.split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .trim_end_matches(':')
                    .chars()
                    .last()
                    .unwrap_or('?')
            })
            .collect();
        assert_eq!(letters, vec!['W', 'E', 'I']);
    }

    #[test]
    fn sort_groups_by_check_reverse_then_severity_piped() {
        // Piped level tokens are bare "W:"/"I:"/"E:", so within a check the
        // descending order is W > I > E (see docs/DESIGN.md §4.4).
        let mut lines: Vec<(String, String)> = vec![
            ("zeta-check".into(), "pkg.src: E: zeta-check".into()),
            ("alpha-check".into(), "pkg.src: W: alpha-check".into()),
            ("zeta-check".into(), "pkg.src: I: zeta-check".into()),
            ("zeta-check".into(), "pkg.src: W: zeta-check".into()),
        ];
        sort_results(&mut lines);
        let rendered: Vec<&str> = lines.iter().map(|(_, l)| l.as_str()).collect();
        assert_eq!(
            rendered,
            vec![
                "pkg.src: W: zeta-check",
                "pkg.src: I: zeta-check",
                "pkg.src: E: zeta-check",
                "pkg.src: W: alpha-check",
            ]
        );
    }

    #[test]
    fn descriptions_from_config_appear_in_verbose_output() {
        // Port of `test_lint.py::test_descriptions_from_config`: the
        // "parametrized" FHS descriptions are overridden from configuration
        // and the `-v` rendering shows the new texts, not the built ones.
        let mut c = cfg();
        c.info = true;
        let mut descriptions = toml::map::Map::new();
        descriptions.insert(
            "non-standard-dir-in-usr".to_string(),
            toml::Value::String("A new text for non-standard-dir-in-usr error.\n".to_string()),
        );
        descriptions.insert(
            "non-standard-dir-in-var".to_string(),
            toml::Value::String("A new text for non-standard-dir-in-var error.\n".to_string()),
        );
        c.configuration
            .insert("Descriptions".to_string(), toml::Value::Table(descriptions));
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        crate::checks::fhs::FHSCheck::register_error_details(&mut f);
        f.add_info(finding("non-standard-dir-in-usr", Level::Warning));
        f.add_info(finding("non-standard-dir-in-var", Level::Warning));
        let out = f.render_results(&c);
        assert!(
            out.contains("A new text for non-standard-dir-in-usr error."),
            "got {out}"
        );
        assert!(
            out.contains("A new text for non-standard-dir-in-var error."),
            "got {out}"
        );
        assert!(
            !out.contains("Your package is creating a non-standard subdirectory in /usr"),
            "got {out}"
        );
        assert!(
            !out.contains("Your package is creating a non-standard subdirectory in /var"),
            "got {out}"
        );
    }

    /// rpmcrab#387: the vendored openSUSE config must carry the mingw
    /// arch-independent filters. The reference suppresses
    /// `arch-independent-package-contains-binary-or-object` for mingw `.a`
    /// files via distro-config filters shipped by mingw{32,64}-filesystem
    /// (see EXTRA_OPENSUSE_FILTERS in scripts/generate-distro-configs.py);
    /// without them rpmcrab emits the finding 12x where the reference is
    /// silent.
    #[test]
    fn vendored_opensuse_config_suppresses_mingw_arch_independent_a_files() {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let toml_path = manifest_dir.join("data/distro/opensuse/opensuse.toml");
        let content = std::fs::read_to_string(&toml_path).expect("read opensuse.toml");
        let value: toml::Value = toml::from_str(&content).expect("parse opensuse.toml");
        let filters = value
            .get("Filters")
            .and_then(|v| v.as_array())
            .expect("Filters list");
        let patterns: Vec<&str> = filters.iter().filter_map(|v| v.as_str()).collect();

        let m32 = patterns
            .iter()
            .find(|p| {
                p.starts_with("^mingw32-.*arch-independent-package-contains-binary-or-object")
            })
            .expect("mingw32 arch-independent filter in vendored opensuse.toml");
        let m64 = patterns
            .iter()
            .find(|p| {
                p.starts_with("^mingw64-.*arch-independent-package-contains-binary-or-object")
            })
            .expect("mingw64 arch-independent filter in vendored opensuse.toml");

        let re32 = fancy_regex::Regex::new(m32).expect("compile mingw32 filter");
        let re64 = fancy_regex::Regex::new(m64).expect("compile mingw64 filter");
        let is_match = |re: &fancy_regex::Regex, s: &str| re.find(s).unwrap().is_some();

        // Suppressed: mingw .a files (the 12 crab-only cases from the audit).
        assert!(is_match(
            &re32,
            "mingw32-binutils-devel.noarch: E: arch-independent-package-contains-binary-or-object /usr/i686-w64-mingw32/sys-root/mingw/lib/libbfd.a"
        ));
        assert!(is_match(
            &re64,
            "mingw64-binutils-devel.noarch: E: arch-independent-package-contains-binary-or-object /usr/x86_64-w64-mingw32/sys-root/mingw/lib/libbfd.a"
        ));

        // Not suppressed: non-mingw packages, non-.a files, other findings.
        assert!(!is_match(
            &re32,
            "foo-devel.noarch: E: arch-independent-package-contains-binary-or-object /usr/lib/libfoo.a"
        ));
        assert!(!is_match(
            &re32,
            "mingw32-foo.noarch: E: arch-independent-package-contains-binary-or-object /usr/i686-w64-mingw32/bin/foo.dll"
        ));
        assert!(!is_match(
            &re32,
            "mingw32-foo.noarch: E: files-duplicate /usr/i686-w64-mingw32/lib/libfoo.a /usr/lib/libfoo.a"
        ));
        assert!(!is_match(
            &re64,
            "foo-devel.noarch: E: arch-independent-package-contains-binary-or-object /usr/lib/libfoo.a"
        ));
    }

    /// The vendored openSUSE config carries no spelling-error filter:
    /// the RPM-ecosystem jargon (librpm, scriptlet, init, namespace)
    /// is vocabulary of the
    /// spellchecker itself — the bundled supplementary wordlist in
    /// spellcheck.rs — so the words are accepted before any finding
    /// exists, and a spelling-error finding that does reach the
    /// config is a genuine typo the shipped filters leave standing.
    #[test]
    fn vendored_opensuse_config_has_no_spelling_error_filter() {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let toml_path = manifest_dir.join("data/distro/opensuse/opensuse.toml");
        let content = std::fs::read_to_string(&toml_path).expect("read opensuse.toml");
        let value: toml::Value = toml::from_str(&content).expect("parse opensuse.toml");
        let filters = value
            .get("Filters")
            .and_then(|v| v.as_array())
            .expect("Filters list");
        let patterns: Vec<&str> = filters.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            patterns.iter().all(|p| !p.contains("spelling-error")),
            "no shipped filter names spelling-error"
        );
        // A genuine typo in the rendered shape still surfaces: no
        // shipped filter suppresses it.
        let line = "foo.x86_64: E: spelling-error Summary(C) recieve -> receive";
        for pattern in &patterns {
            let re = fancy_regex::Regex::new(pattern).expect("compile shipped filter");
            assert!(
                re.find(line).unwrap().is_none(),
                "shipped filter {pattern} suppresses a genuine typo"
            );
        }
    }
}
