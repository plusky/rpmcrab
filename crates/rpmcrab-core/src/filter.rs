//! The suppression engine — `Filter` mirrors rpmlint's `filter.py`.
//!
//! The single most important behaviour: **suppression is applied at emit time**
//! (`add_info`), before the badness total and the per-level counters are
//! incremented, so a suppressed finding is invisible to the footer and the exit
//! code, not merely hidden from stdout.

use std::collections::{HashMap, HashSet};

use fancy_regex::Regex;

use crate::color::Color;
use crate::config::Config;
use crate::describe;
use crate::finding::Finding;
use crate::level::Level;

/// Accumulates findings, applies scoring/strict/suppression, and renders the
/// sorted result block.
pub struct Filter {
    strict: bool,
    scoring: HashMap<String, toml::Value>,
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

    pub score: i64,
    pub filtered_out: u64,
    pub promoted_to_error: u64,
    printed_errors: u64,
    printed_warnings: u64,
    printed_infos: u64,
}

/// Coerce a `[Scoring]` value exactly as Python `int()` does at emit time
/// (`filter.py:101`): integers pass through, strings are parsed (garbage
/// crashes, as `int('abc')` raises `ValueError`), floats truncate, booleans
/// become 1/0. rpmlint crashes on a bad value, so this panics to match.
fn coerce_scoring(v: &toml::Value) -> i64 {
    match v {
        toml::Value::Integer(i) => *i,
        toml::Value::String(s) => s.trim().parse::<i64>().unwrap_or_else(|_| {
            panic!("invalid Scoring value {s:?} (int() would raise ValueError)")
        }),
        toml::Value::Float(f) => *f as i64,
        toml::Value::Boolean(b) => i64::from(*b),
        other => panic!("invalid Scoring value {other:?} (int() would raise ValueError)"),
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
    pub fn new(config: &Config, color: Color) -> Result<Self, fancy_regex::Error> {
        let mut filters = Vec::with_capacity(config.filters.len());
        for f in &config.filters {
            filters.push(Regex::new(f)?);
        }
        Ok(Self {
            strict: config.strict,
            scoring: config.scoring.clone(),
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
            score: 0,
            filtered_out: 0,
            promoted_to_error: 0,
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

    /// Record a finding, applying scoring, strict promotion, and suppression —
    /// the exact order of `filter.py` `add_info`.
    pub fn add_info(&mut self, mut finding: Finding) {
        assert!(
            !finding.check.contains(' '),
            "space cannot be part of an issue name: {:?}",
            finding.check
        );

        // Scoring remaps the level in both directions: to E when badness > 0,
        // and E -> W when the configured badness is 0. The value is coerced at
        // emit time with Python `int()` semantics (`filter.py:124-131`).
        let mut badness = None;
        if let Some(raw) = self.scoring.get(&finding.check) {
            let b = coerce_scoring(raw);
            badness = Some(b);
            if b > 0 {
                finding.level = Level::Error;
            } else if finding.level == Level::Error {
                finding.level = Level::Warning;
            }
        }
        // Strict promotes everything to error (and counts the promotions);
        // default badness is computed after promotion, so promoted
        // findings get the E default of 1.
        //
        // An overridden finding is not counted as strict-promoted: the
        // override below is the final word on its level, and counting it
        // would break the DESIGN §4.6 `printed(E) == promoted` split (a
        // finding overridden back to W is not a strict error, so the run
        // exits 65, not 64).
        let overridden = self.severity_overrides.contains_key(&finding.check);
        if self.strict {
            if finding.level != Level::Error && !overridden {
                self.promoted_to_error += 1;
            }
            finding.level = Level::Error;
        }
        // Per-finding severity overrides (upstream rpmlint#1335): explicit
        // user policy, applied after scoring and strict promotion — the
        // override is the final word on the finding's level. Badness still
        // follows the scoring table when set, else the level default below.
        if let Some(level) = self.severity_overrides.get(&finding.check) {
            self.used_overrides.insert(finding.check.clone());
            finding.level = *level;
        }
        let badness = badness.unwrap_or(if finding.level == Level::Error { 1 } else { 0 });
        finding.badness = badness;

        // Suppression at emit time, on the de-coloured match string.
        if finding.check != "unused-rpmlintrc-filter"
            && !self.blocked_filters.contains(&finding.check)
        {
            if self.filter_titles.contains(&finding.check) {
                self.filtered_out += 1;
                return;
            }
            let match_string = finding.match_string();
            for re in &self.filters {
                if matches!(re.find(&match_string), Ok(Some(_))) {
                    self.used_filters.insert(re.as_str().to_string());
                    self.filtered_out += 1;
                    return;
                }
            }
        }

        self.score += badness;
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
    /// input order (`_replay_result`). Suppression, scoring and strict
    /// promotion are deterministic per finding, so concatenating the results
    /// and summing the counters equals the sequential run exactly.
    pub fn merge_from(&mut self, other: Filter) {
        self.results.extend(other.results);
        self.levels.extend(other.levels);
        self.findings.extend(other.findings);
        self.score += other.score;
        self.filtered_out += other.filtered_out;
        self.promoted_to_error += other.promoted_to_error;
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

    fn finding(check: &str, level: Level, badness: i64) -> Finding {
        Finding {
            level,
            check: check.to_string(),
            details: vec![],
            badness,
            pkg_name: "pkg".to_string(),
            arch: Some("src".to_string()),
            line: None,
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
        f.add_info(finding("no-soname", Level::Warning, 0));
        assert_eq!(f.printed(Level::Warning), 0);
        assert_eq!(f.filtered_out, 1);
        assert_eq!(f.score, 0);
        assert!(f.results().is_empty());
    }

    #[test]
    fn scoring_downgrades_error_to_warning_at_zero_badness() {
        let mut c = cfg();
        c.scoring
            .insert("some-check".to_string(), toml::Value::Integer(0));
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("some-check", Level::Error, 99));
        // level remapped E -> W, badness 0, counts as a warning, no score.
        assert_eq!(f.printed(Level::Warning), 1);
        assert_eq!(f.printed(Level::Error), 0);
        assert_eq!(f.score, 0);
    }

    #[test]
    fn scoring_positive_badness_forces_error() {
        let mut c = cfg();
        c.scoring
            .insert("some-check".to_string(), toml::Value::Integer(50));
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("some-check", Level::Warning, 0));
        assert_eq!(f.printed(Level::Error), 1);
        assert_eq!(f.score, 50);
    }

    #[test]
    fn strict_promotes_with_default_badness() {
        let mut c = cfg();
        c.strict = true;
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("a-warning", Level::Warning, 0));
        assert_eq!(f.printed(Level::Error), 1);
        assert_eq!(f.promoted_to_error, 1);
        assert_eq!(f.score, 1); // E default badness 1 after promotion
    }

    #[test]
    fn severity_override_downgrades_error_to_warning() {
        let mut c = cfg();
        c.severity_overrides
            .insert("spelling-error".to_string(), Level::Warning);
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("spelling-error", Level::Error, 0));
        assert_eq!(f.printed(Level::Warning), 1);
        assert_eq!(f.printed(Level::Error), 0);
        assert_eq!(f.score, 0); // W default badness 0
        assert!(f.results()[0].1.starts_with("pkg.src: W: spelling-error"));
    }

    #[test]
    fn severity_override_upgrades_warning_to_error() {
        let mut c = cfg();
        c.severity_overrides
            .insert("no-soname".to_string(), Level::Error);
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("no-soname", Level::Warning, 0));
        assert_eq!(f.printed(Level::Error), 1);
        assert_eq!(f.score, 1); // E default badness 1
        assert!(f.results()[0].1.starts_with("pkg.src: E: no-soname"));
    }

    #[test]
    fn severity_override_beats_strict_promotion() {
        let mut c = cfg();
        c.strict = true;
        c.severity_overrides
            .insert("spelling-error".to_string(), Level::Warning);
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("spelling-error", Level::Warning, 0));
        // Strict promotes, then the override downgrades back: the table is
        // the final word on the finding's level, and the finding is not
        // counted as strict-promoted (DESIGN §4.6 exit-code split).
        assert_eq!(f.promoted_to_error, 0);
        assert_eq!(f.printed(Level::Warning), 1);
        assert_eq!(f.printed(Level::Error), 0);
    }

    #[test]
    fn strict_promotion_count_skips_overridden_findings() {
        // The exit-code bug: 2 strict-promoted warnings with one overridden
        // back must keep printed(E) == promoted_to_error (1 == 1); counting
        // the overridden finding gave 1 != 2 and the wrong exit code.
        let mut c = cfg();
        c.strict = true;
        c.severity_overrides
            .insert("second-warning".to_string(), Level::Warning);
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("first-warning", Level::Warning, 0));
        f.add_info(finding("second-warning", Level::Warning, 0));
        assert_eq!(f.printed(Level::Error), 1);
        assert_eq!(f.printed(Level::Warning), 1);
        assert_eq!(f.promoted_to_error, 1);
        assert_eq!(f.used_overrides().len(), 1);
        assert!(f.used_overrides().contains("second-warning"));
    }

    #[test]
    fn severity_override_keeps_explicit_scoring_badness() {
        let mut c = cfg();
        c.scoring
            .insert("some-check".to_string(), toml::Value::Integer(50));
        c.severity_overrides
            .insert("some-check".to_string(), Level::Warning);
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("some-check", Level::Warning, 0));
        // scoring forces E, the override returns it to W, explicit badness
        // 50 stays (scoring still drives the score).
        assert_eq!(f.printed(Level::Warning), 1);
        assert_eq!(f.score, 50);
    }

    #[test]
    fn severity_override_to_error_keeps_zero_scoring_badness() {
        // `Scoring(0)` + override to E (DESIGN §4.9): the finding prints as a
        // genuine error for the §4.6 split, but scoring still drives the
        // badness, so it scores nothing.
        let mut c = cfg();
        c.scoring
            .insert("zero-badness".to_string(), toml::Value::Integer(0));
        c.severity_overrides
            .insert("zero-badness".to_string(), Level::Error);
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("zero-badness", Level::Warning, 0));
        assert_eq!(f.printed(Level::Error), 1);
        assert_eq!(f.printed(Level::Warning), 0);
        assert_eq!(f.score, 0);
        // An override is not a strict promotion, even when it raises the level.
        assert_eq!(f.promoted_to_error, 0);
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
        f.add_info(finding("downgraded", Level::Error, 0));
        assert_eq!(f.filtered_out, 1);
        assert_eq!(f.printed(Level::Warning), 0);

        let mut c = cfg();
        c.severity_overrides
            .insert("downgraded".to_string(), Level::Warning);
        c.filters = vec!["E: downgraded".to_string()];
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("downgraded", Level::Error, 0));
        assert_eq!(f.filtered_out, 0);
        assert_eq!(f.printed(Level::Warning), 1);
    }

    #[test]
    fn blocked_filter_is_unfilterable() {
        let mut c = cfg();
        c.filters = vec!["no-soname".to_string()];
        c.blocked_filters = vec!["no-soname".to_string()];
        let mut f = Filter::new(&c, Color::for_tty(false)).unwrap();
        f.add_info(finding("no-soname", Level::Warning, 0));
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
            let mut d = finding("suse-zypp-packageand", Level::Error, 0);
            d.pkg_name = "llvm21-gold".to_string();
            d.arch = Some("aarch64".to_string());
            d.details = vec!["packageand(clang21:binutils)".to_string()];
            d
        });
        f.add_info({
            let mut d = finding("no-soname", Level::Warning, 0);
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
            f.get_description("uncompressed-zip", &c),
            "The zip file is not compressed.\n\n"
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
                badness: 0,
                pkg_name: "pkg".to_string(),
                arch: Some("src".to_string()),
                line: None,
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
        f.add_info(finding("non-standard-dir-in-usr", Level::Warning, 0));
        f.add_info(finding("non-standard-dir-in-var", Level::Warning, 0));
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
}
