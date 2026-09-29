//! The session header, footer and abort banner — the parts of the wire format
//! that are grepped verbatim by build tooling (`docs/DESIGN.md` §4.5).

use std::collections::BTreeMap;

use crate::color::Color;
use crate::term::string_center;

/// The session header block (terminated by a blank line).
pub fn header(
    version: &str,
    conf_files: &[String],
    rpmlintrc: &[String],
    no_checks: usize,
    no_packages: usize,
    color: &Color,
    width: usize,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}{}{}\n",
        color.bold,
        string_center("rpmlint session starts", '=', width),
        color.reset
    ));
    out.push_str(&format!("rpmlint: {version}\n"));
    out.push_str("configuration:\n");
    for cf in conf_files {
        out.push_str(&format!("    {cf}\n"));
    }
    if !rpmlintrc.is_empty() {
        out.push_str("rpmlintrc:\n");
        for rc in rpmlintrc {
            out.push_str(&format!("    {rc}\n"));
        }
    }
    out.push_str(&format!(
        "{}checks: {no_checks}, packages: {no_packages}{}\n",
        color.bold, color.reset
    ));
    out.push('\n');
    out
}

/// The abort banner, printed (in red) before the time report when the badness
/// score exceeds the threshold. Grepped verbatim by build tooling.
pub fn abort_banner(score: i64, threshold: i64, color: &Color, width: usize) -> String {
    let msg = format!("Badness {score} exceeds threshold {threshold}, aborting.");
    format!(
        "{}{}{}\n",
        color.red,
        string_center(&msg, '-', width),
        color.reset
    )
}

/// The footer rule. Colour is bold by default, yellow if any warning, red on
/// abort. `I:` findings are counted nowhere.
#[allow(clippy::too_many_arguments)]
pub fn footer(
    packages: usize,
    specfiles: usize,
    errors: u64,
    warnings: u64,
    filtered: u64,
    score: i64,
    duration_secs: f64,
    aborted: bool,
    color: &Color,
    width: usize,
) -> String {
    let quit_color = if aborted {
        color.red
    } else if warnings > 0 {
        color.yellow
    } else {
        color.bold
    };
    let msg = format!(
        "{packages} packages and {specfiles} specfiles checked; {errors} errors, {warnings} warnings, {filtered} filtered, {score} badness; has taken {duration_secs:.1} s"
    );
    format!(
        "{}{}{}\n",
        quit_color,
        string_center(&msg, '=', width),
        color.reset
    )
}

/// `-t`: the per-check time report (`lint.py` `_print_time_report`). Reproduces
/// the column widths and the >1% / >0.1s cut-off exactly, since the layout is
/// what a user reads.
pub fn time_report(
    durations: &BTreeMap<String, f64>,
    checked_files: &BTreeMap<String, usize>,
    color: &Color,
) -> String {
    const PERCENT_THRESHOLD: f64 = 1.0;
    const TIME_THRESHOLD: f64 = 0.1;
    let total: f64 = durations.values().sum();
    // Only checks that actually walked files contribute to the total count, and
    // the total is the maximum, not the sum: the same file is checked by
    // several checks.
    let total_checked = checked_files
        .values()
        .copied()
        .max()
        .map(|n| n.to_string())
        .unwrap_or_default();

    let mut out = String::new();
    out.push_str(&format!(
        "{bold}Check time report{reset} (>{PERCENT_THRESHOLD}% & >{TIME_THRESHOLD}s):\n",
        bold = color.bold,
        reset = color.reset
    ));
    out.push_str(&format!(
        "{bold}    {check} {duration} {fraction}  Checked files{reset}\n",
        bold = color.bold,
        check = pad_right("Check", 32),
        duration = "Duration (in s)",
        fraction = pad_left("Fraction (in %)", 17),
        reset = color.reset
    ));

    // Sorted by duration, longest first.
    let mut rows: Vec<(&String, &f64)> = durations.iter().collect();
    rows.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
    for (check, duration) in rows {
        let fraction = if total > 0.0 {
            100.0 * duration / total
        } else {
            0.0
        };
        if fraction < PERCENT_THRESHOLD || *duration < TIME_THRESHOLD {
            continue;
        }
        let pct_color = if fraction > 25.0 {
            color.red
        } else if fraction > 5.0 {
            color.yellow
        } else {
            ""
        };
        let files = checked_files
            .get(check)
            .map(|n| n.to_string())
            .unwrap_or_default();
        out.push_str(&format!(
            "    {check:32} {duration:15.1} {pct}{fraction:17.1}{reset} {files:>14}\n",
            pct = pct_color,
            reset = color.reset
        ));
    }

    out.push_str(&format!(
        "    {:32} {total:15.1} {hundred:17.1} {files:>14}\n",
        "TOTAL",
        hundred = 100.0f64,
        files = pad_left(&total_checked, 14)
    ));
    out
}

/// `-T`: rpmcrab's own per-check wall-time report. The reference prints CPython
/// `cProfile` output there, which a Rust port cannot reproduce; this is a
/// deliberate, clearly-labelled substitute (see `tests/parity/divergences.toml`).
pub fn profile_report(durations: &BTreeMap<String, f64>, color: &Color) -> String {
    let total: f64 = durations.values().sum();
    let mut out = String::new();
    out.push_str(&format!(
        "{bold}rpmcrab profile report{reset} (per-check wall time; not a CPython cProfile dump)\n",
        bold = color.bold,
        reset = color.reset
    ));
    let mut rows: Vec<(&String, &f64)> = durations.iter().collect();
    rows.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
    for (check, duration) in rows {
        out.push_str(&format!("    {check:32} {duration:15.6}\n"));
    }
    out.push_str(&format!("    {:32} {total:15.6}\n", "TOTAL"));
    out
}

/// Python's `format(s, '32s')`: pad right to `width`, never truncate.
fn pad_right(s: &str, width: usize) -> String {
    format!("{s:<width$}")
}

/// Python's `format(s, '>17')`: pad left to `width`, never truncate.
fn pad_left(s: &str, width: usize) -> String {
    format!("{s:>width$}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abort_banner_matches_captured() {
        // Captured from a real openSUSE run (liblto21, exit 66).
        let b = abort_banner(10000, 999, &Color::for_tty(false), 80);
        assert_eq!(
            b,
            "---------------- Badness 10000 exceeds threshold 999, aborting. ----------------\n"
        );
    }

    #[test]
    fn footer_matches_captured() {
        // Captured from a real run (llvm21-gold, exit 0).
        let f = footer(1, 0, 2, 1, 1, 2, 0.1, false, &Color::for_tty(false), 80);
        assert_eq!(
            f,
            " 1 packages and 0 specfiles checked; 2 errors, 1 warnings, 1 filtered, 2 badness; has taken 0.1 s \n"
        );
    }

    fn durations(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
        pairs.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()
    }

    #[test]
    fn time_report_header_and_total_match_the_reference_layout() {
        let out = time_report(
            &durations(&[("FilesCheck", 1.0), ("ExtractRpm", 0.0)]),
            &BTreeMap::new(),
            &Color::for_tty(false),
        );
        // ExtractRpm at 0.0s is below the time cut-off, so only FilesCheck shows.
        // The layout is verified column-for-column against a real
        // `rpmlint -t` run over tests/parity/cases/llvm21-gold.
        // The trailing run of spaces is part of the layout: the reference pads
        // the empty `Checked files` column to 14 even when a check walked no
        // files, so the row is a fixed width.
        assert_eq!(
            out,
            concat!(
                "Check time report (>1% & >0.1s):\n",
                "    Check                            Duration (in s)   Fraction (in %)  Checked files\n",
                "    FilesCheck                                   1.0             100.0",
                "               \n",
                "    TOTAL                                        1.0             100.0",
                "               \n",
            )
        );
    }

    #[test]
    fn time_report_drops_rows_under_the_thresholds() {
        // Two checks, one dominant: the small one is under 1% and is skipped.
        let out = time_report(
            &durations(&[("BigCheck", 100.0), ("TinyCheck", 0.2)]),
            &BTreeMap::new(),
            &Color::for_tty(false),
        );
        assert!(out.contains("BigCheck"));
        assert!(!out.contains("TinyCheck"));
    }

    #[test]
    fn time_report_lists_checked_files_and_maximises_the_total() {
        let mut files = BTreeMap::new();
        files.insert("FilesCheck".to_string(), 120usize);
        files.insert("OtherCheck".to_string(), 300usize);
        let out = time_report(
            &durations(&[("FilesCheck", 1.0), ("OtherCheck", 1.0)]),
            &files,
            &Color::for_tty(false),
        );
        // Per-row counts, then the maximum rather than the sum: the same file
        // is walked by several checks.
        let rows: Vec<&str> = out.lines().collect();
        assert_eq!(rows.len(), 5);
        assert_eq!(
            rows[2],
            "    FilesCheck                                   1.0              50.0            120"
        );
        assert_eq!(
            rows[3],
            "    OtherCheck                                   1.0              50.0            300"
        );
        assert_eq!(
            rows[4],
            "    TOTAL                                        2.0             100.0            300"
        );
    }

    #[test]
    fn profile_report_is_labelled_and_has_no_thresholds() {
        let out = profile_report(
            &durations(&[("FilesCheck", 1.0), ("TinyCheck", 0.000001)]),
            &Color::for_tty(false),
        );
        assert!(out.starts_with(
            "rpmcrab profile report (per-check wall time; not a CPython cProfile dump)\n"
        ));
        // Unlike -t, nothing is filtered out.
        assert!(out.contains("TinyCheck"));
        assert!(out.contains("    TOTAL                                   1.000001\n"));
    }

    #[test]
    fn padding_matches_python_format() {
        assert_eq!(pad_right("Check", 32), format!("{:<32}", "Check"));
        assert_eq!(pad_left("x", 5), "    x");
        // Over-long input is never truncated, matching Python's format().
        assert_eq!(pad_right("abcdef", 3), "abcdef");
    }
}
