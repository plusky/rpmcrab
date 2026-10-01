//! The session header, footer and abort banner — the parts of the wire format
//! that are grepped verbatim by build tooling (`docs/DESIGN.md` §4.5).

use std::collections::BTreeMap;

use crate::color::Color;
use crate::term::string_center;

/// The parameters for the session [`header`], bundled so the call reads
/// without the eight-argument sprawl.
pub struct HeaderParams<'a> {
    pub prog: &'a str,
    pub version: &'a str,
    pub conf_files: &'a [String],
    pub rpmlintrc: &'a [String],
    pub no_checks: usize,
    pub no_packages: usize,
    pub color: &'a Color,
    pub width: usize,
}

/// The session header block (terminated by a blank line).
pub fn header(params: &HeaderParams) -> String {
    let &HeaderParams {
        prog,
        version,
        conf_files,
        rpmlintrc,
        no_checks,
        no_packages,
        color,
        width,
    } = params;
    let mut out = String::new();
    out.push_str(&format!(
        "{}{}{}\n",
        color.bold,
        string_center(&format!("{prog} session starts"), '=', width),
        color.reset
    ));
    out.push_str(&format!("{prog}: {version}\n"));
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

/// The parameters for the session [`footer`].
pub struct FooterParams<'a> {
    pub packages: usize,
    pub specfiles: usize,
    pub errors: u64,
    pub warnings: u64,
    pub filtered: u64,
    pub score: i64,
    pub duration_secs: f64,
    pub aborted: bool,
    pub color: &'a Color,
    pub width: usize,
}

/// The footer rule. Colour is bold by default, yellow if any warning, red on
/// abort. `I:` findings are counted nowhere.
pub fn footer(params: &FooterParams) -> String {
    let &FooterParams {
        packages,
        specfiles,
        errors,
        warnings,
        filtered,
        score,
        duration_secs,
        aborted,
        color,
        width,
    } = params;
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
/// `durations` must be in insertion order: the reference sorts by duration and
/// its dict preserves insertion order for equal values, so the sort is stable
/// over the order the phases and checks first ran.
pub fn time_report(
    durations: &[(String, f64)],
    checked_files: &BTreeMap<String, usize>,
    color: &Color,
) -> String {
    const PERCENT_THRESHOLD: f64 = 1.0;
    const TIME_THRESHOLD: f64 = 0.1;
    let total: f64 = durations.iter().map(|(_, v)| *v).sum();
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

    // Sorted by duration, longest first. The sort is stable, so equal durations
    // keep the order they first ran in, as the reference's dict does.
    let mut rows: Vec<(&str, f64)> = durations.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    rows.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    for (check, duration) in rows {
        let fraction = if total > 0.0 {
            100.0 * duration / total
        } else {
            0.0
        };
        if fraction < PERCENT_THRESHOLD || duration < TIME_THRESHOLD {
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
        let color = Color::for_tty(false);
        let f = footer(&FooterParams {
            packages: 1,
            specfiles: 0,
            errors: 2,
            warnings: 1,
            filtered: 1,
            score: 2,
            duration_secs: 0.1,
            aborted: false,
            color: &color,
            width: 80,
        });
        assert_eq!(
            f,
            " 1 packages and 0 specfiles checked; 2 errors, 1 warnings, 1 filtered, 2 badness; has taken 0.1 s \n"
        );
    }

    /// The durations in the order the given pairs name them, which is the
    /// insertion order the report preserves for ties.
    fn durations(pairs: &[(&str, f64)]) -> Vec<(String, f64)> {
        pairs.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()
    }

    /// Equal durations report in insertion order, not alphabetically: the
    /// reference's `check_duration` is a dict, and its sort is stable.
    #[test]
    fn time_report_breaks_ties_by_insertion_order() {
        let out = time_report(
            &durations(&[("ZebraCheck", 1.0), ("AlphaCheck", 1.0)]),
            &BTreeMap::new(),
            &Color::for_tty(false),
        );
        let zebra = out.find("ZebraCheck").expect("row");
        let alpha = out.find("AlphaCheck").expect("row");
        assert!(zebra < alpha, "insertion order lost:\n{out}");
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
    fn padding_matches_python_format() {
        assert_eq!(pad_right("Check", 32), format!("{:<32}", "Check"));
        assert_eq!(pad_left("x", 5), "    x");
        // Over-long input is never truncated, matching Python's format().
        assert_eq!(pad_right("abcdef", 3), "abcdef");
    }
}
