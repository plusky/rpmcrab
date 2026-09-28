//! The session header, footer and abort banner — the parts of the wire format
//! that are grepped verbatim by build tooling (`docs/DESIGN.md` §4.5).

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
pub fn abort_banner(score: u64, threshold: i64, color: &Color, width: usize) -> String {
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
    score: u64,
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
}
