//! `BuildRootAndDateCheck` — build-root and current-date traces in files.
//!
//! Ported from `rpmlint/checks/BuildRootAndDateCheck.py`. Three findings:
//! `file-contains-date-and-time` (W), `file-contains-current-date` (W),
//! `file-contains-buildroot` (E).

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::is_reg;

pub struct BuildRootAndDateCheck {
    looksliketime: Regex,
    istoday: Regex,
    lookslikebuildroot: Regex,
}

/// Today's date in the reference's `time.strftime('%b %e %Y')` shape,
/// e.g. `Oct  2 2026` (day space-padded to width 2).
fn today_string() -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // Days since the Unix epoch -> civil date (Howard Hinnant's algorithm).
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86400)
        .unwrap_or(0) as i64;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{} {:2} {}", MONTHS[(m - 1) as usize], d, y)
}

/// The reference's `prepare_regex`: `%{name}`/`%{version}`/`%{release}`
/// (either case) stand for a 1-20 character name/version/release token.
fn buildroot_regex(buildroot: &str) -> Regex {
    let mut pattern = buildroot.to_string();
    for m in ["name", "version", "release", "NAME", "VERSION", "RELEASE"] {
        pattern = pattern.replace(&format!("%{{{m}}}"), r"[\w\!-\.]{1,20}");
    }
    Regex::new(&pattern).expect("buildroot pattern")
}

impl BuildRootAndDateCheck {
    pub fn new(_config: &Config) -> Self {
        // `rpm.expandMacro('%{?buildroot}')`, empty on rpm >= 4.20 — then the
        // reference falls back to the literal macro-laden path template.
        let _ = crate::pkg::init();
        let macros = librpm::macro_context::MacroContext::default();
        let buildroot = macros.expand("%{?buildroot}").unwrap_or_default();
        let buildroot = if buildroot.is_empty() {
            "/%{NAME}-%{VERSION}-build/BUILDROOT/".to_string()
        } else {
            buildroot
        };
        Self {
            looksliketime: Regex::new(r"(2[0-3]|[01]?[0-9]):([0-5]?[0-9]):([0-5]?[0-9])")
                .expect("static"),
            istoday: Regex::new(&today_string()).expect("static"),
            lookslikebuildroot: buildroot_regex(&buildroot),
        }
    }
}

impl Check for BuildRootAndDateCheck {
    fn name(&self) -> &'static str {
        "BuildRootAndDateCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        // `check_binary` only runs for non-source packages, which subsumes
        // the reference's `pkg.is_source` skip.
        for f in &pkg.files {
            let filename = &f.name;
            if filename.starts_with("/usr/lib/debug") || !is_reg(f.mode) {
                continue;
            }
            let data = pkg.read_file(filename);
            if is_match(&self.istoday, &data) {
                if is_match(&self.looksliketime, &data) {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "file-contains-date-and-time",
                        &[filename],
                    );
                } else {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "file-contains-current-date",
                        &[filename],
                    );
                }
            }
            if is_match(&self.lookslikebuildroot, &data) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "file-contains-buildroot",
                    &[filename],
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn today_string_shape() {
        // `%b %e %Y`: month abbrev, space-padded day, year.
        let today = today_string();
        let re = Regex::new(r"^[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{4}$").unwrap();
        assert!(is_match(&re, &today), "{today}");
    }

    #[test]
    fn buildroot_regex_expands_placeholders() {
        let re = buildroot_regex("/%{NAME}-%{VERSION}-build/BUILDROOT/");
        assert!(is_match(&re, "/foo-1.2-build/BUILDROOT/"));
        assert!(!is_match(&re, "/usr/lib/foo"));
    }
}
