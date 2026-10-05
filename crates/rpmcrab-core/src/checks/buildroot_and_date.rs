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

/// The reference's `time.strftime('%b %e %Y')` shape, e.g. `Oct  2 2026`
/// (day space-padded to width 2). Pure: takes the datetime so tests can pin
/// fixed dates without depending on the machine clock. `%b` under the C
/// locale is the English abbreviations (verified against the reference), so
/// the names are hardcoded rather than locale-derived.
fn format_date(dt: time::OffsetDateTime) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{} {:2} {}",
        MONTHS[dt.month() as usize - 1],
        dt.day(),
        dt.year()
    )
}

/// Today's date as the reference sees it: local time, like `time.strftime`.
/// Falls back to UTC when the local offset cannot be determined, mirroring
/// glibc `localtime` with no usable TZ. In-process via libc — no subprocess.
fn today_string() -> String {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    format_date(now)
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
        Self::with_buildroot(&buildroot)
    }

    /// The macro expansion is platform-dependent (empty on rpm >= 4.20,
    /// the ambient buildroot otherwise), so tests pin it via this seam.
    fn with_buildroot(buildroot: &str) -> Self {
        Self {
            looksliketime: Regex::new(r"(2[0-3]|[01]?[0-9]):([0-5]?[0-9]):([0-5]?[0-9])")
                .expect("static"),
            istoday: Regex::new(&today_string()).expect("static"),
            lookslikebuildroot: buildroot_regex(buildroot),
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
            // AbstractCheck.py:45 drops ghosts before check_file dispatches.
            if pkg.ghost_files.iter().any(|g| g == filename) {
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
// Emission-path tests: each drives check_binary via findings_for_content
// and pins finding name, level, and detail.
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
    fn format_date_pins_strftime_shape() {
        use time::{Date, Month, OffsetDateTime, Time, UtcOffset};
        let dt = |y: i32, m: Month, d: u8| {
            OffsetDateTime::new_utc(Date::from_calendar_date(y, m, d).unwrap(), Time::MIDNIGHT)
        };
        // `%e`: single-digit day is space-padded, not zero-padded.
        assert_eq!(format_date(dt(2026, Month::October, 3)), "Oct  3 2026");
        assert_eq!(format_date(dt(2026, Month::October, 26)), "Oct 26 2026");
        // `%b` under the C locale: all twelve English abbreviations.
        let months = [
            (Month::January, "Jan"),
            (Month::February, "Feb"),
            (Month::March, "Mar"),
            (Month::April, "Apr"),
            (Month::May, "May"),
            (Month::June, "Jun"),
            (Month::July, "Jul"),
            (Month::August, "Aug"),
            (Month::September, "Sep"),
            (Month::October, "Oct"),
            (Month::November, "Nov"),
            (Month::December, "Dec"),
        ];
        for (m, abbrev) in months {
            assert_eq!(format_date(dt(2026, m, 15)), format!("{abbrev} 15 2026"));
        }
        // A day-crossing offset shifts the rendered civil date: 01:00 UTC is
        // still Oct 4 in UTC but already Oct 3 at UTC-2. This pins that
        // `format_date` renders the offset's civil date, not UTC's.
        let instant = OffsetDateTime::new_utc(
            Date::from_calendar_date(2026, Month::October, 4).unwrap(),
            Time::from_hms(1, 0, 0).unwrap(),
        );
        let minus2 = UtcOffset::from_hms(-2, 0, 0).unwrap();
        assert_eq!(format_date(instant), "Oct  4 2026");
        assert_eq!(format_date(instant.to_offset(minus2)), "Oct  3 2026");
    }

    /// `today_string()` follows the local timezone, not UTC. At any instant,
    /// at least one of UTC+14 / UTC-12 lands on a different civil date than
    /// UTC, so probing under the offset that straddles midnight *right now*
    /// deterministically discriminates `now_local()` from `now_utc()`:
    /// reverting to UTC fails this test at any time of day. The probe
    /// re-executes this test binary in a child process with a controlled `TZ`
    /// because `TZ` is process-global and in-process mutation is unavailable
    /// (`std::env::set_var` is `unsafe` in edition 2024; this crate forbids
    /// `unsafe` outright).
    #[test]
    fn today_string_follows_local_timezone() {
        use std::process::Command;
        use time::{OffsetDateTime, UtcOffset};

        // Child mode: print `today_string()` for the parent to read. The
        // value must be exactly "1": merely being set (e.g. a stray export in
        // the ambient environment) must not divert the parent into the child
        // path, where the test would pass trivially.
        if std::env::var("RPMCRAB_TZ_PROBE_CHILD").as_deref() == Ok("1") {
            // Fail loudly when the zone does not resolve: without tzdata
            // `now_local()` silently falls back to UTC, and the date
            // comparison below would then fail exactly like a genuine
            // now_local()/now_utc() regression. Asserting the resolved
            // offset matches the offset the parent requested keeps the
            // two failure modes distinguishable.
            let expected_secs: i32 = std::env::var("RPMCRAB_TZ_PROBE_OFFSET_SECS")
                .expect("parent must pass RPMCRAB_TZ_PROBE_OFFSET_SECS")
                .parse()
                .expect("offset seconds must be an integer");
            let resolved = OffsetDateTime::now_local()
                .expect("now_local() failed outright")
                .offset();
            assert_eq!(
                resolved.whole_seconds(),
                expected_secs,
                "TZ={:?} did not resolve to the requested offset; tzdata may be missing",
                std::env::var("TZ").unwrap_or_default()
            );
            println!("RPMCRAB-TODAY: {}", today_string());
            return;
        }

        // A stray `RPMCRAB_TZ_PROBE_CHILD` in the ambient environment would
        // otherwise make the parent take the child path above and pass
        // trivially. Fail loudly instead.
        assert!(
            std::env::var("RPMCRAB_TZ_PROBE_CHILD").is_err(),
            "RPMCRAB_TZ_PROBE_CHILD must not be set in the ambient environment"
        );
        let now = OffsetDateTime::now_utc();
        // NB: POSIX inverts the sign — `Etc/GMT-14` is UTC+14.
        let (tz_name, offset) =
            if now.to_offset(UtcOffset::from_hms(14, 0, 0).unwrap()).date() != now.date() {
                ("Etc/GMT-14", UtcOffset::from_hms(14, 0, 0).unwrap())
            } else {
                ("Etc/GMT+12", UtcOffset::from_hms(-12, 0, 0).unwrap())
            };
        // `module_path!()` carries the crate name (`rpmcrab_core::...`) which
        // the test harness omits from test names; strip it so a module rename
        // or move keeps the child filter in sync instead of silently matching
        // zero tests.
        let module = module_path!();
        let test_path = module
            .split_once("::")
            .map(|(_, rest)| rest)
            .unwrap_or(module);
        let out = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!("{test_path}::today_string_follows_local_timezone"))
            .arg("--nocapture")
            .env("RPMCRAB_TZ_PROBE_CHILD", "1")
            .env(
                "RPMCRAB_TZ_PROBE_OFFSET_SECS",
                offset.whole_seconds().to_string(),
            )
            .env("TZ", tz_name)
            .output()
            .expect("spawn tz probe");
        assert!(out.status.success(), "tz probe failed: {out:?}");
        let actual = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("RPMCRAB-TODAY: "))
            .expect("probe printed no date line")
            .trim()
            .to_string();
        let expected = format_date(OffsetDateTime::now_utc().to_offset(offset));
        // The chosen offset genuinely crosses a day boundary right now, so the
        // expectation differs from the UTC date by construction.
        assert_ne!(
            format_date(now),
            expected,
            "test setup must straddle midnight"
        );
        assert_eq!(actual, expected, "today_string() under TZ={tz_name}");
    }

    #[test]
    fn buildroot_regex_expands_placeholders() {
        let re = buildroot_regex("/%{NAME}-%{VERSION}-build/BUILDROOT/");
        assert!(is_match(&re, "/foo-1.2-build/BUILDROOT/"));
        assert!(!is_match(&re, "/usr/lib/foo"));
    }
    use crate::color::Color;
    use crate::pkg::pkgfile::PkgFile;
    use std::path::Path;

    /// Drive `check_binary` with a synthetic file on disk, returning findings.
    fn findings_for_content(name: &str, content: &str) -> Vec<(String, String)> {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        // The extraction base dir: PkgFile.path is normpath(dir + "/" + name).
        let first = &pkg.files[0];
        let base = first
            .path
            .strip_suffix(first.name.trim_start_matches('/'))
            .expect("base dir")
            .trim_end_matches('/');
        let disk_path = format!("{base}{name}");
        std::fs::create_dir_all(Path::new(&disk_path).parent().unwrap()).expect("mkdirs");
        std::fs::write(&disk_path, content).expect("write test file");
        pkg.files = vec![PkgFile {
            name: name.to_string(),
            path: disk_path,
            mode: 0o100644,
            ..Default::default()
        }];
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check =
            BuildRootAndDateCheck::with_buildroot("/%{NAME}-%{VERSION}-build/BUILDROOT/");
        check.check_binary(&pkg, &config, &mut out);
        out.results().to_vec()
    }

    /// Today's date plus a time triggers `file-contains-date-and-time` (W).
    #[test]
    fn today_with_time_is_flagged() {
        let content = format!("built {} at 14:30:00", today_string());
        let results = findings_for_content("/usr/bin/with-time", &content);
        assert_eq!(results.len(), 1, "unexpected: {results:?}");
        assert_eq!(results[0].0, "file-contains-date-and-time");
        assert!(results[0].1.contains(": W: "), "level: {}", results[0].1);
        assert!(
            results[0].1.contains("/usr/bin/with-time"),
            "detail: {}",
            results[0].1
        );
    }

    /// Today's date without a time triggers `file-contains-current-date` (W).
    #[test]
    fn today_without_time_is_flagged() {
        let content = format!("built {}", today_string());
        let results = findings_for_content("/usr/bin/with-date", &content);
        assert_eq!(results.len(), 1, "unexpected: {results:?}");
        assert_eq!(results[0].0, "file-contains-current-date");
        assert!(results[0].1.contains(": W: "), "level: {}", results[0].1);
    }

    /// A buildroot path triggers `file-contains-buildroot` (E).
    #[test]
    fn buildroot_path_is_flagged() {
        let results = findings_for_content(
            "/usr/bin/with-buildroot",
            "prefix=/foo-1.2-build/BUILDROOT/usr",
        );
        assert_eq!(results.len(), 1, "unexpected: {results:?}");
        assert_eq!(results[0].0, "file-contains-buildroot");
        assert!(results[0].1.contains(": E: "), "level: {}", results[0].1);
    }
}
