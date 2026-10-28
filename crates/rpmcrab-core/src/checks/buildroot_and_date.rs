//! `BuildRootAndDateCheck` — build-root and current-date traces in files.
//!
//! Ported from `rpmlint/checks/BuildRootAndDateCheck.py`. Three findings:
//! `file-contains-date-and-time` (W), `file-contains-current-date` (W),
//! `file-contains-buildroot` (E). The run day is computed in UTC, and a
//! stamp that is the package's own SOURCE_DATE_EPOCH is reproducible and
//! not reported (issue #1180; SDE sourcing in
//! `crate::checks::shared::source_date_epoch`).

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
    today: time::Date,
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

/// The SDE stamp a file may legitimately carry: SDE's date in the
/// reference's `%b %e %Y` shape, whitespace, then SDE's `HH:MM:SS` (UTC) —
/// the shape `date '+%b %e %Y %T'` and `__DATE__ " " __TIME__` produce.
fn sde_stamp_regex(sde: time::OffsetDateTime) -> Regex {
    Regex::new(&format!(
        r"{}\s+{:02}:{:02}:{:02}",
        fancy_regex::escape(&format_date(sde)),
        sde.hour(),
        sde.minute(),
        sde.second()
    ))
    .expect("static")
}

/// `data` with every match of `re` removed. Used to take the package's
/// own SOURCE_DATE_EPOCH stamps out of a file before the date findings
/// judge what remains.
fn without_matches(data: &str, re: &Regex) -> String {
    let mut out = String::with_capacity(data.len());
    let mut last = 0;
    for m in re.find_iter(data).filter_map(|r| r.ok()) {
        out.push_str(&data[last..m.start()]);
        last = m.end();
    }
    out.push_str(&data[last..]);
    out
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
        let _macro_guard = crate::pkg::global_macro_lock();
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
        Self::with_datetime(buildroot, time::OffsetDateTime::now_utc())
    }

    /// The run instant is a test seam alongside `with_buildroot`: the
    /// SOURCE_DATE_EPOCH reproducer tests pin the run day instead of
    /// depending on the machine clock.
    fn with_datetime(buildroot: &str, now: time::OffsetDateTime) -> Self {
        Self {
            looksliketime: Regex::new(r"(2[0-3]|[01]?[0-9]):([0-5]?[0-9]):([0-5]?[0-9])")
                .expect("static"),
            istoday: Regex::new(&format_date(now)).expect("static"),
            today: now.date(),
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
        let sde = crate::checks::shared::source_date_epoch(pkg);
        self.check_files(pkg, out, sde);
    }
}

impl BuildRootAndDateCheck {
    /// The per-file scan, with the package's SOURCE_DATE_EPOCH resolved
    /// by the caller: an emission seam so tests can pin both the run day
    /// (via `with_datetime`) and SDE without crafting a package header.
    fn check_files(&self, pkg: &Pkg, out: &mut Filter, sde: Option<time::OffsetDateTime>) {
        // The exemption can only bite when a stamp carrying SDE's date
        // can be the run-day match at all: SDE's UTC day is the run day.
        let sde_stamp = sde.filter(|s| s.date() == self.today).map(sde_stamp_regex);
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
                // Take the package's own SDE stamps out before judging
                // what remains: they are reproducible by construction.
                // The rest is judged by the reference's rule unchanged.
                let stripped;
                let judged = match &sde_stamp {
                    Some(re) => {
                        stripped = without_matches(&data, re);
                        &stripped
                    }
                    None => &data,
                };
                if is_match(&self.istoday, judged) && is_match(&self.looksliketime, judged) {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "file-contains-date-and-time",
                        &[filename],
                    );
                } else if sde_stamp.is_none() && is_match(&self.istoday, judged) {
                    // `file-contains-current-date` stays silent on SDE's
                    // own day: a date-only stamp from a build that ran
                    // that day cannot be told apart from an SDE one
                    // (issue #1180 accepts this trade-off explicitly).
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
    fn run_day_shape() {
        // `%b %e %Y`: month abbrev, space-padded day, year.
        let check = BuildRootAndDateCheck::with_buildroot("/%{NAME}-%{VERSION}-build/BUILDROOT/");
        let today = format_date(check.today.with_time(time::Time::MIDNIGHT).assume_utc());
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

    /// The run day a check is constructed with is the UTC date
    /// regardless of the local timezone (issue #1180). At any instant,
    /// at least one of UTC+14 /
    /// UTC-12 lands on a different civil date than UTC, so probing under
    /// the offset that straddles midnight *right now* deterministically
    /// discriminates `now_utc()` from `now_local()`: reverting to local
    /// time fails this test at any time of day. The probe re-executes
    /// this test binary in a child process with a controlled `TZ`
    /// because `TZ` is process-global and in-process mutation is
    /// unavailable (`std::env::set_var` is `unsafe` in edition 2024;
    /// this crate forbids `unsafe` outright).
    #[test]
    fn run_day_uses_utc() {
        use std::process::Command;
        use time::{OffsetDateTime, UtcOffset};

        // Child mode: print the constructed check's run day for the
        // parent to read. The
        // value must be exactly "1": merely being set (e.g. a stray export
        // in the ambient environment) must not divert the parent into the
        // child path, where the test would pass trivially.
        if std::env::var("RPMCRAB_TZ_PROBE_CHILD").as_deref() == Ok("1") {
            // Fail loudly when the zone does not resolve: without tzdata
            // `now_local()` silently falls back to UTC, and the date
            // comparison below would then fail exactly like a genuine
            // now_utc()/now_local() mix-up. Asserting the resolved offset
            // matches the offset the parent requested keeps the two
            // failure modes distinguishable. (`now_local()` serves only
            // as the zone-resolution probe, never as the value under
            // test.)
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
                "TZ={:?} did not resolve to the requested offset",
                std::env::var("TZ").unwrap_or_default()
            );
            let check =
                BuildRootAndDateCheck::with_buildroot("/%{NAME}-%{VERSION}-build/BUILDROOT/");
            println!(
                "RPMCRAB-TODAY: {}",
                format_date(check.today.with_time(time::Time::MIDNIGHT).assume_utc())
            );
            return;
        }

        // A stray `RPMCRAB_TZ_PROBE_CHILD` in the ambient environment
        // would otherwise make the parent take the child path above and
        // pass trivially. Fail loudly instead.
        assert!(
            std::env::var("RPMCRAB_TZ_PROBE_CHILD").is_err(),
            "RPMCRAB_TZ_PROBE_CHILD must not be set in the ambient environment"
        );
        let now = OffsetDateTime::now_utc();
        // POSIX TZ strings are parsed straight from the value — no
        // tzdata files involved — so the probe also works in minimal
        // buildroots. NB: POSIX inverts the sign: `<+14>-14` is UTC+14.
        let (tz_name, offset) =
            if now.to_offset(UtcOffset::from_hms(14, 0, 0).unwrap()).date() != now.date() {
                ("<+14>-14", UtcOffset::from_hms(14, 0, 0).unwrap())
            } else {
                ("<+12>+12", UtcOffset::from_hms(-12, 0, 0).unwrap())
            };
        // `module_path!()` carries the crate name (`rpmcrab_core::...`)
        // which the test harness omits from test names; strip it so a
        // module rename or move keeps the child filter in sync instead
        // of silently matching zero tests.
        let module = module_path!();
        let test_path = module
            .split_once("::")
            .map(|(_, rest)| rest)
            .unwrap_or(module);
        let out = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!("{test_path}::run_day_uses_utc"))
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
        let expected = format_date(now);
        // The chosen offset genuinely crosses a day boundary right now,
        // so the local date at that offset differs from the UTC date by
        // construction: matching the UTC expectation proves the source.
        assert_ne!(
            format_date(now.to_offset(offset)),
            expected,
            "test setup must straddle midnight"
        );
        assert_eq!(actual, expected, "run day under TZ={tz_name}");
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
    use time::{Month, OffsetDateTime};

    /// Drive the scan with a synthetic file on disk, at the real run
    /// instant and with no SOURCE_DATE_EPOCH in effect.
    fn findings_for_content(name: &str, content: &str) -> Vec<(String, String)> {
        findings_pinned(name, content, OffsetDateTime::now_utc(), None)
    }

    /// Drive the scan with a synthetic file on disk, returning findings,
    /// with the run instant and the package's SOURCE_DATE_EPOCH pinned.
    fn findings_pinned(
        name: &str,
        content: &str,
        now: OffsetDateTime,
        sde: Option<OffsetDateTime>,
    ) -> Vec<(String, String)> {
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
        let check =
            BuildRootAndDateCheck::with_datetime("/%{NAME}-%{VERSION}-build/BUILDROOT/", now);
        check.check_files(&pkg, &mut out, sde);
        out.results().to_vec()
    }

    /// Today's date plus a time triggers `file-contains-date-and-time` (W).
    #[test]
    fn today_with_time_is_flagged() {
        let content = format!(
            "built {} at 14:30:00",
            format_date(OffsetDateTime::now_utc())
        );
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
        let content = format!("built {}", format_date(OffsetDateTime::now_utc()));
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

    /// A pinned UTC instant for the SOURCE_DATE_EPOCH tests.
    fn utc_dt(y: i32, m: Month, d: u8, h: u8, min: u8, s: u8) -> OffsetDateTime {
        use time::{Date, Time};
        OffsetDateTime::new_utc(
            Date::from_calendar_date(y, m, d).unwrap(),
            Time::from_hms(h, min, s).unwrap(),
        )
    }

    /// Issue #1180's reproducer, first row: the build ran on SDE's day
    /// (SDE 2026-10-28 09:30:00 UTC). The SDE stamp is reproducible and
    /// silent; the wall-clock stamp in the sibling file fires (W).
    #[test]
    fn sde_reproducer_same_day() {
        let now = utc_dt(2026, Month::October, 28, 12, 0, 0);
        let sde = utc_dt(2026, Month::October, 28, 9, 30, 0);
        let results = findings_pinned(
            "/usr/share/rbdate/sde.txt",
            "built Oct 28 2026 09:30:00\n",
            now,
            Some(sde),
        );
        assert!(results.is_empty(), "unexpected: {results:?}");
        let results = findings_pinned(
            "/usr/share/rbdate/wall.txt",
            "built Oct 28 2026 07:56:10\n",
            now,
            Some(sde),
        );
        assert_eq!(results.len(), 1, "unexpected: {results:?}");
        assert_eq!(results[0].0, "file-contains-date-and-time");
        assert!(results[0].1.contains(": W: "), "level: {}", results[0].1);
    }

    /// Issue #1180's reproducer, second row: SDE is an older day
    /// (2026-10-19 09:30:00 UTC), the build ran on 2026-10-28. The SDE
    /// stamp carries a date that never matches the run day; the
    /// wall-clock stamp on the run day fires (W).
    #[test]
    fn sde_reproducer_older_sde() {
        let now = utc_dt(2026, Month::October, 28, 12, 0, 0);
        let sde = utc_dt(2026, Month::October, 19, 9, 30, 0);
        let results = findings_pinned(
            "/usr/share/rbdate/sde.txt",
            "built Oct 19 2026 09:30:00\n",
            now,
            Some(sde),
        );
        assert!(results.is_empty(), "unexpected: {results:?}");
        let results = findings_pinned(
            "/usr/share/rbdate/wall.txt",
            "built Oct 28 2026 07:56:38\n",
            now,
            Some(sde),
        );
        assert_eq!(results.len(), 1, "unexpected: {results:?}");
        assert_eq!(results[0].0, "file-contains-date-and-time");
        assert!(results[0].1.contains(": W: "), "level: {}", results[0].1);
    }

    /// Near miss: an SDE stamp does not shield a wall-clock stamp in the
    /// same file — removing the SDE stamp leaves the other one judged.
    #[test]
    fn sde_stamp_does_not_shield_wall_stamp() {
        let now = utc_dt(2026, Month::October, 28, 12, 0, 0);
        let sde = utc_dt(2026, Month::October, 28, 9, 30, 0);
        let results = findings_pinned(
            "/usr/share/rbdate/both.txt",
            "built Oct 28 2026 09:30:00, rebuilt Oct 28 2026 07:56:10\n",
            now,
            Some(sde),
        );
        assert_eq!(results.len(), 1, "unexpected: {results:?}");
        assert_eq!(results[0].0, "file-contains-date-and-time");
    }

    /// Near miss: the exemption needs the time next to the date. A file
    /// whose only time is SDE's but not adjacent to the date carries no
    /// SDE stamp, so the unmodified rule fires.
    #[test]
    fn sde_time_not_adjacent_still_fires() {
        let now = utc_dt(2026, Month::October, 28, 12, 0, 0);
        let sde = utc_dt(2026, Month::October, 28, 9, 30, 0);
        let results = findings_pinned(
            "/usr/share/rbdate/prose.txt",
            "built Oct 28 2026, finished at 09:30:00\n",
            now,
            Some(sde),
        );
        assert_eq!(results.len(), 1, "unexpected: {results:?}");
        assert_eq!(results[0].0, "file-contains-date-and-time");
    }

    /// Near miss: the stamp's order is date-then-time. A reversed pair is
    /// not the SDE stamp and fires.
    #[test]
    fn reversed_stamp_still_fires() {
        let now = utc_dt(2026, Month::October, 28, 12, 0, 0);
        let sde = utc_dt(2026, Month::October, 28, 9, 30, 0);
        let results = findings_pinned(
            "/usr/share/rbdate/reversed.txt",
            "built 09:30:00 Oct 28 2026\n",
            now,
            Some(sde),
        );
        assert_eq!(results.len(), 1, "unexpected: {results:?}");
        assert_eq!(results[0].0, "file-contains-date-and-time");
    }

    /// Near miss: the exemption covers the whole stamp, date included.
    /// A wall-clock stamp on the run day that happens to carry SDE's
    /// time-of-day is not SDE's stamp (its date is not SDE's) and fires.
    #[test]
    fn sde_time_of_day_on_run_day_still_fires() {
        let now = utc_dt(2026, Month::October, 28, 12, 0, 0);
        let sde = utc_dt(2026, Month::October, 19, 9, 30, 0);
        let results = findings_pinned(
            "/usr/share/rbdate/coincidence.txt",
            "built Oct 28 2026 09:30:00\n",
            now,
            Some(sde),
        );
        assert_eq!(results.len(), 1, "unexpected: {results:?}");
        assert_eq!(results[0].0, "file-contains-date-and-time");
    }

    /// The `file-contains-current-date` silence is bounded to SDE's own
    /// day: a date-only file is silent then, and fires (W) when SDE is
    /// any other day.
    #[test]
    fn current_date_silence_is_sde_day_only() {
        let now = utc_dt(2026, Month::October, 28, 12, 0, 0);
        let same_day = utc_dt(2026, Month::October, 28, 9, 30, 0);
        let results = findings_pinned(
            "/usr/share/rbdate/date-only.txt",
            "built Oct 28 2026\n",
            now,
            Some(same_day),
        );
        assert!(results.is_empty(), "unexpected: {results:?}");
        let older = utc_dt(2026, Month::October, 19, 9, 30, 0);
        let results = findings_pinned(
            "/usr/share/rbdate/date-only.txt",
            "built Oct 28 2026\n",
            now,
            Some(older),
        );
        assert_eq!(results.len(), 1, "unexpected: {results:?}");
        assert_eq!(results[0].0, "file-contains-current-date");
        assert!(results[0].1.contains(": W: "), "level: {}", results[0].1);
    }

    /// Boundary: an SDE stamp at exactly midnight is still the stamp.
    #[test]
    fn sde_stamp_at_midnight_is_silent() {
        let now = utc_dt(2026, Month::October, 28, 12, 0, 0);
        let sde = utc_dt(2026, Month::October, 28, 0, 0, 0);
        let results = findings_pinned(
            "/usr/share/rbdate/midnight.txt",
            "built Oct 28 2026 00:00:00\n",
            now,
            Some(sde),
        );
        assert!(results.is_empty(), "unexpected: {results:?}");
    }
}
