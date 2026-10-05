//! `LSBCheck` — LSB-compliant package name, version and release.
//!
//! Ported from `rpmlint/checks/LSBCheck.py`. Three findings, all errors:
//! `non-lsb-compliant-package-name`, `non-lsb-compliant-version`,
//! `non-lsb-compliant-release`.
//!
//! The rules are the intersection of compatible NVRs between RPM v3 and DPKG,
//! for portability across RPM and Debian systems through tools like alien.

use fancy_regex::Regex;
use librpm::Tag;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::tags;
use std::sync::OnceLock;

static NAME_REGEX: OnceLock<Regex> = OnceLock::new();
fn name_regex() -> &'static Regex {
    NAME_REGEX.get_or_init(|| Regex::new(r"^[a-z0-9.+-]+$").expect("static regex"))
}

static VERSION_REGEX: OnceLock<Regex> = OnceLock::new();
fn version_regex() -> &'static Regex {
    VERSION_REGEX.get_or_init(|| Regex::new(r"^[a-zA-Z0-9.+]+$").expect("static regex"))
}

pub struct LSBCheck;

impl LSBCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// Pure core: `(finding, offending_value)` for each non-compliant field,
    /// in check order. Empty/absent fields are skipped, as in the reference.
    fn collect(
        name: &str,
        version: Option<&str>,
        release: Option<&str>,
    ) -> Vec<(&'static str, String)> {
        let name_re = name_regex();
        let version_re = version_regex();
        let mut out = Vec::new();
        if !name.is_empty() && !is_match(name_re, name) {
            out.push(("non-lsb-compliant-package-name", name.to_string()));
        }
        if let Some(v) = version
            && !v.is_empty()
            && !is_match(version_re, v)
        {
            out.push(("non-lsb-compliant-version", v.to_string()));
        }
        if let Some(r) = release
            && !r.is_empty()
            && !is_match(version_re, r)
        {
            out.push(("non-lsb-compliant-release", r.to_string()));
        }
        out
    }
}

impl Check for LSBCheck {
    fn name(&self) -> &'static str {
        "LSBCheck"
    }

    /// The reference overrides `check()`, not `check_binary()`, so this runs
    /// for source packages too.
    fn check(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let header = pkg.header();
        let version = tags::str_tag(header, Tag::VERSION);
        let release = tags::str_tag(header, Tag::RELEASE);
        for (check, value) in Self::collect(&pkg.name, version.as_deref(), release.as_deref()) {
            add_info(out, Level::Error, pkg, check, &[&value]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding_names<'a>(findings: &'a [(&'static str, String)]) -> Vec<&'a str> {
        findings.iter().map(|(n, _)| *n).collect()
    }

    #[test]
    fn compliant_nvr_is_quiet() {
        let findings = LSBCheck::collect("foo-bar+baz.qux", Some("1.2.3"), Some("4"));
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn bad_name_is_reported() {
        for name in ["Foo", "foo_bar", "foo bar", "föö"] {
            let findings = LSBCheck::collect(name, Some("1.0"), Some("1"));
            assert_eq!(
                finding_names(&findings),
                vec!["non-lsb-compliant-package-name"],
                "{name}"
            );
            assert_eq!(findings[0].1, name);
        }
    }

    #[test]
    fn bad_version_is_reported() {
        // `~`, `-` and `_` are not in the version alphabet.
        for version in ["1.0~rc1", "1.0-1", "1_0"] {
            let findings = LSBCheck::collect("foo", Some(version), Some("1"));
            assert_eq!(
                finding_names(&findings),
                vec!["non-lsb-compliant-version"],
                "{version}"
            );
        }
    }

    #[test]
    fn plus_in_version_is_allowed() {
        let findings = LSBCheck::collect("foo", Some("1.0+git"), Some("1"));
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn bad_release_is_reported() {
        let findings = LSBCheck::collect("foo", Some("1.0"), Some("1_2"));
        assert_eq!(finding_names(&findings), vec!["non-lsb-compliant-release"]);
        assert_eq!(findings[0].1, "1_2");
    }

    #[test]
    fn empty_or_absent_fields_are_skipped() {
        assert!(LSBCheck::collect("", None, None).is_empty());
        assert!(LSBCheck::collect("foo", Some(""), Some("")).is_empty());
        assert!(LSBCheck::collect("foo", None, None).is_empty());
    }

    #[test]
    fn all_three_can_fire_together() {
        let findings = LSBCheck::collect("Bad_Name", Some("1~x"), Some("2_y"));
        assert_eq!(
            finding_names(&findings),
            vec![
                "non-lsb-compliant-package-name",
                "non-lsb-compliant-version",
                "non-lsb-compliant-release"
            ]
        );
    }
}
