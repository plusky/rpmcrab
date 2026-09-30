//! `BrandingPolicyCheck` — openSUSE branding package policy.
//!
//! Ported from `rpmlint/checks/BrandingPolicyCheck.py`. Findings:
//! `branding-conflicts-missing`, `branding-requires-specific-flavor`,
//! `branding-requires-unversioned`, `branding-supplements-missing`,
//! `branding-provides-missing`, `branding-provides-unversioned`,
//! `branding-excessive-recommends`, `branding-excessive-suggests`,
//! `branding-excessive-enhances`.
//!
//! `new` takes a `Config` only to satisfy the `Check` construction signature;
//! like the reference's `__init__`, it reads no config keys.

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

const RPMSENSE_GREATER: u32 = 4;
const RPMSENSE_EQUAL: u32 = 8;

pub struct BrandingPolicyCheck {
    re_branding: Regex,
    re_branding_generic: Regex,
}

impl BrandingPolicyCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            // `\A`-anchored: the reference uses `re.match`.
            re_branding: Regex::new(r"\A(?P<name>\S+)-(?P<type>branding|theme)-(?P<flavor>\S+)")
                .expect("static regex"),
            re_branding_generic: Regex::new(r"\A(?P<name>\S+)-(?P<type>branding|theme)")
                .expect("static regex"),
        }
    }

    /// The `(name, type, flavor)` triple when `pkg_name` is a branding package.
    fn parse_branding(re: &Regex, pkg_name: &str) -> Option<(String, String, String)> {
        let caps = re.captures(pkg_name).ok().flatten()?;
        Some((
            caps.name("name")?.as_str().to_string(),
            caps.name("type")?.as_str().to_string(),
            caps.name("flavor")?.as_str().to_string(),
        ))
    }
}

impl Check for BrandingPolicyCheck {
    fn name(&self) -> &'static str {
        "BrandingPolicyCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }

        let parsed = Self::parse_branding(&self.re_branding, &pkg.name);
        let Some((branding_pkg, branding_type, branding_flavor)) = parsed else {
            // Not a branding package: check its requires.
            for require in &pkg.requires {
                if is_match(&self.re_branding, &require.name) {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "branding-requires-specific-flavor",
                        &[&require.name],
                    );
                    continue;
                }
                if is_match(&self.re_branding_generic, &require.name)
                    && require.flags != RPMSENSE_EQUAL
                    && require.flags != RPMSENSE_GREATER
                    && require.flags != RPMSENSE_GREATER + RPMSENSE_EQUAL
                {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "branding-requires-unversioned",
                        &[&require.name],
                    );
                }
            }
            return;
        };

        let generic_branding_name = format!("{branding_pkg}-{branding_type}");
        let branding_type_flavor = format!("{branding_type}-{branding_flavor}");

        // Conflicts must name the generic branding package.
        if !pkg
            .conflicts
            .iter()
            .any(|d| d.name == generic_branding_name)
        {
            add_info(
                out,
                Level::Error,
                pkg,
                "branding-conflicts-missing",
                &[&generic_branding_name],
            );
        }

        // Exactly one supplement on `(branding_pkg and branding_type-flavor)`.
        let correct_supplement = format!("({branding_pkg} and {branding_type_flavor})");
        if !pkg.supplements.iter().any(|d| d.name == correct_supplement) {
            add_info(
                out,
                Level::Error,
                pkg,
                "branding-supplements-missing",
                &[&correct_supplement],
            );
        }

        // Provides must carry the generic branding name, versioned with `=`.
        match pkg
            .provides
            .iter()
            .find(|p| p.name == generic_branding_name)
        {
            None => {
                add_info(out, Level::Error, pkg, "branding-provides-missing", &[]);
            }
            Some(provide) => {
                // The reference guards on `len(branding_provide) < 2`, which is
                // constant-false for the three-field DepInfo namedtuple.
                if provide.flags != RPMSENSE_EQUAL {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "branding-provides-unversioned",
                        &[&provide.name],
                    );
                }
            }
        }

        // Branding packages must not carry recommends/suggests/enhances.
        for r in &pkg.recommends {
            add_info(
                out,
                Level::Warning,
                pkg,
                "branding-excessive-recommends",
                &[&r.name],
            );
        }
        for r in &pkg.suggests {
            add_info(
                out,
                Level::Warning,
                pkg,
                "branding-excessive-suggests",
                &[&r.name],
            );
        }
        for r in &pkg.enhances {
            add_info(
                out,
                Level::Warning,
                pkg,
                "branding-excessive-enhances",
                &[&r.name],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::color::Color;
    use crate::pkg::dep::DepInfo;

    /// `Pkg` is header-backed with no test constructor, so open a tiny fixture
    /// and rewrite the public fields the check reads.
    fn fixture_pkg() -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        Pkg::open(&rpm, &std::env::temp_dir()).expect("open fixture pkg")
    }

    fn dep(name: &str, flags: u32) -> DepInfo {
        DepInfo {
            name: name.to_string(),
            flags,
            epoch: None,
            version: None,
            release: None,
        }
    }

    fn dep_ev(name: &str, flags: u32, version: &str) -> DepInfo {
        DepInfo {
            name: name.to_string(),
            flags,
            epoch: None,
            version: Some(version.to_string()),
            release: None,
        }
    }

    fn run(pkg: &Pkg) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = BrandingPolicyCheck::new(&config);
        check.check_binary(pkg, &config, &mut out);
        out.results().to_vec()
    }

    fn has<'a>(results: &'a [(String, String)], name: &str) -> Vec<&'a str> {
        results
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, line)| line.as_str())
            .collect()
    }

    #[test]
    fn parse_branding_package() {
        let check = BrandingPolicyCheck::new(&Config::default());
        let parsed = BrandingPolicyCheck::parse_branding(
            &check.re_branding,
            "libreoffice-branding-upstream",
        );
        assert_eq!(
            parsed,
            Some((
                "libreoffice".to_string(),
                "branding".to_string(),
                "upstream".to_string()
            ))
        );
    }

    #[test]
    fn parse_theme_package() {
        let check = BrandingPolicyCheck::new(&Config::default());
        let parsed =
            BrandingPolicyCheck::parse_branding(&check.re_branding, "terminology-theme-openSUSE");
        assert_eq!(
            parsed,
            Some((
                "terminology".to_string(),
                "theme".to_string(),
                "openSUSE".to_string()
            ))
        );
    }

    #[test]
    fn non_branding_name_is_none() {
        let check = BrandingPolicyCheck::new(&Config::default());
        assert!(BrandingPolicyCheck::parse_branding(&check.re_branding, "vim").is_none());
    }

    // Mirrors the reference's test_branding.py::test_branding_requires.
    #[test]
    fn requires_specific_flavor_is_error() {
        let mut pkg = fixture_pkg();
        pkg.name = "brandingdep-testpackage".to_string();
        pkg.requires = vec![
            dep("testingpackage-branding-openSUSE", 0),
            dep_ev("testingpackage2-branding", RPMSENSE_EQUAL, "1.0"),
            dep_ev(
                "testingpackage4-branding",
                RPMSENSE_GREATER | RPMSENSE_EQUAL,
                "1.0",
            ),
            dep("testingpackage-branding", 0),
        ];
        let results = run(&pkg);

        let specific = has(&results, "branding-requires-specific-flavor");
        assert_eq!(specific.len(), 1, "{results:?}");
        assert!(specific[0].contains(": E: "), "level: {}", specific[0]);
        assert!(specific[0].contains("testingpackage-branding-openSUSE"));

        let unversioned = has(&results, "branding-requires-unversioned");
        assert_eq!(unversioned.len(), 1, "{results:?}");
        assert!(
            unversioned[0].contains(": E: "),
            "level: {}",
            unversioned[0]
        );
        assert!(unversioned[0].ends_with("testingpackage-branding"));
    }

    // Mirrors test_branding.py::test_branding_pkg1. The provide carries `=`
    // flags but no version: the old `!has_version` condition flagged this,
    // the reference's constant-false guard does not.
    #[test]
    fn versioned_provide_with_equal_flags_is_quiet() {
        let mut pkg = fixture_pkg();
        pkg.name = "bla-branding-upstream".to_string();
        pkg.conflicts = vec![dep("bla-branding", 0)];
        pkg.supplements = vec![dep("(bla and branding-upstream)", 0)];
        pkg.provides = vec![dep("bla-branding", RPMSENSE_EQUAL)];
        let results = run(&pkg);
        assert!(
            has(&results, "branding-supplements-missing").is_empty(),
            "{results:?}"
        );
        assert!(
            has(&results, "branding-provides-missing").is_empty(),
            "{results:?}"
        );
        assert!(
            has(&results, "branding-provides-unversioned").is_empty(),
            "{results:?}"
        );
        assert!(
            has(&results, "branding-conflicts-missing").is_empty(),
            "{results:?}"
        );
    }

    // Mirrors test_branding.py::test_branding_pkg2.
    #[test]
    fn theme_package_reports_all_expected_findings() {
        let mut pkg = fixture_pkg();
        pkg.name = "bla-theme-openSUSE".to_string();
        pkg.provides = vec![dep("bla-theme", 0)];
        pkg.recommends = vec![dep("recommendie", 0)];
        pkg.suggests = vec![dep("suggie", 0)];
        pkg.enhances = vec![dep("enhancie", 0)];
        let results = run(&pkg);

        let unversioned = has(&results, "branding-provides-unversioned");
        assert_eq!(unversioned.len(), 1, "{results:?}");
        assert!(
            unversioned[0].contains(": E: "),
            "level: {}",
            unversioned[0]
        );
        assert!(unversioned[0].contains("bla-theme"));

        let missing_suppl = has(&results, "branding-supplements-missing");
        assert_eq!(missing_suppl.len(), 1, "{results:?}");
        assert!(missing_suppl[0].contains("(bla and theme-openSUSE)"));

        let missing_conf = has(&results, "branding-conflicts-missing");
        assert_eq!(missing_conf.len(), 1, "{results:?}");
        assert!(missing_conf[0].contains("bla-theme"));

        for (finding, detail) in [
            ("branding-excessive-recommends", "recommendie"),
            ("branding-excessive-suggests", "suggie"),
            ("branding-excessive-enhances", "enhancie"),
        ] {
            let got = has(&results, finding);
            assert_eq!(got.len(), 1, "{finding}: {results:?}");
            assert!(got[0].contains(": W: "), "level: {}", got[0]);
            assert!(got[0].contains(detail), "detail: {}", got[0]);
        }
    }
}
