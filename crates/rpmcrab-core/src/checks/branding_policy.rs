//! `BrandingPolicyCheck` — openSUSE branding package policy.
//!
//! Ported from `rpmlint/checks/BrandingPolicyCheck.py`. Findings:
//! `branding-conflicts-missing`, `branding-requires-specific-flavor`,
//! `branding-requires-unversioned`, `branding-supplements-missing`,
//! `branding-provides-missing`, `branding-provides-unversioned`,
//! `branding-excessive-recommends`, `branding-excessive-suggests`,
//! `branding-excessive-enhances`.

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
            re_branding: Regex::new(r"(?P<name>\S+)-(?P<type>branding|theme)-(?P<flavor>\S+)")
                .expect("static regex"),
            re_branding_generic: Regex::new(r"(?P<name>\S+)-(?P<type>branding|theme)")
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
                let has_version = provide.version.is_some() || provide.release.is_some();
                if !has_version || provide.flags != RPMSENSE_EQUAL {
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
}
