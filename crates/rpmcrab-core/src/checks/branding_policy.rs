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
//!
//! The supplements obligation is satisfied by the prescribed
//! `(base and branding-<flavor>)` entry, or by any supplement whose
//! rich-boolean tree carries `branding-<flavor>` as a conjunct of a
//! plain conjunction (a renamed or compound base in the same
//! conjunction still gates on the flavour). The zypp `packageand()`
//! spelling and a flavour atom under `or`, `if`, `unless`, `with` or
//! `without` do not satisfy it.
//!
//! The flavour obligations — `branding-conflicts-missing`,
//! `branding-supplements-missing` and `branding-provides-missing` — are
//! scoped to the branding arm: they are charged on
//! `<base>-branding-<flavor>` packages, whose flavour mechanism selects
//! exactly one branding per base package. Theme packages
//! (`<base>-theme-<flavor>`) are additive content packs, co-installed and
//! selected by name; a theme package that provides the generic name is
//! still charged `branding-provides-unversioned` for an unversioned
//! provide, and the excessive-dependency warnings apply on both arms.
//! On the requirer side, `branding-requires-specific-flavor` is charged
//! on package names — require names that parse as a flavour pin; an ELF
//! shared-library capability name (`lib....so...`) is not a package
//! name and pins no flavour.
//! Theme-type requires are not charged at all: themes are additive
//! content packs selected by name, and the generic `<base>-theme`
//! name the finding prescribes usually has no provider.

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::dep::{DepExpr, parse_dep_expr};

const RPMSENSE_GREATER: u32 = 4;
const RPMSENSE_EQUAL: u32 = 8;

pub struct BrandingPolicyCheck {
    re_branding: Regex,
    re_branding_generic: Regex,
    re_icon_theme: Regex,
}

impl BrandingPolicyCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            // `\A`-anchored: the reference uses `re.match`.
            re_branding: Regex::new(r"\A(?P<name>\S+)-(?P<type>branding|theme)-(?P<flavor>\S+)")
                .expect("static regex"),
            // End-anchored: the generic branding name in full, so names
            // that merely contain the pattern (gnome-themes,
            // ocean-sound-theme6, config(yast2-theme)) do not match.
            re_branding_generic: Regex::new(r"\A(?P<name>\S+)-(?P<type>branding|theme)\z")
                .expect("static regex"),
            re_icon_theme: Regex::new(r"\A(?P<name>\S+)-icon-theme\z").expect("static regex"),
        }
    }

    /// Whether `name` is an ELF shared-library capability name
    /// (`lib-theme-resources.so()(64bit)`, `libfoo.so.6(GLIBC_2.4)(64bit)`):
    /// a `.so` component followed only by version or symbol decoration
    /// — version groups of `.` plus digits and parenthesised symbol
    /// sets, nothing else. A name that continues past the decoration
    /// (a flavour spelled after a soname version, say) is a package
    /// name, not a capability. Such names live in the
    /// library-capability namespace, not the package-name namespace
    /// this check polices.
    fn is_elf_capability(name: &str) -> bool {
        let Some(i) = name.find(".so") else {
            return false;
        };
        let mut rest = &name[i + 3..];
        loop {
            if rest.is_empty() {
                return true;
            }
            if let Some(tail) = rest.strip_prefix('.') {
                let digits = tail.bytes().take_while(|b| b.is_ascii_digit()).count();
                if digits == 0 {
                    return false;
                }
                rest = &tail[digits..];
            } else if let Some(tail) = rest.strip_prefix('(') {
                match tail.find(')') {
                    Some(j) => rest = &tail[j + 1..],
                    None => return false,
                }
            } else {
                return false;
            }
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

    /// Whether `require_name`, required by `pkg_name`, is a patterns
    /// composition pin: a branding-type pin charged on a package in
    /// the reserved `patterns-*` namespace. Patterns packages are the
    /// distribution composition layer, the place where a product
    /// flavour selection is *made*, so their branding
    /// pins are the selection itself, not a consumer bypassing the
    /// generic mechanism, and `branding-requires-specific-flavor` is
    /// not charged for them. Theme-type pins are not composition
    /// pins either: they are exempt on every requirer by the
    /// 2026-10-27 ruling (see `is_theme_pin`), patterns packages
    /// included.
    fn is_composition_pin(re: &Regex, pkg_name: &str, require_name: &str) -> bool {
        pkg_name.starts_with("patterns-")
            && matches!(
                Self::parse_branding(re, require_name),
                Some((_, kind, _)) if kind == "branding"
            )
    }

    /// Whether `require_name` is a theme-type pin: its parsed type
    /// component is `theme`. Theme pins are not charged
    /// `branding-requires-specific-flavor` on any requirer
    /// (maintainer ruling, 2026-10-27). The specific-flavor
    /// doctrine redirects a pin to the sanctioned generic virtual;
    /// for themes that virtual usually does not exist — of the 15
    /// theme-type findings on the Factory corpus, 13 require a
    /// generic `<base>-theme` name with zero providers corpus-wide,
    /// so the prescribed require is unsatisfiable — and the rest
    /// sit in ecosystems whose theme names are flavour-specific by
    /// design. Themes are additive content packs selected by name
    /// (the #954 doctrine), not flavour selections. The exemption
    /// keys on the parsed type component only: a name merely
    /// containing `theme` outside that position
    /// (`libtheme-branding-openSUSE`) is a branding pin and keeps
    /// firing, and ELF capability names stay governed by
    /// `is_elf_capability`. The charge site skips a theme pin
    /// before either requirer arm runs: it is not a generic-name
    /// require either, so the unversioned arm cannot re-read a
    /// pin whose flavour is `branding` as a generic branding
    /// require.
    fn is_theme_pin(re: &Regex, require_name: &str) -> bool {
        matches!(
            Self::parse_branding(re, require_name),
            Some((_, kind, _)) if kind == "theme"
        )
    }
}

/// True when `expr` is a plain conjunction carrying `atom` as one of
/// its conjuncts: an `and` tree with the atom — unversioned and
/// unqualified — as a direct conjunct, or a nested `and` carrying it.
/// The atom under any other operator does not gate the expression on
/// the atom, so it never credits; a bare atom is not a conjunction
/// and does not credit either.
fn flavour_conjunct(expr: &DepExpr, atom: &str) -> bool {
    match expr {
        DepExpr::And(children) => children.iter().any(|child| match child {
            DepExpr::Simple {
                name,
                qualifier,
                flags,
                ..
            } => name == atom && qualifier.is_none() && *flags == 0,
            DepExpr::And(_) => flavour_conjunct(child, atom),
            _ => false,
        }),
        _ => false,
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
                // Theme-type pins are exempt from the specific-flavor
                // doctrine entirely (maintainer ruling, 2026-10-27):
                // they select a concrete theme pack, and they are not
                // generic-name requires either, so neither the
                // specific-flavor arm nor the unversioned arm below
                // applies to them — a theme pin whose flavour is
                // `branding` would otherwise be re-read as a generic
                // branding require by the second arm.
                if Self::is_theme_pin(&self.re_branding, &require.name) {
                    continue;
                }
                if is_match(&self.re_branding, &require.name)
                    && !Self::is_composition_pin(&self.re_branding, &pkg.name, &require.name)
                    && !Self::is_elf_capability(&require.name)
                {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "branding-requires-specific-flavor",
                        &[&require.name],
                    );
                    continue;
                }
                // Icon themes are concrete data packages, not flavour
                // virtuals: a version on the require pins no flavour, so
                // they stay silent (the reference's re_icon_theme draws
                // the same line).
                if is_match(&self.re_branding_generic, &require.name)
                    && !is_match(&self.re_icon_theme, &require.name)
                    && require.flags != RPMSENSE_EQUAL
                    && require.flags != RPMSENSE_GREATER
                    && require.flags != RPMSENSE_GREATER + RPMSENSE_EQUAL
                {
                    add_info(
                        out,
                        Level::Warning,
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

        // The flavour obligations are charged on the branding arm
        // (issue #954): a branding package conflicts the generic name
        // and carries exactly one supplement on
        // `(branding_pkg and branding_type-flavor)`.
        if branding_type == "branding" {
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

            let correct_supplement = format!("({branding_pkg} and {branding_type_flavor})");
            let supplement_carried = pkg.supplements.iter().any(|d| {
                d.name == correct_supplement
                    || flavour_conjunct(&parse_dep_expr(&d.name), &branding_type_flavor)
            });
            if !supplement_carried {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "branding-supplements-missing",
                    &[&correct_supplement],
                );
            }
        }

        // Provides must carry the generic branding name, versioned with `=`.
        match pkg
            .provides
            .iter()
            .find(|p| p.name == generic_branding_name)
        {
            None => {
                // The provides obligation is charged on the branding
                // arm (issue #954); a present-but-unversioned provide
                // is charged on both arms in the `Some` branch.
                if branding_type == "branding" {
                    add_info(out, Level::Error, pkg, "branding-provides-missing", &[]);
                }
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
        Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg")
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
        // #953: the unversioned finding is a warning; the versioned form
        // it prescribes is unsatisfiable for branding flavours on their
        // own release train.
        assert!(
            unversioned[0].contains(": W: "),
            "level: {}",
            unversioned[0]
        );
        assert!(unversioned[0].ends_with("testingpackage-branding"));
    }

    // An ELF capability name whose soname is branding-shaped is not a
    // flavour pin: it names a library, not a package. Branding-type
    // package-name near-misses (no `.so` component) keep firing, as
    // does a dotted branding name that continues past its soname
    // decoration. The theme-type names in the list stay silent under
    // the theme-type exemption (maintainer ruling, 2026-10-27), not
    // because they are capabilities.
    #[test]
    fn soname_requires_are_not_flavor_pins() {
        let mut pkg = fixture_pkg();
        pkg.name = "brandingdep-testpackage".to_string();
        pkg.requires = vec![
            dep("lib-theme-resources.so()(64bit)", 0),
            dep("lib-theme.so.1()(64bit)", 0),
            // The versioned-dot branch on a name that does parse as
            // a theme flavour pin.
            dep("lib-theme-resources.so.1()(64bit)", 0),
            dep("libtheme-branding-openSUSE", 0),
            dep("testingpackage-branding-openSUSE", 0),
            // The stripped stem is a plain theme-arm package name:
            // silent under the theme-type exemption.
            dep("lib-theme-resources", 0),
            // Decoration followed by more name is no capability, but
            // the name is theme-type, so the exemption silences it.
            dep("libfoo.so.1-theme-openSUSE", 0),
        ];
        let results = run(&pkg);

        let specific = has(&results, "branding-requires-specific-flavor");
        assert_eq!(specific.len(), 2, "{results:?}");
        assert!(
            specific
                .iter()
                .any(|l| l.contains("libtheme-branding-openSUSE"))
        );
        assert!(
            specific
                .iter()
                .any(|l| l.contains("testingpackage-branding-openSUSE"))
        );
    }

    // #857: the unversioned finding is scoped to the generic branding
    // name itself. Generic names in full are charged on both arms;
    // concrete data packages and non-name require forms stay silent.
    #[test]
    fn unversioned_requires_scoped_to_generic_branding_names() {
        let mut pkg = fixture_pkg();
        pkg.name = "brandingdep-testpackage".to_string();
        pkg.requires = vec![
            dep("testingpackage-branding", 0),
            dep("testingpackage-theme", 0),
            dep("hicolor-icon-theme", 0),
            dep("gnome-themes", 0),
            dep("kalpa-themes-sddm", 0),
            dep("ocean-sound-theme6", 0),
            dep("lib-theme.so()(64bit)", 0),
            dep("config(yast2-theme)", 0),
        ];
        let results = run(&pkg);

        let unversioned = has(&results, "branding-requires-unversioned");
        assert_eq!(unversioned.len(), 2, "{results:?}");
        assert!(
            unversioned
                .iter()
                .any(|line| line.ends_with("testingpackage-branding")),
            "{results:?}"
        );
        assert!(
            unversioned
                .iter()
                .any(|line| line.ends_with("testingpackage-theme")),
            "{results:?}"
        );
        assert!(
            has(&results, "branding-requires-specific-flavor").is_empty(),
            "{results:?}"
        );
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

    // Mirrors test_branding.py::test_branding_pkg2, with the #954
    // scoping of the *-missing obligations to the branding arm.
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

        // #954: the flavour obligations are scoped to the branding arm,
        // so a theme package is charged none of the *-missing trio.
        assert!(
            has(&results, "branding-supplements-missing").is_empty(),
            "{results:?}"
        );
        assert!(
            has(&results, "branding-conflicts-missing").is_empty(),
            "{results:?}"
        );
        assert!(
            has(&results, "branding-provides-missing").is_empty(),
            "{results:?}"
        );

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

    // #954: a theme package carrying none of the three flavour
    // obligations is silent on all three *-missing findings.
    #[test]
    fn theme_package_without_obligations_is_silent_on_the_trio() {
        let mut pkg = fixture_pkg();
        pkg.name = "bla-theme-openSUSE".to_string();
        pkg.conflicts = vec![];
        pkg.supplements = vec![];
        pkg.provides = vec![];
        let results = run(&pkg);
        for finding in [
            "branding-conflicts-missing",
            "branding-supplements-missing",
            "branding-provides-missing",
        ] {
            assert!(has(&results, finding).is_empty(), "{finding}: {results:?}");
        }
    }

    // #954: a branding package missing all three obligations is still
    // charged all three, each at E.
    #[test]
    fn branding_package_missing_all_obligations_reports_the_trio() {
        let mut pkg = fixture_pkg();
        pkg.name = "bla-branding-upstream".to_string();
        pkg.conflicts = vec![];
        pkg.supplements = vec![];
        pkg.provides = vec![];
        let results = run(&pkg);
        for finding in [
            "branding-conflicts-missing",
            "branding-supplements-missing",
            "branding-provides-missing",
        ] {
            let got = has(&results, finding);
            assert_eq!(got.len(), 1, "{finding}: {results:?}");
            assert!(got[0].contains(": E: "), "level: {}", got[0]);
        }
    }

    // #954: a participating theme package — it provides the generic
    // name versioned and conflicts the generic name, the
    // enlightenment-theme-upstream / terminology-theme-upstream shape
    // — is silent on the trio: the missing supplement is not charged
    // on the theme arm.
    #[test]
    fn participating_theme_package_is_silent_on_the_trio() {
        let mut pkg = fixture_pkg();
        pkg.name = "bla-theme-upstream".to_string();
        pkg.conflicts = vec![dep("bla-theme", 0)];
        pkg.supplements = vec![];
        pkg.provides = vec![dep_ev("bla-theme", RPMSENSE_EQUAL, "1.0")];
        let results = run(&pkg);
        for finding in [
            "branding-conflicts-missing",
            "branding-supplements-missing",
            "branding-provides-missing",
            "branding-provides-unversioned",
        ] {
            assert!(has(&results, finding).is_empty(), "{finding}: {results:?}");
        }
    }

    // #954: a branding package missing exactly one obligation is
    // charged exactly that one.
    #[test]
    fn branding_package_missing_one_obligation_reports_exactly_that_one() {
        let mut pkg = fixture_pkg();
        pkg.name = "bla-branding-upstream".to_string();
        pkg.conflicts = vec![dep("bla-branding", 0)];
        pkg.supplements = vec![];
        pkg.provides = vec![dep("bla-branding", RPMSENSE_EQUAL)];
        let results = run(&pkg);
        let got = has(&results, "branding-supplements-missing");
        assert_eq!(got.len(), 1, "{results:?}");
        assert!(got[0].contains(": E: "), "level: {}", got[0]);
        assert!(got[0].contains("(bla and branding-upstream)"));
        for finding in [
            "branding-conflicts-missing",
            "branding-provides-missing",
            "branding-provides-unversioned",
        ] {
            assert!(has(&results, finding).is_empty(), "{finding}: {results:?}");
        }
    }

    /// A branding package whose conflicts and provides obligations
    /// are met, so only `branding-supplements-missing` can be charged.
    fn branding_pkg(name: &str, supplements: Vec<DepInfo>) -> Pkg {
        let (generic, _flavor) = name.rsplit_once('-').expect("flavoured name");
        let mut pkg = fixture_pkg();
        pkg.name = name.to_string();
        pkg.conflicts = vec![dep(generic, 0)];
        pkg.supplements = supplements;
        pkg.provides = vec![dep(generic, RPMSENSE_EQUAL)];
        pkg
    }

    fn supplements_missing(pkg: &Pkg) -> Vec<String> {
        has(&run(pkg), "branding-supplements-missing")
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    // The grub2-branding-openSUSE shape: the flavour atom is a direct
    // conjunct of the top-level `and`; the other conjunct is an `or`
    // over the compound base, mirroring the package's own Requires.
    #[test]
    fn rich_supplement_with_compound_base_credits() {
        let pkg = branding_pkg(
            "grub2-branding-openSUSE",
            vec![dep("((grub2 or grub2-common) and branding-openSUSE)", 0)],
        );
        assert!(supplements_missing(&pkg).is_empty(), "{:?}", run(&pkg));
    }

    // The yast2-qt-branding-openSUSE shape: the base atom is the
    // modern name of the library (libyui-qt), not the legacy base the
    // package name carries; the flavour conjunct still gates.
    #[test]
    fn rich_supplement_with_renamed_base_credits() {
        let pkg = branding_pkg(
            "yast2-qt-branding-openSUSE",
            vec![dep("(libyui-qt and branding-openSUSE)", 0)],
        );
        assert!(supplements_missing(&pkg).is_empty(), "{:?}", run(&pkg));
    }

    // A nested plain conjunction carrying the flavour atom credits:
    // ((yast-installation and icewm) and branding-openSUSE).
    #[test]
    fn rich_supplement_with_nested_and_credits() {
        let pkg = branding_pkg(
            "icewm-branding-openSUSE",
            vec![dep(
                "((yast-installation and icewm) and branding-openSUSE)",
                0,
            )],
        );
        assert!(supplements_missing(&pkg).is_empty(), "{:?}", run(&pkg));
    }

    // The zypp `packageand()` spelling is not credited (settled
    // doctrine, #853/#854): the finding still fires.
    #[test]
    fn packageand_supplement_still_fires() {
        let pkg = branding_pkg(
            "grub2-branding-openSUSE",
            vec![dep("packageand(grub2:branding-openSUSE)", 0)],
        );
        let got = supplements_missing(&pkg);
        assert_eq!(got.len(), 1, "{:?}", run(&pkg));
        assert!(got[0].contains("(grub2 and branding-openSUSE)"), "{got:?}");
    }

    // The flavour atom under `or` does not gate the supplement on the
    // flavour: the finding still fires.
    #[test]
    fn flavour_atom_under_or_still_fires() {
        let pkg = branding_pkg(
            "grub2-branding-openSUSE",
            vec![dep("(grub2 or branding-openSUSE)", 0)],
        );
        assert_eq!(supplements_missing(&pkg).len(), 1, "{:?}", run(&pkg));
    }

    // The flavour atom as an `if` condition does not credit either.
    #[test]
    fn flavour_atom_under_if_still_fires() {
        let pkg = branding_pkg(
            "grub2-branding-openSUSE",
            vec![dep("(grub2 if branding-openSUSE)", 0)],
        );
        assert_eq!(supplements_missing(&pkg).len(), 1, "{:?}", run(&pkg));
    }

    // Nor does the flavour atom under `without`.
    #[test]
    fn flavour_atom_under_without_still_fires() {
        let pkg = branding_pkg(
            "grub2-branding-openSUSE",
            vec![dep("(grub2 without branding-openSUSE)", 0)],
        );
        assert_eq!(supplements_missing(&pkg).len(), 1, "{:?}", run(&pkg));
    }

    // A versioned flavour conjunct is not the plain atom the
    // obligation prescribes: the finding still fires.
    #[test]
    fn versioned_flavour_atom_still_fires() {
        let pkg = branding_pkg(
            "grub2-branding-openSUSE",
            vec![dep("(grub2 and branding-openSUSE >= 84)", 0)],
        );
        assert_eq!(supplements_missing(&pkg).len(), 1, "{:?}", run(&pkg));
    }

    // The libreoffice-branding-upstream corpus shape: a conjunction
    // on a *different* flavour's atom does not credit this flavour.
    #[test]
    fn wrong_flavour_conjunct_still_fires() {
        let pkg = branding_pkg(
            "libreoffice-branding-upstream",
            vec![dep("(libreoffice and branding-openSUSE)", 0)],
        );
        assert_eq!(supplements_missing(&pkg).len(), 1, "{:?}", run(&pkg));
    }

    // A bare flavour atom is not a conjunction: the finding still
    // fires.
    #[test]
    fn bare_flavour_atom_still_fires() {
        let pkg = branding_pkg("grub2-branding-openSUSE", vec![dep("branding-openSUSE", 0)]);
        assert_eq!(supplements_missing(&pkg).len(), 1, "{:?}", run(&pkg));
    }

    // Maintainer ruling (2026-10-26): packages in the reserved
    // patterns-* namespace are the composition layer. Their branding
    // pins, own-flavour, borrowed-flavour and rich conditional alike,
    // make the flavour selection, so the specific-flavor error is not
    // charged for them. Theme pins are not flavour selections; since
    // the 2026-10-27 ruling they are exempt on every requirer, so no
    // specific-flavor finding remains here at all. The generic-name
    // (unversioned) arm is untouched.
    #[test]
    fn patterns_branding_pins_are_composition_not_consumption() {
        let mut pkg = fixture_pkg();
        pkg.name = "patterns-test-base".to_string();
        pkg.requires = vec![
            dep("testingpackage-branding-openSUSE", 0),
            dep("otherpackage-branding-upstream", 0),
            dep("(grub2-branding-openSUSE if branding-openSUSE)", 0),
            dep("testingpackage-theme-openSUSE", 0),
            dep("testingpackage-branding", 0),
        ];
        let results = run(&pkg);

        let specific = has(&results, "branding-requires-specific-flavor");
        assert_eq!(specific.len(), 0, "{results:?}");

        let unversioned = has(&results, "branding-requires-unversioned");
        assert_eq!(unversioned.len(), 1, "{results:?}");
        assert!(unversioned[0].ends_with("testingpackage-branding"));
    }

    // The exemption keys on the reserved patterns-* prefix exactly:
    // names that merely contain "pattern", use the singular, drop the
    // dash or shift the prefix are not in the namespace and keep
    // firing.
    #[test]
    fn near_miss_names_are_not_patterns_packages() {
        for name in [
            "mypatterns-test",
            "pattern-test",
            "patterns",
            "x-patterns-test",
        ] {
            let mut pkg = fixture_pkg();
            pkg.name = name.to_string();
            pkg.requires = vec![dep("testingpackage-branding-openSUSE", 0)];
            let results = run(&pkg);
            let specific = has(&results, "branding-requires-specific-flavor");
            assert_eq!(specific.len(), 1, "{name}: {results:?}");
        }
    }

    // The specific-flavor charge as a matrix (maintainer rulings
    // 2026-10-26 and 2026-10-27): a branding-type pin fires on a
    // plain requirer and is composition on a patterns requirer; a
    // theme-type pin is exempt on both, because the generic
    // <base>-theme name it would be redirected to has no provider
    // for most bases. A name merely containing "theme" outside
    // the type position (libtheme-branding-openSUSE) is a branding
    // pin and keeps firing.
    #[test]
    fn specific_flavor_charge_matrix() {
        for (requirer, require, fires) in [
            (
                "plain-testpackage",
                "testingpackage-branding-openSUSE",
                true,
            ),
            (
                "patterns-test-base",
                "testingpackage-branding-openSUSE",
                false,
            ),
            ("plain-testpackage", "testingpackage-theme-openSUSE", false),
            ("patterns-test-base", "testingpackage-theme-openSUSE", false),
            ("plain-testpackage", "libtheme-branding-openSUSE", true),
        ] {
            let mut pkg = fixture_pkg();
            pkg.name = requirer.to_string();
            pkg.requires = vec![dep(require, 0)];
            let results = run(&pkg);
            let specific = has(&results, "branding-requires-specific-flavor");
            assert_eq!(
                specific.len(),
                usize::from(fires),
                "{requirer} requiring {require}: {results:?}"
            );
        }
    }

    // A theme pin whose flavour component is `branding`
    // (the corpus shape: icewm-theme-branding) parses as a theme
    // pin for the specific-flavor arm and as a generic branding
    // name for the unversioned arm. The exemption covers the
    // require: neither arm fires.
    #[test]
    fn theme_pin_with_branding_flavour_is_fully_silent() {
        let mut pkg = fixture_pkg();
        pkg.name = "plain-testpackage".to_string();
        pkg.requires = vec![dep("testingpackage-theme-branding", 0)];
        let results = run(&pkg);
        assert!(
            has(&results, "branding-requires-specific-flavor").is_empty(),
            "{results:?}"
        );
        assert!(
            has(&results, "branding-requires-unversioned").is_empty(),
            "{results:?}"
        );
    }
}
