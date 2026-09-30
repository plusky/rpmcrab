//! `ZyppSyntaxCheck` — obsolete libzypp rich-dependency syntax.
//!
//! Ported from `rpmlint/checks/ZyppSyntaxCheck.py`. Two findings:
//! `suse-zypp-packageand` and `suse-zypp-otherproviders`.

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct ZyppSyntaxCheck;

impl ZyppSyntaxCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// `(finding, keyword)` for obsolete zypp syntax in dependency names.
    fn obsolete_syntax<'a>(names: impl Iterator<Item = &'a str>) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        for keyword in names {
            if keyword.starts_with("packageand(") {
                out.push(("suse-zypp-packageand", keyword.to_string()));
            }
            if keyword.starts_with("otherproviders(") {
                out.push(("suse-zypp-otherproviders", keyword.to_string()));
            }
        }
        out
    }

    /// All dependency names the reference scans: supplements, enhances,
    /// recommends, suggests, requires and conflicts.
    fn dep_names(pkg: &Pkg) -> Vec<&str> {
        pkg.supplements
            .iter()
            .chain(pkg.enhances.iter())
            .chain(pkg.recommends.iter())
            .chain(pkg.suggests.iter())
            .chain(pkg.requires.iter())
            .chain(pkg.conflicts.iter())
            .map(|d| d.name.as_str())
            .collect()
    }
}

impl Check for ZyppSyntaxCheck {
    fn name(&self) -> &'static str {
        "ZyppSyntaxCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        for (finding, keyword) in Self::obsolete_syntax(Self::dep_names(pkg).into_iter()) {
            add_info(out, Level::Error, pkg, finding, &[&keyword]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packageand_is_flagged() {
        let found = ZyppSyntaxCheck::obsolete_syntax(["packageand(a:b)"].into_iter());
        assert_eq!(
            found,
            vec![("suse-zypp-packageand", "packageand(a:b)".to_string())]
        );
    }

    #[test]
    fn otherproviders_is_flagged() {
        let found = ZyppSyntaxCheck::obsolete_syntax(["otherproviders(sym)"].into_iter());
        assert_eq!(
            found,
            vec![(
                "suse-zypp-otherproviders",
                "otherproviders(sym)".to_string()
            )]
        );
    }

    #[test]
    fn boolean_deps_are_quiet() {
        let found = ZyppSyntaxCheck::obsolete_syntax(["(a and b)", "a", "b"].into_iter());
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn both_syntaxes_in_one_name_are_both_reported() {
        // A single name cannot start with both prefixes, but two names can.
        let found = ZyppSyntaxCheck::obsolete_syntax(
            ["packageand(a:b)", "otherproviders(sym)"].into_iter(),
        );
        assert_eq!(found.len(), 2);
    }
}
