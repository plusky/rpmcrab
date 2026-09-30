//! `SELinuxIndependentModuleCheck` — SELinux `.if` interface files must live in
//! the policy devel include tree.
//!
//! Ported from `rpmlint/checks/SELinuxIndependentModuleCheck.py`. One finding:
//! `selinux-incorrect-if-file-location`.

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

const ALLOWED_IF_DIR: &str = "/usr/share/selinux/devel/include/distributed/";
const SELINUX_MAIN_POLICY_PACKAGES: &[&str] = &["selinux-policy-devel"];

pub struct SELinuxIndependentModuleCheck;

impl SELinuxIndependentModuleCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// True when the package requires `selinux-policy-base` (a requires or a
    /// legacy prereq): an independent SELinux module.
    fn is_independent_module<'a>(
        requires: impl Iterator<Item = &'a str>,
        prereq: impl Iterator<Item = &'a str>,
    ) -> bool {
        requires
            .chain(prereq)
            .any(|name| name == "selinux-policy-base")
    }

    /// The `.if` files outside the allowed directory.
    fn misplaced_if_files<'a>(files: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
        files
            .filter(|f| f.ends_with(".if") && !f.starts_with(ALLOWED_IF_DIR))
            .collect()
    }
}

impl Check for SELinuxIndependentModuleCheck {
    fn name(&self) -> &'static str {
        "SELinuxIndependentModuleCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }
        if SELINUX_MAIN_POLICY_PACKAGES.contains(&pkg.name.as_str()) {
            return;
        }
        if !Self::is_independent_module(
            pkg.requires.iter().map(|d| d.name.as_str()),
            pkg.prereq.iter().map(|d| d.name.as_str()),
        ) {
            return;
        }
        for f in Self::misplaced_if_files(pkg.files.iter().map(|f| f.name.as_str())) {
            add_info(
                out,
                Level::Error,
                pkg,
                "selinux-incorrect-if-file-location",
                &[f],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_marks_independent_module() {
        assert!(SELinuxIndependentModuleCheck::is_independent_module(
            ["selinux-policy-base"].into_iter(),
            [].into_iter()
        ));
    }

    #[test]
    fn prereq_marks_independent_module() {
        assert!(SELinuxIndependentModuleCheck::is_independent_module(
            [].into_iter(),
            ["selinux-policy-base"].into_iter()
        ));
    }

    #[test]
    fn unrelated_requires_are_quiet() {
        assert!(!SELinuxIndependentModuleCheck::is_independent_module(
            ["bash"].into_iter(),
            [].into_iter()
        ));
    }

    #[test]
    fn if_file_in_allowed_dir_is_quiet() {
        let found = SELinuxIndependentModuleCheck::misplaced_if_files(
            ["/usr/share/selinux/devel/include/distributed/foo.if"].into_iter(),
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn if_file_elsewhere_is_reported() {
        let found = SELinuxIndependentModuleCheck::misplaced_if_files(
            ["/usr/share/selinux/packages/foo.if"].into_iter(),
        );
        assert_eq!(found, vec!["/usr/share/selinux/packages/foo.if"]);
    }

    #[test]
    fn non_if_files_are_ignored() {
        let found = SELinuxIndependentModuleCheck::misplaced_if_files(["/usr/bin/foo"].into_iter());
        assert!(found.is_empty(), "{found:?}");
    }
}
