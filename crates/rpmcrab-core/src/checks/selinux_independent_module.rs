//! `SELinuxIndependentModuleCheck` — SELinux `.if` interface files must live in
//! the policy devel include tree.
//!
//! Ported from `rpmlint/checks/SELinuxIndependentModuleCheck.py`. One finding:
//! `selinux-incorrect-if-file-location`.
//!
//! `new` takes a `Config` only to satisfy the `Check` construction signature;
//! the reference's class attributes are `const`s here and no config keys are
//! read.

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
    use std::path::Path;

    use crate::color::Color;
    use crate::pkg::dep::DepInfo;
    use crate::pkg::pkgfile::PkgFile;

    /// `Pkg` is header-backed with no test constructor, so open a tiny fixture
    /// and rewrite the public fields the check reads.
    fn fixture_pkg() -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg")
    }

    fn dep(name: &str) -> DepInfo {
        DepInfo {
            name: name.to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        }
    }

    fn regular(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            ..Default::default()
        }
    }

    fn selinux_pkg(name: &str, files: &[&str]) -> Pkg {
        let mut pkg = fixture_pkg();
        pkg.name = name.to_string();
        pkg.requires = vec![dep("selinux-policy-base")];
        pkg.files = files.iter().map(|f| regular(f)).collect();
        pkg
    }

    fn run(pkg: &Pkg) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SELinuxIndependentModuleCheck::new(&config);
        check.check_binary(pkg, &config, &mut out);
        out.results().to_vec()
    }

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

    // Mirrors the reference's test_selinux.py::test_selinux_independent_module.
    #[test]
    fn misplaced_if_file_is_error() {
        let pkg = selinux_pkg(
            "flatpak-selinux",
            &[
                "/usr/share/selinux/devel/include/contrib/flatpak.if",
                "/usr/share/selinux/packages/flatpak.pp.bz2",
            ],
        );
        let results = run(&pkg);
        let findings: Vec<&str> = results
            .iter()
            .filter(|(n, _)| n == "selinux-incorrect-if-file-location")
            .map(|(_, line)| line.as_str())
            .collect();
        assert_eq!(findings.len(), 1, "{results:?}");
        assert!(findings[0].contains(": E: "), "level: {}", findings[0]);
        assert!(
            findings[0].ends_with("/usr/share/selinux/devel/include/contrib/flatpak.if"),
            "detail: {}",
            findings[0]
        );
    }

    // Mirrors test_selinux.py::test_selinux_no_independent_module.
    #[test]
    fn main_policy_package_and_allowed_dir_are_quiet() {
        for pkg in [
            selinux_pkg(
                "selinux-policy-devel",
                &["/usr/share/selinux/devel/include/contrib/flatpak.if"],
            ),
            selinux_pkg(
                "ok-package",
                &[
                    "/usr/share/selinux/devel/include/distributed/flatpak.if",
                    "/usr/share/selinux/devel/include/distributed/testing.if",
                    "/usr/share/selinux/devel/include/distributed/subfolder/testing.if",
                ],
            ),
        ] {
            let results = run(&pkg);
            assert!(
                results
                    .iter()
                    .all(|(n, _)| n != "selinux-incorrect-if-file-location"),
                "{results:?}"
            );
        }
    }
}
