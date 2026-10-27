//! `SELinuxIndependentModuleCheck` — SELinux `.if` interface files must live in
//! the policy devel include tree.
//!
//! Ported from `rpmlint/checks/SELinuxIndependentModuleCheck.py`. One finding:
//! `selinux-incorrect-if-file-location`.
//!
//! Divergence from the reference: the reference credits only the
//! `distributed/` directory, but the devel Makefile the policy toolchain
//! ships collects interfaces from every layer directory of the include
//! tree (`$(layer)/*.if` for each direct subdirectory other than
//! `support`), so a `.if` sitting directly in any layer directory is
//! found by consuming policy builds exactly like one in `distributed/`.
//! Only files outside that grammar (directly in the include directory,
//! nested inside a layer, in `support/`, or outside the include tree)
//! are reported. Ledgered in the SELinuxIndependentModuleCheck
//! divergences source.
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
const INCLUDE_DIR: &str = "/usr/share/selinux/devel/include/";
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

    /// True when the file sits directly in a layer directory of the
    /// devel include tree: the shipped devel Makefile's
    /// `header_interfaces` collects `$(layer)/*.if` for every direct
    /// subdirectory of the include directory other than `support`, so
    /// consuming policy builds find such files. Files directly in the
    /// include directory, nested below a layer, or in `support/` are
    /// not collected.
    fn in_include_layer(f: &str) -> bool {
        let Some(rest) = f.strip_prefix(INCLUDE_DIR) else {
            return false;
        };
        let Some((layer, name)) = rest.split_once('/') else {
            return false;
        };
        !layer.is_empty() && layer != "support" && !name.is_empty() && !name.contains('/')
    }

    /// The `.if` files outside the allowed directory and outside every
    /// layer directory of the devel include tree.
    fn misplaced_if_files<'a>(files: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
        files
            .filter(|f| {
                f.ends_with(".if") && !f.starts_with(ALLOWED_IF_DIR) && !Self::in_include_layer(f)
            })
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
    fn if_file_in_layer_dir_is_quiet() {
        for f in [
            "/usr/share/selinux/devel/include/contrib/foo.if",
            "/usr/share/selinux/devel/include/services/foo.if",
            "/usr/share/selinux/devel/include/kernel/foo.if",
        ] {
            let found = SELinuxIndependentModuleCheck::misplaced_if_files([f].into_iter());
            assert!(found.is_empty(), "{f}: {found:?}");
        }
    }

    #[test]
    fn if_file_not_collected_by_devel_makefile_is_reported() {
        // The devel Makefile collects only $(layer)/*.if: a file
        // directly in the include directory, one nested below a layer,
        // and one in the excluded support directory are not collected.
        for f in [
            "/usr/share/selinux/devel/include/foo.if",
            "/usr/share/selinux/devel/include/contrib/sub/foo.if",
            "/usr/share/selinux/devel/include/support/foo.if",
        ] {
            let found = SELinuxIndependentModuleCheck::misplaced_if_files([f].into_iter());
            assert_eq!(found, vec![f], "{f}");
        }
    }

    #[test]
    fn layer_placed_if_file_is_quiet() {
        let pkg = selinux_pkg(
            "container-selinux",
            &[
                "/usr/share/selinux/devel/include/services/container.if",
                "/usr/share/selinux/packages/container.pp.bz2",
            ],
        );
        let results = run(&pkg);
        assert!(
            results
                .iter()
                .all(|(n, _)| n != "selinux-incorrect-if-file-location"),
            "{results:?}"
        );
    }

    #[test]
    fn non_if_files_are_ignored() {
        let found = SELinuxIndependentModuleCheck::misplaced_if_files(["/usr/bin/foo"].into_iter());
        assert!(found.is_empty(), "{found:?}");
    }

    // Mirrors the reference's test_selinux.py::test_selinux_independent_module,
    // with the misplaced file directly in the include directory: the
    // reference's contrib/ example is a layer directory the devel
    // Makefile collects, so it is quiet here (see the ledger entry).
    #[test]
    fn misplaced_if_file_is_error() {
        let pkg = selinux_pkg(
            "flatpak-selinux",
            &[
                "/usr/share/selinux/devel/include/flatpak.if",
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
            findings[0].ends_with("/usr/share/selinux/devel/include/flatpak.if"),
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
