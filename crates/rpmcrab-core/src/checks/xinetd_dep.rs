//! `XinetdDepCheck` — xinetd is obsolete.
//!
//! `obsolete-xinetd-requirement` is ported from
//! `rpmlint/checks/XinetdDepCheck.py`. `deprecated-xinetd-config` has no
//! reference counterpart: shipping an xinetd config is an error (the
//! `xinetd` package itself is exempt), and
//! the replacement is a systemd timer unit, or a socket unit where the
//! service was socket-activated (deliberate, ledgered).

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct XinetdDepCheck;

impl XinetdDepCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// True when any requirement name is exactly `xinetd`.
    fn requires_xinetd<'a>(mut reqs: impl Iterator<Item = &'a str>) -> bool {
        reqs.any(|name| name == "xinetd")
    }
}

impl Check for XinetdDepCheck {
    fn name(&self) -> &'static str {
        "XinetdDepCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let reqs = pkg
            .requires
            .iter()
            .chain(pkg.prereq.iter())
            .map(|d| d.name.as_str());
        if Self::requires_xinetd(reqs) {
            add_info(out, Level::Error, pkg, "obsolete-xinetd-requirement", &[]);
        }
        // The xinetd package itself is exempt: the deprecation
        // tells every other package not
        // to ship xinetd configuration; xinetd's own bundled configs
        // are its to retire. The exemption keys on the package name,
        // not on the config state -- an enabled definition shipped by
        // the xinetd package stays silent too.
        if pkg.name != "xinetd" {
            for file in &pkg.files {
                if file.name.starts_with("/etc/xinetd.d/") {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "deprecated-xinetd-config",
                        &[
                            file.name.as_str(),
                            "use a systemd timer or socket unit instead",
                        ],
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::color::Color;
    use crate::pkg::pkgfile::PkgFile;

    #[test]
    fn xinetd_require_is_flagged() {
        assert!(XinetdDepCheck::requires_xinetd(
            ["xinetd", "other"].into_iter()
        ));
    }

    #[test]
    fn xinetd_prereq_is_flagged() {
        assert!(XinetdDepCheck::requires_xinetd(
            ["other", "xinetd"].into_iter()
        ));
    }

    #[test]
    fn no_xinetd_is_quiet() {
        assert!(!XinetdDepCheck::requires_xinetd(
            ["systemd", "other"].into_iter()
        ));
    }

    #[test]
    fn xinetd_prefix_is_not_enough() {
        // The reference compares the bare name for equality.
        assert!(!XinetdDepCheck::requires_xinetd(["xinetd-foo"].into_iter()));
    }

    fn run_check(pkg: &Pkg) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = XinetdDepCheck::new(&config);
        check.check_binary(pkg, &config, &mut out);
        out.results().to_vec()
    }

    fn pkg_named_with_files(name: &str, files: &[&str]) -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = name.to_string();
        pkg.files = files
            .iter()
            .map(|f| PkgFile {
                name: f.to_string(),
                path: f.to_string(),
                ..Default::default()
            })
            .collect();
        pkg
    }

    #[test]
    fn xinetd_config_file_is_an_error_pointing_at_timer_or_socket_units() {
        let pkg = pkg_named_with_files("daytime", &["/etc/xinetd.d/daytime"]);
        let results = run_check(&pkg);
        assert_eq!(results.len(), 1, "{results:?}");
        let (name, line) = &results[0];
        assert_eq!(name, "deprecated-xinetd-config");
        assert!(
            line.contains(": E: deprecated-xinetd-config /etc/xinetd.d/daytime"),
            "unexpected line: {line}"
        );
        assert!(
            line.contains("use a systemd timer or socket unit instead"),
            "detail must name the replacement: {line}"
        );
    }

    #[test]
    fn non_xinetd_config_paths_are_quiet() {
        let pkg = pkg_named_with_files(
            "daytime",
            &[
                "/etc/xinetd/daytime",
                "/usr/lib/systemd/system/daytime.socket",
            ],
        );
        let results = run_check(&pkg);
        assert!(results.is_empty(), "{results:?}");
    }

    #[test]
    fn xinetd_package_itself_is_exempt() {
        // The exemption reverses this test's previous pin: the
        // deprecation tells every OTHER package not to ship
        // xinetd configuration; the xinetd package's own bundled
        // configs are exempt. The exemption keys on the package name,
        // not on the config state, so it holds whatever the bundled
        // definitions say.
        let pkg = pkg_named_with_files(
            "xinetd",
            &["/etc/xinetd.d/daytime", "/etc/xinetd.d/chargen"],
        );
        let results = run_check(&pkg);
        assert!(
            results.iter().all(|(n, _)| n != "deprecated-xinetd-config"),
            "{results:?}"
        );
    }

    #[test]
    fn xinetd_named_lookalikes_still_fire() {
        // Only the exact package name `xinetd` is exempt; a package
        // that merely carries xinetd in its name keeps firing.
        let pkg = pkg_named_with_files("uucp-xinetd", &["/etc/xinetd.d/uucp"]);
        let results = run_check(&pkg);
        assert!(
            results.iter().any(|(n, _)| n == "deprecated-xinetd-config"),
            "{results:?}"
        );
    }

    /// Run the check the way a default run does: the bundled default config
    /// (bundled defaults plus the vendored flavour layer) selects it and
    /// `check::build` constructs it.
    fn run_bundled_default_check(pkg: &Pkg) -> Vec<(String, String)> {
        let config = crate::config::load_bundled();
        assert!(
            config.checks.iter().any(|c| c == "XinetdDepCheck"),
            "the bundled default config must select XinetdDepCheck"
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check =
            crate::check::build("XinetdDepCheck", &config).expect("XinetdDepCheck is registered");
        check.check_binary(pkg, &config, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn default_config_run_flags_xinetd_requirement() {
        use crate::pkg::dep::DepInfo;
        let mut pkg = pkg_named_with_files("uucp-xinetd", &[]);
        pkg.requires.push(DepInfo {
            name: "xinetd".to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        });
        let results = run_bundled_default_check(&pkg);
        assert!(
            results
                .iter()
                .any(|(n, _)| n == "obsolete-xinetd-requirement"),
            "{results:?}"
        );
    }

    #[test]
    fn default_config_run_flags_xinetd_config_file() {
        let pkg = pkg_named_with_files("amanda", &["/etc/xinetd.d/amanda"]);
        let results = run_bundled_default_check(&pkg);
        assert!(
            results.iter().any(|(n, _)| n == "deprecated-xinetd-config"),
            "{results:?}"
        );
    }
}
