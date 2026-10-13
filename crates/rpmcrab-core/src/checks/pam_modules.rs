//! `PAMModulesCheck` — PAM modules must be reviewable and authorized.
//!
//! Ported from `rpmlint/checks/PAMModulesCheck.py`. Two findings:
//! `pam-ghost-module` and `pam-unauthorized-module`.
//!
//! The authorized set is the `PAMAuthorizedModules` config list plus
//! every module named by a `FileDigestGroup` of type `pam` — the distro
//! security-review data `FileDigestCheck` consumes — so the module
//! authorization lives in exactly one place and the two checks cannot
//! drift apart.

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct PAMModulesCheck {
    pam_module_re: Regex,
    authorized: Vec<String>,
}

impl PAMModulesCheck {
    pub fn new(config: &Config) -> Self {
        let mut authorized: Vec<String> = config
            .configuration
            .get("PAMAuthorizedModules")
            .and_then(toml::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        // Derive the rest of the authorized set from the FileDigestGroup
        // data: every `digests` path and `nodigests` entry of a `pam`
        // group names a module the security review has covered.
        if let Some(groups) = config
            .configuration
            .get("FileDigestGroup")
            .and_then(toml::Value::as_array)
        {
            for group in groups {
                let Some(table) = group.as_table() else {
                    continue;
                };
                if table.get("type").and_then(toml::Value::as_str) != Some("pam") {
                    continue;
                }
                let mut paths: Vec<&str> = Vec::new();
                if let Some(digests) = table.get("digests").and_then(toml::Value::as_array) {
                    paths.extend(
                        digests
                            .iter()
                            .filter_map(|d| d.as_table()?.get("path")?.as_str()),
                    );
                }
                if let Some(nodigests) = table.get("nodigests").and_then(toml::Value::as_array) {
                    paths.extend(nodigests.iter().filter_map(toml::Value::as_str));
                }
                for path in paths {
                    let path = path.strip_prefix("glob:").unwrap_or(path);
                    if let Some(base) = path
                        .rsplit('/')
                        .next()
                        .filter(|b| b.ends_with(".so") && !b.contains('*'))
                        && !authorized.iter().any(|a| a == base)
                    {
                        authorized.push(base.to_string());
                    }
                }
            }
        }
        Self {
            pam_module_re: Regex::new(r"^(?:/usr)?/lib(?:64)?/security/([^/]+\.so)$")
                .expect("static regex"),
            authorized,
        }
    }

    /// `(finding, detail)` for PAM module files. `files` yields file names;
    /// `ghosts` holds the ghosted names.
    fn findings<'a>(
        &self,
        files: impl Iterator<Item = &'a str>,
        ghosts: &[&str],
    ) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        for fname in files {
            let Ok(Some(caps)) = self.pam_module_re.captures(fname) else {
                continue;
            };
            if ghosts.contains(&fname) {
                out.push(("pam-ghost-module", fname.to_string()));
                continue;
            }
            let basename = caps
                .get(1)
                .map(|m| m.as_str())
                .unwrap_or_default()
                .to_string();
            if !self.authorized.iter().any(|a| a == &basename) {
                out.push(("pam-unauthorized-module", basename));
            }
        }
        out
    }
}

impl Check for PAMModulesCheck {
    fn name(&self) -> &'static str {
        "PAMModulesCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let ghosts: Vec<&str> = pkg.ghost_files.iter().map(|s| s.as_str()).collect();
        let files = pkg.files.iter().map(|f| f.name.as_str());
        for (finding, detail) in self.findings(files, &ghosts) {
            add_info(out, Level::Error, pkg, finding, &[&detail]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::color::Color;
    use crate::pkg::pkgfile::PkgFile;

    fn checker(authorized: &[&str]) -> PAMModulesCheck {
        let mut config = Config::default();
        config.configuration.insert(
            "PAMAuthorizedModules".to_string(),
            toml::Value::Array(
                authorized
                    .iter()
                    .map(|s| toml::Value::String(s.to_string()))
                    .collect(),
            ),
        );
        PAMModulesCheck::new(&config)
    }

    #[test]
    fn authorized_module_is_quiet() {
        let c = checker(&["pam_unix.so"]);
        let found = c.findings(["/usr/lib64/security/pam_unix.so"].into_iter(), &[]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn unauthorized_module_is_flagged() {
        let c = checker(&["pam_unix.so"]);
        let found = c.findings(["/lib/security/pam_evil.so"].into_iter(), &[]);
        assert_eq!(
            found,
            vec![("pam-unauthorized-module", "pam_evil.so".to_string())]
        );
    }

    #[test]
    fn ghost_module_is_flagged() {
        let c = checker(&["pam_unix.so"]);
        let found = c.findings(
            ["/usr/lib/security/pam_unix.so"].into_iter(),
            &["/usr/lib/security/pam_unix.so"],
        );
        assert_eq!(
            found,
            vec![(
                "pam-ghost-module",
                "/usr/lib/security/pam_unix.so".to_string()
            )]
        );
    }

    #[test]
    fn non_pam_paths_are_skipped() {
        let c = checker(&[]);
        let found = c.findings(["/usr/bin/tool"].into_iter(), &[]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn empty_authorized_list_flags_everything() {
        let c = checker(&[]);
        let found = c.findings(["/lib64/security/pam_unix.so"].into_iter(), &[]);
        assert_eq!(
            found,
            vec![("pam-unauthorized-module", "pam_unix.so".to_string())]
        );
    }

    #[test]
    fn check_binary_entry_point_reports_unauthorized_module() {
        // Kills the neutered-`check_binary` mutant: ghost collection + file
        // iteration + `add_info` must run for the finding to reach `Filter`.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.files = vec![PkgFile {
            name: "/lib/security/pam_evil.so".to_string(),
            ..Default::default()
        }];
        pkg.ghost_files = vec![];
        let mut check = checker(&["pam_unix.so"]);
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&"pam-unauthorized-module"),
            "expected pam-unauthorized-module in {names:?}"
        );
    }

    fn group(type_: &str, nodigests: &[&str], digest_paths: &[&str]) -> toml::Value {
        let mut table = toml::map::Map::new();
        table.insert("type".to_string(), toml::Value::String(type_.to_string()));
        table.insert(
            "package".to_string(),
            toml::Value::String("somepkg".to_string()),
        );
        if !nodigests.is_empty() {
            table.insert(
                "nodigests".to_string(),
                toml::Value::Array(
                    nodigests
                        .iter()
                        .map(|s| toml::Value::String(s.to_string()))
                        .collect(),
                ),
            );
        }
        if !digest_paths.is_empty() {
            table.insert(
                "digests".to_string(),
                toml::Value::Array(
                    digest_paths
                        .iter()
                        .map(|path| {
                            let mut d = toml::map::Map::new();
                            d.insert("path".to_string(), toml::Value::String(path.to_string()));
                            toml::Value::Table(d)
                        })
                        .collect(),
                ),
            );
        }
        toml::Value::Table(table)
    }

    fn checker_with_groups(authorized: &[&str], groups: Vec<toml::Value>) -> PAMModulesCheck {
        let mut config = Config::default();
        config.configuration.insert(
            "PAMAuthorizedModules".to_string(),
            toml::Value::Array(
                authorized
                    .iter()
                    .map(|s| toml::Value::String(s.to_string()))
                    .collect(),
            ),
        );
        config
            .configuration
            .insert("FileDigestGroup".to_string(), toml::Value::Array(groups));
        PAMModulesCheck::new(&config)
    }

    #[test]
    fn module_authorised_by_digest_group_nodigests_is_quiet() {
        let c = checker_with_groups(
            &[],
            vec![group("pam", &["glob:*/security/pam_krb5.so"], &[])],
        );
        let found = c.findings(["/usr/lib64/security/pam_krb5.so"].into_iter(), &[]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn module_authorised_by_digest_group_digest_path_is_quiet() {
        let c = checker_with_groups(
            &[],
            vec![group("pam", &[], &["/usr/lib64/security/pam_winbind.so"])],
        );
        let found = c.findings(["/usr/lib64/security/pam_winbind.so"].into_iter(), &[]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn non_pam_group_does_not_authorise() {
        let c = checker_with_groups(
            &[],
            vec![group("dbus", &["glob:*/security/pam_evil.so"], &[])],
        );
        let found = c.findings(["/lib/security/pam_evil.so"].into_iter(), &[]);
        assert_eq!(
            found,
            vec![("pam-unauthorized-module", "pam_evil.so".to_string())]
        );
    }

    #[test]
    fn group_entries_without_so_do_not_authorise() {
        // A pam group also names non-module files (e.g. /etc/pam.d
        // entries); only *.so basenames may join the authorized set.
        let c = checker_with_groups(
            &[],
            vec![group(
                "pam",
                &["glob:*/security/README"],
                &["/etc/pam.d/login"],
            )],
        );
        let found = c.findings(["/usr/lib/security/pam_unix.so"].into_iter(), &[]);
        assert_eq!(
            found,
            vec![("pam-unauthorized-module", "pam_unix.so".to_string())]
        );
    }

    #[test]
    fn explicit_list_and_group_data_union() {
        let c = checker_with_groups(
            &["pam_unix.so"],
            vec![group("pam", &["glob:*/security/pam_krb5.so"], &[])],
        );
        let found = c.findings(
            [
                "/usr/lib64/security/pam_unix.so",
                "/usr/lib64/security/pam_krb5.so",
                "/usr/lib64/security/pam_evil.so",
            ]
            .into_iter(),
            &[],
        );
        assert_eq!(
            found,
            vec![("pam-unauthorized-module", "pam_evil.so".to_string())]
        );
    }

    fn pkg_with_files(files: &[&str]) -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.files = files
            .iter()
            .map(|n| PkgFile {
                name: n.to_string(),
                ..Default::default()
            })
            .collect();
        pkg.ghost_files = vec![];
        pkg
    }

    /// Run the check the way a default run does: the bundled defaults
    /// select it and `check::build` constructs it. `load_bundled` skips
    /// the vendored flavour layer by design, so the test layers the
    /// vendored `pam-modules.toml` data in explicitly — that file carries
    /// the FileDigestGroup data the authorized set derives from.
    fn run_bundled_default_check(pkg: &Pkg) -> Vec<(String, String)> {
        let mut config = crate::config::load_bundled();
        assert!(
            config.checks.iter().any(|c| c == "PAMModulesCheck"),
            "the bundled default config must select PAMModulesCheck"
        );
        let pam_data =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("data/distro/opensuse/pam-modules.toml");
        let parsed: toml::Table =
            toml::from_str(&std::fs::read_to_string(pam_data).expect("vendored pam data"))
                .expect("vendored pam data parses");
        config.configuration.insert(
            "FileDigestGroup".to_string(),
            parsed["FileDigestGroup"].clone(),
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check =
            crate::check::build("PAMModulesCheck", &config).expect("PAMModulesCheck is registered");
        check.check_binary(pkg, &config, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn default_config_run_authorises_reviewed_module() {
        let pkg = pkg_with_files(&["/usr/lib64/security/pam_unix.so"]);
        let results = run_bundled_default_check(&pkg);
        assert!(
            !results.iter().any(|(n, _)| n == "pam-unauthorized-module"),
            "{results:?}"
        );
    }

    #[test]
    fn default_config_run_flags_unreviewed_module() {
        let pkg = pkg_with_files(&["/usr/lib64/security/pam_unreviewed_evil.so"]);
        let results = run_bundled_default_check(&pkg);
        assert!(
            results.iter().any(|(n, _)| n == "pam-unauthorized-module"),
            "{results:?}"
        );
    }
}
