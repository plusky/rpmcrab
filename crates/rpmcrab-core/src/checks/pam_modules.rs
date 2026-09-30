//! `PAMModulesCheck` — PAM modules must be reviewable and authorized.
//!
//! Ported from `rpmlint/checks/PAMModulesCheck.py`. Two findings:
//! `pam-ghost-module` and `pam-unauthorized-module`.

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
        let authorized = config
            .configuration
            .get("PAMAuthorizedModules")
            .and_then(toml::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
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
}
