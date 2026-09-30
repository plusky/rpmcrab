//! `ConfigFilesCheck` — configuration files must be in `/etc` or `/var` and
//! marked `noreplace`.
//!
//! Ported from `rpmlint/checks/ConfigFilesCheck.py`. Two findings, both
//! warnings: `non-etc-or-var-file-marked-as-conffile` and
//! `conffile-without-noreplace-flag`.

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct ConfigFilesCheck;

impl ConfigFilesCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// Returns the finding name for `filename`, or `None` when it is fine.
    /// `noreplace` indicates whether the file has the noreplace flag.
    fn check_one(filename: &str, noreplace: bool) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !filename.starts_with("/etc/") && !filename.starts_with("/var/") {
            out.push("non-etc-or-var-file-marked-as-conffile");
        }
        if !noreplace {
            out.push("conffile-without-noreplace-flag");
        }
        out
    }
}

impl Check for ConfigFilesCheck {
    fn name(&self) -> &'static str {
        "ConfigFilesCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        // `pkg.config_files` lists the paths; `noreplace_files` lists those
        // with the flag. Mirror the reference's two loops over the same list.
        for filename in &pkg.config_files {
            for finding in Self::check_one(filename, pkg.noreplace_files.contains(filename)) {
                add_info(out, Level::Warning, pkg, finding, &[filename]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etc_noreplace_is_quiet() {
        assert!(ConfigFilesCheck::check_one("/etc/foo.conf", true).is_empty());
    }

    #[test]
    fn var_noreplace_is_quiet() {
        assert!(ConfigFilesCheck::check_one("/var/lib/foo.conf", true).is_empty());
    }

    #[test]
    fn non_etc_var_is_flagged() {
        let findings = ConfigFilesCheck::check_one("/usr/share/foo.conf", true);
        assert_eq!(findings, vec!["non-etc-or-var-file-marked-as-conffile"]);
    }

    #[test]
    fn missing_noreplace_is_flagged() {
        let findings = ConfigFilesCheck::check_one("/etc/foo.conf", false);
        assert_eq!(findings, vec!["conffile-without-noreplace-flag"]);
    }

    #[test]
    fn both_problems_both_findings() {
        let findings = ConfigFilesCheck::check_one("/opt/foo.conf", false);
        assert_eq!(
            findings,
            vec![
                "non-etc-or-var-file-marked-as-conffile",
                "conffile-without-noreplace-flag"
            ]
        );
    }
}
