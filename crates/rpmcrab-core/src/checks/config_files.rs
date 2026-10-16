//! `ConfigFilesCheck` — configuration files must be in `/etc` or `/var` and
//! marked `noreplace`.
//!
//! Ported from `rpmlint/checks/ConfigFilesCheck.py`. Two findings:
//! `non-etc-or-var-file-marked-as-conffile` (info) and
//! `conffile-without-noreplace-flag` (warning).

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

    /// Returns the findings for `filename` with their levels, or an
    /// empty vec when it is fine. `noreplace` indicates whether the
    /// file has the noreplace flag.
    fn check_one(filename: &str, noreplace: bool) -> Vec<(&'static str, Level)> {
        let mut out = Vec::new();
        if !filename.starts_with("/etc/") && !filename.starts_with("/var/") {
            out.push(("non-etc-or-var-file-marked-as-conffile", Level::Info));
        }
        if !noreplace {
            out.push(("conffile-without-noreplace-flag", Level::Warning));
        }
        out
    }
}

impl Check for ConfigFilesCheck {
    fn name(&self) -> &'static str {
        "ConfigFilesCheck"
    }

    /// This check never emits errors (its findings are warnings and
    /// info), so `--errors-only` skips it.
    fn max_severity(&self) -> Level {
        Level::Warning
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        // `pkg.config_files` lists the paths; `noreplace_files` lists those
        // with the flag. Mirror the reference's two loops over the same list.
        for filename in &pkg.config_files {
            for (finding, level) in
                Self::check_one(filename, pkg.noreplace_files.contains(filename))
            {
                add_info(out, level, pkg, finding, &[filename]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::color::Color;

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
        assert_eq!(
            findings,
            vec![("non-etc-or-var-file-marked-as-conffile", Level::Info)]
        );
    }

    #[test]
    fn missing_noreplace_is_flagged() {
        let findings = ConfigFilesCheck::check_one("/etc/foo.conf", false);
        assert_eq!(
            findings,
            vec![("conffile-without-noreplace-flag", Level::Warning)]
        );
    }

    #[test]
    fn both_problems_both_findings() {
        let findings = ConfigFilesCheck::check_one("/opt/foo.conf", false);
        assert_eq!(
            findings,
            vec![
                ("non-etc-or-var-file-marked-as-conffile", Level::Info),
                ("conffile-without-noreplace-flag", Level::Warning)
            ]
        );
    }

    #[test]
    fn check_binary_entry_point_reports_both_findings() {
        // Kills the neutered-`check_binary` mutant: the glue over
        // `pkg.config_files`/`pkg.noreplace_files` must run for the findings
        // to reach the `Filter`.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.config_files = vec!["/opt/foo.conf".to_string()];
        pkg.noreplace_files = vec![];
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = ConfigFilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&"non-etc-or-var-file-marked-as-conffile"),
            "expected non-etc-or-var-file-marked-as-conffile in {names:?}"
        );
        assert!(
            names.contains(&"conffile-without-noreplace-flag"),
            "expected conffile-without-noreplace-flag in {names:?}"
        );
    }
    #[test]
    fn staged_descriptions_carry_deliberate_rewords() {
        // Staged for the M2 `--explain` wiring (see data/descriptions/README.md).
        // `non-etc-or-var-file-marked-as-conffile` carries the reword from
        // upstream #1606 (dropping `%config` named as an option, not just
        // moving files), byte-identical to the reference (pinned
        // rpmlint@84848c0). `conffile-without-noreplace-flag` carries the
        // reword ruled in rpmcrab#556: both `%config` forms are valid, and
        // the text lays out the .rpmsave/.rpmnew upgrade semantics the
        // choice turns on instead of prescribing noreplace; ledgered in
        // tests/parity/divergences.toml.
        let raw = include_str!("../../data/descriptions/ConfigFilesCheck.toml");
        let table: toml::Table = raw.parse().expect("staged descriptions are valid toml");
        assert_eq!(
            table["non-etc-or-var-file-marked-as-conffile"].as_str(),
            Some(
                "A file not in /etc or /var is marked as being a configuration file (%config).\n\
                 Put your configuration files in /etc or /var, or remove the %config attribute\n\
                 from the corresponding line in the %files section.\n"
            )
        );
        assert_eq!(
            table["conffile-without-noreplace-flag"].as_str(),
            Some(
                "A configuration file is stored in your package without the noreplace flag.\n\
                 Both %config and %config(noreplace) are valid; neither is wrong as such.\n\
                 The choice matters on upgrade: with plain %config a locally modified file\n\
                 is preserved as .rpmsave and the newly shipped file takes its place, so\n\
                 the local modifications stop being in effect; with %config(noreplace) the\n\
                 local modifications stay in effect and the newly shipped file arrives as\n\
                 .rpmnew instead. Consider per file which behaviour fits the file.\n"
            )
        );
    }
}
