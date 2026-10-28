//! `ConfigFilesCheck` — configuration files must be in `/etc` or `/var` and
//! marked `noreplace`.
//!
//! Ported from `rpmlint/checks/ConfigFilesCheck.py`. Two findings:
//! `non-etc-or-var-file-marked-as-conffile` (info) and
//! `conffile-without-noreplace-flag` (warning). A third finding,
//! `usr-etc-file-marked-as-conffile` (warning), is crab-only — the
//! reference has no UsrEtc rule; its predicate lives with the
//! transactional-update family in `checks::atomic_update`.

use crate::check::{Check, add_info};
use crate::checks::atomic_update::usr_etc_conffile;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile;

pub struct ConfigFilesCheck;

impl ConfigFilesCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// Returns the findings for `filename` with their levels, or an
    /// empty vec when it is fine. `noreplace` indicates whether the
    /// file has the noreplace flag. A `ghost` entry ships no vendor
    /// content, so the noreplace finding does not apply to it: the
    /// flag protects a shipped default against local edits, and a
    /// ghost has no shipped default. A symlink entry ships no
    /// content of its own either — the content lives at the link
    /// target — so the noreplace finding does not apply to it for
    /// the same reason. The placement finding still applies to
    /// both — it judges the `%config` mark itself.
    fn check_one(
        filename: &str,
        noreplace: bool,
        ghost: bool,
        symlink: bool,
    ) -> Vec<(&'static str, Level)> {
        let mut out = Vec::new();
        if !filename.starts_with("/etc/") && !filename.starts_with("/var/") {
            out.push(("non-etc-or-var-file-marked-as-conffile", Level::Info));
        }
        if !noreplace && !ghost && !symlink {
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
        let symlink_files: std::collections::HashSet<&str> = pkg
            .files
            .iter()
            .filter(|f| pkgfile::is_symlink(f.mode))
            .map(|f| f.name.as_str())
            .collect();
        for filename in &pkg.config_files {
            for (finding, level) in Self::check_one(
                filename,
                pkg.noreplace_files.contains(filename),
                pkg.ghost_files.contains(filename),
                symlink_files.contains(filename.as_str()),
            ) {
                add_info(out, level, pkg, finding, &[filename]);
            }
        }
        // UsrEtc: /usr/etc holds vendor defaults, not administrator
        // configuration, so the `%config` mark is wrong there no matter
        // what the placement findings above said about the same file.
        for pkgfile in &pkg.files {
            if usr_etc_conffile(pkgfile) {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "usr-etc-file-marked-as-conffile",
                    &[pkgfile.name.as_str()],
                );
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
        assert!(ConfigFilesCheck::check_one("/etc/foo.conf", true, false, false).is_empty());
    }

    #[test]
    fn var_noreplace_is_quiet() {
        assert!(ConfigFilesCheck::check_one("/var/lib/foo.conf", true, false, false).is_empty());
    }

    #[test]
    fn non_etc_var_is_flagged() {
        let findings = ConfigFilesCheck::check_one("/usr/share/foo.conf", true, false, false);
        assert_eq!(
            findings,
            vec![("non-etc-or-var-file-marked-as-conffile", Level::Info)]
        );
    }

    #[test]
    fn missing_noreplace_is_flagged() {
        let findings = ConfigFilesCheck::check_one("/etc/foo.conf", false, false, false);
        assert_eq!(
            findings,
            vec![("conffile-without-noreplace-flag", Level::Warning)]
        );
    }

    #[test]
    fn ghost_conffile_without_noreplace_is_quiet() {
        // A %ghost %config entry ships no vendor content: there is
        // no shipped default for noreplace to protect, so the
        // missing flag is not a finding (the apparmor-profiles
        // shape: dozens of %ghost %config placeholders under
        // /etc/apparmor.d/local).
        assert!(ConfigFilesCheck::check_one("/etc/foo.conf", false, true, false).is_empty());
    }

    #[test]
    fn ghost_conffile_outside_etc_reports_placement_only() {
        // Only the noreplace finding is ghost-exempt: the placement
        // finding judges the %config mark itself and still fires.
        let findings = ConfigFilesCheck::check_one("/opt/foo.conf", false, true, false);
        assert_eq!(
            findings,
            vec![("non-etc-or-var-file-marked-as-conffile", Level::Info)]
        );
    }

    #[test]
    fn symlink_conffile_without_noreplace_is_quiet() {
        // A %config symlink ships no content of its own: there is
        // no shipped default for noreplace to protect, so the
        // missing flag is not a finding (the fontconfig shape:
        // /etc/fonts/conf.d links into /usr/share/fontconfig).
        assert!(ConfigFilesCheck::check_one("/etc/foo.conf", false, false, true).is_empty());
    }

    #[test]
    fn symlink_conffile_outside_etc_reports_placement_only() {
        // Only the noreplace finding is symlink-exempt: the
        // placement finding judges the %config mark itself and
        // still fires.
        let findings = ConfigFilesCheck::check_one("/opt/foo.conf", false, false, true);
        assert_eq!(
            findings,
            vec![("non-etc-or-var-file-marked-as-conffile", Level::Info)]
        );
    }

    #[test]
    fn both_problems_both_findings() {
        let findings = ConfigFilesCheck::check_one("/opt/foo.conf", false, false, false);
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
    fn check_binary_entry_point_skips_ghost_conffiles() {
        // Kills the ghost-blind glue mutant: `check_binary` must
        // consult `pkg.ghost_files`, so the ghost conffile without
        // noreplace stays quiet while the real one beside it fires.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.config_files = vec!["/etc/ghost.conf".to_string(), "/etc/real.conf".to_string()];
        pkg.noreplace_files = vec![];
        pkg.ghost_files = vec!["/etc/ghost.conf".to_string()];
        pkg.files = vec![];
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = ConfigFilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let hits: Vec<&(String, String)> = out
            .results()
            .iter()
            .filter(|(n, _)| n == "conffile-without-noreplace-flag")
            .collect();
        assert_eq!(hits.len(), 1, "results: {:?}", out.results());
        assert!(
            hits[0].1.contains("/etc/real.conf"),
            "detail: {}",
            hits[0].1
        );
    }

    #[test]
    fn check_binary_entry_point_skips_symlink_conffiles() {
        // Kills the symlink-blind glue mutant: `check_binary` must
        // consult the entry modes, so the symlink conffile without
        // noreplace stays quiet while the regular one beside it
        // fires.
        use crate::pkg::pkgfile::{PkgFile, RPMFILE_CONFIG};
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.config_files = vec!["/etc/link.conf".to_string(), "/etc/real.conf".to_string()];
        pkg.noreplace_files = vec![];
        pkg.ghost_files = vec![];
        pkg.files = vec![
            PkgFile {
                name: "/etc/link.conf".to_string(),
                mode: 0o120777,
                flags: RPMFILE_CONFIG,
                ..Default::default()
            },
            PkgFile {
                name: "/etc/real.conf".to_string(),
                mode: 0o100644,
                flags: RPMFILE_CONFIG,
                ..Default::default()
            },
        ];
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = ConfigFilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let hits: Vec<&(String, String)> = out
            .results()
            .iter()
            .filter(|(n, _)| n == "conffile-without-noreplace-flag")
            .collect();
        assert_eq!(hits.len(), 1, "results: {:?}", out.results());
        assert!(
            hits[0].1.contains("/etc/real.conf"),
            "detail: {}",
            hits[0].1
        );
    }

    #[test]
    fn check_binary_entry_point_reports_usr_etc_conffile() {
        // Kills the neutered-wiring mutant: the loop over `pkg.files`
        // must run the family predicate for the finding to reach the
        // `Filter`, exactly once per marked /usr/etc entry.
        use crate::pkg::pkgfile::{PkgFile, RPMFILE_CONFIG, RPMFILE_GHOST, RPMFILE_NOREPLACE};
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.config_files = vec![];
        pkg.noreplace_files = vec![];
        pkg.files = vec![
            PkgFile {
                name: "/usr/etc/foo.conf".to_string(),
                mode: 0o100644,
                flags: RPMFILE_CONFIG | RPMFILE_NOREPLACE,
                ..Default::default()
            },
            PkgFile {
                name: "/usr/etc/plain.conf".to_string(),
                mode: 0o100644,
                ..Default::default()
            },
            PkgFile {
                name: "/etc/foo.conf".to_string(),
                mode: 0o100644,
                flags: RPMFILE_CONFIG,
                ..Default::default()
            },
            // A %ghost ships no vendor default: excluded.
            PkgFile {
                name: "/usr/etc/ghost.conf".to_string(),
                mode: 0o100644,
                flags: RPMFILE_CONFIG | RPMFILE_GHOST,
                ..Default::default()
            },
            // A directory never gets .rpmnew/.rpmsave treatment: excluded.
            PkgFile {
                name: "/usr/etc/subdir".to_string(),
                mode: 0o040755,
                flags: RPMFILE_CONFIG,
                ..Default::default()
            },
        ];
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = ConfigFilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let hits: Vec<&(String, String)> = out
            .results()
            .iter()
            .filter(|(n, _)| n == "usr-etc-file-marked-as-conffile")
            .collect();
        assert_eq!(hits.len(), 1, "results: {:?}", out.results());
        assert!(hits[0].1.contains(": W: "), "level: {}", hits[0].1);
        assert!(
            hits[0].1.contains("/usr/etc/foo.conf"),
            "detail: {}",
            hits[0].1
        );
    }

    #[test]
    fn staged_descriptions_carry_deliberate_rewords() {
        // Staged for the M2 `--explain` wiring (see data/descriptions/README.md).
        // `non-etc-or-var-file-marked-as-conffile` carries the reword from
        // upstream #1606 (dropping `%config` named as an option, not just
        // moving files), byte-identical to the reference (pinned
        // rpmlint@84848c0). `conffile-without-noreplace-flag` carries the
        // rpmcrab#556 reword: both `%config` forms are valid, and
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
            table["usr-etc-file-marked-as-conffile"].as_str(),
            Some(
                "A file in /usr/etc is marked as a configuration file (%config).\n\
                 Files in /usr/etc are vendor defaults; administrator configuration\n\
                 belongs in /etc, which takes precedence over them. The %config mark\n\
                 makes rpm preserve local edits to the vendor default across updates\n\
                 (.rpmsave/.rpmnew), which fights the /usr/etc split. Remove the\n\
                 %config attribute from the corresponding line in the %files section.\n"
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
