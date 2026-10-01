//! `SysVInitOnSystemdCheck` — SysV init scripts on a systemd system.
//!
//! Ported from `rpmlint/checks/SysVInitOnSystemdCheck.py`. Findings:
//! `obsolete-insserv-requirement`, `deprecated-boot-script`,
//! `deprecated-init-script`, `systemd-shadowed-initscript`.

use std::path::Path;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct SysVInitOnSystemdCheck;

impl SysVInitOnSystemdCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// Classify file names into `(initscripts, bootscripts, systemdscripts)`.
    fn find_services_and_scripts<'a>(
        files: impl Iterator<Item = &'a str>,
        ghost_files: &[String],
    ) -> (Vec<String>, Vec<String>, Vec<String>) {
        let mut initscripts = Vec::new();
        let mut bootscripts = Vec::new();
        let mut systemdscripts = Vec::new();
        for name in files {
            if ghost_files.iter().any(|g| g == name) {
                continue;
            }
            if name.starts_with("/usr/lib/systemd/system/") {
                if name.contains('@') {
                    continue;
                }
                if name.ends_with(".service") || name.ends_with(".target") {
                    let basename = Path::new(name)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    systemdscripts.push(
                        basename
                            .as_str()
                            .rsplit_once('.')
                            .map(|(s, _)| s.to_string())
                            .unwrap_or_default(),
                    );
                }
            }
            if name.starts_with("/etc/init.d/") || name.starts_with("/etc/rc.d/init.d/") {
                let basename = Path::new(name)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if basename.starts_with("boot.") {
                    bootscripts.push(name.to_string());
                } else if !basename.starts_with("rc") {
                    initscripts.push(name.to_string());
                }
            }
        }
        initscripts.sort();
        bootscripts.sort();
        systemdscripts.sort();
        (initscripts, bootscripts, systemdscripts)
    }
}

impl Check for SysVInitOnSystemdCheck {
    fn name(&self) -> &'static str {
        "SysVInitOnSystemdCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let (initscripts, bootscripts, systemdscripts) = Self::find_services_and_scripts(
            pkg.files.iter().map(|f| f.name.as_str()),
            &pkg.ghost_files,
        );

        if pkg
            .requires
            .iter()
            .chain(pkg.prereq.iter())
            .any(|r| r.name == "insserv")
        {
            add_info(out, Level::Error, pkg, "obsolete-insserv-requirement", &[]);
        }

        for filename in &bootscripts {
            add_info(
                out,
                Level::Error,
                pkg,
                "deprecated-boot-script",
                &[filename],
            );
        }
        for filename in &initscripts {
            add_info(
                out,
                Level::Error,
                pkg,
                "deprecated-init-script",
                &[filename],
            );
            let stem = Path::new(filename)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if systemdscripts.iter().any(|s| s == &stem) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "systemd-shadowed-initscript",
                    &[filename],
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(names: &[&str]) -> (Vec<String>, Vec<String>, Vec<String>) {
        SysVInitOnSystemdCheck::find_services_and_scripts(names.iter().copied(), &[])
    }

    #[test]
    fn initscript_is_found() {
        let (init, boot, _) = classify(&["/etc/init.d/foo"]);
        assert_eq!(init, vec!["/etc/init.d/foo".to_string()]);
        assert!(boot.is_empty());
    }

    #[test]
    fn boot_script_is_found() {
        let (init, boot, _) = classify(&["/etc/init.d/boot.foo"]);
        assert!(init.is_empty());
        assert_eq!(boot, vec!["/etc/init.d/boot.foo".to_string()]);
    }

    #[test]
    fn rc_prefix_is_ignored() {
        let (init, boot, _) = classify(&["/etc/init.d/rcfoo"]);
        assert!(init.is_empty());
        assert!(boot.is_empty());
    }

    #[test]
    fn socket_service_is_ignored() {
        let (_, _, sysd) = classify(&["/usr/lib/systemd/system/foo@.service"]);
        assert!(sysd.is_empty());
    }

    #[test]
    fn service_stem_matches_initscript_basename() {
        let (init, _, sysd) = classify(&["/etc/init.d/foo", "/usr/lib/systemd/system/foo.service"]);
        assert_eq!(init, vec!["/etc/init.d/foo".to_string()]);
        assert_eq!(sysd, vec!["foo".to_string()]);
    }

    #[test]
    fn ghost_is_excluded() {
        let ghosts = vec!["/etc/init.d/foo".to_string()];
        let (init, _, _) = SysVInitOnSystemdCheck::find_services_and_scripts(
            ["/etc/init.d/foo"].into_iter(),
            &ghosts,
        );
        assert!(init.is_empty());
    }
}
