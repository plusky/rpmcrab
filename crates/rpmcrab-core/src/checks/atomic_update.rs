//! `AtomicUpdateCheck` — files must live inside the snapshot (`/etc`, `/usr`).
//!
//! Ported from `rpmlint/checks/AtomicUpdateCheck.py`. Two findings:
//! `dir-or-file-outside-snapshot` (E) and `ghost-outside-snapshot` (W).

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct AtomicUpdateCheck {
    check_ghosts: bool,
    allowed_dirs: Vec<String>,
    disallowed_subdirs: Vec<String>,
}

/// The reference indexes `config.configuration[...]` directly, so a missing
/// key raises `KeyError`; fail just as loudly instead of silently defaulting
/// (an empty allowed-dirs list would flag every file in the package).
fn required<'a>(cfg: &'a toml::Table, key: &str) -> &'a toml::Value {
    cfg.get(key)
        .unwrap_or_else(|| panic!("AtomicUpdateCheck: required config key '{key}' is missing"))
}

fn str_list(value: &toml::Value, key: &str) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| {
            panic!("AtomicUpdateCheck: config key '{key}' must be a list of strings")
        })
        .iter()
        .filter_map(toml::Value::as_str)
        .map(String::from)
        .collect()
}

impl AtomicUpdateCheck {
    pub fn new(config: &Config) -> Self {
        let cfg = &config.configuration;
        Self {
            check_ghosts: required(cfg, "AtomicCheckGhosts")
                .as_bool()
                .expect("AtomicUpdateCheck: config key 'AtomicCheckGhosts' must be a boolean"),
            allowed_dirs: str_list(required(cfg, "AtomicAllowedDirs"), "AtomicAllowedDirs"),
            disallowed_subdirs: str_list(
                required(cfg, "AtomicDisallowedSubdirs"),
                "AtomicDisallowedSubdirs",
            ),
        }
    }

    /// True when `path` is inside an allowed dir and not in a disallowed subdir.
    fn path_allowed(&self, path: &str) -> bool {
        let allowed = self.allowed_dirs.iter().any(|d| path.starts_with(d));
        let disallowed = self.disallowed_subdirs.iter().any(|d| path.starts_with(d));
        allowed && !disallowed
    }
}

impl Check for AtomicUpdateCheck {
    fn name(&self) -> &'static str {
        "AtomicUpdateCheck"
    }

    fn check(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }
        for pkgfile in &pkg.files {
            let name = pkgfile.name.as_str();
            if pkgfile.is_ghost() {
                continue;
            }
            if !self.path_allowed(name) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "dir-or-file-outside-snapshot",
                    &[name],
                );
            }
        }
        if self.check_ghosts {
            for ghost in &pkg.ghost_files {
                if !self.path_allowed(ghost) {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "ghost-outside-snapshot",
                        &[ghost.as_str()],
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
    use crate::pkg::pkgfile::{PkgFile, RPMFILE_GHOST};

    /// `Pkg` is header-backed with no test constructor, so open a tiny fixture
    /// and rewrite the public fields the check reads.
    fn fixture_pkg() -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir()).expect("open fixture pkg");
        pkg.name = "atomic-test".to_string();
        pkg.arch = "x86_64".to_string();
        pkg
    }

    fn regular(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            ..Default::default()
        }
    }

    fn ghost(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            flags: RPMFILE_GHOST,
            ..Default::default()
        }
    }

    fn check_with(allowed: &[&str], disallowed: &[&str], ghosts: bool) -> AtomicUpdateCheck {
        let mut table = toml::Table::new();
        table.insert(
            "AtomicAllowedDirs".to_string(),
            toml::Value::Array(
                allowed
                    .iter()
                    .map(|s| toml::Value::String(s.to_string()))
                    .collect(),
            ),
        );
        table.insert(
            "AtomicDisallowedSubdirs".to_string(),
            toml::Value::Array(
                disallowed
                    .iter()
                    .map(|s| toml::Value::String(s.to_string()))
                    .collect(),
            ),
        );
        table.insert(
            "AtomicCheckGhosts".to_string(),
            toml::Value::Boolean(ghosts),
        );
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        AtomicUpdateCheck::new(&config)
    }

    fn run(check: &mut AtomicUpdateCheck, pkg: &Pkg) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check(pkg, &config, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn allowed_path_passes() {
        let c = check_with(&["/usr", "/etc"], &[], false);
        assert!(c.path_allowed("/usr/bin/foo"));
        assert!(c.path_allowed("/etc/bar.conf"));
    }

    #[test]
    fn disallowed_path_fails() {
        let c = check_with(&["/usr", "/etc"], &[], false);
        assert!(!c.path_allowed("/var/lib/foo"));
        assert!(!c.path_allowed("/opt/bar"));
    }

    #[test]
    fn disallowed_subdir_fails() {
        let c = check_with(&["/usr"], &["/usr/local"], false);
        assert!(!c.path_allowed("/usr/local/bin/foo"));
        assert!(c.path_allowed("/usr/bin/foo"));
    }

    #[test]
    fn files_outside_snapshot_are_errors() {
        let mut pkg = fixture_pkg();
        pkg.files = vec![
            regular("/usr/bin/ok"),
            regular("/etc/ok.conf"),
            regular("/var/lib/outside"),
            regular("/usr/local/bin/disallowed"),
        ];
        let mut check = check_with(&["/usr", "/etc"], &["/usr/local"], false);
        let results = run(&mut check, &pkg);
        assert_eq!(results.len(), 2);
        for (name, line) in &results {
            assert_eq!(name, "dir-or-file-outside-snapshot");
            assert!(line.contains(": E: "), "level: {line}");
        }
        assert!(
            results[0].1.contains("/var/lib/outside"),
            "{}",
            results[0].1
        );
        assert!(
            results[1].1.contains("/usr/local/bin/disallowed"),
            "{}",
            results[1].1
        );
    }

    #[test]
    fn ghost_outside_snapshot_is_warning_when_enabled() {
        let mut pkg = fixture_pkg();
        pkg.files = vec![regular("/usr/bin/ok"), ghost("/var/cache/state")];
        pkg.ghost_files = vec!["/var/cache/state".to_string()];
        let mut check = check_with(&["/usr", "/etc"], &[], true);
        let results = run(&mut check, &pkg);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "ghost-outside-snapshot");
        assert!(results[0].1.contains(": W: "), "level: {}", results[0].1);
        assert!(
            results[0].1.contains("/var/cache/state"),
            "detail: {}",
            results[0].1
        );
    }

    #[test]
    fn ghosts_ignored_when_disabled() {
        let mut pkg = fixture_pkg();
        pkg.files = vec![regular("/usr/bin/ok"), ghost("/var/cache/state")];
        pkg.ghost_files = vec!["/var/cache/state".to_string()];
        let mut check = check_with(&["/usr", "/etc"], &[], false);
        assert!(run(&mut check, &pkg).is_empty());
    }

    #[test]
    fn ghost_inside_snapshot_is_quiet() {
        let mut pkg = fixture_pkg();
        pkg.files = vec![regular("/usr/bin/ok"), ghost("/etc/ghost.conf")];
        pkg.ghost_files = vec!["/etc/ghost.conf".to_string()];
        let mut check = check_with(&["/usr", "/etc"], &[], true);
        assert!(run(&mut check, &pkg).is_empty());
    }

    #[test]
    fn source_package_is_skipped() {
        let mut pkg = fixture_pkg();
        pkg.is_source = true;
        pkg.files = vec![regular("/var/lib/outside")];
        let mut check = check_with(&["/usr", "/etc"], &[], false);
        assert!(run(&mut check, &pkg).is_empty());
    }

    #[test]
    #[should_panic(expected = "required config key 'AtomicAllowedDirs' is missing")]
    fn missing_allowed_dirs_panics() {
        let mut table = toml::Table::new();
        table.insert("AtomicCheckGhosts".to_string(), toml::Value::Boolean(false));
        table.insert(
            "AtomicDisallowedSubdirs".to_string(),
            toml::Value::Array(vec![]),
        );
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = AtomicUpdateCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "required config key 'AtomicDisallowedSubdirs' is missing")]
    fn missing_disallowed_subdirs_panics() {
        let mut table = toml::Table::new();
        table.insert("AtomicCheckGhosts".to_string(), toml::Value::Boolean(false));
        table.insert("AtomicAllowedDirs".to_string(), toml::Value::Array(vec![]));
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = AtomicUpdateCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "required config key 'AtomicCheckGhosts' is missing")]
    fn missing_check_ghosts_panics() {
        let mut table = toml::Table::new();
        table.insert("AtomicAllowedDirs".to_string(), toml::Value::Array(vec![]));
        table.insert(
            "AtomicDisallowedSubdirs".to_string(),
            toml::Value::Array(vec![]),
        );
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = AtomicUpdateCheck::new(&config);
    }
}
