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

impl AtomicUpdateCheck {
    pub fn new(config: &Config) -> Self {
        let cfg = &config.configuration;
        Self {
            check_ghosts: cfg
                .get("AtomicCheckGhosts")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false),
            allowed_dirs: cfg
                .get("AtomicAllowedDirs")
                .and_then(toml::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(toml::Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default(),
            disallowed_subdirs: cfg
                .get("AtomicDisallowedSubdirs")
                .and_then(toml::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(toml::Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default(),
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
                    add_info(out, Level::Warning, pkg, "ghost-outside-snapshot", &[ghost]);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
