//! `FHSCheck` — validate that files are packaged according to the FHS.
//!
//! Ported from `rpmlint/checks/FHSCheck.py`. Two findings, both warnings:
//! `non-standard-dir-in-usr` and `non-standard-dir-in-var`.

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

/// Allowed subdirectories of `/usr` (FHS 3.0, chapters 4.2 and 4.3).
const FHS_USR_SUBDIRS: &[&str] = &[
    "bin", "lib", "local", "sbin", "share", "games", "include", "libexec", "lib64", "src", "spool",
    "tmp",
];

/// Allowed subdirectories of `/var` (FHS 3.0, chapters 5.2 and 5.3).
const FHS_VAR_SUBDIRS: &[&str] = &[
    "cache", "lib", "local", "lock", "log", "opt", "run", "spool", "tmp", "account", "crash",
    "games", "mail", "yp",
];

pub struct FHSCheck;

impl FHSCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// Returns `(dir_type, subdir)` for each non-standard top-level subdir
    /// found under `/usr` or `/var`, deduplicated. `dir_type` is `"usr"` or
    /// `"var"`.
    fn non_standard_dirs<'a>(files: impl Iterator<Item = &'a str>) -> Vec<(String, String)> {
        let mut seen_usr = Vec::new();
        let mut seen_var = Vec::new();
        let mut out = Vec::new();

        for fname in files {
            if let Some(rest) = fname.strip_prefix("/usr/") {
                let subdir: &str = rest.split('/').next().unwrap_or("");
                if !subdir.is_empty()
                    && !FHS_USR_SUBDIRS.contains(&subdir)
                    && !seen_usr.contains(&subdir)
                {
                    seen_usr.push(subdir);
                    out.push(("usr".to_string(), subdir.to_string()));
                }
            } else if let Some(rest) = fname.strip_prefix("/var/") {
                let subdir: &str = rest.split('/').next().unwrap_or("");
                if !subdir.is_empty()
                    && !FHS_VAR_SUBDIRS.contains(&subdir)
                    && !seen_var.contains(&subdir)
                {
                    seen_var.push(subdir);
                    out.push(("var".to_string(), subdir.to_string()));
                }
            }
        }
        out
    }
}

impl Check for FHSCheck {
    fn name(&self) -> &'static str {
        "FHSCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let names: Vec<&str> = pkg.files.iter().map(|f| f.name.as_str()).collect();
        for (dir_type, subdir) in Self::non_standard_dirs(names.into_iter()) {
            let check = format!("non-standard-dir-in-{dir_type}");
            add_info(out, Level::Warning, pkg, &check, &[&subdir]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_dirs_are_quiet() {
        let dirs = FHSCheck::non_standard_dirs(
            [
                "/usr/bin/foo",
                "/usr/share/doc/bar",
                "/var/log/baz",
                "/var/lib/qux",
            ]
            .into_iter(),
        );
        assert!(dirs.is_empty(), "{dirs:?}");
    }

    #[test]
    fn non_standard_usr_dir_is_reported() {
        let dirs = FHSCheck::non_standard_dirs(["/usr/weird/tool"].into_iter());
        assert_eq!(dirs, vec![("usr".to_string(), "weird".to_string())]);
    }

    #[test]
    fn non_standard_var_dir_is_reported() {
        let dirs = FHSCheck::non_standard_dirs(["/var/custom/data"].into_iter());
        assert_eq!(dirs, vec![("var".to_string(), "custom".to_string())]);
    }

    #[test]
    fn duplicates_are_deduplicated() {
        let dirs = FHSCheck::non_standard_dirs(
            ["/usr/weird/a", "/usr/weird/b", "/var/custom/c"].into_iter(),
        );
        assert_eq!(dirs.len(), 2);
    }

    #[test]
    fn non_usr_var_paths_are_ignored() {
        let dirs = FHSCheck::non_standard_dirs(["/etc/foo", "/opt/bar"].into_iter());
        assert!(dirs.is_empty(), "{dirs:?}");
    }
}
