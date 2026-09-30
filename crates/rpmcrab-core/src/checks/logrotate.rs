//! `LogrotateCheck` — logrotate configs must reference packaged, safely
//! permissioned log directories.
//!
//! Ported from `rpmlint/checks/LogrotateCheck.py`. Findings:
//! `logrotate-duplicate`, `logrotate-exception`,
//! `logrotate-log-dir-not-packaged`, `logrotate-user-writable-log-dir`.
//!
//! Deliberate improvement over the reference (rpmlint issue #551): `/var/log`
//! itself is never reported by `logrotate-log-dir-not-packaged`; it is owned
//! by the `filesystem` package, not by the package shipping the logrotate
//! config.

use std::collections::HashMap;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct LogrotateCheck;

impl LogrotateCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// Parse a logrotate config into `dir -> (user, group)` (`su` owners).
    /// Mirrors the reference's primitive parser.
    fn parse_config(content: &str) -> HashMap<String, Option<(String, String)>> {
        let mut dirs: HashMap<String, Option<(String, String)>> = HashMap::new();
        let mut current: Vec<String> = Vec::new();
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.starts_with('#') {
                continue;
            }
            if current.is_empty() {
                if line.ends_with('{') {
                    for logfile in line.split(' ') {
                        let logfile = logfile.trim();
                        if logfile.is_empty() || logfile == "{" {
                            continue;
                        }
                        let dn = parent_dir(logfile);
                        if !dirs.contains_key(&dn) {
                            current.push(dn.clone());
                        }
                        dirs.entry(dn).or_insert(None);
                    }
                }
            } else if line.ends_with('}') {
                current.clear();
            } else if let Some(rest) = line.strip_prefix("su ") {
                let mut parts = rest.split_whitespace();
                if let (Some(user), Some(group)) = (parts.next(), parts.next()) {
                    for dn in &current {
                        dirs.insert(dn.clone(), Some((user.to_string(), group.to_string())));
                    }
                }
            }
        }
        dirs
    }
}

/// True when `dir` is exempt from the log-dir-not-packaged check.
/// rpmlint#551: /var/log is owned by the filesystem package, not by the
/// package shipping the logrotate config.
fn is_exempt_log_dir(dir: &str) -> bool {
    dir == "/var/log"
}

/// The parent directory of a log file path.
fn parent_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => path[..i].to_string(),
        None => String::new(),
    }
}

impl Check for LogrotateCheck {
    fn name(&self) -> &'static str {
        "LogrotateCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }

        let mut dirs: HashMap<String, Option<(String, String)>> = HashMap::new();
        for file in &pkg.files {
            let fname = file.name.as_str();
            if pkg.ghost_files.iter().any(|g| g == fname) {
                continue;
            }
            if !fname.starts_with("/etc/logrotate.d/")
                && !fname.starts_with("/usr/etc/logrotate.d/")
            {
                continue;
            }
            let content = match std::fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(e) => {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "logrotate-exception",
                        &[fname, &e.to_string()],
                    );
                    continue;
                }
            };
            for (dir, owners) in Self::parse_config(&content) {
                if let Some(existing) = dirs.get(&dir) {
                    if existing != &owners {
                        add_info(out, Level::Error, pkg, "logrotate-duplicate", &[&dir]);
                    }
                } else {
                    dirs.insert(dir, owners);
                }
            }
        }

        let mut sorted: Vec<&String> = dirs.keys().collect();
        sorted.sort();
        for dir in sorted {
            let owners = &dirs[dir];
            let Some(pkgfile) = pkg.files.iter().find(|f| &f.name == dir) else {
                // rpmlint#551: /var/log is owned by the filesystem package,
                // so the not-packaged finding is a false positive for it.
                // The exemption is scoped to that finding only; a packaged
                // /var/log still gets the user-writable check below.
                if !is_exempt_log_dir(dir) {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "logrotate-log-dir-not-packaged",
                        &[dir],
                    );
                }
                continue;
            };
            let mode = pkgfile.mode & 0o777;
            let user_ok =
                pkgfile.user == "root" || owners.as_ref().is_some_and(|(u, _)| u == &pkgfile.user);
            let group_ok = pkgfile.group == "root"
                || mode & 0o20 == 0
                || owners.as_ref().is_some_and(|(_, g)| g == &pkgfile.group);
            if !user_ok || !group_ok {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "logrotate-user-writable-log-dir",
                    &[&format!(
                        "{} {}:{} {:04o}",
                        dir, pkgfile.user, pkgfile.group, mode
                    )],
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_dir_of_nested_path() {
        assert_eq!(parent_dir("/var/log/samba/log.smbd"), "/var/log/samba");
    }

    #[test]
    fn parent_dir_of_top_level() {
        assert_eq!(parent_dir("/var/log"), "/var");
    }

    #[test]
    fn parse_simple_config() {
        let content = "/var/log/foo.log {\n  weekly\n}\n";
        let dirs = LogrotateCheck::parse_config(content);
        assert_eq!(dirs.len(), 1);
        assert!(dirs.contains_key("/var/log"));
        assert_eq!(dirs["/var/log"], None);
    }

    #[test]
    fn parse_config_with_su() {
        let content = "/var/log/foo/*.log {\n  su foo bar\n}\n";
        let dirs = LogrotateCheck::parse_config(content);
        assert_eq!(
            dirs["/var/log/foo"],
            Some(("foo".to_string(), "bar".to_string()))
        );
    }

    #[test]
    fn parse_config_ignores_comments() {
        let content = "# a comment\n/var/log/foo.log {\n}\n";
        let dirs = LogrotateCheck::parse_config(content);
        assert_eq!(dirs.len(), 1);
    }

    #[test]
    fn parse_multiple_log_files() {
        let content = "/var/log/a.log /var/log/b.log {\n}\n";
        let dirs = LogrotateCheck::parse_config(content);
        // Both share the /var/log parent; the second is a duplicate dir.
        assert_eq!(dirs.len(), 1);
        assert!(dirs.contains_key("/var/log"));
    }

    #[test]
    fn var_log_itself_is_exempt_from_not_packaged() {
        // rpmlint#551: /var/log is owned by the filesystem package and must
        // never be reported by logrotate-log-dir-not-packaged.
        assert!(is_exempt_log_dir("/var/log"));
        assert!(!is_exempt_log_dir("/var/log/samba"));
        assert!(!is_exempt_log_dir("/var/log/foo"));
    }

    #[test]
    fn parse_deduplicates_current_dirs() {
        // Two stanzas for the same dir keep one entry.
        let content = "/var/log/x/a.log {\n}\n/var/log/x/b.log {\n}\n";
        let dirs = LogrotateCheck::parse_config(content);
        assert_eq!(dirs.len(), 1);
    }
}
