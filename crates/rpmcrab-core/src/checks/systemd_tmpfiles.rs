//! `SystemdTmpfilesCheck` — systemd-tmpfiles configuration restrictions.
//!
//! Ported from `rpmlint/checks/SystemdTmpfilesCheck.py` and
//! `rpmlint/checks/TmpfilesParser.py`. Findings: `systemd-tmpfile-ghost`,
//! `systemd-tmpfile-symlink`, `systemd-tmpfile-parse-error`,
//! `systemd-tmpfile-entry-unauthorized`.

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::{is_dir, is_symlink};

/// Paths whose tmpfiles entries are considered safe.
const WELL_KNOWN_PATHS: &[&str] = &[
    "/var/lib",
    "/var/run",
    "/run",
    "/var/lock",
    "/var/cache",
    "/run/lock",
    "/var/log",
    "/var/spool",
    "/srv",
    "/etc",
    "/sys",
    "/var/yp",
];

/// chattr flags that are not security-interesting.
const BORING_ATTRS: &[char] = &['C'];

/// Entry types supporting a permissions field (TmpfilesParser.TYPES_WITH_PERMS).
const TYPES_WITH_PERMS: &[char] = &[
    'f', 'd', 'D', 'e', 'v', 'q', 'Q', 'p', 'c', 'C', 'b', 'z', 'Z',
];

/// One parsed tmpfiles.d entry (TmpfilesParser.TmpfilesEntry).
#[derive(Debug)]
struct TmpfilesEntry {
    source: String,
    line: String,
    entry_type: String,
    target: String,
    mode: Option<String>,
    owner: Option<String>,
    group: Option<String>,
    arg: Option<String>,
    valid: bool,
    warnings: Vec<String>,
}

impl TmpfilesEntry {
    fn parse(source: &str, line: &str) -> Self {
        let mut entry = Self {
            source: source.to_string(),
            line: line.to_string(),
            entry_type: String::new(),
            target: String::new(),
            mode: None,
            owner: None,
            group: None,
            arg: None,
            valid: false,
            warnings: Vec::new(),
        };
        entry.parse_fields();
        entry
    }

    fn warn(&mut self, msg: &str) {
        self.warnings.push(format!("{}: {}", self.source, msg));
    }

    /// Split a config line per tmpfiles.d(5): first 6 fields are
    /// whitespace-separated (quotes honoured), the rest is the argument.
    fn split_line(line: &str) -> Vec<String> {
        let mut fields = Vec::new();
        let chars: Vec<char> = line.chars().collect();
        let n = chars.len();
        let line_trimmed = line.trim_start();
        let leading_ws = line.len() - line_trimmed.len();
        let mut i = leading_ws;
        for _ in 0..6 {
            while i < n && chars[i].is_whitespace() {
                i += 1;
            }
            if i >= n {
                break;
            }
            let start = i;
            let mut in_quote: Option<char> = None;
            while i < n {
                let c = chars[i];
                if let Some(q) = in_quote {
                    if c == q {
                        in_quote = None;
                    }
                    i += 1;
                } else if c == '"' || c == '\'' {
                    in_quote = Some(c);
                    i += 1;
                } else if c.is_whitespace() {
                    break;
                } else {
                    i += 1;
                }
            }
            fields.push(chars[start..i].iter().collect());
        }
        let remainder: String = chars[i..].iter().collect();
        let remainder = remainder.trim_start();
        if !remainder.is_empty() {
            fields.push(remainder.to_string());
        }
        fields
    }

    fn parse_fields(&mut self) {
        let fields = Self::split_line(&self.line);
        if fields.len() > 7 {
            self.warn("Too many fields encountered");
            return;
        }
        if fields.len() < 2 {
            self.warn("Too few fields encountered");
            return;
        }
        self.entry_type = fields[0].clone();
        self.target = fields[1].clone();
        let mut idx = 2;
        let mut next = || {
            if idx >= fields.len() {
                return None;
            }
            let v = fields[idx].clone();
            idx += 1;
            if v == "-" { None } else { Some(v) }
        };
        self.mode = next();
        self.owner = next();
        self.group = next();
        let _age = next();
        self.arg = next();

        if (self.mode.is_some() || self.owner.is_some() || self.group.is_some())
            && !self.supports_perms()
        {
            self.warn("Permissions specified for entry type that doesn't support perms");
        }
        // `F` is a deprecated form of `f+`; normalize after the permissions
        // check, which the reference runs against the raw type.
        if self.entry_type.starts_with('F') {
            self.entry_type = format!("f+{}", &self.entry_type[1..]);
        }
        self.valid = true;
    }

    fn supports_perms(&self) -> bool {
        self.entry_type
            .chars()
            .next()
            .map(|c| TYPES_WITH_PERMS.contains(&c))
            .unwrap_or(false)
    }

    fn has_default_mode(&self) -> bool {
        self.mode.is_none()
    }

    fn octal_mode(&self) -> Option<u32> {
        let mut mode = self.mode.as_deref()?;
        if let Some(stripped) = mode.strip_prefix('~') {
            mode = stripped;
        }
        u32::from_str_radix(mode, 8).ok()
    }

    fn has_non_root_owner(&self) -> bool {
        self.owner.as_deref().map(|o| o != "root").unwrap_or(false)
    }

    fn has_non_root_group(&self) -> bool {
        self.group.as_deref().map(|g| g != "root").unwrap_or(false)
    }

    fn arg_value(&self) -> &str {
        self.arg.as_deref().unwrap_or("-")
    }

    fn normalized_line(&self) -> String {
        self.line.split_whitespace().collect::<Vec<_>>().join(" ")
    }
}

/// Parse a tmpfiles.d configuration file.
fn parse_tmpfiles(source: &str, content: &str) -> Vec<TmpfilesEntry> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        entries.push(TmpfilesEntry::parse(source, line));
    }
    entries
}

pub struct SystemdTmpfilesCheck {
    dropin_dirs: Vec<String>,
    ignore_packages: Vec<String>,
    whitelist: Vec<WhitelistEntry>,
}

struct WhitelistEntry {
    packages: Vec<String>,
    path: String,
    entries: Vec<String>,
}

impl SystemdTmpfilesCheck {
    pub fn new(config: &Config) -> Self {
        let cfg = config.configuration.get("SystemdTmpfiles");
        let dropin_dirs = cfg
            .and_then(|v| v.get("DropinDirs"))
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_else(|| {
                // The reference raises KeyError when the section is absent;
                // fall back to its two configured dirs so the check still runs.
                vec![
                    "/usr/lib/tmpfiles.d".to_string(),
                    "/etc/tmpfiles.d".to_string(),
                ]
            });
        let ignore_packages = cfg
            .and_then(|v| v.get("IgnorePackages"))
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let whitelist = config
            .configuration
            .get("SystemdTmpfilesWhitelist")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_table())
                    .map(|t| {
                        let mut packages: Vec<String> = t
                            .get("packages")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(str::to_string))
                                    .collect()
                            })
                            .unwrap_or_default();
                        if let Some(p) = t.get("package").and_then(|v| v.as_str()) {
                            packages.push(p.to_string());
                        }
                        let path = t
                            .get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let entries: Vec<String> = t
                            .get("entries")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str())
                                    .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
                                    .collect()
                            })
                            .unwrap_or_default();
                        WhitelistEntry {
                            packages,
                            path,
                            entries,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            dropin_dirs,
            ignore_packages,
            whitelist,
        }
    }

    /// Whether the file is a tmpfiles.d config in a restricted drop-in dir.
    fn is_path_restricted(&self, name: &str, mode: u32) -> bool {
        if is_dir(mode) || !name.ends_with(".conf") {
            return false;
        }
        self.dropin_dirs
            .iter()
            .any(|d| name == d || name.starts_with(&format!("{d}/")))
    }

    fn is_in_safe_location(&self, entry: &TmpfilesEntry) -> bool {
        WELL_KNOWN_PATHS.iter().any(|k| entry.target.starts_with(k))
    }

    /// Whether the entry is security-sensitive (needs whitelisting).
    fn is_sensitive_entry(&self, entry: &TmpfilesEntry) -> bool {
        let base = entry.entry_type.chars().next().unwrap_or(' ');
        match base {
            'L' | 'v' | 'q' | 'Q' | 'r' | 'R' | 'X' | 'x' => false,
            'd' | 'f' | 'c' | 'z' | 'p' | 'D' | 'F' | 'Z' | 'P' | 'C' => {
                if !self.is_in_safe_location(entry) {
                    return true;
                }
                if entry.has_default_mode() {
                    return false;
                }
                match entry.octal_mode() {
                    Some(mode) => {
                        // S_IWOTH, S_ISUID, S_ISGID
                        (mode & 0o002) != 0 || (mode & 0o4000) != 0 || (mode & 0o2000) != 0
                    }
                    None => true,
                }
            }
            'b' => {
                if !entry.target.starts_with("/dev") {
                    return true;
                }
                if entry.has_non_root_owner() || entry.has_non_root_group() {
                    return true;
                }
                match entry.octal_mode() {
                    Some(mode) => (mode & 0o004) != 0 || (mode & 0o002) != 0,
                    None => true,
                }
            }
            'h' | 'H' => {
                let mut attr = entry.arg_value().to_string();
                for prefix in ['+', '-', '='] {
                    attr = attr.trim_start_matches(prefix).to_string();
                }
                attr.chars().any(|c| !BORING_ATTRS.contains(&c))
            }
            _ => true,
        }
    }

    fn is_whitelisted(&self, pkg_name: &str, entry: &TmpfilesEntry) -> bool {
        let normalized = entry.normalized_line();
        self.whitelist.iter().any(|wl| {
            wl.packages.iter().any(|p| p == pkg_name)
                && entry.source == wl.path
                && wl.entries.iter().any(|e| e == &normalized)
        })
    }
}

impl Check for SystemdTmpfilesCheck {
    fn name(&self) -> &'static str {
        "SystemdTmpfilesCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if self.ignore_packages.iter().any(|p| p == &pkg.name) {
            return;
        }
        for pkgfile in &pkg.files {
            if !self.is_path_restricted(&pkgfile.name, pkgfile.mode) {
                continue;
            }
            if pkg.ghost_files.iter().any(|g| g == &pkgfile.name) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "systemd-tmpfile-ghost",
                    &[&pkgfile.name],
                );
                continue;
            }
            if is_symlink(pkgfile.mode) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "systemd-tmpfile-symlink",
                    &[&pkgfile.name],
                );
                continue;
            }
            let content = pkg.read_file(&pkgfile.name);
            let entries = parse_tmpfiles(&pkgfile.name, &content);
            for entry in &entries {
                if !entry.valid {
                    for warning in &entry.warnings {
                        add_info(
                            out,
                            Level::Error,
                            pkg,
                            "systemd-tmpfile-parse-error",
                            &[&pkgfile.name, &entry.line, warning],
                        );
                    }
                }
            }
            for entry in entries
                .iter()
                .filter(|e| e.valid && self.is_sensitive_entry(e))
            {
                if self.is_whitelisted(&pkg.name, entry) {
                    continue;
                }
                let detail = format!("\"{}\"", entry.line);
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "systemd-tmpfile-entry-unauthorized",
                    &[&pkgfile.name, &detail],
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_line_handles_quotes() {
        let fields = TmpfilesEntry::split_line(r#"f "/run/foo bar" 0644 root root -"#);
        assert_eq!(fields[0], "f");
        assert_eq!(fields[1], r#""/run/foo bar""#);
        assert_eq!(fields[2], "0644");
    }

    #[test]
    fn split_line_argument_takes_rest() {
        let fields = TmpfilesEntry::split_line("f /run/foo 0644 root root - some argument here");
        assert_eq!(fields.len(), 7);
        assert_eq!(fields[6], "some argument here");
    }

    #[test]
    fn too_few_fields_is_invalid() {
        let entry = TmpfilesEntry::parse("test.conf", "d");
        assert!(!entry.valid);
        assert!(!entry.warnings.is_empty());
    }

    #[test]
    fn valid_entry_parses() {
        let entry = TmpfilesEntry::parse("test.conf", "d /run/foo 0755 root root -");
        assert!(entry.valid);
        assert_eq!(entry.entry_type, "d");
        assert_eq!(entry.target, "/run/foo");
        assert_eq!(entry.octal_mode(), Some(0o755));
    }

    #[test]
    fn dash_means_default() {
        let entry = TmpfilesEntry::parse("test.conf", "d /run/foo - - - -");
        assert!(entry.valid);
        assert!(entry.has_default_mode());
    }

    #[test]
    fn f_normalizes_to_f_plus() {
        let entry = TmpfilesEntry::parse("test.conf", "F /run/foo - - - -");
        assert_eq!(entry.entry_type, "f+");
    }

    #[test]
    fn f_with_perms_warns_before_normalization() {
        // The reference checks permissions against the raw `F` (which is not
        // in TYPES_WITH_PERMS) and normalizes afterwards.
        let entry = TmpfilesEntry::parse("test.conf", "F /run/foo 0644 root root -");
        assert_eq!(entry.entry_type, "f+");
        assert!(
            entry
                .warnings
                .iter()
                .any(|w| w.contains("Permissions specified")),
            "warnings: {:?}",
            entry.warnings
        );
    }

    #[test]
    fn tilde_mode_is_stripped() {
        let entry = TmpfilesEntry::parse("test.conf", "f /run/foo ~0644 root root -");
        assert_eq!(entry.octal_mode(), Some(0o644));
    }

    #[test]
    fn world_writable_in_safe_location_is_sensitive() {
        let check = SystemdTmpfilesCheck::new(&Config::default());
        let entry = TmpfilesEntry::parse("t.conf", "f /var/log/foo 0666 root root -");
        assert!(check.is_sensitive_entry(&entry));
    }

    #[test]
    fn default_mode_in_safe_location_is_not_sensitive() {
        let check = SystemdTmpfilesCheck::new(&Config::default());
        let entry = TmpfilesEntry::parse("t.conf", "d /var/log/foo - - - -");
        assert!(!check.is_sensitive_entry(&entry));
    }

    #[test]
    fn outside_safe_location_is_sensitive() {
        let check = SystemdTmpfilesCheck::new(&Config::default());
        let entry = TmpfilesEntry::parse("t.conf", "d /opt/foo - - - -");
        assert!(check.is_sensitive_entry(&entry));
    }

    #[test]
    fn symlink_type_is_not_sensitive() {
        let check = SystemdTmpfilesCheck::new(&Config::default());
        let entry = TmpfilesEntry::parse("t.conf", "L /etc/foo - - - - /bar");
        assert!(!check.is_sensitive_entry(&entry));
    }
}
