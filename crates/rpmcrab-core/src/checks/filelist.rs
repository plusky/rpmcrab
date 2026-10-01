//! `FilelistCheck` — file list policy (forbidden paths, FHS prefixes).
//!
//! Ported from `rpmlint/checks/FilelistCheck.py`. The Good/Bad patterns and
//! the FHS prefix list come from the bundled `FilelistCheck.toml`, mirroring
//! the reference.

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

/// The bundled `FilelistCheck.toml` (rpmlint's, same GPL-2.0-or-later).
const FILELIST_TOML: &str = include_str!("../../data/FilelistCheck.toml");

/// A compiled Good/Bad pattern: either a literal or a regex.
enum Pattern {
    Literal(String),
    Regex(Regex),
}

impl Pattern {
    fn matches(&self, path: &str) -> bool {
        match self {
            Pattern::Literal(lit) => lit == path,
            Pattern::Regex(re) => is_match(re, path),
        }
    }

    /// The reference uses `fnmatch.translate` for patterns containing wildcards.
    fn compile(pattern: &str) -> Self {
        if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
            // fnmatch.translate: `*` -> `.*`, `?` -> `.`, `[seq]` kept, rest escaped.
            let mut regex = String::from("(?s:");
            for c in pattern.chars() {
                match c {
                    '*' => regex.push_str(".*"),
                    '?' => regex.push('.'),
                    c => regex.push_str(&fancy_regex::escape(&c.to_string())),
                }
            }
            regex.push_str(r"\z)");
            Pattern::Regex(Regex::new(&regex).expect("fnmatch pattern"))
        } else {
            Pattern::Literal(pattern.to_string())
        }
    }
}

struct FilelistRule {
    message: &'static str,
    good: Vec<Pattern>,
    bad: Vec<Pattern>,
    ignore_pkg_if: Option<fn(&Pkg) -> bool>,
    ignore_file_if: Option<fn(&Pkg, &str) -> bool>,
}

pub struct FilelistCheck {
    good_prefixes: Vec<String>,
    restricted_dirs: Vec<String>,
    rules: Vec<FilelistRule>,
}

impl FilelistCheck {
    pub fn new(_config: &Config) -> Self {
        let table: toml::Table = toml::from_str(FILELIST_TOML).expect("bundled FilelistCheck.toml");
        let good_prefixes: Vec<String> = table
            .get("GoodPrefixes")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        let mut restricted_dirs = vec!["/".to_string()];
        for d in &good_prefixes {
            if d.matches('/').count() > 2 {
                // `d[0:-1].rpartition('/')[0]`
                let trimmed = d.trim_end_matches('/');
                if let Some(idx) = trimmed.rfind('/') {
                    restricted_dirs.push(trimmed[..idx].to_string());
                }
            }
        }

        // The reference hardcodes these rules via the TOML `[[Check]]` list.
        // We compile the same table here.
        let mut rules = Vec::new();
        if let Some(checks) = table.get("Check").and_then(|v| v.as_array()) {
            for check in checks {
                let message = check
                    .get("Message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("filelist-forbidden");
                // Leak to get 'static: the table is parsed once at startup.
                let message: &'static str = Box::leak(message.to_string().into_boxed_str());
                let good = check
                    .get("Good")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .map(Pattern::compile)
                            .collect()
                    })
                    .unwrap_or_default();
                let bad = check
                    .get("Bad")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .map(Pattern::compile)
                            .collect()
                    })
                    .unwrap_or_default();
                let ignore_pkg_if: Option<fn(&Pkg) -> bool> =
                    match check.get("IgnorePkgIf").and_then(|v| v.as_str()) {
                        Some("notnoarch") => Some(|p: &Pkg| p.arch != "noarch"),
                        Some("isfilesystem") => Some(|p: &Pkg| p.name == "filesystem"),
                        Some("isdebuginfo") => Some(|p: &Pkg| {
                            p.name.ends_with("-debuginfo")
                                || p.name.ends_with("-debuginfo-32bit")
                                || p.name.ends_with("-debuginfo-64bit")
                                || p.name.ends_with("-debugsource")
                                || p.name.ends_with("-debug")
                        }),
                        _ => None,
                    };
                let ignore_file_if: Option<fn(&Pkg, &str) -> bool> =
                    match check.get("IgnoreFileIf").and_then(|v| v.as_str()) {
                        Some("notsymlink") => Some(|p: &Pkg, f: &str| {
                            p.files
                                .iter()
                                .find(|pf| pf.name == f)
                                .map(|pf| (pf.mode >> 12) & 0o17 != 0o12)
                                .unwrap_or(true)
                        }),
                        Some("ghostfile") => {
                            Some(|p: &Pkg, f: &str| p.ghost_files.iter().any(|g| g == f))
                        }
                        _ => None,
                    };
                rules.push(FilelistRule {
                    message,
                    good,
                    bad,
                    ignore_pkg_if,
                    ignore_file_if,
                });
            }
        }

        Self {
            good_prefixes,
            restricted_dirs,
            rules,
        }
    }

    /// The FHS-prefix violations, deduplicated to one report per directory.
    fn fhs_violations(&self, pkg: &Pkg) -> (Vec<String>, Vec<String>) {
        let mut invalid_fhs = std::collections::BTreeSet::new();
        let mut invalid_opt = std::collections::BTreeSet::new();
        let is_suse = pkg
            .header()
            .get_owned(librpm::Tag::VENDOR)
            .and_then(|d| match d {
                librpm::OwnedTagData::Str(s) => Some(s),
                _ => None,
            })
            .map(|v| v.contains("SUSE"))
            .unwrap_or(false);

        for pkgfile in &pkg.files {
            let mut f = pkgfile.name.clone();
            let file_type = (pkgfile.mode >> 12) & 0o17;
            if file_type == 4 {
                f.push('/');
            }

            if !self.good_prefixes.iter().any(|p| f.starts_with(p)) {
                // Find the first invalid path component.
                let mut base = f.as_str().rsplit_once('/').map(|(b, _)| b).unwrap_or("");
                let mut pfx: Option<&str> = None;
                while !base.is_empty()
                    && !self.good_prefixes.iter().any(|p| base.starts_with(p))
                    && !self.restricted_dirs.iter().any(|d| d == base)
                {
                    pfx = Some(base);
                    base = base.rsplit_once('/').map(|(b, _)| b).unwrap_or("");
                }
                invalid_fhs.insert(pfx.unwrap_or(&f).to_string());
            }

            if f.starts_with("/opt") {
                let parts: Vec<&str> = f.split('/').collect();
                if parts.len() > 2 {
                    let provider = parts[2];
                    if is_suse && (provider == "suse" || provider == "novell") {
                        continue;
                    }
                    invalid_opt.insert(format!("/opt/{provider}"));
                }
            }
        }
        (
            invalid_fhs.into_iter().collect(),
            invalid_opt.into_iter().collect(),
        )
    }
}

impl Check for FilelistCheck {
    fn name(&self) -> &'static str {
        "FilelistCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }

        for rule in &self.rules {
            if let Some(ignore) = rule.ignore_pkg_if
                && ignore(pkg)
            {
                continue;
            }
            if rule.good.is_empty() && rule.bad.is_empty() {
                continue;
            }
            for pkgfile in &pkg.files {
                let f = pkgfile.name.as_str();
                let ok = rule.good.iter().any(|g| g.matches(f));
                if ok {
                    continue;
                }
                for b in &rule.bad {
                    if let Some(ignore_file) = rule.ignore_file_if
                        && ignore_file(pkg, f)
                    {
                        continue;
                    }
                    if b.matches(f) {
                        add_info(out, Level::Error, pkg, rule.message, &[f]);
                        break;
                    }
                }
            }
        }

        let (invalid_fhs, invalid_opt) = self.fhs_violations(pkg);
        for f in &invalid_fhs {
            add_info(out, Level::Error, pkg, "filelist-forbidden-fhs23", &[f]);
        }
        for f in &invalid_opt {
            add_info(out, Level::Error, pkg, "filelist-forbidden-opt", &[f]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnmatch_star_becomes_dot_star() {
        let p = Pattern::compile("*.orig");
        assert!(p.matches("foo.orig"));
        assert!(p.matches("/a/b.orig"));
        assert!(!p.matches("foo.orig.bak"));
    }

    #[test]
    fn literal_matches_exactly() {
        let p = Pattern::compile("/var/adm/setup");
        assert!(p.matches("/var/adm/setup"));
        assert!(!p.matches("/var/adm/setup2"));
    }

    #[test]
    fn question_mark_matches_one_char() {
        let p = Pattern::compile("file?.txt");
        assert!(p.matches("file1.txt"));
        assert!(!p.matches("file12.txt"));
    }
}
