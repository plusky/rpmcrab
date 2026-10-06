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

    /// The reference translates a pattern only when it contains `*`
    /// (FilelistCheck.py:63); anything else stays a str compared with `==`.
    fn compile(pattern: &str) -> Self {
        if pattern.contains('*') {
            // fnmatch.translate, anchored at both ends. The reference applies
            // the result with `re.match`, so an end-anchor alone is not enough:
            // `is_match` searches, and `/etc/httpd/*` would then match mid-path
            // in `/opt/x/etc/httpd/conf/httpd.conf` -- inventing an Error -- and
            // a Good pattern matching mid-path would suppress one.
            let mut regex = String::from("(?s:^");
            for c in pattern.chars() {
                match c {
                    '*' => regex.push_str(".*"),
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
    message: String,
    good: Vec<Pattern>,
    bad: Vec<Pattern>,
    ignore_pkg_if: Option<fn(&Pkg) -> bool>,
    ignore_file_if: Option<fn(&Pkg, &str) -> bool>,
}

pub struct FilelistCheck {
    good_prefixes: Vec<String>,
    restricted_dirs: Vec<String>,
    rules: Vec<FilelistRule>,
    /// Upstream rpmlint#437: GNOME 1 / KDE 1 era MIME dirs superseded by
    /// shared-mime-info, as (prefix, prefix-with-trailing-slash) pairs.
    /// From `ObsoleteDirPrefixes` (config-driven): trailing slashes are
    /// trimmed and empty entries dropped at load, so a config typo can
    /// neither silently miss nor match everything.
    obsolete_dir_prefixes: Vec<(String, String)>,
}

impl FilelistCheck {
    pub fn new(config: &Config) -> Self {
        // Default to the three obsolete MIME-format dirs; an explicit
        // (even empty) config list overrides.
        let obsolete_dir_prefixes: Vec<(String, String)> =
            match config.configuration.get("ObsoleteDirPrefixes") {
                Some(toml::Value::Array(a)) => a.iter().filter_map(toml::Value::as_str).collect(),
                _ => vec![
                    "/usr/share/mime-info",
                    "/usr/share/application-registry",
                    "/usr/share/mimelnk",
                ],
            }
            .into_iter()
            .map(|p| p.trim_end_matches('/'))
            .filter(|p| !p.is_empty())
            .map(|p| (p.to_string(), format!("{p}/")))
            .collect();
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
                    .unwrap_or("filelist-forbidden")
                    .to_string();
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
            obsolete_dir_prefixes,
        }
    }

    /// The obsolete MIME-format dirs (upstream rpmlint#437) this package
    /// installs into, one finding per directory: the finding is about the
    /// directory being obsolete, so per-file reports would only add noise.
    fn obsolete_mime_dirs(&self, pkg: &Pkg) -> Vec<String> {
        let mut found = std::collections::BTreeSet::new();
        for pkgfile in &pkg.files {
            let f = pkgfile.name.as_str();
            for (prefix, prefix_slash) in &self.obsolete_dir_prefixes {
                // Match the dir itself and anything under it, without
                // matching a longer sibling (`/usr/share/mimelnk2`).
                if f == prefix || f.starts_with(prefix_slash.as_str()) {
                    found.insert(prefix.clone());
                }
            }
        }
        found.into_iter().collect()
    }

    /// The FHS-prefix violations, deduplicated to one report per directory.
    fn fhs_violations(&self, pkg: &Pkg) -> (Vec<String>, Vec<String>) {
        let mut invalid_fhs = std::collections::BTreeSet::new();
        let mut invalid_opt = std::collections::BTreeSet::new();
        let is_suse = pkg
            .tag_str(librpm::Tag::VENDOR)
            .is_some_and(|v| v.contains("SUSE"));

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
                    // The reference emits once per matching pattern; no break.
                    if b.matches(f) {
                        add_info(out, Level::Error, pkg, &rule.message, &[f]);
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
        for d in self.obsolete_mime_dirs(pkg) {
            add_info(out, Level::Warning, pkg, "obsolete-mime-format-dir", &[&d]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;
    use crate::pkg::pkgfile::PkgFile;

    /// Hand-built package shell: the fcprobe header with a caller-supplied
    /// file list, so the test drives the real emission path without a
    /// fixture RPM carrying the payload.
    fn pkg_with_files(files: &[&str]) -> Pkg {
        let rpm = format!(
            "{}/../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture shell");
        pkg.files = files
            .iter()
            .map(|f| PkgFile {
                name: f.to_string(),
                path: f.to_string(),
                mode: 0o100644,
                ..Default::default()
            })
            .collect();
        pkg
    }

    fn run(config: &Config, pkg: &Pkg) -> Vec<(String, String)> {
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        let mut check = FilelistCheck::new(config);
        check.check_binary(pkg, config, &mut out);
        out.results().to_vec()
    }

    fn lines_for(results: &[(String, String)], name: &str) -> Vec<String> {
        results
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, l)| l.clone())
            .collect()
    }

    // Upstream rpmlint#437: obsolete GNOME 1 / KDE 1 MIME dirs.
    #[test]
    fn obsolete_mime_dirs_warn_once_per_dir() {
        let pkg = pkg_with_files(&[
            "/usr/share/mimelnk/foo.desktop",
            "/usr/share/mimelnk/bar.desktop",
            "/usr/share/mime-info/gnome.keys",
        ]);
        let config = Config::default();
        let results = run(&config, &pkg);
        let lines = lines_for(&results, "obsolete-mime-format-dir");
        // One finding per obsolete dir, not per file.
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].contains("W: obsolete-mime-format-dir /usr/share/mime-info"),
            "name, level and detail: {}",
            lines[0]
        );
        assert!(
            lines[1].contains("W: obsolete-mime-format-dir /usr/share/mimelnk"),
            "name, level and detail: {}",
            lines[1]
        );
    }

    #[test]
    fn obsolete_mime_dirs_sibling_prefix_is_quiet() {
        // The boundary match must not fire on a longer sibling
        // (`/usr/share/mimelnk2` is not `/usr/share/mimelnk/`).
        let pkg = pkg_with_files(&["/usr/share/mimelnk2/foo.desktop", "/usr/bin/foo"]);
        let config = Config::default();
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "obsolete-mime-format-dir").is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn obsolete_mime_dirs_are_config_driven() {
        let mut tbl = toml::Table::new();
        tbl.insert(
            "ObsoleteDirPrefixes".to_string(),
            toml::Value::Array(vec![toml::Value::String("/opt/obsolete".to_string())]),
        );
        let config = Config {
            configuration: tbl,
            ..Default::default()
        };
        let pkg = pkg_with_files(&["/opt/obsolete/foo", "/usr/share/mimelnk/foo.desktop"]);
        let results = run(&config, &pkg);
        let lines = lines_for(&results, "obsolete-mime-format-dir");
        // The explicit list replaces the default: only /opt/obsolete warns.
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("/opt/obsolete"), "detail: {}", lines[0]);
    }

    #[test]
    fn obsolete_mime_dirs_empty_list_is_quiet() {
        let mut tbl = toml::Table::new();
        tbl.insert(
            "ObsoleteDirPrefixes".to_string(),
            toml::Value::Array(vec![]),
        );
        let config = Config {
            configuration: tbl,
            ..Default::default()
        };
        let pkg = pkg_with_files(&["/usr/share/mimelnk/foo.desktop"]);
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "obsolete-mime-format-dir").is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn obsolete_mime_dirs_trailing_slash_and_empty_are_normalized() {
        // plusky #251 review: a trailing-slash config entry must still
        // match, and an empty entry must not match everything.
        let mut tbl = toml::Table::new();
        tbl.insert(
            "ObsoleteDirPrefixes".to_string(),
            toml::Value::Array(vec![
                toml::Value::String("/opt/obsolete/".to_string()),
                toml::Value::String(String::new()),
            ]),
        );
        let config = Config {
            configuration: tbl,
            ..Default::default()
        };
        let pkg = pkg_with_files(&["/opt/obsolete/foo", "/usr/bin/foo"]);
        let results = run(&config, &pkg);
        let lines = lines_for(&results, "obsolete-mime-format-dir");
        // The trailing slash is trimmed (still matches); the empty entry
        // is dropped (matches nothing, not even /usr/bin/foo).
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("W: obsolete-mime-format-dir /opt/obsolete"),
            "name, level and detail: {}",
            lines[0]
        );
    }

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
    fn only_a_star_triggers_translation() {
        // FilelistCheck.py:63 translates only when '*' is in the pattern, and
        // the untranslated branch is `g == f` (FilelistCheck.py:88). So `?` is
        // NOT a one-character wildcard here: `file?.txt` is a literal and does
        // not match `file1.txt`.
        let p = Pattern::compile("file?.txt");
        assert!(p.matches("file?.txt"));
        assert!(!p.matches("file1.txt"));
    }

    #[test]
    fn patterns_are_anchored_at_the_start_like_re_match() {
        // The reference applies the translated pattern with `re.match`, so a
        // pattern must not match part-way along a path. `/etc/httpd/*` against
        // `/opt/x/etc/httpd/conf/httpd.conf` is False there; an end-anchored
        // search would call it a Bad hit and invent an Error.
        let bad = Pattern::compile("/etc/httpd/*");
        assert!(bad.matches("/etc/httpd/conf/httpd.conf"));
        assert!(!bad.matches("/opt/x/etc/httpd/conf/httpd.conf"));
        // The mirror image: a Good pattern matching mid-path used to suppress a
        // finding the reference reports.
        let good = Pattern::compile("/etc/sysconfig/scripts/*");
        assert!(good.matches("/etc/sysconfig/scripts/rc.d"));
        assert!(!good.matches("/opt/x/etc/sysconfig/scripts/rc.d"));
    }
}
