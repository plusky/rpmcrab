//! `FilelistCheck` — file list policy (forbidden paths, FHS prefixes).
//!
//! Ported from `rpmlint/checks/FilelistCheck.py`. The Good/Bad patterns and
//! the FHS prefix list come from the bundled `FilelistCheck.toml`, mirroring
//! the reference.

use std::sync::OnceLock;

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
pub(crate) enum Pattern {
    Literal(String),
    Regex(Regex),
}

impl Pattern {
    pub(crate) fn matches(&self, path: &str) -> bool {
        match self {
            Pattern::Literal(lit) => lit == path,
            Pattern::Regex(re) => is_match(re, path),
        }
    }

    /// The reference translates a pattern only when it contains `*`
    /// (FilelistCheck.py:63); anything else stays a str compared with `==`.
    pub(crate) fn compile(pattern: &str) -> Self {
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

/// Whether `path` matches a `Good` pattern of the
/// `filelist-forbidden-sysconfig` rule: the patterns compile from the
/// `Good` list of that rule's `[[Check]]` entry in the bundled
/// `FilelistCheck.toml`, the same data `FilelistCheck` applies before
/// the rule's `Bad` patterns. Other checks consult this so a path the
/// rule blesses is blessed consistently across checks.
pub(crate) fn sysconfig_good_matches(path: &str) -> bool {
    static GOOD: OnceLock<Vec<Pattern>> = OnceLock::new();
    GOOD.get_or_init(|| {
        let table: toml::Table = toml::from_str(FILELIST_TOML).expect("bundled FilelistCheck.toml");
        let checks = table
            .get("Check")
            .and_then(|v| v.as_array())
            .expect("bundled FilelistCheck.toml [[Check]] list");
        let rule = checks
            .iter()
            .find(|c| {
                c.get("Message").and_then(|v| v.as_str()) == Some("filelist-forbidden-sysconfig")
            })
            .expect("bundled filelist-forbidden-sysconfig rule");
        rule.get("Good")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(Pattern::compile)
                    .collect()
            })
            .unwrap_or_default()
    })
    .iter()
    .any(|g| g.matches(path))
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

            // The provider is the first component under /opt, so the
            // match must end at a component boundary: a longer sibling
            // (`/optical/...`) is not an /opt payload, and the bare /opt
            // directory itself has no provider to report.
            if let Some(rest) = f.strip_prefix("/opt/") {
                let provider = rest.split('/').next().unwrap_or("");
                if !provider.is_empty()
                    && !(is_suse && (provider == "suse" || provider == "novell"))
                {
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

    // Issue #386: the MinGW cross-toolchain sysroots are permitted by the
    // MinGW packaging guidelines (the reference only stays silent via
    // Filters shipped by mingw32/64-filesystem), so files under them — and
    // the sysroot dirs themselves — must not raise
    // filelist-forbidden-fhs23. A genuinely non-FHS dir still does.
    #[test]
    fn mingw_sysroots_are_good_fhs_prefixes() {
        let rpm = format!(
            "{}/../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture shell");
        pkg.files = vec![
            PkgFile {
                name: "/usr/i686-w64-mingw32/bin/i686-w64-mingw32-ld.exe".to_string(),
                path: "/usr/i686-w64-mingw32/bin/i686-w64-mingw32-ld.exe".to_string(),
                mode: 0o100755,
                ..Default::default()
            },
            PkgFile {
                name: "/usr/x86_64-w64-mingw32/lib/libz.dll.a".to_string(),
                path: "/usr/x86_64-w64-mingw32/lib/libz.dll.a".to_string(),
                mode: 0o100644,
                ..Default::default()
            },
            // The sysroot directory itself, as the real packages list it.
            PkgFile {
                name: "/usr/i686-w64-mingw32".to_string(),
                path: "/usr/i686-w64-mingw32".to_string(),
                mode: 0o040755,
                ..Default::default()
            },
        ];
        let config = Config::default();
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "filelist-forbidden-fhs23").is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn non_fhs_dir_still_fires_fhs23() {
        let pkg = pkg_with_files(&["/usr/foobar/bin/tool"]);
        let config = Config::default();
        let results = run(&config, &pkg);
        let lines = lines_for(&results, "filelist-forbidden-fhs23");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("E: filelist-forbidden-fhs23 (Badness: 1) /usr/foobar"),
            "name, level and detail: {}",
            lines[0]
        );
    }

    // Issue #495: the xinetd rule's only pattern was the reference's typo
    // `/etc/xinet.d/*`, which matches no real path; real xinetd configs are
    // reported by XinetdDepCheck as deprecated-xinetd-config instead.
    #[test]
    fn xinetd_config_does_not_fire_filelist_forbidden() {
        let pkg = pkg_with_files(&["/etc/xinetd.d/amanda", "/etc/xinetd.d/servers"]);
        let config = Config::default();
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "filelist-forbidden-xinetd-configuration").is_empty(),
            "unexpected: {results:?}"
        );
    }

    // Issue #605: the /opt guard matched the bare "/opt" prefix, so a
    // payload under a longer sibling (`/optical/...`) produced a bogus
    // filelist-forbidden-opt finding naming a directory the package does
    // not install, and a bare `/opt` directory entry produced a malformed
    // `/opt/` finding with an empty provider.
    fn pkg_with_modes(entries: &[(&str, u32)]) -> Pkg {
        let rpm = format!(
            "{}/../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture shell");
        pkg.files = entries
            .iter()
            .map(|(f, mode)| PkgFile {
                name: f.to_string(),
                path: f.to_string(),
                mode: *mode,
                ..Default::default()
            })
            .collect();
        pkg
    }

    #[test]
    fn opt_prefix_siblings_are_quiet() {
        let pkg = pkg_with_files(&[
            "/optical/foo/bin/tool",
            "/opts/foo/bin/tool",
            "/opt-foo/bin/tool",
        ]);
        let config = Config::default();
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "filelist-forbidden-opt").is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn opt_bare_directory_entry_is_quiet() {
        // A directory entry for /opt itself (mode 0o040755) has no
        // provider component to report.
        let pkg = pkg_with_modes(&[("/opt", 0o040755), ("/usr/bin/foo", 0o100644)]);
        let config = Config::default();
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "filelist-forbidden-opt").is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn opt_provider_still_fires_once_per_provider() {
        let pkg = pkg_with_modes(&[
            ("/opt/acme", 0o040755),
            ("/opt/acme/bin/tool", 0o100755),
            ("/opt/acme/lib/libacme.so", 0o100644),
            ("/opt/other/bin/tool", 0o100755),
        ]);
        let config = Config::default();
        let results = run(&config, &pkg);
        let lines = lines_for(&results, "filelist-forbidden-opt");
        assert_eq!(lines.len(), 2, "lines: {lines:?}");
        assert!(
            lines[0].contains("E: filelist-forbidden-opt (Badness: 1) /opt/acme"),
            "name, level and detail: {}",
            lines[0]
        );
        assert!(
            lines[1].contains("E: filelist-forbidden-opt (Badness: 1) /opt/other"),
            "name, level and detail: {}",
            lines[1]
        );
    }

    fn pkg_with_ghosts(files: &[&str], ghosts: &[&str]) -> Pkg {
        for ghost in ghosts {
            assert!(
                files.contains(ghost),
                "{ghost} is not in the package files, so this test would pass vacuously"
            );
        }
        let mut pkg = pkg_with_files(files);
        pkg.ghost_files = ghosts.iter().map(|g| g.to_string()).collect();
        pkg
    }

    #[test]
    fn sysconfig_ghost_file_is_quiet() {
        // A %ghost sysconfig file carries no payload: the file is
        // generated at install time, so the rule does not report it.
        let pkg = pkg_with_ghosts(&["/etc/sysconfig/munge"], &["/etc/sysconfig/munge"]);
        let config = Config::default();
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "filelist-forbidden-sysconfig").is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn sysconfig_real_file_still_fires() {
        let pkg = pkg_with_files(&["/etc/sysconfig/munge"]);
        let config = Config::default();
        let results = run(&config, &pkg);
        let lines = lines_for(&results, "filelist-forbidden-sysconfig");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("E: filelist-forbidden-sysconfig (Badness: 1) /etc/sysconfig/munge"),
            "name, level and detail: {}",
            lines[0]
        );
    }

    #[test]
    fn sysconfig_ghost_in_rc_config_d_is_quiet() {
        // /etc/rc.config.d/* is a Bad-only pattern: it matches no Good
        // entry, so only the ghost exemption keeps this quiet.
        let pkg = pkg_with_ghosts(&["/etc/rc.config.d/munge"], &["/etc/rc.config.d/munge"]);
        let config = Config::default();
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "filelist-forbidden-sysconfig").is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn sysconfig_real_file_in_rc_config_d_still_fires() {
        let pkg = pkg_with_files(&["/etc/rc.config.d/munge"]);
        let config = Config::default();
        let results = run(&config, &pkg);
        let lines = lines_for(&results, "filelist-forbidden-sysconfig");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0]
                .contains("E: filelist-forbidden-sysconfig (Badness: 1) /etc/rc.config.d/munge"),
            "name, level and detail: {}",
            lines[0]
        );
    }

    #[test]
    fn sysconfig_ghost_and_real_sibling_fires_once_for_real_file() {
        // The exemption is per-file, not per-package: the ghost sibling
        // stays quiet while the real sibling in the same rule still fires.
        let pkg = pkg_with_ghosts(
            &["/etc/sysconfig/ghosted", "/etc/sysconfig/real"],
            &["/etc/sysconfig/ghosted"],
        );
        let config = Config::default();
        let results = run(&config, &pkg);
        let lines = lines_for(&results, "filelist-forbidden-sysconfig");
        assert_eq!(lines.len(), 1, "lines: {lines:?}");
        assert!(
            lines[0].contains("E: filelist-forbidden-sysconfig (Badness: 1) /etc/sysconfig/real"),
            "name, level and detail: {}",
            lines[0]
        );
    }

    #[test]
    fn fillup_template_ghost_file_is_quiet() {
        let pkg = pkg_with_ghosts(
            &["/var/adm/fillup-templates/sysconfig.munge"],
            &["/var/adm/fillup-templates/sysconfig.munge"],
        );
        let config = Config::default();
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "filelist-forbidden-sysconfig").is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn fillup_template_real_file_still_fires() {
        let pkg = pkg_with_files(&["/var/adm/fillup-templates/sysconfig.munge"]);
        let config = Config::default();
        let results = run(&config, &pkg);
        let lines = lines_for(&results, "filelist-forbidden-sysconfig");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains(
                "E: filelist-forbidden-sysconfig (Badness: 1) /var/adm/fillup-templates/sysconfig.munge"
            ),
            "name, level and detail: {}",
            lines[0]
        );
    }

    #[test]
    fn sibling_forbidden_path_still_fires() {
        let pkg = pkg_with_files(&["/etc/bash_completion.d/w6comp"]);
        let config = Config::default();
        let results = run(&config, &pkg);
        let lines = lines_for(&results, "filelist-forbidden-bashcomp-userdirs");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains(
                "E: filelist-forbidden-bashcomp-userdirs (Badness: 1) /etc/bash_completion.d/w6comp"
            ),
            "name, level and detail: {}",
            lines[0]
        );
    }
}
