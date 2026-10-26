//! `FilelistCheck` — file list policy (forbidden paths, FHS prefixes).
//!
//! Ported from `rpmlint/checks/FilelistCheck.py`. The Good/Bad patterns and
//! the FHS prefix list come from the bundled `FilelistCheck.toml`, mirroring
//! the reference.

use std::sync::OnceLock;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::fhs::cross_sysroot_matches;
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

    /// Whether `path` sits under a prefix the FHS walk treats as
    /// good: a bundled GoodPrefix, a cross-toolchain target sysroot
    /// (the measured set FHSCheck sanctions, shared through
    /// `cross_sysroot_matches`) or, in a package whose name ends in
    /// `-source`, the `/usr/src` tree - the canonical location of the
    /// sources such a package ships.
    fn fhs_good_prefix(&self, pkg: &Pkg, path: &str) -> bool {
        self.good_prefixes
            .iter()
            .any(|p| path.starts_with(p.as_str()))
            || cross_sysroot_matches(path)
            || (pkg.name.ends_with("-source") && path.starts_with("/usr/src/"))
    }

    /// The FHS-prefix violations, deduplicated to one report per directory.
    fn fhs_violations(&self, pkg: &Pkg) -> (Vec<String>, Vec<String>) {
        let mut invalid_fhs = std::collections::BTreeSet::new();
        let is_suse = pkg
            .tag_str(librpm::Tag::VENDOR)
            .is_some_and(|v| v.contains("SUSE"));

        // Directory entries carry a trailing slash for the prefix
        // matching below; other names are borrowed as-is. The second
        // element records whether the entry is in a suppressible
        // form at a sanctioned path: a directory or a symlink by
        // mode, or a %ghost by flag. The ghost test is the flag, not
        // the mode - `RPMFILE_GHOST` is orthogonal to the file type,
        // and a %ghost may carry a regular mode or mode 0.
        let paths: Vec<(std::borrow::Cow<'_, str>, bool)> = pkg
            .files
            .iter()
            .map(|pkgfile| {
                let file_type = (pkgfile.mode >> 12) & 0o17;
                let suppressible = file_type == 4 || file_type == 0o12 || pkgfile.is_ghost();
                if file_type == 4 {
                    let mut f = pkgfile.name.clone();
                    f.push('/');
                    (std::borrow::Cow::Owned(f), suppressible)
                } else {
                    (
                        std::borrow::Cow::Borrowed(pkgfile.name.as_str()),
                        suppressible,
                    )
                }
            })
            .collect();

        for (f, suppressible) in &paths {
            let f: &str = f;
            if !self.fhs_good_prefix(pkg, f) {
                // Find the first invalid path component.
                let mut base = f.rsplit_once('/').map(|(b, _)| b).unwrap_or("");
                let mut pfx: Option<&str> = None;
                while !base.is_empty()
                    && !self.fhs_good_prefix(pkg, base)
                    && !self.restricted_dirs.iter().any(|d| d == base)
                {
                    pfx = Some(base);
                    base = base.rsplit_once('/').map(|(b, _)| b).unwrap_or("");
                }
                // When the parent is a restricted dir the walk reports
                // the path itself (a top-level path's parent is empty,
                // which lands in the same fallback). If that path is
                // one of the locations the FHS tables themselves
                // sanction - a restricted FHS root, or a GoodPrefix
                // with its trailing slash dropped - and the entry is
                // in a suppressible form (a directory or symlink by
                // mode, or a %ghost by flag), the report names a
                // sanctioned location as forbidden: the mail spool at
                // /var/mail in symlink or %ghost form is the standard
                // arrangement, not an FHS violation. A regular file at
                // such a path still reports.
                if pfx.is_none() && *suppressible && self.fhs_sanctioned_path(f) {
                    continue;
                }
                invalid_fhs.insert(pfx.unwrap_or(f).to_string());
            }
        }
        (
            invalid_fhs.into_iter().collect(),
            Self::invalid_opt_providers(paths.iter().map(|(p, _)| p.as_ref()), is_suse),
        )
    }

    /// Whether `path` is itself one of the locations the FHS tables
    /// sanction: a restricted dir (an FHS root such as /var or /usr) or
    /// a GoodPrefix, compared with trailing slashes dropped - the form
    /// an entry takes when a package ships that location as a symlink
    /// or a %ghost placeholder rather than a directory.
    fn fhs_sanctioned_path(&self, path: &str) -> bool {
        let key = path.trim_end_matches('/');
        let key = if key.is_empty() { "/" } else { key };
        self.restricted_dirs.iter().any(|d| d == key)
            || self
                .good_prefixes
                .iter()
                .any(|p| p.trim_end_matches('/') == key)
    }

    /// The `/opt/<provider>` directories a payload installs into,
    /// deduplicated to one report per provider. The provider is the
    /// first component under /opt, so the match must end at a component
    /// boundary: a longer sibling (`/optical/...`) is not an /opt
    /// payload, and the bare /opt directory itself has no provider to
    /// report. A SUSE-vendor package is exempt for the `suse` and
    /// `novell` providers.
    fn invalid_opt_providers<'a>(
        paths: impl IntoIterator<Item = &'a str>,
        is_suse: bool,
    ) -> Vec<String> {
        let mut invalid_opt = std::collections::BTreeSet::new();
        for f in paths {
            if let Some(rest) = f.strip_prefix("/opt/") {
                let provider = rest.split('/').next().unwrap_or("");
                if !provider.is_empty()
                    && !(is_suse && (provider == "suse" || provider == "novell"))
                {
                    invalid_opt.insert(format!("/opt/{provider}"));
                }
            }
        }
        invalid_opt.into_iter().collect()
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
    use crate::pkg::pkgfile::{PkgFile, RPMFILE_GHOST};

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
            lines[0].contains("E: filelist-forbidden-fhs23 /usr/foobar"),
            "name, level and detail: {}",
            lines[0]
        );
    }

    // Issue #859: the GCC cross-toolchain prefixes are the measured
    // target sysroots FHSCheck sanctions (issue #582); the reference's
    // GoodPrefixes sanction none of them, so it reports every one.
    #[test]
    fn cross_toolchain_sysroots_are_good_fhs_prefixes() {
        let mut pkg = pkg_with_files(&[
            "/usr/aarch64-suse-linux/bin/ld",
            "/usr/arm-suse-linux-gnueabi/lib/libc.so",
            "/usr/bpf-none/bin/bpf-none-clang",
            "/usr/rx-elf/bin/rx-elf-gcc",
            "/usr/amdgcn-amdhsa/lib/libclang_rt.builtins.a",
        ]);
        // The sysroot directory entries themselves, as the real
        // packages list them.
        for sysroot in ["/usr/avr", "/usr/pru"] {
            pkg.files.push(PkgFile {
                name: sysroot.to_string(),
                path: sysroot.to_string(),
                mode: 0o040755,
                ..Default::default()
            });
        }
        let config = Config::default();
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "filelist-forbidden-fhs23").is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn every_measured_cross_sysroot_is_quiet_for_fhs23() {
        // Pin the whole measured set against this check too: a sysroot
        // dropped from the shared set fails here as well as in
        // FHSCheck's own pin on the set.
        let config = Config::default();
        for sysroot in crate::checks::fhs::FHS_USR_CROSS_SYSROOTS {
            let path = format!("/usr/{sysroot}/bin/tool");
            let pkg = pkg_with_files(&[&path]);
            let results = run(&config, &pkg);
            assert!(
                lines_for(&results, "filelist-forbidden-fhs23").is_empty(),
                "{sysroot}: {results:?}"
            );
        }
    }

    #[test]
    fn unmeasured_usr_dirs_still_fire_fhs23() {
        // The sanction is the measured set, not the triplet shape:
        // a novel component of exactly that shape still fires, as
        // does a measured name extended by a suffix.
        let config = Config::default();
        for (path, detail) in [
            (
                "/usr/frobnicate-suse-linux/bin/tool",
                "/usr/frobnicate-suse-linux",
            ),
            (
                "/usr/aarch64-suse-linux2/bin/tool",
                "/usr/aarch64-suse-linux2",
            ),
        ] {
            let pkg = pkg_with_files(&[path]);
            let lines = lines_for(&run(&config, &pkg), "filelist-forbidden-fhs23");
            assert_eq!(lines.len(), 1, "{path}");
            assert!(
                lines[0].contains(&format!("E: filelist-forbidden-fhs23 {detail}")),
                "{path}: {lines:?}"
            );
        }
    }

    #[test]
    fn cross_sysroot_name_below_another_component_still_fires() {
        // Only the leading component sanctions: a sysroot name deeper
        // in the tree leaves the leading directory reported.
        let pkg = pkg_with_files(&["/usr/local/aarch64-suse-linux/tool"]);
        let config = Config::default();
        let lines = lines_for(&run(&config, &pkg), "filelist-forbidden-fhs23");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("E: filelist-forbidden-fhs23 /usr/local"),
            "{lines:?}"
        );
    }

    // Issue #859: /usr/src/<package> is the canonical location of a
    // -source package's payload; the same tree in a package not named
    // as one still fires.
    #[test]
    fn source_package_usr_src_payload_is_quiet() {
        let mut pkg = pkg_with_files(&[
            "/usr/src/nginx/src/core/nginx.c",
            "/usr/src/nginx/configure",
        ]);
        pkg.name = "nginx-source".to_string();
        let config = Config::default();
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "filelist-forbidden-fhs23").is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn usr_src_payload_of_other_packages_still_fires() {
        let config = Config::default();
        // The identical tree in a package not named as a source
        // package.
        let mut pkg = pkg_with_files(&["/usr/src/nginx/src/core/nginx.c"]);
        pkg.name = "nginx".to_string();
        let lines = lines_for(&run(&config, &pkg), "filelist-forbidden-fhs23");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("E: filelist-forbidden-fhs23 /usr/src/nginx"),
            "{lines:?}"
        );
        // A -source package name sanctions nothing outside /usr/src
        // itself: a lookalike tree still fires.
        let mut pkg = pkg_with_files(&["/usr/srcx/nginx/nginx.c", "/usr/frobnicate/tool"]);
        pkg.name = "nginx-source".to_string();
        let lines = lines_for(&run(&config, &pkg), "filelist-forbidden-fhs23");
        assert_eq!(lines.len(), 2);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("E: filelist-forbidden-fhs23 /usr/srcx")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("E: filelist-forbidden-fhs23 /usr/frobnicate")),
            "{lines:?}"
        );
    }

    // Issue #859: /usr/src/kernel-modules is the tree kernel-module
    // source packages install into, sanctioned like the neighbouring
    // /usr/src/debug and /usr/src/packages trees.
    #[test]
    fn kernel_modules_tree_is_quiet() {
        let pkg = pkg_with_files(&[
            "/usr/src/kernel-modules/nvidia-570.86/Makefile",
            "/usr/src/kernel-modules/nvidia-570.86/nv.c",
        ]);
        let config = Config::default();
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "filelist-forbidden-fhs23").is_empty(),
            "unexpected: {results:?}"
        );
        // A sibling name is not the reserved tree.
        let pkg = pkg_with_files(&["/usr/src/kernel-modulesx/pkg/file.c"]);
        let lines = lines_for(&run(&config, &pkg), "filelist-forbidden-fhs23");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("E: filelist-forbidden-fhs23 /usr/src/kernel-modulesx"),
            "{lines:?}"
        );
    }

    // The FHS walk reports a path itself when its parent is a
    // restricted dir. When that path is a location the FHS tables
    // themselves sanction - a restricted FHS root, or a GoodPrefix with
    // its trailing slash dropped - in a suppressible form (a
    // directory or symlink by mode, or a %ghost by flag), the report
    // names a sanctioned location as forbidden: exim ships /var/mail as
    // a symlink to the spool dir, postfix and postfix-bdb ship it as a
    // %ghost, and xkeyboard-config ships the bare /var directory
    // entry. The reference reports all of them.
    #[test]
    fn sanctioned_locations_in_non_regular_form_are_quiet() {
        let config = Config::default();
        for (path, mode, flags) in [
            ("/var/mail", 0o120777, 0), // symlink: the exim shape
            // %ghost with a regular mode: the postfix shape. The
            // ghost test is the flag, which is orthogonal to the
            // mode's file type - this codebase's ghost fixtures
            // keep the file's regular mode and set RPMFILE_GHOST.
            ("/var/mail", 0o100644, RPMFILE_GHOST),
            // %ghost with mode 0: real postfix headers carry
            // exactly this shape (FILEFLAGS = RPMFILE_GHOST, mode 0
            // in the corpus census behind this change).
            ("/var/mail", 0, RPMFILE_GHOST),
            ("/var", 0o040755, 0), // bare root dir entry: the xkeyboard shape
            ("/usr", 0o040755, 0), // bare root dir entry
            ("/var/log", 0o120777, 0), // symlink at another GoodPrefix
            // Top-level symlink: the usrmerge /bin shape. Its
            // parent is empty, and pfx.is_none() covers that too.
            ("/bin", 0o120777, 0),
        ] {
            let pkg = pkg_with_modes_and_flags(&[(path, mode, flags)]);
            let results = run(&config, &pkg);
            assert!(
                lines_for(&results, "filelist-forbidden-fhs23").is_empty(),
                "{path} mode {mode:o} flags {flags}: {results:?}"
            );
        }
    }

    #[test]
    fn regular_file_at_sanctioned_location_still_fires() {
        // The exemption is about the form, not the location: a regular
        // file sitting at a sanctioned path is a real misplacement.
        // /var/mail reaches the fallback through its restricted
        // parent /var; the restricted roots /var and /usr themselves
        // take the empty-parent path, so pin those too.
        let config = Config::default();
        for path in ["/var/mail", "/var", "/usr"] {
            let pkg = pkg_with_modes(&[(path, 0o100644)]);
            let lines = lines_for(&run(&config, &pkg), "filelist-forbidden-fhs23");
            assert_eq!(lines.len(), 1, "{path}: {lines:?}");
            assert!(
                lines[0].contains(&format!("E: filelist-forbidden-fhs23 {path}")),
                "{lines:?}"
            );
        }
    }

    #[test]
    fn mode_zero_without_ghost_flag_still_fires() {
        // Mode 0 alone is not a %ghost: the ghost test is the
        // RPMFILE_GHOST flag, so a bare mode-0 entry at a sanctioned
        // path earns no exemption.
        let pkg = pkg_with_modes(&[("/var/mail", 0)]);
        let config = Config::default();
        let lines = lines_for(&run(&config, &pkg), "filelist-forbidden-fhs23");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("E: filelist-forbidden-fhs23 /var/mail"),
            "{lines:?}"
        );
    }

    #[test]
    fn unsanctioned_sibling_paths_still_fire() {
        let config = Config::default();
        // The samba-client shape: %ghost dirs at a legacy location next
        // to the sanctioned tree.
        let pkg = pkg_with_modes(&[("/var/samba", 0o040000), ("/var/samba/spool", 0o040000)]);
        let lines = lines_for(&run(&config, &pkg), "filelist-forbidden-fhs23");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("E: filelist-forbidden-fhs23 /var/samba"),
            "{lines:?}"
        );
        // A symlink earns no exemption at a location the tables do not
        // sanction.
        let pkg = pkg_with_modes(&[("/var/evil", 0o120777)]);
        let lines = lines_for(&run(&config, &pkg), "filelist-forbidden-fhs23");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("E: filelist-forbidden-fhs23 /var/evil"),
            "{lines:?}"
        );
        // A %ghost earns no exemption at a location the tables do
        // not sanction either.
        let pkg = pkg_with_modes_and_flags(&[("/var/evil", 0o100644, RPMFILE_GHOST)]);
        let lines = lines_for(&run(&config, &pkg), "filelist-forbidden-fhs23");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("E: filelist-forbidden-fhs23 /var/evil"),
            "{lines:?}"
        );
        // Payload under unsanctioned roots is unchanged.
        let pkg = pkg_with_files(&["/gnu/store/tool", "/usr/local/bin/date"]);
        let lines = lines_for(&run(&config, &pkg), "filelist-forbidden-fhs23");
        assert_eq!(lines.len(), 2);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("E: filelist-forbidden-fhs23 /gnu")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("E: filelist-forbidden-fhs23 /usr/local")),
            "{lines:?}"
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

    fn pkg_with_modes_and_flags(entries: &[(&str, u32, u32)]) -> Pkg {
        let rpm = format!(
            "{}/../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture shell");
        pkg.files = entries
            .iter()
            .map(|(f, mode, flags)| PkgFile {
                name: f.to_string(),
                path: f.to_string(),
                mode: *mode,
                flags: *flags,
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
            lines[0].contains("E: filelist-forbidden-opt /opt/acme"),
            "name, level and detail: {}",
            lines[0]
        );
        assert!(
            lines[1].contains("E: filelist-forbidden-opt /opt/other"),
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
            lines[0].contains("E: filelist-forbidden-sysconfig /etc/sysconfig/munge"),
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
            lines[0].contains("E: filelist-forbidden-sysconfig /etc/rc.config.d/munge"),
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
            lines[0].contains("E: filelist-forbidden-sysconfig /etc/sysconfig/real"),
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
                "E: filelist-forbidden-sysconfig /var/adm/fillup-templates/sysconfig.munge"
            ),
            "name, level and detail: {}",
            lines[0]
        );
    }

    #[test]
    fn move_to_usr_ghost_pam_file_is_quiet() {
        // A %ghost pam.d file carries no payload: it is generated at
        // install time (pam-config's common-*-pc files), so the rule
        // does not report it.
        let pkg = pkg_with_ghosts(
            &["/etc/pam.d/common-auth-pc"],
            &["/etc/pam.d/common-auth-pc"],
        );
        let config = Config::default();
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "filelist-forbidden-move-to-usr").is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn move_to_usr_real_pam_file_still_fires() {
        let pkg = pkg_with_files(&["/etc/pam.d/common-auth-pc"]);
        let config = Config::default();
        let results = run(&config, &pkg);
        let lines = lines_for(&results, "filelist-forbidden-move-to-usr");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("E: filelist-forbidden-move-to-usr /etc/pam.d/common-auth-pc"),
            "name, level and detail: {}",
            lines[0]
        );
    }

    #[test]
    fn move_to_usr_ghost_systemd_unit_is_quiet() {
        let pkg = pkg_with_ghosts(
            &["/lib/systemd/system/munge.service"],
            &["/lib/systemd/system/munge.service"],
        );
        let config = Config::default();
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "filelist-forbidden-move-to-usr").is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn move_to_usr_real_systemd_unit_still_fires() {
        let pkg = pkg_with_files(&["/lib/systemd/system/munge.service"]);
        let config = Config::default();
        let results = run(&config, &pkg);
        let lines = lines_for(&results, "filelist-forbidden-move-to-usr");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0]
                .contains("E: filelist-forbidden-move-to-usr /lib/systemd/system/munge.service"),
            "name, level and detail: {}",
            lines[0]
        );
    }

    #[test]
    fn move_to_usr_ghost_udev_rule_is_quiet() {
        let pkg = pkg_with_ghosts(
            &["/lib/udev/rules.d/99-munge.rules"],
            &["/lib/udev/rules.d/99-munge.rules"],
        );
        let config = Config::default();
        let results = run(&config, &pkg);
        assert!(
            lines_for(&results, "filelist-forbidden-move-to-usr").is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn move_to_usr_real_udev_rule_still_fires() {
        let pkg = pkg_with_files(&["/lib/udev/rules.d/99-munge.rules"]);
        let config = Config::default();
        let results = run(&config, &pkg);
        let lines = lines_for(&results, "filelist-forbidden-move-to-usr");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("E: filelist-forbidden-move-to-usr /lib/udev/rules.d/99-munge.rules"),
            "name, level and detail: {}",
            lines[0]
        );
    }

    #[test]
    fn move_to_usr_ghost_and_real_sibling_fires_once_for_real_file() {
        // The exemption is per-file, not per-package: the ghost sibling
        // stays quiet while the real sibling in the same rule still fires.
        let pkg = pkg_with_ghosts(
            &["/etc/pam.d/ghosted-pc", "/etc/pam.d/real-pc"],
            &["/etc/pam.d/ghosted-pc"],
        );
        let config = Config::default();
        let results = run(&config, &pkg);
        let lines = lines_for(&results, "filelist-forbidden-move-to-usr");
        assert_eq!(lines.len(), 1, "lines: {lines:?}");
        assert!(
            lines[0].contains("E: filelist-forbidden-move-to-usr /etc/pam.d/real-pc"),
            "name, level and detail: {}",
            lines[0]
        );
    }

    #[test]
    fn suse_vendor_opt_providers_are_exempt() {
        // A SUSE-vendor package may install under the `suse` and
        // `novell` providers; any other provider is still reported.
        let providers = FilelistCheck::invalid_opt_providers(
            [
                "/opt/suse/bin/tool",
                "/opt/suse/lib/libsuse.so",
                "/opt/novell/bin/tool",
                "/opt/acme/bin/tool",
                "/opt/acme/lib/libacme.so",
            ],
            true,
        );
        assert_eq!(providers, vec!["/opt/acme".to_string()]);
    }

    #[test]
    fn non_suse_vendor_opt_providers_all_fire() {
        // The exemption is gated on the SUSE vendor: the same payload
        // from any other vendor reports every provider.
        let providers = FilelistCheck::invalid_opt_providers(
            [
                "/opt/suse/bin/tool",
                "/opt/novell/bin/tool",
                "/opt/acme/bin/tool",
            ],
            false,
        );
        assert_eq!(
            providers,
            vec![
                "/opt/acme".to_string(),
                "/opt/novell".to_string(),
                "/opt/suse".to_string()
            ]
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
            lines[0]
                .contains("E: filelist-forbidden-bashcomp-userdirs /etc/bash_completion.d/w6comp"),
            "name, level and detail: {}",
            lines[0]
        );
    }
}
