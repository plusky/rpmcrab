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
//!
//! Two further deliberate refinements of the not-packaged judgement, both
//! scoped to that finding only: the derived directory is first reduced to
//! the literal directory it names (see `judged_log_dir`), and a directory
//! created by a tmpfiles.d snippet shipped in the same package counts as
//! provided (see `tmpfiles_created_dirs`).

use indexmap::IndexMap;

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
    /// Insertion-ordered: the reference returns a dict and walks
    /// `parselogrotateconf(...).items()` (LogrotateCheck.py:20), i.e. file order.
    fn parse_config(content: &str) -> IndexMap<String, Option<(String, String)>> {
        let mut dirs: IndexMap<String, Option<(String, String)>> = IndexMap::new();
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

/// Reduce a derived log directory to the literal directory it names.
///
/// The reference charges the raw parent of the config's path pattern, but
/// that string need not name a directory that can exist: a quoted path
/// keeps its leading quote (`"/var/log/i2pd`), and the parent of a
/// two-level glob pattern keeps a glob component
/// (`/var/log/pacemaker/bundles/*`). Judging such a string against the
/// file list can never succeed, so strip one surrounding quote pair and
/// keep only the longest literal prefix of components; that ancestor is
/// the directory whose packaging matters (the remaining components are
/// created by the daemon itself, one per client/bundle/host).
/// Strip one surrounding pair of quote character `q` from `s`; a lone
/// leading or trailing quote is stripped on its own (after `parent_dir`
/// the closing quote of a quoted log path sits in the dropped file part,
/// so a quoted directory usually carries only its opening quote).
fn strip_one_quote_pair(s: &str, q: char) -> &str {
    let s = s.strip_prefix(q).unwrap_or(s);
    s.strip_suffix(q).unwrap_or(s)
}

fn judged_log_dir(dir: &str) -> String {
    let unquoted = strip_one_quote_pair(dir, '"');
    let unquoted = strip_one_quote_pair(unquoted, '\'');
    // Longest literal prefix: components from the first glob-bearing one
    // on are daemon-created structure, not a packageable directory name.
    let mut judged = if unquoted.starts_with('/') {
        String::from("/")
    } else {
        String::new()
    };
    for comp in unquoted.split('/').filter(|c| !c.is_empty()) {
        if comp.contains(['*', '?', '[']) {
            break;
        }
        if judged.len() > 1 {
            judged.push('/');
        }
        judged.push_str(comp);
    }
    if judged.is_empty() {
        judged.push('/');
    }
    judged
}

/// Directories a package creates via systemd-tmpfiles: the paths of
/// `d`/`D` lines in tmpfiles.d snippets shipped in the package itself.
/// Such a directory is guaranteed to exist with its declared mode and
/// owner once the package is installed, so charging it as not packaged
/// is a false positive. Only exact path matches count; other line types
/// (`e` adjusts an existing directory, `x` ignores, ...) never create.
fn tmpfiles_created_dirs(pkg: &Pkg) -> std::collections::HashSet<String> {
    let mut created = std::collections::HashSet::new();
    for file in &pkg.files {
        let fname = file.name.as_str();
        if pkg.ghost_files.iter().any(|g| g == fname) {
            continue;
        }
        if !fname.starts_with("/usr/lib/tmpfiles.d/")
            && !fname.starts_with("/etc/tmpfiles.d/")
            && !fname.starts_with("/run/tmpfiles.d/")
        {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&file.path) else {
            continue;
        };
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let (Some(kind), Some(path)) = (fields.next(), fields.next()) else {
                continue;
            };
            // The type letter may carry modifier suffixes (`d-`, `D!`).
            if matches!(kind.chars().next(), Some('d') | Some('D')) {
                created.insert(path.to_string());
            }
        }
    }
    created
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

        let mut dirs: IndexMap<String, Option<(String, String)>> = IndexMap::new();
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

        // The reference iterates `sorted(dirs.keys())` here (LogrotateCheck.py),
        // so the explicit sort is parity, not a divergence.
        let mut sorted: Vec<&String> = dirs.keys().collect();
        sorted.sort();
        let tmpfiles_dirs = if dirs.is_empty() {
            std::collections::HashSet::new()
        } else {
            tmpfiles_created_dirs(pkg)
        };
        for dir in sorted {
            let owners = &dirs[dir];
            let Some(pkgfile) = pkg.files.iter().find(|f| f.name == *dir) else {
                // rpmlint#551: /var/log is owned by the filesystem package,
                // so the not-packaged finding is a false positive for it.
                // The exemption is scoped to that finding only; a packaged
                // /var/log still gets the user-writable check below.
                // The judged (literal) directory decides: a glob or quoted
                // artefact is satisfied by its literal directory being
                // packaged, and any judged directory the package creates
                // via its own tmpfiles.d snippets is provided as well.
                let judged = judged_log_dir(dir);
                let satisfied = is_exempt_log_dir(&judged)
                    || pkg.files.iter().any(|f| f.name == judged)
                    || tmpfiles_dirs.contains(&judged);
                if !satisfied {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "logrotate-log-dir-not-packaged",
                        &[&judged],
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

    /// `parse_config` must preserve file order: the reference returns a dict and
    /// iterates `.items()` (LogrotateCheck.py:20), and `logrotate-duplicate`
    /// findings share one sort key, so hash order would become output order.
    #[test]
    fn parse_config_preserves_file_order() {
        let content = "/srv/zeta/*.log /srv/alpha/*.log {\n  su root root\n}\n\
                      /srv/mid/*.log {\n  su root root\n}\n";
        let keys: Vec<String> = LogrotateCheck::parse_config(content).into_keys().collect();
        assert_eq!(
            keys,
            vec!["/srv/zeta", "/srv/alpha", "/srv/mid"],
            "file order, not sorted"
        );
    }

    /// B7: the `/var/log` exemption (rpmlint#551) is scoped to
    /// `logrotate-log-dir-not-packaged` only. A packaged `/var/log` that
    /// is user-writable still gets `logrotate-user-writable-log-dir`.
    #[test]
    fn packaged_var_log_still_gets_user_writable_check() {
        use crate::color::Color;
        use crate::pkg::pkgfile::PkgFile;

        let tmp = tempfile::tempdir().expect("tmpdir");
        let dir = tmp.path();
        let conf = dir.join("app");
        std::fs::write(&conf, "/var/log/app.log {\n  weekly\n}\n").expect("write conf");

        let rpm = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = crate::pkg::Pkg::open(&rpm, dir, true).expect("open fixture pkg");
        pkg.name = "logrotate-test".to_string();
        pkg.files = vec![
            PkgFile {
                name: "/etc/logrotate.d/app".to_string(),
                path: conf.to_string_lossy().into_owned(),
                mode: 0o100644,
                ..Default::default()
            },
            // /var/log is packaged (so no not-packaged finding) but owned
            // by a non-root user with a group-writable mode.
            PkgFile {
                name: "/var/log".to_string(),
                path: "/var/log".to_string(),
                mode: 0o40775,
                user: "app".to_string(),
                group: "app".to_string(),
                ..Default::default()
            },
        ];

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = LogrotateCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let rendered: Vec<String> = out.results().iter().map(|(_, line)| line.clone()).collect();

        assert!(
            !rendered
                .iter()
                .any(|l| l.contains("logrotate-log-dir-not-packaged")),
            "unexpected not-packaged: {rendered:?}"
        );
        let writable: Vec<&String> = rendered
            .iter()
            .filter(|l| l.contains("logrotate-user-writable-log-dir"))
            .collect();
        assert_eq!(writable.len(), 1, "{rendered:?}");
        assert!(
            writable[0].starts_with(
                "logrotate-test.noarch: E: logrotate-user-writable-log-dir /var/log app:app 0775"
            ),
            "unexpected line: {}",
            writable[0]
        );
    }

    /// Run `LogrotateCheck::check_binary` over a package whose only logrotate
    /// conf references `log_path`, with the log dir itself unpackaged, and
    /// return the rendered lines.
    fn run_logrotate_not_packaged_case(log_path: &str) -> Vec<String> {
        use crate::color::Color;
        use crate::pkg::pkgfile::PkgFile;

        let tmp = tempfile::tempdir().expect("tmpdir");
        let dir = tmp.path();
        let conf = dir.join("app");
        std::fs::write(&conf, format!("{log_path} {{\n  weekly\n}}\n")).expect("write conf");

        let rpm = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = crate::pkg::Pkg::open(&rpm, dir, true).expect("open fixture pkg");
        pkg.name = "logrotate-test".to_string();
        // The log dir is deliberately absent: this exercises the not-packaged
        // branch, which the packaged-/var/log test above never reaches.
        pkg.files = vec![PkgFile {
            name: "/etc/logrotate.d/app".to_string(),
            path: conf.to_string_lossy().into_owned(),
            mode: 0o100644,
            ..Default::default()
        }];

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = LogrotateCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        out.results().iter().map(|(_, line)| line.clone()).collect()
    }

    /// B7b: the `/var/log` exemption (rpmlint#551) is scoped to the exact
    /// `/var/log` directory. With `/var/log` itself unpackaged no
    /// `logrotate-log-dir-not-packaged` fires; an unpackaged `/var/log/samba`
    /// is still reported.
    #[test]
    fn unpackaged_log_dir_exemption_is_scoped_to_var_log() {
        // (log path in the conf, unpackaged dir, expect the finding)
        let cases: &[(&str, &str, bool)] = &[
            ("/var/log/app.log", "/var/log", false),
            ("/var/log/samba/app.log", "/var/log/samba", true),
        ];
        for (log_path, dir, expect_finding) in cases {
            let rendered = run_logrotate_not_packaged_case(log_path);
            let hits: Vec<&String> = rendered
                .iter()
                .filter(|l| l.contains("logrotate-log-dir-not-packaged"))
                .collect();
            if *expect_finding {
                assert_eq!(hits.len(), 1, "case {log_path}: {rendered:?}");
                assert_eq!(
                    hits[0],
                    &format!("logrotate-test.noarch: E: logrotate-log-dir-not-packaged {dir}"),
                    "case {log_path}"
                );
            } else {
                assert!(
                    hits.is_empty(),
                    "case {log_path}: unexpected {hits:?} in {rendered:?}"
                );
            }
        }
    }

    /// Run `LogrotateCheck::check_binary` over a package with two logrotate
    /// configs and return the rendered lines.
    fn run_logrotate_two_confs(first: &str, second: &str) -> Vec<String> {
        use crate::color::Color;
        use crate::pkg::pkgfile::PkgFile;

        let tmp = tempfile::tempdir().expect("tmpdir");
        let dir = tmp.path();
        let mut files = Vec::new();
        for (name, content) in [("a", first), ("b", second)] {
            let conf = dir.join(name);
            std::fs::write(&conf, content).expect("write conf");
            files.push(PkgFile {
                name: format!("/etc/logrotate.d/{name}"),
                path: conf.to_string_lossy().into_owned(),
                mode: 0o100644,
                ..Default::default()
            });
        }

        let rpm = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = crate::pkg::Pkg::open(&rpm, dir, true).expect("open fixture pkg");
        pkg.name = "logrotate-test".to_string();
        pkg.files = files;

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = LogrotateCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        out.results().iter().map(|(_, line)| line.clone()).collect()
    }

    #[test]
    fn judged_log_dir_reduces_artefacts() {
        // Plain dirs pass through untouched.
        assert_eq!(judged_log_dir("/var/log/app"), "/var/log/app");
        assert_eq!(judged_log_dir("/var/log"), "/var/log");
        // A quoted path keeps only its leading quote after parent_dir.
        assert_eq!(judged_log_dir("\"/var/log/i2pd"), "/var/log/i2pd");
        // Trailing glob components drop to the longest literal ancestor.
        assert_eq!(
            judged_log_dir("/var/log/pacemaker/bundles/*"),
            "/var/log/pacemaker/bundles"
        );
        assert_eq!(
            judged_log_dir("/var/log/radius/radacct/*"),
            "/var/log/radius/radacct"
        );
        assert_eq!(judged_log_dir("/var/log/*"), "/var/log");
        assert_eq!(judged_log_dir("/var/log/*/sub"), "/var/log");
    }

    /// Run `LogrotateCheck::check_binary` over a package with one logrotate
    /// config plus caller-supplied extra files (name, content, mode).
    /// Returns the rendered lines.
    fn run_logrotate_with_extras(conf_content: &str, extras: &[(&str, &str, u32)]) -> Vec<String> {
        use crate::color::Color;
        use crate::pkg::pkgfile::PkgFile;

        let tmp = tempfile::tempdir().expect("tmpdir");
        let dir = tmp.path();
        let conf = dir.join("app");
        std::fs::write(&conf, conf_content).expect("write conf");
        let mut files = vec![PkgFile {
            name: "/etc/logrotate.d/app".to_string(),
            path: conf.to_string_lossy().into_owned(),
            mode: 0o100644,
            ..Default::default()
        }];
        for (i, (name, content, mode)) in extras.iter().enumerate() {
            let fpath = dir.join(format!("extra{i}"));
            std::fs::write(&fpath, content).expect("write extra");
            files.push(PkgFile {
                name: name.to_string(),
                path: fpath.to_string_lossy().into_owned(),
                mode: *mode,
                ..Default::default()
            });
        }

        let rpm = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = crate::pkg::Pkg::open(&rpm, dir, true).expect("open fixture pkg");
        pkg.name = "logrotate-test".to_string();
        pkg.files = files;

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = LogrotateCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        out.results().iter().map(|(_, line)| line.clone()).collect()
    }

    fn not_packaged_lines(rendered: &[String]) -> Vec<&String> {
        rendered
            .iter()
            .filter(|l| l.contains("logrotate-log-dir-not-packaged"))
            .collect()
    }

    /// A two-level glob pattern derives a "directory" ending in a glob
    /// component; when the literal ancestor is packaged the stanza is
    /// satisfied and nothing fires (the pre-fix code charged the glob
    /// string, which no package can ever ship).
    #[test]
    fn glob_pattern_with_packaged_ancestor_is_satisfied() {
        let rendered = run_logrotate_with_extras(
            "/var/log/app/bundles/*/app.log {\n  weekly\n}\n",
            &[("/var/log/app/bundles", "", 0o40755)],
        );
        assert!(
            not_packaged_lines(&rendered).is_empty(),
            "packaged literal ancestor must satisfy: {rendered:?}"
        );
    }

    /// The same pattern with the ancestor unpackaged still fires, but on
    /// the literal directory a maintainer can actually package.
    #[test]
    fn glob_pattern_with_unpackaged_ancestor_fires_on_literal_dir() {
        let rendered =
            run_logrotate_with_extras("/var/log/app/bundles/*/app.log {\n  weekly\n}\n", &[]);
        let hits = not_packaged_lines(&rendered);
        assert_eq!(hits.len(), 1, "{rendered:?}");
        assert!(
            hits[0].ends_with("logrotate-log-dir-not-packaged /var/log/app/bundles"),
            "unexpected charge: {}",
            hits[0]
        );
    }

    /// A quoted log path (i2pd's shape) charges the unquoted directory.
    #[test]
    fn quoted_path_fires_on_unquoted_dir() {
        let rendered = run_logrotate_with_extras("\"/var/log/app/*.log\" {\n  weekly\n}\n", &[]);
        let hits = not_packaged_lines(&rendered);
        assert_eq!(hits.len(), 1, "{rendered:?}");
        assert!(
            hits[0].ends_with("logrotate-log-dir-not-packaged /var/log/app"),
            "unexpected charge: {}",
            hits[0]
        );
    }

    /// A directory created by a tmpfiles.d snippet shipped in the same
    /// package is provided: no finding. Covers the plain case (krb5,
    /// usbguard) and, via the quoted config, the i2pd composition.
    #[test]
    fn tmpfiles_created_dir_is_satisfied() {
        for conf in [
            "/var/log/app/*.log {\n  weekly\n}\n",
            "\"/var/log/app/*.log\" {\n  weekly\n}\n",
        ] {
            let rendered = run_logrotate_with_extras(
                conf,
                &[(
                    "/usr/lib/tmpfiles.d/app.conf",
                    "d /var/log/app 0755 root root -\n",
                    0o100644,
                )],
            );
            assert!(
                not_packaged_lines(&rendered).is_empty(),
                "conf {conf}: tmpfiles-created dir must satisfy: {rendered:?}"
            );
        }
    }

    /// Near misses must keep firing: a non-creating tmpfiles line type, a
    /// commented-out creation line, and a creation line for another dir.
    #[test]
    fn tmpfiles_near_misses_still_fire() {
        for content in [
            "e /var/log/app 0755 root root -\n",
            "#d /var/log/app 0755 root root -\n",
            "d /var/log/other 0755 root root -\n",
        ] {
            let rendered = run_logrotate_with_extras(
                "/var/log/app/*.log {\n  weekly\n}\n",
                &[("/usr/lib/tmpfiles.d/app.conf", content, 0o100644)],
            );
            assert_eq!(
                not_packaged_lines(&rendered).len(),
                1,
                "tmpfiles content {content:?} must not satisfy: {rendered:?}"
            );
        }
    }

    /// The reference's `test_logrotate` (test_logrotate.py:18): the same log
    /// dir in two configs with different `su` owners fires
    /// `logrotate-duplicate`; identical owners stay quiet.
    #[test]
    fn logrotate_duplicate_fires_on_different_su_owners() {
        let rendered = run_logrotate_two_confs(
            "/var/log/myapp/*.log {\n  su user1 group1\n}\n",
            "/var/log/myapp/*.log {\n  su user2 group2\n}\n",
        );
        let duplicates: Vec<&String> = rendered
            .iter()
            .filter(|l| l.contains("logrotate-duplicate"))
            .collect();
        assert_eq!(
            duplicates.len(),
            1,
            "expected one logrotate-duplicate: {rendered:?}"
        );
        assert_eq!(
            duplicates[0].as_str(),
            "logrotate-test.noarch: E: logrotate-duplicate /var/log/myapp",
            "level/name/detail",
        );
    }

    /// The negative side: the same owners in both configs must not fire.
    #[test]
    fn logrotate_duplicate_quiet_on_same_su_owners() {
        let rendered = run_logrotate_two_confs(
            "/var/log/myapp/*.log {\n  su user1 group1\n}\n",
            "/var/log/myapp/*.log {\n  su user1 group1\n}\n",
        );
        assert!(
            !rendered.iter().any(|l| l.contains("logrotate-duplicate")),
            "same owners must not duplicate: {rendered:?}"
        );
    }
}
