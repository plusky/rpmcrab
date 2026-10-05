//! `TmpFilesCheck` — tmpfiles.d packaging rules.
//!
//! Ported from `rpmlint/checks/TmpFilesCheck.py`. Two findings:
//! `tmpfile-not-regular-file` and `tmpfile-not-in-filelist`, plus
//! `pre-with-tmpfile-creation`.

use std::path::Path;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::is_reg;
use librpm::Tag;

pub struct TmpFilesCheck;

impl TmpFilesCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// The tmpfiles.d entry types the reference cares about.
    fn interesting_types() -> &'static [&'static str] {
        &["f", "F", "w", "d", "D", "p", "L", "c", "b"]
    }

    /// Paths referenced by a tmpfiles.d config that are not in the file list.
    fn missing_paths(content: &str, files: &[String]) -> Vec<String> {
        let mut missing = Vec::new();
        for line in content.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let mut typ = parts[0];
            if let Some(stripped) = typ.strip_suffix('!') {
                typ = stripped;
            }
            if !Self::interesting_types().contains(&typ) {
                continue;
            }
            let path = parts[1];
            if !files.iter().any(|f| f == path) {
                missing.push(path.to_string());
            }
        }
        missing.sort();
        missing.dedup();
        missing
    }

    /// Whether the `%pre` scriptlet calls `systemd-tmpfiles --create` for `basename`.
    fn pre_creates_tmpfile(pre: &str, basename: &str) -> bool {
        let pattern = format!(
            r"systemd-tmpfiles --create .*{}",
            fancy_regex::escape(basename)
        );
        let re = Regex::new(&pattern).expect("tmpfile pattern");
        is_match(&re, pre)
    }
}

impl Check for TmpFilesCheck {
    fn name(&self) -> &'static str {
        "TmpFilesCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let pre = pkg.tag_str(Tag::PREIN).unwrap_or_default();
        let file_names: Vec<String> = pkg.files.iter().map(|f| f.name.clone()).collect();

        for pkgfile in &pkg.files {
            let fname = pkgfile.name.as_str();
            if !fname.starts_with("/usr/lib/tmpfiles.d/") {
                continue;
            }
            if !is_reg(pkgfile.mode) {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "tmpfile-not-regular-file",
                    &[fname],
                );
                continue;
            }
            if pkgfile.is_ghost() {
                continue;
            }

            let basename = Path::new(fname)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if Self::pre_creates_tmpfile(&pre, &basename) {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "pre-with-tmpfile-creation",
                    &[fname],
                );
            }

            let content = pkg.read_file(fname);
            for path in Self::missing_paths(&content, &file_names) {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "tmpfile-not-in-filelist",
                    &[&path],
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_path_is_found() {
        let content = "d /run/foo 0755 root root -\n";
        let missing = TmpFilesCheck::missing_paths(content, &[]);
        assert_eq!(missing, vec!["/run/foo".to_string()]);
    }

    #[test]
    fn present_path_is_quiet() {
        let content = "d /run/foo 0755 root root -\n";
        let missing = TmpFilesCheck::missing_paths(content, &["/run/foo".to_string()]);
        assert!(missing.is_empty());
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let content = "# comment\n\nd /run/foo 0755 root root -\n";
        let missing = TmpFilesCheck::missing_paths(content, &["/run/foo".to_string()]);
        assert!(missing.is_empty());
    }

    #[test]
    fn bang_suffix_is_stripped() {
        let content = "d! /run/foo 0755 root root -\n";
        let missing = TmpFilesCheck::missing_paths(content, &[]);
        assert_eq!(missing, vec!["/run/foo".to_string()]);
    }

    #[test]
    fn uninteresting_type_is_skipped() {
        let content = "r /run/foo -\n";
        let missing = TmpFilesCheck::missing_paths(content, &[]);
        assert!(missing.is_empty());
    }

    #[test]
    fn pre_with_tmpfile_creation_is_detected() {
        let pre = "systemd-tmpfiles --create /usr/lib/tmpfiles.d/foo.conf";
        assert!(TmpFilesCheck::pre_creates_tmpfile(pre, "foo.conf"));
        assert!(!TmpFilesCheck::pre_creates_tmpfile("", "foo.conf"));
    }
    use crate::pkg::pkgfile::{PkgFile, RPMFILE_GHOST};

    /// Run `TmpFilesCheck::check_binary` over a package with the given files
    /// and return the rendered lines.
    fn run_tmpfiles(files: Vec<PkgFile>) -> Vec<String> {
        use crate::color::Color;

        let rpm = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut pkg = Pkg::open(&rpm, dir.path(), true).expect("open fixture pkg");
        pkg.name = "tmpfiles-test".to_string();
        pkg.files = files;

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = TmpFilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        out.results().iter().map(|(_, line)| line.clone()).collect()
    }

    /// The reference's `test_tmpfiles` (test_tmp_files.py:22): a symlink under
    /// `/usr/lib/tmpfiles.d/` is `W: tmpfile-not-regular-file`. The `is_reg`
    /// check runs before the ghost skip, so a ghost symlink still warns —
    /// pinning that ordering.
    #[test]
    fn symlink_conf_is_not_regular_file() {
        let rendered = run_tmpfiles(vec![PkgFile {
            name: "/usr/lib/tmpfiles.d/symlink.conf".to_string(),
            mode: 0o120777,
            linkto: "/some/where/some.conf".to_string(),
            ..Default::default()
        }]);
        let not_regular: Vec<&String> = rendered
            .iter()
            .filter(|l| l.contains("tmpfile-not-regular-file"))
            .collect();
        assert_eq!(
            not_regular.len(),
            1,
            "expected tmpfile-not-regular-file: {rendered:?}"
        );
        assert_eq!(
            not_regular[0].as_str(),
            "tmpfiles-test.noarch: W: tmpfile-not-regular-file /usr/lib/tmpfiles.d/symlink.conf",
            "level/name/detail",
        );
    }

    /// A regular ghost conf skips the not-regular-file warning entirely: the
    /// ghost early-return only runs after `is_reg` passes.
    #[test]
    fn regular_ghost_conf_skips_not_regular_file() {
        let rendered = run_tmpfiles(vec![PkgFile {
            name: "/usr/lib/tmpfiles.d/ghost.conf".to_string(),
            mode: 0o100644,
            flags: RPMFILE_GHOST,
            ..Default::default()
        }]);
        assert!(
            !rendered
                .iter()
                .any(|l| l.contains("tmpfile-not-regular-file")),
            "regular ghost must not warn: {rendered:?}"
        );
    }

    /// A ghost symlink still warns: the `is_reg` check runs before the ghost
    /// skip. Reordering the ghost early-return ahead of `is_reg` would
    /// silently drop this warning.
    #[test]
    fn ghost_symlink_conf_still_warns() {
        let rendered = run_tmpfiles(vec![PkgFile {
            name: "/usr/lib/tmpfiles.d/ghostlink.conf".to_string(),
            mode: 0o120777,
            linkto: "/some/where/some.conf".to_string(),
            flags: RPMFILE_GHOST,
            ..Default::default()
        }]);
        let not_regular: Vec<&String> = rendered
            .iter()
            .filter(|l| l.contains("tmpfile-not-regular-file"))
            .collect();
        assert_eq!(
            not_regular.len(),
            1,
            "ghost symlink must warn: {rendered:?}"
        );
        assert_eq!(
            not_regular[0].as_str(),
            "tmpfiles-test.noarch: W: tmpfile-not-regular-file /usr/lib/tmpfiles.d/ghostlink.conf",
            "level/name/detail",
        );
    }
}
