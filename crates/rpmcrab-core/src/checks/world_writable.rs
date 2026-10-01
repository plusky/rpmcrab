//! `WorldWritableCheck` — world-writable files need security-team whitelisting.
//!
//! Ported from `rpmlint/checks/WorldWritableCheck.py`. Two findings:
//! `world-writable-unauthorized-file` and `world-writable-mismatched-attrs`.
//! The whitelist plumbing lives in [`crate::checks::file_metadata`].

use std::collections::HashMap;

use crate::check::{Check, add_info};
use crate::checks::file_metadata::{self, FileMeta};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::PkgFile;

pub struct WorldWritableCheck {
    whitelists: Vec<file_metadata::Whitelist>,
}

impl WorldWritableCheck {
    pub fn new(config: &Config) -> Self {
        Self {
            whitelists: file_metadata::load_whitelists(
                config,
                "WorldWritableWhitelist",
                &["path", "owner", "group", "mode"],
            ),
        }
    }

    /// World-writable files except device files and symlinks: `mode[0]` not
    /// in `bcl` and `mode[-2]` (the other-write bit) is `w`. Last wins per
    /// path, in first-insertion order — like the reference.
    fn world_writable<'a>(files: &'a [PkgFile]) -> Vec<FileMeta<'a>> {
        let mut order: Vec<FileMeta<'a>> = Vec::new();
        let mut index: HashMap<&str, usize> = HashMap::new();
        for f in files {
            let meta = FileMeta::new(f);
            if !is_world_writable(&meta.mode) {
                continue;
            }
            match index.get(meta.path) {
                Some(&i) => order[i] = meta,
                None => {
                    index.insert(meta.path, order.len());
                    order.push(meta);
                }
            }
        }
        order
    }

    /// The findings as pure data: always `Level::Error`. A file missing from
    /// the whitelist (`*-unauthorized-file`) carries just the filename; an
    /// attribute mismatch (`*-mismatched-attrs`) appends the detail.
    fn binary_findings(
        &self,
        pkg_name: &str,
        files: &[FileMeta],
    ) -> Vec<(Level, &'static str, Vec<String>)> {
        let mut findings = Vec::new();
        for v in file_metadata::verify_files(&self.whitelists, pkg_name, files) {
            let mut details = vec![v.filename];
            if let Some(d) = v.detail {
                details.push(d);
            }
            // Literal names in the push tuples: the reference-coverage
            // audit collects these sites textually, so the name must not
            // be built through a variable or format!.
            match v.kind {
                file_metadata::VerdictKind::UnauthorizedFile => {
                    findings.push((Level::Error, "world-writable-unauthorized-file", details));
                }
                file_metadata::VerdictKind::MismatchedAttrs => {
                    findings.push((Level::Error, "world-writable-mismatched-attrs", details));
                }
            }
        }
        findings
    }
}

/// The reference's `f.mode[0] not in 'bcl' and f.mode[-2] == 'w'`.
fn is_world_writable(mode: &str) -> bool {
    if matches!(mode.chars().next(), Some('b' | 'c' | 'l')) {
        return false;
    }
    mode.chars().nth_back(1) == Some('w')
}

impl Check for WorldWritableCheck {
    fn name(&self) -> &'static str {
        "WorldWritableCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let files = Self::world_writable(&pkg.files);
        let findings = self.binary_findings(&pkg.name, &files);
        for (level, check, details) in findings {
            let refs: Vec<&str> = details.iter().map(String::as_str).collect();
            add_info(out, level, pkg, check, &refs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg_file(name: &str, mode: u32) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode,
            user: "root".to_string(),
            group: "root".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn selects_world_writable_files() {
        let files = [
            pkg_file("/tmp", 0o41777),
            pkg_file("/var/tmp", 0o41777),
            pkg_file("/etc/passwd", 0o100644),
            pkg_file("/run/app.sock", 0o140777),
        ];
        let selected = WorldWritableCheck::world_writable(&files);
        let paths: Vec<&str> = selected.iter().map(|m| m.path).collect();
        // Sockets are world-writable but not `bcl`-excluded... they are
        // selected: the reference only excludes b/c/l.
        assert_eq!(paths, ["/tmp", "/var/tmp", "/run/app.sock"]);
    }

    #[test]
    fn skips_devices_symlinks_and_non_writable() {
        let files = [
            pkg_file("/dev/sda", 0o60666),
            pkg_file("/dev/null", 0o20666),
            pkg_file("/etc/link", 0o120777),
            pkg_file("/etc/shadow", 0o100640),
        ];
        let selected = WorldWritableCheck::world_writable(&files);
        assert!(selected.is_empty(), "{selected:?}");
    }

    #[test]
    fn sticky_bit_without_other_write_is_quiet() {
        // `mode[-2]` is the other-write bit, not the sticky bit.
        let files = [pkg_file("/var/spool", 0o411755)];
        let selected = WorldWritableCheck::world_writable(&files);
        assert!(selected.is_empty(), "{selected:?}");
    }

    fn test_config() -> Config {
        let table: toml::Table = toml::from_str(
            r#"
[[WorldWritableWhitelist]]
package = "dummy"
[[WorldWritableWhitelist.files]]
path = '/tempus'
mode = "drw-rw---t"
owner = "root"
group = "tty"
"#,
        )
        .expect("parse test whitelist");
        Config {
            configuration: table,
            ..Default::default()
        }
    }

    fn findings(files: &[PkgFile]) -> Vec<(Level, &'static str, Vec<String>)> {
        let check = WorldWritableCheck::new(&test_config());
        let metas: Vec<FileMeta> = files.iter().map(FileMeta::new).collect();
        check.binary_findings("dummy", &metas)
    }

    #[test]
    fn unauthorized_file_is_an_error_without_detail() {
        // The `None` arm: just the filename reaches `add_info`.
        let files = [pkg_file("/tmp", 0o41777)];
        let found = findings(&files);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Error);
        assert_eq!(found[0].1, "world-writable-unauthorized-file");
        assert_eq!(found[0].2, vec!["/tmp".to_string()]);
    }

    #[test]
    fn mismatched_attrs_is_an_error_with_detail() {
        // The `Some` arm: the expected-vs-actual detail is appended.
        // Whitelisted as drw-rw---t; the actual mode is drwxrwxrwt.
        let files = [pkg_file("/tempus", 0o41777)];
        let found = findings(&files);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Error);
        assert_eq!(found[0].1, "world-writable-mismatched-attrs");
        assert_eq!(found[0].2.len(), 2);
        assert_eq!(found[0].2[0], "/tempus");
        assert!(
            found[0].2[1].starts_with("expected \"mode\""),
            "unexpected detail: {}",
            found[0].2[1]
        );
    }

    #[test]
    fn check_binary_entry_point_reports_through_filter() {
        // Kills M14 (check_binary emitting nothing): the whole entry point
        // must run for findings to reach the `Filter`.
        use std::path::Path;

        use crate::color::Color;

        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir()).expect("open fixture pkg");
        pkg.name = "dummy".to_string();
        pkg.files = vec![pkg_file("/tmp", 0o41777)];
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = WorldWritableCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["world-writable-unauthorized-file"]);
    }
}
