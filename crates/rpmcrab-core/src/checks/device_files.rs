//! `DeviceFilesCheck` — device files need security-team whitelisting.
//!
//! Ported from `rpmlint/checks/DeviceFilesCheck.py`. Two findings:
//! `device-unauthorized-file` and `device-mismatched-attrs`. The whitelist
//! plumbing lives in [`crate::checks::file_metadata`].

use std::collections::HashMap;

use crate::check::{Check, add_info};
use crate::checks::file_metadata::{self, FileMeta};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::PkgFile;

pub struct DeviceFilesCheck {
    whitelists: Vec<file_metadata::Whitelist>,
}

impl DeviceFilesCheck {
    pub fn new(config: &Config) -> Self {
        Self {
            whitelists: file_metadata::load_whitelists(
                config,
                "DeviceFilesWhitelist",
                &[
                    "path",
                    "owner",
                    "group",
                    "mode",
                    "device_minor",
                    "device_major",
                ],
            ),
        }
    }

    /// The package's block and character devices: `{path: file}` for files
    /// whose mode starts with `b`/`c`, last wins, in first-insertion order —
    /// like the reference's dict comprehension (symlinks excluded: their
    /// mode starts with `l`).
    fn device_files<'a>(files: &'a [PkgFile]) -> Vec<FileMeta<'a>> {
        let mut order: Vec<FileMeta<'a>> = Vec::new();
        let mut index: HashMap<&str, usize> = HashMap::new();
        for f in files {
            let meta = FileMeta::new(f);
            if !(meta.mode.starts_with('b') || meta.mode.starts_with('c')) {
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
                    findings.push((Level::Error, "device-unauthorized-file", details));
                }
                file_metadata::VerdictKind::MismatchedAttrs => {
                    findings.push((Level::Error, "device-mismatched-attrs", details));
                }
            }
        }
        findings
    }
}

impl Check for DeviceFilesCheck {
    fn name(&self) -> &'static str {
        "DeviceFilesCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let files = Self::device_files(&pkg.files);
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

    fn pkg_file(name: &str, mode: u32, user: &str, group: &str, rdev: u32) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode,
            user: user.to_string(),
            group: group.to_string(),
            rdev,
            ..Default::default()
        }
    }

    #[test]
    fn selects_only_block_and_character_devices() {
        let files = [
            pkg_file("/dev/sda", 0o60660, "root", "root", 0x801),
            pkg_file("/dev/null", 0o20666, "root", "root", 0x103),
            pkg_file("/etc/passwd", 0o100644, "root", "root", 0),
            pkg_file("/dev/link", 0o120777, "root", "root", 0),
        ];
        let selected = DeviceFilesCheck::device_files(&files);
        let paths: Vec<&str> = selected.iter().map(|m| m.path).collect();
        assert_eq!(paths, ["/dev/sda", "/dev/null"]);
    }

    #[test]
    fn later_duplicate_path_wins() {
        let files = [
            pkg_file("/dev/sda", 0o60660, "root", "root", 0x801),
            pkg_file("/dev/sda", 0o20660, "root", "tty", 0x401),
        ];
        let selected = DeviceFilesCheck::device_files(&files);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].mode, "crw-rw----");
        assert_eq!(selected[0].group, "tty");
    }

    fn test_config() -> Config {
        let table: toml::Table = toml::from_str(
            r#"
[[DeviceFilesWhitelist]]
package = "dummy"
[[DeviceFilesWhitelist.files]]
path = '/dev/sdb1'
mode = "crw-rw----"
owner = "root"
group = "tty"
device_minor = 12
device_major = 55
"#,
        )
        .expect("parse test whitelist");
        Config {
            configuration: table,
            ..Default::default()
        }
    }

    fn findings(files: &[PkgFile]) -> Vec<(Level, &'static str, Vec<String>)> {
        let check = DeviceFilesCheck::new(&test_config());
        let metas: Vec<FileMeta> = files.iter().map(FileMeta::new).collect();
        check.binary_findings("dummy", &metas)
    }

    #[test]
    fn unauthorized_file_is_an_error_without_detail() {
        // The `None` arm: just the filename reaches `add_info`.
        let files = [pkg_file("/dev/mydevice", 0o60660, "root", "root", 0x801)];
        let found = findings(&files);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Error);
        assert_eq!(found[0].1, "device-unauthorized-file");
        assert_eq!(found[0].2, vec!["/dev/mydevice".to_string()]);
    }

    #[test]
    fn mismatched_attrs_is_an_error_with_detail() {
        // The `Some` arm: the expected-vs-actual detail is appended.
        // Whitelisted as crw-rw---- root:tty; this is a block device.
        let files = [pkg_file("/dev/sdb1", 0o60660, "root", "root", 0x801)];
        let found = findings(&files);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Error);
        assert_eq!(found[0].1, "device-mismatched-attrs");
        assert_eq!(found[0].2.len(), 2);
        assert_eq!(found[0].2[0], "/dev/sdb1");
        assert!(
            found[0].2[1].starts_with("expected \"mode\""),
            "unexpected detail: {}",
            found[0].2[1]
        );
    }

    #[test]
    fn check_binary_entry_point_reports_through_filter() {
        // Kills M7 (check_binary emitting nothing): the whole entry point
        // must run for findings to reach the `Filter`.
        use std::path::Path;

        use crate::color::Color;

        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir()).expect("open fixture pkg");
        pkg.name = "dummy".to_string();
        pkg.files = vec![pkg_file("/dev/mydevice", 0o60660, "root", "root", 0x801)];
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = DeviceFilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["device-unauthorized-file"]);
    }
}
