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
}

impl Check for DeviceFilesCheck {
    fn name(&self) -> &'static str {
        "DeviceFilesCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let files = Self::device_files(&pkg.files);
        for v in file_metadata::verify_files("device", &self.whitelists, &pkg.name, &files) {
            match v.detail {
                Some(d) => add_info(out, Level::Error, pkg, &v.check, &[&v.filename, &d]),
                None => add_info(out, Level::Error, pkg, &v.check, &[&v.filename]),
            }
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
}
