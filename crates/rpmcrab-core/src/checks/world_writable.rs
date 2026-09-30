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
        for v in file_metadata::verify_files("world-writable", &self.whitelists, &pkg.name, &files)
        {
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
}
