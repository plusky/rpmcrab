//! `DuplicatesCheck` — find duplicated files in the package.
//!
//! Ported from `rpmlint/checks/DuplicatesCheck.py` with the fix from
//! upstream PR #1603 (fixes #349): hardlink reporting is evaluated per
//! `(rdev, inode)` group inside each md5 group, so hardlinked files are
//! reported even in mixed hardlink/duplicate groups. The reference at the
//! pinned commit misses them (ledgered).
//!
//! Four findings: `hardlink-across-partition` (E),
//! `hardlink-across-config-files` (E), `files-duplicate` (W),
//! `files-duplicated-waste` (E).

use std::collections::{BTreeMap, BTreeSet};

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::{PkgFile, is_reg};

/// Max duplicate filenames shown in the `files-duplicate` detail.
const DUPLICATES_DISPLAY_LIMIT: usize = 5;
/// Byte threshold for `files-duplicated-waste`.
const WASTE_THRESHOLD: u64 = 100_000;

/// One duplicate group finding, for the pure core.
#[derive(Debug, PartialEq, Eq)]
enum DuplicateFinding {
    HardlinkAcrossPartition(String, String),
    HardlinkAcrossConfigFiles(String, String),
    FilesDuplicate(String, String),
    FilesDuplicatedWaste(u64),
}

pub struct DuplicatesCheck {
    min_size: u64,
}

impl DuplicatesCheck {
    pub fn new(config: &Config) -> Self {
        let min_size = config
            .configuration
            .get("DuplicatesMinSize")
            .and_then(|v| v.as_integer())
            .unwrap_or(0) as u64;
        Self { min_size }
    }

    /// First two directories of the path (`_get_prefix`).
    fn get_prefix(name: &str) -> String {
        let parts: Vec<&str> = name.split('/').collect();
        if parts.len() == 3 {
            parts[0..2].join("/")
        } else {
            parts[0..3.min(parts.len())].join("/")
        }
    }

    /// Pure core: group files by md5 and emit findings. `is_config` reports
    /// whether a filename is a config file; `is_ghost` for ghost files.
    ///
    /// Implements the #1603 fix: within each md5 group, files are further
    /// grouped by `(rdev, inode)` so hardlinked files are told apart from
    /// genuine duplicates, and hardlink findings are reported per inode
    /// group even in mixed groups.
    fn find_duplicates(
        files: &[&PkgFile],
        min_size: u64,
        is_config: impl Fn(&str) -> bool,
        is_ghost: impl Fn(&str) -> bool,
    ) -> Vec<DuplicateFinding> {
        let mut md5s: BTreeMap<&str, BTreeSet<usize>> = BTreeMap::new();
        let mut sizes: BTreeMap<&str, u64> = BTreeMap::new();
        let mut out = Vec::new();
        let mut total_dup_size: u64 = 0;

        for (i, f) in files.iter().enumerate() {
            if is_ghost(&f.name) || !is_reg(f.mode) {
                continue;
            }
            let size = f.size.unwrap_or(0);
            if size <= min_size {
                continue;
            }
            let md5 = f.md5.as_deref().unwrap_or("");
            md5s.entry(md5).or_default().insert(i);
            sizes.insert(md5, size);
        }

        for (md5_hash, indices) in &md5s {
            if indices.len() == 1 {
                continue;
            }
            let mut duplicates: Vec<usize> = indices.iter().copied().collect();
            duplicates.sort_by_key(|&i| &files[i].name);
            let first_idx = duplicates.pop().unwrap();
            let first = files[first_idx];

            // Group by (rdev, inode): each group is either hardlinked files
            // or a single genuine duplicate (#1603 fix).
            let mut inode_groups: BTreeMap<(u32, u32), Vec<usize>> = BTreeMap::new();
            for idx in std::iter::once(first_idx).chain(duplicates.iter().copied()) {
                let f = files[idx];
                inode_groups.entry((f.rdev, f.inode)).or_default().push(idx);
            }

            // Report hardlinks inside every inode group, even in groups
            // that also contain genuine duplicates.
            for group in inode_groups.values() {
                if group.len() == 1 {
                    continue;
                }
                let mut group_sorted = group.clone();
                group_sorted.sort_by_key(|&i| &files[i].name);
                let group_first_idx = group_sorted.pop().unwrap();
                let group_first = files[group_first_idx];
                let group_first_is_config = is_config(&group_first.name);
                let group_prefix = Self::get_prefix(&group_first.name);
                for &di in &group_sorted {
                    let dup = files[di];
                    if group_prefix != Self::get_prefix(&dup.name) {
                        out.push(DuplicateFinding::HardlinkAcrossPartition(
                            group_first.name.clone(),
                            dup.name.clone(),
                        ));
                    }
                    if group_first_is_config && is_config(&dup.name) {
                        out.push(DuplicateFinding::HardlinkAcrossConfigFiles(
                            group_first.name.clone(),
                            dup.name.clone(),
                        ));
                    }
                }
            }

            // `diff` counts duplicates of `first` that are not hardlinks to it.
            let first_group_len = inode_groups
                .get(&(first.rdev, first.inode))
                .map(|g| g.len())
                .unwrap_or(1);
            let diff = 1 + duplicates.len() as i64 - first_group_len as i64;

            if diff > 0 {
                let mut diff = diff;
                let prefix = Self::get_prefix(&first.name);
                for &di in &duplicates {
                    if prefix != Self::get_prefix(&files[di].name) {
                        diff -= 1;
                    }
                }
                if sizes.get(md5_hash).copied().unwrap_or(0) > 0 && diff > 0 {
                    let display: Vec<&str> = duplicates
                        .iter()
                        .take(DUPLICATES_DISPLAY_LIMIT)
                        .map(|&i| files[i].name.as_str())
                        .collect();
                    let mut description = display.join(":");
                    let rest = duplicates.len().saturating_sub(DUPLICATES_DISPLAY_LIMIT);
                    if rest > 0 {
                        description.push_str(&format!(":(and {rest} more)"));
                    }
                    out.push(DuplicateFinding::FilesDuplicate(
                        first.name.clone(),
                        description,
                    ));
                }
                total_dup_size += sizes.get(md5_hash).copied().unwrap_or(0) * diff.max(0) as u64;
            }
        }

        if total_dup_size > WASTE_THRESHOLD {
            out.push(DuplicateFinding::FilesDuplicatedWaste(total_dup_size));
        }
        out
    }
}

impl Check for DuplicatesCheck {
    fn name(&self) -> &'static str {
        "DuplicatesCheck"
    }

    fn check(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }
        let files: Vec<&PkgFile> = pkg.files.iter().collect();
        let findings = Self::find_duplicates(
            &files,
            self.min_size,
            |n| pkg.config_files.contains(&n.to_string()),
            |n| pkg.ghost_files.contains(&n.to_string()),
        );
        for f in findings {
            match f {
                DuplicateFinding::HardlinkAcrossPartition(a, b) => add_info(
                    out,
                    Level::Error,
                    pkg,
                    "hardlink-across-partition",
                    &[&a, &b],
                ),
                DuplicateFinding::HardlinkAcrossConfigFiles(a, b) => add_info(
                    out,
                    Level::Error,
                    pkg,
                    "hardlink-across-config-files",
                    &[&a, &b],
                ),
                DuplicateFinding::FilesDuplicate(a, b) => {
                    add_info(out, Level::Warning, pkg, "files-duplicate", &[&a, &b])
                }
                DuplicateFinding::FilesDuplicatedWaste(n) => add_info(
                    out,
                    Level::Error,
                    pkg,
                    "files-duplicated-waste",
                    &[&n.to_string()],
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkgfile(name: &str, md5: &str, size: u64, inode: u32) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            size: Some(size),
            md5: Some(md5.to_string()),
            rdev: 0,
            inode,
            ..Default::default()
        }
    }

    fn no_config(_: &str) -> bool {
        false
    }
    fn no_ghost(_: &str) -> bool {
        false
    }

    #[test]
    fn no_duplicates_is_quiet() {
        let files = [
            pkgfile("/usr/bin/a", "aaa", 100, 1),
            pkgfile("/usr/bin/b", "bbb", 100, 2),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert!(DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost).is_empty());
    }

    #[test]
    fn duplicate_content_is_reported() {
        let files = [
            pkgfile("/usr/bin/a", "aaa", 100, 1),
            pkgfile("/usr/bin/b", "aaa", 100, 2),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        let findings = DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, DuplicateFinding::FilesDuplicate(_, _))),
            "{findings:?}"
        );
    }

    #[test]
    fn hardlinks_are_not_duplicates() {
        let files = [
            pkgfile("/usr/bin/a", "aaa", 100, 1),
            pkgfile("/usr/bin/b", "aaa", 100, 1),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        let findings = DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f, DuplicateFinding::FilesDuplicate(_, _))),
            "{findings:?}"
        );
    }

    #[test]
    fn small_files_are_skipped() {
        let files = [
            pkgfile("/usr/bin/a", "aaa", 10, 1),
            pkgfile("/usr/bin/b", "aaa", 10, 2),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        let findings = DuplicatesCheck::find_duplicates(&refs, 50, no_config, no_ghost);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn mixed_group_reports_hardlink_across_partition() {
        // #1603: a hardlink pair sharing an md5 with a genuine duplicate
        // must still report hardlink-across-partition. The pinned reference
        // misses this (its bookkeeping is global per md5).
        let files = [
            pkgfile("/usr/bin/a", "aaa", 100, 1),
            pkgfile("/opt/bin/b", "aaa", 100, 1), // hardlink to a, other prefix
            pkgfile("/usr/bin/c", "aaa", 100, 2), // genuine duplicate
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        let findings = DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f, DuplicateFinding::HardlinkAcrossPartition(_, _))),
            "expected hardlink-across-partition in mixed group, got {findings:?}"
        );
    }

    #[test]
    fn get_prefix_two_dirs() {
        assert_eq!(DuplicatesCheck::get_prefix("/usr/bin/foo"), "/usr/bin");
        assert_eq!(DuplicatesCheck::get_prefix("/a"), "/a");
    }
}
