//! `DuplicatesCheck` — find duplicated files in the package.
//!
//! Ported from `rpmlint/checks/DuplicatesCheck.py`, adopting the fix
//! proposed in upstream PR #1603 (unmerged; fixes #349): hardlink reporting
//! is evaluated per `(rdev, inode)` group inside each md5 group. The
//! reference at the pinned commit misattributes hardlinks in mixed
//! hardlink/duplicate groups, reporting the wrong file pair (ledgered).
//!
//! `hardlink-across-partition` deliberately diverges from the reference's
//! trigger (upstream #771): the reference warns whenever the first two
//! path directories differ, which false-positives on e.g. `/usr/bin` vs
//! `/usr/lib64` — inseparable post-usr-merge. Device metadata cannot
//! replace the heuristic: rpmbuild flattens it on purpose (FILERDEVS is
//! `st_rdev`, 0 for regular files; FILEDEVICES is `1` for every file —
//! rpm's `build/files.c` stores `fl_dev ? 1 : 0`, verified as `1 1 1` on
//! a real package; FILEINODES are remapped to filelist order preserving
//! only hardlink identity), so no per-device signal survives in the
//! package. The port therefore keeps a path heuristic but narrows it to
//! the top-level directory: only hardlinks spanning genuinely separable
//! trees (`/usr` vs `/var`) are reported. The `files-duplicate`
//! cross-directory suppression uses the same narrowed definition, since
//! it encodes the same "can't be hardlinked anyway" assumption — and
//! because `files-duplicated-waste` accumulates the same suppressed
//! `diff`, its total shifts in lockstep: the port reports it with a
//! larger total where the reference's two-level suppression keeps the
//! package under the threshold (ledgered as a `detail` divergence).
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

    /// First directory of the path: `/usr` for `/usr/bin/foo`.
    ///
    /// Cross-partition detection cannot consult device numbers — rpmbuild
    /// deliberately flattens them (see the module docs) — so the check
    /// stays a path heuristic. Only the top-level directory is compared:
    /// subdirectories of one top-level tree (e.g. `/usr/bin` vs
    /// `/usr/lib64`) cannot live on different partitions in any supported
    /// layout (upstream #771), while distinct top-level trees (`/usr` vs
    /// `/var`) genuinely can.
    fn get_topdir(name: &str) -> &str {
        let rest = name.strip_prefix('/').unwrap_or(name);
        match rest.find('/') {
            Some(idx) => &name[..name.len() - rest.len() + idx],
            None => name,
        }
    }

    /// Pure core: group files by md5 and emit findings. `is_config` reports
    /// whether a filename is a config file; `is_ghost` for ghost files.
    ///
    /// Implements the #1603 fix: within each md5 group, files are further
    /// grouped by `(rdev, inode)` so hardlinked files are told apart from
    /// genuine duplicates, and hardlink findings are reported per inode
    /// group even in mixed groups. `hardlink-across-partition` fires only
    /// when a hardlink group's paths span top-level directories (#771).
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
                let group_topdir = Self::get_topdir(&group_first.name);
                for &di in &group_sorted {
                    let dup = files[di];
                    if group_topdir != Self::get_topdir(&dup.name) {
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
                let topdir = Self::get_topdir(&first.name);
                for &di in &duplicates {
                    // Duplicates under a different top-level directory
                    // cannot be hardlinked together, so they do not count
                    // as wasted space (#771: same narrowed definition as
                    // the hardlink-across-partition trigger).
                    if topdir != Self::get_topdir(&files[di].name) {
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
        // #1603: a hardlink pair sharing an md5 with a genuine duplicate.
        // The pinned reference misattributes the hardlink: it picks `first`
        // from the whole md5 group (c, the genuine duplicate) and reports
        // hardlink-across-partition(c, b). The port groups by (rdev, inode)
        // and reports the true hardlink pair (a, b).
        let files = [
            pkgfile("/usr/bin/a", "aaa", 100, 1),
            pkgfile("/opt/bin/b", "aaa", 100, 1), // hardlink to a, other topdir
            pkgfile("/usr/bin/c", "aaa", 100, 2), // genuine duplicate
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        let findings = DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost);
        assert_eq!(
            findings,
            vec![
                DuplicateFinding::HardlinkAcrossPartition("/usr/bin/a".into(), "/opt/bin/b".into(),),
                DuplicateFinding::FilesDuplicate(
                    "/usr/bin/c".into(),
                    "/opt/bin/b:/usr/bin/a".into(),
                ),
            ],
            "must name the true hardlink pair (a, b), not the reference's (c, b)"
        );
    }

    #[test]
    fn hardlink_within_one_topdir_is_quiet_771() {
        // Upstream #771: hardlinking /usr/bin against /usr/lib64 must not
        // report hardlink-across-partition — the two directories cannot live
        // on different partitions post-usr-merge. The reference's two-level
        // prefix comparison fires here; the narrowed top-level comparison
        // stays quiet.
        let files = [
            pkgfile("/usr/bin/uic-qt5", "aaa", 100, 7),
            pkgfile("/usr/lib64/qt5/bin/uic", "aaa", 100, 7),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost).is_empty(),
            "hardlink inside one top-level directory is not across-partition"
        );
    }

    #[test]
    fn hardlink_across_topdirs_is_reported() {
        // /usr vs /var are genuinely separable filesystems: still an error.
        let files = [
            pkgfile("/usr/bin/a", "aaa", 100, 1),
            pkgfile("/var/lib/b", "aaa", 100, 1),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert_eq!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost),
            vec![DuplicateFinding::HardlinkAcrossPartition(
                "/var/lib/b".into(),
                "/usr/bin/a".into(),
            )],
        );
    }

    #[test]
    fn duplicate_within_one_topdir_counts_as_waste() {
        // #771 applied to the suppression side: /usr/bin vs /usr/lib can be
        // hardlinked in practice, so the duplicate is actionable waste.
        // The reference's two-level prefix comparison suppresses it.
        let files = [
            pkgfile("/usr/bin/a", "aaa", 100, 1),
            pkgfile("/usr/lib/b", "aaa", 100, 2),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert_eq!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost),
            vec![DuplicateFinding::FilesDuplicate(
                "/usr/lib/b".into(),
                "/usr/bin/a".into(),
            )],
        );
    }

    #[test]
    fn duplicate_across_topdirs_stays_suppressed() {
        // /usr vs /etc cannot be hardlinked together: still suppressed.
        let files = [
            pkgfile("/usr/bin/a", "aaa", 100, 1),
            pkgfile("/etc/cron.d/b", "aaa", 100, 2),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost).is_empty(),
            "duplicates across top-level directories cannot be linked"
        );
    }

    #[test]
    fn get_topdir_cases() {
        assert_eq!(DuplicatesCheck::get_topdir("/usr/bin/foo"), "/usr");
        assert_eq!(
            DuplicatesCheck::get_topdir("/usr/lib64/qt5/bin/uic"),
            "/usr"
        );
        assert_eq!(DuplicatesCheck::get_topdir("/var/lib/foo"), "/var");
        assert_eq!(DuplicatesCheck::get_topdir("/a"), "/a");
        assert_eq!(DuplicatesCheck::get_topdir("usr/bin/foo"), "usr");
    }

    #[test]
    fn waste_total_follows_narrowed_suppression() {
        // #771: three same-content files, one per /usr subtree. The
        // reference's two-level prefix suppression zeroes `diff` and the
        // waste total; the narrowed top-level comparison keeps both, so
        // 2 * 60000 = 120000 exceeds the threshold and the port reports
        // E: files-duplicated-waste with that total. Restoring the
        // two-level suppression, or raising the threshold, must fail
        // this test.
        let files = [
            pkgfile("/usr/bin/x", "aaa", 60_000, 1),
            pkgfile("/usr/lib/y", "aaa", 60_000, 2),
            pkgfile("/usr/share/z", "aaa", 60_000, 3),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert_eq!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost),
            vec![
                DuplicateFinding::FilesDuplicate(
                    "/usr/share/z".into(),
                    "/usr/bin/x:/usr/lib/y".into(),
                ),
                DuplicateFinding::FilesDuplicatedWaste(120_000),
            ],
        );
    }
}
