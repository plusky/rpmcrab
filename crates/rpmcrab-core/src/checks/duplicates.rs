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
//! cross-directory suppression shares this narrowed definition — the
//! same "can't be hardlinked anyway" assumption — and because
//! `files-duplicated-waste` accumulates the same suppressed `diff`,
//! its total shifts in lockstep: the port reports it with a larger
//! total where the reference's two-level suppression keeps the
//! package under the threshold (ledgered as a `behaviour` divergence).
//!
//! One md5 group shape is suppressed outright (issue #518): when every
//! member is a bytecode variant of one module — same directory and stem,
//! differing only in interpreter cache tag, `.opt-N` level or
//! `.pyc`/`.pyo` extension — the group is the standard bytecompile
//! output emitted at several optimisation levels. The distro's macros
//! generate every level unconditionally, and neither the dedicated
//! hardlink brp (not wired into the build) nor `%fdupes` links the
//! variants, so no packager action reclaims the space: the group is not
//! reported and contributes nothing to the waste total (ledgered as a
//! `behaviour` divergence). Mixed groups — variants plus a real file, or
//! bytecode of different modules or directories — report as before.
//! A duplicate group whose members are all %config files is not
//! reported either: every copy is meant to be edited independently
//! after install (per-version copies, a live file beside its
//! example or default template), so hardlinking any two would
//! couple edits that must stay separate. The group contributes
//! nothing to the waste total. Existing hardlinks between config
//! files still fire `hardlink-across-config-files`: an
//! already-hardlinked pair is a hazard regardless of whether the
//! group itself is reported.
//! A duplicate that forms a pair listed in the `DuplicatesWhitelistPairs`
//! config key does not count toward the same `diff`: both directories of
//! a whitelisted pair are exacted by different tooling, so neither copy
//! can be dropped and the duplication is not actionable. The bundled
//! defaults pair the `*.dist-info/licenses` embed the Python stack
//! requires (PEP 639) -- or the licence file at the `*.dist-info` root
//! in the pre-PEP 639 layout -- with the `%license` copy SUSE policy
//! requires in `/usr/share/licenses`, or the `%docdir` copy under
//! `/usr/share/doc/packages`. The pair likewise stays out of the
//! `files-duplicated-waste` total, which accumulates the same `diff`.
//!
//! Four findings: `hardlink-across-partition` (E),
//! `hardlink-across-config-files` (E), `files-duplicate` (W),
//! `files-duplicated-waste` (W).

use std::collections::{BTreeMap, BTreeSet};

use super::shared::is_mingw_package;
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

/// One side of a `DuplicatesWhitelistPairs` entry: a directory pattern.
///
/// A pattern starting with `/` is an absolute directory prefix; any other
/// pattern is matched against consecutive path components anywhere in
/// the path. A component may contain `*`, matching any (possibly empty)
/// text within that component.
struct DirPattern {
    anchored: bool,
    components: Vec<String>,
}

impl DirPattern {
    fn parse(text: &str) -> Self {
        Self {
            anchored: text.starts_with('/'),
            components: text
                .split('/')
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .collect(),
        }
    }

    /// Whether the directory part of `path` matches this pattern.
    fn matches(&self, path: &str) -> bool {
        let dir: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        // The last component is the file name; patterns name directories.
        let dir = &dir[..dir.len().saturating_sub(1)];
        if self.components.is_empty() || self.components.len() > dir.len() {
            return false;
        }
        if self.anchored {
            self.components
                .iter()
                .zip(dir.iter())
                .all(|(p, c)| component_matches(p, c))
        } else {
            dir.windows(self.components.len()).any(|window| {
                self.components
                    .iter()
                    .zip(window)
                    .all(|(p, c)| component_matches(p, c))
            })
        }
    }
}

/// A directory pair from `DuplicatesWhitelistPairs`: duplicates sitting
/// one under each directory of the pair do not count against each other.
struct WhitelistPair {
    first: DirPattern,
    second: DirPattern,
}

impl WhitelistPair {
    /// Whether the two file paths sit one under each directory of the pair.
    fn matches(&self, a: &str, b: &str) -> bool {
        (self.first.matches(a) && self.second.matches(b))
            || (self.first.matches(b) && self.second.matches(a))
    }
}

/// Whether one path component matches a pattern component; `*` matches
/// any (possibly empty) text, every other character is literal.
fn component_matches(pattern: &str, component: &str) -> bool {
    fn go(pattern: &[u8], text: &[u8]) -> bool {
        if pattern.is_empty() {
            return text.is_empty();
        }
        if pattern[0] == b'*' {
            return (0..=text.len()).any(|i| go(&pattern[1..], &text[i..]));
        }
        !text.is_empty() && pattern[0] == text[0] && go(&pattern[1..], &text[1..])
    }
    go(pattern.as_bytes(), component.as_bytes())
}

pub struct DuplicatesCheck {
    min_size: u64,
    whitelist_pairs: Vec<WhitelistPair>,
}

impl DuplicatesCheck {
    pub fn new(config: &Config) -> Self {
        let min_size = config
            .configuration
            .get("DuplicatesMinSize")
            .and_then(|v| v.as_integer())
            .unwrap_or(0) as u64;
        Self {
            min_size,
            whitelist_pairs: Self::parse_whitelist_pairs(config),
        }
    }

    /// The `DuplicatesWhitelistPairs` config value: a list of
    /// two-pattern directory pairs. Malformed entries are skipped; the
    /// bundled defaults are well-formed.
    fn parse_whitelist_pairs(config: &Config) -> Vec<WhitelistPair> {
        let Some(entries) = config
            .configuration
            .get("DuplicatesWhitelistPairs")
            .and_then(|v| v.as_array())
        else {
            return Vec::new();
        };
        entries
            .iter()
            .filter_map(|entry| {
                let pair = entry.as_array()?;
                let (first, second) = match pair.as_slice() {
                    [first, second] => (first.as_str()?, second.as_str()?),
                    _ => return None,
                };
                Some(WhitelistPair {
                    first: DirPattern::parse(first),
                    second: DirPattern::parse(second),
                })
            })
            .collect()
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

    /// Whether every file in an md5 group is a bytecode variant of the
    /// same module: same directory and stem for all members (issue #518).
    fn is_bytecode_variant_group(files: &[&PkgFile], indices: &BTreeSet<usize>) -> bool {
        let mut key: Option<(&str, &str)> = None;
        for &i in indices {
            let Some(k) = Self::bytecode_key(&files[i].name) else {
                return false;
            };
            match key {
                None => key = Some(k),
                Some(prev) if prev != k => return false,
                _ => {}
            }
        }
        key.is_some()
    }

    /// `(directory, module stem)` for a Python bytecode file name, or
    /// `None` for any other file. The stem strips the `.pyc`/`.pyo`
    /// extension, an `.opt-N` optimisation suffix and one trailing
    /// interpreter cache tag (`.cpython-313`, `.pypy310`, ...), so
    /// `__pycache__/mod.cpython-313.opt-1.pyc`,
    /// `__pycache__/mod.cpython-313.pyc` and the legacy `mod.pyo` all
    /// map to the same module.
    fn bytecode_key(name: &str) -> Option<(&str, &str)> {
        let (dir, base) = name.rsplit_once('/')?;
        let mut stem = base
            .strip_suffix(".pyc")
            .or_else(|| base.strip_suffix(".pyo"))?;
        if let Some(idx) = stem.rfind(".opt-") {
            let level = &stem[idx + ".opt-".len()..];
            if !level.is_empty() && level.bytes().all(|b| b.is_ascii_digit()) {
                stem = &stem[..idx];
            }
        }
        if let Some(idx) = stem.rfind('.') {
            let tag = &stem[idx + 1..];
            let known = ["cpython-", "pypy", "graalpy-", "ironpython-", "jython-"]
                .iter()
                .any(|prefix| tag.starts_with(prefix));
            if known && tag.bytes().any(|b| b.is_ascii_digit()) {
                stem = &stem[..idx];
            }
        }
        if stem.is_empty() {
            return None;
        }
        Some((dir, stem))
    }

    /// Pure core: group files by (digest, mode, filecaps) and emit findings. `is_config` reports
    /// whether a filename is a config file; `is_ghost` for ghost files;
    /// `is_whitelisted_pair` whether two filenames sit one under each
    /// directory of a `DuplicatesWhitelistPairs` pair.
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
        is_whitelisted_pair: impl Fn(&str, &str) -> bool,
    ) -> Vec<DuplicateFinding> {
        // Grouped by (digest, mode, filecaps), not by digest alone:
        // copies differing only in mode or filecaps are not
        // hardlinkable to each other (a hardlink shares one inode,
        // hence one mode and one capability set), so they are not
        // duplicates of each other. The finer key cannot split a
        // hardlink pair: same inode implies same mode and caps.
        let mut md5s: BTreeMap<(&str, u32, Option<&str>), BTreeSet<usize>> = BTreeMap::new();
        let mut sizes: BTreeMap<(&str, u32, Option<&str>), u64> = BTreeMap::new();
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
            // A missing or empty digest proves nothing about content:
            // digest-less files never group (fail-closed), so two
            // files with unknown digests are not reported as
            // duplicates of each other.
            let Some(md5) = f.md5.as_deref().filter(|d| !d.is_empty()) else {
                continue;
            };
            let key = (md5, f.mode, f.filecaps.as_deref());
            md5s.entry(key).or_default().insert(i);
            sizes.insert(key, size);
        }

        for (group_key, indices) in &md5s {
            if indices.len() == 1 {
                continue;
            }
            if Self::is_bytecode_variant_group(files, indices) {
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

            // Config-only groups are not actionable: every copy is a
            // %config file, meant to be edited independently after
            // install, so no copy can be hardlinked to another
            // without coupling edits. The group contributes nothing
            // to the waste total and is not reported. Hardlink
            // findings above still fire: existing hardlinks between
            // config files are a hazard of their own.
            if indices.iter().all(|&i| is_config(&files[i].name)) {
                continue;
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
                    // Hardlinks to `first` are not part of `diff` (the
                    // inode-group size already excluded them), so they
                    // must not decrement it either.
                    if (files[di].rdev, files[di].inode) == (first.rdev, first.inode) {
                        continue;
                    }
                    // Duplicates under a different top-level directory
                    // cannot be hardlinked together, so they do not count
                    // as wasted space (#771: same narrowed definition as
                    // the hardlink-across-partition trigger). A duplicate
                    // forming a whitelisted pair with `first` does not
                    // count either: both copies are tooling-mandated.
                    if topdir != Self::get_topdir(&files[di].name)
                        || is_whitelisted_pair(&first.name, &files[di].name)
                    {
                        diff -= 1;
                    }
                }
                if sizes.get(group_key).copied().unwrap_or(0) > 0 && diff > 0 {
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
                total_dup_size += sizes.get(group_key).copied().unwrap_or(0) * diff.max(0) as u64;
            }
        }

        if total_dup_size > WASTE_THRESHOLD {
            out.push(DuplicateFinding::FilesDuplicatedWaste(total_dup_size));
        }
        out
    }

    /// Output level, finding name and detail strings for one finding, in a
    /// single `match` arm per variant.
    ///
    /// One match cannot mispair with itself: the name, the level and the
    /// details for a variant are produced together, so there is no second,
    /// independent name `match` that could drift out of agreement (that
    /// shape let a swapped arm stay green). Tests pin the triple per
    /// variant through the real emission path. The reference-coverage
    /// auditor resolves the names from this helper (see `dynamic_sites`
    /// in `scripts/audit-reference-coverage.py`).
    fn describe(f: &DuplicateFinding) -> (Level, &'static str, Vec<String>) {
        match f {
            DuplicateFinding::HardlinkAcrossPartition(a, b) => (
                Level::Error,
                "hardlink-across-partition",
                vec![a.clone(), b.clone()],
            ),
            DuplicateFinding::HardlinkAcrossConfigFiles(a, b) => (
                Level::Error,
                "hardlink-across-config-files",
                vec![a.clone(), b.clone()],
            ),
            DuplicateFinding::FilesDuplicate(a, b) => (
                Level::Warning,
                "files-duplicate",
                vec![a.clone(), b.clone()],
            ),
            DuplicateFinding::FilesDuplicatedWaste(n) => (
                Level::Warning,
                "files-duplicated-waste",
                vec![n.to_string()],
            ),
        }
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
        let mut findings = Self::find_duplicates(
            &files,
            self.min_size,
            |n| pkg.config_files.contains(&n.to_string()),
            |n| pkg.ghost_files.contains(n),
            |a, b| self.whitelist_pairs.iter().any(|pair| pair.matches(a, b)),
        );
        if is_mingw_package(&pkg.name) {
            // The Factory lint session filters files-duplicate wholesale
            // for the MinGW family via mingw32.toml
            // ('^mingw(32|64)-.*files-duplicate'), a config the
            // mingw32/64-filesystem packages install into the lint
            // environment and the mirrored config set never contains.
            // The filter line also catches files-duplicated-waste, whose
            // name shares the prefix, so both findings drop; the
            // hardlink findings stay -- the config does not filter them
            // (issue #522, divergences.toml).
            findings.retain(|f| {
                !matches!(
                    f,
                    DuplicateFinding::FilesDuplicate(..)
                        | DuplicateFinding::FilesDuplicatedWaste(..)
                )
            });
        }
        for f in &findings {
            let (level, name, details) = Self::describe(f);
            // `describe` yields at most two detail strings: a stack array
            // avoids a per-finding heap allocation for the `&str` view.
            debug_assert!(details.len() <= 2);
            let mut detail_refs = [""; 2];
            for (slot, detail) in detail_refs.iter_mut().zip(details.iter()) {
                *slot = detail;
            }
            add_info(out, level, pkg, name, &detail_refs[..details.len()]);
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
    fn no_whitelist(_: &str, _: &str) -> bool {
        false
    }

    /// The bundled defaults' whitelist pairs, via the real parse path.
    fn bundled_whitelist() -> Vec<WhitelistPair> {
        let table: toml::Table = toml::from_str(include_str!("../../data/configdefaults.toml"))
            .expect("parse configdefaults");
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        DuplicatesCheck::parse_whitelist_pairs(&config)
    }

    fn is_whitelisted(pairs: &[WhitelistPair]) -> impl Fn(&str, &str) -> bool + '_ {
        move |a, b| pairs.iter().any(|p| p.matches(a, b))
    }

    #[test]
    fn no_duplicates_is_quiet() {
        let files = [
            pkgfile("/usr/bin/a", "aaa", 100, 1),
            pkgfile("/usr/bin/b", "bbb", 100, 2),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist)
                .is_empty()
        );
    }

    #[test]
    fn duplicate_content_is_reported() {
        let files = [
            pkgfile("/usr/bin/a", "aaa", 100, 1),
            pkgfile("/usr/bin/b", "aaa", 100, 2),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        let findings =
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist);
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
        let findings =
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist);
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
        let findings =
            DuplicatesCheck::find_duplicates(&refs, 50, no_config, no_ghost, no_whitelist);
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
        let findings =
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist);
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
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist)
                .is_empty(),
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
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist),
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
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist),
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
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist)
                .is_empty(),
            "duplicates across top-level directories cannot be linked"
        );
    }

    #[test]
    fn same_digest_different_mode_is_not_a_duplicate() {
        // N=3 mixed by mode: two 644 copies are duplicates of each
        // other; the 755 copy with the same digest is not (a hardlink
        // would lose its mode), so it neither fires nor appears.
        let a = pkgfile("/usr/bin/a", "aaa", 100, 1);
        let b = pkgfile("/usr/bin/b", "aaa", 100, 2);
        let mut c = pkgfile("/usr/bin/c", "aaa", 100, 3);
        c.mode = 0o100755;
        let files = [a, b, c];
        let refs: Vec<&PkgFile> = files.iter().collect();
        let findings =
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist);
        assert_eq!(
            findings,
            vec![DuplicateFinding::FilesDuplicate(
                "/usr/bin/b".into(),
                "/usr/bin/a".into(),
            )],
            "only the same-mode pair fires: {findings:?}"
        );
    }

    #[test]
    fn same_digest_different_filecaps_is_not_a_duplicate() {
        // Same shape with filecaps: a capability-carrying copy is
        // not a duplicate of a plain copy with the same digest.
        let a = pkgfile("/usr/bin/a", "aaa", 100, 1);
        let mut b = pkgfile("/usr/bin/b", "aaa", 100, 2);
        b.filecaps = Some("cap_net_raw+ep".to_string());
        let files = [a, b];
        let refs: Vec<&PkgFile> = files.iter().collect();
        let findings =
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist);
        assert!(
            findings.is_empty(),
            "caps-differing pair must stay quiet: {findings:?}"
        );
    }

    #[test]
    fn digest_less_files_never_group() {
        // Two files with unknown digests are not duplicates: no
        // digest means no evidence of identical content.
        let mut a = pkgfile("/usr/bin/a", "aaa", 100, 1);
        let mut b = pkgfile("/usr/bin/b", "aaa", 100, 2);
        a.md5 = None;
        b.md5 = Some(String::new());
        let files = [a, b];
        let refs: Vec<&PkgFile> = files.iter().collect();
        let findings =
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist);
        assert!(
            findings.is_empty(),
            "digest-less pair must stay quiet: {findings:?}"
        );
    }

    #[test]
    fn digest_less_hardlink_pair_stays_quiet() {
        // The digest-less skip runs before inode grouping, so a
        // hardlink pair with unknown digests earns neither a
        // duplicate nor a hardlink finding, even though inode
        // equality alone proves the same content. Disclosed in the
        // DuplicatesCheck ledger entry; narrowing the skip to
        // content grouping would report hardlinks the reference
        // (md5-first grouping) does not.
        let mut a = pkgfile("/usr/bin/a", "aaa", 100, 1);
        let mut b = pkgfile("/opt/bin/b", "aaa", 100, 1);
        a.md5 = None;
        b.md5 = Some(String::new());
        let files = [a, b];
        let refs: Vec<&PkgFile> = files.iter().collect();
        let findings =
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist);
        assert!(
            findings.is_empty(),
            "digest-less hardlink pair must stay quiet: {findings:?}"
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
        // W: files-duplicated-waste with that total. Restoring the
        // two-level suppression, or raising the threshold, must fail
        // this test.
        let files = [
            pkgfile("/usr/bin/x", "aaa", 60_000, 1),
            pkgfile("/usr/lib/y", "aaa", 60_000, 2),
            pkgfile("/usr/share/z", "aaa", 60_000, 3),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert_eq!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist),
            vec![
                DuplicateFinding::FilesDuplicate(
                    "/usr/share/z".into(),
                    "/usr/bin/x:/usr/lib/y".into(),
                ),
                DuplicateFinding::FilesDuplicatedWaste(120_000),
            ],
        );
    }

    #[test]
    fn distinfo_license_pair_is_whitelisted() {
        // Issue #510: the *.dist-info/licenses embed (PEP 639) and the
        // %license copy in /usr/share/licenses are both mandated, so the
        // pair is not reported -- at any size (150_000 also pins that the
        // pair stays out of the files-duplicated-waste total).
        let pairs = bundled_whitelist();
        assert!(!pairs.is_empty(), "bundled defaults must carry the pairs");
        for size in [100, 150_000] {
            let files = [
                pkgfile(
                    "/usr/lib/python3.13/site-packages/foo-1.0.dist-info/licenses/LICENSE",
                    "aaa",
                    size,
                    1,
                ),
                pkgfile("/usr/share/licenses/foo/LICENSE", "aaa", size, 2),
            ];
            let refs: Vec<&PkgFile> = files.iter().collect();
            assert!(
                DuplicatesCheck::find_duplicates(
                    &refs,
                    0,
                    no_config,
                    no_ghost,
                    is_whitelisted(&pairs)
                )
                .is_empty(),
                "size {size}"
            );
        }
        // The pre-PEP 639 layout -- the licence file at the dist-info
        // root, with no licenses/ subdirectory -- is the same embed in
        // an older spelling and pairs the same way.
        for counterpart in [
            "/usr/share/licenses/foo/LICENSE",
            "/usr/share/doc/packages/foo/LICENSE",
        ] {
            let files = [
                pkgfile(
                    "/usr/lib/python3.13/site-packages/foo-1.0.dist-info/LICENSE",
                    "aaa",
                    100,
                    1,
                ),
                pkgfile(counterpart, "aaa", 100, 2),
            ];
            let refs: Vec<&PkgFile> = files.iter().collect();
            assert!(
                DuplicatesCheck::find_duplicates(
                    &refs,
                    0,
                    no_config,
                    no_ghost,
                    is_whitelisted(&pairs)
                )
                .is_empty(),
                "counterpart {counterpart}"
            );
        }
        // The %docdir variant of the pair is whitelisted too.
        let files = [
            pkgfile(
                "/usr/lib/python3.13/site-packages/foo-1.0.dist-info/licenses/LICENSE",
                "aaa",
                100,
                1,
            ),
            pkgfile("/usr/share/doc/packages/foo/LICENSE", "aaa", 100, 2),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, is_whitelisted(&pairs))
                .is_empty()
        );
    }

    #[test]
    fn license_pairs_without_distinfo_still_fire() {
        // The whitelist covers only the dist-info pair: a %license copy
        // duplicated into the %docdir (no dist-info member), a dist-info
        // license duplicated into an unrelated directory, and two
        // dist-info copies of one file all keep firing.
        let pairs = bundled_whitelist();
        for (a, b) in [
            (
                "/usr/share/licenses/foo/LICENSE",
                "/usr/share/doc/packages/foo/LICENSE",
            ),
            (
                "/usr/lib/python3.13/site-packages/foo-1.0.dist-info/licenses/LICENSE",
                "/usr/share/foo/LICENSE",
            ),
            (
                "/usr/lib/python3.13/site-packages/foo-1.0.dist-info/LICENSE",
                "/usr/share/foo/LICENSE",
            ),
            (
                "/usr/lib/python3.13/site-packages/foo-1.0.dist-info/licenses/LICENSE",
                "/usr/lib/python3.13/site-packages/bar-2.0.dist-info/licenses/LICENSE",
            ),
        ] {
            let files = [pkgfile(a, "aaa", 100, 1), pkgfile(b, "aaa", 100, 2)];
            let refs: Vec<&PkgFile> = files.iter().collect();
            let findings = DuplicatesCheck::find_duplicates(
                &refs,
                0,
                no_config,
                no_ghost,
                is_whitelisted(&pairs),
            );
            assert!(
                findings
                    .iter()
                    .any(|f| matches!(f, DuplicateFinding::FilesDuplicate(_, _))),
                "{a} vs {b}: {findings:?}"
            );
        }
    }

    #[test]
    fn mixed_group_whitelists_only_the_pair() {
        // Three identical copies: the %license file (first), its
        // dist-info embed (whitelisted against first) and a %docdir copy
        // (no dist-info member, so not a pair). Only the pair member is
        // suppressed; the group still fires on the remaining duplicate.
        // Suppressed members still appear in the detail, as with the
        // top-level-directory suppression. The 60_000 size makes the
        // residual diff observable: diff 1 keeps the waste total at
        // 60_000 (no files-duplicated-waste); an unsuppressed pair would
        // give diff 2 and a 120_000 waste finding, and suppressing the
        // whole group would give no files-duplicate at all.
        let pairs = bundled_whitelist();
        let files = [
            pkgfile("/usr/share/licenses/foo/LICENSE", "aaa", 60_000, 1),
            pkgfile(
                "/usr/lib/python3.13/site-packages/foo-1.0.dist-info/licenses/LICENSE",
                "aaa",
                60_000,
                2,
            ),
            pkgfile("/usr/share/doc/packages/foo/LICENSE", "aaa", 60_000, 3),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert_eq!(
            DuplicatesCheck::find_duplicates(
                &refs,
                0,
                no_config,
                no_ghost,
                is_whitelisted(&pairs)
            ),
            vec![DuplicateFinding::FilesDuplicate(
                "/usr/share/licenses/foo/LICENSE".into(),
                "/usr/lib/python3.13/site-packages/foo-1.0.dist-info/licenses/LICENSE:/usr/share/doc/packages/foo/LICENSE".into(),
            )],
        );
    }

    #[test]
    fn whitelisted_hardlink_does_not_silence_genuine_duplicate() {
        // `diff` already excludes hardlinks to `first` (via the inode
        // group size), so the suppression loop must not decrement for
        // one again: A = the %license copy (first), B = its dist-info
        // embed hardlinked to A and forming a whitelisted pair with it,
        // C = the same content on its own inode. The group must still
        // fire on C, and C alone counts toward the waste total.
        let pairs = bundled_whitelist();
        let files = [
            pkgfile("/usr/share/licenses/foo/LICENSE", "aaa", 150_000, 1),
            pkgfile(
                "/usr/lib/python3.13/site-packages/foo-1.0.dist-info/licenses/LICENSE",
                "aaa",
                150_000,
                1,
            ),
            pkgfile("/usr/share/foo/LICENSE", "aaa", 150_000, 2),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert_eq!(
            DuplicatesCheck::find_duplicates(
                &refs,
                0,
                no_config,
                no_ghost,
                is_whitelisted(&pairs)
            ),
            vec![
                DuplicateFinding::FilesDuplicate(
                    "/usr/share/licenses/foo/LICENSE".into(),
                    "/usr/lib/python3.13/site-packages/foo-1.0.dist-info/licenses/LICENSE:/usr/share/foo/LICENSE".into(),
                ),
                DuplicateFinding::FilesDuplicatedWaste(150_000),
            ],
        );
    }

    #[test]
    fn whitelisted_hardlink_pair_alone_is_quiet() {
        // The whitelisted pair on its own, with the dist-info member
        // hardlinked to the %license copy: no genuine duplicate exists,
        // so nothing fires and nothing counts as waste, at any size.
        let pairs = bundled_whitelist();
        let files = [
            pkgfile("/usr/share/licenses/foo/LICENSE", "aaa", 150_000, 1),
            pkgfile(
                "/usr/lib/python3.13/site-packages/foo-1.0.dist-info/licenses/LICENSE",
                "aaa",
                150_000,
                1,
            ),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, is_whitelisted(&pairs))
                .is_empty()
        );
    }

    #[test]
    fn whitelist_pattern_matching() {
        let distinfo = DirPattern::parse("*.dist-info/licenses");
        assert!(
            distinfo
                .matches("/usr/lib/python3.13/site-packages/foo-1.0.dist-info/licenses/LICENSE")
        );
        // Nested content below the licenses directory still matches.
        assert!(distinfo.matches("/usr/lib/foo-1.0.dist-info/licenses/sub/extra.txt"));
        assert!(!distinfo.matches("/usr/lib/python3.13/site-packages/foo-1.0.dist-info/METADATA"));
        assert!(!distinfo.matches("/usr/share/licenses/foo/LICENSE"));

        let licenses = DirPattern::parse("/usr/share/licenses");
        assert!(licenses.matches("/usr/share/licenses/foo/LICENSE"));
        assert!(!licenses.matches("/usr/share/licensesfoo/LICENSE"));
        assert!(!licenses.matches("/opt/usr/share/licenses/foo/LICENSE"));

        assert!(component_matches("*.dist-info", "foo-1.0.dist-info"));
        assert!(!component_matches("*.dist-info", "foo-1.0.egg-info"));
        assert!(component_matches("licenses", "licenses"));
        assert!(!component_matches("licenses", "licensesfoo"));
    }

    #[test]
    fn bytecode_key_cases() {
        let key = DuplicatesCheck::bytecode_key;
        assert_eq!(
            key("/usr/lib/python3.13/site-packages/m/__pycache__/mod.cpython-313.pyc"),
            Some(("/usr/lib/python3.13/site-packages/m/__pycache__", "mod"))
        );
        assert_eq!(
            key("/usr/lib/python3.13/site-packages/m/__pycache__/mod.cpython-313.opt-1.pyc"),
            Some(("/usr/lib/python3.13/site-packages/m/__pycache__", "mod"))
        );
        assert_eq!(
            key("/usr/lib/python3.13/site-packages/m/__pycache__/mod.cpython-313t.opt-2.pyc"),
            Some(("/usr/lib/python3.13/site-packages/m/__pycache__", "mod"))
        );
        assert_eq!(
            key("/usr/lib/python3.13/mod.pyo"),
            Some(("/usr/lib/python3.13", "mod"))
        );
        assert_eq!(
            key("/usr/lib/python3.13/mod.pyc"),
            Some(("/usr/lib/python3.13", "mod"))
        );
        assert_eq!(key("/usr/bin/mod"), None);
        assert_eq!(key("/usr/lib/python3.13/mod.py"), None);
        assert_eq!(key("relative.pyc"), None);
    }

    #[test]
    fn bytecode_opt_variants_are_not_duplicates() {
        // Issue #518: the bytecompile macros emit every module at
        // optimize levels 0 and 1; for a module with no docstrings or
        // asserts to strip the products are byte-identical. Neither the
        // (unwired) hardlink brp nor %fdupes links them, so no packager
        // action reclaims the space and the group stays unreported.
        let files = [
            pkgfile(
                "/usr/lib/python3.13/site-packages/m/__pycache__/mod.cpython-313.pyc",
                "aaa",
                4_000,
                1,
            ),
            pkgfile(
                "/usr/lib/python3.13/site-packages/m/__pycache__/mod.cpython-313.opt-1.pyc",
                "aaa",
                4_000,
                2,
            ),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist)
                .is_empty(),
            "bytecode variants of one module are not actionable duplicates"
        );
    }

    #[test]
    fn bytecode_variants_contribute_no_waste() {
        // The suppressed group must not feed the waste total either:
        // at 200_000 bytes a reported pair would cross the threshold.
        let files = [
            pkgfile(
                "/usr/lib/python3.13/site-packages/m/__pycache__/mod.cpython-313.pyc",
                "aaa",
                200_000,
                1,
            ),
            pkgfile(
                "/usr/lib/python3.13/site-packages/m/__pycache__/mod.cpython-313.opt-1.pyc",
                "aaa",
                200_000,
                2,
            ),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist)
                .is_empty(),
            "suppressed variants contribute no files-duplicated-waste"
        );
    }

    #[test]
    fn config_only_group_is_not_reported() {
        // Every copy is a %config file, meant to be edited
        // independently after install (per-version copies here), so
        // no copy can be hardlinked to another without coupling
        // edits: the group is not actionable and stays unreported,
        // even at a size that would cross the waste threshold.
        let files = [
            pkgfile("/etc/mono/2.0/Browsers/Compat.browser", "aaa", 60_000, 1),
            pkgfile("/etc/mono/4.0/Browsers/Compat.browser", "aaa", 60_000, 2),
            pkgfile("/etc/mono/4.5/Browsers/Compat.browser", "aaa", 60_000, 3),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        let is_config = |n: &str| n.starts_with("/etc/");
        assert!(
            DuplicatesCheck::find_duplicates(&refs, 0, is_config, no_ghost, no_whitelist)
                .is_empty(),
            "config-only groups contribute no duplicate or waste finding"
        );
    }

    #[test]
    fn mixed_config_group_still_reports() {
        // One config copy beside non-config copies under the same
        // top-level tree is still a genuine duplicate: the group is
        // not config-only, so the duplicate and the waste total fire.
        let files = [
            pkgfile("/usr/share/foo/a.conf", "aaa", 60_000, 1),
            pkgfile("/usr/share/foo/b.conf", "aaa", 60_000, 2),
            pkgfile("/usr/share/foo/c.dat", "aaa", 60_000, 3),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        let is_config = |n: &str| n.ends_with("a.conf");
        assert_eq!(
            DuplicatesCheck::find_duplicates(&refs, 0, is_config, no_ghost, no_whitelist),
            vec![
                DuplicateFinding::FilesDuplicate(
                    "/usr/share/foo/c.dat".into(),
                    "/usr/share/foo/a.conf:/usr/share/foo/b.conf".into(),
                ),
                DuplicateFinding::FilesDuplicatedWaste(120_000),
            ],
        );
    }

    #[test]
    fn config_only_group_with_hardlink_still_reports_hardlink() {
        // The suppression covers only the duplicate and waste
        // findings: an already-hardlinked pair of config files still
        // fires hardlink-across-config-files.
        let files = [
            pkgfile("/etc/a.conf", "aaa", 60_000, 1),
            pkgfile("/etc/b.conf", "aaa", 60_000, 1),
            pkgfile("/etc/c.conf", "aaa", 60_000, 2),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        let is_config = |n: &str| n.starts_with("/etc/");
        assert_eq!(
            DuplicatesCheck::find_duplicates(&refs, 0, is_config, no_ghost, no_whitelist),
            vec![DuplicateFinding::HardlinkAcrossConfigFiles(
                "/etc/b.conf".into(),
                "/etc/a.conf".into(),
            )],
        );
    }

    #[test]
    fn bytecode_triple_and_free_threaded_variants_are_suppressed() {
        let files = [
            pkgfile(
                "/usr/lib/python3.13/site-packages/m/__pycache__/mod.cpython-313.pyc",
                "aaa",
                4_000,
                1,
            ),
            pkgfile(
                "/usr/lib/python3.13/site-packages/m/__pycache__/mod.cpython-313.opt-1.pyc",
                "aaa",
                4_000,
                2,
            ),
            pkgfile(
                "/usr/lib/python3.13/site-packages/m/__pycache__/mod.cpython-313.opt-2.pyc",
                "aaa",
                4_000,
                3,
            ),
            pkgfile(
                "/usr/lib/python3.13/site-packages/n/__pycache__/mod.cpython-313t.pyc",
                "bbb",
                4_000,
                4,
            ),
            pkgfile(
                "/usr/lib/python3.13/site-packages/n/__pycache__/mod.cpython-313t.opt-1.pyc",
                "bbb",
                4_000,
                5,
            ),
            pkgfile("/usr/lib/python3.13/legacy.pyc", "ccc", 4_000, 6),
            pkgfile("/usr/lib/python3.13/legacy.pyo", "ccc", 4_000, 7),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist)
                .is_empty(),
            "opt triples, free-threaded tags and legacy .pyc/.pyo pairs are all variants"
        );
    }

    #[test]
    fn bytecode_variants_plus_real_file_are_reported() {
        // Mixed group: the two variants share their md5 with a real
        // file. The group is not all variants of one module, so the
        // normal rule reports it — the real file is not hidden by its
        // bytecode lookalikes.
        let files = [
            pkgfile(
                "/usr/lib/python3.13/site-packages/m/__pycache__/mod.cpython-313.opt-1.pyc",
                "aaa",
                200_000,
                1,
            ),
            pkgfile(
                "/usr/lib/python3.13/site-packages/m/__pycache__/mod.cpython-313.pyc",
                "aaa",
                200_000,
                2,
            ),
            pkgfile("/usr/share/doc/m/mod.txt", "aaa", 200_000, 3),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert_eq!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist),
            vec![
                DuplicateFinding::FilesDuplicate(
                    "/usr/share/doc/m/mod.txt".into(),
                    "/usr/lib/python3.13/site-packages/m/__pycache__/mod.cpython-313.opt-1.pyc:/usr/lib/python3.13/site-packages/m/__pycache__/mod.cpython-313.pyc".into(),
                ),
                DuplicateFinding::FilesDuplicatedWaste(400_000),
            ],
        );
    }

    #[test]
    fn different_modules_identical_bytecode_are_reported() {
        // Identical bytecode of two DIFFERENT modules (empty __init__
        // files are the classic) is not one module's variant set: the
        // group still reports.
        let files = [
            pkgfile(
                "/usr/lib/python3.13/site-packages/m/__pycache__/a.cpython-313.pyc",
                "aaa",
                200,
                1,
            ),
            pkgfile(
                "/usr/lib/python3.13/site-packages/m/__pycache__/b.cpython-313.pyc",
                "aaa",
                200,
                2,
            ),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert_eq!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist),
            vec![DuplicateFinding::FilesDuplicate(
                "/usr/lib/python3.13/site-packages/m/__pycache__/b.cpython-313.pyc".into(),
                "/usr/lib/python3.13/site-packages/m/__pycache__/a.cpython-313.pyc".into(),
            )],
        );
    }

    #[test]
    fn same_stem_variants_in_different_directories_are_reported() {
        // omniORB shape: two packages' __init__ bytecode, same stem,
        // different directories — different modules, still reported.
        let files = [
            pkgfile(
                "/usr/lib/python3.13/site-packages/omniidl/__pycache__/__init__.cpython-313.pyc",
                "aaa",
                200,
                1,
            ),
            pkgfile(
                "/usr/lib/python3.13/site-packages/omniidl_be/__pycache__/__init__.cpython-313.pyc",
                "aaa",
                200,
                2,
            ),
        ];
        let refs: Vec<&PkgFile> = files.iter().collect();
        assert_eq!(
            DuplicatesCheck::find_duplicates(&refs, 0, no_config, no_ghost, no_whitelist),
            vec![DuplicateFinding::FilesDuplicate(
                "/usr/lib/python3.13/site-packages/omniidl_be/__pycache__/__init__.cpython-313.pyc"
                    .into(),
                "/usr/lib/python3.13/site-packages/omniidl/__pycache__/__init__.cpython-313.pyc"
                    .into(),
            )],
        );
    }

    fn fixture_path(name: &str) -> String {
        format!(
            "{}/../../tests/parity/pkg/inputs/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        )
    }

    /// A real `Pkg` whose file list the caller controls, driving the full
    /// `check` -> `add_info` -> `Filter` emission path.
    fn pkg_with_files(files: Vec<PkgFile>, config_files: Vec<String>) -> Pkg {
        let mut pkg = Pkg::open_no_extract(std::path::Path::new(&fixture_path(
            "scriptlet-empty-post-1.0-1.noarch.rpm",
        )))
        .expect("open fixture");
        pkg.files = files;
        pkg.config_files = config_files;
        pkg
    }

    /// `(finding name, level letter, rendered line)` per emitted finding.
    fn emitted(
        check: &mut DuplicatesCheck,
        pkg: &Pkg,
        config: &Config,
    ) -> Vec<(String, char, String)> {
        let mut out = Filter::new(config, crate::color::Color::for_tty(false)).expect("filter");
        check.check(pkg, config, &mut out);
        out.results()
            .iter()
            .zip(out.result_levels().iter())
            .map(|((name, line), level)| (name.clone(), level.letter(), line.clone()))
            .collect()
    }

    /// The exact rendered line for one finding of `pkg`.
    fn line(pkg: &Pkg, letter: char, check: &str, details: &str) -> String {
        format!(
            "{}.{pkg_arch}: {letter}: {check} {details}",
            pkg.name,
            pkg_arch = pkg.arch
        )
    }

    #[test]
    fn finding_output_triple_is_pinned() {
        // The whole (name, level, details) triple lives in one `describe`
        // match arm: a single match cannot mispair with itself. Each case
        // drives the real emission path and asserts the exact rendered
        // line, so junking a name literal, swapping two arms, or flipping
        // a detail order must fail.
        let config = Config::default();
        let mut check = DuplicatesCheck::new(&config);

        // hardlink-across-partition: one inode spanning /usr and /var.
        let pkg = pkg_with_files(
            vec![
                pkgfile("/usr/bin/a", "aaa", 100, 1),
                pkgfile("/var/lib/b", "aaa", 100, 1),
            ],
            vec![],
        );
        assert_eq!(
            emitted(&mut check, &pkg, &config),
            [(
                "hardlink-across-partition".to_string(),
                'E',
                line(
                    &pkg,
                    'E',
                    "hardlink-across-partition",
                    "/var/lib/b /usr/bin/a"
                ),
            )],
        );

        // hardlink-across-config-files: one inode, both ends config files.
        let pkg = pkg_with_files(
            vec![
                pkgfile("/etc/a", "aaa", 100, 1),
                pkgfile("/etc/b", "aaa", 100, 1),
            ],
            vec!["/etc/a".to_string(), "/etc/b".to_string()],
        );
        assert_eq!(
            emitted(&mut check, &pkg, &config),
            [(
                "hardlink-across-config-files".to_string(),
                'E',
                line(&pkg, 'E', "hardlink-across-config-files", "/etc/b /etc/a"),
            )],
        );

        // files-duplicate: same content on different inodes.
        let pkg = pkg_with_files(
            vec![
                pkgfile("/usr/bin/a", "aaa", 100, 1),
                pkgfile("/usr/bin/b", "aaa", 100, 2),
            ],
            vec![],
        );
        assert_eq!(
            emitted(&mut check, &pkg, &config),
            [(
                "files-duplicate".to_string(),
                'W',
                line(&pkg, 'W', "files-duplicate", "/usr/bin/b /usr/bin/a"),
            )],
        );

        // files-duplicated-waste: the waste total rides along with the
        // duplicate group that produced it.
        let pkg = pkg_with_files(
            vec![
                pkgfile("/usr/bin/x", "aaa", 60_000, 1),
                pkgfile("/usr/lib/y", "aaa", 60_000, 2),
                pkgfile("/usr/share/z", "aaa", 60_000, 3),
            ],
            vec![],
        );
        assert_eq!(
            emitted(&mut check, &pkg, &config),
            [
                (
                    "files-duplicate".to_string(),
                    'W',
                    line(
                        &pkg,
                        'W',
                        "files-duplicate",
                        "/usr/share/z /usr/bin/x:/usr/lib/y"
                    ),
                ),
                (
                    "files-duplicated-waste".to_string(),
                    'W',
                    line(&pkg, 'W', "files-duplicated-waste", "120000"),
                ),
            ],
        );
    }

    /// One small duplicate pair plus one waste-sized duplicate triple,
    /// all inside /usr (same top-level tree, so nothing is suppressed by
    /// the #771 rule): the payload fires two files-duplicate findings
    /// and one files-duplicated-waste in an ordinary package.
    fn mingw_scope_fixture_files() -> Vec<PkgFile> {
        vec![
            pkgfile("/usr/bin/a", "aaa", 100, 1),
            pkgfile("/usr/bin/b", "aaa", 100, 2),
            pkgfile("/usr/bin/x", "bbb", 60_000, 3),
            pkgfile("/usr/lib/y", "bbb", 60_000, 4),
            pkgfile("/usr/share/z", "bbb", 60_000, 5),
        ]
    }

    #[test]
    fn mingw_package_duplicates_and_waste_do_not_fire() {
        // Issue #522: the mingw32.toml filter '^mingw(32|64)-.*
        // files-duplicate' drops the family's files-duplicate findings
        // wholesale in the Factory session, and the waste finding with
        // them (its name shares the prefix). The fixture payload fires
        // both in any other package (see the control test below).
        let config = Config::default();
        let mut check = DuplicatesCheck::new(&config);
        let mut pkg = pkg_with_files(mingw_scope_fixture_files(), vec![]);
        pkg.name = "mingw64-runtime".to_string();
        let got = emitted(&mut check, &pkg, &config);
        assert!(got.is_empty(), "MinGW package must stay quiet: {got:?}");
    }

    #[test]
    fn same_duplicates_fire_in_non_mingw_package() {
        // Control for the MinGW suppression: the identical payload in a
        // package outside the family fires both findings.
        let config = Config::default();
        let mut check = DuplicatesCheck::new(&config);
        let mut pkg = pkg_with_files(mingw_scope_fixture_files(), vec![]);
        pkg.name = "foo".to_string();
        let got = emitted(&mut check, &pkg, &config);
        let names: Vec<&str> = got.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "files-duplicate",
                "files-duplicate",
                "files-duplicated-waste"
            ]
        );
    }

    #[test]
    fn mingw_package_hardlink_findings_still_fire() {
        // Scope pin: mingw32.toml does not filter the hardlink findings,
        // so a MinGW package keeps them; only files-duplicate and
        // files-duplicated-waste are suppressed.
        let config = Config::default();
        let mut check = DuplicatesCheck::new(&config);
        let mut pkg = pkg_with_files(
            vec![
                pkgfile("/usr/bin/a", "aaa", 100, 1),
                pkgfile("/var/lib/b", "aaa", 100, 1),
            ],
            vec![],
        );
        pkg.name = "mingw32-foo".to_string();
        let got = emitted(&mut check, &pkg, &config);
        let names: Vec<&str> = got.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(names, ["hardlink-across-partition"]);
    }
}
