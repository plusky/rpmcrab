//! `SharedLibraryPolicyCheck` — shared library packaging policy.
//!
//! Ported from `rpmlint/checks/SharedLibraryPolicyCheck.py`. Findings:
//! `shlib-policy-missing-lib`, `readelf-failed`, `shlib-unversioned-lib`,
//! `shlib-fixed-dependency`, `shlib-policy-excessive-dependency`,
//! `shlib-policy-obsoletes-sibling`, `shlib-policy-etc-payload`.
//!
//! One finding has no reference counterpart: `shlib-devel-unversioned-requires`
//! (Warning). The shared library packaging policy asks a library `-devel`
//! package to require its shared library package with a version constraint.
//! The pairing is cross-package: `check_binary` records every binary package
//! and `after_checks` groups the records by source package (`SOURCERPM`);
//! packages built from different sources never pair, however their names
//! look. A sibling is a package in the same source set whose name matches
//! the policy naming scheme (`lib<name><number>`, a `-32bit`/`-64bit` suffix
//! normalised away) and that ships a versioned shared library file
//! (`.so.<number>`). The `-devel` package paired with it is
//! `lib<name><number>-devel` or `lib<name>-devel`. The finding fires on the
//! `-devel` package when none of its requires names the sibling — under the
//! sibling's own name or one of its non-SONAME provides names — with a
//! version relation. SONAME provides (`libfoo.so.1()(64bit)`) never count:
//! they are the automatic file dependencies, not the package pairing.
//! Sibling candidates are grouped by their normalised base: the base
//! package and its `-32bit`/`-64bit` flavours (`libfoo1`,
//! `libfoo1-32bit`) form one group, a versioned require naming any member
//! satisfies the whole group (a `-devel` package must not be made to drag
//! in the 32-bit flavour), and the check emits at most one finding per
//! (`-devel`, group), naming the group's canonical base name.
//! Rich (boolean) requires are read through their leaves: a leaf naming the
//! sibling with a version relation satisfies the rule, a bare leaf does not.

use std::collections::{HashMap, HashSet};

use fancy_regex::Regex;

use crate::check::{Check, add_info, make_finding};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::dep::DepInfo;
use crate::pkg::pkgfile::is_dir;

const RPMSENSE_EQUAL: u32 = 8;
const RPMSENSE_GREATER: u32 = 4;
const RPMSENSE_LESS: u32 = 2;

/// ELF `st_mode` file-type mask bits for a regular file.
const S_IFREG: u32 = 0o100000;
const S_IFMT: u32 = 0o170000;

pub struct SharedLibraryPolicyCheck {
    re_soname_strongly_versioned: Regex,
    re_soname_pkg: Regex,
    re_so_files: Regex,
    re_versioned_so_file: Regex,
    seen: Vec<SeenPkg>,
}

/// One binary package of the run, recorded for the cross-package `-devel`
/// pairing in `after_checks`.
struct SeenPkg {
    name: String,
    arch: String,
    source_rpm: Option<String>,
    requires: Vec<DepInfo>,
    provides: Vec<String>,
    has_versioned_so: bool,
}

/// Cross-package state, exported per package and merged before
/// `after_checks`.
struct DevelPairingState {
    seen: Vec<SeenPkg>,
}

impl SharedLibraryPolicyCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            re_soname_strongly_versioned: Regex::new(r"-[\d\.]+\.so$").expect("static regex"),
            re_soname_pkg: Regex::new(r"^lib\S+(\d+(-(32|64)bit)?)$").expect("static regex"),
            re_so_files: Regex::new(r"\S+.so((\.(\d+))*)$").expect("static regex"),
            re_versioned_so_file: Regex::new(r"\.so\.\d").expect("static regex"),
            seen: Vec::new(),
        }
    }

    fn record(&mut self, pkg: &Pkg) {
        self.record_seen(SeenPkg {
            name: pkg.name.clone(),
            arch: pkg.arch.clone(),
            source_rpm: pkg.source_rpm.clone(),
            requires: pkg
                .requires
                .iter()
                .chain(pkg.prereq.iter())
                .cloned()
                .collect(),
            provides: pkg.provides.iter().map(|d| d.name.clone()).collect(),
            has_versioned_so: pkg
                .files
                .iter()
                .any(|f| is_match(&self.re_versioned_so_file, &f.name)),
        });
    }

    fn record_seen(&mut self, entry: SeenPkg) {
        // One entry per (name, arch, source): a repeated package replaces
        // its earlier record instead of pairing with itself twice.
        if let Some(old) = self.seen.iter_mut().find(|e| {
            e.name == entry.name && e.arch == entry.arch && e.source_rpm == entry.source_rpm
        }) {
            *old = entry;
        } else {
            self.seen.push(entry);
        }
    }

    /// The `-devel` package names a policy-named shared library package
    /// pairs with: `lib<name><number>-devel` and `lib<name>-devel`, with a
    /// `-32bit`/`-64bit` suffix on the number normalised away. Empty when
    /// the name does not match the naming scheme.
    fn devel_names_for(&self, shlib: &str) -> Vec<String> {
        let Some((stem, number)) = self.sibling_group(shlib) else {
            return Vec::new();
        };
        let base = format!("{stem}{number}");
        vec![format!("{base}-devel"), format!("{stem}-devel")]
    }

    /// The normalised group of a policy-named shared library package:
    /// `(stem, number)` with a `-32bit`/`-64bit` flavour suffix removed,
    /// so `libfoo1`, `libfoo1-32bit` and `libfoo1-64bit` are one group
    /// whose canonical name is `libfoo1`. `None` when the name does not
    /// match the naming scheme.
    fn sibling_group(&self, shlib: &str) -> Option<(String, String)> {
        if !is_match(&self.re_soname_pkg, shlib) {
            return None;
        }
        // The scheme number is the trailing digit run (plus a normalised
        // `-32bit`/`-64bit` suffix); the regex capture alone does not pin
        // it, since the name part is greedy (`libfoo23` captures `3`).
        let base = shlib
            .strip_suffix("-32bit")
            .or_else(|| shlib.strip_suffix("-64bit"))
            .unwrap_or(shlib);
        let num_len = base.len() - base.trim_end_matches(|c: char| c.is_ascii_digit()).len();
        if num_len == 0 {
            return None;
        }
        let stem = &base[..base.len() - num_len];
        Some((stem.to_string(), base[base.len() - num_len..].to_string()))
    }

    /// Whether the `-devel` package requires the sibling with a version
    /// relation, under the sibling's name or one of its non-SONAME provides
    /// names. A bare name or a SONAME require does not satisfy the pairing.
    fn versioned_sibling_require(devel: &SeenPkg, sibling: &SeenPkg) -> bool {
        let mut names: Vec<&str> = vec![sibling.name.as_str()];
        for provide in &sibling.provides {
            let base = provide.split('(').next().unwrap_or("");
            if base.starts_with("lib") && !base.contains(".so") {
                names.push(base);
            }
        }
        devel.requires.iter().any(|dep| {
            dep.leaves().iter().any(|leaf| {
                leaf.flags & (RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL) != 0
                    && names.contains(&leaf.name.split('(').next().unwrap_or(""))
            })
        })
    }

    /// `(soname, needed)` from an ELF file, or the parse failure reason.
    fn elf_dynamic(path: &str) -> Result<(Option<String>, Vec<String>), String> {
        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        let elf = crate::checks::binaries::parse_elf(&data).map_err(|e| e.to_string())?;
        let mut soname = None;
        let mut needed = Vec::new();
        if let Some(dynamic) = &elf.dynamic {
            for d in &dynamic.dyns {
                match d.d_tag {
                    goblin::elf::dynamic::DT_SONAME => {
                        if let Some(s) = elf.dynstrtab.get_at(d.d_val as usize) {
                            soname = Some(s.to_string());
                        }
                    }
                    goblin::elf::dynamic::DT_NEEDED => {
                        if let Some(s) = elf.dynstrtab.get_at(d.d_val as usize) {
                            needed.push(s.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok((soname, needed))
    }
}

/// `(stem, SONAME number)` for a package name in the versioned shared
/// library scheme (`libfoo1`, `libfoo12-32bit`), or `None` for a name
/// outside the scheme. The `-32bit`/`-64bit` suffix is normalised away,
/// matching how the scheme pattern treats those forms: RPM `Obsoletes`
/// is arch-agnostic and the baselibs `-32bit` forms carry the host arch,
/// so an obsoletes in any bitness form removes the sibling generation
/// in every form. The number is the full trailing digit run with
/// leading zeroes dropped.
fn soname_package_parts(re_soname_pkg: &Regex, name: &str) -> Option<(String, String)> {
    if !is_match(re_soname_pkg, name) {
        return None;
    }
    let core = name
        .strip_suffix("-32bit")
        .or_else(|| name.strip_suffix("-64bit"))
        .unwrap_or(name);
    let digits_start = core.len()
        - core
            .bytes()
            .rev()
            .take_while(|b| b.is_ascii_digit())
            .count();
    if digits_start == core.len() {
        return None;
    }
    let number = core[digits_start..].trim_start_matches('0');
    Some((
        core[..digits_start].to_string(),
        if number.is_empty() {
            "0".to_string()
        } else {
            number.to_string()
        },
    ))
}

impl Check for SharedLibraryPolicyCheck {
    fn name(&self) -> &'static str {
        "SharedLibraryPolicyCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }
        self.record(pkg);
        // Only non-development, non-language library packages.
        if !pkg.name.starts_with("lib")
            || pkg.name.ends_with("-devel")
            || pkg.name.ends_with("-lang")
        {
            return;
        }

        // A versioned library package must not obsolete a sibling SONAME
        // generation: the scheme exists so the generations are
        // co-installable, and an obsoletes of one by another removes it.
        // A version constraint does not change that for the obsoleted
        // range, so the dependency's flags and version are not consulted.
        // The bitness suffix is normalised away on both sides (see
        // `soname_package_parts`): `Obsoletes` is arch-agnostic, so a
        // cross-bitness obsoletes removes the sibling generation just
        // as a same-bitness one does, and a same-number cross-suffix
        // pair collapses to a self-obsoletes.
        if let Some((stem, number)) = soname_package_parts(&self.re_soname_pkg, &pkg.name) {
            for obs in &pkg.obsoletes {
                if let Some((obs_stem, obs_number)) =
                    soname_package_parts(&self.re_soname_pkg, &obs.name)
                    && obs_stem == stem
                    && obs_number != number
                {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "shlib-policy-obsoletes-sibling",
                        &[obs.name.as_str()],
                    );
                }
            }
        }

        // A versioned library package ships nothing but the libraries
        // themselves: payload under /etc (or its vendor-default
        // counterpart /usr/etc) is shipped identically by the sibling
        // package for the next SONAME generation, and the two conflict
        // at file level. Directory entries are shared by design and
        // %ghost entries are not shipped payload, so only
        // non-directory, non-ghost entries fire.
        if is_match(&self.re_soname_pkg, &pkg.name) {
            let mut etc_files: Vec<&str> = pkg
                .files
                .iter()
                .filter(|f| f.name.starts_with("/etc/") || f.name.starts_with("/usr/etc/"))
                .filter(|f| !is_dir(f.mode))
                .filter(|f| !f.is_ghost())
                .map(|f| f.name.as_str())
                .collect();
            etc_files.sort_unstable();
            for path in etc_files {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "shlib-policy-etc-payload",
                    &[path],
                );
            }
        }

        // A policy-named package with no library files at all.
        let has_lib_files = pkg
            .files
            .iter()
            .any(|f| is_match(&self.re_so_files, &f.name));
        if !has_lib_files && is_match(&self.re_soname_pkg, &pkg.name) {
            add_info(out, Level::Error, pkg, "shlib-policy-missing-lib", &[]);
        }

        let pkg_requires: HashSet<&str> = pkg
            .requires
            .iter()
            .map(|d| d.name.split('(').next().unwrap_or(""))
            .collect();

        let mut libs: HashSet<String> = HashSet::new();
        let mut libs_needed: HashSet<String> = HashSet::new();
        let mut libs_to_dir: HashMap<String, String> = HashMap::new();
        let mut reqlibs: HashSet<String> = HashSet::new();

        for file in &pkg.files {
            let fname = file.name.as_str();
            if !fname.contains(".so.") && !fname.ends_with(".so") {
                continue;
            }
            if file.mode & S_IFMT != S_IFREG {
                continue;
            }
            if !file.magic.starts_with("ELF ") {
                continue;
            }
            match Self::elf_dynamic(&file.path) {
                Err(reason) => {
                    add_info(out, Level::Error, pkg, "readelf-failed", &[fname, &reason]);
                    return;
                }
                Ok((soname, needed)) => {
                    libs_needed.extend(needed);
                    if let Some(soname) = soname {
                        let dir = match fname.rfind('/') {
                            Some(i) => fname[..i].to_string(),
                            None => String::new(),
                        };
                        if pkg_requires.contains(soname.as_str()) {
                            reqlibs.insert(soname.clone());
                        }
                        libs_to_dir.insert(soname.clone(), dir);
                        libs.insert(soname);
                    }
                }
            }
        }

        // The reference returns early when libs - reqlibs is empty, but
        // then iterates over ALL libs (not the difference): a soname the
        // package itself requires is still reported.
        if libs.difference(&reqlibs).next().is_none() {
            return;
        }

        if pkg.name.chars().last().is_some_and(|c| c.is_ascii_digit()) {
            // Ignore libs in a versioned non-std dir. The reference iterates
            // over all libs here, not libs - reqlibs.
            let mut filtered: HashSet<String> = libs.iter().cloned().collect();
            for lib in filtered.clone() {
                if let Some(dir) = libs_to_dir.get(&lib) {
                    for part in dir.split('/') {
                        if part.is_empty() {
                            continue;
                        }
                        if part.chars().last().is_some_and(|c| c.is_ascii_digit())
                            && !part.ends_with("lib64")
                        {
                            filtered.remove(&lib);
                            break;
                        }
                    }
                }
            }
            // Non-versioned libs in a std lib package. Sorted: the reference
            // iterates a set, and findings sharing (check, level) keep
            // emission order through the stable sort.
            let mut libs_sorted: Vec<&String> = filtered.iter().collect();
            libs_sorted.sort();
            for lib in libs_sorted {
                let versioned = lib.chars().last().is_some_and(|c| c.is_ascii_digit())
                    || is_match(&self.re_soname_strongly_versioned, lib);
                if !versioned {
                    add_info(out, Level::Warning, pkg, "shlib-unversioned-lib", &[lib]);
                }
            }
            // Hard dependencies on non-lib packages.
            for dep in &pkg.requires {
                if dep.name.starts_with("rpmlib(") || dep.name.starts_with("config(") {
                    continue;
                }
                // A flavor package pinning its own base with `=` (e.g.
                // `libfoo-x86-64-v3` requires `libfoo = 1.0`) is version
                // lockstep for co-built flavors, not a policy violation:
                // the base name is a proper prefix of the package name and
                // the remainder is a flavor suffix starting with `-`.
                if pkg
                    .name
                    .strip_prefix(dep.name.as_str())
                    .is_some_and(|rest| rest.starts_with('-'))
                {
                    continue;
                }
                if dep.flags & (RPMSENSE_GREATER | RPMSENSE_EQUAL) == RPMSENSE_EQUAL {
                    // Like the reference's formatRequire: `name`, a space, the
                    // operator from the flags, a space, then the EVR — which may
                    // be empty, leaving the trailing space.
                    let mut op = String::new();
                    if dep.flags & RPMSENSE_LESS != 0 {
                        op.push('<');
                    }
                    if dep.flags & RPMSENSE_GREATER != 0 {
                        op.push('>');
                    }
                    if dep.flags & RPMSENSE_EQUAL != 0 {
                        op.push('=');
                    }
                    let detail = format!("{} {op} {}", dep.name, dep.evr_string());
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "shlib-fixed-dependency",
                        &[&detail],
                    );
                }
            }
        }

        // Non-lib stuff must not add dependencies. Sorted for the same reason
        // as above: one finding per dep, all sharing (check, level).
        if !libs.is_empty() {
            let mut deps_sorted: Vec<&str> = pkg_requires.iter().copied().collect();
            deps_sorted.sort_unstable();
            for dep in deps_sorted {
                if dep.contains(".so.") && !libs.contains(dep) && !libs_needed.contains(dep) {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "shlib-policy-excessive-dependency",
                        &[dep],
                    );
                }
            }
        }
    }

    fn reset(&mut self) {
        self.seen.clear();
    }

    fn export_state(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        Some(Box::new(DevelPairingState {
            seen: std::mem::take(&mut self.seen),
        }))
    }

    fn import_state(&mut self, state: Box<dyn std::any::Any + Send>) {
        if let Ok(state) = state.downcast::<DevelPairingState>() {
            for entry in state.seen {
                self.record_seen(entry);
            }
        }
    }

    fn after_checks(&mut self, _config: &Config, out: &mut Filter) {
        // Lint order of the `-devel` packages drives the finding order.
        for d in 0..self.seen.len() {
            if !self.seen[d].name.ends_with("-devel") {
                continue;
            }
            let Some(source_rpm) = self.seen[d].source_rpm.clone() else {
                continue;
            };
            // Group the sibling candidates by normalised base, in
            // first-seen order: the base package and its flavours are
            // one pairing, not one pairing per sibling.
            let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
            for s in 0..self.seen.len() {
                if s == d {
                    continue;
                }
                let sibling = &self.seen[s];
                if sibling.source_rpm.as_deref() != Some(source_rpm.as_str())
                    || !sibling.has_versioned_so
                    || !self
                        .devel_names_for(&sibling.name)
                        .contains(&self.seen[d].name)
                {
                    continue;
                }
                let Some((stem, number)) = self.sibling_group(&sibling.name) else {
                    continue;
                };
                let base = format!("{stem}{number}");
                if let Some(group) = groups.iter_mut().find(|group| group.0 == base) {
                    group.1.push(s);
                } else {
                    groups.push((base, vec![s]));
                }
            }
            for (base, members) in groups {
                // A versioned require naming any member of the group (or
                // one of its non-SONAME provides names) satisfies the
                // whole group.
                if members
                    .iter()
                    .any(|&s| Self::versioned_sibling_require(&self.seen[d], &self.seen[s]))
                {
                    continue;
                }
                let devel = &self.seen[d];
                out.add_info(make_finding(
                    &devel.name,
                    &devel.arch,
                    Level::Warning,
                    "shlib-devel-unversioned-requires",
                    vec![base],
                    None,
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::color::Color;
    use crate::pkg::dep::DepInfo;
    use crate::pkg::pkgfile::PkgFile;

    fn checker() -> SharedLibraryPolicyCheck {
        SharedLibraryPolicyCheck::new(&Config::default())
    }

    fn dep(name: &str) -> DepInfo {
        DepInfo {
            name: name.to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        }
    }

    #[test]
    fn soname_pkg_pattern_matches() {
        let check = checker();
        assert!(is_match(&check.re_soname_pkg, "libfoo1"));
        assert!(is_match(&check.re_soname_pkg, "libfoo1-32bit"));
        assert!(!is_match(&check.re_soname_pkg, "libfoo"));
    }

    #[test]
    fn so_files_pattern_matches() {
        let check = checker();
        assert!(is_match(&check.re_so_files, "/usr/lib64/libfoo.so"));
        assert!(is_match(&check.re_so_files, "/usr/lib64/libfoo.so.1"));
        assert!(is_match(&check.re_so_files, "/usr/lib64/libfoo.so.1.2.3"));
        assert!(!is_match(&check.re_so_files, "/usr/bin/foo"));
    }

    #[test]
    fn strongly_versioned_soname_matches() {
        let check = checker();
        assert!(is_match(
            &check.re_soname_strongly_versioned,
            "libfoo-1.2.so"
        ));
        assert!(!is_match(
            &check.re_soname_strongly_versioned,
            "libfoo.so.1"
        ));
    }

    #[test]
    fn excessive_dependencies_have_deterministic_order() {
        // Two minimal ELF64 shared objects with unversioned SONAMEs, plus
        // synthetic `.so` requires matching no shipped soname. Both sorted
        // sites emit multiple findings sharing (check, level); without the
        // sorts, HashSet iteration order would randomize the sequence.
        let dir = std::env::temp_dir().join("rpmcrab-shlib-order");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let so_a = dir.join("libfoo.so");
        let so_b = dir.join("libbar.so");
        std::fs::write(&so_a, minimal_elf("libfoo.so")).expect("write elf");
        std::fs::write(&so_b, minimal_elf("libbar.so")).expect("write elf");

        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &dir, true).expect("open fixture pkg");
        pkg.name = "libfoo1".to_string();
        pkg.files = vec![
            PkgFile {
                name: "/usr/lib64/libfoo.so".to_string(),
                path: so_a.to_string_lossy().into_owned(),
                mode: 0o100644,
                magic: "ELF 64-bit LSB shared object".to_string(),
                ..Default::default()
            },
            PkgFile {
                name: "/usr/lib64/libbar.so".to_string(),
                path: so_b.to_string_lossy().into_owned(),
                mode: 0o100644,
                magic: "ELF 64-bit LSB shared object".to_string(),
                ..Default::default()
            },
        ];
        pkg.requires = vec![dep("libzzz.so.1"), dep("libaaa.so.2"), dep("libmmm.so.3")];

        let run = || {
            let config = Config::default();
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            let mut check = SharedLibraryPolicyCheck::new(&config);
            check.check_binary(&pkg, &config, &mut out);
            out.results().to_vec()
        };
        let first = run();
        let second = run();
        assert_eq!(first, second, "finding order must be deterministic");

        let unversioned: Vec<&str> = first
            .iter()
            .filter(|(n, _)| n == "shlib-unversioned-lib")
            .map(|(_, line)| line.rsplit(' ').next().unwrap_or(""))
            .collect();
        assert_eq!(unversioned, vec!["libbar.so", "libfoo.so"]);

        let deps: Vec<&str> = first
            .iter()
            .filter(|(n, _)| n == "shlib-policy-excessive-dependency")
            .map(|(_, line)| line.rsplit(' ').next().unwrap_or(""))
            .collect();
        assert_eq!(deps, vec!["libaaa.so.2", "libmmm.so.3", "libzzz.so.1"]);
    }

    /// A minimal ELF64 shared object with a single DT_SONAME, parseable by
    /// goblin, so tests need no toolchain-produced fixture.
    fn minimal_elf(soname: &str) -> Vec<u8> {
        let mut strtab: Vec<u8> = vec![0];
        let soname_off = strtab.len() as u64;
        strtab.extend_from_slice(soname.as_bytes());
        strtab.push(0);

        // Dynamic entries are (i64 tag, u64 val).
        let mut dynamic: Vec<u8> = Vec::new();
        let mut push_dyn = |tag: i64, val: u64| {
            dynamic.extend_from_slice(&tag.to_le_bytes());
            dynamic.extend_from_slice(&val.to_le_bytes());
        };
        let ehsize: u64 = 64;
        let dyn_off = ehsize + 2 * 56;
        let strtab_off = dyn_off + 4 * 16;
        push_dyn(14, soname_off); // DT_SONAME
        push_dyn(5, strtab_off); // DT_STRTAB: vaddr == file offset (PT_LOAD at 0)
        push_dyn(10, strtab.len() as u64); // DT_STRSZ
        push_dyn(0, 0); // DT_NULL

        let mut elf: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        elf.extend_from_slice(&3u16.to_le_bytes()); // ET_DYN
        elf.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        elf.extend_from_slice(&1u32.to_le_bytes()); // version
        elf.extend_from_slice(&0u64.to_le_bytes()); // entry
        elf.extend_from_slice(&ehsize.to_le_bytes()); // phoff
        elf.extend_from_slice(&0u64.to_le_bytes()); // shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // flags
        elf.extend_from_slice(&64u16.to_le_bytes()); // ehsize
        elf.extend_from_slice(&56u16.to_le_bytes()); // phentsize
        elf.extend_from_slice(&2u16.to_le_bytes()); // phnum
        elf.extend_from_slice(&0u16.to_le_bytes()); // shentsize
        elf.extend_from_slice(&0u16.to_le_bytes()); // shnum
        elf.extend_from_slice(&0u16.to_le_bytes()); // shstrndx

        // PT_LOAD covering the whole file at vaddr 0, then PT_DYNAMIC.
        let total = strtab_off + strtab.len() as u64;
        let mut ph = |p_type: u32, flags: u32, offset: u64, filesz: u64| {
            elf.extend_from_slice(&p_type.to_le_bytes());
            elf.extend_from_slice(&flags.to_le_bytes());
            elf.extend_from_slice(&offset.to_le_bytes());
            elf.extend_from_slice(&offset.to_le_bytes()); // vaddr == offset
            elf.extend_from_slice(&offset.to_le_bytes()); // paddr
            elf.extend_from_slice(&filesz.to_le_bytes());
            elf.extend_from_slice(&filesz.to_le_bytes()); // memsz
            elf.extend_from_slice(&0x1000u64.to_le_bytes()); // align
        };
        ph(1, 5, 0, total); // PT_LOAD
        ph(2, 6, dyn_off, dynamic.len() as u64); // PT_DYNAMIC

        elf.extend_from_slice(&dynamic);
        elf.extend_from_slice(&strtab);
        assert_eq!(elf.len() as u64, total);
        elf
    }

    fn obsoletes_results(name: &str, obsoletes: Vec<DepInfo>) -> Vec<(String, String)> {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture header");
        pkg.name = name.to_string();
        pkg.files = vec![];
        pkg.requires = vec![];
        pkg.obsoletes = obsoletes;
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = checker();
        check.check_binary(&pkg, &config, &mut out);
        out.results().to_vec()
    }

    fn sibling_lines(results: &[(String, String)]) -> Vec<&str> {
        results
            .iter()
            .filter(|(n, _)| n == "shlib-policy-obsoletes-sibling")
            .map(|(_, line)| line.as_str())
            .collect()
    }

    #[test]
    fn sibling_soname_obsoletes_fires_at_error() {
        let results = obsoletes_results("libfoo2", vec![dep("libfoo1")]);
        let lines = sibling_lines(&results);
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("libfoo1"),
            "detail names the obsoleted sibling: {}",
            lines[0]
        );
    }

    #[test]
    fn self_obsoletes_is_quiet() {
        // A rename-style self-obsoletes with a version cap names the
        // package's own SONAME generation, not a sibling.
        let results = obsoletes_results(
            "libfoo2",
            vec![DepInfo {
                name: "libfoo2".to_string(),
                flags: RPMSENSE_LESS,
                epoch: None,
                version: Some("1.0".to_string()),
                release: None,
            }],
        );
        assert!(
            sibling_lines(&results).is_empty(),
            "self-obsoletes must stay quiet: {results:?}"
        );
    }

    #[test]
    fn unrelated_obsoletes_is_quiet() {
        let results = obsoletes_results("libfoo2", vec![dep("libbar1")]);
        assert!(
            sibling_lines(&results).is_empty(),
            "unrelated package must stay quiet: {results:?}"
        );
    }

    #[test]
    fn unversioned_obsoletes_is_quiet() {
        let results = obsoletes_results("libfoo2", vec![dep("libfoo")]);
        assert!(
            sibling_lines(&results).is_empty(),
            "unversioned target must stay quiet: {results:?}"
        );
    }

    #[test]
    fn bit_suffix_sibling_obsoletes_fires() {
        // The scheme pattern treats the -32bit/-64bit forms as the same
        // versioned package name, and RPM `Obsoletes` is arch-agnostic,
        // so every pairing of bitness forms fires: the suffix is
        // normalised away on both sides before the stem and number are
        // compared. All nine form pairings are pinned here.
        for pkg_suffix in ["", "-32bit", "-64bit"] {
            for obs_suffix in ["", "-32bit", "-64bit"] {
                let name = format!("libfoo2{pkg_suffix}");
                let obs = format!("libfoo1{obs_suffix}");
                let results = obsoletes_results(&name, vec![dep(&obs)]);
                assert_eq!(
                    sibling_lines(&results).len(),
                    1,
                    "sibling must fire ({name} vs {obs}): {results:?}"
                );
            }
        }
    }

    #[test]
    fn bit_suffix_self_obsoletes_is_quiet() {
        // A rename-style self-obsoletes names the package's own SONAME
        // generation in every bitness form, not a sibling.
        for suffix in ["", "-32bit", "-64bit"] {
            let name = format!("libfoo2{suffix}");
            let results = obsoletes_results(
                &name,
                vec![DepInfo {
                    name: name.clone(),
                    flags: RPMSENSE_LESS,
                    epoch: None,
                    version: Some("1.0".to_string()),
                    release: None,
                }],
            );
            assert!(
                sibling_lines(&results).is_empty(),
                "self-obsoletes must stay quiet ({name}): {results:?}"
            );
        }
    }

    #[test]
    fn bit_suffix_cross_suffix_self_obsoletes_is_quiet() {
        // Same SONAME number, different bitness form on each side:
        // with the suffix normalised away the pair names the package's
        // own generation, so it is a self-obsoletes, not a sibling
        // one, in every cross-suffix pairing.
        for pkg_suffix in ["", "-32bit", "-64bit"] {
            for obs_suffix in ["", "-32bit", "-64bit"] {
                if pkg_suffix == obs_suffix {
                    continue;
                }
                let name = format!("libfoo2{pkg_suffix}");
                let obs = format!("libfoo2{obs_suffix}");
                let results = obsoletes_results(&name, vec![dep(&obs)]);
                assert!(
                    sibling_lines(&results).is_empty(),
                    "cross-suffix self-obsoletes must stay quiet ({name} vs {obs}): {results:?}"
                );
            }
        }
    }

    #[test]
    fn multi_digit_soname_obsoletes_fires() {
        // The full trailing number is the SONAME generation: 10 differs
        // from both 9 and 1.
        let results = obsoletes_results("libfoo10", vec![dep("libfoo9"), dep("libfoo1")]);
        assert_eq!(
            sibling_lines(&results).len(),
            2,
            "both multi-digit siblings must fire: {results:?}"
        );
    }

    #[test]
    fn versioned_sibling_obsoletes_fires() {
        // A version constraint does not restore co-installability for
        // the obsoleted range, so a capped sibling obsoletes still fires.
        let results = obsoletes_results(
            "libfoo2",
            vec![DepInfo {
                name: "libfoo1".to_string(),
                flags: RPMSENSE_LESS,
                epoch: None,
                version: Some("1.0".to_string()),
                release: None,
            }],
        );
        assert_eq!(
            sibling_lines(&results).len(),
            1,
            "version-capped sibling must fire: {results:?}"
        );
    }

    #[test]
    fn leading_zero_soname_obsoletes_is_quiet() {
        // The SONAME number is the trailing digit run with leading
        // zeroes dropped, so `libfoo01` and `libfoo1` name the same
        // generation: an obsoletes between them is a self-obsoletes,
        // not a sibling one, in either direction.
        for (name, obs) in [
            ("libfoo1", "libfoo01"),
            ("libfoo01", "libfoo1"),
            ("libfoo0", "libfoo00"),
        ] {
            let results = obsoletes_results(name, vec![dep(obs)]);
            assert!(
                sibling_lines(&results).is_empty(),
                "{name} obsoleting {obs} must stay quiet: {results:?}"
            );
        }
        // A leading-zero name for a different generation still fires:
        // the quiet cases above come from the number normalisation,
        // not from leading-zero names falling outside the scheme.
        let results = obsoletes_results("libfoo02", vec![dep("libfoo1")]);
        assert_eq!(
            sibling_lines(&results).len(),
            1,
            "libfoo02 obsoleting libfoo1 must fire: {results:?}"
        );
    }

    #[test]
    fn less_alone_sibling_obsoletes_fires() {
        // The check does not consult the obsoletes relation: an entry
        // carrying only a `<` relation, with no version at all, still
        // fires on a sibling generation.
        let results = obsoletes_results(
            "libfoo2",
            vec![DepInfo {
                name: "libfoo1".to_string(),
                flags: RPMSENSE_LESS,
                epoch: None,
                version: None,
                release: None,
            }],
        );
        assert_eq!(
            sibling_lines(&results).len(),
            1,
            "LESS-alone sibling must fire: {results:?}"
        );
    }

    #[test]
    fn less_alone_self_obsoletes_is_quiet() {
        // The same LESS-alone shape naming the package's own
        // generation stays quiet: the relation neither creates a
        // finding for a self-obsoletes nor suppresses one for a
        // sibling.
        let results = obsoletes_results(
            "libfoo2",
            vec![DepInfo {
                name: "libfoo2".to_string(),
                flags: RPMSENSE_LESS,
                epoch: None,
                version: None,
                release: None,
            }],
        );
        assert!(
            sibling_lines(&results).is_empty(),
            "LESS-alone self-obsoletes must stay quiet: {results:?}"
        );
    }

    #[test]
    fn fixed_dependency_on_non_lib_package_warns() {
        // A versioned library package with a hard (=) dependency on a
        // non-library package: W shlib-fixed-dependency.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let so_path = dir.path().join("libfoo.so");
        std::fs::write(&so_path, minimal_elf("libfoo.so")).expect("write elf");

        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture header");
        pkg.name = "libfoo1".to_string();
        pkg.files = vec![PkgFile {
            name: "/usr/lib64/libfoo.so".to_string(),
            path: so_path.to_string_lossy().into_owned(),
            mode: 0o100644,
            magic: "ELF 64-bit LSB shared object".to_string(),
            ..Default::default()
        }];
        pkg.requires = vec![DepInfo {
            name: "barbaz".to_string(),
            flags: RPMSENSE_EQUAL,
            epoch: None,
            version: Some("1.0".to_string()),
            release: Some("1".to_string()),
        }];

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = checker();
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        let lines: Vec<&str> = results
            .iter()
            .filter(|(n, _)| n == "shlib-fixed-dependency")
            .map(|(_, line)| line.as_str())
            .collect();
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        assert!(
            lines[0].contains("barbaz = 1.0-1"),
            "detail names the pinned dependency: {}",
            lines[0]
        );
    }

    #[test]
    fn fixed_dependency_on_own_base_is_silent() {
        // A flavor package (`libfoo-x86-64-v3`) pinning its own base
        // (`libfoo = 1.0`) is version lockstep, not a policy violation:
        // no shlib-fixed-dependency.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let so_path = dir.path().join("libfoo.so");
        std::fs::write(&so_path, minimal_elf("libfoo.so")).expect("write elf");

        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture header");
        pkg.name = "libfoo-x86-64-v3".to_string();
        pkg.files = vec![PkgFile {
            name: "/usr/lib64/libfoo.so".to_string(),
            path: so_path.to_string_lossy().into_owned(),
            mode: 0o100644,
            magic: "ELF 64-bit LSB shared object".to_string(),
            ..Default::default()
        }];
        pkg.requires = vec![DepInfo {
            name: "libfoo".to_string(),
            flags: RPMSENSE_EQUAL,
            epoch: None,
            version: Some("1.0".to_string()),
            release: Some("1".to_string()),
        }];

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = checker();
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        assert!(
            results.iter().all(|(n, _)| n != "shlib-fixed-dependency"),
            "flavor pin must stay quiet: {results:?}"
        );
    }

    #[test]
    fn fixed_dependency_prefix_without_flavor_suffix_still_warns() {
        // Boundary of the flavor skip: `libfoo1` requiring `libfoo = 1.0`
        // is a proper prefix but the remainder does not start with `-`,
        // so it is not a flavor pin and must still fire.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let so_path = dir.path().join("libfoo.so");
        std::fs::write(&so_path, minimal_elf("libfoo.so")).expect("write elf");

        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture header");
        pkg.name = "libfoo1".to_string();
        pkg.files = vec![PkgFile {
            name: "/usr/lib64/libfoo.so".to_string(),
            path: so_path.to_string_lossy().into_owned(),
            mode: 0o100644,
            magic: "ELF 64-bit LSB shared object".to_string(),
            ..Default::default()
        }];
        pkg.requires = vec![DepInfo {
            name: "libfoo".to_string(),
            flags: RPMSENSE_EQUAL,
            epoch: None,
            version: Some("1.0".to_string()),
            release: Some("1".to_string()),
        }];

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = checker();
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        let lines: Vec<&str> = results
            .iter()
            .filter(|(n, _)| n == "shlib-fixed-dependency")
            .map(|(_, line)| line.as_str())
            .collect();
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        assert!(
            lines[0].contains("libfoo = 1.0-1"),
            "detail names the pinned dependency: {}",
            lines[0]
        );
    }

    fn etc_results(name: &str, extra: Vec<PkgFile>) -> Vec<(String, String)> {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let so_path = dir.path().join("libfoo.so.1");
        std::fs::write(&so_path, minimal_elf("libfoo.so.1")).expect("write elf");

        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture header");
        pkg.name = name.to_string();
        let mut files = vec![PkgFile {
            name: "/usr/lib64/libfoo.so.1".to_string(),
            path: so_path.to_string_lossy().into_owned(),
            mode: 0o100644,
            magic: "ELF 64-bit LSB shared object".to_string(),
            ..Default::default()
        }];
        files.extend(extra);
        pkg.files = files;
        pkg.requires = vec![];

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = checker();
        check.check_binary(&pkg, &config, &mut out);
        out.results().to_vec()
    }

    fn etc_file(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            ..Default::default()
        }
    }

    fn etc_lines(results: &[(String, String)]) -> Vec<&str> {
        results
            .iter()
            .filter(|(n, _)| n == "shlib-policy-etc-payload")
            .map(|(_, line)| line.as_str())
            .collect()
    }

    #[test]
    fn etc_config_file_in_versioned_shlib_warns() {
        // The libsemanage shape: a versioned shlib package shipping an
        // unversioned config file under /etc.
        let results = etc_results("libsemanage1", vec![etc_file("/etc/selinux/semanage.conf")]);
        let lines = etc_lines(&results);
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        assert!(
            lines[0].contains("/etc/selinux/semanage.conf"),
            "detail names the shipped path: {}",
            lines[0]
        );
    }

    #[test]
    fn usr_etc_config_file_in_versioned_shlib_warns() {
        // /usr/etc is the vendor-default counterpart of /etc (treated
        // as /etc elsewhere in the tree), so payload there conflicts
        // between SONAME generations in exactly the same way.
        let results = etc_results("libfoo1", vec![etc_file("/usr/etc/foo/foo.conf")]);
        let lines = etc_lines(&results);
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        assert!(
            lines[0].contains("/usr/etc/foo/foo.conf"),
            "detail names the shipped path: {}",
            lines[0]
        );
    }

    #[test]
    fn usr_etc_directory_and_ghost_entries_are_quiet() {
        let dir_entry = PkgFile {
            name: "/usr/etc/foo".to_string(),
            mode: 0o40755,
            ..Default::default()
        };
        let results = etc_results("libfoo1", vec![dir_entry]);
        assert!(
            etc_lines(&results).is_empty(),
            "directory entry must stay quiet: {results:?}"
        );
        let ghost = PkgFile {
            flags: crate::pkg::pkgfile::RPMFILE_GHOST,
            ..etc_file("/usr/etc/foo/foo.conf")
        };
        let results = etc_results("libfoo1", vec![ghost]);
        assert!(
            etc_lines(&results).is_empty(),
            "ghost entry must stay quiet: {results:?}"
        );
    }

    #[test]
    fn etc_symlink_in_versioned_shlib_warns() {
        // A symlink occupies the path just like a regular file.
        let link = PkgFile {
            name: "/etc/selinux/semanage.conf".to_string(),
            mode: 0o120777,
            linkto: "/etc/selinux/semanage.conf.real".to_string(),
            ..Default::default()
        };
        let results = etc_results("libfoo1", vec![link]);
        let lines = etc_lines(&results);
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
    }

    #[test]
    fn etc_directory_entry_is_quiet() {
        // Directory entries are shared by design; only payload files fire.
        let dir_entry = PkgFile {
            name: "/etc/selinux".to_string(),
            mode: 0o40755,
            ..Default::default()
        };
        let results = etc_results("libfoo1", vec![dir_entry]);
        assert!(
            etc_lines(&results).is_empty(),
            "directory entry must stay quiet: {results:?}"
        );
    }

    #[test]
    fn etc_ghost_entry_is_quiet() {
        // A %ghost entry is not shipped payload, so no sibling package
        // can conflict over it at file level.
        let ghost = PkgFile {
            flags: crate::pkg::pkgfile::RPMFILE_GHOST,
            ..etc_file("/etc/selinux/semanage.conf")
        };
        let results = etc_results("libfoo1", vec![ghost]);
        assert!(
            etc_lines(&results).is_empty(),
            "ghost entry must stay quiet: {results:?}"
        );
    }

    #[test]
    fn etc_payload_in_non_shlib_package_is_quiet() {
        let results = etc_results("foo-daemon", vec![etc_file("/etc/foo/foo.conf")]);
        assert!(
            etc_lines(&results).is_empty(),
            "non-library package must stay quiet: {results:?}"
        );
    }

    #[test]
    fn etc_payload_in_devel_package_is_quiet() {
        let results = etc_results("libfoo1-devel", vec![etc_file("/etc/foo/foo.conf")]);
        assert!(
            etc_lines(&results).is_empty(),
            "-devel package must stay quiet: {results:?}"
        );
    }

    #[test]
    fn etc_payload_in_lang_package_is_quiet() {
        let results = etc_results("libfoo1-lang", vec![etc_file("/etc/foo/foo.conf")]);
        assert!(
            etc_lines(&results).is_empty(),
            "-lang package must stay quiet: {results:?}"
        );
    }

    #[test]
    fn etc_payload_in_unversioned_lib_is_quiet() {
        // The classifier is the module naming-scheme pattern, which
        // requires the trailing SONAME number: an unversioned lib
        // package is outside the versioned shlib population.
        let results = etc_results("libfoo", vec![etc_file("/etc/foo/foo.conf")]);
        assert!(
            etc_lines(&results).is_empty(),
            "unversioned lib package must stay quiet: {results:?}"
        );
    }

    #[test]
    fn etc_payload_in_32bit_shlib_warns() {
        // The naming scheme treats the -32bit form as the same
        // versioned package name.
        let results = etc_results("libfoo1-32bit", vec![etc_file("/etc/foo/foo.conf")]);
        assert_eq!(
            etc_lines(&results).len(),
            1,
            "exactly one finding: {results:?}"
        );
    }

    #[test]
    fn library_only_shlib_is_quiet() {
        let results = etc_results("libfoo1", vec![]);
        assert!(results.is_empty(), "no findings at all: {results:?}");
    }

    #[test]
    fn non_etc_payload_in_versioned_shlib_is_quiet() {
        let results = etc_results("libfoo1", vec![etc_file("/usr/share/foo/foo.conf")]);
        assert!(
            etc_lines(&results).is_empty(),
            "payload outside /etc and /usr/etc must stay quiet: {results:?}"
        );
    }

    #[test]
    fn multiple_etc_files_each_warn_sorted() {
        let results = etc_results(
            "libfoo1",
            vec![
                etc_file("/etc/selinux/semanage.conf"),
                etc_file("/etc/ld.so.conf.d/foo.conf"),
            ],
        );
        let lines = etc_lines(&results);
        assert_eq!(lines.len(), 2, "one finding per path: {results:?}");
        assert!(
            lines[0].contains("/etc/ld.so.conf.d/foo.conf"),
            "findings sorted by path: {}",
            lines[0]
        );
        assert!(
            lines[1].contains("/etc/selinux/semanage.conf"),
            "findings sorted by path: {}",
            lines[1]
        );
    }

    fn set_pkg(
        name: &str,
        source_rpm: &str,
        requires: Vec<DepInfo>,
        provides: Vec<DepInfo>,
        so_file: Option<&str>,
    ) -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture header");
        pkg.name = name.to_string();
        pkg.arch = "x86_64".to_string();
        pkg.source_rpm = Some(source_rpm.to_string());
        pkg.requires = requires;
        pkg.prereq = vec![];
        pkg.provides = provides;
        pkg.files = so_file
            .map(|f| {
                vec![PkgFile {
                    name: f.to_string(),
                    mode: 0o100644,
                    ..Default::default()
                }]
            })
            .unwrap_or_default();
        pkg
    }

    fn shlib(name: &str, source_rpm: &str) -> Pkg {
        set_pkg(
            name,
            source_rpm,
            vec![],
            vec![],
            Some("/usr/lib64/libfoo.so.1"),
        )
    }

    fn devel(name: &str, source_rpm: &str, requires: Vec<DepInfo>) -> Pkg {
        set_pkg(name, source_rpm, requires, vec![], None)
    }

    fn dep_versioned(name: &str, flags: u32) -> DepInfo {
        DepInfo {
            name: name.to_string(),
            flags,
            epoch: None,
            version: Some("1.0".to_string()),
            release: Some("1".to_string()),
        }
    }

    fn run_set(pkgs: &[&Pkg]) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = checker();
        for pkg in pkgs {
            check.check_binary(pkg, &config, &mut out);
        }
        check.after_checks(&config, &mut out);
        out.results()
            .iter()
            .filter(|(n, _)| n == "shlib-devel-unversioned-requires")
            .cloned()
            .collect()
    }

    #[test]
    fn devel_bare_require_on_sibling_warns() {
        let lib = shlib("libfoo1", "foo-1-1.src.rpm");
        let devel = devel("libfoo-devel", "foo-1-1.src.rpm", vec![dep("libfoo1")]);
        let results = run_set(&[&lib, &devel]);
        assert_eq!(results.len(), 1, "exactly one finding: {results:?}");
        assert_eq!(
            results[0].1,
            "libfoo-devel.x86_64: W: shlib-devel-unversioned-requires libfoo1"
        );
    }

    #[test]
    fn devel_missing_require_on_sibling_warns() {
        let lib = shlib("libfoo1", "foo-1-1.src.rpm");
        let devel = devel("libfoo-devel", "foo-1-1.src.rpm", vec![dep("unrelated")]);
        let results = run_set(&[&lib, &devel]);
        assert_eq!(results.len(), 1, "exactly one finding: {results:?}");
        assert_eq!(
            results[0].1,
            "libfoo-devel.x86_64: W: shlib-devel-unversioned-requires libfoo1"
        );
    }

    #[test]
    fn devel_versioned_require_on_sibling_is_quiet() {
        for flags in [RPMSENSE_EQUAL, RPMSENSE_GREATER | RPMSENSE_EQUAL] {
            let lib = shlib("libfoo1", "foo-1-1.src.rpm");
            let devel = devel(
                "libfoo-devel",
                "foo-1-1.src.rpm",
                vec![dep_versioned("libfoo1", flags)],
            );
            assert!(
                run_set(&[&lib, &devel]).is_empty(),
                "flags {flags} must satisfy the pairing"
            );
        }
    }

    #[test]
    fn devel_without_versioned_shlib_sibling_is_quiet() {
        // The sibling candidate carries no policy number, so the pairing
        // is out of scope even with a bare require.
        let lib = shlib("libfoo", "foo-1-1.src.rpm");
        let devel = devel("libfoo-devel", "foo-1-1.src.rpm", vec![dep("libfoo")]);
        assert!(run_set(&[&lib, &devel]).is_empty());
    }

    #[test]
    fn devel_sibling_without_versioned_so_is_quiet() {
        // A policy-named package shipping no versioned library file is not
        // a shared library sibling.
        let lib = set_pkg(
            "libfoo1",
            "foo-1-1.src.rpm",
            vec![],
            vec![],
            Some("/usr/lib64/libfoo.so"),
        );
        let devel = devel("libfoo-devel", "foo-1-1.src.rpm", vec![dep("unrelated")]);
        assert!(run_set(&[&lib, &devel]).is_empty());
    }

    #[test]
    fn devel_and_shlib_from_different_sources_do_not_pair() {
        let lib = shlib("libfoo1", "foo-1-1.src.rpm");
        let devel = devel("libfoo-devel", "other-2-1.src.rpm", vec![dep("unrelated")]);
        assert!(run_set(&[&lib, &devel]).is_empty());
    }

    #[test]
    fn devel_named_after_numbered_sibling_warns() {
        let lib = shlib("libfoo1", "foo-1-1.src.rpm");
        let devel = devel("libfoo1-devel", "foo-1-1.src.rpm", vec![dep("libfoo1")]);
        let results = run_set(&[&lib, &devel]);
        assert_eq!(results.len(), 1, "exactly one finding: {results:?}");
        assert_eq!(
            results[0].1,
            "libfoo1-devel.x86_64: W: shlib-devel-unversioned-requires libfoo1"
        );
    }

    #[test]
    fn devel_32bit_sibling_pairs() {
        let lib = shlib("libfoo1-32bit", "foo-1-1.src.rpm");
        let devel = devel("libfoo-devel", "foo-1-1.src.rpm", vec![dep("unrelated")]);
        let results = run_set(&[&lib, &devel]);
        assert_eq!(results.len(), 1, "exactly one finding: {results:?}");
        // The finding names the group's canonical base name, not the
        // flavour suffix of the only sibling present.
        assert_eq!(
            results[0].1,
            "libfoo-devel.x86_64: W: shlib-devel-unversioned-requires libfoo1"
        );
    }

    #[test]
    fn devel_baselibs_versioned_require_on_base_is_quiet() {
        // Standard baselibs layout: one source builds the base and the
        // -32bit flavour; a versioned require on the base satisfies the
        // whole group and must not fire for the -32bit sibling.
        let lib = shlib("libfoo1", "foo-1-1.src.rpm");
        let lib32 = shlib("libfoo1-32bit", "foo-1-1.src.rpm");
        let devel = devel(
            "libfoo-devel",
            "foo-1-1.src.rpm",
            vec![dep_versioned("libfoo1", RPMSENSE_EQUAL)],
        );
        assert!(run_set(&[&lib, &lib32, &devel]).is_empty());
    }

    #[test]
    fn devel_baselibs_versioned_require_on_32bit_is_quiet() {
        // A versioned require naming any group member satisfies the group.
        let lib = shlib("libfoo1", "foo-1-1.src.rpm");
        let lib32 = shlib("libfoo1-32bit", "foo-1-1.src.rpm");
        let devel = devel(
            "libfoo-devel",
            "foo-1-1.src.rpm",
            vec![dep_versioned("libfoo1-32bit", RPMSENSE_EQUAL)],
        );
        assert!(run_set(&[&lib, &lib32, &devel]).is_empty());
    }

    #[test]
    fn devel_baselibs_without_versioned_require_warns_once() {
        // No versioned require on any group member: exactly one finding
        // for the group, naming its canonical (non-flavoured) sibling.
        let lib = shlib("libfoo1", "foo-1-1.src.rpm");
        let lib32 = shlib("libfoo1-32bit", "foo-1-1.src.rpm");
        let devel = devel("libfoo-devel", "foo-1-1.src.rpm", vec![dep("unrelated")]);
        let results = run_set(&[&lib, &lib32, &devel]);
        assert_eq!(results.len(), 1, "exactly one finding: {results:?}");
        assert_eq!(
            results[0].1,
            "libfoo-devel.x86_64: W: shlib-devel-unversioned-requires libfoo1"
        );
    }

    #[test]
    fn devel_distinct_groups_are_not_merged() {
        // libfoo1 and libbar2 are distinct groups: satisfying foo's group
        // leaves bar's group firing exactly once, on its own -devel.
        let foo = shlib("libfoo1", "foo-1-1.src.rpm");
        let bar = shlib("libbar2", "foo-1-1.src.rpm");
        let foo_devel = devel(
            "libfoo-devel",
            "foo-1-1.src.rpm",
            vec![dep_versioned("libfoo1", RPMSENSE_EQUAL)],
        );
        let bar_devel = devel("libbar-devel", "foo-1-1.src.rpm", vec![dep("unrelated")]);
        let results = run_set(&[&foo, &bar, &foo_devel, &bar_devel]);
        assert_eq!(results.len(), 1, "exactly one finding: {results:?}");
        assert_eq!(
            results[0].1,
            "libbar-devel.x86_64: W: shlib-devel-unversioned-requires libbar2"
        );
    }

    #[test]
    fn devel_versioned_require_on_sibling_provides_name_is_quiet() {
        // The sibling provides its stem name with a version; a versioned
        // require on that name is the package pairing.
        let mut lib = shlib("libfoo23", "foo-1-1.src.rpm");
        lib.provides = vec![dep_versioned("libfoo", RPMSENSE_EQUAL)];
        let devel = devel(
            "libfoo-devel",
            "foo-1-1.src.rpm",
            vec![dep_versioned("libfoo", RPMSENSE_EQUAL)],
        );
        assert!(run_set(&[&lib, &devel]).is_empty());
    }

    #[test]
    fn devel_bare_require_on_sibling_provides_name_warns() {
        let mut lib = shlib("libfoo23", "foo-1-1.src.rpm");
        lib.provides = vec![dep_versioned("libfoo", RPMSENSE_EQUAL)];
        let devel = devel("libfoo-devel", "foo-1-1.src.rpm", vec![dep("libfoo")]);
        let results = run_set(&[&lib, &devel]);
        assert_eq!(results.len(), 1, "exactly one finding: {results:?}");
    }

    #[test]
    fn devel_soname_require_does_not_satisfy() {
        // A SONAME require binds the library file, not the package pairing.
        // The sibling carries the SONAME provide real library packages
        // carry, so only the `.so` exclusion in the provides scan keeps
        // this require from satisfying the pairing: without that
        // exclusion the require would match the provide's base name and
        // this test would go quiet.
        let mut lib = shlib("libfoo1", "foo-1-1.src.rpm");
        lib.provides = vec![dep_versioned("libfoo.so.1()(64bit)", RPMSENSE_EQUAL)];
        let devel = devel(
            "libfoo-devel",
            "foo-1-1.src.rpm",
            vec![dep_versioned("libfoo.so.1()(64bit)", RPMSENSE_EQUAL)],
        );
        let results = run_set(&[&lib, &devel]);
        assert_eq!(results.len(), 1, "exactly one finding: {results:?}");
    }

    #[test]
    fn devel_rich_versioned_require_is_quiet() {
        let lib = shlib("libfoo1", "foo-1-1.src.rpm");
        let devel = devel(
            "libfoo-devel",
            "foo-1-1.src.rpm",
            vec![DepInfo {
                name: "(libfoo1 >= 1.0 with libfoo1-32bit)".to_string(),
                flags: 0,
                epoch: None,
                version: None,
                release: None,
            }],
        );
        assert!(run_set(&[&lib, &devel]).is_empty());
    }

    #[test]
    fn devel_rich_bare_require_warns() {
        let lib = shlib("libfoo1", "foo-1-1.src.rpm");
        let devel = devel(
            "libfoo-devel",
            "foo-1-1.src.rpm",
            vec![DepInfo {
                name: "(libfoo1 or libbar1)".to_string(),
                flags: 0,
                epoch: None,
                version: None,
                release: None,
            }],
        );
        let results = run_set(&[&lib, &devel]);
        assert_eq!(results.len(), 1, "exactly one finding: {results:?}");
    }

    #[test]
    fn devel_pairing_merges_worker_state() {
        let config = Config::default();
        let lib = shlib("libfoo1", "foo-1-1.src.rpm");
        let devel = devel("libfoo-devel", "foo-1-1.src.rpm", vec![dep("unrelated")]);
        let mut w0 = checker();
        let mut out0 = Filter::new(&config, Color::for_tty(false)).unwrap();
        w0.check_binary(&lib, &config, &mut out0);
        let s0 = w0.export_state().expect("worker 0 exports");
        let mut w1 = checker();
        let mut out1 = Filter::new(&config, Color::for_tty(false)).unwrap();
        w1.check_binary(&devel, &config, &mut out1);
        let s1 = w1.export_state().expect("worker 1 exports");
        let mut main = checker();
        main.import_state(s0);
        main.import_state(s1);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        main.after_checks(&config, &mut out);
        let results: Vec<_> = out
            .results()
            .iter()
            .filter(|(n, _)| n == "shlib-devel-unversioned-requires")
            .collect();
        assert_eq!(results.len(), 1, "merged state must pair: {results:?}");
    }

    #[test]
    fn devel_pairing_reset_drops_state() {
        let config = Config::default();
        let lib = shlib("libfoo1", "foo-1-1.src.rpm");
        let devel = devel("libfoo-devel", "foo-1-1.src.rpm", vec![dep("unrelated")]);
        let mut check = checker();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(&lib, &config, &mut out);
        check.check_binary(&devel, &config, &mut out);
        check.reset();
        check.after_checks(&config, &mut out);
        assert!(out.results().is_empty(), "state leaked across reset");
    }
}
