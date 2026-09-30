//! `SharedLibraryPolicyCheck` — shared library packaging policy.
//!
//! Ported from `rpmlint/checks/SharedLibraryPolicyCheck.py`. Findings:
//! `shlib-policy-missing-lib`, `readelf-failed`, `shlib-unversioned-lib`,
//! `shlib-fixed-dependency`, `shlib-policy-excessive-dependency`.

use std::collections::{HashMap, HashSet};

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

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
}

impl SharedLibraryPolicyCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            re_soname_strongly_versioned: Regex::new(r"-[\d\.]+\.so$").expect("static regex"),
            re_soname_pkg: Regex::new(r"^lib\S+(\d+(-(32|64)bit)?)$").expect("static regex"),
            re_so_files: Regex::new(r"\S+.so((\.(\d+))*)$").expect("static regex"),
        }
    }

    /// `(soname, needed)` from an ELF file, or the parse failure reason.
    fn elf_dynamic(path: &str) -> Result<(Option<String>, Vec<String>), String> {
        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        let elf = goblin::elf::Elf::parse(&data).map_err(|e| e.to_string())?;
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

impl Check for SharedLibraryPolicyCheck {
    fn name(&self) -> &'static str {
        "SharedLibraryPolicyCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }
        // Only non-development, non-language library packages.
        if !pkg.name.starts_with("lib")
            || pkg.name.ends_with("-devel")
            || pkg.name.ends_with("-lang")
        {
            return;
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
        let mut pkg = Pkg::open(&rpm, &dir).expect("open fixture pkg");
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
}
