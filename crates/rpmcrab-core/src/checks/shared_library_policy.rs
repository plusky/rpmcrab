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
            // Non-versioned libs in a std lib package.
            for lib in &filtered {
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
                    let evr = dep.evr_string();
                    let detail = if evr.is_empty() {
                        dep.name.clone()
                    } else {
                        // Like the reference's formatRequire: the operator
                        // reflects the flags, not a hardcoded `=`.
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
                        format!("{} {op} {}", dep.name, evr)
                    };
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

        // Non-lib stuff must not add dependencies.
        if !libs.is_empty() {
            for dep in &pkg_requires {
                if dep.contains(".so.") && !libs.contains(*dep) && !libs_needed.contains(*dep) {
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

    fn checker() -> SharedLibraryPolicyCheck {
        SharedLibraryPolicyCheck::new(&Config::default())
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
}
