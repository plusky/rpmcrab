//! `LibraryDependencyCheck` — devel packages must require their libraries.
//!
//! Ported from `rpmlint/checks/LibraryDependencyCheck.py`. Two findings:
//! `no-library-dependency-for` and `no-library-dependency-on`.
//!
//! This is a cross-package check: it collects `.so` symlinks from devel
//! packages and `.so` files from non-devel packages during `check_binary`,
//! then verifies the dependencies in `after_checks`.

use std::collections::HashMap;
use std::path::Path;

use crate::check::Check;
use crate::checks::is_match;
use crate::checks::shared::devel_regex;
use crate::config::Config;
use crate::filter::Filter;
use crate::finding::Finding;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::is_symlink;

pub struct LibraryDependencyCheck {
    package_requires: HashMap<String, Vec<String>>,
    package_so_symlinks: HashMap<String, Vec<String>>,
    package_so_files: HashMap<String, String>,
    package_arch_mapping: HashMap<String, String>,
}

impl LibraryDependencyCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            package_requires: HashMap::new(),
            package_so_symlinks: HashMap::new(),
            package_so_files: HashMap::new(),
            package_arch_mapping: HashMap::new(),
        }
    }

    fn is_devel_pkg(name: &str) -> bool {
        is_match(&devel_regex(), name)
    }

    /// Build a `Finding` for a package identified by name and arch, mirroring
    /// the reference's `FakePkg` usage in `after_checks`.
    fn make_finding(
        pkg_name: &str,
        arch: &str,
        level: Level,
        check: &str,
        details: Vec<String>,
    ) -> Finding {
        // `Path(package.name).name`: the header NAME, not the path.
        let pkg_name = pkg_name.rsplit('/').next().unwrap_or(pkg_name).to_string();
        Finding {
            level,
            check: check.to_string(),
            details,
            badness: 0,
            pkg_name,
            arch: (!arch.is_empty()).then(|| arch.to_string()),
            line: None,
        }
    }
}

impl Check for LibraryDependencyCheck {
    fn name(&self) -> &'static str {
        "LibraryDependencyCheck"
    }

    fn reset(&mut self) {
        self.package_requires.clear();
        self.package_so_symlinks.clear();
        self.package_so_files.clear();
        self.package_arch_mapping.clear();
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, _out: &mut Filter) {
        if pkg.is_source {
            return;
        }

        if Self::is_devel_pkg(&pkg.name) {
            let requires: Vec<String> = pkg
                .requires
                .iter()
                .chain(pkg.prereq.iter())
                .map(|d| d.name.clone())
                .collect();
            self.package_requires.insert(pkg.name.clone(), requires);
            self.package_so_symlinks
                .insert(pkg.name.clone(), Vec::new());
            self.package_arch_mapping
                .insert(pkg.name.clone(), pkg.arch.clone());

            let symlinks = self.package_so_symlinks.get_mut(&pkg.name).unwrap();
            for pkgfile in &pkg.files {
                if is_symlink(pkgfile.mode) && pkgfile.name.ends_with(".so") {
                    let parent = Path::new(&pkgfile.name).parent().unwrap_or(Path::new("/"));
                    let link = parent.join(&pkgfile.linkto);
                    symlinks.push(link.to_string_lossy().into_owned());
                }
            }
        } else {
            for pkgfile in &pkg.files {
                if pkgfile.name.contains(".so") {
                    self.package_so_files
                        .insert(pkgfile.name.clone(), pkg.name.clone());
                }
            }
        }
    }

    fn after_checks(&mut self, _config: &Config, out: &mut Filter) {
        for (pkgname, so_symlinks) in &self.package_so_symlinks {
            let arch = self
                .package_arch_mapping
                .get(pkgname)
                .cloned()
                .unwrap_or_default();
            for link in so_symlinks {
                if let Some(definition) = self.package_so_files.get(link) {
                    let requires = self
                        .package_requires
                        .get(pkgname)
                        .cloned()
                        .unwrap_or_default();
                    if !requires.iter().any(|r| r == definition) {
                        out.add_info(Self::make_finding(
                            pkgname,
                            &arch,
                            Level::Error,
                            "no-library-dependency-on",
                            vec![definition.clone(), link.clone()],
                        ));
                        break;
                    }
                } else {
                    out.add_info(Self::make_finding(
                        pkgname,
                        &arch,
                        Level::Error,
                        "no-library-dependency-for",
                        vec![link.clone()],
                    ));
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devel_pkg_detected() {
        assert!(LibraryDependencyCheck::is_devel_pkg("foo-devel"));
        assert!(LibraryDependencyCheck::is_devel_pkg("foo-debuginfo"));
        assert!(!LibraryDependencyCheck::is_devel_pkg("foo"));
        assert!(!LibraryDependencyCheck::is_devel_pkg("foo-libs"));
    }
}
