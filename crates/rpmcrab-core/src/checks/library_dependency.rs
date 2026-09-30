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

/// The reference reads `%{_isa}` from the running rpm's macros (`(x86-64)` on
/// x86_64, `(aarch64)` on aarch64, …). There is no macro engine here, so map
/// the host arch the way rpm's platform macros do.
fn isa_suffix(arch: &str) -> &'static str {
    match arch {
        "x86_64" => "(x86-64)",
        "i386" | "i486" | "i586" | "i686" => "(x86-32)",
        "aarch64" => "(aarch64)",
        "ppc64" | "ppc64le" => "(ppc-64)",
        "s390x" => "(s390-64)",
        "riscv64" => "(riscv-64)",
        _ => "",
    }
}

pub struct LibraryDependencyCheck {
    package_requires: HashMap<String, Vec<String>>,
    package_so_symlinks: HashMap<String, Vec<String>>,
    package_so_files: HashMap<String, String>,
    package_arch_mapping: HashMap<String, String>,
    isa: String,
}

impl LibraryDependencyCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            package_requires: HashMap::new(),
            package_so_symlinks: HashMap::new(),
            package_so_files: HashMap::new(),
            package_arch_mapping: HashMap::new(),
            isa: isa_suffix(std::env::consts::ARCH).to_string(),
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
        self.isa = isa_suffix(std::env::consts::ARCH).to_string();
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
                    // The reference accepts the bare name or the ISA-qualified
                    // one (`libfoo` or `libfoo(x86-64)`).
                    let with_isa = format!("{definition}{}", self.isa);
                    if !requires.iter().any(|r| r == definition || r == &with_isa) {
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
    use std::path::Path;

    use crate::color::Color;
    use crate::pkg::dep::DepInfo;
    use crate::pkg::pkgfile::PkgFile;

    /// `Pkg` is header-backed with no test constructor, so open a tiny fixture
    /// and rewrite the public fields the check reads.
    fn fixture_pkg() -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        Pkg::open(&rpm, &std::env::temp_dir()).expect("open fixture pkg")
    }

    fn require(name: &str) -> DepInfo {
        DepInfo {
            name: name.to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        }
    }

    fn symlink(name: &str, linkto: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o120777,
            linkto: linkto.to_string(),
            ..Default::default()
        }
    }

    fn regular(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            ..Default::default()
        }
    }

    /// A library package shipping `/usr/lib64/libfoo.so.1` and its `-devel`
    /// subpackage carrying the given requires plus the `.so` symlink.
    fn lib_and_devel(requires: &[String]) -> (Pkg, Pkg) {
        let mut lib = fixture_pkg();
        lib.name = "libfoo".to_string();
        lib.arch = "x86_64".to_string();
        lib.files = vec![regular("/usr/lib64/libfoo.so.1")];

        let mut devel = fixture_pkg();
        devel.name = "foo-devel".to_string();
        devel.arch = "x86_64".to_string();
        devel.requires = requires.iter().map(|r| require(r)).collect();
        devel.prereq = vec![];
        devel.files = vec![symlink("/usr/lib64/libfoo.so", "libfoo.so.1")];
        (lib, devel)
    }

    fn run(lib: &Pkg, devel: &Pkg) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = LibraryDependencyCheck::new(&config);
        check.check_binary(lib, &config, &mut out);
        check.check_binary(devel, &config, &mut out);
        check.after_checks(&config, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn devel_pkg_detected() {
        assert!(LibraryDependencyCheck::is_devel_pkg("foo-devel"));
        assert!(LibraryDependencyCheck::is_devel_pkg("foo-debuginfo"));
        assert!(!LibraryDependencyCheck::is_devel_pkg("foo"));
        assert!(!LibraryDependencyCheck::is_devel_pkg("foo-libs"));
    }

    #[test]
    fn isa_suffix_matches_rpm_platform_macros() {
        assert_eq!(isa_suffix("x86_64"), "(x86-64)");
        assert_eq!(isa_suffix("i586"), "(x86-32)");
        assert_eq!(isa_suffix("aarch64"), "(aarch64)");
        assert_eq!(isa_suffix("ppc64le"), "(ppc-64)");
        assert_eq!(isa_suffix("s390x"), "(s390-64)");
        assert_eq!(isa_suffix("riscv64"), "(riscv-64)");
    }

    #[test]
    fn isa_qualified_require_is_accepted() {
        // Reference `LibraryDependencyCheck.py:61-63`: `definition + self.isa`
        // in requires counts as depending on the library.
        let isa = isa_suffix(std::env::consts::ARCH);
        let (lib, devel) = lib_and_devel(&[format!("libfoo{isa}")]);
        assert!(run(&lib, &devel).is_empty());
    }

    #[test]
    fn bare_require_is_accepted() {
        let (lib, devel) = lib_and_devel(&["libfoo".to_string()]);
        assert!(run(&lib, &devel).is_empty());
    }

    #[test]
    fn missing_require_reports_no_library_dependency_on() {
        let (lib, devel) = lib_and_devel(&["unrelated".to_string()]);
        let results = run(&lib, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-on");
        let line = &results[0].1;
        assert!(line.contains(": E: "), "level: {line}");
        assert!(line.contains("libfoo"), "definition: {line}");
        assert!(line.contains("/usr/lib64/libfoo.so.1"), "link: {line}");
    }

    #[test]
    fn dangling_symlink_reports_no_library_dependency_for() {
        let (mut lib, devel) = lib_and_devel(&["libfoo".to_string()]);
        lib.files = vec![];
        let results = run(&lib, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-for");
        let line = &results[0].1;
        assert!(line.contains(": E: "), "level: {line}");
        assert!(line.contains("/usr/lib64/libfoo.so.1"), "link: {line}");
    }
}
