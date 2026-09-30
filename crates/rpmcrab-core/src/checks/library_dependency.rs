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
use crate::check::basename;
use crate::checks::is_match;
use crate::checks::shared::devel_regex;
use crate::config::Config;
use crate::filter::Filter;
use crate::finding::Finding;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::is_symlink;

/// The reference reads `%{_isa}` from the running rpm's macros at
/// construction time (`LibraryDependencyCheck.py:17`); derive it the same
/// way through librpm instead of a hand-written table.
fn expand_isa() -> String {
    let _ = crate::pkg::init();
    librpm::macro_context::MacroContext::default()
        .expand("%{_isa}")
        .unwrap_or_default()
}

pub struct LibraryDependencyCheck {
    package_requires: HashMap<String, Vec<String>>,
    package_so_symlinks: HashMap<String, Vec<String>>,
    /// Lint order of the devel packages; the reference iterates a plain
    /// dict, so findings follow package lint order deterministically.
    devel_order: Vec<String>,
    package_so_files: HashMap<String, String>,
    package_arch_mapping: HashMap<String, String>,
    isa: String,
}

impl LibraryDependencyCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            package_requires: HashMap::new(),
            package_so_symlinks: HashMap::new(),
            devel_order: Vec::new(),
            package_so_files: HashMap::new(),
            package_arch_mapping: HashMap::new(),
            isa: expand_isa(),
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
        Finding {
            level,
            check: check.to_string(),
            details,
            badness: 0,
            pkg_name: basename(pkg_name).to_string(),
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
        self.devel_order.clear();
        self.package_so_files.clear();
        self.package_arch_mapping.clear();
        self.isa = expand_isa();
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
            // Keyed on `pkg.name` alone, like the reference's dicts
            // (`LibraryDependencyCheck.py:46-52`): linting two arches of the
            // same package together makes each clobber the other, there as
            // here. Inherited upstream quirk, kept for parity.
            let first_seen = self
                .package_requires
                .insert(pkg.name.clone(), requires)
                .is_none();
            self.package_so_symlinks
                .insert(pkg.name.clone(), Vec::new());
            self.package_arch_mapping
                .insert(pkg.name.clone(), pkg.arch.clone());
            if first_seen {
                self.devel_order.push(pkg.name.clone());
            }

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
        // Insertion order, not `HashMap` order: the reference iterates a
        // plain dict (`LibraryDependencyCheck.py:52`), i.e. package lint
        // order, which is what the frozen sort-order contract pins.
        for idx in 0..self.devel_order.len() {
            let pkgname = self.devel_order[idx].clone();
            let arch = self
                .package_arch_mapping
                .get(&pkgname)
                .cloned()
                .unwrap_or_default();
            let so_symlinks = self
                .package_so_symlinks
                .get(&pkgname)
                .cloned()
                .unwrap_or_default();
            let requires = self
                .package_requires
                .get(&pkgname)
                .cloned()
                .unwrap_or_default();
            for link in &so_symlinks {
                if let Some(definition) = self.package_so_files.get(link) {
                    // `definition` is the *package* name, not a soname
                    // (`LibraryDependencyCheck.py:49`), so `definition + isa`
                    // matches nothing rpm generates; dead in the reference
                    // as well, kept faithful.
                    let with_isa = format!("{definition}{}", self.isa);
                    if !requires.iter().any(|r| r == definition || r == &with_isa) {
                        out.add_info(Self::make_finding(
                            &pkgname,
                            &arch,
                            Level::Error,
                            "no-library-dependency-on",
                            vec![definition.clone(), link.clone()],
                        ));
                        break;
                    }
                } else {
                    out.add_info(Self::make_finding(
                        &pkgname,
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

    /// A library package shipping `/usr/lib64/<lib>.so.1` and its `-devel`
    /// subpackage carrying the given requires plus the `.so` symlink.
    fn lib_and_devel_as(lib_name: &str, devel_name: &str, requires: &[String]) -> (Pkg, Pkg) {
        let mut lib = fixture_pkg();
        lib.name = lib_name.to_string();
        lib.arch = "x86_64".to_string();
        lib.files = vec![regular(&format!("/usr/lib64/{lib_name}.so.1"))];

        let mut devel = fixture_pkg();
        devel.name = devel_name.to_string();
        devel.arch = "x86_64".to_string();
        devel.requires = requires.iter().map(|r| require(r)).collect();
        devel.prereq = vec![];
        devel.files = vec![symlink(
            &format!("/usr/lib64/{lib_name}.so"),
            &format!("{lib_name}.so.1"),
        )];
        (lib, devel)
    }

    fn lib_and_devel(requires: &[String]) -> (Pkg, Pkg) {
        lib_and_devel_as("libfoo", "foo-devel", requires)
    }

    fn run_pkgs(pkgs: &[&Pkg]) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = LibraryDependencyCheck::new(&config);
        for pkg in pkgs {
            check.check_binary(pkg, &config, &mut out);
        }
        check.after_checks(&config, &mut out);
        out.results().to_vec()
    }

    fn run(lib: &Pkg, devel: &Pkg) -> Vec<(String, String)> {
        run_pkgs(&[lib, devel])
    }

    #[test]
    fn devel_pkg_detected() {
        assert!(LibraryDependencyCheck::is_devel_pkg("foo-devel"));
        assert!(LibraryDependencyCheck::is_devel_pkg("foo-debuginfo"));
        assert!(!LibraryDependencyCheck::is_devel_pkg("foo"));
        assert!(!LibraryDependencyCheck::is_devel_pkg("foo-libs"));
    }

    #[test]
    fn isa_comes_from_rpm_isa_macro() {
        // Honest integration assertion: the check must use rpm's own
        // `%{_isa}` expansion, not a hand-written table.
        let _ = crate::pkg::init();
        let expected = librpm::macro_context::MacroContext::default()
            .expand("%{_isa}")
            .unwrap_or_default();
        let config = Config::default();
        let check = LibraryDependencyCheck::new(&config);
        assert_eq!(check.isa, expected);
    }

    #[test]
    fn isa_qualified_require_is_accepted() {
        // Reference `LibraryDependencyCheck.py:61-63`: `definition + self.isa`
        // in requires counts as depending on the library (dead arm in
        // practice — `definition` is a package name — but kept faithful).
        let config = Config::default();
        let isa = LibraryDependencyCheck::new(&config).isa.clone();
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

    #[test]
    fn findings_follow_package_lint_order() {
        // The reference iterates a plain dict, i.e. package lint order.
        // With several devel packages tripping the check, the findings must
        // come out in lint order — deterministically, across runs.
        let scenario = || {
            let mut pkgs = Vec::new();
            for i in 0..5 {
                let (lib, devel) = lib_and_devel_as(
                    &format!("libdep{i}"),
                    &format!("libdep{i}-devel"),
                    &["unrelated".to_string()],
                );
                pkgs.push(lib);
                pkgs.push(devel);
            }
            let refs: Vec<&Pkg> = pkgs.iter().collect();
            run_pkgs(&refs)
                .into_iter()
                .map(|(_, line)| line)
                .collect::<Vec<_>>()
        };
        let first = scenario();
        assert_eq!(first.len(), 5, "one finding per devel package");
        for (i, line) in first.iter().enumerate() {
            let prefix = format!("libdep{i}-devel.x86_64:");
            assert!(
                line.starts_with(&prefix),
                "finding {i} out of lint order: {line}"
            );
            assert!(
                line.contains(": E: no-library-dependency-on"),
                "check and level: {line}"
            );
        }
        // Fresh maps per run, so a randomised iteration order would diverge.
        for _ in 0..4 {
            assert_eq!(scenario(), first, "finding order is not deterministic");
        }
    }
}
