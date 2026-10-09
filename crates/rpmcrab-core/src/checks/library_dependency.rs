//! `LibraryDependencyCheck` — devel packages must require their libraries.
//!
//! Ported from `rpmlint/checks/LibraryDependencyCheck.py`. Two findings:
//! `no-library-dependency-for` and `no-library-dependency-on`.
//!
//! This is a cross-package check: it collects `.so` symlinks from devel
//! packages and `.so` files from non-devel packages during `check_binary`,
//! then verifies the dependencies in `after_checks`.
//!
//! Deliberate divergence (plusky/rpmcrab#74): the per-package maps are keyed
//! on `(name, arch)`; the rationale is in the doc comment on the
//! `devel_order` field below.
//!
//! Deliberate divergence: symlink chains are resolved inside the
//! devel package to the real file before recording (any intermediate,
//! not just `.so` links), and joined targets are lexically normalised
//! (`.`/`..` resolved); the reference keeps the unnormalised one-hop
//! target.

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;

use crate::check::Check;
use crate::check::make_finding;
use crate::checks::is_match;
use crate::checks::shared::devel_regex;
use crate::config::Config;
use crate::filter::Filter;
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

/// Join a symlink's parent directory with its target and lexically
/// resolve `.`/`..` (`/usr/lib64/glfw2` + `../libglfw.so.2` becomes
/// `/usr/lib64/libglfw.so.2`). Pure string manipulation: no filesystem
/// access, so dangling links resolve fine and `..` above the root is
/// dropped. Without this, a legitimate `..` in a link target records a
/// path no package can provide and misfires `no-library-dependency-for`.
fn join_link_target(parent: &Path, linkto: &str) -> String {
    let joined = parent.join(linkto).to_string_lossy().into_owned();
    let absolute = joined.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for comp in joined.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    let mut out = parts.join("/");
    if absolute {
        out.insert(0, '/');
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

pub struct LibraryDependencyCheck {
    package_requires: HashMap<(String, String), Vec<String>>,
    package_so_symlinks: HashMap<(String, String), Vec<String>>,
    /// Lint order of the devel packages; the reference iterates a plain
    /// dict, so findings follow package lint order deterministically.
    /// Keyed on `(name, arch)`: the reference keys on `pkg.name` alone
    /// (`LibraryDependencyCheck.py:37-39`), so linting two arches of the
    /// same package together silently drops all but the last arch. The port
    /// deliberately checks each arch (plusky/rpmcrab#74).
    devel_order: Vec<(String, String)>,
    package_so_files: HashMap<String, String>,
    isa: String,
}

/// Cross-package state, exported per package and merged before
/// `after_checks` (`rpmlint#1595`). `devel_order` travels too: the reference
/// iterates a plain dict (insertion order), which the port pins via this
/// vector.
struct LibDepState {
    package_requires: HashMap<(String, String), Vec<String>>,
    package_so_symlinks: HashMap<(String, String), Vec<String>>,
    package_so_files: HashMap<String, String>,
    devel_order: Vec<(String, String)>,
}

impl LibraryDependencyCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            package_requires: HashMap::new(),
            package_so_symlinks: HashMap::new(),
            devel_order: Vec::new(),
            package_so_files: HashMap::new(),
            isa: expand_isa(),
        }
    }

    fn is_devel_pkg(name: &str) -> bool {
        is_match(devel_regex(), name)
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
        self.isa = expand_isa();
    }

    fn export_state(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        let state = LibDepState {
            package_requires: std::mem::take(&mut self.package_requires),
            package_so_symlinks: std::mem::take(&mut self.package_so_symlinks),
            package_so_files: std::mem::take(&mut self.package_so_files),
            devel_order: std::mem::take(&mut self.devel_order),
        };
        self.isa = expand_isa();
        Some(Box::new(state))
    }

    fn import_state(&mut self, state: Box<dyn std::any::Any + Send>) {
        // Merging in package input order keeps the reference's dict
        // insertion order: first-seen package wins the position.
        if let Ok(state) = state.downcast::<LibDepState>() {
            self.package_requires.extend(state.package_requires);
            self.package_so_symlinks.extend(state.package_so_symlinks);
            self.package_so_files.extend(state.package_so_files);
            for name in state.devel_order {
                if !self.devel_order.contains(&name) {
                    self.devel_order.push(name);
                }
            }
        }
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
            // Keyed on `(name, arch)`: the reference keys on `pkg.name`
            // alone (`LibraryDependencyCheck.py:37-39`), so the second arch
            // of a package overwrites the first and only the last arch is
            // ever checked. Deliberate fix (plusky/rpmcrab#74): each arch
            // gets its own entry.
            let key = (pkg.name.clone(), pkg.arch.clone());
            let first_seen = self
                .package_requires
                .insert(key.clone(), requires)
                .is_none();
            self.package_so_symlinks.insert(key.clone(), Vec::new());
            if first_seen {
                self.devel_order.push(key.clone());
            }

            let symlinks = self.package_so_symlinks.get_mut(&key).unwrap();
            // One-hop targets of every symlink in this package, for resolving
            // chained links below.
            let targets: HashMap<&str, String> = pkg
                .files
                .iter()
                .filter(|pf| is_symlink(pf.mode))
                .map(|pf| {
                    let parent = Path::new(&pf.name).parent().unwrap_or(Path::new("/"));
                    (pf.name.as_str(), join_link_target(parent, &pf.linkto))
                })
                .collect();
            for pkgfile in &pkg.files {
                if is_symlink(pkgfile.mode) && pkgfile.name.ends_with(".so") {
                    let parent = Path::new(&pkgfile.name).parent().unwrap_or(Path::new("/"));
                    let mut link = join_link_target(parent, &pkgfile.linkto);
                    // Follow the chain inside the devel package to the real
                    // library (`libfoo.so -> libfoo-1_2.so -> libfoo.so.1`).
                    // The reference records the one-hop target, which misfires
                    // `no-library-dependency-for` on the intermediate link: no
                    // library package can provide a link the devel ships itself.
                    let mut seen = HashSet::new();
                    while let Some(next) = targets.get(link.as_str()) {
                        if !seen.insert(link.clone()) {
                            break;
                        }
                        link = next.clone();
                    }
                    symlinks.push(link);
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
            let (pkgname, arch) = self.devel_order[idx].clone();
            let key = (pkgname.clone(), arch.clone());
            let so_symlinks = self
                .package_so_symlinks
                .get(&key)
                .cloned()
                .unwrap_or_default();
            let requires = self.package_requires.get(&key).cloned().unwrap_or_default();
            for link in &so_symlinks {
                if let Some(definition) = self.package_so_files.get(link) {
                    // `definition` is the *package* name, not a soname
                    // (`LibraryDependencyCheck.py:49`), so `definition + isa`
                    // matches nothing rpm generates; dead in the reference
                    // as well, kept faithful.
                    let with_isa = format!("{definition}{}", self.isa);
                    if !requires.iter().any(|r| r == definition || r == &with_isa) {
                        out.add_info(make_finding(
                            &pkgname,
                            &arch,
                            Level::Error,
                            "no-library-dependency-on",
                            vec![definition.clone(), link.clone()],
                            None,
                        ));
                        break;
                    }
                } else {
                    out.add_info(make_finding(
                        &pkgname,
                        &arch,
                        Level::Error,
                        "no-library-dependency-for",
                        vec![link.clone()],
                        None,
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
        Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg")
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
    fn make_finding_path_renders_exact_line() {
        // Pins the `check::make_finding` field mapping through this check:
        // basename, arch suffix, level letter, check name, detail order and
        // spacing, no badness column. Any field regressing in the refactor
        // fails here, not just in the shared `check.rs` coverage.
        let (lib, devel) = lib_and_devel(&["unrelated".to_string()]);
        let results = run(&lib, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-on");
        assert_eq!(
            results[0].1,
            "foo-devel.x86_64: E: no-library-dependency-on libfoo /usr/lib64/libfoo.so.1"
        );
    }

    #[test]
    fn empty_arch_omits_arch_suffix() {
        // `make_finding` maps an empty arch to `None`; the rendered line
        // must not carry a stray `.` before the colon.
        let (lib, mut devel) = lib_and_devel(&["unrelated".to_string()]);
        devel.arch = String::new();
        let results = run(&lib, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].1,
            "foo-devel: E: no-library-dependency-on libfoo /usr/lib64/libfoo.so.1"
        );
    }

    #[test]
    fn chained_symlink_resolves_to_real_library() {
        // Imath layout: `libfoo.so -> libfoo-1_2.so -> libfoo.so.1`, the
        // intermediate link shipped by the devel package itself. Resolving
        // the chain finds the real library, which the devel requires: no
        // finding. (Fails on the one-hop recording: `no-library-dependency-for`
        // on the intermediate link.)
        let mut lib = fixture_pkg();
        lib.name = "libfoo".to_string();
        lib.arch = "x86_64".to_string();
        lib.files = vec![regular("/usr/lib64/libfoo.so.1")];

        let mut devel = fixture_pkg();
        devel.name = "foo-devel".to_string();
        devel.arch = "x86_64".to_string();
        devel.requires = vec![require("libfoo")];
        devel.prereq = vec![];
        devel.files = vec![
            symlink("/usr/lib64/libfoo.so", "libfoo-1_2.so"),
            symlink("/usr/lib64/libfoo-1_2.so", "libfoo.so.1"),
        ];
        assert!(run(&lib, &devel).is_empty());
    }

    #[test]
    fn chained_symlink_still_checks_requires() {
        // The chain resolves, but the devel does not require the library
        // package: the requires check still fires.
        let mut lib = fixture_pkg();
        lib.name = "libfoo".to_string();
        lib.arch = "x86_64".to_string();
        lib.files = vec![regular("/usr/lib64/libfoo.so.1")];

        let mut devel = fixture_pkg();
        devel.name = "foo-devel".to_string();
        devel.arch = "x86_64".to_string();
        devel.requires = vec![require("unrelated")];
        devel.prereq = vec![];
        devel.files = vec![
            symlink("/usr/lib64/libfoo.so", "libfoo-1_2.so"),
            symlink("/usr/lib64/libfoo-1_2.so", "libfoo.so.1"),
        ];
        let results = run(&lib, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-on");
        assert_eq!(
            results[0].1,
            "foo-devel.x86_64: E: no-library-dependency-on libfoo /usr/lib64/libfoo.so.1"
        );
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

    #[test]
    fn cross_arch_packages_are_each_checked() {
        // plusky/rpmcrab#74: the reference keys its per-package maps on
        // `pkg.name` alone, so linting `foo-devel.x86_64` then
        // `foo-devel.aarch64` together overwrites the first entry — only
        // the last arch is ever checked. The port keys on `(name, arch)`,
        // so both arches must produce findings.
        let (lib, mut devel_x86) = lib_and_devel(&["unrelated".to_string()]);
        devel_x86.arch = "x86_64".to_string();
        let (_, mut devel_aarch64) = lib_and_devel(&["unrelated".to_string()]);
        devel_aarch64.arch = "aarch64".to_string();

        let results = run_pkgs(&[&lib, &devel_x86, &devel_aarch64]);
        assert_eq!(results.len(), 2, "both arches must be checked: {results:?}");
        assert_eq!(results[0].0, "no-library-dependency-on");
        assert_eq!(
            results[0].1,
            "foo-devel.x86_64: E: no-library-dependency-on libfoo /usr/lib64/libfoo.so.1"
        );
        assert_eq!(results[1].0, "no-library-dependency-on");
        assert_eq!(
            results[1].1,
            "foo-devel.aarch64: E: no-library-dependency-on libfoo /usr/lib64/libfoo.so.1"
        );
    }

    /// Export/import merges worker state in package order: two workers
    /// checking disjoint package sets, merged in order, must produce the same
    /// `after_checks` findings as one sequential run.
    #[test]
    fn export_import_merges_in_package_order() {
        let config = Config::default();
        let (lib0, devel0) = lib_and_devel_as("libdep0", "libdep0-devel", &[]);
        let (lib1, devel1) = lib_and_devel_as("libdep1", "libdep1-devel", &[]);

        // Sequential baseline.
        let mut seq = LibraryDependencyCheck::new(&config);
        let mut seq_out = Filter::new(&config, Color::for_tty(false)).unwrap();
        for pkg in [&lib0, &devel0, &lib1, &devel1] {
            seq.check_binary(pkg, &config, &mut seq_out);
            seq.reset();
        }
        seq.after_checks(&config, &mut seq_out);

        // Two workers, one package pair each, merged in package order.
        let mut w0 = LibraryDependencyCheck::new(&config);
        let mut w0_out = Filter::new(&config, Color::for_tty(false)).unwrap();
        for pkg in [&lib0, &devel0] {
            w0.check_binary(pkg, &config, &mut w0_out);
            w0.reset();
        }
        let s0 = w0.export_state().expect("worker 0 exports");
        let mut w1 = LibraryDependencyCheck::new(&config);
        let mut w1_out = Filter::new(&config, Color::for_tty(false)).unwrap();
        for pkg in [&lib1, &devel1] {
            w1.check_binary(pkg, &config, &mut w1_out);
            w1.reset();
        }
        let s1 = w1.export_state().expect("worker 1 exports");

        let mut main = LibraryDependencyCheck::new(&config);
        main.import_state(s0);
        main.import_state(s1);
        let mut main_out = Filter::new(&config, Color::for_tty(false)).unwrap();
        main.after_checks(&config, &mut main_out);

        assert_eq!(
            main_out.results(),
            seq_out.results(),
            "merged after_checks differs from sequential"
        );
    }

    #[test]
    fn dotdot_symlink_target_resolves_to_provided_library() {
        // glfw2 layout: the devel ships `/usr/lib64/glfw2/libglfw.so ->
        // ../libglfw.so.2.7.6` while the real file lives in the lib
        // package. Joining parent + target without normalising records
        // `/usr/lib64/glfw2/../libglfw.so.2.7.6`, which never matches the
        // provided path and misfires `no-library-dependency-for`.
        let mut lib = fixture_pkg();
        lib.name = "libglfw2".to_string();
        lib.arch = "x86_64".to_string();
        lib.files = vec![regular("/usr/lib64/libglfw.so.2.7.6")];

        let mut devel = fixture_pkg();
        devel.name = "glfw2-devel".to_string();
        devel.arch = "x86_64".to_string();
        devel.requires = vec![require("libglfw2")];
        devel.prereq = vec![];
        devel.files = vec![symlink(
            "/usr/lib64/glfw2/libglfw.so",
            "../libglfw.so.2.7.6",
        )];
        assert!(run(&lib, &devel).is_empty());
    }
}
