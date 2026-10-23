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
//!
//! The dependency verdict also credits the anchor chain inside the
//! scanned set (plusky/rpmcrab#863): when a devel package requires a
//! package built from the same source for its own arch — a `noarch`
//! sibling stands in when no same-arch build is in the run — pinned
//! with `=` to that sibling's own version, and the sibling's own
//! requirements name the
//! library package or one of its provides, the dependency on the
//! library exists through the sibling — installing the devel package
//! guarantees the library. The reference credits only a direct
//! requirement on the library package itself.

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
use crate::pkg::dep::DepInfo;
use crate::pkg::dep::DepLeaf;
use crate::pkg::dep::RPMSENSE_EQUAL;
use crate::pkg::dep::RPMSENSE_GREATER;
use crate::pkg::dep::RPMSENSE_LESS;
use crate::pkg::dep::is_rich_dep_expr;
use crate::pkg::dep::version_to_string;
use crate::pkg::pkgfile::is_symlink;

use librpm::Tag;

/// The reference reads `%{_isa}` from the running rpm's macros at
/// construction time (`LibraryDependencyCheck.py:17`); derive it the same
/// way through librpm instead of a hand-written table.
fn expand_isa() -> String {
    let _ = crate::pkg::init();
    let _macro_guard = crate::pkg::global_macro_lock();
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

/// The key two packages of one build share: the `SOURCERPM` header
/// value, falling back to the package name when it is absent (the
/// spelling `FilesCheck` uses for the same notion).
fn source_key(pkg: &Pkg) -> String {
    match pkg.tag_str(Tag::SOURCERPM) {
        Some(srpm) if !srpm.is_empty() => srpm,
        _ => pkg.name.clone(),
    }
}

/// The package names a requirement can anchor on: the name itself,
/// plus the stem when the name carries the running `%{_isa}`
/// qualifier — `akonadi(x86-64)` anchors on the `akonadi` package,
/// the way the direct credit's `definition + isa` arm names the
/// library package. Only the running isa is stripped: a foreign isa
/// qualifies a different architecture's package, and any other
/// parenthesised suffix is part of the name (a soname's `()(64bit)`,
/// a capability's argument).
fn anchor_names<'a>(name: &'a str, isa: &str) -> Vec<&'a str> {
    let mut names = vec![name];
    if !isa.is_empty()
        && let Some(stem) = name.strip_suffix(isa)
    {
        names.push(stem);
    }
    names
}

/// Whether a requirement leaf pins its target to the sibling's own
/// version: an `=` relation whose EVR is the sibling's version, its
/// version-release, or its full epoch:version-release — the spellings
/// the distro's exact-version anchor convention takes (measured on
/// the Factory corpus for plusky/rpmcrab#863: 77 pins to the version,
/// 12 to the version-release, of 89 credited chains).
fn pin_matches(leaf: &DepLeaf, sib: &PkgSnapshot) -> bool {
    // The exact pin only: a floor or ceiling whose bound happens to
    // equal the sibling's version is a range, not the anchor
    // convention.
    if leaf.flags & (RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL) != RPMSENSE_EQUAL
        || leaf.version.is_none()
    {
        return false;
    }
    let evr = version_to_string(leaf.epoch, leaf.version.as_deref(), leaf.release.as_deref());
    evr == sib.version || evr == sib.version_release || evr == sib.evr
}

/// What the anchor-chain credit needs of one package of the run
/// (plusky/rpmcrab#863): the source it was built from, its own EVR in
/// the spellings a pin can take, its requirement list and its provide
/// names.
struct PkgSnapshot {
    source: String,
    version: String,
    version_release: String,
    evr: String,
    requires: Vec<DepInfo>,
    provides: Vec<String>,
}

impl PkgSnapshot {
    fn snapshot(pkg: &Pkg) -> Self {
        let version = pkg.tag_str(Tag::VERSION).unwrap_or_default();
        let release = pkg.tag_str(Tag::RELEASE).unwrap_or_default();
        let epoch = pkg.tag_i64(Tag::EPOCH);
        Self {
            source: source_key(pkg),
            version_release: version_to_string(None, Some(&version), Some(&release)),
            evr: version_to_string(epoch, Some(&version), Some(&release)),
            version,
            requires: pkg
                .requires
                .iter()
                .chain(pkg.prereq.iter())
                .cloned()
                .collect(),
            provides: pkg.provides.iter().map(|d| d.name.clone()).collect(),
        }
    }
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
    package_so_files: HashMap<String, (String, String)>,
    /// Per-package snapshots for the anchor-chain credit
    /// (plusky/rpmcrab#863), keyed like the devel maps.
    package_snapshots: HashMap<(String, String), PkgSnapshot>,
    isa: String,
}

/// Cross-package state, exported per package and merged before
/// `after_checks` (`rpmlint#1595`). `devel_order` travels too: the reference
/// iterates a plain dict (insertion order), which the port pins via this
/// vector.
struct LibDepState {
    package_requires: HashMap<(String, String), Vec<String>>,
    package_so_symlinks: HashMap<(String, String), Vec<String>>,
    package_so_files: HashMap<String, (String, String)>,
    package_snapshots: HashMap<(String, String), PkgSnapshot>,
    devel_order: Vec<(String, String)>,
}

impl LibraryDependencyCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            package_requires: HashMap::new(),
            package_so_symlinks: HashMap::new(),
            devel_order: Vec::new(),
            package_so_files: HashMap::new(),
            package_snapshots: HashMap::new(),
            isa: expand_isa(),
        }
    }

    fn is_devel_pkg(name: &str) -> bool {
        is_match(devel_regex(), name)
    }

    /// Whether the anchor chain credits the devel package `devel`
    /// with a dependency on the library package `definition`
    /// (plusky/rpmcrab#863): one of the devel package's requirements
    /// names a package of the run built from the devel's source
    /// for the devel's own arch, pinned with `=` to that sibling's
    /// own version, and the sibling's own plain requirements name the
    /// library package, its isa-qualified spelling, or one of
    /// its provides. Rich (`or`/`if`) requirements take no part on
    /// either hop: their leaves are alternatives and conditions, not
    /// guarantees. The credit is exactly one hop: a requirement on
    /// the devel package itself or on the library package is the
    /// direct credit's business, an unpinned or differently pinned
    /// requirement guarantees no particular sibling build, and a
    /// sibling whose requirements reach nothing of the library's
    /// leaves the chain broken, which is the finding's real target.
    /// The lookup is keyed on `(name, arch)` like the devel maps
    /// (plusky/rpmcrab#74): a sibling built for another arch credits
    /// nothing — its requires are not the ones the devel package's
    /// installation pulls in — and a `noarch` sibling stands in only
    /// when the run carries no same-arch build of the anchor name.
    /// The library's provides are read from the build that ships
    /// the linked file — the build `definition` and its arch name.
    fn chain_credits(
        &self,
        devel: &(String, String),
        definition: &str,
        definition_arch: &str,
        snapshots_by_key: &HashMap<(&str, &str), &PkgSnapshot>,
    ) -> bool {
        let Some(dev) = self.package_snapshots.get(devel) else {
            return false;
        };
        let Some(lib) = snapshots_by_key.get(&(definition, definition_arch)) else {
            return false;
        };
        let isa_name = format!("{definition}{}", self.isa);
        let mut lib_names: Vec<&str> = vec![definition, isa_name.as_str()];
        lib_names.extend(lib.provides.iter().map(String::as_str));
        // The sibling is the anchor name's build for the devel
        // package's own arch; a `noarch` build stands in when the
        // run carries no same-arch build of the name.
        let sibling = |target: &str| -> Option<&PkgSnapshot> {
            snapshots_by_key
                .get(&(target, devel.1.as_str()))
                .copied()
                .or_else(|| snapshots_by_key.get(&(target, "noarch")).copied())
        };
        dev.requires
            .iter()
            .filter(|d| !is_rich_dep_expr(&d.name))
            .flat_map(|d| d.leaves())
            .any(|leaf| {
                anchor_names(&leaf.name, &self.isa).iter().any(|target| {
                    *target != devel.0
                        && *target != definition
                        && sibling(target).is_some_and(|sib| {
                            sib.source == dev.source
                                && pin_matches(&leaf, sib)
                                && sib
                                    .requires
                                    .iter()
                                    .filter(|d| !is_rich_dep_expr(&d.name))
                                    .flat_map(|d| d.leaves())
                                    .any(|sib_leaf| lib_names.contains(&sib_leaf.name.as_str()))
                        })
                })
            })
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
        self.package_snapshots.clear();
        self.isa = expand_isa();
    }

    fn export_state(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        let state = LibDepState {
            package_requires: std::mem::take(&mut self.package_requires),
            package_so_symlinks: std::mem::take(&mut self.package_so_symlinks),
            package_so_files: std::mem::take(&mut self.package_so_files),
            package_snapshots: std::mem::take(&mut self.package_snapshots),
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
            self.package_snapshots.extend(state.package_snapshots);
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

        // Every package of the run is snapshotted: the anchor-chain
        // credit (plusky/rpmcrab#863) reads the devel package's
        // siblings and the library package's provides in
        // `after_checks`, whichever side of the devel split a package
        // falls on.
        self.package_snapshots.insert(
            (pkg.name.clone(), pkg.arch.clone()),
            PkgSnapshot::snapshot(pkg),
        );

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
                        .insert(pkgfile.name.clone(), (pkg.name.clone(), pkg.arch.clone()));
                }
            }
        }
    }

    fn after_checks(&mut self, _config: &Config, out: &mut Filter) {
        // The run's snapshots by (name, arch), for the anchor-chain
        // credit: the devel maps are keyed the same way
        // (plusky/rpmcrab#74), so a build of another arch — whose
        // requires and provides differ — never credits this arch.
        let mut snapshots_by_key: HashMap<(&str, &str), &PkgSnapshot> = HashMap::new();
        for ((name, arch), snap) in &self.package_snapshots {
            snapshots_by_key.insert((name.as_str(), arch.as_str()), snap);
        }
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
                if let Some((definition, definition_arch)) = self.package_so_files.get(link) {
                    // `definition` is the *package* name, not a soname
                    // (`LibraryDependencyCheck.py:49`), so `definition + isa`
                    // matches nothing rpm generates; dead in the reference
                    // as well, kept faithful.
                    let with_isa = format!("{definition}{}", self.isa);
                    if !requires.iter().any(|r| r == definition || r == &with_isa)
                        && !self.chain_credits(&key, definition, definition_arch, &snapshots_by_key)
                    {
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
                        Level::Warning,
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

    /// A requirement pinned with `=` to `version` (the anchor
    /// convention of plusky/rpmcrab#863).
    fn require_pinned(name: &str, version: &str) -> DepInfo {
        DepInfo {
            name: name.to_string(),
            flags: RPMSENSE_EQUAL,
            epoch: None,
            version: Some(version.to_string()),
            release: None,
        }
    }

    /// A requirement pinned with `=` to a full version-release.
    fn require_pinned_release(name: &str, version: &str, release: &str) -> DepInfo {
        DepInfo {
            name: name.to_string(),
            flags: RPMSENSE_EQUAL,
            epoch: None,
            version: Some(version.to_string()),
            release: Some(release.to_string()),
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
        // Scoped to the expansion only: `LibraryDependencyCheck::new`
        // below expands the same macro under the same lock, which is
        // not re-entrant.
        let expected = {
            let _macro_guard = crate::pkg::global_macro_lock();
            librpm::macro_context::MacroContext::default()
                .expand("%{_isa}")
                .unwrap_or_default()
        };
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
        assert!(line.contains(": W: "), "level: {line}");
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

        // Sequential baseline: state accumulates across packages (no reset
        // between `check_binary` calls), so `after_checks` sees both devel
        // packages.
        let mut seq = LibraryDependencyCheck::new(&config);
        let mut seq_out = Filter::new(&config, Color::for_tty(false)).unwrap();
        for pkg in [&lib0, &devel0, &lib1, &devel1] {
            seq.check_binary(pkg, &config, &mut seq_out);
        }
        seq.after_checks(&config, &mut seq_out);

        // Neither devel package depends on its library, so the baseline is
        // one `no-library-dependency-on` finding per devel package, in
        // package order — the result the merged run must reproduce.
        let seq_results = seq_out.results();
        assert_eq!(seq_results.len(), 2, "{seq_results:?}");
        assert_eq!(seq_results[0].0, "no-library-dependency-on");
        assert!(
            seq_results[0].1.starts_with("libdep0-devel.x86_64:"),
            "first finding out of package order: {}",
            seq_results[0].1
        );
        assert_eq!(seq_results[1].0, "no-library-dependency-on");
        assert!(
            seq_results[1].1.starts_with("libdep1-devel.x86_64:"),
            "second finding out of package order: {}",
            seq_results[1].1
        );

        // Two workers, one package pair each, merged in package order.
        // Production order is check → export → reset, and `export_state`
        // takes the accumulated state, so the export must come first.
        let mut w0 = LibraryDependencyCheck::new(&config);
        let mut w0_out = Filter::new(&config, Color::for_tty(false)).unwrap();
        for pkg in [&lib0, &devel0] {
            w0.check_binary(pkg, &config, &mut w0_out);
        }
        let s0 = w0.export_state().expect("worker 0 exports");
        let mut w1 = LibraryDependencyCheck::new(&config);
        let mut w1_out = Filter::new(&config, Color::for_tty(false)).unwrap();
        for pkg in [&lib1, &devel1] {
            w1.check_binary(pkg, &config, &mut w1_out);
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
        let findings = run(&lib, &devel);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn reset_drops_prior_packages() {
        let config = Config::default();
        let mut check = LibraryDependencyCheck::new(&config);
        let (leak_lib, leak_devel) =
            lib_and_devel_as("libleak", "libleak-devel", &["unrelated".to_string()]);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(&leak_lib, &config, &mut out);
        check.check_binary(&leak_devel, &config, &mut out);
        check.reset();
        let (clean_lib, clean_devel) =
            lib_and_devel_as("libclean", "libclean-devel", &["libclean".to_string()]);
        let mut clean_out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(&clean_lib, &config, &mut clean_out);
        check.check_binary(&clean_devel, &config, &mut clean_out);
        check.after_checks(&config, &mut clean_out);
        assert!(
            clean_out.results().is_empty(),
            "leaked state across reset: {:?}",
            clean_out.results()
        );
    }

    #[test]
    fn import_state_round_trips_worker_state() {
        let config = Config::default();
        let (lib, devel) = lib_and_devel(&["unrelated".to_string()]);
        let mut worker = LibraryDependencyCheck::new(&config);
        let mut worker_out = Filter::new(&config, Color::for_tty(false)).unwrap();
        worker.check_binary(&lib, &config, &mut worker_out);
        worker.check_binary(&devel, &config, &mut worker_out);
        let state = worker.export_state().expect("exports state");
        let mut main = LibraryDependencyCheck::new(&config);
        main.import_state(state);
        let mut main_out = Filter::new(&config, Color::for_tty(false)).unwrap();
        main.after_checks(&config, &mut main_out);
        assert_eq!(main_out.results().len(), 1, "{:?}", main_out.results());
        assert_eq!(main_out.results()[0].0, "no-library-dependency-on");
    }

    /// The trio of plusky/rpmcrab#863: the library package `libfoo`
    /// shipping the real library and providing its soname, the anchor
    /// sibling `foo`, and `foo-devel` shipping the `.so` symlink. All
    /// three are built from the one fixture, so they share a
    /// `SOURCERPM`; the fixture's version is `1`, its release `1`.
    fn anchor_trio(anchor_requires: &[DepInfo], devel_requires: &[DepInfo]) -> (Pkg, Pkg, Pkg) {
        anchor_trio_arches(anchor_requires, devel_requires, "x86_64", "x86_64")
    }

    /// The anchor trio with the anchor's arch chosen by the caller
    /// and the library built for the devel package's arch: the
    /// anchor-chain credit is keyed on `(name, arch)`, so which arch
    /// the anchor carries is part of what the pins pin.
    fn anchor_trio_arches(
        anchor_requires: &[DepInfo],
        devel_requires: &[DepInfo],
        anchor_arch: &str,
        devel_arch: &str,
    ) -> (Pkg, Pkg, Pkg) {
        let mut lib = fixture_pkg();
        lib.name = "libfoo".to_string();
        lib.arch = devel_arch.to_string();
        lib.files = vec![regular("/usr/lib64/libfoo.so.1")];
        lib.provides = vec![require("libfoo.so.1()(64bit)")];

        let mut anchor = fixture_pkg();
        anchor.name = "foo".to_string();
        anchor.arch = anchor_arch.to_string();
        anchor.requires = anchor_requires.to_vec();
        anchor.prereq = vec![];
        anchor.files = vec![];

        let mut devel = fixture_pkg();
        devel.name = "foo-devel".to_string();
        devel.arch = devel_arch.to_string();
        devel.requires = devel_requires.to_vec();
        devel.prereq = vec![];
        devel.files = vec![symlink("/usr/lib64/libfoo.so", "libfoo.so.1")];
        (lib, anchor, devel)
    }

    fn run_trio(lib: &Pkg, anchor: &Pkg, devel: &Pkg) -> Vec<(String, String)> {
        run_pkgs(&[lib, anchor, devel])
    }

    #[test]
    fn anchor_chain_credits_devel_package() {
        // akonadi's shape: the devel anchors on the main package at
        // its exact version, and the main package's own requirements
        // name the library's soname — the dependency on the library
        // exists through the anchor.
        let (lib, anchor, devel) = anchor_trio(
            &[require("libfoo.so.1()(64bit)")],
            &[require_pinned("foo", "1")],
        );
        assert!(run_trio(&lib, &anchor, &devel).is_empty());
    }

    #[test]
    fn anchor_chain_version_release_pin_credits() {
        // The pin's other measured spelling: `=` to the sibling's
        // full version-release.
        let (lib, anchor, devel) = anchor_trio(
            &[require("libfoo.so.1()(64bit)")],
            &[require_pinned_release("foo", "1", "1")],
        );
        assert!(run_trio(&lib, &anchor, &devel).is_empty());
    }

    #[test]
    fn anchor_chain_isa_qualified_anchor_credits() {
        // The anchor named with the running isa qualifier, the
        // spelling a handful of the measured chains take
        // (rocm-clang-devel and rocm-llvm-devel on their sibling libs
        // packages).
        let config = Config::default();
        let isa = LibraryDependencyCheck::new(&config).isa.clone();
        let (lib, anchor, devel) = anchor_trio(
            &[require("libfoo.so.1()(64bit)")],
            &[require_pinned(&format!("foo{isa}"), "1")],
        );
        assert!(run_trio(&lib, &anchor, &devel).is_empty());
    }

    #[test]
    fn anchor_chain_foreign_isa_anchor_still_fires() {
        // Only the running isa is stripped: a pin on the anchor's
        // foreign-isa spelling qualifies another architecture's
        // package, so the name anchors on nothing in this run.
        let config = Config::default();
        let isa = LibraryDependencyCheck::new(&config).isa.clone();
        let foreign = if isa == "(x86-64)" {
            "(aarch-64)"
        } else {
            "(x86-64)"
        };
        let (lib, anchor, devel) = anchor_trio(
            &[require("libfoo.so.1()(64bit)")],
            &[require_pinned(&format!("foo{foreign}"), "1")],
        );
        let results = run_trio(&lib, &anchor, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-on");
    }

    #[test]
    fn anchor_chain_isa_qualified_library_name_credits() {
        // The sibling can reach the library by its isa-qualified
        // package name, the spelling the direct credit's
        // `definition + isa` arm accepts.
        let config = Config::default();
        let isa = LibraryDependencyCheck::new(&config).isa.clone();
        let (lib, anchor, devel) = anchor_trio(
            &[require(&format!("libfoo{isa}"))],
            &[require_pinned("foo", "1")],
        );
        assert!(run_trio(&lib, &anchor, &devel).is_empty());
    }

    #[test]
    fn anchor_chain_rich_requirements_do_not_credit() {
        // A rich requirement's leaves are alternatives and conditions,
        // not guarantees: on the devel hop the pinned anchor inside an
        // `or` credits nothing, and on the sibling hop the library
        // name inside an `or` reaches nothing.
        let (lib, anchor, devel) = anchor_trio(
            &[require("libfoo.so.1()(64bit)")],
            &[require("(foo = 1 or baz)")],
        );
        let results = run_trio(&lib, &anchor, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-on");

        let (lib, anchor, devel) = anchor_trio(
            &[require("(libfoo.so.1()(64bit) or libother.so.9()(64bit))")],
            &[require_pinned("foo", "1")],
        );
        let results = run_trio(&lib, &anchor, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-on");
    }

    #[test]
    fn anchor_chain_library_name_reach_credits() {
        // The sibling can equally reach the library by the library
        // package's own name rather than its soname provide.
        let (lib, anchor, devel) = anchor_trio(&[require("libfoo")], &[require_pinned("foo", "1")]);
        assert!(run_trio(&lib, &anchor, &devel).is_empty());
    }

    #[test]
    fn anchor_without_reach_still_fires() {
        // The anchor's requirements reach a different library, not
        // this one: the chain is broken and the finding is the point.
        // (liburing-devel on liburing-ffi in the corpus: the anchor
        // reaches the main library, the FFI library nothing reaches.)
        let (lib, anchor, devel) = anchor_trio(
            &[require("libother.so.9()(64bit)")],
            &[require_pinned("foo", "1")],
        );
        let results = run_trio(&lib, &anchor, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-on");
        assert_eq!(
            results[0].1,
            "foo-devel.x86_64: E: no-library-dependency-on libfoo /usr/lib64/libfoo.so.1"
        );
    }

    #[test]
    fn anchor_unversioned_still_fires() {
        // An unpinned requirement on the sibling guarantees no
        // particular build of it, so it is not the anchor convention
        // and credits nothing (the toluapp and libaom shapes in the
        // corpus stay charged).
        let (lib, anchor, devel) =
            anchor_trio(&[require("libfoo.so.1()(64bit)")], &[require("foo")]);
        let results = run_trio(&lib, &anchor, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-on");
    }

    #[test]
    fn anchor_wrong_version_still_fires() {
        // A pin to a version the sibling does not carry is not a pin
        // to the co-built sibling.
        let (lib, anchor, devel) = anchor_trio(
            &[require("libfoo.so.1()(64bit)")],
            &[require_pinned("foo", "2")],
        );
        let results = run_trio(&lib, &anchor, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-on");
    }

    #[test]
    fn anchor_floor_pin_still_fires() {
        // A `>=` floor at the sibling's version is a range, not the
        // exact pin: it admits other builds of the sibling.
        let floor = DepInfo {
            name: "foo".to_string(),
            flags: RPMSENSE_EQUAL | RPMSENSE_GREATER,
            epoch: None,
            version: Some("1".to_string()),
            release: None,
        };
        let (lib, anchor, devel) = anchor_trio(&[require("libfoo.so.1()(64bit)")], &[floor]);
        let results = run_trio(&lib, &anchor, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-on");
    }

    #[test]
    fn anchor_other_source_still_fires() {
        // The anchor must be a sibling: a requirement on a package of
        // another source that reaches the library credits nothing,
        // or transitive credit would gut the check.
        let (lib, _, devel) = anchor_trio(
            &[require("libfoo.so.1()(64bit)")],
            &[require_pinned("foo", "1.0")],
        );
        // A fixture built from a different spec: its SOURCERPM
        // differs from the shared fixture's, so it is another source.
        // Its version is 1.0, which the devel's pin matches — only
        // the source condition rejects the credit.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/nodoc-lone-1.0-1.noarch.rpm");
        let mut anchor = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        anchor.name = "foo".to_string();
        anchor.arch = "x86_64".to_string();
        anchor.requires = vec![require("libfoo.so.1()(64bit)")];
        anchor.prereq = vec![];
        anchor.files = vec![];
        let results = run_trio(&lib, &anchor, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-on");
    }

    #[test]
    fn self_anchor_still_fires() {
        // A requirement on the devel package itself is no anchor,
        // even with a reaching sibling standing next to it.
        let (lib, anchor, devel) = anchor_trio(
            &[require("libfoo.so.1()(64bit)")],
            &[require_pinned("foo-devel", "1")],
        );
        let results = run_trio(&lib, &anchor, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-on");
    }

    #[test]
    fn anchor_matching_arch_credits() {
        // The same chain on a non-default arch pair: the credit
        // follows arch equality, not one hardcoded arch.
        let (lib, anchor, devel) = anchor_trio_arches(
            &[require("libfoo.so.1()(64bit)")],
            &[require_pinned("foo", "1")],
            "aarch64",
            "aarch64",
        );
        assert!(run_trio(&lib, &anchor, &devel).is_empty());
    }

    #[test]
    fn anchor_cross_arch_still_fires() {
        // A sibling built for another arch credits nothing: the
        // `foo.i586` build's requirements are not what installing
        // `foo-devel.x86_64` pulls in, however exactly the devel
        // package pins the name.
        let (lib, anchor, devel) = anchor_trio_arches(
            &[require("libfoo.so.1()(64bit)")],
            &[require_pinned("foo", "1")],
            "i586",
            "x86_64",
        );
        let results = run_trio(&lib, &anchor, &devel);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-on");
        assert_eq!(
            results[0].1,
            "foo-devel.x86_64: E: no-library-dependency-on libfoo /usr/lib64/libfoo.so.1"
        );
    }

    #[test]
    fn anchor_noarch_fallback_credits() {
        // A `noarch` sibling stands in for the arch build: it is
        // the build the devel package's installation pulls in on
        // any arch.
        let (lib, anchor, devel) = anchor_trio_arches(
            &[require("libfoo.so.1()(64bit)")],
            &[require_pinned("foo", "1")],
            "noarch",
            "x86_64",
        );
        assert!(run_trio(&lib, &anchor, &devel).is_empty());
    }

    #[test]
    fn anchor_reach_via_other_arch_lib_provides_still_fires() {
        // The library's provides are read from the build that ships
        // the linked file: a same-named build for another arch
        // providing the soname the anchor requires credits nothing —
        // that build is not the library package of this run's link.
        let (mut lib, anchor, devel) = anchor_trio(
            &[require("libfoo.so.1()(64bit)")],
            &[require_pinned("foo", "1")],
        );
        lib.provides = vec![];
        let mut lib_other_arch = fixture_pkg();
        lib_other_arch.name = "libfoo".to_string();
        lib_other_arch.arch = "i586".to_string();
        lib_other_arch.files = vec![];
        lib_other_arch.provides = vec![require("libfoo.so.1()(64bit)")];
        let results = run_pkgs(&[&lib, &lib_other_arch, &anchor, &devel]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "no-library-dependency-on");
    }

    #[test]
    fn anchor_chain_survives_export_import() {
        // The snapshots travel with the exported state: a worker that
        // saw the library and the anchor and a worker that saw the
        // devel package merge into a run that credits the chain.
        let config = Config::default();
        let (lib, anchor, devel) = anchor_trio(
            &[require("libfoo.so.1()(64bit)")],
            &[require_pinned("foo", "1")],
        );
        let mut w0 = LibraryDependencyCheck::new(&config);
        let mut w0_out = Filter::new(&config, Color::for_tty(false)).unwrap();
        for pkg in [&lib, &anchor] {
            w0.check_binary(pkg, &config, &mut w0_out);
        }
        let s0 = w0.export_state().expect("worker 0 exports");
        let mut w1 = LibraryDependencyCheck::new(&config);
        let mut w1_out = Filter::new(&config, Color::for_tty(false)).unwrap();
        w1.check_binary(&devel, &config, &mut w1_out);
        let s1 = w1.export_state().expect("worker 1 exports");

        let mut main = LibraryDependencyCheck::new(&config);
        main.import_state(s0);
        main.import_state(s1);
        let mut main_out = Filter::new(&config, Color::for_tty(false)).unwrap();
        main.after_checks(&config, &mut main_out);
        assert!(
            main_out.results().is_empty(),
            "chain lost across export/import: {:?}",
            main_out.results()
        );
    }
}
