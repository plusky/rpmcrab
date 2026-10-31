//! `SharedLibraryPolicyCheck` — shared library packaging policy.
//!
//! Ported from `rpmlint/checks/SharedLibraryPolicyCheck.py`. Findings:
//! `shlib-policy-missing-lib`, `readelf-failed`, `shlib-unversioned-lib`,
//! `shlib-fixed-dependency`, `shlib-policy-excessive-dependency`,
//! `shlib-policy-obsoletes-sibling`, `shlib-policy-etc-payload`,
//! `shlib-policy-truncated-soname-path`.
//!
//! One deliberate divergence in an existing finding:
//! `shlib-policy-excessive-dependency` is not charged for a SONAME that
//! no file in the package links against when one of the shipped library
//! files imports the dynamic loader and embeds that exact SONAME - the
//! dlopen-shim shape (a library reimplementing another and loading it by
//! name at runtime, e.g. sdl2-compat, libusb-compat). The reference
//! charges it: its walk collects only DT_NEEDED entries, so a runtime
//! load is invisible to it. See the ledger entry.
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
//! sibling's own name or one of its `lib`-prefixed non-SONAME provides
//! names — with a version relation. SONAME provides (`libfoo.so.1()(64bit)`) never count:
//! they are the automatic file dependencies, not the package pairing.
//! Sibling candidates are grouped by their normalised base: the base
//! package and its `-32bit`/`-64bit` flavours (`libfoo1`,
//! `libfoo1-32bit`) form one group, a versioned require naming any member
//! satisfies the whole group (a `-devel` package must not be made to drag
//! in the 32-bit flavour), and the check emits at most one finding per
//! (`-devel`, group), naming the group's canonical base name.
//! Rich (boolean) requires are read through their leaves: a leaf naming the
//! sibling with a version relation satisfies the rule, a bare leaf does not.
//!
//! `shlib-fixed-dependency` is likewise deferred: a versioned library
//! package pinning a dependency at `=` is version lockstep, not a policy
//! violation, when the pinned name resolves within the run to a package
//! built from the same source RPM. `check_binary` captures each candidate
//! and `after_checks` resolves it against the run's provider index (exact
//! name, then provides — which also covers arch-qualified names like
//! `libdnf5_2(x86-64)` and virtuals like `gio-branding`); a candidate with
//! no provider in the run, or no same-source provider, still fires, so
//! single-package runs are unchanged.

use std::collections::{HashMap, HashSet};

use fancy_regex::Regex;

use crate::check::{Check, add_info, make_finding};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::dep::DepInfo;
use crate::pkg::pkgfile::{is_dir, is_symlink};

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
    re_devel_flavoured: Regex,
    re_qlogging_categories: Regex,
    seen: Vec<SeenPkg>,
    /// Index of `seen` by (name, arch, source), for the dedup in
    /// `record_seen`.
    seen_index: HashMap<(String, String, Option<String>), usize>,
    /// `shlib-fixed-dependency` candidates awaiting lockstep resolution
    /// in `after_checks`, in capture order.
    fixed_dep_candidates: Vec<FixedDepCandidate>,
    /// `shlib-policy-etc-payload` candidates awaiting materialisation
    /// resolution in `after_checks`, in capture order.
    etc_payload_candidates: Vec<EtcPayloadCandidate>,
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

/// One `shlib-fixed-dependency` candidate, captured during `check_binary`
/// and resolved in `after_checks`: the finding's package, the pinned
/// dependency name, and the already-formatted detail. Emission is deferred
/// (not decided at check time) because same-source lockstep is only visible
/// once the whole run's packages are seen.
struct FixedDepCandidate {
    pkg_name: String,
    pkg_arch: String,
    source_rpm: Option<String>,
    dep_name: String,
    detail: String,
}

/// One `shlib-policy-etc-payload` candidate, captured during
/// `check_binary` and resolved in `after_checks`: the finding's
/// package, the SONAME stem and number (bitness normalised away, as
/// in the obsoletes-sibling arm), and the /etc or /usr/etc path.
/// Emission is deferred (not decided at check time) because the
/// conflict materialises only when a sibling generation ships the
/// same path, which is visible only once the whole run's packages
/// are seen.
struct EtcPayloadCandidate {
    pkg_name: String,
    pkg_arch: String,
    stem: String,
    number: String,
    path: String,
}

/// Cross-package state, exported per package and merged before
/// `after_checks`: the `-devel` pairing records plus the fixed-dependency
/// candidates awaiting lockstep resolution.
struct DevelPairingState {
    seen: Vec<SeenPkg>,
    fixed_dep_candidates: Vec<FixedDepCandidate>,
    etc_payload_candidates: Vec<EtcPayloadCandidate>,
}

/// Whether a dependency name is a virtual capability rather than a
/// package reference: RPM package names never contain `(`, so a
/// parenthesised name is a capability (`python(abi)`,
/// `typelib(GIRepository)`) unless it is the reference's
/// `name(arch-bits)` shape (`libdnf5_2(x86-64)`), which still names a
/// package.
fn dep_is_virtual_capability(name: &str) -> bool {
    let Some((_, inner)) = name.split_once('(') else {
        return false;
    };
    let Some(inner) = inner.strip_suffix(')') else {
        return true;
    };
    let Some((arch, bits)) = inner.split_once('-') else {
        return true;
    };
    arch.is_empty()
        || !arch.chars().all(|c| c.is_alphanumeric() || c == '_')
        || bits.is_empty()
        || !bits.chars().all(|c| c.is_ascii_digit())
}

impl SharedLibraryPolicyCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            re_soname_strongly_versioned: Regex::new(r"-[\d\.]+\.so$").expect("static regex"),
            re_soname_pkg: Regex::new(r"^lib\S+(\d+(-(32|64)bit)?)$").expect("static regex"),
            // The version tail is dotted alphanumeric components whose
            // final component contains a digit, plus one optional
            // trailing `-<digits>` component: real SONAME spellings such
            // as `libLimeSuite.so.23.11-1`, `libSDL_bgi.so.suse9` and
            // `libcmark-gfm.so.0.29.0.gfm.13` are library files. A
            // word-only tail (`libfoo.so.readme`) or a script name
            // embedding a version (`libstdc++.so.6.0.32-gdb.py`) is not.
            re_so_files: Regex::new(
                r"\S+.so((\.[0-9A-Za-z]+)*\.[0-9A-Za-z]*\d[0-9A-Za-z]*(-\d+)?)?$",
            )
            .expect("static regex"),
            re_versioned_so_file: Regex::new(r"\.so\.\d").expect("static regex"),
            // A `-devel` package in baselibs flavour dress carries the
            // micro-architecture flavour after the `-devel` component:
            // `libgcrypt-devel-x86-64-v3`.
            re_devel_flavoured: Regex::new(r"-devel-x86-64-v\d+$").expect("static regex"),
            // A Qt logging-categories data file in its standard
            // location: `/usr/share/qlogging-categories6/libkdcraw.categories`.
            re_qlogging_categories: Regex::new(
                r"^/usr/share/qlogging-categories\d+/[^/]+\.categories$",
            )
            .expect("static regex"),
            seen: Vec::new(),
            seen_index: HashMap::new(),
            fixed_dep_candidates: Vec::new(),
            etc_payload_candidates: Vec::new(),
        }
    }

    fn record(&mut self, pkg: &Pkg) {
        // The cross-package reads are: a `-devel` package's requires (the
        // `-devel` pairing judges it) and every package's provides (the
        // fixed-dependency lockstep resolution matches a pinned name
        // against the run's providers, including virtuals and
        // arch-qualified names). No other package's lists are ever read,
        // so they are not cloned.
        let is_devel = self.is_devel_package(&pkg.name);
        self.record_seen(SeenPkg {
            name: pkg.name.clone(),
            arch: pkg.arch.clone(),
            source_rpm: pkg.source_rpm.clone(),
            requires: if is_devel {
                pkg.requires
                    .iter()
                    .chain(pkg.prereq.iter())
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            },
            provides: pkg.provides.iter().map(|d| d.name.clone()).collect(),
            has_versioned_so: pkg
                .files
                .iter()
                .any(|f| f.name.contains(".so.") && is_match(&self.re_versioned_so_file, &f.name)),
        });
    }

    fn record_seen(&mut self, entry: SeenPkg) {
        // One entry per (name, arch, source): a repeated package replaces
        // its earlier record instead of pairing with itself twice.
        let key = (
            entry.name.clone(),
            entry.arch.clone(),
            entry.source_rpm.clone(),
        );
        if let Some(&idx) = self.seen_index.get(&key) {
            self.seen[idx] = entry;
        } else {
            self.seen_index.insert(key, self.seen.len());
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
        // The one scheme parser, shared with the obsoletes path: both
        // normalise identically, the number being the trailing digit
        // run with leading zeroes dropped (`libfoo01` groups as
        // `libfoo1`).
        soname_package_parts(&self.re_soname_pkg, shlib)
    }

    /// Whether the `-devel` package requires the sibling with a version
    /// relation, under the sibling's name or one of its `lib`-prefixed
    /// non-SONAME provides names. A bare name or a SONAME require does
    /// not satisfy the pairing.
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

    /// Whether the package ships a versioned shared library: a file
    /// named with a `.so.<number>` component that is a symlink or a
    /// regular ELF file. The name test alone is not sufficient — a
    /// regular non-ELF file can carry such a name without being a
    /// library (gcc's pretty-printer packages ship the gdb auto-load
    /// script `libstdc++.so.<version>-gdb.py` and no library at all).
    fn ships_versioned_library(&self, pkg: &Pkg) -> bool {
        pkg.files.iter().any(|f| {
            is_match(&self.re_versioned_so_file, &f.name)
                && (is_symlink(f.mode)
                    || (f.mode & S_IFMT == S_IFREG && f.magic.starts_with("ELF ")))
        })
    }

    /// Whether the name is a development package's: the plain
    /// `-devel` suffix, or `-devel` followed by a baselibs
    /// micro-architecture flavour (`libfoo1-devel-x86-64-v3`).
    /// A flavour tail with no `-devel` component, or any other tail
    /// after `-devel`, is not a development name.
    fn is_devel_package(&self, name: &str) -> bool {
        name.ends_with("-devel") || is_match(&self.re_devel_flavoured, name)
    }

    /// Whether the package's sole payload is a Qt logging-categories
    /// data file: the KDE categories-only split (`libkdcraw-qt6`
    /// ships only
    /// `/usr/share/qlogging-categories6/libkdcraw.categories`; the
    /// library itself ships under an unrelated name, e.g.
    /// `libKDcrawQt6-5`). Directory entries are not payload. Any
    /// further payload entry \— a second data file, a symlink, a
    /// script \— defeats the credit: the finding exists for
    /// scheme-named packages shipping no library, and only the pure
    /// data split is credited.
    fn sole_payload_is_qlogging_categories(&self, pkg: &Pkg) -> bool {
        let mut payload = pkg.files.iter().filter(|f| !is_dir(f.mode));
        let Some(only) = payload.next() else {
            return false;
        };
        // The entry itself must be a regular file the package actually
        // ships: a symlink to a categories file, or a %ghost categories
        // path, is not the data split this exemption describes.
        payload.next().is_none()
            && only.mode & S_IFMT == S_IFREG
            && !only.is_ghost()
            && is_match(&self.re_qlogging_categories, &only.name)
    }

    /// The scan behind `shlib-policy-truncated-soname-path`. A
    /// versioned library package ships the short path
    /// `<dir>/<stem>.so.<v>` next to the library whose SONAME is
    /// `<stem>.so.<w>`, with `w` starting with `v.`: harmless while
    /// this generation is the only one, but the sibling package for
    /// the next generation (a SONAME with the same `v` prefix and a
    /// different tail) ships the same short path, and the two
    /// co-installable packages conflict on it (mupdf's
    /// `libmupdf.so.28` shipped by both the .28.0 and the .28.1
    /// packages; hiredis's `libhiredis.so.1`). The conflict needs
    /// that co-installable sibling, which exists only when the
    /// package name changes along with the part of `w` after `v`,
    /// so the scan fires only when the package name encodes the
    /// whole of `w`: the `shlib-policy-name-error` name match,
    /// evaluated without that finding's hpc-location exemption. A
    /// package that upgrades in place (the MPI flavours of
    /// scalapack, whose names carry only the leading `2` of the
    /// SONAME `libscalapack.so.2.2.2`) never gains a sibling and
    /// stays quiet, as do extension paths (the shipped path extends
    /// the SONAME, not the reverse) and real files carrying an
    /// unrelated version (the CMake VERSION shape). `%ghost`
    /// entries are not shipped payload and stay quiet. The entry
    /// itself may be the library file (the libgda shape keeps the
    /// real file at the short name), so symlinks and regular files
    /// both count as candidates.
    fn check_truncated_soname_paths(&self, pkg: &Pkg, out: &mut Filter) {
        // SONAMEs shipped per directory, read from the regular ELF
        // files. A file that fails to parse contributes nothing:
        // the walk below reports it as `readelf-failed` when it is
        // library-named, and a file that fails to parse has no
        // observable SONAME either way.
        let mut sonames_by_dir: HashMap<&str, Vec<String>> = HashMap::new();
        for file in &pkg.files {
            if file.mode & S_IFMT != S_IFREG || !file.magic.starts_with("ELF ") {
                continue;
            }
            if !file.name.contains(".so.") && !file.name.ends_with(".so") {
                continue;
            }
            let Ok((Some(soname), _)) = Self::elf_dynamic(&file.path) else {
                continue;
            };
            let dir = match file.name.rfind('/') {
                Some(i) => &file.name[..i],
                None => "",
            };
            sonames_by_dir.entry(dir).or_default().push(soname);
        }
        if sonames_by_dir.is_empty() {
            return;
        }

        let mut hits: Vec<(&str, &str)> = Vec::new();
        for file in &pkg.files {
            if is_dir(file.mode) || file.is_ghost() {
                continue;
            }
            if !is_symlink(file.mode) && file.mode & S_IFMT != S_IFREG {
                continue;
            }
            let (dir, base) = match file.name.rfind('/') {
                Some(i) => (&file.name[..i], &file.name[i + 1..]),
                None => ("", file.name.as_str()),
            };
            let Some((stem, v)) = base.split_once(".so.") else {
                continue;
            };
            if !is_dotted_digits(v) {
                continue;
            }
            let Some(sonames) = sonames_by_dir.get(dir) else {
                continue;
            };
            // The prefix is the same for every SONAME in the
            // directory: format it once per file instead of once per
            // comparison.
            let version_prefix = format!("{v}.");
            for soname in sonames {
                let Some((soname_stem, w)) = soname.split_once(".so.") else {
                    continue;
                };
                if soname_stem != stem || !w.starts_with(&version_prefix) {
                    continue;
                }
                if crate::checks::binaries::soname_name_match(&pkg.name, soname)
                    .is_some_and(|(matches, _)| matches)
                {
                    hits.push((file.name.as_str(), soname.as_str()));
                }
            }
        }
        hits.sort_unstable();
        hits.dedup();
        for (path, soname) in hits {
            add_info(
                out,
                Level::Warning,
                pkg,
                "shlib-policy-truncated-soname-path",
                &[&format!("{path} (SONAME {soname})")],
            );
        }
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

    /// The dlopen-witness evidence for the library file at `path`,
    /// computed once and reused for every charged SONAME: whether it
    /// has an undefined, non-weak FUNC or NOTYPE `dlopen`/`dlmopen`
    /// import (a `@VERSION` suffix on the symbol name ignored, as
    /// elsewhere in this crate -- the crate's own import model in
    /// BinariesCheck: a weak import can be null at runtime and a
    /// defined symbol is not an import), plus its raw bytes for the
    /// name scan in `LoaderWitness::loads`. Any read or parse
    /// failure is a non-witness.
    fn loader_witness(path: &str) -> LoaderWitness {
        let non_witness = LoaderWitness {
            imports_loader: false,
            data: Vec::new(),
        };
        let Ok(data) = std::fs::read(path) else {
            return non_witness;
        };
        let Ok(elf) = crate::checks::binaries::parse_elf(&data) else {
            return non_witness;
        };
        let imports_loader = elf.dynsyms.iter().any(|sym| {
            sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize
                && sym.st_bind() != goblin::elf::sym::STB_WEAK
                && matches!(
                    sym.st_type(),
                    goblin::elf::sym::STT_FUNC | goblin::elf::sym::STT_NOTYPE
                )
                && elf.dynstrtab.get_at(sym.st_name).is_some_and(|name| {
                    let base = name.split('@').next().unwrap_or("");
                    base == "dlopen" || base == "dlmopen"
                })
        });
        LoaderWitness {
            imports_loader,
            data,
        }
    }
}

/// Dlopen-witness evidence for one shipped library file: see
/// `SharedLibraryPolicyCheck::loader_witness`.
struct LoaderWitness {
    imports_loader: bool,
    data: Vec<u8>,
}

impl LoaderWitness {
    /// Whether this file is evidence that the library loads `dep`
    /// at runtime: it imports the dynamic loader and its raw bytes
    /// contain `dep` as a complete string -- the name it hands to the
    /// loader. The delimiters are the boundary test (a leading NUL,
    /// or the start of the buffer, plus a trailing NUL): a
    /// longer name merely containing `dep` (`libbar.so.20` for
    /// `libbar.so.2`), or one glued to a preceding character
    /// (`Xlibbar.so.2`), is not the name being loaded.
    fn loads(&self, dep: &str) -> bool {
        if !self.imports_loader {
            return false;
        }
        let mut needle = Vec::with_capacity(dep.len() + 2);
        needle.push(0);
        needle.extend_from_slice(dep.as_bytes());
        needle.push(0);
        if self
            .data
            .windows(needle.len())
            .any(|w| w == needle.as_slice())
        {
            return true;
        }
        // The start of the buffer is the one other left boundary a raw
        // scan can decide: a name beginning at offset 0 and terminated
        // by a NUL is a complete string. Real ELF bytes never carry a
        // name there (the ELF magic occupies offset 0), so this arm is
        // inert on real files; it keeps the boundary rule exact for
        // the scan itself.
        let dep = dep.as_bytes();
        self.data.len() > dep.len() && self.data[..dep.len()] == *dep && self.data[dep.len()] == 0
    }
}

/// Whether `s` is a non-empty dotted sequence of digit components
/// (`28`, `0.25`, `2.2.2`): the shape of a SONAME version or of one
/// of its leading-component truncations.
fn is_dotted_digits(s: &str) -> bool {
    !s.is_empty()
        && s.split('.')
            .all(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()))
}

/// `(stem, SONAME number)` for a package name in the versioned shared
/// library scheme (`libfoo1`, `libfoo12-32bit`), or `None` for a name
/// outside the scheme. The `-32bit`/`-64bit` suffix is normalised away,
/// matching how the scheme pattern treats those forms: RPM `Obsoletes`
/// is arch-agnostic and the baselibs `-32bit` forms carry the host arch,
/// so an obsoletes in any bitness form removes the sibling generation
/// in every form. The number is the full trailing digit run with
/// leading zeroes dropped.
/// The name the devel pairing judges a package by: a baselibs flavour
/// tail (`-devel-x86-64-v3`) is dress on the plain `-devel` name, so a
/// flavoured devel package pairs as its plain base.
fn devel_pairing_name<'a>(re_flavoured: &Regex, name: &'a str) -> &'a str {
    if is_match(re_flavoured, name) {
        match name.rfind("-x86-64-") {
            Some(i) => &name[..i],
            None => name,
        }
    } else {
        name
    }
}

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
            || self.is_devel_package(&pkg.name)
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
        // The package must actually ship a versioned shared library:
        // a scheme-shaped name on a package with no library payload
        // (gcc's pretty-printer packages, `libstdc++6-pp-gcc<N>`, ship
        // only Python printer scripts) is not a SONAME generation, and
        // its obsoletes of other compiler-version packages do not
        // break any library co-installability. An empty obsoletes list
        // has nothing to judge, so the versioned-library scan is
        // skipped for it outright.
        if !pkg.obsoletes.is_empty()
            && let Some((stem, number)) = soname_package_parts(&self.re_soname_pkg, &pkg.name)
            && self.ships_versioned_library(pkg)
        {
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
        // non-directory, non-ghost entries are candidates. Two shapes stay quiet:
        // a scheme-shaped name on a package shipping no versioned
        // library is not a SONAME generation, and a file named after
        // the package itself (or its lib-stem) belongs to this
        // generation — the next generation's package has a different
        // name and ships a differently-named file.
        // The finding itself is deferred to `after_checks`: the
        // conflict the Warning describes materialises only when a
        // sibling SONAME generation ships the same path, which a
        // single package's payload cannot show. A lone generation
        // shipping /etc payload stays quiet.
        if is_match(&self.re_soname_pkg, &pkg.name)
            && self.ships_versioned_library(pkg)
            && let Some((stem, number)) = soname_package_parts(&self.re_soname_pkg, &pkg.name)
        {
            let mut etc_files: Vec<&str> = pkg
                .files
                .iter()
                .filter(|f| f.name.starts_with("/etc/") || f.name.starts_with("/usr/etc/"))
                .filter(|f| !is_dir(f.mode))
                .filter(|f| !f.is_ghost())
                .filter(|f| {
                    let base = f.name.rsplit('/').next().unwrap_or(f.name.as_str());
                    let stem = match base.rfind('.') {
                        Some(i) if i > 0 => &base[..i],
                        _ => base,
                    };
                    stem != pkg.name.as_str() && Some(stem) != pkg.name.strip_prefix("lib")
                })
                .map(|f| f.name.as_str())
                .collect();
            etc_files.sort_unstable();
            etc_files.dedup();
            for path in etc_files {
                self.etc_payload_candidates.push(EtcPayloadCandidate {
                    pkg_name: pkg.name.clone(),
                    pkg_arch: pkg.arch.clone(),
                    stem: stem.clone(),
                    number: number.clone(),
                    path: path.to_string(),
                });
            }
        }

        // A versioned path shorter than the SONAME of the library
        // it belongs to (see `check_truncated_soname_paths`).
        if is_match(&self.re_soname_pkg, &pkg.name) {
            self.check_truncated_soname_paths(pkg, out);
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
        // Paths of the walked library files, for the dlopen credit in
        // the excessive-dependency loop below.
        let mut lib_files: Vec<&str> = Vec::new();
        // DT_NEEDED of every ELF file in the package, library-named or
        // not: the link-time consumer set for the same credit. The
        // reference never computes this - it only walks library-named
        // files - so a parse failure here is never a readelf-failed
        // finding; it does mark the consumer set incomplete, which
        // withholds the dlopen credit below (the failed file's
        // DT_NEEDED entries are unobservable, so the absence the
        // credit requires cannot be shown). The library files' entries
        // are collected in the walk below; the non-library files are
        // only listed there and parsed after the walk, and only when a
        // charged candidate makes the consumer set matter at all.
        let mut all_needed: HashSet<String> = HashSet::new();
        let mut non_library_elf_paths: Vec<&str> = Vec::new();

        // The `shlib-policy-missing-lib` decision is taken after this
        // walk (issue #1029): a library-named file the walk reads as an
        // ELF carrying a DT_SONAME proves the package ships a library
        // even when its name fails the `re_so_files` file-name test (a
        // word-only version tail, e.g. `libfoo.so.beta`). A file the
        // walk cannot read counts as carrying no SONAME, and the walk
        // stops there, as it did when it returned early; the
        // `readelf-failed` finding is then emitted after the
        // missing-lib decision, in the order the two were emitted
        // before.
        let mut elf_carries_soname = false;
        let mut readelf_failed: Option<(&str, String)> = None;
        for file in &pkg.files {
            let fname = file.name.as_str();
            if file.mode & S_IFMT != S_IFREG {
                continue;
            }
            if !file.magic.starts_with("ELF ") {
                continue;
            }
            if !fname.contains(".so.") && !fname.ends_with(".so") {
                non_library_elf_paths.push(file.path.as_str());
                continue;
            }
            match Self::elf_dynamic(&file.path) {
                Err(reason) => {
                    // Record the failure and keep collecting later
                    // files: one unreadable file must not skip the
                    // rest of the package's libraries.
                    if readelf_failed.is_none() {
                        readelf_failed = Some((fname, reason));
                    }
                    continue;
                }
                Ok((soname, needed)) => {
                    lib_files.push(file.path.as_str());
                    all_needed.extend(needed.iter().cloned());
                    libs_needed.extend(needed);
                    if let Some(soname) = soname {
                        elf_carries_soname = true;
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

        // A policy-named package with no library files at all. The
        // one credited exception is the KDE categories-only split,
        // whose sole payload is a logging-categories data file (see
        // `sole_payload_is_qlogging_categories`).
        let has_lib_files = elf_carries_soname
            || pkg
                .files
                .iter()
                .any(|f| is_match(&self.re_so_files, &f.name));
        if !has_lib_files
            && is_match(&self.re_soname_pkg, &pkg.name)
            && !self.sole_payload_is_qlogging_categories(pkg)
        {
            add_info(out, Level::Error, pkg, "shlib-policy-missing-lib", &[]);
        }

        if let Some((fname, reason)) = readelf_failed {
            add_info(out, Level::Error, pkg, "readelf-failed", &[fname, &reason]);
            return;
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
                // A virtual capability pinned with `=` (`python(abi)`,
                // `typelib(GIRepository)`) is an ABI marker, not a fixed
                // version of another package: it names no package and
                // cannot break parallel installation of libraries.
                if dep_is_virtual_capability(&dep.name) {
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
                    // Deferred, not emitted: same-source lockstep is only
                    // visible once the whole run's packages are seen, so
                    // `after_checks` resolves the candidate against the
                    // run's provider index and emits only the survivors.
                    let detail = format!("{} {op} {}", dep.name, dep.evr_string());
                    self.fixed_dep_candidates.push(FixedDepCandidate {
                        pkg_name: pkg.name.clone(),
                        pkg_arch: pkg.arch.clone(),
                        source_rpm: pkg.source_rpm.clone(),
                        dep_name: dep.name.clone(),
                        detail,
                    });
                }
            }
        }

        // Non-lib stuff must not add dependencies. Sorted for the same reason
        // as above: one finding per dep, all sharing (check, level).
        if !libs.is_empty() {
            // The consumer set is complete only when every shipped
            // program parsed; it is computed here, not in the walk,
            // because it matters only when a charged candidate exists
            // (a required SONAME nothing links against).
            let mut consumer_set_incomplete = false;
            if pkg_requires.iter().any(|dep| {
                dep.contains(".so.") && !libs.contains(*dep) && !libs_needed.contains(*dep)
            }) {
                for path in &non_library_elf_paths {
                    match Self::elf_dynamic(path) {
                        Ok((_, needed)) => all_needed.extend(needed),
                        Err(_) => consumer_set_incomplete = true,
                    }
                }
            }
            // Witness evidence per shipped library file, computed
            // once here instead of re-reading and re-parsing every
            // library for every charged SONAME in the loop below.
            let witnesses: Vec<LoaderWitness> = lib_files
                .iter()
                .map(|path| Self::loader_witness(path))
                .collect();
            let mut deps_sorted: Vec<&str> = pkg_requires.iter().copied().collect();
            deps_sorted.sort_unstable();
            for dep in deps_sorted {
                if dep.contains(".so.") && !libs.contains(dep) && !libs_needed.contains(dep) {
                    // A dependency nothing in the package links against
                    // can still be the shipped library's own runtime
                    // dependency: a dlopen shim (sdl2-compat's libSDL2
                    // loading libSDL3, libusb-compat's libusb-0.1 loading
                    // libusb-1.0) reimplements one library on top of
                    // another and loads it by name at runtime, so the
                    // packager's explicit SONAME require is the library's
                    // real dependency, not an excessive one. Credit it
                    // only when the evidence is complete: every shipped
                    // program parsed (an unparsable one leaves the
                    // consumer set incomplete and withholds the
                    // credit), no file in the package has a DT_NEEDED
                    // entry for the name (a link-time consumer in a
                    // shipped program is the violation this check
                    // exists to report), and one of the shipped library
                    // files both imports the dynamic loader and embeds
                    // the exact name it loads.
                    if !consumer_set_incomplete
                        && !all_needed.contains(dep)
                        && witnesses.iter().any(|w| w.loads(dep))
                    {
                        continue;
                    }
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
        self.seen_index.clear();
        self.fixed_dep_candidates.clear();
        self.etc_payload_candidates.clear();
    }

    fn export_state(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        // The export-clears contract: the index goes with the records,
        // or a reuse without an intervening `reset()` would make
        // `record_seen` index into the drained vector. Candidates drain
        // with the records, for the same reason.
        self.seen_index.clear();
        Some(Box::new(DevelPairingState {
            seen: std::mem::take(&mut self.seen),
            fixed_dep_candidates: std::mem::take(&mut self.fixed_dep_candidates),
            etc_payload_candidates: std::mem::take(&mut self.etc_payload_candidates),
        }))
    }

    fn import_state(&mut self, state: Box<dyn std::any::Any + Send>) {
        if let Ok(state) = state.downcast::<DevelPairingState>() {
            for entry in state.seen {
                self.record_seen(entry);
            }
            self.fixed_dep_candidates.extend(state.fixed_dep_candidates);
            self.etc_payload_candidates
                .extend(state.etc_payload_candidates);
        }
    }

    fn after_checks(&mut self, _config: &Config, out: &mut Filter) {
        // Index the records by source once: the pairing never crosses
        // sources, so each `-devel` package scans only its own set
        // instead of the whole run with a string compare per pair.
        let mut by_source: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, entry) in self.seen.iter().enumerate() {
            if let Some(sr) = entry.source_rpm.as_deref() {
                by_source.entry(sr).or_default().push(i);
            }
        }
        // Lint order of the `-devel` packages drives the finding order.
        for d in 0..self.seen.len() {
            if !self.is_devel_package(&self.seen[d].name) {
                continue;
            }
            let Some(source_rpm) = self.seen[d].source_rpm.clone() else {
                continue;
            };
            // Group the sibling candidates by normalised base, in
            // first-seen order: the base package and its flavours are
            // one pairing, not one pairing per sibling.
            let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
            for &s in &by_source[source_rpm.as_str()] {
                if s == d {
                    continue;
                }
                let sibling = &self.seen[s];
                if !sibling.has_versioned_so
                    || !self.devel_names_for(&sibling.name).iter().any(|n| {
                        n == devel_pairing_name(&self.re_devel_flavoured, &self.seen[d].name)
                    })
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
                // one of its `lib`-prefixed non-SONAME provides names)
                // satisfies the whole group.
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
        // Fixed-dependency lockstep: a pinned `=` dependency that resolves
        // within the run to a package built from the same source RPM moves
        // with the requiring package by construction, so it is not a policy
        // violation. Candidates captured during `check_binary` resolve
        // against the run's provider index — exact name first, then
        // provides (which also covers arch-qualified names like
        // `libdnf5_2(x86-64)`, whose headers provide the qualified name,
        // and virtuals like `gio-branding`). Providers for the requiring
        // package's architecture (noarch satisfies any arch) are preferred;
        // only when none exist do providers of other architectures count.
        // A candidate with no provider in the run, a requirer with no known
        // source, or a provider set with no same-source member still fires:
        // single-package runs are unchanged, and the requiring package
        // itself never satisfies its own pin (its own entry is excluded).
        // No candidates, no index: the provider maps scan the whole
        // run, so they are built only when a candidate needs them.
        let mut by_name: HashMap<&str, Vec<&SeenPkg>> = HashMap::new();
        let mut by_provide: HashMap<&str, Vec<&SeenPkg>> = HashMap::new();
        if !self.fixed_dep_candidates.is_empty() {
            for entry in &self.seen {
                by_name.entry(entry.name.as_str()).or_default().push(entry);
                for provide in &entry.provides {
                    by_provide.entry(provide.as_str()).or_default().push(entry);
                }
            }
        }
        for candidate in std::mem::take(&mut self.fixed_dep_candidates) {
            let silenced = match candidate.source_rpm.as_deref() {
                None => false,
                Some(source_rpm) => {
                    let mut providers: Vec<&SeenPkg> = Vec::new();
                    if let Some(v) = by_name.get(candidate.dep_name.as_str()) {
                        providers.extend(v.iter().copied());
                    } else if let Some(v) = by_provide.get(candidate.dep_name.as_str()) {
                        providers.extend(v.iter().copied());
                    }
                    providers.retain(|p| {
                        !(p.name == candidate.pkg_name && p.arch == candidate.pkg_arch)
                    });
                    let arch_matched: Vec<&SeenPkg> = providers
                        .iter()
                        .copied()
                        .filter(|p| p.arch == candidate.pkg_arch || p.arch == "noarch")
                        .collect();
                    let selected = if arch_matched.is_empty() {
                        providers
                    } else {
                        arch_matched
                    };
                    selected
                        .iter()
                        .any(|p| p.source_rpm.as_deref() == Some(source_rpm))
                }
            };
            if !silenced {
                out.add_info(make_finding(
                    &candidate.pkg_name,
                    &candidate.pkg_arch,
                    Level::Warning,
                    "shlib-fixed-dependency",
                    vec![candidate.detail],
                    None,
                ));
            }
        }
        // Etc-payload materialisation: a candidate fires only when
        // another package in the run with the same SONAME stem but a
        // different number ships the exact same path. A lone
        // generation stays quiet — the conflict it warns about does
        // not exist yet. Paths match exactly: /etc/X and /usr/etc/X
        // are different paths (administrator overlay vs vendor
        // default), not the same conflict. Bitness is normalised
        // away by `soname_package_parts`, as in the obsoletes-sibling
        // arm, so a cross-bitness generation pair counts. Each
        // Pairing is same-arch on top of that: the key carries
        // the package arch, so a cross-arch pair stays quiet.
        // package in the conflicting set gets the finding, in
        // capture order, deduplicated per (package, arch, path).
        let candidates = std::mem::take(&mut self.etc_payload_candidates);
        let mut numbers_by_stem_path_arch: HashMap<(String, String, String), HashSet<String>> =
            HashMap::new();
        for candidate in &candidates {
            numbers_by_stem_path_arch
                .entry((
                    candidate.stem.clone(),
                    candidate.path.clone(),
                    candidate.pkg_arch.clone(),
                ))
                .or_default()
                .insert(candidate.number.clone());
        }
        let mut emitted: HashSet<(String, String, String)> = HashSet::new();
        for candidate in candidates {
            let numbers = &numbers_by_stem_path_arch[&(
                candidate.stem.clone(),
                candidate.path.clone(),
                candidate.pkg_arch.clone(),
            )];
            if numbers.len() < 2 {
                continue;
            }
            if !emitted.insert((
                candidate.pkg_name.clone(),
                candidate.pkg_arch.clone(),
                candidate.path.clone(),
            )) {
                continue;
            }
            out.add_info(make_finding(
                &candidate.pkg_name,
                &candidate.pkg_arch,
                Level::Warning,
                "shlib-policy-etc-payload",
                vec![candidate.path],
                None,
            ));
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
        // Decorated version tails of real shipped SONAMEs.
        assert!(is_match(
            &check.re_so_files,
            "/usr/lib64/libLimeSuite.so.23.11-1"
        ));
        assert!(is_match(
            &check.re_so_files,
            "/usr/lib64/libSDL_bgi.so.suse9"
        ));
        assert!(is_match(
            &check.re_so_files,
            "/usr/lib64/libcmark-gfm.so.0.29.0.gfm.13"
        ));
        assert!(!is_match(&check.re_so_files, "/usr/bin/foo"));
        // A word-only tail is not a version decoration.
        assert!(!is_match(&check.re_so_files, "/usr/lib64/libfoo.so.readme"));
        // A script name embedding a versioned library name is not a
        // library file (the gdb auto-load payload shape).
        assert!(!is_match(
            &check.re_so_files,
            "/usr/share/gdb/auto-load/usr/lib64/libstdc++.so.6.0.32-gdb.py"
        ));
        assert!(!is_match(&check.re_so_files, "/usr/lib64/libfoo.so.1.py"));
    }

    #[test]
    fn missing_lib_silent_when_shipped_lib_has_decorated_tail() {
        // The package ships its library; only the SONAME spelling
        // (alphanumeric components, a trailing -<digits>) used to defeat
        // the file-name test, so the policy-named package was charged
        // with providing no libraries at all.
        let dir = std::env::temp_dir().join("rpmcrab-shlib-missinglib-decorated");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let mut files = Vec::new();
        for soname in [
            "libLimeSuite.so.23.11-1",
            "libSDL_bgi.so.suse9",
            "libcmark-gfm.so.0.29.0.gfm.13",
        ] {
            let so = dir.join(soname);
            std::fs::write(&so, minimal_elf(soname)).expect("write elf");
            files.push(PkgFile {
                name: format!("/usr/lib64/{soname}"),
                path: so.to_string_lossy().into_owned(),
                mode: 0o100755,
                magic: "ELF 64-bit LSB shared object".to_string(),
                ..Default::default()
            });
        }
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &dir, true).expect("open fixture pkg");
        pkg.name = "libmulti1".to_string();
        pkg.files = files;

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SharedLibraryPolicyCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            !names.contains(&"shlib-policy-missing-lib"),
            "decorated-tail libraries must not be charged as missing: {names:?}"
        );
    }

    #[test]
    fn missing_lib_silent_when_elf_carries_soname_under_word_tail() {
        // Issue #1029 (B1): the file name `libfoo.so.beta` fails the
        // file-name test (a word-only version tail), but the file is
        // a regular ELF carrying that string as its DT_SONAME,
        // which proves the package ships a library.
        let dir = std::env::temp_dir().join("rpmcrab-shlib-missinglib-wordtail");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let so = dir.join("libfoo.so.beta");
        std::fs::write(&so, minimal_elf("libfoo.so.beta")).expect("write elf");
        let files = vec![PkgFile {
            name: "/usr/lib64/libfoo.so.beta".to_string(),
            path: so.to_string_lossy().into_owned(),
            mode: 0o100755,
            magic: "ELF 64-bit LSB shared object".to_string(),
            ..Default::default()
        }];
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &dir, true).expect("open fixture pkg");
        pkg.name = "libfoo1".to_string();
        pkg.files = files;

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SharedLibraryPolicyCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            !names.contains(&"shlib-policy-missing-lib"),
            "an ELF carrying a SONAME is a shipped library: {names:?}"
        );
        assert!(
            !names.contains(&"readelf-failed"),
            "the fixture ELF must parse: {names:?}"
        );
    }

    #[test]
    fn missing_lib_and_readelf_failed_for_unreadable_elf() {
        // Issue #1029 (B1) pins the readelf-failure interplay: a
        // policy-named package whose only library-shaped file is an
        // unreadable ELF gets BOTH findings, as it did when the
        // decision came from file names alone -- the unreadable
        // file counts as carrying no SONAME, and the walk continues
        // past it (a single-file package, so the outcome is unchanged).
        let dir = std::env::temp_dir().join("rpmcrab-shlib-missinglib-unreadable");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let so = dir.join("libfoo.so.beta");
        let mut bytes = minimal_elf("libfoo.so.beta");
        bytes.truncate(32);
        std::fs::write(&so, bytes).expect("write truncated elf");
        let files = vec![PkgFile {
            name: "/usr/lib64/libfoo.so.beta".to_string(),
            path: so.to_string_lossy().into_owned(),
            mode: 0o100755,
            magic: "ELF 64-bit LSB shared object".to_string(),
            ..Default::default()
        }];
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &dir, true).expect("open fixture pkg");
        pkg.name = "libfoo1".to_string();
        pkg.files = files;

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SharedLibraryPolicyCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&"shlib-policy-missing-lib"),
            "an unreadable ELF carries no SONAME credit: {names:?}"
        );
        assert!(
            names.contains(&"readelf-failed"),
            "the unreadable ELF must still be reported: {names:?}"
        );
    }

    #[test]
    fn missing_lib_walk_continues_past_unreadable_elf() {
        // The ELF pass records a file it cannot read and continues:
        // a SONAME credit earned earlier in the walk stands (the
        // missing-lib finding stays silent, readelf-failed still
        // fires), and a carrier sitting behind the unreadable
        // file is now seen, so the finding stays silent too.
        let run = |order: &[bool]| {
            let dir = std::env::temp_dir().join(format!(
                "rpmcrab-shlib-missinglib-mixedorder-{}",
                order
                    .iter()
                    .map(|b| if *b { "g" } else { "b" })
                    .collect::<String>()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("tmpdir");
            let mut files = Vec::new();
            for (i, good) in order.iter().enumerate() {
                let soname = format!("lib{}{}.so.beta", if *good { "good" } else { "bad" }, i);
                let path = dir.join(&soname);
                let mut bytes = minimal_elf(&soname);
                if !good {
                    bytes.truncate(32);
                }
                std::fs::write(&path, bytes).expect("write elf");
                files.push(PkgFile {
                    name: format!("/usr/lib64/{soname}"),
                    path: path.to_string_lossy().into_owned(),
                    mode: 0o100755,
                    magic: "ELF 64-bit LSB shared object".to_string(),
                    ..Default::default()
                });
            }
            let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
            let mut pkg = Pkg::open(&rpm, &dir, true).expect("open fixture pkg");
            pkg.name = "libfoo1".to_string();
            pkg.files = files;
            let config = Config::default();
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            let mut check = SharedLibraryPolicyCheck::new(&config);
            check.check_binary(&pkg, &config, &mut out);
            out.results()
                .iter()
                .map(|(n, _)| n.clone())
                .collect::<Vec<String>>()
        };
        let names = run(&[true, false]);
        assert!(
            !names.iter().any(|n| n == "shlib-policy-missing-lib"),
            "an earlier SONAME credit stands: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "readelf-failed"),
            "the unreadable file is still reported: {names:?}"
        );
        let names = run(&[false, true]);
        assert!(
            !names.iter().any(|n| n == "shlib-policy-missing-lib"),
            "a SONAME behind the unreadable file is now seen: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "readelf-failed"),
            "the unreadable file is still reported: {names:?}"
        );
    }

    #[test]
    fn missing_lib_fires_when_only_script_payload() {
        // A policy-named package shipping no library file at all keeps
        // firing: a gdb auto-load script embedding the versioned
        // library name and a word-tailed data file are not libraries.
        let dir = std::env::temp_dir().join("rpmcrab-shlib-missinglib-script");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &dir, true).expect("open fixture pkg");
        pkg.name = "libbar9".to_string();
        pkg.files = vec![
            PkgFile {
                name: "/usr/share/gdb/auto-load/usr/lib64/libbar.so.9.0.1-gdb.py".to_string(),
                path: "/usr/share/gdb/auto-load/usr/lib64/libbar.so.9.0.1-gdb.py".to_string(),
                mode: 0o100644,
                magic: "ASCII text".to_string(),
                ..Default::default()
            },
            PkgFile {
                name: "/usr/lib64/libbar.so.readme".to_string(),
                path: "/usr/lib64/libbar.so.readme".to_string(),
                mode: 0o100644,
                magic: "ASCII text".to_string(),
                ..Default::default()
            },
        ];

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SharedLibraryPolicyCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&"shlib-policy-missing-lib"),
            "script-only payload must still be charged: {names:?}"
        );
    }

    /// Run `check_binary` over the fixture package renamed to
    /// `name` with its file list replaced by `files`, returning the
    /// finding names emitted. `tag` keeps the extraction dir unique
    /// per call site (tests run in parallel).
    fn finding_names(tag: &str, name: &str, files: Vec<PkgFile>) -> Vec<String> {
        let dir = std::env::temp_dir().join(format!("rpmcrab-shlib-missinglib-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &dir, true).expect("open fixture pkg");
        pkg.name = name.to_string();
        pkg.files = files;
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SharedLibraryPolicyCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        out.results().iter().map(|(n, _)| n.to_string()).collect()
    }

    fn data_file(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            mode: 0o100644,
            magic: "ASCII text".to_string(),
            ..Default::default()
        }
    }

    fn dir_entry(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            mode: 0o40755,
            ..Default::default()
        }
    }

    fn link_file(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            mode: 0o120777,
            ..Default::default()
        }
    }

    #[test]
    fn missing_lib_silent_for_categories_only_split() {
        // The KDE categories-only split: the scheme-named package's
        // sole payload is a Qt logging-categories data file; the
        // library itself ships under an unrelated package name. The
        // directory entries around it are not payload.
        let names = finding_names(
            "categories-only",
            "libkdcraw6",
            vec![
                dir_entry("/usr/share/qlogging-categories6"),
                data_file("/usr/share/qlogging-categories6/libkdcraw.categories"),
            ],
        );
        assert!(
            !names.iter().any(|n| n == "shlib-policy-missing-lib"),
            "categories-only split must not be charged as missing: {names:?}"
        );
    }

    #[test]
    fn missing_lib_fires_when_categories_entry_is_not_a_shipped_file() {
        // The exemption describes a shipped data file: a symlink to a
        // categories file, or a %ghost categories path, is not payload
        // the package ships, so the charge stands.
        use crate::pkg::pkgfile::RPMFILE_GHOST;

        let mut ghost = data_file("/usr/share/qlogging-categories6/libkdcraw.categories");
        ghost.flags = RPMFILE_GHOST;
        for (tag, entry) in [
            (
                "categories-symlink",
                link_file("/usr/share/qlogging-categories6/libkdcraw.categories"),
            ),
            ("categories-ghost", ghost),
        ] {
            let names = finding_names(tag, "libkdcraw6", vec![entry]);
            assert!(
                names.iter().any(|n| n == "shlib-policy-missing-lib"),
                "{tag} must still be charged as missing: {names:?}"
            );
        }
    }

    #[test]
    fn loads_treats_buffer_start_as_a_left_boundary() {
        // A name at offset 0 terminated by a NUL is a complete string;
        // a name glued to a preceding byte is not, wherever it sits.
        let at_start = LoaderWitness {
            imports_loader: true,
            data: b"libbar.so.2\0rest".to_vec(),
        };
        assert!(at_start.loads("libbar.so.2"));
        let glued = LoaderWitness {
            imports_loader: true,
            data: b"Xlibbar.so.2\0".to_vec(),
        };
        assert!(!glued.loads("libbar.so.2"));
        let longer = LoaderWitness {
            imports_loader: true,
            data: b"libbar.so.20\0".to_vec(),
        };
        assert!(!longer.loads("libbar.so.2"));
    }

    #[test]
    fn missing_lib_fires_when_categories_file_has_company() {
        // A categories file plus any other payload is not the pure
        // data split: the package still ships no library.
        for (tag, companion) in [
            ("categories-plus-doc", "/usr/share/doc/libkdcraw6/README"),
            (
                "categories-plus-categories",
                "/usr/share/qlogging-categories6/libkdcraw-extra.categories",
            ),
            ("categories-plus-link", "/usr/share/libkdcraw6/helper"),
        ] {
            let companion = if tag == "categories-plus-link" {
                link_file(companion)
            } else {
                data_file(companion)
            };
            let names = finding_names(
                tag,
                "libkdcraw6",
                vec![
                    data_file("/usr/share/qlogging-categories6/libkdcraw.categories"),
                    companion,
                ],
            );
            assert!(
                names.iter().any(|n| n == "shlib-policy-missing-lib"),
                "{tag} must still be charged: {names:?}"
            );
        }
    }

    #[test]
    fn missing_lib_fires_for_categories_outside_standard_location() {
        // The credit keys on the standard categories location and
        // the `.categories` file kind, not on either alone.
        for (tag, path) in [
            (
                "categories-doc-dir",
                "/usr/share/doc/libkdcraw6/libkdcraw.categories",
            ),
            (
                "categories-no-qt-major",
                "/usr/share/qlogging-categories/libkdcraw.categories",
            ),
            (
                "categories-nested",
                "/usr/share/qlogging-categories6/subdir/libkdcraw.categories",
            ),
            (
                "categories-wrong-kind",
                "/usr/share/qlogging-categories6/libkdcraw.txt",
            ),
        ] {
            let names = finding_names(tag, "libkdcraw6", vec![data_file(path)]);
            assert!(
                names.iter().any(|n| n == "shlib-policy-missing-lib"),
                "{path} must keep firing: {names:?}"
            );
        }
    }

    #[test]
    fn missing_lib_silent_for_devel_package_in_baselibs_dress() {
        // A `-devel` package carrying the baselibs flavour suffix is
        // a development package: skipped like a plain `-devel`
        // package, though it ships no library (only config scripts
        // under the baselibs prefix).
        let names = finding_names(
            "devel-flavoured",
            "libfoo1-devel-x86-64-v3",
            vec![data_file("/usr/lib/baselibs-x86-64-v3/bin/libfoo-config")],
        );
        assert!(
            !names.iter().any(|n| n == "shlib-policy-missing-lib"),
            "flavoured devel package must not be charged: {names:?}"
        );
    }

    #[test]
    fn missing_lib_devel_gate_near_misses_keep_firing() {
        // A flavour tail without the `-devel` component is a library
        // package name, and `-devel` followed by a non-flavour tail
        // is not the baselibs dress: all keep firing when they ship
        // no library.
        for name in [
            "libfoo1-x86-64-v3",
            "libfoo1-devel-2",
            "libfoo1-devel-x86-64",
        ] {
            let names = finding_names(
                &format!("near-miss-{name}"),
                name,
                vec![data_file("/usr/share/doc/pkg/README")],
            );
            assert!(
                names.iter().any(|n| n == "shlib-policy-missing-lib"),
                "{name} must keep firing: {names:?}"
            );
        }
    }

    #[test]
    fn missing_lib_residue_shapes_keep_firing() {
        // The deliberate residue: trailing digits that are stem or
        // product numbers, not SONAME generations, on packages
        // shipping no library \— the charge is literally true.
        let cases: Vec<(&str, Vec<PkgFile>)> = vec![
            // A CLI tool plus docs: the "64" is base64.
            (
                "libb64",
                vec![
                    data_file("/usr/bin/b64"),
                    data_file("/usr/share/doc/libb64/README"),
                ],
            ),
            // A grub.d hook symlink plus a libexec helper: the "2"
            // is GRUB 2's product number.
            (
                "libostree-grub2",
                vec![
                    link_file("/etc/grub.d/15_ostree"),
                    data_file("/usr/libexec/libostree/grub2-15_ostree"),
                ],
            ),
        ];
        for (name, files) in cases {
            let names = finding_names(&format!("residue-{name}"), name, files);
            assert!(
                names.iter().any(|n| n == "shlib-policy-missing-lib"),
                "{name} must keep firing: {names:?}"
            );
        }
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

    /// An ELF64 object with a dynamic segment rich enough for the
    /// dlopen-witness path: an optional DT_SONAME, DT_NEEDED entries, and
    /// a DT_SYMTAB/DT_HASH pair exposing `dynsyms` ((name, bind, type,
    /// shndx); shndx 0 is an import) to goblin. `embedded` adds a bare
    /// string to the string table, the way a dlopen target name sits in
    /// a real library's data. VA == file offset throughout (one PT_LOAD).
    fn loader_elf(
        soname: Option<&str>,
        needed: &[&str],
        dynsyms: &[(&str, u8, u8, u16)],
        embedded: Option<&str>,
    ) -> Vec<u8> {
        let mut strtab: Vec<u8> = vec![0];
        let mut push_str = |s: &str| {
            let off = strtab.len() as u64;
            strtab.extend_from_slice(s.as_bytes());
            strtab.push(0);
            off
        };
        let soname_off = soname.map(&mut push_str);
        let mut needed_offs: Vec<u64> = Vec::new();
        for n in needed {
            needed_offs.push(push_str(n));
        }
        let mut sym_offs: Vec<u64> = Vec::new();
        for (n, _, _, _) in dynsyms {
            sym_offs.push(push_str(n));
        }
        if let Some(e) = embedded {
            let _ = push_str(e);
        }

        // Symbol table: null entry plus one 24-byte entry per dynsym.
        let mut symtab: Vec<u8> = vec![0; 24];
        for (i, (_, bind, typ, shndx)) in dynsyms.iter().enumerate() {
            let mut e = vec![0u8; 24];
            e[0..4].copy_from_slice(&(sym_offs[i] as u32).to_le_bytes());
            e[4] = (bind << 4) | typ;
            e[6..8].copy_from_slice(&shndx.to_le_bytes());
            symtab.extend(e);
        }

        // SysV hash: nbucket 1, nchain = symbol count (goblin derives the
        // dynsym count from it).
        let nchain = (1 + dynsyms.len()) as u32;
        let mut hash: Vec<u8> = Vec::new();
        hash.extend_from_slice(&1u32.to_le_bytes());
        hash.extend_from_slice(&nchain.to_le_bytes());
        hash.extend_from_slice(&(if dynsyms.is_empty() { 0u32 } else { 1 }).to_le_bytes());
        for i in 0..nchain {
            let next = if i + 1 < nchain { i + 1 } else { 0 };
            hash.extend_from_slice(&next.to_le_bytes());
        }

        let ehsize: u64 = 64;
        let dyn_off = ehsize + 2 * 56;
        let dyn_count = needed.len() + soname.is_some() as usize + 6;
        let symtab_off = dyn_off + 16 * dyn_count as u64;
        let hash_off = symtab_off + symtab.len() as u64;
        let strtab_off = hash_off + hash.len() as u64;
        let total = strtab_off + strtab.len() as u64;

        let mut dynamic: Vec<u8> = Vec::new();
        let mut entry = |tag: i64, val: u64| {
            dynamic.extend_from_slice(&tag.to_le_bytes());
            dynamic.extend_from_slice(&val.to_le_bytes());
        };
        if let Some(off) = soname_off {
            entry(14, off); // DT_SONAME
        }
        for off in &needed_offs {
            entry(1, *off); // DT_NEEDED
        }
        entry(4, hash_off); // DT_HASH
        entry(6, symtab_off); // DT_SYMTAB
        entry(11, 24); // DT_SYMENT
        entry(5, strtab_off); // DT_STRTAB
        entry(10, strtab.len() as u64); // DT_STRSZ
        entry(0, 0); // DT_NULL
        assert_eq!(dynamic.len(), 16 * dyn_count);

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
        let mut ph = |ptype: u32, off: u64, filesz: u64| {
            elf.extend_from_slice(&ptype.to_le_bytes());
            elf.extend_from_slice(&5u32.to_le_bytes()); // flags R+X
            elf.extend_from_slice(&off.to_le_bytes());
            elf.extend_from_slice(&off.to_le_bytes()); // vaddr == offset
            elf.extend_from_slice(&0u64.to_le_bytes()); // paddr
            elf.extend_from_slice(&filesz.to_le_bytes());
            elf.extend_from_slice(&filesz.to_le_bytes()); // memsz
            elf.extend_from_slice(&0x1000u64.to_le_bytes()); // align
        };
        ph(1, 0, total); // PT_LOAD
        ph(2, dyn_off, dynamic.len() as u64); // PT_DYNAMIC

        elf.extend(dynamic);
        elf.extend(symtab);
        elf.extend(hash);
        elf.extend(strtab);
        assert_eq!(elf.len() as u64, total);
        elf
    }

    /// Run the check over a synthetic `libfoo1` package whose files are
    /// the given (path, ELF bytes) pairs, returning all findings.
    fn run_shlib_pkg(
        dir_name: &str,
        files: Vec<(String, Vec<u8>)>,
        requires: Vec<DepInfo>,
    ) -> Vec<(String, String)> {
        let dir = std::env::temp_dir().join(format!("{dir_name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let mut pkg_files = Vec::new();
        for (i, (name, bytes)) in files.into_iter().enumerate() {
            let path = dir.join(format!("f{i}"));
            std::fs::write(&path, bytes).expect("write elf");
            pkg_files.push(PkgFile {
                name,
                path: path.to_string_lossy().into_owned(),
                mode: 0o100644,
                magic: "ELF 64-bit LSB shared object".to_string(),
                ..Default::default()
            });
        }
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &dir, true).expect("open fixture pkg");
        pkg.name = "libfoo1".to_string();
        pkg.files = pkg_files;
        pkg.requires = requires;
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SharedLibraryPolicyCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        out.results().to_vec()
    }

    fn excessive_deps(results: &[(String, String)]) -> Vec<&str> {
        results
            .iter()
            .filter(|(n, _)| n == "shlib-policy-excessive-dependency")
            .map(|(_, line)| line.rsplit(' ').next().unwrap_or(""))
            .collect()
    }

    #[test]
    fn excessive_dependency_credits_dlopen_shim() {
        // The shipped library loads libbar.so.2 by name at runtime: it
        // imports the dynamic loader, embeds the exact SONAME, and
        // nothing in the package has a DT_NEEDED entry for it. The explicit require is
        // the library's own runtime dependency, not an excessive one.
        let lib = loader_elf(
            Some("libfoo.so"),
            &["libc.so.6"],
            &[("dlopen", 1, 2, 0), ("dlsym", 1, 2, 0)],
            Some("libbar.so.2"),
        );
        let results = run_shlib_pkg(
            "rpmcrab-shlib-dlopen-shim",
            vec![("/usr/lib64/libfoo.so".to_string(), lib)],
            vec![dep("libbar.so.2"), dep("libc.so.6()(64bit)")],
        );
        assert_eq!(excessive_deps(&results), Vec::<&str>::new(), "{results:?}");
    }

    #[test]
    fn excessive_dependency_fires_without_loader_import() {
        // Same package, but the library imports no dynamic loader: an
        // embedded name alone is not evidence of a runtime load.
        let lib = loader_elf(Some("libfoo.so"), &["libc.so.6"], &[], Some("libbar.so.2"));
        let results = run_shlib_pkg(
            "rpmcrab-shlib-no-loader",
            vec![("/usr/lib64/libfoo.so".to_string(), lib)],
            vec![dep("libbar.so.2"), dep("libc.so.6()(64bit)")],
        );
        assert_eq!(excessive_deps(&results), vec!["libbar.so.2"], "{results:?}");
    }

    #[test]
    fn excessive_dependency_fires_without_embedded_soname() {
        // The library imports the loader but never names libbar.so.2.
        let lib = loader_elf(
            Some("libfoo.so"),
            &["libc.so.6"],
            &[("dlopen", 1, 2, 0)],
            Some("libother.so.9"),
        );
        let results = run_shlib_pkg(
            "rpmcrab-shlib-no-embedded",
            vec![("/usr/lib64/libfoo.so".to_string(), lib)],
            vec![dep("libbar.so.2"), dep("libc.so.6()(64bit)")],
        );
        assert_eq!(excessive_deps(&results), vec!["libbar.so.2"], "{results:?}");
    }

    #[test]
    fn excessive_dependency_fires_when_a_program_links_it() {
        // The library is a dlopen shim for libbar.so.2, but a shipped
        // program links libbar.so.2 directly: a link-time consumer in
        // non-library payload is the violation the check exists to
        // report, so the credit does not apply.
        let lib = loader_elf(
            Some("libfoo.so"),
            &["libc.so.6"],
            &[("dlopen", 1, 2, 0)],
            Some("libbar.so.2"),
        );
        let prog = loader_elf(None, &["libbar.so.2"], &[], None);
        let results = run_shlib_pkg(
            "rpmcrab-shlib-program-links",
            vec![
                ("/usr/lib64/libfoo.so".to_string(), lib),
                ("/usr/bin/footool".to_string(), prog),
            ],
            vec![dep("libbar.so.2"), dep("libc.so.6()(64bit)")],
        );
        assert_eq!(excessive_deps(&results), vec!["libbar.so.2"], "{results:?}");
    }

    #[test]
    fn excessive_dependency_fires_with_unparsable_program() {
        // The library is a textbook dlopen shim, but a shipped
        // program fails to parse: its DT_NEEDED set is unobservable,
        // so the consumer set is incomplete and the credit is
        // withheld (the absence the credit requires cannot be shown).
        let lib = loader_elf(
            Some("libfoo.so"),
            &["libc.so.6"],
            &[("dlopen", 1, 2, 0)],
            Some("libbar.so.2"),
        );
        let mut broken = vec![0x7f, b'E', b'L', b'F', 9, 1, 1, 0];
        broken.extend_from_slice(&[0xff; 64]);
        let results = run_shlib_pkg(
            "rpmcrab-shlib-unparsable-program",
            vec![
                ("/usr/lib64/libfoo.so".to_string(), lib),
                ("/usr/bin/footool".to_string(), broken),
            ],
            vec![dep("libbar.so.2"), dep("libc.so.6()(64bit)")],
        );
        assert_eq!(excessive_deps(&results), vec!["libbar.so.2"], "{results:?}");
    }

    #[test]
    fn excessive_dependency_nul_boundary_names_still_fire() {
        // The embedded name must be the charged SONAME delimited by
        // NULs: a longer name containing it, or one glued to a
        // preceding character, is not the name being loaded.
        for embedded in ["libbar.so.20", "Xlibbar.so.2"] {
            let lib = loader_elf(
                Some("libfoo.so"),
                &["libc.so.6"],
                &[("dlopen", 1, 2, 0)],
                Some(embedded),
            );
            let results = run_shlib_pkg(
                "rpmcrab-shlib-nul-boundary",
                vec![("/usr/lib64/libfoo.so".to_string(), lib)],
                vec![dep("libbar.so.2"), dep("libc.so.6()(64bit)")],
            );
            assert_eq!(
                excessive_deps(&results),
                vec!["libbar.so.2"],
                "embedded {embedded}: {results:?}"
            );
        }
    }

    #[test]
    fn excessive_dependency_credits_loader_import_variants() {
        // dlmopen, a versioned dlopen name, and a NOTYPE dlopen
        // import all witness a runtime load.
        for syms in [
            vec![("dlmopen", 1, 2, 0)],
            vec![("dlopen@GLIBC_2.34", 1, 2, 0)],
            vec![("dlopen", 1, 0, 0)],
        ] {
            let lib = loader_elf(
                Some("libfoo.so"),
                &["libc.so.6"],
                &syms,
                Some("libbar.so.2"),
            );
            let results = run_shlib_pkg(
                "rpmcrab-shlib-loader-variants",
                vec![("/usr/lib64/libfoo.so".to_string(), lib)],
                vec![dep("libbar.so.2"), dep("libc.so.6()(64bit)")],
            );
            assert_eq!(
                excessive_deps(&results),
                Vec::<&str>::new(),
                "{syms:?}: {results:?}"
            );
        }
    }

    #[test]
    fn excessive_dependency_fires_for_non_import_loader_symbols() {
        // A weak import (may be null at runtime), a defined symbol
        // of the loader's name, and an OBJECT-type import are not
        // the loader import the credit requires.
        for syms in [
            vec![("dlopen", 2, 2, 0)],
            vec![("dlopen", 1, 2, 1)],
            vec![("dlopen", 1, 1, 0)],
        ] {
            let lib = loader_elf(
                Some("libfoo.so"),
                &["libc.so.6"],
                &syms,
                Some("libbar.so.2"),
            );
            let results = run_shlib_pkg(
                "rpmcrab-shlib-non-import",
                vec![("/usr/lib64/libfoo.so".to_string(), lib)],
                vec![dep("libbar.so.2"), dep("libc.so.6()(64bit)")],
            );
            assert_eq!(
                excessive_deps(&results),
                vec!["libbar.so.2"],
                "{syms:?}: {results:?}"
            );
        }
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

    /// Write `bytes` under the per-test payload dir and return the
    /// path, for fixture entries whose payload the check reads.
    fn trunc_payload_path(tag: &str, key: &str, bytes: &[u8]) -> String {
        let dir = std::env::temp_dir().join(format!("rpmcrab-shlib-trunc-{tag}"));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let path = dir.join(key);
        std::fs::write(&path, bytes).expect("write payload");
        path.to_string_lossy().into_owned()
    }

    fn trunc_elf(tag: &str, key: &str, name: &str, soname: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: trunc_payload_path(tag, key, &minimal_elf(soname)),
            mode: 0o100755,
            magic: "ELF 64-bit LSB shared object".to_string(),
            ..Default::default()
        }
    }

    fn trunc_link(name: &str, linkto: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            mode: 0o120777,
            linkto: linkto.to_string(),
            ..Default::default()
        }
    }

    /// The rendered `shlib-policy-truncated-soname-path` lines for a
    /// fixture package with the given name and file list.
    fn truncated_details(tag: &str, name: &str, files: Vec<PkgFile>) -> Vec<String> {
        let dir = std::env::temp_dir().join(format!("rpmcrab-shlib-trunc-{tag}"));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &dir, true).expect("open fixture pkg");
        pkg.name = name.to_string();
        pkg.files = files;
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SharedLibraryPolicyCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        out.results()
            .iter()
            .filter(|(n, _)| n == "shlib-policy-truncated-soname-path")
            .map(|(_, line)| line.clone())
            .collect()
    }

    #[test]
    fn truncated_path_fires_for_symlink_shape() {
        // The mupdf shape: the SONAME file plus upstream's short
        // symlink, in a package whose name encodes the whole SONAME
        // version (28_0 for .28.0).
        let lines = truncated_details(
            "mupdf",
            "libmupdf28_0",
            vec![
                trunc_elf(
                    "mupdf",
                    "lib",
                    "/usr/lib64/libmupdf.so.28.0",
                    "libmupdf.so.28.0",
                ),
                trunc_link("/usr/lib64/libmupdf.so.28", "libmupdf.so.28.0"),
            ],
        );
        assert_eq!(lines.len(), 1, "exactly one finding: {lines:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        assert!(
            lines[0].contains("/usr/lib64/libmupdf.so.28 (SONAME libmupdf.so.28.0)"),
            "detail: {}",
            lines[0]
        );
    }

    #[test]
    fn truncated_path_fires_for_regular_file_shape() {
        // The libgda shape: the real library file sits at the short
        // name, its SONAME is the longer form.
        let lines = truncated_details(
            "realfile",
            "libbar2_1",
            vec![trunc_elf(
                "realfile",
                "lib",
                "/usr/lib64/libbar.so.2",
                "libbar.so.2.1",
            )],
        );
        assert_eq!(lines.len(), 1, "exactly one finding: {lines:?}");
        assert!(
            lines[0].contains("/usr/lib64/libbar.so.2 (SONAME libbar.so.2.1)"),
            "detail: {}",
            lines[0]
        );
    }

    #[test]
    fn truncated_path_quiet_when_name_carries_only_the_prefix() {
        // The scalapack MPI flavours: the short file is a regular
        // ELF created on purpose, and the package name carries only
        // the leading `2` of the SONAME 2.2.2, so the package
        // upgrades in place and never gains a co-installable
        // sibling. The name match is evaluated without the
        // hpc-location exemption; the name leg alone keeps it quiet.
        let dir = "/usr/lib64/mpi/gcc/openmpi4/lib64";
        let lines = truncated_details(
            "scalapack",
            "libscalapack2-openmpi4",
            vec![
                trunc_elf(
                    "scalapack",
                    "full",
                    &format!("{dir}/libscalapack.so.2.2.2"),
                    "libscalapack.so.2.2.2",
                ),
                trunc_elf(
                    "scalapack",
                    "short",
                    &format!("{dir}/libscalapack.so.2"),
                    "libscalapack.so.2.2.2",
                ),
            ],
        );
        assert!(lines.is_empty(), "in-place upgrade stays quiet: {lines:?}");
    }

    #[test]
    fn truncated_path_quiet_for_misnamed_package() {
        // libxfdashboard0: the truncation shape is present, but the
        // package name does not encode the whole SONAME version;
        // shlib-policy-name-error is the finding for that package.
        let lines = truncated_details(
            "xfdashboard",
            "libxfdashboard0",
            vec![
                trunc_elf(
                    "xfdashboard",
                    "lib",
                    "/usr/lib64/libxfdashboard.so.0.10100.0",
                    "libxfdashboard.so.0.10100.0",
                ),
                trunc_link(
                    "/usr/lib64/libxfdashboard.so.0",
                    "libxfdashboard.so.0.10100.0",
                ),
            ],
        );
        assert!(lines.is_empty(), "misnamed package stays quiet: {lines:?}");
    }

    #[test]
    fn truncated_path_quiet_without_soname() {
        // libf2c0: the shipped ELF carries no DT_SONAME (its provide
        // is rpm's filename fallback), so there is no SONAME for a
        // path to truncate.
        let dir = std::env::temp_dir().join("rpmcrab-shlib-trunc-f2c");
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let payload = trunc_payload_path("f2c", "lib", &loader_elf(None, &[], &[], None));
        let lines = truncated_details(
            "f2c",
            "libf2c0",
            vec![
                PkgFile {
                    name: "/usr/lib64/libf2c.so.0".to_string(),
                    path: payload,
                    mode: 0o100755,
                    magic: "ELF 64-bit LSB shared object".to_string(),
                    ..Default::default()
                },
                trunc_link("/usr/lib64/libf2c.so", "libf2c.so.0"),
            ],
        );
        let _ = dir;
        assert!(lines.is_empty(), "no SONAME, no truncation: {lines:?}");
    }

    #[test]
    fn truncated_path_quiet_for_extension_and_plain_shapes() {
        // libQt5Core5 ships libQt5Core.so.5.15 *for* SONAME
        // libQt5Core.so.5: the shipped path extends the SONAME, not
        // the reverse. The SONAME file itself (path equal to the
        // SONAME) is the plain shape every library package has.
        let lines = truncated_details(
            "qt-extension",
            "libQt5Core5",
            vec![
                trunc_elf(
                    "qt-extension",
                    "lib",
                    "/usr/lib64/libQt5Core.so.5",
                    "libQt5Core.so.5",
                ),
                trunc_link("/usr/lib64/libQt5Core.so.5.15", "libQt5Core.so.5"),
            ],
        );
        assert!(lines.is_empty(), "extension path stays quiet: {lines:?}");
    }

    #[test]
    fn truncated_path_quiet_for_unrelated_version_file() {
        // The CMake VERSION shape: a real file carrying a version
        // unrelated to the SONAME (5.1.23 shipped for SONAME .so.7).
        // The package name encodes the whole SONAME; the version
        // prefix leg alone keeps it quiet.
        let lines = truncated_details(
            "cmake-version",
            "libFcitx5Core7",
            vec![trunc_elf(
                "cmake-version",
                "lib",
                "/usr/lib64/libFcitx5Core.so.5.1.23",
                "libFcitx5Core.so.7",
            )],
        );
        assert!(lines.is_empty(), "unrelated version stays quiet: {lines:?}");
    }

    #[test]
    fn truncated_path_quiet_for_ghost_entry() {
        // A %ghost short path is not shipped payload.
        let mut ghost = trunc_link("/usr/lib64/libmupdf.so.28", "libmupdf.so.28.0");
        ghost.flags = crate::pkg::pkgfile::RPMFILE_GHOST;
        let lines = truncated_details(
            "ghost",
            "libmupdf28_0",
            vec![
                trunc_elf(
                    "ghost",
                    "lib",
                    "/usr/lib64/libmupdf.so.28.0",
                    "libmupdf.so.28.0",
                ),
                ghost,
            ],
        );
        assert!(lines.is_empty(), "ghost entry stays quiet: {lines:?}");
    }

    #[test]
    fn truncated_path_quiet_for_plain_package() {
        // The ordinary library package: the SONAME file and the
        // unversioned -devel-style link. Neither truncates a SONAME.
        let lines = truncated_details(
            "plain",
            "libfoo1",
            vec![
                trunc_elf("plain", "lib", "/usr/lib64/libfoo.so.1", "libfoo.so.1"),
                trunc_link("/usr/lib64/libfoo.so", "libfoo.so.1"),
            ],
        );
        assert!(lines.is_empty(), "plain package stays quiet: {lines:?}");
    }

    fn obsoletes_results(name: &str, obsoletes: Vec<DepInfo>) -> Vec<(String, String)> {
        // The default payload is the versioned library the
        // scheme-named package ships: a `.so.<number>` symlink, the
        // shape real library packages carry next to the versioned
        // regular file.
        let lib = PkgFile {
            name: "/usr/lib64/libfoo.so.2".to_string(),
            path: "/usr/lib64/libfoo.so.2".to_string(),
            mode: 0o120777,
            linkto: "libfoo.so.2.0".to_string(),
            ..Default::default()
        };
        obsoletes_results_with_files(name, obsoletes, vec![lib])
    }

    fn obsoletes_results_with_files(
        name: &str,
        obsoletes: Vec<DepInfo>,
        files: Vec<PkgFile>,
    ) -> Vec<(String, String)> {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture header");
        pkg.name = name.to_string();
        pkg.files = files;
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
    fn sibling_obsoletes_without_library_payload_is_quiet() {
        // A scheme-shaped name is not enough: a package shipping no
        // versioned library is not a SONAME generation, so its
        // obsoletes of another generation number do not fire.
        let results = obsoletes_results_with_files("libfoo2", vec![dep("libfoo1")], vec![]);
        assert!(
            sibling_lines(&results).is_empty(),
            "no library payload must stay quiet: {results:?}"
        );
    }

    #[test]
    fn sibling_obsoletes_with_only_gdb_autoload_payload_is_quiet() {
        // The gcc pretty-printer shape: the only `.so.<number>`-named
        // payload is the gdb auto-load Python script — a regular,
        // non-ELF file — and the package ships no library at all.
        let gdb_script = PkgFile {
            name: "/usr/share/gdb/auto-load/usr/lib64/libstdc++.so.6.0.34-gdb.py".to_string(),
            path: "/usr/share/gdb/auto-load/usr/lib64/libstdc++.so.6.0.34-gdb.py".to_string(),
            mode: 0o100644,
            magic: "Python script, ASCII text executable".to_string(),
            ..Default::default()
        };
        let results = obsoletes_results_with_files(
            "libstdc++6-pp-gcc15",
            vec![dep("libstdc++6-pp-gcc14")],
            vec![gdb_script],
        );
        assert!(
            sibling_lines(&results).is_empty(),
            "printer-only payload must stay quiet: {results:?}"
        );
    }

    #[test]
    fn sibling_obsoletes_with_elf_library_payload_fires() {
        // The regular-ELF arm of the payload test: a versioned library
        // shipped as a regular ELF file (pointed at a real minimal ELF
        // so the check's own ELF walk succeeds).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let so_path = dir.path().join("libfoo.so.2");
        std::fs::write(&so_path, minimal_elf("libfoo.so.2")).expect("write elf");
        let lib = PkgFile {
            name: "/usr/lib64/libfoo.so.2".to_string(),
            path: so_path.to_string_lossy().into_owned(),
            mode: 0o100755,
            magic: "ELF 64-bit LSB shared object".to_string(),
            ..Default::default()
        };
        let results = obsoletes_results_with_files("libfoo2", vec![dep("libfoo1")], vec![lib]);
        assert_eq!(
            sibling_lines(&results).len(),
            1,
            "ELF library payload must fire: {results:?}"
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
        check.after_checks(&config, &mut out);
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
        check.after_checks(&config, &mut out);
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
        check.after_checks(&config, &mut out);
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

    #[test]
    fn fixed_dependency_on_virtual_capability_is_silent() {
        // A virtual capability pinned with `=` (`python(abi)`,
        // `typelib(GIRepository)`) names no package, so it is not a
        // fixed version of another package: no shlib-fixed-dependency.
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
        pkg.requires = vec![
            DepInfo {
                name: "python(abi)".to_string(),
                flags: RPMSENSE_EQUAL,
                epoch: None,
                version: Some("3.13".to_string()),
                release: None,
            },
            DepInfo {
                name: "typelib(GIRepository)".to_string(),
                flags: RPMSENSE_EQUAL,
                epoch: None,
                version: Some("3.0".to_string()),
                release: None,
            },
        ];

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = checker();
        check.check_binary(&pkg, &config, &mut out);
        check.after_checks(&config, &mut out);
        let results = out.results().to_vec();
        assert!(
            results.iter().all(|(n, _)| n != "shlib-fixed-dependency"),
            "virtual capabilities must stay quiet: {results:?}"
        );
    }

    #[test]
    fn fixed_dependency_arch_qualified_package_still_warns() {
        // Boundary of the virtual-capability skip: `barbaz(x86-64)`
        // is the reference's `name(arch-bits)` shape, so it names a
        // package and must still fire.
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
            name: "barbaz(x86-64)".to_string(),
            flags: RPMSENSE_EQUAL,
            epoch: None,
            version: Some("1.0".to_string()),
            release: Some("1".to_string()),
        }];

        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = checker();
        check.check_binary(&pkg, &config, &mut out);
        check.after_checks(&config, &mut out);
        let results = out.results().to_vec();
        let lines: Vec<&str> = results
            .iter()
            .filter(|(n, _)| n == "shlib-fixed-dependency")
            .map(|(_, line)| line.as_str())
            .collect();
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(
            lines[0].contains("barbaz(x86-64) = 1.0-1"),
            "detail names the pinned dependency: {}",
            lines[0]
        );
    }

    fn fixed_dep_results(pkgs: &[&Pkg]) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = checker();
        for pkg in pkgs {
            check.check_binary(pkg, &config, &mut out);
        }
        check.after_checks(&config, &mut out);
        out.results()
            .iter()
            .filter(|(n, _)| n == "shlib-fixed-dependency")
            .cloned()
            .collect()
    }

    fn fixed_dep_requirer(dir: &tempfile::TempDir, dep: &str, source_rpm: &str) -> Pkg {
        // A versioned library package pinning `dep` at `=`, built the
        // same way as the single-package fixed-dependency tests: a real
        // minimal ELF so the check's own library walk succeeds.
        let so_path = dir.path().join("libfoo.so");
        std::fs::write(&so_path, minimal_elf("libfoo.so")).expect("write elf");
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture header");
        pkg.name = "libfoo1".to_string();
        pkg.arch = "x86_64".to_string();
        pkg.source_rpm = Some(source_rpm.to_string());
        pkg.files = vec![PkgFile {
            name: "/usr/lib64/libfoo.so".to_string(),
            path: so_path.to_string_lossy().into_owned(),
            mode: 0o100644,
            magic: "ELF 64-bit LSB shared object".to_string(),
            ..Default::default()
        }];
        pkg.requires = vec![dep_versioned(dep, RPMSENSE_EQUAL)];
        pkg.provides = vec![];
        pkg
    }

    #[test]
    fn fixed_dependency_same_source_lockstep_is_silent() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let requirer = fixed_dep_requirer(&dir, "barbaz", "foo-1-1.src.rpm");
        let provider = set_pkg("barbaz", "foo-1-1.src.rpm", vec![], vec![], None);
        let results = fixed_dep_results(&[&requirer, &provider]);
        assert!(
            results.is_empty(),
            "same-source pin must stay quiet: {results:?}"
        );
    }

    #[test]
    fn fixed_dependency_different_source_still_warns() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let requirer = fixed_dep_requirer(&dir, "barbaz", "foo-1-1.src.rpm");
        let provider = set_pkg("barbaz", "other-1-1.src.rpm", vec![], vec![], None);
        let results = fixed_dep_results(&[&requirer, &provider]);
        assert_eq!(results.len(), 1, "cross-source pin must fire: {results:?}");
        assert!(
            results[0].1.contains("barbaz = 1.0-1"),
            "detail names the pinned dependency: {}",
            results[0].1
        );
    }

    #[test]
    fn fixed_dependency_same_source_virtual_is_silent() {
        // ANY-provider rule: two providers of `gio-branding`, one from a
        // different source, one from the requirer's source — the pin is
        // lockstep and stays quiet.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let requirer = fixed_dep_requirer(&dir, "gio-branding", "libgio-1-1.src.rpm");
        let other = set_pkg(
            "gio-branding-openSUSE",
            "other-1-1.src.rpm",
            vec![],
            vec![dep("gio-branding")],
            None,
        );
        let same = set_pkg(
            "gio-branding-upstream",
            "libgio-1-1.src.rpm",
            vec![],
            vec![dep("gio-branding")],
            None,
        );
        let results = fixed_dep_results(&[&requirer, &other, &same]);
        assert!(
            results.is_empty(),
            "same-source virtual pin must stay quiet: {results:?}"
        );
    }

    #[test]
    fn fixed_dependency_different_source_virtual_still_warns() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let requirer = fixed_dep_requirer(&dir, "gio-branding", "libgio-1-1.src.rpm");
        let provider = set_pkg(
            "gio-branding-openSUSE",
            "other-1-1.src.rpm",
            vec![],
            vec![dep("gio-branding")],
            None,
        );
        let results = fixed_dep_results(&[&requirer, &provider]);
        assert_eq!(
            results.len(),
            1,
            "different-source virtual pin must fire: {results:?}"
        );
    }

    #[test]
    fn fixed_dependency_without_provider_still_warns() {
        // Single-package shape: no provider in the run, the finding stands.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let requirer = fixed_dep_requirer(&dir, "barbaz", "foo-1-1.src.rpm");
        let results = fixed_dep_results(&[&requirer]);
        assert_eq!(results.len(), 1, "provider-less pin must fire: {results:?}");
    }

    #[test]
    fn fixed_dependency_without_source_still_warns() {
        // Fail closed: a requirer with no known source cannot be shown
        // to be lockstep, so the finding stands even with a same-named
        // provider in the run.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut requirer = fixed_dep_requirer(&dir, "barbaz", "foo-1-1.src.rpm");
        requirer.source_rpm = None;
        let provider = set_pkg("barbaz", "foo-1-1.src.rpm", vec![], vec![], None);
        let results = fixed_dep_results(&[&requirer, &provider]);
        assert_eq!(results.len(), 1, "sourceless pin must fire: {results:?}");
    }

    #[test]
    fn fixed_dependency_arch_qualified_same_source_is_silent() {
        // The pinned name resolves through the provider's provides:
        // headers provide the arch-qualified self-name.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let requirer = fixed_dep_requirer(&dir, "libdnf5_2(x86-64)", "dnf5-1-1.src.rpm");
        let provider = set_pkg(
            "libdnf5_2",
            "dnf5-1-1.src.rpm",
            vec![],
            vec![dep("libdnf5_2(x86-64)")],
            Some("/usr/lib64/libdnf5.so.2"),
        );
        let results = fixed_dep_results(&[&requirer, &provider]);
        assert!(
            results.is_empty(),
            "arch-qualified same-source pin must stay quiet: {results:?}"
        );
    }

    #[test]
    fn fixed_dependency_own_provide_does_not_silence() {
        // The requiring package itself never satisfies its own pin.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut requirer = fixed_dep_requirer(&dir, "barbaz", "foo-1-1.src.rpm");
        requirer.provides = vec![dep("barbaz")];
        let results = fixed_dep_results(&[&requirer]);
        assert_eq!(results.len(), 1, "self-provided pin must fire: {results:?}");
    }

    #[test]
    fn fixed_dependency_arch_tier_prefers_same_arch() {
        // Same-arch providers decide: a different-source provider for the
        // requirer's arch beats a same-source provider for another arch.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let requirer = fixed_dep_requirer(&dir, "barbaz", "foo-1-1.src.rpm");
        let same_arch = set_pkg("barbaz", "other-1-1.src.rpm", vec![], vec![], None);
        let mut other_arch = set_pkg("barbaz", "foo-1-1.src.rpm", vec![], vec![], None);
        other_arch.arch = "aarch64".to_string();
        let results = fixed_dep_results(&[&requirer, &same_arch, &other_arch]);
        assert_eq!(
            results.len(),
            1,
            "same-arch different-source pin must fire: {results:?}"
        );
    }

    #[test]
    fn fixed_dependency_candidates_merge_across_workers() {
        // The merge path must carry fixed-dependency candidates, not
        // just seen records: a candidate dropped in export/import
        // would diverge -j runs from sequential runs silently, so
        // the firing shape is the load-bearing half (a silenced pin
        // shows no finding either way).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let requirer = fixed_dep_requirer(&dir, "barbaz", "foo-1-1.src.rpm");
        let provider = set_pkg("barbaz", "other-1-1.src.rpm", vec![], vec![], None);
        let config = Config::default();
        let mut w0 = checker();
        let mut out0 = Filter::new(&config, Color::for_tty(false)).unwrap();
        w0.check_binary(&requirer, &config, &mut out0);
        let s0 = w0.export_state().expect("worker 0 exports");
        let mut w1 = checker();
        let mut out1 = Filter::new(&config, Color::for_tty(false)).unwrap();
        w1.check_binary(&provider, &config, &mut out1);
        let s1 = w1.export_state().expect("worker 1 exports");
        let mut main = checker();
        main.import_state(s0);
        main.import_state(s1);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        main.after_checks(&config, &mut out);
        let results: Vec<_> = out
            .results()
            .iter()
            .filter(|(n, _)| n == "shlib-fixed-dependency")
            .collect();
        assert_eq!(
            results.len(),
            1,
            "merged candidate must still fire: {:?}",
            out.results()
        );
        // Same-source through the merge stays silent.
        let requirer = fixed_dep_requirer(&dir, "barbaz", "foo-1-1.src.rpm");
        let provider = set_pkg("barbaz", "foo-1-1.src.rpm", vec![], vec![], None);
        let mut w0 = checker();
        let mut out0 = Filter::new(&config, Color::for_tty(false)).unwrap();
        w0.check_binary(&requirer, &config, &mut out0);
        let s0 = w0.export_state().expect("worker 0 exports");
        let mut w1 = checker();
        let mut out1 = Filter::new(&config, Color::for_tty(false)).unwrap();
        w1.check_binary(&provider, &config, &mut out1);
        let s1 = w1.export_state().expect("worker 1 exports");
        let mut main = checker();
        main.import_state(s0);
        main.import_state(s1);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        main.after_checks(&config, &mut out);
        assert!(
            out.results()
                .iter()
                .all(|(n, _)| n != "shlib-fixed-dependency"),
            "merged same-source candidate must stay quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn etc_payload_candidates_merge_across_workers() {
        // The merge path must carry etc-payload candidates, not just
        // seen records: a candidate dropped in export/import would
        // diverge -j runs from sequential runs silently, so the
        // firing shape is the load-bearing half, and the merged
        // output set must equal the sequential run's (order is not
        // part of the guarantee).
        let config = Config::default();
        let (_d0, pkg0) = etc_pkg("libfoo1", vec![etc_file("/etc/foo/foo.conf")]);
        let mut w0 = checker();
        let mut out0 = Filter::new(&config, Color::for_tty(false)).unwrap();
        w0.check_binary(&pkg0, &config, &mut out0);
        let s0 = w0.export_state().expect("worker 0 exports");
        let (_d1, pkg1) = etc_pkg("libfoo2", vec![etc_file("/etc/foo/foo.conf")]);
        let mut w1 = checker();
        let mut out1 = Filter::new(&config, Color::for_tty(false)).unwrap();
        w1.check_binary(&pkg1, &config, &mut out1);
        let s1 = w1.export_state().expect("worker 1 exports");
        let mut main = checker();
        main.import_state(s0);
        main.import_state(s1);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        main.after_checks(&config, &mut out);
        let results = out.results().to_vec();
        assert_eq!(
            etc_lines(&results).len(),
            2,
            "merged candidates must still fire: {results:?}"
        );
        // And the merged output set must equal the sequential run's:
        // order is not part of the guarantee (sharded emission
        // follows worker import order), so the comparison is on
        // sorted sets.
        let seq_results = etc_results_many(vec![
            ("libfoo1", vec![etc_file("/etc/foo/foo.conf")]),
            ("libfoo2", vec![etc_file("/etc/foo/foo.conf")]),
        ]);
        let mut seq_lines = etc_lines(&seq_results);
        let mut merged_lines = etc_lines(&results);
        seq_lines.sort_unstable();
        merged_lines.sort_unstable();
        assert_eq!(
            merged_lines, seq_lines,
            "merged output must equal sequential output: {results:?} vs {seq_results:?}"
        );
    }

    #[test]
    fn fixed_dependency_name_first_ignores_provides() {
        // Exclusive name-first lookup: an exact-name provider from a
        // different source beats a same-source provides-only provider,
        // so the pin still fires. Unioning provides in would silence
        // it through the same-source provider.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let requirer = fixed_dep_requirer(&dir, "barbaz", "foo-1-1.src.rpm");
        let named = set_pkg("barbaz", "other-1-1.src.rpm", vec![], vec![], None);
        let providing = set_pkg(
            "other-pkg",
            "foo-1-1.src.rpm",
            vec![],
            vec![dep("barbaz")],
            None,
        );
        let results = fixed_dep_results(&[&requirer, &named, &providing]);
        assert_eq!(
            results.len(),
            1,
            "name-first exclusivity must keep firing: {results:?}"
        );
    }

    fn etc_pkg(name: &str, extra: Vec<PkgFile>) -> (tempfile::TempDir, Pkg) {
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
        (dir, pkg)
    }

    fn etc_results(name: &str, extra: Vec<PkgFile>) -> Vec<(String, String)> {
        etc_results_many(vec![(name, extra)])
    }

    fn etc_results_many(pkgs: Vec<(&str, Vec<PkgFile>)>) -> Vec<(String, String)> {
        let mut dirs = Vec::new();
        let mut built = Vec::new();
        for (name, extra) in pkgs {
            let (dir, pkg) = etc_pkg(name, extra);
            dirs.push(dir);
            built.push(pkg);
        }
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = checker();
        for pkg in &built {
            check.check_binary(pkg, &config, &mut out);
        }
        check.after_checks(&config, &mut out);
        out.results().to_vec()
    }

    fn etc_results_no_lib(name: &str, extra: Vec<PkgFile>) -> Vec<(String, String)> {
        // Same run as etc_results but without the versioned library
        // fixture file: the package under test ships no library.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture header");
        pkg.name = name.to_string();
        pkg.files = extra;
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
        // The libsemanage shape: both SONAME generations ship the
        // unversioned config file under /etc, so the conflict is
        // materialised and each generation warns.
        let results = etc_results_many(vec![
            ("libsemanage1", vec![etc_file("/etc/selinux/semanage.conf")]),
            ("libsemanage2", vec![etc_file("/etc/selinux/semanage.conf")]),
        ]);
        let lines = etc_lines(&results);
        assert_eq!(lines.len(), 2, "one finding per generation: {results:?}");
        assert!(
            lines.iter().all(|l| l.contains(" W: ")),
            "Warning level: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .all(|l| l.contains("/etc/selinux/semanage.conf")),
            "detail names the shipped path: {lines:?}"
        );
    }

    #[test]
    fn etc_single_generation_payload_is_quiet() {
        // The preventive shape that goes away: a lone generation
        // shipping /etc payload warns about a sibling that might
        // never exist, so it stays quiet until a sibling ships the
        // same path.
        let results = etc_results("libsemanage1", vec![etc_file("/etc/selinux/semanage.conf")]);
        assert!(
            etc_lines(&results).is_empty(),
            "lone generation must stay quiet: {results:?}"
        );
    }

    #[test]
    fn usr_etc_config_file_in_versioned_shlib_warns() {
        // /usr/etc is the vendor-default counterpart of /etc (treated
        // as /etc elsewhere in the tree), so payload there conflicts
        // between SONAME generations in exactly the same way.
        let results = etc_results_many(vec![
            ("libfoo1", vec![etc_file("/usr/etc/foo/foo.conf")]),
            ("libfoo2", vec![etc_file("/usr/etc/foo/foo.conf")]),
        ]);
        let lines = etc_lines(&results);
        assert_eq!(lines.len(), 2, "one finding per generation: {results:?}");
        assert!(
            lines.iter().all(|l| l.contains(" W: ")),
            "Warning level: {lines:?}"
        );
        assert!(
            lines.iter().all(|l| l.contains("/usr/etc/foo/foo.conf")),
            "detail names the shipped path: {lines:?}"
        );
    }

    #[test]
    fn usr_etc_directory_entry_is_quiet() {
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
    }

    #[test]
    fn usr_etc_ghost_entry_is_quiet() {
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
        let link = || PkgFile {
            name: "/etc/selinux/semanage.conf".to_string(),
            mode: 0o120777,
            linkto: "/etc/selinux/semanage.conf.real".to_string(),
            ..Default::default()
        };
        let results = etc_results_many(vec![("libfoo1", vec![link()]), ("libfoo2", vec![link()])]);
        let lines = etc_lines(&results);
        assert_eq!(lines.len(), 2, "one finding per generation: {results:?}");
        assert!(
            lines.iter().all(|l| l.contains(" W: ")),
            "Warning level: {lines:?}"
        );
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
        // versioned package name, and bitness is normalised away
        // for the sibling pairing, so a 32bit first generation and
        // a 64bit second generation sharing a path still conflict.
        let results = etc_results_many(vec![
            ("libfoo1-32bit", vec![etc_file("/etc/foo/foo.conf")]),
            ("libfoo2", vec![etc_file("/etc/foo/foo.conf")]),
        ]);
        assert_eq!(
            etc_lines(&results).len(),
            2,
            "one finding per generation: {results:?}"
        );
    }

    #[test]
    fn etc_same_generation_two_arches_is_quiet() {
        // libfoo1 and libfoo1-32bit are the same SONAME generation
        // (the bitness suffix is normalised away), so their shared
        // path is not a generation conflict.
        let results = etc_results_many(vec![
            ("libfoo1", vec![etc_file("/etc/foo/foo.conf")]),
            ("libfoo1-32bit", vec![etc_file("/etc/foo/foo.conf")]),
        ]);
        assert!(
            etc_lines(&results).is_empty(),
            "same generation must stay quiet: {results:?}"
        );
    }

    #[test]
    fn etc_different_paths_across_generations_is_quiet() {
        // Two generations conflict only over a shared path; distinct
        // payloads do not pair.
        let results = etc_results_many(vec![
            ("libfoo1", vec![etc_file("/etc/foo/a.conf")]),
            ("libfoo2", vec![etc_file("/etc/foo/b.conf")]),
        ]);
        assert!(
            etc_lines(&results).is_empty(),
            "distinct paths must stay quiet: {results:?}"
        );
    }

    #[test]
    fn etc_usr_etc_vs_etc_is_quiet() {
        // /etc/X and /usr/etc/X are different paths (administrator
        // overlay vs vendor default), so they do not pair.
        let results = etc_results_many(vec![
            ("libfoo1", vec![etc_file("/etc/foo/foo.conf")]),
            ("libfoo2", vec![etc_file("/usr/etc/foo/foo.conf")]),
        ]);
        assert!(
            etc_lines(&results).is_empty(),
            "cross-prefix paths must stay quiet: {results:?}"
        );
    }

    #[test]
    fn etc_package_named_file_is_quiet() {
        // A file named after the package itself belongs to this SONAME
        // generation: the next generation's package has a different name
        // and ships a differently-named file (libakai0.conf, libgig14.conf).
        let results = etc_results(
            "libakai0",
            vec![etc_file("/etc/ld.so.conf.d/libakai0.conf")],
        );
        assert!(
            etc_lines(&results).is_empty(),
            "package-named file must stay quiet: {results:?}"
        );
    }

    #[test]
    fn etc_lib_stem_named_file_is_quiet() {
        // The lib-stem form: ThePEG30.conf belongs to libThePEG30.
        let results = etc_results(
            "libThePEG30",
            vec![etc_file("/etc/ld.so.conf.d/ThePEG30.conf")],
        );
        assert!(
            etc_lines(&results).is_empty(),
            "lib-stem-named file must stay quiet: {results:?}"
        );
    }

    #[test]
    fn etc_payload_without_library_payload_is_quiet() {
        // A scheme-shaped name on a package shipping no versioned
        // library is not a SONAME generation (libostree-grub2 ships
        // only a grub script, no .so).
        let results =
            etc_results_no_lib("libostree-grub2", vec![etc_file("/etc/grub.d/15_ostree")]);
        assert!(
            etc_lines(&results).is_empty(),
            "no-library package must stay quiet: {results:?}"
        );
    }

    #[test]
    fn etc_paired_exclusions_stay_quiet() {
        // Carried-over exclusions hold for pairs too: the
        // materialised-only gate pairs generations, so each
        // exclusion needs its paired pin, not just its single
        // package one. Every pair below shares one path and stays
        // quiet.
        // Directory entries are shared by design.
        let dir_entry = || PkgFile {
            name: "/etc/foo/foo.conf".to_string(),
            mode: 0o40755,
            ..Default::default()
        };
        let results = etc_results_many(vec![
            ("libfoo1", vec![dir_entry()]),
            ("libfoo2", vec![dir_entry()]),
        ]);
        assert!(
            etc_lines(&results).is_empty(),
            "paired dir entries must stay quiet: {results:?}"
        );
        // Ghost entries are not shipped payload, alone or against a
        // regular entry on the same path.
        let ghost = || PkgFile {
            flags: crate::pkg::pkgfile::RPMFILE_GHOST,
            ..etc_file("/etc/foo/foo.conf")
        };
        let results =
            etc_results_many(vec![("libfoo1", vec![ghost()]), ("libfoo2", vec![ghost()])]);
        assert!(
            etc_lines(&results).is_empty(),
            "paired ghost entries must stay quiet: {results:?}"
        );
        let results = etc_results_many(vec![
            ("libfoo1", vec![ghost()]),
            ("libfoo2", vec![etc_file("/etc/foo/foo.conf")]),
        ]);
        assert!(
            etc_lines(&results).is_empty(),
            "ghost-vs-regular pair must stay quiet: {results:?}"
        );
        // Self-named: libfoo1's own file is excluded, so the pair
        // has only libfoo2's candidate and cannot fire.
        let results = etc_results_many(vec![
            ("libfoo1", vec![etc_file("/etc/ld.so.conf.d/libfoo1.conf")]),
            ("libfoo2", vec![etc_file("/etc/ld.so.conf.d/libfoo1.conf")]),
        ]);
        assert!(
            etc_lines(&results).is_empty(),
            "self-named side of a pair must stay quiet: {results:?}"
        );
        // Name-population exclusions, both sides excluded.
        for (a, b) in [
            ("foo-daemon", "bar-daemon"),
            ("libfoo1-devel", "libfoo2-devel"),
            ("libfoo1-lang", "libfoo2-lang"),
            ("libfoo", "libbar"),
        ] {
            let results = etc_results_many(vec![
                (a, vec![etc_file("/etc/foo/foo.conf")]),
                (b, vec![etc_file("/etc/foo/foo.conf")]),
            ]);
            assert!(
                etc_lines(&results).is_empty(),
                "paired {a}/{b} must stay quiet: {results:?}"
            );
        }
        // No-library pairs: versioned names shipping no versioned
        // library are not SONAME generations, even as a pair.
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = checker();
        for name in ["libfoo1", "libfoo2"] {
            let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
            let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture header");
            pkg.name = name.to_string();
            pkg.files = vec![etc_file("/etc/foo/foo.conf")];
            pkg.requires = vec![];
            check.check_binary(&pkg, &config, &mut out);
        }
        check.after_checks(&config, &mut out);
        let results = out.results().to_vec();
        assert!(
            etc_lines(&results).is_empty(),
            "paired no-library packages must stay quiet: {results:?}"
        );
    }

    #[test]
    fn etc_cross_arch_generations_stay_quiet() {
        // Pairing keys on (stem, path, arch), so generations on
        // different architectures stay quiet over a shared path.
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = checker();
        let (_d0, mut pkg0) = etc_pkg("libfoo1", vec![etc_file("/etc/foo/foo.conf")]);
        pkg0.arch = "x86_64".to_string();
        check.check_binary(&pkg0, &config, &mut out);
        let (_d1, mut pkg1) = etc_pkg("libfoo2", vec![etc_file("/etc/foo/foo.conf")]);
        pkg1.arch = "aarch64".to_string();
        check.check_binary(&pkg1, &config, &mut out);
        check.after_checks(&config, &mut out);
        let results = out.results().to_vec();
        assert!(
            etc_lines(&results).is_empty(),
            "cross-arch pair must stay quiet: {results:?}"
        );
    }

    #[test]
    fn library_only_shlib_is_quiet() {
        let results = etc_results("libfoo1", vec![]);
        assert!(results.is_empty(), "no findings at all: {results:?}");
    }

    #[test]
    fn non_etc_payload_in_versioned_shlib_is_quiet() {
        // /usr/etcfoo only shares a prefix with /usr/etc: the boundary
        // is the slash, so it stays ordinary payload.
        let results = etc_results(
            "libfoo1",
            vec![
                etc_file("/usr/share/foo/foo.conf"),
                etc_file("/usr/etcfoo/foo.conf"),
            ],
        );
        assert!(
            etc_lines(&results).is_empty(),
            "payload outside /etc and /usr/etc must stay quiet: {results:?}"
        );
    }

    #[test]
    fn multiple_etc_files_each_warn_sorted() {
        // Both generations ship both paths, so each generation warns
        // once per path; within a generation the findings stay sorted
        // by path, and generations emit in capture order.
        let files = || {
            vec![
                etc_file("/etc/selinux/semanage.conf"),
                etc_file("/etc/ld.so.conf.d/foo.conf"),
            ]
        };
        let results = etc_results_many(vec![("libfoo1", files()), ("libfoo2", files())]);
        let lines = etc_lines(&results);
        assert_eq!(
            lines.len(),
            4,
            "one finding per path per generation: {results:?}"
        );
        assert!(
            lines[0].contains("/etc/ld.so.conf.d/foo.conf")
                && lines[1].contains("/etc/selinux/semanage.conf")
                && lines[2].contains("/etc/ld.so.conf.d/foo.conf")
                && lines[3].contains("/etc/selinux/semanage.conf"),
            "findings sorted by path within each generation: {lines:?}"
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
    fn devel_repeated_input_warns_once() {
        // The same package recorded twice (a repeated input, or two
        // workers reporting it) replaces its first record: the pairing
        // still emits exactly one finding, not one per record.
        let lib = shlib("libfoo1", "foo-1-1.src.rpm");
        let devel = devel("libfoo-devel", "foo-1-1.src.rpm", vec![dep("libfoo1")]);
        let results = run_set(&[&lib, &devel, &devel]);
        assert_eq!(results.len(), 1, "exactly one finding: {results:?}");
    }

    #[test]
    fn devel_zero_padded_sibling_groups_under_unpadded_name() {
        // The scheme number drops leading zeroes, as on the obsoletes
        // path: libfoo01 is the libfoo1 group, and the finding names
        // the canonical (unpadded) base.
        let lib = shlib("libfoo01", "foo-1-1.src.rpm");
        let devel = devel("libfoo-devel", "foo-1-1.src.rpm", vec![dep("libfoo01")]);
        let results = run_set(&[&lib, &devel]);
        assert_eq!(results.len(), 1, "exactly one finding: {results:?}");
        assert_eq!(
            results[0].1,
            "libfoo-devel.x86_64: W: shlib-devel-unversioned-requires libfoo1"
        );
    }

    #[test]
    fn devel_require_on_non_lib_provides_name_warns() {
        // Only `lib`-prefixed provides names count as pairing names: a
        // versioned require on an unrelated provides name of the
        // sibling does not satisfy the pairing.
        let mut lib = shlib("libfoo1", "foo-1-1.src.rpm");
        lib.provides = vec![dep_versioned("foo", RPMSENSE_EQUAL)];
        let devel = devel(
            "libfoo-devel",
            "foo-1-1.src.rpm",
            vec![dep_versioned("foo", RPMSENSE_EQUAL)],
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

    #[test]
    fn devel_pairing_export_clears_the_seen_index() {
        // `export_state` takes the records, and the export-clears
        // contract (check.rs) lets the check be reused without an
        // intervening `reset()`; a stale index would make
        // `record_seen` write into the drained vector (panic) or
        // dedup against a slot that now holds another package.
        let config = Config::default();
        let lib = shlib("libfoo1", "foo-1-1.src.rpm");
        let devel = devel("libfoo-devel", "foo-1-1.src.rpm", vec![dep("unrelated")]);
        let mut check = checker();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(&lib, &config, &mut out);
        let exported = check.export_state().expect("exports");
        assert!(check.seen.is_empty());
        assert!(check.seen_index.is_empty(), "export left a stale index");
        // Reuse without `reset()`: re-recording the exported package
        // appends a fresh entry instead of indexing the drained vector.
        check.check_binary(&lib, &config, &mut out);
        assert_eq!(check.seen.len(), 1);
        // Dedup on the fresh index still replaces, not duplicates.
        check.check_binary(&devel, &config, &mut out);
        check.check_binary(&lib, &config, &mut out);
        assert_eq!(check.seen.len(), 2);
        drop(exported);
    }
}
