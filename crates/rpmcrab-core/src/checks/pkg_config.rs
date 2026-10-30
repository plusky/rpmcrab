//! `PkgConfigCheck` — validate `.pc` files.
//!
//! Ported from `rpmlint/checks/PkgConfigCheck.py`. Four findings, all errors:
//! `invalid-pkgconfig-file`, `pkgconfig-invalid-libs-dir`,
//! `double-slash-in-pkgconfig-path`, `pkgconfig-exception`.
//!
//! One further finding is the port's own and run-scoped:
//! `pkgconfig-dangling-library` (warning, reported from
//! `after_checks`) fires when a `.pc` file's own-name `-l` names a
//! library no package of the same build ships. The verdict
//! reconciles the `.pc` files of one build against the files of the
//! whole build, so a build is judged only when the run also holds
//! the build's source package — the shape an OBS lint run over a
//! finished build takes. On any partial input the library is
//! expected to sit in a sibling package that was not linted, so the
//! finding stays silent.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use fancy_regex::Regex;

use crate::check::{Check, add_info, basename, make_finding};
use crate::checks::is_match;
use crate::checks::shared::{binary_source_key, is_64bit_arch, is_ghost_file, source_package_keys};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::is_reg;
use std::sync::OnceLock;

static PC_FILE_REGEX: OnceLock<Regex> = OnceLock::new();
fn pc_file_regex() -> &'static Regex {
    PC_FILE_REGEX.get_or_init(|| Regex::new(r".*/pkgconfig/.*\.pc$").expect("static regex"))
}

static SUSPICIOUS_DIR_REGEX: OnceLock<Regex> = OnceLock::new();
fn suspicious_dir_regex() -> &'static Regex {
    SUSPICIOUS_DIR_REGEX.get_or_init(|| {
        Regex::new(r"[=:](?:/usr/src/[\w.-]+/BUILD|/var/tmp|/tmp|/home)").expect("static regex")
    })
}

static WRONGLIB_DIR_64_REGEX: OnceLock<Regex> = OnceLock::new();
fn wronglib_dir_64_regex() -> &'static Regex {
    WRONGLIB_DIR_64_REGEX.get_or_init(|| Regex::new(r"-L/usr/lib\b").expect("static regex"))
}

static WRONGLIB_DIR_32_REGEX: OnceLock<Regex> = OnceLock::new();
fn wronglib_dir_32_regex() -> &'static Regex {
    WRONGLIB_DIR_32_REGEX.get_or_init(|| Regex::new(r"-L/usr/lib64\b").expect("static regex"))
}

pub struct PkgConfigCheck {
    /// `SOURCERPM` spellings of the source packages the run holds.
    sources: HashSet<String>,
    /// Build keys in first-seen order, so findings follow package
    /// lint order deterministically.
    order: Vec<String>,
    builds: HashMap<String, PcBuild>,
}

/// Everything one build contributes to the run-scoped verdict.
#[derive(Default)]
struct PcBuild {
    /// Basenames of the non-`%ghost` entries any package of the
    /// build ships.
    shipped_basenames: HashSet<String>,
    pcs: Vec<PcCandidate>,
}

/// One `.pc` file whose `Libs:` carries an own-name `-l` token.
struct PcCandidate {
    pkg_name: String,
    arch: String,
    path: String,
    /// The own-name `-l` arguments, as written, deduplicated, in
    /// file order.
    tokens: Vec<String>,
}

/// Cross-package state, exported per package and merged before
/// `after_checks` (`rpmlint#1595`).
struct PkgConfigState {
    sources: HashSet<String>,
    order: Vec<String>,
    builds: HashMap<String, PcBuild>,
}

/// The comparison form of a library name: lowercased, with one
/// leading `lib` stripped — `libfoo`, `LibFoo` and `foo` all name
/// the same library stem.
fn norm_lib_name(name: &str) -> String {
    let lower = name.to_lowercase();
    lower.strip_prefix("lib").unwrap_or(&lower).to_string()
}

/// Expand `${var}` references in a `.pc` value against the file's
/// `name=value` variables, repeatedly (a variable's value may
/// itself reference variables). Unknown variables stay literal.
fn expand_pc_vars(text: &str, vars: &HashMap<&str, &str>) -> String {
    let mut out = text.to_string();
    for _ in 0..10 {
        let mut changed = false;
        let mut next = String::with_capacity(out.len());
        let mut rest = out.as_str();
        while let Some(start) = rest.find("${") {
            next.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            match after.find('}') {
                Some(end) => {
                    let name = &after[..end];
                    match vars.get(name) {
                        Some(value) => {
                            next.push_str(value);
                            changed = true;
                        }
                        None => {
                            next.push_str("${");
                            next.push_str(name);
                            next.push('}');
                        }
                    }
                    rest = &after[end + 1..];
                }
                None => {
                    next.push_str(&rest[start..]);
                    rest = "";
                }
            }
        }
        next.push_str(rest);
        out = next;
        if !changed {
            break;
        }
    }
    out
}

/// The own-name `-l` arguments of a `.pc` file's `Libs:` lines: the
/// tokens whose normalised form equals the normalised file stem
/// (basename without `.pc`). Only an own-name token can be judged
/// against the build — a foreign token (`-lm`, `-lz`) is expected
/// to resolve outside the source. `Libs.private` is not read: its
/// libraries are a static-link detail the package's own `Libs:`
/// need not name.
fn own_name_lib_tokens(content: &str, stem: &str) -> Vec<String> {
    // Join backslash continuations into logical lines first.
    let mut logical: Vec<String> = Vec::new();
    for line in content.lines() {
        match logical.last_mut() {
            Some(prev) if prev.ends_with('\\') => {
                prev.pop();
                prev.push_str(line);
            }
            _ => logical.push(line.to_string()),
        }
    }
    let mut vars: HashMap<&str, &str> = HashMap::new();
    for line in &logical {
        if let Some((name, value)) = line.split_once('=') {
            let name = name.trim();
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
            {
                vars.insert(name, value.trim());
            }
        }
    }
    let stem_norm = norm_lib_name(stem);
    let mut tokens: Vec<String> = Vec::new();
    for line in &logical {
        let Some(libs) = line.strip_prefix("Libs:") else {
            continue;
        };
        for tok in expand_pc_vars(libs, &vars).split_whitespace() {
            if let Some(n) = tok.strip_prefix("-l")
                && !n.is_empty()
                && norm_lib_name(n) == stem_norm
                && !tokens.iter().any(|t| t == n)
            {
                tokens.push(n.to_string());
            }
        }
    }
    tokens
}

impl PkgConfigCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            sources: HashSet::new(),
            order: Vec::new(),
            builds: HashMap::new(),
        }
    }

    fn build_mut(&mut self, key: &str) -> &mut PcBuild {
        if !self.builds.contains_key(key) {
            self.order.push(key.to_string());
            self.builds.insert(key.to_string(), PcBuild::default());
        }
        self.builds.get_mut(key).expect("just inserted")
    }

    /// Record a package's shipped basenames under its build key.
    fn record_shipped(&mut self, pkg: &Pkg) {
        let Some(key) = binary_source_key(pkg) else {
            return;
        };
        let build = self.build_mut(&key);
        for file in &pkg.files {
            if !is_ghost_file(pkg, file) {
                build
                    .shipped_basenames
                    .insert(basename(&file.name).to_string());
            }
        }
    }

    /// Record a `.pc` file as a candidate for the run-scoped
    /// verdict when its `Libs:` carries an own-name `-l` token.
    fn record_pc_candidate(&mut self, pkg: &Pkg, file_name: &str, text: &str) {
        let Some(key) = binary_source_key(pkg) else {
            return;
        };
        let stem = basename(file_name).strip_suffix(".pc").unwrap_or("");
        let tokens = own_name_lib_tokens(text, stem);
        if tokens.is_empty() {
            return;
        }
        self.build_mut(&key).pcs.push(PcCandidate {
            pkg_name: pkg.name.clone(),
            arch: pkg.arch.clone(),
            path: file_name.to_string(),
            tokens,
        });
    }

    /// Classify one `.pc` line. Returns `(finding, line_detail)`; the detail
    /// is the `rstrip()`ed line, or `None` when the reference reports only
    /// the filename.
    fn check_line(
        line: &str,
        suspicious: &Regex,
        wronglib: &Regex,
    ) -> Vec<(&'static str, Option<String>)> {
        let mut out = Vec::new();
        if is_match(suspicious, line) {
            out.push(("invalid-pkgconfig-file", None));
        }
        if line.starts_with("Libs:") && is_match(wronglib, line) {
            out.push((
                "pkgconfig-invalid-libs-dir",
                Some(line.trim_end().to_string()),
            ));
        }
        if line.contains("//") && !line.contains("://") {
            out.push((
                "double-slash-in-pkgconfig-path",
                Some(line.trim_end().to_string()),
            ));
        }
        out
    }

    /// Classify a whole `.pc` file's text, in line order.
    fn check_content(content: &str, is_64bit: bool) -> Vec<(&'static str, Option<String>)> {
        let suspicious = suspicious_dir_regex();
        let wronglib = if is_64bit {
            wronglib_dir_64_regex()
        } else {
            wronglib_dir_32_regex()
        };
        let mut out = Vec::new();
        for line in content.lines() {
            out.extend(Self::check_line(line, suspicious, wronglib));
        }
        out
    }

    /// Decode and check raw file bytes. A decoding failure becomes
    /// `pkgconfig-exception`, like the reference's `except Exception` around
    /// the utf-8 read.
    fn check_bytes(
        content: &[u8],
        is_64bit: bool,
    ) -> Result<Vec<(&'static str, Option<String>)>, String> {
        let text = std::str::from_utf8(content).map_err(|e| e.to_string())?;
        Ok(Self::check_content(text, is_64bit))
    }
}

/// The libdir the arch predicate charges as wrong for this package:
/// `/usr/lib` on a 64-bit target, `/usr/lib64` on a 32-bit one.
fn wrong_lib_dir(is_64bit: bool) -> &'static str {
    if is_64bit { "/usr/lib" } else { "/usr/lib64" }
}

/// A `.pc` file installed under the charged libdir tree itself
/// describes that tree's ABI, not the host arch's: the baselibs
/// `-32bit` packages on a 64-bit host install their `.pc` files
/// under `/usr/lib/...` and correctly point `-L` at `/usr/lib`, the
/// directory their libraries live in. Placement is the decidable
/// signal -- the RPM's arch is the host arch, not the ABI the `.pc`
/// describes. The trailing slash keeps a sibling prefix
/// (`/usr/libfoo/...`) from qualifying.
fn pc_installed_under_wrong_lib_dir(pc_path: &str, is_64bit: bool) -> bool {
    pc_path.starts_with(&format!("{}/", wrong_lib_dir(is_64bit)))
}

impl Check for PkgConfigCheck {
    fn name(&self) -> &'static str {
        "PkgConfigCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        self.record_shipped(pkg);
        let re = pc_file_regex();
        let is_64bit = is_64bit_arch(&pkg.arch);
        for file in &pkg.files {
            if !is_match(re, &file.name) || !is_reg(file.mode) {
                continue;
            }
            // AbstractCheck.py:45 filters ghosts out of the dispatch list,
            // so check_file never runs for one and a ghost `.pc` file draws
            // no finding.
            if pkg.ghost_files.contains(&file.name) {
                continue;
            }
            let emit = |out: &mut Filter, check: &str, line: &Option<String>| match line {
                Some(l) => add_info(out, Level::Error, pkg, check, &[&file.name, l]),
                None => add_info(out, Level::Error, pkg, check, &[&file.name]),
            };
            match fs::read(Path::new(&file.path)) {
                Ok(bytes) => {
                    if let Ok(text) = std::str::from_utf8(&bytes) {
                        self.record_pc_candidate(pkg, &file.name, text);
                    }
                    match Self::check_bytes(&bytes, is_64bit) {
                        Ok(findings) => {
                            for (check, line) in &findings {
                                if *check == "pkgconfig-invalid-libs-dir"
                                    && pc_installed_under_wrong_lib_dir(&file.name, is_64bit)
                                {
                                    continue;
                                }
                                emit(out, check, line);
                            }
                        }
                        Err(e) => add_info(
                            out,
                            Level::Error,
                            pkg,
                            "pkgconfig-exception",
                            &[&file.name, &e],
                        ),
                    }
                }
                // The extractor leaves entries it skipped after a path
                // collision out of the tree and reports each skip itself
                // (extract.rs `warn_skip_collision`); a read through the
                // object that won the collision fails with NotADirectory,
                // and that failure alone draws no finding. Every other
                // read failure reports as an exception -- a header-listed
                // file missing from the tree included -- as do decode
                // failures above.
                Err(e) if e.kind() == ErrorKind::NotADirectory => {}
                Err(e) => add_info(
                    out,
                    Level::Error,
                    pkg,
                    "pkgconfig-exception",
                    &[&file.name, &e.to_string()],
                ),
            }
        }
    }

    fn reset(&mut self) {
        self.sources.clear();
        self.order.clear();
        self.builds.clear();
    }

    fn export_state(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        Some(Box::new(PkgConfigState {
            sources: std::mem::take(&mut self.sources),
            order: std::mem::take(&mut self.order),
            builds: std::mem::take(&mut self.builds),
        }))
    }

    fn import_state(&mut self, state: Box<dyn std::any::Any + Send>) {
        if let Ok(mut state) = state.downcast::<PkgConfigState>() {
            self.sources.extend(state.sources.drain());
            for key in std::mem::take(&mut state.order) {
                let Some(data) = state.builds.remove(&key) else {
                    continue;
                };
                match self.builds.get_mut(&key) {
                    Some(mine) => {
                        mine.shipped_basenames.extend(data.shipped_basenames);
                        mine.pcs.extend(data.pcs);
                    }
                    None => {
                        self.order.push(key.clone());
                        self.builds.insert(key, data);
                    }
                }
            }
        }
    }

    fn check_source(&mut self, pkg: &Pkg, _config: &Config, _out: &mut Filter) {
        for key in source_package_keys(pkg) {
            self.sources.insert(key);
        }
    }

    fn after_checks(&mut self, _config: &Config, out: &mut Filter) {
        for key in &self.order {
            // The gate: only a build whose source package the run
            // holds is judged; anything else stays silent.
            if !self.sources.contains(key) {
                continue;
            }
            let build = &self.builds[key];
            for pc in &build.pcs {
                for n in &pc.tokens {
                    let shipped = ["so", "a", "dll.a"]
                        .iter()
                        .any(|ext| build.shipped_basenames.contains(&format!("lib{n}.{ext}")));
                    if !shipped {
                        out.add_info(make_finding(
                            &pc.pkg_name,
                            &pc.arch,
                            Level::Warning,
                            "pkgconfig-dangling-library",
                            vec![pc.path.clone(), format!("-l{n}")],
                            None,
                        ));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;
    use crate::pkg::pkgfile::{PkgFile, RPMFILE_GHOST};

    fn check(line: &str, is_64bit: bool) -> Vec<(&'static str, Option<String>)> {
        PkgConfigCheck::check_line(
            line,
            suspicious_dir_regex(),
            if is_64bit {
                wronglib_dir_64_regex()
            } else {
                wronglib_dir_32_regex()
            },
        )
    }

    fn finding_names<'a>(findings: &'a [(&'static str, Option<String>)]) -> Vec<&'a str> {
        findings.iter().map(|(n, _)| *n).collect()
    }

    #[test]
    fn suspicious_build_dirs_are_reported() {
        for line in [
            "prefix=/var/tmp/buildroot/usr",
            "prefix=/tmp/foo",
            "prefix=/home/user/pkg",
            "prefix=/usr/src/packages/BUILD/usr",
            "prefix=/usr/src/linux-6.1/BUILD/usr",
            "prefix=/usr/src/linux-6.1.2/BUILD",
            "exec_prefix:/var/tmp/x",
        ] {
            assert_eq!(
                finding_names(&check(line, true)),
                vec!["invalid-pkgconfig-file"],
                "{line}"
            );
        }
    }

    #[test]
    fn clean_prefix_is_quiet() {
        for line in ["prefix=/usr", "prefix=/opt/foo", "Name: foo"] {
            assert!(check(line, true).is_empty(), "{line}");
        }
    }

    #[test]
    fn wrong_lib_dir_64bit() {
        let findings = check("Libs: -L/usr/lib -lfoo", true);
        assert_eq!(finding_names(&findings), vec!["pkgconfig-invalid-libs-dir"]);
        assert_eq!(
            findings[0].1.as_deref(),
            Some("Libs: -L/usr/lib -lfoo"),
            "detail is the rstripped line"
        );
    }

    #[test]
    fn right_lib_dir_64bit_is_quiet() {
        assert!(check("Libs: -L/usr/lib64 -lfoo", true).is_empty());
    }

    #[test]
    fn wrong_lib_dir_32bit() {
        let findings = check("Libs: -L/usr/lib64 -lfoo", false);
        assert_eq!(finding_names(&findings), vec!["pkgconfig-invalid-libs-dir"]);
    }

    #[test]
    fn right_lib_dir_32bit_is_quiet() {
        assert!(check("Libs: -L/usr/lib -lfoo", false).is_empty());
    }

    #[test]
    fn libs_check_needs_exact_prefix() {
        // `startswith('Libs:')`: leading space or `.private` do not count.
        assert!(check(" Libs: -L/usr/lib -lfoo", true).is_empty());
        assert!(check("Libs.private: -L/usr/lib -lfoo", true).is_empty());
    }

    #[test]
    fn double_slash_is_reported() {
        let findings = check("prefix=/usr//lib", true);
        assert_eq!(
            finding_names(&findings),
            vec!["double-slash-in-pkgconfig-path"]
        );
        assert_eq!(findings[0].1.as_deref(), Some("prefix=/usr//lib"));
    }

    #[test]
    fn url_with_scheme_is_quiet() {
        // `://` exempts the whole line, even with a later `//`.
        assert!(check("URL=https://example.com/foo", true).is_empty());
        assert!(check("URL=https://example.com//foo", true).is_empty());
    }

    #[test]
    fn trailing_whitespace_is_stripped_from_details() {
        let findings = check("prefix=/usr//lib   ", true);
        assert_eq!(findings[0].1.as_deref(), Some("prefix=/usr//lib"));
    }

    #[test]
    fn multiple_findings_per_line_in_order() {
        // `[=:]` must directly precede the path, so the build dir needs `=`.
        let findings = check("Libs: -L/usr/lib prefix=/tmp/x", true);
        assert_eq!(
            finding_names(&findings),
            vec!["invalid-pkgconfig-file", "pkgconfig-invalid-libs-dir"]
        );
    }

    #[test]
    fn invalid_utf8_is_an_exception() {
        let err = PkgConfigCheck::check_bytes(b"\xff\xfe invalid \x80", true).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn arch_classification() {
        // The shared predicate covers every 64-bit RPM arch: `-L/usr/lib`
        // is the wrong libdir for all of them, `-L/usr/lib64` for the rest.
        for arch in [
            "x86_64",
            "x86_64_v2",
            "x86_64_v3",
            "x86_64_v4",
            "ppc64",
            "ppc64le",
            "s390x",
            "aarch64",
            "riscv64",
            "loongarch64",
        ] {
            assert!(is_64bit_arch(arch), "{arch}");
        }
        for arch in ["i586", "i686", "armv7l", "noarch", ""] {
            assert!(!is_64bit_arch(arch), "{arch}");
        }
    }

    #[test]
    fn pc_filename_selection() {
        let re = pc_file_regex();
        assert!(is_match(re, "usr/lib64/pkgconfig/foo.pc"));
        assert!(is_match(re, "usr/share/pkgconfig/foo.pc"));
        assert!(!is_match(re, "usr/lib64/pkgconfig/foo.pc.orig"));
        assert!(!is_match(re, "usr/bin/foo"));
    }

    /// plusky's #108 nit: `suspicious_build_dirs_are_reported` is
    /// helper-level only -- it drives `check_line` and pins the finding name.
    /// This one drives `check_binary` on a `.pc` file whose prefix points at
    /// a hyphenated build dir, pinning the emitted name, level and detail.
    /// The `Pkg` comes from `open_no_extract` (no payload extraction into
    /// the shared temp dir): `files` is overwritten wholesale and the `.pc`
    /// bytes are read from `file.path`, never through the package root.
    #[test]
    fn hyphenated_build_dir_emits_error_through_check_binary() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pc = dir.path().join("foo.pc");
        std::fs::write(
            &pc,
            "prefix=/usr/src/linux-6.1/BUILD/usr\n\
             exec_prefix=${prefix}\n\
             Name: foo\n\
             Description: fixture\n\
             Version: 1.0\n\
             Libs: -L/usr/lib64 -lfoo\n",
        )
        .expect("write fixture pc file");
        let mut pkg = Pkg::open_no_extract(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm"),
        )
        .expect("open fixture pkg header");
        pkg.name = "pkgconfig-test".to_string();
        pkg.arch = "x86_64".to_string();
        // The leading slash is what the real pipeline emits, not a fixture
        // artifact: real `RPMTAG_FILENAMES` entries carry it (rpmbuild writes
        // absolute DIRNAMES), the reference keys `pkg.files` on the raw tag
        // value (`pkg.py:679,713`) and emits it verbatim
        // (`PkgConfigCheck.py:46`), and this port emits librpm's raw
        // `rpmfilesFN` the same way. The frozen string is golden for the
        // port's widened pattern only: the reference's `\w+` never matches
        // this hyphenated build dir, so it emits no `invalid-pkgconfig-file`
        // here at all (the widening is already ledgered in
        // `divergences.toml`).
        let rel = "usr/lib64/pkgconfig/foo.pc";
        pkg.files = vec![PkgFile {
            name: format!("/{rel}"),
            path: pc.to_string_lossy().into_owned(),
            mode: 0o100644,
            ..Default::default()
        }];
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).expect("filter");
        let mut check = PkgConfigCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "invalid-pkgconfig-file");
        assert_eq!(
            results[0].1,
            "pkgconfig-test.x86_64: E: invalid-pkgconfig-file /usr/lib64/pkgconfig/foo.pc"
        );
    }

    /// Build a `Pkg` carrying one `.pc` entry with the given on-disk
    /// `path`, in the shape of `hyphenated_build_dir_...` above.
    fn pkg_with_pc_path(path: &Path, name: &str) -> Pkg {
        let mut pkg = Pkg::open_no_extract(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm"),
        )
        .expect("open fixture pkg header");
        pkg.name = "pkgconfig-test".to_string();
        pkg.arch = "x86_64".to_string();
        pkg.files = vec![PkgFile {
            name: name.to_string(),
            path: path.to_string_lossy().into_owned(),
            mode: 0o100644,
            ..Default::default()
        }];
        pkg
    }

    fn run_pkg_config_check(pkg: &Pkg) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).expect("filter");
        let mut check = PkgConfigCheck::new(&config);
        check.check_binary(pkg, &config, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn pc_file_behind_a_colliding_file_is_quiet() {
        // The grpc-source shape (#826): the payload carries the regular
        // file `usr/src/grpc/BUILD` and the directory
        // `usr/src/grpc/build`. On the case-insensitive tree the two are
        // one entry: the extractor materialises the file, skips the
        // entries beneath the directory and reports the skips itself.
        // The fixture builds the resulting layout directly -- a regular
        // file at `build`, the exact component the `.pc` path traverses
        // -- so the read runs through a non-directory and fails with
        // NotADirectory on any filesystem. The error kind is asserted
        // here so the pin cannot silently degrade to an absent-path
        // (NotFound) read. The file was never materialised, so the
        // package draws no finding.
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path().join("usr/src/grpc");
        std::fs::create_dir_all(&root).expect("mkdir fixture tree");
        std::fs::write(root.join("build"), "regular file that won the collision\n")
            .expect("write colliding file");
        let pc_path = root.join("build/libs/opt/pkgconfig/gpr.pc");
        let err = std::fs::read(&pc_path).expect_err("read through a regular file must fail");
        assert_eq!(err.kind(), ErrorKind::NotADirectory);
        let pkg = pkg_with_pc_path(&pc_path, "/usr/src/grpc/build/libs/opt/pkgconfig/gpr.pc");
        let results = run_pkg_config_check(&pkg);
        assert!(results.is_empty(), "unexpected results: {results:?}");
    }

    #[test]
    fn ghost_pc_file_absent_from_the_tree_is_quiet() {
        // A %ghost `.pc` entry is in the header's file list but the
        // payload carries no content for it, so it never materialises.
        // The dispatch skips ghosts before any read, so the absence
        // draws no finding; the same absence on a non-ghost entry
        // reports an exception (next test), so this pin fails if the
        // up-front skip goes away.
        let dir = tempfile::tempdir().expect("tmpdir");
        let pc_path = dir.path().join("usr/lib64/pkgconfig/ghost.pc");
        let mut pkg = pkg_with_pc_path(&pc_path, "/usr/lib64/pkgconfig/ghost.pc");
        pkg.files[0].flags = RPMFILE_GHOST;
        pkg.ghost_files = vec!["/usr/lib64/pkgconfig/ghost.pc".to_string()].into();
        let results = run_pkg_config_check(&pkg);
        assert!(results.is_empty(), "unexpected results: {results:?}");
    }

    #[test]
    fn missing_pc_file_reports_an_exception() {
        // A header-listed `.pc` file missing from the tree is a read
        // failure like any other: the reference charges it as
        // `pkgconfig-exception` through the `except Exception` around
        // its `open()`. Only the collision failure (NotADirectory,
        // above) stays silent.
        let dir = tempfile::tempdir().expect("tmpdir");
        let pc_path = dir.path().join("usr/lib64/pkgconfig/missing.pc");
        let pkg = pkg_with_pc_path(&pc_path, "/usr/lib64/pkgconfig/missing.pc");
        let results = run_pkg_config_check(&pkg);
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "pkgconfig-exception");
        assert!(
            results[0]
                .1
                .contains("E: pkgconfig-exception /usr/lib64/pkgconfig/missing.pc"),
            "unexpected line: {}",
            results[0].1
        );
    }

    #[test]
    fn undecodable_pc_file_still_reports_an_exception() {
        // A materialised `.pc` file whose bytes are not valid UTF-8
        // keeps the `pkgconfig-exception` finding: the skip above
        // covers only files the extractor left out of the tree.
        let dir = tempfile::tempdir().expect("tmpdir");
        let pc_dir = dir.path().join("usr/lib64/pkgconfig");
        std::fs::create_dir_all(&pc_dir).expect("mkdir fixture tree");
        let pc_path = pc_dir.join("bad.pc");
        std::fs::write(&pc_path, b"prefix=/usr\n\xff\xfe\n").expect("write fixture pc file");
        let pkg = pkg_with_pc_path(&pc_path, "/usr/lib64/pkgconfig/bad.pc");
        let results = run_pkg_config_check(&pkg);
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "pkgconfig-exception");
        assert!(
            results[0]
                .1
                .contains("E: pkgconfig-exception /usr/lib64/pkgconfig/bad.pc"),
            "unexpected line: {}",
            results[0].1
        );
    }

    /// Write `content` to a scratch `.pc` file, present it as the
    /// package file `name` on a package of arch `arch`, and run the
    /// whole check over it.
    fn run_pc_at(name: &str, arch: &str, content: &str) -> Vec<(String, String)> {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pc = dir.path().join("foo.pc");
        std::fs::write(&pc, content).expect("write fixture pc file");
        let mut pkg = pkg_with_pc_path(&pc, name);
        pkg.arch = arch.to_string();
        run_pkg_config_check(&pkg)
    }

    #[test]
    fn invalid_libs_dir_quiet_when_pc_lives_in_the_charged_tree() {
        // The freetype2-devel-32bit shape: an x86_64 (host-arch)
        // baselibs package whose `.pc` sits in the 32-bit tree
        // `/usr/lib/pkgconfig` and correctly points `-L` at the
        // directory its libraries live in.
        let results = run_pc_at(
            "/usr/lib/pkgconfig/foo.pc",
            "x86_64",
            "Libs: -L/usr/lib -lfoo\n",
        );
        assert!(results.is_empty(), "unexpected results: {results:?}");
    }

    #[test]
    fn invalid_libs_dir_quiet_for_flavour_tree_under_charged_dir() {
        // Flavoured trees under the charged libdir (the openblas
        // `-32bit` shape) describe that tree's ABI the same way.
        let results = run_pc_at(
            "/usr/lib/openblas-serial/pkgconfig/foo.pc",
            "x86_64",
            "Libs: -L/usr/lib -lfoo\n",
        );
        assert!(results.is_empty(), "unexpected results: {results:?}");
    }

    #[test]
    fn invalid_libs_dir_fires_when_pc_lives_in_the_native_tree() {
        // The Coin shape: the `.pc` sits in `/usr/lib64/pkgconfig`,
        // its libraries are the 64-bit ones, and a literal
        // `-L/usr/lib` in its `Libs:` is a stray wrong dir.
        let results = run_pc_at(
            "/usr/lib64/pkgconfig/foo.pc",
            "x86_64",
            "Libs: -L/usr/lib -lfoo\n",
        );
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "pkgconfig-invalid-libs-dir");
    }

    #[test]
    fn invalid_libs_dir_fires_for_share_placed_pc() {
        // An arch-independent placement carries no ABI signal: the
        // charged token still fires on a 64-bit package.
        let results = run_pc_at(
            "/usr/share/pkgconfig/foo.pc",
            "x86_64",
            "Libs: -L/usr/lib -lfoo\n",
        );
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "pkgconfig-invalid-libs-dir");
    }

    #[test]
    fn invalid_libs_dir_fires_for_sibling_prefix_pc() {
        // `/usr/libfoo` merely shares a prefix with `/usr/lib`; a
        // `.pc` there is not installed under the charged tree.
        let results = run_pc_at(
            "/usr/libfoo/pkgconfig/foo.pc",
            "x86_64",
            "Libs: -L/usr/lib -lfoo\n",
        );
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "pkgconfig-invalid-libs-dir");
    }

    #[test]
    fn invalid_libs_dir_32bit_direction_follows_placement() {
        // Mirror direction on a 32-bit package: a `.pc` installed
        // under `/usr/lib64` describing the 64-bit tree is quiet,
        // one installed under `/usr/lib` still fires on the token.
        let quiet = run_pc_at(
            "/usr/lib64/pkgconfig/foo.pc",
            "i586",
            "Libs: -L/usr/lib64 -lfoo\n",
        );
        assert!(quiet.is_empty(), "unexpected results: {quiet:?}");
        let firing = run_pc_at(
            "/usr/lib/pkgconfig/foo.pc",
            "i586",
            "Libs: -L/usr/lib64 -lfoo\n",
        );
        assert_eq!(firing.len(), 1, "unexpected results: {firing:?}");
        assert_eq!(firing[0].0, "pkgconfig-invalid-libs-dir");
    }

    #[test]
    fn placement_credit_is_specific_to_invalid_libs_dir() {
        // The placement credit silences only the libs-dir charge:
        // another finding on the same placed `.pc` still fires.
        let results = run_pc_at(
            "/usr/lib/pkgconfig/foo.pc",
            "x86_64",
            "prefix=/usr//lib\nLibs: -L/usr/lib -lfoo\n",
        );
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "double-slash-in-pkgconfig-path");
    }

    // ---- pkgconfig-dangling-library (run-scoped) ----

    #[test]
    fn own_name_tokens_come_from_libs_only() {
        let content = "prefix=/usr\n\
                       libdir=${prefix}/lib64\n\
                       Libs: -L${libdir} -lfoo -lm\n\
                       Libs.private: -lfoo\n";
        assert_eq!(own_name_lib_tokens(content, "foo"), vec!["foo"]);
        // A foreign token alone is never an own-name token.
        assert!(own_name_lib_tokens("Libs: -lm -lz\n", "foo").is_empty());
        // The token itself may arrive through a variable.
        assert_eq!(
            own_name_lib_tokens("name=foo\nLibs: -l${name}\n", "foo"),
            vec!["foo"]
        );
        // A continuation line is one logical `Libs:` line.
        assert_eq!(
            own_name_lib_tokens("Libs: -L/usr/lib64 \\\n -lfoo\n", "foo"),
            vec!["foo"]
        );
        // Case and one leading `lib` are normalised on both sides.
        assert_eq!(own_name_lib_tokens("Libs: -lFoo\n", "libfoo"), vec!["Foo"]);
        assert_eq!(
            own_name_lib_tokens("Libs: -llibfoo\n", "libfoo"),
            vec!["libfoo"]
        );
    }

    /// A package built from the shared fixture header (`SOURCERPM`
    /// `fcprobe-1-1.src.rpm`), with name/arch/files replaced.
    fn fixture_pkg_named(name: &str, files: Vec<PkgFile>) -> Pkg {
        let mut pkg = Pkg::open_no_extract(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm"),
        )
        .expect("open fixture pkg header");
        pkg.name = name.to_string();
        pkg.arch = "x86_64".to_string();
        pkg.files = files;
        pkg
    }

    /// The fixture header as a source package: the identity
    /// `check_source` derives from it is `fcprobe-1-1.src.rpm`, the
    /// `SOURCERPM` every fixture-built binary carries.
    fn fixture_src() -> Pkg {
        let mut pkg = fixture_pkg_named("fcprobe", Vec::new());
        pkg.is_source = true;
        pkg
    }

    fn pc_pkg(dir: &Path, pkg_name: &str, pc_name: &str, content: &str) -> Pkg {
        let pc = dir.join(pc_name);
        std::fs::write(&pc, content).expect("write fixture pc file");
        fixture_pkg_named(
            pkg_name,
            vec![PkgFile {
                name: format!("/usr/lib64/pkgconfig/{pc_name}"),
                path: pc.to_string_lossy().into_owned(),
                mode: 0o100644,
                ..Default::default()
            }],
        )
    }

    fn lib_pkg(pkg_name: &str, files: &[&str]) -> Pkg {
        fixture_pkg_named(
            pkg_name,
            files
                .iter()
                .map(|name| PkgFile {
                    name: name.to_string(),
                    mode: 0o100644,
                    ..Default::default()
                })
                .collect(),
        )
    }

    /// Run one check instance over the source package (when
    /// `gated`) and the binaries, then `after_checks`; returns the
    /// `pkgconfig-dangling-library` findings only. The fixture
    /// `.pc` contents are written to draw none of the per-file
    /// findings.
    fn run_dangling(gated: bool, pkgs: &[Pkg]) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).expect("filter");
        let mut check = PkgConfigCheck::new(&config);
        if gated {
            check.check(&fixture_src(), &config, &mut out);
        }
        for pkg in pkgs {
            check.check(pkg, &config, &mut out);
        }
        check.after_checks(&config, &mut out);
        out.results()
            .iter()
            .filter(|(tag, _)| tag == "pkgconfig-dangling-library")
            .cloned()
            .collect()
    }

    const FOO_PC: &str = "prefix=/usr\n\
                          libdir=${prefix}/lib64\n\
                          Name: foo\n\
                          Description: fixture\n\
                          Version: 1.0\n\
                          Libs: -L${libdir} -lfoo\n";

    #[test]
    fn dangling_own_name_fires_on_a_complete_build() {
        // The build ships only the versioned library: the link name
        // the `.pc` promises exists nowhere in the build.
        let dir = tempfile::tempdir().expect("tmpdir");
        let devel = pc_pkg(dir.path(), "foo-devel", "foo.pc", FOO_PC);
        let lib = lib_pkg("libfoo", &["/usr/lib64/libfoo.so.1"]);
        let results = run_dangling(true, &[devel, lib]);
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(
            results[0].1,
            "foo-devel.x86_64: W: pkgconfig-dangling-library /usr/lib64/pkgconfig/foo.pc -lfoo"
        );
    }

    #[test]
    fn sibling_library_is_quiet() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let devel = pc_pkg(dir.path(), "foo-devel", "foo.pc", FOO_PC);
        let lib = lib_pkg("libfoo", &["/usr/lib64/libfoo.so"]);
        assert!(run_dangling(true, &[devel, lib]).is_empty());
    }

    #[test]
    fn static_and_mingw_libraries_are_quiet() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let lib = lib_pkg("libfoo", &["/usr/lib64/libfoo.a"]);
        let devel = pc_pkg(dir.path(), "foo-devel", "foo.pc", FOO_PC);
        assert!(run_dangling(true, &[devel, lib]).is_empty());
        let lib = lib_pkg("libfoo", &["/usr/lib64/libfoo.dll.a"]);
        let devel = pc_pkg(dir.path(), "foo-devel", "foo.pc", FOO_PC);
        assert!(run_dangling(true, &[devel, lib]).is_empty());
    }

    #[test]
    fn partial_and_single_runs_are_silent() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let lib = lib_pkg("libfoo", &["/usr/lib64/libfoo.so.1"]);
        let devel = pc_pkg(dir.path(), "foo-devel", "foo.pc", FOO_PC);
        // Without the source package the gate stays shut, however
        // many of the build's packages are present.
        assert!(run_dangling(false, &[devel, lib]).is_empty());
        let devel = pc_pkg(dir.path(), "foo-devel", "foo.pc", FOO_PC);
        assert!(run_dangling(false, &[devel]).is_empty());
    }

    #[test]
    fn doubled_lib_prefix_fires() {
        // `-llibfoo` in `libfoo.pc` names `liblibfoo.so`, which the
        // shipped `libfoo.so` does not satisfy.
        let dir = tempfile::tempdir().expect("tmpdir");
        let devel = pc_pkg(
            dir.path(),
            "libfoo-devel",
            "libfoo.pc",
            "Name: libfoo\nLibs: -L/usr/lib64 -llibfoo\n",
        );
        let lib = lib_pkg("libfoo", &["/usr/lib64/libfoo.so"]);
        let results = run_dangling(true, &[devel, lib]);
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert!(
            results[0].1.ends_with("-llibfoo"),
            "unexpected line: {}",
            results[0].1
        );
    }

    #[test]
    fn libs_private_and_ghost_do_not_count() {
        let dir = tempfile::tempdir().expect("tmpdir");
        // The own-name token sits only in `Libs.private`.
        let devel = pc_pkg(
            dir.path(),
            "foo-devel",
            "foo.pc",
            "Name: foo\nLibs: -L/usr/lib64\nLibs.private: -lfoo\n",
        );
        assert!(run_dangling(true, &[devel]).is_empty());
        // A `%ghost` library entry is not shipped content.
        let devel = pc_pkg(dir.path(), "foo-devel", "foo.pc", FOO_PC);
        let mut ghost_lib = lib_pkg("libfoo", &["/usr/lib64/libfoo.so"]);
        ghost_lib.files[0].flags = RPMFILE_GHOST;
        ghost_lib.ghost_files = vec!["/usr/lib64/libfoo.so".to_string()].into();
        let results = run_dangling(true, &[devel, ghost_lib]);
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
    }

    #[test]
    fn merged_state_matches_sequential() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let devel = pc_pkg(dir.path(), "foo-devel", "foo.pc", FOO_PC);
        let lib = lib_pkg("libfoo", &["/usr/lib64/libfoo.so.1"]);
        let pkgs = [devel, lib];
        let sequential = run_dangling(true, &pkgs);

        let config = Config::default();
        let mut main = PkgConfigCheck::new(&config);
        {
            let mut worker = PkgConfigCheck::new(&config);
            let mut out = Filter::new(&config, Color::for_tty(false)).expect("filter");
            worker.check(&fixture_src(), &config, &mut out);
            if let Some(state) = worker.export_state() {
                main.import_state(state);
            }
        }
        for pkg in &pkgs {
            let mut worker = PkgConfigCheck::new(&config);
            let mut out = Filter::new(&config, Color::for_tty(false)).expect("filter");
            worker.check(pkg, &config, &mut out);
            if let Some(state) = worker.export_state() {
                main.import_state(state);
            }
        }
        let mut main_out = Filter::new(&config, Color::for_tty(false)).expect("filter");
        main.after_checks(&config, &mut main_out);
        let merged: Vec<(String, String)> = main_out
            .results()
            .iter()
            .filter(|(tag, _)| tag == "pkgconfig-dangling-library")
            .cloned()
            .collect();
        assert_eq!(merged, sequential);
        assert_eq!(sequential.len(), 1);
    }

    #[test]
    fn reset_drops_the_run() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let devel = pc_pkg(dir.path(), "foo-devel", "foo.pc", FOO_PC);
        let config = Config::default();
        let mut check = PkgConfigCheck::new(&config);
        let mut out = Filter::new(&config, Color::for_tty(false)).expect("filter");
        check.check(&fixture_src(), &config, &mut out);
        check.check(&devel, &config, &mut out);
        check.reset();
        check.after_checks(&config, &mut out);
        assert!(
            out.results()
                .iter()
                .all(|(tag, _)| tag != "pkgconfig-dangling-library"),
            "leaked state: {:?}",
            out.results()
        );
    }
}
