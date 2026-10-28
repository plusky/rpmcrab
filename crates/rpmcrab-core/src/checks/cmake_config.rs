//! `CMakeConfigCheck` — CMake imported locations must name files the
//! build ships.
//!
//! A CMake export file (`*Targets.cmake` and its per-config satellites)
//! hard-codes the paths of the libraries and executables a package
//! installs as `IMPORTED_LOCATION` values under `${_IMPORT_PREFIX}`.
//! When the spec moves a library to another directory or deletes a
//! static archive after the export was generated, every downstream
//! `find_package()` fails with "the imported target references the
//! file ... but this file does not exist", and nothing in the build
//! notices.
//!
//! The verdict reconciles the imported locations of one build against
//! the files of the whole build, so it is run-scoped: it judges a
//! build only when the run also holds the build's source package
//! (header name-version-release plus `.src.rpm`/`.nosrc.rpm` equals
//! the binaries' `SOURCERPM`) — the shape an OBS lint run over a
//! finished build takes. On any partial input the locations are
//! expected to be missing (the library sits in a sibling package
//! that was not linted), so the check stays silent.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::check::{Check, make_finding};
use crate::checks::shared::{
    binary_source_key, is_ghost_file, normalise_absolute_path, source_package_keys,
};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::is_reg;

/// The line a generated export file computes its install prefix from;
/// its presence is what makes a `.cmake` file an export file.
const IMPORT_PREFIX_MARKER: &str =
    "get_filename_component(_IMPORT_PREFIX \"${CMAKE_CURRENT_LIST_FILE}\" PATH)";

/// Each such line raises the computed prefix one directory level.
const IMPORT_PREFIX_RAISE: &str =
    "get_filename_component(_IMPORT_PREFIX \"${_IMPORT_PREFIX}\" PATH)";

pub struct CMakeConfigCheck {
    /// `SOURCERPM` spellings of the source packages the run holds.
    sources: HashSet<String>,
    /// Build keys in first-seen order, so findings follow package
    /// lint order deterministically.
    order: Vec<String>,
    builds: HashMap<String, CMakeBuild>,
}

/// Everything one build contributes to the verdict.
#[derive(Default)]
struct CMakeBuild {
    /// Non-`%ghost` file paths shipped by any package of the build.
    shipped_paths: HashSet<String>,
    /// The `.cmake` files of the build, grouped by shipping package:
    /// reachability is judged within one package.
    packages: Vec<CMakePackage>,
}

struct CMakePackage {
    pkg_name: String,
    arch: String,
    files: Vec<CMakeFile>,
}

struct CMakeFile {
    path: String,
    text: String,
}

/// Cross-package state, exported per package and merged before
/// `after_checks` (`rpmlint#1595`).
struct CMakeConfigState {
    sources: HashSet<String>,
    order: Vec<String>,
    builds: HashMap<String, CMakeBuild>,
}

impl CMakeConfigCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            sources: HashSet::new(),
            order: Vec::new(),
            builds: HashMap::new(),
        }
    }

    fn build_mut(&mut self, key: &str) -> &mut CMakeBuild {
        if !self.builds.contains_key(key) {
            self.order.push(key.to_string());
            self.builds.insert(key.to_string(), CMakeBuild::default());
        }
        self.builds.get_mut(key).expect("just inserted")
    }
}

/// The last path component.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The parent directory of a path (`/` stays `/`).
fn dirname(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) => "/",
        Some(i) => &path[..i],
        None => "",
    }
}

/// A CMake package config file: `<Pkg>Config.cmake` or
/// `<pkg>-config.cmake`.
fn is_config_name(base: &str) -> bool {
    base.ends_with("Config.cmake") || base.ends_with("-config.cmake")
}

/// Whether the file's text marks it as a generated export file.
fn is_export_text(text: &str) -> bool {
    text.lines().any(|l| l.trim() == IMPORT_PREFIX_MARKER)
}

/// How many levels the export file raises its prefix above its own
/// directory.
fn prefix_raises(text: &str) -> usize {
    text.lines()
        .filter(|l| l.trim() == IMPORT_PREFIX_RAISE)
        .count()
}

/// The install prefix an export file computes: its own directory,
/// raised one level per prefix-raise line.
fn import_prefix(m_path: &str, raises: usize) -> String {
    let mut prefix = dirname(m_path).to_string();
    for _ in 0..raises {
        prefix = dirname(&prefix).to_string();
    }
    prefix
}

/// Glob matching with `*`/`?` confined to one path segment: a `*`
/// never crosses `/`, the way `file(GLOB ...)` patterns behave.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // Iterative wildcard match with backtracking on the last `*`.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' && t[ti] != '/' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_p = pi;
            star_t = ti;
            pi += 1;
        } else if star_p != usize::MAX {
            pi = star_p + 1;
            star_t += 1;
            if star_t > t.len() || t[star_t - 1] == '/' {
                return false;
            }
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// The patterns of every `file(GLOB ...)` / `file(GLOB_RECURSE ...)`
/// statement in `text`: the quoted or bare arguments that carry a
/// glob character or name a `.cmake` file (the result variable and
/// the keyword arguments carry neither). CMake command names are
/// case-insensitive and whitespace may precede the parenthesis, so
/// the scan accepts `FILE (GLOB ...)` and its kin.
fn glob_patterns(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // A `file` command at a word start: the preceding byte is not
        // a name byte, the name matches case-insensitively, and only
        // whitespace may stand between it and the parenthesis.
        let word_start = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
        if word_start && bytes.len() - i >= 4 && bytes[i..i + 4].eq_ignore_ascii_case(b"file") {
            let mut j = i + 4;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                let mut k = j + 1;
                while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                    k += 1;
                }
                if bytes.len() - k >= 4 && bytes[k..k + 4].eq_ignore_ascii_case(b"glob") {
                    let stmt = &text[i..];
                    let Some(end) = stmt.find(')') else { break };
                    for tok in stmt[..end].split(|c: char| c.is_whitespace() || c == '"') {
                        if tok.contains('*') || tok.contains('?') || tok.ends_with(".cmake") {
                            out.push(tok.to_string());
                        }
                    }
                    i += end;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// Expand the variables of a GLOB pattern for matching: the listing
/// directory becomes the directory of the file doing the globbing,
/// any other `${...}` becomes a single-segment wildcard.
fn expand_glob_pattern(pattern: &str, from_dir: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut rest = pattern;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) => {
                if &after[..end] == "CMAKE_CURRENT_LIST_DIR" {
                    out.push_str(from_dir);
                } else {
                    out.push('*');
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// Whether the file at `from_path` with content `text` names the
/// file at `target_path`: by absolute path anywhere in the text, by
/// stem within the same directory, or through a `file(GLOB ...)`
/// pattern that matches it. The stem form credits the generated
/// include shapes that append a suffix variable to the full stem
/// (`OpenCVModules${OpenCV_MODULES_SUFFIX}.cmake`); a variable in
/// the middle of the stem (`ZMusic${_comp}Targets.cmake`) names
/// nothing, and neither does a variable standing for a whole name
/// component (`${CMAKE_FIND_PACKAGE_NAME}-targets.cmake`).
/// Whether `text` mentions `stem` as a name: an occurrence whose
/// following character is not a name character, so a longer name
/// that merely starts with the stem (`Foo` inside `FooBarTargets`)
/// does not count as naming the file.
fn stem_mention(text: &str, stem: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = text[from..].find(stem) {
        let end = from + pos + stem.len();
        match text[end..].chars().next() {
            None => return true,
            Some(c) if !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '+') => {
                return true;
            }
            _ => {}
        }
        from += pos + 1;
    }
    false
}

fn names_file(text: &str, from_path: &str, target_path: &str) -> bool {
    if text.contains(target_path) {
        return true;
    }
    let same_dir = dirname(from_path) == dirname(target_path);
    let stem = basename(target_path)
        .strip_suffix(".cmake")
        .unwrap_or(basename(target_path));
    if same_dir && !stem.is_empty() && stem_mention(text, stem) {
        return true;
    }
    for pattern in glob_patterns(text) {
        let pattern = expand_glob_pattern(&pattern, dirname(from_path));
        if pattern.contains('/') {
            if glob_match(&pattern, target_path) {
                return true;
            }
        } else if same_dir && glob_match(&pattern, basename(target_path)) {
            return true;
        }
    }
    false
}

/// The export files of one package that are judged: an export file
/// counts when it is itself a config file or is reachable from one —
/// a config file names it, directly or transitively. An export no
/// config file reaches is never loaded by `find_package()`, so its
/// locations are not judged. Returns indices into `files`, in file
/// order.
fn checked_exports(files: &[CMakeFile]) -> Vec<usize> {
    let mut reached: HashSet<usize> = HashSet::new();
    let mut queue: Vec<usize> = Vec::new();
    for (i, f) in files.iter().enumerate() {
        if is_config_name(basename(&f.path)) {
            reached.insert(i);
            queue.push(i);
        }
    }
    while let Some(fi) = queue.pop() {
        for (mi, m) in files.iter().enumerate() {
            if !reached.contains(&mi) && names_file(&files[fi].text, &files[fi].path, &m.path) {
                reached.insert(mi);
                queue.push(mi);
            }
        }
    }
    files
        .iter()
        .enumerate()
        .filter(|(i, f)| reached.contains(i) && is_export_text(&f.text))
        .map(|(i, _)| i)
        .collect()
}

/// The raw `IMPORTED_LOCATION` / `IMPORTED_LOCATION_<CONFIG>` values
/// of a text, in order of appearance: the quoted string that follows
/// the property name in `set_target_properties` /
/// `set_property(... PROPERTY ...)` statements.
fn imported_locations(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find("IMPORTED_LOCATION") {
        // The match must start the property name: a name byte
        // directly before it makes it a different, longer property
        // (`MY_IMPORTED_LOCATION` names no imported location).
        let at_boundary = pos == 0
            || !matches!(rest.as_bytes()[pos - 1], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_');
        let after = &rest[pos + "IMPORTED_LOCATION".len()..];
        // An optional `_<CONFIG>` suffix of the property name.
        let after = match after.strip_prefix('_') {
            Some(r) => {
                let end = r
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(r.len());
                &r[end..]
            }
            None => after,
        };
        if at_boundary
            && let Some(quoted) = after.trim_start().strip_prefix('"')
            && let Some(end) = quoted.find('"')
        {
            out.push(quoted[..end].to_string());
        }
        rest = after;
    }
    out
}

/// The locations of export file `m` (its own and those of its
/// `<stem>-*.cmake` satellites), judged against the build's shipped
/// paths: `(counted, missing)`. A value counts once
/// `${_IMPORT_PREFIX}` is substituted: a value still carrying a
/// `${...}` variable or a `$<...>` generator expression, and a value
/// that is not absolute, cannot be judged against a file list and is
/// skipped.
fn judged_locations(
    m: &CMakeFile,
    siblings: &[CMakeFile],
    shipped: &HashSet<String>,
) -> (usize, Vec<String>) {
    let prefix = import_prefix(&m.path, prefix_raises(&m.text));
    let stem = basename(&m.path).strip_suffix(".cmake").unwrap_or("");
    let satellite_prefix = format!("{stem}-");
    let mut satellites: Vec<&CMakeFile> = siblings
        .iter()
        .filter(|f| {
            f.path != m.path
                && dirname(&f.path) == dirname(&m.path)
                && basename(&f.path).starts_with(&satellite_prefix)
                && f.path.ends_with(".cmake")
        })
        .collect();
    satellites.sort_by(|a, b| a.path.cmp(&b.path));
    let mut counted = 0;
    let mut missing: Vec<String> = Vec::new();
    for text in std::iter::once(m.text.as_str()).chain(satellites.iter().map(|f| f.text.as_str())) {
        for raw in imported_locations(text) {
            let value = raw.replace("${_IMPORT_PREFIX}", &prefix);
            if value.contains("${") || value.contains("$<") || !value.starts_with('/') {
                continue;
            }
            let value = normalise_absolute_path(&value);
            counted += 1;
            if !shipped.contains(&value) {
                missing.push(value);
            }
        }
    }
    (counted, missing)
}

impl Check for CMakeConfigCheck {
    fn name(&self) -> &'static str {
        "CMakeConfigCheck"
    }

    /// This check never emits errors (its only finding is a
    /// warning), so `--errors-only` skips it.
    fn max_severity(&self) -> Level {
        Level::Warning
    }

    fn reset(&mut self) {
        self.sources.clear();
        self.order.clear();
        self.builds.clear();
    }

    fn export_state(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        Some(Box::new(CMakeConfigState {
            sources: std::mem::take(&mut self.sources),
            order: std::mem::take(&mut self.order),
            builds: std::mem::take(&mut self.builds),
        }))
    }

    fn import_state(&mut self, state: Box<dyn std::any::Any + Send>) {
        if let Ok(mut state) = state.downcast::<CMakeConfigState>() {
            self.sources.extend(state.sources.drain());
            for key in std::mem::take(&mut state.order) {
                let Some(data) = state.builds.remove(&key) else {
                    continue;
                };
                match self.builds.get_mut(&key) {
                    Some(mine) => {
                        mine.shipped_paths.extend(data.shipped_paths);
                        mine.packages.extend(data.packages);
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

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, _out: &mut Filter) {
        if pkg.is_source {
            return;
        }
        let Some(key) = binary_source_key(pkg) else {
            return;
        };
        let build = self.build_mut(&key);
        let mut cmake_pkg = CMakePackage {
            pkg_name: pkg.name.clone(),
            arch: pkg.arch.clone(),
            files: Vec::new(),
        };
        for file in &pkg.files {
            if is_ghost_file(pkg, file) {
                continue;
            }
            build.shipped_paths.insert(file.name.clone());
            if is_reg(file.mode)
                && file.name.ends_with(".cmake")
                && let Ok(bytes) = fs::read(Path::new(&file.path))
                && let Ok(text) = String::from_utf8(bytes)
            {
                cmake_pkg.files.push(CMakeFile {
                    path: file.name.clone(),
                    text,
                });
            }
        }
        if !cmake_pkg.files.is_empty() {
            build.packages.push(cmake_pkg);
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
            for pkg in &build.packages {
                for idx in checked_exports(&pkg.files) {
                    let m = &pkg.files[idx];
                    let (counted, missing) = judged_locations(m, &pkg.files, &build.shipped_paths);
                    if let Some(first) = missing.first() {
                        out.add_info(make_finding(
                            &pkg.pkg_name,
                            &pkg.arch,
                            Level::Warning,
                            "cmake-dangling-imported-location",
                            vec![
                                m.path.clone(),
                                first.clone(),
                                format!("({} of {} missing)", missing.len(), counted),
                            ],
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
    use crate::pkg::pkgfile::PkgFile;

    /// A package built from the shared fixture header (name
    /// `fcprobe`, version `1`, release `1`, `SOURCERPM`
    /// `fcprobe-1-1.src.rpm`), with name/arch/files replaced.
    fn fixture_pkg(name: &str, files: Vec<PkgFile>) -> Pkg {
        let mut pkg = Pkg::open_no_extract(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm"),
        )
        .expect("open fixture pkg header");
        pkg.name = name.to_string();
        pkg.arch = "x86_64".to_string();
        pkg.files = files;
        pkg
    }

    /// The fixture header as a source package: the source identity
    /// `check_source` derives from it is `fcprobe-1-1.src.rpm`, the
    /// `SOURCERPM` every `fixture_pkg` binary carries.
    fn fixture_src() -> Pkg {
        let mut pkg = fixture_pkg("fcprobe", Vec::new());
        pkg.is_source = true;
        pkg
    }

    fn regular(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            ..Default::default()
        }
    }

    /// A regular file whose content the check reads from `dir`.
    fn with_content(dir: &Path, name: &str, content: &str) -> PkgFile {
        let disk = dir.join(name.rsplit('/').next().unwrap_or(name));
        // Sibling files of one package may share a basename across
        // directories in theory; the fixtures never do.
        std::fs::write(&disk, content).expect("write fixture cmake file");
        PkgFile {
            name: name.to_string(),
            path: disk.to_string_lossy().into_owned(),
            mode: 0o100644,
            ..Default::default()
        }
    }

    /// Run one check instance over the source package (when `gated`)
    /// and the binaries, then `after_checks`, sequentially.
    fn run(gated: bool, pkgs: &[Pkg]) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).expect("filter");
        let mut check = CMakeConfigCheck::new(&config);
        if gated {
            check.check(&fixture_src(), &config, &mut out);
        }
        for pkg in pkgs {
            check.check(pkg, &config, &mut out);
        }
        check.after_checks(&config, &mut out);
        out.results().to_vec()
    }

    const CONFIG: &str = "include(\"${CMAKE_CURRENT_LIST_DIR}/Caffe2Targets.cmake\")\n";

    fn targets(prefix_raises: usize) -> String {
        let mut text = String::from(
            "get_filename_component(_IMPORT_PREFIX \"${CMAKE_CURRENT_LIST_FILE}\" PATH)\n",
        );
        for _ in 0..prefix_raises {
            text.push_str("get_filename_component(_IMPORT_PREFIX \"${_IMPORT_PREFIX}\" PATH)\n");
        }
        text
    }

    const TARGETS_RELEASE: &str = "set_target_properties(c10 PROPERTIES\n  IMPORTED_LOCATION_RELEASE \"${_IMPORT_PREFIX}/lib/libc10.so\"\n)\n";

    /// The torch shape: `Caffe2` files under `/usr/lib64/cmake`, the
    /// imported location under `${_IMPORT_PREFIX}/lib`, and the build
    /// shipping the library only as `/usr/lib64/libc10.so`.
    fn torch_pkgs(dir: &Path, shipped_lib: &str) -> Vec<Pkg> {
        let devel = fixture_pkg(
            "torch-devel",
            vec![
                with_content(dir, "/usr/lib64/cmake/Caffe2/Caffe2Config.cmake", CONFIG),
                with_content(
                    dir,
                    "/usr/lib64/cmake/Caffe2/Caffe2Targets.cmake",
                    &targets(3),
                ),
                with_content(
                    dir,
                    "/usr/lib64/cmake/Caffe2/Caffe2Targets-release.cmake",
                    TARGETS_RELEASE,
                ),
            ],
        );
        let lib = fixture_pkg("libtorch", vec![regular(shipped_lib)]);
        vec![devel, lib]
    }

    #[test]
    fn moved_library_fires_on_a_complete_build() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkgs = torch_pkgs(dir.path(), "/usr/lib64/libc10.so");
        let results = run(true, &pkgs);
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "cmake-dangling-imported-location");
        assert_eq!(
            results[0].1,
            "torch-devel.x86_64: W: cmake-dangling-imported-location \
             /usr/lib64/cmake/Caffe2/Caffe2Targets.cmake /usr/lib/libc10.so (1 of 1 missing)"
        );
    }

    #[test]
    fn sibling_shipped_location_is_quiet() {
        // Today's torch: the imported path itself ships (a compat
        // symlink in a sibling package of the build).
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkgs = torch_pkgs(dir.path(), "/usr/lib/libc10.so");
        let results = run(true, &pkgs);
        assert!(results.is_empty(), "unexpected results: {results:?}");
    }

    #[test]
    fn partial_and_single_runs_are_silent() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkgs = torch_pkgs(dir.path(), "/usr/lib64/libc10.so");
        // No source package in the run: the gate stays shut even
        // though the location dangles.
        assert!(run(false, &pkgs).is_empty());
        // A single package alone is silent too.
        assert!(run(false, &pkgs[..1]).is_empty());
        assert!(run(true, &[]).is_empty());
    }

    #[test]
    fn orphan_export_is_quiet() {
        // The Tensorpipe shape: an export file no config file names.
        let dir = tempfile::tempdir().expect("tmpdir");
        let devel = fixture_pkg(
            "torch-devel",
            vec![
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/Caffe2/Caffe2Config.cmake",
                    CONFIG,
                ),
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/Caffe2/Caffe2Targets.cmake",
                    &targets(3),
                ),
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/Caffe2/Caffe2Targets-release.cmake",
                    TARGETS_RELEASE,
                ),
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/Caffe2/TensorpipeTargets.cmake",
                    &targets(3),
                ),
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/Caffe2/TensorpipeTargets-release.cmake",
                    "set_target_properties(tensorpipe PROPERTIES\n  IMPORTED_LOCATION_RELEASE \"${_IMPORT_PREFIX}/lib/libtensorpipe.so\"\n)\n",
                ),
            ],
        );
        let lib = fixture_pkg("libtorch", vec![regular("/usr/lib/libc10.so")]);
        let results = run(true, &[devel, lib]);
        assert!(results.is_empty(), "unexpected results: {results:?}");
    }

    #[test]
    fn config_file_as_export_fires() {
        // The spirv-cross shape: the config file is itself the
        // export file.
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut config_text = targets(3);
        config_text.push_str(
            "set_target_properties(spirv-cross PROPERTIES\n  IMPORTED_LOCATION \"${_IMPORT_PREFIX}/lib64/libspirv-cross-core.a\"\n)\n",
        );
        let devel = fixture_pkg(
            "spirv-cross-devel",
            vec![with_content(
                dir.path(),
                "/usr/lib64/cmake/SPIRV-Cross/SPIRV-CrossConfig.cmake",
                &config_text,
            )],
        );
        let results = run(true, &[devel]);
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "cmake-dangling-imported-location");
        assert!(
            results[0]
                .1
                .contains("/usr/lib64/libspirv-cross-core.a (1 of 1 missing)"),
            "unexpected line: {}",
            results[0].1
        );
    }

    #[test]
    fn glob_reached_export_fires() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let devel = fixture_pkg(
            "glob-devel",
            vec![
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/Glob/GlobConfig.cmake",
                    "file(GLOB _configs \"${CMAKE_CURRENT_LIST_DIR}/*Targets.cmake\")\n",
                ),
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/Glob/GlobTargets.cmake",
                    &targets(3),
                ),
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/Glob/GlobTargets-release.cmake",
                    "set_target_properties(glob PROPERTIES\n  IMPORTED_LOCATION_RELEASE \"${_IMPORT_PREFIX}/lib64/libglob.a\"\n)\n",
                ),
            ],
        );
        let results = run(true, &[devel]);
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "cmake-dangling-imported-location");
    }

    #[test]
    fn suffix_variable_include_still_names_the_export() {
        // The OpenCV shape: the config includes the export with a
        // suffix variable appended to the full stem.
        let dir = tempfile::tempdir().expect("tmpdir");
        let devel = fixture_pkg(
            "opencv-devel",
            vec![
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/opencv4/OpenCVConfig.cmake",
                    "include(${CMAKE_CURRENT_LIST_DIR}/OpenCVModules${OpenCV_MODULES_SUFFIX}.cmake)\n",
                ),
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/opencv4/OpenCVModules.cmake",
                    &targets(3),
                ),
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/opencv4/OpenCVModules-release.cmake",
                    "set_target_properties(core PROPERTIES\n  IMPORTED_LOCATION_RELEASE \"${_IMPORT_PREFIX}/lib64/libopencv_core.so.4.13.0\"\n)\n",
                ),
            ],
        );
        let results = run(true, &[devel]);
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "cmake-dangling-imported-location");
    }

    #[test]
    fn variable_name_component_include_names_nothing() {
        // The boundary of the naming rules: an include whose file
        // name is built from a variable component
        // (`${CMAKE_FIND_PACKAGE_NAME}-targets.cmake`, the paraview
        // shape) names no file under the stem/path/GLOB rules, so
        // the export stays unreached even though its location
        // dangles. Crediting such includes is a separate measured
        // question (the zmusic shape is the same family).
        let dir = tempfile::tempdir().expect("tmpdir");
        let devel = fixture_pkg(
            "paraview-devel",
            vec![
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/paraview/paraview-config.cmake",
                    "include(\"${CMAKE_CURRENT_LIST_DIR}/${CMAKE_FIND_PACKAGE_NAME}-targets.cmake\")\n",
                ),
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/paraview/ParaView-targets.cmake",
                    &targets(3),
                ),
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/paraview/ParaView-targets-release.cmake",
                    "set_target_properties(pv PROPERTIES\n  IMPORTED_LOCATION_RELEASE \"${_IMPORT_PREFIX}/bin/pvserver\"\n)\n",
                ),
            ],
        );
        let results = run(true, &[devel]);
        assert!(results.is_empty(), "unexpected results: {results:?}");
    }

    #[test]
    fn unjudgeable_locations_are_skipped() {
        // Generator expressions and foreign variables cannot be
        // judged against a file list; the export counts no location
        // and stays quiet.
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut targets_text = targets(3);
        targets_text.push_str(
            "set_target_properties(gen PROPERTIES\n  IMPORTED_LOCATION \"$<TARGET_FILE:gen>\"\n  IMPORTED_LOCATION_RELEASE \"${SOME_DIR}/libgen.so\"\n)\n",
        );
        let devel = fixture_pkg(
            "gen-devel",
            vec![
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/Gen/GenConfig.cmake",
                    "include(\"${CMAKE_CURRENT_LIST_DIR}/GenTargets.cmake\")\n",
                ),
                with_content(
                    dir.path(),
                    "/usr/lib64/cmake/Gen/GenTargets.cmake",
                    &targets_text,
                ),
            ],
        );
        let results = run(true, &[devel]);
        assert!(results.is_empty(), "unexpected results: {results:?}");
    }

    #[test]
    fn merged_state_matches_sequential() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkgs = torch_pkgs(dir.path(), "/usr/lib64/libc10.so");
        let sequential = run(true, &pkgs);

        let config = Config::default();
        let mut main = CMakeConfigCheck::new(&config);
        {
            let mut worker = CMakeConfigCheck::new(&config);
            let mut out = Filter::new(&config, Color::for_tty(false)).expect("filter");
            worker.check(&fixture_src(), &config, &mut out);
            if let Some(state) = worker.export_state() {
                main.import_state(state);
            }
        }
        for pkg in &pkgs {
            let mut worker = CMakeConfigCheck::new(&config);
            let mut out = Filter::new(&config, Color::for_tty(false)).expect("filter");
            worker.check(pkg, &config, &mut out);
            if let Some(state) = worker.export_state() {
                main.import_state(state);
            }
        }
        let mut main_out = Filter::new(&config, Color::for_tty(false)).expect("filter");
        main.after_checks(&config, &mut main_out);
        assert_eq!(main_out.results(), sequential.as_slice());
        assert_eq!(sequential.len(), 1);
    }

    #[test]
    fn reset_drops_the_run() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkgs = torch_pkgs(dir.path(), "/usr/lib64/libc10.so");
        let config = Config::default();
        let mut check = CMakeConfigCheck::new(&config);
        let mut out = Filter::new(&config, Color::for_tty(false)).expect("filter");
        check.check(&fixture_src(), &config, &mut out);
        for pkg in &pkgs {
            check.check(pkg, &config, &mut out);
        }
        check.reset();
        check.after_checks(&config, &mut out);
        assert!(
            out.results().is_empty(),
            "leaked state: {:?}",
            out.results()
        );
    }

    #[test]
    fn stem_mention_needs_a_trailing_delimiter() {
        // The credited generated shape: a suffix variable appended
        // to the full stem.
        assert!(stem_mention(
            "include(OpenCVModules${OpenCV_MODULES_SUFFIX}.cmake)",
            "OpenCVModules"
        ));
        // The plain full name and a closing delimiter credit too.
        assert!(stem_mention("include(FooTargets)", "FooTargets"));
        assert!(stem_mention("\"FooTargets.cmake\"", "FooTargets"));
        // A longer name that merely starts with the stem does not.
        assert!(!stem_mention("include(FooBarTargets)", "Foo"));
        assert!(!stem_mention("include(FooTargetsExtra)", "FooTargets"));
        assert!(!stem_mention("include(FooTargets-Release)", "FooTargets"));
    }

    #[test]
    fn glob_patterns_accept_case_and_whitespace_forms() {
        for text in [
            "file(GLOB CONF \"/x/*.cmake\")",
            "FILE(GLOB CONF \"/x/*.cmake\")",
            "file (GLOB CONF \"/x/*.cmake\")",
            "File(Glob CONF \"/x/*.cmake\")",
            "file(GLOB_RECURSE CONF \"/x/*.cmake\")",
        ] {
            assert_eq!(glob_patterns(text), vec!["/x/*.cmake"], "{text}");
        }
        // A longer identifier ending in `file` is not the command.
        assert!(glob_patterns("myfile(GLOB CONF \"/x/*.cmake\")").is_empty());
    }

    #[test]
    fn imported_locations_need_a_leading_boundary() {
        let text = "set_target_properties(t PROPERTIES IMPORTED_LOCATION \"/a.so\")";
        assert_eq!(imported_locations(text), vec!["/a.so"]);
        // A longer property name containing the string is a
        // different property and contributes no location.
        let text = "set_property(TARGET t PROPERTY MY_IMPORTED_LOCATION \"/b.so\")";
        assert!(imported_locations(text).is_empty());
        // The config-suffixed form still counts.
        let text = "set_target_properties(t PROPERTIES IMPORTED_LOCATION_RELEASE \"/c.so\")";
        assert_eq!(imported_locations(text), vec!["/c.so"]);
    }

    #[test]
    fn glob_match_stays_in_segment() {
        assert!(glob_match("*Targets.cmake", "FooTargets.cmake"));
        assert!(glob_match("/usr/*/cmake", "/usr/lib64/cmake"));
        assert!(!glob_match("/usr/*", "/usr/lib64/cmake"));
        assert!(!glob_match("*", "a/b"));
        assert!(glob_match("lib?.so", "libx.so"));
    }

    #[test]
    fn prefix_and_location_parsing() {
        assert_eq!(
            import_prefix("/usr/lib64/cmake/Foo/FooTargets.cmake", 3),
            "/usr"
        );
        assert_eq!(
            import_prefix("/usr/lib64/cmake/Foo/FooTargets.cmake", 0),
            "/usr/lib64/cmake/Foo"
        );
        let text = "set_target_properties(x PROPERTIES\n  IMPORTED_LOCATION_RELEASE \"${_IMPORT_PREFIX}/lib64/libx.so.1\"\n  IMPORTED_LOCATION_NOCONFIG \"/usr/lib64/liby.a\"\n)\n";
        assert_eq!(
            imported_locations(text),
            vec!["${_IMPORT_PREFIX}/lib64/libx.so.1", "/usr/lib64/liby.a"]
        );
    }
}
