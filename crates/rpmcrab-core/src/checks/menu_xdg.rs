//! `MenuXDGCheck` — XDG desktop file validation.
//!
//! Ported from `rpmlint/checks/MenuXDGCheck.py`. Findings:
//! `invalid-desktopfile`, `desktopfile-missing-header`,
//! `desktopfile-duplicate-section`, `desktopfile-duplicate-option`,
//! `non-utf8-desktopfile`, `desktopfile-without-binary`.
//!
//! Plus two findings the reference has no counterpart for, from the
//! rpminspect desktop inspection (issue #1223): the Icon a desktop
//! file names must resolve in this package when it is an absolute
//! path (`desktopfile-icon-not-found`), and a resolved icon file
//! must be world-readable (`desktopfile-icon-not-readable`).
//!
//! The reference runs `desktop-file-validate` and then parses the file with
//! `configparser`. This port runs `desktop-file-validate` when available and
//! always does the native parse: missing header, duplicate sections/options,
//! non-UTF-8, and the Exec binary check.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use fancy_regex::Regex;

use crate::check::{Check, add_info, make_finding};
use crate::checks::is_match;
use crate::checks::shared::{binary_source_key, is_ghost_file, source_package_keys};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::{PkgFile, is_dir, is_reg, is_symlink};
use crate::tools::{Tool, ToolSource, test_source};

const STANDARD_BIN_DIRS: [&str; 4] = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"];

/// Icon theme file extensions tried for a bare Icon name, mirroring the
/// freedesktop theme lookup (and rpminspect's fallback set).
const ICON_EXTENSIONS: [&str; 4] = ["png", "svg", "svgz", "xpm"];

/// Parsed desktop file: section -> (key -> value).
type DesktopSections = HashMap<String, HashMap<String, String>>;
/// Parse error: (level, finding, details).
type ParseError = (Level, &'static str, Vec<String>);

/// One `desktopfile-without-binary` candidate, held until
/// `after_checks` knows the run's build inventories and which
/// builds are source-complete.
struct DesktopBinaryCandidate {
    pkg_name: String,
    arch: String,
    filename: String,
    binary: String,
}

/// Everything one build contributes to the run-scoped
/// `desktopfile-without-binary` verdict: the regular files and
/// symlink targets its packages ship, plus the candidates its
/// packages raised.
#[derive(Default)]
struct DesktopBuild {
    regular: HashSet<String>,
    symlinks: HashMap<String, String>,
    candidates: Vec<DesktopBinaryCandidate>,
}

/// Cross-package state, exported per package and merged before
/// `after_checks`.
struct DesktopBuildState {
    sources: HashSet<String>,
    order: Vec<String>,
    builds: HashMap<String, DesktopBuild>,
    unkeyed: Vec<DesktopBinaryCandidate>,
}

pub struct MenuXDGCheck {
    file_regex: Regex,
    checked_files: usize,
    validator: Tool,
    sources: HashSet<String>,
    order: Vec<String>,
    builds: HashMap<String, DesktopBuild>,
    unkeyed: Vec<DesktopBinaryCandidate>,
}

impl MenuXDGCheck {
    pub fn new(_config: &Config) -> Self {
        Self::with_tool_source(ToolSource::Path)
    }

    /// Probe for `desktop-file-validate` under `source`.
    pub fn with_tool_source(source: ToolSource) -> Self {
        let (validator, _) = Tool::probe(&source, "desktop-file-validate", &[]);
        Self {
            // AbstractCheck.py:45 applies this with `re.match`; is_match
            // searches, so anchor it explicitly.
            file_regex: Regex::new(r"^/usr/share/applications/.*\.desktop$").expect("static regex"),
            checked_files: 0,
            validator,
            sources: HashSet::new(),
            order: Vec::new(),
            builds: HashMap::new(),
            unkeyed: Vec::new(),
        }
    }

    /// Test entry point: `None` probes the live `PATH`, `Some(dir)`
    /// resolves the tool under `dir` instead of mutating the process
    /// environment.
    pub fn with_tool_dir(bin_dir: Option<&Path>) -> Self {
        Self::with_tool_source(test_source(bin_dir))
    }

    /// Parse a desktop file like `configparser.RawConfigParser`.
    /// Returns the sections on success, or the finding on parse failure.
    ///
    /// Key lookup is case-insensitive: configparser lowercases every key
    /// (`optionxform`), so `Exec` and `EXEC` are the same option.
    fn parse_desktop(content: &str, filename: &str) -> Result<DesktopSections, ParseError> {
        let mut sections: DesktopSections = HashMap::new();
        let mut current: Option<String> = None;
        let mut last_key: Option<String> = None;
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            // configparser treats a line that starts with whitespace as
            // a continuation of the current option's value whenever the
            // section already has an option: the stripped line is appended
            // to the value after a newline, whatever the line contains.
            // With no current option the line is parsed normally below.
            if raw_line.starts_with(char::is_whitespace)
                && let (Some(section), Some(key)) = (&current, &last_key)
            {
                let map = sections.get_mut(section).expect("current section");
                let value = map.get_mut(key).expect("last option");
                value.push('\n');
                value.push_str(line);
                continue;
            }
            if line.starts_with('[') {
                let end = line.find(']').ok_or_else(|| {
                    // configparser raises MissingSectionHeaderError for a
                    // bracket line outside any section, ParsingError inside
                    // one; the latter renders as invalid-desktopfile.
                    if current.is_none() {
                        (
                            Level::Error,
                            "desktopfile-missing-header",
                            vec![filename.to_string()],
                        )
                    } else {
                        (
                            Level::Error,
                            "invalid-desktopfile",
                            vec![
                                filename.to_string(),
                                "Source contains parsing errors".to_string(),
                            ],
                        )
                    }
                })?;
                let name = line[1..end].to_string();
                if sections.contains_key(&name) {
                    return Err((
                        Level::Error,
                        "desktopfile-duplicate-section",
                        vec![filename.to_string(), format!("[{name}]")],
                    ));
                }
                sections.insert(name.clone(), HashMap::new());
                current = Some(name);
                last_key = None;
                continue;
            }
            let section = current.clone().ok_or((
                Level::Error,
                "desktopfile-missing-header",
                vec![filename.to_string()],
            ))?;
            let eq = line.find('=').ok_or((
                Level::Error,
                "invalid-desktopfile",
                // configparser's ParsingError message, first colon-part.
                vec![
                    filename.to_string(),
                    "Source contains parsing errors".to_string(),
                ],
            ))?;
            // configparser lowercases keys.
            let key = line[..eq].trim().to_lowercase();
            if key.is_empty() {
                // configparser raises ParsingError for a line with no key
                // before the separator, and the GKeyFile parser rejects
                // the same line as not a key-value pair.
                return Err((
                    Level::Error,
                    "invalid-desktopfile",
                    vec![
                        filename.to_string(),
                        "Source contains parsing errors".to_string(),
                    ],
                ));
            }
            let value = line[eq + 1..].trim().to_string();
            let map = sections.get_mut(&section).expect("current section");
            if map.contains_key(&key) {
                return Err((
                    Level::Error,
                    "desktopfile-duplicate-option",
                    vec![filename.to_string(), format!("[{section}]/{key}")],
                ));
            }
            map.insert(key.clone(), value);
            last_key = Some(key);
        }
        Ok(sections)
    }

    /// `desktop-file-validate` output, when the tool exists.
    ///
    /// Returns `Err` when the validator's output is not valid UTF-8. The
    /// validator must run under the reference's locale (`LC_ALL=en_US.UTF-8`):
    /// there glib echoes the offending bytes raw, so the strict decode raises
    /// and the outer handler emits only `non-utf8-desktopfile` without ever
    /// parsing. Under `LC_ALL=C` glib escapes the bytes instead and the decode
    /// succeeds, producing spurious `invalid-desktopfile` findings.
    fn external_validate(&self, path: &str) -> Result<Vec<String>, std::string::FromUtf8Error> {
        let Some(mut cmd) = self.validator.command() else {
            return Ok(Vec::new());
        };
        let out = cmd
            .arg(path)
            .env("LC_ALL", "en_US.UTF-8")
            .env("LANGUAGE", "en_US")
            .output();
        let Ok(out) = out else { return Ok(Vec::new()) };
        if out.status.success() {
            return Ok(Vec::new());
        }
        // Decode the concatenated bytes once: a multi-byte sequence
        // straddling the stdout/stderr boundary must not fail the decode.
        let mut combined = out.stdout;
        combined.extend_from_slice(&out.stderr);
        let text = String::from_utf8(combined)?;
        Ok(Self::parse_validate_output(&text))
    }

    /// Pull `error: ...` messages out of validator output. The reference
    /// takes `line.split('error: ')[1]`; `split().nth(1)` is the same
    /// segment (a second `error: ` truncates the message in both).
    fn parse_validate_output(text: &str) -> Vec<String> {
        let mut errors = Vec::new();
        for line in text.lines() {
            if let Some(msg) = line.split("error: ").nth(1) {
                errors.push(msg.to_string());
            }
        }
        if errors.is_empty() {
            errors.push(String::new());
        }
        errors
    }

    /// Strip one layer of surrounding double quotes from an Exec first
    /// token: the Desktop Entry specification permits double-quoted
    /// arguments, and the quoted spelling names the same binary.
    /// An unbalanced or lone quote is left alone: it names no binary
    /// the check could resolve.
    fn unquote_exec_token(token: &str) -> &str {
        if token.len() >= 2 && token.starts_with('"') && token.ends_with('"') {
            &token[1..token.len() - 1]
        } else {
            token
        }
    }

    /// Whether the Exec binary resolves (in the package or on the live root).
    fn binary_exists(pkg: &Pkg, binary: &str) -> bool {
        if binary.starts_with('/') {
            let full = Path::new(pkg.dir_name()).join(binary.trim_start_matches('/'));
            if full.exists() {
                return true;
            }
            // Merged-/usr systems link /bin and /sbin to /usr/bin and
            // /usr/sbin, so an absolute path through the legacy directory
            // resolves when the package ships the merged counterpart.
            if let Some(rest) = binary.strip_prefix("/sbin/") {
                // Sanitize the remainder: a leading slash would make
                // join() replace the package root with a host-absolute
                // path, and an empty remainder would let the merged
                // directory itself satisfy the lookup.
                let rest = rest.trim_start_matches('/');
                if rest.is_empty() {
                    return false;
                }
                return Path::new(pkg.dir_name())
                    .join("usr/sbin")
                    .join(rest)
                    .exists();
            }
            if let Some(rest) = binary.strip_prefix("/bin/") {
                let rest = rest.trim_start_matches('/');
                if rest.is_empty() {
                    return false;
                }
                return Path::new(pkg.dir_name())
                    .join("usr/bin")
                    .join(rest)
                    .exists();
            }
            return false;
        }
        STANDARD_BIN_DIRS.iter().any(|d| {
            Path::new(pkg.dir_name())
                .join(d.trim_start_matches('/'))
                .join(binary)
                .exists()
        })
    }

    /// The merged-/usr counterpart of a legacy-directory absolute
    /// path, mirroring `binary_exists`: `/sbin/x` to `/usr/sbin/x`
    /// and `/bin/x` to `/usr/bin/x`. `None` for any other path.
    fn usrmerge_counterpart(path: &str) -> Option<String> {
        if let Some(rest) = path.strip_prefix("/sbin/") {
            return Some(format!("/usr/sbin/{rest}"));
        }
        if let Some(rest) = path.strip_prefix("/bin/") {
            return Some(format!("/usr/bin/{rest}"));
        }
        None
    }

    /// Paths an Exec token can resolve through: the token itself
    /// (plus its merged-/usr counterpart for absolute paths) for
    /// absolute tokens, every standard bin dir for bare tokens.
    /// A bare token never resolves outside the bin dirs: a plugin
    /// or directory named like the token is not on PATH.
    fn candidate_paths(binary: &str) -> Vec<String> {
        if binary.starts_with('/') {
            let mut paths = vec![binary.to_string()];
            if let Some(counterpart) = Self::usrmerge_counterpart(binary) {
                paths.push(counterpart);
            }
            paths
        } else {
            STANDARD_BIN_DIRS
                .iter()
                .map(|d| format!("{d}/{binary}"))
                .collect()
        }
    }

    /// Whether the Exec token resolves through a sibling's
    /// shipped regular files: any candidate path present in
    /// the build's inventory.
    fn resolves_via_build(build: &DesktopBuild, binary: &str) -> bool {
        Self::candidate_paths(binary)
            .iter()
            .any(|path| build.regular.contains(path))
    }

    fn build_mut(&mut self, key: &str) -> &mut DesktopBuild {
        if !self.builds.contains_key(key) {
            self.order.push(key.to_string());
            self.builds.insert(key.to_string(), DesktopBuild::default());
        }
        self.builds.get_mut(key).expect("just inserted")
    }

    /// Record one binary package's contribution to the run-scoped
    /// verdict: its shipped regular files and symlink targets,
    /// keyed by its build. Ghost entries are not shipped content
    /// and never resolve a token. Packages without a build key
    /// contribute nothing: no build the run can judge owns them.
    fn accumulate_inventory(&mut self, pkg: &Pkg) {
        let Some(key) = binary_source_key(pkg) else {
            return;
        };
        let build = self.build_mut(&key);
        for file in &pkg.files {
            if is_ghost_file(pkg, file) {
                continue;
            }
            if is_reg(file.mode) {
                build.regular.insert(file.name.clone());
            } else if is_symlink(file.mode) {
                build
                    .symlinks
                    .insert(file.name.clone(), file.linkto.clone());
            }
        }
    }

    fn emit_without_binary(out: &mut Filter, cand: &DesktopBinaryCandidate) {
        out.add_info(make_finding(
            &cand.pkg_name,
            &cand.arch,
            Level::Warning,
            "desktopfile-without-binary",
            vec![cand.filename.clone(), cand.binary.clone()],
            None,
        ));
    }

    /// Normalise an absolute path, resolving `.` and `..` segments, so a
    /// symlink chain step matches the package file list exactly.
    fn normalize_icon_path(path: &str) -> String {
        let mut parts: Vec<&str> = Vec::new();
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                _ => parts.push(part),
            }
        }
        format!("/{}", parts.join("/"))
    }

    /// Follow a package file through its symlink chain, staying inside
    /// this package. Returns the final entry, or `None` when the chain
    /// leaves the package or loops: both stay silent, since the icon
    /// may resolve through a sibling or system package.
    fn resolve_icon_file<'a>(pkg: &'a Pkg, start: &str) -> Option<&'a PkgFile> {
        let mut current = start.to_string();
        for _ in 0..10 {
            let entry = pkg.files.iter().find(|f| f.name == current)?;
            if !is_symlink(entry.mode) {
                return Some(entry);
            }
            let linkto = entry.linkto.as_str();
            if linkto.is_empty() {
                return None;
            }
            current = if linkto.starts_with('/') {
                linkto.to_string()
            } else {
                let dir = current.rfind('/').map_or("", |i| &current[..i]);
                if dir.is_empty() {
                    linkto.to_string()
                } else {
                    Self::normalize_icon_path(&format!("{dir}/{linkto}"))
                }
            };
        }
        None
    }

    /// Files under the icon theme dirs (or pixmaps) that could provide
    /// a bare or suffixed Icon name. Directory entries never count: a
    /// directory named like the icon is not an icon file.
    fn theme_icon_candidates<'a>(pkg: &'a Pkg, icon: &str, suffixed: bool) -> Vec<&'a PkgFile> {
        pkg.files
            .iter()
            .filter(|f| {
                if is_dir(f.mode) {
                    return false;
                }
                let name = f.name.as_str();
                if !(name.starts_with("/usr/share/icons/")
                    || name.starts_with("/usr/share/pixmaps/"))
                {
                    return false;
                }
                let base = name.rsplit('/').next().unwrap_or(name);
                if suffixed {
                    base == icon
                } else {
                    base == icon
                        || match base.rsplit_once('.') {
                            Some((stem, ext)) => stem == icon && ICON_EXTENSIONS.contains(&ext),
                            None => false,
                        }
                }
            })
            .collect()
    }

    /// Icon existence for one desktop entry (issue #1223). Fire only
    /// where absence is decidable from this package alone: an absolute
    /// Icon path must resolve to a regular file in this package, and a
    /// resolved icon file must be world-readable. A bare or suffixed
    /// name never fires on absence (a system icon theme may provide
    /// it). Ghost entries, symlink chains leaving the package, and
    /// loops all stay silent. Only the `[Desktop Entry]` Icon is read;
    /// action icons are out of scope.
    fn check_icon(pkg: &Pkg, out: &mut Filter, filename: &str, entry: &HashMap<String, String>) {
        let Some(icon) = entry.get("icon") else {
            return;
        };
        if icon.is_empty() || icon.contains("%{") {
            return;
        }
        if icon.starts_with('/') {
            let Some(start) = pkg.files.iter().find(|f| f.name == *icon) else {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "desktopfile-icon-not-found",
                    &[filename, icon],
                );
                return;
            };
            if start.is_ghost() {
                return;
            }
            match Self::resolve_icon_file(pkg, icon) {
                None => {}
                Some(target) => {
                    if target.is_ghost() {
                        return;
                    }
                    if !is_reg(target.mode) {
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "desktopfile-icon-not-found",
                            &[filename, icon],
                        );
                    } else if target.mode & 0o004 == 0 {
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "desktopfile-icon-not-readable",
                            &[filename, icon],
                        );
                    }
                }
            }
            return;
        }
        if icon.contains('/') {
            // A relative path is malformed; the validator's domain.
            return;
        }
        let suffixed = icon
            .rsplit_once('.')
            .is_some_and(|(_, ext)| ICON_EXTENSIONS.contains(&ext));
        let mut readable = false;
        let mut unreadable = false;
        for candidate in Self::theme_icon_candidates(pkg, icon, suffixed) {
            if candidate.is_ghost() {
                // A managed icon file counts as present.
                return;
            }
            match Self::resolve_icon_file(pkg, &candidate.name) {
                None => {}
                Some(target) => {
                    if target.is_ghost() {
                        return;
                    }
                    if !is_reg(target.mode) {
                        continue;
                    }
                    if target.mode & 0o004 == 0 {
                        unreadable = true;
                    } else {
                        readable = true;
                    }
                }
            }
        }
        if unreadable && !readable {
            add_info(
                out,
                Level::Warning,
                pkg,
                "desktopfile-icon-not-readable",
                &[filename, icon],
            );
        }
    }
}

impl MenuXDGCheck {
    /// Upstream rpmlint#19: desktop entries with unexpanded RPM macros
    /// (`Name=%{title}`) — the macro was never expanded at build time.
    /// Only the display fields are scanned, including their localized
    /// variants (`Name[de]=`, ...); `Exec=` legitimately contains
    /// `%`-codes (`%f`, `%U`) but never `%{`.
    fn check_unexpanded_macros(
        &self,
        pkg: &Pkg,
        out: &mut Filter,
        filename: &str,
        entry: &HashMap<String, String>,
    ) {
        // Keys are already lowercased by parse_desktop. Sort for
        // deterministic emission order.
        let mut keys: Vec<&String> = entry.keys().collect();
        keys.sort();
        for key in keys {
            let base = key.split("[").next().unwrap_or(key);
            let field = match base {
                "name" => "Name",
                "comment" => "Comment",
                "icon" => "Icon",
                _ => continue,
            };
            let value = &entry[key];
            if !value.contains("%{") {
                continue;
            }
            // Detail keeps the localized key shape: Name[de]=%{title}.
            let detail_field = format!("{}{}", field, &key[base.len()..]);
            add_info(
                out,
                Level::Warning,
                pkg,
                "unexpanded-macro-in-desktop-file",
                &[filename, &format!("{}={}", detail_field, value)],
            );
        }
    }
}

impl Check for MenuXDGCheck {
    fn name(&self) -> &'static str {
        "MenuXDGCheck"
    }

    fn check_source(&mut self, pkg: &Pkg, _config: &Config, _out: &mut Filter) {
        // A source package opens its build's gate: the run holds
        // the build only when a source package's spelling equals
        // the build's key. Source presence is the whole gate.
        for key in source_package_keys(pkg) {
            self.sources.insert(key);
        }
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        // Every binary package contributes its shipped files to
        // its build's inventory, whether or not it carries a
        // desktop file: it may be the sibling that resolves one.
        self.accumulate_inventory(pkg);
        for pkgfile in &pkg.files {
            let filename = pkgfile.name.as_str();
            if !is_match(&self.file_regex, filename) {
                continue;
            }
            // AbstractCheck.py:45 drops ghosts from the dispatch list. A ghost
            // desktop file has no payload, so the validator reports it missing
            // and the port would raise invalid-desktopfile for it.
            if pkg.ghost_files.contains(&pkgfile.name) {
                continue;
            }
            self.checked_files += 1;
            // The reference decodes the validator output as UTF-8
            // (`text=True`) under its en_US.UTF-8 locale, where the validator
            // echoes the offending bytes raw; the decode raises and the outer
            // handler emits only non-utf8-desktopfile. Mirror that: on decode
            // failure, skip both the validator findings and the parse.
            let errors = match self.external_validate(&pkgfile.path) {
                Ok(errors) => errors,
                Err(e) => {
                    let detail = format!("Unicode error: {e}");
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "non-utf8-desktopfile",
                        &[filename, &detail],
                    );
                    continue;
                }
            };
            for error in errors {
                if error.is_empty() {
                    add_info(out, Level::Error, pkg, "invalid-desktopfile", &[filename]);
                } else {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "invalid-desktopfile",
                        &[filename, &error],
                    );
                }
            }

            let bytes = std::fs::read(&pkgfile.path).unwrap_or_default();
            let content = match String::from_utf8(bytes) {
                Ok(c) => c,
                Err(e) => {
                    let detail = format!("Unicode error: {e}");
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "non-utf8-desktopfile",
                        &[filename, &detail],
                    );
                    continue;
                }
            };
            match Self::parse_desktop(&content, filename) {
                Err((level, finding, details)) => {
                    let refs: Vec<&str> = details.iter().map(String::as_str).collect();
                    add_info(out, level, pkg, finding, &refs);
                }
                Ok(sections) => {
                    if let Some(entry) = sections.get("Desktop Entry") {
                        self.check_unexpanded_macros(pkg, out, filename, entry);
                    }
                    if let Some(entry) = sections.get("Desktop Entry")
                        && let Some(exec) = entry.get("exec")
                    {
                        // The reference uses `partition(' ')`, which splits
                        // on the first ASCII space only.
                        let binary = exec.split(' ').next().unwrap_or("");
                        let binary = Self::unquote_exec_token(binary);
                        // Anything the package itself does not resolve
                        // is held for `after_checks`, where the
                        // run-scoped sibling credit is judged:
                        // emitting here would fire before the
                        // sibling's inventory is known.
                        if !binary.is_empty() && !Self::binary_exists(pkg, binary) {
                            let candidate = DesktopBinaryCandidate {
                                pkg_name: pkg.name.clone(),
                                arch: pkg.arch.clone(),
                                filename: filename.to_string(),
                                binary: binary.to_string(),
                            };
                            match binary_source_key(pkg) {
                                Some(key) => {
                                    let build = self.build_mut(&key);
                                    build.candidates.push(candidate);
                                }
                                None => self.unkeyed.push(candidate),
                            }
                        }
                    }
                    if let Some(entry) = sections.get("Desktop Entry") {
                        Self::check_icon(pkg, out, filename, entry);
                    }
                }
            }
        }
    }

    /// The deferred `desktopfile-without-binary` verdict: a
    /// candidate is credited only when its build is
    /// source-complete in this run -- the run holds the build's
    /// source package -- and its token resolves through a
    /// sibling's shipped files. Every other candidate fires, so
    /// source-absent (partial) and single-package runs report
    /// exactly the per-package verdict.
    fn after_checks(&mut self, _config: &Config, out: &mut Filter) {
        for cand in &self.unkeyed {
            Self::emit_without_binary(out, cand);
        }
        for key in &self.order {
            let build = &self.builds[key];
            let complete = self.sources.contains(key);
            for cand in &build.candidates {
                if complete && Self::resolves_via_build(build, &cand.binary) {
                    continue;
                }
                Self::emit_without_binary(out, cand);
            }
        }
    }

    fn reset(&mut self) {
        self.checked_files = 0;
        self.sources.clear();
        self.order.clear();
        self.builds.clear();
        self.unkeyed.clear();
    }

    fn export_state(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        Some(Box::new(DesktopBuildState {
            sources: std::mem::take(&mut self.sources),
            order: std::mem::take(&mut self.order),
            builds: std::mem::take(&mut self.builds),
            unkeyed: std::mem::take(&mut self.unkeyed),
        }))
    }

    fn import_state(&mut self, state: Box<dyn std::any::Any + Send>) {
        if let Ok(mut state) = state.downcast::<DesktopBuildState>() {
            self.sources.extend(state.sources.drain());
            self.unkeyed.append(&mut state.unkeyed);
            for key in std::mem::take(&mut state.order) {
                let Some(data) = state.builds.remove(&key) else {
                    continue;
                };
                match self.builds.get_mut(&key) {
                    Some(mine) => {
                        mine.regular.extend(data.regular);
                        mine.symlinks.extend(data.symlinks);
                        mine.candidates.extend(data.candidates);
                    }
                    None => {
                        self.order.push(key.clone());
                        self.builds.insert(key, data);
                    }
                }
            }
        }
    }

    fn checked_files(&self) -> Option<usize> {
        Some(self.checked_files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::color::Color;
    use crate::pkg::pkgfile::PkgFile;

    #[test]
    fn valid_desktop_parses() {
        let content = "[Desktop Entry]\nName=Foo\nExec=foo\n";
        let sections = MenuXDGCheck::parse_desktop(content, "foo.desktop").unwrap();
        // configparser lowercases keys.
        assert_eq!(sections["Desktop Entry"]["exec"], "foo".to_string());
    }

    #[test]
    fn keys_are_case_insensitive() {
        let content = "[Desktop Entry]\nName=Foo\nEXEC=foo\nExec=bar\n";
        let err = MenuXDGCheck::parse_desktop(content, "foo.desktop").unwrap_err();
        assert_eq!(err.1, "desktopfile-duplicate-option");
    }

    #[test]
    fn unclosed_bracket_before_section_is_missing_header() {
        // configparser raises MissingSectionHeaderError here.
        let err = MenuXDGCheck::parse_desktop("[foo\nName=Bar\n", "foo.desktop").unwrap_err();
        assert_eq!(err.1, "desktopfile-missing-header");
    }

    #[test]
    fn unclosed_bracket_in_section_is_invalid() {
        // configparser raises ParsingError here.
        let err = MenuXDGCheck::parse_desktop("[a]\nName=Foo\n[bad\n", "foo.desktop").unwrap_err();
        assert_eq!(err.1, "invalid-desktopfile");
        assert_eq!(err.2[1], "Source contains parsing errors");
    }

    #[test]
    fn missing_equals_is_invalid() {
        let err = MenuXDGCheck::parse_desktop("[a]\nName Foo\n", "foo.desktop").unwrap_err();
        assert_eq!(err.1, "invalid-desktopfile");
        assert_eq!(err.2[1], "Source contains parsing errors");
    }

    #[test]
    fn indented_line_continues_previous_value() {
        // configparser appends a line that starts with whitespace to the
        // current option's value instead of failing the parse.
        let content = "[Desktop Entry]\nName=Foo\n  continued text\nExec=bar\n";
        let sections = MenuXDGCheck::parse_desktop(content, "foo.desktop").unwrap();
        assert_eq!(
            sections["Desktop Entry"]["name"],
            "Foo\ncontinued text".to_string()
        );
        assert_eq!(sections["Desktop Entry"]["exec"], "bar".to_string());
    }

    #[test]
    fn indented_line_with_equals_continues_previous_value() {
        // The continuation rule applies whatever the indented line
        // contains; it does not start a new option.
        let content = "[Desktop Entry]\nName=Foo\n  Other=x\nExec=bar\n";
        let sections = MenuXDGCheck::parse_desktop(content, "foo.desktop").unwrap();
        assert_eq!(
            sections["Desktop Entry"]["name"],
            "Foo\nOther=x".to_string()
        );
        assert!(!sections["Desktop Entry"].contains_key("other"));
    }

    #[test]
    fn indented_option_without_previous_option_parses_as_key() {
        let content = "[Desktop Entry]\n  Name=Foo\n";
        let sections = MenuXDGCheck::parse_desktop(content, "foo.desktop").unwrap();
        assert_eq!(sections["Desktop Entry"]["name"], "Foo".to_string());
    }

    #[test]
    fn indented_line_without_previous_option_or_equals_is_invalid() {
        // configparser raises ParsingError: there is no value to continue.
        let err = MenuXDGCheck::parse_desktop("[Desktop Entry]\n  orphan text\n", "foo.desktop")
            .unwrap_err();
        assert_eq!(err.1, "invalid-desktopfile");
    }

    #[test]
    fn empty_key_is_invalid() {
        let err = MenuXDGCheck::parse_desktop("[Desktop Entry]\nName=Foo\n=value\n", "foo.desktop")
            .unwrap_err();
        assert_eq!(err.1, "invalid-desktopfile");
        assert_eq!(err.2[1], "Source contains parsing errors");
    }

    #[test]
    fn empty_key_as_first_option_is_invalid() {
        let err = MenuXDGCheck::parse_desktop("[Desktop Entry]\n=value\nName=Foo\n", "foo.desktop")
            .unwrap_err();
        assert_eq!(err.1, "invalid-desktopfile");
    }

    #[test]
    fn trailing_junk_after_section_header_is_accepted() {
        // configparser's section pattern is not anchored at the end of
        // the line, so text after the closing bracket is ignored.
        let content = "[Desktop Entry] trailing\nName=Foo\n";
        let sections = MenuXDGCheck::parse_desktop(content, "foo.desktop").unwrap();
        assert_eq!(sections["Desktop Entry"]["name"], "Foo".to_string());
    }

    #[test]
    fn missing_header_is_flagged() {
        let err = MenuXDGCheck::parse_desktop("Name=Foo\n", "foo.desktop").unwrap_err();
        assert_eq!(err.1, "desktopfile-missing-header");
    }

    #[test]
    fn duplicate_section_is_flagged() {
        let content = "[Desktop Entry]\nName=Foo\n[Desktop Entry]\nName=Bar\n";
        let err = MenuXDGCheck::parse_desktop(content, "foo.desktop").unwrap_err();
        assert_eq!(err.1, "desktopfile-duplicate-section");
        assert!(err.2[1].contains("Desktop Entry"));
    }

    #[test]
    fn duplicate_option_is_flagged() {
        let content = "[Desktop Entry]\nName=Foo\nName=Bar\n";
        let err = MenuXDGCheck::parse_desktop(content, "foo.desktop").unwrap_err();
        assert_eq!(err.1, "desktopfile-duplicate-option");
    }

    #[test]
    fn comments_and_blanks_are_skipped() {
        let content = "# comment\n\n[Desktop Entry]\n; another\nName=Foo\n";
        let sections = MenuXDGCheck::parse_desktop(content, "foo.desktop").unwrap();
        assert!(sections.contains_key("Desktop Entry"));
    }

    #[test]
    fn validate_output_truncates_at_second_error_marker() {
        // Matches Python's `line.split('error: ')[1]`.
        let errors =
            MenuXDGCheck::parse_validate_output("f.desktop: error: bad value error: tail\n");
        assert_eq!(errors, vec!["bad value ".to_string()]);
    }

    #[test]
    fn validate_output_without_errors_is_empty_detail() {
        let errors = MenuXDGCheck::parse_validate_output("all good\n");
        assert_eq!(errors, vec![String::new()]);
    }

    #[test]
    fn file_pattern_is_anchored_like_re_match() {
        // AbstractCheck.py:45 applies the pattern with `re.match`; is_match
        // searches, so without `^` a vendored copy under /opt would be
        // validated where the reference never dispatches it.
        let check = MenuXDGCheck::new(&Config::default());
        assert!(is_match(
            &check.file_regex,
            "/usr/share/applications/w6.desktop"
        ));
        assert!(!is_match(
            &check.file_regex,
            "/opt/vendor/usr/share/applications/v.desktop"
        ));
    }

    /// Drive check_binary over a hand-written desktop file: the fcprobe
    /// header is only a shell, the payload is the temp file.
    fn run_desktop(content: &str) -> Vec<(String, String)> {
        // Unique temp file: tests run in parallel and must not share one.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("macrotest.desktop");
        std::fs::write(&path, content).unwrap();
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        let name = "/usr/share/applications/macrotest.desktop";
        pkg.files = vec![crate::pkg::pkgfile::PkgFile {
            name: name.to_string(),
            path: path.to_str().unwrap().to_string(),
            mode: 0o100644,
            ..Default::default()
        }];
        let config = Config::default();
        let mut out = Filter::new(&config, crate::color::Color::for_tty(false)).unwrap();
        let mut check = MenuXDGCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        drop(dir);
        results
    }

    // Upstream rpmlint#19: unexpanded macros in desktop entries.
    #[test]
    fn unexpanded_macro_in_name_warns() {
        let results = run_desktop("[Desktop Entry]\nName=%{title}\nExec=foo\n");
        let lines: Vec<&String> = results
            .iter()
            .filter(|(n, _)| n == "unexpanded-macro-in-desktop-file")
            .map(|(_, l)| l)
            .collect();
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0].contains("W: unexpanded-macro-in-desktop-file"),
            "level: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("Name=%{title}"),
            "field detail: {}",
            lines[0]
        );
    }

    #[test]
    fn unexpanded_macro_in_comment_and_icon_warns() {
        let results =
            run_desktop("[Desktop Entry]\nName=Foo\nComment=%{summary}\nIcon=%{icon}\nExec=foo\n");
        let names: Vec<&str> = results
            .iter()
            .filter(|(n, _)| n == "unexpanded-macro-in-desktop-file")
            .map(|(n, _)| n.as_str())
            .collect();
        // One finding per offending field.
        assert_eq!(names.len(), 2, "unexpected: {results:?}");
    }

    // plusky #251 review: localized display fields are scanned too.
    #[test]
    fn unexpanded_macro_in_localized_name_warns() {
        let results = run_desktop("[Desktop Entry]\nName=Foo\nName[de]=%{title}\nExec=foo\n");
        let lines: Vec<&String> = results
            .iter()
            .filter(|(n, _)| n == "unexpanded-macro-in-desktop-file")
            .map(|(_, l)| l)
            .collect();
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0].contains("W: unexpanded-macro-in-desktop-file"),
            "level: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("Name[de]=%{title}"),
            "localized detail: {}",
            lines[0]
        );
    }

    #[test]
    fn expanded_desktop_entry_is_quiet() {
        // A bare `%` is not a macro: only `%{` marks an unexpanded one.
        let results =
            run_desktop("[Desktop Entry]\nName=100% Foo\nComment=A tool\nIcon=foo\nExec=foo %f\n");
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "unexpanded-macro-in-desktop-file"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn exec_percent_codes_are_not_macros() {
        // `%f`/`%U` in Exec= are desktop field codes, not RPM macros:
        // only Name/Comment/Icon are scanned.
        let results = run_desktop("[Desktop Entry]\nName=Foo\nExec=foo %f %U\n");
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "unexpanded-macro-in-desktop-file"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn non_utf8_desktopfile_is_pinned() {
        // Nothing pins the finding name, level, or the Unicode error prefix,
        // so the divergence entry can rot silently. Pin all three: an
        // invalid-UTF-8 payload must surface as Level::Error
        // non-utf8-desktopfile with a Unicode error detail.
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-menuxdg-nonutf8.desktop");
        std::fs::write(&path, b"[Desktop Entry]\nName=\xff\xfe\n").unwrap();
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        let name = "/usr/share/applications/broken.desktop";
        pkg.files = vec![PkgFile {
            name: name.to_string(),
            path: path.to_str().unwrap().to_string(),
            ..Default::default()
        }];
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = MenuXDGCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        std::fs::remove_file(&path).ok();
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "non-utf8-desktopfile");
        assert!(results[0].1.contains(": E: "), "level: {}", results[0].1);
        assert!(
            results[0].1.contains("Unicode error:"),
            "prefix: {}",
            results[0].1
        );
    }

    #[test]
    fn reset_zeroes_checked_files() {
        let config = Config::default();
        let mut check = MenuXDGCheck::new(&config);
        check.checked_files = 4;
        check.reset();
        assert_eq!(check.checked_files(), Some(0));
    }

    /// Drive check_binary over a desktop file plus icon files, with the
    /// validator pointed at an empty dir so it never runs. Returns only
    /// the icon findings, each with its level.
    fn run_icon_desktop(
        content: &str,
        icon_files: Vec<crate::pkg::pkgfile::PkgFile>,
    ) -> Vec<(String, String, Level)> {
        let dir = tempfile::tempdir().unwrap();
        let app_dir = dir.path().join("usr/share/applications");
        std::fs::create_dir_all(&app_dir).unwrap();
        let path = app_dir.join("app.desktop");
        std::fs::write(&path, content).unwrap();
        let bin_dir = dir.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        let name = "/usr/share/applications/app.desktop";
        pkg.files = vec![crate::pkg::pkgfile::PkgFile {
            name: name.to_string(),
            path: path.to_str().unwrap().to_string(),
            mode: 0o100644,
            ..Default::default()
        }];
        pkg.files.extend(icon_files);
        pkg.ghost_files.clear();
        let config = Config::default();
        let mut out = Filter::new(&config, crate::color::Color::for_tty(false)).unwrap();
        let mut check = MenuXDGCheck::with_tool_dir(Some(&bin_dir));
        check.check_binary(&pkg, &config, &mut out);
        let levels = out.result_levels().to_vec();
        let results: Vec<(String, String, Level)> = out
            .results()
            .iter()
            .zip(levels.iter())
            .filter(|((n, _), _)| n.starts_with("desktopfile-icon"))
            .map(|((n, d), l)| (n.clone(), d.clone(), *l))
            .collect();
        drop(dir);
        results
    }

    fn icon_desktop(icon: &str) -> String {
        format!("[Desktop Entry]\nType=Application\nName=App\nExec=/usr/bin/app\nIcon={icon}\n")
    }

    fn icon_file(name: &str, mode: u32) -> crate::pkg::pkgfile::PkgFile {
        crate::pkg::pkgfile::PkgFile {
            name: name.to_string(),
            mode,
            ..Default::default()
        }
    }

    fn icon_symlink(name: &str, linkto: &str) -> crate::pkg::pkgfile::PkgFile {
        crate::pkg::pkgfile::PkgFile {
            name: name.to_string(),
            mode: 0o120777,
            linkto: linkto.to_string(),
            ..Default::default()
        }
    }

    fn icon_ghost(name: &str) -> crate::pkg::pkgfile::PkgFile {
        crate::pkg::pkgfile::PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            flags: crate::pkg::pkgfile::RPMFILE_GHOST,
            ..Default::default()
        }
    }

    fn assert_icon_finding(results: &[(String, String, Level)], tag: &str, icon: &str) {
        assert_eq!(results.len(), 1, "expected one icon finding: {results:?}");
        assert_eq!(results[0].0, tag, "tag: {results:?}");
        assert_eq!(results[0].2, Level::Warning, "level: {results:?}");
        assert!(
            results[0].1.contains(icon),
            "detail names the icon: {:?}",
            results[0].1
        );
    }

    #[test]
    fn icon_absolute_missing_fires() {
        let results = run_icon_desktop(&icon_desktop("/usr/share/doc/foo/icons/Foo.png"), vec![]);
        assert_icon_finding(&results, "desktopfile-icon-not-found", "Foo.png");
    }

    #[test]
    fn icon_absolute_present_silent() {
        let results = run_icon_desktop(
            &icon_desktop("/usr/share/icons/hicolor/48x48/apps/app.png"),
            vec![icon_file(
                "/usr/share/icons/hicolor/48x48/apps/app.png",
                0o100644,
            )],
        );
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_absolute_unreadable_fires() {
        let results = run_icon_desktop(
            &icon_desktop("/usr/share/icons/hicolor/48x48/apps/app.png"),
            vec![icon_file(
                "/usr/share/icons/hicolor/48x48/apps/app.png",
                0o100600,
            )],
        );
        assert_icon_finding(&results, "desktopfile-icon-not-readable", "app.png");
    }

    #[test]
    fn icon_absolute_symlink_to_file_silent() {
        let results = run_icon_desktop(
            &icon_desktop("/usr/share/icons/hicolor/48x48/apps/app.png"),
            vec![
                icon_symlink(
                    "/usr/share/icons/hicolor/48x48/apps/app.png",
                    "/usr/share/app/icon.png",
                ),
                icon_file("/usr/share/app/icon.png", 0o100644),
            ],
        );
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_absolute_symlink_to_unreadable_fires() {
        let results = run_icon_desktop(
            &icon_desktop("/usr/share/icons/hicolor/48x48/apps/app.png"),
            vec![
                icon_symlink(
                    "/usr/share/icons/hicolor/48x48/apps/app.png",
                    "/usr/share/app/icon.png",
                ),
                icon_file("/usr/share/app/icon.png", 0o100600),
            ],
        );
        assert_icon_finding(&results, "desktopfile-icon-not-readable", "app.png");
    }

    #[test]
    fn icon_absolute_symlink_external_silent() {
        let results = run_icon_desktop(
            &icon_desktop("/usr/share/icons/hicolor/48x48/apps/app.png"),
            vec![icon_symlink(
                "/usr/share/icons/hicolor/48x48/apps/app.png",
                "/usr/share/other/icon.png",
            )],
        );
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_absolute_symlink_loop_silent() {
        let results = run_icon_desktop(
            &icon_desktop("/usr/share/icons/hicolor/48x48/apps/app.png"),
            vec![
                icon_symlink(
                    "/usr/share/icons/hicolor/48x48/apps/app.png",
                    "/usr/share/app/other.png",
                ),
                icon_symlink(
                    "/usr/share/app/other.png",
                    "/usr/share/icons/hicolor/48x48/apps/app.png",
                ),
            ],
        );
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_absolute_ghost_silent() {
        let results = run_icon_desktop(
            &icon_desktop("/usr/share/icons/hicolor/48x48/apps/app.png"),
            vec![icon_ghost("/usr/share/icons/hicolor/48x48/apps/app.png")],
        );
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_absolute_dir_fires() {
        let results = run_icon_desktop(
            &icon_desktop("/usr/share/icons/hicolor/48x48/apps/app.png"),
            vec![icon_file(
                "/usr/share/icons/hicolor/48x48/apps/app.png",
                0o40755,
            )],
        );
        assert_icon_finding(&results, "desktopfile-icon-not-found", "app.png");
    }

    #[test]
    fn icon_absolute_local_path_fires() {
        let results = run_icon_desktop(&icon_desktop("/usr/local/share/foo/icons/foo.png"), vec![]);
        assert_icon_finding(&results, "desktopfile-icon-not-found", "foo.png");
    }

    #[test]
    fn icon_bare_resolved_silent() {
        let results = run_icon_desktop(
            &icon_desktop("app"),
            vec![icon_file(
                "/usr/share/icons/hicolor/48x48/apps/app.png",
                0o100644,
            )],
        );
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_bare_unresolved_silent() {
        let results = run_icon_desktop(&icon_desktop("app"), vec![]);
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_bare_unreadable_fires() {
        let results = run_icon_desktop(
            &icon_desktop("app"),
            vec![icon_file(
                "/usr/share/icons/hicolor/48x48/apps/app.png",
                0o100600,
            )],
        );
        assert_icon_finding(&results, "desktopfile-icon-not-readable", "app");
    }

    #[test]
    fn icon_bare_dir_match_silent() {
        let results = run_icon_desktop(
            &icon_desktop("app"),
            vec![icon_file("/usr/share/pixmaps/app", 0o40755)],
        );
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_bare_wrong_extension_silent() {
        let results = run_icon_desktop(
            &icon_desktop("app"),
            vec![icon_file(
                "/usr/share/icons/hicolor/48x48/apps/app.jpg",
                0o100644,
            )],
        );
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_bare_prefix_no_match_silent() {
        let results = run_icon_desktop(
            &icon_desktop("app"),
            vec![icon_file(
                "/usr/share/icons/hicolor/48x48/apps/app2.png",
                0o100644,
            )],
        );
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_suffixed_resolved_silent() {
        let results = run_icon_desktop(
            &icon_desktop("app.png"),
            vec![icon_file(
                "/usr/share/icons/hicolor/48x48/apps/app.png",
                0o100644,
            )],
        );
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_suffixed_wrong_extension_silent() {
        let results = run_icon_desktop(
            &icon_desktop("app.png"),
            vec![icon_file(
                "/usr/share/icons/hicolor/48x48/apps/app.svg",
                0o100644,
            )],
        );
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_suffixed_unreadable_fires() {
        let results = run_icon_desktop(
            &icon_desktop("app.png"),
            vec![icon_file(
                "/usr/share/icons/hicolor/48x48/apps/app.png",
                0o100600,
            )],
        );
        assert_icon_finding(&results, "desktopfile-icon-not-readable", "app.png");
    }

    #[test]
    fn icon_missing_silent() {
        let results = run_icon_desktop(
            "[Desktop Entry]\nType=Application\nName=App\nExec=/usr/bin/app\n",
            vec![],
        );
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_empty_silent() {
        let results = run_icon_desktop(&icon_desktop(""), vec![]);
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_macro_silent() {
        let results = run_icon_desktop(&icon_desktop("%{foo}"), vec![]);
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_relative_slash_silent() {
        let results = run_icon_desktop(&icon_desktop("icons/app.png"), vec![]);
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn icon_theme_symlinks_external_silent() {
        let results = run_icon_desktop(
            &icon_desktop("veusz"),
            vec![
                icon_symlink(
                    "/usr/share/icons/hicolor/48x48/apps/veusz.png",
                    "/usr/share/veusz/icons/veusz_48.png",
                ),
                icon_symlink(
                    "/usr/share/icons/hicolor/scalable/apps/veusz.svg",
                    "/usr/share/veusz/icons/veusz.svg",
                ),
            ],
        );
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    /// Drive check_binary over a hand-written desktop file, seeding
    /// the given relative paths into the fixture package's extracted
    /// directory first so binary_exists can resolve against them.
    /// The extraction root is a fresh tempdir per call: tests run in
    /// parallel and must not share a seeded directory.
    fn run_desktop_seeded(content: &str, seeded: &[&str]) -> Vec<(String, String)> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seededtest.desktop");
        std::fs::write(&path, content).unwrap();
        let extract_root = tempfile::tempdir().unwrap();
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, extract_root.path(), true).expect("open fixture pkg");
        let root = Path::new(pkg.dir_name()).to_path_buf();
        for rel in seeded {
            let full = root.join(rel);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&full, b"").unwrap();
        }
        let name = "/usr/share/applications/seededtest.desktop";
        pkg.files = vec![PkgFile {
            name: name.to_string(),
            path: path.to_str().unwrap().to_string(),
            mode: 0o100644,
            ..Default::default()
        }];
        let config = Config::default();
        let mut out = Filter::new(&config, crate::color::Color::for_tty(false)).unwrap();
        let mut check = MenuXDGCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        check.after_checks(&config, &mut out);
        let results = out.results().to_vec();
        drop(dir);
        drop(extract_root);
        results
    }

    fn without_binary(results: &[(String, String)]) -> Vec<&String> {
        results
            .iter()
            .filter(|(n, _)| n == "desktopfile-without-binary")
            .map(|(_, l)| l)
            .collect()
    }

    #[test]
    fn bare_exec_token_resolves_in_bin_dirs() {
        let results = run_desktop_seeded("[Desktop Entry]\nName=Foo\nExec=foo\n", &["usr/bin/foo"]);
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn quoted_exec_token_resolves_when_unquoted_binary_present() {
        // gsmartcontrol ships Exec="/usr/bin/gsmartcontrol-root"
        // (quoted) with the binary in the package: the quoted spelling
        // names the same binary and must not fire.
        let results = run_desktop_seeded(
            "[Desktop Entry]\nName=Foo\nExec=\"/usr/bin/gsmartcontrol-root\"\n",
            &["usr/bin/gsmartcontrol-root"],
        );
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn quoted_exec_token_still_fires_when_binary_absent() {
        let results =
            run_desktop_seeded("[Desktop Entry]\nName=Foo\nExec=\"/usr/bin/absent\"\n", &[]);
        let lines = without_binary(&results);
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0].contains("/usr/bin/absent"),
            "detail carries the resolved name: {}",
            lines[0]
        );
        assert!(
            !lines[0].contains('\"'),
            "detail carries no quotes: {}",
            lines[0]
        );
    }

    #[test]
    fn unbalanced_quote_token_still_fires() {
        let results = run_desktop_seeded("[Desktop Entry]\nName=Foo\nExec=\"foo\n", &[]);
        let lines = without_binary(&results);
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn usrmerge_sbin_resolves_via_usr_sbin() {
        // yast2 ships Exec=/sbin/yast2 with only /usr/sbin/yast2 in
        // the package: on merged-/usr systems /sbin is a symlink to
        // /usr/sbin, so the entry resolves.
        let results = run_desktop_seeded(
            "[Desktop Entry]\nName=Foo\nExec=/sbin/yast2\n",
            &["usr/sbin/yast2"],
        );
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn usrmerge_bin_resolves_via_usr_bin() {
        let results = run_desktop_seeded(
            "[Desktop Entry]\nName=Foo\nExec=/bin/tool\n",
            &["usr/bin/tool"],
        );
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn usrmerge_absent_still_fires() {
        let results = run_desktop_seeded("[Desktop Entry]\nName=Foo\nExec=/sbin/yast2\n", &[]);
        let lines = without_binary(&results);
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn binary_exists_usrmerge_edges() {
        let extract_root = tempfile::tempdir().unwrap();
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let pkg = Pkg::open(&rpm, extract_root.path(), true).expect("open fixture pkg");
        let root = Path::new(pkg.dir_name()).to_path_buf();
        std::fs::create_dir_all(root.join("usr/sbin")).unwrap();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::fs::write(root.join("usr/sbin/yast2"), b"").unwrap();
        std::fs::write(root.join("usr/bin/tool"), b"").unwrap();
        assert!(MenuXDGCheck::binary_exists(&pkg, "/sbin/yast2"));
        assert!(MenuXDGCheck::binary_exists(&pkg, "/bin/tool"));
        assert!(!MenuXDGCheck::binary_exists(&pkg, "/sbin/missing"));
        assert!(!MenuXDGCheck::binary_exists(&pkg, "/bin/missing"));
        // No trailing component: not a legacy-directory path.
        assert!(!MenuXDGCheck::binary_exists(&pkg, "/sbin"));
        assert!(!MenuXDGCheck::binary_exists(&pkg, "/bin"));
        // A name merely starting with the legacy prefix is not one.
        assert!(!MenuXDGCheck::binary_exists(&pkg, "/sbinfoo/tool"));
        // Doubled slashes: the remainder is sanitized, so the lookup
        // stays inside the package root and never probes the host.
        assert!(MenuXDGCheck::binary_exists(&pkg, "/sbin//yast2"));
        assert!(!MenuXDGCheck::binary_exists(&pkg, "/sbin//etc/passwd"));
        assert!(!MenuXDGCheck::binary_exists(&pkg, "/bin//etc/passwd"));
        // Bare legacy directory: an empty remainder never satisfies,
        // even though the merged directory itself exists.
        assert!(!MenuXDGCheck::binary_exists(&pkg, "/sbin/"));
        assert!(!MenuXDGCheck::binary_exists(&pkg, "/bin/"));
    }

    /// Drive one check instance over several packages in order,
    /// then the deferred verdicts (`after_checks`).
    fn run_menu_multi(pkgs: &[Pkg]) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, crate::color::Color::for_tty(false)).unwrap();
        let mut check = MenuXDGCheck::new(&config);
        for pkg in pkgs {
            check.check(pkg, &config, &mut out);
        }
        check.after_checks(&config, &mut out);
        out.results().to_vec()
    }

    /// A fixture package with the given name and file list,
    /// opened from the fcprobe RPM so every fixture shares its
    /// build key (`fcprobe-1-1.src.rpm`).
    fn menu_pkg(dir: &tempfile::TempDir, name: &str, files: Vec<PkgFile>) -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, dir.path(), true).expect("open fixture pkg");
        pkg.name = name.to_string();
        pkg.files = files;
        pkg
    }

    /// The run's source package for the fcprobe build: the header
    /// identity it derives (`fcprobe-1-1.src.rpm`) is the `SOURCERPM`
    /// every fixture member carries, so its presence makes the
    /// build complete.
    fn menu_src_pkg(dir: &tempfile::TempDir) -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, dir.path(), true).expect("open fixture pkg");
        pkg.is_source = true;
        pkg.files = Vec::new();
        pkg
    }

    /// A fixture package of another build (fsf-address-fixture
    /// key), for foreign-source and cross-build tests.
    fn menu_foreign_pkg(dir: &tempfile::TempDir, name: &str, files: Vec<PkgFile>) -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fsf-address-fixture-1.0-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, dir.path(), true).expect("open fixture pkg");
        pkg.name = name.to_string();
        pkg.files = files;
        pkg
    }

    /// A desktop file entry whose content lives in `dir`: the
    /// check reads the entry through its on-disk path.
    fn desktop_entry(dir: &std::path::Path, filename: &str, exec: &str) -> PkgFile {
        let path = dir.join("test.desktop");
        std::fs::write(
            &path,
            format!("[Desktop Entry]\nType=Application\nName=Test\nExec={exec}\n"),
        )
        .unwrap();
        PkgFile {
            name: filename.to_string(),
            path: path.to_str().unwrap().to_string(),
            mode: 0o100644,
            ..Default::default()
        }
    }

    fn reg_entry(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            ..Default::default()
        }
    }

    fn link_entry(name: &str, linkto: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o120777,
            linkto: linkto.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn sibling_bare_token_credited_on_complete_build() {
        // git-gui shape: the frontend's desktop file calls `git`
        // with params; the sibling ships /usr/bin/git.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg(
            &d0,
            "git-gui",
            vec![desktop_entry(
                d0.path(),
                "/usr/share/applications/git-gui.desktop",
                "git gui",
            )],
        );
        let sibling = menu_pkg(&d1, "git-core", vec![reg_entry("/usr/bin/git")]);
        let src = menu_src_pkg(&d2);
        let results = run_menu_multi(&[src, desktop, sibling]);
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn sibling_bare_token_fires_on_partial_build() {
        // The sibling ships the token, but the run holds no
        // source package: the build is not judged complete and
        // the candidate fires as the per-package verdict.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg(
            &d0,
            "git-gui",
            vec![desktop_entry(
                d0.path(),
                "/usr/share/applications/git-gui.desktop",
                "git gui",
            )],
        );
        let sibling = menu_pkg(&d1, "git-core", vec![reg_entry("/usr/bin/git")]);
        let results = run_menu_multi(&[desktop, sibling]);
        assert_eq!(without_binary(&results).len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn sibling_bare_token_fires_for_foreign_source() {
        // A source package of another build does not open the
        // gate.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg(
            &d0,
            "git-gui",
            vec![desktop_entry(
                d0.path(),
                "/usr/share/applications/git-gui.desktop",
                "git gui",
            )],
        );
        let sibling = menu_pkg(&d1, "git-core", vec![reg_entry("/usr/bin/git")]);
        let foreign = menu_src_pkg_foreign(&d2);
        let results = run_menu_multi(&[foreign, desktop, sibling]);
        assert_eq!(without_binary(&results).len(), 1, "unexpected: {results:?}");
    }

    /// The fsf-address-fixture source package, whose key matches
    /// no fcprobe fixture: a foreign source for the gate.
    fn menu_src_pkg_foreign(dir: &tempfile::TempDir) -> Pkg {
        let mut pkg = menu_foreign_pkg(dir, "fsf-address-fixture", Vec::new());
        pkg.is_source = true;
        pkg
    }

    #[test]
    fn sibling_bare_token_single_package_fires_with_detail() {
        // A single-package run reports exactly the per-package
        // verdict, in the per-package rendering.
        let d0 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg(
            &d0,
            "git-gui",
            vec![desktop_entry(
                d0.path(),
                "/usr/share/applications/git-gui.desktop",
                "git gui",
            )],
        );
        let results = run_menu_multi(&[desktop]);
        let lines = without_binary(&results);
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0].contains("/usr/share/applications/git-gui.desktop"),
            "detail carries the desktop file: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("git"),
            "detail carries the token: {}",
            lines[0]
        );
    }

    #[test]
    fn sibling_absolute_usrmerge_counterpart_credited() {
        // Absolute token through /sbin resolves through the
        // sibling's merged-/usr counterpart, mirroring
        // `binary_exists`.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg(
            &d0,
            "tool-frontend",
            vec![desktop_entry(
                d0.path(),
                "/usr/share/applications/tool.desktop",
                "/sbin/tool",
            )],
        );
        let sibling = menu_pkg(&d1, "tool", vec![reg_entry("/usr/sbin/tool")]);
        let src = menu_src_pkg(&d2);
        let results = run_menu_multi(&[src, desktop, sibling]);
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn bare_token_in_non_bin_dir_still_fires() {
        // A bare token never resolves outside the standard bin
        // dirs: a same-named file under libexec is not on PATH.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg(
            &d0,
            "foo-frontend",
            vec![desktop_entry(
                d0.path(),
                "/usr/share/applications/foo.desktop",
                "foo",
            )],
        );
        let sibling = menu_pkg(&d1, "foo", vec![reg_entry("/usr/libexec/foo")]);
        let src = menu_src_pkg(&d2);
        let results = run_menu_multi(&[src, desktop, sibling]);
        assert_eq!(without_binary(&results).len(), 1, "unexpected: {results:?}");
    }
}
