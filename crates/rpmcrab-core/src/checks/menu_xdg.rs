//! `MenuXDGCheck` — XDG desktop file validation.
//!
//! Ported from `rpmlint/checks/MenuXDGCheck.py`. Findings:
//! `invalid-desktopfile`, `desktopfile-missing-header`,
//! `desktopfile-duplicate-section`, `desktopfile-duplicate-option`,
//! `non-utf8-desktopfile`, `desktopfile-without-binary`.
//!
//! Plus findings from the rpminspect desktop inspection
//! (`lib/inspect_desktop.c`, issue #1223 and its follow-ups): the
//! Icon a desktop file names must resolve in this package when it
//! is an absolute path (`desktopfile-icon-not-found`), and a
//! resolved icon file must be world-readable
//! (`desktopfile-icon-not-readable`); the Exec program a desktop
//! file launches must be world-executable where it resolves in
//! this package (`desktopfile-exec-not-executable`).
//!
//! Scope covers `.desktop` and `.directory` files under
//! `/usr/share/applications`, like rpminspect: a `.directory`
//! file carries no Exec, but it is validated and its Icon is
//! checked the same way.
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

/// Bare Exec tokens accepted as base-system binaries: they are
/// guaranteed by the base system even when no package in the run
/// ships them, so they never fire. Deliberate fixed list, scoped
/// to this check (see the ledger entry). `python` is deliberately
/// absent: Tumbleweed ships no bare `python` binary, only
/// `python3` (absolute, below).
const SYSTEM_BINARIES_BARE: [&str; 5] = ["env", "sh", "bash", "true", "false"];

/// Absolute Exec paths accepted as base-system binaries: the
/// `/bin` and `/usr/bin` spellings of every bare entry above, plus
/// `python3` in both spellings. The two lists are kept in mirror
/// by the `system_binary_lists_mirror` test: a bare entry added
/// without both absolute spellings, or an absolute entry with no
/// bare counterpart other than `python3`, fails the test.
const SYSTEM_BINARIES_ABS: [&str; 12] = [
    "/bin/env",
    "/usr/bin/env",
    "/bin/sh",
    "/usr/bin/sh",
    "/bin/bash",
    "/usr/bin/bash",
    "/bin/true",
    "/usr/bin/true",
    "/bin/false",
    "/usr/bin/false",
    "/bin/python3",
    "/usr/bin/python3",
];

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
    /// Hard dependency edges of the candidate's package: its
    /// `Requires` names in any phase. Only these gate the
    /// sibling credit in `after_checks`: a `Recommends` or
    /// `Suggests` edge does not guarantee the sibling is installed
    /// alongside the frontend, so it never silences a launcher.
    requires: Vec<String>,
    /// The entry's `TryExec` program, unwrapped like Exec, when
    /// it names a binary that is neither a base-system binary nor
    /// resolved in this package. The entry is shown only when
    /// that program exists: on a source-complete build, if it
    /// resolves nowhere in the build either, the entry stays
    /// hidden and the missing Exec is moot, so `after_checks`
    /// suppresses the candidate. `None` when there is no
    /// `TryExec`, or when its program resolves in this package or
    /// is a base-system binary: the entry is shown, and a missing
    /// Exec is a real broken launcher.
    tryexec: Option<String>,
}

/// One deferred `desktopfile-icon-not-found` candidate: an
/// absolute Icon that resolves to no file in this package, held
/// until `after_checks` so a sibling subpackage of the same
/// source build can credit it, exactly like an Exec candidate.
/// Only absolute icons defer: a bare or suffixed name never fires
/// on absence, and a resolved icon's readability is judged
/// immediately, in this package, where its mode is known.
struct DesktopIconCandidate {
    pkg_name: String,
    arch: String,
    filename: String,
    icon: String,
    /// Hard dependency edges of the candidate's package, as for
    /// `DesktopBinaryCandidate`: only these gate the sibling
    /// credit, since installing just the frontend would leave a
    /// broken icon otherwise.
    requires: Vec<String>,
}

/// Everything one build contributes to the run-scoped
/// `desktopfile-without-binary` verdict: the regular files and
/// symlink targets its packages ship, plus the candidates its
/// packages raised.
#[derive(Default)]
struct DesktopBuild {
    symlinks: HashMap<String, String>,
    candidates: Vec<DesktopBinaryCandidate>,
    icon_candidates: Vec<DesktopIconCandidate>,
    /// Regular file path -> packages shipping it. A symlink chain
    /// resolves to a regular file; this names its owner(s) so the
    /// sibling credit can check the dependency edge to them.
    file_owners: HashMap<String, HashSet<String>>,
    /// Package name or `Provides` name -> packages answering to it.
    /// A frontend `Requires` on any of these names is an edge to
    /// the owner.
    dep_owners: HashMap<String, HashSet<String>>,
}

/// Cross-package state, exported per package and merged before
/// `after_checks`.
struct DesktopBuildState {
    sources: HashSet<String>,
    order: Vec<String>,
    builds: HashMap<String, DesktopBuild>,
    unkeyed: Vec<DesktopBinaryCandidate>,
    unkeyed_icons: Vec<DesktopIconCandidate>,
}

pub struct MenuXDGCheck {
    file_regex: Regex,
    checked_files: usize,
    validator: Tool,
    sources: HashSet<String>,
    order: Vec<String>,
    builds: HashMap<String, DesktopBuild>,
    unkeyed: Vec<DesktopBinaryCandidate>,
    unkeyed_icons: Vec<DesktopIconCandidate>,
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
            // searches, so anchor it explicitly. rpminspect's desktop
            // inspection covers `.directory` files under the same
            // directory too, so both suffixes dispatch.
            file_regex: Regex::new(r"^/usr/share/applications/.*\.(?:desktop|directory)$")
                .expect("static regex"),
            checked_files: 0,
            validator,
            sources: HashSet::new(),
            order: Vec::new(),
            builds: HashMap::new(),
            unkeyed: Vec::new(),
            unkeyed_icons: Vec::new(),
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

    /// Whether a token is an `env` assignment (`NAME=value`): the
    /// name is a shell identifier, so it is skipped when resolving
    /// the real program behind `env`.
    fn is_env_assignment(token: &str) -> bool {
        let Some((name, _)) = token.split_once('=') else {
            return false;
        };
        let mut chars = name.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// The program an Exec line actually launches, unwrapping
    /// `env` and `sh`/`bash -c` wrappers. The check judges this
    /// token, never the wrapper name: `Exec=env FOO=1 missing`
    /// and `Exec=sh -c 'missing'` previously went silent because
    /// the wrapper itself is a base-system binary, hiding a broken
    /// launcher. For `env`, flags (`-i`, `-u NAME`, `-C DIR`,
    /// `--chdir DIR`, `--`) and `NAME=value` assignments are
    /// skipped and the next token is the program (assignments are
    /// skipped after `--` too); with no program left, `env` itself
    /// is returned.
    /// For `sh`/`bash`, a `-c` payload feeds back through the same
    /// unwrapping, so its first word may itself be `env` (or another
    /// wrapper) before the program is reached;
    /// without `-c` the shell itself is the program and is returned
    /// unchanged. Wrapper names are matched by basename, so
    /// absolute spellings (`/usr/bin/env`, `/bin/sh`) unwrap the
    /// same way. One wrapper layer past `env` is followed, so
    /// `env sh -c 'prog'` resolves to `prog`.
    fn effective_exec_binary(exec: &str) -> String {
        // Owned tokens: a `sh -c` payload replaces the token list
        // so it feeds back through the same unwrapping loop.
        let mut tokens: Vec<String> = exec.split_whitespace().map(str::to_string).collect();
        let mut start = 0usize;
        for _ in 0..3 {
            let Some(first) = tokens.get(start) else {
                return String::new();
            };
            let first = Self::unquote_exec_token(first);
            let base = first.rsplit('/').next().unwrap_or(first);
            match base {
                "env" => {
                    let mut idx = start + 1;
                    let mut program_idx = None;
                    while idx < tokens.len() {
                        let tok: &str = &tokens[idx];
                        if tok == "--" {
                            idx += 1;
                            while idx < tokens.len() && Self::is_env_assignment(&tokens[idx]) {
                                idx += 1;
                            }
                            program_idx = if idx < tokens.len() { Some(idx) } else { None };
                            break;
                        }
                        if tok.starts_with('-') && tok.len() > 1 {
                            // `-u`/`--unset` and `-C`/`--chdir`
                            // consume their argument; any other flag
                            // is standalone (`-CDIR` carries its
                            // argument attached, so it consumes one).
                            // Short flags cluster: a value-taking
                            // `u`/`C` consumes the rest of the
                            // cluster as its value, or the next
                            // token when it ends the cluster
                            // (`env -iu NAME prog` is `-i`,
                            // `-u NAME`, program `prog`).
                            if tok.starts_with("--") {
                                idx += if tok == "--unset" || tok == "--chdir" {
                                    2
                                } else {
                                    1
                                };
                                continue;
                            }
                            let cluster = &tok[1..];
                            let mut take_next = false;
                            for (k, ch) in cluster.char_indices() {
                                if ch == 'u' || ch == 'C' {
                                    take_next = k + ch.len_utf8() >= cluster.len();
                                    break;
                                }
                            }
                            idx += if take_next { 2 } else { 1 };
                            continue;
                        }
                        if Self::is_env_assignment(tok) {
                            idx += 1;
                            continue;
                        }
                        program_idx = Some(idx);
                        break;
                    }
                    match program_idx {
                        Some(p) => {
                            start = p;
                            continue;
                        }
                        None => return first.to_string(),
                    }
                }
                "sh" | "bash" => {
                    let mut j = start + 1;
                    let mut payload: Option<String> = None;
                    while j < tokens.len() {
                        let tok: &str = &tokens[j];
                        if tok == "-c" {
                            payload = Some(tokens[j + 1..].join(" "));
                            break;
                        }
                        if tok == "--" {
                            // End of options: a following `-c` is a
                            // script file, not a flag.
                            break;
                        }
                        if tok.starts_with("--") {
                            // Long flags are skipped, not terminal:
                            // `bash --noprofile -c 'prog'` still
                            // finds its payload.
                            j += 1;
                            continue;
                        }
                        if tok.starts_with('-') && tok.len() > 1 {
                            // Short-option cluster, getopt order:
                            // `c` takes the rest of the token as its
                            // payload, `o` takes the rest as its own
                            // argument (so `-noexec` is `-n` plus
                            // `-o`'s argument, not `-c`); any other
                            // flag is skipped. A cluster with no `c`
                            // is skipped whole.
                            let mut cpos = None;
                            for (i, ch) in tok.char_indices().skip(1) {
                                if ch == 'c' {
                                    cpos = Some(i);
                                    break;
                                }
                                if ch == 'o' {
                                    break;
                                }
                            }
                            if let Some(cpos) = cpos {
                                let rest = &tok[cpos + 1..];
                                payload = if rest.is_empty() {
                                    Some(tokens[j + 1..].join(" "))
                                } else {
                                    let mut p = rest.to_string();
                                    if j + 1 < tokens.len() {
                                        p.push(' ');
                                        p.push_str(&tokens[j + 1..].join(" "));
                                    }
                                    Some(p)
                                };
                                break;
                            }
                            j += 1;
                            continue;
                        }
                        // A non-flag argument is a script file, not
                        // a `-c` payload: the shell itself is the
                        // program.
                        break;
                    }
                    return match payload {
                        Some(p) => {
                            // Feed the payload back through the same
                            // loop instead of returning its first word
                            // directly: a payload starting with `env`
                            // unwraps like the other direction, so
                            // `sh -c 'env FOO=1 missing'` resolves to
                            // `missing`, not to the system `env`
                            // binary hiding a broken launcher.
                            // The payload is one shell word string;
                            // edge quotes on its tokens are syntactic
                            // (the old code trimmed them off the first
                            // word only), so strip them per token.
                            tokens = p
                                .split_whitespace()
                                .map(|t| t.trim_matches(['\'', '"']).to_string())
                                .collect();
                            start = 0;
                            continue;
                        }
                        None => first.to_string(),
                    };
                }
                _ => return first.to_string(),
            }
        }
        // Loop exhaustion (three env layers unwrapped exactly as
        // the program is reached) returns the current token, not
        // the outermost wrapper: returning the first token would
        // report `env` for `env env env myprog`, hiding the
        // program behind a base-system binary.
        tokens
            .get(start)
            .map(|t| Self::unquote_exec_token(t).to_string())
            .unwrap_or_default()
    }

    /// The on-disk path an Exec token resolves to in this
    /// package, mirroring `binary_exists` exactly: the literal
    /// path for absolute tokens (plus the merged-/usr counterpart
    /// for legacy `/bin` and `/sbin` spellings), the first
    /// standard bin dir holding the file for bare tokens. `None`
    /// when the token resolves nowhere in this package, and for
    /// any path carrying a `..` segment, mirroring
    /// `binary_exists`' refusal. Symlinks are not resolved here:
    /// the caller reads metadata through them, so the mode judged
    /// is the target's.
    fn resolve_exec_path(pkg: &Pkg, binary: &str) -> Option<std::path::PathBuf> {
        if binary.starts_with('/') {
            if binary.split('/').any(|seg| seg == "..") {
                return None;
            }
            let root = Path::new(pkg.dir_name());
            let full = root.join(binary.trim_start_matches('/'));
            if full.exists() {
                return Some(full);
            }
            if let Some(rest) = binary.strip_prefix("/sbin/") {
                let rest = rest.trim_start_matches('/');
                if !rest.is_empty() {
                    let merged = root.join("usr/sbin").join(rest);
                    if merged.exists() {
                        return Some(merged);
                    }
                }
            }
            if let Some(rest) = binary.strip_prefix("/bin/") {
                let rest = rest.trim_start_matches('/');
                if !rest.is_empty() {
                    let merged = root.join("usr/bin").join(rest);
                    if merged.exists() {
                        return Some(merged);
                    }
                }
            }
            return None;
        }
        STANDARD_BIN_DIRS.iter().find_map(|d| {
            let full = Path::new(pkg.dir_name())
                .join(d.trim_start_matches('/'))
                .join(binary);
            full.exists().then_some(full)
        })
    }

    /// Whether the Exec program the entry launches is executable
    /// by all where it resolves in this package (rpminspect's
    /// desktop inspection: a desktop file referencing an
    /// executable that is not executable by all fails
    /// verification). Only the per-package resolution is judged:
    /// a binary credited through a sibling subpackage in
    /// `after_checks` carries no mode in the build inventory, so
    /// its executability is not judged. Base-system binaries
    /// never fire. A resolved path that is not a regular file
    /// stays silent: a directory named like the binary is a
    /// `binary_exists` quirk, not a non-executable program.
    fn check_exec_executable(pkg: &Pkg, out: &mut Filter, filename: &str, binary: &str) {
        use std::os::unix::fs::MetadataExt;
        if binary.is_empty() || Self::is_system_binary(binary) {
            return;
        }
        let Some(path) = Self::resolve_exec_path(pkg, binary) else {
            return;
        };
        let Ok(meta) = std::fs::metadata(&path) else {
            return;
        };
        if !meta.is_file() || meta.mode() & 0o001 != 0 {
            return;
        }
        add_info(
            out,
            Level::Warning,
            pkg,
            "desktopfile-exec-not-executable",
            &[filename, binary],
        );
    }

    /// Whether the Exec binary resolves (in the package or on the live root).
    fn binary_exists(pkg: &Pkg, binary: &str) -> bool {
        if binary.starts_with('/') {
            // A `..` segment never names a binary the package ships:
            // inside the tree it aliases another package path, and a
            // leading chain escapes the package root into a host
            // `.exists()` probe.
            if binary.split('/').any(|seg| seg == "..") {
                return false;
            }
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

    /// Whether the Exec token names a base-system binary, accepted
    /// without any package shipping it.
    fn is_system_binary(binary: &str) -> bool {
        if binary.starts_with('/') {
            SYSTEM_BINARIES_ABS.contains(&binary)
        } else {
            SYSTEM_BINARIES_BARE.contains(&binary)
        }
    }

    /// The merged-/usr counterpart of a legacy-directory absolute
    /// path, mirroring `binary_exists`: `/sbin/x` to `/usr/sbin/x`
    /// and `/bin/x` to `/usr/bin/x`. `None` for any other path, and
    /// for any path carrying a `..` segment, mirroring
    /// `binary_exists`' refusal: without this, a `..` spelling the
    /// per-package verdict refuses would still gain build credit
    /// through its normalized counterpart. Sanitized like
    /// `binary_exists`, plus the normalization the filesystem
    /// applies: the input is collapsed lexically first, so `//` and
    /// `/.` segments in the prefix collapse the way the filesystem
    /// collapses them, and a path normalizing outside `/bin` or
    /// `/sbin`, or to an empty remainder, resolves to nothing.
    fn usrmerge_counterpart(path: &str) -> Option<String> {
        // A `..` segment never names a binary, mirroring
        // `binary_exists`: without this, a `..` spelling the
        // per-package verdict refuses would still gain build credit
        // through its normalized counterpart.
        if path.split('/').any(|seg| seg == "..") {
            return None;
        }
        // Normalize lexically first, as the filesystem collapses
        // the path: `//` and `/.` segments in the prefix collapse
        // too, so `//bin/x` and `/./bin/x` map like `/bin/x`.
        let path = Self::normalize_icon_path(path);
        let (base, rest) = path
            .strip_prefix("/sbin/")
            .map(|r| ("/usr/sbin", r))
            .or_else(|| path.strip_prefix("/bin/").map(|r| ("/usr/bin", r)))?;
        let segments: Vec<&str> = rest
            .split('/')
            .filter(|seg| !seg.is_empty() && *seg != ".")
            .collect();
        if segments.is_empty() {
            return None;
        }
        Some(format!("{}/{}", base, segments.join("/")))
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

    /// The regular file one path resolves to through the build's
    /// shipped entries, following symlink chains inside the build.
    /// A chain leaving the build or looping stays unresolved: the
    /// target is not a file this build ships.
    fn resolve_in_build(build: &DesktopBuild, start: &str) -> Option<String> {
        let mut current = start.to_string();
        for _ in 0..10 {
            if build.file_owners.contains_key(&current) {
                return Some(current);
            }
            let linkto = build.symlinks.get(&current)?;
            if linkto.is_empty() {
                return None;
            }
            current = if linkto.starts_with('/') {
                Self::normalize_icon_path(linkto)
            } else {
                let dir = current.rfind('/').map_or("", |i| &current[..i]);
                if dir.is_empty() {
                    linkto.clone()
                } else {
                    Self::normalize_icon_path(&format!("{dir}/{linkto}"))
                }
            };
        }
        None
    }

    /// Whether the Exec token is credited through the build: it
    /// resolves to a regular file the build ships, and the
    /// candidate's package is guaranteed to install alongside the
    /// file's owner. The guarantee is a hard dependency edge: the
    /// candidate's package `Requires` the owning package in any
    /// phase by name, by one of its `Provides`, or by the resolved
    /// file path itself (a file dependency). A package
    /// that only `Recommends` or `Suggests` the sibling, or has no
    /// edge to it at all, is not credited: installing just the
    /// frontend would leave a dead launcher. A file the
    /// candidate's own package ships is always credited: it is a
    /// resolution, not sibling credit.
    fn credited_via_build(build: &DesktopBuild, cand: &DesktopBinaryCandidate) -> bool {
        Self::credited_via_build_path(build, &cand.binary, &cand.pkg_name, &cand.requires)
    }

    /// The path form of `credited_via_build`: whether `path`
    /// resolves to a regular file the build ships, with the same
    /// hard-edge guarantee for `pkg_name`/`requires`. Shared by
    /// Exec candidates, deferred absolute-icon candidates (an
    /// icon a sibling ships is credited under the same rule), and
    /// the `TryExec` probe in `after_checks` (a `TryExec` program
    /// a sibling ships, under a hard edge, shows the entry).
    fn credited_via_build_path(
        build: &DesktopBuild,
        path: &str,
        pkg_name: &str,
        requires: &[String],
    ) -> bool {
        for candidate in Self::candidate_paths(path) {
            let Some(final_path) = Self::resolve_in_build(build, &candidate) else {
                continue;
            };
            let Some(owners) = build.file_owners.get(&final_path) else {
                continue;
            };
            if owners.contains(pkg_name) {
                return true;
            }
            // RPM file dependencies are exact-path: a Requires
            // matching any other candidate spelling (a bare token
            // spelling, a merged-/usr counterpart) is not an edge
            // to this file.
            if requires.iter().any(|req| req == &final_path) {
                return true;
            }
            if requires.iter().any(|req| {
                build
                    .dep_owners
                    .get(req)
                    .is_some_and(|providers| providers.iter().any(|owner| owners.contains(owner)))
            }) {
                return true;
            }
        }
        false
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
                build
                    .file_owners
                    .entry(file.name.clone())
                    .or_default()
                    .insert(pkg.name.clone());
            } else if is_symlink(file.mode) {
                build
                    .symlinks
                    .insert(file.name.clone(), file.linkto.clone());
            }
        }
        // Dependency edges are judged by name: the package's own
        // name and every name it provides resolve to this owner.
        build
            .dep_owners
            .entry(pkg.name.clone())
            .or_default()
            .insert(pkg.name.clone());
        for provide in &pkg.provides {
            build
                .dep_owners
                .entry(provide.name.clone())
                .or_default()
                .insert(pkg.name.clone());
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

    /// Emit one deferred `desktopfile-icon-not-found` verdict,
    /// mirroring `emit_without_binary`.
    fn emit_icon_not_found(out: &mut Filter, cand: &DesktopIconCandidate) {
        out.add_info(make_finding(
            &cand.pkg_name,
            &cand.arch,
            Level::Warning,
            "desktopfile-icon-not-found",
            vec![cand.filename.clone(), cand.icon.clone()],
            None,
        ));
    }

    /// Icon existence for one desktop entry (issue #1223). Fire only
    /// where absence is decidable from this package alone: an absolute
    /// Icon path must resolve to a regular file in this package, and a
    /// resolved icon file must be world-readable. A bare or suffixed
    /// name never fires on absence (a system icon theme may provide
    /// it). Ghost entries, symlink chains leaving the package, and
    /// loops all stay silent. Only the `[Desktop Entry]` Icon is read;
    /// action icons are out of scope.
    ///
    /// An absolute Icon that resolves to no file in this package
    /// does not fire here: it defers to `after_checks`, where a
    /// sibling subpackage of the same source build can credit it
    /// under the same hard-`Requires`-edge rule as an Exec
    /// candidate (rpminspect searches every peer subpackage for
    /// the icon). A sibling-credited icon's readability is not
    /// judged: the build inventory carries no modes. An absolute
    /// Icon naming a directory in this package still fires here:
    /// no sibling can ship a regular file at a path this package
    /// claims as a directory.
    fn check_icon(
        &mut self,
        pkg: &Pkg,
        out: &mut Filter,
        filename: &str,
        entry: &HashMap<String, String>,
    ) {
        let Some(icon) = entry.get("icon") else {
            return;
        };
        if icon.is_empty() || icon.contains("%{") {
            return;
        }
        if icon.starts_with('/') {
            let Some(start) = pkg.files.iter().find(|f| f.name == *icon) else {
                // No entry in this package at all: defer, so a
                // sibling subpackage can still credit it.
                let candidate = DesktopIconCandidate {
                    pkg_name: pkg.name.clone(),
                    arch: pkg.arch.clone(),
                    filename: filename.to_string(),
                    icon: icon.clone(),
                    requires: pkg
                        .requires
                        .iter()
                        .chain(pkg.prereq.iter())
                        .map(|dep| dep.name.clone())
                        .collect(),
                };
                match binary_source_key(pkg) {
                    Some(key) => {
                        let build = self.build_mut(&key);
                        build.icon_candidates.push(candidate);
                    }
                    None => self.unkeyed_icons.push(candidate),
                }
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
                        // Judge the program the entry actually
                        // launches, unwrapping `env` and `sh -c`
                        // wrappers: judging the wrapper name would
                        // silence a broken launcher behind a
                        // base-system binary.
                        let binary = Self::effective_exec_binary(exec);
                        // A resolved program that no user can
                        // execute is a broken launcher too, even
                        // though the file exists.
                        Self::check_exec_executable(pkg, out, filename, &binary);
                        // Base-system binaries never fire. Anything
                        // else the package itself does not resolve
                        // is held for `after_checks`, where the
                        // run-scoped sibling credit is judged:
                        // emitting here would fire before the
                        // sibling's inventory is known.
                        if !binary.is_empty()
                            && !Self::binary_exists(pkg, &binary)
                            && !Self::is_system_binary(&binary)
                        {
                            // The entry is shown only when its
                            // TryExec program exists: a TryExec
                            // that resolves nowhere hides the
                            // entry, so the missing Exec is moot.
                            // The probe runs in `after_checks`,
                            // where the build can credit the
                            // TryExec program through a sibling.
                            let tryexec = entry.get("tryexec").and_then(|value| {
                                let program = Self::effective_exec_binary(value);
                                if program.is_empty()
                                    || Self::is_system_binary(&program)
                                    || Self::binary_exists(pkg, &program)
                                {
                                    None
                                } else {
                                    Some(program)
                                }
                            });
                            let candidate = DesktopBinaryCandidate {
                                pkg_name: pkg.name.clone(),
                                arch: pkg.arch.clone(),
                                filename: filename.to_string(),
                                binary: binary.to_string(),
                                requires: pkg
                                    .requires
                                    .iter()
                                    .chain(pkg.prereq.iter())
                                    .map(|dep| dep.name.clone())
                                    .collect(),
                                tryexec,
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
                        self.check_icon(pkg, out, filename, entry);
                    }
                }
            }
        }
    }

    /// The deferred `desktopfile-without-binary` verdict: a
    /// candidate is credited only when its build is
    /// source-complete in this run -- the run holds the build's
    /// source package -- and its token is credited through the
    /// build under `credited_via_build` (resolves to a shipped
    /// file whose owner the candidate's package hard-Requires).
    /// Every other candidate fires, so source-absent (partial) and
    /// single-package runs report exactly the per-package verdict.
    /// On a source-complete build, a candidate whose `TryExec`
    /// program resolves nowhere in the build never fires: the
    /// entry stays hidden, so the missing Exec is moot. Partial
    /// runs still fire for such candidates: whether the entry is
    /// shown is undecidable without the build, and the
    /// per-package verdict stands. Deferred absolute-icon
    /// candidates follow the same rule: a sibling-credited icon
    /// stays silent, every other absolute icon fires.
    fn after_checks(&mut self, _config: &Config, out: &mut Filter) {
        for cand in &self.unkeyed {
            Self::emit_without_binary(out, cand);
        }
        for cand in &self.unkeyed_icons {
            Self::emit_icon_not_found(out, cand);
        }
        for key in &self.order {
            let build = &self.builds[key];
            let complete = self.sources.contains(key);
            for cand in &build.candidates {
                if complete {
                    if let Some(tryexec) = &cand.tryexec {
                        // The entry is shown only when its
                        // TryExec program resolves in the build,
                        // under the same hard-edge credit as the
                        // Exec token. A TryExec that resolves
                        // nowhere hides the entry, so the missing
                        // Exec never fires.
                        let shown = Self::credited_via_build_path(
                            build,
                            tryexec,
                            &cand.pkg_name,
                            &cand.requires,
                        );
                        if !shown {
                            continue;
                        }
                    }
                    if Self::credited_via_build(build, cand) {
                        continue;
                    }
                }
                Self::emit_without_binary(out, cand);
            }
            for cand in &build.icon_candidates {
                if complete
                    && Self::credited_via_build_path(
                        build,
                        &cand.icon,
                        &cand.pkg_name,
                        &cand.requires,
                    )
                {
                    continue;
                }
                Self::emit_icon_not_found(out, cand);
            }
        }
    }

    fn reset(&mut self) {
        self.checked_files = 0;
        self.sources.clear();
        self.order.clear();
        self.builds.clear();
        self.unkeyed.clear();
        self.unkeyed_icons.clear();
    }

    fn export_state(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        Some(Box::new(DesktopBuildState {
            sources: std::mem::take(&mut self.sources),
            order: std::mem::take(&mut self.order),
            builds: std::mem::take(&mut self.builds),
            unkeyed: std::mem::take(&mut self.unkeyed),
            unkeyed_icons: std::mem::take(&mut self.unkeyed_icons),
        }))
    }

    fn import_state(&mut self, state: Box<dyn std::any::Any + Send>) {
        if let Ok(mut state) = state.downcast::<DesktopBuildState>() {
            self.sources.extend(state.sources.drain());
            self.unkeyed.append(&mut state.unkeyed);
            self.unkeyed_icons.append(&mut state.unkeyed_icons);
            for key in std::mem::take(&mut state.order) {
                let Some(data) = state.builds.remove(&key) else {
                    continue;
                };
                match self.builds.get_mut(&key) {
                    Some(mine) => {
                        mine.symlinks.extend(data.symlinks);
                        mine.candidates.extend(data.candidates);
                        mine.icon_candidates.extend(data.icon_candidates);
                        for (path, owners) in data.file_owners {
                            mine.file_owners.entry(path).or_default().extend(owners);
                        }
                        for (name, owners) in data.dep_owners {
                            mine.dep_owners.entry(name).or_default().extend(owners);
                        }
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
    fn file_pattern_matches_directory_files() {
        // rpminspect's desktop inspection covers `.directory`
        // files under the same directory: they carry no Exec, but
        // they are validated and their Icon is checked.
        let check = MenuXDGCheck::new(&Config::default());
        assert!(is_match(
            &check.file_regex,
            "/usr/share/applications/w6.directory"
        ));
        assert!(!is_match(
            &check.file_regex,
            "/usr/share/applications/w6.directory.bak"
        ));
        assert!(!is_match(
            &check.file_regex,
            "/opt/vendor/usr/share/applications/v.directory"
        ));
        assert!(is_match(
            &check.file_regex,
            "/usr/share/applications/w6.desktop"
        ));
    }

    #[test]
    fn directory_file_without_header_is_invalid() {
        // A `.directory` file dispatches like a `.desktop` file:
        // the native parse flags a missing header.
        let results = run_desktop_named("Name=Foo\n", "/usr/share/applications/w6.directory");
        let names: Vec<&str> = results
            .iter()
            .filter(|(n, _)| n == "desktopfile-missing-header")
            .map(|(n, _)| n.as_str())
            .collect();
        assert_eq!(names.len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn directory_file_valid_is_quiet() {
        let results = run_desktop_named(
            "[Desktop Entry]\nName=Foo\nType=Directory\nIcon=foo\n",
            "/usr/share/applications/w6.directory",
        );
        assert!(results.is_empty(), "unexpected: {results:?}");
    }

    #[test]
    fn directory_file_duplicate_option_is_flagged() {
        let results = run_desktop_named(
            "[Desktop Entry]\nName=Foo\nName=Bar\n",
            "/usr/share/applications/w6.directory",
        );
        assert!(
            results
                .iter()
                .any(|(n, _)| n == "desktopfile-duplicate-option"),
            "unexpected: {results:?}"
        );
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
        run_desktop_named(content, "/usr/share/applications/macrotest.desktop")
    }

    /// Like `run_desktop`, with the desktop file installed under
    /// `filename` instead of the default name: `.directory`
    /// files dispatch under their own name.
    fn run_desktop_named(content: &str, filename: &str) -> Vec<(String, String)> {
        // Unique temp file: tests run in parallel and must not share one.
        // The on-disk name must carry the package filename's
        // basename: desktop-file-validate judges the file it is
        // handed, and rejects a Type=Directory entry in a file
        // without a .directory extension.
        let dir = tempfile::tempdir().unwrap();
        let basename = Path::new(filename)
            .file_name()
            .expect("desktop filename has a basename");
        let path = dir.path().join(basename);
        std::fs::write(&path, content).unwrap();
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        let name = filename;
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
        // Absolute-icon absence defers to after_checks: run it so
        // the deferred verdicts land in the collected results.
        check.after_checks(&config, &mut out);
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
    /// parallel and must not share a seeded directory. Seeded files
    /// are real binaries, so they are seeded executable (0755);
    /// `run_desktop_seeded_modes` seeds exact modes instead.
    fn run_desktop_seeded(content: &str, seeded: &[&str]) -> Vec<(String, String)> {
        let modes: Vec<(&str, u32)> = seeded.iter().map(|rel| (*rel, 0o755)).collect();
        run_desktop_seeded_modes(content, &modes)
    }

    /// Like `run_desktop_seeded`, seeding each path with the given
    /// on-disk mode: a 0644 seed names a shipped-but-not-executable
    /// file, which is what `desktopfile-exec-not-executable` fires on.
    fn run_desktop_seeded_modes(content: &str, seeded: &[(&str, u32)]) -> Vec<(String, String)> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seededtest.desktop");
        std::fs::write(&path, content).unwrap();
        let extract_root = tempfile::tempdir().unwrap();
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, extract_root.path(), true).expect("open fixture pkg");
        let root = Path::new(pkg.dir_name()).to_path_buf();
        for (rel, mode) in seeded {
            let full = root.join(rel);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&full, b"").unwrap();
            std::fs::set_permissions(&full, std::os::unix::fs::PermissionsExt::from_mode(*mode))
                .unwrap();
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

    fn exec_not_executable(results: &[(String, String)]) -> Vec<&String> {
        results
            .iter()
            .filter(|(n, _)| n == "desktopfile-exec-not-executable")
            .map(|(_, l)| l)
            .collect()
    }

    #[test]
    fn exec_not_executable_fires_for_bare_token() {
        // rpminspect's desktop inspection fails verification when
        // the referenced executable is not executable by all.
        let results = run_desktop_seeded_modes(
            "[Desktop Entry]\nName=Foo\nExec=foo\n",
            &[("usr/bin/foo", 0o644)],
        );
        let lines = exec_not_executable(&results);
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0].contains("W: desktopfile-exec-not-executable"),
            "level: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("foo"),
            "detail names the binary: {}",
            lines[0]
        );
        // The file exists, so no without-binary fires alongside.
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn exec_executable_is_silent() {
        let results = run_desktop_seeded_modes(
            "[Desktop Entry]\nName=Foo\nExec=foo\n",
            &[("usr/bin/foo", 0o755)],
        );
        assert!(
            exec_not_executable(&results).is_empty(),
            "unexpected: {results:?}"
        );
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn exec_not_executable_fires_for_absolute_token() {
        let results = run_desktop_seeded_modes(
            "[Desktop Entry]\nName=Foo\nExec=/usr/bin/foo\n",
            &[("usr/bin/foo", 0o640)],
        );
        let lines = exec_not_executable(&results);
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0].contains("/usr/bin/foo"),
            "detail names the binary: {}",
            lines[0]
        );
    }

    #[test]
    fn exec_not_executable_fires_via_usrmerge_counterpart() {
        // /sbin/foo resolving through the merged /usr/sbin/foo
        // is judged on the file it actually resolves to.
        let results = run_desktop_seeded_modes(
            "[Desktop Entry]\nName=Foo\nExec=/sbin/foo\n",
            &[("usr/sbin/foo", 0o644)],
        );
        let lines = exec_not_executable(&results);
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0].contains("/sbin/foo"),
            "detail names the Exec spelling: {}",
            lines[0]
        );
    }

    #[test]
    fn exec_not_executable_fires_behind_env_wrapper() {
        // The program behind the wrapper is judged, not `env`.
        let results = run_desktop_seeded_modes(
            "[Desktop Entry]\nName=Foo\nExec=env FOO=1 foo\n",
            &[("usr/bin/foo", 0o644)],
        );
        let lines = exec_not_executable(&results);
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0].contains("foo"),
            "detail names the program: {}",
            lines[0]
        );
    }

    #[test]
    fn exec_not_executable_skips_system_binaries() {
        // A base-system binary is accepted without any package
        // shipping it, so its on-disk mode is never judged: even
        // a non-executable seed of /usr/bin/true stays silent.
        let results = run_desktop_seeded_modes(
            "[Desktop Entry]\nName=Foo\nExec=/usr/bin/true\n",
            &[("usr/bin/true", 0o644)],
        );
        assert!(
            exec_not_executable(&results).is_empty(),
            "unexpected: {results:?}"
        );
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn exec_not_executable_judges_other_execute_bit() {
        // rpminspect's bar is executable by all (S_IXOTH): a
        // group-executable file with no other-execute bit fails,
        // an other-executable file passes even without group.
        let results = run_desktop_seeded_modes(
            "[Desktop Entry]\nName=Foo\nExec=foo\n",
            &[("usr/bin/foo", 0o701)],
        );
        assert!(
            exec_not_executable(&results).is_empty(),
            "unexpected: {results:?}"
        );
        let results = run_desktop_seeded_modes(
            "[Desktop Entry]\nName=Foo\nExec=foo\n",
            &[("usr/bin/foo", 0o750)],
        );
        assert_eq!(
            exec_not_executable(&results).len(),
            1,
            "unexpected: {results:?}"
        );
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
        // `..` segments never resolve: an in-tree `..` would alias
        // another package path, and a leading chain would escape the
        // package root into a host `.exists()` probe.
        assert!(!MenuXDGCheck::binary_exists(&pkg, "/sbin/.."));
        assert!(!MenuXDGCheck::binary_exists(&pkg, "/sbin/../usr/bin/tool"));
        assert!(!MenuXDGCheck::binary_exists(&pkg, "/sbin/../../etc/passwd"));
        assert!(!MenuXDGCheck::binary_exists(&pkg, "/bin/../usr/sbin/yast2"));
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

    fn dep_named(name: &str) -> crate::pkg::dep::DepInfo {
        crate::pkg::dep::DepInfo {
            name: name.to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        }
    }

    /// Like `menu_pkg`, with hard `Requires` edges set: the
    /// sibling credit now requires one (see `credited_via_build`).
    fn menu_pkg_with_requires(
        dir: &tempfile::TempDir,
        name: &str,
        files: Vec<PkgFile>,
        requires: &[&str],
    ) -> Pkg {
        let mut pkg = menu_pkg(dir, name, files);
        pkg.requires = requires.iter().map(|r| dep_named(r)).collect();
        pkg
    }

    fn ghost_entry(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            flags: crate::pkg::pkgfile::RPMFILE_GHOST,
            ..Default::default()
        }
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

    /// A desktop file entry with a `TryExec` line alongside Exec:
    /// the entry is shown only when the TryExec program exists.
    fn desktop_entry_tryexec(
        dir: &std::path::Path,
        filename: &str,
        exec: &str,
        tryexec: &str,
    ) -> PkgFile {
        let path = dir.join("test.desktop");
        std::fs::write(
            &path,
            format!(
                "[Desktop Entry]\nType=Application\nName=Test\nExec={exec}\nTryExec={tryexec}\n"
            ),
        )
        .unwrap();
        PkgFile {
            name: filename.to_string(),
            path: path.to_str().unwrap().to_string(),
            mode: 0o100644,
            ..Default::default()
        }
    }

    /// A desktop file entry naming an absolute Icon, with a
    /// base-system Exec so no `desktopfile-without-binary`
    /// finding pollutes the icon verdicts.
    fn desktop_entry_icon(dir: &std::path::Path, filename: &str, icon: &str) -> PkgFile {
        let path = dir.join("test.desktop");
        std::fs::write(
            &path,
            format!("[Desktop Entry]\nType=Application\nName=Test\nExec=true\nIcon={icon}\n"),
        )
        .unwrap();
        PkgFile {
            name: filename.to_string(),
            path: path.to_str().unwrap().to_string(),
            mode: 0o100644,
            ..Default::default()
        }
    }

    fn icon_not_found(results: &[(String, String)]) -> Vec<&String> {
        results
            .iter()
            .filter(|(n, _)| n == "desktopfile-icon-not-found")
            .map(|(_, l)| l)
            .collect()
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
        let desktop = menu_pkg_with_requires(
            &d0,
            "git-gui",
            vec![desktop_entry(
                d0.path(),
                "/usr/share/applications/git-gui.desktop",
                "git gui",
            )],
            &["git-core"],
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
        let desktop = menu_pkg_with_requires(
            &d0,
            "tool-frontend",
            vec![desktop_entry(
                d0.path(),
                "/usr/share/applications/tool.desktop",
                "/sbin/tool",
            )],
            &["tool"],
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
    #[test]
    fn symlink_to_sibling_credited_on_complete_build() {
        // cosmic-applet shape: the desktop package ships the
        // Exec path as a relative symlink; the sibling ships
        // the target.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg_with_requires(
            &d0,
            "cosmic-applet-audio",
            vec![
                desktop_entry(
                    d0.path(),
                    "/usr/share/applications/cosmic-applet-audio.desktop",
                    "/usr/bin/cosmic-applet-audio",
                ),
                link_entry("/usr/bin/cosmic-applet-audio", "cosmic-applets"),
            ],
            &["cosmic-applets"],
        );
        let sibling = menu_pkg(
            &d1,
            "cosmic-applets",
            vec![reg_entry("/usr/bin/cosmic-applets")],
        );
        let src = menu_src_pkg(&d2);
        let results = run_menu_multi(&[src, desktop, sibling]);
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn symlink_to_nowhere_fires_on_complete_build() {
        // Complete build, but the symlink chain leaves the build.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg(
            &d0,
            "cosmic-applet-audio",
            vec![
                desktop_entry(
                    d0.path(),
                    "/usr/share/applications/cosmic-applet-audio.desktop",
                    "/usr/bin/cosmic-applet-audio",
                ),
                link_entry("/usr/bin/cosmic-applet-audio", "missing-target"),
            ],
        );
        let sibling = menu_pkg(&d1, "cosmic-applets", vec![reg_entry("/usr/bin/unrelated")]);
        let src = menu_src_pkg(&d2);
        let results = run_menu_multi(&[src, desktop, sibling]);
        assert_eq!(without_binary(&results).len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn symlink_target_in_foreign_build_fires() {
        // The target ships in the run, but in a package of
        // another build: the chain leaves this build and the
        // candidate fires.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg(
            &d0,
            "cosmic-applet-audio",
            vec![
                desktop_entry(
                    d0.path(),
                    "/usr/share/applications/cosmic-applet-audio.desktop",
                    "/usr/bin/cosmic-applet-audio",
                ),
                link_entry("/usr/bin/cosmic-applet-audio", "cosmic-applets"),
            ],
        );
        let foreign = menu_foreign_pkg(
            &d1,
            "cosmic-applets",
            vec![reg_entry("/usr/bin/cosmic-applets")],
        );
        let src = menu_src_pkg(&d2);
        let results = run_menu_multi(&[src, desktop, foreign]);
        assert_eq!(without_binary(&results).len(), 1, "unexpected: {results:?}");
    }
    #[test]
    fn system_binaries_silent() {
        // Every allowlisted spelling stays silent on its own,
        // with no sibling or source package in the run.
        for token in [
            "env",
            "sh",
            "bash",
            "true",
            "false",
            "/bin/env",
            "/usr/bin/env",
            "/bin/sh",
            "/usr/bin/sh",
            "/bin/bash",
            "/usr/bin/bash",
            "/bin/true",
            "/usr/bin/true",
            "/bin/false",
            "/usr/bin/false",
            "/bin/python3",
            "/usr/bin/python3",
        ] {
            let d0 = tempfile::tempdir().unwrap();
            let desktop = menu_pkg(
                &d0,
                "sysbin",
                vec![desktop_entry(
                    d0.path(),
                    "/usr/share/applications/sysbin.desktop",
                    token,
                )],
            );
            let results = run_menu_multi(&[desktop]);
            assert!(
                without_binary(&results).is_empty(),
                "{token} should stay silent: {results:?}"
            );
        }
    }

    #[test]
    fn system_binary_lists_mirror() {
        // The absolute list is the /bin + /usr/bin expansion of
        // the bare list, plus python3 (whose bare spelling is not
        // a base-system binary). A drift here reopens the
        // asymmetry the review caught.
        for bare in SYSTEM_BINARIES_BARE {
            let bin = format!("/bin/{bare}");
            assert!(
                SYSTEM_BINARIES_ABS.contains(&bin.as_str()),
                "/bin spelling missing for {bare}"
            );
            let usrbin = format!("/usr/bin/{bare}");
            assert!(
                SYSTEM_BINARIES_ABS.contains(&usrbin.as_str()),
                "/usr/bin spelling missing for {bare}"
            );
        }
        for abs in SYSTEM_BINARIES_ABS {
            let bare = abs.rsplit('/').next().unwrap();
            assert!(
                SYSTEM_BINARIES_BARE.contains(&bare) || bare == "python3",
                "{abs} has no bare counterpart"
            );
        }
    }

    #[test]
    fn bare_python_fires() {
        // Bare `python` is not a base-system binary on
        // Tumbleweed; only `python3` is accepted, absolutely.
        for token in ["python", "/usr/bin/python"] {
            let results =
                run_desktop_seeded(&format!("[Desktop Entry]\nName=Foo\nExec={token}\n"), &[]);
            let lines = without_binary(&results);
            assert_eq!(lines.len(), 1, "{token}: unexpected: {results:?}");
            assert!(
                lines[0].contains(token),
                "detail names the token: {}",
                lines[0]
            );
        }
    }

    #[test]
    fn env_wrapper_judges_program_not_wrapper() {
        // `env FOO=1 missing-prog` fires on the program, never
        // silently on `env`.
        let results = run_desktop_seeded(
            "[Desktop Entry]\nName=Foo\nExec=env FOO=1 missing-prog\n",
            &[],
        );
        let lines = without_binary(&results);
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0].contains("missing-prog"),
            "detail names the program: {}",
            lines[0]
        );
        // The same shape with a present program stays silent.
        let results = run_desktop_seeded(
            "[Desktop Entry]\nName=Foo\nExec=env FOO=1 present-prog\n",
            &["usr/bin/present-prog"],
        );
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn env_wrapper_skips_flags() {
        for exec in ["env -i FOO=1 missing-prog", "env -u FOO missing-prog"] {
            let results =
                run_desktop_seeded(&format!("[Desktop Entry]\nName=Foo\nExec={exec}\n"), &[]);
            let lines = without_binary(&results);
            assert_eq!(lines.len(), 1, "{exec}: unexpected: {results:?}");
            assert!(
                lines[0].contains("missing-prog"),
                "{exec}: detail names the program: {}",
                lines[0]
            );
        }
    }

    #[test]
    fn sh_c_wrapper_judges_payload() {
        for exec in [
            "sh -c 'missing-prog'",
            "sh -c missing-prog",
            "bash -c 'missing-prog --flag'",
            "/bin/sh -c 'missing-prog'",
        ] {
            let results =
                run_desktop_seeded(&format!("[Desktop Entry]\nName=Foo\nExec={exec}\n"), &[]);
            let lines = without_binary(&results);
            assert_eq!(lines.len(), 1, "{exec}: unexpected: {results:?}");
            assert!(
                lines[0].contains("missing-prog"),
                "{exec}: detail names the payload program: {}",
                lines[0]
            );
        }
        // A present payload program stays silent, and a bare `sh`
        // (no `-c`) still resolves to the shell itself.
        let results = run_desktop_seeded(
            "[Desktop Entry]\nName=Foo\nExec=sh -c 'present-prog'\n",
            &["usr/bin/present-prog"],
        );
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
        let results = run_desktop_seeded("[Desktop Entry]\nName=Foo\nExec=sh\n", &[]);
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn absolute_env_wrapper_judges_program() {
        let results = run_desktop_seeded(
            "[Desktop Entry]\nName=Foo\nExec=/usr/bin/env FOO=1 missing-prog\n",
            &[],
        );
        let lines = without_binary(&results);
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0].contains("missing-prog"),
            "detail names the program: {}",
            lines[0]
        );
    }

    #[test]
    fn env_sh_c_nesting_resolves() {
        let results = run_desktop_seeded(
            "[Desktop Entry]\nName=Foo\nExec=env FOO=1 sh -c 'missing-prog'\n",
            &[],
        );
        let lines = without_binary(&results);
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0].contains("missing-prog"),
            "detail names the payload program: {}",
            lines[0]
        );
    }

    #[test]
    fn sibling_credit_requires_hard_edge() {
        // Same shape as the credited test, but the frontend has
        // no edge to the sibling at all: installing just the
        // frontend leaves a dead launcher, so it fires.
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
        assert_eq!(without_binary(&results).len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn sibling_credit_recommends_does_not_count() {
        // A frontend that only `Recommends` the sibling is not
        // credited: the sibling is not guaranteed installed.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let mut desktop = menu_pkg(
            &d0,
            "git-gui",
            vec![desktop_entry(
                d0.path(),
                "/usr/share/applications/git-gui.desktop",
                "git gui",
            )],
        );
        desktop.recommends = vec![dep_named("git-core")];
        let sibling = menu_pkg(&d1, "git-core", vec![reg_entry("/usr/bin/git")]);
        let src = menu_src_pkg(&d2);
        let results = run_menu_multi(&[src, desktop, sibling]);
        assert_eq!(without_binary(&results).len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn sibling_credit_via_provides() {
        // A `Requires` on a name the sibling provides is an edge
        // to the sibling, even when it is not the package name.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg_with_requires(
            &d0,
            "git-gui",
            vec![desktop_entry(
                d0.path(),
                "/usr/share/applications/git-gui.desktop",
                "git gui",
            )],
            &["git-binary"],
        );
        let mut sibling = menu_pkg(&d1, "git-core", vec![reg_entry("/usr/bin/git")]);
        sibling.provides = vec![dep_named("git-binary")];
        let src = menu_src_pkg(&d2);
        let results = run_menu_multi(&[src, desktop, sibling]);
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn sibling_credit_via_file_dependency() {
        // A `Requires` on the resolved file path itself is an
        // edge to whoever ships that file.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg_with_requires(
            &d0,
            "git-gui",
            vec![desktop_entry(
                d0.path(),
                "/usr/share/applications/git-gui.desktop",
                "git gui",
            )],
            &["/usr/bin/git"],
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
    fn effective_exec_binary_env_flags_and_dashdash() {
        // -C/--chdir consume their directory argument.
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("env -C /opt/foo myprog"),
            "myprog"
        );
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("env --chdir /opt/foo myprog"),
            "myprog"
        );
        // Assignments after -- are still skipped.
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("env -- FOO=1 myprog"),
            "myprog"
        );
        assert_eq!(MenuXDGCheck::effective_exec_binary("env -- FOO=1"), "env");
    }

    #[test]
    fn effective_exec_binary_env_flag_clusters() {
        // A cluster ending in a value-taking flag consumes the
        // next token as that flag's value, not as the program.
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("env -iu NAME myprog"),
            "myprog"
        );
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("env -iC /opt/foo myprog"),
            "myprog"
        );
        // A value attached inside the cluster consumes nothing more.
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("env -uNAME myprog"),
            "myprog"
        );
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("env -iuNAME myprog"),
            "myprog"
        );
    }

    #[test]
    fn effective_exec_binary_sh_long_flags_and_clusters() {
        // Long flags are skipped, not terminal.
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("bash --noprofile -c 'myprog'"),
            "myprog"
        );
        // -noexec is -n plus -o's argument, not -c.
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("bash -noexec myprog"),
            "bash"
        );
        // Combined flags ending in c still find -c.
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("bash -ec 'myprog'"),
            "myprog"
        );
        // -c with attached payload.
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("bash -cmyprog"),
            "myprog"
        );
        // End of options: a following -c is a script file.
        assert_eq!(MenuXDGCheck::effective_exec_binary("bash -- -c"), "bash");
    }

    #[test]
    fn effective_exec_binary_sh_c_env_unwraps() {
        // The `sh` direction unwraps `env` just like the `env`
        // direction unwraps `sh`: the payload's program, not `env`.
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("sh -c 'env FOO=1 myprog'"),
            "myprog"
        );
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("env sh -c 'env FOO=1 myprog'"),
            "myprog"
        );
        // A plain `sh -c` payload still resolves to its program.
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("sh -c 'myprog arg'"),
            "myprog"
        );
    }

    #[test]
    fn effective_exec_binary_deep_env_chain_reaches_program() {
        // Three env layers exhaust the unwrap depth exactly as the
        // program is reached: the program, not the outermost env.
        assert_eq!(
            MenuXDGCheck::effective_exec_binary("env env env myprog"),
            "myprog"
        );
    }

    #[test]
    fn usrmerge_counterpart_sanitizes() {
        assert_eq!(
            MenuXDGCheck::usrmerge_counterpart("/bin/x"),
            Some("/usr/bin/x".to_string())
        );
        assert_eq!(
            MenuXDGCheck::usrmerge_counterpart("/sbin/x"),
            Some("/usr/sbin/x".to_string())
        );
        assert_eq!(
            MenuXDGCheck::usrmerge_counterpart("/bin//x"),
            Some("/usr/bin/x".to_string())
        );
        assert_eq!(
            MenuXDGCheck::usrmerge_counterpart("/bin/./x"),
            Some("/usr/bin/x".to_string())
        );
        assert_eq!(
            MenuXDGCheck::usrmerge_counterpart("//bin/x"),
            Some("/usr/bin/x".to_string())
        );
        assert_eq!(
            MenuXDGCheck::usrmerge_counterpart("/./bin/x"),
            Some("/usr/bin/x".to_string())
        );
        // A `..` segment never yields a counterpart, mirroring
        // `binary_exists`: the spelling gains no build credit.
        assert_eq!(MenuXDGCheck::usrmerge_counterpart("/sbin/../bin/x"), None);
        assert_eq!(MenuXDGCheck::usrmerge_counterpart("/bin/../bin/x"), None);
        assert_eq!(MenuXDGCheck::usrmerge_counterpart("/bin/../x"), None);
        assert_eq!(MenuXDGCheck::usrmerge_counterpart("/bin/"), None);
        assert_eq!(MenuXDGCheck::usrmerge_counterpart("/usr/bin/x"), None);
        assert_eq!(MenuXDGCheck::usrmerge_counterpart("x"), None);
    }

    #[test]
    fn resolve_in_build_cycle_returns_none() {
        // A->B->A never resolves to a regular file: the iteration
        // cap returns None instead of hanging, so the candidate
        // fires (check-level pin:
        // sibling_symlink_loop_fires_on_complete_build).
        let build = DesktopBuild {
            symlinks: HashMap::from([
                ("/usr/bin/a".to_string(), "/usr/bin/b".to_string()),
                ("/usr/bin/b".to_string(), "/usr/bin/a".to_string()),
            ]),
            ..Default::default()
        };
        assert_eq!(MenuXDGCheck::resolve_in_build(&build, "/usr/bin/a"), None);
        // Positive control: a chain ending at a regular file resolves.
        let mut build = DesktopBuild {
            symlinks: HashMap::from([("/usr/bin/c".to_string(), "/usr/bin/real".to_string())]),
            ..Default::default()
        };
        // The positive control's target is a regular file: record
        // it as a file owner, since `regular` no longer exists as
        // a separate set.
        build.file_owners.insert(
            "/usr/bin/real".to_string(),
            HashSet::from(["owner".to_string()]),
        );
        assert_eq!(
            MenuXDGCheck::resolve_in_build(&build, "/usr/bin/c"),
            Some("/usr/bin/real".to_string())
        );
    }

    #[test]
    fn resolve_in_build_normalizes_absolute_targets() {
        // An absolute symlink target spelled with `//`, `/.` or
        // `..` segments resolves like its collapsed form, exactly
        // as the relative arm already normalizes its joined path.
        let mut build = DesktopBuild {
            symlinks: HashMap::from([
                ("/usr/bin/c".to_string(), "/usr/bin//real".to_string()),
                ("/usr/bin/d".to_string(), "/usr/bin/./real".to_string()),
                ("/usr/bin/e".to_string(), "/usr/bin/../bin/real".to_string()),
            ]),
            ..Default::default()
        };
        build.file_owners.insert(
            "/usr/bin/real".to_string(),
            HashSet::from(["owner".to_string()]),
        );
        for start in ["/usr/bin/c", "/usr/bin/d", "/usr/bin/e"] {
            assert_eq!(
                MenuXDGCheck::resolve_in_build(&build, start),
                Some("/usr/bin/real".to_string()),
                "{start}"
            );
        }
    }

    #[test]
    fn sibling_symlink_loop_fires_on_complete_build() {
        // A symlink chain that loops never resolves to a regular
        // file, so the candidate fires even on a complete build
        // with a hard edge to the sibling.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg_with_requires(
            &d0,
            "loop-frontend",
            vec![desktop_entry(
                d0.path(),
                "/usr/share/applications/loop.desktop",
                "/usr/bin/loopapp",
            )],
            &["loopapp"],
        );
        let sibling = menu_pkg(
            &d1,
            "loopapp",
            vec![
                link_entry("/usr/bin/loopapp", "loop2"),
                link_entry("/usr/bin/loop2", "loopapp"),
            ],
        );
        let src = menu_src_pkg(&d2);
        let results = run_menu_multi(&[src, desktop, sibling]);
        assert_eq!(without_binary(&results).len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn sibling_ghost_token_fires_on_complete_build() {
        // A token the sibling ships only as a `%ghost` entry is
        // not shipped content: the candidate fires even on a
        // complete build with a hard edge to the sibling.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg_with_requires(
            &d0,
            "ghost-frontend",
            vec![desktop_entry(
                d0.path(),
                "/usr/share/applications/ghost.desktop",
                "ghostprog",
            )],
            &["ghost-pkg"],
        );
        let sibling = menu_pkg(&d1, "ghost-pkg", vec![ghost_entry("/usr/bin/ghostprog")]);
        let src = menu_src_pkg(&d2);
        let results = run_menu_multi(&[src, desktop, sibling]);
        assert_eq!(without_binary(&results).len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn tryexec_missing_suppresses_without_binary_on_complete_build() {
        // The entry is shown only when its TryExec program
        // exists: on a source-complete build where no subpackage
        // ships the TryExec program, the entry stays hidden and
        // the missing Exec is moot.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg(
            &d0,
            "tryexec-frontend",
            vec![desktop_entry_tryexec(
                d0.path(),
                "/usr/share/applications/tryexec.desktop",
                "missing-prog",
                "/usr/bin/also-missing",
            )],
        );
        let src = menu_src_pkg(&d1);
        let results = run_menu_multi(&[src, desktop]);
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn tryexec_shipped_by_sibling_keeps_without_binary() {
        // The sibling ships the TryExec program under a hard
        // edge, so the entry is shown and the missing Exec is a
        // real broken launcher.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg_with_requires(
            &d0,
            "tryexec-frontend",
            vec![desktop_entry_tryexec(
                d0.path(),
                "/usr/share/applications/tryexec.desktop",
                "missing-prog",
                "/usr/bin/tryexec-prog",
            )],
            &["tryexec-pkg"],
        );
        let sibling = menu_pkg(&d1, "tryexec-pkg", vec![reg_entry("/usr/bin/tryexec-prog")]);
        let src = menu_src_pkg(&d2);
        let results = run_menu_multi(&[src, desktop, sibling]);
        assert_eq!(without_binary(&results).len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn tryexec_missing_still_fires_on_partial_build() {
        // Without the build's source package, whether the entry
        // is shown is undecidable: the per-package verdict stands
        // and the missing Exec fires.
        let d0 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg(
            &d0,
            "tryexec-frontend",
            vec![desktop_entry_tryexec(
                d0.path(),
                "/usr/share/applications/tryexec.desktop",
                "missing-prog",
                "/usr/bin/also-missing",
            )],
        );
        let results = run_menu_multi(&[desktop]);
        assert_eq!(without_binary(&results).len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn tryexec_resolving_in_package_keeps_without_binary() {
        // The TryExec program ships in this package, so the entry
        // is shown and the missing Exec fires.
        let results = run_desktop_seeded(
            "[Desktop Entry]\nName=Foo\nExec=missing-prog\nTryExec=/usr/bin/present-prog\n",
            &["usr/bin/present-prog"],
        );
        let lines = without_binary(&results);
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn tryexec_system_binary_keeps_without_binary() {
        // A TryExec naming a base-system binary shows the entry,
        // so the missing Exec fires.
        let results = run_desktop_seeded(
            "[Desktop Entry]\nName=Foo\nExec=missing-prog\nTryExec=/usr/bin/true\n",
            &[],
        );
        let lines = without_binary(&results);
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn sibling_icon_absolute_credited_on_complete_build() {
        // rpminspect searches every peer subpackage for the icon:
        // an absolute Icon shipped by a sibling, under a hard
        // edge on a source-complete build, no longer fires.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg_with_requires(
            &d0,
            "icon-frontend",
            vec![desktop_entry_icon(
                d0.path(),
                "/usr/share/applications/icon.desktop",
                "/usr/share/icons/hicolor/48x48/apps/app.png",
            )],
            &["icon-pkg"],
        );
        let sibling = menu_pkg(
            &d1,
            "icon-pkg",
            vec![reg_entry("/usr/share/icons/hicolor/48x48/apps/app.png")],
        );
        let src = menu_src_pkg(&d2);
        let results = run_menu_multi(&[src, desktop, sibling]);
        assert!(
            icon_not_found(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn sibling_icon_absolute_fires_on_partial_build() {
        // The sibling ships the icon, but the run holds no source
        // package: the build is not judged complete and the
        // candidate fires as the per-package verdict.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg(
            &d0,
            "icon-frontend",
            vec![desktop_entry_icon(
                d0.path(),
                "/usr/share/applications/icon.desktop",
                "/usr/share/icons/hicolor/48x48/apps/app.png",
            )],
        );
        let sibling = menu_pkg(
            &d1,
            "icon-pkg",
            vec![reg_entry("/usr/share/icons/hicolor/48x48/apps/app.png")],
        );
        let results = run_menu_multi(&[desktop, sibling]);
        assert_eq!(icon_not_found(&results).len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn sibling_icon_absolute_fires_without_edge() {
        // Same shape as the credited test, but the frontend has
        // no edge to the sibling at all: installing just the
        // frontend leaves a broken icon, so it fires.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg(
            &d0,
            "icon-frontend",
            vec![desktop_entry_icon(
                d0.path(),
                "/usr/share/applications/icon.desktop",
                "/usr/share/icons/hicolor/48x48/apps/app.png",
            )],
        );
        let sibling = menu_pkg(
            &d1,
            "icon-pkg",
            vec![reg_entry("/usr/share/icons/hicolor/48x48/apps/app.png")],
        );
        let src = menu_src_pkg(&d2);
        let results = run_menu_multi(&[src, desktop, sibling]);
        assert_eq!(icon_not_found(&results).len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn sibling_icon_credit_survives_state_export_import() {
        // The deferred icon verdict merges through export/import
        // like the Exec verdict: the sibling's inventory arrives
        // through `import_state`, and the candidate that arrived
        // the other way is still credited.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg_with_requires(
            &d0,
            "icon-frontend",
            vec![desktop_entry_icon(
                d0.path(),
                "/usr/share/applications/icon.desktop",
                "/usr/share/icons/hicolor/48x48/apps/app.png",
            )],
            &["icon-pkg"],
        );
        let sibling = menu_pkg(
            &d1,
            "icon-pkg",
            vec![reg_entry("/usr/share/icons/hicolor/48x48/apps/app.png")],
        );
        let src = menu_src_pkg(&d2);
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut first = MenuXDGCheck::new(&config);
        first.check(&src, &config, &mut out);
        first.check(&sibling, &config, &mut out);
        let state = first.export_state().expect("exported state");
        let mut second = MenuXDGCheck::new(&config);
        second.check(&desktop, &config, &mut out);
        second.import_state(state);
        second.after_checks(&config, &mut out);
        let results = out.results().to_vec();
        assert!(
            icon_not_found(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn directory_file_icon_missing_fires() {
        // A `.directory` file's absolute Icon defers like a
        // `.desktop` file's: missing everywhere in the run, it
        // fires from `after_checks`.
        let d0 = tempfile::tempdir().unwrap();
        let path = d0.path().join("test.desktop");
        std::fs::write(
            &path,
            "[Desktop Entry]\nType=Directory\nName=Test\nIcon=/usr/share/icons/hicolor/48x48/apps/app.png\n",
        )
        .unwrap();
        let desktop = menu_pkg(
            &d0,
            "dir-frontend",
            vec![PkgFile {
                name: "/usr/share/applications/test.directory".to_string(),
                path: path.to_str().unwrap().to_string(),
                mode: 0o100644,
                ..Default::default()
            }],
        );
        let results = run_menu_multi(&[desktop]);
        assert_eq!(icon_not_found(&results).len(), 1, "unexpected: {results:?}");
    }

    #[test]
    fn sibling_credit_survives_state_export_import() {
        // The run merges per-package check states: the sibling's
        // inventory (and its dep-name owners) arrive through
        // `import_state`, and the deferred verdict must still
        // credit the candidate that arrived the other way.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let desktop = menu_pkg_with_requires(
            &d0,
            "git-gui",
            vec![desktop_entry(
                d0.path(),
                "/usr/share/applications/git-gui.desktop",
                "git gui",
            )],
            &["git-core"],
        );
        let sibling = menu_pkg(&d1, "git-core", vec![reg_entry("/usr/bin/git")]);
        let src = menu_src_pkg(&d2);
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut first = MenuXDGCheck::new(&config);
        first.check(&src, &config, &mut out);
        first.check(&sibling, &config, &mut out);
        let state = first.export_state().expect("exported state");
        let mut second = MenuXDGCheck::new(&config);
        second.check(&desktop, &config, &mut out);
        second.import_state(state);
        second.after_checks(&config, &mut out);
        let results = out.results().to_vec();
        assert!(
            without_binary(&results).is_empty(),
            "unexpected: {results:?}"
        );
    }
}
