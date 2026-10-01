//! `FileDigestCheck` — whitelist file digests in restricted locations.
//!
//! Ported from `rpmlint/checks/FileDigestCheck.py` (639 lines) plus the
//! digester and content-check helpers in `rpmlint/filedigestcheck.py`.
//! Findings: `{type}-file-unauthorized`, `{type}-file-digest-mismatch`,
//! `{type}-file-ghost`, `{type}-file-symlink`, `{type}-file-parse-error`,
//! `{type}-whitelisted-file-missing`.
//!
//! Supports four digesters: `default` (raw bytes), `shell` (strip comments/
//! whitespace), `xml` (approximate canonicalization — a known limitation, see
//! the parity ledger), `systemd-socket` (socket unit keys).

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use indexmap::IndexMap;
use sha2::{Digest, Sha256};

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::{PkgFile, is_dir, is_symlink};

/// A digester: filters file content before hashing.
trait Digester {
    fn digest(&self, path: &str, algorithm: &str) -> Result<String, String>;
}

/// Raw byte digest.
struct DefaultDigester;

impl Digester for DefaultDigester {
    fn digest(&self, path: &str, algorithm: &str) -> Result<String, String> {
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        let mut hasher = new_hasher(algorithm)?;
        let mut buf = [0u8; 4096];
        loop {
            let n = file.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    }
}

/// Shell-style: skip empty lines and `#` comments, normalize shebang.
struct ShellDigester;

impl Digester for ShellDigester {
    fn digest(&self, path: &str, algorithm: &str) -> Result<String, String> {
        let file = File::open(path).map_err(|e| e.to_string())?;
        let reader = BufReader::new(file);
        let mut hasher = new_hasher(algorithm)?;
        for (nr, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| e.to_string())?;
            let stripped = line.trim();
            if stripped.is_empty() {
                continue;
            }
            if nr == 0 && stripped.starts_with("#!") {
                // Normalize python3.x to python3.
                let normalized = normalize_shebang(&line);
                hasher.update(normalized.as_bytes());
                hasher.update(b"\n");
            } else if stripped.starts_with('#') {
                continue;
            } else {
                hasher.update(line.trim_end().as_bytes());
                hasher.update(b"\n");
            }
        }
        Ok(hex::encode(hasher.finalize()))
    }
}

fn normalize_shebang(line: &str) -> String {
    // Replace `python3.N` with `python3`.
    let mut result = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == 'p' {
            let mut word = String::from("p");
            while let Some(&nc) = chars.peek() {
                if nc.is_alphanumeric() || nc == '.' || nc == '_' {
                    word.push(chars.next().unwrap());
                } else {
                    break;
                }
            }
            if word.starts_with("python3.") {
                // Strip the minor version.
                if let Some(dot) = word.find('.') {
                    let after = &word[dot + 1..];
                    if after.chars().all(|c| c.is_ascii_digit()) {
                        result.push_str("python3");
                        continue;
                    }
                }
            }
            result.push_str(&word);
        } else {
            result.push(c);
        }
    }
    result
}

/// XML: canonicalized form without comments.
///
/// This is an approximation, not real C14N (`xml.etree.ElementTree.
/// canonicalize` in the reference): it strips comments and collapses
/// whitespace between tags but does not normalize attributes or namespaces.
/// Recorded as a known limitation in the parity ledger.
struct XmlDigester;

impl Digester for XmlDigester {
    fn digest(&self, path: &str, algorithm: &str) -> Result<String, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let normalized = normalize_xml(&content);
        let mut hasher = new_hasher(algorithm)?;
        hasher.update(normalized.as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }
}

fn normalize_xml(content: &str) -> String {
    // Simple XML normalization: strip comments, collapse whitespace between
    // tags, and remove the XML declaration. This is sufficient for digest
    // stability against comment/whitespace changes.
    let mut out = String::new();
    let mut in_comment = false;
    let mut chars = content.chars().peekable();

    while let Some(c) = chars.next() {
        if in_comment {
            if c == '-' && chars.peek() == Some(&'-') {
                chars.next();
                if chars.peek() == Some(&'>') {
                    chars.next();
                    in_comment = false;
                }
            }
            continue;
        }
        if c == '<' {
            // Check for comment start
            let mut peek = chars.clone();
            if peek.next() == Some('!') && peek.next() == Some('-') && peek.next() == Some('-') {
                // Skip the '<!--'
                chars.next();
                chars.next();
                chars.next();
                in_comment = true;
                continue;
            }
            // Check for XML declaration or DOCTYPE - skip them
            if peek.next() == Some('?') || (peek.next() == Some('!')) {
                // Skip until '>'
                for nc in chars.by_ref() {
                    if nc == '>' {
                        break;
                    }
                }
                continue;
            }
            out.push(c);
        } else if c.is_whitespace() {
            // Collapse whitespace: only keep single spaces between non-whitespace,
            // and skip whitespace between '>' and '<'
            let mut ws = String::from(c);
            while let Some(&nc) = chars.peek() {
                if nc.is_whitespace() {
                    ws.push(chars.next().unwrap());
                } else {
                    break;
                }
            }
            // Only emit whitespace if not between tags
            let last = out.chars().last();
            let next = chars.peek().copied();
            if last != Some('>') && next != Some('<') {
                out.push(' ');
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Systemd socket unit: hash only the relevant `[Socket]` keys.
struct SocketUnitDigester;

impl SocketUnitDigester {
    const KEYS_TO_HASH: &'static [&'static str] = &[
        "ListenStream",
        "ListenDatagram",
        "ListenSequentialPacket",
        "ListenFIFO",
        "ListenSpecial",
        "ListenNetlink",
        "ListenMessageQueue",
        "SocketProtocol",
        "BindToDevice",
        "SocketUser",
        "SocketGroup",
        "SocketMode",
        "DirectoryMode",
        "PassSecurity",
        "AcceptFileDescriptors",
        "ExecStartPre",
        "ExecStartPost",
        "ExecStopPre",
        "ExecStopPost",
        "FileDescriptorName",
        "PassFileDescriptorsToExec",
    ];
}

impl Digester for SocketUnitDigester {
    fn digest(&self, path: &str, algorithm: &str) -> Result<String, String> {
        let config = parse_socket_unit(path).ok_or_else(|| format!("failed to parse {path}"))?;
        let socket = config
            .get("Socket")
            .ok_or_else(|| format!("[Socket] section missing in {path}"))?;
        let mut hasher = new_hasher(algorithm)?;
        for (key, values) in socket {
            if Self::KEYS_TO_HASH.contains(&key.as_str()) {
                for value in values {
                    hasher.update(format!("{key}={value}\n").as_bytes());
                }
            }
        }
        Ok(hex::encode(hasher.finalize()))
    }
}

/// Parse a systemd socket unit file (simplified INI).
///
/// `IndexMap` preserves file order: the reference iterates a Python dict
/// (insertion order) straight into the hasher, so a `HashMap` here would make
/// the digest nondeterministic across processes.
fn parse_socket_unit(path: &str) -> Option<IndexMap<String, IndexMap<String, Vec<String>>>> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut ret: IndexMap<String, IndexMap<String, Vec<String>>> = IndexMap::new();
    let mut section: Option<String> = None;
    let mut multiline = String::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.ends_with('\\') {
            multiline.push_str(line.strip_suffix('\\').unwrap_or(line));
            multiline.push(' ');
            continue;
        }
        let line = format!("{multiline}{line}");
        multiline.clear();

        if line.len() > 2 && line.starts_with('[') && line.ends_with(']') {
            section = Some(line[1..line.len() - 1].to_string());
            ret.entry(section.clone().unwrap()).or_default();
            continue;
        }
        let Some(sec) = &section else {
            return None;
        };
        let (key, value) = line.split_once('=')?;
        // The reference does `key.rstrip()` / `value.lstrip()` (rpmlint
        // #1534): a key keeps leading whitespace, a value keeps trailing.
        let key = key.trim_end().to_string();
        let value = value.trim_start().to_string();
        ret.get_mut(sec)
            .unwrap()
            .entry(key)
            .or_default()
            .push(value);
    }

    Some(ret)
}

/// `VarlinkServiceCheck`: whether a `.socket` unit refers to a Varlink
/// service (used as the `ContentCheck` for socket whitelisting).
struct VarlinkServiceCheck;

impl VarlinkServiceCheck {
    fn is_restricted(path: &str) -> bool {
        let Some(config) = parse_socket_unit(path) else {
            // Failed to parse the file, assume it is restricted.
            return true;
        };
        let Some(socket) = config.get("Socket") else {
            // No socket section in a socket unit? Not Varlink anyway.
            return false;
        };
        socket
            .get("FileDescriptorName")
            .is_some_and(|names| names.iter().any(|name| name.contains("varlink")))
    }
}

/// Create a hasher for the named algorithm.
fn new_hasher(algorithm: &str) -> Result<Box<dyn DynDigest>, String> {
    match algorithm {
        "sha256" => Ok(Box::new(Sha256::new())),
        _ => Err(format!("unsupported digest algorithm: {algorithm}")),
    }
}

/// Object-safe wrapper for digest algorithms.
trait DynDigest {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> Vec<u8>;
}

impl DynDigest for Sha256 {
    fn update(&mut self, data: &[u8]) {
        Digest::update(self, data);
    }
    fn finalize(self: Box<Self>) -> Vec<u8> {
        Digest::finalize(*self).to_vec()
    }
}

/// We need `hex` for encoding. Add a minimal hex encoder here to avoid a
/// dependency.
mod hex {
    pub fn encode(data: Vec<u8>) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// One check type configuration (e.g. `pam`, `dbus`).
#[derive(Debug, Clone)]
struct CheckTypeConfig {
    check_type: String,
    locations: Vec<String>,
    name_patterns: Vec<String>,
    follow_symlinks: bool,
    recursive: bool,
    /// Optional content check (e.g. `VarlinkServiceCheck`) deciding whether
    /// a file in a restricted location is actually subject to whitelisting.
    content_check: Option<String>,
}

/// One digest entry in a group.
#[derive(Debug, Clone)]
struct DigestInfo {
    path: String,
    algorithm: String,
    hash: String,
    digester: String,
}

/// A digest group: whitelisted paths for a package.
#[derive(Debug, Clone)]
struct DigestGroup {
    check_type: String,
    packages: Vec<String>,
    digests: Vec<DigestInfo>,
}

/// A recorded digest mismatch, for the violation report.
#[derive(Debug, Clone)]
struct MismatchInfo {
    algorithm: String,
    expected: String,
    actual: String,
}

/// One `GhostFilesExceptions`/`SymlinkExceptions` entry.
#[derive(Debug, Clone, Default)]
struct ExceptionList {
    packages: Vec<String>,
    paths: Vec<String>,
}

/// Trie node for fast restricted-path lookup.
#[derive(Debug, Default)]
struct TrieNode {
    children: HashMap<String, TrieNode>,
    terminal: bool,
}

impl TrieNode {
    fn insert(&mut self, path: &str) {
        let mut node = self;
        for part in path.split('/').filter(|p| !p.is_empty()) {
            node = node.children.entry(part.to_string()).or_default();
        }
        node.terminal = true;
    }

    /// True when `path` is within a restricted location.
    fn is_restricted(&self, path: &str) -> bool {
        let mut node = self;
        for part in path.split('/').filter(|p| !p.is_empty()) {
            if node.terminal {
                return true;
            }
            match node.children.get(part) {
                Some(child) => node = child,
                None => return false,
            }
        }
        false
    }
}

pub struct FileDigestCheck {
    checks: Vec<CheckTypeConfig>,
    trie: TrieNode,
    digest_groups: Vec<DigestGroup>,
    digest_cache: HashMap<(String, String, String), String>,
    ghost_file_exceptions: Vec<ExceptionList>,
    symlink_exceptions: Vec<ExceptionList>,
}

impl FileDigestCheck {
    pub fn new(config: &Config) -> Self {
        // The reference reads `self.config.configuration['FileDigestLocation']`,
        // raising `KeyError` when the key is absent: fail loudly here too.
        let locations = config
            .configuration
            .get("FileDigestLocation")
            .unwrap_or_else(|| {
                panic!(
                    "FileDigestCheck requires the FileDigestLocation configuration key \
                 (the reference raises KeyError when it is absent)"
                )
            });
        let locations = locations
            .as_table()
            .unwrap_or_else(|| panic!("FileDigestCheck: FileDigestLocation must be a table"));

        let mut checks = Vec::new();
        let mut trie = TrieNode::default();

        for (check_type, cfg) in locations {
            let cfg_table = cfg.as_table().unwrap_or_else(|| {
                panic!("FileDigestCheck: FileDigestLocation[{check_type}] must be a table")
            });
            // The reference reads `config['Locations']`, raising KeyError
            // when absent: fail loudly on absent or malformed entries.
            let locations: Vec<String> = cfg_table
                .get("Locations")
                .unwrap_or_else(|| {
                    panic!(
                        "FileDigestCheck: FileDigestLocation[{check_type}] \
                         is missing required \"Locations\""
                    )
                })
                .as_array()
                .unwrap_or_else(|| {
                    panic!(
                        "FileDigestCheck: FileDigestLocation[{check_type}].Locations \
                         must be an array of strings"
                    )
                })
                .iter()
                .map(|v| {
                    v.as_str()
                        .unwrap_or_else(|| {
                            panic!(
                                "FileDigestCheck: FileDigestLocation[{check_type}].Locations \
                                 must be an array of strings"
                            )
                        })
                        .to_string()
                })
                .collect();
            // Optional keys: the reference `setdefault`s them, so absence
            // keeps the default; a present-but-malformed value is a config
            // error and fails loudly instead of silently defaulting.
            let name_patterns: Vec<String> =
                Self::cfg_string_array(cfg_table, check_type, "NamePatterns");
            let follow_symlinks = Self::cfg_bool(cfg_table, check_type, "FollowSymlinks", false);
            let recursive = Self::cfg_bool(cfg_table, check_type, "Recursive", true);
            let content_check = Self::cfg_opt_string(cfg_table, check_type, "ContentCheck");

            for loc in &locations {
                trie.insert(loc);
            }

            checks.push(CheckTypeConfig {
                check_type: check_type.clone(),
                locations,
                name_patterns,
                follow_symlinks,
                recursive,
                content_check,
            });
        }

        let digest_groups = Self::parse_digest_groups(config);
        let ghost_file_exceptions = Self::parse_exception_lists(config, "GhostFilesExceptions");
        let symlink_exceptions = Self::parse_exception_lists(config, "SymlinkExceptions");

        Self {
            checks,
            trie,
            digest_groups,
            digest_cache: HashMap::new(),
            ghost_file_exceptions,
            symlink_exceptions,
        }
    }

    /// Optional string-array setting (e.g. `NamePatterns`): absent keeps the
    /// default, present-but-malformed fails loudly.
    fn cfg_string_array(cfg: &toml::Table, check_type: &str, key: &str) -> Vec<String> {
        match cfg.get(key) {
            None => Vec::new(),
            Some(v) => v
                .as_array()
                .unwrap_or_else(|| {
                    panic!(
                        "FileDigestCheck: FileDigestLocation[{check_type}].{key} \
                         must be an array of strings"
                    )
                })
                .iter()
                .map(|e| {
                    e.as_str()
                        .unwrap_or_else(|| {
                            panic!(
                                "FileDigestCheck: FileDigestLocation[{check_type}].{key} \
                                 must be an array of strings"
                            )
                        })
                        .to_string()
                })
                .collect(),
        }
    }

    /// Optional boolean setting (e.g. `FollowSymlinks`): absent keeps the
    /// default, present-but-malformed fails loudly.
    fn cfg_bool(cfg: &toml::Table, check_type: &str, key: &str, default: bool) -> bool {
        match cfg.get(key) {
            None => default,
            Some(v) => v.as_bool().unwrap_or_else(|| {
                panic!("FileDigestCheck: FileDigestLocation[{check_type}].{key} must be a boolean")
            }),
        }
    }

    /// Optional string setting (e.g. `ContentCheck`): absent is `None`,
    /// present-but-malformed fails loudly.
    fn cfg_opt_string(cfg: &toml::Table, check_type: &str, key: &str) -> Option<String> {
        cfg.get(key).map(|v| {
            v.as_str()
                .unwrap_or_else(|| {
                    panic!(
                        "FileDigestCheck: FileDigestLocation[{check_type}].{key} \
                         must be a string"
                    )
                })
                .to_string()
        })
    }

    fn parse_exception_lists(config: &Config, key: &str) -> Vec<ExceptionList> {
        let mut out = Vec::new();
        let Some(arr) = config.configuration.get(key).and_then(|v| v.as_array()) else {
            return out;
        };
        for v in arr {
            let Some(table) = v.as_table() else {
                continue;
            };
            let mut packages = Vec::new();
            if let Some(p) = table.get("package").and_then(|v| v.as_str()) {
                packages.push(p.to_string());
            }
            if let Some(arr) = table.get("packages").and_then(|v| v.as_array()) {
                for p in arr {
                    if let Some(s) = p.as_str() {
                        packages.push(s.to_string());
                    }
                }
            }
            // Malformed entries (no package key) cannot match anything.
            if packages.is_empty() {
                continue;
            }
            let paths: Vec<String> = table
                .get("paths")
                .unwrap_or_else(|| {
                    panic!("FileDigestCheck: {key} entry for {packages:?} is missing \"paths\"")
                })
                .as_array()
                .unwrap_or_else(|| {
                    panic!(
                        "FileDigestCheck: {key} entry for {packages:?}: \
                         \"paths\" must be an array of strings"
                    )
                })
                .iter()
                .map(|v| {
                    v.as_str()
                        .unwrap_or_else(|| {
                            panic!(
                                "FileDigestCheck: {key} entry for {packages:?}: \
                                 \"paths\" must be an array of strings"
                            )
                        })
                        .to_string()
                })
                .collect();
            out.push(ExceptionList { packages, paths });
        }
        out
    }

    fn parse_digest_groups(config: &Config) -> Vec<DigestGroup> {
        let mut groups = Vec::new();
        if let Some(arr) = config
            .configuration
            .get("FileDigestGroup")
            .and_then(|v| v.as_array())
        {
            for v in arr {
                if let Some(table) = v.as_table() {
                    let check_type = table
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let mut packages = Vec::new();
                    if let Some(p) = table.get("package").and_then(|v| v.as_str()) {
                        packages.push(p.to_string());
                    }
                    if let Some(arr) = table.get("packages").and_then(|v| v.as_array()) {
                        for p in arr {
                            if let Some(s) = p.as_str() {
                                packages.push(s.to_string());
                            }
                        }
                    }
                    let mut digests = Vec::new();
                    // Expand `nodigests` into skip entries.
                    if let Some(nodigests) = table.get("nodigests").and_then(|v| v.as_array()) {
                        for entry in nodigests {
                            if let Some(path) = entry.as_str() {
                                digests.push(DigestInfo {
                                    path: path.to_string(),
                                    algorithm: "skip".to_string(),
                                    hash: String::new(),
                                    digester: "default".to_string(),
                                });
                            }
                        }
                    }
                    if let Some(arr) = table.get("digests").and_then(|v| v.as_array()) {
                        for d in arr {
                            if let Some(dt) = d.as_table() {
                                digests.push(DigestInfo {
                                    path: dt
                                        .get("path")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    algorithm: dt
                                        .get("algorithm")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("sha256")
                                        .to_string(),
                                    hash: dt
                                        .get("hash")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    digester: dt
                                        .get("digester")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("default")
                                        .to_string(),
                                });
                            }
                        }
                    }
                    groups.push(DigestGroup {
                        check_type,
                        packages,
                        digests,
                    });
                }
            }
        }
        groups
    }

    /// Which check type applies to `pkgfile`, if any.
    fn lookup_check_for_file(&self, pkgfile: &PkgFile) -> Option<&CheckTypeConfig> {
        if is_dir(pkgfile.mode) {
            return None;
        }
        let path = Path::new(&pkgfile.name);
        if !self.trie.is_restricted(&pkgfile.name) {
            return None;
        }
        for config in &self.checks {
            for location in &config.locations {
                let loc_path = Path::new(location);
                if let Ok(subpath) = path.strip_prefix(loc_path) {
                    // The reference's `if not subpath` guard is dead code
                    // (`bool(Path('.'))` is always True), so a file sitting
                    // exactly at a Location root is matched, not skipped.
                    if !config.recursive && subpath.components().count() > 1 {
                        continue;
                    }
                    if config.name_patterns.is_empty() {
                        return Some(config);
                    }
                    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    for pattern in &config.name_patterns {
                        if glob_match(pattern, filename) {
                            return Some(config);
                        }
                    }
                }
            }
        }
        None
    }

    /// Whether the package name matches a `package`/`packages` entry,
    /// resolving `glob:` patterns.
    fn matches_pkg(packages: &[String], pkg_name: &str) -> bool {
        packages.iter().any(|p| {
            if p == pkg_name {
                true
            } else if let Some(pattern) = p.strip_prefix("glob:") {
                glob_match(pattern, pkg_name)
            } else {
                false
            }
        })
    }

    fn matches_group(group: &DigestGroup, pkg_name: &str) -> bool {
        Self::matches_pkg(&group.packages, pkg_name)
    }

    /// Whether a ghost file is covered by a `GhostFilesExceptions` entry.
    fn is_ghost_allowed(&self, pkg: &Pkg, path: &str) -> bool {
        self.ghost_file_exceptions.iter().any(|exc| {
            Self::matches_pkg(&exc.packages, &pkg.name) && exc.paths.iter().any(|p| p == path)
        })
    }

    /// Whether a symlink is covered by a `SymlinkExceptions` entry.
    fn is_symlink_allowed(&self, pkg: &Pkg, path: &str) -> bool {
        self.symlink_exceptions.iter().any(|exc| {
            Self::matches_pkg(&exc.packages, &pkg.name) && exc.paths.iter().any(|p| p == path)
        })
    }

    /// Whether a file in a restricted location contains data subject to
    /// whitelisting, honouring the check type's `ContentCheck` setting.
    fn has_restricted_content(&self, check: &CheckTypeConfig, pkg: &Pkg, path: &str) -> bool {
        let Some(content_check) = check.content_check.as_deref() else {
            // No content check declared: every file in the restricted
            // location is covered.
            return true;
        };
        let resolved = pkg.files.iter().find(|f| f.name == path).map(|pkgfile| {
            pkg.readlink(pkgfile)
                .map(|r| r.path.clone())
                .unwrap_or_else(|| pkgfile.path.clone())
        });
        let Some(resolved) = resolved else {
            // Link resolution failed; later checks complain more explicitly.
            return true;
        };
        match content_check {
            "VarlinkServiceCheck" => VarlinkServiceCheck::is_restricted(&resolved),
            other => panic!("FileDigestCheck: no matching type for ContentCheck={other}"),
        }
    }

    /// Calculate the digest of a file using the named digester.
    fn calc_digest(
        &mut self,
        digester_name: &str,
        path: &str,
        algorithm: &str,
    ) -> Result<String, String> {
        let cache_key = (
            digester_name.to_string(),
            path.to_string(),
            algorithm.to_string(),
        );
        if let Some(cached) = self.digest_cache.get(&cache_key) {
            return Ok(cached.clone());
        }
        let digester: Box<dyn Digester> = match digester_name {
            "default" => Box::new(DefaultDigester),
            "shell" => Box::new(ShellDigester),
            "xml" => Box::new(XmlDigester),
            "systemd-socket" => Box::new(SocketUnitDigester),
            _ => return Err(format!("unknown digester: {digester_name}")),
        };
        let digest = digester.digest(path, algorithm)?;
        self.digest_cache.insert(cache_key, digest.clone());
        Ok(digest)
    }

    /// Follow the symlink chain of the named package file, if any.
    ///
    /// Mirrors the reference `_resolve_links`: an unresolvable link yields
    /// `None` (the caller marks the group mismatched with no finding) rather
    /// than the unresolved entry, which would fail digest calculation with a
    /// bogus `-file-parse-error`.
    fn resolve_pkgfile<'a>(&self, pkg: &'a Pkg, path: &str) -> Option<&'a PkgFile> {
        let pkgfile = pkg.files.iter().find(|f| f.name == path)?;
        if is_symlink(pkgfile.mode) {
            pkg.readlink(pkgfile)
        } else {
            Some(pkgfile)
        }
    }

    /// Check one digest entry against the package: `(matches, actual_hash)`.
    /// The hash is `None` for `skip` entries or when the file is absent.
    fn check_digest(
        &mut self,
        pkg: &Pkg,
        info: &DigestInfo,
    ) -> Result<(bool, Option<String>), String> {
        if info.algorithm == "skip" {
            return Ok((true, None));
        }
        let Some(pkgfile) = self.resolve_pkgfile(pkg, &info.path) else {
            return Ok((false, None));
        };
        let digest_path = pkgfile.path.clone();
        let actual = self.calc_digest(&info.digester, &digest_path, &info.algorithm)?;
        Ok((actual == info.hash, Some(actual)))
    }

    /// All digest groups applying to this check type and package.
    fn find_digest_groups(&self, pkg: &Pkg, check_type: &str) -> Vec<DigestGroup> {
        self.digest_groups
            .iter()
            .filter(|g| g.check_type == check_type && Self::matches_group(g, &pkg.name))
            .cloned()
            .collect()
    }

    /// Complain about restricted files with no whitelisting entry. Returns
    /// the paths that are whitelisted (digests still to verify).
    fn check_for_unauthorized(
        &self,
        pkg: &Pkg,
        check: &CheckTypeConfig,
        restricted_paths: &[String],
        out: &mut Filter,
    ) -> Vec<String> {
        let check_type = &check.check_type;
        let mut known_paths: HashSet<String> = HashSet::new();
        for group in self.find_digest_groups(pkg, check_type) {
            for d in &group.digests {
                known_paths.insert(d.path.clone());
            }
        }

        let mut whitelisted = Vec::new();
        for path in restricted_paths {
            let mut found = false;
            for known in &known_paths {
                if path == known || (known.starts_with("glob:") && glob_match(&known[5..], path)) {
                    found = true;
                    whitelisted.push(path.clone());
                    break;
                }
            }
            if !found {
                // The reference also appends a `({digest_hint})` detail listing
                // the observed digests; see the parity ledger.
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    &format!("{check_type}-file-unauthorized"),
                    &[path],
                );
            }
        }
        whitelisted
    }

    /// Verify one digest group as a set of related paths: the whitelisting
    /// is only complete when every file in the group has a valid digest.
    /// Fully verified paths go into `verified_paths`; mismatches into
    /// `mismatches`.
    fn check_digest_group(
        &mut self,
        pkg: &Pkg,
        check_type: &str,
        group: &DigestGroup,
        verified_paths: &mut HashSet<String>,
        mismatches: &mut HashMap<String, Vec<MismatchInfo>>,
        out: &mut Filter,
    ) {
        let mut missing_files = Vec::new();
        let mut valid_files = Vec::new();
        let mut found_mismatch = false;
        // Mismatches for paths outside restricted locations are only
        // reported when some restricted path verified cleanly, to avoid
        // noise and confusion.
        let mut unrelated_mismatches: HashMap<String, Vec<MismatchInfo>> = HashMap::new();

        for digest_info in &group.digests {
            let path = &digest_info.path;
            if pkg.files.iter().all(|f| f.name != *path) {
                // This digest entry might not be needed anymore. Tolerate
                // absent files as long as the existing ones verify; glob
                // patterns are not supported here.
                if !path.starts_with("glob:") {
                    missing_files.push(path.clone());
                }
                continue;
            }

            match self.check_digest(pkg, digest_info) {
                Err(e) => {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        &format!("{check_type}-file-parse-error"),
                        &[path, &format!("failed to calculate digest: {e}")],
                    );
                    continue;
                }
                Ok((valid, hashsum)) => {
                    if valid {
                        valid_files.push(path.clone());
                    } else {
                        found_mismatch = true;
                    }
                    if let Some(actual) = hashsum {
                        let info = MismatchInfo {
                            algorithm: digest_info.algorithm.clone(),
                            expected: digest_info.hash.clone(),
                            actual,
                        };
                        if self.trie.is_restricted(path) {
                            mismatches.entry(path.clone()).or_default().push(info);
                        } else {
                            unrelated_mismatches
                                .entry(path.clone())
                                .or_default()
                                .push(info);
                        }
                    }
                }
            }
        }

        if !valid_files.is_empty() && !unrelated_mismatches.is_empty() {
            for (path, infos) in unrelated_mismatches {
                mismatches.entry(path).or_default().extend(infos);
            }
        }

        if found_mismatch {
            // The group is not fully valid for this package.
            return;
        }

        for missing in &missing_files {
            add_info(
                out,
                Level::Warning,
                pkg,
                &format!("{check_type}-whitelisted-file-missing"),
                &[missing, "path present in whitelist but not in package"],
            );
        }

        verified_paths.extend(valid_files);
    }

    /// Check the whitelisted restricted paths for valid digest entries.
    fn check_for_valid_digests(
        &mut self,
        pkg: &Pkg,
        check: &CheckTypeConfig,
        restricted_paths: &[String],
        out: &mut Filter,
    ) {
        let check_type = &check.check_type;
        let mut mismatches: HashMap<String, Vec<MismatchInfo>> = HashMap::new();
        let mut verified_paths: HashSet<String> = HashSet::new();

        for group in self.find_digest_groups(pkg, check_type) {
            self.check_digest_group(
                pkg,
                check_type,
                &group,
                &mut verified_paths,
                &mut mismatches,
                out,
            );
        }

        let mut violations: HashSet<String> = HashSet::new();
        for path in restricted_paths {
            if !verified_paths.contains(path) {
                violations.insert(path.clone());
            }
        }
        // "Unrelated files": listed as additional files to verify in a
        // digest group without being in a restricted path themselves.
        for path in mismatches.keys() {
            if !verified_paths.contains(path) {
                violations.insert(path.clone());
            }
        }

        let mut violations: Vec<String> = violations.into_iter().collect();
        violations.sort();

        for violation in &violations {
            // A violation with no recorded digest at all (the file failed to
            // resolve, or a `skip` entry): the reference's
            // `mismatches.get(violation, [])` is empty here, so there is
            // nothing to report. This looks like a missing error branch but
            // pins the reference behaviour — do not "fix" it.
            let Some(mismatch_list) = mismatches.get(violation) else {
                continue;
            };
            if mismatch_list.is_empty() {
                // Mixed digest-coupled and nodigest files in one group: the
                // nodigest files fail with the group but there is no point
                // in printing a file-digest-mismatch for them.
                continue;
            }
            let mut hashes_seen: HashSet<String> = HashSet::new();
            for info in mismatch_list {
                // Several groups may list the same path; avoid printing
                // duplicate errors for the same observed hash.
                if !hashes_seen.insert(info.actual.clone()) {
                    continue;
                }
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    &format!("{check_type}-file-digest-mismatch"),
                    &[
                        violation,
                        &format!(
                            "expected {}:{}, has:{}",
                            info.algorithm, info.expected, info.actual
                        ),
                    ],
                );
            }
        }
    }
}

/// Glob matching with Python `fnmatch` semantics: `*`, `?` and `[...]` character
/// classes (ranges, `[!seq]` negation). Like `fnmatch`, `*` also spans `/`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_inner(&p, &t)
}

fn glob_match_inner(p: &[char], t: &[char]) -> bool {
    if p.is_empty() {
        return t.is_empty();
    }
    if p[0] == '*' {
        for i in 0..=t.len() {
            if glob_match_inner(&p[1..], &t[i..]) {
                return true;
            }
        }
        return false;
    }
    if t.is_empty() {
        return false;
    }
    if p[0] == '[' {
        return match match_bracket(&p[1..], t[0]) {
            // No closing bracket: `[` is literal, like fnmatch.
            None => t[0] == '[' && glob_match_inner(&p[1..], &t[1..]),
            Some((consumed, matched)) => matched && glob_match_inner(&p[1 + consumed..], &t[1..]),
        };
    }
    if p[0] == '?' || p[0] == t[0] {
        return glob_match_inner(&p[1..], &t[1..]);
    }
    false
}

/// Match one char against a bracket expression. `p` starts just after `[`;
/// returns the pattern chars consumed (through the closing `]`) and whether
/// `c` matched, or `None` when there is no closing bracket. Mirrors
/// `fnmatch.translate`: an optional `!` negates, a `]` in first position is
/// literal, `x-y` is a range, and `^` is literal (not negation).
fn match_bracket(p: &[char], c: char) -> Option<(usize, bool)> {
    let mut i = 0;
    let mut negate = false;
    if p.first() == Some(&'!') {
        negate = true;
        i += 1;
    }
    // Find the closing `]`, honouring a literal `]` in first position.
    let mut j = i;
    if p.get(j) == Some(&']') {
        j += 1;
    }
    while p.get(j).is_some_and(|&ch| ch != ']') {
        j += 1;
    }
    if p.get(j) != Some(&']') {
        return None;
    }
    let stuff = &p[i..j];
    let mut matched = false;
    let mut k = 0;
    while k < stuff.len() {
        // A `-` between two chars forms a range; leading/trailing `-` is literal.
        if k + 2 < stuff.len() && stuff[k + 1] == '-' {
            if stuff[k] <= c && c <= stuff[k + 2] {
                matched = true;
                break;
            }
            k += 3;
        } else {
            if stuff[k] == c {
                matched = true;
                break;
            }
            k += 1;
        }
    }
    Some((j + 1, matched != negate))
}

impl Check for FileDigestCheck {
    fn name(&self) -> &'static str {
        "FileDigestCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        // Find all files in this package that are placed in restricted
        // locations, honouring the ghost/symlink exception lists and the
        // per-type content check.
        // Insertion order, like the reference's dict: findings for a
        // package are reported check type by check type in first-seen order.
        let mut restricted: IndexMap<String, Vec<String>> = IndexMap::new();
        for pkgfile in &pkg.files {
            let Some(check) = self.lookup_check_for_file(pkgfile).cloned() else {
                continue;
            };
            let check_type = check.check_type.clone();
            let path = pkgfile.name.clone();

            if pkgfile.is_ghost() {
                if !self.is_ghost_allowed(pkg, &path) {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        &format!("{check_type}-file-ghost"),
                        &[&path],
                    );
                }
            } else if is_symlink(pkgfile.mode) && !check.follow_symlinks {
                if !self.is_symlink_allowed(pkg, &path) {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        &format!("{check_type}-file-symlink"),
                        &[&path],
                    );
                }
            } else if !self.has_restricted_content(&check, pkg, &path) {
                // In a restricted location but the content is not relevant.
                continue;
            } else {
                restricted.entry(check_type).or_default().push(path);
            }
        }

        for (check_type, mut paths) in restricted {
            paths.sort();
            paths.dedup();

            let Some(check) = self
                .checks
                .iter()
                .find(|c| c.check_type == check_type)
                .cloned()
            else {
                continue;
            };
            let whitelisted = self.check_for_unauthorized(pkg, &check, &paths, out);
            self.check_for_valid_digests(pkg, &check, &whitelisted, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;
    use crate::pkg::pkgfile::RPMFILE_GHOST;
    use std::io::Write;

    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        DynDigest::update(&mut hasher, data);
        hex::encode(hasher.finalize().to_vec())
    }

    /// A config with one `FileDigestLocation` type (`pam`) plus the
    /// exception lists, mirroring the opensuse flavour's shape.
    fn test_config(extra: &str) -> Config {
        test_config_with_symlinks(extra, false)
    }

    fn test_config_with_symlinks(extra: &str, follow_symlinks: bool) -> Config {
        let toml_src = format!(
            r#"
[FileDigestLocation.pam]
Locations = ["/etc/pam.d"]
NamePatterns = []
FollowSymlinks = {follow_symlinks}
Recursive = true

[[GhostFilesExceptions]]
package = "testpkg"
paths = ["/etc/pam.d/ghost-allowed"]

[[SymlinkExceptions]]
package = "testpkg"
paths = ["/etc/pam.d/link-allowed"]
{extra}
"#
        );
        let table: toml::Table = toml::from_str(&toml_src).expect("parse test config");
        let mut config = Config {
            configuration: table,
            ..Default::default()
        };
        config.finalize();
        config
    }

    fn fixture_pkg() -> Pkg {
        let rpm = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let header = librpm::PackageHeader::from_file(
            &rpm,
            Some(&librpm::verify::VerifyOptions::skip_verification()),
        )
        .expect("open fixture header");
        let mut pkg = Pkg::installed(header).expect("build installed package");
        pkg.name = "testpkg".to_string();
        pkg
    }

    fn pkgfile(name: &str, path: &str, mode: u32) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: path.to_string(),
            mode,
            user: "root".to_string(),
            group: "root".to_string(),
            ..Default::default()
        }
    }

    fn write_temp(dir: &std::path::Path, name: &str, content: &[u8]) -> String {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create temp file");
        f.write_all(content).expect("write temp file");
        path.to_string_lossy().into_owned()
    }

    fn run_check(pkg: &Pkg, config: &Config, check: &mut FileDigestCheck) -> Vec<(String, String)> {
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        check.check_binary(pkg, config, &mut out);
        out.results().to_vec()
    }

    /// A digest group whitelisting `path` with the digest of `content`.
    fn group_toml(path: &str, content: &[u8]) -> String {
        format!(
            r#"
[[FileDigestGroup]]
type = "pam"
package = "testpkg"
[[FileDigestGroup.digests]]
path = "{path}"
algorithm = "sha256"
digester = "default"
hash = "{}"
"#,
            sha256_hex(content)
        )
    }

    #[test]
    fn unauthorized_file_reported() {
        let dir = std::env::temp_dir().join("rpmcrab-fd-unauth");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let content = b"session required pam_unix.so\n";
        let ondisk = write_temp(&dir, "login", content);

        let config = test_config(&group_toml("/etc/pam.d/other", b"other"));
        let mut pkg = fixture_pkg();
        pkg.files = vec![pkgfile("/etc/pam.d/login", &ondisk, 0o100644)];

        let mut check = FileDigestCheck::new(&config);
        let results = run_check(&pkg, &config, &mut check);
        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&"pam-file-unauthorized"),
            "expected pam-file-unauthorized, got {names:?}"
        );
        let line = results
            .iter()
            .find(|(n, _)| n == "pam-file-unauthorized")
            .map(|(_, l)| l.as_str())
            .unwrap();
        assert!(
            line.starts_with("testpkg.noarch: E: pam-file-unauthorized /etc/pam.d/login"),
            "level/name/detail: {line}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn digest_mismatch_reported_with_dedup() {
        let dir = std::env::temp_dir().join("rpmcrab-fd-mismatch");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let content = b"changed content\n";
        let ondisk = write_temp(&dir, "login", content);

        // Two groups list the same path with different expected hashes: the
        // observed hash is identical, so only one mismatch is reported.
        let extra = format!(
            "{}{}",
            group_toml("/etc/pam.d/login", b"original one"),
            group_toml("/etc/pam.d/login", b"original two"),
        );
        let config = test_config(&extra);
        let mut pkg = fixture_pkg();
        pkg.files = vec![pkgfile("/etc/pam.d/login", &ondisk, 0o100644)];

        let mut check = FileDigestCheck::new(&config);
        let results = run_check(&pkg, &config, &mut check);
        let count = results
            .iter()
            .filter(|(n, _)| *n == "pam-file-digest-mismatch")
            .count();
        assert_eq!(count, 1, "dedup by observed hash failed: {results:?}");
        let line = results
            .iter()
            .find(|(n, _)| *n == "pam-file-digest-mismatch")
            .map(|(_, l)| l.as_str())
            .unwrap();
        assert!(
            line.contains("expected sha256:")
                && line.contains(&format!("has:{}", sha256_hex(content))),
            "mismatch detail: {line}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn whitelisted_file_missing_is_warning() {
        let dir = std::env::temp_dir().join("rpmcrab-fd-missing");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let content = b"auth required pam_unix.so\n";
        let ondisk = write_temp(&dir, "login", content);

        // Group lists two files; only one is in the package. Both digests
        // verify, so the absent one is reported as a warning.
        let extra = format!(
            r#"
[[FileDigestGroup]]
type = "pam"
package = "testpkg"
[[FileDigestGroup.digests]]
path = "/etc/pam.d/login"
algorithm = "sha256"
digester = "default"
hash = "{}"
[[FileDigestGroup.digests]]
path = "/etc/pam.d/gone"
algorithm = "sha256"
digester = "default"
hash = "deadbeef"
"#,
            sha256_hex(content)
        );
        let config = test_config(&extra);
        let mut pkg = fixture_pkg();
        pkg.files = vec![pkgfile("/etc/pam.d/login", &ondisk, 0o100644)];

        let mut check = FileDigestCheck::new(&config);
        let results = run_check(&pkg, &config, &mut check);
        let missing: Vec<&(String, String)> = results
            .iter()
            .filter(|(n, _)| *n == "pam-whitelisted-file-missing")
            .collect();
        assert_eq!(
            missing.len(),
            1,
            "expected one missing finding: {results:?}"
        );
        assert!(
            missing[0]
                .1
                .starts_with("testpkg.noarch: W: pam-whitelisted-file-missing /etc/pam.d/gone"),
            "warning level/detail: {}",
            missing[0].1
        );
        // The present file verified, so no mismatch for it.
        assert!(
            !results
                .iter()
                .any(|(n, _)| *n == "pam-file-digest-mismatch"),
            "unexpected mismatch: {results:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_suppressed_when_group_mismatches() {
        let dir = std::env::temp_dir().join("rpmcrab-fd-missing2");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let ondisk = write_temp(&dir, "login", b"tampered\n");

        // The present file mismatches, so the group is invalid and the
        // absent file must NOT be reported as whitelisted-file-missing.
        let extra = format!(
            r#"
[[FileDigestGroup]]
type = "pam"
package = "testpkg"
[[FileDigestGroup.digests]]
path = "/etc/pam.d/login"
algorithm = "sha256"
digester = "default"
hash = "{}"
[[FileDigestGroup.digests]]
path = "/etc/pam.d/gone"
algorithm = "sha256"
digester = "default"
hash = "deadbeef"
"#,
            sha256_hex(b"original\n")
        );
        let config = test_config(&extra);
        let mut pkg = fixture_pkg();
        pkg.files = vec![pkgfile("/etc/pam.d/login", &ondisk, 0o100644)];

        let mut check = FileDigestCheck::new(&config);
        let results = run_check(&pkg, &config, &mut check);
        assert!(
            !results
                .iter()
                .any(|(n, _)| *n == "pam-whitelisted-file-missing"),
            "missing must be suppressed on group mismatch: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|(n, _)| *n == "pam-file-digest-mismatch"),
            "expected mismatch: {results:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ghost_and_symlink_exceptions_honoured() {
        let dir = std::env::temp_dir().join("rpmcrab-fd-exc");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");

        let config = test_config("");
        let mut pkg = fixture_pkg();
        let mut ghost_allowed = pkgfile("/etc/pam.d/ghost-allowed", "/nonexistent", 0o100644);
        ghost_allowed.flags = RPMFILE_GHOST;
        let mut ghost_denied = pkgfile("/etc/pam.d/ghost-denied", "/nonexistent", 0o100644);
        ghost_denied.flags = RPMFILE_GHOST;
        // Symlinks: mode 0o120777.
        let link_allowed = pkgfile("/etc/pam.d/link-allowed", "/nonexistent", 0o120777);
        let link_denied = pkgfile("/etc/pam.d/link-denied", "/nonexistent", 0o120777);
        pkg.files = vec![ghost_allowed, ghost_denied, link_allowed, link_denied];

        let mut check = FileDigestCheck::new(&config);
        let results = run_check(&pkg, &config, &mut check);
        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names.iter().filter(|&&n| n == "pam-file-ghost").count(),
            1,
            "only the non-excepted ghost: {results:?}"
        );
        assert_eq!(
            names.iter().filter(|&&n| n == "pam-file-symlink").count(),
            1,
            "only the non-excepted symlink: {results:?}"
        );
        let ghost_line = results
            .iter()
            .find(|(n, _)| *n == "pam-file-ghost")
            .map(|(_, l)| l.as_str())
            .unwrap();
        assert!(
            ghost_line.contains("/etc/pam.d/ghost-denied"),
            "ghost detail: {ghost_line}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn content_check_varlink() {
        let dir = std::env::temp_dir().join("rpmcrab-fd-content");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let varlink = write_temp(
            &dir,
            "a.socket",
            b"[Socket]\nListenStream=/run/a.sock\nFileDescriptorName=varlink\n",
        );
        let plain = write_temp(&dir, "b.socket", b"[Socket]\nListenStream=/run/b.sock\n");

        let extra = r#"
[FileDigestLocation.sock]
Locations = ["/usr/lib/systemd/system"]
NamePatterns = ["*.socket"]
FollowSymlinks = false
Recursive = true
ContentCheck = "VarlinkServiceCheck"
"#;
        let config = test_config(extra);
        let mut pkg = fixture_pkg();
        pkg.files = vec![
            pkgfile("/usr/lib/systemd/system/a.socket", &varlink, 0o100644),
            pkgfile("/usr/lib/systemd/system/b.socket", &plain, 0o100644),
        ];

        let mut check = FileDigestCheck::new(&config);
        let results = run_check(&pkg, &config, &mut check);
        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        // The varlink socket is restricted and unauthorized; the plain one
        // has no restricted content and is skipped entirely.
        assert!(
            names.contains(&"sock-file-unauthorized"),
            "varlink socket must be unauthorized: {results:?}"
        );
        assert_eq!(
            names.iter().filter(|n| n.contains("unauthorized")).count(),
            1,
            "plain socket must be skipped by ContentCheck: {results:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_digest_location_panics() {
        let mut config = Config::default();
        config.finalize();
        let result = std::panic::catch_unwind(|| FileDigestCheck::new(&config));
        assert!(
            result.is_err(),
            "absent FileDigestLocation must fail loudly"
        );
    }

    #[test]
    fn trie_restricted() {
        let mut trie = TrieNode::default();
        trie.insert("/etc/dbus-1");
        assert!(trie.is_restricted("/etc/dbus-1/system.d/foo.conf"));
        assert!(!trie.is_restricted("/etc/other/foo"));
        assert!(!trie.is_restricted("/etc/dbus-1"));
    }

    #[test]
    fn glob_star() {
        assert!(glob_match("*.so", "libfoo.so"));
        assert!(!glob_match("*.so", "libfoo.so.1"));
        assert!(glob_match("foo*", "foobar"));
    }

    #[test]
    fn glob_question() {
        assert!(glob_match("foo?", "foox"));
        assert!(!glob_match("foo?", "foo"));
    }

    #[test]
    fn shebang_normalized() {
        assert_eq!(
            normalize_shebang("#!/usr/bin/python3.11"),
            "#!/usr/bin/python3"
        );
        assert_eq!(normalize_shebang("#!/bin/sh"), "#!/bin/sh");
    }

    #[test]
    fn socket_digest_uses_file_order() {
        // B1: the socket section used to be a `HashMap` iterated straight
        // into the hasher, so the digest changed with every process run.
        // `IndexMap` preserves file order like the reference's dict: the
        // digest must equal the file-order hash exactly, for either key
        // order. (Cross-process determinism is verified by running this
        // test in a loop; a `HashMap` fails the exact-value assertions.)
        let dir = std::env::temp_dir().join("rpmcrab-fd-socket-order");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let unit_a = write_temp(
            &dir,
            "a.socket",
            b"[Socket]\nListenStream=/run/a.sock\nSocketUser=root\n",
        );
        let unit_b = write_temp(
            &dir,
            "b.socket",
            b"[Socket]\nSocketUser=root\nListenStream=/run/a.sock\n",
        );
        let digester = SocketUnitDigester;
        let digest_a = digester.digest(&unit_a, "sha256").expect("digest a");
        let digest_b = digester.digest(&unit_b, "sha256").expect("digest b");
        println!("socket digests: a={digest_a} b={digest_b}");
        assert_eq!(
            digest_a,
            sha256_hex(b"ListenStream=/run/a.sock\nSocketUser=root\n")
        );
        assert_eq!(
            digest_b,
            sha256_hex(b"SocketUser=root\nListenStream=/run/a.sock\n")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unrelated_sibling_mismatch_still_reported() {
        // B5: a digest group whose restricted path verifies cleanly must
        // still report a bad digest for a sibling file outside any
        // restricted location (the `unrelated_mismatches` merge). Note the
        // reference also reports the valid login here: once the group is
        // invalid, every group path with a recorded digest becomes a
        // violation, even one whose digest matched.
        let dir = std::env::temp_dir().join("rpmcrab-fd-unrelated");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let login_content = b"auth required pam_unix.so\n";
        let login_disk = write_temp(&dir, "login", login_content);
        let sibling_disk = write_temp(&dir, "sibling", b"sibling data\n");

        let extra = format!(
            r#"
[[FileDigestGroup]]
type = "pam"
package = "testpkg"
[[FileDigestGroup.digests]]
path = "/etc/pam.d/login"
algorithm = "sha256"
digester = "default"
hash = "{}"
[[FileDigestGroup.digests]]
path = "/etc/unrelated/sibling"
algorithm = "sha256"
digester = "default"
hash = "deadbeef"
"#,
            sha256_hex(login_content)
        );
        let config = test_config(&extra);
        let mut pkg = fixture_pkg();
        pkg.files = vec![
            pkgfile("/etc/pam.d/login", &login_disk, 0o100644),
            pkgfile("/etc/unrelated/sibling", &sibling_disk, 0o100644),
        ];

        let mut check = FileDigestCheck::new(&config);
        let results = run_check(&pkg, &config, &mut check);
        let mismatches: Vec<&(String, String)> = results
            .iter()
            .filter(|(n, _)| *n == "pam-file-digest-mismatch")
            .collect();
        // Without the `unrelated_mismatches` merge the sibling's digest is
        // silently dropped and only the login is reported.
        assert!(
            mismatches
                .iter()
                .any(|(_, l)| l.contains("/etc/unrelated/sibling")),
            "sibling mismatch must be reported: {results:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unresolvable_symlink_yields_no_parse_error() {
        // B5/H5: a whitelisted path that is a symlink unresolvable within
        // the package marks the group mismatched with NO finding — the
        // reference's `_resolve_links` returns None and `_check_digest`
        // returns (False, None). (The old code returned the unresolved
        // entry and reported `pam-file-parse-error: No such file or
        // directory`.)
        let extra = group_toml("/etc/pam.d/login", b"whatever");
        let config = test_config_with_symlinks(&extra, true);
        let mut pkg = fixture_pkg();
        let mut link = pkgfile("/etc/pam.d/login", "/nonexistent-target", 0o120777);
        link.linkto = "/etc/pam.d/login-real".to_string();
        pkg.files = vec![link];

        let mut check = FileDigestCheck::new(&config);
        let results = run_check(&pkg, &config, &mut check);
        assert!(
            !results.iter().any(|(n, _)| n == "pam-file-parse-error"),
            "unresolvable link must not raise parse-error: {results:?}"
        );
        assert!(results.is_empty(), "group mismatched silently: {results:?}");
    }

    #[test]
    fn check_type_order_follows_config_order() {
        // H2: without toml `preserve_order`, tables iterate sorted while the
        // reference uses file order; `lookup_check_for_file` is
        // first-match-wins, so the order is observable.
        let extra = r#"
[FileDigestLocation.zebra]
Locations = ["/z"]
[FileDigestLocation.alpha]
Locations = ["/a"]
[FileDigestLocation.mid]
Locations = ["/m"]
"#;
        let config = test_config(extra);
        let check = FileDigestCheck::new(&config);
        let order: Vec<&str> = check.checks.iter().map(|c| c.check_type.as_str()).collect();
        assert_eq!(order, ["pam", "zebra", "alpha", "mid"]);
    }

    #[test]
    fn glob_brackets_match_fnmatch() {
        // G2: `[seq]` / `[!seq]` classes with Python fnmatch semantics.
        // Each case was verified against `fnmatch.fnmatch`.
        let cases = [
            ("foo[abc]", "fooa", true),
            ("foo[abc]", "food", false),
            ("foo[!abc]", "food", true),
            ("foo[!abc]", "fooa", false),
            // `^` is literal in fnmatch, not negation.
            ("foo[^abc]", "foo^", true),
            ("foo[^abc]", "food", false),
            ("foo[a-c]", "foob", true),
            ("foo[a-c]", "food", false),
            ("foo[a-]", "foo-", true),
            ("foo[-a]", "foo-", true),
            ("foo[]]", "foo]", true),
            ("foo[!]]", "foox", true),
            ("foo[!]]", "foo]", false),
            // `[!]` has no closing bracket: `[` is literal.
            ("foo[!]", "foo[!]", true),
            ("foo[", "foo[", true),
            ("foo[]", "foo[]", true),
            ("*.[ch]", "foo.c", true),
            ("*.[ch]", "foo.o", false),
            ("lib*.so.[0-9]", "libfoo.so.1", true),
            ("lib*.so.[0-9]", "libfoo.so.1x", false),
            // `*` spans `/`, like fnmatch.
            ("*.socket", "a/b.socket", true),
        ];
        for (pattern, text, expected) in cases {
            assert_eq!(
                glob_match(pattern, text),
                expected,
                "glob_match({pattern:?}, {text:?})"
            );
        }
    }
}
