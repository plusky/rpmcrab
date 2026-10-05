//! `FileDigestCheck` — whitelist file digests in restricted locations.
//!
//! Ported from `rpmlint/checks/FileDigestCheck.py` (639 lines) plus the
//! digester and content-check helpers in `rpmlint/filedigestcheck.py`.
//! Findings: `{type}-file-unauthorized`, `{type}-file-digest-mismatch`,
//! `{type}-file-ghost`, `{type}-file-symlink`, `{type}-file-parse-error`,
//! `{type}-whitelisted-file-missing`.
//!
//! Supports four digesters: `default` (raw bytes), `shell` (strip comments/
//! whitespace), `xml` (C14N 1.0 canonicalization, see `file_digest_xml`) and
//! `systemd-socket` (socket unit keys).

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use indexmap::IndexMap;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

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
                // The reference yields `line.rstrip() + '\n'` from one place
                // after the substitution, so this branch is rstripped too.
                let normalized = normalize_shebang(&line);
                hasher.update(normalized.trim_end().as_bytes());
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

/// XML: digest the C14N 1.0 canonical form (comments, XML declaration
/// and insignificant whitespace removed), mirroring the reference
/// `XmlDigester` (`ET.canonicalize(strip_text=True)`).
struct XmlDigester;

impl Digester for XmlDigester {
    fn digest(&self, path: &str, algorithm: &str) -> Result<String, String> {
        let canonical = super::file_digest_xml::canonicalize_file(path)?;
        let mut hasher = new_hasher(algorithm)?;
        hasher.update(&canonical);
        Ok(hex::encode(hasher.finalize()))
    }
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
///
/// MD5, SHA-1 and the SHA-2 family are implemented; anything else fails
/// the run at configuration load, like the reference's `hashlib.new` raising
/// on an unknown name. See the parity ledger.
fn new_hasher(algorithm: &str) -> Result<Box<dyn DynDigest>, String> {
    match algorithm {
        "md5" => Ok(Box::new(Md5::new())),
        "sha1" => Ok(Box::new(Sha1::new())),
        "sha224" => Ok(Box::new(Sha224::new())),
        "sha256" => Ok(Box::new(Sha256::new())),
        "sha384" => Ok(Box::new(Sha384::new())),
        "sha512" => Ok(Box::new(Sha512::new())),
        _ => Err(format!("unsupported digest algorithm: {algorithm}")),
    }
}

/// Object-safe wrapper for digest algorithms.
trait DynDigest {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> Vec<u8>;
}

macro_rules! impl_dyn_digest {
    ($t:ty) => {
        impl DynDigest for $t {
            fn update(&mut self, data: &[u8]) {
                Digest::update(self, data);
            }
            fn finalize(self: Box<Self>) -> Vec<u8> {
                Digest::finalize(*self).to_vec()
            }
        }
    };
}

impl_dyn_digest!(Md5);
impl_dyn_digest!(Sha1);
impl_dyn_digest!(Sha224);
impl_dyn_digest!(Sha256);
impl_dyn_digest!(Sha384);
impl_dyn_digest!(Sha512);

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

    /// True when inserting `path` would descend through an existing
    /// terminal, i.e. an already-restricted location is a prefix of `path`.
    /// Mirrors the reference's `Conflicting paths in trie` raise.
    fn conflicts(&self, path: &str) -> bool {
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
                // The reference rejects relative and overlapping locations
                // out of `__init__`; a config typo must kill the run, not
                // silently under-report.
                if !loc.starts_with('/') {
                    panic!("FileDigestCheck: absolute path expected: {loc}");
                }
                if trie.conflicts(loc) {
                    panic!("FileDigestCheck: conflicting paths in trie: {loc}");
                }
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

        let known_types: Vec<String> = checks.iter().map(|c| c.check_type.clone()).collect();
        let digest_groups = Self::parse_digest_groups(config, &known_types);
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
            // The reference sanity-checks these keys too; a malformed entry
            // kills the run instead of silently matching nothing.
            let packages = Self::checked_packages(table, key);
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

    /// Package-key sanity, mirroring the reference's
    /// `_sanity_check_package_keys`: exactly one of `package`/`packages`,
    /// with matching value types, or the run dies.
    fn checked_packages(table: &toml::Table, context: &str) -> Vec<String> {
        match (table.get("package"), table.get("packages")) {
            (None, None) => panic!(
                "FileDigestCheck: missing \"package\" or \"packages\" key in {context}"
            ),
            (Some(_), Some(_)) => panic!(
                "FileDigestCheck: encountered both \"package\" and \"packages\" keys in {context}"
            ),
            (Some(p), None) => vec![
                p.as_str()
                    .unwrap_or_else(|| {
                        panic!(
                            "FileDigestCheck: \"package\" key contains non-string value in {context}"
                        )
                    })
                    .to_string(),
            ],
            (None, Some(ps)) => ps
                .as_array()
                .unwrap_or_else(|| {
                    panic!(
                        "FileDigestCheck: \"packages\" key contains non-list value in {context}"
                    )
                })
                .iter()
                .map(|p| {
                    p.as_str()
                        .unwrap_or_else(|| {
                            panic!(
                                "FileDigestCheck: \"packages\" key contains non-string element in {context}"
                            )
                        })
                        .to_string()
                })
                .collect(),
        }
    }

    /// Normalize then sanity-check the digest groups, mirroring the
    /// reference's `_normalize_digest_group` + `_sanity_check_digest_group`:
    /// malformed configuration kills the run out of the constructor.
    fn parse_digest_groups(config: &Config, known_types: &[String]) -> Vec<DigestGroup> {
        let mut groups = Vec::new();
        let Some(arr) = config
            .configuration
            .get("FileDigestGroup")
            .and_then(|v| v.as_array())
        else {
            return groups;
        };
        for v in arr {
            let Some(table) = v.as_table() else {
                panic!("FileDigestCheck: FileDigestGroup entry must be a table");
            };
            // The reference reads `digest_group['type']`, raising KeyError
            // when the key is absent.
            let check_type = table
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| {
                    panic!("FileDigestCheck: missing \"type\" key in FileDigestGroup entry")
                })
                .to_string();
            if !known_types.contains(&check_type) {
                panic!(
                    "FileDigestCheck: FileDigestGroup type \"{check_type}\" is not supported, \
                     known values: {known_types:?}"
                );
            }
            let packages = Self::checked_packages(table, "FileDigestGroup");
            let mut digests = Vec::new();
            if let Some(arr) = table.get("digests").and_then(|v| v.as_array()) {
                for d in arr {
                    let Some(dt) = d.as_table() else {
                        panic!("FileDigestCheck: FileDigestGroup digests entry must be a table");
                    };
                    // The reference implies sha256 for a missing algorithm,
                    // then validates it via `hashlib.new`.
                    let algorithm = dt
                        .get("algorithm")
                        .and_then(|v| v.as_str())
                        .unwrap_or("sha256")
                        .to_string();
                    if algorithm != "skip" && new_hasher(&algorithm).is_err() {
                        panic!("FileDigestCheck: unsupported digest algorithm \"{algorithm}\"");
                    }
                    let path = dt
                        .get("path")
                        .and_then(|v| v.as_str())
                        .unwrap_or_else(|| {
                            panic!("FileDigestCheck: missing \"path\" key in FileDigestGroup entry")
                        })
                        .to_string();
                    let digester = dt
                        .get("digester")
                        .and_then(|v| v.as_str())
                        .unwrap_or("default");

                    if !matches!(digester, "default" | "shell" | "xml" | "systemd-socket") {
                        panic!("FileDigestCheck: invalid digester \"{digester}\" for path {path}");
                    }
                    digests.push(DigestInfo {
                        path,
                        algorithm,
                        hash: dt
                            .get("hash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        digester: digester.to_string(),
                    });
                }
            }
            // Expand `nodigests` into skip entries, appended after the
            // explicit digests (FileDigestCheck.py:132).
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
            groups.push(DigestGroup {
                check_type,
                packages,
                digests,
            });
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
        config.finalize().unwrap();
        config
    }

    fn fixture_pkg() -> Pkg {
        let rpm = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::installed_from_file(&rpm);
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
        config.finalize().unwrap();
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

    /// XML digests match the reference's `ET.canonicalize(strip_text=True)`
    /// byte-for-byte across the C14N edge cases (plusky/rpmcrab#75).
    #[test]
    fn xml_digester_matches_reference_parity() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "basic.xml",
                r#"<?xml version="1.0"?>
<root>
  <child name="b" id="a">text</child>
</root>
"#,
                "4275d6a6b56026cffb21c77c6cd82caf46fe3a5080a4177bac54fb791ef0787f",
            ),
            (
                "attrs.xml",
                r#"<root z="1" a="2" m="3"><e b="x" a="y"/></root>"#,
                "7e560bc59e6ce8240eff4e218c7c1a3b083c9c0185e120f433732121fcc5350a",
            ),
            (
                "ns.xml",
                r#"<root xmlns="http://default" xmlns:p="http://p"><p:child p:attr="1" plain="2">t</p:child></root>"#,
                "7000ae21521841243bf4bbe7546073c698a4aba4736c6d0f237af8983ce47dec",
            ),
            (
                "ns-nested.xml",
                r#"<a xmlns:n="http://n"><b><n:c n:x="1" y="2"/></b></a>"#,
                "8d5733dc977d17bc11a0c7e2a048e7901cca7f45289a492af64dd004ea679899",
            ),
            (
                "comments.xml",
                r#"<root><!-- a comment --><child>text</child><!-- another --></root>"#,
                "652555980f2fadab20e2f4aa955cd1debac5b392fce42968b387c40f4514be0f",
            ),
            (
                "pi.xml",
                r#"<?xml version="1.0"?><?php echo "hi"; ?><root><?target data?><c/></root>"#,
                "7de74885c43f6491efd9eb7640f2066e9e8b91cbe50f64180eef929ff46f16c5",
            ),
            (
                "cdata.xml",
                r#"<root><c><![CDATA[<raw>&stuff]]></c></root>"#,
                "3b7e314a9e3af8a41a1b320d79815cd51c77ee07f3999ba8a6c754a4a17f13ee",
            ),
            (
                "ws.xml",
                r#"<root>   <a>  x  </a>   <b>y</b>   </root>"#,
                "b8e7015e474048a694ce15755c0cd269eb0ce445b41cc9bd2941a7957a83d029",
            ),
            (
                "mixed.xml",
                r#"<root>before<e/>after</root>"#,
                "a41436cf65ce830b9d4a109a22403b065b72a06deff80cf63346525119538e02",
            ),
            (
                "entities.xml",
                r#"<root><e>&lt;&gt;&amp;&quot;&apos;</e></root>"#,
                "12004dc33491825f575039629a37e0b893e5717177974aabe7a0b111d655b375",
            ),
            (
                "empty.xml",
                r#"<root><a/><b></b></root>"#,
                "eed4b1812e316b74d5c8b1a571e8d5f92c9d4d92678f2988df43157bb005ca38",
            ),
            (
                "doctype.xml",
                r#"<!DOCTYPE root [<!ENTITY foo "bar">]><root>&foo;<e a="1"/></root>"#,
                "8a009794a7ea24dbc0bf35daf3214b930cd0ce3ada15f9f8d7f7db71fc0e20c1",
            ),
            (
                "attr-ns-sort.xml",
                r#"<r xmlns:a="http://a" xmlns:b="http://b" xmlns="http://d"><e b:y="1" a:x="2" z="3" a:w="4"/></r>"#,
                "ac549833aeff54c95e8f35fb04a868107de8f1491be39972be529b47094b568f",
            ),
            (
                "urisort.xml",
                r#"<r xmlns:z="http://a" xmlns:a="http://z"><e z:x="1" a:y="2"/></r>"#,
                "d3d0d20dcb638402402d549e737773e1e4d71641fee8811eef68d921cbad18b7",
            ),
            (
                "nested-default-ns.xml",
                r#"<root xmlns="http://d"><a xmlns=""><b xmlns="http://d2">x</b></a></root>"#,
                "d0ba2f0c1e5814f92d099a14dd97da8b88767b4393d630d5dd98267efb1bcc19",
            ),
            (
                "dup-prefix.xml",
                r#"<a xmlns:p="http://p1"><b xmlns:p="http://p2"><p:c/></b></a>"#,
                "f684a8e2dc85f693ee3b4d5f37c1c910ee6bcae9180a19531714842a18e05b01",
            ),
            (
                "cr.xml",
                r#"<root><e>line1
line2
last</e></root>"#,
                "ac1a3d2cef349d7d1489af9f1998334ea4dd560251b28c6a1e408a6b029b8f95",
            ),
            (
                "attr-ws.xml",
                r#"<root><e a="x	y&#10;z"/></root>"#,
                "ef663126548c61fc033a0f431ad1d84a69c42273a64a89719e3d0fd6357e54ec",
            ),
            (
                "v_attr-tab-charref.xml",
                r#"<r><e a="&#9;"/></r>"#,
                "5b6a9bb5f1e646cdffd34e223f03d4fa8362bf3b36c7358189545f3b87576913",
            ),
            (
                "v_attr-cr-charref.xml",
                r#"<r><e a="&#13;"/></r>"#,
                "7dc3856e285707dcd8a2b331b1dc81bd27fd429ccc6d6dac951bc0cbb0f1fd7d",
            ),
            (
                "v_nested-entity.xml",
                r#"<!DOCTYPE r [<!ENTITY a "x"><!ENTITY b "&a;y">]><r>&b;</r>"#,
                "23b515e2cdd31abb313839cfa7be009d54e61f6d875c511367bdfa02414b051d",
            ),
            (
                "unicode.xml",
                r#"<root><e>café 中文</e></root>"#,
                "c197bb6f13d4eddd69c3d9fa5bdb51f1ee6c8151fe2f3e26bd544f7055fbd627",
            ),
            (
                "xmllang.xml",
                r#"<root xml:lang="en"><e xml:space="preserve">x</e></root>"#,
                "23b7cae1caadffe701d0abfbdcb0344375adcd8d2e73e0d93c418ffc277ed3f9",
            ),
            (
                "v_sortxml.xml",
                r#"<r xmlns:a="http://a"><e z="1" xml:lang="en" a:b="2"/></r>"#,
                "6fdf445fb786d41647f544ccd4d174dc97be2602e367c887e6fc0a5f7213097f",
            ),
            (
                "toppi.xml",
                r#"<?a 1?>
<?b 2?>
<root/>"#,
                "e2155754846daa07e16f1750ef1489bb3577ad92fc715c37d28c5ddf29e0bb20",
            ),
            (
                "t_pi-ws.xml",
                r#"<?a?>

<root/>"#,
                "af6a411435bb3e9fdf1fe5e772bc00ec4cb21e72cb675126601edb0291ffc8d9",
            ),
            (
                "y_pi-split.xml",
                r#"<a>  x  <?p d?>  y  </a>"#,
                "6491ff2a30b1d46fcc29220d4f6048221f2e3db213cd8b4dd5f7caa417c59097",
            ),
            (
                "y_comment-split.xml",
                r#"<a>  x  <!--c-->  y  </a>"#,
                "79d87be9bd527f8e1ab2af7443e3768535409246b7d9979386adaeca1697af54",
            ),
            (
                "y_cdata-split.xml",
                r#"<a>  x  <![CDATA[ y ]]>  z  </a>"#,
                "70890ba60ce3deebce3171ec0ce964e1fc68d4d763e40b89480f0f25065b440d",
            ),
            (
                "s_t1.xml",
                r#"<a>x <b/> y</a>"#,
                "4c4c64dbe903ad3273cf5e4a157fdbc261f28867eb46bb45073afb1b2fccccf0",
            ),
            (
                "v_nbsp.xml",
                r#"<r><e> x </e></r>"#,
                "ad926dabb729569ba83458b620101122db2a154ebc4a8f1a217e81d95246a9bf",
            ),
            (
                "x_v11.xml",
                r#"<?xml version="1.1"?><r><e>x</e></r>"#,
                "ad926dabb729569ba83458b620101122db2a154ebc4a8f1a217e81d95246a9bf",
            ),
        ];
        for (name, xml, expected) in cases {
            let dir = std::env::temp_dir().join("rpmcrab-fd-xmlparity");
            std::fs::create_dir_all(&dir).expect("tmpdir");
            let path = dir.join(name);
            std::fs::write(&path, xml).expect("write fixture");
            let canonical =
                crate::checks::file_digest_xml::canonicalize_file(path.to_str().unwrap())
                    .unwrap_or_else(|e| panic!("{name}: canonicalize failed: {e}"));
            let digest = sha256_hex(&canonical);
            assert_eq!(digest, *expected, "{name}: digest mismatch");
        }
    }
    /// The `xml` digester verifies through `check_digest`: a matching hash
    /// passes silently, a wrong one reports `{type}-file-digest-mismatch`.
    #[test]
    fn xml_digester_verifies_and_mismatches() {
        let dir = std::env::temp_dir().join("rpmcrab-fd-xmlverify");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let content = b"<?xml version=\"1.0\"?>\n<busconfig>\n  <!-- comment -->\n  <policy/>\n</busconfig>\n";
        let ondisk = write_temp(&dir, "test.conf", content);
        // sha256 of the C14N form `<busconfig><policy></policy></busconfig>`.
        let good = sha256_hex(b"<busconfig><policy></policy></busconfig>");

        let extra = format!(
            r#"
[[FileDigestGroup]]
type = "pam"
package = "testpkg"
[[FileDigestGroup.digests]]
path = "/etc/pam.d/test.conf"
algorithm = "sha256"
digester = "xml"
hash = "{good}"
"#
        );
        let config = test_config(&extra);
        let mut pkg = fixture_pkg();
        pkg.files = vec![pkgfile("/etc/pam.d/test.conf", &ondisk, 0o100644)];

        let mut check = FileDigestCheck::new(&config);
        let results = run_check(&pkg, &config, &mut check);
        assert!(
            !results.iter().any(|(n, _)| n == "pam-file-digest-mismatch"),
            "matching xml digest must not mismatch, got {results:?}"
        );

        let extra_bad = extra.replace(&good, "deadbeef");
        let config_bad = test_config(&extra_bad);
        let mut check_bad = FileDigestCheck::new(&config_bad);
        let results_bad = run_check(&pkg, &config_bad, &mut check_bad);
        assert!(
            results_bad
                .iter()
                .any(|(n, _)| n == "pam-file-digest-mismatch"),
            "wrong xml digest must mismatch, got {results_bad:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Malformed XML surfaces as `{type}-file-parse-error`, like the reference.
    #[test]
    fn xml_digester_parse_error() {
        let dir = std::env::temp_dir().join("rpmcrab-fd-xmlparseerr");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let ondisk = write_temp(&dir, "bad.conf", b"<busconfig><unclosed>");

        let extra = r#"
[[FileDigestGroup]]
type = "pam"
package = "testpkg"
[[FileDigestGroup.digests]]
path = "/etc/pam.d/bad.conf"
algorithm = "sha256"
digester = "xml"
hash = "deadbeef"
"#;
        let config = test_config(extra);
        let mut pkg = fixture_pkg();
        pkg.files = vec![pkgfile("/etc/pam.d/bad.conf", &ondisk, 0o100644)];

        let mut check = FileDigestCheck::new(&config);
        let results = run_check(&pkg, &config, &mut check);
        assert!(
            results.iter().any(|(n, _)| n == "pam-file-parse-error"),
            "malformed xml must be a parse error, got {results:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// sha512 from the SHA-2 family matches the reference runtime:
    /// `hashlib.sha512(b"abc").hexdigest()`.
    #[test]
    fn sha512_digester_matches_reference() {
        let mut hasher = new_hasher("sha512").expect("sha512 supported");
        hasher.update(b"abc");
        assert_eq!(
            hex::encode(hasher.finalize()),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    fn config_with_locations(locations: &str) -> Config {
        let toml_src = format!("[FileDigestLocation.pam]\nLocations = [{locations}]\n");
        let table: toml::Table = toml::from_str(&toml_src).expect("parse test config");
        let mut config = Config {
            configuration: table,
            ..Default::default()
        };
        config.finalize().unwrap();
        config
    }

    /// Malformed configuration kills the run out of the constructor, like
    /// the reference's `__init__` raises.
    #[test]
    #[should_panic(expected = "not supported")]
    fn unknown_digest_group_type_panics() {
        let config = test_config("[[FileDigestGroup]]\ntype = \"nope\"\npackage = \"testpkg\"\n");
        let _ = FileDigestCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "missing \"type\"")]
    fn digest_group_without_type_panics() {
        let config = test_config("[[FileDigestGroup]]\npackage = \"testpkg\"\n");
        let _ = FileDigestCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "missing \"path\"")]
    fn digest_entry_without_path_panics() {
        let config = test_config(
            "[[FileDigestGroup]]\ntype = \"pam\"\npackage = \"testpkg\"\n[[FileDigestGroup.digests]]\nalgorithm = \"sha256\"\nhash = \"deadbeef\"\n",
        );
        let _ = FileDigestCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "both \"package\" and \"packages\"")]
    fn digest_group_with_both_package_keys_panics() {
        let config = test_config(
            "[[FileDigestGroup]]\ntype = \"pam\"\npackage = \"a\"\npackages = [\"b\"]\n",
        );
        let _ = FileDigestCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "missing \"package\" or \"packages\"")]
    fn digest_group_without_package_keys_panics() {
        let config = test_config("[[FileDigestGroup]]\ntype = \"pam\"\n");
        let _ = FileDigestCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "invalid digester")]
    fn digest_entry_with_unknown_digester_panics() {
        let config = test_config(
            "[[FileDigestGroup]]\ntype = \"pam\"\npackage = \"testpkg\"\n[[FileDigestGroup.digests]]\npath = \"/etc/pam.d/login\"\ndigester = \"bogus\"\nhash = \"deadbeef\"\n",
        );
        let _ = FileDigestCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "unsupported digest algorithm")]
    fn digest_entry_with_unknown_algorithm_panics() {
        // sha3-256 is valid for the reference's `hashlib.new` but unimplemented
        // here; the run must die at load, not misreport at check time.
        let config = test_config(
            "[[FileDigestGroup]]\ntype = \"pam\"\npackage = \"testpkg\"\n[[FileDigestGroup.digests]]\npath = \"/etc/pam.d/login\"\nalgorithm = \"sha3-256\"\nhash = \"deadbeef\"\n",
        );
        let _ = FileDigestCheck::new(&config);
    }

    #[test]
    fn md5_and_sha1_digest_mismatch_reported() {
        // md5/sha1 support pinned through check_binary: the parsed config
        // drives the checker's groups, a wrong expected hash produces a
        // finding, and the detail pins the computed hash against
        // known-answer vectors for "hello".
        let dir = std::env::temp_dir().join("rpmcrab-fd-md5sha1");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let ondisk = write_temp(&dir, "login", b"hello");

        let extra = r#"
[[FileDigestGroup]]
type = "pam"
package = "testpkg"
[[FileDigestGroup.digests]]
path = "/etc/pam.d/login-md5"
algorithm = "md5"
digester = "default"
hash = "00000000000000000000000000000000"
[[FileDigestGroup.digests]]
path = "/etc/pam.d/login-sha1"
algorithm = "sha1"
digester = "default"
hash = "0000000000000000000000000000000000000000"
"#;
        let config = test_config(extra);
        let mut check = FileDigestCheck::new(&config);
        assert_eq!(check.digest_groups.len(), 1);
        let algorithms: Vec<&str> = check.digest_groups[0]
            .digests
            .iter()
            .map(|d| d.algorithm.as_str())
            .collect();
        assert_eq!(algorithms, ["md5", "sha1"]);

        let mut pkg = fixture_pkg();
        pkg.files = vec![
            pkgfile("/etc/pam.d/login-md5", &ondisk, 0o100644),
            pkgfile("/etc/pam.d/login-sha1", &ondisk, 0o100644),
        ];
        let results = run_check(&pkg, &config, &mut check);
        let mismatches: Vec<&(String, String)> = results
            .iter()
            .filter(|(n, _)| n == "pam-file-digest-mismatch")
            .collect();
        assert_eq!(
            mismatches.len(),
            2,
            "expected one mismatch per algorithm: {results:?}"
        );
        let line_for = |path: &str| {
            mismatches
                .iter()
                .find(|(_, l)| l.contains(path))
                .map(|(_, l)| l.as_str())
                .unwrap_or_else(|| panic!("no mismatch for {path}: {results:?}"))
        };
        assert_eq!(
            line_for("/etc/pam.d/login-md5"),
            "testpkg.noarch: E: pam-file-digest-mismatch /etc/pam.d/login-md5 expected md5:00000000000000000000000000000000, has:5d41402abc4b2a76b9719d911017c592"
        );
        assert_eq!(
            line_for("/etc/pam.d/login-sha1"),
            "testpkg.noarch: E: pam-file-digest-mismatch /etc/pam.d/login-sha1 expected sha1:0000000000000000000000000000000000000000, has:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[should_panic(expected = "absolute path expected")]
    fn relative_location_panics() {
        let config = config_with_locations("\"etc/pam.d\"");
        let _ = FileDigestCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "conflicting paths in trie")]
    fn overlapping_locations_panic() {
        let config = config_with_locations("\"/etc\", \"/etc/pam.d\"");
        let _ = FileDigestCheck::new(&config);
    }

    #[test]
    fn nodigests_append_after_explicit_digests() {
        // The reference appends `nodigests` skip entries after the explicit
        // `digests` list (FileDigestCheck.py:132).
        let mut cfg = test_config("");
        let group: toml::Value = toml::from_str(
            r#"
type = "FileDigestLocation"
package = "testpkg"
digests = [{path = "/check/me", algorithm = "sha256", hash = "abc"}]
nodigests = ["/skip/me"]
"#,
        )
        .unwrap();
        cfg.configuration
            .entry("FileDigestGroup")
            .or_insert(toml::Value::Array(Vec::new()))
            .as_array_mut()
            .unwrap()
            .push(group);
        let known = vec!["FileDigestLocation".to_string()];
        let parsed = FileDigestCheck::parse_digest_groups(&cfg, &known);
        assert_eq!(parsed.len(), 1);
        let digests = &parsed[0].digests;
        assert_eq!(digests.len(), 2);
        assert_eq!(digests[0].path, "/check/me");
        assert_eq!(digests[0].algorithm, "sha256");
        assert_eq!(digests[1].path, "/skip/me");
        assert_eq!(digests[1].algorithm, "skip");
    }

    /// A digest group for an explicit package name. The shared `group_toml`
    /// helper pins `package = "testpkg"`; these tests need other names.
    fn group_toml_for_package(package: &str, path: &str, content: &[u8]) -> String {
        format!(
            r#"
[[FileDigestGroup]]
type = "pam"
package = "{package}"
[[FileDigestGroup.digests]]
path = "{path}"
algorithm = "sha256"
digester = "default"
hash = "{}"
"#,
            sha256_hex(content)
        )
    }

    /// The reference's `test_wrong_pkg_name` (test_file_digest.py:179): a
    /// package whose name matches no digest group must not validate. This is
    /// the security core of the check — a package-name scoping regression
    /// would let a foreign package pass whitelisting silently.
    #[test]
    fn wrong_package_name_does_not_validate() {
        let dir = std::env::temp_dir().join("rpmcrab-fd-wrongpkg");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let content = b"session required pam_unix.so\n";
        let ondisk = write_temp(&dir, "login", content);

        let config = test_config(&group_toml_for_package(
            "testpkg",
            "/etc/pam.d/login",
            content,
        ));
        let mut pkg = fixture_pkg();
        pkg.name = "otherpkg".to_string();
        pkg.files = vec![pkgfile("/etc/pam.d/login", &ondisk, 0o100644)];

        let mut check = FileDigestCheck::new(&config);
        let results = run_check(&pkg, &config, &mut check);
        let unauthorized: Vec<&(String, String)> = results
            .iter()
            .filter(|(n, _)| *n == "pam-file-unauthorized")
            .collect();
        assert_eq!(
            unauthorized.len(),
            1,
            "wrong package must not validate: {results:?}"
        );
        assert!(
            unauthorized[0]
                .1
                .starts_with("otherpkg.noarch: E: pam-file-unauthorized /etc/pam.d/login"),
            "level/name/detail: {}",
            unauthorized[0].1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reference's `test_multiple_packages` (test_file_digest.py:278):
    /// a `packages = [...]` group validates each listed package; an unlisted
    /// package is rejected.
    #[test]
    fn multiple_packages_group_validates_listed_only() {
        let dir = std::env::temp_dir().join("rpmcrab-fd-multipkg");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let content = b"some file content\n";
        let ondisk = write_temp(&dir, "afile", content);

        let extra = format!(
            r#"
[[FileDigestGroup]]
type = "pam"
packages = ["testpkg2", "otherpkg"]
[[FileDigestGroup.digests]]
path = "/etc/pam.d/afile"
algorithm = "sha256"
digester = "default"
hash = "{}"
"#,
            sha256_hex(content)
        );
        let config = test_config(&extra);
        for (pkg_name, expect_ok) in [("testpkg2", true), ("otherpkg", true), ("badpkg", false)] {
            let mut pkg = fixture_pkg();
            pkg.name = pkg_name.to_string();
            pkg.files = vec![pkgfile("/etc/pam.d/afile", &ondisk, 0o100644)];
            let mut check = FileDigestCheck::new(&config);
            let results = run_check(&pkg, &config, &mut check);
            if expect_ok {
                assert!(
                    results.is_empty(),
                    "{pkg_name}: listed package must validate quietly, got {results:?}"
                );
            } else {
                assert!(
                    results.iter().any(|(n, _)| *n == "pam-file-unauthorized"),
                    "{pkg_name}: unlisted package must be rejected, got {results:?}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reference's `test_matching_nodigests` / `test_missing_nodigests_entry`
    /// (test_file_digest.py:206, :218): `nodigests` paths stay silent, while an
    /// extra file not present in the whitelist is still flagged.
    #[test]
    fn nodigests_paths_stay_silent_extra_files_flagged() {
        let dir = std::env::temp_dir().join("rpmcrab-fd-nodigests");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let skipped = write_temp(&dir, "skipped", b"whatever\n");
        let evil = write_temp(&dir, "evil", b"evil stuff\n");

        let extra = r#"
[[FileDigestGroup]]
type = "pam"
package = "testpkg"
nodigests = ["/etc/pam.d/skipped"]
"#
        .to_string();
        let config = test_config(&extra);

        // Whitelisted path: silent.
        let mut pkg = fixture_pkg();
        pkg.files = vec![pkgfile("/etc/pam.d/skipped", &skipped, 0o100644)];
        let mut check = FileDigestCheck::new(&config);
        let results = run_check(&pkg, &config, &mut check);
        assert!(
            results.is_empty(),
            "nodigests path must stay silent: {results:?}"
        );

        // Extra file: still flagged.
        let mut pkg = fixture_pkg();
        pkg.files = vec![
            pkgfile("/etc/pam.d/skipped", &skipped, 0o100644),
            pkgfile("/etc/pam.d/evil", &evil, 0o100644),
        ];
        let mut check = FileDigestCheck::new(&config);
        let results = run_check(&pkg, &config, &mut check);
        let unauthorized: Vec<&(String, String)> = results
            .iter()
            .filter(|(n, _)| *n == "pam-file-unauthorized")
            .collect();
        assert_eq!(
            unauthorized.len(),
            1,
            "extra file must be flagged: {results:?}"
        );
        assert!(
            unauthorized[0]
                .1
                .starts_with("testpkg.noarch: E: pam-file-unauthorized /etc/pam.d/evil"),
            "level/name/detail: {}",
            unauthorized[0].1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reference's `test_shell_digest_filter` (test_file_digest.py:293):
    /// the shell digester is exercised through the check. The fixture has
    /// comments, blank lines and a versioned shebang, so its raw sha256
    /// differs from the shell-normalized one — a digester regression (raw
    /// bytes) would false-positive `E: pam-file-digest-mismatch` here.
    #[test]
    fn shell_digester_normalizes_through_check() {
        let dir = std::env::temp_dir().join("rpmcrab-fd-shell");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let content =
            b"#!/usr/bin/python3.11\n# a comment\n\nsession required pam_unix.so\n# another\n";
        let ondisk = write_temp(&dir, "login", content);

        let expected = Digester::digest(&ShellDigester, &ondisk, "sha256").expect("shell digest");
        assert_ne!(
            expected,
            sha256_hex(content),
            "test is vacuous unless normalization changes the hash"
        );

        let extra = format!(
            r#"
[[FileDigestGroup]]
type = "pam"
package = "testpkg"
[[FileDigestGroup.digests]]
path = "/etc/pam.d/login"
algorithm = "sha256"
digester = "shell"
hash = "{expected}"
"#
        );
        let config = test_config(&extra);
        let mut pkg = fixture_pkg();
        pkg.files = vec![pkgfile("/etc/pam.d/login", &ondisk, 0o100644)];

        let mut check = FileDigestCheck::new(&config);
        let results = run_check(&pkg, &config, &mut check);
        assert!(
            results.is_empty(),
            "shell-normalized file must verify quietly: {results:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
