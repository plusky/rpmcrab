//! `SourceCheck` — validate the files in a source package.
//!
//! Ported from `rpmlint/checks/SourceCheck.py`. Findings:
//! `inconsistent-file-extension`, `strange-permission` and
//! `source-not-compressed` (warnings), plus the rpmcrab-new archive
//! content warnings `prebuilt-binary-in-sources`,
//! `source-archive-contains-vcs-metadata` and
//! `source-archive-contains-lfs-pointer`.
//!
//! `prebuilt-binary-in-sources` is rpmcrab-new (upstream rpmlint#4, still
//! open): the reference never unpacks source archives.
//!
//! `rpmlintrc-uses-setbadness` is rpmcrab-new as well: an rpmlintrc file
//! carried in the source package is scanned for `setBadness` lines, the
//! same predicate the rpmlintrc load path records.

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct SourceCheck {
    compress_ext: String,
    valid_src_perms: Vec<u128>,
    ext_magic: Vec<(String, String, Regex)>,
}

impl SourceCheck {
    /// `error_details` for `--explain`, mirroring `source_details_dict`
    /// (`SourceCheck.py:28-33`) installed in `__init__`.
    pub fn register_error_details(config: &Config, out: &mut Filter) {
        let compress_ext = config
            .configuration
            .get("CompressExtension")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("SourceCheck: CompressExtension must be a string"));
        out.set_error_detail(
            "source-not-compressed",
            Self::not_compressed_detail(compress_ext),
        );
        out.set_error_detail(
            "prebuilt-binary-in-sources",
            "A source archive in this package contains prebuilt binary files: \
             compiled code shipped as binaries instead of being built from \
             source during the package build. Such files are opaque blobs \
             that can neither be audited nor rebuilt; delete them in %prep \
             (or replace them with real sources). Do not repack the upstream \
             archive to remove them — that breaks source verification. Like \
             every warning, this one can be filtered out in the configuration."
                .to_string(),
        );
    }

    fn not_compressed_detail(compress_ext: &str) -> String {
        format!(
            "A source archive or file in your package is not compressed using the {compress_ext}\ncompression method (doesn't have the {compress_ext} extension)."
        )
    }

    pub fn new(config: &Config) -> Self {
        // The reference reads `config.configuration['CompressExtension']`
        // and raises `KeyError` when it is absent; defaulting to `""` would
        // render a mangled description, so this panics just as loudly.
        let compress_ext = config
            .configuration
            .get("CompressExtension")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("SourceCheck: CompressExtension must be a string"))
            .to_string();
        // The reference runs `[int(value, 8) for value in
        // config.configuration['ValidSrcPerms']]` and dies on a missing key
        // or a bad entry. Substituting an empty list instead would emit
        // `strange-permission` for every file, so this panics just as loudly.
        let valid_src_perms: Vec<u128> = match config.configuration.get("ValidSrcPerms") {
            Some(toml::Value::Array(entries)) => entries
                .iter()
                .map(|v| match v.as_str().and_then(parse_octal) {
                    Some(perm) => perm,
                    None => panic!("SourceCheck: ValidSrcPerms entry {v} is not valid octal"),
                })
                .collect(),
            _ => panic!("SourceCheck: ValidSrcPerms must be an array of octal strings"),
        };
        // `re.match(pattern, magic, re.IGNORECASE)`: anchored at the start.
        let ext_magic = [
            ("xz", "XZ compressed"),
            ("gz", "gzip compressed"),
            ("tgz", "gzip compressed"),
            ("bz2", "bzip2 compressed"),
            ("zst", "(ZSTD|Zstandard) compressed"),
            ("zstd", "(ZSTD|Zstandard) compressed"),
            ("zip", "Zip archive data"),
        ]
        .into_iter()
        .map(|(ext, pattern)| {
            (
                ext.to_string(),
                pattern.to_string(),
                Regex::new(&format!("(?i)^{pattern}")).expect("static regex"),
            )
        })
        .collect();
        Self {
            compress_ext,
            valid_src_perms,
            ext_magic,
        }
    }

    /// The per-file findings: `inconsistent-file-extension`,
    /// `strange-permission` and `source-not-compressed`, in reference order.
    fn file_findings(
        &self,
        fname: &str,
        mode: u32,
        magic: &str,
    ) -> Vec<(Level, &'static str, Vec<String>)> {
        let mut out = Vec::new();
        if !magic.is_empty() {
            let ext = fname.rsplit('.').next().unwrap_or(fname);
            match self.ext_magic.iter().find(|(e, _, _)| e == ext) {
                Some((_, pattern, re)) if !is_match(re, magic) => {
                    out.push((
                        Level::Warning,
                        "inconsistent-file-extension",
                        vec![format!(
                            "file {} magic {} does not match {}",
                            py_repr(fname),
                            py_repr(magic),
                            py_repr(pattern)
                        )],
                    ));
                }
                _ => {}
            }
        }
        let perm = mode & 0o7777;
        if !self.valid_src_perms.contains(&(perm as u128)) {
            out.push((
                Level::Warning,
                "strange-permission",
                vec![fname.to_string(), format!("{perm:o}")],
            ));
        }
        // The reference's `source_regex = re.compile(r'\.(tar|tgz)$')`: without
        // `re.MULTILINE`, `$` also matches before a trailing newline, so
        // `foo.tar\n` fires there. `fancy_regex` has no such `$`, hence the
        // one-newline strip, which is exactly equivalent for this pattern.
        let stem = fname.strip_suffix('\n').unwrap_or(fname);
        if (stem.ends_with(".tar") || stem.ends_with(".tgz"))
            && !self.compress_ext.is_empty()
            && !fname.ends_with(self.compress_ext.as_str())
        {
            out.push((
                Level::Warning,
                "source-not-compressed",
                vec![self.compress_ext.clone(), fname.to_string()],
            ));
        }
        out
    }

    /// `rpmlintrc-uses-setbadness`: scan every rpmlintrc file in the
    /// source package (a file whose name ends in `rpmlintrc`, the
    /// source-review bot's `*rpmlintrc` glob) for lines matching
    /// `^\s*setBadness`, one warning per occurrence. A file whose name
    /// matches an rpmlintrc already loaded for this run is skipped --
    /// the load path reports its occurrences -- and a name is scanned
    /// only once per package, so the same directive file is never
    /// reported twice under one name.
    fn check_rpmlintrc_setbadness(&self, pkg: &Pkg, config: &Config, out: &mut Filter) {
        let loaded: std::collections::HashSet<String> = config
            .rpmlintrc_display
            .iter()
            .map(|path| path.rsplit('/').next().unwrap_or(path.as_str()).to_string())
            .collect();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for f in &pkg.files {
            let name = f.name.rsplit('/').next().unwrap_or(f.name.as_str());
            if !name.ends_with("rpmlintrc")
                || loaded.contains(name)
                || !seen.insert(name.to_string())
            {
                continue;
            }
            let Ok(bytes) = std::fs::read(&f.path) else {
                continue;
            };
            let text = String::from_utf8_lossy(&bytes);
            for (line_no, line) in crate::config::setbadness_occurrences(&text) {
                let detail = format!("{name} line {line_no}: {line}");
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "rpmlintrc-uses-setbadness",
                    &[&detail],
                );
            }
        }
    }

    /// The archive-content findings, all rpmcrab-new and ledgered as
    /// `kind = "behaviour"`: `prebuilt-binary-in-sources` (issue #150,
    /// upstream rpmlint#4) scans every file of the source package for
    /// prebuilt binaries — directly by magic bytes, and inside source
    /// archives (tar, gzip/xz/zstd/bzip2-compressed tar, zip), recursing
    /// into nested archives; `source-archive-contains-vcs-metadata` and
    /// `source-archive-contains-lfs-pointer` (issue #1022) inspect only
    /// the direct members of each source archive. The VCS finding is
    /// scoped to sources without an upstream URL, so metadata shipped
    /// inside an upstream tarball stays quiet.
    fn check_archive_contents(&self, pkg: &Pkg, out: &mut Filter) {
        let url_sources = source_url_files(pkg);
        for f in &pkg.files {
            let size = std::fs::metadata(&f.path).map(|m| m.len()).unwrap_or(0);
            if size > prebuilt::MAX_ARCHIVE_BYTES as u64 {
                continue;
            }
            let data = match std::fs::read(&f.path) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let mut hits = Vec::new();
            prebuilt::inspect_entry(&f.name, &data, &f.name, 0, &mut hits);
            for (kind, path) in hits {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "prebuilt-binary-in-sources",
                    &[&path, kind.as_str()],
                );
            }
            let members = prebuilt::top_level_members(&data);
            if !url_sources.contains(&f.name) {
                for root in prebuilt::vcs_roots(&members) {
                    let entries = format!("{} entries", root.entries);
                    let bytes = format!("{} bytes", root.bytes);
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "source-archive-contains-vcs-metadata",
                        &[&f.name, &root.root, &entries, &bytes],
                    );
                }
            }
            for member in prebuilt::lfs_pointers(&members) {
                let path = format!("{}: {}", f.name, member);
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "source-archive-contains-lfs-pointer",
                    &[&path],
                );
            }
        }
    }
}

/// The source files whose spec declaration carries an upstream URL,
/// judged from librpm's parsed source list: the expanded full path of
/// a URL source is the URL itself, while a bare filename expands to a
/// path under `_sourcedir`. The header-named spec is tried first, then
/// the remaining payload specs in file order; the first spec that
/// parses decides. An empty set — no payload spec, or none that
/// parses — scopes every source as URL-less.
fn source_url_files(pkg: &Pkg) -> std::collections::HashSet<String> {
    use librpm::build::SpecFlags;

    let header_spec = format!("{}.spec", pkg.name);
    let mut specs: Vec<&crate::pkg::pkgfile::PkgFile> = pkg
        .files
        .iter()
        .filter(|f| f.name.ends_with(".spec"))
        .collect();
    specs.sort_by_key(|f| f.name != header_spec);
    for spec in specs {
        let _ = crate::pkg::init();
        // The define, the parse, the source iteration and the parsed
        // spec's drop all touch process-global librpm state, so the
        // macro lock is held for the whole sequence.
        let _macro_guard = crate::pkg::global_macro_lock();
        let macros = librpm::macro_context::MacroContext::default();
        let dir = std::path::Path::new(&spec.path)
            .parent()
            .map(|d| d.to_string_lossy().into_owned())
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| ".".to_string());
        let _ = macros.define(&format!("_sourcedir {dir}"), 0);
        let parsed =
            librpm::build::Spec::parse(&spec.path, SpecFlags::ANYARCH | SpecFlags::FORCE, None);
        let _ = macros.pop("_sourcedir");
        let Some(parsed) = parsed else { continue };
        let mut url_files = std::collections::HashSet::new();
        for src in parsed.sources() {
            if src.is_source() && has_url_scheme(src.full_path()) {
                url_files.insert(src.filename().to_string());
            }
        }
        return url_files;
    }
    std::collections::HashSet::new()
}

/// Whether `s` starts with a URI scheme (`scheme://`): the scheme is
/// an ASCII letter followed by ASCII alphanumerics, `+`, `-` or `.`.
fn has_url_scheme(s: &str) -> bool {
    let Some(idx) = s.find("://") else {
        return false;
    };
    let scheme = &s[..idx];
    !scheme.is_empty()
        && scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Prebuilt-binary detection inside source archives (issue #150).
///
/// The walker is deliberately small: magic-byte archive detection, a minimal
/// ustar reader, and capped in-memory decompression.
///
/// Scope choices: only ustar tarballs are recognized - pre-POSIX V7 format
/// has no magic bytes and is skipped - and of the zip-based Java archives
/// only `.jar` is reported as a unit; `.war`/`.ear`/`.aar` are walked like
/// plain zips, their classes listed individually.
mod prebuilt {
    use std::io::Read;

    /// Cap on one archive's in-memory bytes (decompressed). Beyond this the
    /// archive is skipped rather than risk a decompression bomb.
    pub const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
    /// Cap on one archive entry's bytes.
    const MAX_ENTRY_BYTES: usize = 64 * 1024 * 1024;
    /// Nesting limit for archives inside archives.
    const MAX_DEPTH: u8 = 5;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum BinaryKind {
        Elf,
        JavaClass,
        PythonBytecode,
        JavaArchive,
    }

    impl BinaryKind {
        pub fn as_str(self) -> &'static str {
            match self {
                BinaryKind::Elf => "ELF binary",
                BinaryKind::JavaClass => "Java class file",
                BinaryKind::PythonBytecode => "Python bytecode",
                BinaryKind::JavaArchive => "Java archive (jar)",
            }
        }
    }

    /// Magic-byte classification of one file's bytes. ELF and Java class
    /// magics are unambiguous; Python bytecode needs its `.pyc`/`.pyo` name
    /// too (bytes 2-3 are `\r\n` in every CPython version, but so are the
    /// first bytes of any CRLF text file); a jar is a zip archive by
    /// definition, so it needs the `.jar` name as well.
    fn classify(name: &str, data: &[u8]) -> Option<BinaryKind> {
        if data.starts_with(b"\x7fELF") {
            return Some(BinaryKind::Elf);
        }
        if data.starts_with(b"\xca\xfe\xba\xbe") {
            return Some(BinaryKind::JavaClass);
        }
        let lower = name.to_ascii_lowercase();
        if data.len() >= 4
            && &data[2..4] == b"\r\n"
            && (lower.ends_with(".pyc") || lower.ends_with(".pyo"))
        {
            return Some(BinaryKind::PythonBytecode);
        }
        if lower.ends_with(".jar") && data.starts_with(b"PK\x03\x04") {
            return Some(BinaryKind::JavaArchive);
        }
        None
    }

    /// Inspect one file: flag it when it is itself a prebuilt binary,
    /// otherwise walk it when it is an archive. `ctx` is the display path
    /// (`outer.tar.gz: inner/file.o`); `depth` counts nested archives.
    pub fn inspect_entry(
        name: &str,
        data: &[u8],
        ctx: &str,
        depth: u8,
        hits: &mut Vec<(BinaryKind, String)>,
    ) {
        if let Some(kind) = classify(name, data) {
            // A jar is reported as a unit; its classes are not listed
            // separately — the jar is what the packager removes in %prep.
            hits.push((kind, ctx.to_string()));
        } else {
            scan_archive(data, ctx, depth + 1, hits);
        }
    }

    fn scan_archive(data: &[u8], ctx: &str, depth: u8, hits: &mut Vec<(BinaryKind, String)>) {
        if depth > MAX_DEPTH {
            return;
        }
        if data.starts_with(b"\x1f\x8b") {
            if let Some(d) = decompress_gzip(data) {
                scan_decompressed(&d, ctx, depth, hits);
            }
        } else if data.starts_with(b"\xfd7zXZ\x00") {
            if let Some(d) = decompress_xz(data) {
                scan_decompressed(&d, ctx, depth, hits);
            }
        } else if data.starts_with(b"\x28\xb5\x2f\xfd") {
            if let Some(d) = decompress_zstd(data) {
                scan_decompressed(&d, ctx, depth, hits);
            }
        } else if data.len() >= 4 && data.starts_with(b"BZh") && (b'1'..=b'9').contains(&data[3]) {
            // The 4th magic byte is the bzip2 block-size digit
            // ('1'..='9'); anything else is not a bzip2 stream.
            if let Some(d) = decompress_bzip2(data) {
                scan_decompressed(&d, ctx, depth, hits);
            }
        } else if data.starts_with(b"PK\x03\x04") {
            walk_zip(data, ctx, depth, hits);
        } else if is_tar(data) {
            walk_tar(data, ctx, depth, hits);
        }
        // Anything else is opaque: skip silently.
    }

    /// A decompressed stream is either a tarball or a single file (e.g.
    /// `prebuilt.o.gz` — the compressed file itself is the binary).
    fn scan_decompressed(data: &[u8], ctx: &str, depth: u8, hits: &mut Vec<(BinaryKind, String)>) {
        if is_tar(data) {
            walk_tar(data, ctx, depth, hits);
        } else if let Some(kind) = classify(ctx, data) {
            hits.push((kind, ctx.to_string()));
        }
    }

    fn is_tar(data: &[u8]) -> bool {
        data.len() >= 512 && &data[257..262] == b"ustar"
    }

    fn walk_tar(data: &[u8], ctx: &str, depth: u8, hits: &mut Vec<(BinaryKind, String)>) {
        for (name, off, len, _size) in read_tar(data) {
            let entry = &data[off..off + len];
            inspect_entry(&name, entry, &format!("{ctx}: {name}"), depth, hits);
        }
    }

    fn walk_zip(data: &[u8], ctx: &str, depth: u8, hits: &mut Vec<(BinaryKind, String)>) {
        let mut archive = match zip::ZipArchive::new(std::io::Cursor::new(data)) {
            Ok(a) => a,
            Err(_) => return,
        };
        for i in 0..archive.len() {
            let entry = match archive.by_index(i) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !entry.is_file() {
                continue;
            }
            // zip 9 returns entry names as results; skip entries whose
            // names do not decode, like every other unreadable entry here.
            let name = match entry.name() {
                Ok(name) => name.into_owned(),
                Err(_) => continue,
            };
            if entry.size() > MAX_ENTRY_BYTES as u64 {
                continue;
            }
            let mut bytes = Vec::new();
            if entry
                .take(MAX_ENTRY_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .is_err()
                || bytes.len() > MAX_ENTRY_BYTES
            {
                continue;
            }
            inspect_entry(&name, &bytes, &format!("{ctx}: {name}"), depth, hits);
        }
    }

    /// One direct member of a source archive. `head` carries the
    /// member's full bytes when it is at most 1023 bytes long (the
    /// git-lfs pointer size arm), and is empty for larger members.
    pub struct TopLevelMember {
        pub name: String,
        pub size: u64,
        pub head: Vec<u8>,
    }

    /// The direct members of the archive in `data` (depth 1 only:
    /// nested archives appear as opaque members and are not opened).
    /// A compressed stream that does not hold a tarball is a single
    /// file, not an archive, and yields no members.
    pub fn top_level_members(data: &[u8]) -> Vec<TopLevelMember> {
        if data.starts_with(b"\x1f\x8b") {
            decompress_gzip(data)
                .map(|d| tar_members(&d))
                .unwrap_or_default()
        } else if data.starts_with(b"\xfd7zXZ\x00") {
            decompress_xz(data)
                .map(|d| tar_members(&d))
                .unwrap_or_default()
        } else if data.starts_with(b"\x28\xb5\x2f\xfd") {
            decompress_zstd(data)
                .map(|d| tar_members(&d))
                .unwrap_or_default()
        } else if data.len() >= 4 && data.starts_with(b"BZh") && (b'1'..=b'9').contains(&data[3]) {
            decompress_bzip2(data)
                .map(|d| tar_members(&d))
                .unwrap_or_default()
        } else if data.starts_with(b"PK\x03\x04") {
            zip_members(data)
        } else if is_tar(data) {
            tar_members(data)
        } else {
            Vec::new()
        }
    }

    fn tar_members(data: &[u8]) -> Vec<TopLevelMember> {
        if !is_tar(data) {
            return Vec::new();
        }
        read_tar(data)
            .into_iter()
            .map(|(name, off, len, size)| TopLevelMember {
                name: normalize_member_name(&name),
                size,
                head: if size <= 1023 {
                    data[off..off + len].to_vec()
                } else {
                    Vec::new()
                },
            })
            .collect()
    }

    fn zip_members(data: &[u8]) -> Vec<TopLevelMember> {
        let mut archive = match zip::ZipArchive::new(std::io::Cursor::new(data)) {
            Ok(a) => a,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for i in 0..archive.len() {
            let entry = match archive.by_index(i) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !entry.is_file() {
                continue;
            }
            let name = match entry.name() {
                Ok(name) => normalize_member_name(&name),
                Err(_) => continue,
            };
            let size = entry.size();
            let head = if size <= 1023 {
                let mut bytes = Vec::new();
                if entry.take(1024).read_to_end(&mut bytes).is_err() {
                    continue;
                }
                bytes
            } else {
                Vec::new()
            };
            out.push(TopLevelMember { name, size, head });
        }
        out
    }

    /// Member names are matched and reported without leading `./` or
    /// `/` segments.
    fn normalize_member_name(name: &str) -> String {
        let mut s = name;
        loop {
            if let Some(rest) = s.strip_prefix("./") {
                s = rest;
            } else if let Some(rest) = s.strip_prefix('/') {
                s = rest;
            } else {
                break;
            }
        }
        s.to_string()
    }

    /// A version-control metadata tree found among the members.
    pub struct VcsRoot {
        pub root: String,
        pub entries: usize,
        pub bytes: u64,
    }

    /// Group the members matching the VCS predicate by metadata
    /// root, counting entries and bytes per root.
    pub fn vcs_roots(members: &[TopLevelMember]) -> Vec<VcsRoot> {
        let mut by_root: std::collections::BTreeMap<String, (usize, u64)> =
            std::collections::BTreeMap::new();
        for m in members {
            if let Some(root) = vcs_root(&m.name) {
                let e = by_root.entry(root).or_default();
                e.0 += 1;
                e.1 += m.size;
            }
        }
        by_root
            .into_iter()
            .map(|(root, (entries, bytes))| VcsRoot {
                root,
                entries,
                bytes,
            })
            .collect()
    }

    /// The metadata root a member belongs to, if it matches the
    /// predicate: with `/` prefixed, the name contains a
    /// `.(bzr|git|hg|svn)/` tree component, or ends with a file
    /// directly inside a `CVS` directory. The `,v` and `RCS/` arms of
    /// the file-list pattern are out: a CVS repository fixture's `,v`
    /// files are content, not a metadata tree. Working-tree dotfiles
    /// (`.gitignore`, `.gitmodules`, `.github/`) and a `sub/.git`
    /// gitlink file do not match: the tree component must be a
    /// directory.
    fn vcs_root(name: &str) -> Option<String> {
        let prefixed = format!("/{name}");
        let mut best: Option<(usize, String)> = None;
        for kind in [".bzr", ".git", ".hg", ".svn"] {
            let needle = format!("/{kind}/");
            if let Some(idx) = prefixed.find(&needle) {
                let root = prefixed[1..idx + kind.len() + 1].to_string();
                if best.as_ref().is_none_or(|(i, _)| idx < *i) {
                    best = Some((idx, root));
                }
            }
        }
        if let Some(idx) = prefixed.rfind("/CVS/") {
            let rest = &prefixed[idx + 5..];
            if !rest.is_empty() && !rest.contains('/') {
                let root = prefixed[1..idx + 4].to_string();
                if best.as_ref().is_none_or(|(i, _)| idx < *i) {
                    best = Some((idx, root));
                }
            }
        }
        best.map(|(_, root)| root)
    }

    /// The names of members holding a git-lfs pointer stub: a regular
    /// member of 1-1023 bytes that starts with the pointer version
    /// line (the current git-lfs URL or the legacy hawser one) and
    /// carries an `oid sha256:` line. A document merely quoting the
    /// version line after offset 0 is not a pointer.
    pub fn lfs_pointers(members: &[TopLevelMember]) -> Vec<String> {
        members
            .iter()
            .filter(|m| {
                m.size >= 1
                    && m.size <= 1023
                    && (m
                        .head
                        .starts_with(b"version https://git-lfs.github.com/spec/v1\n")
                        || m.head
                            .starts_with(b"version https://hawser.github.com/spec/v1\n"))
                    && m.head
                        .split(|&b| b == b'\n')
                        .any(|line| line.starts_with(b"oid sha256:"))
            })
            .map(|m| m.name.clone())
            .collect()
    }

    /// Capped decompression: one byte past the cap means "too big".
    fn capped<R: Read>(r: R) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        if r.take(MAX_ARCHIVE_BYTES as u64 + 1)
            .read_to_end(&mut out)
            .is_err()
            || out.len() > MAX_ARCHIVE_BYTES
        {
            return None;
        }
        Some(out)
    }

    fn decompress_gzip(data: &[u8]) -> Option<Vec<u8>> {
        capped(flate2::read::GzDecoder::new(data))
    }

    fn decompress_xz(data: &[u8]) -> Option<Vec<u8>> {
        capped(liblzma::read::XzDecoder::new(data))
    }

    fn decompress_zstd(data: &[u8]) -> Option<Vec<u8>> {
        capped(zstd::stream::read::Decoder::new(data).ok()?)
    }

    fn decompress_bzip2(data: &[u8]) -> Option<Vec<u8>> {
        capped(bzip2::read::BzDecoder::new(data))
    }

    /// Parse an octal field (tar size), strictly: only `[0-7]`, blank-padded.
    /// Returns `None` on any other byte so corrupt headers stop the walk
    /// instead of being guessed at.
    fn parse_octal(field: &[u8]) -> Option<u64> {
        let mut s = field;
        while let Some((&b, rest)) = s.split_last() {
            if b == 0 || b == b' ' {
                s = rest;
            } else {
                break;
            }
        }
        while let Some((&b, rest)) = s.split_first() {
            if b == b' ' {
                s = rest;
            } else {
                break;
            }
        }
        if s.is_empty() {
            return Some(0);
        }
        let mut v: u64 = 0;
        for &b in s {
            if !(b'0'..=b'7').contains(&b) {
                return None;
            }
            v = v.checked_mul(8)?.checked_add((b - b'0') as u64)?;
        }
        Some(v)
    }

    fn header_str(hdr: &[u8], range: std::ops::Range<usize>) -> String {
        let raw = &hdr[range];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    }

    /// Minimal ustar reader: `(name, data_offset, data_len)` for regular
    /// files. Understands GNU long names (`L`); skips directories,
    /// symlinks and pax headers with their data; stops at the first
    /// corrupt header or the end-of-archive zero blocks. Entry sizes are
    /// capped — oversized entries are skipped, not read.
    fn read_tar(data: &[u8]) -> Vec<(String, usize, usize, u64)> {
        let mut out = Vec::new();
        let mut pos = 0;
        let mut long_name: Option<String> = None;
        while pos + 512 <= data.len() {
            let hdr = &data[pos..pos + 512];
            if hdr.iter().all(|&b| b == 0) {
                break;
            }
            let typeflag = hdr[156];
            let size = match parse_octal(&hdr[124..136]) {
                Some(s) => s,
                None => break,
            };
            pos += 512;
            // `div_ceil` on the raw size: skipping stays aligned even for
            // entries too big to read.
            let blocks = size.div_ceil(512).checked_mul(512);
            let Some(blocks) = blocks else {
                break;
            };
            let Ok(blocks) = usize::try_from(blocks) else {
                break;
            };
            let data_end = pos.saturating_add(size.min(4096) as usize);
            if typeflag == b'L' {
                // GNU long name: the data is the next entry's name. Capped at
                // 4 KiB: real paths never approach this; longer is corrupt or hostile.
                if data_end <= data.len() {
                    let raw = &data[pos..data_end];
                    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                    long_name = Some(String::from_utf8_lossy(&raw[..end]).into_owned());
                }
            } else if typeflag == b'0' || typeflag == 0 {
                let name = match long_name.take() {
                    Some(n) => n,
                    None => {
                        let mut name = header_str(hdr, 0..100);
                        let prefix = header_str(hdr, 345..500);
                        if !prefix.is_empty() {
                            name = format!("{prefix}/{name}");
                        }
                        name
                    }
                };
                let len = (size as usize).min(MAX_ENTRY_BYTES);
                if size <= MAX_ENTRY_BYTES as u64 && pos + len <= data.len() {
                    out.push((name, pos, len, size));
                }
            } else {
                // Directories, symlinks, pax headers: a pending long name
                // does not belong to them.
                long_name = None;
            }
            pos = pos.saturating_add(blocks);
            if pos > data.len() {
                break;
            }
        }
        out
    }
}

/// The reference's `int(value, 8)`, faithfully: surrounding whitespace is
/// stripped, exactly one ASCII sign is allowed (a second sign is a
/// `ValueError`, not a double negation), the `0o`/`0O` prefix is optional,
/// PEP 515 underscores are allowed between digits and directly after the
/// prefix, and any Unicode decimal digit (`Py_UNICODE_TODECIMAL`) below the
/// base is accepted — so `int('٦٤٤', 8)` is 420.
///
/// The value is unbounded like the reference's: magnitudes beyond `u128`
/// saturate at `u128::MAX` (ledgered as `kind = "detail"` — the saturated
/// value can never equal a real file mode, which is the only comparison
/// this value feeds). Digits past the saturation point are still validated:
/// trailing garbage makes this return `None`, and `SourceCheck::new` panics
/// on `None` — the reference's `int(value, 8)` raises `ValueError` on the
/// same input, so both die on the bad entry instead of silently accepting it.
fn parse_octal(s: &str) -> Option<u128> {
    let s = s.trim();
    let (s, neg) = match s.as_bytes().first() {
        Some(b'-') => (&s[1..], true),
        Some(b'+') => (&s[1..], false),
        _ => (s, false),
    };
    if s.as_bytes()
        .first()
        .is_some_and(|b| *b == b'+' || *b == b'-')
    {
        return None;
    }
    let (s, after_prefix) = match s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        Some(rest) => (rest, true),
        None => (s, false),
    };
    let mut value: u128 = 0;
    // An underscore may follow the prefix or a digit, never anything else.
    let mut underscore_ok = after_prefix;
    // u64: the counter now runs past saturation over the whole string,
    // so a u32 could overflow (and panic a debug build) on an absurdly long entry.
    let mut digits = 0u64;
    // Once the magnitude overflows u128 the value saturates, but every
    // remaining digit is still validated: the reference raises ValueError
    // for trailing garbage regardless of the leading magnitude.
    let mut saturated = false;
    for c in s.chars() {
        if c == '_' {
            if !underscore_ok {
                return None;
            }
            underscore_ok = false;
            continue;
        }
        let d = unicode_octal_digit(c)?;
        underscore_ok = true;
        digits += 1;
        if !saturated {
            value = match value.checked_mul(8).and_then(|v| v.checked_add(d as u128)) {
                Some(v) => v,
                None => {
                    saturated = true;
                    u128::MAX
                }
            };
        }
    }
    if digits == 0 || !underscore_ok {
        return None;
    }
    if saturated {
        // The magnitude alone already exceeds u128, so the sign is moot:
        // saturation wins exactly as the old immediate return did.
        return Some(u128::MAX);
    }
    Some(if neg { value.wrapping_neg() } else { value })
}

/// A Unicode decimal digit's value when below 8, like CPython's
/// `Py_UNICODE_TODECIMAL` restricted to the base.
fn unicode_octal_digit(c: char) -> Option<u32> {
    let v = unicode_decimal_value(c)?;
    (v < 8).then_some(v)
}

/// The decimal value of any Unicode decimal-digit character, mirroring
/// CPython's `Py_UNICODE_TODECIMAL`. Each arm is one digit block laid out
/// 0-9 in order; characters outside these blocks are not decimal digits.
///
/// The blocks are the decimal-digit blocks of CPython 3.14.8's
/// unicodedata (Unicode 16.0.0), regenerated from that interpreter;
/// the block names in the arm comments are its character names.
fn unicode_decimal_value(c: char) -> Option<u32> {
    let c = c as u32;
    let base = match c {
        0x0030..=0x0039 => 0x0030,    // ASCII
        0x0660..=0x0669 => 0x0660,    // Arabic-Indic
        0x06F0..=0x06F9 => 0x06F0,    // Extended Arabic-Indic
        0x07C0..=0x07C9 => 0x07C0,    // NKo
        0x0966..=0x096F => 0x0966,    // Devanagari
        0x09E6..=0x09EF => 0x09E6,    // Bengali
        0x0A66..=0x0A6F => 0x0A66,    // Gurmukhi
        0x0AE6..=0x0AEF => 0x0AE6,    // Gujarati
        0x0B66..=0x0B6F => 0x0B66,    // Oriya
        0x0BE6..=0x0BEF => 0x0BE6,    // Tamil
        0x0C66..=0x0C6F => 0x0C66,    // Telugu
        0x0CE6..=0x0CEF => 0x0CE6,    // Kannada
        0x0D66..=0x0D6F => 0x0D66,    // Malayalam
        0x0DE6..=0x0DEF => 0x0DE6,    // Sinhala Lith
        0x0E50..=0x0E59 => 0x0E50,    // Thai
        0x0ED0..=0x0ED9 => 0x0ED0,    // Lao
        0x0F20..=0x0F29 => 0x0F20,    // Tibetan
        0x1040..=0x1049 => 0x1040,    // Myanmar
        0x1090..=0x1099 => 0x1090,    // Myanmar Shan
        0x17E0..=0x17E9 => 0x17E0,    // Khmer
        0x1810..=0x1819 => 0x1810,    // Mongolian
        0x1946..=0x194F => 0x1946,    // Limbu
        0x19D0..=0x19D9 => 0x19D0,    // New Tai Lue
        0x1A80..=0x1A89 => 0x1A80,    // Tai Tham Hora
        0x1A90..=0x1A99 => 0x1A90,    // Tai Tham Tham
        0x1B50..=0x1B59 => 0x1B50,    // Balinese
        0x1BB0..=0x1BB9 => 0x1BB0,    // Sundanese
        0x1C40..=0x1C49 => 0x1C40,    // Lepcha
        0x1C50..=0x1C59 => 0x1C50,    // Ol Chiki
        0xA620..=0xA629 => 0xA620,    // Vai
        0xA8D0..=0xA8D9 => 0xA8D0,    // Saurashtra
        0xA900..=0xA909 => 0xA900,    // Kayah Li
        0xA9D0..=0xA9D9 => 0xA9D0,    // Javanese
        0xA9F0..=0xA9F9 => 0xA9F0,    // Myanmar Tai Laing
        0xAA50..=0xAA59 => 0xAA50,    // Cham
        0xABF0..=0xABF9 => 0xABF0,    // Meetei Mayek
        0xFF10..=0xFF19 => 0xFF10,    // Fullwidth
        0x104A0..=0x104A9 => 0x104A0, // Osmanya
        0x10D30..=0x10D39 => 0x10D30, // Hanifi Rohingya
        0x10D40..=0x10D49 => 0x10D40, // Garay
        0x11066..=0x1106F => 0x11066, // Brahmi
        0x110F0..=0x110F9 => 0x110F0, // Sora Sompeng
        0x11136..=0x1113F => 0x11136, // Chakma
        0x111D0..=0x111D9 => 0x111D0, // Sharada
        0x112F0..=0x112F9 => 0x112F0, // Khudawadi
        0x11450..=0x11459 => 0x11450, // Newa
        0x114D0..=0x114D9 => 0x114D0, // Tirhuta
        0x11650..=0x11659 => 0x11650, // Modi
        0x116C0..=0x116C9 => 0x116C0, // Takri
        0x116D0..=0x116D9 => 0x116D0, // Myanmar Pao
        0x116DA..=0x116E3 => 0x116DA, // Myanmar Eastern Pwo Karen
        0x11730..=0x11739 => 0x11730, // Ahom
        0x118E0..=0x118E9 => 0x118E0, // Warang Citi
        0x11950..=0x11959 => 0x11950, // Dives Akuru
        0x11BF0..=0x11BF9 => 0x11BF0, // Sunuwar
        0x11C50..=0x11C59 => 0x11C50, // Bhaiksuki
        0x11D50..=0x11D59 => 0x11D50, // Masaram Gondi
        0x11DA0..=0x11DA9 => 0x11DA0, // Gunjala Gondi
        0x11F50..=0x11F59 => 0x11F50, // Kawi
        0x16130..=0x16139 => 0x16130, // Gurung Khema
        0x16A60..=0x16A69 => 0x16A60, // Mro
        0x16AC0..=0x16AC9 => 0x16AC0, // Tangsa
        0x16B50..=0x16B59 => 0x16B50, // Pahawh Hmong
        0x16D70..=0x16D79 => 0x16D70, // Kirat Rai
        0x1CCF0..=0x1CCF9 => 0x1CCF0, // Outlined
        0x1D7CE..=0x1D7D7 => 0x1D7CE, // Mathematical Bold
        0x1D7D8..=0x1D7E1 => 0x1D7D8, // Mathematical Double-Struck
        0x1D7E2..=0x1D7EB => 0x1D7E2, // Mathematical Sans-Serif
        0x1D7EC..=0x1D7F5 => 0x1D7EC, // Mathematical Sans-Serif Bold
        0x1D7F6..=0x1D7FF => 0x1D7F6, // Mathematical Monospace
        0x1E140..=0x1E149 => 0x1E140, // Nyiakeng Puachue Hmong
        0x1E2F0..=0x1E2F9 => 0x1E2F0, // Wancho
        0x1E4F0..=0x1E4F9 => 0x1E4F0, // Nag Mundari
        0x1E5F1..=0x1E5FA => 0x1E5F1, // Ol Onal
        0x1E950..=0x1E959 => 0x1E950, // Adlam
        0x1FBF0..=0x1FBF9 => 0x1FBF0, // Segmented
        _ => return None,
    };
    Some(c - base)
}

/// Python's `repr()` for `str`, for the `inconsistent-file-extension` detail
/// (the reference interpolates `{fname!r}`). Single quotes unless the string
/// contains `'` and no `"`, escaping the quote in use and the backslash,
/// with the C0 controls CPython names (`\\n`, `\\r`, `\\t`, else `\\xNN`).
fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

impl Check for SourceCheck {
    fn name(&self) -> &'static str {
        "SourceCheck"
    }

    /// This check never emits errors (every `add_info` call site passes
    /// `Level::Warning`), so `--errors-only` skips it.
    fn max_severity(&self) -> Level {
        Level::Warning
    }

    fn check_source(&mut self, pkg: &Pkg, config: &Config, out: &mut Filter) {
        Self::register_error_details(config, out);
        for f in &pkg.files {
            for (level, check, details) in self.file_findings(&f.name, f.mode, &f.magic) {
                let refs: Vec<&str> = details.iter().map(String::as_str).collect();
                add_info(out, level, pkg, check, &refs);
            }
        }
        self.check_rpmlintrc_setbadness(pkg, config, out);
        self.check_archive_contents(pkg, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checker() -> SourceCheck {
        let table: toml::Table = toml::from_str(
            r#"
CompressExtension = "gz"
ValidSrcPerms = ["0o644", "0o755"]
"#,
        )
        .expect("parse test config");
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        SourceCheck::new(&config)
    }

    /// Every [`unicode_decimal_value`] match arm, pinned at both edges and
    /// the middle: deleting an arm (or shifting a boundary) turns those
    /// lookups into `None` or wrong values. Neighbors assert `None` except
    /// inside contiguous runs (the Mathematical blocks and the Myanmar
    /// Pao / Eastern Pwo Karen pair), where the adjacency itself is
    /// pinned by the neighboring blocks' edges.
    #[test]
    fn unicode_decimal_value_covers_all_digit_blocks() {
        const BASES: &[u32] = &[
            0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6,
            0xD66, 0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0,
            0x1A80, 0x1A90, 0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0,
            0xAA50, 0xABF0, 0xFF10, 0x104A0, 0x10D30, 0x10D40, 0x11066, 0x110F0, 0x11136, 0x111D0,
            0x112F0, 0x11450, 0x114D0, 0x11650, 0x116C0, 0x116D0, 0x116DA, 0x11730, 0x118E0,
            0x11950, 0x11BF0, 0x11C50, 0x11D50, 0x11DA0, 0x11F50, 0x16130, 0x16A60, 0x16AC0,
            0x16B50, 0x16D70, 0x1CCF0, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140,
            0x1E2F0, 0x1E4F0, 0x1E5F1, 0x1E950, 0x1FBF0,
        ];
        const EXCEPT: &[u32] = &[
            0x116D9, 0x116DA, 0x1D7D7, 0x1D7D8, 0x1D7E1, 0x1D7E2, 0x1D7EB, 0x1D7EC, 0x1D7F5,
            0x1D7F6,
        ];
        for &base in BASES {
            let c = |o| char::from_u32(base + o).unwrap();
            assert_eq!(unicode_decimal_value(c(0)), Some(0), "base {base:#X}");
            assert_eq!(unicode_decimal_value(c(5)), Some(5), "base {base:#X}");
            assert_eq!(unicode_decimal_value(c(9)), Some(9), "base {base:#X}");
            for n in [base.wrapping_sub(1), base + 10] {
                if EXCEPT.contains(&n) {
                    continue;
                }
                assert_eq!(
                    unicode_decimal_value(char::from_u32(n).unwrap()),
                    None,
                    "neighbor {n:#X}"
                );
            }
        }
        for c in ['/', ':', '@', 'A', '\u{1D7C0}', '\u{10FFFF}'] {
            assert_eq!(unicode_decimal_value(c), None, "{c:?}");
        }
    }

    #[test]
    fn matching_extension_and_magic_is_quiet() {
        let c = checker();
        let found = c.file_findings("foo.tar.gz", 0o100644, "gzip compressed data, from Unix");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn mismatched_magic_is_reported() {
        let c = checker();
        let found = c.file_findings("foo.tar.xz", 0o100644, "gzip compressed data");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Warning);
        assert_eq!(found[0].1, "inconsistent-file-extension");
        assert_eq!(
            found[0].2,
            vec!["file 'foo.tar.xz' magic 'gzip compressed data' does not match 'XZ compressed'"]
        );
    }

    #[test]
    fn magic_match_is_case_insensitive() {
        let c = checker();
        let found = c.file_findings("foo.zip", 0o100644, "zip archive data, at least v2.0");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn unknown_extension_is_not_checked() {
        let c = checker();
        let found = c.file_findings("README", 0o100644, "ASCII text");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn empty_magic_is_not_checked() {
        let c = checker();
        let found = c.file_findings("foo.tar.gz", 0o100644, "");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn strange_permission_is_reported_in_octal() {
        let c = checker();
        let found = c.file_findings("foo.tar.gz", 0o100600, "gzip compressed data");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Warning);
        assert_eq!(found[0].1, "strange-permission");
        assert_eq!(found[0].2, vec!["foo.tar.gz", "600"]);
    }

    #[test]
    fn uncompressed_tarball_is_reported() {
        let c = checker();
        let found = c.file_findings("foo.tar", 0o100644, "POSIX tar archive");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Warning);
        assert_eq!(found[0].1, "source-not-compressed");
        assert_eq!(found[0].2, vec!["gz", "foo.tar"]);
    }

    #[test]
    fn tgz_counts_as_compressed_for_gz() {
        // `endswith("gz")`: the reference accepts `.tgz` for `CompressExtension = "gz"`.
        let c = checker();
        let found = c.file_findings("foo.tgz", 0o100644, "gzip compressed data");
        assert!(found.is_empty(), "{found:?}");
    }

    /// Negative pin for the removed `multiple-specfiles` finding: a
    /// source package carrying two spec files stays silent, and
    /// `cargo test` (not just the reference-coverage auditor) must catch
    /// a re-add.
    #[test]
    fn killed_multiple_specfiles_stays_absent() {
        use std::path::Path;

        use crate::color::Color;
        use crate::pkg::pkgfile::PkgFile;

        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.files = ["foo.spec", "bar.spec"]
            .iter()
            .map(|name| PkgFile {
                name: name.to_string(),
                mode: 0o100644,
                magic: "ASCII text".to_string(),
                ..Default::default()
            })
            .collect();
        let table: toml::Table =
            toml::from_str("CompressExtension = \"gz\"\nValidSrcPerms = [\"0o644\", \"0o755\"]")
                .expect("parse test config");
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SourceCheck::new(&config);
        check.check_source(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            !names.contains(&"multiple-specfiles"),
            "must stay silent: {names:?}"
        );
    }

    #[test]
    fn parse_octal_matches_python_int_base_8() {
        assert_eq!(parse_octal("0o644"), Some(0o644));
        assert_eq!(parse_octal("644"), Some(0o644));
        assert_eq!(parse_octal("0o755"), Some(0o755));
        assert_eq!(parse_octal("0O755"), Some(0o755));
        // `int(v, 8)` strips whitespace and accepts a single sign.
        assert_eq!(parse_octal("  644\t"), Some(0o644));
        assert_eq!(parse_octal("+0o644"), Some(0o644));
        assert_eq!(parse_octal("-644"), Some(0o644u128.wrapping_neg()));
        // A second sign is a ValueError, not a double negation.
        assert_eq!(parse_octal("++644"), None);
        assert_eq!(parse_octal("-+644"), None);
        assert_eq!(parse_octal("+-644"), None);
        assert_eq!(parse_octal("+"), None);
        assert_eq!(parse_octal("-"), None);
        // PEP 515 underscores: between digits and after the prefix only.
        assert_eq!(parse_octal("0o6_44"), Some(0o644));
        assert_eq!(parse_octal("6_4_4"), Some(0o644));
        assert_eq!(parse_octal("0o_644"), Some(0o644));
        assert_eq!(parse_octal("_644"), None);
        assert_eq!(parse_octal("644_"), None);
        assert_eq!(parse_octal("6__44"), None);
        assert_eq!(parse_octal("0o_"), None);
        assert_eq!(parse_octal("+_644"), None);
        // Non-ASCII decimal digits below the base are accepted.
        assert_eq!(parse_octal("\u{0666}\u{0664}\u{0664}"), Some(0o644));
        assert_eq!(parse_octal("\u{FF16}\u{FF14}\u{FF14}"), Some(0o644));
        // ...but 8 and 9 are not octal digits in any script.
        assert_eq!(parse_octal("\u{0668}\u{0664}\u{0664}"), None);
        assert_eq!(parse_octal("0o8"), None);
        assert_eq!(parse_octal("8"), None);
        // Unbounded magnitude, like the reference's arbitrary precision.
        assert_eq!(parse_octal("0o777777777777"), Some(0o777777777777));
        assert_eq!(
            parse_octal(&format!("0o{}", "7".repeat(22))),
            Some(73786976294838206463)
        );
        assert_eq!(parse_octal("bogus"), None);
        assert_eq!(parse_octal(""), None);
        assert_eq!(parse_octal("0o"), None);
    }

    #[test]
    fn parse_octal_saturates_beyond_u128() {
        // The ledger documents saturation at u128::MAX where the reference
        // keeps arbitrary precision; Python accepts the input, so pin the
        // port's documented behaviour.
        assert_eq!(
            parse_octal(&format!("0o{}", "7".repeat(50))),
            Some(u128::MAX)
        );
        // The exact boundary still parses precisely, not via saturation.
        assert_eq!(
            parse_octal("0o3777777777777777777777777777777777777777777"),
            Some(u128::MAX)
        );
    }

    #[test]
    fn parse_octal_overflow_still_validates_trailing_digits() {
        // The overflow arm used to return Some(u128::MAX) immediately,
        // abandoning validation of the remaining digits; the reference
        // raises ValueError for every one of these (plusky's #123 review).
        let huge = format!("0o{}", "7".repeat(43));
        for tail in ["9", "8", "_", "0x1"] {
            assert_eq!(parse_octal(&format!("{huge}{tail}")), None, "tail {tail:?}");
        }
        // Valid digits past the saturation point still saturate, ...
        assert_eq!(parse_octal(&format!("{huge}7")), Some(u128::MAX));
        assert_eq!(parse_octal(&format!("{huge}_7")), Some(u128::MAX));
        // ... and saturation wins over the sign, as the old early return did.
        assert_eq!(
            parse_octal(&format!("-0o{}", "7".repeat(50))),
            Some(u128::MAX)
        );
    }

    #[test]
    fn py_repr_matches_python() {
        assert_eq!(py_repr("foo.tar.xz"), "'foo.tar.xz'");
        // Apostrophe without a double quote: double quotes, like `repr`.
        assert_eq!(py_repr("it's.tar.xz"), "\"it's.tar.xz\"");
        // Double quote alone: single quotes, inner quote untouched.
        assert_eq!(py_repr("say \"hi\".tar.xz"), "'say \"hi\".tar.xz'");
        // Both: single quotes with the apostrophe escaped.
        assert_eq!(
            py_repr("it's \"quoted\".tar.xz"),
            "'it\\'s \"quoted\".tar.xz'"
        );
        assert_eq!(py_repr("back\\slash"), "'back\\\\slash'");
        assert_eq!(py_repr("a\nb\tc\rd"), "'a\\nb\\tc\\rd'");
        assert_eq!(py_repr("a\x00b"), "'a\\x00b'");
    }

    #[test]
    fn detail_switches_to_double_quotes_for_apostrophe() {
        // `repr("it's.tar.xz")` is `"it's.tar.xz"`: the reference uses `!r`.
        let c = checker();
        let found = c.file_findings("it's.tar.xz", 0o100644, "gzip compressed data");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Warning);
        assert_eq!(
            found[0].2,
            vec![
                "file \"it's.tar.xz\" magic 'gzip compressed data' does not match 'XZ compressed'"
            ]
        );
    }

    #[test]
    fn detail_escapes_quote_and_backslash_in_magic() {
        // libmagic output embeds filenames; quotes and backslashes must not
        // pass through raw the way hardcoded single quotes would allow.
        let c = checker();
        let found = c.file_findings("foo.tar.xz", 0o100644, "it's a \\weird\nmagic");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].2,
            vec![
                "file 'foo.tar.xz' magic \"it's a \\\\weird\\nmagic\" does not match 'XZ compressed'"
            ]
        );
    }

    #[test]
    #[should_panic(expected = "ValidSrcPerms must be an array")]
    fn missing_valid_src_perms_panics() {
        // The reference raises KeyError; an empty list would flag every file.
        let table: toml::Table =
            toml::from_str("CompressExtension = \"gz\"").expect("parse test config");
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = SourceCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "CompressExtension must be a string")]
    fn missing_compress_extension_panics() {
        // The reference raises KeyError on `config.configuration['CompressExtension']`;
        // defaulting to "" would render a mangled description.
        let table: toml::Table =
            toml::from_str("ValidSrcPerms = [\"0o644\"]").expect("parse test config");
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = SourceCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "not valid octal")]
    fn unparsable_valid_src_perms_entry_panics() {
        // The reference raises ValueError; dropping the entry would flag
        // every file with `strange-permission`.
        let table: toml::Table =
            toml::from_str("CompressExtension = \"gz\"\nValidSrcPerms = [\"bogus\"]")
                .expect("parse test config");
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = SourceCheck::new(&config);
    }

    #[test]
    fn trailing_newline_still_matches_source_regex() {
        // The reference's `source_regex.search` uses `$`, which matches
        // before a trailing newline; `ends_with(".tar")` would stay silent.
        let c = checker();
        let found = c.file_findings("foo.tar\n", 0o100644, "POSIX tar archive");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, "source-not-compressed");
    }

    #[test]
    fn check_source_entry_point_emits_per_file_findings() {
        // Kills M8-prime (zero files iterated) and M15 (per-file findings
        // dropped): the whole `check_source` body must run for findings
        // to reach the `Filter`.
        use std::path::Path;

        use crate::color::Color;
        use crate::pkg::pkgfile::PkgFile;

        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.files = vec![PkgFile {
            name: "bogus.gz".to_string(),
            mode: 0o100644,
            magic: "ASCII text".to_string(),
            ..Default::default()
        }];
        let table: toml::Table =
            toml::from_str("CompressExtension = \"gz\"\nValidSrcPerms = [\"0o644\", \"0o755\"]")
                .expect("parse test config");
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SourceCheck::new(&config);
        check.check_source(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["inconsistent-file-extension"]);
    }
}

#[cfg(test)]
mod prebuilt_tests {
    use super::*;
    use std::io::Write;

    /// Minimal ustar writer for fixtures (test-only). Names must fit in 100
    /// bytes; the production reader is what is under test.
    fn tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in entries {
            assert!(name.len() <= 100, "test tar writer: name too long");
            let mut hdr = [0u8; 512];
            hdr[..name.len()].copy_from_slice(name.as_bytes());
            hdr[100..108].copy_from_slice(b"0000644\0");
            let size = format!("{:011o}\0", data.len());
            hdr[124..136].copy_from_slice(size.as_bytes());
            hdr[156] = b'0';
            hdr[257..262].copy_from_slice(b"ustar");
            hdr[148..156].copy_from_slice(b"        ");
            let sum: u32 = hdr.iter().map(|&b| b as u32).sum();
            let sum_field = format!("{sum:06o}\0 ");
            hdr[148..156].copy_from_slice(sum_field.as_bytes());
            out.extend_from_slice(&hdr);
            out.extend_from_slice(data);
            out.extend(std::iter::repeat_n(0, (512 - data.len() % 512) % 512));
        }
        out.extend([0u8; 1024]);
        out
    }

    fn gzip_bytes(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        for (name, data) in entries {
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            archive.start_file(*name, options).unwrap();
            archive.write_all(data).unwrap();
        }
        archive.finish().unwrap();
        buf
    }

    // Magic-byte fixtures: detection is magic-based, so these carry the real
    // signatures (a longer fake body proves only the head is inspected).
    const ELF: &[u8] = b"\x7fELF\x02\x01\x01\x00fake-elf-binary-body";
    const CLASS: &[u8] = b"\xca\xfe\xba\xbe\x00\x00\x00\x34fake-class-body";
    const PYC: &[u8] = b"\xa6\xf3\x0d\x0afake-pyc-body";

    /// Build a source RPM at test time (never a committed distro RPM) with
    /// `files` at package-relative paths, then open it with real payload
    /// extraction. The rpm crate's builder sets no SOURCERPM tag, so
    /// `is_source` is forced like the reference derives it for .src.rpm.
    fn source_pkg(files: &[(&str, Vec<u8>)]) -> (Pkg, tempfile::TempDir, tempfile::TempDir) {
        use rpm::{BuildConfig, FileMode, FileOptions, PackageBuilder};
        let src = tempfile::tempdir().unwrap();
        let rpm_path = src.path().join("prebuilt-test-1.0-1.src.rpm");
        let mut b = PackageBuilder::new("prebuilt-test", "1.0", "MIT", "x86_64", "prebuilt");
        b.using_config(BuildConfig::default());
        for (name, data) in files {
            let dest = format!("/{name}");
            b.with_file_contents(
                data.clone(),
                FileOptions::new(&dest).mode(FileMode::regular(0o644)),
            )
            .unwrap();
        }
        let built = b.build().unwrap();
        built
            .write(&mut std::fs::File::create(&rpm_path).unwrap())
            .unwrap();
        let extract = tempfile::tempdir().unwrap();
        let mut pkg = Pkg::open(&rpm_path, extract.path(), true).expect("open test srpm");
        // The rpm crate's builder emits a SOURCERPM tag, so force the
        // source-package shape the reference derives for .src.rpm (a real
        // source RPM has no SOURCERPM tag, relative file names and arch
        // "src").
        pkg.is_source = true;
        pkg.arch = "src".to_string();
        for f in &mut pkg.files {
            f.name = f.name.trim_start_matches('/').to_string();
        }
        (pkg, src, extract)
    }

    fn test_config() -> Config {
        let table: toml::Table =
            toml::from_str("CompressExtension = \"gz\"\nValidSrcPerms = [\"0o644\", \"0o755\"]")
                .expect("parse test config");
        Config {
            configuration: table,
            ..Default::default()
        }
    }

    /// Real emission path: `Check::check` dispatch on a source package with
    /// a tarball → findings in the filter.
    fn run_source(pkg: &Pkg) -> Vec<(String, String, Level)> {
        run_source_with_config(pkg, &test_config())
    }

    fn run_source_with_config(pkg: &Pkg, config: &Config) -> Vec<(String, String, Level)> {
        use crate::color::Color;
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        let mut check = SourceCheck::new(config);
        Check::check(&mut check, pkg, config, &mut out);
        out.results()
            .iter()
            .zip(out.result_levels().iter())
            .map(|((n, line), l)| (n.clone(), line.clone(), *l))
            .collect()
    }

    fn setbadness_lines(findings: &[(String, String, Level)]) -> Vec<String> {
        let mut lines: Vec<String> = findings
            .iter()
            .filter(|(n, _, l)| n == "rpmlintrc-uses-setbadness" && *l == Level::Warning)
            .map(|(_, line, _)| line.clone())
            .collect();
        lines.sort();
        lines
    }

    fn prebuilt_lines(findings: &[(String, String, Level)]) -> Vec<String> {
        let mut lines: Vec<String> = findings
            .iter()
            .filter(|(n, _, l)| n == "prebuilt-binary-in-sources" && *l == Level::Warning)
            .map(|(_, line, _)| line.clone())
            .collect();
        lines.sort();
        lines
    }

    #[test]
    fn prebuilt_binaries_in_tarball_emit_through_dispatch() {
        let inner = tarball(&[("nested/prebuilt2.o", ELF)]);
        let jar = zip_bytes(&[("com/example/Foo.class", CLASS)]);
        let tar = tarball(&[
            ("src/prebuilt.o", ELF),
            ("src/Foo.class", CLASS),
            ("src/mod.pyc", PYC),
            ("lib/nested.jar", &jar),
            ("deep/inner.tar.gz", &gzip_bytes(&inner)),
            ("src/main.c", b"int main(void) { return 0; }\n"),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("prebuilt-test-1.0.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        // Pinned output contract: every finding line content, byte-exact
        // (order asserted sorted - the helper sorts before comparing).
        assert_eq!(
            prebuilt_lines(&findings),
            [
                "prebuilt-test.src: W: prebuilt-binary-in-sources \
                 prebuilt-test-1.0.tar.gz: deep/inner.tar.gz: nested/prebuilt2.o ELF binary",
                "prebuilt-test.src: W: prebuilt-binary-in-sources \
                 prebuilt-test-1.0.tar.gz: lib/nested.jar Java archive (jar)",
                "prebuilt-test.src: W: prebuilt-binary-in-sources \
                 prebuilt-test-1.0.tar.gz: src/Foo.class Java class file",
                "prebuilt-test.src: W: prebuilt-binary-in-sources \
                 prebuilt-test-1.0.tar.gz: src/mod.pyc Python bytecode",
                "prebuilt-test.src: W: prebuilt-binary-in-sources \
                 prebuilt-test-1.0.tar.gz: src/prebuilt.o ELF binary",
            ]
        );
    }

    #[test]
    fn setbadness_in_a_payload_rpmlintrc_fires_per_occurrence() {
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            (
                "prebuilt-test-rpmlintrc",
                b"# setBadness in a comment stays quiet\naddFilter('some-check')\nsetBadness('first-check', 0)\n  setBadness('second-check', 10)\n"
                    .to_vec(),
            ),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            setbadness_lines(&findings),
            [
                "prebuilt-test.src: W: rpmlintrc-uses-setbadness \
                 prebuilt-test-rpmlintrc line 3: setBadness('first-check', 0)",
                "prebuilt-test.src: W: rpmlintrc-uses-setbadness \
                 prebuilt-test-rpmlintrc line 4: setBadness('second-check', 10)",
            ]
        );
    }

    #[test]
    fn setbadness_payload_scan_is_quiet_without_the_directive() {
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            (
                "prebuilt-test.rpmlintrc",
                b"# mentions setBadness only in prose\naddFilter('setBadness')\n".to_vec(),
            ),
            (
                "notes.txt",
                b"setBadness('not-in-an-rpmlintrc', 0)\n".to_vec(),
            ),
        ]);
        let findings = run_source(&pkg);
        assert!(setbadness_lines(&findings).is_empty(), "all: {findings:?}");
    }

    #[test]
    fn setbadness_payload_scan_skips_a_name_already_loaded() {
        // The load path reports a loaded rpmlintrc's occurrences, so a
        // payload file of the same name is not reported a second time;
        // a differently named payload file still fires.
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            (
                "loaded-rpmlintrc",
                b"setBadness('loaded-check', 0)\n".to_vec(),
            ),
            (
                "payload-rpmlintrc",
                b"setBadness('payload-check', 0)\n".to_vec(),
            ),
        ]);
        let mut config = test_config();
        config.rpmlintrc_display = vec!["/some/dir/loaded-rpmlintrc".to_string()];
        let findings = run_source_with_config(&pkg, &config);
        assert_eq!(
            setbadness_lines(&findings),
            ["prebuilt-test.src: W: rpmlintrc-uses-setbadness \
              payload-rpmlintrc line 1: setBadness('payload-check', 0)"]
        );
    }

    #[test]
    fn prebuilt_clean_sources_are_silent() {
        let tar = tarball(&[
            ("src/main.c", b"int main(void) { return 0; }\n"),
            ("src/util.h", b"#pragma once\n"),
            ("README", b"hello\n"),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("prebuilt-test-1.0.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert!(prebuilt_lines(&findings).is_empty(), "all: {findings:?}");
    }

    #[test]
    fn prebuilt_direct_object_in_srpm_is_flagged() {
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("prebuilt.o", ELF.to_vec()),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            ["prebuilt-test.src: W: prebuilt-binary-in-sources prebuilt.o ELF binary"]
        );
    }

    #[test]
    fn prebuilt_pyc_magic_without_name_is_silent() {
        // bytes 2-3 are \r\n in every CPython version, but so are the
        // first bytes of any CRLF text file: the .pyc/.pyo name is required.
        let tar = tarball(&[("notes.txt", b"ab\r\nnot bytecode\n")]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("prebuilt-test-1.0.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert!(prebuilt_lines(&findings).is_empty(), "all: {findings:?}");
    }

    fn bzip2_bytes(data: &[u8]) -> Vec<u8> {
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn prebuilt_bzip2_tarball_is_walked() {
        let tar = tarball(&[("src/prebuilt.o", ELF)]);
        let bz2 = bzip2_bytes(&tar);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("prebuilt-test-1.0.tar.bz2", bz2),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            ["prebuilt-test.src: W: prebuilt-binary-in-sources \
              prebuilt-test-1.0.tar.bz2: src/prebuilt.o ELF binary"]
        );
    }

    #[test]
    fn prebuilt_unit_bzip2_tar_is_walked() {
        // Decoder-level pin, without the source-package plumbing:
        // a bzip2 tarball fed straight to the walker is decompressed
        // and its prebuilt entries are reported.
        use super::prebuilt::{BinaryKind, inspect_entry};
        let tar = tarball(&[("src/prebuilt.o", ELF)]);
        let bz2 = bzip2_bytes(&tar);
        let mut hits = Vec::new();
        inspect_entry("t.tar.bz2", &bz2, "t.tar.bz2", 0, &mut hits);
        assert_eq!(
            hits,
            [(BinaryKind::Elf, "t.tar.bz2: src/prebuilt.o".to_string())]
        );
    }

    #[test]
    fn prebuilt_corrupt_bzip2_archive_skipped_silently() {
        // A valid bzip2 header over a corrupt body: the decoder
        // fails, so the archive is skipped, not misread and not
        // a panic.
        let tar = tarball(&[("src/prebuilt.o", ELF)]);
        let mut bz2 = b"BZh91".to_vec();
        bz2.extend_from_slice(&tar);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("prebuilt-test-1.0.tar.bz2", bz2),
        ]);
        let findings = run_source(&pkg);
        assert!(prebuilt_lines(&findings).is_empty(), "all: {findings:?}");
    }

    #[test]
    fn prebuilt_invalid_bzip2_magic_is_skipped() {
        // The 4th magic byte must be the block-size digit: a stream
        // starting BZhx is not bzip2, whatever follows it.
        use super::prebuilt::inspect_entry;
        let tar = tarball(&[("src/prebuilt.o", ELF)]);
        let mut fake = b"BZhx".to_vec();
        fake.extend_from_slice(&tar);
        let mut hits = Vec::new();
        inspect_entry("t.tar.bz2", &fake, "t.tar.bz2", 0, &mut hits);
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn prebuilt_corrupt_tar_does_not_panic() {
        let mut bad = vec![0u8; 1024];
        bad[257..262].copy_from_slice(b"ustar");
        bad[124..136].copy_from_slice(b"not-octal!!!"); // corrupt size
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("prebuilt-test-1.0.tar", bad),
        ]);
        let findings = run_source(&pkg);
        assert!(prebuilt_lines(&findings).is_empty(), "all: {findings:?}");
    }

    #[test]
    fn prebuilt_nesting_depth_is_bounded() {
        // Seven nested tars with an ELF at the bottom: past the depth limit,
        // so silent (and terminating).
        let mut data = ELF.to_vec();
        for i in 0..7 {
            data = tarball(&[(format!("level{i}.tar").as_str(), &data)]);
        }
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("prebuilt-test-1.0.tar", data),
        ]);
        let findings = run_source(&pkg);
        assert!(prebuilt_lines(&findings).is_empty(), "all: {findings:?}");
    }

    #[test]
    fn prebuilt_jar_does_not_list_classes_inside() {
        // The jar is the actionable unit; classes inside are not findings.
        let jar = zip_bytes(&[
            ("com/example/A.class", CLASS),
            ("com/example/B.class", CLASS),
        ]);
        let tar = tarball(&[("lib/app.jar", &jar)]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("prebuilt-test-1.0.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            ["prebuilt-test.src: W: prebuilt-binary-in-sources \
              prebuilt-test-1.0.tar.gz: lib/app.jar Java archive (jar)"]
        );
    }

    #[test]
    fn prebuilt_non_jar_zip_is_walked() {
        // A plain zip (not a jar) is walked for prebuilt entries.
        let z = zip_bytes(&[("payload.o", ELF), ("readme.txt", b"hi\n")]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("sources.zip", z),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            ["prebuilt-test.src: W: prebuilt-binary-in-sources sources.zip: payload.o ELF binary"]
        );
    }

    #[test]
    fn prebuilt_xz_tarball_is_walked() {
        let tar = tarball(&[("src/prebuilt.o", ELF)]);
        let mut xz = Vec::new();
        {
            use liblzma::write::XzEncoder;
            let mut enc = XzEncoder::new(&mut xz, 6);
            enc.write_all(&tar).unwrap();
            enc.finish().unwrap();
        }
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("prebuilt-test-1.0.tar.xz", xz),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            ["prebuilt-test.src: W: prebuilt-binary-in-sources \
              prebuilt-test-1.0.tar.xz: src/prebuilt.o ELF binary"]
        );
    }

    #[test]
    fn prebuilt_zstd_tarball_is_walked() {
        let tar = tarball(&[("src/prebuilt.o", ELF)]);
        let zst = zstd::encode_all(&tar[..], 3).expect("zstd compress");
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test".to_vec()),
            ("prebuilt-test-1.0.tar.zst", zst),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            [
                "prebuilt-test.src: W: prebuilt-binary-in-sources prebuilt-test-1.0.tar.zst: src/prebuilt.o ELF binary"
            ]
        );
    }

    #[test]
    fn prebuilt_unit_classify() {
        use super::prebuilt::{BinaryKind, inspect_entry};
        let mut hits = Vec::new();
        inspect_entry("a.o", ELF, "a.o", 0, &mut hits);
        assert_eq!(hits, [(BinaryKind::Elf, "a.o".to_string())]);
        hits.clear();
        inspect_entry("A.class", CLASS, "A.class", 0, &mut hits);
        assert_eq!(hits, [(BinaryKind::JavaClass, "A.class".to_string())]);
        hits.clear();
        inspect_entry("m.pyc", PYC, "m.pyc", 0, &mut hits);
        assert_eq!(hits, [(BinaryKind::PythonBytecode, "m.pyc".to_string())]);
        // .pyo shares the pyc format.
        hits.clear();
        inspect_entry("m.pyo", PYC, "m.pyo", 0, &mut hits);
        assert_eq!(hits, [(BinaryKind::PythonBytecode, "m.pyo".to_string())]);
        // Text is never a binary, whatever its head bytes.
        hits.clear();
        inspect_entry("t.txt", b"ab\r\ncd", "t.txt", 0, &mut hits);
        assert!(hits.is_empty());
        // A zip that is not a jar is walked, not flagged.
        hits.clear();
        inspect_entry("a.zip", b"PK\x03\x04garbage", "a.zip", 0, &mut hits);
        assert!(hits.is_empty());
    }

    #[test]
    fn prebuilt_unit_tar_reader() {
        // A tar with a directory entry before the regular file: the dir
        // entry is skipped, the file is reported.
        let mut tar = tarball(&[("src/prebuilt.o", ELF)]);
        let mut dir_hdr = [0u8; 512];
        dir_hdr[..4].copy_from_slice(b"src/");
        dir_hdr[156] = b'5';
        dir_hdr[257..262].copy_from_slice(b"ustar");
        let at = tar.len() - 1024; // before the end-of-archive zero blocks
        tar.splice(at..at, dir_hdr.iter().cloned());
        let mut hits = Vec::new();
        super::prebuilt::inspect_entry("t.tar", &tar, "t.tar", 0, &mut hits);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].1.ends_with("src/prebuilt.o"));
    }

    const LFS_POINTER: &[u8] =
        b"version https://git-lfs.github.com/spec/v1\noid sha256:0123456789abcdef\nsize 4242\n";
    const LFS_POINTER_LEGACY: &[u8] =
        b"version https://hawser.github.com/spec/v1\noid sha256:0123456789abcdef\nsize 4242\n";

    fn spec_with_source(source: &str) -> Vec<u8> {
        format!(
            "Name: prebuilt-test\nVersion: 1.0\nRelease: 1\nSummary: test package\nLicense: MIT\nSource0: {source}\n\n%description\ntest package\n"
        )
        .into_bytes()
    }

    fn archive_lines(findings: &[(String, String, Level)], tag: &str) -> Vec<String> {
        let mut lines: Vec<String> = findings
            .iter()
            .filter(|(n, _, l)| n == tag && *l == Level::Warning)
            .map(|(_, line, _)| line.clone())
            .collect();
        lines.sort();
        lines
    }

    #[test]
    fn vcs_metadata_in_url_less_source_fires_per_root() {
        let tar = tarball(&[
            ("pkg-1.0/.git/config", b"x"),
            ("pkg-1.0/.git/objects/ab/cdef", b"yy"),
            ("pkg-1.0/CVS/Entries", b"eee"),
            ("pkg-1.0/src/main.c", b"int main(void) { return 0; }\n"),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", spec_with_source("vcs-1.0.tar.gz")),
            ("vcs-1.0.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            archive_lines(&findings, "source-archive-contains-vcs-metadata"),
            [
                "prebuilt-test.src: W: source-archive-contains-vcs-metadata \
                 vcs-1.0.tar.gz pkg-1.0/.git 2 entries 3 bytes",
                "prebuilt-test.src: W: source-archive-contains-vcs-metadata \
                 vcs-1.0.tar.gz pkg-1.0/CVS 1 entries 3 bytes",
            ]
        );
    }

    #[test]
    fn vcs_metadata_in_url_source_stays_quiet_but_lfs_fires() {
        let tar = tarball(&[
            ("pkg-1.0/.git/config", b"x"),
            ("tests/a.test.xz", LFS_POINTER),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            (
                "prebuilt-test.spec",
                spec_with_source("https://example.com/vcs-1.0.tar.gz"),
            ),
            ("vcs-1.0.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert!(
            archive_lines(&findings, "source-archive-contains-vcs-metadata").is_empty(),
            "{findings:?}"
        );
        assert_eq!(
            archive_lines(&findings, "source-archive-contains-lfs-pointer"),
            ["prebuilt-test.src: W: source-archive-contains-lfs-pointer \
              vcs-1.0.tar.gz: tests/a.test.xz"]
        );
    }

    #[test]
    fn lfs_pointers_fire_and_lookalikes_stay_quiet() {
        let mut big = LFS_POINTER.to_vec();
        big.resize(1500, b' ');
        let tar = tarball(&[
            ("tests/a.test.xz", LFS_POINTER),
            ("tests/b.test.xz", LFS_POINTER_LEGACY),
            (
                "docs/quote.txt",
                b"see: version https://git-lfs.github.com/spec/v1\noid sha256:0123\n",
            ),
            ("tests/empty", b""),
            ("tests/big.test.xz", &big),
            (
                "tests/no-oid",
                b"version https://git-lfs.github.com/spec/v1\nsize 12\n",
            ),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", spec_with_source("lfs-1.0.tar.gz")),
            ("lfs-1.0.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            archive_lines(&findings, "source-archive-contains-lfs-pointer"),
            [
                "prebuilt-test.src: W: source-archive-contains-lfs-pointer \
                 lfs-1.0.tar.gz: tests/a.test.xz",
                "prebuilt-test.src: W: source-archive-contains-lfs-pointer \
                 lfs-1.0.tar.gz: tests/b.test.xz",
            ]
        );
    }

    #[test]
    fn vcs_lookalikes_and_nested_archives_stay_quiet() {
        let nested_zip = zip_bytes(&[("r/.git/config", b"x")]);
        let nested_tar = tarball(&[(".git/config", b"x")]);
        let tar = tarball(&[
            ("pkg/.gitignore", b"x"),
            ("pkg/.gitattributes", b"x"),
            ("pkg/.gitmodules", b"x"),
            ("pkg/.github/workflows/ci.yml", b"x"),
            ("pkg/sub/.git", b"x"),
            ("pkg/git/notes.txt", b"x"),
            ("pkg/bare.git/config", b"x"),
            ("pkg/CVS/Entries/Log", b"x"),
            ("pkg/RCS/foo,v", b"x"),
            ("pkg/nested.zip", &nested_zip),
            ("pkg/nested.tar", &nested_tar),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", spec_with_source("near-1.0.tar.gz")),
            ("near-1.0.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert!(
            archive_lines(&findings, "source-archive-contains-vcs-metadata").is_empty(),
            "{findings:?}"
        );
        assert!(
            archive_lines(&findings, "source-archive-contains-lfs-pointer").is_empty(),
            "{findings:?}"
        );
    }

    #[test]
    fn vcs_metadata_in_zip_source_fires() {
        let z = zip_bytes(&[("pkg/.svn/entries", b"svn"), ("pkg/readme", b"hi")]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", spec_with_source("vcs-1.0.zip")),
            ("vcs-1.0.zip", z),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            archive_lines(&findings, "source-archive-contains-vcs-metadata"),
            [
                "prebuilt-test.src: W: source-archive-contains-vcs-metadata \
              vcs-1.0.zip pkg/.svn 1 entries 3 bytes"
            ]
        );
    }

    #[test]
    fn top_level_member_predicates_pin() {
        let tar = tarball(&[
            ("a/.git/config", b"xx"),
            ("a/CVS/Entries", b"e"),
            ("a/.gitignore", b"i"),
        ]);
        let members = super::prebuilt::top_level_members(&tar);
        let roots = super::prebuilt::vcs_roots(&members);
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].root, "a/.git");
        assert_eq!((roots[0].entries, roots[0].bytes), (1, 2));
        assert_eq!(roots[1].root, "a/CVS");
        assert_eq!((roots[1].entries, roots[1].bytes), (1, 1));
        assert!(super::prebuilt::lfs_pointers(&members).is_empty());
    }
}
