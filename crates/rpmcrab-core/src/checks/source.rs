//! `SourceCheck` — validate the files in a source package.
//!
//! Ported from `rpmlint/checks/SourceCheck.py`. Findings:
//! `inconsistent-file-extension`, `strange-permission` and
//! `source-not-compressed` (warnings), plus the rpmcrab-new archive
//! content warnings `prebuilt-binary-in-sources`,
//! `source-archive-contains-vcs-metadata`,
//! `source-archive-contains-lfs-pointer` and
//! `source-archive-contains-bidi-control`.
//!
//! `prebuilt-binary-in-sources` is rpmcrab-new (upstream rpmlint#4, still
//! open): the reference never unpacks source archives.
//!
//! `rpmlintrc-uses-setbadness` is rpmcrab-new as well: an rpmlintrc file
//! carried in the source package is scanned for `setBadness` lines, the
//! same predicate the rpmlintrc load path records.

use fancy_regex::Regex;

use crate::check::{Check, add_info, make_finding};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::{PkgFile, is_reg};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::checks::shared::{binary_source_key, is_ghost_file, source_package_keys};

pub struct SourceCheck {
    compress_ext: String,
    valid_src_perms: Vec<u128>,
    ext_magic: Vec<(String, String, Regex)>,
    shipped: ShippedState,
}

/// One source copy behind a digest: what the shipped file is, where it
/// comes from, and whether every directory in its path chain is a test
/// directory (the test-data quieting judges copies, not digests).
#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceRecord {
    kind: String,
    display: String,
    test: bool,
}

/// One binary payload file that could match a source record: its digest
/// (the header digest when FILEDIGESTALGO is 8, else a sha256 computed
/// over the file), its payload path, and the package and arch that ship
/// it, so `after_checks` can name the reporting package.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BinaryRecord {
    digest: String,
    path: String,
    pkg_name: String,
    arch: String,
}

/// Run-scoped state for `prebuilt-binary-shipped`: source records keyed
/// by source-package spelling and digest, and binary records in lint
/// order. Moved whole by `export_state` / `import_state` like
/// `CMakeConfigCheck`'s state.
#[derive(Default)]
struct ShippedState {
    sources: HashMap<String, HashMap<String, Vec<SourceRecord>>>,
    binaries: Vec<(String, BinaryRecord)>,
}

/// Whether any directory component of a display path chain is a test
/// directory: the chain joins members with `": "`, so it is split on
/// both separators, and only non-final components count -- a file named
/// `test` is not a test directory.
fn is_test_path(path: &str) -> bool {
    let flat = path.replace(": ", "/");
    let parts: Vec<&str> = flat.split('/').collect();
    parts[..parts.len().saturating_sub(1)]
        .iter()
        .any(|c| matches!(*c, "test" | "tests" | "testdata"))
}

/// The kind string of an archive record: the archive holds `n` hits.
fn archive_kind(n: usize) -> String {
    if n == 1 {
        "archive with 1 hit".to_string()
    } else {
        format!("archive with {n} hits")
    }
}

/// Hex sha256 of `data`.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

/// Hex sha256 of a file's bytes, or `None` when it cannot be read.
fn sha256_file(path: &str) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )
}

/// The digest a binary payload file joins on: the header digest when
/// FILEDIGESTALGO is 8, else a sha256 computed over the file (a header
/// digest under any other algorithm cannot join with sha256 source
/// records). `None` when the file cannot be hashed.
fn binary_digest(algo_is_8: bool, md5: &str, path: &str) -> Option<String> {
    if algo_is_8 {
        return Some(md5.to_string());
    }
    sha256_file(path)
}

/// Whether a payload file's first 512 bytes could match a source
/// record: a hit-kind header, a `.pyc`/`.pyo` name, or a compression
/// or ustar header the source walk opens. The bytes are read from the
/// file itself, never trusted from the header: rpmcrab clears the
/// magic of compressed files.
fn payload_could_match(name: &str, head: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".pyc") || lower.ends_with(".pyo") {
        return true;
    }
    if head.starts_with(b"\x7fELF")
        || head.starts_with(b"\xca\xfe\xba\xbe")
        || head.starts_with(b"PK\x03\x04")
        || head.starts_with(b"!<arch>\n")
        || head.starts_with(b"!<thin>\n")
        || head.starts_with(b"MZ")
        || head.starts_with(b"\0asm")
        || head.starts_with(b"\xfe\xed\xfa\xce")
        || head.starts_with(b"\xfe\xed\xfa\xcf")
        || head.starts_with(b"\xce\xfa\xed\xfe")
        || head.starts_with(b"\xcf\xfa\xed\xfe")
        || head.starts_with(b"\xed\xab\xee\xdb")
        || head.starts_with(b"\x1f\x8b")
        || head.starts_with(b"\xfd7zXZ\x00")
        || head.starts_with(b"\x28\xb5\x2f\xfd")
        || head.starts_with(b"BZh")
    {
        return true;
    }
    head.len() >= 262 && &head[257..262] == b"ustar"
}

/// Record one source file's walk for the run-scoped join: every hit
/// member, every nested archive holding hits, and the top-level Source
/// itself when it holds hits without being a hit itself (a bare binary
/// Source needs no second record: the hit already covers its bytes).
/// Records land under every spelling of the source package, so a
/// binary's `SOURCERPM` joins whichever spelling it carries.
fn record_shipped_source(
    state: &mut ShippedState,
    pkg: &Pkg,
    f: &PkgFile,
    hits: &[prebuilt::Hit],
    archives: &[prebuilt::ArchiveHits],
) {
    if hits.is_empty() {
        return;
    }
    let self_hit = hits.iter().any(|h| h.path == f.name);
    let mut by_digest: HashMap<String, Vec<SourceRecord>> = HashMap::new();
    for h in hits {
        by_digest
            .entry(h.sha256.clone())
            .or_default()
            .push(SourceRecord {
                kind: h.kind.as_str().to_string(),
                display: h.path.clone(),
                test: is_test_path(&h.path),
            });
    }
    for a in archives {
        by_digest
            .entry(a.sha256.clone())
            .or_default()
            .push(SourceRecord {
                kind: archive_kind(a.hits),
                display: a.path.clone(),
                test: is_test_path(&a.path),
            });
    }
    if !self_hit {
        // The whole-file record: the header digest when
        // FILEDIGESTALGO is 8, else a streamed sha256 of the file —
        // but only up to the old 256 MiB whole-file cap, so a large
        // streamed Source costs no extra full read; its member hits
        // still join, only the whole-file record is missing.
        let digest = match (pkg.tag_i64(librpm::Tag::FILEDIGESTALGO), f.md5.as_ref()) {
            (Some(8), Some(md5)) if !md5.is_empty() => Some(md5.clone()),
            _ => {
                let capped = std::fs::metadata(&f.path)
                    .map(|m| m.len() <= prebuilt::MAX_ARCHIVE_BYTES as u64)
                    .unwrap_or(false);
                if capped { sha256_file(&f.path) } else { None }
            }
        };
        if let Some(digest) = digest {
            by_digest.entry(digest).or_default().push(SourceRecord {
                kind: archive_kind(hits.len()),
                display: f.name.clone(),
                test: false,
            });
        }
    }
    for key in source_package_keys(pkg) {
        let entry = state.sources.entry(key).or_default();
        for (digest, recs) in &by_digest {
            entry
                .entry(digest.clone())
                .or_default()
                .extend(recs.iter().cloned());
        }
    }
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
             every warning, this one can be filtered out in the configuration. \
             A vendor archive the packager generates (cargo vendor, node_modules) \
             is not an upstream archive: leave the binaries out when generating it."
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
            shipped: ShippedState::default(),
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
    /// `^\s*setBadness`, one warning per occurrence. Files are keyed
    /// by full path, not basename: a payload file that was itself
    /// loaded for this run is skipped -- the load path reports its
    /// occurrences -- but a different file that merely shares the
    /// basename (a loaded file elsewhere, or another payload file
    /// in a different directory) does not shadow it, and each file
    /// is scanned only once, so the same directive file is never
    /// reported twice.
    fn check_rpmlintrc_setbadness(&self, pkg: &Pkg, config: &Config, out: &mut Filter) {
        let loaded: std::collections::HashSet<&str> = config
            .rpmlintrc_display
            .iter()
            .map(String::as_str)
            .collect();
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for f in &pkg.files {
            let name = f.name.rsplit('/').next().unwrap_or(f.name.as_str());
            if !name.ends_with("rpmlintrc")
                || loaded.contains(f.path.as_str())
                || !seen.insert(f.path.as_str())
            {
                continue;
            }
            let Ok(bytes) = std::fs::read(&f.path) else {
                continue;
            };
            let text = String::from_utf8_lossy(&bytes);
            for (line_no, line) in crate::config::setbadness_occurrences(&text) {
                let detail = format!("{} line {line_no}: {line}", f.name);
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
    /// `kind = "behaviour"`: a payload file in a source package is a
    /// source archive in its own right, but a declared Source that is
    /// also part of the payload (the spec's own tarball, or a source
    /// the build copies into the payload) must not fire twice. Each
    /// payload file is read once here and the bytes are shared with
    /// the bidi pass below.
    fn check_source_archives(&mut self, pkg: &Pkg, out: &mut Filter) {
        let url_sources = source_url_files(pkg);
        // One finding-cap state per source package (issue #1387):
        // every payload file of the package shares it.
        let mut caps = prebuilt::CapState::new();
        for f in &pkg.files {
            let mut walker = prebuilt::Walker::new(&mut caps, !url_sources.contains(&f.name));
            walker.walk_file(std::path::Path::new(&f.path), &f.name);
            let outcome = walker.take_outcome();
            // The run-scoped shipped join (issue #1389): the walk's
            // hits and nested-archive records join by digest, like
            // the old whole-file walk recorded them.
            record_shipped_source(
                &mut self.shipped,
                pkg,
                f,
                &outcome.shipped,
                &outcome.archives,
            );
            // Grouped kinds (ar, PE, wasm) collapse per archive chain
            // (the full outer:inner chain, not the top-level archive alone),
            // directory and kind; every other hit keeps
            // its per-member line, as do bare Sources, which have no
            // archive chain.
            let mut groups: Vec<(String, String, prebuilt::BinaryKind, usize, String)> = Vec::new();
            for (kind, path) in &outcome.prebuilt {
                let kind = *kind;
                if !kind.grouped() {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "prebuilt-binary-in-sources",
                        &[path, kind.as_str()],
                    );
                    continue;
                }
                let Some((archive, member)) = path.rsplit_once(": ") else {
                    // Bare Source: no archive chain, never grouped.
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "prebuilt-binary-in-sources",
                        &[path, kind.as_str()],
                    );
                    continue;
                };
                let archive = archive.to_string();
                let dir = match member.rfind('/') {
                    Some(i) => member[..i].to_string(),
                    None => String::new(),
                };
                match groups
                    .iter_mut()
                    .find(|(a, d, k, _, _)| *a == archive && *d == dir && *k == kind)
                {
                    Some(g) => g.3 += 1,
                    None => groups.push((archive, dir, kind, 1, path.clone())),
                }
            }
            for (archive, dir, kind, count, first_path) in groups {
                if count == 1 {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "prebuilt-binary-in-sources",
                        &[&first_path, kind.as_str()],
                    );
                } else {
                    let path = if dir.is_empty() {
                        format!("{archive}: *")
                    } else {
                        format!("{archive}: {dir}/*")
                    };
                    let label = format!("{} ({count} files)", kind.as_str());
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "prebuilt-binary-in-sources",
                        &[&path, &label],
                    );
                }
            }
            for (root, (entries, bytes)) in &outcome.vcs {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "source-archive-contains-vcs-metadata",
                    &[
                        &f.name,
                        root,
                        &format!("{entries} entries"),
                        &format!("{bytes} bytes"),
                    ],
                );
            }
            for name in &outcome.lfs {
                let path = format!("{}: {}", f.name, name);
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "source-archive-contains-lfs-pointer",
                    &[&path],
                );
            }
            for hit in &outcome.bidi {
                let detail = format!(
                    "{} line {}, column {} {}",
                    hit.path, hit.line, hit.column, hit.control
                );
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "source-archive-contains-bidi-control",
                    &[&detail],
                );
            }
            // Skips are never silent (issue #1387): every recorded
            // stop is logged, in the manner of pkg/extract.rs.
            for line in outcome.stops.lines() {
                tracing::warn!("sourcecheck: {}: {}", f.name, line);
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
/// Prebuilt-binary detection inside source archives (issue #150).
///
/// The walker is deliberately small: magic-byte archive detection, a minimal
/// ustar reader, and streaming decompression.
///
/// Scope choices: only ustar tarballs are recognized - pre-POSIX V7 format
/// has no magic bytes and is skipped - and of the zip-based Java archives
/// only `.jar` is reported as a unit; `.war`/`.ear`/`.aar` are walked like
/// plain zips, their classes listed individually.
///
/// Size handling (issue #1387): a top-level Source is streamed, never held
/// whole. A fixed decompression budget per Source replaces the old 256 MiB
/// whole-archive cap; a zip Source over 256 MiB on disk is still skipped,
/// now with a warning. A member over 64 MiB is read through, not buffered:
/// it counts toward version-control totals at its declared size and its
/// head goes through the git-lfs test, but it is not classified, not
/// scanned for bidi controls and not opened as a nested archive. A zip
/// entry's declared size is never trusted for that decision: an entry
/// declared over the cap over small actual content is visited for bidi
/// only, since the old bidi walk saw through the lie and the old
/// prebuilt walk did not.
mod prebuilt {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::io::{self, Read, Seek, SeekFrom};
    use std::rc::Rc;

    /// On-disk limit kept for zip Sources only (issue #1387): a zip needs
    /// `Seek`, so it cannot stream, and a zip over this size is skipped
    /// with a warning instead of being opened.
    pub const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
    /// Cap on one archive entry's bytes: a member up to this size is
    /// buffered; a larger one is read through (see the module doc).
    const MAX_ENTRY_BYTES: usize = 64 * 1024 * 1024;
    /// Nesting limit for archives inside archives: the top-level archive
    /// is depth 0, and an archive nested inside a depth-3 archive is the
    /// deepest one opened, so five levels are walked in all.
    const MAX_DEPTH: u8 = 5;
    /// Decompression budget per top-level Source (issue #1387): bytes
    /// read from a stream, decompressed or from a plain tar, counted
    /// over all nesting levels. Above the largest Factory Source
    /// measured (nodejs-electron, about 5.4 GiB decompressed).
    const DECOMPRESS_BUDGET_BYTES: u64 = 16 * 1024 * 1024 * 1024;
    /// Findings kept per tag per source package (issue #1387): past
    /// this the walk stops recording for that tag and logs the stop.
    const FINDING_CAP: usize = 25_000;
    /// LZMA decoder memory limit (issue #1387), matching zstd's window.
    const XZ_MEMLIMIT_BYTES: u64 = 128 * 1024 * 1024;
    /// Skip-log lines kept per Source per kind (issue #1387); past
    /// that one closing line gives the count.
    const LOG_LINES_PER_KIND: usize = 10;
    /// Detail paths stored in findings are cut to this many bytes
    /// (issue #1387), with a trailing ellipsis.
    const DETAIL_PATH_LIMIT: usize = 1024;
    /// Bytes of a member's head kept for the git-lfs test.
    const HEAD_BYTES: usize = 1024;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum BinaryKind {
        Elf,
        JavaClass,
        PythonBytecode,
        JavaArchive,
        Ar,
        Pe,
        Wasm,
    }

    impl BinaryKind {
        pub fn as_str(self) -> &'static str {
            match self {
                BinaryKind::Elf => "ELF binary",
                BinaryKind::JavaClass => "Java class file",
                BinaryKind::PythonBytecode => "Python bytecode",
                BinaryKind::JavaArchive => "Java archive (jar)",
                BinaryKind::Ar => "ar archive",
                BinaryKind::Pe => "PE executable or DLL",
                BinaryKind::Wasm => "WebAssembly module",
            }
        }

        /// Whether findings of this kind are grouped per archive,
        /// directory and kind (the #1388 kinds only); every other
        /// kind keeps one finding per member.
        pub fn grouped(self) -> bool {
            matches!(self, BinaryKind::Ar | BinaryKind::Pe | BinaryKind::Wasm)
        }
    }

    /// One prebuilt binary found by the walk: its kind, its display path
    /// (the member chain as `prebuilt-binary-in-sources` prints it), and
    /// the sha256 of the member's bytes, so the run-scoped join can tell
    /// whether a shipped file is byte-identical to it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Hit {
        pub kind: BinaryKind,
        pub path: String,
        pub sha256: String,
    }

    /// A nested archive that holds at least one hit: the sha256 of the
    /// archive member's bytes, how many hits it holds, and its display
    /// path in the member chain.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ArchiveHits {
        pub sha256: String,
        pub hits: usize,
        pub path: String,
    }

    /// Magic-byte classification of one file's bytes. ELF and Java class
    /// magics are unambiguous; Python bytecode needs its `.pyc`/`.pyo` name
    /// too (bytes 2-3 are `\r\n` in every CPython version, but so are the
    /// first bytes of any CRLF text file); a jar is a zip archive by
    /// definition, so it needs the `.jar` name as well. An ar archive
    /// needs a linker symbol index as its first member (thin and
    /// index-less archives stay quiet); a PE image needs `MZ` plus the
    /// `PE` signature at an in-bounds `e_lfanew`; a WebAssembly module
    /// needs the version-1 magic (components and other versions stay
    /// quiet). None of the three needs a name gate.
    /// Whether `data` is an ar archive carrying a linker symbol index
    /// as its first member: `/`, `/SYM64/`, `__.SYMDEF` or
    /// `__.SYMDEF SORTED`. The first member header's terminator is
    /// required, so text starting with the ar magic stays quiet; thin
    /// archives (`!<thin>`) never reach this test.
    /// An indexed ar archive is reported as a unit: its members are
    /// never walked, so an inner ELF stays silent.
    fn ar_indexed(data: &[u8]) -> bool {
        if !data.starts_with(b"!<arch>\n") || data.len() < 68 {
            return false;
        }
        if &data[66..68] != b"`\n" {
            return false;
        }
        let name = match std::str::from_utf8(&data[8..24]) {
            Ok(n) => n.trim_end_matches(' '),
            Err(_) => return false,
        };
        matches!(name, "/" | "/SYM64/" | "__.SYMDEF" | "__.SYMDEF SORTED")
    }

    /// Whether `data` is a PE image: `MZ`, at least 64 bytes so the
    /// `e_lfanew` field exists, and `PE\0\0` at an in-bounds `e_lfanew`.
    fn is_pe(data: &[u8]) -> bool {
        if data.len() < 64 || !data.starts_with(b"MZ") {
            return false;
        }
        let off = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        match off.checked_add(4) {
            Some(end) if end <= data.len() => &data[off..off + 4] == b"PE\0\0",
            _ => false,
        }
    }

    fn classify(name: &str, data: &[u8]) -> Option<BinaryKind> {
        if data.starts_with(b"\x7fELF") {
            return Some(BinaryKind::Elf);
        }
        if data.starts_with(b"\xca\xfe\xba\xbe") {
            return Some(BinaryKind::JavaClass);
        }
        if ar_indexed(data) {
            return Some(BinaryKind::Ar);
        }
        if is_pe(data) {
            return Some(BinaryKind::Pe);
        }
        if data.starts_with(b"\0asm\x01\0\0\0") {
            return Some(BinaryKind::Wasm);
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

    /// Walker limits (issue #1387): the budget and the finding cap are
    /// arguments, so tests pass small ones.
    struct Limits {
        finding_cap: usize,
    }

    impl Limits {
        fn production() -> Self {
            Limits {
                finding_cap: FINDING_CAP,
            }
        }
    }

    /// Per-tag finding caps for one source package (issue #1387). One
    /// instance is shared across all payload files of the package; once
    /// a tag reaches the cap the walk stops recording for it. The
    /// version-control root count is shared the same way: a root that
    /// appears in several Sources is a finding per Source, so each
    /// Source's new root consumes the cap.
    pub struct CapState {
        prebuilt: usize,
        vcs_roots: usize,
        lfs: usize,
        bidi: usize,
        prebuilt_tripped: bool,
        vcs_tripped: bool,
        lfs_tripped: bool,
        bidi_tripped: bool,
    }

    impl CapState {
        pub fn new() -> Self {
            CapState {
                prebuilt: 0,
                vcs_roots: 0,
                lfs: 0,
                bidi: 0,
                prebuilt_tripped: false,
                vcs_tripped: false,
                lfs_tripped: false,
                bidi_tripped: false,
            }
        }
    }

    /// Decompression budget shared with the counting readers (issue
    /// #1387): bytes left, plus whether a read already hit the end of
    /// it. The flag distinguishes a budget stop from a genuinely
    /// truncated stream, which ends the walk silently like today.
    struct BudgetState {
        left: u64,
        hit: bool,
        memlimit_hit: bool,
    }

    /// A reader that counts every byte toward the walk's budget and
    /// reports end-of-stream once the budget is spent. It wraps decoder
    /// outputs and top-level plain-tar streams only: buffer re-reads
    /// and zip metadata are not new bytes and are not counted, while
    /// zip entry bytes are charged by hand in the zip walk.
    struct CountingReader<R: Read> {
        inner: R,
        budget: Rc<RefCell<BudgetState>>,
    }

    impl<R: Read> CountingReader<R> {
        fn new(inner: R, budget: Rc<RefCell<BudgetState>>) -> Self {
            CountingReader { inner, budget }
        }
    }

    impl<R: Read> Read for CountingReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut state = self.budget.borrow_mut();
            if state.left == 0 {
                state.hit = true;
                return Ok(0);
            }
            let want = buf
                .len()
                .min(usize::try_from(state.left).unwrap_or(usize::MAX));
            match self.inner.read(&mut buf[..want]) {
                Ok(n) => {
                    state.left -= n as u64;
                    Ok(n)
                }
                Err(e) => {
                    // An xz decoder refusing a dictionary over its
                    // memlimit surfaces here; anything else (a corrupt
                    // stream, a short file) stays silent downstream.
                    if is_memlimit(&e) {
                        state.memlimit_hit = true;
                    }
                    Err(e)
                }
            }
        }
    }

    /// Whether an I/O error is an xz decoder refusing a dictionary
    /// over its memlimit (issue #1387): liblzma surfaces that as
    /// `Error::MemLimit` inside the I/O error.
    fn is_memlimit(e: &io::Error) -> bool {
        e.get_ref()
            .and_then(|r| r.downcast_ref::<liblzma::stream::Error>())
            .is_some_and(|le| matches!(le, liblzma::stream::Error::MemLimit))
    }

    /// Skip/stop records for one Source walk (issue #1387): per kind,
    /// the first lines kept plus the total count, so a walk with many
    /// skips of one kind logs that kind's lines once and then a
    /// closing line with the count.
    pub struct StopLog {
        kinds: BTreeMap<&'static str, (Vec<String>, usize)>,
    }

    impl StopLog {
        fn new() -> Self {
            StopLog {
                kinds: BTreeMap::new(),
            }
        }

        fn record(&mut self, kind: &'static str, msg: String) {
            let entry = self.kinds.entry(kind).or_default();
            entry.1 += 1;
            if entry.0.len() < LOG_LINES_PER_KIND {
                entry.0.push(msg);
            }
        }

        pub fn lines(&self) -> Vec<String> {
            let mut out = Vec::new();
            for (kind, (kept, total)) in &self.kinds {
                out.extend(kept.iter().cloned());
                if *total > kept.len() {
                    out.push(format!(
                        "{kind}: {} more skips of this kind",
                        total - kept.len()
                    ));
                }
            }
            out
        }
    }

    /// What one source walk found, plus the stops it recorded for
    /// logging (issue #1387). Finding vectors are already capped, and
    /// version-control roots are keyed by root with entry and byte
    /// totals, in root order like the old member-list fold.
    pub struct WalkOutcome {
        pub prebuilt: Vec<(BinaryKind, String)>,
        /// The same hits with their sha256, plus the nested-archive
        /// records, for the run-scoped shipped join (issue #1389).
        /// Both share the finding cap with `prebuilt` (see
        /// `push_prebuilt`), so a cap-tripped walk records neither
        /// further findings nor further shipped records.
        pub shipped: Vec<Hit>,
        pub archives: Vec<ArchiveHits>,
        pub vcs: BTreeMap<String, (usize, u64)>,
        pub lfs: Vec<String>,
        pub bidi: Vec<BidiHit>,
        pub stops: StopLog,
    }

    impl WalkOutcome {
        fn new() -> Self {
            WalkOutcome {
                prebuilt: Vec::new(),
                shipped: Vec::new(),
                archives: Vec::new(),
                vcs: BTreeMap::new(),
                lfs: Vec::new(),
                bidi: Vec::new(),
                stops: StopLog::new(),
            }
        }
    }

    /// Cut a detail path to the storage limit, on a character boundary,
    /// with a trailing ellipsis (issue #1387).
    fn cut_detail(path: &str) -> String {
        if path.len() <= DETAIL_PATH_LIMIT {
            return path.to_owned();
        }
        let mut end = DETAIL_PATH_LIMIT;
        while end > 0 && !path.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &path[..end])
    }

    /// The three names a buffered archive is known by: the name its
    /// bytes classify under, the name bidi scans under, and the name a
    /// further decompression layer strips. Callers pass the right three
    /// for their case.
    pub struct BufferNames<'a> {
        pub classify: &'a str,
        pub bidi: &'a str,
        pub stream: &'a str,
    }

    /// The streaming walker (issue #1387): one pass per top-level
    /// Source feeds all four predicates, so no archive is decompressed
    /// twice and no member list is ever built. Nothing about a member
    /// outlives its visit except the findings themselves.
    pub struct Walker<'a> {
        budget: Rc<RefCell<BudgetState>>,
        caps: &'a mut CapState,
        limits: Limits,
        emit_vcs: bool,
        out: WalkOutcome,
        budget_stop_recorded: bool,
        memlimit_stop_recorded: bool,
    }

    impl<'a> Walker<'a> {
        pub fn new(caps: &'a mut CapState, emit_vcs: bool) -> Self {
            Walker {
                budget: Rc::new(RefCell::new(BudgetState {
                    left: DECOMPRESS_BUDGET_BYTES,
                    hit: false,
                    memlimit_hit: false,
                })),
                caps,
                limits: Limits::production(),
                emit_vcs,
                out: WalkOutcome::new(),
                budget_stop_recorded: false,
                memlimit_stop_recorded: false,
            }
        }

        /// Test-only entry point: same walker with small limits, so
        /// budget and cap stops are reachable without huge fixtures.
        #[cfg(test)]
        pub fn with_limits(
            caps: &'a mut CapState,
            emit_vcs: bool,
            budget: u64,
            finding_cap: usize,
        ) -> Self {
            Walker {
                budget: Rc::new(RefCell::new(BudgetState {
                    left: budget,
                    hit: false,
                    memlimit_hit: false,
                })),
                caps,
                limits: Limits { finding_cap },
                emit_vcs,
                out: WalkOutcome::new(),
                budget_stop_recorded: false,
                memlimit_stop_recorded: false,
            }
        }

        fn budget_hit(&self) -> bool {
            self.budget.borrow().hit
        }

        fn note_budget_stop(&mut self) {
            if !self.budget_stop_recorded {
                self.budget_stop_recorded = true;
                self.out.stops.record(
                    "budget",
                    "decompression budget reached; findings so far are kept".to_owned(),
                );
            }
        }

        fn memlimit_hit(&self) -> bool {
            self.budget.borrow().memlimit_hit
        }

        fn note_memlimit_stop(&mut self) {
            if !self.memlimit_stop_recorded {
                self.memlimit_stop_recorded = true;
                self.out.stops.record(
                    "memlimit",
                    "xz decoder memory limit reached; archive not walked".to_owned(),
                );
            }
        }

        /// Charge decompressed zip entry bytes to the budget by hand
        /// (issue #1387): zip entry reads do not go through a counting
        /// reader. Returns false once the budget is spent.
        fn charge(&mut self, n: u64) -> bool {
            let mut state = self.budget.borrow_mut();
            if state.left >= n {
                state.left -= n;
                true
            } else {
                state.left = 0;
                state.hit = true;
                false
            }
        }

        fn push_prebuilt(&mut self, kind: BinaryKind, ctx: &str, sha256: String) {
            if self.caps.prebuilt >= self.limits.finding_cap {
                if !self.caps.prebuilt_tripped {
                    self.caps.prebuilt_tripped = true;
                    self.out.stops.record(
                        "finding-cap",
                        "prebuilt-binary-in-sources reached the finding cap".to_owned(),
                    );
                }
                return;
            }
            self.caps.prebuilt += 1;
            let path = cut_detail(ctx);
            self.out.prebuilt.push((kind, path.clone()));
            self.out.shipped.push(Hit { kind, path, sha256 });
        }

        fn count_vcs(&mut self, name: &str, size: u64) {
            if !self.emit_vcs {
                return;
            }
            let Some(root) = vcs_root(name) else {
                return;
            };
            if let Some((entries, bytes)) = self.out.vcs.get_mut(&root) {
                *entries = entries.saturating_add(1);
                *bytes = bytes.saturating_add(size);
                return;
            }
            if self.caps.vcs_roots >= self.limits.finding_cap {
                if !self.caps.vcs_tripped {
                    self.caps.vcs_tripped = true;
                    self.out.stops.record(
                        "finding-cap",
                        "source-archive-contains-vcs-metadata reached the finding cap".to_owned(),
                    );
                }
                return;
            }
            self.caps.vcs_roots += 1;
            self.out.vcs.insert(root, (1, size));
        }

        fn test_lfs(&mut self, name: &str, head: &[u8]) {
            // Unlike version-control counting, the git-lfs test is
            // not gated on URL sources: the old walk reported
            // pointers for every Source. The gate is the head length,
            // not the declared size: a pointer is 1-1023 bytes of
            // actual head, starting with the pointer version line
            // (the current git-lfs URL or the legacy hawser one,
            // LF- or CRLF-terminated) and carrying an `oid sha256:`
            // line of its own.
            if head.is_empty() || head.len() > 1023 {
                return;
            }
            if !(starts_with_version_line(head, b"version https://git-lfs.github.com/spec/v1")
                || starts_with_version_line(head, b"version https://hawser.github.com/spec/v1"))
            {
                return;
            }
            if !head
                .split(|&b| b == b'\n')
                .any(|line| line.starts_with(b"oid sha256:"))
            {
                return;
            }
            if self.caps.lfs >= self.limits.finding_cap {
                if !self.caps.lfs_tripped {
                    self.caps.lfs_tripped = true;
                    self.out.stops.record(
                        "finding-cap",
                        "source-archive-contains-lfs-pointer reached the finding cap".to_owned(),
                    );
                }
                return;
            }
            self.caps.lfs += 1;
            self.out.lfs.push(cut_detail(name));
        }

        fn push_bidi(&mut self, hit: BidiHit) {
            if self.caps.bidi >= self.limits.finding_cap {
                if !self.caps.bidi_tripped {
                    self.caps.bidi_tripped = true;
                    self.out.stops.record(
                        "finding-cap",
                        "source-archive-contains-bidi-control reached the finding cap".to_owned(),
                    );
                }
                return;
            }
            self.caps.bidi += 1;
            self.out.bidi.push(BidiHit {
                path: cut_detail(&hit.path),
                line: hit.line,
                column: hit.column,
                control: hit.control,
            });
        }

        /// Scan one member's bytes for a bidi control, unless its name
        /// is excluded (issue #1139's exclusions are name-based: `.git`
        /// path components, documentation suffixes, changelog basenames).
        fn scan_bidi(&mut self, name: &str, data: &[u8], ctx: &str) {
            if bidi_excluded(name) {
                return;
            }
            if let Some((line, column, control)) = first_bidi_control_in_text(data) {
                self.push_bidi(BidiHit {
                    path: ctx.to_owned(),
                    line,
                    column,
                    control,
                });
            }
        }
    }

    /// Read up to `limit` bytes from a stream. Returns the bytes plus
    /// whether the stream holds at least one more byte past the limit
    /// (a one-byte probe, not a grow-past-the-limit read). A stream
    /// that ends early returns its bytes with `false`.
    fn read_up_to<R: Read>(mut r: R, limit: u64) -> io::Result<(Vec<u8>, bool)> {
        let mut buf = Vec::with_capacity(usize::try_from(limit).unwrap_or(usize::MAX));
        let mut limited = (&mut r).take(limit);
        limited.read_to_end(&mut buf)?;
        if (buf.len() as u64) < limit {
            return Ok((buf, false));
        }
        let mut probe = [0u8; 1];
        let n = r.read(&mut probe)?;
        Ok((buf, n > 0))
    }

    /// A stream that first replays a peeked prefix, then continues
    /// with the underlying reader.
    struct Peeked<R: Read> {
        prefix: io::Cursor<Vec<u8>>,
        rest: R,
    }

    impl<R: Read> Read for Peeked<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.prefix.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            self.rest.read(buf)
        }
    }

    /// Read the first 512 bytes of a stream, returning them plus a
    /// stream that replays them. A short read returns what was read;
    /// a read error ends the walk silently, like today's decompress
    /// failure.
    fn peek<R: Read>(mut r: R) -> Option<(Vec<u8>, Peeked<R>)> {
        let mut prefix = vec![0u8; 512];
        let mut got = 0;
        while got < 512 {
            match r.read(&mut prefix[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => return None,
            }
        }
        prefix.truncate(got);
        Some((
            prefix.clone(),
            Peeked {
                prefix: io::Cursor::new(prefix),
                rest: r,
            },
        ))
    }

    enum DecoderKind {
        Gzip,
        Xz,
        Zstd,
        Bzip2,
    }

    /// Stream magics for the four decoders, matching today's
    /// `decompress_*` dispatch. Bzip2 needs its level digit too.
    fn decoder_kind(prefix: &[u8]) -> Option<DecoderKind> {
        if prefix.starts_with(b"\x1f\x8b") {
            Some(DecoderKind::Gzip)
        } else if prefix.starts_with(b"\xfd7zXZ\x00") {
            Some(DecoderKind::Xz)
        } else if prefix.starts_with(b"\x28\xb5\x2f\xfd") {
            Some(DecoderKind::Zstd)
        } else if prefix.len() >= 4
            && prefix.starts_with(b"BZh")
            && (b'1'..=b'9').contains(&prefix[3])
        {
            Some(DecoderKind::Bzip2)
        } else {
            None
        }
    }

    /// Build one decoder over a stream. The xz decoder carries the
    /// stated memlimit (issue #1387): a stream whose dictionary
    /// exceeds it fails the decode instead of allocating past it.
    fn decode<'a, R: Read + 'a>(kind: DecoderKind, r: R) -> Option<Box<dyn Read + 'a>> {
        match kind {
            DecoderKind::Gzip => Some(Box::new(flate2::read::GzDecoder::new(r))),
            DecoderKind::Xz => {
                let Ok(stream) = liblzma::stream::Stream::new_stream_decoder(XZ_MEMLIMIT_BYTES, 0)
                else {
                    return None;
                };
                Some(Box::new(liblzma::read::XzDecoder::new_stream(r, stream)))
            }
            DecoderKind::Zstd => zstd::Decoder::new(r)
                .ok()
                .map(|d| Box::new(d) as Box<dyn Read>),
            DecoderKind::Bzip2 => Some(Box::new(bzip2::read::BzDecoder::new(r))),
        }
    }

    /// Whether bytes look like an archive or a compressed stream, as
    /// opposed to a plain single file.
    fn is_archive_or_compressed(data: &[u8]) -> bool {
        is_tar(data) || data.starts_with(b"PK\x03\x04") || decoder_kind(data).is_some()
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

    /// A tar size field: GNU base-256 when the high bit of the first
    /// byte is set (a big-endian number, for members of 8 GiB or
    /// more), strict octal otherwise. Overflow past u64 is corrupt
    /// and ends the walk.
    fn parse_tar_size(field: &[u8]) -> Option<u64> {
        if field.is_empty() {
            return None;
        }
        if field[0] & 0x80 != 0 {
            let mut value = u64::from(field[0] & 0x7f);
            for &b in &field[1..] {
                value = value.checked_mul(256)?.checked_add(u64::from(b))?;
            }
            return Some(value);
        }
        parse_octal(field)
    }

    fn header_str(header: &[u8], range: std::ops::Range<usize>) -> String {
        let raw = &header[range];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    }

    /// A ustar header is recognized by its magic alone: the prebuilt
    /// check never validates checksums, and V7 tarballs have no magic
    /// at all, so they are never recognized here.
    fn is_tar(data: &[u8]) -> bool {
        data.len() >= 512 && &data[257..262] == b"ustar"
    }

    /// Parse pax extended-header records from the first 4 KiB of an `x`
    /// header's data: `<length> <key>=<value>\n` records, where the length
    /// counts itself. Returns the last `path` and `size` records seen;
    /// other keys are ignored. A malformed record, or one running past
    /// `data`, ends the parse; records parsed before it still apply.
    /// Values decode with `from_utf8_lossy`, like `L` names.
    fn parse_pax(data: &[u8]) -> (Option<String>, Option<u64>) {
        let mut path = None;
        let mut size = None;
        let mut rest = data;
        while !rest.is_empty() {
            let Some(space) = rest.iter().position(|&b| b == b' ') else {
                break;
            };
            let len = match std::str::from_utf8(&rest[..space])
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
            {
                Some(n) => n,
                None => break,
            };
            if len <= space || rest.len() < len {
                break;
            }
            let record = &rest[space + 1..len];
            let record = record.strip_suffix(b"\n").unwrap_or(record);
            if let Some(eq) = record.iter().position(|&b| b == b'=') {
                let (key, value) = (&record[..eq], &record[eq + 1..]);
                if key == b"path" {
                    path = Some(String::from_utf8_lossy(value).into_owned());
                } else if key == b"size" {
                    match std::str::from_utf8(value)
                        .ok()
                        .and_then(|s| s.parse::<u64>().ok())
                    {
                        Some(n) => size = Some(n),
                        None => break,
                    }
                }
            }
            rest = &rest[len..];
        }
        (path, size)
    }

    /// One regular member of a tar stream: its raw name (as written,
    /// long-name or ustar prefix included) and its declared size.
    struct TarEntry {
        name: String,
        size: u64,
    }

    /// A minimal streaming ustar reader. It yields regular members
    /// only (`'0'`/`0` typeflags): GNU long names (`L`, read up to
    /// 4 KiB for the name, the rest skipped), pax extended headers
    /// (`x`, first 4 KiB of records parsed: a pending `path` names
    /// the next regular member ahead of the `L` name and the ustar
    /// fields, and a pending `size` replaces that member's size
    /// field), global headers (`g`, ignored), and every other
    /// non-regular entry are consumed internally, and pending
    /// values never belong to them.
    /// Padding to the 512 boundary is skipped before the next header.
    /// The walk stops at the first corrupt header, at the end-of-
    /// archive zero blocks, or when the stream ends early.
    pub struct TarStream<R: Read> {
        r: R,
        pending_long_name: Option<String>,
        pending_pax_path: Option<String>,
        pending_pax_size: Option<u64>,
        pending_padding: u64,
        ended: bool,
    }

    impl<R: Read> TarStream<R> {
        pub fn new(r: R) -> Self {
            TarStream {
                r,
                pending_long_name: None,
                pending_pax_path: None,
                pending_pax_size: None,
                pending_padding: 0,
                ended: false,
            }
        }

        fn read_exact_or_end(&mut self, mut buf: &mut [u8]) -> bool {
            while !buf.is_empty() {
                match self.r.read(buf) {
                    Ok(0) => return false,
                    Ok(n) => buf = &mut buf[n..],
                    Err(_) => return false,
                }
            }
            true
        }

        fn skip_bytes(&mut self, mut n: u64) -> bool {
            let mut chunk = [0u8; 65536];
            while n > 0 {
                let want = chunk.len().min(usize::try_from(n).unwrap_or(usize::MAX));
                match self.r.read(&mut chunk[..want]) {
                    Ok(0) => return false,
                    Ok(k) => n -= k as u64,
                    Err(_) => return false,
                }
            }
            true
        }

        fn next_regular(&mut self) -> Option<TarEntry> {
            if self.pending_padding > 0 {
                let pad = self.pending_padding;
                self.pending_padding = 0;
                if !self.skip_bytes(pad) {
                    return None;
                }
            }
            loop {
                let mut hdr = [0u8; 512];
                if !self.read_exact_or_end(&mut hdr) {
                    return None;
                }
                if hdr.iter().all(|&b| b == 0) {
                    self.ended = true;
                    return None;
                }
                let typeflag = hdr[156];
                let size = parse_tar_size(&hdr[124..136])?;
                let data_blocks = size.div_ceil(512).saturating_mul(512);
                if typeflag == b'L' {
                    let take = size.min(4096);
                    let mut name_buf = vec![0u8; usize::try_from(take).unwrap_or(usize::MAX)];
                    if !self.read_exact_or_end(&mut name_buf) {
                        return None;
                    }
                    if !self.skip_bytes(data_blocks.saturating_sub(take)) {
                        return None;
                    }
                    let end = name_buf
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(name_buf.len());
                    self.pending_long_name =
                        Some(String::from_utf8_lossy(&name_buf[..end]).into_owned());
                    continue;
                }
                if typeflag == b'x' {
                    // Pax extended header: parse at most the first
                    // 4 KiB of records, like `L` above, and merge
                    // them into the pending values (a later record
                    // with the same key wins; keys absent here leave
                    // pending values intact). Records parsed before
                    // a malformed one still apply. A pending `L`
                    // name stays: a pax `path` wins over it only at
                    // the regular member.
                    let take = size.min(4096);
                    let mut x_buf = vec![0u8; usize::try_from(take).unwrap_or(usize::MAX)];
                    if !self.read_exact_or_end(&mut x_buf) {
                        return None;
                    }
                    if !self.skip_bytes(data_blocks.saturating_sub(take)) {
                        return None;
                    }
                    let (path, psize) = parse_pax(&x_buf);
                    self.pending_pax_path = path.or(self.pending_pax_path.take());
                    self.pending_pax_size = psize.or(self.pending_pax_size.take());
                    continue;
                }
                if typeflag == b'g' {
                    // Global headers stay ignored, and like every
                    // other non-member header they drop both pending
                    // values.
                    self.pending_long_name = None;
                    self.pending_pax_path = None;
                    self.pending_pax_size = None;
                    if !self.skip_bytes(data_blocks) {
                        return None;
                    }
                    continue;
                }
                if typeflag == b'0' || typeflag == 0 {
                    // A pending pax `size` replaces the size field
                    // before padding is counted, so skipping stays
                    // aligned when the ustar field is empty or
                    // capped; a pax `path` wins over the `L` name
                    // and the ustar fields, and both pending values
                    // are spent on this member.
                    let mut size = size;
                    if let Some(s) = self.pending_pax_size.take() {
                        size = s;
                    }
                    let data_blocks = size.div_ceil(512).saturating_mul(512);
                    let name = match self.pending_pax_path.take() {
                        Some(p) => {
                            self.pending_long_name = None;
                            p
                        }
                        None => match self.pending_long_name.take() {
                            Some(n) => n,
                            None => {
                                let mut name = header_str(&hdr, 0..100);
                                let prefix = header_str(&hdr, 345..500);
                                if !prefix.is_empty() {
                                    name = format!("{prefix}/{name}");
                                }
                                name
                            }
                        },
                    };
                    self.pending_padding = data_blocks.saturating_sub(size);
                    return Some(TarEntry { name, size });
                }
                self.pending_long_name = None;
                self.pending_pax_path = None;
                self.pending_pax_size = None;
                if !self.skip_bytes(data_blocks) {
                    return None;
                }
            }
        }

        /// Read one member's whole content (the caller checked the
        /// size against the entry cap first). `None` on a short read
        /// or a read error: the caller checks the budget flag to tell
        /// a budget stop from a truncated stream.
        fn read_member(&mut self, size: u64) -> Option<Vec<u8>> {
            let mut buf = Vec::with_capacity(usize::try_from(size).unwrap_or(usize::MAX));
            let mut chunk = [0u8; 65536];
            let mut left = size;
            while left > 0 {
                let want = chunk.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                match self.r.read(&mut chunk[..want]) {
                    Ok(0) => return None,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        left -= n as u64;
                    }
                    Err(_) => return None,
                }
            }
            Some(buf)
        }

        /// Read a member through without buffering it, keeping only
        /// its first head bytes. Returns the head plus whether the
        /// whole declared size was consumed.
        fn read_through(&mut self, size: u64) -> (Vec<u8>, bool) {
            let mut head = Vec::new();
            let mut chunk = [0u8; 65536];
            let mut left = size;
            while left > 0 {
                let want = chunk.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                match self.r.read(&mut chunk[..want]) {
                    Ok(0) => return (head, false),
                    Ok(n) => {
                        if head.len() < HEAD_BYTES {
                            let take = (HEAD_BYTES - head.len()).min(n);
                            head.extend_from_slice(&chunk[..take]);
                        }
                        left -= n as u64;
                    }
                    Err(_) => return (head, false),
                }
            }
            (head, true)
        }
    }

    impl<'a> Walker<'a> {
        /// Walk one tar stream. Members are visited in stream order;
        /// an oversized member is read through (see the module doc),
        /// a short read ends the walk, and a budget stop is recorded
        /// when the budget flag says the stream ended on the budget
        /// rather than on the archive's own end or a corrupt header.
        pub fn walk_tar_stream<R: Read>(
            &mut self,
            mut stream: TarStream<R>,
            ctx: &str,
            depth: u8,
            prebuilt_active: bool,
        ) {
            while let Some(entry) = stream.next_regular() {
                let mctx = format!("{ctx}: {}", entry.name);
                if entry.size > MAX_ENTRY_BYTES as u64 {
                    let (head, complete) = stream.read_through(entry.size);
                    if !complete {
                        if self.budget_hit() {
                            self.note_budget_stop();
                        } else if self.memlimit_hit() {
                            self.note_memlimit_stop();
                        }
                        break;
                    }
                    if depth == 0 {
                        let norm = normalize_member_name(&entry.name);
                        self.count_vcs(&norm, entry.size);
                        self.test_lfs(&norm, &head);
                    }
                    continue;
                }
                let Some(bytes) = stream.read_member(entry.size) else {
                    if self.budget_hit() {
                        self.note_budget_stop();
                    } else if self.memlimit_hit() {
                        self.note_memlimit_stop();
                    }
                    break;
                };
                self.visit_buffered_member(
                    &entry.name,
                    &bytes,
                    entry.size,
                    &mctx,
                    depth,
                    prebuilt_active,
                );
            }
            if !stream.ended {
                if self.budget_hit() {
                    self.note_budget_stop();
                } else if self.memlimit_hit() {
                    self.note_memlimit_stop();
                }
            }
        }

        /// Walk one zip archive. Entries are visited in central-
        /// directory order. The declared size is never trusted for
        /// the walk decision: every entry is read capped at the
        /// entry cap plus one byte, and the walk follows what was
        /// actually read. A genuinely oversized or unreadable entry
        /// still counts as a member at its declared size, with the
        /// head actually read (empty when unreadable), like today's
        /// `zip_scan`; a declared-oversized entry over small actual
        /// content is visited for bidi only, since the old prebuilt
        /// walk skipped on the declared size while the old bidi walk
        /// never trusted it.
        pub fn walk_zip<R: Read + Seek>(
            &mut self,
            mut archive: zip::ZipArchive<R>,
            ctx: &str,
            depth: u8,
            prebuilt_active: bool,
        ) {
            for i in 0..archive.len() {
                let entry = match archive.by_index(i) {
                    Ok(entry) => entry,
                    Err(_) => continue,
                };
                if !entry.is_file() {
                    continue;
                }
                let raw_name = match entry.name() {
                    Ok(name) => name.into_owned(),
                    Err(_) => continue,
                };
                let declared = entry.size();
                let mctx = format!("{ctx}: {raw_name}");
                let mut bytes = Vec::new();
                let read_ok = entry
                    .take(MAX_ENTRY_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
                    .is_ok();
                if !read_ok || bytes.len() > MAX_ENTRY_BYTES {
                    // Genuinely oversized or unreadable: a member for
                    // version-control counting and the git-lfs test
                    // only, at its declared size.
                    if !self.charge(bytes.len() as u64) {
                        self.note_budget_stop();
                        break;
                    }
                    if depth == 0 {
                        let norm = normalize_member_name(&raw_name);
                        self.count_vcs(&norm, declared);
                        let head: &[u8] = if read_ok { &member_head(&bytes) } else { &[] };
                        self.test_lfs(&norm, head);
                    }
                    continue;
                }
                if !self.charge(bytes.len() as u64) {
                    self.note_budget_stop();
                    break;
                }
                // A declared-oversized entry over small actual content
                // is a lie the old bidi walk saw through and the old
                // prebuilt walk did not: visit it for bidi only.
                let prebuilt_here = prebuilt_active && declared <= MAX_ENTRY_BYTES as u64;
                self.visit_buffered_member(
                    &raw_name,
                    &bytes,
                    declared,
                    &mctx,
                    depth,
                    prebuilt_here,
                );
            }
        }

        /// Visit one buffered member (tar member or zip entry at or
        /// under the entry cap). Version-control counting (skipped
        /// for URL sources) and the git-lfs test apply to top-level
        /// members only, whatever the member is; nested members get
        /// the prebuilt and bidi predicates only. A jar is a prebuilt
        /// unit - its classes are not listed - but bidi still walks
        /// it as a zip, so the jar's subtree is visited with
        /// prebuilt inactive.
        fn visit_buffered_member(
            &mut self,
            raw_name: &str,
            bytes: &[u8],
            declared: u64,
            mctx: &str,
            depth: u8,
            prebuilt_active: bool,
        ) {
            if depth == 0 {
                let norm = normalize_member_name(raw_name);
                self.count_vcs(&norm, declared);
                self.test_lfs(&norm, &member_head(bytes));
            }
            let mut kind = None;
            if prebuilt_active {
                kind = classify(raw_name, bytes);
                if let Some(k) = kind {
                    self.push_prebuilt(k, mctx, super::sha256_hex(bytes));
                }
            }
            match kind {
                Some(BinaryKind::JavaArchive) => {
                    if depth < MAX_DEPTH - 1 {
                        self.walk_zip_bytes(bytes, mctx, depth + 1, false);
                    }
                }
                Some(_) => {
                    // A classified non-jar member is a leaf for
                    // prebuilt; bidi still scans its bytes as text
                    // (binary bytes fail the decode and stay quiet).
                    self.scan_bidi(raw_name, bytes, mctx);
                }
                None => {
                    if is_archive_or_compressed(bytes) {
                        if depth < MAX_DEPTH - 1 {
                            // A nested archive that holds hits joins
                            // the run-scoped shipped records (issue
                            // #1389) with its own bytes' digest, like
                            // the old inspect_entry did.
                            let before = self.out.shipped.len();
                            self.walk_archive_buffer(
                                bytes,
                                BufferNames {
                                    classify: raw_name,
                                    bidi: raw_name,
                                    stream: raw_name,
                                },
                                mctx,
                                depth + 1,
                                prebuilt_active,
                            );
                            let hits = self.out.shipped.len() - before;
                            if hits > 0 {
                                self.out.archives.push(ArchiveHits {
                                    sha256: super::sha256_hex(bytes),
                                    hits,
                                    path: mctx.to_string(),
                                });
                            }
                        }
                        // Too deep: neither predicate walks in, and
                        // the archive's bytes are not scanned as text
                        // either - the old walk refused here too.
                    } else {
                        self.scan_bidi(raw_name, bytes, mctx);
                    }
                }
            }
        }

        /// Walk an archive held in a buffer, at its own depth. The
        /// three names exist because the predicates disagree about
        /// which name to use: a member's bytes classify by the member
        /// name, while a decompressed buffer classifies by its display
        /// path and scans bidi by the compression-stripped member
        /// name; the stream name is what a further decompression
        /// layer strips. Callers pass the right three for their case.
        pub fn walk_archive_buffer(
            &mut self,
            data: &[u8],
            names: BufferNames<'_>,
            ctx: &str,
            depth: u8,
            prebuilt_active: bool,
        ) {
            if is_tar(data) {
                self.walk_tar_stream(
                    TarStream::new(io::Cursor::new(data)),
                    ctx,
                    depth,
                    prebuilt_active,
                );
            } else if data.starts_with(b"PK\x03\x04") {
                if let Ok(archive) = zip::ZipArchive::new(io::Cursor::new(data)) {
                    self.walk_zip(archive, ctx, depth, prebuilt_active);
                }
            } else if let Some(kind) = decoder_kind(data) {
                if depth < MAX_DEPTH - 1
                    && let Some(decoder) = decode(kind, io::Cursor::new(data))
                {
                    let counted = CountingReader::new(decoder, self.budget.clone());
                    self.walk_streamed(
                        Box::new(counted),
                        names.stream,
                        ctx,
                        depth + 1,
                        prebuilt_active,
                    );
                }
            } else {
                if prebuilt_active && let Some(k) = classify(names.classify, data) {
                    self.push_prebuilt(k, ctx, super::sha256_hex(data));
                }
                self.scan_bidi(names.bidi, data, ctx);
            }
        }

        /// Walk a stream (decoder output or a top-level plain tar):
        /// peek at its first bytes, walk a tar directly, or buffer a
        /// compressed single file or zip up to the entry cap and walk
        /// the buffer. Past the cap the stream is not walked and not
        /// classified from its head, and the skip is logged.
        pub fn walk_streamed<'b>(
            &mut self,
            stream: Box<dyn Read + 'b>,
            name: &str,
            ctx: &str,
            depth: u8,
            prebuilt_active: bool,
        ) {
            let Some((prefix, peeked)) = peek(stream) else {
                if self.memlimit_hit() {
                    self.note_memlimit_stop();
                }
                return;
            };
            if self.budget_hit() {
                self.note_budget_stop();
                return;
            }
            if is_tar(&prefix) {
                self.walk_tar_stream(TarStream::new(peeked), ctx, depth, prebuilt_active);
                return;
            }
            match read_up_to(peeked, MAX_ENTRY_BYTES as u64) {
                Ok((buf, false)) => {
                    if self.budget_hit() {
                        self.note_budget_stop();
                        return;
                    }
                    let stripped = strip_compression_suffix(name);
                    self.walk_archive_buffer(
                        &buf,
                        BufferNames {
                            classify: ctx,
                            bidi: stripped,
                            stream: name,
                        },
                        ctx,
                        depth,
                        prebuilt_active,
                    );
                }
                Ok((_, true)) => {
                    self.out.stops.record(
                        "single-over-64",
                        format!("{ctx}: decompressed stream over 64 MiB is not walked"),
                    );
                }
                Err(_) => {
                    // A corrupt stream ends the walk silently, like
                    // today's decompress failure; a memlimit refusal
                    // is reported.
                    if self.memlimit_hit() {
                        self.note_memlimit_stop();
                    }
                }
            }
        }

        /// Walk a zip held in a buffer (a jar member for bidi, or a
        /// decompressed zip buffer).
        fn walk_zip_bytes(&mut self, bytes: &[u8], ctx: &str, depth: u8, prebuilt_active: bool) {
            if let Ok(archive) = zip::ZipArchive::new(io::Cursor::new(bytes)) {
                self.walk_zip(archive, ctx, depth, prebuilt_active);
            }
        }

        /// Walk one top-level Source file. The file is opened once
        /// and peeked at: a zip over the on-disk cap is skipped with
        /// a warning, a zip under it is opened from the file, an
        /// archive or compressed stream is walked streaming, and
        /// anything else is classified from its first bytes and read
        /// no further.
        pub fn walk_file(&mut self, path: &std::path::Path, name: &str) {
            let Ok(metadata) = std::fs::metadata(path) else {
                return;
            };
            let Ok(file) = std::fs::File::open(path) else {
                return;
            };
            let Some((prefix, peeked)) = peek(file) else {
                return;
            };
            if prefix.starts_with(b"PK\x03\x04") {
                if metadata.len() > MAX_ARCHIVE_BYTES as u64 {
                    self.out.stops.record(
                        "zip-skipped",
                        format!("{name}: zip Source over 256 MiB on disk is skipped"),
                    );
                    return;
                }
                let mut file = match std::fs::File::open(path) {
                    Ok(file) => file,
                    Err(_) => return,
                };
                if file.seek(SeekFrom::Start(0)).is_err() {
                    return;
                }
                // A jar is a prebuilt unit: classify first, so a
                // bare .jar Source reports the jar itself and its
                // classes stay quiet; a plain zip keeps walking with
                // prebuilt active.
                let unit = classify(name, &prefix);
                if let Some(k) = unit {
                    // The jar unit is the file itself: hash the file, as
                    // the bare-file case does; an unreadable file yields
                    // an empty digest, which never matches a shipped
                    // record. The hit's path is the Source name, so the
                    // join records no second whole-file record for it.
                    self.push_prebuilt(
                        k,
                        name,
                        super::sha256_file(&path.to_string_lossy()).unwrap_or_default(),
                    );
                }
                if let Ok(archive) = zip::ZipArchive::new(file) {
                    self.walk_zip(archive, name, 0, unit.is_none());
                }
                return;
            }
            // The budget counts decoder outputs and plain-tar bytes
            // only: a compressed file's raw bytes are not charged, so
            // the decoder runs over the uncounted peeked stream and
            // only its output goes through a counting reader.
            if let Some(kind) = decoder_kind(&prefix) {
                if let Some(decoder) = decode(kind, peeked) {
                    let decoder_counted = CountingReader::new(decoder, self.budget.clone());
                    self.walk_streamed(Box::new(decoder_counted), name, name, 0, true);
                }
                return;
            }
            if is_tar(&prefix) {
                let counted = CountingReader::new(peeked, self.budget.clone());
                self.walk_tar_stream(TarStream::new(counted), name, 0, true);
                return;
            }
            if let Some(k) = classify(name, &prefix) {
                // A bare file has no member bytes in hand: hash the
                // file itself, as the old whole-file walk did; an
                // unreadable file yields an empty digest, which never
                // matches a shipped record.
                let digest = super::sha256_file(&path.to_string_lossy()).unwrap_or_default();
                self.push_prebuilt(k, name, digest);
            }
        }

        /// Take the walk's outcome for emission.
        pub fn take_outcome(&mut self) -> WalkOutcome {
            std::mem::replace(&mut self.out, WalkOutcome::new())
        }
    }

    /// A member's head: its first bytes, up to 1024 -- the whole
    /// member when it is at most 1023 bytes long.
    fn member_head(bytes: &[u8]) -> Vec<u8> {
        bytes[..bytes.len().min(1024)].to_vec()
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
    /// Whether `head` opens with the git-lfs pointer version line
    /// for `url`, terminated by LF or CRLF.
    fn starts_with_version_line(head: &[u8], url: &[u8]) -> bool {
        head.strip_prefix(url)
            .is_some_and(|rest| rest.starts_with(b"\n") || rest.starts_with(b"\r\n"))
    }
    /// One bidirectional-control hit inside a source archive:
    /// the display path (`archive: member`, nested archives joined
    /// the same way), and the 1-based line and character column of
    /// the first control in that member.
    pub struct BidiHit {
        pub path: String,
        pub line: u32,
        pub column: u32,
        pub control: &'static str,
    }
    /// The nine Unicode bidirectional control characters
    /// (U+202A-U+202E, U+2066-U+2069) with their Unicode names.
    const BIDI_CONTROLS: [(char, &str); 9] = [
        ('\u{202A}', "U+202A LEFT-TO-RIGHT EMBEDDING"),
        ('\u{202B}', "U+202B RIGHT-TO-LEFT EMBEDDING"),
        ('\u{202C}', "U+202C POP DIRECTIONAL FORMATTING"),
        ('\u{202D}', "U+202D LEFT-TO-RIGHT OVERRIDE"),
        ('\u{202E}', "U+202E RIGHT-TO-LEFT OVERRIDE"),
        ('\u{2066}', "U+2066 LEFT-TO-RIGHT ISOLATE"),
        ('\u{2067}', "U+2067 RIGHT-TO-LEFT ISOLATE"),
        ('\u{2068}', "U+2068 FIRST STRONG ISOLATE"),
        ('\u{2069}', "U+2069 POP DIRECTIONAL ISOLATE"),
    ];
    /// The Unicode name of a bidirectional control character, or
    /// `None` for any other character.
    fn bidi_control_name(c: char) -> Option<&'static str> {
        BIDI_CONTROLS
            .iter()
            .find(|(cp, _)| *cp == c)
            .map(|(_, name)| *name)
    }
    /// The first bidirectional control in decoded text, with its
    /// 1-based line and character column, or `None` when the bytes
    /// hold no control. UTF-8, with an optional byte-order mark, is
    /// tried first; a UTF-16 byte-order mark selects UTF-16LE or
    /// UTF-16BE. Bytes that decode neither way are binary, not
    /// text, and stay quiet; unpaired surrogates fail the UTF-16
    /// decode the same way.
    fn first_bidi_control_in_text(data: &[u8]) -> Option<(u32, u32, &'static str)> {
        if data.starts_with(b"\xEF\xBB\xBF") {
            let text = std::str::from_utf8(&data[3..]).ok()?;
            scan_chars(text.chars())
        } else if data.starts_with(b"\xFF\xFE") {
            scan_chars(decode_utf16(&data[2..], true)?.into_iter())
        } else if data.starts_with(b"\xFE\xFF") {
            scan_chars(decode_utf16(&data[2..], false)?.into_iter())
        } else {
            let text = std::str::from_utf8(data).ok()?;
            scan_chars(text.chars())
        }
    }
    /// First bidi control in a char stream, with its 1-based line
    /// and character column. The stream is consumed lazily: no
    /// intermediate text buffer is built. (UTF-16 still validates
    /// through `decode_utf16`, which must see every unit to fail the
    /// whole member on an unpaired surrogate.)
    fn scan_chars(chars: impl Iterator<Item = char>) -> Option<(u32, u32, &'static str)> {
        let mut line = 1u32;
        let mut column = 1u32;
        for c in chars {
            if let Some(name) = bidi_control_name(c) {
                return Some((line, column, name));
            }
            if c == '\n' {
                line += 1;
                column = 1;
            } else {
                column += 1;
            }
        }
        None
    }
    /// Decode UTF-16 units from `data` (little-endian when `le`),
    /// failing on a trailing byte or any unpaired surrogate.
    fn decode_utf16(data: &[u8], le: bool) -> Option<Vec<char>> {
        if !data.len().is_multiple_of(2) {
            return None;
        }
        let units: Vec<u16> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                if le {
                    u16::from_le_bytes([pair[0], pair[1]])
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                }
            })
            .collect();
        char::decode_utf16(units)
            .collect::<Result<Vec<char>, _>>()
            .ok()
    }
    /// Whether an archive member is outside the bidi scan: a `.git`
    /// path component, a `.desktop` or `.txt` suffix, a `Changelog`
    /// or `NEWS` basename, case-folded (with or without a dotted suffix), or one
    /// of the excluded text formats (`.po`, `.tex`, `.html`, `.htm`,
    /// `.roff`).
    fn bidi_excluded(name: &str) -> bool {
        if name.split('/').any(|part| part == ".git") {
            return true;
        }
        let basename = name.rsplit('/').next().unwrap_or(name);
        let lower = basename.to_ascii_lowercase();
        if lower == "changelog"
            || lower == "news"
            || lower.starts_with("changelog.")
            || lower.starts_with("news.")
        {
            return true;
        }
        let lower = name.to_ascii_lowercase();
        [".po", ".tex", ".html", ".htm", ".roff", ".desktop", ".txt"]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
    }
    /// The member name without one compression suffix (`.gz`, `.xz`, `.zst`, `.zstd`, `.bz2`, case-insensitive), or the name unchanged.
    fn strip_compression_suffix(name: &str) -> &str {
        // ASCII-only lowercasing preserves byte length, so slicing
        // the original name by the stripped length is exact.
        let lower = name.to_ascii_lowercase();
        for suffix in [".gz", ".xz", ".zst", ".zstd", ".bz2"] {
            if let Some(stripped) = lower.strip_suffix(suffix) {
                return &name[..stripped.len()];
            }
        }
        name
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
        self.check_source_archives(pkg, out);
    }

    /// `prebuilt-binary-shipped` (run-scoped): record every binary
    /// payload file whose first 512 bytes could match a source record,
    /// keyed by the build's `SOURCERPM`. The verdict waits for
    /// `after_checks`, when the run's source records are known; a
    /// binary linted without its source package stays silent.
    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, _out: &mut Filter) {
        let Some(key) = binary_source_key(pkg) else {
            return;
        };
        let algo_is_8 = pkg.tag_i64(librpm::Tag::FILEDIGESTALGO) == Some(8);
        for f in &pkg.files {
            if !is_reg(f.mode) || is_ghost_file(pkg, f) {
                continue;
            }
            let Some(md5) = f.md5.as_ref().filter(|s| !s.is_empty()) else {
                continue;
            };
            let mut head = [0u8; 512];
            let head_len = std::fs::File::open(&f.path)
                .and_then(|mut file| std::io::Read::read(&mut file, &mut head))
                .unwrap_or(0);
            if !payload_could_match(&f.name, &head[..head_len]) {
                continue;
            }
            let Some(digest) = binary_digest(algo_is_8, md5, &f.path) else {
                continue;
            };
            self.shipped.binaries.push((
                key.clone(),
                BinaryRecord {
                    digest,
                    path: f.name.clone(),
                    pkg_name: pkg.name.clone(),
                    arch: pkg.arch.clone(),
                },
            ));
        }
    }

    /// `prebuilt-binary-shipped` verdict: for each recorded binary file
    /// whose digest is a source record of its own build, report the
    /// payload path, the kind, and the source member it matches. Two
    /// shapes stay quiet: a digest whose every source copy sits under
    /// a test directory, and a payload path under a firmware
    /// directory (the guideline's binary-firmware exception).
    fn after_checks(&mut self, _config: &Config, out: &mut Filter) {
        for (key, rec) in &self.shipped.binaries {
            let Some(by_digest) = self.shipped.sources.get(key) else {
                continue;
            };
            let Some(copies) = by_digest.get(&rec.digest) else {
                continue;
            };
            if copies.iter().all(|c| c.test) {
                continue;
            }
            if rec.path.starts_with("/usr/lib/firmware/") || rec.path.starts_with("/lib/firmware/")
            {
                continue;
            }
            let first = &copies[0];
            out.add_info(make_finding(
                &rec.pkg_name,
                &rec.arch,
                Level::Warning,
                "prebuilt-binary-shipped",
                vec![
                    rec.path.clone(),
                    first.kind.clone(),
                    format!("from {}", first.display),
                ],
                None,
            ));
        }
    }

    fn reset(&mut self) {
        self.shipped = ShippedState::default();
    }

    fn export_state(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        Some(Box::new(std::mem::take(&mut self.shipped)))
    }

    fn import_state(&mut self, state: Box<dyn std::any::Any + Send>) {
        if let Ok(mut state) = state.downcast::<ShippedState>() {
            for (key, digests) in std::mem::take(&mut state.sources) {
                let entry = self.shipped.sources.entry(key).or_default();
                for (digest, recs) in digests {
                    entry.entry(digest).or_default().extend(recs);
                }
            }
            self.shipped.binaries.append(&mut state.binaries);
        }
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
    use std::io::Read as _;
    use std::io::Write;

    /// Minimal ustar writer for fixtures (test-only). Names must fit in 100
    /// bytes; the production reader is what is under test.
    fn tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in entries {
            assert!(name.len() <= 100, "test tar writer: name too long");
            append_entry(&mut out, name, data.len(), b'0', data);
        }
        out.extend([0u8; 1024]);
        out
    }

    /// One ustar header plus its data blocks (test-only writer). `size` is
    /// the header's size field and may differ from `data.len()` for probes
    /// of readers that take the size from elsewhere (pax `size` records).
    fn append_entry(out: &mut Vec<u8>, name: &str, size: usize, typeflag: u8, data: &[u8]) {
        let mut hdr = [0u8; 512];
        hdr[..name.len()].copy_from_slice(name.as_bytes());
        hdr[100..108].copy_from_slice(b"0000644\0");
        let size_field = format!("{:011o}\0", size);
        hdr[124..136].copy_from_slice(size_field.as_bytes());
        hdr[156] = typeflag;
        hdr[257..262].copy_from_slice(b"ustar");
        hdr[148..156].copy_from_slice(b"        ");
        let sum: u32 = hdr.iter().map(|&b| b as u32).sum();
        let sum_field = format!("{sum:06o}\0 ");
        hdr[148..156].copy_from_slice(sum_field.as_bytes());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(data);
        out.extend(std::iter::repeat_n(0, (512 - data.len() % 512) % 512));
    }

    /// One pax extended-header record, `<length> <key>=<value>\n`, with the
    /// length counting itself (test-only writer).
    fn pax_record(key: &str, value: &str) -> Vec<u8> {
        let mut len = key.len() + value.len() + 3;
        loop {
            let next = key.len() + value.len() + 3 + len.to_string().len();
            if next == len {
                break;
            }
            len = next;
        }
        format!("{len} {key}={value}\n").into_bytes()
    }

    /// One member for `tarball_pax`: optional pax `x`/`g` headers, an
    /// optional GNU long name, then the member itself. `name` is the ustar
    /// name field (the cut name a real writer emits for a long path);
    /// `size` overrides the header's size field when set.
    struct PaxMember<'a> {
        x: &'a [u8],
        g: &'a [u8],
        long: Option<&'a str>,
        name: &'a str,
        data: &'a [u8],
        size: Option<usize>,
        typeflag: u8,
    }

    impl<'a> PaxMember<'a> {
        fn regular(name: &'a str, data: &'a [u8]) -> Self {
            PaxMember {
                x: &[],
                g: &[],
                long: None,
                name,
                data,
                size: None,
                typeflag: b'0',
            }
        }
    }

    /// Ustar writer with pax/`L` prefixes per member (test-only). The
    /// production reader is what is under test.
    fn tarball_pax(members: &[PaxMember]) -> Vec<u8> {
        let mut out = Vec::new();
        for m in members {
            if !m.g.is_empty() {
                append_entry(&mut out, "pax-global", m.g.len(), b'g', m.g);
            }
            if !m.x.is_empty() {
                append_entry(&mut out, "pax", m.x.len(), b'x', m.x);
            }
            if let Some(long) = m.long {
                let mut data = long.as_bytes().to_vec();
                data.push(0);
                append_entry(&mut out, "longname", data.len(), b'L', &data);
            }
            let size = m.size.unwrap_or(m.data.len());
            append_entry(&mut out, m.name, size, m.typeflag, m.data);
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

    /// One ar member header: 16-byte space-padded name, blank
    /// date/uid/gid/mode fields, decimal size, `` `\n `` terminator.
    /// Only the name field matters to `classify`.
    fn ar_member(name: &str, body: &[u8]) -> Vec<u8> {
        let mut hdr = [b' '; 60];
        hdr[..name.len()].copy_from_slice(name.as_bytes());
        let size = format!("{:<10}", body.len());
        hdr[48..58].copy_from_slice(size.as_bytes());
        hdr[58] = b'`';
        hdr[59] = b'\n';
        let mut out = hdr.to_vec();
        out.extend_from_slice(body);
        if body.len() % 2 == 1 {
            out.push(b'\n');
        }
        out
    }

    /// An ar archive whose first member carries `first_name`.
    fn ar_archive(first_name: &str, first_body: &[u8]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        out.extend_from_slice(&ar_member(first_name, first_body));
        out
    }

    /// A thin ar archive: stores object paths, not objects.
    fn thin_archive() -> Vec<u8> {
        let mut out = b"!<thin>\n".to_vec();
        out.extend_from_slice(&ar_member("hello.o/", ELF));
        out
    }

    /// A .deb: an ar archive whose first member is `debian-binary`.
    fn deb_package() -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        out.extend_from_slice(&ar_member("debian-binary", b"2.0\n"));
        out.extend_from_slice(&ar_member("control.tar.xz", b"control"));
        out.extend_from_slice(&ar_member("data.tar.xz", b"data"));
        out
    }

    /// A PE32+ DLL in the issue's recipe shape: DOS header,
    /// `e_lfanew` 0x40, `PE\0\0`, x86-64 COFF header.
    fn pe_dll() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"MZ");
        out.extend(std::iter::repeat_n(0, 58));
        out.extend_from_slice(&0x40u32.to_le_bytes());
        out.extend_from_slice(b"PE\0\0");
        out.extend_from_slice(&0x8664u16.to_le_bytes());
        out.extend(std::iter::repeat_n(0, 14));
        out.extend_from_slice(&[0xf0, 0x00, 0x42, 0x40, 0x0b, 0x02]);
        out.extend(std::iter::repeat_n(0, 238));
        out
    }

    /// DOS header with `e_lfanew` 0: no PE signature.
    fn mz_stub() -> Vec<u8> {
        let mut out = b"MZ".to_vec();
        out.extend(std::iter::repeat_n(0, 62));
        out
    }

    /// DOS header with `e_lfanew` past the end of the file.
    fn mz_past() -> Vec<u8> {
        let mut out = b"MZ".to_vec();
        out.extend(std::iter::repeat_n(0, 58));
        out.extend_from_slice(&[0xff, 0xff, 0x00, 0x00]);
        out
    }

    /// Text that starts with `MZ`: the `e_lfanew` field reads zero.
    fn mz_txt() -> Vec<u8> {
        let mut out = b"MZ".to_vec();
        out.extend(std::iter::repeat_n(b'0', 100));
        out.push(b'\n');
        out
    }

    const WASM: &[u8] =
        b"\x00asm\x01\x00\x00\x00\x01\x04\x01\x60\x00\x00\x03\x02\x01\x00\x0a\x04\x01\x02\x00\x0b";
    const WASM_COMPONENT: &[u8] = b"\x00asm\x0d\x00\x01\x00";
    const WASM_V2: &[u8] = b"\x00asm\x02\x00\x00\x00";

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

    /// A package built from the shared fixture header (name
    /// `fcprobe`, version `1`, release `1`, `SOURCERPM`
    /// `fcprobe-1-1.src.rpm`), with name/arch/files replaced.
    fn fixture_pkg(name: &str, files: Vec<crate::pkg::pkgfile::PkgFile>) -> Pkg {
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

    /// The fixture header as a source package: the source identity
    /// `check_source` derives from it is `fcprobe-1-1.src.rpm`, the
    /// `SOURCERPM` every `fixture_pkg` binary carries.
    fn fixture_src(files: Vec<crate::pkg::pkgfile::PkgFile>) -> Pkg {
        let mut pkg = fixture_pkg("fcprobe", files);
        pkg.is_source = true;
        pkg
    }

    /// A regular file whose bytes live at `dir` and whose header
    /// digest is the true sha256 of those bytes, as a real RPM header
    /// would carry for that payload.
    fn payload_file(
        dir: &std::path::Path,
        name: &str,
        bytes: &[u8],
    ) -> crate::pkg::pkgfile::PkgFile {
        let disk = dir.join(name.rsplit('/').next().unwrap_or(name));
        std::fs::write(&disk, bytes).expect("write fixture payload");
        crate::pkg::pkgfile::PkgFile {
            name: name.to_string(),
            path: disk.to_string_lossy().into_owned(),
            mode: 0o100644,
            md5: Some(sha256_hex(bytes)),
            ..Default::default()
        }
    }

    fn shipped_lines(findings: &[(String, String, Level)]) -> Vec<String> {
        let mut lines: Vec<String> = findings
            .iter()
            .filter(|(n, _, l)| n == "prebuilt-binary-shipped" && *l == Level::Warning)
            .map(|(_, line, _)| line.clone())
            .collect();
        lines.sort();
        lines
    }

    /// The binary-side filter: hit-kind headers, `.pyc`/`.pyo` names
    /// and archive headers pass; anything else stays out.
    #[test]
    fn shipped_payload_filter_keeps_hit_kinds_only() {
        assert!(payload_could_match("a.o", b"\x7fELFxxxx"));
        assert!(payload_could_match("a.zip", b"PK\x03\x04xxxx"));
        assert!(payload_could_match("a.a", b"!<arch>\nxxxx"));
        assert!(payload_could_match("a.a", b"!<thin>\nxxxx"));
        assert!(payload_could_match("a.exe", b"MZxxxx"));
        assert!(payload_could_match("a.wasm", b"\0asm\x01\0\0\0"));
        assert!(payload_could_match("a.o", b"\xfe\xed\xfa\xcexxxx"));
        assert!(payload_could_match("a.o", b"\xfe\xed\xfa\xcfxxxx"));
        assert!(payload_could_match("a.o", b"\xce\xfa\xed\xfexxxx"));
        assert!(payload_could_match("a.o", b"\xcf\xfa\xed\xfexxxx"));
        assert!(payload_could_match("a.rpm", b"\xed\xab\xee\xdbxxxx"));
        assert!(payload_could_match("a.gz", b"\x1f\x8bxxxx"));
        assert!(payload_could_match("a.xz", b"\xfd7zXZ\x00xxxx"));
        assert!(payload_could_match("a.zst", b"\x28\xb5\x2f\xfdxxxx"));
        assert!(payload_could_match("a.bz2", b"BZh9xxxx"));
        assert!(payload_could_match("m.pyc", b"junk"));
        assert!(payload_could_match("m.PYC", b"junk"));
        assert!(payload_could_match("m.pyo", b"junk"));
        let mut tar_head = vec![0u8; 512];
        tar_head[257..262].copy_from_slice(b"ustar");
        assert!(payload_could_match("a.tar", &tar_head));
        assert!(!payload_could_match("a.txt", b"plain text, no magic here"));
        assert!(!payload_could_match("a.txt", b""));
        assert!(!payload_could_match("a.py", b"#!/usr/bin/python\n"));
        assert!(!payload_could_match("a.tar", &vec![0u8; 261]));
    }

    /// Test-directory detection is by directory component, not
    /// substring: `contest` and a file named `test` stay out.
    #[test]
    fn shipped_test_path_needs_a_test_directory() {
        assert!(is_test_path("s.tar.gz: tests/data/f.bin"));
        assert!(is_test_path("s.tar.gz: src/testdata/x.o"));
        assert!(is_test_path("s.tar.gz: outer.zip: test/x.o"));
        assert!(!is_test_path("s.tar.gz: src/contest/x.o"));
        assert!(!is_test_path("s.tar.gz: test"));
        assert!(!is_test_path("s.tar.gz: src/my test/x.o"));
        assert!(!is_test_path("s.tar.gz"));
    }

    /// The digest rule: algorithm 8 trusts the header digest without
    /// touching disk; any other algorithm hashes the payload file.
    #[test]
    fn shipped_binary_digest_prefers_header_algo_8() {
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("blob.bin");
        std::fs::write(&disk, ELF).unwrap();
        let path = disk.to_string_lossy().into_owned();
        assert_eq!(
            binary_digest(true, "deadbeef", "/nonexistent/path"),
            Some("deadbeef".to_string())
        );
        assert_eq!(
            binary_digest(false, "deadbeef", &path),
            Some(sha256_hex(ELF))
        );
        assert_eq!(binary_digest(false, "deadbeef", "/nonexistent/path"), None);
    }

    /// Run-scoped verdict through `Check::check` + `after_checks`:
    /// shipped files byte-identical to source binaries fire; test
    /// data, non-binaries, firmware paths, and binaries of a foreign
    /// build stay quiet.
    #[test]
    fn shipped_binaries_fire_and_quiet_shapes_stay_quiet() {
        use crate::color::Color;
        const FIXTURE_ELF: &[u8] = b"\x7fELF\x02\x01\x01\x00fixture-elf-body";
        let jar = zip_bytes(&[("com/example/Foo.class", CLASS)]);
        let bundle = zip_bytes(&[("mod.pyc", PYC)]);
        let inner = tarball(&[("nested/prebuilt2.o", ELF)]);
        let tar = tarball(&[
            ("src/prebuilt.o", ELF),
            ("lib/nested.jar", &jar),
            ("lib/bundle.zip", &bundle),
            ("deep/inner.tar.gz", &gzip_bytes(&inner)),
            ("tests/data/fixture.bin", FIXTURE_ELF),
            ("README", b"plain text\n"),
        ]);
        let tar_gz = gzip_bytes(&tar);
        let src_dir = tempfile::tempdir().unwrap();
        let src_pkg = fixture_src(vec![
            payload_file(src_dir.path(), "fcprobe.spec", b"Name: fcprobe\n"),
            payload_file(src_dir.path(), "fcprobe-1-1.tar.gz", &tar_gz),
        ]);
        let bin_dir = tempfile::tempdir().unwrap();
        let bin_pkg = fixture_pkg(
            "fcprobe",
            vec![
                payload_file(bin_dir.path(), "/usr/libexec/shipexp/stripped", ELF),
                payload_file(bin_dir.path(), "/usr/share/shipexp/bundle.zip", &bundle),
                payload_file(bin_dir.path(), "/usr/share/shipexp/nested.jar", &jar),
                payload_file(
                    bin_dir.path(),
                    "/usr/share/shipexp/fcprobe-1-1.tar.gz",
                    &tar_gz,
                ),
                payload_file(
                    bin_dir.path(),
                    "/usr/share/shipexp/tests/data/fixture.bin",
                    FIXTURE_ELF,
                ),
                payload_file(bin_dir.path(), "/usr/share/shipexp/README", b"plain text\n"),
                payload_file(bin_dir.path(), "/usr/lib/firmware/fblob.bin", ELF),
            ],
        );
        // A binary of a foreign build: the builder hard-codes
        // SOURCERPM to "(none)", which no source package answers to.
        let foreign_dir = tempfile::tempdir().unwrap();
        let foreign_path = foreign_dir.path().join("foreign-1.0-1.x86_64.rpm");
        let mut b = rpm::PackageBuilder::new("foreign", "1.0", "MIT", "x86_64", "foreign");
        b.using_config(rpm::BuildConfig::default());
        b.with_file_contents(
            ELF.to_vec(),
            rpm::FileOptions::new("/usr/bin/foreign").mode(rpm::FileMode::regular(0o644)),
        )
        .unwrap();
        let built = b.build().unwrap();
        built
            .write(&mut std::fs::File::create(&foreign_path).unwrap())
            .unwrap();
        let foreign_extract = tempfile::tempdir().unwrap();
        let foreign_pkg =
            Pkg::open(&foreign_path, foreign_extract.path(), true).expect("open foreign binary");

        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SourceCheck::new(&config);
        Check::check(&mut check, &src_pkg, &config, &mut out);
        Check::check(&mut check, &bin_pkg, &config, &mut out);
        Check::check(&mut check, &foreign_pkg, &config, &mut out);
        check.after_checks(&config, &mut out);
        let findings: Vec<(String, String, Level)> = out
            .results()
            .iter()
            .zip(out.result_levels().iter())
            .map(|((n, line), l)| (n.clone(), line.clone(), *l))
            .collect();
        assert_eq!(
            shipped_lines(&findings),
            [
                "fcprobe.x86_64: W: prebuilt-binary-shipped /usr/libexec/shipexp/stripped ELF binary from fcprobe-1-1.tar.gz: src/prebuilt.o",
                "fcprobe.x86_64: W: prebuilt-binary-shipped /usr/share/shipexp/bundle.zip archive with 1 hit from fcprobe-1-1.tar.gz: lib/bundle.zip",
                "fcprobe.x86_64: W: prebuilt-binary-shipped /usr/share/shipexp/fcprobe-1-1.tar.gz archive with 5 hits from fcprobe-1-1.tar.gz",
                "fcprobe.x86_64: W: prebuilt-binary-shipped /usr/share/shipexp/nested.jar Java archive (jar) from fcprobe-1-1.tar.gz: lib/nested.jar",
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
    fn setbadness_payload_scan_skips_the_loaded_file_itself() {
        // The load path reports a loaded rpmlintrc's occurrences, so
        // the payload file that was itself loaded is not reported a
        // second time; a differently named payload file still fires.
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
        let loaded_path = pkg
            .files
            .iter()
            .find(|f| f.name == "loaded-rpmlintrc")
            .map(|f| f.path.clone())
            .expect("payload file present");
        let mut config = test_config();
        config.rpmlintrc_display = vec![loaded_path];
        let findings = run_source_with_config(&pkg, &config);
        assert_eq!(
            setbadness_lines(&findings),
            ["prebuilt-test.src: W: rpmlintrc-uses-setbadness \
              payload-rpmlintrc line 1: setBadness('payload-check', 0)"]
        );
    }

    #[test]
    fn setbadness_payload_scan_does_not_shadow_a_same_named_file() {
        // The dedup keys on the full path: a loaded file elsewhere
        // that merely shares the basename does not shadow the
        // payload file -- both payload rpmlintrc files fire.
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
            [
                "prebuilt-test.src: W: rpmlintrc-uses-setbadness \
              loaded-rpmlintrc line 1: setBadness('loaded-check', 0)",
                "prebuilt-test.src: W: rpmlintrc-uses-setbadness \
              payload-rpmlintrc line 1: setBadness('payload-check', 0)"
            ]
        );
    }

    #[test]
    fn setbadness_payload_scan_reports_same_named_files_in_different_dirs() {
        // Two payload files sharing a basename in different
        // directories are different files: both are scanned, and
        // the detail names each by its full package-relative name.
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("a/dup-rpmlintrc", b"setBadness('a-check', 0)\n".to_vec()),
            ("b/dup-rpmlintrc", b"setBadness('b-check', 0)\n".to_vec()),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            setbadness_lines(&findings),
            [
                "prebuilt-test.src: W: rpmlintrc-uses-setbadness \
              a/dup-rpmlintrc line 1: setBadness('a-check', 0)",
                "prebuilt-test.src: W: rpmlintrc-uses-setbadness \
              b/dup-rpmlintrc line 1: setBadness('b-check', 0)"
            ]
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
        use super::prebuilt::BinaryKind;
        let tar = tarball(&[("src/prebuilt.o", ELF)]);
        let bz2 = bzip2_bytes(&tar);
        let outcome = walk_buffer(&bz2, "t.tar.bz2");
        assert_eq!(
            outcome.prebuilt,
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
        let tar = tarball(&[("src/prebuilt.o", ELF)]);
        let mut fake = b"BZhx".to_vec();
        fake.extend_from_slice(&tar);
        let outcome = walk_buffer(&fake, "t.tar.bz2");
        assert!(outcome.prebuilt.is_empty(), "{:?}", outcome.prebuilt);
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
    fn prebuilt_bare_jar_source_reports_unit_only() {
        // A top-level .jar Source is the unit: the jar fires once
        // and its classes do not fire individually.
        let jar = zip_bytes(&[
            ("com/example/A.class", CLASS),
            ("com/example/B.class", CLASS),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("app-1.0.jar", jar),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            ["prebuilt-test.src: W: prebuilt-binary-in-sources app-1.0.jar Java archive (jar)"]
        );
    }

    #[test]
    fn prebuilt_decompression_depth_is_bounded() {
        // Decompression layers count against the depth limit like
        // nested archives: four gzip layers still reach the ELF, a
        // fifth layer is refused, and a long chain terminates
        // instead of recursing one frame-set per layer.
        let mut four = ELF.to_vec();
        for _ in 0..4 {
            four = gzip_bytes(&four);
        }
        let outcome = walk_buffer(&four, "chain.gz");
        assert_eq!(outcome.prebuilt.len(), 1, "{:?}", outcome.prebuilt);
        assert_eq!(outcome.prebuilt[0].1, "chain.gz");
        let mut five = ELF.to_vec();
        for _ in 0..5 {
            five = gzip_bytes(&five);
        }
        let outcome = walk_buffer(&five, "chain.gz");
        assert!(outcome.prebuilt.is_empty(), "{:?}", outcome.prebuilt);
        let mut hundred = ELF.to_vec();
        for _ in 0..100 {
            hundred = gzip_bytes(&hundred);
        }
        let outcome = walk_buffer(&hundred, "chain.gz");
        assert!(outcome.prebuilt.is_empty(), "{:?}", outcome.prebuilt);
    }

    #[test]
    fn prebuilt_streamed_budget_stop_after_peek() {
        // Budget spent while peeking a decompressed stream stops
        // the walk with a logged budget stop instead of walking an
        // empty buffer silently.
        let tar = tarball(&[("a.o", ELF)]);
        let gz = gzip_bytes(&tar);
        let mut caps = super::prebuilt::CapState::new();
        let mut walker = super::prebuilt::Walker::with_limits(&mut caps, true, 100, usize::MAX);
        walker.walk_archive_buffer(
            &gz,
            super::prebuilt::BufferNames {
                classify: "small.tar.gz",
                bidi: "small.tar.gz",
                stream: "small.tar.gz",
            },
            "small.tar.gz",
            0,
            true,
        );
        let outcome = walker.take_outcome();
        assert!(outcome.prebuilt.is_empty(), "{:?}", outcome.prebuilt);
        assert!(
            outcome.stops.lines().iter().any(|l| l.contains("budget")),
            "{:?}",
            outcome.stops.lines()
        );
    }

    #[test]
    fn prebuilt_streamed_budget_stop_mid_read() {
        // Budget spent mid-buffer stops the walk instead of
        // walking truncated bytes as a complete archive.
        let mut content = ELF.to_vec();
        content.resize(2000, 0);
        let gz = gzip_bytes(&content);
        let mut caps = super::prebuilt::CapState::new();
        let mut walker = super::prebuilt::Walker::with_limits(&mut caps, true, 1000, usize::MAX);
        walker.walk_archive_buffer(
            &gz,
            super::prebuilt::BufferNames {
                classify: "big.bin.gz",
                bidi: "big.bin.gz",
                stream: "big.bin.gz",
            },
            "big.bin.gz",
            0,
            true,
        );
        let outcome = walker.take_outcome();
        assert!(outcome.prebuilt.is_empty(), "{:?}", outcome.prebuilt);
        assert!(
            outcome.stops.lines().iter().any(|l| l.contains("budget")),
            "{:?}",
            outcome.stops.lines()
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
        use super::prebuilt::BinaryKind;
        let outcome = walk_buffer(ELF, "a.o");
        assert_eq!(outcome.prebuilt, [(BinaryKind::Elf, "a.o".to_string())]);
        let outcome = walk_buffer(CLASS, "A.class");
        assert_eq!(
            outcome.prebuilt,
            [(BinaryKind::JavaClass, "A.class".to_string())]
        );
        let outcome = walk_buffer(PYC, "m.pyc");
        assert_eq!(
            outcome.prebuilt,
            [(BinaryKind::PythonBytecode, "m.pyc".to_string())]
        );
        // .pyo shares the pyc format.
        let outcome = walk_buffer(PYC, "m.pyo");
        assert_eq!(
            outcome.prebuilt,
            [(BinaryKind::PythonBytecode, "m.pyo".to_string())]
        );
        // Text is never a binary, whatever its head bytes.
        let outcome = walk_buffer(b"ab\r\ncd", "t.txt");
        assert!(outcome.prebuilt.is_empty());
        // A zip that is not a jar is walked, not flagged.
        let outcome = walk_buffer(b"PK\x03\x04garbage", "a.zip");
        assert!(outcome.prebuilt.is_empty());
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
        let outcome = walk_buffer(&tar, "t.tar");
        assert_eq!(outcome.prebuilt.len(), 1, "{:?}", outcome.prebuilt);
        assert!(outcome.prebuilt[0].1.ends_with("src/prebuilt.o"));
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

    /// UTF-16 bytes for `text` behind the matching byte-order mark.
    fn utf16_bytes(text: &str, le: bool) -> Vec<u8> {
        let mut out = if le {
            vec![0xFF, 0xFE]
        } else {
            vec![0xFE, 0xFF]
        };
        for unit in text.encode_utf16() {
            out.extend_from_slice(&if le {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            });
        }
        out
    }

    #[test]
    fn bidi_controls_in_tarball_members_fire_with_line_and_column() {
        let inner = tarball(&[("nested/evil.rs", "\u{202B}fn main() {}\n".as_bytes())]);
        let tar = tarball(&[
            (
                "src/main.c",
                "int a;\n/* \u{3b1}\u{3b2}\u{3b3} \u{202E}evil */\n".as_bytes(),
            ),
            (
                "src/clean.c",
                "/* \u{3b1}\u{3b2}\u{3b3} \u{2192} \u{3bb} */\nint b;\n".as_bytes(),
            ),
            ("deep/inner.tar.gz", &gzip_bytes(&inner)),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("bidi-1.0.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            archive_lines(&findings, "source-archive-contains-bidi-control"),
            [
                "prebuilt-test.src: W: source-archive-contains-bidi-control \
                 bidi-1.0.tar.gz: deep/inner.tar.gz: nested/evil.rs line 1, column 1 \
                 U+202B RIGHT-TO-LEFT EMBEDDING",
                "prebuilt-test.src: W: source-archive-contains-bidi-control \
                 bidi-1.0.tar.gz: src/main.c line 2, column 8 \
                 U+202E RIGHT-TO-LEFT OVERRIDE",
            ]
        );
    }

    #[test]
    fn bidi_excluded_members_and_binary_members_stay_quiet() {
        let tar = tarball(&[
            ("docs/notes.txt", "x \u{202E}y\n".as_bytes()),
            ("docs/guide.desktop", "x \u{202E}y\n".as_bytes()),
            ("pkg/.git/config", "x \u{202E}y\n".as_bytes()),
            ("Changelog", "x \u{202E}y\n".as_bytes()),
            ("NEWS.md", "x \u{202E}y\n".as_bytes()),
            ("locale/fr.po", "x \u{202E}y\n".as_bytes()),
            ("doc/manual.tex", "x \u{202E}y\n".as_bytes()),
            ("doc/page.html", "x \u{202E}y\n".as_bytes()),
            ("doc/page.htm", "x \u{202E}y\n".as_bytes()),
            ("doc/page.roff", "x \u{202E}y\n".as_bytes()),
            ("src/binary.dat", b"\x89PNG\r\n\x1a\n\xe2\x80\xae"),
            ("src/surrogate.c", &[0xFF, 0xFE, 0x61, 0x00, 0x00, 0xD8]),
            ("src/edge.c", "\u{2029}\u{2060}\u{202F}\n".as_bytes()),
            (
                "src/clean.c",
                "/* \u{3b1}\u{3b2}\u{3b3} \u{2192} \u{3bb} */\n".as_bytes(),
            ),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("bidi-1.0.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert!(
            archive_lines(&findings, "source-archive-contains-bidi-control").is_empty(),
            "{findings:?}"
        );
    }

    #[test]
    fn bidi_zip_member_with_lying_declared_size_still_scanned() {
        // The bidi walk never trusts the central-directory declared
        // size: a member declared huge over a small bidi payload
        // still fires.
        let patch = |z: &mut Vec<u8>, size: u32| {
            let pos = z
                .windows(4)
                .position(|w| w == b"PK\x01\x02")
                .expect("central directory present");
            z[pos + 24..pos + 28].copy_from_slice(&size.to_le_bytes());
        };
        let mut z = zip_bytes(&[("src/evil.c", "int a; \u{202A}int b;\n".as_bytes())]);
        patch(&mut z, 0xFFFF_FFF0);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("bidi-1.0.zip", z),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            archive_lines(&findings, "source-archive-contains-bidi-control"),
            [
                "prebuilt-test.src: W: source-archive-contains-bidi-control \
                 bidi-1.0.zip: src/evil.c line 1, column 8 \
                 U+202A LEFT-TO-RIGHT EMBEDDING",
            ],
        );
    }

    #[test]
    fn bidi_decompressed_zip_members_fire() {
        // A gzip whose decompressed bytes are a zip: the members are
        // walked, not scanned as opaque text.
        let z = zip_bytes(&[("src/inner.c", "int a; \u{202E}int b;\n".as_bytes())]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("outer.zip.gz", gzip_bytes(&z)),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            archive_lines(&findings, "source-archive-contains-bidi-control"),
            [
                "prebuilt-test.src: W: source-archive-contains-bidi-control \
                 outer.zip.gz: src/inner.c line 1, column 8 \
                 U+202E RIGHT-TO-LEFT OVERRIDE",
            ],
        );
    }

    #[test]
    fn bidi_exclusions_fold_case() {
        // ChangeLog, CHANGELOG.md and a .GZ-suffixed single file stay
        // quiet: the exclusion match folds case on both the basename
        // and the compression suffix.
        let tar = tarball(&[
            ("ChangeLog", "x \u{202E}y\n".as_bytes()),
            ("CHANGELOG.md", "x \u{202E}y\n".as_bytes()),
            ("docs/NEWS", "x \u{202E}y\n".as_bytes()),
            ("src/evil.c", "int a; \u{202A}int b;\n".as_bytes()),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("bidi-1.0.tar.gz", gzip_bytes(&tar)),
            ("single.TXT.GZ", gzip_bytes("x \u{202E}y\n".as_bytes())),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            archive_lines(&findings, "source-archive-contains-bidi-control"),
            [
                "prebuilt-test.src: W: source-archive-contains-bidi-control \
                 bidi-1.0.tar.gz: src/evil.c line 1, column 8 \
                 U+202A LEFT-TO-RIGHT EMBEDDING",
            ],
        );
    }

    #[test]
    fn bidi_controls_in_zip_utf16_and_compressed_single_fire() {
        let z = zip_bytes(&[
            ("src/evil.c", "int a; \u{202A}int b;\n".as_bytes()),
            ("src/utf16.c", &utf16_bytes("ab\u{202E}cd\n", true)),
            ("src/be.c", &utf16_bytes("q\u{2069}\n", false)),
            ("src/clean.c", "int c;\n".as_bytes()),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("bidi-1.0.zip", z),
            ("single.c.gz", gzip_bytes("x\u{202D}y\n".as_bytes())),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            archive_lines(&findings, "source-archive-contains-bidi-control"),
            [
                "prebuilt-test.src: W: source-archive-contains-bidi-control \
                 bidi-1.0.zip: src/be.c line 1, column 2 \
                 U+2069 POP DIRECTIONAL ISOLATE",
                "prebuilt-test.src: W: source-archive-contains-bidi-control \
                 bidi-1.0.zip: src/evil.c line 1, column 8 \
                 U+202A LEFT-TO-RIGHT EMBEDDING",
                "prebuilt-test.src: W: source-archive-contains-bidi-control \
                 bidi-1.0.zip: src/utf16.c line 1, column 3 \
                 U+202E RIGHT-TO-LEFT OVERRIDE",
                "prebuilt-test.src: W: source-archive-contains-bidi-control \
                 single.c.gz line 1, column 2 U+202D LEFT-TO-RIGHT OVERRIDE",
            ]
        );
    }

    #[test]
    fn bidi_control_in_plain_payload_stays_quiet_in_sourcecheck() {
        let (pkg, _src, _extract) = source_pkg(&[
            (
                "prebuilt-test.spec",
                "Name: prebuilt-test\n# \u{202E}\n".as_bytes().to_vec(),
            ),
            ("loose.c", "int a; \u{202E}int b;\n".as_bytes().to_vec()),
        ]);
        let findings = run_source(&pkg);
        assert!(
            archive_lines(&findings, "source-archive-contains-bidi-control").is_empty(),
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
        let outcome = walk_buffer(&tar, "t.tar");
        assert_eq!(outcome.vcs.len(), 2);
        assert_eq!(outcome.vcs["a/.git"], (1, 2));
        assert_eq!(outcome.vcs["a/CVS"], (1, 1));
        assert!(outcome.lfs.is_empty());
    }

    #[test]
    fn lfs_gate_is_the_head_length_not_the_declared_size() {
        // The central directory can lie about the size in either
        // direction, while the head is bytes actually read.
        let patch = |z: &mut Vec<u8>, size: u32| {
            let pos = z
                .windows(4)
                .position(|w| w == b"PK\x01\x02")
                .expect("central directory present");
            z[pos + 24..pos + 28].copy_from_slice(&size.to_le_bytes());
        };
        // A huge declared size over a real pointer head still fires:
        // the head is bytes actually read.
        let mut z = zip_bytes(&[("tests/a.test.xz", LFS_POINTER)]);
        patch(&mut z, 0xFFFF_FFF0);
        let outcome = walk_buffer(&z, "t.zip");
        assert_eq!(outcome.lfs, ["tests/a.test.xz"]);
        // A tiny declared size over a 1024-byte head (a longer member
        // whose first bytes quote the pointer) stays quiet.
        let mut long_head = LFS_POINTER.to_vec();
        long_head.resize(1024, b' ');
        let mut z = zip_bytes(&[("tests/a.test.xz", &long_head)]);
        patch(&mut z, 10);
        let outcome = walk_buffer(&z, "t.zip");
        assert!(outcome.lfs.is_empty());
        // An unreadable member (empty head) stays quiet.
        let z = zip_bytes(&[("tests/a.test.xz", b"")]);
        let outcome = walk_buffer(&z, "t.zip");
        assert!(outcome.lfs.is_empty());
    }

    #[test]
    fn lfs_crlf_pointers_fire() {
        let tar = tarball(&[
            (
                "tests/a.test.xz",
                b"version https://git-lfs.github.com/spec/v1\r\noid sha256:0123\r\nsize 12\r\n",
            ),
            (
                "tests/b.test.xz",
                b"version https://hawser.github.com/spec/v1\r\noid sha256:0123\r\n",
            ),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            (
                "prebuilt-test.spec",
                spec_with_source("lfs-crlf-1.0.tar.gz"),
            ),
            ("lfs-crlf-1.0.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            archive_lines(&findings, "source-archive-contains-lfs-pointer"),
            [
                "prebuilt-test.src: W: source-archive-contains-lfs-pointer \
                 lfs-crlf-1.0.tar.gz: tests/a.test.xz",
                "prebuilt-test.src: W: source-archive-contains-lfs-pointer \
                 lfs-crlf-1.0.tar.gz: tests/b.test.xz",
            ]
        );
    }

    #[test]
    fn zip_member_with_corrupt_data_still_counts_for_vcs() {
        // A stored member whose data fails its CRC is unreadable:
        // the walk skips it, but the member still counts toward its
        // VCS root (with an empty head, so no LFS verdict either).
        let mut z = zip_bytes(&[("pkg/.git/config", b"VCS-DATA-PAYLOAD")]);
        let pos = z
            .windows(b"VCS-DATA-PAYLOAD".len())
            .position(|w| w == b"VCS-DATA-PAYLOAD")
            .expect("stored payload is verbatim");
        z[pos + 2] ^= 0xFF;
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", spec_with_source("vcs-1.0.zip")),
            ("vcs-1.0.zip", z),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            archive_lines(&findings, "source-archive-contains-vcs-metadata"),
            [
                "prebuilt-test.src: W: source-archive-contains-vcs-metadata \
               vcs-1.0.zip pkg/.git 1 entries 16 bytes"
            ]
        );
        assert!(
            archive_lines(&findings, "source-archive-contains-lfs-pointer").is_empty(),
            "{findings:?}"
        );
    }

    #[test]
    fn zip_lying_declared_size_does_not_hide_or_fake_a_pointer() {
        // Patch the central directory's uncompressed-size field: the
        // declared size is what the old gate trusted.
        let patch = |z: &mut Vec<u8>, size: u32| {
            let pos = z
                .windows(4)
                .position(|w| w == b"PK\x01\x02")
                .expect("central directory present");
            z[pos + 24..pos + 28].copy_from_slice(&size.to_le_bytes());
        };
        // Declared huge over a real pointer payload: the head is
        // read anyway and the pointer fires.
        let mut z = zip_bytes(&[("tests/a.test.xz", LFS_POINTER)]);
        patch(&mut z, 0xFFFF_FFF0);
        let outcome = walk_buffer(&z, "t.zip");
        assert_eq!(outcome.lfs, ["tests/a.test.xz"]);
        // Declared tiny over a 1500-byte payload quoting the pointer
        // text: the head is the actual first 1024 bytes, too long
        // for a pointer, so it stays quiet.
        let mut big = LFS_POINTER.to_vec();
        big.resize(1500, b' ');
        let mut z = zip_bytes(&[("tests/a.test.xz", &big)]);
        patch(&mut z, 10);
        let outcome = walk_buffer(&z, "t.zip");
        assert!(outcome.lfs.is_empty());
    }

    /// Drive the walker over an in-memory archive buffer, as a
    /// top-level Source with no finding cap and no budget pressure.
    fn walk_buffer(data: &[u8], name: &str) -> super::prebuilt::WalkOutcome {
        let mut caps = super::prebuilt::CapState::new();
        let mut walker =
            super::prebuilt::Walker::with_limits(&mut caps, true, u64::MAX, usize::MAX);
        walker.walk_archive_buffer(
            data,
            super::prebuilt::BufferNames {
                classify: name,
                bidi: name,
                stream: name,
            },
            name,
            0,
            true,
        );
        walker.take_outcome()
    }

    /// Drive the tar-stream walker over a stream, as a top-level
    /// Source with production limits and no counting reader: the
    /// stream itself is what is under test, not the budget.
    fn walk_tar_stream_bytes(
        stream: impl std::io::Read,
        ctx: &str,
    ) -> super::prebuilt::WalkOutcome {
        let mut caps = super::prebuilt::CapState::new();
        let mut walker = super::prebuilt::Walker::new(&mut caps, true);
        walker.walk_tar_stream(super::prebuilt::TarStream::new(stream), ctx, 0, true);
        walker.take_outcome()
    }

    /// One ustar header: an octal size, or a GNU base-256 size when
    /// asked (the high bit of byte 124 set, then a big-endian number,
    /// for members of 8 GiB or more).
    fn ustar_header(name: &str, size: u64, base256: bool) -> Vec<u8> {
        let mut hdr = [0u8; 512];
        hdr[..name.len()].copy_from_slice(name.as_bytes());
        if base256 {
            let mut field = [0u8; 12];
            field[0] = 0x80;
            field[4..12].copy_from_slice(&size.to_be_bytes());
            hdr[124..136].copy_from_slice(&field);
        } else {
            let size_field = format!("{size:011o}\0");
            hdr[124..136].copy_from_slice(size_field.as_bytes());
        }
        hdr[156] = b'0';
        hdr[257..262].copy_from_slice(b"ustar");
        hdr.to_vec()
    }

    /// An xz stream whose LZMA2 dictionary is declared at 256 MiB,
    /// over the 128 MiB decoder memlimit: the block header parses,
    /// then the decoder refuses before allocating the dictionary.
    fn xz_huge_dict_stream() -> Vec<u8> {
        let mut out = b"\xfd7zXZ\x00".to_vec();
        let flags = [0x00u8, 0x01];
        let mut crc = flate2::Crc::new();
        crc.update(&flags);
        out.extend_from_slice(&flags);
        out.extend_from_slice(&crc.sum().to_le_bytes());
        let mut header = vec![2u8, 0x00, 0x21, 0x01, 32, 0, 0, 0];
        let mut crc = flate2::Crc::new();
        crc.update(&header);
        header.extend_from_slice(&crc.sum().to_le_bytes());
        out.extend_from_slice(&header);
        out
    }

    #[test]
    fn large_archive_streams_past_old_cap() {
        // The old 256 MiB whole-archive cap: a tar whose members total
        // past it is walked, not skipped, and the member after 260 MiB
        // of streamed zero padding still fires.
        let pad = 260u64 * 1024 * 1024;
        let elf_member = tarball(&[("after.o", ELF)]);
        let stream = std::io::Cursor::new(ustar_header("big.bin", pad, false))
            .chain(std::io::repeat(0u8).take(pad))
            .chain(std::io::Cursor::new(elf_member));
        let outcome = walk_tar_stream_bytes(stream, "big.tar");
        assert_eq!(outcome.prebuilt.len(), 1, "{:?}", outcome.prebuilt);
        assert!(outcome.prebuilt[0].1.ends_with("after.o"));
        assert!(outcome.stops.lines().is_empty());
    }

    #[test]
    fn bidi_member_after_large_padding_fires() {
        let pad = 260u64 * 1024 * 1024;
        let text_member = tarball(&[("src/evil.c", "int a; \u{202A}int b;\n".as_bytes())]);
        let stream = std::io::Cursor::new(ustar_header("big.bin", pad, false))
            .chain(std::io::repeat(0u8).take(pad))
            .chain(std::io::Cursor::new(text_member));
        let outcome = walk_tar_stream_bytes(stream, "big.tar");
        assert_eq!(outcome.bidi.len(), 1);
        assert!(outcome.bidi[0].path.ends_with("src/evil.c"));
    }

    #[test]
    fn vcs_counts_oversized_git_member_at_declared_size() {
        let size = 64u64 * 1024 * 1024 + 12345;
        let small = tarball(&[("llama.cpp/.git/objects/pack/small.pack", b"xxxxx")]);
        // The member's data is followed by its 512-byte-block padding
        // before the next header, like any tar member.
        let pad = (512 - size % 512) % 512;
        let stream = std::io::Cursor::new(ustar_header(
            "llama.cpp/.git/objects/pack/big.pack",
            size,
            false,
        ))
        .chain(std::io::repeat(0u8).take(size))
        .chain(std::io::repeat(0u8).take(pad))
        .chain(std::io::Cursor::new(small));
        let outcome = walk_tar_stream_bytes(stream, "big.tar");
        assert_eq!(outcome.vcs.len(), 1);
        assert_eq!(outcome.vcs["llama.cpp/.git"], (2, size + 5));
    }

    #[test]
    fn base256_size_members_are_walked() {
        // Both members carry GNU base-256 size fields: the walk reads
        // them as such instead of stopping at the first header.
        let mut tar = Vec::new();
        for name in ["a.o", "b.o"] {
            tar.extend_from_slice(&ustar_header(name, ELF.len() as u64, true));
            tar.extend_from_slice(ELF);
            tar.extend_from_slice(&vec![0u8; (512 - ELF.len() % 512) % 512]);
        }
        tar.extend_from_slice(&[0u8; 1024]);
        let outcome = walk_buffer(&tar, "b256.tar");
        assert_eq!(outcome.prebuilt.len(), 2, "{:?}", outcome.prebuilt);
    }

    #[test]
    fn oversized_member_with_elf_head_stays_quiet() {
        // A ustar header whose size field is 77777777777 (8 GiB - 1),
        // followed by 64 bytes starting with the ELF magic, then EOF:
        // no finding, no panic, no allocation above the entry cap.
        let mut tar = ustar_header("huge.bin", 8 * 1024 * 1024 * 1024 - 1, false);
        let mut head = ELF.to_vec();
        head.resize(64, 0);
        tar.extend_from_slice(&head);
        let outcome = walk_tar_stream_bytes(std::io::Cursor::new(tar), "huge.tar");
        assert!(outcome.prebuilt.is_empty());
        assert!(outcome.vcs.is_empty());
        assert!(outcome.lfs.is_empty());
        assert!(outcome.bidi.is_empty());
        assert!(outcome.stops.lines().is_empty());
    }

    #[test]
    fn budget_stop_keeps_earlier_findings() {
        let tar = tarball(&[("first.o", ELF), ("second.o", ELF)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("budget.tar");
        std::fs::write(&path, &tar).unwrap();
        let mut caps = super::prebuilt::CapState::new();
        let mut walker = super::prebuilt::Walker::with_limits(&mut caps, true, 1100, usize::MAX);
        walker.walk_file(&path, "budget.tar");
        let outcome = walker.take_outcome();
        assert_eq!(outcome.prebuilt.len(), 1, "{:?}", outcome.prebuilt);
        assert!(outcome.prebuilt[0].1.ends_with("first.o"));
        assert!(
            outcome.stops.lines().iter().any(|l| l.contains("budget")),
            "{:?}",
            outcome.stops.lines()
        );
    }

    #[test]
    fn finding_cap_reports_exactly_cap() {
        let tar = tarball(&[("a.o", ELF), ("b.o", ELF), ("c.o", ELF)]);
        let mut caps = super::prebuilt::CapState::new();
        let mut walker = super::prebuilt::Walker::with_limits(&mut caps, true, u64::MAX, 2);
        walker.walk_archive_buffer(
            &tar,
            super::prebuilt::BufferNames {
                classify: "cap.tar",
                bidi: "cap.tar",
                stream: "cap.tar",
            },
            "cap.tar",
            0,
            true,
        );
        let outcome = walker.take_outcome();
        assert_eq!(outcome.prebuilt.len(), 2, "{:?}", outcome.prebuilt);
        assert!(
            outcome
                .stops
                .lines()
                .iter()
                .any(|l| l.contains("finding cap")),
            "{:?}",
            outcome.stops.lines()
        );
    }

    #[test]
    fn compressed_single_elf_over_64_mib_not_walked() {
        let mut plain = ELF.to_vec();
        plain.resize(64 * 1024 * 1024 + 1, 0);
        let gz = gzip_bytes(&plain);
        let outcome = walk_buffer(&gz, "big.elf.gz");
        assert!(outcome.prebuilt.is_empty());
        assert!(
            outcome
                .stops
                .lines()
                .iter()
                .any(|l| l.contains("over 64 MiB")),
            "{:?}",
            outcome.stops.lines()
        );
    }

    #[test]
    fn compressed_single_elf_under_64_mib_fires() {
        let gz = gzip_bytes(ELF);
        let outcome = walk_buffer(&gz, "small.elf.gz");
        assert_eq!(outcome.prebuilt.len(), 1, "{:?}", outcome.prebuilt);
        assert_eq!(outcome.prebuilt[0].1, "small.elf.gz");
    }

    #[test]
    fn xz_memlimit_stops_single_and_tar_xz() {
        for name in ["huge.xz", "huge.tar.xz"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(name);
            std::fs::write(&path, xz_huge_dict_stream()).unwrap();
            let mut caps = super::prebuilt::CapState::new();
            let mut walker = super::prebuilt::Walker::new(&mut caps, true);
            walker.walk_file(&path, name);
            let outcome = walker.take_outcome();
            assert!(outcome.prebuilt.is_empty(), "{name}");
            assert!(
                outcome
                    .stops
                    .lines()
                    .iter()
                    .any(|l| l.contains("memory limit")),
                "{name}: {:?}",
                outcome.stops.lines()
            );
        }
    }

    #[test]
    fn zip_source_from_file_fires_and_oversized_zip_skips() {
        let z = zip_bytes(&[("payload.o", ELF)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sources.zip");
        std::fs::write(&path, &z).unwrap();
        let mut caps = super::prebuilt::CapState::new();
        let mut walker = super::prebuilt::Walker::new(&mut caps, true);
        walker.walk_file(&path, "sources.zip");
        let outcome = walker.take_outcome();
        assert_eq!(outcome.prebuilt.len(), 1, "{:?}", outcome.prebuilt);
        // A zip Source over 256 MiB on disk is skipped, now with a report.
        let sparse = dir.path().join("huge.zip");
        let mut f = std::fs::File::create(&sparse).unwrap();
        f.write_all(b"PK\x03\x04").unwrap();
        f.set_len(256 * 1024 * 1024 + 1).unwrap();
        drop(f);
        let mut caps = super::prebuilt::CapState::new();
        let mut walker = super::prebuilt::Walker::new(&mut caps, true);
        walker.walk_file(&sparse, "huge.zip");
        let outcome = walker.take_outcome();
        assert!(outcome.prebuilt.is_empty());
        assert!(
            outcome.stops.lines().iter().any(|l| l.contains("256 MiB")),
            "{:?}",
            outcome.stops.lines()
        );
    }

    #[test]
    fn small_plain_tar_from_file_fires() {
        let tar = tarball(&[("src/prebuilt.o", ELF)]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.tar");
        std::fs::write(&path, &tar).unwrap();
        let mut caps = super::prebuilt::CapState::new();
        let mut walker = super::prebuilt::Walker::new(&mut caps, true);
        walker.walk_file(&path, "plain.tar");
        let outcome = walker.take_outcome();
        assert_eq!(outcome.prebuilt.len(), 1, "{:?}", outcome.prebuilt);
        assert!(outcome.prebuilt[0].1.ends_with("src/prebuilt.o"));
    }

    #[test]
    fn new_kinds_fire_in_tarball_and_group_per_directory() {
        let pe = pe_dll();
        let tar = tarball(&[
            ("m/hello.o", ELF),
            ("m/libf.a", &ar_archive("/", b"\x00\x00\x00\x01")),
            ("m/libg.a", &ar_archive("/", b"\x00\x00\x00\x01")),
            ("m/lib.dll", &pe),
            ("m/mod.wasm", WASM),
            ("m/thin.a", &thin_archive()),
            ("m/text.a", &ar_archive("a.txt", b"a\n")),
            ("m/pkg.deb", &deb_package()),
            ("m/noidx.a", &ar_archive("hello.o/", ELF)),
            ("m/mzstub.exe", &mz_stub()),
            ("m/mzpast.exe", &mz_past()),
            ("m/mz.txt", &mz_txt()),
            ("m/component.wasm", WASM_COMPONENT),
            ("m/v2.wasm", WASM_V2),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("kinds.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            [
                "prebuilt-test.src: W: prebuilt-binary-in-sources kinds.tar.gz: m/* ar archive (2 files)",
                "prebuilt-test.src: W: prebuilt-binary-in-sources kinds.tar.gz: m/hello.o ELF binary",
                "prebuilt-test.src: W: prebuilt-binary-in-sources kinds.tar.gz: m/lib.dll PE executable or DLL",
                "prebuilt-test.src: W: prebuilt-binary-in-sources kinds.tar.gz: m/mod.wasm WebAssembly module",
            ]
        );
    }

    #[test]
    fn new_kinds_fire_in_zip_and_group_per_directory() {
        let pe = pe_dll();
        let z = zip_bytes(&[
            ("m/hello.o", ELF),
            ("m/libf.a", &ar_archive("/", b"\x00\x00\x00\x01")),
            ("m/libg.a", &ar_archive("/", b"\x00\x00\x00\x01")),
            ("m/lib.dll", &pe),
            ("m/mod.wasm", WASM),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("kinds.zip", z),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            [
                "prebuilt-test.src: W: prebuilt-binary-in-sources kinds.zip: m/* ar archive (2 files)",
                "prebuilt-test.src: W: prebuilt-binary-in-sources kinds.zip: m/hello.o ELF binary",
                "prebuilt-test.src: W: prebuilt-binary-in-sources kinds.zip: m/lib.dll PE executable or DLL",
                "prebuilt-test.src: W: prebuilt-binary-in-sources kinds.zip: m/mod.wasm WebAssembly module",
            ]
        );
    }

    #[test]
    fn new_kinds_fire_in_nested_tarball_and_group_per_directory() {
        let pe = pe_dll();
        let inner = tarball(&[
            ("m/hello.o", ELF),
            ("m/libf.a", &ar_archive("/", b"\x00\x00\x00\x01")),
            ("m/libg.a", &ar_archive("/", b"\x00\x00\x00\x01")),
            ("m/lib.dll", &pe),
            ("m/mod.wasm", WASM),
        ]);
        let outer = tarball(&[("n/inner.tar.gz", &gzip_bytes(&inner))]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("nested.tar.gz", gzip_bytes(&outer)),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            [
                "prebuilt-test.src: W: prebuilt-binary-in-sources nested.tar.gz: n/inner.tar.gz: m/* ar archive (2 files)",
                "prebuilt-test.src: W: prebuilt-binary-in-sources nested.tar.gz: n/inner.tar.gz: m/hello.o ELF binary",
                "prebuilt-test.src: W: prebuilt-binary-in-sources nested.tar.gz: n/inner.tar.gz: m/lib.dll PE executable or DLL",
                "prebuilt-test.src: W: prebuilt-binary-in-sources nested.tar.gz: n/inner.tar.gz: m/mod.wasm WebAssembly module",
            ]
        );
    }

    #[test]
    fn new_kinds_fire_as_bare_sources_ungrouped() {
        let pe = pe_dll();
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("libf.a", ar_archive("/", b"\x00\x00\x00\x01")),
            ("libg.a", ar_archive("/", b"\x00\x00\x00\x01")),
            ("lib.dll", pe),
            ("mod.wasm", WASM.to_vec()),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            [
                "prebuilt-test.src: W: prebuilt-binary-in-sources lib.dll PE executable or DLL",
                "prebuilt-test.src: W: prebuilt-binary-in-sources libf.a ar archive",
                "prebuilt-test.src: W: prebuilt-binary-in-sources libg.a ar archive",
                "prebuilt-test.src: W: prebuilt-binary-in-sources mod.wasm WebAssembly module",
            ]
        );
    }

    #[test]
    fn new_kinds_fire_regardless_of_member_extension() {
        // ar, PE and WebAssembly need no name gate: the same bytes
        // fire under extensions that match no kind, unlike .pyc/.pyo
        // and .jar members, which need their names.
        let pe = pe_dll();
        let tar = tarball(&[
            ("m/lib.bin", &ar_archive("/", b"\x00\x00\x00\x01")),
            ("m/prog.dat", &pe),
            ("m/mod.txt", WASM),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("kinds.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            [
                "prebuilt-test.src: W: prebuilt-binary-in-sources kinds.tar.gz: m/lib.bin ar archive",
                "prebuilt-test.src: W: prebuilt-binary-in-sources kinds.tar.gz: m/mod.txt WebAssembly module",
                "prebuilt-test.src: W: prebuilt-binary-in-sources kinds.tar.gz: m/prog.dat PE executable or DLL",
            ]
        );
    }

    #[test]
    fn ar_index_name_variants_fire() {
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("sym64.a", ar_archive("/SYM64/", b"\x00\x00\x00\x01")),
            ("symdef.a", ar_archive("__.SYMDEF", b"\x00\x00\x00\x01")),
            (
                "symdef_sorted.a",
                ar_archive("__.SYMDEF SORTED", b"\x00\x00\x00\x01"),
            ),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            [
                "prebuilt-test.src: W: prebuilt-binary-in-sources sym64.a ar archive",
                "prebuilt-test.src: W: prebuilt-binary-in-sources symdef.a ar archive",
                "prebuilt-test.src: W: prebuilt-binary-in-sources symdef_sorted.a ar archive",
            ]
        );
    }

    #[test]
    fn root_level_ar_members_group_with_star() {
        let tar = tarball(&[
            ("a.a", &ar_archive("/", b"\x00\x00\x00\x01")),
            ("b.a", &ar_archive("/", b"\x00\x00\x00\x01")),
            ("mod.wasm", WASM),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("kinds.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            [
                "prebuilt-test.src: W: prebuilt-binary-in-sources kinds.tar.gz: * ar archive (2 files)",
                "prebuilt-test.src: W: prebuilt-binary-in-sources kinds.tar.gz: mod.wasm WebAssembly module",
            ]
        );
    }

    #[test]
    fn near_miss_members_stay_quiet() {
        let tar = tarball(&[
            ("thin.a", &thin_archive()),
            ("text.a", &ar_archive("a.txt", b"a\n")),
            ("pkg.deb", &deb_package()),
            ("noidx.a", &ar_archive("hello.o/", ELF)),
            ("mzstub.exe", &mz_stub()),
            ("mzpast.exe", &mz_past()),
            ("mz.txt", &mz_txt()),
            ("component.wasm", WASM_COMPONENT),
            ("v2.wasm", WASM_V2),
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("kinds.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert!(
            prebuilt_lines(&findings).is_empty(),
            "unexpected: {:?}",
            prebuilt_lines(&findings)
        );
    }

    #[test]
    fn pax_path_names_long_member() {
        let long = format!("long/{}/mod.pyc", "x".repeat(93));
        assert_eq!(long.len(), 106);
        let cut = long[..100].to_string();
        let mut x = Vec::new();
        x.extend_from_slice(&pax_record("path", &long));
        let tar = tarball_pax(&[PaxMember {
            x: &x,
            ..PaxMember::regular(&cut, PYC)
        }]);
        let outcome = walk_buffer(&tar, "t.tar");
        assert_eq!(
            outcome.prebuilt,
            [(
                super::prebuilt::BinaryKind::PythonBytecode,
                format!("t.tar: {long}")
            )]
        );
    }

    #[test]
    fn pax_size_sizes_member_and_keeps_alignment() {
        let mut first = ELF.to_vec();
        first.resize(64, 0);
        let mut x = Vec::new();
        x.extend_from_slice(&pax_record("size", "64"));
        let tar = tarball_pax(&[
            PaxMember {
                x: &x,
                size: Some(0),
                ..PaxMember::regular("first.bin", &first)
            },
            PaxMember::regular("second.bin", ELF),
        ]);
        // The pax `size` stands (first.bin fires on its 64 bytes) and
        // alignment holds (second.bin fires too).
        let outcome = walk_buffer(&tar, "t.tar");
        assert_eq!(
            outcome.prebuilt,
            [
                (
                    super::prebuilt::BinaryKind::Elf,
                    "t.tar: first.bin".to_string()
                ),
                (
                    super::prebuilt::BinaryKind::Elf,
                    "t.tar: second.bin".to_string()
                ),
            ]
        );
    }

    #[test]
    fn pax_path_beats_long_name() {
        let pax = format!("long/{}/mod.pyc", "x".repeat(93));
        let lname = format!("other/{}/mod.pyc", "y".repeat(91));
        let cut = pax[..100].to_string();
        let mut x = Vec::new();
        x.extend_from_slice(&pax_record("path", &pax));
        let tar = tarball_pax(&[PaxMember {
            x: &x,
            long: Some(&lname),
            ..PaxMember::regular(&cut, PYC)
        }]);
        let outcome = walk_buffer(&tar, "t.tar");
        assert_eq!(
            outcome.prebuilt,
            [(
                super::prebuilt::BinaryKind::PythonBytecode,
                format!("t.tar: {pax}")
            )]
        );
    }

    #[test]
    fn pax_size_survives_long_name() {
        let mut data = ELF.to_vec();
        data.resize(48, 0);
        let mut x = Vec::new();
        x.extend_from_slice(&pax_record("size", "48"));
        let tar = tarball_pax(&[
            PaxMember {
                x: &x,
                long: Some("some/long/name.bin"),
                size: Some(0),
                ..PaxMember::regular("cut.bin", &data)
            },
            PaxMember::regular("after.bin", ELF),
        ]);
        let outcome = walk_buffer(&tar, "t.tar");
        // The `L` name wins for the name (no pax `path`), the pax `size`
        // for the size, and the member after it proves the `L` data was
        // read at its own size.
        assert_eq!(
            outcome.prebuilt,
            [
                (
                    super::prebuilt::BinaryKind::Elf,
                    "t.tar: some/long/name.bin".to_string()
                ),
                (
                    super::prebuilt::BinaryKind::Elf,
                    "t.tar: after.bin".to_string()
                ),
            ]
        );
    }

    #[test]
    fn pax_path_dropped_by_non_member() {
        let mut x = Vec::new();
        x.extend_from_slice(&pax_record("path", "should/not/carry.bin"));
        let tar = tarball_pax(&[
            PaxMember {
                x: &x,
                typeflag: b'5',
                ..PaxMember::regular("dir/", &[])
            },
            PaxMember::regular("real.bin", ELF),
            PaxMember {
                x: &x,
                typeflag: b'2',
                ..PaxMember::regular("link", &[])
            },
            PaxMember::regular("real2.bin", ELF),
        ]);
        let outcome = walk_buffer(&tar, "t.tar");
        assert_eq!(
            outcome.prebuilt,
            [
                (
                    super::prebuilt::BinaryKind::Elf,
                    "t.tar: real.bin".to_string()
                ),
                (
                    super::prebuilt::BinaryKind::Elf,
                    "t.tar: real2.bin".to_string()
                ),
            ]
        );
    }

    #[test]
    fn pax_global_path_ignored() {
        let mut g = Vec::new();
        g.extend_from_slice(&pax_record("path", "global/rename.bin"));
        let tar = tarball_pax(&[PaxMember {
            g: &g,
            ..PaxMember::regular("real.bin", ELF)
        }]);
        let outcome = walk_buffer(&tar, "t.tar");
        assert_eq!(
            outcome.prebuilt,
            [(
                super::prebuilt::BinaryKind::Elf,
                "t.tar: real.bin".to_string()
            )]
        );
    }

    #[test]
    fn pax_malformed_record_keeps_ustar_name() {
        // Length is not a number.
        let tar = tarball_pax(&[PaxMember {
            x: b"xx path=should/not/carry.bin\n",
            ..PaxMember::regular("a.bin", ELF)
        }]);
        let outcome = walk_buffer(&tar, "t.tar");
        assert_eq!(
            outcome.prebuilt,
            [(super::prebuilt::BinaryKind::Elf, "t.tar: a.bin".to_string())]
        );
        // Length runs past the header data.
        let tar = tarball_pax(&[PaxMember {
            x: b"9999 path=should/not/carry.bin\n",
            ..PaxMember::regular("b.bin", ELF)
        }]);
        let outcome = walk_buffer(&tar, "t.tar");
        assert_eq!(
            outcome.prebuilt,
            [(super::prebuilt::BinaryKind::Elf, "t.tar: b.bin".to_string())]
        );
    }

    #[test]
    fn pax_path_past_4kib_keeps_ustar_name() {
        // Fill past the reader's 4 KiB cap with comment records, then a
        // path record: the member keeps its ustar name, and nothing over
        // 4 KiB is allocated for the header.
        let mut x = Vec::new();
        while x.len() <= 4096 {
            x.extend_from_slice(&pax_record("comment", "padding"));
        }
        x.extend_from_slice(&pax_record("path", "should/not/carry.bin"));
        let tar = tarball_pax(&[PaxMember {
            x: &x,
            ..PaxMember::regular("real.bin", ELF)
        }]);
        let outcome = walk_buffer(&tar, "t.tar");
        assert_eq!(
            outcome.prebuilt,
            [(
                super::prebuilt::BinaryKind::Elf,
                "t.tar: real.bin".to_string()
            )]
        );
    }

    #[test]
    fn paxexp_dispatch_names_long_members() {
        let jar = zip_bytes(&[("p/A.class", CLASS)]);
        let dir = format!("long/{}", "x".repeat(93));
        let elf = format!("{dir}/elf.bin");
        let jar_name = format!("{dir}/lib.jar");
        let pyc = format!("{dir}/mod.pyc");
        let elf_cut = elf[..100].to_string();
        let jar_cut = jar_name[..100].to_string();
        let pyc_cut = pyc[..100].to_string();
        let mut x_elf = Vec::new();
        x_elf.extend_from_slice(&pax_record("path", &elf));
        let mut x_jar = Vec::new();
        x_jar.extend_from_slice(&pax_record("path", &jar_name));
        let mut x_pyc = Vec::new();
        x_pyc.extend_from_slice(&pax_record("path", &pyc));
        let tar = tarball_pax(&[
            PaxMember::regular("short/elf.bin", ELF),
            PaxMember::regular("short/lib.jar", &jar),
            PaxMember::regular("short/mod.pyc", PYC),
            PaxMember {
                x: &x_elf,
                ..PaxMember::regular(&elf_cut, ELF)
            },
            PaxMember {
                x: &x_jar,
                ..PaxMember::regular(&jar_cut, &jar)
            },
            PaxMember {
                x: &x_pyc,
                ..PaxMember::regular(&pyc_cut, PYC)
            },
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("paxexp.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        // Sorted, as the helper sorts: the long jar fires as a unit, with
        // no class line for it.
        assert_eq!(
            prebuilt_lines(&findings),
            vec![
                format!(
                    "prebuilt-test.src: W: prebuilt-binary-in-sources paxexp.tar.gz: {elf} ELF binary"
                ),
                format!(
                    "prebuilt-test.src: W: prebuilt-binary-in-sources paxexp.tar.gz: {jar_name} Java archive (jar)"
                ),
                format!(
                    "prebuilt-test.src: W: prebuilt-binary-in-sources paxexp.tar.gz: {pyc} Python bytecode"
                ),
                "prebuilt-test.src: W: prebuilt-binary-in-sources paxexp.tar.gz: short/elf.bin ELF binary"
                    .to_string(),
                "prebuilt-test.src: W: prebuilt-binary-in-sources paxexp.tar.gz: short/lib.jar Java archive (jar)"
                    .to_string(),
                "prebuilt-test.src: W: prebuilt-binary-in-sources paxexp.tar.gz: short/mod.pyc Python bytecode"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn vcsexp_dispatch_names_long_git_root() {
        let dir = format!("long/{}", "x".repeat(93));
        let long_config = format!("{dir}/.git/config");
        let long_head = format!("{dir}/.git/HEAD");
        let mut x_config = Vec::new();
        x_config.extend_from_slice(&pax_record("path", &long_config));
        let mut x_head = Vec::new();
        x_head.extend_from_slice(&pax_record("path", &long_head));
        let tar = tarball_pax(&[
            PaxMember::regular("short/.git/config", b"[core]\n"),
            PaxMember::regular("short/.git/HEAD", b"ref: refs/heads/main\n"),
            PaxMember {
                x: &x_config,
                ..PaxMember::regular(&long_config[..100], b"[core]\n")
            },
            PaxMember {
                x: &x_head,
                ..PaxMember::regular(&long_head[..100], b"ref: refs/heads/main\n")
            },
        ]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", spec_with_source("vcsexp.tar.gz")),
            ("vcsexp.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            archive_lines(&findings, "source-archive-contains-vcs-metadata"),
            vec![
                format!(
                    "prebuilt-test.src: W: source-archive-contains-vcs-metadata vcsexp.tar.gz {dir}/.git 2 entries 28 bytes"
                ),
                "prebuilt-test.src: W: source-archive-contains-vcs-metadata vcsexp.tar.gz short/.git 2 entries 28 bytes"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn pax_names_survive_zip_nesting() {
        let long = format!("long/{}/mod.pyc", "x".repeat(93));
        let cut = long[..100].to_string();
        let mut x = Vec::new();
        x.extend_from_slice(&pax_record("path", &long));
        let inner = tarball_pax(&[PaxMember {
            x: &x,
            ..PaxMember::regular(&cut, PYC)
        }]);
        let zip = zip_bytes(&[("inner.tar.gz", &gzip_bytes(&inner))]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("outer.zip", zip),
        ]);
        let findings = run_source(&pkg);
        assert_eq!(
            prebuilt_lines(&findings),
            vec![format!(
                "prebuilt-test.src: W: prebuilt-binary-in-sources outer.zip: inner.tar.gz: {long} Python bytecode"
            )]
        );
    }

    #[test]
    fn pax_path_bidi_exclusion_uses_full_name() {
        // The excluded `.txt` suffix lives only in the pax `path`: under
        // the cut ustar name this member fires, under its full name it
        // stays quiet.
        let full = format!("long/{}/note.txt", "x".repeat(93));
        let cut = full[..100].to_string();
        let mut x = Vec::new();
        x.extend_from_slice(&pax_record("path", &full));
        let tar = tarball_pax(&[PaxMember {
            x: &x,
            ..PaxMember::regular(&cut, "hello \u{202e} world\n".as_bytes())
        }]);
        let (pkg, _src, _extract) = source_pkg(&[
            ("prebuilt-test.spec", b"Name: prebuilt-test\n".to_vec()),
            ("bidi-1.0.tar.gz", gzip_bytes(&tar)),
        ]);
        let findings = run_source(&pkg);
        assert!(archive_lines(&findings, "source-archive-contains-bidi-control").is_empty());
    }
}
