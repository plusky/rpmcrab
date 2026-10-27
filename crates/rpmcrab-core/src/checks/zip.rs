//! `ZipCheck` — validate zip/jar archives.
//!
//! Ported from `rpmlint/checks/ZipCheck.py`. Three findings:
//! `unable-to-read-zip` (error, or warning when the archive only fails like
//! the reference's `RuntimeError` path), `bad-crc-in-zip`,
//! `class-path-in-manifest`.
//!
//! Uses the pure-Rust `zip` crate instead of CPython's `zipfile`; no
//! subprocesses.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use fancy_regex::Regex;
use zip::ZipArchive;
use zip::result::ZipError;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use std::sync::OnceLock;

static ZIP_REGEX: OnceLock<Regex> = OnceLock::new();
fn zip_regex() -> &'static Regex {
    ZIP_REGEX.get_or_init(|| Regex::new(r"\.(zip|[ewj]ar)$").expect("static regex"))
}

static JAR_REGEX: OnceLock<Regex> = OnceLock::new();
fn jar_regex() -> &'static Regex {
    JAR_REGEX.get_or_init(|| Regex::new(r"\.[ewj]ar$").expect("static regex"))
}

static CLASSPATH_REGEX: OnceLock<Regex> = OnceLock::new();
fn classpath_regex() -> &'static Regex {
    CLASSPATH_REGEX.get_or_init(|| Regex::new(r"(?im)^\s*Class-Path\s*:").expect("static regex"))
}

/// Cap on one entry's inflated bytes, the `checks::source` idiom: an
/// entry inflating past the cap is reported instead of inflated, so a
/// highly-compressible entry cannot grow the heap without bound.
const MAX_ENTRY_BYTES: usize = 64 * 1024 * 1024;

/// How entry-data reading failed: a CRC failure names the entry
/// (`bad-crc-in-zip`); a password-protected entry aborts the file like the
/// reference's `RuntimeError` handler (`unable-to-read-zip` as a warning).
enum CrcOutcome {
    Ok,
    BadEntry(String),
    /// The archive's CRC cannot be verified by this reader; the string is
    /// the detail for the `unable-to-read-zip` warning.
    Unreadable(String),
}

/// Read one entry of the CRC pass into `sink`, capped at
/// `MAX_ENTRY_BYTES + 1` inflated bytes, opening it by its
/// central-directory position (`by_index`) rather than by name.
///
/// Positional opening is what makes the pass exact:
///
/// - A legacy-encoded name (cp437 without the UTF-8 flag) decodes to a
///   string that does not re-encode to the raw central-directory
///   bytes, so a by-name lookup cannot address the entry at all.
/// - Two distinct raw names can decode to the same string (the same
///   name stored once as cp437 bytes and once as UTF-8 bytes); a
///   by-name lookup re-encodes the decoded string and resolves both
///   positions to the one raw entry matching it, so that entry would
///   be verified twice and the other never.
/// - A name that fails to decode has no by-name address at all.
///
/// The reference's `testzip()` likewise reaches its entries by walking
/// `filelist` in central-directory order. `name` is kept only as the
/// identifier a failure is reported under. (Entries sharing the exact
/// same raw name are collapsed into one position by the zip reader
/// itself, before this pass runs.)
///
/// The read happens inside this call rather than returning the opened
/// entry: a returned `ZipFile` would keep the archive borrowed while
/// the caller works through the entries, which the borrow checker
/// rejects (NLL problem case 3).
///
/// A password-protected entry surfaces as
/// `UnsupportedArchive(PASSWORD_REQUIRED)` (zip 9 reports it at open,
/// not at read); like the reference's `RuntimeError` path it aborts
/// the file instead of naming an entry. An entry whose compression
/// method the reader cannot inflate aborts the file the same way
/// (see `map_open_error`).
fn read_entry(
    archive: &mut ZipArchive<File>,
    index: usize,
    name: &str,
    sink: &mut Vec<u8>,
) -> Result<std::io::Result<usize>, CrcOutcome> {
    match archive.by_index(index) {
        Ok(entry) => Ok(entry.take(MAX_ENTRY_BYTES as u64 + 1).read_to_end(sink)),
        Err(err) => Err(map_open_error(err, name)),
    }
}

/// Map an entry-open failure to the CRC pass outcome it aborts with.
///
/// Password-required and unsupported-compression-method failures abort
/// the whole CRC pass — and with it the file's remaining checks — as
/// `unable-to-read-zip` (W): no CRC verdict exists for such an entry,
/// and the pass names no entry for it. The unsupported-method branch
/// is decided at open, before any data is read, so a corrupt entry
/// behind an unsupported method is W here regardless of its stored
/// CRC. Against the reference that is a codec-dependent split: on a
/// Python without the codec, `testzip()` raises `NotImplementedError`
/// — a `RuntimeError` subclass — and the reference's outer handler
/// reports the same W; on a Python with the codec (zstd ships with
/// Python 3.14+) it inflates the entry, and a corrupt one is then
/// `bad-crc-in-zip` (E). Any other open failure names the entry as a
/// bad one instead of aborting.
fn map_open_error(err: ZipError, name: &str) -> CrcOutcome {
    match err {
        ZipError::UnsupportedArchive(msg) if msg == ZipError::PASSWORD_REQUIRED => {
            CrcOutcome::Unreadable("password required".to_string())
        }
        ZipError::InvalidPassword => CrcOutcome::Unreadable("password required".to_string()),
        ZipError::CompressionMethodNotSupported(id) => {
            CrcOutcome::Unreadable(format!("compression method not supported: {id}"))
        }
        _ => CrcOutcome::BadEntry(name.to_string()),
    }
}

/// `ZipFile.testzip()`: the first entry whose data fails to read. Entries are
/// visited in central-directory order, as `filelist` is in the reference.
///
/// An entry inflating past `MAX_ENTRY_BYTES` is a bad entry: it is
/// reported, never inflated in full.
fn first_bad_crc(archive: &mut ZipArchive<File>) -> CrcOutcome {
    // zip 9 yields entry names as results, one per central-directory
    // position. The vector stays index-aligned (no compaction) so a
    // position always names the same entry `by_index` opens. A name
    // that fails to decode does not skip its entry — the reference's
    // `testzip()` walks every `filelist` entry — so the entry is
    // verified positionally and reported under a fallback identifier
    // naming its position.
    let names: Vec<String> = (0..archive.len())
        .map(|index| {
            archive
                .name_for_index(index)
                .and_then(|name| name.ok())
                .map(|name| name.into_owned())
                .unwrap_or_else(|| format!("<undecodable name: entry {index}>"))
        })
        .collect();
    let mut sink = Vec::new();
    for (index, name) in names.iter().enumerate() {
        sink.clear();
        let read = match read_entry(archive, index, name, &mut sink) {
            Ok(read) => read,
            Err(outcome) => return outcome,
        };
        if read.is_err() || sink.len() > MAX_ENTRY_BYTES {
            return CrcOutcome::BadEntry(name.clone());
        }
    }
    CrcOutcome::Ok
}

/// Approximation of CPython's `zipfile.is_zipfile`: scan the tail for the
/// end-of-central-directory signature. Anything else is silently skipped,
/// exactly like the reference.
fn has_end_of_central_dir(path: &Path) -> bool {
    const EOCD: &[u8] = b"PK\x05\x06";
    // CPython scans the last 64 KiB plus the record itself.
    const SCAN: u64 = 65536 + 22;
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let len = match file.metadata() {
        Ok(m) => m.len(),
        Err(_) => return false,
    };
    let tail = len.min(SCAN);
    let mut buf = vec![0u8; tail as usize];
    if file.seek(SeekFrom::Start(len - tail)).is_err() {
        return false;
    }
    if file.read_exact(&mut buf).is_err() {
        return false;
    }
    buf.windows(EOCD.len()).any(|w| w == EOCD)
}

/// The jar manifest, decoded lossily like the reference's
/// `.decode(errors='replace')`. A read failure propagates: the reference's
/// outer handler turns it into `unable-to-read-zip`. The read is capped
/// like the CRC pass: a manifest inflating past `MAX_ENTRY_BYTES` is a
/// read failure.
fn manifest_text(archive: &mut ZipArchive<File>) -> Result<String, std::io::Error> {
    let entry = archive.by_name("META-INF/MANIFEST.MF").map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("cannot open META-INF/MANIFEST.MF: {e}"),
        )
    })?;
    let mut buf = Vec::new();
    entry
        .take(MAX_ENTRY_BYTES as u64 + 1)
        .read_to_end(&mut buf)?;
    if buf.len() > MAX_ENTRY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("META-INF/MANIFEST.MF inflates past the {MAX_ENTRY_BYTES}-byte entry cap"),
        ));
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

pub struct ZipCheck;

impl ZipCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// Inspect one archive. Pure over the filesystem: the fixtures are real
    /// zip files built in the tests, never RPMs. Returns
    /// `(level, finding, details)` in emission order.
    fn inspect(path: &Path, fname: &str) -> Vec<(Level, &'static str, Vec<String>)> {
        let mut out = Vec::new();
        if !has_end_of_central_dir(path) {
            return out;
        }
        let unreadable = |detail: String| {
            vec![(
                Level::Warning,
                "unable-to-read-zip",
                vec![format!("{fname}: {detail}")],
            )]
        };
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                return vec![(
                    Level::Error,
                    "unable-to-read-zip",
                    vec![format!("{fname}: {e}")],
                )];
            }
        };
        let mut archive = match ZipArchive::new(file) {
            Ok(a) => a,
            Err(e) => {
                return vec![(
                    Level::Error,
                    "unable-to-read-zip",
                    vec![format!("{fname}: {e}")],
                )];
            }
        };
        match first_bad_crc(&mut archive) {
            CrcOutcome::Ok => {}
            CrcOutcome::BadEntry(bad) => {
                out.push((Level::Error, "bad-crc-in-zip", vec![bad, fname.to_string()]))
            }
            CrcOutcome::Unreadable(detail) => {
                return unreadable(detail);
            }
        }
        if is_match(jar_regex(), fname) {
            // `namelist()` membership, not `by_name`: a corrupt entry is
            // still listed, as in the reference.
            let names: Vec<String> = archive
                .file_names()
                .filter_map(|name| name.ok().map(|name| name.into_owned()))
                .collect();
            if names.iter().any(|n| n == "META-INF/MANIFEST.MF") {
                match manifest_text(&mut archive) {
                    Ok(manifest) => {
                        if is_match(classpath_regex(), &manifest) {
                            out.push((
                                Level::Warning,
                                "class-path-in-manifest",
                                vec![fname.to_string()],
                            ));
                        }
                    }
                    Err(e) => out.push((
                        Level::Error,
                        "unable-to-read-zip",
                        vec![format!("{fname}: {e}")],
                    )),
                }
            }
        }
        out
    }
}

impl Check for ZipCheck {
    fn name(&self) -> &'static str {
        "ZipCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let zip_re = zip_regex();
        for file in &pkg.files {
            if !is_match(zip_re, &file.name) {
                continue;
            }
            let path = Path::new(&file.path);
            // `exists() and is_file()`: `is_file` alone covers both.
            if !path.is_file() {
                continue;
            }
            for (level, check, details) in Self::inspect(path, &file.name) {
                let detail_refs: Vec<&str> = details.iter().map(String::as_str).collect();
                add_info(out, level, pkg, check, &detail_refs);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::Path;
    use zip::unstable::write::FileOptionsExt;
    use zip::write::SimpleFileOptions;

    use crate::color::Color;
    use crate::pkg::pkgfile::PkgFile;

    /// Build a zip in memory: `(name, data, method)` entries, optional
    /// `META-INF/MANIFEST.MF` content.
    fn build_zip(
        entries: &[(&str, &[u8], zip::CompressionMethod)],
        manifest: Option<&str>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        for (name, data, method) in entries {
            let options = SimpleFileOptions::default().compression_method(*method);
            archive.start_file(*name, options).unwrap();
            archive.write_all(data).unwrap();
        }
        if let Some(text) = manifest {
            // zip 8 defaults FileOptions to deflate; the manifest must stay stored.
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            archive.start_file("META-INF/MANIFEST.MF", options).unwrap();
            archive.write_all(text.as_bytes()).unwrap();
        }
        archive.finish().unwrap();
        buf
    }

    fn write_fixture(dir: &Path, fname: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(fname);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn fixture_names<'a>(findings: &'a [(Level, &'static str, Vec<String>)]) -> Vec<&'a str> {
        findings.iter().map(|(_, n, _)| *n).collect()
    }

    #[test]
    fn compressed_zip_is_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = build_zip(
            &[(
                "a.txt",
                b"hello world, hello world",
                zip::CompressionMethod::Deflated,
            )],
            None,
        );
        let path = write_fixture(dir.path(), "a.zip", &bytes);
        assert!(ZipCheck::inspect(&path, "a.zip").is_empty());
    }

    #[test]
    fn non_archive_with_zip_name_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_fixture(dir.path(), "a.zip", b"this is not a zip file");
        // `is_zipfile()` false: silently skipped, like the reference.
        assert!(ZipCheck::inspect(&path, "a.zip").is_empty());
    }

    #[test]
    fn corrupt_entry_reports_bad_crc() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = build_zip(
            &[("a.txt", b"hello world", zip::CompressionMethod::Stored)],
            None,
        );
        // Flip a byte inside the stored payload so the CRC check fails.
        let pos = bytes
            .windows(b"hello world".len())
            .position(|w| w == b"hello world")
            .unwrap();
        bytes[pos] ^= 0xff;
        let path = write_fixture(dir.path(), "a.zip", &bytes);
        let findings = ZipCheck::inspect(&path, "a.zip");
        let crc: Vec<_> = findings
            .iter()
            .filter(|(_, n, _)| *n == "bad-crc-in-zip")
            .collect();
        assert_eq!(crc.len(), 1, "{findings:?}");
        assert_eq!(crc[0].2, vec!["a.txt".to_string(), "a.zip".to_string()]);
    }

    #[test]
    fn empty_only_zip_is_not_uncompressed() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = build_zip(&[("empty.txt", b"", zip::CompressionMethod::Stored)], None);
        let path = write_fixture(dir.path(), "a.zip", &bytes);
        // Empty archives are valid: no finding.
        assert!(ZipCheck::inspect(&path, "a.zip").is_empty());
    }

    #[test]
    fn truncated_archive_is_unable_to_read() {
        let dir = tempfile::tempdir().unwrap();
        // EOCD claiming one central-directory entry at an offset past EOF:
        // the magic scan passes, but the archive does not open.
        let mut bytes = b"PK\x05\x06".to_vec();
        bytes.extend_from_slice(&[0x00, 0x00]); // disk number
        bytes.extend_from_slice(&[0x00, 0x00]); // cd disk
        bytes.extend_from_slice(&[0x01, 0x00]); // disk entries
        bytes.extend_from_slice(&[0x01, 0x00]); // total entries
        bytes.extend_from_slice(&[0x2e, 0x00, 0x00, 0x00]); // cd size
        bytes.extend_from_slice(&[0x64, 0x00, 0x00, 0x00]); // cd offset (past EOF)
        bytes.extend_from_slice(&[0x00, 0x00]); // comment length
        let path = write_fixture(dir.path(), "a.zip", &bytes);
        let findings = ZipCheck::inspect(&path, "a.zip");
        assert_eq!(fixture_names(&findings), vec!["unable-to-read-zip"]);
        assert!(findings[0].2[0].starts_with("a.zip: "));
    }

    #[test]
    fn jar_with_index_is_quiet_for_index() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = build_zip(
            &[
                (
                    "A.class",
                    b"fake class data",
                    zip::CompressionMethod::Deflated,
                ),
                (
                    "META-INF/INDEX.LIST",
                    b"index",
                    zip::CompressionMethod::Stored,
                ),
            ],
            None,
        );
        let path = write_fixture(dir.path(), "a.jar", &bytes);
        assert!(ZipCheck::inspect(&path, "a.jar").is_empty());
    }

    #[test]
    fn jar_with_hardcoded_class_path_warns() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = build_zip(
            &[(
                "A.class",
                b"fake class data",
                zip::CompressionMethod::Deflated,
            )],
            Some("Manifest-Version: 1.0\nClass-Path: lib/dep.jar\n"),
        );
        let path = write_fixture(dir.path(), "a.jar", &bytes);
        let findings = ZipCheck::inspect(&path, "a.jar");
        assert_eq!(fixture_names(&findings), vec!["class-path-in-manifest"]);
    }

    #[test]
    fn corrupt_manifest_reports_crc_and_unable_to_read() {
        // A corrupt MANIFEST.MF fails the CRC pass (bad-crc-in-zip) and then
        // fails the manifest read, which the reference's outer handler turns
        // into unable-to-read-zip.
        let dir = tempfile::tempdir().unwrap();
        let manifest = "Manifest-Version: 1.0\nClass-Path: lib/dep.jar\n";
        let mut bytes = build_zip(
            &[(
                "A.class",
                b"fake class data",
                zip::CompressionMethod::Deflated,
            )],
            Some(manifest),
        );
        // Corrupt the stored manifest payload.
        let pos = bytes
            .windows(manifest.len())
            .position(|w| w == manifest.as_bytes())
            .unwrap();
        bytes[pos] ^= 0xff;
        let path = write_fixture(dir.path(), "a.jar", &bytes);
        let findings = ZipCheck::inspect(&path, "a.jar");
        assert_eq!(
            fixture_names(&findings),
            vec!["bad-crc-in-zip", "unable-to-read-zip"]
        );
    }

    #[test]
    fn jar_without_class_path_is_quiet_for_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = build_zip(
            &[(
                "A.class",
                b"fake class data",
                zip::CompressionMethod::Deflated,
            )],
            Some("Manifest-Version: 1.0\n"),
        );
        let path = write_fixture(dir.path(), "a.jar", &bytes);
        assert!(ZipCheck::inspect(&path, "a.jar").is_empty());
    }

    #[test]
    fn encrypted_entry_is_unable_to_read_warning() {
        let dir = tempfile::tempdir().unwrap();
        let mut buf = Vec::new();
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"secret")
            .expect("non-empty password");
        archive.start_file("secret.txt", options).unwrap();
        archive.write_all(b"top secret").unwrap();
        archive.finish().unwrap();
        let path = write_fixture(dir.path(), "a.zip", &buf);
        let findings = ZipCheck::inspect(&path, "a.zip");
        // The reference's RuntimeError path: a warning, and no CRC finding.
        assert_eq!(fixture_names(&findings), vec!["unable-to-read-zip"]);
        assert!(matches!(findings[0].0, Level::Warning));
    }

    #[test]
    fn non_zip_names_are_ignored_by_check_binary() {
        // The filename regex is what selects archives; exercised via inspect
        // indirectly: a .txt name never reaches the archive code.
        let re = zip_regex();
        assert!(is_match(re, "a.zip"));
        assert!(is_match(re, "a.jar"));
        assert!(is_match(re, "a.war"));
        assert!(is_match(re, "a.ear"));
        assert!(!is_match(re, "a.txt"));
        assert!(!is_match(re, "a.zip.bak"));
    }

    #[test]
    fn check_binary_entry_point_reports_bad_crc() {
        // Kills the neutered-`check_binary` mutant: the glue (name filter +
        // `path.is_file()` + iteration) must run for the finding to reach `Filter`.
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = build_zip(
            &[("a.txt", b"hello world", zip::CompressionMethod::Stored)],
            None,
        );
        let pos = bytes
            .windows(b"hello world".len())
            .position(|w| w == b"hello world")
            .unwrap();
        bytes[pos] ^= 0xff;
        let path = write_fixture(dir.path(), "test.zip", &bytes);
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.files = vec![PkgFile {
            name: "test.zip".to_string(),
            path: path.to_string_lossy().into_owned(),
            ..Default::default()
        }];
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = ZipCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&"bad-crc-in-zip"),
            "expected bad-crc-in-zip in {names:?}"
        );
    }

    #[test]
    fn over_cap_entry_reports_bad_crc() {
        // An entry inflating past the entry cap is reported, not inflated:
        // 65 MiB of zeros deflate to a few KiB in the archive.
        let dir = tempfile::tempdir().unwrap();
        let data = vec![0u8; MAX_ENTRY_BYTES + 1024 * 1024];
        let bytes = build_zip(
            &[("big.bin", &data, zip::CompressionMethod::Deflated)],
            None,
        );
        let path = write_fixture(dir.path(), "big.zip", &bytes);
        let findings = ZipCheck::inspect(&path, "big.zip");
        assert_eq!(fixture_names(&findings), vec!["bad-crc-in-zip"]);
        assert_eq!(
            findings[0].2,
            vec!["big.bin".to_string(), "big.zip".to_string()]
        );
    }

    #[test]
    fn at_cap_entry_is_quiet() {
        // Exactly at the cap the entry is read in full and CRC-verified.
        let dir = tempfile::tempdir().unwrap();
        let data = vec![0u8; MAX_ENTRY_BYTES];
        let bytes = build_zip(
            &[("full.bin", &data, zip::CompressionMethod::Deflated)],
            None,
        );
        let path = write_fixture(dir.path(), "full.zip", &bytes);
        assert!(ZipCheck::inspect(&path, "full.zip").is_empty());
    }

    #[test]
    fn at_cap_corrupt_entry_still_reports_bad_crc() {
        // The cap does not mask CRC failures at the boundary: a stored
        // entry of exactly the cap with a flipped payload byte still
        // reads to end-of-entry and fails its CRC.
        let dir = tempfile::tempdir().unwrap();
        let mut data = vec![0u8; MAX_ENTRY_BYTES];
        data[..11].copy_from_slice(b"hello world");
        let mut bytes = build_zip(&[("full.bin", &data, zip::CompressionMethod::Stored)], None);
        let pos = bytes
            .windows(b"hello world".len())
            .position(|w| w == b"hello world")
            .unwrap();
        bytes[pos] ^= 0xff;
        let path = write_fixture(dir.path(), "full.zip", &bytes);
        let findings = ZipCheck::inspect(&path, "full.zip");
        assert_eq!(fixture_names(&findings), vec!["bad-crc-in-zip"]);
    }

    /// Build a zip from raw parts: `(name bytes, payload, stored CRC,
    /// method)` entries, all stored in one local header + central
    /// directory + EOCD sequence. Needed for shapes `ZipWriter` cannot
    /// produce (legacy-encoded names, foreign compression methods).
    /// The stored CRC is written verbatim so a test can lie about it.
    fn build_raw_zip(entries: &[(&[u8], &[u8], u32, u16)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for (name, data, crc, method) in entries {
            let offset = out.len() as u32;
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // mod time
            out.extend_from_slice(&0u16.to_le_bytes()); // mod date
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra length
            out.extend_from_slice(name);
            out.extend_from_slice(data);
            cd.extend_from_slice(b"PK\x01\x02");
            cd.extend_from_slice(&20u16.to_le_bytes()); // version made by
            cd.extend_from_slice(&20u16.to_le_bytes()); // version needed
            cd.extend_from_slice(&0u16.to_le_bytes()); // flags
            cd.extend_from_slice(&method.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes()); // mod time
            cd.extend_from_slice(&0u16.to_le_bytes()); // mod date
            cd.extend_from_slice(&crc.to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes()); // extra length
            cd.extend_from_slice(&0u16.to_le_bytes()); // comment length
            cd.extend_from_slice(&0u16.to_le_bytes()); // disk number
            cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            cd.extend_from_slice(&offset.to_le_bytes());
            cd.extend_from_slice(name);
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&cd);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number
        out.extend_from_slice(&0u16.to_le_bytes()); // cd disk
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment length
        out
    }

    #[test]
    fn legacy_encoded_name_with_good_crc_is_quiet() {
        // The CPython test-suite fixture shape (zip_cp437_header.zip,
        // fspy's iso-8859-1.zip): the entry name's raw bytes are cp437
        // without the UTF-8 flag, so the decoded name does not
        // re-encode to the raw bytes and a by-name lookup cannot
        // address the entry. Its data is intact (CRC32 of "hello" is
        // 0x3610a686) and the reference verifies it, so the archive is
        // quiet.
        let dir = tempfile::tempdir().unwrap();
        let bytes = build_raw_zip(&[
            (b"plain.txt", b"hello", 0x3610_a686, 0),
            (b"filename_with_\x91o\x86.txt", b"hello", 0x3610_a686, 0),
        ]);
        let path = write_fixture(dir.path(), "a.zip", &bytes);
        assert!(ZipCheck::inspect(&path, "a.zip").is_empty());
    }

    #[test]
    fn legacy_encoded_name_with_bad_crc_still_reports() {
        // Positional opening must actually verify the entry, not
        // skip it: the same legacy-encoded name carrying a wrong stored
        // CRC is reported under its decoded (cp437) name.
        let dir = tempfile::tempdir().unwrap();
        let bytes = build_raw_zip(&[
            (b"plain.txt", b"hello", 0x3610_a686, 0),
            (b"filename_with_\x91o\x86.txt", b"hello", 0xdead_beef, 0),
        ]);
        let path = write_fixture(dir.path(), "a.zip", &bytes);
        let findings = ZipCheck::inspect(&path, "a.zip");
        assert_eq!(fixture_names(&findings), vec!["bad-crc-in-zip"]);
        assert_eq!(
            findings[0].2,
            vec![
                "filename_with_\u{00e6}o\u{00e5}.txt".to_string(),
                "a.zip".to_string()
            ]
        );
    }

    #[test]
    fn duplicate_decoded_name_second_entry_is_verified() {
        // The same name stored twice under different raw encodings —
        // UTF-8 bytes and cp437 bytes, both decoding to "été.txt" —
        // occupies two central-directory positions. A by-name lookup
        // re-encodes the decoded name as UTF-8, so it resolves both
        // positions to the UTF-8 entry and the cp437 entry's bad CRC
        // would never be seen; positional opening verifies each
        // position in turn and reports the bad one.
        let dir = tempfile::tempdir().unwrap();
        let bytes = build_raw_zip(&[
            ("\u{00e9}t\u{00e9}.txt".as_bytes(), b"hello", 0x3610_a686, 0),
            (b"\x82t\x82.txt", b"hello", 0xdead_beef, 0),
        ]);
        let path = write_fixture(dir.path(), "a.zip", &bytes);
        let findings = ZipCheck::inspect(&path, "a.zip");
        assert_eq!(fixture_names(&findings), vec!["bad-crc-in-zip"]);
        assert_eq!(
            findings[0].2,
            vec!["\u{00e9}t\u{00e9}.txt".to_string(), "a.zip".to_string()]
        );
    }

    #[test]
    fn unsupported_compression_method_is_unable_to_read_warning() {
        // Method 93 (zstd): the reader is built with stored and
        // deflate only, so the entry cannot be inflated and no CRC
        // verdict exists. Like the password case this is
        // unable-to-read-zip as a warning, never bad-crc-in-zip.
        let dir = tempfile::tempdir().unwrap();
        let bytes = build_raw_zip(&[(b"data.bin", b"payload", 0, 93)]);
        let path = write_fixture(dir.path(), "a.zip", &bytes);
        let findings = ZipCheck::inspect(&path, "a.zip");
        assert_eq!(fixture_names(&findings), vec!["unable-to-read-zip"]);
        assert!(matches!(findings[0].0, Level::Warning));
        assert_eq!(
            findings[0].2,
            vec!["a.zip: compression method not supported: 93".to_string()]
        );
    }

    #[test]
    fn over_cap_manifest_reports_bad_crc_and_unable_to_read() {
        // The manifest read is capped like the CRC pass: a MANIFEST.MF
        // inflating past the cap fails the CRC pass as a bad entry and
        // the manifest read as unable-to-read-zip.
        let dir = tempfile::tempdir().unwrap();
        let manifest = vec![0u8; MAX_ENTRY_BYTES + 1024 * 1024];
        let bytes = build_zip(
            &[
                (
                    "A.class",
                    b"fake class data",
                    zip::CompressionMethod::Deflated,
                ),
                (
                    "META-INF/MANIFEST.MF",
                    &manifest,
                    zip::CompressionMethod::Deflated,
                ),
            ],
            None,
        );
        let path = write_fixture(dir.path(), "a.jar", &bytes);
        let findings = ZipCheck::inspect(&path, "a.jar");
        assert_eq!(
            fixture_names(&findings),
            vec!["bad-crc-in-zip", "unable-to-read-zip"]
        );
    }

    #[test]
    fn padded_manifest_still_reports_class_path() {
        // A manifest well under the cap behaves exactly as before.
        let dir = tempfile::tempdir().unwrap();
        let mut text = String::from("Manifest-Version: 1.0\nClass-Path: lib/dep.jar\nX-Pad: ");
        text.push_str(&"A".repeat(1024 * 1024));
        text.push('\n');
        let bytes = build_zip(
            &[(
                "A.class",
                b"fake class data",
                zip::CompressionMethod::Deflated,
            )],
            Some(&text),
        );
        let path = write_fixture(dir.path(), "a.jar", &bytes);
        let findings = ZipCheck::inspect(&path, "a.jar");
        assert_eq!(fixture_names(&findings), vec!["class-path-in-manifest"]);
    }
}
