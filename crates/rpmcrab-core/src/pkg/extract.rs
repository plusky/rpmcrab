//! Native payload extraction and libmagic, mirroring rpmlint's `Pkg._extract_rpm`
//! and `get_magic`.
//!
//! The container is parsed with the pure-Rust `rpm` crate (lead + signature and
//! main headers; the reader is left positioned at the payload), the payload
//! decompressed in-stream (gzip via flate2, xz via liblzma, zstd), and the SVR4
//! newc cpio entries materialized directly. This replaces the old
//! `rpm2archive - | tar -xz` (fallback `rpm2cpio | cpio -id`) subprocess, which
//! dominated wall-clock time on large packages.
//!
//! bzip2 payloads are rejected with a clear error: no pure-Rust decoder is
//! available and the last RPMs using bzip2 payloads predate 2010.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use rpm::{CompressionType, FileEntry, FileType, PackageMetadata};

/// Errors during extraction.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("extract dir {0} is not a directory")]
    BadDir(PathBuf),
    #[error("opening {path}: {source}")]
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing the rpm container: {0}")]
    Container(String),
    #[error("payload compressor {0:?} has no pure-Rust decoder")]
    UnsupportedCompressor(CompressionType),
    #[error("refusing to extract outside the target dir: {0}")]
    UnsafePath(PathBuf),
    #[error("malformed cpio entry: {0}")]
    Entry(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// SVR4 newc header: 6-byte magic + 13 8-char hex fields.
const NEWC_HEADER_LEN: usize = 110;
const TRAILER_NAME: &[u8] = b"TRAILER!!!";

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;
const S_IFIFO: u32 = 0o010_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFBLK: u32 = 0o060_000;
const S_IFSOCK: u32 = 0o140_000;

fn entry_error(msg: impl Into<String>) -> ExtractError {
    ExtractError::Entry(msg.into())
}

fn container_error(msg: impl Into<String>) -> ExtractError {
    ExtractError::Container(msg.into())
}

fn hex_field(hdr: &[u8], from: usize) -> Result<u32, ExtractError> {
    let s = std::str::from_utf8(&hdr[from..from + 8])
        .map_err(|_| entry_error("non-ASCII hex field"))?;
    u32::from_str_radix(s, 16).map_err(|_| entry_error("bad hex field"))
}

/// One parsed newc entry header; `name` is the raw (NUL-stripped) bytes.
struct CpioEntry {
    ino: u32,
    mode: u32,
    nlink: u32,
    mtime: u32,
    size: u32,
    dev_major: u32,
    dev_minor: u32,
    name: Vec<u8>,
}

/// Read one newc entry; `Ok(None)` on the `TRAILER!!!` entry.
///
/// `file_entries` resolves RPM's stripped cpio variant (magic `07070X`,
/// used for payloads with >4GB files): those 14-byte headers carry only a
/// file index, with the name/mode/mtime/size coming from the RPM header.
fn read_entry<R: Read>(
    r: &mut R,
    file_entries: &[FileEntry],
) -> Result<Option<CpioEntry>, ExtractError> {
    let mut magic = [0u8; 6];
    r.read_exact(&mut magic)
        .map_err(|e| entry_error(format!("truncated cpio header: {e}")))?;
    if &magic == b"07070X" {
        return read_stripped_entry(r, file_entries);
    }
    if &magic != b"070701" && &magic != b"070702" {
        return Err(entry_error(format!(
            "bad cpio magic {:?}",
            String::from_utf8_lossy(&magic)
        )));
    }
    let mut hdr = [0u8; NEWC_HEADER_LEN - 6];
    r.read_exact(&mut hdr)
        .map_err(|e| entry_error(format!("truncated cpio header: {e}")))?;
    // Reassemble the full 110-byte header for the field offsets below.
    let mut full = [0u8; NEWC_HEADER_LEN];
    full[..6].copy_from_slice(&magic);
    full[6..].copy_from_slice(&hdr);
    let hdr: &[u8; NEWC_HEADER_LEN] = &full;
    let name_len = hex_field(hdr, 94)? as usize;
    if name_len == 0 || name_len > 4096 {
        return Err(entry_error(format!("bad name length {name_len}")));
    }
    let mut name = vec![0u8; name_len];
    r.read_exact(&mut name)
        .map_err(|e| entry_error(format!("truncated cpio name: {e}")))?;
    // NUL-terminated; some writers pad stray NULs after it.
    while name.last() == Some(&0) {
        name.pop();
    }
    skip_pad(r, NEWC_HEADER_LEN + name_len)?;
    if name == TRAILER_NAME {
        return Ok(None);
    }
    Ok(Some(CpioEntry {
        ino: hex_field(hdr, 6)?,
        mode: hex_field(hdr, 14)?,
        nlink: hex_field(hdr, 38)?,
        mtime: hex_field(hdr, 46)?,
        size: hex_field(hdr, 54)?,
        dev_major: hex_field(hdr, 62)?,
        dev_minor: hex_field(hdr, 70)?,
        name,
    }))
}

/// Read an RPM stripped-cpio entry: 6-byte `07070X` magic + 8 hex chars of
/// file index (14 bytes, padded to 16); metadata comes from the header.
fn read_stripped_entry<R: Read>(
    r: &mut R,
    file_entries: &[FileEntry],
) -> Result<Option<CpioEntry>, ExtractError> {
    let mut index_hex = [0u8; 8];
    r.read_exact(&mut index_hex)
        .map_err(|e| entry_error(format!("truncated stripped cpio header: {e}")))?;
    let index = hex_field(&index_hex, 0)? as usize;
    skip_pad(r, 14)?;
    let fe = file_entries
        .get(index)
        .ok_or_else(|| entry_error(format!("stripped cpio file index {index} out of range")))?;
    let mode = fe.mode().raw_mode() as u32;
    // Directories carry a bogus size in the header; they have no data.
    let size = if fe.file_type() == FileType::Dir {
        0
    } else {
        fe.size() as u32
    };
    let name = fe.path().as_os_str().as_bytes().to_vec();
    Ok(Some(CpioEntry {
        // No inode in the stripped header; the index is unique per entry.
        ino: index as u32,
        mode,
        nlink: 1,
        mtime: fe.modified_at().0,
        size,
        dev_major: 0,
        dev_minor: 0,
        name,
    }))
}

/// Skip the newc 4-byte alignment padding after `len` bytes.
fn skip_pad<R: Read>(r: &mut R, len: usize) -> Result<(), ExtractError> {
    let pad = (4 - len % 4) % 4;
    if pad > 0 {
        let mut buf = [0u8; 3];
        r.read_exact(&mut buf[..pad])
            .map_err(|e| entry_error(format!("truncated cpio padding: {e}")))?;
    }
    Ok(())
}

/// Discard `size` bytes of entry data plus its padding.
fn skip_data<R: Read>(r: &mut R, size: u32) -> Result<(), ExtractError> {
    std::io::copy(&mut r.by_ref().take(size as u64), &mut std::io::sink())?;
    skip_pad(r, size as usize)
}

/// Strip the cpio `./` prefix and any leading `/` (as tar does); refuse `..`
/// — GNU tar fails the whole extraction there, so this is an error, not a
/// skip. Names are raw bytes: RPM filenames need not be UTF-8.
fn sanitize(name: &[u8]) -> Result<PathBuf, ExtractError> {
    let mut out = PathBuf::new();
    for comp in Path::new(OsStr::from_bytes(name)).components() {
        match comp {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                return Err(ExtractError::UnsafePath(PathBuf::from(OsStr::from_bytes(
                    name,
                ))));
            }
            Component::Normal(s) => out.push(s),
        }
    }
    Ok(out)
}

/// Wrap the payload stream in the matching decompressor. The 6 magic bytes are
/// chained back in front: the decoders expect the stream from its start.
fn decoder<'a>(
    stream: impl std::io::BufRead + 'a,
    magic: [u8; 6],
    compressor: &CompressionType,
) -> Result<Box<dyn Read + 'a>, ExtractError> {
    let stream = std::io::Cursor::new(magic).chain(stream);
    let stream = BufReader::with_capacity(1 << 20, stream);
    match compressor {
        CompressionType::None => Ok(Box::new(stream)),
        CompressionType::Gzip => Ok(Box::new(flate2::bufread::GzDecoder::new(stream))),
        CompressionType::Zstd => Ok(Box::new(zstd::stream::Decoder::new(stream)?)),
        CompressionType::Xz => Ok(Box::new(liblzma::bufread::XzDecoder::new(stream))),
        other => Err(ExtractError::UnsupportedCompressor(*other)),
    }
}

/// Hardlink group for one (dev_major, dev_minor, ino) key. cpio stores the data
/// in exactly one of the linked entries (not necessarily the first), with the
/// others carrying size 0; the group tracks every path so placeholders can be
/// re-linked once the data carrier arrives.
#[derive(Default)]
struct HardlinkGroup {
    paths: Vec<PathBuf>,
    data_path: Option<PathBuf>,
}

/// A path needing the post-extraction fixup: the archived permission bits and
/// mtime. Modes are applied in a second pass (like tar's delayed mode restore)
/// so that restrictive directory modes cannot break extraction midway.
struct Fixup {
    path: PathBuf,
    /// Permission bits from the cpio entry (0o7777).
    perm: u32,
    /// None for implicitly created parent dirs (tar leaves those at "now").
    mtime: Option<u32>,
    is_dir: bool,
}

/// Contextualize an I/O error with the path being materialized.
fn io_error(path: &Path, source: std::io::Error) -> ExtractError {
    ExtractError::Io(std::io::Error::new(
        source.kind(),
        format!("{}: {source}", path.display()),
    ))
}

struct Extractor<'a> {
    dir: &'a Path,
    hardlinks: HashMap<(u32, u32, u32), HardlinkGroup>,
    fixups: Vec<Fixup>,
}

impl<'a> Extractor<'a> {
    /// `mkdir -p`, recording implicitly created dirs for the fixup pass.
    /// Created 0o755: traversable during extraction; the archived mode is
    /// applied afterwards. (tar creates these 0o777 & ~umask; 0o755 matches the
    /// universal umask-022 case.)
    fn ensure_dir_all(&mut self, dir: &Path) -> Result<(), ExtractError> {
        let mut missing: Vec<PathBuf> = Vec::new();
        let mut cur = dir;
        loop {
            if cur.as_os_str().is_empty() || cur.exists() {
                break;
            }
            missing.push(cur.to_path_buf());
            match cur.parent() {
                Some(p) if !p.as_os_str().is_empty() => cur = p,
                _ => break,
            }
        }
        for d in missing.iter().rev() {
            fs::create_dir(d).map_err(|e| io_error(d, e))?;
            self.fixups.push(Fixup {
                path: d.clone(),
                perm: 0o755,
                mtime: None,
                is_dir: true,
            });
        }
        Ok(())
    }

    fn ensure_parent(&mut self, path: &Path) -> Result<(), ExtractError> {
        if let Some(parent) = path.parent() {
            self.ensure_dir_all(parent)?;
        }
        Ok(())
    }

    fn record(&mut self, path: PathBuf, perm: u32, mtime: Option<u32>, is_dir: bool) {
        // An explicit entry replaces the implicit record for the same path.
        if let Some(f) = self.fixups.iter_mut().find(|f| f.path == path) {
            f.perm = perm;
            f.mtime = mtime;
            f.is_dir = is_dir;
            return;
        }
        self.fixups.push(Fixup {
            path,
            perm,
            mtime,
            is_dir,
        });
    }

    fn materialize<R: Read>(&mut self, r: &mut R, e: &CpioEntry) -> Result<(), ExtractError> {
        let rel = sanitize(&e.name)?;
        if rel.as_os_str().is_empty() {
            // A bare "./" entry names the target dir itself.
            return skip_data(r, e.size);
        }
        let path = self.dir.join(&rel);
        match e.mode & S_IFMT {
            S_IFDIR => {
                self.ensure_dir_all(&path)?;
                skip_data(r, e.size)?;
                self.record(path, e.mode & 0o7777, Some(e.mtime), true);
            }
            S_IFREG => {
                self.ensure_parent(&path)?;
                if e.nlink > 1 {
                    self.materialize_hardlink(r, e, &path)?;
                } else {
                    let mut f = File::create(&path).map_err(|e| io_error(&path, e))?;
                    std::io::copy(&mut r.by_ref().take(e.size as u64), &mut f)
                        .map_err(|e| io_error(&path, e))?;
                    f.flush().map_err(|e| io_error(&path, e))?;
                    skip_pad(r, e.size as usize)?;
                }
                self.record(path, e.mode & 0o7777, Some(e.mtime), false);
            }
            S_IFLNK => {
                self.ensure_parent(&path)?;
                let mut target = vec![0u8; e.size as usize];
                r.read_exact(&mut target)
                    .map_err(|e| entry_error(format!("truncated symlink target: {e}")))?;
                skip_pad(r, e.size as usize)?;
                let _ = fs::remove_file(&path);
                symlink(OsStr::from_bytes(&target), &path).map_err(|e| io_error(&path, e))?;
                // Symlink modes/mtimes are OS-determined; tar leaves them too.
            }
            S_IFIFO => {
                self.ensure_parent(&path)?;
                let _ = fs::remove_file(&path);
                nix::unistd::mkfifo(&path, nix::sys::stat::Mode::from_bits_truncate(0o644 as _))
                    .map_err(|e| io_error(&path, e.into()))?;
                // No mtime: opening a fifo for writing (as set_modified does)
                // blocks until a reader appears.
                self.record(path, e.mode & 0o7777, None, false);
            }
            S_IFCHR | S_IFBLK => {
                // Device nodes are skipped: creating them needs privilege the
                // extractor does not have, and tar-as-non-root skips them too
                // (exit 0). Running the linter as root is out of scope.
                skip_data(r, e.size)?;
            }
            // tar does not materialize sockets either.
            S_IFSOCK => skip_data(r, e.size)?,
            t => {
                return Err(entry_error(format!(
                    "unknown file type {:o} for {:?}",
                    t,
                    String::from_utf8_lossy(&e.name)
                )));
            }
        }
        Ok(())
    }

    fn materialize_hardlink<R: Read>(
        &mut self,
        r: &mut R,
        e: &CpioEntry,
        path: &Path,
    ) -> Result<(), ExtractError> {
        let key = (e.dev_major, e.dev_minor, e.ino);
        let group = self.hardlinks.entry(key).or_default();
        if e.size > 0 {
            let mut f = File::create(path).map_err(|e| io_error(path, e))?;
            std::io::copy(&mut r.by_ref().take(e.size as u64), &mut f)
                .map_err(|e| io_error(path, e))?;
            f.flush().map_err(|e| io_error(path, e))?;
            skip_pad(r, e.size as usize)?;
            // Re-link earlier placeholders (size-0 entries) to the data carrier.
            for other in group.paths.drain(..) {
                if other != path {
                    fs::remove_file(&other).map_err(|e| io_error(&other, e))?;
                    fs::hard_link(path, &other).map_err(|e| io_error(&other, e))?;
                }
            }
            group.data_path = Some(path.to_path_buf());
        } else {
            skip_data(r, e.size)?;
            match &group.data_path {
                Some(data) => {
                    let data = data.clone();
                    fs::hard_link(&data, path).map_err(|e| io_error(path, e))?;
                }
                // Data carrier not seen yet: placeholder, re-linked above when
                // it arrives.
                None => {
                    File::create(path).map_err(|e| io_error(path, e))?;
                }
            }
        }
        group.paths.push(path.to_path_buf());
        Ok(())
    }

    /// Second pass: archived modes (+rX, as the reference's `chmod -R +rX .`)
    /// and mtimes. Unlike the old BSD-tar path this preserves setuid/setgid/
    /// sticky bits everywhere, matching the reference (GNU tar) on Linux.
    fn fixup(&self) -> Result<(), ExtractError> {
        for f in &self.fixups {
            let mut perm = f.perm | 0o444;
            if f.is_dir || f.perm & 0o111 != 0 {
                perm |= 0o111;
            }
            fs::set_permissions(&f.path, fs::Permissions::from_mode(perm))
                .map_err(|e| io_error(&f.path, e))?;
            if let Some(mtime) = f.mtime {
                let time = UNIX_EPOCH + Duration::from_secs(mtime as u64);
                if f.is_dir {
                    OpenOptions::new()
                        .read(true)
                        .open(&f.path)
                        .map_err(|e| io_error(&f.path, e))?
                        .set_modified(time)
                        .map_err(|e| io_error(&f.path, e))?;
                } else {
                    OpenOptions::new()
                        .write(true)
                        .open(&f.path)
                        .map_err(|e| io_error(&f.path, e))?
                        .set_modified(time)
                        .map_err(|e| io_error(&f.path, e))?;
                }
            }
        }
        Ok(())
    }
}

/// Extract the payload of `rpm` into `dir` (which must already exist), matching
/// rpmlint's `_extract_rpm` without the subprocess: the payload is decompressed
/// in-stream and the cpio entries materialized directly, then `chmod -R +rX`
/// semantics are applied (read for all; execute for dirs and files that already
/// have any execute bit).
///
/// `suppress_stderr` is retained for call-site stability but is now a no-op:
/// native extraction spawns no child, so there is no stderr to suppress.
pub fn extract(rpm: &Path, dir: &Path, _suppress_stderr: bool) -> Result<(), ExtractError> {
    if !dir.is_dir() {
        return Err(ExtractError::BadDir(dir.to_path_buf()));
    }
    let file = File::open(rpm).map_err(|source| ExtractError::Open {
        path: rpm.to_path_buf(),
        source,
    })?;
    // 1MB buffer: payloads are tens-to-hundreds of MB.
    let mut stream = BufReader::with_capacity(1 << 20, file);
    // Locate the payload structurally, without decoding header strings: the
    // old subprocess path never parsed the header, so a non-UTF-8 tag must
    // not fail extraction (that decode failure surfaces later, as before).
    let payload_at = payload_offset(&mut stream)?;
    stream.seek(SeekFrom::Start(payload_at))?;

    let mut magic = [0u8; 6];
    stream
        .read_exact(&mut magic)
        .map_err(|_| entry_error("empty payload"))?;
    let compressor = CompressionType::detect(&magic);
    let mut payload = decoder(stream, magic, &compressor)?;

    // Stripped-cpio payloads (magic `07070X`) carry only a file index per
    // entry; their metadata comes from the header. Load the file entries
    // lazily so normal payloads never parse the header at all.
    let mut entry_magic = [0u8; 6];
    payload
        .read_exact(&mut entry_magic)
        .map_err(|_| entry_error("empty payload"))?;
    let metadata = if &entry_magic == b"07070X" {
        let mut hdr_stream =
            BufReader::new(File::open(rpm).map_err(|source| ExtractError::Open {
                path: rpm.to_path_buf(),
                source,
            })?);
        Some(PackageMetadata::parse(&mut hdr_stream).map_err(|e| container_error(e.to_string()))?)
    } else {
        None
    };
    let file_entries: Vec<FileEntry> = match &metadata {
        Some(m) => m
            .get_file_entries()
            .map_err(|e| container_error(e.to_string()))?,
        None => Vec::new(),
    };
    // The entry magic was consumed; chain it back for read_entry.
    let mut payload = std::io::Cursor::new(entry_magic).chain(payload);

    let mut extractor = Extractor {
        dir,
        hardlinks: HashMap::new(),
        fixups: Vec::new(),
    };
    while let Some(entry) = read_entry(&mut payload, &file_entries)? {
        extractor.materialize(&mut payload, &entry)?;
    }
    extractor.fixup()?;
    // Flush the decoder so truncated-payload errors surface here, not silently.
    let mut sink = std::io::sink();
    std::io::copy(&mut payload, &mut sink)?;
    Ok(())
}

/// Byte offset of the payload in an RPM file: 96-byte lead, then the
/// signature and main headers, each 16 bytes of intro plus 16 bytes per
/// index entry plus the data section. Only the signature header is padded
/// (to 8 bytes); the payload follows the main header immediately.
/// No header strings are decoded, so malformed text cannot fail this.
fn payload_offset(stream: &mut BufReader<File>) -> Result<u64, ExtractError> {
    let mut lead = [0u8; 96];
    stream
        .read_exact(&mut lead)
        .map_err(|e| container_error(format!("truncated rpm lead: {e}")))?;
    if &lead[..4] != b"\xed\xab\xee\xdb" {
        return Err(container_error("bad rpm lead magic"));
    }
    let mut offset = 96u64;
    for (name, padded) in [("signature", true), ("header", false)] {
        let mut intro = [0u8; 16];
        stream
            .read_exact(&mut intro)
            .map_err(|e| container_error(format!("truncated rpm {name} header: {e}")))?;
        if &intro[..3] != b"\x8e\xad\xe8" {
            return Err(container_error(format!("bad rpm {name} header magic")));
        }
        let entries = u32::from_be_bytes(intro[8..12].try_into().unwrap());
        let data_len = u32::from_be_bytes(intro[12..16].try_into().unwrap());
        let mut size = 16u64 + u64::from(entries) * 16 + u64::from(data_len);
        if padded {
            size += (8 - size % 8) % 8;
        }
        // Seek rather than read: headers can be megabytes.
        stream.seek(SeekFrom::Current(size as i64 - 16))?;
        offset += size;
    }
    Ok(offset)
}

/// libmagic's description of `path` — rpmlint's `get_magic` via python-magic's
/// `from_file`. `file -b` produces the identical string; `''` on failure, as
/// the reference returns on `ValueError`/`FileNotFoundError`.
///
/// This shells out per consulted file rather than calling libmagic in-process
/// (the reference uses python-magic). Only files with an empty `FILECLASS` reach
/// it, and `file` is already a dependency (§7.4); a native binding can replace
/// this later without changing the call site.
pub fn file_magic(path: &Path) -> String {
    // `LC_ALL=C` so the `cannot open` message below is stable regardless of the
    // ambient locale (libmagic output itself is locale-independent).
    let stdout = match std::process::Command::new("file")
        .arg("-b")
        .arg(path)
        .env("LC_ALL", "C")
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => return String::new(),
    };
    let text = String::from_utf8_lossy(&stdout);
    let text = text.trim_end_matches('\n');
    // `file` exits 0 and prints `cannot open \`...' (...)` to stdout for a
    // missing or unreadable path; rpmlint's `get_magic` returns '' there.
    if text.starts_with("cannot open ") {
        return String::new();
    }
    text.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_magic_matches_libmagic() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("hello.txt");
        std::fs::write(&p, "hello\n").unwrap();
        // Equal to python-magic's `from_file` (rpmlint's `get_magic`).
        assert_eq!(file_magic(&p), "ASCII text");
    }

    #[test]
    fn file_magic_missing_is_empty() {
        assert_eq!(file_magic(Path::new("/no/such/file/xyz")), "");
    }

    #[test]
    fn extract_rejects_a_non_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        assert!(matches!(
            extract(Path::new("/x.rpm"), &file, true),
            Err(ExtractError::BadDir(_))
        ));
    }

    #[test]
    fn extract_fails_on_a_garbage_rpm() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("not-an.rpm");
        std::fs::write(&bad, b"definitely not an rpm").unwrap();
        let out = tempfile::tempdir().unwrap();
        // No longer platform-dependent: the container parse fails outright,
        // where the old BSD-tar path exited 0 on empty input.
        assert!(matches!(
            extract(&bad, out.path(), true),
            Err(ExtractError::Container(_))
        ));
    }

    #[test]
    fn sanitize_strips_prefixes_and_rejects_dotdot() {
        assert_eq!(
            sanitize(b"./usr/bin/foo").unwrap(),
            PathBuf::from("usr/bin/foo")
        );
        assert_eq!(
            sanitize(b"/usr/bin/foo").unwrap(),
            PathBuf::from("usr/bin/foo")
        );
        assert!(sanitize(b"../evil").is_err());
        assert!(sanitize(b"a/../../evil").is_err());
        assert!(sanitize(b"a/b/../c").is_err());
    }

    /// Build a synthetic RPM at test time (never a committed distro RPM) and
    /// verify the native extractor reproduces the archived file set, modes
    /// (+rX), mtimes, symlink targets, hardlink identity and fifos.
    #[test]
    fn native_extract_roundtrip() {
        use rpm::{BuildConfig, FileMode, FileOptions, PackageBuilder, Timestamp};

        let src = tempfile::tempdir().unwrap();
        let rpm_path = src.path().join("probe.rpm");
        let mut b = PackageBuilder::new("extprobe", "1.0", "MIT", "x86_64", "probe");
        b.using_config(BuildConfig::default().source_date(Timestamp(1_577_922_245)));
        b.with_file_contents(
            b"hello\n".to_vec(),
            FileOptions::new("/usr/bin/tool").mode(FileMode::regular(0o4755)),
        )
        .unwrap();
        b.with_file_contents(
            b"plain\n".to_vec(),
            FileOptions::new("/usr/bin/plain").mode(FileMode::regular(0o600)),
        )
        .unwrap();
        b.with_symlink(FileOptions::symlink("/usr/bin/linktool", "tool"))
            .unwrap();
        // Hardlink pair: the builder emits the data-less entry first, so this
        // exercises the placeholder re-linking.
        b.with_file_contents(
            b"hard\n".to_vec(),
            FileOptions::new("/usr/bin/orig").hardlink("h1"),
        )
        .unwrap();
        b.with_file_contents(
            b"hard\n".to_vec(),
            FileOptions::new("/usr/bin/hardlink").hardlink("h1"),
        )
        .unwrap();
        b.with_special_file(FileOptions::fifo("/etc/myfifo"))
            .unwrap();
        b.with_dir_entry(FileOptions::dir("/usr/bin")).unwrap();
        let pkg = b.build().unwrap();
        pkg.write(&mut File::create(&rpm_path).unwrap()).unwrap();

        let out = tempfile::tempdir().unwrap();
        extract(&rpm_path, out.path(), true).unwrap();

        let mode = |p: &str| {
            std::fs::symlink_metadata(out.path().join(p))
                .unwrap()
                .permissions()
                .mode()
        };
        let mtime = |p: &str| {
            std::fs::metadata(out.path().join(p))
                .unwrap()
                .modified()
                .unwrap()
        };
        let ts = UNIX_EPOCH + Duration::from_secs(1_577_922_245);

        // setuid preserved (the old BSD-tar path dropped it; the reference's
        // GNU tar keeps it), +rX applied on top.
        assert_eq!(mode("usr/bin/tool") & 0o7777, 0o4755);
        // 0600 -> +rX adds the read bits.
        assert_eq!(mode("usr/bin/plain") & 0o7777, 0o644);
        assert_eq!(
            std::fs::read(out.path().join("usr/bin/tool")).unwrap(),
            b"hello\n"
        );
        // Symlink target round-trips; its mode is OS-determined.
        assert_eq!(
            std::fs::read_link(out.path().join("usr/bin/linktool")).unwrap(),
            PathBuf::from("tool")
        );
        // Hardlinks share one inode and the content.
        let a = std::fs::metadata(out.path().join("usr/bin/orig")).unwrap();
        let b_ = std::fs::metadata(out.path().join("usr/bin/hardlink")).unwrap();
        assert_eq!(
            std::fs::read(out.path().join("usr/bin/hardlink")).unwrap(),
            b"hard\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(a.ino(), b_.ino());
            assert_eq!(a.nlink(), 2);
        }
        // Fifo materialized.
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            assert!(
                std::fs::symlink_metadata(out.path().join("etc/myfifo"))
                    .unwrap()
                    .file_type()
                    .is_fifo()
            );
        }
        // mtimes restored from the archive, for files and explicit dirs.
        assert_eq!(mtime("usr/bin/tool"), ts);
        assert_eq!(mtime("usr/bin"), ts);
        // Implicit parent dirs get "now", as with tar.
        assert!(mtime("usr") > ts);
        assert!(mtime("etc") > ts);
    }

    /// bzip2 payloads have no pure-Rust decoder: the failure names the
    /// compressor instead of failing obscurely mid-stream.
    #[test]
    fn bzip2_payload_is_rejected_cleanly() {
        let stream = std::io::BufReader::new(&b"BZh9fake"[..]);
        let err = match decoder(stream, *b"BZh91a", &CompressionType::Bzip2) {
            Ok(_) => panic!("bzip2 payload must be rejected"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            ExtractError::UnsupportedCompressor(CompressionType::Bzip2)
        ));
    }
}
