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

use std::collections::{HashMap, HashSet};
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
/// `size` is u64: the stripped-cpio path exists exactly for >4GB entries,
// which a u32 would truncate (desyncing the stream).
struct CpioEntry {
    ino: u32,
    mode: u32,
    nlink: u32,
    mtime: u32,
    size: u64,
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
    skip_pad(r, (NEWC_HEADER_LEN + name_len) as u64)?;
    // `./`-prefixed trailer: some writers keep the prefix tar would strip.
    if name == TRAILER_NAME || name == b"./TRAILER!!!" {
        return Ok(None);
    }
    Ok(Some(CpioEntry {
        ino: hex_field(hdr, 6)?,
        mode: hex_field(hdr, 14)?,
        nlink: hex_field(hdr, 38)?,
        mtime: hex_field(hdr, 46)?,
        size: u64::from(hex_field(hdr, 54)?),
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
    // No u32 truncation: the stripped path exists exactly for >4GB entries.
    let size = if fe.file_type() == FileType::Dir {
        0
    } else {
        fe.size() as u64
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
/// `len` is u64: callers pass entry sizes, which exceed u32 on 32-bit
/// targets; only `len % 4` matters here, so no truncation is possible.
fn skip_pad<R: Read>(r: &mut R, len: u64) -> Result<(), ExtractError> {
    let pad = (4 - len % 4) % 4;
    if pad > 0 {
        let mut buf = [0u8; 3];
        r.read_exact(&mut buf[..pad as usize])
            .map_err(|e| entry_error(format!("truncated cpio padding: {e}")))?;
    }
    Ok(())
}

/// Discard `size` bytes of entry data plus its padding.
fn skip_data<R: Read>(r: &mut R, size: u64) -> Result<(), ExtractError> {
    std::io::copy(&mut r.by_ref().take(size), &mut std::io::sink())?;
    skip_pad(r, size)
}

/// Strip the cpio `./` prefix and any leading `/` (as tar does); refuse `..`
/// — GNU tar fails the whole extraction there, so this is an error, not a
/// skip. `a/b/../c` is rejected too though it stays inside: fail-closed is
/// safe (tar normalizes-then-checks; no legitimate archive needs `..`).
/// Names are raw bytes: RPM filenames need not be UTF-8.
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

/// Whether `path` already exists as a directory. A symlink counts only when
/// it resolves to a directory; a dangling link or a non-dir is not one.
fn is_existing_dir(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.is_dir())
        .unwrap_or(false)
}

struct Extractor<'a> {
    dir: &'a Path,
    hardlinks: HashMap<(u32, u32, u32), HardlinkGroup>,
    fixups: Vec<Fixup>,
    /// Index of `fixups` by path. `record` replaces the entry for an
    /// already-recorded path; a linear scan per entry is O(n^2) in the
    /// number of files (rocksndiamonds-data ships 108k of them).
    fixup_index: HashMap<PathBuf, usize>,
    /// Sanitized payload paths already materialized, to tell an intentional
    /// same-path replace apart from a case-insensitive collision.
    seen: HashSet<PathBuf>,
}

impl<'a> Extractor<'a> {
    /// `mkdir -p`, recording implicitly created dirs for the fixup pass.
    /// Created 0o755: traversable during extraction; the archived mode is
    /// applied afterwards. (tar creates these 0o777 & ~umask; 0o755 matches the
    /// umask-022 case exactly, and reading the live umask would need unsafe.
    /// Only stat differs — checks read the archived header modes, so benign.)
    ///
    /// Returns false when a path component already exists as a non-directory
    /// (a file or symlink colliding with the directory — e.g. names differing
    /// only by case on a case-insensitive filesystem): the directory cannot be
    /// created there, so the caller skips the entry instead of aborting the
    /// whole extraction. A symlink resolving to a directory counts as one,
    /// matching tar for subsequent members.
    fn ensure_dir_all(&mut self, dir: &Path) -> Result<bool, ExtractError> {
        let mut missing: Vec<PathBuf> = Vec::new();
        let mut cur = dir;
        loop {
            if cur.as_os_str().is_empty() {
                break;
            }
            match fs::symlink_metadata(cur) {
                Ok(m) if m.is_dir() => break,
                Ok(m) if m.is_symlink() && cur.is_dir() => break,
                Ok(_) => return Ok(false),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(cur.to_path_buf());
                    match cur.parent() {
                        Some(p) if !p.as_os_str().is_empty() => cur = p,
                        _ => break,
                    }
                }
                Err(e) => return Err(io_error(cur, e)),
            }
        }
        for d in missing.iter().rev() {
            fs::create_dir(d).map_err(|e| io_error(d, e))?;
            self.record(d.clone(), 0o755, None, true);
        }
        Ok(true)
    }

    fn ensure_parent(&mut self, path: &Path) -> Result<bool, ExtractError> {
        if let Some(parent) = path.parent() {
            return self.ensure_dir_all(parent);
        }
        Ok(true)
    }

    /// Log a skip forced by a path collision. The linter proceeds on an
    /// incomplete tree, so these must be visible, never silent.
    fn log_skip_collision(&self, e: &CpioEntry) {
        log::warn!(
            "extract: skipping entry {:?}: path collides with an incompatible existing object",
            String::from_utf8_lossy(&e.name)
        );
    }

    /// Fail-closed symlink guard: entries are never materialized *through* a
    /// symlink. Every ancestor strictly below the extraction root is checked
    /// with no-follow metadata — `a -> /tmp` in the archive must not let a
    /// later `a/b` entry write outside the root — and a non-symlink entry may
    /// not land on a live symlink final component, where `File::create`
    /// would truncate through the link (link entry first, file entry
    /// second). Only `S_IFLNK` entries may replace a live symlink:
    /// `remove_file` unlinks the link itself, never its target.
    ///
    /// Ordering contract with path-collision skips (#356): this guard runs
    /// first and fails closed -- a non-symlink entry landing on a live
    /// symlink, or any entry beneath one, is UnsafePath; a symlink entry
    /// colliding with an existing directory skips with a warning like other
    /// plain collisions. Plain file/directory collisions with an
    /// incompatible existing object skip with a warning instead of aborting.
    /// Coherent by design: symlinks can escape the extraction root, plain
    /// files cannot.
    fn reject_symlink_escape(&self, path: &Path, is_link: bool) -> Result<(), ExtractError> {
        let is_symlink = |p: &Path| {
            fs::symlink_metadata(p)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        };
        let mut cur = path;
        while let Some(parent) = cur.parent() {
            if parent == self.dir || parent.as_os_str().is_empty() {
                break;
            }
            if is_symlink(parent) {
                return Err(ExtractError::UnsafePath(parent.to_path_buf()));
            }
            cur = parent;
        }
        if !is_link && is_symlink(path) {
            return Err(ExtractError::UnsafePath(path.to_path_buf()));
        }
        Ok(())
    }

    fn record(&mut self, path: PathBuf, perm: u32, mtime: Option<u32>, is_dir: bool) {
        // An explicit entry replaces the implicit record for the same path.
        if let Some(&i) = self.fixup_index.get(&path) {
            let f = &mut self.fixups[i];
            f.perm = perm;
            f.mtime = mtime;
            f.is_dir = is_dir;
            return;
        }
        self.fixup_index.insert(path.clone(), self.fixups.len());
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
        // #354 stopped following symlinks at the final component; the parent
        // components and the link-then-file order get the same fail-closed
        // treatment here.
        self.reject_symlink_escape(&path, e.mode & S_IFMT == S_IFLNK)?;
        let is_duplicate = self.seen.contains(&rel);
        match e.mode & S_IFMT {
            S_IFDIR => {
                // ensure_dir_all doubles as the collision check for the entry
                // itself: an existing non-directory at `path` yields false.
                if !self.ensure_dir_all(&path)? {
                    self.log_skip_collision(e);
                    return skip_data(r, e.size);
                }
                skip_data(r, e.size)?;
                self.record(path, e.mode & 0o7777, Some(e.mtime), true);
                self.seen.insert(rel.clone());
            }
            S_IFREG => {
                if !self.ensure_parent(&path)? || is_existing_dir(&path) {
                    self.log_skip_collision(e);
                    return skip_data(r, e.size);
                }
                if e.nlink > 1 {
                    self.materialize_hardlink(r, e, &path)?;
                } else {
                    let mut f = File::create(&path).map_err(|e| io_error(&path, e))?;
                    std::io::copy(&mut r.by_ref().take(e.size), &mut f)
                        .map_err(|e| io_error(&path, e))?;
                    f.flush().map_err(|e| io_error(&path, e))?;
                    skip_pad(r, e.size)?;
                }
                self.record(path, e.mode & 0o7777, Some(e.mtime), false);
                self.seen.insert(rel.clone());
            }
            S_IFLNK => {
                if !self.ensure_parent(&path)? || is_existing_dir(&path) {
                    self.log_skip_collision(e);
                    return skip_data(r, e.size);
                }
                // `e.size` is attacker-controlled: cap before allocating
                // (a 4GB `vec!` would OOM/abort; PATH_MAX bounds any real target).
                if e.size > 4096 {
                    return Err(entry_error(format!(
                        "symlink target too large: {} bytes",
                        e.size
                    )));
                }
                let mut target = vec![0u8; e.size as usize];
                r.read_exact(&mut target)
                    .map_err(|e| entry_error(format!("truncated symlink target: {e}")))?;
                skip_pad(r, e.size)?;
                // A symlink entry must not clobber an existing non-symlink
                // it did not itself replace: on a case-insensitive
                // filesystem two payload paths can collide (e.g. 4pane's
                // file `4Pane` and symlink `4pane -> 4Pane`), and replacing
                // the file with the link creates a self-loop that breaks
                // every later read with ELOOP. An exact same-path duplicate
                // is an intentional replace (tar semantics) and still wins.
                // Either way the header metadata describes the symlink for
                // the checks.
                if !is_duplicate
                    && fs::symlink_metadata(&path).is_ok_and(|m| !m.file_type().is_symlink())
                {
                    return Ok(());
                }
                // Guard passed: record the path as materialized.
                self.seen.insert(rel.clone());
                let _ = fs::remove_file(&path);
                symlink(OsStr::from_bytes(&target), &path).map_err(|e| io_error(&path, e))?;
                // Symlink modes/mtimes are OS-determined; tar leaves them too.
            }
            S_IFIFO => {
                if !self.ensure_parent(&path)? || is_existing_dir(&path) {
                    self.log_skip_collision(e);
                    return Ok(());
                }
                let _ = fs::remove_file(&path);
                nix::unistd::mkfifo(&path, nix::sys::stat::Mode::from_bits_truncate(0o644 as _))
                    .map_err(|e| io_error(&path, e.into()))?;
                // No mtime: opening a fifo for writing (as set_modified does)
                // blocks until a reader appears.
                self.record(path, e.mode & 0o7777, None, false);
                self.seen.insert(rel.clone());
            }
            S_IFCHR | S_IFBLK => {
                // Device nodes are skipped: creating them needs privilege the
                // extractor does not have. The old tar path actually failed
                // here with exit 2; skipping cleanly is more correct — the
                // linter only needs the file list, not the nodes themselves.
                // Running the linter as root is out of scope.
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
            // Exactly one entry per group carries data; a second one means a
            // corrupt archive, not a second copy.
            if group.data_path.is_some() {
                return Err(entry_error(format!(
                    "duplicate data carrier for hardlink group {:?}",
                    String::from_utf8_lossy(&e.name)
                )));
            }
            let mut f = File::create(path).map_err(|e| io_error(path, e))?;
            std::io::copy(&mut r.by_ref().take(e.size), &mut f).map_err(|e| io_error(path, e))?;
            f.flush().map_err(|e| io_error(path, e))?;
            skip_pad(r, e.size)?;
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

    /// Every hardlink group needs exactly one data carrier: a group whose
    /// entries all carried size 0 would otherwise leave empty placeholders
    /// behind, silently.
    fn check_hardlinks(&self) -> Result<(), ExtractError> {
        for (key, group) in &self.hardlinks {
            if group.data_path.is_none() {
                return Err(entry_error(format!(
                    "hardlink group {key:?} has no data carrier"
                )));
            }
        }
        Ok(())
    }

    /// Second pass: archived modes (+rX, as the reference's `chmod -R +rX .`)
    /// and mtimes. Unlike the old BSD-tar path this preserves setuid/setgid/
    /// sticky bits everywhere, matching the reference (GNU tar) on Linux.
    fn fixup(&self) -> Result<(), ExtractError> {
        for f in &self.fixups {
            // A later entry may have replaced this path with a symlink
            // (duplicate paths, or case collisions on case-insensitive
            // filesystems): the recorded mode/mtime belongs to the old file,
            // and following the link — possibly a self-loop — would ELOOP and
            // abort the whole extraction. tar's delayed mode restore and the
            // reference's `chmod -R +rX` never follow symlinks, so skip these.
            let is_link = fs::symlink_metadata(&f.path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            if is_link {
                continue;
            }
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
                    // `.read(true)`: the file may be 0444 — opening for write
                    // would EACCES where read-open + set_modified succeeds.
                    OpenOptions::new()
                        .read(true)
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
        // Reserve for the known entry count: the index holds one slot per
        // fixup, bounded by the number of file entries (108k in the wild).
        fixup_index: HashMap::with_capacity(file_entries.len()),
        seen: HashSet::new(),
    };
    while let Some(entry) = read_entry(&mut payload, &file_entries)? {
        extractor.materialize(&mut payload, &entry)?;
    }
    extractor.check_hardlinks()?;
    extractor.fixup()?;
    // Flush the decoder so truncated-payload errors surface here, not silently.
    let mut sink = std::io::sink();
    std::io::copy(&mut payload, &mut sink)?;
    Ok(())
}

/// Big-endian u32 from a 4-byte slice, as a typed error — no unwrap on the
/// production path even where the slice length is statically known.
fn u32_be(bytes: &[u8]) -> Result<u32, ExtractError> {
    bytes
        .try_into()
        .map(u32::from_be_bytes)
        .map_err(|_| container_error("truncated rpm header intro"))
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
        let entries = u32_be(&intro[8..12])?;
        let data_len = u32_be(&intro[12..16])?;
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

    /// Regression: the mtime fixup must not open files for writing — a 0444
    /// payload file (docs, licenses, man pages) EACCESes on `.write(true)`.
    #[test]
    fn extract_mtime_fixup_works_on_readonly_files() {
        use rpm::{BuildConfig, FileMode, FileOptions, PackageBuilder, Timestamp};

        let src = tempfile::tempdir().unwrap();
        let rpm_path = src.path().join("readonly.rpm");
        let mut b = PackageBuilder::new("roprobe", "1.0", "MIT", "x86_64", "probe");
        b.using_config(BuildConfig::default().source_date(Timestamp(1_577_922_245)));
        b.with_file_contents(
            b"read me\n".to_vec(),
            FileOptions::new("/usr/share/doc/readme").mode(FileMode::regular(0o444)),
        )
        .unwrap();
        let pkg = b.build().unwrap();
        pkg.write(&mut File::create(&rpm_path).unwrap()).unwrap();

        let out = tempfile::tempdir().unwrap();
        // Used to fail here: Io(PermissionDenied) from the mtime fixup.
        extract(&rpm_path, out.path(), true).unwrap();

        let ts = UNIX_EPOCH + Duration::from_secs(1_577_922_245);
        assert_eq!(
            std::fs::metadata(out.path().join("usr/share/doc/readme"))
                .unwrap()
                .modified()
                .unwrap(),
            ts
        );
        // +rX adds read bits; the archived 0444 stays 0444.
        assert_eq!(
            std::fs::symlink_metadata(out.path().join("usr/share/doc/readme"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o444
        );
    }

    /// Symlink target sizes are attacker-controlled: cap before allocating.
    /// The data holds the full 5000 bytes and the message is asserted, so
    /// without the cap the target would materialize and the test would fail.
    #[test]
    fn symlink_target_size_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let mut ex = Extractor {
            dir: dir.path(),
            hardlinks: HashMap::new(),
            fixups: Vec::new(),
            fixup_index: HashMap::new(),
            seen: HashSet::new(),
        };
        let entry = CpioEntry {
            ino: 1,
            mode: S_IFLNK | 0o777,
            nlink: 1,
            mtime: 0,
            size: 5000,
            dev_major: 0,
            dev_minor: 0,
            name: b"link".to_vec(),
        };
        let full = vec![0x78; 5000];
        let mut data = &full[..];
        let err = ex.materialize(&mut data, &entry).unwrap_err();
        match err {
            ExtractError::Entry(msg) => assert!(
                msg.contains("too large"),
                "oversized symlink target must hit the size cap, got: {msg}"
            ),
            other => panic!("oversized symlink target must be an Entry error, got {other:?}"),
        }
    }

    /// Pad entry data to the 4-byte cpio alignment `materialize` expects.
    fn padded(bytes: &[u8]) -> Vec<u8> {
        let mut v = bytes.to_vec();
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        v
    }

    fn extractor_for(dir: &Path) -> Extractor<'_> {
        Extractor {
            dir,
            hardlinks: HashMap::new(),
            fixups: Vec::new(),
            fixup_index: HashMap::new(),
            seen: HashSet::new(),
        }
    }

    fn cpio_entry(name: &[u8], mode: u32, size: u64) -> CpioEntry {
        CpioEntry {
            ino: 1,
            mode,
            nlink: 1,
            mtime: 0,
            size,
            dev_major: 0,
            dev_minor: 0,
            name: name.to_vec(),
        }
    }

    /// Nit 1 from the #354 review: a symlink parent must not redirect a later
    /// entry outside the extraction root. `a -> <outside>` followed by a
    /// regular file `a/b` fails loudly with `UnsafePath` and writes nothing
    /// outside. Without the parent walk, `File::create` follows the link and
    /// the payload lands in `<outside>/b`.
    #[test]
    fn symlink_parent_escape_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let mut ex = extractor_for(root.path());
        // The symlink entry itself is the #354-accepted case: creating the
        // link never follows anything.
        let target = outside.path().as_os_str().as_bytes().to_vec();
        let link = cpio_entry(b"a", S_IFLNK | 0o777, target.len() as u64);
        let raw = padded(&target);
        let mut data = &raw[..];
        ex.materialize(&mut data, &link).unwrap();

        let reg = cpio_entry(b"a/b", S_IFREG | 0o644, 5);
        let mut fdata = &b"hello\0\0\0"[..];
        let err = ex.materialize(&mut fdata, &reg).unwrap_err();
        assert!(
            matches!(err, ExtractError::UnsafePath(_)),
            "symlink parent escape must be UnsafePath, got {err:?}"
        );
        assert!(
            !outside.path().join("b").exists(),
            "nothing may be written outside the extraction root"
        );
    }

    /// Nit 2 from the #354 review, reverse payload order: a symlink entry
    /// preceding a regular file at the same path must not let `File::create`
    /// truncate through the link. Fails loudly with `UnsafePath`, and the
    /// link target keeps its bytes.
    #[test]
    fn link_then_file_truncation_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        std::fs::write(&victim, b"original").unwrap();
        let mut ex = extractor_for(root.path());
        let target = victim.as_os_str().as_bytes().to_vec();
        let link = cpio_entry(b"link", S_IFLNK | 0o777, target.len() as u64);
        let raw = padded(&target);
        let mut data = &raw[..];
        ex.materialize(&mut data, &link).unwrap();

        let reg = cpio_entry(b"link", S_IFREG | 0o644, 5);
        let mut fdata = &b"pwned\0\0\0"[..];
        let err = ex.materialize(&mut fdata, &reg).unwrap_err();
        assert!(
            matches!(err, ExtractError::UnsafePath(_)),
            "link-then-file truncation must be UnsafePath, got {err:?}"
        );
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"original",
            "the link target must not be truncated through the link"
        );
    }

    /// A symlink entry is still an entry: planting it under a live symlink
    /// parent would create the link outside the root, so it is rejected too.
    #[test]
    fn symlink_entry_under_symlink_parent_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let mut ex = extractor_for(root.path());
        let target = outside.path().as_os_str().as_bytes().to_vec();
        let parent = cpio_entry(b"a", S_IFLNK | 0o777, target.len() as u64);
        let raw = padded(&target);
        let mut data = &raw[..];
        ex.materialize(&mut data, &parent).unwrap();

        let child = cpio_entry(b"a/b", S_IFLNK | 0o777, 1);
        let mut cdata = &b"x\0\0\0"[..];
        let err = ex.materialize(&mut cdata, &child).unwrap_err();
        assert!(
            matches!(err, ExtractError::UnsafePath(_)),
            "symlink under a symlink parent must be UnsafePath, got {err:?}"
        );
        assert!(
            !outside.path().join("b").exists(),
            "no link may be planted outside the extraction root"
        );
    }

    /// Regression for #363: a symlink entry must not delete an existing
    /// file. On a case-insensitive filesystem the 4pane payload's file
    /// `4Pane` and symlink `4pane -> 4Pane` collide; replacing the file
    /// with the link creates a self-loop, and every later read fails with
    /// ELOOP (surfacing as `readelf-failed`). The entry is skipped and
    /// the file survives.
    #[test]
    fn symlink_entry_does_not_clobber_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-create the file, as if an earlier payload entry materialized it.
        let path = dir.path().join("usr/bin/tool");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"binary\n").unwrap();

        let mut ex = Extractor {
            dir: dir.path(),
            hardlinks: HashMap::new(),
            fixups: Vec::new(),
            fixup_index: HashMap::new(),
            seen: HashSet::new(),
        };
        // Symlink entry for the colliding on-disk path.
        let target = b"tool";
        let entry = CpioEntry {
            ino: 2,
            mode: S_IFLNK | 0o777,
            nlink: 1,
            mtime: 0,
            size: target.len() as u64,
            dev_major: 0,
            dev_minor: 0,
            name: b"usr/bin/tool".to_vec(),
        };
        let mut data = &target[..];
        ex.materialize(&mut data, &entry).unwrap();

        // The file survives; no symlink loop is created.
        assert_eq!(std::fs::read(&path).unwrap(), b"binary\n");
        assert!(
            !std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    /// A skipped symlink must not poison `seen`: an exact-duplicate symlink
    /// entry after a guard-fired skip must hit the guard again, not bypass
    /// it via `is_duplicate=true` and recreate the ELOOP self-loop.
    #[test]
    fn duplicate_skipped_symlink_does_not_bypass_guard() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-create the file, as if an earlier payload entry materialized it.
        let path = dir.path().join("usr/bin/tool");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"binary\n").unwrap();

        let mut ex = Extractor {
            dir: dir.path(),
            hardlinks: HashMap::new(),
            fixups: Vec::new(),
            fixup_index: HashMap::new(),
            seen: HashSet::new(),
        };
        // Symlink entry for the colliding on-disk path.
        let target = b"tool";
        let entry = CpioEntry {
            ino: 2,
            mode: S_IFLNK | 0o777,
            nlink: 1,
            mtime: 0,
            size: target.len() as u64,
            dev_major: 0,
            dev_minor: 0,
            name: b"usr/bin/tool".to_vec(),
        };
        // First entry: guard fires (path exists as non-symlink), skipped.
        let mut data = &target[..];
        ex.materialize(&mut data, &entry).unwrap();
        // Second entry: exact duplicate. Must hit the guard again, not
        // bypass it via is_duplicate=true.
        let mut data = &target[..];
        ex.materialize(&mut data, &entry).unwrap();

        // The file survives; no symlink loop is created.
        assert_eq!(std::fs::read(&path).unwrap(), b"binary\n");
        assert!(
            !std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    /// The stripped-cpio path exists exactly for >4GB entries: a large
    /// LONGFILESIZES size must survive as u64, never truncate to u32.
    /// The header is built tiny and fast, then surgically given a
    /// LONGFILESIZES entry — no 4GB file is needed for the guard.
    ///
    /// 64-bit only: the `rpm` crate exposes `FileEntry::size` as `usize`,
    /// so a size above `u32::MAX` is truncated before rpmcrab ever sees it
    /// on 32-bit targets. `read_stripped_entry` keeps `u64` throughout;
    /// the truncation happens upstream, not here.
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn stripped_entry_preserves_size_above_u32_max() {
        use rpm::{
            BuildConfig, FileMode, FileOptions, Header, HeaderEntry, IndexData, IndexTag,
            PackageBuilder, Timestamp,
        };

        const BIG: u64 = u32::MAX as u64 + 0x1_2345;
        let mut b = PackageBuilder::new("bigprobe", "1.0", "MIT", "x86_64", "probe");
        b.using_config(BuildConfig::default().source_date(Timestamp(1_577_922_245)));
        b.with_file_contents(
            b"tiny\n".to_vec(),
            FileOptions::new("/usr/share/big.bin").mode(FileMode::regular(0o644)),
        )
        .unwrap();
        let pkg = b.build().unwrap();
        let mut meta = pkg.metadata.clone();

        // Swap FILESIZES for LONGFILESIZES carrying a >u32::MAX size.
        let mut rebuilt: Vec<HeaderEntry> = meta
            .header
            .get_all_entries()
            .unwrap()
            .into_iter()
            .filter(|(tag, _)| {
                *tag != IndexTag::RPMTAG_FILESIZES as u32
                    && *tag != IndexTag::RPMTAG_HEADERIMMUTABLE as u32
            })
            .map(|(tag, data)| HeaderEntry::new(tag, data))
            .collect();
        rebuilt.push(HeaderEntry::new(
            IndexTag::RPMTAG_LONGFILESIZES as u32,
            IndexData::Int64(vec![BIG]),
        ));
        meta.header = Header::from_entries(rebuilt, IndexTag::RPMTAG_HEADERIMMUTABLE);

        // Sanity: the large size really made it into the file entries.
        let file_entries = meta.get_file_entries().unwrap();
        assert_eq!(file_entries.len(), 1);
        assert_eq!(file_entries[0].size() as u64, BIG);

        // 8 hex chars of file index 0 (the 07070X magic is consumed by
        // `read_entry` before dispatch) + 2 bytes padding to 16.
        let mut hdr = b"00000000".to_vec();
        hdr.extend_from_slice(&[0u8; 2]);
        let mut cur = &hdr[..];
        let entry = read_stripped_entry(&mut cur, &file_entries)
            .unwrap()
            .unwrap();
        assert_eq!(
            entry.size, BIG,
            "stripped entry size must not truncate above u32::MAX"
        );
    }

    /// A `./`-prefixed trailer still ends the payload.
    #[test]
    fn dot_slash_trailer_ends_payload() {
        let mut buf = b"070701".to_vec();
        for _ in 0..11 {
            buf.extend_from_slice(b"00000000");
        }
        buf.extend_from_slice(b"0000000D"); // namesize: "./TRAILER!!!" + NUL
        buf.extend_from_slice(b"00000000"); // check
        buf.extend_from_slice(b"./TRAILER!!!\0");
        buf.push(0); // pad 110 + 13 = 123 up to 124
        let mut cursor = &buf[..];
        assert!(read_entry(&mut cursor, &[]).unwrap().is_none());
    }

    /// Two data carriers for one (dev, ino) is corruption, not a second copy.
    #[test]
    fn duplicate_hardlink_carrier_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut ex = Extractor {
            dir: dir.path(),
            hardlinks: HashMap::new(),
            fixups: Vec::new(),
            fixup_index: HashMap::new(),
            seen: HashSet::new(),
        };
        let entry = CpioEntry {
            ino: 7,
            mode: S_IFREG | 0o644,
            nlink: 2,
            mtime: 0,
            size: 5,
            dev_major: 0,
            dev_minor: 0,
            name: b"f".to_vec(),
        };
        // 5 data bytes + 3 pad bytes.
        let mut data = &b"hello\0\0\0"[..];
        ex.materialize(&mut data, &entry).unwrap();
        let mut data2 = &b"world\0\0\0"[..];
        let err = ex.materialize(&mut data2, &entry).unwrap_err();
        assert!(matches!(err, ExtractError::Entry(_)));
    }

    /// A hardlink group with no data carrier must fail loudly, not leave
    /// empty placeholders behind.
    #[test]
    fn carrierless_hardlink_group_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut ex = Extractor {
            dir: dir.path(),
            hardlinks: HashMap::new(),
            fixups: Vec::new(),
            fixup_index: HashMap::new(),
            seen: HashSet::new(),
        };
        let entry = CpioEntry {
            ino: 9,
            mode: S_IFREG | 0o644,
            nlink: 2,
            mtime: 0,
            size: 0,
            dev_major: 0,
            dev_minor: 0,
            name: b"g".to_vec(),
        };
        let mut data = &b""[..];
        ex.materialize(&mut data, &entry).unwrap();
        let err = ex.check_hardlinks().unwrap_err();
        assert!(matches!(err, ExtractError::Entry(_)));
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

    /// Regression: a symlink entry replacing an earlier regular file at the
    /// same path (duplicate paths, or case collisions on case-insensitive
    /// filesystems) must not abort extraction. The stale fixup recorded for
    /// the old file is skipped, not followed: the link may be a self-loop,
    /// and the reference (tar's delayed restore, `chmod -R +rX`) never
    /// follows symlinks.
    #[test]
    fn extract_symlink_replacing_file_succeeds() {
        // `rpm`'s PackageBuilder rejects duplicate destinations, so the
        // duplicate path is hand-written as raw newc entries: 110-byte header
        // (magic + 13 8-char hex fields), NUL-terminated name padded to 4,
        // then data padded to 4.
        fn newc_entry(name: &str, mode: u32, mtime: u32, data: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(b"070701");
            for f in [
                1u32, // ino
                mode,
                0, // uid
                0, // gid
                1, // nlink
                mtime,
                data.len() as u32,       // filesize
                0,                       // devmajor
                0,                       // devminor
                0,                       // rdevmajor
                0,                       // rdevminor
                (name.len() + 1) as u32, // namesize (incl. NUL)
                0,                       // check
            ] {
                out.extend_from_slice(format!("{f:08X}").as_bytes());
            }
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            while out.len() % 4 != 0 {
                out.push(0);
            }
            out.extend_from_slice(data);
            while out.len() % 4 != 0 {
                out.push(0);
            }
            out
        }

        let mut payload = newc_entry("usr/bin/tool", 0o100_644, 1_577_922_245, b"hello\n");
        // Duplicate path: a symlink entry at the same path, pointing at
        // itself. The regular file wins extraction order, the link wins the
        // path; the recorded fixup for the old file must not follow it.
        payload.extend(newc_entry(
            "usr/bin/tool",
            0o120_777,
            1_577_922_245,
            b"tool",
        ));
        payload.extend(newc_entry("TRAILER!!!", 0, 0, b""));

        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, &payload).unwrap();
        let gz = enc.finish().unwrap();

        // A real rpm container for the hand-rolled payload: the builder needs
        // at least one file, and the signature digests are not verified by
        // `extract`, so splicing the payload after the header is enough.
        use rpm::{BuildConfig, FileMode, FileOptions, PackageBuilder, Timestamp};
        let src = tempfile::tempdir().unwrap();
        let rpm_path = src.path().join("dupprobe.rpm");
        let mut b = PackageBuilder::new("dupprobe", "1.0", "MIT", "x86_64", "probe");
        b.using_config(BuildConfig::default().source_date(Timestamp(1_577_922_245)));
        b.with_file_contents(
            b"keep\n".to_vec(),
            FileOptions::new("/usr/share/keepme").mode(FileMode::regular(0o644)),
        )
        .unwrap();
        let pkg = b.build().unwrap();
        pkg.write(&mut File::create(&rpm_path).unwrap()).unwrap();

        let at = payload_offset(&mut BufReader::new(File::open(&rpm_path).unwrap())).unwrap();
        let mut rpm = std::fs::read(&rpm_path).unwrap();
        rpm.truncate(at as usize);
        rpm.extend_from_slice(&gz);
        std::fs::write(&rpm_path, &rpm).unwrap();

        let out = tempfile::tempdir().unwrap();
        // Pre-fix this fails: the fixup follows the self-loop, ELOOPs, and
        // aborts the whole extraction with an Io error.
        extract(&rpm_path, out.path(), true).unwrap();

        // The symlink won the path; its target round-trips.
        assert_eq!(
            std::fs::read_link(out.path().join("usr/bin/tool")).unwrap(),
            PathBuf::from("tool")
        );
    }

    /// Build one synthetic cpio entry for direct `materialize` tests.
    fn collide_entry(name: &[u8], mode: u32, data: &[u8]) -> (CpioEntry, std::io::Cursor<Vec<u8>>) {
        // Pad to the cpio 4-byte alignment: materialize consumes the entry
        // data plus its padding from the stream.
        let mut padded = data.to_vec();
        while !padded.len().is_multiple_of(4) {
            padded.push(0);
        }
        (
            CpioEntry {
                ino: 1,
                mode,
                nlink: 1,
                mtime: 0,
                size: data.len() as u64,
                dev_major: 0,
                dev_minor: 0,
                name: name.to_vec(),
            },
            std::io::Cursor::new(padded),
        )
    }

    fn collide_extractor(dir: &Path) -> Extractor<'_> {
        Extractor {
            dir,
            hardlinks: HashMap::new(),
            fixups: Vec::new(),
            fixup_index: HashMap::new(),
            seen: HashSet::new(),
        }
    }

    /// A file and a directory at the same path (duplicate entries, or names
    /// differing only by case on a case-insensitive filesystem, as in
    /// libzypp-devel's `ProxyInfo` file vs `proxyinfo/` dir): the loser is
    /// skipped instead of aborting the package.
    #[test]
    fn extract_skips_file_dir_collisions() {
        let dir = tempfile::tempdir().unwrap();
        let mut ex = collide_extractor(dir.path());
        // File first, then a colliding dir and a file that would live under it.
        let (e, mut r) = collide_entry(b"./sub/Thing", S_IFREG | 0o644, b"");
        ex.materialize(&mut r, &e).unwrap();
        let (e, mut r) = collide_entry(b"./sub/Thing", S_IFDIR | 0o755, b"");
        ex.materialize(&mut r, &e).unwrap();
        let (e, mut r) = collide_entry(b"./sub/Thing/nested", S_IFREG | 0o644, b"");
        ex.materialize(&mut r, &e).unwrap();
        // The rest of the package still extracts.
        let (e, mut r) = collide_entry(b"./sub/other", S_IFREG | 0o644, b"x");
        ex.materialize(&mut r, &e).unwrap();
        ex.fixup().unwrap();

        // First writer wins: the file survives, the dir and its would-be
        // child are gone, the unrelated file is intact.
        assert!(dir.path().join("sub/Thing").is_file());
        assert!(!dir.path().join("sub/Thing/nested").exists());
        assert_eq!(std::fs::read(dir.path().join("sub/other")).unwrap(), b"x");
    }

    /// The reverse order: a directory first, then a colliding file or symlink.
    /// The directory tree stays intact; the colliding entries are skipped.
    #[test]
    fn extract_skips_dir_file_collisions() {
        let dir = tempfile::tempdir().unwrap();
        let mut ex = collide_extractor(dir.path());
        let (e, mut r) = collide_entry(b"./sub/Thing", S_IFDIR | 0o755, b"");
        ex.materialize(&mut r, &e).unwrap();
        let (e, mut r) = collide_entry(b"./sub/Thing/nested", S_IFREG | 0o644, b"y");
        ex.materialize(&mut r, &e).unwrap();
        // Colliding file: skipped, not EISDIR.
        let (e, mut r) = collide_entry(b"./sub/Thing", S_IFREG | 0o644, b"");
        ex.materialize(&mut r, &e).unwrap();
        // Colliding symlink: skipped, the dir is not removed.
        let (e, mut r) = collide_entry(b"./sub/Thing", S_IFLNK | 0o777, b"elsewhere");
        ex.materialize(&mut r, &e).unwrap();
        ex.fixup().unwrap();

        assert!(dir.path().join("sub/Thing").is_dir());
        assert_eq!(
            std::fs::read(dir.path().join("sub/Thing/nested")).unwrap(),
            b"y"
        );
    }

    /// A directory entry landing on a live symlink is fail-closed
    /// (UnsafePath), not skipped: symlink handling belongs to the
    /// symlink-escape guard, while this PR only skips file/dir collisions.
    #[test]
    fn extract_dir_on_live_symlink_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut ex = collide_extractor(dir.path());
        let (e, mut r) = collide_entry(b"./sub/Link", S_IFLNK | 0o777, b"target");
        ex.materialize(&mut r, &e).unwrap();
        let (e, mut r) = collide_entry(b"./sub/Link", S_IFDIR | 0o755, b"");
        let err = ex.materialize(&mut r, &e).unwrap_err();
        assert!(
            matches!(err, ExtractError::UnsafePath(_)),
            "expected UnsafePath, got {err:?}"
        );

        assert_eq!(
            std::fs::read_link(dir.path().join("sub/Link")).unwrap(),
            PathBuf::from("target")
        );
    }

    /// `record` replaces the entry for an already-recorded path instead of
    /// pushing a duplicate: the fixup index must stay consistent with the vec.
    #[test]
    fn record_replaces_existing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let mut ex = extractor_for(dir.path());
        let p = dir.path().join("sub/file");
        ex.record(p.clone(), 0o644, Some(1), false);
        ex.record(p.clone(), 0o755, Some(2), false);
        assert_eq!(ex.fixups.len(), 1);
        assert_eq!(ex.fixup_index.len(), 1);
        assert_eq!(ex.fixup_index[&p], 0);
        let f = &ex.fixups[0];
        assert_eq!(f.path, p);
        assert_eq!(f.perm, 0o755);
        assert_eq!(f.mtime, Some(2));
        assert!(!f.is_dir);
    }

    /// Regression for the rocksndiamonds-data hang: `record` used to scan
    /// all previously recorded fixups per entry, O(n^2) path comparisons
    /// (108k files took 277s to extract on the Mac, and timed out the
    /// 1800s container scan). Long shared prefixes, like the real
    /// /usr/share/rocksndiamonds/levels/... paths, make each failed
    /// comparison walk many components before differing.
    #[test]
    fn record_many_distinct_paths_stays_fast() {
        let dir = tempfile::tempdir().unwrap();
        let mut ex = extractor_for(dir.path());
        let start = std::time::Instant::now();
        for i in 0..50_000 {
            let p = dir.path().join(format!(
                "usr/share/rocksndiamonds/levels/level{i:05}/sub/dir/file.dat"
            ));
            ex.record(p, 0o644, None, false);
        }
        let dt = start.elapsed();
        assert_eq!(ex.fixups.len(), 50_000);
        assert_eq!(ex.fixup_index.len(), 50_000);
        // The old O(n^2) scan needs a minute here; the indexed version is
        // milliseconds. Generous bound so slow CI machines don't flake.
        assert!(
            dt.as_secs() < 20,
            "recording 50k paths took {dt:?}, expected linear time"
        );
    }
}
