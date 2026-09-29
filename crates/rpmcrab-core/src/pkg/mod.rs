//! The `Pkg` abstraction — the Rust equivalent of rpmlint's `pkg.py`.
//!
//! Two sources: **file-backed** (the payload extracted into a tempdir so
//! `PkgFile.path` and `magic` match the reference) and **installed** (`db::Db`,
//! rooted at the live filesystem). Both expose the header, the nine dependency
//! lists, the file map, and the derived `config/doc/ghost/noreplace/missingok`
//! name lists. The spec `FakePkg` is M3.

pub mod dep;
pub mod extract;
pub mod installed;
pub mod pkgfile;
pub mod tags;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

use librpm::verify::VerifyOptions;
use librpm::{PackageHeader, Tag};

use dep::{DepInfo, string_to_version};
use pkgfile::PkgFile;

/// `PREREQ_FLAG` (rpmlint `pkg.py:37`): `(RPMSENSE_PREREQ or 64) |
/// SCRIPT_{PRE,POST,PREUN,POSTUN}` — the legacy prereq bit plus the four
/// script-sense bits (`rpmds.h`).
const PREREQ_FLAG: u32 = (1 << 6) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12);

/// The scriptlet tags (rpmlint `SCRIPT_TAGS`), `(body, prog, label)`.
pub const SCRIPT_TAGS: &[(Tag, Tag, &str)] = &[
    (Tag::PREIN, Tag::PREINPROG, "%pre"),
    (Tag::POSTIN, Tag::POSTINPROG, "%post"),
    (Tag::PREUN, Tag::PREUNPROG, "%preun"),
    (Tag::POSTUN, Tag::POSTUNPROG, "%postun"),
    (Tag::TRIGGERSCRIPTS, Tag::TRIGGERSCRIPTPROG, "%trigger"),
    (Tag::PRETRANS, Tag::PRETRANSPROG, "%pretrans"),
    (Tag::POSTTRANS, Tag::POSTTRANSPROG, "%posttrans"),
    (Tag::VERIFYSCRIPT, Tag::VERIFYSCRIPTPROG, "%verifyscript"),
    (
        Tag::FILETRIGGERSCRIPTS,
        Tag::FILETRIGGERSCRIPTPROG,
        "%filetrigger",
    ),
    (
        Tag::TRANSFILETRIGGERSCRIPTS,
        Tag::TRANSFILETRIGGERSCRIPTPROG,
        "%transfiletrigger",
    ),
];

/// Errors opening a package.
#[derive(Debug, thiserror::Error)]
pub enum PkgError {
    #[error("librpm init failed: {0}")]
    Init(String),
    #[error("failed to open {path}: {source}")]
    Open {
        path: PathBuf,
        source: librpm::RpmErrorKind,
    },
    #[error(transparent)]
    Extract(#[from] extract::ExtractError),
    #[error("creating the extraction tempdir: {0}")]
    Tempdir(#[from] std::io::Error),
    /// An rpmdb operation failed. Only the failures librpm surfaces reach this;
    /// a database it cannot open reads as empty (see `installed`).
    #[error("rpmdb: {0}")]
    Db(#[from] librpm::error::Error),
}

/// Call `librpm::init()` exactly once per process, caching its result so
/// concurrent opens neither double-init nor lose the failure. Idempotent, and
/// public because a caller that needs its own `Db` must configure librpm before
/// constructing it.
pub fn init() -> Result<(), PkgError> {
    static INIT: OnceLock<Result<(), String>> = OnceLock::new();
    match INIT.get_or_init(|| librpm::init().map_err(|e| e.to_string())) {
        Ok(()) => Ok(()),
        Err(e) => Err(PkgError::Init(e.clone())),
    }
}

/// A parsed RPM package (file-backed), mirroring rpmlint's `Pkg`.
pub struct Pkg {
    /// The path as passed to [`Pkg::open`] (rpmlint stores it verbatim).
    pub filename: String,
    pub name: String,
    pub arch: String,
    pub is_source: bool,
    pub requires: Vec<DepInfo>,
    pub prereq: Vec<DepInfo>,
    pub provides: Vec<DepInfo>,
    pub conflicts: Vec<DepInfo>,
    pub obsoletes: Vec<DepInfo>,
    pub recommends: Vec<DepInfo>,
    pub suggests: Vec<DepInfo>,
    pub enhances: Vec<DepInfo>,
    pub supplements: Vec<DepInfo>,
    pub req_names: Vec<String>,
    pub files: Vec<PkgFile>,
    pub config_files: Vec<String>,
    pub doc_files: Vec<String>,
    pub ghost_files: Vec<String>,
    pub noreplace_files: Vec<String>,
    pub missingok_files: Vec<String>,
    /// The extraction directory; `None` only for an installed package (M2c),
    /// which reads the live filesystem.
    pub dir_name: Option<PathBuf>,
    /// True once the payload has been unpacked into `dir_name`.
    pub extracted: bool,
    /// Per-phase wall-clock timings, accumulated in seconds and reported by
    /// `-t` (`pkg.py:534`).
    pub timers: Timers,
    header: PackageHeader,
    /// Owns the extraction tempdir; removed on drop.
    tempdir: Option<tempfile::TempDir>,
}

/// rpmlint's `Pkg.timers`: seconds spent per named phase (`ExtractRpm`,
/// `libmagic`), accumulated across the package and folded into the `-t` time
/// report.
#[derive(Debug, Clone, Default)]
pub struct Timers(BTreeMap<String, f64>);

impl Timers {
    /// The seconds accumulated under `key`, `0.0` when it never ran.
    pub fn get(&self, key: &str) -> f64 {
        self.0.get(key).copied().unwrap_or(0.0)
    }

    /// The accumulated `(phase, seconds)` pairs, in phase-name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, f64)> + '_ {
        self.0.iter().map(|(k, v)| (k.as_str(), *v))
    }

    fn add(&mut self, key: &str, secs: f64) {
        *self.0.entry(key.to_string()).or_insert(0.0) += secs;
    }

    /// The reference always records an `ExtractRpm` entry, even for an
    /// installed package where extraction is a no-op (`pkg.py:534`).
    fn with_extract(secs: f64) -> Self {
        let mut t = Self::default();
        t.add(EXTRACT_RPM, secs);
        t
    }
}

/// The `ExtractRpm` phase name.
const EXTRACT_RPM: &str = "ExtractRpm";
/// The `libmagic` phase name.
const LIBMAGIC: &str = "libmagic";

impl Pkg {
    /// Open a `.rpm` file, unpack its payload into a tempdir under
    /// `extract_dir`, and build the package. Signature checks are skipped, as
    /// rpmlint does; `extract_dir` comes from the config's `ExtractDir`.
    pub fn open(path: &Path, extract_dir: &Path) -> Result<Self, PkgError> {
        init()?;
        let header = PackageHeader::from_file(path, Some(&VerifyOptions::skip_verification()))
            .map_err(|source| PkgError::Open {
                path: path.to_path_buf(),
                source,
            })?;
        // rpmlint stores the as-passed path verbatim (`self.filename = filename`)
        // — not the basename. `SignatureCheck` prints it, and it is resolved
        // for extraction.
        let filename = path.to_string_lossy().into_owned();
        // rpmlint treats a `'/'` dirname as "installed package, do not extract"
        // (`pkg.py:610-613`); honour that so `ExtractDir = "/"` cannot unpack
        // into the live root. `extracted` stays false there, as in the
        // reference.
        if extract_dir == Path::new("/") {
            return Ok(Self::build(
                header,
                Some(PathBuf::from("/")),
                filename,
                None,
                false,
                None,
                Timers::with_extract(0.0),
            ));
        }
        // Extraction happens in `Pkg.__init__`: a TemporaryDirectory under the
        // config's `ExtractDir`, prefixed `rpmlint.<rpm-basename>.`.
        let base = Path::new(&filename)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let start = Instant::now();
        let tempdir = tempfile::Builder::new()
            .prefix(&format!("rpmlint.{base}."))
            .tempdir_in(extract_dir)?;
        extract::extract(path, tempdir.path())?;
        let extract_secs = start.elapsed().as_secs_f64();
        let dir_name = tempdir.path().to_path_buf();
        Ok(Self::build(
            header,
            Some(dir_name),
            filename,
            None,
            true,
            Some(tempdir),
            Timers::with_extract(extract_secs),
        ))
    }

    /// Build an installed package from an rpmdb header (rpmlint `InstalledPkg`):
    /// `dir_name` is `/`, so paths are the live filesystem, there is no
    /// extraction, the filename is synthesized, and `is_source` is forced false.
    pub fn installed(header: PackageHeader) -> Self {
        let tag = |t| tags::str_tag(&header, t).unwrap_or_default();
        let filename = format!(
            "{}-{}-{}.{}.rpm",
            tag(Tag::NAME),
            tag(Tag::VERSION),
            tag(Tag::RELEASE),
            tag(Tag::ARCH)
        );
        Self::build(
            header,
            Some(PathBuf::from("/")),
            filename,
            Some(false),
            true,
            None,
            Timers::with_extract(0.0),
        )
    }

    /// Shared construction from a header. `is_source` defaults to the header's
    /// `SOURCERPM` presence (the file case); an installed package passes
    /// `Some(false)` as rpmlint forces it. `extracted` is an explicit parameter
    /// rather than derived from `tempdir`: the reference sets it true for an
    /// installed package (no tempdir, but `dir_name` is the live `/`) and false
    /// for a file with `ExtractDir = "/"`. `timers` carries the `ExtractRpm`
    /// measurement and gains `libmagic` while the file list is built.
    fn build(
        header: PackageHeader,
        dir_name: Option<PathBuf>,
        filename: String,
        is_source: Option<bool>,
        extracted: bool,
        tempdir: Option<tempfile::TempDir>,
        mut timers: Timers,
    ) -> Self {
        let is_source = is_source.unwrap_or_else(|| header.get_owned(Tag::SOURCERPM).is_none());
        let name = tags::str_tag(&header, Tag::NAME).unwrap_or_default();

        let (requires, prereq) = gather_requires(&header);
        let provides = gather_deps(
            &header,
            Tag::PROVIDENAME,
            Tag::PROVIDEFLAGS,
            Tag::PROVIDEVERSION,
        );
        let conflicts = gather_deps(
            &header,
            Tag::CONFLICTNAME,
            Tag::CONFLICTFLAGS,
            Tag::CONFLICTVERSION,
        );
        let obsoletes = gather_deps(
            &header,
            Tag::OBSOLETENAME,
            Tag::OBSOLETEFLAGS,
            Tag::OBSOLETEVERSION,
        );
        let recommends = gather_deps(
            &header,
            Tag::RECOMMENDNAME,
            Tag::RECOMMENDFLAGS,
            Tag::RECOMMENDVERSION,
        );
        let suggests = gather_deps(
            &header,
            Tag::SUGGESTNAME,
            Tag::SUGGESTFLAGS,
            Tag::SUGGESTVERSION,
        );
        let enhances = gather_deps(
            &header,
            Tag::ENHANCENAME,
            Tag::ENHANCEFLAGS,
            Tag::ENHANCEVERSION,
        );
        let supplements = gather_deps(
            &header,
            Tag::SUPPLEMENTNAME,
            Tag::SUPPLEMENTFLAGS,
            Tag::SUPPLEMENTVERSION,
        );

        let req_names = requires
            .iter()
            .chain(&prereq)
            .map(|d| d.name.clone())
            .collect::<Vec<_>>();

        let files = gather_files(&header, dir_name.as_deref(), &mut timers);
        let names = |p: fn(&PkgFile) -> bool| -> Vec<String> {
            files
                .iter()
                .filter(|f| p(f))
                .map(|f| f.name.clone())
                .collect()
        };
        let config_files = names(PkgFile::is_config);
        let doc_files = names(PkgFile::is_doc);
        let ghost_files = names(PkgFile::is_ghost);
        let noreplace_files = names(PkgFile::is_noreplace);
        let missingok_files = names(PkgFile::is_missingok);

        // A NoSource package is a source package whose files are all ghosts.
        let is_no_source = is_source && !ghost_files.is_empty();
        let arch = if is_no_source {
            "nosrc".to_string()
        } else if is_source {
            "src".to_string()
        } else {
            tags::str_tag(&header, Tag::ARCH).unwrap_or_default()
        };

        Self {
            filename,
            name,
            arch,
            is_source,
            requires,
            prereq,
            provides,
            conflicts,
            obsoletes,
            recommends,
            suggests,
            enhances,
            supplements,
            req_names,
            files,
            config_files,
            doc_files,
            ghost_files,
            noreplace_files,
            missingok_files,
            dir_name,
            extracted,
            timers,
            header,
            tempdir,
        }
    }

    /// The underlying librpm header, for tag access.
    pub fn header(&self) -> &PackageHeader {
        &self.header
    }

    /// True for a NoSource package (source whose files are all ghosts).
    pub fn is_no_source(&self) -> bool {
        self.is_source && !self.ghost_files.is_empty()
    }

    /// Read a scalar string tag (rpmlint `pkg[tag]`): byte-decoded, empty →
    /// `None`, and `GROUP == "Unspecified"` → `None`.
    pub fn tag_str(&self, tag: Tag) -> Option<String> {
        let v = tags::str_tag(&self.header, tag);
        if tag == Tag::GROUP && v.as_deref() == Some("Unspecified") {
            return None;
        }
        v
    }

    /// Read a STRING_ARRAY tag.
    pub fn tag_str_array(&self, tag: Tag) -> Vec<String> {
        tags::str_array(&self.header, tag)
    }

    /// The interpreter for a scriptlet tag (rpmlint `scriptprog`): `''` when
    /// absent, otherwise the joined `*PROG` (a 1-element array decodes as a
    /// bare string, so join handles both).
    pub fn scriptprog(&self, which: Tag) -> String {
        self.tag_str_array(which).join("")
    }

    /// Read an extracted file as UTF-8 (rpmlint `read_with_mmap`). `''` when it
    /// cannot be read or is not valid UTF-8, matching the reference's
    /// `except Exception: return ''`.
    pub fn read_file(&self, filename: &str) -> String {
        let base = self.dir_name.as_deref().unwrap_or_else(|| Path::new("/"));
        let path = file_path(Some(base), filename);
        std::fs::read(path)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default()
    }

    /// The first 1-based line number in `filename` matching `regex` (rpmlint
    /// `grep`), or `None`.
    pub fn grep(&self, regex: &fancy_regex::Regex, filename: &str) -> Option<usize> {
        let data = self.read_file(filename);
        let m = regex.find(&data).ok().flatten()?;
        Some(data[..m.start()].matches('\n').count() + 1)
    }

    /// Resolve a symlink chain within this package (rpmlint `readlink`):
    /// returns the dereferenced [`PkgFile`], or `None` when the chain leaves
    /// the package. Bounded by the file count, so a symlink cycle cannot loop
    /// forever (a deliberate robustness divergence; rpmlint would hang).
    pub fn readlink(&self, pkgfile: &PkgFile) -> Option<&PkgFile> {
        // Start from this package's own copy of the file, so the returned
        // reference borrows `self` (the reference resolves within `self.files`
        // too).
        let mut result = self.files.iter().find(|f| f.name == pkgfile.name)?;
        for _ in 0..self.files.len() {
            if result.linkto.is_empty() {
                return Some(result);
            }
            let linkpath = normalize_path(&join_url(&result.name, &result.linkto));
            result = self.files.iter().find(|f| f.name == linkpath)?;
        }
        None
    }

    /// Remove the extraction tempdir (rpmlint `cleanup`); it is also removed on
    /// drop. `dir_name` deliberately keeps pointing at the removed path, so a
    /// read after cleanup fails to `''` exactly as the reference does — nulling
    /// it would make `read_file` fall back to the host filesystem.
    pub fn cleanup(&mut self) {
        self.tempdir = None;
    }
}

/// Split `REQUIRENAME`/`REQUIREFLAGS`/`REQUIREVERSION` into `(requires,
/// prereq)`, moving entries whose flags carry `PREREQ_FLAG` (with the prereq
/// bits stripped) into `prereq` (rpmlint `_gather_aux`).
fn gather_requires(header: &PackageHeader) -> (Vec<DepInfo>, Vec<DepInfo>) {
    let names = tags::str_array(header, Tag::REQUIRENAME);
    let flags = tags::int32_array(header, Tag::REQUIREFLAGS);
    let versions = tags::str_array(header, Tag::REQUIREVERSION);
    let mut requires = Vec::new();
    let mut prereq = Vec::new();
    // rpmlint zips (versions, names, flags): stop at the shortest array.
    let n = versions.len().min(names.len()).min(flags.len());
    for i in 0..n {
        let name = names[i].clone();
        let flag = flags[i] as u32;
        let (epoch, version, release) = string_to_version(&versions[i]);
        if flag & PREREQ_FLAG != 0 {
            prereq.push(DepInfo {
                name,
                flags: flag & !PREREQ_FLAG,
                epoch,
                version,
                release,
            });
        } else {
            requires.push(DepInfo {
                name,
                flags: flag,
                epoch,
                version,
                release,
            });
        }
    }
    (requires, prereq)
}

/// Zip a `NAME`/`FLAGS`/`VERSION` tag triple into `DepInfo`s (rpmlint
/// `_gather_aux`). Like the reference's `zip(versions, names, flags)`, a ragged
/// header stops at the **shortest** of the three arrays — no phantom
/// empty-named deps — and an empty `VERSION` yields none (`if versions:`).
fn gather_deps(
    header: &PackageHeader,
    name_tag: Tag,
    flag_tag: Tag,
    version_tag: Tag,
) -> Vec<DepInfo> {
    let versions = tags::str_array(header, version_tag);
    let names = tags::str_array(header, name_tag);
    let flags = tags::int32_array(header, flag_tag);
    let n = versions.len().min(names.len()).min(flags.len());
    (0..n)
        .map(|i| {
            let (epoch, version, release) = string_to_version(&versions[i]);
            DepInfo {
                name: names[i].clone(),
                flags: flags[i] as u32,
                epoch,
                version,
                release,
            }
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The compressed-payload marker rpmlint strips from `magic`
/// (`Pkg._magic_from_compressed_re`).
fn compressed_magic_re() -> &'static fancy_regex::Regex {
    static RE: OnceLock<fancy_regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        fancy_regex::Regex::new(r"\([^)]+\s+compressed\s+data\b").expect("static regex")
    })
}

/// rpmlint `AbstractPkg._calc_magic`: the header's `FILECLASS` if present,
/// else the directory / symlink / empty branch, else libmagic on the extracted
/// file (skipped for ghosts); then the compressed-marker filter. The libmagic
/// time lands in `timers` under `libmagic` (`pkg.py:396-399`).
fn calc_magic(
    header_magic: &str,
    mode: u32,
    size: u64,
    linkto: &str,
    path: &Path,
    is_ghost: bool,
    timers: &mut Timers,
) -> String {
    let mut m = header_magic.to_string();
    if m.is_empty() {
        if pkgfile::is_dir(mode) {
            m = "directory".to_string();
        } else if pkgfile::is_symlink(mode) {
            m = format!("symbolic link to `{linkto}'");
        } else if size == 0 {
            m = "empty".to_string();
        }
    }
    if m.is_empty() && !is_ghost {
        let start = Instant::now();
        m = extract::file_magic(path);
        timers.add(LIBMAGIC, start.elapsed().as_secs_f64());
    }
    if m.is_empty() || compressed_magic_re().is_match(&m).unwrap_or(false) {
        m.clear();
    }
    m
}

/// rpmlint's `PkgFile.path`: `normpath(join(dir_name or '/', name.lstrip('/')))`.
fn file_path(dir: Option<&Path>, name: &str) -> String {
    let base = dir.unwrap_or_else(|| Path::new("/"));
    let joined = base.join(name.trim_start_matches('/'));
    normalize_path(&joined.to_string_lossy())
}

/// rpmlint's `urljoin(name, linkto)` for path-like strings: an absolute
/// `linkto` wins, otherwise it is resolved against `name`'s directory. The
/// caller `normpath`s the result.
fn join_url(name: &str, linkto: &str) -> String {
    if linkto.starts_with('/') {
        return linkto.to_string();
    }
    match name.rfind('/') {
        Some(i) => format!("{}/{}", &name[..i], linkto),
        None => linkto.to_string(),
    }
}

/// Build the file map (rpmlint `_gather_files_info`). Per-file metadata comes
/// from librpm's `FileEntry`; `inode`/`rdev`/`lang`/`fileclass` are read from
/// the parallel header arrays (librpm's `FileEntry` does not expose them).
fn gather_files(header: &PackageHeader, dir: Option<&Path>, timers: &mut Timers) -> Vec<PkgFile> {
    let inodes = tags::int32_array(header, Tag::FILEINODES);
    let rdevs = tags::int16_array(header, Tag::FILERDEVS);
    let langs = tags::str_array(header, Tag::FILELANGS);
    let fileclass = tags::str_array(header, Tag::FILECLASS);
    let filecaps = tags::str_array(header, Tag::FILECAPS);
    let file_requires = tags::str_array(header, Tag::FILEREQUIRE);
    let file_provides = tags::str_array(header, Tag::FILEPROVIDE);

    let files = header.files();
    let mut out = Vec::with_capacity(files.len());
    for (i, entry) in files.iter().enumerate() {
        let name = entry.path();
        let mode = u32::from(entry.mode());
        let size = entry.size();
        let flags = entry.flags();
        let linkto_raw = entry.link_target().unwrap_or_default();
        let linkto = if linkto_raw.is_empty() {
            String::new()
        } else {
            normalize_path(linkto_raw)
        };
        let path = file_path(dir, &name);
        let magic = calc_magic(
            fileclass.get(i).map(String::as_str).unwrap_or(""),
            mode,
            size,
            &linkto,
            Path::new(&path),
            flags.is_ghost(),
            timers,
        );
        out.push(PkgFile {
            path,
            name,
            flags: flags.bits(),
            mode,
            user: entry.user().to_string(),
            group: entry.group().to_string(),
            linkto,
            size: Some(size),
            // librpm returns an all-zero digest for entries with no digest
            // (directories, symlinks, ghosts); rpmlint's raw FILEMD5S is empty
            // there, so map an all-zero digest to the empty string.
            md5: entry.digest().map(|d| {
                if d.iter().all(|&b| b == 0) {
                    String::new()
                } else {
                    hex(d)
                }
            }),
            mtime: entry.mtime(),
            rdev: rdevs.get(i).map_or(0, |v| *v as u32),
            inode: inodes.get(i).map_or(0, |v| *v as u32),
            lang: langs.get(i).cloned().unwrap_or_default(),
            magic,
            // rpmlint sets `filecaps` only when the `FILECAPS` tag is present
            // (`if filecaps:`): an absent tag yields `None`, a present-but-empty
            // entry yields `''`.
            filecaps: if filecaps.is_empty() {
                None
            } else {
                filecaps.get(i).cloned()
            },
            requires: parse_dep_line(file_requires.get(i).map(String::as_str).unwrap_or("")),
            provides: parse_dep_line(file_provides.get(i).map(String::as_str).unwrap_or("")),
        });
    }
    out
}

/// `os.path.normpath` for POSIX paths: collapse repeated slashes and `.`,
/// resolve `x/..`, and — like `normpath` — **preserve leading `..`** on a
/// relative path (do not resolve them against a root). `""` becomes `"."`.
pub fn normalize_path(p: &str) -> String {
    if p.is_empty() {
        return ".".to_string();
    }
    let absolute = p.starts_with('/');
    // POSIX normpath preserves exactly two leading slashes ("//a" stays "//a").
    let double_leading = p.starts_with("//") && !p.starts_with("///");
    let mut out: Vec<&str> = Vec::new();
    for comp in p.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                if out.last() == Some(&"..") {
                    out.push("..");
                } else if !out.is_empty() {
                    out.pop();
                } else if !absolute {
                    out.push("..");
                }
                // absolute with an empty stack: ".." at the root stays there
            }
            c => out.push(c),
        }
    }
    let joined = out.join("/");
    if absolute {
        if double_leading {
            format!("//{joined}")
        } else {
            format!("/{joined}")
        }
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// Per-file `Requires`/`Provides` (`FILEREQUIRE`/`FILEPROVIDE`) are left
/// unparsed until `PostCheck`/`FileDigestCheck` are ported, which consume them
/// (rpmlint's `parse_deps`). Always empty for now.
fn parse_dep_line(_line: &str) -> Vec<DepInfo> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_matches_os_path_normpath() {
        // Verified against python3 os.path.normpath.
        assert_eq!(normalize_path("/usr/lib64/x"), "/usr/lib64/x");
        assert_eq!(normalize_path("//usr//lib64/x"), "//usr/lib64/x");
        assert_eq!(normalize_path("/usr/lib64/../bin/x"), "/usr/bin/x");
        assert_eq!(normalize_path("../LLVMgold.so"), "../LLVMgold.so");
        assert_eq!(normalize_path("./a/b"), "a/b");
        assert_eq!(normalize_path("a/b/.."), "a");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path(""), ".");
        assert_eq!(normalize_path("."), ".");
        assert_eq!(normalize_path("a//b///c"), "a/b/c");
        assert_eq!(normalize_path("a/./b"), "a/b");
    }

    #[test]
    fn calc_magic_branches_need_no_file() {
        let none = Path::new("/nonexistent");
        let mut t = Timers::default();
        assert_eq!(
            calc_magic("", 0o040755, 0, "", none, false, &mut t),
            "directory"
        );
        assert_eq!(
            calc_magic("", 0o120777, 10, "../x", none, false, &mut t),
            "symbolic link to `../x'"
        );
        assert_eq!(
            calc_magic("", 0o100644, 0, "", none, false, &mut t),
            "empty"
        );
        // A populated FILECLASS wins and needs no file.
        assert_eq!(
            calc_magic("ELF 64-bit LSB", 0o100755, 9, "", none, false, &mut t),
            "ELF 64-bit LSB"
        );
        // A ghost never falls through to libmagic.
        assert_eq!(calc_magic("", 0o100644, 9, "", none, true, &mut t), "");
        // The compressed-payload marker is stripped.
        assert_eq!(
            calc_magic(
                "a (gzip compressed data, from Unix)",
                0o100644,
                9,
                "",
                none,
                false,
                &mut t
            ),
            ""
        );
        // None of those touched the filesystem, so nothing is timed.
        assert_eq!(t.get(LIBMAGIC), 0.0);
        assert!(t.iter().next().is_none());
    }

    #[test]
    fn calc_magic_falls_back_to_libmagic() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("hello.txt");
        std::fs::write(&p, "hello\n").unwrap();
        // Empty FILECLASS, regular non-empty, not a ghost -> libmagic.
        let mut t = Timers::default();
        assert_eq!(
            calc_magic("", 0o100644, 6, "", &p, false, &mut t),
            "ASCII text"
        );
        // The `file -b` call is timed, so it shows up in the `-t` report.
        assert!(t.iter().any(|(k, _)| k == LIBMAGIC));
    }

    #[test]
    fn extract_timer_is_always_recorded() {
        // An installed package records ExtractRpm even though it never extracts.
        let t = Timers::with_extract(0.0);
        assert_eq!(t.get(EXTRACT_RPM), 0.0);
        let t = Timers::with_extract(1.5);
        assert_eq!(t.get(EXTRACT_RPM), 1.5);
    }
}
