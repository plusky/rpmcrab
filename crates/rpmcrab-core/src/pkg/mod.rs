//! The `Pkg` abstraction — the Rust equivalent of rpmlint's `pkg.py`.
//!
//! M2a covers the **file-backed** layer: the header, the nine dependency
//! lists, the file map, and the derived `config/doc/ghost/noreplace/missingok`
//! name lists. Payload extraction (`dir_name`, `PkgFile.path`) is M2b; the
//! installed DB (`db::Db`) is M2c; the spec `FakePkg` is M3.

pub mod dep;
pub mod pkgfile;
pub mod tags;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

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
}

/// Call `librpm::init()` exactly once per process, caching its result so
/// concurrent opens neither double-init nor lose the failure.
fn init() -> Result<(), PkgError> {
    static INIT: OnceLock<Result<(), String>> = OnceLock::new();
    match INIT.get_or_init(|| librpm::init().map_err(|e| e.to_string())) {
        Ok(()) => Ok(()),
        Err(e) => Err(PkgError::Init(e.clone())),
    }
}

/// A parsed RPM package (file-backed), mirroring rpmlint's `Pkg`.
pub struct Pkg {
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
    /// The extraction directory; `None` until M2b unpacks the payload.
    pub dir_name: Option<PathBuf>,
    header: PackageHeader,
}

impl Pkg {
    /// Open a `.rpm` file and build the package (signature checks skipped, as
    /// rpmlint does).
    pub fn open(path: &Path) -> Result<Self, PkgError> {
        init()?;
        let header = PackageHeader::from_file(path, Some(&VerifyOptions::skip_verification()))
            .map_err(|source| PkgError::Open {
                path: path.to_path_buf(),
                source,
            })?;
        Ok(Self::from_header(header, path))
    }

    fn from_header(header: PackageHeader, path: &Path) -> Self {
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = tags::str_tag(&header, Tag::NAME).unwrap_or_default();
        let is_source = header.get_owned(Tag::SOURCERPM).is_none();

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

        let files = gather_files(&header);
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
            dir_name: None,
            header,
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
    for (i, name) in names.iter().enumerate() {
        let flag = flags.get(i).copied().unwrap_or(0) as u32;
        let (epoch, version, release) =
            string_to_version(versions.get(i).map(String::as_str).unwrap_or(""));
        if flag & PREREQ_FLAG != 0 {
            prereq.push(DepInfo {
                name: name.clone(),
                flags: flag & !PREREQ_FLAG,
                epoch,
                version,
                release,
            });
        } else {
            requires.push(DepInfo {
                name: name.clone(),
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
/// `_gather_aux`).
fn gather_deps(
    header: &PackageHeader,
    name_tag: Tag,
    flag_tag: Tag,
    version_tag: Tag,
) -> Vec<DepInfo> {
    let names = tags::str_array(header, name_tag);
    let flags = tags::int32_array(header, flag_tag);
    let versions = tags::str_array(header, version_tag);
    names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let (epoch, version, release) =
                string_to_version(versions.get(i).map(String::as_str).unwrap_or(""));
            DepInfo {
                name: name.clone(),
                flags: flags.get(i).copied().unwrap_or(0) as u32,
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

/// Build the file map (rpmlint `_gather_files_info`). Per-file metadata comes
/// from librpm's `FileEntry`; `inode`/`rdev`/`lang`/`fileclass` are read from
/// the parallel header arrays (librpm's `FileEntry` does not expose them).
fn gather_files(header: &PackageHeader) -> Vec<PkgFile> {
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
        let linkto_raw = entry.link_target().unwrap_or_default();
        let linkto = if linkto_raw.is_empty() {
            String::new()
        } else {
            normalize_path(linkto_raw)
        };
        out.push(PkgFile {
            // M2a: not extracted, so `dir_name` is `None` and the path is the
            // package-relative name (rpmlint uses `'/'` as the base).
            path: normalize_path(&name),
            name,
            flags: entry.flags().bits(),
            mode: u32::from(entry.mode()),
            user: entry.user().to_string(),
            group: entry.group().to_string(),
            linkto,
            size: Some(entry.size()),
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
            magic: fileclass.get(i).cloned().unwrap_or_default(),
            filecaps: filecaps.get(i).filter(|s| !s.is_empty()).cloned(),
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

/// Placeholder for per-file dependency parsing (rpmlint `parse_deps`). The
/// `FILEREQUIRE`/`FILEPROVIDE` strings are space/comma lists of `name [op ver]`
/// clauses; implemented at M3 where `PostCheck`/`FileDigestCheck` consume them.
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
}
