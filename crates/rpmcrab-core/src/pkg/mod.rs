//! The `Pkg` abstraction — the Rust equivalent of rpmlint's `pkg.py`.
//!
//! Two package kinds: **binary RPM** ([`Package::Rpm`], the payload extracted
//! into a tempdir so `PkgFile.path` and `magic` match the reference) and
//! **spec file** ([`Package::Spec`], `SpecPkg` — the former `FakePkg`, now
//! shipped). The binary kind exposes the header, the nine dependency lists,
//! the file map, and the derived `config/doc/ghost/noreplace/missingok`
//! name lists. A third way in is an **installed package** ([`Pkg::installed`],
//! the reference's `InstalledPkg`): a package read from the rpmdb with no
//! extraction, whose reads resolve against the live filesystem.

pub mod dep;
pub mod extract;
pub mod installed;
pub mod pkgfile;
pub mod spec;
pub mod tags;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

use librpm::verify::VerifyOptions;
use librpm::{OwnedTagData, PackageHeader, Tag};

use dep::{DepInfo, string_to_version};
use pkgfile::PkgFile;
use spec::SpecPkg;

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
    /// A panic inside a librpm safe-API call, contained by `guarded`.
    #[error("librpm could not decode the package: {message}")]
    Decode { message: String },
}

/// Run `f` with any panic contained, so a librpm panic becomes a typed
/// [`PkgError::Decode`] instead of unwinding past the report.
///
/// librpm 0.6's decoders panic on data the reference tolerates: a non-UTF-8
/// `STRING_ARRAY` entry aborts `string_array` (`.expect` on `str::from_utf8`),
/// and `FileEntry::path` does `.to_str().expect("file path is not UTF-8")`.
/// Both are reachable from any package header, since every header field read
/// goes through them. Reading the raw bytes instead would mean calling
/// `librpm-sys` directly, which `unsafe_code = "forbid"` rules out, so the
/// panic is caught and surfaced as a read error — the same one-line diagnostic
/// and status the reference produces for a package it cannot read
/// (`lint.py:293-297`).
///
/// The default panic hook is replaced for the duration so the user sees that
/// one line rather than a backtrace followed by it. The hook is process-global,
/// which is why this is scoped to the call and restored immediately.
pub(crate) fn guarded<T>(f: impl FnOnce() -> Result<T, PkgError>) -> Result<T, PkgError> {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(previous);
    match outcome {
        Ok(result) => result,
        Err(payload) => Err(PkgError::Decode {
            message: panic_message(payload),
        }),
    }
}

/// The message from a caught panic payload, which is a `String` for every
/// `panic!` with a format argument (including librpm's own decoders).
fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else {
        "unknown panic payload".to_string()
    }
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

/// Where a [`Pkg`]'s bytes come from. The reference distinguishes exactly these
/// situations, so they are a closed set: separate `dir_name`/`extracted`
/// fields cannot express an impossible combination, and a read can never
/// silently fall back to the host filesystem again. The one extra variant,
/// `Sandboxed`, is test-only: it gives header-only test opens an owned empty
/// base dir, so they stay hermetic without pretending an extraction ran.
#[derive(Debug)]
pub(crate) enum PkgSource {
    /// Payload unpacked into an owned tempdir (removed on drop).
    Extracted {
        /// The extraction directory.
        dir: PathBuf,
        /// Owns the tempdir; dropping it removes the directory.
        tempdir: tempfile::TempDir,
    },
    /// An installed package: reads resolve against the live filesystem.
    /// The reference's `InstalledPkg` reports `extracted == true`.
    Installed,
    /// A file package with `ExtractDir='/'`: no extraction, reads resolve
    /// against the live filesystem, `extracted == false`.
    LiveRoot,
    /// A test-only header open with no extraction: reads resolve against an
    /// owned empty sandbox tempdir (removed on drop), so tests are hermetic —
    /// no read can touch the live filesystem. `extracted == false`, as no
    /// extraction ran; that is why this is its own variant rather than
    /// reusing `Extracted` (which claims an extraction happened) or
    /// `CleanedUp` (which points at a removed path).
    #[cfg(test)]
    Sandboxed {
        /// The sandbox directory.
        dir: PathBuf,
        /// Owns the tempdir; dropping it removes the directory.
        tempdir: tempfile::TempDir,
    },
    /// [`Pkg::cleanup`] dropped the tempdir; reads fail to `''`, exactly as
    /// the reference's post-cleanup reads do. Still points at the removed
    /// path, like the reference's `dirname`.
    CleanedUp {
        /// The removed extraction directory.
        dir: PathBuf,
    },
}

impl PkgSource {
    /// The directory reads resolve against: the extraction directory, the
    /// owned empty sandbox for test-only header opens, or `/` for the
    /// live-filesystem sources. `CleanedUp` keeps pointing at the removed
    /// path, so reads fail there instead of falling back to `/`.
    fn base_dir(&self) -> &Path {
        match self {
            PkgSource::Extracted { dir, .. } => dir,
            #[cfg(test)]
            PkgSource::Sandboxed { dir, .. } => dir,
            PkgSource::Installed | PkgSource::LiveRoot => Path::new("/"),
            PkgSource::CleanedUp { dir } => dir,
        }
    }

    /// The reference's `extracted` flag, as a total function of the variant —
    /// no flag field remains.
    fn extracted(&self) -> bool {
        match self {
            PkgSource::Extracted { .. } | PkgSource::Installed | PkgSource::CleanedUp { .. } => {
                true
            }
            PkgSource::LiveRoot => false,
            #[cfg(test)]
            PkgSource::Sandboxed { .. } => false,
        }
    }
}

/// What the lint loop runs checks over: a binary RPM or a spec file. The
/// reference dispatches `check` vs `check_spec` on holding a `FakePkg`, not
/// on `is_source` (docs/DESIGN.md §7.5).
pub enum Package {
    /// A binary RPM (`Pkg`), boxed: the payload model dwarfs the spec one.
    Rpm(Box<Pkg>),
    /// A `.spec` file (`SpecPkg`).
    Spec(SpecPkg),
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
    /// Where this package's bytes come from (`docs/DESIGN.md` §7.5). Private:
    /// callers use [`Pkg::dir_name`] and [`Pkg::extracted`], never the states.
    source: PkgSource,
    /// Per-phase wall-clock timings, accumulated in seconds and reported by
    /// `-t` (`pkg.py:534`).
    pub timers: Timers,
    header: PackageHeader,
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

/// Read a package header, skipping signature checks as rpmlint does.
fn read_header(path: &Path) -> Result<PackageHeader, PkgError> {
    PackageHeader::from_file(path, Some(&VerifyOptions::skip_verification())).map_err(|source| {
        PkgError::Open {
            path: path.to_path_buf(),
            source,
        }
    })
}

impl Pkg {
    /// Open a `.rpm` file, unpack its payload into a tempdir under
    /// `extract_dir`, and build the package. Signature checks are skipped, as
    /// rpmlint does; `extract_dir` comes from the config's `ExtractDir`.
    /// `suppress_stderr` discards the extractor child's stderr outright;
    /// when false, stderr is inherited in verbose mode and discarded
    /// otherwise. (The reference always discards, DEVNULL even in verbose
    /// mode: pkg.py's `None if verbose else DEVNULL` is dead, overwritten
    /// unconditionally two lines later.)
    pub fn open(path: &Path, extract_dir: &Path, suppress_stderr: bool) -> Result<Self, PkgError> {
        init()?;
        guarded(|| Self::read(path, extract_dir, suppress_stderr))
    }

    /// Open a fixture RPM's header without extracting its payload.
    /// For tests that overwrite `files` wholesale: header tags are read, no
    /// extraction subprocess runs, and reads resolve against an owned empty
    /// sandbox tempdir ([`PkgSource::Sandboxed`]) rather than the live
    /// filesystem — the test stays hermetic (reading a fixture absolute path
    /// returns `''` instead of host content). `extracted` stays false, as no
    /// extraction ran.
    #[cfg(test)]
    pub fn open_no_extract(path: &Path) -> Result<Self, PkgError> {
        init()?;
        guarded(|| {
            let header = read_header(path)?;
            let filename = path.to_string_lossy().into_owned();
            // An owned empty sandbox: reads resolve against it (via
            // `base_dir`), and it is removed on drop. Prefix joins the
            // `rpmlint.` family the extraction tempdirs use.
            let tempdir = tempfile::Builder::new()
                .prefix("rpmlint.sandbox.")
                .tempdir()?;
            let source = PkgSource::Sandboxed {
                dir: tempdir.path().to_path_buf(),
                tempdir,
            };
            Ok(Self::build(
                header,
                source,
                filename,
                None,
                Timers::with_extract(0.0),
            ))
        })
    }

    /// The body of [`Pkg::open`], run under [`guarded`].
    fn read(path: &Path, extract_dir: &Path, suppress_stderr: bool) -> Result<Self, PkgError> {
        let header = read_header(path)?;
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
                PkgSource::LiveRoot,
                filename,
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
        extract::extract(path, tempdir.path(), suppress_stderr)?;
        let extract_secs = start.elapsed().as_secs_f64();
        let dir_name = tempdir.path().to_path_buf();
        let source = PkgSource::Extracted {
            dir: dir_name,
            tempdir,
        };
        Ok(Self::build(
            header,
            source,
            filename,
            None,
            Timers::with_extract(extract_secs),
        ))
    }

    /// Build an installed package from an rpmdb header (rpmlint `InstalledPkg`):
    /// reads resolve against the live filesystem, there is no extraction, the
    /// filename is synthesized, and `is_source` is forced false.
    /// # Errors
    /// [`PkgError::Decode`] when a header field cannot be decoded; see
    /// `guarded`. An installed package is read the same way as a file, so it
    /// fails the same way.
    pub fn installed(header: PackageHeader) -> Result<Self, PkgError> {
        guarded(|| {
            let tag = |t| tags::str_tag(&header, t).unwrap_or_default();
            let filename = format!(
                "{}-{}-{}.{}.rpm",
                tag(Tag::NAME),
                tag(Tag::VERSION),
                tag(Tag::RELEASE),
                tag(Tag::ARCH)
            );
            Ok(Self::build(
                header,
                PkgSource::Installed,
                filename,
                Some(false),
                Timers::with_extract(0.0),
            ))
        })
    }

    /// Shared construction from a header. `is_source` defaults to the header's
    /// `SOURCERPM` presence (the file case); an installed package passes
    /// `Some(false)` as rpmlint forces it. `timers` carries the `ExtractRpm`
    /// measurement and gains `libmagic` while the file list is built.
    fn build(
        header: PackageHeader,
        source: PkgSource,
        filename: String,
        is_source: Option<bool>,
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

        let files = gather_files(&header, source.base_dir(), &mut timers);
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
            source,
            timers,
            header,
        }
    }

    /// The directory reads resolve against: the extraction directory, the
    /// owned empty sandbox for test-only header opens, `/` for the
    /// live-filesystem sources, or the removed path after [`Pkg::cleanup`].
    pub fn dir_name(&self) -> &Path {
        self.source.base_dir()
    }

    /// The reference's `extracted` flag, as a total function of the source
    /// (`docs/DESIGN.md` §7.5).
    pub fn extracted(&self) -> bool {
        self.source.extracted()
    }

    /// True for a NoSource package (source whose files are all ghosts).
    pub fn is_no_source(&self) -> bool {
        self.is_source && !self.ghost_files.is_empty()
    }

    /// Read a scalar string tag (rpmlint `pkg[tag]`): byte-decoded, empty →
    /// `None`, and `GROUP == "Unspecified"` → `None`. Not a faithful
    /// `tags::str_tag` for `Tag::GROUP`: a future `pkg.tag_str(Tag::GROUP)`
    /// call silently inherits the special case.
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

    /// Read an INT32 scalar tag as `i64` (rpmlint `pkg[tag]` on EPOCH): the
    /// first element, or `None` when absent.
    pub fn tag_i64(&self, tag: Tag) -> Option<i64> {
        match self.header.get_owned(tag) {
            Some(OwnedTagData::Int32(v)) => v.into_iter().next().map(|e| e as i64),
            _ => None,
        }
    }

    /// Read an INT32 array tag; empty when absent.
    pub fn tag_int32_array(&self, tag: Tag) -> Vec<i32> {
        tags::int32_array(&self.header, tag)
    }

    /// Read a tag in a specific language. The `C` locale is the header
    /// default; other locales are selected from the raw i18n table.
    pub fn tag_i18n_str(&self, tag: Tag, lang: &str) -> String {
        if lang == "C" || lang == "C.UTF-8" {
            return self.tag_str(tag).unwrap_or_default();
        }
        let table = self.tag_str_array(Tag::HEADERI18NTABLE);
        if let Some(idx) = table.iter().position(|l| l == lang)
            && let Some(OwnedTagData::I18NStr(v)) = self.header.get_owned_with_options(
                tag,
                librpm::package::GetOptions {
                    raw: true,
                    ..Default::default()
                },
            )
        {
            return v.get(idx).cloned().unwrap_or_default();
        }
        String::new()
    }

    /// Build an installed [`Pkg`] from a fixture RPM on disk, skipping
    /// signature verification (test-only).
    #[cfg(test)]
    pub(crate) fn installed_from_file(path: &std::path::Path) -> Self {
        let header = PackageHeader::from_file(path, Some(&VerifyOptions::skip_verification()))
            .expect("open fixture header");
        Self::installed(header).expect("build installed package")
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
        let path = file_path(self.source.base_dir(), filename);
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

    /// Remove the owned tempdir (rpmlint `cleanup`); it is also removed on
    /// drop. This covers the extraction tempdir and the test-only sandbox
    /// tempdir alike. The source becomes `PkgSource::CleanedUp`, still
    /// pointing at the removed path, so a read after cleanup fails to `''`
    /// exactly as the reference does.
    pub fn cleanup(&mut self) {
        // Only a tempdir-owning source (`Extracted`, or the test-only
        // `Sandboxed`) is dropped early here. Taking the source drops the old
        // `TempDir` below, removing the directory from the filesystem.
        let old = std::mem::replace(
            &mut self.source,
            PkgSource::CleanedUp {
                dir: PathBuf::new(),
            },
        );
        self.source = match old {
            PkgSource::Extracted { dir, tempdir } => {
                drop(tempdir);
                PkgSource::CleanedUp { dir }
            }
            // A header-only test package sandbox is removed on cleanup too,
            // exactly like an extraction tempdir.
            #[cfg(test)]
            PkgSource::Sandboxed { dir, tempdir } => {
                drop(tempdir);
                PkgSource::CleanedUp { dir }
            }
            other => other,
        };
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
fn file_path(dir: &Path, name: &str) -> String {
    let joined = dir.join(name.trim_start_matches('/'));
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
fn gather_files(header: &PackageHeader, dir: &Path, timers: &mut Timers) -> Vec<PkgFile> {
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
        // The exact file(1) vocabulary is a libmagic-version detail, so
        // assert the documented property instead of the string (same idiom
        // as the file_magic test in extract.rs).
        let magic = calc_magic("", 0o100644, 6, "", &p, false, &mut t);
        assert!(
            magic.to_lowercase().contains("text"),
            "expected libmagic to describe a text file as text, got {magic:?}"
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

    #[test]
    fn open_no_extract_is_hermetic() {
        // A header-only open resolves reads against an owned empty sandbox,
        // not the live filesystem. `/etc/hosts` exists on every unix/macOS
        // host with content, so it distinguishes the two: with the old
        // `LiveRoot` base dir, `read_file` would return live content and
        // `grep` would find it.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let pkg = Pkg::open_no_extract(&rpm).expect("open fixture");
        // The sandbox dir exists for the life of the pkg.
        assert!(pkg.dir_name().is_dir(), "sandbox dir must exist");
        assert!(!pkg.extracted(), "no extraction ran");
        assert_eq!(pkg.read_file("/etc/hosts"), "");
        let re = fancy_regex::Regex::new(".").expect("static regex");
        assert_eq!(pkg.grep(&re, "/etc/hosts"), None);
    }
}

#[cfg(test)]
mod rich_dep_fixture_tests {
    use crate::pkg::Pkg;
    use std::path::Path;

    fn open_fixture() -> Pkg {
        let rpm_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/richdep-fixture-1.0-1.noarch.rpm");
        Pkg::open(&rpm_path, &std::env::temp_dir(), true).expect("open richdep fixture")
    }

    #[test]
    fn header_rich_deps_parse_to_leaves() {
        // Built by tests/parity/pkg/inputs/build-richdep-fixture.sh in an
        // openSUSE container; the header stores each expression whole in
        // REQUIRENAME with flags 0 (verified with `rpm -qp --requires`).
        let pkg = open_fixture();
        let by_name = |want: &str| {
            pkg.requires
                .iter()
                .find(|d| d.name == want)
                .unwrap_or_else(|| panic!("missing require {want:?}"))
        };

        let dep = by_name("(foo or bar)");
        assert_eq!(dep.flags, 0);
        assert_eq!(dep.leaf_names(), vec!["foo".to_string(), "bar".to_string()]);

        let dep = by_name("(baz >= 1.0 with baz < 2.0)");
        let leaves = dep.leaves();
        assert_eq!(leaves.len(), 2);
        assert_eq!(leaves[0].name, "baz");
        assert_eq!(leaves[0].version.as_deref(), Some("1.0"));
        assert_eq!(leaves[1].version.as_deref(), Some("2.0"));

        let dep = by_name("(outer and (inner1 or inner2))");
        assert_eq!(
            dep.leaf_names(),
            vec![
                "outer".to_string(),
                "inner1".to_string(),
                "inner2".to_string()
            ]
        );

        let dep = by_name("qux(meta)");
        assert_eq!(dep.leaf_names(), vec!["qux(meta)".to_string()]);
        assert_eq!(dep.leaves()[0].qualifier.as_deref(), Some("meta"));

        // rpm auto-adds these; the port must keep them literal.
        let dep = by_name("rpmlib(RichDependencies)");
        assert_eq!(
            dep.leaf_names(),
            vec!["rpmlib(RichDependencies)".to_string()]
        );
    }
}
