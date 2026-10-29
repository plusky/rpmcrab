//! `FilesCheck`: file-level validation, ported from rpmlint's `FilesCheck.py`.
//!
//! Covers the reference's `add_info` call sites: man/info page compression,
//! permissions, ownership, symlinks, hardlinks, scriptlets, and the per-file
//! type dispatches (normal file, directory, symlink).
//!
//! Deliberate gaps are ledgered in `tests/parity/divergences.toml`.
//!
//! Three findings have no reference counterpart: `debug-files-in-non-debug-package`
//! (upstream feature request rpm-software-management/rpmlint#11),
//! `systemd-preset-packaged` (preset files are distro policy, shipped only
//! by the packages named in the `SystemdPresetPackages` config key) and
//! `symlink-loop` (a symlink whose in-package resolution chain cycles;
//! every open of such a link fails with ELOOP). Two more are
//! defect-pattern finders (issue #1023): `udev-rule-world-writable-mode`
//! and `udev-rule-world-writable-node-creator`, which read the content
//! of shipped udev rules for world-writable device modes.

#![allow(clippy::collapsible_if)]

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use fancy_regex::Regex;
use indexmap::IndexMap;

use super::fhs::cross_sysroot_matches;
use super::filelist::sysconfig_good_matches;
use super::is_match;
use super::shared::{
    class_header_detail, devel_regex, is_mingw_package, macro_regex, python_str_repr,
};
use crate::check::{Check, add_info, make_finding};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::dep::{DepInfo, leaf_account_capability};
use crate::pkg::pkgfile::{self, PkgFile, is_dir, is_reg};
use crate::tools::{Tool, ToolSource, test_source};
use std::sync::OnceLock;

static MAN_REGEX: OnceLock<Regex> = OnceLock::new();
fn man_regex() -> &'static Regex {
    MAN_REGEX.get_or_init(|| Regex::new(r"/man(?:\d[px]?|n)/").expect("static regex"))
}

static MAN_BASE_REGEX: OnceLock<Regex> = OnceLock::new();
fn man_base_regex() -> &'static Regex {
    MAN_BASE_REGEX.get_or_init(|| Regex::new(r"(?i)^(?P<path>/usr/share/man|/usr/man)/(?:(?P<lang>[a-z_]+)/)?man(?P<category>[^/]+)/(?P<filename>.+)$")
        .expect("static regex"))
}

/// The binary a man page filename documents, mirroring the `binary`
/// group of the reference's man_base_regex (`(?P<binary>.+)\.\d.*`,
/// FilesCheck.py:207): the filename up to the last `.` followed by a
/// digit, so `zoo.1.gz` -> `zoo`. `None` when the filename carries no
/// section suffix.
fn man_binary_basename(filename: &str) -> Option<&str> {
    let bytes = filename.as_bytes();
    let mut split = None;
    for i in 1..bytes.len() {
        if bytes[i] == b'.' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
            split = Some(i);
        }
    }
    split.map(|i| &filename[..i])
}

/// Whether `s` is a version tail of at least two dot-separated
/// numeric components (`3.13`, `2.1.1756211046`); a single component
/// (`2`, `64`) is a name suffix, not a version.
fn is_version_tail(s: &str) -> bool {
    let mut n = 0;
    for part in s.split('.') {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        n += 1;
    }
    n >= 2
}

/// The base name of a version-suffixed binary name: `exe` minus a
/// trailing version tail (see `is_version_tail`) and one optional
/// separator. The separator on this (binary) side is `-`, `.` or
/// nothing at all -- the digit run directly abutting the name
/// (`luajit-2.1.1756211046` -> `luajit`, `cups-genppd.5.3` ->
/// `cups-genppd`, `perl5.44.0` -> `perl`). `None` when the name
/// carries no such tail or nothing would remain.
fn strip_version_tail(exe: &str) -> Option<&str> {
    let bytes = exe.as_bytes();
    let mut start = bytes.len();
    while start > 0 && (bytes[start - 1].is_ascii_digit() || bytes[start - 1] == b'.') {
        start -= 1;
    }
    // `start` is computed over bytes and can land inside a
    // multi-byte character (a non-ASCII char directly before the
    // digit/dot run); slice through `get` so that fails closed
    // instead of panicking on a non-boundary index.
    let run = exe.get(start..)?;
    let tail = run.strip_prefix('.').unwrap_or(run);
    if start == 0 || !is_version_tail(tail) {
        return None;
    }
    let mut base = exe.get(..start)?;
    if let Some(stripped) = base.strip_suffix(['-', '.']) {
        base = stripped;
    }
    if base.is_empty() { None } else { Some(base) }
}

/// Record a man page basename in the package state, together with
/// every prefix of it that a `-<version>` tail follows, for the
/// version-affix credit in `version_affix_documented`.
fn note_man_basename(st: &mut PkgState, basename: &str) {
    st.man_basenames.insert(basename.to_string());
    for (i, _) in basename.match_indices('-') {
        if is_version_tail(&basename[i + 1..]) {
            st.man_version_bases.insert(basename[..i].to_string());
        }
    }
}

/// Compression suffixes a shipped man page target may carry, mirroring
/// `compr_regex`: a `.so` reference is satisfied by the target name with
/// any of these suffixes, or with none.
const MAN_COMPRESSION_SUFFIXES: &[&str] =
    &[".gz", ".z", ".Z", ".zip", ".bz2", ".lzma", ".xz", ".zst"];

/// Cap on the decompressed text of one man page: real pages stay far
/// below this bound; it only limits a decompressor runaway or an
/// oversized plain page.
const MANPAGE_TEXT_LIMIT: u64 = 8 * 1024 * 1024;

/// `path` with one trailing man page compression suffix removed, when it
/// carries one.
fn strip_man_compression_suffix(path: &str) -> &str {
    for suffix in MAN_COMPRESSION_SUFFIXES {
        if let Some(stripped) = path.strip_suffix(suffix) {
            return stripped;
        }
    }
    path
}

/// Whether the file at `path` opens with the gzip magic bytes
/// (`1F 8B`), or `None` when the file cannot be opened or read: an
/// unreadable page is skipped, not judged.
fn file_has_gzip_magic(path: &str) -> Option<bool> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut head = Vec::new();
    file.take(2).read_to_end(&mut head).ok()?;
    Some(head == [0x1F, 0x8B])
}

/// The `.so` targets named by one man page's text: the first
/// whitespace-delimited token of every line that opens with the soelim
/// request (`.so` followed by whitespace). Comment lines (`.\"`) never
/// open with the request, and a request without an argument names no
/// target.
fn manpage_so_targets(text: &str) -> Vec<String> {
    let mut targets = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(".so") else {
            continue;
        };
        if !rest.starts_with([' ', '\t']) {
            continue;
        }
        if let Some(target) = rest.split_whitespace().next() {
            targets.push(target.to_string());
        }
    }
    targets
}

/// Resolve one `.so` argument to the man-root-relative path it names
/// (`man3/popen.3`), or `None` when the argument names no man-root page:
/// relative arguments are already man-root-relative, absolute arguments
/// count only in their `/usr/share/man/...` or `/usr/man/...` form, and
/// bare filenames or other absolute paths name no man-root page. The
/// first directory of a relative argument must have the reference's
/// loose section shape: `man` plus a first byte that is a digit or
/// `n`, with an arbitrary tail, so real section directories such as
/// `man3pm/` and `man3tcl/` resolve; a merely `man`-prefixed
/// directory (`manual/`, `management/`) names no man page.
fn manpage_so_root_relative(arg: &str) -> Option<String> {
    if let Some(rel) = arg.strip_prefix("/usr/share/man/") {
        return Some(rel.to_string());
    }
    if let Some(rel) = arg.strip_prefix("/usr/man/") {
        return Some(rel.to_string());
    }
    if arg.starts_with('/') {
        return None;
    }
    let (dir, _) = arg.split_once('/')?;
    let section = dir.strip_prefix("man")?;
    let valid = section
        .as_bytes()
        .first()
        .is_some_and(|b| b.is_ascii_digit() || *b == b'n');
    if valid { Some(arg.to_string()) } else { None }
}

/// Whether the `spurious-executable-perm` finding is suppressed for
/// `fname` in `pkg_name`: GCC and libtool create MinGW import libraries
/// (`*.dll.a`) with the executable bit set, and the Factory lint session
/// filters the finding for exactly that shape via the `mingw32.toml`
/// config the mingw32/64-filesystem packages install into the lint
/// environment ('^mingw(32|64)-.*spurious-executable-perm.*\.dll\.a$').
/// That file is not part of the mirrored rpmlint config set, so the
/// suppression lives here instead (issue #522, divergences.toml). The
/// filter carries no path condition beyond the suffix, so neither does
/// this predicate.
fn mingw_dll_a_perm_exempt(pkg_name: &str, fname: &str) -> bool {
    is_mingw_package(pkg_name) && fname.ends_with(".dll.a")
}

/// Whether the `devel-file-in-non-devel-package` finding is suppressed
/// for `fname` in `pkg_name`: a MinGW cross package's payload under the
/// target sys-root (`/usr/<triplet>-w64-mingw32/sys-root/`) is headers
/// and import libraries by definition -- the devel files are the
/// product, with no `-devel` split to move them into. The Factory lint
/// session suppresses the finding for the whole family via the
/// `mingw32.toml` config the mingw32/64-filesystem packages install
/// into the lint environment; that file is not part of the mirrored
/// rpmlint config set, so the suppression lives here instead (issue
/// #511, divergences.toml).
fn mingw_sysroot_devel_exempt(pkg_name: &str, fname: &str) -> bool {
    if !pkg_name.starts_with("mingw32-") && !pkg_name.starts_with("mingw64-") {
        return false;
    }
    let mut segments = fname.split('/');
    matches!(segments.next(), Some(""))
        && matches!(segments.next(), Some("usr"))
        && segments
            .next()
            .is_some_and(|triplet| triplet.ends_with("-w64-mingw32"))
        && matches!(segments.next(), Some("sys-root"))
}

static INFO_REGEX: OnceLock<Regex> = OnceLock::new();
fn info_regex() -> &'static Regex {
    INFO_REGEX.get_or_init(|| Regex::new(r"(/usr/share|/usr)/info/").expect("static regex"))
}

static SCM_REGEX: OnceLock<Regex> = OnceLock::new();

/// The paths `version-control-internal-file` charges (issue #858):
/// files inside a version-control metadata tree (a `.git`, `.svn`,
/// `.hg` or `.bzr` directory, an arch `.arch-ids` or `{arch}`
/// directory), files directly inside a `CVS` or `RCS` directory,
/// RCS `,v` revision files. The divergence from the reference is
/// ledgered in tests/parity/divergences.toml.
fn scm_regex() -> &'static Regex {
    SCM_REGEX.get_or_init(|| {
        Regex::new(r"/(?:RCS|CVS)/[^/]+$|,v$|/\.(?:bzr|git|hg|svn)/|/(?:\.arch-ids|{arch})/")
            .expect("static regex")
    })
}

static BACKUP_REGEX: OnceLock<Regex> = OnceLock::new();

/// The paths `backup-file-in-package` charges: the reference's
/// `backup_regex` (FilesCheck.py) verbatim -- a trailing `~`, an
/// Emacs `#...#` autosave name, or `.orig`/`.rej` optionally followed
/// by a compression suffix; end-anchored and case-sensitive. There
/// is no `.bak` arm: the one Factory instance (`/var/lib/nfs/sm.bak`)
/// is rpc.statd's state file, and uppercase `.ORIG` content such as
/// aranym's AFROS `mint.cnf.ORIG` is deliberate payload, so the wider
/// lowercase suffix test this replaces charged only false positives.
fn backup_regex() -> &'static Regex {
    BACKUP_REGEX.get_or_init(|| {
        Regex::new(r"(~|\#[^/]+\#|((\.orig|\.rej)(\.(gz|z|Z|zip|bz2|lzma|xz|zst))?))$")
            .expect("static regex")
    })
}

/// Whether `fname`'s basename is exactly `Cargo.toml.orig`: the
/// pre-normalization manifest cargo writes next to `Cargo.toml` in
/// every published crate tarball. A package shipping vendored crate
/// sources verbatim (rusty_v8 carries 213 of them) holds them as
/// upstream content, not as a maintainer's patch backup, so the exact
/// basename is exempt from `backup-file-in-package` here and from
/// `filelist-forbidden` in FilelistCheck, whose `*.orig` arm charges
/// the same files (the bundled FilelistCheck.toml declares the
/// exemption there as `IgnoreFileIf = "cargotomlorig"`, implemented
/// through this predicate). Deliberate divergence from the
/// reference, which fires on them. The
/// match is exact and case-sensitive: a lowercase `cargo.toml.orig`,
/// a longer name the string merely ends (`xCargo.toml.orig`), a
/// suffixed name (`Cargo.toml.orig2`, `Cargo.toml.orig.gz`) and
/// other manifests' `.orig` files (`meson.build.orig`) are not
/// cargo's artifact and keep firing in both checks.
pub(crate) fn is_cargo_toml_orig(fname: &str) -> bool {
    fname.rsplit('/').next() == Some("Cargo.toml.orig")
}

static KERNEL_PACKAGE_REGEX: OnceLock<Regex> = OnceLock::new();
fn kernel_package_regex() -> &'static Regex {
    KERNEL_PACKAGE_REGEX.get_or_init(|| {
        Regex::new(r"^kernel(-(default|desktop|pae|xen|vanilla|debug|kdump|source|syms))?$")
            .expect("static regex")
    })
}

static DEBUGINFO_PACKAGE_REGEX: OnceLock<Regex> = OnceLock::new();
fn debuginfo_package_regex() -> &'static Regex {
    DEBUGINFO_PACKAGE_REGEX
        .get_or_init(|| Regex::new(r"-(debuginfo|debug)$").expect("static regex"))
}

static DEBUGSOURCE_PACKAGE_REGEX: OnceLock<Regex> = OnceLock::new();
fn debugsource_package_regex() -> &'static Regex {
    DEBUGSOURCE_PACKAGE_REGEX.get_or_init(|| Regex::new(r"-debugsource$").expect("static regex"))
}

static KERNEL_MODULES_REGEX: OnceLock<Regex> = OnceLock::new();
fn kernel_modules_regex() -> &'static Regex {
    KERNEL_MODULES_REGEX.get_or_init(|| Regex::new(r"^/lib/modules/").expect("static regex"))
}

static QUOTES_REGEX: OnceLock<Regex> = OnceLock::new();

static MANIFEST_PERL_REGEX: OnceLock<Regex> = OnceLock::new();
fn manifest_perl_regex() -> &'static Regex {
    // Mirrors the reference manifest_perl_regex verbatim: only a doc
    // directory literally named perl-* matches.
    MANIFEST_PERL_REGEX.get_or_init(|| {
        Regex::new(r"^/usr/share/doc/perl-.*/MANIFEST(\.SKIP)?$").expect("static regex")
    })
}
fn quotes_regex() -> &'static Regex {
    QUOTES_REGEX.get_or_init(|| Regex::new(r#"['"]"#).expect("static regex"))
}

static COMPR_REGEX: OnceLock<Regex> = OnceLock::new();
fn compr_regex() -> &'static Regex {
    COMPR_REGEX
        .get_or_init(|| Regex::new(r"\.(gz|z|Z|zip|bz2|lzma|xz|zst)$").expect("static regex"))
}

static ABSOLUTE_REGEX: OnceLock<Regex> = OnceLock::new();
fn absolute_regex() -> &'static Regex {
    ABSOLUTE_REGEX.get_or_init(|| Regex::new(r"^/([^/]+)").expect("static regex"))
}

static ABSOLUTE2_REGEX: OnceLock<Regex> = OnceLock::new();
fn absolute2_regex() -> &'static Regex {
    ABSOLUTE2_REGEX.get_or_init(|| Regex::new(r"^/?([^/]+)").expect("static regex"))
}

static POINTS_REGEX: OnceLock<Regex> = OnceLock::new();
fn points_regex() -> &'static Regex {
    POINTS_REGEX.get_or_init(|| Regex::new(r"^\.\./(.*)").expect("static regex"))
}

static DOC_REGEX: OnceLock<Regex> = OnceLock::new();
fn doc_regex() -> &'static Regex {
    DOC_REGEX.get_or_init(|| {
        Regex::new(r"^/usr(/share|/X11R6)?/(doc|man|info)/|^/usr/share/gnome/help")
            .expect("static regex")
    })
}

static BIN_REGEX: OnceLock<Regex> = OnceLock::new();
fn bin_regex() -> &'static Regex {
    BIN_REGEX
        .get_or_init(|| Regex::new(r"^/(?:usr/(?:s?bin|games)|s?bin)/(.*)").expect("static regex"))
}

static INCLUDEFILE_REGEX: OnceLock<Regex> = OnceLock::new();
fn includefile_regex() -> &'static Regex {
    INCLUDEFILE_REGEX.get_or_init(|| Regex::new(r"(?i)\.(c|h)(pp|xx)?$").expect("static regex"))
}

static DEVELFILE_REGEX: OnceLock<Regex> = OnceLock::new();
fn develfile_regex() -> &'static Regex {
    DEVELFILE_REGEX.get_or_init(|| Regex::new(r"\.(a|cmxa?|mli?|gir)$").expect("static regex"))
}

/// The devel keyword as a hyphen-delimited name component
/// (`libstdc++6-devel-gcc7`, `ruby4.0-devel-extra`): a flavoured devel
/// package. Scoped to the devel keyword alone -- a `-debug-`
/// component names a debug flavour of a runtime package, not a devel
/// package.
static DEVEL_COMPONENT_REGEX: OnceLock<Regex> = OnceLock::new();
fn devel_component_regex() -> &'static Regex {
    DEVEL_COMPONENT_REGEX.get_or_init(|| Regex::new(r"(.*)-devel-").expect("static regex"))
}

/// Whether `name`'s final hyphen component is a source component:
/// `src`, `source` or `sources`, matched case-insensitively, a bare
/// name counting as its own final component (`rust1.98-src`,
/// `erlang27-src`, `sdcc-libc-sources`, a bare `sources`). One
/// grammar serves every reader of the fact -- the devel-package
/// credit below and the source-payload gate for script interpreter
/// findings (`script_is_source_data`) -- so the two cannot drift
/// apart on case, the `sources` spelling or bare names.
fn name_has_source_component(name: &str) -> bool {
    name.rsplit('-').next().is_some_and(|c| {
        c.eq_ignore_ascii_case("src")
            || c.eq_ignore_ascii_case("source")
            || c.eq_ignore_ascii_case("sources")
    })
}

static BUILDCONFIGFILE_REGEX: OnceLock<Regex> = OnceLock::new();
fn buildconfigfile_regex() -> &'static Regex {
    BUILDCONFIGFILE_REGEX
        .get_or_init(|| Regex::new(r"(\.pc|/bin/.+-config)$").expect("static regex"))
}

static BUILDCONFIG_RPATH_REGEX: OnceLock<Regex> = OnceLock::new();
fn buildconfig_rpath_regex() -> &'static Regex {
    // The reference pattern is `(?:-rpath|Wl,-R)\b`. Two match shapes are
    // not an rpath directive at all and are excluded by token shape:
    //  - `-rpath-link` (e.g. `-Wl,-rpath-link,<dir>`): the link editor's
    //    search path for secondary dependencies at link time. It is never
    //    recorded in the linked output, so no rpath is introduced into
    //    dependent packages (mozilla-nss's nss-config ships only this).
    //  - `-rpath` as the tail of a `--<word>-rpath` configure-option token
    //    (e.g. `'--disable-rpath'` in php-config's recorded configure
    //    command line): part of a longer word, not a standalone flag. The
    //    `-rpath` arm must start a token: it must not be preceded by a word
    //    character, and must not continue as `-link`.
    BUILDCONFIG_RPATH_REGEX.get_or_init(|| {
        Regex::new(r"(?:(?<![\w])-rpath(?!-link)\b|Wl,-R\b)").expect("static regex")
    })
}

static SOFILE_REGEX: OnceLock<Regex> = OnceLock::new();
fn sofile_regex() -> &'static Regex {
    SOFILE_REGEX.get_or_init(|| Regex::new(r"/lib(64)?/(.+/)?lib[^/]+\.so$").expect("static regex"))
}

static LIB_REGEX: OnceLock<Regex> = OnceLock::new();
fn lib_regex() -> &'static Regex {
    LIB_REGEX.get_or_init(|| Regex::new(r"/lib(?:64)?/lib[A-Za-z0-9](?:(?:|[\w\-\.]*[A-Za-z0-9])\.so\.[\w+\.]+|\w*-\d(?:|[\w\-\.]*[A-Za-z0-9])\.so)$")
        .expect("static regex"))
}

static INTERPRETER_REGEX: OnceLock<Regex> = OnceLock::new();
fn interpreter_regex() -> &'static Regex {
    INTERPRETER_REGEX.get_or_init(|| {
        Regex::new(r"^/(?:usr/)?(?:s?bin|games|libexec(?:/.+)?|(?:lib(?:64)?|share)/.+)/([^/]+)$")
            .expect("static regex")
    })
}

static SCRIPT_REGEX: OnceLock<Regex> = OnceLock::new();
fn script_regex() -> &'static Regex {
    SCRIPT_REGEX.get_or_init(|| {
        Regex::new(
        r"^/((usr/)?s?bin|etc/(rc\.d/init\.d|X11/xinit\.d|cron\.(hourly|daily|monthly|weekly)))/",
    )
    .expect("static regex")
    })
}

static SOURCED_SCRIPT_REGEX: OnceLock<Regex> = OnceLock::new();
fn sourced_script_regex() -> &'static Regex {
    SOURCED_SCRIPT_REGEX.get_or_init(|| {
        Regex::new(r"^/etc/(bash_completion\.d|profile\.d)/").expect("static regex")
    })
}

static FSF_LICENSE_REGEX: OnceLock<Regex> = OnceLock::new();
fn fsf_license_regex() -> &'static Regex {
    FSF_LICENSE_REGEX.get_or_init(|| Regex::new(r"(?i)(GNU((\s+(Library|Lesser|Affero))?(\s+General)?\s+Public|\s+Free\s+Documentation)\s+Licen[cs]e|(GP|FD)L)")
        .expect("static regex"))
}

static FSF_WRONG_ADDRESS_REGEX: OnceLock<Regex> = OnceLock::new();
fn fsf_wrong_address_regex() -> &'static Regex {
    FSF_WRONG_ADDRESS_REGEX.get_or_init(|| {
        Regex::new(r"(?i)(675\s+Mass\s+Ave|59\s+Temple\s+Place|51\s+Franklin\s+St)")
            .expect("static regex")
    })
}

/// The FSF's old Cambridge ZIP as it appears in the reference's
/// wrong-address pattern. It is not matched by the regex above: the
/// digit string also occurs inside longer numbers, decimal fractions
/// and hex strings that carry no address meaning (token tables index
/// `102139`, the IEEE OUI registry lists `002139`, ECDSA test vectors
/// embed it in signatures, SVG path data in coordinates). An
/// occurrence is address evidence only as a standalone token: the
/// byte before it (if any) is neither alphanumeric nor `.`, and the
/// byte after it (if any) is not alphanumeric.
const FSF_ZIP: &[u8] = b"02139";

/// Whether `buf` holds a standalone `FSF_ZIP` occurrence. `left_edge`
/// is the byte just before `buf` in the file (`None` at the start of
/// the file) and `right_edge` the byte just after it (`None` at the
/// end of the file); occurrences touching a buffer edge are judged
/// against those, so a caller scanning in windows classifies an
/// occurrence exactly as if it had the whole file.
fn fsf_zip_in_window(buf: &[u8], left_edge: Option<u8>, right_edge: Option<u8>) -> bool {
    let mut from = 0usize;
    while let Some(rel) = buf[from..]
        .windows(FSF_ZIP.len())
        .position(|w| w == FSF_ZIP)
    {
        let start = from + rel;
        let end = start + FSF_ZIP.len();
        let left = if start > 0 {
            Some(buf[start - 1])
        } else {
            left_edge
        };
        let right = if end < buf.len() {
            Some(buf[end])
        } else {
            right_edge
        };
        let left_clean = left.is_none_or(|b| !(b.is_ascii_alphanumeric() || b == b'.'));
        let right_clean = right.is_none_or(|b| !b.is_ascii_alphanumeric());
        if left_clean && right_clean {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Minimum number of gzipped icons in scalable icon directories
/// for a package's scalable payload to count as an icon theme
/// rather than a set of individually placed icons
/// (`FilesCheck::svgz_theme_credit`).
const SVGZ_THEME_MIN_GZIPPED: usize = 100;

static SCALABLE_ICON_REGEX: OnceLock<Regex> = OnceLock::new();
fn scalable_icon_regex() -> &'static Regex {
    SCALABLE_ICON_REGEX.get_or_init(|| {
        Regex::new(r"^/usr(?:/local)?/share/icons/.*/scalable/").expect("static regex")
    })
}

static TCL_REGEX: OnceLock<Regex> = OnceLock::new();
fn tcl_regex() -> &'static Regex {
    TCL_REGEX
        .get_or_init(|| Regex::new(r"^/usr/lib(64)?/([^/]+/)?pkgIndex\.tcl").expect("static regex"))
}

static PERL_REGEX: OnceLock<Regex> = OnceLock::new();
fn perl_regex() -> &'static Regex {
    PERL_REGEX.get_or_init(|| {
        Regex::new(r"^/usr/lib/perl5/(?:vendor_perl/)?([0-9]+\.[0-9]+)\.([0-9]+)/")
            .expect("static regex")
    })
}

static PYTHON_REGEX: OnceLock<Regex> = OnceLock::new();
fn python_regex() -> &'static Regex {
    PYTHON_REGEX
        .get_or_init(|| Regex::new(r"^/usr/lib(?:64)?/python([.0-9]+)/").expect("static regex"))
}

static PYTHON_LIB_TREE_REGEX: OnceLock<Regex> = OnceLock::new();
fn python_lib_tree_regex() -> &'static Regex {
    PYTHON_LIB_TREE_REGEX
        .get_or_init(|| Regex::new(r"/(?:site|dist)-packages(?:/|$)").expect("static regex"))
}

/// A subdirectory of a bin dir named `<tool>.d` is the companion
/// directory of the executable `<tool>` shipped in the same bin dir:
/// the tool's own modules and helpers, installed next to their driver
/// under a name derived from it (liblouis-tools ships
/// `/usr/bin/lou_maketable.d/*` for `/usr/bin/lou_maketable`). The
/// shape is decidable from the package's own file list: the first
/// component below the bin dir must end in `.d`, and stripping the
/// suffix must name a regular, executable file in the same bin dir.
/// A `.d` directory without that namesake executable, a namesake
/// that is not an executable regular file, and any non-`.d`
/// subdirectory keep firing.
fn subdir_in_bin_is_companion_dir(pkg: &Pkg, bindir: &str, fname: &str) -> bool {
    let rest = &fname[bindir.len()..];
    let Some((first, _)) = rest.split_once('/') else {
        return false;
    };
    let Some(tool) = first.strip_suffix(".d") else {
        return false;
    };
    if tool.is_empty() {
        return false;
    }
    let sibling = format!("{bindir}{tool}");
    pkg.files
        .iter()
        .any(|f| f.name == sibling && is_reg(f.mode) && f.mode & 0o111 != 0)
}

/// Whether the interpreter program is a Python interpreter:
/// `python` with an optional version suffix of digits and dots
/// (`python3`, `python3.13`, `python2.7`) — a bare prefix match
/// would also claim names like `pythonwibble`.
fn is_python_program(program: &str) -> bool {
    program
        .strip_prefix("python")
        .is_some_and(|rest| rest.chars().all(|ch| ch.is_ascii_digit() || ch == '.'))
}

/// Whether a non-executable file carrying an interpreter line is
/// content the owning program consumes by reading, importing,
/// sourcing or rendering, so the interpreter line marks data rather
/// than a script executed in place and the missing exec bit is not a
/// defect (issues #813, #845). Every shape is decidable from the
/// file's path and interpreter alone, and two guards bound the
/// shapes:
///
/// - a file installed directly in a script directory (`/bin`,
///   `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin` or
///   `/usr/local/sbin`) is an entry point and never counts as data;
/// - the remaining directory-component shapes count only inside
///   the data and library trees (`/usr/src/`, `/usr/share/`,
///   `/usr/lib/`, `/usr/lib64/`, `/usr/etc/`, `/etc/`): a component
///   name alone does not distinguish a module tree from an entry
///   point, so the same components in an entry-point tree (under
///   `/usr/libexec/`, say) keep firing.
///
/// The shapes:
///
/// - a library tree: a `site-packages`, `dist-packages`,
///   `node_modules` or `gems` path component, or a file under the
///   Ruby (`/usr/lib/ruby/`, `/usr/lib64/ruby/`) or Perl
///   (`/usr/lib/perl5/`, `/usr/lib64/perl5/`) library roots — a
///   dependency tree is consumed by import wherever it is rooted;
/// - a language directory (inside the data and library trees): a
///   `python` or `python3[.x]` component, a nested `lib` component
///   (past the first two path components) holding a script-language
///   file (`.py`, `.rb`, `.pl`, `.pm`, `.lua`, `.php`, `.sh` or
///   `.bash`), a `bash` component holding a `.sh` or `.bash` file,
///   or a `.py` file in a host-loaded plugin directory
///   (`extensions`, `plugins`) or an `auto-load` directory;
/// - a source tree (inside the data and library trees): a `src`
///   component (the `/usr/src/` trees included);
/// - test and example material (inside the data and library
///   trees): a `test`, `tests`, `selftests`, `example`, `examples`,
///   `sample` or `samples` component;
/// - a sourced fragment: a file under `/usr/share/bash-completion/`,
///   a `profile` or `rc` basename or a basename with a `bashrc`
///   name segment in a sourced location (`/etc/`, `/usr/etc/`,
///   `/usr/lib/`, `/usr/lib64/` or `/usr/share/`), or an
///   interpreter whose basename is exactly `false`, which declares
///   the file is never executed;
/// - a template: a basename ending in `.in`, `.sample`, `.tmpl`,
///   `.tpl`, `.template`, `.skel`, `.j2` or `.ex` — the installed
///   name is the name an instantiation step rewrites, so the
///   shipped file is the template's content, not an entry point
///   (`.ex` is the Debian example-file suffix, dh-make's
///   maintainer-script templates above all — except that an
///   Elixir interpreter line takes a `.ex` file out of this arm,
///   `.ex` being Elixir's own script extension);
/// - a Python package directory (inside the data and library
///   trees): a `.py` file with a Python interpreter whose own
///   directory is a package directory — the package ships an
///   `__init__.py` in the same directory, a fact the predicate
///   judges itself from the package's file list (an `__init__.py`
///   matches its own marker: it is the package's module by
///   definition) — so the file is a module of an
///   application-private package tree (kitty's, calibre's and
///   hplip's module trees), imported by the owning program;
/// - a sourced-fragment, documentation or CI directory (inside
///   the data and library trees): an `include` or `common`
///   component — the fragment libraries a program sources
///   (lynis's `include/`, the blktests and xfstests `common/`
///   helpers) — a `doc` or `docs` component (documentation-tree
///   material, the texlive doc packages' scripts) or a `ci`
///   component (continuous-integration harness scripts, the
///   ceph dashboard's `ci/` runners);
/// - an image tree: a `rootfs` component — the file is payload
///   of a filesystem image another system boots (warewulf's
///   node overlays), so its mode is set when the image is
///   assembled or provisioned, not an installed entry point's
///   defect. The component counts wherever the image tree is
///   rooted.
fn non_executable_script_is_data(
    fname: &str,
    interpreter: &str,
    interpreter_args: &str,
    files: &[PkgFile],
    python_lib_tree_re: &Regex,
) -> bool {
    // Script directories hold entry points: no shape exempts a
    // file installed directly in one.
    let parent = fname.rsplit_once('/').map_or("", |(parent, _)| parent);
    if matches!(
        parent,
        "/bin" | "/sbin" | "/usr/bin" | "/usr/sbin" | "/usr/local/bin" | "/usr/local/sbin"
    ) {
        return false;
    }
    if interpreter.rsplit('/').next() == Some("false") {
        return true;
    }
    // The effective interpreter program: the interpreter's
    // basename, or its first argument's for the `env` form.
    let interp_base = interpreter.rsplit('/').next().unwrap_or("");
    let program = if interp_base == "env" {
        interpreter_args
            .split_whitespace()
            .next()
            .map(|arg| arg.rsplit('/').next().unwrap_or(""))
            .unwrap_or("")
    } else {
        interp_base
    };
    if is_match(python_lib_tree_re, fname) {
        return true;
    }
    // A Python package directory: a `.py` file with a Python
    // interpreter line, inside the data and library trees, whose
    // package ships an `__init__.py` in the same directory.
    let data_tree = fname.starts_with("/usr/src/")
        || fname.starts_with("/usr/share/")
        || fname.starts_with("/usr/lib/")
        || fname.starts_with("/usr/lib64/")
        || fname.starts_with("/usr/etc/")
        || fname.starts_with("/etc/");
    if is_python_program(program) && fname.ends_with(".py") && data_tree {
        let parent = fname.rsplit_once('/').map_or("", |(p, _)| p);
        let init = format!("{parent}/__init__.py");
        if files.iter().any(|f| f.name == init) {
            return true;
        }
    }
    if fname.starts_with("/usr/share/bash-completion/") {
        return true;
    }
    if fname.starts_with("/usr/lib/ruby/")
        || fname.starts_with("/usr/lib64/ruby/")
        || fname.starts_with("/usr/lib/perl5/")
        || fname.starts_with("/usr/lib64/perl5/")
    {
        return true;
    }
    let base = fname.rsplit('/').next().unwrap_or("");
    // Sourced-fragment basenames count only in sourced locations:
    // the config, library and data trees.
    let sourced_tree = fname.starts_with("/etc/")
        || fname.starts_with("/usr/etc/")
        || fname.starts_with("/usr/lib/")
        || fname.starts_with("/usr/lib64/")
        || fname.starts_with("/usr/share/");
    if sourced_tree
        && (base == "profile"
            || base == "rc"
            || base.split(['.', '_', '-']).any(|seg| seg == "bashrc"))
    {
        return true;
    }
    if [
        ".in",
        ".sample",
        ".tmpl",
        ".tpl",
        ".template",
        ".skel",
        ".j2",
    ]
    .iter()
    .any(|suffix| base.ends_with(suffix))
        || (base.ends_with(".ex") && program != "elixir")
    {
        return true;
    }
    let comps: Vec<&str> = fname.split('/').filter(|c| !c.is_empty()).collect();
    if comps.len() < 2 {
        return false;
    }
    let dirs = &comps[..comps.len() - 1];
    if dirs.iter().any(|c| matches!(*c, "node_modules" | "gems")) {
        return true;
    }
    // An image tree's payload is another system's files, wherever
    // the tree is rooted: the mode is set when the image is
    // assembled, so it counts outside the data trees too.
    if dirs.contains(&"rootfs") {
        return true;
    }
    // The remaining shapes are bare directory components, whose
    // names also occur on entry points; they count only inside
    // the data and library trees.
    if !data_tree {
        return false;
    }
    if dirs.iter().any(|c| {
        matches!(
            *c,
            "src" | "test" | "tests" | "selftests" | "example" | "examples" | "sample" | "samples"
        )
    }) {
        return true;
    }
    if dirs
        .iter()
        .any(|c| matches!(*c, "include" | "common" | "doc" | "docs" | "ci"))
    {
        return true;
    }
    if dirs.iter().any(|c| {
        *c == "python"
            || c.strip_prefix("python3")
                .is_some_and(|rest| rest.chars().all(|ch| ch.is_ascii_digit() || ch == '.'))
    }) {
        return true;
    }
    let ext = base
        .rsplit('.')
        .next()
        .filter(|_| base.contains('.'))
        .unwrap_or("");
    if ext == "py"
        && dirs
            .iter()
            .any(|c| matches!(*c, "extensions" | "plugins" | "auto-load"))
    {
        return true;
    }
    if matches!(ext, "sh" | "bash") && dirs.contains(&"bash") {
        return true;
    }
    matches!(
        ext,
        "py" | "rb" | "pl" | "pm" | "lua" | "php" | "sh" | "bash"
    ) && dirs.len() > 2
        && dirs[2..].contains(&"lib")
}

/// Whether a file carrying an interpreter line is test or harness
/// payload: content a testsuite harness runs, sources or reads,
/// rather than a script the installed system executes in place
/// (corpus E audit 2026-10-26, section 2). A test package's
/// scripts are its payload -- the harness invokes them by path,
/// inside a test VM or a scratch tree -- so their interpreter
/// lines and exec bits are the harness's business, not an
/// installed entry point's defect. Every fact is decidable from
/// the binary package's name and the file's path alone:
///
/// - the package's name carries a `test`, `tests` or `testsuite`
///   hyphen component -- the package exists to carry a test suite
///   (lvm2-testsuite, systemd-testsuite, pcp-testsuite,
///   mercurial-tests), wherever in the tree the payload sits
///   (pcp-testsuite's scripts live under /usr/libexec/);
/// - a directory component names a test tree outright --
///   `testsuite` or `testsuites`, or a component ending in
///   `-testsuite` or `-testsuites` -- wherever the tree is rooted;
/// - inside the data and library trees (/usr/src/, /usr/share/,
///   /usr/lib/, /usr/lib64/, /usr/etc/, /etc/), a directory
///   component is `test`, `tests` or `selftests`, or ends in
///   `-tests` or `-test` -- the test directories shipped inside
///   source and data trees (the bazel and kafka source trees,
///   test helpers bundled inside Python packages, doc trees).
///
/// Two bounds keep the gate honest. A file installed directly in
/// a script directory (/bin, /sbin, /usr/bin, /usr/sbin,
/// /usr/local/bin or /usr/local/sbin) is an entry point and never
/// counts as test payload, whatever the package or the tree is
/// called: a test suite's own runner installed in /usr/bin keeps
/// the interpreter findings. Matching folds case on both the
/// package name and the directory components -- a packager's
/// capitalisation carries no test fact -- where the #813
/// data-shape gate beside it matches its path literals
/// case-sensitively: the two gates judge different things,
/// packager naming here, installed content shapes there. And
/// fused names carry no fact:
/// blktests and xfstests glue the word into a single component,
/// so they stay outside this gate -- their `common/` fragments
/// are covered by the data-shape gate's fragment-library shape
/// instead --
/// a raw suffix match would also claim non-test names
/// (perftest, minetest) whose scripts are real entry points.
fn script_is_test_data(pkg_name: &str, fname: &str) -> bool {
    let parent = fname.rsplit_once('/').map_or("", |(parent, _)| parent);
    if matches!(
        parent,
        "/bin" | "/sbin" | "/usr/bin" | "/usr/sbin" | "/usr/local/bin" | "/usr/local/sbin"
    ) {
        return false;
    }
    if pkg_name
        .to_lowercase()
        .split('-')
        .any(|c| matches!(c, "test" | "tests" | "testsuite"))
    {
        return true;
    }
    let comps: Vec<&str> = fname.split('/').filter(|c| !c.is_empty()).collect();
    if comps.len() < 2 {
        return false;
    }
    let dirs = &comps[..comps.len() - 1];
    if dirs.iter().any(|c| {
        let cl = c.to_lowercase();
        cl == "testsuite"
            || cl == "testsuites"
            || cl.ends_with("-testsuite")
            || cl.ends_with("-testsuites")
    }) {
        return true;
    }
    let data_tree = fname.starts_with("/usr/src/")
        || fname.starts_with("/usr/share/")
        || fname.starts_with("/usr/lib/")
        || fname.starts_with("/usr/lib64/")
        || fname.starts_with("/usr/etc/")
        || fname.starts_with("/etc/");
    if !data_tree {
        return false;
    }
    dirs.iter().any(|c| {
        let cl = c.to_lowercase();
        cl == "test"
            || cl == "tests"
            || cl == "selftests"
            || cl.ends_with("-tests")
            || cl.ends_with("-test")
    })
}

/// Whether a file carrying an interpreter line is vendored source
/// payload: a shipped source tree a developer or a build reads,
/// rather than a script the installed system executes in place
/// (corpus E audit 2026-10-26, section 5; the D1 extension of
/// the `script_is_test_data`
/// gate family). Upstream's own build and helper scripts inside
/// such a tree use the `env` form of the interpreter line as the
/// portable choice for whoever unpacks the tree, so it is not an
/// installed entry point's defect there. Every fact is decidable
/// from the binary package's name and the file's path alone:
///
/// - the package's name ends in a source hyphen component
///   (`src`, `source` or `sources`; a bare such name included,
///   matched case-insensitively -- `name_has_source_component`,
///   the grammar the devel-package credit shares) -- the package
///   exists to carry a source
///   tree (the rust*-src standard-library trees, the bazel,
///   kafka, boringssl and other -source packages, fpc-src),
///   wherever in the tree the payload sits (the rust trees live
///   under /usr/lib/rustlib/src/, fpc's under
///   /usr/share/fpcsrc/). A `src` or `source` component in any
///   other position carries no such fact: `source-highlight` is
///   a regular tool package and `my-source-tools` a tool
///   collection, so their scripts keep firing;
/// - or the file sits in the Go source tree
///   /usr/share/go/<version>/src/, with a digit-led version
///   component -- the go1.* packages are not source-named
///   (their payload is the toolchain), but that one directory
///   is Go's own shipped source tree, build scripts included.
///
/// The bounds of the test gate apply the same way. A file
/// installed directly in a script directory (/bin, /sbin,
/// /usr/bin, /usr/sbin, /usr/local/bin or /usr/local/sbin) is an
/// entry point and never counts as source payload, whatever the
/// package is called: Go's own /usr/bin/go wrappers fall outside
/// the Go arm by path, and a source package's /usr/bin helper
/// keeps firing. A `%doc` file never counts either -- the caller
/// applies this gate only to non-doc rows -- and fused names
/// carry no fact: a package merely ending in letters like
/// `resource` glues the word into a single component and stays
/// outside the gate. The gate is deliberately not package-wide:
/// the go1.* packages ship /usr/bin binaries and %doc files by
/// design, so what is exempt is each source-tree row itself,
/// never the package's entry points or documentation.
fn script_is_source_data(pkg_name: &str, fname: &str) -> bool {
    let parent = fname.rsplit_once('/').map_or("", |(parent, _)| parent);
    if matches!(
        parent,
        "/bin" | "/sbin" | "/usr/bin" | "/usr/sbin" | "/usr/local/bin" | "/usr/local/sbin"
    ) {
        return false;
    }
    if name_has_source_component(pkg_name) {
        return true;
    }
    // /usr/share/go/<version>/src/... -- the version component is
    // a single digit-led directory between `go` and `src`.
    let comps: Vec<&str> = fname.split('/').filter(|c| !c.is_empty()).collect();
    comps.len() >= 6
        && comps[0] == "usr"
        && comps[1] == "share"
        && comps[2] == "go"
        && comps[3].starts_with(|c: char| c.is_ascii_digit())
        && comps[4] == "src"
}

/// One token of the small shell lexer behind
/// `shell_script_has_top_level_return`. The lexer resolves quoting
/// and escapes and consumes here-document bodies, so a word token's
/// text is the shell's own view of the word.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ShellTok {
    Word(String),
    Newline,
    /// `;` or `&`
    Semi,
    /// `&&` or `||`
    AndOr,
    /// `|` or `|&`
    Pipe,
    LParen,
    RParen,
    LBrace,
    RBrace,
    /// Any redirection operator; the word after it is its target
    /// (a here-document delimiter included), never a command.
    Redir,
}

/// How much of a script the sourced-fragment proof reads. A shell
/// script past a megabyte is not a fragment anyone sources, and
/// refusing the proof there keeps the scan bounded; the peek the
/// interpreter line comes from reads only 2048 bytes, which is why
/// the proof cannot ride on it.
const FRAGMENT_PROOF_SCAN_LIMIT: u64 = 1_048_576;

/// Whether `word` is a shell name (a function or variable name).
/// The tail also admits `-` and `.`: bash accepts both in function
/// names (`my-func ()`, `my.func ()`), and the function-definition
/// arms gate on this — a definition the gate misses leaves the
/// body's `return`s looking top-level, while a name it admits too
/// freely only ever spans a body the shell reads as one too.
fn is_shell_name(word: &str) -> bool {
    !word.is_empty()
        && word
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Whether `word`, read at command position, is a variable
/// assignment (`name=...`): the command it prefixes is still to
/// come.
fn is_assignment_word(word: &str) -> bool {
    match word.split_once('=') {
        Some((name, _)) => is_shell_name(name),
        None => false,
    }
}

/// Whether a word read at command position leaves the next word at
/// command position too: the condition and body keywords, the
/// negation and the prefix builtins that take a command as their
/// argument, and assignments.
fn word_keeps_command_position(word: &str) -> bool {
    matches!(
        word,
        "if" | "then"
            | "else"
            | "elif"
            | "while"
            | "until"
            | "do"
            | "!"
            | "time"
            | "command"
            | "builtin"
            | "exec"
    ) || is_assignment_word(word)
}

/// The index just past the bracket span that opens at `start`
/// (`chars[start]` is `(` or `{`), or the end of the input if the
/// span never closes. Quoted strings, backtick substitutions,
/// escapes and comments inside the span are skipped whole, so a
/// bracket inside one of them cannot close the span early. Inside
/// a parenthesised span the `)` that ends a `case` pattern list
/// is not the span's closer either: the scanner tracks each open
/// `case` through its pattern and item phases, and only a `)`
/// read outside a pattern list counts towards the balance.
fn scan_balanced(chars: &[char], start: usize) -> usize {
    #[derive(PartialEq)]
    enum CasePhase {
        /// `case` and its subject read, `in` not seen yet.
        BeforeIn,
        /// Reading a pattern list: a `)` ends the list, not the span.
        Pattern,
        /// Reading a pattern's commands, up to `;;` or `esac`.
        Item,
    }

    let n = chars.len();
    let open = chars[start];
    let close = if open == '(' { ')' } else { '}' };
    let parens = open == '(';
    let mut depth = 0usize;
    let mut cases: Vec<CasePhase> = Vec::new();
    let mut command_start = true;
    let mut i = start;
    while i < n {
        match chars[i] {
            '\\' => {
                i += if i + 1 < n { 2 } else { 1 };
            }
            '\'' => {
                i += 1;
                while i < n && chars[i] != '\'' {
                    i += 1;
                }
                if i < n {
                    i += 1;
                }
                command_start = false;
            }
            '"' => {
                i += 1;
                while i < n && chars[i] != '"' {
                    i += if chars[i] == '\\' && i + 1 < n { 2 } else { 1 };
                }
                if i < n {
                    i += 1;
                }
                command_start = false;
            }
            '`' => {
                i += 1;
                while i < n && chars[i] != '`' {
                    i += if chars[i] == '\\' && i + 1 < n { 2 } else { 1 };
                }
                if i < n {
                    i += 1;
                }
                command_start = false;
            }
            '#' if command_start && parens => {
                while i < n && chars[i] != '\n' {
                    i += if chars[i] == '\\' && i + 1 < n { 2 } else { 1 };
                }
            }
            c if c == open => {
                if !(parens && cases.last() == Some(&CasePhase::Pattern)) {
                    depth += 1;
                }
                command_start = true;
                i += 1;
            }
            c if c == close => {
                if parens && cases.last() == Some(&CasePhase::Pattern) {
                    if let Some(top) = cases.last_mut() {
                        *top = CasePhase::Item;
                    }
                } else {
                    depth -= 1;
                    if depth == 0 {
                        return i + 1;
                    }
                }
                command_start = true;
                i += 1;
            }
            ';' => {
                if parens
                    && i + 1 < n
                    && matches!(chars[i + 1], ';' | '&')
                    && cases.last() == Some(&CasePhase::Item)
                {
                    if let Some(top) = cases.last_mut() {
                        *top = CasePhase::Pattern;
                    }
                }
                command_start = true;
                i += 1;
            }
            '&' | '|' | '\n' => {
                command_start = true;
                i += 1;
            }
            ' ' | '\t' | '\r' => {
                i += 1;
            }
            _ => {
                let mut j = i;
                while j < n && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                if j == i {
                    // punctuation that starts no word (`$`, `*`, ...)
                    i += 1;
                } else {
                    if parens {
                        let word: String = chars[i..j].iter().collect();
                        match word.as_str() {
                            "case" if command_start => cases.push(CasePhase::BeforeIn),
                            "in" if cases.last() == Some(&CasePhase::BeforeIn) => {
                                if let Some(top) = cases.last_mut() {
                                    *top = CasePhase::Pattern;
                                }
                            }
                            "esac" if command_start && !cases.is_empty() => {
                                cases.pop();
                            }
                            _ => {}
                        }
                    }
                    i = j;
                }
                command_start = false;
            }
        }
    }
    n
}

/// Scan one shell word starting at `i` (a character that starts a
/// word): quotes and escapes resolve to their literal text, and
/// command and parameter substitutions are consumed whole as
/// opaque content, so no token boundary or keyword hides inside
/// them. Returns the word's text and the index just past it.
fn scan_shell_word(chars: &[char], mut i: usize) -> (String, usize) {
    let n = chars.len();
    let mut word = String::new();
    while i < n {
        match chars[i] {
            ' ' | '\t' | '\r' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>' => break,
            '\\' => {
                if i + 1 < n {
                    if chars[i + 1] != '\n' {
                        word.push(chars[i + 1]);
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            '\'' => {
                i += 1;
                while i < n && chars[i] != '\'' {
                    word.push(chars[i]);
                    i += 1;
                }
                if i < n {
                    i += 1;
                }
            }
            '"' => {
                i += 1;
                while i < n && chars[i] != '"' {
                    if chars[i] == '\\'
                        && i + 1 < n
                        && matches!(chars[i + 1], '"' | '\\' | '$' | '`' | '\n')
                    {
                        if chars[i + 1] != '\n' {
                            word.push(chars[i + 1]);
                        }
                        i += 2;
                    } else {
                        word.push(chars[i]);
                        i += 1;
                    }
                }
                if i < n {
                    i += 1;
                }
            }
            '`' => {
                word.push('`');
                i += 1;
                while i < n {
                    let c = chars[i];
                    word.push(c);
                    i += 1;
                    if c == '\\' && i < n {
                        word.push(chars[i]);
                        i += 1;
                    } else if c == '`' {
                        break;
                    }
                }
            }
            '$' if i + 1 < n && (chars[i + 1] == '(' || chars[i + 1] == '{') => {
                let end = scan_balanced(chars, i + 1);
                word.extend(chars[i..end].iter().copied());
                i = end;
            }
            c => {
                word.push(c);
                i += 1;
            }
        }
    }
    (word, i)
}

/// Skip a here-document body: lines from `i` up to and including
/// the line that consists solely of the delimiter (leading tabs
/// stripped first for `<<-`). Returns the index just past it.
fn skip_heredoc_body(chars: &[char], mut i: usize, delim: &str, strip_tabs: bool) -> usize {
    let n = chars.len();
    while i < n {
        let mut j = i;
        if strip_tabs {
            while j < n && chars[j] == '\t' {
                j += 1;
            }
        }
        let mut k = j;
        while k < n && chars[k] != '\n' {
            k += 1;
        }
        let line: String = chars[j..k].iter().collect();
        i = if k < n { k + 1 } else { k };
        if line == delim {
            break;
        }
    }
    i
}

/// Tokenize a shell script's text. Comments vanish, an arithmetic
/// command `(( ... ))` collapses to one opaque word, and
/// here-document bodies are consumed at the newline that ends the
/// line opening them, so none of those shapes can produce a token.
/// Process substitutions are consumed whole as word tokens, and
/// the brace tokens are re-read against command position at the
/// end (see `recheck_brace_tokens`).
fn lex_shell(content: &str) -> Vec<ShellTok> {
    let chars: Vec<char> = content.chars().collect();
    let n = chars.len();
    let mut toks = Vec::new();
    let mut heredocs: Vec<(String, bool)> = Vec::new();
    let mut want_delim: Option<bool> = None;
    let mut i = 0;
    while i < n {
        match chars[i] {
            ' ' | '\t' | '\r' => i += 1,
            '\n' => {
                toks.push(ShellTok::Newline);
                i += 1;
                for (delim, strip) in std::mem::take(&mut heredocs) {
                    i = skip_heredoc_body(&chars, i, &delim, strip);
                }
            }
            '#' => {
                // A backslash-newline inside a comment continues
                // it onto the next line, so backslashes are
                // consumed in pairs: an escaped backslash does
                // not fake a continuation.
                while i < n && chars[i] != '\n' {
                    i += if chars[i] == '\\' && i + 1 < n { 2 } else { 1 };
                }
            }
            '\\' if i + 1 < n && chars[i + 1] == '\n' => i += 2,
            ';' => {
                toks.push(ShellTok::Semi);
                i += 1;
            }
            '&' => {
                if i + 1 < n && chars[i + 1] == '&' {
                    toks.push(ShellTok::AndOr);
                    i += 2;
                } else {
                    toks.push(ShellTok::Semi);
                    i += 1;
                }
            }
            '|' => {
                if i + 1 < n && chars[i + 1] == '|' {
                    toks.push(ShellTok::AndOr);
                    i += 2;
                } else if i + 1 < n && chars[i + 1] == '&' {
                    toks.push(ShellTok::Pipe);
                    i += 2;
                } else {
                    toks.push(ShellTok::Pipe);
                    i += 1;
                }
            }
            '(' => {
                if i + 1 < n && chars[i + 1] == '(' {
                    let mut depth = 0usize;
                    let mut j = i;
                    while j < n {
                        match chars[j] {
                            '(' => depth += 1,
                            ')' => {
                                depth -= 1;
                                if depth == 0 {
                                    j += 1;
                                    break;
                                }
                            }
                            _ => {}
                        }
                        j += 1;
                    }
                    toks.push(ShellTok::Word("((arith))".to_string()));
                    i = j;
                } else {
                    toks.push(ShellTok::LParen);
                    i += 1;
                }
            }
            ')' => {
                toks.push(ShellTok::RParen);
                i += 1;
            }
            '<' => {
                if i + 1 < n && chars[i + 1] == '(' {
                    // a process substitution is a word-like
                    // operand: consume it whole, like `$(...)`,
                    // so its content produces no tokens
                    let end = scan_balanced(&chars, i + 1);
                    toks.push(ShellTok::Word(chars[i..end].iter().collect()));
                    i = end;
                } else if i + 2 < n && chars[i + 1] == '<' && chars[i + 2] == '<' {
                    // here-string: a redirection, no body follows
                    toks.push(ShellTok::Redir);
                    i += 3;
                } else if i + 1 < n && chars[i + 1] == '<' {
                    let strip = i + 2 < n && chars[i + 2] == '-';
                    toks.push(ShellTok::Redir);
                    want_delim = Some(strip);
                    i += if strip { 3 } else { 2 };
                } else {
                    toks.push(ShellTok::Redir);
                    i += 1;
                    if i < n && (chars[i] == '&' || chars[i] == '|') {
                        i += 1;
                    }
                }
            }
            '>' => {
                if i + 1 < n && chars[i + 1] == '(' {
                    // process substitution, as in the `<` arm
                    let end = scan_balanced(&chars, i + 1);
                    toks.push(ShellTok::Word(chars[i..end].iter().collect()));
                    i = end;
                } else {
                    toks.push(ShellTok::Redir);
                    i += 1;
                    if i < n && chars[i] == '>' {
                        i += 1;
                    }
                    if i < n && (chars[i] == '&' || chars[i] == '|') {
                        i += 1;
                    }
                }
            }
            '{' if i + 1 >= n
                || matches!(
                    chars[i + 1],
                    ' ' | '\t' | '\r' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>'
                ) =>
            {
                toks.push(ShellTok::LBrace);
                i += 1;
            }
            '}' if i + 1 >= n
                || matches!(
                    chars[i + 1],
                    ' ' | '\t' | '\r' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>'
                ) =>
            {
                toks.push(ShellTok::RBrace);
                i += 1;
            }
            _ => {
                let (word, next) = scan_shell_word(&chars, i);
                i = next;
                if let Some(strip) = want_delim.take() {
                    heredocs.push((word.clone(), strip));
                }
                toks.push(ShellTok::Word(word));
            }
        }
    }
    recheck_brace_tokens(&toks)
}

/// Re-read a lexed script's brace tokens. `{` and `}` are shell
/// reserved words only at command position — a brace group's or
/// a function body's brackets — and ordinary word characters
/// everywhere else: arguments (`echo }` prints one), names and
/// redirection targets. A brace emitted at a non-command
/// position becomes a word token, so it can neither manufacture
/// a command position for the word behind it (the `echo a }
/// return` shape, where `return` is an argument) nor close a
/// function span. The position pass mirrors the one in
/// `shell_script_has_top_level_return`, plus the function-header
/// zone that span detection recognizes: between a `name ()` or
/// `function name` header and its body the position is still the
/// body's, so a `{` there still opens it.
fn recheck_brace_tokens(toks: &[ShellTok]) -> Vec<ShellTok> {
    let mut out: Vec<ShellTok> = Vec::with_capacity(toks.len());
    let mut expect_command = true;
    let mut skip_word = false;
    // Between a function header and its body; `name_pending` is
    // set only by the `function` form, whose name is still to come.
    let mut in_header = false;
    let mut name_pending = false;
    for (idx, tok) in toks.iter().enumerate() {
        match tok {
            ShellTok::LBrace | ShellTok::RBrace if skip_word || !expect_command => {
                out.push(ShellTok::Word(
                    if matches!(tok, ShellTok::LBrace) {
                        "{"
                    } else {
                        "}"
                    }
                    .to_string(),
                ));
                skip_word = false;
            }
            ShellTok::LBrace => {
                out.push(tok.clone());
                in_header = false;
                expect_command = true;
            }
            ShellTok::RBrace => {
                out.push(tok.clone());
                in_header = false;
                expect_command = true;
            }
            ShellTok::Word(w) => {
                out.push(tok.clone());
                if skip_word {
                    skip_word = false;
                } else if !w.is_empty()
                    && w.chars().all(|c| c.is_ascii_digit())
                    && matches!(toks.get(idx + 1), Some(ShellTok::Redir))
                {
                    // an fd number before a redirection: the
                    // command it prefixes is still to come, and
                    // the position is unchanged
                } else if in_header {
                    if name_pending {
                        name_pending = false;
                    } else {
                        // the first word of a brace-less body
                        in_header = false;
                        expect_command = word_keeps_command_position(w);
                    }
                } else if expect_command {
                    if w == "function" {
                        in_header = true;
                        name_pending = true;
                    } else if is_shell_name(w)
                        && matches!(toks.get(idx + 1), Some(ShellTok::LParen))
                        && matches!(toks.get(idx + 2), Some(ShellTok::RParen))
                    {
                        in_header = true;
                        name_pending = false;
                    } else {
                        expect_command = word_keeps_command_position(w);
                    }
                }
            }
            ShellTok::Redir => {
                out.push(tok.clone());
                skip_word = true;
            }
            ShellTok::Newline => {
                out.push(tok.clone());
                expect_command = true;
            }
            ShellTok::LParen | ShellTok::RParen => {
                out.push(tok.clone());
                expect_command = true;
            }
            ShellTok::Semi | ShellTok::AndOr | ShellTok::Pipe => {
                out.push(tok.clone());
                in_header = false;
                expect_command = true;
            }
        }
    }
    out
}

/// The token span (opener..=closer) of the body of the function
/// definition whose header starts at token `i`, if `i` starts one:
/// `name ()` or `function name` (the `()` optional there), then a
/// `{ ... }` or `( ... )` body, with redirections and newlines
/// allowed between the header and the body. The body is spanned by
/// counting brackets of the body's own kind. A body that opens
/// with a word instead — a compound command (`f () if ...`,
/// `f () while ...`, `f () case ...`) or any other command — is
/// spanned to the end of the token stream: the scan cannot prove
/// where such a body ends, and a `return` it cannot prove
/// top-level must not count as one (fail-closed).
fn shell_function_body_span(toks: &[ShellTok], i: usize) -> Option<(usize, usize)> {
    let mut j = i;
    match toks.get(j) {
        Some(ShellTok::Word(w)) if is_shell_name(w) => {
            if matches!(toks.get(j + 1), Some(ShellTok::LParen))
                && matches!(toks.get(j + 2), Some(ShellTok::RParen))
            {
                j += 3;
            } else if w == "function" {
                match toks.get(j + 1) {
                    Some(ShellTok::Word(name)) if is_shell_name(name) => j += 2,
                    _ => return None,
                }
                if matches!(toks.get(j), Some(ShellTok::LParen))
                    && matches!(toks.get(j + 1), Some(ShellTok::RParen))
                {
                    j += 2;
                }
            } else {
                return None;
            }
        }
        _ => return None,
    }
    loop {
        match toks.get(j) {
            Some(ShellTok::Newline) => j += 1,
            Some(ShellTok::Redir) => {
                j += if matches!(toks.get(j + 1), Some(ShellTok::Word(_))) {
                    2
                } else {
                    1
                };
            }
            Some(open @ (ShellTok::LBrace | ShellTok::LParen)) => {
                let close = if *open == ShellTok::LBrace {
                    ShellTok::RBrace
                } else {
                    ShellTok::RParen
                };
                let mut depth = 0usize;
                let mut k = j;
                while k < toks.len() {
                    if toks[k] == *open {
                        depth += 1;
                    } else if toks[k] == close {
                        depth -= 1;
                        if depth == 0 {
                            return Some((j, k));
                        }
                    }
                    k += 1;
                }
                return None;
            }
            Some(ShellTok::Word(_)) => return Some((j, usize::MAX)),
            _ => return None,
        }
    }
}

/// Whether a shell script's text carries a `return` statement at
/// top level: at command position, outside every function
/// definition. bash and the POSIX shells refuse a top-level
/// `return` in an executed script ("can only 'return' from a
/// function or sourced script"), so its presence is a decidable
/// marker that the file was written to be sourced by another
/// script. The marker is not exclusive: a dual-mode script that
/// also supports direct execution, guarding its `return` behind
/// a runtime sourcedness test an executing shell never trips,
/// carries the same marker, and no decidable reading of the
/// text separates the two shapes.
///
/// The scan is the lexer above plus a command-position pass, not
/// a text search, so the shapes that merely mention `return` do
/// not count: comments, quoted strings, here-document bodies,
/// substitutions (opaque word content), a `return` used as an
/// argument, a loop variable or a `case` pattern, and a `return`
/// inside a function definition. A `return` directly before a
/// `)` or a `|` is a `case` pattern, not a statement, and does not count
/// either (a bare `return` closing a subshell reads the same and
/// is left firing). Control flow at top level does not suppress
/// the proof: a `return` inside a top-level `if`, loop, `case`
/// item, brace group or subshell would be refused by an
/// executing shell that reached it in exactly the same way.
fn shell_script_has_top_level_return(content: &str) -> bool {
    let toks = lex_shell(content);
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut expect_command = true;
    let mut skip_word = false;
    for (i, tok) in toks.iter().enumerate() {
        match tok {
            ShellTok::Word(w) => {
                if skip_word {
                    skip_word = false;
                    continue;
                }
                if !w.is_empty()
                    && w.chars().all(|c| c.is_ascii_digit())
                    && matches!(toks.get(i + 1), Some(ShellTok::Redir))
                {
                    // the fd number of a redirection (`2>file cmd`):
                    // the command it prefixes is still to come
                    continue;
                }
                if expect_command {
                    if let Some(span) = shell_function_body_span(&toks, i) {
                        spans.push(span);
                    } else if w == "return"
                        && !matches!(
                            toks.get(i + 1),
                            Some(ShellTok::RParen) | Some(ShellTok::Pipe)
                        )
                        && !spans.iter().any(|&(s, e)| s <= i && i <= e)
                    {
                        return true;
                    }
                    expect_command = word_keeps_command_position(w);
                }
            }
            ShellTok::Redir => skip_word = true,
            _ => expect_command = true,
        }
    }
    false
}

/// Whether the interpreter line names a POSIX-family shell,
/// resolving `/usr/bin/env` to the program it names: env's first
/// argument that is neither an option (the argument-taking `-u`
/// and `-C` skipped with their values) nor an assignment. Only
/// the sh family qualifies: a top-level `return` is refused by an
/// executing sh, bash, dash, ash or ksh, while zsh runs a script
/// in a function-like context where `return` is legal, so the
/// proof does not hold there.
fn interpreter_is_posix_shell(interpreter: &str, args: &str) -> bool {
    let base = interpreter.rsplit('/').next().unwrap_or("");
    let program: String = if base == "env" {
        let mut found = None;
        let mut skip_next = false;
        for word in args.split_whitespace() {
            if skip_next {
                skip_next = false;
                continue;
            }
            if matches!(word, "-u" | "--unset" | "-C" | "--chdir") {
                skip_next = true;
                continue;
            }
            if word.starts_with('-') || is_assignment_word(word) {
                continue;
            }
            found = Some(word.rsplit('/').next().unwrap_or(word).to_string());
            break;
        }
        match found {
            Some(p) => p,
            None => return false,
        }
    } else {
        base.to_string()
    };
    matches!(
        program.as_str(),
        "sh" | "bash" | "dash" | "ash" | "ksh" | "ksh93" | "mksh" | "pdksh"
    )
}

/// Whether a non-executable file with an interpreter line is a
/// sourced fragment rather than a script executed in place: the
/// interpreter names a POSIX-family shell (see
/// `interpreter_is_posix_shell`) and the file's text carries a
/// top-level `return` (see `shell_script_has_top_level_return`).
/// An executing shell that reaches the `return` refuses it, so
/// the missing exec bit is the fragment's correct state; a
/// dual-mode script that also runs standalone carries the same
/// marker and is exempted with it, an accepted consequence of
/// there being no decidable separation. The proof reads the
/// file's own text, bounded by `FRAGMENT_PROOF_SCAN_LIMIT`,
/// because a fragment's `return` can sit anywhere in it -- the
/// xim fragment's are at lines 160 to 225, far past the 2048-byte
/// peek the interpreter line is parsed from. The
/// script-directory guard of `non_executable_script_is_data`
/// applies unchanged: a file installed directly in a script
/// directory is an entry point whatever its text says, so the
/// proof is not consulted there.
fn non_executable_script_is_provable_fragment(
    pkgfile: &PkgFile,
    fname: &str,
    interpreter: &str,
    interpreter_args: &str,
) -> bool {
    let parent = fname.rsplit_once('/').map_or("", |(parent, _)| parent);
    if matches!(
        parent,
        "/bin" | "/sbin" | "/usr/bin" | "/usr/sbin" | "/usr/local/bin" | "/usr/local/sbin"
    ) {
        return false;
    }
    if !interpreter_is_posix_shell(interpreter, interpreter_args) {
        return false;
    }
    let Ok(file) = std::fs::File::open(&pkgfile.path) else {
        return false;
    };
    let Ok(bytes) = read_prefix(file, FRAGMENT_PROOF_SCAN_LIMIT + 1) else {
        return false;
    };
    if bytes.len() as u64 > FRAGMENT_PROOF_SCAN_LIMIT {
        return false;
    }
    let Ok(content) = String::from_utf8(bytes) else {
        return false;
    };
    shell_script_has_top_level_return(&content)
}

static PYTHON_BYTECODE_PEP3147_REGEX: OnceLock<Regex> = OnceLock::new();
fn python_bytecode_pep3147_regex() -> &'static Regex {
    PYTHON_BYTECODE_PEP3147_REGEX.get_or_init(|| {
        Regex::new(r"^(.*)/__pycache__/(.*?)\.([^.]+)(\.opt-[12])?\.py[oc]$").expect("static regex")
    })
}

static PYTHON_BYTECODE_REGEX: OnceLock<Regex> = OnceLock::new();
fn python_bytecode_regex() -> &'static Regex {
    PYTHON_BYTECODE_REGEX.get_or_init(|| Regex::new(r"^(.*)(\.py[oc])$").expect("static regex"))
}

static LOG_FILE_REGEX: OnceLock<Regex> = OnceLock::new();
fn log_file_regex() -> &'static Regex {
    LOG_FILE_REGEX.get_or_init(|| Regex::new(r"^/var/log/[^/]+$").expect("static regex"))
}

static LIB_PATH_REGEX: OnceLock<Regex> = OnceLock::new();
fn lib_path_regex() -> &'static Regex {
    LIB_PATH_REGEX.get_or_init(|| Regex::new(r"^(/usr(/X11R6)?)?/lib(64)?").expect("static regex"))
}

static START_CERTIFICATE_REGEX: OnceLock<Regex> = OnceLock::new();
fn start_certificate_regex() -> &'static Regex {
    START_CERTIFICATE_REGEX
        .get_or_init(|| Regex::new(r"^-----BEGIN CERTIFICATE-----\n?$").expect("static regex"))
}

static START_PRIVATE_KEY_REGEX: OnceLock<Regex> = OnceLock::new();
fn start_private_key_regex() -> &'static Regex {
    START_PRIVATE_KEY_REGEX.get_or_init(
        || // NB: the reference spells this with four leading dashes, so it cannot
    // match a well-formed PEM header; replicated exactly.
    // Python's `$` matches before a trailing newline, Rust's does not;
    // the explicit newline keeps the reference behavior.
    Regex::new(r"^----BEGIN PRIVATE KEY-----\n?$").expect("static regex"),
    )
}

/// Look for the file path in all tmpfiles.d configs declared in this package
/// and return the permission column. Mirrors the reference's
/// `find_perm_in_tmpfiles`: the last matching line wins, unreadable configs
/// are skipped, and `None` when no config declares the path (the caller
/// falls back to a type-appropriate default).
fn find_perm_in_tmpfiles(pkg: &Pkg, fname: &str) -> Option<(String, String, String)> {
    let mut found = None;
    // The reference realpaths the package path; package paths are already
    // normalized here, so a lexical clean is equivalent.
    let fname = clean_path(fname);
    let needle = format!(" {fname} ");

    for pkgfile in &pkg.files {
        if !pkgfile.name.contains("tmpfiles.d") || !pkgfile.name.ends_with(".conf") {
            continue;
        }
        let path = Path::new(&pkgfile.path);
        if !path.exists() || path.is_dir() {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines() {
            if !line.contains(&needle) {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                continue;
            }
            found = Some((
                fields[2].to_string(),
                fields[3].to_string(),
                fields[4].to_string(),
            ));
        }
    }

    found
}

/// Whether a `%ghost` entry with mode 000 tracks something whose
/// permissions the package does not own, so `zero-perms-ghost` stays
/// quiet: the alternatives tool owns every link under
/// `/etc/alternatives/`; the SELinux policy store under
/// `/etc/selinux/<policy>/active/` is rewritten by semodule; the kernel
/// boot symlinks `/boot/vmlinuz` and `/boot/initrd` are maintained by
/// kernel install tooling; the listed cache files are regenerated by
/// their tools (gtk-update-icon-cache, mkfontdir/mkfontscale,
/// fonts-config, install-info); and an install-time scriptlet that
/// creates the path as a symlink (see `scriptlet_creates_symlink`)
/// means the entry tracks a link, whose permission bits are ignored.
fn zero_perms_ghost_credit(pkg: &Pkg, fname: &str) -> bool {
    if fname.starts_with("/etc/alternatives/") {
        return true;
    }
    if let Some(rest) = fname.strip_prefix("/etc/selinux/") {
        if rest.split('/').nth(1) == Some("active") {
            return true;
        }
    }
    if fname == "/boot/vmlinuz" || fname == "/boot/initrd" {
        return true;
    }
    if fname == "/usr/share/info/dir" || fname == "/usr/info/dir" {
        return true;
    }
    if let Some(base) = fname.rsplit('/').next() {
        if base == "icon-theme.cache" && fname.starts_with("/usr/share/icons/") {
            return true;
        }
        if matches!(
            base,
            "encodings.dir" | "fonts.scale" | ".fonts-config-timestamp"
        ) && fname.starts_with("/usr/share/fonts/")
        {
            return true;
        }
    }
    scriptlet_creates_symlink(&ghost_scriptlet_text(pkg), fname)
}

/// The byte offset of `word` as a standalone word in `text`, if any:
/// bounded by non-word characters (or text edges) on both sides.
fn find_word(text: &str, word: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = text[from..].find(word) {
        let at = from + rel;
        let before_ok = at == 0
            || (!text.as_bytes()[at - 1].is_ascii_alphanumeric()
                && text.as_bytes()[at - 1] != b'_');
        let after = at + word.len();
        let after_ok = after == text.len()
            || (!text.as_bytes()[after].is_ascii_alphanumeric() && text.as_bytes()[after] != b'_');
        if before_ok && after_ok {
            return Some(at);
        }
        from = at + word.len();
    }
    None
}

/// The link arguments of literal `ln -s` commands in `text`: each
/// command contributes its link only when it carries the `-s` flag,
/// takes exactly two path arguments, and the link is absolute.
/// Value-taking options and `-t`/`--target-directory` disqualify the
/// command; quotes around arguments are stripped.
fn ln_links_in(text: &str) -> Vec<String> {
    let mut links = Vec::new();
    let mut from = 0;
    while let Some(rel) = find_word(&text[from..], "ln") {
        let at = from + rel;
        let rest = &text[at + 2..];
        let cmd_end = rest
            .find(|c| [';', '&', '|', '\n', ')'].contains(&c))
            .unwrap_or(rest.len());
        let cmd = &rest[..cmd_end];
        from = at + 2;
        let tokens: Vec<String> = cmd
            .split_whitespace()
            .map(|t| {
                let t = t.strip_prefix(['\'', '"']).unwrap_or(t);
                let t = t.strip_suffix(['\'', '"']).unwrap_or(t);
                t.to_string()
            })
            .collect();
        let mut options: Vec<String> = Vec::new();
        let mut paths: Vec<String> = Vec::new();
        let mut opts_done = false;
        let mut disqualified = false;
        for tok in &tokens {
            if !opts_done && tok == "--" {
                opts_done = true;
            } else if !opts_done && tok.starts_with('-') && tok.as_str() != "-" {
                if matches!(
                    tok.as_str(),
                    "-t" | "--target-directory" | "-b" | "-S" | "--suffix" | "--backup"
                ) {
                    disqualified = true;
                    break;
                }
                options.push(tok.clone());
            } else {
                paths.push(tok.clone());
            }
        }
        if disqualified {
            continue;
        }
        let has_s = options.iter().any(|o| o.contains('s'));
        if has_s && paths.len() == 2 && paths[1].starts_with('/') {
            links.push(paths[1].clone());
        }
    }
    links
}

/// Whether the install-time scriptlets create `path` as a symlink with
/// `ln -s`: a literal `ln -s <target> <path>`, or a
/// `for V in words; do ... done` loop whose `ln -s` link argument
/// expands `$V` over the word list. A nested loop truncates at the
/// first `done`: under-coverage only, never a false link. Matching is
/// syntactic, like the other scriptlet matchers: a commented-out `ln`
/// line would count.
fn scriptlet_creates_symlink(text: &str, path: &str) -> bool {
    if ln_links_in(text).iter().any(|link| link == path) {
        return true;
    }
    let mut rest = text;
    while let Some(for_at) = find_word(rest, "for") {
        let mut after = rest[for_at + 3..].trim_start();
        let var_end = after
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(after.len());
        let var = &after[..var_end];
        if var.is_empty() {
            break;
        }
        after = after[var_end..].trim_start();
        let mut words_iter = after.splitn(2, |c: char| c.is_whitespace());
        if words_iter.next() != Some("in") {
            break;
        }
        after = words_iter.next().unwrap_or("").trim_start();
        let Some(semi) = after.find(';') else {
            break;
        };
        let words: Vec<&str> = after[..semi].split_whitespace().collect();
        after = after[semi + 1..].trim_start();
        let mut do_iter = after.splitn(2, |c: char| c.is_whitespace());
        if do_iter.next() != Some("do") {
            break;
        }
        after = do_iter.next().unwrap_or("");
        let Some(done_at) = find_word(after, "done") else {
            break;
        };
        let body = &after[..done_at];
        for link in ln_links_in(body) {
            for word in &words {
                let braced = format!("${{{var}}}");
                let expanded = if link.contains(&braced) {
                    link.replacen(&braced, word, 1)
                } else {
                    link.replacen(&format!("${var}"), word, 1)
                };
                if expanded == path {
                    return true;
                }
            }
        }
        rest = &after[done_at + 4..];
    }
    false
}

/// Lexically normalize a path (resolve `.` and `..`), without touching the
/// filesystem.
fn clean_path(path: &str) -> String {
    use std::path::Component;
    let mut out = std::path::PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            _ => out.push(component.as_os_str()),
        }
    }
    out.to_string_lossy().into_owned()
}

/// One `[[FileGrants]]` config entry: the named findings stay quiet
/// for one package's named files. The `reason` is the recorded
/// justification, surfaced in the debug log when the grant applies;
/// an entry without one is rejected at parse time (see
/// `FilesCheck::parse_file_grants`), so every live grant carries its
/// explanation in the settings record itself.
#[derive(Debug, Clone)]
struct FileGrant {
    packages: Vec<String>,
    paths: Vec<String>,
    findings: Vec<String>,
    reason: String,
}

#[allow(dead_code)]
pub struct FilesCheck {
    man_re: Regex,
    man_base_re: Regex,
    info_re: Regex,
    devel_re: Regex,
    devel_component_re: Regex,
    kernel_package_re: Regex,
    debuginfo_package_re: Regex,
    debugsource_package_re: Regex,
    kernel_modules_re: Regex,
    macro_re: Regex,
    quotes_re: Regex,
    games_group_re: Regex,
    skipdocs_re: Regex,
    meta_package_re: Regex,
    compr_re: Regex,
    absolute_re: Regex,
    absolute2_re: Regex,
    points_re: Regex,
    doc_re: Regex,
    bin_re: Regex,
    includefile_re: Regex,
    develfile_re: Regex,
    buildconfigfile_re: Regex,
    buildconfig_rpath_re: Regex,
    sofile_re: Regex,
    lib_re: Regex,
    interpreter_re: Regex,
    script_re: Regex,
    sourced_script_re: Regex,
    fsf_license_re: Regex,
    fsf_wrong_address_re: Regex,
    scalable_icon_re: Regex,
    tcl_re: Regex,
    perl_re: Regex,
    python_re: Regex,
    python_lib_tree_re: Regex,
    python_bytecode_pep3147_re: Regex,
    python_bytecode_re: Regex,
    log_file_re: Regex,
    lib_path_re: Regex,
    start_certificate_re: Regex,
    start_private_key_re: Regex,
    valid_license_keys: HashSet<String>,
    use_debugsource: bool,
    module_rpms_ok: bool,
    use_relative_symlinks: bool,
    perl_version_trick: bool,
    compress_ext: String,
    standard_users: Vec<String>,
    standard_groups: Vec<String>,
    disallowed_dirs: Vec<String>,
    preset_packages: Vec<String>,
    file_grants: Vec<FileGrant>,
    dangling_exceptions: Vec<(String, Regex)>,
    ldconfig_re: Regex,
    python_default_version: String,
    /// Probed `gzip`, `bzip2`, `xz`, `zstd`, in that order.
    decompressors: [Tool; 4],
    /// Session state for `dangling-relative-symlink` (issue #547): the
    /// file names shipped by every package seen since the last export,
    /// and the relative links no single package resolved. The finding
    /// is decided in `after_checks`, once every package of the run has
    /// been seen.
    session_files: HashSet<String>,
    /// Session state for the run-scoped `python-bytecode-without-source`
    /// credit: the names shipped as regular, non-ghost files by every
    /// package seen since the last export. The credit keys on this set,
    /// not on `session_files`, whose name-only contents also cover
    /// directories, symlinks and ghost entries that ship no source.
    session_regular_files: HashSet<String>,
    dangling_candidates: Vec<DanglingCandidate>,
    /// Session state for the run-scoped `python-bytecode-without-source`
    /// credit: the candidates whose mapped source ships only as a
    /// symlink whose chain leaves the package, and the `SOURCERPM`
    /// spellings of the source packages the run holds. The finding
    /// is decided in `after_checks`, once the run's file set and the
    /// completeness of the candidate's build are known.
    bytecode_candidates: Vec<BytecodeCandidate>,
    bytecode_sources: HashSet<String>,
    /// Session state for `non-standard-uid` / `non-standard-gid` (issue
    /// #756): the files whose owner sits outside the standard registry,
    /// held as candidates, and the user/group names the run's packages
    /// declare through the source-wide routes (a shipped sysusers.d
    /// snippet, a `user()` / `group()` Provides), per source key.
    /// Requires crediting is per file-owning package instead and rides
    /// on each candidate itself. The finding is decided in
    /// `after_checks`, once every package of the run has been seen.
    owner_candidates: Vec<OwnerCandidate>,
    declared_users: HashMap<String, HashSet<String>>,
    declared_groups: HashMap<String, HashSet<String>>,
    /// Session state for the `no-dependency-on` perl/python rules
    /// (issue #862): the candidates whose own lists carry no credited
    /// base dependency, and every checked package's dependency lists
    /// by package name, so `after_checks` can credit an anchor
    /// requirement on a same-source sibling that itself carries the
    /// base dependency.
    nodep_candidates: Vec<NodepCandidate>,
    pkg_deps: HashMap<String, Vec<PkgDeps>>,
    /// Decompressed bytes per file path for `manpage_text`
    /// (see `decompressed_bytes`); `None` entries
    /// record outputs that could not be obtained or exceeded the text
    /// limit, so the fallback read is not repeated either.
    decompressed_cache: std::cell::RefCell<HashMap<String, Option<Arc<[u8]>>>>,
}

impl FilesCheck {
    pub fn new(config: &Config) -> Self {
        Self::with_tool_source(config, ToolSource::Path)
    }

    /// Probe for the decompressor tools under `source`.
    pub fn with_tool_source(config: &Config, source: ToolSource) -> Self {
        let tbl = &config.configuration;
        let get_str = |k: &str| {
            tbl.get(k)
                .and_then(toml::Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        let get_bool = |k: &str| tbl.get(k).and_then(toml::Value::as_bool).unwrap_or(false);
        let get_strings = |k: &str| {
            tbl.get(k)
                .and_then(toml::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        let dangling = tbl
            .get("DanglingSymlinkExceptions")
            .and_then(toml::Value::as_table)
            .map(|t| {
                t.values()
                    .filter_map(|v| {
                        let path = v.get("path").and_then(toml::Value::as_str)?;
                        let name = v
                            .get("name")
                            .and_then(toml::Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        Regex::new(path).ok().map(|re| (name, re))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let games_group = get_str("RpmGamesGroup");
        let skipdocs = get_str("SkipDocsRegexp");
        let meta_pkg = get_str("MetaPackageRegexp");
        Self {
            man_re: man_regex().clone(),
            man_base_re: man_base_regex().clone(),
            info_re: info_regex().clone(),
            devel_re: devel_regex().clone(),
            devel_component_re: devel_component_regex().clone(),
            kernel_package_re: kernel_package_regex().clone(),
            debuginfo_package_re: debuginfo_package_regex().clone(),
            debugsource_package_re: debugsource_package_regex().clone(),
            kernel_modules_re: kernel_modules_regex().clone(),
            macro_re: macro_regex().clone(),
            quotes_re: quotes_regex().clone(),
            games_group_re: Regex::new(&games_group)
                .unwrap_or_else(|_| Regex::new("$^").expect("static")),
            skipdocs_re: Regex::new(&format!("(?i){skipdocs}"))
                .unwrap_or_else(|_| Regex::new("$^").expect("static")),
            meta_package_re: Regex::new(&meta_pkg)
                .unwrap_or_else(|_| Regex::new("$^").expect("static")),
            compr_re: compr_regex().clone(),
            absolute_re: absolute_regex().clone(),
            absolute2_re: absolute2_regex().clone(),
            points_re: points_regex().clone(),
            doc_re: doc_regex().clone(),
            bin_re: bin_regex().clone(),
            includefile_re: includefile_regex().clone(),
            develfile_re: develfile_regex().clone(),
            buildconfigfile_re: buildconfigfile_regex().clone(),
            buildconfig_rpath_re: buildconfig_rpath_regex().clone(),
            sofile_re: sofile_regex().clone(),
            lib_re: lib_regex().clone(),
            interpreter_re: interpreter_regex().clone(),
            script_re: script_regex().clone(),
            sourced_script_re: sourced_script_regex().clone(),
            fsf_license_re: fsf_license_regex().clone(),
            fsf_wrong_address_re: fsf_wrong_address_regex().clone(),
            scalable_icon_re: scalable_icon_regex().clone(),
            tcl_re: tcl_regex().clone(),
            perl_re: perl_regex().clone(),
            python_re: python_regex().clone(),
            python_lib_tree_re: python_lib_tree_regex().clone(),
            python_bytecode_pep3147_re: python_bytecode_pep3147_regex().clone(),
            python_bytecode_re: python_bytecode_regex().clone(),
            log_file_re: log_file_regex().clone(),
            lib_path_re: lib_path_regex().clone(),
            start_certificate_re: start_certificate_regex().clone(),
            start_private_key_re: start_private_key_regex().clone(),
            valid_license_keys: {
                let valid: Vec<String> = get_strings("ValidLicenses");
                valid_license_keys(&valid)
            },
            use_debugsource: get_bool("UseDebugSource"),
            module_rpms_ok: get_bool("KernelModuleRPMsOK"),
            use_relative_symlinks: get_bool("UseRelativeSymlinks"),
            perl_version_trick: get_bool("PerlVersionTrick"),
            compress_ext: get_str("CompressExtension"),
            standard_users: get_strings("StandardUsers"),
            standard_groups: get_strings("StandardGroups"),
            disallowed_dirs: get_strings("DisallowedDirs"),
            preset_packages: get_strings("SystemdPresetPackages"),
            file_grants: Self::parse_file_grants(config),
            dangling_exceptions: dangling,
            ldconfig_re: Regex::new(r"(?m)^[^#]*ldconfig").expect("static regex"),
            python_default_version: get_str("PythonDefaultVersion"),
            decompressors: ["gzip", "bzip2", "xz", "zstd"]
                .map(|name| Tool::probe(&source, name, &[]).0),
            session_files: HashSet::new(),
            session_regular_files: HashSet::new(),
            dangling_candidates: Vec::new(),
            bytecode_candidates: Vec::new(),
            bytecode_sources: HashSet::new(),
            owner_candidates: Vec::new(),
            declared_users: HashMap::new(),
            declared_groups: HashMap::new(),
            nodep_candidates: Vec::new(),
            pkg_deps: HashMap::new(),
            decompressed_cache: std::cell::RefCell::new(HashMap::new()),
        }
    }

    /// Test entry point: `None` probes the live `PATH`, `Some(dir)`
    /// resolves the tools under `dir` instead of mutating the process
    /// environment.
    pub fn with_tool_dir(config: &Config, bin_dir: Option<&std::path::Path>) -> Self {
        Self::with_tool_source(config, test_source(bin_dir))
    }

    /// Parse the `FileGrants` tables from the config: the per-file
    /// grants the distribution settings record (the vendored openSUSE
    /// config carries the set; see FILE_GRANTS in
    /// scripts/generate-distro-configs.py). An entry is honoured only
    /// when it names its package(s), paths and findings and records a
    /// non-empty `reason`; a malformed entry is logged and skipped
    /// rather than silently matching nothing or everything.
    fn parse_file_grants(config: &Config) -> Vec<FileGrant> {
        let mut out = Vec::new();
        let Some(list) = config
            .configuration
            .get("FileGrants")
            .and_then(toml::Value::as_array)
        else {
            return out;
        };
        for item in list {
            let Some(table) = item.as_table() else {
                log::error!("FileGrants: entry is not a table, skipping");
                continue;
            };
            let has_package = table.contains_key("package");
            let has_packages = table.contains_key("packages");
            if has_package == has_packages {
                log::error!(
                    "FileGrants: entry needs exactly one of \"package\"/\"packages\", skipping"
                );
                continue;
            }
            let mut packages = Vec::new();
            if let Some(p) = table.get("package") {
                match p.as_str() {
                    Some(s) => packages.push(s.to_string()),
                    None => {
                        log::error!("FileGrants: \"package\" must be a string, skipping entry");
                        continue;
                    }
                }
            }
            if let Some(ps) = table.get("packages") {
                let Some(arr) = ps.as_array() else {
                    log::error!("FileGrants: \"packages\" must be an array, skipping entry");
                    continue;
                };
                let mut ok = true;
                for v in arr {
                    match v.as_str() {
                        Some(s) => packages.push(s.to_string()),
                        None => {
                            log::error!(
                                "FileGrants: \"packages\" entries must be strings, skipping entry"
                            );
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok {
                    continue;
                }
            }
            let string_list = |key: &str| -> Option<Vec<String>> {
                table
                    .get(key)?
                    .as_array()?
                    .iter()
                    .map(|v| v.as_str().map(str::to_string))
                    .collect()
            };
            let Some(paths) = string_list("paths") else {
                log::error!(
                    "FileGrants: entry for {packages:?} needs a \"paths\" array of strings, \
                     skipping"
                );
                continue;
            };
            let Some(findings) = string_list("findings") else {
                log::error!(
                    "FileGrants: entry for {packages:?} needs a \"findings\" array of strings, \
                     skipping"
                );
                continue;
            };
            if paths.is_empty() || findings.is_empty() {
                log::error!(
                    "FileGrants: entry for {packages:?} names no paths or no findings, skipping"
                );
                continue;
            }
            let reason = table
                .get("reason")
                .and_then(toml::Value::as_str)
                .unwrap_or("");
            if reason.trim().is_empty() {
                log::error!("FileGrants: entry for {packages:?} records no reason, skipping");
                continue;
            }
            out.push(FileGrant {
                packages,
                paths,
                findings,
                reason: reason.to_string(),
            });
        }
        out
    }

    /// Whether a `FileGrants` entry covers this package, path and
    /// finding: package name, file path and finding tag must all
    /// match exactly.
    fn file_granted(&self, pkg_name: &str, path: &str, finding: &str) -> bool {
        let Some(grant) = self.file_grants.iter().find(|g| {
            g.packages.iter().any(|p| p.as_str() == pkg_name)
                && g.paths.iter().any(|p| p.as_str() == path)
                && g.findings.iter().any(|f| f.as_str() == finding)
        }) else {
            return false;
        };
        // The logged values are the grant's own config values: the
        // exact-match predicate above means they name the matched
        // package and path, and package-derived data stays out of
        // the log line.
        log::debug!(
            "FileGrants: {finding} on {:?} in {:?} stays quiet: {}",
            grant.paths,
            grant.packages,
            grant.reason
        );
        true
    }
}

/// Per-package mutable state, mirroring the `self.*` attributes set in
/// `FilesCheck.check`.
#[derive(Default)]
#[allow(dead_code)]
struct PkgState {
    devel_pkg: bool,
    is_kernel_package: bool,
    debuginfo_package: bool,
    debugsource_package: bool,
    /// The package's scalable icon payload is a uniformly gzipped
    /// icon theme (see `FilesCheck::svgz_theme_credit`);
    /// `gzipped-svg-icon` stays silent for such a package.
    svgz_theme: bool,
    perl_dep_error: bool,
    python_dep_error: bool,
    /// `no-dependency-on` candidates this package recorded (issue
    /// #862), drained into the check's session state by `check_binary`.
    nodep_candidates: Vec<NodepCandidate>,
    /// Library-tree prefixes of the interpreters this package ships
    /// (see `FilesCheck::interpreter_lib_trees`); a bytecode file
    /// inside one is the shipped interpreter's own payload.
    bytecode_interpreter_trees: Vec<String>,
    /// `python-bytecode-without-source` run-scope candidates this
    /// package recorded, drained into the check's session state by
    /// `check_binary`.
    bytecode_candidates: Vec<BytecodeCandidate>,
    /// The parsed `License` tag identifiers for the license-coverage
    /// tags (issue #1033); empty when the package carries no usable
    /// License tag, which disables the coverage scan for the package.
    license_tag_ids: Vec<LicenseId>,
    /// Unsatisfied license declarations of this package by
    /// aggregation key, in first-seen order (issue #1033).
    license_units: IndexMap<String, LicenseUnitAgg>,
    debuginfo_srcs: bool,
    debuginfo_debugs: bool,
    postin: String,
    postun: String,
    preun: String,
    /// Directories named by the `/etc/ld.so.conf.d/*.conf` snippets this
    /// package ships (issue #569): together with the standard libdirs,
    /// the only directories ldconfig scans.
    ldconfig_dirs: std::collections::HashSet<String>,
    /// The package's SOURCE_DATE_EPOCH when one is known (see
    /// `crate::checks::shared::source_date_epoch_seconds`); without it the
    /// gzip-header MTIME comparison has nothing to compare against.
    source_date_epoch: Option<i64>,
    bindir_exes: IndexMap<String, Vec<String>>,
    man_basenames: std::collections::HashSet<String>,
    /// The subset of `man_basenames` prefixes a `-<version>` tail
    /// follows (`abimap` for the page basename `abimap-3.13.1`),
    /// precomputed when a basename is recorded so the version-affix
    /// credit is a set lookup instead of a per-miss scan of every
    /// man basename.
    man_version_bases: std::collections::HashSet<String>,
    /// Symlink targets by shipped path, for resolving a bindir link to
    /// the file it ultimately invokes.
    link_targets: HashMap<String, String>,
    /// Bindir symlink paths by executable name, indexed when a link
    /// is recorded so the alias credit looks up one name's links
    /// instead of scanning every link path per miss.
    bindir_links: HashMap<String, Vec<String>>,
    /// Every shipped path; link resolution stops at the package boundary.
    shipped_paths: std::collections::HashSet<String>,
    /// Basenames of regular files by (rdev, inode): files sharing a key
    /// are hardlinks to one another.
    inode_basenames: HashMap<(u32, u32), Vec<String>>,
    /// (rdev, inode) of each registered regular bindir executable path.
    bindir_inodes: HashMap<String, (u32, u32)>,
}

impl Check for FilesCheck {
    fn name(&self) -> &'static str {
        "FilesCheck"
    }

    fn check_source(&mut self, pkg: &Pkg, config: &Config, out: &mut Filter) {
        // The trojan-source attack lives in source files, so the bidi scan
        // runs for source packages too; the rest of FilesCheck is
        // binary-only. `Check::check` never routes a source package to
        // `check_binary`, so there is no `is_source` guard there.
        Self::register_error_details(config, out);
        self.check_bidi_controls(pkg, out);
        // A source package opens the completeness gate of its build
        // for the run-scoped `python-bytecode-without-source` credit:
        // the run judges a build complete when it holds the build's
        // source package.
        self.bytecode_sources
            .extend(crate::checks::shared::source_package_keys(pkg));
    }

    fn check_binary(&mut self, pkg: &Pkg, config: &Config, out: &mut Filter) {
        // `-v`/`--explain` descriptions, mirroring the reference's
        // `__init__` dict which installs them unconditionally.
        Self::register_error_details(config, out);
        let mut st = PkgState {
            ..Default::default()
        };
        self.check_utf8(pkg, out);
        self.check_bidi_controls(pkg, out);
        // A devel keyword as a hyphen-delimited name component
        // (`libstdc++6-devel-gcc7`, `ruby4.0-devel-extra`) marks a
        // flavoured devel package just as the suffix form does --
        // the same component test TagsCheck applies to its
        // dependency findings, scoped to the devel keyword: a
        // `-debug-` component names a debug flavour of a runtime
        // package, not a devel package. A final source component
        // (`name_has_source_component`) declares a source package.
        // Provides names take the suffix test plus the same
        // source-component credit: a virtual provide carrying the
        // devel keyword mid-name carries no such fact, but a
        // provide whose final component is a source component
        // declares the same source package the name form does.
        st.devel_pkg = is_match(&self.devel_re, &pkg.name)
            || is_match(&self.devel_component_re, &pkg.name)
            || name_has_source_component(&pkg.name);
        if !st.devel_pkg {
            for p in &pkg.provides {
                if is_match(&self.devel_re, &p.name) || name_has_source_component(&p.name) {
                    st.devel_pkg = true;
                    break;
                }
            }
        }
        st.is_kernel_package = is_match(&self.kernel_package_re, &pkg.name);
        st.debuginfo_package = is_match(&self.debuginfo_package_re, &pkg.name);
        st.debugsource_package = is_match(&self.debugsource_package_re, &pkg.name);
        st.svgz_theme = self.svgz_theme_credit(pkg);
        st.postin = strip_quotes(
            &self.quotes_re,
            &crate::checks::shared::script_body_or_prog(
                pkg,
                librpm::Tag::POSTIN,
                librpm::Tag::POSTINPROG,
            ),
        );
        st.postun = strip_quotes(
            &self.quotes_re,
            &crate::checks::shared::script_body_or_prog(
                pkg,
                librpm::Tag::POSTUN,
                librpm::Tag::POSTUNPROG,
            ),
        );
        // The reference does not strip quotes from preun.
        st.preun = crate::checks::shared::script_body_or_prog(
            pkg,
            librpm::Tag::PREUN,
            librpm::Tag::PREUNPROG,
        );
        st.ldconfig_dirs = ldconfig_conf_dirs(pkg);
        st.source_date_epoch = crate::checks::shared::source_date_epoch_seconds(pkg);
        st.bytecode_interpreter_trees = Self::interpreter_lib_trees(pkg);
        st.license_tag_ids = pkg
            .tag_str(librpm::Tag::LICENSE)
            .map(|t| parse_license_tag(&t))
            .unwrap_or_default();

        self.session_files
            .extend(pkg.files.iter().map(|f| f.name.clone()));
        self.session_regular_files.extend(
            pkg.files
                .iter()
                .filter(|f| !f.is_ghost() && is_reg(f.mode))
                .map(|f| f.name.clone()),
        );
        self.note_declared_owners(pkg);
        self.pkg_deps
            .entry(pkg.name.clone())
            .or_default()
            .push(PkgDeps::snapshot(pkg));
        self.check_meta_package(pkg, &st, out);
        self.check_empty_debuginfo(pkg, &st, out);
        for f in &pkg.files {
            self.check_file(pkg, &f.name, f, &mut st, out);
        }
        self.check_manpage_compression(pkg, out);
        self.check_manpage_so_refs(pkg, out);
        self.check_debug_files_in_non_debug_package(pkg, &st, out);
        self.check_debuginfo_without_sources(pkg, &st, out);
        self.check_bindir_exes(pkg, &st, out);
        self.check_sysconfig_fillup_usage(pkg, out);
        self.check_ghost_buildroot_content(pkg, out);
        self.check_fillup_template_without_call(pkg, out);
        self.check_fillup_usage_discouraged(pkg, out);
        self.check_license_coverage(pkg, &st, out);
        self.nodep_candidates.append(&mut st.nodep_candidates);
        self.bytecode_candidates.append(&mut st.bytecode_candidates);
    }

    fn after_checks(&mut self, _config: &Config, out: &mut Filter) {
        // The session-aware `dangling-relative-symlink` decision (issue
        // #547): a candidate fires only when no package of the run
        // ships its normalised target. Candidates are in lint order,
        // which the stable output sort preserves for equal keys.
        for cand in &self.dangling_candidates {
            if self.session_files.contains(&cand.target) {
                continue;
            }
            match &cand.disposition {
                DanglingDisposition::Plain => out.add_info(make_finding(
                    &cand.name,
                    &cand.arch,
                    Level::Info,
                    "dangling-relative-symlink",
                    vec![cand.fname.clone(), cand.link.clone()],
                    None,
                )),
                DanglingDisposition::Divert(name) => out.add_info(make_finding(
                    &cand.name,
                    &cand.arch,
                    Level::Warning,
                    "no-dependency-on",
                    vec![name.clone()],
                    None,
                )),
                DanglingDisposition::Silent => {}
            }
        }
        // The session-aware `non-standard-uid` / `non-standard-gid`
        // decision (issue #756): a candidate fires only when the owner
        // is declared through a source-wide route -- a sysusers.d
        // snippet or a `user()` / `group()` Provides from a package
        // built from the same source (see `note_declared_owners`) --
        // or the file-owning package itself Requires the capability
        // (`cand.own_requires`). A sibling's Requires credits nothing:
        // installed standalone, the owning package carries no
        // declaration of the account through any of these routes.
        // Candidates are in lint order, which the stable
        // output sort preserves for equal keys.
        for cand in &self.owner_candidates {
            if cand.own_requires {
                continue;
            }
            let declared = if cand.group {
                self.declared_groups.get(&cand.source)
            } else {
                self.declared_users.get(&cand.source)
            };
            if declared.is_some_and(|names| names.contains(&cand.owner)) {
                continue;
            }
            out.add_info(make_finding(
                &cand.name,
                &cand.arch,
                Level::Error,
                if cand.group {
                    "non-standard-gid"
                } else {
                    "non-standard-uid"
                },
                vec![cand.fname.clone(), cand.owner.clone()],
                None,
            ));
        }
        // The session-aware `no-dependency-on` decision (issue #862):
        // a candidate stays quiet when one of its anchor requirements
        // names a package of the run built from the same source whose
        // own lists carry the base dependency — the `-lang`/`-devel`
        // subpackage anchored on its main package. The credit is one
        // hop: the sibling must carry the dependency itself, a
        // requirement on a package of another source credits nothing,
        // and an anchor whose sibling carries nothing credits nothing.
        for cand in &self.nodep_candidates {
            if !self.anchor_credits(cand) {
                out.add_info(make_finding(
                    &cand.name,
                    &cand.arch,
                    Level::Error,
                    "no-dependency-on",
                    vec![cand.base.to_string(), cand.version.clone()],
                    None,
                ));
            }
        }
        // The run-scoped `python-bytecode-without-source` decision:
        // A candidate is credited only when the run holds the build's
        // source package (source presence only, matched by header
        // identity) and a package of the run ships the file the source
        // symlink resolves to, under a `.py` name. Every other candidate
        // fires, so partial and single-package runs report exactly
        // the per-package verdict.
        for cand in &self.bytecode_candidates {
            let complete = cand
                .build_key
                .as_ref()
                .is_some_and(|key| self.bytecode_sources.contains(key));
            if complete
                && cand.target.ends_with(".py")
                && self.session_regular_files.contains(&cand.target)
            {
                continue;
            }
            out.add_info(make_finding(
                &cand.name,
                &cand.arch,
                Level::Warning,
                "python-bytecode-without-source",
                vec![cand.fname.clone()],
                None,
            ));
        }
    }

    fn reset(&mut self) {
        self.session_files.clear();
        self.session_regular_files.clear();
        self.dangling_candidates.clear();
        self.bytecode_candidates.clear();
        self.bytecode_sources.clear();
        self.owner_candidates.clear();
        self.declared_users.clear();
        self.declared_groups.clear();
        self.nodep_candidates.clear();
        self.pkg_deps.clear();
        self.decompressed_cache.borrow_mut().clear();
    }

    fn export_state(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        if self.session_files.is_empty()
            && self.session_regular_files.is_empty()
            && self.dangling_candidates.is_empty()
            && self.bytecode_candidates.is_empty()
            && self.bytecode_sources.is_empty()
            && self.owner_candidates.is_empty()
            && self.declared_users.is_empty()
            && self.declared_groups.is_empty()
            && self.nodep_candidates.is_empty()
            && self.pkg_deps.is_empty()
        {
            return None;
        }
        Some(Box::new(FilesSessionState {
            session_files: std::mem::take(&mut self.session_files),
            session_regular_files: std::mem::take(&mut self.session_regular_files),
            dangling_candidates: std::mem::take(&mut self.dangling_candidates),
            bytecode_candidates: std::mem::take(&mut self.bytecode_candidates),
            bytecode_sources: std::mem::take(&mut self.bytecode_sources),
            owner_candidates: std::mem::take(&mut self.owner_candidates),
            declared_users: std::mem::take(&mut self.declared_users),
            declared_groups: std::mem::take(&mut self.declared_groups),
            nodep_candidates: std::mem::take(&mut self.nodep_candidates),
            pkg_deps: std::mem::take(&mut self.pkg_deps),
        }))
    }

    fn import_state(&mut self, state: Box<dyn std::any::Any + Send>) {
        if let Ok(state) = state.downcast::<FilesSessionState>() {
            self.session_files.extend(state.session_files);
            self.session_regular_files
                .extend(state.session_regular_files);
            self.dangling_candidates.extend(state.dangling_candidates);
            self.bytecode_candidates.extend(state.bytecode_candidates);
            self.bytecode_sources.extend(state.bytecode_sources);
            self.owner_candidates.extend(state.owner_candidates);
            for (source, names) in state.declared_users {
                self.declared_users.entry(source).or_default().extend(names);
            }
            for (source, names) in state.declared_groups {
                self.declared_groups
                    .entry(source)
                    .or_default()
                    .extend(names);
            }
            self.nodep_candidates.extend(state.nodep_candidates);
            for (name, deps) in state.pkg_deps {
                self.pkg_deps.entry(name).or_default().extend(deps);
            }
        }
    }
}

/// Cross-package `FilesCheck` state, exported per package and merged
/// before `after_checks` (`rpmlint#1595`): the session-aware
/// `dangling-relative-symlink` (issue #547), `non-standard-uid` /
/// `non-standard-gid` (issue #756) and `no-dependency-on`
/// (issue #862) decisions and the run-scoped
/// `python-bytecode-without-source` credit.
struct FilesSessionState {
    session_files: HashSet<String>,
    session_regular_files: HashSet<String>,
    dangling_candidates: Vec<DanglingCandidate>,
    bytecode_candidates: Vec<BytecodeCandidate>,
    bytecode_sources: HashSet<String>,
    owner_candidates: Vec<OwnerCandidate>,
    declared_users: HashMap<String, HashSet<String>>,
    declared_groups: HashMap<String, HashSet<String>>,
    nodep_candidates: Vec<NodepCandidate>,
    pkg_deps: HashMap<String, Vec<PkgDeps>>,
}

/// One `no-dependency-on` candidate from the perl/python base rules
/// (issue #862): a package shipping interpreter-tree files whose own
/// dependency lists carry no credited base dependency, held until
/// `after_checks` knows every package of the run.
struct NodepCandidate {
    name: String,
    arch: String,
    source: String,
    /// The finding's first detail: `perl-base` or `python-base`.
    base: &'static str,
    /// The finding's second detail: the interpreter version the
    /// package's files name.
    version: String,
    /// The names the package's `Requires`/`PreReq` name: the possible
    /// anchors.
    anchors: Vec<String>,
}

/// The key grouping binary packages built from one source: the
/// `SOURCERPM` header value. A package whose header carries none
/// groups by its own name, so it is only ever its own sibling and the
/// per-package behaviour is preserved.
fn source_key(pkg: &Pkg) -> String {
    match pkg.tag_str(librpm::Tag::SOURCERPM) {
        Some(srpm) if !srpm.is_empty() => srpm,
        _ => pkg.name.clone(),
    }
}

/// Whether `path` is a sysusers.d snippet: a `.conf` file whose parent
/// directory is named `sysusers.d` (`/usr/lib/sysusers.d/*.conf`,
/// `/etc/sysusers.d/*.conf`).
fn is_sysusers_snippet(path: &str) -> bool {
    path.ends_with(".conf")
        && path
            .rsplit('/')
            .nth(1)
            .is_some_and(|parent| parent == "sysusers.d")
}

/// The `(users, groups)` a sysusers.d snippet declares. A `u` line
/// declares its user and the like-named primary group (the group rpm's
/// sysusers generator provides for a `u` line); a `g` line declares its
/// group. `m` lines record membership and `r` lines id ranges: they
/// declare no account name. A `-` or purely numeric name field declares
/// by id, so it credits no name either.
fn sysusers_declared(text: &str) -> (HashSet<String>, HashSet<String>) {
    let mut users = HashSet::new();
    let mut groups = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (kind, name) = match (fields.next(), fields.next()) {
            (Some(kind), Some(name)) => (kind, name),
            _ => continue,
        };
        if name == "-" || name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        match kind {
            "u" => {
                users.insert(name.to_string());
                groups.insert(name.to_string());
            }
            "g" => {
                groups.insert(name.to_string());
            }
            _ => {}
        }
    }
    (users, groups)
}

/// The `(users, groups)` this package itself declares through the
/// sysusers.d snippets it ships -- the per-package counterpart of the
/// source-wide merge `note_declared_owners` performs for
/// `non-standard-uid` / `non-standard-gid`. Only snippets in this
/// package's own file list count: a sibling subpackage's snippet does
/// not install with this package, so it is no evidence about this
/// package's intent, and neither a `user()` / `group()` Requires nor
/// a Provides credits here -- the shipped snippet is the declaration.
fn own_sysusers_declared(pkg: &Pkg) -> (HashSet<String>, HashSet<String>) {
    let mut users = HashSet::new();
    let mut groups = HashSet::new();
    for f in &pkg.files {
        if is_sysusers_snippet(&f.name) {
            let (snippet_users, snippet_groups) = sysusers_declared(&pkg.read_file(&f.name));
            users.extend(snippet_users);
            groups.extend(snippet_groups);
        }
    }
    (users, groups)
}

/// Whether `pkg`'s own Requires -- plain, or the scriptlet-context
/// split into `prereq` (a packager-written `Requires(pre):
/// user(<name>)`) -- name the `user(<name>)` / `group(<name>)`
/// capability for `name`. This is the per-package Requires route of
/// the `non-standard-uid` / `non-standard-gid` crediting (issue
/// #756): only the file-owning package's own Requires count, never a
/// sibling's. Every leaf of each entry is matched (see
/// `leaf_account_capability`), so plain, versioned and rich-wrapped
/// capability spellings all credit. The account Requires rpm's
/// dependency generator derives from the package's own file ownership
/// are absent from both splits: the header loader drops them (see
/// `gather_requires` in `crate::pkg`), because an entry generated
/// from the ownership under decision declares nothing.
fn own_requires_account(pkg: &Pkg, group: bool, name: &str) -> bool {
    pkg.requires.iter().chain(pkg.prereq.iter()).any(|dep| {
        dep.leaves()
            .iter()
            .any(|leaf| leaf_account_capability(leaf) == Some((group, name)))
    })
}

/// The source package name a `SOURCERPM` value names: the value is
/// `<name>-<version>-<release>.src.rpm`, and only the name is stable
/// across the subpackages of one build. A value in any other shape is
/// returned whole, so it never equals a real package name by accident.
fn source_pkg_name(sourcerpm: &str) -> &str {
    let stem = sourcerpm.strip_suffix(".src.rpm").unwrap_or(sourcerpm);
    match stem.rsplit_once('-') {
        Some((rest, _release)) => match rest.rsplit_once('-') {
            Some((name, _version)) if !name.is_empty() => name,
            _ => stem,
        },
        None => stem,
    }
}

/// Whether a scriptlet slot can create a file when the package is
/// installed: the package's own transaction slots. Removal-time
/// slots (`%preun`, `%postun`), triggers and `%verifyscript` create
/// nothing at install, so a mention in one of them does not credit
/// a ghost -- the slot set the `ghost-files-without-postin` sibling
/// judges by.
fn ghost_credit_slot(label: &str) -> bool {
    matches!(label, "%pretrans" | "%pre" | "%post" | "%posttrans")
}

/// The concatenated scriptlet bodies of `pkg` for the
/// `ghost-file-with-buildroot-content` credit: the install-time
/// slots (see `ghost_credit_slot`). `tag_str_array` accepts both the
/// scalar and the trigger (parallel-array) shapes.
fn ghost_scriptlet_text(pkg: &Pkg) -> String {
    let mut text = String::new();
    for (tag, _prog, label) in crate::pkg::SCRIPT_TAGS {
        if !ghost_credit_slot(label) {
            continue;
        }
        for body in pkg.tag_str_array(*tag) {
            text.push_str(&body);
            text.push('\n');
        }
    }
    text
}

/// Whether `c` can be part of a path token. A scriptlet mention of
/// a path credits only at token boundaries: a suffixed lookalike
/// (`/etc/foo.conf.bak`) or a prefixed one (`/backup/etc/foo.conf`)
/// does not name the path.
fn is_path_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+' | '~')
}

/// Whether `text` names `path` literally at path-token boundaries
/// on both sides.
fn scriptlet_names_path(text: &str, path: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = text[from..].find(path) {
        let start = from + rel;
        let end = start + path.len();
        let before_ok = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_path_token_char(c));
        let after_ok = text[end..]
            .chars()
            .next()
            .is_none_or(|c| !is_path_token_char(c));
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Whether `text` appends the path tail `base` to a variable
/// expansion at a path-token boundary: `${dir}/ls-R` or `$dir/ls-R`
/// -- the directory is computed, the file is written for every
/// value. A literal directory ending in the same basename (another
/// file's path) does not credit.
fn scriptlet_appends_tail(text: &str, base: &str) -> bool {
    let needle = format!("/{base}");
    let mut from = 0;
    while let Some(rel) = text[from..].find(&needle) {
        let start = from + rel;
        let end = start + needle.len();
        let after_ok = text[end..]
            .chars()
            .next()
            .is_none_or(|c| !is_path_token_char(c));
        if after_ok {
            let before = &text[..start];
            // The braced form: the closing brace must close a `${`
            // expansion -- a bare `}` in the text credits nothing.
            if before.ends_with('}')
                && let Some(open) = before.rfind("${")
                && !before[open + 2..before.len() - 1].is_empty()
                && !before[open + 2..before.len() - 1].contains(['{', '}'])
            {
                return true;
            }
            // The unbraced form: the variable name runs back to
            // its `$` with nothing between it and the slash.
            if let Some(dollar) = before.rfind('$') {
                let var = &before[dollar + 1..];
                if !var.is_empty()
                    && var
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                    && var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    return true;
                }
            }
        }
        from = start + 1;
    }
    false
}

/// The firing predicate of `ghost-file-with-buildroot-content`
/// (issue #1017): a `%ghost` regular file whose header size is
/// positive, charged only when it carries the `%config` flag or sits
/// under /etc or /usr/etc, and silent when a scriptlet names the path
/// literally at path-token boundaries (the full path; macros are
/// expanded in the header), or appends the path tail to a variable
/// expansion at a path-token boundary (`${dir}/ls-R`, `$dir/ls-R`:
/// the directory is computed, the file is written for every value).
/// A scriptlet that embeds the path behind a variable prefix
/// (`$sysconfdir/xrdp/rsakeys.ini`) does not name the installed path
/// and does not credit: the package discards bytes it cannot prove
/// are recreated.
fn ghost_buildroot_content_fires(pkgfile: &PkgFile, scriptlet_text: &str) -> bool {
    if !pkgfile.is_ghost() || !is_reg(pkgfile.mode) {
        return false;
    }
    if pkgfile.size.unwrap_or(0) == 0 {
        return false;
    }
    let charged = pkgfile.is_config()
        || pkgfile.name.starts_with("/etc/")
        || pkgfile.name.starts_with("/usr/etc/");
    if !charged {
        return false;
    }
    if scriptlet_names_path(scriptlet_text, &pkgfile.name) {
        return false;
    }
    // A scriptlet that builds the path from a variable expansion --
    // `${dir}/ls-R` in texlive's %post, which regenerates the file for
    // every texmf tree -- names the path tail directly after the
    // expansion.
    let base = pkgfile.name.rsplit('/').next().unwrap_or(&pkgfile.name);
    !scriptlet_appends_tail(scriptlet_text, base)
}

/// A compiled cache whose source ships next to it: a `%ghost` named
/// `<path>.bin` where `<path>` itself is a non-ghost regular file in
/// the same package. The build compiled the cache from the shipped
/// source and install tooling rebuilds it from that source (the
/// SELinux `file_contexts.bin` next to `file_contexts`, rebuilt by
/// `semodule -B`), so the discarded bytes are a derived form of
/// content the package does ship.
fn compiled_cache_of_shipped_source(pkg: &Pkg, pkgfile: &PkgFile) -> bool {
    if !pkgfile.is_ghost() {
        return false;
    }
    let Some(stem) = pkgfile.name.strip_suffix(".bin") else {
        return false;
    };
    pkg.files
        .iter()
        .any(|f| f.name == stem && !f.is_ghost() && is_reg(f.mode))
}

/// Whether a non-executable file in a bin dir is dot-sourced by another
/// payload file in the same package: a helper library the package own
/// entry points source at runtime, not an entry point itself. The
/// sourcing line must start (after whitespace) with a dot or source
/// followed by whitespace, and the sourced path must be exactly the
/// candidate basename or end with /<basename>, so comments, strings
/// and execute forms (./name) do not credit.
fn sourced_by_sibling_script(pkg: &Pkg, fname: &str) -> bool {
    let Some(basename) = fname.rsplit("/").next() else {
        return false;
    };
    if basename.is_empty() {
        return false;
    }
    let suffix = format!("/{basename}");
    pkg.files.iter().any(|f| {
        if f.name == fname || f.is_ghost() || !is_reg(f.mode) {
            return false;
        }
        pkg.read_file(&f.name).lines().any(|line| {
            let trimmed = line.trim_start();
            let rest = if trimmed.starts_with("source")
                && trimmed[6..].starts_with(char::is_whitespace)
            {
                &trimmed[6..]
            } else if trimmed.starts_with(".") && trimmed[1..].starts_with(char::is_whitespace) {
                &trimmed[1..]
            } else {
                return false;
            };
            let rest = rest.trim();
            let rest = rest.trim_end_matches(|c: char| c as u32 == 34 || c as u32 == 39);
            rest == basename || rest.ends_with(&suffix)
        })
    })
}

/// Extensions of data files shipped in bin dirs by convention, each
/// grounded in corpus evidence: fpc compiler data (tdf, rsj, pt, ans),
/// ooRexx class libraries (cls, dtd, xsd, xsl), FIPS sidecars (hmac),
/// configs (conf, defs), a PowerShell script (ps1), and host-loaded
/// interpreter sources (lua, tcl).
fn is_bin_data_file(fname: &str) -> bool {
    let Some(basename) = fname.rsplit("/").next() else {
        return false;
    };
    let Some(ext) = basename.rsplit(".").next() else {
        return false;
    };
    if ext == basename {
        return false;
    }
    matches!(
        ext,
        "ans"
            | "cls"
            | "conf"
            | "defs"
            | "dtd"
            | "hmac"
            | "lua"
            | "ps1"
            | "pt"
            | "rsj"
            | "tcl"
            | "tdf"
            | "xsd"
            | "xsl"
    )
}

/// Whether the first line of a payload file is a shebang. An unreadable
/// file has no first line, so it counts as shebang-free.
fn file_has_shebang(pkg: &Pkg, fname: &str) -> bool {
    pkg.read_file(fname)
        .lines()
        .next()
        .is_some_and(|l| l.starts_with("#!"))
}

/// Whether the package belongs to the sysconfig/fillup mechanism itself:
/// a binary named `sysconfig` or `fillup`, or one built from that source
/// package (the shape of `sysconfig-netconfig`, whose source package is
/// `sysconfig`). The mechanism's own packages ship the payload, the
/// templates and the fillup calls by definition.
fn sysconfig_fillup_exempt(pkg_name: &str, sourcerpm: Option<&str>) -> bool {
    pkg_name == "sysconfig"
        || pkg_name == "fillup"
        || matches!(
            sourcerpm.map(source_pkg_name),
            Some("sysconfig") | Some("fillup")
        )
}

/// A `fillup` invocation at command position in a scriptlet: the shape
/// the `%fillup_only` / `%fillup_and_insserv` macros expand to in a built
/// package (e.g. `/bin/fillup -q /etc/sysconfig/<name> <template>`). The
/// anchors mirror the command-position convention of the scriptlet
/// matchers in `post.rs`, so a guard testing for the binary
/// (`[ -x /bin/fillup ]`) or a mention in prose does not count.
fn fillup_invocation_re() -> &'static Regex {
    static FILLUP_INVOCATION_RE: OnceLock<Regex> = OnceLock::new();
    FILLUP_INVOCATION_RE.get_or_init(|| {
        Regex::new(r"(?m)(^|[;`|]|&&|\$\()\s*(?:\S+/)?fillup(?:\s|$|[;|&])").expect("static regex")
    })
}

/// A literal `%fillup_only` / `%fillup_and_insserv` macro at command
/// position in a scriptlet. Built packages carry the expansion (the
/// invocation shape above), but a scriptlet that still spells the
/// macro -- an unexpanded build, or a build whose macro file did not
/// define it -- invokes fillup just the same.
fn fillup_macro_re() -> &'static Regex {
    static FILLUP_MACRO_RE: OnceLock<Regex> = OnceLock::new();
    FILLUP_MACRO_RE.get_or_init(|| {
        Regex::new(r"(?m)(^|[;`|]|&&|\$\()\s*%\{?fillup_(?:only|and_insserv)\}?(?:\s|$|[;|&])")
            .expect("static regex")
    })
}

/// Whether a scriptlet body invokes fillup: the expanded invocation
/// at command position, or the literal macro.
fn scriptlet_invokes_fillup(body: &str) -> bool {
    is_match(fillup_invocation_re(), body) || is_match(fillup_macro_re(), body)
}

/// The labels of the package's scriptlets that invoke fillup, in
/// `SCRIPT_TAGS` order, each label once.
fn fillup_call_labels(pkg: &Pkg) -> Vec<&str> {
    let mut labels: Vec<&str> = Vec::new();
    for (tag, _prog, label) in crate::pkg::SCRIPT_TAGS {
        let label = *label;
        if labels.contains(&label) {
            continue;
        }
        if pkg
            .tag_str_array(*tag)
            .iter()
            .any(|body| scriptlet_invokes_fillup(body))
        {
            labels.push(label);
        }
    }
    labels
}

/// The fillup templates a package ships: regular, non-`%ghost` files
/// below a `fillup-templates` directory. The bare directory itself is
/// not a template, and a `%ghost` entry ships no content to migrate.
fn fillup_template_paths(pkg: &Pkg) -> Vec<&str> {
    pkg.files
        .iter()
        .filter(|f| is_reg(f.mode) && !f.is_ghost())
        .map(|f| f.name.as_str())
        .filter(|path| {
            path.rsplit_once('/').is_some_and(|(parent, base)| {
                !base.is_empty() && parent.split('/').any(|c| c == "fillup-templates")
            })
        })
        .collect()
}

/// One whitespace-separated `EnvironmentFile` token cleaned to the
/// path it names and whether the reference is mandatory: surrounding
/// single or double quotes and the optional-file `-` prefix are
/// stripped (the `-` applies to the unquoted value, so the quote trim
/// runs again after the `-` strip).
fn env_file_token(token: &str) -> (&str, bool) {
    let unquoted = token.trim_matches(['"', '\'']);
    match unquoted.strip_prefix('-') {
        Some(rest) => (rest.trim_matches(['"', '\'']), false),
        None => (unquoted, true),
    }
}

/// The first `EnvironmentFile` target in a systemd unit that points into
/// `/etc/sysconfig/`, spelled as written (including the optional-file
/// `-` prefix), or `None`. A line names a whitespace-separated list of
/// paths, so every token counts, not only the first.
fn sysconfig_environment_file(content: &str) -> Option<String> {
    for line in content.lines() {
        let Some(rest) = line.trim_start().strip_prefix("EnvironmentFile") else {
            continue;
        };
        let Some(value) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        for token in value.split_whitespace() {
            let (target, mandatory) = env_file_token(token);
            if target.starts_with("/etc/sysconfig/") {
                // The witness is rebuilt from the cleaned target and
                // its mandatory flag: re-trimming the raw token keeps
                // a stray opening quote on a dashed quoted token,
                // whose leading `-` stops the trim.
                let witness = if mandatory {
                    target.to_string()
                } else {
                    format!("-{target}")
                };
                return Some(witness);
            }
        }
    }
    None
}

/// One `EnvironmentFile` target of a systemd unit that points into
/// `/etc/sysconfig/`: the path as written, without the optional-file
/// `-` prefix or surrounding quotes, and whether the reference is
/// mandatory (no `-`: the unit fails to start when the file is
/// absent).
struct SysconfigEnvTarget {
    path: String,
    mandatory: bool,
}

/// Every `EnvironmentFile` target in a systemd unit that points into
/// `/etc/sysconfig/`, in file order. `sysconfig_environment_file`
/// returns only the first target (the migration nudge needs one
/// witness); the fillup-template check gates on any
/// unit that reads the template's target, so every token of every
/// line counts.
fn sysconfig_environment_targets(content: &str) -> Vec<SysconfigEnvTarget> {
    let mut targets = Vec::new();
    for line in content.lines() {
        let Some(rest) = line.trim_start().strip_prefix("EnvironmentFile") else {
            continue;
        };
        let Some(value) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        for token in value.split_whitespace() {
            let (target, mandatory) = env_file_token(token);
            if target.starts_with("/etc/sysconfig/") {
                targets.push(SysconfigEnvTarget {
                    path: target.to_string(),
                    mandatory,
                });
            }
        }
    }
    targets
}

/// The name a shipped fillup template defines: the file sits directly
/// below a `fillup-templates` directory and is named
/// `sysconfig.<name>`; `<name>` is the file fillup would create below
/// `/etc/sysconfig/`.
fn fillup_template_name(path: &str) -> Option<&str> {
    let (parent, base) = path.rsplit_once('/')?;
    if parent != "fillup-templates" && !parent.ends_with("/fillup-templates") {
        return None;
    }
    base.strip_prefix("sysconfig.")
        .filter(|name| !name.is_empty())
}

/// Whether an `EnvironmentFile` target names the file fillup would
/// create from template `sysconfig.<name>`: `/etc/sysconfig/<name>`
/// itself, or one directory below it (the `%fillup_only -d <dir>`
/// form). Specifier and variable targets (`%i`, `$VAR`) never match:
/// they do not resolve to one file from the package alone. The
/// `%fillup_only -s` merge form does not match either: only exact
/// names count, because the split point of a merged target is
/// ambiguous.
fn env_target_names_template(target: &str, name: &str) -> bool {
    if target.contains(['%', '$']) {
        return false;
    }
    let Some(rest) = target.strip_prefix("/etc/sysconfig/") else {
        return false;
    };
    match rest.split_once('/') {
        None => rest == name,
        Some((_, leaf)) => leaf == name && !leaf.contains('/'),
    }
}

/// The paths tmpfiles.d snippet contents create or write as a file,
/// copy or symlink (the `f`, `F`, `w`, `C` and `L` line types,
/// trailing modifiers ignored). A sysconfig target a snippet creates at boot needs no
/// fillup call, so the fillup-template check exempts it. Comment and
/// blank lines are skipped; only the literal path column counts.
fn tmpfiles_created_paths(contents: &str) -> HashSet<&str> {
    let mut paths = HashSet::new();
    for line in contents.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(kind) = fields.next() else {
            continue;
        };
        let mut chars = kind.chars();
        if !matches!(chars.next(), Some('f' | 'F' | 'w' | 'C' | 'L'))
            || !chars.all(|c| matches!(c, '+' | '-' | '~' | '=' | '!'))
        {
            continue;
        }
        if let Some(path) = fields.next() {
            paths.insert(path);
        }
    }
    paths
}

/// One `fillup-template-without-fillup-call` report: the shipped
/// template the finding names, its rendered detail and its level.
struct FillupTemplateReport {
    template_path: String,
    detail: String,
    level: Level,
}

/// The templates `fillup-template-without-fillup-call` reports for
/// `pkg`, computed once for both the emitting check and the
/// `fillup-usage-discouraged` yield rule. The decision is per binary
/// package, from the package alone: every non-`%ghost` regular file
/// below a `fillup-templates` directory is a template; any `fillup`
/// invocation in any scriptlet (triggers included) credits the whole
/// package, because mapping a call to its own template is unreliable
/// (the macros' `PNAME=$1` expansions defeat it). A read gates the
/// template when an `EnvironmentFile` line of a unit below
/// `/systemd/system/` or `/systemd/user/` names the target
/// (`/etc/sysconfig/<name>`, or one directory below it for the
/// `%fillup_only -d` form), unless the package ships the target as a
/// non-`%ghost` payload file or a tmpfiles.d snippet creates it (an `f`,
/// `F`, `w`, `C` or `L` line). The level hangs on the read's form: an optional
/// `-` read is a Warning (the file is absent, runtime unchanged), a
/// mandatory read is an Error (the unit cannot start on a fresh
/// install -- the xsp shape).
fn fillup_template_without_call_reports(pkg: &Pkg) -> Vec<FillupTemplateReport> {
    let templates: Vec<(&str, &str)> = pkg
        .files
        .iter()
        .filter(|f| is_reg(f.mode) && !f.is_ghost())
        .filter_map(|f| fillup_template_name(&f.name).map(|name| (f.name.as_str(), name)))
        .collect();
    if templates.is_empty() {
        return Vec::new();
    }
    let calls_fillup = crate::pkg::SCRIPT_TAGS.iter().any(|(tag, _, _)| {
        pkg.tag_str_array(*tag)
            .iter()
            .any(|body| scriptlet_invokes_fillup(body))
    });
    if calls_fillup {
        return Vec::new();
    }
    let mut gates: Vec<(&str, SysconfigEnvTarget)> = Vec::new();
    let mut created: HashSet<String> = HashSet::new();
    for f in &pkg.files {
        if f.name.contains("/systemd/system/") || f.name.contains("/systemd/user/") {
            let content = pkg.read_file(&f.name);
            gates.extend(
                sysconfig_environment_targets(&content)
                    .into_iter()
                    .map(|target| (f.name.as_str(), target)),
            );
        }
        if f.name.contains("/tmpfiles.d/") && f.name.ends_with(".conf") {
            let content = pkg.read_file(&f.name);
            created.extend(
                tmpfiles_created_paths(&content)
                    .into_iter()
                    .map(str::to_string),
            );
        }
    }
    if gates.is_empty() {
        return Vec::new();
    }
    let mut reports = Vec::new();
    for (template_path, name) in &templates {
        let mut live: Vec<&(&str, SysconfigEnvTarget)> = gates
            .iter()
            .filter(|(_, target)| env_target_names_template(&target.path, name))
            .filter(|(_, target)| {
                !created.contains(&target.path)
                    && !pkg
                        .files
                        .iter()
                        .any(|f| f.name == target.path && !f.is_ghost() && is_reg(f.mode))
            })
            .collect();
        if live.is_empty() {
            continue;
        }
        // The representative read is a mandatory one when any
        // remains: that is the harm the level hangs on.
        live.sort_by_key(|(_, target)| !target.mandatory);
        let (unit, target) = live[0];
        let spelled = if target.mandatory {
            target.path.clone()
        } else {
            format!("-{}", target.path)
        };
        let detail = format!(
            "template {template_path} is never filled: unit {unit} sets \
             EnvironmentFile={spelled}, but no scriptlet calls fillup"
        );
        let level = if target.mandatory {
            Level::Error
        } else {
            Level::Warning
        };
        reports.push(FillupTemplateReport {
            template_path: template_path.to_string(),
            detail,
            level,
        });
    }
    reports
}

/// The sysconfig/fillup uses of one package, as one evidence phrase per
/// category, in category order. `scriptlets` pairs each scriptlet's
/// macro name with its body; `units` pairs each shipped unit file's name
/// with its contents. The payload category skips files matching the
/// `Good` patterns of the `filelist-forbidden-sysconfig` rule (see
/// `sysconfig_good_matches`).
fn sysconfig_fillup_uses(
    files: &[&str],
    scriptlets: &[(&str, &str)],
    units: &[(&str, &str)],
) -> Vec<String> {
    let mut uses = Vec::new();
    // A payload file the `filelist-forbidden-sysconfig` rule blesses
    // through its `Good` patterns is not a use: the distro's own rule
    // data permits those subtrees, so a migration nudge must not flag
    // them either. The remaining categories carry no such allowlist.
    if let Some(path) = files
        .iter()
        .find(|name| name.starts_with("/etc/sysconfig/") && !sysconfig_good_matches(name))
    {
        uses.push(format!("ships file {path}"));
    }
    if let Some(path) = files.iter().find(|name| {
        name.rsplit_once('/')
            .is_some_and(|(parent, _)| parent.split('/').any(|c| c == "fillup-templates"))
    }) {
        uses.push(format!("ships fillup template {path}"));
    }
    if let Some((label, _)) = scriptlets
        .iter()
        .find(|(_, body)| is_match(fillup_invocation_re(), body))
    {
        uses.push(format!("calls fillup from the {label} scriptlet"));
    }
    for (unit, content) in units {
        if let Some(target) = sysconfig_environment_file(content) {
            uses.push(format!("unit {unit} sets EnvironmentFile={target}"));
            break;
        }
    }
    uses
}

/// One relative symlink whose normalised target the emitting package
/// alone does not ship (issue #547).
struct DanglingCandidate {
    name: String,
    arch: String,
    fname: String,
    link: String,
    /// The normalised absolute target path.
    target: String,
    disposition: DanglingDisposition,
}

/// One `python-bytecode-without-source` candidate whose mapped
/// source ships only as a symlink whose chain leaves the package,
/// held until `after_checks` knows the run's file set and whether
/// the candidate's build is complete in the run.
struct BytecodeCandidate {
    name: String,
    arch: String,
    /// The bytecode file the finding names.
    fname: String,
    /// The absolute path the source symlink's chain resolves to
    /// outside the package.
    target: String,
    /// The candidate's build key (its `SOURCERPM` spelling); `None`
    /// when the package carries none -- such a candidate belongs to
    /// no build the run can judge and always fires.
    build_key: Option<String>,
}

/// One file whose owner sits outside the standard registry, held until
/// `after_checks` knows every name the run's packages declare through
/// the source-wide routes (issue #756).
struct OwnerCandidate {
    name: String,
    arch: String,
    source: String,
    fname: String,
    owner: String,
    /// `true` for the group decision (`non-standard-gid`), `false` for
    /// the user decision (`non-standard-uid`).
    group: bool,
    /// `true` when the file-owning package itself Requires the
    /// `user(<owner>)` / `group(<owner>)` capability, in plain or
    /// scriptlet-context (`prereq`) form, as written by the packager
    /// (the header loader drops the account Requires rpm's generator
    /// derives from file ownership). Requires crediting is
    /// per-package, unlike the sysusers-snippet and Provides routes,
    /// which credit the whole source set: a sibling's Requires does
    /// not create the account for a standalone install of the owning
    /// package, so it credits nothing here.
    own_requires: bool,
}

/// What an unresolved candidate emits, precomputed at record time from
/// the emitting package alone (the `DanglingSymlinkExceptions`
/// diversion depends only on it).
enum DanglingDisposition {
    /// `dangling-relative-symlink` for the link.
    Plain,
    /// `no-dependency-on` for the exception's package: the link matches
    /// a `DanglingSymlinkExceptions` entry the package does not Require.
    Divert(String),
    /// Nothing: the link matches a `DanglingSymlinkExceptions` entry
    /// whose package the emitting package Requires.
    Silent,
}

/// The nine Unicode bidirectional control characters behind trojan-source
/// (CVE-2021-42574), as UTF-8 byte triples with their codepoint names.
const BIDI_CONTROLS: [([u8; 3], &str); 9] = [
    ([0xE2, 0x80, 0xAA], "U+202A LEFT-TO-RIGHT EMBEDDING"),
    ([0xE2, 0x80, 0xAB], "U+202B RIGHT-TO-LEFT EMBEDDING"),
    ([0xE2, 0x80, 0xAC], "U+202C POP DIRECTIONAL FORMATTING"),
    ([0xE2, 0x80, 0xAD], "U+202D LEFT-TO-RIGHT OVERRIDE"),
    ([0xE2, 0x80, 0xAE], "U+202E RIGHT-TO-LEFT OVERRIDE"),
    ([0xE2, 0x81, 0xA6], "U+2066 LEFT-TO-RIGHT ISOLATE"),
    ([0xE2, 0x81, 0xA7], "U+2067 RIGHT-TO-LEFT ISOLATE"),
    ([0xE2, 0x81, 0xA8], "U+2068 FIRST STRONG ISOLATE"),
    ([0xE2, 0x81, 0xA9], "U+2069 POP DIRECTIONAL ISOLATE"),
];

/// Scan `path` in windows for the first bidi control character. Windows
/// overlap by 2 bytes (the longest control is 3 bytes) so a control split
/// across a boundary is still matched whole. Unreadable files are skipped
/// silently.
fn first_bidi_control_in_file(path: &Path) -> Option<&'static str> {
    const WINDOW: usize = 8192;
    const OVERLAP: usize = 2;
    let mut file = std::fs::File::open(path).ok()?;
    let mut window = vec![0u8; WINDOW + OVERLAP];
    let mut carry = 0usize;
    loop {
        let n = std::io::Read::read(&mut file, &mut window[carry..WINDOW + carry]).ok()?;
        if n == 0 {
            return None;
        }
        let len = carry + n;
        if let Some(found) = first_bidi_control(&window[..len]) {
            return Some(found);
        }
        carry = OVERLAP.min(len);
        window.copy_within(len - carry..len, 0);
    }
}

/// First bidi control in `bytes`, or `None`.
fn first_bidi_control(bytes: &[u8]) -> Option<&'static str> {
    let mut i = 0;
    while i + 3 <= bytes.len() {
        for (seq, name) in BIDI_CONTROLS {
            if bytes[i..i + 3] == seq {
                return Some(name);
            }
        }
        i += 1;
    }
    None
}

/// Whether `path` is one of the two debug trees itself or below it:
/// `/usr/lib/debug` or `/usr/src/debug`. Tree-prefix equality (not substring
/// or segment matching) keeps lookalikes like `/usr/lib64/debug` and
/// `/usr/share/debugfoo` quiet.
fn is_debug_path(path: &str) -> bool {
    path == "/usr/lib/debug"
        || path.starts_with("/usr/lib/debug/")
        || path == "/usr/src/debug"
        || path.starts_with("/usr/src/debug/")
}

/// Whether libmagic describes a file as text: `text` as a whole word of
/// the description, as in "ASCII text" or "UTF-8 Unicode text". A
/// substring test would also open the gate for binary formats whose
/// descriptions merely contain the letters -- the "texture" of
/// "Khronos KTX texture", a "context" record -- and their compressed
/// payloads then false-fire on coincidental control bytes (issue #533).
fn magic_is_text(magic: &str) -> bool {
    magic
        .split(|c: char| !c.is_alphanumeric())
        .any(|word| word.eq_ignore_ascii_case("text"))
}

fn strip_quotes(re: &Regex, s: &str) -> String {
    re.replace_all(s, "").to_string()
}

impl FilesCheck {
    /// One Warning per package that uses the legacy sysconfig/fillup
    /// configuration scheme, naming every use found: a payload file
    /// below `/etc/sysconfig/`, a template below a `fillup-templates/`
    /// directory, a `fillup` invocation in a scriptlet, or a shipped
    /// systemd unit whose `EnvironmentFile` points into
    /// `/etc/sysconfig/`. The mechanism's own packages are exempt (see
    /// `sysconfig_fillup_exempt`). Port-only as a finding: the
    /// reference's `filelist-forbidden-sysconfig` Error (ported in
    /// `FilelistCheck`) covers the Bad-pattern payloads, so this Warning
    /// double-emits with it there and adds the categories that Error
    /// does not cover. The `--explain` text proposes the migration,
    /// which is the point of the check.
    fn check_sysconfig_fillup_usage(&self, pkg: &Pkg, out: &mut Filter) {
        if sysconfig_fillup_exempt(&pkg.name, pkg.tag_str(librpm::Tag::SOURCERPM).as_deref()) {
            return;
        }
        let files: Vec<&str> = pkg.files.iter().map(|f| f.name.as_str()).collect();
        let mut scriptlets: Vec<(&str, String)> = Vec::new();
        // The canonical scriptlet list (rpmlint SCRIPT_TAGS): a tag
        // upstream adds is picked up here instead of drifting past a
        // hand-kept copy. `tag_str_array` accepts both the scalar and
        // the trigger (parallel-array) shapes.
        for (tag, _prog, label) in crate::pkg::SCRIPT_TAGS {
            for body in pkg.tag_str_array(*tag) {
                if !body.is_empty() {
                    scriptlets.push((label, body));
                }
            }
        }
        let scriptlet_refs: Vec<(&str, &str)> = scriptlets
            .iter()
            .map(|(label, body)| (*label, body.as_str()))
            .collect();
        let mut units: Vec<(&str, String)> = Vec::new();
        for f in &pkg.files {
            if f.name.contains("/systemd/system/") || f.name.contains("/systemd/user/") {
                let content = pkg.read_file(&f.name);
                if !content.is_empty() {
                    units.push((f.name.as_str(), content));
                }
            }
        }
        let unit_refs: Vec<(&str, &str)> = units
            .iter()
            .map(|(name, content)| (*name, content.as_str()))
            .collect();
        let uses = sysconfig_fillup_uses(&files, &scriptlet_refs, &unit_refs);
        if !uses.is_empty() {
            add_info(
                out,
                Level::Warning,
                pkg,
                "sysconfig-fillup-usage",
                &[&uses.join("; ")],
            );
        }
    }

    /// `ghost-file-with-buildroot-content` (issue #1017): a `%ghost`
    /// regular file with a positive header size had real bytes in the
    /// buildroot that the package silently discards. Only config-shaped
    /// ghosts are charged (the `%config` flag, or a path under /etc or
    /// /usr/etc), and an install-time scriptlet that names the path is
    /// credited with creating the file, so the charge is skipped then.
    fn check_ghost_buildroot_content(&self, pkg: &Pkg, out: &mut Filter) {
        let scriptlet_text = ghost_scriptlet_text(pkg);
        for pkgfile in &pkg.files {
            if compiled_cache_of_shipped_source(pkg, pkgfile) {
                continue;
            }
            if !ghost_buildroot_content_fires(pkgfile, &scriptlet_text) {
                continue;
            }
            let size = pkgfile.size.unwrap_or(0);
            add_info(
                out,
                Level::Warning,
                pkg,
                "ghost-file-with-buildroot-content",
                &[&pkgfile.name, &size.to_string()],
            );
        }
    }

    /// One finding per fillup template a package ships but never
    /// fills while a shipped unit reads the template's `/etc/sysconfig`
    /// target: the configuration file never appears on a
    /// fresh install, and new template variables are never merged into
    /// an existing file on update. Either fix clears it: restore the
    /// fillup call, or finish the migration by dropping the template
    /// and the `EnvironmentFile` line.
    ///
    /// The decision is per binary package, from the package alone:
    /// every non-`%ghost` regular file below a `fillup-templates`
    /// directory is a template; any `fillup` invocation in any
    /// scriptlet (triggers included) credits the whole package,
    /// because mapping a call to its own template is unreliable (the
    /// macros' `PNAME=$1` expansions defeat it). A read gates the
    /// template when an `EnvironmentFile` line of a unit below
    /// `/systemd/system/` or `/systemd/user/` names the target
    /// (`/etc/sysconfig/<name>`, or one directory below it for the
    /// `%fillup_only -d` form), unless the package ships the target as
    /// a non-`%ghost` payload file or a tmpfiles.d snippet creates it
    /// (`f`, `C` or `L` line). The level hangs on the read's form: an
    /// optional `-` read is a Warning (the file is absent, runtime
    /// unchanged), a mandatory read is an Error (the unit cannot
    /// start on a fresh install -- the xsp shape).
    fn check_fillup_template_without_call(&self, pkg: &Pkg, out: &mut Filter) {
        // The emission keeps both level literals next to the tag:
        // the severity inventory derives a tag's levels from the
        // literals at its emission sites.
        for report in fillup_template_without_call_reports(pkg) {
            if report.level == Level::Error {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "fillup-template-without-fillup-call",
                    &[&report.detail],
                );
            } else {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "fillup-template-without-fillup-call",
                    &[&report.detail],
                );
            }
        }
    }

    /// One Warning per package that uses fillup at all: it ships a
    /// fillup template, or a scriptlet invokes fillup (the expanded
    /// invocation at command position, or a literal `%fillup_only` /
    /// `%fillup_and_insserv` macro). Either fix direction clears it:
    /// finish the migration the staged description prescribes. The
    /// mechanism's own packages are exempt (see
    /// `sysconfig_fillup_exempt`): they provide fillup rather than
    /// consume it. A unit consuming the generated file through
    /// `EnvironmentFile` earns no exemption -- the two-layer
    /// `EnvironmentFile` pattern in the description is the migration
    /// answer there too.
    ///
    /// Yield rule: when the package's only fillup involvement is
    /// template(s) that `fillup-template-without-fillup-call`
    /// already reports, this tag stays silent for the package -- the
    /// defect report covers that involvement. Any further use (a
    /// template the defect check does not report, or any fillup
    /// call) fires this tag once.
    fn check_fillup_usage_discouraged(&self, pkg: &Pkg, out: &mut Filter) {
        if sysconfig_fillup_exempt(&pkg.name, pkg.tag_str(librpm::Tag::SOURCERPM).as_deref()) {
            return;
        }
        let templates = fillup_template_paths(pkg);
        let call_labels = fillup_call_labels(pkg);
        if templates.is_empty() && call_labels.is_empty() {
            return;
        }
        let mut evidence: Vec<String> = Vec::new();
        if call_labels.is_empty() {
            let reports = fillup_template_without_call_reports(pkg);
            let reported: HashSet<&str> = reports
                .iter()
                .map(|report| report.template_path.as_str())
                .collect();
            let Some(unreported) = templates.iter().find(|path| !reported.contains(**path)) else {
                return;
            };
            evidence.push(format!("ships fillup template {unreported}"));
        } else {
            if let Some(first) = templates.first() {
                evidence.push(format!("ships fillup template {first}"));
            }
            evidence.push(format!(
                "calls fillup from the {} scriptlet",
                call_labels[0]
            ));
        }
        add_info(
            out,
            Level::Warning,
            pkg,
            "fillup-usage-discouraged",
            &[&evidence.join("; ")],
        );
    }

    fn check_utf8(&self, pkg: &Pkg, out: &mut Filter) {
        use librpm::Tag;
        for name in pkg.tag_str_array(Tag::FILENAMES) {
            if !is_utf8(name.as_bytes()) {
                add_info(out, Level::Error, pkg, "filename-not-utf8", &[&name]);
            }
        }
    }

    /// Upstream rpmlint#776: scan text files for Unicode bidirectional
    /// control characters (trojan-source, CVE-2021-42574), which can make
    /// source code render differently from how it executes.
    ///
    /// Byte-level scan: the nine controls are matched as their 3-byte UTF-8
    /// sequences with no decoding, so surrounding non-UTF-8 bytes cannot
    /// hide them. A control stored in another encoding is a different byte
    /// sequence and is not detected (UTF-16's 2-byte units are not the UTF-8
    /// triples). Windows overlap by 2 bytes so a control split across a
    /// window boundary is still seen whole. One finding per file, naming the
    /// first control found. Only libmagic-described text files are scanned,
    /// per the issue's scope.
    fn check_bidi_controls(&self, pkg: &Pkg, out: &mut Filter) {
        for pkgfile in &pkg.files {
            if !is_reg(pkgfile.mode) {
                continue;
            }
            if !magic_is_text(&pkgfile.magic) {
                continue;
            }
            let path = Path::new(&pkgfile.path);
            if !path.is_file() {
                continue;
            }
            if let Some(found) = first_bidi_control_in_file(path) {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "bidi-control-character",
                    &[&pkgfile.name, found],
                );
            }
        }
    }

    fn check_meta_package(&self, pkg: &Pkg, _st: &PkgState, out: &mut Filter) {
        if !pkg.files.is_empty() && is_match(&self.meta_package_re, &pkg.name) {
            add_info(out, Level::Warning, pkg, "file-in-meta-package", &[]);
        }
    }

    fn check_empty_debuginfo(&self, pkg: &Pkg, st: &PkgState, out: &mut Filter) {
        if pkg.files.is_empty() && (st.debuginfo_package || st.debugsource_package) {
            add_info(out, Level::Error, pkg, "empty-debuginfo-package", &[]);
        }
    }

    fn check_debuginfo_without_sources(&self, pkg: &Pkg, st: &PkgState, out: &mut Filter) {
        if !self.use_debugsource
            && st.debuginfo_package
            && st.debuginfo_debugs
            && !st.debuginfo_srcs
        {
            add_info(out, Level::Error, pkg, "debuginfo-without-sources", &[]);
        }
    }

    /// Upstream rpmlint#11: a `%{_libdir}` glob in `%files` also matches
    /// `%{_libdir}/debug`, landing debug files in a non-debug package.
    fn check_debug_files_in_non_debug_package(&self, pkg: &Pkg, st: &PkgState, out: &mut Filter) {
        if st.debuginfo_package || st.debugsource_package {
            return;
        }
        for f in &pkg.files {
            // A %ghost entry has no payload on disk: nothing debug lands
            // in the package.
            if pkg.ghost_files.iter().any(|g| g == &f.name) {
                continue;
            }
            if is_debug_path(&f.name) {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "debug-files-in-non-debug-package",
                    &[f.name.as_str()],
                );
            }
        }
    }

    fn check_bindir_exes(&self, pkg: &Pkg, st: &PkgState, out: &mut Filter) {
        for (exe, paths) in &st.bindir_exes {
            if paths.len() > 1 {
                // Rendered as a Python list repr, matching the reference
                // passing `paths` (a list) through filter.py's f-string.
                let list_repr = format!(
                    "[{}]",
                    paths
                        .iter()
                        .map(|p| python_str_repr(p))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "duplicate-executable",
                    &[exe, &list_repr],
                );
            }
            if !st.man_basenames.contains(exe)
                && !self.documented_alias(exe, paths, st)
                && !self.version_affix_documented(exe, st)
            {
                add_info(out, Level::Info, pkg, "no-manual-page-for-binary", &[exe]);
            }
        }
    }

    /// A bindir name with no man page of its own is still documented
    /// when it is the same binary as a documented one: a symlink whose
    /// resolved in-package target carries a man page under the target's
    /// name, or a hardlink to a regular file whose name carries one.
    /// The reference credits neither shape (FilesCheck.py:559-564
    /// consults only its man_basenames set); the divergence is
    /// ledgered. Resolution stops at the package boundary: a link
    /// whose target the package does not ship earns no credit.
    fn documented_alias(&self, exe: &str, paths: &[String], st: &PkgState) -> bool {
        // Hardlink identity for the regular executable paths.
        for path in paths {
            if let Some(key) = st.bindir_inodes.get(path) {
                if let Some(names) = st.inode_basenames.get(key) {
                    if names
                        .iter()
                        .any(|n| n != exe && st.man_basenames.contains(n))
                    {
                        return true;
                    }
                }
            }
        }
        // Symlink chains starting at a bindir link with this name
        // (bindir symlinks register with an empty `paths` list).
        if let Some(lpaths) = st.bindir_links.get(exe) {
            for lpath in lpaths {
                if let Some(target) = self.resolve_shipped_target(st, lpath) {
                    let base = target.rsplit('/').next().unwrap_or(&target);
                    if st.man_basenames.contains(base) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// A bindir name is documented under a version-affixed twin name:
    /// the package ships the man page for `<exe>-<version>` (the
    /// flavour-suffixed pages parallel-installable toolchains ship,
    /// e.g. the Python singlespec `abimap-3.13.1`), or the binary is
    /// itself the version-suffixed name of a documented tool
    /// (`luajit-2.1.1756211046` for `luajit`). The separator sets are
    /// exact per side: the man-page side credits only the dash form
    /// above; the binary side credits a tail preceded by `-`, by `.`
    /// or by no separator (see `strip_version_tail`). A version tail
    /// is at least two dot-separated numeric components, so
    /// single-suffix names (`ps2ps2`, `gio-querymodules-64`) keep
    /// firing. The reference credits neither shape
    /// (FilesCheck.py:559-564 consults only its man_basenames set);
    /// the divergence is ledgered.
    fn version_affix_documented(&self, exe: &str, st: &PkgState) -> bool {
        if st.man_version_bases.contains(exe) {
            return true;
        }
        if let Some(base) = strip_version_tail(exe) {
            if st.man_basenames.contains(base) {
                return true;
            }
        }
        false
    }

    /// Follow the symlink chain starting at `start` through the
    /// package's own files; the final non-link shipped path, or `None`
    /// when the chain leaves the package, loops, or runs past 40
    /// hops -- a loop or an overlong chain earns no credit, so the
    /// name keeps firing (ledgered). Intermediate links are judged
    /// only on being shipped; only the final target's basename is
    /// judged against the man page set.
    fn resolve_shipped_target(&self, st: &PkgState, start: &str) -> Option<String> {
        let mut cur = start.to_string();
        let mut visited = std::collections::HashSet::new();
        for _ in 0..40 {
            if !visited.insert(cur.clone()) {
                return None;
            }
            let linkto = st.link_targets.get(&cur)?;
            let target = if linkto.starts_with('/') {
                crate::pkg::normalize_path(linkto)
            } else {
                let parent = Path::new(&cur)
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                // A root-level link's parent is `/`: joining with a
                // second slash would spell a `//` path no shipped
                // path equals.
                let joined = if parent == "/" {
                    format!("/{linkto}")
                } else {
                    format!("{parent}/{linkto}")
                };
                crate::pkg::normalize_path(&joined)
            };
            if !st.shipped_paths.contains(&target) {
                return None;
            }
            if !st.link_targets.contains_key(&target) {
                return Some(target);
            }
            cur = target;
        }
        None
    }

    /// Whether an anchor requirement credits `cand` (issue #862):
    /// one of the candidate's `Requires`/`PreReq` names, other than
    /// its own name, belongs to a package of the run built from the
    /// candidate's source whose own lists carry the candidate's base
    /// dependency. The sibling's credit is judged by the same
    /// own-package predicate, so the anchor is exactly one hop.
    fn anchor_credits(&self, cand: &NodepCandidate) -> bool {
        cand.anchors.iter().any(|anchor| {
            anchor != &cand.name
                && self.pkg_deps.get(anchor).is_some_and(|pkgs| {
                    pkgs.iter().any(|sib| {
                        sib.source == cand.source
                            && base_credited(&sib.lists(), cand.base, &cand.version)
                    })
                })
        })
    }

    /// Credit the user and group names this package declares through
    /// the source-wide routes, under the package's source key, for the
    /// `after_checks` `non-standard-uid` / `non-standard-gid` decision
    /// (issue #756): the sysusers.d snippets a package ships and its
    /// `user()` / `group()` Provides. The Requires route is credited
    /// separately and per file-owning package (see
    /// `own_requires_account`): a sibling's Requires does not create
    /// the account for a standalone install of the owning package, so
    /// Requires capabilities are not merged in here. The header
    /// Provides are the declaration, hand-written or generated alike
    /// (rpm's sysusers generator emits the same entries for a package
    /// shipping a snippet); every leaf of each entry is matched (see
    /// `leaf_account_capability`), so plain, versioned and
    /// rich-wrapped capability spellings all credit.
    fn note_declared_owners(&mut self, pkg: &Pkg) {
        let source = source_key(pkg);
        let mut users = HashSet::new();
        let mut groups = HashSet::new();
        for f in &pkg.files {
            if is_sysusers_snippet(&f.name) {
                let (snippet_users, snippet_groups) = sysusers_declared(&pkg.read_file(&f.name));
                users.extend(snippet_users);
                groups.extend(snippet_groups);
            }
        }
        // Provides only: Requires and the scriptlet-context `prereq`
        // split credit the file-owning package alone, never the whole
        // source set, so they are recorded per candidate instead (see
        // `own_requires_account`).
        for dep in &pkg.provides {
            for leaf in dep.leaves() {
                if let Some((group, name)) = leaf_account_capability(&leaf) {
                    if group {
                        groups.insert(name.to_string());
                    } else {
                        users.insert(name.to_string());
                    }
                }
            }
        }
        if !users.is_empty() {
            self.declared_users
                .entry(source.clone())
                .or_default()
                .extend(users);
        }
        if !groups.is_empty() {
            self.declared_groups
                .entry(source)
                .or_default()
                .extend(groups);
        }
    }

    fn check_file(
        &mut self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        st: &mut PkgState,
        out: &mut Filter,
    ) {
        st.shipped_paths.insert(fname.to_string());
        if is_reg(pkgfile.mode) && pkgfile.inode != 0 {
            let base = fname.rsplit('/').next().unwrap_or(fname);
            st.inode_basenames
                .entry((pkgfile.rdev, pkgfile.inode))
                .or_default()
                .push(base.to_string());
        }
        self.check_file_manpage(pkg, fname, pkgfile, st, out);
        self.check_file_class(pkg, fname, pkgfile, out);
        self.check_file_infopage_compressed(pkg, fname, out);
        self.check_file_unexpanded_macro(pkg, fname, out);
        self.check_file_non_standard_uid(pkg, fname, pkgfile);
        self.check_file_non_standard_gid(pkg, fname, pkgfile);
        self.check_file_kernel_modules(pkg, fname, &st.is_kernel_package, out);
        self.check_file_dir_or_file(pkg, fname, pkgfile, out);
        self.check_file_non_ghost_in_run(pkg, fname, pkg, out);
        self.check_file_mimeinfo_cache(pkg, fname, pkgfile, out);
        self.check_file_systemd_unit_in_etc(pkg, fname, out);
        self.check_file_systemd_preset(pkg, fname, pkgfile, out);
        self.check_file_udev_rule_in_etc(pkg, fname, out);
        self.check_file_udev_rules(pkg, fname, pkgfile, out);
        self.check_file_tmpfiles_conf_in_etc(pkg, fname, out);
        self.check_file_subdir_in_bin(pkg, fname, out);
        self.check_file_siteperl_in_perl_module(pkg, fname, pkgfile, out);
        self.check_file_backup_file_in_package(pkg, fname, out);
        self.check_file_version_control_internal_file(pkg, fname, out);
        self.check_file_htaccess_file(pkg, fname, pkgfile, out);
        self.check_file_hidden_file_or_dir(pkg, fname, out);
        self.check_file_manifest_in_perl_module(pkg, fname, out);
        self.check_file_info_dir_file(pkg, fname, out);
        self.check_file_makefile_junk(pkg, fname, out);
        self.check_file_logrotate(pkg, fname, out);
        self.check_file_crontab(pkg, fname, pkgfile, out);
        self.check_file_compressed_symlink(pkg, fname, pkgfile, out);
        self.check_file_normal_file(pkg, fname, pkgfile, st, out);
        self.check_file_dir(pkg, fname, pkgfile, out);
        self.check_file_link(pkg, fname, pkgfile, st, out);
        self.check_file_crond(pkg, fname, pkgfile, out);
        self.check_file_zero_perms(pkg, fname, pkgfile, out);
    }
}

fn is_utf8(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok()
}

/// Read at most the given limit of bytes from the reader; the source is
/// never asked for more than that in total.
fn read_prefix(reader: impl std::io::Read, limit: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    reader.take(limit).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Kept in sync with the filesystem package, mirroring the reference's
/// `STANDARD_DIRS`.
const STANDARD_DIRS: &[&str] = &[
    "/",
    "/bin",
    "/boot",
    "/etc",
    "/etc/X11",
    "/etc/opt",
    "/etc/profile.d",
    "/etc/skel",
    "/etc/xinetd.d",
    "/home",
    "/lib",
    "/lib/modules",
    "/lib64",
    "/media",
    "/mnt",
    "/mnt/cdrom",
    "/mnt/disk",
    "/mnt/floppy",
    "/opt",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/selinux",
    "/srv",
    "/sys",
    "/tmp",
    "/usr",
    "/usr/X11R6",
    "/usr/X11R6/bin",
    "/usr/X11R6/doc",
    "/usr/X11R6/include",
    "/usr/X11R6/lib",
    "/usr/X11R6/lib64",
    "/usr/X11R6/man",
    "/usr/X11R6/man/man1",
    "/usr/X11R6/man/man2",
    "/usr/X11R6/man/man3",
    "/usr/X11R6/man/man4",
    "/usr/X11R6/man/man5",
    "/usr/X11R6/man/man6",
    "/usr/X11R6/man/man7",
    "/usr/X11R6/man/man8",
    "/usr/X11R6/man/man9",
    "/usr/X11R6/man/mann",
    "/usr/bin",
    "/usr/bin/X11",
    "/usr/etc",
    "/usr/games",
    "/usr/include",
    "/usr/lib",
    "/usr/lib/X11",
    "/usr/lib/games",
    "/usr/lib/gcc-lib",
    "/usr/lib/menu",
    "/usr/lib64",
    "/usr/lib64/gcc-lib",
    "/usr/local",
    "/usr/local/bin",
    "/usr/local/doc",
    "/usr/local/etc",
    "/usr/local/games",
    "/usr/local/info",
    "/usr/local/lib",
    "/usr/local/lib64",
    "/usr/local/man",
    "/usr/local/man/man1",
    "/usr/local/man/man2",
    "/usr/local/man/man3",
    "/usr/local/man/man4",
    "/usr/local/man/man5",
    "/usr/local/man/man6",
    "/usr/local/man/man7",
    "/usr/local/man/man8",
    "/usr/local/man/man9",
    "/usr/local/man/mann",
    "/usr/local/sbin",
    "/usr/local/share",
    "/usr/local/share/man",
    "/usr/local/share/man/man1",
    "/usr/local/share/man/man2",
    "/usr/local/share/man/man3",
    "/usr/local/share/man/man4",
    "/usr/local/share/man/man5",
    "/usr/local/share/man/man6",
    "/usr/local/share/man/man7",
    "/usr/local/share/man/man8",
    "/usr/local/share/man/man9",
    "/usr/local/share/man/mann",
    "/usr/local/src",
    "/usr/sbin",
    "/usr/share",
    "/usr/share/dict",
    "/usr/share/doc",
    "/usr/share/icons",
    "/usr/share/info",
    "/usr/share/man",
    "/usr/share/man/man1",
    "/usr/share/man/man2",
    "/usr/share/man/man3",
    "/usr/share/man/man4",
    "/usr/share/man/man5",
    "/usr/share/man/man6",
    "/usr/share/man/man7",
    "/usr/share/man/man8",
    "/usr/share/man/man9",
    "/usr/share/man/mann",
    "/usr/share/misc",
    "/usr/src",
    "/usr/tmp",
    "/var",
    "/var/cache",
    "/var/db",
    "/var/lib",
    "/var/lib/games",
    "/var/lib/misc",
    "/var/lib/rpm",
    "/var/local",
    "/var/log",
    "/var/mail",
    "/var/nis",
    "/var/opt",
    "/var/preserve",
    "/var/spool",
    "/var/tmp",
];

/// Packages allowed to own standard directories: `filesystem` itself
/// and `filesystem-media`, openSUSE's designated split owner of /media.
/// The reference exempts only `filesystem`; see the FilesCheck
/// divergence ledger.
const FILESYS_PACKAGES: &[&str] = &["filesystem", "filesystem-media"];

/// Scan window for the whole-file incorrect-fsf-address scan: the file is
/// streamed in windows of this size so peak memory stays bounded no matter
/// how large the file is.
const FSF_SCAN_WINDOW: usize = 8192;
/// Overlap between consecutive FSF scan windows. Any match of at most this
/// many bytes straddling a window boundary is still seen whole inside one
/// window; the FSF patterns only match fixed license/address phrases of tens
/// of bytes joined by short whitespace runs, so this is ample headroom.
const FSF_SCAN_OVERLAP: usize = 1024;

/// Per-normal-file scratch state, mirroring the reference's `_file_*`
/// attributes.
/// One license identifier in canonical comparison form (issue #1033):
/// the deprecated combined `-with-` spelling is cut at the exception,
/// a trailing `+` is folded into the suffix, and the remaining stem is
/// split into family and trailing version where it carries one.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LicenseId {
    /// Canonical comparison key: lowercase stem plus suffix marker.
    key: String,
    /// The stem minus a trailing version, or the whole stem.
    family: String,
    /// The stem's trailing version, when it carries one.
    version: Option<Vec<u32>>,
    /// The `-only` / `-or-later` suffix after `+`-form normalisation.
    suffix: LicenseSuffix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LicenseSuffix {
    None,
    Only,
    OrLater,
}

/// Split a lowercase stem at its last `-` when the tail is a dotted
/// version (`2.1` in `lgpl-2.1`); otherwise the stem is its own family.
fn license_family_version(stem: &str) -> (String, Option<Vec<u32>>) {
    if let Some(pos) = stem.rfind('-') {
        let tail = &stem[pos + 1..];
        if !tail.is_empty()
            && tail.chars().all(|c| c.is_ascii_digit() || c == '.')
            && tail.chars().any(|c| c.is_ascii_digit())
            && !tail.starts_with('.')
            && !tail.ends_with('.')
        {
            let version: Vec<u32> = tail.split('.').map(|p| p.parse().unwrap_or(0)).collect();
            return (stem[..pos].to_string(), Some(version));
        }
    }
    (stem.to_string(), None)
}

/// The canonical keys of the `ValidLicenses` list. An entry that is
/// itself an expression (`GPL-2.0-only OR GPL-3.0-only`) contributes
/// its leaf keys: canonicalising the whole string would produce one
/// key no declared identifier can ever equal.
fn valid_license_keys(entries: &[String]) -> HashSet<String> {
    let mut keys = HashSet::new();
    for entry in entries {
        match parse_license_expr(entry) {
            Some(expr) => {
                let mut leaves = Vec::new();
                collect_license_leaves(&expr, &mut leaves);
                for leaf in leaves {
                    keys.insert(canonical_license_id(&leaf).key);
                }
            }
            None => {
                keys.insert(canonical_license_id(entry).key);
            }
        }
    }
    keys
}

fn canonical_license_id(raw: &str) -> LicenseId {
    let mut s = raw.trim().to_lowercase();
    // The deprecated combined spelling (`GPL-2.0-with-classpath-exception`)
    // names the license before `-with-`; the exception is ignored, as for
    // the `WITH` operator.
    if let Some(pos) = s.find("-with-") {
        s.truncate(pos);
    }
    let mut plus = false;
    if let Some(stripped) = s.strip_suffix('+') {
        s = stripped.to_string();
        plus = true;
    }
    let (stem, mut suffix) = if let Some(stem) = s.strip_suffix("-or-later") {
        (stem.to_string(), LicenseSuffix::OrLater)
    } else if let Some(stem) = s.strip_suffix("-only") {
        (stem.to_string(), LicenseSuffix::Only)
    } else {
        (s, LicenseSuffix::None)
    };
    if plus && suffix == LicenseSuffix::None {
        suffix = LicenseSuffix::OrLater;
    }
    let key = match suffix {
        LicenseSuffix::None => stem.clone(),
        LicenseSuffix::Only => format!("{stem}-only"),
        LicenseSuffix::OrLater => format!("{stem}-or-later"),
    };
    let (family, version) = license_family_version(&stem);
    LicenseId {
        key,
        family,
        version,
        suffix,
    }
}

/// Lexicographic version comparison with zero padding (`2.0` == `2.0.0`).
fn license_version_cmp(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            std::cmp::Ordering::Equal => {}
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Whether the tag's identifier set covers the declared identifier
/// (issue #1033): exact canonical equality, or the same family where an
/// `-or-later` declaration is met by any tag version at or above it, a
/// declaration is met by a tag `-or-later` range whose floor it
/// reaches, any other declaration by the same version in any suffix
/// form, and a version-less declaration by a version-less tag entry.
fn license_id_covered(declared: &LicenseId, tag_ids: &[LicenseId]) -> bool {
    tag_ids.iter().any(|t| {
        if t.key == declared.key {
            return true;
        }
        if t.family != declared.family {
            return false;
        }
        // A version-less pair in one family covers: `MIT+` declares
        // MIT in its or-later form, and a bare `MIT` tag names the
        // same license.
        if declared.version.is_none() && t.version.is_none() {
            return true;
        }
        let (Some(dv), Some(tv)) = (&declared.version, &t.version) else {
            return false;
        };
        // A declaration and a tag that both range upward from a
        // floor always overlap: each names every version from its
        // own floor up, so the ranges share every version at or
        // above the higher floor, whichever floor is lower.
        if declared.suffix == LicenseSuffix::OrLater && t.suffix == LicenseSuffix::OrLater {
            return true;
        }
        match declared.suffix {
            LicenseSuffix::OrLater => license_version_cmp(tv, dv) != std::cmp::Ordering::Less,
            // The tag's own or-later range covers a declaration at
            // or above the range's floor version.
            _ if t.suffix == LicenseSuffix::OrLater => {
                license_version_cmp(dv, tv) != std::cmp::Ordering::Less
            }
            _ => license_version_cmp(tv, dv) == std::cmp::Ordering::Equal,
        }
    })
}

/// A parsed license expression: the subset of SPDX expression syntax
/// the coverage tags evaluate (`AND` / `OR` / `WITH`, parentheses).
#[derive(Debug, Clone, PartialEq)]
enum LicenseExpr {
    Leaf(String),
    And(Vec<LicenseExpr>),
    Or(Vec<LicenseExpr>),
}

fn license_expr_tokens(text: &str) -> Vec<String> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    for c in text.chars() {
        if c == '(' || c == ')' {
            if !cur.is_empty() {
                toks.push(std::mem::take(&mut cur));
            }
            toks.push(c.to_string());
        } else if c.is_whitespace() {
            if !cur.is_empty() {
                toks.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        toks.push(cur);
    }
    toks
}

struct LicenseExprParser {
    toks: Vec<String>,
    pos: usize,
}

impl LicenseExprParser {
    fn peek(&self) -> Option<&str> {
        self.toks.get(self.pos).map(String::as_str)
    }

    fn advance(&mut self) -> Option<String> {
        let tok = self.toks.get(self.pos).cloned();
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    fn parse_or(&mut self) -> Option<LicenseExpr> {
        let mut arms = vec![self.parse_and()?];
        while self.peek().is_some_and(|t| t.eq_ignore_ascii_case("or")) {
            self.pos += 1;
            arms.push(self.parse_and()?);
        }
        Some(if arms.len() == 1 {
            arms.pop().unwrap()
        } else {
            LicenseExpr::Or(arms)
        })
    }

    fn parse_and(&mut self) -> Option<LicenseExpr> {
        let mut arms = vec![self.parse_atom()?];
        while self.peek().is_some_and(|t| t.eq_ignore_ascii_case("and")) {
            self.pos += 1;
            arms.push(self.parse_atom()?);
        }
        Some(if arms.len() == 1 {
            arms.pop().unwrap()
        } else {
            LicenseExpr::And(arms)
        })
    }

    fn parse_atom(&mut self) -> Option<LicenseExpr> {
        match self.advance()? {
            t if t == "(" => {
                let inner = self.parse_or()?;
                if self.advance().as_deref() == Some(")") {
                    Some(inner)
                } else {
                    None
                }
            }
            t if t == ")" => None,
            t if t.eq_ignore_ascii_case("and")
                || t.eq_ignore_ascii_case("or")
                || t.eq_ignore_ascii_case("with") =>
            {
                None
            }
            t => {
                // `WITH <exception>`: the exception is ignored.
                if self.peek().is_some_and(|x| x.eq_ignore_ascii_case("with")) {
                    self.pos += 1;
                    self.advance()?;
                }
                Some(LicenseExpr::Leaf(t))
            }
        }
    }
}

/// Parse a license expression; `None` on any structural defect, in
/// which case the declaration is not read at all.
fn parse_license_expr(text: &str) -> Option<LicenseExpr> {
    let toks = license_expr_tokens(text);
    if toks.is_empty() {
        return None;
    }
    let mut parser = LicenseExprParser { toks, pos: 0 };
    let expr = parser.parse_or()?;
    if parser.pos != parser.toks.len() {
        return None;
    }
    Some(expr)
}

fn collect_license_leaves(expr: &LicenseExpr, out: &mut Vec<String>) {
    match expr {
        LicenseExpr::Leaf(raw) => out.push(raw.clone()),
        LicenseExpr::And(arms) | LicenseExpr::Or(arms) => {
            for arm in arms {
                collect_license_leaves(arm, out);
            }
        }
    }
}

/// The parsed identifier set of a package `License` tag. An
/// unparsable tag falls back to bare token splitting so its plain
/// identifiers still credit coverage.
fn parse_license_tag(tag: &str) -> Vec<LicenseId> {
    let mut raws = Vec::new();
    if let Some(expr) = parse_license_expr(tag) {
        collect_license_leaves(&expr, &mut raws);
    } else {
        let mut skip_exception = false;
        for tok in license_expr_tokens(tag) {
            if skip_exception {
                skip_exception = false;
                continue;
            }
            if tok.eq_ignore_ascii_case("with") {
                skip_exception = true;
                continue;
            }
            if tok == "("
                || tok == ")"
                || tok.eq_ignore_ascii_case("and")
                || tok.eq_ignore_ascii_case("or")
            {
                continue;
            }
            raws.push(tok);
        }
    }
    raws.iter().map(|r| canonical_license_id(r)).collect()
}

fn render_license_expr(expr: &LicenseExpr) -> String {
    match expr {
        LicenseExpr::Leaf(raw) => raw.clone(),
        LicenseExpr::And(arms) => arms
            .iter()
            .map(render_license_expr)
            .collect::<Vec<_>>()
            .join(" AND "),
        LicenseExpr::Or(arms) => arms
            .iter()
            .map(render_license_expr)
            .collect::<Vec<_>>()
            .join(" OR "),
    }
}

/// Whether one declared leaf is satisfied by the tag: an identifier
/// absent from the openSUSE license list counts as satisfied, so
/// `LicenseRef-…` and unlisted ids never fire.
fn license_leaf_satisfied(raw: &str, tag_ids: &[LicenseId], valid_keys: &HashSet<String>) -> bool {
    let id = canonical_license_id(raw);
    !valid_keys.contains(&id.key) || license_id_covered(&id, tag_ids)
}

fn license_expr_satisfied(
    expr: &LicenseExpr,
    tag_ids: &[LicenseId],
    valid_keys: &HashSet<String>,
) -> bool {
    match expr {
        LicenseExpr::Leaf(raw) => license_leaf_satisfied(raw, tag_ids, valid_keys),
        LicenseExpr::And(arms) => arms
            .iter()
            .all(|a| license_expr_satisfied(a, tag_ids, valid_keys)),
        LicenseExpr::Or(arms) => arms
            .iter()
            .any(|a| license_expr_satisfied(a, tag_ids, valid_keys)),
    }
}

/// The declaration units one finding is emitted per: the top-level
/// `AND` conjuncts, where a leaf is its own unit and an `OR` group is
/// one unit (satisfied when any arm is satisfied).
enum LicenseUnit {
    Leaf(String),
    OrGroup(Vec<LicenseExpr>),
}

fn collect_license_units(expr: &LicenseExpr, units: &mut Vec<LicenseUnit>) {
    match expr {
        LicenseExpr::And(arms) => {
            for arm in arms {
                collect_license_units(arm, units);
            }
        }
        LicenseExpr::Or(arms) => units.push(LicenseUnit::OrGroup(arms.clone())),
        LicenseExpr::Leaf(raw) => units.push(LicenseUnit::Leaf(raw.clone())),
    }
}

/// The unsatisfied units of one parsed SPDX declaration, as
/// (display, aggregation key) pairs.
fn unsatisfied_spdx_units(
    expr: &LicenseExpr,
    tag_ids: &[LicenseId],
    valid_keys: &HashSet<String>,
) -> Vec<(String, String)> {
    let mut units = Vec::new();
    collect_license_units(expr, &mut units);
    let mut out = Vec::new();
    for unit in units {
        match &unit {
            LicenseUnit::Leaf(raw) => {
                if !license_leaf_satisfied(raw, tag_ids, valid_keys) {
                    out.push((raw.clone(), canonical_license_id(raw).key));
                }
            }
            LicenseUnit::OrGroup(arms) => {
                if !arms
                    .iter()
                    .any(|a| license_expr_satisfied(a, tag_ids, valid_keys))
                {
                    let display = arms
                        .iter()
                        .map(render_license_expr)
                        .collect::<Vec<_>>()
                        .join(" OR ");
                    // The aggregation key is order-free: the same
                    // group declared in another arm order is one
                    // finding, not two. The display keeps the
                    // declaration order.
                    let mut key_arms: Vec<String> = arms.iter().map(render_license_expr).collect();
                    key_arms.sort();
                    let key = format!("or:{}", key_arms.join(" OR ").to_lowercase());
                    out.push((display, key));
                }
            }
        }
    }
    out
}

/// The `SPDX-License-Identifier:` declarations of a peek window, one
/// expression per line. Trailing comment decoration is stripped
/// (`*/`, `-->`, LLVM's `*|`).
fn spdx_expressions_in_window(text: &str) -> Vec<LicenseExpr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(pos) = line.find("SPDX-License-Identifier:") else {
            continue;
        };
        let mut rest = &line[pos + "SPDX-License-Identifier:".len()..];
        loop {
            let trimmed = rest.trim();
            match ["*/", "-->", "*|"]
                .iter()
                .find_map(|d| trimmed.strip_suffix(d))
            {
                Some(stripped) => rest = stripped,
                None => {
                    rest = trimmed;
                    break;
                }
            }
        }
        if rest.is_empty() {
            continue;
        }
        if let Some(expr) = parse_license_expr(rest) {
            out.push(expr);
        }
    }
    out
}

/// The normalisation the grant grammar reads (issue #1033): each line
/// loses one comment leader (`#`, `//`, `/*`, `*`, `;`, `--`, `dnl`,
/// `%`, `!`, `"`, `REM`) and whitespace collapses to single spaces.
fn normalize_grant_text(text: &str) -> String {
    let mut joined = String::new();
    for line in text.lines() {
        let mut l = line.trim_start();
        let mut stripped = false;
        for leader in ["/*", "//", "--", "#", "*", ";", "%", "!", "\""] {
            if let Some(rest) = l.strip_prefix(leader) {
                l = rest;
                stripped = true;
                break;
            }
        }
        if !stripped {
            // `dnl` is m4's comment word and case-sensitive; batch's
            // `REM` is not -- a lowercase `rem` leader strips too.
            if let Some(rest) = l.strip_prefix("dnl")
                && (rest.is_empty() || rest.starts_with([' ', '\t']))
            {
                l = rest;
            } else if let Some(head) = l.get(..3)
                && head.eq_ignore_ascii_case("REM")
                && (l.len() == 3 || matches!(l.as_bytes()[3], b' ' | b'\t'))
            {
                l = &l[3..];
            }
        }
        joined.push(' ');
        joined.push_str(l);
    }
    joined.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Scan a grant version (`N` or `N.M`) at the start of `s`.
fn scan_grant_version(s: &str) -> Option<(String, &str)> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    if i < bytes.len() && bytes[i] == b'.' {
        let mut j = i + 1;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j > i + 1 {
            i = j;
        }
    }
    // A further dot-digit component makes the scanned version a
    // three-component one -- a file or product version, not a
    // license version: `2.0.1` must not scan as `2.0` with a `.1`
    // tail left for the grant's tail table to consume.
    if i < bytes.len() && bytes[i] == b'.' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
        return None;
    }
    Some((s[..i].to_string(), &s[i..]))
}

fn gnu_family_prefix(rest: &str) -> (&'static str, &str) {
    if let Some(r) = rest.strip_prefix("Lesser ") {
        ("LGPL", r)
    } else if let Some(r) = rest.strip_prefix("Library ") {
        ("LGPL", r)
    } else if let Some(r) = rest.strip_prefix("Affero ") {
        ("AGPL", r)
    } else {
        ("GPL", rest)
    }
}

/// The (display, canonical id) of a GNU-family grant: an integer
/// version `N` maps to `N.0`.
fn grant_license_id(family: &str, version: &str, or_later: bool) -> (String, LicenseId) {
    let v = if version.contains('.') {
        version.to_string()
    } else {
        format!("{version}.0")
    };
    let display = format!(
        "{family}-{v}-{}",
        if or_later { "or-later" } else { "only" }
    );
    let id = canonical_license_id(&display);
    (display, id)
}

/// Grant form A, read at the text right after `terms of the GNU `:
/// `[Lesser |Library |Affero ]General Public License[ as published by
/// the Free Software Foundation][;|,] either version N[ of the
/// License]`, then exactly `[,] or (at your option) any later version`
/// plus `.`/`;` for `-or-later`, or directly `.`/`;` for `-only`. Any
/// other tail is unknown and reads as no grant.
fn gnu_grant_a(rest: &str) -> Option<(String, LicenseId)> {
    let (family, rest) = gnu_family_prefix(rest);
    let rest = rest.strip_prefix("General Public License")?;
    let rest = rest
        .strip_prefix(" as published by the Free Software Foundation")
        .unwrap_or(rest);
    let rest = match rest.chars().next() {
        Some(';' | '|' | ',') => &rest[1..],
        _ => rest,
    };
    let rest = rest.strip_prefix(" either version ")?;
    let (version, rest) = scan_grant_version(rest)?;
    let rest = rest.strip_prefix(" of the License").unwrap_or(rest);
    for (tail, or_later) in [
        (", or (at your option) any later version.", true),
        (", or (at your option) any later version;", true),
        (" or (at your option) any later version.", true),
        (" or (at your option) any later version;", true),
        (".", false),
        (";", false),
    ] {
        if rest.starts_with(tail) {
            return Some(grant_license_id(family, &version, or_later));
        }
    }
    None
}

/// Grant form B, read at an occurrence of `General Public License`
/// (its index in `t`): `[GNU ][Lesser |Library |Affero ]General Public
/// License[,] version N[,] as published by the Free Software
/// Foundation.`, which gives `-only`.
fn gnu_grant_b(t: &str, at: usize) -> Option<(String, LicenseId)> {
    let before = &t[..at];
    let family = if before.ends_with("GNU Lesser ") || before.ends_with("GNU Library ") {
        "LGPL"
    } else if before.ends_with("GNU Affero ") {
        "AGPL"
    } else if before.ends_with("GNU ") {
        "GPL"
    } else {
        return None;
    };
    let rest = &t[at + "General Public License".len()..];
    let rest = rest.strip_prefix(',').unwrap_or(rest);
    let rest = rest.strip_prefix(' ').unwrap_or(rest);
    let rest = rest.strip_prefix("version ")?;
    let (version, rest) = scan_grant_version(rest)?;
    let rest = rest.strip_prefix(',').unwrap_or(rest);
    let rest = rest.strip_prefix(' ').unwrap_or(rest);
    let rest = rest.strip_prefix("as published by the Free Software Foundation")?;
    rest.strip_prefix('.')?;
    Some(grant_license_id(family, &version, false))
}

fn push_grant(out: &mut Vec<(String, LicenseId)>, grant: (String, LicenseId)) {
    if !out.iter().any(|(_, id)| id.key == grant.1.key) {
        out.push(grant);
    }
}

/// The license grants of a peek window (issue #1033): the exact GNU
/// forms and the Apache / Mozilla / WTFPL grant strings, read over the
/// normalised text. A window containing `special exception` or
/// `Alternatively` is skipped whole: those grants cannot be read
/// plainly.
fn license_grants_in_window(text: &str) -> Vec<(String, LicenseId)> {
    let t = normalize_grant_text(text);
    // The skip test is the one case-folded read of the window:
    // headers capitalise freely (`Special Exception`, `ALTERNATIVELY`)
    // while the grant grammar below matches its forms exactly.
    let folded = t.to_lowercase();
    if folded.contains("special exception") || folded.contains("alternatively") {
        return Vec::new();
    }
    let mut out: Vec<(String, LicenseId)> = Vec::new();
    let mut from = 0;
    while let Some(rel) = t[from..].find("terms of the GNU ") {
        let start = from + rel + "terms of the GNU ".len();
        if let Some(grant) = gnu_grant_a(&t[start..]) {
            push_grant(&mut out, grant);
        }
        from = start;
    }
    let mut from = 0;
    while let Some(rel) = t[from..].find("General Public License") {
        let at = from + rel;
        if let Some(grant) = gnu_grant_b(&t, at) {
            push_grant(&mut out, grant);
        }
        from = at + 1;
    }
    if t.contains("Licensed under the Apache License, Version 2.0 (the \"License\")") {
        push_grant(
            &mut out,
            ("Apache-2.0".to_string(), canonical_license_id("Apache-2.0")),
        );
    }
    if t.contains(
        "This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0",
    ) {
        push_grant(
            &mut out,
            ("MPL-2.0".to_string(), canonical_license_id("MPL-2.0")),
        );
    }
    if t.contains("Do What The Fuck You Want To Public License, Version 2") {
        push_grant(
            &mut out,
            ("WTFPL".to_string(), canonical_license_id("WTFPL")),
        );
    }
    out
}

/// Which of the two coverage tags a declaration unit belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LicenseUnitKind {
    Spdx,
    Grant,
}

impl LicenseUnitKind {
    fn tag_name(self) -> &'static str {
        match self {
            LicenseUnitKind::Spdx => "spdx-license-not-in-license-tag",
            LicenseUnitKind::Grant => "license-grant-not-in-license-tag",
        }
    }
}

/// The unsatisfied declaration units of one file's peek window, as
/// (kind, display, aggregation key) triples, deduplicated per file.
/// An SPDX declaration is the file's machine-readable license, so a
/// file carrying one is not also read for grants.
fn license_units_in_window(
    text: &str,
    tag_ids: &[LicenseId],
    valid_keys: &HashSet<String>,
) -> Vec<(LicenseUnitKind, String, String)> {
    let exprs = spdx_expressions_in_window(text);
    // A window carrying the marker declares its license even when
    // the expression after the marker does not parse: it must not
    // fall through to grant detection, which is scoped to files
    // without a declaration.
    let has_marker = text.contains("SPDX-License-Identifier:");
    if !exprs.is_empty() || has_marker {
        let mut out: Vec<(LicenseUnitKind, String, String)> = Vec::new();
        for expr in &exprs {
            for (display, key) in unsatisfied_spdx_units(expr, tag_ids, valid_keys) {
                if !out.iter().any(|(_, _, k)| *k == key) {
                    out.push((LicenseUnitKind::Spdx, display, key));
                }
            }
        }
        return out;
    }
    license_grants_in_window(text)
        .into_iter()
        .filter(|(_, id)| valid_keys.contains(&id.key) && !license_id_covered(id, tag_ids))
        .map(|(display, id)| (LicenseUnitKind::Grant, display, id.key))
        .collect()
}

/// One aggregated unsatisfied declaration of a package (issue #1033):
/// the first file declaring it and how many files declare it.
struct LicenseUnitAgg {
    kind: LicenseUnitKind,
    display: String,
    first_path: String,
    count: usize,
}

#[derive(Default)]
struct FileData {
    chunk: Vec<u8>,
    istext: bool,
    interpreter: Option<String>,
    interpreter_args: String,
    nonexec_file: bool,
    is_buildconfig: bool,
}

/// Bytes the reference's `peek` treats as printable when deciding
/// text-vs-binary.
fn is_peek_printable(b: u8) -> bool {
    matches!(b, b'\n' | b'\r' | b'\t' | 0x0c | 0x08) || b >= 32
}

/// The standard library directories ldconfig always scans (issue #569).
const STANDARD_LIBDIRS: [&str; 6] = [
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/lib",
    "/usr/local/lib64",
];

/// Collect the directories the `/etc/ld.so.conf.d/*.conf` snippets
/// shipped in `pkg` register with ldconfig (issue #569).
fn ldconfig_conf_dirs(pkg: &Pkg) -> std::collections::HashSet<String> {
    let mut dirs = std::collections::HashSet::new();
    for f in &pkg.files {
        let Some(rest) = f.name.strip_prefix("/etc/ld.so.conf.d/") else {
            continue;
        };
        if rest.contains('/') || !rest.ends_with(".conf") {
            continue;
        }
        parse_ldso_conf(&pkg.read_file(&f.name), &mut dirs);
    }
    dirs
}

/// Record the directory entries of one ld.so.conf-format text in `dirs`:
/// one directory per line; `#` comments and `include` directives name
/// none, and relative entries can never name a library's parent.
pub(crate) fn parse_ldso_conf(content: &str, dirs: &mut std::collections::HashSet<String>) {
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with("include") || !line.starts_with('/') {
            continue;
        }
        let dir = line.trim_end_matches('/');
        dirs.insert(if dir.is_empty() { "/" } else { dir }.to_string());
    }
}

impl FilesCheck {
    /// Read up to 2048 bytes and decide text-vs-binary, mirroring the
    /// reference's `peek` (including its `read-error` on `OSError`).
    fn peek(&self, pkg: &Pkg, pkgfile: &PkgFile, out: &mut Filter) -> (Vec<u8>, bool) {
        let chunk = match std::fs::File::open(&pkgfile.path).and_then(|f| read_prefix(f, 2048)) {
            Ok(c) => c,
            Err(e) => {
                add_info(out, Level::Warning, pkg, "read-error", &[&e.to_string()]);
                return (Vec::new(), false);
            }
        };
        if chunk.contains(&0) {
            return (chunk, false);
        }
        if chunk.is_empty() {
            return (chunk, true);
        }
        let lower = pkgfile.path.to_lowercase();
        if lower.ends_with(".pdf") && chunk.starts_with(b"%PDF-") {
            return (chunk, false);
        }
        if lower.ends_with(".ri") && lower.contains("/ri/") {
            return (chunk, false);
        }
        if lower.ends_with(".inv") && chunk.starts_with(b"# Sphinx inventory") {
            return (chunk, false);
        }
        let control = chunk.iter().filter(|b| !is_peek_printable(**b)).count();
        let istext = control as f64 / chunk.len() as f64 <= 0.30;
        (chunk, istext)
    }

    /// Scan the whole file for the FSF license and wrong-address patterns in
    /// bounded windows.
    ///
    /// Upstream rpmlint#40: the reference searches only its 2048-byte peek
    /// chunk, so a stale FSF address past byte 2048 goes unreported. The port
    /// scans the whole file instead (divergences.toml), but streams it in
    /// `FSF_SCAN_WINDOW`-byte windows: each window is lossy-decoded and
    /// regex-scanned on its own, so peak memory is one window plus overlap
    /// regardless of file size -- the file is never materialized whole, let
    /// alone twice via a lossy UTF-8 copy.
    ///
    /// Consecutive windows overlap by `FSF_SCAN_OVERLAP` bytes, so a match
    /// straddling a window boundary is still found whole inside one window.
    /// A file that cannot be opened, or a read that fails mid-scan, reports
    /// `read-error` through the same plumbing `peek` uses, and the check is
    /// skipped loudly rather than on an empty buffer.
    ///
    /// Returns true when both patterns match anywhere in the file, mirroring
    /// the reference's boolean `search() and search()`: one finding per file,
    /// never per match.
    fn fsf_address_matches(&self, pkg: &Pkg, pkgfile: &PkgFile, out: &mut Filter) -> bool {
        let mut file = match std::fs::File::open(&pkgfile.path) {
            Ok(f) => f,
            Err(e) => {
                add_info(out, Level::Warning, pkg, "read-error", &[&e.to_string()]);
                return false;
            }
        };
        // One window plus the overlap carried over from the previous window.
        let mut window = vec![0u8; FSF_SCAN_WINDOW + FSF_SCAN_OVERLAP];
        let mut carry = 0usize;
        let mut found_license = false;
        let mut found_address = false;
        // The ZIP alternative is adjudicated one window behind the
        // read loop: an occurrence is classified by its neighbouring
        // bytes, and the byte after a window's last byte is only known
        // once the next window (or EOF) arrives. `prev` holds the
        // window awaiting that adjudication and `prev_left` the byte
        // just before it in the file.
        let mut prev: Option<(Vec<u8>, Option<u8>)> = None;
        loop {
            let n =
                match std::io::Read::read(&mut file, &mut window[carry..FSF_SCAN_WINDOW + carry]) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        add_info(out, Level::Warning, pkg, "read-error", &[&e.to_string()]);
                        return false;
                    }
                };
            let len = carry + n;
            let text = String::from_utf8_lossy(&window[..len]);
            if !found_license && is_match(&self.fsf_license_re, text.as_ref()) {
                found_license = true;
            }
            if !found_address && is_match(&self.fsf_wrong_address_re, text.as_ref()) {
                found_address = true;
            }
            if !found_address && let Some((pbuf, pleft)) = &prev {
                // The byte just after the previous window's content is
                // the first freshly read byte of this window.
                if fsf_zip_in_window(pbuf, *pleft, Some(window[carry])) {
                    found_address = true;
                }
            }
            if found_license && found_address {
                return true;
            }
            // The byte just before this window in the file: for the
            // first window there is none; later windows start with the
            // previous window's carried tail, so it is the byte just
            // before that tail in the previous window.
            let left_edge = match &prev {
                None => None,
                Some((pbuf, pleft)) => {
                    if carry > 0 && pbuf.len() > carry {
                        Some(pbuf[pbuf.len() - carry - 1])
                    } else {
                        *pleft
                    }
                }
            };
            prev = Some((window[..len].to_vec(), left_edge));
            carry = len.min(FSF_SCAN_OVERLAP);
            window.copy_within(len - carry..len, 0);
        }
        if !found_address && let Some((pbuf, pleft)) = &prev {
            if fsf_zip_in_window(pbuf, *pleft, None) {
                found_address = true;
            }
        }
        found_license && found_address
    }

    /// The license-coverage scan of one regular file (issue #1033):
    /// read the peek window of a text file that is not itself marked
    /// `%license` and does not live under `/usr/src/`, and aggregate
    /// its unsatisfied license declarations into the package state.
    /// The findings are emitted once per package by
    /// `check_license_coverage`.
    fn check_normal_license_coverage(
        &self,
        fname: &str,
        pkgfile: &PkgFile,
        st: &mut PkgState,
        fd: &FileData,
    ) {
        if !fd.istext || st.license_tag_ids.is_empty() {
            return;
        }
        if pkgfile.flags & pkgfile::RPMFILE_LICENSE != 0 {
            return;
        }
        if fname.starts_with("/usr/src/") {
            return;
        }
        let text = String::from_utf8_lossy(&fd.chunk);
        for (kind, display, key) in
            license_units_in_window(&text, &st.license_tag_ids, &self.valid_license_keys)
        {
            let agg_key = format!("{}:{key}", kind.tag_name());
            match st.license_units.get_mut(&agg_key) {
                Some(agg) => agg.count += 1,
                None => {
                    st.license_units.insert(
                        agg_key,
                        LicenseUnitAgg {
                            kind,
                            display,
                            first_path: fname.to_string(),
                            count: 1,
                        },
                    );
                }
            }
        }
    }

    /// Emit the license-coverage findings of one package (issue
    /// #1033): one finding per unsatisfied declared license, with the
    /// license, the first file declaring it and the file count as
    /// detail.
    fn check_license_coverage(&self, pkg: &Pkg, st: &PkgState, out: &mut Filter) {
        for agg in st.license_units.values() {
            let count = agg.count.to_string();
            match agg.kind {
                LicenseUnitKind::Spdx => add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "spdx-license-not-in-license-tag",
                    &[&agg.display, &agg.first_path, &count],
                ),
                LicenseUnitKind::Grant => add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "license-grant-not-in-license-tag",
                    &[&agg.display, &agg.first_path, &count],
                ),
            }
        }
    }
}

/// The reference's `script_interpreter`: a `#!` line at the very start of
/// the chunk, decoded lossy like `byte_to_string`.
fn script_interpreter(chunk: &[u8]) -> (Option<String>, String) {
    if !chunk.starts_with(b"#!") {
        return (None, String::new());
    }
    let mut rest = &chunk[2..];
    while let Some((&b, tail)) = rest.split_first() {
        if matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | 0x0b) {
            rest = tail;
        } else {
            break;
        }
    }
    let end = rest
        .iter()
        .position(|&b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | 0x0b))
        .unwrap_or(rest.len());
    let interpreter = String::from_utf8_lossy(&rest[..end]).into_owned();
    if interpreter.is_empty() {
        return (None, String::new());
    }
    let line_end = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
    let args = String::from_utf8_lossy(&rest[end..line_end])
        .trim()
        .to_string();
    (Some(interpreter), args)
}

/// The dependency lists the `no-dependency-on` base-dependency rules
/// read: the tested package's own, or a session sibling's snapshot.
struct DepLists<'a> {
    requires: &'a [DepInfo],
    prereq: &'a [DepInfo],
    recommends: &'a [DepInfo],
    suggests: &'a [DepInfo],
}

impl<'a> DepLists<'a> {
    fn of_pkg(pkg: &'a Pkg) -> Self {
        Self {
            requires: &pkg.requires,
            prereq: &pkg.prereq,
            recommends: &pkg.recommends,
            suggests: &pkg.suggests,
        }
    }

    /// The `Requires`/`PreReq` union the versioned and path forms read.
    fn hard(&self) -> impl Iterator<Item = &DepInfo> {
        self.requires.iter().chain(self.prereq)
    }
}

/// One package's dependency lists, snapshotted into the session state
/// when the package is checked, so `after_checks` can judge whether a
/// sibling carries a base dependency (issue #862).
#[derive(Clone)]
struct PkgDeps {
    source: String,
    requires: Vec<DepInfo>,
    prereq: Vec<DepInfo>,
    recommends: Vec<DepInfo>,
    suggests: Vec<DepInfo>,
}

impl PkgDeps {
    fn snapshot(pkg: &Pkg) -> Self {
        Self {
            source: source_key(pkg),
            requires: pkg.requires.clone(),
            prereq: pkg.prereq.clone(),
            recommends: pkg.recommends.clone(),
            suggests: pkg.suggests.clone(),
        }
    }

    fn lists(&self) -> DepLists<'_> {
        DepLists {
            requires: &self.requires,
            prereq: &self.prereq,
            recommends: &self.recommends,
            suggests: &self.suggests,
        }
    }
}

/// rpmlint's `check_versioned_dep`: a `Requires`/`PreReq` on `name` (with an
/// optional `(arch-bits)` suffix) pinned with `=` to `version`.
fn versioned_dep_in(lists: &DepLists, name: &str, version: &str) -> bool {
    const RPMSENSE_EQUAL: u32 = 8;
    for d in lists.hard() {
        if !dep_name_matches(&d.name, name) {
            continue;
        }
        if d.flags & RPMSENSE_EQUAL != RPMSENSE_EQUAL {
            return false;
        }
        if d.version.as_deref() != Some(version) {
            return false;
        }
        return true;
    }
    false
}

/// Whether the lists carry the perl base dependency for `vers`: the
/// `=`-pinned `perl-base` / `perl` names and the
/// `perl(:MODULE_COMPAT_<vers>)` token the reference credits, plus the
/// interpreter expressed as the unversioned `/usr/bin/perl` path or
/// the `libperl` soname (issue #862) — the forms a linked perl module
/// or a perl consumer carries.
fn perl_base_credited(lists: &DepLists, vers: &str) -> bool {
    if versioned_dep_in(lists, "perl-base", vers) || versioned_dep_in(lists, "perl", vers) {
        return true;
    }
    let compat = format!("perl(:MODULE_COMPAT_{vers})");
    if lists
        .requires
        .iter()
        .chain(lists.recommends)
        .chain(lists.suggests)
        .any(|d| d.name == compat)
    {
        return true;
    }
    lists
        .hard()
        .any(|d| d.name == "/usr/bin/perl" || d.name.starts_with("libperl.so"))
}

/// Whether `name` is a flavour base package name: `python3`
/// followed by one or more digits and `-base` - `python313-base`,
/// `python314-base` - carrying the optional `(arch-bits)` qualifier
/// of the `dep_name_matches` shape. Nothing else is the form: a
/// longer suffix (`python313-base-devel`), a letter in the digit run
/// (`python31a-base`) or the bare `python3-base` (credited on its own
/// arm) does not match.
fn is_flavour_base_name(name: &str) -> bool {
    let stem = match name.split_once('(') {
        Some((head, rest)) => {
            let Some(inner) = rest.strip_suffix(')') else {
                return false;
            };
            let Some((arch, bits)) = inner.split_once('-') else {
                return false;
            };
            if arch.is_empty()
                || !arch.chars().all(|c| c.is_alphanumeric() || c == '_')
                || bits.is_empty()
                || !bits.chars().all(|c| c.is_ascii_digit())
            {
                return false;
            }
            head
        }
        None => name,
    };
    let Some(digits) = stem
        .strip_prefix("python3")
        .and_then(|rest| rest.strip_suffix("-base"))
    else {
        return false;
    };
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

/// Whether the lists carry the python base dependency for `ver`: the
/// `=`-pinned `python` / `python-base` / `python(abi)` names the
/// reference credits, the SUSE base name `python3-base` in any
/// relation and the versioned interpreter path `/usr/bin/python<ver>`
/// (issue #568), plus the interpreter expressed as the unversioned
/// `/usr/bin/python3` path or the `libpython<ver>` soname (issue
/// #862), plus the flavour base name `python3<digits>-base` in any
/// relation - the base package of
/// one specific flavour, which for a non-primary flavour is the
/// only spelling of that base.
fn python_base_credited(lists: &DepLists, ver: &str) -> bool {
    let interpreter = format!("/usr/bin/python{ver}");
    let soname = format!("libpython{ver}.so");
    if lists.hard().any(|d| {
        dep_name_matches(&d.name, "python3-base")
            || is_flavour_base_name(&d.name)
            || d.name == interpreter
            || d.name == "/usr/bin/python3"
            || d.name.starts_with(&soname)
    }) {
        return true;
    }
    ["python", "python-base", "python(abi)"]
        .iter()
        .any(|dep| versioned_dep_in(lists, dep, ver))
}

/// Whether the lists carry the base dependency a `no-dependency-on`
/// candidate names.
fn base_credited(lists: &DepLists, base: &str, version: &str) -> bool {
    if base == "perl-base" {
        perl_base_credited(lists, version)
    } else {
        python_base_credited(lists, version)
    }
}

/// The names a package's `Requires`/`PreReq` name: a
/// `no-dependency-on` candidate's possible anchors (issue #862).
fn anchor_names(pkg: &Pkg) -> Vec<String> {
    pkg.requires
        .iter()
        .chain(&pkg.prereq)
        .map(|d| d.name.clone())
        .collect()
}

/// The reference's `^name(\(\w+-\d+\))?$` name match (e.g. `perl-base`,
/// `perl-base(x86-64)`).
fn dep_name_matches(dep: &str, name: &str) -> bool {
    if dep == name {
        return true;
    }
    let Some(inner) = dep
        .strip_prefix(name)
        .and_then(|s| s.strip_prefix('('))
        .and_then(|s| s.strip_suffix(')'))
    else {
        return false;
    };
    let Some((arch, bits)) = inner.split_once('-') else {
        return false;
    };
    !arch.is_empty()
        && arch.chars().all(|c| c.is_alphanumeric() || c == '_')
        && !bits.is_empty()
        && bits.chars().all(|c| c.is_ascii_digit())
}

impl FilesCheck {
    /// The probed decompressor for `fname`'s extension, if any.
    fn decompressor_for(&self, fname: &str) -> Option<&Tool> {
        let lower = fname.to_lowercase();
        let name = if lower.ends_with(".gz") || lower.ends_with(".z") {
            "gzip"
        } else if lower.ends_with(".bz2") {
            "bzip2"
        } else if lower.ends_with(".xz") || lower.ends_with(".lzma") {
            "xz"
        } else if lower.ends_with(".zst") {
            "zstd"
        } else {
            return None;
        };
        self.decompressors.iter().find(|t| t.name() == name)
    }

    /// The decompressed bytes of `path` through `fname`'s decompressor.
    /// A complete output up to `MANPAGE_TEXT_LIMIT` is cached
    /// per path on this instance when the caller passes `cache_result`
    /// (the man-page consumer). `None` — no decompressor for the
    /// suffix, an absent or failing decompressor, or an output past the
    /// limit — is cached as well; callers then apply their own read for
    /// those cases (streaming validation, a capped prefix) exactly as
    /// when no cache entry exists.
    fn decompressed_bytes(&self, fname: &str, path: &str, cache_result: bool) -> Option<Arc<[u8]>> {
        if let Some(hit) = self.decompressed_cache.borrow().get(path) {
            return hit.clone();
        }
        let result = self.decompressor_for(fname).and_then(|tool| {
            let mut cmd = tool.command()?;
            cmd.arg("-dc")
                .arg(path)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null());
            let mut child = cmd.spawn().ok()?;
            let bytes = child
                .stdout
                .take()
                .and_then(|s| read_prefix(s, MANPAGE_TEXT_LIMIT + 1).ok());
            // Reap the child before the read result propagates: an
            // early return on a failed read would leave it a zombie.
            let status = child.wait().ok()?;
            let bytes = bytes?;
            if status.success() && bytes.len() as u64 <= MANPAGE_TEXT_LIMIT {
                Some(Arc::from(bytes))
            } else {
                None
            }
        });
        if cache_result {
            self.decompressed_cache
                .borrow_mut()
                .insert(path.to_string(), result.clone());
        }
        result
    }
}

impl FilesCheck {
    /// The text of a man page, decompressed through the probed tools
    /// when its name carries a compression suffix. `None` when the
    /// content cannot be obtained (unreadable file, missing or failing
    /// decompressor): the page's references cannot be judged, so the
    /// page is skipped rather than guessed at. A name carrying a compression suffix the
    /// codebase recognises but has no decompressor for (`.zip`) is
    /// skipped the same way: its bytes are compressed content, not
    /// page text to scan.
    fn manpage_text(&self, pkgfile: &PkgFile) -> Option<String> {
        match self.decompressor_for(&pkgfile.name) {
            Some(tool) => {
                if let Some(bytes) = self.decompressed_bytes(&pkgfile.name, &pkgfile.path, true) {
                    return Some(String::from_utf8_lossy(&bytes).into_owned());
                }
                // The shared helper could not serve the page (a failing
                // decompressor, or output past the text limit): fall
                // back to this page's own capped run.
                let mut cmd = tool.command()?;
                cmd.arg("-dc")
                    .arg(&pkgfile.path)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null());
                let mut child = cmd.spawn().ok()?;
                let bytes = child
                    .stdout
                    .take()
                    .and_then(|s| read_prefix(s, MANPAGE_TEXT_LIMIT).ok());
                // Reap the child before the read result propagates:
                // an early return on a failed read would leave it a
                // zombie.
                let status = child.wait().ok()?;
                let bytes = bytes?;
                // A saturated read means the output ran past the text
                // limit and the decompressor then died of SIGPIPE on
                // the closed pipe: the prefix is the page text to
                // judge, so the exit status only decides the verdict
                // for outputs that fit under the limit.
                if (bytes.len() as u64) < MANPAGE_TEXT_LIMIT && !status.success() {
                    return None;
                }
                Some(String::from_utf8_lossy(&bytes).into_owned())
            }
            None => {
                if strip_man_compression_suffix(&pkgfile.name) != pkgfile.name {
                    return None;
                }
                let file = std::fs::File::open(&pkgfile.path).ok()?;
                let bytes = read_prefix(file, MANPAGE_TEXT_LIMIT).ok()?;
                Some(String::from_utf8_lossy(&bytes).into_owned())
            }
        }
    }

    /// A man page can redirect to another page with a `.so` line (a
    /// soelim include); when the target page is not shipped, `man`
    /// fails to display the referencing page. The reference is judged
    /// within the package, like the reference's dangling-symlink
    /// family: a target shipped by another package satisfies it only
    /// when this package declares the dependency, through the same
    /// `req_names` escape `check_link_absolute` uses (a file Require
    /// on the target page's path). The check deliberately stays
    /// package-local even though the port's relative-symlink form is
    /// session-aware (issue #547); the parity ledger records the
    /// approximation. A shipped file, and likewise a file Require,
    /// matches under any compression suffix, or none. One finding
    /// per (referencing page, missing
    /// target).
    ///
    /// Resolution mirrors how the target is found at display time: a
    /// `man<section>/<page>` argument resolves against the man root,
    /// a bare filename against the referencing page's own directory,
    /// and a page under a locale directory (`/usr/share/man/de/...`)
    /// also resolves against that locale directory, which is where
    /// localised page sets keep their redirect targets.
    fn check_manpage_so_refs(&self, pkg: &Pkg, out: &mut Filter) {
        let shipped: HashSet<&str> = pkg
            .files
            .iter()
            .map(|f| strip_man_compression_suffix(&f.name))
            .collect();
        for pkgfile in &pkg.files {
            if !is_reg(pkgfile.mode) {
                continue;
            }
            let Ok(Some(caps)) = self.man_base_re.captures(&pkgfile.name) else {
                continue;
            };
            let page_root = caps.name("path").map(|m| m.as_str()).unwrap_or("");
            let page_lang = caps.name("lang").map(|m| m.as_str());
            let Some(text) = self.manpage_text(pkgfile) else {
                continue;
            };
            let mut seen: HashSet<String> = HashSet::new();
            for arg in manpage_so_targets(&text) {
                let candidates: Vec<String> = if !arg.contains('/') {
                    let dir = pkgfile
                        .name
                        .rsplit_once('/')
                        .map(|(d, _)| d)
                        .unwrap_or_default();
                    vec![format!("{dir}/{arg}")]
                } else {
                    let Some(rel) = manpage_so_root_relative(&arg) else {
                        continue;
                    };
                    let rel = strip_man_compression_suffix(&rel);
                    let mut cands =
                        vec![format!("/usr/share/man/{rel}"), format!("/usr/man/{rel}")];
                    if let Some(lang) = page_lang {
                        cands.push(format!("{page_root}/{lang}/{rel}"));
                    }
                    cands
                };
                let candidates: Vec<&str> = candidates
                    .iter()
                    .map(|c| strip_man_compression_suffix(c))
                    .collect();
                if !seen.insert(candidates[0].to_string()) {
                    continue;
                }
                if !candidates.iter().any(|c| {
                    shipped.contains(c)
                        || pkg
                            .req_names
                            .iter()
                            .any(|n| strip_man_compression_suffix(n) == *c)
                }) {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "manpage-dangling-so-ref",
                        &[&pkgfile.name, &arg],
                    );
                }
            }
        }
    }

    /// Man page compression defects beyond the suffix rule in
    /// `check_file_manpage`: a `.gz`-suffixed page whose first two
    /// bytes are not the gzip magic claims a compression its content
    /// does not carry, and a compressed page that decompresses to
    /// empty ships no page at all. Only man pages are judged (the
    /// man-root locations `man_base_re` matches, regular files): an
    /// uncompressed page stays under the existing
    /// `manpage-not-compressed` rule and never fires here, and a
    /// page whose decompressor is absent or fails is skipped rather
    /// than judged -- a failed decompression is not an empty page,
    /// and a page without magic fails decompression, so it does not
    /// also read as empty. One finding per page per predicate. The
    /// decompressed bytes come from the shared cache, so the
    /// `.so`-reference scan reuses this check's decompression.
    fn check_manpage_compression(&self, pkg: &Pkg, out: &mut Filter) {
        for pkgfile in &pkg.files {
            if !is_reg(pkgfile.mode) {
                continue;
            }
            let Ok(Some(_)) = self.man_base_re.captures(&pkgfile.name) else {
                continue;
            };
            if pkgfile.name.to_lowercase().ends_with(".gz")
                && file_has_gzip_magic(&pkgfile.path) == Some(false)
            {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "manpage-gzip-magic-mismatch",
                    &[&pkgfile.name],
                );
            }
            if self.decompressor_for(&pkgfile.name).is_some() {
                if let Some(bytes) = self.decompressed_bytes(&pkgfile.name, &pkgfile.path, true) {
                    if bytes.is_empty() {
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "manpage-empty-after-decompression",
                            &[&pkgfile.name],
                        );
                    }
                }
            }
        }
    }
}

/// The embedded world-writable-udev allowlist (issue #1023): the
/// device node names whose MODE="0666" in a shipped rule is an
/// upstream systemd default rather than a package defect. Baked in
/// like the other check data so an installed binary needs no data
/// dir next to it.
const UDEV_WW_ALLOWLIST_TOML: &str = include_str!("../../data/udev-world-writable-allowlist.toml");

static UDEV_WW_ALLOWLIST: OnceLock<HashSet<String>> = OnceLock::new();

/// The allowlisted node names, parsed once from
/// [`UDEV_WW_ALLOWLIST_TOML`]. Panics on a malformed table, the way a
/// broken staged description corpus surfaces at startup.
fn udev_ww_allowlist() -> &'static HashSet<String> {
    UDEV_WW_ALLOWLIST.get_or_init(|| {
        let table: toml::Table = UDEV_WW_ALLOWLIST_TOML
            .parse()
            .expect("udev world-writable allowlist is valid TOML");
        table
            .get("entry")
            .and_then(toml::Value::as_array)
            .expect("udev world-writable allowlist has an [[entry]] array")
            .iter()
            .map(|e| {
                e.get("name")
                    .and_then(toml::Value::as_str)
                    .expect("udev world-writable allowlist entry has a name")
                    .to_string()
            })
            .collect()
    })
}

/// The device nodes whose write access creates new devices other
/// processes trust: uinput (input devices), uhid (HID devices) and
/// cuse (character devices, CVE-2016-1233). Curated (issue #1023):
/// userio and vhci have the same shape and stay out until the corpus
/// evidence decides them.
const UDEV_NODE_CREATORS: [&str; 3] = ["cuse", "uhid", "uinput"];

/// Whether `fname` matches `*/udev/rules.d/*.rules`, the rules-file
/// population the udev content finders scan.
fn is_udev_rules_file(fname: &str) -> bool {
    if !fname.ends_with(".rules") {
        return false;
    }
    let Some(idx) = fname.find("/udev/rules.d/") else {
        return false;
    };
    !fname[idx + "/udev/rules.d/".len()..].contains('/')
}

/// Join a rules file's physical lines into logical lines at a
/// trailing `\`, the continuation udev itself applies.
fn udev_logical_lines(content: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for raw in content.lines() {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        match raw.strip_suffix('\\') {
            Some(head) => current.push_str(head),
            None => {
                current.push_str(raw);
                lines.push(std::mem::take(&mut current));
            }
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// One assignment of a udev rule: the key (`KERNEL`, `MODE`,
/// `ENV{MODE}`, ...), the operator (`==`, `=`, `:=`, ...) and the
/// unquoted value.
struct UdevAssignment<'a> {
    key: &'a str,
    op: &'a str,
    value: &'a str,
}

/// Split one logical rule line into its comma-separated assignments.
/// Commas inside a quoted value do not separate assignments.
fn udev_assignments(line: &str) -> Vec<UdevAssignment<'_>> {
    let mut tokens = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    let bytes = line.as_bytes();
    for (i, c) in line.char_indices() {
        match c {
            // Only an unescaped quote delimits: a quote preceded by
            // an odd run of backslashes is part of the value, and
            // toggling on it desyncs the tracking so the comma after
            // the value reads as quoted and the next assignment is
            // swallowed.
            '"' => {
                let backslashes = bytes[..i].iter().rev().take_while(|b| **b == b'\\').count();
                if backslashes % 2 == 0 {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                tokens.push(&line[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    tokens.push(&line[start..]);
    tokens
        .iter()
        .filter_map(|t| parse_udev_assignment(t.trim()))
        .collect()
}

/// Parse one `KEY<op>"value"` token; `None` when the token carries
/// no assignment operator (a stray word is not an assignment).
fn parse_udev_assignment(token: &str) -> Option<UdevAssignment<'_>> {
    let eq = token.find('=')?;
    // The operator ends at the first '='; a two-character operator
    // either precedes it (!=, <=, >=, +=, -=, :=) or is the doubled
    // '==' itself.
    let (key, op, val_start) = if token[eq..].starts_with("==") {
        (&token[..eq], "==", eq + 2)
    } else if eq > 0
        && matches!(
            token.as_bytes()[eq - 1],
            b'!' | b'<' | b'>' | b'+' | b'-' | b':'
        )
    {
        (&token[..eq - 1], &token[eq - 1..eq + 1], eq + 1)
    } else {
        (&token[..eq], "=", eq + 1)
    };
    let raw_value = token[val_start..].trim();
    let value = raw_value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(raw_value);
    Some(UdevAssignment {
        key: key.trim(),
        op,
        value,
    })
}

/// The octal mode an assignment value names, when it parses as one;
/// a value that does not parse is not a mode this check charges.
fn udev_mode_value(value: &str) -> Option<u32> {
    u32::from_str_radix(value.trim(), 8).ok()
}

impl FilesCheck {
    fn check_file_manpage(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        st: &mut PkgState,
        out: &mut Filter,
    ) {
        if pkgfile::is_dir(pkgfile.mode) {
            return;
        }
        let caps = match self.man_base_re.captures(fname) {
            Ok(Some(c)) => c,
            _ => return,
        };
        let category = caps.name("category").map(|m| m.as_str()).unwrap_or("");
        let filename = caps.name("filename").map(|m| m.as_str()).unwrap_or("");
        if is_reg(pkgfile.mode) {
            if let Some(binary) = man_binary_basename(filename) {
                note_man_basename(st, binary);
            }
        }
        let suffixes: Vec<&str> = filename.rsplit('.').collect();
        let mut suffixes = suffixes;
        if !self.compress_ext.is_empty() {
            let last = suffixes.first().copied().unwrap_or("");
            if last != self.compress_ext {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "manpage-not-compressed",
                    &[&self.compress_ext, fname],
                );
            }
            suffixes.remove(0);
        }
        if let Some(file_category) = suffixes.first() {
            if !file_category.starts_with(category) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "bad-manual-page-folder",
                    &[fname, &format!("expected folder: man{file_category}")],
                );
            }
            if filename.contains('/') {
                add_info(out, Level::Error, pkg, "manual-page-in-subfolder", &[fname]);
            }
        }
    }

    fn check_file_infopage_compressed(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if !self.compress_ext.is_empty()
            && is_match(&self.info_re, fname)
            && !fname.ends_with("/info/dir")
            && !fname.ends_with(&self.compress_ext)
        {
            add_info(
                out,
                Level::Warning,
                pkg,
                "infopage-not-compressed",
                &[&self.compress_ext, fname],
            );
        }
    }

    /// A shipped `.class` file whose 8-byte header is corrupt
    /// (bad magic) or truncated (fewer than 8 bytes): the class
    /// cannot load, so the file is dead weight at best. Only
    /// regular files are judged, and only the header: the major
    /// version is not floored here, since no openSUSE policy floor
    /// exists for it. Classes inside archives are judged by the
    /// archive check, not here.
    fn check_file_class(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        use std::io::Read as _;
        if !is_reg(pkgfile.mode) || !fname.ends_with(".class") {
            return;
        }
        let mut head = Vec::new();
        let Ok(file) = std::fs::File::open(&pkgfile.path) else {
            return;
        };
        if file.take(8).read_to_end(&mut head).is_err() {
            return;
        }
        if let Some(detail) = class_header_detail(&head) {
            add_info(
                out,
                Level::Warning,
                pkg,
                "corrupt-class-file",
                &[fname, &detail],
            );
        }
    }

    fn check_file_unexpanded_macro(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if let Ok(matches) = self
            .macro_re
            .find_iter(fname)
            .collect::<Result<Vec<_>, _>>()
        {
            for m in matches {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "unexpanded-macro",
                    &[fname, m.as_str()],
                );
            }
        }
    }

    fn check_file_non_standard_uid(&mut self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile) {
        if !self.standard_users.contains(&pkgfile.user) {
            self.owner_candidates.push(OwnerCandidate {
                name: pkg.name.clone(),
                arch: pkg.arch.clone(),
                source: source_key(pkg),
                fname: fname.to_string(),
                owner: pkgfile.user.clone(),
                group: false,
                own_requires: own_requires_account(pkg, false, &pkgfile.user),
            });
        }
    }

    fn check_file_non_standard_gid(&mut self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile) {
        if !self.standard_groups.contains(&pkgfile.group) {
            self.owner_candidates.push(OwnerCandidate {
                name: pkg.name.clone(),
                arch: pkg.arch.clone(),
                source: source_key(pkg),
                fname: fname.to_string(),
                owner: pkgfile.group.clone(),
                group: true,
                own_requires: own_requires_account(pkg, true, &pkgfile.group),
            });
        }
    }

    fn check_file_kernel_modules(
        &self,
        pkg: &Pkg,
        fname: &str,
        is_kernel: &bool,
        out: &mut Filter,
    ) {
        if !self.module_rpms_ok && is_match(&self.kernel_modules_re, fname) && !is_kernel {
            add_info(
                out,
                Level::Error,
                pkg,
                "kernel-modules-not-in-kernel-packages",
                &[fname],
            );
        }
    }

    fn check_file_dir_or_file(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        // A %ghost entry installs no payload, so there is nothing in the
        // directory to forbid.
        if pkgfile.is_ghost() || pkg.ghost_files.iter().any(|g| g == fname) {
            return;
        }
        for d in &self.disallowed_dirs {
            if fname.starts_with(d.as_str()) {
                let tag = format!(
                    "dir-or-file-in-{}",
                    d.trim_start_matches('/').replace('/', "-")
                );
                add_info(out, Level::Error, pkg, &tag, &[fname]);
            }
        }
    }

    /// Upstream rpmlint#435: `/usr/share/applications/mimeinfo.cache` is
    /// generated at install time and must not be packaged as a real file.
    /// The `desktop-file-utils` exception ships it `%ghost`, which has no
    /// payload and is skipped.
    fn check_file_mimeinfo_cache(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        out: &mut Filter,
    ) {
        if fname == "/usr/share/applications/mimeinfo.cache"
            && !pkgfile.is_ghost()
            && !pkg.ghost_files.iter().any(|g| g == fname)
        {
            add_info(out, Level::Error, pkg, "mimeinfo-cache-packaged", &[fname]);
        }
    }

    fn check_file_non_ghost_in_run(&self, pkg: &Pkg, fname: &str, pkg_ref: &Pkg, out: &mut Filter) {
        // /var/run is a symlink to /run on openSUSE, so both spellings name
        // the same tmpfs directory. An error outright (issue #699): payload
        // under a tmpfs runtime directory is never legitimate package
        // content — runtime directories belong in tmpfiles.d snippets.
        // The reference emits W; the port previously reached E only via
        // shipped scoring. The %ghost exemption is unchanged.
        if (fname.starts_with("/run/") || fname.starts_with("/var/run/"))
            && !pkg_ref.ghost_files.contains(&fname.to_string())
        {
            add_info(out, Level::Error, pkg, "non-ghost-in-run", &[fname]);
        }
    }

    fn check_file_systemd_unit_in_etc(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if fname.starts_with("/etc/systemd/system/") {
            add_info(out, Level::Warning, pkg, "systemd-unit-in-etc", &[fname]);
        }
    }

    fn check_file_systemd_preset(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        out: &mut Filter,
    ) {
        // Preset files encode the distribution's default enablement policy
        // and are shipped only by its preset packages (the
        // `SystemdPresetPackages` config key); any other package shipping
        // one sets enablement policy outside that central place.
        if self.preset_packages.iter().any(|n| n == &pkg.name) {
            return;
        }
        if !pkgfile::is_reg(pkgfile.mode) {
            return;
        }
        // A %ghost entry installs no payload, so nothing ships on disk.
        if pkgfile.is_ghost() || pkg.ghost_files.iter().any(|g| g == fname) {
            return;
        }
        for dir in [
            "/usr/lib/systemd/system-preset/",
            "/usr/lib/systemd/user-preset/",
            "/etc/systemd/system-preset/",
            "/etc/systemd/user-preset/",
        ] {
            if let Some(base) = fname.strip_prefix(dir) {
                if !base.contains('/') && base.len() > ".preset".len() && base.ends_with(".preset")
                {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "systemd-preset-packaged",
                        &[fname],
                    );
                }
                break;
            }
        }
    }

    fn check_file_udev_rule_in_etc(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if fname.starts_with("/etc/udev/rules.d/") {
            add_info(out, Level::Warning, pkg, "udev-rule-in-etc", &[fname]);
        }
    }

    /// Defect-pattern finders (issue #1023): a shipped udev rule that
    /// assigns a world-writable mode to a device node. The bare tag
    /// fires on every such rule whose KERNEL match does not name an
    /// allowlisted upstream systemd default exactly; a rule naming
    /// one of the node creators (uinput, uhid, cuse) carries the
    /// node-creator tag instead, so each line yields one finding.
    /// Access granted through a bare TAG+="uaccess" and chmod commands
    /// in RUN assignments are out of scope: neither is a MODE
    /// assignment.
    fn check_file_udev_rules(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        if !is_reg(pkgfile.mode) || !is_udev_rules_file(fname) {
            return;
        }
        let content = pkg.read_file(fname);
        for line in udev_logical_lines(&content) {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let assignments = udev_assignments(line);
            let world_writable = assignments.iter().any(|a| {
                a.key == "MODE"
                    && (a.op == "=" || a.op == ":=")
                    && udev_mode_value(a.value).is_some_and(|m| m & 0o002 != 0)
            });
            if !world_writable {
                continue;
            }
            let kernel = assignments
                .iter()
                .find(|a| a.key == "KERNEL" && a.op == "==")
                .map(|a| a.value);
            let detail = format!("\"{line}\"");
            if let Some(name) = kernel {
                if UDEV_NODE_CREATORS.contains(&name) {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "udev-rule-world-writable-node-creator",
                        &[fname, &detail],
                    );
                    continue;
                }
                if udev_ww_allowlist().contains(name) {
                    continue;
                }
            }
            add_info(
                out,
                Level::Warning,
                pkg,
                "udev-rule-world-writable-mode",
                &[fname, &detail],
            );
        }
    }

    fn check_file_tmpfiles_conf_in_etc(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if fname.starts_with("/etc/tmpfiles.d/") {
            add_info(out, Level::Warning, pkg, "tmpfiles-conf-in-etc", &[fname]);
        }
    }

    fn check_file_subdir_in_bin(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        // sub_bin_regex: bin dirs with a subdirectory component
        for bindir in ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"] {
            if fname.starts_with(bindir) && fname[bindir.len()..].contains('/') {
                if subdir_in_bin_is_companion_dir(pkg, bindir, fname) {
                    break;
                }
                add_info(out, Level::Error, pkg, "subdir-in-bin", &[fname]);
                break;
            }
        }
    }

    fn check_file_siteperl_in_perl_module(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        out: &mut Filter,
    ) {
        // A directory entry is tree ownership, not a shipped module
        // file: the perl package itself owns its site_perl tree.
        if fname.contains("/site_perl/") && !is_dir(pkgfile.mode) {
            add_info(
                out,
                Level::Warning,
                pkg,
                "siteperl-in-perl-module",
                &[fname],
            );
        }
    }

    fn check_file_backup_file_in_package(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if is_match(backup_regex(), fname) && !is_cargo_toml_orig(fname) {
            add_info(out, Level::Error, pkg, "backup-file-in-package", &[fname]);
        }
    }

    fn check_file_version_control_internal_file(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if is_match(scm_regex(), fname) {
            add_info(
                out,
                Level::Error,
                pkg,
                "version-control-internal-file",
                &[fname],
            );
        }
    }

    fn check_file_htaccess_file(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        out: &mut Filter,
    ) {
        if fname.ends_with("/.htaccess") {
            // Severity split on the %doc flag plus doc-tree path
            // (see the divergence ledger):
            // a .htaccess shipped as documentation under
            // /usr/share/doc/packages/ is a website artefact of the
            // shipped docs (a DirectoryIndex for a website source,
            // Sphinx redirect maps written for the upstream docs
            // website) -- inert unless an admin serves the doc tree,
            // so it warns instead of erroring. Both conditions are
            // required: an unflagged .htaccess inside the doc tree
            // and a %doc-flagged one outside it keep the reference's
            // error, as do all web-root and application payloads.
            let level = if pkgfile.is_doc() && fname.starts_with("/usr/share/doc/packages/") {
                Level::Warning
            } else {
                Level::Error
            };
            add_info(out, level, pkg, "htaccess-file", &[fname]);
        }
    }

    fn check_file_hidden_file_or_dir(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        // Upstream hidden_file_regex is r'/\.[^/]*$': only the final path
        // component is tested, so files under a hidden dir are not flagged.
        // The '/' before the dot is required (a slashless name never matches)
        // and [^/]* may be empty (a bare '.' component matches).
        let is_hidden = fname
            .rsplit('/')
            .next()
            .is_some_and(|c| c.starts_with('.') && fname.contains('/'));
        // /usr/etc/skel/ is the same skeleton directory on usrmerge
        // layouts, where the skeleton payload ships at the /usr path.
        // .cargo_vcs_info.json is the second metadata file cargo writes
        // into a vendored crate tree, next to .cargo-checksum.json: it
        // records the upstream VCS revision of the vendored sources.
        if is_hidden
            && !fname.starts_with("/etc/skel/")
            && !fname.starts_with("/usr/etc/skel/")
            && !fname.ends_with("/.build-id")
            && !fname.ends_with("/.cargo-checksum.json")
            && !fname.ends_with("/.cargo_vcs_info.json")
        {
            add_info(out, Level::Warning, pkg, "hidden-file-or-dir", &[fname]);
        }
    }

    fn check_file_manifest_in_perl_module(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        // The reference only fires for a doc dir literally named perl-*;
        // /usr/share/doc/packages/perl-*/MANIFEST must stay silent.
        if is_match(manifest_perl_regex(), fname) {
            add_info(
                out,
                Level::Warning,
                pkg,
                "manifest-in-perl-module",
                &[fname],
            );
        }
    }

    fn check_file_info_dir_file(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if fname == "/usr/info/dir" || fname == "/usr/share/info/dir" {
            add_info(out, Level::Error, pkg, "info-dir-file", &[fname]);
        }
    }

    fn check_file_makefile_junk(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if fname.ends_with("/Makefile.am") {
            let base = fname.trim_end_matches(".am");
            let in_file = format!("{base}.in");
            if pkg.files.iter().any(|f| f.name == in_file)
                && pkg.doc_files.contains(&fname.to_string())
            {
                add_info(out, Level::Warning, pkg, "makefile-junk", &[fname]);
            }
        }
    }
}

/// One row of the Python bytecode magic table.
struct PythonMagicVersion {
    version: String,
    magics: Vec<u32>,
}

/// The Python bytecode magic table, baked in like the Go toolchain
/// floor so an installed binary needs no data dir next to it.
const PYTHON_MAGIC_VALUES_TOML: &str = include_str!("../../data/python-magic-values.toml");

/// The parsed magic table, parsed once (the `defect_pattern::registry`
/// pattern).
fn python_magic_table() -> &'static [PythonMagicVersion] {
    static TABLE: OnceLock<Vec<PythonMagicVersion>> = OnceLock::new();
    TABLE.get_or_init(|| parse_python_magic_values(PYTHON_MAGIC_VALUES_TOML))
}

/// Parse and validate the table. Validation takes the staged-data
/// posture (the registry's): a malformed table panics at startup
/// instead of silently disabling the finder.
fn parse_python_magic_values(raw: &str) -> Vec<PythonMagicVersion> {
    let table: toml::Table = raw.parse().expect("python magic values is valid TOML");
    assert!(
        table.get("as_of").and_then(toml::Value::as_str).is_some(),
        "python magic values records an as_of date"
    );
    let records = table
        .get("version")
        .and_then(toml::Value::as_array)
        .expect("python magic values has a [[version]] array");
    let versions: Vec<PythonMagicVersion> = records
        .iter()
        .map(|record| {
            let version = record
                .get("version")
                .and_then(toml::Value::as_str)
                .expect("python magic version has a version string")
                .to_string();
            let magics = record
                .get("magics")
                .and_then(toml::Value::as_array)
                .expect("python magic version has a magics array")
                .iter()
                .map(|v| {
                    u32::try_from(v.as_integer().expect("python magic value is an integer"))
                        .expect("python magic value fits u32")
                })
                .collect();
            PythonMagicVersion { version, magics }
        })
        .collect();
    // Ascending version order: the found-version lookup reports the
    // first entry containing a magic.
    let key = |v: &str| -> Vec<u64> {
        v.split('.')
            .map(|part| part.parse().expect("python magic version is numeric"))
            .collect()
    };
    let mut prev: Option<Vec<u64>> = None;
    for entry in &versions {
        assert!(
            !entry.version.is_empty(),
            "python magic version is non-empty"
        );
        assert!(
            !entry.magics.is_empty(),
            "python magic version lists magics"
        );
        let k = key(&entry.version);
        if let Some(p) = &prev {
            assert!(k > *p, "python magic versions are in ascending order");
        }
        prev = Some(k);
    }
    versions
}

impl FilesCheck {
    /// Names from requires + recommends + suggests, mirroring the
    /// reference's deps list used by the missing-dependency-to-*
    /// checks.
    fn dep_names(pkg: &Pkg) -> Vec<&str> {
        pkg.requires
            .iter()
            .chain(pkg.recommends.iter())
            .chain(pkg.suggests.iter())
            .map(|d| d.name.as_str())
            .collect()
    }

    /// Name credits for `incoherent-logrotate-file` beyond the
    /// reference's exact package-name equality (FilesCheck ledger;
    /// measured over the Factory corpus, 15 findings -> 9). A
    /// logrotate file is coherent when it is named after the package
    /// up to case, after the package plus a logrotate suffix, or
    /// after a daemon the same package ships as an executable:
    ///
    /// - case-only difference: openQA ships `openqa`;
    /// - suffix: `grommunio-sync.lr` counts as `grommunio-sync`;
    ///   only the logrotate suffixes `.lr` and `.conf` strip, and
    ///   the stem is compared with the same case-insensitive
    ///   equality as the bare name, so the two credits compose
    ///   (openQA's `openqa.lr` is coherent). A stem differing by
    ///   more than case still fires (slurm-config's `slurmctld.conf`
    ///   stem differs and keeps firing);
    /// - daemon name: cobbler ships /usr/bin/cobblerd, so its
    ///   `cobblerd` file is coherent. The name must be an executable
    ///   regular file in THIS package, compared case-sensitively --
    ///   ceph-base ships only lib directories called `ceph` (the
    ///   `ceph` executable lives in ceph-common) and keeps firing.
    ///   The scan excludes the logrotate file under judgement
    ///   itself and any %ghost entry: neither is a shipped daemon
    ///   binary, and an executable logrotate file must not suppress
    ///   its own finding.
    fn logrotate_name_credited(pkg: &Pkg, fname: &str, basename: &str) -> bool {
        if basename.eq_ignore_ascii_case(&pkg.name) {
            return true;
        }
        for suffix in [".lr", ".conf"] {
            if basename
                .strip_suffix(suffix)
                .is_some_and(|stem| stem.eq_ignore_ascii_case(&pkg.name))
            {
                return true;
            }
        }
        pkg.files.iter().any(|f| {
            f.name != fname
                && !f.is_ghost()
                && is_reg(f.mode)
                && f.mode & 0o111 != 0
                && f.name.rsplit('/').next() == Some(basename)
        })
    }

    fn check_file_logrotate(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        // logrotate_regex: /etc/logrotate.d/
        if fname.starts_with("/etc/logrotate.d/") && fname != "/etc/logrotate.d/" {
            let basename = fname.rsplit('/').next().unwrap_or("");
            if basename != pkg.name && !Self::logrotate_name_credited(pkg, fname, basename) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "incoherent-logrotate-file",
                    &[fname],
                );
            }
        }
        // The reference counts requires + recommends + suggests here; a bare
        // Requires check false-positives on the common Recommends: logrotate
        // pattern (#388).
        let deps = Self::dep_names(pkg);
        if fname.starts_with("/etc/logrotate.d/")
            && !deps.contains(&"logrotate")
            && pkg.name != "logrotate"
        {
            add_info(
                out,
                Level::Error,
                pkg,
                "missing-dependency-to-logrotate",
                &["for logrotate script", fname],
            );
        }
    }

    fn check_file_crontab(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        // Same #388 root cause as logrotate: the reference also counts
        // requires + recommends + suggests here.
        let deps = Self::dep_names(pkg);
        // Divergence (FilesCheck ledger): the reference credits only the
        // literal name `crontabs`, but that provider was renamed -- the
        // cron.* directories are shipped by `cron` and the daemon is
        // `cronie`, and the name `crontabs` exists nowhere in the corpus.
        // A dep on either current name satisfies the check the same way;
        // exact name matches only, so lookalikes
        // (cronie-anacron, systemd-cron, cron-utils) keep firing.
        const CRON_PROVIDERS: [&str; 3] = ["crontabs", "cron", "cronie"];
        if !fname.starts_with("/etc/cron.")
            || CRON_PROVIDERS.iter().any(|name| deps.contains(name))
            || CRON_PROVIDERS.contains(&pkg.name.as_str())
        {
            return;
        }
        // Divergence (FilesCheck ledger): the reference charges every
        // "/etc/cron." entry, including the cron.* directory entries
        // themselves (#552's base-dir false positive) and daemon files
        // sitting directly in /etc -- /etc/cron.deny is the cron daemon's
        // own access-control file, not a cron script. Neither shape is a
        // cron script: only a non-directory entry *inside* a cron.*
        // directory can be one, so charge only those. A real file inside
        // a charged directory still fires on its own entry.
        let inside_cron_dir = fname["/etc/cron.".len()..].contains('/');
        if inside_cron_dir && !is_dir(pkgfile.mode) {
            add_info(
                out,
                Level::Error,
                pkg,
                "missing-dependency-to-crontabs",
                &["for cron script", fname],
            );
        }
    }

    fn check_file_compressed_symlink(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        out: &mut Filter,
    ) {
        let link = &pkgfile.linkto;
        if !link.is_empty() {
            for ext in [".gz", ".bz2", ".xz", ".zst"] {
                if link.ends_with(ext) && !fname.ends_with(ext) {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "compressed-symlink-with-wrong-ext",
                        &[fname, link],
                    );
                    break;
                }
            }
        }
    }

    fn check_file_crond(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        if !fname.starts_with("/etc/cron.d/") {
            return;
        }
        let mode = pkgfile.mode;
        if mode & 0o111 != 0 {
            add_info(out, Level::Error, pkg, "executable-crontab-file", &[fname]);
        }
        if mode & 0o022 != 0 {
            add_info(
                out,
                Level::Error,
                pkg,
                "non-owner-writeable-only-crontab-file",
                &[fname],
            );
        }
    }

    fn check_file_zero_perms(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        let perm = pkgfile.mode & 0o7777;
        if perm == 0 {
            if pkgfile.is_ghost() {
                if zero_perms_ghost_credit(pkg, fname) {
                    return;
                }
                let (perms, user, group) = match find_perm_in_tmpfiles(pkg, fname) {
                    Some(found) => found,
                    // No tmpfiles.d entry declares the path: fall back to
                    // a traversable mode for directories, 0644 for files.
                    // A 0644 directory cannot be entered, so suggesting it
                    // for a directory entry is unusable advice.
                    None => (
                        if is_dir(pkgfile.mode) { "0755" } else { "0644" }.to_string(),
                        "root".to_string(),
                        "root".to_string(),
                    ),
                };
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "zero-perms-ghost",
                    &[&format!(
                        "Suggestion: \"%ghost %attr({perms},{user},{group}) {fname}\""
                    )],
                );
            } else {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "zero-perms",
                    &[fname, &format!("{:o}", perm)],
                );
            }
        }
    }

    fn check_file_link(
        &mut self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        st: &mut PkgState,
        out: &mut Filter,
    ) {
        if !pkgfile::is_symlink(pkgfile.mode) {
            return;
        }
        st.link_targets
            .insert(fname.to_string(), pkgfile.linkto.clone());
        if let Ok(Some(caps)) = self.bin_re.captures(fname) {
            if let Some(name) = caps.get(1).map(|m| m.as_str()) {
                if !name.contains('/') {
                    st.bindir_links
                        .entry(name.to_string())
                        .or_default()
                        .push(fname.to_string());
                }
            }
        }
        let link = &pkgfile.linkto;
        // devel-file-in-non-devel-package for .so links: the reference
        // gates on the anchored sofile_regex (FilesCheck.py:165,
        // _check_file_link_devel), so versioned libfoo.so.0 links do not fire.
        if !st.devel_pkg
            && !mingw_sysroot_devel_exempt(&pkg.name, fname)
            && is_match(&self.sofile_re, fname)
            && !link.ends_with(".so")
        {
            add_info(
                out,
                Level::Warning,
                pkg,
                "devel-file-in-non-devel-package",
                &[fname],
            );
        }
        // man page basenames
        if let Ok(Some(caps)) = self.man_base_re.captures(fname) {
            if let Some(m) = caps.name("filename") {
                if let Some(binary) = man_binary_basename(m.as_str()) {
                    note_man_basename(st, binary);
                }
            }
        }
        // bindir exes: symlinks register an empty entry (man page existence
        // check only, not subject to the duplicate binary check).
        // FilesCheck.py:499-500, 819. bin_re is the reference's bin_regex,
        // so /usr/games symlinks register too.
        if let Ok(Some(caps)) = self.bin_re.captures(fname) {
            if let Some(exe) = caps.get(1).map(|m| m.as_str()) {
                if !exe.contains('/') {
                    st.bindir_exes.entry(exe.to_string()).or_default();
                }
            }
        }
        // dangling symlink checks
        self.check_link_absolute(pkg, fname, pkgfile, st, out);
        self.check_link_relative(pkg, fname, pkgfile, st, out);
        self.check_link_loop(pkg, fname, pkgfile, out);
        self.check_link_bindir_shebang(pkg, fname, pkgfile, out);
    }

    /// The reference's exception lookup: the first matching exception's
    /// package name, or `None` for a plain dangling symlink.
    fn dangling_exception(&self, link: &str) -> Option<&str> {
        for (name, re) in &self.dangling_exceptions {
            if is_match(re, link) {
                return Some(name);
            }
        }
        None
    }

    fn report_dangling(&self, pkg: &Pkg, fname: &str, link: &str, out: &mut Filter) {
        match self.dangling_exception(link) {
            // An empty exception name behaves like no exception.
            Some(name) if !name.is_empty() => {
                if !pkg.req_names.iter().any(|n| n == name) {
                    add_info(out, Level::Warning, pkg, "no-dependency-on", &[name]);
                }
            }
            _ => {
                add_info(out, Level::Warning, pkg, "dangling-symlink", &[fname, link]);
            }
        }
    }

    fn check_link_absolute(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        _st: &PkgState,
        out: &mut Filter,
    ) {
        let link = &pkgfile.linkto;
        let caps = match self.absolute_re.captures(link) {
            Ok(Some(c)) => c,
            _ => return,
        };
        let is_so = is_match(&self.sofile_re, fname);
        if !is_so
            && !pkg.files.iter().any(|f| f.name == *link)
            && !pkg.req_names.iter().any(|n| n == link)
        {
            self.report_dangling(pkg, fname, link, out);
        }
        let linktop = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if let Ok(Some(fcaps)) = self.absolute_re.captures(fname) {
            let filetop = fcaps.get(1).map(|m| m.as_str()).unwrap_or("");
            if filetop == linktop || self.use_relative_symlinks {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "symlink-should-be-relative",
                    &[fname, link],
                );
            }
        }
    }

    /// The `DanglingSymlinkExceptions` outcome for a link, mirroring
    /// `report_dangling`'s match: the first matching exception diverts
    /// the finding to `no-dependency-on` for its package, unless the
    /// emitting package Requires that package (then nothing is
    /// reported); an empty exception name behaves like no exception.
    fn dangling_disposition(&self, pkg: &Pkg, link: &str) -> DanglingDisposition {
        match self.dangling_exception(link) {
            Some(name) if !name.is_empty() => {
                if pkg.req_names.iter().any(|n| n == name) {
                    DanglingDisposition::Silent
                } else {
                    DanglingDisposition::Divert(name.to_string())
                }
            }
            _ => DanglingDisposition::Plain,
        }
    }

    fn check_link_relative(
        &mut self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        _st: &PkgState,
        out: &mut Filter,
    ) {
        let link = &pkgfile.linkto;
        if is_match(&self.absolute_re, link) {
            return;
        }
        let is_so = is_match(&self.sofile_re, fname);
        if !is_so {
            let parent = Path::new(fname)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let abslink = crate::pkg::normalize_path(&format!("{parent}/{link}"));
            // A target naming a directory this package itself populates
            // is not dangling: installing the package creates the target
            // directory as a leading directory of its own payload, so the
            // link resolves even though no header entry names the target
            // itself (a link to `.` or `../..`, a JDK tree link whose
            // directory carries the package's own headers). The evidence
            // must be a non-%ghost entry strictly below the target --
            // a %ghost entry installs no payload, so it creates no
            // directory -- and the prefix carries a trailing slash, so a
            // sibling path that merely shares a string prefix does not
            // credit. The test runs on the verbatim normalised target:
            // a root-level link's `//usr/...` form matches no shipped
            // path, so the class-F parity shape (filesystem's own root
            // links) keeps firing, as the #547 ledger entry pins. A
            // target of exactly `/` is the one special case: its
            // verbatim prefix would be `//`, which no shipped path
            // starts with, so the prefix is `/` itself. The reference
            // has no such credit; the divergence is ledgered.
            let prefix = if abslink == "/" {
                "/".to_string()
            } else {
                format!("{abslink}/")
            };
            let populated_dir = pkg
                .files
                .iter()
                .any(|f| !f.is_ghost() && f.name.starts_with(&prefix));
            if !populated_dir
                && !pkg.files.iter().any(|f| f.name == abslink)
                && !pkg.req_names.contains(&abslink)
            {
                // Session-aware decision (issue #547): record the link
                // and decide in `after_checks`, when the file sets of
                // the whole run are known — a sibling package in the
                // run may ship the target. A run over one package keeps
                // today's behaviour: its session set is its own file
                // list. The reference decides per package
                // (`FilesCheck.py` `_check_file_link_relative`); the
                // divergence is ledgered.
                let disposition = self.dangling_disposition(pkg, link);
                self.dangling_candidates.push(DanglingCandidate {
                    name: pkg.name.clone(),
                    arch: pkg.arch.clone(),
                    fname: fname.to_string(),
                    link: link.to_string(),
                    target: abslink,
                    disposition,
                });
            }
        }
        let parts: Vec<&str> = fname.split('/').skip(1).collect();
        let mut pathcomponents: &[&str] = &parts;
        let mut mylink: Option<&str> = None;
        let mut lastpop: Option<&str> = None;
        let mut r = self.points_re.captures(link.as_str()).ok().flatten();
        while let Some(caps) = r {
            let rest = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            mylink = Some(rest);
            if pathcomponents.is_empty() {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "symlink-has-too-many-up-segments",
                    &[fname, link],
                );
                break;
            }
            lastpop = Some(pathcomponents[0]);
            pathcomponents = &pathcomponents[1..];
            r = self.points_re.captures(rest).ok().flatten();
        }
        if let (Some(mylink), Some(lastpop)) = (mylink, lastpop) {
            if let Ok(Some(caps)) = self.absolute2_re.captures(mylink) {
                let linktop = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                // have we reached the root directory?
                if pathcomponents.is_empty() && linktop != lastpop && !self.use_relative_symlinks {
                    // relative link into other toplevel directory
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "symlink-should-be-absolute",
                        &[fname, link],
                    );
                }
            }
            // A .. left in the target after the leading run means the
            // link goes up and then back down, e.g. ../foo/../bar.
            // A target made only of .. segments never goes back down:
            // the leading-run scan cannot consume its final .. (the
            // pattern needs a trailing slash), so that segment
            // survives as the whole remainder and would be counted
            // here even though the link is already in its shortest
            // form (a chroot mirror link such as ../..). The
            // reference counts it; the divergence is ledgered.
            let pure_up = link
                .split('/')
                .all(|segment| segment.is_empty() || segment == "..");
            if !pure_up {
                for segment in mylink.split("/") {
                    if segment == ".." {
                        add_info(
                            out,
                            Level::Error,
                            pkg,
                            "symlink-contains-up-and-down-segments",
                            &[fname, link],
                        );
                    }
                }
            }
        }
    }

    /// `symlink-loop` (issue #723): follow the link's resolution chain
    /// within this package; a chain that revisits a path can never
    /// resolve, so every open of the link fails with ELOOP. The
    /// dangling findings are presence-based and cannot see the shape:
    /// a loop's target is present in the file list, being the link
    /// itself or another link in the cycle. A chain reaching a shipped
    /// non-link entry resolves, and a chain leaving the package is the
    /// dangling family's business, so only a revisited path fires. The
    /// walk terminates because every step either returns or visits a
    /// package path not visited before.
    fn check_link_loop(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        let mut visited: HashSet<&str> = HashSet::new();
        visited.insert(fname);
        let mut current: &PkgFile = pkgfile;
        while !current.linkto.is_empty() {
            let target = &current.linkto;
            let joined = if target.starts_with('/') {
                target.clone()
            } else {
                match current.name.rfind('/') {
                    Some(i) => format!("{}/{target}", &current.name[..i]),
                    None => target.clone(),
                }
            };
            let next_name = crate::pkg::normalize_path(&joined);
            let Some(next) = pkg.files.iter().find(|f| f.name == next_name) else {
                return;
            };
            if !visited.insert(next.name.as_str()) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "symlink-loop",
                    &[fname, &pkgfile.linkto],
                );
                return;
            }
            current = next;
        }
    }

    fn check_link_bindir_shebang(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        out: &mut Filter,
    ) {
        let link = &pkgfile.linkto;
        let linkto = if link.starts_with('/') {
            crate::pkg::normalize_path(link)
        } else {
            let parent = Path::new(fname)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            crate::pkg::normalize_path(&format!("{parent}/{link}"))
        };
        // Link to a file not in the package, so ignore
        let Some(realbin) = pkg.files.iter().find(|f| f.name == linkto) else {
            return;
        };
        // Link to something in bindir is okay
        if is_match(&self.bin_re, &realbin.name) {
            return;
        }
        if !pkgfile::is_reg(realbin.mode) {
            return;
        }
        let (chunk, _istext) = self.peek(pkg, realbin, out);
        let (interpreter, _) = script_interpreter(&chunk);
        // Not a script with shebang, so ignore
        let Some(interpreter) = interpreter else {
            return;
        };
        // A `#!/bin/false` shebang marks a file that must never be
        // executed directly (uwsm ships its sourced session-plugin
        // fragments this way: the false interpreter keeps them inert
        // when reached by name). There is no interpreter dependency
        // to demand for a file whose design is that nothing runs it,
        // so the idiom stays quiet.
        if interpreter == "/bin/false" || interpreter == "/usr/bin/false" {
            return;
        }
        // If the shebang interpreter is a dependency, it's okay
        if pkg.requires.iter().any(|d| d.name == interpreter) {
            return;
        }
        add_info(
            out,
            Level::Warning,
            pkg,
            "symlink-to-binary-with-shebang",
            &[
                fname,
                &format!(
                    "is a link to a script ({}) but missing requires for {interpreter}",
                    realbin.name
                ),
            ],
        );
    }

    fn check_file_dir(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        if !pkgfile::is_dir(pkgfile.mode) {
            return;
        }
        let perm = pkgfile.mode & 0o7777;
        // world-writable: other-write with no sticky bit - the
        // reference predicate is `mode & 0o1002 == 2`, so sticky-bit
        // directories (1777, e.g. /tmp and /var/tmp) stay quiet.
        if perm & 0o1002 == 0o002 {
            add_info(
                out,
                Level::Error,
                pkg,
                "world-writable",
                &[fname, &format!("{:o}", perm)],
            );
        }
        if !FILESYS_PACKAGES.contains(&pkg.name.as_str()) && STANDARD_DIRS.contains(&fname) {
            add_info(
                out,
                Level::Error,
                pkg,
                "standard-dir-owned-by-package",
                &[fname],
            );
        }
    }

    fn check_file_normal_file(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        st: &mut PkgState,
        out: &mut Filter,
    ) {
        if !pkgfile::is_reg(pkgfile.mode) {
            return;
        }
        // Port of the reference's _check_file_normal_file_debuginfo: a
        // debuginfo package's .debug files set debugs, any other regular
        // file sets srcs; the without-sources finding needs debugs
        // without srcs.
        if st.debuginfo_package {
            if fname.ends_with(".debug") {
                st.debuginfo_debugs = true;
            } else {
                st.debuginfo_srcs = true;
            }
        }
        let mut fd = FileData::default();
        self.check_normal_logfile(pkg, fname, pkgfile, &mut fd, out);
        self.check_normal_getdata(pkg, fname, pkgfile, &mut fd, out);
        self.check_normal_license_coverage(fname, pkgfile, st, &fd);
        self.check_normal_doc(pkg, fname, &mut fd, out);
        self.check_normal_non_devel(pkg, fname, st, out);
        self.check_normal_lib(pkg, fname, pkgfile, st, out);
        self.check_normal_rpaths_in_buildconfig(pkg, fname, &fd, out);
        self.check_normal_bin(pkg, fname, pkgfile, st, out);
        self.check_normal_devel(pkg, fname, st, &fd, out);
        self.check_normal_world_w(pkg, fname, pkgfile, out);
        self.check_normal_perl_dep(pkg, fname, st);
        self.check_normal_python_dep(pkg, fname, st);
        self.check_normal_python_source(pkg, fname, &fd, st, out);
        self.check_normal_exec(pkg, fname, pkgfile, &mut fd, out);
        self.check_normal_non_conf_in_etc(pkg, fname, pkgfile, out);
        self.check_normal_python_noarch(pkg, fname, out);
        self.check_normal_gzipped_svg(pkg, fname, st, out);
        self.check_normal_gzip_mtime(pkg, fname, &fd, st, out);
        self.check_normal_pem(pkg, fname, out);
        self.check_normal_tcl(pkg, fname, out);
        self.check_normal_text(pkg, fname, pkgfile, &mut fd, out);
        // library without ldconfig (with #1602 fix: check interpreter too)
        self.check_ldconfig(pkg, fname, pkgfile, st, out);
    }

    fn check_normal_logfile(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        fd: &mut FileData,
        out: &mut Filter,
    ) {
        if !is_match(&self.log_file_re, fname) {
            return;
        }
        fd.nonexec_file = true;
        if pkgfile.user != "root" || pkgfile.group != "root" {
            // Severity split (see the
            // divergence ledger): an owner this package itself declares
            // through a sysusers.d snippet it ships warns instead of
            // erroring. The snippet is the service's runtime identity
            // -- the package creates the very account its daemon drops
            // to -- so the ghost's recorded ownership is the design,
            // and the finding stays visible for the packager's call
            // without failing the build. Only the package's own
            // snippets count, per tag: a `u` line credits the user
            // (and the like-named primary group it creates), a `g`
            // line the group; an owner carried only by a Requires, or
            // declared by a sibling package, carries no such signal
            // and keeps the reference's error.
            let (declared_users, declared_groups) = own_sysusers_declared(pkg);
            if pkgfile.user != "root" {
                let level = if declared_users.contains(&pkgfile.user) {
                    Level::Warning
                } else {
                    Level::Error
                };
                add_info(
                    out,
                    level,
                    pkg,
                    "non-root-user-log-file",
                    &[fname, &pkgfile.user],
                );
            }
            if pkgfile.group != "root" {
                let level = if declared_groups.contains(&pkgfile.group) {
                    Level::Warning
                } else {
                    Level::Error
                };
                add_info(
                    out,
                    level,
                    pkg,
                    "non-root-group-log-file",
                    &[fname, &pkgfile.group],
                );
            }
        }
        if !pkg.ghost_files.iter().any(|g| g == fname) {
            add_info(out, Level::Error, pkg, "non-ghost-file", &[fname]);
        }
    }

    fn check_normal_getdata(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        fd: &mut FileData,
        out: &mut Filter,
    ) {
        // os.access(path, R_OK): unreadable files are skipped silently here;
        // peek (below and for symlink targets) reports read-error instead.
        // The reference's UnicodeError branch has no Rust equivalent: paths
        // are handled as bytes, so it cannot fail that way (divergences.toml).
        if std::fs::File::open(&pkgfile.path).is_ok() {
            let (chunk, istext) = self.peek(pkg, pkgfile, out);
            fd.chunk = chunk;
            fd.istext = istext;
        }
        let (interpreter, args) = script_interpreter(&fd.chunk);
        fd.interpreter = interpreter;
        fd.interpreter_args = args;
        fd.is_buildconfig = fd.istext && is_match(&self.buildconfigfile_re, fname);
    }

    fn check_normal_doc(&self, pkg: &Pkg, fname: &str, fd: &mut FileData, out: &mut Filter) {
        let is_doc = pkg.doc_files.iter().any(|d| d == fname);
        if is_match(&self.doc_re, fname) {
            if fd.interpreter.is_none() {
                fd.nonexec_file = true;
            }
            if !is_doc {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "not-listed-as-documentation",
                    &[fname],
                );
            }
        }
    }

    fn check_normal_non_devel(&self, pkg: &Pkg, fname: &str, st: &PkgState, out: &mut Filter) {
        // FilesCheck.py:1079-1081. The cross-sysroot scoping is ours
        // (issue #860, divergences.toml): under a cross-toolchain
        // target sysroot the file is the devel package's own payload,
        // not host layout.
        if st.devel_pkg && fname.ends_with(".typelib") && !cross_sysroot_matches(fname) {
            add_info(
                out,
                Level::Error,
                pkg,
                "non-devel-file-in-devel-package",
                &[fname],
            );
        }
    }

    fn check_normal_devel(
        &self,
        pkg: &Pkg,
        fname: &str,
        st: &PkgState,
        fd: &FileData,
        out: &mut Filter,
    ) {
        // FilesCheck.py:1174, _check_file_normal_file_devel. The .so
        // symlink half already lives in check_file_link; this is the
        // normal-file half: headers, static libs and build config files
        // (the latter only when the file is text, via fd.is_buildconfig)
        // in a non-devel package, excluding listed documentation.
        let is_doc = pkg.doc_files.iter().any(|d| d == fname);
        if !st.devel_pkg
            && !is_doc
            && !mingw_sysroot_devel_exempt(&pkg.name, fname)
            && (fd.is_buildconfig
                || is_match(&self.includefile_re, fname)
                || is_match(&self.develfile_re, fname))
        {
            add_info(
                out,
                Level::Warning,
                pkg,
                "devel-file-in-non-devel-package",
                &[fname],
            );
        }
    }

    fn check_normal_lib(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        st: &PkgState,
        out: &mut Filter,
    ) {
        // FilesCheck.py:1083-1088, with the cross-sysroot scoping of
        // check_normal_non_devel (issue #860): a runtime library under
        // a target sysroot is the cross devel package's payload. The
        // debug trees hold the mirrored .debug companions of the
        // runtime libraries (issue #955, divergences.toml): a
        // -debuginfo package's payload by construction, scoped out
        // via is_debug_path. A package that is the library's combined
        // home (lib_combined_home) is scoped out the same way.
        if is_match(&self.lib_re, fname)
            && st.devel_pkg
            && !is_debug_path(fname)
            && !cross_sysroot_matches(fname)
            && !(is_match(&self.sofile_re, fname) && pkgfile::is_symlink(pkgfile.mode))
            && !Self::lib_combined_home(pkg, fname)
        {
            add_info(
                out,
                Level::Error,
                pkg,
                "non-devel-file-in-devel-package",
                &[fname],
            );
        }
    }

    /// Combined-home shape for the versioned-library arm above: the
    /// package ships the library's own devel payload — the
    /// unversioned linker symlink (`libfoo.so`) in the same
    /// directory, resolving within the package to the versioned file
    /// itself. Within the package's own build the library then has
    /// no other home: no separate runtime package was deprived of
    /// the file, so the finding's premise (a devel package holding a
    /// runtime file that belongs elsewhere) does not hold. gettext-tools, which
    /// ships libgettextpo with its headers and linker symlink and
    /// Provides gettext-devel, is the measured instance
    /// (divergences.toml). A linker symlink whose chain leaves the
    /// package or lands on a different file points at a runtime home
    /// elsewhere and does not credit.
    fn lib_combined_home(pkg: &Pkg, fname: &str) -> bool {
        let (dir, base) = match fname.rfind('/') {
            Some(i) => (&fname[..i + 1], &fname[i + 1..]),
            None => ("", fname),
        };
        let Some(idx) = base.find(".so.") else {
            return false;
        };
        let linker = format!("{dir}{}", &base[..idx + 3]);
        let Some(link) = pkg.files.iter().find(|f| f.name == linker) else {
            return false;
        };
        if !pkgfile::is_symlink(link.mode) {
            return false;
        }
        matches!(pkg.readlink(link), Some(resolved) if resolved.name == fname)
    }

    fn check_normal_rpaths_in_buildconfig(
        &self,
        pkg: &Pkg,
        fname: &str,
        fd: &FileData,
        out: &mut Filter,
    ) {
        if fd.is_buildconfig {
            if let Some(ln) = pkg.grep(&self.buildconfig_rpath_re, fname) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "rpath-in-buildconfig",
                    &[fname, "lines", &ln.to_string()],
                );
            }
        }
    }

    fn check_normal_bin(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        st: &mut PkgState,
        out: &mut Filter,
    ) {
        // A %ghost entry is bookkeeping, not payload: the package
        // installs no file, and the header mode placeholder (regular
        // file type with permission bits 0) is not a permission.
        if pkgfile.is_ghost() {
            return;
        }
        if let Ok(Some(caps)) = self.bin_re.captures(fname) {
            if pkgfile.mode & 0o111 == 0 {
                // A helper library dot-sourced by the package own
                // entry points is not an entry point itself.
                if sourced_by_sibling_script(pkg, fname) {
                    return;
                }
                // Data files shipped in a bin dir by convention are not
                // entry points either, unless they carry a shebang.
                if is_bin_data_file(fname) && !file_has_shebang(pkg, fname) {
                    return;
                }
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "non-executable-in-bin",
                    &[fname, &format!("{:o}", pkgfile.mode & 0o7777)],
                );
            } else if let Some(exe) = caps.get(1).map(|m| m.as_str()) {
                // FilesCheck.py:1169-1171: only regular executable files feed
                // the duplicate-executable check.
                if !exe.contains('/') {
                    // An unknown inode (0) registers no hardlink
                    // identity, mirroring the inode_basenames guard:
                    // a (rdev, 0) key could otherwise alias unrelated
                    // files whose inode the header does not know.
                    if pkgfile.inode != 0 {
                        st.bindir_inodes
                            .insert(fname.to_string(), (pkgfile.rdev, pkgfile.inode));
                    }
                    st.bindir_exes
                        .entry(exe.to_string())
                        .or_default()
                        .push(fname.to_string());
                }
            }
        }
    }

    fn check_normal_world_w(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        let perm = pkgfile.mode & 0o7777;
        // world-writable
        if perm & 0o002 != 0 {
            add_info(
                out,
                Level::Error,
                pkg,
                "world-writable",
                &[fname, &format!("{:o}", perm)],
            );
        }
    }

    fn check_normal_perl_dep(&self, pkg: &Pkg, fname: &str, st: &mut PkgState) {
        if st.perl_dep_error {
            return;
        }
        // The base package itself cannot carry the dependency.
        if pkg.name == "perl-base" {
            return;
        }
        let caps = match self.perl_re.captures(fname) {
            Ok(Some(c)) => c,
            _ => return,
        };
        let vers = if self.perl_version_trick {
            format!(
                "{}.{}",
                caps.get(1).map(|m| m.as_str()).unwrap_or(""),
                caps.get(2).map(|m| m.as_str()).unwrap_or("")
            )
        } else {
            format!(
                "{}{}",
                caps.get(1).map(|m| m.as_str()).unwrap_or(""),
                caps.get(2).map(|m| m.as_str()).unwrap_or("")
            )
        };
        if !perl_base_credited(&DepLists::of_pkg(pkg), &vers) {
            // No credited form of its own: the decision moves to
            // `after_checks`, where an anchor sibling can still
            // credit it (issue #862).
            st.nodep_candidates.push(NodepCandidate {
                name: pkg.name.clone(),
                arch: pkg.arch.clone(),
                source: source_key(pkg),
                base: "perl-base",
                version: vers,
                anchors: anchor_names(pkg),
            });
            st.perl_dep_error = true;
        }
    }

    fn check_normal_python_dep(&self, pkg: &Pkg, fname: &str, st: &mut PkgState) {
        if st.python_dep_error {
            return;
        }
        // The base packages themselves cannot carry the dependency.
        if pkg.name == "python-base" || pkg.name == "python3-base" {
            return;
        }
        let caps = match self.python_re.captures(fname) {
            Ok(Some(c)) => c,
            _ => return,
        };
        let ver = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if !python_base_credited(&DepLists::of_pkg(pkg), ver) {
            // No credited form of its own: the decision moves to
            // `after_checks`, where an anchor sibling can still
            // credit it (issue #862).
            st.nodep_candidates.push(NodepCandidate {
                name: pkg.name.clone(),
                arch: pkg.arch.clone(),
                source: source_key(pkg),
                base: "python-base",
                version: ver.to_string(),
                anchors: anchor_names(pkg),
            });
            st.python_dep_error = true;
        }
    }

    /// The reference's `python_bytecode_to_script`.
    /// Python bytecode magic values, mirroring the reference's
    /// `_python_magic_values` dict. The table lives in
    /// `data/python-magic-values.toml`, baked in like the Go
    /// toolchain floor so an installed binary needs no data dir
    /// next to it.
    fn python_magic_values(version: &str) -> &'static [u32] {
        python_magic_table()
            .iter()
            .find(|entry| entry.version == version)
            .map(|entry| entry.magics.as_slice())
            .unwrap_or(&[])
    }

    /// Read a little-endian u32 from the first 4 bytes, like the
    /// reference's `py_demarshal_long`.
    fn demarshal_long(b: &[u8]) -> u32 {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    /// Magic number from the start of a .pyc file.
    fn pyc_magic_from_chunk(chunk: &[u8]) -> u32 {
        Self::demarshal_long(&chunk[..4]) & 0xffff
    }

    /// mtime from the .pyc header, or None if not present (PEP 552).
    fn pyc_mtime_from_chunk(chunk: &[u8]) -> Option<u32> {
        if chunk.len() < 12 {
            return None;
        }
        let magic = Self::pyc_magic_from_chunk(chunk);
        let second = Self::demarshal_long(&chunk[4..8]);
        // 3390 is the first 3.7 magic value
        if magic >= 3390 {
            if second == 0 {
                return Some(Self::demarshal_long(&chunk[8..12]));
            }
            return None;
        }
        Some(second)
    }

    /// Expected magic values and version for a .pyc path, mirroring
    /// `get_expected_pyc_magic`. Returns (magics, version_from_path).
    fn expected_pyc_magic(&self, path: &str) -> (Option<Vec<u32>>, Option<String>) {
        let ver_from_path = self
            .python_re
            .captures(path)
            .ok()
            .flatten()
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());
        let expected_version = ver_from_path.clone().or_else(|| {
            if self.python_default_version.is_empty() {
                None
            } else {
                Some(self.python_default_version.clone())
            }
        });
        let magics = expected_version.as_deref().and_then(|v| {
            let m = Self::python_magic_values(v);
            if m.is_empty() {
                None
            } else if v == "3.0" || v == "3.1" {
                // Python 3.0/3.1 always use the value one higher
                Some(m.iter().map(|x| x + 1).collect())
            } else {
                Some(m.to_vec())
            }
        });
        (magics, ver_from_path)
    }

    /// Decide whether a wrong-magic finding should be emitted for a .pyc.
    /// Returns the level and detail parts, or None when the magic matches.
    fn pyc_magic_check(&self, fname: &str, found_magic: u32) -> Option<(Level, Vec<String>)> {
        let (exp_magic, exp_version) = self.expected_pyc_magic(fname);
        let exp = exp_magic?;
        if exp.contains(&found_magic) {
            return None;
        }
        // Find the version name for the found magic value: the
        // first table entry containing it, in ascending version
        // order (the file's order is significant).
        let mut found_version = "unknown";
        for entry in python_magic_table() {
            if entry.magics.contains(&found_magic) {
                found_version = entry.version.as_str();
                break;
            }
        }
        let exp_str = exp
            .iter()
            .map(|m| m.to_string())
            .collect::<Vec<_>>()
            .join(" or ");
        let exp_ver = exp_version
            .as_deref()
            .unwrap_or(&self.python_default_version);
        let detail = format!(
            "expected {} ({}), found {} ({})",
            exp_str, exp_ver, found_magic, found_version
        );
        // E when the expected version came from the .pyc path, W otherwise.
        let level = if exp_version.is_some() {
            Level::Error
        } else {
            Level::Warning
        };
        Some((level, vec![fname.to_string(), detail]))
    }

    /// Decide whether an inconsistent-mtime finding should be emitted.
    /// Returns the detail parts, or None. Per rpmlint#1331 (open, unmerged),
    /// only a stale .pyc (older than the source) is reported; a newer .pyc
    /// is a local-build artifact.
    fn pyc_mtime_check(
        pyc_timestamp: Option<u32>,
        src_mtime: u64,
        fname: &str,
        src_name: &str,
    ) -> Option<Vec<String>> {
        let ts = pyc_timestamp?;
        if (ts as u64) < src_mtime {
            Some(vec![
                fname.to_string(),
                ts.to_string(),
                src_name.to_string(),
                src_mtime.to_string(),
            ])
        } else {
            None
        }
    }

    /// True when `fname` is a PEP 3147 cache file whose cache tag names a
    /// different CPython version than the `pythonX.Y` tree it ships in (for
    /// example a `cpython-312` cache file under `python3.13`). The tree's
    /// interpreter never consults such a file -- the cache filename is keyed
    /// to the other version -- so its embedded timestamp cannot make the
    /// shipped source's bytecode stale in this tree. (The wrong-magic
    /// check does not take the shape over either: its magic table ends
    /// at 3.7, so for a current tree version it returns no finding and
    /// the file is silent in both tags.) Anything that does not parse
    /// (no PEP 3147 tag, a non-CPython tag, no version in the tree
    /// path) returns false: the mtime check keeps its say.
    fn pyc_cache_version_mismatch(&self, fname: &str) -> bool {
        let Ok(Some(caps)) = self.python_bytecode_pep3147_re.captures(fname) else {
            return false;
        };
        let Some(tag) = caps.get(3).map(|m| m.as_str()) else {
            return false;
        };
        let Some(digits) = tag.strip_prefix("cpython-") else {
            return false;
        };
        if digits.len() < 2 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        let tag_version = format!("{}.{}", &digits[..1], &digits[1..]);
        let Ok(Some(tree)) = self.python_re.captures(fname) else {
            return false;
        };
        let Some(tree_version) = tree.get(1).map(|m| m.as_str()) else {
            return false;
        };
        // A bare `python3` tree pins no minor version to compare against.
        if !tree_version.contains('.') {
            return false;
        }
        tag_version != tree_version
    }

    /// True when `fname` sits at least one directory level below a
    /// `__pycache__` directory -- the cache directory is not the file's
    /// parent, as in a byte-compiled tree copied into a documentation
    /// payload, where the compiled tree's own directory structure is
    /// mirrored below `__pycache__`. No import lookup reads such a file
    /// as bytecode: a PEP 3147 cache entry is a direct child of
    /// `__pycache__`, and a legacy sourceless module is a direct child
    /// of its module directory. A file directly inside `__pycache__`,
    /// and any path with no non-parent `__pycache__` component, returns
    /// false: the source checks keep their say.
    fn pyc_nested_below_cache_dir(fname: &str) -> bool {
        let parts: Vec<&str> = fname.split('/').collect();
        if parts.len() < 3 {
            return false;
        }
        // Directory components other than the file's parent directory:
        // every component between the leading segment and the
        // second-to-last one.
        parts[1..parts.len() - 2].contains(&"__pycache__")
    }

    /// The library-tree prefixes of the interpreters this package
    /// ships: for a regular executable file named
    /// `python<major>.<minor>` with an optional trailing `t` for a
    /// free-threaded build in a `bin` directory, the tree
    /// `<prefix>/lib/python<major>.<minor>[t]/` its modules live in
    /// (the measured self-contained shape: `/opt/testing/bin/python3.13`
    /// with `/opt/testing/lib/python3.13/`). The tree is `lib` only,
    /// never `lib64`. Unversioned or partially versioned names,
    /// non-regular or non-executable entries, interpreters outside a
    /// `bin` directory, and interpreters under `/usr/local` (user
    /// territory, not a shipped payload) earn no tree.
    fn interpreter_lib_trees(pkg: &Pkg) -> Vec<String> {
        let mut trees = Vec::new();
        for f in &pkg.files {
            if !pkgfile::is_reg(f.mode) || f.mode & 0o111 == 0 {
                continue;
            }
            let Some(slash) = f.name.rfind('/') else {
                continue;
            };
            let base = &f.name[slash + 1..];
            if !Self::is_versioned_python_name(base) {
                continue;
            }
            let dir = &f.name[..slash];
            let Some(prefix) = dir.strip_suffix("/bin") else {
                continue;
            };
            // /usr/local is user territory: no distro package ships
            // an interpreter anywhere under it, and a user-installed
            // interpreter is not this package's payload.
            if prefix == "/usr/local" || prefix.starts_with("/usr/local/") {
                continue;
            }
            trees.push(format!("{prefix}/lib/{base}/"));
        }
        trees
    }

    /// Whether `base` is a fully versioned interpreter name:
    /// `python` followed by `<digits>.<digits>` with an optional
    /// trailing `t` for a free-threaded build, and nothing else.
    /// Any other trailing letter fails closed.
    fn is_versioned_python_name(base: &str) -> bool {
        let Some(rest) = base.strip_prefix("python") else {
            return false;
        };
        let Some((maj, min)) = rest.split_once('.') else {
            return false;
        };
        let min = min.strip_suffix('t').unwrap_or(min);
        !maj.is_empty()
            && !min.is_empty()
            && maj.bytes().all(|b| b.is_ascii_digit())
            && min.bytes().all(|b| b.is_ascii_digit())
    }

    /// The absolute path a symlink chain resolves to when it leaves
    /// the package: follows `Pkg::readlink`'s walk, but where
    /// `readlink` reports `None` because the next path is not
    /// shipped, that path is the chain's resolution. Returns `None`
    /// when the chain resolves inside the package or cycles without
    /// leaving it.
    fn symlink_exit_path(pkg: &Pkg, src: &PkgFile) -> Option<String> {
        let mut current = pkg.files.iter().find(|f| f.name == src.name)?;
        for _ in 0..pkg.files.len() {
            if current.linkto.is_empty() {
                return None;
            }
            let joined = if current.linkto.starts_with('/') {
                current.linkto.clone()
            } else {
                match current.name.rfind('/') {
                    Some(i) => format!("{}/{}", &current.name[..i], current.linkto),
                    None => current.linkto.clone(),
                }
            };
            let linkpath = crate::pkg::normalize_path(&joined);
            match pkg.files.iter().find(|f| f.name == linkpath) {
                Some(next) => current = next,
                None => return Some(linkpath),
            }
        }
        None
    }

    fn python_bytecode_to_script(&self, path: &str) -> Option<String> {
        if let Ok(Some(caps)) = self.python_bytecode_pep3147_re.captures(path) {
            return Some(format!(
                "{}/{}.py",
                caps.get(1).map(|m| m.as_str()).unwrap_or(""),
                caps.get(2).map(|m| m.as_str()).unwrap_or("")
            ));
        }
        if let Ok(Some(caps)) = self.python_bytecode_re.captures(path) {
            return Some(format!(
                "{}.py",
                caps.get(1).map(|m| m.as_str()).unwrap_or("")
            ));
        }
        None
    }

    fn check_normal_python_source(
        &self,
        pkg: &Pkg,
        fname: &str,
        fd: &FileData,
        st: &mut PkgState,
        out: &mut Filter,
    ) {
        let source_file = match self.python_bytecode_to_script(fname) {
            Some(s) => s,
            None => return,
        };
        // A bytecode file nested below a `__pycache__` directory is
        // not in a location any import lookup reads as bytecode, so
        // the without-source finding does not apply to it. The magic
        // and mtime checks below keep their say whenever its source
        // is shipped and resolves.
        let below_cache_dir = Self::pyc_nested_below_cache_dir(fname);
        // A bytecode file inside the library tree of an interpreter
        // this package ships is that interpreter's own payload: a
        // self-contained bundle ships its standard library sourceless
        // by design, next to the interpreter that runs it. The
        // without-source finding does not apply to it either; the
        // magic and mtime checks keep their say on the same terms.
        let in_shipped_tree = st
            .bytecode_interpreter_trees
            .iter()
            .any(|tree| fname.starts_with(tree.as_str()));
        match pkg.files.iter().find(|f| f.name == source_file) {
            None => {
                if !below_cache_dir && !in_shipped_tree {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "python-bytecode-without-source",
                        &[fname],
                    );
                }
            }
            Some(src) => {
                let srcfile = match pkg.readlink(src) {
                    Some(s) => s,
                    None => {
                        if !below_cache_dir && !in_shipped_tree {
                            // The source ships only as a symlink whose
                            // chain leaves the package; a package of
                            // the same build may ship the file the
                            // chain resolves to (singlespec
                            // cross-flavour dedup). Record the
                            // candidate and decide in `after_checks`,
                            // when the run's file set and the build's
                            // completeness are known. A chain with no
                            // decidable exit path (a cycle) fires here,
                            // as today.
                            match Self::symlink_exit_path(pkg, src) {
                                Some(target) => {
                                    st.bytecode_candidates.push(BytecodeCandidate {
                                        name: pkg.name.clone(),
                                        arch: pkg.arch.clone(),
                                        fname: fname.to_string(),
                                        target,
                                        build_key: crate::checks::shared::binary_source_key(pkg),
                                    });
                                }
                                None => {
                                    add_info(
                                        out,
                                        Level::Warning,
                                        pkg,
                                        "python-bytecode-without-source",
                                        &[fname],
                                    );
                                }
                            }
                        }
                        return;
                    }
                };

                // Verify the magic ABI value embedded in the .pyc header.
                if fd.chunk.len() >= 4 {
                    let found_magic = Self::pyc_magic_from_chunk(&fd.chunk);
                    if let Some((level, details)) = self.pyc_magic_check(fname, found_magic) {
                        let refs: Vec<&str> = details.iter().map(|s| s.as_str()).collect();
                        add_info(out, level, pkg, "python-bytecode-wrong-magic-value", &refs);
                    }
                }

                // Verify the timestamp embedded in the .pyc header matches
                // the mtime of the .py file. A cache file keyed to a
                // different CPython version than its tree is never read by
                // that tree's interpreter, so skip it here (see
                // pyc_cache_version_mismatch).
                if !self.pyc_cache_version_mismatch(fname)
                    && let Some(details) = Self::pyc_mtime_check(
                        Self::pyc_mtime_from_chunk(&fd.chunk),
                        srcfile.mtime,
                        fname,
                        &srcfile.name,
                    )
                {
                    let refs: Vec<&str> = details.iter().map(|s| s.as_str()).collect();
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "python-bytecode-inconsistent-mtime",
                        &refs,
                    );
                }
            }
        }
    }

    fn check_normal_exec(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        fd: &mut FileData,
        out: &mut Filter,
    ) {
        let mode = pkgfile.mode;
        let mode_is_exec = mode & 0o111 != 0;
        if mode_is_exec {
            if pkg.config_files.iter().any(|c| c == fname)
                && !self.file_granted(&pkg.name, fname, "executable-marked-as-config-file")
            {
                // Severity split on the noreplace flag (see the
                // divergence ledger): a
                // %config(noreplace) executable warns instead of
                // erroring. The noreplace marking is deliberate -- the
                // packager opted into keep-local-edits semantics for
                // this file, and for hook-style files the execution is
                // the design -- so the finding stays visible for the
                // maintainer's call and can be suppressed per package,
                // but it does not fail the build. A plain %config
                // executable carries no such signal and keeps the
                // reference's error.
                let level = if pkgfile.is_noreplace() {
                    Level::Warning
                } else {
                    Level::Error
                };
                add_info(
                    out,
                    level,
                    pkg,
                    "executable-marked-as-config-file",
                    &[fname],
                );
            }
            // Set when only the text gate below marks the file: that is
            // the population the reference tags script-without-shebang,
            // renamed to spurious-executable-perm by the port (#426). The
            // finding carries the old tag as its filter alias so rpmlintrc
            // opt-outs written against it keep working (#524).
            let mut renamed_from_sws = false;
            if !fd.nonexec_file {
                // doc_regex and log_regex checked earlier, no match,
                // check rest of usual cases here.  Sourced scripts have
                // their own check, so disregard them here.
                let name_based = fname.ends_with(".pc")
                    || is_match(&self.compr_re, fname)
                    || is_match(&self.includefile_re, fname)
                    || is_match(&self.develfile_re, fname)
                    || fname.starts_with("/etc/logrotate.d/");
                // Data file with spurious executable bit: a text file
                // with no shebang, not an ELF binary, and not in a
                // script path (those keep script-without-shebang). The
                // istext gate matches the reference, which early-returns
                // on non-text in the same code path and stays silent
                // there, so the port warns nowhere the reference is
                // silent. Libtool .la files in lib paths are exempt,
                // mirroring the reference (its devel-file regex covers
                // .a but not .la, and its script-without-shebang path
                // exempts them); check_normal_text carries the same
                // exemption, but this gate runs first for these files
                // (#493).
                let text_gate = fd.istext
                    && fd.interpreter.is_none()
                    && !pkgfile.magic.starts_with("ELF")
                    && !is_match(&self.script_re, fname)
                    && !(is_match(&self.lib_path_re, fname) && fname.ends_with(".la"));
                fd.nonexec_file = name_based || text_gate;
                renamed_from_sws = text_gate && !name_based;
            }
            // Vendored source payload is read or built from, not
            // executed in place, so a stray exec bit on one of its
            // text files is not the defect this finding names: the
            // renamed population (marked by the text gate alone) is
            // covered by `script_is_source_data`, the gate the
            // interpreter findings in source trees use, with its
            // bounds -- a file directly in a script directory and
            // a %doc row never count. This emission adds one arm
            // the interpreter findings do not take: a file under
            // /usr/src/ is source payload by place, whatever the
            // shipping package is called, because that tree is
            // where shipped source code lives. The name-based
            // setters and the doc/log paths are the reference's own
            // spurious-executable-perm population and stay ungated.
            let source_credited = renamed_from_sws
                && !pkg.doc_files.iter().any(|d| d == fname)
                && (script_is_source_data(&pkg.name, fname) || fname.starts_with("/usr/src/"));
            if fd.nonexec_file && !source_credited && !mingw_dll_a_perm_exempt(&pkg.name, fname) {
                if renamed_from_sws {
                    let mut finding = make_finding(
                        &pkg.name,
                        &pkg.arch,
                        Level::Warning,
                        "spurious-executable-perm",
                        vec![fname.to_string()],
                        None,
                    );
                    finding.filter_alias = Some("script-without-shebang");
                    out.add_info(finding);
                } else {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "spurious-executable-perm",
                        &[fname],
                    );
                }
            }
        }
    }

    /// Whether `fname` lies inside a SELinux policy store,
    /// `/etc/selinux/<policy>/active/…`: the store is libsemanage's
    /// managed area — compiled policy modules the tooling rewrites on
    /// every semodule operation, never administrator-edited
    /// configuration. The policy component is required: files placed
    /// directly under `/etc/selinux/` or a policy directory do not
    /// qualify.
    fn selinux_policy_store_path(fname: &str) -> bool {
        let Some(rest) = fname.strip_prefix("/etc/selinux/") else {
            return false;
        };
        let mut components = rest.split('/');
        matches!(
            (components.next(), components.next(), components.next()),
            (Some(policy), Some("active"), Some(_)) if !policy.is_empty()
        )
    }

    fn check_normal_non_conf_in_etc(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        out: &mut Filter,
    ) {
        // A non-config file under /etc is usually a packaging mistake, but
        // drop-in directories managed by other tooling are exempt: the
        // reference exempts /etc/ld.so.conf.d/, and /etc/alternatives/ is
        // managed by the alternatives system (upstream rpmlint#1137).
        // The SELinux policy store is libsemanage's managed area and is
        // exempt for the same reason.
        if fname.starts_with("/etc/")
            && !pkgfile.is_config()
            && !pkgfile.is_ghost()
            && !fname.starts_with("/etc/ld.so.conf.d/")
            && !fname.starts_with("/etc/alternatives/")
            && !Self::selinux_policy_store_path(fname)
        {
            add_info(out, Level::Warning, pkg, "non-conffile-in-etc", &[fname]);
        }
    }

    fn check_normal_python_noarch(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if pkg.arch == "noarch" && fname.starts_with("/usr/lib64/python") {
            add_info(
                out,
                Level::Error,
                pkg,
                "noarch-python-in-64bit-path",
                &[fname],
            );
        }
    }

    /// Uniformly gzipped icon theme credit for `gzipped-svg-icon`:
    /// a package whose own scalable icon payload ships at least
    /// `SVGZ_THEME_MIN_GZIPPED` gzipped icons, with the gzipped
    /// icons making up at least nine tenths of the payload's vector
    /// files (`.svg` + `.svgz` regular files under scalable icon
    /// directories), ships a theme in its native format rather than
    /// a set of individually misplaced icons, so the per-icon
    /// finding does not apply to it. Below theme scale, and for
    /// large but mixed payloads, the finding fires per icon.
    fn svgz_theme_credit(&self, pkg: &Pkg) -> bool {
        let (mut svgz, mut svg) = (0usize, 0usize);
        for f in &pkg.files {
            if pkgfile::is_reg(f.mode) && is_match(&self.scalable_icon_re, &f.name) {
                if f.name.ends_with(".svgz") {
                    svgz += 1;
                } else if f.name.ends_with(".svg") {
                    svg += 1;
                }
            }
        }
        svgz >= SVGZ_THEME_MIN_GZIPPED && svgz >= 9 * svg
    }

    /// The reproducibility comparison for `gzip-mtime-after-source-date-epoch`:
    /// a regular `*.gz` file (not `.tar.gz`; `.tgz` does not end in `.gz`)
    /// outside the `/usr/share/man` and `/usr/share/info` trees, starting
    /// with the gzip magic, whose header MTIME (bytes 4-7, little-endian)
    /// is non-zero and later than SOURCE_DATE_EPOCH plus 2 s. The 2 s
    /// slack absorbs the rounding of the two clocks being compared.
    /// Without a known SOURCE_DATE_EPOCH nothing fires.
    fn gzip_mtime_after_sde(fname: &str, chunk: &[u8], sde: Option<i64>) -> bool {
        let Some(sde) = sde else { return false };
        if !fname.ends_with(".gz") || fname.ends_with(".tar.gz") {
            return false;
        }
        if fname.starts_with("/usr/share/man/") || fname.starts_with("/usr/share/info/") {
            return false;
        }
        // The magic includes the method byte: only deflate (8) is a
        // gzip stream whose header bytes 4..8 are an MTIME; a
        // reserved method's header must not contribute its bytes as
        // a timestamp.
        if chunk.len() < 10 || chunk[0] != 0x1f || chunk[1] != 0x8b || chunk[2] != 8 {
            return false;
        }
        let mtime = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        mtime != 0 && i64::from(mtime) > sde.saturating_add(2)
    }

    fn check_normal_gzip_mtime(
        &self,
        pkg: &Pkg,
        fname: &str,
        fd: &FileData,
        st: &PkgState,
        out: &mut Filter,
    ) {
        // rpm clamps the payload's file mtimes to SOURCE_DATE_EPOCH but
        // not timestamps stored inside files, so a file the build
        // generated and gzipped without -n embeds the build wall clock.
        if Self::gzip_mtime_after_sde(fname, &fd.chunk, st.source_date_epoch) {
            add_info(
                out,
                Level::Warning,
                pkg,
                "gzip-mtime-after-source-date-epoch",
                &[fname],
            );
        }
    }

    fn check_normal_gzipped_svg(&self, pkg: &Pkg, fname: &str, st: &PkgState, out: &mut Filter) {
        if st.svgz_theme {
            return;
        }
        if fname.ends_with(".svgz")
            && !pkg.files.iter().any(|f| f.name == fname[..fname.len() - 1])
            && is_match(&self.scalable_icon_re, fname)
        {
            add_info(out, Level::Warning, pkg, "gzipped-svg-icon", &[fname]);
        }
    }

    fn check_normal_pem(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if !fname.ends_with(".pem") || pkg.ghost_files.iter().any(|g| g == fname) {
            return;
        }
        // NB: the reference's regexes are anchored without re.M, so they only
        // match a file whose whole content is the BEGIN line; replicated here.
        if pkg.grep(&self.start_certificate_re, fname).is_some() {
            add_info(out, Level::Warning, pkg, "pem-certificate", &[fname]);
        }
        if pkg.grep(&self.start_private_key_re, fname).is_some() {
            add_info(out, Level::Error, pkg, "pem-private-key", &[fname]);
        }
    }

    fn check_normal_tcl(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if is_match(&self.tcl_re, fname) {
            add_info(out, Level::Error, pkg, "tcl-extension-file", &[fname]);
        }
    }

    /// Whether `wrong-script-end-of-line-encoding` applies to a text
    /// file (issue #849): the file is a script when it carries a kernel
    /// interpreter line, when its name carries a Unix shell-script
    /// extension, or when it is an executable file in a script location
    /// (the `script_re` paths). A kernel interpreter line names an
    /// absolute interpreter path; a leading `#!` followed by anything
    /// else is source syntax (a Rust `#![...]` inner attribute), not an
    /// interpreter line. Shell-script extensions name scripts on their
    /// own because shell scripts are routinely sourced and carry no
    /// interpreter line; language source extensions (.py, .pl, .rb,
    /// ...) name modules as readily as scripts, so they make a file a
    /// script only through its interpreter line; `.ps1` sits with
    /// them rather than with the shell extensions because the
    /// PowerShell interpreter accepts CRLF, so a dot-sourced `.ps1`
    /// is not corrupted by it. A
    /// `.bat`/`.cmd` name
    /// suppresses the name- and location-based arms — CRLF is the
    /// correct end-of-line encoding for a Windows batch file — while an
    /// interpreter line still applies, because a file starting with
    /// `#!` is executed by that interpreter. Matching of both
    /// extension sets is case-insensitive.
    fn script_eol_applies(
        fname: &str,
        interpreter: Option<&str>,
        mode_is_exec: bool,
        in_script_path: bool,
    ) -> bool {
        if interpreter.is_some_and(|i| i.starts_with('/')) {
            return true;
        }
        let lower = fname.to_lowercase();
        if lower.ends_with(".bat") || lower.ends_with(".cmd") {
            return false;
        }
        const SHELL_SCRIPT_EXTS: [&str; 8] = [
            ".sh", ".bash", ".zsh", ".ksh", ".csh", ".tcsh", ".fish", ".bsh",
        ];
        if SHELL_SCRIPT_EXTS.iter().any(|e| lower.ends_with(e)) {
            return true;
        }
        in_script_path && mode_is_exec
    }

    /// Whether `wrong-file-end-of-line-encoding` applies to a doc
    /// file: its peek chunk must show an end-of-line encoding that
    /// is wrong on Unix — CRLF line endings, or CR-only line
    /// endings (the chunk carries carriage returns and no line
    /// feed, so the carriage returns are the line terminators).
    /// A carriage return inside an otherwise LF-ended file is
    /// content (a recorded progress marker, a data byte), not an
    /// encoding. Formats whose own specification or interpreter
    /// makes CRLF the correct encoding are out of the finding's
    /// scope for the CRLF shape; see `crlf_is_native`. That credit
    /// does not extend to CR-only endings — no credited format
    /// terminates lines with a bare carriage return — so a CR-only
    /// chunk fires whatever the file's name. Logs shipped by a
    /// compiler test-results package are out of scope for every
    /// ending shape; see `is_compiler_test_log`.
    fn doc_eol_is_wrong(pkg_name: &str, fname: &str, chunk: &[u8]) -> bool {
        if Self::is_compiler_test_log(pkg_name, fname) {
            return false;
        }
        if chunk.contains(&b'\r') && !chunk.contains(&b'\n') {
            return true;
        }
        if Self::crlf_is_native(fname, chunk) {
            return false;
        }
        chunk.windows(2).any(|w| w == b"\r\n")
    }

    /// Whether a doc file is a test log shipped by a compiler
    /// test-results package (named `gcc<version>-testresults`,
    /// the version a run of ASCII digits): the package's payload
    /// is the recorded output of the compiler's own test suites
    /// (the ACATS report generator emits CRLF; DejaGnu logs carry
    /// the tested programs' own line endings). The log is a byte
    /// record of a test run — normalising its line endings would
    /// falsify the record, and a re-run reproduces the same
    /// bytes. The credit is the package family plus the log name:
    /// a log shipped anywhere else, and any other file in such a
    /// package, is judged on its own shape.
    fn is_compiler_test_log(pkg_name: &str, fname: &str) -> bool {
        let lower = pkg_name.to_lowercase();
        let Some(version) = lower
            .strip_prefix("gcc")
            .and_then(|rest| rest.strip_suffix("-testresults"))
        else {
            return false;
        };
        if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        fname.to_lowercase().ends_with(".log")
    }

    /// Whether CRLF is the correct end-of-line encoding for a file
    /// of this name or content: Windows batch files (the cmd.exe
    /// interpreter expects CRLF line endings), PowerShell scripts
    /// (the interpreter accepts CRLF, so the encoding corrupts
    /// nothing; see `script_eol_applies`), iCalendar and mail
    /// message files (their formats delimit lines with CRLF),
    /// MSBuild and Visual Studio project files (the toolchain
    /// writes them with CRLF line endings), and
    /// shipped HTTP response messages (the HTTP message format
    /// delimits its lines with CRLF; the name alone does not
    /// decide -- the content must open with the status line,
    /// `HTTP/` followed by a version digit).
    /// Name matching is on the final suffix, case-insensitive.
    fn crlf_is_native(fname: &str, chunk: &[u8]) -> bool {
        let lower = fname.to_lowercase();
        const CRLF_NATIVE_EXTS: [&str; 9] = [
            ".bat", ".cmd", ".ps1", ".ics", ".eml", ".proj", ".props", ".vcxproj", ".sln",
        ];
        if CRLF_NATIVE_EXTS.iter().any(|e| lower.ends_with(e)) {
            return true;
        }
        lower.ends_with(".http")
            && chunk.starts_with(b"HTTP/")
            && chunk.get(5).is_some_and(|b| b.is_ascii_digit())
    }

    fn check_normal_text(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        fd: &mut FileData,
        out: &mut Filter,
    ) {
        if !fd.istext {
            return;
        }
        let mode = pkgfile.mode;
        let perm = mode & 0o7777;
        let mode_is_exec = mode & 0o111 != 0;
        let is_doc = pkg.doc_files.iter().any(|d| d == fname);
        // ignore perl module shebang -- TODO: disputed...
        if fname.ends_with(".pm") {
            fd.interpreter = None;
        }
        // sourced scripts should not be executable
        if is_match(&self.sourced_script_re, fname) {
            if let Some(interpreter) = fd.interpreter.as_deref() {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "sourced-script-with-shebang",
                    &[fname, interpreter, &fd.interpreter_args],
                );
            }
            if mode_is_exec {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "executable-sourced-script",
                    &[fname, &format!("{:o}", perm)],
                );
            }
        // ...but executed ones should
        } else if fd.interpreter.is_some() || mode_is_exec || is_match(&self.script_re, fname) {
            if let Some(interpreter) = fd.interpreter.clone() {
                // rpmlint#31: the interpreter check only applies to executable
                // files or files in script paths.
                if mode_is_exec || is_match(&self.script_re, fname) {
                    match self.interpreter_re.captures(&interpreter) {
                        Ok(Some(caps)) if caps.get(1).map(|m| m.as_str()) == Some("env") => {
                            // Test and harness payload is run by
                            // its harness, not executed in place as
                            // an installed entry point, so the env
                            // form of its interpreter line is not a
                            // defect there: `script_is_test_data`
                            // carries the shapes and their guards.
                            // Vendored source payload is read or
                            // built from, not executed in place,
                            // the same way: `script_is_source_data`
                            // carries the source-tree shapes, and
                            // its doc bound is the row itself -- a
                            // %doc file keeps the finding.
                            if !script_is_test_data(&pkg.name, fname)
                                && !(!is_doc && script_is_source_data(&pkg.name, fname))
                            {
                                add_info(
                                    out,
                                    Level::Error,
                                    pkg,
                                    "env-script-interpreter",
                                    &[fname, &interpreter, &fd.interpreter_args],
                                );
                            }
                        }
                        Ok(Some(_)) => {}
                        _ => {
                            // The interpreter line is wrong here,
                            // but in test or vendored source payload
                            // it is the harness's or upstream's
                            // business the same way as the env form
                            // above: the shared
                            // `script_is_test_data` and
                            // `script_is_source_data` gates carry
                            // the shapes and their guards, doc bound
                            // included, so this emission joins the
                            // gate family rather than adding a
                            // second one.
                            if !script_is_test_data(&pkg.name, fname)
                                && !(!is_doc && script_is_source_data(&pkg.name, fname))
                            {
                                add_info(
                                    out,
                                    Level::Error,
                                    pkg,
                                    "wrong-script-interpreter",
                                    &[fname, &interpreter, &fd.interpreter_args],
                                );
                            }
                        }
                    }
                }
            } else if !fd.nonexec_file
                && !(is_match(&self.lib_path_re, fname) && fname.ends_with(".la"))
            {
                add_info(out, Level::Error, pkg, "script-without-shebang", &[fname]);
            }
            // Files the owning program consumes by reading,
            // importing, sourcing or rendering are data, so an
            // interpreter line there marks content rather than a
            // script executed in place and the missing exec bit is
            // not a defect (issues #813, #845):
            // `non_executable_script_is_data` carries the shapes
            // and their guards. Test and harness payload is data
            // the same way -- a harness runs it by path, so the
            // missing exec bit is not a defect there either:
            // `script_is_test_data` carries those shapes and
            // their guards. A script whose own text marks it as
            // a sourced fragment -- a top-level `return` in a
            // POSIX-family shell script -- is not a defect
            // either: `non_executable_script_is_provable_fragment`
            // carries that proof. Scripts none of the shapes
            // cover keep the reference behaviour.
            if !mode_is_exec && !is_doc {
                if let Some(interpreter) = &fd.interpreter {
                    if interpreter.starts_with('/')
                        && !non_executable_script_is_data(
                            fname,
                            interpreter,
                            &fd.interpreter_args,
                            &pkg.files,
                            &self.python_lib_tree_re,
                        )
                        && !script_is_test_data(&pkg.name, fname)
                        && !non_executable_script_is_provable_fragment(
                            pkgfile,
                            fname,
                            interpreter,
                            &fd.interpreter_args,
                        )
                    {
                        add_info(
                            out,
                            Level::Error,
                            pkg,
                            "non-executable-script",
                            &[
                                fname,
                                &format!("{:o}", perm),
                                interpreter,
                                &fd.interpreter_args,
                            ],
                        );
                    }
                }
            }
            if fd.chunk.contains(&b'\r')
                && Self::script_eol_applies(
                    fname,
                    fd.interpreter.as_deref(),
                    mode_is_exec,
                    is_match(&self.script_re, fname),
                )
            {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "wrong-script-end-of-line-encoding",
                    &[fname],
                );
            }
        } else if is_doc && !is_match(&self.skipdocs_re, fname) {
            if Self::doc_eol_is_wrong(&pkg.name, fname, &fd.chunk) {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "wrong-file-end-of-line-encoding",
                    &[fname],
                );
            }
        }
        // Upstream rpmlint#40: the reference scans only its 2048-byte peek
        // chunk for the FSF address, missing it in longer files. The port
        // scans the whole file instead (divergences.toml), streaming it in
        // bounded windows so a large file never sits in memory twice.
        if self.fsf_address_matches(pkg, pkgfile, out) {
            add_info(out, Level::Warning, pkg, "incorrect-fsf-address", &[fname]);
        }
    }

    fn check_ldconfig(
        &self,
        pkg: &Pkg,
        fname: &str,
        _pkgfile: &PkgFile,
        st: &PkgState,
        out: &mut Filter,
    ) {
        // #1602: honor -p ldconfig interpreter. The check is satisfied by an
        // ldconfig call in the body (line-anchored, comment-skipping, matching
        // the reference's ^[^#]*ldconfig) OR by the interpreter itself being
        // ldconfig.
        let is_ldconfig = |script: &str, prog: &str| {
            is_match(&self.ldconfig_re, script)
                || prog
                    .split_whitespace()
                    .next()
                    .map(|p| p.rsplit('/').next().unwrap_or("") == "ldconfig")
                    .unwrap_or(false)
        };
        // The reference gates on lib_regex (anchored /lib(?:64)?/lib...),
        // not a `.so` substring: `.../libbasegfxlo.so-gdb.py` is not a library.
        if is_match(&self.lib_re, fname) {
            // Issue #569: ldconfig scans only the standard libdirs and
            // the directories a shipped /etc/ld.so.conf.d/*.conf snippet
            // names. A library anywhere else (GHC's
            // /usr/lib64/ghc-<ver>/lib tree, polymake's private tree) is
            // invisible to ldconfig whether or not the package runs it,
            // so the scriptlet test does not apply there; the reference
            // applies it to every lib_regex match (divergences.toml).
            let parent = fname.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
            if !STANDARD_LIBDIRS.contains(&parent) && !st.ldconfig_dirs.contains(parent) {
                return;
            }
            let postin_prog = pkg.scriptprog(librpm::Tag::POSTINPROG);
            let postun_prog = pkg.scriptprog(librpm::Tag::POSTUNPROG);
            if !is_ldconfig(&st.postin, &postin_prog) {
                // Mirror the reference (FilesCheck._check_file_normal_file_lib):
                // a missing scriptlet emits library-without-ldconfig-*, a
                // present-but-ldconfig-less one emits postin-without-ldconfig.
                // Emitting both was a port bug. A -p ldconfig interpreter
                // satisfies the check outright via is_ldconfig above. A
                // FileGrants entry naming this package, file and finding
                // suppresses the emission (see parse_file_grants).
                if st.postin.is_empty() {
                    if !self.file_granted(&pkg.name, fname, "library-without-ldconfig-postin") {
                        add_info(
                            out,
                            Level::Error,
                            pkg,
                            "library-without-ldconfig-postin",
                            &[fname],
                        );
                    }
                } else if !self.file_granted(&pkg.name, fname, "postin-without-ldconfig") {
                    add_info(out, Level::Error, pkg, "postin-without-ldconfig", &[fname]);
                }
            }
            if !is_ldconfig(&st.postun, &postun_prog) {
                if st.postun.is_empty() {
                    if !self.file_granted(&pkg.name, fname, "library-without-ldconfig-postun") {
                        add_info(
                            out,
                            Level::Error,
                            pkg,
                            "library-without-ldconfig-postun",
                            &[fname],
                        );
                    }
                } else if !self.file_granted(&pkg.name, fname, "postun-without-ldconfig") {
                    add_info(out, Level::Error, pkg, "postun-without-ldconfig", &[fname]);
                }
            }
        }
    }
}

// Upstream bug analyses and their dispositions:
// - #1602: ldconfig -p interpreter honored — FIXED behavior implemented.
// - #552: missing-dependency-to-crontabs base dir false positive — replicated as-is
//   until the 2026-10-26 FP-trim tightening (directory entries and daemon files
//   directly in /etc are no longer charged; see the FilesCheck divergence ledger).
// - #551: logrotate-log-dir-not-packaged — NOT PORTED (LogrotateCheck not yet
//   ported; the /var/log exclusion from rpmlint#551 defers to that port).
// - #771: hardlink catch-22 — ABANDONED, replicate reference exactly.

impl FilesCheck {
    /// `error_details` for `--explain`, mirroring the `__init__` dict
    /// (`FilesCheck.py:386-418`): uid/gid/compression texts, plus one
    /// `dir-or-file-in-*` entry per `DisallowedDirs`.
    pub fn register_error_details(config: &Config, out: &mut Filter) {
        let tbl = &config.configuration;
        let get_str = |k: &str| {
            tbl.get(k)
                .and_then(toml::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let get_strings = |k: &str| {
            tbl.get(k)
                .and_then(toml::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        let compress_ext = get_str("CompressExtension");
        out.set_error_detail(
            "non-standard-uid",
            format!(
                "A file in this package is owned by a non standard user.\nStandard users are:\n{}.",
                get_strings("StandardUsers").join(", ")
            ),
        );
        out.set_error_detail(
            "non-standard-gid",
            format!(
                "A file in this package is owned by a non standard group.\nStandard groups are:\n{}.",
                get_strings("StandardGroups").join(", ")
            ),
        );
        out.set_error_detail(
            "bidi-control-character",
            "The file contains Unicode bidirectional control characters.\nThese can be abused to make source code render differently from how\nit executes (trojan-source, CVE-2021-42574). Remove them unless\nthey are intentional (e.g. a test demonstrating the attack).".to_string(),
        );
        for (id, kind) in [
            ("manpage-not-compressed", "manual page"),
            ("infopage-not-compressed", "info page"),
        ] {
            out.set_error_detail(
                id,
                format!(
                    "This {kind} is not compressed with the {compress_ext} compression method\n(does not have the {compress_ext} extension). If the compression does not happen\nautomatically when the package is rebuilt, make sure that you have the\nappropriate rpm helper and/or config packages for your target distribution\ninstalled and try rebuilding again; if it still does not happen automatically,\nyou can compress this file in the %install section of the spec file."
                ),
            );
        }
        for d in get_strings("DisallowedDirs") {
            out.set_error_detail(
                &format!("dir-or-file-in-{}", d.trim_start_matches('/').replace('/', "-")),
                format!(
                    "A file in the package is located in {d}. It's not permitted\nfor packages to install files in this directory."
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;
    use crate::pkg::dep::{DepInfo, account_capability};
    use crate::pkg::pkgfile::{RPMFILE_CONFIG, RPMFILE_DOC, RPMFILE_GHOST, RPMFILE_NOREPLACE};

    fn test_config() -> Config {
        // Load the bundled defaults so the check sees the same configuration
        // as the real binary (empty Config::default would leave regexes like
        // MetaPackageRegexp empty, matching everything).
        let defaults: toml::Table = toml::from_str(include_str!("../../data/configdefaults.toml"))
            .expect("parse configdefaults");
        Config {
            configuration: defaults,
            ..Default::default()
        }
    }

    #[test]
    fn files_check_registers() {
        let _check = FilesCheck::new(&test_config());
    }

    #[test]
    fn ldconfig_regex_skips_comments() {
        // The reference uses ^[^#]*ldconfig: a %post mentioning ldconfig only
        // in a comment must NOT satisfy the check.
        let check = FilesCheck::new(&test_config());
        assert!(is_match(&check.ldconfig_re, "ldconfig"));
        assert!(is_match(&check.ldconfig_re, "echo hi\nldconfig"));
        assert!(
            !check
                .ldconfig_re
                .is_match("# run ldconfig later")
                .unwrap_or(true)
        );
        assert!(!check.ldconfig_re.is_match("   # ldconfig").unwrap_or(true));
    }

    fn fixture_path(name: &str) -> String {
        format!(
            "{}/../../tests/parity/pkg/inputs/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        )
    }

    /// Drive `FilesCheck` over `rpms` the way the lint loop drives a
    /// batch: one worker instance checks each package in order and
    /// exports its cross-package state after each one, the main
    /// instance merges the exports and runs `after_checks` once at the
    /// end. Returns the `(finding, rendered line)` pairs.
    fn run_files_check_session(
        rpms: &[&str],
        config: &Config,
    ) -> (Vec<(String, String)>, Vec<tempfile::TempDir>) {
        let mut dirs = Vec::new();
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        let mut worker = FilesCheck::new(config);
        let mut main = FilesCheck::new(config);
        for rpm in rpms {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let pkg = Pkg::open(std::path::Path::new(rpm), dir.path(), true).expect("open fixture");
            worker.check(&pkg, config, &mut out);
            if let Some(state) = worker.export_state() {
                main.import_state(state);
            }
            worker.reset();
            dirs.push(dir);
        }
        main.after_checks(config, &mut out);
        (out.results().to_vec(), dirs)
    }

    fn run_files_check(rpm: &str, config: &Config) -> (Vec<String>, tempfile::TempDir) {
        let (results, mut dirs) = run_files_check_session(&[rpm], config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        (names, dirs.pop().expect("one extraction dir"))
    }

    /// Drive `FilesCheck` over already-opened packages the way the lint
    /// loop drives a batch: one worker instance checks each package in
    /// order and exports its cross-package state after each one, the
    /// main instance merges the exports and runs `after_checks` once at
    /// the end. Returns the `(finding, rendered line)` pairs and their
    /// levels.
    fn run_files_check_pkgs(pkgs: &[Pkg], config: &Config) -> (Vec<(String, String)>, Vec<Level>) {
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        let mut worker = FilesCheck::new(config);
        let mut main = FilesCheck::new(config);
        for pkg in pkgs {
            worker.check(pkg, config, &mut out);
            if let Some(state) = worker.export_state() {
                main.import_state(state);
            }
            worker.reset();
        }
        main.after_checks(config, &mut out);
        (out.results().to_vec(), out.result_levels().to_vec())
    }

    /// The level one finding was emitted at, from `run_files_check_pkgs`
    /// output.
    fn level_of(results: &[(String, String)], levels: &[Level], finding: &str) -> Option<Level> {
        results
            .iter()
            .zip(levels)
            .find(|((name, _), _)| name == finding)
            .map(|(_, level)| *level)
    }

    fn assert_has(names: &[String], finding: &str) {
        assert!(
            names.iter().any(|n| n == finding),
            "expected {finding}, got: {names:?}"
        );
    }

    fn assert_lacks(names: &[String], finding: &str) {
        assert!(
            !names.iter().any(|n| n == finding),
            "unexpected {finding} in: {names:?}"
        );
    }

    #[test]
    fn missing_dependency_to_xinetd_is_gone() {
        // Issue #214: the rule was deleted outright (it contradicted
        // E obsolete-xinetd-requirement). A package shipping /etc/xinetd.d/
        // files must not get missing-dependency-to-xinetd from FilesCheck;
        // the deprecation signal moved to XinetdDepCheck.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.files = vec![PkgFile {
            name: "/etc/xinetd.d/daytime".to_string(),
            path: "/etc/xinetd.d/daytime".to_string(),
            ..Default::default()
        }];
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "missing-dependency-to-xinetd");
    }

    fn dep_named(name: &str) -> crate::pkg::dep::DepInfo {
        crate::pkg::dep::DepInfo {
            name: name.to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        }
    }

    /// Run the full FilesCheck over a package shipping a single file with the
    /// given dependency sets; return the emitted finding names.
    fn run_files_check_with_deps(
        file_name: &str,
        requires: Vec<crate::pkg::dep::DepInfo>,
        recommends: Vec<crate::pkg::dep::DepInfo>,
        suggests: Vec<crate::pkg::dep::DepInfo>,
    ) -> Vec<String> {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.files = vec![PkgFile {
            name: file_name.to_string(),
            path: file_name.to_string(),
            ..Default::default()
        }];
        pkg.requires = requires;
        pkg.recommends = recommends;
        pkg.suggests = suggests;
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        out.results().iter().map(|(n, _)| n.clone()).collect()
    }

    #[test]
    fn missing_dependency_to_logrotate_quiet_when_recommended() {
        // #388: the reference counts requires + recommends + suggests
        // (FilesCheck.py `_check_file_logrotate`); 30 of the 34 corpus false
        // positives were Recommends:/Suggests: logrotate (e.g. apcupsd).
        let names = run_files_check_with_deps(
            "/etc/logrotate.d/fcprobe",
            vec![],
            vec![dep_named("logrotate")],
            vec![],
        );
        assert_lacks(&names, "missing-dependency-to-logrotate");
    }

    #[test]
    fn missing_dependency_to_logrotate_quiet_when_suggested() {
        let names = run_files_check_with_deps(
            "/etc/logrotate.d/fcprobe",
            vec![],
            vec![],
            vec![dep_named("logrotate")],
        );
        assert_lacks(&names, "missing-dependency-to-logrotate");
    }

    #[test]
    fn missing_dependency_to_logrotate_fires_without_any_dep() {
        // Negative guard: with no logrotate dep of any kind the finding stays.
        let names = run_files_check_with_deps("/etc/logrotate.d/fcprobe", vec![], vec![], vec![]);
        assert_has(&names, "missing-dependency-to-logrotate");
    }

    /// Run the full FilesCheck over one package called `name`
    /// shipping exactly `files`; return the finding names.
    fn named_pkg_findings(name: &str, files: Vec<PkgFile>) -> Vec<String> {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = name.to_string();
        pkg.ghost_files = files
            .iter()
            .filter(|f| f.is_ghost())
            .map(|f| f.name.clone())
            .collect();
        pkg.files = files;
        let (results, _levels) = run_files_check_pkgs(&[pkg], &test_config());
        results.iter().map(|(n, _)| n.clone()).collect()
    }

    fn mode_file(name: &str, mode: u32) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            mode,
            ..Default::default()
        }
    }

    #[test]
    fn incoherent_logrotate_credits_shipped_daemon_name() {
        // A logrotate file named after a daemon
        // the same package ships as an executable is coherent
        // (cobbler ships /usr/bin/cobblerd and /etc/logrotate.d/cobblerd).
        let names = named_pkg_findings(
            "cobbler",
            vec![
                mode_file("/etc/logrotate.d/cobblerd", 0o100644),
                mode_file("/usr/bin/cobblerd", 0o100755),
            ],
        );
        assert_lacks(&names, "incoherent-logrotate-file");
    }

    #[test]
    fn incoherent_logrotate_daemon_credit_needs_an_executable() {
        // ceph-base shape: only a lib directory and a plain data
        // file are called `ceph` -- the `ceph` executable lives in
        // ceph-common -- so nothing credits and the finding stays.
        let names = named_pkg_findings(
            "ceph-base",
            vec![
                mode_file("/etc/logrotate.d/ceph", 0o100644),
                mode_file("/usr/lib64/ceph", 0o40755),
                mode_file("/usr/share/ceph", 0o100644),
            ],
        );
        assert_has(&names, "incoherent-logrotate-file");
    }

    #[test]
    fn incoherent_logrotate_daemon_credit_is_case_sensitive() {
        // The case credit compares the file name against the
        // package name only; a daemon whose shipped name differs
        // from the logrotate file's in case does not credit.
        let names = named_pkg_findings(
            "bar",
            vec![
                mode_file("/etc/logrotate.d/bard", 0o100644),
                mode_file("/usr/bin/BarD", 0o100755),
            ],
        );
        assert_has(&names, "incoherent-logrotate-file");
    }

    #[test]
    fn incoherent_logrotate_daemon_credit_is_per_package() {
        // The executable must ship in the SAME package: a sibling
        // package owning the daemon does not credit this package's
        // logrotate file.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut owner = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        owner.name = "daemon-owner".to_string();
        owner.files = vec![mode_file("/usr/bin/shared", 0o100755)];
        let mut logger = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        logger.name = "log-owner".to_string();
        logger.files = vec![mode_file("/etc/logrotate.d/shared", 0o100644)];
        let (results, _levels) = run_files_check_pkgs(&[owner, logger], &test_config());
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "incoherent-logrotate-file");
    }

    #[test]
    fn incoherent_logrotate_credits_case_only_difference() {
        // openQA ships /etc/logrotate.d/openqa.
        let names = named_pkg_findings(
            "openQA",
            vec![mode_file("/etc/logrotate.d/openqa", 0o100644)],
        );
        assert_lacks(&names, "incoherent-logrotate-file");
    }

    #[test]
    fn incoherent_logrotate_credits_logrotate_suffix() {
        // grommunio-sync ships /etc/logrotate.d/grommunio-sync.lr;
        // the .conf form strips the same way.
        let names = named_pkg_findings(
            "grommunio-sync",
            vec![mode_file("/etc/logrotate.d/grommunio-sync.lr", 0o100644)],
        );
        assert_lacks(&names, "incoherent-logrotate-file");
        let names = named_pkg_findings(
            "fcprobe",
            vec![mode_file("/etc/logrotate.d/fcprobe.conf", 0o100644)],
        );
        assert_lacks(&names, "incoherent-logrotate-file");
    }

    #[test]
    fn incoherent_logrotate_suffix_strip_is_exact_and_closed() {
        // Only .lr/.conf strip: other extensions and the slurm shape
        // (stem != the -config package's name) keep firing.
        for file in [
            "/etc/logrotate.d/fcprobe.txt",
            "/etc/logrotate.d/fcprobe.bak",
        ] {
            let names = named_pkg_findings("fcprobe", vec![mode_file(file, 0o100644)]);
            assert_has(&names, "incoherent-logrotate-file");
        }
        let names = named_pkg_findings(
            "slurm-config",
            vec![mode_file("/etc/logrotate.d/slurmctld.conf", 0o100644)],
        );
        assert_has(&names, "incoherent-logrotate-file");
    }

    #[test]
    fn incoherent_logrotate_case_and_suffix_compose() {
        // The case credit and the suffix credit compose: the stem
        // left by stripping .lr/.conf is compared with the same
        // case-insensitive equality as the bare name.
        let names = named_pkg_findings(
            "openQA",
            vec![mode_file("/etc/logrotate.d/openqa.lr", 0o100644)],
        );
        assert_lacks(&names, "incoherent-logrotate-file");
        let names = named_pkg_findings(
            "fcprobe",
            vec![mode_file("/etc/logrotate.d/FCprobe.conf", 0o100644)],
        );
        assert_lacks(&names, "incoherent-logrotate-file");
        // A stem differing by more than case still fires.
        let names = named_pkg_findings(
            "openQA",
            vec![mode_file("/etc/logrotate.d/openqax.lr", 0o100644)],
        );
        assert_has(&names, "incoherent-logrotate-file");
    }

    #[test]
    fn incoherent_logrotate_daemon_credit_excludes_the_file_itself() {
        // The judged file is not its own daemon evidence: an
        // executable logrotate file does not suppress its own
        // finding.
        let names = named_pkg_findings("bar", vec![mode_file("/etc/logrotate.d/bard", 0o100755)]);
        assert_has(&names, "incoherent-logrotate-file");
    }

    #[test]
    fn incoherent_logrotate_daemon_credit_skips_ghosts() {
        // A %ghost entry is not a shipped executable: a ghost daemon
        // path does not credit.
        use crate::pkg::pkgfile::RPMFILE_GHOST;

        let mut ghost = mode_file("/usr/bin/bard", 0o100755);
        ghost.flags = RPMFILE_GHOST;
        let names = named_pkg_findings(
            "bar",
            vec![mode_file("/etc/logrotate.d/bard", 0o100644), ghost],
        );
        assert_has(&names, "incoherent-logrotate-file");
    }

    #[test]
    fn incoherent_logrotate_residue_keeps_firing() {
        // Shapes with no credit:
        // a subpackage carrying the product-named file (dnf-data)
        // and a stale previous-major name (tomcat11 ships tomcat10).
        let names = named_pkg_findings(
            "dnf-data",
            vec![mode_file("/etc/logrotate.d/dnf", 0o100644)],
        );
        assert_has(&names, "incoherent-logrotate-file");
        let names = named_pkg_findings(
            "tomcat11",
            vec![mode_file("/etc/logrotate.d/tomcat10", 0o100644)],
        );
        assert_has(&names, "incoherent-logrotate-file");
    }

    /// Run the full FilesCheck over a package shipping exactly `files`;
    /// return the (finding, rendered line) pairs.
    fn run_files_check_with_files(files: Vec<PkgFile>) -> Vec<(String, String)> {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.ghost_files = files
            .iter()
            .filter(|f| f.is_ghost())
            .map(|f| f.name.clone())
            .collect();
        pkg.files = files;
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        out.results().to_vec()
    }

    /// Build a package from `files` with the header-derived config
    /// lists set explicitly, run the full FilesCheck over it, and
    /// return the levels `executable-marked-as-config-file` fired at,
    /// in emission order.
    fn exec_config_levels(
        files: Vec<PkgFile>,
        config_files: &[&str],
        noreplace_files: &[&str],
    ) -> Vec<Level> {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.ghost_files = files
            .iter()
            .filter(|f| f.is_ghost())
            .map(|f| f.name.clone())
            .collect();
        pkg.files = files;
        pkg.config_files = config_files.iter().map(|s| s.to_string()).collect();
        pkg.noreplace_files = noreplace_files.iter().map(|s| s.to_string()).collect();
        let (results, levels) = run_files_check_pkgs(&[pkg], &test_config());
        results
            .iter()
            .zip(&levels)
            .filter(|((name, _), _)| name == "executable-marked-as-config-file")
            .map(|(_, level)| *level)
            .collect()
    }

    /// A regular executable file carrying the given header flags.
    fn exec_file(name: &str, flags: u32) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            mode: 0o100755,
            flags,
            ..Default::default()
        }
    }

    #[test]
    fn executable_config_noreplace_is_warning() {
        // %config(noreplace) is a
        // deliberate marking -- the executable warns, it does not
        // error, and it is not dropped.
        let levels = exec_config_levels(
            vec![exec_file(
                "/etc/fcprobe/hook.sh",
                RPMFILE_CONFIG | RPMFILE_NOREPLACE,
            )],
            &["/etc/fcprobe/hook.sh"],
            &["/etc/fcprobe/hook.sh"],
        );
        assert_eq!(levels, vec![Level::Warning]);
    }

    #[test]
    fn executable_config_plain_stays_error() {
        // A plain %config executable carries no deliberate-marking
        // signal and keeps the reference's error.
        let levels = exec_config_levels(
            vec![exec_file("/etc/fcprobe/hook.sh", RPMFILE_CONFIG)],
            &["/etc/fcprobe/hook.sh"],
            &[],
        );
        assert_eq!(levels, vec![Level::Error]);
    }

    /// Build a package from `files`, run the full FilesCheck over it,
    /// and return the levels `htaccess-file` fired at, in emission
    /// order.
    fn htaccess_levels(files: Vec<PkgFile>) -> Vec<Level> {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.ghost_files = files
            .iter()
            .filter(|f| f.is_ghost())
            .map(|f| f.name.clone())
            .collect();
        pkg.files = files;
        let (results, levels) = run_files_check_pkgs(&[pkg], &test_config());
        results
            .iter()
            .zip(&levels)
            .filter(|((name, _), _)| name == "htaccess-file")
            .map(|(_, level)| *level)
            .collect()
    }

    /// Run the full FilesCheck over `files` and return the levels
    /// `siteperl-in-perl-module` fired at, in emission order.
    fn siteperl_levels(files: Vec<PkgFile>) -> Vec<Level> {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.files = files;
        let (results, levels) = run_files_check_pkgs(&[pkg], &test_config());
        results
            .iter()
            .zip(&levels)
            .filter(|((name, _), _)| name == "siteperl-in-perl-module")
            .map(|(_, level)| *level)
            .collect()
    }

    fn siteperl_file(name: &str, mode: u32) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            mode,
            ..Default::default()
        }
    }

    #[test]
    fn siteperl_module_file_still_warns() {
        let levels = siteperl_levels(vec![siteperl_file(
            "/usr/lib/perl5/site_perl/5.44.0/Foo.pm",
            0o100644,
        )]);
        assert_eq!(levels, vec![Level::Warning]);
    }

    #[test]
    fn siteperl_directory_entry_is_quiet() {
        // The perl package itself owns its site_perl tree; a
        // directory entry is not a shipped module file.
        let levels = siteperl_levels(vec![
            siteperl_file("/usr/lib/perl5/site_perl/5.44.0", 0o40755),
            siteperl_file(
                "/usr/lib/perl5/site_perl/5.44.0/x86_64-linux-thread-multi",
                0o40755,
            ),
        ]);
        assert!(levels.is_empty());
    }

    /// A regular non-executable file carrying the given header flags.
    fn flagged_file(name: &str, flags: u32) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            mode: 0o100644,
            flags,
            ..Default::default()
        }
    }

    #[test]
    fn htaccess_doc_in_doc_tree_warns() {
        // A %doc-flagged .htaccess under
        // /usr/share/doc/packages/ is a documentation website
        // artefact -- it warns, it does not error, and it is not
        // dropped.
        let levels = htaccess_levels(vec![flagged_file(
            "/usr/share/doc/packages/fcprobe-doc/html/.htaccess",
            RPMFILE_DOC,
        )]);
        assert_eq!(levels, vec![Level::Warning]);
    }

    #[test]
    fn htaccess_doc_outside_doc_tree_stays_error() {
        // The %doc flag alone is not enough: outside the doc tree
        // the file keeps the reference's error.
        let levels = htaccess_levels(vec![flagged_file(
            "/srv/www/htdocs/fcprobe/.htaccess",
            RPMFILE_DOC,
        )]);
        assert_eq!(levels, vec![Level::Error]);
    }

    #[test]
    fn htaccess_unflagged_in_doc_tree_stays_error() {
        // The doc-tree path alone is not enough either: an
        // unflagged .htaccess there is payload, not a documentation
        // artefact, and keeps the error.
        let levels = htaccess_levels(vec![flagged_file(
            "/usr/share/doc/packages/fcprobe/html/.htaccess",
            0,
        )]);
        assert_eq!(levels, vec![Level::Error]);
    }

    #[test]
    fn htaccess_webroot_stays_error() {
        // Ordinary web-root payload: the check's core case.
        let levels = htaccess_levels(vec![flagged_file(
            "/srv/www/htdocs/nextcloud/config/.htaccess",
            0,
        )]);
        assert_eq!(levels, vec![Level::Error]);
    }

    #[test]
    fn executable_config_split_within_one_package() {
        // Both arms in one package: the noreplace file warns, the
        // plain one errors; neither finding is dropped.
        let levels = exec_config_levels(
            vec![
                exec_file("/etc/fcprobe/a.sh", RPMFILE_CONFIG | RPMFILE_NOREPLACE),
                exec_file("/etc/fcprobe/b.sh", RPMFILE_CONFIG),
            ],
            &["/etc/fcprobe/a.sh", "/etc/fcprobe/b.sh"],
            &["/etc/fcprobe/a.sh"],
        );
        // Emission follows pkg.files order, so the pair is ordered:
        // the noreplace arm warns first, the plain arm errors.
        assert_eq!(levels, vec![Level::Warning, Level::Error]);
    }

    #[test]
    fn executable_config_ghost_noreplace_warns_not_exempt() {
        // The aaa_base shape: a %ghost %config(noreplace) stub follows
        // the same split -- it lands on the warning arm; there is no
        // ghost exemption.
        let levels = exec_config_levels(
            vec![exec_file(
                "/etc/init.d/after.local",
                RPMFILE_CONFIG | RPMFILE_NOREPLACE | RPMFILE_GHOST,
            )],
            &["/etc/init.d/after.local"],
            &["/etc/init.d/after.local"],
        );
        assert_eq!(levels, vec![Level::Warning]);
    }

    #[test]
    fn executable_nonconfig_file_is_quiet() {
        // Near-miss: an executable not marked %config at all must not
        // fire this tag.
        let levels = exec_config_levels(vec![exec_file("/usr/lib/fcprobe/tool.sh", 0)], &[], &[]);
        assert!(levels.is_empty(), "{levels:?}");
    }

    #[test]
    fn nonexec_config_noreplace_file_is_quiet() {
        // Near-miss: %config(noreplace) without the exec bit must not
        // fire this tag.
        let mut file = exec_file("/etc/fcprobe/hook.sh", RPMFILE_CONFIG | RPMFILE_NOREPLACE);
        file.mode = 0o100644;
        let levels = exec_config_levels(
            vec![file],
            &["/etc/fcprobe/hook.sh"],
            &["/etc/fcprobe/hook.sh"],
        );
        assert!(levels.is_empty(), "{levels:?}");
    }

    fn plain_file(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            ..Default::default()
        }
    }

    fn ghost_file(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            flags: RPMFILE_GHOST,
            ..Default::default()
        }
    }

    #[test]
    fn subdir_in_bin_quiet_for_companion_dot_d_dir() {
        // A `.d` directory named after an executable in the same bin
        // dir is that tool's companion directory (liblouis-tools
        // ships /usr/bin/lou_maketable.d/* for /usr/bin/lou_maketable):
        // its payload, at any depth below it, stays quiet.
        let names = finding_names(&run_files_check_with_files(vec![
            mkfile("/usr/bin/lou_tool", 0o100755, 1),
            mkfile("/usr/bin/lou_tool.d/helper.py", 0o100755, 2),
            mkfile("/usr/bin/lou_tool.d/sub/deep.sh", 0o100644, 3),
        ]));
        assert_lacks(&names, "subdir-in-bin");
    }

    #[test]
    fn subdir_in_bin_fires_for_dot_d_dir_without_namesake() {
        // Near miss: no executable named after the `.d` directory.
        let names = finding_names(&run_files_check_with_files(vec![mkfile(
            "/usr/bin/orphan.d/helper",
            0o100755,
            1,
        )]));
        assert_has(&names, "subdir-in-bin");
    }

    #[test]
    fn subdir_in_bin_fires_when_namesake_not_executable() {
        // Near miss: the namesake exists but is not an executable
        // regular file, so the `.d` directory is nobody's companion.
        let names = finding_names(&run_files_check_with_files(vec![
            mkfile("/usr/bin/tool", 0o100644, 1),
            mkfile("/usr/bin/tool.d/helper", 0o100755, 2),
        ]));
        assert_has(&names, "subdir-in-bin");
    }

    #[test]
    fn subdir_in_bin_fires_when_namesake_is_symlink() {
        // Near miss: a symlink namesake is not the tool itself.
        let names = finding_names(&run_files_check_with_files(vec![
            mkfile("/usr/bin/tool", 0o120777, 1),
            mkfile("/usr/bin/tool.d/helper", 0o100755, 2),
        ]));
        assert_has(&names, "subdir-in-bin");
    }

    #[test]
    fn subdir_in_bin_still_fires_for_plain_subdir_with_sibling() {
        // Only the `.d` companion shape is credited; a plain
        // subdirectory next to a same-named executable keeps firing.
        let names = finding_names(&run_files_check_with_files(vec![
            mkfile("/usr/bin/tool", 0o100755, 1),
            mkfile("/usr/bin/tool/helper", 0o100755, 2),
        ]));
        assert_has(&names, "subdir-in-bin");
    }

    #[test]
    fn subdir_in_bin_fires_for_plain_subdir() {
        let names = finding_names(&run_files_check_with_files(vec![mkfile(
            "/usr/bin/foo/bar",
            0o100755,
            1,
        )]));
        assert_has(&names, "subdir-in-bin");
    }

    #[test]
    fn dir_or_file_in_var_run_quiet_for_ghost() {
        let names = finding_names(&run_files_check_with_files(vec![ghost_file(
            "/var/run/fcprobe",
        )]));
        assert_lacks(&names, "dir-or-file-in-var-run");
    }

    #[test]
    fn dir_or_file_in_other_disallowed_dir_quiet_for_ghost() {
        let names = finding_names(&run_files_check_with_files(vec![ghost_file(
            "/home/fcprobe",
        )]));
        assert_lacks(&names, "dir-or-file-in-home");
    }

    #[test]
    fn dir_or_file_in_var_run_still_fires_for_real_file() {
        let results = run_files_check_with_files(vec![plain_file("/var/run/fcprobe")]);
        let names = finding_names(&results);
        assert_has(&names, "dir-or-file-in-var-run");
        let (_, line) = results
            .iter()
            .find(|(n, _)| n == "dir-or-file-in-var-run")
            .expect("finding fires");
        assert!(
            line.contains(": E: dir-or-file-in-var-run"),
            "real file stays an error: {line}"
        );
    }

    #[test]
    fn dir_or_file_in_usr_local_exemption_is_per_entry() {
        // One package carrying both shapes in the same disallowed
        // directory: the %ghost entry stays quiet while the real
        // payload entry still fires -- the exemption is per entry,
        // not per package.
        let results = run_files_check_with_files(vec![
            ghost_file("/usr/local/share/fcprobe"),
            plain_file("/usr/local/bin/fcprobe"),
        ]);
        let hits: Vec<&(String, String)> = results
            .iter()
            .filter(|(n, _)| n == "dir-or-file-in-usr-local")
            .collect();
        assert_eq!(hits.len(), 1, "exactly one entry fires: {results:?}");
        let (_, line) = hits[0];
        assert!(
            line.contains(": E: dir-or-file-in-usr-local")
                && line.contains("/usr/local/bin/fcprobe"),
            "the real entry fires at error: {line}"
        );
    }

    fn finding_names(results: &[(String, String)]) -> Vec<String> {
        results.iter().map(|(n, _)| n.clone()).collect()
    }

    #[test]
    fn non_ghost_in_run_fires_for_var_run_file() {
        // /var/run is a symlink to /run on openSUSE, so a non-ghost file
        // under either spelling is a file in the same tmpfs directory.
        for path in ["/run/fcprobe/pid", "/var/run/fcprobe/pid"] {
            let results = run_files_check_with_files(vec![plain_file(path)]);
            let names = finding_names(&results);
            assert_has(&names, "non-ghost-in-run");
            let (_, line) = results
                .iter()
                .find(|(n, _)| n == "non-ghost-in-run")
                .expect("finding fires");
            assert!(
                line.contains(": E: non-ghost-in-run") && line.contains(path),
                "error line names the path: {line}"
            );
        }
    }

    #[test]
    fn non_ghost_in_run_ghost_var_run_is_quiet() {
        for path in ["/run/fcprobe/pid", "/var/run/fcprobe/pid"] {
            let names = finding_names(&run_files_check_with_files(vec![ghost_file(path)]));
            assert_lacks(&names, "non-ghost-in-run");
        }
    }

    #[test]
    fn non_ghost_in_run_ignores_other_var_dirs() {
        for path in [
            "/var/lib/fcprobe/pid",
            "/var/log/fcprobe/pid",
            "/var/spool/fcprobe/pid",
        ] {
            let names = finding_names(&run_files_check_with_files(vec![plain_file(path)]));
            assert_lacks(&names, "non-ghost-in-run");
        }
    }

    #[test]
    fn non_ghost_in_run_bare_dir_symmetry() {
        // The /run/ spelling fires only on paths carrying the trailing
        // slash: the bare directory name itself stays quiet. The
        // /var/run spelling mirrors that exactly.
        for path in ["/run", "/var/run"] {
            let names = finding_names(&run_files_check_with_files(vec![plain_file(path)]));
            assert_lacks(&names, "non-ghost-in-run");
        }
        for path in ["/run/", "/var/run/"] {
            let names = finding_names(&run_files_check_with_files(vec![plain_file(path)]));
            assert_has(&names, "non-ghost-in-run");
        }
    }

    /// Negative pin for the removed `log-files-without-logrotate`
    /// finding: top-level /var/log entries without a logrotate file
    /// stay silent.
    #[test]
    fn killed_log_files_without_logrotate_stays_absent() {
        for files in [
            vec![plain_file("/var/log/fcprobe")],
            vec![plain_file("/var/log/fcprobe.log")],
            vec![PkgFile {
                name: "/var/log/fcprobe.log".to_string(),
                path: "/var/log/fcprobe.log".to_string(),
                flags: RPMFILE_GHOST,
                ..Default::default()
            }],
        ] {
            let names = finding_names(&run_files_check_with_files(files));
            assert_lacks(&names, "log-files-without-logrotate");
        }
    }

    #[test]
    fn missing_dependency_to_crontabs_quiet_when_recommended() {
        // Same #388 root cause in the sibling check: the reference's
        // `_check_file_crontab` also counts requires + recommends + suggests.
        let names = run_files_check_with_deps(
            "/etc/cron.daily/fcprobe",
            vec![],
            vec![dep_named("crontabs")],
            vec![],
        );
        assert_lacks(&names, "missing-dependency-to-crontabs");
    }

    #[test]
    fn hidden_file_or_dir_only_flags_final_component() {
        // Upstream hidden_file_regex r'/\.[^/]*$' tests only the final
        // path component: the hidden dir itself is flagged, but files nested
        // under it are not.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.files = vec![
            PkgFile {
                name: "/usr/src/bazel-skylib/.bcr".to_string(),
                path: "/usr/src/bazel-skylib/.bcr".to_string(),
                ..Default::default()
            },
            PkgFile {
                name: "/usr/src/bazel-skylib/.bcr/gazelle/dep.json".to_string(),
                path: "/usr/src/bazel-skylib/.bcr/gazelle/dep.json".to_string(),
                ..Default::default()
            },
            PkgFile {
                name: "/usr/share/doc/pkg/.hidden-note".to_string(),
                path: "/usr/share/doc/pkg/.hidden-note".to_string(),
                ..Default::default()
            },
            PkgFile {
                name: "/usr/share/doc/pkg/README".to_string(),
                path: "/usr/share/doc/pkg/README".to_string(),
                ..Default::default()
            },
        ];
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let findings: Vec<(Level, String)> = out
            .results()
            .iter()
            .zip(out.result_levels().iter())
            .filter(|((name, _), _)| *name == "hidden-file-or-dir")
            .map(|((_, line), level)| (*level, line.clone()))
            .collect();
        assert_eq!(
            findings.len(),
            2,
            "exactly the hidden dir and the hidden file flagged: {findings:?}"
        );
        assert!(
            findings.iter().all(|(level, _)| *level == Level::Warning),
            "both findings are warnings: {findings:?}"
        );
        // Suffix match, not `contains`: the unflagged dep.json line contains
        // "/usr/src/bazel-skylib/.bcr" as a path prefix, so `contains` cannot
        // tell the flagged dir from its unflagged child.
        let mut details: Vec<&str> = findings.iter().map(|(_, line)| line.as_str()).collect();
        details.sort_unstable();
        assert!(
            details[0].ends_with("/usr/share/doc/pkg/.hidden-note"),
            "hidden file flagged: {details:?}"
        );
        assert!(
            details[1].ends_with("/usr/src/bazel-skylib/.bcr"),
            "hidden dir itself flagged: {details:?}"
        );
    }

    #[test]
    fn hidden_file_or_dir_final_component_edges() {
        // Exact upstream r'/\.[^/]*$' parity: a hidden file nested under a
        // hidden dir is still flagged (only the final component is tested);
        // the three upstream exceptions suppress the finding; a bare '.'
        // final component matches ([^/]* may be empty).
        let extra = [
            ("/srv/data/.cache/.index", true), // hidden file under hidden dir
            ("/srv/data/.cache/obj/blob", false), // nested under two hidden dirs
            ("/etc/skel/.profile", false),     // /etc/skel/ exception
            ("/usr/lib/.build-id", false),     // /.build-id exception
            (
                "/usr/lib/python3.13/site-packages/pkg/.cargo-checksum.json",
                false,
            ), // /.cargo-checksum.json exception
            ("/var/tmp/.", true),              // bare '.' matches upstream
        ];
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.files = extra
            .iter()
            .map(|(name, _)| PkgFile {
                name: (*name).to_string(),
                path: (*name).to_string(),
                ..Default::default()
            })
            .collect();
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let flagged: Vec<&str> = out
            .results()
            .iter()
            .filter(|(n, _)| n == "hidden-file-or-dir")
            .map(|(_, line)| line.as_str())
            .collect();
        for (name, want) in &extra {
            let got = flagged.iter().any(|f| f.contains(name));
            assert_eq!(
                got, *want,
                "hidden-file-or-dir for {name}: want flagged={want}, got lines {flagged:?}"
            );
        }
    }

    #[test]
    fn hidden_file_or_dir_skel_usrmerge_and_cargo_vcs_info() {
        // The /etc/skel/ exception covers the same skeleton directory at
        // its usrmerge location /usr/etc/skel/: the dotfiles there are
        // the shipped product (a new account's initial home content).
        // The /.cargo-checksum.json exception extends to the second
        // cargo metadata file, /.cargo_vcs_info.json, which cargo writes
        // next to the checksum file in vendored crate trees and which
        // records the vendored sources' upstream VCS revision. Both
        // credits are exact-shape: a lookalike prefix or an extended
        // suffix keeps firing.
        let extra = [
            ("/usr/etc/skel/.bashrc", false), // skeleton file, usrmerge path
            ("/usr/etc/skel/.config", false), // skeleton dir, usrmerge path
            ("/usr/lib64/crates/foo-1.2.3/.cargo_vcs_info.json", false), // vendored crate metadata
            ("/usr/share/doc/pkg/.cargo_vcs_info.json", false), // name-exact, as the checksum file
            ("/usr/etc/skel-other/.bashrc", true), // prefix must end at the slash
            ("/usr/etc/skell/.profile", true), // lookalike prefix
            ("/usr/lib64/crates/foo-1.2.3/.cargo_vcs_info.json.bak", true), // suffix must be exact
            ("/usr/lib64/crates/foo-1.2.3/.cargo_vcs_info", true), // truncated name
        ];
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.files = extra
            .iter()
            .map(|(name, _)| PkgFile {
                name: (*name).to_string(),
                path: (*name).to_string(),
                ..Default::default()
            })
            .collect();
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let flagged: Vec<&str> = out
            .results()
            .iter()
            .filter(|(n, _)| n == "hidden-file-or-dir")
            .map(|(_, line)| line.as_str())
            .collect();
        for (name, want) in &extra {
            // Suffix match, not substring match: the firing .json.bak
            // line contains the credited .cargo_vcs_info.json path as a
            // substring, so a substring test cannot tell them apart.
            let got = flagged.iter().any(|f| f.ends_with(name));
            assert_eq!(
                got, *want,
                "hidden-file-or-dir for {name}: want flagged={want}, got lines {flagged:?}"
            );
        }
    }

    #[test]
    fn files_check_scripts_kitchen_sink() {
        let config = test_config();
        let (names, _dir) = run_files_check(
            &fixture_path("filescheck-scripts-1.0-1.noarch.rpm"),
            &config,
        );
        // script findings
        assert_has(&names, "env-script-interpreter");
        assert_has(&names, "executable-sourced-script");
        assert_has(&names, "wrong-script-interpreter");
        assert_has(&names, "script-without-shebang");
        assert_has(&names, "non-executable-script");
        assert_has(&names, "wrong-script-end-of-line-encoding");
        // permission findings
        assert_has(&names, "non-executable-in-bin");
        assert_has(&names, "spurious-executable-perm");
        // documentation and encoding
        assert_has(&names, "wrong-file-end-of-line-encoding");
        assert_lacks(&names, "file-not-utf8");
        assert_has(&names, "incorrect-fsf-address");
        // symlinks
        assert_has(&names, "symlink-has-too-many-up-segments");
        assert_has(&names, "symlink-should-be-relative");
        assert_has(&names, "symlink-to-binary-with-shebang");
        assert_has(&names, "dangling-symlink");
        // logs
        assert_has(&names, "non-root-user-log-file");
        assert_has(&names, "non-root-group-log-file");
        assert_has(&names, "non-ghost-file");
        // pem
        assert_has(&names, "pem-certificate");
        assert_has(&names, "pem-private-key");
        // misc
        assert_has(&names, "tcl-extension-file");
        assert_has(&names, "python-bytecode-without-source");
        assert_has(&names, "rpath-in-buildconfig");
        assert_has(&names, "gzipped-svg-icon");
        assert_has(&names, "noarch-python-in-64bit-path");
        assert_has(&names, "standard-dir-owned-by-package");
        // no read errors: extraction works
        assert_lacks(&names, "read-error");
        // Removed findings (issue #883 leftover rulings): the fixture
        // exercises all three shapes and stays silent.
        assert_lacks(&names, "non-standard-executable-perm");
        assert_lacks(&names, "perl-temp-file");
        assert_lacks(&names, "dir-or-file-in-opt");
    }

    #[test]
    fn non_executable_in_bin_ghost_is_silent() {
        // A %ghost entry is bookkeeping, not payload: the package
        // installs no file, so there is no installed file to judge,
        // and the header mode placeholder (regular file type with
        // permission bits 0) is not a permission.
        use crate::pkg::pkgfile::RPMFILE_GHOST;

        let mut ghost = mode_file("/usr/bin/java", 0o100000);
        ghost.flags = RPMFILE_GHOST;
        let names = named_pkg_findings("java-11-openjdk-headless", vec![ghost]);
        assert_lacks(&names, "non-executable-in-bin");
        // The same header shape without the ghost flag still fires.
        let names = named_pkg_findings(
            "java-11-openjdk-headless",
            vec![mode_file("/usr/bin/java", 0o100000)],
        );
        assert_has(&names, "non-executable-in-bin");
        // A real non-executable regular file still fires.
        let names = named_pkg_findings("foo", vec![mode_file("/usr/bin/foo-data", 0o100644)]);
        assert_has(&names, "non-executable-in-bin");
    }

    fn nonexec_details(pkg: &Pkg) -> Vec<String> {
        run_check_binary(pkg)
            .into_iter()
            .filter(|(n, _)| n == "non-executable-in-bin")
            .map(|(_, d)| d)
            .collect()
    }

    #[test]
    fn non_executable_in_bin_sourced_by_sibling_is_silent() {
        // Bare dot-source form (clevis shape) silences the candidate.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let pkg = content_pkg(
            &dir,
            &[
                (
                    "/usr/bin/clevis-luks-common-functions",
                    r#"# common functions
"#,
                ),
                (
                    "/usr/bin/clevis-luks-bind",
                    r#"#!/bin/sh
. clevis-luks-common-functions
"#,
                ),
            ],
        );
        let details = nonexec_details(&pkg);
        assert!(
            !details
                .iter()
                .any(|d| d.contains("clevis-luks-common-functions")),
            "sourced helper must stay silent: {details:?}"
        );
        // Dirname form (brltty shape) silences too.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let pkg = content_pkg(
            &dir,
            &[
                (
                    "/usr/bin/brltty-prologue.sh",
                    r#"# prologue
"#,
                ),
                (
                    "/usr/bin/brltty-term",
                    r#"#!/bin/sh
. "$(dirname "${0}")/brltty-prologue.sh"
"#,
                ),
            ],
        );
        let details = nonexec_details(&pkg);
        assert!(
            !details.iter().any(|d| d.contains("brltty-prologue.sh")),
            "dirname-sourced helper must stay silent: {details:?}"
        );
        // A comment mention does not credit.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let pkg = content_pkg(
            &dir,
            &[
                (
                    "/usr/bin/clevis-luks-common-functions",
                    r#"# common functions
"#,
                ),
                (
                    "/usr/bin/clevis-luks-bind",
                    r#"#!/bin/sh
# see clevis-luks-common-functions for helpers
"#,
                ),
            ],
        );
        let details = nonexec_details(&pkg);
        assert!(
            details
                .iter()
                .any(|d| d.contains("clevis-luks-common-functions")),
            "comment mention must still fire: {details:?}"
        );
        // An execute form does not credit.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let pkg = content_pkg(
            &dir,
            &[
                (
                    "/usr/bin/clevis-luks-common-functions",
                    r#"# common functions
"#,
                ),
                (
                    "/usr/bin/clevis-luks-bind",
                    r#"#!/bin/sh
./clevis-luks-common-functions
"#,
                ),
            ],
        );
        let details = nonexec_details(&pkg);
        assert!(
            details
                .iter()
                .any(|d| d.contains("clevis-luks-common-functions")),
            "execute form must still fire: {details:?}"
        );
        // A self-reference does not credit.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let pkg = content_pkg(
            &dir,
            &[(
                "/usr/bin/clevis-luks-common-functions",
                r#". clevis-luks-common-functions
"#,
            )],
        );
        let details = nonexec_details(&pkg);
        assert!(
            details
                .iter()
                .any(|d| d.contains("clevis-luks-common-functions")),
            "self-reference must still fire: {details:?}"
        );
    }

    #[test]
    fn non_executable_in_bin_data_files_are_silent() {
        // Compiler data, FIPS sidecar and host-loaded source are silent.
        for (path, content) in [
            (
                "/usr/bin/cvsdiff.tdf",
                r#"# tdf data
"#,
            ),
            (
                "/usr/bin/ssh.hmac",
                r#"0123456789abcdef0123456789abcdef01234567  ssh
"#,
            ),
            (
                "/usr/bin/brltty-prologue.lua",
                r#"-- loaded by the brltty binary
"#,
            ),
        ] {
            let dir = tempfile::TempDir::new().expect("tempdir");
            let pkg = content_pkg(&dir, &[(path, content)]);
            let details = nonexec_details(&pkg);
            assert!(
                details.is_empty(),
                "data file {path} must stay silent: {details:?}"
            );
        }
        // A shebang script still fires whatever its suffix.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let pkg = content_pkg(
            &dir,
            &[(
                "/usr/bin/brltty-prologue.lua",
                r#"#!/usr/bin/lua
print("hi")
"#,
            )],
        );
        let details = nonexec_details(&pkg);
        assert!(
            details.iter().any(|d| d.contains("brltty-prologue.lua")),
            "shebang lua script must still fire: {details:?}"
        );
        // A non-data suffix still fires.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let pkg = content_pkg(
            &dir,
            &[(
                "/usr/bin/helper.sh",
                r#"# helper, sourced by nothing
"#,
            )],
        );
        let details = nonexec_details(&pkg);
        assert!(
            details.iter().any(|d| d.contains("helper.sh")),
            "unsourced .sh file must still fire: {details:?}"
        );
    }

    /// A synthetic package carrying a single standard-dir entry,
    /// mirroring the world-writable tests' construction.
    fn standard_dir_pkg(name: &str, dir: &str) -> (Pkg, Config) {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = name.to_string();
        pkg.files = vec![PkgFile {
            name: dir.to_string(),
            path: dir.to_string(),
            mode: 0o040755,
            ..Default::default()
        }];
        let config = test_config();
        (pkg, config)
    }

    fn standard_dir_names(pkg: &Pkg, config: &Config) -> Vec<String> {
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(config);
        check.check(pkg, config, &mut out);
        out.results().iter().map(|(n, _)| n.clone()).collect()
    }

    #[test]
    fn standard_dir_silent_for_filesystem_media() {
        // filesystem-media is openSUSE's designated split owner of
        // /media (the filesystem package ships no /media entry), so it
        // joins the FILESYS_PACKAGES exemption.
        let (pkg, config) = standard_dir_pkg("filesystem-media", "/media");
        let names = standard_dir_names(&pkg, &config);
        assert_lacks(&names, "standard-dir-owned-by-package");
    }

    #[test]
    fn standard_dir_fires_for_non_exempt_owner_of_media() {
        // virtualbox-guest-tools duplicates filesystem-media's /media
        // entry; not being the designated owner, it keeps firing.
        let (pkg, config) = standard_dir_pkg("virtualbox-guest-tools", "/media");
        let names = standard_dir_names(&pkg, &config);
        assert_has(&names, "standard-dir-owned-by-package");
    }

    #[test]
    fn standard_dir_fires_for_near_miss_filesystem_name() {
        // The exemption is an exact name match, not a prefix: a
        // filesystem-* name outside the set keeps firing.
        let (pkg, config) = standard_dir_pkg("filesystem-media-doc", "/media");
        let names = standard_dir_names(&pkg, &config);
        assert_has(&names, "standard-dir-owned-by-package");
    }

    /// Build an extracted package shipping `files` -- (path, user,
    /// group, content) -- with real on-disk content, so the sysusers.d
    /// snippets a test ships parse for real. Every `/var/log/` entry is
    /// marked %ghost, mirroring the live population (flat log files are
    /// always placeholders).
    fn logfile_pkg(dir: &tempfile::TempDir, files: &[(&str, &str, &str, &[u8])]) -> Pkg {
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        pkg.name = "logfile-test".to_string();
        // Content must land in the package's own extraction dir:
        // `Pkg::read_file` resolves against it, not the parent `dir`.
        let root = pkg
            .extracted_dir()
            .expect("extracted fixture")
            .to_path_buf();
        pkg.files = files
            .iter()
            .map(|(name, user, group, content)| {
                let path = root.join(name.trim_start_matches('/'));
                std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
                std::fs::write(&path, content).expect("write temp file");
                PkgFile {
                    name: name.to_string(),
                    path: path.to_string_lossy().into_owned(),
                    mode: 0o100644,
                    user: user.to_string(),
                    group: group.to_string(),
                    ..Default::default()
                }
            })
            .collect();
        pkg.ghost_files = pkg
            .files
            .iter()
            .filter(|f| f.name.starts_with("/var/log/"))
            .map(|f| f.name.clone())
            .collect();
        pkg.requires = vec![];
        pkg
    }

    /// (tag, level) pairs for the two non-root log-file tags, in
    /// emission order.
    fn logfile_tag_levels(pkgs: &[Pkg], config: &Config) -> Vec<(String, Level)> {
        let (results, levels) = run_files_check_pkgs(pkgs, config);
        results
            .iter()
            .zip(levels.iter())
            .filter(|((name, _), _)| {
                name == "non-root-user-log-file" || name == "non-root-group-log-file"
            })
            .map(|((name, _), level)| (name.clone(), *level))
            .collect()
    }

    fn user_group_levels(user: Level, group: Level) -> Vec<(String, Level)> {
        vec![
            ("non-root-user-log-file".to_string(), user),
            ("non-root-group-log-file".to_string(), group),
        ]
    }

    #[test]
    fn non_root_logfile_warns_when_owner_declared_by_own_sysusers() {
        // fapolicyd's shape: one `u` line declares the user and the
        // like-named primary group it creates, so both tags warn.
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg = logfile_pkg(
            &dir,
            &[
                (
                    "/usr/lib/sysusers.d/svc.conf",
                    "root",
                    "root",
                    b"u svc - \"Service\" /var/lib/svc /sbin/nologin\n",
                ),
                ("/var/log/svc.log", "svc", "svc", b""),
            ],
        );
        let config = test_config();
        assert_eq!(
            logfile_tag_levels(&[pkg], &config),
            user_group_levels(Level::Warning, Level::Warning)
        );
    }

    #[test]
    fn non_root_logfile_warns_for_declared_user_with_root_group() {
        // openQA's shape: the user is declared by the package's own
        // snippet (its `m` membership line declares no account), the
        // group is root, so only the user tag fires, at W.
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg = logfile_pkg(
            &dir,
            &[
                (
                    "/usr/lib/sysusers.d/geekotest.conf",
                    "root",
                    "root",
                    b"u geekotest - \"openQA user\" /var/lib/openqa /bin/bash\nm geekotest nogroup\n",
                ),
                ("/var/log/openqa", "geekotest", "root", b""),
            ],
        );
        let config = test_config();
        assert_eq!(
            logfile_tag_levels(&[pkg], &config),
            vec![("non-root-user-log-file".to_string(), Level::Warning)]
        );
    }

    #[test]
    fn non_root_logfile_membership_line_declares_no_group() {
        // The `m` line above records membership only: a group named by
        // an `m` line is not declared, so the group tag keeps E.
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg = logfile_pkg(
            &dir,
            &[
                (
                    "/usr/lib/sysusers.d/geekotest.conf",
                    "root",
                    "root",
                    b"u geekotest - \"openQA user\" /var/lib/openqa /bin/bash\nm geekotest nogroup\n",
                ),
                ("/var/log/openqa", "root", "nogroup", b""),
            ],
        );
        let config = test_config();
        assert_eq!(
            logfile_tag_levels(&[pkg], &config),
            vec![("non-root-group-log-file".to_string(), Level::Error)]
        );
    }

    #[test]
    fn non_root_logfile_errors_when_owner_not_declared() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg = logfile_pkg(&dir, &[("/var/log/svc.log", "svc", "svc", b"")]);
        let config = test_config();
        assert_eq!(
            logfile_tag_levels(&[pkg], &config),
            user_group_levels(Level::Error, Level::Error)
        );
    }

    #[test]
    fn non_root_logfile_errors_when_snippet_declares_another_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg = logfile_pkg(
            &dir,
            &[
                (
                    "/usr/lib/sysusers.d/alice.conf",
                    "root",
                    "root",
                    b"u alice - \"Alice\" /var/lib/alice /sbin/nologin\n",
                ),
                ("/var/log/svc.log", "svc", "svc", b""),
            ],
        );
        let config = test_config();
        assert_eq!(
            logfile_tag_levels(&[pkg], &config),
            user_group_levels(Level::Error, Level::Error)
        );
    }

    #[test]
    fn non_root_logfile_errors_when_owner_only_required() {
        // A user()/group() Requires without a shipped snippet declares
        // nothing for this split: both tags keep E.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut pkg = logfile_pkg(&dir, &[("/var/log/svc.log", "svc", "svc", b"")]);
        pkg.requires = crate::pkg::dep::parse_dep_infos("user(svc) group(svc)");
        let config = test_config();
        assert_eq!(
            logfile_tag_levels(&[pkg], &config),
            user_group_levels(Level::Error, Level::Error)
        );
    }

    #[test]
    fn non_root_logfile_g_line_does_not_credit_the_user() {
        // A `g` line declares its group only: the group tag warns, a
        // user of the same name still errors.
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg = logfile_pkg(
            &dir,
            &[
                (
                    "/usr/lib/sysusers.d/svcgrp.conf",
                    "root",
                    "root",
                    b"g svcgrp -\n",
                ),
                ("/var/log/svc.log", "svcgrp", "svcgrp", b""),
            ],
        );
        let config = test_config();
        assert_eq!(
            logfile_tag_levels(&[pkg], &config),
            user_group_levels(Level::Error, Level::Warning)
        );
    }

    #[test]
    fn non_root_logfile_u_line_does_not_credit_another_group() {
        // A `u` line credits its user and the like-named group only;
        // an unrelated charged group keeps E.
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg = logfile_pkg(
            &dir,
            &[
                (
                    "/usr/lib/sysusers.d/svc.conf",
                    "root",
                    "root",
                    b"u svc - \"Service\" /var/lib/svc /sbin/nologin\n",
                ),
                ("/var/log/svc.log", "svc", "other", b""),
            ],
        );
        let config = test_config();
        assert_eq!(
            logfile_tag_levels(&[pkg], &config),
            user_group_levels(Level::Warning, Level::Error)
        );
    }

    #[test]
    fn non_root_logfile_sibling_snippet_does_not_credit() {
        // The snippet ships in a different package than the log file:
        // no credit crosses the package boundary.
        let dir = tempfile::tempdir().expect("tempdir");
        let declarer = logfile_pkg(
            &dir,
            &[(
                "/usr/lib/sysusers.d/svc.conf",
                "root",
                "root",
                b"u svc - \"Service\" /var/lib/svc /sbin/nologin\n",
            )],
        );
        let dir2 = tempfile::tempdir().expect("tempdir");
        let owner = logfile_pkg(&dir2, &[("/var/log/svc.log", "svc", "svc", b"")]);
        let config = test_config();
        assert_eq!(
            logfile_tag_levels(&[declarer, owner], &config),
            user_group_levels(Level::Error, Level::Error)
        );
    }

    /// Build a package of executable files with real on-disk content (so
    /// peek/istext run for real), mirroring the appdata_pkg helper.
    fn spurious_exec_pkg(dir: &tempfile::TempDir, files: &[(&str, &str, &[u8])]) -> Pkg {
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        pkg.name = "spurious-test".to_string();
        pkg.files = files
            .iter()
            .map(|(name, magic, content)| {
                let path = dir.path().join(name.trim_start_matches('/'));
                std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
                std::fs::write(&path, content).expect("write temp file");
                PkgFile {
                    name: name.to_string(),
                    path: path.to_string_lossy().into_owned(),
                    mode: 0o100755,
                    magic: magic.to_string(),
                    ..Default::default()
                }
            })
            .collect();
        pkg
    }

    /// (name, Level, detail) triples for the two findings in play here.
    fn spurious_script_findings(out: &Filter) -> Vec<(String, Level, String)> {
        out.results()
            .iter()
            .zip(out.result_levels().iter())
            .filter(|((name, _), _)| {
                *name == "spurious-executable-perm" || *name == "script-without-shebang"
            })
            .map(|((name, detail), level)| (name.clone(), *level, detail.clone()))
            .collect()
    }

    fn check_spurious_script(pkg: &Pkg, config: &Config) -> Vec<(String, Level, String)> {
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(config);
        check.check(pkg, config, &mut out);
        spurious_script_findings(&out)
    }

    #[test]
    fn missing_dependency_to_crontabs_fires_without_any_dep() {
        // Sibling of the logrotate firing guard: a cron file with no
        // crontabs dep of any kind must emit missing-dependency-to-crontabs.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = "cron-test".to_string();
        pkg.files = vec![PkgFile {
            name: "/etc/cron.daily/fcprobe".to_string(),
            path: "/etc/cron.daily/fcprobe".to_string(),
            ..Default::default()
        }];
        pkg.requires = vec![];
        pkg.recommends = vec![];
        pkg.suggests = vec![];
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "missing-dependency-to-crontabs");
    }

    /// Run FilesCheck over a package (named cron-test, no deps of any
    /// kind) shipping exactly `files`; return the finding names.
    fn crontabs_findings(files: Vec<PkgFile>) -> Vec<String> {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = "cron-test".to_string();
        pkg.files = files;
        pkg.requires = vec![];
        pkg.recommends = vec![];
        pkg.suggests = vec![];
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        out.results().iter().map(|(n, _)| n.clone()).collect()
    }

    fn cron_entry(name: &str, mode: u32) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            mode,
            ..Default::default()
        }
    }

    #[test]
    fn missing_dependency_to_crontabs_skips_directory_entries() {
        // The cron.* directories themselves are not cron scripts: the
        // `cron` package ships exactly these five entries and drew five
        // findings. A subdirectory inside a cron dir is likewise a dir.
        let names = crontabs_findings(vec![
            cron_entry("/etc/cron.d", 0o40755),
            cron_entry("/etc/cron.daily", 0o40755),
            cron_entry("/etc/cron.hourly", 0o40755),
            cron_entry("/etc/cron.monthly", 0o40755),
            cron_entry("/etc/cron.weekly", 0o40755),
            cron_entry("/etc/cron.d/subdir", 0o40755),
        ]);
        assert_lacks(&names, "missing-dependency-to-crontabs");
    }

    #[test]
    fn missing_dependency_to_crontabs_skips_daemon_files_in_etc() {
        // /etc/cron.deny (and .allow) are the daemon's own access-control
        // files directly in /etc, not scripts inside a cron directory.
        let names = crontabs_findings(vec![cron_entry("/etc/cron.deny", 0o100600)]);
        assert_lacks(&names, "missing-dependency-to-crontabs");
    }

    #[test]
    fn missing_dependency_to_crontabs_fires_on_script_and_symlink() {
        // A real script file inside a cron dir still fires, and so does a
        // symlink registration pointing at one.
        let names = crontabs_findings(vec![
            cron_entry("/etc/cron.hourly/0fcprobe", 0o100755),
            PkgFile {
                name: "/etc/cron.d/fcprobe".to_string(),
                path: "/etc/cron.d/fcprobe".to_string(),
                mode: 0o120777,
                linkto: "../fcprobe".to_string(),
                ..Default::default()
            },
        ]);
        assert_has(&names, "missing-dependency-to-crontabs");
    }

    #[test]
    fn missing_dependency_to_crontabs_cron_dep_credits() {
        // A dep on `cron` (the renamed provider of the cron.*
        // directories) satisfies the check, exactly as `crontabs` did;
        // this supersedes the boundary pin the test used to carry.
        // Corpus shape: nextcloud (Requires: cron).
        let names = run_files_check_with_deps(
            "/etc/cron.d/nextcloud",
            vec![dep_named("cron")],
            vec![],
            vec![],
        );
        assert_lacks(&names, "missing-dependency-to-crontabs");
    }

    #[test]
    fn missing_dependency_to_crontabs_cronie_dep_credits() {
        // Corpus shape: cronie-anacron (Requires: cronie) -- the
        // daemon package is the cron stack its scripts run under.
        let names = run_files_check_with_deps(
            "/etc/cron.hourly/0anacron",
            vec![dep_named("cronie")],
            vec![],
            vec![],
        );
        assert_lacks(&names, "missing-dependency-to-crontabs");
    }

    #[test]
    fn missing_dependency_to_crontabs_recommended_cron_credits() {
        // Corpus shape: matomo (Recommends: cron) -- the relation arms
        // are the ones the check already counts (#388), unchanged.
        let names = run_files_check_with_deps(
            "/etc/cron.d/matomo-archive",
            vec![],
            vec![dep_named("cron")],
            vec![],
        );
        assert_lacks(&names, "missing-dependency-to-crontabs");
    }

    #[test]
    fn missing_dependency_to_crontabs_lookalike_deps_still_fire() {
        // The credit is an exact name match on the provider's real
        // names; lookalike dep names do not satisfy the check.
        for lookalike in ["cronie-anacron", "systemd-cron", "cron-utils"] {
            let names = run_files_check_with_deps(
                "/etc/cron.d/fcprobe",
                vec![dep_named(lookalike)],
                vec![],
                vec![],
            );
            assert_has(&names, "missing-dependency-to-crontabs");
        }
    }

    #[test]
    fn missing_dependency_to_crontabs_provider_package_itself_quiet() {
        // A package that IS one of the credited provider names needs
        // no dep on the stack (the `crontabs` self-credit, extended
        // to the current names): cronie shipping a script stays quiet.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = "cronie".to_string();
        pkg.files = vec![cron_entry("/etc/cron.d/cronie-probe", 0o100755)];
        pkg.requires = vec![];
        pkg.recommends = vec![];
        pkg.suggests = vec![];
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "missing-dependency-to-crontabs");
    }

    /// Negative pin for the removed `no-documentation` finding: a
    /// doc-less non-lib package stays silent through the session
    /// lifecycle (export, merge, after_checks).
    #[test]
    fn killed_no_documentation_stays_absent() {
        // Drive the
        // session lifecycle the lint loop drives: export the package's
        // state, merge it back, then run after_checks.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = "nodoc-test".to_string();
        pkg.doc_files = vec![];
        pkg.files = vec![];
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        if let Some(state) = check.export_state() {
            check.import_state(state);
        }
        check.after_checks(&config, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "no-documentation");
    }

    #[test]
    fn world_writable_fires_for_world_writable_regular_file() {
        // Regular file with o+w must emit world-writable; the dispatch
        // gates on S_IFREG, so the mode carries the file-type bits.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.files = vec![PkgFile {
            name: "/usr/share/foo/data.txt".to_string(),
            path: "/usr/share/foo/data.txt".to_string(),
            mode: 0o100666,
            ..Default::default()
        }];
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "world-writable");
    }

    #[test]
    fn world_writable_fires_for_world_writable_dir_without_sticky_bit() {
        // Directory with o+w and no sticky bit must emit world-writable
        // at Error (issue #738); the dispatch gates on S_IFDIR, so the
        // mode carries the file-type bits.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.files = vec![PkgFile {
            name: "/var/lib/foo".to_string(),
            path: "/var/lib/foo".to_string(),
            mode: 0o040777,
            ..Default::default()
        }];
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let hits: Vec<Level> = out
            .results()
            .iter()
            .zip(out.result_levels().iter())
            .filter(|((n, _), _)| n.as_str() == "world-writable")
            .map(|(_, l)| *l)
            .collect();
        assert_eq!(hits, [Level::Error], "world-writable must fire at Error");
    }

    #[test]
    fn world_writable_silent_for_sticky_world_writable_dir() {
        // Sticky-bit world-writable directories stay quiet: the
        // reference fires only when the sticky bit is absent
        // (`mode & 0o1002 == 2`), so the FHS public tmp directories at
        // 1777 emit no world-writable (issue #738).
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = "filesystem".to_string();
        pkg.files = vec![
            PkgFile {
                name: "/tmp".to_string(),
                path: "/tmp".to_string(),
                mode: 0o041777,
                ..Default::default()
            },
            PkgFile {
                name: "/var/tmp".to_string(),
                path: "/var/tmp".to_string(),
                mode: 0o041777,
                ..Default::default()
            },
        ];
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "world-writable");
    }

    #[test]
    fn world_writable_silent_for_sticky_dir_on_an_ordinary_path() {
        // Same path as the firing case above, only the sticky bit
        // differs: /var/lib/foo at 1777 stays quiet, proving the silence
        // comes from the mode predicate alone and not from the path
        // being an FHS tmp directory (issue #772).
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.files = vec![PkgFile {
            name: "/var/lib/foo".to_string(),
            path: "/var/lib/foo".to_string(),
            mode: 0o041777,
            ..Default::default()
        }];
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "world-writable");
    }

    #[test]
    fn spurious_executable_perm_fires_for_text_data_file() {
        // Text data file with the executable bit but no shebang: not a
        // script, not an ELF binary, not in a script path ->
        // spurious-executable-perm. Pinned at Warning: the test config
        // carries no Scoring table, so the openSUSE 50-point promotion to
        // Error does not apply here.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = spurious_exec_pkg(
            &dir,
            &[(
                "/usr/share/themes/foo/index.theme",
                "ASCII text",
                b"[Icon Theme]\nName=Foo\n",
            )],
        );
        let findings = check_spurious_script(&pkg, &config);
        assert_eq!(
            findings,
            [(
                "spurious-executable-perm".to_string(),
                Level::Warning,
                "spurious-test.noarch: W: spurious-executable-perm \
                 /usr/share/themes/foo/index.theme"
                    .to_string(),
            )],
            "exactly one pinned (name, Level, detail) triple"
        );
    }

    #[test]
    fn spurious_executable_perm_silent_in_source_packages() {
        // Vendored source payload: a source tree's text files are
        // read or built from, not executed in place, so the stray
        // exec bit the text gate marks is not a defect there --
        // `script_is_source_data` carries the shapes, the same gate
        // the interpreter findings in source trees use. The package
        // arm covers the payload wherever it sits in the tree.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = spurious_exec_pkg(
            &dir,
            &[
                (
                    "/usr/src/kafka/config/example.yml",
                    "ASCII text",
                    b"key: value\n",
                ),
                (
                    "/usr/share/kafka-source/notes.txt",
                    "ASCII text",
                    b"release notes\n",
                ),
            ],
        );
        pkg.name = "kafka-source".to_string();
        let findings = check_spurious_script(&pkg, &config);
        assert_eq!(findings, [], "no finding for source package payload");
        // The rust standard-library trees live under
        // /usr/lib/rustlib/src/ in *-src packages: the same credit.
        let dir2 = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = spurious_exec_pkg(
            &dir2,
            &[(
                "/usr/lib/rustlib/src/rust/library/core/notes.txt",
                "ASCII text",
                b"library notes\n",
            )],
        );
        pkg.name = "rust1.97-src".to_string();
        let findings = check_spurious_script(&pkg, &config);
        assert_eq!(findings, [], "no finding for rust source payload");
    }

    #[test]
    fn spurious_executable_perm_silent_in_go_source_tree() {
        // The Go source tree is source payload the same way: the
        // go1.* packages are not source-named, but
        // /usr/share/go/<version>/src/ is Go's own shipped source
        // tree, at any depth below `src`.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = spurious_exec_pkg(
            &dir,
            &[
                (
                    "/usr/share/go/1.24/src/README.txt",
                    "ASCII text",
                    b"go source tree\n",
                ),
                (
                    "/usr/share/go/1.24/src/cmd/compile/notes.txt",
                    "ASCII text",
                    b"compiler notes\n",
                ),
            ],
        );
        pkg.name = "go1.24".to_string();
        let findings = check_spurious_script(&pkg, &config);
        assert_eq!(findings, [], "no finding for Go source payload");
    }

    #[test]
    fn spurious_executable_perm_silent_under_usr_src_in_plain_package() {
        // The /usr/src path arm: that tree is where shipped
        // source code lives, so a text file under it is source
        // payload by place, whatever the shipping package is
        // called -- `spurious_exec_pkg` carries an ordinary name
        // with no src/source component, so the shared gate alone
        // would not credit these rows. The identical file
        // outside the tree keeps firing.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = spurious_exec_pkg(
            &dir,
            &[
                ("/usr/src/myapp/data.txt", "ASCII text", b"payload\n"),
                ("/usr/src/myapp/sub/notes.txt", "ASCII text", b"notes\n"),
                ("/usr/share/myapp/data.txt", "ASCII text", b"payload\n"),
            ],
        );
        let findings = check_spurious_script(&pkg, &config);
        assert!(
            !findings
                .iter()
                .any(|(_, _, d)| d.contains("/usr/src/myapp/data.txt")),
            "no finding for /usr/src payload in a plain package: {findings:?}"
        );
        assert!(
            !findings
                .iter()
                .any(|(_, _, d)| d.contains("/usr/src/myapp/sub/notes.txt")),
            "no finding for nested /usr/src payload: {findings:?}"
        );
        assert!(
            findings.iter().any(|(n, _, d)| {
                n == "spurious-executable-perm" && d.contains("/usr/share/myapp/data.txt")
            }),
            "identical payload outside /usr/src keeps firing: {findings:?}"
        );
    }

    #[test]
    fn usr_src_path_arm_does_not_reach_interpreter_findings() {
        // The /usr/src arm belongs to the spurious emission
        // alone: the interpreter findings keep the shared
        // `script_is_source_data` gate, so an env interpreter
        // line under /usr/src in an ordinary package (named
        // nonexec-demo by the helper) draws env-script-interpreter
        // exactly as it did before the arm existed.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = script_mode_pkg(
            &dir,
            &[(
                "/usr/src/myapp/run.sh",
                0o100755,
                "Bourne-Again shell script, ASCII text executable",
                b"#!/usr/bin/env bash\n",
            )],
        );
        let lines = script_finding_lines(&pkg, &config);
        assert!(
            flagged(&lines, "env-script-interpreter", "/usr/src/myapp/run.sh"),
            "env finding under /usr/src in a plain package stands: {lines:?}"
        );
    }

    #[test]
    fn spurious_executable_perm_still_fires_at_source_gate_bounds() {
        // The bounds of the source credit, each pinned with the
        // identical text file shape the silent cases above use.
        let config = test_config();
        let fires = |pkg: &Pkg, path: &str| {
            check_spurious_script(pkg, &config)
                .iter()
                .any(|(name, _, detail)| {
                    name == "spurious-executable-perm" && detail.contains(path)
                })
        };
        // The /usr/src path arm needs the tree itself: a
        // lookalike prefix is not the source tree.
        for path in ["/usr/srcfoo/data.txt", "/usr/src-other/data.txt"] {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let pkg = spurious_exec_pkg(&dir, &[(path, "ASCII text", b"payload\n")]);
            assert!(fires(&pkg, path), "lookalike prefix {path} keeps firing");
        }
        // A %doc row under /usr/src never counts as source
        // payload either -- the doc bound applies to the path
        // arm the same way it applies to the shared gate.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = spurious_exec_pkg(
            &dir,
            &[("/usr/src/myapp/docs/notes.txt", "ASCII text", b"docs\n")],
        );
        pkg.doc_files = vec!["/usr/src/myapp/docs/notes.txt".to_string()];
        assert!(
            fires(&pkg, "/usr/src/myapp/docs/notes.txt"),
            "%doc row under /usr/src keeps firing"
        );
        // A `src` directory component inside a plain package is
        // not covered either -- only the package-name arm and the
        // Go tree are.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = spurious_exec_pkg(
            &dir,
            &[("/usr/share/foo/src/data.txt", "ASCII text", b"payload\n")],
        );
        assert!(
            fires(&pkg, "/usr/share/foo/src/data.txt"),
            "src-named directory in a plain package keeps firing"
        );
        // A `src`/`source` component in a non-final package-name
        // position carries no source fact, and neither does a
        // fused name.
        for name in ["source-highlight", "myresource"] {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let mut pkg = spurious_exec_pkg(
                &dir,
                &[("/usr/share/tool/data.txt", "ASCII text", b"payload\n")],
            );
            pkg.name = name.to_string();
            assert!(
                fires(&pkg, "/usr/share/tool/data.txt"),
                "{name} keeps firing"
            );
        }
        // A %doc row in a source package never counts as source
        // payload.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = spurious_exec_pkg(
            &dir,
            &[("/usr/src/kafka/docs/notes.txt", "ASCII text", b"docs\n")],
        );
        pkg.name = "kafka-source".to_string();
        pkg.doc_files = vec!["/usr/src/kafka/docs/notes.txt".to_string()];
        assert!(
            fires(&pkg, "/usr/src/kafka/docs/notes.txt"),
            "%doc row in a source package keeps firing"
        );
        // The Go arm needs the digit-led version component and the
        // `src` directory itself.
        for path in [
            "/usr/share/go/1.24/misc/wasm/notes.txt",
            "/usr/share/go/latest/src/notes.txt",
        ] {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let mut pkg = spurious_exec_pkg(&dir, &[(path, "ASCII text", b"payload\n")]);
            pkg.name = "go1.24".to_string();
            assert!(fires(&pkg, path), "Go bound {path} keeps firing");
        }
        // The name-based setters are the reference's own
        // spurious-executable-perm population and stay ungated,
        // even inside a source package.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = spurious_exec_pkg(
            &dir,
            &[(
                "/usr/src/kafka/lib/pkgconfig/kafka.pc",
                "ASCII text",
                b"prefix=/usr\n",
            )],
        );
        pkg.name = "kafka-source".to_string();
        assert!(
            fires(&pkg, "/usr/src/kafka/lib/pkgconfig/kafka.pc"),
            "name-arm finding in a source package keeps firing"
        );
        // The doc path is likewise ungated.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = spurious_exec_pkg(
            &dir,
            &[(
                "/usr/share/doc/packages/kafka-source/notes.txt",
                "ASCII text",
                b"docs\n",
            )],
        );
        pkg.name = "kafka-source".to_string();
        assert!(
            fires(&pkg, "/usr/share/doc/packages/kafka-source/notes.txt"),
            "doc-arm finding in a source package keeps firing"
        );
        // A source package's entry point in a script directory is
        // outside the text gate entirely: it keeps the script
        // finding and never flips to spurious-executable-perm.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = spurious_exec_pkg(
            &dir,
            &[("/usr/bin/kafka-helper", "ASCII text", b"echo hi\n")],
        );
        pkg.name = "kafka-source".to_string();
        let findings = check_spurious_script(&pkg, &config);
        assert!(
            findings
                .iter()
                .any(|(name, _, _)| name == "script-without-shebang"),
            "script-dir entry point keeps script-without-shebang: {findings:?}"
        );
        assert!(
            !findings
                .iter()
                .any(|(name, _, _)| name == "spurious-executable-perm"),
            "script-dir entry point never draws spurious-executable-perm: {findings:?}"
        );
    }

    #[test]
    fn spurious_executable_perm_silent_for_nontext_data() {
        // Non-text data (120 control bytes, like the nul.bin probe): the
        // reference early-returns on non-text in the same code path and
        // stays silent, so the istext gate keeps the port silent too.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = spurious_exec_pkg(&dir, &[("/usr/share/data/nul.bin", "data", &[0x01; 120])]);
        let findings = check_spurious_script(&pkg, &config);
        assert_eq!(findings, [], "no finding where the reference is silent");
    }

    #[test]
    fn spurious_executable_perm_silent_for_elf_in_non_script_path() {
        // ELF binaries are executable by design, even outside script paths.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = spurious_exec_pkg(
            &dir,
            &[(
                "/usr/share/games/foo/game",
                "ELF 64-bit LSB executable",
                b"\x7fELF\x02\x01\x01\x00",
            )],
        );
        let findings = check_spurious_script(&pkg, &config);
        assert_eq!(findings, [], "ELF exemption holds outside script paths");
    }

    #[test]
    fn script_path_keeps_script_without_shebang() {
        // Control: a shebang-less executable in a script path keeps the old
        // script-without-shebang Error and must not flip to
        // spurious-executable-perm.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = spurious_exec_pkg(&dir, &[("/usr/bin/noshebang", "ASCII text", b"echo hi\n")]);
        let findings = check_spurious_script(&pkg, &config);
        assert_eq!(
            findings,
            [(
                "script-without-shebang".to_string(),
                Level::Error,
                "spurious-test.noarch: E: script-without-shebang /usr/bin/noshebang".to_string(),
            )],
            "script paths keep script-without-shebang, not spurious"
        );
    }

    #[test]
    fn sws_rpmlintrc_filter_suppresses_text_gate_spurious() {
        // Issue #524 (the grpc shape): the package's rpmlintrc filters the
        // reference tag script-without-shebang, which is exactly the
        // population the #426 rename moved to spurious-executable-perm.
        // The old opt-out must keep working, and the filter must count as
        // used instead of being reported back as unused-rpmlintrc-filter.
        // A second, unrelated rpmlintrc filter stays unused.
        let mut config = test_config();
        let sws = "spurious-test.* script-without-shebang".to_string();
        let unrelated = "spurious-test.* no-such-check".to_string();
        config.filters.push(sws.clone());
        config.filters.push(unrelated.clone());
        config.rpmlintrc_filters = vec![sws, unrelated.clone()];
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = spurious_exec_pkg(
            &dir,
            &[(
                "/usr/share/themes/foo/index.theme",
                "ASCII text",
                b"[Icon Theme]\nName=Foo\n",
            )],
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        assert_eq!(
            spurious_script_findings(&out),
            [],
            "the script-without-shebang filter suppresses the renamed finding"
        );
        assert_eq!(
            out.unused_filters(&config.rpmlintrc_filters),
            vec![unrelated.as_str()],
            "the alias match counts as filter usage; the unrelated filter stays unused"
        );
    }

    #[test]
    fn sws_rpmlintrc_filter_does_not_suppress_name_based_spurious() {
        // Precision guard for #524: a .pc file is spurious under its own
        // tag in the reference too (the name-based setter), so it is not
        // part of the renamed script-without-shebang population and a
        // script-without-shebang filter must not touch it — the filter
        // stays unused.
        let mut config = test_config();
        let sws = "spurious-test.* script-without-shebang".to_string();
        config.filters.push(sws.clone());
        config.rpmlintrc_filters = vec![sws.clone()];
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = spurious_exec_pkg(
            &dir,
            &[("/usr/lib/pkgconfig/foo.pc", "ASCII text", b"prefix=/usr\n")],
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        assert_eq!(
            spurious_script_findings(&out),
            [(
                "spurious-executable-perm".to_string(),
                Level::Warning,
                "spurious-test.noarch: W: spurious-executable-perm \
                 /usr/lib/pkgconfig/foo.pc"
                    .to_string(),
            )],
            "name-based spurious finding is not the renamed population"
        );
        assert_eq!(
            out.unused_filters(&config.rpmlintrc_filters),
            vec![sws.as_str()],
            "no alias match: the filter never fired"
        );
    }

    #[test]
    fn spurious_rpmlintrc_filter_still_suppresses_text_gate_spurious() {
        // Filters written against the new tag keep working unchanged.
        let mut config = test_config();
        config
            .filters
            .push("spurious-test.* spurious-executable-perm".to_string());
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = spurious_exec_pkg(
            &dir,
            &[(
                "/usr/share/themes/foo/index.theme",
                "ASCII text",
                b"[Icon Theme]\nName=Foo\n",
            )],
        );
        let findings = check_spurious_script(&pkg, &config);
        assert_eq!(findings, [], "the current-tag filter still suppresses");
    }

    #[test]
    fn la_file_in_lib_path_is_quiet() {
        // The reference is deliberately silent on .la files in lib paths:
        // its devel-file regex covers .a but not .la, and the
        // script-without-shebang path exempts (lib path + .la). Crab's
        // script-without-shebang branch carries the same exemption; the
        // text gate in check_normal_exec must not fire
        // spurious-executable-perm there either (#493).
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = spurious_exec_pkg(
            &dir,
            &[
                (
                    "/usr/lib64/libfoo.la",
                    "ASCII text",
                    b"# libfoo.la - a libtool library file\ndlname='libfoo.so.1'\n",
                ),
                (
                    "/usr/lib/libbar.la",
                    "ASCII text",
                    b"# libbar.la - a libtool library file\ndlname='libbar.so.0'\n",
                ),
            ],
        );
        let findings = check_spurious_script(&pkg, &config);
        assert_eq!(findings, [], "no finding for .la files in lib paths");
    }

    #[test]
    fn la_file_outside_lib_path_keeps_spurious() {
        // The reference exemption needs the lib path; a .la file elsewhere
        // is a plain data file and keeps the #426 reclassification (the
        // reference fires script-without-shebang on the same file).
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = spurious_exec_pkg(
            &dir,
            &[(
                "/usr/share/foo/libfoo.la",
                "ASCII text",
                b"# libfoo.la - a libtool library file\ndlname='libfoo.so.1'\n",
            )],
        );
        let findings = check_spurious_script(&pkg, &config);
        assert_eq!(
            findings,
            [(
                "spurious-executable-perm".to_string(),
                Level::Warning,
                "spurious-test.noarch: W: spurious-executable-perm \
                 /usr/share/foo/libfoo.la"
                    .to_string(),
            )],
            "exactly one pinned (name, Level, detail) triple"
        );
    }

    #[test]
    fn mingw_dll_a_spurious_perm_is_quiet() {
        // Issue #522: GCC and libtool create MinGW import libraries with
        // the executable bit set, and the Factory session filters
        // spurious-executable-perm for *.dll.a in the family via
        // mingw32.toml. The filter has no path condition: both the
        // cross-gcc host-libdir copies and the sys-root copies stay
        // quiet.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = spurious_exec_pkg(
            &dir,
            &[
                (
                    "/usr/lib64/gcc/x86_64-w64-mingw32/16.2.0/libfoo.dll.a",
                    "current ar archive",
                    b"!<arch>\n",
                ),
                (
                    "/usr/x86_64-w64-mingw32/sys-root/mingw/lib/libbar.dll.a",
                    "current ar archive",
                    b"!<arch>\n",
                ),
            ],
        );
        pkg.name = "mingw64-cross-gcc".to_string();
        let findings = check_spurious_script(&pkg, &config);
        assert!(
            findings.is_empty(),
            "no finding for MinGW *.dll.a: {findings:?}"
        );
    }

    #[test]
    fn dll_a_spurious_perm_fires_in_non_mingw_package() {
        // Control for the MinGW suppression: the same executable import
        // library in a package outside the family still fires.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = spurious_exec_pkg(
            &dir,
            &[(
                "/usr/lib64/gcc/x86_64-w64-mingw32/16.2.0/libfoo.dll.a",
                "current ar archive",
                b"!<arch>\n",
            )],
        );
        let findings = check_spurious_script(&pkg, &config);
        assert_eq!(
            findings,
            [(
                "spurious-executable-perm".to_string(),
                Level::Warning,
                "spurious-test.noarch: W: spurious-executable-perm \
                 /usr/lib64/gcc/x86_64-w64-mingw32/16.2.0/libfoo.dll.a"
                    .to_string(),
            )],
        );
    }

    #[test]
    fn mingw_plain_archive_spurious_perm_still_fires() {
        // Scope pin: the mingw32.toml filter covers only *.dll.a; an
        // executable plain .a in a MinGW package still fires.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = spurious_exec_pkg(
            &dir,
            &[(
                "/usr/lib64/gcc/x86_64-w64-mingw32/16.2.0/libfoo.a",
                "current ar archive",
                b"!<arch>\n",
            )],
        );
        pkg.name = "mingw64-cross-gcc".to_string();
        let findings = check_spurious_script(&pkg, &config);
        assert_eq!(
            findings,
            [(
                "spurious-executable-perm".to_string(),
                Level::Warning,
                "mingw64-cross-gcc.noarch: W: spurious-executable-perm \
                 /usr/lib64/gcc/x86_64-w64-mingw32/16.2.0/libfoo.a"
                    .to_string(),
            )],
        );
    }

    #[test]
    fn sourced_script_with_shebang_pins_name_level_and_detail() {
        // A sourced script (profile.d) carrying a shebang is an Error naming
        // the file and its interpreter; the args variant pins the
        // interpreter arguments in the detail. The executable variant
        // additionally fires executable-sourced-script. The shebang-less
        // and .pm controls stay silent (the perl-module shebang exception).
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = fixture_path("w6-sourced-script-1.0-1.noarch.rpm");
        let pkg = Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let levels = out.result_levels().to_vec();
        let findings: Vec<(String, Level, String)> = out
            .results()
            .iter()
            .zip(levels)
            .map(|((name, detail), level)| (name.clone(), level, detail.clone()))
            .collect();
        let mut details: Vec<&str> = findings
            .iter()
            .filter(|(name, _, _)| name == "sourced-script-with-shebang")
            .map(|(_, level, detail)| {
                assert_eq!(*level, Level::Error, "sourced-script-with-shebang is E");
                detail.as_str()
            })
            .collect();
        details.sort_unstable();
        assert_eq!(
            details,
            [
                "w6-sourced-script.noarch: E: sourced-script-with-shebang /etc/profile.d/w6-args.sh /bin/sh -x -e",
                "w6-sourced-script.noarch: E: sourced-script-with-shebang /etc/profile.d/w6-exec.sh /bin/sh",
                "w6-sourced-script.noarch: E: sourced-script-with-shebang /etc/profile.d/w6-shebang.sh /bin/sh",
            ],
            "name+level+detail: {findings:?}"
        );
        let exec: Vec<_> = findings
            .iter()
            .filter(|(name, _, _)| name == "executable-sourced-script")
            .collect();
        assert_eq!(exec.len(), 1, "only the executable variant: {findings:?}");
        assert!(exec[0].2.contains("w6-exec.sh"), "detail: {}", exec[0].2);
        for (name, _, detail) in &findings {
            if name == "sourced-script-with-shebang" || name == "executable-sourced-script" {
                assert!(
                    !detail.contains("w6-clean.sh") && !detail.contains("w6module.pm"),
                    "control fired {name}: {detail}"
                );
            }
        }
    }

    fn bidi_pkg(dir: &tempfile::TempDir, files: Vec<(&str, &str, Vec<u8>)>) -> Pkg {
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        pkg.files = files
            .into_iter()
            .map(|(name, magic, content)| {
                let path = dir.path().join(name.trim_start_matches('/'));
                std::fs::write(&path, &content).expect("write temp file");
                PkgFile {
                    name: name.to_string(),
                    path: path.to_string_lossy().into_owned(),
                    mode: 0o100644,
                    magic: magic.to_string(),
                    ..Default::default()
                }
            })
            .collect();
        pkg
    }

    fn bidi_findings(out: &Filter) -> Vec<(Level, String)> {
        out.results()
            .iter()
            .zip(out.result_levels().iter())
            .filter(|((name, _), _)| *name == "bidi-control-character")
            .map(|((_, line), level)| (*level, line.clone()))
            .collect()
    }

    #[test]
    fn normal_non_devel_typelib_in_devel_package() {
        // .typelib in a -devel package: non-devel payload, lib half needs a .so path.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = "foo-devel".to_string();
        pkg.doc_files = vec![];
        let fname = "/usr/lib64/girepository-1.0/Foo-1.0.typelib";
        let path = dir.path().join(fname.trim_start_matches('/'));
        std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
        std::fs::write(&path, b"typelib\n").expect("write temp file");
        pkg.files = vec![PkgFile {
            name: fname.to_string(),
            path: path.to_string_lossy().into_owned(),
            mode: 0o100644,
            magic: "ASCII text".to_string(),
            ..Default::default()
        }];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "non-devel-file-in-devel-package");
    }

    #[test]
    fn normal_lib_versioned_so_in_devel_package() {
        // Versioned .so in -devel: lib half fires, exact-.so symlink exemption needs a bare .so.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = "foo-devel".to_string();
        pkg.doc_files = vec![];
        let fname = "/usr/lib64/libfoo.so.1.2.3";
        let path = dir.path().join(fname.trim_start_matches('/'));
        std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
        std::fs::write(&path, b"fake lib\n").expect("write temp file");
        pkg.files = vec![PkgFile {
            name: fname.to_string(),
            path: path.to_string_lossy().into_owned(),
            mode: 0o100644,
            magic: "ASCII text".to_string(),
            ..Default::default()
        }];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "non-devel-file-in-devel-package");
    }

    #[test]
    fn debuginfo_flags_populate_from_file_kinds() {
        // Port of the reference's _check_file_normal_file_debuginfo: a
        // debuginfo package's .debug files set debugs, any other regular
        // file sets srcs.
        let config = test_config();
        let check = FilesCheck::new(&config);
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let debug_path = dir.path().join("foo.debug");
        std::fs::write(&debug_path, b"").expect("write debug");
        let other_path = dir.path().join("foo");
        std::fs::write(&other_path, b"").expect("write other");
        let pkg = pybc_pkg(&dir, &[]);
        let mut st = PkgState {
            debuginfo_package: true,
            ..Default::default()
        };
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let debug = PkgFile {
            name: "/usr/lib/debug/usr/bin/foo.debug".to_string(),
            path: debug_path.to_string_lossy().into_owned(),
            mode: 0o100644,
            ..Default::default()
        };
        check.check_file_normal_file(&pkg, debug.name.as_str(), &debug, &mut st, &mut out);
        assert!(st.debuginfo_debugs, "a .debug file sets debugs");
        assert!(!st.debuginfo_srcs, "no non-.debug file seen yet");
        let other = PkgFile {
            name: "/usr/lib/debug/usr/bin/foo".to_string(),
            path: other_path.to_string_lossy().into_owned(),
            mode: 0o100644,
            ..Default::default()
        };
        check.check_file_normal_file(&pkg, other.name.as_str(), &other, &mut st, &mut out);
        assert!(st.debuginfo_srcs, "a non-.debug file sets srcs");
    }

    #[test]
    fn debuginfo_without_sources_fires_on_debugs_only() {
        let mut config = test_config();
        config
            .configuration
            .insert("UseDebugSource".to_string(), toml::Value::Boolean(false));
        let check = FilesCheck::new(&config);
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = pybc_pkg(&dir, &[]);
        let mut st = PkgState {
            debuginfo_package: true,
            debuginfo_debugs: true,
            ..Default::default()
        };
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_debuginfo_without_sources(&pkg, &st, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "debuginfo-without-sources");
        st.debuginfo_srcs = true;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_debuginfo_without_sources(&pkg, &st, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "debuginfo-without-sources");
    }

    #[test]
    fn debug_companion_in_debuginfo_package_is_quiet() {
        // Issue #955: a -debuginfo package's payload is the mirrored
        // .debug companion of the versioned runtime library; the lib
        // arm scopes the debug trees out.
        let lines = non_devel_lines(
            "libply5-debuginfo",
            &["/usr/lib/debug/usr/lib64/libply.so.5.0.0.debug"],
        );
        assert!(lines.is_empty(), "debug companion must be quiet: {lines:?}");
        // Near misses stay charged: a real versioned runtime library
        // in a -devel package, and a lib-shaped path under a
        // lookalike prefix.
        let lines = non_devel_lines("foo-devel", &["/usr/lib64/libfoo.so.1.2.3"]);
        assert_eq!(lines.len(), 1, "real runtime lib must fire: {lines:?}");
        let lines = non_devel_lines(
            "foo-devel",
            &["/usr/lib/debugfoo/usr/lib64/libfoo.so.1.2.3"],
        );
        assert_eq!(lines.len(), 1, "debugfoo lookalike must fire: {lines:?}");
    }

    // Issue #860: run the check over one synthetic package and
    // return the `non-devel-file-in-devel-package` report lines.
    fn non_devel_lines(pkg_name: &str, fnames: &[&str]) -> Vec<String> {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = pkg_name.to_string();
        pkg.doc_files = vec![];
        pkg.files = fnames
            .iter()
            .map(|fname| {
                let path = dir.path().join(fname.trim_start_matches('/'));
                std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
                std::fs::write(&path, b"fake lib\n").expect("write temp file");
                PkgFile {
                    name: fname.to_string(),
                    path: path.to_string_lossy().into_owned(),
                    mode: 0o100644,
                    magic: "ASCII text".to_string(),
                    ..Default::default()
                }
            })
            .collect();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        out.results()
            .iter()
            .filter(|(name, _)| name == "non-devel-file-in-devel-package")
            .map(|(_, line)| line.clone())
            .collect()
    }

    /// Like `non_devel_lines`, but each file carries a mode and a
    /// symlink target (empty for regular files), and the package may
    /// carry explicit Provides — the devel classification can come
    /// from a Provide rather than the package name.
    fn non_devel_lines_typed(
        pkg_name: &str,
        provides: &[&str],
        files: &[(&str, u32, &str)],
    ) -> Vec<String> {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = pkg_name.to_string();
        pkg.doc_files = vec![];
        pkg.provides = provides.iter().map(|p| dep_named(p)).collect();
        pkg.files = files
            .iter()
            .map(|(fname, mode, linkto)| {
                let path = dir.path().join(fname.trim_start_matches('/'));
                std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
                std::fs::write(&path, b"fake lib\n").expect("write temp file");
                PkgFile {
                    name: fname.to_string(),
                    path: path.to_string_lossy().into_owned(),
                    mode: *mode,
                    magic: "ASCII text".to_string(),
                    linkto: linkto.to_string(),
                    ..Default::default()
                }
            })
            .collect();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        out.results()
            .iter()
            .filter(|(name, _)| name == "non-devel-file-in-devel-package")
            .map(|(_, line)| line.clone())
            .collect()
    }

    #[test]
    fn combined_home_linker_symlink_is_quiet() {
        // gettext-tools shape: a tools package that is its library's
        // combined home — the versioned library plus the linker
        // symlink resolving to it in the same package. The devel
        // classification comes from the gettext-devel Provide.
        let lines = non_devel_lines_typed(
            "gettext-tools",
            &["gettext-devel"],
            &[
                ("/usr/lib64/libgettextpo.so.0.6.0", 0o100644, ""),
                (
                    "/usr/lib64/libgettextpo.so",
                    0o120777,
                    "libgettextpo.so.0.6.0",
                ),
            ],
        );
        assert!(lines.is_empty(), "combined home must be quiet: {lines:?}");
        // glib2-stage1 shape: a -devel-named bootstrap package whose
        // linker chain runs through the SONAME symlink.
        let lines = non_devel_lines_typed(
            "foo-devel",
            &[],
            &[
                ("/usr/lib64/libfoo.so.1.2.3", 0o100644, ""),
                ("/usr/lib64/libfoo.so.1", 0o120777, "libfoo.so.1.2.3"),
                ("/usr/lib64/libfoo.so", 0o120777, "libfoo.so.1"),
            ],
        );
        assert!(
            lines.is_empty(),
            "two-hop combined home must be quiet: {lines:?}"
        );
    }

    #[test]
    fn combined_home_near_misses_still_fire() {
        // Linker symlink present, but its target is not shipped: the
        // chain points at a runtime home elsewhere.
        let lines = non_devel_lines_typed(
            "foo-devel",
            &[],
            &[
                ("/usr/lib64/libfoo.so.1.2.3", 0o100644, ""),
                ("/usr/lib64/libfoo.so", 0o120777, "libfoo.so.1"),
            ],
        );
        assert_eq!(lines.len(), 1, "dangling linker chain must fire: {lines:?}");
        // The linker symlink belongs to another library of the same
        // package; the versioned libfoo has no devel payload here.
        let lines = non_devel_lines_typed(
            "foo-devel",
            &[],
            &[
                ("/usr/lib64/libfoo.so.1.2.3", 0o100644, ""),
                ("/usr/lib64/libbar.so.9.9", 0o100644, ""),
                ("/usr/lib64/libbar.so", 0o120777, "libbar.so.9.9"),
            ],
        );
        assert_eq!(lines.len(), 1, "only libfoo must fire: {lines:?}");
        assert!(lines[0].contains("libfoo"), "{lines:?}");
        // A -devel Provide unrelated to the shipped library does not
        // credit on its own: no linker symlink, no combined home.
        let lines = non_devel_lines_typed(
            "bar-tools",
            &["foo-devel"],
            &[("/usr/lib64/libbar.so.1.2.3", 0o100644, "")],
        );
        assert_eq!(
            lines.len(),
            1,
            "unrelated Provide must not credit: {lines:?}"
        );
        // A regular file at the linker name is not a linker symlink.
        let lines = non_devel_lines_typed(
            "foo-devel",
            &[],
            &[
                ("/usr/lib64/libfoo.so.1.2.3", 0o100644, ""),
                ("/usr/lib64/libfoo.so", 0o100644, ""),
            ],
        );
        assert_eq!(
            lines.len(),
            1,
            "regular libfoo.so must not credit: {lines:?}"
        );
    }

    #[test]
    fn combined_home_does_not_touch_the_typelib_arm() {
        // nemo-extension-preview shape: the package's own typelib is
        // charged by the .typelib arm; the combined-home credit is
        // scoped to the versioned-library arm.
        let lines = non_devel_lines_typed(
            "nemo-extension-preview",
            &["nemo-extension-preview-devel"],
            &[(
                "/usr/lib64/nemo-preview/girepository-1.0/NemoPreview-1.0.typelib",
                0o100644,
                "",
            )],
        );
        assert_eq!(lines.len(), 1, "typelib arm must still fire: {lines:?}");
    }

    #[test]
    fn cross_sysroot_runtime_libs_in_devel_package_are_quiet() {
        // Issue #860: the glibc-cross packages ship the target's
        // runtime libraries under the sys-root; that payload is the
        // cross devel package's own content, not host layout.
        let lines = non_devel_lines(
            "cross-aarch64-glibc-devel",
            &[
                "/usr/aarch64-suse-linux/sys-root/lib64/libc.so.6",
                "/usr/aarch64-suse-linux/sys-root/lib64/libanl.so.1",
                "/usr/hppa-suse-linux/sys-root/lib/libc.so.6",
                // the whole triplet tree is target content: no
                // sys-root component is required
                "/usr/powerpc64le-suse-linux/lib64/libc.so.6",
            ],
        );
        assert!(lines.is_empty(), "{lines:?}");
    }

    #[test]
    fn every_measured_cross_sysroot_is_quiet_for_non_devel() {
        // Pin the whole measured set against this check too: a
        // sysroot dropped from the shared set fails here as well as
        // in FHSCheck's own pin on the set.
        for sysroot in crate::checks::fhs::FHS_USR_CROSS_SYSROOTS {
            let path = format!("/usr/{sysroot}/sys-root/lib64/libc.so.6");
            let lines = non_devel_lines("cross-foo-glibc-devel", &[&path]);
            assert!(lines.is_empty(), "{sysroot}: {lines:?}");
        }
    }

    #[test]
    fn non_devel_still_fires_outside_the_measured_sysroots() {
        // The sanction is the measured set in the leading component,
        // not the triplet shape and not the sys-root name anywhere in
        // the path: host layout, a novel triplet, a measured name
        // extended by a suffix and a sysroot name below another
        // component all keep firing.
        let fnames = [
            "/usr/lib64/libc.so.6",
            "/usr/frobnicate-suse-linux/sys-root/lib64/libc.so.6",
            "/usr/aarch64-suse-linux2/sys-root/lib64/libc.so.6",
            "/usr/share/aarch64-suse-linux/sys-root/lib64/libc.so.6",
            "/usr/local/aarch64-suse-linux/sys-root/lib64/libc.so.6",
        ];
        let lines = non_devel_lines("cross-aarch64-glibc-devel", &fnames);
        assert_eq!(lines.len(), fnames.len(), "{lines:?}");
        for fname in fnames {
            assert!(
                lines.iter().any(|l| l.contains(fname)),
                "{fname}: {lines:?}"
            );
        }
    }

    #[test]
    fn cross_sysroot_typelib_in_devel_package_is_quiet() {
        // The scoping is a property of the path, so the typelib arm
        // of the finding is scoped the same way.
        let lines = non_devel_lines(
            "cross-aarch64-glibc-devel",
            &["/usr/aarch64-suse-linux/sys-root/lib64/girepository-1.0/Target-1.0.typelib"],
        );
        assert!(lines.is_empty(), "{lines:?}");
        // the same payload at a host path keeps firing
        let lines = non_devel_lines(
            "foo-devel",
            &["/usr/lib64/girepository-1.0/Foo-1.0.typelib"],
        );
        assert_eq!(lines.len(), 1, "{lines:?}");
    }

    #[test]
    fn normal_perl_dep_missing_versioned_dep() {
        // Perl module path with no versioned perl dep: compat and version checks have nothing to match.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = "foo".to_string();
        pkg.requires = vec![];
        pkg.prereq = vec![];
        pkg.recommends = vec![];
        pkg.suggests = vec![];
        pkg.doc_files = vec![];
        let fname = "/usr/lib/perl5/vendor_perl/5.38.2/Foo/Bar.pm";
        let path = dir.path().join(fname.trim_start_matches('/'));
        std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
        std::fs::write(&path, b"package Foo::Bar;\n1;\n").expect("write temp file");
        pkg.files = vec![PkgFile {
            name: fname.to_string(),
            path: path.to_string_lossy().into_owned(),
            mode: 0o100644,
            magic: "ASCII text".to_string(),
            ..Default::default()
        }];
        let (results, _levels) = run_files_check_pkgs(&[pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "no-dependency-on");
    }

    #[test]
    fn normal_python_dep_missing_versioned_dep() {
        // Python module path with no versioned python dep.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = "foo".to_string();
        pkg.requires = vec![];
        pkg.prereq = vec![];
        pkg.recommends = vec![];
        pkg.suggests = vec![];
        pkg.doc_files = vec![];
        let fname = "/usr/lib/python3.12/site-packages/foo.py";
        let path = dir.path().join(fname.trim_start_matches('/'));
        std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
        std::fs::write(&path, b"x = 1\n").expect("write temp file");
        pkg.files = vec![PkgFile {
            name: fname.to_string(),
            path: path.to_string_lossy().into_owned(),
            mode: 0o100644,
            magic: "ASCII text".to_string(),
            ..Default::default()
        }];
        let (results, _levels) = run_files_check_pkgs(&[pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "no-dependency-on");
    }

    fn dep_flagged(name: &str, flags: u32, version: Option<&str>) -> crate::pkg::dep::DepInfo {
        crate::pkg::dep::DepInfo {
            name: name.to_string(),
            flags,
            epoch: None,
            version: version.map(str::to_string),
            release: None,
        }
    }

    /// Run FilesCheck over a package named `pkg_name` shipping one real
    /// file `fname` with the given Requires, through the batch
    /// lifecycle (issue #862: findings the base rules defer to
    /// `after_checks` must be visible here); return the finding names.
    fn run_dep_check(
        pkg_name: &str,
        requires: Vec<crate::pkg::dep::DepInfo>,
        fname: &str,
        contents: &[u8],
    ) -> Vec<String> {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = pkg_name.to_string();
        pkg.requires = requires;
        pkg.prereq = vec![];
        pkg.recommends = vec![];
        pkg.suggests = vec![];
        pkg.doc_files = vec![];
        let path = dir.path().join(fname.trim_start_matches('/'));
        std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
        std::fs::write(&path, contents).expect("write temp file");
        pkg.files = vec![PkgFile {
            name: fname.to_string(),
            path: path.to_string_lossy().into_owned(),
            mode: 0o100644,
            magic: "ASCII text".to_string(),
            ..Default::default()
        }];
        let (results, _levels) = run_files_check_pkgs(&[pkg], &config);
        results.iter().map(|(n, _)| n.clone()).collect()
    }

    /// Fabricate a package over the shared fixture the way
    /// `run_dep_check` does: named `pkg_name`, with the given Requires
    /// and — when `file` is given — one real file (name, contents)
    /// written under a per-package subdirectory of `dir`, so several
    /// fabricated packages can share one TempDir (issue #862 session
    /// tests).
    fn dep_test_pkg(
        dir: &tempfile::TempDir,
        pkg_name: &str,
        requires: Vec<crate::pkg::dep::DepInfo>,
        file: Option<(&str, &[u8])>,
    ) -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = pkg_name.to_string();
        pkg.requires = requires;
        pkg.prereq = vec![];
        pkg.recommends = vec![];
        pkg.suggests = vec![];
        pkg.doc_files = vec![];
        pkg.files = match file {
            Some((fname, contents)) => {
                let path = dir
                    .path()
                    .join(pkg_name)
                    .join(fname.trim_start_matches('/'));
                std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
                std::fs::write(&path, contents).expect("write temp file");
                vec![PkgFile {
                    name: fname.to_string(),
                    path: path.to_string_lossy().into_owned(),
                    mode: 0o100644,
                    magic: "ASCII text".to_string(),
                    ..Default::default()
                }]
            }
            None => vec![],
        };
        pkg
    }

    #[test]
    fn normal_python_dep_python3_base_unversioned_satisfies() {
        // SUSE's base package name, in the unversioned form specs use.
        let names = run_dep_check(
            "foo",
            vec![dep_named("python3-base")],
            "/usr/lib/python3.13/site-packages/foo.py",
            b"x = 1\n",
        );
        assert_lacks(&names, "no-dependency-on");
    }

    #[test]
    fn normal_python_dep_python3_base_floor_satisfies() {
        // The `>=` floor form also carries the base dependency.
        let names = run_dep_check(
            "foo",
            vec![dep_flagged("python3-base", 12, Some("3.8"))],
            "/usr/lib/python3.13/site-packages/foo.py",
            b"x = 1\n",
        );
        assert_lacks(&names, "no-dependency-on");
    }

    #[test]
    fn normal_python_dep_interpreter_path_satisfies() {
        // The interpreter-path dependency pins the version in the path.
        let names = run_dep_check(
            "foo",
            vec![dep_flagged("/usr/bin/python3.13", 16384, None)],
            "/usr/lib/python3.13/site-packages/foo.py",
            b"x = 1\n",
        );
        assert_lacks(&names, "no-dependency-on");
    }

    #[test]
    fn normal_python_dep_interpreter_path_other_version_fires() {
        // An interpreter path for a different version is not the dep owed.
        let names = run_dep_check(
            "foo",
            vec![dep_flagged("/usr/bin/python3.12", 16384, None)],
            "/usr/lib/python3.13/site-packages/foo.py",
            b"x = 1\n",
        );
        assert_has(&names, "no-dependency-on");
    }

    #[test]
    fn normal_python_dep_unrelated_python_name_fires() {
        // A bare `python3` dependency is not the base package.
        let names = run_dep_check(
            "foo",
            vec![dep_named("python3")],
            "/usr/lib/python3.13/site-packages/foo.py",
            b"x = 1\n",
        );
        assert_has(&names, "no-dependency-on");
    }

    #[test]
    fn normal_python_dep_base_packages_quiet() {
        // The base packages cannot depend on themselves.
        for base in ["python-base", "python3-base"] {
            let names = run_dep_check(
                base,
                vec![],
                "/usr/lib/python3.13/site-packages/foo.py",
                b"x = 1\n",
            );
            assert_lacks(&names, "no-dependency-on");
        }
    }

    #[test]
    fn normal_perl_dep_base_package_quiet() {
        // The base package cannot depend on itself.
        let names = run_dep_check(
            "perl-base",
            vec![],
            "/usr/lib/perl5/vendor_perl/5.44.0/Foo/Bar.pm",
            b"package Foo::Bar;\n1;\n",
        );
        assert_lacks(&names, "no-dependency-on");
    }

    #[test]
    fn normal_perl_dep_interpreter_path_satisfies() {
        // Issue #862: the unversioned interpreter path is the perl
        // dependency expressed as a file dependency (collectd,
        // perl-Net-IPv4Addr, remind in the corpus).
        let names = run_dep_check(
            "foo",
            vec![dep_flagged("/usr/bin/perl", 16384, None)],
            "/usr/lib/perl5/vendor_perl/5.44.0/Foo/Bar.pm",
            b"package Foo::Bar;\n1;\n",
        );
        assert_lacks(&names, "no-dependency-on");
    }

    #[test]
    fn normal_perl_dep_libperl_soname_satisfies() {
        // Issue #862: a module linked against libperl carries the
        // interpreter dependency as the soname (perl-libdnf5,
        // perl-mapscript in the corpus).
        let names = run_dep_check(
            "foo",
            vec![dep_flagged("libperl.so()(64bit)", 16384, None)],
            "/usr/lib/perl5/vendor_perl/5.44.0/Foo/Bar.pm",
            b"package Foo::Bar;\n1;\n",
        );
        assert_lacks(&names, "no-dependency-on");
    }

    #[test]
    fn normal_perl_dep_unpinned_perl_name_fires() {
        // A bare `perl` requirement expresses no version at all: the
        // `=` pin / MODULE_COMPAT semantics are deliberate (perl-NKF
        // in the corpus), so the finding stands.
        let names = run_dep_check(
            "foo",
            vec![dep_named("perl")],
            "/usr/lib/perl5/vendor_perl/5.44.0/Foo/Bar.pm",
            b"package Foo::Bar;\n1;\n",
        );
        assert_has(&names, "no-dependency-on");
    }

    #[test]
    fn normal_python_dep_unversioned_interpreter_path_satisfies() {
        // Issue #862: the unversioned interpreter path is the python
        // dependency expressed as a file dependency.
        let names = run_dep_check(
            "foo",
            vec![dep_flagged("/usr/bin/python3", 16384, None)],
            "/usr/lib/python3.13/site-packages/foo.py",
            b"x = 1\n",
        );
        assert_lacks(&names, "no-dependency-on");
    }

    #[test]
    fn normal_python_dep_libpython_soname_satisfies() {
        // Issue #862: a consumer linked against libpython carries the
        // interpreter dependency as the versioned soname (the dnf5
        // plugins loader in the corpus).
        let names = run_dep_check(
            "foo",
            vec![dep_flagged("libpython3.13.so.1.0()(64bit)", 16384, None)],
            "/usr/lib/python3.13/site-packages/foo.py",
            b"x = 1\n",
        );
        assert_lacks(&names, "no-dependency-on");
    }

    #[test]
    fn normal_python_dep_libpython_soname_other_version_fires() {
        // The soname pins its own version: libpython for 3.14 is not
        // the dependency 3.13 files owe.
        let names = run_dep_check(
            "foo",
            vec![dep_flagged("libpython3.14.so.1.0()(64bit)", 16384, None)],
            "/usr/lib/python3.13/site-packages/foo.py",
            b"x = 1\n",
        );
        assert_has(&names, "no-dependency-on");
    }

    #[test]
    fn normal_python_dep_non_interpreter_deps_fire() {
        // File and soname dependencies on anything but the
        // interpreter credit nothing.
        let names = run_dep_check(
            "foo",
            vec![
                dep_flagged("libc.so.6()(64bit)", 16384, None),
                dep_flagged("/usr/bin/make", 16384, None),
            ],
            "/usr/lib/python3.13/site-packages/foo.py",
            b"x = 1\n",
        );
        assert_has(&names, "no-dependency-on");
    }

    #[test]
    fn normal_python_dep_flavour_base_name_satisfies() {
        // The flavour-named base form is the base dependency: the
        // package `python313-base` is the very package that provides
        // the credited `python3-base` name. #568 and #862 left the
        // form uncredited; it is credited (any relation, floor
        // included).
        let names = run_dep_check(
            "foo",
            vec![dep_flagged("python313-base", 12, Some("3.9"))],
            "/usr/lib/python3.13/site-packages/foo.py",
            b"x = 1\n",
        );
        assert_lacks(&names, "no-dependency-on");
    }

    #[test]
    fn normal_python_dep_flavour_base_name_other_flavour_satisfies() {
        // The 3.14 flavour's base package provides no `python3-base`
        // at all, so the flavour name is the only spelling of its
        // base dependency.
        let names = run_dep_check(
            "foo",
            vec![dep_flagged("python314-base", 12, Some("3.9"))],
            "/usr/lib/python3.14/site-packages/foo.py",
            b"x = 1\n",
        );
        assert_lacks(&names, "no-dependency-on");
    }

    #[test]
    fn normal_python_dep_flavour_base_name_arch_qualified_satisfies() {
        // The `(arch-bits)` qualifier shape counts, as it does for
        // the `python3-base` name (`dep_name_matches` semantics).
        let names = run_dep_check(
            "foo",
            vec![dep_named("python313-base(x86-64)")],
            "/usr/lib/python3.13/site-packages/foo.py",
            b"x = 1\n",
        );
        assert_lacks(&names, "no-dependency-on");
    }

    #[test]
    fn normal_python_dep_flavour_base_lookalikes_fire() {
        // The grammar is exact - `python3` + digits + `-base` and
        // nothing else: a suffixed package name, a letter in the
        // digit run and a flavour module package are not the base.
        let names = run_dep_check(
            "foo",
            vec![
                dep_named("python313-base-devel"),
                dep_named("python31a-base"),
                dep_named("python313-gobject"),
            ],
            "/usr/lib/python3.13/site-packages/foo.py",
            b"x = 1\n",
        );
        assert_has(&names, "no-dependency-on");
    }

    /// The `no-dependency-on` lines of a session run, rendered.
    fn nodep_lines(results: &[(String, String)]) -> Vec<&str> {
        results
            .iter()
            .filter(|(n, _)| n == "no-dependency-on")
            .map(|(_, line)| line.as_str())
            .collect()
    }

    #[test]
    fn normal_python_dep_anchor_sibling_carries_base() {
        // Issue #862: the -lang subpackage requires its main package
        // (WTForms-lang in the corpus), and the main package carries
        // the base dependency — the subpackage stays quiet, in either
        // lint order.
        let config = test_config();
        for order in [0, 1] {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let lang = dep_test_pkg(
                &dir,
                "foo-lang",
                vec![dep_flagged("foo", 8, Some("1.0"))],
                Some(("/usr/lib/python3.13/site-packages/foo.py", b"x = 1\n")),
            );
            let main = dep_test_pkg(
                &dir,
                "foo",
                vec![dep_flagged("python(abi)", 8, Some("3.13"))],
                None,
            );
            let pkgs = if order == 0 {
                vec![lang, main]
            } else {
                vec![main, lang]
            };
            let (results, _levels) = run_files_check_pkgs(&pkgs, &config);
            assert!(
                nodep_lines(&results).is_empty(),
                "order {order}: got {:?}",
                nodep_lines(&results)
            );
        }
    }

    #[test]
    fn normal_python_dep_anchor_sibling_carries_flavour_base() {
        // The anchor judgement shares the own-package predicate: a
        // sibling carrying the base dependency in its flavour-named
        // form credits the anchored package the same way.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let lang = dep_test_pkg(
            &dir,
            "foo-lang",
            vec![dep_flagged("foo", 8, Some("1.0"))],
            Some(("/usr/lib/python3.13/site-packages/foo.py", b"x = 1\n")),
        );
        let main = dep_test_pkg(
            &dir,
            "foo",
            vec![dep_flagged("python313-base", 12, Some("3.9"))],
            None,
        );
        let (results, _levels) = run_files_check_pkgs(&[lang, main], &config);
        assert!(
            nodep_lines(&results).is_empty(),
            "got {:?}",
            nodep_lines(&results)
        );
    }

    #[test]
    fn normal_python_dep_anchor_sibling_without_base_fires() {
        // The anchor sibling must itself carry the base dependency:
        // folder-color-common in the corpus is required by its
        // extension siblings and carries no python dependency, so
        // anchoring on it credits nothing.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let lang = dep_test_pkg(
            &dir,
            "foo-lang",
            vec![dep_flagged("foo-common", 8, Some("1.0"))],
            Some(("/usr/lib/python3.13/site-packages/foo.py", b"x = 1\n")),
        );
        let common = dep_test_pkg(&dir, "foo-common", vec![dep_named("gtk3-tools")], None);
        let (results, _levels) = run_files_check_pkgs(&[lang, common], &config);
        let lines = nodep_lines(&results);
        assert_eq!(lines.len(), 1, "got: {lines:?}");
        assert!(lines[0].starts_with("foo-lang.noarch"), "got: {}", lines[0]);
    }

    #[test]
    fn normal_python_dep_anchor_other_source_fires() {
        // A requirement on a package of another source that carries
        // the base dependency credits nothing: transitive credit
        // would gut the check (the azure leaves' cross-source
        // requirements in the corpus).
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let lang = dep_test_pkg(
            &dir,
            "foo-lang",
            vec![dep_flagged("ext-main", 8, Some("1.0"))],
            Some(("/usr/lib/python3.13/site-packages/foo.py", b"x = 1\n")),
        );
        // A fixture built from a different spec: its SOURCERPM
        // differs from the shared fixture's, so it is another source.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/nodoc-lone-1.0-1.noarch.rpm");
        let mut ext = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        ext.name = "ext-main".to_string();
        ext.requires = vec![dep_flagged("python(abi)", 8, Some("3.13"))];
        ext.prereq = vec![];
        ext.recommends = vec![];
        ext.suggests = vec![];
        ext.doc_files = vec![];
        ext.files = vec![];
        let (results, _levels) = run_files_check_pkgs(&[lang, ext], &config);
        let lines = nodep_lines(&results);
        assert_eq!(lines.len(), 1, "got: {lines:?}");
        assert!(lines[0].starts_with("foo-lang.noarch"), "got: {}", lines[0]);
    }

    #[test]
    fn normal_python_dep_anchor_chain_does_not_credit() {
        // One hop only: the mid package is itself anchored on the
        // main package, but that does not make the mid package carry
        // the dependency for the subpackage anchored on the mid.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let lang = dep_test_pkg(
            &dir,
            "foo-lang",
            vec![dep_flagged("foo-mid", 8, Some("1.0"))],
            Some(("/usr/lib/python3.13/site-packages/foo.py", b"x = 1\n")),
        );
        let mid = dep_test_pkg(
            &dir,
            "foo-mid",
            vec![dep_flagged("foo", 8, Some("1.0"))],
            None,
        );
        let main = dep_test_pkg(
            &dir,
            "foo",
            vec![dep_flagged("python(abi)", 8, Some("3.13"))],
            None,
        );
        let (results, _levels) = run_files_check_pkgs(&[lang, mid, main], &config);
        let lines = nodep_lines(&results);
        assert_eq!(lines.len(), 1, "got: {lines:?}");
        assert!(lines[0].starts_with("foo-lang.noarch"), "got: {}", lines[0]);
    }

    #[test]
    fn normal_python_dep_anchor_wrong_version_fires() {
        // The sibling must carry the base dependency for the version
        // the candidate's files name, not any version.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let lang = dep_test_pkg(
            &dir,
            "foo-lang",
            vec![dep_flagged("foo", 8, Some("1.0"))],
            Some(("/usr/lib/python3.13/site-packages/foo.py", b"x = 1\n")),
        );
        let main = dep_test_pkg(
            &dir,
            "foo",
            vec![dep_flagged("python(abi)", 8, Some("3.14"))],
            None,
        );
        let (results, _levels) = run_files_check_pkgs(&[lang, main], &config);
        let lines = nodep_lines(&results);
        assert_eq!(lines.len(), 1, "got: {lines:?}");
        assert!(lines[0].starts_with("foo-lang.noarch"), "got: {}", lines[0]);
    }

    #[test]
    fn normal_perl_dep_anchor_sibling_carries_compat() {
        // Issue #862: the devel subpackage anchored on a main package
        // carrying the MODULE_COMPAT token stays quiet (perl-Tk-devel
        // in the corpus).
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sub = dep_test_pkg(
            &dir,
            "perl-foo-devel",
            vec![dep_flagged("perl-foo", 8, Some("1.0"))],
            Some((
                "/usr/lib/perl5/vendor_perl/5.44.0/Foo/Bar.pm",
                b"package Foo::Bar;\n1;\n",
            )),
        );
        let main = dep_test_pkg(
            &dir,
            "perl-foo",
            vec![dep_named("perl(:MODULE_COMPAT_5.44.0)")],
            None,
        );
        let (results, _levels) = run_files_check_pkgs(&[sub, main], &config);
        assert!(
            nodep_lines(&results).is_empty(),
            "got: {:?}",
            nodep_lines(&results)
        );
    }

    #[test]
    fn normal_perl_dep_anchor_sibling_carries_via_interpreter_path() {
        // The sibling's own credit may come from the file/soname
        // forms: collectd-spamassassin anchors on collectd, whose
        // perl dependency is the /usr/bin/perl path plus the libperl
        // soname.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sub = dep_test_pkg(
            &dir,
            "foo-spam",
            vec![dep_flagged("foo", 8, Some("1.0"))],
            Some((
                "/usr/lib/perl5/vendor_perl/5.44.0/Foo/Bar.pm",
                b"package Foo::Bar;\n1;\n",
            )),
        );
        let main = dep_test_pkg(
            &dir,
            "foo",
            vec![
                dep_flagged("/usr/bin/perl", 16384, None),
                dep_flagged("libperl.so()(64bit)", 16384, None),
            ],
            None,
        );
        let (results, _levels) = run_files_check_pkgs(&[sub, main], &config);
        assert!(
            nodep_lines(&results).is_empty(),
            "got: {:?}",
            nodep_lines(&results)
        );
    }

    #[test]
    fn normal_not_utf8_compressed_doc_flagged() {
        // .zip has no decompressor so raw non-UTF8 bytes fail; NUL keeps the text path silent.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.name = "foo".to_string();
        let fname = "/usr/share/doc/foo/README.zip";
        let path = dir.path().join(fname.trim_start_matches('/'));
        std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
        std::fs::write(&path, b"\xff\xfe\x00\xff\xfe not utf8\n").expect("write temp file");
        pkg.files = vec![PkgFile {
            name: fname.to_string(),
            path: path.to_string_lossy().into_owned(),
            mode: 0o100644,
            magic: "data".to_string(),
            ..Default::default()
        }];
        pkg.doc_files = vec![fname.to_string()];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "file-not-utf8");
    }

    #[test]
    fn bidi_control_character_detected_and_named() {
        // Trojan-source shape: U+202E flips the rendered order of what follows.
        let evil = "if admin /* \u{202E} */ { return true; }\n";
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = bidi_pkg(
            &dir,
            vec![("/evil.c", "ASCII text", evil.as_bytes().to_vec())],
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        FilesCheck::new(&config).check_bidi_controls(&pkg, &mut out);
        let findings = bidi_findings(&out);
        assert_eq!(findings.len(), 1, "one finding: {findings:?}");
        assert_eq!(findings[0].0, Level::Warning, "warning, not error");
        assert!(
            findings[0].1.contains("U+202E"),
            "names the control: {}",
            findings[0].1
        );
        assert!(findings[0].1.contains("/evil.c"), "names the file");
    }

    #[test]
    fn bidi_clean_text_file_stays_silent() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = bidi_pkg(
            &dir,
            vec![(
                "/clean.c",
                "ASCII text",
                b"int main(void) { return 0; }\n".to_vec(),
            )],
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        FilesCheck::new(&config).check_bidi_controls(&pkg, &mut out);
        assert!(bidi_findings(&out).is_empty(), "no findings");
    }

    #[test]
    fn bidi_binary_file_not_scanned() {
        // Byte-identical payload, but libmagic says ELF: out of scope for a
        // text-file check, even though the bytes are present.
        let mut content = b"\x7fELF".to_vec();
        content.extend_from_slice("/* \u{202E} */".as_bytes());
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = bidi_pkg(&dir, vec![("/a.out", "ELF 64-bit LSB executable", content)]);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        FilesCheck::new(&config).check_bidi_controls(&pkg, &mut out);
        assert!(bidi_findings(&out).is_empty(), "binaries out of scope");
    }

    #[test]
    fn bidi_texture_payload_not_scanned() {
        // Issue #533: libmagic calls KTX payloads "Khronos KTX texture" --
        // "texture" contains "text" but the file is compressed binary, so
        // the gate stays shut even though the payload holds a control.
        let mut content = b"KTX".to_vec();
        content.extend_from_slice("/* \u{202E} */".as_bytes());
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = bidi_pkg(
            &dir,
            vec![(
                "/waffles.ktx",
                "Khronos KTX texture (little-endian), 160 x 106, COMPRESSED_RGBA_ASTC_10x5",
                content,
            )],
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        FilesCheck::new(&config).check_bidi_controls(&pkg, &mut out);
        assert!(
            bidi_findings(&out).is_empty(),
            "binary texture payloads out of scope"
        );
    }

    #[test]
    fn bidi_unicode_text_description_still_scanned() {
        // The whole-word gate keeps real text in scope: in "UTF-8 Unicode
        // text" the word `text` stands alone, so a control still fires.
        let evil = "name = \"a\u{202A}b\";\n";
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = bidi_pkg(
            &dir,
            vec![("/names.txt", "UTF-8 Unicode text", evil.as_bytes().to_vec())],
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        FilesCheck::new(&config).check_bidi_controls(&pkg, &mut out);
        let findings = bidi_findings(&out);
        assert_eq!(findings.len(), 1, "one finding: {findings:?}");
    }

    #[test]
    fn bidi_control_split_across_window_boundary_found() {
        // U+202E is E2 80 AE: place E2 80 at the very end of the first
        // 8192-byte window and AE at the start of the next.
        let mut content = vec![b'x'; 8192 - 2];
        content.extend_from_slice(&[0xE2, 0x80, 0xAE]);
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = bidi_pkg(&dir, vec![("/boundary.txt", "ASCII text", content)]);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        FilesCheck::new(&config).check_bidi_controls(&pkg, &mut out);
        let findings = bidi_findings(&out);
        assert_eq!(
            findings.len(),
            1,
            "boundary split still found: {findings:?}"
        );
    }

    #[test]
    fn bidi_all_nine_controls_recognized() {
        for (seq, name) in BIDI_CONTROLS {
            assert_eq!(
                first_bidi_control(&seq),
                Some(name),
                "{} not recognized",
                name
            );
        }
        assert_eq!(first_bidi_control(b"plain ascii"), None);
        // Trailing partial sequence is not a match.
        assert_eq!(first_bidi_control(&[0xE2, 0x80]), None);
    }

    #[test]
    fn bidi_source_package_scanned_through_check_dispatch() {
        // The trojan-source attack lives in source files: the scan must run
        // for source packages through the real `Check::check` dispatch, not
        // just when `check_bidi_controls` is called directly.
        let evil = "if admin /* \u{202E} */ { return true; }\n";
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = bidi_pkg(
            &dir,
            vec![("/evil.c", "ASCII text", evil.as_bytes().to_vec())],
        );
        pkg.is_source = true;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let findings = bidi_findings(&out);
        assert_eq!(findings.len(), 1, "source pkg: one finding: {findings:?}");
        assert_eq!(findings[0].0, Level::Warning, "warning, not error");
        assert!(findings[0].1.contains("U+202E"), "names the control");
        assert!(findings[0].1.contains("/evil.c"), "names the file");
        assert!(
            out.get_description("bidi-control-character", &config)
                .contains("trojan-source"),
            "the --explain detail must be registered"
        );
    }

    #[test]
    fn bidi_control_found_amid_non_utf8_surroundings() {
        // 0xE9 alone is not valid UTF-8 (Latin-1 e-acute) and 0xFF is not
        // valid anywhere; the U+202E triple is still found between them.
        let mut content = b"prefix-\xe9 /* ".to_vec();
        content.extend_from_slice(&[0xE2, 0x80, 0xAE]);
        content.extend_from_slice(b" */ \xff\n");
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = bidi_pkg(&dir, vec![("/latin1.c", "ASCII text", content)]);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        FilesCheck::new(&config).check_bidi_controls(&pkg, &mut out);
        let findings = bidi_findings(&out);
        assert_eq!(
            findings.len(),
            1,
            "control amid non-UTF-8 surroundings: {findings:?}"
        );
        assert!(findings[0].1.contains("U+202E"), "names the control");
    }

    #[test]
    fn fsf_address_scanned_past_2048_bytes() {
        // Upstream rpmlint#40: the reference scans only its 2048-byte peek
        // chunk for the FSF address, missing it in longer files. The port
        // scans the whole file instead.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let pkg = Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let fsf: Vec<&str> = out
            .results()
            .iter()
            .filter(|(name, _)| name == "incorrect-fsf-address")
            .map(|(_, line)| line.as_str())
            .collect();
        // LICENSE-early carries the wrong address at byte 385 (inside the
        // old 2048-byte window); LICENSE-late carries it at byte 3372
        // (past it); LICENSE-ok mentions the GPL with no street address
        // and must stay silent.
        assert_eq!(
            fsf,
            [
                "fsf-address-fixture.noarch: W: incorrect-fsf-address /usr/share/doc/packages/fsf-address-fixture/LICENSE-early",
                "fsf-address-fixture.noarch: W: incorrect-fsf-address /usr/share/doc/packages/fsf-address-fixture/LICENSE-late",
            ],
        );
    }

    #[test]
    fn fsf_address_match_survives_window_boundary() {
        // The whole-file FSF scan streams in FSF_SCAN_WINDOW-byte windows with
        // FSF_SCAN_OVERLAP bytes of overlap: a wrong-address match straddling
        // a window boundary must still be found whole inside one window.
        // Without the overlap this fails (neither window sees "Place" whole).
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let pkg = Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = FilesCheck::new(&config);

        // "59 Temple Place" starts 4 bytes before the first window ends, so
        // the address match spans the 8192-byte boundary.
        let mut content = vec![b'x'; FSF_SCAN_WINDOW - 4];
        content.extend_from_slice(b"59 Temple Place, Suite 330, Boston, MA 02111-1307 USA");
        content.extend_from_slice(b"\nGNU General Public License\n");
        let path = dir.path().join("boundary.txt");
        std::fs::write(&path, &content).expect("write temp file");
        let pkgfile = PkgFile {
            path: path.to_string_lossy().into_owned(),
            ..Default::default()
        };
        assert!(check.fsf_address_matches(&pkg, &pkgfile, &mut out));

        // Sanity: the license phrase alone, with no street address, stays
        // silent.
        let ok_path = dir.path().join("ok.txt");
        std::fs::write(
            &ok_path,
            b"GNU General Public License\nno street address here\n",
        )
        .expect("write temp file");
        let ok_file = PkgFile {
            path: ok_path.to_string_lossy().into_owned(),
            ..Default::default()
        };
        assert!(!check.fsf_address_matches(&pkg, &ok_file, &mut out));
    }

    #[test]
    fn fsf_zip_must_be_a_standalone_token() {
        // The 02139 alternative of the wrong-address pattern counts
        // only as a standalone token: embedded in a longer number, a
        // decimal fraction or a hex string, the digit string is data
        // (token-table indices, IEEE OUI entries, test-vector
        // signatures, SVG coordinates), not the FSF's old ZIP.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let pkg = Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = FilesCheck::new(&config);
        let licence = b"GNU General Public License\n";
        let mut run = |name: &str, body: &[u8]| {
            let path = dir.path().join(name);
            std::fs::write(&path, body).expect("write temp file");
            let pkgfile = PkgFile {
                path: path.to_string_lossy().into_owned(),
                ..Default::default()
            };
            check.fsf_address_matches(&pkg, &pkgfile, &mut out)
        };
        let with_licence = |tail: &[u8]| {
            let mut v = licence.to_vec();
            v.extend_from_slice(tail);
            v
        };
        // Standalone forms fire: the spelled-out street name is not a
        // street alternative, so the ZIP alone carries these.
        assert!(run(
            "zip.txt",
            &with_licence(b"675 Massachusetts Ave, Cambridge, MA 02139, USA\n"),
        ));
        assert!(run(
            "zip4.txt",
            &with_licence(b"Cambridge, MA 02139-1234\n")
        ));
        // ZIP at the very start of the file, and at EOF with no
        // trailing byte.
        let mut start = b"02139\n".to_vec();
        start.extend_from_slice(licence);
        assert!(run("zip-start.txt", &start));
        assert!(run("zip-eof.txt", &with_licence(b"Cambridge, MA 02139"),));
        // Embedded forms stay silent.
        assert!(!run(
            "oui.txt",
            &with_licence(b"002139\tEscherlogic Inc.\n")
        ));
        assert!(!run("token.txt", &with_licence(b"\"lacak\": 102139,\n")));
        assert!(!run(
            "float.txt",
            &with_licence(b"matrix(0.2073796,7.0213973)\n")
        ));
        assert!(!run("decimal.txt", &with_licence(b"score 0.02139\n")));
        assert!(!run("hexstr.txt", &with_licence(b"sig 9abc02139def0\n")));
        assert!(!run("suffix.txt", &with_licence(b"\"02139abc\"\n")));
        // Window boundaries: a standalone ZIP straddling the first
        // window edge still fires (its right neighbour arrives with
        // the next window); an embedded one straddling it stays
        // silent.
        let mut strad = licence.to_vec();
        strad.resize(FSF_SCAN_WINDOW - 2, b'x');
        strad.extend_from_slice(b" 02139, USA\n");
        assert!(run("zip-straddle.txt", &strad));
        let mut estrad = licence.to_vec();
        estrad.resize(FSF_SCAN_WINDOW - 3, b'x');
        estrad.extend_from_slice(b"102139, token index\n");
        assert!(!run("zip-embedded-straddle.txt", &estrad));
        // A standalone ZIP ending exactly at EOF after a full window
        // fires through the end-of-file adjudication.
        let mut eof = licence.to_vec();
        eof.resize(FSF_SCAN_WINDOW, b'x');
        eof.extend_from_slice(b" 02139");
        assert!(run("zip-eof-window.txt", &eof));
    }

    #[test]
    fn files_check_infopage_not_compressed() {
        // Uncompressed info page must warn via the per-file dispatch.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.files = vec![PkgFile {
            name: "/usr/share/info/foo.info".to_string(),
            path: "/usr/share/info/foo.info".to_string(),
            user: "root".to_string(),
            group: "root".to_string(),
            ..Default::default()
        }];
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "infopage-not-compressed");
    }

    #[test]
    fn files_check_non_standard_uid() {
        // Owner outside StandardUsers and declared nowhere must error
        // via the session decision (issue #756). A root-owned sibling
        // file in the same package stays quiet, so the tag fires once.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.files = vec![
            PkgFile {
                name: "/usr/share/fcprobe/data.dat".to_string(),
                path: "/usr/share/fcprobe/data.dat".to_string(),
                user: "nosuchuser".to_string(),
                group: "root".to_string(),
                ..Default::default()
            },
            PkgFile {
                name: "/usr/share/fcprobe/other.dat".to_string(),
                path: "/usr/share/fcprobe/other.dat".to_string(),
                user: "root".to_string(),
                group: "root".to_string(),
                ..Default::default()
            },
        ];
        let config = test_config();
        let (results, levels) = run_files_check_pkgs(&[pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_eq!(
            names
                .iter()
                .filter(|n| n.as_str() == "non-standard-uid")
                .count(),
            1
        );
        assert_eq!(
            level_of(&results, &levels, "non-standard-uid"),
            Some(Level::Error)
        );
    }

    #[test]
    fn files_check_non_standard_gid() {
        // Group outside StandardGroups and declared nowhere must error
        // via the session decision (issue #756).
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.files = vec![PkgFile {
            name: "/usr/share/fcprobe/data.dat".to_string(),
            path: "/usr/share/fcprobe/data.dat".to_string(),
            user: "root".to_string(),
            group: "nosuchgroup".to_string(),
            ..Default::default()
        }];
        let config = test_config();
        let (results, levels) = run_files_check_pkgs(&[pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "non-standard-gid");
        assert_eq!(
            level_of(&results, &levels, "non-standard-gid"),
            Some(Level::Error)
        );
    }

    /// Open one uidgid-session fixture RPM with extraction, keeping the
    /// extraction dir alive in the returned TempDir.
    fn uidgid_fixture(name: &str) -> (Pkg, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = fixture_path(name);
        let pkg = Pkg::open(Path::new(&rpm), dir.path(), true).expect("open fixture");
        (pkg, dir)
    }

    /// Clear a fixture package's dependency headers, so a test of
    /// one crediting route cannot be satisfied through another
    /// route's data riding on the same fixture (issue #766): rpm's
    /// sysusers generator emits `user()` / `group()` Provides for a
    /// package shipping a snippet, and a regenerated fixture would
    /// otherwise credit through the Provides route while the test
    /// names the snippet route.
    fn clear_dep_headers(pkg: &mut Pkg) {
        pkg.provides.clear();
        pkg.requires.clear();
        pkg.prereq.clear();
    }

    #[test]
    fn non_standard_uid_quiet_when_sibling_ships_sysusers_snippet() {
        // The uidgid-session-sysusers subpackage ships the snippet
        // declaring svcfoo; a file in the main subpackage owned by
        // svcfoo stays quiet when both are linted in one run (issue
        // #756, declaration route (a)). The candidate is recorded
        // before the declaring package is seen: the decision is
        // order-independent.
        let (mut main_pkg, _d1) = uidgid_fixture("uidgid-session-main-1.0-1.noarch.rpm");
        main_pkg.files.push(PkgFile {
            name: "/var/lib/svcfoo/state".to_string(),
            path: "/var/lib/svcfoo/state".to_string(),
            user: "svcfoo".to_string(),
            group: "root".to_string(),
            ..Default::default()
        });
        let (mut sysusers_pkg, _d2) = uidgid_fixture("uidgid-session-sysusers-1.0-1.noarch.rpm");
        // Route isolation (issue #766): clear both packages'
        // dependency headers, so the verdict pins the sysusers
        // snippet route only -- rpm's sysusers generator emits
        // `user()` / `group()` Provides for a package shipping a
        // snippet, which a regenerated fixture would otherwise
        // credit through the Provides route.
        clear_dep_headers(&mut main_pkg);
        clear_dep_headers(&mut sysusers_pkg);
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[main_pkg, sysusers_pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "non-standard-uid");
    }

    #[test]
    fn non_standard_gid_quiet_for_u_line_primary_group() {
        // The snippet's `u svcfoo` line declares svcfoo's like-named
        // primary group too, so a file owned by group svcfoo stays
        // quiet (issue #756; the 389-ds shape).
        let (mut main_pkg, _d1) = uidgid_fixture("uidgid-session-main-1.0-1.noarch.rpm");
        main_pkg.files.push(PkgFile {
            name: "/var/lib/svcfoo/state".to_string(),
            path: "/var/lib/svcfoo/state".to_string(),
            user: "root".to_string(),
            group: "svcfoo".to_string(),
            ..Default::default()
        });
        let (mut sysusers_pkg, _d2) = uidgid_fixture("uidgid-session-sysusers-1.0-1.noarch.rpm");
        // Route isolation (issue #766): clear both packages'
        // dependency headers, so the verdict pins the sysusers
        // snippet route only -- rpm's sysusers generator emits
        // `user()` / `group()` Provides for a package shipping a
        // snippet, which a regenerated fixture would otherwise
        // credit through the Provides route.
        clear_dep_headers(&mut main_pkg);
        clear_dep_headers(&mut sysusers_pkg);
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[main_pkg, sysusers_pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "non-standard-gid");
    }

    #[test]
    fn non_standard_uid_fires_for_group_only_name() {
        // Near-miss: the snippet declares svcbar with a `g` line only,
        // so svcbar is a declared group but not a declared user; a file
        // owned by user svcbar still fires (issue #756).
        let (mut main_pkg, _d1) = uidgid_fixture("uidgid-session-main-1.0-1.noarch.rpm");
        main_pkg.files.push(PkgFile {
            name: "/var/lib/svcbar/state".to_string(),
            path: "/var/lib/svcbar/state".to_string(),
            user: "svcbar".to_string(),
            group: "root".to_string(),
            ..Default::default()
        });
        let (mut sysusers_pkg, _d2) = uidgid_fixture("uidgid-session-sysusers-1.0-1.noarch.rpm");
        // Route isolation (issue #766): clear both packages'
        // dependency headers, so the verdict pins the sysusers
        // snippet route only -- rpm's sysusers generator emits
        // `user()` / `group()` Provides for a package shipping a
        // snippet, which a regenerated fixture would otherwise
        // credit through the Provides route.
        clear_dep_headers(&mut main_pkg);
        clear_dep_headers(&mut sysusers_pkg);
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[main_pkg, sysusers_pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "non-standard-uid");
    }

    #[test]
    fn non_standard_uid_fires_when_snippet_declares_another_name() {
        // Near-miss: the sibling snippet declares svcfoo/svcbar, not
        // the file's owner svcother (issue #756).
        let (mut main_pkg, _d1) = uidgid_fixture("uidgid-session-main-1.0-1.noarch.rpm");
        main_pkg.files.push(PkgFile {
            name: "/var/lib/svcother/state".to_string(),
            path: "/var/lib/svcother/state".to_string(),
            user: "svcother".to_string(),
            group: "root".to_string(),
            ..Default::default()
        });
        let (mut sysusers_pkg, _d2) = uidgid_fixture("uidgid-session-sysusers-1.0-1.noarch.rpm");
        // Route isolation (issue #766): clear both packages'
        // dependency headers, so the verdict pins the sysusers
        // snippet route only -- rpm's sysusers generator emits
        // `user()` / `group()` Provides for a package shipping a
        // snippet, which a regenerated fixture would otherwise
        // credit through the Provides route.
        clear_dep_headers(&mut main_pkg);
        clear_dep_headers(&mut sysusers_pkg);
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[main_pkg, sysusers_pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "non-standard-uid");
    }

    #[test]
    fn non_standard_quiet_with_provides_only_package() {
        // Declaration route (b): explicit user()/group() Provides on a
        // package that ships no snippet (the legacy class).
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.provides = vec![
            DepInfo {
                name: "user(svcfoo)".to_string(),
                flags: 0,
                epoch: None,
                version: None,
                release: None,
            },
            DepInfo {
                name: "group(svcbar)".to_string(),
                flags: 0,
                epoch: None,
                version: None,
                release: None,
            },
        ];
        pkg.requires = vec![];
        pkg.files = vec![PkgFile {
            name: "/var/lib/svcfoo/state".to_string(),
            path: "/var/lib/svcfoo/state".to_string(),
            user: "svcfoo".to_string(),
            group: "svcbar".to_string(),
            ..Default::default()
        }];
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "non-standard-uid");
        assert_lacks(&names, "non-standard-gid");
    }

    #[test]
    fn non_standard_quiet_with_requires_capability() {
        // Declaration route (c): the file-owning package Requires the
        // user()/group() capabilities a provider package declares.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.provides = vec![];
        pkg.requires = vec![
            DepInfo {
                name: "user(svcfoo)".to_string(),
                flags: 0,
                epoch: None,
                version: None,
                release: None,
            },
            DepInfo {
                name: "group(svcbar)".to_string(),
                flags: 0,
                epoch: None,
                version: None,
                release: None,
            },
        ];
        pkg.files = vec![PkgFile {
            name: "/var/lib/svcfoo/state".to_string(),
            path: "/var/lib/svcfoo/state".to_string(),
            user: "svcfoo".to_string(),
            group: "svcbar".to_string(),
            ..Default::default()
        }];
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "non-standard-uid");
        assert_lacks(&names, "non-standard-gid");
    }

    #[test]
    fn non_standard_fires_when_provides_name_another_account() {
        // Near-miss for route (b): the Provides name a different
        // account than the file's owner.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.provides = vec![DepInfo {
            name: "user(svcfoo)".to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        }];
        pkg.requires = vec![];
        pkg.files = vec![PkgFile {
            name: "/var/lib/svcother/state".to_string(),
            path: "/var/lib/svcother/state".to_string(),
            user: "svcother".to_string(),
            group: "root".to_string(),
            ..Default::default()
        }];
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "non-standard-uid");
    }

    #[test]
    fn non_standard_declaration_does_not_leak_across_sources() {
        // The uidgid-session declaration credits only packages built
        // from that source: an unrelated package's svcfoo-owned file
        // in the same run still fires (issue #756).
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut lone = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        lone.files = vec![PkgFile {
            name: "/var/lib/svcfoo/state".to_string(),
            path: "/var/lib/svcfoo/state".to_string(),
            user: "svcfoo".to_string(),
            group: "root".to_string(),
            ..Default::default()
        }];
        let (mut sysusers_pkg, _d2) = uidgid_fixture("uidgid-session-sysusers-1.0-1.noarch.rpm");
        // Route isolation (issue #766): the verdict must pin the
        // snippet route, not either package's dependency headers.
        clear_dep_headers(&mut lone);
        clear_dep_headers(&mut sysusers_pkg);
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[lone, sysusers_pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "non-standard-uid");
    }

    #[test]
    fn non_standard_realdhdr_uncredited_fires() {
        // End-to-end through a real header (issue #827): the fixture's
        // payload files are owned by hdruser/hdrgroup in the header
        // itself, and the only account Requires the header carries
        // are the ones rpm's generator derived from that ownership,
        // which the header loader drops. Both findings fire at E.
        let (pkg, _d) = uidgid_fixture("uidgid-realhdr-main-1.0-1.noarch.rpm");
        assert!(
            pkg.prereq
                .iter()
                .all(|d| !d.name.starts_with("user(") && !d.name.starts_with("group(")),
            "generator stamps must not reach prereq: {:?}",
            pkg.prereq.iter().map(|d| &d.name).collect::<Vec<_>>()
        );
        let config = test_config();
        let (results, levels) = run_files_check_pkgs(&[pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "non-standard-uid");
        assert_has(&names, "non-standard-gid");
        assert_eq!(
            level_of(&results, &levels, "non-standard-uid"),
            Some(Level::Error)
        );
        assert_eq!(
            level_of(&results, &levels, "non-standard-gid"),
            Some(Level::Error)
        );
    }

    #[test]
    fn non_standard_realdhdr_handwritten_prereq_quiet() {
        // The gromox shape in a real header (issue #827): the same
        // generator stamps, plus packager-written Requires(pre)
        // capabilities for both accounts. The packager-written entries
        // survive the header loader and credit both accounts.
        let (pkg, _d) = uidgid_fixture("uidgid-realhdr-handwritten-1.0-1.noarch.rpm");
        assert!(
            pkg.prereq.iter().any(|d| d.name == "user(hdruser)"),
            "packager-written Requires(pre) must reach prereq: {:?}",
            pkg.prereq.iter().map(|d| &d.name).collect::<Vec<_>>()
        );
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "non-standard-uid");
        assert_lacks(&names, "non-standard-gid");
    }

    #[test]
    fn non_standard_realdhdr_snippet_control_quiet() {
        // Real-header control (issue #827): the package ships a
        // sysusers.d snippet declaring both owners, so both findings
        // stay quiet even though its header carries the same
        // generator stamps as the uncredited fixture.
        let (pkg, _d) = uidgid_fixture("uidgid-realhdr-control-1.0-1.noarch.rpm");
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "non-standard-uid");
        assert_lacks(&names, "non-standard-gid");
    }

    #[test]
    fn non_standard_realdhdr_declaration_does_not_leak_across_sources() {
        // The control's snippet belongs to a different source: linted
        // in one run, the uncredited fixture still fires both
        // findings (issue #827, on the session grouping of issue
        // #756).
        let (main_pkg, _d1) = uidgid_fixture("uidgid-realhdr-main-1.0-1.noarch.rpm");
        let (control_pkg, _d2) = uidgid_fixture("uidgid-realhdr-control-1.0-1.noarch.rpm");
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[main_pkg, control_pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "non-standard-uid");
        assert_has(&names, "non-standard-gid");
    }

    #[test]
    fn non_standard_quiet_with_prereq_capability() {
        // Declaration route (c) in its real-world form: the account
        // capabilities sit in the scriptlet-context Requires split
        // (`Requires(pre): user(<name>)`), which the header loader
        // stores in `prereq` (the grommunio-web / gromox corpus shape).
        // Entries injected here model the packager-written form: the
        // loader drops rpm's generator stamps before `prereq` is
        // populated, so a stored entry is a declaration by
        // construction (issue #827; the real-header pins are the
        // `non_standard_realdhdr_*` tests).
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.provides = vec![];
        pkg.requires = vec![];
        pkg.prereq = vec![
            DepInfo {
                name: "user(svcfoo)".to_string(),
                flags: 0,
                epoch: None,
                version: None,
                release: None,
            },
            DepInfo {
                name: "group(svcbar)".to_string(),
                flags: 0,
                epoch: None,
                version: None,
                release: None,
            },
        ];
        pkg.files = vec![PkgFile {
            name: "/var/lib/svcfoo/state".to_string(),
            path: "/var/lib/svcfoo/state".to_string(),
            user: "svcfoo".to_string(),
            group: "svcbar".to_string(),
            ..Default::default()
        }];
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "non-standard-uid");
        assert_lacks(&names, "non-standard-gid");
    }

    #[test]
    fn non_standard_fires_when_only_sibling_requires_capability() {
        // Negative for the Requires route's scope: crediting is
        // per-package, not set-wide. The sibling subpackage (same
        // SOURCERPM) Requires user(svcfoo) in plain form and
        // group(svcbar) in prereq form, but the file-owning package
        // Requires nothing, so a standalone install of the owning
        // package has no creator for either account and both findings
        // fire at E (issue #756).
        let (mut owner, _d1) = uidgid_fixture("uidgid-session-main-1.0-1.noarch.rpm");
        owner.provides = vec![];
        owner.requires = vec![];
        owner.prereq = vec![];
        owner.files.push(PkgFile {
            name: "/var/lib/svcfoo/state".to_string(),
            path: "/var/lib/svcfoo/state".to_string(),
            user: "svcfoo".to_string(),
            group: "svcbar".to_string(),
            ..Default::default()
        });
        let (mut sibling, _d2) = uidgid_fixture("uidgid-session-sysusers-1.0-1.noarch.rpm");
        // Strip the sibling's shipped files so its sysusers snippet
        // cannot credit the accounts, and clear its Provides: the only
        // declarations left in the run are the sibling's Requires.
        sibling.files = vec![];
        sibling.provides = vec![];
        sibling.requires = vec![DepInfo {
            name: "user(svcfoo)".to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        }];
        sibling.prereq = vec![DepInfo {
            name: "group(svcbar)".to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        }];
        let config = test_config();
        let (results, levels) = run_files_check_pkgs(&[owner, sibling], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "non-standard-uid");
        assert_has(&names, "non-standard-gid");
        assert_eq!(
            level_of(&results, &levels, "non-standard-uid"),
            Some(Level::Error)
        );
        assert_eq!(
            level_of(&results, &levels, "non-standard-gid"),
            Some(Level::Error)
        );
    }

    #[test]
    fn rich_wrapped_requires_capability_credits() {
        // Issue #766: inside a rich expression the dependency
        // grammar splits a `user(svcfoo)` spelling into name `user`
        // plus qualifier `svcfoo` (see `DepInfo::leaves`); the leaf
        // matcher must credit the capability through the qualifier
        // too, or the owning package's files fire a spurious error.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.provides = vec![];
        pkg.prereq = vec![];
        pkg.requires = vec![
            DepInfo {
                name: "(user(svcfoo) or bash)".to_string(),
                flags: 0,
                epoch: None,
                version: None,
                release: None,
            },
            DepInfo {
                name: "(group(svcfoo) and bash)".to_string(),
                flags: 0,
                epoch: None,
                version: None,
                release: None,
            },
        ];
        pkg.files = vec![PkgFile {
            name: "/var/lib/svcfoo/state".to_string(),
            path: "/var/lib/svcfoo/state".to_string(),
            user: "svcfoo".to_string(),
            group: "svcfoo".to_string(),
            ..Default::default()
        }];
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "non-standard-uid");
        assert_lacks(&names, "non-standard-gid");

        // A rich capability naming a different account credits
        // nothing: the owner still fires.
        let mut pkg2 = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg2.provides = vec![];
        pkg2.prereq = vec![];
        pkg2.requires = vec![DepInfo {
            name: "(user(other) or bash)".to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        }];
        pkg2.files = vec![PkgFile {
            name: "/var/lib/svcfoo/state".to_string(),
            path: "/var/lib/svcfoo/state".to_string(),
            user: "svcfoo".to_string(),
            group: "root".to_string(),
            ..Default::default()
        }];
        let (results, _levels) = run_files_check_pkgs(&[pkg2], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "non-standard-uid");
    }

    #[test]
    fn rich_wrapped_provides_capability_credits() {
        // Issue #766: the same split leaf feeds the Provides route --
        // a rich-wrapped `user(svcfoo)` Provides on the declaring
        // package quiets the uid finding while the group, declared
        // nowhere, still fires.
        let (mut main_pkg, _d1) = uidgid_fixture("uidgid-session-main-1.0-1.noarch.rpm");
        main_pkg.files.push(PkgFile {
            name: "/var/lib/svcfoo/state".to_string(),
            path: "/var/lib/svcfoo/state".to_string(),
            user: "svcfoo".to_string(),
            group: "svcfoo".to_string(),
            ..Default::default()
        });
        let (mut declaring_pkg, _d2) = uidgid_fixture("uidgid-session-sysusers-1.0-1.noarch.rpm");
        // Route isolation (issue #766): clear both packages'
        // dependency headers and strip the declaring package's
        // shipped files, so the sysusers snippet cannot credit and
        // no route but the rich Provides below can: the verdict
        // pins the Provides route only.
        clear_dep_headers(&mut main_pkg);
        clear_dep_headers(&mut declaring_pkg);
        declaring_pkg.files = vec![];
        declaring_pkg.provides = vec![DepInfo {
            name: "(user(svcfoo) or bash)".to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        }];
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[main_pkg, declaring_pkg], &config);
        let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "non-standard-uid");
        assert_has(&names, "non-standard-gid");
    }

    #[test]
    fn sysusers_declared_credits_u_and_g_lines() {
        let (users, groups) = sysusers_declared(
            "u svcfoo - \"svcfoo service user\" /var/lib/svcfoo -\ng svcbar - -\n",
        );
        assert!(users.contains("svcfoo"));
        // A `u` line declares its like-named primary group too.
        assert!(groups.contains("svcfoo"));
        assert!(groups.contains("svcbar"));
        assert!(!users.contains("svcbar"));
    }

    #[test]
    fn sysusers_declared_ignores_membership_ranges_and_ids() {
        // `m` lines are membership, `r` lines id ranges, `-` and
        // numeric name fields declare by id: none credits a name.
        let (users, groups) =
            sysusers_declared("# comment\n\nm svcfoo svcbar\nr 200..299\nu - 500:500\ng 123 - -\n");
        assert!(users.is_empty());
        assert!(groups.is_empty());
    }

    #[test]
    fn account_capability_reads_user_and_group_caps() {
        assert_eq!(account_capability("user(svcfoo)"), Some((false, "svcfoo")));
        assert_eq!(account_capability("group(svcbar)"), Some((true, "svcbar")));
        assert_eq!(account_capability("user()"), None);
        assert_eq!(account_capability("/bin/sh"), None);
    }

    #[test]
    fn account_capability_rejects_parenthesised_inner_names() {
        // A malformed spelling whose inner text carries a parenthesis
        // names no account: the stray-paren forms would otherwise read
        // as the accounts `foo)` / `a)b`.
        assert_eq!(account_capability("user(foo))"), None);
        assert_eq!(account_capability("group(foo))"), None);
        assert_eq!(account_capability("user(foo(bar))"), None);
        assert_eq!(account_capability("user(a)b)"), None);
    }

    #[test]
    fn sysusers_snippet_paths_match_conf_under_sysusers_d() {
        assert!(is_sysusers_snippet("/usr/lib/sysusers.d/foo.conf"));
        assert!(is_sysusers_snippet("/etc/sysusers.d/foo.conf"));
        assert!(!is_sysusers_snippet("/usr/lib/sysusers.d/foo.txt"));
        assert!(!is_sysusers_snippet("/usr/lib/tmpfiles.d/foo.conf"));
        assert!(!is_sysusers_snippet("/foo.conf"));
    }

    fn svgz_findings(pkg: &Pkg) -> Vec<String> {
        run_check_binary(pkg)
            .into_iter()
            .filter(|(n, _)| n == "gzipped-svg-icon")
            .map(|(_, line)| line)
            .collect()
    }

    fn scalable_icon_files(svgz: usize, svg: usize) -> Vec<PkgFile> {
        let mut files = Vec::new();
        for i in 0..svgz {
            files.push(mode_file(
                &format!("/usr/share/icons/hicolor/scalable/apps/icon{i}.svgz"),
                0o100644,
            ));
        }
        for i in 0..svg {
            files.push(mode_file(
                &format!("/usr/share/icons/hicolor/scalable/apps/plain{i}.svg"),
                0o100644,
            ));
        }
        files
    }

    #[test]
    fn gzipped_svg_icon_fires_for_a_single_app_icon() {
        let (pkg, _dir) = pkg_with_files(scalable_icon_files(1, 0));
        let hits = svgz_findings(&pkg);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(
            hits[0].contains("/usr/share/icons/hicolor/scalable/apps/icon0.svgz"),
            "the finding names the icon: {}",
            hits[0]
        );
    }

    #[test]
    fn gzipped_svg_icon_fires_per_untwinned_icon_in_a_mixed_package() {
        let mut files = scalable_icon_files(1, 0);
        files.push(mode_file(
            "/usr/share/icons/hicolor/scalable/apps/pair.svgz",
            0o100644,
        ));
        files.push(mode_file(
            "/usr/share/icons/hicolor/scalable/apps/pair.svg",
            0o100644,
        ));
        let (pkg, _dir) = pkg_with_files(files);
        let hits = svgz_findings(&pkg);
        assert_eq!(hits.len(), 1, "only the untwinned icon fires: {hits:?}");
        assert!(hits[0].contains("icon0.svgz"), "{hits:?}");
    }

    #[test]
    fn gzipped_svg_icon_silent_for_a_uniform_theme() {
        // 120 gzipped against 6 plain: theme scale, 95% gzipped.
        let (pkg, _dir) = pkg_with_files(scalable_icon_files(120, 6));
        assert!(svgz_findings(&pkg).is_empty());
    }

    #[test]
    fn gzipped_svg_icon_fires_below_theme_scale() {
        // Uniform but small: 99 gzipped icons are individually
        // placed icons, not a theme.
        let (pkg, _dir) = pkg_with_files(scalable_icon_files(99, 0));
        assert_eq!(svgz_findings(&pkg).len(), 99);
    }

    #[test]
    fn gzipped_svg_icon_fires_for_a_large_mixed_payload() {
        // Theme scale but only 89% gzipped: a mixed payload keeps
        // firing per icon.
        let (pkg, _dir) = pkg_with_files(scalable_icon_files(100, 12));
        assert_eq!(svgz_findings(&pkg).len(), 100);
    }

    #[test]
    fn gzipped_svg_icon_credits_at_the_share_boundary() {
        // 100 gzipped against 11 plain is a 90.09% share: credited.
        let (pkg, _dir) = pkg_with_files(scalable_icon_files(100, 11));
        assert!(svgz_findings(&pkg).is_empty());
    }

    #[test]
    fn gzipped_svg_icon_population_counts_regular_files_only() {
        // Symlinked .svgz names neither fire nor count toward the
        // theme population: 99 regular + 3 symlinks stays below
        // theme scale and every regular icon fires.
        let mut files = scalable_icon_files(99, 0);
        for i in 0..3 {
            files.push(mode_file(
                &format!("/usr/share/icons/hicolor/scalable/apps/link{i}.svgz"),
                0o120777,
            ));
        }
        let (pkg, _dir) = pkg_with_files(files);
        assert_eq!(svgz_findings(&pkg).len(), 99);
    }

    #[test]
    fn gzipped_svg_icon_ignores_non_scalable_dirs() {
        let mut files = Vec::new();
        for i in 0..120 {
            files.push(mode_file(
                &format!("/usr/share/icons/hicolor/48x48/apps/icon{i}.svgz"),
                0o100644,
            ));
        }
        // Control: one scalable icon alongside the non-scalable
        // population. It must be the only finding -- the 120
        // non-scalable icons neither fire nor build theme credit,
        // so the single scalable icon (below the theme threshold)
        // still fires on its own.
        files.push(mode_file(
            "/usr/share/icons/hicolor/scalable/apps/icon.svgz",
            0o100644,
        ));
        let (pkg, _dir) = pkg_with_files(files);
        let hits = svgz_findings(&pkg);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(
            hits[0].contains("/usr/share/icons/hicolor/scalable/apps/icon.svgz"),
            "the finding names the scalable icon: {}",
            hits[0]
        );
    }

    #[test]
    fn files_check_devel_non_devel_file() {
        let config = test_config();
        let (names, _dir) =
            run_files_check(&fixture_path("filescheck-devel-1.0-1.noarch.rpm"), &config);
        assert_has(&names, "non-devel-file-in-devel-package");
    }

    #[test]
    fn filename_with_unexpanded_macro_emits_finding() {
        // The shared macro_regex must match "%{unexpanded}" in a filename:
        // with the broken double-escaped form it matched a literal
        // backslash-w, so unexpanded-macro was never emitted from FilesCheck.
        // Restoring the broken regex makes this fail.
        let config = test_config();
        let (names, _dir) = run_files_check(
            &fixture_path("unexpandedmacro-test-1.0-1.noarch.rpm"),
            &config,
        );
        assert_has(&names, "unexpanded-macro");
    }

    #[test]
    fn files_check_depmod_findings_absent() {
        // The depmod findings were removed (SUSE-KMP-specific; the KMP macro
        // template handles depmod). Each fixture below fired its pair before
        // the removal -- restoring any of the four emissions makes this fail.
        let config = test_config();
        let (missing_names, _d1) = run_files_check(
            &fixture_path("filescheck-depmod-missing-1.0-1.noarch.rpm"),
            &config,
        );
        assert_lacks(&missing_names, "module-without-depmod-postin");
        assert_lacks(&missing_names, "module-without-depmod-postun");

        let (wrong_names, _d2) = run_files_check(
            &fixture_path("filescheck-depmod-wrong-1.0-1.noarch.rpm"),
            &config,
        );
        assert_lacks(&wrong_names, "postin-with-wrong-depmod");
        assert_lacks(&wrong_names, "postun-with-wrong-depmod");
    }

    #[test]
    fn files_check_deps_ok_no_missing_deps() {
        let config = test_config();
        let (names, _dir) = run_files_check(
            &fixture_path("filescheck-deps-ok-1.0-1.noarch.rpm"),
            &config,
        );
        assert_lacks(&names, "no-dependency-on");
    }

    #[test]
    fn files_check_read_error_on_missing_file() {
        // Mutating a PkgFile path to a nonexistent file makes peek fail,
        // emitting read-error.
        let config = test_config();
        let rpm = fixture_path("filescheck-scripts-1.0-1.noarch.rpm");
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open");
        // Point a symlink target at a missing path so peek fails with
        // read-error (check_link_bindir_shebang peeks the target).
        if let Some(f) = pkg
            .files
            .iter_mut()
            .find(|f| f.name == "/usr/share/filescheck-scripts/runme.sh")
        {
            f.path = "/nonexistent/missing".to_string();
        }
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "read-error");
    }

    #[test]
    fn files_check_symlink_absolute_with_config() {
        // With UseRelativeSymlinks=false, a relative symlink into another
        // toplevel dir emits symlink-should-be-absolute instead of
        // symlink-should-be-relative.
        let mut config = test_config();
        config.configuration.insert(
            "UseRelativeSymlinks".to_string(),
            toml::Value::Boolean(false),
        );
        let (names, _dir) = run_files_check(
            &fixture_path("filescheck-scripts-1.0-1.noarch.rpm"),
            &config,
        );
        assert_has(&names, "symlink-should-be-absolute");
        assert_lacks(&names, "symlink-should-be-relative");
    }

    #[test]
    fn dangling_relative_fires_for_lang_package_alone() {
        // Issue #547: the -lang subpackage's link target ships only in
        // its sibling; linted alone the session set is its own file
        // list, so the finding fires — per-package behaviour preserved.
        let config = test_config();
        let (results, _dirs) = run_files_check_session(
            &[&fixture_path("dangling-session-lang-1.0-1.noarch.rpm")],
            &config,
        );
        let lines: Vec<&str> = results
            .iter()
            .filter(|(n, _)| n == "dangling-relative-symlink")
            .map(|(_, line)| line.as_str())
            .collect();
        assert_eq!(lines.len(), 1, "got: {results:?}");
        assert!(
            lines[0].starts_with("dangling-session-lang.noarch"),
            "unexpected line: {}",
            lines[0]
        );
    }

    #[test]
    fn dangling_relative_suppressed_when_sibling_ships_target() {
        // Issue #547: dangling-session-main and dangling-session-lang
        // are built from one spec; the main package ships the figure
        // the lang package links to, so the pair stays quiet — in
        // either lint order. Deciding per package, as the reference
        // does, makes the lang package fire and this fail.
        let config = test_config();
        let main = fixture_path("dangling-session-main-1.0-1.noarch.rpm");
        let lang = fixture_path("dangling-session-lang-1.0-1.noarch.rpm");
        for rpms in [
            [lang.as_str(), main.as_str()],
            [main.as_str(), lang.as_str()],
        ] {
            let (results, _dirs) = run_files_check_session(&rpms, &config);
            let names: Vec<String> = results.iter().map(|(n, _)| n.clone()).collect();
            assert_lacks(&names, "dangling-relative-symlink");
        }
    }

    #[test]
    fn dangling_relative_unrelated_package_does_not_resolve() {
        // Issue #547: session awareness is target existence, not a
        // blanket suppression — a run whose other package does not
        // ship the target leaves the lang package's finding in place.
        let config = test_config();
        let (results, _dirs) = run_files_check_session(
            &[
                &fixture_path("dangling-session-lang-1.0-1.noarch.rpm"),
                &fixture_path("dangling-lone-1.0-1.noarch.rpm"),
            ],
            &config,
        );
        let lines: Vec<&str> = results
            .iter()
            .filter(|(n, _)| n == "dangling-relative-symlink")
            .map(|(_, line)| line.as_str())
            .collect();
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("dangling-session-lang.noarch")),
            "got: {results:?}"
        );
    }

    #[test]
    fn dangling_relative_fires_for_lone_dangling_package() {
        // Issue #547: dangling-lone's build-host-shaped link target
        // (the gfxboot shape) exists in no package, so it fires in a
        // session too; the intended in-package target shipping
        // alongside does not save it. The consolehelper-shaped link
        // fires plainly here: the default test config carries no
        // DanglingSymlinkExceptions.
        let config = test_config();
        let (results, _dirs) =
            run_files_check_session(&[&fixture_path("dangling-lone-1.0-1.noarch.rpm")], &config);
        let lines: Vec<&str> = results
            .iter()
            .filter(|(n, _)| n == "dangling-relative-symlink")
            .map(|(_, line)| line.as_str())
            .collect();
        assert!(
            lines.iter().any(|l| l.contains("links/logo.txt")),
            "got: {results:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("dangling-lone-helper")),
            "got: {results:?}"
        );
        // The mid-tree dir-link resolves: its target is a directory
        // entry the same package ships (%dir), and the lookup matches
        // header entries verbatim.
        assert!(
            !lines.iter().any(|l| l.contains("dir-link")),
            "got: {results:?}"
        );
        // Class F parity: the root-level link's normalised target
        // keeps POSIX's double leading slash (`//usr/...`), which
        // never equals a header entry, so it fires — the reference
        // emits the identical lines for filesystem's own root links.
        assert!(
            lines.iter().any(|l| l.contains("lone-root-link")),
            "got: {results:?}"
        );
    }

    fn symlink(name: &str, target: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            mode: 0o120777,
            linkto: target.to_string(),
            ..Default::default()
        }
    }

    /// Run FilesCheck over a synthetic package holding one regular
    /// script file under /usr/share/probe and one symlink to it, and
    /// return the `symlink-to-binary-with-shebang` findings.
    fn bindir_shebang_findings(
        target_content: &[u8],
        linkto: &str,
        requires: &[&str],
    ) -> (Vec<(String, String)>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        let root = pkg
            .extracted_dir()
            .expect("extracted fixture")
            .to_path_buf();
        let target_name = "/usr/share/probe/target.sh";
        let target_path = root.join(target_name.trim_start_matches('/'));
        std::fs::create_dir_all(target_path.parent().unwrap()).expect("mkdirs");
        std::fs::write(&target_path, target_content).expect("write target");
        let target = PkgFile {
            name: target_name.to_string(),
            path: target_path.to_string_lossy().into_owned(),
            mode: 0o100644,
            ..Default::default()
        };
        let link = PkgFile {
            name: "/usr/share/probe/link.sh".to_string(),
            path: "/usr/share/probe/link.sh".to_string(),
            mode: 0o120777,
            linkto: linkto.to_string(),
            ..Default::default()
        };
        pkg.files = vec![target, link];
        pkg.ghost_files = vec![];
        pkg.requires = requires.iter().map(|n| dep_named(n)).collect();
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let hits = out
            .results()
            .iter()
            .filter(|(n, _)| n == "symlink-to-binary-with-shebang")
            .cloned()
            .collect();
        (hits, dir)
    }

    #[test]
    fn symlink_to_false_shebang_script_is_quiet() {
        // uwsm's shape: the plugin fragments are sourced by the
        // session manager and carry a /bin/false shebang so they stay
        // inert when reached by name; there is no interpreter
        // dependency to demand for them.
        for content in [
            b"#!/bin/false\n# plugin fragment\n".as_slice(),
            b"#!/usr/bin/false\n".as_slice(),
            b"#!/bin/false --\n".as_slice(),
        ] {
            let (hits, _dir) = bindir_shebang_findings(content, "target.sh", &[]);
            assert!(hits.is_empty(), "{content:?} must stay quiet, got {hits:?}");
        }
    }

    #[test]
    fn symlink_to_real_shebang_script_still_fires() {
        // Near-miss controls: a real interpreter without a matching
        // requires still fires, and a name that merely starts with
        // the false path is a different interpreter entirely.
        let (hits, _dir) = bindir_shebang_findings(b"#!/bin/bash\n", "target.sh", &[]);
        assert_eq!(hits.len(), 1, "got {hits:?}");
        let (hits, _dir) = bindir_shebang_findings(b"#!/bin/falsehood\n", "target.sh", &[]);
        assert_eq!(hits.len(), 1, "got {hits:?}");
        // The long-standing credit is untouched: a package that does
        // require its interpreter is quiet.
        let (hits, _dir) = bindir_shebang_findings(b"#!/bin/bash\n", "target.sh", &["/bin/bash"]);
        assert!(hits.is_empty(), "got {hits:?}");
    }

    fn loop_findings(results: &[(String, String)]) -> Vec<&(String, String)> {
        results
            .iter()
            .filter(|(n, _)| n == "symlink-loop")
            .collect()
    }

    #[test]
    fn symlink_loop_self_link_relative_fires() {
        // Issue #723: a link pointing at itself. Its target is present
        // in the file list (it is the link itself), so neither dangling
        // finding can fire; the loop finding is the only report.
        let results = run_files_check_with_files(vec![symlink("/usr/lib/foo/self", "self")]);
        let names = finding_names(&results);
        let hits = loop_findings(&results);
        assert_eq!(hits.len(), 1, "got: {results:?}");
        assert!(
            hits[0].1.contains(": E: symlink-loop /usr/lib/foo/self"),
            "level and detail must render, got: {}",
            hits[0].1
        );
        assert_lacks(&names, "dangling-symlink");
        assert_lacks(&names, "dangling-relative-symlink");
    }

    #[test]
    fn symlink_loop_self_link_absolute_fires() {
        // Issue #723: the absolute spelling of a self-pointing link.
        let results =
            run_files_check_with_files(vec![symlink("/usr/lib/foo/self", "/usr/lib/foo/self")]);
        assert_eq!(loop_findings(&results).len(), 1, "got: {results:?}");
        assert_lacks(&finding_names(&results), "dangling-symlink");
    }

    #[test]
    fn symlink_loop_two_cycle_fires_for_both_links() {
        // Issue #723: a 2-cycle; both members' resolutions loop.
        let results = run_files_check_with_files(vec![
            symlink("/usr/lib/foo/a", "b"),
            symlink("/usr/lib/foo/b", "a"),
        ]);
        assert_eq!(loop_findings(&results).len(), 2, "got: {results:?}");
    }

    #[test]
    fn symlink_loop_longer_cycle_fires_for_every_link() {
        // Issue #723: a 3-cycle.
        let results = run_files_check_with_files(vec![
            symlink("/usr/lib/foo/a", "b"),
            symlink("/usr/lib/foo/b", "c"),
            symlink("/usr/lib/foo/c", "a"),
        ]);
        assert_eq!(loop_findings(&results).len(), 3, "got: {results:?}");
    }

    #[test]
    fn symlink_loop_across_directories_fires() {
        // Issue #723: the cycle crosses a directory hop and a `..`
        // segment; the normalised chain still revisits a path.
        let results = run_files_check_with_files(vec![
            symlink("/usr/lib/foo/a", "sub/b"),
            symlink("/usr/lib/foo/sub/b", "../a"),
        ]);
        assert_eq!(loop_findings(&results).len(), 2, "got: {results:?}");
    }

    #[test]
    fn symlink_loop_feeder_link_fires() {
        // Issue #723: a link resolving into a cycle never resolves
        // either; opening it fails with ELOOP like the cycle members.
        let results = run_files_check_with_files(vec![
            symlink("/usr/lib/foo/feeder", "a"),
            symlink("/usr/lib/foo/a", "b"),
            symlink("/usr/lib/foo/b", "a"),
        ]);
        assert_eq!(loop_findings(&results).len(), 3, "got: {results:?}");
    }

    #[test]
    fn symlink_chain_ending_at_real_file_is_quiet() {
        // Near miss (issue #723): a long but acyclic chain of links
        // ending at a shipped regular file.
        let results = run_files_check_with_files(vec![
            symlink("/usr/lib/foo/a", "b"),
            symlink("/usr/lib/foo/b", "c"),
            symlink("/usr/lib/foo/c", "real"),
            plain_file("/usr/lib/foo/real"),
        ]);
        assert_lacks(&finding_names(&results), "symlink-loop");
    }

    #[test]
    fn symlink_to_directory_is_quiet() {
        // Near miss (issue #723): a link whose target is a directory
        // entry the package ships.
        let dir = PkgFile {
            name: "/usr/share/foo".to_string(),
            path: "/usr/share/foo".to_string(),
            mode: 0o40755,
            ..Default::default()
        };
        let results = run_files_check_with_files(vec![symlink("/usr/share/link", "foo"), dir]);
        assert_lacks(&finding_names(&results), "symlink-loop");
    }

    #[test]
    fn dangling_link_reports_dangling_not_loop() {
        // Near miss (issue #723): a plain dangling link keeps its
        // existing finding only; its chain leaves the package at the
        // first hop.
        let results = run_files_check_with_files(vec![symlink(
            "/usr/lib/foo/dangling",
            "/usr/lib/foo/missing",
        )]);
        let names = finding_names(&results);
        assert_has(&names, "dangling-symlink");
        assert_lacks(&names, "symlink-loop");
    }

    /// The distro-shaped `DanglingSymlinkExceptions` table (the
    /// consolehelper entry of the vendored openSUSE config).
    fn config_with_consolehelper_exception() -> Config {
        let mut config = test_config();
        let mut entry = toml::Table::new();
        entry.insert(
            "path".to_string(),
            toml::Value::String("consolehelper$".to_string()),
        );
        entry.insert(
            "name".to_string(),
            toml::Value::String("usermode-consoleonly".to_string()),
        );
        let mut exceptions = toml::Table::new();
        exceptions.insert("consolehelper$".to_string(), toml::Value::Table(entry));
        config.configuration.insert(
            "DanglingSymlinkExceptions".to_string(),
            toml::Value::Table(exceptions),
        );
        config
    }

    #[test]
    fn dangling_relative_exception_diverts_to_no_dependency_on() {
        // Issue #547: the exceptions diversion survives the deferral —
        // with the consolehelper exception configured, the helper link
        // reports `no-dependency-on usermode-consoleonly` instead of
        // `dangling-relative-symlink`, decided in `after_checks` like
        // the plain finding; the build-host link still fires plainly.
        let config = config_with_consolehelper_exception();
        let (results, _dirs) =
            run_files_check_session(&[&fixture_path("dangling-lone-1.0-1.noarch.rpm")], &config);
        let diverted: Vec<&str> = results
            .iter()
            .filter(|(n, _)| n == "no-dependency-on")
            .map(|(_, line)| line.as_str())
            .collect();
        assert_eq!(diverted.len(), 1, "got: {results:?}");
        assert!(
            diverted[0].contains("usermode-consoleonly"),
            "unexpected line: {}",
            diverted[0]
        );
        let plain: Vec<&str> = results
            .iter()
            .filter(|(n, _)| n == "dangling-relative-symlink")
            .map(|(_, line)| line.as_str())
            .collect();
        assert_eq!(plain.len(), 2, "got: {results:?}");
        assert!(
            plain.iter().any(|l| l.contains("links/logo.txt")),
            "got: {results:?}"
        );
        assert!(
            plain.iter().any(|l| l.contains("lone-root-link")),
            "got: {results:?}"
        );
    }

    #[test]
    fn dangling_relative_exception_required_stays_silent() {
        // Issue #547: when the emitting package Requires the
        // exception's package, the diverted finding disappears
        // entirely — the per-package diversion outcome is unchanged by
        // the deferral. The build-host link still fires.
        let config = config_with_consolehelper_exception();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = Pkg::open(
            std::path::Path::new(&fixture_path("dangling-lone-1.0-1.noarch.rpm")),
            dir.path(),
            true,
        )
        .expect("open fixture");
        pkg.req_names.push("usermode-consoleonly".to_string());
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        if let Some(state) = check.export_state() {
            check.import_state(state);
        }
        check.after_checks(&config, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        assert_lacks(&names, "no-dependency-on");
        let lines: Vec<&str> = out
            .results()
            .iter()
            .filter(|(n, _)| n == "dangling-relative-symlink")
            .map(|(_, line)| line.as_str())
            .collect();
        assert_eq!(lines.len(), 2, "got: {:?}", out.results());
        assert!(
            lines.iter().any(|l| l.contains("links/logo.txt")),
            "got: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("lone-root-link")),
            "got: {lines:?}"
        );
    }

    /// Build one package from `files` (fcprobe header) and return the
    /// names of the findings the full session-aware FilesCheck emits.
    fn dangling_names_for_files(files: Vec<PkgFile>) -> Vec<String> {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        pkg.ghost_files = files
            .iter()
            .filter(|f| f.is_ghost())
            .map(|f| f.name.clone())
            .collect();
        // The fixture header carries its own Requires; clear them so
        // a case cannot be satisfied through the req_names escape
        // instead of the population it means to exercise.
        pkg.req_names.clear();
        pkg.files = files;
        let (results, _levels) = run_files_check_pkgs(&[pkg], &test_config());
        results.iter().map(|(n, _)| n.clone()).collect()
    }

    #[test]
    fn dangling_relative_populated_dir_target_stays_silent() {
        // The link's target is a directory no header entry names, but
        // the package ships payload below it, so installing the package
        // creates the directory and the link resolves (gajim-lang's
        // locale link shape). The reference fires here; the divergence
        // is ledgered.
        let names = dangling_names_for_files(vec![
            symlink("/usr/share/foo/locale", "../locale"),
            plain_file("/usr/share/locale/en/LC_MESSAGES/foo.mo"),
        ]);
        assert_lacks(&names, "dangling-relative-symlink");
    }

    #[test]
    fn dangling_relative_ancestor_target_stays_silent() {
        // A link to an ancestor of its own tree (`../..`, the ntp
        // chroot-mirror shape) names a directory the package's own
        // payload creates as a leading directory.
        let names = dangling_names_for_files(vec![
            symlink("/var/lib/foo/var/lib/foo", "../.."),
            plain_file("/var/lib/foo/drift"),
        ]);
        assert_lacks(&names, "dangling-relative-symlink");
    }

    #[test]
    fn dangling_relative_dot_target_stays_silent() {
        // A link to `.` (the onednn / X11 shape): the directory the
        // link itself sits in.
        let names = dangling_names_for_files(vec![
            symlink("/usr/include/mkl-foo", "."),
            plain_file("/usr/include/foo.h"),
        ]);
        assert_lacks(&names, "dangling-relative-symlink");
    }

    #[test]
    fn dangling_relative_lone_ancestor_and_dot_links_stay_silent() {
        // Lone-link pins: with no other payload at all, an ancestor
        // or dot link still resolves -- installing the link creates
        // its target as a leading directory of the link's own path,
        // so the link entry itself is the population evidence.
        for files in [
            vec![symlink("/var/lib/foo/var/lib/foo", "../..")],
            vec![symlink("/usr/include/mkl-foo", ".")],
        ] {
            let names = dangling_names_for_files(files);
            assert_lacks(&names, "dangling-relative-symlink");
        }
    }

    #[test]
    fn dangling_relative_root_target_stays_silent() {
        // A link whose normalised target is `/` itself: every
        // shipped path is below the root, so the package's payload
        // populates it. (The verbatim prefix would be `//`, which no
        // shipped path starts with; the `//usr/...` target form of
        // the root-link parity pin is a different shape and still
        // fires.)
        let names = dangling_names_for_files(vec![
            symlink("/usr/share/foo/rootlink", "../../.."),
            plain_file("/usr/share/foo/data.txt"),
        ]);
        assert_lacks(&names, "dangling-relative-symlink");
    }

    #[test]
    fn dangling_relative_ghost_only_population_fires() {
        // A %ghost entry below the target installs no payload, so it
        // creates no directory: the target stays dangling.
        let mut ghost = plain_file("/usr/share/locale/en/LC_MESSAGES/foo.mo");
        ghost.flags = crate::pkg::pkgfile::RPMFILE_GHOST;
        let names =
            dangling_names_for_files(vec![symlink("/usr/share/foo/locale", "../locale"), ghost]);
        assert_has(&names, "dangling-relative-symlink");
    }

    #[test]
    fn dangling_relative_string_prefix_lookalike_fires() {
        // `/usr/share/locale2/...` shares a string prefix with the
        // target `/usr/share/locale` but is not below it: no credit.
        let names = dangling_names_for_files(vec![
            symlink("/usr/share/foo/locale", "../locale"),
            plain_file("/usr/share/locale2/en/LC_MESSAGES/foo.mo"),
        ]);
        assert_has(&names, "dangling-relative-symlink");
    }

    #[test]
    fn dangling_relative_root_link_populated_target_still_fires() {
        // Class-F parity (issue #547): a root-level link's normalised
        // target keeps the double leading slash (`//usr/...`), which no
        // shipped path starts with, so the populated-directory credit
        // does not rescue it -- the reference fires identically.
        let names = dangling_names_for_files(vec![
            symlink("/lone-root-link", "usr/share/foo/sub"),
            plain_file("/usr/share/foo/sub/data.txt"),
        ]);
        assert_has(&names, "dangling-relative-symlink");
    }

    #[test]
    fn symlink_up_and_down_segments() {
        // The reference emits E symlink-contains-up-and-down-segments once
        // per ".." segment left in the link target after the leading "../"
        // run is consumed. Only targets starting with "../" are examined;
        // an empty remainder stays silent. Cases verified against the
        // pinned reference interpreter, except the all-".." targets:
        // the reference counts the final ".." of a pure-up target such
        // as "../.." (it needs a trailing slash to be consumed as part
        // of the leading run), but such a link has no down segment and
        // is already in its shortest form, so crab stays silent there;
        // the divergence is ledgered (ntp's chroot mirror link
        // /var/lib/ntp/var/lib/ntp -> ../.. is the corpus instance).
        let config = test_config();
        let mut check = FilesCheck::new(&config);
        // (fname, link target, expected E count)
        let cases = [
            ("/a/b/c", "../foo/../bar", 1),
            ("/a/b/c", "../../x/../y", 1),
            ("/a/b/c", "../../a/../b/../c", 2),
            ("/a/b/c", "../..", 0),
            ("/a/b/c", "../../..", 0),
            ("/a/b/c", "../foo/..", 1),
            ("/a/b/c", "../..../..", 1),
            ("/a/b/c", "../", 0),
            ("/a/b/c", "foo/../bar", 0),
            ("/a/b/c", "../foo", 0),
            ("/a/b/c", "/abs/path", 0),
        ];
        for (fname, link, expected) in cases {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let mut pkg = Pkg::open(
                std::path::Path::new(&fixture_path("fcprobe-1-1.noarch.rpm")),
                dir.path(),
                true,
            )
            .expect("open fixture");
            // Silence the dangling-relative-symlink finding so the count
            // below sees only this check's emissions.
            let parent = std::path::Path::new(fname)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            pkg.req_names
                .push(crate::pkg::normalize_path(&format!("{parent}/{link}")));
            let pkgfile = crate::pkg::pkgfile::PkgFile {
                name: fname.to_string(),
                linkto: link.to_string(),
                ..Default::default()
            };
            let st = PkgState::default();
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_link_relative(&pkg, fname, &pkgfile, &st, &mut out);
            let hits: Vec<(usize, &(String, String))> = out
                .results()
                .iter()
                .enumerate()
                .filter(|(_, (name, _))| name == "symlink-contains-up-and-down-segments")
                .collect();
            assert_eq!(hits.len(), expected, "fname={fname} link={link}");
            for (i, (name, line)) in hits {
                assert_eq!(name, "symlink-contains-up-and-down-segments");
                assert_eq!(out.result_levels()[i], Level::Error);
                assert!(
                    line.contains(fname) && line.contains(link),
                    "detail must name the file and target, got: {line}"
                );
            }
        }
    }

    #[test]
    fn pyc_magic_from_chunk_reads_little_endian() {
        // Magic 3379 (Python 3.6) as little-endian u32, masked to 16 bits.
        let chunk = [0x33, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(FilesCheck::pyc_magic_from_chunk(&chunk), 3379);
    }

    #[test]
    fn pyc_mtime_from_chunk_pre37() {
        // Pre-3.7: mtime is bytes 4-8.
        let mut chunk = [0u8; 12];
        chunk[0..4].copy_from_slice(&3379u32.to_le_bytes());
        chunk[4..8].copy_from_slice(&1234567890u32.to_le_bytes());
        assert_eq!(FilesCheck::pyc_mtime_from_chunk(&chunk), Some(1234567890));
    }

    #[test]
    fn pyc_mtime_from_chunk_37_hash_based_returns_none() {
        // Python 3.7+: if the flags field (bytes 4-8) is nonzero, the pyc is
        // hash-based and has no mtime.
        let mut chunk = [0u8; 12];
        chunk[0..4].copy_from_slice(&3390u32.to_le_bytes());
        chunk[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(FilesCheck::pyc_mtime_from_chunk(&chunk), None);
    }

    #[test]
    fn pyc_mtime_from_chunk_37_timestamp_based() {
        // Python 3.7+: flags == 0 means timestamp-based, mtime at bytes 8-12.
        let mut chunk = [0u8; 12];
        chunk[0..4].copy_from_slice(&3390u32.to_le_bytes());
        chunk[4..8].copy_from_slice(&0u32.to_le_bytes());
        chunk[8..12].copy_from_slice(&1234567890u32.to_le_bytes());
        assert_eq!(FilesCheck::pyc_mtime_from_chunk(&chunk), Some(1234567890));
    }

    #[test]
    fn expected_pyc_magic_from_path() {
        let check = FilesCheck::new(&test_config());
        let (magics, ver) = check.expected_pyc_magic("/usr/lib/python3.6/foo.pyc");
        assert_eq!(ver, Some("3.6".to_string()));
        assert_eq!(magics, Some(vec![3379]));
    }

    #[test]
    fn expected_pyc_magic_unknown_version_returns_none() {
        let check = FilesCheck::new(&test_config());
        // No version in path and no PythonDefaultVersion configured.
        let (magics, ver) = check.expected_pyc_magic("/opt/foo.pyc");
        assert_eq!(ver, None);
        assert_eq!(magics, None);
    }

    #[test]
    fn python_magic_values_known_versions() {
        assert_eq!(FilesCheck::python_magic_values("3.6"), &[3379][..]);
        assert_eq!(
            FilesCheck::python_magic_values("3.7"),
            &[3390, 3391, 3392, 3393, 3394][..]
        );
        assert!(FilesCheck::python_magic_values("9.9").is_empty());
    }

    #[test]
    fn python_magic_table_matches_the_former_hardcoded_table() {
        // The move from a hardcoded match to the data file must not
        // change a single value: every former entry, checked through
        // the real lookup path.
        let expected: [(&str, &[u32]); 14] = [
            ("2.2", &[60717]),
            ("2.3", &[62011]),
            ("2.4", &[62061]),
            ("2.5", &[62131]),
            ("2.6", &[62161]),
            ("2.7", &[62211]),
            ("3.0", &[3130]),
            ("3.1", &[3150]),
            ("3.2", &[3180]),
            ("3.3", &[3230]),
            ("3.4", &[3310]),
            ("3.5", &[3350, 3351]),
            ("3.6", &[3379]),
            ("3.7", &[3390, 3391, 3392, 3393, 3394]),
        ];
        for (version, magics) in expected {
            assert_eq!(FilesCheck::python_magic_values(version), magics);
        }
    }

    #[test]
    fn pyc_magic_check_modern_versions_from_path() {
        // Magic numbers verified against installed interpreters (3.12.16,
        // 3.13.18, 3.15.2) and CPython release-branch heads (3.8, 3.9,
        // 3.10, 3.11, 3.14). A matching magic stays silent; a foreign magic
        // fires an Error from the path version.
        let check = FilesCheck::new(&test_config());
        assert!(
            check
                .pyc_magic_check("/usr/lib/python3.8/foo.pyc", 3413)
                .is_none()
        );
        assert!(
            check
                .pyc_magic_check("/usr/lib/python3.9/foo.pyc", 3425)
                .is_none()
        );
        assert!(
            check
                .pyc_magic_check("/usr/lib/python3.10/foo.pyc", 3439)
                .is_none()
        );
        assert!(
            check
                .pyc_magic_check("/usr/lib/python3.11/foo.pyc", 3495)
                .is_none()
        );
        assert!(
            check
                .pyc_magic_check("/usr/lib/python3.12/foo.pyc", 3531)
                .is_none()
        );
        assert!(
            check
                .pyc_magic_check("/usr/lib/python3.13/foo.pyc", 3571)
                .is_none()
        );
        assert!(
            check
                .pyc_magic_check("/usr/lib/python3.14/foo.pyc", 3627)
                .is_none()
        );
        assert!(
            check
                .pyc_magic_check("/usr/lib/python3.15/foo.pyc", 3666)
                .is_none()
        );
        let (level, details) = check
            .pyc_magic_check("/usr/lib/python3.12/foo.pyc", 3571)
            .expect("finding");
        assert_eq!(level, Level::Error);
        assert!(
            details[1].contains("expected 3531 (3.12)"),
            "{}",
            details[1]
        );
        assert!(details[1].contains("found 3571 (3.13)"), "{}", details[1]);
    }

    #[test]
    fn pyc_magic_check_wrong_magic_from_path_is_error() {
        // The expected version came from the .pyc path -> E.
        let check = FilesCheck::new(&test_config());
        let (level, details) = check
            .pyc_magic_check("/usr/lib/python3.6/foo.pyc", 3390)
            .expect("finding");
        assert_eq!(level, Level::Error);
        assert_eq!(details[0], "/usr/lib/python3.6/foo.pyc");
        assert!(details[1].contains("expected 3379 (3.6)"), "{}", details[1]);
        assert!(details[1].contains("found 3390 (3.7)"), "{}", details[1]);
    }

    #[test]
    fn pyc_magic_check_wrong_magic_from_default_is_warning() {
        // No version in the path; the default version supplies it -> W.
        let mut config = test_config();
        config.configuration.insert(
            "PythonDefaultVersion".to_string(),
            toml::Value::String("3.6".to_string()),
        );
        let check = FilesCheck::new(&config);
        let (level, details) = check
            .pyc_magic_check("/opt/foo.pyc", 3390)
            .expect("finding");
        assert_eq!(level, Level::Warning);
        assert!(details[1].contains("expected 3379 (3.6)"), "{}", details[1]);
    }

    #[test]
    fn pyc_magic_check_matching_magic_emits_nothing() {
        let check = FilesCheck::new(&test_config());
        assert!(
            check
                .pyc_magic_check("/usr/lib/python3.6/foo.pyc", 3379)
                .is_none()
        );
    }

    #[test]
    fn pyc_magic_check_unknown_version_emits_nothing() {
        // No version in the path and no default configured: no expected
        // magics, so nothing to compare against.
        let check = FilesCheck::new(&test_config());
        assert!(check.pyc_magic_check("/opt/foo.pyc", 12345).is_none());
    }

    #[test]
    fn pyc_mtime_check_stale_pyc_emits_finding() {
        // The .pyc is older than the source: the four detail parts in the
        // reference's order.
        let details = FilesCheck::pyc_mtime_check(
            Some(1000),
            2000,
            "/usr/lib/python3.6/foo.pyc",
            "/usr/lib/python3.6/foo.py",
        )
        .expect("finding");
        assert_eq!(
            details,
            vec![
                "/usr/lib/python3.6/foo.pyc",
                "1000",
                "/usr/lib/python3.6/foo.py",
                "2000",
            ]
        );
    }

    #[test]
    fn pyc_mtime_check_newer_pyc_is_silent() {
        // rpmlint#1331 (open, unmerged): a newer .pyc is a local-build
        // artifact, not an error. This pins the `<` vs `!=` divergence: a
        // `!=` comparison would emit here.
        assert!(
            FilesCheck::pyc_mtime_check(
                Some(3000),
                2000,
                "/usr/lib/python3.6/foo.pyc",
                "/usr/lib/python3.6/foo.py",
            )
            .is_none()
        );
    }

    #[test]
    fn pyc_mtime_check_equal_timestamps_is_silent() {
        assert!(
            FilesCheck::pyc_mtime_check(
                Some(2000),
                2000,
                "/usr/lib/python3.6/foo.pyc",
                "/usr/lib/python3.6/foo.py",
            )
            .is_none()
        );
    }

    #[test]
    fn pyc_mtime_check_hash_based_pyc_emits_nothing() {
        // PEP 552 hash-based .pyc carries no mtime (None): neither mtime
        // finding can fire.
        assert!(
            FilesCheck::pyc_mtime_check(
                None,
                2000,
                "/usr/lib/python3.7/foo.pyc",
                "/usr/lib/python3.7/foo.py",
            )
            .is_none()
        );
    }

    #[test]
    fn pyc_cache_version_mismatch_foreign_tag() {
        let check = FilesCheck::new(&test_config());
        // The live shape: a cpython-312 cache file in a python3.13 tree
        // (and in a python3.14 tree), plain and opt-1 forms.
        assert!(check.pyc_cache_version_mismatch(
            "/usr/lib64/python3.13/site-packages/foo/__pycache__/__init__.cpython-312.pyc"
        ));
        assert!(check.pyc_cache_version_mismatch(
            "/usr/lib64/python3.14/site-packages/foo/__pycache__/__init__.cpython-312.opt-1.pyc"
        ));
        assert!(check.pyc_cache_version_mismatch(
            "/usr/lib/python3.13/site-packages/foo/__pycache__/mod.cpython-27.pyc"
        ));
    }

    #[test]
    fn pyc_cache_version_mismatch_matching_tag_is_no_mismatch() {
        let check = FilesCheck::new(&test_config());
        assert!(!check.pyc_cache_version_mismatch(
            "/usr/lib64/python3.13/site-packages/foo/__pycache__/__init__.cpython-313.pyc"
        ));
        assert!(!check.pyc_cache_version_mismatch(
            "/usr/lib64/python3.13/site-packages/foo/__pycache__/__init__.cpython-313.opt-2.pyc"
        ));
        assert!(!check.pyc_cache_version_mismatch(
            "/usr/lib/python2.7/site-packages/foo/__pycache__/__init__.cpython-27.pyc"
        ));
        assert!(!check.pyc_cache_version_mismatch(
            "/usr/lib64/python3.9/site-packages/foo/__pycache__/__init__.cpython-39.pyc"
        ));
    }

    #[test]
    fn pyc_cache_version_mismatch_fails_closed() {
        let check = FilesCheck::new(&test_config());
        // Direct (non-PEP 3147) layout: no cache tag at all.
        assert!(
            !check
                .pyc_cache_version_mismatch("/usr/lib64/python3.13/site-packages/foo/__init__.pyc")
        );
        // No versioned tree in the path: nothing to compare against.
        assert!(
            !check
                .pyc_cache_version_mismatch("/usr/share/foo/__pycache__/__init__.cpython-312.pyc")
        );
        // A bare python3 tree pins no minor version.
        assert!(!check.pyc_cache_version_mismatch(
            "/usr/lib/python3/site-packages/foo/__pycache__/__init__.cpython-312.pyc"
        ));
        // Non-CPython cache tags do not parse as a CPython version.
        assert!(!check.pyc_cache_version_mismatch(
            "/usr/lib64/python3.13/site-packages/foo/__pycache__/__init__.pypy-41.pyc"
        ));
        assert!(!check.pyc_cache_version_mismatch(
            "/usr/lib64/python3.13/site-packages/foo/__pycache__/__init__.graalpy-310.pyc"
        ));
    }

    /// Build a package holding one .py and one .pyc with real on-disk
    /// content, so the .pyc header chunk is read for real.
    fn pyc_mtime_pkg(
        dir: &tempfile::TempDir,
        py_name: &str,
        py_mtime: u64,
        pyc_name: &str,
        pyc_header: &[u8],
    ) -> Pkg {
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        pkg.name = "pyc-mtime-test".to_string();
        let mk = |name: &str, content: &[u8], mtime: u64| {
            let path = dir.path().join(name.trim_start_matches('/'));
            std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
            std::fs::write(&path, content).expect("write temp file");
            PkgFile {
                name: name.to_string(),
                path: path.to_string_lossy().into_owned(),
                mode: 0o100644,
                mtime,
                ..Default::default()
            }
        };
        pkg.files = vec![
            mk(py_name, b"x = 1\n", py_mtime),
            mk(pyc_name, pyc_header, py_mtime),
        ];
        pkg
    }

    fn pyc_header(magic: u32, flags: u32, ts: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&magic.to_le_bytes());
        v.extend_from_slice(&flags.to_le_bytes());
        v.extend_from_slice(&ts.to_le_bytes());
        v.extend_from_slice(&4u32.to_le_bytes());
        v
    }

    fn inconsistent_mtime_lines(pkg: &Pkg) -> Vec<String> {
        run_check_binary(pkg)
            .iter()
            .filter(|(n, _)| n == "python-bytecode-inconsistent-mtime")
            .map(|(_, l)| l.clone())
            .collect()
    }

    #[test]
    fn pyc_mtime_foreign_cache_version_is_silent() {
        // Stale embedded timestamp (1000 < 2000), but the cache file is
        // keyed to CPython 3.12 while the tree is python3.13: the tree's
        // interpreter never reads it, so no mtime finding.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = pyc_mtime_pkg(
            &dir,
            "/usr/lib64/python3.13/site-packages/foo/__init__.py",
            2000,
            "/usr/lib64/python3.13/site-packages/foo/__pycache__/__init__.cpython-312.pyc",
            &pyc_header(3531, 0, 1000),
        );
        assert!(inconsistent_mtime_lines(&pkg).is_empty());
    }

    #[test]
    fn pyc_mtime_matching_cache_version_stale_fires() {
        // Same staleness with the tree's own cache tag: the finding fires.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = pyc_mtime_pkg(
            &dir,
            "/usr/lib64/python3.13/site-packages/foo/__init__.py",
            2000,
            "/usr/lib64/python3.13/site-packages/foo/__pycache__/__init__.cpython-313.pyc",
            &pyc_header(3571, 0, 1000),
        );
        let lines = inconsistent_mtime_lines(&pkg);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("1000"), "{}", lines[0]);
        assert!(lines[0].contains("2000"), "{}", lines[0]);
    }

    #[test]
    fn pyc_mtime_unversioned_tree_stale_fires() {
        // Fail closed: no version in the tree path, so the foreign tag
        // cannot be credited and the stale finding stands.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = pyc_mtime_pkg(
            &dir,
            "/usr/share/foo/__init__.py",
            2000,
            "/usr/share/foo/__pycache__/__init__.cpython-312.pyc",
            &pyc_header(3531, 0, 1000),
        );
        assert_eq!(inconsistent_mtime_lines(&pkg).len(), 1);
    }

    #[test]
    fn pyc_nested_below_cache_dir_shapes() {
        // The live shape: a byte-compiled tree mirrored below
        // __pycache__ inside a documentation payload.
        assert!(FilesCheck::pyc_nested_below_cache_dir(
            "/usr/share/doc/kernel/html/rst/__pycache__/home/abuild/rpmbuild/BUILD/linux/Documentation/sphinx/kerneldoc.cpython-313.pyc"
        ));
        // One extra directory level is enough.
        assert!(FilesCheck::pyc_nested_below_cache_dir(
            "/usr/share/foo/__pycache__/sub/mod.cpython-313.pyc"
        ));
        // A doubled cache directory: the outer one is not the parent.
        assert!(FilesCheck::pyc_nested_below_cache_dir(
            "/usr/share/foo/__pycache__/__pycache__/mod.cpython-313.pyc"
        ));
        // A plain PEP 3147 entry: __pycache__ is the parent directory.
        assert!(!FilesCheck::pyc_nested_below_cache_dir(
            "/usr/lib64/python3.13/site-packages/foo/__pycache__/mod.cpython-313.pyc"
        ));
        // A legacy sourceless module: no cache directory at all.
        assert!(!FilesCheck::pyc_nested_below_cache_dir(
            "/usr/lib64/python3.13/site-packages/foo/mod.pyc"
        ));
        // A directory merely named with a __pycache__ prefix is not a
        // cache directory.
        assert!(!FilesCheck::pyc_nested_below_cache_dir(
            "/usr/share/foo/__pycache__data/sub/mod.pyc"
        ));
        // A cache directory as the module directory itself: the file
        // is its direct child, so the predicate stays out.
        assert!(!FilesCheck::pyc_nested_below_cache_dir(
            "/usr/share/__pycache__/mod.pyc"
        ));
    }

    /// Build a package from explicit file entries so the bytecode
    /// source checks can be driven over arbitrary layouts. Regular
    /// files get real on-disk content; a symlink entry carries its
    /// target in the package metadata, as a shipped symlink does.
    fn pybc_pkg(dir: &tempfile::TempDir, entries: &[(&str, &[u8], Option<&str>)]) -> Pkg {
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        pkg.name = "pyc-without-source-test".to_string();
        pkg.files = entries
            .iter()
            .map(|(name, content, linkto)| {
                let path = dir.path().join(name.trim_start_matches('/'));
                std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
                std::fs::write(&path, content).expect("write temp file");
                PkgFile {
                    name: name.to_string(),
                    path: path.to_string_lossy().into_owned(),
                    mode: if linkto.is_some() { 0o120777 } else { 0o100644 },
                    linkto: linkto.unwrap_or("").to_string(),
                    ..Default::default()
                }
            })
            .collect();
        pkg
    }

    fn without_source_lines(pkg: &Pkg) -> Vec<String> {
        run_check_binary(pkg)
            .iter()
            .filter(|(n, _)| n == "python-bytecode-without-source")
            .map(|(_, l)| l.clone())
            .collect()
    }

    #[test]
    fn pyc_without_source_nested_below_cache_dir_is_silent() {
        // Byte-compiled build tree mirrored below __pycache__ in a
        // documentation payload; no source ships, and the location is
        // not one any import lookup reads as bytecode.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = pybc_pkg(
            &dir,
            &[(
                "/usr/share/doc/kernel/html/rst/__pycache__/home/abuild/build/Documentation/sphinx/kerneldoc.cpython-313.pyc",
                &pyc_header(3571, 0, 1000),
                None,
            )],
        );
        assert!(without_source_lines(&pkg).is_empty());
    }

    #[test]
    fn pyc_without_source_nested_with_symlink_source_is_silent() {
        // The computed source of a nested file ships as a symlink whose
        // chain leaves the package; the location credit still applies.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = pybc_pkg(
            &dir,
            &[
                (
                    "/usr/share/foo/__pycache__/build/tree/mod.cpython-313.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
                (
                    "/usr/share/foo/build/tree/mod.py",
                    b"x = 1\n",
                    Some("/usr/share/elsewhere/mod.py"),
                ),
            ],
        );
        assert!(without_source_lines(&pkg).is_empty());
    }

    #[test]
    fn pyc_without_source_normal_cache_entry_still_fires() {
        // Near miss: a plain PEP 3147 cache entry whose source is
        // absent keeps the finding -- __pycache__ is its parent.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = pybc_pkg(
            &dir,
            &[(
                "/usr/lib64/python3.13/site-packages/foo/__pycache__/mod.cpython-313.pyc",
                &pyc_header(3571, 0, 1000),
                None,
            )],
        );
        assert_eq!(without_source_lines(&pkg).len(), 1);
    }

    #[test]
    fn pyc_without_source_legacy_layout_still_fires() {
        // Near miss: a legacy sourceless module keeps the finding.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = pybc_pkg(
            &dir,
            &[(
                "/usr/lib64/python3.13/site-packages/foo/mod.pyc",
                &pyc_header(3571, 0, 1000),
                None,
            )],
        );
        assert_eq!(without_source_lines(&pkg).len(), 1);
    }

    #[test]
    fn pyc_nested_with_shipped_source_keeps_mtime_check() {
        // The credit is scoped to the without-source finding: a nested
        // file whose source ships and resolves still gets the mtime
        // comparison (a stale embedded timestamp fires).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = pybc_pkg(
            &dir,
            &[
                (
                    "/usr/share/foo/__pycache__/build/tree/mod.cpython-313.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
                ("/usr/share/foo/build/tree/mod.py", b"x = 1\n", None),
            ],
        );
        for f in pkg.files.iter_mut() {
            if f.name.ends_with(".py") {
                f.mtime = 2000;
            }
        }
        assert!(without_source_lines(&pkg).is_empty());
        assert_eq!(inconsistent_mtime_lines(&pkg).len(), 1);
    }

    /// Mark the named entry of a `pybc_pkg` package executable, as
    /// a shipped interpreter entry is.
    fn mark_exec(pkg: &mut Pkg, name: &str) {
        pkg.files
            .iter_mut()
            .find(|f| f.name == name)
            .expect("entry exists")
            .mode = 0o100755;
    }

    #[test]
    fn pyc_in_shipped_interpreter_tree_is_silent() {
        // The rpmlint-mini shape: the package ships its interpreter
        // and the interpreter's whole library tree as sourceless
        // bytecode, in legacy and PEP 3147 layouts alike.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = pybc_pkg(
            &dir,
            &[
                ("/opt/testing/bin/python3.13", b"elf", None),
                (
                    "/opt/testing/lib/python3.13/encodings/aliases.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
                (
                    "/opt/testing/lib/python3.13/json/__pycache__/decoder.cpython-313.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
            ],
        );
        mark_exec(&mut pkg, "/opt/testing/bin/python3.13");
        assert!(without_source_lines(&pkg).is_empty());
    }

    #[test]
    fn pyc_in_free_threaded_interpreter_tree_is_silent() {
        // The t grammar: a free-threaded interpreter earns the
        // same lib tree as its GIL twin.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = pybc_pkg(
            &dir,
            &[
                ("/opt/testing/bin/python3.13t", b"elf", None),
                (
                    "/opt/testing/lib/python3.13t/encodings/aliases.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
            ],
        );
        mark_exec(&mut pkg, "/opt/testing/bin/python3.13t");
        assert!(without_source_lines(&pkg).is_empty());
    }

    #[test]
    fn pyc_tree_with_abi_suffix_other_than_t_still_fires() {
        // Near misses: d and m suffixes fail closed, so their trees
        // earn no credit and the bytecode keeps firing.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = pybc_pkg(
            &dir,
            &[
                ("/opt/testing/bin/python3.13d", b"elf", None),
                (
                    "/opt/testing/lib/python3.13d/encodings/aliases.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
                ("/opt/testing/bin/python3.13m", b"elf", None),
                (
                    "/opt/testing/lib/python3.13m/encodings/aliases.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
            ],
        );
        mark_exec(&mut pkg, "/opt/testing/bin/python3.13d");
        mark_exec(&mut pkg, "/opt/testing/bin/python3.13m");
        assert_eq!(without_source_lines(&pkg).len(), 2);
    }

    #[test]
    fn pyc_tree_under_usr_local_still_fires() {
        // Near miss: an interpreter under /usr/local earns no tree,
        // so its library's bytecode keeps firing.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = pybc_pkg(
            &dir,
            &[
                ("/usr/local/bin/python3.13", b"elf", None),
                (
                    "/usr/local/lib/python3.13/encodings/aliases.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
            ],
        );
        mark_exec(&mut pkg, "/usr/local/bin/python3.13");
        assert_eq!(without_source_lines(&pkg).len(), 1);
    }

    #[test]
    fn pyc_tree_under_nested_usr_local_still_fires() {
        // Near miss: the exclusion covers the whole /usr/local
        // subtree, so a nested interpreter earns no tree either.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = pybc_pkg(
            &dir,
            &[
                ("/usr/local/myapp/bin/python3.13", b"elf", None),
                (
                    "/usr/local/myapp/lib/python3.13/encodings/aliases.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
            ],
        );
        mark_exec(&mut pkg, "/usr/local/myapp/bin/python3.13");
        assert_eq!(without_source_lines(&pkg).len(), 1);
    }

    #[test]
    fn pyc_tree_without_interpreter_still_fires() {
        // Near miss: the same library tree with no interpreter
        // shipped keeps the finding.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = pybc_pkg(
            &dir,
            &[
                (
                    "/opt/testing/lib/python3.13/encodings/aliases.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
                (
                    "/opt/testing/lib/python3.13/json/__pycache__/decoder.cpython-313.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
            ],
        );
        assert_eq!(without_source_lines(&pkg).len(), 2);
    }

    #[test]
    fn pyc_outside_shipped_interpreter_tree_still_fires() {
        // Near miss: an interpreter is shipped, but the bytecode
        // sits in a different version's tree and in the system tree,
        // neither of which is the shipped interpreter's library tree.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = pybc_pkg(
            &dir,
            &[
                ("/opt/testing/bin/python3.13", b"elf", None),
                (
                    "/opt/testing/lib/python3.12/encodings/aliases.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
                (
                    "/usr/lib/python3.13/site-packages/foo.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
            ],
        );
        mark_exec(&mut pkg, "/opt/testing/bin/python3.13");
        assert_eq!(without_source_lines(&pkg).len(), 2);
    }

    #[test]
    fn pyc_tree_with_non_executable_interpreter_still_fires() {
        // Near miss: the interpreter name is present but the entry
        // is not an executable regular file.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = pybc_pkg(
            &dir,
            &[
                ("/opt/testing/bin/python3.13", b"elf", None),
                (
                    "/opt/testing/lib/python3.13/encodings/aliases.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
            ],
        );
        assert_eq!(without_source_lines(&pkg).len(), 1);
    }

    #[test]
    fn pyc_tree_with_unversioned_or_linked_interpreter_still_fires() {
        // Near misses: an unversioned interpreter name pins no
        // library tree, and a symlink entry is not the shipped
        // interpreter itself.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = pybc_pkg(
            &dir,
            &[
                ("/opt/testing/bin/python3", b"elf", None),
                (
                    "/opt/testing/lib/python3.13/encodings/aliases.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
            ],
        );
        mark_exec(&mut pkg, "/opt/testing/bin/python3");
        assert_eq!(without_source_lines(&pkg).len(), 1);

        let dir2 = tempfile::TempDir::new().expect("tmpdir");
        let pkg = pybc_pkg(
            &dir2,
            &[
                (
                    "/opt/testing/bin/python3.13",
                    b"",
                    Some("/usr/bin/python3.13"),
                ),
                (
                    "/opt/testing/lib/python3.13/encodings/aliases.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
            ],
        );
        assert_eq!(without_source_lines(&pkg).len(), 1);
    }

    #[test]
    fn pyc_in_tree_with_shipped_source_keeps_mtime_check() {
        // The credit is scoped to the without-source finding: a
        // module of the tree whose source ships and resolves still
        // gets the mtime comparison.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = pybc_pkg(
            &dir,
            &[
                ("/opt/testing/bin/python3.13", b"elf", None),
                ("/opt/testing/lib/python3.13/foo.py", b"x = 1\n", None),
                (
                    "/opt/testing/lib/python3.13/__pycache__/foo.cpython-313.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
            ],
        );
        mark_exec(&mut pkg, "/opt/testing/bin/python3.13");
        for f in pkg.files.iter_mut() {
            if f.name.ends_with(".py") {
                f.mtime = 2000;
            }
        }
        assert!(without_source_lines(&pkg).is_empty());
        assert_eq!(inconsistent_mtime_lines(&pkg).len(), 1);
    }

    /// A run member for the cross-package bytecode credit, built on
    /// the fsf fixture: its header `SOURCERPM` is
    /// `fsf-address-fixture-1.0-1.src.rpm`.
    fn pybc_run_pkg(
        dir: &tempfile::TempDir,
        name: &str,
        entries: &[(&str, &[u8], Option<&str>)],
    ) -> Pkg {
        let mut pkg = pybc_pkg(dir, entries);
        pkg.name = name.to_string();
        pkg
    }

    /// The fsf fixture as the run's source package: the identity it
    /// derives (`fsf-address-fixture-1.0-1.src.rpm`) is the
    /// `SOURCERPM` every run member carries, so its presence makes
    /// the build complete.
    fn pybc_src_pkg(dir: &tempfile::TempDir) -> Pkg {
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        pkg.is_source = true;
        pkg.files = Vec::new();
        pkg
    }

    fn run_without_source_count(pkgs: &[Pkg]) -> usize {
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(pkgs, &config);
        results
            .iter()
            .filter(|(n, _)| n == "python-bytecode-without-source")
            .count()
    }

    /// The singlespec dedup shape: the candidate's `caca/__init__.py`
    /// is a symlink into the sibling flavour package's tree, and its
    /// cache entry maps to that symlink.
    fn caca_candidate(dir: &tempfile::TempDir) -> Pkg {
        pybc_run_pkg(
            dir,
            "python313-caca",
            &[
                (
                    "/usr/lib/python3.13/site-packages/caca/__pycache__/__init__.cpython-313.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
                (
                    "/usr/lib/python3.13/site-packages/caca/__init__.py",
                    b"",
                    Some("../../../python3.14/site-packages/caca/__init__.py"),
                ),
            ],
        )
    }

    fn caca_sibling(dir: &tempfile::TempDir) -> Pkg {
        pybc_run_pkg(
            dir,
            "python314-caca",
            &[(
                "/usr/lib/python3.14/site-packages/caca/__init__.py",
                b"x = 1\n",
                None,
            )],
        )
    }

    #[test]
    fn pyc_sibling_source_credited_on_complete_build() {
        // Complete build: the run holds the source package and the
        // sibling flavour ships the file the source symlink resolves
        // to, so the candidate is credited.
        let d0 = tempfile::TempDir::new().expect("tmpdir");
        let d1 = tempfile::TempDir::new().expect("tmpdir");
        let d2 = tempfile::TempDir::new().expect("tmpdir");
        let src = pybc_src_pkg(&d0);
        let cand = caca_candidate(&d1);
        let sib = caca_sibling(&d2);
        assert_eq!(run_without_source_count(&[src, cand, sib]), 0);
    }

    #[test]
    fn pyc_sibling_source_fires_on_partial_build() {
        // The sibling ships the target, but the run holds no source
        // package: the build is not judged complete and the
        // candidate fires as the per-package verdict.
        let d1 = tempfile::TempDir::new().expect("tmpdir");
        let d2 = tempfile::TempDir::new().expect("tmpdir");
        let cand = caca_candidate(&d1);
        let sib = caca_sibling(&d2);
        assert_eq!(run_without_source_count(&[cand, sib]), 1);
    }

    #[test]
    fn pyc_sibling_source_fires_for_foreign_source() {
        // A source package of another build does not open the gate.
        let d0 = tempfile::TempDir::new().expect("tmpdir");
        let d1 = tempfile::TempDir::new().expect("tmpdir");
        let d2 = tempfile::TempDir::new().expect("tmpdir");
        let mut src = pybc_src_pkg(&d0);
        src.name = "otherbuild".to_string();
        let cand = caca_candidate(&d1);
        let sib = caca_sibling(&d2);
        assert_eq!(run_without_source_count(&[src, cand, sib]), 1);
    }

    #[test]
    fn pyc_sibling_source_fires_when_target_not_in_run() {
        // Complete build, but no package of the run ships the file
        // the symlink resolves to.
        let d0 = tempfile::TempDir::new().expect("tmpdir");
        let d1 = tempfile::TempDir::new().expect("tmpdir");
        let src = pybc_src_pkg(&d0);
        let cand = caca_candidate(&d1);
        assert_eq!(run_without_source_count(&[src, cand]), 1);
    }

    #[test]
    fn pyc_sibling_source_single_package_fires_with_exact_line() {
        // A single-package run reports exactly the per-package
        // verdict, in the per-package rendering.
        let d1 = tempfile::TempDir::new().expect("tmpdir");
        let cand = caca_candidate(&d1);
        let config = test_config();
        let (results, _levels) = run_files_check_pkgs(&[cand], &config);
        let lines: Vec<&str> = results
            .iter()
            .filter(|(n, _)| n == "python-bytecode-without-source")
            .map(|(_, l)| l.as_str())
            .collect();
        assert_eq!(lines.len(), 1, "got: {results:?}");
        assert_eq!(
            lines[0],
            "python313-caca.noarch: W: python-bytecode-without-source /usr/lib/python3.13/site-packages/caca/__pycache__/__init__.cpython-313.pyc"
        );
    }

    #[test]
    fn pyc_sibling_link_to_non_py_fires_on_complete_build() {
        // The chain resolves to a file the run ships, but not under
        // a `.py` name: not a shipped source.
        let d0 = tempfile::TempDir::new().expect("tmpdir");
        let d1 = tempfile::TempDir::new().expect("tmpdir");
        let d2 = tempfile::TempDir::new().expect("tmpdir");
        let src = pybc_src_pkg(&d0);
        let cand = pybc_run_pkg(
            &d1,
            "python313-caca",
            &[
                (
                    "/usr/lib/python3.13/site-packages/caca/__pycache__/__init__.cpython-313.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
                (
                    "/usr/lib/python3.13/site-packages/caca/__init__.py",
                    b"",
                    Some("../../../python3.14/site-packages/caca/__init__.txt"),
                ),
            ],
        );
        let sib = pybc_run_pkg(
            &d2,
            "python314-caca",
            &[(
                "/usr/lib/python3.14/site-packages/caca/__init__.txt",
                b"x = 1\n",
                None,
            )],
        );
        assert_eq!(run_without_source_count(&[src, cand, sib]), 1);
    }

    #[test]
    fn pyc_direct_sibling_link_credited_on_complete_build() {
        // The arcconf shape: the module itself (legacy layout) maps
        // to a source that is a direct symlink into the sibling
        // plugin package.
        let d0 = tempfile::TempDir::new().expect("tmpdir");
        let d1 = tempfile::TempDir::new().expect("tmpdir");
        let d2 = tempfile::TempDir::new().expect("tmpdir");
        let src = pybc_src_pkg(&d0);
        let cand = pybc_run_pkg(
            &d1,
            "libstoragemgmt-arcconf-plugin",
            &[
                (
                    "/usr/lib/python3.13/site-packages/arcconf_plugin/utils.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
                (
                    "/usr/lib/python3.13/site-packages/arcconf_plugin/utils.py",
                    b"",
                    Some("../hpsa_plugin/utils.py"),
                ),
            ],
        );
        let sib = pybc_run_pkg(
            &d2,
            "libstoragemgmt-hpsa-plugin",
            &[(
                "/usr/lib/python3.13/site-packages/hpsa_plugin/utils.py",
                b"x = 1\n",
                None,
            )],
        );
        assert_eq!(run_without_source_count(&[src, cand, sib]), 0);
    }

    #[test]
    fn pyc_sibling_source_fires_when_target_shipped_only_as_directory() {
        // The run credit requires a regular file: a sibling shipping
        // the resolved target only as a directory ships no source.
        let d0 = tempfile::TempDir::new().expect("tmpdir");
        let d1 = tempfile::TempDir::new().expect("tmpdir");
        let d2 = tempfile::TempDir::new().expect("tmpdir");
        let src = pybc_src_pkg(&d0);
        let cand = caca_candidate(&d1);
        let mut sib = caca_sibling(&d2);
        for f in sib.files.iter_mut() {
            if f.name.ends_with(".py") {
                f.mode = 0o040755;
            }
        }
        assert_eq!(run_without_source_count(&[src, cand, sib]), 1);
    }

    #[test]
    fn pyc_sibling_source_fires_when_target_shipped_only_as_ghost() {
        // The run credit requires a non-ghost file: a sibling shipping
        // the resolved target only as a %ghost entry ships no source.
        use crate::pkg::pkgfile::RPMFILE_GHOST;
        let d0 = tempfile::TempDir::new().expect("tmpdir");
        let d1 = tempfile::TempDir::new().expect("tmpdir");
        let d2 = tempfile::TempDir::new().expect("tmpdir");
        let src = pybc_src_pkg(&d0);
        let cand = caca_candidate(&d1);
        let mut sib = caca_sibling(&d2);
        for f in sib.files.iter_mut() {
            if f.name.ends_with(".py") {
                f.flags = RPMFILE_GHOST;
            }
        }
        assert_eq!(run_without_source_count(&[src, cand, sib]), 1);
    }

    #[test]
    fn pyc_sibling_source_fires_when_target_shipped_only_as_symlink() {
        // The run credit requires a regular file: a sibling shipping
        // the resolved target only as a further symlink ships no source.
        let d0 = tempfile::TempDir::new().expect("tmpdir");
        let d1 = tempfile::TempDir::new().expect("tmpdir");
        let d2 = tempfile::TempDir::new().expect("tmpdir");
        let src = pybc_src_pkg(&d0);
        let cand = caca_candidate(&d1);
        let sib = pybc_run_pkg(
            &d2,
            "python314-caca",
            &[(
                "/usr/lib/python3.14/site-packages/caca/__init__.py",
                b"",
                Some("/usr/lib/python3.14/site-packages/caca/__init__.py.real"),
            )],
        );
        assert_eq!(run_without_source_count(&[src, cand, sib]), 1);
    }

    #[test]
    fn pyc_sibling_source_cycle_fires_on_complete_build() {
        // The undecidable-chain pin: the mapped source symlinks in a
        // cycle inside the package, so the exit walk never steps to a
        // path no package file ships and the candidate never reaches
        // the run decision -- it fires even on a complete build, where
        // a leaving chain would be credited.
        let d0 = tempfile::TempDir::new().expect("tmpdir");
        let d1 = tempfile::TempDir::new().expect("tmpdir");
        let src = pybc_src_pkg(&d0);
        let cand = pybc_run_pkg(
            &d1,
            "python313-cyc",
            &[
                (
                    "/usr/lib/python3.13/site-packages/cyc/__pycache__/mod.cpython-313.pyc",
                    &pyc_header(3571, 0, 1000),
                    None,
                ),
                (
                    "/usr/lib/python3.13/site-packages/cyc/mod.py",
                    b"",
                    Some("mod2.py"),
                ),
                (
                    "/usr/lib/python3.13/site-packages/cyc/mod2.py",
                    b"",
                    Some("mod.py"),
                ),
            ],
        );
        assert_eq!(run_without_source_count(&[src, cand]), 1);
    }

    #[test]
    fn duplicate_executable_fires_for_two_real_executables() {
        // Drives check_binary (the real emission path): two regular executable
        // files sharing a basename across bindirs. FilesCheck.py:1171.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/mytool", 0o100755, 11),
            mkfile("/bin/mytool", 0o100755, 12),
        ]);
        let results = run_check_binary(&pkg);
        let line = results
            .iter()
            .find(|(n, _)| n == "duplicate-executable")
            .map(|(_, l)| l.clone())
            .expect("duplicate-executable should fire for two real executables");
        assert!(
            line.contains(": W: duplicate-executable mytool ['/usr/bin/mytool', '/bin/mytool']"),
            "name, level and Python-list detail must match the reference, got: {line}"
        );
    }

    #[test]
    fn bindir_exes_emit_in_package_file_order() {
        // The reference iterates its exe dict in insertion (package file)
        // order, and emission order is a contract: swapping the IndexMap for
        // a HashMap flips the order between runs (independently built maps
        // draw different hash seeds), which the re-render comparison catches.
        let render = || {
            let (pkg, _dir) = pkg_with_files(vec![
                mkfile("/usr/bin/zebra", 0o100755, 11),
                mkfile("/usr/bin/apple", 0o100755, 12),
                mkfile("/bin/mango", 0o100755, 13),
                mkfile("/usr/bin/kiwi", 0o100755, 14),
            ]);
            run_check_binary(&pkg)
                .into_iter()
                .filter(|(n, _)| n == "no-manual-page-for-binary")
                .map(|(_, line)| line.rsplit(' ').next().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        let first = render();
        assert_eq!(
            first,
            ["zebra", "apple", "mango", "kiwi"],
            "package file order, not sorted order"
        );
        assert_eq!(first, render(), "emission order must not flip between runs");
    }

    #[test]
    fn bindir_exes_emit_in_the_order_files_were_added() {
        // Insertion order, not sorted order: files added zzz, aaa, mmm.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/zzz", 0o100755, 21),
            mkfile("/usr/bin/aaa", 0o100755, 22),
            mkfile("/usr/bin/mmm", 0o100755, 23),
        ]);
        let tails: Vec<String> = run_check_binary(&pkg)
            .into_iter()
            .filter(|(n, _)| n == "no-manual-page-for-binary")
            .map(|(_, line)| line.rsplit(' ').next().unwrap().to_string())
            .collect();
        assert_eq!(
            tails,
            ["zzz", "aaa", "mmm"],
            "insertion order, not sorted order"
        );
    }

    #[test]
    fn no_manual_page_still_fires_for_duplicate_executable() {
        // FilesCheck.py:559-564 uses two independent ifs: an exe that is both
        // duplicated and man-pageless must emit both findings. Reverting to
        // `else if` drops no-manual-page-for-binary.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/mytool", 0o100755, 31),
            mkfile("/bin/mytool", 0o100755, 32),
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            results
                .iter()
                .any(|(n, d)| n == "duplicate-executable" && d.contains("mytool")),
            "duplicate-executable missing: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("mytool")),
            "no-manual-page-for-binary must fire alongside duplicate-executable: {results:?}"
        );
    }

    #[test]
    fn usr_games_symlink_registers_for_man_page_check() {
        // The reference's bin_regex covers /usr/games (FilesCheck.py:158),
        // so a symlink there must feed no-manual-page-for-binary. Reverting
        // the symlink registration to the hand-rolled
        // /bin//sbin//usr/bin//usr/sbin/ loop drops gamelink silently.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/gametool", 0o100755, 51),
            PkgFile {
                linkto: "/usr/bin/gametool".to_string(),
                ..mkfile("/usr/games/gamelink", 0o120777, 52)
            },
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("gamelink")),
            "no-manual-page-for-binary must fire for a /usr/games symlink: {results:?}"
        );
    }

    #[test]
    fn man_binary_basename_matches_reference_binary_group() {
        // The `binary` group is greedy: the split is at the last `.`
        // followed by a digit, and anything may trail the digit.
        assert_eq!(man_binary_basename("zoo.1.gz"), Some("zoo"));
        assert_eq!(man_binary_basename("fiz.1"), Some("fiz"));
        assert_eq!(man_binary_basename("foo.1x"), Some("foo"));
        assert_eq!(man_binary_basename("libfoo.3pm.gz"), Some("libfoo"));
        assert_eq!(man_binary_basename("foo.1.2.gz"), Some("foo.1"));
        // No section suffix: the reference regex does not match at all.
        assert_eq!(man_binary_basename("README"), None);
        assert_eq!(man_binary_basename("README.gz"), None);
        assert_eq!(man_binary_basename("foo.bar1"), None);
    }

    #[test]
    fn regular_file_man_page_suppresses_no_manual_page() {
        // The reference registers the `binary` group of
        // man_base_regex for regular files too
        // (_check_file_normal_file_look_for_man, FilesCheck.py:1155), so a
        // binary whose man page ships as a regular file must not warn.
        // The zoo package: /usr/bin/zoo + /usr/share/man/man1/zoo.1.gz.
        // The control binary (fiz, no man page at all) must still warn.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/zoo", 0o100755, 61),
            mkfile("/usr/bin/fiz", 0o100755, 62),
            mkfile("/usr/share/man/man1/zoo.1.gz", 0o100644, 63),
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("zoo")),
            "no-manual-page-for-binary must not fire for zoo, its man page ships as a regular file: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("fiz")),
            "no-manual-page-for-binary must still fire for fiz, which has no man page: {results:?}"
        );
    }

    #[test]
    fn no_manual_page_for_binary_is_info_level() {
        // rpmcrab#484: a missing manpage is upstream debt, so the finding
        // is demoted to Info. The level comes from the structured results,
        // not from re-parsing the rendered line.
        let (pkg, _dir) = pkg_with_files(vec![mkfile("/usr/bin/fiz", 0o100755, 62)]);
        let config = test_config();
        let mut check = FilesCheck::new(&config);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(&pkg, &config, &mut out);
        let hits: Vec<(&str, Level)> = out
            .results()
            .iter()
            .zip(out.result_levels())
            .filter(|((n, _), _)| n.as_str() == "no-manual-page-for-binary")
            .map(|((_, line), level)| (line.as_str(), *level))
            .collect();
        assert_eq!(hits.len(), 1, "exactly one finding: {hits:?}");
        assert_eq!(hits[0].1, Level::Info, "demoted level: {hits:?}");
        assert!(
            hits[0].0.contains(": I: no-manual-page-for-binary"),
            "rendered at I: {}",
            hits[0].0
        );
    }

    #[test]
    fn symlinked_man_page_suppresses_no_manual_page() {
        // The reference registers the `binary` group for
        // symlinks too (_check_file_link_man, FilesCheck.py:810), so the
        // set key is `fiz`, not the full filename `fiz.1.gz`.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/fiz", 0o100755, 71),
            mkfile("/usr/share/man/man1/zoo.1.gz", 0o100644, 72),
            PkgFile {
                linkto: "zoo.1.gz".to_string(),
                ..mkfile("/usr/share/man/man1/fiz.1.gz", 0o120777, 73)
            },
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("fiz")),
            "no-manual-page-for-binary must not fire for fiz, its man page is a symlink: {results:?}"
        );
    }

    #[test]
    fn symlink_to_documented_binary_suppresses_no_manual_page() {
        // A bindir symlink invoking a documented binary in the same
        // package is that binary under another name: the target's man
        // page documents it. The reference credits only the exe's own
        // name, so this is a ledgered divergence. The control link to
        // an undocumented binary must still fire.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/tool", 0o100755, 81),
            mkfile("/usr/share/man/man1/tool.1.gz", 0o100644, 82),
            PkgFile {
                linkto: "/usr/bin/tool".to_string(),
                ..mkfile("/usr/bin/alias", 0o120777, 83)
            },
            PkgFile {
                linkto: "tool2".to_string(),
                ..mkfile("/usr/bin/alias2", 0o120777, 84)
            },
            mkfile("/usr/bin/tool2", 0o100755, 85),
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("alias")),
            "alias invokes the documented tool and must not fire: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("alias2")),
            "alias2 invokes undocumented tool2 and must still fire: {results:?}"
        );
    }

    #[test]
    fn symlink_chain_and_external_target_for_no_manual_page() {
        // A chain of links resolves through the package; a link whose
        // target the package does not ship earns no credit.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/tool", 0o100755, 91),
            mkfile("/usr/share/man/man1/tool.1.gz", 0o100644, 92),
            PkgFile {
                linkto: "/usr/bin/mid".to_string(),
                ..mkfile("/usr/bin/alias", 0o120777, 93)
            },
            PkgFile {
                linkto: "tool".to_string(),
                ..mkfile("/usr/bin/mid", 0o120777, 94)
            },
            PkgFile {
                linkto: "/usr/bin/elsewhere".to_string(),
                ..mkfile("/usr/bin/ext", 0o120777, 95)
            },
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("alias")),
            "alias resolves through mid to the documented tool: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("ext")),
            "ext leaves the package and must still fire: {results:?}"
        );
    }

    #[test]
    fn hardlink_to_documented_binary_suppresses_no_manual_page() {
        // Two names for one inode: the documented name's page covers
        // the alias. A same-named file on a different inode is a
        // different binary and keeps firing.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/tool", 0o100755, 99),
            mkfile("/usr/share/man/man1/tool.1.gz", 0o100644, 98),
            mkfile("/usr/bin/alias", 0o100755, 99),
            mkfile("/usr/bin/other", 0o100755, 97),
            PkgFile {
                linkto: "/usr/bin/tool".to_string(),
                ..mkfile("/usr/share/man/man1/other.1.gz", 0o120777, 96)
            },
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("alias")),
            "alias is a hardlink to the documented tool: {results:?}"
        );
        // `other` has its own (symlink) page, so it is quiet either way;
        // the pin is on alias only.
        let (pkg2, _dir2) = pkg_with_files(vec![
            mkfile("/usr/bin/tool", 0o100755, 99),
            mkfile("/usr/share/man/man1/tool.1.gz", 0o100644, 98),
            mkfile("/usr/bin/alias", 0o100755, 100),
        ]);
        let results2 = run_check_binary(&pkg2);
        assert!(
            results2
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("alias")),
            "a different inode is a different binary and must fire: {results2:?}"
        );
    }

    #[test]
    fn alias_symlink_loop_keeps_firing() {
        // A two-link loop never resolves, so the undocumented name
        // earns no alias credit even though its loop partner's
        // basename carries a man page (loopb itself is documented
        // directly and is not the discriminator).
        let (pkg, _dir) = pkg_with_files(vec![
            PkgFile {
                linkto: "loopb".to_string(),
                ..mkfile("/usr/bin/loopa", 0o120777, 51)
            },
            PkgFile {
                linkto: "loopa".to_string(),
                ..mkfile("/usr/bin/loopb", 0o120777, 52)
            },
            mkfile("/usr/share/man/man1/loopb.1.gz", 0o100644, 53),
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("loopa")),
            "loopa must still fire: {results:?}"
        );
    }

    #[test]
    fn alias_symlink_chain_length_limit() {
        // A short chain to a documented target earns the credit; a
        // chain past the 40-hop cap earns none and keeps firing.
        let build = |links: usize| {
            let mut files: Vec<PkgFile> = Vec::new();
            for i in 0..links {
                let next = if i + 1 == links {
                    "realtool".to_string()
                } else {
                    format!("hop{}", i + 1)
                };
                files.push(PkgFile {
                    linkto: next,
                    ..mkfile(&format!("/usr/bin/hop{i}"), 0o120777, 100 + i as u32)
                });
            }
            files.push(mkfile("/usr/bin/realtool", 0o100755, 200));
            files.push(mkfile("/usr/share/man/man1/realtool.1.gz", 0o100644, 201));
            files
        };
        let (pkg, _dir) = pkg_with_files(build(10));
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("hop0")),
            "a 10-hop chain resolves: {results:?}"
        );
        let (pkg, _dir) = pkg_with_files(build(41));
        let results = run_check_binary(&pkg);
        assert!(
            results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("hop0")),
            "a 41-hop chain is over the cap and must fire: {results:?}"
        );
    }

    #[test]
    fn alias_symlink_root_level_intermediate_resolves() {
        // The chain passes through a root-level link whose target is
        // spelled relative to the root: the join must not produce a
        // `//` path that no shipped path equals.
        let (pkg, _dir) = pkg_with_files(vec![
            PkgFile {
                linkto: "/toplink".to_string(),
                ..mkfile("/usr/bin/viaalias", 0o120777, 61)
            },
            PkgFile {
                linkto: "usr/bin/realtool".to_string(),
                ..mkfile("/toplink", 0o120777, 62)
            },
            mkfile("/usr/bin/realtool", 0o100755, 63),
            mkfile("/usr/share/man/man1/realtool.1.gz", 0o100644, 64),
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("viaalias")),
            "viaalias resolves through the root-level link: {results:?}"
        );
    }

    #[test]
    fn alias_unknown_inode_earns_no_hardlink_credit() {
        // Both files carry inode 0 (unknown): no hardlink identity
        // is registered on either side, so the documented sibling
        // does not credit the undocumented name.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/zeroexe", 0o100755, 0),
            mkfile("/usr/bin/zerodoc", 0o100755, 0),
            mkfile("/usr/share/man/man1/zerodoc.1.gz", 0o100644, 72),
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("zeroexe")),
            "zeroexe must still fire: {results:?}"
        );
    }

    #[test]
    fn version_affix_name_forms_for_no_manual_page() {
        // Flavour-suffixed page: the Python singlespec shape -- the
        // generic name is an alternatives link, the shipped page is
        // named <tool>-<flavour version>.
        let (pkg, _dir) = pkg_with_files(vec![
            PkgFile {
                linkto: "/usr/bin/alts".to_string(),
                ..mkfile("/usr/bin/abimap", 0o120777, 11)
            },
            mkfile("/usr/share/man/man1/abimap-3.13.1.gz", 0o100644, 12),
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with("abimap")),
            "abimap is documented by its flavour page: {results:?}"
        );
        // Version-suffixed binary: the real binary carries the
        // version, the page the plain name.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/luajit-2.1.1756211046", 0o100755, 13),
            mkfile("/usr/share/man/man1/luajit.1.gz", 0o100644, 14),
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "no-manual-page-for-binary"),
            "luajit-2.1.1756211046 is documented by luajit.1: {results:?}"
        );
    }

    #[test]
    fn version_affix_dot_and_separatorless_forms_for_no_manual_page() {
        // Binary side, dot separator: cups-genppd.5.3 is documented
        // by cups-genppd.1.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/cups-genppd.5.3", 0o100755, 31),
            mkfile("/usr/share/man/man1/cups-genppd.1.gz", 0o100644, 32),
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "no-manual-page-for-binary"),
            "cups-genppd.5.3 is documented by cups-genppd.1: {results:?}"
        );
        // Binary side, separatorless: perl5.44.0 is documented by
        // perl.1.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/perl5.44.0", 0o100755, 33),
            mkfile("/usr/share/man/man1/perl.1.gz", 0o100644, 34),
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "no-manual-page-for-binary"),
            "perl5.44.0 is documented by perl.1: {results:?}"
        );
        // Man side positive: bar is documented by the bar-1.2 page
        // (shipped as bar-1.2.1, whose man basename is bar-1.2).
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/bar", 0o100755, 35),
            mkfile("/usr/share/man/man1/bar-1.2.1.gz", 0o100644, 36),
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "no-manual-page-for-binary"),
            "bar is documented by its bar-1.2 page: {results:?}"
        );
        // Single-suffix misses keep firing end to end.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/stunnel3", 0o100755, 37),
            mkfile("/usr/share/man/man1/stunnel.1.gz", 0o100644, 38),
            mkfile("/usr/bin/foo-2", 0o100755, 39),
            mkfile("/usr/share/man/man1/foo.1.gz", 0o100644, 40),
        ]);
        let results = run_check_binary(&pkg);
        for exe in ["stunnel3", "foo-2"] {
            assert!(
                results
                    .iter()
                    .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with(exe)),
                "{exe} must still fire: {results:?}"
            );
        }
    }

    #[test]
    fn version_affix_near_misses_still_fire_for_no_manual_page() {
        // A single trailing component is a name suffix, not a
        // version: ps2ps2 is a distinct tool from ps2ps, and a
        // hypothetical foo-2 page does not document foo.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/ps2ps2", 0o100755, 21),
            mkfile("/usr/share/man/man1/ps2ps.1.gz", 0o100644, 22),
            mkfile("/usr/bin/foo", 0o100755, 23),
            mkfile("/usr/share/man/man1/foo-2.1.gz", 0o100644, 24),
            mkfile("/usr/bin/bar-1.2", 0o100755, 25),
            mkfile("/usr/share/man/man1/baz.1.gz", 0o100644, 26),
        ]);
        let results = run_check_binary(&pkg);
        for exe in ["ps2ps2", "foo", "bar-1.2"] {
            assert!(
                results
                    .iter()
                    .any(|(n, d)| n == "no-manual-page-for-binary" && d.ends_with(exe)),
                "{exe} must still fire: {results:?}"
            );
        }
    }

    #[test]
    fn version_tail_grammar() {
        assert!(is_version_tail("3.13"));
        assert!(is_version_tail("2.1.1756211046"));
        assert!(!is_version_tail("2"));
        assert!(!is_version_tail("64"));
        assert!(!is_version_tail("1.2a"));
        assert!(!is_version_tail(""));
        assert!(!is_version_tail("1."));
        assert_eq!(strip_version_tail("luajit-2.1.1756211046"), Some("luajit"));
        assert_eq!(strip_version_tail("perl5.44.0"), Some("perl"));
        assert_eq!(strip_version_tail("cups-genppd.5.3"), Some("cups-genppd"));
        assert_eq!(strip_version_tail("ps2ps2"), None);
        assert_eq!(strip_version_tail("gio-querymodules-64"), None);
        assert_eq!(strip_version_tail("plain"), None);
        // Single-suffix shapes: one trailing component is a name
        // suffix, not a version.
        assert_eq!(strip_version_tail("stunnel3"), None);
        assert_eq!(strip_version_tail("foo-2"), None);
        // A non-ASCII char directly before the digit/dot run: the
        // byte-computed split must fail closed or land on a
        // boundary, never panic.
        assert_eq!(strip_version_tail("foo\u{e9}5.44.0"), Some("foo\u{e9}"));
    }

    #[test]
    fn duplicate_executable_uses_python_repr_for_quoted_paths() {
        // filter.py renders the paths list with Python repr: a path containing
        // `'` switches the whole string to double quotes.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/it's", 0o100755, 41),
            mkfile("/bin/it's", 0o100755, 42),
        ]);
        let line = run_check_binary(&pkg)
            .into_iter()
            .find(|(n, _)| n == "duplicate-executable")
            .map(|(_, l)| l)
            .expect("duplicate-executable should fire");
        assert!(
            line.contains(r#"["/usr/bin/it's", "/bin/it's"]"#),
            "Python repr expected, got: {line}"
        );
    }

    #[test]
    fn duplicate_executable_escapes_backslash_in_python_repr() {
        // Python repr escapes backslashes; the old hand-rolled '{p}' did not.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/bs\\x", 0o100755, 43),
            mkfile("/bin/bs\\x", 0o100755, 44),
        ]);
        let line = run_check_binary(&pkg)
            .into_iter()
            .find(|(n, _)| n == "duplicate-executable")
            .map(|(_, l)| l)
            .expect("duplicate-executable should fire");
        assert!(
            line.contains(r"['/usr/bin/bs\\x', '/bin/bs\\x']"),
            "escaped backslashes expected, got: {line}"
        );
    }

    #[test]
    fn duplicate_executable_does_not_fire_for_symlink_pair() {
        // The reference deliberately excludes symlinks from the duplicate
        // binary check (FilesCheck.py:499-500): a real exec plus a symlink
        // sharing a basename must NOT fire duplicate-executable.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/mytool", 0o100755, 21),
            PkgFile {
                linkto: "/usr/bin/mytool".to_string(),
                ..mkfile("/bin/mytool", 0o120777, 22)
            },
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results.iter().any(|(n, _)| n == "duplicate-executable"),
            "duplicate-executable must not fire for a symlink pair, got: {results:?}"
        );
    }

    /// Negative pin for the removed `cross-directory-hard-link`
    /// finding: two files sharing (rdev, inode) in different
    /// directories stay silent.
    #[test]
    fn killed_cross_directory_hard_link_stays_absent() {
        let (pkg, _dir) = pkg_with_files(vec![
            PkgFile {
                rdev: 7,
                inode: 99,
                ..mkfile("/usr/lib/mydata", 0o100644, 31)
            },
            PkgFile {
                rdev: 7,
                inode: 99,
                ..mkfile("/etc/mydata", 0o100644, 32)
            },
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "cross-directory-hard-link"),
            "must stay silent: {results:?}"
        );
    }

    /// Negative pins for the removed permission findings: setuid,
    /// setgid, non-standard executable and directory permissions and
    /// non-readable files all stay silent.
    #[test]
    fn killed_permission_findings_stay_absent() {
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/bin/suidtool", 0o104755, 41),
            mkfile("/usr/bin/sgidtool", 0o102755, 42),
            mkfile("/usr/bin/exec700", 0o100700, 43),
            mkfile("/usr/share/secret", 0o100000, 44),
            mkfile("/usr/share/odd-dir", 0o40770, 45),
        ]);
        let results = run_check_binary(&pkg);
        for name in [
            "setuid-binary",
            "setgid-binary",
            "non-standard-executable-perm",
            "non-standard-dir-perm",
            "non-readable",
        ] {
            assert!(
                !results.iter().any(|(n, _)| n == name),
                "{name} must stay silent: {results:?}"
            );
        }
    }

    fn mkfile(name: &str, mode: u32, inode: u32) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            mode,
            user: "root".to_string(),
            group: "root".to_string(),
            rdev: 1,
            inode,
            ..Default::default()
        }
    }

    #[test]
    fn ldconfig_uses_anchored_lib_regex() {
        // Benchmark found: `.../libbasegfxlo.so-gdb.py` triggered
        // library-without-ldconfig because files.rs used
        // `fname.contains(".so")`. The reference gates on the anchored
        // lib_regex. Drive through check_binary: a .so-gdb.py file must NOT
        // emit the finding, while a real .so file without ldconfig MUST.
        let config = test_config();
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        // Header only, no extraction: `files` is overwritten wholesale below.
        let mut pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture");
        pkg.files = vec![
            PkgFile {
                name: "/usr/lib64/libfoo.so-gdb.py".to_string(),
                path: "/usr/lib64/libfoo.so-gdb.py".to_string(),
                mode: 0o100644,
                size: Some(100),
                ..Default::default()
            },
            PkgFile {
                name: "/usr/lib64/libfoo.so.1.2.3".to_string(),
                path: "/usr/lib64/libfoo.so.1.2.3".to_string(),
                mode: 0o100755,
                size: Some(100),
                ..Default::default()
            },
        ];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let results: Vec<(String, String)> = out
            .results()
            .iter()
            .map(|(n, d)| (n.clone(), d.clone()))
            .collect();
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "library-without-ldconfig-postin" && d.contains("so-gdb.py")),
            "false positive on .so-gdb.py: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|(n, d)| n == "library-without-ldconfig-postin"
                    && d.contains(": E: library-without-ldconfig-postin")
                    && d.contains("libfoo.so.1.2.3")),
            "missing E-level finding on real .so: {results:?}"
        );
    }

    #[test]
    fn ldconfig_missing_scriptlet_vs_ldconfig_less() {
        // Reference parity (FilesCheck._check_file_normal_file_lib): a
        // missing %postin emits library-without-ldconfig-postin, while a
        // present-but-ldconfig-less %postin emits postin-without-ldconfig.
        // Emitting both was a port bug (#375).
        let config = test_config();
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture");
        let pkgfile = PkgFile {
            name: "/usr/lib64/libfoo.so.1.2.3".to_string(),
            path: "/usr/lib64/libfoo.so.1.2.3".to_string(),
            mode: 0o100755,
            size: Some(100),
            ..Default::default()
        };
        let check = FilesCheck::new(&config);
        let run = |postin: &str, postun: &str| {
            let st = PkgState {
                postin: postin.to_string(),
                postun: postun.to_string(),
                ..Default::default()
            };
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_ldconfig(&pkg, "/usr/lib64/libfoo.so.1.2.3", &pkgfile, &st, &mut out);
            out.results().to_vec()
        };
        // Pin name, level and detail explicitly: exactly the two expected
        // Error lines, each naming the library file.
        let pin = |results: &[(String, String)], expected: &[&str]| {
            assert_eq!(results.len(), 2, "expected exactly 2 findings: {results:?}");
            for (name, line) in results {
                assert!(
                    expected.contains(&name.as_str()),
                    "unexpected finding {name}: {results:?}"
                );
                assert!(
                    line.contains(": E: "),
                    "finding {name} must be Error level: {line:?}"
                );
                assert!(
                    line.contains("/usr/lib64/libfoo.so.1.2.3"),
                    "finding {name} must name the file: {line:?}"
                );
            }
        };
        // No scriptlets at all: library-without-ldconfig-* only.
        pin(
            &run("", ""),
            &[
                "library-without-ldconfig-postin",
                "library-without-ldconfig-postun",
            ],
        );
        // Scriptlets present but ldconfig-less: postin/postun-without-ldconfig only.
        pin(
            &run("echo hi", "echo hi"),
            &["postin-without-ldconfig", "postun-without-ldconfig"],
        );
        // ldconfig present: silence.
        let results = run("/sbin/ldconfig", "/sbin/ldconfig");
        assert!(results.is_empty(), "unexpected findings: {results:?}");
    }

    #[test]
    fn ldconfig_private_subtree_is_quiet() {
        // Issue #569: ldconfig never scans private subtrees, so a library
        // there must not draw the scriptlet demand. GHC's
        // /usr/lib64/ghc-<ver>/lib tree (registered via ghc-pkg) is the
        // measured pile: 193 of the 195 private-subdir lines on Factory.
        let config = test_config();
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture");
        let check = FilesCheck::new(&config);
        let st = PkgState::default();
        for fname in [
            "/usr/lib64/ghc-9.12.4/lib/libHSpolyparse-1.13.1-1Na5SdBty6sEY6bGCl8BU7-ghc9.12.4.so",
            "/usr/lib64/polymake-4.15/lib/libpolymake-apps.so.4.15",
            "/opt/vendor/lib/libvendor.so.2",
        ] {
            let pkgfile = PkgFile {
                name: fname.to_string(),
                path: fname.to_string(),
                mode: 0o100755,
                size: Some(100),
                ..Default::default()
            };
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_ldconfig(&pkg, fname, &pkgfile, &st, &mut out);
            assert!(
                out.results().is_empty(),
                "private-subtree library must stay quiet: {fname}: {:?}",
                out.results()
            );
        }
    }

    #[test]
    fn ldconfig_standard_libdirs_still_fire() {
        // Issue #569: the gate keeps the genuine class -- a library
        // directly in a standard libdir with no scriptlet still fires
        // (powercap's /usr/lib64/libpowercap.so.0.6.0 is the archetype).
        // /usr/local/lib{,64} are standard libdirs too: stock glibc's
        // /etc/ld.so.conf names them explicitly, so a library shipped
        // there without scriptlets is a genuine miss, not a private
        // subtree (PR #570 review).
        let config = test_config();
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture");
        let check = FilesCheck::new(&config);
        let st = PkgState::default();
        for fname in [
            "/lib/libfoo.so.1",
            "/lib64/libfoo.so.1",
            "/usr/lib/libfoo.so.1",
            "/usr/lib64/libpowercap.so.0.6.0",
            "/usr/local/lib/libfoo.so.1",
            "/usr/local/lib64/libfoo.so.1",
        ] {
            let pkgfile = PkgFile {
                name: fname.to_string(),
                path: fname.to_string(),
                mode: 0o100755,
                size: Some(100),
                ..Default::default()
            };
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_ldconfig(&pkg, fname, &pkgfile, &st, &mut out);
            let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(
                names,
                [
                    "library-without-ldconfig-postin",
                    "library-without-ldconfig-postun"
                ],
                "standard libdir {fname} must still fire: {:?}",
                out.results()
            );
        }
    }

    #[test]
    fn ldconfig_conf_registered_dir_still_fires() {
        // Issue #569: a private directory the package itself registers in
        // /etc/ld.so.conf.d is ldconfig-managed, so the scriptlet test
        // applies there in both its shapes (missing scriptlet and
        // ldconfig-less scriptlet); outside the registered set the same
        // library stays quiet.
        let config = test_config();
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture");
        let check = FilesCheck::new(&config);
        let fname = "/usr/lib64/foo/lib/libfoo.so.1";
        let pkgfile = PkgFile {
            name: fname.to_string(),
            path: fname.to_string(),
            mode: 0o100755,
            size: Some(100),
            ..Default::default()
        };
        let mut dirs = std::collections::HashSet::new();
        dirs.insert("/usr/lib64/foo/lib".to_string());
        let run = |postin: &str, postun: &str| {
            let st = PkgState {
                postin: postin.to_string(),
                postun: postun.to_string(),
                ldconfig_dirs: dirs.clone(),
                ..Default::default()
            };
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_ldconfig(&pkg, fname, &pkgfile, &st, &mut out);
            out.results().to_vec()
        };
        let results = run("", "");
        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "library-without-ldconfig-postin",
                "library-without-ldconfig-postun"
            ],
            "conf-registered dir with no scriptlets"
        );
        let results = run("echo hi", "echo hi");
        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            ["postin-without-ldconfig", "postun-without-ldconfig"],
            "conf-registered dir with ldconfig-less scriptlets"
        );
        let st = PkgState::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_ldconfig(&pkg, fname, &pkgfile, &st, &mut out);
        assert!(
            out.results().is_empty(),
            "unregistered private dir must stay quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn ldso_conf_parsing_collects_only_directory_entries() {
        // Issue #569: comments, include directives and relative entries
        // name no directory; trailing slashes normalise away.
        let mut dirs = std::collections::HashSet::new();
        parse_ldso_conf(
            "# comment\n/usr/lib64/foo\ninclude /etc/ld.so.conf.d/*.conf\n\n/opt/bar/  # trailing comment\nrelative/dir\nhwcap 1 nosegneg\n",
            &mut dirs,
        );
        let expected: std::collections::HashSet<String> =
            ["/usr/lib64/foo".to_string(), "/opt/bar".to_string()]
                .into_iter()
                .collect();
        assert_eq!(dirs, expected);
    }

    #[test]
    fn ldconfig_conf_snippet_wires_through_check_binary() {
        // Issue #569: the conf-snippet collection runs at package level,
        // so through check_binary a library in a snippet-registered
        // private dir fires while a GHC-tree library in the same package
        // stays quiet. The snippet is materialised in the extract dir,
        // where read_file resolves it.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = Pkg::open(
            std::path::Path::new(&fixture_path("fcprobe-1-1.noarch.rpm")),
            dir.path(),
            true,
        )
        .expect("open fixture");
        // Extraction lands in a per-package subdir of the extract dir;
        // read_file resolves against it.
        let conf_dir = pkg
            .extracted_dir()
            .expect("extracted fixture")
            .join("etc/ld.so.conf.d");
        std::fs::create_dir_all(&conf_dir).expect("mkdir conf.d");
        std::fs::write(conf_dir.join("foo.conf"), "/usr/lib64/foo/lib\n").expect("write conf");
        pkg.files = vec![
            mkfile("/etc/ld.so.conf.d/foo.conf", 0o100644, 91),
            mkfile("/usr/lib64/foo/lib/libfoo.so.1", 0o100755, 92),
            mkfile(
                "/usr/lib64/ghc-9.12.4/lib/libHSbar-1.0-ghc9.12.4.so",
                0o100755,
                93,
            ),
        ];
        let results = run_check_binary(&pkg);
        assert!(
            results
                .iter()
                .any(|(n, d)| n == "library-without-ldconfig-postin"
                    && d.contains("/usr/lib64/foo/lib/libfoo.so.1")),
            "conf-registered private dir must fire: {results:?}"
        );
        assert!(
            !results
                .iter()
                .any(|(n, d)| n.contains("ldconfig") && d.contains("ghc-9.12.4")),
            "GHC private tree must stay quiet: {results:?}"
        );
    }

    #[test]
    fn devel_link_uses_anchored_sofile_regex() {
        // Log diff on FastCGI: crab flagged /usr/lib64/libfcgi.so.0 ->
        // libfcgi.so.0.0.0 as devel-file-in-non-devel-package, but the
        // reference does not. The reference gates on the anchored
        // sofile_regex (FilesCheck.py:165, _check_file_link_devel), so only
        // the unversioned development symlink (libfoo.so) triggers -- not
        // versioned libfoo.so.0 / libfoo.so.0.0.0 links, and not a
        // libbar.so.bak backup (the regex is end-anchored).
        let (pkg, _dir) = pkg_with_files(vec![
            PkgFile {
                linkto: "libfcgi.so.0.0.0".to_string(),
                ..mkfile("/usr/lib64/libfcgi.so.0", 0o120777, 61)
            },
            PkgFile {
                linkto: "libbar.so.1".to_string(),
                ..mkfile("/usr/lib64/libbar.so.bak", 0o120777, 63)
            },
            PkgFile {
                linkto: "libfoo.so.1.2.3".to_string(),
                ..mkfile("/usr/lib64/libfoo.so", 0o120777, 62)
            },
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "devel-file-in-non-devel-package" && d.contains("libfcgi.so.0")),
            "false positive on versioned .so link: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|(n, d)| n == "devel-file-in-non-devel-package"
                    && d.contains("/usr/lib64/libfoo.so")),
            "missing finding on unversioned .so link: {results:?}"
        );
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "devel-file-in-non-devel-package" && d.contains("libbar.so.bak")),
            "false positive on .so.bak backup: {results:?}"
        );
        let lines: Vec<&String> = results
            .iter()
            .filter(|(n, _)| n == "devel-file-in-non-devel-package")
            .map(|(_, l)| l)
            .collect();
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0].contains(": W: devel-file-in-non-devel-package /usr/lib64/libfoo.so"),
            "name, level and detail: {}",
            lines[0]
        );
    }

    #[test]
    fn devel_file_in_non_devel_package_fires_for_normal_files() {
        // Mass-build audit: the reference warns on .h/.a/.pc files in
        // non-devel packages, but the normal-file half of the check
        // (_check_file_normal_file_devel) was never ported, so rpmcrab
        // stayed silent. Drive through check_binary.
        let (mut pkg, dir) = pkg_with_files(vec![
            PkgFile {
                ..mkfile("/usr/include/foo.h", 0o100644, 71)
            },
            PkgFile {
                ..mkfile("/usr/lib64/libfoo.a", 0o100644, 72)
            },
            PkgFile {
                ..mkfile("/usr/bin/foo", 0o100755, 73)
            },
        ]);
        // .pc files only count when the file is text: materialize one so
        // fd.is_buildconfig is true, mirroring the reference's peek.
        let pc_path = dir.path().join("foo.pc");
        std::fs::write(
            &pc_path,
            "prefix=/usr
",
        )
        .expect("write pc fixture");
        pkg.files.push(PkgFile {
            path: pc_path.to_string_lossy().into_owned(),
            ..mkfile("/usr/lib64/pkgconfig/foo.pc", 0o100644, 74)
        });
        let results = run_check_binary(&pkg);
        for f in [
            "/usr/include/foo.h",
            "/usr/lib64/libfoo.a",
            "/usr/lib64/pkgconfig/foo.pc",
        ] {
            assert!(
                results
                    .iter()
                    .any(|(n, d)| n == "devel-file-in-non-devel-package" && d.contains(f)),
                "missing finding for {f}: {results:?}"
            );
        }
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "devel-file-in-non-devel-package" && d.contains("/usr/bin/foo")),
            "false positive on regular file: {results:?}"
        );
        let lines: Vec<&String> = results
            .iter()
            .filter(|(n, _)| n == "devel-file-in-non-devel-package")
            .map(|(_, l)| l)
            .collect();
        assert_eq!(lines.len(), 3, "unexpected: {results:?}");
        for line in &lines {
            assert!(
                line.contains(": W: devel-file-in-non-devel-package"),
                "level: {line}"
            );
        }
    }

    /// Build a package whose files have real on-disk content, so the
    /// buildconfig peek and grep run for real: reads resolve against the
    /// extraction dir (peek via PkgFile.path, grep via dir_name), so the
    /// payload is materialized there (mirrors spurious_exec_pkg).
    fn buildconfig_pkg(dir: &tempfile::TempDir, files: &[(&str, u32, &str)]) -> Pkg {
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        pkg.name = "buildconfig-test".to_string();
        let base = pkg.dir_name().to_path_buf();
        pkg.files = files
            .iter()
            .enumerate()
            .map(|(i, (name, mode, content))| {
                let path = base.join(name.trim_start_matches('/'));
                std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
                std::fs::write(&path, content).expect("write temp file");
                PkgFile {
                    path: path.to_string_lossy().into_owned(),
                    ..mkfile(name, *mode, 200 + i as u32)
                }
            })
            .collect();
        pkg
    }

    fn rpath_findings(results: &[(String, String)]) -> Vec<&(String, String)> {
        results
            .iter()
            .filter(|(n, _)| n == "rpath-in-buildconfig")
            .collect()
    }

    #[test]
    fn rpath_in_buildconfig_fires_on_emitted_rpath_forms() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = buildconfig_pkg(
            &dir,
            &[
                (
                    "/usr/lib64/pkgconfig/wl.pc",
                    0o100644,
                    "Libs: -L${libdir} -Wl,-rpath,${libdir} -lfoo\n",
                ),
                (
                    "/usr/bin/plain-config",
                    0o100755,
                    "APR_LIB_TARGET=\"-rpath $(libdir) $(OBJECTS)\"\n",
                ),
                (
                    "/usr/lib64/pkgconfig/cap-r.pc",
                    0o100644,
                    "Libs: -Wl,-R/usr/lib64/foo -lfoo\n",
                ),
                (
                    "/usr/lib64/pkgconfig/joined.pc",
                    0o100644,
                    "Libs: -rpath=/usr/lib64 -lfoo\n",
                ),
                (
                    "/usr/lib64/pkgconfig/longflag.pc",
                    0o100644,
                    "Libs: -Wl,--rpath,/usr/lib64 -lfoo\n",
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        let hits = rpath_findings(&results);
        assert_eq!(hits.len(), 5, "unexpected: {results:?}");
    }

    #[test]
    fn rpath_in_buildconfig_ignores_rpath_link() {
        // -rpath-link is the link editor's link-time search path for
        // secondary dependencies; it is never recorded in the output, so
        // no rpath is introduced into dependent packages. A token that
        // merely continues as the `-link` prefix (`-rpath-linkfoo`) is
        // quiet for the same reason.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = buildconfig_pkg(
            &dir,
            &[
                (
                    "/usr/bin/linkonly-config",
                    0o100755,
                    "libdirs=\"-Wl,-rpath-link,$libdir -L$libdir\"\n",
                ),
                (
                    "/usr/lib64/pkgconfig/linkonly.pc",
                    0o100644,
                    "Libs: -rpath-link /usr/lib64 -lfoo\n",
                ),
                (
                    "/usr/lib64/pkgconfig/linkfoo.pc",
                    0o100644,
                    "Libs: -rpath-linkfoo /usr/lib64 -lfoo\n",
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        assert!(
            rpath_findings(&results).is_empty(),
            "false positive on -rpath-link: {results:?}"
        );
    }

    #[test]
    fn rpath_in_buildconfig_ignores_configure_option_tokens() {
        // '--disable-rpath' / '--enable-rpath' in a recorded configure
        // command line are option names, not linker flags.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = buildconfig_pkg(
            &dir,
            &[(
                "/usr/bin/opts-config",
                0o100755,
                "configure_options=\" '--prefix=/usr' '--disable-rpath' '--enable-rpath'\"\n",
            )],
        );
        let results = run_check_binary(&pkg);
        assert!(
            rpath_findings(&results).is_empty(),
            "false positive on configure-option tokens: {results:?}"
        );
    }

    #[test]
    fn rpath_in_buildconfig_reports_first_qualifying_line() {
        // Non-qualifying matches do not stop the scan: the reported line
        // is the first line carrying an actual rpath directive.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = buildconfig_pkg(
            &dir,
            &[(
                "/usr/bin/mixed-config",
                0o100755,
                "libdirs=\"-Wl,-rpath-link,$libdir\"\n# built with --disable-rpath\nlibs=\"-Wl,-rpath,/usr/lib64\"\n",
            )],
        );
        let results = run_check_binary(&pkg);
        let hits = rpath_findings(&results);
        assert_eq!(hits.len(), 1, "unexpected: {results:?}");
        assert!(
            hits[0].1.contains("lines 3"),
            "first qualifying line: {hits:?}"
        );
    }

    #[test]
    fn rpath_in_buildconfig_glued_token_stays_quiet() {
        // Parity boundary kept: '-rpath' glued to a following word
        // character is not a flag token under either pattern.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = buildconfig_pkg(
            &dir,
            &[(
                "/usr/lib64/pkgconfig/glued.pc",
                0o100644,
                "Libs: -rpathfoo -lfoo\n",
            )],
        );
        let results = run_check_binary(&pkg);
        assert!(
            rpath_findings(&results).is_empty(),
            "unexpected firing on glued token: {results:?}"
        );
    }

    #[test]
    fn devel_file_quiet_in_flavoured_devel_package() {
        // A devel keyword as a hyphen-delimited name component marks
        // a flavoured devel package: `libstdc++6-devel-gcc7` ships
        // the gcc7 libstdc++ headers and `ruby4.0-devel-extra` the
        // ruby devel extras; neither is a non-devel package stranding
        // devel files. The same component test TagsCheck applies to
        // its dependency findings.
        for name in [
            "libstdc++6-devel-gcc7",
            "ruby4.0-devel-extra",
            "foo-devel-32bit",
        ] {
            let (mut pkg, _dir) = pkg_with_files(vec![PkgFile {
                ..mkfile("/usr/include/foo.h", 0o100644, 77)
            }]);
            pkg.name = name.to_string();
            let results = run_check_binary(&pkg);
            assert!(
                !results
                    .iter()
                    .any(|(n, _)| n == "devel-file-in-non-devel-package"),
                "false positive in flavoured devel package {name}: {results:?}"
            );
        }
        // Near misses: the keyword must be a whole hyphen-delimited
        // component -- a name merely containing the letters stays a
        // non-devel package and keeps firing.
        for name in ["foo-development", "foodevel-bar"] {
            let (mut pkg, _dir) = pkg_with_files(vec![PkgFile {
                ..mkfile("/usr/include/foo.h", 0o100644, 78)
            }]);
            pkg.name = name.to_string();
            let results = run_check_binary(&pkg);
            assert!(
                results
                    .iter()
                    .any(|(n, _)| n == "devel-file-in-non-devel-package"),
                "genuine finding lost for {name}: {results:?}"
            );
        }
    }

    #[test]
    fn devel_file_quiet_in_src_named_package() {
        // A final -src/-sources component declares a source package
        // (rust1.98-src, erlang27-src, sdcc-libc-sources): its headers
        // and sources are the product, not devel files stranded in a
        // non-devel package.
        for name in ["rust1.98-src", "erlang27-src", "sdcc-libc-sources"] {
            let (mut pkg, _dir) = pkg_with_files(vec![PkgFile {
                ..mkfile("/usr/include/foo.h", 0o100644, 79)
            }]);
            pkg.name = name.to_string();
            let results = run_check_binary(&pkg);
            assert!(
                !results
                    .iter()
                    .any(|(n, _)| n == "devel-file-in-non-devel-package"),
                "false positive in source package {name}: {results:?}"
            );
        }
        // Near misses: the component must be exactly src/sources at
        // the end of the name.
        for name in ["foo-srcx", "foo-resources", "srcfoo"] {
            let (mut pkg, _dir) = pkg_with_files(vec![PkgFile {
                ..mkfile("/usr/include/foo.h", 0o100644, 80)
            }]);
            pkg.name = name.to_string();
            let results = run_check_binary(&pkg);
            assert!(
                results
                    .iter()
                    .any(|(n, _)| n == "devel-file-in-non-devel-package"),
                "genuine finding lost for {name}: {results:?}"
            );
        }
    }

    #[test]
    fn devel_file_src_credit_unified_grammar_1173() {
        // The unified source-component grammar (issue #1173): the
        // final component src/source/sources credits in any case,
        // and a bare name is its own final component.
        for name in ["foo-SRC", "foo-Sources", "foo-Source", "src", "sources"] {
            let (mut pkg, _dir) = pkg_with_files(vec![PkgFile {
                ..mkfile("/usr/include/foo.h", 0o100644, 82)
            }]);
            pkg.name = name.to_string();
            let results = run_check_binary(&pkg);
            assert!(
                !results
                    .iter()
                    .any(|(n, _)| n == "devel-file-in-non-devel-package"),
                "false positive in source package {name}: {results:?}"
            );
        }
        // The boundary pins, re-derived from the unified grammar:
        // an infix source component and a fused or near-miss final
        // component carry no credit, so the finding still fires.
        for name in ["foo-src-bar", "foo-resource", "resources", "foo-sourcesx"] {
            let (mut pkg, _dir) = pkg_with_files(vec![PkgFile {
                ..mkfile("/usr/include/foo.h", 0o100644, 83)
            }]);
            pkg.name = name.to_string();
            let results = run_check_binary(&pkg);
            assert!(
                results
                    .iter()
                    .any(|(n, _)| n == "devel-file-in-non-devel-package"),
                "genuine finding lost for {name}: {results:?}"
            );
        }
        // Item 1: the credit reaches Provides names too -- a package
        // providing a source-component name is a source package.
        for provide in ["foo-src", "bar-SOURCES"] {
            let (mut pkg, _dir) = pkg_with_files(vec![PkgFile {
                ..mkfile("/usr/include/foo.h", 0o100644, 84)
            }]);
            pkg.name = "foo".to_string();
            pkg.provides = vec![dep_named(provide)];
            let results = run_check_binary(&pkg);
            assert!(
                !results
                    .iter()
                    .any(|(n, _)| n == "devel-file-in-non-devel-package"),
                "false positive via provide {provide}: {results:?}"
            );
        }
    }

    #[test]
    fn script_source_gate_unified_grammar_1173() {
        // The script gate reads the same grammar: `sources` credits
        // now, case-insensitively, bare names included.
        let path = "/usr/share/foo/run.py";
        assert!(script_is_source_data("foo-sources", path));
        assert!(script_is_source_data("foo-SRC", path));
        assert!(script_is_source_data("sources", path));
        // Infix and fused components carry no fact on either check.
        assert!(!script_is_source_data("foo-src-bar", path));
        assert!(!script_is_source_data("resource", path));
        assert!(!script_is_source_data("my-source-tools", path));
        // The entry-point bound is unchanged.
        assert!(!script_is_source_data("foo-src", "/usr/bin/run.py"));
    }

    #[test]
    fn devel_component_credit_is_devel_only() {
        // The credit is scoped to the -devel- component: a -debug-
        // component names a debug flavour of a runtime package
        // (dapl-debug-libs), not a devel package -- its headers keep
        // firing devel-file, and its versioned runtime library does
        // not trip the inverse finding.
        let (mut pkg, _dir) = pkg_with_files(vec![PkgFile {
            ..mkfile("/usr/include/foo.h", 0o100644, 81)
        }]);
        pkg.name = "dapl-debug-libs".to_string();
        let results = run_check_binary(&pkg);
        assert!(
            results
                .iter()
                .any(|(n, _)| n == "devel-file-in-non-devel-package"),
            "genuine finding lost for dapl-debug-libs: {results:?}"
        );
        let lines = non_devel_lines("dapl-debug-libs", &["/usr/lib64/libdat2.so.2.0.0"]);
        assert!(lines.is_empty(), "{lines:?}");
    }

    #[test]
    fn devel_file_quiet_in_devel_package_and_doc_files() {
        // True negatives: a -devel package may ship headers, and a header
        // listed as %doc is exempt, per the reference.
        let (mut pkg, _dir) = pkg_with_files(vec![PkgFile {
            ..mkfile("/usr/include/foo.h", 0o100644, 75)
        }]);
        pkg.name = "foo-devel".to_string();
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "devel-file-in-non-devel-package"),
            "false positive in -devel package: {results:?}"
        );

        let (mut pkg, _dir) = pkg_with_files(vec![PkgFile {
            ..mkfile("/usr/include/bar.h", 0o100644, 76)
        }]);
        pkg.doc_files = vec!["/usr/include/bar.h".to_string()];
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "devel-file-in-non-devel-package"),
            "false positive on doc-listed header: {results:?}"
        );
    }

    #[test]
    fn mingw_sysroot_devel_files_do_not_fire() {
        // Issue #511: a MinGW cross package's sys-root payload is its
        // development environment by definition, so the finding does
        // not fire for files under /usr/<triplet>-w64-mingw32/sys-root/.
        // Covers both emission sites: normal files (.h, .a, .dll.a,
        // .pc) and the unversioned .so symlink.
        let (mut pkg, dir) = pkg_with_files(vec![
            PkgFile {
                ..mkfile(
                    "/usr/x86_64-w64-mingw32/sys-root/mingw/include/stdio.h",
                    0o100644,
                    81,
                )
            },
            PkgFile {
                ..mkfile(
                    "/usr/x86_64-w64-mingw32/sys-root/mingw/lib/libfoo.a",
                    0o100644,
                    82,
                )
            },
            PkgFile {
                ..mkfile(
                    "/usr/x86_64-w64-mingw32/sys-root/mingw/lib/libfoo.dll.a",
                    0o100644,
                    83,
                )
            },
            PkgFile {
                linkto: "libfoo.dll".to_string(),
                ..mkfile(
                    "/usr/x86_64-w64-mingw32/sys-root/mingw/lib/libfoo.so",
                    0o120777,
                    84,
                )
            },
        ]);
        pkg.name = "mingw64-gcc".to_string();
        // .pc files only count when the file is text: materialize one so
        // fd.is_buildconfig is true, mirroring the reference's peek.
        let pc_path = dir.path().join("foo.pc");
        std::fs::write(&pc_path, "prefix=/usr\n").expect("write pc fixture");
        pkg.files.push(PkgFile {
            path: pc_path.to_string_lossy().into_owned(),
            ..mkfile(
                "/usr/x86_64-w64-mingw32/sys-root/mingw/lib/pkgconfig/foo.pc",
                0o100644,
                85,
            )
        });
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "devel-file-in-non-devel-package"),
            "false positive on MinGW sys-root payload: {results:?}"
        );
    }

    #[test]
    fn sysroot_devel_files_fire_in_non_mingw_package() {
        // The exemption is name-scoped: the same sys-root payload in a
        // package outside the mingw32-/mingw64- family still fires.
        let (mut pkg, dir) = pkg_with_files(vec![
            PkgFile {
                ..mkfile(
                    "/usr/i686-w64-mingw32/sys-root/mingw/include/stdio.h",
                    0o100644,
                    86,
                )
            },
            PkgFile {
                ..mkfile(
                    "/usr/i686-w64-mingw32/sys-root/mingw/lib/libfoo.dll.a",
                    0o100644,
                    87,
                )
            },
            PkgFile {
                linkto: "libfoo.dll".to_string(),
                ..mkfile(
                    "/usr/i686-w64-mingw32/sys-root/mingw/lib/libfoo.so",
                    0o120777,
                    88,
                )
            },
        ]);
        pkg.name = "foo".to_string();
        let pc_path = dir.path().join("foo.pc");
        std::fs::write(&pc_path, "prefix=/usr\n").expect("write pc fixture");
        pkg.files.push(PkgFile {
            path: pc_path.to_string_lossy().into_owned(),
            ..mkfile(
                "/usr/i686-w64-mingw32/sys-root/mingw/lib/pkgconfig/foo.pc",
                0o100644,
                89,
            )
        });
        let results = run_check_binary(&pkg);
        for f in [
            "/usr/i686-w64-mingw32/sys-root/mingw/include/stdio.h",
            "/usr/i686-w64-mingw32/sys-root/mingw/lib/libfoo.dll.a",
            "/usr/i686-w64-mingw32/sys-root/mingw/lib/libfoo.so",
            "/usr/i686-w64-mingw32/sys-root/mingw/lib/pkgconfig/foo.pc",
        ] {
            assert!(
                results
                    .iter()
                    .any(|(n, d)| n == "devel-file-in-non-devel-package" && d.contains(f)),
                "missing finding for {f}: {results:?}"
            );
        }
    }

    #[test]
    fn mingw_devel_files_outside_sysroot_still_fire() {
        // The exemption is path-scoped too: devel files a MinGW-named
        // package ships outside the sys-root (the host include dir, or
        // the triplet dir without the sys-root level) still fire.
        let (mut pkg, _dir) = pkg_with_files(vec![
            PkgFile {
                ..mkfile("/usr/include/stdio.h", 0o100644, 90)
            },
            PkgFile {
                ..mkfile("/usr/x86_64-w64-mingw32/include/stdio.h", 0o100644, 91)
            },
        ]);
        pkg.name = "mingw64-gcc".to_string();
        let results = run_check_binary(&pkg);
        for f in [
            "/usr/include/stdio.h",
            "/usr/x86_64-w64-mingw32/include/stdio.h",
        ] {
            assert!(
                results
                    .iter()
                    .any(|(n, d)| n == "devel-file-in-non-devel-package" && d.contains(f)),
                "missing finding for {f}: {results:?}"
            );
        }
    }

    // Upstream rpmlint#435: mimeinfo.cache must not be packaged as a real file.
    #[test]
    fn mimeinfo_cache_packaged_errors() {
        let config = test_config();
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture");
        pkg.files = vec![PkgFile {
            name: "/usr/share/applications/mimeinfo.cache".to_string(),
            path: "/usr/share/applications/mimeinfo.cache".to_string(),
            mode: 0o100644,
            size: Some(100),
            ..Default::default()
        }];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let results: Vec<(String, String)> = out.results().to_vec();
        let lines: Vec<&String> = results
            .iter()
            .filter(|(n, _)| n == "mimeinfo-cache-packaged")
            .map(|(_, l)| l)
            .collect();
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0]
                .contains(": E: mimeinfo-cache-packaged /usr/share/applications/mimeinfo.cache"),
            "name, level and detail: {}",
            lines[0]
        );
    }

    #[test]
    fn mimeinfo_cache_ghost_is_quiet() {
        // The desktop-file-utils exception: a %ghost mimeinfo.cache has no
        // payload and must not warn.
        let config = test_config();
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture");
        pkg.files = vec![PkgFile {
            name: "/usr/share/applications/mimeinfo.cache".to_string(),
            path: "/usr/share/applications/mimeinfo.cache".to_string(),
            mode: 0o100644,
            size: Some(100),
            ..Default::default()
        }];
        pkg.ghost_files = vec!["/usr/share/applications/mimeinfo.cache".to_string()];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let results: Vec<(String, String)> = out.results().to_vec();
        assert!(
            !results.iter().any(|(n, _)| n == "mimeinfo-cache-packaged"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn mimeinfo_cache_other_desktop_files_are_quiet() {
        // The check is an exact path match: other files under
        // /usr/share/applications/ — including a sibling name a prefix
        // match would catch — must not warn.
        let config = test_config();
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture");
        pkg.files = vec![
            PkgFile {
                name: "/usr/share/applications/foo.desktop".to_string(),
                path: "/usr/share/applications/foo.desktop".to_string(),
                mode: 0o100644,
                size: Some(100),
                ..Default::default()
            },
            PkgFile {
                name: "/usr/share/applications/mimeinfo.cache.bak".to_string(),
                path: "/usr/share/applications/mimeinfo.cache.bak".to_string(),
                mode: 0o100644,
                size: Some(100),
                ..Default::default()
            },
        ];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let results: Vec<(String, String)> = out.results().to_vec();
        assert!(
            !results.iter().any(|(n, _)| n == "mimeinfo-cache-packaged"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn non_conf_in_etc_exempts_managed_dropins() {
        // Upstream rpmlint#1137: entries under /etc/alternatives/ are managed
        // by the alternatives system, not hand-edited config, so flagging
        // them is wrong. The reference additionally exempts
        // /etc/ld.so.conf.d/ drop-ins; a genuine non-config file under /etc
        // must still warn. Drive through check_binary.
        let config = test_config();
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        pkg.files = vec![
            PkgFile {
                name: "/etc/alternatives/foo".to_string(),
                path: "/etc/alternatives/foo".to_string(),
                mode: 0o100644,
                size: Some(100),
                ..Default::default()
            },
            PkgFile {
                name: "/etc/ld.so.conf.d/foo.conf".to_string(),
                path: "/etc/ld.so.conf.d/foo.conf".to_string(),
                mode: 0o100644,
                size: Some(100),
                ..Default::default()
            },
            PkgFile {
                name: "/etc/foo.conf".to_string(),
                path: "/etc/foo.conf".to_string(),
                mode: 0o100644,
                size: Some(100),
                ..Default::default()
            },
        ];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let results: Vec<(String, String)> = out
            .results()
            .iter()
            .map(|(n, d)| (n.clone(), d.clone()))
            .collect();
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "non-conffile-in-etc" && d.contains("alternatives")),
            "false positive on /etc/alternatives: {results:?}"
        );
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "non-conffile-in-etc" && d.contains("ld.so.conf.d")),
            "false positive on /etc/ld.so.conf.d: {results:?}"
        );
        assert!(
            results.iter().any(|(n, d)| n == "non-conffile-in-etc"
                && d.contains(": W: non-conffile-in-etc")
                && d.contains("/etc/foo.conf")),
            "missing W-level non-conffile-in-etc on /etc/foo.conf: {results:?}"
        );
    }

    #[test]
    fn non_conf_in_etc_selinux_store_is_exempt() {
        // Files inside a SELinux policy store
        // (/etc/selinux/<policy>/active/…) are libsemanage's
        // compiled module store, not administrator configuration:
        // no finding. Near misses must still warn: the policy-store
        // root artefacts, the policy directory itself, and a path
        // missing the policy component. Drive through check_binary.
        let config = test_config();
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        let entry = |name: &str| PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            mode: 0o100600,
            size: Some(100),
            ..Default::default()
        };
        pkg.files = vec![
            entry("/etc/selinux/targeted/active/modules/400/foo/cil"),
            entry("/etc/selinux/targeted/active/policy.kern"),
            entry("/etc/selinux/targeted/policy/policy.35"),
            entry("/etc/selinux/targeted/semanage.conf"),
            entry("/etc/selinux/config"),
            entry("/etc/selinux/active/loose.cil"),
        ];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let hits: Vec<&str> = out
            .results()
            .iter()
            .filter(|(n, _)| n == "non-conffile-in-etc")
            .map(|(_, d)| d.as_str())
            .collect();
        for store in [
            "/etc/selinux/targeted/active/modules/400/foo/cil",
            "/etc/selinux/targeted/active/policy.kern",
        ] {
            assert!(
                !hits.iter().any(|d| d.contains(store)),
                "false positive inside the policy store: {hits:?}"
            );
        }
        for want in [
            "/etc/selinux/targeted/policy/policy.35",
            "/etc/selinux/targeted/semanage.conf",
            "/etc/selinux/config",
            "/etc/selinux/active/loose.cil",
        ] {
            assert!(
                hits.iter().any(|d| d.contains(want)),
                "missing non-conffile-in-etc on {want}: {hits:?}"
            );
        }
        assert_eq!(hits.len(), 4, "hits: {hits:?}");
    }

    struct CountingReader {
        inner: std::io::Cursor<Vec<u8>>,
        consumed: usize,
    }

    impl std::io::Read for CountingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.consumed += n;
            Ok(n)
        }
    }

    #[test]
    fn read_prefix_consumes_only_the_prefix() {
        // Regression for issue #606: peek() loaded the whole file to
        // sniff 2048 bytes. The bounded read must not drain the source.
        let mut reader = CountingReader {
            inner: std::io::Cursor::new(vec![97u8; 100_000]),
            consumed: 0,
        };
        let chunk = read_prefix(&mut reader, 2048).expect("read");
        assert_eq!(chunk.len(), 2048);
        assert_eq!(reader.consumed, 2048, "source must not be drained");
        let mut small = CountingReader {
            inner: std::io::Cursor::new(b"short".to_vec()),
            consumed: 0,
        };
        assert_eq!(read_prefix(&mut small, 2048).expect("read"), b"short");
        assert_eq!(small.consumed, 5);
    }

    #[test]
    fn manual_page_in_subfolder_fires() {
        // The reference expects man3/foo/bar/baz.3.gz to fire
        // manual-page-in-subfolder (test_files.py); the port captured
        // the filename as a single path component, so the finding was
        // unreachable. Normal and wrong-folder pages pin the rest of
        // the flow.
        let (pkg, _dir) = pkg_with_files(vec![
            PkgFile {
                name: "/usr/share/man/man3/foo/bar/baz.3.gz".to_string(),
                path: "/usr/share/man/man3/foo/bar/baz.3.gz".to_string(),
                mode: 0o100644,
                ..Default::default()
            },
            PkgFile {
                name: "/usr/share/man/man1/foo.1.gz".to_string(),
                path: "/usr/share/man/man1/foo.1.gz".to_string(),
                mode: 0o100644,
                ..Default::default()
            },
            PkgFile {
                name: "/usr/share/man/man1/wrong.3.gz".to_string(),
                path: "/usr/share/man/man1/wrong.3.gz".to_string(),
                mode: 0o100644,
                ..Default::default()
            },
        ]);
        let results = run_check_binary(&pkg);
        let hits =
            |tag: &str, path: &str| results.iter().any(|(n, d)| n == tag && d.contains(path));
        assert!(
            hits(
                "manual-page-in-subfolder",
                "/usr/share/man/man3/foo/bar/baz.3.gz"
            ),
            "subfolder man page must fire: {results:?}"
        );
        assert!(!hits(
            "manual-page-in-subfolder",
            "/usr/share/man/man1/foo.1.gz"
        ));
        assert!(!hits(
            "manual-page-in-subfolder",
            "/usr/share/man/man1/wrong.3.gz"
        ));
        assert!(hits(
            "bad-manual-page-folder",
            "/usr/share/man/man1/wrong.3.gz"
        ));
        assert!(!hits(
            "bad-manual-page-folder",
            "/usr/share/man/man3/foo/bar/baz.3.gz"
        ));
    }

    #[test]
    fn manual_page_sectionless_subfolder_shapes() {
        // Pins the ledgered behaviour (tests/parity/divergences.toml,
        // manual-page-in-subfolder) under the shipped CompressExtension
        // (bz2 in configdefaults): a dotless subdir name prints only
        // manpage-not-compressed -- the compression step pops the sole
        // suffix-list entry (the whole filename), and the empty remainder
        // makes the suffix guard skip both error findings -- while a
        // dotted section-less name also fires bad-manual-page-folder and
        // manual-page-in-subfolder.
        for (path, errors_fire) in [
            ("/usr/share/man/man1/foo/bar", false),
            ("/usr/share/man/man1/foo/bar.baz", true),
        ] {
            let (pkg, _dir) = pkg_with_files(vec![PkgFile {
                name: path.to_string(),
                path: path.to_string(),
                mode: 0o100644,
                ..Default::default()
            }]);
            let results = run_check_binary(&pkg);
            let hits = |tag: &str| results.iter().any(|(n, _)| n == tag);
            assert!(
                hits("manpage-not-compressed"),
                "{path} must warn manpage-not-compressed: {results:?}"
            );
            assert_eq!(
                hits("bad-manual-page-folder"),
                errors_fire,
                "{path} bad-manual-page-folder: {results:?}"
            );
            assert_eq!(
                hits("manual-page-in-subfolder"),
                errors_fire,
                "{path} manual-page-in-subfolder: {results:?}"
            );
            if errors_fire {
                assert!(
                    results.iter().any(|(n, d)| n == "bad-manual-page-folder"
                        && d.contains("expected folder: manfoo/bar")),
                    "{path} bad-folder detail: {results:?}"
                );
            }
        }
    }

    #[test]
    fn peek_unreadable_file_reports_read_error_detail() {
        // Pins the port's own read-error detail for FilesCheck.peek (ledgered
        // divergence: the reference's str(OSError) carries the [Errno N] prefix
        // and the filename).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let secret = dir.path().join("secret.bin");
        std::fs::write(&secret, b"\x00\x01").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o0))
                .expect("chmod 000");
        }
        let pkg = Pkg::open(
            std::path::Path::new(&fixture_path("scriptlet-empty-post-1.0-1.noarch.rpm")),
            dir.path(),
            true,
        )
        .expect("open fixture");
        let pkgfile = PkgFile {
            name: "/usr/bin/secret".to_string(),
            path: secret.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = FilesCheck::new(&config);
        let (chunk, istext) = check.peek(&pkg, &pkgfile, &mut out);
        assert!(chunk.is_empty() && !istext);
        let line = out
            .results()
            .iter()
            .find(|(n, _)| n == "read-error")
            .map(|(_, l)| l.clone())
            .expect("read-error must fire");
        assert!(
            line.contains(": W: "),
            "read-error must be Warning level: {line}"
        );
        assert!(
            line.contains("Permission denied (os error 13)"),
            "unexpected detail: {line}"
        );
    }

    /// A minimal gzip header (magic, deflate, no flags) carrying the
    /// given MTIME, plus the two trailing header bytes.
    fn gzip_header(mtime: u32) -> Vec<u8> {
        let mut v = vec![0x1f, 0x8b, 0x08, 0x00];
        v.extend_from_slice(&mtime.to_le_bytes());
        v.extend_from_slice(&[0x00, 0x03]);
        v
    }

    const GZIP_SDE: i64 = 1_785_909_409;

    #[test]
    fn gzip_mtime_after_sde_fires() {
        let chunk = gzip_header((GZIP_SDE + 3) as u32);
        assert!(FilesCheck::gzip_mtime_after_sde(
            "/usr/share/data/table.gz",
            &chunk,
            Some(GZIP_SDE)
        ));
        let chunk = gzip_header((GZIP_SDE + 86_400) as u32);
        assert!(FilesCheck::gzip_mtime_after_sde(
            "/usr/lib64/erlang/man/man1/erl.gz",
            &chunk,
            Some(GZIP_SDE)
        ));
    }

    #[test]
    fn gzip_reserved_method_byte_stays_silent() {
        // A header with a reserved compression method (not deflate)
        // is not a gzip stream: its bytes 4..8 are not an MTIME and
        // must not fire however large they are.
        let mut chunk = gzip_header(u32::MAX);
        chunk[2] = 7;
        assert!(!FilesCheck::gzip_mtime_after_sde(
            "/usr/share/data/table.gz",
            &chunk,
            Some(GZIP_SDE)
        ));
    }

    #[test]
    fn gzip_mtime_at_or_below_sde_plus_slack_stays_silent() {
        // The boundary is exact: SDE + 2 s is the last silent value.
        for mtime in [GZIP_SDE + 2, GZIP_SDE + 1, GZIP_SDE, GZIP_SDE - 100] {
            let chunk = gzip_header(mtime as u32);
            assert!(
                !FilesCheck::gzip_mtime_after_sde(
                    "/usr/share/data/table.gz",
                    &chunk,
                    Some(GZIP_SDE)
                ),
                "mtime {mtime} must stay silent"
            );
        }
    }

    #[test]
    fn gzip_mtime_zero_stays_silent() {
        // A zero MTIME is what compressing from a pipe (or with -n)
        // stores: no timestamp at all, nothing to compare.
        let chunk = gzip_header(0);
        assert!(!FilesCheck::gzip_mtime_after_sde(
            "/usr/share/data/table.gz",
            &chunk,
            Some(GZIP_SDE)
        ));
    }

    #[test]
    fn gzip_mtime_without_known_sde_stays_silent() {
        let chunk = gzip_header(u32::MAX);
        assert!(!FilesCheck::gzip_mtime_after_sde(
            "/usr/share/data/table.gz",
            &chunk,
            None
        ));
    }

    #[test]
    fn gzip_mtime_man_and_info_trees_stay_silent() {
        let chunk = gzip_header((GZIP_SDE + 86_400) as u32);
        for fname in [
            "/usr/share/man/man1/tool.1.gz",
            "/usr/share/man/de/man1/tool.1.gz",
            "/usr/share/info/tool.info.gz",
        ] {
            assert!(
                !FilesCheck::gzip_mtime_after_sde(fname, &chunk, Some(GZIP_SDE)),
                "{fname} is in an excluded tree"
            );
        }
        // Near miss: only the two named trees are excluded -- a man tree
        // elsewhere (the erlang shape) and a lookalike prefix still fire.
        assert!(FilesCheck::gzip_mtime_after_sde(
            "/usr/lib64/erlang/man/man1/erl.gz",
            &chunk,
            Some(GZIP_SDE)
        ));
        assert!(FilesCheck::gzip_mtime_after_sde(
            "/usr/share/manual/table.gz",
            &chunk,
            Some(GZIP_SDE)
        ));
    }

    #[test]
    fn gzip_mtime_archive_and_other_names_stay_silent() {
        let chunk = gzip_header((GZIP_SDE + 86_400) as u32);
        for fname in [
            "/usr/share/data/archive.tar.gz",
            "/usr/share/data/archive.tgz",
            "/usr/share/data/table.gzip",
            "/usr/share/data/table.gz.bak",
            "/usr/share/icons/icon.svgz",
            "/usr/share/data/TABLE.GZ",
        ] {
            assert!(
                !FilesCheck::gzip_mtime_after_sde(fname, &chunk, Some(GZIP_SDE)),
                "{fname} is not a plain *.gz name"
            );
        }
    }

    #[test]
    fn gzip_mtime_bad_magic_or_short_header_stays_silent() {
        let late = (GZIP_SDE + 86_400) as u32;
        // Plain text that merely carries a .gz name.
        assert!(!FilesCheck::gzip_mtime_after_sde(
            "/usr/share/data/table.gz",
            b"not a gzip stream at all",
            Some(GZIP_SDE)
        ));
        // One magic byte wrong.
        let mut chunk = gzip_header(late);
        chunk[1] = 0x8c;
        assert!(!FilesCheck::gzip_mtime_after_sde(
            "/usr/share/data/table.gz",
            &chunk,
            Some(GZIP_SDE)
        ));
        // Truncated before the MTIME field ends, and empty.
        let chunk = gzip_header(late);
        assert!(!FilesCheck::gzip_mtime_after_sde(
            "/usr/share/data/table.gz",
            &chunk[..7],
            Some(GZIP_SDE)
        ));
        assert!(!FilesCheck::gzip_mtime_after_sde(
            "/usr/share/data/table.gz",
            &[],
            Some(GZIP_SDE)
        ));
    }

    /// Drive the emission seam with an explicit SOURCE_DATE_EPOCH, the
    /// fixture headers carrying neither a reproducible BUILDHOST nor a
    /// usable BUILDTIME for this comparison.
    fn gzip_mtime_findings(fname: &str, chunk: &[u8], sde: Option<i64>) -> Vec<(String, String)> {
        let (pkg, _dir) = pkg_with_files(vec![PkgFile {
            name: fname.to_string(),
            ..Default::default()
        }]);
        let config = test_config();
        let check = FilesCheck::new(&config);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let fd = FileData {
            chunk: chunk.to_vec(),
            ..Default::default()
        };
        let st = PkgState {
            source_date_epoch: sde,
            ..Default::default()
        };
        check.check_normal_gzip_mtime(&pkg, fname, &fd, &st, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn gzip_mtime_emission_fires_once_at_warning() {
        let chunk = gzip_header((GZIP_SDE + 3600) as u32);
        let results = gzip_mtime_findings("/usr/share/data/table.gz", &chunk, Some(GZIP_SDE));
        let hits: Vec<&(String, String)> = results
            .iter()
            .filter(|(n, _)| n == "gzip-mtime-after-source-date-epoch")
            .collect();
        assert_eq!(hits.len(), 1, "exactly one finding: {results:?}");
        assert!(
            hits[0].1.contains(": W: ") && hits[0].1.contains("/usr/share/data/table.gz"),
            "warning naming the file: {}",
            hits[0].1
        );
    }

    #[test]
    fn gzip_mtime_emission_silent_for_excluded_paths() {
        let chunk = gzip_header((GZIP_SDE + 3600) as u32);
        for fname in ["/usr/share/man/man1/tool.1.gz", "/usr/share/data/a.tar.gz"] {
            let results = gzip_mtime_findings(fname, &chunk, Some(GZIP_SDE));
            assert!(
                results
                    .iter()
                    .all(|(n, _)| n != "gzip-mtime-after-source-date-epoch"),
                "{fname} must not fire: {results:?}"
            );
        }
    }

    #[test]
    fn gzip_mtime_check_binary_silent_without_late_mtime() {
        // End to end through check_binary: an MTIME of 1 can only fire
        // against a negative SOURCE_DATE_EPOCH, so the tag stays silent
        // whatever SDE the ambient environment or fixture header yields.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        let root = pkg
            .extracted_dir()
            .expect("extracted fixture")
            .to_path_buf();
        let path = root.join("usr/share/data/table.gz");
        std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
        std::fs::write(&path, gzip_header(1)).expect("write gzip header");
        pkg.files = vec![PkgFile {
            name: "/usr/share/data/table.gz".to_string(),
            path: path.to_string_lossy().into_owned(),
            mode: 0o100644,
            ..Default::default()
        }];
        let results = run_check_binary(&pkg);
        assert!(
            results
                .iter()
                .all(|(n, _)| n != "gzip-mtime-after-source-date-epoch"),
            "no gzip-mtime finding expected: {results:?}"
        );
    }

    fn pkg_with_files(files: Vec<PkgFile>) -> (Pkg, tempfile::TempDir) {
        // Pkg::open with "/" as the extract dir takes the LiveRoot path:
        // the header is read but nothing is extracted. The fixture paths do
        // not exist on disk, so findings other than the asserted one are noise.
        let rpm = format!(
            "{}/../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut pkg = Pkg::open(std::path::Path::new(&rpm), std::path::Path::new("/"), true)
            .expect("open fixture header");
        pkg.files = files;
        let dir = tempfile::TempDir::new().expect("tmpdir");
        (pkg, dir)
    }

    fn run_check_binary(pkg: &Pkg) -> Vec<(String, String)> {
        let config = test_config();
        let mut check = FilesCheck::new(&config);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(pkg, &config, &mut out);
        out.results().to_vec()
    }

    /// Build an extracted package shipping the given (path, content)
    /// files with real on-disk content, so the content-reading
    /// per-file checks parse the real bytes.
    fn content_pkg(dir: &tempfile::TempDir, files: &[(&str, &str)]) -> Pkg {
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        pkg.name = "udev-rules-test".to_string();
        let root = pkg
            .extracted_dir()
            .expect("extracted fixture")
            .to_path_buf();
        pkg.files = files
            .iter()
            .map(|(name, content)| {
                let path = root.join(name.trim_start_matches('/'));
                std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
                std::fs::write(&path, content).expect("write temp file");
                PkgFile {
                    name: name.to_string(),
                    path: path.to_string_lossy().into_owned(),
                    mode: 0o100644,
                    ..Default::default()
                }
            })
            .collect();
        pkg
    }

    fn udev_findings(pkg: &Pkg) -> Vec<(String, String)> {
        run_check_binary(pkg)
            .into_iter()
            .filter(|(n, _)| n.starts_with("udev-rule-world-writable"))
            .collect()
    }

    const UDEV_RULES_PATH: &str = "/usr/lib/udev/rules.d/99-test.rules";

    #[test]
    fn udev_allowlist_holds_the_systemd_defaults() {
        let mut names: Vec<&str> = udev_ww_allowlist().iter().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "fuse",
                "kvm",
                "ptmx",
                "tty",
                "tun",
                "vfio",
                "vhost-net",
                "vhost-vsock",
                "vsock"
            ]
        );
        // Deliberately absent: the security team removed renderD*
        // from systemd's 0666 set (boo#1217118), and the node
        // creators are charged by their own tag, never allowlisted.
        for absent in ["renderD*", "uinput", "uhid", "cuse", "userio", "vhci"] {
            assert!(!udev_ww_allowlist().contains(absent), "{absent}");
        }
    }

    #[test]
    fn udev_rules_file_population() {
        assert!(is_udev_rules_file("/usr/lib/udev/rules.d/50-x.rules"));
        assert!(is_udev_rules_file("/etc/udev/rules.d/99-y.rules"));
        assert!(!is_udev_rules_file("/usr/lib/udev/rules.d/sub/x.rules"));
        assert!(!is_udev_rules_file("/usr/lib/udev/hwdb.d/20-x.hwdb"));
        assert!(!is_udev_rules_file("/usr/lib/udev/rules.d/x.conf"));
    }

    #[test]
    fn udev_world_writable_mode_fires() {
        // The firing shapes of issue #1023 section 4.
        for line in [
            // boo#1202160, verbatim from the shipped 90-libiio.rules:
            // the mode behind PROGRAM/RESULT guards.
            "SUBSYSTEM==\"usb\", PROGRAM==\"/bin/sh -c '/usr/bin/iio_info -S usb=%s{idVendor}:%s{idProduct} | grep %s{idVendor}:%s{idProduct}'\", RESULT!=\"\", MODE=\"666\"",
            // boo#1274923, verbatim from the shipped
            // 69-sc-controller.rules (the 28de vendor rules).
            "SUBSYSTEM==\"usb\", ATTRS{idVendor}==\"28de\", MODE=\"0666\", TAG+=\"uaccess\"",
            "KERNEL==\"vboxguest\", MODE=\"0666\"",
            "KERNEL==\"vboxuser\", MODE=\"0666\"",
            // boo#1217118's class: renderD* is not on the allowlist.
            "SUBSYSTEM==\"drm\", KERNEL==\"renderD*\", GROUP=\"render\", MODE=\"0666\"",
            "KERNEL==\"somechar\", MODE:=\"0666\"",
            "KERNEL==\"somechar\", MODE=\"0777\"",
            // The allowlist matches exact names only: a glob fires.
            "KERNEL==\"tun*\", MODE=\"0666\"",
        ] {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let pkg = content_pkg(&dir, &[(UDEV_RULES_PATH, line)]);
            let hits = udev_findings(&pkg);
            assert_eq!(hits.len(), 1, "line must fire once: {line}: {hits:?}");
            assert_eq!(hits[0].0, "udev-rule-world-writable-mode");
            assert!(
                hits[0].1.contains(
                    ": W: udev-rule-world-writable-mode /usr/lib/udev/rules.d/99-test.rules"
                ),
                "name, level and path must render, got: {}",
                hits[0].1
            );
        }
    }

    #[test]
    fn udev_world_writable_after_escaped_quote_fires() {
        // An escaped quote inside a value is part of the value, not
        // a delimiter: the MODE after it stays its own assignment.
        // Toggling on the escaped quote desyncs the split and
        // swallows the MODE token (issue #1144).
        for line in [
            "PROGRAM==\"a\\\"\", MODE=\"0666\"",
            // An even run of backslashes leaves the quote a
            // delimiter, so this line splits the same way.
            "PROGRAM==\"a\\\\\", MODE=\"0666\"",
        ] {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let pkg = content_pkg(&dir, &[(UDEV_RULES_PATH, line)]);
            assert_eq!(udev_findings(&pkg).len(), 1, "{line}");
        }
    }

    #[test]
    fn udev_world_writable_continuation_line_fires() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let content = "KERNEL==\"somechar\", \\\n    MODE=\"0666\"\n";
        let pkg = content_pkg(&dir, &[(UDEV_RULES_PATH, content)]);
        let hits = udev_findings(&pkg);
        assert_eq!(hits.len(), 1, "continued rule must fire: {hits:?}");
        assert_eq!(hits[0].0, "udev-rule-world-writable-mode");
    }

    #[test]
    fn udev_world_writable_node_creator_replaces_bare_tag() {
        for line in [
            // The DSA-3451 line of CVE-2016-1233.
            "KERNEL==\"cuse\", MODE=\"0666\", OPTIONS+=\"static_node=cuse\"",
            "KERNEL==\"uinput\", MODE=\"0666\"",
            "KERNEL==\"uhid\", MODE=\"0666\"",
            // boo#1274923, verbatim from the shipped
            // 69-sc-controller.rules: the mode alongside uaccess.
            "KERNEL==\"uinput\", SUBSYSTEM==\"misc\", TAG+=\"uaccess\", OPTIONS+=\"static_node=uinput\", MODE=\"0666\"",
        ] {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let pkg = content_pkg(&dir, &[(UDEV_RULES_PATH, line)]);
            let hits = udev_findings(&pkg);
            assert_eq!(
                hits.len(),
                1,
                "node-creator line yields exactly one finding: {line}: {hits:?}"
            );
            assert_eq!(hits[0].0, "udev-rule-world-writable-node-creator");
        }
    }

    #[test]
    fn udev_world_writable_quiet_shapes() {
        for line in [
            // The allowlisted upstream systemd defaults, in their
            // shipped shapes.
            "SUBSYSTEM==\"tty\", KERNEL==\"ptmx\", GROUP=\"tty\", MODE=\"0666\"",
            "SUBSYSTEM==\"tty\", KERNEL==\"tty\", GROUP=\"tty\", MODE=\"0666\"",
            "KERNEL==\"tun\", MODE=\"0666\", OPTIONS+=\"static_node=net/tun\"",
            "KERNEL==\"fuse\", MODE=\"0666\", OPTIONS+=\"static_node=fuse\"",
            "KERNEL==\"kvm\", GROUP=\"kvm\", MODE=\"0666\", OPTIONS+=\"static_node=kvm\"",
            "KERNEL==\"vfio\", MODE=\"0666\", OPTIONS+=\"static_node=vfio/vfio\"",
            "KERNEL==\"vsock\", MODE=\"0666\"",
            "KERNEL==\"vhost-vsock\", GROUP=\"kvm\", MODE=\"0666\", OPTIONS+=\"static_node=vhost-vsock\"",
            "KERNEL==\"vhost-net\", GROUP=\"kvm\", MODE=\"0666\", OPTIONS+=\"static_node=vhost-net\"",
            // Other-readable is not world-writable; 0664 on js* is a
            // systemd default too.
            "SUBSYSTEM==\"input\", KERNEL==\"js[0-9]*\", MODE=\"0664\"",
            // The sanctioned shape: group-scoped, seat access via
            // uaccess.
            "KERNEL==\"uinput\", MODE=\"0660\", TAG+=\"uaccess\"",
            // uaccess alone assigns no mode.
            "KERNEL==\"uinput\", TAG+=\"uaccess\"",
            // A match is not an assignment.
            "KERNEL==\"somechar\", MODE==\"0666\"",
            // ENV{MODE} is not MODE.
            "KERNEL==\"somechar\", ENV{MODE}=\"0666\"",
            // Out of scope (issue #1023): chmod in a RUN assignment.
            "SUBSYSTEM==\"usb\", RUN+=\"/bin/chmod 0666 /dev/bus/usb/001/001\"",
        ] {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let pkg = content_pkg(&dir, &[(UDEV_RULES_PATH, line)]);
            let hits = udev_findings(&pkg);
            assert!(hits.is_empty(), "line must stay quiet: {line}: {hits:?}");
        }
        // Comment lines are skipped.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = content_pkg(
            &dir,
            &[(UDEV_RULES_PATH, "# KERNEL==\"uinput\", MODE=\"0666\"\n")],
        );
        assert!(udev_findings(&pkg).is_empty());
    }

    #[test]
    fn udev_world_writable_mixed_file_counts_each_line_once() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let content = "KERNEL==\"vboxguest\", MODE=\"0666\"
KERNEL==\"uinput\", MODE=\"0666\"
KERNEL==\"kvm\", MODE=\"0666\"
KERNEL==\"hidraw*\", MODE=\"0660\"
";
        let pkg = content_pkg(&dir, &[(UDEV_RULES_PATH, content)]);
        let hits = udev_findings(&pkg);
        assert_eq!(hits.len(), 2, "one bare + one node-creator: {hits:?}");
        assert_eq!(hits[0].0, "udev-rule-world-writable-mode");
        assert_eq!(hits[1].0, "udev-rule-world-writable-node-creator");
    }

    #[test]
    fn scm_regex_charges_vcs_internals() {
        // The scoped pattern of issue #858: version-control metadata
        // trees and RCS ,v files charge. The second list
        // pins the working-tree dotfiles the reference's pattern
        // charges and this one leaves silent.
        for path in [
            "/foo/CVS/bar",
            "/foo/RCS/bar",
            "/bar/foo,v",
            "bar/.git/refs",
            "/usr/src/foo/.git/HEAD",
            "/opt/bar/.hg/store",
            "/x/.bzr/branch",
            "/x/.svn/entries",
            "/x/.arch-ids/=id",
            "/foo/{arch}/bar",
        ] {
            assert!(is_match(scm_regex(), path), "scm_regex must match {path}");
        }
        for path in [
            "/usr/bin/foo",
            "/etc/gitconfig",
            "bar/.gitignore.bak",
            "/home/user/.github/workflows",
            "/.gitignore",
            "bar/.svnignore",
            "/usr/share/foo/.gitignore",
            "/usr/share/foo/.cvsignore",
            "/usr/share/foo/.gitattributes",
            "/usr/share/foo/.hgignore",
            "/usr/share/foo/.hgtags",
            "/usr/share/foo/.bzrignore",
            "/.gitmodules",
            "/usr/share/foo/.gitmodules",
            "/usr/share/doc/git/HEAD",
            "/usr/share/foo/x.gitmodules",
            "/usr/share/foo/.gitmodules.bak",
        ] {
            assert!(
                !is_match(scm_regex(), path),
                "scm_regex must not match {path}"
            );
        }
    }

    #[test]
    fn backup_regex_matches_the_reference_pattern() {
        // The reference's backup_regex (FilesCheck.py) verbatim: a
        // trailing `~`, an Emacs `#...#` autosave name, or `.orig`/
        // `.rej` optionally followed by a compression suffix;
        // end-anchored and case-sensitive.
        for path in [
            "/usr/share/foo/file.txt~",
            "/usr/share/foo/file.orig",
            "/usr/share/foo/file.rej",
            "/usr/share/foo/file.orig.gz",
            "/usr/share/foo/file.rej.xz",
            "/usr/include/foo/#file.hpp#",
            "/etc/openvswitch/.conf.db.~lock~",
        ] {
            assert!(
                is_match(backup_regex(), path),
                "backup_regex must match {path}"
            );
        }
        for path in [
            // No `.bak` arm in the reference; the Factory instance is
            // rpc.statd's state file, not an editor leftover.
            "/var/lib/nfs/sm.bak",
            "/usr/share/foo/file.bak",
            // Case-sensitive: uppercase suffixes are not charged.
            "/usr/share/foo/file.BAK",
            "/usr/share/aranym/afros/drive_c/mint/1-17-cur/mint.cnf.ORIG",
            "/usr/share/foo/file.Rej",
            // `.orig` must end the name (modulo a compression suffix).
            "/usr/share/foo/file.orig.bak",
            "/usr/share/foo/file.original",
            // A lone `#` is not an Emacs autosave pair.
            "/usr/share/foo/#file.hpp",
            "/usr/share/foo/file.hpp#",
            "/usr/share/foo/file.txt",
        ] {
            assert!(
                !is_match(backup_regex(), path),
                "backup_regex must not match {path}"
            );
        }
    }

    #[test]
    fn backup_file_in_package_charges_reference_shapes_only() {
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/share/foo/file.orig.gz", 0o100644, 71),
            mkfile("/var/lib/nfs/sm.bak", 0o100644, 72),
            mkfile("/usr/share/foo/mint.cnf.ORIG", 0o100644, 73),
        ]);
        let results = run_check_binary(&pkg);
        let lines: Vec<&String> = results
            .iter()
            .filter(|(n, _)| n == "backup-file-in-package")
            .map(|(_, l)| l)
            .collect();
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0].contains("/usr/share/foo/file.orig.gz"),
            "the compressed .orig charges: {}",
            lines[0]
        );
    }

    #[test]
    fn cargo_toml_orig_basename_match_is_exact() {
        for path in [
            "/usr/lib64/crates/rusty_v8/vendor/anyhow/Cargo.toml.orig",
            "/Cargo.toml.orig",
            "Cargo.toml.orig",
        ] {
            assert!(is_cargo_toml_orig(path), "must exempt {path}");
        }
        for path in [
            // Case matters: cargo writes exactly `Cargo.toml.orig`.
            "/usr/share/foo/cargo.toml.orig",
            "/usr/share/foo/CARGO.TOML.ORIG",
            // The string as the tail of a longer name is not the basename.
            "/usr/share/foo/xCargo.toml.orig",
            // Suffixed names are not the plain artifact.
            "/usr/share/foo/Cargo.toml.orig2",
            "/usr/share/foo/Cargo.toml.orig.gz",
            "/usr/share/foo/Cargo.toml.orig.bak",
            // Other manifests' backups stay ordinary patch litter.
            "/usr/share/foo/meson.build.orig",
            "/usr/share/foo/Makefile.orig",
            "/usr/share/foo/package.json.orig",
            "/usr/share/foo/Cargo.toml",
        ] {
            assert!(!is_cargo_toml_orig(path), "must not exempt {path}");
        }
    }

    #[test]
    fn backup_file_in_package_exempts_cargo_toml_orig_only() {
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile(
                "/usr/lib64/crates/vendored/anyhow/Cargo.toml.orig",
                0o100644,
                71,
            ),
            mkfile("/usr/share/foo/package.json.orig", 0o100644, 72),
            mkfile("/usr/share/foo/xCargo.toml.orig", 0o100644, 73),
        ]);
        let results = run_check_binary(&pkg);
        let lines: Vec<&String> = results
            .iter()
            .filter(|(n, _)| n == "backup-file-in-package")
            .map(|(_, l)| l)
            .collect();
        assert_eq!(lines.len(), 2, "unexpected: {results:?}");
        assert!(
            lines.iter().any(|l| l.contains("package.json.orig")),
            "package.json.orig still charges: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("xCargo.toml.orig")),
            "xCargo.toml.orig still charges: {lines:?}"
        );
    }

    #[test]
    fn version_control_internal_file_charges_internals_not_dotfiles() {
        let config = test_config();
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture");
        pkg.files = vec![
            PkgFile {
                name: "/bar/foo,v".to_string(),
                path: "/bar/foo,v".to_string(),
                ..Default::default()
            },
            PkgFile {
                name: "/usr/src/foo/.git/HEAD".to_string(),
                path: "/usr/src/foo/.git/HEAD".to_string(),
                ..Default::default()
            },
            PkgFile {
                name: "/usr/share/foo/.gitmodules".to_string(),
                path: "/usr/share/foo/.gitmodules".to_string(),
                ..Default::default()
            },
            PkgFile {
                name: "/.gitignore".to_string(),
                path: "/.gitignore".to_string(),
                ..Default::default()
            },
            PkgFile {
                name: "/usr/share/foo/.cvsignore".to_string(),
                path: "/usr/share/foo/.cvsignore".to_string(),
                ..Default::default()
            },
            PkgFile {
                name: "/usr/bin/foo".to_string(),
                path: "/usr/bin/foo".to_string(),
                ..Default::default()
            },
        ];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let hits: Vec<_> = out
            .results()
            .iter()
            .filter(|(n, _)| n == "version-control-internal-file")
            .map(|(_, d)| d.clone())
            .collect();
        assert_eq!(hits.len(), 2, "expected 2 findings, got: {hits:?}");
        assert!(hits.iter().any(|d| d.contains("/bar/foo,v")));
        assert!(hits.iter().any(|d| d.contains("/usr/src/foo/.git/HEAD")));
    }

    fn ghost_sized_file(name: &str, flags: u32, mode: u32, size: u64) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            flags,
            mode,
            size: Some(size),
            ..Default::default()
        }
    }

    #[test]
    fn ghost_buildroot_content_predicate_fires() {
        // Probe shapes that must fire (issue #1017): a plain %ghost over
        // real content under /etc, the %config(noreplace) %ghost flag
        // merge, the forgejo shape, a %ghost %attr(0600) file, and a
        // %config ghost outside /etc (the Regina-REXX shape).
        let cases = [
            ghost_sized_file("/etc/foo.conf", RPMFILE_GHOST, 0o100644, 29),
            ghost_sized_file(
                "/etc/foo.conf",
                RPMFILE_GHOST | RPMFILE_CONFIG | RPMFILE_NOREPLACE,
                0o100644,
                11,
            ),
            ghost_sized_file(
                "/etc/forgejo-runner/config.yaml",
                RPMFILE_GHOST | RPMFILE_CONFIG | RPMFILE_NOREPLACE,
                0o100640,
                22,
            ),
            ghost_sized_file("/etc/foo.key", RPMFILE_GHOST, 0o100600, 9),
            ghost_sized_file(
                "/etc/rxstack.conf",
                RPMFILE_GHOST | RPMFILE_CONFIG,
                0o100644,
                402,
            ),
            // The %config flag alone charges, outside /etc and
            // /usr/etc alike (issue #1145).
            ghost_sized_file(
                "/var/lib/foo/state.conf",
                RPMFILE_GHOST | RPMFILE_CONFIG,
                0o100644,
                128,
            ),
            // The /usr/etc path alone charges, with no %config flag
            // (issue #1145).
            ghost_sized_file("/usr/etc/foo.conf", RPMFILE_GHOST, 0o100644, 42),
        ];
        for f in &cases {
            assert!(
                ghost_buildroot_content_fires(f, ""),
                "must fire: {}",
                f.name
            );
        }
        // A key whose %post builds its path from a variable: the literal
        // path never appears, so nothing credits the scriptlet and the
        // dropped bytes still fire (the secret-first remedy applies).
        let key = ghost_sized_file("/etc/xrdp/rsakeys.ini", RPMFILE_GHOST, 0o100600, 2939);
        let post = "keyfile=\"$sysconfdir/xrdp/rsakeys.ini\"; openssl genrsa -out \"$keyfile\"";
        assert!(
            ghost_buildroot_content_fires(&key, post),
            "a %post that computes the path does not name it literally"
        );
        // haproxy near-miss: the %post names the profile at a literal
        // path sharing the basename; the local stub at the longer path
        // is not named and keeps firing.
        let stub = ghost_sized_file(
            "/etc/apparmor.d/local/usr.sbin.haproxy",
            RPMFILE_GHOST | RPMFILE_CONFIG,
            0o100644,
            70,
        );
        let apparmor_post = "apparmor_parser -r /etc/apparmor.d/usr.sbin.haproxy";
        assert!(
            ghost_buildroot_content_fires(&stub, apparmor_post),
            "a literal path sharing the basename does not credit"
        );
        // Boundary near-misses (issue #1145): a suffixed or prefixed
        // lookalike does not name the path, and a tail match must
        // end at a token boundary too.
        let conf = ghost_sized_file(
            "/etc/foo.conf",
            RPMFILE_GHOST | RPMFILE_CONFIG,
            0o100644,
            29,
        );
        for text in [
            "touch /etc/foo.conf.bak",
            "cp /dev/null /backup/etc/foo.conf",
        ] {
            assert!(
                ghost_buildroot_content_fires(&conf, text),
                "a boundary-less lookalike does not credit: {text}"
            );
        }
        let tex = ghost_sized_file(
            "/etc/texmf/ls-R",
            RPMFILE_GHOST | RPMFILE_CONFIG,
            0o100664,
            67,
        );
        for text in ["echo x > ${dir}/ls-R.bak", "echo x > $dir/ls-R2"] {
            assert!(
                ghost_buildroot_content_fires(&tex, text),
                "a tail match without a trailing boundary does not credit: {text}"
            );
        }
    }

    #[test]
    fn ghost_credit_slots_are_the_install_time_slots() {
        // Only the slots that can create the file when the package
        // is installed credit a ghost (issue #1145): removal-time
        // slots, triggers and %verifyscript are excluded -- this is
        // the executable form of the %verifyscript exclusion, over
        // the real slot table.
        let credited: Vec<&str> = crate::pkg::SCRIPT_TAGS
            .iter()
            .map(|(_, _, label)| *label)
            .filter(|label| ghost_credit_slot(label))
            .collect();
        assert_eq!(credited, ["%pre", "%post", "%pretrans", "%posttrans"]);
    }

    #[test]
    fn ghost_buildroot_content_predicate_quiet() {
        // Probe shapes that must stay quiet: the `touch` idiom and
        // absent files (size 0, with or without %attr), a ghost symlink
        // and a ghost directory, a real (non-ghost) file, and a sized
        // ghost outside the charged shapes.
        let quiet = [
            ghost_sized_file("/etc/foo.conf", RPMFILE_GHOST, 0o100644, 0),
            ghost_sized_file("/etc/foo.conf", RPMFILE_GHOST, 0o100000, 0),
            ghost_sized_file("/etc/foo.conf", RPMFILE_GHOST, 0o100640, 0),
            ghost_sized_file("/etc/foo.link", RPMFILE_GHOST, 0o120777, 16),
            ghost_sized_file("/etc/food", RPMFILE_GHOST, 0o40755, 0),
            ghost_sized_file("/etc/foo.conf", RPMFILE_CONFIG, 0o100644, 29),
            ghost_sized_file("/var/lib/foo/state", RPMFILE_GHOST, 0o100644, 128),
        ];
        for f in &quiet {
            assert!(
                !ghost_buildroot_content_fires(f, ""),
                "must stay quiet: {}",
                f.name
            );
        }
        // A %config ghost whose %post writes the path literally is
        // credited (xrdp's regenerated key, audit-rules,
        // crypto-policies): the content is recreated at install time.
        let named = ghost_sized_file(
            "/etc/xrdp/rsakeys.ini",
            RPMFILE_GHOST | RPMFILE_CONFIG,
            0o100600,
            2939,
        );
        let post = "[ -f /etc/xrdp/rsakeys.ini ] || openssl genrsa -out /etc/xrdp/rsakeys.ini";
        assert!(
            !ghost_buildroot_content_fires(&named, post),
            "a scriptlet naming the path literally credits it"
        );
        // texlive's ls-R: the %post regenerates the file for every
        // texmf tree through a computed directory, appending the path
        // tail to the expansion.
        let tex = ghost_sized_file(
            "/etc/texmf/ls-R",
            RPMFILE_GHOST | RPMFILE_CONFIG,
            0o100664,
            67,
        );
        let tex_post = "for dir in /etc/texmf /var/lib/texmf; do \
            echo x > ${dir}/ls-R; done";
        assert!(
            !ghost_buildroot_content_fires(&tex, tex_post),
            "a path tail appended to a variable expansion credits it"
        );
        // The unbraced expansion form credits the same way.
        assert!(
            !ghost_buildroot_content_fires(&tex, "echo x > $dir/ls-R"),
            "an unbraced variable expansion credits the tail"
        );
        // A quoted literal names the path: the quotes are token
        // boundaries, not path characters.
        let named_post = "[ -f \"/etc/xrdp/rsakeys.ini\" ] || \
            openssl genrsa -out \"/etc/xrdp/rsakeys.ini\"";
        assert!(
            !ghost_buildroot_content_fires(&named, named_post),
            "a quoted literal names the path"
        );
    }

    #[test]
    fn ghost_buildroot_content_compiled_cache() {
        // The SELinux shape: the .bin ghost's source ships next to it,
        // so the cache is a derived form of shipped content.
        let cache = ghost_sized_file(
            "/etc/selinux/targeted/contexts/files/file_contexts.bin",
            RPMFILE_GHOST,
            0o100644,
            5_335_108,
        );
        let source = ghost_sized_file(
            "/etc/selinux/targeted/contexts/files/file_contexts",
            0,
            0o100644,
            5_000_000,
        );
        let (pkg, _dir) = pkg_with_files(vec![source, cache.clone()]);
        assert!(compiled_cache_of_shipped_source(&pkg, &cache));
        let hits: Vec<_> = run_check_binary(&pkg)
            .into_iter()
            .filter(|(n, _)| n == "ghost-file-with-buildroot-content")
            .collect();
        assert!(hits.is_empty(), "compiled cache must stay quiet: {hits:?}");
        // Without the shipped source the same ghost fires.
        let (pkg2, _dir2) = pkg_with_files(vec![cache]);
        let hits2: Vec<_> = run_check_binary(&pkg2)
            .into_iter()
            .filter(|(n, _)| n == "ghost-file-with-buildroot-content")
            .collect();
        assert_eq!(hits2.len(), 1, "orphan cache must fire: {hits2:?}");
    }

    #[test]
    fn ghost_buildroot_content_emission() {
        // The forgejo shape end to end: the merged %config(noreplace)
        // %ghost over a filled file fires once, with path and byte
        // count; the touched ghost next to it stays quiet.
        let (pkg, _dir) = pkg_with_files(vec![
            ghost_sized_file(
                "/etc/forgejo-runner/config.yaml",
                RPMFILE_GHOST | RPMFILE_CONFIG | RPMFILE_NOREPLACE,
                0o100640,
                22,
            ),
            ghost_sized_file("/etc/forgejo-runner/cache", RPMFILE_GHOST, 0o100644, 0),
        ]);
        let hits: Vec<_> = run_check_binary(&pkg)
            .into_iter()
            .filter(|(n, _)| n == "ghost-file-with-buildroot-content")
            .collect();
        assert_eq!(hits.len(), 1, "expected 1 finding, got: {hits:?}");
        let (_, line) = &hits[0];
        assert!(line.contains(": W: "), "must be Warning level: {line}");
        assert!(
            line.contains("/etc/forgejo-runner/config.yaml") && line.contains("22"),
            "detail must carry path and byte count: {line}"
        );
    }

    #[test]
    fn zero_perms_ghost_uses_tmpfiles_suggestion() {
        // Mirrors the reference's test_files_without_perms_tmpfiles: the
        // suggestion's perms/user/group come from the tmpfiles.d config,
        // not from a static string. Non-default 0640/netdev/netdev pins
        // that the values are read, not defaulted.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let conf_path = dir.path().join("netconfig.conf");
        std::fs::write(
            &conf_path,
            "d /run/netconfig 0755 root group -\n\
             f /run/netconfig/resolv.conf 0640 netdev netdev -\n",
        )
        .expect("write tmpfiles conf");
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture");
        pkg.files = vec![
            PkgFile {
                name: "/run/netconfig".to_string(),
                path: "/run/netconfig".to_string(),
                mode: 0,
                flags: RPMFILE_GHOST,
                ..Default::default()
            },
            PkgFile {
                name: "/run/netconfig/resolv.conf".to_string(),
                path: "/run/netconfig/resolv.conf".to_string(),
                mode: 0,
                flags: RPMFILE_GHOST,
                ..Default::default()
            },
            PkgFile {
                name: "/usr/lib/tmpfiles.d/netconfig.conf".to_string(),
                path: conf_path.to_string_lossy().into_owned(),
                ..Default::default()
            },
        ];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let hits: Vec<_> = out
            .results()
            .iter()
            .filter(|(n, _)| n == "zero-perms-ghost")
            .map(|(_, d)| d.clone())
            .collect();
        assert_eq!(hits.len(), 2, "expected 2 findings, got: {hits:?}");
        assert!(
            hits.iter()
                .any(|d| d.contains("W: zero-perms-ghost Suggestion: \"%ghost %attr(0640,netdev,netdev) /run/netconfig/resolv.conf\"")),
            "suggestion must use tmpfiles.d perms: {hits:?}"
        );
        assert!(
            hits.iter().any(|d| d.contains(
                "W: zero-perms-ghost Suggestion: \"%ghost %attr(0755,root,group) /run/netconfig\""
            )),
            "suggestion must use tmpfiles.d perms: {hits:?}"
        );
    }

    #[test]
    fn debug_path_segment_match_11() {
        assert!(is_debug_path("/usr/lib/debug/foo.debug"));
        assert!(is_debug_path("/usr/lib/debug"));
        assert!(is_debug_path("/usr/src/debug/foo.c"));
        assert!(is_debug_path("/usr/src/debug"));
        assert!(!is_debug_path("/usr/lib64/debug"));
        assert!(!is_debug_path("/usr/bin/foo"));
        assert!(!is_debug_path("/usr/share/debugfoo/bar"));
        assert!(!is_debug_path("/usr/lib/debugfoo/x"));
        // Coincidental `debug` segments elsewhere are not debug payload.
        assert!(!is_debug_path("/usr/share/doc/debug/notes"));
    }

    #[test]
    fn debug_files_in_non_debug_package_warns_11() {
        // Real emission path (check_binary -> add_info); the rendered line
        // pins name, level and detail together.
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/lib/debug/foo.debug", 0o100644, 21),
            mkfile("/usr/bin/foo", 0o100755, 22),
        ]);
        let results = run_check_binary(&pkg);
        let line = results
            .iter()
            .find(|(n, _)| n == "debug-files-in-non-debug-package")
            .map(|(_, l)| l.clone())
            .expect("debug-files-in-non-debug-package should fire");
        assert!(
            line.contains(": W: debug-files-in-non-debug-package /usr/lib/debug/foo.debug"),
            "name, level and detail must render, got: {line}"
        );
        assert_eq!(
            results
                .iter()
                .filter(|(n, _)| n == "debug-files-in-non-debug-package")
                .count(),
            1,
            "only the debug path warns: {results:?}"
        );
    }

    #[test]
    fn zero_perms_ghost_falls_back_without_tmpfiles() {
        // No tmpfiles.d config declaring the path: defaults 0644/root/root.
        let config = test_config();
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture");
        pkg.files = vec![PkgFile {
            name: "/var/cache/ghost.dat".to_string(),
            path: "/var/cache/ghost.dat".to_string(),
            mode: 0,
            flags: RPMFILE_GHOST,
            ..Default::default()
        }];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let line = out
            .results()
            .iter()
            .find(|(n, _)| n == "zero-perms-ghost")
            .map(|(_, d)| d.clone())
            .expect("zero-perms-ghost must fire");
        assert_eq!(
            out.results()
                .iter()
                .filter(|(n, _)| n == "zero-perms-ghost")
                .count(),
            1,
            "exactly one zero-perms-ghost finding: {line}"
        );
        assert!(
            line.contains("W: zero-perms-ghost Suggestion: \"%ghost %attr(0644,root,root) /var/cache/ghost.dat\""),
            "suggestion must use defaults: {line}"
        );
    }

    #[test]
    fn zero_perms_ghost_tool_managed_paths_are_quiet() {
        // Every credited shape: the alternatives admin dir, the SELinux
        // policy store, tool-generated caches, and the kernel boot
        // symlinks. None of these entries owns its permissions.
        let (pkg, _dir) = pkg_with_files(vec![
            ghost_sized_file("/etc/alternatives/foo", RPMFILE_GHOST, 0, 0),
            ghost_sized_file(
                "/etc/selinux/targeted/active/modules/200/foo",
                RPMFILE_GHOST,
                0,
                0,
            ),
            ghost_sized_file("/usr/share/icons/Arc/icon-theme.cache", RPMFILE_GHOST, 0, 0),
            ghost_sized_file(
                "/usr/share/fonts/truetype/encodings.dir",
                RPMFILE_GHOST,
                0,
                0,
            ),
            ghost_sized_file("/usr/share/fonts/truetype/fonts.scale", RPMFILE_GHOST, 0, 0),
            ghost_sized_file(
                "/usr/share/fonts/truetype/.fonts-config-timestamp",
                RPMFILE_GHOST,
                0,
                0,
            ),
            ghost_sized_file("/usr/share/info/dir", RPMFILE_GHOST, 0, 0),
            ghost_sized_file("/boot/vmlinuz", RPMFILE_GHOST, 0, 0),
            ghost_sized_file("/boot/initrd", RPMFILE_GHOST, 0, 0),
        ]);
        let hits: Vec<_> = run_check_binary(&pkg)
            .into_iter()
            .filter(|(n, _)| n == "zero-perms-ghost")
            .collect();
        assert!(
            hits.is_empty(),
            "tool-managed ghosts must stay quiet: {hits:?}"
        );
    }

    #[test]
    fn zero_perms_ghost_lookalikes_still_fire() {
        // Prefix boundaries and exact basenames: a lookalike path is
        // not the managed shape, so the warning stands.
        let (pkg, _dir) = pkg_with_files(vec![
            ghost_sized_file("/etc/alternativesX/foo", RPMFILE_GHOST, 0, 0),
            ghost_sized_file("/etc/selinux/config", RPMFILE_GHOST, 0, 0),
            ghost_sized_file("/usr/share/icons/Arc/foo.txt", RPMFILE_GHOST, 0, 0),
            ghost_sized_file("/boot/vmlinuz-7.3.0", RPMFILE_GHOST, 0, 0),
        ]);
        let hits: Vec<_> = run_check_binary(&pkg)
            .into_iter()
            .filter(|(n, _)| n == "zero-perms-ghost")
            .collect();
        assert_eq!(hits.len(), 4, "lookalikes must all fire: {hits:?}");
    }

    #[test]
    fn zero_perms_ghost_dir_fallback_suggests_0755() {
        // No tmpfiles.d entry declares the path, and the entry is a
        // directory: the fallback must be traversable.
        let (pkg, _dir) = pkg_with_files(vec![ghost_sized_file(
            "/run/cockpit",
            RPMFILE_GHOST,
            0o40000,
            0,
        )]);
        let line = run_check_binary(&pkg)
            .into_iter()
            .find(|(n, _)| n == "zero-perms-ghost")
            .map(|(_, l)| l)
            .expect("zero-perms-ghost must fire for the directory");
        assert!(
            line.contains(
                "W: zero-perms-ghost Suggestion: \"%ghost %attr(0755,root,root) /run/cockpit\""
            ),
            "directory fallback must be 0755: {line}"
        );
    }

    #[test]
    fn scriptlet_creates_symlink_literal_loop_and_negatives() {
        assert!(scriptlet_creates_symlink(
            "ln -sf /usr/bin/alts /usr/bin/javac\n",
            "/usr/bin/javac"
        ));
        assert!(!scriptlet_creates_symlink(
            "ln -sf /usr/bin/alts /usr/bin/javac\n",
            "/usr/bin/jar"
        ));
        let looped = "for i in javac jar javadoc; do\n  if ! [ -e /usr/bin/${i} ]; then\n    ln -sf /usr/bin/alts /usr/bin/${i}\n  fi\ndone\n";
        assert!(scriptlet_creates_symlink(looped, "/usr/bin/jar"));
        assert!(!scriptlet_creates_symlink(looped, "/usr/bin/java"));
        // A hard link is not a symlink.
        assert!(!scriptlet_creates_symlink("ln -f /a /b\n", "/b"));
        // Multi-target form: the link is a directory join, not the
        // argument itself.
        assert!(!scriptlet_creates_symlink("ln -sf /a /b /dir\n", "/b"));
        // -t form skipped for the same reason.
        assert!(!scriptlet_creates_symlink("ln -s -t /dir /a\n", "/a"));
        // Loop variable mismatch.
        assert!(!scriptlet_creates_symlink(
            "for j in a b; do ln -sf /t /d/${i}; done\n",
            "/d/a"
        ));
    }

    #[test]
    fn debug_files_in_debuginfo_package_are_quiet_11() {
        let (mut pkg, _dir) =
            pkg_with_files(vec![mkfile("/usr/lib/debug/foo.debug", 0o100644, 21)]);
        pkg.name = "foo-debuginfo".to_string();
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "debug-files-in-non-debug-package"),
            "debuginfo packages must stay quiet: {results:?}"
        );
    }

    #[test]
    fn debug_files_in_legacy_debug_package_are_quiet() {
        // Legacy -debug suffix (e.g. qemu-ovmf-x86_64-debug) must also be
        // recognized as a debuginfo package.
        let (mut pkg, _dir) =
            pkg_with_files(vec![mkfile("/usr/lib/debug/foo.debug", 0o100644, 21)]);
        pkg.name = "foo-debug".to_string();
        let results = run_check_binary(&pkg);
        assert_eq!(
            results
                .iter()
                .filter(|(n, _)| n == "debug-files-in-non-debug-package")
                .count(),
            0,
            "legacy -debug packages must stay quiet: {results:?}"
        );
    }

    #[test]
    fn empty_debuginfo_package_fires_for_legacy_debug_suffix() {
        // The empty-debuginfo-package side effect also applies to the legacy
        // -debug suffix, not only to -debuginfo.
        let (mut pkg, _dir) = pkg_with_files(vec![]);
        pkg.name = "foo-debug".to_string();
        let results = run_check_binary(&pkg);
        assert_eq!(
            results
                .iter()
                .filter(|(n, _)| n == "empty-debuginfo-package")
                .count(),
            1,
            "empty legacy -debug package must fire empty-debuginfo-package: {results:?}"
        );
    }

    #[test]
    fn debug_files_ghost_is_quiet_11() {
        // A %ghost debug path has no payload on disk: nothing lands in
        // the package, so the warning must stay quiet.
        let (mut pkg, _dir) =
            pkg_with_files(vec![mkfile("/usr/lib/debug/foo.debug", 0o100644, 21)]);
        pkg.ghost_files.push("/usr/lib/debug/foo.debug".to_string());
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "debug-files-in-non-debug-package"),
            "ghost debug paths must stay quiet: {results:?}"
        );
    }

    #[test]
    fn manifest_in_perl_module_matches_reference_regex() {
        // Issue #385: the port used fname.contains("/perl"), firing on
        // /usr/share/doc/packages/perl-*/MANIFEST (21 false positives in
        // the Factory audit). The reference manifest_perl_regex only
        // matches a doc dir literally named perl-*.
        for (path, should_fire) in [
            ("/usr/share/doc/perl-Foo/MANIFEST", true),
            ("/usr/share/doc/perl-Foo/MANIFEST.SKIP", true),
            ("/usr/share/doc/perl-Foo/sub/MANIFEST", true),
            (
                "/usr/share/doc/packages/perl-Apache-SessionX/MANIFEST",
                false,
            ),
            (
                "/usr/share/doc/packages/perl-Apache-SessionX/MANIFEST.SKIP",
                false,
            ),
            ("/usr/share/doc/perl-Foo/README", false),
            ("/usr/share/doc/packages/perl-Foo/MANIFEST", false),
        ] {
            let (pkg, _dir) = pkg_with_files(vec![mkfile(path, 0o100644, 1)]);
            let results = run_check_binary(&pkg);
            let fired = results.iter().any(|(n, _)| n == "manifest-in-perl-module");
            assert_eq!(fired, should_fire, "path {path}");
        }
    }

    #[test]
    fn manpage_so_targets_parsing() {
        let text = ".so man3/popen.3\n.so\tman1/foo.1 trailing\n.\\\" .so man1/no.1\n.so\n.sox man1/no.1\nplain text\n.so man2/bar.2\n";
        assert_eq!(
            manpage_so_targets(text),
            vec![
                "man3/popen.3".to_string(),
                "man1/foo.1".to_string(),
                "man2/bar.2".to_string()
            ]
        );
        assert!(manpage_so_targets("").is_empty());
    }

    #[test]
    fn manpage_so_root_relative_forms() {
        assert_eq!(
            manpage_so_root_relative("man3/popen.3"),
            Some("man3/popen.3".to_string())
        );
        assert_eq!(
            manpage_so_root_relative("mann/intro.n"),
            Some("mann/intro.n".to_string())
        );
        assert_eq!(
            manpage_so_root_relative("/usr/share/man/man3/popen.3"),
            Some("man3/popen.3".to_string())
        );
        assert_eq!(
            manpage_so_root_relative("/usr/man/man1/x.1"),
            Some("man1/x.1".to_string())
        );
        // Multi-letter section directories resolve under the loose
        // shape (first byte a digit or `n`, arbitrary tail).
        assert_eq!(
            manpage_so_root_relative("man3pm/x.3pm"),
            Some("man3pm/x.3pm".to_string())
        );
        assert_eq!(
            manpage_so_root_relative("man3tcl/x.3tcl"),
            Some("man3tcl/x.3tcl".to_string())
        );
        assert_eq!(manpage_so_root_relative("/etc/passwd"), None);
        assert_eq!(manpage_so_root_relative("popen.3"), None);
        assert_eq!(manpage_so_root_relative("otherdir/x.1"), None);
    }

    #[test]
    fn manpage_so_root_relative_rejects_man_prefixed_dirs() {
        // The first directory must carry the loose section shape
        // (a digit or `n` first), not just the `man` prefix:
        // `manual/` and `management/` name no man page (issue #672).
        assert_eq!(manpage_so_root_relative("manual/x.1"), None);
        assert_eq!(manpage_so_root_relative("management/x.1"), None);
        assert_eq!(manpage_so_root_relative("manx/x.1"), None);
        assert_eq!(
            manpage_so_root_relative("man1p/x.1p"),
            Some("man1p/x.1p".to_string())
        );
        assert_eq!(
            manpage_so_root_relative("man3p/x.3p"),
            Some("man3p/x.3p".to_string())
        );
    }

    #[test]
    fn strip_man_compression_suffix_cases() {
        assert_eq!(
            strip_man_compression_suffix("/usr/share/man/man3/popen.3.gz"),
            "/usr/share/man/man3/popen.3"
        );
        assert_eq!(
            strip_man_compression_suffix("/usr/share/man/man3/popen.3.zst"),
            "/usr/share/man/man3/popen.3"
        );
        assert_eq!(
            strip_man_compression_suffix("/usr/share/man/man3/popen.3"),
            "/usr/share/man/man3/popen.3"
        );
        assert_eq!(
            strip_man_compression_suffix("/usr/share/man/man3/popen.3x"),
            "/usr/share/man/man3/popen.3x"
        );
    }

    /// Build a package whose files carry real on-disk content, so the
    /// man page `.so` scan reads actual bytes: `(name, mode, content)`
    /// triples written under a fresh tempdir.
    fn manpage_pkg(dir: &tempfile::TempDir, files: &[(&str, u32, &[u8])]) -> Pkg {
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        pkg.files = files
            .iter()
            .map(|(name, mode, content)| {
                let path = dir.path().join(name.trim_start_matches('/'));
                std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
                std::fs::write(&path, content).expect("write temp file");
                PkgFile {
                    name: name.to_string(),
                    path: path.to_string_lossy().into_owned(),
                    mode: *mode,
                    user: "root".to_string(),
                    group: "root".to_string(),
                    ..Default::default()
                }
            })
            .collect();
        pkg
    }

    fn so_ref_hits(results: &[(String, String)]) -> Vec<&(String, String)> {
        results
            .iter()
            .filter(|(n, _)| n == "manpage-dangling-so-ref")
            .collect()
    }

    #[test]
    fn manpage_so_ref_missing_target_fires_warning() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[(
                "/usr/share/man/man3/alias.3",
                0o100644,
                b".so man3/popen.3\n".as_slice(),
            )],
        );
        let results = run_check_binary(&pkg);
        let hits = so_ref_hits(&results);
        assert_eq!(
            hits.len(),
            1,
            "one missing .so target must fire once: {results:?}"
        );
        assert!(
            hits[0].1.contains(": W: manpage-dangling-so-ref"),
            "the finding is a warning: {}",
            hits[0].1
        );
        assert!(
            hits[0].1.contains("/usr/share/man/man3/alias.3"),
            "the detail names the referencing page: {}",
            hits[0].1
        );
        assert!(
            hits[0].1.contains("man3/popen.3"),
            "the detail names the missing target: {}",
            hits[0].1
        );
    }

    #[test]
    fn manpage_so_ref_required_target_is_quiet() {
        // The `req_names` escape (issue #672): a file Require on the
        // target page's path declares the sibling dependency, so the
        // reference is satisfied even though this package does not
        // ship the target — the escape `check_link_absolute` uses.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = manpage_pkg(
            &dir,
            &[(
                "/usr/share/man/man3/alias.3",
                0o100644,
                b".so man3/popen.3\n".as_slice(),
            )],
        );
        pkg.req_names
            .push("/usr/share/man/man3/popen.3".to_string());
        let results = run_check_binary(&pkg);
        assert!(
            so_ref_hits(&results).is_empty(),
            "a required target satisfies the reference: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_required_compressed_target_is_quiet() {
        // A file Require names the target as the sibling package
        // ships it — compressed (popen.3.gz) — while the resolved
        // candidate is suffix-stripped; the escape must strip the
        // Require side too, or it never matches a compressed target
        // (issue #672).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = manpage_pkg(
            &dir,
            &[(
                "/usr/share/man/man3/alias.3",
                0o100644,
                b".so man3/popen.3\n".as_slice(),
            )],
        );
        pkg.req_names
            .push("/usr/share/man/man3/popen.3.gz".to_string());
        let results = run_check_binary(&pkg);
        assert!(
            so_ref_hits(&results).is_empty(),
            "a required compressed target satisfies the reference: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_usr_man_root_candidate_is_quiet() {
        // Both man roots are accepted for both argument forms
        // (issue #672): an absolute `/usr/man` argument is satisfied
        // by the target shipped under `/usr/share/man`.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                (
                    "/usr/share/man/man1/alias.1",
                    0o100644,
                    b".so /usr/man/man1/real.1\n".as_slice(),
                ),
                (
                    "/usr/share/man/man1/real.1",
                    0o100644,
                    b".TH real 1\n".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        assert!(
            so_ref_hits(&results).is_empty(),
            "the /usr/man root candidate resolves: {results:?}"
        );
    }

    fn class_tag_hits(results: &[(String, String)]) -> Vec<&(String, String)> {
        results
            .iter()
            .filter(|(n, _)| n == "corrupt-class-file")
            .collect()
    }

    #[test]
    fn standalone_class_header_defects_fire() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                (
                    "/usr/share/java/Good.class",
                    0o100644,
                    b"\xCA\xFE\xBA\xBE\x00\x00\x00\x34good-body".as_slice(),
                ),
                (
                    "/usr/share/java/Bad.class",
                    0o100644,
                    b"NOPE-not-a-class-file-body".as_slice(),
                ),
                (
                    "/usr/share/java/Short.class",
                    0o100644,
                    b"\xCA\xFE\xBA\xBE\x00\x00".as_slice(),
                ),
                ("/usr/share/java/Empty.class", 0o100644, b"".as_slice()),
                (
                    "/usr/share/java/Old.class",
                    0o100644,
                    b"\xCA\xFE\xBA\xBE\x00\x00\x00\x2Bold-body".as_slice(),
                ),
                (
                    "/usr/share/java/Fake.class.txt",
                    0o100644,
                    b"NOPE-not-a-class-file-body".as_slice(),
                ),
                (
                    "/usr/share/java/Link.class",
                    0o120777,
                    b"NOPE-not-a-class-file-body".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        let hits = class_tag_hits(&results);
        assert_eq!(hits.len(), 3, "bad, short and empty only: {results:?}");
        assert!(
            hits.iter()
                .all(|(_, line)| line.contains(": W: corrupt-class-file")),
            "the findings are warnings: {results:?}"
        );
        let lines: Vec<&str> = hits.iter().map(|(_, line)| line.as_str()).collect();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("Bad.class") && l.contains("bad magic"))
                && lines
                    .iter()
                    .any(|l| l.contains("Short.class") && l.contains("truncated header: 6 bytes"))
                && lines
                    .iter()
                    .any(|l| l.contains("Empty.class") && l.contains("truncated header: 0 bytes")),
            "each defect named with its reason: {results:?}"
        );
    }

    fn gzip_bytes(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn bzip2_bytes(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn manpage_tag_hits<'a>(
        results: &'a [(String, String)],
        tag: &str,
    ) -> Vec<&'a (String, String)> {
        results.iter().filter(|(n, _)| n == tag).collect()
    }

    #[test]
    fn manpage_gz_without_gzip_magic_fires_mismatch_only() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                (
                    "/usr/share/man/man1/plain.1.gz",
                    0o100644,
                    b".TH plain 1\n".as_slice(),
                ),
                (
                    "/usr/share/man/man1/tiny.1.gz",
                    0o100644,
                    b"\x1f".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        let mismatch = manpage_tag_hits(&results, "manpage-gzip-magic-mismatch");
        assert_eq!(mismatch.len(), 2, "both magic-less pages: {results:?}");
        assert!(
            mismatch[0].1.contains(": W: manpage-gzip-magic-mismatch"),
            "the finding is a warning: {}",
            mismatch[0].1
        );
        assert!(
            mismatch.iter().any(|(_, line)| line.contains("plain.1.gz"))
                && mismatch.iter().any(|(_, line)| line.contains("tiny.1.gz")),
            "both pages named: {results:?}"
        );
        assert!(
            manpage_tag_hits(&results, "manpage-empty-after-decompression").is_empty(),
            "a page without magic fails decompression, so it does not also read as empty: {results:?}"
        );
    }

    #[test]
    fn manpage_gz_empty_after_decompression_fires_empty_only() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let good = gzip_bytes(b".TH good 1\n");
        let empty = gzip_bytes(b"");
        let pkg = manpage_pkg(
            &dir,
            &[
                ("/usr/share/man/man1/good.1.gz", 0o100644, &good),
                ("/usr/share/man/man1/empty.1.gz", 0o100644, &empty),
            ],
        );
        let results = run_check_binary(&pkg);
        let empty_hits = manpage_tag_hits(&results, "manpage-empty-after-decompression");
        assert_eq!(empty_hits.len(), 1, "only the empty page: {results:?}");
        assert!(
            empty_hits[0]
                .1
                .contains(": W: manpage-empty-after-decompression"),
            "the finding is a warning: {}",
            empty_hits[0].1
        );
        assert!(
            empty_hits[0].1.contains("empty.1.gz"),
            "the detail names the page: {}",
            empty_hits[0].1
        );
        assert!(
            manpage_tag_hits(&results, "manpage-gzip-magic-mismatch").is_empty(),
            "valid magic stays quiet on mismatch: {results:?}"
        );
    }

    #[test]
    fn manpage_uncompressed_and_non_man_gz_pages_do_not_double_fire() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                (
                    "/usr/share/man/man1/plain.1",
                    0o100644,
                    b".TH plain 1\n".as_slice(),
                ),
                (
                    "/usr/share/doc/foo.txt.gz",
                    0o100644,
                    b"plain text, not gzip\n".as_slice(),
                ),
                (
                    "/usr/share/foo.1.gz",
                    0o100644,
                    b"plain text, not gzip\n".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        assert!(
            manpage_tag_hits(&results, "manpage-gzip-magic-mismatch").is_empty()
                && manpage_tag_hits(&results, "manpage-empty-after-decompression").is_empty(),
            "neither new tag fires outside .gz man pages: {results:?}"
        );
        assert_eq!(
            manpage_tag_hits(&results, "manpage-not-compressed").len(),
            1,
            "the uncompressed page stays under the existing rule: {results:?}"
        );
    }

    #[test]
    fn manpage_bz2_empty_after_decompression_fires_without_mismatch() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let empty = bzip2_bytes(b"");
        let pkg = manpage_pkg(
            &dir,
            &[("/usr/share/man/man1/empty.1.bz2", 0o100644, &empty)],
        );
        let results = run_check_binary(&pkg);
        assert_eq!(
            manpage_tag_hits(&results, "manpage-empty-after-decompression").len(),
            1,
            "the empty predicate covers every compressed suffix: {results:?}"
        );
        assert!(
            manpage_tag_hits(&results, "manpage-gzip-magic-mismatch").is_empty(),
            "the magic predicate is .gz-only: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_zip_page_is_skipped() {
        // `.zip` is a recognised man page compression suffix with no
        // decompressor: the page is skipped rather than scanned as
        // raw text (issue #672).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[(
                "/usr/share/man/man3/alias.3.zip",
                0o100644,
                b".so man3/popen.3\n".as_slice(),
            )],
        );
        let results = run_check_binary(&pkg);
        assert!(
            so_ref_hits(&results).is_empty(),
            "an undecompressible .zip page must not be scanned as text: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_unreadable_page_is_skipped() {
        // A page whose content cannot be read is skipped, not judged
        // (issue #672).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[(
                "/usr/share/man/man3/alias.3",
                0o100644,
                b".so man3/popen.3\n".as_slice(),
            )],
        );
        std::fs::remove_file(&pkg.files[0].path).expect("remove page content");
        let results = run_check_binary(&pkg);
        assert!(
            so_ref_hits(&results).is_empty(),
            "an unreadable page is skipped: {results:?}"
        );
    }

    /// Write an executable fake tool `name` holding `script` under a
    /// fresh tempdir and return the dir.
    fn fake_tool_dir(name: &str, script: &str) -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().expect("tool tmpdir");
        let tool = dir.path().join(name);
        std::fs::write(&tool, script).expect("write fake tool");
        let mut perms = std::fs::metadata(&tool)
            .expect("stat fake tool")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tool, perms).expect("chmod fake tool");
        dir
    }

    #[test]
    fn manpage_so_ref_absent_decompressor_skips_page() {
        // No gzip in the tool dir: the `.gz` page cannot be read, so
        // it is skipped rather than guessed at (issue #672).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let empty = tempfile::TempDir::new().expect("empty tool dir");
        let pkg = manpage_pkg(
            &dir,
            &[(
                "/usr/share/man/man3/alias.3.gz",
                0o100644,
                b".so man3/popen.3\n".as_slice(),
            )],
        );
        let config = test_config();
        let mut check = FilesCheck::with_tool_dir(&config, Some(empty.path()));
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        assert!(
            so_ref_hits(&results).is_empty(),
            "a page whose decompressor is absent is skipped: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_failing_decompressor_skips_page() {
        // A decompressor that exits non-zero leaves the page
        // unreadable: skipped, not guessed at (issue #672).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let tools = fake_tool_dir("gzip", "#!/bin/sh\nexit 1\n");
        let pkg = manpage_pkg(
            &dir,
            &[(
                "/usr/share/man/man3/alias.3.gz",
                0o100644,
                b"not really gzip".as_slice(),
            )],
        );
        let config = test_config();
        let mut check = FilesCheck::with_tool_dir(&config, Some(tools.path()));
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        assert!(
            so_ref_hits(&results).is_empty(),
            "a page whose decompressor fails is skipped: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_over_limit_output_hides_late_targets() {
        // Decompressed output is capped at the man page text limit: a
        // `.so` line past the cap is never seen, so nothing fires;
        // the same line ahead of the cap fires as usual (issue #672).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[(
                "/usr/share/man/man3/alias.3.gz",
                0o100644,
                b"not really gzip".as_slice(),
            )],
        );
        let filler = "head -c 9000000 /dev/zero | tr '\\0' 'x'";
        for (script, expect_hits) in [
            (
                format!("#!/bin/sh\n{filler}\nprintf '\\n.so man3/popen.3\\n'\n"),
                0,
            ),
            (
                format!("#!/bin/sh\nprintf '.so man3/popen.3\\n'\n{filler}\n"),
                1,
            ),
        ] {
            let tools = fake_tool_dir("gzip", &script);
            let config = test_config();
            let mut check = FilesCheck::with_tool_dir(&config, Some(tools.path()));
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_binary(&pkg, &config, &mut out);
            let results = out.results().to_vec();
            assert_eq!(
                so_ref_hits(&results).len(),
                expect_hits,
                "over-limit output handling: {results:?}"
            );
        }
    }

    #[test]
    fn manpage_so_ref_shipped_target_is_quiet() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                (
                    "/usr/share/man/man3/alias.3",
                    0o100644,
                    b".so man3/popen.3\n".as_slice(),
                ),
                (
                    "/usr/share/man/man3/popen.3",
                    0o100644,
                    b".TH popen 3\n".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        assert!(
            so_ref_hits(&results).is_empty(),
            "a shipped uncompressed target satisfies the reference: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_shipped_gz_target_is_quiet() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                (
                    "/usr/share/man/man3/alias.3",
                    0o100644,
                    b".so man3/popen.3\n".as_slice(),
                ),
                (
                    "/usr/share/man/man3/popen.3.gz",
                    0o100644,
                    b"compressed\n".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        assert!(
            so_ref_hits(&results).is_empty(),
            "a shipped .gz target satisfies the reference: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_shipped_xz_target_is_quiet() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                (
                    "/usr/share/man/man3/alias.3",
                    0o100644,
                    b".so man3/popen.3\n".as_slice(),
                ),
                (
                    "/usr/share/man/man3/popen.3.xz",
                    0o100644,
                    b"compressed\n".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        assert!(
            so_ref_hits(&results).is_empty(),
            "a shipped .xz target satisfies the reference: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_locale_page_resolves_against_man_root() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                (
                    "/usr/share/man/de/man1/alias.1",
                    0o100644,
                    b".so man1/real.1\n".as_slice(),
                ),
                (
                    "/usr/share/man/man1/real.1.gz",
                    0o100644,
                    b"compressed\n".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        assert!(
            so_ref_hits(&results).is_empty(),
            "a locale page resolves its target against the man root: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_locale_target_in_same_locale_is_quiet() {
        // Localised page sets keep their redirect targets in the same
        // locale directory: a target shipped solely under the
        // referencing page's locale directory satisfies the reference.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                (
                    "/usr/share/man/de/man1/alias.1",
                    0o100644,
                    b".so man1/real.1\n".as_slice(),
                ),
                (
                    "/usr/share/man/de/man1/real.1.gz",
                    0o100644,
                    b"compressed\n".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        assert!(
            so_ref_hits(&results).is_empty(),
            "a same-locale target satisfies the reference: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_locale_target_in_other_locale_fires() {
        // Only the referencing page's own locale directory counts: a
        // target shipped under a different locale does not satisfy it.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                (
                    "/usr/share/man/de/man1/alias.1",
                    0o100644,
                    b".so man1/real.1\n".as_slice(),
                ),
                (
                    "/usr/share/man/fr/man1/real.1.gz",
                    0o100644,
                    b"compressed\n".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        assert_eq!(
            so_ref_hits(&results).len(),
            1,
            "a target in another locale does not resolve the reference: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_bare_target_resolves_in_page_directory() {
        // A bare filename names a page in the referencing page's own
        // directory (the systemd/pmem stub shape).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                (
                    "/usr/share/man/man3/alias.3",
                    0o100644,
                    b".so popen.3\n.so missing.3\n".as_slice(),
                ),
                (
                    "/usr/share/man/man3/popen.3.gz",
                    0o100644,
                    b"compressed\n".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        let hits = so_ref_hits(&results);
        assert_eq!(
            hits.len(),
            1,
            "only the missing bare target fires: {results:?}"
        );
        assert!(
            hits[0].1.contains("missing.3"),
            "the detail names the missing bare target: {}",
            hits[0].1
        );
    }

    #[test]
    fn manpage_so_ref_symlink_target_counts_as_shipped() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                (
                    "/usr/share/man/man3/alias.3",
                    0o100644,
                    b".so man3/popen.3\n".as_slice(),
                ),
                (
                    "/usr/share/man/man3/popen.3.gz",
                    0o120777,
                    b"compressed\n".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        assert!(
            so_ref_hits(&results).is_empty(),
            "a target shipped as a symlink counts as shipped: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_comments_and_non_requests_are_quiet() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[(
                "/usr/share/man/man1/quiet.1",
                0o100644,
                b".\\\" .so man1/ghost.1\n.TH quiet 1\n.so\n.sox man1/ghost.1\nplain .so man1/ghost.1\n"
                    .as_slice(),
            )],
        );
        let results = run_check_binary(&pkg);
        assert!(
            so_ref_hits(&results).is_empty(),
            "comments, argument-less requests and prose name no target: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_ignores_non_man_files() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                ("/usr/bin/foo", 0o100755, b".so man1/ghost.1\n".as_slice()),
                (
                    "/usr/share/doc/foo/README",
                    0o100644,
                    b".so man1/ghost.1\n".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        assert!(
            so_ref_hits(&results).is_empty(),
            "only man pages are scanned for .so references: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_absolute_form() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                (
                    "/usr/share/man/man3/alias.3",
                    0o100644,
                    b".so /usr/share/man/man3/popen.3\n.so /usr/share/man/man1/missing.1\n"
                        .as_slice(),
                ),
                (
                    "/usr/share/man/man3/popen.3",
                    0o100644,
                    b".TH popen 3\n".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        let hits = so_ref_hits(&results);
        assert_eq!(
            hits.len(),
            1,
            "only the missing absolute target fires: {results:?}"
        );
        assert!(
            hits[0].1.contains("/usr/share/man/man1/missing.1"),
            "the detail names the missing absolute target: {}",
            hits[0].1
        );
    }

    #[test]
    fn manpage_so_ref_one_finding_per_missing_target() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[(
                "/usr/share/man/man1/alias.1",
                0o100644,
                b".so man1/a.1\n.so man1/a.1\n.so man1/a.1.gz\n.so man1/b.1\n".as_slice(),
            )],
        );
        let results = run_check_binary(&pkg);
        assert_eq!(
            so_ref_hits(&results).len(),
            2,
            "a repeated target fires once, distinct targets fire each: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_argument_may_carry_a_compression_suffix() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = manpage_pkg(
            &dir,
            &[
                (
                    "/usr/share/man/man3/alias.3",
                    0o100644,
                    b".so man3/popen.3.gz\n".as_slice(),
                ),
                (
                    "/usr/share/man/man3/popen.3",
                    0o100644,
                    b".TH popen 3\n".as_slice(),
                ),
            ],
        );
        let results = run_check_binary(&pkg);
        assert!(
            so_ref_hits(&results).is_empty(),
            "a suffixed argument matches the target under any suffix: {results:?}"
        );
    }

    #[test]
    fn manpage_so_ref_reads_gzipped_page_via_decompressor() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().expect("tmpdir");
        // A stand-in gzip whose output is the payload named by the input
        // file's stem, mirroring decompressor_branch_validates_the_child_output.
        let payload = dir.path().join("alias.3.out");
        std::fs::write(&payload, ".so man3/popen.3\n").expect("write payload");
        let script = dir.path().join("gzip");
        std::fs::write(
            &script,
            "#!/bin/sh\nfor last; do :; done\ncat \"${last%.*}.out\"\n",
        )
        .expect("write fake gzip");
        let mut perms = std::fs::metadata(&script)
            .expect("stat fake gzip")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("chmod fake gzip");
        for _ in 0..100 {
            match std::process::Command::new(&script)
                .arg("--version")
                .output()
            {
                Ok(_) => break,
                Err(e) if e.raw_os_error() == Some(26) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => panic!("fake gzip failed: {e}"),
            }
        }
        let pkg = manpage_pkg(
            &dir,
            &[(
                "/usr/share/man/man3/alias.3.gz",
                0o100644,
                b"not really gzip".as_slice(),
            )],
        );
        // manpage_pkg rooted the on-disk path under a subdirectory; the
        // fake gzip maps <dir>/alias.3.gz to the payload, so point the
        // file entry at the flat path the script expects.
        let mut pkg = pkg;
        let flat = dir.path().join("alias.3.gz");
        std::fs::write(&flat, b"not really gzip").expect("write flat page");
        pkg.files[0].path = flat.to_string_lossy().into_owned();
        let config = test_config();
        let mut check = FilesCheck::with_tool_dir(&config, Some(dir.path()));
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        assert_eq!(
            so_ref_hits(&results).len(),
            1,
            "a gzipped page is decompressed and its missing target fires: {results:?}"
        );
    }

    #[test]
    fn debug_lookalike_paths_are_quiet_11() {
        let (pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/share/debugfoo/bar", 0o100644, 21),
            mkfile("/usr/bin/foo", 0o100755, 22),
        ]);
        let results = run_check_binary(&pkg);
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "debug-files-in-non-debug-package"),
            "segment equality must not match debugfoo: {results:?}"
        );
    }

    /// `test_config` plus the `FileGrants` tables parsed from the
    /// given TOML snippet.
    fn grant_test_config(snippet: &str) -> Config {
        let mut cfg = test_config();
        let parsed: toml::Table = toml::from_str(snippet).expect("grant snippet parses");
        cfg.configuration
            .insert("FileGrants".to_string(), parsed["FileGrants"].clone());
        cfg
    }

    /// Drive `check_ldconfig` for one library of a synthetic package
    /// with the given scriptlet bodies, returning the emitted
    /// (name, line) pairs.
    fn run_ldconfig(
        config: &Config,
        pkg_name: &str,
        fname: &str,
        postin: &str,
        postun: &str,
    ) -> Vec<(String, String)> {
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture");
        pkg.name = pkg_name.to_string();
        let pkgfile = PkgFile {
            name: fname.to_string(),
            path: fname.to_string(),
            mode: 0o100755,
            size: Some(100),
            ..Default::default()
        };
        let st = PkgState {
            postin: postin.to_string(),
            postun: postun.to_string(),
            ..Default::default()
        };
        let check = FilesCheck::new(config);
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        check.check_ldconfig(&pkg, fname, &pkgfile, &st, &mut out);
        out.results().to_vec()
    }

    const RPM_GRANT: &str = r#"
[[FileGrants]]
package = "rpm"
paths = ["/usr/lib64/librpm.so.10.2.1"]
findings = ["postin-without-ldconfig", "library-without-ldconfig-postun"]
reason = "no ldconfig scriptlets by design"
"#;

    #[test]
    fn file_grants_quiet_the_granted_ldconfig_findings() {
        // rpm's shape: %post present but ldconfig-less, no %postun at
        // all. Both resulting tags are granted for the named library.
        let config = grant_test_config(RPM_GRANT);
        let results = run_ldconfig(&config, "rpm", "/usr/lib64/librpm.so.10.2.1", "echo hi", "");
        assert!(
            results.is_empty(),
            "granted findings must stay quiet: {results:?}"
        );
        // The same shape without the grant config fires both tags at E.
        let results = run_ldconfig(
            &test_config(),
            "rpm",
            "/usr/lib64/librpm.so.10.2.1",
            "echo hi",
            "",
        );
        assert_eq!(results.len(), 2, "ungranted shape must fire: {results:?}");
        assert!(results.iter().all(|(_, line)| line.contains(": E: ")));
    }

    #[test]
    fn file_grants_stay_exact() {
        let config = grant_test_config(RPM_GRANT);
        // Ungranted path in the granted package still fires.
        let results = run_ldconfig(&config, "rpm", "/usr/lib64/libfoo.so.1", "echo hi", "");
        assert_eq!(results.len(), 2, "ungranted path must fire: {results:?}");
        // Granted path in an ungranted package still fires.
        let results = run_ldconfig(
            &config,
            "rpm2",
            "/usr/lib64/librpm.so.10.2.1",
            "echo hi",
            "",
        );
        assert_eq!(results.len(), 2, "ungranted package must fire: {results:?}");
        // A grant naming only one of the two tags leaves the other live.
        let partial = grant_test_config(
            r#"
[[FileGrants]]
package = "rpm"
paths = ["/usr/lib64/librpm.so.10.2.1"]
findings = ["postin-without-ldconfig"]
reason = "postin side only"
"#,
        );
        let results = run_ldconfig(
            &partial,
            "rpm",
            "/usr/lib64/librpm.so.10.2.1",
            "echo hi",
            "",
        );
        assert_eq!(
            results.len(),
            1,
            "only the granted tag is quiet: {results:?}"
        );
        assert_eq!(results[0].0, "library-without-ldconfig-postun");
    }

    #[test]
    fn file_grants_without_a_reason_are_rejected() {
        // No reason key at all: the grant is invalid and never applies.
        let no_reason = grant_test_config(
            r#"
[[FileGrants]]
package = "rpm"
paths = ["/usr/lib64/librpm.so.10.2.1"]
findings = ["postin-without-ldconfig", "library-without-ldconfig-postun"]
"#,
        );
        assert!(FilesCheck::parse_file_grants(&no_reason).is_empty());
        let results = run_ldconfig(
            &no_reason,
            "rpm",
            "/usr/lib64/librpm.so.10.2.1",
            "echo hi",
            "",
        );
        assert_eq!(
            results.len(),
            2,
            "a reasonless grant must not apply: {results:?}"
        );
        // A blank reason is no reason.
        let blank_reason = grant_test_config(
            r#"
[[FileGrants]]
package = "rpm"
paths = ["/usr/lib64/librpm.so.10.2.1"]
findings = ["postin-without-ldconfig"]
reason = "  "
"#,
        );
        assert!(FilesCheck::parse_file_grants(&blank_reason).is_empty());
        // Both package keys at once is malformed, as is a missing
        // paths list: neither parses into a live grant.
        let both_keys = grant_test_config(
            r#"
[[FileGrants]]
package = "rpm"
packages = ["rpm"]
paths = ["/usr/lib64/librpm.so.10.2.1"]
findings = ["postin-without-ldconfig"]
reason = "recorded"
"#,
        );
        assert!(FilesCheck::parse_file_grants(&both_keys).is_empty());
        let no_paths = grant_test_config(
            r#"
[[FileGrants]]
package = "rpm"
findings = ["postin-without-ldconfig"]
reason = "recorded"
"#,
        );
        assert!(FilesCheck::parse_file_grants(&no_paths).is_empty());
    }

    #[test]
    fn file_grants_quiet_the_granted_config_file_finding() {
        let config = grant_test_config(
            r#"
[[FileGrants]]
package = "smartmontools"
paths = ["/etc/smartd_warning.sh"]
findings = ["executable-marked-as-config-file"]
reason = "warning hook: executable and %config by design"
"#,
        );
        let config_findings = |results: &[(String, String)]| {
            results
                .iter()
                .filter(|(n, _)| n == "executable-marked-as-config-file")
                .count()
        };
        let (mut pkg, _dir) = pkg_with_files(vec![mkfile("/etc/smartd_warning.sh", 0o100755, 61)]);
        pkg.name = "smartmontools".to_string();
        pkg.config_files = vec!["/etc/smartd_warning.sh".to_string()];
        assert_eq!(
            config_findings(&run_check_binary_with_config(&pkg, &config)),
            0,
            "granted config file must stay quiet"
        );
        assert_eq!(
            config_findings(&run_check_binary(&pkg)),
            1,
            "the same file fires without the grant"
        );
        // An executable %config file of another package at an
        // ungranted path still fires under the grant config.
        let (mut pkg, _dir) = pkg_with_files(vec![mkfile("/etc/init.d/after.local", 0o100755, 62)]);
        pkg.name = "aaa_base".to_string();
        pkg.config_files = vec!["/etc/init.d/after.local".to_string()];
        assert_eq!(
            config_findings(&run_check_binary_with_config(&pkg, &config)),
            1,
            "ungranted config file must still fire"
        );
    }

    /// The vendored openSUSE config's `FileGrants` set is the grant
    /// source default runs actually use: the four audited core-package
    /// clusters (rpm/systemd ldconfig, smartmontools/tuned config
    /// files) stay quiet under it, so generator or typo drift in the
    /// set surfaces here instead of false-firing on those packages.
    #[test]
    fn opensuse_file_grants_cover_the_audited_clusters() {
        let opensuse_toml =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("data/distro/opensuse/opensuse.toml");
        let parsed: toml::Table = toml::from_str(
            &std::fs::read_to_string(opensuse_toml).expect("vendored opensuse config"),
        )
        .expect("vendored opensuse config parses");
        let grants = parsed["FileGrants"]
            .as_array()
            .expect("FileGrants is an array");
        assert_eq!(
            grants.len(),
            4,
            "the vendored openSUSE grant set changed: {grants:?}"
        );
        for g in grants {
            let reason = g.get("reason").and_then(toml::Value::as_str).unwrap_or("");
            assert!(
                !reason.trim().is_empty(),
                "every vendored grant records its reason: {g:?}"
            );
        }
        let mut cfg = test_config();
        cfg.configuration
            .insert("FileGrants".to_string(), parsed["FileGrants"].clone());
        // rpm: %post ldconfig-less, no %postun — quiet on all three
        // libraries the audit measured.
        for path in [
            "/usr/lib64/librpm.so.10.2.1",
            "/usr/lib64/librpmio.so.10.2.1",
            "/usr/lib64/librpmsign.so.10.2.1",
        ] {
            let results = run_ldconfig(&cfg, "rpm", path, "echo hi", "");
            assert!(
                results.is_empty(),
                "rpm grant must cover {path}: {results:?}"
            );
        }
        // systemd: %post runs ldconfig, %postun is ldconfig-less —
        // quiet on both NSS modules; without the grant exactly the
        // postun tag fires.
        for path in [
            "/usr/lib64/libnss_myhostname.so.2",
            "/usr/lib64/libnss_systemd.so.2",
        ] {
            let results = run_ldconfig(&cfg, "systemd", path, "/sbin/ldconfig", "echo hi");
            assert!(
                results.is_empty(),
                "systemd grant must cover {path}: {results:?}"
            );
            let ungranted =
                run_ldconfig(&test_config(), "systemd", path, "/sbin/ldconfig", "echo hi");
            assert_eq!(
                ungranted.len(),
                1,
                "systemd shape fires without the grant: {ungranted:?}"
            );
            assert_eq!(ungranted[0].0, "postun-without-ldconfig");
        }
        // smartmontools and tuned: executable %config files stay quiet.
        for (pkg_name, path) in [
            ("smartmontools", "/etc/smartd_warning.sh"),
            ("tuned", "/etc/grub.d/00_tuned"),
        ] {
            let (mut pkg, _dir) = pkg_with_files(vec![mkfile(path, 0o100755, 71)]);
            pkg.name = pkg_name.to_string();
            pkg.config_files = vec![path.to_string()];
            let results = run_check_binary_with_config(&pkg, &cfg);
            assert!(
                !results
                    .iter()
                    .any(|(n, _)| n == "executable-marked-as-config-file"),
                "{pkg_name} grant must cover {path}: {results:?}"
            );
        }
    }

    /// `test_config` plus a `SystemdPresetPackages` exemption list, the
    /// config key the vendored openSUSE/SLFO distro configs carry.
    fn preset_test_config() -> Config {
        let mut cfg = test_config();
        cfg.configuration.insert(
            "SystemdPresetPackages".to_string(),
            toml::Value::Array(vec![
                toml::Value::String("systemd".to_string()),
                toml::Value::String("systemd-presets-common-SUSE".to_string()),
                toml::Value::String("systemd-presets-branding-openSUSE".to_string()),
            ]),
        );
        cfg
    }

    fn run_check_binary_with_config(pkg: &Pkg, config: &Config) -> Vec<(String, String)> {
        let mut check = FilesCheck::new(config);
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        check.check_binary(pkg, config, &mut out);
        out.results().to_vec()
    }

    fn preset_findings(results: &[(String, String)]) -> Vec<&(String, String)> {
        results
            .iter()
            .filter(|(n, _)| n == "systemd-preset-packaged")
            .collect()
    }

    #[test]
    fn systemd_preset_file_in_other_package_fires() {
        let (mut pkg, _dir) = pkg_with_files(vec![mkfile(
            "/usr/lib/systemd/system-preset/99-foo.preset",
            0o100644,
            31,
        )]);
        pkg.name = "foo".to_string();
        let results = run_check_binary_with_config(&pkg, &preset_test_config());
        let hits = preset_findings(&results);
        assert_eq!(hits.len(), 1, "exactly one preset finding: {results:?}");
        assert!(
            hits[0].1.contains(
                ": W: systemd-preset-packaged /usr/lib/systemd/system-preset/99-foo.preset"
            ),
            "name, level and detail must render, got: {}",
            hits[0].1
        );
    }

    #[test]
    fn systemd_user_preset_file_in_other_package_fires() {
        let (mut pkg, _dir) = pkg_with_files(vec![mkfile(
            "/usr/lib/systemd/user-preset/99-foo.preset",
            0o100644,
            32,
        )]);
        pkg.name = "foo".to_string();
        let results = run_check_binary_with_config(&pkg, &preset_test_config());
        assert_eq!(
            preset_findings(&results).len(),
            1,
            "user-preset files fire too: {results:?}"
        );
    }

    #[test]
    fn systemd_preset_file_in_preset_packages_is_quiet() {
        for name in [
            "systemd",
            "systemd-presets-common-SUSE",
            "systemd-presets-branding-openSUSE",
        ] {
            let (mut pkg, _dir) = pkg_with_files(vec![mkfile(
                "/usr/lib/systemd/system-preset/90-default.preset",
                0o100644,
                33,
            )]);
            pkg.name = name.to_string();
            let results = run_check_binary_with_config(&pkg, &preset_test_config());
            assert!(
                preset_findings(&results).is_empty(),
                "preset package {name} must stay quiet: {results:?}"
            );
        }
    }

    /// The vendored openSUSE config's `SystemdPresetPackages` list is the
    /// exemption source default runs actually use: every package it names
    /// stays quiet under it, so generator or typo drift in the list
    /// surfaces here instead of false-firing on real preset packages.
    #[test]
    fn opensuse_preset_packages_are_quiet_under_vendored_opensuse_config() {
        let opensuse_toml =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("data/distro/opensuse/opensuse.toml");
        let parsed: toml::Table = toml::from_str(
            &std::fs::read_to_string(opensuse_toml).expect("vendored opensuse config"),
        )
        .expect("vendored opensuse config parses");
        let names: Vec<&str> = parsed["SystemdPresetPackages"]
            .as_array()
            .expect("SystemdPresetPackages is an array")
            .iter()
            .map(|v| v.as_str().expect("preset package names are strings"))
            .collect();
        assert_eq!(
            names.len(),
            13,
            "the vendored openSUSE preset list changed: {names:?}"
        );
        let mut cfg = test_config();
        cfg.configuration.insert(
            "SystemdPresetPackages".to_string(),
            parsed["SystemdPresetPackages"].clone(),
        );
        for name in &names {
            let (mut pkg, _dir) = pkg_with_files(vec![mkfile(
                "/usr/lib/systemd/system-preset/90-default.preset",
                0o100644,
                46,
            )]);
            pkg.name = name.to_string();
            let results = run_check_binary_with_config(&pkg, &cfg);
            assert!(
                preset_findings(&results).is_empty(),
                "openSUSE preset package {name} must stay quiet: {results:?}"
            );
        }
    }

    #[test]
    fn systemd_preset_file_fires_without_exemption_config() {
        // No SystemdPresetPackages key configured: no package is exempt,
        // including a distro preset package name.
        let (mut pkg, _dir) = pkg_with_files(vec![mkfile(
            "/usr/lib/systemd/system-preset/90-default.preset",
            0o100644,
            34,
        )]);
        pkg.name = "systemd-presets-common-SUSE".to_string();
        let results = run_check_binary(&pkg);
        assert_eq!(
            preset_findings(&results).len(),
            1,
            "without the exemption config every preset shipper fires: {results:?}"
        );
    }

    #[test]
    fn preset_like_paths_outside_preset_dirs_are_quiet() {
        let (mut pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/lib/systemd/system/99-foo.preset", 0o100644, 35),
            mkfile("/usr/share/foo/99-foo.preset", 0o100644, 36),
            mkfile("/usr/lib/systemd/system-preset/99-foo.conf", 0o100644, 37),
            mkfile(
                "/usr/lib/systemd/system-preset/sub/99-foo.preset",
                0o100644,
                38,
            ),
        ]);
        pkg.name = "foo".to_string();
        let results = run_check_binary_with_config(&pkg, &preset_test_config());
        assert!(
            preset_findings(&results).is_empty(),
            "only *.preset directly in the preset dirs fires: {results:?}"
        );
    }

    #[test]
    fn systemd_preset_file_in_etc_fires() {
        // systemd reads presets from /etc/systemd/{system,user}-preset/
        // too (the higher-priority admin policy dirs), so a preset file
        // shipped there sets enablement policy exactly as in /usr/lib.
        for path in [
            "/etc/systemd/system-preset/99-foo.preset",
            "/etc/systemd/user-preset/99-foo.preset",
        ] {
            let (mut pkg, _dir) = pkg_with_files(vec![mkfile(path, 0o100644, 44)]);
            pkg.name = "foo".to_string();
            let results = run_check_binary_with_config(&pkg, &preset_test_config());
            assert_eq!(
                preset_findings(&results).len(),
                1,
                "/etc preset files fire too ({path}): {results:?}"
            );
        }
    }

    #[test]
    fn systemd_preset_ghost_entry_is_quiet() {
        let mut ghost = mkfile("/usr/lib/systemd/system-preset/99-foo.preset", 0o100644, 45);
        ghost.flags = RPMFILE_GHOST;
        let (mut pkg, _dir) = pkg_with_files(vec![ghost]);
        pkg.name = "foo".to_string();
        let results = run_check_binary_with_config(&pkg, &preset_test_config());
        assert!(
            preset_findings(&results).is_empty(),
            "a %ghost preset entry installs nothing and must stay quiet: {results:?}"
        );
    }

    #[test]
    fn systemd_preset_dir_entry_is_quiet() {
        let (mut pkg, _dir) = pkg_with_files(vec![
            mkfile("/usr/lib/systemd/system-preset", 0o040755, 40),
            mkfile("/usr/lib/systemd/user-preset", 0o040755, 41),
        ]);
        pkg.name = "foo".to_string();
        let results = run_check_binary_with_config(&pkg, &preset_test_config());
        assert!(
            preset_findings(&results).is_empty(),
            "bare directory entries must stay quiet: {results:?}"
        );
    }

    /// Build a binary RPM at test time with the given payload files
    /// (path, contents) and an optional %post scriptlet, then open it
    /// with real payload extraction.
    fn sysconfig_test_pkg(
        name: &str,
        files: &[(&str, &str)],
        post: Option<&str>,
    ) -> (Pkg, tempfile::TempDir, tempfile::TempDir) {
        use rpm::{BuildConfig, FileMode, FileOptions, PackageBuilder};
        let src = tempfile::tempdir().unwrap();
        let rpm_path = src.path().join(format!("{name}-1.0-1.noarch.rpm"));
        let mut b = PackageBuilder::new(name, "1.0", "MIT", "noarch", "sysconfig test package");
        b.using_config(BuildConfig::default());
        for &(path, contents) in files {
            b.with_file_contents(
                contents.as_bytes().to_vec(),
                FileOptions::new(path).mode(FileMode::regular(0o644)),
            )
            .unwrap();
        }
        if let Some(post) = post {
            b.post_install_script(post);
        }
        let built = b.build().unwrap();
        built
            .write(&mut std::fs::File::create(&rpm_path).unwrap())
            .unwrap();
        let extract = tempfile::tempdir().unwrap();
        let pkg = Pkg::open(&rpm_path, extract.path(), true).expect("open test pkg");
        (pkg, src, extract)
    }

    /// The `sysconfig-fillup-usage` findings (name, rendered line, level)
    /// `FilesCheck` emits for `pkg`.
    fn sysconfig_findings(pkg: &Pkg) -> Vec<(String, String, Level)> {
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check_binary(pkg, &config, &mut out);
        out.results()
            .iter()
            .zip(out.result_levels().iter())
            .filter(|((n, _), _)| n == "sysconfig-fillup-usage")
            .map(|((n, line), l)| (n.clone(), line.clone(), *l))
            .collect()
    }

    #[test]
    fn sysconfig_source_pkg_name_strips_version_and_release() {
        assert_eq!(source_pkg_name("sysconfig-0.90.5-1.2.src.rpm"), "sysconfig");
        assert_eq!(source_pkg_name("fillup-1.42-281.7.src.rpm"), "fillup");
        assert_eq!(source_pkg_name("libvirt-12.7.0-3.1.src.rpm"), "libvirt");
        assert_eq!(
            source_pkg_name("python3.14-3.14.0-1.1.src.rpm"),
            "python3.14"
        );
        // Builder-made packages carry the placeholder, which names no
        // real source package.
        assert_eq!(source_pkg_name("(none)"), "(none)");
    }

    #[test]
    fn sysconfig_fillup_exemption_shapes() {
        // By binary name.
        assert!(sysconfig_fillup_exempt("sysconfig", None));
        assert!(sysconfig_fillup_exempt("fillup", None));
        // By source package: the sysconfig-netconfig shape.
        assert!(sysconfig_fillup_exempt(
            "sysconfig-netconfig",
            Some("sysconfig-0.90.5-1.2.src.rpm")
        ));
        assert!(sysconfig_fillup_exempt(
            "fillup-lang",
            Some("fillup-1.42-281.7.src.rpm")
        ));
        // Lookalikes and ordinary packages are not exempt.
        assert!(!sysconfig_fillup_exempt(
            "sysconfigfoo",
            Some("sysconfigfoo-1.0-1.src.rpm")
        ));
        assert!(!sysconfig_fillup_exempt("demo", Some("demo-1.0-1.src.rpm")));
        assert!(!sysconfig_fillup_exempt("demo", Some("(none)")));
        assert!(!sysconfig_fillup_exempt("demo", None));
    }

    #[test]
    fn sysconfig_uses_collector_edges() {
        // The bare directories are not uses: only entries below them.
        assert!(sysconfig_fillup_uses(&["/etc/sysconfig"], &[], &[]).is_empty());
        assert!(sysconfig_fillup_uses(&["/usr/share/fillup-templates"], &[], &[]).is_empty());
        // A template under any fillup-templates directory counts.
        assert_eq!(
            sysconfig_fillup_uses(&["/opt/fillup-templates/sysconfig.demo"], &[], &[]),
            vec!["ships fillup template /opt/fillup-templates/sysconfig.demo".to_string()]
        );
        // A lookalike directory name does not count.
        assert!(sysconfig_fillup_uses(&["/usr/share/fillup-templates-old/x"], &[], &[]).is_empty());
        // Spacing around the `=` and a quoted value still resolve.
        assert_eq!(
            sysconfig_environment_file("[Service]\nEnvironmentFile = -/etc/sysconfig/demo\n"),
            Some("-/etc/sysconfig/demo".to_string())
        );
        assert_eq!(
            sysconfig_environment_file("EnvironmentFile=\"/etc/sysconfig/demo\"\n"),
            Some("/etc/sysconfig/demo".to_string())
        );
        // The optional-file dash next to a quoted value resolves too,
        // in either order: the quote trim runs again after the dash
        // strip, since systemd applies the `-` to the unquoted value.
        assert_eq!(
            sysconfig_environment_file("EnvironmentFile=-\"/etc/sysconfig/demo\"\n"),
            Some("-/etc/sysconfig/demo".to_string())
        );
        assert_eq!(
            sysconfig_environment_file("EnvironmentFile=\"-/etc/sysconfig/demo\"\n"),
            Some("-/etc/sysconfig/demo".to_string())
        );
        // A sysconfig-shaped path that is not inside /etc/sysconfig does
        // not count.
        assert_eq!(
            sysconfig_environment_file("EnvironmentFile=/usr/share/demo/etc/sysconfig/demo\n"),
            None
        );
        assert_eq!(
            sysconfig_environment_file("ExecStart=/usr/bin/demo\n"),
            None
        );
    }

    #[test]
    fn sysconfig_payload_file_fires() {
        let (pkg, _src, _extract) =
            sysconfig_test_pkg("demo", &[("/etc/sysconfig/demo", "FOO=1\n")], None);
        let found = sysconfig_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert_eq!(found[0].2, Level::Warning);
        assert!(
            found[0].1.contains("/etc/sysconfig/demo"),
            "detail names the payload file: {}",
            found[0].1
        );
    }

    #[test]
    fn sysconfig_fillup_template_fires() {
        let (pkg, _src, _extract) = sysconfig_test_pkg(
            "demo",
            &[("/usr/share/fillup-templates/sysconfig.demo", "# template\n")],
            None,
        );
        let found = sysconfig_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert_eq!(found[0].2, Level::Warning);
        assert!(
            found[0]
                .1
                .contains("/usr/share/fillup-templates/sysconfig.demo"),
            "detail names the template: {}",
            found[0].1
        );
    }

    #[test]
    fn sysconfig_legacy_fillup_template_fires() {
        let (pkg, _src, _extract) = sysconfig_test_pkg(
            "demo",
            &[("/var/adm/fillup-templates/sysconfig.demo", "# template\n")],
            None,
        );
        let found = sysconfig_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert!(
            found[0]
                .1
                .contains("/var/adm/fillup-templates/sysconfig.demo"),
            "detail names the template: {}",
            found[0].1
        );
    }

    #[test]
    fn sysconfig_fillup_scriptlet_fires() {
        // The macro-expanded shape: a guard testing for the binary, then
        // the invocation at command position.
        let post = "PNAME=demo\n\
                    if [ -x /bin/fillup ]; then\n\
                    \t/bin/fillup -q /etc/sysconfig/$PNAME /usr/share/fillup-templates/sysconfig.$PNAME\n\
                    fi\n";
        let (pkg, _src, _extract) = sysconfig_test_pkg("demo", &[], Some(post));
        let found = sysconfig_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert_eq!(found[0].2, Level::Warning);
        assert!(
            found[0].1.contains("%post"),
            "detail names the scriptlet: {}",
            found[0].1
        );
    }

    #[test]
    fn sysconfig_fillup_mention_without_invocation_is_quiet() {
        // The guard alone tests for the binary without invoking it, and
        // the word in prose is not a command position either.
        let post = "if [ -x /bin/fillup ]; then\n\
                    \techo fillup is available\n\
                    fi\n\
                    # fillup would merge the template here\necho done\n";
        let (pkg, _src, _extract) = sysconfig_test_pkg("demo", &[], Some(post));
        assert!(
            sysconfig_findings(&pkg).is_empty(),
            "no invocation, no finding"
        );
    }

    #[test]
    fn sysconfig_unit_environment_file_fires() {
        let unit = "[Service]\nEnvironmentFile=/etc/sysconfig/demo\nExecStart=/usr/bin/demo\n";
        let (pkg, _src, _extract) = sysconfig_test_pkg(
            "demo",
            &[("/usr/lib/systemd/system/demo.service", unit)],
            None,
        );
        let found = sysconfig_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert_eq!(found[0].2, Level::Warning);
        assert!(
            found[0].1.contains("/etc/sysconfig/demo"),
            "detail names the EnvironmentFile target: {}",
            found[0].1
        );
    }

    #[test]
    fn sysconfig_unit_environment_file_dash_prefixed_fires() {
        // The `-` prefix marks the file optional; the unit still reads
        // its configuration from /etc/sysconfig.
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\nExecStart=/usr/bin/demo\n";
        let (pkg, _src, _extract) = sysconfig_test_pkg(
            "demo",
            &[("/usr/lib/systemd/system/demo.service", unit)],
            None,
        );
        let found = sysconfig_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert!(
            found[0].1.contains("/etc/sysconfig/demo"),
            "detail names the EnvironmentFile target: {}",
            found[0].1
        );
    }

    #[test]
    fn sysconfig_unit_environment_file_elsewhere_is_quiet() {
        let unit = "[Service]\nEnvironmentFile=/etc/default/demo\n\
                    EnvironmentFile=-/usr/share/demo/demo.env\nExecStart=/usr/bin/demo\n";
        let (pkg, _src, _extract) = sysconfig_test_pkg(
            "demo",
            &[("/usr/lib/systemd/system/demo.service", unit)],
            None,
        );
        assert!(
            sysconfig_findings(&pkg).is_empty(),
            "EnvironmentFile outside /etc/sysconfig is not a use"
        );
    }

    #[test]
    fn sysconfig_multiple_uses_fire_once() {
        let post =
            "/bin/fillup -q /etc/sysconfig/demo /usr/share/fillup-templates/sysconfig.demo\n";
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\n";
        let (pkg, _src, _extract) = sysconfig_test_pkg(
            "demo",
            &[
                ("/etc/sysconfig/demo", "FOO=1\n"),
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            Some(post),
        );
        let found = sysconfig_findings(&pkg);
        assert_eq!(found.len(), 1, "one finding per package: {found:?}");
        let line = &found[0].1;
        for evidence in [
            "/etc/sysconfig/demo",
            "/usr/share/fillup-templates/sysconfig.demo",
            "%post",
            "demo.service",
        ] {
            assert!(line.contains(evidence), "detail covers {evidence}: {line}");
        }
    }

    #[test]
    fn sysconfig_package_itself_is_quiet() {
        // The mechanism's own package ships the payload, the templates
        // and the fillup calls; it is exempt by name.
        let post =
            "/bin/fillup -q /etc/sysconfig/network /usr/share/fillup-templates/sysconfig.network\n";
        let (pkg, _src, _extract) = sysconfig_test_pkg(
            "sysconfig",
            &[
                ("/etc/sysconfig/network/config", "NETWORKING=yes\n"),
                (
                    "/usr/share/fillup-templates/sysconfig.network",
                    "# template\n",
                ),
            ],
            Some(post),
        );
        assert!(
            sysconfig_findings(&pkg).is_empty(),
            "the sysconfig package is exempt"
        );
    }

    /// Build a binary RPM at test time for the fillup-template check:
    /// payload files with contents, `%ghost` entries,
    /// and a free-form builder hook for scriptlets beyond `%post`.
    fn fillup_test_pkg(
        name: &str,
        files: &[(&str, &str)],
        ghosts: &[&str],
        extra: &dyn Fn(&mut rpm::PackageBuilder),
    ) -> (Pkg, tempfile::TempDir, tempfile::TempDir) {
        use rpm::{BuildConfig, FileMode, FileOptions, PackageBuilder};
        let src = tempfile::tempdir().unwrap();
        let rpm_path = src.path().join(format!("{name}-1.0-1.noarch.rpm"));
        let mut b = PackageBuilder::new(name, "1.0", "MIT", "noarch", "fillup test package");
        b.using_config(BuildConfig::default());
        for &(path, contents) in files {
            b.with_file_contents(
                contents.as_bytes().to_vec(),
                FileOptions::new(path).mode(FileMode::regular(0o644)),
            )
            .unwrap();
        }
        for &path in ghosts {
            b.with_ghost(FileOptions::ghost(path)).unwrap();
        }
        extra(&mut b);
        let built = b.build().unwrap();
        built
            .write(&mut std::fs::File::create(&rpm_path).unwrap())
            .unwrap();
        let extract = tempfile::tempdir().unwrap();
        let pkg = Pkg::open(&rpm_path, extract.path(), true).expect("open test pkg");
        (pkg, src, extract)
    }

    /// The `fillup-template-without-fillup-call` findings (name,
    /// rendered line, level) `FilesCheck` emits for `pkg`.
    fn fillup_findings(pkg: &Pkg) -> Vec<(String, String, Level)> {
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check_binary(pkg, &config, &mut out);
        out.results()
            .iter()
            .zip(out.result_levels().iter())
            .filter(|((n, _), _)| n == "fillup-template-without-fillup-call")
            .map(|((n, line), l)| (n.clone(), line.clone(), *l))
            .collect()
    }

    /// The `fillup-usage-discouraged` findings (name, rendered
    /// line, level) `FilesCheck` emits for `pkg`.
    fn discouraged_findings(pkg: &Pkg) -> Vec<(String, String, Level)> {
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check_binary(pkg, &config, &mut out);
        out.results()
            .iter()
            .zip(out.result_levels().iter())
            .filter(|((n, _), _)| n == "fillup-usage-discouraged")
            .map(|((n, line), l)| (n.clone(), line.clone(), *l))
            .collect()
    }

    #[test]
    fn fillup_discouraged_template_and_call_fire_once() {
        // A consumed template plus a call: the defect check is quiet
        // (the call credits the package), the discouragement tag
        // fires once, and the unit's EnvironmentFile consumption
        // earns no exemption.
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\nExecStart=/usr/bin/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|b| {
                b.post_install_script(
                    "/bin/fillup -q /etc/sysconfig/demo /usr/share/fillup-templates/sysconfig.demo\n",
                );
            },
        );
        assert!(fillup_findings(&pkg).is_empty());
        let found = discouraged_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert_eq!(found[0].2, Level::Warning);
        assert!(
            found[0]
                .1
                .contains("/usr/share/fillup-templates/sysconfig.demo"),
            "detail names the template: {}",
            found[0].1
        );
        assert!(
            found[0].1.contains("%post"),
            "detail names the scriptlet: {}",
            found[0].1
        );
    }

    #[test]
    fn fillup_discouraged_unconsumed_template_fires() {
        // A template nothing reads: the defect check needs a gated
        // read and stays quiet; the discouragement tag fires on the
        // template arm alone.
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[("/usr/share/fillup-templates/sysconfig.demo", "# template\n")],
            &[],
            &|_| {},
        );
        assert!(fillup_findings(&pkg).is_empty());
        let found = discouraged_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert_eq!(found[0].2, Level::Warning);
    }

    #[test]
    fn fillup_discouraged_yields_to_defect_report() {
        // The package's only fillup involvement is the template the
        // defect check already reports: the discouragement tag
        // yields for the package.
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\nExecStart=/usr/bin/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|_| {},
        );
        assert_eq!(fillup_findings(&pkg).len(), 1);
        assert!(
            discouraged_findings(&pkg).is_empty(),
            "the defect report covers the package's only fillup involvement"
        );
    }

    #[test]
    fn fillup_discouraged_second_template_breaks_the_yield() {
        // One defect-reported template plus a second, unconsumed
        // one: the second is fillup involvement beyond the defect
        // report, so the tag fires once and names it.
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\nExecStart=/usr/bin/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                (
                    "/usr/share/fillup-templates/sysconfig.other",
                    "# template\n",
                ),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|_| {},
        );
        assert_eq!(fillup_findings(&pkg).len(), 1);
        let found = discouraged_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert!(
            found[0].1.contains("sysconfig.other"),
            "detail names the unreported template: {}",
            found[0].1
        );
    }

    #[test]
    fn fillup_discouraged_call_only_fires() {
        // A bare invocation with no shipped template (the
        // %fillup_only -s merge shape) fires on the call arm alone.
        let (pkg, _src, _extract) = fillup_test_pkg("demo", &[], &[], &|b| {
            b.post_install_script(
                "/bin/fillup -q /etc/sysconfig/demo /usr/share/fillup-templates/sysconfig.demo\n",
            );
        });
        let found = discouraged_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert!(
            found[0].1.contains("%post"),
            "detail names the scriptlet: {}",
            found[0].1
        );
    }

    #[test]
    fn fillup_discouraged_macro_only_fires() {
        // A scriptlet spelling the macro literally (the unexpanded
        // shape) invokes fillup just the same.
        let (pkg, _src, _extract) = fillup_test_pkg("demo", &[], &[], &|b| {
            b.post_install_script(
                    "%fillup_only -n demo /etc/sysconfig/demo /usr/share/fillup-templates/sysconfig.demo\n",
                );
        });
        let found = discouraged_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert!(
            found[0].1.contains("%post"),
            "detail names the scriptlet: {}",
            found[0].1
        );
    }

    #[test]
    fn fillup_discouraged_mention_is_quiet() {
        // A guard testing for the binary and a prose mention are not
        // invocations, in either shape.
        let post = "if [ -x /bin/fillup ]; then\n\
                    \techo fillup is available\n\
                    fi\n\
                    # fillup would merge the template here\necho done\n";
        let (pkg, _src, _extract) = fillup_test_pkg("demo", &[], &[], &|b| {
            b.post_install_script(post);
        });
        assert!(discouraged_findings(&pkg).is_empty());
    }

    #[test]
    fn fillup_discouraged_ghost_template_is_quiet() {
        // A %ghost entry ships no template content to migrate.
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[],
            &["/usr/share/fillup-templates/sysconfig.demo"],
            &|_| {},
        );
        assert!(discouraged_findings(&pkg).is_empty());
    }

    #[test]
    fn fillup_discouraged_mechanism_package_is_quiet() {
        // The fillup package provides the mechanism; it does not
        // consume it.
        let (pkg, _src, _extract) = fillup_test_pkg(
            "fillup",
            &[("/usr/share/fillup-templates/sysconfig.demo", "# template\n")],
            &[],
            &|b| {
                b.post_install_script(
                    "/bin/fillup -q /etc/sysconfig/demo /usr/share/fillup-templates/sysconfig.demo\n",
                );
            },
        );
        assert!(discouraged_findings(&pkg).is_empty());
    }

    #[test]
    fn fillup_template_name_shapes() {
        assert_eq!(
            fillup_template_name("/usr/share/fillup-templates/sysconfig.demo"),
            Some("demo")
        );
        assert_eq!(
            fillup_template_name("/var/adm/fillup-templates/sysconfig.demo"),
            Some("demo")
        );
        // Not directly below the templates directory.
        assert_eq!(
            fillup_template_name("/usr/share/fillup-templates/sub/sysconfig.demo"),
            None
        );
        // Not a sysconfig template name.
        assert_eq!(
            fillup_template_name("/usr/share/fillup-templates/demo"),
            None
        );
        assert_eq!(
            fillup_template_name("/usr/share/fillup-templates/sysconfig."),
            None
        );
        assert_eq!(
            fillup_template_name("/usr/share/other/sysconfig.demo"),
            None
        );
    }

    #[test]
    fn fillup_gate_match_shapes() {
        assert!(env_target_names_template("/etc/sysconfig/demo", "demo"));
        // The %fillup_only -d form: one directory below.
        assert!(env_target_names_template("/etc/sysconfig/sub/demo", "demo"));
        // Deeper nesting is not the -d form.
        assert!(!env_target_names_template(
            "/etc/sysconfig/a/b/demo",
            "demo"
        ));
        // Another package's file, and the -s merge split point.
        assert!(!env_target_names_template("/etc/sysconfig/proxy", "demo"));
        assert!(!env_target_names_template("/etc/sysconfig/foo", "foo-bar"));
        // Specifier and variable targets never resolve.
        assert!(!env_target_names_template(
            "/etc/sysconfig/foo-%i",
            "foo-%i"
        ));
        assert!(!env_target_names_template("/etc/sysconfig/$NAME", "$NAME"));
        // Outside /etc/sysconfig entirely.
        assert!(!env_target_names_template("/etc/default/demo", "demo"));
    }

    #[test]
    fn fillup_tmpfiles_created_path_shapes() {
        let conf = "\
# comment
f /etc/sysconfig/a 0644 root root -
C /etc/sysconfig/b - - - - /usr/share/fillup-templates/sysconfig.b
L /etc/sysconfig/c - - - - /usr/share/fillup-templates/sysconfig.c
f+ /etc/sysconfig/d - - - -
d /etc/sysconfig/e 0755 root root -
x /etc/sysconfig/f - - - -
";
        let paths = tmpfiles_created_paths(conf);
        assert!(paths.contains("/etc/sysconfig/a"));
        assert!(paths.contains("/etc/sysconfig/b"));
        assert!(paths.contains("/etc/sysconfig/c"));
        assert!(paths.contains("/etc/sysconfig/d"));
        assert!(!paths.contains("/etc/sysconfig/e"));
        assert!(!paths.contains("/etc/sysconfig/f"));
        // F truncates-or-creates the file and w writes its content:
        // both materialise the target like f does.
        let conf = "F /etc/sysconfig/g 0644 root root -\nw /etc/sysconfig/h - - - - FOO=1\n";
        let paths = tmpfiles_created_paths(conf);
        assert!(paths.contains("/etc/sysconfig/g"));
        assert!(paths.contains("/etc/sysconfig/h"));
    }

    #[test]
    fn fillup_optional_read_fires_warning() {
        // The ollama shape: the file is optional, so the daemon runs
        // on defaults while the documented settings file is absent.
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\nExecStart=/usr/bin/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "DEMO_HOST=\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|_| {},
        );
        let found = fillup_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert_eq!(found[0].2, Level::Warning);
        assert!(
            found[0].1.contains("/etc/sysconfig/demo"),
            "detail names the target: {}",
            found[0].1
        );
    }

    #[test]
    fn fillup_mandatory_read_fires_error() {
        // The xsp shape: a mandatory EnvironmentFile that never
        // appears keeps the unit from starting at all.
        let unit = "[Service]\nEnvironmentFile=/etc/sysconfig/demo\nExecStart=/usr/bin/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                (
                    "/usr/share/fillup-templates/sysconfig.demo",
                    "DEMO_PORT=\"8080\"\n",
                ),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|_| {},
        );
        let found = fillup_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert_eq!(found[0].2, Level::Error);
    }

    #[test]
    fn fillup_second_environment_line_gates() {
        // The cri-o shape: the unit reads another package's file
        // first; the template's own target sits on the second line.
        let unit = "[Service]\n\
                    EnvironmentFile=-/etc/sysconfig/proxy\n\
                    EnvironmentFile=-/etc/sysconfig/crio\n\
                    ExecStart=/usr/bin/crio\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "crio",
            &[
                ("/usr/share/fillup-templates/sysconfig.crio", "# crio\n"),
                ("/usr/lib/systemd/system/crio.service", unit),
            ],
            &[],
            &|_| {},
        );
        let found = fillup_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert_eq!(found[0].2, Level::Warning);
    }

    #[test]
    fn fillup_two_gated_templates_two_findings() {
        let unit = "[Service]\n\
                    EnvironmentFile=-/etc/sysconfig/one\n\
                    EnvironmentFile=-/etc/sysconfig/two\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.one", "# one\n"),
                ("/usr/share/fillup-templates/sysconfig.two", "# two\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|_| {},
        );
        assert_eq!(fillup_findings(&pkg).len(), 2, "one finding per template");
    }

    #[test]
    fn fillup_ghost_target_does_not_exempt() {
        // A %ghost entry creates nothing, so the read still gates.
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &["/etc/sysconfig/demo"],
            &|_| {},
        );
        assert_eq!(fillup_findings(&pkg).len(), 1);
    }

    #[test]
    fn fillup_dash_d_form_fires() {
        let unit = "[Service]\nEnvironmentFile=/etc/sysconfig/sub/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|_| {},
        );
        let found = fillup_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert_eq!(found[0].2, Level::Error);
        assert!(
            found[0].1.contains("/etc/sysconfig/sub/demo"),
            "detail names the -d target: {}",
            found[0].1
        );
    }

    #[test]
    fn fillup_legacy_template_dir_fires() {
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/var/adm/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|_| {},
        );
        assert_eq!(fillup_findings(&pkg).len(), 1);
    }

    #[test]
    fn fillup_guard_only_scriptlet_fires() {
        // A `[ -x /bin/fillup ]` guard tests for the binary without
        // invoking it: no credit.
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|b| {
                b.post_install_script("if [ -x /bin/fillup ]; then echo yes; fi\n");
            },
        );
        assert_eq!(fillup_findings(&pkg).len(), 1);
    }

    #[test]
    fn fillup_call_in_post_is_quiet() {
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|b| {
                b.post_install_script(
                    "/bin/fillup -q /etc/sysconfig/demo /usr/share/fillup-templates/sysconfig.demo\n",
                );
            },
        );
        assert!(fillup_findings(&pkg).is_empty());
    }

    #[test]
    fn fillup_macro_only_call_is_quiet() {
        // A scriptlet that invokes fillup only through the literal
        // macro (an unexpanded build) calls fillup just the same:
        // the defect helper shares the discouraged check's
        // invocation predicate, macros included.
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|b| {
                b.post_install_script("%fillup_only -n demo\n");
            },
        );
        assert!(fillup_findings(&pkg).is_empty());
    }

    #[test]
    fn fillup_call_in_trigger_is_quiet() {
        // Triggers are scriptlets too (SCRIPT_TAGS): a call there
        // credits the package the same way.
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|b| {
                b.trigger_in(
                    "demo",
                    None,
                    "/bin/fillup -q /etc/sysconfig/demo /usr/share/fillup-templates/sysconfig.demo\n",
                );
            },
        );
        assert!(fillup_findings(&pkg).is_empty());
    }

    #[test]
    fn fillup_call_for_one_template_credits_all() {
        // Stated silence: a call is not mapped to its template, so
        // one call silences the package's other templates too.
        let unit = "[Service]\n\
                    EnvironmentFile=-/etc/sysconfig/one\n\
                    EnvironmentFile=-/etc/sysconfig/two\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.one", "# one\n"),
                ("/usr/share/fillup-templates/sysconfig.two", "# two\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|b| {
                b.post_install_script(
                    "/bin/fillup -q /etc/sysconfig/one /usr/share/fillup-templates/sysconfig.one\n",
                );
            },
        );
        assert!(fillup_findings(&pkg).is_empty());
    }

    #[test]
    fn fillup_env_file_list_second_token_gates() {
        // systemd accepts a whitespace-separated list of paths: a
        // template target in second position gates like a first one,
        // and its own `-` prefix sets the level.
        let unit = "[Service]\nEnvironmentFile=/etc/sysconfig/other -/etc/sysconfig/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|_| {},
        );
        let found = fillup_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert_eq!(found[0].2, Level::Warning);
        // A single-quoted token resolves the same way.
        let unit = "[Service]\nEnvironmentFile='-/etc/sysconfig/demo'\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|_| {},
        );
        let found = fillup_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert_eq!(found[0].2, Level::Warning);
    }

    #[test]
    fn fillup_tmpfiles_truncate_and_write_are_quiet() {
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\n";
        for kind in ["F", "w"] {
            let tmpfiles = format!(
                "{kind} /etc/sysconfig/demo - - - - /usr/share/fillup-templates/sysconfig.demo\n"
            );
            let (pkg, _src, _extract) = fillup_test_pkg(
                "demo",
                &[
                    ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                    ("/usr/lib/systemd/system/demo.service", unit),
                    ("/usr/lib/tmpfiles.d/demo.conf", tmpfiles.as_str()),
                ],
                &[],
                &|_| {},
            );
            assert!(
                fillup_findings(&pkg).is_empty(),
                "tmpfiles type {kind} materialises the target"
            );
        }
    }

    #[test]
    fn fillup_shipped_target_directory_still_fires() {
        // The shipped-target exemption covers payload files only: a
        // directory entry at the target path ships no content.
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|b| {
                b.with_dir_entry(rpm::FileOptions::dir("/etc/sysconfig/demo"))
                    .unwrap();
            },
        );
        assert_eq!(fillup_findings(&pkg).len(), 1);
    }

    #[test]
    fn fillup_shipped_target_symlink_still_fires() {
        // A symlink at the target path ships no payload content
        // either, so it earns no exemption.
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|b| {
                b.with_symlink(rpm::FileOptions::symlink(
                    "/etc/sysconfig/demo",
                    "/usr/share/fillup-templates/sysconfig.demo",
                ))
                .unwrap();
            },
        );
        assert_eq!(fillup_findings(&pkg).len(), 1);
    }

    #[test]
    fn fillup_shipped_target_is_quiet() {
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/etc/sysconfig/demo", "DEMO_HOST=\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|_| {},
        );
        assert!(fillup_findings(&pkg).is_empty());
    }

    #[test]
    fn fillup_tmpfiles_copy_is_quiet() {
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\n";
        let tmpfiles = "C /etc/sysconfig/demo - - - - /usr/share/fillup-templates/sysconfig.demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
                ("/usr/lib/tmpfiles.d/demo.conf", tmpfiles),
            ],
            &[],
            &|_| {},
        );
        assert!(fillup_findings(&pkg).is_empty());
    }

    #[test]
    fn fillup_other_package_file_is_quiet() {
        // The unit reads only a file this package does not template.
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/proxy\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                ("/usr/share/fillup-templates/sysconfig.demo", "# template\n"),
                ("/usr/lib/systemd/system/demo.service", unit),
            ],
            &[],
            &|_| {},
        );
        assert!(fillup_findings(&pkg).is_empty());
    }

    #[test]
    fn fillup_ghost_template_is_quiet() {
        let unit = "[Service]\nEnvironmentFile=-/etc/sysconfig/demo\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[("/usr/lib/systemd/system/demo.service", unit)],
            &["/usr/share/fillup-templates/sysconfig.demo"],
            &|_| {},
        );
        assert!(fillup_findings(&pkg).is_empty());
    }

    #[test]
    fn fillup_specifier_target_is_quiet() {
        let unit = "[Service]\nEnvironmentFile=/etc/sysconfig/foo-%i\n";
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[
                (
                    "/usr/share/fillup-templates/sysconfig.foo-%i",
                    "# template\n",
                ),
                ("/usr/lib/systemd/system/demo@.service", unit),
            ],
            &[],
            &|_| {},
        );
        assert!(fillup_findings(&pkg).is_empty());
    }

    #[test]
    fn fillup_unread_template_is_quiet() {
        // The lighttpd shape: a template nothing reads.
        let (pkg, _src, _extract) = fillup_test_pkg(
            "demo",
            &[("/usr/share/fillup-templates/sysconfig.demo", "# template\n")],
            &[],
            &|_| {},
        );
        assert!(fillup_findings(&pkg).is_empty());
    }

    #[test]
    fn fillup_package_itself_is_quiet() {
        let (pkg, _src, _extract) =
            sysconfig_test_pkg("fillup", &[("/etc/sysconfig/fillup", "FOO=1\n")], None);
        assert!(
            sysconfig_findings(&pkg).is_empty(),
            "the fillup package is exempt"
        );
    }

    #[test]
    fn sysconfig_fillup_command_substitution_fires() {
        // `$(...)` is a command position: the substitution runs fillup.
        // The substitution sits mid-line after a word, so no other
        // separator (line start, `;`, `&&`) can reach the invocation:
        // only the `$(` separator itself can, which pins it -- a bare
        // `x=$(/bin/fillup ...)` at line start would also be reached by
        // the line-start separator through the path-prefix group.
        assert_eq!(
            sysconfig_fillup_uses(
                &[],
                &[(
                    "%post",
                    "echo x=$(/bin/fillup -q /etc/sysconfig/demo /usr/share/fillup-templates/sysconfig.demo)\n"
                )],
                &[]
            ),
            vec!["calls fillup from the %post scriptlet".to_string()]
        );
        let post = "echo x=$(/bin/fillup -q /etc/sysconfig/demo /usr/share/fillup-templates/sysconfig.demo)\n";
        let (pkg, _src, _extract) = sysconfig_test_pkg("demo", &[], Some(post));
        let found = sysconfig_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert_eq!(found[0].2, Level::Warning);
        assert!(
            found[0].1.contains("%post"),
            "detail names the scriptlet: {}",
            found[0].1
        );
    }

    #[test]
    fn sysconfig_uses_blessed_subdirs_are_quiet() {
        // The Good patterns of the `filelist-forbidden-sysconfig` rule
        // bless these subtrees; a payload there is not a category-1 use.
        assert!(sysconfig_fillup_uses(&["/etc/sysconfig/network/ifcfg-eth0"], &[], &[]).is_empty());
        assert!(sysconfig_fillup_uses(&["/etc/sysconfig/scripts/ifup-route"], &[], &[]).is_empty());
        assert!(sysconfig_fillup_uses(&["/etc/sysconfig/cbq"], &[], &[]).is_empty());
        // A blessed file does not mask an ordinary one: the ordinary
        // file is the use that is named.
        assert_eq!(
            sysconfig_fillup_uses(
                &["/etc/sysconfig/network/ifcfg-eth0", "/etc/sysconfig/demo"],
                &[],
                &[]
            ),
            vec!["ships file /etc/sysconfig/demo".to_string()]
        );
    }

    #[test]
    fn sysconfig_blessed_network_payload_is_quiet() {
        let (pkg, _src, _extract) = sysconfig_test_pkg(
            "demo",
            &[("/etc/sysconfig/network/ifcfg-eth0", "BOOTPROTO=dhcp\n")],
            None,
        );
        assert!(
            sysconfig_findings(&pkg).is_empty(),
            "a Good-pattern payload is not a use"
        );
    }

    #[test]
    fn sysconfig_blessed_scripts_payload_is_quiet() {
        let (pkg, _src, _extract) = sysconfig_test_pkg(
            "demo",
            &[("/etc/sysconfig/scripts/ifup-route", "#!/bin/sh\n")],
            None,
        );
        assert!(
            sysconfig_findings(&pkg).is_empty(),
            "a Good-pattern payload is not a use"
        );
    }

    #[test]
    fn sysconfig_blessed_payload_does_not_mask_scriptlet_use() {
        // The Good allowlist covers only the payload category: a fillup
        // call from a scriptlet still fires, and the blessed payload is
        // not named as evidence.
        let post =
            "/bin/fillup -q /etc/sysconfig/demo /usr/share/fillup-templates/sysconfig.demo\n";
        let (pkg, _src, _extract) = sysconfig_test_pkg(
            "demo",
            &[("/etc/sysconfig/network/ifcfg-eth0", "BOOTPROTO=dhcp\n")],
            Some(post),
        );
        let found = sysconfig_findings(&pkg);
        assert_eq!(found.len(), 1, "exactly one finding: {found:?}");
        assert!(
            found[0].1.contains("%post"),
            "detail names the scriptlet: {}",
            found[0].1
        );
        assert!(
            !found[0].1.contains("ifcfg-eth0"),
            "blessed payload is not evidence: {}",
            found[0].1
        );
    }

    #[test]
    fn sysconfig_ordinary_package_is_quiet() {
        let (pkg, _src, _extract) = sysconfig_test_pkg(
            "demo",
            &[
                ("/usr/bin/demo", "#!/bin/sh\n"),
                ("/usr/share/demo/README", "demo\n"),
            ],
            Some("echo installed\n"),
        );
        assert!(
            sysconfig_findings(&pkg).is_empty(),
            "no sysconfig use, no finding"
        );
    }

    /// Build a package whose files carry real on-disk content and the
    /// exact modes given, so the script text checks run for real
    /// (mirrors the spurious_exec_pkg helper, with per-file modes).
    fn script_mode_pkg(dir: &tempfile::TempDir, files: &[(&str, u32, &str, &[u8])]) -> Pkg {
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        pkg.name = "nonexec-demo".to_string();
        pkg.files = files
            .iter()
            .map(|(name, mode, magic, content)| {
                let path = dir.path().join(name.trim_start_matches('/'));
                std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
                std::fs::write(&path, content).expect("write temp file");
                PkgFile {
                    name: name.to_string(),
                    path: path.to_string_lossy().into_owned(),
                    mode: *mode,
                    magic: magic.to_string(),
                    ..Default::default()
                }
            })
            .collect();
        pkg
    }

    fn script_finding_lines(pkg: &Pkg, config: &Config) -> Vec<(String, String)> {
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(config);
        check.check(pkg, config, &mut out);
        out.results().to_vec()
    }

    /// Files inside a Python library tree are modules or package data
    /// consumed by import or by reading: a non-executable file there
    /// with an interpreter line draws no `non-executable-script`
    /// (issue #813). Covers the salt shapes: a vendored Python module,
    /// a deploy script the owning program reads and streams elsewhere,
    /// and a Jinja template whose rendered output is a script.
    #[test]
    fn non_executable_script_silent_inside_python_library_trees() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/lib/python3.13/site-packages/pkg/mod.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/lib64/python3.14/site-packages/pkg/deploy.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/lib/python3/dist-packages/pkg/tool.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/python3\n",
                ),
                (
                    "/usr/lib/python3.13/site-packages/pkg/route.jinja",
                    0o100644,
                    "ASCII text",
                    b"#!/bin/sh\n",
                ),
            ],
        );
        let lines = script_finding_lines(&pkg, &config);
        let flagged: Vec<&str> = lines
            .iter()
            .filter(|(n, _)| n == "non-executable-script")
            .map(|(_, line)| line.as_str())
            .collect();
        assert_eq!(
            flagged,
            Vec::<&str>::new(),
            "no non-executable-script inside Python library trees: {lines:?}"
        );
    }

    /// The gate is confined to the shapes it names: a non-executable
    /// script with an interpreter line in any other location still
    /// draws `non-executable-script` (issues #813, #845), including a
    /// directory whose name merely starts with an exempt component's
    /// name, an exempt word carried by a file name rather than a
    /// directory, a template word that is not the final suffix, a
    /// shape matched inside a script directory, an exempt component
    /// in an entry-point tree or outside the data and library
    /// trees, and a sourced basename outside the sourced locations.
    #[test]
    fn non_executable_script_still_fires_outside_data_shapes() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/share/myapp/helper.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/libexec/myapp/run.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/myapp/site-packages-other/mod.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/srcfoo/scripts/run.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/bin/tool.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/python3\n",
                ),
                (
                    "/usr/share/myapp/tests.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/share/myapp/lib.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/share/myapp/run.sample.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/myapp/profile.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/myapp/extensions/tool.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/myapp/sleeper.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/falsehood\n",
                ),
                (
                    "/usr/bin/gen.py.in",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/python3\n",
                ),
                (
                    "/usr/bin/never.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/false\n",
                ),
                (
                    "/usr/sbin/rc",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/sh\n",
                ),
                (
                    "/usr/libexec/myapp/src/run.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/libexec/myapp/tests/run.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/libexec/myapp/extensions/tool.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/python3\n",
                ),
                (
                    "/usr/libexec/myapp/bash/run.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/libexec/myapp/profile",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/sh\n",
                ),
                (
                    "/opt/myapp/tests/run.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
            ],
        );
        let lines = script_finding_lines(&pkg, &config);
        for path in [
            "/usr/share/myapp/helper.py",
            "/usr/libexec/myapp/run.sh",
            "/usr/share/myapp/site-packages-other/mod.py",
            "/usr/srcfoo/scripts/run.sh",
            "/usr/bin/tool.py",
            "/usr/share/myapp/tests.py",
            "/usr/share/myapp/lib.py",
            "/usr/share/myapp/run.sample.sh",
            "/usr/share/myapp/profile.sh",
            "/usr/share/myapp/extensions/tool.sh",
            "/usr/share/myapp/sleeper.sh",
            "/usr/bin/gen.py.in",
            "/usr/bin/never.sh",
            "/usr/sbin/rc",
            "/usr/libexec/myapp/src/run.sh",
            "/usr/libexec/myapp/tests/run.py",
            "/usr/libexec/myapp/extensions/tool.py",
            "/usr/libexec/myapp/bash/run.sh",
            "/usr/libexec/myapp/profile",
            "/opt/myapp/tests/run.py",
        ] {
            assert!(
                lines
                    .iter()
                    .any(|(n, line)| n == "non-executable-script" && line.contains(path)),
                "non-executable-script must fire for {path}: {lines:?}"
            );
        }
    }

    /// The shapes from issue #845: a non-executable file with an
    /// interpreter line that the owning program consumes by reading,
    /// importing, sourcing or rendering draws no
    /// `non-executable-script`. Covers a shipped source tree and a
    /// test fixture inside it, a language directory outside the
    /// Python library trees, gdb's auto-load directory, host-loaded
    /// Python plugin directories, the Node and Ruby library trees,
    /// the Perl library root, a nested `lib` directory holding shell,
    /// Ruby and Perl library files, an application `src` layout,
    /// sample material, a sourced bashrc fragment, a profile file,
    /// an rc fragment in a library tree, a plugin
    /// whose interpreter line names `false`, a bash-completion file,
    /// a shell library directory named for its language, and
    /// template files.
    #[test]
    fn non_executable_script_silent_for_data_shapes() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sh = "Bourne-Again shell script, ASCII text executable";
        let py = "Python script, ASCII text executable";
        let rb = "Ruby script, ASCII text executable";
        let pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/src/linux-9.9/scripts/build.sh",
                    0o100644,
                    sh,
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/src/skylib/tests/copy_file/a.txt",
                    0o100644,
                    "ASCII text",
                    b"#!/bin/sh\n",
                ),
                (
                    "/usr/lib64/dirsrv/python/failedbinds.py",
                    0o100644,
                    py,
                    b"#!/usr/bin/python3\n",
                ),
                (
                    "/usr/lib/python3.13/tools/tool.py",
                    0o100644,
                    py,
                    b"#!/usr/bin/python3\n",
                ),
                (
                    "/usr/share/gdb/auto-load/usr/sbin/ns-slapd-gdb.py",
                    0o100644,
                    py,
                    b"#!/usr/bin/python3\n",
                ),
                (
                    "/usr/share/inkscape/extensions/addnodes.py",
                    0o100644,
                    py,
                    b"#!/usr/bin/python3\n",
                ),
                (
                    "/usr/share/myapp/plugins/hook.py",
                    0o100644,
                    py,
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/lib64/node_modules/pkg/cli.js",
                    0o100644,
                    "ASCII text",
                    b"#!/usr/bin/env node\n",
                ),
                (
                    "/usr/libexec/hawk/vendor/gems/builder-3.3.0/lib/builder.rb",
                    0o100644,
                    rb,
                    b"#!/usr/bin/ruby\n",
                ),
                (
                    "/usr/lib64/ruby/english.rb",
                    0o100644,
                    rb,
                    b"#!/usr/bin/ruby\n",
                ),
                (
                    "/usr/lib/perl5/vendor_perl/5.44.0/Helper.pl",
                    0o100644,
                    "Perl script text executable",
                    b"#!/usr/bin/perl\n",
                ),
                (
                    "/usr/share/cockpit/devel/lib/credentials-test.sh",
                    0o100644,
                    sh,
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/cadence/src/cadence.py",
                    0o100644,
                    py,
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/share/scribus/samples/Sample1.py",
                    0o100644,
                    py,
                    b"#!/usr/bin/python3\n",
                ),
                (
                    "/usr/lib/blktests/tests/block/001",
                    0o100644,
                    sh,
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/hxtools/hxtools_bashrc.bash",
                    0o100644,
                    sh,
                    b"#!/bin/bash\n",
                ),
                ("/usr/etc/profile", 0o100644, sh, b"#!/bin/sh\n"),
                (
                    "/usr/share/uwsm/plugins/sway.sh",
                    0o100644,
                    sh,
                    b"#!/bin/false\n",
                ),
                (
                    "/usr/share/bash-completion/completions/myapp",
                    0o100644,
                    sh,
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/scap-security-guide/bash/sle-script-standard.sh",
                    0o100644,
                    sh,
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/myapp/templates/deploy.tmpl",
                    0o100644,
                    sh,
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/myapp/gen.py.in",
                    0o100644,
                    py,
                    b"#!/usr/bin/python3\n",
                ),
                (
                    "/usr/share/myapp/gems/tool.rb",
                    0o100644,
                    rb,
                    b"#!/usr/bin/ruby\n",
                ),
                ("/usr/lib/myapp/common/rc", 0o100644, sh, b"#!/bin/bash\n"),
                (
                    "/usr/share/myapp/lib/helper.pl",
                    0o100644,
                    "Perl script text executable",
                    b"#!/usr/bin/perl\n",
                ),
                (
                    "/usr/share/myapp/never.py",
                    0o100644,
                    py,
                    b"#!/usr/bin/false\n",
                ),
            ],
        );
        let lines = script_finding_lines(&pkg, &config);
        let flagged: Vec<&str> = lines
            .iter()
            .filter(|(n, _)| n == "non-executable-script")
            .map(|(_, line)| line.as_str())
            .collect();
        assert_eq!(
            flagged,
            Vec::<&str>::new(),
            "no non-executable-script for data shapes: {lines:?}"
        );
    }

    /// The sourced-fragment proof is read from the script's own
    /// text: a top-level `return` counts bare and inside top-level
    /// control flow, a function definition and a redirection or
    /// assignment prefix alike.
    #[test]
    fn top_level_return_shapes() {
        let positives = [
            "#!/bin/bash\nreturn 0\n",
            "#!/bin/sh\nif [ -z \"$X\" ]; then\n  return 1\nfi\n",
            "#!/bin/sh\nfor f in a b; do\n  return 1\ndone\n",
            "#!/bin/sh\nwhile read -r l; do\n  return 1\ndone\n",
            "#!/bin/sh\ncase $1 in\n  a) return 1 ;;\nesac\n",
            "#!/bin/sh\n{ return 1; }\n",
            "#!/bin/sh\n( return 1 )\n",
            "#!/bin/sh\nf() { return 1; }\nreturn 0\n",
            "#!/bin/sh\n2>/dev/null return 1\n",
            "#!/bin/sh\nX=1 return 1\n",
            "#!/bin/sh\ncat <<EOF\nbody\nEOF\nreturn 0\n",
            "#!/bin/sh\n! return 1\n",
            "#!/bin/bash\ncase $1 in\n  a|b) echo ok ;;\nesac\nreturn 0\n",
            "#!/bin/bash\nx=$((1+2))\nreturn 0\n",
            "#!/bin/bash\nx=${#a[@]}\nreturn 0\n",
            "#!/bin/bash\necho }\nreturn 0\n",
        ];
        for text in positives {
            assert!(
                shell_script_has_top_level_return(text),
                "top-level return expected: {text:?}"
            );
        }
    }

    /// The shapes that merely mention `return` are not a proof:
    /// returns inside function definitions of every header form
    /// (`name ()`, `function name`, with and without `()`) and
    /// every body form (brace group, subshell and brace-less
    /// compound commands), in comments — a backslash-continued
    /// one included — in quoted strings, in here-document bodies
    /// and in substitutions (process substitutions included),
    /// and `return` read as an argument, a value, a loop
    /// variable or a `case` pattern, a pattern alternative
    /// before a `|` included.
    #[test]
    fn no_top_level_return_shapes() {
        let negatives = [
            "#!/bin/bash\necho hello\n",
            "#!/bin/bash\nf() { return 1; }\n",
            "#!/bin/bash\nf()\n{\n  return 1\n}\n",
            "#!/bin/bash\nfunction f { return 1; }\n",
            "#!/bin/bash\nfunction f() { return 1; }\n",
            "#!/bin/bash\nf() ( return 1 )\n",
            "#!/bin/bash\nouter() { inner() { return 1; }; return 2; }\n",
            "#!/bin/bash\n# return 0\necho hi # return\n",
            "#!/bin/bash\necho \"return\"\necho 'return'\n",
            "#!/bin/bash\necho return\n",
            "#!/bin/bash\nx=return\n",
            "#!/bin/bash\nfor return in a b; do echo $return; done\n",
            "#!/bin/bash\ncase $1 in\n  return) echo x ;;\nesac\n",
            "#!/bin/bash\ncat <<EOF\nreturn 0\nEOF\n",
            "#!/bin/bash\ncat <<-'EOF'\n\treturn 0\n\tEOF\n",
            "#!/bin/bash\nx=$(return)\n",
            "#!/bin/bash\necho ${x:-return}\n",
            "#!/bin/bash\ncase $1 in\n  a|return|b) echo ok ;;\nesac\n",
            "#!/bin/bash\nf() if true; then return 0; fi\n",
            "#!/bin/bash\nf() while true; do return 0; done\n",
            "#!/bin/bash\nf() until true; do return 0; done\n",
            "#!/bin/bash\nf() for i in 1 2; do return 0; done\n",
            "#!/bin/bash\nf() case $1 in\n  a) return 0 ;;\nesac\n",
            "#!/bin/bash\nf() select i in a; do return 0; done\n",
            "#!/bin/bash\nmy-func() { return 1; }\n",
            "#!/bin/bash\nmy.func() { return 1; }\n",
            "#!/bin/bash\nfunction my-func { return 1; }\n",
            "#!/bin/bash\nx=$(case $y in a) return 1 ;; esac)\n",
            "#!/bin/bash\nx=$(echo \")\"; return 1)\n",
            "#!/bin/bash\nx=$(echo $(return 1))\n",
            "#!/bin/bash\ncat <(return 1)\n",
            "#!/bin/bash\ndiff <(return 1) >(return 2)\n",
            "#!/bin/bash\nf() { return 1; }>log\n",
            "#!/bin/bash\n# setup \\\nreturn 0\necho hi\n",
            "#!/bin/bash\necho a } return 0\n",
            "#!/bin/bash\necho { return 0\n",
        ];
        for text in negatives {
            assert!(
                !shell_script_has_top_level_return(text),
                "no top-level return expected: {text:?}"
            );
        }
    }

    /// The dialect gate: the proof holds for the sh family,
    /// resolved through `/usr/bin/env`, and not for other
    /// interpreters -- zsh included, which runs a script in a
    /// function-like context where `return` is legal.
    #[test]
    fn posix_shell_interpreter_resolution() {
        assert!(interpreter_is_posix_shell("/bin/sh", ""));
        assert!(interpreter_is_posix_shell("/bin/bash", ""));
        assert!(interpreter_is_posix_shell("/usr/bin/env", "bash"));
        assert!(interpreter_is_posix_shell("/usr/bin/env", "-i /bin/sh"));
        assert!(interpreter_is_posix_shell("/usr/bin/env", "FOO=1 dash"));
        assert!(!interpreter_is_posix_shell("/usr/bin/env", "python3"));
        assert!(!interpreter_is_posix_shell("/usr/bin/env", ""));
        assert!(!interpreter_is_posix_shell("/bin/zsh", ""));
        assert!(!interpreter_is_posix_shell("/usr/bin/python3", ""));
    }

    /// A shell script whose text marks it as a sourced fragment
    /// (a top-level `return`) draws no `non-executable-script`:
    /// the xim shape, whose returns sit past the 2048-byte peek so
    /// the proof has to read the whole file, an `/usr/bin/env`
    /// fragment, and a fragment whose only return sits inside
    /// top-level control flow.
    #[test]
    fn non_executable_script_silent_for_provable_sourced_fragments() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sh = "Bourne-Again shell script, ASCII text executable";
        let mut xim = String::from(
            "#!/bin/bash\n# XIM fragment\nsetup() {\n  XMODIFIERS=@im=local\n}\ncleanup() {\n  unset XMODIFIERS\n}\n",
        );
        while xim.len() < 2100 {
            xim.push_str("# input method selection follows\n");
        }
        xim.push_str("if [ -z \"$InputMethod\" ]; then\n  return 0\nfi\nreturn 0\n");
        let pkg = script_mode_pkg(
            &dir,
            &[
                ("/usr/etc/X11/xim", 0o100644, sh, xim.as_bytes()),
                (
                    "/usr/share/myapp/helper",
                    0o100644,
                    sh,
                    b"#!/usr/bin/env bash\nreturn 0\n",
                ),
                (
                    "/usr/share/myapp/frag",
                    0o100644,
                    sh,
                    b"#!/bin/sh\nif [ -n \"$SKIP\" ]; then\n  return 1\nfi\n",
                ),
            ],
        );
        let lines = script_finding_lines(&pkg, &config);
        let flagged: Vec<&str> = lines
            .iter()
            .filter(|(n, _)| n == "non-executable-script")
            .map(|(_, line)| line.as_str())
            .collect();
        assert_eq!(
            flagged,
            Vec::<&str>::new(),
            "no non-executable-script for provable fragments: {lines:?}"
        );
    }

    /// The proof is confined to what it proves: a script whose
    /// only `return` sits inside a function, a non-shell script
    /// carrying a top-level `return`, a zsh script (legal there),
    /// and a provable fragment installed directly in a script
    /// directory all keep `non-executable-script`.
    #[test]
    fn non_executable_script_still_fires_for_unprovable_scripts() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sh = "Bourne-Again shell script, ASCII text executable";
        let py = "Python script, ASCII text executable";
        let pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/etc/X11/ximfunc",
                    0o100644,
                    sh,
                    b"#!/bin/bash\nf() { return 1; }\nf\n",
                ),
                (
                    "/usr/share/myapp/tool.py",
                    0o100644,
                    py,
                    b"#!/usr/bin/python3\nreturn\n",
                ),
                (
                    "/usr/share/myapp/ztool",
                    0o100644,
                    sh,
                    b"#!/bin/zsh\nreturn 1\n",
                ),
                ("/usr/bin/xim", 0o100644, sh, b"#!/bin/bash\nreturn 0\n"),
            ],
        );
        let lines = script_finding_lines(&pkg, &config);
        for path in [
            "/usr/etc/X11/ximfunc",
            "/usr/share/myapp/tool.py",
            "/usr/share/myapp/ztool",
            "/usr/bin/xim",
        ] {
            assert!(
                lines
                    .iter()
                    .any(|(n, line)| n == "non-executable-script" && line.contains(path)),
                "non-executable-script must fire for {path}: {lines:?}"
            );
        }
    }

    /// A `.py` file whose directory is a Python package directory
    /// — the package ships an `__init__.py` in the same directory —
    /// is a module of an application-private package tree, imported
    /// by the owning program: a non-executable module there draws
    /// no `non-executable-script`. The bounds: a `.py` file with no
    /// package marker, a package tree in an entry-point tree
    /// (`/usr/libexec/`), and a non-Python file inside a package
    /// directory all keep firing.
    #[test]
    fn non_executable_script_silent_in_python_package_dirs() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/lib64/kitty/kitty/__init__.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/python\n",
                ),
                (
                    "/usr/lib64/kitty/kitty/boss.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/python\n",
                ),
                (
                    "/usr/share/hplip/base/__init__.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/share/hplip/base/device.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/share/myapp/tool.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/libexec/myapp/pkg/__init__.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/python3\n",
                ),
                (
                    "/usr/libexec/myapp/pkg/mod.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/python3\n",
                ),
                (
                    "/usr/share/myapp/pkg/__init__.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/python3\n",
                ),
                (
                    "/usr/share/myapp/pkg/run.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
            ],
        );
        let lines = script_finding_lines(&pkg, &config);
        for path in [
            "/usr/lib64/kitty/kitty/__init__.py",
            "/usr/lib64/kitty/kitty/boss.py",
            "/usr/share/hplip/base/__init__.py",
            "/usr/share/hplip/base/device.py",
            "/usr/share/myapp/pkg/__init__.py",
        ] {
            assert!(
                !lines
                    .iter()
                    .any(|(n, line)| n == "non-executable-script" && line.contains(path)),
                "no non-executable-script for package module {path}: {lines:?}"
            );
        }
        for path in [
            "/usr/share/myapp/tool.py",
            "/usr/libexec/myapp/pkg/__init__.py",
            "/usr/libexec/myapp/pkg/mod.py",
            "/usr/share/myapp/pkg/run.sh",
        ] {
            assert!(
                lines
                    .iter()
                    .any(|(n, line)| n == "non-executable-script" && line.contains(path)),
                "non-executable-script must fire for {path}: {lines:?}"
            );
        }
    }

    /// Sourced-fragment directories (`include`, `common`),
    /// documentation trees (`doc`, `docs`), CI harness directories
    /// (`ci`), image payload under a `rootfs` component and `.ex`
    /// example templates are content the owning program sources,
    /// reads or assembles elsewhere: non-executable files there
    /// draw no `non-executable-script`. The bounds: the same
    /// components in an entry-point tree or outside the data
    /// trees, a `rootfs` basename rather than a directory
    /// component, and an Elixir `.ex` script, all keep firing.
    #[test]
    fn non_executable_script_silent_for_fragment_doc_and_image_trees() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/share/lynis/include/functions",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/sh\n",
                ),
                (
                    "/usr/lib/blktests/common/rc",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/texmf/doc/latex/foo/build.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/ceph/mgr/dashboard/ci/run.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/var/lib/warewulf/overlays/ignition/rootfs/warewulf/wwinit.d/10-ignition.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/sh\n",
                ),
                (
                    "/usr/share/debhelper/dh_make/debian/postinst.ex",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/sh\n",
                ),
                (
                    "/usr/share/myapp/docs/tool.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/myapp/beam/serve.ex",
                    0o100644,
                    "ASCII text executable",
                    b"#!/usr/bin/env elixir\n",
                ),
                (
                    "/usr/libexec/myapp/common/helper.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/myapp/scripts/build.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/myapp/rootfs.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/opt/myapp/doc/build.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
            ],
        );
        let lines = script_finding_lines(&pkg, &config);
        for path in [
            "/usr/share/lynis/include/functions",
            "/usr/lib/blktests/common/rc",
            "/usr/share/texmf/doc/latex/foo/build.sh",
            "/usr/share/ceph/mgr/dashboard/ci/run.sh",
            "/var/lib/warewulf/overlays/ignition/rootfs/warewulf/wwinit.d/10-ignition.sh",
            "/usr/share/debhelper/dh_make/debian/postinst.ex",
            "/usr/share/myapp/docs/tool.sh",
        ] {
            assert!(
                !lines
                    .iter()
                    .any(|(n, line)| n == "non-executable-script" && line.contains(path)),
                "no non-executable-script for data shape {path}: {lines:?}"
            );
        }
        for path in [
            "/usr/libexec/myapp/common/helper.sh",
            "/usr/share/myapp/scripts/build.sh",
            "/usr/share/myapp/rootfs.sh",
            "/opt/myapp/doc/build.sh",
            // An Elixir script is no Debian example template:
            // `.ex` is Elixir's own extension.
            "/usr/share/myapp/beam/serve.ex",
        ] {
            assert!(
                lines
                    .iter()
                    .any(|(n, line)| n == "non-executable-script" && line.contains(path)),
                "non-executable-script must fire for {path}: {lines:?}"
            );
        }
    }

    /// The gate covers the one emission only: an executable file
    /// inside a source tree still draws the interpreter findings, so
    /// `env-script-interpreter` keeps parity there (issue #845).
    #[test]
    fn executable_script_in_source_tree_still_draws_interpreter_findings() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = script_mode_pkg(
            &dir,
            &[(
                "/usr/src/linux-9.9/scripts/tool.py",
                0o100755,
                "Python script, ASCII text executable",
                b"#!/usr/bin/env python3\n",
            )],
        );
        let lines = script_finding_lines(&pkg, &config);
        let names: Vec<String> = lines.iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "env-script-interpreter");
        assert_lacks(&names, "non-executable-script");
    }

    /// The gate covers the one emission only: an executable file
    /// inside a Python library tree still draws the interpreter
    /// findings, so `env-script-interpreter` keeps parity there
    /// (issue #813).
    #[test]
    fn executable_script_in_python_tree_still_draws_interpreter_findings() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = script_mode_pkg(
            &dir,
            &[(
                "/usr/lib/python3.13/site-packages/pkg/tool.py",
                0o100755,
                "Python script, ASCII text executable",
                b"#!/usr/bin/env python3\n",
            )],
        );
        let lines = script_finding_lines(&pkg, &config);
        let names: Vec<String> = lines.iter().map(|(n, _)| n.clone()).collect();
        assert_has(&names, "env-script-interpreter");
        assert_lacks(&names, "non-executable-script");
    }

    fn flagged(lines: &[(String, String)], tag: &str, path: &str) -> bool {
        lines
            .iter()
            .any(|(n, line)| n == tag && line.contains(path))
    }

    /// Test packages carry their suite as payload: a harness runs
    /// the scripts by path, so a non-executable test script draws
    /// no `non-executable-script` and an executable one's env
    /// interpreter line draws no `env-script-interpreter`,
    /// wherever in the tree the payload sits (the audit's
    /// lvm2-testsuite, systemd-testsuite and pcp-testsuite
    /// shapes, the last under /usr/libexec/).
    #[test]
    fn script_findings_silent_in_test_packages() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/share/lvm2-testsuite/shell/check.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/libexec/pcp/stash/testsuite/src/helper.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/lib/systemd/tests/integration-tests/run.sh",
                    0o100755,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/usr/bin/env bash\n",
                ),
            ],
        );
        pkg.name = "lvm2-testsuite".to_string();
        let lines = script_finding_lines(&pkg, &config);
        for (tag, path) in [
            (
                "non-executable-script",
                "/usr/share/lvm2-testsuite/shell/check.sh",
            ),
            (
                "non-executable-script",
                "/usr/libexec/pcp/stash/testsuite/src/helper.py",
            ),
            (
                "env-script-interpreter",
                "/usr/lib/systemd/tests/integration-tests/run.sh",
            ),
        ] {
            assert!(
                !flagged(&lines, tag, path),
                "no {tag} for test payload {path}: {lines:?}"
            );
        }
    }

    /// Test trees inside a plain package's source or data tree are
    /// harness material the same way: test directories of the
    /// shipped bazel and kafka source trees, test helpers bundled
    /// inside a Python package, and a `testsuite` tree under a
    /// doc directory draw neither script finding.
    #[test]
    fn script_findings_silent_in_test_trees_of_plain_packages() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/src/kafka/tests/bin/run.sh",
                    0o100755,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/usr/bin/env bash\n",
                ),
                (
                    "/usr/lib/python3.13/site-packages/certbot/tests/helper.py",
                    0o100755,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/share/doc/myapp/testsuite/check.q",
                    0o100644,
                    "ASCII text executable",
                    b"#!/usr/bin/env qore\n",
                ),
                (
                    "/usr/share/myapp/integration-tests/tool.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
            ],
        );
        let lines = script_finding_lines(&pkg, &config);
        for (tag, path) in [
            ("env-script-interpreter", "/usr/src/kafka/tests/bin/run.sh"),
            (
                "env-script-interpreter",
                "/usr/lib/python3.13/site-packages/certbot/tests/helper.py",
            ),
            (
                "non-executable-script",
                "/usr/share/doc/myapp/testsuite/check.q",
            ),
            (
                "non-executable-script",
                "/usr/share/myapp/integration-tests/tool.py",
            ),
        ] {
            assert!(
                !flagged(&lines, tag, path),
                "no {tag} for test tree payload {path}: {lines:?}"
            );
        }
    }

    /// The test gate's bounds: an entry point in a script
    /// directory keeps both findings whatever the package is
    /// called; fused package names (blktests, perftest) carry no
    /// test fact; a weak test component in an entry-point tree
    /// (/usr/libexec/) does not exempt; and the test word must be
    /// a directory component or a package-name component, never
    /// part of a file name or a longer component.
    #[test]
    fn script_findings_still_fire_at_test_gate_bounds() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/bin/runfabtests.py",
                    0o100755,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/lib/blktests/fio",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/perftest/run.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/libexec/myapp/tests/run.py",
                    0o100755,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/share/myapp/test-runner.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
                (
                    "/usr/share/myapp/contest/run.sh",
                    0o100644,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/bin/bash\n",
                ),
            ],
        );
        pkg.name = "fabtests".to_string();
        let lines = script_finding_lines(&pkg, &config);
        for (tag, path) in [
            ("env-script-interpreter", "/usr/bin/runfabtests.py"),
            ("non-executable-script", "/usr/lib/blktests/fio"),
            ("non-executable-script", "/usr/share/perftest/run.sh"),
            ("env-script-interpreter", "/usr/libexec/myapp/tests/run.py"),
            ("non-executable-script", "/usr/share/myapp/test-runner.sh"),
            ("non-executable-script", "/usr/share/myapp/contest/run.sh"),
        ] {
            assert!(
                flagged(&lines, tag, path),
                "{tag} must fire for {path}: {lines:?}"
            );
        }
    }

    /// The test gate's case folding and branch isolation, pinned
    /// at the predicate: the package-name branch alone (no test
    /// component anywhere in the tree) exempts; the same tree
    /// under a plain name does not; the script-directory bound
    /// beats the package-name branch; capitalisation changes
    /// nothing on either branch.
    #[test]
    fn script_is_test_data_case_and_branch_pins() {
        assert!(script_is_test_data(
            "widget-testsuite",
            "/usr/libexec/widget/helper.sh"
        ));
        assert!(!script_is_test_data(
            "widget",
            "/usr/libexec/widget/helper.sh"
        ));
        assert!(!script_is_test_data("lvm2-testsuite", "/usr/bin/runner"));
        assert!(script_is_test_data(
            "Widget-TestSuite",
            "/usr/libexec/widget/helper.sh"
        ));
        assert!(script_is_test_data(
            "widget",
            "/usr/share/widget/Tests/helper.py"
        ));
    }

    /// Source packages carry a vendored source tree as payload:
    /// upstream's own build and helper scripts inside it draw no
    /// `env-script-interpreter`, wherever in the tree the payload
    /// sits (the audit's kafka-source tree under /usr/src/, the
    /// rust*-src trees under /usr/lib/rustlib/src/, fpc-src under
    /// /usr/share/fpcsrc/).
    #[test]
    fn env_script_silent_in_source_packages() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/src/kafka/kafka-merge-pr.py",
                    0o100755,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
                (
                    "/usr/share/fpcsrc/rtl/unix/scripts/check_sys.sh",
                    0o100755,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/usr/bin/env bash\n",
                ),
            ],
        );
        pkg.name = "kafka-source".to_string();
        let lines = script_finding_lines(&pkg, &config);
        for path in [
            "/usr/src/kafka/kafka-merge-pr.py",
            "/usr/share/fpcsrc/rtl/unix/scripts/check_sys.sh",
        ] {
            assert!(
                !flagged(&lines, "env-script-interpreter", path),
                "no env-script-interpreter for source payload {path}: {lines:?}"
            );
        }
        let dir2 = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir2,
            &[(
                "/usr/lib/rustlib/src/rust/library/stdarch/ci/run.sh",
                0o100755,
                "Bourne-Again shell script, ASCII text executable",
                b"#!/usr/bin/env bash\n",
            )],
        );
        pkg.name = "rust1.97-src".to_string();
        let lines = script_finding_lines(&pkg, &config);
        assert!(
            !flagged(
                &lines,
                "env-script-interpreter",
                "/usr/lib/rustlib/src/rust/library/stdarch/ci/run.sh"
            ),
            "no env-script-interpreter for rust source payload: {lines:?}"
        );
        // A bare `src` name is the suffix arm with no hyphen at
        // all, and the component match folds case.
        for name in ["src", "widget-Source"] {
            let dir3 = tempfile::TempDir::new().expect("tmpdir");
            let mut pkg = script_mode_pkg(
                &dir3,
                &[(
                    "/usr/share/widget/data/tool.sh",
                    0o100755,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/usr/bin/env bash\n",
                )],
            );
            pkg.name = name.to_string();
            let lines = script_finding_lines(&pkg, &config);
            assert!(
                !flagged(
                    &lines,
                    "env-script-interpreter",
                    "/usr/share/widget/data/tool.sh"
                ),
                "no env-script-interpreter for bare/case-folded suffix {name}: {lines:?}"
            );
        }
    }

    /// The Go source tree is source payload the same way: the
    /// go1.* packages are not source-named, but
    /// /usr/share/go/<version>/src/ is Go's own shipped source
    /// tree, build scripts included, at any depth below `src`.
    #[test]
    fn env_script_silent_in_go_source_tree() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/share/go/1.24/src/make.bash",
                    0o100755,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/usr/bin/env bash\n",
                ),
                (
                    "/usr/share/go/1.24/src/cmd/compile/internal/ssa/_gen/cover.bash",
                    0o100755,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/usr/bin/env bash\n",
                ),
            ],
        );
        pkg.name = "go1.24".to_string();
        let lines = script_finding_lines(&pkg, &config);
        for path in [
            "/usr/share/go/1.24/src/make.bash",
            "/usr/share/go/1.24/src/cmd/compile/internal/ssa/_gen/cover.bash",
        ] {
            assert!(
                !flagged(&lines, "env-script-interpreter", path),
                "no env-script-interpreter for Go source payload {path}: {lines:?}"
            );
        }
    }

    /// The source gate's bounds: an entry point in a script
    /// directory keeps firing whatever the package is called; a
    /// %doc row in a source package keeps firing; the Go arm
    /// needs the version component and the `src` directory (the
    /// wasm helpers under misc/ are executed payload, not source);
    /// fused names (resource) carry no source fact; a `src` or
    /// `source` component in prefix or middle position
    /// (source-highlight, my-source-tools) carries no source
    /// fact either; an ordinary package's /usr/src payload is
    /// not covered; and the gate
    /// does not reach `non-executable-script` -- a source tree's
    /// non-executable script keeps that finding.
    #[test]
    fn env_script_still_fires_at_source_gate_bounds() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/bin/kafka-run.sh",
                    0o100755,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/usr/bin/env bash\n",
                ),
                (
                    "/usr/src/kafka/docs/tool.py",
                    0o100755,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\n",
                ),
            ],
        );
        pkg.name = "kafka-source".to_string();
        pkg.doc_files = vec!["/usr/src/kafka/docs/tool.py".to_string()];
        let lines = script_finding_lines(&pkg, &config);
        for (tag, path) in [
            ("env-script-interpreter", "/usr/bin/kafka-run.sh"),
            ("env-script-interpreter", "/usr/src/kafka/docs/tool.py"),
        ] {
            assert!(
                flagged(&lines, tag, path),
                "{tag} must fire for {path}: {lines:?}"
            );
        }
        // The source gate does not reach `non-executable-script`:
        // fpc-src's non-executable source script (a shape the
        // corpus fires on today) keeps that finding.
        let dir4 = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir4,
            &[(
                "/usr/share/fpcsrc/packages/odata/regen.sh",
                0o100644,
                "Bourne-Again shell script, ASCII text executable",
                b"#!/bin/bash\n",
            )],
        );
        pkg.name = "fpc-src".to_string();
        let lines = script_finding_lines(&pkg, &config);
        assert!(
            flagged(
                &lines,
                "non-executable-script",
                "/usr/share/fpcsrc/packages/odata/regen.sh"
            ),
            "non-executable-script must fire in a source package: {lines:?}"
        );
        let dir2 = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir2,
            &[
                (
                    "/usr/share/go/1.24/misc/wasm/run.sh",
                    0o100755,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/usr/bin/env bash\n",
                ),
                (
                    "/usr/share/go/src/make.bash",
                    0o100755,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/usr/bin/env bash\n",
                ),
                (
                    "/usr/share/go/latest/src/make.bash",
                    0o100755,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/usr/bin/env bash\n",
                ),
                (
                    "/usr/src/myapp/tool.sh",
                    0o100755,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/usr/bin/env bash\n",
                ),
            ],
        );
        pkg.name = "go1.24".to_string();
        let lines = script_finding_lines(&pkg, &config);
        for path in [
            "/usr/share/go/1.24/misc/wasm/run.sh",
            "/usr/share/go/src/make.bash",
            "/usr/share/go/latest/src/make.bash",
        ] {
            assert!(
                flagged(&lines, "env-script-interpreter", path),
                "env-script-interpreter must fire for {path}: {lines:?}"
            );
        }
        pkg.name = "myapp".to_string();
        let lines = script_finding_lines(&pkg, &config);
        assert!(
            flagged(&lines, "env-script-interpreter", "/usr/src/myapp/tool.sh"),
            "env-script-interpreter must fire for a plain package's /usr/src payload: {lines:?}"
        );
        // A `source` component in prefix or middle position is
        // not a source-tree carrier: source-highlight is a
        // regular tool package and my-source-tools a tool
        // collection, so their scripts keep firing. The same holds
        // when the word is fused into a single component as a
        // suffix (resource, mysrc, myresource): the name arm is
        // exact last-component equality, so a fused name is not a
        // source-tree carrier either.
        for name in [
            "source-highlight",
            "my-source-tools",
            "resource",
            "mysrc",
            "myresource",
        ] {
            let dir5 = tempfile::TempDir::new().expect("tmpdir");
            let mut pkg = script_mode_pkg(
                &dir5,
                &[(
                    "/usr/share/tools/data/tool.sh",
                    0o100755,
                    "Bourne-Again shell script, ASCII text executable",
                    b"#!/usr/bin/env bash\n",
                )],
            );
            pkg.name = name.to_string();
            let lines = script_finding_lines(&pkg, &config);
            assert!(
                flagged(
                    &lines,
                    "env-script-interpreter",
                    "/usr/share/tools/data/tool.sh"
                ),
                "env-script-interpreter must fire for non-carrier name {name}: {lines:?}"
            );
        }
        let dir3 = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir3,
            &[(
                "/usr/share/resource/data/tool.py",
                0o100755,
                "Python script, ASCII text executable",
                b"#!/usr/bin/env python3\n",
            )],
        );
        pkg.name = "resource-compiler".to_string();
        let lines = script_finding_lines(&pkg, &config);
        assert!(
            flagged(
                &lines,
                "env-script-interpreter",
                "/usr/share/resource/data/tool.py"
            ),
            "env-script-interpreter must fire for a fused name: {lines:?}"
        );
    }

    /// The gate family reaches `wrong-script-interpreter` the
    /// same way: the bazel wheel fixtures are
    /// test payload inside a -source package's tests tree, a
    /// testsuite package's own scripts are its payload wherever
    /// they sit, a source package's helper scripts are vendored
    /// source, and the Go source tree is source payload -- a
    /// wrong interpreter line in any of them is the harness's or
    /// upstream's business, not an installed entry point's defect.
    #[test]
    fn wrong_script_silent_in_test_and_source_payload() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/src/bazel-rules-python/tests/repos/whl_with_data1/whl_with_data1-1.0.data/scripts/whl_with_data1_pythonw",
                    0o100755,
                    "Python script, ASCII text executable",
                    b"#!pythonw\n",
                ),
                (
                    "/usr/src/bazel-rules-python/tests/repos/whl_with_data1/whl_with_data1-1.0.data/scripts/whl_with_data1_script",
                    0o100755,
                    "Python script, ASCII text executable",
                    b"#!python\n",
                ),
            ],
        );
        pkg.name = "bazel-rules-python-source".to_string();
        let lines = script_finding_lines(&pkg, &config);
        for path in [
            "/usr/src/bazel-rules-python/tests/repos/whl_with_data1/whl_with_data1-1.0.data/scripts/whl_with_data1_pythonw",
            "/usr/src/bazel-rules-python/tests/repos/whl_with_data1/whl_with_data1-1.0.data/scripts/whl_with_data1_script",
        ] {
            assert!(
                !flagged(&lines, "wrong-script-interpreter", path),
                "no wrong-script-interpreter for bazel fixture {path}: {lines:?}"
            );
        }
        let dir2 = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir2,
            &[(
                "/usr/share/lvm2-testsuite/shell/check.pl",
                0o100755,
                "Perl script text executable",
                b"#!perl\n",
            )],
        );
        pkg.name = "lvm2-testsuite".to_string();
        let lines = script_finding_lines(&pkg, &config);
        assert!(
            !flagged(
                &lines,
                "wrong-script-interpreter",
                "/usr/share/lvm2-testsuite/shell/check.pl"
            ),
            "no wrong-script-interpreter for testsuite payload: {lines:?}"
        );
        let dir3 = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir3,
            &[(
                "/usr/src/kafka/kafka-merge-pr.py",
                0o100755,
                "Python script, ASCII text executable",
                b"#!/usr/local/bin/python3\n",
            )],
        );
        pkg.name = "kafka-source".to_string();
        let lines = script_finding_lines(&pkg, &config);
        assert!(
            !flagged(
                &lines,
                "wrong-script-interpreter",
                "/usr/src/kafka/kafka-merge-pr.py"
            ),
            "no wrong-script-interpreter for source payload: {lines:?}"
        );
        let dir4 = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir4,
            &[(
                "/usr/share/go/1.24/src/cmd/tool.py",
                0o100755,
                "Python script, ASCII text executable",
                b"#!python3\n",
            )],
        );
        pkg.name = "go1.24".to_string();
        let lines = script_finding_lines(&pkg, &config);
        assert!(
            !flagged(
                &lines,
                "wrong-script-interpreter",
                "/usr/share/go/1.24/src/cmd/tool.py"
            ),
            "no wrong-script-interpreter for Go source payload: {lines:?}"
        );
    }

    /// The bounds of the family bind this emission identically:
    /// doc and example payload is not a gate shape (the audit's
    /// perl and texlive examples keep firing); an entry point in
    /// a script directory keeps firing whatever the package is
    /// called; a %doc row in a source package keeps firing;
    /// fused names carry no fact; a plain package's /usr/src
    /// payload is not covered; and a private /opt/testing tree
    /// is not a gate shape either (rpmlint-mini's own script
    /// keeps the finding).
    #[test]
    fn wrong_script_still_fires_at_gate_bounds() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/share/doc/packages/perl-Dumbbench/examples/timethese.pl",
                    0o100755,
                    "Perl script text executable",
                    b"#!perl\n",
                ),
                (
                    "/usr/share/texmf/doc/metapost/metapost-examples/mp2html.pl",
                    0o100755,
                    "Perl script text executable",
                    b"#!perl -w\n",
                ),
            ],
        );
        let lines = script_finding_lines(&pkg, &config);
        for path in [
            "/usr/share/doc/packages/perl-Dumbbench/examples/timethese.pl",
            "/usr/share/texmf/doc/metapost/metapost-examples/mp2html.pl",
        ] {
            assert!(
                flagged(&lines, "wrong-script-interpreter", path),
                "wrong-script-interpreter must fire for doc payload {path}: {lines:?}"
            );
        }
        let dir2 = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir2,
            &[
                (
                    "/usr/bin/runner.pl",
                    0o100755,
                    "Perl script text executable",
                    b"#!perl\n",
                ),
                (
                    "/usr/src/kafka/docs/tool.py",
                    0o100755,
                    "Python script, ASCII text executable",
                    b"#!/usr/local/bin/python3\n",
                ),
            ],
        );
        pkg.name = "lvm2-testsuite".to_string();
        let lines = script_finding_lines(&pkg, &config);
        assert!(
            flagged(&lines, "wrong-script-interpreter", "/usr/bin/runner.pl"),
            "wrong-script-interpreter must fire in a script directory: {lines:?}"
        );
        pkg.name = "kafka-source".to_string();
        pkg.doc_files = vec!["/usr/src/kafka/docs/tool.py".to_string()];
        let lines = script_finding_lines(&pkg, &config);
        assert!(
            flagged(
                &lines,
                "wrong-script-interpreter",
                "/usr/src/kafka/docs/tool.py"
            ),
            "wrong-script-interpreter must fire for a %doc row: {lines:?}"
        );
        let dir3 = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg = script_mode_pkg(
            &dir3,
            &[
                (
                    "/usr/share/resource/data/tool.py",
                    0o100755,
                    "Python script, ASCII text executable",
                    b"#!python3\n",
                ),
                (
                    "/usr/src/myapp/tool.py",
                    0o100755,
                    "Python script, ASCII text executable",
                    b"#!python3\n",
                ),
                (
                    "/opt/testing/bin/rpmlint.real",
                    0o100755,
                    "Python script, ASCII text executable",
                    b"#!/opt/testing/bin/python3\n",
                ),
            ],
        );
        pkg.name = "resource-compiler".to_string();
        let lines = script_finding_lines(&pkg, &config);
        assert!(
            flagged(
                &lines,
                "wrong-script-interpreter",
                "/usr/share/resource/data/tool.py"
            ),
            "wrong-script-interpreter must fire for a fused name: {lines:?}"
        );
        pkg.name = "myapp".to_string();
        let lines = script_finding_lines(&pkg, &config);
        assert!(
            flagged(&lines, "wrong-script-interpreter", "/usr/src/myapp/tool.py"),
            "wrong-script-interpreter must fire for a plain package's /usr/src payload: {lines:?}"
        );
        pkg.name = "rpmlint-mini".to_string();
        let lines = script_finding_lines(&pkg, &config);
        assert!(
            flagged(
                &lines,
                "wrong-script-interpreter",
                "/opt/testing/bin/rpmlint.real"
            ),
            "wrong-script-interpreter must fire for the /opt/testing tree: {lines:?}"
        );
    }

    fn eol_flagged(lines: &[(String, String)], path: &str) -> bool {
        lines
            .iter()
            .any(|(n, line)| n == "wrong-script-end-of-line-encoding" && line.contains(path))
    }

    /// Scripts with CRLF keep drawing `wrong-script-end-of-line-encoding`
    /// (issue #849): a file with a kernel interpreter line, a file with
    /// a Unix shell-script extension (shell scripts are routinely
    /// sourced and carry no interpreter line), and an executable file
    /// in a script location. An interpreter line also wins over a
    /// `.bat` name: that file is executed by its interpreter, not by
    /// cmd.exe.
    #[test]
    fn script_eol_still_fires_for_scripts() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/bin/file-rename",
                    0o100555,
                    "Perl script text executable",
                    b"#!/usr/bin/perl\r\nuse strict;\r\n",
                ),
                (
                    "/usr/share/myapp/helper.py",
                    0o100644,
                    "Python script, ASCII text executable",
                    b"#!/usr/bin/env python3\r\nprint(1)\r\n",
                ),
                (
                    "/usr/share/vtcl/demo.tcl",
                    0o100755,
                    "ASCII text executable",
                    b"#!/bin/sh\r\n# restarts using wish\r\n",
                ),
                (
                    "/usr/share/myapp/run.sh",
                    0o100755,
                    "Bourne-Again shell script, ASCII text executable",
                    b"echo hi\r\n",
                ),
                (
                    "/usr/share/myapp/env.zsh",
                    0o100755,
                    "ASCII text",
                    b"export X=1\r\n",
                ),
                (
                    "/usr/share/bsh2/tests/testnullinvocation.bsh",
                    0o100755,
                    "ASCII text",
                    b"\r\n#!/usr/bin/bsh2\r\nsource(\"x\");\r\n",
                ),
                (
                    "/usr/bin/plain-tool",
                    0o100755,
                    "ASCII text",
                    b"echo hi\r\n",
                ),
                (
                    "/usr/share/myapp/SETUP.BAT",
                    0o100755,
                    "ASCII text executable",
                    b"#!/bin/sh\r\necho hi\r\n",
                ),
            ],
        );
        let lines = script_finding_lines(&pkg, &config);
        for path in [
            "/usr/bin/file-rename",
            "/usr/share/myapp/helper.py",
            "/usr/share/vtcl/demo.tcl",
            "/usr/share/myapp/run.sh",
            "/usr/share/myapp/env.zsh",
            "/usr/share/bsh2/tests/testnullinvocation.bsh",
            "/usr/bin/plain-tool",
            "/usr/share/myapp/SETUP.BAT",
        ] {
            assert!(
                eol_flagged(&lines, path),
                "wrong-script-end-of-line-encoding must fire for {path}: {lines:?}"
            );
        }
    }

    /// Files that are not scripts stay silent on
    /// `wrong-script-end-of-line-encoding` (issue #849), however they
    /// entered the script branch of the reference-shaped check — in
    /// the Factory corpus every one of these shapes is installed
    /// executable, which alone used to draw the error. Windows batch
    /// files stay silent because CRLF is their correct encoding.
    #[test]
    fn script_eol_silent_for_non_scripts_and_batch_files() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = script_mode_pkg(
            &dir,
            &[
                (
                    "/usr/lib/python3.13/site-packages/pkg/CHANGELOG.md",
                    0o100755,
                    "ASCII text",
                    b"# Changes\r\n",
                ),
                (
                    "/usr/lib/python3.13/site-packages/pkg/playbook.yml",
                    0o100755,
                    "ASCII text",
                    b"---\r\n- hosts: all\r\n",
                ),
                (
                    "/usr/lib/python3.13/site-packages/pkg/module.py",
                    0o100755,
                    "Python script, ASCII text",
                    b"import os\r\n",
                ),
                (
                    "/usr/share/licenses/pkg/LICENSE",
                    0o100755,
                    "ASCII text",
                    b"License\r\n",
                ),
                (
                    "/usr/lib64/crates/vendor/src/lib.rs",
                    0o100644,
                    "ASCII text",
                    b"#![no_std]\r\n//! crate docs\r\n",
                ),
                (
                    "/usr/share/myapp/data.txt",
                    0o100755,
                    "ASCII text",
                    b"hello\r\n",
                ),
                (
                    "/usr/share/myapp/install.ps1",
                    0o100755,
                    "ASCII text",
                    b"Write-Host hi\r\n",
                ),
                (
                    "/usr/share/tetra/gradle-5.1/bin/gradle.bat",
                    0o100755,
                    "DOS batch file, ASCII text",
                    b"@if \"%DEBUG%\" == \"\" @echo off\r\n",
                ),
                (
                    "/usr/lib64/node_modules/corepack/shims/npm.cmd",
                    0o100755,
                    "DOS batch file, ASCII text",
                    b"@SETLOCAL\r\n@IF EXIST node.exe (\r\n",
                ),
                (
                    "/usr/share/myapp/RUN.BAT",
                    0o100755,
                    "DOS batch file, ASCII text",
                    b"@echo off\r\n",
                ),
                (
                    "/usr/bin/helper.bat",
                    0o100755,
                    "DOS batch file, ASCII text",
                    b"@echo off\r\n",
                ),
                (
                    "/usr/bin/helper.cmd",
                    0o100755,
                    "DOS batch file, ASCII text",
                    b"@echo off\r\n",
                ),
            ],
        );
        let lines = script_finding_lines(&pkg, &config);
        let flagged: Vec<&str> = lines
            .iter()
            .filter(|(n, _)| n == "wrong-script-end-of-line-encoding")
            .map(|(_, line)| line.as_str())
            .collect();
        assert_eq!(
            flagged,
            Vec::<&str>::new(),
            "no wrong-script-end-of-line-encoding for non-scripts or batch files: {lines:?}"
        );
    }

    fn doc_eol_flagged(pkg: &Pkg, config: &Config) -> Vec<String> {
        let lines = script_finding_lines(pkg, config);
        lines
            .iter()
            .filter(|(n, _)| n == "wrong-file-end-of-line-encoding")
            .map(|(_, line)| line.clone())
            .collect()
    }

    /// Doc files whose line endings are CRLF or CR-only keep
    /// drawing `wrong-file-end-of-line-encoding`: a uniform CRLF
    /// file, a file whose lines end with a bare carriage return,
    /// and an LF file carrying even a single CRLF-terminated line
    /// all have a wrong end-of-line encoding. A native-format name
    /// that is not the file's final suffix (.ics.txt, .bat.txt)
    /// and an .http file that does not open with an HTTP status
    /// line earn no credit. A file under a native-format suffix
    /// whose endings are CR-only fires too -- the native credit
    /// covers the CRLF shape only -- and an .http opener whose
    /// `HTTP/` is not followed by a version digit is not a status
    /// line and earns no credit.
    #[test]
    fn doc_eol_still_fires_for_wrong_encodings() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let files: [(&str, u32, &str, &[u8]); 10] = [
            (
                "/usr/share/doc/packages/demo/README.txt",
                0o100644,
                "ASCII text",
                b"line one\r\nline two\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/MANUAL.txt",
                0o100644,
                "ASCII text",
                b"line one\rline two\r",
            ),
            (
                "/usr/share/doc/packages/demo/demo.cpp",
                0o100644,
                "ASCII text",
                b"int a;\n#include <x>\r\nint b;\n",
            ),
            (
                "/usr/share/doc/packages/demo/notes.http",
                0o100644,
                "ASCII text",
                b"Notes about the protocol\r\nsecond line\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/data.ics.txt",
                0o100644,
                "ASCII text",
                b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/run.bat.txt",
                0o100644,
                "ASCII text",
                b"@echo off\r\necho hi\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/legacy.bat",
                0o100644,
                "ASCII text",
                b"@echo off\recho hi\r",
            ),
            (
                "/usr/share/doc/packages/demo/oldcal.ics",
                0o100644,
                "ASCII text",
                b"BEGIN:VCALENDAR\rEND:VCALENDAR\r",
            ),
            (
                "/usr/share/doc/packages/demo/badversion.http",
                0o100644,
                "ASCII text",
                b"HTTP/x 400 Bad request\r\n\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/noversion.http",
                0o100644,
                "ASCII text",
                b"HTTP/ 400 Bad request\r\n\r\n",
            ),
        ];
        let mut pkg = script_mode_pkg(&dir, &files);
        pkg.doc_files = files.iter().map(|(n, _, _, _)| n.to_string()).collect();
        let flagged = doc_eol_flagged(&pkg, &config);
        assert_eq!(flagged.len(), files.len(), "all fire: {flagged:?}");
        for (name, _, _, _) in &files {
            assert!(
                flagged.iter().any(|l| l.contains(name)),
                "expected wrong-file-end-of-line-encoding for {name}: {flagged:?}"
            );
        }
    }

    /// Doc files stay silent on `wrong-file-end-of-line-encoding`
    /// when the carriage returns are not line endings (an LF-ended
    /// test log whose recorded output carries progress carriage
    /// returns; a single stray carriage return in an LF file) and
    /// when CRLF is the file format's own encoding: Windows batch
    /// files and PowerShell scripts, iCalendar and mail message
    /// files, and an HTTP response message shipped as a file.
    #[test]
    fn doc_eol_silent_for_content_cr_and_crlf_native_formats() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let files: [(&str, u32, &str, &[u8]); 8] = [
            (
                "/usr/share/doc/packages/demo/results.txt",
                0o100644,
                "ASCII text",
                b"TEST 1/10 [x]\rPASS\nTEST 2/10 [y]\rPASS\n",
            ),
            (
                "/usr/share/doc/packages/demo/changelog.txt",
                0o100644,
                "ASCII text",
                b"2003-02-07\r A Name\n\n  o entry\n",
            ),
            (
                "/usr/share/doc/packages/demo/install.bat",
                0o100644,
                "ASCII text",
                b"@echo off\r\necho hi\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/SETUP.CMD",
                0o100644,
                "ASCII text",
                b"@echo off\r\necho hi\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/deploy.ps1",
                0o100644,
                "ASCII text",
                b"Write-Host hi\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/calendar.ics",
                0o100644,
                "ASCII text",
                b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/letter.eml",
                0o100644,
                "ASCII text",
                b"From: a@b.c\r\nSubject: hi\r\n\r\nbody\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/error.http",
                0o100644,
                "ASCII text",
                b"HTTP/1.0 400 Bad request\r\nConnection: close\r\n\r\n<html>\n</html>\n",
            ),
        ];
        let mut pkg = script_mode_pkg(&dir, &files);
        pkg.doc_files = files.iter().map(|(n, _, _, _)| n.to_string()).collect();
        let flagged = doc_eol_flagged(&pkg, &config);
        assert_eq!(
            flagged,
            Vec::<String>::new(),
            "no wrong-file-end-of-line-encoding for content CRs or CRLF-native formats: {flagged:?}"
        );
    }

    /// Doc files in MSBuild and Visual Studio project formats
    /// stay silent on `wrong-file-end-of-line-encoding`: the
    /// toolchain writes .proj, .props, .vcxproj and .sln files
    /// with CRLF line endings, so the encoding is the formats'
    /// own. Matching is by final extension, case-insensitive.
    #[test]
    fn doc_eol_silent_for_msbuild_project_files() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let files: [(&str, u32, &str, &[u8]); 5] = [
            (
                "/usr/share/doc/packages/demo/build.proj",
                0o100644,
                "ASCII text",
                b"<Project>\r\n</Project>\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/Directory.Build.props",
                0o100644,
                "ASCII text",
                b"<Project>\r\n</Project>\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/app.vcxproj",
                0o100644,
                "ASCII text",
                b"<Project>\r\n</Project>\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/APP.VCXPROJ",
                0o100644,
                "ASCII text",
                b"<Project>\r\n</Project>\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/solution.sln",
                0o100644,
                "ASCII text",
                b"Microsoft Visual Studio Solution File\r\n\r\n",
            ),
        ];
        let mut pkg = script_mode_pkg(&dir, &files);
        pkg.doc_files = files.iter().map(|(n, _, _, _)| n.to_string()).collect();
        let flagged = doc_eol_flagged(&pkg, &config);
        assert_eq!(
            flagged,
            Vec::<String>::new(),
            "no wrong-file-end-of-line-encoding for MSBuild project files: {flagged:?}"
        );
    }

    /// A name that merely resembles an MSBuild extension earns no
    /// credit: the match is on the final extension, so a project
    /// notes file (.proj.txt), a longer extension sharing the
    /// letters (.project) and a suffixed name (.sln.bak) all keep
    /// firing.
    #[test]
    fn doc_eol_still_fires_for_lookalike_extensions() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let files: [(&str, u32, &str, &[u8]); 3] = [
            (
                "/usr/share/doc/packages/demo/notes.proj.txt",
                0o100644,
                "ASCII text",
                b"project notes\r\nsecond line\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/plan.project",
                0o100644,
                "ASCII text",
                b"the plan\r\nsecond line\r\n",
            ),
            (
                "/usr/share/doc/packages/demo/solution.sln.bak",
                0o100644,
                "ASCII text",
                b"backup copy\r\nsecond line\r\n",
            ),
        ];
        let mut pkg = script_mode_pkg(&dir, &files);
        pkg.doc_files = files.iter().map(|(n, _, _, _)| n.to_string()).collect();
        let flagged = doc_eol_flagged(&pkg, &config);
        assert_eq!(flagged.len(), files.len(), "all fire: {flagged:?}");
        for (name, _, _, _) in &files {
            assert!(
                flagged.iter().any(|l| l.contains(name)),
                "expected wrong-file-end-of-line-encoding for {name}: {flagged:?}"
            );
        }
    }

    /// Logs shipped by a compiler test-results package stay
    /// silent on `wrong-file-end-of-line-encoding`: the files are
    /// byte records of the compiler's own test runs, whose
    /// generators emit CRLF (the uniform ACATS reports; DejaGnu
    /// logs whose tested programs emitted CRLF). The credit needs
    /// both halves of the shape — the gcc<version>-testresults
    /// package name and a .log file name.
    #[test]
    fn doc_eol_silent_for_compiler_test_logs() {
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let files: [(&str, u32, &str, &[u8]); 2] = [
            (
                "/usr/share/doc/packages/gcc16-testresults/a22006b.log",
                0o100644,
                "ASCII text",
                b"\r\n,.,. A22006B ACATS 4.2A\r\n",
            ),
            (
                "/usr/share/doc/packages/gcc16-testresults/gcc.log",
                0o100644,
                "ASCII text",
                b"Running target unix\noutput\r\nmore\n",
            ),
        ];
        let mut pkg = script_mode_pkg(&dir, &files);
        pkg.name = "gcc16-testresults".to_string();
        pkg.doc_files = files.iter().map(|(n, _, _, _)| n.to_string()).collect();
        let flagged = doc_eol_flagged(&pkg, &config);
        assert_eq!(
            flagged,
            Vec::<String>::new(),
            "no wrong-file-end-of-line-encoding for compiler test logs: {flagged:?}"
        );
    }

    /// The test-log credit is narrow: a CRLF log in an ordinary
    /// package, a CRLF log in another test-results family, a CRLF
    /// text file inside a compiler test-results package, a log in
    /// the compiler package without the -testresults suffix, and
    /// a CRLF log in a package whose name carries no digit run
    /// (gcc-testresults itself) or a non-digit version
    /// (gccAB-testresults) all keep firing -- the credited shape
    /// needs gcc plus a non-empty ASCII-digit run.
    #[test]
    fn doc_eol_still_fires_outside_the_test_log_shape() {
        let config = test_config();
        let cases: [(&str, &str); 6] = [
            ("demo", "/usr/share/doc/packages/demo/results.log"),
            (
                "gdb-testresults",
                "/usr/share/doc/packages/gdb-testresults/session.log",
            ),
            (
                "gcc16-testresults",
                "/usr/share/doc/packages/gcc16-testresults/README.txt",
            ),
            ("gcc16", "/usr/share/doc/packages/gcc16/build.log"),
            (
                "gcc-testresults",
                "/usr/share/doc/packages/gcc-testresults/session.log",
            ),
            (
                "gccAB-testresults",
                "/usr/share/doc/packages/gccAB-testresults/session.log",
            ),
        ];
        for (pkg_name, fname) in cases {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let files: [(&str, u32, &str, &[u8]); 1] = [(
                fname,
                0o100644,
                "ASCII text",
                b"recorded output\r\nsecond line\r\n",
            )];
            let mut pkg = script_mode_pkg(&dir, &files);
            pkg.name = pkg_name.to_string();
            pkg.doc_files = vec![fname.to_string()];
            let flagged = doc_eol_flagged(&pkg, &config);
            assert_eq!(
                flagged.len(),
                1,
                "expected wrong-file-end-of-line-encoding for {fname} in {pkg_name}: {flagged:?}"
            );
        }
    }

    // ---- license coverage (issue #1033) ----

    const TEST_LICENSES: &[&str] = &[
        "0BSD",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "CC0-1.0",
        "GFDL-1.3-only",
        "GPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "LGPL-2.1",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MIT",
        "MIT-0",
        "MPL-2.0",
        "PSF-2.0",
        "WTFPL",
    ];

    fn test_valid_license_keys() -> HashSet<String> {
        TEST_LICENSES
            .iter()
            .map(|s| canonical_license_id(s).key)
            .collect()
    }

    fn license_displays(text: &str, tag: &str) -> Vec<(LicenseUnitKind, String)> {
        license_units_in_window(text, &parse_license_tag(tag), &test_valid_license_keys())
            .into_iter()
            .map(|(kind, display, _)| (kind, display))
            .collect()
    }

    #[test]
    fn license_id_canonical_forms() {
        assert_eq!(canonical_license_id("GPL-2.0+").key, "gpl-2.0-or-later");
        assert_eq!(canonical_license_id("GPL-2.0-only+").key, "gpl-2.0-only");
        assert_eq!(
            canonical_license_id("GPL-2.0-with-classpath-exception").key,
            "gpl-2.0"
        );
        assert_eq!(canonical_license_id(" gpl-2.0-ONLY ").key, "gpl-2.0-only");
        assert_eq!(canonical_license_id("MIT").key, "mit");
        let id = canonical_license_id("LGPL-2.1-or-later");
        assert_eq!(id.family, "lgpl");
        assert_eq!(id.version, Some(vec![2, 1]));
        // A name-shaped tail is not a version: the whole stem is the family.
        let id = canonical_license_id("BSD-2-Clause");
        assert_eq!(id.family, "bsd-2-clause");
        assert_eq!(id.version, None);
    }

    #[test]
    fn scriptlet_tail_credit_requires_braced_opener_1175() {
        // The braced tail credit hangs off a `${` expansion: a bare
        // closing brace in the scriptlet text credits nothing
        // (issue #1175).
        assert!(scriptlet_appends_tail("echo x > ${dir}/ls-R", "ls-R"));
        assert!(scriptlet_appends_tail("echo x > ${dir:-/def}/ls-R", "ls-R"));
        assert!(scriptlet_appends_tail("echo x > $dir/ls-R", "ls-R"));
        assert!(!scriptlet_appends_tail("echo x > }/ls-R", "ls-R"));
        assert!(!scriptlet_appends_tail("echo x > ${dir}/other", "ls-R"));
    }

    #[test]
    fn license_coverage_tag_range_and_versionless() {
        let covered = |declared: &str, tag: &str| {
            license_id_covered(&canonical_license_id(declared), &parse_license_tag(tag))
        };
        // The tag's own or-later range covers a declaration at or
        // above its floor version (issue #1159).
        assert!(covered("GPL-3.0-only", "GPL-2.0-or-later"));
        assert!(!covered("GPL-1.0-only", "GPL-2.0-or-later"));
        // Both sides or-later: the ranges overlap whichever floor
        // is lower (issue #1175).
        assert!(covered("GPL-3.0-or-later", "GPL-2.0-or-later"));
        assert!(covered("GPL-2.0-or-later", "GPL-3.0-or-later"));
        // A version-less plus form and the bare tag name the same
        // license, in both directions.
        assert!(covered("MIT+", "MIT"));
        assert!(covered("MIT", "MIT+"));
        // A versioned declaration under a version-less tag entry
        // stays uncovered: no version relation is decidable.
        assert!(!covered("GPL-2.0-only", "GPL"));
    }

    #[test]
    fn license_coverage_grant_version_three_components() {
        // `either version 2.0.1` names a three-component version:
        // no grant is read, where scanning `2.0` and letting the
        // tail table eat `.1` would fabricate a GPL-2.0-only grant
        // (issue #1159).
        let text = "This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2.0.1 of the License.\n";
        assert!(license_displays(text, "MIT").is_empty());
    }

    #[test]
    fn license_coverage_malformed_spdx_marker_suppresses_grants() {
        // The marker is present but its expression does not parse:
        // the file declares a license, so grant detection -- scoped
        // to files without a declaration -- stays out (issue #1159).
        let text = "// SPDX-License-Identifier: Foo Bar Baz\n//\n// This program is free software; you can redistribute it and/or\n// modify it under the terms of the GNU General Public License\n// as published by the Free Software Foundation; either version 2\n// of the License, or (at your option) any later version.\n";
        assert!(license_displays(text, "MIT").is_empty());
    }

    #[test]
    fn license_coverage_window_skip_any_case() {
        // The whole-window skip reads case-insensitively (issue
        // #1159): capitalised exception and Alternatively headers
        // skip the window just like the lowercase forms.
        let exception = "This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version. As a Special Exception, the copyright holders give you permission to link this program with the OpenSSL library.\n";
        assert!(license_displays(exception, "MIT").is_empty());
        let alternatively = "ALTERNATIVELY, this file may be used under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.\n";
        assert!(license_displays(alternatively, "MIT").is_empty());
    }

    #[test]
    fn license_coverage_rem_leader_any_case() {
        // Batch comment leaders strip in any case, so a grant whose
        // sentence wraps across `rem` leaders still reads whole
        // (issue #1159).
        let text = "rem This program is free software; you can redistribute it and/or\nrem modify it under the terms of the GNU\nrem General Public License as published by the Free Software Foundation; either version 2\nrem of the License, or (at your option) any later version.\n";
        assert_eq!(
            license_displays(text, "MIT"),
            [(LicenseUnitKind::Grant, "GPL-2.0-or-later".to_string())]
        );
    }

    #[test]
    fn license_or_group_key_ignores_arm_order() {
        // The same OR group in another arm order aggregates under
        // one key; the display keeps the declaration order (issue
        // #1159).
        let tag = parse_license_tag("BSD-3-Clause");
        let keys = test_valid_license_keys();
        let a = parse_license_expr("MIT OR Apache-2.0").expect("expr");
        let b = parse_license_expr("Apache-2.0 OR MIT").expect("expr");
        let ua = unsatisfied_spdx_units(&a, &tag, &keys);
        let ub = unsatisfied_spdx_units(&b, &tag, &keys);
        assert_eq!(ua.len(), 1, "{ua:?}");
        assert_eq!(ub.len(), 1, "{ub:?}");
        assert_eq!(ua[0].1, ub[0].1);
        assert_ne!(ua[0].0, ub[0].0);
    }

    #[test]
    fn valid_license_keys_collect_expression_leaves() {
        // An expression-form entry contributes its leaf keys, not
        // one canonicalisation of the whole string (issue #1159).
        let keys = valid_license_keys(&[
            "GPL-2.0-only OR GPL-3.0-only".to_string(),
            "MIT".to_string(),
        ]);
        assert!(keys.contains("gpl-2.0-only"), "{keys:?}");
        assert!(keys.contains("gpl-3.0-only"), "{keys:?}");
        assert!(keys.contains("mit"), "{keys:?}");
        assert_eq!(keys.len(), 3, "{keys:?}");
    }

    #[test]
    fn license_coverage_spdx_fires() {
        // python313-asyncpg shape: a PSF-2.0 file under an Apache tag.
        assert_eq!(
            license_displays("# SPDX-License-Identifier: PSF-2.0\n", "Apache-2.0"),
            [(LicenseUnitKind::Spdx, "PSF-2.0".to_string())]
        );
        // tree-sitter shape: a bare GPL-2.0 declaration under an MIT tag.
        assert_eq!(
            license_displays("// SPDX-License-Identifier: GPL-2.0\n", "MIT"),
            [(LicenseUnitKind::Spdx, "GPL-2.0".to_string())]
        );
        // libxdp shape: the whole unsatisfied OR group is one unit.
        assert_eq!(
            license_displays(
                "// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)\n",
                "GPL-2.0-only"
            ),
            [(
                LicenseUnitKind::Spdx,
                "LGPL-2.1 OR BSD-2-Clause".to_string()
            )]
        );
        // libspelling shapes.
        assert_eq!(
            license_displays(
                "/* SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later */\n",
                "LGPL-2.1-or-later"
            ),
            [(
                LicenseUnitKind::Spdx,
                "Apache-2.0 OR GPL-3.0-or-later".to_string()
            )]
        );
        assert_eq!(
            license_displays("// SPDX-License-Identifier: MIT\n", "LGPL-2.1-or-later"),
            [(LicenseUnitKind::Spdx, "MIT".to_string())]
        );
        // An AND declaration reports only its unsatisfied conjunct.
        assert_eq!(
            license_displays("// SPDX-License-Identifier: MIT AND GPL-2.0-only\n", "MIT"),
            [(LicenseUnitKind::Spdx, "GPL-2.0-only".to_string())]
        );
        // An -only declaration is not covered by a later -only.
        assert_eq!(
            license_displays("// SPDX-License-Identifier: GPL-2.0-only\n", "GPL-3.0-only"),
            [(LicenseUnitKind::Spdx, "GPL-2.0-only".to_string())]
        );
    }

    #[test]
    fn license_coverage_spdx_quiet() {
        // One satisfied arm satisfies the whole OR group.
        assert!(
            license_displays(
                "// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)\n",
                "GPL-2.0-only"
            )
            .is_empty()
        );
        // `GPL-2.0+ WITH Linux-syscall-note` under GPL-2.0-only: the
        // +-form is an -or-later declaration met by the same version,
        // and the exception is ignored.
        assert!(
            license_displays(
                "// SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note\n",
                "GPL-2.0-only"
            )
            .is_empty()
        );
        // An unlisted arm (a LicenseRef) satisfies the OR group.
        assert!(license_displays(
            "// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL\n",
            "MIT"
        )
        .is_empty());
        // LLVM's banner: the trailing `*|` decoration is stripped and
        // the WITH exception ignored.
        assert!(
            license_displays(
                "// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception *|\n",
                "Apache-2.0"
            )
            .is_empty()
        );
        // An -or-later declaration is met by any later version.
        assert!(
            license_displays(
                "// SPDX-License-Identifier: GPL-2.0-or-later\n",
                "GPL-3.0-only"
            )
            .is_empty()
        );
        // The declared license in the tag, plainly.
        assert!(
            license_displays("// SPDX-License-Identifier: MIT\n", "MIT AND Apache-2.0").is_empty()
        );
    }

    #[test]
    fn license_coverage_grants_fire() {
        // The standard GPL header, C comment form.
        let gpl = "/*\n * This program is free software; you can redistribute it and/or\n * modify it under the terms of the GNU General Public License\n * as published by the Free Software Foundation; either version 2\n * of the License, or (at your option) any later version.\n */\n";
        assert_eq!(
            license_displays(gpl, "MIT"),
            [(LicenseUnitKind::Grant, "GPL-2.0-or-later".to_string())]
        );
        assert!(license_displays(gpl, "GPL-2.0-or-later").is_empty());
        // geolite2legacy shape: LGPL-3.0-or-later grant, MIT tag.
        let geolite = "# This library is free software; you can redistribute it and/or\n# modify it under the terms of the GNU Lesser General Public\n# License as published by the Free Software Foundation; either\n# version 3 of the License, or (at your option) any later version.\n";
        assert_eq!(
            license_displays(geolite, "MIT"),
            [(LicenseUnitKind::Grant, "LGPL-3.0-or-later".to_string())]
        );
        // An LGPL notice under a GPL tag fires (its own class): the
        // -only tail is a bare period after `of the License`.
        let lgpl_only = "This library is free software; you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation; either version 2.1 of the License.\n";
        assert_eq!(
            license_displays(lgpl_only, "GPL-2.1-only"),
            [(LicenseUnitKind::Grant, "LGPL-2.1-only".to_string())]
        );
        assert!(license_displays(lgpl_only, "LGPL-2.1-only").is_empty());
        // Form B: `version N` right after the license name gives -only.
        let form_b = "This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License version 2 as published by the Free Software Foundation.\n";
        assert_eq!(
            license_displays(form_b, "GPL-3.0-only"),
            [(LicenseUnitKind::Grant, "GPL-2.0-only".to_string())]
        );
        assert!(license_displays(form_b, "GPL-2.0-or-later").is_empty());
        // The Apache grant string.
        let apache = "Licensed under the Apache License, Version 2.0 (the \"License\");\nyou may not use this file except in compliance with the License.\n";
        assert_eq!(
            license_displays(apache, "MIT"),
            [(LicenseUnitKind::Grant, "Apache-2.0".to_string())]
        );
        // The Mozilla grant string.
        let mpl = "/* This Source Code Form is subject to the terms of the Mozilla Public\n * License, v. 2.0. If a copy of the MPL was not distributed with this\n * file, You can obtain one at http://mozilla.org/MPL/2.0/. */\n";
        assert_eq!(
            license_displays(mpl, "MIT"),
            [(LicenseUnitKind::Grant, "MPL-2.0".to_string())]
        );
        // vapoursynth shape: the WTFPL grant behind `*` comment leaders.
        let wtfpl = "/*\n * Do What The Fuck You Want To Public License, Version 2\n */\n";
        assert_eq!(
            license_displays(wtfpl, "LGPL-2.1-or-later"),
            [(LicenseUnitKind::Grant, "WTFPL".to_string())]
        );
    }

    #[test]
    fn license_coverage_grants_quiet() {
        // kernel sign-file.c shape: the British `of the Licence` tail
        // is unknown -- it is not read as either grant form.
        let sign_file = "/*\n * This program is free software; you can redistribute it and/or\n * modify it under the terms of the GNU General Public License\n * as published by the Free Software Foundation; either version 2\n * of the Licence, or (at your option) any later version.\n */\n";
        assert!(license_displays(sign_file, "MIT").is_empty());
        // libyui shape: `or (at your option) version 3.0` is not the
        // exact -or-later tail.
        let libyui = "This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) version 3.0 of the License.\n";
        assert!(license_displays(libyui, "MIT").is_empty());
        // A missing parenthesis makes the tail unknown, never -only.
        let sloppy = "This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or at your option any later version.\n";
        assert!(license_displays(sloppy, "MIT").is_empty());
        // A case variant of the prefix is unknown.
        let capitalised = "This program is free software; you can redistribute it and/or modify it under the Terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.\n";
        assert!(license_displays(capitalised, "MIT").is_empty());
        // Windows naming a special exception are skipped whole.
        let exception = "This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version. As a special exception, the copyright holders give you permission to link this program with the OpenSSL library.\n";
        assert!(license_displays(exception, "MIT").is_empty());
        // An Alternatively dual grant is skipped whole.
        let alternatively = "Alternatively, this file may be used under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.\n";
        assert!(license_displays(alternatively, "MIT").is_empty());
    }

    #[test]
    fn license_coverage_spdx_wins_over_grant() {
        // A file with an SPDX declaration is not also read for grants:
        // under an MIT tag the GPL grant text stays silent, and under a
        // GPL tag only the SPDX unit reports.
        let text = "// SPDX-License-Identifier: MIT\n//\n// This program is free software; you can redistribute it and/or\n// modify it under the terms of the GNU General Public License\n// as published by the Free Software Foundation; either version 2\n// of the License, or (at your option) any later version.\n";
        assert!(license_displays(text, "MIT").is_empty());
        assert_eq!(
            license_displays(text, "GPL-2.0-or-later"),
            [(LicenseUnitKind::Spdx, "MIT".to_string())]
        );
    }

    #[test]
    fn license_coverage_aggregates_per_package() {
        let config = license_test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm = fixture_path("fsf-address-fixture-1.0-1.noarch.rpm");
        let pkg = Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = FilesCheck::new(&config);
        let mut st = PkgState {
            license_tag_ids: parse_license_tag("MIT"),
            ..Default::default()
        };
        let grant_file = PkgFile {
            mode: 0o100644,
            ..Default::default()
        };
        for (fname, content) in [
            (
                "/usr/share/demo/a.py",
                "# SPDX-License-Identifier: GPL-2.0\n",
            ),
            (
                "/usr/share/demo/b.py",
                "# SPDX-License-Identifier: GPL-2.0\n",
            ),
            ("/usr/share/demo/c.py", "# SPDX-License-Identifier: MIT\n"),
        ] {
            let fd = FileData {
                chunk: content.as_bytes().to_vec(),
                istext: true,
                ..Default::default()
            };
            check.check_normal_license_coverage(fname, &grant_file, &mut st, &fd);
        }
        check.check_license_coverage(&pkg, &st, &mut out);
        let lines: Vec<&str> = out
            .results()
            .iter()
            .filter(|(name, _)| name == "spdx-license-not-in-license-tag")
            .map(|(_, line)| line.as_str())
            .collect();
        assert_eq!(lines.len(), 1, "one aggregated finding: {lines:?}");
        assert!(
            lines[0].contains("GPL-2.0 /usr/share/demo/a.py 2"),
            "license, first path and count: {}",
            lines[0]
        );
    }

    #[test]
    fn license_coverage_scopes_out_license_files_and_usr_src() {
        let config = license_test_config();
        let check = FilesCheck::new(&config);
        let mut st = PkgState {
            license_tag_ids: parse_license_tag("MIT"),
            ..Default::default()
        };
        let fd = FileData {
            chunk: b"# SPDX-License-Identifier: GPL-2.0\n".to_vec(),
            istext: true,
            ..Default::default()
        };
        // A %license file is the license text itself: out of scope.
        let license_file = PkgFile {
            mode: 0o100644,
            flags: crate::pkg::pkgfile::RPMFILE_LICENSE,
            ..Default::default()
        };
        check.check_normal_license_coverage(
            "/usr/share/licenses/demo/COPYING",
            &license_file,
            &mut st,
            &fd,
        );
        // /usr/src/ is out of scope.
        let plain_file = PkgFile {
            mode: 0o100644,
            ..Default::default()
        };
        check.check_normal_license_coverage("/usr/src/debug/demo/a.py", &plain_file, &mut st, &fd);
        assert!(st.license_units.is_empty());
    }

    fn license_test_config() -> Config {
        let mut config = test_config();
        config.configuration.insert(
            "ValidLicenses".to_string(),
            toml::Value::Array(
                TEST_LICENSES
                    .iter()
                    .map(|s| toml::Value::String(s.to_string()))
                    .collect(),
            ),
        );
        config
    }
}
