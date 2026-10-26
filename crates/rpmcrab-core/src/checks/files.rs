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
//! every open of such a link fails with ELOOP).

#![allow(clippy::collapsible_if)]

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use fancy_regex::Regex;
use indexmap::IndexMap;

use super::fhs::cross_sysroot_matches;
use super::filelist::sysconfig_good_matches;
use super::is_match;
use super::shared::{devel_regex, is_mingw_package, macro_regex, python_str_repr};
use crate::check::{Check, add_info, make_finding};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::dep::{DepInfo, leaf_account_capability};
use crate::pkg::pkgfile::{self, PkgFile, is_reg};
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

static BUILDCONFIGFILE_REGEX: OnceLock<Regex> = OnceLock::new();
fn buildconfigfile_regex() -> &'static Regex {
    BUILDCONFIGFILE_REGEX
        .get_or_init(|| Regex::new(r"(\.pc|/bin/.+-config)$").expect("static regex"))
}

static BUILDCONFIG_RPATH_REGEX: OnceLock<Regex> = OnceLock::new();
fn buildconfig_rpath_regex() -> &'static Regex {
    BUILDCONFIG_RPATH_REGEX.get_or_init(|| Regex::new(r"(?:-rpath|Wl,-R)\b").expect("static regex"))
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
        Regex::new(r"(?i)(675\s+Mass\s+Ave|59\s+Temple\s+Place|02139|51\s+Franklin\s+St)")
            .expect("static regex")
    })
}

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
///   `.tpl`, `.template`, `.skel` or `.j2` — the installed name is
///   the name an instantiation step rewrites, so the shipped file
///   is the template's content, not an entry point.
fn non_executable_script_is_data(
    fname: &str,
    interpreter: &str,
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
    if is_match(python_lib_tree_re, fname) {
        return true;
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
    // The remaining shapes are bare directory components, whose
    // names also occur on entry points; they count only inside
    // the data and library trees.
    let data_tree = fname.starts_with("/usr/src/")
        || fname.starts_with("/usr/share/")
        || fname.starts_with("/usr/lib/")
        || fname.starts_with("/usr/lib64/")
        || fname.starts_with("/usr/etc/")
        || fname.starts_with("/etc/");
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
/// the interpreter findings. And fused names carry no fact:
/// blktests and xfstests glue the word into a single component,
/// so they and their `common/` fragments stay outside this gate --
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
/// `find_perm_in_tmpfiles`: defaults are `0644`/`root`/`root`, the last
/// matching line wins, and unreadable configs are skipped.
fn find_perm_in_tmpfiles(pkg: &Pkg, fname: &str) -> (String, String, String) {
    let mut perms = "0644".to_string();
    let mut user = "root".to_string();
    let mut group = "root".to_string();
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
            perms = fields[2].to_string();
            user = fields[3].to_string();
            group = fields[4].to_string();
        }
    }

    (perms, user, group)
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
    dangling_candidates: Vec<DanglingCandidate>,
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
            dangling_candidates: Vec::new(),
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
    perl_dep_error: bool,
    python_dep_error: bool,
    /// `no-dependency-on` candidates this package recorded (issue
    /// #862), drained into the check's session state by `check_binary`.
    nodep_candidates: Vec<NodepCandidate>,
    debuginfo_srcs: bool,
    debuginfo_debugs: bool,
    postin: String,
    postun: String,
    preun: String,
    /// Directories named by the `/etc/ld.so.conf.d/*.conf` snippets this
    /// package ships (issue #569): together with the standard libdirs,
    /// the only directories ldconfig scans.
    ldconfig_dirs: std::collections::HashSet<String>,
    bindir_exes: IndexMap<String, Vec<String>>,
    man_basenames: std::collections::HashSet<String>,
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
        st.devel_pkg = is_match(&self.devel_re, &pkg.name);
        if !st.devel_pkg {
            for p in &pkg.provides {
                if is_match(&self.devel_re, &p.name) {
                    st.devel_pkg = true;
                    break;
                }
            }
        }
        st.is_kernel_package = is_match(&self.kernel_package_re, &pkg.name);
        st.debuginfo_package = is_match(&self.debuginfo_package_re, &pkg.name);
        st.debugsource_package = is_match(&self.debugsource_package_re, &pkg.name);
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

        self.session_files
            .extend(pkg.files.iter().map(|f| f.name.clone()));
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
        self.check_manpage_so_refs(pkg, out);
        self.check_debug_files_in_non_debug_package(pkg, &st, out);
        self.check_debuginfo_without_sources(pkg, &st, out);
        self.check_bindir_exes(pkg, &st, out);
        self.check_sysconfig_fillup_usage(pkg, out);
        self.nodep_candidates.append(&mut st.nodep_candidates);
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
    }

    fn reset(&mut self) {
        self.session_files.clear();
        self.dangling_candidates.clear();
        self.owner_candidates.clear();
        self.declared_users.clear();
        self.declared_groups.clear();
        self.nodep_candidates.clear();
        self.pkg_deps.clear();
        self.decompressed_cache.borrow_mut().clear();
    }

    fn export_state(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        if self.session_files.is_empty()
            && self.dangling_candidates.is_empty()
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
            dangling_candidates: std::mem::take(&mut self.dangling_candidates),
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
            self.dangling_candidates.extend(state.dangling_candidates);
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
/// (issue #862) decisions.
struct FilesSessionState {
    session_files: HashSet<String>,
    dangling_candidates: Vec<DanglingCandidate>,
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

/// The first `EnvironmentFile` target in a systemd unit that points into
/// `/etc/sysconfig/`, spelled as written (including the optional-file
/// `-` prefix), or `None`.
fn sysconfig_environment_file(content: &str) -> Option<String> {
    for line in content.lines() {
        let Some(rest) = line.trim_start().strip_prefix("EnvironmentFile") else {
            continue;
        };
        let Some(value) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let token = value
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches('"');
        let target = token.strip_prefix('-').unwrap_or(token).trim_matches('"');
        if target.starts_with("/etc/sysconfig/") {
            return Some(token.to_string());
        }
    }
    None
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
            if !st.man_basenames.contains(exe) {
                add_info(out, Level::Info, pkg, "no-manual-page-for-binary", &[exe]);
            }
        }
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
        self.check_file_manpage(pkg, fname, pkgfile, st, out);
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
        self.check_file_tmpfiles_conf_in_etc(pkg, fname, out);
        self.check_file_subdir_in_bin(pkg, fname, out);
        self.check_file_siteperl_in_perl_module(pkg, fname, out);
        self.check_file_backup_file_in_package(pkg, fname, out);
        self.check_file_version_control_internal_file(pkg, fname, out);
        self.check_file_htaccess_file(pkg, fname, out);
        self.check_file_hidden_file_or_dir(pkg, fname, out);
        self.check_file_manifest_in_perl_module(pkg, fname, out);
        self.check_file_info_dir_file(pkg, fname, out);
        self.check_file_makefile_junk(pkg, fname, out);
        self.check_file_logrotate(pkg, fname, out);
        self.check_file_crontab(pkg, fname, out);
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

/// Packages allowed to own standard directories.
const FILESYS_PACKAGES: &[&str] = &["filesystem"];

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
fn parse_ldso_conf(content: &str, dirs: &mut std::collections::HashSet<String>) {
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
            if found_license && found_address {
                return true;
            }
            carry = len.min(FSF_SCAN_OVERLAP);
            window.copy_within(len - carry..len, 0);
        }
        found_license && found_address
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

/// Whether the lists carry the python base dependency for `ver`: the
/// `=`-pinned `python` / `python-base` / `python(abi)` names the
/// reference credits, the SUSE base name `python3-base` in any
/// relation and the versioned interpreter path `/usr/bin/python<ver>`
/// (issue #568), plus the interpreter expressed as the unversioned
/// `/usr/bin/python3` path or the `libpython<ver>` soname (issue
/// #862).
fn python_base_credited(lists: &DepLists, ver: &str) -> bool {
    let interpreter = format!("/usr/bin/python{ver}");
    let soname = format!("libpython{ver}.so");
    if lists.hard().any(|d| {
        dep_name_matches(&d.name, "python3-base")
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
                st.man_basenames.insert(binary.to_string());
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

    fn check_file_tmpfiles_conf_in_etc(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if fname.starts_with("/etc/tmpfiles.d/") {
            add_info(out, Level::Warning, pkg, "tmpfiles-conf-in-etc", &[fname]);
        }
    }

    fn check_file_subdir_in_bin(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        // sub_bin_regex: bin dirs with a subdirectory component
        for bindir in ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"] {
            if fname.starts_with(bindir) && fname[bindir.len()..].contains('/') {
                add_info(out, Level::Error, pkg, "subdir-in-bin", &[fname]);
                break;
            }
        }
    }

    fn check_file_siteperl_in_perl_module(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if fname.contains("/site_perl/") {
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
        if is_match(backup_regex(), fname) {
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

    fn check_file_htaccess_file(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if fname.ends_with("/.htaccess") {
            add_info(out, Level::Error, pkg, "htaccess-file", &[fname]);
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
        if is_hidden
            && !fname.starts_with("/etc/skel/")
            && !fname.ends_with("/.build-id")
            && !fname.ends_with("/.cargo-checksum.json")
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

    fn check_file_logrotate(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        // logrotate_regex: /etc/logrotate.d/
        if fname.starts_with("/etc/logrotate.d/") && fname != "/etc/logrotate.d/" {
            let basename = fname.rsplit('/').next().unwrap_or("");
            if basename != pkg.name {
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

    fn check_file_crontab(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        // #552: replicate reference as-is (matches base dirs too, known bug).
        // Same #388 root cause as logrotate: the reference also counts
        // requires + recommends + suggests here.
        let deps = Self::dep_names(pkg);
        if fname.starts_with("/etc/cron.") && !deps.contains(&"crontabs") && pkg.name != "crontabs"
        {
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
                let (perms, user, group) = find_perm_in_tmpfiles(pkg, fname);
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
                    st.man_basenames.insert(binary.to_string());
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
            if !pkg.files.iter().any(|f| f.name == abslink) && !pkg.req_names.contains(&abslink) {
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
        let mut fd = FileData::default();
        self.check_normal_logfile(pkg, fname, pkgfile, &mut fd, out);
        self.check_normal_getdata(pkg, fname, pkgfile, &mut fd, out);
        self.check_normal_doc(pkg, fname, &mut fd, out);
        self.check_normal_non_devel(pkg, fname, st, out);
        self.check_normal_lib(pkg, fname, pkgfile, st, out);
        self.check_normal_rpaths_in_buildconfig(pkg, fname, &fd, out);
        self.check_normal_bin(pkg, fname, pkgfile, st, out);
        self.check_normal_devel(pkg, fname, st, &fd, out);
        self.check_normal_world_w(pkg, fname, pkgfile, out);
        self.check_normal_perl_dep(pkg, fname, st);
        self.check_normal_python_dep(pkg, fname, st);
        self.check_normal_python_source(pkg, fname, &fd, out);
        self.check_normal_exec(pkg, fname, pkgfile, &mut fd, out);
        self.check_normal_non_conf_in_etc(pkg, fname, pkgfile, out);
        self.check_normal_python_noarch(pkg, fname, out);
        self.check_normal_gzipped_svg(pkg, fname, out);
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
        if pkgfile.user != "root" {
            add_info(
                out,
                Level::Error,
                pkg,
                "non-root-user-log-file",
                &[fname, &pkgfile.user],
            );
        }
        if pkgfile.group != "root" {
            add_info(
                out,
                Level::Error,
                pkg,
                "non-root-group-log-file",
                &[fname, &pkgfile.group],
            );
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
        if let Ok(Some(caps)) = self.bin_re.captures(fname) {
            if pkgfile.mode & 0o111 == 0 {
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
    /// `_python_magic_values` dict.
    fn python_magic_values(version: &str) -> &'static [u32] {
        match version {
            "2.2" => &[60717],
            "2.3" => &[62011],
            "2.4" => &[62061],
            "2.5" => &[62131],
            "2.6" => &[62161],
            "2.7" => &[62211],
            "3.0" => &[3130],
            "3.1" => &[3150],
            "3.2" => &[3180],
            "3.3" => &[3230],
            "3.4" => &[3310],
            "3.5" => &[3350, 3351],
            "3.6" => &[3379],
            "3.7" => &[3390, 3391, 3392, 3393, 3394],
            _ => &[],
        }
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
            } else if v.starts_with("3.0") || v.starts_with("3.1") {
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
        // Find the version name for the found magic value.
        let mut found_version = "unknown";
        for v in [
            "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "3.0", "3.1", "3.2", "3.3", "3.4", "3.5",
            "3.6", "3.7",
        ] {
            if Self::python_magic_values(v).contains(&found_magic) {
                found_version = v;
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

    fn check_normal_python_source(&self, pkg: &Pkg, fname: &str, fd: &FileData, out: &mut Filter) {
        let source_file = match self.python_bytecode_to_script(fname) {
            Some(s) => s,
            None => return,
        };
        match pkg.files.iter().find(|f| f.name == source_file) {
            None => {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "python-bytecode-without-source",
                    &[fname],
                );
            }
            Some(src) => {
                let srcfile = match pkg.readlink(src) {
                    Some(s) => s,
                    None => {
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "python-bytecode-without-source",
                            &[fname],
                        );
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
                // the mtime of the .py file.
                if let Some(details) = Self::pyc_mtime_check(
                    Self::pyc_mtime_from_chunk(&fd.chunk),
                    srcfile.mtime,
                    fname,
                    &srcfile.name,
                ) {
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
                // Severity split on the noreplace flag (maintainer
                // ruling, 2026-10-26; see the divergence ledger): a
                // %config(noreplace) executable warns instead of
                // erroring. The noreplace marking is deliberate -- the
                // packager opted into keep-local-edits semantics for
                // this file, and for hook-style files the execution is
                // the design -- so the finding stays visible for the
                // maintainer's call and can be suppressed per package,
                // but it does not fail the build. A plain %config
                // executable carries no such signal and keeps the
                // reference's error.
                let level = if pkg.noreplace_files.iter().any(|c| c == fname) {
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
            if fd.nonexec_file && !mingw_dll_a_perm_exempt(&pkg.name, fname) {
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
        if fname.starts_with("/etc/")
            && !pkgfile.is_config()
            && !pkgfile.is_ghost()
            && !fname.starts_with("/etc/ld.so.conf.d/")
            && !fname.starts_with("/etc/alternatives/")
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

    fn check_normal_gzipped_svg(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
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
                            if !script_is_test_data(&pkg.name, fname) {
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
            if fd.chunk.contains(&b'\r') {
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

// Bug analysis decisions (2026-09-29):
// - #1602 (Tom's PR): ldconfig -p interpreter honored — FIXED behavior implemented.
// - #552: missing-dependency-to-crontabs base dir false positive — REPLICATED as-is.
// - #551: logrotate-log-dir-not-packaged — NOT PORTED (LogrotateCheck not yet
//   ported; the /var/log exclusion from rpmlint#551 defers to that port).
// - #771: hardlink catch-22 — ABANDONED by Tom, replicate reference exactly.

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
    use crate::pkg::pkgfile::{RPMFILE_CONFIG, RPMFILE_GHOST, RPMFILE_NOREPLACE};

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
        // Maintainer ruling (2026-10-26): %config(noreplace) is a
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
        assert_eq!(levels.len(), 2, "both arms fire: {levels:?}");
        assert!(levels.contains(&Level::Warning), "{levels:?}");
        assert!(levels.contains(&Level::Error), "{levels:?}");
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
    fn normal_python_dep_flavour_base_name_fires() {
        // The flavour-named base form (`python313-base`, even with a
        // floor) is not one of the credited forms: #568 already left
        // it firing, and #862 does not widen the name forms.
        let names = run_dep_check(
            "foo",
            vec![dep_flagged("python313-base", 12, Some("3.9"))],
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

    #[test]
    fn symlink_up_and_down_segments() {
        // The reference emits E symlink-contains-up-and-down-segments once
        // per ".." segment left in the link target after the leading "../"
        // run is consumed. Only targets starting with "../" are examined;
        // an empty remainder stays silent. Cases verified against the
        // pinned reference interpreter.
        let config = test_config();
        let mut check = FilesCheck::new(&config);
        // (fname, link target, expected E count)
        let cases = [
            ("/a/b/c", "../foo/../bar", 1),
            ("/a/b/c", "../../x/../y", 1),
            ("/a/b/c", "../../a/../b/../c", 2),
            ("/a/b/c", "../..", 1),
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
            Some("-\"/etc/sysconfig/demo".to_string())
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
                    "/usr/lib/blktests/common/fio",
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
            ("non-executable-script", "/usr/lib/blktests/common/fio"),
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
}
