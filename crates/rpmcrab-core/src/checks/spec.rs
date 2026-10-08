//! `SpecCheck`: spec-file validation, ported from rpmlint's `SpecCheck.py`.
//!
//! Covers all 63 `add_info` call sites: the per-line checks (sections,
//! buildroot usage, `%setup`/`%autosetup`/`%autopatch`, applied patches,
//! `%{_sourcedir}` use, `./configure` handling, hardcoded library paths,
//! `%mklibname`, preamble tags, dependencies, changelog/files-section rules,
//! indentation, deprecated grep, `Group` validity, macros in comments, the
//! python helpers, forbidden control characters, the
//! `update-desktop-files` deprecation) and the whole-package checks
//! (`BuildRoot` tag, missing sections, superfluous `%clean`, multiple
//! `%changelog`, `%mklibname` for lib packages, depgen, patch fuzz, mixed
//! indentation, `%ifarch`-applied and unapplied patches), plus the two
//! checks that need the `rpm` tool or the spec parser (`specfile-error`,
//! `specfile-warning`, `invalid-url`), skipped in mini mode.
//!
//! Two upstream fixes ship as fixed behaviour: `#1600` (a trailing
//! line-continuation `\` on `BuildArch: noarch`) and `#1601` (quote-aware
//! `#` comment detection for `macro-in-comment`). The openSUSE-only
//! `obsolete-suse-version-check` / `invalid-suse-version-check` are part of
//! the reference flavour and are implemented. Deliberate divergences are
//! ledgered in `tests/parity/divergences.toml`.
//!
//! One finding has no reference counterpart: `translated-description` for
//! `%description -l <lang>` (upstream feature request
//! rpm-software-management/rpmlint#2).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;

use fancy_regex::Regex;

use crate::check::{Check, add_info, spec_add_info};
use crate::checks::shared::macro_regex;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::dep::{
    has_forbidden_controlchars, has_forbidden_controlchars_deps, is_rich_dep_expr, parse_deps,
};
use crate::pkg::spec::{self, SpecPkg};
use crate::pkg::{Pkg, init as pkg_init};
use crate::tools::{Tool, ToolSource, test_source};
use std::sync::OnceLock;

static PATCH_RE: OnceLock<Regex> = OnceLock::new();
fn patch_re() -> &'static Regex {
    PATCH_RE.get_or_init(|| Regex::new(r"(?i)^Patch(\d*)\s*:\s*(\S.*?)\s*$").expect("static regex"))
}

static APPLIED_PATCH_RPM420_RE: OnceLock<Regex> = OnceLock::new();
fn applied_patch_rpm420_re() -> &'static Regex {
    APPLIED_PATCH_RPM420_RE.get_or_init(|| Regex::new(r"^%patch(\d+)").expect("static regex"))
}

static APPLIED_PATCH_RE: OnceLock<Regex> = OnceLock::new();
fn applied_patch_re() -> &'static Regex {
    APPLIED_PATCH_RE.get_or_init(|| Regex::new(r"^%patch\s*(\d*)").expect("static regex"))
}

static APPLIED_PATCH_P_RE: OnceLock<Regex> = OnceLock::new();
fn applied_patch_p_re() -> &'static Regex {
    APPLIED_PATCH_P_RE.get_or_init(|| Regex::new(r"\s-P\s*(\d+)\b").expect("static regex"))
}

static APPLIED_PATCH_PIPE_RE: OnceLock<Regex> = OnceLock::new();
fn applied_patch_pipe_re() -> &'static Regex {
    APPLIED_PATCH_PIPE_RE
        .get_or_init(|| Regex::new(r"\s%\{PATCH(\d+)\}\s*(%\{?__)?patch\b").expect("static regex"))
}

static APPLIED_PATCH_I_RE: OnceLock<Regex> = OnceLock::new();
fn applied_patch_i_re() -> &'static Regex {
    APPLIED_PATCH_I_RE.get_or_init(|| {
        Regex::new(r"(?:%\{?__)?patch\}?.*?\s+(?:<|-i)\s+%\{PATCH(\d+)\}").expect("static regex")
    })
}

static SOURCE_DIR_RE: OnceLock<Regex> = OnceLock::new();
fn source_dir_re() -> &'static Regex {
    SOURCE_DIR_RE.get_or_init(|| {
        Regex::new(r"^[^#]*(\$RPM_SOURCE_DIR|%{?_sourcedir}?)").expect("static regex")
    })
}

static OBSOLETE_TAGS_RE: OnceLock<Regex> = OnceLock::new();
fn obsolete_tags_re() -> &'static Regex {
    OBSOLETE_TAGS_RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:Serial|Copyright)\s*:\s*(\S.*?)\s*$").expect("static regex")
    })
}

static PREFIX_RE: OnceLock<Regex> = OnceLock::new();
fn prefix_re() -> &'static Regex {
    PREFIX_RE.get_or_init(|| Regex::new(r"(?i)^Prefix\s*:\s*(\S.*?)\s*$").expect("static regex"))
}

static PACKAGER_RE: OnceLock<Regex> = OnceLock::new();
fn packager_re() -> &'static Regex {
    PACKAGER_RE
        .get_or_init(|| Regex::new(r"(?i)^Packager\s*:\s*(\S.*?)\s*$").expect("static regex"))
}

static BUILDARCH_RE: OnceLock<Regex> = OnceLock::new();
fn buildarch_re() -> &'static Regex {
    BUILDARCH_RE.get_or_init(|| {
        Regex::new(r"(?i)^BuildArch(?:itectures)?\s*:\s*(\S.*?)\s*$").expect("static regex")
    })
}

static BUILDPREREQ_RE: OnceLock<Regex> = OnceLock::new();
fn buildprereq_re() -> &'static Regex {
    BUILDPREREQ_RE
        .get_or_init(|| Regex::new(r"(?i)^BuildPreReq\s*:\s*(\S.*?)\s*$").expect("static regex"))
}

static PREREQ_RE: OnceLock<Regex> = OnceLock::new();
fn prereq_re() -> &'static Regex {
    PREREQ_RE
        .get_or_init(|| Regex::new(r"(?i)^PreReq(\(.*\))\s*:\s*(\S.*?)\s*$").expect("static regex"))
}

static SUSE_VERSION_RE: OnceLock<Regex> = OnceLock::new();
fn suse_version_re() -> &'static Regex {
    SUSE_VERSION_RE.get_or_init(|| {
        Regex::new(r"%({|{\?)?suse_version}?\s*[<>=]+\s*(?P<version>\d+)").expect("static regex")
    })
}

static MAKE_CHECK_RE: OnceLock<Regex> = OnceLock::new();
fn make_check_re() -> &'static Regex {
    MAKE_CHECK_RE
        .get_or_init(|| Regex::new(r"(^|\s|%{?__)make}?\s+(check|test)").expect("static regex"))
}

static RPM_BUILDROOT_RE: OnceLock<Regex> = OnceLock::new();
fn rpm_buildroot_re() -> &'static Regex {
    RPM_BUILDROOT_RE.get_or_init(|| {
        Regex::new(r"^[^#]*?(?:(\\*)\${?RPM_BUILD_ROOT}?|(%+){?buildroot}?)").expect("static regex")
    })
}

static CONFIGURE_LIBDIR_SPEC_RE: OnceLock<Regex> = OnceLock::new();
fn configure_libdir_spec_re() -> &'static Regex {
    CONFIGURE_LIBDIR_SPEC_RE.get_or_init(|| {
        Regex::new(r"ln |\./configure[^#]*--libdir=(\S+)[^#]*").expect("static regex")
    })
}

/// `hardcoded_library_paths`, start-anchored: the reference applies it with
/// `re.match`.
static HARDCODED_LIBDIR_PATHS_RE: OnceLock<Regex> = OnceLock::new();
fn hardcoded_libdir_paths_re() -> &'static Regex {
    HARDCODED_LIBDIR_PATHS_RE.get_or_init(|| {
        Regex::new(r"^(/lib|/usr/lib|/usr/X11R6/lib/(?!([^/]+/)+)[^/]*\.([oa]|la|so[0-9.]*))")
            .expect("static regex")
    })
}

static LIB_PACKAGE_RE: OnceLock<Regex> = OnceLock::new();
fn lib_package_re() -> &'static Regex {
    LIB_PACKAGE_RE.get_or_init(|| Regex::new(r"^%package.*\Wlib").expect("static regex"))
}

static IFARCH_RE: OnceLock<Regex> = OnceLock::new();
fn ifarch_re() -> &'static Regex {
    IFARCH_RE.get_or_init(|| Regex::new(r"^\s*%ifn?arch\s").expect("static regex"))
}

static IF_RE: OnceLock<Regex> = OnceLock::new();
fn if_re() -> &'static Regex {
    IF_RE.get_or_init(|| Regex::new(r"^\s*%if\s").expect("static regex"))
}

static ENDIF_RE: OnceLock<Regex> = OnceLock::new();
fn endif_re() -> &'static Regex {
    ENDIF_RE.get_or_init(|| Regex::new(r"^\s*%endif\b").expect("static regex"))
}

/// `DEFAULT_BIARCH_PACKAGES`: hardcoded library paths are not checked in
/// biarch packages.
static BIARCH_PACKAGE_RE: OnceLock<Regex> = OnceLock::new();
fn biarch_package_re() -> &'static Regex {
    BIARCH_PACKAGE_RE.get_or_init(|| Regex::new(r"^(gcc|glibc)").expect("static regex"))
}

static LIBDIR_RE: OnceLock<Regex> = OnceLock::new();
fn libdir_re() -> &'static Regex {
    LIBDIR_RE.get_or_init(|| Regex::new(r"%{?_lib(?:dir)?\}?\b").expect("static regex"))
}

/// `%description -l <lang>`: the `-l` flag with its language (upstream
/// rpm-software-management/rpmlint#2). `-l` glued to the language (`-lfi`)
/// is not the flag form and stays quiet.
static DESCRIPTION_LANG_RE: OnceLock<Regex> = OnceLock::new();
fn description_lang_re() -> &'static Regex {
    DESCRIPTION_LANG_RE
        .get_or_init(|| Regex::new(r"^%description\b.*\s-l\s+(\S+)").expect("static regex"))
}

/// `section_regexs`: `^%<name>(?:\s|$)` for the script sections plus
/// `RPM_SCRIPTLETS`.
fn section_res() -> Vec<(String, Regex)> {
    let mut names = vec![
        "build",
        "changelog",
        "check",
        "clean",
        "description",
        "files",
        "install",
        "package",
        "prep",
    ];
    names.extend(RPM_SCRIPTLETS);
    names
        .into_iter()
        .map(|n| {
            (
                n.to_string(),
                Regex::new(&format!(r"^%{n}(?:\s|$)")).expect("static regex"),
            )
        })
        .collect()
}

/// `Pkg.RPM_SCRIPTLETS` (`pkg.py:59-63`).
const RPM_SCRIPTLETS: &[&str] = &[
    "pre",
    "post",
    "preun",
    "postun",
    "pretrans",
    "posttrans",
    "trigger",
    "triggerin",
    "triggerprein",
    "triggerun",
    "triggerpostun",
    "verifyscript",
    "filetriggerin",
    "filetrigger",
    "filetriggerun",
    "filetriggerpostun",
    "transfiletriggerin",
    "transfiletrigger",
    "transfiletriggerun",
    "transfiletriggerun",
    "transfiletriggerpostun",
];

static DEPRECATED_GREP_RE: OnceLock<Regex> = OnceLock::new();
fn deprecated_grep_re() -> &'static Regex {
    DEPRECATED_GREP_RE.get_or_init(|| Regex::new(r"\b[ef]grep\b").expect("static regex"))
}

static TMPFILES_MACRO_RE: OnceLock<Regex> = OnceLock::new();
fn tmpfiles_macro_re() -> &'static Regex {
    TMPFILES_MACRO_RE.get_or_init(|| {
        Regex::new(
            r"%tmpfiles_create_package\b|%tmpfiles_create\b|%\{tmpfiles_create_package\}|%\{tmpfiles_create\}",
        )
        .expect("static regex")
    })
}

static HARDCODED_LIBRARY_PATH_RE: OnceLock<Regex> = OnceLock::new();
fn hardcoded_library_path_re() -> &'static Regex {
    HARDCODED_LIBRARY_PATH_RE.get_or_init(|| Regex::new(r"^[^#]*((^|\s+|\.\./\.\.|\${?RPM_BUILD_ROOT}?|%{?buildroot}?|%{?_prefix}?)(/lib|/usr/lib|/usr/X11R6/lib/(?!([^/]+/)+)[^/]*\.([oa]|la|so[0-9.]*))(?=[\s;/])([^\s,;]*))")
        .expect("static regex"))
}

static DEPSCRIPT_OVERRIDE_RE: OnceLock<Regex> = OnceLock::new();
fn depscript_override_re() -> &'static Regex {
    DEPSCRIPT_OVERRIDE_RE.get_or_init(|| {
        Regex::new(r"(^|\s)%(define|global)\s+__find_(requires|provides)\s").expect("static regex")
    })
}

static DEPGEN_DISABLE_RE: OnceLock<Regex> = OnceLock::new();
fn depgen_disable_re() -> &'static Regex {
    DEPGEN_DISABLE_RE.get_or_init(|| {
        Regex::new(r"(^|\s)%(define|global)\s+_use_internal_dependency_generator\s+0")
            .expect("static regex")
    })
}

static PATCH_FUZZ_OVERRIDE_RE: OnceLock<Regex> = OnceLock::new();
fn patch_fuzz_override_re() -> &'static Regex {
    PATCH_FUZZ_OVERRIDE_RE.get_or_init(|| {
        Regex::new(r"(^|\s)%(define|global)\s+_default_patch_fuzz\s+(\d+)").expect("static regex")
    })
}

static INDENT_SPACES_RE: OnceLock<Regex> = OnceLock::new();
fn indent_spaces_re() -> &'static Regex {
    INDENT_SPACES_RE.get_or_init(|| {
        Regex::new(r"( \t|(^|\t)([^\t]{8})*[^\t]{4}[^\t]?([^\t][^\t.!?]|[^\t]?[.!?] )  )")
            .expect("static regex")
    })
}

static REQUIRES_RE: OnceLock<Regex> = OnceLock::new();
fn requires_re() -> &'static Regex {
    REQUIRES_RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:Build)?(?:Pre)?Req(?:uires)?(?:\([^\)]+\))?:\s*(.*)")
            .expect("static regex")
    })
}

static PROVIDES_RE: OnceLock<Regex> = OnceLock::new();
fn provides_re() -> &'static Regex {
    PROVIDES_RE
        .get_or_init(|| Regex::new(r"(?i)^Provides(?:\([^\)]+\))?:\s*(.*)").expect("static regex"))
}

static OBSOLETES_RE: OnceLock<Regex> = OnceLock::new();
fn obsoletes_re() -> &'static Regex {
    OBSOLETES_RE.get_or_init(|| Regex::new(r"(?i)^Obsoletes:\s*(.*)").expect("static regex"))
}

static CONFLICTS_RE: OnceLock<Regex> = OnceLock::new();
fn conflicts_re() -> &'static Regex {
    CONFLICTS_RE
        .get_or_init(|| Regex::new(r"(?i)^(?:Build)?Conflicts:\s*(.*)").expect("static regex"))
}

static DECLARATIVE_RE: OnceLock<Regex> = OnceLock::new();
fn declarative_re() -> &'static Regex {
    DECLARATIVE_RE.get_or_init(|| Regex::new(r"(?i)^BuildSystem:\s*(.*)").expect("static regex"))
}

/// `Summary:` tag lines (optional language qualifier) — prose for the
/// `non-break-space` relaxation (upstream rpmlint#554).
static SUMMARY_RE: OnceLock<Regex> = OnceLock::new();
fn summary_re() -> &'static Regex {
    SUMMARY_RE.get_or_init(|| Regex::new(r"(?i)^\s*Summary(\([^)]*\))?\s*:").expect("static regex"))
}

/// `SourceN:`/`PatchN:` tag lines — a conditional one (inside `%if`) warns
/// `conditional-source-or-patch` (upstream rpmlint#45).
static SOURCE_PATCH_RE: OnceLock<Regex> = OnceLock::new();
fn source_patch_re() -> &'static Regex {
    SOURCE_PATCH_RE
        .get_or_init(|| Regex::new(r"^\s*(Source\d*|Patch\d*)\s*:").expect("static regex"))
}

static COMPOP_RE: OnceLock<Regex> = OnceLock::new();
fn compop_re() -> &'static Regex {
    COMPOP_RE.get_or_init(|| Regex::new(r"[<>=]").expect("static regex"))
}

/// Anchored: the reference applies it with `re.match` ("intentionally no
/// whitespace before!").
static SETUP_RE: OnceLock<Regex> = OnceLock::new();
fn setup_re() -> &'static Regex {
    SETUP_RE.get_or_init(|| Regex::new(r"^%setup\b").expect("static regex"))
}

static AUTOSETUP_RE: OnceLock<Regex> = OnceLock::new();
fn autosetup_re() -> &'static Regex {
    AUTOSETUP_RE.get_or_init(|| Regex::new(r"^\s*%autosetup(\s.*|$)").expect("static regex"))
}

static AUTOSETUP_N_RE: OnceLock<Regex> = OnceLock::new();
fn autosetup_n_re() -> &'static Regex {
    AUTOSETUP_N_RE.get_or_init(|| Regex::new(r" -[A-Za-z]*N").expect("static regex"))
}

static AUTOPATCH_RE: OnceLock<Regex> = OnceLock::new();
fn autopatch_re() -> &'static Regex {
    AUTOPATCH_RE.get_or_init(|| Regex::new(r"^\s*%autopatch(?:\s|$)").expect("static regex"))
}

static FILELIST_RE: OnceLock<Regex> = OnceLock::new();
fn filelist_re() -> &'static Regex {
    FILELIST_RE.get_or_init(|| Regex::new(r"\s+-f\s+\S+").expect("static regex"))
}

static PKGNAME_RE: OnceLock<Regex> = OnceLock::new();
fn pkgname_re() -> &'static Regex {
    PKGNAME_RE.get_or_init(|| Regex::new(r"\s+(?:-n\s+)?(\S+)").expect("static regex"))
}

static TARBALL_RE: OnceLock<Regex> = OnceLock::new();
fn tarball_re() -> &'static Regex {
    TARBALL_RE
        .get_or_init(|| Regex::new(r"(?i)\.(?:t(?:ar|[glx]z|bz2?)|zip)\b").expect("static regex"))
}

static PYTHON_SETUP_TEST_RE: OnceLock<Regex> = OnceLock::new();
fn python_setup_test_re() -> &'static Regex {
    PYTHON_SETUP_TEST_RE.get_or_init(|| Regex::new(r"^[^#]*(setup.py test)").expect("static regex"))
}

static PYTHON_SETUP_INSTALL_RE: OnceLock<Regex> = OnceLock::new();
fn python_setup_install_re() -> &'static Regex {
    PYTHON_SETUP_INSTALL_RE.get_or_init(|| {
        Regex::new(r"^[^#]*(setup.py install|%\{?py(thon)?\d*_install)").expect("static regex")
    })
}

static PYTHON_MODULE_DEF_RE: OnceLock<Regex> = OnceLock::new();
fn python_module_def_re() -> &'static Regex {
    PYTHON_MODULE_DEF_RE.get_or_init(|| {
        Regex::new(r"^[^#]*%{\?!python_module:%define python_module\(\)").expect("static regex")
    })
}

static PYTHON_SITELIB_GLOB_RE: OnceLock<Regex> = OnceLock::new();
fn python_sitelib_glob_re() -> &'static Regex {
    PYTHON_SITELIB_GLOB_RE
        .get_or_init(|| Regex::new(r"^[^#]*%{python_site(lib|arch)}/\*\s*$").expect("static regex"))
}

static SHARED_DIR_GLOB_RE: OnceLock<Regex> = OnceLock::new();
fn shared_dir_glob_re() -> &'static Regex {
    SHARED_DIR_GLOB_RE.get_or_init(|| {
        Regex::new(r"^[^#]*%{_(?:bin|data|doc|include|man)dir}/\*\s*$").expect("static regex")
    })
}

static SUSE_UPDATE_DESKTOP_FILE_RE: OnceLock<Regex> = OnceLock::new();
fn suse_update_desktop_file_re() -> &'static Regex {
    SUSE_UPDATE_DESKTOP_FILE_RE.get_or_init(|| {
        Regex::new(r"(?i)^BuildRequires:\s*update-desktop-files").expect("static regex")
    })
}

/// Non-breaking space (`UNICODE_NBSP`).
const NBSP: char = '\u{a0}';

/// The position of the first `#` that starts a shell comment, or `None`.
///
/// `#` inside single- or double-quoted shell strings does not start a
/// comment. A backslash escapes the next character unless inside single
/// quotes (shell semantics); the caller still decides whether a `#`
/// candidate counts as a comment start. Fixed behaviour per `#1601`.
fn comment_start_pos(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut pos = 0;
    while pos < bytes.len() {
        let c = bytes[pos];
        if c == b'#' && !in_single && !in_double {
            return Some(pos);
        }
        if c == b'\\' && !in_single && pos + 1 < bytes.len() {
            pos += 2;
            continue;
        }
        if c == b'\'' && !in_double {
            in_single = !in_single;
        } else if c == b'"' && !in_single {
            in_double = !in_double;
        }
        pos += 1;
    }
    None
}

/// `line[:-1]`: drop the last character (the line's trailing newline).
fn without_newline(line: &str) -> &str {
    match line.char_indices().next_back() {
        Some((i, _)) => &line[..i],
        None => line,
    }
}

/// `contains_buildroot` (`SpecCheck.py:108-116`): true when the line uses
/// `$RPM_BUILD_ROOT` / `%{buildroot}` without an odd count of escaping
/// `%`s or an even count of escaping backslashes.
fn contains_buildroot(line: &str, re: &Regex) -> bool {
    if let Ok(Some(caps)) = re.captures(line) {
        let backslashes = caps.get(1).map(|m| m.as_str());
        let percents = caps.get(2).map(|m| m.as_str());
        backslashes.is_none_or(|s| s.len() % 2 == 0) && percents.is_none_or(|s| s.len() % 2 != 0)
    } else {
        false
    }
}

/// The `(scheme, netloc)` pair `urllib.parse.urlparse(url)[0:2]` yields, for
/// the `scheme://netloc` forms this check cares about. Only "both present"
/// is ever tested, so subtler `urlparse` distinctions do not matter.
fn url_scheme_netloc(url: &str) -> (Option<&str>, Option<&str>) {
    let Some((scheme, rest)) = url.split_once("://") else {
        return (None, None);
    };
    let mut chars = scheme.chars();
    let scheme_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c));
    if !scheme_ok {
        return (None, None);
    }
    let netloc = rest.split('/').next().unwrap_or("");
    (Some(scheme), (!netloc.is_empty()).then_some(netloc))
}

/// `SpecCheck`, ported from rpmlint's `SpecCheck.py`.
pub struct SpecCheck {
    hardcoded_lib_path_exceptions_re: Regex,
    mini_mode: bool,
    macro_re: Regex,
    patch_re: Regex,
    applied_patch_rpm420_re: Regex,
    applied_patch_re: Regex,
    applied_patch_p_re: Regex,
    applied_patch_pipe_re: Regex,
    applied_patch_i_re: Regex,
    source_dir_re: Regex,
    obsolete_tags_re: Regex,
    prefix_re: Regex,
    packager_re: Regex,
    buildarch_re: Regex,
    buildprereq_re: Regex,
    prereq_re: Regex,
    suse_version_re: Regex,
    make_check_re: Regex,
    rpm_buildroot_re: Regex,
    configure_libdir_spec_re: Regex,
    hardcoded_libdir_paths_re: Regex,
    lib_package_re: Regex,
    ifarch_re: Regex,
    if_re: Regex,
    endif_re: Regex,
    biarch_package_re: Regex,
    libdir_re: Regex,
    description_lang_re: Regex,
    section_res: Vec<(String, Regex)>,
    deprecated_grep_re: Regex,
    tmpfiles_macro_re: Regex,
    hardcoded_library_path_re: Regex,
    /// Required: spec parsing shells out to `rpm`.
    rpm: Tool,
    depscript_override_re: Regex,
    depgen_disable_re: Regex,
    patch_fuzz_override_re: Regex,
    indent_spaces_re: Regex,
    requires_re: Regex,
    provides_re: Regex,
    obsoletes_re: Regex,
    conflicts_re: Regex,
    declarative_re: Regex,
    summary_re: Regex,
    source_patch_re: Regex,
    compop_re: Regex,
    setup_re: Regex,
    autosetup_re: Regex,
    autosetup_n_re: Regex,
    autopatch_re: Regex,
    patch_applying_macros: Vec<String>,
    filelist_re: Regex,
    pkgname_re: Regex,
    tarball_re: Regex,
    python_setup_test_re: Regex,
    python_setup_install_re: Regex,
    python_module_def_re: Regex,
    python_sitelib_glob_re: Regex,
    shared_dir_glob_re: Regex,
    suse_update_desktop_file_re: Regex,
    // Per-package state (`_default_state`).
    spec_file: Option<String>,
    spec_name: Option<String>,
    patches: BTreeMap<i64, String>,
    applied_patches: Vec<i64>,
    patches_auto_applied: bool,
    source_dir: bool,
    configure_linenum: Option<u32>,
    configure_cmdline: String,
    mklibname: bool,
    is_lib_pkg: bool,
    if_depth: i32,
    ifarch_depth: i32,
    depscript_override: bool,
    depgen_disabled: bool,
    patch_fuzz_override: bool,
    indent_spaces: u32,
    indent_tabs: u32,
    section: BTreeMap<String, u32>,
    declarative: bool,
    current_section: String,
    current_package: Option<String>,
    package_noarch: BTreeMap<Option<String>, bool>,
    spec_only: bool,
}

impl SpecCheck {
    /// Build the check from the config (`PatchApplyingMacros`,
    /// `HardcodedLibPathExceptions`, `mini_mode`).
    pub fn new(config: &Config) -> Self {
        Self::with_tool_source(config, ToolSource::Path)
    }

    /// Probe for the required `rpm` tool under `source`. `rpm` is
    /// mandatory for spec parsing, so absence fails here with a clear
    /// message instead of deep inside the check.
    pub fn with_tool_source(config: &Config, source: ToolSource) -> Self {
        let patch_applying_macros = config
            .configuration
            .get("PatchApplyingMacros")
            .and_then(toml::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let exceptions = config
            .configuration
            .get("HardcodedLibPathExceptions")
            .and_then(toml::Value::as_str)
            // An empty pattern would match every path and suppress all
            // findings; fall back to the configdefaults.toml default.
            .unwrap_or(r"/lib/(modules|cpp|perl5|rpm|hotplug|firmware|systemd)($|[\s/,])");
        Self {
            hardcoded_lib_path_exceptions_re: Regex::new(exceptions)
                .unwrap_or_else(|_| Regex::new("$^").expect("static regex")),
            mini_mode: config.mini_mode,
            macro_re: macro_regex().clone(),
            patch_re: patch_re().clone(),
            applied_patch_rpm420_re: applied_patch_rpm420_re().clone(),
            applied_patch_re: applied_patch_re().clone(),
            applied_patch_p_re: applied_patch_p_re().clone(),
            applied_patch_pipe_re: applied_patch_pipe_re().clone(),
            applied_patch_i_re: applied_patch_i_re().clone(),
            source_dir_re: source_dir_re().clone(),
            obsolete_tags_re: obsolete_tags_re().clone(),
            prefix_re: prefix_re().clone(),
            packager_re: packager_re().clone(),
            buildarch_re: buildarch_re().clone(),
            buildprereq_re: buildprereq_re().clone(),
            prereq_re: prereq_re().clone(),
            suse_version_re: suse_version_re().clone(),
            make_check_re: make_check_re().clone(),
            rpm_buildroot_re: rpm_buildroot_re().clone(),
            configure_libdir_spec_re: configure_libdir_spec_re().clone(),
            hardcoded_libdir_paths_re: hardcoded_libdir_paths_re().clone(),
            lib_package_re: lib_package_re().clone(),
            ifarch_re: ifarch_re().clone(),
            if_re: if_re().clone(),
            endif_re: endif_re().clone(),
            biarch_package_re: biarch_package_re().clone(),
            libdir_re: libdir_re().clone(),
            description_lang_re: description_lang_re().clone(),
            section_res: section_res(),
            deprecated_grep_re: deprecated_grep_re().clone(),
            tmpfiles_macro_re: tmpfiles_macro_re().clone(),
            hardcoded_library_path_re: hardcoded_library_path_re().clone(),
            depscript_override_re: depscript_override_re().clone(),
            depgen_disable_re: depgen_disable_re().clone(),
            patch_fuzz_override_re: patch_fuzz_override_re().clone(),
            indent_spaces_re: indent_spaces_re().clone(),
            requires_re: requires_re().clone(),
            provides_re: provides_re().clone(),
            obsoletes_re: obsoletes_re().clone(),
            conflicts_re: conflicts_re().clone(),
            declarative_re: declarative_re().clone(),
            summary_re: summary_re().clone(),
            source_patch_re: source_patch_re().clone(),
            compop_re: compop_re().clone(),
            setup_re: setup_re().clone(),
            autosetup_re: autosetup_re().clone(),
            autosetup_n_re: autosetup_n_re().clone(),
            autopatch_re: autopatch_re().clone(),
            patch_applying_macros,
            filelist_re: filelist_re().clone(),
            pkgname_re: pkgname_re().clone(),
            tarball_re: tarball_re().clone(),
            python_setup_test_re: python_setup_test_re().clone(),
            python_setup_install_re: python_setup_install_re().clone(),
            python_module_def_re: python_module_def_re().clone(),
            python_sitelib_glob_re: python_sitelib_glob_re().clone(),
            shared_dir_glob_re: shared_dir_glob_re().clone(),
            suse_update_desktop_file_re: suse_update_desktop_file_re().clone(),
            spec_file: None,
            spec_name: None,
            patches: BTreeMap::new(),
            applied_patches: Vec::new(),
            patches_auto_applied: false,
            source_dir: false,
            configure_linenum: None,
            configure_cmdline: String::new(),
            mklibname: false,
            is_lib_pkg: false,
            if_depth: 0,
            ifarch_depth: -1,
            depscript_override: false,
            depgen_disabled: false,
            patch_fuzz_override: false,
            indent_spaces: 0,
            indent_tabs: 0,
            section: BTreeMap::new(),
            declarative: false,
            current_section: "package".to_string(),
            current_package: None,
            package_noarch: BTreeMap::new(),
            spec_only: false,
            rpm: Self::probe_rpm(&source),
        }
    }

    /// Test entry point: `None` probes the live `PATH`, `Some(dir)`
    /// resolves `rpm` under `dir` instead of mutating the process
    /// environment.
    pub fn with_tool_dir(config: &Config, bin_dir: Option<&std::path::Path>) -> Self {
        Self::with_tool_source(config, test_source(bin_dir))
    }

    /// `rpm` is needed only by `check_specfile_error`, which the reference
    /// likewise gates on there being a spec file (SpecCheck.py:224-227), so
    /// probing must not be fatal: a binary-only lint never reaches the tool.
    fn probe_rpm(source: &ToolSource) -> Tool {
        let (rpm, _) = Tool::probe(source, "rpm", &["--version"]);
        rpm
    }

    /// `output.add_info` for spec findings: the line is the package's
    /// `current_linenum`, rendered as `file.spec:NN:`.
    fn info(&self, out: &mut Filter, pkg: &SpecPkg, level: Level, check: &str, details: &[&str]) {
        spec_add_info(out, level, pkg, pkg.current_linenum.get(), check, details);
    }

    /// The spec file's directory, for the `_sourcedir` macro define. Mirrors
    /// `str(Path(self._spec_file).parent)` (`.` for a bare filename).
    fn spec_file_dir(&self) -> String {
        let dir = self
            .spec_file
            .as_deref()
            .map(Path::new)
            .and_then(|p| p.parent())
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        if dir.is_empty() { ".".to_string() } else { dir }
    }
}

impl Check for SpecCheck {
    fn name(&self) -> &'static str {
        "SpecCheck"
    }

    /// `check_source`: find the spec file in the SRPM's file list and run
    /// the spec checks on it.
    fn check_source(&mut self, pkg: &Pkg, config: &Config, out: &mut Filter) {
        let mut spec_file = None;
        let mut spec_name = None;
        let mut wrong_spec = false;
        for f in &pkg.files {
            if f.name.ends_with(".spec") {
                spec_file = Some(f.path.clone());
                spec_name = Some(f.name.clone());
                if f.name == format!("{}.spec", pkg.name) {
                    wrong_spec = false;
                    break;
                }
                wrong_spec = true;
            }
        }

        if spec_file.is_none() {
            add_info(out, Level::Error, pkg, "no-spec-file", &[]);
        }
        if wrong_spec {
            add_info(out, Level::Error, pkg, "invalid-spec-name", &[]);
        }

        if let Some(path) = spec_file {
            self.spec_name = spec_name;
            let spec_pkg =
                SpecPkg::open(Path::new(&path)).expect("spec file from the SRPM is readable");
            self.check_spec(&spec_pkg, config, out);
        }
    }

    /// `check_spec`: run the spec checks over a `.spec` input.
    fn check_spec(&mut self, pkg: &SpecPkg, config: &Config, out: &mut Filter) {
        // `error_details` for `-v`/`--explain`, set in `__init__` in the
        // reference.
        Self::register_error_details(config, out);

        self.spec_file = Some(pkg.name.clone());

        if !spec::is_utf8(Path::new(&pkg.name)) {
            let detail = self.spec_name.clone().unwrap_or_else(|| pkg.name.clone());
            self.info(out, pkg, Level::Error, "non-utf8-spec-file", &[&detail]);
        }

        self.spec_only = true;
        pkg.current_linenum.set(Some(0));
        for line in &pkg.lines {
            pkg.current_linenum
                .set(Some(pkg.current_linenum.get().unwrap_or(0) + 1));
            self.check_line(pkg, out, line);
        }
        pkg.current_linenum.set(None);

        if !self.declarative {
            for sec in ["prep", "build", "install", "check"] {
                if self.section.get(sec).copied().unwrap_or(0) == 0 {
                    let check = format!("no-%{sec}-section");
                    self.info(out, pkg, Level::Warning, &check, &[]);
                }
            }
        }
        if self.section.get("clean").copied().unwrap_or(0) > 0 {
            self.info(out, pkg, Level::Error, "superfluous-%clean-section", &[]);
        }
        if self.section.get("changelog").copied().unwrap_or(0) > 1 {
            self.info(
                out,
                pkg,
                Level::Warning,
                "more-than-one-%changelog-section",
                &[],
            );
        }
        if self.is_lib_pkg && !self.mklibname {
            self.info(
                out,
                pkg,
                Level::Error,
                "lib-package-without-%mklibname",
                &[],
            );
        }
        if self.depscript_override && !self.depgen_disabled {
            self.info(
                out,
                pkg,
                Level::Warning,
                "depscript-without-disabling-depgen",
                &[],
            );
        }
        if self.patch_fuzz_override {
            self.info(out, pkg, Level::Warning, "patch-fuzz-is-changed", &[]);
        }
        if self.indent_spaces != 0 && self.indent_tabs != 0 {
            let detail = format!(
                "(spaces: line {}, tab: line {})",
                self.indent_spaces, self.indent_tabs
            );
            pkg.current_linenum
                .set(Some(self.indent_spaces.max(self.indent_tabs)));
            self.info(
                out,
                pkg,
                Level::Warning,
                "mixed-use-of-spaces-and-tabs",
                &[&detail],
            );
            pkg.current_linenum.set(None);
        }
        if !self.patches_auto_applied {
            let patches: Vec<(i64, String)> =
                self.patches.iter().map(|(n, f)| (*n, f.clone())).collect();
            for (pnum, pfile) in &patches {
                if !self.applied_patches.contains(pnum) {
                    let tag = format!("Patch{pnum}:");
                    self.info(
                        out,
                        pkg,
                        Level::Warning,
                        "patch-not-applied",
                        &[&tag, pfile],
                    );
                }
            }
        }

        if self.spec_file.is_none() {
            return;
        }
        if !self.mini_mode {
            self.check_specfile_error(pkg, out);
            self.check_invalid_url(pkg, out);
        }
    }

    fn reset(&mut self) {
        self.spec_file = None;
        self.spec_name = None;
        self.patches.clear();
        self.applied_patches.clear();
        self.patches_auto_applied = false;
        self.source_dir = false;
        self.configure_linenum = None;
        self.configure_cmdline.clear();
        self.mklibname = false;
        self.is_lib_pkg = false;
        self.if_depth = 0;
        self.ifarch_depth = -1;
        self.depscript_override = false;
        self.depgen_disabled = false;
        self.patch_fuzz_override = false;
        self.indent_spaces = 0;
        self.indent_tabs = 0;
        self.section.clear();
        self.declarative = false;
        self.current_section = "package".to_string();
        self.current_package = None;
        self.package_noarch.clear();
        self.spec_only = false;
    }
}

impl SpecCheck {
    /// Parse the spec with the `rpm` tool and forward its diagnostics
    /// (`SpecCheck.py:300-322`).
    fn check_specfile_error(&self, pkg: &SpecPkg, out: &mut Filter) {
        let spec_file = self.spec_file.as_deref().unwrap_or("");
        let define = format!("_sourcedir {}", self.spec_file_dir());
        // The reference lets a missing `rpm` raise here (no try/except around
        // the subprocess). Skipping is this project's standing treatment for an
        // absent tool -- see the PostCheck interpreter and BashismsCheck
        // checkbashisms entries -- and keeps a missing rpm from aborting the
        // whole run instead of one check.
        let Some(mut cmd) = self.rpm.command() else {
            return;
        };
        let output = cmd
            .args(["-q", "--qf=", "-D", &define, "--specfile", spec_file])
            .env("LC_ALL", "en_US.UTF-8")
            .env("LANGUAGE", "en_US")
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .output()
            .expect("the rpm binary is required for the specfile-error check");
        let stderr = match String::from_utf8(output.stderr) {
            Ok(stderr) => stderr,
            Err(e) => {
                self.info(out, pkg, Level::Error, "specfile-error", &[&e.to_string()]);
                return;
            }
        };
        for line in stderr.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.contains("warning:") {
                self.info(out, pkg, Level::Warning, "specfile-warning", &[line]);
            } else {
                self.info(out, pkg, Level::Error, "specfile-error", &[line]);
            }
        }
    }

    /// Check `Source`/`Patch` URLs via the spec parser (`_check_invalid_url`).
    /// Uses librpm's `Spec::parse` — the same C parser the reference reaches
    /// through `TransactionSet().parseSpec` — so the expanded source URLs
    /// match.
    fn check_invalid_url(&self, pkg: &SpecPkg, out: &mut Filter) {
        use librpm::build::SpecFlags;
        let spec_file = self.spec_file.as_deref().unwrap_or("");
        let _ = pkg_init();
        let macros = librpm::macro_context::MacroContext::default();
        let _ = macros.define(&format!("_sourcedir {}", self.spec_file_dir()), 0);
        let parsed =
            librpm::build::Spec::parse(spec_file, SpecFlags::ANYARCH | SpecFlags::FORCE, None);
        let _ = macros.pop("_sourcedir");
        let Some(parsed) = parsed else {
            // The reference also reports librpm's error text here, which
            // `Spec::parse` does not surface (ledgered).
            self.info(out, pkg, Level::Error, "specfile-error", &[spec_file]);
            return;
        };
        for src in parsed.sources() {
            // `rpmSpecSrcFilename(src, 1)`: the expanded URL, exactly what
            // the reference's `spec.sources` yields as `url`.
            let url = src.full_path();
            let num = src.num();
            let is_source = src.is_source();
            let tag = format!("{}{num}", if is_source { "Source" } else { "Patch" });
            let (scheme, netloc) = url_scheme_netloc(url);
            if scheme.is_some() && netloc.is_some() {
                continue;
            }
            if is_source && self.tarball_re.is_match(url).unwrap_or(false) {
                let tag = format!("{tag}:");
                self.info(out, pkg, Level::Warning, "invalid-url", &[&tag, url]);
            }
        }
    }

    fn check_line(&mut self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        self.checkline_declarative(line);
        self.checkline_break_space(pkg, out, line);
        if self.checkline_section(pkg, out, line) {
            return;
        }
        self.checkline_buildroot_usage(pkg, out, line);
        self.checkline_make_check(pkg, out, line);
        self.checkline_setup(pkg, out, line);
        self.checkline_autopatch(pkg, out, line);
        self.checkline_patch_applying_macros(pkg, out, line);
        self.checkline_applied_patch(pkg, out, line);
        self.checkline_sourcedir(pkg, out, line);
        self.checkline_configure(pkg, out, line);
        self.checkline_hardcoded_library_path(pkg, out, line);
        self.checkline_mklibname(line);
        self.checkline_package(pkg, out, line);
        self.checkline_changelog(pkg, out, line);
        self.checkline_files(pkg, out, line);
        self.checkline_indent(pkg, line);
        self.checkline_deprecated_grep(pkg, out, line);
        self.checkline_obsolete_tmpfiles_macro(pkg, out, line);
        self.checkline_macros_in_comments(pkg, out, line);
        self.checkline_python_setup_test(pkg, out, line);
        self.checkline_python_setup_install(pkg, out, line);
        self.checkline_python_module_def(pkg, out, line);
        self.checkline_python_sitelib_glob(pkg, out, line);
        self.checkline_shared_dir_glob(pkg, out, line);
        // Before the `%if`/`%endif` depth update below: a `Source:` on the
        // `%if` line itself is not conditional.
        self.checkline_conditional_source_patch(pkg, out, line);

        if self.ifarch_re.is_match(line).unwrap_or(false) {
            self.if_depth += 1;
            self.ifarch_depth = self.if_depth;
        } else if self.if_re.is_match(line).unwrap_or(false) {
            self.if_depth += 1;
        } else if self.endif_re.is_match(line).unwrap_or(false) {
            if self.ifarch_depth == self.if_depth {
                self.ifarch_depth = -1;
            }
            self.if_depth -= 1;
        }
    }

    fn checkline_declarative(&mut self, line: &str) {
        if self.declarative {
            return;
        }
        self.declarative = self.declarative_re.is_match(line).unwrap_or(false);
        if self.declarative {
            // Implicit %prep.
            self.patches_auto_applied = true;
        }
    }

    fn checkline_break_space(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        // Upstream rpmlint#554: NBSP in prose (%description bodies,
        // Summary: tag lines, %changelog entries) is harmless typesetting,
        // not a syntax hazard; flagging it is a false positive. Code and
        // scriptlet sections keep the warning.
        if self.current_section == "description"
            || self.current_section == "changelog"
            || (self.current_section == "package"
                && self.summary_re.is_match(line).unwrap_or(false))
        {
            return;
        }
        if let Some(char) = line.find(NBSP) {
            let detail = format!(
                "line {}, char {}",
                pkg.current_linenum.get().unwrap_or(0),
                char
            );
            self.info(out, pkg, Level::Warning, "non-break-space", &[&detail]);
        }
    }

    /// Warn when a `Source:`/`Patch:` tag sits inside `%if`/`%endif`:
    /// the resulting SRPM can miss the files the spec references
    /// (upstream rpmlint#45). Only the preamble (`package` section)
    /// carries these tags; prose elsewhere may mention them freely.
    /// `%ifos` blocks are not depth-tracked (pre-existing gap), so a
    /// conditional tag inside one is not flagged.
    fn checkline_conditional_source_patch(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.if_depth <= 0 || self.current_section != "package" {
            return;
        }
        let Ok(Some(caps)) = self.source_patch_re.captures(line) else {
            return;
        };
        let tag = format!("{}:", caps.get(1).map(|m| m.as_str()).unwrap_or(""));
        // The spec-line prefix already carries the line number.
        self.info(
            out,
            pkg,
            Level::Warning,
            "conditional-source-or-patch",
            &[&tag],
        );
    }

    fn checkline_section(&mut self, pkg: &SpecPkg, out: &mut Filter, line: &str) -> bool {
        let mut found = None;
        for (sec, re) in &self.section_res {
            if let Ok(Some(m)) = re.find(line) {
                found = Some((sec.clone(), m.end()));
                break;
            }
        }
        let Some((sec, end)) = found else {
            return false;
        };
        self.current_section = sec.clone();
        if sec == "description" {
            self.checkline_translated_description(pkg, out, line);
        }
        *self.section.entry(sec.clone()).or_insert(0) += 1;
        if sec == "package" || sec == "files" {
            let rest = self
                .filelist_re
                .replace_all(&line[end.saturating_sub(1)..], "");
            self.current_package = self
                .pkgname_re
                .captures(rest.as_ref())
                .ok()
                .flatten()
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().to_string());
        }
        if !self.is_lib_pkg && self.lib_package_re.is_match(line).unwrap_or(false) {
            self.is_lib_pkg = true;
        }
        true
    }

    /// Upstream rpmlint#2: a `%description -l <lang>` section carries a
    /// translated description, which some distros don't want to ship.
    fn checkline_translated_description(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.description_lang_re.captures(line) {
            let lang = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            self.info(out, pkg, Level::Warning, "translated-description", &[lang]);
        }
    }

    fn checkline_buildroot_usage(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        let in_scriptlet = RPM_SCRIPTLETS.contains(&self.current_section.as_str())
            || self.current_section == "prep"
            || self.current_section == "build";
        if in_scriptlet && contains_buildroot(line, &self.rpm_buildroot_re) {
            let section = format!("%{}", self.current_section);
            let detail = without_newline(line).trim();
            self.info(
                out,
                pkg,
                Level::Error,
                "rpm-buildroot-usage",
                &[&section, detail],
            );
        }
    }

    fn checkline_make_check(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.make_check_re.is_match(line).unwrap_or(false)
            && !["check", "changelog", "package", "description"]
                .contains(&self.current_section.as_str())
        {
            self.info(
                out,
                pkg,
                Level::Warning,
                "make-check-outside-check-section",
                &[without_newline(line)],
            );
        }
    }

    fn checkline_setup(&mut self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.setup_re.is_match(line).unwrap_or(false) {
            if self.current_section != "prep" {
                self.info(out, pkg, Level::Warning, "setup-not-in-prep", &[]);
            }
            return;
        }
        if let Ok(Some(caps)) = self.autosetup_re.captures(line) {
            let args = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if !self.autosetup_n_re.is_match(args).unwrap_or(false) {
                self.patches_auto_applied = true;
            }
            if self.current_section != "prep" {
                self.info(out, pkg, Level::Warning, "%autosetup-not-in-prep", &[]);
            }
        }
    }

    fn checkline_autopatch(&mut self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.autopatch_re.is_match(line).unwrap_or(false) {
            self.patches_auto_applied = true;
            if self.current_section != "prep" {
                self.info(out, pkg, Level::Warning, "%autopatch-not-in-prep", &[]);
            }
        }
    }

    fn checkline_patch_applying_macros(&mut self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        // Upstream rpmlint#1074: wrapper macros like Fedora's %forgeautosetup
        // apply patches just like %autosetup does. The list lives in the
        // config (PatchApplyingMacros) so distros can extend it; %autosetup
        // and %autopatch keep their dedicated handling above.
        let stripped = line.trim_start();
        let Some(rest) = stripped.strip_prefix('%') else {
            return;
        };
        for name in &self.patch_applying_macros {
            // An empty name would match a bare "%" line and wrongly quiet
            // patch-not-applied; skip it.
            if name.is_empty() {
                continue;
            }
            if let Some(after) = rest.strip_prefix(name.as_str())
                && (after.is_empty() || after.starts_with(char::is_whitespace))
            {
                // Mirror %autosetup: -N means the patches are NOT applied.
                let applies = !self.autosetup_n_re.is_match(after).unwrap_or(false);
                let not_in_prep = self.current_section != "prep";
                let name = name.clone();
                if applies {
                    self.patches_auto_applied = true;
                }
                if not_in_prep {
                    self.info(
                        out,
                        pkg,
                        Level::Warning,
                        &format!("%{name}-not-in-prep"),
                        &[],
                    );
                }
                return;
            }
        }
    }

    fn checkline_applied_patch(&mut self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.applied_patch_re.captures(line) {
            // rpm 4.20 doesn't support %patchN anymore.
            if self.applied_patch_rpm420_re.is_match(line).unwrap_or(false) {
                self.info(out, pkg, Level::Error, "patch-macro-old-format", &[]);
            }
            let pnum: i64 = caps
                .get(1)
                .map(|m| m.as_str())
                .filter(|s| !s.is_empty())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let mut pnums = Vec::new();
            let mut iter = self.applied_patch_p_re.captures_iter(line);
            while let Some(Ok(caps)) = iter.next() {
                if let Some(m) = caps.get(1)
                    && let Ok(n) = m.as_str().parse::<i64>()
                {
                    pnums.push(n);
                }
            }
            if pnums.is_empty() {
                pnums.push(pnum);
            }
            for pnum in pnums {
                self.applied_patches.push(pnum);
            }
            return;
        }
        if let Ok(Some(caps)) = self.applied_patch_pipe_re.captures(line) {
            let pnum: i64 = caps
                .get(1)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            self.applied_patches.push(pnum);
            return;
        }
        if let Ok(Some(caps)) = self.applied_patch_i_re.captures(line) {
            let pnum: i64 = caps
                .get(1)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            self.applied_patches.push(pnum);
        }
    }

    fn checkline_sourcedir(&mut self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.source_dir {
            return;
        }
        if self.source_dir_re.is_match(line).unwrap_or(false) {
            self.source_dir = true;
            self.info(out, pkg, Level::Error, "use-of-RPM_SOURCE_DIR", &[]);
        }
    }

    fn checkline_configure(&mut self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Some(configure_linenum) = self.configure_linenum {
            if self.configure_cmdline.ends_with('\\') {
                self.configure_cmdline.pop();
                self.configure_cmdline.push_str(line.trim());
            } else {
                match self
                    .configure_libdir_spec_re
                    .captures(&self.configure_cmdline)
                    .ok()
                    .flatten()
                {
                    None => {
                        // Report at the line where ./configure started.
                        let real_linenum = pkg.current_linenum.get();
                        pkg.current_linenum.set(Some(configure_linenum));
                        self.info(
                            out,
                            pkg,
                            Level::Warning,
                            "configure-without-libdir-spec",
                            &[],
                        );
                        pkg.current_linenum.set(real_linenum);
                    }
                    Some(caps) => {
                        if let Some(m) = caps.get(1)
                            && let Ok(Some(hc)) =
                                self.hardcoded_libdir_paths_re.captures(m.as_str())
                        {
                            let path = hc.get(1).map(|m| m.as_str()).unwrap_or("");
                            self.info(
                                out,
                                pkg,
                                Level::Error,
                                "hardcoded-library-path",
                                &[path, "in configure options"],
                            );
                        }
                    }
                }
                self.configure_linenum = None;
            }
        }

        let hash_pos = line.find('#');
        if self.current_section != "changelog"
            && let Some(cfg_pos) = line.find("./configure")
            && hash_pos.is_none_or(|h| h > cfg_pos)
        {
            self.configure_linenum = pkg.current_linenum.get();
            self.configure_cmdline = line.trim().to_string();
        }
    }

    fn checkline_hardcoded_library_path(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.current_section == "changelog" {
            return;
        }
        if let Ok(Some(caps)) = self.hardcoded_library_path_re.captures(line) {
            let path = caps.get(1).map(|m| m.as_str().trim_start()).unwrap_or("");
            // Don't check for hardcoded library paths in biarch packages.
            if self.biarch_package_re.is_match(&pkg.name).unwrap_or(false) {
                return;
            }
            if self
                .hardcoded_lib_path_exceptions_re
                .is_match(path)
                .unwrap_or(false)
            {
                return;
            }
            self.info(
                out,
                pkg,
                Level::Error,
                "hardcoded-library-path",
                &["in", path],
            );
        }
    }

    fn checkline_mklibname(&mut self, line: &str) {
        // The reference assigns (not ORs): after the line loop `mklibname`
        // reflects the last line only.
        self.mklibname = line.contains("%mklibname");
    }
}

impl SpecCheck {
    fn checkline_package(&mut self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.current_section != "package" {
            return;
        }
        self.checkline_package_patch(line);
        self.checkline_package_obsolete_tags(pkg, out, line);
        self.checkline_package_buildarch(pkg, out, line);
        self.checkline_package_packager(pkg, out, line);
        self.checkline_package_prefix(pkg, out, line);
        self.checkline_package_suse_prefix(pkg, out, line);
        self.checkline_package_prereq(pkg, out, line);
        self.checkline_package_buildprereq(pkg, out, line);
        self.checkline_package_requires(pkg, out, line);
        self.checkline_package_provides(pkg, out, line);
        self.checkline_package_obsoletes(pkg, out, line);
        self.checkline_package_conflicts(pkg, out, line);
        self.checkline_forbidden_controlchars(pkg, out, line);
        self.check_suse_update_desktop_file(pkg, out, line);
    }

    fn checkline_package_patch(&mut self, line: &str) {
        if let Ok(Some(caps)) = self.patch_re.captures(line) {
            let pnum: i64 = caps
                .get(1)
                .map(|m| m.as_str())
                .filter(|s| !s.is_empty())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let pfile = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
            self.patches.insert(pnum, pfile);
        }
    }

    fn checkline_package_obsolete_tags(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.obsolete_tags_re.captures(line) {
            let tag = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            self.info(out, pkg, Level::Warning, "obsolete-tag", &[tag]);
        }
    }

    fn checkline_package_buildarch(&mut self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.buildarch_re.captures(line) {
            let raw = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            // #1600: a trailing backslash is a line-continuation marker when
            // the tag sits inside a multi-line macro; strip one before
            // comparing so `BuildArch: noarch \` is not reported.
            let arch = raw.strip_suffix('\\').unwrap_or(raw).trim();
            if arch != "noarch" {
                self.info(
                    out,
                    pkg,
                    Level::Error,
                    "buildarch-instead-of-exclusivearch-tag",
                    &[raw],
                );
            } else {
                self.package_noarch
                    .insert(self.current_package.clone(), true);
            }
        }
    }

    fn checkline_package_packager(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.packager_re.captures(line) {
            let value = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            self.info(out, pkg, Level::Warning, "hardcoded-packager-tag", &[value]);
        }
    }

    fn checkline_package_prefix(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.prefix_re.captures(line) {
            let value = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if !value.starts_with('%') {
                self.info(out, pkg, Level::Warning, "hardcoded-prefix-tag", &[value]);
            }
        }
    }

    fn checkline_package_suse_prefix(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.suse_version_re.captures(line) {
            let version: i64 = caps
                .name("version")
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            let detail = version.to_string();
            if version > 0 && version < 1315 {
                self.info(
                    out,
                    pkg,
                    Level::Error,
                    "obsolete-suse-version-check",
                    &[&detail],
                );
            } else if version > 1699 {
                self.info(
                    out,
                    pkg,
                    Level::Error,
                    "invalid-suse-version-check",
                    &[&detail],
                );
            }
        }
    }

    fn checkline_package_prereq(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.prereq_re.captures(line) {
            let value = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            self.info(out, pkg, Level::Error, "prereq-use", &[value]);
        }
    }

    fn checkline_package_buildprereq(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.buildprereq_re.captures(line) {
            let value = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            self.info(out, pkg, Level::Error, "buildprereq-use", &[value]);
        }
    }

    fn checkline_package_requires(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.requires_re.captures(line) {
            let reqs = parse_deps(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
            if let Some(token) = has_forbidden_controlchars_deps(&reqs) {
                let detail = format!("Requires: {token}");
                self.info(
                    out,
                    pkg,
                    Level::Error,
                    "forbidden-controlchar-found",
                    &[&detail],
                );
            }
            for (req, version) in &reqs {
                // Rich expressions contain comparison operators as syntax
                // (`>=` in `(baz >= 1.0 with baz < 2.0)`); the regex would
                // false-positive on them, so they are skipped.
                if version.is_none()
                    && !is_rich_dep_expr(req)
                    && self.compop_re.is_match(req).unwrap_or(false)
                {
                    self.info(
                        out,
                        pkg,
                        Level::Warning,
                        "comparison-operator-in-deptoken",
                        &[req],
                    );
                }
            }
        }
    }

    fn checkline_package_provides(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.provides_re.captures(line) {
            let provs = parse_deps(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
            if let Some(token) = has_forbidden_controlchars_deps(&provs) {
                let detail = format!("Provides: {token}");
                self.info(
                    out,
                    pkg,
                    Level::Error,
                    "forbidden-controlchar-found",
                    &[&detail],
                );
            }
            for (prov, version) in &provs {
                if version.is_none() {
                    // As above: operators inside a rich expression are
                    // syntax, not a comparison in a dep token.
                    if !is_rich_dep_expr(prov) && self.compop_re.is_match(prov).unwrap_or(false) {
                        self.info(
                            out,
                            pkg,
                            Level::Warning,
                            "comparison-operator-in-deptoken",
                            &[prov],
                        );
                    }
                }
            }
        }
    }

    fn checkline_package_obsoletes(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.obsoletes_re.captures(line) {
            let obses = parse_deps(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
            if let Some(token) = has_forbidden_controlchars_deps(&obses) {
                let detail = format!("Obsoletes: {token}");
                self.info(
                    out,
                    pkg,
                    Level::Error,
                    "forbidden-controlchar-found",
                    &[&detail],
                );
            }
            for (obs, version) in &obses {
                if version.is_none() {
                    // As above: operators inside a rich expression are
                    // syntax, not a comparison in a dep token.
                    if !is_rich_dep_expr(obs) && self.compop_re.is_match(obs).unwrap_or(false) {
                        self.info(
                            out,
                            pkg,
                            Level::Warning,
                            "comparison-operator-in-deptoken",
                            &[obs],
                        );
                    }
                }
            }
        }
    }

    fn checkline_package_conflicts(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.conflicts_re.captures(line) {
            let confs = parse_deps(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
            if let Some(token) = has_forbidden_controlchars_deps(&confs) {
                let detail = format!("Conflicts: {token}");
                self.info(
                    out,
                    pkg,
                    Level::Error,
                    "forbidden-controlchar-found",
                    &[&detail],
                );
            }
            for (conf, version) in &confs {
                // As above: operators inside a rich expression are
                // syntax, not a comparison in a dep token.
                if version.is_none()
                    && !is_rich_dep_expr(conf)
                    && self.compop_re.is_match(conf).unwrap_or(false)
                {
                    self.info(
                        out,
                        pkg,
                        Level::Warning,
                        "comparison-operator-in-deptoken",
                        &[conf],
                    );
                }
            }
        }
    }
}

impl SpecCheck {
    fn checkline_changelog(&mut self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.current_section == "changelog" {
            if let Some(token) = has_forbidden_controlchars(line) {
                let detail = format!("%changelog: {token}");
                self.info(
                    out,
                    pkg,
                    Level::Error,
                    "forbidden-controlchar-found",
                    &[&detail],
                );
            }
            if let Ok(matches) = self.macro_re.find_iter(line).collect::<Result<Vec<_>, _>>() {
                for m in matches {
                    let mt = m.as_str();
                    let percents = mt.chars().take_while(|&c| c == '%').count();
                    if percents % 2 == 1 && mt != "%autochangelog" && mt != "%{autochangelog}" {
                        self.info(out, pkg, Level::Warning, "macro-in-%changelog", &[mt]);
                    }
                }
            }
        } else {
            if !self.depscript_override {
                self.depscript_override =
                    self.depscript_override_re.is_match(line).unwrap_or(false);
            }
            if !self.depgen_disabled {
                self.depgen_disabled = self.depgen_disable_re.is_match(line).unwrap_or(false);
            }
            if !self.patch_fuzz_override {
                self.patch_fuzz_override =
                    self.patch_fuzz_override_re.is_match(line).unwrap_or(false);
            }
        }
    }

    fn checkline_files(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.current_section != "files" {
            return;
        }
        let noarch = self
            .package_noarch
            .get(&self.current_package)
            .copied()
            .unwrap_or(false)
            || (!self.package_noarch.contains_key(&self.current_package)
                && self.package_noarch.get(&None).copied().unwrap_or(false));
        if noarch && self.libdir_re.is_match(line).unwrap_or(false) {
            let pkgname = self
                .current_package
                .clone()
                .unwrap_or_else(|| "(main package)".to_string());
            let detail = line.trim_end();
            self.info(
                out,
                pkg,
                Level::Warning,
                "libdir-macro-in-noarch-package",
                &[&pkgname, detail],
            );
        }
    }

    fn checkline_indent(&mut self, pkg: &SpecPkg, line: &str) {
        if self.indent_tabs == 0 && line.contains('\t') {
            self.indent_tabs = pkg.current_linenum.get().unwrap_or(0);
        }
        if self.indent_spaces == 0 && self.indent_spaces_re.is_match(line).unwrap_or(false) {
            self.indent_spaces = pkg.current_linenum.get().unwrap_or(0);
        }
    }

    fn checkline_deprecated_grep(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if ["package", "changelog", "description", "files"].contains(&self.current_section.as_str())
        {
            return;
        }
        let greps: Vec<String> = self
            .deprecated_grep_re
            .find_iter(line)
            .filter_map(|r| r.ok().map(|m| m.as_str().to_string()))
            .collect();
        if !greps.is_empty() {
            // The reference passes the list; `add_info` renders it with the
            // Python `str()` of a string list.
            let detail = format!("['{}']", greps.join("', '"));
            self.info(out, pkg, Level::Warning, "deprecated-grep", &[&detail]);
        }
    }

    /// The `%tmpfiles_create` / `%tmpfiles_create_package` macros have been
    /// no-ops since 2023 (tmpfiles.d entries are created by the systemd
    /// package's file triggers); flag the dead call in scriptlets so
    /// packagers remove it.
    fn checkline_obsolete_tmpfiles_macro(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if !RPM_SCRIPTLETS.contains(&self.current_section.as_str()) {
            return;
        }
        let Ok(Some(m)) = self.tmpfiles_macro_re.captures(line) else {
            return;
        };
        let name = m.get(0).map(|m| m.as_str()).unwrap_or("");
        self.info(out, pkg, Level::Warning, "obsolete-tmpfiles-macro", &[name]);
    }

    fn checkline_macros_in_comments(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        // Quote-aware `#` detection (#1601): a `#` inside shell quotes does
        // not start a comment.
        let Some(hash_pos) = comment_start_pos(line) else {
            return;
        };
        if hash_pos != 0
            && line.as_bytes()[hash_pos - 1] != b' '
            && line.as_bytes()[hash_pos - 1] != b'\t'
        {
            return;
        }
        let comment = &line[hash_pos + 1..];
        // Ignore special comments like #!BuildIgnore.
        if comment.starts_with('!') {
            return;
        }
        if let Ok(matches) = self
            .macro_re
            .find_iter(comment)
            .collect::<Result<Vec<_>, _>>()
        {
            for m in matches {
                let mt = m.as_str();
                let percents = mt.chars().take_while(|&c| c == '%').count();
                if percents % 2 == 1 {
                    self.info(out, pkg, Level::Warning, "macro-in-comment", &[mt]);
                }
            }
        }
    }

    fn checkline_python_setup_test(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.current_section == "check"
            && self.python_setup_test_re.is_match(line).unwrap_or(false)
        {
            self.info(
                out,
                pkg,
                Level::Warning,
                "python-setup-test",
                &[without_newline(line)],
            );
        }
    }

    fn checkline_python_setup_install(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.current_section == "install"
            && self.python_setup_install_re.is_match(line).unwrap_or(false)
        {
            self.info(
                out,
                pkg,
                Level::Warning,
                "python-setup-install",
                &[without_newline(line)],
            );
        }
    }

    fn checkline_python_module_def(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.python_module_def_re.is_match(line).unwrap_or(false) {
            self.info(
                out,
                pkg,
                Level::Warning,
                "python-module-def",
                &[without_newline(line)],
            );
        }
    }

    fn checkline_python_sitelib_glob(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.current_section == "files"
            && self.python_sitelib_glob_re.is_match(line).unwrap_or(false)
        {
            self.info(
                out,
                pkg,
                Level::Warning,
                "python-sitelib-glob-in-files",
                &[without_newline(line)],
            );
        }
    }

    fn checkline_shared_dir_glob(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.current_section == "files"
            && self.shared_dir_glob_re.is_match(line).unwrap_or(false)
        {
            self.info(
                out,
                pkg,
                Level::Warning,
                "shared-dir-glob-in-files",
                &[without_newline(line)],
            );
        }
    }

    fn checkline_forbidden_controlchars(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if has_forbidden_controlchars(line).is_some() {
            self.info(out, pkg, Level::Warning, "forbidden-controlchar-found", &[]);
        }
    }

    fn check_suse_update_desktop_file(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self
            .suse_update_desktop_file_re
            .is_match(line)
            .unwrap_or(false)
        {
            // No migration path for yast yet.
            if pkg.name.to_lowercase().contains("yast") {
                return;
            }
            self.info(
                out,
                pkg,
                Level::Warning,
                "suse-update-desktop-file-deprecated",
                &["%suse_update_desktop_file is deprecated"],
            );
        }
    }
}

impl SpecCheck {
    /// `error_details` for `--explain`, mirroring the `__init__` entry
    /// (`SpecCheck.py:124-126`).
    pub fn register_error_details(_config: &Config, out: &mut Filter) {
        out.set_error_detail(
            "obsolete-tmpfiles-macro",
            "The %tmpfiles_create and %tmpfiles_create_package macros are no-ops: \
             tmpfiles.d entries are created by the systemd package's file triggers \
             at install time. Remove the macro call from the scriptlet."
                .to_string(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;

    fn config_mini() -> Config {
        Config {
            mini_mode: true,
            ..Config::default()
        }
    }

    /// Run `SpecCheck` over `text` as `test.spec`, returning the raw
    /// `(check, rendered line)` pairs. Mini mode keeps the test hermetic
    /// (no `rpm` subprocess, no spec parser).
    fn run_mini(text: &str) -> Vec<(String, String)> {
        run_with(text, &config_mini())
    }

    fn run_with(text: &str, config: &Config) -> Vec<(String, String)> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.spec");
        std::fs::write(&path, text).unwrap();
        let pkg = SpecPkg::open(&path).unwrap();
        let mut check = SpecCheck::new(config);
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        check.check_spec(&pkg, config, &mut out);
        out.results().to_vec()
    }

    fn has(results: &[(String, String)], check: &str) -> bool {
        results.iter().any(|(c, _)| c == check)
    }

    fn lines_for(results: &[(String, String)], check: &str) -> Vec<String> {
        results
            .iter()
            .filter(|(c, _)| c == check)
            .map(|(_, l)| l.clone())
            .collect()
    }

    #[test]
    fn comment_start_pos_cases_from_1601() {
        // (line, expected byte position of `#`, None when no comment start)
        let cases: &[(&str, Option<usize>)] = &[
            ("# comment with %{macro}", Some(0)),
            ("cmd arg # comment with %{macro}", Some(8)),
            ("sed -i 'a #text %{macro}' file", None),
            ("echo \"quoted #text %{macro}\"", None),
            ("echo 'single #text %{macro}'", None),
            ("echo it\\'s # comment %{macro}", Some(11)),
            ("echo \"a\\\"b\" # comment %{macro}", Some(12)),
            ("no hash here", None),
            ("#!BuildIgnore: %{macro}", Some(0)),
        ];
        for (line, expected) in cases {
            assert_eq!(comment_start_pos(line), *expected, "line: {line}");
        }
    }

    #[test]
    fn buildarch_noarch_with_continuation_backslash_is_quiet_1600() {
        let results = run_mini("Name: foo\nBuildArch: noarch \\\n");
        assert!(
            !has(&results, "buildarch-instead-of-exclusivearch-tag"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn prefix_macro_value_is_quiet_35() {
        // Upstream #35 asked for a warning on literally any `Prefix:`,
        // but maintainer scop declined in r1462: a macro value is not
        // hardcoded. The port matches the reference: only non-macro
        // values warn.
        let results = run_mini("Name: foo\nPrefix: %{_prefix}\n");
        assert!(
            !has(&results, "hardcoded-prefix-tag"),
            "unexpected: {results:?}"
        );

        let results = run_mini("Name: foo\nPrefix: /opt/foo\n");
        let lines = lines_for(&results, "hardcoded-prefix-tag");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "test.spec:2: W: hardcoded-prefix-tag /opt/foo");
    }

    #[test]
    fn buildarch_real_arch_still_errors() {
        let results = run_mini("Name: foo\nBuildArch: x86_64\n");
        let lines = lines_for(&results, "buildarch-instead-of-exclusivearch-tag");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("E: buildarch-instead-of-exclusivearch-tag x86_64"));
    }

    #[test]
    fn macro_in_shell_quotes_is_not_a_comment_1601() {
        let results = run_mini("Name: foo\n%prep\nsed -i 's/#%{version}//' file\n");
        assert!(
            !has(&results, "macro-in-comment"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn macro_in_real_comment_still_warns() {
        let results = run_mini("Name: foo\n# a comment with %{version} inside\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("W: macro-in-comment %{version}"));
    }

    #[test]
    fn obsolete_suse_version_check_fires() {
        let results = run_mini("Name: foo\n%if %{?suse_version} < 1314\n%endif\n");
        let lines = lines_for(&results, "obsolete-suse-version-check");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("E: obsolete-suse-version-check 1314"));
    }

    #[test]
    fn invalid_suse_version_check_fires() {
        let results = run_mini("Name: foo\n%if %{?suse_version} > 1700\n%endif\n");
        let lines = lines_for(&results, "invalid-suse-version-check");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("E: invalid-suse-version-check 1700"));
    }

    // Upstream rpmlint#554: NBSP in prose is not a syntax hazard.
    #[test]
    fn nbsp_in_description_is_quiet() {
        let results = run_mini("Name: foo\n%description\nhot\u{a0} latte\n");
        assert!(!has(&results, "non-break-space"), "unexpected: {results:?}");
    }

    #[test]
    fn nbsp_in_summary_is_quiet() {
        let results = run_mini("Name: foo\nSummary: hot\u{a0} latte\n");
        assert!(!has(&results, "non-break-space"), "unexpected: {results:?}");
    }

    #[test]
    fn nbsp_in_changelog_is_quiet() {
        let results = run_mini("Name: foo\n%changelog\n* Wed hot\u{a0} latte\n");
        assert!(!has(&results, "non-break-space"), "unexpected: {results:?}");
    }

    #[test]
    fn nbsp_in_scriptlet_still_warns() {
        // The relaxation is prose-only: a NBSP in a code section is still a
        // syntax hazard, so the check must still fire there.
        let results = run_mini("Name: foo\n%prep\nhot\u{a0} latte\n");
        let lines = lines_for(&results, "non-break-space");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("W: non-break-space line 3, char 3"));
    }

    #[test]
    fn nbsp_on_summary_keyword_line_only() {
        // A bare word "Summary" elsewhere is not a tag line.
        let results = run_mini("Name: foo\n%prep\necho Summary\u{a0} here\n");
        assert!(has(&results, "non-break-space"), "missing: {results:?}");
    }

    #[test]
    fn nbsp_summary_prefixed_code_line_still_warns() {
        // A `Summary:`-prefixed line in %prep is code, not a tag line:
        // the prose exemption must not silence it.
        let results = run_mini("Name: foo\n%prep\nSummary: hot\u{a0} latte\n");
        assert!(has(&results, "non-break-space"), "missing: {results:?}");
    }

    // Upstream rpmlint#45: conditional Source:/Patch: tags.
    #[test]
    fn conditional_source_warns() {
        let results = run_mini("Name: foo\n%if 0%{?suse_version}\nSource0: a.tar.gz\n%endif\n");
        let lines = lines_for(&results, "conditional-source-or-patch");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("W: conditional-source-or-patch Source0:"));
    }

    #[test]
    fn conditional_patch_warns() {
        let results = run_mini("Name: foo\n%ifarch x86_64\nPatch1: b.patch\n%endif\n");
        let lines = lines_for(&results, "conditional-source-or-patch");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("W: conditional-source-or-patch Patch1:"));
    }

    #[test]
    fn unconditional_source_is_quiet() {
        let results = run_mini("Name: foo\nSource0: a.tar.gz\n");
        assert!(
            !has(&results, "conditional-source-or-patch"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn source_after_endif_is_quiet() {
        let results = run_mini("Name: foo\n%if 0\n%endif\nSource0: a.tar.gz\n");
        assert!(
            !has(&results, "conditional-source-or-patch"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn source_word_in_description_is_quiet() {
        // Only the preamble carries Source:/Patch: tags; prose mentioning
        // them must not warn.
        let results = run_mini("Name: foo\n%description\n%if 0\nSource0: a.tar.gz\n%endif\n");
        assert!(
            !has(&results, "conditional-source-or-patch"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn suse_version_boundaries_are_quiet() {
        // 0, 1315 and 1699 hit neither check (`version > 0`, `< 1315`,
        // `> 1699` in the reference).
        for v in [0, 1315, 1699] {
            let results = run_mini(&format!(
                "Name: foo\n%if %{{?suse_version}} == {v}\n%endif\n"
            ));
            assert!(
                !has(&results, "obsolete-suse-version-check"),
                "{v}: {results:?}"
            );
            assert!(
                !has(&results, "invalid-suse-version-check"),
                "{v}: {results:?}"
            );
        }
    }

    #[test]
    fn suse_version_braced_form_is_checked() {
        // Deliberate improvement over the reference: its `%({\?)?suse_version}?`
        // misses the common `%{suse_version}` form; we match it too.
        let results = run_mini("Name: foo\n%if %{suse_version} < 1000\n%endif\n");
        assert!(has(&results, "obsolete-suse-version-check"), "{results:?}");
    }

    #[test]
    fn fixture_exercising_major_checks() {
        let config = config_mini();
        let spec = r#"Name:           wobble
Version:        1.0
Release:        1
Summary:        Wobble
License:        MIT
Group:          Not/A/Group
Source0:        wobble-1.0.tar.gz
Patch0:         fix-it.patch
Patch1:         another.patch
BuildArch:      x86_64
BuildRoot:      /var/tmp/wobble
Packager:       somebody
Prefix:         /opt/wobble
Requires:       foo<bar
Provides:       wobble-cap
BuildRequires:  update-desktop-files

%description
Wobble.

%prep
%setup -q
%patch -P 0 -p1

%build
./configure
make

%install
make install

%files
%{_bindir}/*

%changelog
"#;
        let results = run_with(spec, &config);
        for check in [
            "buildarch-instead-of-exclusivearch-tag",
            "hardcoded-packager-tag",
            "hardcoded-prefix-tag",
            "comparison-operator-in-deptoken",
            "suse-update-desktop-file-deprecated",
            "no-%check-section",
            "configure-without-libdir-spec",
            "shared-dir-glob-in-files",
            "patch-not-applied",
        ] {
            assert!(has(&results, check), "missing {check}: {results:?}");
        }
        // Patch0 applied via `%patch -P 0`; Patch1 never applied.
        let not_applied = lines_for(&results, "patch-not-applied");
        assert_eq!(not_applied.len(), 1);
        assert!(
            not_applied[0].contains("Patch1:"),
            "line: {}",
            not_applied[0]
        );
    }

    #[test]
    fn codequery_spec_matches_captured_reference() {
        let input =
            include_str!("../../../../tests/parity/cases/codequery-spec/input/codequery.spec");
        let results = run_with(input, &Config::default());
        let summary: Vec<(&str, &str)> = results
            .iter()
            .map(|(c, l)| {
                let level = if l.contains(": E: ") { "E" } else { "W" };
                (c.as_str(), level)
            })
            .collect();
        for (check, level) in [
            ("suse-update-desktop-file-deprecated", "W"),
            ("superfluous-%clean-section", "E"),
            ("specfile-warning", "W"),
            ("no-%check-section", "W"),
            ("macro-in-comment", "W"),
            ("invalid-url", "W"),
        ] {
            assert!(
                summary.contains(&(check, level)),
                "missing {level}: {check} in {summary:?}"
            );
        }
        let invalid = lines_for(&results, "invalid-url");
        assert_eq!(invalid.len(), 1);
        assert!(
            invalid[0].contains("W: invalid-url Source0: codequery-0.08.tar.gz"),
            "line: {}",
            invalid[0]
        );
        let warning = lines_for(&results, "specfile-warning");
        assert_eq!(warning.len(), 1);
        assert!(
            warning[0].contains("Macro expanded in comment on line 20"),
            "line: {}",
            warning[0]
        );
        let comment = lines_for(&results, "macro-in-comment");
        assert_eq!(comment.len(), 1);
        assert!(
            comment[0].contains(":20: W: macro-in-comment %{version}"),
            "line: {}",
            comment[0]
        );
    }

    #[test]
    fn url_scheme_netloc_splits_scheme_correctly() {
        assert_eq!(
            url_scheme_netloc("https://example.com/foo.tar.gz"),
            (Some("https"), Some("example.com"))
        );
        assert_eq!(url_scheme_netloc("codequery-0.08.tar.gz"), (None, None));
        assert_eq!(
            url_scheme_netloc("obs://build/foo"),
            (Some("obs"), Some("build"))
        );
    }

    /// A missing `rpm` must not abort the run. `rpm` is only needed by
    /// `check_specfile_error`, and the reference gates that on there being a
    /// spec file (SpecCheck.py:224-227), so a binary-only lint never reaches
    /// it. Constructing SpecCheck in an empty tool dir used to panic.
    #[test]
    fn spec_check_constructs_without_rpm() {
        let empty = tempfile::TempDir::new().expect("tmpdir");
        let config = Config::default();
        let mut check = SpecCheck::with_tool_dir(&config, Some(empty.path()));
        let spec_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/codequery-0.08.tar.gz");
        if !spec_path.is_file() {
            return; // fixture absent; nothing to assert
        }
        let pkg = SpecPkg::open(&spec_path).expect("spec opens");
        let mut filter = Filter::new(&config, Color::for_tty(false)).unwrap();
        // No panic, and no finding invented from the absent tool.
        check.check_spec(&pkg, &config, &mut filter);
        assert!(
            !filter.results().iter().any(|(n, _)| n == "spec-file-error"),
            "absent rpm should skip rather than fabricate: {:?}",
            filter.results()
        );
    }
    // ---- Cannibalized reference emission tests (test_speccheck.py) ----
    //
    // Each pins a per-finding emission the reference tests but the port
    // left unpinned, with hand-built specs. The `refNNN` suffix is the
    // test_speccheck.py line number at pinned 84848c05.

    /// Write raw `bytes` as `test.spec` and run `SpecCheck` over it, for
    /// inputs that are not valid UTF-8.
    fn run_mini_bytes(bytes: &[u8]) -> Vec<(String, String)> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.spec");
        std::fs::write(&path, bytes).unwrap();
        let config = config_mini();
        let pkg = SpecPkg::open(&path).unwrap();
        let mut check = SpecCheck::new(&config);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_spec(&pkg, &config, &mut out);
        out.results().to_vec()
    }

    /// Drive `check_source` over a synthetic source package: the header of
    /// a real fixture RPM with the file list replaced by `files`.
    fn run_source(files: Vec<crate::pkg::pkgfile::PkgFile>) -> Vec<(String, String)> {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/w6-tmpfiles-1.0-1.noarch.rpm");
        let config = config_mini();
        let mut pkg = Pkg::open_no_extract(&fixture).expect("open fixture header");
        pkg.files = files;
        let mut check = SpecCheck::new(&config);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_source(&pkg, &config, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn no_spec_file_fires_error_ref88() {
        let results = run_source(vec![]);
        let lines = lines_for(&results, "no-spec-file");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(lines[0].contains("E: no-spec-file"), "line: {}", lines[0]);
    }

    #[test]
    fn invalid_spec_name_fires_error_ref106() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mismatched.spec");
        std::fs::write(&path, "Name: foo\n").unwrap();
        let results = run_source(vec![crate::pkg::pkgfile::PkgFile {
            name: "mismatched.spec".to_string(),
            path: path.to_string_lossy().to_string(),
            ..Default::default()
        }]);
        let lines = lines_for(&results, "invalid-spec-name");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("E: invalid-spec-name"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn non_utf8_spec_file_fires_error_ref126() {
        let results = run_mini_bytes(b"Name: foo\nSummary: na\xefve\n");
        let lines = lines_for(&results, "non-utf8-spec-file");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("E: non-utf8-spec-file"),
            "line: {}",
            lines[0]
        );
        // A clean spec stays quiet.
        let clean = run_mini("Name: foo\n");
        assert!(!has(&clean, "non-utf8-spec-file"), "results: {clean:?}");
    }

    #[test]
    fn nbsp_in_summary_quiet_ref144() {
        // Deliberate divergence from the frozen 2.10.0 reference (upstream
        // rpmlint#554, ledgered): a non-breaking space in a `Summary:` tag
        // line is harmless prose typesetting, not a syntax hazard, so the
        // port stays quiet where the reference warns.
        let results = run_mini("Name: foo\nSummary: bar\u{a0}baz\n");
        let lines = lines_for(&results, "non-break-space");
        assert!(lines.is_empty(), "results: {results:?}");
    }

    #[test]
    fn deprecated_grep_fires_warning_ref803() {
        let results = run_mini("Name: foo\n%build\negrep foo\n");
        let lines = lines_for(&results, "deprecated-grep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: deprecated-grep ['egrep']"),
            "line: {}",
            lines[0]
        );
        // `grep -E` is the sanctioned spelling.
        let clean = run_mini("Name: foo\n%build\ngrep -E foo\n");
        assert!(!has(&clean, "deprecated-grep"), "results: {clean:?}");
    }

    #[test]
    fn obsolete_tmpfiles_macro_fires_in_post() {
        let results = run_mini("Name: foo\n%post\n%tmpfiles_create_package\n");
        let lines = lines_for(&results, "obsolete-tmpfiles-macro");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: obsolete-tmpfiles-macro %tmpfiles_create_package"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn obsolete_tmpfiles_macro_short_form_fires() {
        let results = run_mini("Name: foo\n%post\n%tmpfiles_create\n");
        let lines = lines_for(&results, "obsolete-tmpfiles-macro");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: obsolete-tmpfiles-macro %tmpfiles_create"),
            "line: {}",
            lines[0]
        );
        // The longer macro must not be truncated to its prefix.
        assert!(
            !lines[0].contains("tmpfiles_create_package"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn obsolete_tmpfiles_macro_braced_form_fires() {
        let results = run_mini("Name: foo\n%post\n%{tmpfiles_create}\n");
        let lines = lines_for(&results, "obsolete-tmpfiles-macro");
        assert_eq!(lines.len(), 1, "results: {results:?}");
    }

    #[test]
    fn obsolete_tmpfiles_macro_braced_package_form_fires() {
        let results = run_mini("Name: foo\n%post\n%{tmpfiles_create_package}\n");
        let lines = lines_for(&results, "obsolete-tmpfiles-macro");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: obsolete-tmpfiles-macro %{tmpfiles_create_package}"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn obsolete_tmpfiles_macro_outside_scriptlet_is_quiet() {
        // A mention in prose is not a scriptlet call.
        let results = run_mini("Name: foo\n%description\nUses %tmpfiles_create_package.\n");
        assert!(
            !has(&results, "obsolete-tmpfiles-macro"),
            "results: {results:?}"
        );
    }

    #[test]
    fn obsolete_tmpfiles_macro_has_description() {
        let config = config_mini();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        SpecCheck::register_error_details(&config, &mut out);
        let text = out.get_description("obsolete-tmpfiles-macro", &config);
        assert!(
            text.contains("no-ops") && text.contains("file triggers"),
            "description: {text:?}"
        );
    }

    #[test]
    fn libdir_macro_in_noarch_package_fires_warning_ref781() {
        let results = run_mini("Name: foo\nBuildArch: noarch\n%files\n%{_libdir}/foo\n");
        let lines = lines_for(&results, "libdir-macro-in-noarch-package");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: libdir-macro-in-noarch-package (main package) %{_libdir}/foo"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn mixed_use_of_spaces_and_tabs_fires_warning_ref1043() {
        // Mirrors the reference fixture: tabs after the colon, spaces
        // aligning the Version value.
        let results = run_mini("Name:\tfoo\nVersion:        1.0\n");
        let lines = lines_for(&results, "mixed-use-of-spaces-and-tabs");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: mixed-use-of-spaces-and-tabs (spaces: line 2, tab: line 1)"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn patch_macro_old_format_fires_error_ref1098() {
        let results = run_mini("Name: foo\n%prep\n%patch1\n");
        let lines = lines_for(&results, "patch-macro-old-format");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("E: patch-macro-old-format"),
            "line: {}",
            lines[0]
        );
        // The modern `%patch -P N` spelling stays quiet.
        let modern = run_mini("Name: foo\nPatch1: Patch1.patch\n%prep\n%patch -P 1\n");
        assert!(
            !has(&modern, "patch-macro-old-format"),
            "results: {modern:?}"
        );
    }

    #[test]
    fn forgeautosetup_counts_as_patch_applying_ref1074() {
        // Upstream rpmlint#1074: %forgeautosetup wraps %autosetup, so patches
        // are deemed applied and patch-not-applied stays quiet. (The shipped
        // default lists it in PatchApplyingMacros; the test config inserts
        // the key explicitly because Config::default() carries no table.)
        let mut config = config_mini();
        config.configuration.insert(
            "PatchApplyingMacros".into(),
            toml::Value::Array(vec![toml::Value::String("forgeautosetup".into())]),
        );
        let results = run_with(
            "Name: foo
Patch0: foo.patch
%prep
%forgeautosetup
%build
",
            &config,
        );
        let quiet = lines_for(&results, "patch-not-applied");
        assert!(quiet.is_empty(), "results: {results:?}");
        // Without any patch-applying macro the finding still fires, with
        // name, level and detail pinned.
        let bare = run_mini(
            "Name: foo
Patch0: foo.patch
%prep
%build
",
        );
        let lines = lines_for(&bare, "patch-not-applied");
        assert_eq!(lines.len(), 1, "results: {bare:?}");
        assert!(
            lines[0].contains("W: patch-not-applied Patch0:"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn patch_applying_macros_list_is_config_extensible() {
        // A distro-specific wrapper added to PatchApplyingMacros is honored.
        let mut config = config_mini();
        config.configuration.insert(
            "PatchApplyingMacros".into(),
            toml::Value::Array(vec![toml::Value::String("myapplypatches".into())]),
        );
        let results = run_with(
            "Name: foo
Patch0: foo.patch
%prep
%myapplypatches
%build
",
            &config,
        );
        let quiet = lines_for(&results, "patch-not-applied");
        assert!(quiet.is_empty(), "results: {results:?}");
    }

    #[test]
    fn patch_applying_macro_dash_n_means_not_applied_ref1074() {
        // Mirror %autosetup: -N means the patches are NOT applied, so the
        // finding fires even though the wrapper macro is present.
        let mut config = config_mini();
        config.configuration.insert(
            "PatchApplyingMacros".into(),
            toml::Value::Array(vec![toml::Value::String("forgeautosetup".into())]),
        );
        let results = run_with(
            "Name: foo
Patch0: foo.patch
%prep
%forgeautosetup -N
%build
",
            &config,
        );
        let lines = lines_for(&results, "patch-not-applied");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: patch-not-applied Patch0:"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn empty_patch_applying_macro_name_is_ignored_ref1074() {
        // A [""] entry must not let a bare "%" line suppress the finding.
        let mut config = config_mini();
        config.configuration.insert(
            "PatchApplyingMacros".into(),
            toml::Value::Array(vec![toml::Value::String("".into())]),
        );
        let results = run_with(
            "Name: foo
Patch0: foo.patch
%prep
%
%build
",
            &config,
        );
        let lines = lines_for(&results, "patch-not-applied");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: patch-not-applied Patch0:"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn patch_applying_macro_outside_prep_warns_ref1074() {
        // Mirror %autopatch: the wrapper outside %prep warns (with its own
        // name in the finding) while still counting the patches as applied.
        let mut config = config_mini();
        config.configuration.insert(
            "PatchApplyingMacros".into(),
            toml::Value::Array(vec![toml::Value::String("forgeautosetup".into())]),
        );
        let results = run_with(
            "Name: foo
Patch0: foo.patch
%prep
%build
%forgeautosetup
",
            &config,
        );
        let lines = lines_for(&results, "%forgeautosetup-not-in-prep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: %forgeautosetup-not-in-prep"),
            "line: {}",
            lines[0]
        );
        let quiet = lines_for(&results, "patch-not-applied");
        assert!(quiet.is_empty(), "results: {results:?}");
    }

    #[test]
    fn macro_in_changelog_fires_warning_ref739() {
        let results = run_mini("Name: foo\n%changelog\nYou have a %buildroot macro\n");
        let lines = lines_for(&results, "macro-in-%changelog");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: macro-in-%changelog %buildroot"),
            "line: {}",
            lines[0]
        );
        // `%autochangelog` is explicitly exempt.
        let auto = run_mini("Name: foo\n%changelog\n%autochangelog\n");
        assert!(!has(&auto, "macro-in-%changelog"), "results: {auto:?}");
    }

    #[test]
    fn more_than_one_changelog_section_fires_warning_ref937() {
        let results = run_mini(
            "Name: foo\n%changelog\n* Tue Jan 1 2020 A\n- x\n%changelog\n* Wed Jan 2 2020 B\n- y\n",
        );
        let lines = lines_for(&results, "more-than-one-%changelog-section");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: more-than-one-%changelog-section"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn missing_mandatory_sections_fire_warnings() {
        let results = run_mini("Name: foo\nVersion: 1.0\n%description\nfoo\n");
        for check in [
            "no-%prep-section",
            "no-%build-section",
            "no-%install-section",
            "no-%check-section",
        ] {
            let lines = lines_for(&results, check);
            assert_eq!(lines.len(), 1, "missing {check}: {results:?}");
            assert!(
                lines[0].contains(&format!("W: {check}")),
                "line: {}",
                lines[0]
            );
        }
    }

    #[test]
    fn present_sections_do_not_fire() {
        let results = run_mini(
            "Name: foo\nVersion: 1.0\n%description\nfoo\n%prep\n%build\n%install\n%check\n%files\n%changelog\n",
        );
        for check in [
            "no-%prep-section",
            "no-%build-section",
            "no-%install-section",
            "no-%check-section",
        ] {
            assert!(!has(&results, check), "unexpected {check}: {results:?}");
        }
    }

    #[test]
    fn declarative_build_skips_section_warnings() {
        let results = run_mini("Name: foo\nVersion: 1.0\nBuildSystem: cargo\n%description\nfoo\n");
        for check in [
            "no-%prep-section",
            "no-%build-section",
            "no-%install-section",
            "no-%check-section",
        ] {
            assert!(!has(&results, check), "unexpected {check}: {results:?}");
        }
    }

    #[test]
    fn missing_section_descriptions_resolve() {
        let config = config_mini();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.spec");
        std::fs::write(&path, "Name: foo\n").unwrap();
        let pkg = SpecPkg::open(&path).unwrap();
        let mut check = SpecCheck::new(&config);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_spec(&pkg, &config, &mut out);
        for id in [
            "no-%prep-section",
            "no-%build-section",
            "no-%install-section",
        ] {
            let detail = out.get_description(id, &config);
            assert!(
                !detail.contains("Unknown message"),
                "no --explain description for {id}"
            );
            assert!(!detail.trim().is_empty(), "empty description for {id}");
        }
    }

    #[test]
    fn lib_package_without_mklibname_fires_error_ref959() {
        let results = run_mini("Name: foo\n%package -n libfoo\n%description\nfoo\n");
        let lines = lines_for(&results, "lib-package-without-%mklibname");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("E: lib-package-without-%mklibname"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn depscript_without_disabling_depgen_fires_warning_ref980() {
        let results = run_mini("Name: foo\n%define __find_provides /bin/true\n");
        let lines = lines_for(&results, "depscript-without-disabling-depgen");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: depscript-without-disabling-depgen"),
            "line: {}",
            lines[0]
        );
        let disabled = run_mini(
            "Name: foo\n%define _use_internal_dependency_generator 0\n%define __find_provides /bin/true\n",
        );
        assert!(
            !has(&disabled, "depscript-without-disabling-depgen"),
            "results: {disabled:?}"
        );
    }

    #[test]
    fn patch_fuzz_is_changed_fires_warning_ref1013() {
        let results = run_mini("Name: foo\n%define _default_patch_fuzz 2\n");
        let lines = lines_for(&results, "patch-fuzz-is-changed");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: patch-fuzz-is-changed"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn python_setup_test_fires_warning_ref1164() {
        let results = run_mini("Name: foo\n%check\n%python_exec setup.py test\n");
        let lines = lines_for(&results, "python-setup-test");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: python-setup-test %python_exec setup.py test"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn python_setup_install_fires_warning_ref1177() {
        // Mirrors the reference fixtures: `setup.py install` and the
        // `%py*_install` macro spellings.
        for cmd in [
            "python3 setup.py install",
            "%python_install",
            "%python3_install",
            "%python312_install",
            "%py3_install",
        ] {
            let results = run_mini(&format!("Name: foo\n%install\n{cmd}\n"));
            let lines = lines_for(&results, "python-setup-install");
            assert_eq!(lines.len(), 1, "for {cmd}: {results:?}");
            assert!(
                lines[0].contains(&format!("W: python-setup-install {cmd}")),
                "line: {}",
                lines[0]
            );
        }
    }

    #[test]
    fn python_module_def_fires_warning_ref1189() {
        let results =
            run_mini("Name: foo\n%{?!python_module:%define python_module() python-%{**}}\n");
        let lines = lines_for(&results, "python-module-def");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: python-module-def"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn python_sitelib_glob_in_files_fires_warning_ref1216() {
        let results = run_mini("Name: foo\n%files\n%{python_sitelib}/*\n");
        let lines = lines_for(&results, "python-sitelib-glob-in-files");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: python-sitelib-glob-in-files"),
            "line: {}",
            lines[0]
        );
        // The bare macro (no glob) stays quiet.
        let plain = run_mini("Name: foo\n%files\n%{python_sitelib}\n");
        assert!(
            !has(&plain, "python-sitelib-glob-in-files"),
            "results: {plain:?}"
        );
    }

    #[test]
    fn make_check_outside_check_section_ref205() {
        // Fires in %build...
        let outside = run_mini("Name: foo\n%build\nmake check\n");
        let lines = lines_for(&outside, "make-check-outside-check-section");
        assert_eq!(lines.len(), 1, "results: {outside:?}");
        assert!(
            lines[0].contains("W: make-check-outside-check-section"),
            "line: {}",
            lines[0]
        );
        // ...but not inside %check, and not when absent.
        let inside = run_mini("Name: foo\n%check\nmake check\n");
        assert!(
            !has(&inside, "make-check-outside-check-section"),
            "results: {inside:?}"
        );
        let absent = run_mini("Name: foo\n%build\nmake\n");
        assert!(
            !has(&absent, "make-check-outside-check-section"),
            "results: {absent:?}"
        );
    }

    #[test]
    fn use_of_rpm_source_dir_fires_error_ref357() {
        let results = run_mini("Name: foo\n%build\necho $RPM_SOURCE_DIR\n");
        let lines = lines_for(&results, "use-of-RPM_SOURCE_DIR");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("E: use-of-RPM_SOURCE_DIR"),
            "line: {}",
            lines[0]
        );
        // The macro form is the same finding.
        let macro_form = run_mini("Name: foo\n%build\necho %{_sourcedir}\n");
        assert!(
            has(&macro_form, "use-of-RPM_SOURCE_DIR"),
            "results: {macro_form:?}"
        );
    }

    #[test]
    fn hardcoded_library_path_fires_error_ref401() {
        let results = run_mini("Name: foo\n%description\n/usr/lib\n");
        let lines = lines_for(&results, "hardcoded-library-path");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("E: hardcoded-library-path in /usr/lib"),
            "line: {}",
            lines[0]
        );
        // The macro form stays quiet.
        let ok = run_mini("Name: foo\n%description\n%{_libdir}/foo\n");
        assert!(!has(&ok, "hardcoded-library-path"), "results: {ok:?}");
    }

    #[test]
    fn obsolete_tag_fires_warning_ref423() {
        let results = run_mini("Name: foo\nSerial: 2\nCopyright: Something\n");
        let lines = lines_for(&results, "obsolete-tag");
        assert_eq!(lines.len(), 2, "results: {results:?}");
        assert!(
            lines.iter().any(|l| l.contains("W: obsolete-tag 2")),
            "lines: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("W: obsolete-tag Something")),
            "lines: {lines:?}"
        );
    }

    #[test]
    fn translated_description_section_warns_2() {
        // Upstream rpmlint#2: real emission path (check_spec -> add_info);
        // the rendered line pins name, level and detail together.
        let text = "Name: foo\nVersion: 1\nRelease: 1\nSummary: foo\nLicense: MIT\n\n%description -l fi\nKuvaus.\n\n%description\nPlain.\n";
        let results = run_mini(text);
        let line = results
            .iter()
            .find(|(c, _)| c == "translated-description")
            .map(|(_, l)| l.clone())
            .expect("translated-description should fire");
        assert!(
            line.contains("W: translated-description fi"),
            "name, level and detail must render, got: {line}"
        );
        assert_eq!(
            results
                .iter()
                .filter(|(c, _)| c == "translated-description")
                .count(),
            1,
            "only the -l section warns: {results:?}"
        );
    }

    #[test]
    fn prereq_use_fires_error_ref529() {
        let results = run_mini("Name: foo\nPreReq(pre): none\nPreReq(post): none_other\n");
        let lines = lines_for(&results, "prereq-use");
        assert_eq!(lines.len(), 2, "results: {results:?}");
        assert!(
            lines[0].contains("E: prereq-use none"),
            "line: {}",
            lines[0]
        );
        assert!(
            lines[1].contains("E: prereq-use none_other"),
            "line: {}",
            lines[1]
        );
    }

    #[test]
    fn plain_description_section_is_quiet_2() {
        let text = "Name: foo\nVersion: 1\nRelease: 1\nSummary: foo\nLicense: MIT\n\n%description\nPlain.\n";
        let results = run_mini(text);
        assert!(
            !has(&results, "translated-description"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn buildprereq_use_fires_error_ref562() {
        let results = run_mini("Name: foo\nBuildPreReq: Something\n");
        let lines = lines_for(&results, "buildprereq-use");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("E: buildprereq-use Something"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn rpm_buildroot_usage_fires_error_ref164() {
        let results = run_mini("Name: foo\n%prep\necho $RPM_BUILD_ROOT\n");
        let lines = lines_for(&results, "rpm-buildroot-usage");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("E: rpm-buildroot-usage %prep echo $RPM_BUILD_ROOT"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn rpm_buildroot_usage_shell_var_escapes_stay_quiet_ref194() {
        // Mirrors test_speccheck.py:194: escaped, double-escaped and
        // commented references in %prep are not real uses; the two in
        // %build are.
        let spec = "Name: foo\n\
            %description\n\
            $RPM_BUILD_ROOT should not be touched during %build or %prep stage, as it\n\
            may break short circuit builds.\n\
            \n\
            %prep\n\
            # None of these actually refer to the build root\n\
            \\$RPM_BUILD_ROOT\n\
            \\\\\\$RPM_BUILD_ROOT\n\
            # $RPM_BUILD_ROOT\n\
            \n\
            %build\n\
            \\\\$RPM_BUILD_ROOT\n\
            echo ${RPM_BUILD_ROOT} # comment\n";
        let results = run_mini(spec);
        let lines = lines_for(&results, "rpm-buildroot-usage");
        assert_eq!(lines.len(), 2, "results: {results:?}");
        assert!(
            lines.iter().all(|l| l.contains("%build")),
            "lines: {lines:?}"
        );
    }

    #[test]
    fn description_lang_glued_to_dash_l_is_quiet_2() {
        // `%description -lfi` is not the `-l <lang>` flag form.
        let text = "Name: foo\nVersion: 1\nRelease: 1\nSummary: foo\nLicense: MIT\n\n%description -lfi\nKuvaus.\n";
        let results = run_mini(text);
        assert!(
            !has(&results, "translated-description"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn translated_description_has_explain_text() {
        // Port-only finding (upstream rpmlint#2): --explain must describe it,
        // not print "Unknown message".
        let text = "Name: foo\nVersion: 1\nRelease: 1\nSummary: foo\nLicense: MIT\n\n%description -l fi\nKuvaus.\n\n%description\nPlain.\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.spec");
        std::fs::write(&path, text).unwrap();
        let pkg = SpecPkg::open(&path).unwrap();
        let config = config_mini();
        let mut check = SpecCheck::new(&config);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_spec(&pkg, &config, &mut out);
        assert!(
            out.results()
                .iter()
                .any(|(c, _)| c == "translated-description"),
            "finding must fire"
        );
        let desc = out.get_description("translated-description", &config);
        assert!(
            desc.contains("translated description"),
            "explain text missing, got: {desc:?}"
        );
    }

    #[test]
    fn conditional_source_or_patch_has_explain_text() {
        // Port-only finding (upstream rpmlint#45): --explain must describe it,
        // not print "Unknown message".
        let text = "Name: foo\n%if 0%{?suse_version}\nSource0: a.tar.gz\n%endif\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.spec");
        std::fs::write(&path, text).unwrap();
        let pkg = SpecPkg::open(&path).unwrap();
        let config = config_mini();
        let mut check = SpecCheck::new(&config);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_spec(&pkg, &config, &mut out);
        assert!(
            out.results()
                .iter()
                .any(|(c, _)| c == "conditional-source-or-patch"),
            "finding must fire"
        );
        let desc = out.get_description("conditional-source-or-patch", &config);
        assert!(
            desc.contains("conditional"),
            "explain text missing, got: {desc:?}"
        );
    }

    /// Deliberately removed findings stay silent. The reference still emits
    /// each of these, but no shipped distro config treats them as wanted
    /// signal -- openSUSE's config filters them all, and Fedora's config
    /// carries them only as commented-out filter lines, never enabled --
    /// so the port drops them. Every fixture below fired in the reference
    /// (and in the port before removal); absence is pinned here so a
    /// reintroduction cannot slip back silently.
    #[test]
    fn removed_ifarch_applied_patch_stays_quiet() {
        let results = run_mini(
            "Name: foo\nPatch1: Patch1.patch\n%prep\n%build\n%install\n%ifarch\n%patch1 -P 1\n%endif\n",
        );
        assert!(
            !has(&results, "%ifarch-applied-patch"),
            "results: {results:?}"
        );
        // The patch tracking itself is untouched: a conditionally applied
        // patch is still not "not applied".
        assert!(!has(&results, "patch-not-applied"), "results: {results:?}");
    }

    #[test]
    fn removed_no_buildroot_tag_stays_quiet() {
        let results = run_mini("Name: foo\n");
        assert!(!has(&results, "no-buildroot-tag"), "results: {results:?}");
    }

    #[test]
    fn removed_hardcoded_path_in_buildroot_tag_stays_quiet() {
        let results = run_mini("Name: foo\nBuildRoot: /tmp/buildroot\n");
        assert!(
            !has(&results, "hardcoded-path-in-buildroot-tag"),
            "results: {results:?}"
        );
    }

    #[test]
    fn removed_unversioned_explicit_provides_stays_quiet() {
        let results = run_mini("Name: foo\nProvides: Something\n");
        assert!(
            !has(&results, "unversioned-explicit-provides"),
            "results: {results:?}"
        );
    }

    #[test]
    fn removed_unversioned_explicit_obsoletes_stays_quiet() {
        let results = run_mini("Name: foo\nObsoletes: Something\n");
        assert!(
            !has(&results, "unversioned-explicit-obsoletes"),
            "results: {results:?}"
        );
    }

    #[test]
    fn removed_setup_not_quiet_stays_quiet() {
        let results = run_mini("Name: foo\n%prep\n%setup\n");
        assert!(!has(&results, "setup-not-quiet"), "results: {results:?}");
        // The neighboring setup-not-in-prep check is untouched: %setup
        // inside %prep stays quiet there too.
        assert!(!has(&results, "setup-not-in-prep"), "results: {results:?}");
    }
}
