//! `SpecCheck`: spec-file validation, ported from rpmlint's `SpecCheck.py`.
//!
//! Covers the reference's `add_info` call sites: the per-line checks (sections,
//! buildroot usage, `%setup`/`%autosetup`/`%autopatch`, applied patches,
//! preamble tags, dependencies, changelog/files-section rules,
//! deprecated grep, `Group` validity, macros in comments, the
//! python helpers, forbidden control characters, the
//! `update-desktop-files` deprecation) and the whole-package checks
//! (`BuildRoot` tag, missing sections, superfluous `%clean`, multiple
//! `%changelog`, depgen, patch fuzz,
//! `%ifarch`-applied and unapplied patches), plus the two
//! checks that need the `rpm` tool or the spec parser (`specfile-error`,
//! `specfile-warning`, `invalid-url`), skipped in mini mode.
//!
//! Two upstream fixes ship as fixed behaviour: `#1600` (a trailing
//! line-continuation `\` on `BuildArch: noarch`) and `#1601` (quote-aware
//! `#` comment detection for `macro-in-comment`). `macro-in-comment`
//! (`#442`, `#482`) errors on every unescaped macro mention in a
//! comment, plain references included: rpm expands macros on a comment
//! line before treating it as a comment, so a mention whose expansion
//! runs to several lines leaks its tail into live spec text or shell.
//! The effectful expansions rpm performs while parsing — shell
//! (`%(...)`), Lua (`%{lua:...}`), macro-file (`%{load:...}`) and the
//! executing directives (`%define`, `%global`, `%undefine`, `%lua`,
//! `%load` and the braced `%{define:...}`, `%{global:...}`,
//! `%{undefine:...}`, `%{error:...}` forms), including ones an enclosing
//! `%{expand:...}` makes live by re-expanding escaped `%%` runs — are
//! the sharp end of the same hazard. Spec-syntax keywords (section
//! headers, `%files` directives, conditional keywords) are not macro
//! mentions and stay quiet, as do `%%` escapes and the
//! conditional-with-text form `%{?name:text}`. The
//! openSUSE-only
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
    first_dep_token, has_forbidden_controlchars, has_forbidden_controlchars_deps,
    is_parenthesized_versioned, is_rich_dep_expr, parse_deps,
};
use crate::pkg::spec::SpecPkg;
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

static OBSOLETE_TAGS_RE: OnceLock<Regex> = OnceLock::new();
fn obsolete_tags_re() -> &'static Regex {
    OBSOLETE_TAGS_RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:Serial|Copyright)\s*:\s*(\S.*?)\s*$").expect("static regex")
    })
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
    PREREQ_RE.get_or_init(|| {
        Regex::new(r"(?i)^PreReq(\(.*\))?\s*:\s*(\S.*?)\s*$").expect("static regex")
    })
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

static WITH_MACRO_EMPTY_RE: OnceLock<Regex> = OnceLock::new();
fn with_macro_empty_re() -> &'static Regex {
    WITH_MACRO_EMPTY_RE
        .get_or_init(|| Regex::new(r"%\{!?\?(?:with|without)[\s:}]").expect("static regex"))
}

static CMAKE_KF_RE: OnceLock<Regex> = OnceLock::new();
fn cmake_kf_re() -> &'static Regex {
    CMAKE_KF_RE.get_or_init(|| Regex::new(r"^\s*%cmake_kf[56]\b").expect("static regex"))
}

static BUILD_TESTING_RE: OnceLock<Regex> = OnceLock::new();
fn build_testing_re() -> &'static Regex {
    BUILD_TESTING_RE.get_or_init(|| {
        Regex::new(r#"-DBUILD_TESTING(?::[A-Za-z]+)?\s*=\s*([^\s"']+)"#).expect("static regex")
    })
}

static RPM_BUILDROOT_RE: OnceLock<Regex> = OnceLock::new();
fn rpm_buildroot_re() -> &'static Regex {
    RPM_BUILDROOT_RE.get_or_init(|| {
        Regex::new(r"^[^#]*?(?:(\\*)\${?RPM_BUILD_ROOT}?|(%+){?buildroot}?)").expect("static regex")
    })
}

/// One buildroot token, unanchored: the token arm of `RPM_BUILDROOT_RE`
/// with the same capture groups (1 = escaping backslashes, 2 = escaping
/// `%`s), for walking every token on a line.
static BUILDROOT_TOKEN_RE: OnceLock<Regex> = OnceLock::new();
fn buildroot_token_re() -> &'static Regex {
    BUILDROOT_TOKEN_RE.get_or_init(|| {
        Regex::new(r"(\\*)\${?RPM_BUILD_ROOT}?|(%+){?buildroot}?").expect("static regex")
    })
}

/// An assignment a buildroot reference can lead the value of: a `name=`
/// pair at a token boundary (line start, whitespace or a shell
/// separator), the name optionally carrying a configure-style `--`
/// prefix. The pattern anchors at the end of the examined prefix, so
/// the `=` directly precedes the reference.
static BUILDROOT_ASSIGN_EQ_RE: OnceLock<Regex> = OnceLock::new();
fn buildroot_assign_eq_re() -> &'static Regex {
    BUILDROOT_ASSIGN_EQ_RE.get_or_init(|| {
        Regex::new(r"(?:^|[\s;(])(?:--)?[A-Za-z_][A-Za-z0-9_-]*=$").expect("static regex")
    })
}

/// The space-separated configure form: a `--name` option followed only
/// by whitespace up to the reference (`--prefix $RPM_BUILD_ROOT/usr`).
static BUILDROOT_ASSIGN_SPACE_RE: OnceLock<Regex> = OnceLock::new();
fn buildroot_assign_space_re() -> &'static Regex {
    BUILDROOT_ASSIGN_SPACE_RE
        .get_or_init(|| Regex::new(r"(?:^|\s)--[A-Za-z][A-Za-z0-9_-]*\s+$").expect("static regex"))
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
/// Matches `egrep`/`fgrep` in command position: at line start, or behind
/// whitespace, a path slash, a quote, `(`, a backtick, a backslash, or one
/// of `;`, `|`, `&` — the shapes a shell command invocation takes. Group 1
/// is the command name. The name must end the token: a following word
/// character, `.` or `-` makes it a longer name (an `egrep-helper` script,
/// an `egrep.foo` file), not the deprecated command. A token behind `-`,
/// `.`, `=` or an identifier character is a name fragment or an assignment
/// value (the findutils `posix-egrep` dialect name, a `foo.egrep` data
/// file, a `my-egrep-helper` script, `FOO=egrep`) and never matches.
fn deprecated_grep_re() -> &'static Regex {
    DEPRECATED_GREP_RE.get_or_init(|| {
        Regex::new(r#"(?:^|[\s/'"`(;&|\\])([ef]grep)(?![\w.-])"#).expect("static regex")
    })
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

static LICENSE_TOKEN_RE: OnceLock<Regex> = OnceLock::new();
/// spec-cleaner's `re_doclicense` (`rpmregexp.py`): a token carrying
/// `LICENSE`, `LICENCE` or `COPYING`, with an optional path prefix and
/// an optional `*` or `.suffix`, ending at whitespace or end of line.
fn license_token_re() -> &'static Regex {
    LICENSE_TOKEN_RE.get_or_init(|| {
        Regex::new(r"(?i)(\S+)?(LICEN(S|C)E|COPYING)(\*|\.(\*|\S+))?($|\s)").expect("static regex")
    })
}

static FILE_QUALIFIER_RE: OnceLock<Regex> = OnceLock::new();
/// spec-cleaner's `re_file_qualifier` (`rpmregexp.py`): the file
/// qualifiers that apply to every file on a `%files` line.
fn file_qualifier_re() -> &'static Regex {
    FILE_QUALIFIER_RE.get_or_init(|| {
        Regex::new(r"%(attr|caps|config|dir|ghost|lang|missingok|verify)(\s*\(|\s|$)")
            .expect("static regex")
    })
}

/// Non-breaking space (`UNICODE_NBSP`).
const NBSP: char = '\u{a0}';

/// The position of the first `#` that starts a shell comment, or `None`.
///
/// `#` inside single- or double-quoted shell strings does not start a
/// comment, and neither does a `#` glued to a word (`${var#pattern}`,
/// `a#b`): a `#` opens a comment only at the start of a word -- at the
/// line start or after whitespace or a command separator. A backslash
/// escapes the next character unless inside single quotes (shell
/// semantics); the caller still decides whether a `#` candidate counts
/// as a comment start. Fixed behaviour per `#1601`.
fn comment_start_pos(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut pos = 0;
    while pos < bytes.len() {
        let c = bytes[pos];
        if c == b'#' && !in_single && !in_double {
            let at_word_start =
                pos == 0 || matches!(bytes[pos - 1], b' ' | b'\t' | b';' | b'&' | b'|' | b'(');
            if at_word_start {
                return Some(pos);
            }
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

/// Bare names that are spec syntax rather than macros: section
/// headers, `%files` directives and conditional keywords, plus the
/// parser's `%include`. A comment naming one (`# %license is how the
/// license file is shipped`) mentions no macro and stays quiet.
const SPEC_SYNTAX_KEYWORDS: &[&str] = &[
    // Section headers.
    "package",
    "description",
    "changelog",
    "prep",
    "build",
    "install",
    "check",
    "files",
    "clean",
    "pre",
    "post",
    "preun",
    "postun",
    "pretrans",
    "posttrans",
    "verifyscript",
    "trigger",
    "triggerin",
    "triggerprein",
    "triggerun",
    "triggerpostun",
    "filetriggerin",
    "filetrigger",
    "filetriggerun",
    "filetriggerpostun",
    "transfiletriggerin",
    "transfiletrigger",
    "transfiletriggerun",
    "transfiletriggerpostun",
    "generate_buildrequires",
    // `%files` directives.
    "attr",
    "caps",
    "defattr",
    "dir",
    "doc",
    "docdir",
    "license",
    "config",
    "exclude",
    "ghost",
    "lang",
    "missingok",
    "verify",
    "artifact",
    // Conditional keywords and the parser's `%include`.
    "if",
    "ifarch",
    "ifnarch",
    "ifos",
    "ifnos",
    "ifdef",
    "ifndef",
    "ifexpr",
    "else",
    "elif",
    "elifarch",
    "elifnarch",
    "elifos",
    "elifnos",
    "endif",
    "include",
];

/// The macro mentions in a spec comment that `macro-in-comment`
/// reports: every unescaped reference, plain (`%name`, `%{name}`,
/// `%{?name}`) or effectful. The effectful forms are the expansions
/// rpm performs while parsing: shell expansion (`%(...)`), Lua
/// (`%{lua:...}`), macro-file loading (`%{load:...}`) and the executing
/// directives, bare (`%define`, `%global`, `%undefine`, `%lua`,
/// `%load`) and braced (`%{define:...}`, `%{global:...}`,
/// `%{undefine:...}`, `%{error:...}`). Returns the source span of each
/// live occurrence.
///
/// Verified against rpm 4.20.1 (`rpmspec -P` over crafted specs): all
/// of the effectful forms execute, define, load or abort from inside a
/// comment, at parse time in the preamble and at build-script
/// generation in scriptlets, and plain references expand there too —
/// rpm expands macros on a comment line before treating it as a
/// comment, so an expansion that runs to several lines leaves only
/// its first line commented and the tail becomes live spec text or
/// shell. `%[...]` / `%{expr:...}` / `%{getenv:...}` evaluate pure
/// expressions, `%{shell:...}` and `%{eval:...}` do not exist, and
/// conditional keywords in comments are never honoured.
///
/// Whether a `%` run is live follows rpm's expansion passes: the text
/// is expanded once, plus once more per enclosing `%{expand:...}`. On
/// each pass an odd run before an introducer expands (and executes)
/// while an even run collapses to half its length, so `%%(` stays inert
/// but `%%(` inside one `%{expand:...}` executes. Other braced
/// constructs expand their argument in place (even `%{quote:...}`), so
/// their contents are scanned with the surrounding pass budget. A
/// conditional-with-text branch's text expands only when the branch is
/// taken: on rpm 4.20.1 the `%{error:...}`, `%{lua:...}` and `%(...)`
/// forms nested in `%{?name:...}` execute when the guard macro is
/// defined and never when it is not (likewise for a nested untaken
/// branch inside a taken one). Taken-ness turns on the macro state at
/// that point of the parse, which the scan does not decide, so
/// effectful forms in the text are reported, while plain mentions in
/// the text stay quiet. A `%{lua:...}` body reaches the
/// interpreter unexpanded, so it is opaque: the construct itself is the
/// finding and its body is not scanned.
fn comment_macro_mentions(comment: &str) -> Vec<&str> {
    let mut found = Vec::new();
    scan_comment_text(comment, 0, 0, false, &mut found);
    found
}

/// Whether a run of `run` percent signs before an expansion introducer
/// expands within `passes` expansion passes (see `comment_macro_mentions`).
fn percent_run_expands(mut run: usize, passes: usize) -> bool {
    for _ in 0..passes {
        if run % 2 == 1 {
            return true;
        }
        run /= 2;
        if run == 0 {
            return false;
        }
    }
    false
}

/// The end of the first argument token of a bare directive whose name
/// ends at `name_end`, or `None` when no argument follows. A bare
/// directive needs whitespace and an argument to act: `%define` defines
/// the macro named by that argument, `%load` loads the file it names,
/// and so on; a bare name with nothing after it does nothing.
fn bare_directive_argument(text: &str, name_end: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if !matches!(bytes.get(name_end), Some(b' ' | b'\t')) {
        return None;
    }
    let mut i = name_end;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    if i == bytes.len() {
        return None;
    }
    while i < bytes.len() && !matches!(bytes[i], b' ' | b'\t') {
        i += 1;
    }
    Some(i)
}

/// The index just past the `close` matching the `open` at `start`,
/// counting nested pairs the way rpm's macro grabber does, or `None`
/// when the span never closes.
fn balanced_span_end(bytes: &[u8], start: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == open {
            depth += 1;
        } else if bytes[i] == close {
            depth -= 1;
            if depth == 0 {
                return Some(i + 1);
            }
        }
        i += 1;
    }
    None
}

/// Scan `text` (a comment, or the argument of a braced construct) for
/// macro mentions. `expand_depth` counts the enclosing live
/// `%{expand:...}` arguments; `depth` caps construct recursion;
/// `plain_suppressed` holds inside a conditional-with-text form,
/// whose own text is quiet for plain mentions.
fn scan_comment_text<'a>(
    text: &'a str,
    expand_depth: usize,
    depth: usize,
    plain_suppressed: bool,
    found: &mut Vec<&'a str>,
) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        let run_start = i;
        while i < bytes.len() && bytes[i] == b'%' {
            i += 1;
        }
        let run = i - run_start;
        match bytes.get(i) {
            Some(b'(') => {
                if percent_run_expands(run, 1 + expand_depth) {
                    let end = balanced_span_end(bytes, i, b'(', b')').unwrap_or(bytes.len());
                    found.push(&text[run_start..end]);
                    i = end;
                }
                // An inert `%(` is literal text: scanning continues
                // into the parentheses as ordinary comment text.
            }
            Some(b'{') => {
                i = scan_braced_construct(
                    text,
                    run_start,
                    i,
                    expand_depth,
                    depth,
                    plain_suppressed,
                    found,
                );
            }
            Some(b'[') => {
                // `%[...]`: a pure expression, but it is expanded in
                // place, so its contents keep the surrounding budget.
                let end = balanced_span_end(bytes, i, b'[', b']');
                if depth < 32 {
                    let inner_end = end.map(|e| e - 1).unwrap_or(bytes.len());
                    scan_comment_text(
                        &text[i + 1..inner_end],
                        expand_depth,
                        depth + 1,
                        plain_suppressed,
                        found,
                    );
                }
                i = end.unwrap_or(bytes.len());
            }
            _ => {
                // A bare directive rpm executes while parsing —
                // `%define` / `%global` / `%undefine` / `%lua` / `%load` —
                // is effectful. Any other name that is not spec syntax
                // (see `SPEC_SYNTAX_KEYWORDS`) is a plain macro
                // reference; a stray `%` has no name at all. A bare
                // conditional reference (`%?name`, `%!name`) carries
                // its sigil before the name: the sigil is consumed so
                // the name is judged exactly as the braced form's is.
                if matches!(bytes.get(i), Some(b'?' | b'!')) {
                    i += 1;
                }
                let name_start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let name = &text[name_start..i];
                if !name.is_empty()
                    && !matches!(name, "define" | "global" | "undefine" | "lua" | "load")
                    && !SPEC_SYNTAX_KEYWORDS.contains(&name)
                    && !plain_suppressed
                    && percent_run_expands(run, 1 + expand_depth)
                {
                    // A plain macro reference: rpm expands it on the
                    // comment line, so the mention itself is reported.
                    found.push(&text[run_start..i]);
                }
                if matches!(name, "define" | "global" | "undefine" | "lua" | "load")
                    && percent_run_expands(run, 1 + expand_depth)
                    && let Some(arg_end) = bare_directive_argument(text, i)
                {
                    if matches!(name, "define" | "global" | "lua") {
                        // The argument is the rest of the text: a macro
                        // body (stored unexpanded) or Lua code (run
                        // as-is), so it is opaque — the directive itself
                        // is the finding and its body is not scanned.
                        let end = text.trim_end().len();
                        found.push(&text[run_start..end]);
                        i = bytes.len();
                    } else {
                        // `%undefine` / `%load` take a single argument;
                        // text after it keeps the surrounding budget.
                        found.push(&text[run_start..arg_end]);
                        i = arg_end;
                    }
                }
            }
        }
    }
}

/// Handle the `%{` construct whose percent run starts at `run_start`
/// and whose `{` is at `brace`. Returns the index scanning continues
/// from.
fn scan_braced_construct<'a>(
    text: &'a str,
    run_start: usize,
    brace: usize,
    expand_depth: usize,
    depth: usize,
    plain_suppressed: bool,
    found: &mut Vec<&'a str>,
) -> usize {
    let bytes = text.as_bytes();
    // The name: word characters plus the `?`/`!` conditional markers.
    let mut name_end = brace + 1;
    while name_end < bytes.len()
        && (bytes[name_end].is_ascii_alphanumeric()
            || matches!(bytes[name_end], b'_' | b'?' | b'!'))
    {
        name_end += 1;
    }
    let end = balanced_span_end(bytes, brace, b'{', b'}');
    let span_end = end.unwrap_or(bytes.len());
    match bytes.get(name_end) {
        // No argument: a plain (possibly conditional) reference — a
        // mention, reported when its percent run is live.
        Some(b'}') => {
            // The same tests the bare path applies: conditional
            // sigils are stripped before the name is judged, spec
            // syntax is not a macro mention, an executing directive
            // with no argument does nothing, and a lone sigil (the
            // preamble tokenizer's literal empty group) names no
            // macro at all.
            let name = text[brace + 1..name_end].trim_start_matches(['?', '!']);
            if !name.is_empty()
                && !SPEC_SYNTAX_KEYWORDS.contains(&name)
                && !matches!(
                    name,
                    "define" | "global" | "undefine" | "lua" | "load" | "error"
                )
                && !plain_suppressed
                && percent_run_expands(brace - run_start, 1 + expand_depth)
            {
                found.push(&text[run_start..span_end]);
            }
            span_end
        }
        Some(b':' | b' ' | b'\t') => {
            let name = &text[brace + 1..name_end];
            let live = percent_run_expands(brace - run_start, 1 + expand_depth);
            let inner_end = end.map(|e| e - 1).unwrap_or(bytes.len());
            let inner = &text[name_end + 1..inner_end];
            if live
                && matches!(
                    name,
                    "lua" | "load" | "define" | "global" | "undefine" | "error"
                )
                && !inner.trim().is_empty()
            {
                found.push(&text[run_start..span_end]);
            } else if depth < 32 {
                // A live `%{expand:...}` re-expands its argument, adding
                // a pass; everything else (including a dead expansion
                // form, whose argument stays ordinary text) is scanned
                // with the surrounding budget. A conditional-with-text
                // form (`%{?name:text}`) is itself quiet, and so are
                // plain mentions in its text; effectful expansions
                // there still count, because rpm expands them whenever
                // the branch is taken and taken-ness is not decidable
                // from the comment (see `comment_macro_mentions`).
                let extra = if live && name == "expand" {
                    expand_depth + 1
                } else {
                    expand_depth
                };
                let conditional = name.starts_with('?') || name.starts_with('!');
                scan_comment_text(
                    inner,
                    extra,
                    depth + 1,
                    plain_suppressed || conditional,
                    found,
                );
            }
            span_end
        }
        // Not a readable construct: the `{` is literal text.
        _ => brace + 1,
    }
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

/// True when every buildroot reference on the line leads the value of an
/// assignment: a `name=` pair (`DESTDIR=`, `destdir=`, any variable or
/// macro-definition payload name) or a configure-style `--name` option in
/// its `=` or space-separated form. In %build and %prep the buildroot is
/// the install destination, and a reference in that position hands it to
/// the build system as a path parameter the build consumes; a reference
/// in any other position (a command's path or plain argument, a value
/// the reference does not lead, text a compiler flag carries) is not the
/// assignment idiom. Only the text before the first `#` is walked --
/// `RPM_BUILDROOT_RE` cannot see past one, so neither can this. Tokens
/// failing the `contains_buildroot` escaping-parity rule are literals,
/// not references, and are skipped.
fn buildroot_refs_are_install_assignments(line: &str) -> bool {
    let segment = line.split('#').next().unwrap_or("");
    let mut any = false;
    for caps in buildroot_token_re()
        .captures_iter(segment)
        .filter_map(|r| r.ok())
    {
        let backslashes = caps.get(1).map(|m| m.as_str());
        let percents = caps.get(2).map(|m| m.as_str());
        let effective = backslashes.is_none_or(|s| s.len() % 2 == 0)
            && percents.is_none_or(|s| s.len() % 2 != 0);
        if !effective {
            continue;
        }
        any = true;
        let token = caps.get(0).expect("token match");
        let prefix = segment[..token.start()].trim_end_matches(['"', '\'']);
        if !buildroot_assign_eq_re().is_match(prefix).unwrap_or(false)
            && !buildroot_assign_space_re()
                .is_match(prefix)
                .unwrap_or(false)
        {
            return false;
        }
    }
    any
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

/// Per-`%files`-section state for the licence-marking scan (#821),
/// collected line by line and judged once the whole spec has been
/// walked (`flush_license_marking`).
#[derive(Default)]
struct FilesSectionScan {
    /// The header carried `-f`: part of the entry text lives in a list
    /// file the scan cannot see.
    from_list_file: bool,
    /// A generator macro line, braced or unbraced, generates entries
    /// the text scan cannot see.
    has_generator_macro: bool,
    /// The section carries a `%license` line.
    has_license_line: bool,
    /// A `%doc` line (qualified or not) carries a licence token.
    doc_license: bool,
    /// The first licence token on an unqualified `%doc` line, with its
    /// line number: the `license-file-as-doc` candidate.
    doc_license_unqualified: Option<(String, u32)>,
    /// An entry token's basename is a licence token: the licence file
    /// is shipped, unmarked.
    plain_license_entry: bool,
    /// Count of explicit entries: glob-free entries that name a
    /// dotted file or sit in an exec location.
    explicit_entries: u32,
    /// Count of explicit entries that are documentation: `%doc`-line
    /// entries and entries under a documentation directory.
    explicit_doc_entries: u32,
    /// The section lists a build-metadata directory entry
    /// (`*.dist-info`, `*.egg-info`), or a file under one: the
    /// build system assembles the installed tree, licence files
    /// included.
    has_info_entry: bool,
    /// A `%doc` entry whose contents the spec text does not name:
    /// a directory argument, or a glob whose literal prefix reaches
    /// no licence stem. What `%install` left in the directory, or
    /// among the glob's matches, may be a licence file (#831, #832).
    has_indeterminate_doc: bool,
}

/// The `%files` entry directives that lead a line, by the shape their
/// tokens take for the licence-marking scan.
enum FilesDirective {
    /// `%attr`/`%caps`/`%config`/`%lang`/`%missingok`/`%verify`:
    /// the remaining tokens are shipped entries.
    Entry,
    /// `%dir`: the remaining tokens are directories.
    Dir,
    /// `%ghost`: the remaining tokens carry no shipped content.
    Ghost,
}

/// Classify a `%files` line's leading directive token for the
/// licence-marking scan; `None` for entry lines and for directives
/// whose lines carry no judgeable entries (`%docdir`, `%defattr`,
/// `%exclude`, conditionals).
fn files_directive(first: &str) -> Option<FilesDirective> {
    let name: String = first
        .strip_prefix('%')?
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect();
    match name.as_str() {
        "attr" | "caps" | "config" | "lang" | "missingok" | "verify" => Some(FilesDirective::Entry),
        "dir" => Some(FilesDirective::Dir),
        "ghost" => Some(FilesDirective::Ghost),
        _ => None,
    }
}

/// A token that consists solely of braced macro invocations,
/// nested (`%{expand:%{...}}`) or concatenated (`%{...}%{...}`):
/// in a `%files` body it generates entries the text scan cannot
/// see. A token carrying any literal text - a macro-composed path
/// such as `%{_bindir}/%{name}` - is an entry, not a generator.
fn is_bare_macro(token: &str) -> bool {
    let bytes = token.as_bytes();
    let mut at = 0;
    let mut spans = 0;
    while at < bytes.len() {
        if !token[at..].starts_with("%{") {
            return false;
        }
        // Find the brace matching the span's opening brace.
        let mut depth = 0;
        let mut end = None;
        for (i, &b) in bytes.iter().enumerate().skip(at + 1) {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { return false };
        spans += 1;
        at = end + 1;
    }
    spans > 0
}

/// Presence test for the licence-marking scan: the name carries a
/// licence stem (`LICENCE`, `LICENSE`, `COPYING`, `COPYRIGHT`, `GPL`,
/// `LGPL`, `AGPL`) delimited by non-alphanumerics, so `LICENSE_GPL`,
/// `licence-LGPL.txt`, `gpl-2.0.txt`, `COPYING3` and `{COPYING,README}`
/// all count, while a stem buried in a longer word (`LICENSES`,
/// `gplv3`) does not. `COPYING` closed by a digit run counts
/// (`COPYING3`, `COPYING3.LIB`): the digits are the licence version
/// glued to the GNU licence file's name, and the run closes on a
/// non-alphanumeric boundary or the end of the name, where a letter
/// glued to the digits would make a longer word.
/// Every shape `license_token_re` accepts counts too — a stem joined
/// to a prefix (`FOOCOPYING`) is the conversion predicate's shape, so
/// a name the warning fires on always establishes presence.
fn name_carries_licence(name: &str) -> bool {
    if license_token_re().find(name).ok().flatten().is_some() {
        return true;
    }
    let lower = name.to_lowercase();
    let bytes = lower.as_bytes();
    for stem in [
        "licence",
        "license",
        "copying",
        "copyright",
        "agpl",
        "lgpl",
        "gpl",
    ] {
        let mut at = 0;
        while let Some(pos) = lower[at..].find(stem) {
            let start = at + pos;
            let end = start + stem.len();
            let before_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
            let after_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
            // `COPYING` closed by a digit run (`COPYING3`,
            // `COPYING3.LIB`) carries the stem with the licence
            // version glued on: the digit run closes on a
            // non-alphanumeric boundary or at the end of the name,
            // where a letter glued to the digits (`COPYING3X`)
            // would make a longer word.
            let digit_suffix = stem == "copying" && {
                let digits = bytes[end..]
                    .iter()
                    .take_while(|b| b.is_ascii_digit())
                    .count();
                digits > 0
                    && (end + digits == bytes.len() || !bytes[end + digits].is_ascii_alphanumeric())
            };
            if before_ok && (after_ok || digit_suffix) {
                return true;
            }
            at = start + 1;
        }
    }
    false
}

/// The digit run glued to a `COPYING` stem in an uppercased glob
/// prefix, with the byte that closes it (`None` at the end of the
/// prefix); `None` when the prefix carries no `COPYING` stem.
/// The digits are the licence version glued to the GNU licence
/// file's name, the shape the plain name test accepts for
/// `COPYING3` and `COPYING3.LIB`.
fn copying_digit_run(upper: &str) -> Option<(usize, Option<u8>)> {
    let rest = upper.strip_prefix("COPYING")?;
    let digits = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
    Some((digits, rest.as_bytes().get(digits).copied()))
}

/// A globbed name whose literal prefix reaches into a licence stem
/// (`COPY*`, `LICEN*`, `LICENSE-*`): the glob ships the licence file
/// among its matches. A `COPYING` prefix closed by a digit run
/// counts too (`COPYING3*`), mirroring the plain name test.
fn glob_prefix_carries_licence(basename: &str) -> bool {
    if !basename.contains(['*', '?', '[']) {
        return false;
    }
    let prefix: String = basename
        .chars()
        .take_while(|c| !matches!(c, '*' | '?' | '['))
        .collect();
    if prefix.len() < 3 {
        return false;
    }
    let upper = prefix.to_uppercase();
    ["COPYING", "LICENCE", "LICENSE", "COPYRIGHT"]
        .iter()
        .any(|stem| {
            // The literal prefix is a stem prefix (`COPY*`, `LICEN*`),
            // the whole stem (`COPYING*`), or the stem closed by a
            // non-alphanumeric boundary (`LICENSE-*`, `COPYING.txt*`).
            // A stem running into a longer word (`COPYINGFOO*`) is the
            // buried-stem shape the plain name test rejects.
            stem.starts_with(upper.as_str())
                || upper == *stem
                || (upper.starts_with(stem)
                    && !upper.as_bytes()[stem.len()].is_ascii_alphanumeric())
                || (*stem == "COPYING"
                    && copying_digit_run(&upper).is_some_and(|(digits, next)| {
                        digits > 0 && next.is_none_or(|b| !b.is_ascii_alphanumeric())
                    }))
        })
}

/// A globbed name whose literal prefix runs a licence stem into a
/// longer word (`COPYINGFOO*`): the prefix itself shows the stem
/// buried, the shape the plain name test rejects, so the glob's
/// matches are judged on the names they can carry rather than
/// treated as unknowable. A digit continuation does not bury the
/// stem: `COPYING3*` still runs into the digit-suffixed licence
/// name the plain test accepts. A digit run running into a letter
/// (`COPYING3X*`) is the longer word again, exactly as the plain
/// test rejects `COPYING3X`.
fn glob_prefix_buries_licence_stem(basename: &str) -> bool {
    if !basename.contains(['*', '?', '[']) {
        return false;
    }
    let prefix: String = basename
        .chars()
        .take_while(|c| !matches!(c, '*' | '?' | '['))
        .collect();
    let upper = prefix.to_uppercase();
    ["COPYING", "LICENCE", "LICENSE", "COPYRIGHT"]
        .iter()
        .any(|stem| {
            upper.len() > stem.len()
                && upper.starts_with(stem)
                && (upper.as_bytes()[stem.len()].is_ascii_alphabetic()
                    || (*stem == "COPYING"
                        && copying_digit_run(&upper).is_some_and(|(digits, next)| {
                            digits > 0 && next.is_some_and(|b| b.is_ascii_alphabetic())
                        })))
        })
}

/// The normalised docdir destinations of the licence copies literal
/// `install`/`cp` commands on this `%install` line perform (#833):
/// each destination path as written, with any buildroot prefix and
/// trailing slash removed. A command qualifies at command position
/// (the start of the line or of a `;`/`&&`/`||`/`|` segment, after
/// any environment assignments), spelled `install`, `cp`,
/// `%{__install}` or `%{__cp}` -- an absolute tool path qualifies by
/// its basename. Quoted tokens are unquoted, and a redirection and
/// its target are not arguments. Flags are skipped: the value-taking
/// flags (`-m`, `-o`, `-g`, `--mode`, `--owner`, `--group`) consume
/// the following token or the rest of their bundle, while
/// `-t`/`--target-directory` names the destination itself, so with
/// no target directory the destination is the final positional
/// argument and every earlier positional argument is a source. The
/// copy qualifies when a source's basename carries a licence stem
/// (`name_carries_licence`) or is a glob whose prefix does
/// (`glob_prefix_carries_licence`), and the destination names the
/// docdir or a path under it (`docdir_destination`). An
/// `install -d` line creates directories and copies nothing, so it
/// never qualifies.
fn install_copy_docdirs(line: &str) -> Vec<String> {
    let line = match comment_start_pos(line) {
        Some(pos) => &line[..pos],
        None => line,
    };
    line.split(';')
        .flat_map(|segment| segment.split("&&"))
        .flat_map(|segment| segment.split("||"))
        .flat_map(|segment| segment.split('|'))
        .filter_map(segment_copy_docdir)
        .collect()
}

/// The normalised docdir destination of the copy a single command
/// segment performs; see `install_copy_docdirs`.
fn segment_copy_docdir(segment: &str) -> Option<String> {
    let tokens: Vec<&str> = segment.split_whitespace().map(strip_token_quotes).collect();
    // Environment assignments precede the command proper.
    let start = tokens
        .iter()
        .position(|t| !is_env_assignment(t))
        .unwrap_or(tokens.len());
    let command = *tokens.get(start)?;
    let base = command.rsplit('/').next().unwrap_or(command);
    let is_install = base == "install" || command == "%{__install}";
    if !is_install && base != "cp" && command != "%{__cp}" {
        return None;
    }
    let args = &tokens[start + 1..];
    if is_install && install_creates_dir(args) {
        return None;
    }
    let mut positional: Vec<&str> = Vec::new();
    let mut target_dir: Option<&str> = None;
    let mut options_done = false;
    let mut i = 0;
    while i < args.len() {
        let token = args[i];
        if let Some(skip) = redirect_skip(token) {
            i += skip;
        } else if !options_done && token == "--" {
            options_done = true;
            i += 1;
        } else if !options_done && token.starts_with("--") {
            if token == "--target-directory" {
                target_dir = args.get(i + 1).copied();
                i += 2;
            } else if let Some(value) = token.strip_prefix("--target-directory=") {
                target_dir = Some(value);
                i += 1;
            } else if matches!(token, "--mode" | "--owner" | "--group") {
                i += 2;
            } else {
                i += 1;
            }
        } else if !options_done && token.len() > 1 && token.starts_with('-') {
            // A short-flag bundle: a value-taking letter consumes
            // the rest of the bundle as its value, or the following
            // token when it ends the bundle. The `-t` value is the
            // target directory -- the copy's destination.
            let body = &token[1..];
            match body
                .char_indices()
                .find(|(_, c)| matches!(c, 'm' | 'o' | 'g' | 't'))
            {
                Some((at, kind)) => {
                    let glued = &body[at + kind.len_utf8()..];
                    if kind == 't' {
                        if glued.is_empty() {
                            target_dir = args.get(i + 1).copied();
                            i += 2;
                        } else {
                            target_dir = Some(glued);
                            i += 1;
                        }
                    } else {
                        i += if glued.is_empty() { 2 } else { 1 };
                    }
                }
                None => i += 1,
            }
        } else {
            positional.push(token);
            i += 1;
        }
    }
    let (dest, sources): (&str, &[&str]) = match target_dir {
        Some(dir) => (dir, &positional),
        None => {
            let (dest, sources) = positional.split_last()?;
            (*dest, sources)
        }
    };
    if sources.is_empty() {
        return None;
    }
    let dest = docdir_destination(dest)?;
    sources
        .iter()
        .any(|source| {
            let base = source.rsplit('/').next().unwrap_or(source);
            name_carries_licence(base) || glob_prefix_carries_licence(base)
        })
        .then_some(dest)
}

/// A token with one layer of matching surrounding quotes removed:
/// shell quoting groups a word; it is not part of the word.
fn strip_token_quotes(token: &str) -> &str {
    let bytes = token.as_bytes();
    if token.len() >= 2 {
        let (first, last) = (bytes[0], bytes[token.len() - 1]);
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &token[1..token.len() - 1];
        }
    }
    token
}

/// A leading `NAME=value` environment assignment token: the name is
/// a shell identifier and the value carries no command substitution
/// (a substitution executes, so such a token is no plain assignment).
fn is_env_assignment(token: &str) -> bool {
    let Some((name, value)) = token.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
        && !value.contains("$(")
        && !value.contains('`')
}

/// The tokens a redirection at this position consumes: the operator
/// plus its target -- one token when the target is glued to the
/// operator (`2>/dev/null`, `>log`), two when it stands alone
/// (`> log`). `None` for a non-redirection token.
fn redirect_skip(token: &str) -> Option<usize> {
    let digits = token.bytes().take_while(|b| b.is_ascii_digit()).count();
    let rest = &token[digits..];
    let rest = rest.strip_prefix('&').unwrap_or(rest);
    if !rest.starts_with('>') && !rest.starts_with('<') {
        return None;
    }
    let op_len = if rest.starts_with(">>") || rest.starts_with("<<") {
        2
    } else {
        1
    };
    Some(if rest.len() > op_len { 1 } else { 2 })
}

/// An `install` argument list creates directories rather than
/// copying when a flag token before the `--` terminator says so
/// (`install_token_creates_dir`): tokens after `--` are operands,
/// never flags.
fn install_creates_dir(args: &[&str]) -> bool {
    args.iter()
        .take_while(|t| **t != "--")
        .any(|t| install_token_creates_dir(t))
}

/// An `install` flag token creates directories rather than copying:
/// `--directory`, or a short-flag bundle whose `d` precedes any
/// value-taking flag (`-dm755` creates; `-gadm` carries a glued
/// group value and copies).
fn install_token_creates_dir(token: &str) -> bool {
    if token == "--directory" {
        return true;
    }
    if !token.starts_with('-') || token.starts_with("--") || token.len() < 2 {
        return false;
    }
    for c in token[1..].chars() {
        if c == 'd' {
            return true;
        }
        if matches!(c, 'm' | 'o' | 'g' | 't') {
            return false;
        }
    }
    false
}

/// The docdir path a copy destination names, as written in the
/// spec: the buildroot prefix and a trailing slash are removed, so
/// the result compares against `%files` entry text. The destination
/// must carry the buildroot prefix (`%{buildroot}`, `%buildroot`,
/// `$RPM_BUILD_ROOT` or `${RPM_BUILD_ROOT}`) -- a bare docdir path
/// names the build host's docdir, not the packaged copy. The
/// destination names the docdir when it is `%{_docdir}`,
/// `%{_defaultdocdir}` or the literal `usr/share/doc`, or a path
/// under any of them; anything else returns `None`.
fn docdir_destination(dest: &str) -> Option<String> {
    let mut rest = dest;
    let mut in_buildroot = false;
    for prefix in [
        "%{buildroot}",
        "%buildroot",
        "${RPM_BUILD_ROOT}",
        "$RPM_BUILD_ROOT",
    ] {
        if let Some(stripped) = rest.strip_prefix(prefix) {
            rest = stripped;
            in_buildroot = true;
            break;
        }
    }
    if !in_buildroot {
        return None;
    }
    let rest = rest.trim_start_matches('/');
    for docdir in ["%{_docdir}", "%{_defaultdocdir}"] {
        if rest == docdir || rest.starts_with(&format!("{docdir}/")) {
            return Some(rest.trim_end_matches('/').to_string());
        }
    }
    // The literal docdir path keeps its leading slash: `%files`
    // entries spell it that way, unlike the macro spellings.
    if rest == "usr/share/doc" || rest.starts_with("usr/share/doc/") {
        return Some(format!("/{}", rest.trim_end_matches('/')));
    }
    None
}

/// An entry path in an executable or library-exec location: its final
/// component names a file even without an extension.
fn in_exec_location(token: &str) -> bool {
    [
        "%{_bindir}/",
        "%{_sbindir}/",
        "%{_libexecdir}/",
        "%{_prefix}/bin/",
        "%{_prefix}/sbin/",
        "%{_prefix}/libexec/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/libexec/",
        "/bin/",
        "/sbin/",
    ]
    .iter()
    .any(|prefix| token.starts_with(prefix))
}

/// The entry is documentation: it sits under a documentation
/// directory. `%{_defaultdocdir}` is the canonical documentation
/// directory macro; `%{_docdir}` appears in specs in the wild too.
fn in_doc_location(token: &str) -> bool {
    token.contains("%{_defaultdocdir}") || token.contains("%{_docdir}") || token.contains("/doc/")
}

/// The entry names a build-metadata directory the build system
/// assembles: the dotted metadata suffixes (`*.dist-info`,
/// `*.egg-info`), with a trailing glob marker allowed, or the
/// historical glob spelling `*-info`, whose literal ending
/// names the same directories. Data names ending in `-info`
/// stay ordinary entries.
fn is_info_entry(basename: &str) -> bool {
    let name = basename.strip_suffix('*').unwrap_or(basename);
    name.ends_with(".dist-info") || name.ends_with(".egg-info") || name.ends_with("*-info")
}

/// The value of a `License:` tag line; the tag name matches
/// case-insensitively (`rpmspec` accepts `license:` too).
fn license_tag_value(line: &str) -> Option<&str> {
    let (tag, value) = line.split_once(':')?;
    tag.trim().eq_ignore_ascii_case("license").then_some(value)
}

/// A `License:` value naming only public-domain dedications: every
/// licence identifier in the SPDX expression is a public-domain
/// identifier, so `MIT AND SUSE-Public-Domain` does not qualify —
/// the expression as a whole is not a dedication. A `LicenseRef-`
/// identifier counts by the identifier it references, so
/// `LicenseRef-SUSE-Public-Domain` qualifies while
/// `LicenseRef-Apache-2.0` does not.
fn license_value_is_public_domain_only(value: &str) -> bool {
    let mut any = false;
    let mut skip_exception = false;
    for token in value.split(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | ',')) {
        let token = token.trim_end_matches('+');
        if token.is_empty() {
            continue;
        }
        if skip_exception {
            skip_exception = false;
            continue;
        }
        if token.eq_ignore_ascii_case("WITH") {
            skip_exception = true;
            continue;
        }
        if ["AND", "OR"]
            .iter()
            .any(|op| token.eq_ignore_ascii_case(op))
        {
            continue;
        }
        any = true;
        // A `LicenseRef-` identifier names the licence it references
        // after the prefix.
        let id = if token.len() > "licenseref-".len()
            && token.as_bytes()[.."licenseref-".len()].eq_ignore_ascii_case(b"licenseref-")
        {
            &token["licenseref-".len()..]
        } else {
            token
        };
        if !["public-domain", "suse-public-domain", "publicdomain"]
            .iter()
            .any(|pd| id.eq_ignore_ascii_case(pd))
        {
            return false;
        }
    }
    any
}

/// The macro name of a token that is exactly one unbraced macro
/// invocation (`%pyproject_files` -> `pyproject_files`); `None` for
/// any other token shape.
fn unbraced_macro_name(token: &str) -> Option<&str> {
    let name = token.strip_prefix('%')?;
    (!name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .then_some(name)
}

/// `%files` directive, qualifier and conditional words: a line led
/// by one of these carries entries (or nothing) under rules of its
/// own, so the word never marks its section opaque as a generator
/// macro.
const FILES_DIRECTIVE_WORDS: &[&str] = &[
    "attr",
    "caps",
    "config",
    "defattr",
    "dir",
    "doc",
    "docdir",
    "else",
    "endif",
    "exclude",
    "ghost",
    "if",
    "ifarch",
    "ifnarch",
    "lang",
    "license",
    "missingok",
    "verify",
];

/// The value names a file carrying extension `ext`: the extension
/// is closed by the end of the value or by a character that cannot
/// continue an extension name, so `.gem` does not match inside
/// `.gemspec`.
fn value_names_extension(value: &str, ext: &str) -> bool {
    value.match_indices(ext).any(|(at, _)| {
        value[at + ext.len()..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
    })
}

/// The line is a `Source`/`SourceN` tag whose value names an archive.
fn source_line_is_archive(line: &str) -> bool {
    let Some((tag, value)) = line.split_once(':') else {
        return false;
    };
    let tag = tag.trim().to_lowercase();
    if !tag.starts_with("source") || !tag[6..].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    [
        ".tar", ".tgz", ".tbz", ".txz", ".zip", ".jar", ".7z", ".crate", ".gem", ".whl",
    ]
    .iter()
    .any(|ext| value_names_extension(value, ext))
}

/// The line is a `Source`/`SourceN` tag whose value names a package
/// format (gem, wheel) whose installer assembles the whole upstream
/// tree, licence files included.
fn source_line_is_packaged(line: &str) -> bool {
    let Some((tag, value)) = line.split_once(':') else {
        return false;
    };
    let tag = tag.trim().to_lowercase();
    if !tag.starts_with("source") || !tag[6..].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    value_names_extension(value, ".gem") || value_names_extension(value, ".whl")
}

/// `SpecCheck`, ported from rpmlint's `SpecCheck.py`.
/// One physical line of a shell build section (`%prep`, `%build`,
/// `%install`, `%check`), recorded during the line walk for the
/// deferred exit-status analysis in `flush_check_soundness` (#1019).
struct BodyLine {
    section: String,
    instance: u32,
    lineno: u32,
    text: String,
}

/// One enclosing `%if`-family directive in the raw-line walk.
///
/// `construct` identifies the directive instance within the spec (two
/// lines inside the same `%if` block share it); `text` is the
/// whitespace-normalised directive line, so two separate blocks
/// written with the same condition (the `_multibuild` flavour idiom)
/// also compare as the same condition. `segment` is 0 in the `%if`
/// branch, increments per `%elif`, and is `u32::MAX` in the `%else`
/// branch.
#[derive(Clone, Debug)]
struct CondFrame {
    construct: u64,
    text: String,
    segment: u32,
}

/// Whether two conditional contexts can hold in the same build. The
/// only provable exclusion is a level where both sides share a
/// condition (the same directive instance, or the same condition
/// text) but sit in different branches of it: branches of one
/// condition are mutually exclusive. Any other shape -- different
/// conditions, nesting, an unconditional side -- stays compatible,
/// so the caller keeps judging.
fn cond_contexts_compatible(a: &[CondFrame], b: &[CondFrame]) -> bool {
    for (fa, fb) in a.iter().zip(b.iter()) {
        if fa.construct == fb.construct || fa.text == fb.text {
            if fa.segment != fb.segment {
                return false;
            }
        } else {
            return true;
        }
    }
    true
}

pub struct SpecCheck {
    mini_mode: bool,
    macro_re: Regex,
    patch_re: Regex,
    applied_patch_rpm420_re: Regex,
    applied_patch_re: Regex,
    applied_patch_p_re: Regex,
    applied_patch_pipe_re: Regex,
    applied_patch_i_re: Regex,
    obsolete_tags_re: Regex,
    packager_re: Regex,
    buildarch_re: Regex,
    buildprereq_re: Regex,
    prereq_re: Regex,
    suse_version_re: Regex,
    make_check_re: Regex,
    rpm_buildroot_re: Regex,
    libdir_re: Regex,
    description_lang_re: Regex,
    section_res: Vec<(String, Regex)>,
    deprecated_grep_re: Regex,
    tmpfiles_macro_re: Regex,
    /// Required: spec parsing shells out to `rpm`.
    rpm: Tool,
    depscript_override_re: Regex,
    depgen_disable_re: Regex,
    patch_fuzz_override_re: Regex,
    requires_re: Regex,
    provides_re: Regex,
    obsoletes_re: Regex,
    conflicts_re: Regex,
    declarative_re: Regex,
    summary_re: Regex,
    compop_re: Regex,
    setup_re: Regex,
    autosetup_re: Regex,
    autosetup_n_re: Regex,
    autopatch_re: Regex,
    patch_applying_macros: Vec<String>,
    filelist_re: Regex,
    pkgname_re: Regex,
    python_setup_test_re: Regex,
    python_setup_install_re: Regex,
    python_module_def_re: Regex,
    python_sitelib_glob_re: Regex,
    shared_dir_glob_re: Regex,
    suse_update_desktop_file_re: Regex,
    license_token_re: Regex,
    file_qualifier_re: Regex,
    with_macro_empty_re: Regex,
    cmake_kf_re: Regex,
    build_testing_re: Regex,
    // Per-package state (`_default_state`).
    spec_file: Option<String>,
    spec_name: Option<String>,
    patches: BTreeMap<i64, String>,
    applied_patches: Vec<i64>,
    patches_auto_applied: bool,
    depscript_override: bool,
    depgen_disabled: bool,
    patch_fuzz_override: bool,
    section: BTreeMap<String, u32>,
    declarative: bool,
    current_section: String,
    current_package: Option<String>,
    package_noarch: BTreeMap<Option<String>, Vec<Vec<CondFrame>>>,
    /// Conditional context of the line being walked: one frame per
    /// enclosing `%if`-family directive, outermost first. Maintained
    /// by `checkline_cond_stack` ahead of the other per-line scans.
    cond_stack: Vec<CondFrame>,
    /// Id source for `CondFrame::construct`; reset per spec.
    cond_next_construct: u64,
    spec_only: bool,
    license_sections: Vec<FilesSectionScan>,
    license_section: Option<FilesSectionScan>,
    /// The walker is in a preamble region (the main preamble, or a
    /// `%package` preamble): the only regions whose `License:` and
    /// `Source` lines are tags rather than body text.
    license_preamble: bool,
    license_tag_seen: bool,
    license_tags_public_domain: bool,
    license_in_install: bool,
    license_install_dests: Vec<String>,
    /// A `%install` line continued with a trailing backslash: the
    /// partial logical line, scanned once its continuation arrives.
    license_install_join: String,
    archive_source_seen: bool,
    packaged_source_seen: bool,
    /// #1019: shell-section lines and whole-spec facts for the
    /// deferred exit-status analysis (`flush_check_soundness`).
    body_lines: Vec<BodyLine>,
    prev_section: String,
    section_instance: u32,
    saw_cmake_kf: bool,
    build_testing_on: bool,
    install_post_nil: bool,
    // Silent-constructs scan (#1020) state.
    sc_defines: Vec<(String, String)>,
    sc_main_name: Option<String>,
    sc_version: Option<String>,
    sc_release: Option<String>,
    sc_pkg_headers: Vec<SilentPkgHeader>,
    sc_files_names: Vec<String>,
    sc_files_short: Vec<String>,
    sc_python_files: Vec<String>,
    sc_python_files_all: bool,
    sc_has_include: bool,
    sc_files_generated: bool,
    sc_files_unresolved: bool,
    sc_kmp: bool,
    sc_section: String,
    sc_non_shell_scriptlet: bool,
    sc_name_toks: [Option<String>; 3],
    sc_name_conflict: [bool; 3],
    sc_in_single: bool,
    sc_single_ansi: bool,
    sc_in_double: bool,
    sc_ctx: Vec<bool>,
    sc_heredocs: Vec<(String, bool, bool)>,
    sc_continuation: bool,
    sc_if_stack: Vec<bool>,
    sc_macro_open: bool,
    sc_candidates: Vec<(u32, String, String, bool)>,
    sc_assigned: Vec<String>,
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
        Self {
            mini_mode: config.mini_mode,
            macro_re: macro_regex().clone(),
            patch_re: patch_re().clone(),
            applied_patch_rpm420_re: applied_patch_rpm420_re().clone(),
            applied_patch_re: applied_patch_re().clone(),
            applied_patch_p_re: applied_patch_p_re().clone(),
            applied_patch_pipe_re: applied_patch_pipe_re().clone(),
            applied_patch_i_re: applied_patch_i_re().clone(),
            obsolete_tags_re: obsolete_tags_re().clone(),
            packager_re: packager_re().clone(),
            buildarch_re: buildarch_re().clone(),
            buildprereq_re: buildprereq_re().clone(),
            prereq_re: prereq_re().clone(),
            suse_version_re: suse_version_re().clone(),
            make_check_re: make_check_re().clone(),
            rpm_buildroot_re: rpm_buildroot_re().clone(),
            libdir_re: libdir_re().clone(),
            description_lang_re: description_lang_re().clone(),
            section_res: section_res(),
            deprecated_grep_re: deprecated_grep_re().clone(),
            tmpfiles_macro_re: tmpfiles_macro_re().clone(),
            depscript_override_re: depscript_override_re().clone(),
            depgen_disable_re: depgen_disable_re().clone(),
            patch_fuzz_override_re: patch_fuzz_override_re().clone(),
            requires_re: requires_re().clone(),
            provides_re: provides_re().clone(),
            obsoletes_re: obsoletes_re().clone(),
            conflicts_re: conflicts_re().clone(),
            declarative_re: declarative_re().clone(),
            summary_re: summary_re().clone(),
            compop_re: compop_re().clone(),
            setup_re: setup_re().clone(),
            autosetup_re: autosetup_re().clone(),
            autosetup_n_re: autosetup_n_re().clone(),
            autopatch_re: autopatch_re().clone(),
            patch_applying_macros,
            filelist_re: filelist_re().clone(),
            pkgname_re: pkgname_re().clone(),
            python_setup_test_re: python_setup_test_re().clone(),
            python_setup_install_re: python_setup_install_re().clone(),
            python_module_def_re: python_module_def_re().clone(),
            python_sitelib_glob_re: python_sitelib_glob_re().clone(),
            shared_dir_glob_re: shared_dir_glob_re().clone(),
            suse_update_desktop_file_re: suse_update_desktop_file_re().clone(),
            license_token_re: license_token_re().clone(),
            file_qualifier_re: file_qualifier_re().clone(),
            with_macro_empty_re: with_macro_empty_re().clone(),
            cmake_kf_re: cmake_kf_re().clone(),
            build_testing_re: build_testing_re().clone(),
            spec_file: None,
            spec_name: None,
            patches: BTreeMap::new(),
            applied_patches: Vec::new(),
            patches_auto_applied: false,
            depscript_override: false,
            depgen_disabled: false,
            patch_fuzz_override: false,
            section: BTreeMap::new(),
            declarative: false,
            current_section: "package".to_string(),
            current_package: None,
            package_noarch: BTreeMap::new(),
            cond_stack: Vec::new(),
            cond_next_construct: 0,
            spec_only: false,
            license_sections: Vec::new(),
            license_section: None,
            license_preamble: true,
            license_tag_seen: false,
            license_tags_public_domain: true,
            license_in_install: false,
            license_install_dests: Vec::new(),
            license_install_join: String::new(),
            archive_source_seen: false,
            packaged_source_seen: false,
            body_lines: Vec::new(),
            prev_section: "package".to_string(),
            section_instance: 0,
            saw_cmake_kf: false,
            build_testing_on: false,
            install_post_nil: false,
            sc_defines: Vec::new(),
            sc_main_name: None,
            sc_version: None,
            sc_release: None,
            sc_pkg_headers: Vec::new(),
            sc_files_names: Vec::new(),
            sc_files_short: Vec::new(),
            sc_python_files: Vec::new(),
            sc_python_files_all: false,
            sc_has_include: false,
            sc_files_generated: false,
            sc_files_unresolved: false,
            sc_kmp: false,
            sc_section: "package".to_string(),
            sc_non_shell_scriptlet: false,
            sc_name_toks: [None, None, None],
            sc_name_conflict: [false; 3],
            sc_in_single: false,
            sc_single_ansi: false,
            sc_in_double: false,
            sc_ctx: Vec::new(),
            sc_heredocs: Vec::new(),
            sc_continuation: false,
            sc_if_stack: Vec::new(),
            sc_macro_open: false,
            sc_candidates: Vec::new(),
            sc_assigned: Vec::new(),
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

/// The grounds on which a payload spec's file name is consistent
/// with the package, judged separately because `check_source`'s
/// selection prefers the header ground over the declared one.
struct NameVerdict {
    /// The file is named after the source RPM's header name — the
    /// container OBS names after the build job, so a payload file
    /// carrying it is the ordinary case.
    header: bool,
    /// The file is named after a name the spec's own `Name:`
    /// declarations can produce: a multibuild spec declares one
    /// name per flavour branch while the payload file keeps one of
    /// the declared names (util-linux-systemd and python-libmount
    /// both carry util-linux.spec).
    declared: bool,
}

impl NameVerdict {
    /// The file is inconsistent only when it matches neither name.
    fn consistent(&self) -> bool {
        self.header || self.declared
    }
}

/// Judge a payload spec's file name on both grounds. A declaration
/// whose expansion the preamble cannot determine produces an
/// unconstrained pattern, which constrains nothing and is set
/// aside; the remaining declarations judge the declared ground.
/// The header ground decides alone when no declaration constrains
/// the name — a preamble declaring no `Name:`, every declaration
/// unconstrained, or a payload file that cannot be opened.
fn spec_name_verdict(
    pkg: &Pkg,
    f: &crate::pkg::pkgfile::PkgFile,
    spec: Option<&SpecPkg>,
) -> NameVerdict {
    let header = f.name == format!("{}.spec", pkg.name);
    let declared = spec
        .and_then(|spec| spec.declared_name_patterns())
        .map(|patterns| {
            let stem = f.name.strip_suffix(".spec").unwrap_or(&f.name);
            patterns
                .iter()
                .filter(|p| !p.is_unconstrained())
                .any(|p| p.matches(stem))
        })
        .unwrap_or(false);
    NameVerdict { header, declared }
}

impl Check for SpecCheck {
    fn name(&self) -> &'static str {
        "SpecCheck"
    }

    /// `check_source`: find the spec file in the SRPM's file list and run
    /// the spec checks on it.
    fn check_source(&mut self, pkg: &Pkg, config: &Config, out: &mut Filter) {
        // Verdict and selection are separate computations over the
        // same per-file judgements: the verdict judges every `.spec`
        // file in the source (the finding fires when none of them is
        // consistent on either ground), the selection picks the file
        // the spec checks run on — the first the header names, else
        // the first a declaration names, else the last. Each payload
        // spec is opened once, for its verdict; the selection reuses
        // that opened spec. The selection considers only specs that
        // opened, in each tier — header-named first, then
        // declaration-named, then the last readable one — so a payload
        // file that vanished between the SRPM listing and the read
        // leaves its tier to a readable file.
        let scans: Vec<(&crate::pkg::pkgfile::PkgFile, Option<SpecPkg>, NameVerdict)> = pkg
            .files
            .iter()
            .filter(|f| f.name.ends_with(".spec"))
            .map(|f| {
                let spec = SpecPkg::open(Path::new(&f.path)).ok();
                let verdict = spec_name_verdict(pkg, f, spec.as_ref());
                (f, spec, verdict)
            })
            .collect();

        if scans.is_empty() {
            add_info(out, Level::Error, pkg, "no-spec-file", &[]);
        }
        if !scans.is_empty() && scans.iter().all(|(_, _, verdict)| !verdict.consistent()) {
            add_info(out, Level::Error, pkg, "invalid-spec-name", &[]);
        }

        let selected = scans
            .iter()
            .filter(|(_, spec, _)| spec.is_some())
            .find(|(_, _, verdict)| verdict.header)
            .or_else(|| {
                scans
                    .iter()
                    .filter(|(_, spec, _)| spec.is_some())
                    .find(|(_, _, verdict)| verdict.declared)
            })
            .or_else(|| scans.iter().filter(|(_, spec, _)| spec.is_some()).last());
        if let Some((f, Some(spec_pkg), _)) = selected {
            self.spec_name = Some(f.name.clone());
            self.check_spec(spec_pkg, config, out);
        }
    }

    /// `check_spec`: run the spec checks over a `.spec` input.
    fn check_spec(&mut self, pkg: &SpecPkg, config: &Config, out: &mut Filter) {
        // `error_details` for `-v`/`--explain`, set in `__init__` in the
        // reference.
        Self::register_error_details(config, out);

        self.spec_file = Some(pkg.name.clone());

        if !pkg.utf8 {
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
        self.flush_license_marking(pkg, out);
        self.flush_check_soundness(pkg, out);
        self.flush_silent_constructs(pkg, out);
        if !self.declarative {
            for sec in ["prep", "build", "install", "check"] {
                if self.section.get(sec).copied().unwrap_or(0) == 0 {
                    let check = format!("no-%{sec}-section");
                    // Deliberate divergence (#593): a missing %check
                    // section is advisory (info); the other missing
                    // sections stay warnings.
                    let level = if sec == "check" {
                        Level::Info
                    } else {
                        Level::Warning
                    };
                    self.info(out, pkg, level, &check, &[]);
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
            let parse_failure_reported = self.check_specfile_error(pkg, out);
            self.check_invalid_url(pkg, out, parse_failure_reported);
            self.check_parse_time_cpu_count(pkg, out);
        }
    }

    fn reset(&mut self) {
        self.spec_file = None;
        self.spec_name = None;
        self.patches.clear();
        self.applied_patches.clear();
        self.patches_auto_applied = false;
        self.depscript_override = false;
        self.depgen_disabled = false;
        self.patch_fuzz_override = false;
        self.section.clear();
        self.declarative = false;
        self.current_section = "package".to_string();
        self.current_package = None;
        self.package_noarch.clear();
        self.cond_stack.clear();
        self.cond_next_construct = 0;
        self.spec_only = false;
        self.license_sections.clear();
        self.license_section = None;
        self.license_preamble = true;
        self.license_tag_seen = false;
        self.license_tags_public_domain = true;
        self.license_in_install = false;
        self.license_install_dests.clear();
        self.license_install_join.clear();
        self.archive_source_seen = false;
        self.packaged_source_seen = false;
        self.body_lines.clear();
        self.prev_section = "package".to_string();
        self.section_instance = 0;
        self.saw_cmake_kf = false;
        self.build_testing_on = false;
        self.install_post_nil = false;
        self.sc_defines.clear();
        self.sc_main_name = None;
        self.sc_version = None;
        self.sc_release = None;
        self.sc_pkg_headers.clear();
        self.sc_files_names.clear();
        self.sc_files_short.clear();
        self.sc_python_files.clear();
        self.sc_python_files_all = false;
        self.sc_has_include = false;
        self.sc_files_generated = false;
        self.sc_files_unresolved = false;
        self.sc_kmp = false;
        self.sc_section = "package".to_string();
        self.sc_non_shell_scriptlet = false;
        self.sc_name_toks = [None, None, None];
        self.sc_name_conflict = [false; 3];
        self.sc_reset_shell();
        self.sc_candidates.clear();
        self.sc_assigned.clear();
    }
}

impl SpecCheck {
    /// Parse the spec with the `rpm` tool and forward its diagnostics
    /// (`SpecCheck.py:300-322`). Returns whether a fatal parse failure
    /// is reported by a `specfile-error` finding that survives the
    /// filter: the child signals a fatal failure with a non-zero exit
    /// or its `can't parse` summary line, and the surviving count is
    /// the `results()` delta around the forwarding below, so a finding
    /// the filter suppresses counts as unreported. The caller uses
    /// this to tell a parse failure reported here from one only the
    /// spec parser saw.
    fn check_specfile_error(&self, pkg: &SpecPkg, out: &mut Filter) -> bool {
        let spec_file = self.spec_file.as_deref().unwrap_or("");
        let define = format!("_sourcedir {}", self.spec_file_dir());
        // The reference lets a missing `rpm` raise here (no try/except around
        // the subprocess). Skipping is this project's standing treatment for an
        // absent tool -- see the PostCheck interpreter and BashismsCheck
        // checkbashisms entries -- and keeps a missing rpm from aborting the
        // whole run instead of one check.
        let Some(mut cmd) = self.rpm.command() else {
            return false;
        };
        let output = cmd
            .args(["-q", "--qf=", "-D", &define, "--specfile", spec_file])
            .env("LC_ALL", "en_US.UTF-8")
            .env("LANGUAGE", "en_US")
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .output()
            .expect("the rpm binary is required for the specfile-error check");
        let fatal_exit = !output.status.success();
        let stderr = match String::from_utf8(output.stderr) {
            Ok(stderr) => stderr,
            Err(e) => {
                // Level follows specfile-error's temporary W levelling
                // (issue #699, pending #702; see the stderr loop below).
                self.info(
                    out,
                    pkg,
                    Level::Warning,
                    "specfile-error",
                    &[&e.to_string()],
                );
                // An undecodable stderr reports an encoding failure of
                // the child's output, a distinct finding from a parse
                // failure: the parse-failure fallback stays armed.
                return false;
            }
        };
        let fatal = fatal_exit || stderr.lines().any(|line| line.contains("can't parse"));
        let count_errors = |out: &Filter| {
            out.results()
                .iter()
                .filter(|(check, _)| check == "specfile-error")
                .count()
        };
        let errors_before = count_errors(out);
        for line in stderr.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.contains("warning:") {
                self.info(out, pkg, Level::Warning, "specfile-warning", &[line]);
            } else {
                // TEMPORARY W (issue #699 levelling pass, ledgered in
                // tests/parity/divergences.toml): pending #702, which
                // gives the spec parser the distro macro context (Factory
                // prjconf plus the macro-providing packages). The
                // 20261018 Factory sweep's 22,528 firings across 6,876
                // srcpkgs are overwhelmingly missing-context artefacts
                // (unknown tags for macros the parse environment lacks),
                // not broken specs; at E they would fail about 40% of
                // Factory under the #699 exit doctrine.
                self.info(out, pkg, Level::Warning, "specfile-error", &[line]);
            }
        }
        fatal && count_errors(out) > errors_before
    }

    /// Check `Source`/`Patch` URLs via the spec parser (`_check_invalid_url`).
    /// Uses librpm's `Spec::parse` — the same C parser the reference reaches
    /// through `TransactionSet().parseSpec` — so the expanded source URLs
    /// match.
    fn check_invalid_url(&self, pkg: &SpecPkg, out: &mut Filter, parse_failure_reported: bool) {
        use librpm::build::SpecFlags;
        let spec_file = self.spec_file.as_deref().unwrap_or("");
        let _ = pkg_init();
        // The define, the parse, the pop, the source iteration below and
        // the parsed spec's drop at the end of the check all touch
        // process-global librpm state, so the macro lock is held for the
        // whole check: no sibling worker's sequence interleaves with any
        // of it. `parsed` is declared after the guard so it drops first.
        let _macro_guard = crate::pkg::global_macro_lock();
        let macros = librpm::macro_context::MacroContext::default();
        let _ = macros.define(&format!("_sourcedir {}", self.spec_file_dir()), 0);
        let parsed =
            librpm::build::Spec::parse(spec_file, SpecFlags::ANYARCH | SpecFlags::FORCE, None);
        let _ = macros.pop("_sourcedir");
        let Some(parsed) = parsed else {
            // The reference also reports librpm's error text here, which
            // `Spec::parse` does not surface (ledgered). When the `rpm`
            // child already reported this fatal parse failure with a
            // finding that survived the filter, that report is the
            // only one: the fallback detail is the bare spec path,
            // so emitting it too would state the same failure twice
            // (ledgered). The level is specfile-error's temporary W
            // (issue #699, pending #702).
            if !parse_failure_reported {
                self.info(out, pkg, Level::Warning, "specfile-error", &[spec_file]);
            }
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
            if scheme.is_none() {
                // A bare filename is not a URL and is not required to be
                // one: nothing to validate. Deliberate divergence from the
                // reference _check_invalid_url (ledgered).
                continue;
            }
            if netloc.is_none() {
                let tag = format!("{tag}:");
                self.info(out, pkg, Level::Warning, "invalid-url", &[&tag, url]);
            }
        }
    }

    /// Check for job-count macros that expand to a literal CPU count
    /// while the spec is parsed (`parse-time-cpu-count`).
    ///
    /// `%jobs`, `%_smp_build_ncpus` and `%_smp_build_nthreads` expand at
    /// parse time, so the parsing machine's CPU count is stored in the
    /// source rpm -- and, through the source digest every binary rpm
    /// records, in the binaries. The run-time forms (`%{?_smp_mflags}`,
    /// `%make_build`, `${RPM_BUILD_NCPUS}` in shell) only resolve when
    /// the build script runs. To tell the two apart the spec is parsed
    /// once more with the three macros defined to a sentinel value:
    /// each line of the parsed spec text that contains the sentinel
    /// stored a parse-time CPU count. Parsing (rather than scanning the
    /// raw text) is what keeps dead `%if` branches, `%define` bodies,
    /// escaped `%%jobs` and constant `%{?jobs:-n 4}` bodies silent.
    fn check_parse_time_cpu_count(&self, pkg: &SpecPkg, out: &mut Filter) {
        use librpm::build::SpecFlags;
        // A sentinel already present in the raw spec would also match
        // the literal text, not just macro expansions, so use the first
        // candidate the raw spec does not contain.
        let sentinel = [
            "7919", "17919", "27919", "37919", "47919", "57919", "67919", "77919", "87919", "97919",
        ]
        .into_iter()
        .find(|cand| !pkg.lines.iter().any(|line| line.contains(*cand)))
        .unwrap_or("7919");
        let spec_file = self.spec_file.as_deref().unwrap_or("");
        let _ = pkg_init();
        // The probe, the defines, the parse, the section read, the
        // pops and the parsed spec's drop all touch process-global
        // librpm state, so the macro lock is held for the whole
        // sequence, exactly as in `check_invalid_url`. `parsed` is
        // declared after the guard so it drops first.
        let _macro_guard = crate::pkg::global_macro_lock();
        // The re-parse is internal machinery: its only output is the
        // findings below, and the spec's parse diagnostics are already
        // reported from the `rpm` child's output in
        // `check_specfile_error`. librpm logs through rpmlog while
        // parsing -- a macro a previous parse left defined in the
        // global context makes it warn about macros expanded in
        // comments, for example -- so the whole sequence runs with
        // rpmlog masked to critical, the treatment
        // `SignatureCheck`'s verified reads use. The mask is declared
        // after the macro guard so it drops before the lock is
        // released.
        let _rpmlog_mask = crate::pkg::RpmlogMask::hush();
        let macros = librpm::macro_context::MacroContext::default();
        let _ = macros.define(&format!("_sourcedir {}", self.spec_file_dir()), 0);
        // Snapshot the effective state of the three judged macros.
        // A parse pushes the spec's own defines of them into the
        // global context, where they outlive the parse, and one of
        // this check's pops could then remove the spec's entry
        // instead of the sentinel, stranding the sentinel in the
        // context. The state found here is restored before leaving,
        // so the check leaves the context as it found it.
        let expansion = |name: &str| macros.expand(&format!("%{{?{name}}}")).unwrap_or_default();
        let before = [
            ("jobs", expansion("jobs")),
            ("_smp_build_ncpus", expansion("_smp_build_ncpus")),
            ("_smp_build_nthreads", expansion("_smp_build_nthreads")),
        ];
        // A distribution macro file may already map `%jobs` to the
        // run-time `${RPM_BUILD_NCPUS}`; a sentinel define would shadow
        // that mapping and report the run-time form as a parse-time
        // one. Probe the expansion before defining anything and leave
        // `jobs` alone when it already expands to `${RPM_BUILD_NCPUS}`.
        // A spec's own `%define jobs ...` needs no probe: defined at
        // spec level, it overrides the sentinel (see below) by itself.
        let jobs_is_run_time = before[0].1.trim() == "${RPM_BUILD_NCPUS}";
        // Level -7 is RMIL_CMDLINE, the level `rpmspec --define`
        // uses: above the macro files (-13), so the sentinel replaces
        // the host's own job-count definitions, but below the spec's
        // `%define` (-3) and `%global` (0), so a spec that defines
        // these macros itself keeps its own expansion.
        let _ = macros.define(&format!("_smp_build_ncpus {sentinel}"), -7);
        let _ = macros.define(&format!("_smp_build_nthreads {sentinel}"), -7);
        if !jobs_is_run_time {
            let _ = macros.define(&format!("jobs {sentinel}"), -7);
        }
        let parsed =
            librpm::build::Spec::parse(spec_file, SpecFlags::ANYARCH | SpecFlags::FORCE, None);
        if !jobs_is_run_time {
            let _ = macros.pop("jobs");
        }
        let _ = macros.pop("_smp_build_nthreads");
        let _ = macros.pop("_smp_build_ncpus");
        // Restore the snapshotted state of the judged macros: pop
        // entries the sequence added (a spec define of one of them,
        // or a sentinel the pops above did not reach) until the
        // incoming expansion is effective again.
        for (name, target) in &before {
            for _ in 0..16 {
                if expansion(name) == *target || !macros.is_defined(name) {
                    break;
                }
                let _ = macros.pop(name);
            }
            if expansion(name) != *target && !target.is_empty() {
                let _ = macros.define(&format!("{name} {target}"), -7);
            }
        }
        let _ = macros.pop("_sourcedir");
        let Some(parsed) = parsed else {
            // A spec that does not parse is already reported through
            // `specfile-error`; there is no parsed text to judge.
            return;
        };
        let Some(text) = parsed.get_section(librpm::build::Section::NONE) else {
            return;
        };
        for line in text.lines() {
            if line.contains(sentinel) {
                self.info(
                    out,
                    pkg,
                    Level::Warning,
                    "parse-time-cpu-count",
                    &[line.trim()],
                );
            }
        }
    }

    fn check_line(&mut self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        self.checkline_cond_stack(line);
        self.checkline_silent_constructs(pkg, out, line);
        self.checkline_declarative(line);
        self.checkline_break_space(pkg, out, line);
        self.checkline_license_marking(pkg, line);
        if self.checkline_section(pkg, out, line) {
            return;
        }
        self.note_body_line(pkg, line);
        self.checkline_buildroot_usage(pkg, out, line);
        self.checkline_make_check(pkg, out, line);
        self.checkline_setup(pkg, out, line);
        self.checkline_autopatch(pkg, out, line);
        self.checkline_patch_applying_macros(pkg, out, line);
        self.checkline_applied_patch(pkg, out, line);
        self.checkline_package(pkg, out, line);
        self.checkline_changelog(pkg, out, line);
        self.checkline_files(pkg, out, line);
        self.checkline_deprecated_grep(pkg, out, line);
        self.checkline_obsolete_tmpfiles_macro(pkg, out, line);
        self.checkline_macros_in_comments(pkg, out, line);
        self.checkline_python_setup_test(pkg, out, line);
        self.checkline_python_setup_install(pkg, out, line);
        self.checkline_python_module_def(pkg, out, line);
        self.checkline_python_sitelib_glob(pkg, out, line);
        self.checkline_shared_dir_glob(pkg, out, line);
        self.checkline_with_macro_empty(pkg, out, line);
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
            // In %build and %prep, a line whose buildroot references all
            // lead assignment values (`DESTDIR=%{buildroot}`,
            // `--prefix=$RPM_BUILD_ROOT/usr`, ...) states the install
            // destination for the build system -- the working idiom of
            // those sections -- and is not charged. Scriptlet sections
            // keep the charge in every form: a scriptlet runs on the
            // installed system, where the buildroot does not exist.
            if (self.current_section == "build" || self.current_section == "prep")
                && buildroot_refs_are_install_assignments(line)
            {
                return;
            }
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
                    .entry(self.current_package.clone())
                    .or_default()
                    .push(self.cond_stack.clone());
            }
        }
    }

    fn checkline_package_packager(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.packager_re.captures(line) {
            let value = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            self.info(out, pkg, Level::Warning, "hardcoded-packager-tag", &[value]);
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
            self.info(out, pkg, Level::Warning, "prereq-use", &[value]);
        }
    }

    fn checkline_package_buildprereq(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.buildprereq_re.captures(line) {
            let value = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            self.info(out, pkg, Level::Error, "buildprereq-use", &[value]);
        }
    }

    /// Shared body of the `Requires:`/`Provides:`/`Obsoletes:`/`Conflicts:`
    /// line checks: `forbidden-controlchar-found` plus
    /// `comparison-operator-in-deptoken`.
    fn checkline_dep_list(&self, pkg: &SpecPkg, out: &mut Filter, tag: &str, raw: &str) {
        // Perf: most dep lines are plain names with no comparison operators.
        // Probe the raw string first so the `parse_deps` allocation is
        // skipped when no `comparison-operator-in-deptoken` finding can fire
        // (a token match implies a raw-string match). The
        // forbidden-controlchar check only ever examines the first token,
        // so it keeps a cheap probe of its own.
        if self.compop_re.is_match(raw).unwrap_or(false) {
            let deps = parse_deps(raw);
            if let Some(token) = has_forbidden_controlchars_deps(&deps) {
                let detail = format!("{tag}: {token}");
                self.info(
                    out,
                    pkg,
                    Level::Error,
                    "forbidden-controlchar-found",
                    &[&detail],
                );
            }
            for (dep, version) in &deps {
                // Rich expressions contain comparison operators as syntax
                // (`>=` in `(baz >= 1.0 with baz < 2.0)`); the regex would
                // false-positive on them, so they are skipped.
                if version.is_none()
                    && !is_rich_dep_expr(dep)
                    && !is_parenthesized_versioned(dep)
                    && self.compop_re.is_match(dep).unwrap_or(false)
                {
                    self.info(
                        out,
                        pkg,
                        Level::Warning,
                        "comparison-operator-in-deptoken",
                        &[dep],
                    );
                }
            }
        } else if let Some(token) = first_dep_token(raw).and_then(has_forbidden_controlchars) {
            let detail = format!("{tag}: {token}");
            self.info(
                out,
                pkg,
                Level::Error,
                "forbidden-controlchar-found",
                &[&detail],
            );
        }
    }

    fn checkline_package_requires(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.requires_re.captures(line) {
            self.checkline_dep_list(
                pkg,
                out,
                "Requires",
                caps.get(1).map(|m| m.as_str()).unwrap_or(""),
            );
        }
    }

    fn checkline_package_provides(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.provides_re.captures(line) {
            self.checkline_dep_list(
                pkg,
                out,
                "Provides",
                caps.get(1).map(|m| m.as_str()).unwrap_or(""),
            );
        }
    }

    fn checkline_package_obsoletes(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.obsoletes_re.captures(line) {
            self.checkline_dep_list(
                pkg,
                out,
                "Obsoletes",
                caps.get(1).map(|m| m.as_str()).unwrap_or(""),
            );
        }
    }

    fn checkline_package_conflicts(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.conflicts_re.captures(line) {
            self.checkline_dep_list(
                pkg,
                out,
                "Conflicts",
                caps.get(1).map(|m| m.as_str()).unwrap_or(""),
            );
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

    /// Track the `%if`-family nesting of the raw-line walk: one
    /// `CondFrame` per enclosing directive. A directive spelled in a
    /// comment never reaches here as one (its first word starts with
    /// `#`); a directive inside a macro body or a text section is
    /// tracked like any other line, the same exposure the reference's
    /// own line walk has.
    fn checkline_cond_stack(&mut self, line: &str) {
        let trimmed = line.trim();
        let first_word = trimmed.split_whitespace().next().unwrap_or("");
        match first_word {
            "%if" | "%ifarch" | "%ifnarch" | "%ifos" | "%ifnos" | "%ifdef" | "%ifndef"
            | "%ifexpr" => {
                self.cond_next_construct += 1;
                self.cond_stack.push(CondFrame {
                    construct: self.cond_next_construct,
                    text: trimmed.split_whitespace().collect::<Vec<_>>().join(" "),
                    segment: 0,
                });
            }
            "%elif" | "%elifarch" | "%elifnarch" | "%elifos" | "%elifnos" => {
                if let Some(top) = self.cond_stack.last_mut() {
                    top.segment = top.segment.saturating_add(1);
                }
            }
            "%else" => {
                if let Some(top) = self.cond_stack.last_mut() {
                    top.segment = u32::MAX;
                }
            }
            "%endif" => {
                self.cond_stack.pop();
            }
            _ => {}
        }
    }

    fn checkline_files(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if self.current_section != "files" {
            return;
        }
        // A `BuildArch: noarch` counts only where it can hold in the
        // same build as this line. The candidates are the package's
        // own declarations plus the main package's (a subpackage
        // inherits the main `BuildArch` unless its own declaration's
        // branch is the taken one), each with the conditional context
        // it was declared under. A declaration in the opposite branch
        // of a shared condition (the `_multibuild` flavour shape)
        // never applies to the line.
        let mut decls: Vec<&Vec<CondFrame>> = Vec::new();
        if let Some(own) = self.package_noarch.get(&self.current_package) {
            decls.extend(own.iter());
        }
        if self.current_package.is_some()
            && let Some(main) = self.package_noarch.get(&None)
        {
            decls.extend(main.iter());
        }
        let noarch = decls
            .iter()
            .any(|decl| cond_contexts_compatible(decl, &self.cond_stack));
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

    /// Licence-marking scan (#821): collect per-`%files`-section state
    /// line by line. Runs before `checkline_section` so it sees the
    /// header lines that call consumes; the boundary scan repeats its
    /// header patterns, so the sections judged here are the walker's
    /// sections. `License:`/`Source` collection runs in preamble
    /// regions only - in body sections the same text is prose, a
    /// changelog entry or a shell line, not a tag. `flush_license_marking`
    /// emits the findings.
    fn checkline_license_marking(&mut self, pkg: &SpecPkg, line: &str) {
        for (sec, re) in &self.section_res {
            if let Ok(Some(_)) = re.find(line) {
                if !self.license_install_join.is_empty() {
                    // A continuation left open at the section end:
                    // scan what was collected rather than drop it.
                    let pending = std::mem::take(&mut self.license_install_join);
                    self.license_install_dests
                        .extend(install_copy_docdirs(&pending));
                }
                // Tag collection is a preamble activity: a section
                // header ends it, a `%package` header opens the
                // next package's preamble.
                self.license_preamble = sec == "package";
                if let Some(scan) = self.license_section.take() {
                    self.license_sections.push(scan);
                }
                if sec == "files" {
                    self.license_section = Some(FilesSectionScan {
                        from_list_file: self.filelist_re.is_match(line).unwrap_or(false),
                        ..Default::default()
                    });
                }
                self.license_in_install = sec == "install";
                return;
            }
        }
        if self.license_in_install {
            // A trailing backslash joins the next physical line
            // into this command; scan the logical line once it is
            // complete.
            let mut logical = std::mem::take(&mut self.license_install_join);
            let line = line.strip_suffix('\n').unwrap_or(line);
            let line = line.strip_suffix('\r').unwrap_or(line);
            logical.push_str(line);
            let trailing = logical.bytes().rev().take_while(|b| *b == b'\\').count();
            if trailing % 2 == 1 {
                logical.pop();
                self.license_install_join = logical;
            } else {
                self.license_install_dests
                    .extend(install_copy_docdirs(&logical));
            }
        }
        if self.license_section.is_none() && self.license_preamble {
            let trimmed = line.trim_start();
            if let Some(value) = license_tag_value(trimmed) {
                self.license_tag_seen = true;
                if !license_value_is_public_domain_only(value) {
                    self.license_tags_public_domain = false;
                }
            } else if source_line_is_archive(trimmed) {
                self.archive_source_seen = true;
            }
            if source_line_is_packaged(trimmed) {
                self.packaged_source_seen = true;
            }
        }
        let Some(mut scan) = self.license_section.take() else {
            return;
        };
        self.scan_license_line(pkg, &mut scan, line);
        self.license_section = Some(scan);
    }

    /// Fold one `%files` body line into the section's scan state.
    fn scan_license_line(&self, pkg: &SpecPkg, scan: &mut FilesSectionScan, line: &str) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return;
        }
        // A standalone `#` token opens a trailing comment; the tokens
        // before it are the line's content.
        let tokens: Vec<&str> = line
            .split_whitespace()
            .take_while(|t| !t.starts_with('#'))
            .collect();
        let Some(&first) = tokens.first() else {
            return;
        };
        if first == "%doc" {
            let content = tokens.join(" ");
            if tokens[1..].iter().any(|t| {
                let base = t.rsplit('/').next().unwrap_or(t);
                name_carries_licence(base) || glob_prefix_carries_licence(base)
            }) {
                scan.doc_license = true;
            }
            let unqualified_hit = if scan.doc_license_unqualified.is_none()
                && !self.file_qualifier_re.is_match(&content).unwrap_or(false)
            {
                self.license_token_re.find(&content).ok().flatten()
            } else {
                None
            };
            if let Some(m) = unqualified_hit {
                let linenum = pkg.current_linenum.get().unwrap_or(0);
                // The match runs through the whitespace that ends
                // it; the finding's detail is the token alone.
                scan.doc_license_unqualified = Some((m.as_str().trim_end().to_string(), linenum));
            }
            self.scan_license_entries(scan, &tokens[1..], false, true);
            return;
        }
        if first == "%license" {
            // Presence requires the line to carry at least one
            // entry token: a bare `%license` line marks no file.
            if tokens.len() > 1 {
                scan.has_license_line = true;
            }
            self.scan_license_entries(scan, &tokens[1..], false, false);
            return;
        }
        match files_directive(first) {
            Some(FilesDirective::Entry) => {
                self.scan_license_entries(scan, &tokens[1..], false, false);
            }
            Some(FilesDirective::Dir) => {
                self.scan_license_entries(scan, &tokens[1..], true, false);
            }
            // `%ghost` entries carry no shipped content.
            Some(FilesDirective::Ghost) => {}
            None => {
                if unbraced_macro_name(first)
                    .is_some_and(|name| !FILES_DIRECTIVE_WORDS.contains(&name))
                {
                    // An unbraced generator macro (`%pyproject_files`)
                    // expands to entries the text scan cannot see.
                    scan.has_generator_macro = true;
                } else if !first.starts_with('%') || first.starts_with("%{") {
                    self.scan_license_entries(scan, &tokens, false, false);
                }
                // Any other `%`-led line carries no entries the scan
                // can judge.
            }
        }
    }

    /// Judge the entry tokens of one `%files` line for the
    /// licence-marking scan: a licence basename establishes presence,
    /// an explicit entry establishes that the shipped set is textually
    /// visible, a bare macro token marks it opaque.
    fn scan_license_entries(
        &self,
        scan: &mut FilesSectionScan,
        tokens: &[&str],
        force_dir: bool,
        doc_line: bool,
    ) {
        let mut dir_next = force_dir;
        for token in tokens {
            if *token == "%dir" {
                dir_next = true;
                continue;
            }
            if let Some(name) = unbraced_macro_name(token) {
                // A generator macro expands to entries the text scan
                // cannot see; a directive or qualifier word is skipped
                // (its argument rides on the same token for the
                // parenthesised forms, handled below).
                if !FILES_DIRECTIVE_WORDS.contains(&name) {
                    scan.has_generator_macro = true;
                }
                continue;
            }
            if token.starts_with('%') && !token.starts_with("%{") {
                // A qualifier or directive word; its argument rides on
                // the same token and the entries follow it.
                continue;
            }
            if is_bare_macro(token) {
                // A generator token is not a judged entry, so it does
                // not consume a pending `%dir` flag: the flag belongs
                // to the next judged entry, as it does across the
                // unbraced generator and qualifier tokens.
                scan.has_generator_macro = true;
                continue;
            }
            let is_dir = dir_next || token.ends_with('/');
            // A line led by `%dir` marks every token on it a
            // directory; the flag is the line's, not one token's.
            if !force_dir {
                dir_next = false;
            }
            if doc_line && is_dir {
                // A `%doc` directory argument ships the directory's
                // contents, none of which the spec text names.
                scan.has_indeterminate_doc = true;
            }
            if is_dir {
                continue;
            }
            let basename = token.rsplit('/').next().unwrap_or(token);
            if doc_line
                && !basename.contains('.')
                && token.contains('/')
                && !token.contains(['*', '?', '['])
                && !in_exec_location(token)
            {
                // A `%doc` path whose final component carries no
                // extension names a directory as often as a file;
                // the directory's contents are fixed by `%install`,
                // not by the spec text.
                scan.has_indeterminate_doc = true;
            }
            if doc_line
                && basename.contains(['*', '?', '['])
                && !glob_prefix_carries_licence(basename)
                && !glob_prefix_buries_licence_stem(basename)
            {
                // A `%doc` glob whose literal prefix reaches no
                // licence stem guarantees nothing about its matches:
                // the match set is what `%install` left behind, and
                // a licence file may be among it. A prefix that runs
                // a stem into a longer word is the buried-stem shape
                // instead: it shows the stem the names carry, so the
                // section stays decidable.
                scan.has_indeterminate_doc = true;
            }
            if name_carries_licence(basename) || glob_prefix_carries_licence(basename) {
                scan.plain_license_entry = true;
            }
            // An entry under a build-metadata directory (a file
            // inside a `*.dist-info` directory) marks the section
            // too: the build system assembled that tree.
            if token.split('/').any(is_info_entry) {
                scan.has_info_entry = true;
            }
            // An entry evidences a shipped file when it is glob-free
            // and either names a dotted file or sits in an exec
            // location; an extension-less entry elsewhere is a
            // directory name as often as a file name.
            let explicit = !token.contains(['*', '?', '['])
                && (basename.contains('.') || in_exec_location(token));
            if explicit {
                scan.explicit_entries += 1;
                if doc_line || in_doc_location(token) {
                    scan.explicit_doc_entries += 1;
                }
            }
        }
    }

    /// The anchor for the `%install` licence-copy route (#833): a
    /// recorded destination counts when the destination directory
    /// (the destination itself or one of its ancestors) appears as
    /// an entry in some `%files` section of the spec, so the
    /// directory the licence file was copied into is actually
    /// shipped. Lines that carry no shipped entries contribute no
    /// anchor: `%exclude` and `%ghost` lines carry no shipped
    /// content, a `%dir` line ships the directory alone and not the
    /// files copied into it, and `%docdir`, `%defattr` and
    /// conditional lines declare or guard entries rather than
    /// shipping any.
    fn install_dest_shipped(&self, pkg: &SpecPkg) -> bool {
        if self.license_install_dests.is_empty() {
            return false;
        }
        let mut shipped: Vec<&str> = Vec::new();
        let mut in_files = false;
        for line in &pkg.lines {
            let mut boundary = false;
            for (sec, re) in &self.section_res {
                if re.find(line).ok().flatten().is_some() {
                    in_files = sec == "files";
                    boundary = true;
                    break;
                }
            }
            if boundary {
                continue;
            }
            if !in_files {
                continue;
            }
            // A standalone `#` token opens a trailing comment; the
            // tokens before it are the line's content.
            let tokens: Vec<&str> = line
                .split_whitespace()
                .take_while(|t| !t.starts_with('#'))
                .collect();
            let Some(&first) = tokens.first() else {
                continue;
            };
            let directive: String = first
                .strip_prefix('%')
                .unwrap_or(first)
                .chars()
                .take_while(|c| c.is_ascii_alphabetic())
                .collect();
            if matches!(
                directive.as_str(),
                "exclude"
                    | "ghost"
                    | "dir"
                    | "docdir"
                    | "defattr"
                    | "if"
                    | "ifarch"
                    | "ifnarch"
                    | "ifos"
                    | "ifnos"
                    | "else"
                    | "endif"
            ) {
                continue;
            }
            shipped.extend(tokens.iter().map(|t| t.trim_end_matches('/')));
        }
        self.license_install_dests.iter().any(|dest| {
            let mut at = dest.as_str();
            loop {
                if shipped.contains(&at) {
                    return true;
                }
                match at.rsplit_once('/') {
                    Some((parent, _)) if !parent.is_empty() => at = parent,
                    _ => return false,
                }
            }
        })
    }

    /// Emit the licence-marking findings (#821) from the collected
    /// per-section state: `license-file-as-doc` per unconverted
    /// section, and `no-license-file-in-spec` when no licence file
    /// is marked in any section or installed by an `%install` copy
    /// (#833) and every section is textually decidable.
    fn flush_license_marking(&mut self, pkg: &SpecPkg, out: &mut Filter) {
        if let Some(scan) = self.license_section.take() {
            self.license_sections.push(scan);
        }
        let sections = std::mem::take(&mut self.license_sections);
        for scan in &sections {
            if scan.from_list_file || scan.has_generator_macro || scan.has_license_line {
                continue;
            }
            if let Some((token, linenum)) = &scan.doc_license_unqualified {
                pkg.current_linenum.set(Some(*linenum));
                self.info(out, pkg, Level::Warning, "license-file-as-doc", &[token]);
                pkg.current_linenum.set(None);
            }
        }
        if sections.is_empty() {
            return;
        }
        let presence = sections
            .iter()
            .any(|s| s.has_license_line || s.doc_license || s.plain_license_entry)
            || self.install_dest_shipped(pkg);
        let decidable = sections
            .iter()
            .all(|s| !s.from_list_file && !s.has_generator_macro && !s.has_indeterminate_doc);
        let explicit_entries: u32 = sections.iter().map(|s| s.explicit_entries).sum();
        let explicit_doc_entries: u32 = sections.iter().map(|s| s.explicit_doc_entries).sum();
        // Shapes whose shipped set the text scan cannot judge stay
        // silent: build systems that assemble the tree (an info-dir
        // entry rides in the sections), public-domain dedications
        // (no licence file exists), specs assembled from local files
        // (no archive source), and documentation-only packages.
        let auto_assembled = sections.iter().any(|s| s.has_info_entry) || self.packaged_source_seen;
        let public_domain_only = self.license_tag_seen && self.license_tags_public_domain;
        let documentation_only = explicit_entries > 0 && explicit_doc_entries == explicit_entries;
        if !presence
            && decidable
            && explicit_entries > 0
            && !auto_assembled
            && !public_domain_only
            && self.archive_source_seen
            && !documentation_only
        {
            self.info(out, pkg, Level::Error, "no-license-file-in-spec", &[]);
        }
    }

    fn checkline_deprecated_grep(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if ["package", "changelog", "description", "files"].contains(&self.current_section.as_str())
        {
            return;
        }
        let greps: Vec<String> = self
            .deprecated_grep_re
            .captures_iter(line)
            .filter_map(|r| r.ok())
            .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
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
        self.info(out, pkg, Level::Info, "obsolete-tmpfiles-macro", &[name]);
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
        // #482/#1026: rpm expands macros on a comment line before
        // treating it as a comment, so every unescaped macro mention
        // errors (see `comment_macro_mentions`), wherever in the
        // comment it sits.
        for token in comment_macro_mentions(comment) {
            self.info(out, pkg, Level::Error, "macro-in-comment", &[token]);
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

// ---------------------------------------------------------------------
// Silent constructs (#1020): three findings decided from the spec text
// alone, collected by a dedicated scan that runs alongside the line
// walker. `subpackage-without-files` is judged once the whole spec has
// been walked; `comment-in-continued-command` fires as the offending
// comment line is reached; `spec-tag-as-shell-variable` candidates are
// judged when their shell section ends, once the section's own
// assignments are all known.

/// One `%package` header, as collected for `subpackage-without-files`.
struct SilentPkgHeader {
    /// The header line exactly as written, trimmed.
    raw: String,
    linenum: u32,
    /// The expanded full package name, when it could be resolved.
    full: Option<String>,
    /// The expanded subpackage token (the part after the main package
    /// name), for the `%{python_files X}` coverage test.
    short: Option<String>,
}

/// Whether `section` is an install-time scriptlet section.
fn sc_is_scriptlet(section: &str) -> bool {
    RPM_SCRIPTLETS.contains(&section)
}

/// Whether the occurrence at byte `i` of `code` sits at command
/// position in its segment: every word before it in the segment is an
/// environment assignment or a shell keyword, so the word itself is
/// the command (or one of its leading assignments).
fn sc_at_command_position(code: &str, i: usize) -> bool {
    let seg_start = code[..i]
        .rfind([';', '&', '|', '('])
        .map(|p| p + 1)
        .unwrap_or(0);
    code[seg_start..i].split_whitespace().all(|w| {
        matches!(
            w,
            "while" | "until" | "do" | "then" | "else" | "elif" | "!" | "{" | "}"
        ) || w.split_once('=').is_some_and(|(name, _)| {
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    })
}

/// The interpreter a scriptlet header's `-p` flag names, when it
/// names one: `%post -p /bin/sh`, the glued `-p/bin/sh` included.
fn sc_header_interpreter(line: &str) -> Option<&str> {
    let mut words = line.split_whitespace();
    while let Some(w) = words.next() {
        if w == "-p" {
            return words.next();
        }
        if let Some(rest) = w.strip_prefix("-p")
            && !rest.is_empty()
        {
            return Some(rest);
        }
    }
    None
}

/// Whether `full` is a Python-flavoured package name for the no-arg
/// `%{python_files}` credit: `python-...`, or `python` followed by a
/// digit (`python3-...`, `python311-...`, `python3.11-...`).
fn sc_python_flavour_name(full: &str) -> bool {
    full.strip_prefix("python").is_some_and(|rest| {
        rest.starts_with('-') || rest.as_bytes().first().is_some_and(u8::is_ascii_digit)
    })
}

/// Whether `section` carries shell text: a build section or a
/// scriptlet.
fn sc_is_shell(section: &str) -> bool {
    matches!(section, "prep" | "build" | "install" | "check" | "clean") || sc_is_scriptlet(section)
}

/// Whether the word starting at `i` in `s` is exactly `word`, bounded
/// by a non-identifier character or the end of the string.
fn sc_word_at(s: &str, i: usize, word: &str) -> bool {
    if !s[i..].starts_with(word) {
        return false;
    }
    let after = i + word.len();
    after >= s.len()
        || !matches!(s.as_bytes()[after], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_')
}

impl SpecCheck {
    /// One pass of macro substitution over `s`: `%%` becomes a
    /// placeholder, `%{nil}` becomes empty, and known names (the
    /// `Name:`/`Version:`/`Release:` tags and single-line
    /// `%define`/`%global` values) are substituted. `None` when a
    /// construct stays unresolved (an unknown macro, a conditional or
    /// a braced form with arguments).
    fn sc_expand_once(&self, s: &str) -> Option<String> {
        let bytes = s.as_bytes();
        let mut out = String::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b'%' {
                let ch = s[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
                continue;
            }
            if i + 1 < bytes.len() && bytes[i + 1] == b'%' {
                out.push('\u{1}');
                i += 2;
                continue;
            }
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                let close = s[i + 2..].find('}').map(|p| p + i + 2)?;
                let inner = &s[i + 2..close];
                if inner.is_empty() || inner.contains([':', '?', '!', '(', ')', ' ', '\t']) {
                    return None;
                }
                out.push_str(&self.sc_macro_value(inner)?);
                i = close + 1;
                continue;
            }
            let start = i + 1;
            let mut end = start;
            while end < bytes.len()
                && matches!(bytes[end], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_')
            {
                end += 1;
            }
            if end == start {
                return None;
            }
            out.push_str(&self.sc_macro_value(&s[start..end])?);
            i = end;
        }
        Some(out)
    }

    /// The value a plain macro name expands to in the silent scan.
    fn sc_macro_value(&self, name: &str) -> Option<String> {
        match name {
            "nil" => Some(String::new()),
            "name" => self.sc_main_name.clone(),
            "version" => self.sc_version.clone(),
            "release" => self.sc_release.clone(),
            _ => self
                .sc_defines
                .iter()
                .rev()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone()),
        }
    }

    /// Expand `token` as far as the collected names allow; `None` when
    /// any macro reference stays unresolved.
    fn sc_expand(&self, token: &str) -> Option<String> {
        let mut cur = token.to_string();
        for _ in 0..10 {
            if !cur.contains('%') {
                return Some(cur.replace('\u{1}', "%"));
            }
            cur = self.sc_expand_once(&cur)?;
        }
        if cur.contains('%') {
            None
        } else {
            Some(cur.replace('\u{1}', "%"))
        }
    }

    /// Collect a `%package` header for `subpackage-without-files`.
    fn sc_collect_package_header(&mut self, line: &str, linenum: u32) {
        let rest = line
            .trim_start()
            .strip_prefix("%package")
            .unwrap_or("")
            .trim_start();
        let tokens: Vec<&str> = rest.split_whitespace().collect();
        let mut full_tok: Option<&str> = None;
        let mut short_tok: Option<&str> = None;
        let mut i = 0;
        while i < tokens.len() {
            let t = tokens[i];
            if t == "-n" {
                full_tok = tokens.get(i + 1).copied();
                i += 2;
                continue;
            }
            if t.starts_with('-') {
                i += 1;
                continue;
            }
            short_tok = Some(t);
            break;
        }
        let full_tok = full_tok.map(|t| {
            t.strip_prefix('"')
                .and_then(|t| t.strip_suffix('"'))
                .unwrap_or(t)
        });
        let short_tok = short_tok.map(|t| {
            t.strip_prefix('"')
                .and_then(|t| t.strip_suffix('"'))
                .unwrap_or(t)
        });
        if full_tok.is_none() && short_tok.is_none() {
            // A bare `%package` header is the main package's preamble.
            return;
        }
        let (full, short) = if let Some(ft) = full_tok {
            let full = self.sc_expand(ft);
            let short = match (&full, &self.sc_main_name) {
                (Some(f), Some(m)) => f.strip_prefix(&format!("{m}-")).map(|s| s.to_string()),
                _ => None,
            };
            (full, short)
        } else {
            let se = short_tok.and_then(|t| self.sc_expand(t));
            let full = match (&self.sc_main_name, &se) {
                (Some(m), Some(s)) => Some(format!("{m}-{s}")),
                _ => None,
            };
            (full, se)
        };
        self.sc_pkg_headers.push(SilentPkgHeader {
            raw: line.trim().to_string(),
            linenum,
            full,
            short,
        });
    }

    /// Collect a `%files` header's package coverage.
    fn sc_collect_files_header(&mut self, line: &str) {
        if line.contains("%{lua:") {
            self.sc_files_generated = true;
        }
        // `%{python_files X}` generates the section for X; the
        // argument may itself be a braced macro, so read to the
        // construct's matching close brace.
        let mut rest = line;
        while let Some(pos) = rest.find("%{python_files") {
            let after = &rest[pos + "%{python_files".len()..];
            let mut depth = 1usize;
            let mut close = None;
            let bytes = after.as_bytes();
            let mut k = 0;
            while k < bytes.len() {
                if bytes[k] == b'{' {
                    depth += 1;
                } else if bytes[k] == b'}' {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(k);
                        break;
                    }
                }
                k += 1;
            }
            let Some(close) = close else { break };
            let arg = after[..close].trim();
            if arg.is_empty() {
                // The no-argument form generates the sections for
                // the spec's declared python subpackages.
                self.sc_python_files_all = true;
            } else {
                match self.sc_expand(arg) {
                    Some(v) => self.sc_python_files.push(v),
                    None => self.sc_files_unresolved = true,
                }
            }
            rest = &after[close + 1..];
        }
        let body = line
            .trim_start()
            .strip_prefix("%files")
            .unwrap_or("")
            .trim_start();
        let tokens: Vec<&str> = body.split_whitespace().collect();
        let mut i = 0;
        while i < tokens.len() {
            let t = tokens[i];
            if t == "-f" {
                i += 2;
                continue;
            }
            if t == "-n" {
                if let Some(ft) = tokens.get(i + 1) {
                    match self.sc_expand(
                        ft.strip_prefix('"')
                            .and_then(|t| t.strip_suffix('"'))
                            .unwrap_or(ft),
                    ) {
                        Some(e) => self.sc_files_names.push(e),
                        None => self.sc_files_unresolved = true,
                    }
                }
                return;
            }
            if t.starts_with('-') {
                i += 1;
                continue;
            }
            if t.contains("%{") && !t.contains('}') && !t.contains("python_files") {
                // A braced construct with arguments, split across
                // tokens: it names its package through a macro the
                // text scan cannot resolve.
                self.sc_files_unresolved = true;
                return;
            }
            if t.contains("python_files") {
                // The name coverage of a `%{python_files ...}` header
                // is recorded above; the bare `%python_files` token
                // is the no-argument generation form.
                if t == "%python_files" {
                    self.sc_python_files_all = true;
                }
                return;
            }
            // A short-form name, plain or macro-built: it binds to
            // the subpackage `<main>-<name>`, so record both forms.
            let short = if t.contains('%') {
                match self.sc_expand(t) {
                    Some(e) => e,
                    None => {
                        self.sc_files_unresolved = true;
                        return;
                    }
                }
            } else {
                t.to_string()
            };
            self.sc_files_short.push(short.clone());
            if let Some(m) = &self.sc_main_name {
                self.sc_files_names.push(format!("{m}-{short}"));
            }
            return;
        }
    }

    /// Collect a single-line `%define`/`%global`; returns true when
    /// the line is one. A definition whose value ends in a backslash
    /// opens a multi-line body, tracked by the caller.
    fn sc_collect_define(&mut self, line: &str) -> bool {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("%undefine")
            && (rest.is_empty() || rest.starts_with([' ', '\t']))
        {
            let name_tok = rest.split_whitespace().next().unwrap_or("");
            let name = name_tok.split('(').next().unwrap_or("");
            if !name.is_empty() {
                self.sc_defines.retain(|(n, _)| n != name);
            }
            return true;
        }
        let rest = trimmed
            .strip_prefix("%define")
            .or_else(|| trimmed.strip_prefix("%global"));
        let Some(rest) = rest else {
            return false;
        };
        if !rest.is_empty() && !rest.starts_with([' ', '\t']) {
            return false;
        }
        let rest = rest.trim_start();
        let name_tok = rest.split_whitespace().next().unwrap_or("");
        if name_tok.is_empty() {
            return true;
        }
        let value = rest[name_tok.len()..].trim();
        if !name_tok.contains('(') {
            self.sc_defines.retain(|(n, _)| n != name_tok);
            self.sc_defines
                .push((name_tok.to_string(), value.to_string()));
        }
        if value.contains("%files") {
            self.sc_files_generated = true;
        }
        if line.trim_end().ends_with('\\') {
            self.sc_macro_open = true;
        }
        true
    }

    /// Collect the main `Name:`/`Version:`/`Release:` tags, the base
    /// the subpackage names expand from.
    fn sc_collect_name_tags(&mut self, line: &str) {
        for (tag, slot) in [("Name:", 0usize), ("Version:", 1), ("Release:", 2)] {
            if let Some(v) = line.strip_prefix(tag) {
                let tok = v.split_whitespace().next().unwrap_or("");
                if tok.is_empty() {
                    return;
                }
                let expanded = self.sc_expand(tok);
                if self.sc_name_conflict[slot] || self.sc_name_toks[slot].as_deref() == Some(tok) {
                    return;
                }
                let value = match slot {
                    0 => &mut self.sc_main_name,
                    1 => &mut self.sc_version,
                    _ => &mut self.sc_release,
                };
                if self.sc_name_toks[slot].is_none() {
                    *value = expanded;
                    self.sc_name_toks[slot] = Some(tok.to_string());
                } else if *value != expanded {
                    // A second, different header for the same tag: the
                    // base value is undecidable, not the first header's.
                    *value = None;
                    self.sc_name_conflict[slot] = true;
                }
                return;
            }
        }
    }

    /// Reset the shell state at a section boundary.
    fn sc_reset_shell(&mut self) {
        self.sc_in_single = false;
        self.sc_single_ansi = false;
        self.sc_in_double = false;
        self.sc_ctx.clear();
        self.sc_heredocs.clear();
        self.sc_continuation = false;
        self.sc_if_stack.clear();
        self.sc_macro_open = false;
    }

    /// Judge the current section's `spec-tag-as-shell-variable`
    /// candidates against the assignments the section turned out to
    /// contain, and clear the per-section state.
    fn sc_flush_tag_vars(&mut self, pkg: &SpecPkg, out: &mut Filter) {
        let assigned = std::mem::take(&mut self.sc_assigned);
        let cands = std::mem::take(&mut self.sc_candidates);
        for (linenum, var, written, scriptlet) in &cands {
            if assigned.iter().any(|a| a == var) {
                continue;
            }
            let sugg = match (var.as_str(), *scriptlet) {
                ("name", false) => "%{name} or $RPM_PACKAGE_NAME",
                ("version", false) => "%{version} or $RPM_PACKAGE_VERSION",
                ("release", false) => "%{release} or $RPM_PACKAGE_RELEASE",
                ("name", true) => "%{name}",
                ("version", true) => "%{version}",
                _ => "%{release}",
            };
            let saved_linenum = pkg.current_linenum.get();
            pkg.current_linenum.set(Some(*linenum));
            self.info(
                out,
                pkg,
                Level::Warning,
                "spec-tag-as-shell-variable",
                &[written, sugg],
            );
            pkg.current_linenum.set(saved_linenum);
        }
    }

    /// Record the assignments a shell code fragment makes to the tag
    /// variables: `var=`, `for var`, `read ... var ...` and
    /// `local var`.
    fn sc_collect_assignments(&mut self, code: &str) {
        const VARS: [&str; 3] = ["name", "version", "release"];
        for var in VARS {
            if self.sc_assigned.iter().any(|a| a == var) {
                continue;
            }
            let bytes = code.as_bytes();
            let mut found = false;
            let mut from = 0;
            while let Some(pos) = code[from..].find(var) {
                let i = from + pos;
                let before_ok =
                    i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b';' | b'&' | b'|' | b'(');
                let after = i + var.len();
                let is_assign = after < bytes.len()
                    && ((bytes[after] == b'=' && bytes.get(after + 1) != Some(&b'='))
                        || (bytes[after] == b'+' && bytes.get(after + 1) == Some(&b'=')));
                if before_ok && is_assign && sc_at_command_position(code, i) {
                    found = true;
                }
                if before_ok {
                    // `for var in ...`: the last shell word before the
                    // variable is `for`, whatever precedes it.
                    let back = code[..i].trim_end();
                    if back
                        .split_whitespace()
                        .last()
                        .map(|w| w.trim_start_matches('('))
                        == Some("for")
                    {
                        found = true;
                    }
                    if sc_word_at(code, i, var) {
                        // `read ... var ...` / `local var ...`: the
                        // variable is a plain word after the builtin in
                        // its segment; leading `VAR=value` words are an
                        // environment prefix on the builtin, not the
                        // builtin itself.
                        for seg in code.split([';', '&', '|']) {
                            let words: Vec<&str> = seg.split_whitespace().collect();
                            let mut k = 0;
                            while k < words.len()
                                && (words[k].contains('=')
                                    || matches!(
                                        words[k],
                                        "while" | "until" | "do" | "then" | "else" | "!"
                                    ))
                            {
                                k += 1;
                            }
                            if k < words.len()
                                && (words[k] == "read" || words[k] == "local")
                                && words[k + 1..]
                                    .iter()
                                    .any(|w| *w == var || w.starts_with(&format!("{var}=")))
                            {
                                found = true;
                            }
                        }
                    }
                }
                if found {
                    break;
                }
                from = after.max(i + 1);
            }
            if found {
                self.sc_assigned.push(var.to_string());
            }
        }
    }

    /// Try to read a tag variable at the `$` at byte `i` of `line`;
    /// on a match, record the candidate and return the index just
    /// past the variable as written.
    fn sc_try_tag_var(&mut self, line: &str, i: usize, linenum: u32) -> Option<usize> {
        let bytes = line.as_bytes();
        let scriptlet = sc_is_scriptlet(&self.sc_section);
        if bytes.get(i + 1) == Some(&b'{') {
            let mut start = i + 2;
            // `${#name}` is the length of `name`, `${!name}` an
            // indirect expansion of it: both read the tag variable.
            if matches!(bytes.get(start), Some(b'#') | Some(b'!')) {
                start += 1;
            }
            let mut end = start;
            while end < bytes.len()
                && matches!(bytes[end], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_')
            {
                end += 1;
            }
            let name = &line[start..end];
            if !matches!(name, "name" | "version" | "release") {
                return None;
            }
            let written_end = if bytes.get(end) == Some(&b'}') {
                end + 1
            } else if let Some(close) = line[end..].find('}') {
                end + close + 1
            } else {
                end
            };
            self.sc_candidates.push((
                linenum,
                name.to_string(),
                line[i..written_end].to_string(),
                scriptlet,
            ));
            return Some(end);
        }
        let start = i + 1;
        let mut end = start;
        while end < bytes.len()
            && matches!(bytes[end], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_')
        {
            end += 1;
        }
        if end == start {
            return None;
        }
        let name = &line[start..end];
        if !matches!(name, "name" | "version" | "release") {
            return None;
        }
        self.sc_candidates.push((
            linenum,
            name.to_string(),
            line[i..end].to_string(),
            scriptlet,
        ));
        Some(end)
    }

    /// Scan a heredoc body line (unquoted delimiter) for tag
    /// variables: the body undergoes expansion, but quotes and
    /// comments have no meaning in it.
    fn sc_scan_heredoc_body(&mut self, line: &str, linenum: u32) {
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == b'$'
                && let Some(next) = self.sc_try_tag_var(line, i, linenum)
            {
                i = next;
                continue;
            }
            i += 1;
        }
    }

    /// Scan one shell code line, updating the cross-line quote,
    /// context and heredoc state, recording `spec-tag-as-shell-variable`
    /// candidates and assignments, and setting the continuation flag
    /// the next line's comment test reads.
    fn sc_scan_shell_line(&mut self, line: &str, linenum: u32) {
        let bytes = line.as_bytes();
        let mut i = 0;
        let mut comment_start: Option<usize> = None;
        while i < bytes.len() {
            let c = bytes[i];
            if self.sc_in_single {
                if self.sc_single_ansi && c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == b'\'' {
                    self.sc_in_single = false;
                    self.sc_single_ansi = false;
                }
                i += 1;
                continue;
            }
            if self.sc_in_double {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == b'"' {
                    self.sc_in_double = false;
                    i += 1;
                    continue;
                }
                if c == b'$'
                    && let Some(next) = self.sc_try_tag_var(line, i, linenum)
                {
                    i = next;
                    continue;
                }
                i += 1;
                continue;
            }
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'\'' {
                self.sc_in_single = true;
                self.sc_single_ansi = i > 0 && bytes[i - 1] == b'$';
                i += 1;
                continue;
            }
            if c == b'"' {
                self.sc_in_double = true;
                i += 1;
                continue;
            }
            if c == b'#' {
                let at_word_start =
                    i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b';' | b'&' | b'|' | b'(');
                if at_word_start {
                    comment_start = Some(i);
                    break;
                }
                i += 1;
                continue;
            }
            if c == b'$' {
                if bytes.get(i + 1) == Some(&b'(') && bytes.get(i + 2) == Some(&b'(') {
                    self.sc_ctx.push(true);
                    i += 3;
                    continue;
                }
                if bytes.get(i + 1) == Some(&b'(') {
                    self.sc_ctx.push(false);
                    i += 2;
                    continue;
                }
                if let Some(next) = self.sc_try_tag_var(line, i, linenum) {
                    i = next;
                    continue;
                }
                i += 1;
                continue;
            }
            if c == b'(' {
                if bytes.get(i + 1) == Some(&b'(') {
                    self.sc_ctx.push(true);
                    i += 2;
                    continue;
                }
                self.sc_ctx.push(false);
                i += 1;
                continue;
            }
            if c == b')' {
                if bytes.get(i + 1) == Some(&b')') && self.sc_ctx.last() == Some(&true) {
                    // `))` is the single closer of an arithmetic
                    // context, not two nested closers.
                    self.sc_ctx.pop();
                    i += 2;
                    continue;
                }
                self.sc_ctx.pop();
                i += 1;
                continue;
            }
            if c == b'<' && bytes.get(i + 1) == Some(&b'<') {
                if self.sc_ctx.iter().any(|ctx| *ctx) {
                    // `<<` inside arithmetic is a shift, no heredoc.
                    i += 2;
                    continue;
                }
                if bytes.get(i + 2) == Some(&b'<') {
                    // A herestring has no body lines.
                    i += 3;
                    continue;
                }
                // Parse the heredoc operator: optional `-`, blanks,
                // an optional quote, the delimiter word.
                let mut j = i + 2;
                let mut dash = false;
                if bytes.get(j) == Some(&b'-') {
                    dash = true;
                    j += 1;
                }
                while bytes.get(j) == Some(&b' ') || bytes.get(j) == Some(&b'\t') {
                    j += 1;
                }
                let mut quoted = false;
                let mut quote: Option<u8> = None;
                if matches!(bytes.get(j), Some(b'\'') | Some(b'"') | Some(b'\\')) {
                    quoted = true;
                    if matches!(bytes.get(j), Some(b'\'') | Some(b'"')) {
                        quote = bytes.get(j).copied();
                    }
                    j += 1;
                }
                let dstart = j;
                while j < bytes.len()
                    && matches!(bytes[j], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-')
                {
                    j += 1;
                }
                if j > dstart {
                    let delim = line[dstart..j].to_string();
                    // Skip the closing quote of a quoted delimiter
                    // before pushing the heredoc: resuming the scan
                    // on it would toggle quote state the delimiter
                    // never opened.
                    if quote.is_some() && bytes.get(j) == quote.as_ref() {
                        j += 1;
                    }
                    self.sc_heredocs.push((delim, quoted, dash));
                    i = j;
                    continue;
                }
                i += 2;
                continue;
            }
            i += 1;
        }
        let code = &line[..comment_start.unwrap_or(bytes.len())];
        self.sc_collect_assignments(code);
        // Counted on the raw slice (bar the line terminator): a
        // backslash followed by blanks is an escaped blank, not a
        // continuation.
        let code = code.strip_suffix('\n').unwrap_or(code);
        let code = code.strip_suffix('\r').unwrap_or(code);
        let trailing = code.bytes().rev().take_while(|b| *b == b'\\').count();
        self.sc_continuation = !self.sc_in_single && trailing % 2 == 1;
    }

    /// Feed one spec line to the silent-constructs scan. Runs before
    /// the section walker consumes header lines, so the scan keeps its
    /// own section and shell state.
    fn checkline_silent_constructs(&mut self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        let linenum = pkg.current_linenum.get().unwrap_or(0);
        if line.contains("%kernel_module_package") {
            self.sc_kmp = true;
        }
        // A multi-line macro body is literal text until its last
        // continuation line: a header-shaped line inside it is body
        // text, so the body is consumed before headers are recognised.
        if self.sc_macro_open {
            if line.contains("%files") {
                self.sc_files_generated = true;
            }
            if !line.trim_end().ends_with('\\') {
                self.sc_macro_open = false;
            }
            return;
        }
        // A section header is recognised regardless of shell quote or
        // heredoc state, and it resets that state.
        let mut header: Option<String> = None;
        for (sec, re) in &self.section_res {
            if let Ok(Some(_)) = re.find(line) {
                header = Some(sec.clone());
                break;
            }
        }
        if let Some(sec) = header {
            if sec == "package" {
                self.sc_collect_package_header(line, linenum);
            }
            if sec == "files" {
                self.sc_collect_files_header(line);
            }
            self.sc_flush_tag_vars(pkg, out);
            self.sc_reset_shell();
            self.sc_non_shell_scriptlet = sc_is_scriptlet(&sec)
                && sc_header_interpreter(line).is_some_and(|interp| {
                    !matches!(
                        interp.rsplit('/').next().unwrap_or(interp),
                        "sh" | "bash" | "dash" | "ash" | "ksh" | "mksh" | "zsh" | "pdksh"
                    )
                });
            self.sc_section = sec;
            return;
        }
        if self.sc_collect_define(line) {
            return;
        }
        let trimmed = line.trim();
        if trimmed.starts_with("%include") {
            self.sc_has_include = true;
            return;
        }
        if !sc_is_shell(&self.sc_section) || self.sc_non_shell_scriptlet {
            self.sc_collect_name_tags(line);
            return;
        }
        // Conditional directives are rpm text, not shell: `%else` and
        // `%elif` restore the continuation state saved at the `%if`.
        let first_word = trimmed.split_whitespace().next().unwrap_or("");
        if matches!(
            first_word,
            "%if" | "%ifarch" | "%ifnarch" | "%ifos" | "%ifnos" | "%ifdef" | "%ifndef" | "%ifexpr"
        ) {
            self.sc_if_stack.push(self.sc_continuation);
            return;
        }
        if matches!(
            first_word,
            "%else" | "%elif" | "%elifarch" | "%elifnarch" | "%elifos" | "%elifnos"
        ) {
            if let Some(saved) = self.sc_if_stack.last() {
                self.sc_continuation = *saved;
            }
            return;
        }
        if first_word == "%endif" {
            self.sc_if_stack.pop();
            return;
        }
        // Heredoc bodies: the terminator line is consumed as such; a
        // quoted body is literal, an unquoted body still expands.
        if !self.sc_heredocs.is_empty() {
            let (delim, quoted, dash) = self.sc_heredocs[0].clone();
            let body = line.strip_suffix('\n').unwrap_or(line);
            let body = body.strip_suffix('\r').unwrap_or(body);
            let is_terminator = if dash {
                body.trim_start_matches('\t') == delim
            } else {
                body == delim
            };
            if is_terminator {
                self.sc_heredocs.remove(0);
                self.sc_continuation = false;
                return;
            }
            if !quoted {
                self.sc_scan_heredoc_body(line, linenum);
            }
            return;
        }
        // A comment line: when the previous line continued into it,
        // the comment ends that command.
        if !self.sc_in_single && !self.sc_in_double && trimmed.starts_with('#') {
            if self.sc_continuation {
                let detail = trimmed.to_string();
                self.info(
                    out,
                    pkg,
                    Level::Warning,
                    "comment-in-continued-command",
                    &[&detail],
                );
            }
            let trailing = trimmed.bytes().rev().take_while(|b| *b == b'\\').count();
            self.sc_continuation = trailing % 2 == 1;
            return;
        }
        self.sc_scan_shell_line(line, linenum);
    }

    /// End-of-spec judging for the silent-constructs scan: the last
    /// section's tag variables, then the subpackage coverage.
    fn flush_silent_constructs(&mut self, pkg: &SpecPkg, out: &mut Filter) {
        self.sc_flush_tag_vars(pkg, out);
        if self.sc_kmp || self.sc_has_include || self.sc_files_generated || self.sc_files_unresolved
        {
            self.sc_pkg_headers.clear();
            return;
        }
        let headers = std::mem::take(&mut self.sc_pkg_headers);
        for h in &headers {
            let Some(full) = &h.full else {
                continue;
            };
            if let Some(m) = &self.sc_main_name
                && full == m
            {
                continue;
            }
            let covered = self.sc_files_names.iter().any(|n| n == full)
                || h.short
                    .as_ref()
                    .is_some_and(|s| self.sc_python_files.iter().any(|p| p == s))
                || self
                    .sc_python_files
                    .iter()
                    .any(|p| full.ends_with(&format!("-{p}")));
            // With the main name itself unresolvable, a `-n` header
            // ending in a declared short files name may be that very
            // subpackage; coverage is then undecidable.
            let covered = covered || (self.sc_python_files_all && sc_python_flavour_name(full));
            let covered = covered
                || (self.sc_main_name.is_none()
                    && self
                        .sc_files_short
                        .iter()
                        .any(|sh| full == sh || full.ends_with(&format!("-{sh}"))));
            if !covered {
                pkg.current_linenum.set(Some(h.linenum));
                self.info(
                    out,
                    pkg,
                    Level::Warning,
                    "subpackage-without-files",
                    &[&h.raw],
                );
                pkg.current_linenum.set(None);
            }
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

// ---------------------------------------------------------------------
// #1019: a `%check` that cannot fail. rpm runs build sections under
// `bash -e` and a section's status is its last command's, so three
// shapes cannot stop the build: a runner whose failure a `||` fallback
// absorbs, a runner piped into a pass-through (the pipeline reports
// the last element's status), and a `!`-negated command that is not
// the section's last command (the negation is discarded). Two more
// shapes are dead by construction: `%{?with N}` always expands to
// nothing, and `ctest` under the KDE cmake macros finds no tests
// because they pass `-DBUILD_TESTING=FALSE`. The four masking tags
// are warnings; `with-macro-expands-empty` has no safe use and
// ships as an error: the Factory corpus measurement recorded in
// the ledger found every occurrence to be a condition or value
// that never depends on the named bcond, and `rpmspec` confirms
// all eight forms expand to nothing with the bcond on and off.
const WITH_MACRO_LEVEL: Level = Level::Error;

impl SpecCheck {
    /// Record whole-spec facts and shell-section lines for the #1019
    /// analysis. Runs on every non-header line of the walk.
    fn note_body_line(&mut self, pkg: &SpecPkg, line: &str) {
        let text = without_newline(line);
        if self.cmake_kf_re.is_match(text).unwrap_or(false) {
            self.saw_cmake_kf = true;
        }
        if let Ok(Some(caps)) = self.build_testing_re.captures(text) {
            let value = caps
                .get(1)
                .map(|m| m.as_str().trim_end_matches(')'))
                .unwrap_or("");
            if cmake_true_value(value) {
                self.build_testing_on = true;
            }
        }
        let trimmed = text.trim_start();
        if (trimmed.starts_with("%define") || trimmed.starts_with("%global"))
            && text.contains("__spec_install_post")
            && text.contains("%{nil}")
        {
            self.install_post_nil = true;
        }
        let section = self.current_section.as_str();
        let shell = matches!(section, "prep" | "build" | "install" | "check");
        if section != self.prev_section {
            self.prev_section = section.to_string();
            if shell {
                self.section_instance += 1;
            }
        }
        if shell {
            self.body_lines.push(BodyLine {
                section: section.to_string(),
                instance: self.section_instance,
                lineno: pkg.current_linenum.get().unwrap_or(0),
                text: text.to_string(),
            });
        }
    }

    /// `%{?with N}`, `%{!?without N}` and the other `?`/`!?` forms:
    /// rpm drops the argument of the `?` form, so the expansion is
    /// empty whatever N names (#1019). `%%`-escaped text is literal
    /// prose and stays quiet, as does `%{with N}` (no `?`) and
    /// `0%{?with_N}` (a different macro name).
    fn checkline_with_macro_empty(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        let text = without_newline(line);
        for m in self.with_macro_empty_re.find_iter(text) {
            let Ok(m) = m else { break };
            if m.start() > 0 && text.as_bytes()[m.start() - 1] == b'%' {
                continue;
            }
            self.info(
                out,
                pkg,
                WITH_MACRO_LEVEL,
                "with-macro-expands-empty",
                &[text.trim()],
            );
            return;
        }
    }

    /// The deferred #1019 analysis: findings that need the whole
    /// section (or the whole spec), emitted at the recorded lines.
    fn flush_check_soundness(&mut self, pkg: &SpecPkg, out: &mut Filter) {
        let hits = soundness_hits(
            &self.body_lines,
            self.saw_cmake_kf,
            self.build_testing_on,
            self.install_post_nil,
        );
        for hit in hits {
            pkg.current_linenum.set(Some(hit.lineno));
            let tag = match hit.kind {
                SoundnessKind::NegatedCommandNotLast => "negated-command-not-last",
                SoundnessKind::CheckExitStatusMasked => "check-exit-status-masked",
                SoundnessKind::CheckPipelineStatusMasked => "check-pipeline-status-masked",
                SoundnessKind::CtestWithTestingDisabled => "ctest-with-testing-disabled",
            };
            self.info(out, pkg, hit.level, tag, &[&hit.detail]);
        }
        pkg.current_linenum.set(None);
    }
}

/// A CMake truthy value for `-DBUILD_TESTING`: `1`, `ON`, `YES`,
/// `TRUE`, `Y` or a non-zero number, case-insensitive.
fn cmake_true_value(value: &str) -> bool {
    if ["on", "yes", "true", "y"]
        .iter()
        .any(|w| value.eq_ignore_ascii_case(w))
    {
        return true;
    }
    value.parse::<i64>().map(|n| n != 0).unwrap_or(false)
}

/// Which of the deferred soundness findings a [`SoundnessHit`]
/// carries; the emitted tag is fixed per kind (see
/// `flush_check_soundness`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SoundnessKind {
    NegatedCommandNotLast,
    CheckExitStatusMasked,
    CheckPipelineStatusMasked,
    CtestWithTestingDisabled,
}

struct SoundnessHit {
    lineno: u32,
    level: Level,
    kind: SoundnessKind,
    detail: String,
}

/// A test runner from the closed list in #1019 §3: make/ninja
/// `check`/`test`, ctest, pytest, pyunittest, meson test, cargo test,
/// go test, prove, runtest.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Runner {
    Make,
    Ninja,
    Ctest,
    Pytest,
    Pyunittest,
    Meson,
    Cargo,
    Go,
    Prove,
    Runtest,
}

/// `VAR=value` (or `VAR+=value`) as a shell word.
fn is_assignment(word: &str) -> bool {
    let Some(eq) = word.find('=') else {
        return false;
    };
    let name = word[..eq].trim_end_matches('+');
    !name.is_empty()
        && name
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic() || c == '_')
            .unwrap_or(false)
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The command word of a statement: the first word that is not an
/// assignment, `env` or a negation, reduced to its basename.
fn command_word(stmt: &str) -> Option<String> {
    for word in stmt.split_whitespace() {
        let word = if word.starts_with('%') {
            word
        } else {
            word.trim_matches(|c| matches!(c, '(' | ')' | '{' | '}' | ';'))
        };
        if word == "!" || word == "env" || is_assignment(word) {
            continue;
        }
        return Some(word.rsplit('/').next().unwrap_or(word).to_string());
    }
    None
}

/// The runner a statement invokes, if any. Only the statement's
/// command position counts: prose mentioning a runner is not a run.
fn runner_of(stmt: &str) -> Option<Runner> {
    let toks: Vec<&str> = stmt
        .split_whitespace()
        .map(|t| {
            if t.starts_with('%') {
                t
            } else {
                t.trim_matches(|c| matches!(c, '(' | ')' | '{' | '}' | ';'))
            }
        })
        .collect();
    let mut i = 0;
    while i < toks.len() && (toks[i] == "!" || toks[i] == "env" || is_assignment(toks[i])) {
        i += 1;
    }
    let word = *toks.get(i)?;
    let base = word.rsplit('/').next().unwrap_or(word);
    let later = &toks[i + 1..];
    let has_later = |w: &str| later.contains(&w);
    match base {
        "make" | "gmake" | "%{__make}" | "%__make" => {
            if has_later("check") || has_later("test") {
                return Some(Runner::Make);
            }
        }
        "ninja" | "%{__ninja}" => {
            if has_later("test") || has_later("check") {
                return Some(Runner::Ninja);
            }
        }
        "ctest" => return Some(Runner::Ctest),
        "meson" => {
            if has_later("test") {
                return Some(Runner::Meson);
            }
        }
        "%meson_test" => return Some(Runner::Meson),
        "cargo" => {
            if has_later("test") {
                return Some(Runner::Cargo);
            }
        }
        "%cargo_test" => return Some(Runner::Cargo),
        "go" => {
            if has_later("test") {
                return Some(Runner::Go);
            }
        }
        "prove" => return Some(Runner::Prove),
        "runtest" => return Some(Runner::Runtest),
        _ => {}
    }
    if word.starts_with("%ctest") {
        return Some(Runner::Ctest);
    }
    if base == "pytest" || base.starts_with("pytest") || word == "%pytest" {
        return Some(Runner::Pytest);
    }
    if base.contains("pyunittest") {
        return Some(Runner::Pyunittest);
    }
    if later.windows(2).any(|w| w[0] == "-m" && w[1] == "unittest") {
        return Some(Runner::Pyunittest);
    }
    None
}

/// The operator preceding a statement in its logical line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    Start,
    And,
    Or,
    Semi,
    Pipe,
}

struct Stmt {
    op: Op,
    text: String,
}

/// Split a logical line into statements at top-level `&&`, `||`,
/// `;`, `|` and background `&`, honouring quotes, backslash escapes
/// and parenthesis depth (operators inside `$(...)` or a subshell do
/// not split). The recorded operator is the one *preceding* each
/// statement.
#[allow(unused_assignments)] // the final cut! assigns an operator nothing reads
fn split_statements(text: &str) -> Vec<Stmt> {
    let bytes = text.as_bytes();
    let mut stmts = Vec::new();
    let mut op = Op::Start;
    let mut seg_start = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut depth: i32 = 0;
    let mut i = 0usize;
    macro_rules! cut {
        ($end:expr, $next_op:expr) => {
            let seg = text[seg_start..$end].trim();
            if !seg.is_empty() {
                stmts.push(Stmt {
                    op,
                    text: seg.to_string(),
                });
            }
            op = $next_op;
        };
    }
    while i < bytes.len() {
        let c = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if c == b'\\' && !in_single {
            escaped = true;
            i += 1;
            continue;
        }
        if c == b'\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if c == b'"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if !in_single && !in_double {
            match c {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            if depth == 0 {
                if c == b'&' && bytes.get(i + 1) == Some(&b'&') {
                    cut!(i, Op::And);
                    i += 2;
                    seg_start = i;
                    continue;
                }
                if c == b'|' && bytes.get(i + 1) == Some(&b'|') {
                    cut!(i, Op::Or);
                    i += 2;
                    seg_start = i;
                    continue;
                }
                if c == b'|' {
                    cut!(i, Op::Pipe);
                    i += if bytes.get(i + 1) == Some(&b'&') {
                        2
                    } else {
                        1
                    };
                    seg_start = i;
                    continue;
                }
                if c == b';' {
                    cut!(i, Op::Semi);
                    i += 1;
                    seg_start = i;
                    continue;
                }
                if c == b'&' && (i == 0 || bytes[i - 1] != b'>') {
                    cut!(i, Op::Semi);
                    i += 1;
                    seg_start = i;
                    continue;
                }
            }
        }
        i += 1;
    }
    cut!(bytes.len(), Op::Start);
    stmts
}

/// A statement with brace-group decoration removed, for the
/// fallback-shape tests in `fallback_masks`.
fn clean_stmt(text: &str) -> &str {
    text.trim()
        .trim_start_matches(['{', ' '])
        .trim_end_matches(['}', ')', ' '])
}

/// An `exit` statement that propagates a failure: a bare `exit`
/// (the runner's own status) or an exit with a non-zero argument.
fn exit_fails(text: &str) -> bool {
    let mut words = text.split_whitespace();
    if words.next() != Some("exit") {
        return false;
    }
    match words.next() {
        None => true,
        Some(arg) => arg != "0",
    }
}

/// Adjust `depth` by the group brackets `(`, `{`, `)`, `}` in
/// `text` that sit outside quotes.
fn group_depth(text: &str, depth: &mut i32) {
    let b = text.as_bytes();
    let (mut sq, mut dq) = (false, false);
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if !sq => {
                i += 2;
                continue;
            }
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'(' | b'{' if !sq && !dq => *depth += 1,
            b')' | b'}' if !sq && !dq => *depth -= 1,
            _ => {}
        }
        i += 1;
    }
}

/// Whether `text` ends inside an open single or double quote.
fn quote_open(text: &str) -> bool {
    let b = text.as_bytes();
    let (mut sq, mut dq) = (false, false);
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if !sq => {
                i += 2;
                continue;
            }
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            _ => {}
        }
        i += 1;
    }
    sq || dq
}

/// The delimiter of a here-document opened on `text`, if any: an
/// unquoted `<<` (not `<<<`) followed by an optional `-`, optional
/// quoting and a delimiter word.
fn heredoc_delimiter(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let (mut sq, mut dq) = (false, false);
    let mut i = 0;
    while i + 1 < b.len() {
        match b[i] {
            b'\\' if !sq => {
                i += 2;
                continue;
            }
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'<' if !sq && !dq && b[i + 1] == b'<' && b.get(i + 2) != Some(&b'<') => {
                let mut j = i + 2;
                if b.get(j) == Some(&b'-') {
                    j += 1;
                }
                while b.get(j).map(|c| *c == b' ' || *c == b'\t').unwrap_or(false) {
                    j += 1;
                }
                if matches!(b.get(j), Some(b'\'') | Some(b'"')) {
                    j += 1;
                }
                let start = j;
                while b
                    .get(j)
                    .map(|c| c.is_ascii_alphanumeric() || *c == b'_')
                    .unwrap_or(false)
                {
                    j += 1;
                }
                if j > start {
                    return Some(text[start..j].to_string());
                }
                return None;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Whether the `||` fallback (the statements after the runner)
/// absorbs the runner's failure: it masks when it neither re-runs a
/// runner, nor defers the verdict to a variable it assigns, nor can
/// itself fail - except that an explicit `exit 0` in the fallback
/// masks outright. A group fallback may span following commands;
/// its statements join the analysis until the group closes. The
/// verdict reads leaf statements (group interiors split on `;`,
/// `&&` and `||`): an `exit` leaf with a non-zero or bare argument
/// fails, an `exit 0` leaf masks, and a trailing `false` fails.
fn fallback_masks(fallback: &[Stmt], following: &[CmdLine]) -> bool {
    if fallback.iter().any(|s| runner_of(&s.text).is_some()) {
        return false;
    }
    let defers = fallback
        .first()
        .map(|f| {
            let t = clean_stmt(&f.text);
            let t = ["export ", "local ", "readonly ", "declare "]
                .iter()
                .find_map(|p| t.strip_prefix(p))
                .unwrap_or(t);
            is_assignment(t.split_whitespace().next().unwrap_or(""))
        })
        .unwrap_or(false);
    if defers {
        return false;
    }
    if fallback.iter().any(|s| {
        let t = clean_stmt(&s.text);
        t == "false" || t.starts_with("false ")
    }) {
        return false;
    }
    let mut stmts: Vec<&Stmt> = fallback.iter().collect();
    let mut depth = 0i32;
    for s in fallback {
        group_depth(&s.text, &mut depth);
    }
    let mut fi = 0;
    while depth > 0 && fi < following.len() {
        for s in &following[fi].stmts {
            group_depth(&s.text, &mut depth);
            stmts.push(s);
            if depth <= 0 {
                break;
            }
        }
        fi += 1;
    }
    let mut leaves: Vec<String> = Vec::new();
    for s in &stmts {
        for part in clean_stmt(&s.text).split(';') {
            for leaf in part.split("&&").flat_map(|x| x.split("||")) {
                leaves.push(
                    leaf.trim()
                        .trim_start_matches(['(', '{', ' '])
                        .trim_end_matches([')', '}', ' '])
                        .to_string(),
                );
            }
        }
    }
    if leaves.iter().any(|l| exit_fails(l)) {
        return false;
    }
    if leaves
        .iter()
        .any(|l| l == "exit 0" || l.starts_with("exit 0 "))
    {
        return true;
    }
    let last_false = leaves
        .last()
        .map(|l| l == "false" || l.starts_with("false "))
        .unwrap_or(false);
    !last_false
}

/// The `&&`-arm mask forms: `&& exit 0`, `&& echo`, `&& :`,
/// `&& true` after a runner.
fn and_mask_form(text: &str) -> bool {
    let t = clean_stmt(text);
    t == "exit 0"
        || t.starts_with("exit 0 ")
        || matches!(command_word(t).as_deref(), Some("echo" | ":" | "true"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LineKind {
    If,
    ElseLike,
    Endif,
    Blank,
    Closing,
    Command,
}

/// `text` opens with the directive `kw` at a word boundary.
fn directive(text: &str, kw: &str) -> bool {
    text == kw
        || text
            .strip_prefix(kw)
            .map(|rest| rest.starts_with([' ', '\t']))
            .unwrap_or(false)
}

/// One command logical line of a shell section, with its conditional
/// arm path (the `(if, arm)` stack enclosing it).
struct CmdLine {
    lineno: u32,
    text: String,
    stmts: Vec<Stmt>,
    arm_path: Vec<(u32, u32)>,
}

/// Whether a command after `s` in the same section can run in a
/// configuration where `s` runs: every conditional enclosing `s`
/// either does not enclose the later command, or encloses it in the
/// same arm.
fn arm_compatible(s: &[(u32, u32)], later: &[(u32, u32)]) -> bool {
    s.iter()
        .all(|(id, arm)| match later.iter().find(|(oid, _)| oid == id) {
            None => true,
            Some((_, other)) => other == arm,
        })
}

fn soundness_hits(
    lines: &[BodyLine],
    cmake_kf: bool,
    build_testing_on: bool,
    install_post_nil: bool,
) -> Vec<SoundnessHit> {
    let mut hits = Vec::new();
    let mut ctest_fired = false;
    let mut start = 0;
    while start < lines.len() {
        let instance = lines[start].instance;
        let mut end = start;
        while end < lines.len() && lines[end].instance == instance {
            end += 1;
        }
        soundness_block(
            &lines[start].section,
            &lines[start..end],
            cmake_kf,
            build_testing_on,
            install_post_nil,
            &mut ctest_fired,
            &mut hits,
        );
        start = end;
    }
    hits.sort_by_key(|h| h.lineno);
    hits
}

fn soundness_block(
    section: &str,
    phys: &[BodyLine],
    cmake_kf: bool,
    build_testing_on: bool,
    install_post_nil: bool,
    ctest_fired: &mut bool,
    hits: &mut Vec<SoundnessHit>,
) {
    // Build logical lines from the physical ones. A conditional
    // directive stands alone and never joins a continuation. A
    // logical line continues while it ends in a backslash, in a
    // binary operator (`||`, `&&`, `|`) or inside an open quote.
    // Lines inside a here-document are content, not commands, and
    // are recorded as blank lines.
    let mut logicals: Vec<(u32, String)> = Vec::new();
    let mut cur: Option<(u32, String)> = None;
    let mut heredoc: Option<String> = None;
    for p in phys {
        let t = p.text.trim();
        if let Some(delim) = &heredoc {
            logicals.push((p.lineno, String::new()));
            if t == delim.as_str() {
                heredoc = None;
            }
            continue;
        }
        if directive(t, "%endif")
            || directive(t, "%else")
            || directive(t, "%elif")
            || t.starts_with("%if")
        {
            logicals.push((p.lineno, t.to_string()));
            continue;
        }
        let (ln, mut acc) = cur.take().unwrap_or((p.lineno, String::new()));
        acc.push_str(&p.text);
        let stripped = match comment_start_pos(&acc) {
            Some(i) => acc[..i].to_string(),
            None => acc,
        };
        let st = stripped.trim_end().to_string();
        let trailing = st.chars().rev().take_while(|c| *c == '\\').count();
        if trailing % 2 == 1 {
            let mut a = st;
            a.pop();
            cur = Some((ln, a));
        } else if st.ends_with('|') || st.ends_with("&&") || quote_open(&st) {
            cur = Some((ln, st));
        } else {
            if heredoc.is_none() {
                heredoc = heredoc_delimiter(&st);
            }
            logicals.push((ln, st.trim().to_string()));
        }
    }
    if let Some((ln, acc)) = cur {
        logicals.push((ln, acc.trim().to_string()));
    }

    // Classify the lines and record each command's arm path.
    let mut kinds: Vec<LineKind> = Vec::with_capacity(logicals.len());
    let mut cmds: Vec<CmdLine> = Vec::new();
    let mut stack: Vec<(u32, u32)> = Vec::new();
    let mut next_if = 0u32;
    for (ln, text) in &logicals {
        let kind = if text.is_empty() {
            LineKind::Blank
        } else if directive(text, "%endif") {
            LineKind::Endif
        } else if directive(text, "%else") || directive(text, "%elif") {
            LineKind::ElseLike
        } else if text.starts_with("%if") {
            LineKind::If
        } else if text.starts_with(['}', ')']) || matches!(text.as_str(), "fi" | "done" | "esac") {
            LineKind::Closing
        } else {
            LineKind::Command
        };
        match kind {
            LineKind::If => {
                stack.push((next_if, 0));
                next_if += 1;
            }
            LineKind::ElseLike => {
                if let Some(top) = stack.last_mut() {
                    top.1 += 1;
                }
            }
            LineKind::Endif => {
                stack.pop();
            }
            LineKind::Command => cmds.push(CmdLine {
                lineno: *ln,
                text: text.clone(),
                stmts: split_statements(text),
                arm_path: stack.clone(),
            }),
            _ => {}
        }
        kinds.push(kind);
    }

    // `negated-command-not-last`, in every shell section.
    for (ci, c) in cmds.iter().enumerate() {
        if !c.text.starts_with("! ") {
            continue;
        }
        // (a) no `||`, `&&` or `;` follows the negation on the line.
        if c.stmts
            .iter()
            .any(|s| matches!(s.op, Op::And | Op::Or | Op::Semi))
        {
            continue;
        }
        // (b) the next command does not read `$?`.
        let reads_status = cmds
            .get(ci + 1)
            .map(|n| n.text.contains("$?") || n.text.contains("${?}"))
            .unwrap_or(false);
        if reads_status {
            continue;
        }
        // (c) it is not the last command of a function body or a
        // subshell: the next content line closes the body.
        let span_tail = {
            let pos = logicals.iter().position(|(ln, _)| *ln == c.lineno);
            let mut tail = false;
            if let Some(pos) = pos {
                for kind in &kinds[pos + 1..] {
                    match kind {
                        LineKind::Blank | LineKind::If | LineKind::ElseLike | LineKind::Endif => {
                            continue;
                        }
                        LineKind::Closing => {
                            tail = true;
                            break;
                        }
                        LineKind::Command => break,
                    }
                }
            }
            tail
        };
        if span_tail {
            continue;
        }
        // (d) a later command may run.
        let later = (section == "install" && !install_post_nil)
            || cmds[ci + 1..]
                .iter()
                .any(|o| arm_compatible(&c.arm_path, &o.arm_path));
        if !later {
            continue;
        }
        hits.push(SoundnessHit {
            lineno: c.lineno,
            level: Level::Warning,
            kind: SoundnessKind::NegatedCommandNotLast,
            detail: c.text.clone(),
        });
    }

    if section != "check" {
        return;
    }

    // Runner kinds that also run unmasked in this section: a mask
    // on them is informational (the plain run still gates).
    let mut unmasked: Vec<Runner> = Vec::new();
    for c in &cmds {
        for (i, s) in c.stmts.iter().enumerate() {
            if let Some(kind) = runner_of(&s.text) {
                let last = i + 1 == c.stmts.len();
                let clean_line = c.stmts.iter().all(|x| !matches!(x.op, Op::Or | Op::Pipe));
                if last && clean_line && !unmasked.contains(&kind) {
                    unmasked.push(kind);
                }
            }
        }
    }

    let last_cmd = cmds.last().map(|c| c.lineno);
    let mut flat = 0usize;
    let mut pipefail_before: Option<usize> = None;
    // Flat statement positions, for the pipefail/PIPESTATUS tests.
    let mut positions: Vec<Vec<usize>> = Vec::with_capacity(cmds.len());
    for c in &cmds {
        let mut row = Vec::with_capacity(c.stmts.len());
        for s in &c.stmts {
            if pipefail_before.is_none()
                && command_word(&s.text).as_deref() == Some("set")
                && s.text.contains("pipefail")
            {
                pipefail_before = Some(flat);
            }
            row.push(flat);
            flat += 1;
        }
        positions.push(row);
    }
    let pipestatus_after = |pos: usize, cmds: &[CmdLine]| {
        let mut seen = 0usize;
        for c in cmds {
            for s in &c.stmts {
                if seen > pos && s.text.contains("PIPESTATUS") {
                    return true;
                }
                seen += 1;
            }
        }
        false
    };

    for (ci, c) in cmds.iter().enumerate() {
        // `check-exit-status-masked`.
        let mut fired = false;
        // A `||` chain is analysed once, at its first runner: later
        // runner segments are retries of the same chain, and their
        // own fallback slice is not a separate mask.
        let mut or_subject = false;
        for (i, s) in c.stmts.iter().enumerate() {
            if matches!(s.op, Op::Start | Op::Semi) {
                or_subject = false;
            }
            let Some(kind) = runner_of(&s.text) else {
                continue;
            };
            if s.op == Op::Or && or_subject {
                continue;
            }
            if unmasked.contains(&kind) {
                continue;
            }
            let Some(next) = c.stmts.get(i + 1) else {
                continue;
            };
            match next.op {
                Op::Or => {
                    or_subject = true;
                    if fallback_masks(&c.stmts[i + 1..], &cmds[ci + 1..]) {
                        fired = true;
                    }
                }
                Op::And => {
                    // A `%ctest` line is never the section's last
                    // command: the macro appends `; cd ..`.
                    let is_ctest = s.text.trim_start().starts_with("%ctest");
                    if and_mask_form(&next.text) && (is_ctest || Some(c.lineno) != last_cmd) {
                        fired = true;
                    }
                }
                _ => {}
            }
            if fired {
                break;
            }
        }
        if fired {
            hits.push(SoundnessHit {
                lineno: c.lineno,
                level: Level::Warning,
                kind: SoundnessKind::CheckExitStatusMasked,
                detail: c.text.clone(),
            });
        }

        // `check-pipeline-status-masked`.
        for (i, s) in c.stmts.iter().enumerate() {
            if s.op != Op::Pipe {
                continue;
            }
            let word = command_word(&s.text);
            let passthrough = matches!(
                word.as_deref(),
                Some("tee" | "cat" | "head" | "tail" | "sed" | "sort")
            );
            if !passthrough {
                continue;
            }
            if !c.stmts[..i].iter().any(|x| runner_of(&x.text).is_some()) {
                continue;
            }
            let pos = positions[ci][i];
            let suppressed =
                pipefail_before.map(|p| p < pos).unwrap_or(false) || pipestatus_after(pos, &cmds);
            if !suppressed {
                hits.push(SoundnessHit {
                    lineno: c.lineno,
                    level: Level::Warning,
                    kind: SoundnessKind::CheckPipelineStatusMasked,
                    detail: c.text.clone(),
                });
            }
            break;
        }

        // `ctest-with-testing-disabled` (once per spec).
        if cmake_kf
            && !build_testing_on
            && !*ctest_fired
            && c.stmts
                .iter()
                .any(|s| runner_of(&s.text) == Some(Runner::Ctest))
        {
            hits.push(SoundnessHit {
                lineno: c.lineno,
                level: Level::Warning,
                kind: SoundnessKind::CtestWithTestingDisabled,
                detail: c.text.clone(),
            });
            *ctest_fired = true;
        }
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

    /// Run `SpecCheck` over the spec file at `path`, returning the raw
    /// `(check, rendered line)` pairs.
    fn run_spec_at(path: &Path, config: &Config) -> Vec<(String, String)> {
        let pkg = SpecPkg::open(path).unwrap();
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
    fn macro_mention_in_prose_comment_errors_1026() {
        // #442/#482 kept prose mentions quiet; #1026 errors on every
        // unescaped mention: rpm expands it on the comment line, and a
        // multi-line expansion would leak out of the comment.
        let results = run_mini("Name: foo\n# a comment with %{version} inside\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(
            lines[0].contains("E: macro-in-comment %{version}"),
            "unexpected: {lines:?}"
        );
    }

    #[test]
    fn syntax_keyword_in_prose_comment_stays_quiet_1026() {
        // The dtrx case that motivated #442: prose about the `%files`
        // directive, not a macro mention — spec-syntax keywords are
        // not macros, so this stays quiet.
        let results =
            run_mini("Name: foo\n# License is shipped via %license; drop the dist-info copy\n");
        assert!(
            !has(&results, "macro-in-comment"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn syntax_keyword_families_in_comment_stay_quiet_1176() {
        // Item 1: the keyword list covers the whole spec-syntax
        // families -- filetrigger scriptlets, %caps/%docdir,
        // generate_buildrequires and the conditional family.
        for line in [
            "# the %caps directive is per-file",
            "# docs land in %docdir",
            "# generated by %generate_buildrequires",
            "# runs as %triggerprein",
            "# a %filetriggerin scriptlet",
            "# a %transfiletriggerpostun scriptlet",
            "# under %ifdef it differs",
            "# under %ifndef it differs",
            "# an %ifexpr guard",
            "# the %elifarch branch",
        ] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            assert!(!has(&results, "macro-in-comment"), "{line}: {results:?}");
        }
    }

    #[test]
    fn braced_no_arg_comment_forms_1176() {
        // Item 2: a braced keyword mention is as quiet as the bare
        // form, sigils stripped before the consult; a conditional
        // mention of a real macro still errors.
        for line in ["# see %{license}", "# see %{?license}", "# see %{!doc}"] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            assert!(!has(&results, "macro-in-comment"), "{line}: {results:?}");
        }
        let results = run_mini("Name: foo\n# see %{?version}\n");
        assert_eq!(
            lines_for(&results, "macro-in-comment").len(),
            1,
            "{results:?}"
        );
        // Item 4: a braced executing directive with no argument
        // does nothing, like the bare form.
        for line in ["# %{define}", "# %{error}", "# %{lua}"] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            assert!(!has(&results, "macro-in-comment"), "{line}: {results:?}");
        }
        // Item 5: a lone sigil group names no macro.
        for line in ["# %{?}", "# %{!}"] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            assert!(!has(&results, "macro-in-comment"), "{line}: {results:?}");
        }
    }

    #[test]
    fn plain_macro_opening_comment_errors_1026() {
        // #442 warned here (a macro opening the comment looks like a
        // commented-out invocation); #482 kept it quiet; #1026 errors
        // on any unescaped mention, wherever it sits in the comment.
        let results = run_mini("Name: foo\n# %{version} was commented out\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(
            lines[0].contains("E: macro-in-comment %{version}"),
            "unexpected: {lines:?}"
        );
    }

    #[test]
    fn plain_macro_glued_in_comment_errors_1026() {
        // Tom's #442 cases: commented-out code full of plain macros,
        // the deliberate idiom for keeping disabled lines visible.
        // #482 kept it all quiet; #1026 errors on the mentions —
        // commented-out invocations are the hazard, since a multi-line
        // expansion leaks out of the comment.
        for (line, token) in [
            ("# /usr/%{_bindir}/foo", "%{_bindir}"),
            ("# foo-%bar", "%bar"),
            ("#%makeinstall", "%makeinstall"),
        ] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            let lines = lines_for(&results, "macro-in-comment");
            assert_eq!(lines.len(), 1, "{line}: {results:?}");
            assert!(
                lines[0].contains(&format!("E: macro-in-comment {token}")),
                "{line}: {lines:?}"
            );
        }
    }

    #[test]
    fn shell_expansion_in_comment_errors_482() {
        // The hazard the check exists for: rpm executes %(...) while
        // parsing, even inside a comment, in any position.
        let results = run_mini("Name: foo\n# %(touch /tmp/x) was here\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(
            lines[0].contains("E: macro-in-comment %(touch /tmp/x)"),
            "unexpected: {lines:?}"
        );
        let results = run_mini("Name: foo\n# do not run %(touch /tmp/x) at home\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 1, "{results:?}");
        // Two live expansions on one line warn twice.
        let results = run_mini("Name: foo\n# %(a) and %(b)\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 2, "{results:?}");
    }

    #[test]
    fn escaped_shell_expansion_in_comment_stays_quiet_482() {
        // %% is the documented escape: rpm leaves it a literal %.
        let results = run_mini("Name: foo\n# %%(touch /tmp/x)\n");
        assert!(
            !has(&results, "macro-in-comment"),
            "unexpected: {results:?}"
        );
        // An odd run still expands (and executes) on the first pass.
        let results = run_mini("Name: foo\n# %%%(touch /tmp/x)\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(
            lines[0].contains("E: macro-in-comment %%%(touch /tmp/x)"),
            "unexpected: {lines:?}"
        );
    }

    #[test]
    fn lua_and_load_in_comment_errors_482() {
        let results = run_mini("Name: foo\n# %{lua:io.open('/tmp/x','w')}\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(
            lines[0].contains("E: macro-in-comment %{lua:io.open('/tmp/x','w')}"),
            "unexpected: {lines:?}"
        );
        let results = run_mini("Name: foo\n# %{load:/tmp/defs.macros}\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(
            lines[0].contains("E: macro-in-comment %{load:/tmp/defs.macros}"),
            "unexpected: {lines:?}"
        );
        // A %(...) inside a Lua body is Lua data, not an rpm expansion:
        // the only finding is the Lua construct itself.
        let results = run_mini("Name: foo\n# %{lua:s = \"%(touch /tmp/x)\"}\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(lines[0].contains("%{lua:"), "unexpected: {lines:?}");
    }

    #[test]
    fn bare_directives_in_comment_errors_482() {
        // Review on #487 (verified against rpm 4.20.1): rpm also executes
        // the bare directives in a comment — %define/%global define a
        // macro, %undefine removes one, bare %lua runs and bare %load
        // loads a macro file.
        for (line, token) in [
            ("# %define foo 1", "%define foo 1"),
            ("# %global foo 1", "%global foo 1"),
            ("# %undefine foo", "%undefine foo"),
            (
                "# %lua os.execute('touch /tmp/x')",
                "%lua os.execute('touch /tmp/x')",
            ),
            ("# %load /tmp/defs.macros", "%load /tmp/defs.macros"),
        ] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            let lines = lines_for(&results, "macro-in-comment");
            assert_eq!(lines.len(), 1, "{line}: {results:?}");
            assert!(
                lines[0].contains(&format!("E: macro-in-comment {token}")),
                "{line}: {lines:?}"
            );
        }
        // A %define body is stored unexpanded, so a shell expansion in
        // it is part of the one finding, not a second execution.
        let results = run_mini("Name: foo\n# %define foo %(touch /tmp/x)\n");
        assert_eq!(
            lines_for(&results, "macro-in-comment").len(),
            1,
            "{results:?}"
        );
        // %undefine takes a single argument: a later live expansion on
        // the same line still fires on its own.
        let results = run_mini("Name: foo\n# %undefine foo %(touch /tmp/x)\n");
        assert_eq!(
            lines_for(&results, "macro-in-comment").len(),
            2,
            "{results:?}"
        );
    }

    #[test]
    fn braced_directives_in_comment_errors_482() {
        // The braced executing directives fire the same way: they define
        // or undefine a macro, and %{error:...} aborts the parse.
        for token in [
            "%{define:foo 1}",
            "%{global:foo 1}",
            "%{undefine:foo}",
            "%{error:boom}",
        ] {
            let results = run_mini(&format!("Name: foo\n# {token}\n"));
            let lines = lines_for(&results, "macro-in-comment");
            assert_eq!(lines.len(), 1, "{token}: {results:?}");
            assert!(
                lines[0].contains(&format!("E: macro-in-comment {token}")),
                "{token}: {lines:?}"
            );
        }
    }

    #[test]
    fn directive_lookalikes_in_comment_stay_quiet_482() {
        for line in [
            // No argument: the directive does nothing.
            "# %define",
            "# %lua",
            // (A longer name than a directive — %defined, %loader —
            // is a plain macro mention and errors under #1026; see
            // directive_lookalikes_error_as_plain_mentions_1026.)
            // The %license-type exclusions stay quiet (the intended
            // divergence the #487 review asked to keep).
            "# %license is how the license file is shipped",
            "# %{license:MIT}",
            // Empty braced arguments do not act.
            "# %{define:} and %{error:}",
            // Escaped: %% collapses to a literal %.
            "# %%define foo 1",
            "# %%{error:boom}",
        ] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            assert!(!has(&results, "macro-in-comment"), "{line}: {results:?}");
        }
    }

    #[test]
    fn directive_lookalikes_error_as_plain_mentions_1026() {
        // A name that merely starts like a directive is a plain macro
        // reference, and #1026 errors on plain mentions.
        for (line, token) in [
            ("# %defined foo 1", "%defined"),
            ("# %loader /tmp/defs.macros", "%loader"),
        ] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            let lines = lines_for(&results, "macro-in-comment");
            assert_eq!(lines.len(), 1, "{line}: {results:?}");
            assert!(
                lines[0].contains(&format!("E: macro-in-comment {token}")),
                "{line}: {lines:?}"
            );
        }
    }

    #[test]
    fn escaped_bare_directive_errors_inside_expand_482() {
        // One %{expand:...} pass consumes the escape, so the directive
        // goes live inside it, exactly like %%( does.
        let results = run_mini("Name: foo\n# %{expand:%%define foo 1}\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(
            lines[0].contains("E: macro-in-comment %%define foo 1"),
            "unexpected: {lines:?}"
        );
    }

    #[test]
    fn expand_controls_escaped_expansions_482() {
        // %{expand:...} re-expands its argument: one escape level is
        // consumed, so %%( goes live inside a single expand...
        let results = run_mini("Name: foo\n# %{expand:%%(touch /tmp/x)}\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(
            lines[0].contains("E: macro-in-comment %%(touch /tmp/x)"),
            "unexpected: {lines:?}"
        );
        // ...but %%%%( survives one expand still escaped.
        let results = run_mini("Name: foo\n# %{expand:%%%%(touch /tmp/x)}\n");
        assert!(
            !has(&results, "macro-in-comment"),
            "unexpected: {results:?}"
        );
        // A direct %(...) inside an expand fires; plain text does not.
        let results = run_mini("Name: foo\n# %{expand:%(touch /tmp/x)}\n");
        assert_eq!(
            lines_for(&results, "macro-in-comment").len(),
            1,
            "{results:?}"
        );
        // #1026: a plain mention inside an expand is expanded like
        // any other, so the mention errors too.
        let results = run_mini("Name: foo\n# %{expand:%{name} plain}\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(
            lines[0].contains("E: macro-in-comment %{name}"),
            "unexpected: {lines:?}"
        );
        // Escaped Lua inside an expand goes live the same way.
        let results = run_mini("Name: foo\n# %{expand:%%{lua:print(1)}}\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(
            lines[0].contains("E: macro-in-comment %%{lua:print(1)}"),
            "unexpected: {lines:?}"
        );
    }

    #[test]
    fn wrapped_shell_expansion_in_comment_errors_482() {
        // Other braced constructs expand their argument in place, and
        // conditional branches are expanded even when untaken.
        let results = run_mini("Name: foo\n# %{quote:%(touch /tmp/x)}\n");
        assert_eq!(
            lines_for(&results, "macro-in-comment").len(),
            1,
            "{results:?}"
        );
        let results = run_mini("Name: foo\n# %{!?nosuchmacro:%(touch /tmp/x)}\n");
        assert_eq!(
            lines_for(&results, "macro-in-comment").len(),
            1,
            "{results:?}"
        );
        // %[...] expressions are transparent to a nested expansion.
        let results = run_mini("Name: foo\n# %[%(touch /tmp/x) == \"\"]\n");
        assert_eq!(
            lines_for(&results, "macro-in-comment").len(),
            1,
            "{results:?}"
        );
    }

    #[test]
    fn pure_and_nonexistent_forms_in_comment_stay_quiet_482() {
        // Pure evaluation, inert keywords and forms rpm does not have
        // expand harmlessly or not at all: none of them can execute.
        for line in [
            "# sum %[1+1] and %{expr:2+2}",
            "# home is %{getenv:HOME}",
            "# %{shell:touch /tmp/x} and %{eval:1+1}",
            "# %endif",
            "# conditional %if 0 keyword",
        ] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            assert!(!has(&results, "macro-in-comment"), "{line}: {results:?}");
        }
    }

    #[test]
    fn commented_out_invocations_error_1026() {
        // The #1026 motivating shapes: mentions that read as
        // commented-out invocations. The scan is textual — it fires on
        // the mention itself and computes no expansion — so distro
        // macros are caught in mini mode too.
        for (spec, token) in [
            (
                "Name: foo\n# single-flavour application: no %python_subpackages here\n",
                "%python_subpackages",
            ),
            (
                "Name: foo\n%build\n./configure --enable-static\n#%configure --disable-static\n",
                "%configure",
            ),
            (
                "Name: foo\n%check\n# disabled, needs network: %pytest -k online\n",
                "%pytest",
            ),
            ("Name: foo\n%build\n#%cmake ..\n", "%cmake"),
            ("Name: foo\n%build\n#%meson ..\n", "%meson"),
            ("Name: foo\n%build\n#%cargo_build\n", "%cargo_build"),
        ] {
            let results = run_mini(spec);
            let lines = lines_for(&results, "macro-in-comment");
            assert_eq!(lines.len(), 1, "{spec}: {results:?}");
            assert!(
                lines[0].contains(&format!("E: macro-in-comment {token}")),
                "{spec}: {lines:?}"
            );
        }
        // Two plain mentions on one line error twice.
        let results = run_mini("Name: foo\n# a %{name} mention and %version\n");
        assert_eq!(
            lines_for(&results, "macro-in-comment").len(),
            2,
            "{results:?}"
        );
    }

    #[test]
    fn bare_conditional_sigils_error_1176() {
        // Item 3: a bare conditional reference names its macro after
        // the sigil, exactly as the braced form does, so it errors;
        // a keyword after the sigil stays quiet, and a lone sigil
        // names nothing.
        for (line, token) in [
            ("# see %?version for the old spelling", "%?version"),
            ("# see %!version for the old spelling", "%!version"),
        ] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            let lines = lines_for(&results, "macro-in-comment");
            assert_eq!(lines.len(), 1, "{line}: {results:?}");
            assert!(
                lines[0].contains(&format!("E: macro-in-comment {token}")),
                "{line}: {lines:?}"
            );
        }
        for line in ["# a %?license mention", "# a %!files section", "# just %?"] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            assert!(!has(&results, "macro-in-comment"), "{line}: {results:?}");
        }
    }

    #[test]
    fn nested_effectful_in_conditional_text_errors_1176() {
        // Item 6, settled against rpm output: rpm expands a taken
        // conditional branch's text, so the effectful forms nested
        // in `%{?name:...}` text execute whenever the guard holds;
        // the scan reports them (taken-ness is not decidable from
        // the comment), while plain mentions in the text stay quiet
        // (pinned in conditional_text_and_escapes_stay_quiet_1026).
        for line in [
            "# %{?foo:%{lua:print(1)}}",
            "# %{?foo:%(touch /tmp/x)}",
            "# %{?foo:%{error:boom}}",
            "# %{?foo:%define x 1}",
            "# %{!foo:%{lua:print(1)}}",
        ] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            assert_eq!(
                lines_for(&results, "macro-in-comment").len(),
                1,
                "{line}: {results:?}"
            );
        }
    }

    #[test]
    fn conditional_text_and_escapes_stay_quiet_1026() {
        for line in [
            // The conditional-with-text form is quiet, and so is a
            // plain mention inside its text.
            "# %{?with_tests:yes} enables the suite",
            "# %{?foo:%bar} legacy toggle",
            // Escapes and prose percent signs are not mentions.
            "# 100%% verified",
            "# 50% of the cases",
            // Spec-syntax keywords are not macros.
            "# %doc marks the documentation",
            "# %files lists the payload",
            // Special comments are skipped whole.
            "#!BuildIgnore: %{version}",
        ] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            assert!(!has(&results, "macro-in-comment"), "{line}: {results:?}");
        }
    }

    #[test]
    fn mention_of_later_definition_errors_1026() {
        // The scan is textual and does not track definitions, so a
        // mention of a macro defined further down — or under `%if 0`
        // — errors like any other mention.
        let results = run_mini("Name: foo\n# see %later for details\n%define later 1\n");
        let lines = lines_for(&results, "macro-in-comment");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(
            lines[0].contains("E: macro-in-comment %later"),
            "unexpected: {lines:?}"
        );
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
    fn comparison_operator_skips_parenthesized_versioned_deps() {
        // #362: `(clang >= 17)` and rich expressions using `=<` are boolean
        // dependencies; their operators are legitimate syntax, not misplaced
        // deptoken characters. The reference never warns on these.
        let spec = "Name:           wobble\nVersion:        1.0\nRelease:        1\n\
Summary:        Wobble\nLicense:        MIT\n\
BuildRequires:  (clang >= 17)\n\
BuildRequires:  (cmake(Clang) >= 1.0 with cmake(Clang) =< 2.0)\n\
Requires:       foo<bar\n";
        let results = run_mini(spec);
        let lines = lines_for(&results, "comparison-operator-in-deptoken");
        // Only the `foo<bar` positive control fires; the parenthesized
        // boolean dependencies stay silent.
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(lines[0].contains("foo<bar"), "{results:?}");
        assert!(lines[0].contains("W:"), "{results:?}");
    }

    #[test]
    fn comparison_operator_still_fires_on_glued_operator() {
        // `Requires: foo>=1.0` (no spaces) puts the operator in the deptoken;
        // the reference warns and so do we.
        let results = run_mini(
            "Name:           wobble\nVersion:        1.0\nRelease:        1\nSummary:        Wobble\nLicense:        MIT\nRequires:       foo>=1.0\n",
        );
        let lines = lines_for(&results, "comparison-operator-in-deptoken");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(lines[0].contains("W:"), "{results:?}");
    }

    #[test]
    fn comparison_operator_silent_on_macro_body_rich_deps() {
        // #588: inside a %define body each line ends with a continuation
        // backslash. Glued to the closing paren (`)\`) it is line
        // punctuation, not part of the token, so rich dependencies stay
        // silent exactly like the spaced spelling.
        for requires in [
            "(tesseract-ocr >= %{version} or libtesseract5 >= %{version})\\",
            "(tesseract-ocr >= %{version} or libtesseract5 >= %{version}) \\",
            "(a >= 1 and b >= 2)\\",
            "(a >= 1 with b < 2)\\",
        ] {
            let spec = format!(
                "Name:           wobble\nVersion:        1.0\nRelease:        1\nSummary:        Wobble\nLicense:        MIT\n\n%description\nWobble.\n\n%define lang_subpkg(m:l:n:o:) \\\n\\\n%package       %{{macrolang}}\\\nSummary:       %{{langname}} language data for %{{name}}\\\nBuildArch:     noarch\\\nRequires:      {requires}\n%lang_subpkg -m eng -n English -o english\n"
            );
            let results = run_mini(&spec);
            let lines = lines_for(&results, "comparison-operator-in-deptoken");
            assert!(lines.is_empty(), "{requires}: {results:?}");
        }
        // Plain preamble spellings of the same rich forms.
        for requires in [
            "(a >= 1 or b >= 2)",
            "(a >= 1 and b >= 2)",
            "(a >= 1 with b < 2)",
        ] {
            let results = run_mini(&format!(
                "Name:           wobble\nVersion:        1.0\nRelease:        1\nSummary:        Wobble\nLicense:        MIT\nRequires:       {requires}\n"
            ));
            let lines = lines_for(&results, "comparison-operator-in-deptoken");
            assert!(lines.is_empty(), "{requires}: {results:?}");
        }
    }

    #[test]
    fn comparison_operator_glued_operator_fires_with_continuation() {
        // Positive control in a %define continuation context: an
        // operator glued into the deptoken itself still warns, with or
        // without the trailing continuation backslash, while the spaced
        // spelling is an ordinary versioned dep and stays silent.
        let spec = "Name:           wobble\nVersion:        1.0\nRelease:        1\nSummary:        Wobble\nLicense:        MIT\n\n%description\nWobble.\n\n%define sub(m:) \\\n\\\n%package       %{macrolang}\\\nSummary:       sub\\\nBuildArch:     noarch\\\nRequires:      foo>=1.0\\\n%sub -m eng\n";
        let results = run_mini(spec);
        let lines = lines_for(&results, "comparison-operator-in-deptoken");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(lines[0].contains("foo>=1.0"), "{results:?}");

        let spaced = "Name:           wobble\nVersion:        1.0\nRelease:        1\nSummary:        Wobble\nLicense:        MIT\n\n%description\nWobble.\n\n%define sub(m:) \\\n\\\n%package       %{macrolang}\\\nSummary:       sub\\\nBuildArch:     noarch\\\nRequires:      foo >= 1.0\\\n%sub -m eng\n";
        let results = run_mini(spaced);
        let lines = lines_for(&results, "comparison-operator-in-deptoken");
        assert!(lines.is_empty(), "{results:?}");
    }

    #[test]
    fn controlchar_in_dep_list_still_fires_without_compop() {
        // Fast path: no comparison operator in the raw line, so `parse_deps`
        // is skipped -- the forbidden-controlchar probe must still fire on
        // the first token.
        let results = run_mini(
            "Name:           wobble\nVersion:        1.0\nRelease:        1\nSummary:        Wobble\nLicense:        MIT\nRequires:       dep\x01x bar\n",
        );
        let lines = lines_for(&results, "forbidden-controlchar-found");
        // The generic line-level check also fires (W:); the dep-list probe
        // is the E: one with the tag detail.
        let tagged: Vec<_> = lines.iter().filter(|l| l.contains(" E: ")).collect();
        assert_eq!(tagged.len(), 1, "{results:?}");
        assert!(tagged[0].contains("Requires: dep\x01x"), "{:?}", tagged[0]);
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
            "comparison-operator-in-deptoken",
            "suse-update-desktop-file-deprecated",
            "no-%check-section",
            "shared-dir-glob-in-files",
            "patch-not-applied",
        ] {
            assert!(has(&results, check), "missing {check}: {results:?}");
        }
        // Negative pin for the removed `configure-without-libdir-spec`
        // finding: the bare `./configure` above stays silent.
        assert!(
            !has(&results, "configure-without-libdir-spec"),
            "must stay silent: {results:?}"
        );
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
    fn codequery_spec_plus_invalid_url_divergence() {
        let input =
            include_str!("../../../../tests/parity/cases/codequery-spec/input/codequery.spec");
        let results = run_with(input, &Config::default());
        let summary: Vec<(&str, &str)> = results
            .iter()
            .map(|(c, l)| {
                let level = if l.contains(": E: ") {
                    "E"
                } else if l.contains(": I: ") {
                    "I"
                } else {
                    "W"
                };
                (c.as_str(), level)
            })
            .collect();
        for (check, level) in [
            ("suse-update-desktop-file-deprecated", "W"),
            ("superfluous-%clean-section", "E"),
            ("specfile-warning", "W"),
            ("no-%check-section", "I"),
        ] {
            assert!(
                summary.contains(&(check, level)),
                "missing {level}: {check} in {summary:?}"
            );
        }
        // Deliberate divergence (ledgered): a bare tarball filename is
        // not a URL and is not required to be one, so no `invalid-url`
        // fires here even though the reference emits one.
        let invalid = lines_for(&results, "invalid-url");
        assert!(invalid.is_empty(), "unexpected invalid-url: {invalid:?}");
        let warning = lines_for(&results, "specfile-warning");
        assert_eq!(warning.len(), 1);
        assert!(
            warning[0].contains("Macro expanded in comment on line 20"),
            "line: {}",
            warning[0]
        );
        // #1026: the `%{version}` on line 20 sits in a commented-out
        // URL; every unescaped mention errors (the reference warns).
        let comment = lines_for(&results, "macro-in-comment");
        assert_eq!(comment.len(), 1, "{results:?}");
        assert!(
            comment[0].contains("E: macro-in-comment %{version}"),
            "unexpected: {comment:?}"
        );
    }

    /// The unclosed-`%if` spec the dedup tests below parse: the
    /// in-process `Spec::parse` fails on it, so the bare-path fallback
    /// is armed unless the child already reported the failure.
    const UNTERM_SPEC: &str = "Name:           unterm\nVersion:        1.0\nRelease:        1\n\
         Summary:        unterm\nLicense:        MIT\n%if 0\n\n\
         %description\nunterm\n";

    /// Write a fake `rpm` tool running `body` (a shell script body
    /// after the shebang) into `dir`, so a test controls the child's
    /// stderr and exit status exactly instead of depending on the
    /// live `rpm` on `PATH`.
    #[cfg(unix)]
    fn fake_rpm(dir: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("rpm");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        // A just-written script can still be "text file busy" (ETXTBSY)
        // on first spawn under parallel load; settle it so the probe in
        // `SpecCheck::with_tool_dir` sees an exec-ready tool.
        for _ in 0..100 {
            match std::process::Command::new(&path).arg("--version").output() {
                Ok(_) => return,
                Err(e) if e.raw_os_error() == Some(26) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => panic!("fake rpm {} failed: {e}", path.display()),
            }
        }
        // Exhaustion must not fall through silently: with the tool
        // never exec-ready, the probe in `SpecCheck::with_tool_dir`
        // treats `rpm` as absent, and the filtered/silent tests
        // below could pass without the child ever running.
        panic!(
            "fake rpm {} never became exec-ready (ETXTBSY) in 100 attempts",
            path.display()
        );
    }

    /// Run `SpecCheck` over the unclosed-`%if` spec with `rpm`
    /// resolved under `tool_dir`, returning the results and the spec
    /// path (the fallback finding's detail).
    fn run_unterm_with_tool_dir(
        tool_dir: &Path,
        config: &Config,
    ) -> (Vec<(String, String)>, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unterm.spec");
        std::fs::write(&path, UNTERM_SPEC).unwrap();
        let pkg = SpecPkg::open(&path).unwrap();
        let mut check = SpecCheck::with_tool_dir(config, Some(tool_dir));
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        check.check_spec(&pkg, config, &mut out);
        (out.results().to_vec(), path.to_string_lossy().into_owned())
    }

    /// #702: one parse failure, one report. The fake `rpm` child's
    /// stderr carries the parse diagnostics and the `can't parse`
    /// summary and it exits non-zero, so the in-process parse failing
    /// on the same spec must not repeat the failure with its bare-path
    /// fallback finding. Hermetic: the child is the fake above, so the
    /// pin holds whatever `rpm` the host carries.
    #[test]
    #[cfg(unix)]
    fn specfile_error_not_duplicated_when_rpm_child_reports() {
        let tools = tempfile::tempdir().unwrap();
        fake_rpm(
            tools.path(),
            r#"for a in "$@"; do if [ "$a" = "--version" ]; then exit 0; fi; done
printf '%s\n' 'error: line 7: unclosed %if' >&2
printf '%s\n' "error: query of specfile failed, can't parse" >&2
exit 1"#,
        );
        let (results, path) = run_unterm_with_tool_dir(tools.path(), &Config::default());
        let errors = lines_for(&results, "specfile-error");
        assert!(
            errors.iter().any(|l| l.contains("can't parse")),
            "child summary missing: {errors:?}"
        );
        assert!(
            errors.iter().all(|l| l.contains("error:")),
            "bare-path fallback repeated the failure: {errors:?}"
        );
        assert!(
            errors.iter().all(|l| !l.contains(&path)),
            "bare-path fallback repeated the failure: {errors:?}"
        );
    }

    /// #702: a child emitting only non-fatal artefacts (an unknown-tag
    /// line, with a successful exit and no `can't parse` summary) has
    /// not reported the fatal failure the in-process parse hits, so
    /// the fallback still fires alongside the artefact.
    #[test]
    #[cfg(unix)]
    fn specfile_error_fallback_fires_when_child_reports_only_artefacts() {
        let tools = tempfile::tempdir().unwrap();
        fake_rpm(
            tools.path(),
            r#"for a in "$@"; do if [ "$a" = "--version" ]; then exit 0; fi; done
printf '%s\n' 'error: line 3: Unknown tag: Frobnicate' >&2
exit 0"#,
        );
        let (results, path) = run_unterm_with_tool_dir(tools.path(), &Config::default());
        let errors = lines_for(&results, "specfile-error");
        assert!(
            errors.iter().any(|l| l.contains("Unknown tag")),
            "child artefact missing: {errors:?}"
        );
        assert!(
            errors.iter().any(|l| l.contains(&path)),
            "fallback silenced by a non-fatal artefact: {errors:?}"
        );
    }

    /// #702: filter-suppressed child diagnostics are not a report.
    /// The filter pattern suppresses both child lines, while the
    /// bare-path fallback (a different match string) survives it, so
    /// the fallback fires and carries the failure alone.
    #[test]
    #[cfg(unix)]
    fn specfile_error_fallback_fires_when_child_lines_are_filtered() {
        let tools = tempfile::tempdir().unwrap();
        fake_rpm(
            tools.path(),
            r#"for a in "$@"; do if [ "$a" = "--version" ]; then exit 0; fi; done
printf '%s\n' 'error: childparse line 7: unclosed %if' >&2
printf '%s\n' "error: childparse query of specfile failed, can't parse" >&2
exit 1"#,
        );
        let config = Config {
            filters: vec!["childparse".to_string()],
            ..Config::default()
        };
        let (results, path) = run_unterm_with_tool_dir(tools.path(), &config);
        let errors = lines_for(&results, "specfile-error");
        assert!(
            errors.iter().all(|l| !l.contains("childparse")),
            "suppressed child lines leaked: {errors:?}"
        );
        assert_eq!(errors.len(), 1, "the lone fallback expected: {results:?}");
        assert!(
            errors[0].contains(&path),
            "fallback detail is the spec path: {}",
            errors[0]
        );
    }

    /// #702: a silent `rpm` child (successful exit, no output) reports
    /// nothing, so the in-process parse failure keeps its fallback
    /// finding.
    #[test]
    #[cfg(unix)]
    fn specfile_error_fallback_fires_when_rpm_child_is_silent() {
        let tools = tempfile::tempdir().unwrap();
        fake_rpm(tools.path(), "exit 0");
        let (results, path) = run_unterm_with_tool_dir(tools.path(), &Config::default());
        let errors = lines_for(&results, "specfile-error");
        assert_eq!(errors.len(), 1, "the lone fallback expected: {results:?}");
        assert!(
            errors[0].contains(&path),
            "fallback detail is the spec path: {}",
            errors[0]
        );
    }

    /// #702: undecodable child stderr reports an encoding failure,
    /// a distinct finding from a parse failure, so the in-process
    /// parse failure still gets its fallback finding alongside it.
    #[test]
    #[cfg(unix)]
    fn specfile_error_fallback_fires_when_child_stderr_is_not_utf8() {
        let tools = tempfile::tempdir().unwrap();
        fake_rpm(
            tools.path(),
            r#"for a in "$@"; do if [ "$a" = "--version" ]; then exit 0; fi; done
printf '\377\n' >&2
exit 1"#,
        );
        let (results, path) = run_unterm_with_tool_dir(tools.path(), &Config::default());
        let errors = lines_for(&results, "specfile-error");
        assert!(
            errors.iter().any(|l| l.contains("invalid utf-8")),
            "encoding failure missing: {errors:?}"
        );
        assert!(
            errors.iter().any(|l| l.contains(&path)),
            "fallback silenced by an encoding failure: {errors:?}"
        );
    }

    /// #702: with no `rpm` tool the child reports nothing, so the
    /// in-process parse failure keeps its fallback finding -- the dedup
    /// must not silence the only report of the failure.
    #[test]
    fn specfile_error_fallback_fires_without_rpm() {
        let empty = tempfile::tempdir().unwrap();
        let config = Config::default();
        let (results, path) = run_unterm_with_tool_dir(empty.path(), &config);
        let errors = lines_for(&results, "specfile-error");
        assert_eq!(errors.len(), 1, "the lone fallback expected: {results:?}");
        assert!(
            errors[0].contains(&path),
            "fallback detail is the spec path: {}",
            errors[0]
        );
    }

    /// A minimal spec scaffold for the `parse-time-cpu-count` tests:
    /// `pre` goes into the preamble (before `%description`), `build`
    /// becomes the `%build` section body.
    fn cpu_count_spec(pre: &str, build: &str) -> String {
        let mut text = String::new();
        text.push_str(pre);
        text.push_str(
            "Name:           wobble\n\
             Version:        1.0\n\
             Release:        1\n\
             Summary:        Wobble\n\
             License:        MIT\n\
             \n\
             %description\n\
             Wobble.\n\
             \n\
             %build\n",
        );
        text.push_str(build);
        text.push('\n');
        text
    }

    fn cpu_count_lines(results: &[(String, String)]) -> Vec<String> {
        lines_for(results, "parse-time-cpu-count")
    }

    #[test]
    fn parse_time_cpu_count_firing_forms_and_spec_define_override() {
        // The firing forms and the spec-define override are sequenced
        // in one test on purpose: parsing a spec pushes its `%define`s
        // into the process-global macro context, where they outlive
        // the parse, so after the override spec has been parsed the
        // context no longer shows the host's own `%jobs` state and no
        // other test in the process could judge `%jobs` against it.
        // The firing forms therefore run first; no other test judges
        // `%jobs`.
        for form in [
            "echo %jobs",
            "echo %{_smp_build_ncpus}",
            "echo %{_smp_build_nthreads}",
            "echo %{?jobs}",
            "echo %{?jobs:-n %jobs}",
        ] {
            let results = run_with(&cpu_count_spec("", form), &Config::default());
            let hits = cpu_count_lines(&results);
            assert_eq!(hits.len(), 1, "form {form:?}: {hits:?}");
            assert!(hits[0].contains("7919"), "form {form:?}: {}", hits[0]);
        }

        // A spec's own `%define jobs ${RPM_BUILD_NCPUS}` is the
        // run-time mapping: defined at spec level it overrides the
        // command-line-level sentinel, so even the conditional forms
        // store the shell variable, not a number.
        let build = "echo %jobs\necho %{?jobs:-n %jobs}";
        let results = run_with(
            &cpu_count_spec("%define jobs ${RPM_BUILD_NCPUS}\n", build),
            &Config::default(),
        );
        assert!(cpu_count_lines(&results).is_empty(), "{results:?}");
    }

    #[test]
    fn parse_time_cpu_count_dead_branch_stays_silent() {
        // A `%jobs` use in the never-taken branch of an `%if` is not
        // stored, and neither is one in a dead `%else` branch; the
        // live branch of the second spec carries no macro at all.
        let spec = cpu_count_spec("", "echo live\n%if 0\necho %{_smp_build_ncpus}\n%endif");
        let results = run_with(&spec, &Config::default());
        assert!(cpu_count_lines(&results).is_empty(), "{results:?}");
        let build = "%if 1\necho live\n%else\necho %{jobs}\n%endif";
        let results = run_with(&cpu_count_spec("", build), &Config::default());
        assert!(cpu_count_lines(&results).is_empty(), "{results:?}");
    }

    #[test]
    fn parse_time_cpu_count_escaped_and_run_time_forms_stay_silent() {
        for form in [
            // Escaped: stored literally, never expanded.
            "echo %%jobs",
            // A constant conditional body: the *value* of jobs is
            // discarded, so nothing parse-time is stored.
            "echo %{?jobs:-n 4}",
            // The run-time forms the tag description recommends.
            "echo %{?_smp_mflags}",
            "make ${RPM_BUILD_NCPUS}",
        ] {
            let results = run_with(&cpu_count_spec("", form), &Config::default());
            assert!(
                cpu_count_lines(&results).is_empty(),
                "form {form:?}: {results:?}"
            );
        }
    }

    #[test]
    fn parse_time_cpu_count_comment_in_script_section_fires() {
        // Comments inside script sections are stored (and expanded),
        // so a job-count macro in one stores the number too.
        let results = run_with(
            &cpu_count_spec("", "# pin workers to %{_smp_build_ncpus}\necho ok"),
            &Config::default(),
        );
        assert_eq!(cpu_count_lines(&results).len(), 1, "{results:?}");
    }

    #[test]
    fn parse_time_cpu_count_literal_sentinel_in_spec_does_not_fire() {
        // The sentinel is chosen outside the raw spec's own text: a
        // literal 7919 is not a finding, and a real expansion in the
        // same spec is reported under the bumped sentinel instead.
        let literal_only = run_with(&cpu_count_spec("", "echo 7919"), &Config::default());
        assert!(
            cpu_count_lines(&literal_only).is_empty(),
            "{literal_only:?}"
        );
        let mixed = run_with(
            &cpu_count_spec("", "echo 7919\necho %{_smp_build_ncpus}"),
            &Config::default(),
        );
        let hits = cpu_count_lines(&mixed);
        assert_eq!(hits.len(), 1, "{mixed:?}");
        assert!(hits[0].contains("17919"), "{}", hits[0]);
    }

    #[test]
    fn parse_time_cpu_count_parallel_checks_match_serial() {
        // The sentinel sequence (probe, defines, parse, pops) runs
        // against the process-global macro context; concurrent checks
        // must reproduce the serial result exactly -- a leaked define
        // or pop would change the stored text a sibling worker's parse
        // produces. The fixture uses the `%_smp_build_*` pair rather
        // than `%jobs`: a spec-level `%define jobs` parsed anywhere in
        // the process outlives its parse in the global context (see
        // the firing-forms test), so `%jobs` outcomes depend on
        // process history, not on this sequence's locking.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("race.spec");
        std::fs::write(
            &path,
            cpu_count_spec("", "echo %{_smp_build_ncpus} %{_smp_build_nthreads}"),
        )
        .unwrap();
        let config = Config::default();
        let baseline = run_spec_at(&path, &config);
        assert_eq!(cpu_count_lines(&baseline).len(), 1, "{baseline:?}");
        let mismatches: Vec<String> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        let mut bad = Vec::new();
                        for round in 0..10 {
                            if run_spec_at(&path, &config) != baseline {
                                bad.push(format!("round {round} diverged"));
                            }
                        }
                        bad
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap())
                .collect()
        });
        assert!(mismatches.is_empty(), "{mismatches:?}");
    }

    /// `check_invalid_url` defines `_sourcedir`, parses the spec and
    /// pops the define, all against the process-global macro context.
    /// Run distinct specs through the check concurrently and require
    /// every parallel result to equal the serial one. Each fixture's
    /// `Source` URLs embed `%{_sourcedir}`, so a sibling worker's define
    /// leaking into a parse changes that parse's `invalid-url` lines and
    /// breaks the equality.

    #[test]
    fn parallel_spec_checks_match_serial_results() {
        const WORKERS: usize = 8;
        const ROUNDS: usize = 20;
        const SOURCES: usize = 24;

        // One fixture spec per worker, each in its own directory, so
        // every worker's `_sourcedir` differs from the others'.
        let mut dirs = Vec::new();
        let mut paths = Vec::new();
        for w in 0..WORKERS {
            let dir = tempfile::tempdir().unwrap();
            let mut text = String::new();
            text.push_str("Name:           wobble\n");
            text.push_str("Version:        1.0\n");
            text.push_str("Release:        1\n");
            text.push_str("Summary:        Wobble\n");
            text.push_str("License:        MIT\n");
            for s in 0..SOURCES {
                text.push_str(&format!(
                    "Source{s}:        http://%{{_sourcedir}}/f{s}.tar.gz\n"
                ));
            }
            text.push_str("\n%description\nWobble.\n");
            let path = dir.path().join(format!("race{w}.spec"));
            std::fs::write(&path, &text).unwrap();
            dirs.push(dir);
            paths.push(path);
        }

        // Serial baselines. The fixture must yield one `invalid-url` per
        // source, all naming a single source directory, and the directory
        // must differ between fixtures -- otherwise the parallel
        // comparison below could not observe a leaked define.
        let config = Config::default();
        let baselines: Vec<Vec<(String, String)>> =
            paths.iter().map(|p| run_spec_at(p, &config)).collect();
        let mut prefixes = Vec::new();
        for baseline in &baselines {
            let invalid = lines_for(baseline, "invalid-url");
            assert_eq!(invalid.len(), SOURCES, "baseline: {invalid:?}");
            // librpm's source iteration order varies by version, so
            // pick the Source0 line explicitly instead of assuming it
            // heads the list.
            let first = invalid
                .iter()
                .find(|line| line.contains("Source0:"))
                .expect("baseline carries a Source0 finding");
            let prefix = first
                .split("http://")
                .nth(1)
                .and_then(|rest| rest.rsplit_once("/f0.tar.gz"))
                .map(|(prefix, _)| prefix.to_string())
                .expect("invalid-url line carries the expanded URL");
            assert!(
                invalid.iter().all(|l| l.contains(&prefix)),
                "all findings share one sourcedir: {invalid:?}"
            );
            prefixes.push(prefix);
        }
        let mut unique = prefixes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), WORKERS, "fixture sourcedirs must differ");

        // Parallel rounds: each worker re-checks only its own spec and
        // must reproduce its serial baseline exactly, every round.
        let mismatches: Vec<String> = std::thread::scope(|scope| {
            let handles: Vec<_> = paths
                .iter()
                .zip(&baselines)
                .map(|(path, baseline)| {
                    scope.spawn(move || {
                        let config = Config::default();
                        let mut bad = Vec::new();
                        for round in 0..ROUNDS {
                            let results = run_spec_at(path, &config);
                            if results != *baseline {
                                bad.push(format!(
                                    "{path:?} round {round} diverged from the serial baseline"
                                ));
                            }
                        }
                        bad
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap())
                .collect()
        });
        assert!(
            mismatches.is_empty(),
            "parallel spec checks diverged:\n{}",
            mismatches.join("\n")
        );
    }

    #[test]
    fn invalid_url_only_fires_for_malformed_urls() {
        fn spec_with(source_line: &str) -> String {
            format!(
                "Name:           wobble\nVersion:        1.0\nRelease:        1\n\
                 Summary:        Wobble\nLicense:        MIT\n{source_line}\n\n\
                 %description\nWobble.\n"
            )
        }
        // Bare filename: not a URL and not required to be one — no finding.
        let results = run_with(
            &spec_with("Source0:        codequery-0.08.tar.gz"),
            &Config::default(),
        );
        assert!(
            lines_for(&results, "invalid-url").is_empty(),
            "bare filename must not warn: {results:?}"
        );
        // Scheme present but empty netloc: a malformed URL — warns.
        let results = run_with(&spec_with("Source0:        http://"), &Config::default());
        let invalid = lines_for(&results, "invalid-url");
        assert_eq!(
            invalid.len(),
            1,
            "expected one invalid-url, got: {invalid:?}"
        );
        assert!(
            invalid[0].contains("W: invalid-url Source0: http://"),
            "line: {}",
            invalid[0]
        );
        // Well-formed URL: no finding.
        let results = run_with(
            &spec_with("Source0:        https://example.com/foo-1.0.tar.gz"),
            &Config::default(),
        );
        assert!(
            lines_for(&results, "invalid-url").is_empty(),
            "valid URL must not warn: {results:?}"
        );
        // The malformed-URL rule is not Source-only: Patch warns too.
        let results = run_with(&spec_with("Patch0:         http://"), &Config::default());
        let invalid = lines_for(&results, "invalid-url");
        assert_eq!(
            invalid.len(),
            1,
            "expected one invalid-url, got: {invalid:?}"
        );
        assert!(
            invalid[0].contains("W: invalid-url Patch0: http://"),
            "line: {}",
            invalid[0]
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

    /// Write a payload spec file (name + contents) into `dir` and return
    /// its `PkgFile`, for `check_source` name-consistency tests. The
    /// synthetic source package's header name is `w6-tmpfiles`.
    fn source_spec(
        dir: &tempfile::TempDir,
        name: &str,
        text: &str,
    ) -> crate::pkg::pkgfile::PkgFile {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        crate::pkg::pkgfile::PkgFile {
            name: name.to_string(),
            path: path.to_string_lossy().to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn invalid_spec_name_quiet_for_flavour_shaped_source() {
        // The multibuild artefact (#750): the container (header) name is
        // the build job's, the payload spec is self-consistent — its file
        // name matches its own `Name:` — so nothing fires.
        let dir = tempfile::tempdir().unwrap();
        let results = run_source(vec![source_spec(
            &dir,
            "selfnamed.spec",
            "Name: selfnamed\nVersion: 1\n",
        )]);
        assert!(!has(&results, "invalid-spec-name"), "results: {results:?}");
    }

    #[test]
    fn invalid_spec_name_quiet_when_file_matches_the_header_only() {
        // The file name matches the container (header) name, but the
        // spec declares a different name for itself: the header match
        // alone keeps it quiet — the finding fires only when the file
        // matches neither the header nor a declared name.
        let dir = tempfile::tempdir().unwrap();
        let results = run_source(vec![source_spec(
            &dir,
            "w6-tmpfiles.spec",
            "Name: renamed\nVersion: 1\n",
        )]);
        assert!(!has(&results, "invalid-spec-name"), "results: {results:?}");
    }

    #[test]
    fn invalid_spec_name_quiet_for_matching_declared_name() {
        let dir = tempfile::tempdir().unwrap();
        let results = run_source(vec![source_spec(
            &dir,
            "w6-tmpfiles.spec",
            "Name: w6-tmpfiles\nVersion: 1\n",
        )]);
        assert!(!has(&results, "invalid-spec-name"), "results: {results:?}");
    }

    #[test]
    fn invalid_spec_name_macro_name_resolves_to_a_pattern() {
        // A macro-valued `Name:` expands to a pattern: the undefined
        // macro is unconstrained and the literal tail anchors the
        // pattern, so a file named after the composed name stays quiet
        // while an unrelated file name still fires.
        let dir = tempfile::tempdir().unwrap();
        let matching = run_source(vec![source_spec(
            &dir,
            "w6-tmpfiles.spec",
            "Name: %{flavour}tmpfiles\nVersion: 1\n",
        )]);
        assert!(
            !has(&matching, "invalid-spec-name"),
            "results: {matching:?}"
        );
        let other = run_source(vec![source_spec(
            &dir,
            "other.spec",
            "Name: %{flavour}tmpfiles\nVersion: 1\n",
        )]);
        assert_eq!(
            lines_for(&other, "invalid-spec-name").len(),
            1,
            "results: {other:?}"
        );
    }

    #[test]
    fn invalid_spec_name_conditional_names_are_declared() {
        // A multibuild spec declares one `Name:` per flavour branch;
        // the payload file is named after one of them (the base), so
        // the flavour-shaped source stays quiet, while a file named
        // after no declared branch still fires.
        let dir = tempfile::tempdir().unwrap();
        let text = "%if 1\nName: cond\n%endif\nVersion: 1\n";
        let quiet = run_source(vec![source_spec(&dir, "cond.spec", text)]);
        assert!(!has(&quiet, "invalid-spec-name"), "results: {quiet:?}");
        let firing = run_source(vec![source_spec(&dir, "other.spec", text)]);
        assert_eq!(
            lines_for(&firing, "invalid-spec-name").len(),
            1,
            "results: {firing:?}"
        );
    }

    #[test]
    fn invalid_spec_name_quiet_for_macro_composed_flavour() {
        // The dominant multibuild shape (#750): the payload pins
        // `%global flavor`, the suffix macro branches on it and the
        // `Name:` composes base + suffix (the ImageMagick shape). The
        // payload file keeps the base name — a name the declarations
        // produce — so the flavour-shaped source stays quiet.
        let dir = tempfile::tempdir().unwrap();
        let text = "%global flavor config_open%{nil}\n\
                    %if \"%{flavor}\" == \"\"\n%define nsuffix %nil\n\
                    %else\n%define nsuffix -%{flavor}\n%endif\n\
                    Name: base%{?nsuffix}\nVersion: 1\n";
        let results = run_source(vec![source_spec(&dir, "base.spec", text)]);
        assert!(!has(&results, "invalid-spec-name"), "results: {results:?}");
    }

    #[test]
    fn invalid_spec_name_fires_when_template_produces_no_match() {
        // A macro-composed `Name:` still judges the file: a payload
        // file named after nothing the declarations can produce is
        // the genuine misnaming and fires.
        let dir = tempfile::tempdir().unwrap();
        let text = "%define sfx -x\nName: base%{?sfx}\nVersion: 1\n";
        let results = run_source(vec![source_spec(&dir, "stray.spec", text)]);
        assert_eq!(
            lines_for(&results, "invalid-spec-name").len(),
            1,
            "results: {results:?}"
        );
    }

    #[test]
    fn invalid_spec_name_fires_when_file_matches_neither_name() {
        // The payload file is named after neither the header nor any
        // name the spec declares: the genuine misnaming fires.
        let dir = tempfile::tempdir().unwrap();
        let results = run_source(vec![source_spec(
            &dir,
            "stray.spec",
            "Name: renamed\nVersion: 1\n",
        )]);
        let lines = lines_for(&results, "invalid-spec-name");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("E: invalid-spec-name"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn invalid_spec_name_unconstrained_declaration_falls_back_to_the_header() {
        // A `Name:` the preamble cannot determine — a macro it does
        // not define — leaves the header-name comparison in charge:
        // the header-named file stays quiet, any other file fires.
        let dir = tempfile::tempdir().unwrap();
        let text = "Name: %{pypi_name}\nVersion: 1\n";
        let quiet = run_source(vec![source_spec(&dir, "w6-tmpfiles.spec", text)]);
        assert!(!has(&quiet, "invalid-spec-name"), "results: {quiet:?}");
        let firing = run_source(vec![source_spec(&dir, "other.spec", text)]);
        assert_eq!(
            lines_for(&firing, "invalid-spec-name").len(),
            1,
            "results: {firing:?}"
        );
    }

    #[test]
    fn invalid_spec_name_nameless_preamble_uses_the_header_name() {
        // No `Name:` in the preamble at all: the header-name
        // comparison decides, as it did before declared names were
        // consulted.
        let dir = tempfile::tempdir().unwrap();
        let text = "Version: 1\nSummary: x\n";
        let quiet = run_source(vec![source_spec(&dir, "w6-tmpfiles.spec", text)]);
        assert!(!has(&quiet, "invalid-spec-name"), "results: {quiet:?}");
        let firing = run_source(vec![source_spec(&dir, "other.spec", text)]);
        assert_eq!(
            lines_for(&firing, "invalid-spec-name").len(),
            1,
            "results: {firing:?}"
        );
    }

    #[test]
    fn invalid_spec_name_quiet_for_pattern_only_match() {
        // The payload file is named after a name only the declared
        // pattern produces — the header names a different
        // package — and the pattern alone keeps it quiet.
        let dir = tempfile::tempdir().unwrap();
        let results = run_source(vec![source_spec(
            &dir,
            "footmpfiles.spec",
            "Name: %{flavour}tmpfiles\nVersion: 1\n",
        )]);
        assert!(!has(&results, "invalid-spec-name"), "results: {results:?}");
    }

    #[test]
    fn invalid_spec_name_two_branch_union() {
        // A multibuild spec declares one `Name:` per conditional
        // branch; the accepted set is the union over both branches,
        // so a payload file named after either branch stays quiet
        // and a file named after neither fires.
        let dir = tempfile::tempdir().unwrap();
        let text = "%if 1\nName: alpha\n%else\nName: beta\n%endif\nVersion: 1\n";
        for name in ["alpha.spec", "beta.spec"] {
            let results = run_source(vec![source_spec(&dir, name, text)]);
            assert!(
                !has(&results, "invalid-spec-name"),
                "{name} results: {results:?}"
            );
        }
        let firing = run_source(vec![source_spec(&dir, "stray.spec", text)]);
        assert_eq!(
            lines_for(&firing, "invalid-spec-name").len(),
            1,
            "results: {firing:?}"
        );
    }

    #[test]
    fn invalid_spec_name_mixed_declarations_judge_by_the_constrained_one() {
        // One declaration's name is determinable, the other's is
        // not: the unconstrained declaration constrains nothing and
        // is set aside, so the determinable one judges — a file
        // named after it stays quiet even though the header names a
        // different package, and a file named after neither fires.
        let dir = tempfile::tempdir().unwrap();
        let text = "%if 1\nName: cond\n%endif\nName: %{pypi_name}\nVersion: 1\n";
        let quiet = run_source(vec![source_spec(&dir, "cond.spec", text)]);
        assert!(!has(&quiet, "invalid-spec-name"), "results: {quiet:?}");
        let header = run_source(vec![source_spec(&dir, "w6-tmpfiles.spec", text)]);
        assert!(!has(&header, "invalid-spec-name"), "results: {header:?}");
        let firing = run_source(vec![source_spec(&dir, "other.spec", text)]);
        assert_eq!(
            lines_for(&firing, "invalid-spec-name").len(),
            1,
            "results: {firing:?}"
        );
    }

    #[test]
    fn invalid_spec_name_mixed_macro_definitions_keep_the_concrete_name() {
        // A macro defined literally in one declaration and
        // undeterminably in another: the concrete name the preamble
        // does determine judges \u2014 a file named after it stays quiet
        // even though the header names a different package, and a
        // file named after neither fires.
        let dir = tempfile::tempdir().unwrap();
        let text = "%define v one\n%define v %(shell)\nName: %{v}\nVersion: 1\n";
        let quiet = run_source(vec![source_spec(&dir, "one.spec", text)]);
        assert!(!has(&quiet, "invalid-spec-name"), "results: {quiet:?}");
        let firing = run_source(vec![source_spec(&dir, "other.spec", text)]);
        assert_eq!(
            lines_for(&firing, "invalid-spec-name").len(),
            1,
            "results: {firing:?}"
        );
    }

    #[test]
    fn invalid_spec_name_suffixed_branch_union() {
        // Each conditional branch pins its own suffix; a payload
        // file named after either branch's suffixed name stays
        // quiet, and a file named after neither fires.
        let dir = tempfile::tempdir().unwrap();
        let text =
            "%if 0\n%global sfx -a\n%else\n%global sfx -b\n%endif\nName: pkg%{sfx}\nVersion: 1\n";
        for name in ["pkg-a.spec", "pkg-b.spec"] {
            let results = run_source(vec![source_spec(&dir, name, text)]);
            assert!(
                !has(&results, "invalid-spec-name"),
                "{name} results: {results:?}"
            );
        }
        let firing = run_source(vec![source_spec(&dir, "pkg-c.spec", text)]);
        assert_eq!(
            lines_for(&firing, "invalid-spec-name").len(),
            1,
            "results: {firing:?}"
        );
    }

    #[test]
    fn invalid_spec_name_branch_undefine_keeps_the_defined_name() {
        // A `%undefine` inside a conditional branch removes the
        // macro for that branch's reading only: the name the other
        // reading defines still judges, so a file named after it
        // stays quiet even though the header names a different
        // package, and a file named after neither fires.
        let dir = tempfile::tempdir().unwrap();
        let text = "%define v one\n%if 0\n%undefine v\n%endif\nName: %{v}\nVersion: 1\n";
        let quiet = run_source(vec![source_spec(&dir, "one.spec", text)]);
        assert!(!has(&quiet, "invalid-spec-name"), "results: {quiet:?}");
        let firing = run_source(vec![source_spec(&dir, "other.spec", text)]);
        assert_eq!(
            lines_for(&firing, "invalid-spec-name").len(),
            1,
            "results: {firing:?}"
        );
    }

    // ----- #1020 silent constructs -----

    #[test]
    fn subpackage_without_files_fires_1020() {
        let results = run_mini(
            "Name: zig\n%package libs\nSummary: libs\n%description libs\nlibs\n%files\n/usr/bin/zig\n",
        );
        let lines = lines_for(&results, "subpackage-without-files");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(lines[0].contains("%package libs"), "{lines:?}");
    }

    #[test]
    fn subpackage_without_files_n_form_fires_1020() {
        let results = run_mini("Name: foo\n%package -n foo-tools\nSummary: t\n");
        let lines = lines_for(&results, "subpackage-without-files");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(lines[0].contains("%package -n foo-tools"), "{lines:?}");
    }

    #[test]
    fn subpackage_with_files_is_quiet_1020() {
        // An empty %files section still names the subpackage.
        let results = run_mini(
            "Name: foo\n%package doc\nSummary: d\n%description doc\nd\n%files doc\n%files\n/usr/bin/foo\n",
        );
        assert!(
            !has(&results, "subpackage-without-files"),
            "unexpected: {results:?}"
        );
        // `%files -f` names the subpackage too.
        let results = run_mini(
            "Name: foo\n%package doc\nSummary: d\n%description doc\nd\n%files -f list doc\n",
        );
        assert!(
            !has(&results, "subpackage-without-files"),
            "unexpected: {results:?}"
        );
        // The main package without %files is out of scope.
        let results = run_mini("Name: foo\nSummary: x\n");
        assert!(
            !has(&results, "subpackage-without-files"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn subpackage_python_files_cover_1020() {
        let results = run_mini(
            "Name: python-foo\n%package converters\nSummary: c\n%description converters\nc\n%files %{python_files converters}\n",
        );
        assert!(
            !has(&results, "subpackage-without-files"),
            "unexpected: {results:?}"
        );
        // A different python_files name does not cover it.
        let results = run_mini(
            "Name: python-foo\n%package converters\nSummary: c\n%description converters\nc\n%files %{python_files other}\n",
        );
        assert!(has(&results, "subpackage-without-files"), "{results:?}");
    }

    #[test]
    fn subpackage_macro_short_forms_match_1020() {
        // A macro-built short name binds the same way on the
        // `%package` and `%files` sides, whichever conditional
        // definition wins.
        let results = run_mini(
            "Name: budgie\n%define nsuffix openSUSE\n%define nsuffix SLE\n%package %{nsuffix}\nSummary: s\n%files %{nsuffix}\n/usr/share/x\n",
        );
        assert!(
            lines_for(&results, "subpackage-without-files").is_empty(),
            "{results:?}"
        );
    }

    #[test]
    fn subpackage_unresolvable_main_name_suffix_quiet_1020() {
        // When `Name:` itself does not expand, whether `%files data`
        // covers `-n %{pname}-data` is undecidable: quiet. With a
        // known main name the same shape is a real miss and fires.
        let results = run_mini(
            "Name: %{pname}%{?my_suffix}\n%define pname elk\n%package -n %{pname}-data\nSummary: s\n%files data\n/usr/share/x\n",
        );
        assert!(
            lines_for(&results, "subpackage-without-files").is_empty(),
            "{results:?}"
        );
        let results =
            run_mini("Name: foo\n%package -n bar-data\nSummary: s\n%files data\n/usr/share/x\n");
        assert_eq!(
            lines_for(&results, "subpackage-without-files").len(),
            1,
            "{results:?}"
        );
    }

    #[test]
    fn subpackage_python_files_nested_arg_1020() {
        let results = run_mini(
            "Name: eduvpn-client\n%package -n python-%{name}\nSummary: s\n%files %{python_files %{name}}\n",
        );
        assert!(
            lines_for(&results, "subpackage-without-files").is_empty(),
            "{results:?}"
        );
    }

    #[test]
    fn subpackage_quoted_files_name_1020() {
        let results = run_mini(
            "Name: libxdg-basedir\n%define soname 1\n%package -n %{name}%{soname}\nSummary: s\n%files -n \"%{name}%{soname}\"\n/usr/lib/libxdg-basedir.so.1\n",
        );
        assert!(
            lines_for(&results, "subpackage-without-files").is_empty(),
            "{results:?}"
        );
    }

    #[test]
    fn subpackage_python_files_no_arg_covers_python_only_1020() {
        // The no-argument generation form covers the declared
        // python subpackages; an unrelated header still fires.
        let results = run_mini(
            "Name: mapserver\n%package -n python-mapscript\nSummary: s\n%package tools\nSummary: t\n%files %python_files\n",
        );
        let lines = lines_for(&results, "subpackage-without-files");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(lines[0].contains("%package tools"), "{lines:?}");
    }

    #[test]
    fn subpackage_undecidable_shapes_stay_quiet_1020() {
        // Unresolved macro in the %package header.
        let results = run_mini("Name: foo\n%package %{unknownmacro}\nSummary: u\n");
        assert!(
            !has(&results, "subpackage-without-files"),
            "unexpected: {results:?}"
        );
        // A spec using %include.
        let results =
            run_mini("Name: foo\n%include %{_sourcedir}/x.inc\n%package libs\nSummary: l\n");
        assert!(
            !has(&results, "subpackage-without-files"),
            "unexpected: {results:?}"
        );
        // The KMP template under %kernel_module_package.
        let results = run_mini(
            "Name: foo\n%kernel_module_package -n foo\n%package -n foo-kmp-default\nSummary: k\n",
        );
        assert!(
            !has(&results, "subpackage-without-files"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn subpackage_files_header_after_shell_traps_1020() {
        // Shell state opened in an earlier section does not hide a
        // later %files header from the scan.
        let results = run_mini(
            "Name: foo\n%package doc\nSummary: d\n%description doc\nd\n%prep\necho $((1<<n))\nprintf $'it\\'s\\n'\ncat <<\\EOF\nbody\nEOF\n%files doc\n",
        );
        assert!(
            !has(&results, "subpackage-without-files"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn comment_in_continued_command_fires_1020() {
        let results = run_mini("Name: foo\n%prep\n./configure \\\n# comment\n--flags\n");
        let lines = lines_for(&results, "comment-in-continued-command");
        assert_eq!(lines.len(), 1, "{results:?}");
        // The ardour shape: comment inside the chain under %ifarch.
        let results = run_mini(
            "Name: foo\n%prep\n%ifarch aarch64\n./waf configure \\\n# comment\n--dist-target=aarch64\n%endif\n",
        );
        assert_eq!(
            lines_for(&results, "comment-in-continued-command").len(),
            1,
            "{results:?}"
        );
        // Assignment continued into a comment.
        let results = run_mini("Name: foo\n%prep\nFOO=bar \\\n# comment\n./configure\n");
        assert_eq!(
            lines_for(&results, "comment-in-continued-command").len(),
            1,
            "{results:?}"
        );
        // A commented-out flag that keeps its backslash still fires:
        // the comment itself is the line that ends the command.
        let results = run_mini("Name: foo\n%prep\n./configure \\\n# --foo \\\n--bar\n");
        assert_eq!(
            lines_for(&results, "comment-in-continued-command").len(),
            1,
            "{results:?}"
        );
    }

    #[test]
    fn comment_in_continued_command_quiet_shapes_1020() {
        // %else restores the pre-%if continuation state.
        let results = run_mini("Name: foo\n%prep\n%if 1\ncmd \\\n%else\n# c\n%endif\n");
        assert!(
            !has(&results, "comment-in-continued-command"),
            "unexpected: {results:?}"
        );
        // A `#` line inside a macro body.
        let results = run_mini("Name: foo\n%define foo \\\n# text\nbar\n%prep\ncmd \\\n# c\n");
        assert_eq!(
            lines_for(&results, "comment-in-continued-command").len(),
            1,
            "{results:?}"
        );
        let results = run_mini("Name: foo\n%define foo \\\n# text\nbar\n%prep\ncmd\n# c\n");
        assert!(
            !has(&results, "comment-in-continued-command"),
            "unexpected: {results:?}"
        );
        // A `#` line inside a heredoc body.
        let results = run_mini("Name: foo\n%prep\ncat <<EOF\n# text\nEOF\n");
        assert!(
            !has(&results, "comment-in-continued-command"),
            "unexpected: {results:?}"
        );
        // A `#` line inside a multi-line quoted string.
        let results = run_mini("Name: foo\n%prep\necho 'one\n# two'\n");
        assert!(
            !has(&results, "comment-in-continued-command"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn silent_constructs_gap_fixes_1164() {
        // Item 1: the `for` credit reads the last shell word before
        // the variable, whatever precedes it on the line.
        let results =
            run_mini("Name: foo\n%prep\nif true; then for name in a; do echo ${name}; done; fi\n");
        assert!(
            !has(&results, "spec-tag-as-shell-variable"),
            "unexpected: {results:?}"
        );
        // Item 6: `while read` credits the loop variable.
        let results =
            run_mini("Name: foo\n%prep\nwhile read name; do echo $name; done < /dev/null\n");
        assert!(
            !has(&results, "spec-tag-as-shell-variable"),
            "unexpected: {results:?}"
        );
        // Item 9: `echo name=...` is not an assignment; `name+=...`
        // at command position is.
        let results = run_mini("Name: foo\n%prep\necho name=text\necho $name\n");
        assert_eq!(
            lines_for(&results, "spec-tag-as-shell-variable").len(),
            1,
            "{results:?}"
        );
        let results = run_mini("Name: foo\n%prep\nname+=x\necho $name\n");
        assert!(
            !has(&results, "spec-tag-as-shell-variable"),
            "unexpected: {results:?}"
        );
        // Item 14: `${#name}` and `${!name}` read the tag variables.
        let results = run_mini("Name: foo\n%prep\necho ${#name} ${!version}\n");
        assert_eq!(
            lines_for(&results, "spec-tag-as-shell-variable").len(),
            2,
            "{results:?}"
        );
        // Item 3: the full conditional family saves and restores the
        // continuation state.
        let results = run_mini("Name: foo\n%prep\n%ifdef %{x}\ncmd \\\n%else\n# c\n%endif\n");
        assert!(
            !has(&results, "comment-in-continued-command"),
            "unexpected: {results:?}"
        );
        let results =
            run_mini("Name: foo\n%prep\n%ifarch x86_64\ncmd \\\n%elifarch aarch64\n# c\n%endif\n");
        assert!(
            !has(&results, "comment-in-continued-command"),
            "unexpected: {results:?}"
        );
        // Item 7: a backslash followed by a blank is an escaped
        // blank, not a continuation.
        let results = run_mini("Name: foo\n%prep\ncmd \\ \n# c\n");
        assert!(
            !has(&results, "comment-in-continued-command"),
            "unexpected: {results:?}"
        );
        // Item 15: a backslash-terminated comment keeps the
        // continuation state, so the next comment line is still
        // inside the continued command.
        let results = run_mini("Name: foo\n%prep\ncmd \\\n# c \\\n# d\n");
        assert_eq!(
            lines_for(&results, "comment-in-continued-command").len(),
            2,
            "{results:?}"
        );
        // Item 11: a shift inside arithmetic nested in a subshell is
        // not a heredoc; the comment after the continued line fires.
        let results = run_mini("Name: foo\n%prep\n( echo $(( (1 << 2) )) ) \\\n# comment\n");
        assert_eq!(
            lines_for(&results, "comment-in-continued-command").len(),
            1,
            "{results:?}"
        );
    }

    #[test]
    fn silent_constructs_heredoc_terminator_1164() {
        // Item 10: a plain heredoc terminator is the exact line; a
        // blank-padded line does not end a quoted heredoc.
        let results = run_mini("Name: foo\n%prep\ncat <<'EOF'\nbody\n EOF\necho $name\nEOF\n");
        assert!(
            !has(&results, "spec-tag-as-shell-variable"),
            "unexpected: {results:?}"
        );
        // The `<<-` form strips leading tabs, and only tabs.
        let results = run_mini("Name: foo\n%prep\ncat <<-EOF\nbody\n\tEOF\necho $name\n");
        assert_eq!(
            lines_for(&results, "spec-tag-as-shell-variable").len(),
            1,
            "{results:?}"
        );
        let results = run_mini("Name: foo\n%prep\ncat <<-'EOF'\nbody\n  EOF\necho $name\nEOF\n");
        assert!(
            !has(&results, "spec-tag-as-shell-variable"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn silent_constructs_macro_body_and_undefine_1164() {
        // Item 2: a header-shaped line inside a macro body is body
        // text, not a %package header.
        let results =
            run_mini("Name: foo\n%define x \\\n%package evil\n%prep\ntrue\n%files\n/usr/bin/foo\n");
        assert!(
            !has(&results, "subpackage-without-files"),
            "unexpected: {results:?}"
        );
        // Item 4: `%undefine` removes a collected define, so the
        // subpackage name built from it is undecidable and skipped;
        // without the undefine the same shape fires.
        let results = run_mini(
            "Name: foo\n%define suffix bar\n%package %{suffix}\nSummary: s\n%description %{suffix}\nd\n%files baz\n/usr/bin/x\n",
        );
        assert_eq!(
            lines_for(&results, "subpackage-without-files").len(),
            1,
            "{results:?}"
        );
        let results = run_mini(
            "Name: foo\n%define suffix bar\n%undefine suffix\n%package %{suffix}\nSummary: s\n%description %{suffix}\nd\n%files baz\n/usr/bin/x\n",
        );
        assert!(
            !has(&results, "subpackage-without-files"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn silent_constructs_name_conflict_and_python_family_1164() {
        // Item 12: conflicting Name: headers make the base name
        // undecidable; an identical duplicate does not.
        let results = run_mini(
            "Name: foo\nName: bar\n%package sub\nSummary: s\n%description sub\nd\n%files\n/usr/bin/foo\n",
        );
        assert!(
            !has(&results, "subpackage-without-files"),
            "unexpected: {results:?}"
        );
        let results = run_mini(
            "Name: foo\nName: foo\n%package sub\nSummary: s\n%description sub\nd\n%files\n/usr/bin/foo\n",
        );
        assert_eq!(
            lines_for(&results, "subpackage-without-files").len(),
            1,
            "{results:?}"
        );
        // Item 5: the no-arg %{python_files} credit covers the
        // python-digit flavour family, not just python-/python3-.
        let results = run_mini(
            "Name: python-foo\n%package -n python311-bar\nSummary: s\n%description -n python311-bar\nd\n%files %{python_files}\n",
        );
        assert!(
            !has(&results, "subpackage-without-files"),
            "unexpected: {results:?}"
        );
        let results = run_mini(
            "Name: python-foo\n%package -n ruby-bar\nSummary: s\n%description -n ruby-bar\nd\n%files %{python_files}\n",
        );
        assert_eq!(
            lines_for(&results, "subpackage-without-files").len(),
            1,
            "{results:?}"
        );
    }

    #[test]
    fn silent_constructs_scriptlet_interpreter_1164() {
        // Item 13: a scriptlet whose -p interpreter is not a shell
        // is not shell-scanned; a shell interpreter still is.
        let results = run_mini("Name: foo\n%post -p /usr/bin/python3\nprint($name)\n");
        assert!(
            !has(&results, "spec-tag-as-shell-variable"),
            "unexpected: {results:?}"
        );
        let results = run_mini("Name: foo\n%post -p /bin/sh\necho $name\n");
        assert_eq!(
            lines_for(&results, "spec-tag-as-shell-variable").len(),
            1,
            "{results:?}"
        );
    }

    #[test]
    fn sc_expand_placeholder_and_utf8_1164() {
        // Items 8 and 16: the %% placeholder never leaks into an
        // expansion result, and non-ASCII text survives expansion.
        let check = SpecCheck::new(&config_mini());
        assert_eq!(check.sc_expand("foo%%bar"), Some("foo%bar".to_string()));
        assert_eq!(check.sc_expand("100%%"), Some("100%".to_string()));
        assert_eq!(check.sc_expand("föö%{nil}"), Some("föö".to_string()));
    }

    #[test]
    fn spec_tag_as_shell_variable_fires_1020() {
        let results = run_mini("Name: foo\n%prep\nrm -rf %{buildroot}/doc/${name}\n");
        let lines = lines_for(&results, "spec-tag-as-shell-variable");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(lines[0].contains("${name}"), "{lines:?}");
        assert!(lines[0].contains("$RPM_PACKAGE_NAME"), "{lines:?}");
        // The zsh shape, in %build.
        let results = run_mini(
            "Name: zsh\n%build\n./configure --enable-fndir=/usr/share/%{name}/${version}/functions\n",
        );
        let lines = lines_for(&results, "spec-tag-as-shell-variable");
        assert_eq!(lines.len(), 1, "{results:?}");
        // Inside double quotes the variable still expands.
        let results = run_mini("Name: foo\n%prep\necho \"$release\"\n");
        assert_eq!(
            lines_for(&results, "spec-tag-as-shell-variable").len(),
            1,
            "{results:?}"
        );
    }

    #[test]
    fn spec_tag_as_shell_variable_scriptlet_message_1020() {
        // Install-time scriptlets name only the rpm macro: rpm exports
        // no RPM_PACKAGE_* variables there.
        let results = run_mini("Name: foo\n%post\necho $version\n");
        let lines = lines_for(&results, "spec-tag-as-shell-variable");
        assert_eq!(lines.len(), 1, "{results:?}");
        assert!(lines[0].contains("%{version}"), "{lines:?}");
        assert!(!lines[0].contains("RPM_PACKAGE"), "{lines:?}");
    }

    #[test]
    fn tag_var_line_numbers_stay_absolute_1020() {
        // Findings flushed at a later section header keep the absolute
        // line of the use, and flushing must not disturb the line
        // counter for the sections that follow.
        let spec =
            "Name: foo\n%post a\necho ${name}\n%postun a\necho ${name}\n%post b\necho ${name}\n";
        let results = run_mini(spec);
        let hits = lines_for(&results, "spec-tag-as-shell-variable");
        assert_eq!(hits.len(), 3, "{results:?}");
        assert!(hits[0].contains(":3:"), "{hits:?}");
        assert!(hits[1].contains(":5:"), "{hits:?}");
        assert!(hits[2].contains(":7:"), "{hits:?}");
    }

    #[test]
    fn tag_var_heredoc_closes_and_assignments_count_1020() {
        // The heredoc terminator ends the body: lines after it are
        // shell again, and an assignment there counts for the
        // section (as does one anywhere else in the section).
        let results =
            run_mini("Name: foo\n%build\ncat <<EOF\nbody\nEOF\nname=${nic%%:*}\necho ${name}\n");
        assert!(
            lines_for(&results, "spec-tag-as-shell-variable").is_empty(),
            "{results:?}"
        );
        let results =
            run_mini("Name: foo\n%build\ncat <<EOF\necho $name\nEOF\nname=x\necho $name\n");
        assert!(
            lines_for(&results, "spec-tag-as-shell-variable").is_empty(),
            "{results:?}"
        );
    }

    #[test]
    fn quoted_heredoc_keeps_quote_state_1020() {
        // A quoted heredoc delimiter does not open a quote: lines
        // after the terminator scan as plain shell, so a tag
        // variable there still fires and continuation tracking
        // still works, while a single-quoted variable stays quiet.
        for opener in ["cat <<'EOF'", "cat <<\"EOF\""] {
            let spec = format!("Name: foo\n%prep\n{opener}\nbody\nEOF\necho $name\n");
            let results = run_mini(&spec);
            assert_eq!(
                lines_for(&results, "spec-tag-as-shell-variable").len(),
                1,
                "opener {opener}: {results:?}"
            );
            let spec = format!(
                "Name: foo\n%prep\n{opener}\nbody\nEOF\n./configure \\\n# comment\n--flags\n"
            );
            let results = run_mini(&spec);
            assert_eq!(
                lines_for(&results, "comment-in-continued-command").len(),
                1,
                "opener {opener}: {results:?}"
            );
            let spec = format!("Name: foo\n%prep\n{opener}\nbody\nEOF\necho '$name'\n");
            let results = run_mini(&spec);
            assert!(
                !has(&results, "spec-tag-as-shell-variable"),
                "opener {opener}: {results:?}"
            );
        }
    }

    #[test]
    fn tag_var_env_prefixed_read_assigns_1020() {
        let results =
            run_mini("Name: foo\n%build\nIFS=: read -r name vid did <<< \"$nic\"\necho ${name}\n");
        assert!(
            lines_for(&results, "spec-tag-as-shell-variable").is_empty(),
            "{results:?}"
        );
    }

    #[test]
    fn spec_tag_as_shell_variable_quiet_shapes_1020() {
        for text in [
            "Name: foo\n%prep\necho %{name}\n",
            "Name: foo\n%prep\necho $RPM_PACKAGE_NAME\n",
            "Name: foo\n%prep\necho $NAME\n",
            "Name: foo\n%prep\necho \\$name\n",
            "Name: foo\n%prep\nawk '{print $name}' file\n",
            "Name: foo\n%prep\ncat <<'EOF'\n$name\nEOF\n",
            "Name: foo\n%prep\ncat <<\\EOF\n$name\nEOF\n",
            "Name: foo\n%prep\nname=foo\necho $name\n",
            "Name: foo\n%prep\necho $name\nname=foo\n",
            "Name: foo\n%prep\nfor name in a b; do echo $name; done\n",
            "Name: foo\n%prep\nread name\necho $name\n",
            "Name: foo\n%prep\nlocal name\necho $name\n",
        ] {
            let results = run_mini(text);
            assert!(
                !has(&results, "spec-tag-as-shell-variable"),
                "spec: {text:?} unexpected: {results:?}"
            );
        }
    }

    #[test]
    fn check_source_tolerates_an_unreadable_payload_spec() {
        // A payload spec listed in the SRPM that cannot be opened
        // — removed between the listing and the read — is
        // judged on the header name alone and the spec checks are
        // skipped for it, without panicking.
        let missing = |name: &str| crate::pkg::pkgfile::PkgFile {
            name: name.to_string(),
            path: format!("/nonexistent/{name}"),
            ..Default::default()
        };
        let quiet = run_source(vec![missing("w6-tmpfiles.spec")]);
        assert!(quiet.is_empty(), "results: {quiet:?}");
        let firing = run_source(vec![missing("stray.spec")]);
        assert_eq!(
            lines_for(&firing, "invalid-spec-name").len(),
            1,
            "results: {firing:?}"
        );
    }

    #[test]
    fn check_source_runs_spec_checks_on_the_header_named_spec() {
        // With several payload specs, the spec checks run on the
        // header-named file in preference to an earlier
        // declaration-named one: the header name is the container's
        // own name for the source.
        let dir = tempfile::tempdir().unwrap();
        let declared = source_spec(
            &dir,
            "alpha.spec",
            "Name: alpha\nVersion: 1\n%clean\nrm -rf %{buildroot}\n",
        );
        let header = source_spec(&dir, "w6-tmpfiles.spec", "Name: renamed\nVersion: 1\n");
        let results = run_source(vec![declared, header]);
        assert!(
            !has(&results, "superfluous-%clean-section"),
            "results: {results:?}"
        );
        let lines = lines_for(&results, "no-%prep-section");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(lines[0].contains("w6-tmpfiles.spec"), "line: {}", lines[0]);
    }

    #[test]
    fn check_source_unreadable_header_named_spec_falls_back_to_a_declared_one() {
        // The header-named payload file cannot be opened — it vanished
        // between the SRPM listing and the read — while a later
        // declaration-named file is readable: the spec checks run on
        // the readable declaration-named file.
        let missing_header = crate::pkg::pkgfile::PkgFile {
            name: "w6-tmpfiles.spec".to_string(),
            path: "/nonexistent/w6-tmpfiles.spec".to_string(),
            ..Default::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let declared = source_spec(
            &dir,
            "alpha.spec",
            "Name: alpha\nVersion: 1\n%clean\nrm -rf %{buildroot}\n",
        );
        let results = run_source(vec![missing_header, declared]);
        assert!(!has(&results, "invalid-spec-name"), "results: {results:?}");
        let lines = lines_for(&results, "superfluous-%clean-section");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(lines[0].contains("alpha.spec"), "line: {}", lines[0]);
    }

    #[test]
    fn check_source_fallback_uses_the_last_readable_spec() {
        // No payload spec is consistent and the last one cannot be
        // opened: the spec checks run on the last readable file.
        let dir = tempfile::tempdir().unwrap();
        let readable = source_spec(
            &dir,
            "one.spec",
            "Name: uno\nVersion: 1\n%clean\nrm -rf %{buildroot}\n",
        );
        let missing_last = crate::pkg::pkgfile::PkgFile {
            name: "dos.spec".to_string(),
            path: "/nonexistent/dos.spec".to_string(),
            ..Default::default()
        };
        let results = run_source(vec![readable, missing_last]);
        assert_eq!(
            lines_for(&results, "invalid-spec-name").len(),
            1,
            "results: {results:?}"
        );
        let lines = lines_for(&results, "superfluous-%clean-section");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(lines[0].contains("one.spec"), "line: {}", lines[0]);
    }

    #[test]
    fn check_source_runs_spec_checks_on_the_last_spec_when_none_is_consistent() {
        // No payload spec matches the header name or its own
        // declarations: the finding fires and the spec checks run
        // on the last file.
        let dir = tempfile::tempdir().unwrap();
        let first = source_spec(&dir, "one.spec", "Name: uno\nVersion: 1\n");
        let last = source_spec(
            &dir,
            "dos.spec",
            "Name: deux\nVersion: 1\n%clean\nrm -rf %{buildroot}\n",
        );
        let results = run_source(vec![first, last]);
        assert_eq!(
            lines_for(&results, "invalid-spec-name").len(),
            1,
            "results: {results:?}"
        );
        let lines = lines_for(&results, "superfluous-%clean-section");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(lines[0].contains("dos.spec"), "line: {}", lines[0]);
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
    fn deprecated_grep_quiet_on_name_fragments() {
        // The findutils `-regextype` dialect names select a regex dialect
        // for `find`; no grep command runs.
        let results =
            run_mini("Name: foo\n%install\nfind . -regextype posix-egrep -regex '.*\\.c'\n");
        assert!(!has(&results, "deprecated-grep"), "results: {results:?}");
        let results =
            run_mini("Name: foo\n%install\nfind . -regextype posix-fgrep -regex '.*\\.h'\n");
        assert!(!has(&results, "deprecated-grep"), "results: {results:?}");
        // A dotted data file name.
        let results =
            run_mini("Name: foo\n%install\ninstall -m 644 foo.egrep %{buildroot}/usr/share/foo/\n");
        assert!(!has(&results, "deprecated-grep"), "results: {results:?}");
        // A hyphenated helper script name invoked as a command is a
        // different binary, not the deprecated egrep.
        let results = run_mini("Name: foo\n%build\nmy-egrep-helper --check\n");
        assert!(!has(&results, "deprecated-grep"), "results: {results:?}");
        // The suffix rule holds at command position too: a longer name
        // that merely starts with egrep is a different binary or file.
        let results = run_mini("Name: foo\n%build\negrep-helper --check\n");
        assert!(!has(&results, "deprecated-grep"), "results: {results:?}");
        let results = run_mini("Name: foo\n%build\negrep.foo --check\n");
        assert!(!has(&results, "deprecated-grep"), "results: {results:?}");
        let results =
            run_mini("Name: foo\n%install\ninstall -m 644 x %{buildroot}/usr/share/egrep.foo\n");
        assert!(!has(&results, "deprecated-grep"), "results: {results:?}");
        // An assignment value names the command but does not run it.
        let results = run_mini("Name: foo\n%build\nGREPPER=egrep\n");
        assert!(!has(&results, "deprecated-grep"), "results: {results:?}");
        let results = run_mini("Name: foo\n%build\n./configure --with-grep=fgrep\n");
        assert!(!has(&results, "deprecated-grep"), "results: {results:?}");
    }

    #[test]
    fn deprecated_grep_fires_on_command_invocations() {
        // Path invocation.
        let results = run_mini("Name: foo\n%build\n/usr/bin/egrep foo\n");
        let lines = lines_for(&results, "deprecated-grep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: deprecated-grep ['egrep']"),
            "line: {}",
            lines[0]
        );
        // Command substitution.
        let results = run_mini("Name: foo\n%build\ncount=$(egrep -c x file)\n");
        let lines = lines_for(&results, "deprecated-grep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: deprecated-grep ['egrep']"),
            "line: {}",
            lines[0]
        );
        // Pipeline.
        let results = run_mini("Name: foo\n%build\ncat file | fgrep bar\n");
        let lines = lines_for(&results, "deprecated-grep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: deprecated-grep ['fgrep']"),
            "line: {}",
            lines[0]
        );
        // Backtick substitution.
        let results = run_mini("Name: foo\n%build\ncount=`egrep -c x file`\n");
        let lines = lines_for(&results, "deprecated-grep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: deprecated-grep ['egrep']"),
            "line: {}",
            lines[0]
        );
        // Two invocations on one line render as one list detail.
        let results = run_mini("Name: foo\n%build\negrep a; fgrep b\n");
        let lines = lines_for(&results, "deprecated-grep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: deprecated-grep ['egrep', 'fgrep']"),
            "line: {}",
            lines[0]
        );
        // Spaceless pipeline and semicolon separators.
        let results = run_mini("Name: foo\n%build\ncat file|fgrep bar\n");
        let lines = lines_for(&results, "deprecated-grep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: deprecated-grep ['fgrep']"),
            "line: {}",
            lines[0]
        );
        let results = run_mini("Name: foo\n%build\negrep a;fgrep b\n");
        let lines = lines_for(&results, "deprecated-grep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: deprecated-grep ['egrep', 'fgrep']"),
            "line: {}",
            lines[0]
        );
        // Background separator, spaceless and spaced.
        let results = run_mini("Name: foo\n%build\ncat file&egrep bar\n");
        let lines = lines_for(&results, "deprecated-grep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: deprecated-grep ['egrep']"),
            "line: {}",
            lines[0]
        );
        let results = run_mini("Name: foo\n%build\ncat file & fgrep bar\n");
        let lines = lines_for(&results, "deprecated-grep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: deprecated-grep ['fgrep']"),
            "line: {}",
            lines[0]
        );
        // Quoted command names still invoke the command.
        let results = run_mini("Name: foo\n%build\n'egrep' foo\n");
        let lines = lines_for(&results, "deprecated-grep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: deprecated-grep ['egrep']"),
            "line: {}",
            lines[0]
        );
        let results = run_mini("Name: foo\n%build\n\"fgrep\" bar\n");
        let lines = lines_for(&results, "deprecated-grep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: deprecated-grep ['fgrep']"),
            "line: {}",
            lines[0]
        );
        // The backslash-escaped name is the shell alias-bypass idiom: it
        // runs the command, and the pre-gate pattern matched it.
        let results = run_mini("Name: foo\n%build\n\\egrep foo\n");
        let lines = lines_for(&results, "deprecated-grep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: deprecated-grep ['egrep']"),
            "line: {}",
            lines[0]
        );
        // An assignment prefix does not mask a later command word.
        let results = run_mini("Name: foo\n%build\nFOO=bar egrep foo\n");
        let lines = lines_for(&results, "deprecated-grep");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: deprecated-grep ['egrep']"),
            "line: {}",
            lines[0]
        );
    }

    #[test]
    fn obsolete_tmpfiles_macro_fires_in_post() {
        let results = run_mini("Name: foo\n%post\n%tmpfiles_create_package\n");
        let lines = lines_for(&results, "obsolete-tmpfiles-macro");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("I: obsolete-tmpfiles-macro %tmpfiles_create_package"),
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
            lines[0].contains("I: obsolete-tmpfiles-macro %tmpfiles_create"),
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
            lines[0].contains("I: obsolete-tmpfiles-macro %{tmpfiles_create_package}"),
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

    /// #1171: the `_multibuild` flavour shape -- `BuildArch: noarch`
    /// sits in the `%else` branch of the flavour condition while the
    /// `%files` lines sit in the `%if` branch, so no build puts
    /// `%{_libdir}` into a noarch package.
    #[test]
    fn libdir_macro_silent_for_multibuild_opposite_branches_1171() {
        let spec = "Name: foo\n%global flavor @BUILD_FLAVOR@%{nil}\n%if \"%{flavor}\" == \"firefox\"\n%else\nBuildArch: noarch\n%endif\n%if \"%{flavor}\" == \"firefox\"\n%files\n%dir %{_libdir}/firefox\n%files -n %{base_name}-firefox-defaults\n%{_libdir}/firefox/browser/defaults/preferences/foo.js\n%endif\n";
        let results = run_mini(spec);
        let lines = lines_for(&results, "libdir-macro-in-noarch-package");
        assert_eq!(lines.len(), 0, "results: {results:?}");
    }

    /// #1171, the reported layout with the declaration under the
    /// subpackage's own key: the `BuildArch` line sits textually in
    /// the subpackage's region (after its `%package` header), in
    /// the %else branch, while the subpackage's %files lines are
    /// in the %if branch of the same condition.
    #[test]
    fn libdir_macro_silent_for_subpackage_own_key_opposite_branches_1171() {
        let spec = "Name: foo\n%package -n foo-sub\nSummary: x\n%if \"%{flavor}\" == \"firefox\"\n%files -n foo-sub\n%{_libdir}/foo\n%else\nBuildArch: noarch\n%endif\n";
        let results = run_mini(spec);
        let lines = lines_for(&results, "libdir-macro-in-noarch-package");
        assert_eq!(lines.len(), 0, "results: {results:?}");
    }

    /// #1171 near-miss: declaration and `%files` line in the SAME
    /// branch of the condition -- the noarch build really carries
    /// the libdir path.
    #[test]
    fn libdir_macro_fires_when_noarch_in_same_branch_1171() {
        let spec = "Name: foo\n%if \"%{flavor}\" == \"firefox\"\nBuildArch: noarch\n%files\n%{_libdir}/foo\n%endif\n";
        let results = run_mini(spec);
        let lines = lines_for(&results, "libdir-macro-in-noarch-package");
        assert_eq!(lines.len(), 1, "results: {results:?}");
    }

    /// #1171 near-miss: an unconditional `BuildArch: noarch` applies
    /// to `%files` lines under any conditional.
    #[test]
    fn libdir_macro_fires_when_noarch_unconditional_1171() {
        let spec = "Name: foo\nBuildArch: noarch\n%if \"%{flavor}\" == \"firefox\"\n%files\n%{_libdir}/foo\n%endif\n";
        let results = run_mini(spec);
        let lines = lines_for(&results, "libdir-macro-in-noarch-package");
        assert_eq!(lines.len(), 1, "results: {results:?}");
    }

    /// #1171 near-miss: opposite branches of DIFFERENT conditions
    /// can hold in the same build, so the finding stays.
    #[test]
    fn libdir_macro_fires_for_opposite_branches_of_other_condition_1171() {
        let spec = "Name: foo\n%if \"%{flavor}\" == \"firefox\"\n%else\nBuildArch: noarch\n%endif\n%ifarch x86_64\n%files\n%{_libdir}/foo\n%endif\n";
        let results = run_mini(spec);
        let lines = lines_for(&results, "libdir-macro-in-noarch-package");
        assert_eq!(lines.len(), 1, "results: {results:?}");
    }

    /// #1171: an `%elif` branch is exclusive with the `%if` branch of
    /// the same construct, so a declaration there does not reach a
    /// `%files` line in the `%if` branch.
    #[test]
    fn libdir_macro_silent_for_elif_branch_1171() {
        let spec = "Name: foo\n%if \"%{flavor}\" == \"firefox\"\nBuildArch: noarch\n%elif \"%{flavor}\" == \"seamonkey\"\n%files\n%{_libdir}/foo\n%endif\n";
        let results = run_mini(spec);
        let lines = lines_for(&results, "libdir-macro-in-noarch-package");
        assert_eq!(lines.len(), 0, "results: {results:?}");
    }

    /// #1171: `%ifarch` conditions compare the same way -- the
    /// declaration in the `%else` branch does not reach the `%files`
    /// line in the `%ifarch` branch.
    #[test]
    fn libdir_macro_silent_for_ifarch_opposite_branches_1171() {
        let spec = "Name: foo\n%ifarch x86_64\n%else\nBuildArch: noarch\n%endif\n%ifarch x86_64\n%files\n%{_libdir}/foo\n%endif\n";
        let results = run_mini(spec);
        let lines = lines_for(&results, "libdir-macro-in-noarch-package");
        assert_eq!(lines.len(), 0, "results: {results:?}");
    }

    /// #1171 near-miss: a subpackage whose own conditional
    /// declaration cannot apply still inherits the main package's
    /// unconditional `BuildArch: noarch`.
    #[test]
    fn libdir_macro_fires_for_subpackage_inheriting_main_noarch_1171() {
        let spec = "Name: foo\nBuildArch: noarch\n%package sub\nSummary: sub\n%if \"%{flavor}\" == \"firefox\"\n%else\nBuildArch: noarch\n%endif\n%description sub\nsub.\n%if \"%{flavor}\" == \"firefox\"\n%files sub\n%{_libdir}/foo\n%endif\n";
        let results = run_mini(spec);
        let lines = lines_for(&results, "libdir-macro-in-noarch-package");
        assert_eq!(lines.len(), 1, "results: {results:?}");
    }

    /// Negative pin for the removed `mixed-use-of-spaces-and-tabs`
    /// finding: the conventional layout (tab after the colon, spaces
    /// aligning the value) stays silent.
    #[test]
    fn killed_mixed_use_of_spaces_and_tabs_stays_absent() {
        let results = run_mini("Name:\tfoo\nVersion:        1.0\n");
        assert!(
            !has(&results, "mixed-use-of-spaces-and-tabs"),
            "must stay silent: {results:?}"
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
        for (check, level) in [
            ("no-%prep-section", "W"),
            ("no-%build-section", "W"),
            ("no-%install-section", "W"),
            ("no-%check-section", "I"),
        ] {
            let lines = lines_for(&results, check);
            assert_eq!(lines.len(), 1, "missing {check}: {results:?}");
            assert!(
                lines[0].contains(&format!("{level}: {check}")),
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

    /// Negative pin for the deliberately removed Mandriva-policy finding
    /// (`lib-package-without-%mklibname`, issue #531): the input is the
    /// shape that fired pre-removal -- a spec defining a lib subpackage
    /// with no `%mklibname` anywhere -- so re-adding the emission fails
    /// here under plain `cargo test`.
    #[test]
    fn killed_mklibname_finding_stays_absent() {
        let results = run_mini("Name: foo\n%package -n libfoo\n%description\nfoo\n");
        assert!(
            !has(&results, "lib-package-without-%mklibname"),
            "results: {results:?}"
        );
    }

    #[test]
    fn package_dep_lines_with_control_char_fire_per_tag() {
        // Kills the neutered `checkline_package_provides/obsoletes/conflicts`
        // mutants: each delegation must reach `checkline_dep_list` with its
        // tag (the detail carries it; the standalone controlchar probe below
        // emits the same slug with empty details).
        let pkg = SpecPkg {
            name: "test.spec".to_string(),
            lines: Vec::new(),
            current_linenum: std::cell::Cell::new(None),
            utf8: true,
        };
        let config = config_mini();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = SpecCheck::new(&config);
        check.checkline_package_provides(&pkg, &mut out, "Provides: foo\x07");
        check.checkline_package_obsoletes(&pkg, &mut out, "Obsoletes: bar\x07");
        check.checkline_package_conflicts(&pkg, &mut out, "Conflicts: baz\x07");
        let results = out.results().to_vec();
        let hits = lines_for(&results, "forbidden-controlchar-found");
        assert_eq!(hits.len(), 3, "results: {results:?}");
        for line in &hits {
            assert!(
                line.contains(": E: forbidden-controlchar-found"),
                "line: {line}"
            );
        }
        for tag in ["Provides:", "Obsoletes:", "Conflicts:"] {
            assert!(
                hits.iter().any(|l| l.contains(tag)),
                "no {tag} detail in: {hits:?}"
            );
        }
    }

    #[test]
    fn forbidden_controlchar_line_fires() {
        // Kills the neutered-`checkline_forbidden_controlchars` mutant: the
        // whole-line probe is a separate path from the dep-list one above.
        let pkg = SpecPkg {
            name: "test.spec".to_string(),
            lines: Vec::new(),
            current_linenum: std::cell::Cell::new(None),
            utf8: true,
        };
        let config = config_mini();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = SpecCheck::new(&config);
        check.checkline_forbidden_controlchars(&pkg, &mut out, "Name: foo\x07");
        let results = out.results().to_vec();
        let hits = lines_for(&results, "forbidden-controlchar-found");
        assert_eq!(hits.len(), 1, "results: {results:?}");
        // The line ending at the check name pins both the Warning level
        // and the empty detail (a detail would be appended after it).
        assert!(
            hits[0].ends_with(": W: forbidden-controlchar-found"),
            "line: {}",
            hits[0]
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
    fn license_file_as_doc_fires_on_doc_license_821() {
        let results = run_mini("Name: foo\n%files\n%doc COPYING\n");
        let lines = lines_for(&results, "license-file-as-doc");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: license-file-as-doc"),
            "line: {}",
            lines[0]
        );
        assert!(lines[0].contains("COPYING"), "line: {}", lines[0]);
        // A licence token under %doc is presence: the E stays silent.
        assert!(
            !has(&results, "no-license-file-in-spec"),
            "results: {results:?}"
        );
    }

    #[test]
    fn license_file_as_doc_token_and_case_variants_821() {
        // A path token is reported whole.
        let path = run_mini("Name: foo\n%files\n%doc docs/LICENSE.txt\n");
        let lines = lines_for(&path, "license-file-as-doc");
        assert_eq!(lines.len(), 1, "results: {path:?}");
        assert!(lines[0].contains("docs/LICENSE.txt"), "line: {}", lines[0]);
        // One finding per section even with several licence tokens.
        let multi = run_mini("Name: foo\n%files\n%doc README COPYING NEWS\n");
        let lines = lines_for(&multi, "license-file-as-doc");
        assert_eq!(lines.len(), 1, "results: {multi:?}");
        assert!(lines[0].contains("COPYING"), "line: {}", lines[0]);
        // The token match is case-insensitive.
        let lower = run_mini("Name: foo\n%files\n%doc copying\n");
        assert!(has(&lower, "license-file-as-doc"), "results: {lower:?}");
    }

    #[test]
    fn license_file_as_doc_near_misses_821() {
        // A section already carrying %license is converted.
        let converted = run_mini("Name: foo\n%files\n%license LICENSE\n%doc COPYING\n");
        assert!(
            !has(&converted, "license-file-as-doc"),
            "results: {converted:?}"
        );
        // A qualified %doc line is outside the conversion shape, and
        // the licence token still counts as presence for the E.
        for line in [
            "%doc %attr(0644,root,root) COPYING",
            "%doc %lang(en) COPYING",
        ] {
            let results = run_mini(&format!(
                "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%files\n{line}\n"
            ));
            assert!(
                !has(&results, "license-file-as-doc"),
                "line {line}: {results:?}"
            );
            assert!(
                !has(&results, "no-license-file-in-spec"),
                "line {line}: {results:?}"
            );
        }
        // %docdir declares a directory; it ships no licence file.
        let docdir = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%files\n%docdir %{_docdir}/licenses\n%{_bindir}/foo\n",
        );
        assert!(!has(&docdir, "license-file-as-doc"), "results: {docdir:?}");
        assert!(
            has(&docdir, "no-license-file-in-spec"),
            "results: {docdir:?}"
        );
        // A licence-named directory is not a licence file.
        let dir = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%files\n%doc LICENSES/\n",
        );
        assert!(!has(&dir, "license-file-as-doc"), "results: {dir:?}");
        assert!(!has(&dir, "no-license-file-in-spec"), "results: {dir:?}");
        // A list-file section's marking is not textually visible.
        let list = run_mini("Name: foo\n%files -f files.list\n%doc COPYING\n");
        assert!(!has(&list, "license-file-as-doc"), "results: {list:?}");
    }

    #[test]
    fn license_file_as_doc_per_section_821() {
        // The converted root stays silent; the unconverted subpackage
        // section fires once.
        let results = run_mini(
            "Name: foo\n%files\n%license LICENSE\n%doc README\n%files bar\n%doc COPYING\n",
        );
        let lines = lines_for(&results, "license-file-as-doc");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(lines[0].contains("COPYING"), "line: {}", lines[0]);
        assert!(
            !has(&results, "no-license-file-in-spec"),
            "results: {results:?}"
        );
    }

    #[test]
    fn no_license_file_in_spec_fires_821() {
        let results = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%files\n%{_bindir}/foo\n",
        );
        let lines = lines_for(&results, "no-license-file-in-spec");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("E: no-license-file-in-spec"),
            "line: {}",
            lines[0]
        );
        // An empty sibling section does not rescue the spec.
        let sibling = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%files\n%{_bindir}/foo\n%files doc\n",
        );
        assert!(
            has(&sibling, "no-license-file-in-spec"),
            "results: {sibling:?}"
        );
    }

    #[test]
    fn no_license_file_in_spec_presence_821() {
        // A %license line in any section is presence.
        let sub = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%files\n%{_bindir}/foo\n%files bar\n%license LICENSE\n",
        );
        assert!(!has(&sub, "no-license-file-in-spec"), "results: {sub:?}");
        // A licence file shipped as a plain entry is presence.
        let plain = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%files\n%{_datadir}/foo/COPYING\n%{_bindir}/foo\n",
        );
        assert!(
            !has(&plain, "no-license-file-in-spec"),
            "results: {plain:?}"
        );
        assert!(!has(&plain, "license-file-as-doc"), "results: {plain:?}");
    }

    #[test]
    fn no_license_file_in_spec_undecidable_821() {
        // List-file sections hide their marking.
        let list = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%files -f files.list\n",
        );
        assert!(!has(&list, "no-license-file-in-spec"), "results: {list:?}");
        let mixed = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%files\n%{_bindir}/foo\n%files -f x.list extra\n",
        );
        assert!(
            !has(&mixed, "no-license-file-in-spec"),
            "results: {mixed:?}"
        );
        // Directory/glob-only content: the shipped set is not visible.
        let glob = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%files\n%dir %{_datadir}/foo\n%{_datadir}/foo/*\n",
        );
        assert!(!has(&glob, "no-license-file-in-spec"), "results: {glob:?}");
        // A bare macro generates entries the scan cannot see.
        let generator = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%files\n%{pyproject_files}\n%{_bindir}/foo\n",
        );
        assert!(
            !has(&generator, "no-license-file-in-spec"),
            "results: {generator:?}"
        );
        // Empty and absent %files sections stay silent.
        let empty = run_mini("Name: foo\n%files\n");
        assert!(
            !has(&empty, "no-license-file-in-spec"),
            "results: {empty:?}"
        );
        let absent = run_mini("Name: foo\n");
        assert!(
            !has(&absent, "no-license-file-in-spec"),
            "results: {absent:?}"
        );
    }

    #[test]
    fn no_license_file_in_spec_scoping_821() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let run = |body: &str| run_mini(&format!("{hdr}%files\n{body}"));
        // A build-metadata directory entry: the build system assembles
        // the installed tree, licence files included.
        let info = run("%{_bindir}/foo\n%{python_sitelib}/foo-%{version}.dist-info\n");
        assert!(!has(&info, "no-license-file-in-spec"), "results: {info:?}");
        // A public-domain dedication has no licence file to mark.
        let pd = run_mini(
            "Name: foo\nLicense:        SUSE-Public-Domain\nSource:         foo-1.0.tar.gz\n%files\n%{_bindir}/foo\n",
        );
        assert!(!has(&pd, "no-license-file-in-spec"), "results: {pd:?}");
        // No archive source: the package is assembled from local files.
        let local = run_mini("Name: foo\nLicense:        MIT\n%files\n%{_bindir}/foo\n");
        assert!(
            !has(&local, "no-license-file-in-spec"),
            "results: {local:?}"
        );
        // Documentation-only content.
        let docs = run("%doc README\n%{_docdir}/foo/notes.txt\n");
        assert!(!has(&docs, "no-license-file-in-spec"), "results: {docs:?}");
        // An extension-less entry outside the exec locations is a
        // directory name as often as a file name: not explicit.
        let dir_entry = run("%{_datadir}/foo\n");
        assert!(
            !has(&dir_entry, "no-license-file-in-spec"),
            "results: {dir_entry:?}"
        );
        // A licence glob on a %doc line ships the licence file among
        // its matches.
        let glob = run("%doc COPY* README*\n%{_bindir}/foo\n");
        assert!(!has(&glob, "no-license-file-in-spec"), "results: {glob:?}");
        assert!(!has(&glob, "license-file-as-doc"), "results: {glob:?}");
        // A gem source: the installer assembles the whole tree.
        let gem = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.gem\n%files\n%{_bindir}/foo\n",
        );
        assert!(!has(&gem, "no-license-file-in-spec"), "results: {gem:?}");
        // Licence names beyond the conversion predicate still count
        // as shipped: suffixed, abbreviated and brace-grouped names,
        // and the Debian copyright file. None of them is the
        // spec-cleaner conversion shape, so the W stays silent too.
        for body in [
            "%doc LICENSE_GPL\n%{_bindir}/foo\n",
            "%doc licence-LGPL.txt\n%{_bindir}/foo\n",
            "%doc debian/copyright\n%{_bindir}/foo\n",
            "%doc docs/{COPYING,README}\n%{_bindir}/foo\n",
            "%{_datadir}/foo/gpl-2.0.txt\n%{_bindir}/foo\n",
        ] {
            let results = run(body);
            assert!(
                !has(&results, "no-license-file-in-spec"),
                "body {body}: {results:?}"
            );
            assert!(
                !has(&results, "license-file-as-doc"),
                "body {body}: {results:?}"
            );
        }
    }

    #[test]
    fn no_license_file_defaultdocdir_is_doc_location_822() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let run = |body: &str| run_mini(&format!("{hdr}%files\n{body}"));
        // Documentation under the canonical doc macro alone is a
        // documentation-only package: the E stays silent.
        let docs = run("%{_defaultdocdir}/%{name}/manual.pdf\n");
        assert!(!has(&docs, "no-license-file-in-spec"), "results: {docs:?}");
        // A doc entry does not rescue a package that also ships a
        // binary with no licence file marked.
        let mixed = run("%{_defaultdocdir}/%{name}/manual.pdf\n%{_bindir}/foo\n");
        assert!(has(&mixed, "no-license-file-in-spec"), "results: {mixed:?}");
    }

    #[test]
    fn no_license_file_missingok_licence_line_822() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let run = |body: &str| run_mini(&format!("{hdr}%files\n{body}"));
        // A leading %missingok qualifier does not hide the licence
        // entry behind it.
        let marked = run("%missingok %{_datadir}/foo/COPYING\n%{_bindir}/foo\n");
        assert!(
            !has(&marked, "no-license-file-in-spec"),
            "results: {marked:?}"
        );
        // %missingok on a non-licence entry is not presence.
        let other = run("%missingok %{_sysconfdir}/foo.conf\n%{_bindir}/foo\n");
        assert!(has(&other, "no-license-file-in-spec"), "results: {other:?}");
    }

    #[test]
    fn no_license_file_license_tag_case_and_spdx_822() {
        let run = |license: &str| {
            run_mini(&format!(
                "Name: foo\n{license}\nSource:         foo-1.0.tar.gz\n%files\n%{{_bindir}}/foo\n"
            ))
        };
        // rpmspec accepts a lowercase tag; a public-domain-only value
        // still exempts, in either case.
        for tag in [
            "License:        SUSE-Public-Domain",
            "license:        SUSE-Public-Domain",
            "LICENSE:        (SUSE-Public-Domain)",
        ] {
            let results = run(tag);
            assert!(
                !has(&results, "no-license-file-in-spec"),
                "tag {tag}: {results:?}"
            );
        }
        // A public-domain identifier inside a larger SPDX expression
        // is not a dedication: the E fires.
        for tag in [
            "License:        MIT AND SUSE-Public-Domain",
            "license:        MIT AND SUSE-Public-Domain",
        ] {
            let results = run(tag);
            assert!(
                has(&results, "no-license-file-in-spec"),
                "tag {tag}: {results:?}"
            );
        }
        // An expression naming only public-domain identifiers, joined
        // by an SPDX operator, stays exempt.
        let both = run("License:        SUSE-Public-Domain AND Public-Domain");
        assert!(!has(&both, "no-license-file-in-spec"), "results: {both:?}");
    }

    #[test]
    fn no_license_file_license_ref_public_domain_825() {
        let run = |license: &str| {
            run_mini(&format!(
                "Name: foo\n{license}\nSource:         foo-1.0.tar.gz\n%files\n%{{_bindir}}/foo\n"
            ))
        };
        // A `LicenseRef-` identifier counts by the identifier it
        // references: a public-domain ref is a public-domain-only
        // tag, in either tag case and parenthesised.
        for tag in [
            "License:        LicenseRef-SUSE-Public-Domain",
            "License:        LicenseRef-Public-Domain",
            "license:        LicenseRef-SUSE-Public-Domain",
            "LICENSE:        (LicenseRef-SUSE-Public-Domain)",
        ] {
            let results = run(tag);
            assert!(
                !has(&results, "no-license-file-in-spec"),
                "tag {tag}: {results:?}"
            );
        }
        // A ref to a real licence is not a dedication, and a
        // public-domain ref inside a larger expression does not
        // make the expression one either: the E fires.
        for tag in [
            "License:        LicenseRef-Apache-2.0",
            "License:        LicenseRef-SUSE-Public-Domain AND MIT",
            "License:        MIT AND LicenseRef-SUSE-Public-Domain",
        ] {
            let results = run(tag);
            assert!(
                has(&results, "no-license-file-in-spec"),
                "tag {tag}: {results:?}"
            );
        }
    }

    #[test]
    fn no_license_file_unbraced_generator_macro_822() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let run = |body: &str| run_mini(&format!("{hdr}%files\n{body}"));
        // The unbraced generator form is as opaque to the text scan
        // as the braced form: the E stays silent.
        for body in [
            "%pyproject_files\n%{_bindir}/foo\n",
            "%{_bindir}/foo\n%pyproject_files\n",
        ] {
            let results = run(body);
            assert!(
                !has(&results, "no-license-file-in-spec"),
                "body {body}: {results:?}"
            );
        }
        // A directive word does not mark the section opaque.
        let directive = run("%docdir %{_defaultdocdir}/foo\n%{_bindir}/foo\n");
        assert!(
            has(&directive, "no-license-file-in-spec"),
            "results: {directive:?}"
        );
    }

    #[test]
    fn license_marking_joined_stem_presence_822() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let run = |body: &str| run_mini(&format!("{hdr}%files\n{body}"));
        // The conversion predicate fires the W on a prefix-joined
        // stem, so the same line establishes presence: the E stays
        // silent and the two findings never contradict.
        let doc = run("%doc FOOCOPYING\n%{_bindir}/foo\n");
        assert!(has(&doc, "license-file-as-doc"), "results: {doc:?}");
        assert!(!has(&doc, "no-license-file-in-spec"), "results: {doc:?}");
        // A plain entry with a prefix-joined stem is presence too.
        let plain = run("%{_datadir}/foo/FOOCOPYING\n%{_bindir}/foo\n");
        assert!(
            !has(&plain, "no-license-file-in-spec"),
            "results: {plain:?}"
        );
        assert!(!has(&plain, "license-file-as-doc"), "results: {plain:?}");
        // A stem buried in a longer word is neither shape: no W, and
        // the E fires.
        let buried = run("%doc LICENSES\n%{_bindir}/foo\n");
        assert!(!has(&buried, "license-file-as-doc"), "results: {buried:?}");
        assert!(
            has(&buried, "no-license-file-in-spec"),
            "results: {buried:?}"
        );
    }

    #[test]
    fn license_file_as_doc_detail_is_the_token_alone_823() {
        // The token match runs through the whitespace that ends
        // it; the reported detail is the token alone.
        let results = run_mini("Name: foo\n%files\n%doc README COPYING NEWS\n");
        let lines = lines_for(&results, "license-file-as-doc");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(lines[0].ends_with("COPYING"), "line: {}", lines[0]);
    }

    #[test]
    fn no_license_file_bare_license_line_marks_nothing_823() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let run = |body: &str| run_mini(&format!("{hdr}%files\n{body}"));
        // A bare `%license` line carries no entry token: it marks
        // no licence file, so the E fires.
        let bare = run("%license\n%{_bindir}/foo\n");
        assert!(has(&bare, "no-license-file-in-spec"), "results: {bare:?}");
        // ...and it does not convert a `%doc` licence line either.
        let doc = run("%license\n%doc COPYING\n%{_bindir}/foo\n");
        assert!(has(&doc, "license-file-as-doc"), "results: {doc:?}");
        // A `%license` line carrying a file is presence (control).
        let marked = run("%license LICENSE\n%{_bindir}/foo\n");
        assert!(
            !has(&marked, "no-license-file-in-spec"),
            "results: {marked:?}"
        );
    }

    #[test]
    fn no_license_file_dir_line_marks_all_tokens_directories_823() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let run = |body: &str| run_mini(&format!("{hdr}%files\n{body}"));
        // Every token on a `%dir` line is a directory: the second
        // directory's licence name is a directory name, not a
        // shipped licence file, so the E fires.
        let dirs = run("%dir %{_datadir}/foo %{_datadir}/COPYING\n%{_bindir}/foo\n");
        assert!(has(&dirs, "no-license-file-in-spec"), "results: {dirs:?}");
        // The flag is the line's: a licence file on the next entry
        // line is still presence.
        let after =
            run("%dir %{_datadir}/foo %{_datadir}/bar\n%{_datadir}/foo/COPYING\n%{_bindir}/foo\n");
        assert!(
            !has(&after, "no-license-file-in-spec"),
            "results: {after:?}"
        );
    }

    #[test]
    fn no_license_file_pure_macro_tokens_are_generators_823() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let run = |body: &str| run_mini(&format!("{hdr}%files\n{body}"));
        // Concatenated and nested braced macros are pure macro
        // text: the entries they generate are invisible to the
        // scan, so the section is undecidable and the E stays
        // silent.
        for body in [
            "%{foo}%{bar}\n%{_bindir}/foo\n",
            "%{expand:%{foo}}\n%{_bindir}/foo\n",
        ] {
            let results = run(body);
            assert!(
                !has(&results, "no-license-file-in-spec"),
                "body {body}: {results:?}"
            );
        }
        // A macro-composed path carries literal text and stays a
        // judged entry: the E fires.
        let path = run("%{_bindir}/%{name}\n");
        assert!(has(&path, "no-license-file-in-spec"), "results: {path:?}");
    }

    #[test]
    fn no_license_file_info_entry_shapes_823() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let run = |body: &str| run_mini(&format!("{hdr}%files\n{body}"));
        // A file under a build-metadata directory marks the
        // section: the build system assembled that tree. A glob
        // naming the metadata directory itself does too.
        for body in [
            "%{python3_sitelib}/foo-1.0.dist-info/METADATA\n%{_bindir}/foo\n",
            "%{python3_sitelib}/foo.egg-info/PKG-INFO\n%{_bindir}/foo\n",
            "%{python3_sitelib}/*.egg-info\n%{_bindir}/foo\n",
            "%{python3_sitelib}/foo-%{version}*-info\n%{_bindir}/foo\n",
        ] {
            let results = run(body);
            assert!(
                !has(&results, "no-license-file-in-spec"),
                "body {body}: {results:?}"
            );
        }
        // A plain `*-info` data name is not build metadata, and
        // neither is an `*info` glob: the E fires.
        for body in [
            "%{_datadir}/foo-info\n%{_bindir}/foo\n",
            "%{_datadir}/foo*info\n%{_bindir}/foo\n",
        ] {
            let results = run(body);
            assert!(
                has(&results, "no-license-file-in-spec"),
                "body {body}: {results:?}"
            );
        }
    }

    #[test]
    fn no_license_file_glob_prefix_boundary_823() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let run = |body: &str| run_mini(&format!("{hdr}%files\n{body}"));
        // A glob whose literal prefix runs the stem into a longer
        // word is the buried-stem shape, exactly like the plain
        // name: the E fires, and the W does not fire either.
        let buried = run("%doc COPYINGFOO*\n%{_bindir}/foo\n");
        assert!(
            has(&buried, "no-license-file-in-spec"),
            "results: {buried:?}"
        );
        assert!(!has(&buried, "license-file-as-doc"), "results: {buried:?}");
        // A stem prefix, or the stem closed by a boundary, still
        // counts: the glob ships the licence file among its
        // matches.
        for body in [
            "%doc LICEN*\n%{_bindir}/foo\n",
            "%doc LICENSE-*\n%{_bindir}/foo\n",
        ] {
            let results = run(body);
            assert!(
                !has(&results, "no-license-file-in-spec"),
                "body {body}: {results:?}"
            );
        }
    }

    #[test]
    fn no_license_file_copying_digit_suffix_825() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let run = |body: &str| run_mini(&format!("{hdr}%files\n{body}"));
        // `COPYING` closed by a digit run is the GNU licence file
        // with its version glued on (`COPYING3`): presence counts,
        // under %doc and as a plain entry. The digit run may close
        // on a non-alphanumeric boundary too (`COPYING3.LIB`, the
        // file GCC ships; `COPYING3.txt`). The name is beyond the
        // conversion predicate, so the W stays silent too.
        for body in [
            "%doc COPYING3\n%{_bindir}/foo\n",
            "%{_datadir}/foo/COPYING3\n%{_bindir}/foo\n",
            "%doc COPYING3.LIB\n%{_bindir}/foo\n",
            "%{_datadir}/foo/COPYING3.LIB\n%{_bindir}/foo\n",
            "%doc COPYING3.txt\n%{_bindir}/foo\n",
            "%{_datadir}/foo/COPYING3.txt\n%{_bindir}/foo\n",
        ] {
            let results = run(body);
            assert!(
                !has(&results, "no-license-file-in-spec"),
                "body {body}: {results:?}"
            );
            assert!(
                !has(&results, "license-file-as-doc"),
                "body {body}: {results:?}"
            );
        }
        // A stem running into letters — or digits followed by more
        // word — is a longer word, not the licence file: the E fires.
        for body in [
            "%doc COPYINGFOO\n%{_bindir}/foo\n",
            "%doc COPYING3X\n%{_bindir}/foo\n",
            "%doc COPYING3X.txt\n%{_bindir}/foo\n",
        ] {
            let results = run(body);
            assert!(
                has(&results, "no-license-file-in-spec"),
                "body {body}: {results:?}"
            );
        }
    }

    #[test]
    fn glob_prefix_copying_digit_suffix_840() {
        // The glob prefix tests mirror the plain name test's
        // `COPYING`+digits rule: a digit run closed by the end of the
        // prefix or a non-alphanumeric boundary carries the stem, and
        // a digit run running into a letter buries it, exactly as the
        // plain test accepts `COPYING3` and rejects `COPYING3X`.
        for name in ["COPYING3*", "COPYING30*", "COPYING3.LIB*", "COPYING3-*"] {
            assert!(glob_prefix_carries_licence(name), "{name}");
            assert!(!glob_prefix_buries_licence_stem(name), "{name}");
        }
        for name in ["COPYING3X*", "COPYING3X.txt*"] {
            assert!(!glob_prefix_carries_licence(name), "{name}");
            assert!(glob_prefix_buries_licence_stem(name), "{name}");
        }
    }

    #[test]
    fn no_license_file_doc_glob_copying_digit_letter_suffix_840() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let run = |body: &str| run_mini(&format!("{hdr}%files\n{body}"));
        // A `%doc` glob running `COPYING` into digits and then a
        // letter names only longer words (the buried-stem shape), so
        // the section stays decidable and the E fires, as it does for
        // the plain name `COPYING3X`.
        let buried = run("%doc COPYING3X*\n%{_bindir}/foo\n");
        assert!(
            has(&buried, "no-license-file-in-spec"),
            "results: {buried:?}"
        );
        // The digit-suffixed glob ships the licence file among its
        // matches: presence, and the E stays silent.
        let digit = run("%doc COPYING3*\n%{_bindir}/foo\n");
        assert!(
            !has(&digit, "no-license-file-in-spec"),
            "results: {digit:?}"
        );
    }

    #[test]
    fn archive_source_extension_boundary_840() {
        // Every archive extension goes through the boundary-aware
        // test: an extension running into a longer word names no
        // archive, so with no other source the package counts as
        // assembled from local files and the E stays silent.
        for source in ["foo-1.0.tarball", "foo-1.0.zippo", "foo-1.0.crates"] {
            let results = run_mini(&format!(
                "Name: foo\nLicense:        MIT\nSource:         {source}\n%files\n%{{_bindir}}/foo\n"
            ));
            assert!(
                !has(&results, "no-license-file-in-spec"),
                "source {source}: {results:?}"
            );
        }
        // The same extensions closed by a boundary or the end of the
        // value still name an archive (controls): the E fires.
        for source in ["foo-1.0.tar.gz", "foo-1.0.zip", "foo-1.0.crate"] {
            let results = run_mini(&format!(
                "Name: foo\nLicense:        MIT\nSource:         {source}\n%files\n%{{_bindir}}/foo\n"
            ));
            assert!(
                has(&results, "no-license-file-in-spec"),
                "source {source}: {results:?}"
            );
        }
    }

    #[test]
    fn license_scan_dir_flag_passes_generator_tokens_840() {
        // A mid-line `%dir` flag belongs to the next judged entry:
        // generator tokens of either spelling pass it through, so the
        // licence name after `%dir <generator>` is judged a directory
        // in both spellings and establishes no presence.
        let config = config_mini();
        let check = SpecCheck::new(&config);
        for generator in ["%{expand:%{foo}}", "%pyproject_files"] {
            let mut scan = FilesSectionScan::default();
            check.scan_license_entries(
                &mut scan,
                &["/x/foo", "%dir", generator, "/y/COPYING"],
                false,
                false,
            );
            assert!(scan.has_generator_macro, "generator {generator}");
            assert!(!scan.plain_license_entry, "generator {generator}");
        }
        // The flag still applies to the next judged entry (control),
        // and a licence entry with no flag is presence (control).
        let mut scan = FilesSectionScan::default();
        check.scan_license_entries(&mut scan, &["/x/foo", "%dir", "/y/COPYING"], false, false);
        assert!(!scan.plain_license_entry);
        let mut scan = FilesSectionScan::default();
        check.scan_license_entries(&mut scan, &["/y/COPYING"], false, false);
        assert!(scan.plain_license_entry);
    }

    #[test]
    fn no_license_file_gemspec_source_is_not_an_assembled_package_823() {
        // A `.gemspec` is a recipe text, not a gem: next to the
        // tarball it does not make the tree installer-assembled,
        // so the E fires.
        let gemspec = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\nSource1:        foo.gemspec\n%files\n%{_bindir}/foo\n",
        );
        assert!(
            has(&gemspec, "no-license-file-in-spec"),
            "results: {gemspec:?}"
        );
        // A `.gem` source still assembles the whole tree (control).
        let gem = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\nSource1:        foo-1.0.gem\n%files\n%{_bindir}/foo\n",
        );
        assert!(!has(&gem, "no-license-file-in-spec"), "results: {gem:?}");
    }

    #[test]
    fn no_license_file_wheel_suffix_shapes_823() {
        // A `.whl2` name is not a wheel: it is neither an assembled
        // package nor, on its own, an archive source, so with no
        // other source the E stays silent.
        let suffixed = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.whl2\n%files\n%{_bindir}/foo\n",
        );
        assert!(
            !has(&suffixed, "no-license-file-in-spec"),
            "results: {suffixed:?}"
        );
        // A real wheel source assembles the tree (control): the E
        // stays silent even though no licence file is marked.
        let wheel = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.whl\n%files\n%{_bindir}/foo\n",
        );
        assert!(
            !has(&wheel, "no-license-file-in-spec"),
            "results: {wheel:?}"
        );
        // A tarball beside the suffixed name is an archive source:
        // the E fires (control for the archive gate itself).
        let tarball = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\nSource1:        foo-1.0.whl2\n%files\n%{_bindir}/foo\n",
        );
        assert!(
            has(&tarball, "no-license-file-in-spec"),
            "results: {tarball:?}"
        );
    }

    #[test]
    fn no_license_file_tags_collect_in_preambles_only_823() {
        // A `License:` line inside %description is prose, not a
        // tag: the public-domain exemption does not apply.
        let desc = run_mini(
            "Name: foo\nSource:         foo-1.0.tar.gz\n%description\nLicense: SUSE-Public-Domain\n%files\n%{_bindir}/foo\n",
        );
        assert!(has(&desc, "no-license-file-in-spec"), "results: {desc:?}");
        // A `Source` line inside %changelog is an entry, not a
        // tag: it does not make the source an assembled package.
        let chlog = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%files\n%{_bindir}/foo\n%changelog\n* Tue Jan 01 2026 Foo <foo@example.com>\nSource: foo-1.0.gem\n",
        );
        assert!(has(&chlog, "no-license-file-in-spec"), "results: {chlog:?}");
        // A `Source` line inside %description does not create an
        // archive source either: without one the E stays silent.
        let desc_source = run_mini(
            "Name: foo\nLicense:        MIT\n%description\nSource: foo-1.0.tar.gz\n%files\n%{_bindir}/foo\n",
        );
        assert!(
            !has(&desc_source, "no-license-file-in-spec"),
            "results: {desc_source:?}"
        );
        // A subpackage preamble is a preamble: its `License:` tag
        // still collects (control).
        let sub = run_mini(
            "Name: foo\nSource:         foo-1.0.tar.gz\n%files\n%{_bindir}/foo\n%package doc\nLicense:        SUSE-Public-Domain\n%files doc\n%doc README\n",
        );
        assert!(!has(&sub, "no-license-file-in-spec"), "results: {sub:?}");
    }

    #[test]
    fn no_license_file_doc_directory_indeterminate_831() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let run = |body: &str| run_mini(&format!("{hdr}%files\n{body}"));
        // A bare-directory %doc argument ships whatever %install left
        // in it, licence file or not: the E stays silent (dbench).
        let dir = run("%{_bindir}/foo\n%doc %{_docdir}/foo\n");
        assert!(!has(&dir, "no-license-file-in-spec"), "results: {dir:?}");
        assert!(!has(&dir, "license-file-as-doc"), "results: {dir:?}");
        // The trailing-slash form names the same shape.
        let slash = run("%{_bindir}/foo\n%doc docs/\n");
        assert!(
            !has(&slash, "no-license-file-in-spec"),
            "results: {slash:?}"
        );
        // The E is spec-level: an indeterminate entry in a sibling
        // section silences it for the whole spec.
        let sibling = run_mini(&format!(
            "{hdr}%files\n%{{_bindir}}/foo\n%doc README.md\n%files doc\n%doc %{{_docdir}}/foo\n"
        ));
        assert!(
            !has(&sibling, "no-license-file-in-spec"),
            "results: {sibling:?}"
        );
        // Plain %doc files stay decidable: the E fires.
        let dotted = run("%{_bindir}/foo\n%doc README.md NEWS.txt\n");
        assert!(
            has(&dotted, "no-license-file-in-spec"),
            "results: {dotted:?}"
        );
        // A bare %doc name is a file the packager names individually;
        // its basename is the evidence, and it carries no stem.
        let bare = run("%{_bindir}/foo\n%doc README ChangeLog\n");
        assert!(has(&bare, "no-license-file-in-spec"), "results: {bare:?}");
        // An extension-less %doc path in an exec location names a
        // file, as elsewhere in the scan.
        let exec = run("%{_bindir}/foo\n%doc %{_bindir}/foodoc\n");
        assert!(has(&exec, "no-license-file-in-spec"), "results: {exec:?}");
    }

    #[test]
    fn no_license_file_doc_glob_indeterminate_832() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let run = |body: &str| run_mini(&format!("{hdr}%files\n{body}"));
        // A %doc glob constrains nothing about its matches: the E
        // stays silent (viruskiller).
        let glob = run("%{_bindir}/foo\n%doc doc/*\n");
        assert!(!has(&glob, "no-license-file-in-spec"), "results: {glob:?}");
        assert!(!has(&glob, "license-file-as-doc"), "results: {glob:?}");
        // A bare wildcard and a non-licence prefix are the same shape.
        for body in ["%{_bindir}/foo\n%doc *\n", "%{_bindir}/foo\n%doc README*\n"] {
            let results = run(body);
            assert!(
                !has(&results, "no-license-file-in-spec"),
                "body {body}: {results:?}"
            );
        }
        // The E is spec-level: a glob in a sibling section silences
        // it for the whole spec.
        let sibling = run_mini(&format!(
            "{hdr}%files\n%{{_bindir}}/foo\n%doc README.md\n%files doc\n%doc doc/*\n"
        ));
        assert!(
            !has(&sibling, "no-license-file-in-spec"),
            "results: {sibling:?}"
        );
        // A glob whose prefix reaches a licence stem is affirmative
        // presence, as before: silent through presence, not opacity.
        let stem = run("%{_bindir}/foo\n%doc LICENSE-*\n");
        assert!(!has(&stem, "no-license-file-in-spec"), "results: {stem:?}");
        // A glob on a plain entry is not this shape: the section
        // stays decidable on its explicit entries and the E fires.
        let plain = run("%{_datadir}/foo/*\n%{_bindir}/foo\n%doc README.md\n");
        assert!(has(&plain, "no-license-file-in-spec"), "results: {plain:?}");
    }

    #[test]
    fn no_license_file_install_copy_presence_833() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let files = "%files\n%{_bindir}/foo\n%{_docdir}/%{name}/\n";
        let run = |install: &str| run_mini(&format!("{hdr}%install\n{install}\n{files}"));
        // The gnulib shape: the licence files ride a multi-source
        // copy into the shipped docdir, beside non-licence sources,
        // one of them a licence glob.
        let gnulib = run(
            "cp -p doc/gnulib.html NEWS COPYING ChangeLog doc/COPYING* %{buildroot}%{_docdir}/%{name}/",
        );
        assert!(
            !has(&gnulib, "no-license-file-in-spec"),
            "results: {gnulib:?}"
        );
        // A value-taking flag's value is not an argument: the mode
        // is skipped and the destination is the final argument.
        let install = run("install -m 644 COPYING %{buildroot}%{_docdir}/%{name}");
        assert!(
            !has(&install, "no-license-file-in-spec"),
            "results: {install:?}"
        );
        // The macro spelling of the command, the canonical docdir
        // macro and a buildroot variable prefix.
        let macro_cmd = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%install\n%{__cp} COPYING $RPM_BUILD_ROOT%{_defaultdocdir}/%{name}/\n%files\n%{_bindir}/foo\n%{_defaultdocdir}/%{name}/\n",
        );
        assert!(
            !has(&macro_cmd, "no-license-file-in-spec"),
            "results: {macro_cmd:?}"
        );
        // A command after a `&&` separator is at command position.
        let chained = run(
            "mkdir -p %{buildroot}%{_docdir}/%{name} && cp COPYING %{buildroot}%{_docdir}/%{name}/",
        );
        assert!(
            !has(&chained, "no-license-file-in-spec"),
            "results: {chained:?}"
        );
        // The destination names the licence file itself; its parent
        // directory is the shipped entry that anchors the copy.
        let filed = run("cp COPYING %{buildroot}%{_docdir}/%{name}/COPYING");
        assert!(
            !has(&filed, "no-license-file-in-spec"),
            "results: {filed:?}"
        );
        // The `-t` value is the destination: the copy lands in the
        // target directory and every positional argument is a source.
        let target = run("install -t %{buildroot}%{_docdir}/%{name} COPYING");
        assert!(
            !has(&target, "no-license-file-in-spec"),
            "results: {target:?}"
        );
    }

    #[test]
    fn no_license_file_install_copy_near_misses_833() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let files = "%files\n%{_bindir}/foo\n%{_docdir}/%{name}/\n";
        let run = |install: &str| run_mini(&format!("{hdr}%install\n{install}\n{files}"));
        // A copy of non-licence files into the docdir.
        let readme = run("cp -p README NEWS %{buildroot}%{_docdir}/%{name}/");
        assert!(
            has(&readme, "no-license-file-in-spec"),
            "results: {readme:?}"
        );
        // A licence file copied somewhere other than the docdir.
        let datadir = run("cp COPYING %{buildroot}%{_datadir}/%{name}/");
        assert!(
            has(&datadir, "no-license-file-in-spec"),
            "results: {datadir:?}"
        );
        // The same, into a non-docdir directory the spec does ship:
        // only the destination test keeps the E firing here, the
        // anchor alone would accept the copy.
        let shipped_datadir = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%install\ncp COPYING %{buildroot}%{_datadir}/%{name}/\n%files\n%{_bindir}/foo\n%{_datadir}/%{name}/\n",
        );
        assert!(
            has(&shipped_datadir, "no-license-file-in-spec"),
            "results: {shipped_datadir:?}"
        );
        // The destination directory is shipped by no %files section.
        let unshipped = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%install\ncp COPYING %{buildroot}%{_docdir}/%{name}/\n%files\n%{_bindir}/foo\n",
        );
        assert!(
            has(&unshipped, "no-license-file-in-spec"),
            "results: {unshipped:?}"
        );
        // The same copy in %prep never reaches the shipped tree.
        let prep = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%prep\ncp COPYING %{buildroot}%{_docdir}/%{name}/\n%files\n%{_bindir}/foo\n%{_docdir}/%{name}/\n",
        );
        assert!(has(&prep, "no-license-file-in-spec"), "results: {prep:?}");
        // Other tools and obscured command positions do not count.
        for line in [
            "rsync -a COPYING %{buildroot}%{_docdir}/%{name}/",
            "mv COPYING %{buildroot}%{_docdir}/%{name}/",
            "INSTALLED=$(cp COPYING %{buildroot}%{_docdir}/%{name}/)",
            "$CP COPYING %{buildroot}%{_docdir}/%{name}/",
        ] {
            let results = run(line);
            assert!(
                has(&results, "no-license-file-in-spec"),
                "line {line}: {results:?}"
            );
        }
        // `install -d` creates a directory; it copies no file, even
        // when a directory argument carries a licence stem.
        let mkdir = run("install -d COPYING %{buildroot}%{_docdir}/%{name}/");
        assert!(has(&mkdir, "no-license-file-in-spec"), "results: {mkdir:?}");
        // A flag value carrying a licence stem is the flag's value,
        // not a source.
        let flag_value = run("install -m COPYING README %{buildroot}%{_docdir}/%{name}/");
        assert!(
            has(&flag_value, "no-license-file-in-spec"),
            "results: {flag_value:?}"
        );
    }

    #[test]
    fn no_license_file_install_copy_hardening_873() {
        let hdr = "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n";
        let files = "%files\n%{_bindir}/foo\n%{_docdir}/%{name}/\n";
        let run = |install: &str| run_mini(&format!("{hdr}%install\n{install}\n{files}"));
        for line in [
            // Every qualifying copy on the line is recorded: the
            // shipped second destination anchors even though the
            // first copy names an unshipped docdir.
            "cp COPYING %{buildroot}%{_docdir}/other/; cp COPYING %{buildroot}%{_docdir}/%{name}/",
            // A command after a pipe is at command position.
            "echo done | cp COPYING %{buildroot}%{_docdir}/%{name}/",
            // A redirection and its target are not arguments.
            "cp COPYING %{buildroot}%{_docdir}/%{name}/ > /dev/null 2>&1",
            // Quoted tokens name the same paths.
            "cp \"COPYING\" \"%{buildroot}%{_docdir}/%{name}/\"",
            // An environment assignment precedes the command.
            "LC_ALL=C install -m 644 COPYING %{buildroot}%{_docdir}/%{name}",
            // An absolute tool path qualifies by its basename.
            "/usr/bin/install -m 644 COPYING %{buildroot}%{_docdir}/%{name}",
            // The unbraced buildroot spelling.
            "cp COPYING %buildroot%{_docdir}/%{name}/",
            // The glued target-directory form names the destination.
            "install --target-directory=%{buildroot}%{_docdir}/%{name} COPYING",
            // A bundled flag's value is the following token: `644`
            // is the mode, `COPYING` a source.
            "install -pm 644 COPYING %{buildroot}%{_docdir}/%{name}",
            // A `#` glued to a word is no comment: the line after a
            // `${var#pattern}` expansion still counts in full.
            "D=${DOCROOT#prefix} cp COPYING %{buildroot}%{_docdir}/%{name}/",
            // A `-d` operand after `--` is a file operand, not the
            // directory-creation flag.
            "install -- -d COPYING %{buildroot}%{_docdir}/%{name}",
        ] {
            let results = run(line);
            assert!(
                !has(&results, "no-license-file-in-spec"),
                "line {line}: {results:?}"
            );
        }
        // A backslash continuation joins the command's lines.
        let joined = run("install -m 644 COPYING \\\n        %{buildroot}%{_docdir}/%{name}");
        assert!(
            !has(&joined, "no-license-file-in-spec"),
            "results: {joined:?}"
        );
        // The anchor walks every ancestor of the destination.
        let deep = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%install\ncp COPYING %{buildroot}%{_docdir}/%{name}/deep/\n%files\n%{_bindir}/foo\n%{_docdir}/\n",
        );
        assert!(!has(&deep, "no-license-file-in-spec"), "results: {deep:?}");
        // The literal docdir path names the docdir too.
        let literal = run_mini(
            "Name: foo\nLicense:        MIT\nSource:         foo-1.0.tar.gz\n%install\ncp COPYING %{buildroot}/usr/share/doc/%{name}/\n%files\n%{_bindir}/foo\n/usr/share/doc/%{name}/\n",
        );
        assert!(
            !has(&literal, "no-license-file-in-spec"),
            "results: {literal:?}"
        );
        for line in [
            // A destination without the buildroot names the build
            // host's docdir, not the packaged copy.
            "cp COPYING %{_docdir}/%{name}/",
            // A bundled flag ending the bundle takes the next token
            // as its value: `COPYING` here is the mode, no source
            // remains.
            "install -pm COPYING %{buildroot}%{_docdir}/%{name}",
        ] {
            let results = run(line);
            assert!(
                has(&results, "no-license-file-in-spec"),
                "line {line}: {results:?}"
            );
        }
        // The destination named only by lines that ship nothing does
        // not anchor the copy.
        for files_section in [
            // A `%dir` entry ships the directory alone, not the
            // files copied into it.
            "%files\n%{_bindir}/foo\n%dir %{_docdir}/%{name}\n",
            // A trailing comment names nothing shipped.
            "%files\n%{_bindir}/foo # %{_docdir}/%{name}\n",
            // `%docdir` declares the directory; it ships nothing.
            "%files\n%{_bindir}/foo\n%docdir %{_docdir}/%{name}\n",
            // `%defattr` sets attributes for the entries that
            // follow; its own tokens ship nothing.
            "%files\n%{_bindir}/foo\n%defattr(-,root,root,-) %{_docdir}/%{name}\n",
            // A conditional guards entries; its own tokens ship
            // nothing.
            "%files\n%{_bindir}/foo\n%if %{_docdir}/%{name}\n%endif\n",
        ] {
            let results = run_mini(&format!(
                "{hdr}%install\ncp COPYING %{{buildroot}}%{{_docdir}}/%{{name}}/\n{files_section}"
            ));
            assert!(
                has(&results, "no-license-file-in-spec"),
                "files {files_section}: {results:?}"
            );
        }
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

    /// Negative pin for the removed `use-of-RPM_SOURCE_DIR` finding:
    /// both the variable and the macro form stay silent.
    #[test]
    fn killed_use_of_rpm_source_dir_stays_absent() {
        let results = run_mini("Name: foo\n%build\necho $RPM_SOURCE_DIR\n");
        assert!(
            !has(&results, "use-of-RPM_SOURCE_DIR"),
            "must stay silent: {results:?}"
        );
        let macro_form = run_mini("Name: foo\n%build\necho %{_sourcedir}\n");
        assert!(
            !has(&macro_form, "use-of-RPM_SOURCE_DIR"),
            "must stay silent: {macro_form:?}"
        );
    }

    /// Negative pin for the removed `hardcoded-library-path` finding:
    /// a literal library path stays silent.
    #[test]
    fn killed_hardcoded_library_path_stays_absent() {
        let results = run_mini("Name: foo\n%description\n/usr/lib\n");
        assert!(
            !has(&results, "hardcoded-library-path"),
            "must stay silent: {results:?}"
        );
        // The configure-options form is the same removed finding.
        let configure_form = run_mini("Name: foo\n%build\n./configure --libdir=/usr/lib\n");
        assert!(
            !has(&configure_form, "hardcoded-library-path"),
            "must stay silent: {configure_form:?}"
        );
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
    fn prereq_use_fires_warning_parenthesised_ref529() {
        let results = run_mini("Name: foo\nPreReq(pre): none\nPreReq(post): none_other\n");
        let lines = lines_for(&results, "prereq-use");
        assert_eq!(lines.len(), 2, "results: {results:?}");
        assert!(
            lines[0].contains("W: prereq-use none"),
            "line: {}",
            lines[0]
        );
        assert!(
            lines[1].contains("W: prereq-use none_other"),
            "line: {}",
            lines[1]
        );
    }

    #[test]
    fn prereq_use_fires_on_plain_tag_form() {
        // The plain `PreReq:` tag is the form the Factory tree carries
        // (253 lines in 153 specs at measurement); the parenthesised
        // qualifier is optional in the predicate.
        let results = run_mini("Name: foo\nPreReq: sed\n");
        let lines = lines_for(&results, "prereq-use");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(lines[0].contains("W: prereq-use sed"), "line: {}", lines[0]);
    }

    #[test]
    fn prereq_use_silent_on_modern_requires_qualifiers() {
        let results = run_mini("Name: foo\nRequires(pre): none\nRequires(post): none_other\n");
        assert!(!has(&results, "prereq-use"), "unexpected: {results:?}");
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
    fn rpm_buildroot_usage_install_assignment_idiom_is_quiet() {
        // In %build and %prep the buildroot is the install destination:
        // a reference that leads the value of an assignment (a `name=`
        // pair or a configure-style `--name` option, `=` or space form)
        // hands it to the build system as a path parameter.
        for spec in [
            "Name: foo\n%build\nmake DESTDIR=%{buildroot}\n",
            "Name: foo\n%build\nmake DESTDIR=$RPM_BUILD_ROOT\n",
            "Name: foo\n%build\n./configure --prefix=%{buildroot}%{_prefix}\n",
            "Name: foo\n%build\n./configure --temproot=%{buildroot}\n",
            "Name: foo\n%build\nperl Build.PL destdir=%{buildroot} installdirs=vendor\n",
            "Name: foo\n%build\nperl Build.PL --prefix $RPM_BUILD_ROOT/usr --installdirs vendor\n",
            "Name: foo\n%build\n%global _make_args DESTDIR=%{buildroot} DOC_INSTALL_DIR=%{buildroot}/%{_docdir}\n",
            "Name: foo\n%prep\n%define env export DESTDIR=%{buildroot}\n",
        ] {
            let results = run_mini(spec);
            assert!(
                !has(&results, "rpm-buildroot-usage"),
                "spec {spec:?}: {results:?}"
            );
        }
    }

    #[test]
    fn rpm_buildroot_usage_non_assignment_forms_still_fire() {
        // The assignment form in a scriptlet, and %build/%prep
        // references that lead no assignment value, keep the finding:
        // a command's path or plain argument, a define a compiler flag
        // carries, a value the reference does not lead, and a credited
        // reference sharing its line with an uncredited one.
        for spec in [
            "Name: foo\n%post\nmake DESTDIR=%{buildroot}\n",
            "Name: foo\n%build\necho %{buildroot}\n",
            "Name: foo\n%build\nmkdir -p %{buildroot}%{_datadir}\n",
            "Name: foo\n%build\n%{buildroot}%{_bindir}/fipshmac %{buildroot}%{_bindir}/fipscheck\n",
            "Name: foo\n%build\nexport CFLAGS=\"%optflags -DCMAKE_INSTALL_DATADIR=%{buildroot}/usr/lib64/pkgconfig/\"\n",
            "Name: foo\n%build\nPATH=\"$PATH:%buildroot/%{_bindir}\" make\n",
            "Name: foo\n%build\nmake DESTDIR=%{buildroot} && rm -rf %{buildroot}\n",
        ] {
            let results = run_mini(spec);
            let lines = lines_for(&results, "rpm-buildroot-usage");
            assert_eq!(lines.len(), 1, "spec {spec:?}: {results:?}");
        }
    }

    #[test]
    fn rpm_buildroot_usage_install_section_is_quiet() {
        // %install sits outside the finding's sections and stays quiet
        // in every form.
        let results = run_mini("Name: foo\n%install\ninstall -m 644 x %{buildroot}%{_datadir}/\n");
        assert!(
            !has(&results, "rpm-buildroot-usage"),
            "results: {results:?}"
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

    #[test]
    fn removed_conditional_source_or_patch_stays_quiet() {
        // Both fixtures used to warn conditional-source-or-patch (#352).
        let results = run_mini("Name: foo\n%if 0%{?suse_version}\nSource0: a.tar.gz\n%endif\n");
        assert!(
            !has(&results, "conditional-source-or-patch"),
            "results: {results:?}"
        );
        let results = run_mini("Name: foo\n%ifarch x86_64\nPatch1: b.patch\n%endif\n");
        assert!(
            !has(&results, "conditional-source-or-patch"),
            "results: {results:?}"
        );
    }

    #[test]
    fn reset_clears_applied_patches_between_specs() {
        // Worker resets between specs; A's applied patch must not silence
        // B's patch-not-applied. Without the reset B stays quiet via A's
        // applied patch 0.
        let config = config_mini();
        let dir = tempfile::tempdir().unwrap();
        let a_path = dir.path().join("a.spec");
        std::fs::write(
            &a_path,
            "Name: foo\nPatch0: foo.patch\n%prep\n%patch -P 0\n%build\n",
        )
        .unwrap();
        let b_path = dir.path().join("b.spec");
        std::fs::write(&b_path, "Name: foo\nPatch0: foo.patch\n%prep\n%build\n").unwrap();
        let a = SpecPkg::open(&a_path).unwrap();
        let b = SpecPkg::open(&b_path).unwrap();
        let mut check = SpecCheck::new(&config);
        let mut out_a = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_spec(&a, &config, &mut out_a);
        check.reset();
        let mut out_b = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_spec(&b, &config, &mut out_b);
        let results = out_b.results().to_vec();
        let lines = lines_for(&results, "patch-not-applied");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("W: patch-not-applied Patch0:"),
            "line: {}",
            lines[0]
        );
    }
    // ---- #1019: a %check that cannot fail ----

    #[test]
    fn exit_status_masked_or_fallbacks_fire() {
        // PDAL r17-r18 / shapelib r6 / redis r18 shapes.
        for body in [
            "make check || :",
            "make check ||:",
            "make check || true",
            "%{__make} check || :",
            "ninja test || :",
            "pytest || :",
            "%meson_test || :",
            "cargo test || :",
            "go test ./... || :",
            "prove -r t || :",
            "ctest || :",
        ] {
            let text = format!("Name: foo\n%check\n{body}\n");
            let results = run_mini(&text);
            assert!(
                has(&results, "check-exit-status-masked"),
                "no fire for {body:?}: {results:?}"
            );
        }
    }

    #[test]
    fn exit_status_failing_or_deferring_fallbacks_stay_quiet() {
        for body in [
            "make check || { cat test/test-suite.log; exit 1; }",
            "make check || exit 1",
            "make check || exit",
            "make check || false",
            "make check || make check -j1",
            "ulimit -c unlimited || :",
        ] {
            let text = format!("Name: foo\n%check\n{body}\n");
            let results = run_mini(&text);
            assert!(
                !has(&results, "check-exit-status-masked"),
                "unexpected fire for {body:?}: {results:?}"
            );
        }
        // python-PyMySQL: the fallback records the status in a
        // variable the section exits with afterwards.
        let results = run_mini("Name: foo\n%check\nmake check || exit_code=1\nexit $exit_code\n");
        assert!(
            !has(&results, "check-exit-status-masked"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn exit_status_masked_and_arm() {
        // libsmi: the fallback prints the log and exits 0.
        let results =
            run_mini("Name: foo\n%check\nmake check || cat test/test-suite.log && exit 0\n");
        assert!(
            has(&results, "check-exit-status-masked"),
            "missing: {results:?}"
        );
        // `cmd && exit 0` as the section's last command still fails
        // the build when cmd fails.
        let results = run_mini("Name: foo\n%check\nmake check && exit 0\n");
        assert!(
            !has(&results, "check-exit-status-masked"),
            "unexpected: {results:?}"
        );
        // ... but not when more commands follow.
        let results = run_mini("Name: foo\n%check\nmake check && exit 0\necho done\n");
        assert!(
            has(&results, "check-exit-status-masked"),
            "missing: {results:?}"
        );
        // A %ctest line is never the last command (the macro appends
        // `; cd ..`), so the reproducer shape fires as the last line.
        let results = run_mini("Name: foo\n%check\n%ctest && exit 0\n");
        assert!(
            has(&results, "check-exit-status-masked"),
            "missing: {results:?}"
        );
    }

    #[test]
    fn exit_status_masked_informational_rerun_stays_quiet() {
        // The same runner also runs unmasked (apache-arrow shape).
        let results = run_mini("Name: foo\n%check\npytest || :\npytest\n");
        assert!(
            !has(&results, "check-exit-status-masked"),
            "unexpected: {results:?}"
        );
        // gdal: a masked pytest beside a gating %ctest still fires.
        let results = run_mini("Name: foo\n%check\n%ctest\npytest || :\n");
        assert!(
            has(&results, "check-exit-status-masked"),
            "missing: {results:?}"
        );
    }

    #[test]
    fn pipeline_status_masked_shapes() {
        // tcl r74.
        let results = run_mini(
            "Name: foo\n%check\nmake test 2>&1 | tee testresults\ngrep FAILED testresults && exit 1\n",
        );
        assert!(
            has(&results, "check-pipeline-status-masked"),
            "missing: {results:?}"
        );
        // pipefail before the pipe.
        let results = run_mini("Name: foo\n%check\nset -o pipefail\nmake test | tee log\n");
        assert!(
            !has(&results, "check-pipeline-status-masked"),
            "unexpected: {results:?}"
        );
        // PIPESTATUS read after the pipe.
        let results = run_mini("Name: foo\n%check\nmake test | tee log\nexit ${PIPESTATUS[0]}\n");
        assert!(
            !has(&results, "check-pipeline-status-masked"),
            "unexpected: {results:?}"
        );
        // A pipe into a checker is not a pass-through (piglit).
        let results = run_mini("Name: foo\n%check\nmake test | grep -q FAILED\n");
        assert!(
            !has(&results, "check-pipeline-status-masked"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn negated_command_not_last_shapes() {
        // Mid-section in %prep (%build and %check behave the same).
        let results = run_mini("Name: foo\n%prep\n! grep -q foo bar\necho ok\n");
        assert!(
            has(&results, "negated-command-not-last"),
            "missing: {results:?}"
        );
        // Dead because of a following operator.
        let results = run_mini("Name: foo\n%prep\n! grep -q foo bar || exit 1\necho ok\n");
        assert!(
            !has(&results, "negated-command-not-last"),
            "unexpected: {results:?}"
        );
        // The next command reads the status.
        let results = run_mini("Name: foo\n%prep\n! grep -q foo bar\nrc=$?\necho $rc\n");
        assert!(
            !has(&results, "negated-command-not-last"),
            "unexpected: {results:?}"
        );
        // Last in a function body.
        let results = run_mini(
            "Name: foo\n%build\ncheck_it() {\n  make thing\n  ! grep -q a b\n}\ncheck_it\n",
        );
        assert!(
            !has(&results, "negated-command-not-last"),
            "unexpected: {results:?}"
        );
        // mupdf: the `!` is a find argument on a continued line.
        let results =
            run_mini("Name: foo\n%build\nfind . \\\n  ! -name '*.o' \\\n  -delete\necho done\n");
        assert!(
            !has(&results, "negated-command-not-last"),
            "unexpected: {results:?}"
        );
        // Last command of %build: the negation is the section status.
        let results = run_mini("Name: foo\n%build\nmake\n! grep -q a b\n");
        assert!(
            !has(&results, "negated-command-not-last"),
            "unexpected: {results:?}"
        );
        // Last line of %install still fires: %__spec_install_post
        // runs after the body.
        let results =
            run_mini("Name: foo\n%install\nmake install\n! test -f %{buildroot}/usr/bin/x\n");
        assert!(
            has(&results, "negated-command-not-last"),
            "missing: {results:?}"
        );
        // ... unless the spec disables the install post step.
        let results = run_mini(
            "Name: foo\n%define __spec_install_post %{nil}\n%install\nmake install\n! test -f x\n",
        );
        assert!(
            !has(&results, "negated-command-not-last"),
            "unexpected: {results:?}"
        );
        // Before an %endif that more commands follow.
        let results = run_mini("Name: foo\n%prep\n%if 1\n! grep -q a b\n%endif\necho ok\n");
        assert!(
            has(&results, "negated-command-not-last"),
            "missing: {results:?}"
        );
        // A sibling %else arm does not count as a later command.
        let results =
            run_mini("Name: foo\n%prep\n%if 1\n! grep -q a b\n%else\necho other\n%endif\n");
        assert!(
            !has(&results, "negated-command-not-last"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn with_macro_expands_empty_shapes() {
        // zig0.15/zig0.16: the guard around %check.
        let results = run_mini(
            "Name: foo\n%bcond_without test\n%if 0%{?with test}\n%check\nmake check\n%endif\n",
        );
        assert!(
            has(&results, "with-macro-expands-empty"),
            "missing: {results:?}"
        );
        for line in ["%{!?without foo}", "%{?without:foo}", "%{?with foo}"] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            assert!(
                has(&results, "with-macro-expands-empty"),
                "no fire for {line:?}: {results:?}"
            );
        }
        for line in [
            "%{with foo}",
            "0%{?with_foo}",
            "%%{?with foo}",
            "%{?with_foo}",
        ] {
            let results = run_mini(&format!("Name: foo\n{line}\n"));
            assert!(
                !has(&results, "with-macro-expands-empty"),
                "unexpected fire for {line:?}: {results:?}"
            );
        }
    }

    #[test]
    fn ctest_with_testing_disabled_shapes() {
        // rkward.
        let results = run_mini("Name: foo\n%build\n%cmake_kf6\n%cmake_build\n%check\n%ctest\n");
        assert!(
            has(&results, "ctest-with-testing-disabled"),
            "missing: {results:?}"
        );
        // kaidan turns testing on.
        let results =
            run_mini("Name: foo\n%build\n%cmake_kf6 -DBUILD_TESTING:BOOL=ON\n%check\n%ctest\n");
        assert!(
            !has(&results, "ctest-with-testing-disabled"),
            "unexpected: {results:?}"
        );
        // No KDE cmake macro, no finding.
        let results = run_mini("Name: foo\n%build\n%cmake\n%check\nctest\n");
        assert!(
            !has(&results, "ctest-with-testing-disabled"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn failing_group_fallbacks_stay_quiet() {
        // `(cat log; false)`: the subshell's last command fails, so
        // the chain gates (acl, nss-mdns).
        let results = run_mini("Name: foo\n%check\nmake check || (cat test-suite.log; false)\n");
        assert!(
            !has(&results, "check-exit-status-masked"),
            "unexpected: {results:?}"
        );
        // A subshell ending in `exit 1` gates; one ending in
        // `exit 0` masks (gsl's two arms).
        let results = run_mini(
            "Name: foo\n%check\nmake check || (find . -name x.log -exec cat {} \\; ; exit 1)\n",
        );
        assert!(
            !has(&results, "check-exit-status-masked"),
            "unexpected: {results:?}"
        );
        let results = run_mini(
            "Name: foo\n%check\nmake check || (find . -name x.log -exec cat {} \\; ; exit 0)\n",
        );
        assert!(
            has(&results, "check-exit-status-masked"),
            "missing: {results:?}"
        );
        // A brace group spanning lines, with an `exit 1` inside
        // (gnutls, postgresql), gates.
        let results =
            run_mini("Name: foo\n%check\nmake check || {\n    cat test-suite.log\n    exit 1\n}\n");
        assert!(
            !has(&results, "check-exit-status-masked"),
            "unexpected: {results:?}"
        );
        // The same group with only a log dump masks.
        let results = run_mini("Name: foo\n%check\nmake check || {\n    cat test-suite.log\n}\n");
        assert!(
            has(&results, "check-exit-status-masked"),
            "missing: {results:?}"
        );
        // `export VAR=...` defers to the re-run consuming it (meep).
        let results = run_mini(
            "Name: foo\n%check\nmake check TESTS=x || export xfail=x\n%make_build check XFAIL_TESTS=${xfail}\n",
        );
        assert!(
            !has(&results, "check-exit-status-masked"),
            "unexpected: {results:?}"
        );
        // A retry chain whose final fallback fails gates (zeromq).
        let results = run_mini(
            "Name: foo\n%check\nmake check || make check || make check || (cat ./test-suite.log && false)\n",
        );
        assert!(
            !has(&results, "check-exit-status-masked"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn negated_text_lookalikes_stay_quiet() {
        // A conditional directive inside a backslash-continued
        // `find` command: the `!` tokens are find primaries
        // (kernel-source).
        let results = run_mini(
            "Name: foo\n%install\nfind %{buildroot} \\\n    -type f \\\n%if 1\n    ! -path '*/symtypes*' \\\n%endif\n    -printf '%%p\\n'\necho done\n",
        );
        assert!(
            !has(&results, "negated-command-not-last"),
            "unexpected: {results:?}"
        );
        // Here-document content is not a command (frr).
        let results = run_mini(
            "Name: foo\n%build\ncat > vtysh.conf << __EOF__\n! vtysh is using PAM authentication.\n__EOF__\necho done\n",
        );
        assert!(
            !has(&results, "negated-command-not-last"),
            "unexpected: {results:?}"
        );
        // A multi-line quoted awk program: the `!` is awk
        // negation (inn).
        let results = run_mini(
            "Name: foo\n%install\nfind %{buildroot} | awk '\n! /^\\/etc/ { next }\n{ print }\n' > list\necho done\n",
        );
        assert!(
            !has(&results, "negated-command-not-last"),
            "unexpected: {results:?}"
        );
        // A `||` chain continued over plain newlines: the negated
        // segment is followed by `||`, which condition (a)
        // excludes (rpmlint-mini).
        let results = run_mini("Name: foo\n%install\ncp a b ||\n ! <\"b\" ||\n false\necho done\n");
        assert!(
            !has(&results, "negated-command-not-last"),
            "unexpected: {results:?}"
        );
    }
}
