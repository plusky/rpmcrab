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

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;

use fancy_regex::Regex;

use crate::check::{Check, add_info, spec_add_info};
use crate::checks::shared::macro_regex;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::dep::{has_forbidden_controlchars, has_forbidden_controlchars_deps, parse_deps};
use crate::pkg::spec::{self, SpecPkg};
use crate::pkg::{Pkg, init as pkg_init};
use crate::tools::{Tool, ToolSource, test_source};

/// `re_tag_compile`: `^{tag}\s*:\s*(\S.*?)\s*$`, case-insensitive.
fn tag_re(tag: &str) -> Regex {
    Regex::new(&format!(r"(?i)^{tag}\s*:\s*(\S.*?)\s*$")).expect("static regex")
}

fn patch_re() -> Regex {
    tag_re(r"Patch(\d*)")
}

fn applied_patch_rpm420_re() -> Regex {
    Regex::new(r"^%patch(\d+)").expect("static regex")
}

fn applied_patch_re() -> Regex {
    Regex::new(r"^%patch\s*(\d*)").expect("static regex")
}

fn applied_patch_p_re() -> Regex {
    Regex::new(r"\s-P\s*(\d+)\b").expect("static regex")
}

fn applied_patch_pipe_re() -> Regex {
    Regex::new(r"\s%\{PATCH(\d+)\}\s*(%\{?__)?patch\b").expect("static regex")
}

fn applied_patch_i_re() -> Regex {
    Regex::new(r"(?:%\{?__)?patch\}?.*?\s+(?:<|-i)\s+%\{PATCH(\d+)\}").expect("static regex")
}

fn source_dir_re() -> Regex {
    Regex::new(r"^[^#]*(\$RPM_SOURCE_DIR|%{?_sourcedir}?)").expect("static regex")
}

fn obsolete_tags_re() -> Regex {
    tag_re(r"(?:Serial|Copyright)")
}

fn buildroot_re() -> Regex {
    tag_re("BuildRoot")
}

fn prefix_re() -> Regex {
    tag_re("Prefix")
}

fn packager_re() -> Regex {
    tag_re("Packager")
}

fn buildarch_re() -> Regex {
    tag_re(r"BuildArch(?:itectures)?")
}

fn buildprereq_re() -> Regex {
    tag_re("BuildPreReq")
}

fn prereq_re() -> Regex {
    tag_re(r"PreReq(\(.*\))")
}

fn suse_version_re() -> Regex {
    Regex::new(r"%({|{\?)?suse_version}?\s*[<>=]+\s*(?P<version>\d+)").expect("static regex")
}

fn make_check_re() -> Regex {
    Regex::new(r"(^|\s|%{?__)make}?\s+(check|test)").expect("static regex")
}

fn rpm_buildroot_re() -> Regex {
    Regex::new(r"^[^#]*?(?:(\\)*\${?RPM_BUILD_ROOT}?|(%+){?buildroot}?)").expect("static regex")
}

fn configure_libdir_spec_re() -> Regex {
    Regex::new(r"ln |\./configure[^#]*--libdir=(\S+)[^#]*").expect("static regex")
}

/// `hardcoded_library_paths`, start-anchored: the reference applies it with
/// `re.match`.
fn hardcoded_libdir_paths_re() -> Regex {
    Regex::new(r"^(/lib|/usr/lib|/usr/X11R6/lib/(?!([^/]+/)+)[^/]*\.([oa]|la|so[0-9.]*))")
        .expect("static regex")
}

fn lib_package_re() -> Regex {
    Regex::new(r"^%package.*\Wlib").expect("static regex")
}

fn ifarch_re() -> Regex {
    Regex::new(r"^\s*%ifn?arch\s").expect("static regex")
}

fn if_re() -> Regex {
    Regex::new(r"^\s*%if\s").expect("static regex")
}

fn endif_re() -> Regex {
    Regex::new(r"^\s*%endif\b").expect("static regex")
}

/// `DEFAULT_BIARCH_PACKAGES`: hardcoded library paths are not checked in
/// biarch packages.
fn biarch_package_re() -> Regex {
    Regex::new(r"^(gcc|glibc)").expect("static regex")
}

fn libdir_re() -> Regex {
    Regex::new(r"%{?_lib(?:dir)?\}?\b").expect("static regex")
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

fn deprecated_grep_re() -> Regex {
    Regex::new(r"\b[ef]grep\b").expect("static regex")
}

fn hardcoded_library_path_re() -> Regex {
    Regex::new(r"^[^#]*((^|\s+|\.\./\.\.|\${?RPM_BUILD_ROOT}?|%{?buildroot}?|%{?_prefix}?)(/lib|/usr/lib|/usr/X11R6/lib/(?!([^/]+/)+)[^/]*\.([oa]|la|so[0-9.]*))(?=[\s;/])([^\s,;]*))")
        .expect("static regex")
}

/// `(^|\s)%(define|global)\s+` + the macro being overridden.
fn define_re(inner: &str) -> Regex {
    Regex::new(&format!(r"(^|\s)%(define|global)\s+{inner}")).expect("static regex")
}

fn depscript_override_re() -> Regex {
    define_re(r"__find_(requires|provides)\s")
}

fn depgen_disable_re() -> Regex {
    define_re(r"_use_internal_dependency_generator\s+0")
}

fn patch_fuzz_override_re() -> Regex {
    define_re(r"_default_patch_fuzz\s+(\d+)")
}

fn indent_spaces_re() -> Regex {
    Regex::new(r"( \t|(^|\t)([^\t]{8})*[^\t]{4}[^\t]?([^\t][^\t.!?]|[^\t]?[.!?] )  )")
        .expect("static regex")
}

fn requires_re() -> Regex {
    Regex::new(r"(?i)^(?:Build)?(?:Pre)?Req(?:uires)?(?:\([^\)]+\))?:\s*(.*)")
        .expect("static regex")
}

fn provides_re() -> Regex {
    Regex::new(r"(?i)^Provides(?:\([^\)]+\))?:\s*(.*)").expect("static regex")
}

fn obsoletes_re() -> Regex {
    Regex::new(r"(?i)^Obsoletes:\s*(.*)").expect("static regex")
}

fn conflicts_re() -> Regex {
    Regex::new(r"(?i)^(?:Build)?Conflicts:\s*(.*)").expect("static regex")
}

fn declarative_re() -> Regex {
    Regex::new(r"(?i)^BuildSystem:\s*(.*)").expect("static regex")
}

fn compop_re() -> Regex {
    Regex::new(r"[<>=]").expect("static regex")
}

/// Anchored: the reference applies it with `re.match` ("intentionally no
/// whitespace before!").
fn setup_re() -> Regex {
    Regex::new(r"^%setup\b").expect("static regex")
}

fn setup_q_re() -> Regex {
    Regex::new(r" -[A-Za-z]*q").expect("static regex")
}

fn setup_t_re() -> Regex {
    Regex::new(r" -[A-Za-z]*T").expect("static regex")
}

fn setup_ab_re() -> Regex {
    Regex::new(r" -[A-Za-z]*[ab]").expect("static regex")
}

fn autosetup_re() -> Regex {
    Regex::new(r"^\s*%autosetup(\s.*|$)").expect("static regex")
}

fn autosetup_n_re() -> Regex {
    Regex::new(r" -[A-Za-z]*N").expect("static regex")
}

fn autopatch_re() -> Regex {
    Regex::new(r"^\s*%autopatch(?:\s|$)").expect("static regex")
}

fn filelist_re() -> Regex {
    Regex::new(r"\s+-f\s+\S+").expect("static regex")
}

fn pkgname_re() -> Regex {
    Regex::new(r"\s+(?:-n\s+)?(\S+)").expect("static regex")
}

fn tarball_re() -> Regex {
    Regex::new(r"(?i)\.(?:t(?:ar|[glx]z|bz2?)|zip)\b").expect("static regex")
}

fn python_setup_test_re() -> Regex {
    Regex::new(r"^[^#]*(setup.py test)").expect("static regex")
}

fn python_setup_install_re() -> Regex {
    Regex::new(r"^[^#]*(setup.py install|%\{?py(thon)?\d*_install)").expect("static regex")
}

fn python_module_def_re() -> Regex {
    Regex::new(r"^[^#]*%{\?!python_module:%define python_module\(\)").expect("static regex")
}

fn python_sitelib_glob_re() -> Regex {
    Regex::new(r"^[^#]*%{python_site(lib|arch)}/\*\s*$").expect("static regex")
}

fn shared_dir_glob_re() -> Regex {
    Regex::new(r"^[^#]*%{_(?:bin|data|doc|include|man)dir}/\*\s*$").expect("static regex")
}

fn suse_update_desktop_file_re() -> Regex {
    Regex::new(r"(?i)^BuildRequires:\s*update-desktop-files").expect("static regex")
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
    valid_groups: Vec<String>,
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
    buildroot_re: Regex,
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
    section_res: Vec<(String, Regex)>,
    deprecated_grep_re: Regex,
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
    compop_re: Regex,
    setup_re: Regex,
    setup_q_re: Regex,
    setup_t_re: Regex,
    setup_ab_re: Regex,
    autosetup_re: Regex,
    autosetup_n_re: Regex,
    autopatch_re: Regex,
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
    applied_patches_ifarch: Vec<i64>,
    patches_auto_applied: bool,
    source_dir: bool,
    buildroot: bool,
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
    /// Build the check from the config (`ValidGroups`,
    /// `HardcodedLibPathExceptions`, `mini_mode`).
    pub fn new(config: &Config) -> Self {
        Self::with_tool_source(config, ToolSource::Path)
    }

    /// Probe for the required `rpm` tool under `source`. `rpm` is
    /// mandatory for spec parsing, so absence fails here with a clear
    /// message instead of deep inside the check.
    pub fn with_tool_source(config: &Config, source: ToolSource) -> Self {
        let valid_groups = config
            .configuration
            .get("ValidGroups")
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
            .unwrap_or("");
        Self {
            valid_groups,
            hardcoded_lib_path_exceptions_re: Regex::new(exceptions)
                .unwrap_or_else(|_| Regex::new("$^").expect("static regex")),
            mini_mode: config.mini_mode,
            macro_re: macro_regex(),
            patch_re: patch_re(),
            applied_patch_rpm420_re: applied_patch_rpm420_re(),
            applied_patch_re: applied_patch_re(),
            applied_patch_p_re: applied_patch_p_re(),
            applied_patch_pipe_re: applied_patch_pipe_re(),
            applied_patch_i_re: applied_patch_i_re(),
            source_dir_re: source_dir_re(),
            obsolete_tags_re: obsolete_tags_re(),
            buildroot_re: buildroot_re(),
            prefix_re: prefix_re(),
            packager_re: packager_re(),
            buildarch_re: buildarch_re(),
            buildprereq_re: buildprereq_re(),
            prereq_re: prereq_re(),
            suse_version_re: suse_version_re(),
            make_check_re: make_check_re(),
            rpm_buildroot_re: rpm_buildroot_re(),
            configure_libdir_spec_re: configure_libdir_spec_re(),
            hardcoded_libdir_paths_re: hardcoded_libdir_paths_re(),
            lib_package_re: lib_package_re(),
            ifarch_re: ifarch_re(),
            if_re: if_re(),
            endif_re: endif_re(),
            biarch_package_re: biarch_package_re(),
            libdir_re: libdir_re(),
            section_res: section_res(),
            deprecated_grep_re: deprecated_grep_re(),
            hardcoded_library_path_re: hardcoded_library_path_re(),
            depscript_override_re: depscript_override_re(),
            depgen_disable_re: depgen_disable_re(),
            patch_fuzz_override_re: patch_fuzz_override_re(),
            indent_spaces_re: indent_spaces_re(),
            requires_re: requires_re(),
            provides_re: provides_re(),
            obsoletes_re: obsoletes_re(),
            conflicts_re: conflicts_re(),
            declarative_re: declarative_re(),
            compop_re: compop_re(),
            setup_re: setup_re(),
            setup_q_re: setup_q_re(),
            setup_t_re: setup_t_re(),
            setup_ab_re: setup_ab_re(),
            autosetup_re: autosetup_re(),
            autosetup_n_re: autosetup_n_re(),
            autopatch_re: autopatch_re(),
            filelist_re: filelist_re(),
            pkgname_re: pkgname_re(),
            tarball_re: tarball_re(),
            python_setup_test_re: python_setup_test_re(),
            python_setup_install_re: python_setup_install_re(),
            python_module_def_re: python_module_def_re(),
            python_sitelib_glob_re: python_sitelib_glob_re(),
            shared_dir_glob_re: shared_dir_glob_re(),
            suse_update_desktop_file_re: suse_update_desktop_file_re(),
            spec_file: None,
            spec_name: None,
            patches: BTreeMap::new(),
            applied_patches: Vec::new(),
            applied_patches_ifarch: Vec::new(),
            patches_auto_applied: false,
            source_dir: false,
            buildroot: false,
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

    fn probe_rpm(source: &ToolSource) -> Tool {
        let (rpm, _) = Tool::probe(source, "rpm", &["--version"]);
        assert!(
            rpm.is_present(),
            "SpecCheck requires the 'rpm' tool, but it could not be executed"
        );
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
    fn check_spec(&mut self, pkg: &SpecPkg, _config: &Config, out: &mut Filter) {
        // `error_details` for `-i/--explain`, set in `__init__` in the
        // reference.
        out.set_error_detail(
            "non-standard-group",
            format!(
                "The value of the Group tag in the package is not valid.  Valid groups are:\n'{}'.",
                self.valid_groups.join(", ")
            ),
        );

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

        self.check_no_buildroot_tag(pkg, out);
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
                if self.applied_patches_ifarch.contains(pnum) {
                    let tag = format!("Patch{pnum}:");
                    self.info(
                        out,
                        pkg,
                        Level::Warning,
                        "%ifarch-applied-patch",
                        &[&tag, pfile],
                    );
                }
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
        self.applied_patches_ifarch.clear();
        self.patches_auto_applied = false;
        self.source_dir = false;
        self.buildroot = false;
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
    fn check_no_buildroot_tag(&self, pkg: &SpecPkg, out: &mut Filter) {
        if !self.buildroot {
            self.info(out, pkg, Level::Warning, "no-buildroot-tag", &[]);
        }
    }

    /// Parse the spec with the `rpm` tool and forward its diagnostics
    /// (`SpecCheck.py:300-322`).
    fn check_specfile_error(&self, pkg: &SpecPkg, out: &mut Filter) {
        let spec_file = self.spec_file.as_deref().unwrap_or("");
        let define = format!("_sourcedir {}", self.spec_file_dir());
        let mut cmd = self
            .rpm
            .command()
            .expect("rpm was probed present when SpecCheck was constructed");
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
        if self.checkline_section(line) {
            return;
        }
        self.checkline_buildroot_usage(pkg, out, line);
        self.checkline_make_check(pkg, out, line);
        self.checkline_setup(pkg, out, line);
        self.checkline_autopatch(pkg, out, line);
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
        self.checkline_valid_groups(pkg, out, line);
        self.checkline_macros_in_comments(pkg, out, line);
        self.checkline_python_setup_test(pkg, out, line);
        self.checkline_python_setup_install(pkg, out, line);
        self.checkline_python_module_def(pkg, out, line);
        self.checkline_python_sitelib_glob(pkg, out, line);
        self.checkline_shared_dir_glob(pkg, out, line);

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
        if let Some(char) = line.find(NBSP) {
            let detail = format!(
                "line {}, char {}",
                pkg.current_linenum.get().unwrap_or(0),
                char
            );
            self.info(out, pkg, Level::Warning, "non-break-space", &[&detail]);
        }
    }

    fn checkline_section(&mut self, line: &str) -> bool {
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
            if !self.setup_q_re.is_match(line).unwrap_or(false) {
                // Don't warn if there's a -T without -a or -b.
                if !self.setup_t_re.is_match(line).unwrap_or(false)
                    || self.setup_ab_re.is_match(line).unwrap_or(false)
                {
                    self.info(out, pkg, Level::Warning, "setup-not-quiet", &[]);
                }
            }
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
                if self.ifarch_depth > 0 {
                    self.applied_patches_ifarch.push(pnum);
                }
            }
            return;
        }
        if let Ok(Some(caps)) = self.applied_patch_pipe_re.captures(line) {
            let pnum: i64 = caps
                .get(1)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            self.applied_patches.push(pnum);
            if self.ifarch_depth > 0 {
                self.applied_patches_ifarch.push(pnum);
            }
            return;
        }
        if let Ok(Some(caps)) = self.applied_patch_i_re.captures(line) {
            let pnum: i64 = caps
                .get(1)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            self.applied_patches.push(pnum);
            if self.ifarch_depth > 0 {
                self.applied_patches_ifarch.push(pnum);
            }
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
        self.checkline_package_buildroot(pkg, out, line);
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

    fn checkline_package_buildroot(&mut self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        if let Ok(Some(caps)) = self.buildroot_re.captures(line) {
            self.buildroot = true;
            let value = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if value.starts_with('/') {
                self.info(
                    out,
                    pkg,
                    Level::Warning,
                    "hardcoded-path-in-buildroot-tag",
                    &[value],
                );
            }
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
                if version.is_none() && self.compop_re.is_match(req).unwrap_or(false) {
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
                    if !prov.starts_with('/') {
                        self.info(
                            out,
                            pkg,
                            Level::Warning,
                            "unversioned-explicit-provides",
                            &[prov],
                        );
                    }
                    if self.compop_re.is_match(prov).unwrap_or(false) {
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
                    if !obs.starts_with('/') {
                        self.info(
                            out,
                            pkg,
                            Level::Warning,
                            "unversioned-explicit-obsoletes",
                            &[obs],
                        );
                    }
                    if self.compop_re.is_match(obs).unwrap_or(false) {
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
                if version.is_none() && self.compop_re.is_match(conf).unwrap_or(false) {
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

    fn checkline_valid_groups(&self, pkg: &SpecPkg, out: &mut Filter, line: &str) {
        // When not checking a spec file only, the spec comes from inside an
        // SRPM; skip to avoid duplicate warnings (#167).
        if self.spec_only
            && !self.valid_groups.is_empty()
            && line.to_lowercase().starts_with("group:")
        {
            let group = line[6..].trim();
            if !self.valid_groups.iter().any(|g| g == group) {
                self.info(out, pkg, Level::Warning, "non-standard-group", &[group]);
            }
        }
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
        let mut config = config_mini();
        config.configuration.insert(
            "ValidGroups".to_string(),
            toml::Value::Array(vec![toml::Value::String(
                "System Environment/Base".to_string(),
            )]),
        );
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
            "hardcoded-path-in-buildroot-tag",
            "hardcoded-packager-tag",
            "hardcoded-prefix-tag",
            "comparison-operator-in-deptoken",
            "unversioned-explicit-provides",
            "suse-update-desktop-file-deprecated",
            "no-%check-section",
            "configure-without-libdir-spec",
            "shared-dir-glob-in-files",
            "patch-not-applied",
            "non-standard-group",
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

    #[test]
    #[should_panic(expected = "requires the 'rpm' tool")]
    fn spec_check_fails_fast_without_rpm() {
        let empty = tempfile::TempDir::new().expect("tmpdir");
        let config = Config::default();
        let _ = SpecCheck::with_tool_dir(&config, Some(empty.path()));
    }
}
