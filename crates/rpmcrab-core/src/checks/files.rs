//! `FilesCheck`: file-level validation, ported from rpmlint's `FilesCheck.py`.
//!
//! Covers the reference's `add_info` call sites: man/info page compression,
//! permissions, ownership, symlinks, hardlinks, scriptlets, and the per-file
//! type dispatches (normal file, directory, symlink).
//!
//! Deliberate gaps are ledgered in `tests/parity/divergences.toml`.

#![allow(clippy::collapsible_if, clippy::bool_comparison)]

use std::collections::HashMap;
use std::path::Path;

use fancy_regex::Regex;
use indexmap::IndexMap;

use super::is_match;
use super::shared::{devel_regex, lib_package_regex, macro_regex};
use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::{self, PkgFile};
use crate::tools::{Tool, ToolSource, test_source};

fn man_regex() -> Regex {
    Regex::new(r"/man(?:\d[px]?|n)/").expect("static regex")
}

fn man_base_regex() -> Regex {
    Regex::new(r"(?i)^(?P<path>/usr/share/man|/usr/man)/(?:(?P<lang>[a-z_]+)/)?man(?P<category>[^/]+)/(?P<filename>[^/]+)$")
        .expect("static regex")
}

fn info_regex() -> Regex {
    Regex::new(r"(/usr/share|/usr)/info/").expect("static regex")
}

fn log_regex() -> Regex {
    Regex::new(r"/var/log/").expect("static regex")
}

fn kernel_package_regex() -> Regex {
    Regex::new(r"^kernel(-(default|desktop|pae|xen|vanilla|debug|kdump|source|syms))?$")
        .expect("static regex")
}

fn debuginfo_package_regex() -> Regex {
    Regex::new(r"-debuginfo$").expect("static regex")
}

fn debugsource_package_regex() -> Regex {
    Regex::new(r"-debugsource$").expect("static regex")
}

fn kernel_modules_regex() -> Regex {
    Regex::new(r"^/lib/modules/").expect("static regex")
}

fn quotes_regex() -> Regex {
    Regex::new(r#"['"]"#).expect("static regex")
}

fn compr_regex() -> Regex {
    Regex::new(r"\.(gz|z|Z|zip|bz2|lzma|xz|zst)$").expect("static regex")
}

fn absolute_regex() -> Regex {
    Regex::new(r"^/([^/]+)").expect("static regex")
}

fn absolute2_regex() -> Regex {
    Regex::new(r"^/?([^/]+)").expect("static regex")
}

fn points_regex() -> Regex {
    Regex::new(r"^\.\./(.*)").expect("static regex")
}

fn doc_regex() -> Regex {
    Regex::new(r"^/usr(/share|/X11R6)?/(doc|man|info)/|^/usr/share/gnome/help")
        .expect("static regex")
}

fn bin_regex() -> Regex {
    Regex::new(r"^/(?:usr/(?:s?bin|games)|s?bin)/(.*)").expect("static regex")
}

fn includefile_regex() -> Regex {
    Regex::new(r"(?i)\.(c|h)(pp|xx)?$").expect("static regex")
}

fn develfile_regex() -> Regex {
    Regex::new(r"\.(a|cmxa?|mli?|gir)$").expect("static regex")
}

fn buildconfigfile_regex() -> Regex {
    Regex::new(r"(\.pc|/bin/.+-config)$").expect("static regex")
}

fn buildconfig_rpath_regex() -> Regex {
    Regex::new(r"(?:-rpath|Wl,-R)\b").expect("static regex")
}

fn sofile_regex() -> Regex {
    Regex::new(r"/lib(64)?/(.+/)?lib[^/]+\.so$").expect("static regex")
}

fn lib_regex() -> Regex {
    Regex::new(r"/lib(?:64)?/lib[A-Za-z0-9](?:(?:|[\w\-\.]*[A-Za-z0-9])\.so\.[\w+\.]+|\w*-\d(?:|[\w\-\.]*[A-Za-z0-9])\.so)$")
        .expect("static regex")
}

/// Files exempt from the zero-length check (FilesCheck.py:180).
fn normal_zero_length_regex() -> Regex {
    Regex::new(
        r"^/etc/security/console\.apps/|/\.nosearch$|/__init__\.py$|/py\.typed$|\.dist-info/REQUESTED$|/gem\.build_complete$",
    )
    .expect("static regex")
}

fn depmod_regex() -> Regex {
    Regex::new(r"(?m)^[^#]*depmod").expect("static regex")
}

fn install_info_regex() -> Regex {
    Regex::new(r"(?m)^[^#]*install-info").expect("static regex")
}

fn perl_temp_file_regex() -> Regex {
    Regex::new(r".*perl.*/(\.packlist|perllocal\.pod)$").expect("static regex")
}

fn interpreter_regex() -> Regex {
    Regex::new(r"^/(?:usr/)?(?:s?bin|games|libexec(?:/.+)?|(?:lib(?:64)?|share)/.+)/([^/]+)$")
        .expect("static regex")
}

fn script_regex() -> Regex {
    Regex::new(
        r"^/((usr/)?s?bin|etc/(rc\.d/init\.d|X11/xinit\.d|cron\.(hourly|daily|monthly|weekly)))/",
    )
    .expect("static regex")
}

fn sourced_script_regex() -> Regex {
    Regex::new(r"^/etc/(bash_completion\.d|profile\.d)/").expect("static regex")
}

fn fsf_license_regex() -> Regex {
    Regex::new(r"(?i)(GNU((\s+(Library|Lesser|Affero))?(\s+General)?\s+Public|\s+Free\s+Documentation)\s+Licen[cs]e|(GP|FD)L)")
        .expect("static regex")
}

fn fsf_wrong_address_regex() -> Regex {
    Regex::new(r"(?i)(675\s+Mass\s+Ave|59\s+Temple\s+Place|02139|51\s+Franklin\s+St)")
        .expect("static regex")
}

fn scalable_icon_regex() -> Regex {
    Regex::new(r"^/usr(?:/local)?/share/icons/.*/scalable/").expect("static regex")
}

fn tcl_regex() -> Regex {
    Regex::new(r"^/usr/lib(64)?/([^/]+/)?pkgIndex\.tcl").expect("static regex")
}

fn perl_regex() -> Regex {
    Regex::new(r"^/usr/lib/perl5/(?:vendor_perl/)?([0-9]+\.[0-9]+)\.([0-9]+)/")
        .expect("static regex")
}

fn python_regex() -> Regex {
    Regex::new(r"^/usr/lib(?:64)?/python([.0-9]+)/").expect("static regex")
}

fn python_bytecode_pep3147_regex() -> Regex {
    Regex::new(r"^(.*)/__pycache__/(.*?)\.([^.]+)(\.opt-[12])?\.py[oc]$").expect("static regex")
}

fn python_bytecode_regex() -> Regex {
    Regex::new(r"^(.*)(\.py[oc])$").expect("static regex")
}

fn depmod_kernel_regex() -> Regex {
    Regex::new(r"^(?:/usr)/lib/modules/([0-9]+\.[0-9]+\.[0-9]+[^/]*?)/").expect("static regex")
}

fn log_file_regex() -> Regex {
    Regex::new(r"^/var/log/[^/]+$").expect("static regex")
}

fn lib_path_regex() -> Regex {
    Regex::new(r"^(/usr(/X11R6)?)?/lib(64)?").expect("static regex")
}

fn start_certificate_regex() -> Regex {
    Regex::new(r"^-----BEGIN CERTIFICATE-----\n?$").expect("static regex")
}

fn start_private_key_regex() -> Regex {
    // NB: the reference spells this with four leading dashes, so it cannot
    // match a well-formed PEM header; replicated exactly.
    // Python's `$` matches before a trailing newline, Rust's does not;
    // the explicit newline keeps the reference behavior.
    Regex::new(r"^----BEGIN PRIVATE KEY-----\n?$").expect("static regex")
}

#[allow(dead_code)]
pub struct FilesCheck {
    man_re: Regex,
    man_base_re: Regex,
    info_re: Regex,
    log_re: Regex,
    devel_re: Regex,
    lib_package_re: Regex,
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
    normal_zero_length_re: Regex,
    depmod_re: Regex,
    install_info_re: Regex,
    perl_temp_file_re: Regex,
    interpreter_re: Regex,
    script_re: Regex,
    sourced_script_re: Regex,
    fsf_license_re: Regex,
    fsf_wrong_address_re: Regex,
    scalable_icon_re: Regex,
    tcl_re: Regex,
    perl_re: Regex,
    python_re: Regex,
    python_bytecode_pep3147_re: Regex,
    python_bytecode_re: Regex,
    depmod_kernel_re: Regex,
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
    dangling_exceptions: Vec<(String, Regex)>,
    ldconfig_re: Regex,
    python_default_version: String,
    /// Probed `gzip`, `bzip2`, `xz`, `zstd`, in that order.
    decompressors: [Tool; 4],
}

/// Whether `script` contains a depmod call for `kernel_version`, replicating
/// the reference's per-kernel regex without compiling one per file.
fn depmod_call_for_kernel(script: &str, kernel_version: &str) -> bool {
    fn is_word(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }
    let bytes = script.as_bytes();
    let mut pos = 0;
    while let Some(i) = script[pos..].find("depmod") {
        let d = pos + i;
        // \bdepmod
        if d > 0 && is_word(bytes[d - 1]) {
            pos = d + 1;
            continue;
        }
        // \s+-a
        let after = script[d + 6..].trim_start_matches(|c: char| c.is_whitespace());
        if !after.starts_with("-a") {
            pos = d + 1;
            continue;
        }
        let rest = &after[2..];
        // .*F\s+/boot/System\.map-<ver>\b
        let needle = format!("/boot/System.map-{kernel_version}");
        let mut found = false;
        let mut fpos = 0;
        while let Some(fi) = rest[fpos..].find('F') {
            let f = fpos + fi;
            let after_f = rest[f + 1..].trim_start_matches(|c: char| c.is_whitespace());
            if let Some(ni) = after_f.find(&needle) {
                let after_ver = &after_f[ni + needle.len()..];
                if after_ver.as_bytes().first().is_none_or(|&b| !is_word(b)) {
                    // .*\b<ver>\b
                    let mut vpos = ni + needle.len();
                    while let Some(vi) = after_f[vpos..].find(kernel_version) {
                        let v = vpos + vi;
                        let before_ok = v == 0 || !is_word(after_f.as_bytes()[v - 1]);
                        let after_v = &after_f[v + kernel_version.len()..];
                        let after_ok = after_v.as_bytes().first().is_none_or(|&b| !is_word(b));
                        if before_ok && after_ok {
                            found = true;
                            break;
                        }
                        vpos = v + 1;
                    }
                }
            }
            if found {
                break;
            }
            fpos = f + 1;
        }
        if found {
            return true;
        }
        pos = d + 1;
    }
    false
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
            man_re: man_regex(),
            man_base_re: man_base_regex(),
            info_re: info_regex(),
            log_re: log_regex(),
            devel_re: devel_regex(),
            lib_package_re: lib_package_regex(),
            kernel_package_re: kernel_package_regex(),
            debuginfo_package_re: debuginfo_package_regex(),
            debugsource_package_re: debugsource_package_regex(),
            kernel_modules_re: kernel_modules_regex(),
            macro_re: macro_regex(),
            quotes_re: quotes_regex(),
            games_group_re: Regex::new(&games_group)
                .unwrap_or_else(|_| Regex::new("$^").expect("static")),
            skipdocs_re: Regex::new(&format!("(?i){skipdocs}"))
                .unwrap_or_else(|_| Regex::new("$^").expect("static")),
            meta_package_re: Regex::new(&meta_pkg)
                .unwrap_or_else(|_| Regex::new("$^").expect("static")),
            compr_re: compr_regex(),
            absolute_re: absolute_regex(),
            absolute2_re: absolute2_regex(),
            points_re: points_regex(),
            doc_re: doc_regex(),
            bin_re: bin_regex(),
            includefile_re: includefile_regex(),
            develfile_re: develfile_regex(),
            buildconfigfile_re: buildconfigfile_regex(),
            buildconfig_rpath_re: buildconfig_rpath_regex(),
            sofile_re: sofile_regex(),
            lib_re: lib_regex(),
            normal_zero_length_re: normal_zero_length_regex(),
            depmod_re: depmod_regex(),
            install_info_re: install_info_regex(),
            perl_temp_file_re: perl_temp_file_regex(),
            interpreter_re: interpreter_regex(),
            script_re: script_regex(),
            sourced_script_re: sourced_script_regex(),
            fsf_license_re: fsf_license_regex(),
            fsf_wrong_address_re: fsf_wrong_address_regex(),
            scalable_icon_re: scalable_icon_regex(),
            tcl_re: tcl_regex(),
            perl_re: perl_regex(),
            python_re: python_regex(),
            python_bytecode_pep3147_re: python_bytecode_pep3147_regex(),
            python_bytecode_re: python_bytecode_regex(),
            depmod_kernel_re: depmod_kernel_regex(),
            log_file_re: log_file_regex(),
            lib_path_re: lib_path_regex(),
            start_certificate_re: start_certificate_regex(),
            start_private_key_re: start_private_key_regex(),
            use_debugsource: get_bool("UseDebugSource"),
            module_rpms_ok: get_bool("KernelModuleRPMsOK"),
            use_relative_symlinks: get_bool("UseRelativeSymlinks"),
            perl_version_trick: get_bool("PerlVersionTrick"),
            compress_ext: get_str("CompressExtension"),
            standard_users: get_strings("StandardUsers"),
            standard_groups: get_strings("StandardGroups"),
            disallowed_dirs: get_strings("DisallowedDirs"),
            dangling_exceptions: dangling,
            ldconfig_re: Regex::new(r"(?m)^[^#]*ldconfig").expect("static regex"),
            python_default_version: get_str("PythonDefaultVersion"),
            decompressors: ["gzip", "bzip2", "xz", "zstd"]
                .map(|name| Tool::probe(&source, name, &[]).0),
        }
    }

    /// Test entry point: `None` probes the live `PATH`, `Some(dir)`
    /// resolves the tools under `dir` instead of mutating the process
    /// environment.
    pub fn with_tool_dir(config: &Config, bin_dir: Option<&std::path::Path>) -> Self {
        Self::with_tool_source(config, test_source(bin_dir))
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
    lib_package: bool,
    perl_dep_error: bool,
    python_dep_error: bool,
    lib_file: bool,
    non_lib_file: Option<String>,
    log_files: Vec<String>,
    logrotate_file: bool,
    debuginfo_srcs: bool,
    debuginfo_debugs: bool,
    postin: String,
    postun: String,
    preun: String,
    hardlinks: HashMap<(u32, u32), Vec<String>>,
    bindir_exes: IndexMap<String, Vec<String>>,
    man_basenames: std::collections::HashSet<String>,
}

impl Check for FilesCheck {
    fn name(&self) -> &'static str {
        "FilesCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let mut st = PkgState::default();
        self.check_utf8(pkg, out);
        if pkg.is_source {
            return;
        }
        st.devel_pkg = is_match(&self.devel_re, &pkg.name);
        if !st.devel_pkg {
            for p in &pkg.provides {
                if is_match(&self.devel_re, &p.name) {
                    st.devel_pkg = true;
                    break;
                }
            }
        }
        st.lib_package = is_match(&self.lib_package_re, &pkg.name);
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

        self.check_nodoc(pkg, &st, out);
        self.check_meta_package(pkg, &st, out);
        self.check_empty_debuginfo(pkg, &st, out);
        for f in &pkg.files {
            self.check_file(pkg, &f.name, f, &mut st, out);
        }
        self.check_log_files_without_logrotate(pkg, &st, out);
        self.check_outside_libdir_files(pkg, &st, out);
        self.check_debuginfo_without_sources(pkg, &st, out);
        self.check_bindir_exes(pkg, &st, out);
    }
}

fn strip_quotes(re: &Regex, s: &str) -> String {
    re.replace_all(s, "").to_string()
}

impl FilesCheck {
    fn check_utf8(&self, pkg: &Pkg, out: &mut Filter) {
        use librpm::Tag;
        for name in pkg.tag_str_array(Tag::FILENAMES) {
            if !is_utf8(name.as_bytes()) {
                add_info(out, Level::Error, pkg, "filename-not-utf8", &[&name]);
            }
        }
    }

    fn check_nodoc(&self, pkg: &Pkg, st: &PkgState, out: &mut Filter) {
        if !st.lib_package && pkg.doc_files.is_empty() {
            add_info(out, Level::Warning, pkg, "no-documentation", &[]);
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

    fn check_log_files_without_logrotate(&self, pkg: &Pkg, st: &PkgState, out: &mut Filter) {
        if !st.log_files.is_empty() && !st.logrotate_file {
            let mut files = st.log_files.clone();
            files.sort();
            let joined = files.join(" ");
            add_info(
                out,
                Level::Warning,
                pkg,
                "log-files-without-logrotate",
                &[&joined],
            );
        }
    }

    fn check_outside_libdir_files(&self, pkg: &Pkg, st: &PkgState, out: &mut Filter) {
        if st.lib_package && st.lib_file {
            if let Some(f) = st.non_lib_file.as_ref() {
                add_info(out, Level::Error, pkg, "outside-libdir-files", &[f]);
            }
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

    fn check_bindir_exes(&self, pkg: &Pkg, st: &PkgState, out: &mut Filter) {
        for (exe, paths) in &st.bindir_exes {
            if paths.len() > 1 {
                let joined = paths.join(" ");
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "duplicate-executable",
                    &[exe, &joined],
                );
            } else if !st.man_basenames.contains(exe) {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "no-manual-page-for-binary",
                    &[exe],
                );
            }
        }
    }

    fn check_file(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        st: &mut PkgState,
        out: &mut Filter,
    ) {
        if is_match(&self.log_re, fname) {
            st.log_files.push(fname.to_string());
        }
        self.check_file_manpage(pkg, fname, pkgfile, out);
        self.check_file_infopage_compressed(pkg, fname, out);
        self.check_file_unexpanded_macro(pkg, fname, out);
        self.check_file_non_standard_uid(pkg, fname, pkgfile, out);
        self.check_file_non_standard_gid(pkg, fname, pkgfile, out);
        self.check_file_kernel_modules(pkg, fname, &st.is_kernel_package, out);
        self.check_file_dir_or_file(pkg, fname, out);
        self.check_file_non_ghost_in_run(pkg, fname, pkg, out);
        self.check_file_systemd_unit_in_etc(pkg, fname, out);
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
        self.check_file_logrotate(pkg, fname, st, out);
        self.check_file_crontab(pkg, fname, out);
        self.check_file_xinetd(pkg, fname, out);
        self.check_file_compressed_symlink(pkg, fname, pkgfile, out);
        self.check_file_hardlink(pkg, fname, pkgfile, st, out);
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

impl FilesCheck {
    /// Read up to 2048 bytes and decide text-vs-binary, mirroring the
    /// reference's `peek` (including its `read-error` on `OSError`).
    fn peek(&self, pkg: &Pkg, pkgfile: &PkgFile, out: &mut Filter) -> (Vec<u8>, bool) {
        let bytes = match std::fs::read(&pkgfile.path) {
            Ok(b) => b,
            Err(e) => {
                add_info(out, Level::Warning, pkg, "read-error", &[&e.to_string()]);
                return (Vec::new(), false);
            }
        };
        let chunk: Vec<u8> = bytes.into_iter().take(2048).collect();
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

/// rpmlint's `check_versioned_dep`: a `Requires`/`PreReq` on `name` (with an
/// optional `(arch-bits)` suffix) pinned with `=` to `version`.
fn check_versioned_dep(pkg: &Pkg, name: &str, version: &str) -> bool {
    const RPMSENSE_EQUAL: u32 = 8;
    for d in pkg.requires.iter().chain(&pkg.prereq) {
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

    /// rpmlint's `is_utf8`: strict UTF-8, transparently decompressing the
    /// compression formats the reference knows. A failed decompression reads
    /// as UTF-8, matching the reference's `except OSError: return True`.
    ///
    /// An absent decompressor also reads as UTF-8. The reference decompresses
    /// IN-PROCESS (pkg.py imports bz2, gzip, lzma, zstandard) so it never needs
    /// a decompressor binary and always gets to the real bytes; reading the
    /// still-compressed file instead would report `file-not-utf8` for every
    /// `.gz` man page on a host without gzip, which the reference never does.
    fn is_utf8_file(&self, fname: &str, path: &str) -> bool {
        match self.decompressor_for(fname) {
            Some(tool) => {
                let Some(mut cmd) = tool.command() else {
                    return true;
                };
                cmd.arg("-dc")
                    .arg(path)
                    .output()
                    .map(|o| !o.status.success() || is_utf8(&o.stdout))
                    .unwrap_or(true)
            }
            None => std::fs::read(path).map(|b| is_utf8(&b)).unwrap_or(true),
        }
    }
}

impl FilesCheck {
    fn check_file_manpage(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        if pkgfile::is_dir(pkgfile.mode) {
            return;
        }
        let caps = match self.man_base_re.captures(fname) {
            Ok(Some(c)) => c,
            _ => return,
        };
        let category = caps.name("category").map(|m| m.as_str()).unwrap_or("");
        let filename = caps.name("filename").map(|m| m.as_str()).unwrap_or("");
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
            if !filename.contains('/')
                || Path::new(filename)
                    .parent()
                    .map(|p| p.as_os_str().is_empty())
                    .unwrap_or(true)
                    == false
            {
                // filename has a parent dir component
                if filename.contains('/') {
                    add_info(out, Level::Error, pkg, "manual-page-in-subfolder", &[fname]);
                }
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

    fn check_file_non_standard_uid(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        out: &mut Filter,
    ) {
        if !self.standard_users.contains(&pkgfile.user) {
            add_info(
                out,
                Level::Warning,
                pkg,
                "non-standard-uid",
                &[fname, &pkgfile.user],
            );
        }
    }

    fn check_file_non_standard_gid(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        out: &mut Filter,
    ) {
        if !self.standard_groups.contains(&pkgfile.group) {
            add_info(
                out,
                Level::Warning,
                pkg,
                "non-standard-gid",
                &[fname, &pkgfile.group],
            );
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

    fn check_file_dir_or_file(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
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

    fn check_file_non_ghost_in_run(&self, pkg: &Pkg, fname: &str, pkg_ref: &Pkg, out: &mut Filter) {
        if fname.starts_with("/run/") && !pkg_ref.ghost_files.contains(&fname.to_string()) {
            add_info(out, Level::Warning, pkg, "non-ghost-in-run", &[fname]);
        }
    }

    fn check_file_systemd_unit_in_etc(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if fname.starts_with("/etc/systemd/system/") {
            add_info(out, Level::Warning, pkg, "systemd-unit-in-etc", &[fname]);
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
        let lower = fname.to_lowercase();
        if lower.ends_with('~')
            || lower.ends_with(".bak")
            || lower.ends_with(".orig")
            || lower.ends_with(".rej")
        {
            add_info(out, Level::Error, pkg, "backup-file-in-package", &[fname]);
        }
    }

    fn check_file_version_control_internal_file(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if fname.contains("/.git/")
            || fname.contains("/.svn/")
            || fname.contains("/.hg/")
            || fname.contains("/CVS/")
        {
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
        let is_hidden = fname.split('/').any(|c| c.starts_with('.') && c.len() > 1);
        if is_hidden
            && !fname.starts_with("/etc/skel/")
            && !fname.ends_with("/.build-id")
            && !fname.ends_with("/.cargo-checksum.json")
        {
            add_info(out, Level::Warning, pkg, "hidden-file-or-dir", &[fname]);
        }
    }

    fn check_file_manifest_in_perl_module(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if fname.ends_with("/MANIFEST") && fname.contains("/perl") {
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
    fn check_file_logrotate(&self, pkg: &Pkg, fname: &str, st: &mut PkgState, out: &mut Filter) {
        // logrotate_regex: /etc/logrotate.d/
        if fname.starts_with("/etc/logrotate.d/") && fname != "/etc/logrotate.d/" {
            st.logrotate_file = true;
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
        let deps: Vec<&str> = pkg.requires.iter().map(|d| d.name.as_str()).collect();
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
        // #552: replicate reference as-is (matches base dirs too, known bug)
        let deps: Vec<&str> = pkg.requires.iter().map(|d| d.name.as_str()).collect();
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

    fn check_file_xinetd(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        let deps: Vec<&str> = pkg.requires.iter().map(|d| d.name.as_str()).collect();
        if fname.starts_with("/etc/xinetd.d/") && !deps.contains(&"xinetd") && pkg.name != "xinetd"
        {
            add_info(
                out,
                Level::Error,
                pkg,
                "missing-dependency-to-xinetd",
                &["for xinet.d script", fname],
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

    fn check_file_hardlink(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        st: &mut PkgState,
        out: &mut Filter,
    ) {
        let key = (pkgfile.rdev, pkgfile.inode);
        if let Some(hardlinks) = st.hardlinks.get(&key) {
            for hardlink in hardlinks {
                let hp = Path::new(hardlink).parent();
                let fp = Path::new(fname).parent();
                if hp != fp {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "cross-directory-hard-link",
                        &[fname, hardlink],
                    );
                }
            }
        }
        st.hardlinks.entry(key).or_default().push(fname.to_string());
    }

    fn check_file_crond(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        if !fname.starts_with("/etc/cron.d/") {
            return;
        }
        let mode = pkgfile.mode;
        if pkgfile::is_symlink(mode) {
            add_info(out, Level::Error, pkg, "symlink-crontab-file", &[fname]);
        }
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
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "zero-perms-ghost",
                    &[&format!("Suggestion: \"%ghost %attr(,,) {fname}\"")],
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
        &self,
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
        // devel-file-in-non-devel-package for .so links
        if !st.devel_pkg && fname.contains(".so") && !link.ends_with(".so") {
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
                st.man_basenames.insert(m.as_str().to_string());
            }
        }
        // bindir exes
        for bindir in ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"] {
            if fname.starts_with(bindir) {
                let rest = fname.strip_prefix(bindir).unwrap_or("");
                if !rest.contains('/') {
                    st.bindir_exes.entry(rest.to_string()).or_default();
                }
                break;
            }
        }
        // dangling symlink checks
        self.check_link_absolute(pkg, fname, pkgfile, st, out);
        self.check_link_relative(pkg, fname, pkgfile, st, out);
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

    fn report_dangling(
        &self,
        pkg: &Pkg,
        fname: &str,
        link: &str,
        relative: bool,
        out: &mut Filter,
    ) {
        match self.dangling_exception(link) {
            // An empty exception name behaves like no exception.
            Some(name) if !name.is_empty() => {
                if !pkg.req_names.iter().any(|n| n == name) {
                    add_info(out, Level::Warning, pkg, "no-dependency-on", &[name]);
                }
            }
            _ => {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    if relative {
                        "dangling-relative-symlink"
                    } else {
                        "dangling-symlink"
                    },
                    &[fname, link],
                );
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
            self.report_dangling(pkg, fname, link, false, out);
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

    fn check_link_relative(
        &self,
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
                self.report_dangling(pkg, fname, link, true, out);
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
        if perm & 0o002 != 0 {
            add_info(
                out,
                Level::Error,
                pkg,
                "world-writable",
                &[fname, &format!("{:o}", perm)],
            );
        }
        // non-standard-dir-perm: dirs should be 0755
        if perm != 0o755 && perm != 0o555 {
            add_info(
                out,
                Level::Error,
                pkg,
                "non-standard-dir-perm",
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
        self.check_normal_setuid_bit(pkg, fname, pkgfile, out);
        self.check_normal_libfile(pkg, fname, st);
        self.check_normal_logfile(pkg, fname, pkgfile, &mut fd, out);
        self.check_normal_getdata(pkg, fname, pkgfile, &mut fd, out);
        self.check_normal_doc(pkg, fname, &mut fd, out);
        self.check_normal_non_devel(pkg, fname, st, out);
        self.check_normal_lib(pkg, fname, pkgfile, st, out);
        self.check_normal_depmod_call(pkg, fname, st, out);
        self.check_normal_install_info(pkg, fname, st, out);
        self.check_normal_perl_temp(pkg, fname, out);
        self.check_normal_rpaths_in_buildconfig(pkg, fname, &fd, out);
        self.check_normal_bin(pkg, fname, pkgfile, out);
        self.check_normal_non_readable(pkg, fname, pkgfile, out);
        self.check_normal_zero_length(pkg, fname, pkgfile, out);
        self.check_normal_world_w(pkg, fname, pkgfile, out);
        self.check_normal_perl_dep(pkg, fname, st, out);
        self.check_normal_python_dep(pkg, fname, st, out);
        self.check_normal_python_source(pkg, fname, &fd, out);
        self.check_normal_exec(pkg, fname, pkgfile, &mut fd, out);
        self.check_normal_non_conf_in_etc(pkg, fname, pkgfile, out);
        self.check_normal_python_noarch(pkg, fname, out);
        self.check_normal_gzipped_svg(pkg, fname, out);
        self.check_normal_pem(pkg, fname, out);
        self.check_normal_tcl(pkg, fname, out);
        self.check_normal_text(pkg, fname, pkgfile, &mut fd, out);
        self.check_normal_not_utf8(pkg, fname, pkgfile, &fd, out);
        // library without ldconfig (with #1602 fix: check interpreter too)
        self.check_ldconfig(pkg, fname, pkgfile, st, out);
    }

    fn check_normal_setuid_bit(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        let mode = pkgfile.mode;
        let perm = mode & 0o7777;
        if mode & 0o6000 == 0 {
            return;
        }
        // setuid/setgid
        if mode & 0o4000 != 0 {
            add_info(
                out,
                Level::Error,
                pkg,
                "setuid-binary",
                &[fname, &pkgfile.user, &format!("{:o}", perm)],
            );
        }
        if mode & 0o2000 != 0 {
            add_info(
                out,
                Level::Error,
                pkg,
                "setgid-binary",
                &[fname, &pkgfile.group, &format!("{:o}", perm)],
            );
        }
        if mode & 0o777 != 0o755 {
            add_info(
                out,
                Level::Error,
                pkg,
                "non-standard-executable-perm",
                &[fname, &format!("{:o}", perm)],
            );
        }
    }

    fn check_normal_libfile(&self, pkg: &Pkg, fname: &str, st: &mut PkgState) {
        let is_doc = pkg.doc_files.iter().any(|d| d == fname);
        if !st.devel_pkg {
            if is_match(&self.lib_path_re, fname) {
                st.lib_file = true;
            } else if !is_doc {
                st.non_lib_file = Some(fname.to_string());
            }
        }
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
        if st.devel_pkg && fname.ends_with(".typelib") {
            add_info(
                out,
                Level::Error,
                pkg,
                "non-devel-file-in-devel-package",
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
        if is_match(&self.lib_re, fname)
            && st.devel_pkg
            && !(is_match(&self.sofile_re, fname) && pkgfile::is_symlink(pkgfile.mode))
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

    fn check_normal_depmod_call(&self, pkg: &Pkg, fname: &str, st: &PkgState, out: &mut Filter) {
        let caps = match self.depmod_kernel_re.captures(fname) {
            Ok(Some(c)) if !st.is_kernel_package => c,
            _ => return,
        };
        let kernel_version = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if st.postin.is_empty() || !is_match(&self.depmod_re, &st.postin) {
            add_info(
                out,
                Level::Error,
                pkg,
                "module-without-depmod-postin",
                &[fname],
            );
        } else if !depmod_call_for_kernel(&st.postin, kernel_version) {
            add_info(out, Level::Error, pkg, "postin-with-wrong-depmod", &[fname]);
        }
        if st.postun.is_empty() || !is_match(&self.depmod_re, &st.postun) {
            add_info(
                out,
                Level::Error,
                pkg,
                "module-without-depmod-postun",
                &[fname],
            );
        } else if !depmod_call_for_kernel(&st.postun, kernel_version) {
            add_info(out, Level::Error, pkg, "postun-with-wrong-depmod", &[fname]);
        }
    }

    fn check_normal_install_info(&self, pkg: &Pkg, fname: &str, st: &PkgState, out: &mut Filter) {
        // check install-info call in %post and %postun
        if !fname.starts_with("/usr/share/info/") {
            return;
        }
        if !st.postin.is_empty() && !is_match(&self.install_info_re, &st.postin) {
            add_info(
                out,
                Level::Error,
                pkg,
                "postin-without-install-info",
                &[fname],
            );
        }
        let postun_ok = !st.postun.is_empty() && is_match(&self.install_info_re, &st.postun);
        let preun_ok = !st.preun.is_empty() && is_match(&self.install_info_re, &st.preun);
        // NB: the reference checks postun/preun here yet still reports
        // 'postin-without-install-info'.
        if !postun_ok && !preun_ok && (!st.postun.is_empty() || !st.preun.is_empty()) {
            add_info(
                out,
                Level::Error,
                pkg,
                "postin-without-install-info",
                &[fname],
            );
        }
    }

    fn check_normal_perl_temp(&self, pkg: &Pkg, fname: &str, out: &mut Filter) {
        if is_match(&self.perl_temp_file_re, fname) {
            add_info(out, Level::Warning, pkg, "perl-temp-file", &[fname]);
        }
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

    fn check_normal_bin(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        if is_match(&self.bin_re, fname) && pkgfile.mode & 0o111 == 0 {
            add_info(
                out,
                Level::Warning,
                pkg,
                "non-executable-in-bin",
                &[fname, &format!("{:o}", pkgfile.mode & 0o7777)],
            );
        }
    }

    fn check_normal_non_readable(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        out: &mut Filter,
    ) {
        let perm = pkgfile.mode & 0o7777;
        // non-readable (#1291: skip ghost files)
        if perm & 0o444 == 0 && !pkgfile.is_ghost() {
            add_info(
                out,
                Level::Error,
                pkg,
                "non-readable",
                &[fname, &format!("{:o}", perm)],
            );
        }
    }

    fn check_normal_zero_length(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        out: &mut Filter,
    ) {
        // zero-length: the reference exempts __init__.py, py.typed, etc.
        // via normal_zero_length_regex, and skips ghost files.
        if pkgfile.size == Some(0)
            && !is_match(&self.normal_zero_length_re, fname)
            && !pkg.ghost_files.iter().any(|g| g == fname)
        {
            add_info(out, Level::Error, pkg, "zero-length", &[fname]);
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

    fn check_normal_perl_dep(&self, pkg: &Pkg, fname: &str, st: &mut PkgState, out: &mut Filter) {
        if st.perl_dep_error {
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
        let compat = format!("perl(:MODULE_COMPAT_{vers})");
        let has_compat = pkg
            .requires
            .iter()
            .chain(&pkg.recommends)
            .chain(&pkg.suggests)
            .any(|d| d.name == compat);
        if !(check_versioned_dep(pkg, "perl-base", &vers)
            || check_versioned_dep(pkg, "perl", &vers)
            || has_compat)
        {
            add_info(
                out,
                Level::Error,
                pkg,
                "no-dependency-on",
                &["perl-base", &vers],
            );
            st.perl_dep_error = true;
        }
    }

    fn check_normal_python_dep(&self, pkg: &Pkg, fname: &str, st: &mut PkgState, out: &mut Filter) {
        if st.python_dep_error {
            return;
        }
        let caps = match self.python_re.captures(fname) {
            Ok(Some(c)) => c,
            _ => return,
        };
        let ver = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if !["python", "python-base", "python(abi)"]
            .iter()
            .any(|dep| check_versioned_dep(pkg, dep, ver))
        {
            add_info(
                out,
                Level::Error,
                pkg,
                "no-dependency-on",
                &["python-base", ver],
            );
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
        let perm = mode & 0o7777;
        let mode_is_exec = mode & 0o111 != 0;
        if mode & 0o100 != 0 && perm != 0o755 {
            add_info(
                out,
                Level::Error,
                pkg,
                "non-standard-executable-perm",
                &[fname, &format!("{:o}", perm)],
            );
        }
        if mode_is_exec {
            if pkg.config_files.iter().any(|c| c == fname) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "executable-marked-as-config-file",
                    &[fname],
                );
            }
            if !fd.nonexec_file {
                // doc_regex and log_regex checked earlier, no match,
                // check rest of usual cases here.  Sourced scripts have
                // their own check, so disregard them here.
                fd.nonexec_file = fname.ends_with(".pc")
                    || is_match(&self.compr_re, fname)
                    || is_match(&self.includefile_re, fname)
                    || is_match(&self.develfile_re, fname)
                    || fname.starts_with("/etc/logrotate.d/");
            }
            if fd.nonexec_file {
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

    fn check_normal_non_conf_in_etc(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        out: &mut Filter,
    ) {
        // non-conffile in /etc
        if fname.starts_with("/etc/") && !pkgfile.is_config() && !pkgfile.is_ghost() {
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
                            add_info(
                                out,
                                Level::Error,
                                pkg,
                                "env-script-interpreter",
                                &[fname, &interpreter, &fd.interpreter_args],
                            );
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
            if !mode_is_exec && !is_doc {
                if let Some(interpreter) = &fd.interpreter {
                    if interpreter.starts_with('/') {
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
            if fd.chunk.contains(&b'\r') {
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
            // We check only doc text files for UTF-8-ness;
            // checking everything may be slow and can generate
            // lots of unwanted noise.
            if !self.is_utf8_file(fname, &pkgfile.path) {
                add_info(out, Level::Warning, pkg, "file-not-utf8", &[fname]);
            }
        }
        let text = String::from_utf8_lossy(&fd.chunk);
        if is_match(&self.fsf_license_re, text.as_ref())
            && is_match(&self.fsf_wrong_address_re, text.as_ref())
        {
            add_info(out, Level::Error, pkg, "incorrect-fsf-address", &[fname]);
        }
    }

    fn check_normal_not_utf8(
        &self,
        pkg: &Pkg,
        fname: &str,
        pkgfile: &PkgFile,
        fd: &FileData,
        out: &mut Filter,
    ) {
        let is_doc = pkg.doc_files.iter().any(|d| d == fname);
        if !fd.istext && is_doc && !fd.chunk.is_empty() && is_match(&self.compr_re, fname) {
            // compressed docs, eg. info and man files etc
            let base = self.compr_re.replace(fname, "").to_string();
            if !is_match(&self.skipdocs_re, &base) && !self.is_utf8_file(fname, &pkgfile.path) {
                add_info(out, Level::Warning, pkg, "file-not-utf8", &[fname]);
            }
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
            let postin_prog = pkg.scriptprog(librpm::Tag::POSTINPROG);
            let postun_prog = pkg.scriptprog(librpm::Tag::POSTUNPROG);
            if !is_ldconfig(&st.postin, &postin_prog) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "library-without-ldconfig-postin",
                    &[fname],
                );
                add_info(out, Level::Error, pkg, "postin-without-ldconfig", &[fname]);
            }
            if !is_ldconfig(&st.postun, &postun_prog) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "library-without-ldconfig-postun",
                    &[fname],
                );
                add_info(out, Level::Error, pkg, "postun-without-ldconfig", &[fname]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;
    use crate::pkg::pkgfile::RPMFILE_GHOST;

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

    fn run_files_check(rpm: &str, config: &Config) -> (Vec<String>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = Pkg::open(std::path::Path::new(rpm), dir.path(), true).expect("open fixture");
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(config);
        check.check(&pkg, config, &mut out);
        let names: Vec<String> = out.results().iter().map(|(n, _)| n.clone()).collect();
        (names, dir)
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
        assert_has(&names, "non-standard-executable-perm");
        // documentation and encoding
        assert_has(&names, "wrong-file-end-of-line-encoding");
        assert_has(&names, "file-not-utf8");
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
        assert_has(&names, "perl-temp-file");
        assert_has(&names, "python-bytecode-without-source");
        assert_has(&names, "rpath-in-buildconfig");
        assert_has(&names, "gzipped-svg-icon");
        assert_has(&names, "noarch-python-in-64bit-path");
        assert_has(&names, "standard-dir-owned-by-package");
        assert_has(&names, "dir-or-file-in-opt");
        // no read errors: extraction works
        assert_lacks(&names, "read-error");
    }

    #[test]
    fn files_check_devel_non_devel_file() {
        let config = test_config();
        let (names, _dir) =
            run_files_check(&fixture_path("filescheck-devel-1.0-1.noarch.rpm"), &config);
        assert_has(&names, "non-devel-file-in-devel-package");
    }

    #[test]
    fn lib_package_without_docs_skips_no_documentation() {
        // The shared lib_package_regex must match "libnodoc-test": with the
        // broken double-escaped form it never matched, so no-documentation
        // fired on every lib package (a false positive the reference does
        // not emit). Restoring the broken regex makes this fail.
        let config = test_config();
        let (names, _dir) =
            run_files_check(&fixture_path("libnodoc-test-1.0-1.noarch.rpm"), &config);
        assert_lacks(&names, "no-documentation");
    }

    #[test]
    fn lib_package_with_non_lib_file_emits_outside_libdir_files() {
        // The shared lib_package_regex must match "liboutsidelib-test": with
        // the broken double-escaped form st.lib_package was always false, so
        // outside-libdir-files could never fire. Restoring the broken regex
        // makes this fail.
        let config = test_config();
        let (names, _dir) = run_files_check(
            &fixture_path("liboutsidelib-test-1.0-1.noarch.rpm"),
            &config,
        );
        assert_has(&names, "outside-libdir-files");
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
    fn files_check_depmod_variants() {
        let config = test_config();
        let (ok_names, _d1) = run_files_check(
            &fixture_path("filescheck-depmod-ok-1.0-1.noarch.rpm"),
            &config,
        );
        assert_lacks(&ok_names, "module-without-depmod-postin");
        assert_lacks(&ok_names, "module-without-depmod-postun");
        assert_lacks(&ok_names, "postin-with-wrong-depmod");
        assert_lacks(&ok_names, "postun-with-wrong-depmod");

        let (wrong_names, _d2) = run_files_check(
            &fixture_path("filescheck-depmod-wrong-1.0-1.noarch.rpm"),
            &config,
        );
        assert_has(&wrong_names, "postin-with-wrong-depmod");
        assert_has(&wrong_names, "postun-with-wrong-depmod");

        let (missing_names, _d3) = run_files_check(
            &fixture_path("filescheck-depmod-missing-1.0-1.noarch.rpm"),
            &config,
        );
        assert_has(&missing_names, "module-without-depmod-postin");
        assert_has(&missing_names, "module-without-depmod-postun");
    }

    #[test]
    fn files_check_install_info_variants() {
        let config = test_config();
        let (ok_names, _d1) = run_files_check(
            &fixture_path("filescheck-installinfo-ok-1.0-1.noarch.rpm"),
            &config,
        );
        assert_lacks(&ok_names, "postin-without-install-info");

        let (postin_names, _d2) = run_files_check(
            &fixture_path("filescheck-installinfo-postin-1.0-1.noarch.rpm"),
            &config,
        );
        assert_has(&postin_names, "postin-without-install-info");

        let (postun_names, _d3) = run_files_check(
            &fixture_path("filescheck-installinfo-postun-1.0-1.noarch.rpm"),
            &config,
        );
        // NB: the reference reports postin-without-install-info for the
        // postun case too.
        assert_has(&postun_names, "postin-without-install-info");
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
    fn bindir_exes_emit_in_package_file_order() {
        let render = || {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let pkg = Pkg::open(
                std::path::Path::new(&fixture_path("filescheck-depmod-ok-1.0-1.noarch.rpm")),
                dir.path(),
                true,
            )
            .expect("open fixture");
            let config = Config::default();
            let check = FilesCheck::new(&config);
            let mut st = PkgState::default();
            for exe in ["link-alt", "link-up", "link-script", "link-abs"] {
                st.bindir_exes.entry(exe.to_string()).or_default();
            }
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_bindir_exes(&pkg, &st, &mut out);
            out.results()
                .iter()
                .map(|(_, line)| line.clone())
                .collect::<Vec<_>>()
        };
        // Two maps built independently in one process draw different hash seeds,
        // so a HashMap here renders a different order and this fails.
        assert_eq!(render(), render());
    }

    #[test]
    fn bindir_exes_emit_in_the_order_files_were_added() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = Pkg::open(
            std::path::Path::new(&fixture_path("filescheck-depmod-ok-1.0-1.noarch.rpm")),
            dir.path(),
            true,
        )
        .expect("open fixture");
        let config = Config::default();
        let check = FilesCheck::new(&config);
        let mut st = PkgState::default();
        for exe in ["zzz", "aaa", "mmm"] {
            st.bindir_exes.entry(exe.to_string()).or_default();
        }
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_bindir_exes(&pkg, &st, &mut out);
        let lines: Vec<String> = out.results().iter().map(|(_, l)| l.clone()).collect();
        let tail = |line: &String| line.rsplit(' ').next().unwrap().to_string();
        assert_eq!(
            lines.iter().map(tail).collect::<Vec<_>>(),
            vec!["zzz", "aaa", "mmm"],
            "insertion order, not sorted order"
        );
        assert!(
            lines
                .iter()
                .all(|l| l.contains("no-manual-page-for-binary"))
        );
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
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
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
    fn zero_length_exempts_init_py_and_ghosts() {
        // Benchmark found: zero-length __init__.py files were flagged, and
        // ghost files were not skipped. The reference exempts both.
        let config = test_config();
        let rpm = fixture_path("fcprobe-1-1.noarch.rpm");
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture");
        pkg.files = vec![
            PkgFile {
                name: "/usr/lib/python3.12/site-packages/foo/__init__.py".to_string(),
                path: "/usr/lib/python3.12/site-packages/foo/__init__.py".to_string(),
                mode: 0o100644,
                size: Some(0),
                ..Default::default()
            },
            PkgFile {
                name: "/usr/bin/empty-script".to_string(),
                path: "/usr/bin/empty-script".to_string(),
                mode: 0o100755,
                size: Some(0),
                ..Default::default()
            },
            PkgFile {
                name: "/var/log/ghost.log".to_string(),
                path: "/var/log/ghost.log".to_string(),
                mode: 0o100644,
                size: Some(0),
                flags: RPMFILE_GHOST,
                ..Default::default()
            },
        ];
        pkg.ghost_files = vec!["/var/log/ghost.log".to_string()];
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
                .any(|(n, d)| n == "zero-length" && d.contains("__init__.py")),
            "false positive on __init__.py: {results:?}"
        );
        assert!(
            !results
                .iter()
                .any(|(n, d)| n == "zero-length" && d.contains("ghost.log")),
            "false positive on ghost: {results:?}"
        );
        assert!(
            results.iter().any(|(n, d)| n == "zero-length"
                && d.contains(": E: zero-length")
                && d.contains("empty-script")),
            "missing E-level zero-length on empty-script: {results:?}"
        );
    }

    /// An absent decompressor must not turn a compressed file into
    /// `file-not-utf8`. The reference decompresses in-process (pkg.py imports
    /// bz2/gzip/lzma/zstandard), so it never needs a binary and always reaches
    /// the real bytes. Reading the still-compressed file instead flagged every
    /// `.gz` man page on a host without gzip -- a regression against main, which
    /// returned true.
    #[test]
    fn absent_decompressor_reads_as_utf8() {
        let empty = tempfile::TempDir::new().expect("tmpdir");
        let config = Config::default();
        let check = FilesCheck::with_tool_dir(&config, Some(empty.path()));
        let doc = empty.path().join("page.gz");
        std::fs::write(&doc, [0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe, 0xfd]).expect("write");
        assert!(
            check.is_utf8_file(&doc.to_string_lossy(), &doc.to_string_lossy()),
            "a compressed file with no decompressor must read as UTF-8"
        );
    }
}
