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

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::{self, PkgFile};

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

fn devel_regex() -> Regex {
    Regex::new(r"(.*)-(debug(info|source)?|devel|headers|source|static|prof)$")
        .expect("static regex")
}

fn lib_package_regex() -> Regex {
    Regex::new(r"(?i)(?:^(?:compat-)?lib.*?(\\.so.*)?|libs?[\\d-]*)$").expect("static regex")
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

fn macro_regex() -> Regex {
    Regex::new(r"%+[{(]?[a-zA-Z_]\\w{2,}[)}]?").expect("static regex")
}

fn quotes_regex() -> Regex {
    Regex::new(r#"['"]"#).expect("static regex")
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
    use_debugsource: bool,
    module_rpms_ok: bool,
    use_relative_symlinks: bool,
    compress_ext: String,
    standard_users: Vec<String>,
    standard_groups: Vec<String>,
    disallowed_dirs: Vec<String>,
    dangling_exceptions: Vec<Regex>,
    ldconfig_re: Regex,
}

impl FilesCheck {
    pub fn new(config: &Config) -> Self {
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
                    .filter_map(|v| v.get("path").and_then(toml::Value::as_str))
                    .filter_map(|p| Regex::new(p).ok())
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
            use_debugsource: get_bool("UseDebugSource"),
            module_rpms_ok: get_bool("KernelModuleRPMsOK"),
            use_relative_symlinks: get_bool("UseRelativeSymlinks"),
            compress_ext: get_str("CompressExtension"),
            standard_users: get_strings("StandardUsers"),
            standard_groups: get_strings("StandardGroups"),
            disallowed_dirs: get_strings("DisallowedDirs"),
            dangling_exceptions: dangling,
            ldconfig_re: Regex::new(r"(?m)^[^#]*ldconfig").expect("static regex"),
        }
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
    hardlinks: HashMap<(u32, u32), Vec<String>>,
    bindir_exes: HashMap<String, Vec<String>>,
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
        st.devel_pkg = self.devel_re.is_match(&pkg.name).unwrap_or(false);
        if !st.devel_pkg {
            for p in &pkg.provides {
                if self.devel_re.is_match(&p.name).unwrap_or(false) {
                    st.devel_pkg = true;
                    break;
                }
            }
        }
        st.lib_package = self.lib_package_re.is_match(&pkg.name).unwrap_or(false);
        st.is_kernel_package = self.kernel_package_re.is_match(&pkg.name).unwrap_or(false);
        st.debuginfo_package = self
            .debuginfo_package_re
            .is_match(&pkg.name)
            .unwrap_or(false);
        st.debugsource_package = self
            .debugsource_package_re
            .is_match(&pkg.name)
            .unwrap_or(false);
        st.postin = strip_quotes(
            &self.quotes_re,
            &pkg.tag_str(librpm::Tag::POSTIN).unwrap_or_default(),
        );
        st.postun = strip_quotes(
            &self.quotes_re,
            &pkg.tag_str(librpm::Tag::POSTUN).unwrap_or_default(),
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
        if !pkg.files.is_empty() && self.meta_package_re.is_match(&pkg.name).unwrap_or(false) {
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
        if self.log_re.is_match(fname).unwrap_or(false) {
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
            && self.info_re.is_match(fname).unwrap_or(false)
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
        if !self.module_rpms_ok
            && self.kernel_modules_re.is_match(fname).unwrap_or(false)
            && !is_kernel
        {
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
        // dangling symlink check
        let is_absolute = link.starts_with('/');
        if !is_absolute {
            // relative link: resolve against parent
            if let Some(parent) = Path::new(fname).parent() {
                let abslink = parent.join(link);
                let norm = abslink.to_string_lossy().replace("/./", "/");
                if !pkg.files.iter().any(|f| f.name == norm) {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "dangling-relative-symlink",
                        &[fname, link],
                    );
                }
            }
        } else if !pkg.files.iter().any(|f| f.name == *link) {
            let mut is_exception = false;
            for e in &self.dangling_exceptions {
                if e.is_match(link).unwrap_or(false) {
                    is_exception = true;
                    break;
                }
            }
            if !is_exception {
                add_info(out, Level::Warning, pkg, "dangling-symlink", &[fname, link]);
            }
        }
        // symlink should be relative/absolute
        if is_absolute && self.use_relative_symlinks {
            add_info(
                out,
                Level::Warning,
                pkg,
                "symlink-should-be-relative",
                &[fname, link],
            );
        }
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
        let perm = pkgfile.mode & 0o7777;
        // setuid/setgid
        if perm & 0o4000 != 0 {
            add_info(
                out,
                Level::Error,
                pkg,
                "setuid-binary",
                &[fname, &pkgfile.user, &format!("{:o}", perm)],
            );
        }
        if perm & 0o2000 != 0 {
            add_info(
                out,
                Level::Error,
                pkg,
                "setgid-binary",
                &[fname, &pkgfile.group, &format!("{:o}", perm)],
            );
        }
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
        // zero-length
        if pkgfile.size == Some(0) {
            add_info(out, Level::Error, pkg, "zero-length", &[fname]);
        }
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
        // executable marked as config
        if perm & 0o111 != 0 && pkgfile.is_config() {
            add_info(
                out,
                Level::Error,
                pkg,
                "executable-marked-as-config-file",
                &[fname],
            );
        }
        // non-conffile in /etc
        if fname.starts_with("/etc/") && !pkgfile.is_config() && !pkgfile.is_ghost() {
            add_info(out, Level::Warning, pkg, "non-conffile-in-etc", &[fname]);
        }
        // library without ldconfig (with #1602 fix: check interpreter too)
        self.check_ldconfig(pkg, fname, pkgfile, st, out);
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
            self.ldconfig_re.is_match(script).unwrap_or(false)
                || prog
                    .split_whitespace()
                    .next()
                    .map(|p| p.rsplit('/').next().unwrap_or("") == "ldconfig")
                    .unwrap_or(false)
        };
        if fname.contains(".so") {
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

    fn test_config() -> Config {
        Config::default()
    }

    #[test]
    fn files_check_registers() {
        let _check = FilesCheck::new(&test_config());
    }

    #[test]
    fn ldconfig_p_interpreter_satisfies_check() {
        // #1602: %post -p /sbin/ldconfig with a body that does not call
        // ldconfig must NOT emit postin-without-ldconfig. The fixture RPM has
        // a .so file and scriptlets whose -p interpreter is /sbin/ldconfig.
        // Reverting to the stub scriptprog (or the reference body-only search)
        // makes this fail.
        let rpm = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/parity/pkg/inputs/ldconfig-test-1.0-1.noarch.rpm"
        );
        let dir = std::env::temp_dir().join("rpmcrab-ldconfig-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let pkg = Pkg::open(std::path::Path::new(rpm), &dir).expect("open fixture");
        assert_eq!(pkg.scriptprog(librpm::Tag::POSTINPROG), "/sbin/ldconfig");

        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            !names.contains(&"postin-without-ldconfig"),
            "unexpected postin-without-ldconfig: {names:?}"
        );
        assert!(
            !names.contains(&"postun-without-ldconfig"),
            "unexpected postun-without-ldconfig: {names:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ldconfig_regex_skips_comments() {
        // The reference uses ^[^#]*ldconfig: a %post mentioning ldconfig only
        // in a comment must NOT satisfy the check.
        let check = FilesCheck::new(&test_config());
        assert!(check.ldconfig_re.is_match("ldconfig").unwrap_or(false));
        assert!(
            check
                .ldconfig_re
                .is_match("echo hi\nldconfig")
                .unwrap_or(false)
        );
        assert!(
            !check
                .ldconfig_re
                .is_match("# run ldconfig later")
                .unwrap_or(true)
        );
        assert!(!check.ldconfig_re.is_match("   # ldconfig").unwrap_or(true));
    }
}
