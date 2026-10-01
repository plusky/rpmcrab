//! `SUIDPermissionsCheck` — restrict setuid/setgid bits and capabilities.
//!
//! Ported from `rpmlint/checks/SUIDPermissionsCheck.py` (221 lines) plus the
//! profile parser in `rpmlint/permissions.py`. Findings:
//! `permissions-directory-setuid-bit`, `permissions-file-setuid-bit`,
//! `permissions-dir-without-slash`, `permissions-file-as-dir`,
//! `permissions-incorrect`, `permissions-fscaps`, `permissions-incorrect-owner`,
//! `permissions-missing-postin`, `permissions-missing-verifyscript`,
//! `permissions-symlink`, `permissions-missing-requires`, `permissions-parse-error`.
//!
//! Parses the permissions profiles (`/usr/share/permissions/permissions`,
//! `permissions.secure`, and per-package `permissions.d/` drop-ins) natively.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use fancy_regex::Regex;
use librpm::Tag;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::{PkgFile, is_dir, is_symlink};

const SHARE_DIR: &str = "/usr/share/permissions";

/// One entry from a permissions profile.
#[derive(Debug, Clone)]
struct PermissionsEntry {
    profile: String,
    path: String,
    owner: String,
    group: String,
    mode: u32,
    packages: Vec<String>,
}

impl PermissionsEntry {
    fn matches_pkg(&self, pkg_name: &str) -> bool {
        self.packages.is_empty() || self.packages.iter().any(|p| p == pkg_name)
    }

    fn is_static(&self) -> bool {
        self.profile.ends_with("/permissions")
    }
}

/// Handles `%{VAR}` expansions from `variables.conf`.
struct VariablesHandler {
    variables: HashMap<String, Vec<String>>,
}

impl VariablesHandler {
    fn new(path: &str) -> Self {
        let mut variables = HashMap::new();
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((name, values)) = line.split_once('=') {
                    let name = name.trim().to_string();
                    let values: Vec<String> = values
                        .split_whitespace()
                        .map(|v| v.trim_matches('/').to_string())
                        .collect();
                    variables.insert(name, values);
                }
            }
        }
        Self { variables }
    }

    /// Expand `%{VAR}` components in `path`, returning all expansions.
    fn expand_paths(&self, path: &str) -> Vec<String> {
        let mut ret = vec![String::new()];
        for part in path.split('/') {
            if part.starts_with("%{") && part.ends_with('}') {
                let var = &part[2..part.len() - 1];
                if let Some(expansions) = self.variables.get(var) {
                    let mut new_ret = Vec::new();
                    for p in &ret {
                        for value in expansions {
                            if p.is_empty() {
                                new_ret.push(format!("/{value}"));
                            } else {
                                new_ret.push(format!("{p}/{value}"));
                            }
                        }
                    }
                    ret = new_ret;
                }
            } else if part.is_empty() {
                continue;
            } else {
                ret = ret
                    .into_iter()
                    .map(|p| {
                        if p.is_empty() {
                            format!("/{part}")
                        } else {
                            format!("{p}/{part}")
                        }
                    })
                    .collect();
            }
        }
        if path.ends_with('/') {
            ret = ret.into_iter().map(|p| format!("{p}/")).collect();
        }
        ret
    }
}

/// Parse a permissions profile file.
fn parse_profile(
    var_handler: &VariablesHandler,
    profile_path: &str,
) -> Result<HashMap<String, Vec<PermissionsEntry>>, String> {
    let mut entries: HashMap<String, Vec<PermissionsEntry>> = HashMap::new();
    let mut active_packages: Vec<String> = Vec::new();

    let content = fs::read_to_string(profile_path).map_err(|e| format!("{profile_path}: {e}"))?;

    for (nr, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let nr = nr + 1;

        if line.starts_with('/') || line.starts_with('%') {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() != 3 {
                return Err(format!("{profile_path}:{nr}: expected 3 fields"));
            }
            let path = parts[0].to_string();
            let ownership = parts[1].replace('.', ":");
            let (owner, group) = ownership
                .split_once(':')
                .ok_or_else(|| format!("{profile_path}:{nr}: bad ownership"))?;
            let mode = u32::from_str_radix(parts[2], 8)
                .map_err(|_| format!("{profile_path}:{nr}: bad mode"))?;

            let entry = PermissionsEntry {
                profile: profile_path.to_string(),
                path: path.clone(),
                owner: owner.to_string(),
                group: group.to_string(),
                mode,
                packages: active_packages.clone(),
            };

            for expanded in var_handler.expand_paths(&path) {
                let mut e = entry.clone();
                e.path = expanded.clone();
                let key = expanded.trim_end_matches('/').to_string();
                let key = if key.is_empty() { "/".to_string() } else { key };
                entries.entry(key).or_default().push(e);
            }
        } else if line.starts_with("+capabilities") {
            // Capability lines attach to the preceding entries; we track them
            // but the check rejects packaged capabilities outright.
            continue;
        } else if line.starts_with(":package:") {
            let line = line.split('#').next().unwrap_or("");
            if let Some(rest) = line.strip_prefix(":package:") {
                active_packages = rest.split(',').map(|s| s.trim().to_string()).collect();
            }
        } else if line.starts_with('+') {
            return Err(format!("{profile_path}:{nr}: unexpected +line"));
        } else {
            return Err(format!("{profile_path}:{nr}: unexpected line"));
        }
    }

    Ok(entries)
}

/// The scriptlet body, falling back to the `-p` interpreter program
/// (rpmlint `pkg[tag] or pkg.scriptprog(prog)`).
fn script_body_or_prog(pkg: &Pkg, tag: Tag, prog: Tag) -> String {
    match pkg.tag_str(tag) {
        Some(body) if !body.is_empty() => body,
        _ => pkg.scriptprog(prog),
    }
}

pub struct SUIDPermissionsCheck {
    perms: HashMap<String, Vec<PermissionsEntry>>,
    var_handler: VariablesHandler,
    /// Profile parse errors from the constructor, reported as
    /// `permissions-parse-error` on the first `check()` (the reference
    /// raises in the constructor; this is the non-fatal equivalent).
    parse_errors: Vec<String>,
}

impl SUIDPermissionsCheck {
    pub fn new(_config: &Config) -> Self {
        let var_handler = VariablesHandler::new(&format!("{SHARE_DIR}/variables.conf"));
        let mut perms: HashMap<String, Vec<PermissionsEntry>> = HashMap::new();
        let mut parse_errors = Vec::new();

        for name in ["permissions", "permissions.secure"] {
            for path in [format!("{SHARE_DIR}/{name}"), format!("/etc/{name}")] {
                if !Path::new(&path).exists() {
                    continue;
                }
                match parse_profile(&var_handler, &path) {
                    Ok(entries) => {
                        for (k, v) in entries {
                            perms.entry(k).or_default().extend(v);
                        }
                    }
                    // The reference propagates the parse error; record it so
                    // `check()` can emit `permissions-parse-error`.
                    Err(e) => parse_errors.push(e),
                }
            }
        }

        Self {
            perms,
            var_handler,
            parse_errors,
        }
    }

    fn is_suid(mode: u32) -> bool {
        mode & (0o4000 | 0o2000) != 0
    }

    /// Check whether `permctl -n {path}` (or `chkstat`) is called in `script`.
    fn lookup_permctl_call(path: &str, script: Option<&str>) -> bool {
        let Some(script) = script else {
            return false;
        };
        // Reference: `re.search(rf"(chkstat|permctl) -n.* {re.escape(path)}", script)`.
        // The missing space before `.*` is load-bearing: fancy-regex 0.19
        // never matches ` .* ` (spaces on both sides of the star).
        let escaped = fancy_regex::escape(path);
        let pattern = format!(r"(chkstat|permctl) -n.* {escaped}");
        let Ok(re) = Regex::new(&pattern) else {
            return false;
        };
        script.lines().any(|line| is_match(&re, line))
    }

    fn is_static_entry(&self, pkg_name: &str, path: &str) -> bool {
        self.perms
            .get(path)
            .map(|entries| {
                entries
                    .iter()
                    .any(|e| e.matches_pkg(pkg_name) && e.is_static())
            })
            .unwrap_or(false)
    }

    /// Complain about disagreements between the package metadata and the
    /// permissions profile settings.
    fn verify_entry(
        &self,
        entry: &PermissionsEntry,
        pkg: &Pkg,
        path: &str,
        pkgfile: &PkgFile,
        out: &mut Filter,
    ) {
        let is_listed_as_dir = entry.path.ends_with('/');
        let is_packaged_as_dir = is_dir(pkgfile.mode);

        if is_packaged_as_dir && !is_listed_as_dir {
            add_info(
                out,
                Level::Warning,
                pkg,
                "permissions-dir-without-slash",
                &[path],
            );
        } else if is_listed_as_dir && !is_packaged_as_dir {
            add_info(
                out,
                Level::Warning,
                pkg,
                "permissions-file-as-dir",
                &[&format!("{path} is a file but listed as directory")],
            );
        }

        if (pkgfile.mode & 0o7777) != entry.mode {
            add_info(
                out,
                Level::Error,
                pkg,
                "permissions-incorrect",
                &[&format!(
                    "{path} has mode 0{:o} but should be 0{:o}",
                    pkgfile.mode & 0o7777,
                    entry.mode
                )],
            );
        }
        // Comparing the capabilities found in RPM metadata against the
        // capabilities configured in the profiles would be too much
        // complexity with little gain: reject packaged capabilities
        // outright, they should only be managed by the permissions package.
        if pkgfile.filecaps.is_some() {
            add_info(
                out,
                Level::Error,
                pkg,
                "permissions-fscaps",
                &[&format!(
                    "{path} has capabilities \"{}\". Capabilities should only be managed by the permissions package.",
                    pkgfile.filecaps.as_deref().unwrap_or("")
                )],
            );
        }
        let entry_owner = format!("{}:{}", entry.owner, entry.group);
        let pkg_owner = format!("{}:{}", pkgfile.user, pkgfile.group);
        if pkg_owner != entry_owner {
            add_info(
                out,
                Level::Error,
                pkg,
                "permissions-incorrect-owner",
                &[&format!(
                    "{path} belongs to {pkg_owner} but should be {entry_owner}"
                )],
            );
        }
    }

    /// Complain about privileged bits with no permissions-profile whitelisting.
    fn complain_restricted_privs(pkg: &Pkg, path: &str, pkgfile: &PkgFile, out: &mut Filter) {
        let diag = if is_dir(pkgfile.mode) {
            "permissions-directory-setuid-bit"
        } else {
            "permissions-file-setuid-bit"
        };
        if let Some(caps) = &pkgfile.filecaps {
            add_info(
                out,
                Level::Error,
                pkg,
                diag,
                &[&format!("{path} is packaged with capabilities ({caps})")],
            );
        }
        if Self::is_suid(pkgfile.mode) {
            add_info(
                out,
                Level::Error,
                pkg,
                diag,
                &[&format!(
                    "{path} is packaged with setuid/setgid bits (0{:o})",
                    pkgfile.mode & 0o7777
                )],
            );
        }
    }

    /// Check whether a call to `permctl -n {path}` is found in the `%post`
    /// and `%verifyscript` scriptlets, complaining when it is not.
    fn check_post_scriptlets(&self, pkg: &Pkg, path: &str, out: &mut Filter) {
        let postin = script_body_or_prog(pkg, Tag::POSTIN, Tag::POSTINPROG);
        let verifyscript = script_body_or_prog(pkg, Tag::VERIFYSCRIPT, Tag::VERIFYSCRIPTPROG);
        let found_postin = Self::lookup_permctl_call(path, Some(&postin));
        let found_verify = Self::lookup_permctl_call(path, Some(&verifyscript));

        if !found_postin {
            add_info(
                out,
                Level::Error,
                pkg,
                "permissions-missing-postin",
                &[&format!("missing %set_permissions {path} in %post")],
            );
        }
        if !found_verify {
            add_info(
                out,
                Level::Warning,
                pkg,
                "permissions-missing-verifyscript",
                &[&format!("missing %verify_permissions -e {path}")],
            );
        }
    }

    /// Parse per-package drop-in profiles (`permissions.d/`, `packages.d/`),
    /// which take priority over the central profiles parsed in `new()`.
    fn parse_dropins(&mut self, pkg: &Pkg, out: &mut Filter) {
        let prefixes = [
            format!("{SHARE_DIR}/permissions.d/"),
            "/etc/permissions.d/".to_string(),
            format!("{SHARE_DIR}/packages.d/"),
        ];
        let mut dropin_files: HashSet<String> = HashSet::new();

        for pkgfile in &pkg.files {
            let name = pkgfile.name.as_str();
            for prefix in &prefixes {
                if !name.starts_with(prefix.as_str()) {
                    continue;
                }
                if pkgfile.is_ghost() {
                    continue;
                }
                let dropin_dir = prefix
                    .trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or("");
                // Basename without suffix; the `.secure` variant is looked
                // up first below.
                let basename = format!(
                    "{dropin_dir}/{}",
                    name[prefix.len()..].split('.').next().unwrap_or("")
                );
                dropin_files.insert(basename);
            }
        }

        for basename in &dropin_files {
            for candidate in [
                format!("{SHARE_DIR}/{basename}.secure"),
                format!("/etc/{basename}.secure"),
                format!("{SHARE_DIR}/{basename}"),
                format!("/etc/{basename}"),
            ] {
                let Some(pkgfile) = pkg.files.iter().find(|f| f.name == candidate) else {
                    continue;
                };
                match parse_profile(&self.var_handler, &pkgfile.path) {
                    Ok(entries) => {
                        // Drop-ins take priority over the central profiles.
                        for (k, v) in entries {
                            self.perms.insert(k, v);
                        }
                    }
                    Err(e) => {
                        add_info(
                            out,
                            Level::Error,
                            pkg,
                            "permissions-parse-error",
                            &[&format!("{} caused a parsing error: {e}.", pkgfile.path)],
                        );
                    }
                }
                break;
            }
        }
    }
}

impl Check for SUIDPermissionsCheck {
    fn name(&self) -> &'static str {
        "SUIDPermissionsCheck"
    }

    fn check(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }

        if !self.parse_errors.is_empty() {
            for e in std::mem::take(&mut self.parse_errors) {
                add_info(out, Level::Error, pkg, "permissions-parse-error", &[&e]);
            }
            return;
        }

        self.parse_dropins(pkg, out);

        // Whether a PreReq for the permissions package is needed in this RPM.
        let mut requires_permctl = false;

        for pkgfile in &pkg.files {
            if pkgfile.is_ghost() {
                // Ghost files are not actually shipped; privileges described
                // by them may come from other mechanisms (e.g. tmpfiles.d).
                continue;
            }
            let path = pkgfile.name.as_str();
            let mode = pkgfile.mode;
            let is_link = is_symlink(mode);
            // Whether we need to check for invocation of permctl in %post or
            // %verifyscript for this path.
            let mut check_scriptlets = false;
            let mut skip_file = false;

            let mut matched = false;
            if let Some(entries) = self.perms.get(path) {
                for entry in entries {
                    if entry.matches_pkg(&pkg.name) {
                        matched = true;
                        if is_link {
                            add_info(out, Level::Warning, pkg, "permissions-symlink", &[path]);
                            skip_file = true;
                        } else {
                            check_scriptlets = true;
                            self.verify_entry(entry, pkg, path, pkgfile, out);
                        }
                        break;
                    }
                }
            }
            if !matched {
                // No matching entry: no whitelisting for any privileged bits.
                let grants_privileges = pkgfile.filecaps.is_some() || Self::is_suid(mode);
                if !is_link && grants_privileges {
                    check_scriptlets = true;
                    Self::complain_restricted_privs(pkg, path, pkgfile, out);
                }
            }

            if skip_file {
                // A symlink we warned about.
                continue;
            }

            if check_scriptlets {
                // Static entries only serve a whitelisting purpose (e.g.
                // directory sticky bits) or a sanity check; their permissions
                // are already correct after RPM install, so no permctl call
                // in %post is needed.
                if !self.is_static_entry(&pkg.name, path) {
                    self.check_post_scriptlets(pkg, path, out);
                    requires_permctl = true;
                }
            }
        }

        if requires_permctl && !pkg.prereq.iter().any(|d| d.name == "permissions") {
            add_info(
                out,
                Level::Error,
                pkg,
                "permissions-missing-requires",
                &["missing 'permissions' in PreReq"],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;
    use crate::pkg::dep::DepInfo;
    use std::io::Write;

    fn test_config() -> Config {
        let mut config = Config::default();
        config.finalize();
        config
    }

    fn fixture_pkg(name: &str) -> Pkg {
        let rpm = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs")
            .join(name);
        let header = librpm::PackageHeader::from_file(
            &rpm,
            Some(&librpm::verify::VerifyOptions::skip_verification()),
        )
        .expect("open fixture header");
        let mut pkg = Pkg::installed(header).expect("build installed package");
        pkg.name = "testpkg".to_string();
        pkg
    }

    fn pkgfile(name: &str, mode: u32) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            mode,
            user: "root".to_string(),
            group: "root".to_string(),
            ..Default::default()
        }
    }

    fn entry(path: &str, mode: u32, profile: &str) -> PermissionsEntry {
        PermissionsEntry {
            profile: profile.to_string(),
            path: path.to_string(),
            owner: "root".to_string(),
            group: "root".to_string(),
            mode,
            packages: Vec::new(),
        }
    }

    /// A check with no central profiles, so tests inject entries directly.
    /// Clears anything `new()` picked up (e.g. on openSUSE hosts) to stay
    /// environment-independent.
    fn check_with(entries: Vec<PermissionsEntry>) -> SUIDPermissionsCheck {
        let mut check = SUIDPermissionsCheck::new(&test_config());
        check.perms.clear();
        for e in entries {
            let key = e.path.trim_end_matches('/').to_string();
            let key = if key.is_empty() { "/".to_string() } else { key };
            check.perms.entry(key).or_default().push(e);
        }
        check
    }

    fn run_check(pkg: &Pkg, check: &mut SUIDPermissionsCheck) -> Vec<(String, String)> {
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check(pkg, &config, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn incorrect_mode_and_owner_reported() {
        let mut pkg = fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.files = vec![pkgfile("/usr/bin/suidbin", 0o1004750)];
        let mut check = check_with(vec![entry(
            "/usr/bin/suidbin",
            0o4755,
            "/usr/share/permissions/permissions.secure",
        )]);
        let results = run_check(&pkg, &mut check);
        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&"permissions-incorrect"),
            "expected permissions-incorrect: {results:?}"
        );
        let line = results
            .iter()
            .find(|(n, _)| *n == "permissions-incorrect")
            .map(|(_, l)| l.as_str())
            .unwrap();
        assert!(
            line.contains("has mode 04750 but should be 04755"),
            "mode detail: {line}"
        );
        // Non-static entry without permctl calls in scriptlets.
        assert!(names.contains(&"permissions-missing-postin"), "{results:?}");
        assert!(
            names.contains(&"permissions-missing-verifyscript"),
            "{results:?}"
        );
        assert!(
            names.contains(&"permissions-missing-requires"),
            "{results:?}"
        );
    }

    #[test]
    fn static_entry_skips_scriptlet_checks() {
        let mut pkg = fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.files = vec![pkgfile("/usr/bin/staticbin", 0o1004755)];
        let mut check = check_with(vec![entry(
            "/usr/bin/staticbin",
            0o4755,
            "/usr/share/permissions/permissions",
        )]);
        let results = run_check(&pkg, &mut check);
        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            !names.contains(&"permissions-missing-postin"),
            "static entries need no permctl: {results:?}"
        );
        assert!(
            !names.contains(&"permissions-missing-requires"),
            "static entries need no prereq: {results:?}"
        );
    }

    #[test]
    fn symlink_with_entry_warns_and_skips() {
        let mut pkg = fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.files = vec![pkgfile("/usr/bin/linkbin", 0o120777)];
        let mut check = check_with(vec![entry(
            "/usr/bin/linkbin",
            0o4755,
            "/usr/share/permissions/permissions.secure",
        )]);
        let results = run_check(&pkg, &mut check);
        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names
                .iter()
                .filter(|&&n| n == "permissions-symlink")
                .count(),
            1,
            "exactly one permissions-symlink: {results:?}"
        );
        let line = results
            .iter()
            .find(|(n, _)| *n == "permissions-symlink")
            .map(|(_, l)| l.as_str())
            .unwrap();
        assert!(
            line.starts_with("testpkg.noarch: W: permissions-symlink /usr/bin/linkbin"),
            "warning level: {line}"
        );
        assert!(
            !names.contains(&"permissions-incorrect"),
            "symlink must not be verified: {results:?}"
        );
    }

    #[test]
    fn dir_without_slash_and_file_as_dir() {
        let mut pkg = fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.files = vec![
            pkgfile("/srv/listed-file", 0o040755),
            pkgfile("/srv/listed-dir", 0o100644),
        ];
        let mut check = check_with(vec![
            entry(
                "/srv/listed-file",
                0o755,
                "/usr/share/permissions/permissions.secure",
            ),
            entry(
                "/srv/listed-dir/",
                0o644,
                "/usr/share/permissions/permissions.secure",
            ),
        ]);
        let results = run_check(&pkg, &mut check);
        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&"permissions-dir-without-slash"),
            "{results:?}"
        );
        assert!(names.contains(&"permissions-file-as-dir"), "{results:?}");
        for (n, l) in &results {
            if n == "permissions-dir-without-slash" || n == "permissions-file-as-dir" {
                assert!(l.contains("W:"), "warning level: {l}");
            }
        }
    }

    #[test]
    fn unlisted_setuid_bits_reported() {
        let mut pkg = fixture_pkg("fcprobe-1-1.noarch.rpm");
        let mut suid = pkgfile("/usr/bin/rogue", 0o1004755);
        suid.filecaps = Some("cap_net_raw+ep".to_string());
        pkg.files = vec![suid, pkgfile("/usr/bin/plain", 0o100755)];
        let mut check = check_with(vec![]);
        let results = run_check(&pkg, &mut check);
        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        // One for the capabilities, one for the setuid bit.
        assert_eq!(
            names
                .iter()
                .filter(|&&n| n == "permissions-file-setuid-bit")
                .count(),
            2,
            "{results:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("/usr/bin/plain")),
            "plain file must not appear: {results:?}"
        );
    }

    #[test]
    fn missing_requires_only_when_absent() {
        let mut pkg = fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.files = vec![pkgfile("/usr/bin/suidbin", 0o1004755)];
        pkg.prereq = vec![DepInfo {
            name: "permissions".to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        }];
        let mut check = check_with(vec![entry(
            "/usr/bin/suidbin",
            0o4755,
            "/usr/share/permissions/permissions.secure",
        )]);
        let results = run_check(&pkg, &mut check);
        assert!(
            !results
                .iter()
                .any(|(n, _)| *n == "permissions-missing-requires"),
            "prereq present: {results:?}"
        );

        pkg.prereq = Vec::new();
        let mut check = check_with(vec![entry(
            "/usr/bin/suidbin",
            0o4755,
            "/usr/share/permissions/permissions.secure",
        )]);
        let results = run_check(&pkg, &mut check);
        assert!(
            results
                .iter()
                .any(|(n, _)| *n == "permissions-missing-requires"),
            "prereq absent: {results:?}"
        );
    }

    #[test]
    fn dropin_profile_takes_priority() {
        let dir = std::env::temp_dir().join("rpmcrab-suid-dropin");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let profile = dir.join("mypkg");
        let mut f = std::fs::File::create(&profile).expect("create profile");
        writeln!(f, "/usr/bin/dropbin root:root 4750").expect("write profile");
        // A broken drop-in for the parse-error case.
        let bad = dir.join("badpkg");
        let mut f = std::fs::File::create(&bad).expect("create bad profile");
        writeln!(f, "this is not a valid profile line at all").expect("write");

        let mut pkg = fixture_pkg("fcprobe-1-1.noarch.rpm");
        let mut dropin = pkgfile("/usr/share/permissions/permissions.d/mypkg", 0o100644);
        dropin.path = profile.to_string_lossy().into_owned();
        let mut bad_dropin = pkgfile("/usr/share/permissions/permissions.d/badpkg", 0o100644);
        bad_dropin.path = bad.to_string_lossy().into_owned();
        // Matches the drop-in's mode, proving the drop-in was parsed: without
        // it there would be no entry and `permissions-file-setuid-bit`.
        let target = pkgfile("/usr/bin/dropbin", 0o1004750);
        pkg.files = vec![dropin, bad_dropin, target];

        let mut check = check_with(vec![]);
        let results = run_check(&pkg, &mut check);
        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            !names.contains(&"permissions-incorrect"),
            "drop-in mode must apply: {results:?}"
        );
        assert!(
            !names.contains(&"permissions-file-setuid-bit"),
            "drop-in whitelists the setuid bit: {results:?}"
        );
        assert!(
            names.contains(&"permissions-parse-error"),
            "broken drop-in must error: {results:?}"
        );
        let line = results
            .iter()
            .find(|(n, _)| *n == "permissions-parse-error")
            .map(|(_, l)| l.as_str())
            .unwrap();
        assert!(
            line.contains("caused a parsing error:"),
            "parse-error detail: {line}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn permctl_call_found() {
        let script = "#!/bin/sh\npermctl -n /usr/bin/foo\n";
        assert!(SUIDPermissionsCheck::lookup_permctl_call(
            "/usr/bin/foo",
            Some(script)
        ));
        assert!(!SUIDPermissionsCheck::lookup_permctl_call(
            "/usr/bin/bar",
            Some(script)
        ));
        // chkstat variant from the reference regex.
        assert!(SUIDPermissionsCheck::lookup_permctl_call(
            "/usr/bin/foo",
            Some("chkstat -n /usr/bin/foo --system\n")
        ));
        assert!(!SUIDPermissionsCheck::lookup_permctl_call(
            "/usr/bin/foo",
            None
        ));
    }

    #[test]
    fn is_suid_detects() {
        assert!(SUIDPermissionsCheck::is_suid(0o4755));
        assert!(SUIDPermissionsCheck::is_suid(0o2755));
        assert!(!SUIDPermissionsCheck::is_suid(0o0755));
    }

    #[test]
    fn variables_expand() {
        let handler = VariablesHandler {
            variables: [(
                "BIN".to_string(),
                vec!["bin".to_string(), "sbin".to_string()],
            )]
            .into_iter()
            .collect(),
        };
        let expanded = handler.expand_paths("/usr/%{BIN}/foo");
        assert!(expanded.contains(&"/usr/bin/foo".to_string()));
        assert!(expanded.contains(&"/usr/sbin/foo".to_string()));
    }
}
