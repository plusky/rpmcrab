//! Guard against regex compilation regressions.
//!
//! Profiling (2026-10-02, 33 LibreOffice RPMs) showed `Regex::new` compilation
//! was ~18% of total runtime because factory functions rebuilt the same
//! patterns per file. The fix was `OnceLock<Regex>` statics.
//!
//! This test fails if:
//! 1. Any function returns an owned `Regex` (the old factory anti-pattern).
//!    All cached regexes return `&'static Regex`.
//! 2. Any `Regex::new` appears outside a `get_or_init` closure, unless it is
//!    in the ALLOWLIST below with a documented reason.
//!
//! ALLOWLIST categories (each entry documents WHY it cannot be a static):
//! - "config": pattern comes from user configuration at runtime.
//! - "package": pattern incorporates package data (names, paths).
//! - "ctor-once": compiled once in a constructor, stored in the struct.
//! - "fallback": constant never-matching pattern used as the error path when a
//!   config-supplied pattern fails to compile; kept as a runtime fallback
//!   rather than a static because it only exists for the error path.

use std::path::PathBuf;

/// (file, line_substring, reason) for legitimate non-static Regex::new calls.
const ALLOWLIST: &[(&str, &str, &str)] = &[
    // Config-driven: patterns come from rpmlint configuration.
    (
        "binaries.rs",
        "filter_map(|r| Regex::new(r).ok())",
        "config",
    ),
    ("binaries.rs", "Regex::new(usr_lib_exception)", "config"),
    ("files.rs", "Regex::new(path).ok()", "config"),
    ("files.rs", "Regex::new(&games_group)", "config"),
    ("files.rs", "skipdocs_re: Regex::new", "config"),
    ("files.rs", "Regex::new(&meta_pkg)", "config"),
    ("menu.rs", "Regex::new(regexp).ok()", "config"),
    ("menu.rs", "Regex::new(icon_ext)", "config"),
    ("tags.rs", "Regex::new(p).ok()", "config"),
    ("tags.rs", "Regex::new(&packager).ok()", "config"),
    ("tags.rs", "Regex::new(&release_ext).ok()", "config"),
    ("tags.rs", "invalid_url_re", "config"),
    ("tags.rs", "forbidden_words_re", "config"),
    ("tags.rs", "Regex::new(&valid_buildhost).ok()", "config"),
    ("spec.rs", "Regex::new(exceptions)", "config"),
    // Package-data-driven: patterns incorporate package names/paths.
    ("alternatives.rs", "--remove\\s+", "package"),
    ("alternatives.rs", ".*.conf$", "package"),
    ("erlang.rs", "source_re: Regex::new", "package"),
    ("filelist.rs", "Regex::new(&regex)", "package"),
    ("post.rs", "prereq regex", "package"),
    ("python.rs", "Regex::new(&pattern)", "package"),
    ("source.rs", "Regex::new(&format!", "package"),
    ("spec.rs", "^%{n}(?:\\s|$)", "package"),
    ("suid_permissions.rs", "Regex::new(&pattern)", "package"),
    ("systemd_install.rs", "Regex::new(pattern)", "package"),
    ("tags.rs", "Regex::new(&re_str)", "package"),
    ("tags.rs", "(?i){pat}", "package"),
    ("tmpfiles.rs", "Regex::new(&pattern)", "package"),
    ("init_script.rs", "assign_re", "package"),
    ("binaries.rs", "f_name", "package"),
    ("binaries.rs", "Regex::new(gp)", "package"),
    ("binaries.rs", "arch_re", "package"),
    // Compiled once in constructor, stored in struct.
    ("systemd_install.rs", "unit_regex", "ctor-once"),
    // Struct fields with constant patterns (compile once per check instance).
    ("branding_policy.rs", "re_branding", "ctor-once"),
    ("icon_sizes.rs", "file_size_re", "ctor-once"),
    ("init_script.rs", "chkconfig_content_re", "ctor-once"),
    ("kmp_policy.rs", "re_kmp_pkg", "ctor-once"),
    ("menu_xdg.rs", "file_regex", "ctor-once"),
    ("pam_modules.rs", "pam_module_re", "ctor-once"),
    ("shared_library_policy.rs", "re_soname:", "ctor-once"),
    ("shared_library_policy.rs", "re_soname_strongly_versioned", "ctor-once"),
    ("shared_library_policy.rs", "re_soname_pkg", "ctor-once"),
    ("files.rs", "ldconfig_re", "ctor-once"),
    ("tags.rs", "changelog_text_version_re", "ctor-once"),
    ("tags.rs", "changelog_version_re", "ctor-once"),
    ("appdata.rs", "file_regex", "ctor-once"),
    // Fallback "never matches" pattern for config-driven regexes.
    ("binaries.rs", "Regex::new(\"$^\")", "fallback"),
    ("files.rs", "Regex::new(\"$^\")", "fallback"),
    ("spec.rs", "Regex::new(\"$^\")", "fallback"),
    // Constant patterns in struct fields (compile once per instance).
    ("tags.rs", "devel_number_re", "ctor-once"),
    ("tags.rs", "leading_space_re", "ctor-once"),
    ("tags.rs", "license_re", "ctor-once"),
    ("tags.rs", "license_exception_re", "ctor-once"),
    ("tags.rs", "pkg_config_re", "ctor-once"),
    ("tags.rs", "tag_re:", "ctor-once"),
    ("init_script.rs", "subsys_re", "ctor-once"),
    ("init_script.rs", "chkconfig_re", "ctor-once"),
    ("init_script.rs", "status_re", "ctor-once"),
    ("init_script.rs", "reload_re", "ctor-once"),
    ("init_script.rs", "lsb_tags_re", "ctor-once"),
    ("init_script.rs", "lsb_cont_re", "ctor-once"),
    ("init_script.rs", "var_re", "ctor-once"),
    ("shared_library_policy.rs", "re_so_files", "ctor-once"),
    ("icon_sizes.rs", "info_size_re", "ctor-once"),
    ("branding_policy.rs", "re_branding_generic", "ctor-once"),
    // Config-driven with format!.
    ("tags.rs", "invalid_url", "config"),
    ("tags.rs", "forbidden_words", "config"),
];

fn checks_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/checks")
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_allowlisted(file: &str, line: &str) -> bool {
    ALLOWLIST.iter().any(|(f, pat, _)| {
        if *f != file {
            return false;
        }
        // The fragment must appear as a whole token, not embedded in a longer
        // identifier: an allowlisted fragment must not silently permit an
        // unrelated line that merely contains it as a substring.
        let mut start = 0;
        while let Some(idx) = line[start..].find(pat) {
            let s = start + idx;
            let e = s + pat.len();
            let before_ok =
                s == 0 || !line[..s].chars().next_back().is_some_and(is_ident_char);
            let after_ok =
                e == line.len() || !line[e..].chars().next().is_some_and(is_ident_char);
            if before_ok && after_ok {
                return true;
            }
            start = s + 1;
        }
        false
    })
}

/// Returns true if the line looks like `fn name(...) -> Regex` (owned).
fn is_owned_regex_factory(line: &str) -> bool {
    let t = line.trim();
    if !t.starts_with("fn ") {
        return false;
    }
    if let Some(arrow) = t.find("->") {
        let ret = t[arrow + 2..].trim_start();
        // Owned Regex: starts with "Regex" but not "&'static" or "&"
        return ret.starts_with("Regex") && !ret.starts_with("&");
    }
    false
}

#[test]
fn owned_regex_factory_detector() {
    // Pins the detector directly against string inputs, independently of
    // whether a mutated tree compiles: a reintroduced factory that typechecks
    // (e.g. `let re = zip_regex(); &re`) must still be flagged at its
    // definition site.
    assert!(is_owned_regex_factory("fn zip_regex() -> Regex {"));
    assert!(is_owned_regex_factory("    fn make_re(x: &str) -> Regex {"));
    assert!(is_owned_regex_factory("fn f() -> Regex{"));
    // The converted form and other return types are not flagged.
    assert!(!is_owned_regex_factory("fn zip_regex() -> &'static Regex {"));
    assert!(!is_owned_regex_factory("fn zip_regex() -> &Regex {"));
    assert!(!is_owned_regex_factory("fn f() -> Result<Regex> {"));
    assert!(!is_owned_regex_factory("fn f() -> Option<Regex> {"));
    assert!(!is_owned_regex_factory("fn f(x: Regex) -> bool {"));
    assert!(!is_owned_regex_factory("fn f() {"));
    // Not a function definition line at all.
    assert!(!is_owned_regex_factory("    let re = Regex::new(\"x\");"));
    assert!(!is_owned_regex_factory(""));
    assert!(!is_owned_regex_factory("// fn old() -> Regex {"));
}

#[test]
fn allowlist_matching_is_token_anchored() {
    // "invalid_url_re" is allowlisted for tags.rs; a longer identifier merely
    // containing it must not be permitted.
    assert!(is_allowlisted("tags.rs", "        invalid_url_re: Regex::new(&x),"));
    assert!(!is_allowlisted(
        "tags.rs",
        "        my_invalid_url_re: Regex::new(&x),"
    ));
    // Full-call fragments still match as whole tokens.
    assert!(is_allowlisted(
        "binaries.rs",
        "        filter_map(|r| Regex::new(r).ok()),"
    ));
    // Wrong file never matches.
    assert!(!is_allowlisted(
        "files.rs",
        "        filter_map(|r| Regex::new(r).ok()),"
    ));
}

#[test]
fn no_owned_regex_factories() {
    let dir = checks_dir();
    let mut violations = Vec::new();

    for entry in std::fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.ends_with(".rs") {
            continue;
        }
        let src = std::fs::read_to_string(entry.path()).unwrap();
        for (i, line) in src.lines().enumerate() {
            if is_owned_regex_factory(line) {
                violations.push(format!("{}:{}: {}", fname, i + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "functions returning owned Regex (use OnceLock statics returning &'static Regex):\n{}",
        violations.join("\n")
    );
}

#[test]
fn no_bare_regex_new() {
    let dir = checks_dir();
    let mut violations = Vec::new();

    for entry in std::fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.ends_with(".rs") {
            continue;
        }
        let src = std::fs::read_to_string(entry.path()).unwrap();
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains("Regex::new") {
                continue;
            }
            // Skip comments.
            if line.trim_start().starts_with("//") {
                continue;
            }
            // Allow get_or_init closures (check 20 lines above for multi-line).
            let window_start = i.saturating_sub(20);
            let in_static = lines[window_start..=i]
                .iter()
                .any(|l| l.contains("get_or_init"));
            if in_static {
                continue;
            }
            if is_allowlisted(&fname, line) {
                continue;
            }
            violations.push(format!("{}:{}: {}", fname, i + 1, line.trim()));
        }
    }

    assert!(
        violations.is_empty(),
        "Regex::new outside get_or_init (add to ALLOWLIST with reason if legitimate):\n{}",
        violations.join("\n")
    );
}
