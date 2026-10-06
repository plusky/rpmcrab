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
//! - "runtime": pattern incorporates runtime values (RPM macro expansions,
//!   the current date) that are unknowable at compile time.
//! - "ctor-once": compiled once in a constructor, stored in the struct.
//! - "fallback": constant never-matching pattern used as the error path when a
//!   config-supplied pattern fails to compile; kept as a runtime fallback
//!   rather than a static because it only exists for the error path.
//! - "test": `Regex::new` inside unit tests; never on a hot path.
//!
//! The same list also feeds `no_owned_regex_factories`: an owned-`Regex`
//! factory is legitimate only when the pattern depends on a runtime value
//! and the result is compiled once in a constructor, stored in the struct.

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
    (
        "shared_library_policy.rs",
        "re_soname_strongly_versioned",
        "ctor-once",
    ),
    ("shared_library_policy.rs", "re_soname_pkg", "ctor-once"),
    ("files.rs", "ldconfig_re", "ctor-once"),
    ("tags.rs", "changelog_text_version_re", "ctor-once"),
    ("tags.rs", "changelog_version_re", "ctor-once"),
    // Fallback "never matches" pattern for config-driven regexes.
    ("binaries.rs", "Regex::new(\"$^\")", "fallback"),
    ("files.rs", "Regex::new(\"$^\")", "fallback"),
    ("spec.rs", "Regex::new(\"$^\")", "fallback"),
    // Constant patterns in struct fields (compile once per instance).
    ("tags.rs", "devel_number_re", "ctor-once"),
    ("tags.rs", "leading_space_re", "ctor-once"),
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
    // buildroot_and_date.rs (landed on main after this branch): the buildroot
    // pattern embeds the runtime `%{?buildroot}` macro value and `istoday`
    // embeds today's date, so neither can be a static; both are compiled once
    // in the constructor and stored in the struct. `looksliketime` is a
    // constant struct-field pattern (ctor-once, matching the entries above).
    ("buildroot_and_date.rs", "Regex::new(&pattern)", "runtime"),
    ("buildroot_and_date.rs", "looksliketime", "ctor-once"),
    ("buildroot_and_date.rs", "istoday", "runtime"),
    // Owned-Regex factory with a runtime-data pattern; called once in the
    // constructor, never on the per-file hot path.
    ("buildroot_and_date.rs", "fn buildroot_regex", "runtime"),
    // Unit-test shape assertion for `today_string()`.
    ("buildroot_and_date.rs", "^[A-Z][a-z]{2}", "test"),
];

fn checks_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/checks")
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Whether `pat` occurs in `line` as a whole token: an allowlisted fragment
/// must not silently permit an unrelated line that merely contains it as a
/// substring (e.g. `invalid_url` must not match `invalid_url_regex`).
fn fragment_matches_token_anchored(line: &str, pat: &str) -> bool {
    let mut start = 0;
    while let Some(idx) = line[start..].find(pat) {
        let s = start + idx;
        let e = s + pat.len();
        let before_ok = s == 0 || !line[..s].chars().next_back().is_some_and(is_ident_char);
        let after_ok = e == line.len() || !line[e..].chars().next().is_some_and(is_ident_char);
        if before_ok && after_ok {
            return true;
        }
        start = s + 1;
    }
    false
}

fn is_allowlisted(file: &str, line: &str) -> bool {
    ALLOWLIST.iter().any(|(f, pat, _)| {
        if *f != file {
            return false;
        }
        fragment_matches_token_anchored(line, pat)
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
    assert!(!is_owned_regex_factory(
        "fn zip_regex() -> &'static Regex {"
    ));
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
    // "tag_re:" is allowlisted for tags.rs; a longer identifier merely
    // containing it must not be permitted.
    assert!(is_allowlisted(
        "tags.rs",
        "        tag_re: Regex::new(r\"x\"),"
    ));
    assert!(!is_allowlisted(
        "tags.rs",
        "        my_tag_re: Regex::new(r\"x\"),"
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
fn every_allowlist_entry_matches_a_guarded_line() {
    // Dead entries rot silently: without this test nothing reports an entry
    // that stopped matching (e.g. the four pruned when token anchoring
    // landed: the real lines had all been renamed). The fragment must match
    // on a line the guards actually consult — a `Regex::new` line (comments
    // and `get_or_init`-closure lines excluded, as in `no_bare_regex_new`)
    // or an owned-`Regex` factory line (as in `no_owned_regex_factories`):
    // a bare mention elsewhere (struct field, call site, test fn) does not
    // keep an entry alive. This caught `appdata.rs` `file_regex`, which had
    // migrated to a `OnceLock` static while the fragment lingered on
    // unrelated lines.
    let dir = checks_dir();
    let mut dead = Vec::new();
    for (file, pat, _) in ALLOWLIST {
        let src = std::fs::read_to_string(dir.join(file)).unwrap();
        let lines: Vec<&str> = src.lines().collect();
        let live = lines.iter().enumerate().any(|(i, line)| {
            // Mirror the guards: `no_bare_regex_new` skips `Regex::new`
            // inside `get_or_init` closures before consulting the
            // allowlist, so such a line cannot keep an entry alive.
            // `no_owned_regex_factories` has no such skip, so the factory
            // arm stays as-is.
            fragment_matches_token_anchored(line, pat)
                && ((line.contains("Regex::new")
                    && !line.trim_start().starts_with("//")
                    && !in_get_or_init_closure(&lines, i))
                    || is_owned_regex_factory(line))
        });
        if !live {
            dead.push(format!("{file}: {pat}"));
        }
    }
    assert!(
        dead.is_empty(),
        "allowlist entries matching no guarded line (prune them):\n{}",
        dead.join("\n")
    );
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
            if is_owned_regex_factory(line) && !is_allowlisted(&fname, line) {
                violations.push(format!("{}:{}: {}", fname, i + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "functions returning owned Regex (use OnceLock statics returning &'static Regex; add to ALLOWLIST with reason if legitimate):\n{}",
        violations.join("\n")
    );
}

/// Net `(` minus `)` on a line, ignoring delimiters inside string literals,
/// character literals, and line comments. Regex patterns are full of
/// parentheses (`r"^lib(.*?)([0-9.]+)"`); counting those would corrupt the
/// depth tracking in [`in_get_or_init_closure`].
fn net_parens_outside_strings(line: &str) -> i32 {
    let b = line.as_bytes();
    let n = b.len();
    let mut depth = 0i32;
    let mut i = 0;
    while i < n {
        match b[i] {
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                i += 1;
            }
            // A line comment ends any depth contribution from the rest.
            b'/' if b.get(i + 1) == Some(&b'/') => break,
            // Character literal: '(' , ')' , '\''.
            b'\'' => {
                i += 1;
                if b.get(i) == Some(&b'\\') {
                    i += 1;
                }
                i += 1;
                if b.get(i) == Some(&b'\'') {
                    i += 1;
                }
            }
            b'"' => {
                // Raw string r#*"..."*# or byte-string br#*"..."*# (the
                // terminator is `"` followed by exactly the opening hash
                // count). The prefix must not be glued to an identifier
                // (`formatr#"..."#` is not a raw string); the same boundary
                // applies to the `b` of `br#`.
                let mut j = i;
                while j > 0 && b[j - 1] == b'#' {
                    j -= 1;
                }
                let raw = if j > 0 && b[j - 1] == b'r' {
                    let start = if j > 1 && b[j - 2] == b'b' {
                        j - 2
                    } else {
                        j - 1
                    };
                    start == 0 || !is_ident_char(b[start - 1] as char)
                } else {
                    false
                };
                if raw {
                    let hashes = i - j;
                    i += 1;
                    while i < n {
                        let terminator = b[i] == b'"'
                            && (0..hashes).all(|k| b.get(i + 1 + k) == Some(&b'#'))
                            && b.get(i + 1 + hashes) != Some(&b'#');
                        if terminator {
                            i += 1 + hashes;
                            break;
                        }
                        i += 1;
                    }
                } else {
                    // Ordinary string: honor `\"` and `\\` escapes.
                    i += 1;
                    while i < n {
                        match b[i] {
                            b'\\' => i += 2,
                            b'"' => {
                                i += 1;
                                break;
                            }
                            _ => i += 1,
                        }
                    }
                }
            }
            _ => i += 1,
        }
    }
    depth
}

/// Whether the `Regex::new` on `lines[i]` sits inside a `get_or_init`
/// closure.
///
/// The nearest `get_or_init` at most 20 lines above opens the search; the
/// line counts as inside only while that call's parentheses still enclose
/// it. The closure is always the call's single argument, so the paren scope
/// is exactly the closure's extent. This covers the `|| { ... }` bodies,
/// the single-line `|| Regex::new(...)` form, and the split form with the
/// closure on following lines (files.rs `start_private_key_regex`); a mere
/// mention of `get_or_init` in a comment grants no skip.
///
/// The 20-line search window is itself a bound: a legitimate closure longer
/// than 20 lines would make a `Regex::new` inside it a false positive. The
/// longest real span is 15 lines (`python.rs:73-88`, `ERR_PATHS`), so the
/// headroom is 5 — keep closures short, or widen the window and re-measure.
fn in_get_or_init_closure(lines: &[&str], i: usize) -> bool {
    let window_start = i.saturating_sub(20);
    let opener = (window_start..=i)
        .rev()
        .find(|&j| lines[j].contains("get_or_init"));
    let g = match opener {
        Some(g) => g,
        None => return false,
    };
    if g == i {
        // `get_or_init(|| Regex::new(...))` on one line.
        return true;
    }
    let mut depth = 0i32;
    for line in &lines[g..=i] {
        depth += net_parens_outside_strings(line);
        if depth <= 0 {
            // The get_or_init call closed before line i.
            return false;
        }
    }
    true
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
            // Skip Regex::new inside a get_or_init closure (multi-line
            // OnceLock bodies included); proximity to a get_or_init line
            // alone is not membership.
            if in_get_or_init_closure(&lines, i) {
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

#[test]
fn get_or_init_skip_is_membership_not_proximity() {
    // plusky's A/B from the #101 review: a genuine per-call compile below a
    // *closed* closure but inside the 20-line window must be flagged, while
    // the identical line 30 lines clear is flagged under any rule.
    let closed: Vec<&str> = vec![
        "static FOO_RE: OnceLock<Regex> = OnceLock::new();",
        "fn foo_re() -> &'static Regex {",
        "    FOO_RE.get_or_init(|| {",
        "        Regex::new(r\"^foo\").expect(\"static regex\")",
        "    })",
        "}",
    ];
    // Legitimate closure bodies are still skipped: braced multi-line ...
    assert!(in_get_or_init_closure(&closed, 3));
    // ... single-line expression form ...
    assert!(in_get_or_init_closure(
        &["    FOO_RE.get_or_init(|| Regex::new(r\"^foo\").expect(\"static\"))"],
        0
    ));
    // ... and the split form with the closure on following lines
    // (files.rs `start_private_key_regex` shape).
    let split = vec![
        "    START_PRIVATE_KEY_REGEX.get_or_init(",
        "        || // NB: comment between the call and its closure",
        "        Regex::new(r\"^----BEGIN PRIVATE KEY-----\\n?$\").expect(\"static regex\"),",
        "    )",
    ];
    assert!(in_get_or_init_closure(&split, 2));

    // A: injected per-call compile 14 lines below the closed closure --
    // inside the old proximity window, outside the closure.
    let mut a = closed.clone();
    a.extend(std::iter::repeat_n("    let _pad = 1;", 14));
    a.push("    let re = fancy_regex::Regex::new(&format!(\"{a}{b}\"));");
    let injected = a.len() - 1;
    assert!(
        !in_get_or_init_closure(&a, injected),
        "per-call compile below a closed closure must be flagged"
    );

    // B: the identical injection 30 lines clear of any get_or_init.
    let mut b = closed.clone();
    b.extend(std::iter::repeat_n("    let _pad = 1;", 30));
    b.push("    let re = fancy_regex::Regex::new(&format!(\"{a}{b}\"));");
    assert!(!in_get_or_init_closure(&b, b.len() - 1));

    // A comment merely mentioning get_or_init grants no skip.
    let comment = vec![
        "    // migrated to get_or_init elsewhere",
        "    let re = Regex::new(r\"^foo$\");",
    ];
    assert!(!in_get_or_init_closure(&comment, 1));

    // Delimiters inside strings and comments do not disturb depth tracking.
    let tricky = vec![
        "    FOO_RE.get_or_init(|| {",
        "        // ) ( } comment delimiters must not count",
        "        let pat = \"(\"; // unbalanced delimiter in a string",
        "        Regex::new(&format!(\"{a}{b}\")).expect(\"static\")",
        "    })",
    ];
    assert!(in_get_or_init_closure(&tricky, 3));
}

#[test]
fn net_parens_ignores_raw_and_byte_raw_strings() {
    // Parens inside raw strings must not move the depth counter; the
    // get_or_init skip depends on it. Byte-string raw strings (`br#"..."#`)
    // used to fall through to ordinary-string scanning, which ends the
    // string at the first `"` of the content and counts the rest as code.
    assert_eq!(net_parens_outside_strings("f(r\"(x)\")"), 0);
    assert_eq!(net_parens_outside_strings("f(br\"(x)\")"), 0);
    assert_eq!(net_parens_outside_strings("f(br#\"(x)\"#)"), 0);
    // `"` inside the content must not end the string early: the `(` after
    // the fake end used to be counted.
    assert_eq!(net_parens_outside_strings("f(br#\"a\"\"#)"), 0);
    assert_eq!(net_parens_outside_strings("f(br#\"a\"(\"#)"), 0);
    // The `r`/`br` prefix must not be glued to an identifier.
    assert_eq!(net_parens_outside_strings("formatr#\"x\"#"), 0);
    // The `b` of `br#` is subject to the same boundary: `xbr#` is an
    // identifier tail, so the `(` after the fake string end counts.
    assert_eq!(net_parens_outside_strings("xbr#\"a\"(\"#"), 1);
    // Unbalanced delimiters outside strings still count.
    assert_eq!(net_parens_outside_strings("f(g("), 2);
    assert_eq!(net_parens_outside_strings("f(g))"), -1);
}

#[test]
fn allowlist_liveness_get_or_init_closure_skip() {
    // plusky's #225 nit: the get_or_init-closure skip in the allowlist
    // liveness check must be non-inert. Mirror the liveness predicate from
    // `every_allowlist_entry_matches_a_guarded_line` over synthetic lines
    // (shape borrowed from `get_or_init_skip_is_membership_not_proximity`
    // below).
    fn is_live(lines: &[&str], pat: &str) -> bool {
        lines.iter().enumerate().any(|(i, line)| {
            fragment_matches_token_anchored(line, pat)
                && ((line.contains("Regex::new")
                    && !line.trim_start().starts_with("//")
                    && !in_get_or_init_closure(lines, i))
                    || is_owned_regex_factory(line))
        })
    }

    // The sole `Regex::new` match sits inside a get_or_init closure: the
    // entry must not stay alive.
    let closed: Vec<&str> = vec![
        "static FOO_RE: OnceLock<Regex> = OnceLock::new();",
        "fn foo_re() -> &'static Regex {",
        "    FOO_RE.get_or_init(|| {",
        "        Regex::new(r\"^foo\").expect(\"static regex\")",
        "    })",
        "}",
    ];
    assert!(
        !is_live(&closed, "^foo"),
        "entry whose sole match is inside a get_or_init closure must not stay alive"
    );

    // Converse: a `Regex::new` below the *closed* closure is outside it, so
    // it keeps the entry alive.
    let mut open = closed.clone();
    open.extend(std::iter::repeat_n("    let _pad = 1;", 14));
    open.push("    let re = Regex::new(r\"^foo\");");
    assert!(
        is_live(&open, "^foo"),
        "per-call compile below a closed closure keeps the entry alive"
    );
}
