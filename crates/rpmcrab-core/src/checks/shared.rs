//! Shared check helpers (`docs/DESIGN.md` §7.2).
//!
//! Path/mode predicates, tag readers, and regexes that two or more checks
//! would otherwise each write. A new check reuses these; new shared logic
//! goes here, not in the check.

use fancy_regex::Regex;

use crate::pkg::Pkg;

/// `AbstractCheck.macro_regex`: `%+[{(]?[a-zA-Z_]\w{2,}[)}]?`.
pub fn macro_regex() -> Regex {
    Regex::new(r"%+[{(]?[a-zA-Z_]\w{2,}[)}]?").expect("static regex")
}

/// `FilesCheck.devel_regex`: `(.*)-(debug(info|source)?|devel|headers|source|static|prof)$`.
pub fn devel_regex() -> Regex {
    Regex::new(r"(.*)-(debug(info|source)?|devel|headers|source|static|prof)$")
        .expect("static regex")
}

/// `lib_package_regex`: `(?:^(?:compat-)?lib.*?(\.so.*)?|libs?[\d-]*)$`, case-insensitive.
pub fn lib_package_regex() -> Regex {
    Regex::new(r"(?i)(?:^(?:compat-)?lib.*?(\.so.*)?|libs?[\d-]*)$").expect("static regex")
}

// The reference's `pkg[tag] or pkg.scriptprog(prog)`: an empty scriptlet
// body falls back to the `-p` interpreter string.
pub fn script_body_or_prog(pkg: &Pkg, tag: librpm::Tag, prog: librpm::Tag) -> String {
    let body = pkg.tag_str(tag).unwrap_or_default();
    if body.is_empty() {
        pkg.scriptprog(prog)
    } else {
        body
    }
}

/// Python `str()` of a list of strings: `['a', 'b']`. The reference
/// interpolates `str(list)` into finding details; Rust's `{:?}` would print
/// `["a", "b"]` instead. (Python switches to double quotes for strings
/// containing a quote; package and file names never do, so single quotes
/// match for every realistic input.)
pub fn python_str_list(items: &[&str]) -> String {
    let inner: Vec<String> = items.iter().map(|s| format!("'{s}'")).collect();
    format!("[{}]", inner.join(", "))
}

/// Python `str()` of a tuple of strings: `('a', 'b')`. Same caveat as
/// [`python_str_list`].
pub fn python_str_tuple(items: &[&str]) -> String {
    let inner: Vec<String> = items.iter().map(|s| format!("'{s}'")).collect();
    format!("({})", inner.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macro_regex_matches_unexpanded_macro() {
        // Regression: files.rs had \\w (double-escaped) which matched a
        // literal backslash-w instead of word characters. This fails if the
        // broken form is restored.
        let re = macro_regex();
        assert!(re.is_match("%{foo}").unwrap_or(false));
        assert!(re.is_match("%foo").unwrap_or(false));
        assert!(!re.is_match("plain").unwrap_or(true));
    }

    #[test]
    fn lib_package_regex_matches_lib_names() {
        let re = lib_package_regex();
        assert!(re.is_match("libfoo").unwrap_or(false));
        assert!(re.is_match("lib64").unwrap_or(false));
        assert!(!re.is_match("foo").unwrap_or(true));
    }

    #[test]
    fn script_body_or_prog_prefers_body_over_interpreter() {
        // B2: the reference is `pkg[POSTIN] or pkg.scriptprog(POSTINPROG)` --
        // the body wins. The ldconfig fixture has a %post body plus
        // `%post -p /sbin/ldconfig`; returning the interpreter here would be
        // the inverted precedence.
        let rpm = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/parity/pkg/inputs/ldconfig-test-1.0-1.noarch.rpm"
        );
        let dir = std::env::temp_dir().join("rpmcrab-script-body-or-prog");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let pkg = crate::pkg::Pkg::open(std::path::Path::new(rpm), &dir).expect("fixture opens");
        let body = script_body_or_prog(&pkg, librpm::Tag::POSTIN, librpm::Tag::POSTINPROG);
        assert!(
            !body.contains("/sbin/ldconfig"),
            "body won, not the -p interpreter: {body:?}"
        );
        assert!(!body.is_empty(), "fixture has a %post body");
    }

    #[test]
    fn python_str_list_matches_python_repr() {
        // B9: the reference prints Python repr (['a']), not Rust Debug (["a"]).
        assert_eq!(python_str_list(&["a"]), "['a']");
        assert_eq!(python_str_list(&["a", "b"]), "['a', 'b']");
        assert_eq!(python_str_list(&[]), "[]");
    }

    #[test]
    fn python_str_tuple_matches_python_repr() {
        // B9: the reference prints str of a tuple (('a', 'ad')).
        assert_eq!(python_str_tuple(&["a", "ad"]), "('a', 'ad')");
    }

    #[test]
    fn shared_regexes_have_no_double_escaping() {
        // Regression: files.rs had \\.so, [\\d-], and \\w (double-escaped
        // in raw strings). The Debug format escapes backslashes, so a correct
        // single-backslash pattern appears as \\ in debug output, while a
        // double-backslash (broken) pattern appears as \\\\. This fails
        // if the broken forms are restored.
        let macro_dbg = format!("{:?}", macro_regex());
        let lib_dbg = format!("{:?}", lib_package_regex());
        assert!(
            !macro_dbg.contains("\\\\"),
            "macro_regex double-escaped: {macro_dbg}"
        );
        assert!(
            !lib_dbg.contains("\\\\"),
            "lib_package_regex double-escaped: {lib_dbg}"
        );
    }
}
