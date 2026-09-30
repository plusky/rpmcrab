//! Shared check helpers (`docs/DESIGN.md` §7.2).
//!
//! Path/mode predicates, tag readers, and regexes that two or more checks
//! would otherwise each write. A new check reuses these; new shared logic
//! goes here, not in the check.

use fancy_regex::Regex;

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
