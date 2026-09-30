//! Shared check helpers (`docs/DESIGN.md` §7.2).
//!
//! Path/mode predicates, tag readers, and regexes that two or more checks
//! would otherwise each write. A new check reuses these; new shared logic
//! goes here, not in the check.
>>>>>>> fc254f7 (design: shared check helpers and Wave 1 DESIGN.md updates)

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
