//! Regexes shared between checks.
//!
//! Hoisted from the individual ports so the `AbstractCheck` helpers exist
//! exactly once instead of once per check module.

use fancy_regex::Regex;

/// `AbstractCheck.macro_regex`: `%+[{(]?[a-zA-Z_]\w{2,}[)}]?`.
pub fn macro_regex() -> Regex {
    Regex::new(r"%+[{(]?[a-zA-Z_]\w{2,}[)}]?").expect("static regex")
}
