//! A single lint finding and its two textual forms.
//!
//! Two strings are derived from a finding, and the distinction is the frozen
//! contract (`docs/DESIGN.md` §4.1, §4.2):
//!
//! - [`Finding::line`] is the printed line, optionally coloured, with the
//!   `(Badness: N)` column.
//! - [`Finding::match_string`] is what `Filters` regexes run against: the same
//!   layout, de-coloured, **without** the badness column.

use crate::color::Color;
use crate::level::Level;

/// A lint finding with the package context needed to render its line prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    /// The check tag name. Must be space-free (rpmlint raises otherwise).
    pub check: String,
    /// Free-form details; empty strings are dropped, each kept detail is
    /// prefixed with a single space.
    pub details: Vec<String>,
    /// Final badness after scoring (signed: a negative configured badness
    /// subtracts from the score, per Python `int()`). The column prints only
    /// when `> 1`.
    pub badness: i64,
    /// `Path(package.name).name` — the `Name:` tag for binaries, the spec
    /// filename for `.spec`.
    pub pkg_name: String,
    /// Real arch, `src`, `nosrc`, or none.
    pub arch: Option<String>,
    /// Spec line number; omitted for binary findings.
    pub line: Option<u32>,
}

impl Finding {
    /// `{filename}{arch}:{line}` — arch carries its leading `.`, line its
    /// trailing `:`.
    fn prefix(&self) -> String {
        let arch = self
            .arch
            .as_deref()
            .map(|a| format!(".{a}"))
            .unwrap_or_default();
        // A line number of 0 is falsy in Python (`f'{n}:' if n else ''`) and
        // renders no suffix, matching `SpecCheck` setting `current_linenum = 0`
        // transiently.
        let line = self
            .line
            .filter(|&n| n != 0)
            .map(|n| format!("{n}:"))
            .unwrap_or_default();
        format!("{}{}:{}", self.pkg_name, arch, line)
    }

    /// ` detail` for each non-empty detail, concatenated.
    fn detail_output(&self) -> String {
        self.details
            .iter()
            .filter(|d| !d.is_empty())
            .map(|d| format!(" {d}"))
            .collect()
    }

    /// The de-coloured filter-match string: no colour, no `(Badness: N)`.
    pub fn match_string(&self) -> String {
        format!(
            "{} {}: {}{}",
            self.prefix(),
            self.level.letter(),
            self.check,
            self.detail_output()
        )
    }

    /// The printed line. Coloured iff `color` is the tty table.
    pub fn line(&self, color: &Color) -> String {
        let bad_output = if self.badness > 1 {
            format!(" (Badness: {})", self.badness)
        } else {
            String::new()
        };
        format!(
            "{bold}{prefix}{reset} {lc}{level}: {issue}{reset}{bad}{details}",
            bold = color.bold,
            prefix = self.prefix(),
            reset = color.reset,
            lc = self.level.color(color),
            level = self.level.letter(),
            issue = self.check,
            bad = bad_output,
            details = self.detail_output(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(check: &str, level: Level) -> Finding {
        Finding {
            level,
            check: check.to_string(),
            details: vec![],
            badness: 0,
            pkg_name: "llvm21-gold".to_string(),
            arch: Some("aarch64".to_string()),
            line: None,
        }
    }

    #[test]
    fn binary_line_piped() {
        let mut f = pkg("suse-zypp-packageand", Level::Error);
        f.details = vec!["packageand(clang21:binutils)".to_string()];
        assert_eq!(
            f.line(&Color::for_tty(false)),
            "llvm21-gold.aarch64: E: suse-zypp-packageand packageand(clang21:binutils)"
        );
    }

    #[test]
    fn spec_line_with_linenum() {
        let f = Finding {
            level: Level::Warning,
            check: "mixed-use-of-spaces-and-tabs".to_string(),
            details: vec!["(spaces: line 24, tab: line 2)".to_string()],
            badness: 0,
            pkg_name: "qdmr.spec".to_string(),
            arch: None,
            line: Some(24),
        };
        assert_eq!(
            f.line(&Color::for_tty(false)),
            "qdmr.spec:24: W: mixed-use-of-spaces-and-tabs (spaces: line 24, tab: line 2)"
        );
    }

    #[test]
    fn badness_column_only_when_over_one() {
        let mut f = pkg("shlib-policy-name-error", Level::Error);
        f.badness = 10000;
        f.details = vec!["SONAME: libLTO.so.21.1".to_string()];
        assert_eq!(
            f.line(&Color::for_tty(false)),
            "llvm21-gold.aarch64: E: shlib-policy-name-error (Badness: 10000) SONAME: libLTO.so.21.1"
        );
        f.badness = 1;
        assert!(!f.line(&Color::for_tty(false)).contains("Badness"));
    }

    #[test]
    fn match_string_omits_badness() {
        let mut f = pkg("shlib-policy-name-error", Level::Error);
        f.badness = 10000;
        assert_eq!(
            f.match_string(),
            "llvm21-gold.aarch64: E: shlib-policy-name-error"
        );
    }
}
