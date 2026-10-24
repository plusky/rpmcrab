//! A single lint finding and its two textual forms.
//!
//! Two strings are derived from a finding, and the distinction is the frozen
//! contract (`docs/DESIGN.md` §4.1, §4.2):
//!
//! - [`Finding::line`] is the printed line, optionally coloured.
//! - [`Finding::match_string`] is what `Filters` regexes run against: the same
//!   layout, de-coloured.

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
    /// `Path(package.name).name` — the `Name:` tag for binaries, the spec
    /// filename for `.spec`.
    pub pkg_name: String,
    /// Real arch, `src`, `nosrc`, or none.
    pub arch: Option<String>,
    /// Spec line number; omitted for binary findings.
    pub line: Option<u32>,
    /// The former check name for a finding whose tag the port renamed for
    /// one emission path (the `script-without-shebang` population that
    /// `spurious-executable-perm` absorbed): filters are also matched
    /// against the finding rendered under this name, so rpmlintrc opt-outs
    /// written against the reference tag keep working. `None` for findings
    /// whose tag was never renamed.
    pub filter_alias: Option<&'static str>,
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

    /// The de-coloured filter-match string: no colour.
    pub fn match_string(&self) -> String {
        self.match_string_as(&self.check)
    }

    /// The match string rendered under another check name — the form a
    /// filter written against the finding's `filter_alias` is matched
    /// with. Everything else (prefix, level, details) is unchanged.
    pub fn match_string_as(&self, check: &str) -> String {
        format!(
            "{} {}: {}{}",
            self.prefix(),
            self.level.letter(),
            check,
            self.detail_output()
        )
    }

    /// The machine-readable form for `--format json` (upstream
    /// rpmlint#1156): one object per finding. The level is the frozen wire
    /// letter (`E`/`W`/`I`); empty details are dropped like in the text
    /// form; a line number of 0 renders as null like in the text prefix.
    pub fn json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "level": self.level.letter().to_string(),
            "check": self.check,
            "package": self.pkg_name,
            "arch": self.arch,
            "line": self.line.filter(|&n| n != 0),
            "details": self
                .details
                .iter()
                .filter(|d| !d.is_empty())
                .collect::<Vec<_>>(),
        })
    }

    /// The printed line. Coloured iff `color` is the tty table.
    pub fn line(&self, color: &Color) -> String {
        format!(
            "{bold}{prefix}{reset} {lc}{level}: {issue}{reset}{details}",
            bold = color.bold,
            prefix = self.prefix(),
            reset = color.reset,
            lc = self.level.color(color),
            level = self.level.letter(),
            issue = self.check,
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
            pkg_name: "llvm21-gold".to_string(),
            arch: Some("aarch64".to_string()),
            line: None,
            filter_alias: None,
        }
    }

    #[test]
    fn json_shape() {
        let mut f = pkg("suse-zypp-packageand", Level::Error);
        f.details = vec!["packageand(clang21:binutils)".to_string(), String::new()];
        f.line = Some(42);
        let v = f.json_value();
        assert_eq!(v["level"], "E");
        assert_eq!(v["check"], "suse-zypp-packageand");
        assert_eq!(v["package"], "llvm21-gold");
        assert_eq!(v["arch"], "aarch64");
        assert_eq!(v["line"], 42);
        // Empty details are dropped, like in the text form.
        assert_eq!(
            v["details"],
            serde_json::json!(["packageand(clang21:binutils)"])
        );
        assert!(v.get("badness").is_none(), "no badness field: {v}");
    }

    #[test]
    fn json_absent_arch_and_line_are_null() {
        let mut f = pkg("no-changelogname-tag", Level::Warning);
        f.arch = None;
        let v = f.json_value();
        assert!(v["arch"].is_null());
        assert!(v["line"].is_null());
        assert_eq!(v["level"], "W");
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
            check: "libdir-macro-in-noarch-package".to_string(),
            details: vec!["(main package) %{_libdir}/foo".to_string()],
            pkg_name: "qdmr.spec".to_string(),
            arch: None,
            line: Some(24),
            filter_alias: None,
        };
        assert_eq!(
            f.line(&Color::for_tty(false)),
            "qdmr.spec:24: W: libdir-macro-in-noarch-package (main package) %{_libdir}/foo"
        );
    }

    #[test]
    fn match_string_layout() {
        let f = pkg("shlib-policy-name-error", Level::Error);
        assert_eq!(
            f.match_string(),
            "llvm21-gold.aarch64: E: shlib-policy-name-error"
        );
    }
}
