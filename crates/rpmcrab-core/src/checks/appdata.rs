//! `AppDataCheck` — AppStream metadata validation.
//!
//! Ported from `rpmlint/checks/AppDataCheck.py`. One finding:
//! `invalid-appdata-file`.
//!
//! The reference runs `appstream-util validate-relax --nonet` and falls back
//! to a bare XML well-formedness check when the tool is absent. This port
//! does the same: subprocess when available, otherwise a native well-formed
//! XML check (no new dependency).

use std::path::Path;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::tools::{Tool, ToolSource, test_source};

pub struct AppDataCheck {
    file_regex: Regex,
    checked_files: usize,
    tool: Tool,
}

impl AppDataCheck {
    pub fn new(_config: &Config) -> Self {
        Self::with_tool_source(ToolSource::Path)
    }

    /// Resolve `appstream-util` under `source`. Tests pass
    /// `ToolSource::Dir` pointing at a scratch dir: a fake named
    /// `appstream-util` there is used, an empty dir forces the native
    /// well-formedness fallback.
    pub fn with_tool_source(source: ToolSource) -> Self {
        let (tool, _) = Tool::probe(&source, "appstream-util", &["--version"]);
        Self {
            // The reference passes this to AbstractFilesCheck, which applies it
            // with `re.match` (AbstractCheck.py:45), so it is anchored at the
            // start; is_match searches, hence the explicit `^`. The dot before
            // `xml` is unescaped in the reference pattern and stays that way
            // here: it matches any character, so `foo.appdata_xml` is
            // validated upstream and must be here too.
            file_regex: Regex::new(r"^/usr/share/appdata/.*\.(appdata|metainfo).xml$")
                .expect("static regex"),
            checked_files: 0,
            tool,
        }
    }

    /// Test entry point: `None` probes the live `PATH`, `Some(dir)`
    /// resolves `appstream-util` under `dir`.
    pub fn with_tool_dir(dir: Option<&Path>) -> Self {
        Self::with_tool_source(test_source(dir))
    }

    /// True if the text contains an undefined XML entity reference.
    ///
    /// The reference falls back to `ElementTree.parse`, which rejects
    /// undefined entities (`&foo;`). Only the five predefined entities
    /// (`lt`, `gt`, `amp`, `apos`, `quot`) and numeric character references
    /// (`&#65;`, `&#x41;`) are valid. An empty numeric body (`&#;`, `&#x;`)
    /// is `not well-formed (invalid token)`, and a number outside the XML
    /// character ranges is `reference to invalid character number`.
    fn has_undefined_entity(text: &str) -> bool {
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] != '&' {
                i += 1;
                continue;
            }
            let start = i + 1;
            let mut end = start;
            while end < chars.len() && chars[end] != ';' && chars[end] != '&' {
                end += 1;
            }
            if end >= chars.len() || chars[end] != ';' {
                return true; // unterminated `&`
            }
            let entity: String = chars[start..end].iter().collect();
            let valid = matches!(entity.as_str(), "lt" | "gt" | "amp" | "apos" | "quot")
                || entity.strip_prefix('#').is_some_and(|num| {
                    // `"".chars().all(..)` is vacuously true, so the
                    // emptiness check is explicit: `&#;` is invalid token.
                    if !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) {
                        return num.parse::<u32>().is_ok_and(Self::is_valid_xml_char);
                    }
                    // `&#x;` likewise; the `x` is lowercase only (`&#X41;`
                    // is invalid token in the reference).
                    if let Some(hex) = num.strip_prefix('x') {
                        return !hex.is_empty()
                            && hex.chars().all(|c| c.is_ascii_hexdigit())
                            && u32::from_str_radix(hex, 16).is_ok_and(Self::is_valid_xml_char);
                    }
                    false
                });
            if !valid {
                return true;
            }
            i = end + 1;
        }
        false
    }

    /// The XML 1.0 character ranges expat accepts in a character reference;
    /// anything else is `reference to invalid character number`.
    fn is_valid_xml_char(n: u32) -> bool {
        matches!(
            n,
            0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
        )
    }

    /// Minimal XML well-formedness check: balanced tags, single root.
    /// Only used when `appstream-util` is unavailable.
    fn is_well_formed_xml(text: &str) -> bool {
        let chars: Vec<char> = text.chars().collect();
        let n = chars.len();
        let mut i = 0;
        let mut stack: Vec<String> = Vec::new();
        let mut root_seen = false;

        while i < n {
            // Find next '<', checking text content for undefined entities.
            let text_start = i;
            while i < n && chars[i] != '<' {
                i += 1;
            }
            let text: String = chars[text_start..i].iter().collect();
            if Self::has_undefined_entity(&text) {
                return false;
            }
            if i >= n {
                break;
            }
            i += 1; // skip '<'
            if i >= n {
                return false;
            }

            // Processing instruction or comment/doctype: skip to '>'
            if chars[i] == '?' || chars[i] == '!' {
                while i < n && chars[i] != '>' {
                    i += 1;
                }
                i += 1;
                continue;
            }

            // Closing tag
            if chars[i] == '/' {
                i += 1;
                let start = i;
                while i < n && chars[i] != '>' && !chars[i].is_whitespace() {
                    i += 1;
                }
                let name: String = chars[start..i].iter().collect();
                while i < n && chars[i] != '>' {
                    i += 1;
                }
                i += 1; // skip '>'
                if stack.pop().as_deref() != Some(name.as_str()) {
                    return false;
                }
                continue;
            }

            // Opening tag: parse name
            let start = i;
            while i < n && !chars[i].is_whitespace() && chars[i] != '>' && chars[i] != '/' {
                i += 1;
            }
            let name: String = chars[start..i].iter().collect();
            if name.is_empty() {
                return false;
            }

            // Skip attributes, watching for '/>'. Attribute values are
            // checked for undefined entities (the reference's ElementTree
            // rejects them).
            let mut self_closing = false;
            let mut in_quote: Option<char> = None;
            let mut attr_start = 0;
            while i < n && chars[i] != '>' {
                let ch = chars[i];
                if let Some(q) = in_quote {
                    if ch == q {
                        let value: String = chars[attr_start..i].iter().collect();
                        if Self::has_undefined_entity(&value) {
                            return false;
                        }
                        in_quote = None;
                    }
                } else if ch == '"' || ch == '\'' {
                    in_quote = Some(ch);
                    attr_start = i + 1;
                } else if ch == '/' && i + 1 < n && chars[i + 1] == '>' {
                    self_closing = true;
                }
                i += 1;
            }
            i += 1; // skip '>'

            if stack.is_empty() {
                if root_seen {
                    return false; // second root element
                }
                root_seen = true;
            }
            if !self_closing {
                stack.push(name);
            }
        }
        root_seen && stack.is_empty()
    }

    /// Validate one file: the configured `appstream-util` when present,
    /// else well-formedness.
    fn validate(&self, path: &str) -> bool {
        if let Some(mut cmd) = self.tool.command() {
            // The reference builds `self.cmd + f` and calls `cmd.split()`,
            // so a path containing whitespace is split into several argv
            // elements.
            let args = format!("validate-relax --nonet {path}");
            if let Ok(o) = cmd
                .args(args.split_whitespace())
                .env("LC_ALL", "C")
                .output()
            {
                return o.status.success();
            }
        }
        std::fs::read_to_string(path)
            .map(|t| Self::is_well_formed_xml(&t))
            .unwrap_or(false)
    }
}

impl Check for AppDataCheck {
    fn name(&self) -> &'static str {
        "AppDataCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        for pkgfile in &pkg.files {
            if !is_match(&self.file_regex, &pkgfile.name) {
                continue;
            }
            // AbstractCheck.py:45 filters ghosts out of the dispatch list, so
            // check_file never runs for one and a ghost appdata file draws no
            // finding.
            if pkg.ghost_files.iter().any(|g| g == &pkgfile.name) {
                continue;
            }
            self.checked_files += 1;
            if !self.validate(&pkgfile.path) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "invalid-appdata-file",
                    &[&pkgfile.name],
                );
            }
        }
    }

    fn reset(&mut self) {
        self.checked_files = 0;
    }

    fn checked_files(&self) -> Option<usize> {
        Some(self.checked_files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_passes() {
        assert!(AppDataCheck::is_well_formed_xml(
            r#"<?xml version="1.0"?><component><name>Foo</name></component>"#
        ));
    }

    #[test]
    fn self_closing_passes() {
        assert!(AppDataCheck::is_well_formed_xml(
            "<component><br/></component>"
        ));
    }

    #[test]
    fn mismatched_tags_fail() {
        assert!(!AppDataCheck::is_well_formed_xml("<a><b></a></b>"));
    }

    #[test]
    fn unclosed_tag_fails() {
        assert!(!AppDataCheck::is_well_formed_xml("<a><b></b>"));
    }

    #[test]
    fn two_roots_fail() {
        assert!(!AppDataCheck::is_well_formed_xml("<a/><b/>"));
    }

    #[test]
    fn attributes_are_skipped() {
        assert!(AppDataCheck::is_well_formed_xml(
            r#"<component type="desktop"><name lang="en">Foo</name></component>"#
        ));
    }

    #[test]
    fn file_regex_matches_appdata() {
        let check = AppDataCheck::new(&Config::default());
        assert!(is_match(
            &check.file_regex,
            "/usr/share/appdata/foo.appdata.xml"
        ));
        assert!(is_match(
            &check.file_regex,
            "/usr/share/appdata/foo.metainfo.xml"
        ));
        assert!(!is_match(&check.file_regex, "/usr/share/doc/foo.xml"));
    }
}
