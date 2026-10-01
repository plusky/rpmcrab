//! `AppDataCheck` — AppStream metadata validation.
//!
//! Ported from `rpmlint/checks/AppDataCheck.py`. One finding:
//! `invalid-appdata-file`.
//!
//! The reference runs `appstream-util validate-relax --nonet` and falls back
//! to a bare XML well-formedness check when the tool is absent. This port
//! does the same: subprocess when available, otherwise a native well-formed
//! XML check (no new dependency).

use std::process::Command;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct AppDataCheck {
    file_regex: Regex,
}

impl AppDataCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            file_regex: Regex::new(r"/usr/share/appdata/.*\.(appdata|metainfo)\.xml$")
                .expect("static regex"),
        }
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
            // Find next '<'
            while i < n && chars[i] != '<' {
                i += 1;
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

            // Skip attributes, watching for '/>'
            let mut self_closing = false;
            let mut in_quote: Option<char> = None;
            while i < n && chars[i] != '>' {
                let ch = chars[i];
                if let Some(q) = in_quote {
                    if ch == q {
                        in_quote = None;
                    }
                } else if ch == '"' || ch == '\'' {
                    in_quote = Some(ch);
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

    /// Validate one file: `appstream-util` when present, else well-formedness.
    fn validate(path: &str) -> bool {
        let util = Command::new("appstream-util")
            .args(["validate-relax", "--nonet", path])
            .env("LC_ALL", "C")
            .output();
        match util {
            Ok(o) => o.status.success(),
            Err(_) => std::fs::read_to_string(path)
                .map(|t| Self::is_well_formed_xml(&t))
                .unwrap_or(false),
        }
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
            if !Self::validate(&pkgfile.path) {
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
