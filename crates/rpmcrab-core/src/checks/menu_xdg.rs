//! `MenuXDGCheck` — XDG desktop file validation.
//!
//! Ported from `rpmlint/checks/MenuXDGCheck.py`. Findings:
//! `invalid-desktopfile`, `desktopfile-missing-header`,
//! `desktopfile-duplicate-section`, `desktopfile-duplicate-option`,
//! `non-utf8-desktopfile`, `desktopfile-without-binary`.
//!
//! The reference runs `desktop-file-validate` and then parses the file with
//! `configparser`. This port runs `desktop-file-validate` when available and
//! always does the native parse: missing header, duplicate sections/options,
//! non-UTF-8, and the Exec binary check.

use std::collections::HashMap;
use std::path::Path;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::tools::{Tool, ToolSource, test_source};

const STANDARD_BIN_DIRS: [&str; 4] = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"];

/// Parsed desktop file: section -> (key -> value).
type DesktopSections = HashMap<String, HashMap<String, String>>;
/// Parse error: (level, finding, details).
type ParseError = (Level, &'static str, Vec<String>);

pub struct MenuXDGCheck {
    file_regex: Regex,
    checked_files: usize,
    validator: Tool,
}

impl MenuXDGCheck {
    pub fn new(_config: &Config) -> Self {
        Self::with_tool_source(ToolSource::Path)
    }

    /// Probe for `desktop-file-validate` under `source`.
    pub fn with_tool_source(source: ToolSource) -> Self {
        let (validator, _) = Tool::probe(&source, "desktop-file-validate", &[]);
        Self {
            // AbstractCheck.py:45 applies this with `re.match`; is_match
            // searches, so anchor it explicitly.
            file_regex: Regex::new(r"^/usr/share/applications/.*\.desktop$").expect("static regex"),
            checked_files: 0,
            validator,
        }
    }

    /// Test entry point: `None` probes the live `PATH`, `Some(dir)`
    /// resolves the tool under `dir` instead of mutating the process
    /// environment.
    pub fn with_tool_dir(bin_dir: Option<&Path>) -> Self {
        Self::with_tool_source(test_source(bin_dir))
    }

    /// Parse a desktop file like `configparser.RawConfigParser`.
    /// Returns the sections on success, or the finding on parse failure.
    ///
    /// Key lookup is case-insensitive: configparser lowercases every key
    /// (`optionxform`), so `Exec` and `EXEC` are the same option.
    fn parse_desktop(content: &str, filename: &str) -> Result<DesktopSections, ParseError> {
        let mut sections: DesktopSections = HashMap::new();
        let mut current: Option<String> = None;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') {
                let end = line.find(']').ok_or_else(|| {
                    // configparser raises MissingSectionHeaderError for a
                    // bracket line outside any section, ParsingError inside
                    // one; the latter renders as invalid-desktopfile.
                    if current.is_none() {
                        (
                            Level::Error,
                            "desktopfile-missing-header",
                            vec![filename.to_string()],
                        )
                    } else {
                        (
                            Level::Error,
                            "invalid-desktopfile",
                            vec![
                                filename.to_string(),
                                "Source contains parsing errors".to_string(),
                            ],
                        )
                    }
                })?;
                let name = line[1..end].to_string();
                if sections.contains_key(&name) {
                    return Err((
                        Level::Error,
                        "desktopfile-duplicate-section",
                        vec![filename.to_string(), format!("[{name}]")],
                    ));
                }
                sections.insert(name.clone(), HashMap::new());
                current = Some(name);
                continue;
            }
            let section = current.clone().ok_or((
                Level::Error,
                "desktopfile-missing-header",
                vec![filename.to_string()],
            ))?;
            let eq = line.find('=').ok_or((
                Level::Error,
                "invalid-desktopfile",
                // configparser's ParsingError message, first colon-part.
                vec![
                    filename.to_string(),
                    "Source contains parsing errors".to_string(),
                ],
            ))?;
            // configparser lowercases keys.
            let key = line[..eq].trim().to_lowercase();
            let value = line[eq + 1..].trim().to_string();
            let map = sections.get_mut(&section).expect("current section");
            if map.contains_key(&key) {
                return Err((
                    Level::Error,
                    "desktopfile-duplicate-option",
                    vec![filename.to_string(), format!("[{section}]/{key}")],
                ));
            }
            map.insert(key, value);
        }
        Ok(sections)
    }

    /// `desktop-file-validate` output, when the tool exists.
    fn external_validate(&self, path: &str) -> Vec<String> {
        let Some(mut cmd) = self.validator.command() else {
            return Vec::new();
        };
        let out = cmd.arg(path).env("LC_ALL", "C").output();
        let Ok(out) = out else { return Vec::new() };
        if out.status.success() {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        Self::parse_validate_output(&text)
    }

    /// Pull `error: ...` messages out of validator output. The reference
    /// takes `line.split('error: ')[1]`; `split().nth(1)` is the same
    /// segment (a second `error: ` truncates the message in both).
    fn parse_validate_output(text: &str) -> Vec<String> {
        let mut errors = Vec::new();
        for line in text.lines() {
            if let Some(msg) = line.split("error: ").nth(1) {
                errors.push(msg.to_string());
            }
        }
        if errors.is_empty() {
            errors.push(String::new());
        }
        errors
    }

    /// Whether the Exec binary resolves (in the package or on the live root).
    fn binary_exists(pkg: &Pkg, binary: &str) -> bool {
        if binary.starts_with('/') {
            let full = Path::new(pkg.dir_name()).join(binary.trim_start_matches('/'));
            return full.exists();
        }
        STANDARD_BIN_DIRS.iter().any(|d| {
            Path::new(pkg.dir_name())
                .join(d.trim_start_matches('/'))
                .join(binary)
                .exists()
        })
    }
}

impl Check for MenuXDGCheck {
    fn name(&self) -> &'static str {
        "MenuXDGCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        for pkgfile in &pkg.files {
            let filename = pkgfile.name.as_str();
            if !is_match(&self.file_regex, filename) {
                continue;
            }
            // AbstractCheck.py:45 drops ghosts from the dispatch list. A ghost
            // desktop file has no payload, so the validator reports it missing
            // and the port would raise invalid-desktopfile for it.
            if pkg.ghost_files.iter().any(|g| g == &pkgfile.name) {
                continue;
            }
            self.checked_files += 1;
            for error in self.external_validate(&pkgfile.path) {
                if error.is_empty() {
                    add_info(out, Level::Error, pkg, "invalid-desktopfile", &[filename]);
                } else {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "invalid-desktopfile",
                        &[filename, &error],
                    );
                }
            }

            let bytes = std::fs::read(&pkgfile.path).unwrap_or_default();
            let content = match String::from_utf8(bytes) {
                Ok(c) => c,
                Err(e) => {
                    let detail = format!("Unicode error: {e}");
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "non-utf8-desktopfile",
                        &[filename, &detail],
                    );
                    continue;
                }
            };
            match Self::parse_desktop(&content, filename) {
                Err((level, finding, details)) => {
                    let refs: Vec<&str> = details.iter().map(String::as_str).collect();
                    add_info(out, level, pkg, finding, &refs);
                }
                Ok(sections) => {
                    if let Some(entry) = sections.get("Desktop Entry")
                        && let Some(exec) = entry.get("exec")
                    {
                        // The reference uses `partition(' ')`, which splits
                        // on the first ASCII space only.
                        let binary = exec.split(' ').next().unwrap_or("");
                        if !binary.is_empty() && !Self::binary_exists(pkg, binary) {
                            add_info(
                                out,
                                Level::Warning,
                                pkg,
                                "desktopfile-without-binary",
                                &[filename, binary],
                            );
                        }
                    }
                }
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
    use std::path::Path;

    use crate::color::Color;
    use crate::pkg::pkgfile::PkgFile;

    #[test]
    fn valid_desktop_parses() {
        let content = "[Desktop Entry]\nName=Foo\nExec=foo\n";
        let sections = MenuXDGCheck::parse_desktop(content, "foo.desktop").unwrap();
        // configparser lowercases keys.
        assert_eq!(sections["Desktop Entry"]["exec"], "foo".to_string());
    }

    #[test]
    fn keys_are_case_insensitive() {
        let content = "[Desktop Entry]\nName=Foo\nEXEC=foo\nExec=bar\n";
        let err = MenuXDGCheck::parse_desktop(content, "foo.desktop").unwrap_err();
        assert_eq!(err.1, "desktopfile-duplicate-option");
    }

    #[test]
    fn unclosed_bracket_before_section_is_missing_header() {
        // configparser raises MissingSectionHeaderError here.
        let err = MenuXDGCheck::parse_desktop("[foo\nName=Bar\n", "foo.desktop").unwrap_err();
        assert_eq!(err.1, "desktopfile-missing-header");
    }

    #[test]
    fn unclosed_bracket_in_section_is_invalid() {
        // configparser raises ParsingError here.
        let err = MenuXDGCheck::parse_desktop("[a]\nName=Foo\n[bad\n", "foo.desktop").unwrap_err();
        assert_eq!(err.1, "invalid-desktopfile");
        assert_eq!(err.2[1], "Source contains parsing errors");
    }

    #[test]
    fn missing_equals_is_invalid() {
        let err = MenuXDGCheck::parse_desktop("[a]\nName Foo\n", "foo.desktop").unwrap_err();
        assert_eq!(err.1, "invalid-desktopfile");
        assert_eq!(err.2[1], "Source contains parsing errors");
    }

    #[test]
    fn missing_header_is_flagged() {
        let err = MenuXDGCheck::parse_desktop("Name=Foo\n", "foo.desktop").unwrap_err();
        assert_eq!(err.1, "desktopfile-missing-header");
    }

    #[test]
    fn duplicate_section_is_flagged() {
        let content = "[Desktop Entry]\nName=Foo\n[Desktop Entry]\nName=Bar\n";
        let err = MenuXDGCheck::parse_desktop(content, "foo.desktop").unwrap_err();
        assert_eq!(err.1, "desktopfile-duplicate-section");
        assert!(err.2[1].contains("Desktop Entry"));
    }

    #[test]
    fn duplicate_option_is_flagged() {
        let content = "[Desktop Entry]\nName=Foo\nName=Bar\n";
        let err = MenuXDGCheck::parse_desktop(content, "foo.desktop").unwrap_err();
        assert_eq!(err.1, "desktopfile-duplicate-option");
    }

    #[test]
    fn comments_and_blanks_are_skipped() {
        let content = "# comment\n\n[Desktop Entry]\n; another\nName=Foo\n";
        let sections = MenuXDGCheck::parse_desktop(content, "foo.desktop").unwrap();
        assert!(sections.contains_key("Desktop Entry"));
    }

    #[test]
    fn validate_output_truncates_at_second_error_marker() {
        // Matches Python's `line.split('error: ')[1]`.
        let errors =
            MenuXDGCheck::parse_validate_output("f.desktop: error: bad value error: tail\n");
        assert_eq!(errors, vec!["bad value ".to_string()]);
    }

    #[test]
    fn validate_output_without_errors_is_empty_detail() {
        let errors = MenuXDGCheck::parse_validate_output("all good\n");
        assert_eq!(errors, vec![String::new()]);
    }

    #[test]
    fn file_pattern_is_anchored_like_re_match() {
        // AbstractCheck.py:45 applies the pattern with `re.match`; is_match
        // searches, so without `^` a vendored copy under /opt would be
        // validated where the reference never dispatches it.
        let check = MenuXDGCheck::new(&Config::default());
        assert!(is_match(
            &check.file_regex,
            "/usr/share/applications/w6.desktop"
        ));
        assert!(!is_match(
            &check.file_regex,
            "/opt/vendor/usr/share/applications/v.desktop"
        ));
    }

    #[test]
    fn non_utf8_desktopfile_is_pinned() {
        // Nothing pins the finding name, level, or the Unicode error prefix,
        // so the divergence entry can rot silently. Pin all three: an
        // invalid-UTF-8 payload must surface as Level::Error
        // non-utf8-desktopfile with a Unicode error detail.
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-menuxdg-nonutf8.desktop");
        std::fs::write(&path, b"[Desktop Entry]\nName=\xff\xfe\n").unwrap();
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir()).expect("open fixture pkg");
        let name = "/usr/share/applications/broken.desktop";
        pkg.files = vec![PkgFile {
            name: name.to_string(),
            path: path.to_str().unwrap().to_string(),
            ..Default::default()
        }];
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = MenuXDGCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        std::fs::remove_file(&path).ok();
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "non-utf8-desktopfile");
        assert!(results[0].1.contains(": E: "), "level: {}", results[0].1);
        assert!(
            results[0].1.contains("Unicode error:"),
            "prefix: {}",
            results[0].1
        );
    }
}
