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
    ///
    /// Returns `Err` when the validator's output is not valid UTF-8. The
    /// validator must run under the reference's locale (`LC_ALL=en_US.UTF-8`):
    /// there glib echoes the offending bytes raw, so the strict decode raises
    /// and the outer handler emits only `non-utf8-desktopfile` without ever
    /// parsing. Under `LC_ALL=C` glib escapes the bytes instead and the decode
    /// succeeds, producing spurious `invalid-desktopfile` findings.
    fn external_validate(&self, path: &str) -> Result<Vec<String>, std::string::FromUtf8Error> {
        let Some(mut cmd) = self.validator.command() else {
            return Ok(Vec::new());
        };
        let out = cmd
            .arg(path)
            .env("LC_ALL", "en_US.UTF-8")
            .env("LANGUAGE", "en_US")
            .output();
        let Ok(out) = out else { return Ok(Vec::new()) };
        if out.status.success() {
            return Ok(Vec::new());
        }
        // Decode the concatenated bytes once: a multi-byte sequence
        // straddling the stdout/stderr boundary must not fail the decode.
        let mut combined = out.stdout;
        combined.extend_from_slice(&out.stderr);
        let text = String::from_utf8(combined)?;
        Ok(Self::parse_validate_output(&text))
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

impl MenuXDGCheck {
    /// Upstream rpmlint#19: desktop entries with unexpanded RPM macros
    /// (`Name=%{title}`) — the macro was never expanded at build time.
    /// Only the display fields are scanned; `Exec=` legitimately contains
    /// `%`-codes (`%f`, `%U`) but never `%{`.
    fn check_unexpanded_macros(
        &self,
        pkg: &Pkg,
        out: &mut Filter,
        filename: &str,
        entry: &HashMap<String, String>,
    ) {
        // Keys are already lowercased by parse_desktop.
        for (key, field) in [("name", "Name"), ("comment", "Comment"), ("icon", "Icon")] {
            if let Some(value) = entry.get(key)
                && value.contains("%{")
            {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "unexpanded-macro-in-desktop-file",
                    &[filename, &format!("{field}={value}")],
                );
            }
        }
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
            // The reference decodes the validator output as UTF-8
            // (`text=True`) under its en_US.UTF-8 locale, where the validator
            // echoes the offending bytes raw; the decode raises and the outer
            // handler emits only non-utf8-desktopfile. Mirror that: on decode
            // failure, skip both the validator findings and the parse.
            let errors = match self.external_validate(&pkgfile.path) {
                Ok(errors) => errors,
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
            for error in errors {
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
                    if let Some(entry) = sections.get("Desktop Entry") {
                        self.check_unexpanded_macros(pkg, out, filename, entry);
                    }
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

    /// Drive check_binary over a hand-written desktop file: the fcprobe
    /// header is only a shell, the payload is the temp file.
    fn run_desktop(content: &str) -> Vec<(String, String)> {
        // Unique temp file: tests run in parallel and must not share one.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("macrotest.desktop");
        std::fs::write(&path, content).unwrap();
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        let name = "/usr/share/applications/macrotest.desktop";
        pkg.files = vec![crate::pkg::pkgfile::PkgFile {
            name: name.to_string(),
            path: path.to_str().unwrap().to_string(),
            mode: 0o100644,
            ..Default::default()
        }];
        let config = Config::default();
        let mut out = Filter::new(&config, crate::color::Color::for_tty(false)).unwrap();
        let mut check = MenuXDGCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        drop(dir);
        results
    }

    // Upstream rpmlint#19: unexpanded macros in desktop entries.
    #[test]
    fn unexpanded_macro_in_name_warns() {
        let results = run_desktop("[Desktop Entry]\nName=%{title}\nExec=foo\n");
        let lines: Vec<&String> = results
            .iter()
            .filter(|(n, _)| n == "unexpanded-macro-in-desktop-file")
            .map(|(_, l)| l)
            .collect();
        assert_eq!(lines.len(), 1, "unexpected: {results:?}");
        assert!(
            lines[0].contains("W: unexpanded-macro-in-desktop-file"),
            "level: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("Name=%{title}"),
            "field detail: {}",
            lines[0]
        );
    }

    #[test]
    fn unexpanded_macro_in_comment_and_icon_warns() {
        let results =
            run_desktop("[Desktop Entry]\nName=Foo\nComment=%{summary}\nIcon=%{icon}\nExec=foo\n");
        let names: Vec<&str> = results
            .iter()
            .filter(|(n, _)| n == "unexpanded-macro-in-desktop-file")
            .map(|(n, _)| n.as_str())
            .collect();
        // One finding per offending field.
        assert_eq!(names.len(), 2, "unexpected: {results:?}");
    }

    #[test]
    fn expanded_desktop_entry_is_quiet() {
        // A bare `%` is not a macro: only `%{` marks an unexpanded one.
        let results =
            run_desktop("[Desktop Entry]\nName=100% Foo\nComment=A tool\nIcon=foo\nExec=foo %f\n");
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "unexpanded-macro-in-desktop-file"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn exec_percent_codes_are_not_macros() {
        // `%f`/`%U` in Exec= are desktop field codes, not RPM macros:
        // only Name/Comment/Icon are scanned.
        let results = run_desktop("[Desktop Entry]\nName=Foo\nExec=foo %f %U\n");
        assert!(
            !results
                .iter()
                .any(|(n, _)| n == "unexpanded-macro-in-desktop-file"),
            "unexpected: {results:?}"
        );
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
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
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
