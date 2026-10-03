//! `AppDataCheck` — AppStream metadata validation.
//!
//! Ported from `rpmlint/checks/AppDataCheck.py`. One finding:
//! `invalid-appdata-file`.
//!
//! The reference runs `appstream-util validate-relax --nonet` and falls back
//! to a bare XML well-formedness check when the tool is absent. This port
//! keeps that shape but extends it (ledgered): files under
//! `/usr/share/metainfo/` are scanned too — the reference only looks at
//! `/usr/share/appdata/`, but metainfo is the current AppStream location —
//! and the native fallback additionally requires the mandatory AppStream
//! tags (`id`, `name`, `summary`, `description`, `licence`).

use std::collections::HashSet;
use std::path::Path;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::tools::{Tool, ToolSource, test_source};

/// Required AppStream component tags. `project_license` satisfies `licence`:
/// it is the current spelling (renamed in AppStream 0.12), so demanding the
/// literal old name would flag every modern file.
const REQUIRED_TAGS: [&str; 5] = ["id", "name", "summary", "description", "licence"];

/// Outcome of the native (no `appstream-util`) validation.
#[derive(Debug, PartialEq, Eq)]
enum NativeOutcome {
    Ok,
    /// Not well-formed XML, or the file could not be read.
    Malformed,
    /// Well-formed XML missing required AppStream tags.
    MissingTags(Vec<String>),
}

pub struct AppDataCheck {
    file_regex: Regex,
    checked_files: usize,
    tool: Tool,
}

/// Parse a tag name starting at `i`; leaves `i` just past the name.
fn tag_name(chars: &[char], i: &mut usize) -> String {
    let start = *i;
    while *i < chars.len() && !chars[*i].is_whitespace() && chars[*i] != '>' && chars[*i] != '/' {
        *i += 1;
    }
    chars[start..*i].iter().collect()
}

/// Walk the document, checking XML well-formedness. Returns the tag names of
/// the root element's direct children, or `None` when malformed.
fn walk_xml(text: &str) -> Option<HashSet<String>> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut i = 0;
    let mut stack: Vec<String> = Vec::new();
    let mut root_seen = false;
    let mut children: HashSet<String> = HashSet::new();

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
            return None;
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
            let name = tag_name(&chars, &mut i);
            while i < n && chars[i] != '>' {
                i += 1;
            }
            i += 1; // skip '>'
            if stack.pop().as_deref() != Some(name.as_str()) {
                return None;
            }
            continue;
        }

        // Opening tag
        let name = tag_name(&chars, &mut i);
        if name.is_empty() {
            return None;
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
                return None; // second root element
            }
            root_seen = true;
        } else if stack.len() == 1 {
            // Direct child of the root element.
            children.insert(name.clone());
        }
        if !self_closing {
            stack.push(name);
        }
    }
    if root_seen && stack.is_empty() {
        Some(children)
    } else {
        None
    }
}

/// Required tags absent from the root's direct children, in
/// [`REQUIRED_TAGS`] order.
fn missing_required_tags(children: &HashSet<String>) -> Vec<String> {
    REQUIRED_TAGS
        .iter()
        .filter(|tag| {
            if **tag == "licence" {
                !(children.contains("licence") || children.contains("project_license"))
            } else {
                !children.contains(**tag)
            }
        })
        .map(|s| s.to_string())
        .collect()
}

/// Native validation: XML well-formedness plus required AppStream tags.
fn native_validate(text: &str) -> NativeOutcome {
    match walk_xml(text) {
        None => NativeOutcome::Malformed,
        Some(children) => {
            let missing = missing_required_tags(&children);
            if missing.is_empty() {
                NativeOutcome::Ok
            } else {
                NativeOutcome::MissingTags(missing)
            }
        }
    }
}

impl AppDataCheck {
    pub fn new(_config: &Config) -> Self {
        Self::with_tool_source(ToolSource::Path)
    }

    /// Resolve `appstream-util` under `source`. Tests pass
    /// `ToolSource::Dir` pointing at a scratch dir: a fake named
    /// `appstream-util` there is used, an empty dir forces the native
    /// fallback.
    pub fn with_tool_source(source: ToolSource) -> Self {
        let (tool, _) = Tool::probe(&source, "appstream-util", &["--version"]);
        Self {
            // The reference passes `/usr/share/appdata/.*\.(appdata|metainfo).xml$`
            // to AbstractFilesCheck, which applies it with `re.match`
            // (AbstractCheck.py:45), so it is anchored at the start; is_match
            // searches, hence the explicit `^`. The dot before `xml` is
            // unescaped in the reference pattern and stays that way here: it
            // matches any character, so `foo.appdata_xml` is validated
            // upstream and must be here too. `/usr/share/metainfo/` is a
            // deliberate extension (ledgered): the reference predates it.
            file_regex: Regex::new(r"^/usr/share/(appdata|metainfo)/.*\.(appdata|metainfo).xml$")
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

    /// Minimal XML well-formedness check: balanced tags, single root.
    #[cfg(test)]
    fn is_well_formed_xml(text: &str) -> bool {
        walk_xml(text).is_some()
    }

    /// Validate one file: the configured `appstream-util` when present,
    /// else native well-formedness plus required-tag validation.
    fn validate(&self, path: &str) -> NativeOutcome {
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
                return if o.status.success() {
                    NativeOutcome::Ok
                } else {
                    // Detail stays the bare filename, like the reference.
                    NativeOutcome::Malformed
                };
            }
        }
        std::fs::read_to_string(path)
            .map(|t| native_validate(&t))
            .unwrap_or(NativeOutcome::Malformed)
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
            let detail = match self.validate(&pkgfile.path) {
                NativeOutcome::Ok => continue,
                // The reference reports the bare filename.
                NativeOutcome::Malformed => pkgfile.name.clone(),
                NativeOutcome::MissingTags(tags) => {
                    format!(
                        "{}: missing required tag(s): {}",
                        pkgfile.name,
                        tags.join(", ")
                    )
                }
            };
            add_info(out, Level::Error, pkg, "invalid-appdata-file", &[&detail]);
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
    use crate::color::Color;
    use crate::pkg::pkgfile::PkgFile;

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

    #[test]
    fn file_regex_matches_metainfo_dir() {
        let check = AppDataCheck::new(&Config::default());
        assert!(is_match(
            &check.file_regex,
            "/usr/share/metainfo/org.example.foo.metainfo.xml"
        ));
        assert!(is_match(
            &check.file_regex,
            "/usr/share/metainfo/foo.appdata.xml"
        ));
        assert!(!is_match(
            &check.file_regex,
            "/usr/share/doc/org.example.foo.metainfo.xml"
        ));
    }

    #[test]
    fn root_children_are_collected() {
        let children = walk_xml("<component><id>x</id><name>y</name></component>").unwrap();
        assert!(children.contains("id"));
        assert!(children.contains("name"));
        assert!(!children.contains("component"));
    }

    #[test]
    fn nested_tags_are_not_root_children() {
        let children = walk_xml(
            "<component><description><p><name>nested</name></p></description></component>",
        )
        .unwrap();
        assert!(!children.contains("name"));
        assert!(children.contains("description"));
    }

    #[test]
    fn self_closing_root_child_is_collected() {
        let children = walk_xml("<component><launchable/></component>").unwrap();
        assert!(children.contains("launchable"));
    }

    const COMPLETE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop">
  <id>org.example.foo</id>
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>GPL-3.0-or-later</project_license>
  <name>Foo</name>
  <summary>Does foo things</summary>
  <description><p>Foo bar.</p></description>
</component>
"#;

    const MISSING_ID: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop">
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>GPL-3.0-or-later</project_license>
  <name>Foo</name>
  <summary>Does foo things</summary>
  <description><p>Foo bar.</p></description>
</component>
"#;

    const MISSING_SEVERAL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop">
  <id>org.example.foo</id>
  <name>Foo</name>
</component>
"#;

    const MALFORMED: &str = "<component><name>Foo</name>";

    /// Build a package holding the given `(relative path, content)` files,
    /// forcing the native validation fallback (empty tool dir, so no
    /// `appstream-util` is resolved).
    fn appdata_pkg(dir: &std::path::Path, files: &[(&str, &str)]) -> (Pkg, tempfile::TempDir) {
        let mut pkg = Pkg::open(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm"),
            &std::env::temp_dir(),
            true,
        )
        .expect("open fixture pkg");
        pkg.name = "appdata-test".to_string();
        pkg.files.clear();
        for (rel, content) in files {
            let path = dir.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
            std::fs::write(&path, content).expect("write xml");
            pkg.files.push(PkgFile {
                name: format!("/{rel}"),
                path: path.to_string_lossy().into_owned(),
                mode: 0o100644,
                ..Default::default()
            });
        }
        let tool_dir = tempfile::tempdir().expect("tool dir");
        (pkg, tool_dir)
    }

    fn findings_for(pkg: &Pkg, tool_dir: &Path) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = AppDataCheck::with_tool_dir(Some(tool_dir));
        check.check_binary(pkg, &config, &mut out);
        out.results().to_vec()
    }

    /// A metainfo file missing `id` warns with the missing tags in the detail.
    #[test]
    fn metainfo_missing_id_warns_with_detail() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let (pkg, tool_dir) = appdata_pkg(
            dir.path(),
            &[(
                "usr/share/metainfo/org.example.foo.metainfo.xml",
                MISSING_ID,
            )],
        );
        let results = findings_for(&pkg, tool_dir.path());
        assert_eq!(results.len(), 1, "results: {results:?}");
        assert_eq!(results[0].0, "invalid-appdata-file");
        assert_eq!(
            results[0].1,
            "appdata-test.noarch: E: invalid-appdata-file \
             /usr/share/metainfo/org.example.foo.metainfo.xml: missing required tag(s): id"
        );
    }

    /// A metainfo file missing several tags lists them all in order.
    #[test]
    fn metainfo_missing_several_tags_lists_all() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let (pkg, tool_dir) = appdata_pkg(
            dir.path(),
            &[(
                "usr/share/metainfo/org.example.foo.metainfo.xml",
                MISSING_SEVERAL,
            )],
        );
        let results = findings_for(&pkg, tool_dir.path());
        assert_eq!(results.len(), 1, "results: {results:?}");
        assert_eq!(results[0].0, "invalid-appdata-file");
        assert_eq!(
            results[0].1,
            "appdata-test.noarch: E: invalid-appdata-file \
             /usr/share/metainfo/org.example.foo.metainfo.xml: missing required tag(s): summary, description, licence"
        );
    }

    /// A complete metainfo file is silent.
    #[test]
    fn metainfo_complete_file_is_silent() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let (pkg, tool_dir) = appdata_pkg(
            dir.path(),
            &[("usr/share/metainfo/org.example.foo.metainfo.xml", COMPLETE)],
        );
        let results = findings_for(&pkg, tool_dir.path());
        assert!(results.is_empty(), "results: {results:?}");
    }

    /// `project_license` satisfies the `licence` requirement.
    #[test]
    fn project_license_satisfies_licence() {
        // COMPLETE uses project_license and no licence tag.
        let dir = tempfile::tempdir().expect("tmpdir");
        let (pkg, tool_dir) = appdata_pkg(
            dir.path(),
            &[("usr/share/metainfo/org.example.foo.metainfo.xml", COMPLETE)],
        );
        assert!(findings_for(&pkg, tool_dir.path()).is_empty());
    }

    /// Malformed XML keeps the reference's bare-filename detail.
    #[test]
    fn malformed_metainfo_warns_with_filename() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let (pkg, tool_dir) = appdata_pkg(
            dir.path(),
            &[("usr/share/metainfo/org.example.foo.metainfo.xml", MALFORMED)],
        );
        let results = findings_for(&pkg, tool_dir.path());
        assert_eq!(results.len(), 1, "results: {results:?}");
        assert_eq!(results[0].0, "invalid-appdata-file");
        assert_eq!(
            results[0].1,
            "appdata-test.noarch: E: invalid-appdata-file \
             /usr/share/metainfo/org.example.foo.metainfo.xml"
        );
    }

    /// The legacy `/usr/share/appdata/` location is still scanned.
    #[test]
    fn appdata_dir_missing_tag_warns() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let (pkg, tool_dir) = appdata_pkg(
            dir.path(),
            &[("usr/share/appdata/foo.appdata.xml", MISSING_ID)],
        );
        let results = findings_for(&pkg, tool_dir.path());
        assert_eq!(results.len(), 1, "results: {results:?}");
        assert_eq!(results[0].0, "invalid-appdata-file");
        assert!(results[0].1.contains("missing required tag(s): id"));
    }
}
