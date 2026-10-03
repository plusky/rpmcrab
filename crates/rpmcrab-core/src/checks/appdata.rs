//! `AppDataCheck` — AppStream metadata validation.
//!
//! Ported from `rpmlint/checks/AppDataCheck.py`. One finding:
//! `invalid-appdata-file`.
//!
//! The reference runs `appstream-util validate-relax --nonet` when the tool
//! is present and falls back to a bare XML well-formedness check when it is
//! absent. This port keeps that two-path shape, deliberately: when the real
//! validator is available it is deferred to entirely, because second-guessing
//! it with a stricter native tag check would emit findings the reference
//! never produces. The native path is an extension of the reference's
//! fallback (ledgered): files under `/usr/share/metainfo/` are scanned too —
//! the reference only looks at `/usr/share/appdata/`, but metainfo is the
//! current AppStream location — and the fallback additionally requires the
//! mandatory AppStream tags, where the reference only checks well-formedness.
//!
//! The mandatory licence tag is `metadata_license` (AppStream §2 "Metainfo
//! Files"); `licence`/`project_license` are accepted as alternatives so
//! legacy files are not flagged. The required set is type-aware: `id`,
//! `name`, `summary` and the licence for every component, plus `description`
//! only where the spec mandates it (`desktop-application`, and `desktop`,
//! its legacy alias) — a fixed set false-positives on legitimate types like
//! `generic`, which needs no `description`.

use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::tools::{Tool, ToolSource, test_source};

/// AppStream's mandatory licence tag is `metadata_license`
/// (§2 "Metainfo Files"; `project_license` is explicitly optional).
/// The commonly-misspelled `licence` is a Fedora-era misspelling, not an
/// AppStream tag; it is accepted alongside the legacy `project_license`
/// spelling so legacy files are not flagged.
const LICENCE_TAGS: [&str; 3] = ["metadata_license", "licence", "project_license"];

/// Required tags for every component type (AppStream §2).
const BASE_REQUIRED_TAGS: [&str; 3] = ["id", "name", "summary"];

/// Component types whose required set includes `description` (AppStream §2.3;
/// `desktop` is the legacy alias of `desktop-application`).
fn description_required(component_type: Option<&str>) -> bool {
    matches!(
        component_type,
        Some("desktop-application") | Some("desktop")
    )
}

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

/// What `walk_xml` recovers from a document: the root `<component>`'s
/// `type` attribute and its direct children's tag names.
struct ComponentShape {
    component_type: Option<String>,
    children: HashSet<String>,
}

/// The `type` attribute's value in a raw attribute slice, if present.
fn type_attr(attrs: &[char]) -> Option<String> {
    let s: String = attrs.iter().collect();
    let mut rest = s.as_str();
    while let Some(pos) = rest.find("type") {
        let before = &rest[..pos];
        let after = &rest[pos + "type".len()..];
        // `type` must be a standalone attribute name: a boundary before it
        // (so `prototype` does not match) and `=` after it.
        let boundary = before.is_empty()
            || before
                .chars()
                .next_back()
                .is_some_and(|c| c.is_whitespace());
        if boundary && let Some(val) = after.trim_start().strip_prefix('=') {
            let val = val.trim_start();
            let quote = val.chars().next()?;
            if quote == '"' || quote == '\'' {
                let inner = &val[quote.len_utf8()..];
                return inner.find(quote).map(|end| inner[..end].to_string());
            }
            return None;
        }
        rest = after;
    }
    None
}

/// Walk the document, checking XML well-formedness. Undefined entity
/// references (the reference's ElementTree.parse rejects them) also fail
/// the walk. Returns the component shape, or `None` when malformed.
fn walk_xml(text: &str) -> Option<ComponentShape> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut i = 0;
    let mut stack: Vec<String> = Vec::new();
    let mut root_seen = false;
    let mut component_type: Option<String> = None;
    let mut children: HashSet<String> = HashSet::new();

    while i < n {
        // Find next '<', checking text content for undefined entities
        // (the reference's ElementTree rejects them).
        let text_start = i;
        while i < n && chars[i] != '<' {
            i += 1;
        }
        let text: String = chars[text_start..i].iter().collect();
        if AppDataCheck::has_undefined_entity(&text) {
            return None;
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

        // Skip attributes, watching for '/>'. Attribute values are
        // checked for undefined entities (the reference's ElementTree
        // rejects them).
        let attrs_start = i;
        let mut self_closing = false;
        let mut in_quote: Option<char> = None;
        let mut attr_start = 0;
        while i < n && chars[i] != '>' {
            let ch = chars[i];
            if let Some(q) = in_quote {
                if ch == q {
                    let value: String = chars[attr_start..i].iter().collect();
                    if AppDataCheck::has_undefined_entity(&value) {
                        return None;
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
                return None; // second root element
            }
            root_seen = true;
            component_type = type_attr(&chars[attrs_start..i]);
        } else if stack.len() == 1 {
            // Direct child of the root element.
            children.insert(name.clone());
        }
        if !self_closing {
            stack.push(name);
        }
    }
    if root_seen && stack.is_empty() {
        Some(ComponentShape {
            component_type,
            children,
        })
    } else {
        None
    }
}

/// Required tags absent from the component, in spec order: `id`, `name`,
/// `summary`, `metadata_license`, then `description` for component types
/// that mandate it. A missing licence is reported as `metadata_license`,
/// the mandatory spelling; `licence`/`project_license` satisfy it.
fn missing_required_tags(shape: &ComponentShape) -> Vec<String> {
    let mut missing = Vec::new();
    for tag in BASE_REQUIRED_TAGS {
        if !shape.children.contains(tag) {
            missing.push(tag.to_string());
        }
    }
    if !LICENCE_TAGS.iter().any(|t| shape.children.contains(*t)) {
        missing.push("metadata_license".to_string());
    }
    if description_required(shape.component_type.as_deref())
        && !shape.children.contains("description")
    {
        missing.push("description".to_string());
    }
    missing
}

/// Native validation: XML well-formedness plus required AppStream tags.
fn native_validate(text: &str) -> NativeOutcome {
    match walk_xml(text) {
        None => NativeOutcome::Malformed,
        Some(shape) => {
            let missing = missing_required_tags(&shape);
            if missing.is_empty() {
                NativeOutcome::Ok
            } else {
                NativeOutcome::MissingTags(missing)
            }
        }
    }
}

static FILE_REGEX: OnceLock<Regex> = OnceLock::new();
fn file_regex() -> &'static Regex {
    FILE_REGEX.get_or_init(|| {
        Regex::new(r"^/usr/share/(appdata|metainfo)/.*\.(appdata|metainfo).xml$")
            .expect("static regex")
    })
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
            file_regex: file_regex().clone(),
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
        let shape = walk_xml("<component><id>x</id><name>y</name></component>").unwrap();
        let children = &shape.children;
        assert!(children.contains("id"));
        assert!(children.contains("name"));
        assert!(!children.contains("component"));
    }

    #[test]
    fn nested_tags_are_not_root_children() {
        let shape = walk_xml(
            "<component><description><p><name>nested</name></p></description></component>",
        )
        .unwrap();
        let children = &shape.children;
        assert!(!children.contains("name"));
        assert!(children.contains("description"));
    }

    #[test]
    fn self_closing_root_child_is_collected() {
        let shape = walk_xml("<component><launchable/></component>").unwrap();
        let children = &shape.children;
        assert!(children.contains("launchable"));
    }

    #[test]
    fn root_type_attribute_is_captured() {
        let shape =
            walk_xml(r#"<component type="desktop-application"><id>x</id></component>"#).unwrap();
        assert_eq!(shape.component_type.as_deref(), Some("desktop-application"));
    }

    #[test]
    fn missing_type_attribute_is_none() {
        let shape = walk_xml("<component><id>x</id></component>").unwrap();
        assert_eq!(shape.component_type, None);
    }

    #[test]
    fn type_like_attribute_names_do_not_match() {
        // `prototype` contains "type" but is not the type attribute.
        let shape = walk_xml(r#"<component prototype="x"><id>y</id></component>"#).unwrap();
        assert_eq!(shape.component_type, None);
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
             /usr/share/metainfo/org.example.foo.metainfo.xml: missing required tag(s): summary, metadata_license, description"
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

    /// A real spec-compliant file — `metadata_license`, no
    /// `project_license` (the shape of e.g. gstreamer-plugins-base's
    /// appdata file, which the old `licence` requirement false-positived
    /// on) — is silent.
    const SPEC_COMPLIANT_NO_PROJECT_LICENSE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<component type="codec">
  <id>org.example.codec</id>
  <metadata_license>CC0-1.0</metadata_license>
  <name>Example codec</name>
  <summary>Decodes examples</summary>
  <description><p>Fixture.</p></description>
</component>
"#;

    #[test]
    fn metadata_license_without_project_license_is_silent() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let (pkg, tool_dir) = appdata_pkg(
            dir.path(),
            &[(
                "usr/share/metainfo/org.example.codec.metainfo.xml",
                SPEC_COMPLIANT_NO_PROJECT_LICENSE,
            )],
        );
        assert!(findings_for(&pkg, tool_dir.path()).is_empty());
    }

    /// `licence`/`project_license` are accepted as alternatives to the
    /// mandatory `metadata_license` spelling.
    #[test]
    fn legacy_licence_spellings_satisfy_the_requirement() {
        for tag in ["licence", "project_license"] {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<component type="generic">
  <id>org.example.foo</id>
  <{tag}>CC0-1.0</{tag}>
  <name>Foo</name>
  <summary>Does foo things</summary>
</component>
"#
            );
            let dir = tempfile::tempdir().expect("tmpdir");
            let (pkg, tool_dir) = appdata_pkg(
                dir.path(),
                &[("usr/share/metainfo/org.example.foo.metainfo.xml", &xml)],
            );
            assert!(findings_for(&pkg, tool_dir.path()).is_empty(), "tag: {tag}");
        }
    }

    /// No licence tag at all is reported as the mandatory spelling.
    #[test]
    fn missing_licence_is_reported_as_metadata_license() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<component type="generic">
  <id>org.example.foo</id>
  <name>Foo</name>
  <summary>Does foo things</summary>
</component>
"#;
        let dir = tempfile::tempdir().expect("tmpdir");
        let (pkg, tool_dir) = appdata_pkg(
            dir.path(),
            &[("usr/share/metainfo/org.example.foo.metainfo.xml", xml)],
        );
        let results = findings_for(&pkg, tool_dir.path());
        assert_eq!(results.len(), 1, "results: {results:?}");
        assert!(
            results[0]
                .1
                .contains("missing required tag(s): metadata_license")
        );
    }

    /// `generic` needs no `description`; `desktop-application` does.
    #[test]
    fn required_set_is_type_aware() {
        let generic = r#"<?xml version="1.0" encoding="UTF-8"?>
<component type="generic">
  <id>org.example.foo</id>
  <metadata_license>CC0-1.0</metadata_license>
  <name>Foo</name>
  <summary>Does foo things</summary>
</component>
"#;
        let dir = tempfile::tempdir().expect("tmpdir");
        let (pkg, tool_dir) = appdata_pkg(
            dir.path(),
            &[("usr/share/metainfo/org.example.foo.metainfo.xml", generic)],
        );
        assert!(
            findings_for(&pkg, tool_dir.path()).is_empty(),
            "generic without description must be silent"
        );

        let desktop_no_desc = generic.replace(
            r#"<component type="generic">"#,
            r#"<component type="desktop-application">"#,
        );
        let dir = tempfile::tempdir().expect("tmpdir");
        let (pkg, tool_dir) = appdata_pkg(
            dir.path(),
            &[(
                "usr/share/metainfo/org.example.foo.metainfo.xml",
                &desktop_no_desc,
            )],
        );
        let results = findings_for(&pkg, tool_dir.path());
        assert_eq!(results.len(), 1, "results: {results:?}");
        assert!(
            results[0]
                .1
                .contains("missing required tag(s): description")
        );
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
