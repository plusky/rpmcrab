//! `PolkitCheck` — polkit policy whitelisting.
//!
//! Ported from `rpmlint/checks/PolkitCheck.py`. Findings:
//! `polkit-ghost-file`, `polkit-xml-exception`, `polkit-user-privilege`,
//! `polkit-untracked-privilege`.
//!
//! The reference reads the `polkit-default-privs` standard profile from the
//! live filesystem (`PolkitPrivsFiles`, default
//! `/usr/etc/polkit-default-privs/profiles/standard`); an action whose id is
//! listed there is whitelisted.

use std::collections::HashMap;

use quick_xml::Reader;
use quick_xml::XmlVersion;
use quick_xml::events::Event;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

/// Parsed actions: (action_id, defaults).
type PolkitActions = Vec<(String, HashMap<String, String>)>;

/// An `<action>` element whose end tag has not been seen yet: its slot in
/// the result vector, plus whether its `<defaults>` is currently open.
/// Nested `<action>` elements are pathological (polkit rejects them), but
/// each level needs its own state so an inner `<defaults>` cannot clobber
/// the outer action's.
struct OpenAction {
    idx: usize,
    in_defaults: bool,
}

pub struct PolkitCheck {
    privs: HashMap<String, String>,
}

impl PolkitCheck {
    pub fn new(config: &Config) -> Self {
        let mut privs = HashMap::new();
        let files = config
            .configuration
            .get("PolkitPrivsFiles")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["/usr/etc/polkit-default-privs/profiles/standard".to_string()]);
        for filename in &files {
            Self::parse_privs_file(filename, &mut privs);
        }
        Self { privs }
    }

    /// Parse a `polkit-default-privs` profile: `action value` per line,
    /// `#` comments stripped. Lines with fewer than two tokens are skipped
    /// and both line ends are trimmed; both are deliberate divergences from
    /// the reference (see divergences.toml), which crashes the whole run on
    /// a one-token line and whitelists an empty action id for indented ones.
    fn parse_privs_file(filename: &str, privs: &mut HashMap<String, String>) {
        let Ok(content) = std::fs::read_to_string(filename) else {
            return;
        };
        for line in content.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                privs.insert(parts[0].to_string(), parts[1].to_string());
            }
        }
    }

    /// Check one `<action>` element. Returns the finding, if any.
    fn check_action(
        &self,
        action_id: &str,
        defaults: &HashMap<String, String>,
    ) -> Option<(Level, String, String)> {
        if self.privs.contains_key(action_id) {
            return None;
        }
        let allow_types = ["allow_any", "allow_inactive", "allow_active"];
        let mut settings: HashMap<&str, &str> = HashMap::new();
        let mut found_unauthorized = false;
        for t in allow_types {
            match defaults.get(t) {
                Some(v) => {
                    settings.insert(t, v.as_str());
                    if !v.starts_with("auth_admin") && *v != "no" {
                        found_unauthorized = true;
                    }
                }
                None => {
                    // Absent means polkit defaults to `no`.
                    settings.insert(t, "no");
                }
            }
        }
        let detail = format!(
            "{} ({}:{}:{})",
            action_id, settings["allow_any"], settings["allow_inactive"], settings["allow_active"]
        );
        if found_unauthorized {
            Some((Level::Error, "polkit-user-privilege".to_string(), detail))
        } else {
            Some((
                Level::Error,
                "polkit-untracked-privilege".to_string(),
                detail,
            ))
        }
    }

    /// `action.getAttribute('id')`: '' when the attribute is absent.
    fn action_id(attrs: quick_xml::events::attributes::Attributes<'_>) -> String {
        for attr in attrs.flatten() {
            if attr.key.as_ref() == "id" {
                return attr
                    .normalized_value(XmlVersion::Implicit1_0)
                    .map(|v| v.into_owned())
                    .unwrap_or_default();
            }
        }
        String::new()
    }

    /// Parse a polkit policy file, returning `(action_id, defaults)` pairs.
    /// Err on malformed XML (the reference's `polkit-xml-exception`).
    fn parse_actions(path: &str) -> Result<PolkitActions, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut reader = Reader::from_str(&content);
        reader.config_mut().trim_text(true);
        // The reference parses with minidom, which rejects any not-well-formed
        // XML. quick-xml is laxer by default: count open elements so unclosed
        // tags at EOF error, and check end-tag names so mismatches error.
        reader.config_mut().check_end_names = true;
        let mut depth = 0u32;
        let mut actions: PolkitActions = Vec::new();
        // Open `<action>` elements, innermost last. Each action takes its
        // result slot at its start tag: the reference's minidom
        // `getElementsByTagName` yields document order, and pushing at the
        // end tag reported a nested self-closing action before its parent.
        let mut open: Vec<OpenAction> = Vec::new();
        let mut current_setting: Option<String> = None;
        let mut current_text = String::new();

        loop {
            match reader.read_event() {
                Ok(Event::Start(e)) => {
                    depth += 1;
                    match e.name().as_ref() {
                        "action" => {
                            // `action.getAttribute('id')` (PolkitCheck.py:61)
                            // yields '' for an action with no id, and the
                            // action is still evaluated. Dropping it instead
                            // would silently skip a privilege declaration.
                            actions.push((Self::action_id(e.attributes()), HashMap::new()));
                            open.push(OpenAction {
                                idx: actions.len() - 1,
                                in_defaults: false,
                            });
                        }
                        "defaults" => {
                            if let Some(top) = open.last_mut() {
                                top.in_defaults = true;
                            }
                        }
                        "allow_any" | "allow_inactive" | "allow_active"
                            if open.last().is_some_and(|top| top.in_defaults) =>
                        {
                            current_setting = Some(e.name().as_ref().to_owned());
                            current_text.clear();
                        }
                        _ => {}
                    }
                }
                Ok(Event::Text(e)) => {
                    if current_setting.is_some() {
                        current_text.push_str(&e.into_inner());
                    }
                }
                // Since 0.38 entity references are their own events; splice them
                // back into the raw text so the value unescapes as a whole.
                Ok(Event::GeneralRef(e)) => {
                    if current_setting.is_some() {
                        current_text.push('&');
                        current_text.push_str(&e.into_inner());
                        current_text.push(';');
                    }
                }
                Ok(Event::End(e)) => {
                    depth = depth.saturating_sub(1);
                    match e.name().as_ref() {
                        "action" => {
                            open.pop();
                        }
                        "defaults" => {
                            if let Some(top) = open.last_mut() {
                                top.in_defaults = false;
                            }
                        }
                        name @ ("allow_any" | "allow_inactive" | "allow_active")
                            if current_setting.as_deref() == Some(name) =>
                        {
                            let setting = current_setting.take().expect("guard checked");
                            let value = quick_xml::escape::unescape(&current_text)
                                .map(|v| v.into_owned())
                                .unwrap_or_default();
                            current_text.clear();
                            // The setting belongs to the innermost open action;
                            // `check_end_names` guarantees an action is still
                            // open here, the `if let` is just belt and braces.
                            if let Some(top) = open.last() {
                                actions[top.idx].1.insert(setting, value);
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Empty(e)) => {
                    if e.name().as_ref() == "action" {
                        // A self-closing `<action id="x"/>` never yields
                        // Start/End; the reference's minidom reports it as an
                        // action without `<defaults>`, so it takes its
                        // document-order slot like a Start immediately
                        // followed by End.
                        actions.push((Self::action_id(e.attributes()), HashMap::new()));
                    }
                }
                Ok(Event::Eof) => {
                    if depth != 0 {
                        return Err("unclosed element at end of file".to_string());
                    }
                    break;
                }
                Err(e) => return Err(e.to_string()),
                _ => {}
            }
        }
        Ok(actions)
    }
}

impl Check for PolkitCheck {
    fn name(&self) -> &'static str {
        "PolkitCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        const PREFIX: &str = "/usr/share/polkit-1/actions/";
        for pkgfile in &pkg.files {
            let f = pkgfile.name.as_str();
            if !f.starts_with(PREFIX) {
                continue;
            }
            if pkg.ghost_files.iter().any(|g| g == f) {
                add_info(out, Level::Error, pkg, "polkit-ghost-file", &[f]);
                continue;
            }
            match Self::parse_actions(&pkgfile.path) {
                Err(e) => {
                    let detail = format!("{f} raised an exception: {e}");
                    add_info(out, Level::Error, pkg, "polkit-xml-exception", &[&detail]);
                }
                Ok(actions) => {
                    for (action_id, defaults) in &actions {
                        if let Some((level, finding, detail)) =
                            self.check_action(action_id, defaults)
                        {
                            add_info(out, level, pkg, &finding, &[&detail]);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::color::Color;
    use crate::pkg::pkgfile::PkgFile;

    fn check() -> PolkitCheck {
        PolkitCheck {
            privs: HashMap::new(),
        }
    }

    #[test]
    fn whitelisted_action_is_quiet() {
        let mut privs = HashMap::new();
        privs.insert("org.foo.bar".to_string(), "auth_admin".to_string());
        let check = PolkitCheck { privs };
        assert!(check.check_action("org.foo.bar", &HashMap::new()).is_none());
    }

    #[test]
    fn unauthorized_setting_is_flagged() {
        let mut defaults = HashMap::new();
        defaults.insert("allow_any".to_string(), "yes".to_string());
        let found = check().check_action("org.foo.baz", &defaults);
        let (level, finding, detail) = found.expect("finding");
        assert_eq!(level, Level::Error);
        assert_eq!(finding, "polkit-user-privilege");
        assert!(detail.contains("org.foo.baz"));
        assert!(detail.contains("yes:no:no"));
    }

    #[test]
    fn missing_settings_default_to_no() {
        let found = check().check_action("org.foo.baz", &HashMap::new());
        let (_, finding, detail) = found.expect("finding");
        assert_eq!(finding, "polkit-untracked-privilege");
        assert!(detail.contains("no:no:no"));
    }

    #[test]
    fn auth_admin_is_untracked_not_unauthorized() {
        let mut defaults = HashMap::new();
        defaults.insert("allow_any".to_string(), "auth_admin".to_string());
        let (_, finding, _) = check()
            .check_action("org.foo.baz", &defaults)
            .expect("finding");
        assert_eq!(finding, "polkit-untracked-privilege");
    }

    #[test]
    fn privs_file_parsing_strips_comments() {
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-polkit-test.privs");
        std::fs::write(&path, "# comment\norg.foo.bar auth_admin\n\n").unwrap();
        let mut privs = HashMap::new();
        PolkitCheck::parse_privs_file(path.to_str().unwrap(), &mut privs);
        assert_eq!(
            privs.get("org.foo.bar").map(String::as_str),
            Some("auth_admin")
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn unclosed_tags_are_an_error() {
        // The reference parses with minidom and raises on unclosed tags;
        // quick-xml yields Eof without error unless we count depth.
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-polkit-unclosed.policy");
        std::fs::write(&path, "<policyconfig><action id=\"org.foo.bar\"><defaults>").unwrap();
        let err = PolkitCheck::parse_actions(path.to_str().unwrap()).expect_err("must err");
        assert!(err.contains("unclosed"), "unexpected error: {err}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn mismatched_end_tags_are_an_error() {
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-polkit-mismatch.policy");
        std::fs::write(
            &path,
            "<policyconfig><action id=\"org.foo.bar\"></defaults></policyconfig>",
        )
        .unwrap();
        assert!(PolkitCheck::parse_actions(path.to_str().unwrap()).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn parse_actions_unescapes_entities() {
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-polkit-entities.policy");
        std::fs::write(
            &path,
            "<policyconfig><action id=\"org.foo.a&amp;b\"><defaults>\
             <allow_any>yes</allow_any><allow_inactive>a&lt;b</allow_inactive>\
             </defaults></action></policyconfig>",
        )
        .unwrap();
        let actions = PolkitCheck::parse_actions(path.to_str().unwrap()).expect("parse");
        std::fs::remove_file(&path).ok();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].0, "org.foo.a&b");
        assert_eq!(
            actions[0].1.get("allow_any").map(String::as_str),
            Some("yes")
        );
        assert_eq!(
            actions[0].1.get("allow_inactive").map(String::as_str),
            Some("a<b")
        );
    }

    #[test]
    fn action_without_defaults_does_not_crash() {
        // The reference does `action.getElementsByTagName('defaults')[0]`,
        // which raises IndexError (not the caught KeyError) when <defaults>
        // is absent, crashing the check. The port treats the missing
        // settings as `no` per the polkit default and reports
        // polkit-untracked-privilege instead.
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-polkit-nodefaults.policy");
        std::fs::write(
            &path,
            "<policyconfig><action id=\"org.foo.nodefaults\"></action></policyconfig>",
        )
        .unwrap();
        let actions = PolkitCheck::parse_actions(path.to_str().unwrap()).expect("parse");
        std::fs::remove_file(&path).ok();
        assert_eq!(actions.len(), 1);
<<<<<<< HEAD
        let (level, finding, detail) = check()
            .check_action("org.foo.nodefaults", &actions[0].1)
            .expect("finding");
        assert_eq!(level, Level::Error);
=======
        let (_, finding, detail) = check()
            .check_action("org.foo.nodefaults", &actions[0].1)
            .expect("finding");
>>>>>>> cf1e7e7 (perf(checks): cache compiled regexes in OnceLock statics)
        assert_eq!(finding, "polkit-untracked-privilege");
        assert!(detail.contains("no:no:no"), "unexpected detail: {detail}");
    }

    #[test]
    fn action_without_an_id_attribute_is_still_collected() {
        // PolkitCheck.py:61 uses getAttribute('id'), which is '' when the
        // attribute is absent, and the action is still evaluated. Dropping it
        // would silently skip the privilege declaration.
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-polkit-noid.policy");
        std::fs::write(
            &path,
            "<policyconfig><action><defaults>\
             <allow_any>yes</allow_any><allow_inactive>no</allow_inactive>\
             <allow_active>no</allow_active></defaults></action></policyconfig>",
        )
        .unwrap();
        let actions = PolkitCheck::parse_actions(path.to_str().unwrap()).expect("parse");
        std::fs::remove_file(&path).ok();
        let ids: Vec<&str> = actions.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, vec![""], "an <action> without id was dropped: {ids:?}");
    }

    #[test]
    fn ghost_policy_file_is_flagged_not_parsed() {
        // check_binary routes ghost files to polkit-ghost-file without
        // parsing them: a ghost has no payload on disk, so parse_actions
        // would fail on a missing file. This covers the ghost filter that
        // unit tests stopping at check_action never reach.
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        // Header only, no extraction: `files` is overwritten wholesale below.
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        let name = "/usr/share/polkit-1/actions/org.foo.ghost.policy";
        pkg.files = vec![PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            ..Default::default()
        }];
        pkg.ghost_files = vec![name.to_string()];
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = check();
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "polkit-ghost-file");
        assert!(results[0].1.contains(": E: "), "level: {}", results[0].1);
        assert!(results[0].1.contains(name), "detail: {}", results[0].1);
    }

    #[test]
    fn privs_file_skips_one_token_lines() {
        // PolkitCheck.py:36-38 does `priv = line[0]; value = line[1]`, so a
        // one-token line raises IndexError, which escapes the check and kills
        // the whole run (exit 3). The port deliberately skips such lines
        // instead; the divergence is ledgered in divergences.toml.
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-polkit-onetoken.privs");
        std::fs::write(&path, "org.foo.lonely\norg.foo.bar auth_admin\n").unwrap();
        let mut privs = HashMap::new();
        PolkitCheck::parse_privs_file(path.to_str().unwrap(), &mut privs);
        std::fs::remove_file(&path).ok();
        assert_eq!(privs.len(), 1, "one-token line leaked in: {privs:?}");
        assert_eq!(
            privs.get("org.foo.bar").map(String::as_str),
            Some("auth_admin")
        );
    }

    #[test]
    fn privs_file_trims_indented_lines() {
        // The reference strips comments with `line.split('#')[0].rstrip()`
        // (PolkitCheck.py:34); on an indented line its `re.split(r'\s+',
        // ...)` yields a leading empty token, so it whitelists the empty
        // action id with the real id as its value. The port trims both ends;
        // the divergence is ledgered in divergences.toml.
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-polkit-indented.privs");
        std::fs::write(&path, "  org.foo.indented bar\n").unwrap();
        let mut privs = HashMap::new();
        PolkitCheck::parse_privs_file(path.to_str().unwrap(), &mut privs);
        std::fs::remove_file(&path).ok();
        assert!(!privs.contains_key(""), "empty-key wart: {privs:?}");
        assert_eq!(
            privs.get("org.foo.indented").map(String::as_str),
            Some("bar")
        );
    }

    #[test]
    fn self_closing_action_reports_untracked_privilege() {
        // quick-xml reports `<action id="x"/>` as Event::Empty (no
        // Start/End); the reference's minidom sees it as an action without
        // <defaults>, which flows through the ledgered no-defaults path.
        // Without the Empty handling no finding is emitted at all.
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-polkit-selfclosing.policy");
        std::fs::write(
            &path,
            "<policyconfig><action id=\"org.foo.selfclosed\"/></policyconfig>",
        )
        .unwrap();
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        // Header only, no extraction: `files` is overwritten wholesale below.
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        let name = "/usr/share/polkit-1/actions/org.foo.policy";
        pkg.files = vec![PkgFile {
            name: name.to_string(),
            path: path.to_str().unwrap().to_string(),
            ..Default::default()
        }];
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = check();
        check.check_binary(&pkg, &config, &mut out);
        std::fs::remove_file(&path).ok();
        let results = out.results().to_vec();
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "polkit-untracked-privilege");
        assert!(results[0].1.contains(": E: "), "level: {}", results[0].1);
        assert!(
            results[0].1.contains("org.foo.selfclosed"),
            "detail: {}",
            results[0].1
        );
        assert!(
            results[0].1.contains("no:no:no"),
            "detail: {}",
            results[0].1
        );
    }

    #[test]
    fn nested_actions_report_in_document_order() {
        // plusky's #185 follow-up nit: minidom's `getElementsByTagName`
        // yields document order, so for pathological nesting
        // `<action id="a"><action id="b"/></action>` the reference reports
        // a before b. The port used to push each action at its end tag, so
        // the self-closing inner action (an `Empty` event, pushed at once)
        // came out before its still-open parent. Reverting the start-tag
        // slotting fails this with the ids swapped.
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-polkit-nested.policy");
        std::fs::write(
            &path,
            "<policyconfig><action id=\"org.foo.outer\"><action id=\"org.foo.inner\"/></action></policyconfig>",
        )
        .unwrap();
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        // Header only, no extraction: `files` is overwritten wholesale below.
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        let name = "/usr/share/polkit-1/actions/org.foo.policy";
        pkg.files = vec![PkgFile {
            name: name.to_string(),
            path: path.to_str().unwrap().to_string(),
            ..Default::default()
        }];
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = check();
        check.check_binary(&pkg, &config, &mut out);
        std::fs::remove_file(&path).ok();
        let results = out.results().to_vec();
        assert_eq!(results.len(), 2, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "polkit-untracked-privilege");
        assert!(results[0].1.contains(": E: "), "level: {}", results[0].1);
        assert!(
            results[0].1.contains("org.foo.outer"),
            "first: {}",
            results[0].1
        );
        assert!(
            results[0].1.contains("no:no:no"),
            "first detail: {}",
            results[0].1
        );
        assert_eq!(results[1].0, "polkit-untracked-privilege");
        assert!(results[1].1.contains(": E: "), "level: {}", results[1].1);
        assert!(
            results[1].1.contains("org.foo.inner"),
            "second: {}",
            results[1].1
        );
        assert!(
            results[1].1.contains("no:no:no"),
            "second detail: {}",
            results[1].1
        );
    }
}
