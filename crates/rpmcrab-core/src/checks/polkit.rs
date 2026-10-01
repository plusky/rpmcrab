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
use quick_xml::events::Event;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

/// Parsed actions: (action_id, defaults).
type PolkitActions = Vec<(String, HashMap<String, String>)>;

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
    /// `#` comments stripped.
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

    /// Parse a polkit policy file, returning `(action_id, defaults)` pairs.
    /// Err on malformed XML (the reference's `polkit-xml-exception`).
    fn parse_actions(path: &str) -> Result<PolkitActions, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut reader = Reader::from_str(&content);
        reader.config_mut().trim_text(true);
        let mut actions = Vec::new();
        let mut buf = Vec::new();
        let mut current_id: Option<String> = None;
        let mut current_defaults: HashMap<String, String> = HashMap::new();
        let mut in_action = false;
        let mut in_defaults = false;
        let mut current_setting: Option<String> = None;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => match e.name().as_ref() {
                    b"action" => {
                        in_action = true;
                        current_id = None;
                        current_defaults = HashMap::new();
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"id" {
                                current_id = Some(
                                    attr.unescape_value()
                                        .map(|v| v.into_owned())
                                        .unwrap_or_default(),
                                );
                            }
                        }
                    }
                    b"defaults" if in_action => in_defaults = true,
                    b"allow_any" | b"allow_inactive" | b"allow_active" if in_defaults => {
                        current_setting =
                            Some(String::from_utf8_lossy(e.name().as_ref()).into_owned());
                    }
                    _ => {}
                },
                Ok(Event::Text(e)) => {
                    if let Some(setting) = current_setting.take() {
                        let value = e.unescape().map(|v| v.into_owned()).unwrap_or_default();
                        current_defaults.insert(setting, value);
                    }
                }
                Ok(Event::End(e)) => match e.name().as_ref() {
                    b"action" => {
                        if let Some(id) = current_id.take() {
                            actions.push((id, std::mem::take(&mut current_defaults)));
                        }
                        in_action = false;
                        in_defaults = false;
                    }
                    b"defaults" => in_defaults = false,
                    _ => {}
                },
                Ok(Event::Eof) => break,
                Err(e) => return Err(e.to_string()),
                _ => {}
            }
            buf.clear();
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
}
