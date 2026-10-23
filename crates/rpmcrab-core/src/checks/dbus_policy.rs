//! `DBusPolicyCheck` — D-Bus system bus policy files must not grant overly
//! broad access.
//!
//! Ported from `rpmlint/checks/DBusPolicyCheck.py`. Findings:
//! `dbus-policy-missing-allow`, `dbus-parsing-exception`,
//! `dbus-policy-allow-without-destination`, `dbus-policy-allow-receive`,
//! `dbus-policy-allow-wildcard`, `dbus-policy-deny-without-destination`.

use std::collections::HashSet;

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

const DBUS_DIRECTORIES: &[&str] = &["/etc/dbus-1/system.d/", "/usr/share/dbus-1/system.d/"];

pub struct DBusPolicyCheck;

impl DBusPolicyCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// True when `path` is a D-Bus system policy file.
    fn is_policy_file(path: &str) -> bool {
        DBUS_DIRECTORIES.iter().any(|d| path.starts_with(d))
    }
}

/// One `<allow>` or `<deny>` element: its attributes (in document order)
/// and raw XML.
struct PolicyElement {
    attrs: Vec<(String, String)>,
    xml: String,
}

/// Escape an attribute value for the rebuilt XML detail, mirroring
/// minidom's `toxml()`: only `&`, `<`, `>` and `"` are escaped. Control
/// characters such as tab, newline and CR pass through literally —
/// CPython's `xml.dom.minidom._write_data` has no `&#9;`/`&#10;`/`&#13;`
/// mapping.
fn escape_xml_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// Record an `<allow>` or `<deny>` element into the current `<policy>`.
fn push_element(e: &quick_xml::events::BytesStart<'_>, current: &mut Option<PolicyBlock>) {
    let name = e.name();
    let kind: &'static str = if name.as_ref() == "allow" {
        "allow"
    } else if name.as_ref() == "deny" {
        "deny"
    } else {
        return;
    };
    let tag = name.as_ref().to_owned();
    let mut attrs = Vec::new();
    for attr in e.attributes().filter_map(|a| a.ok()) {
        let key = attr.key.as_ref().to_owned();
        let val = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map(|v| v.into_owned())
            .unwrap_or_default();
        attrs.push((key, val));
    }
    // Document order with XML-escaped values, byte-identical to minidom's
    // `toxml()` for empty elements (no space before `/>`).
    let xml = format!(
        "<{tag}{}/>",
        attrs
            .iter()
            .map(|(k, v)| format!(" {k}=\"{}\"", escape_xml_attr(v)))
            .collect::<String>()
    );
    if let Some(block) = current {
        block.elems.push((kind, PolicyElement { attrs, xml }));
    }
}

/// One `<policy>` element: whether it is scoped to named subjects (a
/// `user`, `group` or `at_console` attribute, as opposed to
/// `context="default"` or no attribute) and its `<allow>`/`<deny>`
/// elements in document order.
struct PolicyBlock {
    subject_scoped: bool,
    elems: Vec<(&'static str, PolicyElement)>,
}

/// True when a `<policy>` element names the subjects it governs.
fn policy_subject_scoped(e: &quick_xml::events::BytesStart<'_>) -> bool {
    e.attributes()
        .filter_map(|a| a.ok())
        .any(|a| matches!(a.key.as_ref(), "user" | "group" | "at_console"))
}

/// The findings for one policy file's content: `(level, finding, detail)`.
fn check_content(content: &str) -> Result<Vec<(Level, &'static str, String)>, String> {
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    // Collect <allow>/<deny> elements grouped by their enclosing <policy>.
    let mut policies: Vec<PolicyBlock> = Vec::new();
    let mut current: Option<PolicyBlock> = None;
    let mut buf = Vec::new();
    // Track open elements so unclosed tags are a parse error, like minidom.
    let mut open: Vec<String> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                open.push(e.name().as_ref().to_owned());
                if e.name().as_ref() == "policy" {
                    current = Some(PolicyBlock {
                        subject_scoped: policy_subject_scoped(e),
                        elems: Vec::new(),
                    });
                } else {
                    push_element(e, &mut current);
                }
            }
            Ok(Event::Empty(ref e)) => {
                if e.name().as_ref() == "policy" {
                    // An empty <policy/> contributes no elements.
                    policies.push(PolicyBlock {
                        subject_scoped: policy_subject_scoped(e),
                        elems: Vec::new(),
                    });
                } else {
                    push_element(e, &mut current);
                }
            }
            Ok(Event::End(ref e)) => {
                match open.pop() {
                    Some(name) if name == e.name().as_ref() => {}
                    _ => return Err("mismatched closing tag".to_string()),
                }
                if e.name().as_ref() == "policy"
                    && let Some(block) = current.take()
                {
                    policies.push(block);
                }
            }
            Ok(Event::Eof) => {
                if !open.is_empty() {
                    return Err("unclosed elements at end of input".to_string());
                }
                break;
            }
            Err(e) => return Err(e.to_string()),
            _ => {}
        }
        buf.clear();
    }

    // The names this file itself pins down: every `own`, `own_prefix`
    // and `send_destination` value on its <allow>/<deny> elements. A
    // destination for one of these names can always be written, so an
    // interface rule naming one of them is not the agent idiom below.
    let mut pinned: HashSet<&str> = HashSet::new();
    let mut file_has_own = false;
    for block in &policies {
        for (_, elem) in &block.elems {
            for (key, val) in &elem.attrs {
                match key.as_str() {
                    "own" | "own_prefix" => {
                        file_has_own = true;
                        pinned.insert(val.as_str());
                    }
                    "send_destination" => {
                        pinned.insert(val.as_str());
                    }
                    _ => {}
                }
            }
        }
    }

    // The reference scopes send_policy_seen per file, not per policy:
    // one flag for the whole file, one finding naming the file.
    let mut findings = Vec::new();
    let mut send_policy_seen = false;
    for block in &policies {
        for (kind, elem) in &block.elems {
            if *kind == "allow" {
                send_policy_seen |= check_allow(
                    elem,
                    block.subject_scoped,
                    &pinned,
                    file_has_own,
                    &mut findings,
                );
            } else {
                check_deny(elem, &mut findings);
            }
        }
    }
    if !send_policy_seen {
        findings.push((Level::Error, "dbus-policy-missing-allow", String::new()));
    }
    Ok(findings)
}

/// True when the leaf (final dotted component) of an interface name
/// denotes an agent role: `Agent`, a name ending in `Agent`, or either
/// with a trailing version number (`Agent1`). Agent interfaces are
/// implemented by whichever process registers as the agent, under a
/// per-session unique bus name.
fn is_agent_interface(name: &str) -> bool {
    let leaf = name.rsplit('.').next().unwrap_or(name);
    let base = leaf.trim_end_matches(|c: char| c.is_ascii_digit());
    base == "Agent" || base.ends_with("Agent")
}

/// True when an interface-scoped `<allow>` without `send_destination`
/// is the agent idiom: the rule grants a named subject (the daemon or
/// a privileged user) the use of an interface whose implementer
/// registers at runtime, so no static `send_destination` can name the
/// recipient and the rule is complete as written. The idiom applies
/// only where the file gives the rule its service-policy context:
/// the interface must not be one of the names the file itself pins
/// (a destination for those can always be written), and the file
/// must either declare the names its service owns, scope the rule
/// to an object path, or name an agent interface outright.
fn is_agent_idiom(
    elem: &PolicyElement,
    subject_scoped: bool,
    pinned: &HashSet<&str>,
    file_has_own: bool,
) -> bool {
    if !subject_scoped {
        return false;
    }
    let attrs = &elem.attrs;
    let get = |k: &str| {
        attrs
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
    };
    let Some(iface) = get("send_interface") else {
        return false;
    };
    if pinned.contains(iface) {
        return false;
    }
    file_has_own || get("send_path").is_some() || is_agent_interface(iface)
}

/// Check one `<allow>` element, returning true when it counts as a send
/// policy (sets `send_policy_seen`).
fn check_allow(
    elem: &PolicyElement,
    subject_scoped: bool,
    pinned: &HashSet<&str>,
    file_has_own: bool,
    findings: &mut Vec<(Level, &'static str, String)>,
) -> bool {
    let attrs = &elem.attrs;
    let has = |k: &str| attrs.iter().any(|(key, _)| key == k);
    let mut seen = false;

    if (has("send_interface") || has("send_member") || has("send_path")) && !has("send_destination")
    {
        seen = true;
        if !is_agent_idiom(elem, subject_scoped, pinned, file_has_own) {
            findings.push((
                Level::Error,
                "dbus-policy-allow-without-destination",
                elem.xml.clone(),
            ));
        }
    } else if has("send_destination") {
        seen = true;
    }

    if has("receive_sender") || has("receive_interface") {
        findings.push((
            Level::Warning,
            "dbus-policy-allow-receive",
            elem.xml.clone(),
        ));
    }

    // bsc#1220215: reject wildcards in send_* attributes (except send_member,
    // which has valid wildcard uses).
    for (key, val) in attrs {
        if key == "send_member" {
            continue;
        }
        if key.starts_with("send_") && val.contains('*') {
            findings.push((Level::Error, "dbus-policy-allow-wildcard", elem.xml.clone()));
        }
    }

    seen
}

/// Check one `<deny>` element.
fn check_deny(elem: &PolicyElement, findings: &mut Vec<(Level, &'static str, String)>) {
    let attrs = &elem.attrs;
    let has = |k: &str| attrs.iter().any(|(key, _)| key == k);
    if has("send_interface") && !has("send_destination") {
        findings.push((
            Level::Error,
            "dbus-policy-deny-without-destination",
            elem.xml.clone(),
        ));
    }
}

impl Check for DBusPolicyCheck {
    fn name(&self) -> &'static str {
        "DBusPolicyCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }
        for file in &pkg.files {
            let fname = file.name.as_str();
            if !Self::is_policy_file(fname) {
                continue;
            }
            if pkg.ghost_files.iter().any(|g| g == fname) {
                continue;
            }
            let content = match std::fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(e) => {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "dbus-parsing-exception",
                        &[&format!("raised an exception: {e}"), fname],
                    );
                    continue;
                }
            };
            match check_content(&content) {
                Ok(findings) => {
                    for (level, finding, detail) in findings {
                        if detail.is_empty() {
                            add_info(out, level, pkg, finding, &[fname]);
                        } else {
                            add_info(out, level, pkg, finding, &[&detail, fname]);
                        }
                    }
                }
                Err(e) => {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "dbus-parsing-exception",
                        &[&format!("raised an exception: {e}"), fname],
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_directories_are_recognized() {
        assert!(DBusPolicyCheck::is_policy_file(
            "/etc/dbus-1/system.d/foo.conf"
        ));
        assert!(DBusPolicyCheck::is_policy_file(
            "/usr/share/dbus-1/system.d/foo.conf"
        ));
        assert!(!DBusPolicyCheck::is_policy_file("/etc/foo.conf"));
    }

    #[test]
    fn escape_xml_attr_matches_minidom() {
        // Verified against CPython 3.9's xml.dom.minidom._write_data: only
        // & < > " are escaped; \t \n \r are emitted literally.
        assert_eq!(escape_xml_attr("a&b<c>d\"e"), "a&amp;b&lt;c&gt;d&quot;e");
        assert_eq!(escape_xml_attr("x\ty\nz\rw"), "x\ty\nz\rw");
    }

    #[test]
    fn proper_policy_is_quiet() {
        let xml = r#"<?xml version="1.0"?>
<busconfig>
  <policy user="root">
    <allow send_destination="org.foo.Bar"/>
  </policy>
</busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn allow_without_destination_is_flagged() {
        let xml = r#"<busconfig><policy user="root">
<allow send_interface="org.foo.Bar"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(
            findings
                .iter()
                .any(|(_, f, _)| *f == "dbus-policy-allow-without-destination"),
            "{findings:?}"
        );
        // A bare allow-without-destination still counts as a send policy.
        assert!(
            !findings
                .iter()
                .any(|(_, f, _)| *f == "dbus-policy-missing-allow"),
            "{findings:?}"
        );
    }

    #[test]
    fn missing_allow_is_flagged() {
        let xml = r#"<busconfig><policy user="root">
<deny send_interface="org.foo.Bar" send_destination="org.foo.Baz"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(
            findings
                .iter()
                .any(|(_, f, _)| *f == "dbus-policy-missing-allow"),
            "{findings:?}"
        );
    }

    #[test]
    fn missing_allow_is_per_file_not_per_policy() {
        // One policy with a send-allow plus one deny-only policy: the
        // reference emits nothing (send_policy_seen is per file).
        let xml = r#"<busconfig>
<policy user="root">
<allow send_destination="org.foo.Bar"/>
</policy>
<policy context="default">
<deny send_interface="org.foo.Bar"/>
</policy>
</busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(
            !findings
                .iter()
                .any(|(_, f, _)| *f == "dbus-policy-missing-allow"),
            "{findings:?}"
        );
    }

    #[test]
    fn attribute_detail_uses_document_order() {
        // The rebuilt element detail must be byte-identical to minidom's
        // `toxml()`: attributes in document order, XML-escaped values, and
        // no space before `/>`. (A default policy, so the rule is not the
        // agent idiom and the finding fires.)
        let xml = r#"<busconfig><policy context="default">
<allow send_path="/org/foo" send_interface="org.foo.Bar"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        let detail = findings
            .iter()
            .find(|(_, f, _)| *f == "dbus-policy-allow-without-destination")
            .map(|(_, _, d)| d.as_str())
            .expect("finding present");
        assert_eq!(
            detail,
            r#"<allow send_path="/org/foo" send_interface="org.foo.Bar"/>"#
        );
    }

    #[test]
    fn attribute_detail_escapes_like_toxml() {
        // minidom escapes & < > " in attribute values; the rebuilt detail
        // must do the same (byte-identical to `toxml()`).
        let xml = "<busconfig><policy user=\"root\">\n<allow send_interface=\"a&amp;b&lt;c\"/>\n</policy></busconfig>";
        let findings = check_content(xml).expect("parses");
        let detail = findings
            .iter()
            .find(|(_, f, _)| *f == "dbus-policy-allow-without-destination")
            .map(|(_, _, d)| d.as_str())
            .expect("finding present");
        assert_eq!(detail, "<allow send_interface=\"a&amp;b&lt;c\"/>");
    }

    #[test]
    fn allow_receive_is_a_warning() {
        let xml = r#"<busconfig><policy user="root">
<allow send_destination="org.foo.Bar" receive_sender="org.foo.Baz"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(
            findings
                .iter()
                .any(|(l, f, _)| *l == Level::Warning && *f == "dbus-policy-allow-receive"),
            "{findings:?}"
        );
    }

    #[test]
    fn wildcard_in_send_destination_is_flagged() {
        let xml = r#"<busconfig><policy user="root">
<allow send_destination="org.foo.*"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(
            findings
                .iter()
                .any(|(_, f, _)| *f == "dbus-policy-allow-wildcard"),
            "{findings:?}"
        );
    }

    #[test]
    fn wildcard_in_send_member_is_allowed() {
        let xml = r#"<busconfig><policy user="root">
<allow send_destination="org.foo.Bar" send_member="*"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(
            !findings
                .iter()
                .any(|(_, f, _)| *f == "dbus-policy-allow-wildcard"),
            "{findings:?}"
        );
    }

    #[test]
    fn deny_without_destination_is_flagged() {
        let xml = r#"<busconfig><policy user="root">
<allow send_destination="org.foo.Bar"/>
<deny send_interface="org.foo.Baz"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(
            findings
                .iter()
                .any(|(_, f, _)| *f == "dbus-policy-deny-without-destination"),
            "{findings:?}"
        );
    }

    #[test]
    fn malformed_xml_is_an_error() {
        assert!(check_content("<busconfig><policy>").is_err());
    }

    #[test]
    fn agent_allows_in_service_policy_are_quiet() {
        // The bluez/ofono shape: the daemon's own policy pins its name
        // and owns it; the destinationless interface rules name the
        // peer interfaces the daemon calls back into (an agent and a
        // registered-object interface alike).
        let xml = r#"<busconfig><policy user="root">
<allow own="org.foo"/>
<allow send_destination="org.foo"/>
<allow send_interface="org.foo.Agent1"/>
<allow send_interface="org.foo.GattThing1"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn agent_allow_alone_still_counts_as_send_policy() {
        // A credited agent rule is still a send policy: no
        // dbus-policy-missing-allow may follow from crediting it.
        let xml = r#"<busconfig><policy user="root">
<allow send_interface="org.foo.Agent"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn agent_allow_in_pinless_file_is_quiet() {
        // The geoclue shape: no names are pinned anywhere in the file;
        // the agent leaf (and the object path) carry the idiom.
        let xml = r#"<busconfig><policy user="srvfoo">
<allow send_interface="org.foo.Agent" send_path="/org/foo/Agent"/>
<allow send_interface="org.freedesktop.DBus.Properties" send_path="/org/foo/Agent"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn service_interface_named_like_its_destination_still_fires() {
        // The wpa_supplicant shape: the interface value is the very
        // name the same policy pins as a destination -- a destination
        // can always be written for it, so the rule is no idiom.
        let xml = r#"<busconfig><policy user="root">
<allow own="org.foo.Bar"/>
<allow send_destination="org.foo.Bar"/>
<allow send_interface="org.foo.Bar"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(
            findings
                .iter()
                .any(|(_, f, _)| *f == "dbus-policy-allow-without-destination"),
            "{findings:?}"
        );
    }

    #[test]
    fn agent_allow_in_default_policy_still_fires() {
        // The kauth shape: a default policy grants everyone the
        // interface; that breadth is the finding's target even when
        // the leaf names an agent.
        let xml = r#"<busconfig><policy context="default">
<allow send_interface="org.foo.Agent"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(
            findings
                .iter()
                .any(|(_, f, _)| *f == "dbus-policy-allow-without-destination"),
            "{findings:?}"
        );
    }

    #[test]
    fn foreign_interface_in_pinless_file_still_fires() {
        // The cups shape: the file pins nothing, the rule carries no
        // object path and the leaf names no agent -- no service-policy
        // context credits it.
        let xml = r#"<busconfig><policy user="root">
<allow send_interface="com.foo.PrinterSpooler"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(
            findings
                .iter()
                .any(|(_, f, _)| *f == "dbus-policy-allow-without-destination"),
            "{findings:?}"
        );
    }

    #[test]
    fn agent_manager_leaf_still_fires() {
        // AgentManager is a service interface (the manager API on the
        // daemon itself), not an agent leaf: the name-shape boundary
        // is a leaf that is or ends in Agent, not one that starts so.
        let xml = r#"<busconfig><policy user="root">
<allow send_interface="org.foo.AgentManager"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(
            findings
                .iter()
                .any(|(_, f, _)| *f == "dbus-policy-allow-without-destination"),
            "{findings:?}"
        );
    }

    #[test]
    fn member_only_allow_in_service_policy_still_fires() {
        // The credit is interface-scoped: a member-only rule in the
        // daemon's own policy still fires.
        let xml = r#"<busconfig><policy user="root">
<allow own="org.foo"/>
<allow send_destination="org.foo"/>
<allow send_member="SomeMember"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(
            findings
                .iter()
                .any(|(_, f, _)| *f == "dbus-policy-allow-without-destination"),
            "{findings:?}"
        );
    }

    #[test]
    fn deny_with_agent_interface_still_fires() {
        // Deny rules are untouched by the credit, agent leaf or not.
        let xml = r#"<busconfig><policy user="root">
<allow send_destination="org.foo.Bar"/>
<deny send_interface="org.foo.Agent"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(
            findings
                .iter()
                .any(|(_, f, _)| *f == "dbus-policy-deny-without-destination"),
            "{findings:?}"
        );
    }

    #[test]
    fn agent_allow_with_destination_is_unaffected() {
        // A destination-pinned agent rule was never charged and is
        // still a plain send policy.
        let xml = r#"<busconfig><policy user="root">
<allow send_destination="org.foo.Bar" send_interface="org.foo.Agent"/>
</policy></busconfig>"#;
        let findings = check_content(xml).expect("parses");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn parity_fixture_matches_reference() {
        use crate::color::Color;

        // Pinned against reference rpmlint 2.10.0 (DBusPolicyCheck.py at
        // 84848c0), verified in an openSUSE container: the fixture's two
        // <policy> elements (one send-allow, one deny-only) yield exactly
        // one finding. B1: a per-policy send_policy_seen scope would add a
        // false-positive E dbus-policy-missing-allow for the deny-only
        // policy. B3: the detail is byte-identical to minidom's toxml().
        let rpm = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/parity/pkg/inputs/dbus-parity-1.0-1.noarch.rpm"
        );
        let dir = std::env::temp_dir().join("rpmcrab-dbus-parity");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let pkg =
            crate::pkg::Pkg::open(std::path::Path::new(rpm), &dir, true).expect("fixture opens");
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = DBusPolicyCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let rendered: Vec<String> = out.results().iter().map(|(_, line)| line.clone()).collect();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        assert!(
            rendered[0].contains("dbus-policy-allow-without-destination"),
            "{rendered:?}"
        );
        assert!(
            rendered[0].contains(r#"<allow send_interface="org.parity.If"/>"#),
            "{rendered:?}"
        );
    }
}
