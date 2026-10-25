//! The defect-pattern registry (issue #959): the finding tags that are
//! defect-pattern finders, their families, gates and provenance.
//!
//! Membership is a property of the finding tag, recorded once in the
//! embedded `data/defect-patterns.toml`; the renderers, the rpmlintrc
//! filter expansion and the `-v` descriptions all resolve through this
//! module, so every consumer reads the same source. A member finder
//! pairs a pattern decidable from the shipped binary and package with
//! a context gate; the registry records the gate shape each finder's
//! severity hangs on and the defect samples (provenance) that put the
//! finder on the on-ramp.

use std::collections::HashMap;
use std::sync::OnceLock;

/// The embedded registry, baked in like the description corpus so an
/// installed binary needs no data dir next to it.
const REGISTRY_TOML: &str = include_str!("../data/defect-patterns.toml");

/// The family a member belongs to: a dangerous-API / call pattern, or
/// a mitigation-absence (hardening) pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Pattern,
    Hardening,
}

impl Family {
    /// The registry token for this family.
    pub fn as_str(&self) -> &'static str {
        match self {
            Family::Pattern => "pattern",
            Family::Hardening => "hardening",
        }
    }
}

/// The context gate a member's severity hangs on (issue #959 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// The pattern in a file carrying privilege (setuid/setgid mode
    /// bits, file capabilities) or in a package shipping daemon
    /// surface (systemd service or socket units).
    PrivilegeOrExposure,
    /// The pattern's legitimate modern use is empty, so it carries
    /// no gate.
    NoSafeUse,
    /// The pattern is gated by its own construction.
    SelfGated,
    /// The finder reports the pattern as measured, ungated.
    None,
}

impl Gate {
    /// The registry token for this gate.
    pub fn as_str(&self) -> &'static str {
        match self {
            Gate::PrivilegeOrExposure => "privilege-or-exposure",
            Gate::NoSafeUse => "no-safe-use",
            Gate::SelfGated => "self",
            Gate::None => "none",
        }
    }
}

/// One registry record: a member tag and its class data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The finding tag, exactly as emitted.
    pub tag: String,
    /// The class the tag belongs to.
    pub class: String,
    pub family: Family,
    pub gate: Gate,
    /// The recorded defect samples behind the finder: CVE/advisory
    /// root causes in the pattern's class, or a verified in-distro
    /// instance. Never empty (the on-ramp bar, issue #959 §5).
    pub provenance: Vec<String>,
}

impl Member {
    /// The block `-v`/`--explain` appends to the member's staged
    /// description: the class, family and gate, then the recorded
    /// provenance, so the explanation a maintainer reads names the
    /// defect history behind the pattern.
    pub fn description_suffix(&self) -> String {
        format!(
            "Defect-pattern class: {} (family: {}; gate: {}).\nProvenance: {}",
            self.class,
            self.family.as_str(),
            self.gate.as_str(),
            self.provenance.join(" ")
        )
    }
}

/// The parsed registry: members in file order, plus a tag index.
#[derive(Debug)]
pub struct Registry {
    members: Vec<Member>,
    by_tag: HashMap<String, usize>,
}

impl Registry {
    /// The member record for a finding tag, if the tag is registered.
    pub fn member(&self, tag: &str) -> Option<&Member> {
        self.by_tag.get(tag).map(|&i| &self.members[i])
    }

    /// Every member of a class, in registry order.
    pub fn class_members(&self, class: &str) -> Vec<&Member> {
        self.members.iter().filter(|m| m.class == class).collect()
    }

    /// Every registered member, in registry order.
    pub fn members(&self) -> &[Member] {
        &self.members
    }
}

/// The process-wide registry, parsed once: `Filter::new` runs per
/// package in the worker pool, and re-parsing per filter would be
/// pure overhead. Panics on a malformed registry, the way a broken
/// staged description corpus surfaces at startup.
pub fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| parse_registry(REGISTRY_TOML))
}

/// The class a finding tag belongs to, if it is a registry member.
pub fn class_of(tag: &str) -> Option<&'static str> {
    registry().member(tag).map(|m| m.class.as_str())
}

/// The member record for a finding tag, if it is registered.
pub fn member(tag: &str) -> Option<&'static Member> {
    registry().member(tag)
}

/// Every member of a class, in registry order; empty for a class the
/// registry does not know.
pub fn class_members(class: &str) -> Vec<&'static Member> {
    registry().class_members(class)
}

/// Parse and validate the registry text. Validation is the on-ramp
/// bar made mechanical (issue #959 §5): every member names a class, a
/// known family and gate, and at least one provenance sample, and no
/// tag is registered twice.
fn parse_registry(raw: &str) -> Registry {
    let table: toml::Table = raw.parse().expect("defect-pattern registry is valid TOML");
    let records = table
        .get("member")
        .and_then(toml::Value::as_array)
        .expect("defect-pattern registry has a [[member]] array");
    let mut members = Vec::with_capacity(records.len());
    let mut by_tag = HashMap::with_capacity(records.len());
    for record in records {
        let field = |name: &str| -> String {
            record
                .get(name)
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("defect-pattern member is missing {name:?}"))
                .to_string()
        };
        let tag = field("tag");
        let family = match field("family").as_str() {
            "pattern" => Family::Pattern,
            "hardening" => Family::Hardening,
            other => panic!("defect-pattern member {tag}: unknown family {other:?}"),
        };
        let gate = match field("gate").as_str() {
            "privilege-or-exposure" => Gate::PrivilegeOrExposure,
            "no-safe-use" => Gate::NoSafeUse,
            "self" => Gate::SelfGated,
            "none" => Gate::None,
            other => panic!("defect-pattern member {tag}: unknown gate {other:?}"),
        };
        let provenance: Vec<String> = record
            .get("provenance")
            .and_then(toml::Value::as_array)
            .unwrap_or_else(|| panic!("defect-pattern member {tag} is missing provenance"))
            .iter()
            .map(|v| {
                v.as_str()
                    .unwrap_or_else(|| {
                        panic!("defect-pattern member {tag}: provenance is not a string")
                    })
                    .to_string()
            })
            .collect();
        assert!(
            !provenance.is_empty(),
            "defect-pattern member {tag} carries no provenance sample"
        );
        let member = Member {
            tag: tag.clone(),
            class: field("class"),
            family,
            gate,
            provenance,
        };
        assert!(
            by_tag.insert(tag.clone(), members.len()).is_none(),
            "defect-pattern tag {tag} is registered twice"
        );
        members.push(member);
    }
    Registry { members, by_tag }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_registers_the_seed_inventory() {
        let tags: Vec<&str> = registry()
            .members()
            .iter()
            .map(|m| m.tag.as_str())
            .collect();
        assert_eq!(
            tags,
            [
                "binary-or-shlib-calls-gethostbyname",
                "call-to-mktemp",
                "missing-call-to-setgroups-before-setuid",
                "missing-fortify",
                "missing-stack-protector",
                "missing-relro",
                "partial-relro",
                "missing-cf-protection",
                "executable-stack",
                "non-position-independent-executable",
            ]
        );
    }

    #[test]
    fn class_of_resolves_members_only() {
        assert_eq!(class_of("call-to-mktemp"), Some("defect-pattern"));
        assert_eq!(class_of("no-soname"), None);
    }

    #[test]
    fn class_members_come_in_registry_order() {
        let members = class_members("defect-pattern");
        assert_eq!(members.len(), 10);
        assert_eq!(members[0].tag, "binary-or-shlib-calls-gethostbyname");
        assert!(class_members("no-such-class").is_empty());
    }

    #[test]
    fn families_and_gates_match_the_design() {
        let gethostbyname = member("binary-or-shlib-calls-gethostbyname").unwrap();
        assert_eq!(gethostbyname.family, Family::Pattern);
        assert_eq!(gethostbyname.gate, Gate::PrivilegeOrExposure);
        assert_eq!(member("call-to-mktemp").unwrap().gate, Gate::NoSafeUse);
        assert_eq!(
            member("missing-call-to-setgroups-before-setuid")
                .unwrap()
                .gate,
            Gate::SelfGated
        );
        assert_eq!(member("missing-relro").unwrap().family, Family::Hardening);
    }

    #[test]
    fn description_suffix_names_class_and_provenance() {
        let suffix = member("call-to-mktemp").unwrap().description_suffix();
        assert!(suffix.contains("defect-pattern"), "{suffix}");
        assert!(suffix.contains("mkstemp"), "{suffix}");
    }
}
