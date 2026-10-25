//! Defect-pattern class guards (issue #959).
//!
//! The registry (`data/defect-patterns.toml`) is the single source of
//! class membership; these tests pin it against the other places a
//! tag's identity lives: the severity inventory snapshot (every
//! member is a real emitted tag) and the staged description corpus
//! (every member carries a `-v` description for the class block to
//! ride on).

use std::collections::BTreeSet;
use std::path::PathBuf;

use rpmcrab_core::defect_pattern;
use rpmcrab_core::describe;

/// The `[emitted-levels]` tags of the severity inventory snapshot.
fn inventory_tags() -> BTreeSet<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/severity-inventory.txt");
    let text = std::fs::read_to_string(path).unwrap();
    let mut tags = BTreeSet::new();
    let mut in_emitted = false;
    for line in text.lines() {
        if line.starts_with('[') {
            in_emitted = line == "[emitted-levels]";
            continue;
        }
        if in_emitted && let Some((tag, _)) = line.split_once(" = ") {
            tags.insert(tag.to_string());
        }
    }
    tags
}

#[test]
fn every_member_is_an_emitted_tag() {
    let tags = inventory_tags();
    for m in defect_pattern::registry().members() {
        assert!(
            tags.contains(&m.tag),
            "registry member {} is not an emitted tag",
            m.tag
        );
    }
}

#[test]
fn every_member_has_a_staged_description() {
    let descriptions = describe::staged_descriptions();
    for m in defect_pattern::registry().members() {
        assert!(
            descriptions.contains_key(&m.tag),
            "registry member {} has no staged description",
            m.tag
        );
    }
}
