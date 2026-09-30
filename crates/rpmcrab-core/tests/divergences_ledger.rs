//! The parity ledger is the project's map of every place rpmcrab differs from
//! the reference. Nothing else validated it, so a hand-resolved merge could
//! silently fuse two entries (dropping a `[[divergence]]` header) or leave an
//! unescaped backslash in a `reason`, and the file stopped being parseable TOML
//! while every other test still passed.

use std::path::{Path, PathBuf};

fn ledger_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/parity/divergences.toml")
}

fn entries() -> Vec<toml::value::Table> {
    let raw = std::fs::read_to_string(ledger_path()).expect("read tests/parity/divergences.toml");
    let parsed: toml::Value =
        toml::from_str(&raw).unwrap_or_else(|e| panic!("ledger must parse as TOML: {e}"));
    parsed
        .get("divergence")
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("ledger has no [[divergence]] array"))
        .iter()
        .map(|v| {
            v.as_table()
                .unwrap_or_else(|| panic!("divergence entry is not a table: {v:?}"))
                .clone()
        })
        .collect()
}

fn field<'a>(entry: &'a toml::value::Table, key: &str, index: usize) -> &'a str {
    entry
        .get(key)
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("entry {index} has no non-empty string `{key}`: {entry:?}"))
}

#[test]
fn ledger_is_valid_toml_with_complete_entries() {
    let entries = entries();
    assert!(!entries.is_empty(), "ledger is empty");
    for (i, entry) in entries.iter().enumerate() {
        for key in ["case", "check", "kind", "reason", "since"] {
            let value = field(entry, key, i);
            assert!(!value.trim().is_empty(), "entry {i} `{key}` is blank");
        }
        assert_eq!(
            field(entry, "case", i),
            "global",
            "entry {i} (`{}`): only the `global` case is defined so far",
            field(entry, "check", i)
        );
    }
}

/// Several findings legitimately share one `check` umbrella — `pkg-layer` has
/// three distinct reasons — so uniqueness is per (check, reason) pair.
#[test]
fn ledger_entries_are_not_duplicated() {
    let mut seen = std::collections::HashSet::new();
    for (i, entry) in entries().iter().enumerate() {
        let key = (field(entry, "check", i), field(entry, "reason", i));
        assert!(
            seen.insert(key),
            "entry {i} duplicates an earlier entry for `{}` with an identical reason",
            key.0
        );
    }
}

/// Every finding the port is known not to emit must be in the ledger, or the
/// corpus comparison cannot tell a deliberate departure from a gap. Cheap
/// guard: the entries that record an absent check all declare `kind =
/// "missing"`, so any future omission has to be written down in that shape.
#[test]
fn missing_findings_declare_their_kind() {
    for (i, entry) in entries().iter().enumerate() {
        let kind = field(entry, "kind", i);
        assert!(
            matches!(kind, "missing" | "behaviour" | "severity" | "detail"),
            "entry {i} (`{}`) has unknown kind `{kind}`",
            field(entry, "check", i)
        );
        if kind == "missing" {
            assert!(
                field(entry, "reason", i).to_lowercase().contains("not ")
                    || field(entry, "reason", i)
                        .to_lowercase()
                        .contains("unreachable"),
                "a `kind = \"missing\"` entry (`{}`) must say what is absent and why",
                field(entry, "check", i)
            );
        }
    }
}
