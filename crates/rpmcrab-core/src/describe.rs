//! The `--explain`/`-v` description corpus.
//!
//! Mirrors `filter.py::_load_descriptions` + `_replace_description_variables`:
//! the staged `data/descriptions/*.toml` files merge in sorted-name order and
//! `#VAR#` placeholders resolve recursively against the merged table. The
//! reference reads the files from disk at `Filter` construction; the port
//! bakes the staged files in with `include_str!` so an installed binary needs
//! no data dir next to it.

use std::collections::HashMap;

/// One staged description file per line here, in sorted-name order to match
/// the reference's `sorted(descr_folder.glob('*.toml'))` merge.
const STAGED: &[&str] = &[
    include_str!("../data/descriptions/AtomicUpdateCheck.toml"),
    include_str!("../data/descriptions/BinariesCheck.toml"),
    include_str!("../data/descriptions/ConfigFilesCheck.toml"),
    include_str!("../data/descriptions/DeviceFilesCheck.toml"),
    include_str!("../data/descriptions/I18NCheck.toml"),
    include_str!("../data/descriptions/IconSizesCheck.toml"),
    include_str!("../data/descriptions/LibraryDependencyCheck.toml"),
    include_str!("../data/descriptions/MixedOwnershipCheck.toml"),
    include_str!("../data/descriptions/PAMModulesCheck.toml"),
    include_str!("../data/descriptions/SourceCheck.toml"),
    include_str!("../data/descriptions/Variables.toml"),
    include_str!("../data/descriptions/WorldWritableCheck.toml"),
    include_str!("../data/descriptions/XinetdDepCheck.toml"),
    include_str!("../data/descriptions/ZipCheck.toml"),
    include_str!("../data/descriptions/ZyppSyntaxCheck.toml"),
];

/// The merged, variable-resolved description table (`Filter.error_details`
/// seed). Parsed once per process: `Filter::new` runs per package in the
/// worker pool, and re-parsing the corpus each time would be pure overhead.
/// Cloned (not shared) per `Filter::new` because checks register their own
/// descriptions into their Filter's map (`register_description`,
/// `FHSCheck::register_error_details`).
/// Panics on invalid TOML or an unresolvable `#VAR#`, the way the
/// reference's `KeyError`/parse warning surfaces a broken corpus at startup.
pub fn staged_descriptions() -> HashMap<String, String> {
    static CORPUS: std::sync::OnceLock<HashMap<String, String>> = std::sync::OnceLock::new();
    CORPUS
        .get_or_init(|| {
            let mut merged: HashMap<String, String> = HashMap::new();
            for raw in STAGED {
                let table: toml::Table = raw.parse().expect("staged description is valid TOML");
                for (k, v) in table {
                    let text = v
                        .as_str()
                        .unwrap_or_else(|| panic!("staged description {k} is not a string"));
                    merged.insert(k, text.to_string());
                }
            }
            replace_description_variables(&mut merged);
            merged
        })
        .clone()
}

/// `filter.py::_replace_description_variables`: `#VAR#` resolves against the
/// merged table itself, recursively (e.g. `REVIEW_NEEDED_TEXT` embeds
/// `#AUDIT_BUG_URL#`).
///
/// Resolution is depth-first with cycle detection (upstream rpmlint#1589):
/// a self-referential or cyclic `#VAR#` fails loudly naming the chain
/// instead of spinning, and an unknown variable fails naming the referencing
/// entry — the way the reference's `KeyError` surfaces a broken corpus at
/// startup.
fn replace_description_variables(merged: &mut HashMap<String, String>) {
    let keys: Vec<String> = merged.keys().cloned().collect();
    for key in keys {
        let mut visiting = Vec::new();
        let resolved = resolve_entry(&key, merged, &mut visiting);
        merged.insert(key, resolved);
    }
}

/// Fully resolve one entry, following `#VAR#` references depth-first.
/// `visiting` is the current resolution stack, for cycle detection.
fn resolve_entry(key: &str, table: &HashMap<String, String>, visiting: &mut Vec<String>) -> String {
    if visiting.iter().any(|k| k == key) {
        let mut chain = visiting.clone();
        chain.push(key.to_string());
        panic!(
            "cyclic #VAR# reference in staged descriptions: {}",
            chain.join(" -> ")
        );
    }
    visiting.push(key.to_string());
    let text = table.get(key).cloned().unwrap_or_default();
    let out = substitute_vars(&text, table, visiting);
    visiting.pop();
    out
}

/// Single pass of `#VAR#` substitution over one entry's text, resolving each
/// placeholder recursively. A `#` without a closing `#`, or one whose
/// content is not a variable name, is literal (e.g. the `#audit_bugs` URL
/// fragment).
fn substitute_vars(
    text: &str,
    table: &HashMap<String, String>,
    visiting: &mut Vec<String>,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('#') {
        let after = &rest[start + 1..];
        match after.find('#') {
            Some(end) => {
                let var = &after[..end];
                if !var.is_empty() && var.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    let referrer = visiting.last().cloned().unwrap_or_default();
                    if !table.contains_key(var) {
                        panic!("staged description {referrer:?} references unknown #{var}#");
                    }
                    out.push_str(&rest[..start]);
                    out.push_str(&resolve_entry(var, table, visiting));
                    rest = &after[end + 1..];
                } else {
                    out.push_str(&rest[..=start]);
                    rest = after;
                }
            }
            None => break,
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A leftover `#VAR#` placeholder. A bare `#` (as in the
    /// `#audit_bugs` URL fragment) is not a variable.
    fn unresolved_var(text: &str) -> bool {
        let mut rest = text;
        while let Some(start) = rest.find('#') {
            let after = &rest[start + 1..];
            match after.find('#') {
                Some(end) => {
                    let var = &after[..end];
                    if !var.is_empty() && var.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        return true;
                    }
                    rest = after;
                }
                None => return false,
            }
        }
        false
    }

    fn panic_message(r: std::thread::Result<()>) -> String {
        let payload = r.unwrap_err();
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    #[test]
    fn self_referential_variable_fails_loudly() {
        let mut table = HashMap::from([("A".to_string(), "#A#".to_string())]);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            replace_description_variables(&mut table);
        }));
        assert!(r.is_err(), "self-reference must not resolve silently");
        let msg = panic_message(r);
        assert!(msg.contains("cyclic"), "unexpected panic: {msg}");
        assert!(msg.contains("A -> A"), "chain not named: {msg}");
    }

    #[test]
    fn two_cycle_with_surrounding_text_fails_loudly() {
        // The old fixed-point loop spun forever here: every pass grew the
        // strings, so `changed` never settled.
        let mut table = HashMap::from([
            ("A".to_string(), "x #B#".to_string()),
            ("B".to_string(), "y #A#".to_string()),
        ]);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            replace_description_variables(&mut table);
        }));
        assert!(r.is_err(), "cycle must not spin forever");
        let msg = panic_message(r);
        assert!(msg.contains("cyclic"), "unexpected panic: {msg}");
        assert!(
            msg.contains('A') && msg.contains('B'),
            "chain not named: {msg}"
        );
    }

    #[test]
    fn unknown_variable_names_the_referring_entry() {
        let mut table = HashMap::from([("ENTRY".to_string(), "see #NOPE# here".to_string())]);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            replace_description_variables(&mut table);
        }));
        assert!(r.is_err(), "unknown variable must fail loudly");
        let msg = panic_message(r);
        assert!(msg.contains("ENTRY"), "referrer not named: {msg}");
        assert!(msg.contains("#NOPE#"), "variable not named: {msg}");
    }

    #[test]
    fn nested_acyclic_variables_resolve_fully() {
        let mut table = HashMap::from([
            ("A".to_string(), "a #B# #C#".to_string()),
            ("B".to_string(), "b #D#".to_string()),
            ("C".to_string(), "c".to_string()),
            ("D".to_string(), "d".to_string()),
        ]);
        replace_description_variables(&mut table);
        assert_eq!(table["A"], "a b d c");
        assert_eq!(table["B"], "b d");
    }

    #[test]
    fn staged_corpus_loads_and_resolves_variables() {
        let descriptions = staged_descriptions();
        // `#REVIEW_NEEDED_TEXT#` embeds `#AUDIT_BUG_URL#`: both must resolve.
        let device = &descriptions["device-unauthorized-file"];
        assert!(!unresolved_var(device), "unresolved variable in: {device}");
        assert!(
            device.contains(
                "https://en.opensuse.org/openSUSE:Package_security_guidelines#audit_bugs"
            )
        );
        // Plain entries pass through untouched.
        assert_eq!(
            descriptions["uncompressed-zip"],
            "The zip file is not compressed.\n"
        );
    }

    /// The 15 staged description files, byte-pinned: any edit, truncation,
    /// or bad rebase merge changes a hash. Provenance of each file against
    /// the pinned reference (`84848c0`) is documented in
    /// `data/descriptions/README.md`.
    #[test]
    fn staged_toml_files_are_pinned() {
        use sha2::{Digest, Sha256};
        let pinned: &[(&str, &str)] = &[
            (
                "AtomicUpdateCheck.toml",
                "d3878db058303c051de21eeb464179e1fe660457f318fb2756f51d42f58e289c",
            ),
            (
                "BinariesCheck.toml",
                "c641607ac210f5820d81956c70147cbd6610edcfb9037bddef9d4e97d8b026a7",
            ),
            (
                "ConfigFilesCheck.toml",
                "4c026df7eff586f7ba46cf07719cd8235dca25e30fb4e07de5e73331008a86bf",
            ),
            (
                "DeviceFilesCheck.toml",
                "bc009d9bd4058a4602aebcce655dec2fc7d784c13425875a2a5ac242caa8d38f",
            ),
            (
                "I18NCheck.toml",
                "d3e474f88850adfd48fb963a02d5324c76f2b43b861087f94e1927ccbf7e5ff5",
            ),
            (
                "IconSizesCheck.toml",
                "a51bddc5b66a4958b0707bc5a2ef05b7ba39ba0e7d9951dcbcf76dfc2d94d2ce",
            ),
            (
                "LibraryDependencyCheck.toml",
                "2263735551a41186b48588ccc8176ceaca36399b600407fa2c4c4be4f50856aa",
            ),
            (
                "MixedOwnershipCheck.toml",
                "2f12570e6b429b07f6ae04f8f8058b1feca8576c66e9fff3aadfdf557f5e7be4",
            ),
            (
                "PAMModulesCheck.toml",
                "6644539632fe3d9f5d4c12a1593b23ec227212ad8342007b7fa06ca8c0565f7d",
            ),
            (
                "SourceCheck.toml",
                "7b491c89b33ba2362dfb775f6ea360a104efbdeb77a50bb002874962bb9152c6",
            ),
            (
                "Variables.toml",
                "1f16f802df34c12091239310164f0727e800e66eb75fcce8b108bbf5b47bad92",
            ),
            (
                "WorldWritableCheck.toml",
                "4b0e6ecfabd5be179bbbf51ea66802aeddcd13c60e621f20907735cbf50069fe",
            ),
            (
                "XinetdDepCheck.toml",
                "b06d87b46bbd576b8ae3064d541d08ddcfb308c68901bf1ec7406a88743d8f0b",
            ),
            (
                "ZipCheck.toml",
                "48b0053c4eda21d28d80abda66570882e720c0bd6ded4b0983852695bfe428ea",
            ),
            (
                "ZyppSyntaxCheck.toml",
                "0c3b686f87244b2d5f3ad4db4a4ec95fe6ff6b1f97e3201b8d2f24530a5410a2",
            ),
        ];
        assert_eq!(pinned.len(), STAGED.len(), "pin every staged file");
        for ((name, expected), raw) in pinned.iter().zip(STAGED.iter()) {
            let mut h = Sha256::new();
            h.update(raw.as_bytes());
            let got: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(&got, expected, "staged file {name} changed");
        }
    }

    #[test]
    fn every_staged_variable_resolves() {
        let descriptions = staged_descriptions();
        for (k, v) in &descriptions {
            assert!(
                !unresolved_var(v),
                "unresolved variable in staged description {k}: {v}"
            );
        }
    }
}
