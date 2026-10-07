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
    include_str!("../data/descriptions/AlternativesCheck.toml"),
    include_str!("../data/descriptions/AppDataCheck.toml"),
    include_str!("../data/descriptions/AtomicUpdateCheck.toml"),
    include_str!("../data/descriptions/BashismsCheck.toml"),
    include_str!("../data/descriptions/BinariesCheck.toml"),
    include_str!("../data/descriptions/BrandingPolicyCheck.toml"),
    include_str!("../data/descriptions/BuildRootAndDateCheck.toml"),
    include_str!("../data/descriptions/CheckForXinetd.toml"),
    include_str!("../data/descriptions/ConfigFilesCheck.toml"),
    include_str!("../data/descriptions/DBusPolicyCheck.toml"),
    include_str!("../data/descriptions/DeviceFilesCheck.toml"),
    include_str!("../data/descriptions/DocCheck.toml"),
    include_str!("../data/descriptions/DuplicatesCheck.toml"),
    include_str!("../data/descriptions/ErlangCheck.toml"),
    include_str!("../data/descriptions/FileDigestCheck.toml"),
    include_str!("../data/descriptions/FileMetadataCheck.toml"),
    include_str!("../data/descriptions/FilelistCheck.toml"),
    include_str!("../data/descriptions/FilesCheck.toml"),
    include_str!("../data/descriptions/I18NCheck.toml"),
    include_str!("../data/descriptions/IconSizesCheck.toml"),
    include_str!("../data/descriptions/KMPPolicyCheck.toml"),
    include_str!("../data/descriptions/LSBCheck.toml"),
    include_str!("../data/descriptions/LibraryDependencyCheck.toml"),
    include_str!("../data/descriptions/LogrotateCheck.toml"),
    include_str!("../data/descriptions/MenuCheck.toml"),
    include_str!("../data/descriptions/MenuXDGCheck.toml"),
    include_str!("../data/descriptions/MixedOwnershipCheck.toml"),
    include_str!("../data/descriptions/PAMModulesCheck.toml"),
    include_str!("../data/descriptions/PkgConfigCheck.toml"),
    include_str!("../data/descriptions/PolkitCheck.toml"),
    include_str!("../data/descriptions/PythonCheck.toml"),
    include_str!("../data/descriptions/SELinuxIndependentModuleCheck.toml"),
    include_str!("../data/descriptions/SUIDPermissionsCheck.toml"),
    include_str!("../data/descriptions/SharedLibraryPolicyCheck.toml"),
    include_str!("../data/descriptions/SignatureCheck.toml"),
    include_str!("../data/descriptions/SourceCheck.toml"),
    include_str!("../data/descriptions/SpecCheck.toml"),
    include_str!("../data/descriptions/SysVInitOnSystemdCheck.toml"),
    include_str!("../data/descriptions/SystemdInstallCheck.toml"),
    include_str!("../data/descriptions/SystemdTmpfilesCheck.toml"),
    include_str!("../data/descriptions/TagsCheck.toml"),
    include_str!("../data/descriptions/TmpFilesCheck.toml"),
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
    fn three_cycle_fails_loudly() {
        // Longer rings go through the same chain-tracking path as the
        // two-cycle: the entry point depends on HashMap iteration order,
        // so the assertion names every member without pinning order.
        let mut table = HashMap::from([
            ("A".to_string(), "#B#".to_string()),
            ("B".to_string(), "#C#".to_string()),
            ("C".to_string(), "#A#".to_string()),
        ]);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            replace_description_variables(&mut table);
        }));
        assert!(r.is_err(), "cycle must not spin forever");
        let msg = panic_message(r);
        assert!(msg.contains("cyclic"), "unexpected panic: {msg}");
        assert!(
            msg.contains('A') && msg.contains('B') && msg.contains('C'),
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

    /// The 47 staged description files, byte-pinned: any edit, truncation,
    /// or bad rebase merge changes a hash. Provenance of each file against
    /// the pinned reference (`84848c0`) is documented in
    /// `data/descriptions/README.md`.

    #[test]
    fn staged_toml_files_are_pinned() {
        use sha2::{Digest, Sha256};
        let pinned: &[(&str, &str)] = &[
            (
                "AlternativesCheck.toml",
                "d423336243cdb0f96d367c7fb8ddebf936ede9fa3c5a8d95ccb55e2c9acf1458",
            ),
            (
                "AppDataCheck.toml",
                "a7ebdfead7b1aef79273fd76878647227b2fed6f977a49761bd88eda68dc5241",
            ),
            (
                "AtomicUpdateCheck.toml",
                "d3878db058303c051de21eeb464179e1fe660457f318fb2756f51d42f58e289c",
            ),
            (
                "BashismsCheck.toml",
                "d1235f30411c3b9a6a5843461a7d80a54465b77cf4ea4dce2908247635db63a2",
            ),
            (
                "BinariesCheck.toml",
                "c641607ac210f5820d81956c70147cbd6610edcfb9037bddef9d4e97d8b026a7",
            ),
            (
                "BrandingPolicyCheck.toml",
                "eab07cd05c29feaa5b2a537aff908d815f15a39bb14a00cd2c70270aa7c9d24a",
            ),
            (
                "BuildRootAndDateCheck.toml",
                "210a6d9b95b683072b46e7734a81583beea0f7169ec11479fefdf6e44ffa45f5",
            ),
            (
                "CheckForXinetd.toml",
                "985a789bb7e6671d530a60a19215b6b250e693fd3e25cb0e0bb34fd57a8e594a",
            ),
            (
                "ConfigFilesCheck.toml",
                "4c026df7eff586f7ba46cf07719cd8235dca25e30fb4e07de5e73331008a86bf",
            ),
            (
                "DBusPolicyCheck.toml",
                "df4abb3068b47bc1dbb3c6bbd79911866efa038fed8b9dc31c9873008d3703b5",
            ),
            (
                "DeviceFilesCheck.toml",
                "c478130450cf85993df51fd59bf5c3f8cc900aefd0b71c7a09d6bd51faad5ace",
            ),
            (
                "DocCheck.toml",
                "94929cc2087b74f1af0bed8050805ba69372a503f267bca7224f3c7429663de0",
            ),
            (
                "DuplicatesCheck.toml",
                "ab5e07931eed229932c07fa17bf3ef75bc278ad5cec5e8fe25a2619ea60dc79a",
            ),
            (
                "ErlangCheck.toml",
                "48df0f4ba8f088c5a50425a6a3b84811b3404a62dbc6505ce1388cf98800f9fd",
            ),
            (
                "FileDigestCheck.toml",
                "2ed29b916b02a456a60c3dc87d99d17325d22d6e4ab9ff4f5a68cc40a6752f4d",
            ),
            (
                "FileMetadataCheck.toml",
                "337ce93d39a4c182ae04b9909533ea502e60deb005a25a61f2649163907e8901",
            ),
            (
                "FilelistCheck.toml",
                "21f9f0db18fe90a0cbf1e53ad222e77236e5affe75aca6265feae65ca884890e",
            ),
            (
                "FilesCheck.toml",
                "fed1fec48f73a0ba249d15e605201ef70651f2fc9dff2dd1567649f3d8ffa855",
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
                "KMPPolicyCheck.toml",
                "eab5b6cfe39e79e8e2f19328214970f5a4cccfd9c7a596beb5122d9a922f6493",
            ),
            (
                "LSBCheck.toml",
                "8d8693d4f0f7169ddc7e8031aef0f7a8a1689d393aa68068a02c967d2a08958a",
            ),
            (
                "LibraryDependencyCheck.toml",
                "2263735551a41186b48588ccc8176ceaca36399b600407fa2c4c4be4f50856aa",
            ),
            (
                "LogrotateCheck.toml",
                "25c54f3ab3b9a77ae53c6caff8e6fd904f008bd272327e47989819ff2594f7a4",
            ),
            (
                "MenuCheck.toml",
                "2c0d654ef52bd397aa2f0642ec6920919fc49989acf6a47c59ebe1fbe3ee2f24",
            ),
            (
                "MenuXDGCheck.toml",
                "3d015c3bfd054208bdf0eea23cce623e208ff3197149cf8041224248d73b0739",
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
                "PkgConfigCheck.toml",
                "fa5aebc5e51fcdb42ae2c45fa185f50cd851d580d4da1fe9c21bcf85e5dd655a",
            ),
            (
                "PolkitCheck.toml",
                "e9a8b8246e7227e1df94dacce99a5eaf4bc98a22b07c5ecf2203882ab3b8e77a",
            ),
            (
                "PythonCheck.toml",
                "4e531ff3d2f94153a9137f6aa0d42b35b69c8a20e9063076b9cd6050e9e7552d",
            ),
            (
                "SELinuxIndependentModuleCheck.toml",
                "e528a746c24b29b9342dcceff47bb2589d9f9b51dbe49d99c62c33410cc8e652",
            ),
            (
                "SUIDPermissionsCheck.toml",
                "56156810855981231341ebf3c1e6490878f4c3dfc0de42fa2f7ef75bb312df26",
            ),
            (
                "SharedLibraryPolicyCheck.toml",
                "5c86008e156d20ed9000ffc7a1af8beeef25981878730ae25f14d4720faf2342",
            ),
            (
                "SignatureCheck.toml",
                "70d774d2460a8ba85a0a2f00a50f6491a932926e346aa7e6b93b9060751b11be",
            ),
            (
                "SourceCheck.toml",
                "7b491c89b33ba2362dfb775f6ea360a104efbdeb77a50bb002874962bb9152c6",
            ),
            (
                "SpecCheck.toml",
                "949e8272fddfcdbab5843b8b96d3873595e5de3d7577f9f1932237b857945c1b",
            ),
            (
                "SysVInitOnSystemdCheck.toml",
                "f080982b5136ff3661b84510e3a9e7dcda5410a287a39f83b67fdbdadec0ddd6",
            ),
            (
                "SystemdInstallCheck.toml",
                "96be0fba5e6d82c65270088fd9c65c2e14f805e05effb2de95990bb2eea31491",
            ),
            (
                "SystemdTmpfilesCheck.toml",
                "5817ac6b70ca3e605265eaad2d7e92b1abebd983ce061fcb719bcb397e9aa8ed",
            ),
            (
                "TagsCheck.toml",
                "50b68c01f4c33a1747f025040d558a69bdbef3ab3201bce3ec8ca6b105bdb8dc",
            ),
            (
                "TmpFilesCheck.toml",
                "c60d2945c48acdb692c114a857a0635ead12faf37da63d343b1d70a89d51e4df",
            ),
            (
                "Variables.toml",
                "1f16f802df34c12091239310164f0727e800e66eb75fcce8b108bbf5b47bad92",
            ),
            (
                "WorldWritableCheck.toml",
                "dddbb946fb9b449cff9ac37cc312f7f95365cb78aefd4039c45f4dca1f02d103",
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

    /// Upstream rpmlint#427: the reference useless-provides text claims
    /// versioned and unversioned symbols are provided at once, which is not
    /// always accurate (duplicate versioned provides trigger the check too).
    /// The staged text is reworded ahead of the reference, per the
    /// fix-in-port rule.
    #[test]
    fn useless_provides_description_is_reworded() {
        let descriptions = staged_descriptions();
        let detail = &descriptions["useless-provides"];
        assert_eq!(
            detail,
            "This package provides multiple times the same capacity.\n\
             Identical automated and manual provides exist, so the redundant manual\n\
             provide is useless: the same provide name is listed more than once\n\
             (e.g. 'foo' together with 'foo = 1.0').\n"
        );
        assert!(
            !detail.contains("versioned and unversioned symbols are provided at once"),
            "inaccurate reference wording still present: {detail}"
        );
    }


    /// Every check the registry can build has description coverage: a staged
    /// `<Name>.toml` in `STAGED` — or, for `FHSCheck`/`PostCheck`, details
    /// registered in code, mirroring the reference which ships no TOML for
    /// those two either (`fhs_details_dict` / `post_details_dict` installed
    /// in each check's `__init__`). Adding a check without either fails here.
    /// Port-only findings have no reference TOML entry to be byte-identical
    /// to; their staged descriptions are deliberate additions (ledgered as
    /// `kind="detail"`). This pins them so they cannot silently go back to
    /// `--explain` printing "Unknown message".
    #[test]
    fn port_only_findings_have_description_coverage() {
        let corpus = staged_descriptions();
        for id in ["conditional-source-or-patch", "translated-description"] {
            let text = corpus.get(id).cloned().unwrap_or_default();
            assert!(
                !text.trim().is_empty(),
                "port-only finding `{id}` has no staged --explain description"
            );
        }
    }

    #[test]
    fn every_registered_check_has_description_coverage() {
        fn check_names() -> Vec<String> {
            let src = include_str!("check.rs");
            let body = match src.find("pub fn build(") {
                Some(start) => {
                    let rest = &src[start..];
                    let end = rest.find("\n}\n").map(|i| i + 1).unwrap_or(rest.len());
                    &rest[..end]
                }
                None => panic!("check::build not found"),
            };
            body.lines()
                .filter_map(|l| {
                    let l = l.trim();
                    let rest = l.strip_prefix('"')?;
                    let end = rest.find('"')?;
                    let name = &rest[..end];
                    rest[end + 1..]
                        .trim_start()
                        .starts_with("=>")
                        .then(|| name.to_string())
                })
                .collect()
        }
        fn staged_files() -> Vec<String> {
            let src = include_str!("describe.rs");
            src.lines()
                .filter_map(|l| {
                    let l = l.trim();
                    let rest = l.strip_prefix("include_str!(\"../data/descriptions/")?;
                    let end = rest.find('"')?;
                    Some(rest[..end].to_string())
                })
                .collect()
        }
        let staged = staged_files();
        let mut checks = check_names();
        assert!(!checks.is_empty(), "no check names parsed from check.rs");
        checks.sort();
        for name in checks {
            let expected = match name.as_str() {
                // No TOML upstream either; details registered in code.
                "FHSCheck" | "PostCheck" => continue,
                _ => format!("{name}.toml"),
            };
            assert!(
                staged.contains(&expected),
                "check `{name}` has no staged description TOML: add \
                 `data/descriptions/{expected}` and wire it into STAGED"
            );
        }
    }
}
