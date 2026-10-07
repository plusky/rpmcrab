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
                "0ca651303419582d8eee3e3cc8a5269b3051068ea517a9c7dc1a1081feb0618a",
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
                "d806458289d950f477e7a5da2d98f51c2ae125fc4b225dca1841a81dd455e35f",
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
                "fcb653433c3b6e59dfbcdefbcc1f13fe998b3bcdaa130415f4da574e374ed694",
            ),
            (
                "FilesCheck.toml",
                "0a31a9747d558b3d0d640b0496db4b3b49893e7cc73f75d8207fd65101c26afb",
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
                "ff31ebe15488f56277851a98914be28af295ff8643184d004d2ff20f71da9f19",
            ),
            (
                "MenuCheck.toml",
                "373e9c6e375dcb1c7e3bcec10e664c8884334608c88e54fddc72e1703ee49a7d",
            ),
            (
                "MenuXDGCheck.toml",
                "6e55c908f703f4c00f2c153788210298c98bb1b1ca0017ad9bcdd79622f9a34f",
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
                "49e4b376d2751cc7812af728b779938aa79f3de9c6d370b6c6a74eeff7fdfbee",
            ),
            (
                "SourceCheck.toml",
                "7b491c89b33ba2362dfb775f6ea360a104efbdeb77a50bb002874962bb9152c6",
            ),
            (
                "SpecCheck.toml",
                "d7e29c5ed54de2e3fe8d1199336c5a39a7125c2c67da24fadaa37aa34883df88",
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
                "4c1de7fd03501549352656b445ca95ad528274e6d65b4db2bf38e55c527d66a8",
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
                "d4271d3a9848eda2c043d5825d6ef64c3d6225abc1fc3bf8766f26fa94b58144",
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

    /// The reference's `use-of-RPM_SOURCE_DIR` advice ("use $RPM_BUILD_ROOT
    /// instead") is wrong: `$RPM_SOURCE_DIR` is `%{_sourcedir}` (the SOURCES
    /// dir) while `$RPM_BUILD_ROOT` is the install staging dir. The staged
    /// text is reworded per the Fedora RPM_Source_Dir guideline: `Source#:`
    /// files go by their `%{SOURCEN}` macro, because a renamed `Source#:`
    /// entry still resolves by bare filename in the source directory — the
    /// build succeeds locally while the SRPM silently ships the wrong file.
    /// Byte-exact `--explain` pin; the check itself stays at Error.
    #[test]
    fn explain_reworded_use_of_rpm_source_dir() {
        let config = crate::config::load_bundled();
        let mut filter =
            crate::filter::Filter::new(&config, crate::color::Color::for_tty(false)).unwrap();
        crate::check::register_error_details(&config, &mut filter);
        // The `--explain` path prints `filter.explanation(id)` with one
        // trailing newline (`println!`).
        let stdout = format!("{}\n", filter.explanation("use-of-RPM_SOURCE_DIR", &config));
        assert_eq!(
            stdout,
            "use-of-RPM_SOURCE_DIR:\n\
             You use $RPM_SOURCE_DIR or %{_sourcedir} in your spec file. Files itemized as\n\
             Source#: must be referenced by their %{SOURCEN} macro instead: if a Source#:\n\
             entry is renamed, the old filename still resolves in the source directory, so\n\
             the build succeeds locally while the SRPM silently ships the wrong file.\n\n\n",
            "exact --explain stdout",
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
        // Reverse direction: every *.toml on disk must be wired into STAGED,
        // so a stray unwired file fails here instead of staying silently inert.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data/descriptions");
        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("cannot list description dir {dir:?}: {e}"))
            .map(|entry| {
                entry
                    .unwrap_or_else(|e| panic!("cannot read description dir entry {dir:?}: {e}"))
                    .file_name()
            })
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".toml"))
            .collect();
        on_disk.sort_unstable();
        for name in on_disk {
            assert!(
                staged.contains(&name),
                "staged description `{name}` is on disk but not wired into STAGED"
            );
        }
    }
    /// Finding-ID patterns constructed at runtime via `format!`; they cannot
    /// be enumerated by static source parsing. Each entry has a one-line
    /// comment giving the construction site and why the ID varies.
    const DYNAMIC_FINDING_PATTERNS: &[&str] = &[
        // menu.rs: `format!("{typ}-icon-not-in-package")`, `typ` from the config `IconPath` table.
        "*-icon-not-in-package",
        // tags.rs: `format!("no-epoch-in-{tagname}")`; concrete IDs get in-code descriptions.
        "no-epoch-in-*",
        // fhs.rs: `format!("non-standard-dir-in-{dir_type}")`; concrete IDs get in-code descriptions.
        "non-standard-dir-in-*",
        // files.rs: `format!("dir-or-file-in-{}")` from config `DisallowedDirs`; concrete IDs get in-code descriptions.
        "dir-or-file-in-*",
        // filelist.rs: `Message` from the config `[[Check]]` list.
        "filelist-forbidden*",
        // file_digest.rs: `format!("{check_type}-file-{kind}")`, `check_type` from config `FileDigestLocation` tables.
        "*-file-digest-mismatch",
        "*-file-ghost",
        "*-file-symlink",
        "*-file-unauthorized",
        "*-file-parse-error",
        // i18n.rs: `format!("incorrect-i18n-tag-{correct}")`; concrete IDs get in-code descriptions per `INCORRECT_LOCALES`.
        "incorrect-i18n-tag-*",
        // i18n.rs: `format!("incorrect-locale-{correct}")`; concrete IDs get in-code descriptions per `INCORRECT_LOCALES`.
        "incorrect-locale-*",
    ];

    /// Finding IDs with live emission sites the static parser cannot see
    /// (unusual patterns: struct fields, `out.push`, match arms). Each entry
    /// names the pattern so a future refactor can drop it from this list.
    const STATICALLY_OPAQUE_LIVE_IDS: &[&str] = &[
        // i18n.rs: struct field `invalid: ...then_some("invalid-lc-messages-dir")`.
        "invalid-lc-messages-dir",
        // i18n.rs: struct field for man dir locale.
        "invalid-locale-man-dir",
        // library_dependency.rs: emitted via helper with variable ID.
        "no-library-dependency-for",
        "no-library-dependency-on",
        // suid_permissions.rs: `diag` variable from helper.
        "permissions-directory-setuid-bit",
        "permissions-file-setuid-bit",
        // python.rs: match arms mapping dir names to IDs.
        "python-doc-in-site-packages",
        "python-src-in-site-packages",
        "python-tests-in-site-packages",
        // alternatives.rs: variable ID from helper.
        "update-alternatives-post-call-missing",
        // filelist.rs: `Message` from bundled `[[Check]]` config (not the default `filelist-forbidden*` family).
        "wrong-suse-capitalisation",
        // bashisms.rs: `out.push("...")` into a findings vec.
        "bin-sh-syntax-error",
        "potential-bashisms",
        // configfiles.rs: `out.push("...")` into a findings vec, emitted via variable.
        // spec.rs: `format!("no-%{sec}-section")` loop over prep/build/install/check;
        // the parser sees only `&check`, not the IDs.
        "conffile-without-noreplace-flag",
        "non-etc-or-var-file-marked-as-conffile",
        "no-%prep-section",
        "no-%build-section",
        "no-%install-section",
        "no-%check-section",
    ];

    fn matches_dynamic(id: &str) -> bool {
        DYNAMIC_FINDING_PATTERNS.iter().any(|p| {
            if let Some(prefix) = p.strip_suffix('*') {
                id.starts_with(prefix)
            } else if let Some(suffix) = p.strip_prefix('*') {
                id.ends_with(suffix)
            } else {
                id == *p
            }
        })
    }

    /// All `src/checks/*.rs` sources, read at test time so new check files
    /// are covered without editing this test.
    fn check_sources() -> Vec<String> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/checks");
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .expect("checks dir is readable")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
            .collect();
        paths.sort();
        paths
            .into_iter()
            .map(|p| std::fs::read_to_string(&p).expect("check source is readable"))
            .collect()
    }

    /// Whether `s` looks like a finding ID: lowercase alphanumerics,
    /// dashes and `%` (e.g. `%ifarch-applied-patch`), no `format!`
    /// placeholders.
    fn is_finding_id(s: &str) -> bool {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'%')
    }

    /// String literals in `text` that look like finding IDs.
    fn finding_literals(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut in_str = false;
        let mut esc = false;
        let mut cur = String::new();
        for c in text.chars() {
            if in_str {
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == '"' {
                    in_str = false;
                    if is_finding_id(&cur) {
                        out.push(std::mem::take(&mut cur));
                    } else {
                        cur.clear();
                    }
                    continue;
                }
                cur.push(c);
            } else if c == '"' {
                in_str = true;
                cur.clear();
            }
        }
        out
    }

    /// The 4th comma-separated argument of the call whose opening paren ends
    /// at byte index `open` (index just after `(`), respecting nesting and
    /// string literals.
    fn fourth_arg(src: &str, open: usize) -> Option<String> {
        let chars: Vec<(usize, char)> = src[open..].char_indices().collect();
        let mut depth = 0i32;
        let mut arg_idx = 0;
        let mut arg_start = 0;
        let mut in_str = false;
        let mut esc = false;
        let mut i = 0;
        while i < chars.len() {
            let (byte_off, c) = chars[i];
            let abs_byte = open + byte_off;
            if in_str {
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == '"' {
                    in_str = false;
                }
            } else if c == '"' {
                in_str = true;
            } else if c == '(' || c == '[' || c == '{' {
                depth += 1;
            } else if c == ')' || c == ']' || c == '}' {
                if depth == 0 {
                    return if arg_idx == 3 {
                        Some(src[open + arg_start..abs_byte].to_string())
                    } else {
                        None
                    };
                }
                depth -= 1;
            } else if c == ',' && depth == 0 {
                arg_idx += 1;
                if arg_idx == 4 {
                    return Some(src[open + arg_start..abs_byte].to_string());
                }
                // arg starts after this comma (at next char's byte offset)
                arg_start = if i + 1 < chars.len() {
                    chars[i + 1].0
                } else {
                    byte_off + c.len_utf8()
                };
            }
            i += 1;
        }
        None
    }

    /// Byte indices just after the `(` of `add_info(` (free function) and
    /// `.info(` (SpecCheck's method); the finding ID is the 4th argument in
    /// both.
    fn emission_call_opens(src: &str) -> Vec<usize> {
        let mut out = Vec::new();
        let mut search = 0;
        while search < src.len() {
            let rest = &src[search..];
            if let Some(pos) = rest.find("add_info(") {
                let abs = search + pos;
                let ok = abs == 0 || {
                    let p = src[..abs].chars().next_back().unwrap();
                    !p.is_alphanumeric() && p != '_' && p != '.'
                };
                if ok {
                    out.push(abs + "add_info(".len());
                }
                search = abs + 1;
            } else if let Some(pos) = rest.find(".info(") {
                let abs = search + pos;
                out.push(abs + ".info(".len());
                search = abs + 1;
            } else {
                break;
            }
        }
        out
    }

    /// Finding IDs from `(Level::X, "id", ...)` tuples (helpers returning
    /// findings for later emission).
    fn tuple_literals(src: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut search = 0;
        while let Some(pos) = src[search..].find("(Level::") {
            let abs = search + pos;
            if let Some(comma) = src[abs..].find(',') {
                let rest = src[abs + comma + 1..].trim_start();
                if let Some(lit) = rest.strip_prefix('"') {
                    let mut esc = false;
                    let mut cur = String::new();
                    let mut done = false;
                    for c in lit.chars() {
                        if esc {
                            esc = false;
                        } else if c == '\\' {
                            esc = true;
                        } else if c == '"' {
                            done = true;
                            break;
                        }
                        cur.push(c);
                    }
                    if done && is_finding_id(&cur) {
                        out.push(cur);
                    }
                }
            }
            search = abs + 1;
        }
        out
    }

    /// Bodies of the finding-collector helpers: functions returning
    /// `Vec<(&'static str, ...)>` (`LSBCheck::collect`,
    /// `PkgConfigCheck::check_line`, ...). Their `("kebab-id", ...)` tuples
    /// are emitted later through a variable, invisible to the `(Level::X,
    /// "id", ...)` tuple scan and the fourth-argument scan. Brace matching
    /// skips strings, char literals and comments so a `}` inside any of
    /// those cannot end the body early.
    fn finding_helper_bodies(src: &str) -> Vec<&str> {
        const NEEDLE: &[u8] = b"-> Vec<(&'static str";
        let bytes = src.as_bytes();
        let mut out = Vec::new();
        let mut search = 0;
        while search < bytes.len() {
            let Some(rel) = bytes[search..]
                .windows(NEEDLE.len())
                .position(|w| w == NEEDLE)
            else {
                break;
            };
            // The return type holds no braces, so the next `{` opens the
            // function body.
            let mut i = search + rel + NEEDLE.len();
            while i < bytes.len() && bytes[i] != b'{' {
                i += 1;
            }
            if i >= bytes.len() {
                break;
            }
            if let Some(end) = brace_matched_end(bytes, i) {
                out.push(&src[i..end]);
                search = end;
            } else {
                break;
            }
        }
        out
    }

    /// Byte index just past the `}` matching the `{` at `open`. String
    /// literals, char literals and line/block comments are skipped; all the
    /// syntax characters matched here are ASCII, which never appear inside
    /// a multi-byte UTF-8 sequence.
    fn brace_matched_end(bytes: &[u8], open: usize) -> Option<usize> {
        #[derive(PartialEq)]
        enum State {
            Code,
            Str,
            Chr,
            LineComment,
            BlockComment,
        }
        let mut state = State::Code;
        let mut block_depth = 0u32;
        let mut depth = 0u32;
        let mut esc = false;
        let mut i = open;
        while i < bytes.len() {
            let c = bytes[i];
            let next = bytes.get(i + 1).copied();
            match state {
                State::Code => {
                    if c == b'"' {
                        state = State::Str;
                    } else if c == b'\'' {
                        state = State::Chr;
                    } else if c == b'/' && next == Some(b'/') {
                        state = State::LineComment;
                        i += 1;
                    } else if c == b'/' && next == Some(b'*') {
                        state = State::BlockComment;
                        block_depth = 1;
                        i += 1;
                    } else if c == b'{' {
                        depth += 1;
                    } else if c == b'}' {
                        depth -= 1;
                        if depth == 0 {
                            return Some(i + 1);
                        }
                    }
                }
                State::Str | State::Chr => {
                    let quote = if state == State::Str { b'"' } else { b'\'' };
                    if esc {
                        esc = false;
                    } else if c == b'\\' {
                        esc = true;
                    } else if c == quote {
                        state = State::Code;
                    }
                }
                State::LineComment => {
                    if c == b'\n' {
                        state = State::Code;
                    }
                }
                State::BlockComment => {
                    if c == b'/' && next == Some(b'*') {
                        block_depth += 1;
                        i += 1;
                    } else if c == b'*' && next == Some(b'/') {
                        block_depth -= 1;
                        i += 1;
                        if block_depth == 0 {
                            state = State::Code;
                        }
                    }
                }
            }
            i += 1;
        }
        None
    }

    /// Finding IDs from `("kebab-id", ...)` string-first 2-tuples inside the
    /// finding-collector helper bodies: literals emitted later through a
    /// variable (`LSBCheck::collect`, ...). A `(` following an identifier is
    /// a call's argument list, not a tuple (`dep("name", 0)`).
    fn string_tuple_literals(src: &str) -> Vec<String> {
        let bytes = src.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'(' {
                let mut p = i;
                while p > 0 && bytes[p - 1].is_ascii_whitespace() {
                    p -= 1;
                }
                let is_call =
                    p > 0 && (bytes[p - 1].is_ascii_alphanumeric() || bytes[p - 1] == b'_');
                if !is_call {
                    let mut j = i + 1;
                    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j < bytes.len() && bytes[j] == b'"' {
                        let mut k = j + 1;
                        let mut esc = false;
                        let mut cur = String::new();
                        let mut done = false;
                        while k < bytes.len() {
                            let c = bytes[k];
                            if esc {
                                esc = false;
                            } else if c == b'\\' {
                                esc = true;
                            } else if c == b'"' {
                                done = true;
                                break;
                            }
                            cur.push(c as char);
                            k += 1;
                        }
                        if done {
                            let mut m = k + 1;
                            while m < bytes.len() && bytes[m].is_ascii_whitespace() {
                                m += 1;
                            }
                            if m < bytes.len() && bytes[m] == b',' && is_finding_id(&cur) {
                                out.push(cur);
                            }
                        }
                    }
                }
            }
            i += 1;
        }
        out
    }

    /// All statically-enumerated finding IDs emitted across the checks.
    fn emitted_finding_ids(sources: &[String]) -> Vec<String> {
        let mut ids = std::collections::HashSet::new();
        for src in sources {
            for open in emission_call_opens(src) {
                if let Some(arg) = fourth_arg(src, open) {
                    for id in finding_literals(&arg) {
                        ids.insert(id);
                    }
                }
            }
            for id in tuple_literals(src) {
                ids.insert(id);
            }
            for body in finding_helper_bodies(src) {
                for id in string_tuple_literals(body) {
                    ids.insert(id);
                }
            }
        }
        let mut v: Vec<_> = ids.into_iter().collect();
        v.sort();
        v
    }

    /// Finding IDs with in-code `--explain` descriptions via
    /// `set_error_detail("id", ...)`.
    fn incode_description_ids(sources: &[String]) -> Vec<String> {
        let mut ids = std::collections::HashSet::new();
        for src in sources {
            let mut search = 0;
            while let Some(pos) = src[search..].find("set_error_detail") {
                let abs = search + pos;
                let rest = src[abs + "set_error_detail".len()..].trim_start();
                if let Some(inner) = rest.strip_prefix('(') {
                    let inner = inner.trim_start();
                    if let Some(lit) = inner.strip_prefix('"') {
                        let mut esc = false;
                        let mut cur = String::new();
                        let mut done = false;
                        for c in lit.chars() {
                            if esc {
                                esc = false;
                            } else if c == '\\' {
                                esc = true;
                            } else if c == '"' {
                                done = true;
                                break;
                            }
                            cur.push(c);
                        }
                        if done && is_finding_id(&cur) {
                            ids.insert(cur);
                        }
                    }
                }
                search = abs + 1;
            }
        }
        let mut v: Vec<_> = ids.into_iter().collect();
        v.sort();
        v
    }

    /// Every finding a check can emit must resolve to an `--explain`
    /// description: a staged TOML entry, an in-code `set_error_detail`
    /// registration, or an allowlisted dynamic pattern. Emitting a finding
    /// without a description fails here.
    #[test]
    fn every_emitted_finding_has_description() {
        let sources = check_sources();
        let emitted = emitted_finding_ids(&sources);
        let incode: std::collections::HashSet<_> =
            incode_description_ids(&sources).into_iter().collect();
        let staged = staged_descriptions();
        assert!(!emitted.is_empty(), "no finding IDs parsed from checks");
        let mut missing = Vec::new();
        for id in emitted {
            if !staged.contains_key(&id) && !incode.contains(&id) && !matches_dynamic(&id) {
                missing.push(id);
            }
        }
        assert!(
            missing.is_empty(),
            "findings without --explain descriptions: {}\nAdd a staged TOML entry, an in-code set_error_detail registration, or a DYNAMIC_FINDING_PATTERNS entry with justification.",
            missing.join(", ")
        );
    }

    /// Every staged description must correspond to a live finding: a
    /// statically-emitted ID, an in-code registration, an allowlisted dynamic
    /// pattern, a manually-verified opaque emission site, or a quoted literal
    /// anywhere in the check sources (catches unusual emission patterns).
    /// Stale entries fail here instead of lingering.
    #[test]
    fn every_staged_description_has_finding() {
        let sources = check_sources();
        let emitted: std::collections::HashSet<_> =
            emitted_finding_ids(&sources).into_iter().collect();
        let incode: std::collections::HashSet<_> =
            incode_description_ids(&sources).into_iter().collect();
        let opaque: std::collections::HashSet<_> = STATICALLY_OPAQUE_LIVE_IDS
            .iter()
            .map(|s| s.to_string())
            .collect();
        let staged = staged_descriptions();
        let mut dangling = Vec::new();
        'keys: for key in staged.keys() {
            // `Variables.toml` constants (`#VAR#` substitution), not findings.
            if key.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                continue;
            }
            if emitted.contains(key)
                || incode.contains(key)
                || opaque.contains(key)
                || matches_dynamic(key)
            {
                continue;
            }
            // Fallback: the ID appears as a quoted literal in the check
            // sources (unusual emission patterns the parser cannot see).
            let quoted = format!("\"{key}\"");
            for src in &sources {
                if src.contains(&quoted) {
                    continue 'keys;
                }
            }
            dangling.push(key.clone());
        }
        dangling.sort();
        assert!(
            dangling.is_empty(),
            "staged descriptions without a live finding: {}\nDelete the entry, or document the emission site in STATICALLY_OPAQUE_LIVE_IDS / DYNAMIC_FINDING_PATTERNS.",
            dangling.join(", ")
        );
    }
}
