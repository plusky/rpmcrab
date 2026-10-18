//! Registry drift guards.
//!
//! A hand-resolved rebase once deleted `pub mod binaries;` *and* its `build()`
//! arm in the same merge. The module still compiled as an orphan file, its unit
//! tests still passed (they construct the check directly), CI stayed green, and
//! `BinariesCheck` silently stopped running — a whole check, 46 findings, gone
//! from the default run, because `load()` drops names it cannot build by design.
//!
//! Module names and check names deliberately differ (`icon_sizes` vs
//! `IconSizesCheck`), so these tests compare what is actually coupled: the
//! `crate::checks::<module>::` paths in `check::build`'s match arms against the
//! module declarations in `checks/mod.rs`.

use std::path::PathBuf;

use rpmcrab_core::check;
use rpmcrab_core::config;
use rpmcrab_core::level::Level;

fn core_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Modules declared in `checks/mod.rs`, excluding the helper modules (they hold no
/// `Check` of their own: `shared` is reached through `super::shared`,
/// `file_metadata` only ever backs `DeviceFilesCheck`/`WorldWritableCheck`,
/// `file_digest_xml` only ever backs `FileDigestCheck`, and `spdx` is the
/// SPDX license table backing `TagsCheck`'s `invalid-license-spellcheck`).
fn declared_modules() -> Vec<String> {
    let src = std::fs::read_to_string(core_root().join("src/checks/mod.rs")).expect("read mod.rs");
    let modules: Vec<String> = src
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub mod "))
        .filter_map(|l| l.strip_suffix(';'))
        .map(str::to_string)
        .filter(|m| m != "shared" && m != "file_metadata" && m != "file_digest_xml" && m != "spdx")
        .collect();
    let mut sorted = modules.clone();
    sorted.sort_unstable();
    let before = sorted.len();
    sorted.dedup();
    assert_eq!(
        before,
        sorted.len(),
        "duplicate module declaration in mod.rs"
    );
    modules
}

/// `crate::checks::<module>::` paths referenced by `check::build`, i.e. the
/// modules it can actually construct.
fn modules_built_by_registry() -> Vec<String> {
    let src = std::fs::read_to_string(core_root().join("src/check.rs")).expect("read check.rs");
    let body = match src.find("pub fn build(") {
        Some(start) => {
            let rest = &src[start..];
            // Stop at the end of the match, which closes before the next item.
            let end = rest.find("\n}\n").map(|i| i + 1).unwrap_or(rest.len());
            &rest[..end]
        }
        None => panic!("check::build not found"),
    };
    let mut found: Vec<String> = body
        .match_indices("checks::")
        .filter_map(|(i, _)| {
            let tail = &body[i + "checks::".len()..];
            let end = tail.find("::")?;
            Some(tail[..end].to_string())
        })
        .collect();
    found.sort();
    found.dedup();
    found
}

/// A module that compiles but is never constructed is dead code no other test
/// can see: its own unit tests construct it directly, so they keep passing.
#[test]
fn every_declared_check_module_is_constructible() {
    let built = modules_built_by_registry();
    for module in declared_modules() {
        assert!(
            built.contains(&module),
            "`checks::{module}` is declared but `check::build` never constructs it, \
             so it can never run (built: {built:?})"
        );
    }
}

/// The other direction: an arm naming a module that does not exist will not
/// compile, but only once someone touches `mod.rs`.
#[test]
fn registry_only_constructs_declared_modules() {
    let declared = declared_modules();
    for module in modules_built_by_registry() {
        assert!(
            declared.contains(&module),
            "`check::build` constructs `checks::{module}` but no such module is declared"
        );
    }
}

/// Check names `check::build` can construct, from the match arms' string keys.
fn names_built_by_registry() -> Vec<String> {
    let src = std::fs::read_to_string(core_root().join("src/check.rs")).expect("read check.rs");
    check::parse_registry_names(&src)
}

/// Every literal of a multi-pattern arm is a registry key. If the parse only
/// recognised single-literal arms, an aliased key would escape all six guards
/// in this file: `check::build` constructs the check under the alias, yet no
/// guard would ever build it by that name or pin its reported `name()`.
#[test]
fn registry_parse_collects_multi_pattern_arm_keys() {
    let src = r#"
pub fn build(name: &str, config: &Config) -> Option<Box<dyn Check>> {
    match name {
        "TagsCheck" => Some(Box::new(crate::checks::tags::TagsCheck::new(config))),
        "PAMModulesAlias" | "PAMModulesCheck" => Some(Box::new(
            crate::checks::pam_modules::PAMModulesCheck::new(config),
        )),
        "WrappedAlias"
            | "WrappedCheck" => None,
        _ => None,
    }
}
"#;
    assert_eq!(
        check::parse_registry_names(src),
        vec![
            "PAMModulesAlias",
            "PAMModulesCheck",
            "TagsCheck",
            "WrappedAlias",
            "WrappedCheck",
        ]
    );
}

/// The `Checks = [...]` list from one shipped config file.
fn checks_in_config_file(path: &std::path::Path) -> Vec<String> {
    let src = std::fs::read_to_string(path).expect("read config file");
    let mut in_list = false;
    let mut names = Vec::new();
    for line in src.lines() {
        let line = line.trim();
        if line.starts_with("Checks = [") {
            in_list = true;
            continue;
        }
        if in_list {
            if line.starts_with(']') {
                break;
            }
            if let Some(rest) = line.strip_prefix('"').or_else(|| line.strip_prefix('\''))
                && let Some(end) = rest.find(['"', '\''])
            {
                names.push(rest[..end].to_string());
            }
        }
    }
    assert!(
        !names.is_empty(),
        "no Checks parsed from {}",
        path.display()
    );
    names
}

/// The union of the `Checks = [...]` lists of every shipped config layer:
/// the bundled defaults and both vendored flavour configs. A check listed
/// in any layer runs under that layer's flavour.
fn checks_in_shipped_configs() -> Vec<String> {
    let mut names = checks_in_config_file(&core_root().join("data/configdefaults.toml"));
    for flavor in ["opensuse", "slfo"] {
        for name in
            checks_in_config_file(&core_root().join(format!("data/distro/{flavor}/opensuse.toml")))
        {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

/// A check that `check::build` can construct but no shipped config ever
/// selects can never run — the same class of defect as #49 (issue #66).
/// `XinetdDepCheck` and `PAMModulesCheck` are both deliberately enabled
/// (ledgered in tests/parity/divergences.toml), and `LSBCheck` is deleted,
/// so it is not constructible. `AtomicUpdateCheck` is listed in the
/// bundled defaults and in both flavour configs (issue #698). Every
/// constructible check must appear in the `Checks = [...]` list of at
/// least one shipped config (issue #66 closed).
#[test]
fn every_constructible_check_is_listed_in_checks() {
    let listed = checks_in_shipped_configs();
    for name in names_built_by_registry() {
        assert!(
            listed.contains(&name),
            "`check::build` constructs `{name}` but it is absent from \
             `Checks = [...]` in every shipped config, so it can never run"
        );
    }
}

/// `--errors-only` (upstream rpmlint#134) drops exactly the five audited
/// warning-only checks. The per-check assertion lives in `check.rs`; this
/// closes the multiplicity gap: no other registry check may report a
/// sub-Error `max_severity`, or `--errors-only` would silently skip a check
/// that was never audited as warning-only.
#[test]
fn exactly_five_warning_only_checks_in_registry() {
    // Bundled defaults: some checks (e.g. AtomicUpdateCheck) require config
    // keys that `Config::default()` does not provide.
    let config = config::load_bundled();
    let mut below_error: Vec<String> = names_built_by_registry()
        .iter()
        .filter_map(|name| check::build(name, &config))
        .filter(|c| c.max_severity() != Level::Error)
        .map(|c| c.name().to_string())
        .collect();
    below_error.sort_unstable();
    assert_eq!(
        below_error,
        vec![
            "BashismsCheck",
            "ConfigFilesCheck",
            "FHSCheck",
            "SystemdInstallCheck",
            "TmpFilesCheck",
        ],
        "warning-only set changed: re-audit every add_info call site of the new member"
    );
}

/// A check whose `name()` disagrees with its `check::build` key corrupts every
/// finding line it emits (`{check}` is the frozen output contract), and no
/// emission test can see it: unit tests construct the check directly, so a
/// renamed check keeps passing them. The mutants baseline caught two dozen
/// `name -> "xyzzy"` survivors across the tree; this closes the class wholesale.
#[test]
fn every_built_check_reports_its_registry_name() {
    // Bundled defaults: some checks (e.g. AtomicUpdateCheck) require config
    // keys that `Config::default()` does not provide.
    let config = config::load_bundled();
    for name in names_built_by_registry() {
        let built = check::build(&name, &config)
            .unwrap_or_else(|| panic!("`check::build` cannot construct `{name}`"));
        assert_eq!(
            built.name(),
            name,
            "`{name}` reports {:?}: its finding lines would carry the wrong check",
            built.name()
        );
    }
}

/// Issue #698: transactional updates are mandatory, not an slfo-only
/// requirement, so `AtomicUpdateCheck` is listed in the bundled defaults
/// and in both flavour configs. The openSUSE flavour keeps the
/// `filesystem` exemption for the finding (the check now runs there, so
/// the exemption is live), and no flavour ships a scoring entry for
/// `dir-or-file-outside-snapshot`: a vendored `= 0` would demote the
/// emitted Error to a warning, and the finding's significance is its
/// Error level (issue #699).
#[test]
fn atomic_update_check_is_enabled_everywhere() {
    let root = core_root();
    let defaults = checks_in_config_file(&root.join("data/configdefaults.toml"));
    assert!(
        defaults.iter().any(|n| n == "AtomicUpdateCheck"),
        "AtomicUpdateCheck must be listed in the bundled defaults"
    );
    for flavor in ["opensuse", "slfo"] {
        let listed =
            checks_in_config_file(&root.join(format!("data/distro/{flavor}/opensuse.toml")));
        assert!(
            listed.iter().any(|n| n == "AtomicUpdateCheck"),
            "AtomicUpdateCheck must be listed in the {flavor} flavour config"
        );
        let scoring =
            std::fs::read_to_string(root.join(format!("data/distro/{flavor}/scoring.toml")))
                .expect("read scoring.toml");
        assert!(
            !scoring.contains("dir-or-file-outside-snapshot"),
            "the {flavor} flavour must not ship a scoring entry for \
             dir-or-file-outside-snapshot (it would demote the Error)"
        );
    }
    let opensuse = std::fs::read_to_string(root.join("data/distro/opensuse/opensuse.toml"))
        .expect("read opensuse.toml");
    assert!(
        opensuse.contains("'^filesystem\\..*: dir-or-file-outside-snapshot'"),
        "the openSUSE flavour must keep the filesystem exemption for \
         dir-or-file-outside-snapshot"
    );
}

/// The reverse direction (issue #85): a name in a shipped config's
/// `Checks = [...]` that `check::build` cannot construct is silently
/// dropped by `load_with`, so the run advertises checks that never execute.
#[test]
fn every_listed_check_is_constructible() {
    let built = names_built_by_registry();
    let files = [
        core_root().join("data/configdefaults.toml"),
        core_root().join("data/distro/opensuse/opensuse.toml"),
        core_root().join("data/distro/slfo/opensuse.toml"),
    ];
    for path in files {
        for name in checks_in_config_file(&path) {
            assert!(
                built.contains(&name),
                "`{name}` is listed in `Checks = [...]` in {} \
                 but `check::build` cannot construct it, so it silently never runs",
                path.display()
            );
        }
    }
}
