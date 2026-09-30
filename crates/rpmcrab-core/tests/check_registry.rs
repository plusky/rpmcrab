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

fn core_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Modules declared in `checks/mod.rs`, excluding the helper module (it holds no
/// `Check` and is reached through `super::shared`).
fn declared_modules() -> Vec<String> {
    let src = std::fs::read_to_string(core_root().join("src/checks/mod.rs")).expect("read mod.rs");
    let modules: Vec<String> = src
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub mod "))
        .filter_map(|l| l.strip_suffix(';'))
        .map(str::to_string)
        .filter(|m| m != "shared")
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
    let body = match src.find("pub fn build(") {
        Some(start) => {
            let rest = &src[start..];
            let end = rest.find("\n}\n").map(|i| i + 1).unwrap_or(rest.len());
            &rest[..end]
        }
        None => panic!("check::build not found"),
    };
    let mut found: Vec<String> = body
        .lines()
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
        .collect();
    found.sort();
    found.dedup();
    found
}

/// The `Checks = [...]` list from the default config.
fn checks_in_default_config() -> Vec<String> {
    let src = std::fs::read_to_string(core_root().join("data/configdefaults.toml"))
        .expect("read configdefaults.toml");
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
            if let Some(rest) = line
                .strip_prefix('"')
                .or_else(|| line.strip_prefix('\''))
                && let Some(end) = rest.find(['"', '\''])
            {
                names.push(rest[..end].to_string());
            }
        }
    }
    assert!(!names.is_empty(), "no Checks parsed from configdefaults.toml");
    names
}

/// A check that `check::build` can construct but the default config never
/// selects can never run — the same class of defect as #49 (issue #66).
/// The documented exceptions are modules the reference ships but lists in no
/// shipped config's `Checks` (`InitScriptCheck`, `LSBCheck`, `XinetdDepCheck`),
/// plus `PAMModulesCheck`, which the reference lists only in the Fedora
/// flavour config (not yet ported); the port mirrors all of that.
#[test]
fn every_constructible_check_is_listed_in_checks() {
    let listed = checks_in_default_config();
    for name in names_built_by_registry() {
        if name == "InitScriptCheck"
            || name == "LSBCheck"
            || name == "XinetdDepCheck"
            || name == "PAMModulesCheck"
        {
            continue;
        }
        assert!(
            listed.contains(&name),
            "`check::build` constructs `{name}` but it is absent from \
             `Checks = [...]` in configdefaults.toml, so it can never run"
        );
    }
}
