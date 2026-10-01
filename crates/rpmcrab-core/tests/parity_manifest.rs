//! Guard: every directory under `tests/parity/cases/` is indexed in
//! `tests/parity/manifest.toml`.
//!
//! The parity runner iterates the manifest, so a case directory on disk
//! with no manifest entry is silently never run.

use std::path::PathBuf;

fn parity_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/parity")
}

#[test]
fn every_case_directory_is_indexed_in_the_manifest() {
    let dir = parity_dir();
    let cases: Vec<String> = std::fs::read_dir(dir.join("cases"))
        .expect("read tests/parity/cases")
        .map(|entry| {
            entry
                .expect("dir entry")
                .file_name()
                .into_string()
                .expect("utf-8 case name")
        })
        .collect();
    let raw = std::fs::read_to_string(dir.join("manifest.toml"))
        .expect("read tests/parity/manifest.toml");
    let indexed: Vec<&str> = raw
        .lines()
        .filter_map(|line| line.strip_prefix("name = \""))
        .filter_map(|line| line.strip_suffix('"'))
        .collect();
    let missing: Vec<&str> = cases
        .iter()
        .map(String::as_str)
        .filter(|case| !indexed.contains(case))
        .collect();
    assert!(
        missing.is_empty(),
        "case directories missing from tests/parity/manifest.toml: {missing:?}"
    );
}
