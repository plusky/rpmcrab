//! Parity test: rpmcrab's `Pkg` must reproduce rpmlint's `Pkg` for the same
//! RPM, field for field.
//!
//! The oracle is `tests/parity/pkg/<case>.json` — rpmlint's real `Pkg` dumped
//! by `scripts/capture-pkg-dump.py` (recorded on the openSUSE reference). This
//! test builds the same structure from `rpmcrab_core::pkg::Pkg` and compares.
//!
//! `path` and `dir_name` are excluded: they depend on payload extraction,
//! which is M2b; M2a is the header/file-metadata layer.

use std::path::{Path, PathBuf};

use rpmcrab_core::pkg::{Pkg, SCRIPT_TAGS, pkgfile};
use serde_json::{Value, json};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// (case dir name, committed rpm file name)
const CASES: &[(&str, &str)] = &[
    ("llvm21-gold", "llvm21-gold-21.1.8-9.2.aarch64.rpm"),
    ("liblto21", "libLTO21-21.1.8-9.2.aarch64.rpm"),
];

fn pkg_to_json(pkg: &Pkg) -> Value {
    let deps = |v: &[rpmcrab_core::pkg::dep::DepInfo]| -> Value {
        Value::Array(
            v.iter()
                .map(|d| {
                    json!({
                        "name": d.name,
                        "flags": d.flags,
                        "epoch": d.epoch,
                        "version": d.version,
                        "release": d.release,
                    })
                })
                .collect(),
        )
    };
    let files = Value::Array(
        pkg.files
            .iter()
            .map(|f| {
                json!({
                    "name": f.name,
                    "flags": f.flags,
                    "mode": f.mode,
                    "user": f.user,
                    "group": f.group,
                    "linkto": f.linkto,
                    "size": f.size,
                    "md5": f.md5,
                    "mtime": f.mtime,
                    "rdev": f.rdev,
                    "inode": f.inode,
                    "lang": f.lang,
                    "filecaps": f.filecaps,
                    "is_config": f.is_config(),
                    "is_doc": f.is_doc(),
                    "is_ghost": f.is_ghost(),
                    "is_noreplace": f.is_noreplace(),
                    "is_missingok": f.is_missingok(),
                    "is_dir": pkgfile::is_dir(f.mode),
                    "is_symlink": pkgfile::is_symlink(f.mode),
                    "is_reg": pkgfile::is_reg(f.mode),
                    "filemode": pkgfile::filemode(f.mode),
                    "suid": f.mode & 0o4000 != 0,
                    "sgid": f.mode & 0o2000 != 0,
                })
            })
            .collect(),
    );
    let scriptlets = Value::Object(
        SCRIPT_TAGS
            .iter()
            .map(|(body, prog, label)| {
                let exists = pkg.tag_str(*body).is_some_and(|s| !s.is_empty());
                (
                    (*label).to_string(),
                    json!({ "exists": exists, "prog": pkg.scriptprog(*prog) }),
                )
            })
            .collect(),
    );
    json!({
        "name": pkg.name,
        "arch": pkg.arch,
        "is_source": pkg.is_source,
        "is_no_source": pkg.is_no_source(),
        "filename": pkg.filename,
        "requires": deps(&pkg.requires),
        "prereq": deps(&pkg.prereq),
        "provides": deps(&pkg.provides),
        "conflicts": deps(&pkg.conflicts),
        "obsoletes": deps(&pkg.obsoletes),
        "recommends": deps(&pkg.recommends),
        "suggests": deps(&pkg.suggests),
        "enhances": deps(&pkg.enhances),
        "supplements": deps(&pkg.supplements),
        "files": files,
        "doc_files": pkg.doc_files,
        "config_files": pkg.config_files,
        "ghost_files": pkg.ghost_files,
        "noreplace_files": pkg.noreplace_files,
        "missingok_files": pkg.missingok_files,
        "scriptlets": scriptlets,
    })
}

/// Drop the extraction-dependent keys (`path`, `dir_name`) so the oracle and
/// rpmcrab compare on equal footing.
fn strip_extraction(v: &mut Value) {
    if let Some(o) = v.as_object_mut() {
        o.remove("dir_name");
    }
    if let Some(files) = v.get_mut("files").and_then(Value::as_array_mut) {
        for f in files {
            if let Some(o) = f.as_object_mut() {
                o.remove("path");
            }
        }
    }
}

#[test]
fn pkg_reproduces_rpmlint_for_corpus_rpms() {
    let root = repo_root();
    for (case, rpm_name) in CASES {
        let rpm = root
            .join("tests/parity/cases")
            .join(case)
            .join("input")
            .join(rpm_name);
        let dump_path = root.join("tests/parity/pkg").join(format!("{case}.json"));
        assert!(rpm.exists(), "missing committed RPM: {}", rpm.display());

        let mut expected: Value =
            serde_json::from_str(&std::fs::read_to_string(&dump_path).unwrap()).unwrap();
        strip_extraction(&mut expected);

        let pkg = Pkg::open(&rpm).unwrap_or_else(|e| panic!("open {case}: {e}"));
        let actual = pkg_to_json(&pkg);

        // Compare top-level keys individually for a readable diff.
        for key in expected.as_object().unwrap().keys() {
            assert_eq!(
                actual.get(key),
                expected.get(key),
                "case {case}: mismatch in `{key}`"
            );
        }
    }
}
