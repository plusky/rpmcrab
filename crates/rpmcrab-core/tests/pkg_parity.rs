//! Parity test: rpmcrab's `Pkg` must reproduce rpmlint's `Pkg` for the same
//! RPM, field for field.
//!
//! The oracle is `tests/parity/pkg/<case>.json` — rpmlint's real `Pkg` dumped
//! by `scripts/capture-pkg-dump.py` (recorded on the openSUSE reference). This
//! test builds the same structure from `rpmcrab_core::pkg::Pkg` and compares.
//!
//! Normalizations applied to both sides:
//! - `dir_name`, `path`: depend on payload extraction (M2b).
//! - `meta`: oracle provenance, not package data.
//! - `filename`: reduced to `<DIR>/<basename>` (the reference stores a path;
//!   `filename_is_the_as_passed_path` pins the path semantics).
//! - `fileclass`: the oracle records the raw `FILECLASS`; rpmcrab does not
//!   expose it. It is used to decide the one remaining normalization: `magic`
//!   is dropped where the reference consulted **libmagic** (empty `FILECLASS`,
//!   not dir/symlink/empty/ghost), which is M2b. Everywhere `FILECLASS` is
//!   populated, `magic` is authoritative and compared.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use rpmcrab_core::pkg::{Pkg, SCRIPT_TAGS, pkgfile};
use serde_json::{Value, json};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// (case name, committed rpm file name)
const CASES: &[(&str, &str)] = &[
    ("llvm21-gold", "llvm21-gold-21.1.8-9.2.aarch64.rpm"),
    ("liblto21", "libLTO21-21.1.8-9.2.aarch64.rpm"),
];

fn case_rpm(root: &Path, case: &str, rpm_name: &str) -> PathBuf {
    root.join("tests/parity/cases")
        .join(case)
        .join("input")
        .join(rpm_name)
}

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
                    "magic": f.magic,
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

/// Top-level normalization (see the module docs).
fn normalize_toplevel(v: &mut Value) {
    let o = v.as_object_mut().unwrap();
    o.remove("dir_name");
    o.remove("meta");
    if let Some(f) = o
        .get("filename")
        .and_then(Value::as_str)
        .map(str::to_string)
    {
        let base = Path::new(&f)
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        o.insert(
            "filename".to_string(),
            Value::String(format!("<DIR>/{base}")),
        );
    }
    if let Some(files) = o.get_mut("files").and_then(Value::as_array_mut) {
        for f in files {
            if let Some(fo) = f.as_object_mut() {
                fo.remove("path");
            }
        }
    }
}

/// Reconcile the one extraction-dependent field per file, then drop the
/// oracle-only `fileclass` key.
fn reconcile_files(expected: &mut Value, actual: &mut Value) {
    let exp = expected
        .get_mut("files")
        .and_then(Value::as_array_mut)
        .unwrap();
    let act = actual
        .get_mut("files")
        .and_then(Value::as_array_mut)
        .unwrap();
    assert_eq!(exp.len(), act.len(), "file count differs");
    for (e, a) in exp.iter_mut().zip(act.iter_mut()) {
        let eo = e.as_object_mut().unwrap();
        let ao = a.as_object_mut().unwrap();
        let fileclass_empty = eo
            .get("fileclass")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty);
        let is_dir = eo.get("is_dir").and_then(Value::as_bool).unwrap_or(false);
        let is_symlink = eo
            .get("is_symlink")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let is_ghost = eo.get("is_ghost").and_then(Value::as_bool).unwrap_or(false);
        let size = eo.get("size").and_then(Value::as_u64).unwrap_or(0);
        // The reference consults libmagic only when FILECLASS is empty *after*
        // the dir/symlink/empty branches and the entry is not a ghost (M2b).
        if fileclass_empty && !is_dir && !is_symlink && !is_ghost && size != 0 {
            eo.remove("magic");
            ao.remove("magic");
        }
        eo.remove("fileclass");
    }
}

#[test]
fn pkg_reproduces_rpmlint_for_corpus_rpms() {
    let root = repo_root();
    for (case, rpm_name) in CASES {
        let rpm = case_rpm(&root, case, rpm_name);
        let dump_path = root.join("tests/parity/pkg").join(format!("{case}.json"));
        assert!(rpm.exists(), "missing committed RPM: {}", rpm.display());

        let mut expected: Value =
            serde_json::from_str(&std::fs::read_to_string(&dump_path).unwrap()).unwrap();
        let mut actual =
            pkg_to_json(&Pkg::open(&rpm).unwrap_or_else(|e| panic!("open {case}: {e}")));
        normalize_toplevel(&mut expected);
        normalize_toplevel(&mut actual);
        reconcile_files(&mut expected, &mut actual);

        // The key sets must match, so a renamed/extra Rust field cannot pass.
        let exp_keys: BTreeSet<&String> = expected.as_object().unwrap().keys().collect();
        let act_keys: BTreeSet<&String> = actual.as_object().unwrap().keys().collect();
        assert_eq!(exp_keys, act_keys, "case {case}: top-level key set differs");

        for key in exp_keys {
            assert_eq!(
                actual.get(key),
                expected.get(key),
                "case {case}: mismatch in `{key}`"
            );
        }
    }
}

/// `Pkg.filename` must be the path exactly as passed (rpmlint stores it
/// verbatim), not the basename and not a normalized form.
#[test]
fn filename_is_the_as_passed_path() {
    let root = repo_root();
    let plain = case_rpm(&root, "llvm21-gold", "llvm21-gold-21.1.8-9.2.aarch64.rpm");
    let a = Pkg::open(&plain).unwrap().filename;
    assert_eq!(
        a,
        plain.to_string_lossy(),
        "filename is not the as-passed path"
    );

    // A different spelling of the same file: `./` and `..` must survive verbatim.
    let spelled = root
        .join("tests/parity/cases/./llvm21-gold/input/../input/llvm21-gold-21.1.8-9.2.aarch64.rpm");
    assert!(spelled.exists(), "spelled path does not resolve");
    let b = Pkg::open(&spelled).unwrap().filename;
    assert_eq!(b, spelled.to_string_lossy(), "filename was normalized: {b}");
    assert_ne!(
        a, b,
        "the two path spellings must yield different filenames"
    );
}
