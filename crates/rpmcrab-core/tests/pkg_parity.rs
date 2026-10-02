//! Parity test: rpmcrab's `Pkg` must reproduce rpmlint's `Pkg` for the same
//! RPM, field for field.
//!
//! The oracle is `tests/parity/pkg/<case>.json` — rpmlint's real `Pkg` dumped
//! by `scripts/capture-pkg-dump.py` (recorded on the openSUSE reference). This
//! test builds the same structure from `rpmcrab_core::pkg::Pkg`, extracting the
//! payload into a tempdir the way rpmlint does, and compares.
//!
//! Normalizations applied to both sides:
//! - `meta`: oracle provenance, not package data.
//! - `filename`: reduced to `<DIR>/<basename>` (the reference stores a path;
//!   `filename_is_the_as_passed_path` pins the path semantics).
//! - `dir_name`, `path`: the real extraction tempdir is replaced by `<DIR>`
//!   (the oracle's placeholder) so the location is not compared, only the
//!   shape.
//! - `fileclass`: the oracle records the raw `FILECLASS`; rpmcrab does not
//!   expose it, so it is dropped before comparison.
//!
//! `magic` is compared as-is. The `fcprobe` case has a file with an empty
//! `FILECLASS`, so the libmagic branch is exercised — rpmlint's python-magic
//! against rpmcrab's `file -b` — rather than skipped; both share the libmagic
//! version recorded in the oracle's `meta.libmagic`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use librpm::PackageHeader;
use librpm::verify::VerifyOptions;
use rpmcrab_core::pkg::{Pkg, SCRIPT_TAGS, pkgfile};
use serde_json::{Value, json};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// (case name, committed rpm path relative to `tests/parity/`)
const CASES: &[(&str, &str)] = &[
    (
        "llvm21-gold",
        "cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm",
    ),
    (
        "liblto21",
        "cases/liblto21/input/libLTO21-21.1.8-9.2.aarch64.rpm",
    ),
    // A file with an empty FILECLASS, so the libmagic branch is compared.
    ("fcprobe", "pkg/inputs/fcprobe-1-1.noarch.rpm"),
];

fn case_rpm(root: &Path, rel: &str) -> PathBuf {
    root.join("tests/parity").join(rel)
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
                    "path": f.path,
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
        "dir_name": pkg.dir_name().to_string_lossy().into_owned(),
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
}

/// Replace the real extraction tempdir with the oracle's `<DIR>` placeholder.
fn replace_dir(v: &mut Value, dir: &str) {
    replace_value_prefix(v, "dir_name", dir);
    if let Some(files) = v.get_mut("files").and_then(Value::as_array_mut) {
        for f in files {
            replace_value_prefix(f, "path", dir);
        }
    }
}

/// In object `v`, replace the leading `dir` in the string `key` with `<DIR>`.
fn replace_value_prefix(v: &mut Value, key: &str, dir: &str) {
    let Some(s) = v.get(key).and_then(Value::as_str).map(str::to_string) else {
        return;
    };
    if let Some(o) = v.as_object_mut() {
        o.insert(key.to_string(), Value::String(s.replacen(dir, "<DIR>", 1)));
    }
}

/// Drop the oracle-only `fileclass` key, after checking the file counts match.
/// `magic` is compared as-is: the corpus includes an empty-`FILECLASS` file so
/// the libmagic branch (rpmlint's python-magic vs rpmcrab's `file -b`) is
/// exercised, not skipped. Their shared libmagic version is recorded in the
/// oracle's `meta.libmagic`.
fn reconcile_files(expected: &mut Value, actual: &Value) {
    let exp = expected
        .get_mut("files")
        .and_then(Value::as_array_mut)
        .unwrap();
    let act = actual.get("files").and_then(Value::as_array).unwrap();
    assert_eq!(exp.len(), act.len(), "file count differs");
    for e in exp.iter_mut() {
        e.as_object_mut().unwrap().remove("fileclass");
    }
}

#[test]
fn pkg_reproduces_rpmlint_for_corpus_rpms() {
    let root = repo_root();
    let scratch = tempfile::tempdir().unwrap();
    for (case, rel) in CASES {
        let rpm = case_rpm(&root, rel);
        let dump_path = root.join("tests/parity/pkg").join(format!("{case}.json"));
        assert!(rpm.exists(), "missing committed RPM: {}", rpm.display());

        let mut expected: Value =
            serde_json::from_str(&std::fs::read_to_string(&dump_path).unwrap()).unwrap();
        let pkg =
            Pkg::open(&rpm, scratch.path(), true).unwrap_or_else(|e| panic!("open {case}: {e}"));
        let tmpdir = pkg.dir_name().to_string_lossy().into_owned();
        let mut actual = pkg_to_json(&pkg);

        normalize_toplevel(&mut expected);
        normalize_toplevel(&mut actual);
        replace_dir(&mut actual, &tmpdir);
        reconcile_files(&mut expected, &actual);

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
    let scratch = tempfile::tempdir().unwrap();
    let plain = case_rpm(
        &root,
        "cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm",
    );
    let a = Pkg::open(&plain, scratch.path(), true).unwrap().filename;
    assert_eq!(
        a,
        plain.to_string_lossy(),
        "filename is not the as-passed path"
    );

    // A different spelling of the same file: `./` and `..` must survive verbatim.
    let spelled = root
        .join("tests/parity/cases/./llvm21-gold/input/../input/llvm21-gold-21.1.8-9.2.aarch64.rpm");
    assert!(spelled.exists(), "spelled path does not resolve");
    let b = Pkg::open(&spelled, scratch.path(), true).unwrap().filename;
    assert_eq!(b, spelled.to_string_lossy(), "filename was normalized: {b}");
    assert_ne!(
        a, b,
        "the two path spellings must yield different filenames"
    );
}

/// `cleanup()` removes the payload but keeps `dir_name` pointing at the now-dead
/// path, so a later read must come back empty — never silently fall back to the
/// host filesystem via `dir_name or '/'` (rpmlint `pkg.py:647`).
#[test]
fn read_file_after_cleanup_is_empty() {
    let root = repo_root();
    let scratch = tempfile::tempdir().unwrap();
    let rpm = case_rpm(
        &root,
        "cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm",
    );
    let mut pkg = Pkg::open(&rpm, scratch.path(), true).unwrap();

    // A file that really is in the payload, so the pre-cleanup read is non-empty.
    // `read_file` is UTF-8 only, so pick a text file rather than any regular one.
    let victim = pkg
        .files
        .iter()
        .filter(|f| pkgfile::is_reg(f.mode) && f.size.is_some_and(|s| s > 0))
        .map(|f| f.name.clone())
        .find(|n| !pkg.read_file(n).is_empty())
        .expect("corpus rpm has a non-empty UTF-8 regular file");
    assert!(
        !pkg.read_file(&victim).is_empty(),
        "precondition: {victim} should be readable before cleanup"
    );

    pkg.cleanup();

    assert!(
        !pkg.dir_name().exists(),
        "cleanup must remove the extraction directory"
    );
    assert_eq!(
        pkg.read_file(&victim),
        "",
        "read after cleanup must be empty, not a host-filesystem read"
    );
}

/// `ExtractDir = "/"` means "installed package, do not extract"
/// (`pkg.py:610-613`): the package reads from the live root with `extracted`
/// false. `Installed` and `LiveRoot` share `dir_name = "/"` and own no
/// tempdir — only the reference's `extracted` flag tells them apart, which is
/// why they are separate `PkgSource` variants rather than one.
#[test]
fn live_root_reports_the_reference_extracted_flag() {
    let root = repo_root();
    let rpm = case_rpm(
        &root,
        "cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm",
    );
    let header = PackageHeader::from_file(&rpm, Some(&VerifyOptions::skip_verification()))
        .expect("open header");

    let installed = Pkg::installed(header).expect("build installed package");
    assert!(installed.extracted());
    assert_eq!(installed.dir_name(), Path::new("/"));

    let live = Pkg::open(&rpm, Path::new("/"), true).unwrap();
    assert!(!live.extracted(), "ExtractDir = / must not set extracted");
    assert_eq!(live.dir_name(), Path::new("/"));
}
