//! `InstalledPkg` (M2c) parity.
//!
//! The rpmdb is host-specific, so the oracle is not a committed dump. Two
//! layers:
//!
//! - `installed_facade_matches_file_pkg`: builds an `InstalledPkg` from the
//!   corpus RPM's header and checks every header-derived field equals the
//!   file-backed `Pkg`, differing only in the installed facade (`dir_name =
//!   "/"`, synthesized `filename`, `is_source` forced false). Deterministic.
//! - `host_db_smoke`: resolves `rpm` through the real rpmdb — this is also the
//!   **ndb** check (openSUSE's backend). Tolerant: it skips (prints) when the
//!   host rpmdb is unavailable or lacks `rpm`.

use std::path::Path;

use librpm::PackageHeader;
use librpm::verify::VerifyOptions;
use rpmcrab_core::pkg::Pkg;
use rpmcrab_core::pkg::installed::find_installed;

fn corpus_rpm() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity/cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm")
        .canonicalize()
        .unwrap()
}

#[test]
fn installed_facade_matches_file_pkg() {
    let rpm = corpus_rpm();
    let header = PackageHeader::from_file(&rpm, Some(&VerifyOptions::skip_verification()))
        .expect("open header");
    let inst = Pkg::installed(header);
    let scratch = tempfile::tempdir().unwrap();
    let file_pkg = Pkg::open(&rpm, scratch.path()).unwrap();

    // Identity + every header-derived field equals the file-backed package.
    assert_eq!(inst.name, file_pkg.name);
    assert_eq!(inst.arch, file_pkg.arch);
    assert_eq!(inst.is_source, file_pkg.is_source);
    assert_eq!(inst.requires, file_pkg.requires);
    assert_eq!(inst.prereq, file_pkg.prereq);
    assert_eq!(inst.provides, file_pkg.provides);
    assert_eq!(inst.conflicts, file_pkg.conflicts);
    assert_eq!(inst.obsoletes, file_pkg.obsoletes);
    assert_eq!(inst.ghost_files, file_pkg.ghost_files);
    assert_eq!(inst.files.len(), file_pkg.files.len());
    for (a, b) in inst.files.iter().zip(&file_pkg.files) {
        assert_eq!(a.name, b.name);
        assert_eq!(a.mode, b.mode);
        assert_eq!(a.flags, b.flags);
        assert_eq!(a.user, b.user);
        assert_eq!(a.group, b.group);
        assert_eq!(a.size, b.size);
        assert_eq!(a.md5, b.md5);
        assert_eq!(a.linkto, b.linkto);
    }

    // The installed facade: live dir, synthesized filename, forced is_source.
    assert_eq!(inst.dir_name.as_deref(), Some(Path::new("/")));
    assert_eq!(inst.filename, "llvm21-gold-21.1.8-9.2.aarch64.rpm");
    assert!(!inst.is_source);
    // Paths are rooted at the live filesystem, not a tempdir.
    assert!(inst.files.iter().all(|f| f.path.starts_with('/')));
    assert_ne!(inst.files[0].path, file_pkg.files[0].path);
}

#[test]
fn host_db_smoke() {
    // Tolerant: only asserts when the host rpmdb opens and has `rpm`. This is
    // the ndb check — librpm must read openSUSE's backend.
    let (pkgs, missing) = match find_installed(&["rpm".to_string()]) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skip: rpmdb unavailable: {e}");
            return;
        }
    };
    if !missing.is_empty() {
        eprintln!("skip: 'rpm' is not installed on the host");
        return;
    }
    assert!(pkgs.iter().any(|p| p.name == "rpm"));
    assert!(pkgs.iter().all(|p| !p.is_source));
}
