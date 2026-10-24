//! `InstalledPkg` (M2c) parity.
//!
//! The rpmdb is host-specific, so the oracle is not a committed dump. Four
//! layers:
//!
//! - `installed_facade_matches_file_pkg`: builds an `InstalledPkg` from the
//!   corpus RPM's header and checks every header-derived field equals the
//!   file-backed `Pkg`, differing only in the installed facade (`dir_name =
//!   "/"`, `extracted`, synthesized `filename`, `is_source` forced false).
//!   Deterministic.
//! - `find_in_against_an_empty_db`: the real librpm query path against a
//!   throwaway database (`Db::open_with_root` + `init_db`, neither of which
//!   needs privilege), pinning that an unknown name is reported missing rather
//!   than raising, and that a glob is routed to the glob query.
//! - `find_in_against_a_populated_db`: registers the corpus RPM's header in
//!   a throwaway database and pins that exact and glob lookups resolve it and
//!   that the facade builds from a database-returned header. The database
//!   path is redirected to a tempdir (`_dbpath`) while the root stays `/`,
//!   and the header is registered with a `JUSTDB` transaction, so the test
//!   needs no privilege and writes no payload. Deterministic.
//! - `host_db_smoke` (`#[ignore]`): resolves `rpm` through the real host rpmdb,
//!   which is also the **ndb** check (openSUSE's backend). Ignored by default
//!   because it needs a populated host database: CI installs only `librpm-dev`.
//!   Run it on a developer machine with
//!   `cargo test --test pkg_installed -- --ignored`.

use std::path::Path;

use librpm::PackageHeader;
use librpm::db::Db;
use librpm::macro_context::MacroContext;
use librpm::transaction::{ProblemFilter, TransactionFlags};
use librpm::verify::VerifyOptions;
use rpmcrab_core::pkg::Pkg;
use rpmcrab_core::pkg::installed::{find_in, find_installed};

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
    let inst = Pkg::installed(header).expect("build installed package");
    let scratch = tempfile::tempdir().unwrap();
    let file_pkg = Pkg::open(&rpm, scratch.path(), true).unwrap();

    // Identity.
    assert_eq!(inst.name, file_pkg.name);
    assert_eq!(inst.arch, file_pkg.arch);
    assert_eq!(inst.is_source, file_pkg.is_source);
    // Every dependency list, all nine.
    assert_eq!(inst.requires, file_pkg.requires);
    assert_eq!(inst.prereq, file_pkg.prereq);
    assert_eq!(inst.provides, file_pkg.provides);
    assert_eq!(inst.conflicts, file_pkg.conflicts);
    assert_eq!(inst.obsoletes, file_pkg.obsoletes);
    assert_eq!(inst.recommends, file_pkg.recommends);
    assert_eq!(inst.suggests, file_pkg.suggests);
    assert_eq!(inst.enhances, file_pkg.enhances);
    assert_eq!(inst.supplements, file_pkg.supplements);
    assert_eq!(inst.req_names, file_pkg.req_names);
    // Every derived file-name list, all five.
    assert_eq!(inst.config_files, file_pkg.config_files);
    assert_eq!(inst.doc_files, file_pkg.doc_files);
    assert_eq!(inst.ghost_files, file_pkg.ghost_files);
    assert_eq!(inst.noreplace_files, file_pkg.noreplace_files);
    assert_eq!(inst.missingok_files, file_pkg.missingok_files);
    // Every file field, in header order.
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
    assert_eq!(inst.dir_name(), Path::new("/"));
    assert_eq!(inst.filename, "llvm21-gold-21.1.8-9.2.aarch64.rpm");
    assert!(!inst.is_source);
    // The reference marks an installed package extracted even though nothing was
    // unpacked: `InstalledPkg` sets `extracted = True` (pkg.py:758).
    assert!(inst.extracted());
    // Paths are rooted at the live filesystem, not a tempdir.
    assert!(inst.files.iter().all(|f| f.path.starts_with('/')));
    assert_ne!(inst.files[0].path, file_pkg.files[0].path);
}

/// The librpm query path against a valid but empty database. `init_db` and
/// `open_with_root` need no privilege, so this runs everywhere.
/// `find_in_against_a_populated_db` covers the registered-header case.
#[test]
fn find_in_against_an_empty_db() {
    // A `Db` can only be built once librpm is configured; the crate's own
    // process-wide init is the supported way to do that.
    rpmcrab_core::pkg::init().expect("init librpm");
    let root = tempfile::tempdir().unwrap();
    let db = Db::open_with_root(root.path()).expect("open db under a throwaway root");
    db.init_db(0o755).expect("init db");

    let names: Vec<String> = ["no-such-pkg", "no-such-*", ""]
        .into_iter()
        .map(String::from)
        .collect();
    let (headers, missing) = find_in(&db, &names).expect("query an empty db");

    assert!(headers.is_empty());
    assert_eq!(missing, names, "every name is missing in an empty database");
}

/// Macros defined for the duration of a scope and popped on drop, including
/// on panic, so a test never leaks librpm configuration into its siblings.
/// The scope holds the crate's global macro lock throughout: the context
/// behind `MacroContext::default()` is process-global, and the lock keeps
/// the define/pop sequence from interleaving with another thread's macro
/// work. The value is built incrementally -- each name is recorded as it
/// is defined -- so a panic from `define` unwinds through a live value
/// whose `Drop` pops the names defined so far instead of leaking them.
struct ScopedMacros {
    context: MacroContext,
    names: Vec<&'static str>,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl ScopedMacros {
    fn define(defs: &[(&'static str, String)]) -> Self {
        let mut scoped = Self {
            context: MacroContext::default(),
            names: Vec::new(),
            _guard: rpmcrab_core::pkg::global_macro_lock(),
        };
        for (name, body) in defs {
            scoped
                .context
                .define(&format!("{name} {body}"), 0)
                .expect("define macro");
            scoped.names.push(*name);
        }
        scoped
    }
}

impl Drop for ScopedMacros {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = self.context.pop(name);
        }
    }
}

/// The librpm query path against a database holding one registered package.
///
/// Registration takes a payload to register, not a transaction against the
/// live system: the corpus RPM's header is added with a `JUSTDB` transaction,
/// which writes only the database. Two pieces of steering keep that hermetic
/// and unprivileged:
///
/// - `_dbpath` points at a tempdir while the database root stays `/` — a
///   rooted database is what makes `Transaction::run` chroot.
/// - The corpus package's signing key is not in the throwaway keyring, and
///   the registration is about the header, so verification is off
///   (`_pkgverify_level none`; the transaction's verification flags are
///   skipped too). The problem filter ignores the host's platform and free
///   space: a Linux/aarch64 header registers on any host, and `JUSTDB`
///   writes no payload whose size could matter.
#[test]
fn find_in_against_a_populated_db() {
    rpmcrab_core::pkg::init().expect("init librpm");
    let root = tempfile::tempdir().unwrap();
    let dbpath = root.path().join("rpmdb");
    std::fs::create_dir_all(&dbpath).unwrap();
    let _macros = ScopedMacros::define(&[
        ("_dbpath", dbpath.display().to_string()),
        ("_pkgverify_level", "none".to_string()),
    ]);

    let mut db = Db::open().expect("open db at the redirected path");
    db.init_db(0o755).expect("init db");
    let rpm = corpus_rpm();
    let header = PackageHeader::from_file(&rpm, Some(&VerifyOptions::skip_verification()))
        .expect("open header");
    {
        let mut ts = db.transaction();
        ts.set_flags(TransactionFlags::JUSTDB | TransactionFlags::NOSCRIPTS);
        ts.set_verify_options(&VerifyOptions::skip_verification());
        ts.set_problem_filter(
            ProblemFilter::IGNORE_OS
                | ProblemFilter::IGNORE_ARCH
                | ProblemFilter::DISK_SPACE
                | ProblemFilter::DISK_NODES,
        );
        ts.add_install(&header, &rpm, false).expect("add install");
        ts.run().expect("register the header");
    }

    let names: Vec<String> = ["llvm21-gold", "llvm21-*", "no-such-pkg"]
        .into_iter()
        .map(String::from)
        .collect();
    let (headers, missing) = find_in(&db, &names).expect("query the populated db");
    assert_eq!(missing, vec!["no-such-pkg".to_string()]);
    assert_eq!(headers.len(), 2, "exact and glob lookups both resolve");

    // The facade builds from headers that came out of the database, with the
    // identity fields of the file-backed package.
    let scratch = tempfile::tempdir().unwrap();
    let file_pkg = Pkg::open(&rpm, scratch.path(), true).unwrap();
    for header in &headers {
        let inst = Pkg::installed(header.clone()).expect("build installed package");
        assert_eq!(inst.name, "llvm21-gold");
        assert_eq!(inst.name, file_pkg.name);
        assert_eq!(inst.arch, file_pkg.arch);
        assert_eq!(inst.files.len(), file_pkg.files.len());
        assert!(!inst.is_source);
        assert_eq!(inst.dir_name(), Path::new("/"));
    }
}

/// Dev-machine only: needs a populated host rpmdb. See the module docs.
#[test]
#[ignore = "needs a populated host rpmdb; run with --ignored"]
fn host_db_smoke() {
    let (headers, missing) = find_installed(&["rpm".to_string()]).expect("open host rpmdb");
    assert!(
        missing.is_empty(),
        "rpm is expected to be installed on the host"
    );
    assert!(!headers.is_empty(), "the host rpmdb returned no headers");

    // The ndb check: librpm must read openSUSE's backend, and the facade must
    // build from a header that came out of the real database.
    for header in &headers {
        let inst = Pkg::installed(header.clone()).expect("build installed package");
        assert_eq!(inst.name, "rpm");
        assert!(!inst.is_source);
        assert_eq!(inst.dir_name(), Path::new("/"));
    }
}
