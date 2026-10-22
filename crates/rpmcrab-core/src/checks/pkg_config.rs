//! `PkgConfigCheck` — validate `.pc` files.
//!
//! Ported from `rpmlint/checks/PkgConfigCheck.py`. Four findings, all errors:
//! `invalid-pkgconfig-file`, `pkgconfig-invalid-libs-dir`,
//! `double-slash-in-pkgconfig-path`, `pkgconfig-exception`.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::checks::shared::is_64bit_arch;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::is_reg;
use std::sync::OnceLock;

static PC_FILE_REGEX: OnceLock<Regex> = OnceLock::new();
fn pc_file_regex() -> &'static Regex {
    PC_FILE_REGEX.get_or_init(|| Regex::new(r".*/pkgconfig/.*\.pc$").expect("static regex"))
}

static SUSPICIOUS_DIR_REGEX: OnceLock<Regex> = OnceLock::new();
fn suspicious_dir_regex() -> &'static Regex {
    SUSPICIOUS_DIR_REGEX.get_or_init(|| {
        Regex::new(r"[=:](?:/usr/src/[\w.-]+/BUILD|/var/tmp|/tmp|/home)").expect("static regex")
    })
}

static WRONGLIB_DIR_64_REGEX: OnceLock<Regex> = OnceLock::new();
fn wronglib_dir_64_regex() -> &'static Regex {
    WRONGLIB_DIR_64_REGEX.get_or_init(|| Regex::new(r"-L/usr/lib\b").expect("static regex"))
}

static WRONGLIB_DIR_32_REGEX: OnceLock<Regex> = OnceLock::new();
fn wronglib_dir_32_regex() -> &'static Regex {
    WRONGLIB_DIR_32_REGEX.get_or_init(|| Regex::new(r"-L/usr/lib64\b").expect("static regex"))
}

pub struct PkgConfigCheck;

impl PkgConfigCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// Classify one `.pc` line. Returns `(finding, line_detail)`; the detail
    /// is the `rstrip()`ed line, or `None` when the reference reports only
    /// the filename.
    fn check_line(
        line: &str,
        suspicious: &Regex,
        wronglib: &Regex,
    ) -> Vec<(&'static str, Option<String>)> {
        let mut out = Vec::new();
        if is_match(suspicious, line) {
            out.push(("invalid-pkgconfig-file", None));
        }
        if line.starts_with("Libs:") && is_match(wronglib, line) {
            out.push((
                "pkgconfig-invalid-libs-dir",
                Some(line.trim_end().to_string()),
            ));
        }
        if line.contains("//") && !line.contains("://") {
            out.push((
                "double-slash-in-pkgconfig-path",
                Some(line.trim_end().to_string()),
            ));
        }
        out
    }

    /// Classify a whole `.pc` file's text, in line order.
    fn check_content(content: &str, is_64bit: bool) -> Vec<(&'static str, Option<String>)> {
        let suspicious = suspicious_dir_regex();
        let wronglib = if is_64bit {
            wronglib_dir_64_regex()
        } else {
            wronglib_dir_32_regex()
        };
        let mut out = Vec::new();
        for line in content.lines() {
            out.extend(Self::check_line(line, suspicious, wronglib));
        }
        out
    }

    /// Decode and check raw file bytes. A decoding failure becomes
    /// `pkgconfig-exception`, like the reference's `except Exception` around
    /// the utf-8 read.
    fn check_bytes(
        content: &[u8],
        is_64bit: bool,
    ) -> Result<Vec<(&'static str, Option<String>)>, String> {
        let text = std::str::from_utf8(content).map_err(|e| e.to_string())?;
        Ok(Self::check_content(text, is_64bit))
    }
}

impl Check for PkgConfigCheck {
    fn name(&self) -> &'static str {
        "PkgConfigCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let re = pc_file_regex();
        let is_64bit = is_64bit_arch(&pkg.arch);
        for file in &pkg.files {
            if !is_match(re, &file.name) || !is_reg(file.mode) {
                continue;
            }
            // AbstractCheck.py:45 filters ghosts out of the dispatch list,
            // so check_file never runs for one and a ghost `.pc` file draws
            // no finding.
            if pkg.ghost_files.iter().any(|g| g == &file.name) {
                continue;
            }
            let emit = |out: &mut Filter, check: &str, line: &Option<String>| match line {
                Some(l) => add_info(out, Level::Error, pkg, check, &[&file.name, l]),
                None => add_info(out, Level::Error, pkg, check, &[&file.name]),
            };
            match fs::read(Path::new(&file.path)) {
                Ok(bytes) => match Self::check_bytes(&bytes, is_64bit) {
                    Ok(findings) => {
                        for (check, line) in &findings {
                            emit(out, check, line);
                        }
                    }
                    Err(e) => add_info(
                        out,
                        Level::Error,
                        pkg,
                        "pkgconfig-exception",
                        &[&file.name, &e],
                    ),
                },
                // The extractor leaves entries it skipped after a path
                // collision out of the tree and reports each skip itself
                // (extract.rs `warn_skip_collision`); a read through the
                // object that won the collision fails with NotADirectory,
                // and that failure alone draws no finding. Every other
                // read failure reports as an exception -- a header-listed
                // file missing from the tree included -- as do decode
                // failures above.
                Err(e) if e.kind() == ErrorKind::NotADirectory => {}
                Err(e) => add_info(
                    out,
                    Level::Error,
                    pkg,
                    "pkgconfig-exception",
                    &[&file.name, &e.to_string()],
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;
    use crate::pkg::pkgfile::{PkgFile, RPMFILE_GHOST};

    fn check(line: &str, is_64bit: bool) -> Vec<(&'static str, Option<String>)> {
        PkgConfigCheck::check_line(
            line,
            suspicious_dir_regex(),
            if is_64bit {
                wronglib_dir_64_regex()
            } else {
                wronglib_dir_32_regex()
            },
        )
    }

    fn finding_names<'a>(findings: &'a [(&'static str, Option<String>)]) -> Vec<&'a str> {
        findings.iter().map(|(n, _)| *n).collect()
    }

    #[test]
    fn suspicious_build_dirs_are_reported() {
        for line in [
            "prefix=/var/tmp/buildroot/usr",
            "prefix=/tmp/foo",
            "prefix=/home/user/pkg",
            "prefix=/usr/src/packages/BUILD/usr",
            "prefix=/usr/src/linux-6.1/BUILD/usr",
            "prefix=/usr/src/linux-6.1.2/BUILD",
            "exec_prefix:/var/tmp/x",
        ] {
            assert_eq!(
                finding_names(&check(line, true)),
                vec!["invalid-pkgconfig-file"],
                "{line}"
            );
        }
    }

    #[test]
    fn clean_prefix_is_quiet() {
        for line in ["prefix=/usr", "prefix=/opt/foo", "Name: foo"] {
            assert!(check(line, true).is_empty(), "{line}");
        }
    }

    #[test]
    fn wrong_lib_dir_64bit() {
        let findings = check("Libs: -L/usr/lib -lfoo", true);
        assert_eq!(finding_names(&findings), vec!["pkgconfig-invalid-libs-dir"]);
        assert_eq!(
            findings[0].1.as_deref(),
            Some("Libs: -L/usr/lib -lfoo"),
            "detail is the rstripped line"
        );
    }

    #[test]
    fn right_lib_dir_64bit_is_quiet() {
        assert!(check("Libs: -L/usr/lib64 -lfoo", true).is_empty());
    }

    #[test]
    fn wrong_lib_dir_32bit() {
        let findings = check("Libs: -L/usr/lib64 -lfoo", false);
        assert_eq!(finding_names(&findings), vec!["pkgconfig-invalid-libs-dir"]);
    }

    #[test]
    fn right_lib_dir_32bit_is_quiet() {
        assert!(check("Libs: -L/usr/lib -lfoo", false).is_empty());
    }

    #[test]
    fn libs_check_needs_exact_prefix() {
        // `startswith('Libs:')`: leading space or `.private` do not count.
        assert!(check(" Libs: -L/usr/lib -lfoo", true).is_empty());
        assert!(check("Libs.private: -L/usr/lib -lfoo", true).is_empty());
    }

    #[test]
    fn double_slash_is_reported() {
        let findings = check("prefix=/usr//lib", true);
        assert_eq!(
            finding_names(&findings),
            vec!["double-slash-in-pkgconfig-path"]
        );
        assert_eq!(findings[0].1.as_deref(), Some("prefix=/usr//lib"));
    }

    #[test]
    fn url_with_scheme_is_quiet() {
        // `://` exempts the whole line, even with a later `//`.
        assert!(check("URL=https://example.com/foo", true).is_empty());
        assert!(check("URL=https://example.com//foo", true).is_empty());
    }

    #[test]
    fn trailing_whitespace_is_stripped_from_details() {
        let findings = check("prefix=/usr//lib   ", true);
        assert_eq!(findings[0].1.as_deref(), Some("prefix=/usr//lib"));
    }

    #[test]
    fn multiple_findings_per_line_in_order() {
        // `[=:]` must directly precede the path, so the build dir needs `=`.
        let findings = check("Libs: -L/usr/lib prefix=/tmp/x", true);
        assert_eq!(
            finding_names(&findings),
            vec!["invalid-pkgconfig-file", "pkgconfig-invalid-libs-dir"]
        );
    }

    #[test]
    fn invalid_utf8_is_an_exception() {
        let err = PkgConfigCheck::check_bytes(b"\xff\xfe invalid \x80", true).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn arch_classification() {
        // The shared predicate covers every 64-bit RPM arch: `-L/usr/lib`
        // is the wrong libdir for all of them, `-L/usr/lib64` for the rest.
        for arch in [
            "x86_64",
            "x86_64_v2",
            "x86_64_v3",
            "x86_64_v4",
            "ppc64",
            "ppc64le",
            "s390x",
            "aarch64",
            "riscv64",
            "loongarch64",
        ] {
            assert!(is_64bit_arch(arch), "{arch}");
        }
        for arch in ["i586", "i686", "armv7l", "noarch", ""] {
            assert!(!is_64bit_arch(arch), "{arch}");
        }
    }

    #[test]
    fn pc_filename_selection() {
        let re = pc_file_regex();
        assert!(is_match(re, "usr/lib64/pkgconfig/foo.pc"));
        assert!(is_match(re, "usr/share/pkgconfig/foo.pc"));
        assert!(!is_match(re, "usr/lib64/pkgconfig/foo.pc.orig"));
        assert!(!is_match(re, "usr/bin/foo"));
    }

    /// plusky's #108 nit: `suspicious_build_dirs_are_reported` is
    /// helper-level only -- it drives `check_line` and pins the finding name.
    /// This one drives `check_binary` on a `.pc` file whose prefix points at
    /// a hyphenated build dir, pinning the emitted name, level and detail.
    /// The `Pkg` comes from `open_no_extract` (no payload extraction into
    /// the shared temp dir): `files` is overwritten wholesale and the `.pc`
    /// bytes are read from `file.path`, never through the package root.
    #[test]
    fn hyphenated_build_dir_emits_error_through_check_binary() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pc = dir.path().join("foo.pc");
        std::fs::write(
            &pc,
            "prefix=/usr/src/linux-6.1/BUILD/usr\n\
             exec_prefix=${prefix}\n\
             Name: foo\n\
             Description: fixture\n\
             Version: 1.0\n\
             Libs: -L/usr/lib64 -lfoo\n",
        )
        .expect("write fixture pc file");
        let mut pkg = Pkg::open_no_extract(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm"),
        )
        .expect("open fixture pkg header");
        pkg.name = "pkgconfig-test".to_string();
        pkg.arch = "x86_64".to_string();
        // The leading slash is what the real pipeline emits, not a fixture
        // artifact: real `RPMTAG_FILENAMES` entries carry it (rpmbuild writes
        // absolute DIRNAMES), the reference keys `pkg.files` on the raw tag
        // value (`pkg.py:679,713`) and emits it verbatim
        // (`PkgConfigCheck.py:46`), and this port emits librpm's raw
        // `rpmfilesFN` the same way. The frozen string is golden for the
        // port's widened pattern only: the reference's `\w+` never matches
        // this hyphenated build dir, so it emits no `invalid-pkgconfig-file`
        // here at all (the widening is already ledgered in
        // `divergences.toml`).
        let rel = "usr/lib64/pkgconfig/foo.pc";
        pkg.files = vec![PkgFile {
            name: format!("/{rel}"),
            path: pc.to_string_lossy().into_owned(),
            mode: 0o100644,
            ..Default::default()
        }];
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).expect("filter");
        let mut check = PkgConfigCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "invalid-pkgconfig-file");
        assert_eq!(
            results[0].1,
            "pkgconfig-test.x86_64: E: invalid-pkgconfig-file /usr/lib64/pkgconfig/foo.pc"
        );
    }

    /// Build a `Pkg` carrying one `.pc` entry with the given on-disk
    /// `path`, in the shape of `hyphenated_build_dir_...` above.
    fn pkg_with_pc_path(path: &Path, name: &str) -> Pkg {
        let mut pkg = Pkg::open_no_extract(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm"),
        )
        .expect("open fixture pkg header");
        pkg.name = "pkgconfig-test".to_string();
        pkg.arch = "x86_64".to_string();
        pkg.files = vec![PkgFile {
            name: name.to_string(),
            path: path.to_string_lossy().into_owned(),
            mode: 0o100644,
            ..Default::default()
        }];
        pkg
    }

    fn run_pkg_config_check(pkg: &Pkg) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).expect("filter");
        let mut check = PkgConfigCheck::new(&config);
        check.check_binary(pkg, &config, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn pc_file_behind_a_colliding_file_is_quiet() {
        // The grpc-source shape (#826): the payload carries the regular
        // file `usr/src/grpc/BUILD` and the directory
        // `usr/src/grpc/build`. On the case-insensitive tree the two are
        // one entry: the extractor materialises the file, skips the
        // entries beneath the directory and reports the skips itself.
        // The fixture builds the resulting layout directly -- a regular
        // file at `build`, the exact component the `.pc` path traverses
        // -- so the read runs through a non-directory and fails with
        // NotADirectory on any filesystem. The error kind is asserted
        // here so the pin cannot silently degrade to an absent-path
        // (NotFound) read. The file was never materialised, so the
        // package draws no finding.
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path().join("usr/src/grpc");
        std::fs::create_dir_all(&root).expect("mkdir fixture tree");
        std::fs::write(root.join("build"), "regular file that won the collision\n")
            .expect("write colliding file");
        let pc_path = root.join("build/libs/opt/pkgconfig/gpr.pc");
        let err = std::fs::read(&pc_path).expect_err("read through a regular file must fail");
        assert_eq!(err.kind(), ErrorKind::NotADirectory);
        let pkg = pkg_with_pc_path(&pc_path, "/usr/src/grpc/build/libs/opt/pkgconfig/gpr.pc");
        let results = run_pkg_config_check(&pkg);
        assert!(results.is_empty(), "unexpected results: {results:?}");
    }

    #[test]
    fn ghost_pc_file_absent_from_the_tree_is_quiet() {
        // A %ghost `.pc` entry is in the header's file list but the
        // payload carries no content for it, so it never materialises.
        // The dispatch skips ghosts before any read, so the absence
        // draws no finding; the same absence on a non-ghost entry
        // reports an exception (next test), so this pin fails if the
        // up-front skip goes away.
        let dir = tempfile::tempdir().expect("tmpdir");
        let pc_path = dir.path().join("usr/lib64/pkgconfig/ghost.pc");
        let mut pkg = pkg_with_pc_path(&pc_path, "/usr/lib64/pkgconfig/ghost.pc");
        pkg.files[0].flags = RPMFILE_GHOST;
        pkg.ghost_files = vec!["/usr/lib64/pkgconfig/ghost.pc".to_string()];
        let results = run_pkg_config_check(&pkg);
        assert!(results.is_empty(), "unexpected results: {results:?}");
    }

    #[test]
    fn missing_pc_file_reports_an_exception() {
        // A header-listed `.pc` file missing from the tree is a read
        // failure like any other: the reference charges it as
        // `pkgconfig-exception` through the `except Exception` around
        // its `open()`. Only the collision failure (NotADirectory,
        // above) stays silent.
        let dir = tempfile::tempdir().expect("tmpdir");
        let pc_path = dir.path().join("usr/lib64/pkgconfig/missing.pc");
        let pkg = pkg_with_pc_path(&pc_path, "/usr/lib64/pkgconfig/missing.pc");
        let results = run_pkg_config_check(&pkg);
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "pkgconfig-exception");
        assert!(
            results[0]
                .1
                .contains("E: pkgconfig-exception /usr/lib64/pkgconfig/missing.pc"),
            "unexpected line: {}",
            results[0].1
        );
    }

    #[test]
    fn undecodable_pc_file_still_reports_an_exception() {
        // A materialised `.pc` file whose bytes are not valid UTF-8
        // keeps the `pkgconfig-exception` finding: the skip above
        // covers only files the extractor left out of the tree.
        let dir = tempfile::tempdir().expect("tmpdir");
        let pc_dir = dir.path().join("usr/lib64/pkgconfig");
        std::fs::create_dir_all(&pc_dir).expect("mkdir fixture tree");
        let pc_path = pc_dir.join("bad.pc");
        std::fs::write(&pc_path, b"prefix=/usr\n\xff\xfe\n").expect("write fixture pc file");
        let pkg = pkg_with_pc_path(&pc_path, "/usr/lib64/pkgconfig/bad.pc");
        let results = run_pkg_config_check(&pkg);
        assert_eq!(results.len(), 1, "unexpected results: {results:?}");
        assert_eq!(results[0].0, "pkgconfig-exception");
        assert!(
            results[0]
                .1
                .contains("E: pkgconfig-exception /usr/lib64/pkgconfig/bad.pc"),
            "unexpected line: {}",
            results[0].1
        );
    }
}
