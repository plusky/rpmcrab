//! Integration test: a full `Lint` run over a synthetic check set must produce
//! byte-identical output to a real openSUSE rpmlint run.
//!
//! This is the M1 thesis — the report pipeline (header, sorted findings,
//! footer, exit code) reproduces the frozen wire format. The expected block
//! below is a hand-transcribed rendering of the captured
//! `tests/parity/cases/llvm21-gold/expected/stdout`, with the wall-clock
//! duration rendered as a fixed `0.1`; it is verified byte-for-byte against
//! that capture.
//!
//! The package is a real one from the corpus (built as an installed package so
//! nothing is unpacked) driven through the same `run_package` loop the binary
//! uses; the checks themselves are synthetic, so the findings are canned and
//! the output stays a pure test of the report pipeline.

use std::path::Path;

use librpm::PackageHeader;
use librpm::verify::VerifyOptions;
use rpmcrab_core::check::{Check, SyntheticCheck};
use rpmcrab_core::color::Color;
use rpmcrab_core::config::Config;
use rpmcrab_core::level::Level;
use rpmcrab_core::lint::Lint;
use rpmcrab_core::pkg::Pkg;

const CONF_FILES: &[&str] = &[
    "<VENV>/lib64/python3.13/site-packages/rpmlint/configdefaults.toml",
    "<XDG>/rpmlint/cron-whitelist.toml",
    "<XDG>/rpmlint/dbus-services.toml",
    "<XDG>/rpmlint/device-files-whitelist.toml",
    "<XDG>/rpmlint/licenses.toml",
    "<XDG>/rpmlint/opensuse.toml",
    "<XDG>/rpmlint/pam-modules.toml",
    "<XDG>/rpmlint/permissions-whitelist.toml",
    "<XDG>/rpmlint/pie-executables.toml",
    "<XDG>/rpmlint/polkit-rules-whitelist.toml",
    "<XDG>/rpmlint/scoring.toml",
    "<XDG>/rpmlint/security.toml",
    "<XDG>/rpmlint/sudoers-whitelist.toml",
    "<XDG>/rpmlint/sysctl-whitelist.toml",
    "<XDG>/rpmlint/systemd-tmpfiles.toml",
    "<XDG>/rpmlint/users-groups.toml",
    "<XDG>/rpmlint/varlink-whitelist.toml",
    "<XDG>/rpmlint/world-writable-whitelist.toml",
    "<XDG>/rpmlint/zypper-plugins.toml",
];

#[test]
fn reproduces_llvm21_gold_byte_for_byte() {
    let config = Config {
        conf_files: CONF_FILES.iter().map(|s| (*s).to_string()).collect(),
        checks: (0..43).map(|i| format!("Check{i}")).collect(),
        badness_threshold: 999,
        permissive: true, // openSUSE forces --permissive unless -s
        filters: vec!["no-documentation".to_string()],
        ..Config::default()
    };
    let checks: Vec<Box<dyn Check>> = vec![Box::new(SyntheticCheck::new(
        "SyntheticCheck",
        "llvm21-gold",
        Some("aarch64"),
        vec![
            (
                Level::Error,
                "suse-zypp-packageand",
                vec!["packageand(clang21:binutils)".to_string()],
            ),
            (
                Level::Error,
                "suse-zypp-packageand",
                vec!["packageand(clang21:binutils-gold)".to_string()],
            ),
            (
                Level::Warning,
                "no-soname",
                vec!["/usr/lib64/LLVMgold.so".to_string()],
            ),
            // Suppressed by the `no-documentation` filter -> "1 filtered".
            (Level::Warning, "no-documentation", vec![]),
        ],
    ))];

    let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity/cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm");
    let header = PackageHeader::from_file(&rpm, Some(&VerifyOptions::skip_verification()))
        .expect("open corpus header");
    let mut pkg = Pkg::installed(header);

    let mut lint = Lint::new(config, checks, Color::for_tty(false), 80).unwrap();
    lint.run_package(&mut pkg, true);
    // version, header arg count, no -t, no -T, duration.
    let out = lint.render("2.10.0", 1, false, false, 0.1);

    let expected = "\
============================ rpmlint session starts ============================
rpmlint: 2.10.0
configuration:
    <VENV>/lib64/python3.13/site-packages/rpmlint/configdefaults.toml
    <XDG>/rpmlint/cron-whitelist.toml
    <XDG>/rpmlint/dbus-services.toml
    <XDG>/rpmlint/device-files-whitelist.toml
    <XDG>/rpmlint/licenses.toml
    <XDG>/rpmlint/opensuse.toml
    <XDG>/rpmlint/pam-modules.toml
    <XDG>/rpmlint/permissions-whitelist.toml
    <XDG>/rpmlint/pie-executables.toml
    <XDG>/rpmlint/polkit-rules-whitelist.toml
    <XDG>/rpmlint/scoring.toml
    <XDG>/rpmlint/security.toml
    <XDG>/rpmlint/sudoers-whitelist.toml
    <XDG>/rpmlint/sysctl-whitelist.toml
    <XDG>/rpmlint/systemd-tmpfiles.toml
    <XDG>/rpmlint/users-groups.toml
    <XDG>/rpmlint/varlink-whitelist.toml
    <XDG>/rpmlint/world-writable-whitelist.toml
    <XDG>/rpmlint/zypper-plugins.toml
checks: 43, packages: 1

llvm21-gold.aarch64: E: suse-zypp-packageand packageand(clang21:binutils)
llvm21-gold.aarch64: E: suse-zypp-packageand packageand(clang21:binutils-gold)
llvm21-gold.aarch64: W: no-soname /usr/lib64/LLVMgold.so
 1 packages and 0 specfiles checked; 2 errors, 1 warnings, 1 filtered, 2 badness; has taken 0.1 s \n";

    assert_eq!(out, expected);
    // openSUSE forces permissive, so two errors still exit 0 (score 2 < 999).
    assert_eq!(lint.exit_code(), 0);
}
