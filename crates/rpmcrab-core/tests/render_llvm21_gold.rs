//! Integration test: a full `Lint` run over a synthetic check set must produce
//! the frozen report wire format (header, sorted findings, footer, exit code).
//!
//! The expected block below is the rendering of the captured
//! `tests/parity/cases/llvm21-gold` case, with the wall-clock duration
//! rendered as a fixed `0.1`. It departs from the captured reference
//! output in ledgered places (`tests/parity/divergences.toml`): the
//! session banner identifies rpmcrab itself (`rpmcrab: <crate version>`,
//! `docs/DESIGN.md` §4.5), and the report carries no badness column,
//! footer total or threshold banner (issue #699, `docs/DESIGN.md` §4.1).
//!
//! The package is a real one from the corpus driven through the same
//! `check_batch` loop the binary uses; the checks themselves are synthetic, so
//! the findings are canned and the output stays a pure test of the report
//! pipeline.

use std::path::Path;

use rpmcrab_core::check::{Check, SyntheticCheck};
use rpmcrab_core::color::Color;
use rpmcrab_core::config;
use rpmcrab_core::level::Level;
use rpmcrab_core::lint::Lint;
use rpmcrab_core::worker::Task;

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
    // The bundled defaults, not a struct literal: the defaults are not
    // permissive, so the exit-code assertion below pins issue #699's
    // contract (errors fail the run by default).
    let mut config = config::load_bundled();
    config.conf_files = CONF_FILES.iter().map(|s| (*s).to_string()).collect();
    config.checks = (0..43).map(|i| format!("Check{i}")).collect();
    config.filters = vec!["no-documentation".to_string()];
    let canned = vec![
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
    ];
    let make_checks = || {
        vec![Box::new(SyntheticCheck::new(
            "SyntheticCheck",
            "llvm21-gold",
            Some("aarch64"),
            canned.clone(),
        )) as Box<dyn Check>]
    };

    let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity/cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm");

    let mut lint = Lint::new(config, make_checks(), Color::for_tty(false), 80).unwrap();
    lint.check_batch(vec![Task::File(rpm)], 1, &make_checks, true);
    // version, header arg count, no -t, no -T, duration.
    let version = env!("CARGO_PKG_VERSION");
    let out = lint.render_report("text", "rpmcrab", version, 1, false, 0.1);

    let expected = format!(
        "\
============================ rpmcrab session starts ============================
rpmcrab: {version}
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
 1 packages and 0 specfiles checked; 2 errors, 1 warnings, 1 filtered; has taken 0.1 s \n",
    );

    assert_eq!(out, expected);
    // Two errors fail the run by default (issue #699).
    assert_eq!(lint.exit_code(), 64);
}
