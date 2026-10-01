//! Entry-point tests for the wave-6 straightforward checks.
//!
//! Each test opens a hand-built fixture RPM via `Pkg::open`, drives the
//! check's `check_binary`, and asserts the findings the reference rpmlint
//! 2.10.0 (opensuse @ 84848c05c5571c22274a55ff9afdfe6d88c67dc9) emits for the
//! same fixture. These pin the check to its entry point: a no-op `add_info`
//! (M1) or a deleted finding arm (M2) fails them.
//!
//! Fixtures live in `tests/parity/pkg/inputs/` with their `.spec` files.

use std::path::PathBuf;

use rpmcrab_core::check::Check;
use rpmcrab_core::checks::alternatives::AlternativesCheck;
use rpmcrab_core::checks::menu::MenuCheck;
use rpmcrab_core::checks::menu_xdg::MenuXDGCheck;
use rpmcrab_core::checks::python::PythonCheck;
use rpmcrab_core::checks::systemd_tmpfiles::SystemdTmpfilesCheck;
use rpmcrab_core::checks::sysv_init_on_systemd::SysVInitOnSystemdCheck;
use rpmcrab_core::checks::systemd_install::SystemdInstallCheck;
use rpmcrab_core::checks::tmpfiles::TmpFilesCheck;
use rpmcrab_core::color::Color;
use rpmcrab_core::config::Config;
use rpmcrab_core::filter::Filter;
use rpmcrab_core::pkg::Pkg;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity/pkg/inputs")
        .join(name)
}

/// Run one check's `check_binary` over the fixture and return the
/// `(check_name, rendered_line)` pairs in emission order.
fn run_check(check: &mut impl Check, rpm: &str) -> Vec<(String, String)> {
    let rpm_path = fixture(rpm);
    assert!(rpm_path.is_file(), "fixture missing: {}", rpm_path.display());
    let scratch = tempfile::tempdir().unwrap();
    let pkg = Pkg::open(&rpm_path, scratch.path()).unwrap();
    let config = Config::default();
    let mut filter = Filter::new(&config, Color::for_tty(false)).unwrap();
    check.check_binary(&pkg, &config, &mut filter);
    filter.results().to_vec()
}

/// Assert every `(finding, detail)` pair appears in the results.
fn assert_findings(results: &[(String, String)], expected: &[(&str, &str)]) {
    for (finding, detail) in expected {
        assert!(
            results
                .iter()
                .any(|(_, line)| line.contains(finding) && line.contains(detail)),
            "missing {finding} {detail} in {results:?}"
        );
    }
}

#[test]
fn sysv_init_on_systemd_flags_deprecated_and_shadowed() {
    let mut check = SysVInitOnSystemdCheck::new(&Config::default());
    let results = run_check(&mut check, "w6-sysv-1.0-1.noarch.rpm");
    assert_findings(
        &results,
        &[
            ("deprecated-init-script", "w6sysv"),
            ("systemd-shadowed-initscript", "w6sysv"),
        ],
    );
}

#[test]
fn python_flags_missing_require() {
    let mut check = PythonCheck::new(&Config::default());
    let results = run_check(&mut check, "w6-python-1.0-1.noarch.rpm");
    assert_findings(&results, &[("python-missing-require", "w6-missing-dep")]);
}

#[test]
fn systemd_install_flags_missing_scriptlets() {
    let mut check = SystemdInstallCheck::new(&Config::default());
    let results = run_check(&mut check, "w6-sysv-1.0-1.noarch.rpm");
    assert_findings(
        &results,
        &[
            ("systemd-service-without-service_del_preun", "w6sysv.service"),
            ("systemd-service-without-service_del_postun", "w6sysv.service"),
            ("systemd-service-without-service_add_pre", "w6sysv.service"),
            ("systemd-service-without-service_add_post", "w6sysv.service"),
        ],
    );
}

#[test]
fn tmpfiles_flags_paths_not_in_filelist() {
    let mut check = TmpFilesCheck::new(&Config::default());
    let results = run_check(&mut check, "w6-tmpfiles-1.0-1.noarch.rpm");
    assert_findings(
        &results,
        &[
            ("tmpfile-not-in-filelist", "/run/w6tmp"),
            ("tmpfile-not-in-filelist", "/run/w6tmp/file"),
        ],
    );
}

#[test]
fn systemd_tmpfiles_flags_unauthorized_entry() {
    let mut check = SystemdTmpfilesCheck::new(&Config::default());
    let results = run_check(&mut check, "w6-systemd-tmpfiles-1.0-1.noarch.rpm");
    assert_findings(
        &results,
        &[("systemd-tmpfile-entry-unauthorized", "/etc/w6st")],
    );
}

#[test]
fn alternatives_flags_missing_prereqs_and_links() {
    let mut check = AlternativesCheck::new(&Config::default());
    let results = run_check(&mut check, "w6-alternatives-1.0-1.noarch.rpm");
    assert_findings(
        &results,
        &[
            ("update-alternatives-requirement-missing", ""),
            ("update-alternatives-postun-call-missing", ""),
            ("alternative-link-missing", "/etc/alternatives/w6cmd"),
            ("alternative-generic-name-missing", "/usr/bin/w6cmd"),
        ],
    );
}

#[test]
fn menu_xdg_flags_desktopfile_without_binary() {
    let mut check = MenuXDGCheck::new(&Config::default());
    let results = run_check(&mut check, "w6-menu-1.0-1.noarch.rpm");
    assert_findings(
        &results,
        &[(
            "desktopfile-without-binary",
            "/usr/bin/w6-missing-binary",
        )],
    );
}

#[test]
fn menu_flags_old_menu_entry() {
    let mut check = MenuCheck::new(&Config::default());
    let results = run_check(&mut check, "w6-menulegacy-1.0-1.noarch.rpm");
    assert_findings(
        &results,
        &[("old-menu-entry", "/usr/share/applnk/w6legacy.desktop")],
    );
}
