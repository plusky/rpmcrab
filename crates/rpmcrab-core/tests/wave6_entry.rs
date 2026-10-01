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
use rpmcrab_core::checks::appdata::AppDataCheck;
use rpmcrab_core::checks::bashisms::BashismsCheck;
use rpmcrab_core::checks::filelist::FilelistCheck;
use rpmcrab_core::checks::menu::MenuCheck;
use rpmcrab_core::checks::menu_xdg::MenuXDGCheck;
use rpmcrab_core::checks::polkit::PolkitCheck;
use rpmcrab_core::checks::python::PythonCheck;
use rpmcrab_core::checks::systemd_install::SystemdInstallCheck;
use rpmcrab_core::checks::systemd_tmpfiles::SystemdTmpfilesCheck;
use rpmcrab_core::checks::sysv_init_on_systemd::SysVInitOnSystemdCheck;
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
    run_check_with(check, rpm, &Config::default())
}

/// Like `run_check` but with a caller-supplied config (e.g. to point
/// `PolkitCheck` at a scratch privs profile instead of the live path).
fn run_check_with(check: &mut impl Check, rpm: &str, config: &Config) -> Vec<(String, String)> {
    let rpm_path = fixture(rpm);
    assert!(
        rpm_path.is_file(),
        "fixture missing: {}",
        rpm_path.display()
    );
    let scratch = tempfile::tempdir().unwrap();
    let pkg = Pkg::open(&rpm_path, scratch.path()).unwrap();
    let mut filter = Filter::new(config, Color::for_tty(false)).unwrap();
    check.check_binary(&pkg, config, &mut filter);
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

/// Write an executable fake tool script, settling it past the ETXTBSY window
/// so the first real spawn never fails under parallel test load.
#[cfg(unix)]
fn fake_tool(dir: &std::path::Path, name: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    for _ in 0..100 {
        match std::process::Command::new(&path).arg("--version").output() {
            Ok(_) => return,
            Err(e) if e.raw_os_error() == Some(26) => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) => panic!("fake tool {} failed: {e}", path.display()),
        }
    }
    panic!("fake tool {} stayed busy", path.display());
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
            (
                "systemd-service-without-service_del_preun",
                "w6sysv.service",
            ),
            (
                "systemd-service-without-service_del_postun",
                "w6sysv.service",
            ),
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
        &[("desktopfile-without-binary", "/usr/bin/w6-missing-binary")],
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

/// The fixture ships `/usr/local/man/man1/w6.1` and `/var/lib/games/w6.scores`,
/// which match the absolute Bad patterns `/usr/local/man/*/*` and
/// `/var/lib/games/*` under fnmatch, plus `/opt/w6provider/bin/w6` for the
/// `-opt` provider-directory rule. The fhs23 rule carries no `IgnorePkgIf`
/// or `IgnoreFileIf`, so it applies to every file unconditionally.
///
/// The comparison is on the full package-relative path, not a basename:
/// `PkgFile.__init__` sets `self.name` and `self.path` to the same value and
/// `pkg.py:845` keys `pkg.files` by it. The emit-order divergence entries for
/// fhs23 and -opt assume the rule fires, so this pins that it does.
#[test]
fn filelist_reports_absolute_bad_patterns() {
    let mut check = FilelistCheck::new(&Config::default());
    let results = run_check(&mut check, "w6-filelist-1.0-1.noarch.rpm");
    assert_findings(
        &results,
        &[
            ("filelist-forbidden-fhs23", "/usr/local/man/man1/w6.1"),
            ("filelist-forbidden-fhs23", "/var/lib/games/w6.scores"),
            // The prefix walk-up: /usr/local/man/man1/w6.1 matches no good
            // prefix, so the reference reports the first bad component.
            ("filelist-forbidden-fhs23", "/usr/local"),
            // /opt/<provider> files are collapsed to the provider dir.
            ("filelist-forbidden-opt", "/opt/w6provider"),
        ],
    );
}

/// `AppDataCheck` validates `/usr/share/appdata/*.xml` with `appstream-util`
/// when present, else a native well-formedness check. The malformed fixture
/// file fails both paths; the valid one passes both, so this is independent
/// of whether the tool is installed.
#[test]
fn appdata_reports_malformed_file() {
    let mut check = AppDataCheck::new(&Config::default());
    let results = run_check(&mut check, "w6-appdata-1.0-1.noarch.rpm");
    assert_findings(
        &results,
        &[("invalid-appdata-file", "w6broken.appdata.xml")],
    );
    assert!(
        !results.iter().any(|(_, line)| line.contains("w6valid")),
        "valid appdata file should be quiet: {results:?}"
    );
}

/// `BashismsCheck` shells out to `dash` and `checkbashisms`. The tool dir is
/// injected, so fakes with verified real-tool semantics drive the whole check
/// deterministically: `dash -n` exits 0 on `[[ ]]` (it parses as a plain
/// command) and `checkbashisms` exits 1 when it reports a bashism.
#[test]
#[cfg(unix)]
fn bashisms_reports_bashism_script() {
    let dir = tempfile::tempdir().unwrap();
    fake_tool(dir.path(), "dash", "exit 0");
    fake_tool(
        dir.path(),
        "checkbashisms",
        "if [ \"$1\" = \"--help\" ]; then echo \'usage: checkbashisms [-e] file [...]\'; exit 0; fi\nif grep -q \'\\[\\[\' \"$1\" 2>/dev/null; then echo \"possible bashism in $1\" >&2; exit 1; fi\nexit 0",
    );
    let mut check = BashismsCheck::with_tool_dir(Some(dir.path()));
    let results = run_check(&mut check, "w6-bashisms-1.0-1.noarch.rpm");
    assert_findings(&results, &[("potential-bashisms", "w6bashism")]);
    assert!(
        !results.iter().any(|(_, line)| line.contains("w6clean")),
        "clean POSIX script should be quiet: {results:?}"
    );
}

/// `PolkitCheck` whitelists actions against a privs profile. The live default
/// (`/usr/etc/polkit-default-privs/profiles/standard`) must not leak into the
/// test, so the profile is injected via a scratch `PolkitPrivsFiles` config.
#[test]
fn polkit_reports_privilege_findings() {
    let dir = tempfile::tempdir().unwrap();
    let privs = dir.path().join("standard");
    std::fs::write(&privs, "# scratch profile\norg.w6.whitelisted auth_admin\n").unwrap();
    let mut config = Config::default();
    config.configuration.insert(
        "PolkitPrivsFiles".to_string(),
        toml::Value::Array(vec![toml::Value::String(
            privs.to_str().unwrap().to_string(),
        )]),
    );
    let mut check = PolkitCheck::new(&config);
    let results = run_check_with(&mut check, "w6-polkit-1.0-1.noarch.rpm", &config);
    assert_findings(
        &results,
        &[
            // allow_any=yes, not whitelisted.
            (
                "polkit-user-privilege",
                "org.w6.unprivileged (yes:no:auth_admin)",
            ),
            // All settings no/absent: polkit defaults to `no`.
            ("polkit-untracked-privilege", "org.w6.locked (no:no:no)"),
            ("polkit-xml-exception", "w6broken.policy"),
            ("polkit-ghost-file", "w6ghost.policy"),
        ],
    );
    assert!(
        !results
            .iter()
            .any(|(_, line)| line.contains("org.w6.whitelisted")),
        "whitelisted action should be quiet: {results:?}"
    );
}
