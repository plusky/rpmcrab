//! Pin for the capture-parity empty-input guard: invoking the script
//! with a case name but no inputs must fail with exit 2 before the
//! case directory exists, rather than capturing an empty run.

use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn capture_parity_empty_input_exits_2_without_creating_the_case() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ref_dir = dir.path().join("ref");
    let venv_bin = ref_dir.join("venv").join("bin");
    std::fs::create_dir_all(&venv_bin).expect("venv bin dir");
    let rpmlint = venv_bin.join("rpmlint");
    std::fs::write(&rpmlint, "#!/bin/sh\nexit 0\n").expect("stub rpmlint");
    #[cfg(unix)]
    std::fs::set_permissions(&rpmlint, std::fs::Permissions::from_mode(0o755))
        .expect("stub rpmlint executable");
    let xdg = ref_dir.join("xdg");
    std::fs::create_dir_all(&xdg).expect("xdg dir");

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/capture-parity.sh");
    let case = "empty-input-pin-test";
    let output = std::process::Command::new("bash")
        .arg(&script)
        .arg(case)
        .arg("--")
        .arg("extra-arg")
        .env("RPMLINT_REF", &ref_dir)
        .env("RPMLINT_XDG", &xdg)
        .output()
        .expect("run capture-parity.sh");
    assert_eq!(
        output.status.code(),
        Some(2),
        "empty inputs must exit 2: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no inputs given"),
        "stderr must name the guard: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let case_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity/cases")
        .join(case);
    assert!(
        !case_dir.exists(),
        "the guard must fail before the case directory exists: {}",
        case_dir.display()
    );
}
