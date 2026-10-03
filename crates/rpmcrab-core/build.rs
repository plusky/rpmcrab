// Detect the build environment's Python version for the `python_version`
// marker default in PythonCheck.
//
// The reference derives it from the interpreter running rpmlint
// (platform.python_version_tuple(), PythonCheck.py:140). The port is a
// Rust binary with no interpreter; the build-time Python is the closest
// equivalent -- on a normal build host it is the same Python rpmlint would
// run under. Falls back to 3.12 when no python3 is found at build time.
fn main() {
    let version = detect_python_version().unwrap_or_else(|| "3.12".to_string());
    println!("cargo:rustc-env=BUILDTIME_PYTHON_VERSION={version}");
}

fn detect_python_version() -> Option<String> {
    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg("import sys; print(f\"{sys.version_info[0]}.{sys.version_info[1]}\")")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    let mut parts = s.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(format!("{major}.{minor}"))
}
