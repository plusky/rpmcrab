//! `BashismsCheck` — bash-specific constructs in `/bin/sh` scripts.
//!
//! Ported from `rpmlint/checks/BashismsCheck.py`. Two findings:
//! `bin-sh-syntax-error` and `potential-bashisms`.
//!
//! The reference shells out to `dash -n` and `checkbashisms`; this port runs
//! `dash -n` when dash exists and skips the file (debug-logged) when it does
//! not, rather than crashing at init like the reference. `checkbashisms` is
//! optional: without it only `potential-bashisms` is suppressed.

use std::path::Path;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::is_reg;
use crate::tools::{Tool, ToolSource, test_source};

pub struct BashismsCheck {
    dash: Tool,
    checkbashisms: Tool,
    use_early_fail: bool,
    checked_files: usize,
}

impl BashismsCheck {
    pub fn new(_config: &Config) -> Self {
        Self::with_tool_source(ToolSource::Path)
    }

    /// Probe for `dash` and `checkbashisms` under `source`. The reference
    /// crashes when `checkbashisms` is absent; we degrade gracefully instead:
    /// without dash the check is a no-op, without checkbashisms only
    /// `potential-bashisms` is suppressed.
    pub fn with_tool_source(source: ToolSource) -> Self {
        let (dash, _) = Tool::probe(&source, "dash", &["--version"]);
        let (checkbashisms, help) = Tool::probe(&source, "checkbashisms", &["--help"]);
        // The `--early-fail` option speeds the check up; detect it from the
        // probe output instead of spawning twice.
        let use_early_fail = help
            .map(|o| {
                String::from_utf8_lossy(&o.stdout).into_owned()
                    + &String::from_utf8_lossy(&o.stderr)
            })
            .map(|text| text.contains("[-e]"))
            .unwrap_or(false);
        Self {
            dash,
            checkbashisms,
            use_early_fail,
            checked_files: 0,
        }
    }

    /// Test entry point: `None` probes the live `PATH`, `Some(dir)`
    /// resolves both tools under `dir`, so tests can drive the whole check
    /// against fake tools without mutating the process environment.
    pub fn with_tool_dir(bin_dir: Option<&Path>) -> Self {
        Self::with_tool_source(test_source(bin_dir))
    }

    /// `(have_dash, use_early_fail)`, kept for the probe tests.
    pub fn detect_tools(bin_dir: Option<&Path>) -> (bool, bool) {
        let check = Self::with_tool_dir(bin_dir);
        (check.have_dash(), check.use_early_fail)
    }

    /// `bin-sh-syntax-error` needs only `dash -n`; `checkbashisms` is optional.
    fn have_dash(&self) -> bool {
        self.dash.is_present()
    }

    /// The warnings for one script file: `bin-sh-syntax-error` and/or
    /// `potential-bashisms`.
    ///
    /// Pure classification of the two tools' exit codes, split out so tests
    /// can drive it without subprocesses.
    fn classify_bashisms(dash_code: Option<i32>, bashisms_code: Option<i32>) -> Vec<&'static str> {
        let mut out = Vec::new();
        match dash_code {
            Some(2) => out.push("bin-sh-syntax-error"),
            // 127 or spawn failure: dash itself is missing, nothing to report.
            Some(127) | None => return out,
            _ => {}
        }
        if bashisms_code == Some(1) {
            out.push("potential-bashisms");
        }
        out
    }

    /// Run the tools and classify their exit codes.
    fn check_bashisms(&self, path: &str) -> Vec<&'static str> {
        let dash_code = self.run_dash(path);
        let bashisms_code = self.run_checkbashisms(path);
        Self::classify_bashisms(dash_code, bashisms_code)
    }

    fn run_dash(&self, path: &str) -> Option<i32> {
        let mut cmd = self.dash.command()?;
        cmd.args(["-n", path]).env("LC_ALL", "C");
        cmd.output().ok()?.status.code()
    }

    fn run_checkbashisms(&self, path: &str) -> Option<i32> {
        let mut cmd = self.checkbashisms.command()?;
        cmd.arg(path).env("LC_ALL", "C");
        if self.use_early_fail {
            cmd.arg("-e");
        }
        cmd.output().ok()?.status.code()
    }
}

impl Check for BashismsCheck {
    fn name(&self) -> &'static str {
        "BashismsCheck"
    }

    /// This check only ever emits warnings (every `add_info` call site
    /// passes `Level::Warning`), so `--errors-only` skips it.
    fn max_severity(&self) -> Level {
        Level::Warning
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if !self.have_dash() {
            log::debug!("BashismsCheck: dash not found, skipping");
            return;
        }
        // Cache by md5 like the reference (kernel-source ships the same
        // script in several packages).
        let mut cache: std::collections::HashMap<String, Vec<&'static str>> =
            std::collections::HashMap::new();
        for pkgfile in &pkg.files {
            // The reference counts every non-ghost file (files_re is `.*`) and
            // drops ghosts from the dispatch list (AbstractCheck.py:45), so a
            // ghost script is never handed to the tools.
            if pkg.ghost_files.iter().any(|g| g == &pkgfile.name) {
                continue;
            }
            self.checked_files += 1;
            if !is_reg(pkgfile.mode) {
                continue;
            }
            if !pkgfile.magic.starts_with("POSIX shell script") {
                continue;
            }
            let key = pkgfile.md5.clone().unwrap_or_else(|| pkgfile.name.clone());
            let warnings = cache
                .entry(key)
                .or_insert_with(|| self.check_bashisms(&pkgfile.path));
            for warning in warnings.clone() {
                add_info(out, Level::Warning, pkg, warning, &[&pkgfile.name]);
            }
        }
    }

    fn reset(&mut self) {
        self.checked_files = 0;
    }

    fn checked_files(&self) -> Option<usize> {
        Some(self.checked_files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn fake_tool(dir: &std::path::Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write fake tool");
        let mut perms = std::fs::metadata(&path)
            .expect("stat fake tool")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod fake tool");
        // A just-written script can still be "text file busy" (ETXTBSY) on
        // first spawn under parallel load; settle it so probes below see an
        // exec-ready tool.
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
    #[cfg(unix)]
    fn detect_tools_finds_probed_tools() {
        let dir = tempfile::tempdir().expect("tmpdir");
        fake_tool(dir.path(), "dash", "echo 'dash 0.5.12'");
        fake_tool(
            dir.path(),
            "checkbashisms",
            "echo 'usage: checkbashisms [-e] file'",
        );
        assert_eq!(BashismsCheck::detect_tools(Some(dir.path())), (true, true));
    }

    #[test]
    #[cfg(unix)]
    fn detect_tools_reports_missing_checkbashisms() {
        let dir = tempfile::tempdir().expect("tmpdir");
        fake_tool(dir.path(), "dash", "echo 'dash 0.5.12'");
        // dash alone suffices for bin-sh-syntax-error; only the
        // checkbashisms-dependent early-fail probe is negative.
        assert_eq!(BashismsCheck::detect_tools(Some(dir.path())), (true, false));
    }

    #[test]
    #[cfg(unix)]
    fn detect_tools_reports_missing_dash() {
        let dir = tempfile::tempdir().expect("tmpdir");
        fake_tool(
            dir.path(),
            "checkbashisms",
            "echo 'usage: checkbashisms [-e] file'",
        );
        assert_eq!(BashismsCheck::detect_tools(Some(dir.path())), (false, true));
    }

    #[test]
    #[cfg(unix)]
    fn detect_tools_detects_early_fail_support() {
        let dir = tempfile::tempdir().expect("tmpdir");
        fake_tool(dir.path(), "dash", "echo 'dash 0.5.12'");
        fake_tool(
            dir.path(),
            "checkbashisms",
            "echo 'usage: checkbashisms file'",
        );
        assert_eq!(BashismsCheck::detect_tools(Some(dir.path())), (true, false));
    }

    #[test]
    fn syntax_error_is_reported() {
        assert_eq!(
            BashismsCheck::classify_bashisms(Some(2), Some(0)),
            vec!["bin-sh-syntax-error"]
        );
    }

    #[test]
    fn syntax_error_and_bashisms_combine() {
        assert_eq!(
            BashismsCheck::classify_bashisms(Some(2), Some(1)),
            vec!["bin-sh-syntax-error", "potential-bashisms"]
        );
    }

    #[test]
    fn clean_dash_with_bashisms() {
        assert_eq!(
            BashismsCheck::classify_bashisms(Some(0), Some(1)),
            vec!["potential-bashisms"]
        );
    }

    #[test]
    fn clean_run_is_quiet() {
        assert!(BashismsCheck::classify_bashisms(Some(0), Some(0)).is_empty());
    }

    #[test]
    fn missing_dash_reports_nothing() {
        // dash exit 127 (or a spawn failure): the tool is absent, and the
        // reference's FileNotFoundError path yields no findings either.
        assert!(BashismsCheck::classify_bashisms(Some(127), Some(1)).is_empty());
        assert!(BashismsCheck::classify_bashisms(None, Some(1)).is_empty());
    }
}
