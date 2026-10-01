//! `BashismsCheck` — bash-specific constructs in `/bin/sh` scripts.
//!
//! Ported from `rpmlint/checks/BashismsCheck.py`. Two findings:
//! `bin-sh-syntax-error` and `potential-bashisms`.
//!
//! The reference shells out to `dash -n` and `checkbashisms`; this port does
//! the same when the tools exist and skips the file (debug-logged) when they
//! do not, rather than crashing at init like the reference.

use std::process::Command;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::is_reg;

pub struct BashismsCheck {
    use_early_fail: bool,
    have_tools: bool,
    checked_files: usize,
}

impl BashismsCheck {
    pub fn new(_config: &Config) -> Self {
        let (have_tools, use_early_fail) = Self::detect_tools();
        Self {
            use_early_fail,
            have_tools,
            checked_files: 0,
        }
    }

    /// Probe for `dash` and `checkbashisms`. The reference crashes here when
    /// `checkbashisms` is absent; we degrade to a no-op check instead.
    fn detect_tools() -> (bool, bool) {
        let dash = Command::new("dash").arg("--version").output().is_ok();
        let help = Command::new("checkbashisms").arg("--help").output();
        match help {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout).into_owned()
                    + &String::from_utf8_lossy(&out.stderr);
                (dash, text.contains("[-e]"))
            }
            Err(_) => (false, false),
        }
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
    fn check_bashisms(path: &str, use_early_fail: bool) -> Vec<&'static str> {
        let dash_code = Command::new("dash")
            .args(["-n", path])
            .env("LC_ALL", "C")
            .output()
            .ok()
            .and_then(|o| o.status.code());
        let mut cmd = Command::new("checkbashisms");
        cmd.arg(path).env("LC_ALL", "C");
        if use_early_fail {
            cmd.arg("-e");
        }
        let bashisms_code = cmd.output().ok().and_then(|o| o.status.code());
        Self::classify_bashisms(dash_code, bashisms_code)
    }
}

impl Check for BashismsCheck {
    fn name(&self) -> &'static str {
        "BashismsCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if !self.have_tools {
            log::debug!("BashismsCheck: dash/checkbashisms not found, skipping");
            return;
        }
        // Cache by md5 like the reference (kernel-source ships the same
        // script in several packages).
        let mut cache: std::collections::HashMap<String, Vec<&'static str>> =
            std::collections::HashMap::new();
        for pkgfile in &pkg.files {
            // The reference counts every non-ghost file (files_re is `.*`).
            if !pkg.ghost_files.iter().any(|g| g == &pkgfile.name) {
                self.checked_files += 1;
            }
            if !is_reg(pkgfile.mode) {
                continue;
            }
            if !pkgfile.magic.starts_with("POSIX shell script") {
                continue;
            }
            let key = pkgfile.md5.clone().unwrap_or_else(|| pkgfile.name.clone());
            let warnings = cache
                .entry(key)
                .or_insert_with(|| Self::check_bashisms(&pkgfile.path, self.use_early_fail));
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

    #[test]
    fn detect_tools_is_deterministic() {
        // The probe only reads the environment, so two consecutive runs
        // must agree. PATH is deliberately not mutated to force a case:
        // that would be unsafe under parallel in-process tests.
        assert_eq!(BashismsCheck::detect_tools(), BashismsCheck::detect_tools());
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
