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
}

impl BashismsCheck {
    pub fn new(_config: &Config) -> Self {
        let (have_tools, use_early_fail) = Self::detect_tools();
        Self {
            use_early_fail,
            have_tools,
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
    fn check_bashisms(path: &str, use_early_fail: bool) -> Vec<&'static str> {
        let mut out = Vec::new();
        let dash = Command::new("dash")
            .args(["-n", path])
            .env("LC_ALL", "C")
            .output();
        match dash {
            Ok(o) if o.status.code() == Some(2) => out.push("bin-sh-syntax-error"),
            Ok(o) if o.status.code() == Some(127) => return out,
            Err(_) => return out,
            _ => {}
        }
        let mut cmd = Command::new("checkbashisms");
        cmd.arg(path).env("LC_ALL", "C");
        if use_early_fail {
            cmd.arg("-e");
        }
        match cmd.output() {
            Ok(o) if o.status.code() == Some(1) => out.push("potential-bashisms"),
            _ => {}
        }
        out
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_tools_does_not_panic() {
        // Just exercises the probe; the result depends on the environment.
        let _ = BashismsCheck::detect_tools();
    }
}
