//! The check interface and registry.
//!
//! Checks are keyed by the exact Python module name (`FilesCheck`, `TagsCheck`,
//! …) so a TOML `Checks = [...]` list resolves unchanged (`docs/DESIGN.md`
//! §7.2). For M1 the registry is populated with synthetic checks that emit
//! known findings, proving the renderer before any real check exists.

use crate::filter::Filter;
use crate::level::Level;

/// A lint check. Real checks inspect a package; the M1 synthetic checks emit
/// canned findings to exercise the report pipeline.
pub trait Check {
    /// The check's registry name (the Python module name, e.g. `FilesCheck`).
    fn name(&self) -> &'static str;

    /// Run the check, emitting findings into `out`.
    fn run(&self, out: &mut Filter);
}

/// A check that emits a fixed set of findings. Used to prove the wire format
/// byte-for-byte without any RPM parsing.
pub struct SyntheticCheck {
    name: &'static str,
    pkg_name: String,
    arch: Option<String>,
    findings: Vec<(Level, &'static str, Vec<String>)>,
}

impl SyntheticCheck {
    pub fn new(
        name: &'static str,
        pkg_name: &str,
        arch: Option<&str>,
        findings: Vec<(Level, &'static str, Vec<String>)>,
    ) -> Self {
        Self {
            name,
            pkg_name: pkg_name.to_string(),
            arch: arch.map(str::to_string),
            findings,
        }
    }
}

impl Check for SyntheticCheck {
    fn name(&self) -> &'static str {
        self.name
    }

    fn run(&self, out: &mut Filter) {
        for (level, check, details) in &self.findings {
            out.add_info(crate::finding::Finding {
                level: *level,
                check: (*check).to_string(),
                details: details.clone(),
                badness: 0,
                pkg_name: self.pkg_name.clone(),
                arch: self.arch.clone(),
                line: None,
            });
        }
    }
}
