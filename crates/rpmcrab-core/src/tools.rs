//! Declared external tool dependencies.
//!
//! Checks that shell out to helper binaries (`rpm`, `appstream-util`,
//! `dash`, …) declare them here instead of scattering ad-hoc probing.
//! Each tool is probed once, when the check is constructed, and resolves
//! to a concrete path from then on. Tests inject fakes deterministically
//! by pointing the probe at a scratch directory.
//!
//! A missing tool is never an error at this layer: [`Tool::command`]
//! returns `None` and each check decides how to degrade (skip the
//! sub-check, fall back to a native implementation, …). The one exception
//! is a tool the check cannot function without at all — that check panics
//! at construction with a message naming the binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Where external tool binaries resolve from.
#[derive(Debug, Clone)]
pub enum ToolSource {
    /// The live `PATH` (production).
    Path,
    /// A scratch directory (tests): `name` resolves to `dir.join(name)`,
    /// so a missing file reads as an absent tool.
    Dir(PathBuf),
}

impl ToolSource {
    fn resolve(&self, name: &str) -> PathBuf {
        match self {
            ToolSource::Path => PathBuf::from(name),
            ToolSource::Dir(dir) => dir.join(name),
        }
    }
}

/// One external binary a check depends on, probed once.
///
/// `path` is `Some` when spawning the binary succeeded during the probe,
/// whatever its exit status was; `None` means the tool is absent and the
/// check degrades gracefully.
#[derive(Debug, Clone)]
pub struct Tool {
    name: &'static str,
    path: Option<PathBuf>,
}

impl Tool {
    /// Probe `name` under `source` by spawning it with `probe_args`.
    ///
    /// The spawn succeeding is what counts, not the exit status — a
    /// `--version` or `--help` probe may exit nonzero on a present tool.
    /// The output is returned alongside so callers can detect capabilities
    /// (feature flags, version strings) from it without spawning twice.
    pub fn probe(
        source: &ToolSource,
        name: &'static str,
        probe_args: &[&str],
    ) -> (Self, Option<Output>) {
        let path = source.resolve(name);
        let output = Command::new(&path).args(probe_args).output().ok();
        let tool = Self {
            name,
            path: output.as_ref().map(|_| path),
        };
        (tool, output)
    }

    /// `true` when the probe found the tool.
    pub fn is_present(&self) -> bool {
        self.path.is_some()
    }

    /// The declared binary name, for diagnostics.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// A `Command` running the resolved binary, or `None` when the tool
    /// is absent and the caller must degrade gracefully.
    pub fn command(&self) -> Option<Command> {
        self.path.as_ref().map(Command::new)
    }
}

/// Build a [`ToolSource`] for tests: `None` probes the live `PATH`,
/// `Some(dir)` resolves every tool under `dir`.
pub(crate) fn test_source(dir: Option<&Path>) -> ToolSource {
    match dir {
        Some(dir) => ToolSource::Dir(dir.to_path_buf()),
        None => ToolSource::Path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_marks_missing_tool_absent() {
        let source = ToolSource::Dir(PathBuf::from("/nonexistent-tool-dir"));
        let (tool, output) = Tool::probe(&source, "no-such-tool", &["--version"]);
        assert!(!tool.is_present());
        assert!(tool.command().is_none());
        assert!(output.is_none());
        assert_eq!(tool.name(), "no-such-tool");
    }

    #[test]
    fn probe_marks_spawnable_binary_present() {
        // `sh` exists on every unix test host; the exit status is
        // irrelevant, only the spawn succeeding matters.
        let (tool, output) = Tool::probe(&ToolSource::Path, "sh", &["--no-such-flag"]);
        assert!(tool.is_present());
        assert!(tool.command().is_some());
        assert!(output.is_some());
    }

    #[test]
    fn dir_source_resolves_under_the_dir() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let source = ToolSource::Dir(dir.path().to_path_buf());
        let (tool, _) = Tool::probe(&source, "dash", &["--version"]);
        assert!(!tool.is_present());
        // The probe tried <dir>/dash, not PATH's dash.
        assert!(tool.command().is_none());
    }

    #[test]
    fn test_source_maps_none_to_path() {
        assert!(matches!(test_source(None), ToolSource::Path));
        assert!(matches!(
            test_source(Some(Path::new("/tmp/x"))),
            ToolSource::Dir(_)
        ));
    }
}
