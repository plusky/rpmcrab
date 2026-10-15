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
use std::time::Duration;

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
        let output = spawn_with_retry(|| Command::new(&path).args(probe_args).output());
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

/// Attempts for one probe spawn before the tool is declared absent.
///
/// A single spawn can fail transiently under load (fork/exec pressure
/// on a busy runner), and one failure would otherwise read as "the
/// tool is not installed", silently disabling every check that depends
/// on it. Only transient failures (`WouldBlock`, `Interrupted`) are
/// retried; a permanent failure -- a missing or non-executable
/// binary -- fails fast on the first attempt.
const PROBE_ATTEMPTS: usize = 3;

/// Pause between probe attempts; see [`PROBE_ATTEMPTS`].
const PROBE_RETRY_DELAY: Duration = Duration::from_millis(25);

/// Run `spawn` until it succeeds and return the output; `None` when
/// the spawn failed permanently or every attempt failed transiently.
///
/// Retries apply only to transient spawn errors -- `WouldBlock`
/// (resource pressure) and `Interrupted` (a signal interrupted the
/// spawn) -- up to [`PROBE_ATTEMPTS`] attempts. Any other error, such
/// as `NotFound` for a missing binary or `PermissionDenied` for a
/// non-executable one, fails identically on every attempt, so it
/// returns `None` on the first attempt.
///
/// Split out of [`Tool::probe`] so the retry policy is testable with a
/// scripted spawner instead of a real binary.
fn spawn_with_retry<F>(mut spawn: F) -> Option<Output>
where
    F: FnMut() -> std::io::Result<Output>,
{
    for attempt in 0..PROBE_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(PROBE_RETRY_DELAY);
        }
        match spawn() {
            Ok(output) => return Some(output),
            Err(err) => match err.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => {}
                _ => return None,
            },
        }
    }
    None
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
    use std::cell::Cell;
    use std::io;

    /// A stand-in successful spawn result, built without spawning.
    #[cfg(unix)]
    fn fake_output() -> Output {
        use std::os::unix::process::ExitStatusExt;
        Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn spawn_retry_returns_the_first_success() {
        // Two transient (WouldBlock) failures, then the spawn works:
        // the tool must read as present, not absent.
        let attempts = Cell::new(0);
        let output = spawn_with_retry(|| {
            attempts.set(attempts.get() + 1);
            if attempts.get() < 3 {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            } else {
                Ok(fake_output())
            }
        });
        assert!(output.is_some());
        assert_eq!(attempts.get(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn spawn_retry_retries_an_interrupted_spawn() {
        // Interrupted is the other transient kind: one interrupted
        // spawn, then the retry succeeds.
        let attempts = Cell::new(0);
        let output = spawn_with_retry(|| {
            attempts.set(attempts.get() + 1);
            if attempts.get() < 2 {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                Ok(fake_output())
            }
        });
        assert!(output.is_some());
        assert_eq!(attempts.get(), 2);
    }

    #[test]
    fn spawn_retry_fails_fast_on_a_missing_binary() {
        // NotFound is permanent -- a missing binary stays missing --
        // so the probe must not retry it.
        let attempts = Cell::new(0);
        let output: Option<Output> = spawn_with_retry(|| {
            attempts.set(attempts.get() + 1);
            Err(io::Error::from(io::ErrorKind::NotFound))
        });
        assert!(output.is_none());
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn spawn_retry_fails_fast_on_a_non_executable_binary() {
        // PermissionDenied is permanent too: exactly one attempt.
        let attempts = Cell::new(0);
        let output: Option<Output> = spawn_with_retry(|| {
            attempts.set(attempts.get() + 1);
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        });
        assert!(output.is_none());
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn spawn_retry_gives_up_when_every_attempt_fails_transiently() {
        // A spawn that keeps failing transiently must still end up
        // absent after exactly PROBE_ATTEMPTS tries.
        let attempts = Cell::new(0);
        let output: Option<Output> = spawn_with_retry(|| {
            attempts.set(attempts.get() + 1);
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        });
        assert!(output.is_none());
        assert_eq!(attempts.get(), PROBE_ATTEMPTS);
    }

    #[cfg(unix)]
    #[test]
    fn spawn_retry_does_not_retry_a_success() {
        let attempts = Cell::new(0);
        let output = spawn_with_retry(|| {
            attempts.set(attempts.get() + 1);
            Ok(fake_output())
        });
        assert!(output.is_some());
        assert_eq!(attempts.get(), 1);
    }

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
