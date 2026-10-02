//! Payload extraction and libmagic, mirroring rpmlint's `Pkg._extract_rpm` and
//! `get_magic`.
//!
//! Extraction shells out to `rpm2archive | tar -xz` (fallback
//! `rpm2cpio | cpio -id`) — the same commands rpmlint runs — because librpm's
//! safe `archive::PackageReader` yields no entries for compressed payloads
//! (`docs/DESIGN.md` §3.1).

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Errors during extraction.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("extract dir {0} is not a directory")]
    BadDir(PathBuf),
    #[error("neither rpm2archive nor rpm2cpio is on PATH")]
    NoTool,
    #[error("opening {path}: {source}")]
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("running the extractor: {0}")]
    Run(std::io::Error),
    #[error("extraction failed (exit status {0})")]
    Status(i32),
}

/// True if `name` is an executable on `PATH` (rpmlint's `shutil.which`).
fn which(name: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| {
            let p = dir.join(name);
            p.metadata()
                .is_ok_and(|m| p.is_file() && m.permissions().mode() & 0o111 != 0)
        })
    })
}

/// POSIX single-quote a path for a `sh -c` command (the rpm2cpio fallback
/// interpolates the path; the rpm2archive branch does not, so its command is a
/// fixed string).
fn sh_quote(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "'\\''"))
}

/// The shell command for the chosen extractor and whether the rpm is fed on
/// stdin. Pure, so the rpm2archive-vs-rpm2cpio branching and its quoting are
/// golden-testable without the tools installed. `rpm` must already be absolute
/// (the command runs with `cwd` = the tempdir). `None` when neither tool exists.
fn extract_command(
    rpm: &Path,
    have_rpm2archive: bool,
    have_rpm2cpio: bool,
) -> Option<(String, bool)> {
    if have_rpm2archive {
        Some((
            "rpm2archive - | tar -xz && chmod -R +rX .".to_string(),
            true,
        ))
    } else if have_rpm2cpio {
        Some((
            format!("rpm2cpio {} | cpio -id && chmod -R +rX .", sh_quote(rpm)),
            false,
        ))
    } else {
        None
    }
}

/// Extract the payload of `rpm` into `dir` (which must already exist), matching
/// rpmlint's `_extract_rpm`:
/// `rpm2archive - | tar -xz && chmod -R +rX .` with the rpm on stdin, or
/// `rpm2cpio <quoted> | cpio -id && chmod -R +rX .` when `rpm2archive` is
/// absent. stderr is discarded and `LC_ALL`/`LANGUAGE` are forced to English,
/// as the reference does.
pub fn extract(rpm: &Path, dir: &Path, suppress_stderr: bool) -> Result<(), ExtractError> {
    if !dir.is_dir() {
        return Err(ExtractError::BadDir(dir.to_path_buf()));
    }
    // rpmlint resolves the path (`Path(self.filename).resolve()`) before use, so
    // a relative rpm path still works in the `cwd`=tempdir child.
    let abs = std::fs::canonicalize(rpm).unwrap_or_else(|_| rpm.to_path_buf());
    let (cmd, needs_stdin) = extract_command(&abs, which("rpm2archive"), which("rpm2cpio"))
        .ok_or(ExtractError::NoTool)?;

    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(&cmd)
        .current_dir(dir)
        .env("LC_ALL", "en_US.UTF-8")
        .env("LANGUAGE", "en_US")
        // rpmlint captures the extractor's output via `check_output` and drops
        // it; nothing may reach rpmcrab's own stdout. stderr follows
        // `SuppressExtractionStderr` (rpmlint#1592).
        .stdout(Stdio::null())
        .stderr(if suppress_stderr {
            Stdio::null()
        } else {
            Stdio::inherit()
        });
    if needs_stdin {
        let f = File::open(&abs).map_err(|source| ExtractError::Open {
            path: abs.clone(),
            source,
        })?;
        command.stdin(Stdio::from(f));
    }
    let status = command.status().map_err(ExtractError::Run)?;
    if !status.success() {
        return Err(ExtractError::Status(status.code().unwrap_or(-1)));
    }
    Ok(())
}

/// libmagic's description of `path` — rpmlint's `get_magic` via python-magic's
/// `from_file`. `file -b` produces the identical string; `''` on failure, as
/// the reference returns on `ValueError`/`FileNotFoundError`.
///
/// This shells out per consulted file rather than calling libmagic in-process
/// (the reference uses python-magic). Only files with an empty `FILECLASS` reach
/// it, and `file` is already a dependency (§7.4); a native binding can replace
/// this later without changing the call site.
pub fn file_magic(path: &Path) -> String {
    // `LC_ALL=C` so the `cannot open` message below is stable regardless of the
    // ambient locale (libmagic output itself is locale-independent).
    let stdout = match Command::new("file")
        .arg("-b")
        .arg(path)
        .env("LC_ALL", "C")
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        _ => return String::new(),
    };
    let text = String::from_utf8_lossy(&stdout);
    let text = text.trim_end_matches('\n');
    // `file` exits 0 and prints `cannot open \`...' (...)` to stdout for a
    // missing or unreadable path; rpmlint's `get_magic` returns '' there.
    if text.starts_with("cannot open ") {
        return String::new();
    }
    text.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_quote_wraps_and_escapes() {
        assert_eq!(sh_quote(Path::new("/tmp/a b.rpm")), "'/tmp/a b.rpm'");
        assert_eq!(sh_quote(Path::new("/tmp/it's.rpm")), "'/tmp/it'\\''s.rpm'");
    }

    #[test]
    fn which_finds_a_real_tool() {
        assert!(which("sh"));
        assert!(!which("definitely-not-a-real-tool-xyz"));
    }

    #[test]
    fn file_magic_matches_libmagic() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("hello.txt");
        std::fs::write(&p, "hello\n").unwrap();
        // Equal to python-magic's `from_file` (rpmlint's `get_magic`).
        assert_eq!(file_magic(&p), "ASCII text");
    }

    #[test]
    fn file_magic_missing_is_empty() {
        assert_eq!(file_magic(Path::new("/no/such/file/xyz")), "");
    }

    #[test]
    fn extract_command_prefers_rpm2archive() {
        let (cmd, stdin) = extract_command(Path::new("/x/y.rpm"), true, true).unwrap();
        assert_eq!(cmd, "rpm2archive - | tar -xz && chmod -R +rX .");
        assert!(stdin, "rpm2archive reads the rpm on stdin");
    }

    #[test]
    fn extract_command_falls_back_to_quoted_rpm2cpio() {
        let (cmd, stdin) = extract_command(Path::new("/x/it's y.rpm"), false, true).unwrap();
        assert_eq!(
            cmd,
            "rpm2cpio '/x/it'\\''s y.rpm' | cpio -id && chmod -R +rX ."
        );
        assert!(!stdin, "rpm2cpio takes the path as an argument");
    }

    #[test]
    fn extract_command_none_without_tools() {
        assert!(extract_command(Path::new("/x.rpm"), false, false).is_none());
    }

    #[test]
    fn extract_rejects_a_non_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        assert!(matches!(
            extract(Path::new("/x.rpm"), &file, true),
            Err(ExtractError::BadDir(_))
        ));
    }

    // BSD tar exits 0 on empty input (stdin and file alike), so a garbage
    // rpm "extracts" to an empty directory on macOS instead of failing.
    // Known divergence; the reference behaves the same there.
    #[cfg_attr(
        target_os = "macos",
        ignore = "BSD tar exits 0 on empty input; known divergence"
    )]
    #[test]
    fn extract_fails_on_a_garbage_rpm() {
        // Needs an extractor present to reach a non-zero status rather than
        // NoTool.
        if !which("rpm2archive") && !which("rpm2cpio") {
            eprintln!("skip: no rpm2archive/rpm2cpio");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("not-an.rpm");
        std::fs::write(&bad, b"definitely not an rpm").unwrap();
        let out = tempfile::tempdir().unwrap();
        assert!(matches!(
            extract(&bad, out.path(), true),
            Err(ExtractError::Status(_))
        ));
    }
}
