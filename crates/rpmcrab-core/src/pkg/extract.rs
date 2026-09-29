//! Payload extraction and libmagic, mirroring rpmlint's `Pkg._extract_rpm` and
//! `get_magic`.
//!
//! Extraction shells out to `rpm2archive` staged into a file that `tar -xzf`
//! unpacks (fallback `rpm2cpio | cpio -id`) — the same tools rpmlint uses —
//! because librpm's safe `archive::PackageReader` yields no entries for
//! compressed payloads (`docs/DESIGN.md` §3.1).

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

/// The staged name for the extractor's output. It lives in the extract dir and
/// is removed once unpacked; if unpacking fails the tempdir is dropped with it.
const STAGED: &str = ".rpmcrab-payload.tgz";

/// The shell command for the chosen extractor and whether the rpm is fed on
/// stdin. Pure, so the rpm2archive-vs-rpm2cpio branching and its quoting are
/// golden-testable without the tools installed. `rpm` must already be absolute
/// (the command runs with `cwd` = the tempdir). `None` when neither tool exists.
///
/// How extraction decides success.
///
/// The extractor's exit status is deliberately discarded, and `tar` arbitrates
/// alone. `rpm2archive` reports 1 with *empty* stderr for a payload it could
/// not fully represent — a filename that is not valid UTF-8, say — while still
/// writing a perfectly good archive, so treating its status as fatal turns a
/// warning into `fatal error while reading` on a package the reference unpacks
/// without complaint. `set -o pipefail` does exactly that, and it is not a
/// portable fix either: `set` is a POSIX special builtin, so on dash the
/// unsupported option kills the shell before the pipeline runs and extraction
/// stops working altogether.
///
/// Staging to a file is what lets the unpacker reject a broken archive at all,
/// and it is also what closes the gap `pipefail` was reaching for: BSD tar
/// exits 0 on empty *stdin*, but errors on an empty *file*, so a garbage rpm
/// fails on macOS too. The reference has no `pipefail` and therefore already
/// judges on `tar` alone — this matches it, and matches `cpio` on the fallback.
fn extract_command(
    rpm: &Path,
    have_rpm2archive: bool,
    have_rpm2cpio: bool,
) -> Option<(String, bool)> {
    if have_rpm2archive {
        Some((
            format!(
                "rpm2archive - > {STAGED}; tar -xzf {STAGED} && rm -f {STAGED} && chmod -R +rX ."
            ),
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
/// rpmlint's `_extract_rpm`: `rpm2archive -` into a staged file that `tar -xzf`
/// unpacks, or `rpm2cpio <quoted> | cpio -id` when `rpm2archive` is absent. In
/// both cases the unpacker alone decides success, as it does for the reference
/// (see the `extract_command` comment for why). stderr is discarded and
/// `LC_ALL`/`LANGUAGE` are forced to English, as the reference does.
pub fn extract(rpm: &Path, dir: &Path) -> Result<(), ExtractError> {
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
        // it; nothing may reach rpmcrab's own stdout.
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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
        assert_eq!(
            cmd,
            "rpm2archive - > .rpmcrab-payload.tgz; tar -xzf .rpmcrab-payload.tgz && rm -f .rpmcrab-payload.tgz && chmod -R +rX ."
        );
        assert!(stdin, "rpm2archive reads the rpm on stdin");
    }

    /// The extractor's status must not reach the `&&` chain. Golden strings
    /// cannot catch a regression to `&&` or to `pipefail` — only running the
    /// command can — and getting it wrong turns every warned-about package into
    /// `fatal error while reading`.
    #[test]
    fn a_warning_extractor_still_extracts() {
        let dir = tempfile::tempdir().unwrap();
        // A stub standing in for rpm2archive: emits a real archive, then fails
        // the way a non-UTF-8 payload name makes the real one fail — non-zero,
        // silently. `tar` is the arbiter, so this must succeed.
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let stub = bin.join("rpm2archive");
        std::fs::write(
            &stub,
            "#!/bin/sh\n\
             printf 'payload' > .rpmcrab-payload.tgz\n\
             tar -czf .rpmcrab-payload.tgz payload 2>/dev/null\n\
             exit 1\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("payload"), "hello\n").unwrap();
        make_executable(&stub);

        let (cmd, needs_stdin) = extract_command(Path::new("/dev/null"), true, true).unwrap();
        assert!(needs_stdin);
        let status = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .current_dir(dir.path())
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .stdin(Stdio::null())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "a warned-about archive must still extract"
        );
        assert!(
            !dir.path().join(STAGED).exists(),
            "the staged archive must be cleaned up"
        );
    }

    /// The gap the staging closes: BSD tar exits 0 on empty stdin, so the
    /// reference "extracts" garbage to an empty dir on macOS. From a *file* it
    /// errors, so a broken archive fails everywhere.
    #[test]
    fn a_broken_archive_fails_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let stub = bin.join("rpm2archive");
        std::fs::write(&stub, "#!/bin/sh\n: > .rpmcrab-payload.tgz\nexit 0\n").unwrap();
        make_executable(&stub);

        let (cmd, _) = extract_command(Path::new("/dev/null"), true, true).unwrap();
        let status = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .current_dir(dir.path())
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .stdin(Stdio::null())
            .status()
            .unwrap();
        assert!(
            !status.success(),
            "an empty archive must not count as success"
        );
    }

    #[cfg(unix)]
    fn make_executable(p: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
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
            extract(Path::new("/x.rpm"), &file),
            Err(ExtractError::BadDir(_))
        ));
    }

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
            extract(&bad, out.path()),
            Err(ExtractError::Status(_))
        ));
    }
}
