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

/// Extract the payload of `rpm` into `dir` (which must already exist), matching
/// rpmlint's `_extract_rpm`:
/// `rpm2archive - | tar -xz && chmod -R +rX .` with the rpm on stdin, or
/// `rpm2cpio <quoted> | cpio -id && chmod -R +rX .` when `rpm2archive` is
/// absent. stderr is discarded and `LC_ALL`/`LANGUAGE` are forced to English,
/// as the reference does.
pub fn extract(rpm: &Path, dir: &Path) -> Result<(), ExtractError> {
    if !dir.is_dir() {
        return Err(ExtractError::BadDir(dir.to_path_buf()));
    }
    let archive_stdin = which("rpm2archive");
    let cmd = if archive_stdin {
        "rpm2archive - | tar -xz && chmod -R +rX .".to_string()
    } else if which("rpm2cpio") {
        format!("rpm2cpio {} | cpio -id && chmod -R +rX .", sh_quote(rpm))
    } else {
        return Err(ExtractError::NoTool);
    };

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
    if archive_stdin {
        let f = File::open(rpm).map_err(|source| ExtractError::Open {
            path: rpm.to_path_buf(),
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
pub fn file_magic(path: &Path) -> String {
    let stdout = match Command::new("file").arg("-b").arg(path).output() {
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
}
