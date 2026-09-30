//! The `.spec` package model — the Rust equivalent of rpmlint's `FakePkg`
//! for spec inputs.
//!
//! A spec is text with line numbers, not an RPM with a payload: there is no
//! header, no file list, no extraction. The reference builds a `FakePkg`
//! around the spec path (`name` is the as-passed path, `is_source` is forced
//! false) and dispatches `check_spec` on holding one.

use std::cell::Cell;
use std::io;
use std::path::{Path, PathBuf};

/// A `.spec` file being linted.
#[derive(Debug)]
pub struct SpecPkg {
    /// The spec path as passed (`pkg.name` in the reference; the finding's
    /// file part is its basename).
    pub name: String,
    /// The spec text, read at [`SpecPkg::open`] time
    /// (`rpmlint.helpers.readlines` at the top of `SpecCheck.check_spec`).
    pub lines: Vec<String>,
    /// The 1-based line the check is currently looking at
    /// (`FakePkg.current_linenum`, rendered as `file.spec:NN:`). Interior
    /// mutability: the `Check` trait hands the check a shared reference,
    /// mirroring how the reference mutates the `FakePkg` it was given.
    pub current_linenum: Cell<Option<u32>>,
}

/// `SpecPkg::open` failures.
#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    /// The spec file could not be read.
    #[error("reading the spec file {path}: {source}")]
    Read {
        /// The spec path as passed.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl SpecPkg {
    /// Open a `.spec` file, reading its lines now. Readability is validated
    /// here: the reference's `validate_file` treats any read failure as
    /// fatal, surfacing when `SpecCheck` first reads the file.
    pub fn open(path: &Path) -> Result<Self, SpecError> {
        let lines = readlines(path).map_err(|source| SpecError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self {
            name: path.to_string_lossy().into_owned(),
            lines,
            current_linenum: Cell::new(None),
        })
    }
}

/// `rpmlint.helpers.readlines`: the file's lines, each keeping its trailing
/// newline (like iterating a binary file object), decoded as UTF-8 with
/// undecodable bytes replaced (`helpers.byte_to_string`).
pub fn readlines(path: &Path) -> io::Result<Vec<String>> {
    let bytes = std::fs::read(path)?;
    Ok(bytes
        .split_inclusive(|b: &u8| *b == b'\n')
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect())
}

/// `rpmlint.pkg.is_utf8` for a spec file: true when the bytes are valid
/// UTF-8. (The reference also handles compressed files; a spec never is.)
pub fn is_utf8(path: &Path) -> bool {
    std::fs::read(path).is_ok_and(|bytes| std::str::from_utf8(&bytes).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readlines_keeps_trailing_newlines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.spec");
        std::fs::write(&path, "Name: foo\nVersion: 1\n").unwrap();
        assert_eq!(
            readlines(&path).unwrap(),
            vec!["Name: foo\n", "Version: 1\n"]
        );
    }

    #[test]
    fn readlines_last_line_without_newline_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.spec");
        std::fs::write(&path, "Name: foo\nVersion: 1").unwrap();
        assert_eq!(readlines(&path).unwrap(), vec!["Name: foo\n", "Version: 1"]);
    }

    #[test]
    fn readlines_replaces_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.spec");
        std::fs::write(&path, b"Name: f\xffo\n").unwrap();
        assert_eq!(readlines(&path).unwrap(), vec!["Name: f�o\n"]);
    }

    #[test]
    fn is_utf8_rejects_invalid_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let ok = dir.path().join("ok.spec");
        let bad = dir.path().join("bad.spec");
        std::fs::write(&ok, "Name: foo\n").unwrap();
        std::fs::write(&bad, b"Name: f\xffo\n").unwrap();
        assert!(is_utf8(&ok));
        assert!(!is_utf8(&bad));
    }

    #[test]
    fn open_reads_lines_and_starts_without_linenum() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.spec");
        std::fs::write(&path, "Name: foo\n").unwrap();
        let pkg = SpecPkg::open(&path).unwrap();
        assert_eq!(pkg.lines, vec!["Name: foo\n"]);
        assert_eq!(pkg.current_linenum.get(), None);
    }
}
