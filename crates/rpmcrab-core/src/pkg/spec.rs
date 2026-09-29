//! The `.spec` package model — the Rust equivalent of rpmlint's `FakePkg`
//! for spec inputs.
//!
//! A spec is text with line numbers, not an RPM with a payload: there is no
//! header, no file list, no extraction. The reference builds a `FakePkg`
//! around the spec path (`name` is the as-passed path, `is_source` is forced
//! false) and dispatches `check_spec` on holding one.

use std::path::{Path, PathBuf};

/// A `.spec` file being linted.
#[derive(Debug)]
pub struct SpecPkg {
    /// The spec path as passed (`pkg.name` in the reference; the finding's
    /// file part is its basename).
    pub name: String,
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
    /// Open a `.spec` file. Readability is validated now, like `Pkg::open`
    /// validates the rpm: the reference's `validate_file` treats any read
    /// failure as fatal.
    pub fn open(path: &Path) -> Result<Self, SpecError> {
        std::fs::read(path).map_err(|source| SpecError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self {
            name: path.to_string_lossy().into_owned(),
        })
    }
}
