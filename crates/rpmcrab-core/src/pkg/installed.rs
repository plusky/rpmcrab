//! Installed-package lookup over the rpmdb (rpmlint `get_installed_pkgs`).

use librpm::db::{Db, Index};

use super::{Pkg, PkgError, init};

/// True when rpmlint treats `name` as a glob: `re.search(r'[?*]|\[.+\]', name)`.
fn is_glob(name: &str) -> bool {
    name.contains(['?', '*']) || has_bracket_class(name)
}

/// A `[` … `]` with at least one character between (`\[.+\]`).
fn has_bracket_class(name: &str) -> bool {
    let bytes = name.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'[' && name[i + 1..].find(']').is_some_and(|rel| rel >= 1) {
            return true;
        }
    }
    false
}

/// Resolve `-i/--installed` names (rpmlint `get_installed_pkgs`): exact match
/// unless the name is a glob. Names that match nothing are returned in
/// `missing` (the caller prints rpmlint's `there is no installed rpm` warning).
pub fn find_installed(names: &[String]) -> Result<(Vec<Pkg>, Vec<String>), PkgError> {
    init()?;
    let db = Db::open().map_err(|e| PkgError::Db(e.to_string()))?;
    find_in(&db, names)
}

/// Like [`find_installed`] but against the rpmdb rooted at `root` (used by the
/// parity test's isolated database).
pub fn find_installed_in(
    root: &std::path::Path,
    names: &[String],
) -> Result<(Vec<Pkg>, Vec<String>), PkgError> {
    init()?;
    let db = Db::open_with_root(root).map_err(|e| PkgError::Db(e.to_string()))?;
    find_in(&db, names)
}

fn find_in(db: &Db, names: &[String]) -> Result<(Vec<Pkg>, Vec<String>), PkgError> {
    let mut pkgs = Vec::new();
    let mut missing = Vec::new();
    for name in names {
        let matched: Vec<_> = if is_glob(name) {
            db.find_glob(Index::Name, name).collect()
        } else {
            db.find(Index::Name, name).collect()
        };
        if matched.is_empty() {
            missing.push(name.clone());
        }
        for header in matched {
            pkgs.push(Pkg::installed(header));
        }
    }
    Ok((pkgs, missing))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_detection_matches_rpmlint() {
        // No metacharacters -> exact.
        assert!(!is_glob("bash"));
        assert!(!is_glob("libstdc++6"));
        // `?` / `*` -> glob.
        assert!(is_glob("bash?"));
        assert!(is_glob("lib*"));
        // `\[.+\]` -> glob, but an empty `[]` is not.
        assert!(is_glob("pkg[12]"));
        assert!(is_glob("name[a]extra"));
        assert!(!is_glob("pkg[]"));
        assert!(!is_glob("pkg["));
    }
}
