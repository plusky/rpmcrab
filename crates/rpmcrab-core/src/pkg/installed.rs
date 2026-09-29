//! Installed-package lookup over the rpmdb (rpmlint `get_installed_pkgs`).
//!
//! **Divergence — an unreadable rpmdb looks like an empty one.** The reference
//! opens the db itself and raises on failure (`rpmtsOpenDB(ts, O_RDONLY)`,
//! `rpmts-py.c:675-683`), so a broken database aborts the run. librpm 0.6 does
//! not expose that result: `Db::open` only builds a transaction set, and
//! `rpmtsInitIterator` returning NULL is reported as "no match". `Db::verify`
//! is not a substitute — it returns `Ok` on a missing database and rebuilds the
//! indexes as a side effect, which a read-only lint must not do. Recorded in
//! `tests/parity/divergences.toml`.

use librpm::PackageHeader;
use librpm::db::{Db, Index};

use super::{PkgError, init};

/// How a requested name is resolved against the rpmdb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lookup {
    /// Never queried: an empty name matches nothing.
    Missing,
    /// `rpmdbFind` on the literal name.
    Exact,
    /// `rpmdbFind` through `RPMMIRE_GLOB`.
    Glob,
}

/// Resolve `-i/--installed` names (rpmlint `get_installed_pkgs`): exact match
/// unless the name is a glob. Returns the matched headers plus the names that
/// matched nothing, for the caller's `there is no installed rpm` warning.
///
/// Headers rather than `Pkg`s: building the facade walks every file of every
/// match, so a wide glob would stat the whole system for a caller that only
/// needs the names. `Pkg::installed` runs when a check asks for a package.
pub fn find_installed(names: &[String]) -> Result<(Vec<PackageHeader>, Vec<String>), PkgError> {
    init()?;
    let db = Db::open()?;
    find_in(&db, names)
}

/// Resolve `-i/--installed` names against an open rpmdb; [`find_installed`]
/// opens the host database and calls this. Public so the query path is testable
/// against a throwaway database without privilege.
pub fn find_in(db: &Db, names: &[String]) -> Result<(Vec<PackageHeader>, Vec<String>), PkgError> {
    init()?;
    let mut found_headers = Vec::new();
    let mut missing = Vec::new();
    for name in names {
        match lookup_kind(name) {
            // The reference passes the zero-length key straight through
            // (`rpmtsInitIterator(s->ts, tag, key, len)`, len = 0), which
            // matches no package. librpm turns an empty key into a NULL key,
            // which is "every package", so `-i ""` would lint the whole system.
            Lookup::Missing => missing.push(name.clone()),
            Lookup::Exact => {
                let found: Vec<_> = db.find(Index::Name, name).collect();
                if found.is_empty() {
                    missing.push(name.clone());
                }
                found_headers.extend(found);
            }
            Lookup::Glob => {
                let found: Vec<_> = db.find_glob(Index::Name, name).collect();
                if found.is_empty() {
                    missing.push(name.clone());
                }
                found_headers.extend(found);
            }
        }
    }
    Ok((found_headers, missing))
}

fn lookup_kind(name: &str) -> Lookup {
    if name.is_empty() {
        Lookup::Missing
    } else if is_glob(name) {
        Lookup::Glob
    } else {
        Lookup::Exact
    }
}

/// True when rpmlint treats `name` as a glob: `re.search(r'[?*]|\[.+\]', name)`.
fn is_glob(name: &str) -> bool {
    name.contains(['?', '*']) || has_bracket_class(name)
}

/// A `[` … `]` with at least one character between (`\[.+\]`).
///
/// `.+` backtracks, so the class may close at any `]` after the first character,
/// not only the first one: `[]a]` is a class (`.+` = `]a`) and
/// `re.search(r'\[.+\]', "[]a]')` matches. Only looking at the first `]` after
/// each `[` misclassifies such names and silently turns a glob into an exact
/// lookup.
fn has_bracket_class(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes
        .iter()
        .enumerate()
        .any(|(i, &b)| b == b'[' && bytes[i + 1..].iter().skip(1).any(|&c| c == b']'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every case below is the verdict of `re.search(r'[?*]|\[.+\]', name)` from
    /// CPython 3, including the `[]a]` family that a first-`]`-only
    /// implementation gets wrong.
    #[test]
    fn glob_detection_matches_rpmlint() {
        const CASES: &[(&str, bool)] = &[
            // No metacharacters -> exact.
            ("bash", false),
            ("libstdc++6", false),
            ("a[b", false),
            ("a]b", false),
            ("[ab", false),
            ("ab]", false),
            // `?` / `*` -> glob.
            ("bash?", true),
            ("lib*", true),
            // `\[.+\]` -> glob, but an empty `[]` is not.
            ("pkg[12]", true),
            ("name[a]extra", true),
            ("pkg[]", false),
            ("pkg[", false),
            ("[]", false),
            // The backtracking cases: `]` counts as the `.+` content.
            ("[]a]", true),
            ("[]]", true),
            ("[[]", true),
            ("[]]a", true),
            ("x[]y]z", true),
            ("[]]]", true),
            ("[]]b]", true),
            // Nested and multi-close.
            ("[a[b]c]", true),
            ("[a[]]", true),
            ("[a[]]]", true),
            ("[[]]", true),
            ("a[[]b]", true),
            ("[a]b]", true),
            ("[[[]]]", true),
            // Metacharacters inside a class still glob.
            ("[?]", true),
            ("[a]*", true),
            // Non-ASCII: byte scanning must not split a code point.
            ("é[", false),
            ("é]", false),
            ("[é", false),
            ("[é]", true),
            ("é[a]", true),
        ];
        for &(name, want) in CASES {
            assert_eq!(is_glob(name), want, "is_glob({name:?})");
        }
    }

    /// A glob-looking name must reach the glob query, never the exact one.
    #[test]
    fn lookup_kind_never_exact_matches_a_glob() {
        assert_eq!(lookup_kind("bash"), Lookup::Exact);
        assert_eq!(lookup_kind("lib*"), Lookup::Glob);
        assert_eq!(lookup_kind("[]a]"), Lookup::Glob);
    }

    /// librpm reads an empty key as "match everything"; the reference matches
    /// nothing, so the name is reported missing without querying.
    #[test]
    fn empty_name_is_missing_without_querying() {
        assert_eq!(lookup_kind(""), Lookup::Missing);
    }
}
