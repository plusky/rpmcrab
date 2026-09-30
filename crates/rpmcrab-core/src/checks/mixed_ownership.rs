//! `MixedOwnershipCheck` — files must not be owned by a different unprivileged
//! user than their parent directory.
//!
//! Ported from `rpmlint/checks/MixedOwnershipCheck.py`. One finding:
//! `file-parent-ownership-mismatch`.

use std::collections::HashMap;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct MixedOwnershipCheck;

impl MixedOwnershipCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// Messages for files whose owner differs from the parent directory's
    /// owner, when the parent is packaged and not owned by root.
    /// `files` yields `(path, user)` pairs.
    fn mismatches<'a>(files: impl Iterator<Item = (&'a str, &'a str)>) -> Vec<String> {
        let owners: HashMap<&str, &str> = files.collect();
        let mut out = Vec::new();
        for (path, user) in &owners {
            // Parent directory, or "" when there is no '/'.
            let parent = match path.rfind('/') {
                Some(i) => &path[..i],
                None => "",
            };
            // The parent directory is not part of this package: unverifiable.
            let Some(parent_owner) = owners.get(parent) else {
                continue;
            };
            // root-owned directories are trusted.
            if *parent_owner == "root" || *parent_owner == "0" {
                continue;
            }
            if *user != *parent_owner {
                out.push(format!(
                    "Path \"{path}\" owned by \"{user}\" is stored in directory owned by \"{parent_owner}\""
                ));
            }
        }
        out
    }
}

impl Check for MixedOwnershipCheck {
    fn name(&self) -> &'static str {
        "MixedOwnershipCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let files = pkg.files.iter().map(|f| (f.name.as_str(), f.user.as_str()));
        for message in Self::mismatches(files) {
            add_info(
                out,
                Level::Error,
                pkg,
                "file-parent-ownership-mismatch",
                &[&message],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_ownership_is_quiet() {
        let found = MixedOwnershipCheck::mismatches(
            [("/srv/app", "app"), ("/srv/app/data", "app")].into_iter(),
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn mismatch_is_reported() {
        let found = MixedOwnershipCheck::mismatches(
            [("/srv/app", "app"), ("/srv/app/data", "other")].into_iter(),
        );
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("/srv/app/data"), "{}", found[0]);
        assert!(found[0].contains("\"other\""), "{}", found[0]);
        assert!(found[0].contains("\"app\""), "{}", found[0]);
    }

    #[test]
    fn root_owned_parent_is_trusted() {
        let found = MixedOwnershipCheck::mismatches(
            [("/usr", "root"), ("/usr/bin/tool", "daemon")].into_iter(),
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn numeric_root_is_trusted() {
        let found = MixedOwnershipCheck::mismatches(
            [("/srv/app", "0"), ("/srv/app/data", "other")].into_iter(),
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn unpackaged_parent_is_skipped() {
        let found = MixedOwnershipCheck::mismatches([("/srv/app/data", "other")].into_iter());
        assert!(found.is_empty(), "{found:?}");
    }
}
