//! `MixedOwnershipCheck` — files must not be owned by a different unprivileged
//! user than their parent directory.
//!
//! Ported from `rpmlint/checks/MixedOwnershipCheck.py`. One finding:
//! `file-parent-ownership-mismatch`. The port demotes the case where the
//! mismatched file itself is root-owned to a warning (see the divergence
//! ledger); a mismatch between two unprivileged owners stays an error.

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

    /// Findings for files whose owner differs from the parent directory's
    /// owner, when the parent is packaged and not owned by root.
    /// `files` yields `(path, user)` pairs; each finding carries its level:
    /// a root-owned file is a warning, a mismatch between two unprivileged
    /// owners is an error.
    fn mismatches<'a>(files: impl Iterator<Item = (&'a str, &'a str)>) -> Vec<(Level, String)> {
        let entries: Vec<(&str, &str)> = files.collect();
        let owners: HashMap<&str, &str> = entries.iter().copied().collect();
        let mut out = Vec::new();
        // Iterate the package's file order, not the map's: the reference walks
        // `pkg.files.items()` (MixedOwnershipCheck.py:16) and every finding here
        // shares one sort key, so hash order would become the output order.
        for (path, user) in &entries {
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
                // A root-owned file inside a service user's directory is a
                // widespread deliberate layout (web-app writable dirs, daemon
                // state dirs, spool trees): the directory owner gains nothing
                // it does not already have over payload it executes or reads.
                // It stays visible as a warning -- root-executed scripts in
                // such a directory (the hylafax+ shape) are the same file
                // facts, and which uid executes a file is runtime wiring this
                // check cannot decide. Two unprivileged owners keep the
                // reference's error: one user can replace files another user
                // owns and executes.
                let level = if *user == "root" || *user == "0" {
                    Level::Warning
                } else {
                    Level::Error
                };
                out.push((
                    level,
                    format!(
                        "Path \"{path}\" owned by \"{user}\" is stored in directory owned by \"{parent_owner}\""
                    ),
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
        for (level, message) in Self::mismatches(files) {
            add_info(
                out,
                level,
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
        assert!(found[0].1.contains("/srv/app/data"), "{}", found[0].1);
        assert!(found[0].1.contains("\"other\""), "{}", found[0].1);
        assert!(found[0].1.contains("\"app\""), "{}", found[0].1);
    }

    /// The both-unprivileged shape is the reference's canonical example and
    /// keeps the error: munin-node's nobody-owned plugin-state directory
    /// inside the munin-owned /var/lib/munin.
    #[test]
    fn unprivileged_peer_mismatch_stays_error() {
        let found = MixedOwnershipCheck::mismatches(
            [
                ("/var/lib/munin", "munin"),
                ("/var/lib/munin/plugin-state", "nobody"),
            ]
            .into_iter(),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Error, "error, not warning");
    }

    /// The demoted shape: a root-owned file in a service user's directory
    /// still fires, as a warning.
    #[test]
    fn root_owned_file_is_warning() {
        let found = MixedOwnershipCheck::mismatches(
            [("/srv/www/app", "wwwrun"), ("/srv/www/app/data", "root")].into_iter(),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Warning, "warning, not error");
        assert!(found[0].1.contains("\"root\""), "{}", found[0].1);
    }

    #[test]
    fn numeric_root_file_is_warning() {
        let found = MixedOwnershipCheck::mismatches(
            [("/srv/www/app", "wwwrun"), ("/srv/www/app/data", "0")].into_iter(),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Warning, "warning, not error");
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

    /// `mismatches` must follow the package's file order. Each call builds its
    /// own `HashMap`, so a hash-order implementation renders differently
    /// between calls and this fails.
    #[test]
    fn mismatches_follow_file_order() {
        // Parents must be in the package too: an unpackaged parent is skipped.
        let files: &[(&str, &str)] = &[
            ("/srv/a", "tftp"),
            ("/srv/a/one", "lp"),
            ("/srv/b", "tftp"),
            ("/srv/b/two", "lp"),
            ("/srv/c", "tftp"),
            ("/srv/c/three", "lp"),
            ("/srv/d", "tftp"),
            ("/srv/d/four", "lp"),
            ("/srv/e", "tftp"),
            ("/srv/e/five", "lp"),
            ("/srv/f", "tftp"),
            ("/srv/f/six", "lp"),
        ];
        let render = || {
            MixedOwnershipCheck::mismatches(files.iter().copied())
                .into_iter()
                .map(|m| m.1.split('"').nth(1).unwrap_or("").to_string())
                .collect::<Vec<_>>()
        };
        let first = render();
        assert_eq!(
            first,
            vec![
                "/srv/a/one",
                "/srv/b/two",
                "/srv/c/three",
                "/srv/d/four",
                "/srv/e/five",
                "/srv/f/six",
            ]
        );
        // Two independently built maps, 12 times: hash order would permute.
        for _ in 0..12 {
            assert_eq!(render(), first);
        }
    }
}
