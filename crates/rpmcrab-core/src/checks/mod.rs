//! The lint checks, keyed by their Python module names (`TagsCheck`, …).

pub mod atomic_update;
pub mod binaries;
pub mod config_files;
pub mod doc;
pub mod duplicates;
pub mod fhs;
pub mod files;
pub mod i18n;
pub mod icon_sizes;
pub mod library_dependency;
pub mod lsb;
pub mod mixed_ownership;
pub mod pam_modules;
pub mod pkg_config;
pub mod shared;
pub mod spec;
pub mod tags;
pub mod xinetd_dep;
pub mod zip;
pub mod zypp_syntax;
/// Match `text` against a `fancy_regex`, logging engine failures.
///
/// `fancy_regex` can fail at match time (e.g. backtracking-limit errors on
/// hostile input); the reference treats an unmatchable pattern as no match,
/// so the error is logged at debug level and reported as no match rather
/// than silently swallowed or panicked on.
pub fn is_match(re: &fancy_regex::Regex, text: &str) -> bool {
    match re.is_match(text) {
        Ok(matched) => matched,
        Err(e) => {
            log::debug!("regex engine error: {e}");
            false
        }
    }
}
