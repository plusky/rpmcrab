//! The check interface and registry.
//!
//! Checks are keyed by the exact Python module name (`FilesCheck`,
//! `TagsCheck`, …) so a TOML `Checks = [...]` list resolves unchanged
//! (`docs/DESIGN.md` §7.2). The trait mirrors rpmlint's `AbstractCheck`:
//! `check` dispatches on `is_source`, `check_spec` runs for `.spec` inputs,
//! and a check may also run `after_checks` once the last package has been
//! checked, plus `reset` between packages.
//!
//! A configured check that is not implemented yet is **skipped**, not an
//! error: the run still reports the configured check count in the header while
//! the checks land wave by wave (§8).

use crate::config::Config;
use crate::filter::Filter;
use crate::finding::Finding;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::spec::SpecPkg;

/// `Filter.add_info(level, package, rpmlint_issue, *details)`: the finding a
/// check emits, with the package context filled in the way `filter.py:121-156`
/// derives it. Empty details are dropped and each kept detail is prefixed with
/// one space.
///
/// `line` is `package.current_linenum`, which only the `.spec` checks set; a
/// binary finding carries no line, so it is `None` here.
pub fn add_info(out: &mut Filter, level: Level, pkg: &Pkg, check: &str, details: &[&str]) {
    add_info_at(out, level, pkg, None, check, details)
}

/// [`add_info`] with an explicit spec line number, for the `.spec` checks that
/// report the line they are looking at.
pub fn add_info_at(
    out: &mut Filter,
    level: Level,
    pkg: &Pkg,
    line: Option<u32>,
    check: &str,
    details: &[&str],
) {
    out.add_info(Finding {
        level,
        check: check.to_string(),
        details: details.iter().map(|d| (*d).to_string()).collect(),
        // Scoring decides the real badness at emit time (`Filter::add_info`).
        badness: 0,
        // `Path(package.name).name`: the header NAME, not the path we were
        // handed, so a findings block never leaks the working directory.
        pkg_name: basename(&pkg.name).to_string(),
        arch: (!pkg.arch.is_empty()).then(|| pkg.arch.clone()),
        line,
    });
}

/// [`add_info`] for `.spec` inputs: the file part is the spec's basename and
/// there is no arch suffix (the reference's `FakePkg` has `arch = None`,
/// `filter.py:164-166`).
pub fn spec_add_info(
    out: &mut Filter,
    level: Level,
    pkg: &SpecPkg,
    line: Option<u32>,
    check: &str,
    details: &[&str],
) {
    out.add_info(Finding {
        level,
        check: check.to_string(),
        details: details.iter().map(|d| (*d).to_string()).collect(),
        // Scoring decides the real badness at emit time (`Filter::add_info`).
        badness: 0,
        // `Path(package.name).name`, as for binary findings.
        pkg_name: basename(&pkg.name).to_string(),
        arch: None,
        line,
    });
}

/// `PurePath(name).name` — rpmlint prints the basename of the package name.
fn basename(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// A lint check. Ported from the Python module of the same name.
pub trait Check {
    /// The check's registry name (the Python module name, e.g. `FilesCheck`).
    fn name(&self) -> &'static str;

    /// `AbstractCheck.check`: dispatch on whether the package is a source
    /// package. Both hooks default to doing nothing, like the reference.
    fn check(&mut self, pkg: &Pkg, config: &Config, out: &mut Filter) {
        if pkg.is_source {
            self.check_source(pkg, config, out);
        } else {
            self.check_binary(pkg, config, out);
        }
    }

    /// `AbstractCheck.check_source`.
    fn check_source(&mut self, _pkg: &Pkg, _config: &Config, _out: &mut Filter) {}

    /// `AbstractCheck.check_binary`.
    fn check_binary(&mut self, _pkg: &Pkg, _config: &Config, _out: &mut Filter) {}

    /// `AbstractCheck.check_spec`, for `.spec` inputs. Dispatched on the lint
    /// loop holding a `SpecPkg`, not on `is_source` — like the reference,
    /// which dispatches it on holding a `FakePkg`.
    fn check_spec(&mut self, _pkg: &SpecPkg, _config: &Config, _out: &mut Filter) {}

    /// `AbstractCheck.after_checks`, run once after the last package so a check
    /// can report on the whole run (`PostCheck`).
    fn after_checks(&mut self, _config: &Config, _out: &mut Filter) {}

    /// `AbstractCheck.reset`, run between packages so per-run state does not
    /// leak into the next one.
    fn reset(&mut self) {}

    /// `AbstractFilesCheck.checked_files`, reported by the `-t` time report.
    /// `None` for a check that does not walk files.
    fn checked_files(&self) -> Option<usize> {
        None
    }
}

/// Build a check from its exact Python module name, or `None` when it is not
/// implemented yet. The waves in `docs/DESIGN.md` §8 add their arms here.
pub fn build(name: &str, config: &Config) -> Option<Box<dyn Check>> {
    match name {
        "TagsCheck" => Some(Box::new(crate::checks::tags::TagsCheck::new(config))),
        "FilesCheck" => Some(Box::new(crate::checks::files::FilesCheck::new(config))),
        "SpecCheck" => Some(Box::new(crate::checks::spec::SpecCheck::new(config))),
        "BinariesCheck" => Some(Box::new(crate::checks::binaries::BinariesCheck::new(
            config,
        ))),
        _ => None,
    }
}

/// `Lint.load_checks`: the configured `Checks` list in order, deduplicated by
/// name and narrowed by `--checks` when that is given.
pub fn load(config: &Config, selected: Option<&str>) -> Vec<Box<dyn Check>> {
    load_with(config, selected, |name| build(name, config))
}

/// [`load`] with an injectable factory, so the ordering, deduplication and
/// `--checks` narrowing are testable before any real check exists.
pub fn load_with(
    config: &Config,
    selected: Option<&str>,
    mut make: impl FnMut(&str) -> Option<Box<dyn Check>>,
) -> Vec<Box<dyn Check>> {
    let selected: Vec<&str> = selected.map(|s| s.split(',').collect()).unwrap_or_default();
    let mut built: Vec<Box<dyn Check>> = Vec::new();
    for name in &config.checks {
        if built.iter().any(|c| c.name() == name.as_str()) {
            continue;
        }
        if !selected.is_empty() && !selected.contains(&name.as_str()) {
            continue;
        }
        if let Some(check) = make(name) {
            built.push(check);
        }
    }
    built
}

/// A check that emits a fixed set of findings. Proves the report pipeline
/// byte-for-byte without any RPM parsing; the real checks replace it.
pub struct SyntheticCheck {
    name: &'static str,
    pkg_name: String,
    arch: Option<String>,
    findings: Vec<(Level, &'static str, Vec<String>)>,
}

impl SyntheticCheck {
    pub fn new(
        name: &'static str,
        pkg_name: &str,
        arch: Option<&str>,
        findings: Vec<(Level, &'static str, Vec<String>)>,
    ) -> Self {
        Self {
            name,
            pkg_name: pkg_name.to_string(),
            arch: arch.map(str::to_string),
            findings,
        }
    }
}

impl Check for SyntheticCheck {
    fn name(&self) -> &'static str {
        self.name
    }

    fn check_binary(&mut self, _pkg: &Pkg, _config: &Config, out: &mut Filter) {
        for (level, check, details) in &self.findings {
            out.add_info(Finding {
                level: *level,
                check: (*check).to_string(),
                details: details.clone(),
                badness: 0,
                pkg_name: self.pkg_name.clone(),
                arch: self.arch.clone(),
                line: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(names: &[&str]) -> Config {
        Config {
            checks: names.iter().map(|n| (*n).to_string()).collect(),
            ..Config::default()
        }
    }

    fn always(_name: &str) -> Option<Box<dyn Check>> {
        None
    }

    #[test]
    fn load_keeps_configured_order_and_drops_unknown_names() {
        let config = cfg_with(&["TagsCheck", "NotYetPorted", "FilesCheck"]);
        let built = load_with(&config, None, |name| match name {
            "TagsCheck" => Some(
                Box::new(SyntheticCheck::new("TagsCheck", "p", None, vec![])) as Box<dyn Check>,
            ),
            "FilesCheck" => Some(
                Box::new(SyntheticCheck::new("FilesCheck", "p", None, vec![])) as Box<dyn Check>,
            ),
            _ => None,
        });
        let names: Vec<&str> = built.iter().map(|c| c.name()).collect();
        assert_eq!(names, vec!["TagsCheck", "FilesCheck"]);
    }

    #[test]
    fn load_deduplicates_a_repeated_name() {
        let config = cfg_with(&["FilesCheck", "FilesCheck", "TagsCheck"]);
        let built = load_with(&config, None, |name| {
            Some(Box::new(SyntheticCheck::new(
                match name {
                    "FilesCheck" => "FilesCheck",
                    _ => "TagsCheck",
                },
                "p",
                None,
                vec![],
            )) as Box<dyn Check>)
        });
        let names: Vec<&str> = built.iter().map(|c| c.name()).collect();
        assert_eq!(names, vec!["FilesCheck", "TagsCheck"]);
    }

    #[test]
    fn load_narrows_to_the_requested_checks() {
        let config = cfg_with(&["TagsCheck", "FilesCheck", "SpecCheck"]);
        let built = load_with(&config, Some("FilesCheck"), |name| {
            Some(Box::new(SyntheticCheck::new(
                match name {
                    "TagsCheck" => "TagsCheck",
                    "FilesCheck" => "FilesCheck",
                    _ => "SpecCheck",
                },
                "p",
                None,
                vec![],
            )) as Box<dyn Check>)
        });
        let names: Vec<&str> = built.iter().map(|c| c.name()).collect();
        assert_eq!(names, vec!["FilesCheck"]);
    }

    /// An unknown `--checks` value selects nothing rather than everything, and
    /// an unimplemented module is skipped instead of failing the run.
    #[test]
    fn load_with_nothing_implemented_is_empty() {
        let config = cfg_with(&["FilesCheck", "NotYetPorted"]);
        assert!(load_with(&config, None, always).is_empty());
    }

    /// `TagsCheck` is implemented: `load` builds it from the config.
    #[test]
    fn load_builds_tags_check() {
        let config = cfg_with(&["TagsCheck", "FilesCheck"]);
        let built = load(&config, None);
        let names: Vec<&str> = built.iter().map(|c| c.name()).collect();
        assert_eq!(names, vec!["TagsCheck", "FilesCheck"]);
    }

    #[test]
    fn basename_takes_the_last_path_segment() {
        assert_eq!(basename("llvm21-gold"), "llvm21-gold");
        assert_eq!(basename("/srv/rpms/llvm21-gold.rpm"), "llvm21-gold.rpm");
        assert_eq!(basename(""), "");
    }
}

#[cfg(test)]
mod add_info_tests {
    use super::*;
    use crate::config::Config;

    /// A package built from a header is the only realistic `add_info` input, so
    /// the helper is pinned against a real one.
    fn corpus() -> Pkg {
        let rpm = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm");
        let header = librpm::PackageHeader::from_file(
            &rpm,
            Some(&librpm::verify::VerifyOptions::skip_verification()),
        )
        .expect("open corpus header");
        Pkg::installed(header).expect("build installed package")
    }

    /// The finding's package context comes from the header, not from a path, so
    /// a findings block never leaks the working directory.
    #[test]
    fn add_info_takes_the_package_name_from_the_header() {
        let pkg = corpus();
        let config = Config::default();
        let mut out = Filter::new(&config, crate::color::Color::for_tty(false)).unwrap();
        add_info(&mut out, Level::Error, &pkg, "some-finding", &[]);
        let results = out.results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "some-finding");
        assert!(
            results[0]
                .1
                .starts_with("llvm21-gold.aarch64: E: some-finding"),
            "line: {}",
            results[0].1
        );
    }

    /// `filter.py:152-155`: each non-empty detail gets one leading space, and an
    /// empty detail contributes nothing.
    #[test]
    fn add_info_joins_details_with_a_single_space_and_skips_empties() {
        let pkg = corpus();
        let config = Config::default();
        let mut out = Filter::new(&config, crate::color::Color::for_tty(false)).unwrap();
        add_info(
            &mut out,
            Level::Warning,
            &pkg,
            "no-soname",
            &["/usr/lib64/libfoo.so", "", "detail two"],
        );
        let line = &out.results()[0].1;
        assert!(
            line.contains(": W: no-soname /usr/lib64/libfoo.so detail two"),
            "{line}"
        );
        assert!(!line.contains("  "), "no double space: {line}");
    }

    /// An empty package name and arch render no prefix parts, matching
    /// `filter.py:150-151` where both are falsy.
    #[test]
    fn add_info_handles_an_empty_name_and_arch() {
        let mut pkg = corpus();
        pkg.name = String::new();
        pkg.arch = String::new();
        let config = Config::default();
        let mut out = Filter::new(&config, crate::color::Color::for_tty(false)).unwrap();
        add_info(&mut out, Level::Error, &pkg, "no-name", &[]);
        assert_eq!(out.results()[0].1, ": E: no-name");
    }

    /// A path-shaped package name is reduced to its basename, as
    /// `Path(package.name).name` does.
    #[test]
    fn add_info_reduces_a_path_shaped_name_to_its_basename() {
        let mut pkg = corpus();
        pkg.name = "/srv/rpms/weird.rpm".to_string();
        let config = Config::default();
        let mut out = Filter::new(&config, crate::color::Color::for_tty(false)).unwrap();
        add_info(&mut out, Level::Error, &pkg, "odd-name", &[]);
        assert!(
            out.results()[0].1.starts_with("weird.rpm.aarch64:"),
            "{}",
            out.results()[0].1
        );
    }
}
