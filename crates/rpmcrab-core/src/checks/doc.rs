//! `DocCheck` — package documentation checks.
//!
//! Ported from `rpmlint/checks/DocCheck.py`. Four findings:
//! `executable-docs` (E), `doc-file-dependency` (W), `install-file-in-docs`
//! (W), `package-with-huge-docs` (W).
//!
//! `package-with-huge-docs` is additionally skipped for package names ending in
//! an `ExemptDocSuffixes` entry (default `-javadoc`): fix-in-port for
//! rpm-software-management/rpmlint#555, whose reference still flags 100%-docs
//! javadoc packages.

use std::collections::{BTreeMap, BTreeSet};

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::dep::RPMSENSE_FIND_REQUIRES;
use crate::pkg::pkgfile::{PkgFile, is_reg};

/// Suffixes that must never be executable in documentation.
const DOC_EXTENSIONS: &[&str] = &[
    ".txt", ".gif", ".jpg", ".html", ".pdf", ".ps", ".pdf.gz", ".ps.gz",
];
/// Basenames that must never be executable in documentation.
const DOC_BASENAMES: &[&str] = &["README", "NEWS", "COPYING", "AUTHORS", "LICENCE", "LICENSE"];

pub struct DocCheck {
    exempt_doc_suffixes: Vec<String>,
}

impl DocCheck {
    pub fn new(config: &Config) -> Self {
        Self {
            exempt_doc_suffixes: Self::exempt_doc_suffixes(config),
        }
    }

    /// `ExemptDocSuffixes` from the configuration. The bundled
    /// `configdefaults.toml` always ships the key. A missing key, or a
    /// non-empty array with no usable strings (mistyped elements), falls back
    /// to the documented default instead of silently disabling the exemption
    /// (mirrors the `BadnessThreshold` code-default pattern). Only an
    /// explicitly empty array disables the exemption.
    fn exempt_doc_suffixes(config: &Config) -> Vec<String> {
        const DEFAULT: &[&str] = &["-javadoc"];
        match config.configuration.get("ExemptDocSuffixes") {
            Some(toml::Value::Array(items)) => {
                let collected: Vec<String> = items
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                if collected.is_empty() && !items.is_empty() {
                    DEFAULT.iter().map(|s| (*s).to_owned()).collect()
                } else {
                    collected
                }
            }
            _ => DEFAULT.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    /// Whether `name` is exempt from the huge-docs finding by configured suffix.
    fn exempt_by_suffix(&self, name: &str) -> bool {
        self.exempt_doc_suffixes
            .iter()
            .any(|suffix| name.ends_with(suffix))
    }

    fn ignore_pkg(name: &str) -> bool {
        name.starts_with("bundle-") || name.contains("-devel") || name.contains("-doc")
    }

    /// Filenames in `doc_files` that are executable docs.
    fn executable_docs<'a>(doc_files: &[&'a str], mode_of: &dyn Fn(&str) -> u32) -> Vec<&'a str> {
        let mut out = Vec::new();
        for f in doc_files {
            let mode = mode_of(f);
            if !is_reg(mode) || mode & 0o111 == 0 {
                continue;
            }
            let lower = f.to_lowercase();
            let suffix_hit = DOC_EXTENSIONS.iter().any(|e| lower.ends_with(e));
            let base = f.rsplit('/').next().unwrap_or(f).to_lowercase();
            let base_hit = DOC_BASENAMES.iter().any(|b| base == b.to_lowercase());
            if suffix_hit || base_hit {
                out.push(*f);
            }
        }
        out
    }

    /// Doc files that introduce dependencies not needed by non-doc files.
    /// Returns `(doc_file, dep)` pairs. `requires_of` maps filename to its
    /// requirement names; `core_provides` are the names that count as core:
    /// provides, all file paths, and explicit package-level requires
    /// (the reference get_core_reqs seeding).
    fn doc_file_dependencies(
        doc_files: &[&str],
        all_files: &[&str],
        requires_of: &dyn Fn(&str) -> Vec<String>,
        core_provides: &BTreeSet<String>,
    ) -> Vec<(String, String)> {
        let mut core_reqs: BTreeSet<String> = core_provides.clone();
        let mut doc_reqs: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for f in all_files {
            let is_doc = doc_files.contains(f);
            for r in requires_of(f) {
                if is_doc {
                    doc_reqs.entry(r).or_default().push(f.to_string());
                } else {
                    core_reqs.insert(r);
                }
            }
        }

        let mut out = Vec::new();
        for (dep, req_files) in &doc_reqs {
            if !core_reqs.contains(dep) {
                for f in req_files {
                    out.push((f.clone(), dep.clone()));
                }
            }
        }
        out
    }

    /// Doc files ending in `/INSTALL`.
    fn install_files<'a>(doc_files: &[&'a str]) -> Vec<&'a str> {
        doc_files
            .iter()
            .filter(|f| f.ends_with("/INSTALL"))
            .copied()
            .collect()
    }

    /// Percentage of the package that is documentation, when huge.
    fn huge_docs_pct(files: &[PkgFile], doc_files: &[&str]) -> Option<u32> {
        let by_name: BTreeMap<&str, &PkgFile> =
            files.iter().map(|f| (f.name.as_str(), f)).collect();
        let complete_size: u64 = files
            .iter()
            .filter(|f| is_reg(f.mode))
            .map(|f| f.size.unwrap_or(0))
            .sum();
        let doc_size: u64 = doc_files
            .iter()
            .filter_map(|n| by_name.get(n))
            .filter(|f| is_reg(f.mode))
            .map(|f| f.size.unwrap_or(0))
            .sum();
        if doc_size * 2 >= complete_size && doc_size > 100 * 1024 && complete_size > 0 {
            Some((doc_size * 100 / complete_size) as u32)
        } else {
            None
        }
    }
}

impl Check for DocCheck {
    fn name(&self) -> &'static str {
        "DocCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.doc_files.is_empty() {
            return;
        }
        let by_name: BTreeMap<&str, &PkgFile> =
            pkg.files.iter().map(|f| (f.name.as_str(), f)).collect();
        let doc_refs: Vec<&str> = pkg.doc_files.iter().map(|s| s.as_str()).collect();

        for f in Self::executable_docs(&doc_refs, &|n| by_name.get(n).map(|p| p.mode).unwrap_or(0))
        {
            add_info(out, Level::Error, pkg, "executable-docs", &[f]);
        }

        let all_refs: Vec<&str> = pkg.files.iter().map(|f| f.name.as_str()).collect();
        let mut core_provides: BTreeSet<String> =
            pkg.provides.iter().map(|d| d.name.clone()).collect();
        for f in &all_refs {
            core_provides.insert(f.to_string());
        }
        // Explicit package-level Requires also cover doc-file deps;
        // skip find-requires-generated entries, like the reference
        // get_core_reqs.
        for d in pkg.requires.iter().chain(&pkg.prereq) {
            if d.flags & RPMSENSE_FIND_REQUIRES == 0 {
                core_provides.insert(d.name.clone());
            }
        }
        for (f, dep) in Self::doc_file_dependencies(
            &doc_refs,
            &all_refs,
            &|n| {
                by_name
                    .get(n)
                    .map(|p| p.requires.iter().map(|d| d.name.clone()).collect())
                    .unwrap_or_default()
            },
            &core_provides,
        ) {
            add_info(out, Level::Warning, pkg, "doc-file-dependency", &[&f, &dep]);
        }

        for f in Self::install_files(&doc_refs) {
            add_info(out, Level::Warning, pkg, "install-file-in-docs", &[f]);
        }

        if !Self::ignore_pkg(&pkg.name)
            && !self.exempt_by_suffix(&pkg.name)
            && let Some(pct) = Self::huge_docs_pct(&pkg.files, &doc_refs)
        {
            add_info(
                out,
                Level::Warning,
                pkg,
                "package-with-huge-docs",
                &[&format!(
                    "{pct}% (documentation should be in a -doc subpackage)"
                )],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode_of(reg_exec: bool) -> u32 {
        if reg_exec { 0o100755 } else { 0o100644 }
    }

    #[test]
    fn executable_txt_is_flagged() {
        let docs = vec!["/usr/share/doc/pkg/README.txt"];
        let found = DocCheck::executable_docs(&docs, &|_| mode_of(true));
        assert_eq!(found, vec!["/usr/share/doc/pkg/README.txt"]);
    }

    #[test]
    fn non_executable_is_quiet() {
        let docs = vec!["/usr/share/doc/pkg/README.txt"];
        let found = DocCheck::executable_docs(&docs, &|_| mode_of(false));
        assert!(found.is_empty());
    }

    #[test]
    fn executable_readme_basename_is_flagged() {
        let docs = vec!["/usr/share/doc/pkg/README"];
        let found = DocCheck::executable_docs(&docs, &|_| mode_of(true));
        assert_eq!(found, vec!["/usr/share/doc/pkg/README"]);
    }

    #[test]
    fn executable_binary_suffix_is_quiet() {
        // `.so` is not in the doc extension list.
        let docs = vec!["/usr/share/doc/pkg/tool.so"];
        let found = DocCheck::executable_docs(&docs, &|_| mode_of(true));
        assert!(found.is_empty());
    }

    #[test]
    fn install_file_is_flagged() {
        assert_eq!(
            DocCheck::install_files(&["/usr/share/doc/pkg/INSTALL"]),
            vec!["/usr/share/doc/pkg/INSTALL"]
        );
        assert!(DocCheck::install_files(&["/usr/share/doc/pkg/README"]).is_empty());
    }

    #[test]
    fn ignore_pkg_names() {
        assert!(DocCheck::ignore_pkg("bundle-foo"));
        assert!(DocCheck::ignore_pkg("foo-devel"));
        assert!(DocCheck::ignore_pkg("foo-doc"));
        assert!(!DocCheck::ignore_pkg("foo"));
    }

    /// `Pkg` is header-backed with no test constructor, so open a tiny fixture
    /// and rewrite the public fields the check reads.
    fn fixture_pkg() -> Pkg {
        use std::path::Path;
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg")
    }

    fn big_doc_file(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            size: Some(200 * 1024),
            ..Default::default()
        }
    }

    /// A package that is 100% documentation over the 100 KiB threshold.
    fn huge_docs_pkg(name: &str) -> Pkg {
        let mut pkg = fixture_pkg();
        pkg.name = name.to_string();
        pkg.arch = "noarch".to_string();
        let doc = format!("/usr/share/doc/{name}/api.html");
        pkg.files = vec![big_doc_file(&doc)];
        pkg.doc_files = vec![doc];
        pkg
    }

    fn config_with_suffixes(suffixes: &[&str]) -> Config {
        let mut table = toml::Table::new();
        table.insert(
            "ExemptDocSuffixes".to_string(),
            toml::Value::Array(
                suffixes
                    .iter()
                    .map(|s| toml::Value::String(s.to_string()))
                    .collect(),
            ),
        );
        Config {
            configuration: table,
            ..Default::default()
        }
    }

    fn run(config: &Config, check: &mut DocCheck, pkg: &Pkg) -> Vec<(String, String)> {
        use crate::color::Color;
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        check.check_binary(pkg, config, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn javadoc_package_with_huge_docs_is_silent() {
        let config = config_with_suffixes(&["-javadoc"]);
        let mut check = DocCheck::new(&config);
        assert!(run(&config, &mut check, &huge_docs_pkg("foo-javadoc")).is_empty());
    }

    #[test]
    fn regular_package_with_huge_docs_warns_with_doc_convention_hint() {
        let config = config_with_suffixes(&["-javadoc"]);
        let mut check = DocCheck::new(&config);
        let results = run(&config, &mut check, &huge_docs_pkg("foo"));
        assert_eq!(results.len(), 1, "expected one finding, got {results:?}");
        assert_eq!(results[0].0, "package-with-huge-docs");
        assert_eq!(
            results[0].1,
            "foo.noarch: W: package-with-huge-docs 100% (documentation should be in a -doc subpackage)"
        );
    }

    #[test]
    fn exempt_suffixes_are_configurable() {
        // An empty list disables the exemption: the javadoc package warns again.
        let config = config_with_suffixes(&[]);
        let mut check = DocCheck::new(&config);
        let results = run(&config, &mut check, &huge_docs_pkg("foo-javadoc"));
        assert_eq!(results.len(), 1, "expected one finding, got {results:?}");
        assert_eq!(results[0].0, "package-with-huge-docs");
    }

    #[test]
    fn custom_suffix_exempts_matching_names_only() {
        // "-apidoc" chosen deliberately: it does not contain "-doc", so the
        // pre-existing ignore_pkg() cannot mask the suffix exemption.
        let config = config_with_suffixes(&["-apidoc"]);
        let mut check = DocCheck::new(&config);
        assert!(run(&config, &mut check, &huge_docs_pkg("foo-apidoc")).is_empty());
        assert_eq!(
            run(&config, &mut check, &huge_docs_pkg("foo-javadoc")).len(),
            1
        );
    }

    #[test]
    fn mistyped_elements_fall_back_to_javadoc_default() {
        // A non-empty array with no usable strings is mistyped, not an
        // explicit opt-out: the exemption keeps working on the default.
        let mut table = toml::Table::new();
        table.insert(
            "ExemptDocSuffixes".to_string(),
            toml::Value::Array(vec![toml::Value::Integer(5)]),
        );
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let mut check = DocCheck::new(&config);
        assert!(run(&config, &mut check, &huge_docs_pkg("foo-javadoc")).is_empty());
    }

    /// NsCDE-doc shape: every file is documentation, and one doc file
    /// carries a per-file require (`/bin/ksh`) that no non-doc file and no
    /// package provide covers.
    fn doc_dep_pkg(cover_dep: bool) -> Pkg {
        use crate::pkg::dep::parse_dep_infos;
        let mut pkg = fixture_pkg();
        pkg.name = "nscde".to_string();
        pkg.arch = "noarch".to_string();
        let mut nitro = big_doc_file("/usr/share/doc/NsCDE-doc/nitrowrapper");
        nitro.size = Some(1024);
        nitro.requires = parse_dep_infos("/bin/ksh");
        let mut readme = big_doc_file("/usr/share/doc/NsCDE-doc/README");
        readme.size = Some(1024);
        let nitro_name = nitro.name.clone();
        let readme_name = readme.name.clone();
        if cover_dep {
            // A non-doc file with the same require covers the dep.
            let mut tool = big_doc_file("/usr/bin/nitrowrapper");
            tool.size = Some(1024);
            tool.requires = parse_dep_infos("/bin/ksh");
            pkg.files = vec![nitro, readme, tool];
            pkg.doc_files = vec![nitro_name, readme_name];
        } else {
            pkg.files = vec![nitro, readme];
            pkg.doc_files = vec![nitro_name, readme_name];
        }
        pkg
    }

    #[test]
    fn doc_file_with_unique_per_file_require_is_flagged() {
        let config = Config::default();
        let mut check = DocCheck::new(&config);
        let results = run(&config, &mut check, &doc_dep_pkg(false));
        assert_eq!(results.len(), 1, "expected one finding, got {results:?}");
        assert_eq!(results[0].0, "doc-file-dependency");
        assert!(
            results[0]
                .1
                .contains("/usr/share/doc/NsCDE-doc/nitrowrapper"),
            "line: {}",
            results[0].1
        );
        assert!(results[0].1.contains("/bin/ksh"), "line: {}", results[0].1);
    }

    #[test]
    fn doc_file_require_covered_by_non_doc_file_is_quiet() {
        let config = Config::default();
        let mut check = DocCheck::new(&config);
        let results = run(&config, &mut check, &doc_dep_pkg(true));
        assert!(results.is_empty(), "expected no findings, got {results:?}");
    }

    /// A doc file whose per-file dep is also an explicit package Requires
    /// stays quiet: the reference seeds such requires into core_reqs
    /// (get_core_reqs), so the port must not fire doc-file-dependency.
    /// Adversarial twin: a find-requires-generated package require does
    /// NOT cover the dep, so the finding still fires.
    fn doc_dep_pkg_with_package_require(flags: u32) -> Pkg {
        use crate::pkg::dep::DepInfo;
        let mut pkg = doc_dep_pkg(false);
        pkg.requires.push(DepInfo {
            name: "/bin/ksh".to_string(),
            flags,
            epoch: None,
            version: None,
            release: None,
        });
        pkg
    }

    #[test]
    fn doc_file_require_covered_by_explicit_package_require_is_quiet() {
        let config = Config::default();
        let mut check = DocCheck::new(&config);
        let results = run(&config, &mut check, &doc_dep_pkg_with_package_require(0));
        assert!(results.is_empty(), "expected no findings, got {results:?}");
    }

    #[test]
    fn doc_file_require_covered_only_by_find_requires_require_still_fires() {
        let config = Config::default();
        let mut check = DocCheck::new(&config);
        let results = run(
            &config,
            &mut check,
            &doc_dep_pkg_with_package_require(RPMSENSE_FIND_REQUIRES),
        );
        assert_eq!(results.len(), 1, "expected one finding, got {results:?}");
        assert_eq!(results[0].0, "doc-file-dependency");
    }

    #[test]
    fn missing_key_falls_back_to_javadoc_default() {
        // A bare Config with no ExemptDocSuffixes key still exempts -javadoc.
        let config = Config::default();
        let mut check = DocCheck::new(&config);
        assert!(run(&config, &mut check, &huge_docs_pkg("foo-javadoc")).is_empty());
    }
}
