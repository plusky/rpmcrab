//! `PythonCheck` — Python packaging checks.
//!
//! Ported from `rpmlint/checks/PythonCheck.py`. Findings:
//! `python-doc-in-package`, `python-sphinx-doctrees-leftover`,
//! `python-egg-info-distutils-style`, `python-tests-in-site-packages`,
//! `python-doc-in-site-packages`, `python-src-in-site-packages`,
//! `python-pyc-multiple-versions`, `python-missing-require`,
//! `python-leftover-require`.
//!
//! Requirement metadata is read from `egg-info/requires.txt` or
//! `dist-info/METADATA` natively (no `importlib.metadata`); environment
//! markers are evaluated for the common `python_version` / `sys_platform`
//! cases.

use std::path::Path;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct PythonCheck {
    pyc_version: Option<String>,
    checked_files: usize,
}

/// A parsed requirement: distribution name, environment marker, extras.
struct Requirement {
    name: String,
    marker: Option<String>,
    extras: Vec<String>,
}

impl PythonCheck {
    /// Fallback `python_version` marker value (the reference uses the
    /// interpreter running rpmlint; the port has no interpreter to ask).
    const DEFAULT_PYTHON: &'static str = "3.12";

    pub fn new(_config: &Config) -> Self {
        Self {
            pyc_version: None,
            checked_files: 0,
        }
    }

    fn sitelib_pattern() -> &'static str {
        r"/usr/lib[^/]*/python([^/]*)/site-packages"
    }

    /// `(regex, key)` for warning paths.
    fn warn_paths() -> Vec<(Regex, &'static str)> {
        vec![
            (
                Regex::new(&format!("{}/[^/]+/docs?$", Self::sitelib_pattern())).expect("static"),
                "doc",
            ),
            (Regex::new(r".*/\.doctrees$").expect("static"), "sphinx"),
        ]
    }

    /// `(regex, key)` for error paths.
    fn err_paths() -> Vec<(Regex, &'static str)> {
        vec![
            (
                Regex::new(&format!("{}/tests?$", Self::sitelib_pattern())).expect("static"),
                "tests",
            ),
            (
                Regex::new(&format!("{}/docs?$", Self::sitelib_pattern())).expect("static"),
                "doc",
            ),
            (
                Regex::new(&format!("{}/src$", Self::sitelib_pattern())).expect("static"),
                "src",
            ),
        ]
    }

    /// Name variants: the name itself plus `-`/`_` swaps, plus
    /// `name-extra` variants for each extra (reference `_module_names`).
    fn module_names(name: &str, extras: &[String]) -> Vec<String> {
        let mut out = vec![
            name.to_string(),
            name.replace('-', "_"),
            name.replace('_', "-"),
        ];
        for extra in extras {
            out.extend(Self::module_names(&format!("{name}-{extra}"), &[]));
        }
        out
    }

    /// One parsed requirement: name, environment marker, extras.
    fn parse_requirements(
        content: &str,
        is_metadata: bool,
        python_version: &str,
    ) -> Vec<Requirement> {
        let mut out = Vec::new();
        let mut section: Option<String> = None;
        for line in content.lines() {
            let line = line.trim();
            if is_metadata {
                if line.starts_with("Requires-Dist:") {
                    let req = line
                        .strip_prefix("Requires-Dist:")
                        .unwrap_or(line)
                        .trim()
                        .to_string();
                    out.push(Self::split_marker(&req));
                }
                continue;
            }
            // requires.txt: sections like `[section]`, `[section:marker]`,
            // or `[:marker]`. The reference (`importlib.metadata`) synthesizes
            // `extra == "<section>"` markers for named sections.
            if line.starts_with('[') && line.ends_with(']') {
                let inner = &line[1..line.len() - 1];
                section = Some(inner.to_string());
                continue;
            }
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Skip section-gated requirements with unmet markers.
            if let Some(sec) = &section
                && sec.starts_with(':')
                && !Self::marker_holds(&sec[1..], python_version)
            {
                continue;
            }
            let mut req = Self::split_marker(line);
            // Synthesize `extra == "<section>"` for named sections, matching
            // `importlib.metadata`: `[extra]` → `extra == "extra"`,
            // `[extra:marker]` → `(marker) and extra == "extra"`.
            if let Some(sec) = &section
                && !sec.starts_with(':')
            {
                let (name, marker) = match sec.split_once(':') {
                    Some((n, m)) => (n, Some(m)),
                    None => (sec.as_str(), None),
                };
                let extra_marker = format!("extra == \"{name}\"");
                req.marker = match (&req.marker, marker) {
                    (Some(existing), Some(m)) => {
                        Some(format!("({m}) and ({existing}) and {extra_marker}"))
                    }
                    (Some(existing), None) => Some(format!("({existing}) and {extra_marker}")),
                    (None, Some(m)) => Some(format!("({m}) and {extra_marker}")),
                    (None, None) => Some(extra_marker),
                };
            }
            out.push(req);
        }
        out
    }

    /// Split `name[extras]; marker` into its parts, stripping version
    /// specifiers: `foo[bar]>=1.0` -> name `foo`, extras `["bar"]`.
    fn split_marker(req: &str) -> Requirement {
        let mut parts = req.splitn(2, ';');
        let name = parts.next().unwrap_or("").trim();
        let (name, extras) = match name.split_once('[') {
            Some((n, rest)) => {
                let extras = rest
                    .trim_end_matches(']')
                    .split(',')
                    .map(|e| e.trim().to_string())
                    .filter(|e| !e.is_empty())
                    .collect();
                (n, extras)
            }
            None => (name, Vec::new()),
        };
        let name = name
            .split(|c| "<>=!~ [(,".contains(c))
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let marker = parts.next().map(|m| m.trim().to_string());
        Requirement {
            name,
            marker,
            extras,
        }
    }

    /// Evaluate the common environment markers. Unknown markers are treated
    /// as holding (the reference evaluates the full PEP 508 environment; we
    /// cover `python_version`, `sys_platform`, and `extra`).
    fn marker_holds(marker: &str, python_version: &str) -> bool {
        let marker = marker.trim();
        // `extra == "..."` means an optional dependency: skip it.
        if marker.contains("extra") {
            return false;
        }
        // python_version comparisons, e.g. `python_version < "3.10"`.
        let pv_re = Regex::new(r#"python_version\s*(==|!=|<=|>=|<|>)\s*["']([\d.]+)["']"#)
            .expect("static regex");
        if let Some(caps) = pv_re.captures(marker).ok().flatten() {
            let op = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let want = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let cmp = compare_versions(python_version, want);
            return match op {
                "==" => cmp == 0,
                "!=" => cmp != 0,
                "<" => cmp < 0,
                "<=" => cmp <= 0,
                ">" => cmp > 0,
                ">=" => cmp >= 0,
                _ => true,
            };
        }
        // sys_platform, e.g. `sys_platform != "win32"`.
        if marker.contains("sys_platform") {
            // We are always on Linux here.
            return !marker.contains("win32") || marker.contains("!=");
        }
        true
    }

    /// The `python_version` marker environment, mirroring the reference:
    /// the `python(abi)` require's version wins over the default, and the
    /// version embedded in the dist-info/egg-info path wins over that.
    fn marker_python_version(requires: &[crate::pkg::dep::DepInfo], filename: &str) -> String {
        let mut version = Self::DEFAULT_PYTHON.to_string();
        if let Some(abi) = requires.iter().find(|r| r.name == "python(abi)")
            && let Some(v) = abi.version.as_deref()
        {
            version = v.to_string();
        }
        let sitelib_re = Regex::new(Self::sitelib_pattern()).expect("static regex");
        if let Some(caps) = sitelib_re.captures(filename).ok().flatten()
            && let Some(v) = caps.get(1)
        {
            version = v.as_str().to_string();
        }
        version
    }

    /// Whether an RPM require satisfies a Python requirement name.
    fn require_satisfied(req_names: &[String], req: &Requirement) -> bool {
        let mut names = Self::module_names(&req.name, &req.extras);
        // pythonX-foo variants
        for n in Self::module_names(&req.name, &req.extras) {
            names.push(format!("python\\d*-{}", fancy_regex::escape(&n)));
        }
        // python3.12dist(foo) variants
        for n in Self::module_names(&req.name, &req.extras) {
            names.push(format!(
                r"python\d+(\.\d+)?dist\({}\)",
                fancy_regex::escape(&n)
            ));
        }
        let pattern = format!(
            r"(?i)^\(?({})(\s*(==|<|<=|>|>=)\s*[\w.]+\s*)?(\s+(and|or|if|unless|else|with|without)\s+.*)?\)?\s*$",
            names.join("|")
        );
        let Ok(re) = Regex::new(&pattern) else {
            return false;
        };
        req_names.iter().any(|r| is_match(&re, r))
    }
}

/// Compare dotted versions: -1, 0, 1.
fn compare_versions(a: &str, b: &str) -> i32 {
    let pa: Vec<u64> = a.split('.').filter_map(|p| p.parse().ok()).collect();
    let pb: Vec<u64> = b.split('.').filter_map(|p| p.parse().ok()).collect();
    for i in 0..pa.len().max(pb.len()) {
        let x = pa.get(i).copied().unwrap_or(0);
        let y = pb.get(i).copied().unwrap_or(0);
        if x != y {
            return if x < y { -1 } else { 1 };
        }
    }
    0
}

impl Check for PythonCheck {
    fn name(&self) -> &'static str {
        "PythonCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        self.pyc_version = None;
        let egg_info_re = Regex::new(r".*egg-info$").expect("static regex");
        let pyc_re = Regex::new(r"cpython-(\d+)").expect("static regex");
        let file_names: Vec<&str> = pkg.files.iter().map(|f| f.name.as_str()).collect();

        for pkgfile in &pkg.files {
            let filename = pkgfile.name.as_str();

            // AbstractCheck.py:45 drops ghosts from the dispatch list, and
            // files_re is `.*` here, so this is the only filter: a ghost
            // site-packages tests/ or doc/ directory is never inspected.
            if pkg.ghost_files.iter().any(|g| g == &pkgfile.name) {
                continue;
            }
            self.checked_files += 1;

            if filename.ends_with("egg-info/requires.txt") {
                let content = pkg.read_file(filename);
                let python_version = Self::marker_python_version(&pkg.requires, filename);
                let reqs = Self::parse_requirements(&content, false, &python_version);
                self.check_requirements(pkg, out, &reqs, &python_version);
                continue;
            }
            if filename.ends_with("dist-info/METADATA") {
                let content = pkg.read_file(filename);
                let python_version = Self::marker_python_version(&pkg.requires, filename);
                let reqs = Self::parse_requirements(&content, true, &python_version);
                self.check_requirements(pkg, out, &reqs, &python_version);
                continue;
            }
            if is_match(&egg_info_re, filename) {
                // The legacy distutils layout is a plain file named
                // `*.egg-info`; the reference flags it with `is_file()`.
                let full = Path::new(pkg.dir_name()).join(filename.trim_start_matches('/'));
                if full.is_file() {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "python-egg-info-distutils-style",
                        &[filename],
                    );
                }
                continue;
            }

            for (re, key) in Self::warn_paths() {
                if is_match(&re, filename) {
                    if key == "doc" {
                        let module_file = format!("{filename}/__init__.py");
                        if file_names.contains(&module_file.as_str()) {
                            continue;
                        }
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "python-doc-in-package",
                            &[filename],
                        );
                    } else {
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "python-sphinx-doctrees-leftover",
                            &[filename],
                        );
                    }
                }
            }
            for (re, key) in Self::err_paths() {
                if is_match(&re, filename) {
                    let finding = match key {
                        "tests" => "python-tests-in-site-packages",
                        "doc" => "python-doc-in-site-packages",
                        _ => "python-src-in-site-packages",
                    };
                    add_info(out, Level::Error, pkg, finding, &[filename]);
                }
            }

            if filename.ends_with(".pyc")
                && let Some(caps) = pyc_re.captures(filename).ok().flatten()
            {
                let version = caps.get(1).map(|m| m.as_str().to_string());
                match (&self.pyc_version, version) {
                    (None, Some(v)) => self.pyc_version = Some(v),
                    (Some(expected), Some(v)) if expected != &v => {
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "python-pyc-multiple-versions",
                            &["expected:", expected, filename],
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    fn reset(&mut self) {
        self.checked_files = 0;
    }

    fn checked_files(&self) -> Option<usize> {
        Some(self.checked_files)
    }
}

impl PythonCheck {
    /// Check parsed requirements against the RPM requires.
    fn check_requirements(
        &self,
        pkg: &Pkg,
        out: &mut Filter,
        reqs: &[Requirement],
        python_version: &str,
    ) {
        // The reference returns early when the distribution declares no
        // requirements; without the guard every pythonX-* require would be
        // reported as leftover.
        if reqs.is_empty() {
            return;
        }
        for req in reqs {
            if req.name.is_empty() {
                continue;
            }
            if let Some(m) = &req.marker
                && !Self::marker_holds(m, python_version)
            {
                continue;
            }
            if !Self::require_satisfied(&pkg.req_names, req) {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "python-missing-require",
                    &[&req.name],
                );
            }
        }

        // Leftover requirements: python-foo in RPM requires with no match.
        let mut wanted: Vec<String> = Vec::new();
        for req in reqs {
            if let Some(m) = &req.marker
                && !Self::marker_holds(m, python_version)
            {
                continue;
            }
            wanted.extend(Self::module_names(&req.name, &req.extras));
        }
        let wanted: Vec<String> = wanted.iter().map(|n| n.to_lowercase()).collect();
        let py_re = Regex::new(r"^python\d*-(?P<name>.+)$").expect("static regex");
        for req in &pkg.req_names {
            let Some(caps) = py_re.captures(req).ok().flatten() else {
                continue;
            };
            let module = caps
                .get(1)
                .map(|m| m.as_str().trim().to_lowercase())
                .unwrap_or_default();
            if module == "base" || module == "devel" {
                continue;
            }
            let variants: Vec<String> = Self::module_names(&module, &[])
                .iter()
                .map(|n| n.to_lowercase())
                .collect();
            if !variants.iter().any(|v| wanted.contains(v)) {
                add_info(out, Level::Warning, pkg, "python-leftover-require", &[req]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_txt_parses_names() {
        let content = "backcall\ndecorator\njedi>=0.16\n";
        let reqs = PythonCheck::parse_requirements(content, false, "3.12");
        assert_eq!(reqs.len(), 3);
        assert_eq!(reqs[0].name, "backcall");
        assert_eq!(reqs[2].name, "jedi");
    }

    #[test]
    fn requires_txt_section_markers_are_respected() {
        // python_version < "3.10" does not hold for 3.12.
        let content = "backcall\n[:python_version < \"3.10\"]\ntyping_extensions\n";
        let reqs = PythonCheck::parse_requirements(content, false, "3.12");
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].name, "backcall");
    }

    #[test]
    fn extra_markers_are_skipped() {
        let content = "foo; extra == \"test\"\nbar\n";
        let reqs = PythonCheck::parse_requirements(content, false, "3.12");
        // `foo` has an extra marker, which marker_holds rejects.
        assert!(reqs.iter().any(|r| r.name == "foo"));
        assert!(!PythonCheck::marker_holds("extra == \"test\"", "3.12"));
    }

    #[test]
    fn metadata_requires_dist_parses() {
        let content = "Metadata-Version: 2.1\nRequires-Dist: requests>=2.0\nRequires-Dist: foo; python_version < \"3.10\"\n";
        let reqs = PythonCheck::parse_requirements(content, true, "3.12");
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].name, "requests");
    }

    #[test]
    fn extras_produce_name_variants() {
        let content = "requests[security]\n";
        let reqs = PythonCheck::parse_requirements(content, false, "3.12");
        assert_eq!(reqs[0].extras, vec!["security".to_string()]);
        let names = PythonCheck::module_names(&reqs[0].name, &reqs[0].extras);
        assert!(names.contains(&"requests-security".to_string()));
        assert!(names.contains(&"requests_security".to_string()));
    }

    #[test]
    fn module_names_include_variants() {
        let names = PythonCheck::module_names("foo-bar", &[]);
        assert!(names.contains(&"foo-bar".to_string()));
        assert!(names.contains(&"foo_bar".to_string()));
    }

    fn requirement(name: &str) -> Requirement {
        Requirement {
            name: name.to_string(),
            marker: None,
            extras: Vec::new(),
        }
    }

    #[test]
    fn require_satisfied_matches_python3_foo() {
        let req_names = vec!["python3-requests".to_string()];
        assert!(PythonCheck::require_satisfied(
            &req_names,
            &requirement("requests")
        ));
        assert!(!PythonCheck::require_satisfied(
            &req_names,
            &requirement("urllib3")
        ));
    }

    #[test]
    fn require_satisfied_matches_dist() {
        let req_names = vec!["python312dist(requests)".to_string()];
        assert!(PythonCheck::require_satisfied(
            &req_names,
            &requirement("requests")
        ));
    }

    #[test]
    fn marker_python_version_prefers_dist_info_path() {
        use crate::pkg::dep::DepInfo;
        let abi = DepInfo {
            name: "python(abi)".to_string(),
            flags: 0,
            epoch: None,
            version: Some("3.11".to_string()),
            release: None,
        };
        // dist-info path beats both the default and a python(abi) require.
        let version = PythonCheck::marker_python_version(
            &[abi],
            "/usr/lib/python3.13/site-packages/foo-1.0.dist-info/METADATA",
        );
        assert_eq!(version, "3.13");
    }

    #[test]
    fn marker_python_version_falls_back_to_abi_require() {
        use crate::pkg::dep::DepInfo;
        let abi = DepInfo {
            name: "python(abi)".to_string(),
            flags: 0,
            epoch: None,
            version: Some("3.11".to_string()),
            release: None,
        };
        let version =
            PythonCheck::marker_python_version(&[abi], "/somewhere/foo-1.0.dist-info/METADATA");
        assert_eq!(version, "3.11");
    }

    #[test]
    fn marker_python_version_defaults() {
        let version =
            PythonCheck::marker_python_version(&[], "/somewhere/foo-1.0.dist-info/METADATA");
        assert_eq!(version, PythonCheck::DEFAULT_PYTHON);
    }

    #[test]
    fn warn_path_doc_matches() {
        let (re, _) = &PythonCheck::warn_paths()[0];
        assert!(is_match(re, "/usr/lib/python3.12/site-packages/foo/doc"));
    }

    #[test]
    fn err_path_tests_matches() {
        let (re, _) = &PythonCheck::err_paths()[0];
        assert!(is_match(re, "/usr/lib64/python3.12/site-packages/tests"));
    }

    fn fixture_pkg_with_requires(req_names: &[&str]) -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.name = "python-test".to_string();
        pkg.arch = "noarch".to_string();
        pkg.req_names = req_names.iter().map(|s| s.to_string()).collect();
        pkg
    }

    fn check_requirements_findings(
        reqs: &[Requirement],
        req_names: &[&str],
    ) -> Vec<(String, String)> {
        use crate::color::Color;
        let pkg = fixture_pkg_with_requires(req_names);
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = PythonCheck {
            pyc_version: None,
            checked_files: 0,
        };
        check.check_requirements(&pkg, &mut out, reqs, "3.12");
        out.results().to_vec()
    }

    #[test]
    fn extra_section_synthesis_prevents_false_missing_require() {
        // Emission-path test: `[extra]` sections in requires.txt must
        // synthesize `extra == "extra"` markers (matching
        // `importlib.metadata`). Without the marker, `w6extra` is treated
        // as a required dependency and falsely reported as missing.
        let content = "[extra]\nw6extra\n";
        let reqs = PythonCheck::parse_requirements(content, false, "3.12");
        assert_eq!(reqs.len(), 1);
        assert_eq!(
            reqs[0].marker.as_deref(),
            Some("extra == \"extra\""),
            "marker: {:?}",
            reqs[0].marker
        );
        // The RPM does NOT require python3-w6extra: no false positive.
        let findings = check_requirements_findings(&reqs, &[]);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn extra_section_with_marker_combines_correctly() {
        // `[extra:marker]` must synthesize the section condition AND
        // `extra == "extra"` in one marker. Exact equality, not `contains`:
        // loose substring checks pass on wrongly parenthesized or reordered
        // combinations that drift from the reference's
        // `(marker) and extra == "extra"` form.
        let content = "[extra:python_version > \"3.8\"]\nw6extra\n";
        let reqs = PythonCheck::parse_requirements(content, false, "3.12");
        assert_eq!(reqs.len(), 1);
        assert_eq!(
            reqs[0].marker.as_deref(),
            Some("(python_version > \"3.8\") and extra == \"extra\""),
            "marker: {:?}",
            reqs[0].marker
        );
        // Emission path: the section condition holds for 3.12, but the
        // synthesized extra marker never does, so `w6extra` must not be
        // reported missing. If the combination dropped the extra part, the
        // false positive would fire here.
        let findings = check_requirements_findings(&reqs, &[]);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }
}
