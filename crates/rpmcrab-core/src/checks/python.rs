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
}

impl PythonCheck {
    pub fn new(_config: &Config) -> Self {
        Self { pyc_version: None }
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

    /// Name variants: the name itself plus `-`/`_` swaps.
    fn module_names(name: &str) -> Vec<String> {
        vec![
            name.to_string(),
            name.replace('-', "_"),
            name.replace('_', "-"),
        ]
    }

    /// Parse requirement names from `requires.txt` or `METADATA`
    /// (`Requires-Dist` lines). Markers after `;` are kept for evaluation.
    fn parse_requirements(content: &str, is_metadata: bool) -> Vec<(String, Option<String>)> {
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
            // requires.txt: sections like `[section]` or `[:marker]`
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
                && !Self::marker_holds(&sec[1..])
            {
                continue;
            }
            out.push(Self::split_marker(line));
        }
        out
    }

    /// Split `name; marker` into `(name-with-extras-stripped, marker)`.
    fn split_marker(req: &str) -> (String, Option<String>) {
        let mut parts = req.splitn(2, ';');
        let name = parts.next().unwrap_or("").trim();
        // Strip version specifiers and extras: `foo[bar]>=1.0` -> `foo`.
        let name = name
            .split(|c| "<>=!~ [(,".contains(c))
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let marker = parts.next().map(|m| m.trim().to_string());
        (name, marker)
    }

    /// Evaluate the common environment markers. Unknown markers are treated
    /// as holding (the reference evaluates the full PEP 508 environment; we
    /// cover `python_version`, `sys_platform`, and `extra`).
    fn marker_holds(marker: &str) -> bool {
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
            // Current runtime Python version is unknown; use 3.x comparison
            // on the major.minor prefix. We approximate with "3.12".
            const HAVE: &str = "3.12";
            let cmp = compare_versions(HAVE, want);
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

    /// Whether an RPM require satisfies a Python requirement name.
    fn require_satisfied(req_names: &[String], module: &str) -> bool {
        let mut names = Self::module_names(module);
        // pythonX-foo variants
        for n in Self::module_names(module) {
            names.push(format!("python\\d*-{}", fancy_regex::escape(&n)));
        }
        // python3.12dist(foo) variants
        for n in Self::module_names(module) {
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

            if filename.ends_with("egg-info/requires.txt") {
                let content = pkg.read_file(filename);
                let reqs = Self::parse_requirements(&content, false);
                self.check_requirements(pkg, out, &reqs);
                continue;
            }
            if filename.ends_with("dist-info/METADATA") {
                let content = pkg.read_file(filename);
                let reqs = Self::parse_requirements(&content, true);
                self.check_requirements(pkg, out, &reqs);
                continue;
            }
            if is_match(&egg_info_re, filename) {
                // Distutils-style egg-info is a directory on disk.
                let full = Path::new(pkg.dir_name()).join(filename.trim_start_matches('/'));
                if full.is_dir() {
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
}

impl PythonCheck {
    /// Check parsed requirements against the RPM requires.
    fn check_requirements(&self, pkg: &Pkg, out: &mut Filter, reqs: &[(String, Option<String>)]) {
        for (name, marker) in reqs {
            if name.is_empty() {
                continue;
            }
            if let Some(m) = marker
                && !Self::marker_holds(m)
            {
                continue;
            }
            if !Self::require_satisfied(&pkg.req_names, name) {
                add_info(out, Level::Warning, pkg, "python-missing-require", &[name]);
            }
        }

        // Leftover requirements: python-foo in RPM requires with no match.
        let mut wanted: Vec<String> = Vec::new();
        for (name, marker) in reqs {
            if let Some(m) = marker
                && !Self::marker_holds(m)
            {
                continue;
            }
            wanted.extend(Self::module_names(name));
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
            let variants: Vec<String> = Self::module_names(&module)
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
        let reqs = PythonCheck::parse_requirements(content, false);
        assert_eq!(reqs.len(), 3);
        assert_eq!(reqs[0].0, "backcall");
        assert_eq!(reqs[2].0, "jedi");
    }

    #[test]
    fn requires_txt_section_markers_are_respected() {
        // python_version < "3.10" does not hold for 3.12.
        let content = "backcall\n[:python_version < \"3.10\"]\ntyping_extensions\n";
        let reqs = PythonCheck::parse_requirements(content, false);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].0, "backcall");
    }

    #[test]
    fn extra_markers_are_skipped() {
        let content = "foo; extra == \"test\"\nbar\n";
        let reqs = PythonCheck::parse_requirements(content, false);
        // `foo` has an extra marker, which marker_holds rejects.
        assert!(reqs.iter().any(|(n, _)| n == "foo"));
        assert!(!PythonCheck::marker_holds("extra == \"test\""));
    }

    #[test]
    fn metadata_requires_dist_parses() {
        let content = "Metadata-Version: 2.1\nRequires-Dist: requests>=2.0\nRequires-Dist: foo; python_version < \"3.10\"\n";
        let reqs = PythonCheck::parse_requirements(content, true);
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].0, "requests");
    }

    #[test]
    fn module_names_include_variants() {
        let names = PythonCheck::module_names("foo-bar");
        assert!(names.contains(&"foo-bar".to_string()));
        assert!(names.contains(&"foo_bar".to_string()));
    }

    #[test]
    fn require_satisfied_matches_python3_foo() {
        let req_names = vec!["python3-requests".to_string()];
        assert!(PythonCheck::require_satisfied(&req_names, "requests"));
        assert!(!PythonCheck::require_satisfied(&req_names, "urllib3"));
    }

    #[test]
    fn require_satisfied_matches_dist() {
        let req_names = vec!["python312dist(requests)".to_string()];
        assert!(PythonCheck::require_satisfied(&req_names, "requests"));
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
}
