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
use std::sync::OnceLock;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct PythonCheck {
    pyc_version: Option<String>,
    checked_files: usize,
    default_python: String,
}

/// A parsed requirement: distribution name, environment marker, extras.
struct Requirement {
    name: String,
    marker: Option<String>,
    extras: Vec<String>,
}

/// Find the byte index of a top-level `and`/`or` operator, skipping quoted
/// strings and parenthesized groups.
fn find_top_level(expr: &str, op: &str) -> Option<usize> {
    let mut depth = 0;
    let mut in_quote: Option<char> = None;
    let bytes = expr.as_bytes();
    let op_bytes = op.as_bytes();
    let mut i = 0;
    while i + op_bytes.len() <= bytes.len() {
        let c = bytes[i] as char;
        if let Some(q) = in_quote {
            if c == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            in_quote = Some(c);
            i += 1;
            continue;
        }
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
        }
        if depth == 0 && &bytes[i..i + op_bytes.len()] == op_bytes {
            let before = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            let after = i + op_bytes.len() >= bytes.len()
                || !bytes[i + op_bytes.len()].is_ascii_alphanumeric();
            if before && after {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

impl PythonCheck {
    /// Fallback `python_version` marker value when `PythonDefaultVersion`
    /// is empty (as in the shipped defaults). The reference evaluates
    /// markers with the interpreter running rpmlint
    /// (`platform.python_version_tuple()[:2]`, `PythonCheck.py:140`) and
    /// never reads this key; the port consults it deliberately so a distro
    /// can pin the marker-evaluation version via config without rebuilding
    /// (ledgered under `PythonCheck` in `tests/parity/divergences.toml`).
    const DEFAULT_PYTHON: &'static str = "3.12";

    pub fn new(config: &Config) -> Self {
        let default_python = config
            .configuration
            .get("PythonDefaultVersion")
            .and_then(toml::Value::as_str)
            .filter(|v| !v.is_empty())
            .unwrap_or(Self::DEFAULT_PYTHON)
            .to_string();
        Self {
            pyc_version: None,
            checked_files: 0,
            default_python,
        }
    }

    fn sitelib_pattern() -> &'static str {
        r"/usr/lib[^/]*/python([^/]*)/site-packages"
    }

    /// `(regex, key)` for warning paths.
    fn warn_paths() -> &'static [(Regex, &'static str)] {
        static WARN_PATHS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
        WARN_PATHS.get_or_init(|| {
            vec![
                (
                    Regex::new(&format!("{}/[^/]+/docs?$", Self::sitelib_pattern()))
                        .expect("static"),
                    "doc",
                ),
                (Regex::new(r".*/\.doctrees$").expect("static"), "sphinx"),
            ]
        })
    }

    /// `(regex, key)` for error paths.
    fn err_paths() -> &'static [(Regex, &'static str)] {
        static ERR_PATHS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
        ERR_PATHS.get_or_init(|| {
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
        })
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
                // The reference (`_convert_egg_info_reqs_to_simple_reqs`)
                // appends the section condition as a second `;`-part to the
                // requirement verbatim, so a requirement that already carries
                // a marker keeps it first: `req; req-marker; (section-marker)
                // and extra == "name"`. The port stores the post-first-`;`
                // text verbatim instead of merging everything with `and`.
                // NB: the stored marker can be syntactically invalid PEP 508
                // (two `;` parts, matching the reference verbatim append).
                // Fine only because `marker_holds` is the sole consumer and
                // bails on `contains("extra")` before parsing; a future real
                // marker parser would choke on it.
                req.marker = match (&req.marker, marker) {
                    (Some(existing), Some(m)) => {
                        Some(format!("{existing}; ({m}) and {extra_marker}"))
                    }
                    (Some(existing), None) => Some(format!("{existing}; {extra_marker}")),
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
        // Extras live between `[` and the first `]`; the version specifier
        // follows the closing bracket (`Twisted[tls]>=14.0`), so split on
        // `]` instead of trimming a trailing one that may not be there.
        let (name, extras) = match name.split_once('[') {
            Some((n, rest)) => {
                let (extra_part, _) = rest.split_once(']').unwrap_or((rest, ""));
                let extras = extra_part
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
    /// cover `python_version`, `sys_platform`, `os_name`, `platform_system`,
    /// and `extra`).
    ///
    /// For the missing-requirement check the reference skips any requirement
    /// whose marker mentions `extra` (`'extra' in str(req.marker)`), so an
    /// extra marker never holds here.
    fn marker_holds(marker: &str, python_version: &str) -> bool {
        let marker = marker.trim();
        // `extra == "..."` means an optional dependency: skip it.
        // The reference skips any requirement whose marker mentions `extra`.
        if marker.contains("extra") {
            return false;
        }
        // Evaluate the full boolean expression (`and`/`or`/`not`), not just
        // the first atom: e.g. `python_version >= "3.0" and
        // python_version < "3.11"` must be false on 3.13.
        Self::eval_marker_expr(marker, python_version)
    }

    /// Detect a malformed marker: unbalanced parentheses or unterminated
    /// quotes. The reference (`packaging`) is fail-closed on these
    /// (`InvalidRequirement` drops the requirement); we return false.
    fn is_malformed_marker(expr: &str) -> bool {
        let mut depth = 0;
        let mut in_quote: Option<char> = None;
        for c in expr.chars() {
            if let Some(q) = in_quote {
                if c == q {
                    in_quote = None;
                }
                continue;
            }
            match c {
                '"' | '\'' => in_quote = Some(c),
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth < 0 {
                        return true;
                    }
                }
                _ => {}
            }
        }
        depth != 0 || in_quote.is_some()
    }

    /// Evaluate a single non-boolean marker comparison (no `and`/`or`/`not`).
    /// The reference evaluates markers with the full PEP 508 environment,
    /// pinning `os_name='posix'` and `platform_system='Linux'`
    /// (`PythonCheck.py:139-143`); the port mirrors that for the keys it
    /// knows and fails closed for the remaining `default_environment()`
    /// keys (ledgered in `divergences.toml`). A variable that is not a PEP
    /// 508 environment key is still treated as holding. Malformed markers
    /// are fail-closed (false), matching `packaging`.
    fn marker_atom_holds(atom: &str, python_version: &str) -> bool {
        let atom = atom.trim();
        if Self::is_malformed_marker(atom) {
            return false;
        }
        // python_version comparisons, e.g. `python_version < "3.10"`.
        static PV_RE: OnceLock<Regex> = OnceLock::new();
        let pv_re = PV_RE.get_or_init(|| {
            Regex::new(r#"python_version\s*(==|!=|<=|>=|<|>)\s*["']([\d.]+)["']"#)
                .expect("static regex")
        });
        if let Some(caps) = pv_re.captures(atom).ok().flatten() {
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
        // `python_version in "..."` / `not in`: `packaging` does a string
        // containment check, e.g. `python_version in "2.6 2.7"` is false on
        // 3.13.
        static PV_IN_RE: OnceLock<Regex> = OnceLock::new();
        let pv_in_re = PV_IN_RE.get_or_init(|| {
            Regex::new(r#"python_version\s+(not\s+in|in)\s+["']([^"']*)["']"#)
                .expect("static regex")
        });
        if let Some(caps) = pv_in_re.captures(atom).ok().flatten() {
            let op = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let want = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let contains = want.contains(python_version);
            return if op.starts_with("not") {
                !contains
            } else {
                contains
            };
        }
        // `extra` is never provided: `packaging` evaluates markers with
        // `extra == ""`, so only `extra == ""` holds.
        if let Some(holds) = Self::string_marker_holds(atom, "extra", "") {
            return holds;
        }
        // sys_platform: we are always on Linux here, mirroring the
        // reference's environment. Evaluate properly instead of the old
        // win32-only heuristic, which wrongly treated
        // `sys_platform == "darwin"` as holding.
        if let Some(holds) = Self::string_marker_holds(atom, "sys_platform", "linux") {
            return holds;
        }
        // The port only ever runs on Linux, mirroring the reference's
        // pinned environment.
        if let Some(holds) = Self::string_marker_holds(atom, "os_name", "posix") {
            return holds;
        }
        if let Some(holds) = Self::string_marker_holds(atom, "platform_system", "Linux") {
            return holds;
        }
        // The remaining `default_environment()` keys are not evaluated:
        // fail closed rather than guess.
        for key in [
            "implementation_name",
            "implementation_version",
            "platform_machine",
            "platform_release",
            "platform_version",
            "python_full_version",
            "platform_python_implementation",
        ] {
            if atom.contains(key) {
                return false;
            }
        }
        true
    }

    /// Evaluate a `var == "value"` / `var != "value"` comparison against a
    /// pinned value. Returns `None` when the atom is not such a comparison.
    fn string_marker_holds(atom: &str, var: &str, pinned: &str) -> Option<bool> {
        // Per-`var` cached regexes: the pattern varies only with `var`,
        // which comes from a small fixed set of call sites.
        static STRING_MARKER_RES: [(&str, OnceLock<Regex>); 4] = [
            ("extra", OnceLock::new()),
            ("os_name", OnceLock::new()),
            ("platform_system", OnceLock::new()),
            ("sys_platform", OnceLock::new()),
        ];
        let cell = STRING_MARKER_RES
            .iter()
            .find(|(v, _)| *v == var)
            .map(|(_, cell)| cell);
        debug_assert!(
            cell.is_some(),
            "string_marker_holds called with unexpected var: {var}"
        );
        let cell = cell?;
        let re = cell.get_or_init(|| {
            Regex::new(&format!(r#"{var}\s*(==|!=)\s*["']([^"']*)["']"#)).expect("static regex")
        });
        let caps = re.captures(atom).ok().flatten()?;
        let op = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let want = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        match op {
            "==" => Some(want == pinned),
            "!=" => Some(want != pinned),
            _ => None,
        }
    }

    /// Evaluate a marker for the leftover-requirements check.
    ///
    /// Unlike [`Self::marker_holds`], the reference does not skip
    /// extra-marked requirements here: it evaluates the marker with the
    /// full PEP 508 environment. `extra` is never provided, so
    /// [`Self::marker_atom_holds`] evaluates `extra` comparisons against
    /// `""` (verified against `packaging.markers`).
    fn marker_holds_leftover(marker: &str, python_version: &str) -> bool {
        Self::eval_marker_expr(marker, python_version)
    }

    /// Strip one layer of parentheses, returning `None` unless the `(` at
    /// index 0 is matched by the final `)`. Depth-tracked: `(a) or (b)`
    /// starts with `(` and ends with `)` without the outer pair wrapping
    /// the whole expression, and must not be stripped. (The caller already
    /// rejected unbalanced input via [`Self::is_malformed_marker`].)
    fn strip_outer_parens(expr: &str) -> Option<&str> {
        let bytes = expr.as_bytes();
        if bytes.len() < 2 || bytes[0] != b'(' || bytes[bytes.len() - 1] != b')' {
            return None;
        }
        let mut depth = 0;
        let mut in_quote: Option<u8> = None;
        for (i, &b) in bytes.iter().enumerate() {
            if let Some(q) = in_quote {
                if b == q {
                    in_quote = None;
                }
                continue;
            }
            match b {
                b'"' | b'\'' => in_quote = Some(b),
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 && i != bytes.len() - 1 {
                        return None;
                    }
                }
                _ => {}
            }
        }
        Some(&expr[1..expr.len() - 1])
    }

    /// Evaluate a boolean marker expression with `and`/`or`/`not` over the
    /// single comparisons [`Self::marker_atom_holds`] understands.
    fn eval_marker_expr(expr: &str, python_version: &str) -> bool {
        let expr = expr.trim();
        // Fail-closed on malformed markers, matching `packaging`.
        if Self::is_malformed_marker(expr) {
            return false;
        }
        // Strip one layer of outer parentheses, but only when the `(` at
        // index 0 is matched by the final `)`. A bare first/last-character
        // check mangles `(a) or (b)` into `a) or (b)`.
        if let Some(inner) = Self::strip_outer_parens(expr) {
            return Self::eval_marker_expr(inner, python_version);
        }
        // `or` binds loosest.
        if let Some(idx) = find_top_level(expr, "or") {
            return Self::eval_marker_expr(&expr[..idx], python_version)
                || Self::eval_marker_expr(&expr[idx + 2..], python_version);
        }
        // Then `and`.
        if let Some(idx) = find_top_level(expr, "and") {
            return Self::eval_marker_expr(&expr[..idx], python_version)
                && Self::eval_marker_expr(&expr[idx + 3..], python_version);
        }
        // `not` prefix.
        if let Some(rest) = expr.strip_prefix("not ") {
            return !Self::eval_marker_expr(rest, python_version);
        }
        let expr = expr.trim();
        if expr == "true" {
            return true;
        }
        if expr == "false" {
            return false;
        }
        Self::marker_atom_holds(expr, python_version)
    }

    /// The `python_version` marker environment, mirroring the reference:
    /// the `python(abi)` require's version wins over the default, and the
    /// version embedded in the dist-info/egg-info path wins over that.
    fn marker_python_version(
        &self,
        requires: &[crate::pkg::dep::DepInfo],
        filename: &str,
    ) -> String {
        let mut version = self.default_python.clone();
        if let Some(abi) = requires.iter().find(|r| r.name == "python(abi)")
            && let Some(v) = abi.version.as_deref()
        {
            version = v.to_string();
        }
        static SITELIB_RE: OnceLock<Regex> = OnceLock::new();
        let sitelib_re =
            SITELIB_RE.get_or_init(|| Regex::new(Self::sitelib_pattern()).expect("static regex"));
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
        static EGG_INFO_RE: OnceLock<Regex> = OnceLock::new();
        static PYC_RE: OnceLock<Regex> = OnceLock::new();
        let egg_info_re =
            EGG_INFO_RE.get_or_init(|| Regex::new(r".*egg-info$").expect("static regex"));
        let pyc_re = PYC_RE.get_or_init(|| Regex::new(r"cpython-(\d+)").expect("static regex"));
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
                let python_version = self.marker_python_version(&pkg.requires, filename);
                let reqs = Self::parse_requirements(&content, false, &python_version);
                self.check_requirements(pkg, out, &reqs, &python_version);
                continue;
            }
            if filename.ends_with("dist-info/METADATA") {
                let content = pkg.read_file(filename);
                let python_version = self.marker_python_version(&pkg.requires, filename);
                let reqs = Self::parse_requirements(&content, true, &python_version);
                self.check_requirements(pkg, out, &reqs, &python_version);
                continue;
            }
            if is_match(egg_info_re, filename) {
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

            for &(ref re, key) in Self::warn_paths() {
                if is_match(re, filename) {
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
            for &(ref re, key) in Self::err_paths() {
                if is_match(re, filename) {
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

static PYTHON_NAME_RE: OnceLock<Regex> = OnceLock::new();

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
        // Extra markers are evaluated here, not skipped: the reference
        // runs the full PEP 508 environment over them.
        let mut wanted: Vec<String> = Vec::new();
        for req in reqs {
            if let Some(m) = &req.marker
                && !Self::marker_holds_leftover(m, python_version)
            {
                continue;
            }
            wanted.extend(Self::module_names(&req.name, &req.extras));
        }
        let wanted: Vec<String> = wanted.iter().map(|n| n.to_lowercase()).collect();
        let py_re = PYTHON_NAME_RE
            .get_or_init(|| Regex::new(r"^python\d*-(?P<name>.+)$").expect("static regex"));
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
    fn leftover_extra_markers_are_evaluated_not_skipped() {
        // Emission-path test through `check_requirements`: the reference
        // evaluates `extra` markers in the leftover path with the full PEP 508
        // environment, where `extra` is never provided. `extra == "test"` is
        // false (requirement not wanted → leftover if the RPM requires it);
        // `extra != "test"` is true (requirement wanted → no leftover).
        // Verified against `packaging.markers` and the reference end-to-end.
        let content = "Metadata-Version: 2.1\nRequires-Dist: w6extra; extra == \"test\"\n";
        let reqs = PythonCheck::parse_requirements(content, true, "3.12");
        let findings = check_requirements_findings(&reqs, &["python3-w6extra"]);
        assert_eq!(findings.len(), 1, "unexpected findings: {findings:?}");
        let (name, level, line) = &findings[0];
        assert_eq!(name, "python-leftover-require");
        assert_eq!(*level, Level::Warning);
        assert!(line.contains("python3-w6extra"), "detail: {line}");

        // `extra != "test"` holds, so the requirement is wanted: no leftover.
        let content = "Metadata-Version: 2.1\nRequires-Dist: w6extra; extra != \"test\"\n";
        let reqs = PythonCheck::parse_requirements(content, true, "3.12");
        let findings = check_requirements_findings(&reqs, &["python3-w6extra"]);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn leftover_extras_with_version_specifier_match() {
        // `Twisted[tls]>=14.0`: the version specifier follows the closing
        // bracket, so extras must be split on `]` — trimming a trailing
        // `]` left `tls]>=14.0` as the extra and emitted a bogus
        // `python-leftover-require` for `python3-Twisted-tls` (issue #381,
        // e.g. python-TxSNI, python-ldaptor, python-dask-ml).
        let req = PythonCheck::split_marker("Twisted[tls]>=14.0");
        assert_eq!(req.name, "Twisted");
        assert_eq!(req.extras, vec!["tls".to_string()]);

        let content = "Metadata-Version: 2.1\nRequires-Dist: Twisted[tls]>=14.0\n";
        let reqs = PythonCheck::parse_requirements(content, true, "3.12");
        let findings = check_requirements_findings(&reqs, &["python3-Twisted-tls"]);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");

        // Multiple extras with a version: `dask[array,dataframe]>=2025.1.0`.
        let req = PythonCheck::split_marker("dask[array,dataframe]>=2025.1.0");
        assert_eq!(req.name, "dask");
        assert_eq!(
            req.extras,
            vec!["array".to_string(), "dataframe".to_string()]
        );
        let content = "Metadata-Version: 2.1\nRequires-Dist: dask[array,dataframe]>=2025.1.0\n";
        let reqs = PythonCheck::parse_requirements(content, true, "3.12");
        let findings = check_requirements_findings(&reqs, &["python3-dask-dataframe"]);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");

        // Unclosed-bracket fallback: `foo[bar` still yields `bar` as extra.
        let req = PythonCheck::split_marker("foo[bar");
        assert_eq!(req.extras, vec!["bar".to_string()]);
    }

    #[test]
    fn marker_boolean_evaluator_handles_parenthesised_operands() {
        // Direct tests for the `and`/`or` evaluator added by this change.
        // Expected values verified against `packaging` with
        // python_version=3.12, os_name=posix. `os_name`/`platform_system`
        // are pinned to the reference's Linux environment, so the cases
        // below are comparable on both sides.
        let cases = [
            ("(python_version >= \"3.9\") or (os_name == \"nt\")", true),
            (
                "(python_version >= \"3.9\") and (os_name == \"posix\")",
                true,
            ),
            (
                "(python_version < \"3.9\") or (python_version > \"4.0\")",
                false,
            ),
            (
                "(python_version >= \"3.9\") and (python_version < \"3.10\")",
                false,
            ),
            ("((python_version >= \"3.9\"))", true),
            ("(python_version >= \"3.9\")", true),
            (
                "(python_version < \"3.0\") or (python_version >= \"3.9\") and (python_version < \"3.13\")",
                true,
            ),
        ];
        for (marker, expected) in cases {
            assert_eq!(
                PythonCheck::eval_marker_expr(marker, "3.12"),
                expected,
                "marker: {marker}"
            );
        }
    }

    #[test]
    fn leftover_parenthesised_markers_are_evaluated() {
        // Emission-path test through `check_requirements`: a top-level
        // boolean with parenthesised operands must not be mangled by paren
        // stripping. Both markers hold for python_version 3.12 (verified
        // against `packaging`), so the requirements are wanted and no
        // `python-leftover-require` fires. With the old first/last-char
        // stripping the expression becomes malformed, evaluates false, and
        // a bogus leftover finding is emitted.
        for marker in [
            "(python_version >= \"3.9\") or (os_name == \"nt\")",
            "(python_version >= \"3.9\") and (os_name == \"posix\")",
        ] {
            let content = format!("Metadata-Version: 2.1\nRequires-Dist: w6paren; {marker}\n");
            let reqs = PythonCheck::parse_requirements(&content, true, "3.12");
            let findings = check_requirements_findings(&reqs, &["python3-w6paren"]);
            assert!(
                findings.is_empty(),
                "marker {marker}: unexpected findings: {findings:?}"
            );
        }
    }

    #[test]
    fn leftover_false_parenthesised_marker_still_fires() {
        // The paren fix must not make everything true: a parenthesised
        // marker that genuinely does not hold still yields the leftover.
        let content = "Metadata-Version: 2.1\nRequires-Dist: w6paren; (python_version < \"3.9\") or (python_version > \"4.0\")\n";
        let reqs = PythonCheck::parse_requirements(content, true, "3.12");
        let findings = check_requirements_findings(&reqs, &["python3-w6paren"]);
        assert_eq!(findings.len(), 1, "unexpected findings: {findings:?}");
        let (name, level, line) = &findings[0];
        assert_eq!(name, "python-leftover-require");
        assert_eq!(*level, Level::Warning);
        assert!(line.contains("python3-w6paren"), "detail: {line}");
    }

    #[test]
    fn leftover_empty_extra_marker_holds() {
        // `packaging` evaluates markers with `extra == ""`, so
        // `extra == ""` holds and the requirement is wanted: no leftover.
        // The old substitution treated every `extra == "<anything>"` as
        // false, emitting a false `python-leftover-require`. Expected
        // values verified against `packaging.markers`.
        assert!(PythonCheck::marker_holds_leftover("extra == \"\"", "3.12"));
        assert!(!PythonCheck::marker_holds_leftover("extra != \"\"", "3.12"));
        assert!(!PythonCheck::marker_holds_leftover(
            "extra == \"test\"",
            "3.12"
        ));
        assert!(PythonCheck::marker_holds_leftover(
            "extra != \"test\"",
            "3.12"
        ));
        // Emission path: `extra == ""` holds, so no finding.
        let content = "Metadata-Version: 2.1\nRequires-Dist: w6ext; extra == \"\"\n";
        let reqs = PythonCheck::parse_requirements(content, true, "3.12");
        let findings = check_requirements_findings(&reqs, &["python3-w6ext"]);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn marker_pinned_linux_environment() {
        // The reference pins `os_name='posix'` and `platform_system='Linux'`
        // (`PythonCheck.py:139-143`); the port only ever runs on Linux.
        // Expected values verified against `packaging` with the reference
        // environment.
        assert!(PythonCheck::marker_atom_holds(
            "os_name == \"posix\"",
            "3.12"
        ));
        assert!(!PythonCheck::marker_atom_holds("os_name == \"nt\"", "3.12"));
        assert!(PythonCheck::marker_atom_holds("os_name != \"nt\"", "3.12"));
        assert!(PythonCheck::marker_atom_holds(
            "platform_system == \"Linux\"",
            "3.12"
        ));
        assert!(!PythonCheck::marker_atom_holds(
            "platform_system == \"Windows\"",
            "3.12"
        ));
        // The remaining `default_environment()` keys fail closed.
        assert!(!PythonCheck::marker_atom_holds(
            "platform_machine == \"x86_64\"",
            "3.12"
        ));
        assert!(!PythonCheck::marker_atom_holds(
            "python_full_version == \"3.12.1\"",
            "3.12"
        ));
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
        let check = PythonCheck::new(&Config::default());
        // dist-info path beats both the default and a python(abi) require.
        let version = check.marker_python_version(
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
        let check = PythonCheck::new(&Config::default());
        let version = check.marker_python_version(&[abi], "/somewhere/foo-1.0.dist-info/METADATA");
        assert_eq!(version, "3.11");
    }

    #[test]
    fn marker_python_version_defaults() {
        let check = PythonCheck::new(&Config::default());
        let version = check.marker_python_version(&[], "/somewhere/foo-1.0.dist-info/METADATA");
        // Literal, not the constant: changing DEFAULT_PYTHON must fail.
        assert_eq!(version, "3.12");
    }

    #[test]
    fn marker_python_version_honors_configured_default() {
        // Built on the shipped config rather than `Config::default()`: the
        // empty value there is the branch production actually takes, and the
        // override must win over it.
        let mut config = crate::config::load_bundled();
        config.configuration.insert(
            "PythonDefaultVersion".to_string(),
            toml::Value::String("3.9".to_string()),
        );
        let check = PythonCheck::new(&config);
        let version = check.marker_python_version(&[], "/somewhere/foo-1.0.dist-info/METADATA");
        assert_eq!(version, "3.9");
    }

    #[test]
    fn shipped_config_empty_python_default_version_falls_back_to_312() {
        // Pins the branch production actually takes: the shipped
        // `configdefaults.toml` leaves `PythonDefaultVersion = ""`, so the
        // empty-string filter in `new` fires and the hardcoded default
        // applies.
        let config = crate::config::load_bundled();
        assert_eq!(
            config
                .configuration
                .get("PythonDefaultVersion")
                .and_then(toml::Value::as_str),
            Some(""),
            "shipped configdefaults.toml must leave PythonDefaultVersion empty"
        );
        let check = PythonCheck::new(&config);
        // Literal, not the constant: changing DEFAULT_PYTHON must fail.
        assert_eq!(check.default_python, "3.12");
    }

    #[test]
    fn configured_python_version_drives_marker_evaluation_through_check_binary() {
        use crate::color::Color;
        use std::sync::atomic::{AtomicU64, Ordering};

        static SEQ: AtomicU64 = AtomicU64::new(0);

        // Gated on `python_version < "3.10"`: holds at 3.9, not at 3.11.
        // The requires.txt lives outside any versioned sitelib path so the
        // configured default — not a path-embedded version — decides, and
        // the emission runs through the real `check_binary` path.
        let content = "unavailable-dep; python_version < \"3.10\"\n";
        for (version, expect_finding) in [("3.9", true), ("3.11", false)] {
            let mut config = crate::config::load_bundled();
            config.configuration.insert(
                "PythonDefaultVersion".to_string(),
                toml::Value::String(version.to_string()),
            );
            let mut check = PythonCheck::new(&config);

            let mut pkg = fixture_pkg_with_requires(&[]);
            pkg.requires = Vec::new();
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let rel = format!("cfgtest-{n}/somelib-1.0.egg-info/requires.txt");
            let disk = pkg.dir_name().join(&rel);
            std::fs::create_dir_all(disk.parent().unwrap()).expect("test dirs");
            std::fs::write(&disk, content).expect("test requires.txt");
            let mut pf = pkg.files[0].clone();
            pf.name = format!("/{rel}");
            pf.path = disk.to_string_lossy().into_owned();
            pkg.files.push(pf);

            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_binary(&pkg, &config, &mut out);
            let levels = out.result_levels().to_vec();
            let findings: Vec<_> = out
                .results()
                .iter()
                .zip(levels)
                .filter(|((name, _), _)| name == "python-missing-require")
                .map(|((name, line), level)| (name.clone(), level, line.clone()))
                .collect();
            if expect_finding {
                assert_eq!(findings.len(), 1, "results: {:?}", out.results());
                let (name, level, line) = &findings[0];
                assert_eq!(name, "python-missing-require");
                assert_eq!(*level, Level::Warning);
                assert_eq!(
                    line,
                    "python-test.noarch: W: python-missing-require unavailable-dep"
                );
            } else {
                assert!(findings.is_empty(), "results: {:?}", out.results());
            }
            std::fs::remove_dir_all(pkg.dir_name().join(format!("cfgtest-{n}"))).ok();
        }
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
    ) -> Vec<(String, Level, String)> {
        use crate::color::Color;
        let pkg = fixture_pkg_with_requires(req_names);
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = PythonCheck::new(&config);
        check.check_requirements(&pkg, &mut out, reqs, "3.12");
        let levels = out.result_levels().to_vec();
        out.results()
            .iter()
            .zip(levels)
            .map(|((name, line), level)| (name.clone(), level, line.clone()))
            .collect()
    }

    #[test]
    fn missing_require_pins_name_level_and_detail() {
        // Positive control for the helper: an unsatisfied requirement emits
        // `python-missing-require` at Warning (the reference emits `W` too).
        // The helper now returns the level, so this pins it structurally
        // (plusky's #119 review nit) instead of relying on `is_empty()`.
        let content = "w6missing\n";
        let reqs = PythonCheck::parse_requirements(content, false, "3.12");
        let findings = check_requirements_findings(&reqs, &[]);
        assert_eq!(findings.len(), 1, "expected one finding: {findings:?}");
        let (name, level, line) = &findings[0];
        assert_eq!(name, "python-missing-require");
        assert_eq!(*level, Level::Warning);
        assert_eq!(
            line,
            "python-test.noarch: W: python-missing-require w6missing"
        );
    }

    #[test]
    fn leftover_require_pins_name_level_and_detail() {
        // The #119 nit's other half: `python-leftover-require` also had
        // no level pin. An RPM-level requirement with no matching
        // requires.txt entry fires at Warning. (One satisfied requirement
        // is needed: the check returns early when reqs is empty.)
        let reqs = PythonCheck::parse_requirements("w6satisfied\n", false, "3.12");
        let findings =
            check_requirements_findings(&reqs, &["python3-w6satisfied", "python3-w6leftover"]);
        assert_eq!(findings.len(), 1, "expected one finding: {findings:?}");
        let (name, level, line) = &findings[0];
        assert_eq!(name, "python-leftover-require");
        assert_eq!(*level, Level::Warning);
        assert_eq!(
            line,
            "python-test.noarch: W: python-leftover-require python3-w6leftover"
        );
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

    #[test]
    fn extra_section_with_marker_and_req_marker_uses_double_semicolon_form() {
        // plusky's #119 review nit: the reference
        // (`_convert_egg_info_reqs_to_simple_reqs`) appends the section
        // condition as a second `;`-part to the requirement verbatim, so a
        // requirement that already carries a marker yields
        // `w6extra; python_version > "3.9"; (sys_platform == "linux") and
        // extra == "extra"`. The port used to merge everything into one
        // `and`ed marker. The assert_eq pins the reference form (it fails on
        // the old merged form); the emission-path assertion below pins the
        // no-false-positive invariant (it fails if the extra term is
        // dropped). Exact equality, like the sibling tests.
        let content = "[extra:sys_platform == \"linux\"]\nw6extra; python_version > \"3.9\"\n";
        let reqs = PythonCheck::parse_requirements(content, false, "3.12");
        assert_eq!(reqs.len(), 1);
        assert_eq!(
            reqs[0].marker.as_deref(),
            Some("python_version > \"3.9\"; (sys_platform == \"linux\") and extra == \"extra\""),
            "marker: {:?}",
            reqs[0].marker
        );
        // Emission path: the synthesized extra marker never holds, so
        // `w6extra` must not be reported missing.
        let findings = check_requirements_findings(&reqs, &[]);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn extra_section_req_marker_keeps_section_condition_separate() {
        // Sibling arm: `[extra]` (no section marker) with a requirement that
        // already carries a marker. The reference yields
        // `w6extra; python_version > "3.9"; extra == "extra"`, not one merged
        // `and`ed marker.
        let content = "[extra]\nw6extra; python_version > \"3.9\"\n";
        let reqs = PythonCheck::parse_requirements(content, false, "3.12");
        assert_eq!(reqs.len(), 1);
        assert_eq!(
            reqs[0].marker.as_deref(),
            Some("python_version > \"3.9\"; extra == \"extra\""),
            "marker: {:?}",
            reqs[0].marker
        );
        let findings = check_requirements_findings(&reqs, &[]);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn extras_with_version_specifier_parse_correctly() {
        // Issue #382: `Twisted[tls]>=14.0` must yield extras `["tls"]`,
        // not `["tls]>=14.0"]`.
        let req = PythonCheck::split_marker("Twisted[tls]>=14.0");
        assert_eq!(req.name, "Twisted");
        assert_eq!(req.extras, vec!["tls".to_string()]);
        let req = PythonCheck::split_marker("jsonschema[format-nongpl]>=4.18.0");
        assert_eq!(req.extras, vec!["format-nongpl".to_string()]);
    }

    #[test]
    fn string_marker_regexes_are_keyed_by_var() {
        // The OnceLock table in `string_marker_holds` keys the cached
        // regex by `var`: an atom naming a different variable must not
        // match, even when another var's regex was compiled first.
        for var in ["extra", "os_name", "platform_system", "sys_platform"] {
            let pinned = match var {
                "extra" => "",
                "os_name" => "posix",
                "platform_system" => "Linux",
                "sys_platform" => "linux",
                _ => unreachable!(),
            };
            assert_eq!(
                PythonCheck::string_marker_holds(&format!("{var} == '{pinned}'"), var, pinned),
                Some(true),
                "own-var atom must match for {var}"
            );
            assert_eq!(
                PythonCheck::string_marker_holds("extra == ''", var, pinned),
                if var == "extra" { Some(true) } else { None },
                "other-var atom must not match for {var}"
            );
        }
    }

    #[test]
    fn sys_platform_darwin_does_not_hold_on_linux() {
        // Issue #382: `sys_platform == "darwin"` must not hold on Linux.
        assert!(!PythonCheck::marker_holds(
            "sys_platform == 'darwin'",
            "3.13"
        ));
        assert!(!PythonCheck::marker_holds(
            "sys_platform == \"darwin\"",
            "3.13"
        ));
        assert!(!PythonCheck::marker_holds(
            "sys_platform == 'emscripten'",
            "3.13"
        ));
        assert!(PythonCheck::marker_holds("sys_platform == 'linux'", "3.13"));
        assert!(PythonCheck::marker_holds("sys_platform != 'win32'", "3.13"));
        assert!(!PythonCheck::marker_holds(
            "sys_platform == 'win32'",
            "3.13"
        ));
    }

    #[test]
    fn boolean_markers_evaluate_fully() {
        // Issue #382: `marker_holds` must evaluate the whole boolean
        // expression, not just the first atom.
        assert!(!PythonCheck::marker_holds(
            "python_version >= \"3.0\" and python_version < \"3.11\"",
            "3.13"
        ));
        assert!(PythonCheck::marker_holds(
            "python_version >= \"3.0\" and python_version < \"3.14\"",
            "3.13"
        ));
        assert!(!PythonCheck::marker_holds(
            "sys_platform == \"win32\" and python_version >= \"3.8\"",
            "3.13"
        ));
    }

    #[test]
    fn python_version_in_marker() {
        // Issue #382: `python_version in "..."` must be evaluated.
        assert!(!PythonCheck::marker_holds(
            "python_version in \"2.6 2.7 3.2 3.3\"",
            "3.13"
        ));
        assert!(PythonCheck::marker_holds(
            "python_version in \"3.13 3.14\"",
            "3.13"
        ));
    }

    #[test]
    fn extras_match_subpackage_requires() {
        // Issue #382: `Twisted[tls]` must match `python313-Twisted-tls`.
        let req = PythonCheck::split_marker("Twisted[tls]>=14.0");
        let req_names = vec!["python313-Twisted-tls >= 14.0.0".to_string()];
        assert!(PythonCheck::require_satisfied(&req_names, &req));
        // And `dask[array]` must match `python313-dask-array`.
        let req = PythonCheck::split_marker("dask[array]>=2022.2.0");
        let req_names = vec!["python313-dask-array >= 2022.2.0".to_string()];
        assert!(PythonCheck::require_satisfied(&req_names, &req));
    }
}
