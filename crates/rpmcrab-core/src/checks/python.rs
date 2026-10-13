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
//!
//! `python-leftover-require` is computed once per package over the
//! union of all its dist-infos and resolved after the whole run has
//! been checked: a leftover is suppressed when the package's shipped
//! code provably imports the dependency — an exact dotted module
//! path, with string literals, comments and `/usr/share/doc`
//! examples not counting as code — and a package shipping no
//! Python code never produces one (#481).

use std::collections::{HashMap, HashSet};
use std::path::Path;

use fancy_regex::Regex;
use std::sync::OnceLock;

use crate::check::{Check, add_info, make_finding};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct PythonCheck {
    pyc_version: Option<String>,
    checked_files: usize,
    default_python: String,
    /// Deferred `python-leftover-require` candidates, resolved in
    /// `after_checks` once every package in the run has contributed its
    /// provider metadata (#481).
    leftover_packages: Vec<LeftoverPackage>,
    /// `(module path, provider key)` pairs seen so far: which provider
    /// (by normalised distribution name or by the providing package's
    /// name) ships which exact dotted module path, from dist-info
    /// metadata and from site-packages file lists.
    provider_modules: Vec<(String, String)>,
}

/// One package's deferred leftover candidates (#481).
struct LeftoverPackage {
    name: String,
    arch: String,
    /// Dotted module paths imported by the package's shipped Python
    /// code (`azure.mgmt.network`, not just `azure`).
    imports: HashSet<String>,
    /// RPM require strings no dist-info of the package accounts for,
    /// deduplicated, in first-seen order.
    candidates: Vec<String>,
}

/// Cross-package leftover state, exported per package and merged before
/// `after_checks` (`rpmlint#1595`).
struct PythonLeftoverState {
    packages: Vec<LeftoverPackage>,
    provider_modules: Vec<(String, String)>,
}

/// One parsed dist-info / egg-info of a package.
struct DistInfo {
    reqs: Vec<Requirement>,
    python_version: String,
    /// Directory holding the `METADATA` / `requires.txt`, for the
    /// sibling `top_level.txt` / `RECORD`.
    dir: String,
    /// The distribution's own name (`Name:` for dist-info, derived from
    /// the directory name for egg-info).
    dist_name: Option<String>,
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
            leftover_packages: Vec::new(),
            provider_modules: Vec::new(),
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
    /// keys (ledgered in divergences.toml). A variable that is not a PEP
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
        // platform_machine: pinned to x86_64, mirroring the reference's
        // build environment (the audit's python3-cffi FP came from failing
        // closed on `platform_machine != 'aarch64'`).
        if let Some(holds) = Self::string_marker_holds(atom, "platform_machine", "x86_64") {
            return holds;
        }
        // platform_python_implementation: pinned to CPython, mirroring the
        // reference environment.
        if let Some(holds) =
            Self::string_marker_holds(atom, "platform_python_implementation", "CPython")
        {
            return holds;
        }
        // The remaining `default_environment()` keys are not evaluated:
        // fail closed rather than guess.
        // The pinned keys stay in the fail-closed loop as a backstop:
        // `string_marker_holds` above handles the valid comparison forms,
        // anything else mentioning these keys (e.g. a reversed `in`)
        // fails closed rather than falling through to `true`.
        for key in [
            "implementation_name",
            "implementation_version",
            "platform_machine",
            "platform_python_implementation",
            "platform_release",
            "platform_version",
            "python_full_version",
        ] {
            if atom.contains(key) {
                return false;
            }
        }
        true
    }

    /// Evaluate a `var == "value"` / `var != "value"` / `var in "value"` /
    /// `var not in "value"` comparison against a pinned value. Also handles
    /// the reversed `"value" == var` / `"value" != var` form (`==`/`!=` are
    /// symmetric). Returns `None` when the atom is not such a comparison.
    fn string_marker_holds(atom: &str, var: &str, pinned: &str) -> Option<bool> {
        // Per-`var` cached regexes: the pattern varies only with `var`,
        // which comes from a small fixed set of call sites.
        static STRING_MARKER_RES: [(&str, OnceLock<Regex>); 6] = [
            ("extra", OnceLock::new()),
            ("os_name", OnceLock::new()),
            ("platform_machine", OnceLock::new()),
            ("platform_python_implementation", OnceLock::new()),
            ("platform_system", OnceLock::new()),
            ("sys_platform", OnceLock::new()),
        ];
        // Reversed-operand patterns for `"literal" == var` /
        // `"literal" != var`. Only `==`/`!=` are symmetric; a reversed `in`
        // is left unmatched so the fail-closed backstop in
        // `marker_atom_holds` handles it.
        static STRING_MARKER_REV_RES: [(&str, OnceLock<Regex>); 6] = [
            ("extra", OnceLock::new()),
            ("os_name", OnceLock::new()),
            ("platform_machine", OnceLock::new()),
            ("platform_python_implementation", OnceLock::new()),
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
        // Var on the left: `var == "value"`.
        let re = cell.get_or_init(|| {
            Regex::new(&format!(
                r#"{var}\s*(==|!=|\bin\b|not\s+in)\s*["']([^"']*)["']"#
            ))
            .expect("static regex")
        });
        if let Some(caps) = re.captures(atom).ok().flatten() {
            let op = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let want = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            // Normalize the operator (e.g. "not  in" -> "not in").
            let op_norm: String = op.split_whitespace().collect::<Vec<_>>().join(" ");
            match op_norm.as_str() {
                "==" => return Some(want == pinned),
                "!=" => return Some(want != pinned),
                "in" => return Some(want.contains(pinned)),
                "not in" => return Some(!want.contains(pinned)),
                _ => {}
            }
        }
        // Literal on the left: `"value" == var` / `"value" != var`.
        let rev_cell = STRING_MARKER_REV_RES
            .iter()
            .find(|(v, _)| *v == var)
            .map(|(_, cell)| cell)?;
        let rev_re = rev_cell.get_or_init(|| {
            Regex::new(&format!(r#"["']([^"']*)["']\s*(==|!=)\s*{var}\b"#)).expect("static regex")
        });
        let caps = rev_re.captures(atom).ok().flatten()?;
        let want = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let op = caps.get(2).map(|m| m.as_str()).unwrap_or("");
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
        let mut dist_infos: Vec<DistInfo> = Vec::new();

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
                self.check_missing_requirements(pkg, out, &reqs, &python_version);
                let dir = filename
                    .rsplit_once('/')
                    .map(|(d, _)| d.to_string())
                    .unwrap_or_default();
                let dist_name = Self::egg_info_dist_name(&dir);
                dist_infos.push(DistInfo {
                    reqs,
                    python_version,
                    dir,
                    dist_name,
                });
                continue;
            }
            if filename.ends_with("dist-info/METADATA") {
                let content = pkg.read_file(filename);
                let python_version = self.marker_python_version(&pkg.requires, filename);
                let reqs = Self::parse_requirements(&content, true, &python_version);
                self.check_missing_requirements(pkg, out, &reqs, &python_version);
                let dir = filename
                    .rsplit_once('/')
                    .map(|(d, _)| d.to_string())
                    .unwrap_or_default();
                let dist_name = content
                    .lines()
                    .find_map(|l| l.strip_prefix("Name:"))
                    .map(|n| n.trim().to_string())
                    .filter(|n| !n.is_empty());
                dist_infos.push(DistInfo {
                    reqs,
                    python_version,
                    dir,
                    dist_name,
                });
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

        // Provider metadata (#481b), file-list part: the exact module
        // paths this package ships under site-packages, from its own
        // file list. Some providers ship no dist-info at all
        // (python313-opencv ships a bare `cv2.*.so`), so this is the
        // only attribution evidence for them — the same evidence
        // `RECORD` carries, read from the RPM header instead.
        let pkg_key = Self::package_key(&pkg.name);
        for module in Self::site_packages_module_paths(pkg) {
            self.provider_modules.push((module, pkg_key.clone()));
        }
        if dist_infos.is_empty() {
            return;
        }
        // Provider metadata (#481b), dist-info part: this package's
        // dist-infos state which module paths they ship, so another
        // package's leftover can be attributed when its code imports
        // one of them. Recorded for every package with dist-infos,
        // whether or not the package itself has leftover candidates.
        for di in &dist_infos {
            let modules = Self::dist_module_paths(pkg, di);
            if modules.is_empty() {
                continue;
            }
            let mut keys: Vec<String> = Vec::new();
            if let Some(name) = &di.dist_name {
                keys.push(pep503(name));
            }
            keys.push(pkg_key.clone());
            for module in modules {
                for key in &keys {
                    self.provider_modules.push((module.clone(), key.clone()));
                }
            }
        }
        // Leftover candidates (#481a): computed once per package over
        // the union of all its dist-infos, then deferred — the import
        // suppression (#481b) needs the whole run's provider metadata,
        // which only exists in `after_checks`. A package that ships no
        // Python code at all (a metadata-only metapackage, #481c) never
        // produces candidates: its Requires are its entire content.
        let refs: Vec<(&[Requirement], &str)> = dist_infos
            .iter()
            .map(|d| (d.reqs.as_slice(), d.python_version.as_str()))
            .collect();
        let candidates = Self::leftover_require_strings(&pkg.req_names, &refs);
        if !candidates.is_empty() && Self::package_has_code(pkg) {
            self.leftover_packages.push(LeftoverPackage {
                name: pkg.name.clone(),
                arch: pkg.arch.clone(),
                imports: Self::scan_imports(pkg),
                candidates,
            });
        }
    }

    fn export_state(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        Some(Box::new(PythonLeftoverState {
            packages: std::mem::take(&mut self.leftover_packages),
            provider_modules: std::mem::take(&mut self.provider_modules),
        }))
    }

    fn import_state(&mut self, state: Box<dyn std::any::Any + Send>) {
        if let Ok(state) = state.downcast::<PythonLeftoverState>() {
            self.leftover_packages.extend(state.packages);
            self.provider_modules.extend(state.provider_modules);
        }
    }

    fn after_checks(&mut self, _config: &Config, out: &mut Filter) {
        // Dotted module path -> the provider keys shipping exactly
        // that path.
        let mut providers: HashMap<String, HashSet<String>> = HashMap::new();
        for (module, key) in &self.provider_modules {
            providers
                .entry(module.clone())
                .or_default()
                .insert(key.clone());
        }
        for lp in &self.leftover_packages {
            for req in &lp.candidates {
                if Self::leftover_suppressed(req, &lp.imports, &providers) {
                    continue;
                }
                out.add_info(make_finding(
                    &lp.name,
                    &lp.arch,
                    Level::Warning,
                    "python-leftover-require",
                    vec![req.clone()],
                    None,
                ));
            }
        }
    }

    fn reset(&mut self) {
        self.checked_files = 0;
        self.leftover_packages.clear();
        self.provider_modules.clear();
    }

    fn checked_files(&self) -> Option<usize> {
        Some(self.checked_files)
    }
}

static PYTHON_NAME_RE: OnceLock<Regex> = OnceLock::new();

impl PythonCheck {
    /// `python-missing-require`: declared requirements the RPM requires
    /// do not satisfy.
    fn check_missing_requirements(
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
    }

    /// The dependency name a `python3-foo`-style RPM require stands for,
    /// lowercased; `None` for requires of any other shape.
    fn leftover_dep_name(req: &str) -> Option<String> {
        let py_re = PYTHON_NAME_RE
            .get_or_init(|| Regex::new(r"^python\d*-(?P<name>.+)$").expect("static regex"));
        let caps = py_re.captures(req).ok().flatten()?;
        let module = caps
            .get(1)
            .map(|m| m.as_str().trim().to_lowercase())
            .unwrap_or_default();
        if module.is_empty() {
            None
        } else {
            Some(module)
        }
    }

    /// RPM require strings that no dist-info in `dist_infos` accounts
    /// for (#481a): the declared names are unioned across all of the
    /// package's dist-infos (each evaluated with its own marker
    /// `python_version`), and each require is returned at most once.
    /// Extra markers are evaluated, not skipped: the reference runs the
    /// full PEP 508 environment over them.
    fn leftover_require_strings(
        req_names: &[String],
        dist_infos: &[(&[Requirement], &str)],
    ) -> Vec<String> {
        // The reference returns early when a distribution declares no
        // requirements; the union keeps that guard: with nothing
        // declared anywhere, every pythonX-* require would be reported.
        if dist_infos.iter().all(|(reqs, _)| reqs.is_empty()) {
            return Vec::new();
        }
        let mut wanted: Vec<String> = Vec::new();
        for (reqs, python_version) in dist_infos {
            for req in *reqs {
                if let Some(m) = &req.marker
                    && !Self::marker_holds_leftover(m, python_version)
                {
                    continue;
                }
                wanted.extend(Self::module_names(&req.name, &req.extras));
            }
        }
        let wanted: Vec<String> = wanted.iter().map(|n| n.to_lowercase()).collect();
        let mut out: Vec<String> = Vec::new();
        for req in req_names {
            let Some(module) = Self::leftover_dep_name(req) else {
                continue;
            };
            if module == "base" || module == "devel" {
                continue;
            }
            let variants: Vec<String> = Self::module_names(&module, &[])
                .iter()
                .map(|n| n.to_lowercase())
                .collect();
            if !variants.iter().any(|v| wanted.contains(v)) && !out.contains(req) {
                out.push(req.clone());
            }
        }
        out
    }

    /// Whether a leftover candidate is proven used (#481b): the
    /// package's shipped code imports a dotted module path that
    /// either *is* the dependency — the full path PEP 503-normalises
    /// to the dependency's name (`azure.mgmt.network` for
    /// `azure-mgmt-network`), or the path's top-level component does
    /// (`starlette.routing` for `starlette`: a submodule of the
    /// dependency's own module tree) — or is exactly a module path a
    /// provider package's metadata seen in this run attributes to
    /// the dependency (`providers`: module path -> provider keys).
    /// Neither name arm can repeat the shared-namespace confusion: a
    /// namespace top level (`azure`) never equals a namespaced
    /// dependency's name (`azure-mgmt-core`), so importing
    /// `azure.mgmt.network` says nothing about `azure-mgmt-core`,
    /// however many `azure-*` packages are installed. Anything else
    /// keeps firing: the suppression is a proof, not a heuristic.
    fn leftover_suppressed(
        req: &str,
        imports: &HashSet<String>,
        providers: &HashMap<String, HashSet<String>>,
    ) -> bool {
        let Some(dep) = Self::leftover_dep_name(req) else {
            return false;
        };
        let key = pep503(&dep);
        imports.iter().any(|path| {
            pep503(path) == key
                || path.split('.').next().is_some_and(|top| pep503(top) == key)
                || providers.get(path).is_some_and(|keys| keys.contains(&key))
        })
    }

    /// The provider key for a package name: `python313-opencv` and
    /// `python3-opencv` both key as `opencv`; a name without the python
    /// prefix keys as itself. PEP 503 normalised.
    fn package_key(pkg_name: &str) -> String {
        // Strip a leading `python3-` / `python313-` style prefix, if any.
        let stripped = pkg_name
            .strip_prefix("python")
            .and_then(|rest| {
                let digits: usize = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .map(|c| c.len_utf8())
                    .sum();
                rest[digits..].strip_prefix('-')
            })
            .unwrap_or(pkg_name);
        pep503(stripped)
    }

    /// The distribution name of an egg-info directory:
    /// `foo_bar-1.0.egg-info` -> `foo_bar` (the version is the last
    /// `-`-separated component starting with a digit).
    fn egg_info_dist_name(dir: &str) -> Option<String> {
        let base = dir.rsplit('/').next().unwrap_or(dir);
        let stem = base.strip_suffix(".egg-info")?;
        let name = match stem.rfind('-') {
            Some(idx)
                if stem[idx + 1..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit()) =>
            {
                &stem[..idx]
            }
            _ => stem,
        };
        if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        }
    }

    /// The module paths a dist-info attests shipping: the exact
    /// dotted paths derived from `RECORD`, plus the names listed in
    /// `top_level.txt`. The two sources are not equivalent:
    /// `top_level.txt` names top levels only, so a name it lists
    /// attests that top level itself and nothing below it — the
    /// `azure` every `azure-*` distribution lists does not attest
    /// `azure.mgmt.network`. `RECORD` carries the full paths, which
    /// is what makes subpackage attribution possible at all.
    fn dist_module_paths(pkg: &Pkg, di: &DistInfo) -> Vec<String> {
        let record = pkg.read_file(&format!("{}/RECORD", di.dir));
        let mut out = Self::module_paths_from_record(&record);
        let top = pkg.read_file(&format!("{}/top_level.txt", di.dir));
        for line in top.lines() {
            let name = line.trim();
            if !name.is_empty() && !out.iter().any(|p| p == name) {
                out.push(name.to_string());
            }
        }
        out
    }

    /// Module paths attested by a dist-info `RECORD`: each entry,
    /// read relative to the site-packages root, contributes the
    /// paths of [`Self::module_paths_for_file`]. Paths escaping the
    /// root (`../..`) are skipped.
    fn module_paths_from_record(record: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for line in record.lines() {
            let path = line.split(',').next().unwrap_or("").trim();
            if path.is_empty() || path.starts_with("..") || path.starts_with('/') {
                continue;
            }
            for module in Self::module_paths_for_file(path) {
                if !out.contains(&module) {
                    out.push(module);
                }
            }
        }
        out
    }

    /// The module paths one shipped file attests, given its path
    /// relative to the site-packages root: the file's own module
    /// path (`a/b.py` -> `a.b`, `a/__init__.py` -> `a`,
    /// `a/b.abi3.so` -> `a.b`) and its containing package directory
    /// (`a/b.py` also attests `a`). A directory is attested only by
    /// a file shipped directly in it, never by a deeper descendant,
    /// so a shared namespace directory is attested by nobody in
    /// particular: `azure/mgmt/core/__init__.py` attests
    /// `azure.mgmt.core`, not `azure` or `azure.mgmt`. Non-code
    /// files attest nothing, and entries under a
    /// `.dist-info`/`.egg-info` directory or `__pycache__` are
    /// skipped.
    fn module_paths_for_file(rel_path: &str) -> Vec<String> {
        let mut parts: Vec<&str> = rel_path.split('/').collect();
        let Some(file) = parts.pop() else {
            return Vec::new();
        };
        if file.is_empty()
            || parts.iter().any(|p| {
                *p == "__pycache__" || p.ends_with(".dist-info") || p.ends_with(".egg-info")
            })
        {
            return Vec::new();
        }
        let dir = parts.join(".");
        let module: Option<String> = if file == "__init__.py" {
            if dir.is_empty() {
                None
            } else {
                Some(dir.clone())
            }
        } else if let Some(stem) = file.strip_suffix(".py") {
            Some(join_module(&dir, stem))
        } else if file.split('.').any(|c| c == "so") {
            let stem = file.split('.').next().unwrap_or("");
            if stem == "__init__" {
                if dir.is_empty() {
                    None
                } else {
                    Some(dir.clone())
                }
            } else {
                Some(join_module(&dir, stem))
            }
        } else {
            None
        };
        let Some(module) = module else {
            return Vec::new();
        };
        if module.is_empty() {
            return Vec::new();
        }
        let mut out = vec![module];
        if !dir.is_empty() && !out.contains(&dir) {
            out.push(dir);
        }
        out
    }

    /// The module paths a package ships under a site-packages
    /// directory, from its file list — the same per-file derivation
    /// `RECORD` entries get ([`Self::module_paths_for_file`]).
    fn site_packages_module_paths(pkg: &Pkg) -> Vec<String> {
        static SITELIB_RE: OnceLock<Regex> = OnceLock::new();
        let sitelib_re = SITELIB_RE.get_or_init(|| {
            Regex::new(&format!("{}/", Self::sitelib_pattern())).expect("static regex")
        });
        let mut out: Vec<String> = Vec::new();
        for pkgfile in &pkg.files {
            if pkg.ghost_files.iter().any(|g| g == &pkgfile.name) {
                continue;
            }
            let Some(caps) = sitelib_re.captures(&pkgfile.name).ok().flatten() else {
                continue;
            };
            let whole = caps.get(0).expect("regex match");
            let rest = &pkgfile.name[whole.end()..];
            for module in Self::module_paths_for_file(rest) {
                if !out.contains(&module) {
                    out.push(module);
                }
            }
        }
        out
    }

    /// Whether the package ships any Python code at all: a `.py` or
    /// `.pyc` file, or a compiled extension module (`.so`). A package
    /// with none of these is a metadata-only metapackage (#481c).
    fn package_has_code(pkg: &Pkg) -> bool {
        pkg.files.iter().any(|f| {
            !pkg.ghost_files.iter().any(|g| g == &f.name)
                && (f.name.ends_with(".py") || f.name.ends_with(".pyc") || f.name.ends_with(".so"))
        })
    }

    /// Dotted module paths imported by the package's shipped `.py`
    /// files. The scan runs over the code skeleton
    /// ([`strip_strings_and_comments`]): an `import` mentioned in a
    /// docstring, a string literal or a comment is not an import, and
    /// files under `/usr/share/doc` are documentation examples, not
    /// the package's code — neither counts as proof of use. Relative
    /// imports are the package's own modules and are skipped, and
    /// dynamic imports (`importlib`, `__import__`) are not chased — a
    /// dependency used only that way is unprovable and keeps firing.
    fn scan_imports(pkg: &Pkg) -> HashSet<String> {
        let mut out = HashSet::new();
        for pkgfile in &pkg.files {
            if !pkgfile.name.ends_with(".py")
                || pkg.ghost_files.iter().any(|g| g == &pkgfile.name)
                || pkgfile.name.starts_with("/usr/share/doc/")
            {
                continue;
            }
            let content = pkg.read_file(&pkgfile.name);
            let code = strip_strings_and_comments(&content);
            for line in code.lines() {
                Self::scan_import_line(line, &mut out);
            }
        }
        out
    }

    fn scan_import_line(line: &str, out: &mut HashSet<String>) {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix("import ") {
            // `import a.b, c as d`
            for part in rest.split(',') {
                let dotted = part.split_whitespace().next().unwrap_or("");
                Self::push_module_path(dotted, out);
            }
        } else if let Some(rest) = line.strip_prefix("from ") {
            // `from a.b import c, d as e`: the statement imports `a.b`
            // and each named submodule (`a.b.c`), so record both —
            // `from azure.mgmt import network` proves
            // `azure.mgmt.network`, not the shared `azure` namespace.
            let mut halves = rest.splitn(2, " import ");
            let dotted = halves.next().unwrap_or("").trim();
            if dotted.starts_with('.') {
                return;
            }
            if Self::push_module_path(dotted, out)
                && let Some(names) = halves.next()
            {
                for part in names.split(',') {
                    let name = part
                        .trim()
                        .trim_matches(|c| c == '(' || c == ')')
                        .split_whitespace()
                        .next()
                        .unwrap_or("");
                    if Self::is_module_component(name) {
                        Self::push_module_path(&format!("{dotted}.{name}"), out);
                    }
                }
            }
        }
    }

    /// Record `dotted` when it is a well-formed dotted module path
    /// (every component an identifier); returns whether it was.
    fn push_module_path(dotted: &str, out: &mut HashSet<String>) -> bool {
        if !dotted.is_empty() && dotted.split('.').all(Self::is_module_component) {
            out.insert(dotted.to_string());
            true
        } else {
            false
        }
    }

    fn is_module_component(part: &str) -> bool {
        !part.is_empty()
            && part
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }
}

/// Join a package directory path and a module stem into a dotted
/// module path (`("a.b", "c")` -> `"a.b.c"`; `("", "c")` -> `"c"`).
fn join_module(dir: &str, stem: &str) -> String {
    if dir.is_empty() {
        stem.to_string()
    } else {
        format!("{dir}.{stem}")
    }
}

/// Blank out string literals and comments in Python source,
/// preserving newlines — and therefore line numbers and line
/// starts — so line-based scanning sees only the code skeleton. A
/// backslash pair never terminates a literal (true for raw strings
/// too: a closing quote cannot follow an odd number of backslashes),
/// which is the only escape rule the scan needs. F-string
/// expressions stay blanked with the rest of the literal: an
/// `import` statement cannot appear inside one.
fn strip_strings_and_comments(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '#' {
            // Comment: dropped up to (not including) the newline.
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c != '"' && c != '\'' {
            out.push(c);
            i += 1;
            continue;
        }
        // String literal: blank it whole, opening quotes included.
        let triple = i + 2 < chars.len() && chars[i + 1] == c && chars[i + 2] == c;
        let opening = if triple { 3 } else { 1 };
        for _ in 0..opening {
            out.push(' ');
        }
        i += opening;
        while i < chars.len() {
            let ch = chars[i];
            if ch == '\\' && i + 1 < chars.len() {
                out.push(' ');
                out.push(if chars[i + 1] == '\n' { '\n' } else { ' ' });
                i += 2;
                continue;
            }
            if triple {
                if ch == c && i + 2 < chars.len() && chars[i + 1] == c && chars[i + 2] == c {
                    out.push(' ');
                    out.push(' ');
                    out.push(' ');
                    i += 3;
                    break;
                }
            } else if ch == c {
                out.push(' ');
                i += 1;
                break;
            } else if ch == '\n' {
                // Unterminated single-line literal: it ends here.
                break;
            }
            out.push(if ch == '\n' { '\n' } else { ' ' });
            i += 1;
        }
    }
    out
}

/// PEP 503 name normalisation: lowercase, with runs of `-`, `_` and `.`
/// collapsed to a single `-`.
fn pep503(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !out.is_empty() && !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
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
        // Emission-path test through `check_requirements_findings`: the reference
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
        // Emission-path test through `check_requirements_findings`: a top-level
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
    fn marker_pinned_machine_and_implementation() {
        assert!(PythonCheck::marker_atom_holds(
            "platform_machine == \"x86_64\"",
            "3.12"
        ));
        assert!(!PythonCheck::marker_atom_holds(
            "platform_machine == \"aarch64\"",
            "3.12"
        ));
        assert!(PythonCheck::marker_atom_holds(
            "platform_python_implementation == \"CPython\"",
            "3.12"
        ));
        // Each pinned key gets its own assertion: the OR form is dominated
        // by its first (true) disjunct, so it would still pass if
        // `platform_python_implementation` were dropped from the
        // implementation entirely.
        assert!(PythonCheck::marker_atom_holds(
            "platform_machine != 'aarch64'",
            "3.12"
        ));
        assert!(PythonCheck::marker_atom_holds(
            "platform_python_implementation != 'PyPy'",
            "3.12"
        ));
        assert!(!PythonCheck::marker_atom_holds(
            "sys_platform != 'linux'",
            "3.12"
        ));
        // `in` / `not in` on the newly pinned keys.
        assert!(PythonCheck::marker_atom_holds(
            "platform_machine in \"x86_64\"",
            "3.12"
        ));
        assert!(!PythonCheck::marker_atom_holds(
            "platform_machine in \"aarch64\"",
            "3.12"
        ));
        assert!(PythonCheck::marker_atom_holds(
            "platform_machine not in \"aarch64\"",
            "3.12"
        ));
        assert!(!PythonCheck::marker_atom_holds(
            "platform_python_implementation not in \"CPython PyPy\"",
            "3.12"
        ));
        // Reversed operands: literal on the left. `==`/`!=` are symmetric.
        // Verified against `packaging`: `"aarch64" == platform_machine` is
        // false on x86_64/CPython.
        assert!(!PythonCheck::marker_atom_holds(
            "\"aarch64\" == platform_machine",
            "3.12"
        ));
        assert!(PythonCheck::marker_atom_holds(
            "\"x86_64\" == platform_machine",
            "3.12"
        ));
        assert!(PythonCheck::marker_atom_holds(
            "\"aarch64\" != platform_machine",
            "3.12"
        ));
        assert!(!PythonCheck::marker_atom_holds(
            "\"CPython\" != platform_python_implementation",
            "3.12"
        ));
        assert!(PythonCheck::marker_atom_holds(
            "\"PyPy\" != platform_python_implementation",
            "3.12"
        ));
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
        // The single-dist-info flow of `check_binary`: missing inline,
        // leftover over this dist-info alone, emitted unsuppressed.
        check.check_missing_requirements(&pkg, &mut out, reqs, "3.12");
        for req in PythonCheck::leftover_require_strings(&pkg.req_names, &[(reqs, "3.12")]) {
            add_info(
                &mut out,
                Level::Warning,
                &pkg,
                "python-leftover-require",
                &[&req],
            );
        }
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
    fn leftover_union_across_dist_infos_emits_once_per_dep() {
        // #481a: the reference evaluates the RPM requires against each
        // dist-info separately, so a dep declared in dist-info B still
        // fires from dist-info A's pass (gnuhealth: ~51 deps re-emitted
        // per dist-info). The union accounts for a dep declared
        // *anywhere* in the package, and a duplicated require string is
        // returned once.
        let reqs_a = PythonCheck::parse_requirements("alpha\nbeta\n", false, "3.12");
        let reqs_b = PythonCheck::parse_requirements("beta\ngamma\n", false, "3.12");
        let req_names: Vec<String> = [
            "python3-alpha",
            "python3-beta",
            "python3-gamma",
            "python3-delta",
            "python3-delta",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let got = PythonCheck::leftover_require_strings(
            &req_names,
            &[(&reqs_a, "3.12"), (&reqs_b, "3.12")],
        );
        assert_eq!(got, vec!["python3-delta".to_string()]);
    }

    #[test]
    fn leftover_union_keeps_per_dist_info_marker_versions() {
        // A dep declared only under a marker that does not hold for its
        // dist-info's python version is not accounted for, even in the
        // union; the same declaration with a holding marker is.
        let reqs = PythonCheck::parse_requirements(
            "Requires-Dist: old; python_version < \"3.0\"\nRequires-Dist: new; python_version >= \"3.0\"\n",
            true,
            "3.13",
        );
        let req_names: Vec<String> = ["python3-old", "python3-new"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let got = PythonCheck::leftover_require_strings(&req_names, &[(&reqs, "3.13")]);
        assert_eq!(got, vec!["python3-old".to_string()]);
    }

    #[test]
    fn leftover_all_empty_dist_infos_stay_quiet() {
        // The no-declarations guard, union form: nothing declared
        // anywhere means no leftover evaluation at all.
        let req_names: Vec<String> = vec!["python3-anything".to_string()];
        let empty: Vec<Requirement> = Vec::new();
        assert!(PythonCheck::leftover_require_strings(&req_names, &[(&empty, "3.12")]).is_empty());
        assert!(PythonCheck::leftover_require_strings(&req_names, &[]).is_empty());
    }

    #[test]
    fn scan_import_line_collects_module_paths() {
        let mut imports = HashSet::new();
        for line in [
            "import os, sys",
            "    import torch.nn as nn",
            "from cv2 import imread",
            "from pydantic_extra_types.color import Color",
            "from . import sibling",
            "from .local import thing",
            "import importlib",
            "# import commented_out",
            "x = 'import not_code'",
            "importlib.import_module('dynamic')",
            "from __future__ import annotations",
        ] {
            PythonCheck::scan_import_line(line, &mut imports);
        }
        let want: HashSet<String> = [
            "os",
            "sys",
            "torch.nn",
            "cv2",
            "cv2.imread",
            "pydantic_extra_types.color",
            "pydantic_extra_types.color.Color",
            "importlib",
            "__future__",
            "__future__.annotations",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(imports, want);
    }

    #[test]
    fn module_paths_from_record_are_exact() {
        let record = "\
cv2/__init__.py,sha256=abc,123
cv2/cv2.abi3.so,,
numpy-2.0.dist-info/METADATA,,
yaml/__init__.py,,
yaml.py,,
../../usr/bin/opaque,,
data.txt,,
foo.egg-info/PKG-INFO,,
";
        let mut got = PythonCheck::module_paths_from_record(record);
        got.sort();
        assert_eq!(
            got,
            vec!["cv2".to_string(), "cv2.cv2".to_string(), "yaml".to_string()]
        );
    }

    #[test]
    fn module_paths_from_record_do_not_attest_shared_namespaces() {
        // An azure-mgmt-core RECORD attests `azure.mgmt.core` (and
        // its own submodule files) — never the shared `azure` /
        // `azure.mgmt` namespace directories, and never a sibling
        // subpackage like `azure.mgmt.network`.
        let record = "\
azure/mgmt/core/__init__.py,,
azure/mgmt/core/models.py,,
azure_mgmt_core-1.0.dist-info/METADATA,,
azure_mgmt_core-1.0.dist-info/RECORD,,
";
        let mut got = PythonCheck::module_paths_from_record(record);
        got.sort();
        assert_eq!(
            got,
            vec![
                "azure.mgmt.core".to_string(),
                "azure.mgmt.core.models".to_string()
            ]
        );
    }

    #[test]
    fn site_packages_module_paths_come_from_the_file_list() {
        // The python313-opencv shape: no dist-info, just a bare
        // extension module in site-packages — the file list is the only
        // attribution evidence. Deep files attest their exact path
        // only, not the shared namespace directories above them.
        use crate::pkg::pkgfile::PkgFile;
        let mut pkg = fixture_pkg_with_requires(&[]);
        let file = |name: &str| PkgFile {
            name: name.to_string(),
            ..Default::default()
        };
        pkg.files = vec![
            file("/usr/lib64/python3.13/site-packages/cv2.cpython-313-x86_64-linux-gnu.so"),
            file("/usr/lib/python3.13/site-packages/yaml/__init__.py"),
            file("/usr/lib/python3.13/site-packages/azure/mgmt/core/__init__.py"),
            file("/usr/lib/python3.13/site-packages/top.py"),
            file("/usr/lib/python3.13/site-packages/foo-1.0.dist-info/METADATA"),
            file("/usr/lib/python3.13/site-packages/__pycache__/top.cpython-313.pyc"),
            file("/usr/share/doc/readme.txt"),
        ];
        let mut got = PythonCheck::site_packages_module_paths(&pkg);
        got.sort();
        assert_eq!(
            got,
            vec![
                "azure.mgmt.core".to_string(),
                "cv2".to_string(),
                "top".to_string(),
                "yaml".to_string()
            ]
        );
    }

    #[test]
    fn egg_info_dist_name_strips_the_version() {
        assert_eq!(
            PythonCheck::egg_info_dist_name("/usr/lib/python3/site-packages/foo_bar-1.0.egg-info"),
            Some("foo_bar".to_string())
        );
        assert_eq!(
            PythonCheck::egg_info_dist_name("/x/setuptools-80.9.0.egg-info"),
            Some("setuptools".to_string())
        );
        assert_eq!(
            PythonCheck::egg_info_dist_name("/x/bare.egg-info"),
            Some("bare".to_string())
        );
    }

    #[test]
    fn pep503_and_package_key_normalisation() {
        assert_eq!(pep503("PyYAML"), "pyyaml");
        assert_eq!(pep503("opencv_python"), "opencv-python");
        assert_eq!(pep503("zope.interface"), "zope-interface");
        assert_eq!(PythonCheck::package_key("python313-opencv"), "opencv");
        assert_eq!(PythonCheck::package_key("python3-PyYAML"), "pyyaml");
        assert_eq!(
            PythonCheck::package_key("python-pydantic_extra_types"),
            "pydantic-extra-types"
        );
        assert_eq!(PythonCheck::package_key("gnuhealth"), "gnuhealth");
    }

    #[test]
    fn metadata_only_package_has_no_code() {
        // #481c: the azure umbrella shape — a dist-info and nothing else.
        use crate::pkg::pkgfile::PkgFile;
        let mut pkg = fixture_pkg_with_requires(&[]);
        let file = |name: &str| PkgFile {
            name: name.to_string(),
            ..Default::default()
        };
        pkg.files = vec![file(
            "/usr/lib/python3.13/site-packages/azure_mgmt-1.0.dist-info/METADATA",
        )];
        assert!(!PythonCheck::package_has_code(&pkg));
        pkg.files
            .push(file("/usr/lib/python3.13/site-packages/azure/__init__.py"));
        assert!(PythonCheck::package_has_code(&pkg));
        pkg.files = vec![file(
            "/usr/lib64/python3.13/lib-dynload/_ssl.cpython-313.so",
        )];
        assert!(PythonCheck::package_has_code(&pkg));
    }

    fn leftover_package(name: &str, imports: &[&str], candidates: &[&str]) -> LeftoverPackage {
        LeftoverPackage {
            name: name.to_string(),
            arch: "noarch".to_string(),
            imports: imports.iter().map(|s| s.to_string()).collect(),
            candidates: candidates.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn after_checks_findings(check: &mut PythonCheck) -> Vec<(String, Level, String)> {
        use crate::color::Color;
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.after_checks(&config, &mut out);
        let levels = out.result_levels().to_vec();
        out.results()
            .iter()
            .zip(levels)
            .map(|((name, line), level)| (name.clone(), level, line.clone()))
            .collect()
    }

    #[test]
    fn after_checks_suppresses_only_proven_leftovers() {
        // #481b: `torch` is proven by the exact name match (the code
        // imports `torch`), `opencv` by provider attribution (the code
        // imports `cv2`, which the run's provider metadata attributes
        // to the `opencv` provider key). `numba` has neither and fires.
        let config = Config::default();
        let mut check = PythonCheck::new(&config);
        check.leftover_packages.push(leftover_package(
            "python3-vllm",
            &["torch", "cv2"],
            &["python313-torch", "python313-opencv", "python313-numba"],
        ));
        check
            .provider_modules
            .push(("cv2".to_string(), "opencv".to_string()));
        let findings = after_checks_findings(&mut check);
        assert_eq!(findings.len(), 1, "unexpected findings: {findings:?}");
        let (name, level, line) = &findings[0];
        assert_eq!(name, "python-leftover-require");
        assert_eq!(*level, Level::Warning);
        assert_eq!(
            line,
            "python3-vllm.noarch: W: python-leftover-require python313-numba"
        );
    }

    #[test]
    fn after_checks_suppression_needs_the_import_itself() {
        // Provider metadata alone is not a proof: without an import of
        // the provider's module in this package's code, the leftover
        // keeps firing.
        let config = Config::default();
        let mut check = PythonCheck::new(&config);
        check.leftover_packages.push(leftover_package(
            "python3-consumer",
            &["unrelated"],
            &["python313-opencv"],
        ));
        check
            .provider_modules
            .push(("cv2".to_string(), "opencv".to_string()));
        let findings = after_checks_findings(&mut check);
        assert_eq!(findings.len(), 1, "unexpected findings: {findings:?}");
    }

    #[test]
    fn after_checks_merges_exported_worker_state() {
        // The parallel path: two workers each export their half of the
        // state; the merged main instance must decide exactly like a
        // single instance holding everything (the provider lives on the
        // other worker from the consumer).
        let config = Config::default();
        let mut worker_a = PythonCheck::new(&config);
        worker_a.leftover_packages.push(leftover_package(
            "python3-vllm",
            &["cv2"],
            &["python313-opencv"],
        ));
        let mut worker_b = PythonCheck::new(&config);
        worker_b
            .provider_modules
            .push(("cv2".to_string(), "opencv".to_string()));
        worker_b.leftover_packages.push(leftover_package(
            "python3-other",
            &[],
            &["python313-unproven"],
        ));

        let mut main = PythonCheck::new(&config);
        main.import_state(worker_a.export_state().expect("worker A exports"));
        main.import_state(worker_b.export_state().expect("worker B exports"));
        let findings = after_checks_findings(&mut main);
        assert_eq!(findings.len(), 1, "unexpected findings: {findings:?}");
        assert!(findings[0].2.contains("python313-unproven"));
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

    #[test]
    fn strip_strings_and_comments_blanks_literals_and_comments() {
        let src = "import os  # import in_comment\nx = \"import in_string\"\n'''import in_docstring\nstill string: import in_docstring2'''\nimport sys\n";
        let code = strip_strings_and_comments(src);
        assert!(!code.contains("in_comment"), "cleaned: {code:?}");
        assert!(!code.contains("in_string"), "cleaned: {code:?}");
        assert!(!code.contains("in_docstring"), "cleaned: {code:?}");
        assert!(code.contains("import os"), "cleaned: {code:?}");
        assert!(code.contains("import sys"), "cleaned: {code:?}");
        assert_eq!(code.matches('\n').count(), src.matches('\n').count());
        // An escaped quote does not terminate the literal, raw or not.
        let src = "x = \"a\\\" import nope\"\nimport real\n";
        let code = strip_strings_and_comments(src);
        assert!(!code.contains("nope"), "cleaned: {code:?}");
        assert!(code.contains("import real"), "cleaned: {code:?}");
        let src = "x = r\"a\\\" import nope\"\nimport real\n";
        let code = strip_strings_and_comments(src);
        assert!(!code.contains("nope"), "cleaned: {code:?}");
        assert!(code.contains("import real"), "cleaned: {code:?}");
        // A hash inside a string is not a comment; a quote inside a
        // comment does not open a string.
        let src = "x = \"# not a comment\"  # don't\nimport real\n";
        let code = strip_strings_and_comments(src);
        assert!(code.contains("import real"), "cleaned: {code:?}");
        assert!(!code.contains("not a comment"), "cleaned: {code:?}");
    }

    #[test]
    fn scan_imports_ignores_strings_comments_and_doc_files() {
        // plusky's PR #489 repro, second half: an `import` inside a
        // docstring example and one in a `/usr/share/doc` demo file
        // used to count as proof of use. Neither is the package's
        // code; only the real imports below may be recorded.
        use crate::pkg::pkgfile::PkgFile;
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        let write = |pkg: &Pkg, name: &str, content: &str| {
            let disk = pkg.dir_name().join(name.trim_start_matches('/'));
            std::fs::create_dir_all(disk.parent().unwrap()).expect("test dirs");
            std::fs::write(&disk, content).expect("test file");
            PkgFile {
                name: name.to_string(),
                ..Default::default()
            }
        };
        pkg.files = vec![
            write(
                &pkg,
                "/usr/lib/python3.13/site-packages/proofpkg/__init__.py",
                "\"\"\"Usage example:\n\n    import torch\n\"\"\"\n# import commented_out\nimport requests\ns = \"import in_string\"\nfrom azure.mgmt import network\n",
            ),
            write(
                &pkg,
                "/usr/share/doc/python3-proofpkg/demo.py",
                "import doc_only\n",
            ),
        ];
        let got = PythonCheck::scan_imports(&pkg);
        let want: HashSet<String> = ["requests", "azure.mgmt", "azure.mgmt.network"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn dist_module_paths_top_level_attests_only_itself() {
        // With no `RECORD`, a dist-info's `top_level.txt` attests
        // exactly the names it lists — the shared namespace top level
        // and nothing below it.
        use crate::pkg::pkgfile::PkgFile;
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
        let dir = "/usr/lib/python3.13/site-packages/azure_mgmt_core-1.0.dist-info";
        let disk = pkg
            .dir_name()
            .join(format!("{}/top_level.txt", dir.trim_start_matches('/')));
        std::fs::create_dir_all(disk.parent().unwrap()).expect("test dirs");
        std::fs::write(&disk, "azure\n").expect("test file");
        pkg.files = vec![PkgFile {
            name: format!("{dir}/top_level.txt"),
            ..Default::default()
        }];
        let di = DistInfo {
            reqs: Vec::new(),
            python_version: "3.13".to_string(),
            dir: dir.to_string(),
            dist_name: Some("azure-mgmt-core".to_string()),
        };
        assert_eq!(
            PythonCheck::dist_module_paths(&pkg, &di),
            vec!["azure".to_string()]
        );
    }

    #[test]
    fn after_checks_suppression_uses_exact_module_paths() {
        // Provider attribution is by exact module path: `PIL.Image`
        // is attributed to `pillow` and suppresses it, while the
        // `azure` top level attributed to `azure-mgmt-core` does not
        // suppress anything for an import of `azure.mgmt.network`.
        let config = Config::default();
        let mut check = PythonCheck::new(&config);
        check.leftover_packages.push(leftover_package(
            "python3-consumer",
            &["azure.mgmt.network", "PIL.Image"],
            &["python3-azure-mgmt-core", "python3-pillow"],
        ));
        check
            .provider_modules
            .push(("azure".to_string(), "azure-mgmt-core".to_string()));
        check
            .provider_modules
            .push(("azure.mgmt.core".to_string(), "azure-mgmt-core".to_string()));
        check
            .provider_modules
            .push(("PIL.Image".to_string(), "pillow".to_string()));
        let findings = after_checks_findings(&mut check);
        assert_eq!(findings.len(), 1, "unexpected findings: {findings:?}");
        assert!(findings[0].2.contains("python3-azure-mgmt-core"));
    }

    #[test]
    fn after_checks_top_level_name_proves_submodule_imports() {
        // The fastmcp shape: the code imports submodules of the
        // dependency's own module tree (`starlette.routing`,
        // `starlette.requests`) and the provider is not part of the
        // run. The dependency's name *is* the top-level module name,
        // so the imports prove it — unlike a shared namespace, where
        // the top level is nobody's name.
        let config = Config::default();
        let mut check = PythonCheck::new(&config);
        check.leftover_packages.push(leftover_package(
            "python3-fastmcp-slim",
            &[
                "starlette.routing",
                "starlette.requests",
                "packaging.version",
            ],
            &["python313-starlette", "python313-packaging"],
        ));
        let findings = after_checks_findings(&mut check);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn leftover_namespace_import_is_not_proof_for_sibling_dist() {
        // plusky's PR #489 repro, end to end: the consumer imports
        // `azure.mgmt.network`; the only azure provider in the run is
        // `azure-mgmt-core`, whose `top_level.txt` lists the shared
        // `azure` namespace. That must not silence the consumer's
        // undeclared `python3-azure-mgmt-core` require. The sibling
        // consumer importing `azure.mgmt.core` itself is genuinely
        // proven and stays quiet.
        use crate::color::Color;
        use crate::pkg::pkgfile::PkgFile;
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let write = |pkg: &Pkg, name: &str, content: &str| {
            let disk = pkg.dir_name().join(name.trim_start_matches('/'));
            std::fs::create_dir_all(disk.parent().unwrap()).expect("test dirs");
            std::fs::write(&disk, content).expect("test file");
            PkgFile {
                name: name.to_string(),
                ..Default::default()
            }
        };
        let mkpkg = |name: &str, req_names: &[&str]| {
            let mut pkg = Pkg::open_no_extract(&rpm).expect("open fixture pkg");
            pkg.name = name.to_string();
            pkg.arch = "noarch".to_string();
            pkg.req_names = req_names.iter().map(|s| s.to_string()).collect();
            pkg
        };
        let config = Config::default();
        let mut check = PythonCheck::new(&config);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();

        // Provider: python3-azure-mgmt-core.
        let mut provider = mkpkg("python3-azure-mgmt-core", &[]);
        let di = "/usr/lib/python3.13/site-packages/azure_mgmt_core-1.0.dist-info";
        provider.files = vec![
            write(
                &provider,
                &format!("{di}/METADATA"),
                "Metadata-Version: 2.1\nName: azure-mgmt-core\nVersion: 1.0\n",
            ),
            write(
                &provider,
                &format!("{di}/RECORD"),
                "azure/mgmt/core/__init__.py,,\nazure/mgmt/core/models.py,,\n",
            ),
            write(&provider, &format!("{di}/top_level.txt"), "azure\n"),
            write(
                &provider,
                "/usr/lib/python3.13/site-packages/azure/mgmt/core/__init__.py",
                "",
            ),
            write(
                &provider,
                "/usr/lib/python3.13/site-packages/azure/mgmt/core/models.py",
                "",
            ),
        ];
        check.check_binary(&provider, &config, &mut out);

        // Consumer A: declares azure-mgmt-network, also requires
        // azure-mgmt-core, imports azure.mgmt.network only.
        let mut a = mkpkg(
            "python3-consumer-a",
            &["python3-azure-mgmt-network", "python3-azure-mgmt-core"],
        );
        let di_a = "/usr/lib/python3.13/site-packages/consumer_a-1.0.dist-info";
        a.files = vec![
            write(
                &a,
                &format!("{di_a}/METADATA"),
                "Metadata-Version: 2.1\nName: consumer-a\nVersion: 1.0\nRequires-Dist: azure-mgmt-network\n",
            ),
            write(
                &a,
                "/usr/lib/python3.13/site-packages/consumer_a/__init__.py",
                "import azure.mgmt.network\n",
            ),
        ];
        check.check_binary(&a, &config, &mut out);

        // Consumer B: declares requests, also requires
        // azure-mgmt-core, imports azure.mgmt.core itself.
        let mut b = mkpkg(
            "python3-consumer-b",
            &["python3-requests", "python3-azure-mgmt-core"],
        );
        let di_b = "/usr/lib/python3.13/site-packages/consumer_b-1.0.dist-info";
        b.files = vec![
            write(
                &b,
                &format!("{di_b}/METADATA"),
                "Metadata-Version: 2.1\nName: consumer-b\nVersion: 1.0\nRequires-Dist: requests\n",
            ),
            write(
                &b,
                "/usr/lib/python3.13/site-packages/consumer_b/__init__.py",
                "import azure.mgmt.core\n",
            ),
        ];
        check.check_binary(&b, &config, &mut out);

        let findings = after_checks_findings(&mut check);
        assert_eq!(findings.len(), 1, "unexpected findings: {findings:?}");
        let (name, level, line) = &findings[0];
        assert_eq!(name, "python-leftover-require");
        assert_eq!(*level, Level::Warning);
        assert_eq!(
            line,
            "python3-consumer-a.noarch: W: python-leftover-require python3-azure-mgmt-core"
        );
    }
}
