//! `PythonCheck` — Python packaging checks.
//!
//! Ported from `rpmlint/checks/PythonCheck.py`. Findings:
//! `python-doc-in-package`, `python-sphinx-doctrees-leftover`,
//! `python-egg-info-distutils-style`, `python-tests-in-site-packages`,
//! `python-doc-in-site-packages`, `python-src-in-site-packages`,
//! `python-pyc-multiple-versions`, `python-missing-require`,
//! `python-leftover-require`.
//!
//! The require/metadata coherence tags — `python-unflavoured-require`,
//! `python-dist-info-version-mismatch`,
//! `python-require-floor-below-metadata` and
//! `python-require-unversioned-despite-metadata-floor`, plus the
//! `python-missing-require` satisfaction changes they ride on — are
//! crab-only (#1024, ledgered in
//! `data/divergences/PythonCheck.toml`): the package's own
//! `python3.Xdist()` Provides satisfy its declared requirements, a
//! requirement met only by a bare `python-<name>` Require is reported
//! under its own tag, the shipped dist-info version is compared against
//! the RPM version under PEP 440, and an RPM Require that carries
//! no version, or whose floor sits below the floor the shipped
//! metadata declares, is reported under its own tag.
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
use librpm::Tag;
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
    /// The dist-info `Version:` header (dist-info only; egg-info
    /// carries no version this port reads).
    metadata_version: Option<String>,
}

/// A parsed requirement: distribution name, environment marker, extras,
/// and the raw version specifier (possibly empty).
struct Requirement {
    name: String,
    marker: Option<String>,
    extras: Vec<String>,
    specifier: String,
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
        if is_metadata {
            // The Requires-Dist fields of the header block, read
            // through the shared header helper: field names match
            // case-insensitively, the block ends at the first blank
            // line, and folded continuation lines are not headers.
            return Self::metadata_headers(content, "Requires-Dist")
                .iter()
                .map(|req| Self::split_marker(req))
                .collect();
        }
        let mut out = Vec::new();
        let mut section: Option<String> = None;
        for line in content.lines() {
            let line = line.trim();
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

    /// Split `name[extras]; marker` into its parts, keeping the version
    /// specifier: `foo[bar]>=1.0` -> name `foo`, extras `["bar"]`,
    /// specifier `">=1.0"`.
    fn split_marker(req: &str) -> Requirement {
        let mut parts = req.splitn(2, ';');
        let head = parts.next().unwrap_or("").trim();
        let (name, extras, specifier) = Self::split_head(head);
        let marker = parts.next().map(|m| m.trim().to_string());
        Requirement {
            name,
            marker,
            extras,
            specifier,
        }
    }

    /// One header field of a dist-info METADATA: the first of
    /// `metadata_headers`.
    fn metadata_header(content: &str, field: &str) -> Option<String> {
        Self::metadata_headers(content, field).into_iter().next()
    }

    /// All values of one header field of a dist-info METADATA:
    /// header names are matched case-insensitively, and the header
    /// block ends at the first blank line - a `Name:` or `Version:`
    /// line in the long-description body is not a header (#1177
    /// item 8). Folded continuation lines (leading whitespace)
    /// belong to the previous field and are never headers
    /// themselves.
    fn metadata_headers(content: &str, field: &str) -> Vec<String> {
        content
            .lines()
            .take_while(|l| !l.trim().is_empty())
            .filter(|l| !l.starts_with([' ', '\t']))
            .filter_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case(field)
                    .then(|| value.trim().to_string())
            })
            .filter(|v| !v.is_empty())
            .collect()
    }

    /// Split a requirement head (`name[extras]specifier`) into the name,
    /// the extras and the raw version specifier. The name ends at the
    /// first specifier/bracket character (the historical charset
    /// split); extras live between `[` and the first `]`; the version
    /// specifier follows the closing bracket (`Twisted[tls]>=14.0`), so
    /// split on `]` instead of trimming a trailing one that may not be
    /// there.
    fn split_head(head: &str) -> (String, Vec<String>, String) {
        let name_end = head.find(|c| "<>=!~ [(,".contains(c)).unwrap_or(head.len());
        let name = head[..name_end].trim().to_string();
        // A spaced head (`name [extra] >= 1`) leaves the bracket
        // behind the space: trim before testing for it, or the
        // extras are silently dropped (#1177 item 3).
        let mut rest = head[name_end..].trim_start();
        let mut extras = Vec::new();
        if let Some(bracketed) = rest.strip_prefix('[') {
            let (extra_part, after) = match bracketed.split_once(']') {
                Some((e, a)) => (e, a),
                None => (bracketed, ""),
            };
            extras = extra_part
                .split(',')
                .map(|e| e.trim().to_string())
                .filter(|e| !e.is_empty())
                .collect();
            rest = after;
        }
        let mut specifier = rest.trim().to_string();
        // The legacy parenthesised form: `name (>=1.0)`.
        if specifier.len() >= 2 && specifier.starts_with('(') && specifier.ends_with(')') {
            specifier = specifier[1..specifier.len() - 1].trim().to_string();
        }
        (name, extras, specifier)
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
        // implementation_name: pinned to `cpython`, the PEP 508 value of
        // `sys.implementation.name` for the CPython interpreter the
        // `platform_python_implementation` pin above already assumes.
        if let Some(holds) = Self::string_marker_holds(atom, "implementation_name", "cpython") {
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
        static STRING_MARKER_RES: [(&str, OnceLock<Regex>); 7] = [
            ("extra", OnceLock::new()),
            ("implementation_name", OnceLock::new()),
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
        static STRING_MARKER_REV_RES: [(&str, OnceLock<Regex>); 7] = [
            ("extra", OnceLock::new()),
            ("implementation_name", OnceLock::new()),
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
        // pythonX-foo variants, the dotted flavour spelling
        // (`python3.13-foo`) included, as in `classify_atom`.
        for n in Self::module_names(&req.name, &req.extras) {
            names.push(format!("python\\d*(\\.\\d+)?-{}", fancy_regex::escape(&n)));
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
        // A rich require string satisfies through ANY of its atoms,
        // not only the leading one the anchored pattern reaches
        // (#1177 item 10).
        req_names.iter().any(|r| {
            is_match(&re, r)
                || Self::split_rich_atoms(r)
                    .iter()
                    .any(|atom| is_match(&re, atom))
        })
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

/// A PEP 440 version, normalised for comparison (#1024 §3.2/§3.3):
/// release segments compare zero-padded (`2.18` equals `2.18.0`),
/// and the local segment never participates (a `+git` suffix on an
/// equal base is quiet by the issue's ruling).
#[derive(Debug, Clone, PartialEq)]
struct Pep440Version {
    epoch: u64,
    release: Vec<u64>,
    /// Pre-release: (kind rank, number); a < b < c < dev-only.
    pre: Option<(u8, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
}

impl Pep440Version {
    fn is_zero(&self) -> bool {
        self.epoch == 0
            && self.release.iter().all(|&n| n == 0)
            && self.pre.is_none()
            && self.post.is_none()
            && self.dev.is_none()
    }
}

/// Parse a PEP 440 version string; `None` when it is not one. The
/// grammar covered is the one distribution metadata and openSUSE
/// version strings actually use: `[epoch!]release[.pre][.post][.dev]
/// [+local]`, with the letter-spelled pre-release forms (`alpha`,
/// `beta`, `preview`, `rc`, `pre`, `a`, `b`, `c`) and separator
/// variants (`.`, `-`, `_`) normalised.
fn pep440_parse(text: &str) -> Option<Pep440Version> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    // The local segment is dropped for comparison.
    let text = text.split('+').next().unwrap_or("");
    let (epoch, rest) = match text.split_once('!') {
        Some((e, r)) => (e.parse::<u64>().ok()?, r),
        None => (0, text),
    };
    // `X.Y-N` with no letters anywhere is the implicit post-release
    // spelling (`1.0-1` == `1.0.post1`).
    let (rest, tail_post) = split_tail_post(rest);
    // Tokenise into release numbers and letter markers: insert a dot
    // at every digit<->letter boundary, then split on separators.
    let mut norm = String::with_capacity(rest.len());
    let mut prev: Option<char> = None;
    for c in rest.chars() {
        if let Some(p) = prev
            && ((p.is_ascii_digit() && c.is_ascii_alphabetic())
                || (p.is_ascii_alphabetic() && c.is_ascii_digit()))
        {
            norm.push('.');
        }
        norm.push(c);
        prev = Some(c);
    }
    // The marker a letter token opens, waiting for its number.
    #[derive(PartialEq, Clone, Copy)]
    enum Marker {
        Pre(u8),
        Post,
        Dev,
    }
    let mut release: Vec<u64> = Vec::new();
    let mut pre: Option<(u8, u64)> = None;
    let mut post: Option<u64> = tail_post;
    let mut dev: Option<u64> = None;
    let mut pending: Option<Marker> = None;
    // Whether a letter marker has been assigned: a bare number after
    // that closes nothing and is not a version (`1.0a1.2`). The
    // implicit tail post does not count — it precedes the release.
    let mut closed = false;
    for tok in norm.split(['.', '-', '_']) {
        if tok.is_empty() {
            continue;
        }
        if let Ok(n) = tok.parse::<u64>() {
            match pending.take() {
                Some(Marker::Pre(rank)) => {
                    if pre.is_some() {
                        return None;
                    }
                    pre = Some((rank, n));
                    closed = true;
                }
                Some(Marker::Post) => {
                    if post.is_some() {
                        return None;
                    }
                    post = Some(n);
                    closed = true;
                }
                Some(Marker::Dev) => {
                    if dev.is_some() {
                        return None;
                    }
                    dev = Some(n);
                    closed = true;
                }
                None => {
                    if closed {
                        return None;
                    }
                    release.push(n);
                }
            }
            continue;
        }
        // A letter token closes any pending marker at value 0 (the
        // `1.0a` spelling) before opening its own.
        if let Some(m) = pending.take() {
            match m {
                Marker::Pre(rank) => {
                    if pre.is_some() {
                        return None;
                    }
                    pre = Some((rank, 0));
                }
                Marker::Post => {
                    if post.is_some() {
                        return None;
                    }
                    post = Some(0);
                }
                Marker::Dev => {
                    if dev.is_some() {
                        return None;
                    }
                    dev = Some(0);
                }
            }
            closed = true;
        }
        pending = Some(match tok.to_ascii_lowercase().as_str() {
            "dev" => Marker::Dev,
            "post" | "rev" | "r" => Marker::Post,
            "a" | "alpha" => Marker::Pre(0),
            "b" | "beta" => Marker::Pre(1),
            "c" | "rc" | "pre" | "preview" => Marker::Pre(2),
            _ => return None,
        });
    }
    if let Some(m) = pending.take() {
        match m {
            Marker::Pre(rank) => {
                if pre.is_some() {
                    return None;
                }
                pre = Some((rank, 0));
            }
            Marker::Post => {
                if post.is_some() {
                    return None;
                }
                post = Some(0);
            }
            Marker::Dev => {
                if dev.is_some() {
                    return None;
                }
                dev = Some(0);
            }
        }
    }
    if release.is_empty() {
        return None;
    }
    Some(Pep440Version {
        epoch,
        release,
        pre,
        post,
        dev,
    })
}

/// The implicit post-release tail of `X.Y-N` spellings: returns the
/// string without the tail and the post number, when the tail is a
/// lone `-<digits>` and the head carries no letters or markers.
fn split_tail_post(rest: &str) -> (&str, Option<u64>) {
    if let Some((head, tail)) = rest.rsplit_once('-')
        && !tail.is_empty()
        && tail.bytes().all(|b| b.is_ascii_digit())
        && !head.is_empty()
        && head.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && let Ok(n) = tail.parse::<u64>()
    {
        return (head, Some(n));
    }
    (rest, None)
}

/// PEP 440 ordering: epoch, then release (zero-padded), then the
/// pre/post/dev phase (`.devN` alone first, pre-releases before the
/// final, post-releases after; a dev segment sorts before its own
/// phase).
fn pep440_cmp(a: &Pep440Version, b: &Pep440Version) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    if a.epoch != b.epoch {
        return a.epoch.cmp(&b.epoch);
    }
    let n = a.release.len().max(b.release.len());
    for i in 0..n {
        let x = a.release.get(i).copied().unwrap_or(0);
        let y = b.release.get(i).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
    }
    // No pre, no post, with dev: the .devN-of-the-final phase, which
    // sorts before every pre-release.
    let phase = |v: &Pep440Version| match (v.pre.is_some(), v.post.is_some(), v.dev.is_some()) {
        (false, false, true) => 0,
        (true, _, _) => 1,
        (false, false, false) => 2,
        (false, true, _) => 3,
    };
    let (pa, pb) = (phase(a), phase(b));
    if pa != pb {
        return pa.cmp(&pb);
    }
    if let (Some(x), Some(y)) = (a.pre, b.pre)
        && x != y
    {
        return x.cmp(&y);
    }
    if a.post != b.post {
        return a.post.cmp(&b.post);
    }
    // dev sorts ascending, and its absence sorts after any dev.
    match (a.dev, b.dev) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// Normalise an RPM version into PEP 440 space for the #1024
/// comparisons: `~` introduces a pre-release segment and `^` a
/// post-release one, the epoch comes from the header, and any
/// segment that is not PEP 440-shaped (letters fused into a release
/// segment, e.g. `1.2a1` snapshot suffixes) keeps the string
/// unparsable rather than guessing — the caller then stays quiet.
fn rpm_to_pep440(version: &str, epoch: Option<i64>) -> Option<Pep440Version> {
    let epoch_prefix = match epoch {
        Some(e) if e > 0 => format!("{e}!"),
        _ => String::new(),
    };
    let mut out = String::with_capacity(version.len() + 8);
    out.push_str(&epoch_prefix);
    let mut chars = version.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            // `~` marks what follows as a pre-release of the version
            // in front of it. A letter segment after it is the
            // pre-release itself (`1.0~rc1` is `1.0rc1`), so the
            // marker contributes nothing; a bare number after it is
            // a snapshot counter and becomes a dev segment
            // (`5.0~1` is `5.0.dev1`).
            '~' => {
                if chars.peek().is_some_and(|n| n.is_ascii_digit()) {
                    out.push_str(".dev");
                }
            }
            '^' => {
                // `^` needs a release in front of it to post-date; at
                // the start it is not a version. The generator
                // spelling repeats the marker (`2.9^post0`): consume
                // a literal `post` after the caret instead of
                // emitting it twice.
                if out.len() == epoch_prefix.len() {
                    return None;
                }
                out.push_str(".post");
                let rest: String = chars.clone().collect();
                if rest
                    .get(..4)
                    .is_some_and(|head| head.eq_ignore_ascii_case("post"))
                {
                    for _ in 0..4 {
                        chars.next();
                    }
                }
            }
            _ => out.push(c),
        }
    }
    pep440_parse(&out)
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
                    metadata_version: None,
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
                let dist_name = Self::metadata_header(&content, "Name");
                let metadata_version = Self::metadata_header(&content, "Version");
                dist_infos.push(DistInfo {
                    reqs,
                    python_version,
                    dir,
                    dist_name,
                    metadata_version,
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
        // Dist-info version coherence (#1024 §3.2): the package's own
        // dist-info version against the RPM version.
        for di in &dist_infos {
            self.check_dist_info_version(pkg, out, di);
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

/// How a declared requirement is met by the package (#1024 §3.1).
enum Satisfaction {
    Satisfied,
    /// Met only by bare `python-<name>` Require(s); carries the
    /// first such require string for the finding detail.
    BareOnly(String),
    Missing,
}

/// How the require strings classify against a requirement's variants.
enum MatchClass {
    Full,
    BareOnly(String),
    Unknown,
}

/// One require atom's shape against a requirement's variants.
enum AtomMatch {
    Full,
    Bare,
}

/// The floor state of one RPM require leaf (#1177 item 2): a leaf
/// carrying a version constraint whose value yields no usable
/// floor is `Versioned`, never `Unversioned` - only a leaf with
/// no version constraint at all is unversioned.
enum LeafFloor {
    /// No version constraint on the leaf.
    Unversioned,
    /// A version constraint is present but yields no usable floor
    /// (an upper bound only, or a version that does not parse).
    Versioned,
    /// A usable floor.
    Floor(Pep440Version),
}

impl PythonCheck {
    /// `python-missing-require`: declared requirements the RPM requires
    /// do not satisfy. A requirement met only by a bare `python-<name>`
    /// Require is reported as `python-unflavoured-require` instead
    /// (#1024 §3.1), and every kept requirement also goes through the
    /// floor comparison (`python-require-floor-below-metadata` and
    /// `python-require-unversioned-despite-metadata-floor`, #1024
    /// §3.3).
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
            match Self::require_satisfaction(pkg, req) {
                Satisfaction::Satisfied => {}
                Satisfaction::BareOnly(bare) => {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "python-unflavoured-require",
                        &[&bare],
                    );
                }
                Satisfaction::Missing => {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "python-missing-require",
                        &[&req.name],
                    );
                }
            }
            Self::check_require_floor(pkg, out, req);
        }
    }

    /// How a declared requirement is met by the package itself (#1024
    /// §3.1): by one of its own `python3.Xdist()` Provides, by a
    /// flavoured or dist-spelled RPM Require, only by a bare
    /// `python-<name>` Require, or not at all.
    fn require_satisfaction(pkg: &Pkg, req: &Requirement) -> Satisfaction {
        let variants = Self::module_names(&req.name, &req.extras);
        // The package's own `python3.Xdist()` Provides satisfy: the
        // reference ignores them, so a package shipping the very dist
        // it declares a requirement on (python313-ua-parser on
        // `ua-parser-builtins`) warned on itself.
        let own_provides = pkg.provides.iter().flat_map(|p| p.leaves()).any(|leaf| {
            Self::dist_provide_inner(&Self::leaf_capability(&leaf))
                .is_some_and(|inner| variants.iter().any(|v| v.eq_ignore_ascii_case(inner)))
        });
        if own_provides {
            return Satisfaction::Satisfied;
        }
        if !Self::require_satisfied(&pkg.req_names, req) {
            return Satisfaction::Missing;
        }
        match Self::classify_matches(pkg, &variants) {
            MatchClass::Full | MatchClass::Unknown => Satisfaction::Satisfied,
            MatchClass::BareOnly(bare) => Satisfaction::BareOnly(bare),
        }
    }

    /// Classify how the package's requires match a requirement's
    /// name variants, per `or` branch as the floor comparison
    /// judges them: a branch whose matching leaves are all bare
    /// `python-<name>` atoms is a bare branch, and one bare branch
    /// makes the match bare-only however fully shaped a sibling
    /// branch is (an alternative that resolves through the bare
    /// name guarantees no flavour); a branch mixing bare and
    /// fully-shaped matching leaves counts as fully shaped. With
    /// no bare branch, any fully-shaped branch (the name itself, a
    /// `python<digits>-` flavour name, a `python3.Xdist()` spelling)
    /// makes the match full. Shapes no branch classifies leave the
    /// match `Unknown`, and the caller keeps the historical
    /// satisfied verdict — the bare-only demotion must never invent
    /// a finding.
    fn classify_matches(pkg: &Pkg, variants: &[String]) -> MatchClass {
        let mut bare: Option<String> = None;
        let mut any_full = false;
        for dep in pkg.requires.iter().chain(&pkg.prereq) {
            for branch in Self::require_branches(dep) {
                let mut branch_full = false;
                let mut branch_bare = false;
                for leaf in &branch {
                    match Self::classify_atom(&Self::leaf_capability(leaf), variants) {
                        Some(AtomMatch::Full) => branch_full = true,
                        Some(AtomMatch::Bare) => branch_bare = true,
                        None => {}
                    }
                }
                if branch_bare && !branch_full {
                    if bare.is_none() {
                        bare = Some(dep.name.clone());
                    }
                } else if branch_full {
                    any_full = true;
                }
            }
        }
        if let Some(bare) = bare {
            return MatchClass::BareOnly(bare);
        }
        if any_full {
            return MatchClass::Full;
        }
        MatchClass::Unknown
    }

    /// The atoms of a require string: a plain name yields itself; a
    /// rich `(a or b)` expression yields its requirement atoms,
    /// recursing into parenthesised groups. Segments behind an
    /// `if` / `unless` / `else` keyword are conditions, not
    /// requirements, and end the list at that nesting level.
    fn split_rich_atoms(req_name: &str) -> Vec<String> {
        let mut out = Vec::new();
        Self::split_rich_into(req_name.trim(), &mut out, 0);
        out
    }

    fn split_rich_into(s: &str, out: &mut Vec<String>, nesting: usize) {
        let mut atoms = Vec::new();
        let mut depth = 0i32;
        let mut current = String::new();
        for word in s.split_whitespace() {
            for c in word.chars() {
                match c {
                    '(' => depth += 1,
                    // Clamp at zero: a stray `)` must not push the
                    // depth negative and deaden every following
                    // depth-0 operator (#1177 item 4).
                    ')' => depth = (depth - 1).max(0),
                    _ => {}
                }
            }
            if depth == 0 && matches!(word, "and" | "or" | "with" | "without") {
                atoms.push(std::mem::take(&mut current));
                continue;
            }
            if depth == 0 && matches!(word, "if" | "unless" | "else") {
                // The condition tail belongs to the segment being
                // built; the atoms collected so far (plus this one)
                // are the requirement side.
                break;
            }
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
        if !current.trim().is_empty() {
            atoms.push(current);
        }
        for atom in atoms {
            let atom = atom.trim();
            // A fully parenthesised group is a sub-expression: its
            // atoms are the requirements.
            if atom.len() >= 2 && atom.starts_with('(') && atom.ends_with(')') {
                let inner = &atom[1..atom.len() - 1];
                // Only recurse when the opening paren really spans
                // the whole atom (balanced at the last character).
                let mut d = 0i32;
                let mut spans = true;
                for (i, c) in inner.char_indices() {
                    match c {
                        '(' => d += 1,
                        ')' => {
                            d -= 1;
                            if d < 0 && i != inner.len() - 1 {
                                spans = false;
                            }
                        }
                        _ => {}
                    }
                }
                if spans && nesting < crate::pkg::dep::MAX_RICH_DEP_DEPTH {
                    Self::split_rich_into(inner.trim(), out, nesting + 1);
                    continue;
                }
            }
            // Only a leading grouping paren can cling to a leaf
            // atom (a group the splitter did not recurse into); a
            // trailing one is part of the atom itself
            // (`python3.13dist(<name>)`).
            let cleaned = atom.trim_start_matches('(').trim().to_string();
            if !cleaned.is_empty() {
                out.push(cleaned);
            }
        }
    }

    /// Classify one require atom against a requirement's name
    /// variants: `Full` for the name itself, a flavoured
    /// `python<digits>-<name>` (or the dotted `python3.13-<name>`
    /// spelling), or a `python3.Xdist(<name>)` spelling;
    /// `Bare` for the unflavoured `python-<name>` only.
    fn classify_atom(atom: &str, variants: &[String]) -> Option<AtomMatch> {
        // The atom's name token: up to whitespace or a comparison
        // operator (a version tail may follow).
        let name = atom
            .split(|c: char| c.is_whitespace() || "<>=!".contains(c))
            .next()
            .unwrap_or("")
            .trim();
        if name.is_empty() {
            return None;
        }
        let in_variants = |n: &str| variants.iter().any(|v| v.eq_ignore_ascii_case(n));
        if let Some(inner) = Self::dist_provide_inner(name) {
            return in_variants(inner).then_some(AtomMatch::Full);
        }
        if in_variants(name) {
            return Some(AtomMatch::Full);
        }
        // The flavour prefix matches case-insensitively, like the
        // variant comparison itself (#1177 item 7).
        let rest = name
            .get(.."python".len())
            .filter(|p| p.eq_ignore_ascii_case("python"))
            .map(|_| &name["python".len()..]);
        if let Some(rest) = rest
            && let Some((digits, sub)) = rest.split_once('-')
        {
            if digits.bytes().any(|b| b.is_ascii_digit())
                && digits.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            {
                return in_variants(sub).then_some(AtomMatch::Full);
            }
            if digits.is_empty() {
                return in_variants(sub).then_some(AtomMatch::Bare);
            }
        }
        None
    }

    /// The full capability a require leaf names. Rich-expression
    /// leaves split the name from its qualifier
    /// (`python3.13dist` / `dulwich`), while a plain header leaf
    /// keeps the whole spelling in its name; reconstruct the
    /// `name(qualifier)` form for the split shape so classification
    /// sees the capability it would see in the plain shape.
    fn leaf_capability(leaf: &crate::pkg::dep::DepLeaf) -> String {
        match &leaf.qualifier {
            Some(q) if !leaf.name.contains('(') => format!("{}({})", leaf.name, q),
            _ => leaf.name.clone(),
        }
    }

    /// The inner name of a `python3.Xdist(<name>)` capability, if the
    /// string has that shape.
    fn dist_provide_inner(name: &str) -> Option<&str> {
        static DIST_RE: OnceLock<Regex> = OnceLock::new();
        let re = DIST_RE.get_or_init(|| {
            Regex::new(r"(?i)^python\d+(\.\d+)?dist\(([^()]*)\)$").expect("static regex")
        });
        let caps = re.captures(name).ok().flatten()?;
        caps.get(2).map(|m| m.as_str())
    }

    /// The alternative branches of one require entry (#1177
    /// item 9): a plain entry is a single branch holding its
    /// leaves; a rich entry splits at `or` - each alternative is
    /// its own branch, with `and`/`with`/`without` groups combined
    /// into every branch they join and `if`/`unless` contributing
    /// their `then` side. Past the shared rich-depth budget of
    /// branches the entry falls back to one pooled branch of all
    /// its leaves.
    fn require_branches(dep: &crate::pkg::dep::DepInfo) -> Vec<Vec<crate::pkg::dep::DepLeaf>> {
        use crate::pkg::dep::{DepExpr, DepLeaf, MAX_RICH_DEP_DEPTH, parse_dep_expr};

        fn walk(expr: &DepExpr, depth: usize) -> Option<Vec<Vec<DepLeaf>>> {
            if depth > MAX_RICH_DEP_DEPTH {
                return None;
            }
            match expr {
                DepExpr::Simple {
                    name,
                    qualifier,
                    flags,
                    epoch,
                    version,
                    release,
                } => Some(vec![vec![DepLeaf {
                    name: name.clone(),
                    qualifier: qualifier.clone(),
                    flags: *flags,
                    epoch: *epoch,
                    version: version.clone(),
                    release: release.clone(),
                }]]),
                DepExpr::Or(children) => {
                    let mut out = Vec::new();
                    for child in children {
                        out.extend(walk(child, depth + 1)?);
                        if out.len() > MAX_RICH_DEP_DEPTH {
                            return None;
                        }
                    }
                    Some(out)
                }
                DepExpr::And(children) => {
                    let mut acc: Vec<Vec<DepLeaf>> = vec![Vec::new()];
                    for child in children {
                        let branches = walk(child, depth + 1)?;
                        let mut next = Vec::new();
                        for a in &acc {
                            for b in &branches {
                                let mut joined = a.clone();
                                joined.extend(b.iter().cloned());
                                next.push(joined);
                                if next.len() > MAX_RICH_DEP_DEPTH {
                                    return None;
                                }
                            }
                        }
                        acc = next;
                    }
                    Some(acc)
                }
                DepExpr::With { lhs, rhs } | DepExpr::Without { lhs, rhs } => {
                    let lhs_branches = walk(lhs, depth + 1)?;
                    let rhs_branches = walk(rhs, depth + 1)?;
                    let mut out = Vec::new();
                    for a in &lhs_branches {
                        for b in &rhs_branches {
                            let mut joined = a.clone();
                            joined.extend(b.iter().cloned());
                            out.push(joined);
                            if out.len() > MAX_RICH_DEP_DEPTH {
                                return None;
                            }
                        }
                    }
                    Some(out)
                }
                DepExpr::If { then, .. } | DepExpr::Unless { then, .. } => walk(then, depth + 1),
            }
        }

        match parse_dep_expr(&dep.name) {
            DepExpr::Simple { .. } => vec![dep.leaves()],
            expr => walk(&expr, 0).unwrap_or_else(|| vec![dep.leaves()]),
        }
    }

    /// The floor comparison (#1024 §3.3): a kept requirement whose
    /// declared lower bound the matching RPM Requires do not carry.
    /// The verdict is computed per require entry first (#1177
    /// item 9): each `or` branch of a rich entry is judged on its
    /// own leaves — a branch carrying a usable floor is governed by
    /// that floor (a branch mixing floored and unversioned matching
    /// leaves counts as floored), and an entry with an unversioned
    /// branch is an unversioned entry even when a sibling branch
    /// carries a floor, its own floors then not credited. Separate
    /// entries are conjunctive, so the per-entry verdicts join:
    /// the entries' floors join by maximum — a joined floor below
    /// the metadata's fires `python-require-floor-below-metadata`,
    /// a joined floor at or above it is quiet — and only when no
    /// entry carries a floor does an unversioned entry fire
    /// `python-require-unversioned-despite-metadata-floor`. A
    /// requirement no RPM Require names at all is
    /// `python-missing-require`'s finding, not these ones', and a
    /// requirement met by the package's own Provides has no RPM
    /// floor to compare.
    fn check_require_floor(pkg: &Pkg, out: &mut Filter, req: &Requirement) {
        let Some((floor, floor_text)) = Self::metadata_floor(req) else {
            return;
        };
        let variants = Self::module_names(&req.name, &req.extras);
        let mut any_match = false;
        let mut any_unversioned_entry = false;
        let mut joined_floor: Option<(Pep440Version, String)> = None;
        for dep in pkg.requires.iter().chain(&pkg.prereq) {
            let mut entry_match = false;
            let mut entry_unversioned = false;
            let mut entry_floor: Option<(Pep440Version, String)> = None;
            for branch in Self::require_branches(dep) {
                let mut branch_match = false;
                let mut branch_unversioned = false;
                let mut branch_highest: Option<(Pep440Version, String)> = None;
                for leaf in &branch {
                    if Self::classify_atom(&Self::leaf_capability(leaf), &variants).is_none() {
                        continue;
                    }
                    branch_match = true;
                    match Self::leaf_floor(leaf) {
                        LeafFloor::Unversioned => branch_unversioned = true,
                        LeafFloor::Versioned => {}
                        LeafFloor::Floor(leaf_floor) => {
                            let floor_str = match leaf.epoch {
                                Some(e) if e > 0 => {
                                    format!("{e}:{}", leaf.version.as_deref().unwrap_or(""))
                                }
                                _ => leaf.version.clone().unwrap_or_default(),
                            };
                            if branch_highest.as_ref().is_none_or(|(h, _)| {
                                pep440_cmp(&leaf_floor, h) == std::cmp::Ordering::Greater
                            }) {
                                branch_highest = Some((leaf_floor, floor_str));
                            }
                        }
                    }
                }
                if !branch_match {
                    continue;
                }
                entry_match = true;
                match branch_highest {
                    Some((h, h_text)) => {
                        if entry_floor
                            .as_ref()
                            .is_none_or(|(b, _)| pep440_cmp(&h, b) == std::cmp::Ordering::Greater)
                        {
                            entry_floor = Some((h, h_text));
                        }
                    }
                    None if branch_unversioned => entry_unversioned = true,
                    None => {}
                }
            }
            if !entry_match {
                continue;
            }
            any_match = true;
            if entry_unversioned {
                any_unversioned_entry = true;
            } else if let Some(f) = entry_floor
                && joined_floor
                    .as_ref()
                    .is_none_or(|(b, _)| pep440_cmp(&f.0, b) == std::cmp::Ordering::Greater)
            {
                joined_floor = Some(f);
            }
        }
        if !any_match {
            return;
        }
        match joined_floor {
            Some((f, h_text)) if pep440_cmp(&f, &floor) == std::cmp::Ordering::Less => {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "python-require-floor-below-metadata",
                    &[
                        &req.name,
                        "metadata-floor",
                        &floor_text,
                        "rpm-floor",
                        &h_text,
                    ],
                );
            }
            Some(_) => {}
            None if any_unversioned_entry => {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "python-require-unversioned-despite-metadata-floor",
                    &[
                        &req.name,
                        "metadata-floor",
                        &floor_text,
                        "rpm-floor",
                        "unversioned",
                    ],
                );
            }
            None => {}
        }
    }

    /// The strongest lower bound a requirement's specifier declares
    /// (#1024 §3.3): the largest version among its `>=`, `>`, `~=`
    /// and `==` clauses. The bound is the version value alone — a
    /// `> 2.0` clause contributes 2.0, exactly as the issue defines
    /// the comparison — and `!=`-only requirements declare no bound.
    fn metadata_floor(req: &Requirement) -> Option<(Pep440Version, String)> {
        let mut best: Option<(Pep440Version, String)> = None;
        for clause in req.specifier.split(',') {
            let clause = clause.trim();
            let Some((op, ver)) = ["===", "==", ">=", "<=", "!=", "~=", ">", "<"]
                .iter()
                .find_map(|op| clause.strip_prefix(op).map(|v| (*op, v.trim())))
            else {
                continue;
            };
            if !matches!(op, ">=" | ">" | "~=" | "==" | "===") {
                continue;
            }
            let ver = ver.strip_suffix(".*").unwrap_or(ver);
            let Some(v) = pep440_parse(ver) else {
                continue;
            };
            if best
                .as_ref()
                .is_none_or(|(b, _)| pep440_cmp(&v, b) == std::cmp::Ordering::Greater)
            {
                best = Some((v, ver.to_string()));
            }
        }
        best
    }

    /// The floor state of one RPM require leaf: a `>`/`>=`
    /// constraint, or an exact `=` pin, yields its `Floor`; a
    /// `<`/`<=` constraint bounds from above and yields no floor
    /// but is still `Versioned`, as is a floor-shaped constraint
    /// whose version does not parse. Only a leaf with no version
    /// constraint at all is `Unversioned` (#1177 item 2).
    fn leaf_floor(leaf: &crate::pkg::dep::DepLeaf) -> LeafFloor {
        use crate::pkg::dep::{RPMSENSE_EQUAL, RPMSENSE_GREATER, RPMSENSE_LESS};
        let sense = leaf.flags & (RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL);
        if sense == 0 {
            return LeafFloor::Unversioned;
        }
        if sense & RPMSENSE_GREATER == 0
            && !(sense & RPMSENSE_EQUAL != 0 && sense & RPMSENSE_LESS == 0)
        {
            return LeafFloor::Versioned;
        }
        let Some(version) = leaf.version.as_deref() else {
            return LeafFloor::Versioned;
        };
        rpm_to_pep440(version, leaf.epoch).map_or(LeafFloor::Versioned, LeafFloor::Floor)
    }

    /// `python-dist-info-version-mismatch` (#1024 §3.2): the version
    /// in the package's own dist-info METADATA disagrees with the RPM
    /// version under PEP 440. The version-0 arm — an own-name
    /// dist-info at 0.0.0 in a non-0 RPM, the metadata never stamped —
    /// fires for any source package; the general arm is scoped to
    /// `python-*` sources. A dist-info that is not the package's own
    /// (its `Name` does not PEP 503-match the package key) never
    /// fires.
    fn check_dist_info_version(&self, pkg: &Pkg, out: &mut Filter, di: &DistInfo) {
        let (Some(dist_name), Some(meta_text)) = (&di.dist_name, &di.metadata_version) else {
            return;
        };
        if pep503(dist_name) != Self::package_key(&pkg.name) {
            return;
        }
        let Some(meta) = pep440_parse(meta_text) else {
            return;
        };
        let rpm_text = pkg.tag_str(Tag::VERSION).unwrap_or_default();
        let Some(rpmv) = rpm_to_pep440(&rpm_text, pkg.tag_i64(Tag::EPOCH)) else {
            return;
        };
        if meta.is_zero() {
            if !rpmv.is_zero() {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "python-dist-info-version-mismatch",
                    &[dist_name, meta_text, &rpm_text],
                );
            }
            return;
        }
        if !Self::source_is_python(pkg) {
            return;
        }
        if pep440_cmp(&meta, &rpmv) != std::cmp::Ordering::Equal {
            add_info(
                out,
                Level::Warning,
                pkg,
                "python-dist-info-version-mismatch",
                &[dist_name, meta_text, &rpm_text],
            );
        }
    }

    /// Whether the package's source package is a `python-*` source,
    /// from the `SOURCERPM` header (`python-foo-1.0-1.src.rpm`).
    fn source_is_python(pkg: &Pkg) -> bool {
        let Some(srpm) = pkg.source_rpm.as_deref() else {
            return false;
        };
        let stem = srpm.strip_suffix(".src.rpm").unwrap_or(srpm);
        // Version and release contain no '-': the source name is what
        // precedes the last two dash-separated components.
        let mut parts = stem.rsplitn(3, '-');
        let (Some(_rel), Some(_ver), Some(name)) = (parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        name == "python"
            || name.starts_with("python3.")
            || Self::python_prefixed_rest(name).is_some()
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
    /// Names are compared in PEP 503 canonical form, so a requirement
    /// declared as `jaraco-classes` also accounts for an RPM require
    /// on `python3-jaraco.classes` (the reference compares raw
    /// `-`/`_` variants only and reports that pair).
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
        let wanted: Vec<String> = wanted.iter().map(|n| pep503(n)).collect();
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
                .map(|n| pep503(n))
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
        let stripped = Self::python_prefixed_rest(pkg_name).unwrap_or(pkg_name);
        pep503(stripped)
    }

    /// The part of a `python<digits>-...` name after its python
    /// prefix (`python3-foo` and `python313-foo` both yield
    /// `foo`), or `None` when the name has no such prefix. The
    /// prefix grammar - `python`, digits and dots, a dash - is
    /// the one `package_key` strips (#1177 item 6).
    fn python_prefixed_rest(name: &str) -> Option<&str> {
        let rest = name.strip_prefix("python")?;
        let digits: usize = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .map(|c| c.len_utf8())
            .sum();
        rest[digits..].strip_prefix('-')
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
    fn leftover_pep503_canonical_names_match() {
        // PEP 503 canonical form equates `-`, `_` and `.` in
        // distribution names: metadata declaring `jaraco-classes`
        // accounts for the RPM require `python3-jaraco.classes`
        // (mistral-vibe), and the mirror image holds too. The
        // reference compares raw `-`/`_` variants only and reports
        // both pairs.
        let reqs = PythonCheck::parse_requirements(
            "Metadata-Version: 2.1\nRequires-Dist: jaraco-classes\n",
            true,
            "3.13",
        );
        let got = PythonCheck::leftover_require_strings(
            &["python3-jaraco.classes".to_string()],
            &[(&reqs, "3.13")],
        );
        assert!(got.is_empty(), "unexpected leftovers: {got:?}");

        let reqs = PythonCheck::parse_requirements(
            "Metadata-Version: 2.1\nRequires-Dist: jaraco.classes\n",
            true,
            "3.13",
        );
        let got = PythonCheck::leftover_require_strings(
            &["python3-jaraco-classes".to_string()],
            &[(&reqs, "3.13")],
        );
        assert!(got.is_empty(), "unexpected leftovers: {got:?}");

        // Near miss: a different distribution under the same
        // namespace prefix is not the declared one and still fires.
        let got = PythonCheck::leftover_require_strings(
            &["python3-jaraco-context".to_string()],
            &[(&reqs, "3.13")],
        );
        assert_eq!(got, vec!["python3-jaraco-context".to_string()]);
    }

    #[test]
    fn leftover_implementation_name_marker_is_wanted() {
        // mistral-vibe declares `pycparser` under a marker that only
        // excludes PyPy, aarch64 and non-Linux; with
        // `implementation_name` pinned to the linter's CPython
        // environment the marker holds, the requirement is wanted,
        // and the RPM require is no leftover. The reference,
        // evaluating the real environment, stays quiet here too.
        let content = "Metadata-Version: 2.1\nRequires-Dist: pycparser==3.0; (implementation_name != 'PyPy' and platform_machine != 'aarch64') or (implementation_name != 'PyPy' and platform_python_implementation != 'PyPy') or (implementation_name != 'PyPy' and sys_platform != 'linux')\n";
        let reqs = PythonCheck::parse_requirements(content, true, "3.13");
        let got = PythonCheck::leftover_require_strings(
            &["python3-pycparser".to_string()],
            &[(&reqs, "3.13")],
        );
        assert!(got.is_empty(), "unexpected leftovers: {got:?}");

        // Near miss: the same requirement gated on running under
        // PyPy is not wanted in this environment, so the require
        // stays a leftover.
        let content =
            "Metadata-Version: 2.1\nRequires-Dist: pycparser; implementation_name == \"pypy\"\n";
        let reqs = PythonCheck::parse_requirements(content, true, "3.13");
        let got = PythonCheck::leftover_require_strings(
            &["python3-pycparser".to_string()],
            &[(&reqs, "3.13")],
        );
        assert_eq!(got, vec!["python3-pycparser".to_string()]);
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
    fn marker_pinned_implementation_name() {
        // PEP 508 `implementation_name` is `sys.implementation.name`;
        // the linter's environment is CPython, whose value is
        // `cpython` — the same assumption the
        // `platform_python_implementation` pin makes. The reference
        // evaluates the real environment. Each form gets its own
        // assertion so no arm is dominated by another.
        assert!(PythonCheck::marker_atom_holds(
            "implementation_name == \"cpython\"",
            "3.12"
        ));
        assert!(PythonCheck::marker_atom_holds(
            "implementation_name != \"PyPy\"",
            "3.12"
        ));
        assert!(!PythonCheck::marker_atom_holds(
            "implementation_name == \"pypy\"",
            "3.12"
        ));
        assert!(PythonCheck::marker_atom_holds(
            "\"PyPy\" != implementation_name",
            "3.12"
        ));
        assert!(PythonCheck::marker_atom_holds(
            "implementation_name in \"cpython pypy\"",
            "3.12"
        ));
        assert!(!PythonCheck::marker_atom_holds(
            "implementation_name not in \"cpython pypy\"",
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
            specifier: String::new(),
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

    fn dep(name: &str, flags: u32, version: Option<&str>) -> crate::pkg::dep::DepInfo {
        crate::pkg::dep::DepInfo {
            name: name.to_string(),
            flags,
            epoch: None,
            version: version.map(str::to_string),
            release: None,
        }
    }

    /// Run `check_missing_requirements` over a fixture package the
    /// closure customises (requires / provides / source), returning
    /// every finding as (name, level, line).
    fn findings_with_pkg(
        reqs: &[Requirement],
        mutate: impl FnOnce(&mut Pkg),
    ) -> Vec<(String, Level, String)> {
        use crate::color::Color;
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.name = "python-test".to_string();
        pkg.arch = "noarch".to_string();
        mutate(&mut pkg);
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = PythonCheck::new(&config);
        check.check_missing_requirements(&pkg, &mut out, reqs, "3.13");
        let levels = out.result_levels().to_vec();
        out.results()
            .iter()
            .zip(levels)
            .map(|((name, line), level)| (name.clone(), level, line.clone()))
            .collect()
    }

    fn tags_of(findings: &[(String, Level, String)]) -> Vec<&str> {
        findings.iter().map(|(n, _, _)| n.as_str()).collect()
    }

    #[test]
    fn own_dist_provides_satisfy_requirements() {
        // #1024 §3.1: python313-ua-parser requires
        // `ua-parser-builtins` (Requires-Dist of its own dist) and
        // provides it itself as `python3.13dist(ua-parser-builtins)`.
        // The reference ignores own Provides and warns on the package
        // itself; the provide satisfies here.
        let reqs = PythonCheck::parse_requirements("ua-parser-builtins\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = Vec::new();
            pkg.requires = Vec::new();
            pkg.provides = vec![dep(
                "python3.13dist(ua-parser-builtins)",
                crate::pkg::dep::RPMSENSE_EQUAL,
                Some("0.18.2"),
            )];
        });
        assert!(findings.is_empty(), "findings: {findings:?}");
    }

    #[test]
    fn own_dist_provides_in_rich_expression_satisfy_requirements() {
        // A rich Provides entry's leaves split the capability into
        // name and qualifier (`python3.13dist` / `ua-parser-builtins`);
        // the satisfaction test must reconstruct the `name(qualifier)`
        // spelling, as the floor path does, or the split leaf reads
        // as a bare `python3.13dist` and satisfies nothing.
        let reqs = PythonCheck::parse_requirements("ua-parser-builtins\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = Vec::new();
            pkg.requires = Vec::new();
            pkg.provides = vec![dep(
                "(python3.13dist(ua-parser-builtins) or python3.13dist(ua-parser))",
                0,
                None,
            )];
        });
        assert!(findings.is_empty(), "findings: {findings:?}");
    }

    #[test]
    fn bare_python_require_moves_to_unflavoured_tag() {
        // #1024 §3.1: satisfaction via a bare `python-<name>` Require
        // (the in-toto shape) is reported on the new tag, with the
        // bare require string as the detail.
        let reqs = PythonCheck::parse_requirements("securesystemslib\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = vec!["python-securesystemslib".to_string()];
            pkg.requires = vec![dep("python-securesystemslib", 0, None)];
        });
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let (name, level, line) = &findings[0];
        assert_eq!(name, "python-unflavoured-require");
        assert_eq!(*level, Level::Warning);
        assert_eq!(
            line,
            "python-test.noarch: W: python-unflavoured-require python-securesystemslib"
        );
    }

    #[test]
    fn flavoured_and_dist_spelled_requires_stay_quiet() {
        // #1024 §3.1: only the bare shape moves; the flavoured and
        // dist spellings keep satisfying silently.
        let reqs = PythonCheck::parse_requirements("securesystemslib\n", false, "3.13");
        for req_name in [
            "python313-securesystemslib",
            "python3-securesystemslib",
            "python3.13dist(securesystemslib)",
        ] {
            let findings = check_requirements_findings(&reqs, &[req_name]);
            let non_leftover: Vec<_> = findings
                .iter()
                .filter(|(n, _, _)| n != "python-leftover-require")
                .collect();
            assert!(non_leftover.is_empty(), "{req_name}: {findings:?}");
        }
    }

    #[test]
    fn rich_dep_bare_branch_demotes_despite_full_sibling() {
        // Branches are judged independently, as in the floor
        // comparison: the bare alternative resolves through the
        // unflavoured name and guarantees no flavour, so the match
        // is bare-only even beside a fully-shaped sibling branch.
        let reqs = PythonCheck::parse_requirements("securesystemslib\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names =
                vec!["(python-securesystemslib or python3.13dist(securesystemslib))".to_string()];
            pkg.requires = vec![dep(
                "(python-securesystemslib or python3.13dist(securesystemslib))",
                0,
                None,
            )];
        });
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let (name, _, line) = &findings[0];
        assert_eq!(name, "python-unflavoured-require");
        assert!(line.contains("python-securesystemslib"), "line: {line}");
    }

    #[test]
    fn floor_below_metadata_fires() {
        // #1024 §3.3: the metadata declares `>=0.22`, the RPM floor
        // sits at 0.21.
        let reqs = PythonCheck::parse_requirements("dulwich>=0.22\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = vec!["python3.13dist(dulwich) >= 0.21".to_string()];
            pkg.requires = vec![dep(
                "python3.13dist(dulwich)",
                crate::pkg::dep::RPMSENSE_GREATER | crate::pkg::dep::RPMSENSE_EQUAL,
                Some("0.21"),
            )];
        });
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let (name, level, line) = &findings[0];
        assert_eq!(name, "python-require-floor-below-metadata");
        assert_eq!(*level, Level::Warning);
        assert_eq!(
            line,
            "python-test.noarch: W: python-require-floor-below-metadata dulwich metadata-floor 0.22 rpm-floor 0.21"
        );
    }

    #[test]
    fn floor_rich_dist_require_below_metadata_fires() {
        // Rich leaves split the capability name from its qualifier,
        // so the floor check must reconstruct
        // `python3.13dist(dulwich)` before classifying; the bare
        // name alone never matches and the canonical floored rich
        // shape stayed quiet below the metadata floor.
        let reqs = PythonCheck::parse_requirements("dulwich>=0.22\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = vec![
                "(python3.13dist(dulwich) >= 0.21 or python3.13dist(dulwich) >= 0.21)".to_string(),
            ];
            pkg.requires = vec![dep(
                "(python3.13dist(dulwich) >= 0.21 or python3.13dist(dulwich) >= 0.21)",
                0,
                None,
            )];
        });
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let (name, level, line) = &findings[0];
        assert_eq!(name, "python-require-floor-below-metadata");
        assert_eq!(*level, Level::Warning);
        assert_eq!(
            line,
            "python-test.noarch: W: python-require-floor-below-metadata dulwich metadata-floor 0.22 rpm-floor 0.21"
        );
    }

    #[test]
    fn floor_rich_unversioned_branch_fires_unversioned() {
        // #1177 item 9: branches are judged separately - the
        // floored branch clearing the metadata floor does not hide
        // the unversioned alternative beside it.
        let reqs = PythonCheck::parse_requirements("dulwich>=0.22\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names =
                vec!["(python3.13dist(dulwich) >= 0.30 or python3-dulwich)".to_string()];
            pkg.requires = vec![dep(
                "(python3.13dist(dulwich) >= 0.30 or python3-dulwich)",
                0,
                None,
            )];
        });
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let (name, level, line) = &findings[0];
        assert_eq!(name, "python-require-unversioned-despite-metadata-floor");
        assert_eq!(*level, Level::Warning);
        assert_eq!(
            line,
            "python-test.noarch: W: python-require-unversioned-despite-metadata-floor dulwich metadata-floor 0.22 rpm-floor unversioned"
        );
    }

    #[test]
    fn floor_rich_all_branches_above_floor_stays_quiet() {
        // #1177 item 9: a rich require whose every branch carries a
        // floor above the metadata floor is satisfied.
        let reqs = PythonCheck::parse_requirements("dulwich>=0.22\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = vec![
                "(python3.13dist(dulwich) >= 0.30 or python3.13dist(dulwich) >= 0.25)".to_string(),
            ];
            pkg.requires = vec![dep(
                "(python3.13dist(dulwich) >= 0.30 or python3.13dist(dulwich) >= 0.25)",
                0,
                None,
            )];
        });
        let tags = tags_of(&findings);
        assert!(
            !tags.contains(&"python-require-unversioned-despite-metadata-floor"),
            "findings: {findings:?}"
        );
        assert!(
            !tags.contains(&"python-require-floor-below-metadata"),
            "findings: {findings:?}"
        );
    }

    #[test]
    fn floor_unversioned_entry_joins_floored_entry_by_conjunction() {
        // Separate require entries are conjunctive: the unversioned
        // entry contributes no floor, but the joined floor is the
        // floored entry's, so the below tag fires with it - the
        // unversioned tag fires only when no entry carries a floor.
        let reqs = PythonCheck::parse_requirements("dulwich>=0.22\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = vec![
                "python3-dulwich".to_string(),
                "python3.13dist(dulwich) >= 0.21".to_string(),
            ];
            pkg.requires = vec![
                dep("python3-dulwich", 0, None),
                dep(
                    "python3.13dist(dulwich)",
                    crate::pkg::dep::RPMSENSE_GREATER | crate::pkg::dep::RPMSENSE_EQUAL,
                    Some("0.21"),
                ),
            ];
        });
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let (name, _, line) = &findings[0];
        assert_eq!(name, "python-require-floor-below-metadata");
        assert_eq!(
            line,
            "python-test.noarch: W: python-require-floor-below-metadata dulwich metadata-floor 0.22 rpm-floor 0.21"
        );
    }

    #[test]
    fn floor_unversioned_entry_beside_clearing_entry_is_quiet() {
        // The conjunction again: a sibling entry whose floor meets
        // the metadata's satisfies the requirement, so the
        // unversioned entry fires neither floor tag.
        let reqs = PythonCheck::parse_requirements("dulwich>=0.22\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = vec![
                "python3-dulwich".to_string(),
                "python3.13dist(dulwich) >= 0.22".to_string(),
            ];
            pkg.requires = vec![
                dep("python3-dulwich", 0, None),
                dep(
                    "python3.13dist(dulwich)",
                    crate::pkg::dep::RPMSENSE_GREATER | crate::pkg::dep::RPMSENSE_EQUAL,
                    Some("0.22"),
                ),
            ];
        });
        assert!(findings.is_empty(), "findings: {findings:?}");
    }

    #[test]
    fn split_rich_atoms_deeply_nested_beyond_depth_budget_returns() {
        // A crafted deeply nested require must not recurse without
        // bound and abort the run: past the shared rich-depth
        // budget the remaining group is kept as a leaf atom.
        let nested = format!(
            "{}python3.13dist(dulwich){}",
            "(".repeat(200),
            ")".repeat(200)
        );
        let atoms = PythonCheck::split_rich_atoms(&nested);
        assert!(!atoms.is_empty(), "atoms: {atoms:?}");
    }

    #[test]
    fn floor_unversioned_require_fires() {
        // #1024 §3.3: a matching RPM Require with no version at all
        // carries no floor.
        let reqs = PythonCheck::parse_requirements("dulwich>=0.22\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = vec!["python3-dulwich".to_string()];
            pkg.requires = vec![dep("python3-dulwich", 0, None)];
        });
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let (name, level, line) = &findings[0];
        assert_eq!(name, "python-require-unversioned-despite-metadata-floor");
        assert_eq!(*level, Level::Warning);
        assert_eq!(
            line,
            "python-test.noarch: W: python-require-unversioned-despite-metadata-floor dulwich metadata-floor 0.22 rpm-floor unversioned"
        );
    }

    #[test]
    fn rpm_to_pep440_caret_multibyte_straddle_does_not_panic() {
        // #1177 item 1: the `post` probe after `^` sliced the
        // remaining string at byte 4; a multibyte character
        // straddling that offset panicked the conversion.
        let _ = rpm_to_pep440("1.0^a\u{e9}\u{e9}", None);
        // The generator spelling is still consumed as a post segment.
        assert!(rpm_to_pep440("2.9^post0", None).is_some());
    }

    #[test]
    fn floor_unparsable_versioned_require_stays_quiet() {
        // #1177 item 2: a matching Require carrying a version whose
        // value does not parse is versioned, not unversioned:
        // neither floor tag fires for it alone.
        let reqs = PythonCheck::parse_requirements("dulwich>=0.22\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = vec!["python3.13dist(dulwich) >= notaversion".to_string()];
            pkg.requires = vec![dep(
                "python3.13dist(dulwich)",
                crate::pkg::dep::RPMSENSE_GREATER | crate::pkg::dep::RPMSENSE_EQUAL,
                Some("notaversion"),
            )];
        });
        let tags = tags_of(&findings);
        assert!(
            !tags.contains(&"python-require-unversioned-despite-metadata-floor"),
            "findings: {findings:?}"
        );
        assert!(
            !tags.contains(&"python-require-floor-below-metadata"),
            "findings: {findings:?}"
        );
    }

    #[test]
    fn floor_unversioned_leaf_fires_alongside_unparsable_one() {
        // #1177 item 2: an unparsable versioned leaf does not mask
        // a truly unversioned matching leaf.
        let reqs = PythonCheck::parse_requirements("dulwich>=0.22\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = vec![
                "python3-dulwich".to_string(),
                "python3.13dist(dulwich) >= notaversion".to_string(),
            ];
            pkg.requires = vec![
                dep("python3-dulwich", 0, None),
                dep(
                    "python3.13dist(dulwich)",
                    crate::pkg::dep::RPMSENSE_GREATER | crate::pkg::dep::RPMSENSE_EQUAL,
                    Some("notaversion"),
                ),
            ];
        });
        let unversioned: Vec<_> = findings
            .iter()
            .filter(|(n, _, _)| n == "python-require-unversioned-despite-metadata-floor")
            .collect();
        assert_eq!(unversioned.len(), 1, "findings: {findings:?}");
    }

    #[test]
    fn split_head_spaced_extras_are_parsed() {
        // #1177 item 3: a space before the extras bracket must not
        // silently drop the extras.
        let (name, extras, specifier) = PythonCheck::split_head("Twisted [tls]>=14.0");
        assert_eq!(name, "Twisted");
        assert_eq!(extras, vec!["tls".to_string()]);
        assert_eq!(specifier, ">=14.0");
    }

    #[test]
    fn split_rich_atoms_stray_paren_keeps_operators_live() {
        // #1177 item 4: a stray `)` clamps the depth at zero
        // instead of pushing it negative, which deadened every
        // following depth-0 operator.
        let atoms = PythonCheck::split_rich_atoms("python3-a) or python3-b");
        assert_eq!(
            atoms,
            vec!["python3-a)".to_string(), "python3-b".to_string()]
        );
    }

    #[test]
    fn split_rich_atoms_without_is_an_operator() {
        // #1177 item 4: `without` separates atoms at depth 0,
        // like `with` does.
        let atoms = PythonCheck::split_rich_atoms("(python3-a without python3-b)");
        assert_eq!(
            atoms,
            vec!["python3-a".to_string(), "python3-b".to_string()]
        );
    }

    #[test]
    fn split_rich_atoms_whitespace_variants_split() {
        // #1177 item 4: tabs and runs of spaces separate words
        // exactly like single spaces.
        let atoms = PythonCheck::split_rich_atoms("python3-a\tor  python3-b");
        assert_eq!(
            atoms,
            vec!["python3-a".to_string(), "python3-b".to_string()]
        );
    }

    #[test]
    fn dist_info_version_mismatch_fires_for_python3_dash_sources() {
        // #1177 item 6: `python3-foo` and `python313-foo` source
        // names are python sources too, not only `python-foo`.
        for source in ["python3-foo-2.0-1.src.rpm", "python313-foo-2.0-1.src.rpm"] {
            let findings = dist_info_findings("python3-foo", Some(source), "foo", "2.0");
            assert_eq!(findings.len(), 1, "{source}: {findings:?}");
            assert_eq!(findings[0].0, "python-dist-info-version-mismatch");
        }
        // A non-python source stays quiet on the general arm.
        let findings =
            dist_info_findings("python3-foo", Some("kde-foo-2.0-1.src.rpm"), "foo", "2.0");
        assert!(findings.is_empty(), "findings: {findings:?}");
    }

    #[test]
    fn classify_atom_flavour_prefix_is_case_insensitive() {
        // #1177 item 7: the `python` flavour prefix matches
        // case-insensitively, like the variant comparison itself.
        let variants = vec!["dulwich".to_string()];
        assert!(matches!(
            PythonCheck::classify_atom("Python3-dulwich", &variants),
            Some(AtomMatch::Full)
        ));
        assert!(matches!(
            PythonCheck::classify_atom("PYTHON313-dulwich", &variants),
            Some(AtomMatch::Full)
        ));
        assert!(matches!(
            PythonCheck::classify_atom("Python-dulwich", &variants),
            Some(AtomMatch::Bare)
        ));
    }

    #[test]
    fn classify_atom_dotted_flavour_is_full() {
        // #1177 item 5: the dotted flavour spelling
        // (`python3.13-dulwich`) classifies Full, as the check's
        // description promises; a dotted non-flavour and a dotted
        // flavour on a different module stay unmatched.
        let variants = vec!["dulwich".to_string()];
        assert!(matches!(
            PythonCheck::classify_atom("python3.13-dulwich", &variants),
            Some(AtomMatch::Full)
        ));
        assert!(PythonCheck::classify_atom("python3.x-dulwich", &variants).is_none());
        assert!(PythonCheck::classify_atom("python3.13-other", &variants).is_none());
        // A flavour of only dots carries no digit and is no flavour.
        assert!(PythonCheck::classify_atom("python.-dulwich", &variants).is_none());
        assert!(PythonCheck::classify_atom("python..-dulwich", &variants).is_none());
    }

    #[test]
    fn metadata_requires_dist_uses_the_header_block() {
        // Requires-Dist extraction shares the header helper: the
        // field name matches case-insensitively, a folded
        // continuation line is not a header, and the block ends at
        // the first blank line.
        let content = "Metadata-Version: 2.1\nName: demo\nDescription: folded\n Requires-Dist: foldedfake\nrequires-dist: lowerreq\nRequires-Dist: realreq>=1.0\n\nRequires-Dist: bodyreq\n";
        let reqs = PythonCheck::parse_requirements(content, true, "3.13");
        let names: Vec<&str> = reqs.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["lowerreq", "realreq"]);
    }

    #[test]
    fn metadata_header_is_case_insensitive_and_stops_at_blank_line() {
        // #1177 item 8: header names match case-insensitively, and
        // the header block ends at the first blank line.
        let content = "Metadata-Version: 2.1\nname: foo\nVersion: 1.2\n\nVersion: 9.9\n";
        assert_eq!(
            PythonCheck::metadata_header(content, "Name"),
            Some("foo".to_string())
        );
        assert_eq!(
            PythonCheck::metadata_header(content, "Version"),
            Some("1.2".to_string())
        );
        let body_only = "Metadata-Version: 2.1\n\nName: bar\n";
        assert_eq!(PythonCheck::metadata_header(body_only, "Name"), None);
    }

    #[test]
    fn dotted_flavour_require_satisfies_end_to_end() {
        // The dotted flavour spelling classifies Full, and the
        // satisfaction pattern accepts the same grammar, so a
        // `python3.13-<name>` Require at the metadata floor leaves
        // no missing, unflavoured or floor finding.
        let reqs = PythonCheck::parse_requirements("dulwich>=0.22\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = vec!["python3.13-dulwich >= 0.22".to_string()];
            pkg.requires = vec![dep(
                "python3.13-dulwich",
                crate::pkg::dep::RPMSENSE_GREATER | crate::pkg::dep::RPMSENSE_EQUAL,
                Some("0.22"),
            )];
        });
        assert!(findings.is_empty(), "findings: {findings:?}");
    }

    #[test]
    fn require_satisfied_matches_non_leading_rich_atom() {
        // #1177 item 10: satisfaction can come from any atom of a
        // rich require, not only the leading one.
        let req_names = vec!["(python3-other or python3-requests)".to_string()];
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
    fn floor_met_or_exceeded_stays_quiet() {
        // #1024 §3.3: RPM floors at or above the metadata floor.
        let reqs = PythonCheck::parse_requirements("dulwich>=0.22\n", false, "3.13");
        for rpm_ver in ["0.22", "0.23", "1.0"] {
            let findings = findings_with_pkg(&reqs, |pkg| {
                pkg.req_names = vec![format!("python3.13dist(dulwich) >= {rpm_ver}")];
                pkg.requires = vec![dep(
                    "python3.13dist(dulwich)",
                    crate::pkg::dep::RPMSENSE_GREATER | crate::pkg::dep::RPMSENSE_EQUAL,
                    Some(rpm_ver),
                )];
            });
            assert!(findings.is_empty(), "rpm {rpm_ver}: {findings:?}");
        }
    }

    #[test]
    fn floor_generator_caret_spelling_counts_as_post() {
        // #1024 §3.3 quiet rule: the generator spelling
        // `>= 2.9^post0` is a floor of 2.9.post0 and meets a
        // metadata floor of 2.9. (The require string itself keeps
        // whatever `python-missing-require` verdict the reference
        // gives it — the `^` is outside that check's version
        // grammar; only the floor tag is asserted here.)
        let reqs = PythonCheck::parse_requirements("something>=2.9\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = vec!["python3.13dist(something) >= 2.9^post0".to_string()];
            pkg.requires = vec![dep(
                "python3.13dist(something)",
                crate::pkg::dep::RPMSENSE_GREATER | crate::pkg::dep::RPMSENSE_EQUAL,
                Some("2.9^post0"),
            )];
        });
        assert!(
            !tags_of(&findings).contains(&"python-require-floor-below-metadata"),
            "findings: {findings:?}"
        );
        // The reconstructed floor is a floor: the unversioned tag,
        // which fires only when no usable floor exists, stays quiet
        // as well -- neither floor tag may fire on the caret shape.
        assert!(
            !tags_of(&findings).contains(&"python-require-unversioned-despite-metadata-floor"),
            "findings: {findings:?}"
        );
    }

    #[test]
    fn floor_not_equal_only_requirement_declares_no_floor() {
        // #1024 §3.3 quiet rule: `!=`-only requirements have no
        // lower bound to compare.
        let reqs = PythonCheck::parse_requirements("dulwich!=0.22\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = vec!["python3-dulwich".to_string()];
            pkg.requires = vec![dep("python3-dulwich", 0, None)];
        });
        assert!(findings.is_empty(), "findings: {findings:?}");
    }

    #[test]
    fn floor_without_rpm_match_is_missing_require_only() {
        // #1024 §3.3: no RPM Require names the requirement at all —
        // that is `python-missing-require`'s finding alone.
        let reqs = PythonCheck::parse_requirements("dulwich>=0.22\n", false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = Vec::new();
            pkg.requires = Vec::new();
        });
        assert_eq!(tags_of(&findings), ["python-missing-require"]);
    }

    #[test]
    fn floor_marker_false_branch_stays_quiet() {
        // #1024 §3.3 quiet rule (the python313-mistral-common
        // shape): the strict floor sits under a marker that is false
        // for this dist-info's python; the true branch's floor is
        // what the RPM Requires carry.
        let content = "mistral-lib>=2.12; python_version >= \"3.14\"\n\
                       mistral-lib>=2.7; python_version < \"3.14\"\n";
        let reqs = PythonCheck::parse_requirements(content, false, "3.13");
        let findings = findings_with_pkg(&reqs, |pkg| {
            pkg.req_names = vec!["python3.13dist(mistral-lib) >= 2.7".to_string()];
            pkg.requires = vec![dep(
                "python3.13dist(mistral-lib)",
                crate::pkg::dep::RPMSENSE_GREATER | crate::pkg::dep::RPMSENSE_EQUAL,
                Some("2.7"),
            )];
        });
        assert!(findings.is_empty(), "findings: {findings:?}");
    }

    /// Run `check_dist_info_version` over a fixture package; the
    /// fixture's RPM version is `1`.
    fn dist_info_findings(
        pkg_name: &str,
        source_rpm: Option<&str>,
        dist_name: &str,
        metadata_version: &str,
    ) -> Vec<(String, Level, String)> {
        use crate::color::Color;
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.name = pkg_name.to_string();
        pkg.arch = "noarch".to_string();
        pkg.source_rpm = source_rpm.map(str::to_string);
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = PythonCheck::new(&config);
        let di = DistInfo {
            reqs: Vec::new(),
            python_version: "3.13".to_string(),
            dir: String::new(),
            dist_name: Some(dist_name.to_string()),
            metadata_version: Some(metadata_version.to_string()),
        };
        check.check_dist_info_version(&pkg, &mut out, &di);
        let levels = out.result_levels().to_vec();
        out.results()
            .iter()
            .zip(levels)
            .map(|((name, line), level)| (name.clone(), level, line.clone()))
            .collect()
    }

    #[test]
    fn dist_info_version_mismatch_fires_for_python_source() {
        // #1024 §3.2 general arm: own-name dist-info at 2.0 in an
        // RPM at version 1 (the fixture's), python-* source.
        let findings =
            dist_info_findings("python3-foo", Some("python-foo-1-1.src.rpm"), "foo", "2.0");
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        let (name, level, line) = &findings[0];
        assert_eq!(name, "python-dist-info-version-mismatch");
        assert_eq!(*level, Level::Warning);
        assert_eq!(
            line,
            "python3-foo.noarch: W: python-dist-info-version-mismatch foo 2.0 1"
        );
    }

    #[test]
    fn dist_info_pep440_equal_spelling_stays_quiet() {
        // #1024 §3.2 quiet rule: `1.0` and the RPM's `1` are the
        // same PEP 440 version (zero-padded release).
        let findings =
            dist_info_findings("python3-foo", Some("python-foo-1-1.src.rpm"), "foo", "1.0");
        assert!(findings.is_empty(), "findings: {findings:?}");
    }

    #[test]
    fn dist_info_mismatch_in_non_python_source_stays_quiet() {
        // #1024 §3.2 scope: the general arm covers `python-*`
        // sources only.
        let findings = dist_info_findings("bar", Some("bar-1-1.src.rpm"), "bar", "2.0");
        assert!(findings.is_empty(), "findings: {findings:?}");
    }

    #[test]
    fn dist_info_version_zero_arm_fires_for_any_source() {
        // #1024 §3.2 version-0 arm: an own-name dist-info stamped
        // 0.0.0 inside a non-0 RPM, whatever the source.
        let findings = dist_info_findings("bar", Some("bar-1-1.src.rpm"), "bar", "0.0.0");
        assert_eq!(findings.len(), 1, "findings: {findings:?}");
        assert_eq!(findings[0].0, "python-dist-info-version-mismatch");
        assert_eq!(
            findings[0].2,
            "bar.noarch: W: python-dist-info-version-mismatch bar 0.0.0 1"
        );
    }

    #[test]
    fn dist_info_not_own_name_stays_quiet() {
        // #1024 §3.2 quiet rule: cockpit-bridge ships a `cockpit`
        // dist-info at 0 — not its own name, never a finding.
        let findings = dist_info_findings(
            "cockpit-bridge",
            Some("cockpit-1-1.src.rpm"),
            "cockpit",
            "0.0.0",
        );
        assert!(findings.is_empty(), "findings: {findings:?}");
    }

    #[test]
    fn pep440_equal_spellings_compare_equal() {
        // #1024 §3.2: the PEP 440 census quiet rules — trailing
        // zero segments and local segments do not differ.
        for (a, b) in [
            ("2.18", "2.18.0"),
            ("1.0", "1"),
            ("1.0+git", "1.0"),
            ("0.33.3+git20150318", "0.33.3"),
            ("1.0a", "1.0a0"),
            ("1.0-1", "1.0.post1"),
            ("1.0_alpha1", "1.0a1"),
        ] {
            let (va, vb) = (pep440_parse(a).unwrap(), pep440_parse(b).unwrap());
            assert_eq!(
                pep440_cmp(&va, &vb),
                std::cmp::Ordering::Equal,
                "{a} vs {b}"
            );
        }
    }

    #[test]
    fn pep440_ordering_follows_the_spec() {
        let chain = [
            "1.0.dev1",
            "1.0a1.dev1",
            "1.0a1",
            "1.0a2",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0.post1.dev1",
            "1.0.post1",
            "1.0.1",
        ];
        for w in chain.windows(2) {
            let (va, vb) = (pep440_parse(w[0]).unwrap(), pep440_parse(w[1]).unwrap());
            assert_eq!(
                pep440_cmp(&va, &vb),
                std::cmp::Ordering::Less,
                "{} < {}",
                w[0],
                w[1]
            );
        }
        let epoch = pep440_parse("1!0.1").unwrap();
        let plain = pep440_parse("2.0").unwrap();
        assert_eq!(pep440_cmp(&epoch, &plain), std::cmp::Ordering::Greater);
    }

    #[test]
    fn pep440_rejects_non_versions() {
        assert!(pep440_parse("").is_none());
        assert!(pep440_parse("abc").is_none());
        assert!(pep440_parse("1.0a1.2").is_none());
        assert!(pep440_parse("1.0.x").is_none());
    }

    #[test]
    fn rpm_versions_translate_to_pep440() {
        // openSUSE spellings: `~` pre-release, `^` post-release, the
        // generator's repeated `^post`, letter suffixes as
        // pre-releases, epochs from the header.
        for (rpm, epoch, pep) in [
            ("1.0~rc1", None, "1.0rc1"),
            ("5.0~1", None, "5.0.dev1"),
            ("2.9^post0", None, "2.9.post0"),
            ("0.1.5a", None, "0.1.5a0"),
            ("2.18.0", None, "2.18"),
            ("1.0", Some(2), "2!1.0"),
        ] {
            let got = rpm_to_pep440(rpm, epoch).unwrap();
            let want = pep440_parse(pep).unwrap();
            assert_eq!(pep440_cmp(&got, &want), std::cmp::Ordering::Equal, "{rpm}");
        }
        assert!(rpm_to_pep440("0", None).unwrap().is_zero());
        assert!(!rpm_to_pep440("0.0.1", None).unwrap().is_zero());
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
            metadata_version: None,
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

    #[test]
    fn reset_clears_provider_suppression_between_packages() {
        // Worker resets between packages; provider metadata from A must
        // not suppress B's leftover. Without the reset B's opencv stays
        // quiet via A's cv2.
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

        let mut provider = mkpkg("python313-opencv", &[]);
        provider.files = vec![PkgFile {
            name: "/usr/lib64/python3.13/site-packages/cv2.cpython-313-x86_64-linux-gnu.so"
                .to_string(),
            ..Default::default()
        }];
        check.check_binary(&provider, &config, &mut out);
        check.reset();

        let mut consumer = mkpkg("python3-consumer", &["python3-foo", "python3-opencv"]);
        let di = "/usr/lib/python3.13/site-packages/consumer-1.0.dist-info";
        consumer.files = vec![
            write(
                &consumer,
                &format!("{di}/METADATA"),
                "Metadata-Version: 2.1\nName: consumer\nVersion: 1.0\nRequires-Dist: foo\n",
            ),
            write(
                &consumer,
                "/usr/lib/python3.13/site-packages/consumer/__init__.py",
                "import cv2\n",
            ),
        ];
        check.check_binary(&consumer, &config, &mut out);

        let findings = after_checks_findings(&mut check);
        assert_eq!(findings.len(), 1, "unexpected findings: {findings:?}");
        assert!(
            findings[0].2.contains("python3-opencv"),
            "findings: {findings:?}"
        );
    }
}
