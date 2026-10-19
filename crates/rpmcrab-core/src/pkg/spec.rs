//! The `.spec` package model — the Rust equivalent of rpmlint's `FakePkg`
//! for spec inputs.
//!
//! A spec is text with line numbers, not an RPM with a payload: there is no
//! header, no file list, no extraction. The reference builds a `FakePkg`
//! around the spec path (`name` is the as-passed path, `is_source` is forced
//! false) and dispatches `check_spec` on holding one.

use std::cell::Cell;
use std::io;
use std::path::{Path, PathBuf};

/// A `.spec` file being linted.
#[derive(Debug)]
pub struct SpecPkg {
    /// The spec path as passed (`pkg.name` in the reference; the finding's
    /// file part is its basename).
    pub name: String,
    /// The spec text, read at [`SpecPkg::open`] time
    /// (`rpmlint.helpers.readlines` at the top of `SpecCheck.check_spec`).
    pub lines: Vec<String>,
    /// The 1-based line the check is currently looking at
    /// (`FakePkg.current_linenum`, rendered as `file.spec:NN:`). Interior
    /// mutability: the `Check` trait hands the check a shared reference,
    /// mirroring how the reference mutates the `FakePkg` it was given.
    pub current_linenum: Cell<Option<u32>>,
}

/// `SpecPkg::open` failures.
#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    /// The spec file could not be read.
    #[error("reading the spec file {path}: {source}")]
    Read {
        /// The spec path as passed.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl SpecPkg {
    /// Open a `.spec` file, reading its lines now. Readability is validated
    /// here: the reference's `validate_file` treats any read failure as
    /// fatal, surfacing when `SpecCheck` first reads the file.
    pub fn open(path: &Path) -> Result<Self, SpecError> {
        let lines = readlines(path).map_err(|source| SpecError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self {
            name: path.to_string_lossy().into_owned(),
            lines,
            current_linenum: Cell::new(None),
        })
    }

    /// The patterns for the package names this spec's own `Name:`
    /// declarations can produce. Multibuild specs compose the name in
    /// the preamble — a `%global flavor` the payload pins,
    /// flavour-conditional affix macros, one literal `Name:` per branch
    /// (util-linux declares util-linux, util-linux-systemd and
    /// python-libmount) — so the declarations expand to a set of
    /// patterns: literal text anchors a pattern, and a macro the
    /// preamble does not define contributes an unconstrained segment.
    /// Macro definitions take effect from their own line on — a
    /// `%undefine` removes a macro's earlier definitions — and the
    /// definitions of every conditional branch count, since branch
    /// conditions are not evaluated. `None` when the preamble
    /// declares no `Name:` at all.
    pub fn declared_name_patterns(&self) -> Option<Vec<NamePattern>> {
        declared_name_patterns(&self.lines)
    }
}

/// The section headers that end the main preamble: the scan runs
/// until the first of these. Every other `%`-led line — macro
/// definitions, conditionals (`%if`, `%ifdef`, `%else`, …),
/// build-conditionals and bare macro invocations — is preamble
/// content the scan reads past.
const SECTION_HEADERS: &[&str] = &[
    "build",
    "changelog",
    "check",
    "clean",
    "conf",
    "configure",
    "description",
    "files",
    "generate_buildrequires",
    "install",
    "package",
    "post",
    "posttrans",
    "postun",
    "pre",
    "prep",
    "pretrans",
    "preun",
    "trigger",
    "triggerin",
    "triggerpostun",
    "triggerun",
    "verify",
];

/// One segment of a [`NamePattern`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NameSegment {
    /// Literal text at this position of the name.
    Literal(String),
    /// Text contributed by a macro whose value the preamble does not
    /// determine; matches any text, including none.
    Any,
}

/// A pattern for a package name a spec's `Name:` declaration can
/// produce: the literal segments must appear in order, anchored at
/// both ends, with [`NameSegment::Any`] segments spanning the rest.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NamePattern(Vec<NameSegment>);

impl NamePattern {
    /// Whether `candidate` is a name this pattern can produce.
    pub fn matches(&self, candidate: &str) -> bool {
        let mut failed = std::collections::HashSet::new();
        self.matches_at(0, candidate.as_bytes(), 0, &mut failed)
    }

    /// Whether this pattern constrains nothing: every segment is
    /// [`NameSegment::Any`], so the pattern produces any name at all.
    pub fn is_unconstrained(&self) -> bool {
        !self.0.is_empty() && self.0.iter().all(|s| matches!(s, NameSegment::Any))
    }

    fn matches_at(
        &self,
        seg: usize,
        candidate: &[u8],
        pos: usize,
        failed: &mut std::collections::HashSet<(usize, usize)>,
    ) -> bool {
        if seg == self.0.len() {
            return pos == candidate.len();
        }
        if failed.contains(&(seg, pos)) {
            return false;
        }
        let ok = match &self.0[seg] {
            NameSegment::Literal(text) => {
                candidate[pos..].starts_with(text.as_bytes())
                    && self.matches_at(seg + 1, candidate, pos + text.len(), failed)
            }
            NameSegment::Any => {
                (pos..=candidate.len()).any(|end| self.matches_at(seg + 1, candidate, end, failed))
            }
        };
        if !ok {
            failed.insert((seg, pos));
        }
        ok
    }
}

/// The preamble scan's yield: the `Name:` values and the
/// macro-environment events, each with its logical-line position.
type PreambleScan = (Vec<(usize, String)>, Vec<(usize, MacroEvent)>);

/// One macro-environment event of the preamble scan: a `%define` /
/// `%global` definition or a `%undefine`, in declaration order.
enum MacroEvent {
    /// `%define name body` / `%global name body`.
    Define(String, String),
    /// `%undefine name`.
    Undefine(String),
}

/// The preamble scan behind [`SpecPkg::declared_name_patterns`]: the
/// `Name:` values and the macro-environment events of the main
/// preamble, each with its logical-line position, in declaration
/// order. The scan stops at the first section header; conditionals,
/// build-conditionals and bare macro invocations are preamble
/// content and the scan reads past them.
fn scan_preamble(lines: &[String]) -> PreambleScan {
    // Join backslash-continued lines first: a definition's or a
    // `Name:` tag's value runs to the end of its logical line.
    let mut logical: Vec<String> = Vec::with_capacity(lines.len());
    for line in lines {
        let line = line.trim();
        match logical.last_mut() {
            Some(prev)
                if prev.ends_with('\\') && (is_definition_line(prev) || is_name_line(prev)) =>
            {
                prev.pop();
                prev.push_str(line);
            }
            _ => logical.push(line.to_string()),
        }
    }

    let mut names = Vec::new();
    let mut events = Vec::new();
    for (pos, line) in logical.iter().enumerate() {
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('%') {
            // A macro-expansion statement (`%{?mpi_flavor:%{bcond_without
            // mpi}}` and friends) is preamble content, not a section:
            // it expands for its side effects and the preamble runs on.
            if rest.starts_with(['{', '(', '[']) {
                continue;
            }
            let directive: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphabetic() || *c == '_')
                .collect();
            match directive.as_str() {
                "define" | "global" => {
                    if let Some((name, body)) = parse_macro(&rest[directive.len()..]) {
                        events.push((pos, MacroEvent::Define(name, body)));
                    }
                }
                "undefine" => {
                    if let Some(name) = parse_undefine(&rest[directive.len()..]) {
                        events.push((pos, MacroEvent::Undefine(name)));
                    }
                }
                d if SECTION_HEADERS.contains(&d) => break,
                _ => {}
            }
            continue;
        }
        let Some((tag, value)) = line.split_once(':') else {
            continue;
        };
        if !tag.trim().eq_ignore_ascii_case("name") {
            continue;
        }
        let value = value.trim();
        if !value.is_empty() {
            names.push((pos, value.to_string()));
        }
    }
    (names, events)
}

/// Whether `line` opens a `%define` / `%global` definition.
fn is_definition_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix('%') else {
        return false;
    };
    ["define", "global"].iter().any(|d| {
        rest.strip_prefix(d)
            .is_some_and(|after| after.is_empty() || after.starts_with(char::is_whitespace))
    })
}

/// Whether `line` is a `Name:` tag line.
fn is_name_line(line: &str) -> bool {
    line.split_once(':')
        .is_some_and(|(tag, _)| tag.trim().eq_ignore_ascii_case("name"))
}

/// Parse one `%define` / `%global` definition from the text after
/// the directive word. Parametric definitions (`%define name(args)
/// body`) define functions, not values, and do not parse.
fn parse_macro(rest: &str) -> Option<(String, String)> {
    let mut parts = rest.trim_start().splitn(2, char::is_whitespace);
    let name = parts.next().unwrap_or_default();
    if name.is_empty() || name.contains('(') {
        return None;
    }
    let body = parts.next().unwrap_or_default().trim();
    if body.starts_with('(') {
        return None;
    }
    Some((name.to_string(), body.to_string()))
}

/// Parse the macro name of a `%undefine` from the text after the
/// directive word.
fn parse_undefine(rest: &str) -> Option<String> {
    let name = rest.split_whitespace().next().unwrap_or_default();
    if name.is_empty() || name.contains('(') {
        None
    } else {
        Some(name.to_string())
    }
}

/// An item of a macro-bearing value: a literal run or a macro
/// reference, as tokenised by [`tokenise_value`].
enum ValueItem {
    /// Literal text.
    Lit(String),
    /// `%{name}` / `%name`: the macro's own expansion.
    Value(String),
    /// `%{?name}`: the macro's expansion, or nothing.
    Query(String),
    /// `%{?name:text}` / `%{!name:text}`: nothing, or the expansion of
    /// `text`.
    Choice(Vec<ValueItem>),
    /// `%{expand:text}`: the expansion of `text`.
    Expand(Vec<ValueItem>),
    /// A construct whose expansion the preamble cannot determine
    /// (shell expansion, an expression, a macro invocation with
    /// arguments, a non-`expand` colon form).
    Opaque,
}

/// Tokenise a `Name:` value or a macro definition body into items.
/// `%%` is a literal percent; a `%` that opens nothing recognisable is
/// opaque.
fn tokenise_value(value: &str) -> Vec<ValueItem> {
    let chars: Vec<char> = value.chars().collect();
    let mut items = Vec::new();
    let mut lit = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '%' {
            lit.push(chars[i]);
            i += 1;
            continue;
        }
        let Some(&next) = chars.get(i + 1) else {
            if !lit.is_empty() {
                items.push(ValueItem::Lit(std::mem::take(&mut lit)));
            }
            items.push(ValueItem::Opaque);
            break;
        };
        match next {
            '%' => {
                lit.push('%');
                i += 2;
            }
            '{' | '(' | '[' => {
                let close = match next {
                    '{' => '}',
                    '(' => ')',
                    _ => ']',
                };
                let mut depth = 0usize;
                let mut j = i + 1;
                while j < chars.len() {
                    if chars[j] == next {
                        depth += 1;
                    } else if chars[j] == close {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    j += 1;
                }
                if !lit.is_empty() {
                    items.push(ValueItem::Lit(std::mem::take(&mut lit)));
                }
                if j >= chars.len() {
                    items.push(ValueItem::Opaque);
                    i = chars.len();
                } else if next == '{' {
                    let inner: String = chars[i + 2..j].iter().collect();
                    items.push(brace_item(&inner));
                    i = j + 1;
                } else {
                    items.push(ValueItem::Opaque);
                    i = j + 1;
                }
            }
            '?' | '!' => {
                // `%?name` / `%!name`: the short conditional reference —
                // the macro's expansion, or nothing. The identifier is
                // the macro's name, not literal text.
                match chars.get(i + 2) {
                    Some(&c) if c.is_ascii_alphanumeric() || c == '_' => {
                        let mut j = i + 2;
                        while j < chars.len()
                            && (chars[j].is_ascii_alphanumeric() || chars[j] == '_')
                        {
                            j += 1;
                        }
                        if !lit.is_empty() {
                            items.push(ValueItem::Lit(std::mem::take(&mut lit)));
                        }
                        let name: String = chars[i + 2..j].iter().collect();
                        items.push(ValueItem::Query(name));
                        i = j;
                    }
                    Some(&'{') => {
                        let mut depth = 0usize;
                        let mut j = i + 2;
                        while j < chars.len() {
                            if chars[j] == '{' {
                                depth += 1;
                            } else if chars[j] == '}' {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            j += 1;
                        }
                        if !lit.is_empty() {
                            items.push(ValueItem::Lit(std::mem::take(&mut lit)));
                        }
                        if j >= chars.len() {
                            items.push(ValueItem::Opaque);
                            i = chars.len();
                        } else {
                            let inner: String = chars[i + 3..j].iter().collect();
                            items.push(brace_item(&format!("{next}{inner}")));
                            i = j + 1;
                        }
                    }
                    _ => {
                        if !lit.is_empty() {
                            items.push(ValueItem::Lit(std::mem::take(&mut lit)));
                        }
                        items.push(ValueItem::Opaque);
                        i += 2;
                    }
                }
            }
            c if c.is_ascii_alphanumeric() || c == '_' => {
                let mut j = i + 1;
                while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                if !lit.is_empty() {
                    items.push(ValueItem::Lit(std::mem::take(&mut lit)));
                }
                let name: String = chars[i + 1..j].iter().collect();
                items.push(ValueItem::Value(name));
                i = j;
            }
            _ => {
                if !lit.is_empty() {
                    items.push(ValueItem::Lit(std::mem::take(&mut lit)));
                }
                items.push(ValueItem::Opaque);
                i += 2;
            }
        }
    }
    if !lit.is_empty() {
        items.push(ValueItem::Lit(lit));
    }
    items
}

/// The item for a `%{...}` group, from its inner text.
fn brace_item(inner: &str) -> ValueItem {
    let (conditional, rest) = match inner.strip_prefix('?').or_else(|| inner.strip_prefix('!')) {
        Some(rest) => (true, rest),
        None => (false, inner),
    };
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    let after = &rest[name.len()..];
    if after.is_empty() {
        return if conditional {
            ValueItem::Query(name)
        } else {
            ValueItem::Value(name)
        };
    }
    if let Some(text) = after.strip_prefix(':') {
        if conditional {
            return ValueItem::Choice(tokenise_value(text));
        }
        if name == "expand" {
            return ValueItem::Expand(tokenise_value(text));
        }
        return ValueItem::Opaque;
    }
    ValueItem::Opaque
}

/// Cap on the patterns one value expands to; past it the value is
/// widened to a single unconstrained pattern rather than enumerated.
const MAX_NAME_PATTERNS: usize = 64;

/// Cap on macro-expansion recursion depth.
const MAX_EXPANSION_DEPTH: usize = 8;

/// Expand one `Name:` value into its patterns against the preamble's
/// macro definitions.
fn expand_value(
    value: &str,
    macros: &[(String, String)],
    depth: usize,
    visiting: &mut Vec<String>,
) -> Vec<NamePattern> {
    expand_items(&tokenise_value(value), macros, depth, visiting)
}

/// Collapse a completed pattern set that contains an unconstrained
/// pattern: the unconstrained alternative produces every name the
/// other alternatives produce, so the set is the single unconstrained
/// pattern. Keeps widened expansions from being enumerated further.
fn collapse_unconstrained(patterns: Vec<NamePattern>) -> Vec<NamePattern> {
    if patterns.iter().any(|p| p.is_unconstrained()) {
        vec![NamePattern(vec![NameSegment::Any])]
    } else {
        patterns
    }
}

/// Expand tokenised items into patterns by composing the items'
/// alternatives in order.
fn expand_items(
    items: &[ValueItem],
    macros: &[(String, String)],
    depth: usize,
    visiting: &mut Vec<String>,
) -> Vec<NamePattern> {
    let mut patterns = vec![NamePattern(Vec::new())];
    for item in items {
        let alternatives: Vec<NamePattern> = match item {
            ValueItem::Lit(text) => {
                vec![NamePattern(vec![NameSegment::Literal(text.clone())])]
            }
            ValueItem::Value(name) => macro_patterns(name, macros, depth, visiting),
            ValueItem::Query(name) => {
                let mut alts = vec![NamePattern(Vec::new())];
                alts.extend(macro_patterns(name, macros, depth, visiting));
                alts
            }
            ValueItem::Choice(inner) => {
                let mut alts = vec![NamePattern(Vec::new())];
                alts.extend(expand_items(inner, macros, depth, visiting));
                alts
            }
            ValueItem::Expand(inner) => expand_items(inner, macros, depth, visiting),
            ValueItem::Opaque => vec![NamePattern(vec![NameSegment::Any])],
        };
        patterns = compose_patterns(&patterns, &alternatives);
        if patterns.len() > MAX_NAME_PATTERNS {
            return vec![NamePattern(vec![NameSegment::Any])];
        }
    }
    collapse_unconstrained(patterns)
}

/// The patterns for one macro reference: each of the macro's preamble
/// definitions expanded in turn. `%{nil}` is empty; a macro the
/// preamble does not define, a recursive reference and an exhausted
/// depth budget are unconstrained.
fn macro_patterns(
    name: &str,
    macros: &[(String, String)],
    depth: usize,
    visiting: &mut Vec<String>,
) -> Vec<NamePattern> {
    if name == "nil" {
        return vec![NamePattern(Vec::new())];
    }
    if depth >= MAX_EXPANSION_DEPTH || visiting.iter().any(|v| v == name) {
        return vec![NamePattern(vec![NameSegment::Any])];
    }
    let bodies: Vec<&str> = macros
        .iter()
        .filter(|(n, _)| n == name)
        .map(|(_, body)| body.as_str())
        .collect();
    if bodies.is_empty() {
        return vec![NamePattern(vec![NameSegment::Any])];
    }
    visiting.push(name.to_string());
    let mut out = std::collections::BTreeSet::new();
    for body in bodies {
        for pattern in expand_items(&tokenise_value(body), macros, depth + 1, visiting) {
            out.insert(pattern);
        }
    }
    visiting.pop();
    if out.len() > MAX_NAME_PATTERNS {
        return vec![NamePattern(vec![NameSegment::Any])];
    }
    collapse_unconstrained(out.into_iter().collect())
}

/// Concatenate two pattern sets pairwise, merging adjacent literal
/// segments, deduplicated.
fn compose_patterns(left: &[NamePattern], right: &[NamePattern]) -> Vec<NamePattern> {
    let mut out = std::collections::BTreeSet::new();
    for l in left {
        for r in right {
            let mut segs = l.0.clone();
            for seg in &r.0 {
                match (segs.last_mut(), seg) {
                    (Some(NameSegment::Literal(a)), NameSegment::Literal(b)) => {
                        a.push_str(b);
                    }
                    _ => segs.push(seg.clone()),
                }
            }
            out.insert(NamePattern(segs));
            if out.len() > MAX_NAME_PATTERNS {
                return vec![NamePattern(vec![NameSegment::Any])];
            }
        }
    }
    out.into_iter().collect()
}

/// The declared-name patterns behind [`SpecPkg::declared_name_patterns`].
fn declared_name_patterns(lines: &[String]) -> Option<Vec<NamePattern>> {
    let (names, events) = scan_preamble(lines);
    if names.is_empty() {
        return None;
    }
    let mut out = std::collections::BTreeSet::new();
    for (pos, value) in &names {
        // The macro environment in effect at the `Name:` line: the
        // preamble's events before it, replayed in order — a
        // definition takes effect from its own line on, a `%undefine`
        // removes the definitions before it, and a definition below
        // the tag is not in effect yet. Branch conditions are not
        // evaluated, so the definitions of every branch before the
        // tag accumulate as alternatives.
        let mut env: Vec<(String, String)> = Vec::new();
        for (at, event) in &events {
            if at >= pos {
                break;
            }
            match event {
                MacroEvent::Define(name, body) => env.push((name.clone(), body.clone())),
                MacroEvent::Undefine(name) => env.retain(|(n, _)| n != name),
            }
        }
        let mut visiting = Vec::new();
        for pattern in expand_value(value, &env, 0, &mut visiting) {
            out.insert(pattern);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out.into_iter().collect())
    }
}

/// `rpmlint.helpers.readlines`: the file's lines, each keeping its trailing
/// newline (like iterating a binary file object), decoded as UTF-8 with
/// undecodable bytes replaced (`helpers.byte_to_string`).
pub fn readlines(path: &Path) -> io::Result<Vec<String>> {
    let bytes = std::fs::read(path)?;
    Ok(bytes
        .split_inclusive(|b: &u8| *b == b'\n')
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect())
}

/// `rpmlint.pkg.is_utf8` for a spec file: true when the bytes are valid
/// UTF-8. (The reference also handles compressed files; a spec never is.)
pub fn is_utf8(path: &Path) -> bool {
    std::fs::read(path).is_ok_and(|bytes| std::str::from_utf8(&bytes).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readlines_keeps_trailing_newlines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.spec");
        std::fs::write(&path, "Name: foo\nVersion: 1\n").unwrap();
        assert_eq!(
            readlines(&path).unwrap(),
            vec!["Name: foo\n", "Version: 1\n"]
        );
    }

    #[test]
    fn readlines_last_line_without_newline_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.spec");
        std::fs::write(&path, "Name: foo\nVersion: 1").unwrap();
        assert_eq!(readlines(&path).unwrap(), vec!["Name: foo\n", "Version: 1"]);
    }

    #[test]
    fn readlines_replaces_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.spec");
        std::fs::write(&path, b"Name: f\xffo\n").unwrap();
        assert_eq!(readlines(&path).unwrap(), vec!["Name: f�o\n"]);
    }

    #[test]
    fn is_utf8_rejects_invalid_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let ok = dir.path().join("ok.spec");
        let bad = dir.path().join("bad.spec");
        std::fs::write(&ok, "Name: foo\n").unwrap();
        std::fs::write(&bad, b"Name: f\xffo\n").unwrap();
        assert!(is_utf8(&ok));
        assert!(!is_utf8(&bad));
    }

    #[test]
    fn open_reads_lines_and_starts_without_linenum() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.spec");
        std::fs::write(&path, "Name: foo\n").unwrap();
        let pkg = SpecPkg::open(&path).unwrap();
        assert_eq!(pkg.lines, vec!["Name: foo\n"]);
        assert_eq!(pkg.current_linenum.get(), None);
    }
}

#[cfg(test)]
mod name_patterns_tests {
    use super::*;

    fn patterns(text: &str) -> Option<Vec<NamePattern>> {
        let pkg = SpecPkg {
            name: "t.spec".to_string(),
            lines: text.lines().map(str::to_string).collect(),
            current_linenum: Cell::new(None),
        };
        pkg.declared_name_patterns()
    }

    /// Assert the patterns of `text` produce every name in `yes` and
    /// no name in `no`.
    fn assert_matches(text: &str, yes: &[&str], no: &[&str]) {
        let pats = patterns(text).expect("patterns declared");
        for y in yes {
            assert!(
                pats.iter().any(|p| p.matches(y)),
                "{text:?} should produce {y:?}"
            );
        }
        for n in no {
            assert!(
                !pats.iter().any(|p| p.matches(n)),
                "{text:?} should not produce {n:?}"
            );
        }
    }

    #[test]
    fn literal_name_is_declared() {
        assert_matches(
            "Name: foo\nVersion: 1\n",
            &["foo"],
            &["foox", "xfoo", "bar"],
        );
    }

    #[test]
    fn tag_matching_is_case_insensitive_and_trims() {
        assert_matches("  name:   foo  \n", &["foo"], &["bar"]);
    }

    #[test]
    fn preamble_directives_do_not_end_the_scan() {
        assert_matches(
            "%global flavour 1\n%define x y\nName: foo\n",
            &["foo"],
            &["bar"],
        );
    }

    #[test]
    fn commented_name_is_skipped() {
        assert_matches("# Name: wrong\nName: right\n", &["right"], &["wrong"]);
    }

    #[test]
    fn conditional_branches_contribute_their_names() {
        // The multibuild shape: one literal `Name:` per flavour branch
        // (mirrors util-linux's core/systemd/python preambles).
        let text = "%if \"%subset\" == \"core\"\nName: foo\n%endif\n\
                    %if \"%subset\" == \"systemd\"\nName: foo-systemd\n%endif\n\
                    Version: 1\n";
        assert_matches(text, &["foo", "foo-systemd"], &["foo-python", "bar"]);
    }

    #[test]
    fn scan_stops_at_the_first_section() {
        assert_eq!(patterns("%description\nName: foo\n"), None);
        assert_matches("Name: foo\n%package -n x\nName: bar\n", &["foo"], &["bar"]);
    }

    #[test]
    fn absent_or_empty_name_is_undecidable() {
        assert_eq!(patterns("Version: 1\n"), None);
        assert_eq!(patterns("Name:\n"), None);
    }

    #[test]
    fn suffix_macro_with_pinned_flavour() {
        // The ImageMagick shape: OBS pins `%global flavor` in the
        // payload, the suffix macro branches on it, and the `Name:`
        // composes base + suffix.
        let text = "%global flavor config_open%{nil}\n\
                    %if \"%{flavor}\" == \"\"\n%define nsuffix %nil\n\
                    %else\n%define nsuffix -%{flavor}\n%endif\n\
                    Name: ImageMagick%{?nsuffix}\n";
        assert_matches(
            text,
            &["ImageMagick", "ImageMagick-config_open"],
            &["ImageMagick-config", "ImageMagickX", "imagemagick"],
        );
    }

    #[test]
    fn prefix_and_suffix_macros_around_a_defined_literal() {
        // The php8 shape: prefix and suffix macros branch on the
        // pinned flavour around a literally defined middle.
        let text = "%global flavor apache2%{nil}\n\
                    %define php_name php8\n\
                    %if \"%{flavor}\" == \"apache2\"\n%define pprefix apache2-mod_\n\
                    %define psuffix %{nil}\n%endif\n\
                    %if \"%{flavor}\" == \"fpm\"\n%define pprefix %{nil}\n\
                    %define psuffix -%{flavor}\n%endif\n\
                    %if \"%{flavor}\" == \"\"\n%define pprefix %{nil}\n\
                    %define psuffix %{nil}\n%endif\n\
                    Name: %{pprefix}%{php_name}%{psuffix}\n";
        assert_matches(
            text,
            &["php8", "apache2-mod_php8"],
            &["php7", "apache2-mod_php7", "php8x"],
        );
    }

    #[test]
    fn query_macro_with_conditional_globals() {
        // The systemd shape: `%{?mini}` over two conditional `%global`
        // definitions of the affix macro.
        let text = "%global flavor mini%{nil}\n\
                    %if \"%{flavor}\" == \"mini\"\n%global mini -mini\n\
                    %else\n%global mini %{nil}\n%endif\n\
                    Name: systemd%{?mini}\n";
        assert_matches(text, &["systemd", "systemd-mini"], &["systemd-maxi"]);
    }

    #[test]
    fn chained_macro_with_undefined_query_suffix() {
        // The hdf5 shape: the `Name:` is a macro defined through a
        // short-form reference, with a second definition appending an
        // undefined queried macro.
        let text = "%define pname hdf5\n\
                    %define package_name %pname\n\
                    %if 1\n%define package_name %pname%{?my_suffix}\n%endif\n\
                    Name: %{package_name}\n";
        assert_matches(text, &["hdf5", "hdf5-openmpi4"], &["hdf4", "xhdf5"]);
    }

    #[test]
    fn undefined_macro_is_unconstrained() {
        // A `Name:` the preamble cannot determine constrains nothing:
        // with no literal anchor anywhere, every candidate matches.
        let pats = patterns("Name: %{pypi_name}\n").expect("patterns declared");
        assert!(pats.iter().any(|p| p.matches("anything")));
    }

    #[test]
    fn query_of_undefined_macro_matches_empty_and_text() {
        assert_matches("Name: foo%{?bar}\n", &["foo", "fooXYZ"], &["foe", "xfoo"]);
    }

    #[test]
    fn recursive_macro_terminates_unconstrained() {
        assert_matches(
            "%define a %{a}\nName: x%{a}\n",
            &["xanything"],
            &["yanything"],
        );
    }

    #[test]
    fn definition_after_the_name_tag_is_not_in_effect() {
        // Definitions take effect from their own line on: at the
        // `Name:` tag the macro is not defined yet, so it contributes
        // an unconstrained segment instead of the later value.
        assert_matches(
            "Name: foo%{sfx}\n%define sfx -bar\n",
            &["foo", "foo-bar", "foo-zzz"],
            &["bar", "xfoo"],
        );
    }

    #[test]
    fn doubled_percent_is_a_literal_percent() {
        assert_matches("Name: 100%%\n", &["100%"], &["100%%", "100"]);
    }

    #[test]
    fn shell_expansion_is_unconstrained() {
        assert_matches("Name: foo%(echo x)\n", &["foox", "foo"], &["barfoo"]);
    }

    #[test]
    fn conditional_text_form_expands_its_text() {
        // The conditional-expansion form contributes its text as one
        // alternative, emptiness as the other.
        let text = "%define mpi_flavor openmpi4\n\
                    %define pname hdf5\n\
                    Name: %{pname}%{?mpi_flavor:-%{mpi_flavor}}\n";
        assert_matches(text, &["hdf5", "hdf5-openmpi4"], &["hdf5-openmpi"]);
    }

    #[test]
    fn parametric_definitions_are_not_values() {
        // The systemd preamble shape: function-like definitions with
        // opaque bodies must not poison name resolution.
        let text = "%define when() %{expand:%%__when_%# %{*}}\n\
                    Name: systemd\n";
        assert_matches(text, &["systemd"], &["systemd-mini"]);
    }

    #[test]
    fn macro_expansion_statements_do_not_end_the_scan() {
        // The hdf5 shape: statement macros between the definitions
        // and the `Name:` tag run bconds conditionally; the preamble
        // continues past them.
        let text = "%define pname hdf5\n\
                    %{?mpi_flavor:%{bcond_without mpi}}%{!?mpi_flavor:%{bcond_with mpi}}\n\
                    Name: %{pname}\n";
        assert_matches(text, &["hdf5"], &["hdf4"]);
    }

    #[test]
    fn continued_definition_body_is_joined() {
        assert_matches(
            "%define sfx -a\\\nb\nName: foo%{sfx}\n",
            &["foo-ab"],
            &["foo-a"],
        );
    }

    #[test]
    fn conditionals_and_invocations_do_not_end_the_scan() {
        // `%ifdef` / `%ifndef` / `%ifos`, `%with` / `%without` and bare
        // macro invocations are preamble content: the `Name:` below
        // them still counts, and a section header still ends the scan.
        assert_matches("%ifdef foo\nName: bar\n", &["bar"], &["foo"]);
        assert_matches(
            "%ifos linux\n%with x\n%without y\n%some_macro arg\nName: bar\n",
            &["bar"],
            &["foo"],
        );
        assert_eq!(patterns("%ifndef foo\n%description\nName: bar\n"), None);
    }

    #[test]
    fn unbraced_query_reference_expands_conditionally() {
        // `%?bar` is the short conditional reference: the expansion of
        // `bar`, or nothing — the identifier is not literal text, so
        // `foo` itself is a producible name.
        assert_matches(
            "%define bar baz\nName: foo%?bar\n",
            &["foo", "foobaz"],
            &["foox", "bar"],
        );
        assert_matches("Name: foo%?bar\n", &["foo", "fooXYZ"], &["foe", "xfoo"]);
    }

    #[test]
    fn undefine_removes_the_definitions_before_it() {
        // After `%undefine` the macro is undefined: its segment is
        // unconstrained and the earlier value no longer applies.
        assert_matches(
            "%define sfx -x\n%undefine sfx\nName: foo%{sfx}\n",
            &["foo", "foo-zzz"],
            &["xfoo"],
        );
        // A fresh definition after the `%undefine` is the value again.
        assert_matches(
            "%define sfx -x\n%undefine sfx\n%define sfx -y\nName: foo%{sfx}\n",
            &["foo-y"],
            &["foo-x", "foo"],
        );
        // A `%undefine` below the `Name:` tag is not in effect yet.
        assert_matches(
            "%define sfx -x\nName: foo%{sfx}\n%undefine sfx\n",
            &["foo-x"],
            &["foo"],
        );
    }

    #[test]
    fn forward_reference_inside_a_definition_stays_undefined() {
        // A definition's own forward reference resolves against the
        // environment at the `Name:` tag: `b` is defined only below
        // it, so the segment is unconstrained.
        assert_matches(
            "%define a %{b}\nName: foo%{a}\n%define b -x\n",
            &["foo-x", "foo-zzz"],
            &["bar"],
        );
    }

    #[test]
    fn continued_name_value_is_joined() {
        assert_matches("Name: foo\\\n-bar\n", &["foo-bar"], &["foo"]);
    }

    #[test]
    fn widened_expansions_collapse_to_one_unconstrained_pattern() {
        // One undeterminable definition among concrete ones collapses
        // the macro's set: the unconstrained alternative already
        // produces every name the concrete ones do.
        let pats =
            patterns("%define v one\n%define v %(shell)\nName: %{v}\n").expect("patterns declared");
        assert_eq!(pats.len(), 1);
        assert!(pats[0].is_unconstrained());

        // A chain deeper than the recursion budget widens the same way.
        let mut text = String::from("%define m0 x\n");
        for n in 1..=12 {
            text.push_str(&format!("%define m{n} %{{m{}}}\n", n - 1));
        }
        text.push_str("Name: %{m12}\n");
        let pats = patterns(&text).expect("patterns declared");
        assert_eq!(pats.len(), 1);
        assert!(pats[0].is_unconstrained());
    }
}
