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
    /// The patterns are the ground truth for the spec's own identity —
    /// a source RPM's header name names the container (OBS names
    /// multibuild flavour source RPMs after the build job), not the
    /// spec. `None` when the preamble declares no `Name:` at all.
    pub fn declared_name_patterns(&self) -> Option<Vec<NamePattern>> {
        declared_name_patterns(&self.lines)
    }
}

/// Directives that may appear in the main preamble ahead of the `Name:`
/// tag: macro definitions and conditionals. Any other `%`-led line opens
/// a section or a scriptlet and ends the preamble.
const PREAMBLE_DIRECTIVES: &[&str] = &[
    "bcond",
    "bcond_with",
    "bcond_without",
    "define",
    "elif",
    "elifarch",
    "elifnarch",
    "else",
    "expand",
    "global",
    "include",
    "undefine",
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

/// The preamble scan behind [`SpecPkg::declared_name_patterns`]: the
/// `Name:` values and the `%define` / `%global` macro definitions of
/// the main preamble, in declaration order. The scan stops at the
/// first section directive.
fn scan_preamble(lines: &[String]) -> (Vec<String>, Vec<(String, String)>) {
    // Join backslash-continued definition lines first: a definition's
    // body runs to the end of its logical line.
    let mut logical: Vec<String> = Vec::with_capacity(lines.len());
    for line in lines {
        let line = line.trim();
        match logical.last_mut() {
            Some(prev) if prev.ends_with('\\') && is_definition_line(prev) => {
                prev.pop();
                prev.push_str(line);
            }
            _ => logical.push(line.to_string()),
        }
    }

    let mut names = Vec::new();
    let mut macros: Vec<(String, String)> = Vec::new();
    for line in &logical {
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
                "if" | "ifarch" | "ifnarch" | "endif" => {}
                d if PREAMBLE_DIRECTIVES.contains(&d) => {
                    if d == "define" || d == "global" {
                        record_macro(&rest[directive.len()..], &mut macros);
                    }
                }
                _ => break,
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
            names.push(value.to_string());
        }
    }
    (names, macros)
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

/// Record one `%define` / `%global` definition from the text after the
/// directive word. Parametric definitions (`%define name(args) body`)
/// define functions, not values, and are not recorded.
fn record_macro(rest: &str, macros: &mut Vec<(String, String)>) {
    let mut parts = rest.trim_start().splitn(2, char::is_whitespace);
    let name = parts.next().unwrap_or_default();
    if name.is_empty() || name.contains('(') {
        return;
    }
    let body = parts.next().unwrap_or_default().trim();
    if body.starts_with('(') {
        return;
    }
    macros.push((name.to_string(), body.to_string()));
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
    patterns
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
    out.into_iter().collect()
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
    let (names, macros) = scan_preamble(lines);
    if names.is_empty() {
        return None;
    }
    let mut out = std::collections::BTreeSet::new();
    for value in &names {
        let mut visiting = Vec::new();
        for pattern in expand_value(value, &macros, 0, &mut visiting) {
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
    fn definition_after_the_name_tag_still_counts() {
        // rpm resolves the preamble lazily: a definition below the
        // `Name:` line is part of the declaration.
        assert_matches(
            "Name: foo%{sfx}\n%define sfx -bar\n",
            &["foo-bar"],
            &["foo"],
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
                    Name: %{pname}%{?mpi_flavor:-%{mpi_flavor}}\n\
                    %define pname hdf5\n";
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
}
