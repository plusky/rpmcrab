//! Severity inventory guard.
//!
//! Finding levels are compile-time literals at the emission sites and
//! badness lives in the vendored `[Scoring]` tables — deliberately no
//! runtime severity table (DESIGN §8). The price of that choice is that a
//! level or scoring change is invisible unless something diffs the whole
//! inventory, so this test derives it mechanically and compares it to the
//! checked-in snapshot in `tests/data/severity-inventory.txt`: a deliberate
//! recalibration updates the snapshot in the same diff, and an accidental
//! one fails here instead of drifting silently.
//!
//! Derivation, emissions: a static scan of `src/**/*.rs` for the emission
//! entry points (`add_info`, `add_info_at`, `spec_add_info`, `make_finding`,
//! and the spec check's `info` helper). In every shape the level literal
//! precedes the tag literal inside the call, so a call window yields
//! (level, tag) pairs. Every tag-shaped literal passed as a direct argument
//! of the call counts, not just the first, so an `if`/`else` pair sharing
//! one window contributes both tags. Comments and `#[cfg(test)]` blocks are
//! excluded.
//!
//! Variable-tag sites are resolved by following the producing function,
//! the same indirection `scripts/audit-reference-coverage.py` draws for
//! its dynamic sites: `bashisms.rs`'s `warning` from the literals pushed
//! in `classify_bashisms`, `alternatives.rs`'s `finding` from the `Err(..)`
//! literals in `check_post_phase`, `systemd_install.rs`'s `finding` from
//! the tag-shaped literals in `check_unit`, and the `(Level, tag)` tuple
//! producers `parse_desktop` (`menu_xdg.rs`) and `describe`
//! (`duplicates.rs`), whose tuples carry their own level. A call window
//! that still yields no tag — format!-built families such as
//! `no-%{sec}-section` and `{check_type}-file-*`, data-driven tags or
//! levels, filelist `rule.message` — is NOT dropped silently: it is
//! recorded in the snapshot's `[unresolved-sites]` section, so the
//! snapshot never reads as a complete inventory and any new unresolved
//! shape fails here until it is resolved or ratified in the snapshot.
//!
//! Derivation, scoring: every `[Scoring]` and `[SeverityOverrides]`
//! table under `data/` (the built-in defaults and the vendored distro
//! layers) — both are per-tag level knobs, so a shipped override that
//! flips a tag's level fails here just like a scoring change.
//!
//! Regenerate the snapshot after an intentional change:
//!     UPDATE_SEVERITY_INVENTORY=1 cargo test -p rpmcrab-core --test severity_inventory

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn core_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The emission entry points whose call windows carry a level literal
/// followed by the tag literal.
const CALL_TOKENS: &[&str] = &[
    "add_info_at(",
    "spec_add_info(",
    "add_info(",
    "make_finding(",
    ".info(",
];

// ---------------------------------------------------------------------------
// A small Rust-source scanner: just enough lexing to blank comments, find
// string literals, and match brackets without being confused by either.
// ---------------------------------------------------------------------------

/// One string literal: byte range of the whole literal in the source and
/// the range of its content (without quotes or the `r`/`b` prefixes).
struct StrLit {
    start: usize,
    end: usize,
    content: (usize, usize),
}

/// Blank comments in `src` (positions preserved) and collect string
/// literals. Operates on chars so multi-byte text cannot shift indices;
/// the returned text has exactly the input's char count.
fn lex(src: &[char]) -> (Vec<char>, Vec<StrLit>) {
    let mut clean = src.to_vec();
    let mut strings = Vec::new();
    let n = src.len();
    let mut i = 0;
    while i < n {
        let c = src[i];
        // Line comment.
        if c == '/' && i + 1 < n && src[i + 1] == '/' {
            let mut j = i;
            while j < n && src[j] != '\n' {
                clean[j] = ' ';
                j += 1;
            }
            i = j;
            continue;
        }
        // Block comment (Rust block comments nest).
        if c == '/' && i + 1 < n && src[i + 1] == '*' {
            let mut depth = 1usize;
            let mut j = i + 2;
            while j < n && depth > 0 {
                if src[j] == '*' && j + 1 < n && src[j + 1] == '/' {
                    depth -= 1;
                    j += 2;
                } else if src[j] == '/' && j + 1 < n && src[j + 1] == '*' {
                    depth += 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            for slot in clean.iter_mut().take(j.min(n)).skip(i) {
                if *slot != '\n' {
                    *slot = ' ';
                }
            }
            i = j;
            continue;
        }
        // Raw string: r"...", r#"..."#, br"..." (the prefix counts only at
        // an identifier boundary, so a variable named `r` is not one).
        let boundary = i == 0 || !(src[i - 1].is_alphanumeric() || src[i - 1] == '_');
        if boundary && (c == 'r' || (c == 'b' && i + 1 < n && src[i + 1] == 'r')) {
            let mut j = if c == 'b' { i + 2 } else { i + 1 };
            let mut hashes = 0usize;
            while j < n && src[j] == '#' {
                hashes += 1;
                j += 1;
            }
            if j < n && src[j] == '"' {
                let body = j + 1;
                let mut k = body;
                let content_end;
                loop {
                    if k >= n {
                        content_end = n;
                        break;
                    }
                    if src[k] == '"' {
                        let mut h = 0usize;
                        while k + 1 + h < n && src[k + 1 + h] == '#' {
                            h += 1;
                        }
                        if h == hashes {
                            content_end = k;
                            k += 1 + hashes;
                            break;
                        }
                    }
                    k += 1;
                }
                strings.push(StrLit {
                    start: i,
                    end: k,
                    content: (body, content_end),
                });
                i = k;
                continue;
            }
        }
        // Byte string: b"...".
        if c == 'b' && i + 1 < n && src[i + 1] == '"' && boundary {
            let (content, end) = scan_quoted(src, i + 1);
            strings.push(StrLit {
                start: i,
                end,
                content,
            });
            i = end;
            continue;
        }
        // Plain string.
        if c == '"' {
            let (content, end) = scan_quoted(src, i);
            strings.push(StrLit {
                start: i,
                end,
                content,
            });
            i = end;
            continue;
        }
        // Char literal ('x', '\n', '\u{...}') vs lifetime ('a): only a
        // closed literal shape is a literal; anything else is a lifetime
        // and just the quote is skipped. A recognised literal is blanked
        // in `clean`, so bracket matching never counts a '(' or '{'
        // carried by a char literal.
        if c == '\'' {
            let lit_len = if i + 3 < n && src[i + 1] == '\\' && src[i + 3] == '\'' {
                Some(4)
            } else if i + 2 < n && src[i + 1] != '\\' && src[i + 2] == '\'' {
                Some(3)
            } else if i + 3 < n && src[i + 1] == '\\' && src[i + 2] == 'u' && src[i + 3] == '{' {
                (i + 4..(i + 16).min(n))
                    .find(|&j| src[j] == '}')
                    .filter(|&j| j + 1 < n && src[j + 1] == '\'')
                    .map(|j| j + 2 - i)
            } else {
                None
            };
            if let Some(len) = lit_len {
                for slot in clean.iter_mut().take(i + len).skip(i) {
                    *slot = ' ';
                }
                i += len;
            } else {
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    (clean, strings)
}

/// Scan a `"..."` literal starting at the opening quote `q`; returns the
/// content range and the index just past the closing quote.
fn scan_quoted(src: &[char], q: usize) -> ((usize, usize), usize) {
    let n = src.len();
    let mut j = q + 1;
    while j < n {
        if src[j] == '\\' {
            j += 2;
            continue;
        }
        if src[j] == '"' {
            break;
        }
        j += 1;
    }
    ((q + 1, j.min(n)), (j + 1).min(n))
}

/// String-literal ends by start index, for bracket matching that must not
/// see brackets inside literals.
type SpanEnds = std::collections::HashMap<usize, usize>;

fn span_ends(strings: &[StrLit]) -> SpanEnds {
    strings.iter().map(|l| (l.start, l.end)).collect()
}

/// Index just past the bracket that closes the one at `open`, skipping
/// string literals. `open_ch`/`close_ch` are `(` `)` or `{` `}`.
fn match_bracket(
    clean: &[char],
    spans: &SpanEnds,
    open: usize,
    open_ch: char,
    close_ch: char,
) -> usize {
    let n = clean.len();
    let mut depth = 0usize;
    let mut j = open;
    while j < n {
        if let Some(&end) = spans.get(&j) {
            j = end;
            continue;
        }
        if clean[j] == open_ch {
            depth += 1;
        } else if clean[j] == close_ch {
            depth -= 1;
            if depth == 0 {
                return (j + 1).min(n);
            }
        }
        j += 1;
    }
    n
}

/// Blank the brace block following each `#[cfg(test)]` attribute (a test
/// module, helper fn or impl): test code constructs findings with fixture
/// tags that are not emissions.
fn blank_test_blocks(clean: &mut [char], strings: &[StrLit]) {
    let spans = span_ends(strings);
    let needle: Vec<char> = "#[cfg(test)]".chars().collect();
    let n = clean.len();
    let mut i = 0;
    while i + needle.len() < n {
        if clean[i..i + needle.len()] == needle[..] {
            // Find the block's opening brace before any `;` (a `use` item
            // has no block and is skipped).
            let mut j = i + needle.len();
            let mut brace = None;
            while j < n {
                if let Some(&end) = spans.get(&j) {
                    j = end;
                    continue;
                }
                if clean[j] == ';' {
                    break;
                }
                if clean[j] == '{' {
                    brace = Some(j);
                    break;
                }
                j += 1;
            }
            if let Some(b) = brace {
                let end = match_bracket(clean, &spans, b, '{', '}');
                for slot in clean.iter_mut().take(end).skip(i) {
                    if *slot != '\n' {
                        *slot = ' ';
                    }
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
}

fn find_subslice(haystack: &[char], needle: &[char], from: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let mut i = from;
    while i + needle.len() <= haystack.len() {
        if haystack[i..i + needle.len()] == needle[..] {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// A tag-shaped literal: starts with a letter, digit or `%`, continues with
/// those plus `-`, `.`, `_`. Detail strings (paths, prose, format
/// templates) contain other characters and never match.
fn is_tag(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() || c == '%' => {}
        _ => return false,
    }
    s.len() >= 3 && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '%'))
}

/// tag -> set of level letters, from every statically literal emission
/// site under `src/`, plus the set of call windows that yielded no tag
/// (recorded in the snapshot instead of being dropped silently).
fn emitted_levels(src_root: &PathBuf) -> (BTreeMap<String, BTreeSet<char>>, BTreeSet<String>) {
    let mut files = Vec::new();
    collect_rs(src_root, &mut files);
    files.sort();
    let mut inventory: BTreeMap<String, BTreeSet<char>> = BTreeMap::new();
    let mut unresolved: BTreeSet<String> = BTreeSet::new();
    for file in files {
        let text =
            std::fs::read_to_string(&file).unwrap_or_else(|_| panic!("read {}", file.display()));
        let chars: Vec<char> = text.chars().collect();
        let (mut clean, strings) = lex(&chars);
        blank_test_blocks(&mut clean, &strings);
        let file_name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        extract_from_file(
            &file_name,
            &chars,
            &clean,
            &strings,
            &mut inventory,
            &mut unresolved,
        );
    }
    (inventory, unresolved)
}

fn collect_rs(dir: &PathBuf, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|_| panic!("read_dir {}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn collect_toml(dir: &PathBuf, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|_| panic!("read_dir {}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_toml(&path, out);
        } else if path.extension().is_some_and(|e| e == "toml") {
            out.push(path);
        }
    }
}

/// How a variable-tag site's producing function yields its tags; the same
/// dynamic-site table `scripts/audit-reference-coverage.py` uses.
/// (file, tag variable, producing function, extractor kind)
#[derive(Clone, Copy, PartialEq)]
enum ProducerKind {
    /// Literals in `Err("...")` / `Err((Level::.., "..."))` (`fn_err_literals`).
    Err,
    /// Every tag-shaped literal in the producer body (`fn_finding_literals`).
    TagShapedBody,
    /// `(Level::.., "tag", ...)` tuples; each tuple carries its own level,
    /// so the call site needs none (`fn_describe_tuple_literals`, and the
    /// tuple form of `fn_err_literals`).
    LevelTuples,
}

const DYNAMIC_SITES: &[(&str, &str, &str, ProducerKind)] = &[
    (
        "alternatives.rs",
        "finding",
        "check_post_phase",
        ProducerKind::Err,
    ),
    (
        "bashisms.rs",
        "warning",
        "classify_bashisms",
        ProducerKind::LevelTuples,
    ),
    (
        "duplicates.rs",
        "name",
        "describe",
        ProducerKind::LevelTuples,
    ),
    (
        "menu_xdg.rs",
        "finding",
        "parse_desktop",
        ProducerKind::LevelTuples,
    ),
    (
        "systemd_install.rs",
        "finding",
        "check_unit",
        ProducerKind::TagShapedBody,
    ),
];

/// Byte-char range of the body (braces included) of `fn <name>` in the
/// cleaned source, or None if there is no such function.
fn fn_body_range(clean: &[char], spans: &SpanEnds, name: &str) -> Option<(usize, usize)> {
    let needle: Vec<char> = format!("fn {name}").chars().collect();
    let mut from = 0;
    loop {
        let pos = find_subslice(clean, &needle, from)?;
        // Word boundary after the name, so `fn describe_x` is not `describe`.
        let after = pos + needle.len();
        if after < clean.len() && (clean[after].is_alphanumeric() || clean[after] == '_') {
            from = pos + 1;
            continue;
        }
        let mut j = after;
        while j < clean.len() {
            if let Some(&end) = spans.get(&j) {
                j = end;
                continue;
            }
            if clean[j] == '{' {
                return Some((j, match_bracket(clean, spans, j, '{', '}')));
            }
            if clean[j] == ';' {
                return None;
            }
            j += 1;
        }
        return None;
    }
}

fn tag_text(original: &[char], lit: &StrLit) -> String {
    original[lit.content.0..lit.content.1].iter().collect()
}

/// Tags (with levels) a producer function yields, per its extractor kind.
/// Err/TagShapedBody tags pair with `call_level`; LevelTuples pairs
/// come from the tuples themselves.
fn producer_tags(
    original: &[char],
    clean: &[char],
    strings: &[StrLit],
    fn_name: &str,
    kind: ProducerKind,
    call_level: Option<char>,
) -> Vec<(String, char)> {
    let spans = span_ends(strings);
    let Some((bstart, bend)) = fn_body_range(clean, &spans, fn_name) else {
        return Vec::new();
    };
    let in_body = |l: &StrLit| l.start >= bstart && l.start < bend;
    let mut out: Vec<(String, char)> = Vec::new();
    let push_tag = |tag: String, level: char, out: &mut Vec<(String, char)>| {
        if is_tag(&tag) && !out.contains(&(tag.clone(), level)) {
            out.push((tag, level));
        }
    };
    match kind {
        ProducerKind::LevelTuples => {
            for (form, letter) in LEVEL_FORMS {
                let needle: Vec<char> = form.chars().collect();
                let mut from = bstart;
                while let Some(p) = find_subslice(&clean[from..bend], &needle, 0) {
                    let abs = from + p;
                    from = abs + needle.len();
                    // The tag is the first literal after `(Level::.., `.
                    if let Some(lit) = strings
                        .iter()
                        .find(|l| l.start >= abs + needle.len() && l.start < bend)
                    {
                        push_tag(tag_text(original, lit), letter, &mut out);
                    }
                }
            }
        }
        ProducerKind::Err => {
            let Some(level) = call_level else { return out };
            let needle: Vec<char> = "Err(".chars().collect();
            let mut from = bstart;
            while let Some(p) = find_subslice(&clean[from..bend], &needle, 0) {
                let abs = from + p;
                from = abs + needle.len();
                // Err("tag") or Err((Level::.., "tag", ..)): first literal
                // after the Err( (skipping a level form in between) whose
                // text is tag-shaped.
                if let Some(lit) = strings
                    .iter()
                    .find(|l| l.start >= abs + needle.len() && l.start < bend)
                {
                    push_tag(tag_text(original, lit), level, &mut out);
                }
            }
            // Bare `(Level::.., "tag", ..)` tuple returns, as in the audit.
            for (form, _letter) in LEVEL_FORMS {
                let needle2: Vec<char> = form.chars().collect();
                let mut from2 = bstart;
                while let Some(p) = find_subslice(&clean[from2..bend], &needle2, 0) {
                    let abs = from2 + p;
                    from2 = abs + needle2.len();
                    if let Some(lit) = strings
                        .iter()
                        .find(|l| l.start >= abs + needle2.len() && l.start < bend)
                    {
                        push_tag(tag_text(original, lit), level, &mut out);
                    }
                }
            }
        }
        ProducerKind::TagShapedBody => {
            let Some(level) = call_level else { return out };
            for lit in strings.iter().filter(|l| in_body(l)) {
                push_tag(tag_text(original, lit), level, &mut out);
            }
        }
    }
    out
}

const LEVEL_FORMS: [(&str, char); 3] = [
    ("Level::Error", 'E'),
    ("Level::Warning", 'W'),
    ("Level::Info", 'I'),
];

/// Paren/bracket depth of `pos` relative to the call's opening paren at
/// `open` (0 = a direct argument of the call), skipping string literals.
/// Braces do not count: an `if`/`else` tag expression is still a direct
/// argument, while detail literals sit inside `&[...]` or a nested call.
fn rel_depth(clean: &[char], spans: &SpanEnds, open: usize, pos: usize) -> usize {
    let mut depth = 0usize;
    let mut j = open + 1;
    while j < pos {
        if let Some(&end) = spans.get(&j) {
            j = end;
            continue;
        }
        match clean[j] {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            _ => {}
        }
        j += 1;
    }
    depth
}

fn extract_from_file(
    file_name: &str,
    original: &[char],
    clean: &[char],
    strings: &[StrLit],
    inventory: &mut BTreeMap<String, BTreeSet<char>>,
    unresolved: &mut BTreeSet<String>,
) {
    let spans = span_ends(strings);
    let tokens: Vec<Vec<char>> = CALL_TOKENS.iter().map(|t| t.chars().collect()).collect();
    let level_forms: Vec<(Vec<char>, char)> = LEVEL_FORMS
        .iter()
        .map(|(s, l)| (s.chars().collect(), *l))
        .collect();
    let mut i = 0;
    loop {
        // Earliest next call token at or after i.
        let mut best: Option<(usize, usize)> = None; // (pos, token len)
        for tok in &tokens {
            if let Some(pos) = find_subslice(clean, tok, i)
                && best.is_none_or(|(b, _)| pos < b)
            {
                best = Some((pos, tok.len()));
            }
        }
        let Some((pos, tok_len)) = best else { break };
        // A `fn add_info(` / `fn make_finding(` definition is the plumbing,
        // not an emission site: skip it outright instead of recording it
        // as unresolved.
        let mut back = pos;
        while back > 0 && clean[back - 1] == ' ' {
            back -= 1;
        }
        if back >= 2
            && clean[back - 2..back] == ['f', 'n']
            && (back == 2 || !(clean[back - 3].is_alphanumeric() || clean[back - 3] == '_'))
        {
            i = pos + tok_len;
            continue;
        }
        let open = pos + tok_len - 1; // the '(' itself
        let end = match_bracket(clean, &spans, open, '(', ')');
        // First Level:: literal inside the window.
        let mut level: Option<(usize, char)> = None;
        for (form, letter) in &level_forms {
            if let Some(p) = find_subslice(&clean[open..end], form, 0) {
                let abs = open + p + form.len();
                if level.is_none_or(|(b, _)| abs < b) {
                    level = Some((abs, *letter));
                }
            }
        }
        let mut produced = false;
        if let Some((level_end, letter)) = level {
            // Tag literals: the first literal at or after the level (the
            // historical rule, which also reaches a tag nested inside a
            // constructor argument) plus every tag-shaped literal passed
            // as a direct argument of the call, so an if/else pair sharing
            // one window contributes both tags.
            let mut literals: Vec<&StrLit> = Vec::new();
            if let Some(first) = strings
                .iter()
                .find(|l| l.start >= level_end && l.start < end)
            {
                literals.push(first);
            }
            for lit in strings
                .iter()
                .filter(|l| l.start >= level_end && l.start < end)
            {
                if rel_depth(clean, &spans, open, lit.start) == 0
                    && !literals.iter().any(|l| l.start == lit.start)
                {
                    literals.push(lit);
                }
            }
            for lit in literals {
                let tag = tag_text(original, lit);
                if is_tag(&tag) {
                    inventory.entry(tag).or_default().insert(letter);
                    produced = true;
                }
            }
        }
        // Variable-tag sites: follow the producing function, as the
        // reference-coverage audit does. Applies with or without a
        // literal level at the call site (tuple producers carry their
        // own levels).
        for (dfile, var, producer, kind) in DYNAMIC_SITES {
            if *dfile != file_name {
                continue;
            }
            let var_needle: Vec<char> = var.chars().collect();
            if find_subslice(&clean[pos..end], &var_needle, 0).is_none() {
                continue;
            }
            for (tag, letter) in producer_tags(
                original,
                clean,
                strings,
                producer,
                *kind,
                level.map(|(_, l)| l),
            ) {
                inventory.entry(tag).or_default().insert(letter);
                produced = true;
            }
        }
        if !produced {
            // Never drop a window silently: record it for the snapshot's
            // [unresolved-sites] section (whitespace collapsed, truncated).
            let snippet: String = clean[pos..end.min(pos + 110)]
                .iter()
                .collect::<String>()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            unresolved.insert(format!("{file_name}: {snippet}"));
        }
        i = pos + tok_len;
    }
}

// ---------------------------------------------------------------------------
// Vendored [Scoring] and [SeverityOverrides] tables.
// ---------------------------------------------------------------------------

type ScoringTables = BTreeMap<String, BTreeMap<String, i64>>;
type OverrideTables = BTreeMap<String, BTreeMap<String, char>>;

/// (relpath -> (tag -> badness), relpath -> (tag -> level letter)), for
/// every `[Scoring]` / `[SeverityOverrides]` table under `data/`.
fn distro_tables(data_root: &PathBuf) -> (ScoringTables, OverrideTables) {
    let mut files = Vec::new();
    collect_toml(data_root, &mut files);
    files.sort();
    let mut scoring = BTreeMap::new();
    let mut overrides = BTreeMap::new();
    for file in files {
        let text =
            std::fs::read_to_string(&file).unwrap_or_else(|_| panic!("read {}", file.display()));
        #[derive(PartialEq)]
        enum Section {
            Other,
            Scoring,
            Overrides,
        }
        let mut section = Section::Other;
        let mut saw_scoring = false;
        let mut saw_overrides = false;
        let mut scoring_entries: BTreeMap<String, i64> = BTreeMap::new();
        let mut override_entries: BTreeMap<String, char> = BTreeMap::new();
        for (lineno, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();
            if line.starts_with('[') {
                section = match line {
                    "[Scoring]" => Section::Scoring,
                    "[SeverityOverrides]" => Section::Overrides,
                    _ => Section::Other,
                };
                saw_scoring |= section == Section::Scoring;
                saw_overrides |= section == Section::Overrides;
                continue;
            }
            if section == Section::Other || line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                panic!(
                    "{}:{}: unparsable table line: {line}",
                    file.display(),
                    lineno + 1
                );
            };
            let key = key.trim().trim_matches('"').to_string();
            // Strip a trailing `#` comment outside quotes.
            let mut in_str = false;
            let mut cut = value.len();
            for (idx, c) in value.char_indices() {
                match c {
                    '"' => in_str = !in_str,
                    '#' if !in_str => {
                        cut = idx;
                        break;
                    }
                    _ => {}
                }
            }
            let value = value[..cut].trim();
            if section == Section::Scoring {
                scoring_entries.insert(key, coerce_scoring_value(&file, lineno + 1, line, value));
            } else {
                let raw = value.trim_matches('"');
                let letter = match raw.to_ascii_lowercase().as_str() {
                    "e" | "error" => 'E',
                    "w" | "warning" => 'W',
                    "i" | "info" => 'I',
                    _ => panic!(
                        "{}:{}: unparsable [SeverityOverrides] value: {line}",
                        file.display(),
                        lineno + 1
                    ),
                };
                override_entries.insert(key, letter);
            }
        }
        let rel = file
            .strip_prefix(core_root())
            .expect("data file under crate root")
            .to_string_lossy()
            .replace('\\', "/");
        if saw_scoring {
            scoring.insert(rel.clone(), scoring_entries);
        }
        if saw_overrides {
            overrides.insert(rel, override_entries);
        }
    }
    (scoring, overrides)
}

/// Coerce a `[Scoring]` value the way `filter.rs`'s `coerce_scoring`
/// does (mirroring Python `int()`): integers pass through, quoted
/// strings are parsed, floats truncate toward zero, booleans are 1/0.
/// Anything else panics, as an unparsable value did before.
fn coerce_scoring_value(file: &std::path::Path, lineno: usize, line: &str, value: &str) -> i64 {
    let fail = || -> ! {
        panic!(
            "{}:{}: unparsable [Scoring] value: {line}",
            file.display(),
            lineno
        )
    };
    if value == "true" {
        return 1;
    }
    if value == "false" {
        return 0;
    }
    if let Some(quoted) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        return quoted.trim().parse().unwrap_or_else(|_| fail());
    }
    if value.contains(['.', 'e', 'E']) {
        let f: f64 = value.parse().unwrap_or_else(|_| fail());
        if !f.is_finite() || f.trunc() < i64::MIN as f64 || f.trunc() >= i64::MAX as f64 {
            fail();
        }
        return f.trunc() as i64;
    }
    value.parse().unwrap_or_else(|_| fail())
}

// ---------------------------------------------------------------------------
// The snapshot and the guard.
// ---------------------------------------------------------------------------

fn render_inventory() -> String {
    let root = core_root();
    let (emissions, unresolved) = emitted_levels(&root.join("src"));
    let (scoring, overrides) = distro_tables(&root.join("data"));
    let mut out = String::new();
    out.push_str(
        "# Severity inventory: emitted level(s) per finding tag and the vendored\n\
         # [Scoring] / [SeverityOverrides] tables, derived mechanically from the\n\
         # tree by the severity_inventory test\n\
         # (crates/rpmcrab-core/tests/severity_inventory.rs).\n\
         #\n\
         # A deliberate level or scoring change updates this file in the same diff:\n\
         #     UPDATE_SEVERITY_INVENTORY=1 cargo test -p rpmcrab-core --test severity_inventory\n\
         # An unintentional change fails the test instead of drifting silently.\n\
         #\n\
         # Emission sites whose tag or level is computed at runtime and cannot\n\
         # be resolved statically are listed under [unresolved-sites] below,\n\
         # never dropped silently.\n",
    );
    out.push_str("\n[emitted-levels]\n");
    for (tag, levels) in &emissions {
        let letters: Vec<String> = ['E', 'W', 'I']
            .iter()
            .filter(|l| levels.contains(l))
            .map(|l| l.to_string())
            .collect();
        out.push_str(&format!("{tag} = {}\n", letters.join(",")));
    }
    out.push_str("\n[unresolved-sites]\n");
    out.push_str(&format!("# count = {}\n", unresolved.len()));
    for site in &unresolved {
        out.push_str(&format!("{site}\n"));
    }
    for (rel, entries) in &scoring {
        out.push_str(&format!("\n[scoring {rel}]\n"));
        for (tag, badness) in entries {
            out.push_str(&format!("{tag} = {badness}\n"));
        }
    }
    for (rel, entries) in &overrides {
        out.push_str(&format!("\n[severity-overrides {rel}]\n"));
        for (tag, letter) in entries {
            out.push_str(&format!("{tag} = {letter}\n"));
        }
    }
    out
}

#[test]
fn severity_inventory_matches_snapshot() {
    let snapshot_path = core_root().join("tests/data/severity-inventory.txt");
    let derived = render_inventory();
    match std::env::var("UPDATE_SEVERITY_INVENTORY") {
        Err(std::env::VarError::NotPresent) => {}
        Ok(value) if value == "1" => {
            std::fs::write(&snapshot_path, &derived).expect("write severity inventory snapshot");
            return;
        }
        Ok(value) => {
            panic!(
                "UPDATE_SEVERITY_INVENTORY must be exactly \"1\" to regenerate the \
                 severity inventory snapshot, got {value:?}; unset it to run the guard"
            );
        }
        Err(e) => panic!("UPDATE_SEVERITY_INVENTORY is not readable: {e}"),
    }
    let expected = std::fs::read_to_string(&snapshot_path).unwrap_or_else(|_| {
        panic!(
            "severity inventory snapshot is checked in at {}",
            snapshot_path.display()
        )
    });
    if expected != derived {
        let exp: Vec<&str> = expected.lines().collect();
        let got: Vec<&str> = derived.lines().collect();
        let mut diff = String::from("severity inventory drifted from the snapshot:\n");
        let max = exp.len().max(got.len());
        let mut shown = 0;
        for idx in 0..max {
            let e = exp.get(idx).copied().unwrap_or("<missing>");
            let g = got.get(idx).copied().unwrap_or("<missing>");
            if e != g {
                diff.push_str(&format!(
                    "  line {}:\n    snapshot: {e}\n    derived:  {g}\n",
                    idx + 1
                ));
                shown += 1;
                if shown >= 20 {
                    diff.push_str("  ... (further differences elided)\n");
                    break;
                }
            }
        }
        diff.push_str(
            "If this change is deliberate, regenerate the snapshot in the same diff:\n\
             \x20   UPDATE_SEVERITY_INVENTORY=1 cargo test -p rpmcrab-core --test severity_inventory",
        );
        panic!("{diff}");
    }
}
