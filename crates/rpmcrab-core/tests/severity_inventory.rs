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
//! (level, tag) pairs. Comments and `#[cfg(test)]` blocks are excluded.
//! Only statically literal sites are listed: findings whose tag or level is
//! computed at runtime (format!-built families such as `no-%{sec}-section`
//! and `{check_type}-file-*`, variable tags, data-driven levels) resolve at
//! runtime and do not appear — the same boundary the reference-coverage
//! audit draws.
//!
//! Derivation, scoring: every `[Scoring]` table under `data/` (the built-in
//! defaults and the vendored distro layers).
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
        // Char literal ('x', '\n') vs lifetime ('a): only the closed,
        // single-char shape is a literal; anything else is a lifetime and
        // just the quote is skipped.
        if c == '\'' {
            if i + 3 < n && src[i + 1] == '\\' && src[i + 3] == '\'' {
                i += 4;
            } else if i + 2 < n && src[i + 1] != '\\' && src[i + 2] == '\'' {
                i += 3;
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
/// site under `src/`.
fn emitted_levels(src_root: &PathBuf) -> BTreeMap<String, BTreeSet<char>> {
    let mut files = Vec::new();
    collect_rs(src_root, &mut files);
    files.sort();
    let mut inventory: BTreeMap<String, BTreeSet<char>> = BTreeMap::new();
    for file in files {
        let text =
            std::fs::read_to_string(&file).unwrap_or_else(|_| panic!("read {}", file.display()));
        let chars: Vec<char> = text.chars().collect();
        let (mut clean, strings) = lex(&chars);
        blank_test_blocks(&mut clean, &strings);
        extract_from_file(&chars, &clean, &strings, &mut inventory);
    }
    inventory
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

fn extract_from_file(
    original: &[char],
    clean: &[char],
    strings: &[StrLit],
    inventory: &mut BTreeMap<String, BTreeSet<char>>,
) {
    let spans = span_ends(strings);
    let tokens: Vec<Vec<char>> = CALL_TOKENS.iter().map(|t| t.chars().collect()).collect();
    let level_forms: Vec<(Vec<char>, char)> = [
        ("Level::Error", 'E'),
        ("Level::Warning", 'W'),
        ("Level::Info", 'I'),
    ]
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
        if let Some((level_end, letter)) = level {
            // The tag is the first string literal starting at or after the
            // level literal within the window.
            if let Some(lit) = strings
                .iter()
                .find(|l| l.start >= level_end && l.start < end)
            {
                let tag: String = original[lit.content.0..lit.content.1].iter().collect();
                if is_tag(&tag) {
                    inventory.entry(tag).or_default().insert(letter);
                }
            }
        }
        i = pos + tok_len;
    }
}

// ---------------------------------------------------------------------------
// Vendored [Scoring] tables.
// ---------------------------------------------------------------------------

/// relpath (from the crate root) -> (tag -> badness), for every `[Scoring]`
/// table under `data/`.
fn scoring_tables(data_root: &PathBuf) -> BTreeMap<String, BTreeMap<String, i64>> {
    let mut files = Vec::new();
    collect_toml(data_root, &mut files);
    files.sort();
    let mut tables = BTreeMap::new();
    for file in files {
        let text =
            std::fs::read_to_string(&file).unwrap_or_else(|_| panic!("read {}", file.display()));
        let mut in_scoring = false;
        let mut saw_scoring = false;
        let mut entries: BTreeMap<String, i64> = BTreeMap::new();
        for (lineno, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.starts_with('[') {
                in_scoring = line == "[Scoring]";
                saw_scoring |= in_scoring;
                continue;
            }
            if !in_scoring || line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                panic!(
                    "{}:{}: unparsable [Scoring] line: {line}",
                    file.display(),
                    lineno + 1
                );
            };
            let key = key.trim().trim_matches('"');
            let digits: String = value
                .trim()
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '-')
                .collect();
            let badness: i64 = digits.parse().unwrap_or_else(|_| {
                panic!(
                    "{}:{}: unparsable [Scoring] value: {line}",
                    file.display(),
                    lineno + 1
                )
            });
            entries.insert(key.to_string(), badness);
        }
        if saw_scoring {
            let rel = file
                .strip_prefix(core_root())
                .expect("data file under crate root")
                .to_string_lossy()
                .replace('\\', "/");
            tables.insert(rel, entries);
        }
    }
    tables
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

// ---------------------------------------------------------------------------
// The snapshot and the guard.
// ---------------------------------------------------------------------------

fn render_inventory() -> String {
    let root = core_root();
    let emissions = emitted_levels(&root.join("src"));
    let scoring = scoring_tables(&root.join("data"));
    let mut out = String::new();
    out.push_str(
        "# Severity inventory: emitted level(s) per finding tag and the vendored\n\
         # [Scoring] tables, derived mechanically from the tree by the\n\
         # severity_inventory test (crates/rpmcrab-core/tests/severity_inventory.rs).\n\
         #\n\
         # A deliberate level or scoring change updates this file in the same diff:\n\
         #     UPDATE_SEVERITY_INVENTORY=1 cargo test -p rpmcrab-core --test severity_inventory\n\
         # An unintentional change fails the test instead of drifting silently.\n\
         #\n\
         # Only statically literal emission sites are listed. Findings whose tag\n\
         # or level is computed at runtime (format!-built families such as\n\
         # `no-%{sec}-section` and `{check_type}-file-*`, variable tags,\n\
         # data-driven levels) do not appear.\n",
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
    for (rel, entries) in &scoring {
        out.push_str(&format!("\n[scoring {rel}]\n"));
        for (tag, badness) in entries {
            out.push_str(&format!("{tag} = {badness}\n"));
        }
    }
    out
}

#[test]
fn severity_inventory_matches_snapshot() {
    let snapshot_path = core_root().join("tests/data/severity-inventory.txt");
    let derived = render_inventory();
    if std::env::var_os("UPDATE_SEVERITY_INVENTORY").is_some() {
        std::fs::write(&snapshot_path, &derived).expect("write severity inventory snapshot");
        return;
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
