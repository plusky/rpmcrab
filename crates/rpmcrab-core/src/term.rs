//! Terminal-width text centering, byte-compatible with rpmlint's
//! `helpers.string_center` (which is `(" " + msg + " ").center(cols, filler)`).

/// Center `s` to `width` columns with `fill`, matching CPython `str.center`.
///
/// The odd-pad side is not fixed: CPython computes
/// `left = marg // 2 + (marg & width & 1)`, so the extra fill character lands
/// on the **left** only when both the margin and the width are odd. Replicated
/// exactly because the footer and abort banner are grepped verbatim.
pub fn center(s: &str, width: usize, fill: char) -> String {
    let len = s.chars().count();
    if len >= width {
        return s.to_string();
    }
    let marg = width - len;
    let left = marg / 2 + usize::from((marg & width & 1) == 1);
    let right = marg - left;
    let mut out = String::with_capacity(width * fill.len_utf8());
    out.extend(std::iter::repeat_n(fill, left));
    out.push_str(s);
    out.extend(std::iter::repeat_n(fill, right));
    out
}

/// Center `message` exactly as rpmlint does: wrap in a space each side, then
/// center to the terminal width with `filler`.
pub fn string_center(message: &str, filler: char, width: usize) -> String {
    center(&format!(" {message} "), width, filler)
}

/// The terminal width as rpmlint sees it (`shutil.get_terminal_size`):
/// `$COLUMNS` if it is a valid positive integer, then the actual tty winsize,
/// then the 80 fallback. Piped output — the corpus and build-tooling case —
/// takes the 80 fallback (no tty winsize on a pipe).
pub fn terminal_width() -> usize {
    if let Some(n) = std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
    {
        return n;
    }
    terminal_size::terminal_size()
        .map(|(w, _)| usize::from(w.0))
        .filter(|&n| n > 0)
        .unwrap_or(80)
}

/// Expand tabs exactly as CPython `str.expandtabs(8)` (the default `textwrap`
/// `expand_tabs=True`): a tab advances to the next multiple-of-8 column, and
/// the column resets after each `\n` / `\r`.
fn expand_tabs(text: &str) -> String {
    const TABSIZE: usize = 8;
    let mut out = String::with_capacity(text.len());
    let mut col = 0usize;
    for c in text.chars() {
        match c {
            '\t' => {
                let n = TABSIZE - (col % TABSIZE);
                out.extend(std::iter::repeat_n(' ', n));
                col += n;
            }
            '\n' | '\r' => {
                out.push(c);
                col = 0;
            }
            _ => {
                out.push(c);
                col += 1;
            }
        }
    }
    out
}

/// Word-wrap `text` to `width`, matching Python `textwrap.fill(text, width,
/// break_on_hyphens=False)` with defaults (`expand_tabs=True`,
/// `replace_whitespace=True`, `drop_whitespace=True`, `break_long_words=True`).
/// Faithful to CPython `_split`/`_wrap_chunks`/`_handle_long_word`: whitespace
/// runs are preserved as chunks, the first line keeps its leading whitespace,
/// later lines drop theirs, and trailing whitespace is dropped per line.
pub fn textwrap_fill(text: &str, width: usize) -> String {
    use std::collections::VecDeque;
    let char_len = |s: &str| s.chars().count();
    let char_at = |s: &str, n: usize| s.char_indices().nth(n).map(|(i, _)| i).unwrap_or(s.len());

    // expand_tabs runs BEFORE whitespace replacement (CPython _munge_whitespace).
    let expanded = expand_tabs(text);
    let normalized: String = expanded
        .chars()
        .map(|c| {
            if matches!(c, '\n' | '\x0b' | '\x0c' | '\r' | '\t') {
                ' '
            } else {
                c
            }
        })
        .collect();

    // Split into alternating word / whitespace-run chunks, preserving the runs.
    let mut chunks: VecDeque<String> = VecDeque::new();
    {
        let mut cur = String::new();
        let mut cur_ws: Option<bool> = None;
        for c in normalized.chars() {
            let ws = c == ' ';
            if cur_ws == Some(ws) || cur_ws.is_none() {
                cur.push(c);
                cur_ws = Some(ws);
            } else {
                chunks.push_back(std::mem::take(&mut cur));
                cur.push(c);
                cur_ws = Some(ws);
            }
        }
        if !cur.is_empty() {
            chunks.push_back(cur);
        }
    }

    let mut lines: Vec<String> = Vec::new();
    let mut first = true;
    while !chunks.is_empty() {
        // Drop this line's leading whitespace, except on the first line.
        if !first && chunks.front().is_some_and(|c| c.trim().is_empty()) {
            chunks.pop_front();
        }
        first = false;
        if chunks.is_empty() {
            break;
        }

        let mut cur_line: Vec<String> = Vec::new();
        let mut cur_len = 0usize;
        while let Some(front) = chunks.front() {
            let l = char_len(front);
            if cur_len + l <= width {
                cur_line.push(chunks.pop_front().expect("front"));
                cur_len += l;
            } else {
                break;
            }
        }
        // break_long_words: a chunk too long to fit anywhere.
        if let Some(front) = chunks.front().filter(|f| char_len(f) > width) {
            let space_left = width.saturating_sub(cur_len).max(1);
            let at = char_at(front, space_left);
            cur_line.push(front[..at].to_string());
            let rest = front[at..].to_string();
            *chunks.front_mut().expect("front") = rest;
        }
        // Drop this line's trailing whitespace.
        if cur_line.last().is_some_and(|c| c.trim().is_empty()) {
            cur_line.pop();
        }
        if !cur_line.is_empty() {
            lines.push(cur_line.concat());
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn center_matches_cpython() {
        // Verified against python3 str.center:
        // 'ab'.center(7,'=') == '===ab=='  (marg 5, width 7, extra on left)
        assert_eq!(center("ab", 7, '='), "===ab==");
        // 'hello'.center(10,'=') == '==hello==='  (marg 5, width 10, extra on right)
        assert_eq!(center("hello", 10, '='), "==hello===");
        // already-wide input is returned unchanged
        assert_eq!(center("toolong", 3, '='), "toolong");
    }

    #[test]
    fn session_banner_is_80_wide() {
        // Matches the captured banner byte for byte.
        let banner = string_center("rpmlint session starts", '=', 80);
        assert_eq!(
            banner,
            "============================ rpmlint session starts ============================"
        );
        assert_eq!(banner.chars().count(), 80);
    }

    #[test]
    fn textwrap_matches_rpmlint_description() {
        // The `suse-zypp-packageand` description value from the openSUSE
        // descriptions/ZyppSyntaxCheck.toml. TOML trims the newline right after
        // the opening `"""`, so the value starts at "The" and ends with one \n;
        // this is its captured `-v` rendering.
        let raw = "The 'packageand(package1:package2)' syntax is obsolete, please use boolean\ndependencies like:\n'Supplements: (package1 and package2)'\n";
        let expected = "The 'packageand(package1:package2)' syntax is obsolete, please use boolean\ndependencies like: 'Supplements: (package1 and package2)'";
        assert_eq!(textwrap_fill(raw, 78), expected);
    }

    #[test]
    fn textwrap_long_word_fills_leftover_then_full_width() {
        // Verified against CPython textwrap.fill directly:
        // 'aaa '+'b'*15 at width 10 -> 'aaa bbbbbb\nbbbbbbbbb' (head fills the
        // current line's leftover 6 cols, remainder wraps at full width).
        let input = format!("aaa {}", "b".repeat(15));
        assert_eq!(textwrap_fill(&input, 10), "aaa bbbbbb\nbbbbbbbbb");
        // 'shortword '+'v'*20 at width 12 -> 'shortword vv\nvvvvvvvvvvvv\nvvvvvv'
        let input2 = format!("shortword {}", "v".repeat(20));
        assert_eq!(
            textwrap_fill(&input2, 12),
            "shortword vv\nvvvvvvvvvvvv\nvvvvvv"
        );
        // A long word with no open line breaks at full width: 'b'*15 at 10.
        assert_eq!(textwrap_fill(&"b".repeat(15), 10), "bbbbbbbbbb\nbbbbb");
    }

    #[test]
    fn textwrap_expands_tabs_before_whitespace_replacement() {
        // CPython: textwrap.fill('a\tb', 10) == 'a       b' (tab -> next
        // multiple-of-8 column, not a single space).
        assert_eq!(textwrap_fill("a\tb", 10), "a       b");
    }

    #[test]
    fn textwrap_preserves_whitespace_runs_and_drop_semantics() {
        // All verified against CPython textwrap.fill(..., break_on_hyphens=False):
        assert_eq!(textwrap_fill("a       b", 20), "a       b"); // runs preserved
        assert_eq!(
            textwrap_fill("word    with  spaces", 12),
            "word    with\nspaces"
        ); // wrap at a run
        assert_eq!(textwrap_fill(" The quick", 78), " The quick"); // first-line leading ws kept
        assert_eq!(textwrap_fill("trail  ", 78), "trail"); // trailing ws dropped
        assert_eq!(textwrap_fill("  a  b  ", 6), "  a  b");
        assert_eq!(textwrap_fill("one two three", 7), "one two\nthree");
    }
}
