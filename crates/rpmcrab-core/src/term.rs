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

/// The terminal width as rpmlint sees it: `$COLUMNS` if it is a valid
/// positive integer, else 80. (Piped output — the corpus and build-tooling
/// case — takes the 80 fallback; rpmlint uses `shutil.get_terminal_size`,
/// which honours `$COLUMNS` then falls back to 80 when there is no tty.)
pub fn terminal_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(80)
}

/// Word-wrap `text` to `width`, matching Python `textwrap.fill(text, width,
/// break_on_hyphens=False)` with defaults (`replace_whitespace=True`,
/// `drop_whitespace=True`, `break_long_words=True`). Used for the `-v`
/// explanation paragraphs; verified against captured `-v` output.
pub fn textwrap_fill(text: &str, width: usize) -> String {
    // replace_whitespace: each whitespace char becomes a space.
    let normalized: String = text
        .chars()
        .map(|c| {
            if matches!(c, '\t' | '\n' | '\x0b' | '\x0c' | '\r') {
                ' '
            } else {
                c
            }
        })
        .collect();
    // drop_whitespace at the ends of the whole text.
    let normalized = normalized.trim_matches(' ');
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    for word in normalized.split(' ') {
        // drop_whitespace: skip the empty fragments from consecutive spaces.
        if word.is_empty() {
            continue;
        }
        // break_long_words: a word longer than width starts on its own line and
        // is hard-broken at width.
        let mut w = word;
        while w.chars().count() > width {
            if !cur.is_empty() {
                lines.push(std::mem::take(&mut cur));
            }
            let byte_at = w
                .char_indices()
                .nth(width)
                .map(|(i, _)| i)
                .unwrap_or(w.len());
            lines.push(w[..byte_at].to_string());
            w = &w[byte_at..];
        }
        if cur.is_empty() {
            cur = w.to_string();
        } else if cur.chars().count() + 1 + w.chars().count() <= width {
            cur.push(' ');
            cur.push_str(w);
        } else {
            lines.push(std::mem::take(&mut cur));
            cur = w.to_string();
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
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
        // The raw `suse-zypp-packageand` description from the openSUSE
        // descriptions/ZyppSyntaxCheck.toml, and its captured `-v` rendering.
        let raw = "\nThe 'packageand(package1:package2)' syntax is obsolete, please use boolean\ndependencies like:\n'Supplements: (package1 and package2)'\n";
        let expected = "The 'packageand(package1:package2)' syntax is obsolete, please use boolean\ndependencies like: 'Supplements: (package1 and package2)'";
        assert_eq!(textwrap_fill(raw, 78), expected);
    }
}
