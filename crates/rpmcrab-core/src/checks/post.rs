//! `PostCheck` — scriptlet content checks.
//!
//! Ported from `rpmlint/checks/PostCheck.py`. The regex-based findings are
//! ported natively; the `sh -n` / `perl -wc` syntax checks shell out when
//! the interpreter exists and are skipped otherwise.

use std::process::Command;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::atomic_update::direct_user_creation_in_body;
use crate::checks::atomic_update::rc_link_invocations_in_body;
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use librpm::Tag;
use std::sync::OnceLock;

pub struct PostCheck {
    valid_shells: Vec<String>,
    empty_shells: Vec<String>,
}

/// Scanner state `PostCheck::heredoc_delimiters` threads across the
/// lines of a scriptlet: shell quotes and arithmetic expansions span
/// lines, so a `<<` on the continuation line of a quoted string is
/// string content, not a heredoc operator.
#[derive(Default)]
struct HeredocScan {
    in_single: bool,
    in_double: bool,
    arith_depth: usize,
    bracket_depth: usize,
}

static POST_MENU_RE: OnceLock<Regex> = OnceLock::new();

impl PostCheck {
    pub fn new(config: &Config) -> Self {
        let get_list = |key: &str, default: &[&str]| {
            config
                .configuration
                .get(key)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_else(|| default.iter().map(|s| s.to_string()).collect())
        };
        Self {
            valid_shells: get_list(
                "ValidShells",
                &[
                    "<lua>",
                    "/bin/sh",
                    "/bin/bash",
                    "/sbin/sash",
                    "/usr/bin/perl",
                    "/sbin/ldconfig",
                ],
            ),
            empty_shells: get_list("ValidEmptyShells", &["/sbin/ldconfig"]),
        }
    }

    fn percent_regex() -> &'static Regex {
        static PERCENT_REGEX: OnceLock<Regex> = OnceLock::new();
        PERCENT_REGEX.get_or_init(|| Regex::new(r"(?m)^[^#]*%+\{?\w{3,}").expect("static regex"))
    }
    fn home_regex() -> &'static Regex {
        static HOME_REGEX: OnceLock<Regex> = OnceLock::new();
        HOME_REGEX
            .get_or_init(|| Regex::new(r"(?m)[^a-zA-Z]+~/|\$\{?HOME(\W|$)").expect("static regex"))
    }
    fn dangerous_regex() -> &'static Regex {
        static DANGEROUS_REGEX: OnceLock<Regex> = OnceLock::new();
        DANGEROUS_REGEX.get_or_init(|| Regex::new(
            r"(?m)(^|[;`|]|&&|$\()\s*(?:\S*/s?bin/)?(cp|mv|ln|tar|rpm|chmod|chown|rm|cpio|install|perl|userdel|groupdel)\s",
        )
        .expect("static regex"))
    }
    fn selinux_regex() -> &'static Regex {
        static SELINUX_REGEX: OnceLock<Regex> = OnceLock::new();
        SELINUX_REGEX.get_or_init(|| {
            Regex::new(r"(?m)(^|[;`|]|&&|$\()\s*(?:\S*/s?bin/)?(chcon|runcon)\s")
                .expect("static regex")
        })
    }
    fn tmp_token_regex() -> &'static Regex {
        static TMP_TOKEN_REGEX: OnceLock<Regex> = OnceLock::new();
        TMP_TOKEN_REGEX
            .get_or_init(|| Regex::new(r"(?:^|\s)((?:/var)?/tmp[^\s]*)").expect("static regex"))
    }

    /// Whether the scriptlet names a *literal* path under /tmp or /var/tmp.
    ///
    /// Deliberate divergence from the reference, whose `tmp_regex` fires on
    /// any whitespace-preceded `/tmp` token: a token that is a creation
    /// template (a run of `X`, the mktemp/mkstemp convention — the name is
    /// generated at runtime, not predictable) or a shell glob pattern (it
    /// matches existing files instead of naming a creation target) is not
    /// a predictable path and does not fire. Lines inside a heredoc fed to
    /// `systemd-tmpfiles` are declarative tmpfiles.d entries, not scriptlet
    /// scratch use, and do not fire either. Ledgered in
    /// tests/parity/divergences.toml.
    fn uses_tmp_literal(script: &str) -> bool {
        // Pending heredocs in the order their bodies appear:
        // (delimiter, body is fed to `systemd-tmpfiles`, `<<-` form).
        let mut pending: Vec<(String, bool, bool)> = Vec::new();
        // Quote/arithmetic state spans lines; the heredoc scanner
        // threads it so a phantom opener inside a multi-line string
        // cannot swallow the blocks after it.
        let mut scan = HeredocScan::default();
        let physical: Vec<&str> = script.lines().collect();
        let mut idx = 0;
        while idx < physical.len() {
            if !pending.is_empty() {
                let line = physical[idx];
                idx += 1;
                // Compare through a borrow; only the terminator line
                // mutates the queue.
                let (terminated, exempt) = {
                    let (delim, exempt, strip_tabs) = &pending[0];
                    (
                        Self::tmp_heredoc_terminator(line, delim, *strip_tabs),
                        *exempt,
                    )
                };
                if terminated {
                    pending.remove(0);
                    continue;
                }
                if exempt {
                    continue;
                }
                if Self::line_has_tmp_literal(line) {
                    return true;
                }
                continue;
            }
            // A backslash-continued command is one logical line to the
            // shell: join continuations before scanning, so a wrapped
            // invocation is attributed whole.
            let mut logical = physical[idx].to_string();
            idx += 1;
            while Self::ends_with_continuation(&logical) && idx < physical.len() {
                logical.pop();
                logical.push_str(physical[idx]);
                idx += 1;
            }
            if Self::line_has_tmp_literal(&logical) {
                return true;
            }
            // The reference's `^[^#]*` prefix cannot cross a `#`.
            let code = logical.split('#').next().unwrap_or("");
            pending.extend(Self::heredoc_delimiters(code, &mut scan));
        }
        false
    }

    /// Whether `line` terminates a tmpfiles-scan heredoc: an exact
    /// match for the plain form, leading tabs stripped for the `<<-`
    /// form — the shell's own rule, so a delimiter-like body line
    /// that is indented or carries trailing blanks does not end the
    /// body early.
    fn tmp_heredoc_terminator(line: &str, delim: &str, strip_tabs: bool) -> bool {
        if strip_tabs {
            line.trim_start_matches('\t') == delim
        } else {
            line == delim
        }
    }

    /// Whether the line's code portion (before any `#` comment) ends
    /// in an unescaped backslash, i.e. the shell joins the next
    /// physical line onto this one.
    fn ends_with_continuation(line: &str) -> bool {
        let code = line.split('#').next().unwrap_or("");
        code.chars().rev().take_while(|c| *c == '\\').count() % 2 == 1
    }

    fn line_has_tmp_literal(line: &str) -> bool {
        // The reference's `^[^#]*` prefix cannot cross a `#`.
        let code = line.split('#').next().unwrap_or("");
        Self::tmp_token_regex()
            .captures_iter(code)
            .filter_map(|c| c.ok())
            .filter_map(|c| c.get(1))
            .any(|m| {
                let token = m.as_str();
                !token.contains('*') && !token.contains('[') && !token.contains("XXX")
            })
    }

    fn invokes_systemd_tmpfiles(code: &str) -> bool {
        code.split(|c: char| {
            c.is_whitespace() || matches!(c, ';' | '|' | '&' | '(' | ')' | '`' | '"' | '\'')
        })
        .any(|tok| tok == "systemd-tmpfiles" || tok.ends_with("/systemd-tmpfiles"))
    }

    /// Whether a command segment feeds `systemd-tmpfiles` from stdin:
    /// it invokes the tool and passes the standalone `-` path argument
    /// whose content the heredoc supplies.
    fn segment_feeds_tmpfiles_stdin(segment: &str) -> bool {
        Self::invokes_systemd_tmpfiles(segment)
            && segment
                .split(|c: char| {
                    c.is_whitespace()
                        || matches!(
                            c,
                            ';' | '|' | '&' | '(' | ')' | '`' | '"' | '\'' | '<' | '>'
                        )
                })
                .any(|tok| tok == "-")
    }

    /// Heredocs opened on a line, in order, each paired with whether
    /// its body is fed to `systemd-tmpfiles` and whether the operator
    /// is the `<<-` form. Handles the plain, `<<-`, and
    /// quoted-delimiter forms; a herestring is not a heredoc. A `<<`
    /// inside single/double quotes or inside an arithmetic context
    /// (a `$((...))` expansion, the `((...))` command, a `$[...]`
    /// expansion, a `let` expression), where it is the left-shift
    /// operator, is not a heredoc operator. Quote and arithmetic
    /// state lives in `scan` and threads across the scriptlet's
    /// lines, because both span lines. The exemption is per heredoc,
    /// not per line: only the last heredoc of a command segment that
    /// feeds `systemd-tmpfiles` its `-` stdin is exempt — the shell
    /// reads and discards the earlier stdin redirections — so a
    /// heredoc opened by another command on the same line is still
    /// scanned.
    fn heredoc_delimiters(code: &str, scan: &mut HeredocScan) -> Vec<(String, bool, bool)> {
        let bytes = code.as_bytes();
        // (byte offset of the `<<`, delimiter, `<<-` form), plus the
        // byte offsets of the command separators (`;`, `|`, `&`) seen
        // in code position — each heredoc belongs to the segment
        // around it.
        let mut found: Vec<(usize, String, bool)> = Vec::new();
        let mut separators: Vec<usize> = Vec::new();
        // A `let` command makes the rest of its segment arithmetic.
        let mut arith_segment = false;
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            if scan.in_single {
                if c == b'\'' {
                    scan.in_single = false;
                }
                i += 1;
                continue;
            }
            if scan.in_double {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == b'"' {
                    scan.in_double = false;
                }
                i += 1;
                continue;
            }
            if scan.arith_depth > 0 {
                if c == b'(' {
                    scan.arith_depth += 1;
                } else if c == b')' {
                    scan.arith_depth -= 1;
                }
                i += 1;
                continue;
            }
            if scan.bracket_depth > 0 {
                if c == b'[' {
                    scan.bracket_depth += 1;
                } else if c == b']' {
                    scan.bracket_depth -= 1;
                }
                i += 1;
                continue;
            }
            match c {
                b'\\' => {
                    i += 2;
                    continue;
                }
                b'\'' => scan.in_single = true,
                b'"' => scan.in_double = true,
                b'$' => {
                    if code[i..].starts_with("$((") {
                        scan.arith_depth = 2;
                        i += 3;
                        continue;
                    }
                    if code[i..].starts_with("$[") {
                        scan.bracket_depth = 1;
                        i += 2;
                        continue;
                    }
                }
                b'(' => {
                    // The `((...))` arithmetic command at command
                    // position: its `<<` is the left-shift operator.
                    if code[i..].starts_with("((")
                        && (i == 0
                            || matches!(bytes[i - 1], b' ' | b'\t' | b';' | b'|' | b'&' | b'('))
                    {
                        scan.arith_depth = 2;
                        i += 2;
                        continue;
                    }
                }
                b'l' => {
                    // A leading `let` makes the rest of the segment
                    // an arithmetic expression.
                    let seg_start = separators
                        .iter()
                        .copied()
                        .filter(|s| *s < i)
                        .max()
                        .map_or(0, |s| s + 1);
                    if code[seg_start..i].trim().is_empty()
                        && code[i..].starts_with("let")
                        && matches!(bytes.get(i + 3).copied(), None | Some(b' ') | Some(b'\t'))
                    {
                        arith_segment = true;
                        i += 3;
                        continue;
                    }
                }
                b';' | b'|' | b'&' => {
                    separators.push(i);
                    arith_segment = false;
                }
                b'<' => {
                    if arith_segment {
                        i += 1;
                        continue;
                    }
                    if code[i..].starts_with("<<<") {
                        i += 3;
                        continue;
                    }
                    if code[i..].starts_with("<<") {
                        if let Some((delim, strip_tabs, next)) = Self::delimiter_after(code, i) {
                            found.push((i, delim, strip_tabs));
                            i = next;
                            continue;
                        }
                        i += 2;
                        continue;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        let seg_start = |at: usize| {
            separators
                .iter()
                .copied()
                .filter(|s| *s < at)
                .max()
                .map_or(0, |s| s + 1)
        };
        // The shell feeds a segment's stdin from its LAST heredoc:
        // earlier stdin redirections are read and discarded.
        let mut last_in_segment: std::collections::HashMap<usize, usize> =
            std::collections::HashMap::new();
        for (idx, (at, _, _)) in found.iter().enumerate() {
            last_in_segment.insert(seg_start(*at), idx);
        }
        found
            .into_iter()
            .enumerate()
            .map(|(idx, (at, delim, strip_tabs))| {
                let start = seg_start(at);
                let end = separators
                    .iter()
                    .copied()
                    .filter(|s| *s > at)
                    .min()
                    .unwrap_or(code.len());
                let exempt = last_in_segment[&start] == idx
                    && Self::segment_feeds_tmpfiles_stdin(&code[start..end]);
                (delim, exempt, strip_tabs)
            })
            .collect()
    }

    /// Parse the delimiter following a `<<` at byte offset `at` in
    /// `code`; returns the delimiter, whether the operator is the
    /// `<<-` strip-tabs form, and the offset just past the delimiter.
    /// The delimiter is the full shell word, so a hyphen or dot
    /// inside it (`<<MY-DELIM`, `<<MY.DELIM`) is part of the
    /// delimiter, not its end. A leading `-` is the `<<-` strip-tabs
    /// marker, not part of the word.
    fn delimiter_after(code: &str, at: usize) -> Option<(String, bool, usize)> {
        let bytes = code.as_bytes();
        let mut j = at + 2;
        let strip_tabs = j < bytes.len() && bytes[j] == b'-';
        if strip_tabs {
            j += 1;
        }
        while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
        if j < bytes.len() && (bytes[j] == b'\'' || bytes[j] == b'"') {
            let quote = bytes[j];
            j += 1;
            let start = j;
            while j < bytes.len() && bytes[j] != quote {
                j += 1;
            }
            if j == start {
                return None;
            }
            let delim = code[start..j].to_string();
            if j < bytes.len() {
                j += 1;
            }
            return Some((delim, strip_tabs, j));
        }
        if j < bytes.len() && bytes[j] == b'\\' {
            j += 1;
        }
        let start = j;
        while j < bytes.len()
            && (bytes[j].is_ascii_alphanumeric() || matches!(bytes[j], b'_' | b'-' | b'.'))
        {
            j += 1;
        }
        if j == start || !(bytes[start].is_ascii_alphabetic() || bytes[start] == b'_') {
            return None;
        }
        Some((code[start..j].to_string(), strip_tabs, j))
    }
    fn bogus_var_regex() -> &'static Regex {
        static BOGUS_VAR_REGEX: OnceLock<Regex> = OnceLock::new();
        BOGUS_VAR_REGEX
            .get_or_init(|| Regex::new(r"(\$\{?RPM_BUILD_(ROOT|DIR)}?)").expect("static regex"))
    }

    fn insserv_regex() -> &'static Regex {
        static INSSERV_REGEX: OnceLock<Regex> = OnceLock::new();
        INSSERV_REGEX.get_or_init(|| {
            Regex::new(
                r"(?m)((?:^|[;`|]|&&|&|\$\()\s*(?:then\s+|do\s+|else\s+)?|^\s*[^\s()]+\s*\)\s*)(?:\S*/)?insserv\b([^\n;|&]*)",
            )
            .expect("static regex")
        })
    }
    fn systemctl_regex() -> &'static Regex {
        static SYSTEMCTL_REGEX: OnceLock<Regex> = OnceLock::new();
        SYSTEMCTL_REGEX.get_or_init(|| {
            // `restart` and `reload-or-restart` unconditionally start an
            // inactive unit, and `reenable` disables then enables, so all
            // three activate just as `enable`/`start` do. The try-forms
            // (`try-restart`, `condrestart`, `reload-or-try-restart`)
            // genuinely no-op when the unit is inactive and stay quiet.
            // In the args tail, `>&` is tried before the single-character
            // class: the class would consume the `>` first and truncate
            // the capture at the `&`, dropping units named after a
            // `>&` redirection.
            Regex::new(
                r"(?m)((?:^|[;`|]|&&|&|\$\()\s*(?:then\s+|do\s+|else\s+)?|^\s*[^\s()]+\s*\)\s*)(?:\S*/)?systemctl\s+(?:--?\S+\s+)*(reload-or-restart|reenable|enable|start|restart)\b((?:>&|[^\n;|&]|&[\d-]|&>>?)*)",
            )
            .expect("static regex")
        })
    }
    fn chkconfig_regex() -> &'static Regex {
        static CHKCONFIG_REGEX: OnceLock<Regex> = OnceLock::new();
        CHKCONFIG_REGEX.get_or_init(|| {
            Regex::new(
                r"(?m)((?:^|[;`|]|&&|&|\$\()\s*(?:then\s+|do\s+|else\s+)?|^\s*[^\s()]+\s*\)\s*)(?:\S*/)?chkconfig\b([^\n;|&]*)",
            )
            .expect("static regex")
        })
    }

    fn cache_updater_regex() -> &'static Regex {
        static CACHE_UPDATER_REGEX: OnceLock<Regex> = OnceLock::new();
        CACHE_UPDATER_REGEX.get_or_init(|| {
            Regex::new(
                r"(?m)((?:^|[;`|{]|&&|&|\$\(|\()\s*(?:then\s+|do\s+|else\s+)?|^\s*[^\s()]+\s*\)\s*)(?:env\s+)?(?:[A-Za-z_]\w*=\S*\s+)*(?:[^\s=]*/)?(update-desktop-database|gtk-update-icon-cache|update-mime-database|glib-compile-schemas|install-info)\b((?:[^\n;|&]|&[\d-])*)",
            )
            .expect("static regex")
        })
    }

    /// Scriptlet text with heredoc bodies blanked. Text a scriptlet
    /// writes out (an update message, a generated file) is not executed,
    /// so a command named inside it is not an invocation.
    pub(crate) fn without_heredoc_bodies(script: &str) -> String {
        // Parse the delimiter following a `<<` at byte offset `at` in
        // `line`: the delimiter word, and whether the operator is the
        // `<<-` form (whose terminator may be indented with tabs).
        // Handles the plain (`<<EOF`), quoted (`<<'EOF'`, `<<"EOF"`),
        // escaped (`<<\EOF`) and ANSI-C-quoted (`<<$'EOF'`) forms.
        fn delimiter_after(line: &str, at: usize) -> Option<(String, bool)> {
            // A delimiter word ends at whitespace or a shell
            // metacharacter; `-`, `.` and `:` are ordinary delimiter
            // characters (`<<'END-OF-MESSAGE'`, `<<EOF.2`).
            fn is_stop(c: char) -> bool {
                c.is_whitespace()
                    || matches!(
                        c,
                        ';' | '|' | '&' | '<' | '>' | '(' | ')' | '`' | '\'' | '"'
                    )
            }
            fn finish(word: String) -> Option<String> {
                if word.is_empty() || word.starts_with(|c: char| c.is_ascii_digit()) {
                    None
                } else {
                    Some(word)
                }
            }
            // The quoted text up to the matching closing quote.
            fn quoted_word(s: &str, q: char) -> Option<String> {
                finish(s.chars().take_while(|c| *c != q).collect())
            }
            let rest = &line[at + 2..];
            let (rest, strip_tabs) = match rest.strip_prefix('-') {
                Some(r) => (r, true),
                None => (rest, false),
            };
            let rest = rest.trim_start();
            if let Some(quoted) = rest.strip_prefix('$') {
                // `$'EOF'` / `$"EOF"`: the delimiter is the quoted text.
                let q = quoted.chars().next()?;
                if q != '\'' && q != '"' {
                    return None;
                }
                return quoted_word(&quoted[q.len_utf8()..], q).map(|w| (w, strip_tabs));
            }
            if let Some(escaped) = rest.strip_prefix('\\') {
                // `\EOF`: a backslash quotes the next character into
                // the delimiter; the word ends at an unquoted stop.
                let mut word = String::new();
                let mut chars = escaped.chars();
                loop {
                    match chars.next() {
                        None => break,
                        Some('\\') => match chars.next() {
                            Some(c) => word.push(c),
                            None => break,
                        },
                        Some(c) if is_stop(c) => break,
                        Some(c) => word.push(c),
                    }
                }
                return finish(word).map(|w| (w, strip_tabs));
            }
            if let Some(quoted) = rest
                .strip_prefix('\'')
                .map(|s| (s, '\''))
                .or_else(|| rest.strip_prefix('"').map(|s| (s, '"')))
            {
                return quoted_word(quoted.0, quoted.1).map(|w| (w, strip_tabs));
            }
            finish(rest.chars().take_while(|c| !is_stop(*c)).collect()).map(|w| (w, strip_tabs))
        }
        // Delimiters introduced by unquoted `<<` operators on `line`.
        // A `<<` inside single/double quotes, inside a `#` comment, or
        // inside a `$((...))` arithmetic expansion (where it is the
        // left-shift operator) is not a heredoc operator, and `<<<`
        // is a herestring, not a heredoc.
        fn delimiters_in_line(line: &str) -> Vec<(String, bool)> {
            // Context stack: a `$(...)` or backtick substitution
            // re-enters code even inside double quotes, so a heredoc
            // operator inside one is live; `$((...))` arithmetic is
            // skipped whole (its `<<` is the left-shift operator).
            #[derive(Clone, Copy)]
            enum Frame {
                Subst(usize),
                Backtick(usize),
                Arith(usize),
                Single,
                Double,
            }
            let bytes = line.as_bytes();
            let mut out = Vec::new();
            let mut stack: Vec<Frame> = Vec::new();
            let mut i = 0;
            while i < bytes.len() {
                let c = bytes[i] as char;
                if matches!(stack.last(), Some(Frame::Single)) {
                    if c == '\'' {
                        stack.pop();
                    }
                    i += 1;
                    continue;
                }
                if matches!(stack.last(), Some(Frame::Arith(_))) {
                    match c {
                        '(' => {
                            if let Some(Frame::Arith(d)) = stack.last_mut() {
                                *d += 1;
                            }
                        }
                        ')' => {
                            let done = match stack.last_mut() {
                                Some(Frame::Arith(d)) => {
                                    *d -= 1;
                                    *d == 0
                                }
                                _ => false,
                            };
                            if done {
                                stack.pop();
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                    continue;
                }
                if matches!(stack.last(), Some(Frame::Double)) {
                    match c {
                        '\\' => i += 2,
                        '"' => {
                            stack.pop();
                            i += 1;
                        }
                        '$' if line[i..].starts_with("$((") => {
                            stack.push(Frame::Arith(2));
                            i += 3;
                        }
                        '$' if line[i..].starts_with("$(") => {
                            stack.push(Frame::Subst(0));
                            i += 2;
                        }
                        '`' => {
                            stack.push(Frame::Backtick(0));
                            i += 1;
                        }
                        _ => i += 1,
                    }
                    continue;
                }
                match c {
                    '\\' => {
                        i += 2;
                    }
                    '\'' => {
                        stack.push(Frame::Single);
                        i += 1;
                    }
                    '"' => {
                        stack.push(Frame::Double);
                        i += 1;
                    }
                    '`' => {
                        if matches!(stack.last(), Some(Frame::Backtick(_))) {
                            stack.pop();
                        } else {
                            stack.push(Frame::Backtick(0));
                        }
                        i += 1;
                    }
                    '#' => {
                        // A `#` starting a word begins a comment.
                        if i == 0
                            || matches!(bytes[i - 1] as char, ' ' | '\t' | ';' | '|' | '&' | '(')
                        {
                            break;
                        }
                        i += 1;
                    }
                    '$' if line[i..].starts_with("$((") => {
                        stack.push(Frame::Arith(2));
                        i += 3;
                    }
                    '$' if line[i..].starts_with("$(") => {
                        stack.push(Frame::Subst(0));
                        i += 2;
                    }
                    '(' => {
                        match stack.last_mut() {
                            Some(Frame::Subst(d)) | Some(Frame::Backtick(d)) => *d += 1,
                            _ => {}
                        }
                        i += 1;
                    }
                    ')' => {
                        match stack.last_mut() {
                            Some(Frame::Subst(d)) | Some(Frame::Backtick(d)) if *d > 0 => {
                                *d -= 1;
                            }
                            Some(Frame::Subst(_)) => {
                                stack.pop();
                            }
                            _ => {}
                        }
                        i += 1;
                    }
                    '<' => {
                        if line[i..].starts_with("<<<") {
                            i += 3;
                            continue;
                        }
                        if line[i..].starts_with("<<")
                            && let Some(delim) = delimiter_after(line, i)
                        {
                            out.push(delim);
                            i += 2;
                            continue;
                        }
                        i += 1;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }
            out
        }
        // Whether `line` terminates the heredoc: an exact match for
        // the plain form, leading tabs stripped for the `<<-` form —
        // the shell's own rule, so an indented body line that merely
        // looks like the delimiter does not end the body early.
        fn is_terminator(line: &str, delim: &str, strip_tabs: bool) -> bool {
            if strip_tabs {
                line.trim_start_matches('\t') == delim
            } else {
                line == delim
            }
        }
        let lines: Vec<&str> = script.lines().collect();
        let mut pending: Vec<(String, bool)> = Vec::new();
        let mut out: Vec<&str> = Vec::new();
        for (idx, line) in lines.iter().enumerate() {
            if let Some((delim, strip_tabs)) = pending.first().cloned() {
                if is_terminator(line, &delim, strip_tabs) {
                    pending.remove(0);
                    out.push(line);
                } else {
                    out.push("");
                }
                continue;
            }
            // Only blank when a terminator actually appears later in
            // the scriptlet: a false opener otherwise blanks the rest
            // of the scriptlet and hides genuine invocations.
            for (delim, strip_tabs) in delimiters_in_line(line) {
                if lines[idx + 1..]
                    .iter()
                    .any(|l| is_terminator(l, &delim, strip_tabs))
                {
                    pending.push((delim, strip_tabs));
                }
            }
            out.push(line);
        }
        out.join("\n")
    }

    /// A scriptlet with comments removed and quoted-string contents
    /// blanked to spaces, for command matching: text inside a comment
    /// or a quoted string never executes, so a shell separator there
    /// does not put a following command name at command position.
    /// Command substitutions are the exception — `$(...)` and
    /// backticks execute even inside double quotes, so their contents
    /// stay live. The quote characters are kept; only the contents go.
    /// The result is length-preserving (comment text is blanked, not
    /// cut), so a match span in the result is the same span in the
    /// input. The frame stack threads across lines, like the heredoc
    /// scan: a quoted string spanning lines keeps its continuation
    /// lines blanked instead of letting them read as code.
    pub(crate) fn code_only(script: &str) -> String {
        #[derive(Clone, Copy)]
        enum Frame {
            // Parenthesis depth within a `$(...)` frame.
            Subst(usize),
            // Parenthesis depth within a backtick frame.
            Backtick(usize),
            Single,
            Double,
        }
        fn code_line(line: &str, stack: &mut Vec<Frame>) -> String {
            let bytes = line.as_bytes();
            let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
            let mut i = 0;
            while i < bytes.len() {
                let c = bytes[i] as char;
                match stack.last() {
                    Some(Frame::Single) => {
                        if c == '\'' {
                            out.push(bytes[i]);
                            stack.pop();
                        } else {
                            out.push(b' ');
                        }
                        i += 1;
                    }
                    Some(Frame::Double) => match c {
                        '\\' => {
                            out.push(b' ');
                            if i + 1 < bytes.len() {
                                out.push(b' ');
                                i += 1;
                            }
                            i += 1;
                        }
                        '"' => {
                            out.push(bytes[i]);
                            stack.pop();
                            i += 1;
                        }
                        '$' if line[i..].starts_with("$(") => {
                            out.extend_from_slice(b"$(");
                            stack.push(Frame::Subst(0));
                            i += 2;
                        }
                        '`' => {
                            out.push(bytes[i]);
                            stack.push(Frame::Backtick(0));
                            i += 1;
                        }
                        _ => {
                            out.push(b' ');
                            i += 1;
                        }
                    },
                    _ => match c {
                        '\\' => {
                            out.push(bytes[i]);
                            if i + 1 < bytes.len() {
                                // An escaped separator or quote is a
                                // literal argument character, not
                                // syntax: blank the escaped byte so
                                // matchers cannot read the separator
                                // (the double-quote frame blanks
                                // escaped bytes the same way).
                                if matches!(
                                    bytes[i + 1] as char,
                                    ';' | '|'
                                        | '&'
                                        | '`'
                                        | '\''
                                        | '"'
                                        | '('
                                        | ')'
                                        | '<'
                                        | '>'
                                        | '#'
                                        | '$'
                                ) {
                                    out.push(b' ');
                                } else {
                                    out.push(bytes[i + 1]);
                                }
                                i += 1;
                            }
                            i += 1;
                        }
                        '\'' => {
                            out.push(bytes[i]);
                            stack.push(Frame::Single);
                            i += 1;
                        }
                        '"' => {
                            out.push(bytes[i]);
                            stack.push(Frame::Double);
                            i += 1;
                        }
                        '`' => {
                            out.push(bytes[i]);
                            if matches!(stack.last(), Some(Frame::Backtick(_))) {
                                stack.pop();
                            } else {
                                stack.push(Frame::Backtick(0));
                            }
                            i += 1;
                        }
                        '$' if line[i..].starts_with("$(") => {
                            out.extend_from_slice(b"$(");
                            stack.push(Frame::Subst(0));
                            i += 2;
                        }
                        '(' => {
                            match stack.last_mut() {
                                Some(Frame::Subst(d)) | Some(Frame::Backtick(d)) => *d += 1,
                                _ => {}
                            }
                            out.push(bytes[i]);
                            i += 1;
                        }
                        ')' => {
                            match stack.last_mut() {
                                Some(Frame::Subst(d)) | Some(Frame::Backtick(d)) if *d > 0 => {
                                    *d -= 1;
                                }
                                Some(Frame::Subst(_)) => {
                                    stack.pop();
                                }
                                _ => {}
                            }
                            out.push(bytes[i]);
                            i += 1;
                        }
                        '#' => {
                            // A `#` starting a word begins a comment
                            // (the `delimiters_in_line` rule); blank
                            // the rest of the line rather than cutting
                            // it, keeping the line's length.
                            if i == 0
                                || matches!(
                                    bytes[i - 1] as char,
                                    ' ' | '\t' | ';' | '|' | '&' | '('
                                )
                            {
                                out.resize(bytes.len(), b' ');
                                break;
                            }
                            out.push(bytes[i]);
                            i += 1;
                        }
                        _ => {
                            out.push(bytes[i]);
                            i += 1;
                        }
                    },
                }
            }
            String::from_utf8(out).expect("blanking preserves UTF-8")
        }
        let mut stack: Vec<Frame> = Vec::new();
        script
            .lines()
            .map(|line| code_line(line, &mut stack))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Cache and database updaters invoked at command position in a
    /// scriptlet and aimed at a directory the RPM file triggers own,
    /// in first-seen order, each named once. The triggers already run
    /// these commands when the files they index change, so a
    /// hand-rolled invocation duplicates the trigger. Matching runs on
    /// the heredoc-blanked, comment-stripped, quote-blanked text
    /// (`code_only`) and is command-position only (start of line or
    /// after a command separator — a bare `&` backgrounding included —
    /// a `then`/`do`/`else` keyword, a subshell or group opener, an
    /// `env` or environment assignment, or a `case` pattern; a `sudo`
    /// prefix is not recognised), so comments, quoted or echoed text
    /// and heredoc bodies do not fire.
    fn cache_updaters(script: &str) -> Vec<String> {
        let blanked = Self::without_heredoc_bodies(script);
        let text = Self::code_only(&blanked);
        let mut out: Vec<String> = Vec::new();
        for caps in Self::cache_updater_regex().captures_iter(&text).flatten() {
            let (Some(cmd), Some(args)) = (caps.get(2), caps.get(3)) else {
                continue;
            };
            // `code_only` is length-preserving, so the args span in
            // the matched text is the same span in the heredoc-blanked
            // text, where quoted arguments survive for classification.
            if !Self::cache_target_is_trigger_owned(&blanked[args.range()]) {
                continue;
            }
            let cmd = cmd.as_str().to_string();
            if !out.contains(&cmd) {
                out.push(cmd);
            }
        }
        out
    }

    /// Whether an invocation with argument tail `args` (the raw text
    /// following the command name, up to the next command separator)
    /// is pointed at a directory the RPM file triggers own. The
    /// indexed directory is the `--info-dir`/`--targetdir` value when
    /// one is given, else the first positional argument; no positional
    /// argument means the tool's default directory. Redirections are
    /// not the target: fd-prefixed and attached forms are
    /// self-contained and a bare operator consumes the following
    /// token. The triggers own
    /// the system data directories (`/usr/share`, `/usr/local/share`);
    /// a literal absolute target anywhere else (e.g.
    /// `/opt/<app>/schemas`) is a private directory no file trigger
    /// indexes — the manual call is the only thing building that
    /// cache, so it stays quiet. A target that is not a literal
    /// absolute path (relative, a shell variable, a macro) cannot be
    /// proven private and counts as trigger-owned.
    fn cache_target_is_trigger_owned(args: &str) -> bool {
        let mut tokens = args.split_whitespace().peekable();
        let mut explicit_dir: Option<String> = None;
        let mut positional: Option<String> = None;
        while let Some(tok) = tokens.next() {
            let tok = tok.trim_matches(|c| c == '"' || c == '\'');
            if tok.is_empty() {
                continue;
            }
            if let Some(v) = tok
                .strip_prefix("--info-dir=")
                .or_else(|| tok.strip_prefix("--targetdir="))
                .or_else(|| tok.strip_prefix("--infodir="))
            {
                explicit_dir = Some(v.trim_matches(|c| c == '"' || c == '\'').to_string());
                continue;
            }
            if matches!(
                tok,
                "--info-dir" | "--targetdir" | "--infodir" | "--dir-file"
            ) {
                if let Some(v) = tokens.next()
                    && tok != "--dir-file"
                {
                    explicit_dir = Some(v.trim_matches(|c| c == '"' || c == '\'').to_string());
                }
                continue;
            }
            if tok.starts_with('-') {
                continue;
            }
            // A redirection is not the target. Fd-prefixed and
            // attached forms (`2>/dev/null`, `2>&1`) are
            // self-contained; a bare operator (`>`, `2>`) consumes
            // the next token as its target file.
            let redir = tok
                .trim_start_matches(|c: char| c.is_ascii_digit())
                .trim_start_matches('&');
            if redir.starts_with('>') || redir.starts_with('<') {
                if redir.chars().all(|c| matches!(c, '>' | '<' | '&')) {
                    tokens.next();
                }
                continue;
            }
            if positional.is_none() {
                positional = Some(tok.to_string());
            }
        }
        let target = explicit_dir.as_deref().or(positional.as_deref());
        match target {
            None => true,
            Some(t) => {
                !t.starts_with('/')
                    || t == "/usr/share"
                    || t == "/usr/local/share"
                    || t.starts_with("/usr/share/")
                    || t.starts_with("/usr/local/share/")
            }
        }
    }

    /// Daemon activations in a scriptlet: an `insserv` invocation that
    /// installs an init script (the removal form, `-r`/`--remove`,
    /// deactivates and is not an activation), each distinct
    /// activating `systemctl` verb form, and the `chkconfig` enable
    /// forms (`chkconfig <name> on`, `chkconfig --add <name>` and
    /// `chkconfig --level <levels> <name> on`), in first-seen order.
    /// `chkconfig <name> off` and `chkconfig --del`/`--remove <name>`
    /// deactivate or remove and stay quiet, like the insserv removal
    /// form. A `systemctl` verb form whose invocations all name
    /// `.timer` units only is not an activation either: enabling or
    /// starting a timer schedules the oneshot it drives, it starts
    /// no daemon. Matching runs on the heredoc-blanked, comment-stripped,
    /// quote-blanked text (`code_only`) and is command-position only
    /// (start of line, after a command separator — a bare `&`
    /// backgrounding included — or as a `case` arm), so comments,
    /// echoed or otherwise quoted text and the preset-based
    /// `systemd-update-helper` expansions of the `%service_*` macros
    /// do not fire.
    fn daemon_activations(script: &str) -> Vec<String> {
        let text = Self::code_only(&Self::without_heredoc_bodies(script));
        let mut out: Vec<String> = Vec::new();
        for caps in Self::insserv_regex().captures_iter(&text).flatten() {
            let args = caps.get(2).map_or("", |m| m.as_str());
            let removal = args.split_whitespace().any(|a| {
                a == "--remove"
                    || (a.starts_with('-') && !a.starts_with("--") && a[1..].contains('r'))
            });
            if !removal && !out.iter().any(|o| o == "insserv") {
                out.push("insserv".to_string());
            }
        }
        let mut verb_order: Vec<String> = Vec::new();
        let mut activating: Vec<String> = Vec::new();
        for caps in Self::systemctl_regex().captures_iter(&text).flatten() {
            let Some(verb) = caps.get(2) else {
                continue;
            };
            let detail = format!("systemctl {}", verb.as_str());
            if !verb_order.contains(&detail) {
                verb_order.push(detail.clone());
            }
            let args = caps.get(3).map_or("", |m| m.as_str());
            if !Self::timer_only_invocation(args) && !activating.contains(&detail) {
                activating.push(detail);
            }
        }
        for detail in verb_order {
            if activating.contains(&detail) {
                out.push(detail);
            }
        }
        for caps in Self::chkconfig_regex().captures_iter(&text).flatten() {
            let args = caps.get(2).map_or("", |m| m.as_str());
            let tokens: Vec<&str> = args.split_whitespace().collect();
            if tokens
                .iter()
                .any(|t| matches!(*t, "--del" | "--remove" | "--delete"))
            {
                continue;
            }
            let detail = if tokens.contains(&"--add") {
                Some("chkconfig --add")
            } else if tokens.contains(&"on") {
                Some("chkconfig on")
            } else {
                None
            };
            if let Some(detail) = detail
                && !out.iter().any(|o| o == detail)
            {
                out.push(detail.to_string());
            }
        }
        out
    }

    /// Whether one systemctl invocation's argument tail names at
    /// least one unit and every unit it names is a `.timer`. Option
    /// tokens (starting with `-`) and redirection tokens name no
    /// unit, and a closing paren left attached to a unit name by a
    /// subshell or case arm is not part of the name. Quoted unit
    /// names reach this scan blanked (see `code_only`), so they
    /// name no unit here and the invocation counts as an
    /// activation: only a literally written `.timer` target is
    /// trusted.
    fn timer_only_invocation(args: &str) -> bool {
        let tokens: Vec<&str> = args.split_whitespace().collect();
        let mut targets = 0;
        let mut i = 0;
        while i < tokens.len() {
            let token = tokens[i];
            i += 1;
            if token.starts_with('-') {
                continue;
            }
            match Self::redirection(token) {
                // A bare operator takes the next token as its file
                // target; neither names a unit.
                Some(true) => i += 1,
                Some(false) => {}
                None => {
                    let target = token.trim_end_matches(')');
                    if target.is_empty() {
                        continue;
                    }
                    targets += 1;
                    if !target.ends_with(".timer") {
                        return false;
                    }
                }
            }
        }
        targets > 0
    }

    /// The redirection shape of a token in a systemctl argument
    /// tail: `Some(true)` for a bare operator (`>`, `>>`, `2>`),
    /// whose file target is the following token; `Some(false)` for
    /// an operator with its target glued on (`>/dev/null`,
    /// `2>/dev/null`); `None` for any other token. The both-stream
    /// forms classify the same way: `&>` and `&>>` once the leading
    /// `&` is dropped, and the bare `>&` -- whose `&` trails, so no
    /// strip applies -- is itself a bare operator, while a glued
    /// `>&2` or `>&/dev/null` stays in the glued arm.
    fn redirection(token: &str) -> Option<bool> {
        let digits = token
            .len()
            .saturating_sub(token.trim_start_matches(|c: char| c.is_ascii_digit()).len());
        let rest = &token[digits..];
        let rest = match rest.strip_prefix('&') {
            Some(after) if after.starts_with('>') => after,
            _ => rest,
        };
        if matches!(rest, ">" | ">>" | "<" | "<<" | ">&") {
            return Some(true);
        }
        if rest.starts_with('>') || rest.starts_with('<') {
            return Some(false);
        }
        None
    }

    /// `sh -n` / `perl -wc` syntax check via subprocess. `None` when the
    /// interpreter is unavailable (skipped, not an error).
    fn syntax_ok(prog: &str, args: &[&str], script: &str) -> Option<bool> {
        // One temp file per call: tests run in parallel threads of one
        // process, so a fixed name races and `sh -n` spuriously fails on a
        // missing or half-written file.
        let tmp = tempfile::NamedTempFile::new().ok()?;
        std::fs::write(tmp.path(), script).ok()?;
        // The reference passes ENGLISH_ENVIRONMENT (PostCheck.py:66):
        // `sh -n` / `perl -wc` diagnostics are locale-dependent.
        let result = Command::new(prog)
            .args(args)
            .arg(tmp.path())
            .env("LC_ALL", "en_US.UTF-8")
            .env("LANGUAGE", "en_US")
            .output()
            .ok();
        let _ = tmp.close();
        result.map(|o| o.status.success())
    }

    /// Check one scriptlet. Returns `(finding, details)` pairs.
    /// Mirrors the reference's `check_aux`, which only runs when the
    /// scriptlet body is non-empty.
    fn check_scriptlet(
        &self,
        prog: &str,
        script: &str,
        tag: &str,
        prereq: &[String],
        files: &[String],
    ) -> Vec<(Level, String, Vec<String>)> {
        let mut out = Vec::new();
        if script.is_empty() {
            return out;
        }
        let finding = |f: &str| format!("{f}-{tag}");

        // upstream rpmlint#396 (rationale rpm#714): %pretrans runs before any
        // package payload is installed, so the internal Lua interpreter is
        // the only one guaranteed to exist. A missing -p flag defaults to
        // /bin/sh, which is why an empty prog also warns.
        // `<lua>` is deliberately hardcoded rather than read from
        // ValidShells: rpm guarantees the interpreter only for the literal
        // token, so a config change there must not silence this error.
        if tag == "%pretrans" && prog != "<lua>" {
            out.push((
                Level::Error,
                "pretrans-not-lua".to_string(),
                vec![prog.to_string()],
            ));
        }

        if !prog.is_empty() {
            if !self.valid_shells.iter().any(|s| s == prog) {
                out.push((
                    Level::Error,
                    finding("invalid-shell-in"),
                    vec![prog.to_string()],
                ));
            }
            if self.empty_shells.iter().any(|s| s == prog) {
                out.push((Level::Error, finding("non-empty"), vec![prog.to_string()]));
            }
        }

        if prog == "/bin/sh" || prog == "/bin/bash" || prog == "/usr/bin/perl" {
            if is_match(Self::percent_regex(), script) {
                out.push((Level::Warning, finding("percent-in"), vec![]));
            }
            if let Some(m) = Self::dangerous_regex()
                .captures(script)
                .ok()
                .flatten()
                .and_then(|c| c.get(2))
            {
                out.push((
                    Level::Warning,
                    finding("dangerous-command-in"),
                    vec![m.as_str().to_string()],
                ));
            }
            if let Some(m) = Self::selinux_regex()
                .captures(script)
                .ok()
                .flatten()
                .and_then(|c| c.get(2))
            {
                out.push((
                    Level::Error,
                    finding("forbidden-selinux-command-in"),
                    vec![m.as_str().to_string()],
                ));
            }
            if script.contains("update-menus") {
                let menu_re = POST_MENU_RE.get_or_init(|| {
                    Regex::new(r"^/usr/lib/menu/|^/etc/menu-methods/|^/usr/share/applications/")
                        .expect("static regex")
                });
                if !files.iter().any(|f| is_match(menu_re, f)) {
                    out.push((
                        Level::Error,
                        finding("update-menus-without-menu-file-in"),
                        vec![],
                    ));
                }
            }
            if Self::uses_tmp_literal(script) {
                out.push((Level::Error, finding("use-tmp-in"), vec![]));
            }
            // prereq_assoc: chkfontpath, rpm-helper
            for (name, bins) in [
                ("chkfontpath", vec!["chkfontpath", "/usr/sbin/chkfontpath"]),
                ("rpm-helper", vec!["rpm-helper"]),
            ] {
                let re = Regex::new(&format!(r"(?m)^[^#]+{name}")).expect("prereq regex");
                if is_match(&re, script)
                    && !bins
                        .iter()
                        .any(|b| prereq.iter().any(|p| p == b) || files.iter().any(|f| f == b))
                {
                    out.push((
                        Level::Error,
                        "no-prereq-on".to_string(),
                        vec![bins[0].to_string()],
                    ));
                }
            }
        }

        // The daemon-activation scan also runs for an empty prog: a
        // missing `-p` flag defaults to /bin/sh, which is exactly how
        // macro-expanded %post/%preun bodies arrive, so gating the scan
        // on a named interpreter would skip the common form.
        if prog.is_empty() || prog == "/bin/sh" || prog == "/bin/bash" || prog == "/usr/bin/perl" {
            for activation in Self::daemon_activations(script) {
                out.push((
                    Level::Error,
                    finding("daemon-activation-in"),
                    vec![activation],
                ));
            }
        }

        // The cache-updater scan also covers scriptlets without a
        // `-p` flag: a missing prog defaults to /bin/sh (the default
        // the %pretrans check above relies on), so an empty prog must
        // not skip the scan.
        if prog.is_empty() || prog == "/bin/sh" || prog == "/bin/bash" || prog == "/usr/bin/perl" {
            // Trigger scriptlets are the file-trigger mechanism itself:
            // an updater invoked there is the trigger doing its work,
            // not a hand-rolled duplicate of it.
            if !matches!(tag, "%trigger" | "%filetrigger" | "%transfiletrigger") {
                for cmd in Self::cache_updaters(script) {
                    out.push((
                        Level::Warning,
                        finding("deprecated-cache-updater-in"),
                        vec![cmd],
                    ));
                }
            }
        }

        // The direct user/group creation scan runs under the same
        // interpreter gate as the other lexical scans. Users and
        // groups are created declaratively through sysusers.d, so
        // a useradd/groupadd invocation is the finding in every
        // scriptlet kind this check scans (issue #640,
        // boo#1285892).
        if prog.is_empty() || prog == "/bin/sh" || prog == "/bin/bash" || prog == "/usr/bin/perl" {
            for (tool, line) in direct_user_creation_in_body(script) {
                out.push((
                    Level::Warning,
                    finding(&format!("scriptlet-{tool}-in")),
                    vec![line],
                ));
            }
        }

        // The rc<service> link scan runs under the same interpreter
        // gate as the other lexical scans. The links were removed in
        // the SLE 16 legacy cleanup, so an invocation is obsolete
        // whatever the verb (issue #731).
        if prog.is_empty() || prog == "/bin/sh" || prog == "/bin/bash" || prog == "/usr/bin/perl" {
            for line in rc_link_invocations_in_body(script) {
                out.push((
                    Level::Warning,
                    finding("scriptlet-rc-link-invocation-in"),
                    vec![line],
                ));
            }
        }

        if prog == "/bin/sh" || prog == "/bin/bash" {
            if let Some(ok) = Self::syntax_ok(prog, &["-n"], script)
                && !ok
            {
                out.push((Level::Error, finding("shell-syntax-error-in"), vec![]));
            }
            if is_match(Self::home_regex(), script) {
                out.push((Level::Error, finding("use-of-home-in"), vec![]));
            }
            if let Some(m) = Self::bogus_var_regex()
                .captures(script)
                .ok()
                .flatten()
                .and_then(|c| c.get(1))
            {
                out.push((
                    Level::Warning,
                    finding("bogus-variable-use-in"),
                    vec![m.as_str().to_string()],
                ));
            }
        }

        if prog == "/usr/bin/perl"
            && let Some(ok) = Self::syntax_ok(prog, &["-wc"], script)
            && !ok
        {
            out.push((Level::Error, finding("perl-syntax-error-in"), vec![]));
        }

        out
    }

    /// The reference's `empty-<tag>` warning: an empty body with a valid,
    /// non-empty-shell interpreter.
    fn check_empty(&self, prog: &str, script: &str, tag: &str) -> Option<(Level, String)> {
        if script.is_empty()
            && !self.empty_shells.iter().any(|s| s == prog)
            && self.valid_shells.iter().any(|s| s == prog)
        {
            Some((Level::Warning, format!("empty-{tag}")))
        } else {
            None
        }
    }
}

/// `error_details` for `-v`, mirroring the reference's `post_details_dict`
/// (`PostCheck.py:78-83`): three families over `Pkg.RPM_SCRIPTLETS` plus
/// the ghost-file entry. Texts are byte-identical to the reference,
/// including its duplicated `transfiletriggerun` row (dict insertion
/// dedupes it there; the loop below simply overwrites it here).
/// `percent-in-<scriptlet>`:
const PERCENT_IN_DETAIL: &str = "The {tag} scriptlet contains a '%' in a context which might indicate it being\n        fallout from an rpm macro/variable which was not expanded during build.\n        Investigate whether this is the case and fix if appropriate.";
/// `forbidden-selinux-command-in-<scriptlet>`:
const FORBIDDEN_SELINUX_DETAIL: &str = "A command which requires intimate knowledge about a specific SELinux\n        policy type was found in the scriptlet. These types are subject to change\n        on a policy version upgrade. Use the restorecon command which queries the\n        currently loaded policy for the correct type instead.";
/// `daemon-activation-in-<scriptlet>`:
const DAEMON_ACTIVATION_DETAIL: &str = "The scriptlet activates a daemon at installation time. Packages must not enable or start services on installation; enablement is governed by systemd presets, not by insserv, chkconfig or systemctl calls in scriptlets.";
/// `deprecated-cache-updater-in-<scriptlet>`:
const DEPRECATED_CACHE_UPDATER_DETAIL: &str = "The scriptlet runs a cache or database updater (update-desktop-database, gtk-update-icon-cache, update-mime-database, glib-compile-schemas or install-info) by hand, pointed at a directory the RPM file triggers own. The triggers already run the updater when the files it indexes change, so the manual call is redundant; remove it and rely on the file trigger.";
/// `scriptlet-useradd-in-<scriptlet>`:
const SCRIPTLET_USERADD_DETAIL: &str = "The scriptlet creates a user by invoking useradd directly. Users and groups are created declaratively: the package ships a sysusers.d configuration and the sysusers macros create the account during installation (openSUSE packaging guidelines, Users and Groups). A direct useradd invocation cannot create the account on image-based installations, where scriptlets run on the build host without access to the target /etc/passwd, and useradd is not part of container images.";
/// `scriptlet-groupadd-in-<scriptlet>`:
const SCRIPTLET_GROUPADD_DETAIL: &str = "The scriptlet creates a group by invoking groupadd directly. Users and groups are created declaratively: the package ships a sysusers.d configuration and the sysusers macros create the group during installation (openSUSE packaging guidelines, Users and Groups). A direct groupadd invocation cannot create the group on image-based installations, where scriptlets run on the build host without access to the target /etc/group, and groupadd is not part of container images.";
/// `scriptlet-rc-link-invocation-in-<scriptlet>`:
const RC_LINK_INVOCATION_DETAIL: &str = "The scriptlet invokes an rc<service> link (rc<name>, invoked bare or by path from a sbin directory; the same-shaped real binaries rclone, rcs and rcp are not rc links). The rc<service> symlinks to the service command are the pre-systemd service-control form, removed from the distribution in the SLE 16 legacy cleanup; drive the service through systemctl or the systemd service macros instead.";
/// `non-empty-<scriptlet>`:
const NON_EMPTY_DETAIL: &str = "Scriptlets for the interpreter mentioned in the message should be empty.\n        One common case where they are unintentionally not is when the specfile\n        contains comments after the scriptlet and before the next section. Review\n        and clean up the scriptlet contents if appropriate.";
pub fn register_error_details(out: &mut Filter) {
    out.set_error_detail(
        "pretrans-not-lua",
        "The %pretrans scriptlet must be written in Lua: it runs before any package payload is installed, so the internal Lua interpreter is the only one guaranteed to exist.".to_string(),
    );
    out.set_error_detail(
        "ghost-files-without-postin",
        "The package tags files as ghost but has no %postin scriptlet to create them.".to_string(),
    );
    out.set_error_detail(
        "no-prereq-on",
        "The package should have a Prereq dependency but does not declare one.".to_string(),
    );
    out.set_error_detail(
        "empty-%post",
        "The %post scriptlet is empty. Remove it if it serves no purpose.".to_string(),
    );
    // `Pkg.RPM_SCRIPTLETS` in the reference.
    for name in [
        "pre",
        "post",
        "preun",
        "postun",
        "pretrans",
        "posttrans",
        "trigger",
        "triggerin",
        "triggerprein",
        "triggerun",
        "triggerpostun",
        "verifyscript",
        "filetriggerin",
        "filetrigger",
        "filetriggerun",
        "filetriggerpostun",
        "transfiletriggerin",
        "transfiletrigger",
        "transfiletriggerun",
        "transfiletriggerpostun",
    ] {
        let tag = format!("%{name}");
        // `percent-in-<scriptlet>`:
        out.set_error_detail(
            &format!("percent-in-{tag}"),
            PERCENT_IN_DETAIL.replace("{tag}", &tag),
        );
        // `forbidden-selinux-command-in-<scriptlet>`:
        out.set_error_detail(
            &format!("forbidden-selinux-command-in-{tag}"),
            FORBIDDEN_SELINUX_DETAIL.replace("{tag}", &tag),
        );
        // `daemon-activation-in-<scriptlet>`:
        out.set_error_detail(
            &format!("daemon-activation-in-{tag}"),
            DAEMON_ACTIVATION_DETAIL.to_string(),
        );
        // `deprecated-cache-updater-in-<scriptlet>`:
        out.set_error_detail(
            &format!("deprecated-cache-updater-in-{tag}"),
            DEPRECATED_CACHE_UPDATER_DETAIL.to_string(),
        );
        // `scriptlet-useradd-in-<scriptlet>`:
        out.set_error_detail(
            &format!("scriptlet-useradd-in-{tag}"),
            SCRIPTLET_USERADD_DETAIL.to_string(),
        );
        // `scriptlet-groupadd-in-<scriptlet>`:
        out.set_error_detail(
            &format!("scriptlet-groupadd-in-{tag}"),
            SCRIPTLET_GROUPADD_DETAIL.to_string(),
        );
        // `scriptlet-rc-link-invocation-in-<scriptlet>`:
        out.set_error_detail(
            &format!("scriptlet-rc-link-invocation-in-{tag}"),
            RC_LINK_INVOCATION_DETAIL.to_string(),
        );
        // `non-empty-<scriptlet>`:
        out.set_error_detail(
            &format!("non-empty-{tag}"),
            NON_EMPTY_DETAIL.replace("{tag}", &tag),
        );
    }
}

impl Check for PostCheck {
    fn name(&self) -> &'static str {
        "PostCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        // `-v` descriptions, mirroring the reference's `post_details_dict`
        // which `__init__` installs unconditionally.
        register_error_details(out);
        // (script tag, prog tag, macro name, is list) mirroring
        // `Pkg.SCRIPT_TAGS` (rpmlint/pkg.py). Trigger scriptlets store
        // parallel arrays; rpm returns a list for the three trigger tags
        // even for a single entry, so `is_list` is fixed per tag.
        let scriptlets = [
            (Tag::PREIN, Tag::PREINPROG, "%pre", false),
            (Tag::POSTIN, Tag::POSTINPROG, "%post", false),
            (Tag::PREUN, Tag::PREUNPROG, "%preun", false),
            (Tag::POSTUN, Tag::POSTUNPROG, "%postun", false),
            (
                Tag::TRIGGERSCRIPTS,
                Tag::TRIGGERSCRIPTPROG,
                "%trigger",
                true,
            ),
            (Tag::PRETRANS, Tag::PRETRANSPROG, "%pretrans", false),
            (Tag::POSTTRANS, Tag::POSTTRANSPROG, "%posttrans", false),
            (
                Tag::VERIFYSCRIPT,
                Tag::VERIFYSCRIPTPROG,
                "%verifyscript",
                false,
            ),
            (
                Tag::FILETRIGGERSCRIPTS,
                Tag::FILETRIGGERSCRIPTPROG,
                "%filetrigger",
                true,
            ),
            (
                Tag::TRANSFILETRIGGERSCRIPTS,
                Tag::TRANSFILETRIGGERSCRIPTPROG,
                "%transfiletrigger",
                true,
            ),
        ];
        let prereq: Vec<String> = pkg.prereq.iter().map(|d| d.name.clone()).collect();
        let files: Vec<String> = pkg.files.iter().map(|f| f.name.clone()).collect();

        let mut emit = |level: Level, finding: &str, details: &[&str]| {
            add_info(out, level, pkg, finding, details);
        };

        for (script_tag, prog_tag, tag, is_list) in scriptlets {
            if is_list {
                let scripts = pkg.tag_str_array(script_tag);
                let progs = pkg.tag_str_array(prog_tag);
                for (idx, prog) in progs.iter().enumerate() {
                    let script = scripts.get(idx).map(String::as_str).unwrap_or("");
                    for (level, finding, details) in
                        self.check_scriptlet(prog, script, tag, &prereq, &files)
                    {
                        let refs: Vec<&str> = details.iter().map(String::as_str).collect();
                        emit(level, &finding, &refs);
                    }
                    if let Some((level, finding)) = self.check_empty(prog, script, tag) {
                        emit(level, &finding, &[]);
                    }
                }
            } else {
                let script = pkg.tag_str(script_tag).unwrap_or_default();
                let prog = pkg.scriptprog(prog_tag);
                let prog = prog.split_whitespace().next().unwrap_or("").to_string();
                for (level, finding, details) in
                    self.check_scriptlet(&prog, &script, tag, &prereq, &files)
                {
                    let refs: Vec<&str> = details.iter().map(String::as_str).collect();
                    emit(level, &finding, &refs);
                }
                if let Some((level, finding)) = self.check_empty(&prog, &script, tag) {
                    emit(level, &finding, &[]);
                }
            }
        }

        // Deliberate absence: the per-ghost finding
        // `postin-without-ghost-file-creation` is not emitted (issue #562,
        // ledgered as kind = "missing" in tests/parity/divergences.toml);
        // only the package-level sibling below remains.
        if !pkg.ghost_files.is_empty() {
            let postin = pkg.tag_str(Tag::POSTIN).unwrap_or_default();
            let prein = pkg.tag_str(Tag::PREIN).unwrap_or_default();
            for f in &pkg.ghost_files {
                if pkg.missingok_files.iter().any(|m| m == f) {
                    continue;
                }
                if postin.is_empty() && prein.is_empty() {
                    add_info(out, Level::Warning, pkg, "ghost-files-without-postin", &[]);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;
    use std::path::Path;

    fn check() -> PostCheck {
        PostCheck {
            valid_shells: vec![
                "<lua>".to_string(),
                "/bin/sh".to_string(),
                "/usr/bin/perl".to_string(),
            ],
            empty_shells: vec!["/sbin/ldconfig".to_string()],
        }
    }

    #[test]
    fn invalid_shell_is_flagged() {
        let found = check().check_scriptlet("/bad/sh", "echo hi", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(l, f, _)| *l == Level::Error && f == "invalid-shell-in-%post")
        );
    }

    #[test]
    fn pretrans_shell_is_flagged() {
        // upstream rpmlint#396 (rationale rpm#714): a shell %pretrans
        // cannot run — only the internal Lua interpreter is guaranteed
        // to exist when %pretrans executes.
        let found = check().check_scriptlet("/bin/sh", "echo pretrans", "%pretrans", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "pretrans-not-lua"
            && d == &vec!["/bin/sh".to_string()]));
    }

    #[test]
    fn pretrans_missing_prog_is_flagged() {
        // No -p flag means the default /bin/sh, which is equally not Lua.
        let found = check().check_scriptlet("", "echo pretrans", "%pretrans", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(l, f, _)| *l == Level::Error && f == "pretrans-not-lua")
        );
    }

    #[test]
    fn pretrans_lua_is_quiet() {
        let found = check().check_scriptlet("<lua>", "print('hello')", "%pretrans", &[], &[]);
        assert!(found.is_empty());
    }

    #[test]
    fn pretrans_check_ignores_other_scriptlets() {
        let found = check().check_scriptlet("/bin/sh", "echo hi", "%post", &[], &[]);
        assert!(!found.iter().any(|(_, f, _)| f == "pretrans-not-lua"));
    }

    #[test]
    fn empty_script_skips_content_checks() {
        // The reference gates check_aux on `if script:`; an empty body only
        // produces the empty-<tag> warning, never content findings.
        let found = check().check_scriptlet("/bad/sh", "", "%post", &[], &[]);
        assert!(found.is_empty());
    }

    #[test]
    fn percent_without_brace_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "echo %foo", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(l, f, _)| *l == Level::Warning && f == "percent-in-%post")
        );
    }

    #[test]
    fn percent_with_brace_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "echo %{foo}", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(l, f, _)| *l == Level::Warning && f == "percent-in-%post")
        );
    }

    #[test]
    fn forbidden_selinux_command_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "chcon -t foo /bar", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(l, f, _)| *l == Level::Error && f == "forbidden-selinux-command-in-%post")
        );
    }

    /// Negative pin for the deleted `spurious-bracket-in-*` findings (#308):
    /// the port must stay silent on the exact shape the old emission fired
    /// on, and `cargo test` (not just the reference-coverage auditor) must
    /// catch a re-add.
    #[test]
    fn killed_spurious_bracket_stays_absent() {
        // The deleted test drove `if a]` through check_scriptlet; the
        // bracket regex no longer fires.
        let found = check().check_scriptlet("/bin/sh", "if a]", "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "spurious-bracket-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    /// Negative pin for the deleted `one-line-command-in-*` findings (#308):
    /// the port must stay silent on the exact shape the old emission fired
    /// on, and `cargo test` (not just the reference-coverage auditor) must
    /// catch a re-add.
    #[test]
    fn killed_one_line_command_stays_absent() {
        // The deleted test drove a bare `/usr/bin/update-foo` scriptlet;
        // the single-command regex no longer fires.
        let found = check().check_scriptlet("/bin/sh", "/usr/bin/update-foo", "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "one-line-command-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn tmp_use_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "echo hi > /tmp/foo", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(l, f, _)| *l == Level::Error && f == "use-tmp-in-%post")
        );
    }

    fn tmp_finding(script: &str) -> bool {
        check()
            .check_scriptlet("/bin/sh", script, "%post", &[], &[])
            .iter()
            .any(|(_, f, _)| f == "use-tmp-in-%post")
    }

    #[test]
    fn tmp_template_is_not_flagged() {
        // mktemp templates: the name is generated, not predictable.
        assert!(!tmp_finding("tmpfile=$(mktemp /tmp/tmp-XXXX)"));
        assert!(!tmp_finding("tmpdir=$(mktemp -d /tmp/tmpdir-XXXXXXXXX)"));
        assert!(!tmp_finding("tmpfile=$(mktemp /var/tmp/tmp-XXXX)"));
    }

    #[test]
    fn tmp_glob_is_not_flagged() {
        // A glob matches existing files; it names no creation target.
        assert!(!tmp_finding(
            "rm -f /tmp/tmp\\.[A-Z,a-z,0-9]*\\.google-accounts-daemon-active"
        ));
    }

    #[test]
    fn tmp_literal_alongside_template_is_flagged() {
        assert!(tmp_finding(
            "d=$(mktemp -d /tmp/x-XXXXXX); echo hi > /tmp/fixed"
        ));
    }

    #[test]
    fn var_tmp_literal_is_flagged() {
        assert!(tmp_finding("echo hi > /var/tmp/foo"));
    }

    #[test]
    fn tmp_in_comment_is_not_flagged() {
        assert!(!tmp_finding("# scratch lives in /tmp/foo\necho ok"));
    }

    #[test]
    fn tmpfiles_heredoc_tmp_entry_is_not_flagged() {
        // The expanded `%tmpfiles_create_package` shape: the entry is a
        // declarative tmpfiles.d line, not scriptlet scratch use.
        let script = "systemd-tmpfiles --create - <<SYSTEMD_INLINE_EOF\nd /tmp/myapp 0755 root root -\nSYSTEMD_INLINE_EOF";
        assert!(!tmp_finding(script));
        let found = check().check_scriptlet("/bin/sh", script, "%pre", &[], &[]);
        assert!(
            !found.iter().any(|(_, f, _)| f == "use-tmp-in-%pre"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn tmpfiles_heredoc_var_tmp_entry_is_not_flagged() {
        let script = "systemd-tmpfiles --create - <<SYSTEMD_INLINE_EOF\nd /var/tmp/myapp 0755 root root -\nSYSTEMD_INLINE_EOF";
        assert!(!tmp_finding(script));
    }

    #[test]
    fn tmpfiles_heredoc_variants_are_not_flagged() {
        // Path-prefixed invocation.
        assert!(!tmp_finding(
            "/usr/bin/systemd-tmpfiles --create - <<SYSTEMD_INLINE_EOF\nd /tmp/myapp 0755 root root -\nSYSTEMD_INLINE_EOF"
        ));
        // `<<-` with an indented terminator.
        assert!(!tmp_finding(
            "systemd-tmpfiles --create - <<-SYSTEMD_INLINE_EOF\n\td /tmp/myapp 0755 root root -\n\tSYSTEMD_INLINE_EOF"
        ));
        // Quoted delimiter.
        assert!(!tmp_finding(
            "systemd-tmpfiles --create - <<'SYSTEMD_INLINE_EOF'\nd /tmp/myapp 0755 root root -\nSYSTEMD_INLINE_EOF"
        ));
    }

    #[test]
    fn tmp_scratch_around_tmpfiles_heredoc_is_flagged() {
        let before = "echo hi > /tmp/before\nsystemd-tmpfiles --create - <<SYSTEMD_INLINE_EOF\nd /tmp/myapp 0755 root root -\nSYSTEMD_INLINE_EOF";
        assert!(tmp_finding(before));
        let after = "systemd-tmpfiles --create - <<SYSTEMD_INLINE_EOF\nd /tmp/myapp 0755 root root -\nSYSTEMD_INLINE_EOF\necho hi > /tmp/after";
        assert!(tmp_finding(after));
    }

    #[test]
    fn tmp_in_non_tmpfiles_heredoc_is_flagged() {
        let script = "cat <<EOF\nd /tmp/myapp 0755 root root -\nEOF";
        assert!(tmp_finding(script));
    }

    #[test]
    fn tmpfiles_without_heredoc_is_flagged() {
        let script = "systemd-tmpfiles --create -\necho hi > /tmp/foo";
        assert!(tmp_finding(script));
    }

    #[test]
    fn multiple_heredocs_only_tmpfiles_is_exempt() {
        // A tmpfiles heredoc alongside a plain heredoc stays quiet when
        // neither holds scratch use outside the tmpfiles entries.
        let quiet = "cat <<EOF\nhello\nEOF\nsystemd-tmpfiles --create - <<SYSTEMD_INLINE_EOF\nd /tmp/myapp 0755 root root -\nSYSTEMD_INLINE_EOF";
        assert!(!tmp_finding(quiet));
        // The `cat` heredoc's /tmp line still fires even when a tmpfiles
        // heredoc is present in the same scriptlet.
        let loud = "cat <<EOF\nd /tmp/myapp 0755 root root -\nEOF\nsystemd-tmpfiles --create - <<SYSTEMD_INLINE_EOF\nd /tmp/other 0755 root root -\nSYSTEMD_INLINE_EOF";
        assert!(tmp_finding(loud));
    }

    #[test]
    fn two_heredocs_one_line_tmpfiles_exemption_does_not_leak() {
        // The exemption belongs to the heredoc attached to the
        // tmpfiles `-` stdin, not to the whole line: the `cat` body on
        // the same opener line is still scanned.
        let quiet =
            "systemd-tmpfiles --create - <<A; cat <<B\nd /tmp/myapp 0755 root root -\nA\nhello\nB";
        assert!(!tmp_finding(quiet));
        let loud = "systemd-tmpfiles --create - <<A; cat <<B\nd /tmp/myapp 0755 root root -\nA\necho hi > /tmp/scratch\nB";
        assert!(tmp_finding(loud));
    }

    #[test]
    fn hyphenated_heredoc_delimiter_terminates_block() {
        // The delimiter is the full shell word: `MY-DELIM` does not
        // terminate at `MY`, so entries inside stay quiet and a
        // scratch use after the block still fires.
        let inside =
            "systemd-tmpfiles --create - <<MY-DELIM\nd /tmp/myapp 0755 root root -\nMY-DELIM";
        assert!(!tmp_finding(inside));
        let after = "systemd-tmpfiles --create - <<MY-DELIM\nd /tmp/myapp 0755 root root -\nMY-DELIM\necho hi > /tmp/after";
        assert!(tmp_finding(after));
        // A dotted delimiter is one word too.
        let dotted = "systemd-tmpfiles --create - <<MY.DELIM\nd /tmp/myapp 0755 root root -\nMY.DELIM\necho hi > /tmp/after";
        assert!(tmp_finding(dotted));
    }

    #[test]
    fn phantom_heredoc_does_not_swallow_tmpfiles_block() {
        // A `<<` inside quotes or arithmetic is not a heredoc opener:
        // it must not swallow the genuine tmpfiles block after it.
        for phantom in ["echo \"a << b\"", "echo $((x << y))"] {
            let quiet = format!(
                "{phantom}\nsystemd-tmpfiles --create - <<SYSTEMD_INLINE_EOF\nd /tmp/myapp 0755 root root -\nSYSTEMD_INLINE_EOF"
            );
            assert!(!tmp_finding(&quiet), "phantom: {phantom}");
            let after = format!("{quiet}\necho hi > /tmp/after");
            assert!(tmp_finding(&after), "phantom: {phantom}");
        }
    }

    #[test]
    fn wrapped_tmpfiles_invocation_is_attributed() {
        // A backslash-continued invocation is one logical line: the
        // `-` argument lands on the continuation line, and the
        // heredoc it opens is still the tmpfiles one.
        let quiet = "systemd-tmpfiles --create \\
 - <<SYSTEMD_INLINE_EOF\nd /tmp/myapp 0755 root root -\nSYSTEMD_INLINE_EOF";
        assert!(!tmp_finding(quiet));
        let after = format!("{quiet}\necho hi > /tmp/after");
        assert!(tmp_finding(&after));
    }

    #[test]
    fn multiline_quote_does_not_phantom_swallow_tmpfiles_block() {
        // The `<<` sits inside a quoted string spanning lines: it
        // opens nothing, so the genuine tmpfiles block after it is
        // still recognised (quote state threads across lines).
        let quiet = "echo \"start\nmiddle <<EOF still string\"\nsystemd-tmpfiles --create - <<SYSTEMD_INLINE_EOF\nd /tmp/myapp 0755 root root -\nSYSTEMD_INLINE_EOF";
        assert!(!tmp_finding(quiet));
    }

    #[test]
    fn arithmetic_shift_is_not_a_heredoc_opener() {
        // `<<` is the left-shift operator in every arithmetic
        // context: the `((...))` command, `$[...]`, and `let`.
        for arith in ["(( x << y ))", "echo $[x << y]", "let a = x << y"] {
            let quiet = format!(
                "{arith}\nsystemd-tmpfiles --create - <<SYSTEMD_INLINE_EOF\nd /tmp/myapp 0755 root root -\nSYSTEMD_INLINE_EOF"
            );
            assert!(!tmp_finding(&quiet), "arith: {arith}");
            let after = format!("{quiet}\necho hi > /tmp/after");
            assert!(tmp_finding(&after), "arith: {arith}");
        }
    }

    #[test]
    fn last_heredoc_of_tmpfiles_segment_is_the_exempt_one() {
        // Two stdin heredocs on one segment: the shell feeds the
        // LAST one, so the tmpfiles entries live there, while the
        // first body is discarded text the scan still reads.
        let quiet =
            "systemd-tmpfiles --create - <<A <<B\nhello\nA\nd /tmp/myapp 0755 root root -\nB";
        assert!(!tmp_finding(quiet));
        let loud =
            "systemd-tmpfiles --create - <<A <<B\nd /tmp/myapp 0755 root root -\nA\nhello\nB";
        assert!(tmp_finding(loud));
    }

    #[test]
    fn plain_heredoc_terminator_must_match_exactly() {
        // An indented delimiter-like body line does not end a plain
        // heredoc (only `<<-` strips leading tabs): the block runs
        // to the exact terminator, so both entries stay exempt.
        let quiet = "systemd-tmpfiles --create - <<EOF\nd /tmp/one 0755 root root -\n EOF\nd /tmp/two 0755 root root -\nEOF";
        assert!(!tmp_finding(quiet));
        let after = format!("{quiet}\necho hi > /tmp/after");
        assert!(tmp_finding(&after));
    }

    #[test]
    fn home_use_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "echo ~/foo", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(l, f, _)| *l == Level::Error && f == "use-of-home-in-%post")
        );
    }

    #[test]
    fn bogus_var_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "echo $RPM_BUILD_ROOT", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(l, f, _)| *l == Level::Warning && f == "bogus-variable-use-in-%post")
        );
    }

    #[test]
    fn empty_valid_shell_is_warned() {
        assert_eq!(
            check().check_empty("/bin/sh", "", "%post"),
            Some((Level::Warning, "empty-%post".to_string()))
        );
    }

    #[test]
    fn update_menus_without_menu_file_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "update-menus", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(l, f, _)| *l == Level::Error
                    && f == "update-menus-without-menu-file-in-%post")
        );
    }

    fn check_fixture_names(rpm: &str) -> Vec<String> {
        let rpm_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs")
            .join(rpm);
        let pkg = Pkg::open(&rpm_path, &std::env::temp_dir(), true).expect("open fixture pkg");
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = PostCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        out.results().iter().map(|(name, _)| name.clone()).collect()
    }

    #[test]
    fn parity_fixture_matches_reference() {
        // Pinned against reference rpmlint 2.10.0 (PostCheck.py at 84848c0),
        // verified by running the reference in a Tumbleweed container over
        // the same RPM. This vector pins finding names and their positions
        // only; level and detail were confirmed by that reference run, and
        // for `pretrans-not-lua` are pinned by the unit tests below.
        //
        // The three %triggerin entries form a 3-element trigger array whose
        // bodies each trip a different finding family; the exact vector pins
        // the parallel-array walk (a flipped `is_list` or a renamed tag
        // changes it). The empty %post pins `check_empty` through
        // `check_binary`.
        assert_eq!(
            check_fixture_names("postcheck-parity-1.0-1.noarch.rpm"),
            vec![
                "percent-in-%pre",
                "empty-%post",
                "percent-in-%postun",
                "percent-in-%trigger",
                "dangerous-command-in-%trigger",
                "use-tmp-in-%trigger",
                // Deliberate divergence from the pinned reference: the
                // fixture's shell %pretrans trips pretrans-not-lua, which
                // upstream #396 asks for but 2.10.0 does not implement.
                "pretrans-not-lua",
                "percent-in-%filetrigger",
                "dangerous-command-in-%transfiletrigger",
                // Deliberate divergence from the pinned reference:
                // `postin-without-ghost-file-creation` is dropped
                // (issue #562); the fixture's ghost path, spelled in
                // neither %prein nor %postin, yields no finding.
            ]
        );
    }

    #[test]
    fn parity_ghost_fixture_matches_reference() {
        // Same reference run: a ghost file with no %pre/%post at all.
        // The reference also emits `postin-without-ghost-file-creation`
        // here; the port dropped that finding (issue #562), so the
        // sibling stands alone -- the exact vector pins the absence.
        assert_eq!(
            check_fixture_names("postcheck-ghost-parity-1.0-1.noarch.rpm"),
            vec!["ghost-files-without-postin"]
        );
    }

    #[test]
    fn lua_pretrans_fixture_is_quiet() {
        // `%pretrans -p <lua>` is the only form RPM guarantees at
        // pretrans time: PostCheck must stay silent on it.
        assert_eq!(
            check_fixture_names("postcheck-pretrans-lua-1.0-1.noarch.rpm"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn verbose_output_includes_error_details() {
        // `-v` is wire format: the reference prints `post_details_dict`
        // explanations after each finding block.
        let rpm_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/postcheck-parity-1.0-1.noarch.rpm");
        let pkg = Pkg::open(&rpm_path, &std::env::temp_dir(), true).expect("open fixture pkg");
        let config = Config {
            info: true,
            ..Default::default()
        };
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = PostCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let rendered = out.render_results(&config);
        // Only finding names present in the results get their description;
        // the fixture trips percent-in-* and empty-%post.
        assert!(rendered.contains("macro/variable"));
        assert!(rendered.contains("scriptlet is empty"));
        // The dropped ghost finding's detail must not resurface (#562).
        assert!(!rendered.contains("not created during %prein"));
    }

    #[test]
    fn missing_interpreter_skips_syntax_check() {
        // Ledgered: the reference dies with FileNotFoundError when the
        // interpreter is absent; the port skips the probe instead.
        assert_eq!(
            PostCheck::syntax_ok("/nonexistent-interpreter", &["-n"], "echo hi"),
            None
        );
    }

    #[test]
    fn percent_macro_on_third_line_is_flagged() {
        // Dropping `(?m)` from `percent_regex` loses the line-3 macro case.
        let found =
            check().check_scriptlet("/bin/sh", "echo a\necho b\necho %foo", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(l, f, _)| *l == Level::Warning && f == "percent-in-%post")
        );
    }

    #[test]
    fn two_letter_macro_is_not_flagged() {
        // `\\w{3,}` must not become `\\w{2,}`: `%ab` is not a macro.
        let found = check().check_scriptlet("/bin/sh", "echo %ab", "%post", &[], &[]);
        assert!(!found.iter().any(|(_, f, _)| f == "percent-in-%post"));
    }

    #[test]
    fn shell_syntax_error_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "if [", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(l, f, _)| *l == Level::Error && f == "shell-syntax-error-in-%post")
        );
    }

    #[test]
    fn valid_shell_script_has_no_syntax_error() {
        let found = check().check_scriptlet("/bin/sh", "echo hi", "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "shell-syntax-error-in-%post")
        );
    }

    #[test]
    fn perl_syntax_error_is_flagged() {
        if PostCheck::syntax_ok("/usr/bin/perl", &["-wc"], "print 1;\n").is_none() {
            // perl absent: the probe is skipped (ledgered divergence).
            return;
        }
        let found = check().check_scriptlet("/usr/bin/perl", "sub foo {", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(l, f, _)| *l == Level::Error && f == "perl-syntax-error-in-%post")
        );
    }

    #[test]
    fn non_empty_ldconfig_is_flagged() {
        let check = PostCheck {
            valid_shells: vec!["/sbin/ldconfig".to_string()],
            empty_shells: vec!["/sbin/ldconfig".to_string()],
        };
        let found = check.check_scriptlet("/sbin/ldconfig", "ldconfig", "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "non-empty-%post"
            && d == &vec!["/sbin/ldconfig".to_string()]));
    }

    #[test]
    fn dangerous_command_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "rm -rf /foo", "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Warning
            && f == "dangerous-command-in-%post"
            && d == &vec!["rm".to_string()]));
    }

    #[test]
    fn deprecated_cache_updaters_in_post_are_flagged() {
        for (script, cmd) in [
            (
                "update-desktop-database /usr/share/applications",
                "update-desktop-database",
            ),
            (
                "gtk-update-icon-cache -f /usr/share/icons/hicolor",
                "gtk-update-icon-cache",
            ),
            (
                "update-mime-database /usr/share/mime",
                "update-mime-database",
            ),
            (
                "glib-compile-schemas /usr/share/glib-2.0/schemas",
                "glib-compile-schemas",
            ),
            (
                "install-info /usr/share/info/foo.info /usr/share/info/dir",
                "install-info",
            ),
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found.iter().any(|(l, f, d)| *l == Level::Warning
                    && f == "deprecated-cache-updater-in-%post"
                    && d == &vec![cmd.to_string()]),
                "{script}: {found:?}"
            );
        }
    }

    #[test]
    fn cache_updater_in_glob_case_arm_is_flagged() {
        // The arm pattern is the token preceding `)`: glob characters
        // beyond the word set (`.`, `[`, `-`, quotes) belong to it.
        let script =
            "case $f in\n*.desktop) update-desktop-database /usr/share/applications;;\nesac";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
            "{found:?}"
        );
    }

    #[test]
    fn cache_updater_fd_redirection_is_not_the_target() {
        // The fd redirection is self-contained: the directory after
        // it is the target that gets classified.
        for script in [
            "update-mime-database 2>/dev/null /opt/pkg/share/mime",
            "update-mime-database 2>&1 /opt/pkg/share/mime",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
                "{script}: {found:?}"
            );
        }
        let found = check().check_scriptlet(
            "/bin/sh",
            "update-mime-database 2>/dev/null /usr/share/mime",
            "%post",
            &[],
            &[],
        );
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
            "{found:?}"
        );
    }

    #[test]
    fn cache_updater_quoted_info_dir_is_classified_by_its_value() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "install-info --info-dir=\"/opt/pkg/info\" /opt/pkg/info/dir",
            "%post",
            &[],
            &[],
        );
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
            "{found:?}"
        );
        let found = check().check_scriptlet(
            "/bin/sh",
            "install-info --info-dir=\"/usr/share/info\" /usr/share/info/dir",
            "%post",
            &[],
            &[],
        );
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
            "{found:?}"
        );
    }

    #[test]
    fn cache_updater_after_background_opener_or_env_is_flagged() {
        for script in [
            "sleep 1 & update-mime-database /usr/share/mime",
            "(update-mime-database /usr/share/mime)",
            "{ update-mime-database /usr/share/mime; }",
            "env update-mime-database /usr/share/mime",
            "env FOO=1 update-mime-database /usr/share/mime",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found
                    .iter()
                    .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
                "{script}: {found:?}"
            );
        }
    }

    #[test]
    fn cache_updater_after_sudo_is_quiet() {
        // Deliberate narrowing: a `sudo` prefix is not a recognised
        // command position, matching the documented scope.
        let found = check().check_scriptlet(
            "/bin/sh",
            "sudo update-mime-database /usr/share/mime",
            "%post",
            &[],
            &[],
        );
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
            "{found:?}"
        );
    }

    #[test]
    fn cache_updater_after_escaped_separator_is_quiet() {
        // The `\;` ends find's -exec clause; it is a literal argument
        // character, not a separator, so the words after it are still
        // find arguments, not an invocation.
        let script = "find /usr/share/icons/hicolor -name '*.png' -exec touch {} \\; gtk-update-icon-cache /usr/share/icons/hicolor";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
            "{found:?}"
        );
    }

    #[test]
    fn deprecated_cache_updater_in_postun_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "glib-compile-schemas /usr/share/glib-2.0/schemas",
            "%postun",
            &[],
            &[],
        );
        assert!(found.iter().any(|(l, f, d)| *l == Level::Warning
            && f == "deprecated-cache-updater-in-%postun"
            && d == &vec!["glib-compile-schemas".to_string()]));
    }

    #[test]
    fn deprecated_cache_updater_path_prefixed_is_flagged() {
        for script in [
            "/usr/bin/update-desktop-database",
            "/usr/bin/gtk-update-icon-cache /usr/share/icons/hicolor",
            "/usr/sbin/install-info --info-dir=/usr/share/info /usr/share/info/foo.info",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found
                    .iter()
                    .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
                "{script}: {found:?}"
            );
        }
    }

    #[test]
    fn deprecated_cache_updater_after_separator_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "true && update-mime-database /usr/share/mime; gtk-update-icon-cache /usr/share/icons/hicolor",
            "%post",
            &[],
            &[],
        );
        let cmds: Vec<&str> = found
            .iter()
            .filter(|(_, f, _)| f == "deprecated-cache-updater-in-%post")
            .map(|(_, _, d)| d[0].as_str())
            .collect();
        assert_eq!(cmds, vec!["update-mime-database", "gtk-update-icon-cache"]);
    }

    #[test]
    fn deprecated_cache_updater_repeated_is_reported_once() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "update-desktop-database\nupdate-desktop-database /usr/share/applications",
            "%post",
            &[],
            &[],
        );
        assert_eq!(
            found
                .iter()
                .filter(|(_, f, _)| f == "deprecated-cache-updater-in-%post")
                .count(),
            1
        );
    }

    #[test]
    fn deprecated_cache_updater_in_comment_and_echo_is_quiet() {
        let script = "# update-desktop-database\n\
            echo \"glib-compile-schemas /usr/share/glib-2.0/schemas\"\n\
            echo install-info";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn deprecated_cache_updater_in_heredoc_text_is_quiet() {
        let script = "cat >> /var/adm/update-messages/foo << EOF\n\
            glib-compile-schemas /usr/share/glib-2.0/schemas\n\
            EOF";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn unrelated_scriptlet_is_quiet_for_cache_updaters() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "update-ca-certificates\ntouch /usr/share/icons/hicolor/icon-theme.cache",
            "%post",
            &[],
            &[],
        );
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn deprecated_cache_updater_in_trigger_scriptlets_is_quiet() {
        // A trigger scriptlet is the file-trigger mechanism itself: the
        // packages providing a trigger (desktop-file-utils,
        // shared-mime-info) and packages registering their own run the
        // updater there legitimately.
        for tag in ["%trigger", "%filetrigger", "%transfiletrigger"] {
            let found = check().check_scriptlet(
                "/bin/sh",
                "update-desktop-database /usr/share/applications",
                tag,
                &[],
                &[],
            );
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f.starts_with("deprecated-cache-updater-in-")),
                "{tag}: {found:?}"
            );
        }
    }

    #[test]
    fn deprecated_cache_updater_with_private_target_dir_is_quiet() {
        // Scoping decision: the finding covers invocations aimed at
        // the directories the file triggers own. A literal private
        // target is indexed by no file trigger, so there the manual
        // call is the only thing building the cache and the "rely on
        // the file trigger" advice would be false.
        for script in [
            "glib-compile-schemas /opt/myapp/schemas",
            "glib-compile-schemas \"/opt/myapp/schemas\"",
            "gtk-update-icon-cache /opt/myapp/icons/hicolor",
            "install-info --info-dir=/opt/myapp/info /opt/myapp/info/foo.info",
            "update-desktop-database /srv/myapp/applications",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
                "{script}: {found:?}"
            );
        }
    }

    #[test]
    fn deprecated_cache_updater_with_explicit_system_dir_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "install-info --info-dir=/usr/share/info /usr/share/info/foo.info",
            "%post",
            &[],
            &[],
        );
        assert!(found.iter().any(|(l, f, d)| *l == Level::Warning
            && f == "deprecated-cache-updater-in-%post"
            && d == &vec!["install-info".to_string()]));
    }

    #[test]
    fn deprecated_cache_updater_in_then_do_else_forms_is_flagged() {
        // The dominant scriptlet shape: `if ...; then updater || :`.
        for script in [
            "if [ $1 -eq 1 ]; then update-desktop-database /usr/share/applications || :; fi",
            "if [ $1 -eq 0 ]; then :; else gtk-update-icon-cache /usr/share/icons/hicolor; fi",
            "for d in /usr/share/icons/*; do update-mime-database /usr/share/mime; done",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found
                    .iter()
                    .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
                "{script}: {found:?}"
            );
        }
    }

    #[test]
    fn deprecated_cache_updater_in_command_substitution_is_flagged() {
        for script in [
            "x=$(update-desktop-database)",
            "x=`update-mime-database /usr/share/mime`",
            "echo \"$(glib-compile-schemas /usr/share/glib-2.0/schemas)\"",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found
                    .iter()
                    .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
                "{script}: {found:?}"
            );
        }
    }

    #[test]
    fn deprecated_cache_updater_in_case_arm_is_flagged() {
        let script = "case \"$1\" in\n  1) update-desktop-database /usr/share/applications ;;\n  0) gtk-update-icon-cache /usr/share/icons/hicolor ;;\nesac";
        let found = check().check_scriptlet("/bin/sh", script, "%postun", &[], &[]);
        let cmds: Vec<&str> = found
            .iter()
            .filter(|(_, f, _)| f == "deprecated-cache-updater-in-%postun")
            .map(|(_, _, d)| d[0].as_str())
            .collect();
        assert_eq!(
            cmds,
            vec!["update-desktop-database", "gtk-update-icon-cache"]
        );
    }

    #[test]
    fn deprecated_cache_updater_after_env_assignment_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "NO_GTK_UPDATE=1 gtk-update-icon-cache /usr/share/icons/hicolor",
            "%post",
            &[],
            &[],
        );
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post")
        );
    }

    #[test]
    fn cache_updater_name_as_assignment_value_is_quiet() {
        // Merely naming the tool (even by absolute path) in an
        // assignment is not an invocation.
        for script in [
            "UPDATER=/usr/bin/update-desktop-database",
            "UPDATER=update-desktop-database",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
                "{script}: {found:?}"
            );
        }
    }

    #[test]
    fn deprecated_cache_updater_without_prog_is_flagged() {
        // A scriptlet without -p runs under the default shell, so the
        // scan covers it exactly like an explicit /bin/sh one; the
        // bash and perl forms are covered by the same gate.
        for prog in ["", "/bin/bash", "/usr/bin/perl"] {
            let found = check().check_scriptlet(
                prog,
                "update-desktop-database /usr/share/applications",
                "%post",
                &[],
                &[],
            );
            assert!(
                found
                    .iter()
                    .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
                "prog {prog:?}: {found:?}"
            );
        }
    }

    #[test]
    fn deprecated_cache_updater_after_comment_separator_is_quiet() {
        // A separator inside a comment does not put the following
        // text at command position.
        let found = check().check_scriptlet(
            "/bin/sh",
            "echo done # note; update-desktop-database /usr/share/applications",
            "%post",
            &[],
            &[],
        );
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn deprecated_cache_updater_in_quoted_text_is_quiet() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "echo \"please run: update-desktop-database; gtk-update-icon-cache\"",
            "%post",
            &[],
            &[],
        );
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn quoted_shift_opener_does_not_blank_following_lines() {
        // `<<` inside quotes is not a heredoc operator; the genuine
        // invocation on the next line must still be seen.
        let script =
            "echo \"append with << FILE\"\nupdate-desktop-database /usr/share/applications";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post")
        );
    }

    #[test]
    fn arithmetic_shift_opener_does_not_blank_following_lines() {
        // `<<` inside $((...)) is the left-shift operator.
        let script = "flags=$((flags << shift))\nupdate-mime-database /usr/share/mime";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post")
        );
    }

    #[test]
    fn escaped_delimiter_heredoc_text_is_quiet() {
        let script = "cat <<\\EOF\nupdate-desktop-database\nEOF";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn ansi_c_delimiter_heredoc_text_is_quiet() {
        let script = "cat <<$'EOF'\nupdate-desktop-database\nEOF";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "deprecated-cache-updater-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn dotted_delimiter_heredoc_ends_at_its_terminator() {
        // The delimiter is the whole word `EOF.txt`: the body stays
        // silent and the invocation after the terminator is seen.
        let script =
            "cat <<EOF.txt\nupdate-desktop-database\nEOF.txt\nupdate-mime-database /usr/share/mime";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        let cmds: Vec<&str> = found
            .iter()
            .filter(|(_, f, _)| f == "deprecated-cache-updater-in-%post")
            .map(|(_, _, d)| d[0].as_str())
            .collect();
        assert_eq!(cmds, vec!["update-mime-database"]);
    }

    #[test]
    fn indented_line_does_not_end_plain_heredoc() {
        // Only `<<-` tolerates an indented terminator (tabs); a
        // space-indented lookalike inside a plain heredoc is body
        // text, so the invocation after it is still body text too.
        let script =
            "cat <<EOF\n EOF\nupdate-desktop-database\nEOF\nupdate-mime-database /usr/share/mime";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        let cmds: Vec<&str> = found
            .iter()
            .filter(|(_, f, _)| f == "deprecated-cache-updater-in-%post")
            .map(|(_, _, d)| d[0].as_str())
            .collect();
        assert_eq!(cmds, vec!["update-mime-database"]);
    }

    #[test]
    fn dash_heredoc_ends_at_tab_indented_terminator() {
        let script =
            "cat <<-EOF\nupdate-desktop-database\n\tEOF\nupdate-mime-database /usr/share/mime";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        let cmds: Vec<&str> = found
            .iter()
            .filter(|(_, f, _)| f == "deprecated-cache-updater-in-%post")
            .map(|(_, _, d)| d[0].as_str())
            .collect();
        assert_eq!(cmds, vec!["update-mime-database"]);
    }

    #[test]
    fn no_prereq_on_chkfontpath_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", " chkfontpath --add /x", "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "no-prereq-on"
            && d == &vec!["chkfontpath".to_string()]));
    }
    #[test]
    fn insserv_in_post_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "insserv foo", "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["insserv".to_string()]));
    }

    #[test]
    fn insserv_path_prefixed_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "/sbin/insserv foo", "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["insserv".to_string()]));
    }

    #[test]
    fn systemctl_enable_in_post_is_flagged() {
        let found =
            check().check_scriptlet("/bin/sh", "systemctl enable foo.service", "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["systemctl enable".to_string()]));
    }

    #[test]
    fn systemctl_enable_path_prefixed_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "/usr/bin/systemctl enable foo.service",
            "%post",
            &[],
            &[],
        );
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["systemctl enable".to_string()]));
    }

    #[test]
    fn systemctl_enable_now_after_verb_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "systemctl enable --now foo.service",
            "%post",
            &[],
            &[],
        );
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post")
        );
    }

    #[test]
    fn systemctl_enable_now_before_verb_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "systemctl --now enable foo.service",
            "%post",
            &[],
            &[],
        );
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post")
        );
    }

    #[test]
    fn systemctl_start_is_flagged() {
        let found =
            check().check_scriptlet("/bin/sh", "systemctl start foo.service", "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["systemctl start".to_string()]));
    }

    #[test]
    fn systemctl_enable_timer_only_is_quiet() {
        let found =
            check().check_scriptlet("/bin/sh", "systemctl enable foo.timer", "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "a timer-only enable starts no daemon: {found:?}"
        );
    }

    #[test]
    fn systemctl_start_timer_only_is_quiet() {
        let found =
            check().check_scriptlet("/bin/sh", "systemctl start foo.timer", "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "a timer-only start only schedules the oneshot: {found:?}"
        );
    }

    #[test]
    fn systemctl_timer_enable_and_start_guarded_are_quiet() {
        // The openSUSE-build-key shape: a guarded enable+start of the
        // key-import timer beside the %service_add_post expansion.
        let script = "test -x /usr/bin/systemctl && systemctl enable openSUSE-build-key-import.timer && systemctl start openSUSE-build-key-import.timer || true";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "guarded timer enable+start must stay quiet: {found:?}"
        );
    }

    #[test]
    fn systemctl_enable_timer_and_service_on_one_line_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "systemctl enable foo.timer bar.service",
            "%post",
            &[],
            &[],
        );
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["systemctl enable".to_string()]));
    }

    #[test]
    fn systemctl_enable_timer_line_and_service_line_is_flagged_once() {
        let script = "systemctl enable foo.timer\nsystemctl enable bar.service";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        let hits: Vec<_> = found
            .iter()
            .filter(|(_, f, _)| f == "daemon-activation-in-%post")
            .collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].2, vec!["systemctl enable".to_string()]);
    }

    #[test]
    fn systemctl_timer_verb_does_not_mask_service_verb() {
        let script = "systemctl enable foo.timer\nsystemctl start bar.service";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        let details: Vec<&str> = found
            .iter()
            .filter(|(_, f, _)| f == "daemon-activation-in-%post")
            .map(|(_, _, d)| d[0].as_str())
            .collect();
        assert_eq!(details, vec!["systemctl start"]);
    }

    #[test]
    fn systemctl_restart_timer_only_is_quiet() {
        let found =
            check().check_scriptlet("/bin/sh", "systemctl restart foo.timer", "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "a timer-only restart reschedules, it restarts no daemon: {found:?}"
        );
    }

    #[test]
    fn systemctl_enable_without_unit_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "systemctl enable", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "a unit-less enable names no timer and stays flagged: {found:?}"
        );
    }

    #[test]
    fn systemctl_enable_timer_with_redirections_is_quiet() {
        for script in [
            "systemctl enable foo.timer >/dev/null 2>&1",
            "systemctl enable foo.timer > /dev/null",
            "systemctl start foo.timer 2>/dev/null",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "daemon-activation-in-%post"),
                "{script} must stay quiet: {found:?}"
            );
        }
    }

    #[test]
    fn systemctl_enable_service_with_redirections_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "systemctl enable foo.service >/dev/null 2>&1",
            "%post",
            &[],
            &[],
        );
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["systemctl enable".to_string()]));
    }

    #[test]
    fn systemctl_enable_service_after_fd_duplication_is_flagged() {
        // The args tail must not stop at the `&` of `2>&1`: a service
        // named after the duplication is still enabled by the call.
        let found = check().check_scriptlet(
            "/bin/sh",
            "systemctl enable foo.timer 2>&1 bar.service",
            "%post",
            &[],
            &[],
        );
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["systemctl enable".to_string()]));
    }

    #[test]
    fn systemctl_enable_timer_after_fd_duplication_is_quiet() {
        for script in [
            "systemctl enable foo.timer 2>&1 bar.timer",
            "systemctl enable 2>&1 foo.timer",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "daemon-activation-in-%post"),
                "{script} must stay quiet: {found:?}"
            );
        }
    }

    #[test]
    fn systemctl_enable_timer_with_both_stream_redirect_is_quiet() {
        for script in [
            "systemctl enable foo.timer &>/dev/null",
            "systemctl enable foo.timer &> /dev/null",
            "systemctl enable foo.timer &>>/var/log/enable.log",
            "systemctl enable foo.timer >&2",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "daemon-activation-in-%post"),
                "{script} must stay quiet: {found:?}"
            );
        }
    }

    #[test]
    fn systemctl_enable_service_after_both_stream_redirect_is_flagged() {
        // The args tail must not stop at the `&` of `&>`: a service
        // named after the redirection is still enabled by the call.
        let found = check().check_scriptlet(
            "/bin/sh",
            "systemctl enable foo.timer &>/dev/null bar.service",
            "%post",
            &[],
            &[],
        );
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["systemctl enable".to_string()]));
    }

    #[test]
    fn systemctl_enable_service_after_fd_redirect_is_flagged() {
        // The `>&` form must not truncate the args tail either: the
        // single-character class would consume the `>` first and cut
        // the capture at the `&`, dropping a unit named after the
        // redirection. `>&` is tried before the single-character
        // class in the tail alternation.
        for script in [
            "systemctl enable foo.timer >&/dev/null bar.service",
            "systemctl enable foo.timer >& /dev/null bar.service",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found.iter().any(|(l, f, d)| *l == Level::Error
                    && f == "daemon-activation-in-%post"
                    && d == &vec!["systemctl enable".to_string()]),
                "{script} must be flagged: {found:?}"
            );
        }
    }

    #[test]
    fn systemctl_enable_timer_with_fd_redirect_only_is_quiet() {
        // The `>&` forms with no unit after them stay quiet, glued
        // and separated alike.
        for script in [
            "systemctl enable foo.timer >&/dev/null",
            "systemctl enable foo.timer >& /dev/null",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "daemon-activation-in-%post"),
                "{script} must stay quiet: {found:?}"
            );
        }
    }

    #[test]
    fn systemctl_enable_timer_with_flag_is_quiet() {
        for script in [
            "systemctl enable --now foo.timer",
            "systemctl start --now foo.timer",
            "systemctl --now enable foo.timer",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "daemon-activation-in-%post"),
                "{script} must stay quiet: {found:?}"
            );
        }
    }

    #[test]
    fn systemctl_enable_timer_instance_is_quiet() {
        let found =
            check().check_scriptlet("/bin/sh", "systemctl enable foo@.timer", "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "a timer template instance must stay quiet: {found:?}"
        );
    }

    #[test]
    fn daemon_activation_is_flagged_in_pre_and_postun() {
        let found = check().check_scriptlet("/bin/sh", "insserv foo", "%pre", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%pre")
        );
        let found = check().check_scriptlet(
            "/bin/sh",
            "systemctl enable foo.service",
            "%postun",
            &[],
            &[],
        );
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%postun")
        );
    }

    #[test]
    fn daemon_activation_after_separator_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "true && systemctl enable foo.service",
            "%post",
            &[],
            &[],
        );
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post")
        );
    }

    #[test]
    fn service_macro_expansion_is_quiet() {
        // The expanded form of the %service_* macros in a binary package:
        // systemd-update-helper drives presets and enablement state, and
        // no command here enables or starts a unit directly.
        let script = "if [ -x /usr/lib/systemd/systemd-update-helper ]; then\n\
            /usr/lib/systemd/systemd-update-helper install-system-units foo.service || :\n\
            fi\n\
            if [ -x /usr/lib/systemd/systemd-update-helper ]; then\n\
            /usr/lib/systemd/systemd-update-helper mark-install-system-units foo.service || :\n\
            fi\n\
            if [ $1 -eq 1 ] ; then\n\
            /usr/bin/systemctl preset foo.service >/dev/null 2>&1 || :\n\
            fi";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn systemctl_non_activation_verbs_are_quiet() {
        // The try-forms genuinely no-op when the unit is inactive, so
        // they stay quiet; `restart`/`reload-or-restart` do not (they
        // start an inactive unit) and are pinned firing below.
        let script = "systemctl preset foo.service\n\
            systemctl daemon-reload\n\
            systemctl is-enabled foo.service\n\
            systemctl try-restart foo.service\n\
            systemctl condrestart foo.service\n\
            systemctl reload-or-try-restart foo.service";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn systemctl_restart_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "systemctl restart foo.service",
            "%post",
            &[],
            &[],
        );
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["systemctl restart".to_string()]));
    }

    #[test]
    fn systemctl_reload_or_restart_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "systemctl reload-or-restart foo.service",
            "%post",
            &[],
            &[],
        );
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["systemctl reload-or-restart".to_string()]));
    }

    #[test]
    fn systemctl_reenable_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "systemctl reenable foo.service",
            "%post",
            &[],
            &[],
        );
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["systemctl reenable".to_string()]));
    }

    #[test]
    fn systemctl_in_command_substitution_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "$(systemctl enable foo.service)",
            "%post",
            &[],
            &[],
        );
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["systemctl enable".to_string()]));
    }

    #[test]
    fn chkconfig_on_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "chkconfig foo on", "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["chkconfig on".to_string()]));
        let found =
            check().check_scriptlet("/bin/sh", "/sbin/chkconfig foo on", "%preun", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%preun")
        );
    }

    #[test]
    fn chkconfig_add_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "chkconfig --add foo", "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["chkconfig --add".to_string()]));
        let found =
            check().check_scriptlet("/bin/sh", "/sbin/chkconfig --add foo", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post")
        );
    }

    #[test]
    fn chkconfig_level_on_is_flagged() {
        let found =
            check().check_scriptlet("/bin/sh", "chkconfig --level 345 foo on", "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["chkconfig on".to_string()]));
    }

    #[test]
    fn chkconfig_off_and_removal_are_quiet() {
        for script in [
            "chkconfig foo off",
            "chkconfig --del foo",
            "chkconfig --remove foo",
            "/sbin/chkconfig --del foo",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "daemon-activation-in-%post"),
                "must stay silent for {script:?}: {found:?}"
            );
        }
    }

    #[test]
    fn daemon_activation_in_empty_prog_is_flagged() {
        // No `-p` flag defaults to /bin/sh: macro-expanded bodies
        // arrive this way and must still be scanned.
        let found = check().check_scriptlet("", "systemctl enable foo.service", "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "daemon-activation-in-%post"
            && d == &vec!["systemctl enable".to_string()]));
        let found = check().check_scriptlet("", "insserv foo", "%preun", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%preun")
        );
    }

    #[test]
    fn systemctl_in_comment_and_echo_is_quiet() {
        // Command-position matching: a mention in a comment or as an
        // argument to echo is not an invocation.
        let script = "# systemctl enable foo.service\n\
            echo \"systemctl enable foo.service\"\n\
            echo systemctl start foo.service";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn systemctl_single_dash_option_before_verb_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "systemctl -f enable foo.service",
            "%post",
            &[],
            &[],
        );
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post")
        );
        let found = check().check_scriptlet(
            "/bin/sh",
            "/usr/bin/systemctl --quiet enable foo.service",
            "%post",
            &[],
            &[],
        );
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post")
        );
    }

    #[test]
    fn insserv_removal_is_quiet() {
        // `insserv -r` removes the service from the runlevels; it
        // deactivates, so it is not an activation.
        let found = check().check_scriptlet(
            "/bin/sh",
            "/sbin/insserv -r /etc/init.d/foo",
            "%preun",
            &[],
            &[],
        );
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%preun"),
            "must stay silent: {found:?}"
        );
        let found = check().check_scriptlet(
            "/bin/sh",
            "/sbin/insserv ${YAST_IS_RUNNING:+-f} -r /etc/init.d/foo",
            "%postun",
            &[],
            &[],
        );
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%postun"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn daemon_activation_after_background_ampersand_is_flagged() {
        // A bare `&` backgrounds the previous command; what follows
        // is at command position just as after `&&`.
        let found = check().check_scriptlet(
            "/bin/sh",
            "sleep 1 & systemctl enable foo.service",
            "%post",
            &[],
            &[],
        );
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post")
        );
    }

    #[test]
    fn daemon_activation_in_case_arm_is_flagged() {
        let script =
            "case $1 in\nstart) systemctl enable foo.service;;\nstop) chkconfig foo off;;\nesac";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "{found:?}"
        );
        let script = "case $1 in\n1) chkconfig foo on;;\nesac";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "{found:?}"
        );
    }

    #[test]
    fn fd_redirect_does_not_open_command_position() {
        // `2>&1` is a redirection, not a separator: the words after
        // it are arguments to the first command, not an invocation.
        let found = check().check_scriptlet(
            "/bin/sh",
            "foo 2>&1 systemctl enable foo.service",
            "%post",
            &[],
            &[],
        );
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn daemon_activation_in_multiline_quote_is_quiet() {
        // A quoted string spanning lines: the continuation line is
        // string content, not code — the quote state threads across
        // lines in `code_only`.
        let script = "echo \"the service is managed with\nsystemctl enable foo.service\"";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn escaped_separator_does_not_open_command_position() {
        // `\;` is a literal argument character: what follows it is
        // still an argument, not a command at command position.
        let found = check().check_scriptlet(
            "/bin/sh",
            "echo \\; systemctl enable foo.service",
            "%post",
            &[],
            &[],
        );
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn heredoc_delimiter_lookalike_line_does_not_end_body() {
        // Only the exact terminator ends a plain heredoc body (the
        // `<<-` tab-stripping form aside): the indented lookalike
        // line is body text, so the mention after it is still
        // heredoc text, not code.
        let script = "cat <<EOF\n  EOF\nsystemctl enable foo.service\nEOF";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn systemctl_in_heredoc_text_is_quiet() {
        // An update message written through a heredoc is text the
        // scriptlet prints, not a command it runs.
        let script = "cat >> /var/adm/update-messages/foo << EOF\n\
            You can start it via:\n\
             systemctl start foo\n\
            EOF";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must stay silent: {found:?}"
        );
    }

    #[test]
    fn heredoc_escaped_delimiter_text_is_quiet() {
        for opener in ["cat <<\\EOF", "cat <<$'EOF'"] {
            let script = format!("{opener}\nsystemctl start foo\nEOF");
            let found = check().check_scriptlet("/bin/sh", &script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "daemon-activation-in-%post"),
                "must stay silent for {opener:?}: {found:?}"
            );
        }
    }

    #[test]
    fn non_heredoc_shift_does_not_hide_activation() {
        // `$((x << bits))` is an arithmetic left-shift, not a
        // heredoc: a genuine activation after it must still fire.
        let script = "echo $((x << bits))\nsystemctl enable foo.service";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must fire: {found:?}"
        );
    }

    #[test]
    fn non_heredoc_double_less_than_does_not_hide_activation() {
        for script in [
            "# see <<EOF\nsystemctl enable foo.service",
            "echo '<< orphan'\nsystemctl enable foo.service",
            "echo \"<< orphan\"\nsystemctl enable foo.service",
            "cat <<EOF\nsystemctl enable foo.service",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found
                    .iter()
                    .any(|(_, f, _)| f == "daemon-activation-in-%post"),
                "must fire for {script:?}: {found:?}"
            );
        }
    }

    #[test]
    fn heredoc_hyphenated_delimiter_text_is_quiet() {
        // The delimiter runs to the closing quote or the first shell
        // metacharacter, not to the first `-`, `.` or `:`: a body under
        // a hyphenated, dotted or colon delimiter is heredoc text.
        for (opener, term) in [
            ("cat <<'END-OF-MESSAGE'", "END-OF-MESSAGE"),
            ("cat <<EOF.2", "EOF.2"),
            ("cat <<end:of:msg", "end:of:msg"),
        ] {
            let script = format!("{opener}\nsystemctl start foo\n{term}");
            let found = check().check_scriptlet("/bin/sh", &script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "daemon-activation-in-%post"),
                "must stay silent for {opener:?}: {found:?}"
            );
        }
    }

    #[test]
    fn systemctl_after_separator_in_comment_or_quotes_is_quiet() {
        // A separator inside a comment or a quoted string does not put
        // the following text at command position: it never executes.
        for script in [
            "# foo; systemctl enable bar.service",
            "# cmd && systemctl enable bar.service",
            "echo \"a; systemctl enable foo.service\"",
            "echo 'a; systemctl start foo.service'",
            "echo \"a; /sbin/insserv foo\"",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "daemon-activation-in-%post"),
                "must stay silent for {script:?}: {found:?}"
            );
        }
    }

    #[test]
    fn systemctl_in_command_substitution_inside_quotes_is_flagged() {
        // A command substitution executes even inside double quotes,
        // so blanking quoted text must not hide it.
        let script = "echo \"$(systemctl enable foo.service)\"";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must fire: {found:?}"
        );
    }

    #[test]
    fn chkconfig_off_with_trailing_comment_mentioning_on_is_quiet() {
        // The trailing comment is stripped before the argument tokens
        // are classified, so its `on` does not flip an `off` command.
        let found = check().check_scriptlet(
            "/bin/sh",
            "chkconfig foo off # turn on at your own risk",
            "%post",
            &[],
            &[],
        );
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must stay silent: {found:?}"
        );
        let found = check().check_scriptlet(
            "/bin/sh",
            "chkconfig foo on # freshly installed",
            "%post",
            &[],
            &[],
        );
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must fire: {found:?}"
        );
    }

    #[test]
    fn insserv_long_remove_and_chkconfig_delete_are_quiet() {
        for (script, tag) in [
            ("/sbin/insserv --remove /etc/init.d/foo", "%preun"),
            ("chkconfig --delete foo", "%preun"),
        ] {
            let found = check().check_scriptlet("/bin/sh", script, tag, &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == &format!("daemon-activation-in-{tag}")),
                "must stay silent for {script:?}: {found:?}"
            );
        }
    }

    #[test]
    fn activation_after_heredoc_terminator_is_flagged() {
        // Blanking stops at the terminator: code after it is scanned.
        let script = "cat <<EOF\nsome text\nEOF\nsystemctl enable foo.service";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must fire: {found:?}"
        );
    }

    #[test]
    fn heredoc_in_command_substitution_text_is_quiet() {
        let script = "msg=\"$(cat <<EOF\nsystemctl start foo\nEOF\n)\"";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must stay silent for quoted substitution: {found:?}"
        );
        let script2 = "x=$(cat <<EOF\nsystemctl start foo\nEOF\n)";
        let found2 = check().check_scriptlet("/bin/sh", script2, "%post", &[], &[]);
        assert!(
            !found2
                .iter()
                .any(|(_, f, _)| f == "daemon-activation-in-%post"),
            "must stay silent for unquoted substitution: {found2:?}"
        );
    }

    #[test]
    fn useradd_invocation_is_flagged() {
        let found = check().check_scriptlet(
            "/bin/sh",
            "/usr/sbin/useradd -r -s /sbin/nologin foo",
            "%pre",
            &[],
            &[],
        );
        assert!(found.iter().any(|(l, f, d)| *l == Level::Warning
            && f == "scriptlet-useradd-in-%pre"
            && d == &vec!["/usr/sbin/useradd -r -s /sbin/nologin foo".to_string()]));
    }

    #[test]
    fn groupadd_invocation_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "groupadd -r foo", "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Warning
            && f == "scriptlet-groupadd-in-%post"
            && d == &vec!["groupadd -r foo".to_string()]));
    }

    #[test]
    fn useradd_bare_and_full_path_are_flagged() {
        for body in ["useradd foo", "/usr/sbin/useradd foo"] {
            let found = check().check_scriptlet("/bin/sh", body, "%preun", &[], &[]);
            assert!(
                found
                    .iter()
                    .any(|(_, f, _)| f == "scriptlet-useradd-in-%preun"),
                "must fire: {body}"
            );
        }
    }

    #[test]
    fn useradd_near_misses_are_quiet() {
        for body in [
            "systemd-sysusers",
            "/usr/bin/systemd-sysusers --replace=/usr/lib/sysusers.d/foo.conf -",
            "usermod -a -G video foo",
            "userdel foo",
            "# useradd -r foo\ntrue",
            "echo \"create the account with useradd -r foo\"",
        ] {
            let found = check().check_scriptlet("/bin/sh", body, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f.starts_with("scriptlet-useradd-in")
                        || f.starts_with("scriptlet-groupadd-in")),
                "must stay silent: {body}: {found:?}"
            );
        }
    }

    #[test]
    fn useradd_in_heredoc_is_quiet() {
        let body = "cat >> /var/adm/update-messages/foo << EOF\nCreate the account first:\n useradd -r foo\nEOF";
        let found = check().check_scriptlet("/bin/sh", body, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "scriptlet-useradd-in-%post"),
            "must stay silent for heredoc text: {found:?}"
        );
    }

    #[test]
    fn useradd_non_shell_prog_is_quiet() {
        let found = check().check_scriptlet("<lua>", "useradd foo", "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "scriptlet-useradd-in-%post"),
            "must stay silent for a lua scriptlet: {found:?}"
        );
    }

    #[test]
    fn rc_link_bare_invocation_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "rcmysql start", "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Warning
            && f == "scriptlet-rc-link-invocation-in-%post"
            && d == &vec!["rcmysql start".to_string()]));
    }

    #[test]
    fn rc_link_any_verb_or_none_is_flagged() {
        // Verb-independent: the invocation itself is the obsolete
        // part, so verbs outside the restart family — and no verb at
        // all — fire here while staying silent for
        // scriptlet-service-restart.
        for body in [
            "rcapache2 status",
            "rcapache2",
            "/usr/sbin/rcfoo stop",
            "FOO=bar rcapache2 status",
            "if rcapache2 status; then true; fi",
        ] {
            let found = check().check_scriptlet("/bin/sh", body, "%preun", &[], &[]);
            assert!(
                found
                    .iter()
                    .any(|(_, f, _)| f == "scriptlet-rc-link-invocation-in-%preun"),
                "must fire: {body}"
            );
        }
    }

    #[test]
    fn rc_link_in_case_arm_is_flagged() {
        let body = "case $1 in\n  1) rcapache2 graceful ;;\nesac";
        let found = check().check_scriptlet("/bin/sh", body, "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "scriptlet-rc-link-invocation-in-%post"),
            "must fire in a case arm: {found:?}"
        );
    }

    #[test]
    fn rc_link_after_separator_is_flagged_once() {
        // The corpus firer (uisp %post): the test -x operand on the
        // same line is not an invocation; the command after && is,
        // and the line is reported once.
        let body = "test -x /usr/sbin/rcresmgr && /usr/sbin/rcresmgr restart";
        let found = check().check_scriptlet("/bin/sh", body, "%post", &[], &[]);
        let hits: Vec<_> = found
            .iter()
            .filter(|(_, f, _)| f == "scriptlet-rc-link-invocation-in-%post")
            .collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].2, vec![body.to_string()]);
    }

    #[test]
    fn rc_link_lookalikes_are_quiet() {
        // The pinned near misses: rc-shaped names that are not
        // rc<service> link invocations — a real binary in a bin
        // directory, a name whose rc is not a prefix, the bare word
        // rc, an rc name under a non-sbin parent directory, and an
        // rc name in argument position. The bare-name collisions
        // (`rclone`, `rcs`, `rcp`) are real binaries that resolve
        // through PATH, so the bare forms stay quiet for any
        // arguments, exactly like the path-qualified forms.
        for body in [
            "/usr/bin/rclone sync a b",
            "rclone sync a b",
            "rclone restart",
            "rcs -i somefile",
            "rcp a b",
            "/usr/sbin/myrc restart",
            "rc start",
            "/opt/rcfoo/bin/rcbar start",
            "echo rcapp start",
        ] {
            let found = check().check_scriptlet("/bin/sh", body, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "scriptlet-rc-link-invocation-in-%post"),
                "must stay silent: {body}"
            );
        }
    }

    #[test]
    fn rc_link_function_definition_is_quiet() {
        // A shell function definition names a command, it does not
        // invoke one: `rcfoo() { ...; }` stays quiet even though
        // the bare name in command position would fire.
        for body in [
            "rcfoo() { echo hi; }",
            "rcfoo () { echo hi; }",
            "rcfoo()\n{\n echo hi\n}",
        ] {
            let found = check().check_scriptlet("/bin/sh", body, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "scriptlet-rc-link-invocation-in-%post"),
                "must stay silent for a function definition: {body}: {found:?}"
            );
        }
    }

    #[test]
    fn rc_link_repeated_line_is_flagged_per_line() {
        // Per-line reporting, matching the sibling
        // scriptlet-service-restart scan: the same offending line
        // twice in one body is two findings, not one.
        let body = "rcfoo status\nrcfoo status";
        let found = check().check_scriptlet("/bin/sh", body, "%post", &[], &[]);
        let hits: Vec<_> = found
            .iter()
            .filter(|(_, f, _)| f == "scriptlet-rc-link-invocation-in-%post")
            .collect();
        assert_eq!(hits.len(), 2, "{found:?}");
    }

    #[test]
    fn rc_link_in_quoted_text_is_quiet() {
        // The corpus near miss (w3c-markup-validator %post): an rc
        // name inside a quoted message is text, not an invocation.
        let body = "echo \"\nFinally, restart the webserver with 'rcapache2 graceful'.\"";
        let found = check().check_scriptlet("/bin/sh", body, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "scriptlet-rc-link-invocation-in-%post"),
            "must stay silent for quoted text: {found:?}"
        );
    }

    #[test]
    fn rc_link_in_heredoc_is_quiet() {
        // The corpus near miss (mariadb %post): the rc name is in a
        // heredoc update message the scriptlet writes out.
        let body = "cat >> /var/adm/update-messages/mariadb-something << EOF\nYou can start it via:\n rcmysql start\nEOF";
        let found = check().check_scriptlet("/bin/sh", body, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "scriptlet-rc-link-invocation-in-%post"),
            "must stay silent for heredoc text: {found:?}"
        );
    }

    #[test]
    fn rc_link_in_comment_is_quiet() {
        let body = "# rcapache2 restart\ntrue";
        let found = check().check_scriptlet("/bin/sh", body, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "scriptlet-rc-link-invocation-in-%post"),
            "must stay silent for comments: {found:?}"
        );
    }

    #[test]
    fn rc_link_non_shell_prog_is_quiet() {
        let found = check().check_scriptlet("<lua>", "rcapache2 restart", "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "scriptlet-rc-link-invocation-in-%post"),
            "must stay silent for a lua scriptlet: {found:?}"
        );
    }
}
