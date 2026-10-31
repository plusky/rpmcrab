//! `PostCheck` — scriptlet content checks.
//!
//! Ported from `rpmlint/checks/PostCheck.py`. The regex-based findings are
//! ported natively; the `sh -n` / `perl -wc` syntax checks shell out when
//! the interpreter exists and are skipped otherwise.

use std::collections::HashSet;
use std::process::Command;

use fancy_regex::Regex;

use super::files::strip_comment_tails;
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

/// What a bundled short-option token contributes to the
/// target-directory rule. GNU `-t` takes an argument even when
/// bundled, and `-S` takes one too: the first `t` not consumed
/// by `-S` is the target flag.
enum BundleTarget<'a> {
    /// That `t` carries the rest of the bundle as its argument.
    Attached(&'a str),
    /// That `t` is last: the next token is the target.
    Separate,
    /// A trailing `-S` takes the next token as its suffix argument.
    SuffixArg,
    /// No target-directory reading (not a bundle, or no
    /// unconsumed `t` and no trailing `-S`).
    None,
}

/// Read a token as a bundled short-option token: a reading only
/// for a single-dash token longer than the flag itself. Scanning
/// left to right, `-S` consumes the rest of the bundle (or the
/// next token when last) as its suffix argument, so no later `t`
/// in the same bundle is a target flag.
fn bundle_target(tok: &str) -> BundleTarget<'_> {
    if !tok.starts_with('-') || tok.starts_with("--") || tok.len() <= 2 {
        return BundleTarget::None;
    }
    let bundle = &tok[1..];
    for (ci, c) in bundle.char_indices() {
        if c == 'S' {
            if ci + c.len_utf8() == bundle.len() {
                return BundleTarget::SuffixArg;
            }
            return BundleTarget::None;
        }
        if c == 't' {
            let rest = &bundle[ci + c.len_utf8()..];
            if rest.is_empty() {
                return BundleTarget::Separate;
            }
            return BundleTarget::Attached(rest);
        }
    }
    BundleTarget::None
}

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

    /// Scriptlet text with rpm `--qf` / `--queryformat` arguments blanked,
    /// for the `percent-in` match only: a `--qf` argument IS a queryformat
    /// string, so `%{TAG}` inside it is format syntax, never macro fallout
    /// (the openblas-common-devel %pre case: `rpm -q --qf '%{NAME}'`).
    /// Blanking replaces argument bytes with spaces, preserving newlines
    /// (line anchors) and `#` (comment masking); an unterminated quote or
    /// a missing argument leaves the text untouched, so the check fails
    /// closed. Every other check still sees the original scriptlet.
    fn scrub_queryformat_args(script: &str) -> String {
        let bytes = script.as_bytes();
        let mut out = bytes.to_vec();
        let mut i = 0;
        while i < bytes.len() {
            let opt_len = if bytes[i..].starts_with(b"--queryformat") {
                13
            } else if bytes[i..].starts_with(b"--qf") {
                4
            } else {
                i += 1;
                continue;
            };
            // Option token boundaries: preceded by start, whitespace or a
            // shell separator; followed by whitespace, `=` or end of text.
            let prev_ok = i == 0
                || matches!(
                    bytes[i - 1],
                    b' ' | b'\t' | b'\n' | b';' | b'|' | b'&' | b'('
                );
            let next_ok = match bytes.get(i + opt_len) {
                None => true,
                Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'=') => true,
                Some(_) => false,
            };
            if !prev_ok || !next_ok {
                i += 1;
                continue;
            }
            // Skip separators: whitespace, `=`, and backslash-newline
            // continuations.
            let mut j = i + opt_len;
            loop {
                match bytes.get(j) {
                    Some(b' ') | Some(b'\t') | Some(b'=') => j += 1,
                    Some(b'\\') if bytes.get(j + 1) == Some(&b'\n') => j += 2,
                    _ => break,
                }
            }
            if j >= bytes.len() {
                break;
            }
            let arg_start = j;
            let arg_end = match bytes[j] {
                b'\'' | b'"' => {
                    let quote = bytes[j];
                    let mut k = j + 1;
                    while k < bytes.len() && bytes[k] != quote {
                        k += 1;
                    }
                    if k >= bytes.len() {
                        // Unterminated quote: fail closed, scrub nothing.
                        i = j + 1;
                        continue;
                    }
                    k + 1
                }
                _ => {
                    let mut k = j;
                    while k < bytes.len()
                        && !matches!(bytes[k], b' ' | b'\t' | b'\n' | b';' | b'|' | b'&' | b')')
                    {
                        k += 1;
                    }
                    k
                }
            };
            for byte in out.iter_mut().take(arg_end).skip(arg_start) {
                if *byte != b'\n' && *byte != b'#' {
                    *byte = b' ';
                }
            }
            i = arg_end;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    fn home_regex() -> &'static Regex {
        static HOME_REGEX: OnceLock<Regex> = OnceLock::new();
        HOME_REGEX
            .get_or_init(|| Regex::new(r"(?m)[^a-zA-Z]+~/|\$\{?HOME(\W|$)").expect("static regex"))
    }
    /// The verb terminator is a space or tab, never a newline: a
    /// bare verb at end-of-line must not swallow the next line's
    /// words as its operands.
    fn dangerous_regex() -> &'static Regex {
        static DANGEROUS_REGEX: OnceLock<Regex> = OnceLock::new();
        DANGEROUS_REGEX.get_or_init(|| Regex::new(
            r"(?m)(^|[;`|]|&&|$\()\s*(?:\S*/s?bin/)?(cp|mv|ln|tar|rpm|chmod|chown|rm|cpio|install|perl|userdel|groupdel)[ \t]",
        )
        .expect("static regex"))
    }
    /// State directories whose removal is credited in the
    /// dangerous-command scan: `rm` operands under these paths are
    /// package state, not payload. Deliberately not including /run or
    /// /var/run: state-file removal there stays firing.
    const VAR_STATE_PREFIXES: [&str; 5] = [
        "/var/lib/",
        "/var/adm/",
        "/var/log/",
        "/var/cache/",
        "/var/yp/",
    ];

    /// Whether this `rm` invocation is credited: every operand
    /// sits under a state prefix.
    ///
    /// `rest` is the text after the `rm` verb on the matched line.
    /// Flags (`-rf`, `--one-file-system`, `--`) are skipped; parsing
    /// stops at the first operator or redirect, so later commands and
    /// redirect targets are never mistaken for operands. A line
    /// continued with a trailing backslash is never credited: its
    /// operands continue on the next line and are not all visible
    /// here. Quoted operands count by their inner path. A non-`rm`
    /// verb, a tag outside the five ruled scriptlet phases, an empty
    /// operand list, or any operand outside the state prefixes keeps
    /// the finding firing. Ledgered in
    /// tests/parity/divergences.toml.
    fn rm_var_state_credit(tag: &str, verb: &str, rest: &str) -> bool {
        if verb != "rm" || !matches!(tag, "%post" | "%postun" | "%pre" | "%preun" | "%trigger") {
            return false;
        }
        let rest = rest.trim_end();
        if rest.ends_with('\\') {
            return false;
        }
        let mut tokens: Vec<String> = Vec::new();
        let mut cur = String::new();
        let mut quote: Option<char> = None;
        let mut in_token = false;
        for ch in rest.chars() {
            match quote {
                Some(q) => {
                    if ch == q {
                        quote = None;
                    } else {
                        cur.push(ch);
                    }
                }
                None => {
                    if ch == '"' || ch == '\'' {
                        quote = Some(ch);
                        in_token = true;
                    } else if ch.is_whitespace() {
                        if in_token {
                            tokens.push(std::mem::take(&mut cur));
                            in_token = false;
                        }
                    } else {
                        cur.push(ch);
                        in_token = true;
                    }
                }
            }
        }
        if in_token {
            tokens.push(cur);
        }
        let mut idx = 0;
        while idx < tokens.len() {
            let t = &tokens[idx];
            if t == "--" {
                idx += 1;
                break;
            }
            if t.starts_with('-') && t.len() > 1 {
                idx += 1;
            } else {
                break;
            }
        }
        let mut operands = 0;
        while idx < tokens.len() {
            let t = &tokens[idx];
            let first = t.chars().next().unwrap_or(' ');
            if first == ';'
                || first == '&'
                || first == '|'
                || first == '>'
                || first == '<'
                || (t.chars().take_while(|c| c.is_ascii_digit()).count() > 0
                    && (t.contains('>') || t.contains('<')))
            {
                break;
            }
            // A `..` component escapes the prefix, so it keeps firing.
            if t.split('/').any(|c| c == "..") {
                return false;
            }
            // A glob operand is not operand-exact: `/var/lib/*` wipes
            // shared state, so it keeps firing.
            if t.contains('*') || t.contains('?') || t.contains('[') {
                return false;
            }
            if !Self::VAR_STATE_PREFIXES.iter().any(|p| t.starts_with(p)) {
                return false;
            }
            operands += 1;
            idx += 1;
        }
        operands > 0
    }

    /// Whether a token names a backup file: a `.rpmsave` or `.rpmtmp`
    /// name, the names rpm itself writes when it preserves a modified
    /// config file across an upgrade.
    fn is_backup_name(token: &str) -> bool {
        token.ends_with(".rpmsave") || token.ends_with(".rpmtmp")
    }

    /// The logical command line starting at byte `at` in `text`: the
    /// rest of the physical line, with backslash-newline continuations
    /// (outside single quotes) joined. Stops at an unquoted newline.
    /// Inside double quotes a backslash follows the shell escape set:
    /// it is kept except before `$`, backtick, `"`, `\` and newline
    /// (a backslash-newline still joins); outside quotes the
    /// backslash is preserved except for continuations.
    fn logical_line_after(text: &str, at: usize) -> String {
        let mut out = String::new();
        let mut chars = text[at..].chars().peekable();
        let mut quote: Option<char> = None;
        while let Some(c) = chars.next() {
            match quote {
                Some(q) => {
                    // Inside double quotes a backslash follows the
                    // shell escape set: kept except before `$`,
                    // backtick, `"`, `\` and newline, where the
                    // escape resolves (a backslash-newline joins).
                    if c == '\\' && q == '"' {
                        match chars.peek() {
                            Some('\n') => {
                                chars.next();
                            }
                            Some(n) if matches!(*n, '$' | '`' | '"' | '\\') => {
                                out.push(*n);
                                chars.next();
                            }
                            Some(n) => {
                                out.push(c);
                                out.push(*n);
                                chars.next();
                            }
                            None => {}
                        }
                    } else if c == q {
                        quote = None;
                        out.push(c);
                    } else {
                        out.push(c);
                    }
                }
                None => {
                    if c == '\'' || c == '"' {
                        quote = Some(c);
                        out.push(c);
                    } else if c == '\\' {
                        match chars.peek() {
                            Some('\n') => {
                                chars.next();
                            }
                            Some(n) => {
                                out.push(c);
                                out.push(*n);
                                chars.next();
                            }
                            None => out.push(c),
                        }
                    } else if c == '\n' {
                        break;
                    } else {
                        out.push(c);
                    }
                }
            }
        }
        out
    }

    /// Split a logical command line into operand tokens, honouring
    /// single/double quotes and backslash escapes. Stops at an
    /// unquoted command separator, redirection, or comment start; an
    /// all-digit token attached to a redirection (e.g. `2>`) is the
    /// redirection's file descriptor, not an operand, and is dropped,
    /// while a space-separated digit before a redirection stays a
    /// positional operand (the shell parses it as a file to act on).
    fn split_operands(line: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut cur = String::new();
        let mut in_token = false;
        let mut chars = line.chars().peekable();
        let mut quote: Option<char> = None;
        while let Some(c) = chars.next() {
            match quote {
                Some(q) => {
                    // POSIX: inside double quotes a backslash is
                    // special only before `$`, backtick, `"`, `\`
                    // and newline; otherwise both chars are kept.
                    if c == '\\' && q == '"' {
                        match chars.peek() {
                            Some('\n') => {
                                chars.next();
                            }
                            Some(n) if matches!(*n, '$' | '`' | '"' | '\\') => {
                                cur.push(*n);
                                chars.next();
                            }
                            Some(n) => {
                                cur.push(c);
                                cur.push(*n);
                                chars.next();
                            }
                            None => {}
                        }
                    } else if c == q {
                        quote = None;
                    } else {
                        cur.push(c);
                    }
                }
                None => match c {
                    '\'' | '"' => {
                        quote = Some(c);
                        in_token = true;
                    }
                    '\\' => {
                        if let Some(n) = chars.next() {
                            cur.push(n);
                            in_token = true;
                        }
                    }
                    ' ' | '\t' => {
                        if in_token {
                            tokens.push(std::mem::take(&mut cur));
                            in_token = false;
                        }
                    }
                    '#' if !in_token => break,
                    ';' | '|' | '&' | '(' | ')' => break,
                    '<' | '>' => {
                        if in_token {
                            let tok = std::mem::take(&mut cur);
                            if !tok.chars().all(|c| c.is_ascii_digit()) {
                                tokens.push(tok);
                            }
                            in_token = false;
                        }
                        break;
                    }
                    _ => {
                        cur.push(c);
                        in_token = true;
                    }
                },
            }
        }
        if in_token {
            tokens.push(cur);
        }
        tokens
    }

    /// Whether a dangerous-command match at a command position is a
    /// backup-direction operation: `cp`/`mv` writing to a `.rpmsave`
    /// or `.rpmtmp` destination, or `rm` removing such a name. A
    /// restore (a backup name as the source, live path as the
    /// destination) is not a backup operation and keeps firing.
    /// A rotation (a backup name moved to a `.old` name, whose
    /// destination carries no backup suffix) is not a
    /// backup-direction operation either; it is credited separately
    /// by is_rotation.
    /// The destination rule: `-t` / `--target-directory` (separate
    /// or attached, including `-tDIR` and bundled `-pt` with the
    /// first `t` not consumed by `-S`) supply the destination for
    /// `cp`/`mv` only — `rm` has no target-directory option, so its
    /// `-t` argument stays positional, and its attached forms are
    /// dropped as plain flags with no operand effect. A copy/move
    /// also needs a real destination: at least two operands without
    /// `-t`, at least one with it.
    fn dangerous_match_is_backup(scan_text: &str, operand_at: usize, verb: &str) -> bool {
        if !matches!(verb, "cp" | "mv" | "rm") {
            return false;
        }
        let line = Self::logical_line_after(scan_text, operand_at);
        let tokens = Self::split_operands(&line);
        // Walk flags: `--` ends them; `-t` / `--target-directory`
        // (separate or attached, including `-tDIR`) take the
        // destination as their argument for `cp`/`mv` only.
        let mut positionals: Vec<&str> = Vec::new();
        let mut target_dir: Option<&str> = None;
        let mut i = 0;
        let mut no_more_flags = false;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            if !no_more_flags && tok == "--" {
                no_more_flags = true;
            } else if !no_more_flags && tok.starts_with('-') && tok.len() > 1 {
                // `-t` / `--target-directory` are `cp`/`mv` options
                // only: `rm` has no target-directory option, so for
                // `rm` these tokens are plain flags and a following
                // path stays positional. Attached `-tDIR` supplies
                // the destination directly.
                if verb != "rm" {
                    if tok == "-t" {
                        target_dir = tokens.get(i + 1).map(|s| s.as_str());
                        i += 1;
                    } else if tok.starts_with("-t") && !tok.starts_with("--") && tok.len() > 2 {
                        target_dir = Some(&tok[2..]);
                    } else if let Some(dir) = tok.strip_prefix("--target-directory=") {
                        target_dir = Some(dir);
                    } else if tok == "--target-directory" {
                        target_dir = tokens.get(i + 1).map(|s| s.as_str());
                        i += 1;
                    } else {
                        match bundle_target(tok) {
                            BundleTarget::Attached(dir) => target_dir = Some(dir),
                            BundleTarget::Separate => {
                                target_dir = tokens.get(i + 1).map(|s| s.as_str());
                                i += 1;
                            }
                            BundleTarget::SuffixArg => {
                                // A trailing `-S` takes the next
                                // token as its suffix argument,
                                // not an operand.
                                i += 1;
                            }
                            BundleTarget::None => {}
                        }
                    }
                }
                // Any other dash token is a flag (or a bundle) and
                // carries no operand of its own here.
            } else {
                positionals.push(tok);
            }
            i += 1;
        }
        match verb {
            // `rm` is credited only when every operand is a backup
            // name: a mixed removal still deletes live files.
            "rm" => !positionals.is_empty() && positionals.iter().all(|t| Self::is_backup_name(t)),
            _ => {
                // A copy/move needs a real destination: at least two
                // operands without `-t`, at least one with it. A lone
                // operand (or a bare `-t` target) is an incomplete
                // command, not a backup-direction operation.
                let enough = if target_dir.is_some() {
                    !positionals.is_empty()
                } else {
                    positionals.len() >= 2
                };
                if !enough {
                    return false;
                }
                let dest = target_dir.or_else(|| positionals.last().copied());
                dest.is_some_and(Self::is_backup_name)
            }
        }
    }

    /// Whether a dangerous command in the heredoc-blanked
    /// scriptlet text is a `.rpmsave` rotation aside-step: `mv`/`cp`
    /// of a `.rpmsave` path to the same path with `.old` appended,
    /// so rpm's own leftover saved config is set aside for a fresh
    /// `.rpmsave` to be created. The command is read from the end of
    /// the verb match: backslash-newline continuations are joined,
    /// option flags are skipped (a target-directory flag fails
    /// closed instead), and the first operands are compared
    /// with quotes stripped, so variable-carrying paths
    /// (`/etc/${i}.rpmsave`) match their rotated form literally.
    /// The tokenizer below stays separate from
    /// `logical_line_after`+`split_operands`: the two are close but
    /// not provably identical (a trailing token before an operator
    /// is kept here and dropped there), so no sharing.
    /// Exactly two operands are required: a restore to the live
    /// path, a backup to `.rpmsave`, a multi-operand move, or any
    /// other verb still fires. A glob operand keeps firing too: a
    /// `*`, `?`, or `[` in either operand moves a set of files, not
    /// one rpm leftover, so it is not operand-exact (the same rule
    /// the `rm` state credit applies). An unescaped newline ends the
    /// command, so words on later lines are never operands.
    fn is_rotation(scan_text: &str, verb: &str, verb_end: usize) -> bool {
        if verb != "mv" && verb != "cp" {
            return false;
        }
        let mut tokens: Vec<String> = Vec::new();
        let mut cur = String::new();
        let mut in_token = false;
        let mut in_single = false;
        let mut in_double = false;
        let mut chars = scan_text[verb_end..].chars();
        // Push the pending token, if any. The whitespace arm
        // resets `in_token` itself because the loop continues there;
        // the break arms leave it alone (the value is never read
        // after a break).
        macro_rules! push_token {
            () => {
                if in_token {
                    tokens.push(std::mem::take(&mut cur));
                }
            };
        }
        while let Some(c) = chars.next() {
            if in_single {
                if c == '\'' {
                    in_single = false;
                } else {
                    cur.push(c);
                }
                continue;
            }
            if in_double {
                if c == '"' {
                    in_double = false;
                } else if c == '\\' {
                    match chars.next() {
                        Some('\n') => {}
                        Some(other) => cur.push(other),
                        None => cur.push('\\'),
                    }
                } else {
                    cur.push(c);
                }
                continue;
            }
            match c {
                '\\' => match chars.next() {
                    // Backslash-newline is a continuation: no break.
                    Some('\n') => {}
                    Some(other) => {
                        cur.push(other);
                        in_token = true;
                    }
                    None => {}
                },
                '\'' => {
                    in_single = true;
                    in_token = true;
                }
                '"' => {
                    in_double = true;
                    in_token = true;
                }
                // A `#` at word start opens a comment: the rest of the
                // line is not operands.
                '#' if !in_token => break,
                ' ' | '\t' => {
                    push_token!();
                    in_token = false;
                }
                // An unescaped newline ends the command: without
                // this, words on later lines (a closing `fi`, the
                // next command) would read as extra operands and a
                // genuine two-operand rotation would never match.
                // Backslash-newline continuations never reach here
                // (they are skipped as continuations above).
                '\n' => {
                    push_token!();
                    in_token = false;
                    break;
                }
                ';' | '|' | '&' | '(' | ')' => {
                    push_token!();
                    in_token = false;
                    break;
                }
                // A redirect target is not an operand; a bare fd
                // (`2>`) is not one either.
                '<' | '>' => {
                    if in_token && !cur.chars().all(|d| d.is_ascii_digit()) {
                        push_token!();
                    } else {
                        cur.clear();
                    }
                    in_token = false;
                    break;
                }
                _ => {
                    cur.push(c);
                    in_token = true;
                }
            }
        }
        push_token!();
        // Skip option flags (`-v`, `--backup=numbered`); `--` ends
        // the flags and is itself skipped. A lone `-` is an operand.
        // A target-directory flag fails closed, including a bundled
        // `-t` not consumed by `-S` (or a trailing `-S` whose
        // argument is the next token, so the operand reading is
        // unreliable): a move into a directory is never a rotation
        // aside-step.
        let mut operands = tokens.into_iter().peekable();
        while let Some(t) = operands.peek() {
            if t == "--" {
                operands.next();
                break;
            }
            if t.starts_with("-t")
                || t == "--target-directory"
                || t.starts_with("--target-directory=")
                || !matches!(bundle_target(t), BundleTarget::None)
            {
                return false;
            }
            if t.len() > 1 && t.starts_with('-') {
                operands.next();
            } else {
                break;
            }
        }
        let operands: Vec<String> = operands.collect();
        if operands.len() != 2 {
            return false;
        }
        // The tokenizer above already drops quote characters, so
        // the operands never carry surrounding quotes.
        let source = operands[0].as_str();
        let dest = operands[1].as_str();
        // A glob operand is not operand-exact: `mv /etc/*.rpmsave
        // /etc/*.rpmsave.old` moves a set of files, not one rpm
        // leftover, so it keeps firing.
        if source.contains(['*', '?', '[']) || dest.contains(['*', '?', '[']) {
            return false;
        }
        source.ends_with(".rpmsave") && dest.strip_suffix(".old") == Some(source)
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
    /// so a command named inside it is not an invocation — but a body
    /// fed directly to a shell (`sh <<'EOF'`) IS executed, so directly
    /// shell-fed heredocs are left unblanked (see `line_feeds_shell`);
    /// piped-to-a-shell and wrapped shapes stay blanked.
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
        // Whether `line` feeds a heredoc directly to a shell: the
        // last command segment's first word (after `env` with flags,
        // `VAR=` prefixes, `time` with flags and shell keywords
        // including `if`, with any directory stripped)
        // names a POSIX shell. Piped-to-a-shell (`cat <<EOF | sh`),
        // sudo-wrapped and substitution shapes are not recognised
        // here and stay blanked.
        fn line_feeds_shell(line: &str) -> bool {
            let before = match line.rfind("<<") {
                Some(i) => &line[..i],
                None => return false,
            };
            let last = before.split([';', '|', '&', '(']).next_back().unwrap_or("");
            let mut words = last
                .split_whitespace()
                .map(|w| w.trim_matches(|c| c == '"' || c == '\''));
            let mut word = match words.next() {
                Some(w) => w,
                None => return false,
            };
            loop {
                if matches!(word, "then" | "do" | "else" | "!") {
                    word = match words.next() {
                        Some(w) => w,
                        None => return false,
                    };
                    continue;
                }
                if word == "if" {
                    word = match words.next() {
                        Some(w) => w,
                        None => return false,
                    };
                    continue;
                }
                if word == "time" {
                    word = match words.next() {
                        Some(w) => w,
                        None => return false,
                    };
                    // `time -p` (and other time flags) precede the command.
                    while word.starts_with('-') {
                        word = match words.next() {
                            Some(w) => w,
                            None => return false,
                        };
                    }
                    continue;
                }
                if word == "env" {
                    word = match words.next() {
                        Some(w) => w,
                        None => return false,
                    };
                    // `env -i` (and other env flags) precede the command.
                    while word.starts_with('-') {
                        word = match words.next() {
                            Some(w) => w,
                            None => return false,
                        };
                    }
                    continue;
                }
                if word.contains('=')
                    && word
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                {
                    word = match words.next() {
                        Some(w) => w,
                        None => return false,
                    };
                    continue;
                }
                break;
            }
            let base = word.rsplit('/').next().unwrap_or(word);
            matches!(
                base,
                "sh" | "bash" | "dash" | "ash" | "ksh" | "mksh" | "zsh"
            )
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
            // of the scriptlet and hides genuine invocations. A body
            // fed directly to a shell is executed, so it is never
            // blanked.
            let shell_fed = line_feeds_shell(line);
            for (delim, strip_tabs) in delimiters_in_line(line) {
                if shell_fed {
                    continue;
                }
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
        let mut tokens = args.split_whitespace();
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
            if is_match(Self::percent_regex(), &Self::scrub_queryformat_args(script)) {
                out.push((Level::Warning, finding("percent-in"), vec![]));
            }
            // Heredoc bodies are written out, not executed, so a command
            // named inside one is not an invocation in the scriptlet.
            // The blanking only applies to a body whose terminator
            // appears later, so a false opener cannot hide genuine
            // invocations.
            let scan_text = Self::without_heredoc_bodies(script);
            // Every dangerous-command match is examined: the finding
            // fires on the first match that is neither a credited `rm` of
            // package state, nor a credited backup-direction operation,
            // nor a `.rpmsave` rotation aside-step, so a credited match
            // cannot hide a later genuinely-dangerous command on the
            // same line or a later line. No match, or every match
            // credited, stays quiet. A rotation aside-step is credited
            // because the moved-aside file is rpm's own leftover, set
            // aside so a fresh `.rpmsave` can be created.
            let mut offending: Option<String> = None;
            for caps in Self::dangerous_regex().captures_iter(&scan_text).flatten() {
                let Some(m) = caps.get(2) else {
                    continue;
                };
                let line_end = scan_text[m.end()..]
                    .find('\n')
                    .map(|i| m.end() + i)
                    .unwrap_or(scan_text.len());
                let rest = &scan_text[m.end()..line_end];
                let backup = caps.get(0).is_some_and(|full| {
                    Self::dangerous_match_is_backup(&scan_text, full.end(), m.as_str())
                });
                if !Self::rm_var_state_credit(tag, m.as_str(), rest)
                    && !backup
                    && !Self::is_rotation(&scan_text, m.as_str(), m.end())
                {
                    offending = Some(m.as_str().to_string());
                    break;
                }
            }
            if let Some(verb) = offending {
                out.push((Level::Warning, finding("dangerous-command-in"), vec![verb]));
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
            let posttrans = pkg.tag_str(Tag::POSTTRANS).unwrap_or_default();
            let tmpfiles = tmpfiles_declared_paths(pkg);
            let posttrans_mentions = posttrans_mention_tokens(&posttrans);
            for f in &pkg.ghost_files {
                if pkg.missingok_files.iter().any(|m| m == f) {
                    continue;
                }
                if is_icon_theme_cache(f) {
                    continue;
                }
                if posttrans_mentions.contains(f.as_str()) {
                    continue;
                }
                if tmpfiles.contains(f.as_str()) {
                    continue;
                }
                if postin.is_empty() && prein.is_empty() {
                    add_info(out, Level::Warning, pkg, "ghost-files-without-postin", &[]);
                }
            }
        }
    }
}

/// The whole-token path mentions of a scriptlet: a pure
/// substring match credits prefixes (`/etc/foobar` for a
/// `/etc/foo` ghost), so the scriptlet is split on whitespace and
/// shell separators and each token is compared whole, with
/// surrounding quotes stripped and a trailing slash ignored
/// (except root `/`), matching the tmpfiles credit.
/// A mention is not a creation: any whole-token mention credits
/// the ghost, including non-creation reads (`test -f`, `cat`,
/// `echo`, `[ -e`, `dirname`), so a ghost only tested, never
/// created, goes silent. Narrowing the credit to creation
/// context is a behaviour change and is not done here.
fn scriptlet_path_tokens(scriptlet: &str) -> HashSet<String> {
    scriptlet
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '&' | '(' | ')' | '<' | '>'))
        .map(|tok| tok.trim_matches(|c| c == '"' || c == '\''))
        .map(|tok| {
            tok.strip_suffix('/')
                .filter(|t| !t.is_empty())
                .unwrap_or(tok)
        })
        .filter(|tok| !tok.is_empty())
        .map(str::to_string)
        .collect()
}

/// The %posttrans path mentions the ghost credit reads: whole
/// tokens of the heredoc-blanked, comment-stripped scriptlet, so a
/// path named only in a comment or a heredoc body does not credit
/// the ghost. Tokenized once for the whole ghost loop.
fn posttrans_mention_tokens(posttrans: &str) -> HashSet<String> {
    scriptlet_path_tokens(&strip_comment_tails(&PostCheck::without_heredoc_bodies(
        posttrans,
    )))
}

/// The icon-theme cache ghost: `/usr/share/icons/<theme>/icon-theme.cache`,
/// with exactly one path component (the theme name) between the icons
/// directory and the cache file. openSUSE creates these caches with a
/// file trigger (gtk3-tools, over `/usr/share/icons`); the package's
/// own `%post` never creates them, so the cache ghost is the
/// trigger's to create and does not count toward
/// `ghost-files-without-postin` (#1172). Deeper or shallower shapes
/// are ordinary ghosts.
fn is_icon_theme_cache(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/usr/share/icons/") else {
        return false;
    };
    let Some(theme) = rest.strip_suffix("/icon-theme.cache") else {
        return false;
    };
    !theme.is_empty() && !theme.contains('/')
}

/// The path a tmpfiles.d creation line declares, if the line is an exact
/// literal path: comment and empty lines, non-creation lines (`x`, `r`,
/// `z`, `t`, `h`, `a` and friends), glob patterns, and %-specifier
/// paths never declare a path. A trailing slash on a directory line is
/// stripped so `d /run/foo/` declares the ghost `/run/foo`.
fn tmpfiles_line_path(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut fields = line.split_whitespace();
    let kind = fields.next()?.trim_end_matches(['!', '+']);
    if !matches!(
        kind,
        "d" | "D" | "f" | "F" | "w" | "L" | "c" | "C" | "b" | "p" | "P"
    ) {
        return None;
    }
    let path = fields.next()?;
    if path.contains(['*', '?', '[', '%']) {
        return None;
    }
    let path = path.strip_suffix('/').unwrap_or(path);
    if path.is_empty() {
        return None;
    }
    Some(path.to_string())
}

/// Paths declared by same-package tmpfiles.d creation lines: a %ghost
/// created by systemd-tmpfiles at boot is created, not missing.
/// Unreadable fragments declare nothing, so packages without extraction
/// never gain the credit.
fn tmpfiles_declared_paths(pkg: &Pkg) -> HashSet<String> {
    let mut declared = HashSet::new();
    for file in &pkg.files {
        if !file.name.contains("/tmpfiles.d/") || !file.name.ends_with(".conf") {
            continue;
        }
        for line in pkg.read_file(&file.name).lines() {
            if let Some(path) = tmpfiles_line_path(line) {
                declared.insert(path);
            }
        }
    }
    declared
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

    /// Run the check over the ghost fixture (no %prein/%postin at
    /// all) with its ghost set replaced by `ghosts`.
    fn ghost_fixture_results(ghosts: &[&str]) -> Vec<String> {
        let rpm_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/postcheck-ghost-parity-1.0-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm_path, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.ghost_files = ghosts.iter().map(|g| g.to_string()).collect();
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = PostCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        out.results().iter().map(|(name, _)| name.clone()).collect()
    }

    /// #1172: a package whose only ghosts are icon-theme caches
    /// stays silent -- the caches are created by the gtk3-tools file
    /// trigger, not by any %post of the owning package.
    #[test]
    fn icon_theme_cache_ghost_is_quiet_1172() {
        assert_eq!(
            ghost_fixture_results(&["/usr/share/icons/hicolor/icon-theme.cache"]),
            Vec::<String>::new()
        );
        assert_eq!(
            ghost_fixture_results(&[
                "/usr/share/icons/hicolor/icon-theme.cache",
                "/usr/share/icons/Adwaita/icon-theme.cache",
            ]),
            Vec::<String>::new()
        );
    }

    /// #1172 near-misses: lookalike shapes are ordinary ghosts and
    /// keep firing, and an ordinary ghost beside a cache still
    /// carries the finding.
    #[test]
    fn icon_theme_cache_lookalikes_still_fire_1172() {
        for ghosts in [
            // No theme component.
            vec!["/usr/share/icons/icon-theme.cache"],
            // Two components below the icons directory.
            vec!["/usr/share/icons/hicolor/48x48/icon-theme.cache"],
            // Not the icons directory.
            vec!["/usr/share/pixmaps/hicolor/icon-theme.cache"],
            // Not the cache file name.
            vec!["/usr/share/icons/hicolor/other.cache"],
        ] {
            assert_eq!(
                ghost_fixture_results(&ghosts),
                vec!["ghost-files-without-postin"],
                "ghosts: {ghosts:?}"
            );
        }
        assert_eq!(
            ghost_fixture_results(&[
                "/usr/share/icons/hicolor/icon-theme.cache",
                "/var/lib/foo/state",
            ]),
            vec!["ghost-files-without-postin"]
        );
    }

    #[test]
    fn is_icon_theme_cache_shape_1172() {
        assert!(is_icon_theme_cache(
            "/usr/share/icons/openSUSE-halloween/icon-theme.cache"
        ));
        assert!(!is_icon_theme_cache("/usr/share/icons/icon-theme.cache"));
        assert!(!is_icon_theme_cache(
            "/usr/share/icons/a/b/icon-theme.cache"
        ));
        assert!(!is_icon_theme_cache("/usr/share/icons//icon-theme.cache"));
        assert!(!is_icon_theme_cache(
            "/usr/share/icons/hicolor/icon-theme.cache.bak"
        ));
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

    /// Run the check over a fixture RPM and count
    /// `ghost-files-without-postin` findings, optionally with the
    /// fixture's ghost set replaced by `ghosts`.
    fn ghost_count(rpm: &str, ghosts: Option<&[&str]>) -> usize {
        let rpm_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs")
            .join(rpm);
        let mut pkg = Pkg::open(&rpm_path, &std::env::temp_dir(), true).expect("open fixture pkg");
        if let Some(g) = ghosts {
            pkg.ghost_files = g.iter().map(|s| s.to_string()).collect();
        }
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = PostCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        out.results()
            .iter()
            .filter(|(name, _)| name == "ghost-files-without-postin")
            .count()
    }

    #[test]
    fn scriptlet_path_tokens_is_boundary_aware() {
        assert!(scriptlet_path_tokens("ln -sf /etc/foo /etc/bar").contains("/etc/foo"));
        assert!(scriptlet_path_tokens("ln -sf \"/etc/foo\" /etc/bar").contains("/etc/foo"));
        // A mention pin, not a creation pin: `test -f` only tests
        // the path, yet the whole-token mention credits the ghost.
        assert!(scriptlet_path_tokens("test -f /etc/foo").contains("/etc/foo"));
        // A trailing slash on the mention is ignored, matching the
        // tmpfiles credit; the boundary rule still applies.
        assert!(scriptlet_path_tokens("mkdir -p /run/foo/").contains("/run/foo"));
        assert!(!scriptlet_path_tokens("mkdir -p /run/foobar/").contains("/run/foo"));
        assert!(!scriptlet_path_tokens("ln -sf /etc/foobar /etc/bar").contains("/etc/foo"));
        assert!(!scriptlet_path_tokens("test -f /etc/foobar").contains("/etc/foo"));
        assert!(!scriptlet_path_tokens("").contains("/etc/foo"));
    }

    #[test]
    fn posttrans_mention_tokens_ignore_comments_and_heredoc_bodies() {
        let script = "# mkdir -p /etc/commented\ncat <<'EOF'\nmkdir -p /etc/heredoc\nEOF\nmkdir -p /etc/real/\n";
        let tokens = posttrans_mention_tokens(script);
        assert!(tokens.contains("/etc/real"));
        assert!(
            !tokens.contains("/etc/commented"),
            "a path named only in a comment must not credit: {tokens:?}"
        );
        assert!(
            !tokens.contains("/etc/heredoc"),
            "a path named only in a heredoc body must not credit: {tokens:?}"
        );
    }

    #[test]
    fn posttrans_created_ghost_is_quiet() {
        // %posttrans creates one ghost (ln -sf) and never mentions the
        // other; only the unmentioned ghost carries the finding.
        assert_eq!(
            ghost_count("postcheck-ghost-posttrans-1.0-1.noarch.rpm", None),
            1
        );
        assert_eq!(
            ghost_count(
                "postcheck-ghost-posttrans-1.0-1.noarch.rpm",
                Some(&["/etc/postcheck-ghost-posttrans-created"])
            ),
            0
        );
        assert_eq!(
            ghost_count(
                "postcheck-ghost-posttrans-1.0-1.noarch.rpm",
                Some(&["/etc/postcheck-ghost-posttrans-unmentioned"])
            ),
            1
        );
    }

    #[test]
    fn tmpfiles_declared_ghosts_are_quiet() {
        // The shipped fragment declares the directory ghost (through a
        // trailing-slash line) and the state file; the glob line never
        // matches, and the unmentioned ghost is untouched.
        assert_eq!(
            ghost_count("postcheck-ghost-tmpfiles-1.0-1.noarch.rpm", None),
            2
        );
        assert_eq!(
            ghost_count(
                "postcheck-ghost-tmpfiles-1.0-1.noarch.rpm",
                Some(&["/run/postcheck-tmpfiles"])
            ),
            0
        );
        assert_eq!(
            ghost_count(
                "postcheck-ghost-tmpfiles-1.0-1.noarch.rpm",
                Some(&["/var/lib/postcheck-tmpfiles/state"])
            ),
            0
        );
        assert_eq!(
            ghost_count(
                "postcheck-ghost-tmpfiles-1.0-1.noarch.rpm",
                Some(&["/var/lib/postcheck-tmpfiles/globfile"])
            ),
            1
        );
        assert_eq!(
            ghost_count(
                "postcheck-ghost-tmpfiles-1.0-1.noarch.rpm",
                Some(&["/var/lib/postcheck-tmpfiles/unmentioned"])
            ),
            1
        );
    }

    #[test]
    fn tmpfiles_line_path_shapes() {
        assert_eq!(
            tmpfiles_line_path("d /run/foo 0755 root root -"),
            Some("/run/foo".to_string())
        );
        assert_eq!(
            tmpfiles_line_path("d /run/foo/ 0755 root root -"),
            Some("/run/foo".to_string())
        );
        assert_eq!(
            tmpfiles_line_path("L /var/lib/link - - - - /target"),
            Some("/var/lib/link".to_string())
        );
        assert_eq!(tmpfiles_line_path("# comment"), None);
        assert_eq!(tmpfiles_line_path(""), None);
        assert_eq!(
            tmpfiles_line_path("d /var/lib/glob* 0755 root root -"),
            None
        );
        assert_eq!(
            tmpfiles_line_path("d /var/lib/%m/foo 0755 root root -"),
            None
        );
        assert_eq!(tmpfiles_line_path("d"), None);
        assert_eq!(
            tmpfiles_line_path("x /var/lib/excluded 0755 root root -"),
            None
        );
        assert_eq!(
            tmpfiles_line_path("r /var/lib/removed 0755 root root -"),
            None
        );
        assert_eq!(
            tmpfiles_line_path("d! /run/foo 0755 root root -"),
            Some("/run/foo".to_string())
        );
        // Trailing-slash strip applies to all types, not just
        // directories: an `f` or `L` line for `/run/foo/` declares
        // `/run/foo`, so a shipped `/run/foo` matches it.
        assert_eq!(
            tmpfiles_line_path("f /run/foo/ 0644 root root -"),
            Some("/run/foo".to_string())
        );
        assert_eq!(
            tmpfiles_line_path("L /run/foo/ - - - - /target"),
            Some("/run/foo".to_string())
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
    fn percent_queryformat_arg_is_silent() {
        // The openblas-common-devel %pre case: `%{NAME}` is the argument
        // to `rpm -q --qf`, a queryformat string, not macro fallout.
        let script = "d=/usr/lib64/cmake/openblas\n[ -d $d -a ! -L $d -a \"$(rpm -q --qf '%{NAME}' -f $d 2>/dev/null)\" = \"openblas-devel\" ] \\\n    && { n=$(mktemp -d $(dirname $d)/tmpd-XXXXX); mv $d $n; rm -rf $n; } || true";
        let found = check().check_scriptlet("/bin/sh", script, "%pre", &[], &[]);
        assert!(!found.iter().any(|(_, f, _)| f == "percent-in-%pre"));
        // The scrub applies to the percent check only: the `rm -rf` in
        // the same scriptlet still fires its own finding.
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "dangerous-command-in-%pre")
        );
    }

    #[test]
    fn percent_queryformat_forms_are_silent() {
        for script in [
            "rpm -q --qf '%{NAME}' -f /x",
            "rpm -q --qf \"%{NAME}\" -f /x",
            "rpm -q --qf=%{NAME} -f /x",
            "rpm -q --qf='%{NAME}' -f /x",
            "rpm -q --queryformat '%{NAME} %{VERSION}' -f /x",
            "rpm -q --qf \\\n'%{NAME}' -f /x",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%pre", &[], &[]);
            assert!(
                !found.iter().any(|(_, f, _)| f == "percent-in-%pre"),
                "queryformat form fired: {script}"
            );
        }
    }

    #[test]
    fn percent_outside_queryformat_still_fires() {
        let script = "rpm -q --qf '%{NAME}' -f /x\necho %foo";
        let found = check().check_scriptlet("/bin/sh", script, "%pre", &[], &[]);
        assert!(found.iter().any(|(_, f, _)| f == "percent-in-%pre"));
    }

    #[test]
    fn percent_queryformat_lookalike_option_still_fires() {
        // `--qformat` is not `--qf`: the option boundary matters.
        let found =
            check().check_scriptlet("/bin/sh", "echo --qformat '%{NAME}'", "%pre", &[], &[]);
        assert!(found.iter().any(|(_, f, _)| f == "percent-in-%pre"));
    }

    #[test]
    fn percent_queryformat_unterminated_quote_still_fires() {
        // Fail closed: an unterminated quote scrubs nothing.
        let found = check().check_scriptlet("/bin/sh", "rpm -q --qf '%{NAME}", "%pre", &[], &[]);
        assert!(found.iter().any(|(_, f, _)| f == "percent-in-%pre"));
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
    fn dangerous_command_var_state_credit() {
        // Every credited prefix, in the ruled phases, goes quiet.
        for prefix in [
            "/var/lib/",
            "/var/adm/",
            "/var/log/",
            "/var/cache/",
            "/var/yp/",
        ] {
            let script = format!("rm -rf {prefix}foo");
            for tag in ["%post", "%postun", "%pre", "%preun", "%trigger"] {
                let found = check().check_scriptlet("/bin/sh", &script, tag, &[], &[]);
                assert!(
                    !found
                        .iter()
                        .any(|(_, f, _)| f == &format!("dangerous-command-in-{tag}")),
                    "{tag} {script} should be credited"
                );
            }
        }
        // /run and /var/run stay firing.
        for path in ["/run/foo", "/var/run/foo"] {
            let script = format!("rm -rf {path}");
            let found = check().check_scriptlet("/bin/sh", &script, "%post", &[], &[]);
            assert!(
                found
                    .iter()
                    .any(|(_, f, _)| f == "dangerous-command-in-%post")
            );
        }
        // Ruled phases only: %posttrans and %pretrans keep firing.
        for tag in ["%posttrans", "%pretrans"] {
            let found = check().check_scriptlet("/bin/sh", "rm -rf /var/lib/foo", tag, &[], &[]);
            assert!(
                found
                    .iter()
                    .any(|(_, f, _)| f == &format!("dangerous-command-in-{tag}"))
            );
        }
        // Mixed operands, variables, payload paths and other verbs keep firing.
        for script in [
            "rm -rf /var/lib/foo /etc/bar",
            "rm -rf $dir",
            "rm -rf /etc/foo",
            "rm -rf /var/lib",
            "rm -rf /var/lib/../etc/passwd",
            "cp -f /var/lib/foo /var/lib/bar",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found
                    .iter()
                    .any(|(_, f, _)| f == "dangerous-command-in-%post"),
                "{script} should still fire"
            );
        }
        // Quoted operands, long flags, redirects and operators.
        for script in [
            "rm -f \"/var/lib/foo\"",
            "rm -rf --one-file-system /var/lib/foo || true",
            "rm /var/log/dump >/dev/null 2>&1 || true",
            "rm -f /var/yp/nicknames ||:",
            "/usr/bin/rm -f /var/lib/a /var/lib/b",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "dangerous-command-in-%post"),
                "{script} should be credited"
            );
        }
        // Glob operands are not operand-exact: they wipe shared state.
        for script in [
            "rm -rf /var/lib/*",
            "rm -rf /var/cache/*",
            "rm -rf /var/lib/foo?",
            "rm -rf /var/lib/foo[12]",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found
                    .iter()
                    .any(|(_, f, _)| f == "dangerous-command-in-%post"),
                "{script} should still fire"
            );
        }
        // Multi-command scriptlets: the finding stays quiet only when
        // every dangerous-command match is a credited `rm`, in both
        // directions and across separators.
        for script in [
            "rm -rf /var/lib/foo && rm -rf /var/lib/bar",
            "rm -rf /var/lib/foo ; rm -rf /var/log/bar",
            "rm -rf /var/lib/foo\nrm -rf /var/cache/bar",
            "rm -rf /var/lib/foo && rm -rf /var/lib/bar && rm -rf /var/log/baz",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "dangerous-command-in-%post"),
                "{script} should be credited"
            );
        }
        // ... and any non-credited match in the chain keeps it firing,
        // whether it comes first, last, or is a non-`rm` verb or a glob.
        for script in [
            "rm -rf /var/lib/foo && rm -rf /etc/passwd",
            "rm -rf /var/lib/foo ; rm -rf /etc/passwd",
            "rm -rf /var/lib/foo\nrm -rf /etc/passwd",
            "rm -rf /var/lib/foo;rm -rf /etc/passwd",
            "rm -rf /etc/passwd && rm -rf /var/lib/foo",
            "rm -rf /var/lib/foo && cp -f /var/lib/a /etc/b",
            "rm -rf /var/lib/foo && rm -rf /var/lib/*",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found
                    .iter()
                    .any(|(_, f, _)| f == "dangerous-command-in-%post"),
                "{script} should still fire"
            );
        }
        // A continued line is never credited: its operands are not all visible.
        let found = check().check_scriptlet(
            "/bin/sh",
            "rm -rf /var/lib/foo \\\n/etc/bar",
            "%post",
            &[],
            &[],
        );
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "dangerous-command-in-%post")
        );
    }

    #[test]
    fn dangerous_command_in_heredoc_body_is_silent() {
        let script = "cat > /var/run/texlive/scriptlets/x << 'EOF'\n/usr/bin/perl /usr/share/texmf/tlpkg/tlpostcode/x.pl install /usr/share/texmf\nEOF\n";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "dangerous-command-in-%post")
        );
    }

    #[test]
    fn dangerous_command_in_shell_fed_heredoc_still_fires() {
        // A body fed directly to a shell IS executed, so its
        // invocations fire; the path-qualified and flagged forms
        // count as directly fed too.
        for script in [
            "sh <<'EOF'\nrm -rf /foo\nEOF\n",
            "/bin/sh -e <<EOF\nrm -rf /foo\nEOF\n",
            "env -i sh <<'EOF'\nrm -rf /foo\nEOF\n",
            "time -p sh <<'EOF'\nrm -rf /foo\nEOF\n",
            "if sh <<'EOF'\nrm -rf /foo\nEOF\n",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found.iter().any(|(l, f, d)| *l == Level::Warning
                    && f == "dangerous-command-in-%post"
                    && d == &vec!["rm".to_string()]),
                "shell-fed body must fire: {script}"
            );
        }
        // Piped-to-a-shell stays blanked (known residual): the body
        // reaches the shell through the pipe, not as its stdin.
        let script = "cat <<'EOF' | sh\nrm -rf /foo\nEOF\n";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "dangerous-command-in-%post"),
            "piped-to-shell body stays blanked: {found:?}"
        );
    }

    #[test]
    fn dangerous_command_after_heredoc_still_fires() {
        let script = "cat > /tmp/note << 'EOF'\nln -s a b\nEOF\nrm -rf /bar\n";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Warning
            && f == "dangerous-command-in-%post"
            && d == &vec!["rm".to_string()]));
    }

    #[test]
    fn dangerous_command_in_unclosed_heredoc_still_fires() {
        // No terminator later in the scriptlet, so the body is not
        // blanked and the command still fires.
        let script = "cat > /tmp/note << 'EOF'\nrm -rf /foo\n";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Warning
            && f == "dangerous-command-in-%post"
            && d == &vec!["rm".to_string()]));
    }

    #[test]
    fn dangerous_command_in_plain_heredoc_body_is_silent() {
        // Unquoted delimiter: the body is still written out, not
        // executed, so the named command stays silent.
        let script = "cat > /tmp/note <<EOF\nrm -rf /foo\nEOF\n";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "dangerous-command-in-%post")
        );
    }

    #[test]
    fn dangerous_command_heredoc_body_lines_fire_standalone() {
        // Firing controls for the silenced body lines: the same
        // commands outside any heredoc still fire.
        for script in [
            "rm -rf /foo\n",
            "/usr/bin/perl /usr/share/texmf/tlpkg/tlpostcode/x.pl install /usr/share/texmf\n",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found
                    .iter()
                    .any(|(_, f, _)| f == "dangerous-command-in-%post"),
                "standalone line should fire: {script}"
            );
        }
    }

    #[test]
    fn dangerous_command_in_dash_heredoc_body_is_silent() {
        let script = "cat <<- 'EOF'\n\trm -rf /foo\n\tEOF\n";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "dangerous-command-in-%post")
        );
    }

    #[test]
    fn dangerous_command_backup_direction_is_silent() {
        for script in [
            "cp -p /etc/dat.conf /etc/dat.conf.rpmtmp\n",
            "mv /etc/conman.conf /etc/conman.conf.rpmsave\n",
            "rm -f /usr/share/smartmontools/drivedb.h.rpmsave\n",
            "[ -f /boot/efi/config.txt ] && cp /boot/efi/config.txt /boot/efi/config.txt.rpmsave\n",
            "cp /etc/zypp/repos.d/$repo_file /etc/zypp/repos.d/$repo_file.rpmsave\n",
            "cp \"/etc/foo\" \"/etc/foo.rpmsave\"\n",
            "cp -t /etc/foo.rpmsave /etc/foo\n",
            "cp --target-directory=/etc/foo.rpmtmp /etc/foo\n",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "dangerous-command-in-%post"),
                "backup direction should stay silent: {script}"
            );
        }
    }

    #[test]
    fn dangerous_command_rm_target_directory_still_fires() {
        // GNU rm has no -t: the separate "target dir" argument is a
        // live operand, so the removal is mixed and keeps firing.
        for script in [
            "rm -t /live /a.rpmsave\n",
            "rm --target-directory /live /a.rpmsave\n",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found.iter().any(|(l, f, d)| *l == Level::Warning
                    && f == "dangerous-command-in-%post"
                    && d == &vec!["rm".to_string()]),
                "rm with a live operand must fire: {script}"
            );
        }
    }

    #[test]
    fn dangerous_command_rm_attached_target_directory_is_silent() {
        // GNU rm has no -t in any form: an attached -tDIR or
        // --target-directory=DIR token is dropped as a plain flag
        // with no operand effect, so an rm whose only remaining
        // operands are backup names goes quiet -- unlike the
        // separate form, where the directory stays positional and
        // keeps a mixed rm firing.
        for script in [
            "rm -t/live /a.rpmsave\n",
            "rm --target-directory=/live /a.rpmsave\n",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "dangerous-command-in-%post"),
                "rm attached target-dir form fired: {script}"
            );
        }
    }

    #[test]
    fn dangerous_command_mixed_rm_still_fires() {
        // The rm arm credits only all-backup operand sets: a backup
        // name next to a live path still deletes live files.
        for script in [
            "rm -f /etc/foo.rpmsave /etc/passwd\n",
            "rm -f /etc/passwd /etc/foo.rpmsave\n",
            "rm -f /etc/foo /etc/foo.rpmsave\n",
            "rm -t /live /etc/foo.rpmsave\n",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found.iter().any(|(l, f, d)| *l == Level::Warning
                    && f == "dangerous-command-in-%post"
                    && d == &vec!["rm".to_string()]),
                "mixed rm must fire: {script}"
            );
        }
    }

    #[test]
    fn dangerous_command_bare_verb_newline_does_not_swallow_next_line() {
        // A bare verb at end-of-line is not a match: the next
        // line's words are not its operands, so the finding names
        // the real verb on the next line.
        let script = "cp\nrm -rf /bar\n";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            found.iter().any(|(l, f, d)| *l == Level::Warning
                && f == "dangerous-command-in-%post"
                && d == &vec!["rm".to_string()]),
            "finding must name rm, not cp: {found:?}"
        );
        assert!(
            !found
                .iter()
                .any(|(_, f, d)| f == "dangerous-command-in-%post" && d == &vec!["cp".to_string()]),
            "bare cp must not swallow the next line: {found:?}"
        );
    }

    #[test]
    fn split_operands_double_quote_escape_set() {
        // Shell unescapes only `$`, backtick, `"`, `\` and newline
        // inside double quotes; any other backslash stays.
        assert_eq!(
            PostCheck::split_operands("cp \"x\\ay\" z"),
            vec!["cp".to_string(), "x\\ay".to_string(), "z".to_string()]
        );
        assert_eq!(
            PostCheck::split_operands("cp \"x\\$y\" z"),
            vec!["cp".to_string(), "x$y".to_string(), "z".to_string()]
        );
        assert_eq!(
            PostCheck::split_operands("cp \"x\\\"y\" z"),
            vec!["cp".to_string(), "x\"y".to_string(), "z".to_string()]
        );
    }

    #[test]
    fn dangerous_command_save_rotation_mv_is_silent() {
        for script in [
            "test -f /etc/foo.rpmsave && mv -v /etc/foo.rpmsave /etc/foo.rpmsave.old || :",
            "mv -f \"/etc/modprobe.d/${_f}.rpmsave\" \"/etc/modprobe.d/${_f}.rpmsave.old\" || :",
            "test -f /etc/${i}.rpmsave && mv -v /etc/${i}.rpmsave /etc/${i}.rpmsave.old || :",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%pre", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "dangerous-command-in-%pre"),
                "rotation fired: {script}"
            );
        }
    }

    #[test]
    fn dangerous_command_restore_and_rotation_still_fire() {
        for (script, verb) in [
            ("cp /etc/foo.rpmsave /etc/foo\n", "cp"),
            ("cp -t /etc /etc/foo.rpmsave\n", "cp"),
            ("rm -f /etc/foo\n", "rm"),
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found.iter().any(|(l, f, d)| *l == Level::Warning
                    && f == "dangerous-command-in-%post"
                    && d == &vec![verb.to_string()]),
                "should still fire: {script}"
            );
        }
    }

    #[test]
    fn dangerous_command_save_rotation_cp_is_silent() {
        // The strongswan-ipsec %preun shape: flags, a backslash
        // continuation, and the destination on the next line.
        let script = "if test -s /etc/ipsec.secrets.rpmsave ; then\n\tcp -p --backup=numbered /etc/ipsec.secrets.rpmsave \\\n\t                        /etc/ipsec.secrets.rpmsave.old\nfi\n";
        let found = check().check_scriptlet("/bin/sh", script, "%preun", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "dangerous-command-in-%preun")
        );
    }

    #[test]
    fn dangerous_command_save_rotation_other_shapes_still_fire() {
        for (script, verb) in [
            // Restore to the live path.
            ("mv /etc/foo.rpmsave /etc/foo", "mv"),
            // Backup to `.rpmsave` is credited by the backup-direction
            // rule, so it is not a still-firing rotation shape here.
            // Destination is not the source plus `.old`.
            ("mv /etc/foo.rpmsave /etc/bar.rpmsave.old", "mv"),
            // A different verb entirely.
            ("rm -f /etc/foo.rpmsave.old", "rm"),
            // The rotation is not the first dangerous command.
            (
                "rm -rf /foo; mv /etc/foo.rpmsave /etc/foo.rpmsave.old",
                "rm",
            ),
            // Multi-operand move: not a two-operand rotation.
            ("mv /etc/foo.rpmsave /etc/foo.rpmsave.old /etc/spare/", "mv"),
            // The cp firing shapes: wrong destination and
            // multi-operand, mirroring the mv shapes above.
            ("cp /etc/foo.rpmsave /etc/bar.rpmsave.old", "cp"),
            ("cp /etc/foo.rpmsave /etc/foo.rpmsave.old /etc/spare/", "cp"),
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%pre", &[], &[]);
            assert!(
                found.iter().any(|(l, f, d)| *l == Level::Warning
                    && f == "dangerous-command-in-%pre"
                    && d == &vec![verb.to_string()]),
                "shape went silent: {script}"
            );
        }
    }

    #[test]
    fn dangerous_command_rotation_then_dangerous_still_fires() {
        // Every match is evaluated: a credited rotation first must
        // not hide a genuine dangerous command later.
        let script = "mv /etc/foo.rpmsave /etc/foo.rpmsave.old; rm -rf /bar\n";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Warning
            && f == "dangerous-command-in-%post"
            && d == &vec!["rm".to_string()]));
    }

    #[test]
    fn dangerous_command_rotation_posttrans_is_silent() {
        // The rotation census counts one %posttrans row: the credit
        // carries no phase gate, so the %posttrans rotation stays
        // quiet — while a genuine command in %posttrans still fires,
        // proving the scan runs for the phase.
        let script = "mv /etc/foo.rpmsave /etc/foo.rpmsave.old\n";
        let found = check().check_scriptlet("/bin/sh", script, "%posttrans", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "dangerous-command-in-%posttrans"),
            "posttrans rotation must stay silent: {found:?}"
        );
        let found = check().check_scriptlet("/bin/sh", "rm -rf /bar\n", "%posttrans", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Warning
            && f == "dangerous-command-in-%posttrans"
            && d == &vec!["rm".to_string()]));
    }

    #[test]
    fn dangerous_command_rotation_verb_gate_still_fires() {
        // The rotation rule gates to mv/cp: a rotation-shaped ln
        // (matched by the dangerous regex) still fires.
        let script = "ln /etc/foo.rpmsave /etc/foo.rpmsave.old\n";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Warning
            && f == "dangerous-command-in-%post"
            && d == &vec!["ln".to_string()]));
    }

    #[test]
    fn dangerous_command_rotation_target_directory_still_fires() {
        // A target-directory move is a move into a directory, never
        // a rotation aside-step — including the attached forms,
        // where the old flag-skip left exactly the rotation shape.
        for script in [
            "mv --target-directory=/tmp/dir /etc/foo.rpmsave /etc/foo.rpmsave.old\n",
            "mv -t/tmp/dir /etc/foo.rpmsave /etc/foo.rpmsave.old\n",
            "mv --target-directory /tmp/dir /etc/foo.rpmsave /etc/foo.rpmsave.old\n",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found.iter().any(|(l, f, d)| *l == Level::Warning
                    && f == "dangerous-command-in-%post"
                    && d == &vec!["mv".to_string()]),
                "target-directory move must fire: {script}"
            );
        }
        // The separate `-t` form at the rotation-function level:
        // the old flag-skip read it as the rotation operands.
        assert!(!PostCheck::is_rotation(
            "mv -t /etc/foo.rpmsave /etc/foo.rpmsave.old",
            "mv",
            2
        ));
        // The bundled form likewise: the old flag-skip read the
        // bundle as a plain flag and left exactly the rotation
        // shape, silencing a move into a directory.
        assert!(!PostCheck::is_rotation(
            "mv -pt /etc/foo.rpmsave /etc/foo.rpmsave.old",
            "mv",
            2
        ));
        // At scriptlet level the live target isolates the rotation
        // fail-closed: a backup-named target would instead go quiet
        // through the backup credit, exactly as the separate -t
        // form does.
        let found = check().check_scriptlet(
            "/bin/sh",
            "mv -pt /tmp/dir /etc/foo.rpmsave /etc/foo.rpmsave.old\n",
            "%post",
            &[],
            &[],
        );
        assert!(
            found.iter().any(|(l, f, d)| *l == Level::Warning
                && f == "dangerous-command-in-%post"
                && d == &vec!["mv".to_string()]),
            "bundled -t rotation shape went silent"
        );
    }

    #[test]
    fn rotation_operand_count_and_terminator_shapes() {
        // 1-operand and 0-operand shapes never credit; `--` ends
        // the flags and is itself skipped, so a two-operand shape
        // after `--` still credits; a lone `-` is an operand, so it
        // breaks the two-operand shape.
        assert!(!PostCheck::is_rotation("mv /etc/foo.rpmsave", "mv", 2));
        assert!(!PostCheck::is_rotation("mv", "mv", 2));
        assert!(PostCheck::is_rotation(
            "mv -- /etc/foo.rpmsave /etc/foo.rpmsave.old",
            "mv",
            2
        ));
        assert!(!PostCheck::is_rotation(
            "mv - /etc/foo.rpmsave /etc/foo.rpmsave.old",
            "mv",
            2
        ));
    }

    #[test]
    fn dangerous_command_save_rotation_glob_still_fires() {
        // A glob operand is not operand-exact: each of these matched
        // the rotation shape before the glob guard and stayed silent.
        for (script, verb) in [
            ("mv /etc/*.rpmsave /etc/*.rpmsave.old\n", "mv"),
            ("mv \"/etc/*.rpmsave\" \"/etc/*.rpmsave.old\"\n", "mv"),
            ("mv /etc/?.rpmsave /etc/?.rpmsave.old\n", "mv"),
            ("mv /etc/[a].rpmsave /etc/[a].rpmsave.old\n", "mv"),
            ("cp /etc/*.rpmsave /etc/*.rpmsave.old\n", "cp"),
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%pre", &[], &[]);
            assert!(
                found.iter().any(|(l, f, d)| *l == Level::Warning
                    && f == "dangerous-command-in-%pre"
                    && d == &vec![verb.to_string()]),
                "glob rotation went silent: {script}"
            );
        }
    }

    #[test]
    fn dangerous_command_after_backup_still_fires() {
        let script = "cp /etc/foo /etc/foo.rpmsave; rm -rf /bar\n";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Warning
            && f == "dangerous-command-in-%post"
            && d == &vec!["rm".to_string()]));
    }

    #[test]
    fn dangerous_command_same_verb_masking_still_fires() {
        // Same-verb masking: a backup-direction cp goes quiet, but
        // a genuine cp in the same section keeps the finding firing
        // (contrast the other-verb shape in
        // dangerous_command_after_backup_still_fires, where the
        // finding names the genuine rm).
        let script = "cp /etc/foo /etc/foo.rpmsave; cp /etc/bar /etc/baz\n";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Warning
            && f == "dangerous-command-in-%post"
            && d == &vec!["cp".to_string()]));
    }

    #[test]
    fn dangerous_command_single_operand_cp_still_fires() {
        for script in ["cp /etc/foo.rpmsave\n", "cp -t /etc/foo.rpmsave\n"] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                found.iter().any(|(l, f, d)| *l == Level::Warning
                    && f == "dangerous-command-in-%post"
                    && d == &vec!["cp".to_string()]),
                "single-operand cp went silent: {script}"
            );
        }
    }

    #[test]
    fn dangerous_command_attached_target_dir() {
        // Attached `-tDIR` is a real target directory: a backup
        // destination stays silent, a live destination still fires.
        let found = check().check_scriptlet(
            "/bin/sh",
            "cp -t/etc/foo.rpmsave /etc/foo\n",
            "%post",
            &[],
            &[],
        );
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "dangerous-command-in-%post"),
            "attached -t backup destination fired"
        );
        let found = check().check_scriptlet(
            "/bin/sh",
            "cp -t/etc/live /etc/foo.rpmsave\n",
            "%post",
            &[],
            &[],
        );
        assert!(
            found.iter().any(|(l, f, d)| *l == Level::Warning
                && f == "dangerous-command-in-%post"
                && d == &vec!["cp".to_string()]),
            "attached -t live destination went silent"
        );
        // Bundled `-t`: the first `t` not consumed by `-S` is the
        // target flag, so a live target still fires even though the
        // trailing name is a backup name.
        let found = check().check_scriptlet(
            "/bin/sh",
            "cp -pt /live /etc/foo.rpmsave\n",
            "%post",
            &[],
            &[],
        );
        assert!(
            found.iter().any(|(l, f, d)| *l == Level::Warning
                && f == "dangerous-command-in-%post"
                && d == &vec!["cp".to_string()]),
            "bundled -t live destination went silent"
        );
        // `-S` consumes the `t`: no target flag, so the backup
        // destination stays silent, as does a trailing `-S` whose
        // suffix argument is the next token.
        for script in [
            "cp -St /live /etc/foo.rpmsave\n",
            "cp -pS .bak /live /etc/foo.rpmsave\n",
        ] {
            let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
            assert!(
                !found
                    .iter()
                    .any(|(_, f, _)| f == "dangerous-command-in-%post"),
                "S-consumed bundle fired: {script}"
            );
        }
    }

    #[test]
    fn dangerous_command_space_separated_fd_still_fires() {
        // A space-separated digit before `>` is a positional operand
        // (a file to act on), not the redirection's file descriptor;
        // only an attached digit (`2>`) is dropped as an fd.
        let found = check().check_scriptlet(
            "/bin/sh",
            "rm /etc/foo.rpmsave 2 > /dev/null\n",
            "%post",
            &[],
            &[],
        );
        assert!(
            found.iter().any(|(l, f, d)| *l == Level::Warning
                && f == "dangerous-command-in-%post"
                && d == &vec!["rm".to_string()]),
            "space-separated fd went silent"
        );
        let found = check().check_scriptlet(
            "/bin/sh",
            "rm /etc/foo.rpmsave 2>/dev/null\n",
            "%post",
            &[],
            &[],
        );
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "dangerous-command-in-%post"),
            "attached fd fired"
        );
    }

    #[test]
    fn dangerous_command_bare_verb_newline_does_not_take_next_line() {
        // A bare verb at end of line is not a command with operands
        // from the next line: the next line's own verb fires instead.
        let found = check().check_scriptlet("/bin/sh", "cp\nrm -rf /foo\n", "%post", &[], &[]);
        assert!(
            found.iter().any(|(l, f, d)| *l == Level::Warning
                && f == "dangerous-command-in-%post"
                && d == &vec!["rm".to_string()]),
            "bare verb swallowed the next line: {found:?}"
        );
        assert!(
            !found.iter().any(|(l, f, d)| *l == Level::Warning
                && f == "dangerous-command-in-%post"
                && d == &vec!["cp".to_string()]),
            "bare verb fired as cp: {found:?}"
        );
    }

    #[test]
    fn dangerous_command_backslash_continuation_still_joins() {
        let script = "cp -p /etc/foo \\\n/etc/foo.rpmsave\n";
        let found = check().check_scriptlet("/bin/sh", script, "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "dangerous-command-in-%post"),
            "backslash continuation broke backup credit"
        );
    }

    #[test]
    fn logical_line_after_applies_double_quote_escape_set() {
        // Inside double quotes the shell escape set applies: a
        // backslash is kept except before `$`, backtick, `"`,
        // `\` and newline (a backslash-newline still joins).
        assert_eq!(
            PostCheck::logical_line_after("cp \"a\\\"b\" /etc/x\n", 3),
            "\"a\"b\" /etc/x"
        );
        assert_eq!(
            PostCheck::logical_line_after("cp \"a\\b\" /etc/x\n", 3),
            "\"a\\b\" /etc/x"
        );
        assert_eq!(
            PostCheck::logical_line_after("cp \"a\\$b\" /etc/x\n", 3),
            "\"a$b\" /etc/x"
        );
        assert_eq!(
            PostCheck::logical_line_after("cp \"a\\\\b\" /etc/x\n", 3),
            "\"a\\b\" /etc/x"
        );
        assert_eq!(
            PostCheck::logical_line_after("cp \"a\\`b\" /etc/x\n", 3),
            "\"a`b\" /etc/x"
        );
        // A backslash-newline inside quotes still joins.
        assert_eq!(
            PostCheck::logical_line_after("cp \"a\\\n b\" /etc/x\n", 3),
            "\"a b\" /etc/x"
        );
    }

    #[test]
    fn split_operands_posix_double_quote_escapes() {
        // POSIX: inside double quotes a backslash is special only
        // before `$`, backtick, `"`, `\` and newline.
        assert_eq!(
            PostCheck::split_operands("\"a\\\"b\""),
            vec!["a\"b".to_string()]
        );
        assert_eq!(
            PostCheck::split_operands("\"a\\b\""),
            vec!["a\\b".to_string()]
        );
        assert_eq!(
            PostCheck::split_operands("\"a\\$b\""),
            vec!["a$b".to_string()]
        );
        assert_eq!(
            PostCheck::split_operands("\"a\\\\b\""),
            vec!["a\\b".to_string()]
        );
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
