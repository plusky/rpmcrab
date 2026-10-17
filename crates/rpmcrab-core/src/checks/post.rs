//! `PostCheck` — scriptlet content checks.
//!
//! Ported from `rpmlint/checks/PostCheck.py`. The regex-based findings are
//! ported natively; the `sh -n` / `perl -wc` syntax checks shell out when
//! the interpreter exists and are skipped otherwise.

use std::process::Command;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
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
    /// a predictable path and does not fire. Ledgered in
    /// tests/parity/divergences.toml.
    fn uses_tmp_literal(script: &str) -> bool {
        script.lines().any(|line| {
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
        })
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
                r"(?m)(^|[;`|]|&&|\$\()\s*(?:then\s+|do\s+|else\s+)?(?:\S*/)?insserv\b([^\n;|&]*)",
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
            Regex::new(
                r"(?m)(^|[;`|]|&&|\$\()\s*(?:then\s+|do\s+|else\s+)?(?:\S*/)?systemctl\s+(?:--?\S+\s+)*(reload-or-restart|reenable|enable|start|restart)\b",
            )
            .expect("static regex")
        })
    }
    fn chkconfig_regex() -> &'static Regex {
        static CHKCONFIG_REGEX: OnceLock<Regex> = OnceLock::new();
        CHKCONFIG_REGEX.get_or_init(|| {
            Regex::new(
                r"(?m)(^|[;`|]|&&|\$\()\s*(?:then\s+|do\s+|else\s+)?(?:\S*/)?chkconfig\b([^\n;|&]*)",
            )
            .expect("static regex")
        })
    }

    /// Scriptlet text with heredoc bodies blanked. Text a scriptlet
    /// writes out (an update message, a generated file) is not executed,
    /// so a command named inside it is not an invocation.
    fn without_heredoc_bodies(script: &str) -> String {
        // Parse the delimiter following a `<<` at byte offset `at`.
        // Handles the plain (`<<EOF`), quoted (`<<'EOF'`, `<<"EOF"`),
        // escaped (`<<\EOF`) and ANSI-C-quoted (`<<$'EOF'`) forms.
        fn delimiter_after(line: &str, at: usize) -> Option<String> {
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
            let rest = rest.strip_prefix('-').unwrap_or(rest);
            let rest = rest.trim_start();
            if let Some(quoted) = rest.strip_prefix('$') {
                // `$'EOF'` / `$"EOF"`: the delimiter is the quoted text.
                let q = quoted.chars().next()?;
                if q != '\'' && q != '"' {
                    return None;
                }
                return quoted_word(&quoted[q.len_utf8()..], q);
            }
            if let Some(escaped) = rest.strip_prefix('\\') {
                // `\\EOF`: a backslash quotes the next character into
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
                return finish(word);
            }
            if let Some(quoted) = rest
                .strip_prefix('\'')
                .map(|s| (s, '\''))
                .or_else(|| rest.strip_prefix('"').map(|s| (s, '"')))
            {
                return quoted_word(quoted.0, quoted.1);
            }
            finish(rest.chars().take_while(|c| !is_stop(*c)).collect())
        }
        // Delimiters introduced by unquoted `<<` operators on `line`.
        // A `<<` inside single/double quotes, inside a `#` comment, or
        // inside a `$((...))` arithmetic expansion (where it is the
        // left-shift operator) is not a heredoc operator, and `<<<`
        // is a herestring, not a heredoc.
        fn delimiters_in_line(line: &str) -> Vec<String> {
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
        let lines: Vec<&str> = script.lines().collect();
        let mut pending: Vec<String> = Vec::new();
        let mut out: Vec<&str> = Vec::new();
        for (idx, line) in lines.iter().enumerate() {
            if let Some(delim) = pending.first() {
                if line.trim() == delim.as_str() {
                    pending.remove(0);
                    out.push(line);
                } else {
                    out.push("");
                }
                continue;
            }
            // Only blank when a terminator actually appears later in
            // the scriptlet: a false opener otherwise blanks the rest
            // of the scriptlet and hides genuine activations.
            for delim in delimiters_in_line(line) {
                if lines[idx + 1..].iter().any(|l| l.trim() == delim) {
                    pending.push(delim);
                }
            }
            out.push(line);
        }
        out.join("\n")
    }

    /// A scriptlet line with comments removed and quoted-string
    /// contents blanked to spaces, for command matching: text inside
    /// a comment or a quoted string never executes, so a shell
    /// separator there does not put a following command name at
    /// command position. Command substitutions are the exception --
    /// `$(...)` and backticks execute even inside double quotes, so
    /// their contents stay live. The quote characters are kept; only
    /// the contents go. Scanned per line, like `delimiters_in_line`.
    fn code_only(script: &str) -> String {
        #[derive(Clone, Copy)]
        enum Frame {
            // Parenthesis depth within a `$(...)` frame.
            Subst(usize),
            // Parenthesis depth within a backtick frame.
            Backtick(usize),
            Single,
            Double,
        }
        fn code_line(line: &str) -> String {
            let bytes = line.as_bytes();
            let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
            let mut stack: Vec<Frame> = Vec::new();
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
                                out.push(bytes[i + 1]);
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
                            // (the `delimiters_in_line` rule).
                            if i == 0
                                || matches!(
                                    bytes[i - 1] as char,
                                    ' ' | '\t' | ';' | '|' | '&' | '('
                                )
                            {
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
        script.lines().map(code_line).collect::<Vec<_>>().join("\n")
    }

    /// Daemon activations in a scriptlet: an `insserv` invocation that
    /// installs an init script (the removal form, `-r`/`--remove`,
    /// deactivates and is not an activation), each distinct
    /// activating `systemctl` verb form, and the `chkconfig` enable
    /// forms (`chkconfig <name> on`, `chkconfig --add <name>` and
    /// `chkconfig --level <levels> <name> on`), in first-seen order.
    /// `chkconfig <name> off` and `chkconfig --del`/`--remove <name>`
    /// deactivate or remove and stay quiet, like the insserv removal
    /// form. Matching runs on the heredoc-blanked, comment-stripped,
    /// quote-blanked text (`code_only`) and is command-position only
    /// (start of line or after a command separator), so comments,
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
        for caps in Self::systemctl_regex().captures_iter(&text).flatten() {
            if let Some(verb) = caps.get(2) {
                let detail = format!("systemctl {}", verb.as_str());
                if !out.contains(&detail) {
                    out.push(detail);
                }
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
    fn no_prereq_on_chkfontpath_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", " chkfontpath --add /x", "%post", &[], &[]);
        assert!(found.iter().any(|(l, f, d)| *l == Level::Error
            && f == "no-prereq-on"
            && d == &vec!["chkfontpath".to_string()]));
    }
}
