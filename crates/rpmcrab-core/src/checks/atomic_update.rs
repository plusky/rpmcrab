//! `AtomicUpdateCheck` — files must live inside the snapshot (`/etc`, `/usr`).
//!
//! Ported from `rpmlint/checks/AtomicUpdateCheck.py`. Two findings:
//! `dir-or-file-outside-snapshot` (E) and `ghost-outside-snapshot` (W).
//! A third finding, `scriptlet-writes-outside-snapshot` (W), has no
//! reference counterpart (issue #708, ledgered in
//! `tests/parity/divergences.toml`): the payload findings cannot see the
//! writes an install scriptlet performs, and on a transactional-update
//! system those writes land outside the snapshot being installed, so
//! they take effect immediately and vanish or turn inconsistent on a
//! rollback; the packaging guidelines require them deferred to the
//! first boot of the new snapshot instead.
//!
//! Directory entries are exempt from the error: a shipped directory
//! carries no payload that a snapshot switch could lose or leave
//! inconsistent, and the transactional-update guide allows directories
//! anywhere. The reference makes no dir/file distinction, so the
//! exemption is a ledgered fix-and-diverge (issue #711). Symlinks are
//! not directories and still fire.
//!
//! This file hosts the transactional-update family's predicates. It also
//! carries `usr_etc_conffile`, the predicate behind the crab-only
//! `usr-etc-file-marked-as-conffile` warning emitted by
//! `ConfigFilesCheck`: under the UsrEtc layout `/usr/etc` holds vendor
//! defaults, so no file there may be marked `%config`.

use super::shared::scriptlets_for;
use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::{PkgFile, is_dir};

pub struct AtomicUpdateCheck {
    check_ghosts: bool,
    allowed_dirs: Vec<String>,
    disallowed_subdirs: Vec<String>,
}

/// The reference indexes `config.configuration[...]` directly, so a missing
/// key raises `KeyError`; fail just as loudly instead of silently defaulting
/// (an empty allowed-dirs list would flag every file in the package).
fn required<'a>(cfg: &'a toml::Table, key: &str) -> &'a toml::Value {
    cfg.get(key)
        .unwrap_or_else(|| panic!("AtomicUpdateCheck: required config key '{key}' is missing"))
}

fn str_list(value: &toml::Value, key: &str) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| {
            panic!("AtomicUpdateCheck: config key '{key}' must be a list of strings")
        })
        .iter()
        .map(|element| {
            element.as_str().unwrap_or_else(|| {
                panic!("AtomicUpdateCheck: config key '{key}' must be a list of strings")
            })
        })
        .map(String::from)
        .collect()
}

impl AtomicUpdateCheck {
    pub fn new(config: &Config) -> Self {
        let cfg = &config.configuration;
        Self {
            check_ghosts: required(cfg, "AtomicCheckGhosts")
                .as_bool()
                .unwrap_or_else(|| {
                    panic!("AtomicUpdateCheck: config key 'AtomicCheckGhosts' must be a boolean")
                }),
            allowed_dirs: str_list(required(cfg, "AtomicAllowedDirs"), "AtomicAllowedDirs"),
            disallowed_subdirs: str_list(
                required(cfg, "AtomicDisallowedSubdirs"),
                "AtomicDisallowedSubdirs",
            ),
        }
    }

    /// True when `path` is inside an allowed dir and not in a disallowed subdir.
    fn path_allowed(&self, path: &str) -> bool {
        let allowed = self.allowed_dirs.iter().any(|d| path.starts_with(d));
        let disallowed = self.disallowed_subdirs.iter().any(|d| path.starts_with(d));
        allowed && !disallowed
    }

    /// True when a scriptlet write target lies outside the snapshot.
    /// A bare prefix names the directory itself (`mkdir /var`,
    /// `touch /run`), which a payload path never does, so the prefix
    /// test treats the bare form as under itself; runtime filesystems
    /// (TRANSIENT_PREFIXES) are never outside.
    fn scriptlet_target_outside(&self, path: &str) -> bool {
        let under = |prefix: &str| path == prefix.trim_end_matches('/') || path.starts_with(prefix);
        if TRANSIENT_PREFIXES.iter().any(|p| under(p))
            || SANCTIONED_PREFIXES.iter().any(|p| under(p))
        {
            return false;
        }
        let allowed = self.allowed_dirs.iter().any(|d| under(d));
        let disallowed = self.disallowed_subdirs.iter().any(|d| under(d));
        !(allowed && !disallowed)
    }
}

/// True when `file` is a shipped `/usr/etc` file marked `%config`.
///
/// Under the UsrEtc layout `/usr/etc` ships vendor defaults and
/// administrator configuration lives in `/etc`; the `%config` mark makes
/// rpm preserve local edits to the vendor default across updates, which
/// fights the split. Every `%config` variant counts, but `%ghost` entries
/// ship no vendor default and directory entries never get
/// `.rpmnew`/`.rpmsave` treatment, so neither fires — the same scope as
/// the sibling `shlib-policy-etc-payload` rule.
pub(crate) fn usr_etc_conffile(file: &PkgFile) -> bool {
    file.is_config()
        && !file.is_ghost()
        && !is_dir(file.mode)
        && (file.name == "/usr/etc" || file.name.starts_with("/usr/etc/"))
}

impl Check for AtomicUpdateCheck {
    fn name(&self) -> &'static str {
        "AtomicUpdateCheck"
    }

    fn check(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }
        for pkgfile in &pkg.files {
            let name = pkgfile.name.as_str();
            if pkgfile.is_ghost() {
                continue;
            }
            // Directories carry no payload; the transactional-update
            // guide exempts them wherever they are shipped (issue #711).
            // A symlink is not a directory and still fires below.
            if is_dir(pkgfile.mode) {
                continue;
            }
            if !self.path_allowed(name) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "dir-or-file-outside-snapshot",
                    &[name],
                );
            }
        }
        if self.check_ghosts {
            for ghost in &pkg.ghost_files {
                if !self.path_allowed(ghost) {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "ghost-outside-snapshot",
                        &[ghost.as_str()],
                    );
                }
            }
        }
        for slot in scriptlets_for(pkg, &SCRIPTLET_LABELS) {
            if !is_shell_prog(&slot.prog) {
                continue;
            }
            for target in scan_scriptlet(&slot.body) {
                if self.scriptlet_target_outside(&target) {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "scriptlet-writes-outside-snapshot",
                        &[slot.label, &target],
                    );
                }
            }
        }
    }
}

/// The scriptlet slots this check scans: the install scriptlets that run
/// inside the update transaction. Trigger and verify scriptlets are out of
/// scope: triggers also run for other packages' changes, and verify
/// scriptlets do not install anything.
const SCRIPTLET_LABELS: [&str; 6] = [
    "%pre",
    "%post",
    "%preun",
    "%postun",
    "%pretrans",
    "%posttrans",
];

/// Runtime filesystems and their legacy spellings (`/var/run` and
/// `/var/lock` are the pre-systemd names of `/run` and `/run/lock`, and
/// `/var/tmp` is the tmpfiles-managed part of `/var`). Paths here are
/// not snapshot subvolumes at all, so a write to them is runtime state
/// by definition, not a snapshot escape.
/// Corpus evidence (issue #708 measurement): the apache2 family touches
/// `/var/run/httpd.restart.flag` from %postun/%posttrans as its restart
/// hand-off; flagging that spelling of `/run` would be a false positive.
const TRANSIENT_PREFIXES: &[&str] = &[
    "/dev/",
    "/proc/",
    "/sys/",
    "/run/",
    "/tmp/",
    "/var/run/",
    "/var/lock/",
    "/var/tmp/",
];

/// The distro's deferred-notification spool: files dropped in
/// `/var/adm/update-messages/` are displayed to the user by the updater
/// after the transaction. Dropping a notice there is the sanctioned way
/// to communicate across an update, not a state change escaping the
/// snapshot. Corpus evidence (issue #708 measurement): every firer under
/// `/var/adm/` outside this spool is a genuine state write, and every
/// spool write sampled is a notice file. The sibling
/// `/var/adm/update-scripts/` is NOT carved out: the corpus shows it
/// used as scriptlet scratch state within one transaction (cyrus-sasl
/// generates, executes and deletes a migration script there), which is
/// exactly the pattern this finding exists to catch.
const SANCTIONED_PREFIXES: &[&str] = &["/var/adm/update-messages/"];

/// Write commands whose every path argument is a target.
const WRITE_EVERY_ARG: &[&str] = &["mkdir", "touch", "rm", "rmdir", "tee"];
/// Write commands whose target is the last path argument (the rest are
/// sources).
const WRITE_LAST_ARG: &[&str] = &["cp", "mv", "ln"];
/// Shell keywords that leave the next word in command position.
const SHELL_KEYWORDS: &[&str] = &[
    "if", "then", "else", "elif", "while", "until", "do", "!", "time",
];

/// True when the interpreter string names a POSIX shell. An empty string
/// (the header carries no `-p`) means rpm's default, `/bin/sh`.
/// Non-shell scriptlets (lua, perl, python, prog-only `/sbin/ldconfig`,
/// ...) are not scanned: the tokeniser below speaks shell, and judging
/// another language's text by shell rules would invent findings.
fn is_shell_prog(prog: &str) -> bool {
    let prog = prog.trim();
    if prog.is_empty() || prog == "(none)" {
        return true;
    }
    let first = prog.split_whitespace().next().unwrap_or("");
    let base = first.rsplit('/').next().unwrap_or(first);
    base == "sh" || base == "bash"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokKind {
    Word,
    Op,
    Sep,
}

#[derive(Debug, Clone)]
struct Tok {
    kind: TokKind,
    text: String,
    /// The word contains an unquoted `$`, backtick or `%{`/`%(`: its value
    /// is computed at install time, so it is not a literal path.
    dynamic: bool,
}

/// Blank heredoc bodies: their lines are data for the command reading
/// them, not commands. The `<<DELIM` line itself is kept.
fn blank_heredocs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut delim: Option<String> = None;
    for line in text.split('\n') {
        if let Some(d) = &delim {
            if line.trim() == d || line.trim_start_matches('\t') == d.as_str() {
                delim = None;
            }
            out.push('\n');
            continue;
        }
        out.push_str(line);
        out.push('\n');
        // Find a heredoc opener: `<<` (not `<<<`), optional `-`, optional
        // quote, then the delimiter word.
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i + 1 < chars.len() {
            if chars[i] == '<' && chars[i + 1] == '<' {
                if i + 2 < chars.len() && chars[i + 2] == '<' {
                    break; // herestring, no body follows
                }
                let mut j = i + 2;
                if j < chars.len() && chars[j] == '-' {
                    j += 1;
                }
                while j < chars.len() && (chars[j] == ' ' || chars[j] == '\t') {
                    j += 1;
                }
                if j < chars.len() && (chars[j] == '\'' || chars[j] == '"') {
                    j += 1;
                }
                let start = j;
                while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                if j > start {
                    delim = Some(chars[start..j].iter().collect());
                }
                break;
            }
            i += 1;
        }
    }
    out
}

/// A small shell tokeniser: words (quotes removed, contents kept, as the
/// shell builds them), redirection operators and command separators.
/// This is deliberately not a shell parser: it recognises exactly the
/// constructs the scan below matches on, nothing more.
fn tokenize(text: &str) -> Vec<Tok> {
    let text = blank_heredocs(text);
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut toks = Vec::new();
    let mut word: Vec<char> = Vec::new();
    let mut dynamic = false;
    let mut in_word = false;
    let mut i = 0;

    macro_rules! flush {
        () => {
            if in_word {
                toks.push(Tok {
                    kind: TokKind::Word,
                    text: word.iter().collect(),
                    dynamic,
                });
                word = Vec::new();
                dynamic = false;
                in_word = false;
            }
        };
    }

    #[derive(PartialEq, Clone, Copy)]
    enum Quote {
        None,
        Single,
        Double,
    }
    let mut quote = Quote::None;

    while i < n {
        let c = chars[i];
        match quote {
            Quote::Single => {
                if c == '\'' {
                    quote = Quote::None;
                } else {
                    word.push(c);
                }
                i += 1;
                continue;
            }
            Quote::Double => {
                if c == '"' {
                    quote = Quote::None;
                    i += 1;
                    continue;
                }
                if c == '\\' && i + 1 < n && matches!(chars[i + 1], '"' | '$' | '`' | '\\') {
                    word.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                if c == '$' || c == '`' {
                    dynamic = true;
                }
                word.push(c);
                i += 1;
                continue;
            }
            Quote::None => {}
        }
        match c {
            '\'' => {
                quote = Quote::Single;
                in_word = true;
                i += 1;
            }
            '"' => {
                quote = Quote::Double;
                in_word = true;
                i += 1;
            }
            '\\' if i + 1 < n => {
                word.push(chars[i + 1]);
                in_word = true;
                i += 2;
            }
            '#' if !in_word => {
                while i < n && chars[i] != '\n' {
                    i += 1;
                }
            }
            '$' | '`' => {
                dynamic = true;
                word.push(c);
                in_word = true;
                i += 1;
            }
            '%' if i + 1 < n && (chars[i + 1] == '{' || chars[i + 1] == '(') => {
                dynamic = true;
                word.push(c);
                in_word = true;
                i += 1;
            }
            ' ' | '\t' | '\r' => {
                flush!();
                i += 1;
            }
            '\n' | ';' => {
                flush!();
                toks.push(Tok {
                    kind: TokKind::Sep,
                    text: ";".to_string(),
                    dynamic: false,
                });
                i += 1;
            }
            '|' => {
                flush!();
                if i + 1 < n && chars[i + 1] == '|' {
                    toks.push(Tok {
                        kind: TokKind::Sep,
                        text: "||".to_string(),
                        dynamic: false,
                    });
                    i += 2;
                } else {
                    toks.push(Tok {
                        kind: TokKind::Sep,
                        text: "|".to_string(),
                        dynamic: false,
                    });
                    i += 1;
                }
            }
            '&' => {
                flush!();
                if i + 1 < n && chars[i + 1] == '&' {
                    toks.push(Tok {
                        kind: TokKind::Sep,
                        text: "&&".to_string(),
                        dynamic: false,
                    });
                    i += 2;
                } else if i + 1 < n && chars[i + 1] == '>' {
                    toks.push(Tok {
                        kind: TokKind::Op,
                        text: "&>".to_string(),
                        dynamic: false,
                    });
                    i += 2;
                } else {
                    toks.push(Tok {
                        kind: TokKind::Sep,
                        text: "&".to_string(),
                        dynamic: false,
                    });
                    i += 1;
                }
            }
            '(' | ')' => {
                flush!();
                toks.push(Tok {
                    kind: TokKind::Sep,
                    text: c.to_string(),
                    dynamic: false,
                });
                i += 1;
            }
            '>' | '<' => {
                // An all-digits pending word is the fd of the redirect.
                let mut op = String::new();
                if in_word && word.iter().all(|d| d.is_ascii_digit()) {
                    op = word.iter().collect();
                    word = Vec::new();
                    dynamic = false;
                    in_word = false;
                } else {
                    flush!();
                }
                op.push(c);
                let mut j = i + 1;
                if j < n && chars[j] == c {
                    op.push(c);
                    j += 1;
                }
                if j < n && chars[j] == '&' {
                    op.push('&');
                    j += 1;
                }
                toks.push(Tok {
                    kind: TokKind::Op,
                    text: op,
                    dynamic: false,
                });
                i = j;
            }
            _ => {
                word.push(c);
                in_word = true;
                i += 1;
            }
        }
    }
    if in_word {
        toks.push(Tok {
            kind: TokKind::Word,
            text: word.iter().collect(),
            dynamic,
        });
    }
    toks
}

fn is_literal(tok: &Tok) -> bool {
    !tok.dynamic && !tok.text.contains("%{") && !tok.text.contains("%(")
}

/// An assignment word (`NAME=value`) in command position leaves the next
/// word in command position.
fn is_assignment(word: &str) -> bool {
    let mut chars = word.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    for c in chars {
        if c == '=' {
            return true;
        }
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
    }
    false
}

/// The literal absolute-path targets of the write constructs in one
/// scriptlet body, in first-seen order, de-duplicated. Two decidable
/// classes (issue #708):
///
/// - C1: a redirection operator whose target word is a literal absolute
///   path (`> /var/log/x`, `cat >> /srv/data/f`, `2> /var/log/err`).
/// - C2: a write command in command position with literal absolute path
///   arguments: `mkdir`/`touch`/`rm`/`rmdir`/`tee` (every path argument),
///   `cp`/`mv`/`ln` (the last path argument -- the rest are sources),
///   `install` (every path argument with `-d`, the last one without, the
///   `-t`/`--target-directory` directory in both modes), `dd` (its `of=`
///   argument).
///
/// Everything else is out of scope by construction: dynamic targets
/// (`$var`, `%{...}`), relative paths, read-only references, metadata
/// commands (`chmod`, `chown`), in-place editors (`sed -i`) and
/// tool-implied writes name no decidable literal target here.
fn scan_scriptlet(body: &str) -> Vec<String> {
    let toks = tokenize(body);
    let mut targets: Vec<String> = Vec::new();
    let mut push = |t: &str| {
        if !targets.iter().any(|x| x == t) {
            targets.push(t.to_string());
        }
    };
    let mut cmd_pos = true;
    let mut i = 0;
    while i < toks.len() {
        let tok = &toks[i];
        match tok.kind {
            TokKind::Sep => {
                cmd_pos = true;
                i += 1;
            }
            TokKind::Op => {
                // Only output redirects name a written file; an input
                // redirect (`< /var/lib/data`) reads its target.
                let core = tok.text.trim_start_matches(|c: char| c.is_ascii_digit());
                let output = core.starts_with('>') || core.starts_with("&>");
                if output && i + 1 < toks.len() && toks[i + 1].kind == TokKind::Word {
                    let w = &toks[i + 1];
                    if is_literal(w) && w.text.starts_with('/') {
                        push(&w.text);
                    }
                    i += 2;
                    cmd_pos = false;
                } else {
                    i += 1;
                }
            }
            TokKind::Word => {
                if !cmd_pos {
                    i += 1;
                    continue;
                }
                let base = tok.text.rsplit('/').next().unwrap_or(&tok.text);
                if SHELL_KEYWORDS.contains(&tok.text.as_str()) || is_assignment(&tok.text) {
                    i += 1;
                    continue;
                }
                let known = WRITE_EVERY_ARG.contains(&base)
                    || WRITE_LAST_ARG.contains(&base)
                    || base == "install"
                    || base == "dd";
                if !known {
                    cmd_pos = false;
                    i += 1;
                    continue;
                }
                // Gather argv (the consecutive words).
                let mut args: Vec<&Tok> = Vec::new();
                let mut j = i + 1;
                while j < toks.len() && toks[j].kind == TokKind::Word {
                    args.push(&toks[j]);
                    j += 1;
                }
                let plain: Vec<&&Tok> = args.iter().filter(|a| !a.text.starts_with('-')).collect();
                let mut cands: Vec<&Tok> = Vec::new();
                // `--target-directory=DIR` (install/cp/mv long form).
                for a in &args {
                    if let Some(dir) = a.text.strip_prefix("--target-directory=") {
                        let owned = Tok {
                            kind: TokKind::Word,
                            text: dir.to_string(),
                            dynamic: a.dynamic,
                        };
                        if is_literal(&owned) && owned.text.starts_with('/') {
                            push(&owned.text);
                        }
                    }
                }
                if WRITE_EVERY_ARG.contains(&base) {
                    cands.extend(plain.iter().copied());
                } else if WRITE_LAST_ARG.contains(&base) {
                    if let Some(last) = plain.last() {
                        cands.push(last);
                    }
                } else if base == "install" {
                    let dir_mode = args
                        .iter()
                        .any(|a| a.text == "-d" || a.text == "--directory");
                    // With `-t DIR` every operand is a source; the `-t`
                    // loop below names the directory itself.
                    let has_t = args.iter().any(|a| {
                        a.text == "-t"
                            || a.text == "--target-directory"
                            || a.text.starts_with("--target-directory=")
                    });
                    if dir_mode {
                        cands.extend(plain.iter().copied());
                    } else if !has_t && let Some(last) = plain.last() {
                        cands.push(last);
                    }
                    for (k, a) in args.iter().enumerate() {
                        if a.text == "-t"
                            && let Some(t) = args.get(k + 1)
                        {
                            cands.push(t);
                        }
                    }
                } else if base == "dd" {
                    for a in &args {
                        if let Some(of) = a.text.strip_prefix("of=")
                            && !a.dynamic
                            && of.starts_with('/')
                        {
                            push(of);
                        }
                    }
                }
                for tg in cands {
                    if is_literal(tg) && tg.text.starts_with('/') {
                        push(&tg.text);
                    }
                }
                i = j;
                cmd_pos = false;
            }
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::color::Color;
    use crate::pkg::pkgfile::{
        PkgFile, RPMFILE_CONFIG, RPMFILE_GHOST, RPMFILE_MISSINGOK, RPMFILE_NOREPLACE,
    };

    /// `Pkg` is header-backed with no test constructor, so open a tiny fixture
    /// and rewrite the public fields the check reads.
    fn fixture_pkg() -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.name = "atomic-test".to_string();
        pkg.arch = "x86_64".to_string();
        pkg
    }

    fn regular(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            ..Default::default()
        }
    }

    fn ghost(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            flags: RPMFILE_GHOST,
            ..Default::default()
        }
    }

    fn dir_entry(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o040755,
            ..Default::default()
        }
    }

    fn symlink(name: &str, target: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o120777,
            linkto: target.to_string(),
            ..Default::default()
        }
    }

    fn check_with(allowed: &[&str], disallowed: &[&str], ghosts: bool) -> AtomicUpdateCheck {
        let mut table = toml::Table::new();
        table.insert(
            "AtomicAllowedDirs".to_string(),
            toml::Value::Array(
                allowed
                    .iter()
                    .map(|s| toml::Value::String(s.to_string()))
                    .collect(),
            ),
        );
        table.insert(
            "AtomicDisallowedSubdirs".to_string(),
            toml::Value::Array(
                disallowed
                    .iter()
                    .map(|s| toml::Value::String(s.to_string()))
                    .collect(),
            ),
        );
        table.insert(
            "AtomicCheckGhosts".to_string(),
            toml::Value::Boolean(ghosts),
        );
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        AtomicUpdateCheck::new(&config)
    }

    fn run(check: &mut AtomicUpdateCheck, pkg: &Pkg) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check(pkg, &config, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn allowed_path_passes() {
        let c = check_with(&["/usr", "/etc"], &[], false);
        assert!(c.path_allowed("/usr/bin/foo"));
        assert!(c.path_allowed("/etc/bar.conf"));
    }

    #[test]
    fn disallowed_path_fails() {
        let c = check_with(&["/usr", "/etc"], &[], false);
        assert!(!c.path_allowed("/var/lib/foo"));
        assert!(!c.path_allowed("/opt/bar"));
    }

    #[test]
    fn disallowed_subdir_fails() {
        let c = check_with(&["/usr"], &["/usr/local"], false);
        assert!(!c.path_allowed("/usr/local/bin/foo"));
        assert!(c.path_allowed("/usr/bin/foo"));
    }

    #[test]
    fn files_outside_snapshot_are_errors() {
        let mut pkg = fixture_pkg();
        pkg.files = vec![
            regular("/usr/bin/ok"),
            regular("/etc/ok.conf"),
            regular("/var/lib/outside"),
            regular("/usr/local/bin/disallowed"),
        ];
        let mut check = check_with(&["/usr", "/etc"], &["/usr/local"], false);
        let results = run(&mut check, &pkg);
        assert_eq!(results.len(), 2);
        for (name, line) in &results {
            assert_eq!(name, "dir-or-file-outside-snapshot");
            assert!(line.contains(": E: "), "level: {line}");
        }
        assert!(
            results[0].1.contains("/var/lib/outside"),
            "{}",
            results[0].1
        );
        assert!(
            results[1].1.contains("/usr/local/bin/disallowed"),
            "{}",
            results[1].1
        );
    }

    #[test]
    fn directories_outside_snapshot_are_exempt() {
        // A shipped directory carries no payload, so it never fires --
        // wherever it sits, and whatever its name looks like. The
        // exemption keys on the entry type alone (issue #711).
        let mut pkg = fixture_pkg();
        pkg.files = vec![
            dir_entry("/var/lib/daemon"),
            dir_entry("/var/log/daemon"),
            dir_entry("/srv/www/htdocs"),
            // A directory whose name looks like a payload file.
            dir_entry("/var/lib/libpayload.so"),
            // Inside a disallowed subdir: still just a directory.
            dir_entry("/usr/local/share/tool"),
        ];
        let mut check = check_with(&["/usr", "/etc"], &["/usr/local"], false);
        assert!(run(&mut check, &pkg).is_empty());
    }

    #[test]
    fn directory_exemption_keeps_file_findings() {
        let mut pkg = fixture_pkg();
        pkg.files = vec![
            dir_entry("/var/lib/daemon"),
            regular("/var/lib/daemon/state.db"),
        ];
        let mut check = check_with(&["/usr", "/etc"], &[], false);
        let results = run(&mut check, &pkg);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "dir-or-file-outside-snapshot");
        assert!(
            results[0].1.contains("/var/lib/daemon/state.db"),
            "{}",
            results[0].1
        );
    }

    #[test]
    fn symlink_to_directory_outside_snapshot_still_fires() {
        // A symlink is not a directory (S_IFLNK, not S_IFDIR): it still
        // fires, even when its target is a directory. The /usr/lib link
        // is the near-miss: inside the snapshot, so quiet either way.
        let mut pkg = fixture_pkg();
        pkg.files = vec![
            symlink("/var/lib/current", "/var/lib/daemon"),
            symlink("/usr/lib/inside", "/usr/lib/real"),
        ];
        let mut check = check_with(&["/usr", "/etc"], &[], false);
        let results = run(&mut check, &pkg);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "dir-or-file-outside-snapshot");
        assert!(results[0].1.contains(": E: "), "level: {}", results[0].1);
        assert!(
            results[0].1.contains("/var/lib/current"),
            "{}",
            results[0].1
        );
    }

    #[test]
    fn ghost_directory_stays_on_the_ghost_path() {
        // A %ghost directory leaves the error loop as a ghost and is
        // reported, if at all, by the ghost loop: the directory
        // exemption neither promotes nor demotes it.
        let mut pkg = fixture_pkg();
        pkg.files = vec![PkgFile {
            name: "/var/cache/state".to_string(),
            mode: 0o040755,
            flags: RPMFILE_GHOST,
            ..Default::default()
        }];
        pkg.ghost_files = vec!["/var/cache/state".to_string()];
        let mut check = check_with(&["/usr", "/etc"], &[], true);
        let results = run(&mut check, &pkg);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "ghost-outside-snapshot");
        assert!(results[0].1.contains(": W: "), "level: {}", results[0].1);

        let mut pkg = fixture_pkg();
        pkg.files = vec![PkgFile {
            name: "/var/cache/state".to_string(),
            mode: 0o040755,
            flags: RPMFILE_GHOST,
            ..Default::default()
        }];
        pkg.ghost_files = vec!["/var/cache/state".to_string()];
        let mut check = check_with(&["/usr", "/etc"], &[], false);
        assert!(run(&mut check, &pkg).is_empty());
    }

    #[test]
    fn ghost_outside_snapshot_is_warning_when_enabled() {
        let mut pkg = fixture_pkg();
        pkg.files = vec![regular("/usr/bin/ok"), ghost("/var/cache/state")];
        pkg.ghost_files = vec!["/var/cache/state".to_string()];
        let mut check = check_with(&["/usr", "/etc"], &[], true);
        let results = run(&mut check, &pkg);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "ghost-outside-snapshot");
        assert!(results[0].1.contains(": W: "), "level: {}", results[0].1);
        assert!(
            results[0].1.contains("/var/cache/state"),
            "detail: {}",
            results[0].1
        );
    }

    #[test]
    fn ghosts_ignored_when_disabled() {
        let mut pkg = fixture_pkg();
        pkg.files = vec![regular("/usr/bin/ok"), ghost("/var/cache/state")];
        pkg.ghost_files = vec!["/var/cache/state".to_string()];
        let mut check = check_with(&["/usr", "/etc"], &[], false);
        assert!(run(&mut check, &pkg).is_empty());
    }

    #[test]
    fn ghost_inside_snapshot_is_quiet() {
        let mut pkg = fixture_pkg();
        pkg.files = vec![regular("/usr/bin/ok"), ghost("/etc/ghost.conf")];
        pkg.ghost_files = vec!["/etc/ghost.conf".to_string()];
        let mut check = check_with(&["/usr", "/etc"], &[], true);
        assert!(run(&mut check, &pkg).is_empty());
    }

    #[test]
    fn source_package_is_skipped() {
        let mut pkg = fixture_pkg();
        pkg.is_source = true;
        pkg.files = vec![regular("/var/lib/outside")];
        let mut check = check_with(&["/usr", "/etc"], &[], false);
        assert!(run(&mut check, &pkg).is_empty());
    }

    #[test]
    #[should_panic(expected = "required config key 'AtomicAllowedDirs' is missing")]
    fn missing_allowed_dirs_panics() {
        let mut table = toml::Table::new();
        table.insert("AtomicCheckGhosts".to_string(), toml::Value::Boolean(false));
        table.insert(
            "AtomicDisallowedSubdirs".to_string(),
            toml::Value::Array(vec![]),
        );
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = AtomicUpdateCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "required config key 'AtomicDisallowedSubdirs' is missing")]
    fn missing_disallowed_subdirs_panics() {
        let mut table = toml::Table::new();
        table.insert("AtomicCheckGhosts".to_string(), toml::Value::Boolean(false));
        table.insert("AtomicAllowedDirs".to_string(), toml::Value::Array(vec![]));
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = AtomicUpdateCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "required config key 'AtomicCheckGhosts' is missing")]
    fn missing_check_ghosts_panics() {
        let mut table = toml::Table::new();
        table.insert("AtomicAllowedDirs".to_string(), toml::Value::Array(vec![]));
        table.insert(
            "AtomicDisallowedSubdirs".to_string(),
            toml::Value::Array(vec![]),
        );
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = AtomicUpdateCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "config key 'AtomicDisallowedSubdirs' must be a list of strings")]
    fn non_string_list_element_panics() {
        let mut table = toml::Table::new();
        table.insert("AtomicCheckGhosts".to_string(), toml::Value::Boolean(false));
        table.insert("AtomicAllowedDirs".to_string(), toml::Value::Array(vec![]));
        table.insert(
            "AtomicDisallowedSubdirs".to_string(),
            toml::Value::Array(vec![toml::Value::Integer(42)]),
        );
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = AtomicUpdateCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "config key 'AtomicCheckGhosts' must be a boolean")]
    fn wrong_type_check_ghosts_panics() {
        let mut table = toml::Table::new();
        table.insert(
            "AtomicCheckGhosts".to_string(),
            toml::Value::String("false".to_string()),
        );
        table.insert("AtomicAllowedDirs".to_string(), toml::Value::Array(vec![]));
        table.insert(
            "AtomicDisallowedSubdirs".to_string(),
            toml::Value::Array(vec![]),
        );
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = AtomicUpdateCheck::new(&config);
    }

    fn flagged(name: &str, flags: u32) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            flags,
            ..Default::default()
        }
    }

    #[test]
    fn usr_etc_conffile_fires_on_every_config_variant() {
        for flags in [
            RPMFILE_CONFIG,
            RPMFILE_CONFIG | RPMFILE_NOREPLACE,
            RPMFILE_CONFIG | RPMFILE_MISSINGOK,
            RPMFILE_CONFIG | RPMFILE_NOREPLACE | RPMFILE_MISSINGOK,
        ] {
            assert!(
                usr_etc_conffile(&flagged("/usr/etc/foo.conf", flags)),
                "flags {flags:#x} must fire"
            );
        }
    }

    #[test]
    fn usr_etc_conffile_covers_subdirs_but_not_dir_entries() {
        // A directory never gets .rpmnew/.rpmsave treatment, so a
        // `%config`-marked directory entry — /usr/etc itself or a
        // subdirectory — does not fire; files below them do.
        for name in ["/usr/etc", "/usr/etc/sysctl.d"] {
            let dir = PkgFile {
                name: name.to_string(),
                mode: 0o040755,
                flags: RPMFILE_CONFIG,
                ..Default::default()
            };
            assert!(!usr_etc_conffile(&dir), "dir {name} must not fire");
        }
        assert!(usr_etc_conffile(&flagged(
            "/usr/etc/sysctl.d/10-x.conf",
            RPMFILE_CONFIG
        )));
    }

    #[test]
    fn usr_etc_conffile_ghost_does_not_fire() {
        // A %ghost ships no vendor default in the package, so there is
        // no vendor default for the %config mark to misclassify.
        assert!(!usr_etc_conffile(&flagged(
            "/usr/etc/foo.conf",
            RPMFILE_CONFIG | RPMFILE_GHOST
        )));
        assert!(!usr_etc_conffile(&flagged(
            "/usr/etc/foo.conf",
            RPMFILE_CONFIG | RPMFILE_GHOST | RPMFILE_NOREPLACE
        )));
    }

    #[test]
    fn usr_etc_conffile_negatives() {
        // No `%config` mark under /usr/etc: fine.
        assert!(!usr_etc_conffile(&flagged("/usr/etc/foo.conf", 0)));
        assert!(!usr_etc_conffile(&flagged(
            "/usr/etc/foo.conf",
            RPMFILE_NOREPLACE
        )));
        // `%config` outside /usr/etc is other findings' business.
        assert!(!usr_etc_conffile(&flagged("/etc/foo.conf", RPMFILE_CONFIG)));
        assert!(!usr_etc_conffile(&flagged(
            "/var/lib/foo.conf",
            RPMFILE_CONFIG
        )));
        assert!(!usr_etc_conffile(&flagged(
            "/usr/share/foo.conf",
            RPMFILE_CONFIG
        )));
        // Prefix trap: /usr/etcfoo is not /usr/etc.
        assert!(!usr_etc_conffile(&flagged(
            "/usr/etcfoo/foo.conf",
            RPMFILE_CONFIG
        )));
        // The dir itself without the mark is fine.
        let dir = PkgFile {
            name: "/usr/etc".to_string(),
            mode: 0o040755,
            ..Default::default()
        };
        assert!(!usr_etc_conffile(&dir));
    }

    #[test]
    #[should_panic(expected = "config key 'AtomicAllowedDirs' must be a list of strings")]
    fn wrong_type_allowed_dirs_panics() {
        let mut table = toml::Table::new();
        table.insert("AtomicCheckGhosts".to_string(), toml::Value::Boolean(false));
        table.insert(
            "AtomicAllowedDirs".to_string(),
            toml::Value::String("/etc/".to_string()),
        );
        table.insert(
            "AtomicDisallowedSubdirs".to_string(),
            toml::Value::Array(vec![]),
        );
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = AtomicUpdateCheck::new(&config);
    }

    /// The scan layer is verdict-free: it returns literal targets in
    /// first-seen order; `scriptlet_target_outside` decides which of
    /// them are findings. Cases pin one construct each: the firing
    /// classes (C1 redirects, C2 write commands) and the near-miss
    /// negatives (dynamic targets, quoted/comment/heredoc text,
    /// non-command positions, out-of-scope commands).
    #[test]
    fn scan_scriptlet_cases() {
        let cases: &[(&str, &[&str])] = &[
            // C2: every-arg commands.
            ("mkdir /var/lib/foo", &["/var/lib/foo"]),
            (
                "mkdir -p /var/lib/foo /srv/bar",
                &["/var/lib/foo", "/srv/bar"],
            ),
            ("rm -rf /var/lib/foo", &["/var/lib/foo"]),
            ("rmdir /var/lib/foodir", &["/var/lib/foodir"]),
            ("touch /var/lib/flag", &["/var/lib/flag"]),
            (
                "tee /var/log/x /var/log/y < /dev/null",
                &["/var/log/x", "/var/log/y"],
            ),
            ("/usr/bin/mkdir /var/lib/abs", &["/var/lib/abs"]),
            ("mkdir '/var/lib/single'", &["/var/lib/single"]),
            ("mkdir \"/var/lib/quoted\"", &["/var/lib/quoted"]),
            ("mkdir /var/lib/with\\ space", &["/var/lib/with space"]),
            // C2: last-arg commands. The scan names the destination
            // even when the source is the outside path; the verdict
            // layer is what keeps an inside destination quiet.
            ("cp /usr/share/a /var/lib/b", &["/var/lib/b"]),
            ("cp /var/lib/a /usr/share/b", &["/usr/share/b"]),
            ("mv /tmp/a /opt/b", &["/opt/b"]),
            ("ln -s /usr/share/a /var/lib/link", &["/var/lib/link"]),
            ("ln -s /var/lib/a /usr/share/link", &["/usr/share/link"]),
            // C2: install modes and dd.
            ("install -d /var/lib/foo", &["/var/lib/foo"]),
            ("install -m644 /usr/share/a /var/lib/b", &["/var/lib/b"]),
            ("install -t /var/lib/dir /usr/share/a", &["/var/lib/dir"]),
            (
                "install --target-directory=/srv/dir /usr/share/a",
                &["/srv/dir"],
            ),
            ("dd if=/dev/zero of=/var/lib/img bs=1M", &["/var/lib/img"]),
            ("dd if=/var/lib/src of=/dev/null", &["/dev/null"]),
            // C1: redirects, incl. fd-prefixed and command-free forms.
            ("echo seed > /var/lib/seed", &["/var/lib/seed"]),
            ("cat /usr/share/x >> /srv/data/f", &["/srv/data/f"]),
            ("somecmd 2>/var/log/err", &["/var/log/err"]),
            ("> /var/lib/trunc", &["/var/lib/trunc"]),
            ("echo x > /dev/null; echo y 2>/dev/null", &["/dev/null"]),
            ("echo z 2>&1", &[]),
            // Command position: separators, keywords, assignments,
            // pipelines; a write word as an argument is not a command.
            (
                "if [ $1 -eq 1 ]; then mkdir /var/lib/cond; fi",
                &["/var/lib/cond"],
            ),
            ("false || mkdir /var/lib/orcase", &["/var/lib/orcase"]),
            ("gen | tee /var/log/pipe", &["/var/log/pipe"]),
            ("x=1 mkdir /var/lib/envassign", &["/var/lib/envassign"]),
            ("echo mkdir /var/lib/notcmd", &[]),
            // Dynamic targets are not literal paths.
            ("mkdir $VAR/sub", &[]),
            ("mkdir ${VAR}/sub", &[]),
            ("mkdir %{_localstatedir}/lib/x", &[]),
            ("mkdir '/var/%{name}'", &[]),
            // Quoted operator text, comments and heredoc bodies are
            // not constructs.
            ("echo 'use > /var/lib/x to store'", &[]),
            (
                "# mkdir /var/lib/commented\nmkdir /usr/share/ok",
                &["/usr/share/ok"],
            ),
            (
                "mkdir /usr/share/ok # mkdir /var/lib/commented",
                &["/usr/share/ok"],
            ),
            (
                "cat <<EOF\nmkdir /var/lib/heredoc\nEOF\nmkdir /var/lib/after",
                &["/var/lib/after"],
            ),
            // De-duplication across constructs in one body.
            ("mkdir /var/lib/a; rm /var/lib/a", &["/var/lib/a"]),
            // Out-of-scope commands name no target here.
            ("sed -i s/a/b/ /var/lib/file", &[]),
            (
                "chmod 755 /var/lib/file; chown root:root /var/lib/file",
                &[],
            ),
            // Scan keeps transient and allowed targets; the verdict
            // layer filters them.
            (
                "mkdir /etc/foo /usr/share/bar",
                &["/etc/foo", "/usr/share/bar"],
            ),
            ("touch /run/foo /var/run/bar", &["/run/foo", "/var/run/bar"]),
        ];
        for (body, expected) in cases {
            assert_eq!(&scan_scriptlet(body), expected, "body: {body}");
        }
    }

    #[test]
    fn scriptlet_target_outside_verdicts() {
        let check = check_with(
            &[
                "/etc/", "/usr/", "/bin/", "/lib/", "/lib64/", "/sbin/", "/boot/",
            ],
            &["/usr/local/", "/boot/efi/"],
            false,
        );
        for outside in [
            "/var/lib/x",
            "/var",
            "/srv/www",
            "/opt/x",
            "/home/user",
            "/root/x",
            "/usr/local/bin/x",
            "/usr/local",
            "/boot/efi/x",
            "/var/adm/messages",
            "/var/adm/update-scripts/saslpwd",
        ] {
            assert!(
                check.scriptlet_target_outside(outside),
                "expected outside: {outside}"
            );
        }
        for inside in [
            "/etc/x",
            "/etc",
            "/usr/share/x",
            "/usr",
            "/bin/x",
            "/boot/grub2/x",
            // Runtime filesystems and their legacy spellings.
            "/run/x",
            "/run",
            "/var/run/x",
            "/var/lock/subsys/foo",
            "/var/lock",
            "/tmp/x",
            "/var/tmp/x",
            "/dev/null",
            "/proc/self/x",
            "/sys/kernel/x",
            // The sanctioned deferred-notification spool.
            "/var/adm/update-messages",
            "/var/adm/update-messages/pkg-1.0-1-notify",
        ] {
            assert!(
                !check.scriptlet_target_outside(inside),
                "expected inside/transient: {inside}"
            );
        }
    }

    #[test]
    fn shell_prog_recognition() {
        for shell in ["", "  ", "/bin/sh", "/bin/bash", " /bin/sh "] {
            assert!(is_shell_prog(shell), "expected shell: {shell:?}");
        }
        for other in ["/sbin/ldconfig", "/usr/bin/lua", "<lua>", "/usr/bin/perl"] {
            assert!(!is_shell_prog(other), "expected non-shell: {other:?}");
        }
    }

    fn fixture_pkg_named(name: &str) -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../tests/parity/pkg/inputs/{name}"));
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.name = "atomic-scriptlet-test".to_string();
        pkg.arch = "noarch".to_string();
        pkg
    }

    /// The shipped configuration lists (configdefaults and both
    /// flavours carry the same Atomic* keys).
    fn shipped_check() -> AtomicUpdateCheck {
        check_with(
            &[
                "/etc/", "/usr/", "/bin/", "/lib/", "/lib64/", "/sbin/", "/boot/",
            ],
            &["/usr/local/", "/boot/efi/"],
            false,
        )
    }

    #[test]
    fn scriptlet_fires_fixture_reports_each_write() {
        let pkg = fixture_pkg_named("atomic-scriptlet-fires-1.0-1.noarch.rpm");
        let mut check = shipped_check();
        let results = run(&mut check, &pkg);
        let expected: &[(&str, &str)] = &[
            ("%pre", "/var/lib/atomic-fixture"),
            ("%post", "/srv/atomic-fixture/seed.conf"),
            ("%post", "/var/cache/atomic-fixture"),
            ("%post", "/var/lib/atomic-fixture/quoted"),
            ("%postun", "/var/lib/atomic-fixture/state"),
            ("%posttrans", "/opt/atomic-fixture.conf"),
        ];
        assert_eq!(results.len(), expected.len(), "results: {results:?}");
        for ((name, line), (label, target)) in results.iter().zip(expected) {
            assert_eq!(name, "scriptlet-writes-outside-snapshot");
            assert!(line.contains(": W: "), "level: {line}");
            assert!(
                line.contains(&format!("{label} {target}")),
                "detail: {line}"
            );
        }
    }

    #[test]
    fn scriptlet_clean_fixture_is_quiet() {
        let pkg = fixture_pkg_named("atomic-scriptlet-clean-1.0-1.noarch.rpm");
        let mut check = shipped_check();
        assert!(run(&mut check, &pkg).is_empty());
    }
}
