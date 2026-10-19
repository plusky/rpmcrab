//! `AtomicUpdateCheck` — the transactional-update (atomic) requirements.
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
//! The reference docstring also states that (re)starting daemons is not
//! possible during a transactional update, but the reference implements
//! no such rule; `scriptlet-service-restart` (W) implements it here: a
//! scriptlet that invokes `systemctl`/`service`/`rc*` to (re)start a
//! service directly, instead of going through the distribution macros
//! (which defer via `systemd-update-helper`), silently does nothing on
//! an atomic system, where scriptlets run inside the new snapshot with
//! systemd offline.
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
use crate::checks::post::PostCheck;
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
    /// (TRANSIENT_PREFIXES) are never outside. The verdict judges the
    /// lexically normalised path (`/usr/../var/lib/x` is a `/var/lib`
    /// write, `/run/../var/lib/x` does not inherit `/run`'s transient
    /// status); the finding itself reports the literal target.
    fn scriptlet_target_outside(&self, path: &str) -> bool {
        let path = &crate::pkg::normalize_path(path);
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

/// `systemctl` verbs that (re)start a daemon.
const RESTART_VERBS: &[&str] = &[
    "restart",
    "try-restart",
    "reload-or-restart",
    "try-reload-or-restart",
    "start",
];

/// Verbs of the legacy `service`/`rc*` command forms that (re)start a
/// daemon. `try-restart` and `condrestart` are the legacy spellings of
/// the conditional restart (the `systemctl` list carries `try-restart`
/// natively); both forms accept both spellings in the wild, so both
/// lists carry both.
const LEGACY_RESTART_VERBS: &[&str] = &["restart", "start", "try-restart", "condrestart"];

/// `systemctl` options that consume the following token as their value;
/// the verb scan steps over both tokens.
const SYSTEMCTL_VALUE_OPTIONS: &[&str] = &[
    "--host",
    "-H",
    "--machine",
    "--root",
    "--job-mode",
    "--type",
    "-t",
    "--signal",
    "-s",
    "--property",
    "-p",
    "--state",
    "--kill-whom",
    "--lines",
    "-n",
    "--output",
    "-o",
];

/// True for scriptlet tags whose bodies run during the install
/// transaction. `%verifyscript` is excluded: it runs on demand
/// (`rpm -V`) against the live system, where a restart can work.
fn scanned_scriptlet(tag: librpm::Tag) -> bool {
    tag != librpm::Tag::VERIFYSCRIPT
}

/// The (re)start invocations in one scriptlet body, as trimmed lines.
///
/// The scan is lexical and line-based, over the heredoc-blanked,
/// quote-blanked form of the body (`PostCheck::without_heredoc_bodies`
/// and `PostCheck::code_only`, the same pair `PostCheck` matches on):
/// heredoc bodies are text the scriptlet writes out, not commands, and
/// a `;`/`|`/`&` inside a quoted string or a comment does not split a
/// command, so `cat <<EOF` payloads and `echo "a; systemctl restart
/// foo"` stay quiet. Both transforms preserve the line count, so the
/// scan zips 1:1 with the original lines and reports the original
/// text. Each resulting line is split into command segments on `;`,
/// `|` and `&`, and only a `systemctl`/`service`/`rc*` word in command
/// position (after leading braces, shell keywords, a `case`-arm
/// pattern and environment assignments) counts, so comments, `echo`
/// text and status/preset plumbing stay quiet. A shell function
/// definition (`rcfoo() { ...; }`) names a command rather than
/// invoking one and stays quiet. A body that mentions
/// `TRANSACTIONAL_UPDATE` is exempt as a whole: the packager gates the
/// scriptlet on the update mechanism explicitly, and which lines the
/// gate covers is not decidable lexically.
fn service_restarts_in_body(body: &str) -> Vec<String> {
    if body.contains("TRANSACTIONAL_UPDATE") {
        return Vec::new();
    }
    invocation_lines(body, segment_restarts)
}

/// The lines of one scriptlet body in which a command segment
/// satisfies `segment_matches`, in body order, one entry per line
/// occurrence (a line repeated in the body reports per occurrence,
/// as the sibling scans sharing this walker do). The walk is over
/// the heredoc-blanked, quote-blanked form of the body
/// (`PostCheck::without_heredoc_bodies` and `PostCheck::code_only`):
/// both transforms preserve the line count, so the walk zips 1:1
/// with the original lines and reports the original text. Each
/// resulting line is split into command segments on `;`, `|` and
/// `&`; only a command substitution's opener (`$(...)` or
/// backticks) starts no segment in this tokenisation (no
/// substitution depth is tracked, so an interior command after a
/// separator is a segment of its own), and the predicates built
/// on this walker judge segment-start command positions only.
fn invocation_lines(body: &str, segment_matches: impl Fn(&str) -> bool) -> Vec<String> {
    let blanked = PostCheck::without_heredoc_bodies(body);
    let coded = PostCheck::code_only(&blanked);
    body.lines()
        .zip(coded.lines())
        .filter_map(|(raw_line, code_line)| {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            code_line
                .split([';', '|', '&'])
                .any(&segment_matches)
                .then(|| line.to_string())
        })
        .collect()
}

/// The words of one command segment: split on whitespace, with the
/// shell decoration characters (`{}`, `()`, quotes) trimmed off
/// each word. A substitution's closing backtick is trimmed off
/// the word it lands on (an interior's last word) as well: the
/// closing delimiter is decoration of the same kind as the `)`
/// closing a `$(...)`, which the trim above already removes, so a
/// separator-delimited interior is judged by the same words in
/// both substitution forms. The opening backtick stays glued to
/// the interior's first word: that word reads as a substitution
/// opener, not as a bare command word, the same reading the `$(`
/// opener gets (see `invocation_lines`).
fn segment_words(segment: &str) -> Vec<&str> {
    segment
        .split_whitespace()
        .map(|w| w.trim_matches(['{', '}', '(', ')', '"', '\'']))
        .map(|w| w.trim_end_matches('`'))
        .filter(|w| !w.is_empty())
        .collect()
}

/// The index of the command word in a segment's words: the first
/// word past the command-position decoration — shell keywords and
/// VAR=value environment assignments leave the next word in
/// command position.
fn segment_command_index(words: &[&str]) -> Option<usize> {
    let mut i = 0;
    while i < words.len()
        && (matches!(
            words[i],
            "if" | "elif" | "while" | "until" | "then" | "do" | "else" | "!"
        ) || is_assignment(words[i]))
    {
        i += 1;
    }
    if i >= words.len() { None } else { Some(i) }
}

/// True when a segment's command word is a shell function
/// definition (`rcfoo() { ...; }`, `rcfoo () { ...; }`): a
/// definition names a command, it does not invoke one.
/// `segment_words` trims `()` off each word, which would reduce
/// the definition's name to a bare command word, so the test
/// inspects the raw segment: the word at command position (the
/// raw word the trimmed `words[i]` came from) carries a `(`
/// directly after the command name, or the following raw word is
/// the `()` of the spaced form. A `(` before the command name
/// (a subshell invocation, `( rcfoo restart )`) is an invocation
/// and stays visible to the scans.
fn segment_is_function_definition(segment: &str) -> bool {
    let segment = skip_case_pattern(segment);
    let words = segment_words(segment);
    let Some(i) = segment_command_index(&words) else {
        return false;
    };
    let command = words[i];
    // Raw words and trimmed words line up 1:1 once the raw words
    // that trim to nothing (pure decoration) are skipped.
    let raw_words: Vec<&str> = segment.split_whitespace().collect();
    let mut trimmed_index = 0;
    for (pos, raw) in raw_words.iter().enumerate() {
        let trimmed = raw.trim_matches(['{', '}', '(', ')', '"', '\'']);
        if trimmed.is_empty() {
            continue;
        }
        if trimmed_index == i {
            let core = raw.trim_start_matches(['{', '"', '\'']);
            let Some(rest) = core.strip_prefix(command) else {
                return false;
            };
            if rest.starts_with('(') {
                return true;
            }
            // The spaced form: the command word stands alone and
            // the next raw word is exactly `()`.
            return rest.is_empty()
                && raw_words
                    .get(pos + 1)
                    .is_some_and(|next| next.trim_matches(['{', '}', '"', '\'']) == "()");
        }
        trimmed_index += 1;
    }
    false
}

/// Basenames that are shaped like an rc<service> link but name a
/// real, widely used binary instead: `rclone` (the file-sync
/// tool), `rcs` (the RCS version-control command) and `rcp` (the
/// remote-copy command). None of them is an rc link, in any
/// directory and invoked bare — a bare `rclone` resolves through
/// PATH exactly like the path-qualified form the sbin gate
/// already excludes, so the gate alone cannot separate them.
const RC_NAME_COLLISIONS: &[&str] = &["rclone", "rcs", "rcp"];

/// True when `command` — the word in command position — names an
/// rc<service> link: basename `rc<name>`, invoked bare or by path.
/// A path-qualified form only counts when its immediate parent
/// directory is a sbin directory, where the rc<service> links
/// live; a same-shaped binary elsewhere (e.g. `/usr/bin/rclone`)
/// is not an rc link. A bare `rc<name>` carries no path to judge
/// and counts, with the known bare-name collisions in
/// `RC_NAME_COLLISIONS` excluded: those basenames name real
/// binaries, not rc links.
fn rc_link_command(command: &str) -> bool {
    let base = command.rsplit('/').next().unwrap_or(command);
    if base.len() <= 2 || !base.starts_with("rc") || RC_NAME_COLLISIONS.contains(&base) {
        return false;
    }
    !(command.contains('/') && !command.rsplit('/').nth(1).is_some_and(|dir| dir == "sbin"))
}

/// True when one command segment invokes a service (re)start.
fn segment_restarts(segment: &str) -> bool {
    if segment_is_function_definition(segment) {
        return false;
    }
    let words = segment_words(skip_case_pattern(segment));
    let Some(i) = segment_command_index(&words) else {
        return false;
    };
    let command = words[i];
    let args = &words[i + 1..];
    if command == "systemctl" || command.ends_with("/systemctl") {
        return systemctl_verb(args).is_some_and(|v| RESTART_VERBS.contains(&v));
    }
    if command == "service" || command.ends_with("/service") {
        // `service NAME VERB`; the pair is positional.
        return args.len() >= 2 && LEGACY_RESTART_VERBS.contains(&args[1]);
    }
    // The legacy rc form is `rc<name> VERB`, invoked bare or by path.
    if rc_link_command(command) {
        return args
            .first()
            .is_some_and(|v| LEGACY_RESTART_VERBS.contains(v));
    }
    false
}

/// Skip a leading `case`-arm pattern (`*)`, `restart)`, `(start)`) in
/// a command segment, returning the segment past it. The pattern is a
/// single word ending in `)`; without the skip the pattern reads as
/// the command word (`*`) and the arm's command is missed. A word
/// containing a substitution, a backtick or an assignment is not a
/// pattern (a `$(...)` command word keeps its old reading).
fn skip_case_pattern(segment: &str) -> &str {
    let trimmed = segment.trim_start();
    let Some(first) = trimmed.split_whitespace().next() else {
        return segment;
    };
    let core = first.strip_prefix('(').unwrap_or(first);
    let Some(pattern) = core.strip_suffix(')') else {
        return segment;
    };
    if pattern.is_empty() || pattern.contains(['(', ')', '$', '`', '=']) {
        return segment;
    }
    trimmed[first.len()..].trim_start()
}

/// The verb of a `systemctl` invocation: the first non-option token,
/// stepping over options and the values of options that take one.
fn systemctl_verb<'a>(args: &[&'a str]) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg.starts_with('-') {
            i += if SYSTEMCTL_VALUE_OPTIONS.contains(&arg) {
                2
            } else {
                1
            };
            continue;
        }
        return Some(arg);
    }
    None
}

/// All (re)start invocations across a package's scriptlets: pairs of
/// the scriptlet label (`%post`, ...) and the offending line.
fn service_restarts<'a>(scriptlets: &[(&'a str, &'a str)]) -> Vec<(&'a str, String)> {
    let mut hits = Vec::new();
    for (label, body) in scriptlets {
        for line in service_restarts_in_body(body) {
            hits.push((*label, line));
        }
    }
    hits
}

/// The direct user/group creation invocations in one scriptlet
/// body: (tool, line) pairs in body order, one entry per line
/// occurrence and tool. The scan shares the lexical walk of
/// `service_restarts_in_body` — the heredoc-blanked, quote-blanked
/// form of the body (`PostCheck::without_heredoc_bodies` and
/// `PostCheck::code_only`), zipped 1:1 with the original lines and
/// reported in the original text. Each line is split into command
/// segments on `;`, `|` and `&`, and only a `useradd`/`groupadd`
/// word in command position (after leading braces, shell keywords,
/// a `case`-arm pattern and environment assignments) counts, so
/// mentions in comments, quoted text, heredoc bodies and operand
/// position stay silent, as do shell function definitions
/// (`useradd() { ...; }`), which name the tool without invoking
/// it. `PostCheck` reports the pairs as
/// `scriptlet-useradd-in-<scriptlet>` and
/// `scriptlet-groupadd-in-<scriptlet>` (issue #640).
pub(crate) fn direct_user_creation_in_body(body: &str) -> Vec<(&'static str, String)> {
    let blanked = PostCheck::without_heredoc_bodies(body);
    let coded = PostCheck::code_only(&blanked);
    let mut hits = Vec::new();
    for (raw_line, code_line) in body.lines().zip(coded.lines()) {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut tools: Vec<&'static str> = Vec::new();
        for segment in code_line.split([';', '|', '&']) {
            if let Some(tool) = segment_user_creation(segment)
                && !tools.contains(&tool)
            {
                tools.push(tool);
            }
        }
        for tool in tools {
            hits.push((tool, line.to_string()));
        }
    }
    hits
}

/// True when a segment's command word is a shell function
/// definition (`useradd() { ...; }`, `useradd () { ...; }`): a
/// definition names a command, it does not invoke one. The word
/// tokenisation trims `()` off each word, which would reduce
/// the definition's name to a bare command word, so the test
/// inspects the raw segment: the raw word at command position
/// (the raw word the trimmed command word came from) carries a
/// `(` directly after the command name, or the following raw
/// word is the `()` of the spaced form. A `(` before the command
/// name (a subshell invocation, `( useradd -r foo )`) is an
/// invocation and stays visible to the scan.
fn segment_defines_function(segment: &str) -> bool {
    let segment = skip_case_pattern(segment);
    let raw_words: Vec<&str> = segment.split_whitespace().collect();
    let words: Vec<&str> = raw_words
        .iter()
        .map(|w| w.trim_matches(['{', '}', '(', ')', '\"', '\\']))
        .filter(|w| !w.is_empty())
        .collect();
    let mut i = 0;
    // Skip command-position decoration: shell keywords and
    // VAR=value environment assignments.
    while i < words.len()
        && (matches!(
            words[i],
            "if" | "elif" | "while" | "until" | "then" | "do" | "else" | "!"
        ) || is_assignment(words[i]))
    {
        i += 1;
    }
    if i >= words.len() {
        return false;
    }
    let command = words[i];
    // Raw words and trimmed words line up 1:1 once the raw words
    // that trim to nothing (pure decoration) are skipped.
    let mut trimmed_index = 0;
    for (pos, raw) in raw_words.iter().enumerate() {
        let trimmed = raw.trim_matches(['{', '}', '(', ')', '\"', '\\']);
        if trimmed.is_empty() {
            continue;
        }
        if trimmed_index == i {
            let core = raw.trim_start_matches(['{', '\"', '\\']);
            let Some(rest) = core.strip_prefix(command) else {
                return false;
            };
            if rest.starts_with('(') {
                return true;
            }
            // The spaced form: the command word stands alone and
            // the next raw word is exactly `()`.
            return rest.is_empty()
                && raw_words
                    .get(pos + 1)
                    .is_some_and(|next| next.trim_matches(['{', '}', '\"', '\\']) == "()");
        }
        trimmed_index += 1;
    }
    false
}

/// The creation tool one command segment invokes, if any:
/// `useradd` or `groupadd` as the command word, bare or by path
/// from any directory (the canonical full form is
/// `/usr/sbin/useradd`). The lifecycle tools (`usermod`,
/// `userdel`, `groupmod`, `groupdel`) manage existing accounts
/// and stay silent, as does `systemd-sysusers`: a sysusers
/// invocation is the declarative mechanism itself. A shell
/// function definition names the tool without invoking it and
/// stays silent (`segment_defines_function`).
fn segment_user_creation(segment: &str) -> Option<&'static str> {
    if segment_defines_function(segment) {
        return None;
    }
    let segment = skip_case_pattern(segment);
    let words: Vec<&str> = segment
        .split_whitespace()
        .map(|w| w.trim_matches(['{', '}', '(', ')', '"', '\\']))
        .filter(|w| !w.is_empty())
        .collect();
    let mut i = 0;
    // Skip command-position decoration: shell keywords and
    // VAR=value environment assignments.
    while i < words.len()
        && (matches!(
            words[i],
            "if" | "elif" | "while" | "until" | "then" | "do" | "else" | "!"
        ) || is_assignment(words[i]))
    {
        i += 1;
    }
    if i >= words.len() {
        return None;
    }
    match words[i].rsplit('/').next().unwrap_or(words[i]) {
        "useradd" => Some("useradd"),
        "groupadd" => Some("groupadd"),
        _ => None,
    }
}

/// The lines of one scriptlet body that invoke an rc<service>
/// link, in body order, one entry per line occurrence. The scan
/// shares the tokenisation of `service_restarts_in_body` — the
/// same `invocation_lines` walk over the heredoc-blanked,
/// quote-blanked lines, command segments split on `;`, `|` and
/// `&`, command position only — but is verb-independent: the
/// rc<name> invocation itself is the obsolete part, whatever verb
/// follows it, so `rcfoo status` fires here while staying silent
/// for `scriptlet-service-restart`. A shell function definition
/// (`rcfoo() { ...; }`) names a command and does not invoke one,
/// so it stays silent in both scans. There is no
/// `TRANSACTIONAL_UPDATE` exemption: the links are removed from
/// the distribution outright, on classic and transactional systems
/// alike. `PostCheck` reports the lines as
/// `scriptlet-rc-link-invocation-in-<scriptlet>` (issue #731).
pub(crate) fn rc_link_invocations_in_body(body: &str) -> Vec<String> {
    invocation_lines(body, segment_rc_link)
}

/// True when one command segment's command word is an rc<service>
/// link invocation.
fn segment_rc_link(segment: &str) -> bool {
    if segment_is_function_definition(segment) {
        return false;
    }
    let words = segment_words(skip_case_pattern(segment));
    let Some(i) = segment_command_index(&words) else {
        return false;
    };
    rc_link_command(words[i])
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
        let mut scriptlets: Vec<(&str, String)> = Vec::new();
        for (tag, _prog, label) in crate::pkg::SCRIPT_TAGS {
            if !scanned_scriptlet(*tag) {
                continue;
            }
            for body in pkg.tag_str_array(*tag) {
                if !body.is_empty() {
                    scriptlets.push((label, body));
                }
            }
        }
        let scriptlet_refs: Vec<(&str, &str)> = scriptlets
            .iter()
            .map(|(label, body)| (*label, body.as_str()))
            .collect();
        for (label, line) in service_restarts(&scriptlet_refs) {
            add_info(
                out,
                Level::Warning,
                pkg,
                "scriptlet-service-restart",
                &[label, line.as_str()],
            );
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
            '(' | ')' | '{' | '}' => {
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
///   `cp`/`mv`/`ln` (the last path argument -- the rest are sources --
///   or the `-t`/`--target-directory` directory when one is given),
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
                // The `-t`/`--target-directory` directory (space forms;
                // the `=` form is pushed by the loop above). With one,
                // every operand is a source and the directory itself is
                // the write target, for `install` and `cp`/`mv`/`ln`
                // alike.
                let mut target_dirs: Vec<&Tok> = Vec::new();
                for (k, a) in args.iter().enumerate() {
                    if (a.text == "-t" || a.text == "--target-directory")
                        && let Some(t) = args.get(k + 1)
                    {
                        target_dirs.push(t);
                    }
                }
                let has_t = !target_dirs.is_empty()
                    || args
                        .iter()
                        .any(|a| a.text.starts_with("--target-directory="));
                if WRITE_EVERY_ARG.contains(&base) {
                    cands.extend(plain.iter().copied());
                } else if WRITE_LAST_ARG.contains(&base) {
                    if has_t {
                        cands.extend(target_dirs.iter().copied());
                    } else if let Some(last) = plain.last() {
                        cands.push(last);
                    }
                } else if base == "install" {
                    let dir_mode = args
                        .iter()
                        .any(|a| a.text == "-d" || a.text == "--directory");
                    if dir_mode {
                        cands.extend(plain.iter().copied());
                    } else if has_t {
                        cands.extend(target_dirs.iter().copied());
                    } else if let Some(last) = plain.last() {
                        cands.push(last);
                    }
                } else if base == "dd" {
                    for a in &args {
                        if let Some(of) = a.text.strip_prefix("of=") {
                            let owned = Tok {
                                kind: TokKind::Word,
                                text: of.to_string(),
                                dynamic: a.dynamic,
                            };
                            if is_literal(&owned) && owned.text.starts_with('/') {
                                push(&owned.text);
                            }
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
    fn verifyscript_is_not_scanned() {
        assert!(!scanned_scriptlet(librpm::Tag::VERIFYSCRIPT));
        assert!(scanned_scriptlet(librpm::Tag::POSTIN));
        assert!(scanned_scriptlet(librpm::Tag::POSTTRANS));
        assert!(scanned_scriptlet(librpm::Tag::TRIGGERSCRIPTS));
    }

    #[test]
    fn verifyscript_restart_body_is_quiet_through_check() {
        // Wiring pin for the %verifyscript exclusion: the scan loop in
        // `check` must skip the tag, not just the predicate above.
        // Deleting the guard makes this fixture fire once.
        let pkg = fixture_pkg_named("atomic-verify-restart-1.0-1.noarch.rpm");
        let mut check = check_with(&["/usr", "/etc"], &[], false);
        let results = run(&mut check, &pkg);
        assert!(
            results
                .iter()
                .all(|(name, _)| name != "scriptlet-service-restart"),
            "{results:?}"
        );
    }

    #[test]
    fn post_restart_body_fires_through_check() {
        let pkg = fixture_pkg_named("atomic-post-restart-1.0-1.noarch.rpm");
        let mut check = check_with(&["/usr", "/etc"], &[], false);
        let results = run(&mut check, &pkg);
        let hits: Vec<_> = results
            .iter()
            .filter(|(name, _)| name == "scriptlet-service-restart")
            .collect();
        assert_eq!(hits.len(), 1, "{results:?}");
        assert!(hits[0].1.contains("%post"), "{}", hits[0].1);
        assert!(hits[0].1.contains("restart"), "{}", hits[0].1);
    }

    #[test]
    fn bare_systemctl_restart_fires() {
        let hits = service_restarts(&[("%post", "/usr/bin/systemctl restart apache2.service\n")]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "%post");
        assert!(hits[0].1.contains("restart apache2.service"));
    }

    #[test]
    fn restart_verb_family_fires() {
        for body in [
            "systemctl try-restart foo.service || :",
            "systemctl reload-or-restart foo.service",
            "systemctl try-reload-or-restart foo.service",
            "systemctl start foo.service",
        ] {
            assert_eq!(service_restarts_in_body(body).len(), 1, "{body}");
        }
    }

    #[test]
    fn systemctl_options_are_stepped_over() {
        for body in [
            "systemctl --no-reload restart foo.service",
            "systemctl --machine=host1 restart foo.service",
            "systemctl --machine host1 try-restart foo.service",
            "systemctl --root /srv/target restart foo.service",
            "systemctl --output json restart foo.service",
            "systemctl -o json restart foo.service",
        ] {
            assert_eq!(service_restarts_in_body(body).len(), 1, "{body}");
        }
    }

    #[test]
    fn status_guarded_compound_line_fires_once() {
        // bluez-auto-enable-devices %post/%postun, verbatim.
        let body = "{  systemctl status -n0 bluetooth.service > /dev/null \
                    && systemctl restart bluetooth.service ; } ||:";
        assert_eq!(service_restarts_in_body(body).len(), 1);
    }

    #[test]
    fn apache_posttrans_fixture_fires_on_restarts_only() {
        // apache2 %posttrans (Factory): flag-driven restarts; the
        // daemon-reload lines in the same body must stay quiet.
        let body = "\
if [ -x /usr/bin/systemctl ]; then
    if [ -e /var/run/httpd.restart.flag ]; then
      /usr/bin/systemctl daemon-reload > /dev/null 2>&1 || :
      /usr/bin/systemctl restart apache2.target > /dev/null 2>&1 || :
      rm /var/run/httpd.restart.flag*
    else
      /usr/bin/systemctl daemon-reload > /dev/null 2>&1 || :
      /usr/bin/systemctl restart apache2${instance_suffix}.service > /dev/null 2>&1 || :
    fi
fi
";
        let hits = service_restarts_in_body(body);
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert!(hits.iter().all(|l| l.contains("restart")));
    }

    #[test]
    fn legacy_service_and_rc_forms_fire() {
        for body in [
            "service httpd restart",
            "/sbin/service httpd start",
            "rchapache2 restart",
            "/usr/sbin/rchapache2 restart",
            "rchapache2 try-restart",
            "rchapache2 condrestart",
            "service httpd condrestart",
            "service httpd try-restart",
        ] {
            assert_eq!(service_restarts_in_body(body).len(), 1, "{body}");
        }
    }

    #[test]
    fn non_sbin_rc_lookalike_is_quiet() {
        // `rclone` is a file-sync tool, not an rc<service> link; the
        // rc links live in sbin directories.
        for body in ["/usr/bin/rclone restart", "/usr/bin/rclone start"] {
            assert!(service_restarts_in_body(body).is_empty(), "{body}");
        }
    }

    #[test]
    fn bare_rc_name_collisions_are_quiet() {
        // The known bare-name collisions (review on #732): a bare
        // `rclone` resolves through PATH exactly like the excluded
        // `/usr/bin/rclone`, and `rcs`/`rcp` are real binaries too —
        // none of them is an rc<service> link, for either scan and
        // for any arguments.
        for body in [
            "rclone sync a b",
            "rclone restart",
            "rcs -i somefile",
            "rcp a b",
            "rcp restart",
        ] {
            assert!(service_restarts_in_body(body).is_empty(), "{body}");
            assert!(rc_link_invocations_in_body(body).is_empty(), "{body}");
        }
    }

    #[test]
    fn function_definition_is_quiet() {
        // A definition names a command, it does not invoke one
        // (review on #732): `segment_words` trims `()`, so the
        // definition must be recognised on the raw segment. The
        // definition's header segment is suppressed as a whole, so
        // an invocation inside a one-line body stays silent with
        // it; an invocation after a separator or on a later body
        // line is a segment of its own and still fires.
        for body in [
            "rcfoo() { echo hi; }",
            "rcfoo () { echo hi; }",
            "rcfoo()\n{\n echo hi\n}",
        ] {
            assert!(rc_link_invocations_in_body(body).is_empty(), "{body}");
            assert!(service_restarts_in_body(body).is_empty(), "{body}");
        }
        assert_eq!(
            rc_link_invocations_in_body("rcfoo() { true; }; rcbar status").len(),
            1
        );
        // The one-line body shares the header segment: silent in
        // both scans even with a restart verb inside it.
        assert!(rc_link_invocations_in_body("rcfoo() { rcbar restart; }").is_empty());
        assert!(service_restarts_in_body("rcfoo() { rcbar restart; }").is_empty());
        // A body invocation on its own line is its own segment.
        assert_eq!(
            rc_link_invocations_in_body("rcfoo() {\n rcbar restart\n}").len(),
            1
        );
        assert_eq!(
            service_restarts_in_body("rcfoo() {\n rcbar restart\n}").len(),
            1
        );
        // A subshell invocation is not a definition.
        assert_eq!(rc_link_invocations_in_body("( rcfoo restart )").len(), 1);
        assert_eq!(service_restarts_in_body("( rcfoo restart )").len(), 1);
    }

    #[test]
    fn rc_link_invocations_report_per_line_occurrence() {
        // Per-line reporting, matching `service_restarts_in_body`:
        // a line repeated in the body reports per occurrence, not
        // once per distinct line text.
        let body = "rcfoo status\nrcfoo status";
        assert_eq!(rc_link_invocations_in_body(body).len(), 2);
        assert_eq!(
            service_restarts_in_body("rcfoo restart\nrcfoo restart").len(),
            2
        );
    }

    #[test]
    fn substitution_opener_starts_no_segment_but_separator_interior_fires() {
        // Pinned scope of the shared tokenisation (disclosed in the
        // #731 ledger entry): the substitution opener starts no
        // segment, so an interior without a separator stays inside
        // the outer segment and neither scan judges it \u2014 and a
        // substitution standing alone is its opener word, read the
        // same way. The splitter tracks no substitution depth,
        // though, so an interior command after a separator is a
        // segment of its own and is judged: both substitution
        // forms fire in both scans (issue #783 \u2014 the closing
        // backtick is trimmed off the interior's last word exactly
        // as the closing parenthesis is, so the restart scan's
        // verb matching sees the same words in both forms).
        // Widening the opener case is a recall change for both
        // checks, not part of this predicate.
        for body in [
            "x=$(rcfoo restart)",
            "echo `rcfoo restart`",
            "$(rcfoo restart)",
            "`rcfoo restart`",
        ] {
            assert!(rc_link_invocations_in_body(body).is_empty(), "{body}");
            assert!(service_restarts_in_body(body).is_empty(), "{body}");
        }
        for body in [
            "echo $(echo hi; rcfoo restart)",
            "echo `echo hi; rcfoo restart`",
        ] {
            assert_eq!(rc_link_invocations_in_body(body).len(), 1, "{body}");
            assert_eq!(service_restarts_in_body(body).len(), 1, "{body}");
        }
        // The closing delimiter lands on the word that ends the
        // interior \u2014 here the verb of the service and systemctl
        // forms, the position the restart scan matches on \u2014 and
        // is trimmed there in both forms.
        for body in [
            "echo $(echo hi; service foo restart)",
            "echo `echo hi; service foo restart`",
            "echo $(echo hi; systemctl --no-block restart)",
            "echo `echo hi; systemctl --no-block restart`",
        ] {
            assert_eq!(service_restarts_in_body(body).len(), 1, "{body}");
        }
        // A non-restart verb inside a substitution interior is
        // judged like one outside it: the rc scan fires (the
        // invocation itself is the finding there), the restart
        // scan stays silent \u2014 in both forms.
        for body in [
            "echo $(echo hi; rcfoo status)",
            "echo `echo hi; rcfoo status`",
        ] {
            assert_eq!(rc_link_invocations_in_body(body).len(), 1, "{body}");
            assert!(service_restarts_in_body(body).is_empty(), "{body}");
        }
        // The denylist reads the same words in both forms too: an
        // interior `rclone` is the file-sync tool, not an rc link,
        // exactly like the bare word \u2014 the closing backtick
        // does not carry it past the denylist.
        for body in [
            "echo $(echo hi; rclone) sync a b",
            "echo `echo hi; rclone` sync a b",
        ] {
            assert!(rc_link_invocations_in_body(body).is_empty(), "{body}");
            assert!(service_restarts_in_body(body).is_empty(), "{body}");
        }
        // A plain interior command is no invocation in either
        // scan, in either form.
        for body in ["echo $(echo hi; ls -la)", "echo `echo hi; ls -la`"] {
            assert!(rc_link_invocations_in_body(body).is_empty(), "{body}");
            assert!(service_restarts_in_body(body).is_empty(), "{body}");
        }
    }

    #[test]
    fn heredoc_body_is_quiet() {
        let body = "cat <<EOF\nsystemctl restart foo.service\nEOF\n";
        assert!(service_restarts_in_body(body).is_empty());
        let body = "cat <<'EOF'\nservice foo restart\nEOF\n";
        assert!(service_restarts_in_body(body).is_empty());
    }

    #[test]
    fn restart_after_heredoc_terminator_fires() {
        let body = "cat <<EOF\nsome text\nEOF\nsystemctl restart foo.service\n";
        assert_eq!(service_restarts_in_body(body).len(), 1);
    }

    #[test]
    fn quoted_separator_text_is_quiet() {
        for body in [
            "echo \"a; systemctl restart foo.service\"",
            "echo 'a; systemctl restart foo.service'",
            "echo \"a | systemctl restart foo.service\"",
        ] {
            assert!(service_restarts_in_body(body).is_empty(), "{body}");
        }
    }

    #[test]
    fn case_arm_restart_fires() {
        assert_eq!(
            service_restarts_in_body("*) systemctl restart foo.service;;").len(),
            1
        );
        let body = "case \"$1\" in\n*) systemctl restart foo.service;;\nesac\n";
        assert_eq!(service_restarts_in_body(body).len(), 1, "{body}");
        let body = "case \"$1\" in\nrestart) systemctl restart foo.service;;\nesac\n";
        assert_eq!(service_restarts_in_body(body).len(), 1, "{body}");
    }

    #[test]
    fn non_restart_systemctl_verbs_are_quiet() {
        for body in [
            "systemctl daemon-reload",
            "systemctl preset foo.service",
            "systemctl enable foo.service",
            "systemctl is-active foo.service",
            "systemctl status foo.service",
            // Scope is (re)starts, per the reference docstring; a stop
            // is pinned quiet here deliberately.
            "systemctl stop foo.service",
        ] {
            assert!(service_restarts_in_body(body).is_empty(), "{body}");
        }
    }

    #[test]
    fn comments_and_echo_text_are_quiet() {
        for body in [
            "# systemctl restart foo.service",
            "echo 'run systemctl restart foo.service manually'",
            "systemctl daemon-reload # then systemctl restart foo.service",
            "xsystemctl restart foo.service",
            "/usr/sbin/myrc restart",
        ] {
            assert!(service_restarts_in_body(body).is_empty(), "{body}");
        }
    }

    #[test]
    fn transactional_update_guard_exempts_body() {
        let body = "if [ -z \"${TRANSACTIONAL_UPDATE}\" ]; then\n\
                    systemctl restart foo.service\nfi\n";
        assert!(service_restarts_in_body(body).is_empty());
    }

    #[test]
    fn macro_helper_body_is_quiet() {
        let body = "/usr/lib/systemd/systemd-update-helper mark-restart-system-units foo.service\n\
                    /usr/bin/systemctl preset foo.service\n";
        assert!(service_restarts_in_body(body).is_empty());
    }

    #[test]
    fn env_assignment_and_keyword_prefixes_still_fire() {
        assert_eq!(
            service_restarts_in_body("SYSTEMD_LOG_LEVEL=debug systemctl restart foo.service").len(),
            1
        );
        assert_eq!(
            service_restarts_in_body(
                "if systemctl is-active foo.service; then systemctl restart foo.service; fi"
            )
            .len(),
            1
        );
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
            (
                "install --target-directory /srv/dir /usr/share/a",
                &["/srv/dir"],
            ),
            ("dd if=/dev/zero of=/var/lib/img bs=1M", &["/var/lib/img"]),
            ("dd if=/var/lib/src of=/dev/null", &["/dev/null"]),
            // A quoted `%{` in `of=` is a macro, not a literal path:
            // the tokeniser does not flag quoted text dynamic, so the
            // `is_literal` text guard is what keeps this quiet.
            ("dd if=/dev/zero of='/var/%{name}' bs=1M", &[]),
            ("dd if=/dev/zero of=%{_localstatedir}/lib/img", &[]),
            // C2: `-t`/`--target-directory` on the last-arg commands.
            // The directory is the target and every operand a source,
            // in the space forms as well as the `=` form: the source
            // is never the candidate, and an outside source feeding an
            // inside directory stays a scan hit on the directory only.
            ("cp -t /var/lib/dir /usr/share/src", &["/var/lib/dir"]),
            (
                "cp --target-directory /var/lib/dir /usr/share/src",
                &["/var/lib/dir"],
            ),
            (
                "cp --target-directory=/var/lib/dir /usr/share/src",
                &["/var/lib/dir"],
            ),
            ("cp -t /usr/share/dir /var/lib/src", &["/usr/share/dir"]),
            ("mv -t /opt/dir /usr/share/src", &["/opt/dir"]),
            ("ln -t /var/lib/dir /usr/share/src", &["/var/lib/dir"]),
            // A dynamic `-t` directory names no literal target, and
            // the operands stay sources (no last-arg fallback).
            ("cp -t $DIR /usr/share/src", &[]),
            ("install -t $DIR /usr/share/a", &[]),
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
            // Brace groups are command separators like parens: the
            // write inside a `{ ...; }` group (or a function body)
            // is in command position after the `{`.
            ("{ mkdir /var/lib/brace; }", &["/var/lib/brace"]),
            (
                "f() { mkdir /var/lib/funcbody; }; f",
                &["/var/lib/funcbody"],
            ),
            ("echo {a,b}", &[]),
            // Dynamic targets are not literal paths. The
            // absolute-path-with-dynamic-suffix forms pin the dynamic
            // guard itself: without it they would be literal hits.
            ("mkdir $VAR/sub", &[]),
            ("mkdir ${VAR}/sub", &[]),
            ("mkdir /var/lib/$SUFFIX", &[]),
            ("mkdir /var/lib/${SUFFIX}", &[]),
            ("mkdir %{_localstatedir}/lib/x", &[]),
            ("mkdir '/var/%{name}'", &[]),
            // The scan reports the literal target; lexical
            // normalisation is the verdict layer's business.
            ("mkdir /usr/../var/lib/evil", &["/usr/../var/lib/evil"]),
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
            // `..` segments are judged after lexical normalisation:
            // an allowed or transient prefix on the raw literal does
            // not carry over the `..`.
            "/usr/../var/lib/evil",
            "/run/../var/lib/x",
            "/etc/../var/lib/x",
            "/usr/local/../../var/lib/x",
            "/var/tmp/../../var/lib/x",
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
            // `..` segments that normalise back inside (or onto a
            // transient prefix) stay quiet: the normalised form is
            // judged, not the literal.
            "/var/../usr/share/x",
            "/usr/lib/../share/x",
            "/var/lib/../../etc/x",
            "/run/../run/x",
            "/var/../var/run/x",
            "/usr/../usr/local/../share/x",
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

    #[test]
    fn direct_user_creation_fires() {
        for (body, tool) in [
            ("useradd -r -s /sbin/nologin foo", "useradd"),
            ("/usr/sbin/useradd -r foo", "useradd"),
            ("/usr/bin/useradd foo", "useradd"),
            ("groupadd -r foo", "groupadd"),
            ("/usr/sbin/groupadd foo", "groupadd"),
            ("FOO=bar useradd foo", "useradd"),
            ("if useradd foo; then true; fi", "useradd"),
        ] {
            let hits = direct_user_creation_in_body(body);
            assert_eq!(hits, vec![(tool, body.to_string())], "must fire: {body}");
        }
    }

    #[test]
    fn direct_user_creation_after_separator_fires_once() {
        // The `test -x` operand on the same line is not an
        // invocation; the command after `&&` is, and the line
        // is reported once.
        let body = "test -x /usr/sbin/useradd && /usr/sbin/useradd -r foo";
        let hits = direct_user_creation_in_body(body);
        assert_eq!(hits, vec![("useradd", body.to_string())]);
    }

    #[test]
    fn direct_user_creation_case_arm_fires() {
        let body = "case $1 in\n  1) groupadd -r foo ;;\nesac";
        let hits = direct_user_creation_in_body(body);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "groupadd");
    }

    #[test]
    fn direct_user_creation_reports_each_tool_on_a_line() {
        let body = "groupadd -r foo; useradd -r -g foo foo";
        let hits = direct_user_creation_in_body(body);
        assert_eq!(
            hits,
            vec![
                ("groupadd", body.to_string()),
                ("useradd", body.to_string())
            ]
        );
    }

    #[test]
    fn direct_user_creation_repeated_line_reports_per_line() {
        let body = "useradd -r foo\nuseradd -r foo";
        assert_eq!(direct_user_creation_in_body(body).len(), 2);
    }

    #[test]
    fn direct_user_creation_near_misses_are_quiet() {
        for body in [
            // The declarative mechanism itself: systemd-sysusers
            // invocations, including the shape the sysusers RPM
            // macros expand to.
            "systemd-sysusers",
            "/usr/bin/systemd-sysusers --replace=/usr/lib/sysusers.d/foo.conf -",
            // The lifecycle tools manage existing accounts; they
            // are not creation.
            "usermod -a -G video foo",
            "userdel foo",
            "groupmod -g 42 foo",
            "groupdel foo",
            // The Debian creation tool is outside the ruling,
            // which names useradd/groupadd.
            "adduser --system foo",
            // Mentions: comments, quoted text, operand position.
            "# create the account with useradd -r foo\ntrue",
            "true # useradd -r foo",
            "echo \"create the account with useradd -r foo\"",
            "echo useradd",
            "test -x /usr/sbin/useradd",
            // Shipping a sysusers.d file is the desired end state.
            "install -m 0644 foo.conf /usr/lib/sysusers.d/foo.conf",
        ] {
            assert!(
                direct_user_creation_in_body(body).is_empty(),
                "must stay silent: {body}"
            );
        }
    }

    #[test]
    fn direct_user_creation_in_heredoc_is_quiet() {
        let body = "cat >> /var/adm/update-messages/foo << EOF\nCreate the account first:\n useradd -r foo\nEOF";
        assert!(direct_user_creation_in_body(body).is_empty());
    }

    #[test]
    fn direct_user_creation_function_definitions_are_quiet() {
        // A definition names a command, it does not invoke one
        // (review on #754): the word tokenisation trims `()`, so
        // the definition is recognised on the raw segment, in
        // the attached and the spaced form alike.
        for body in [
            "useradd() { echo hi; }",
            "groupadd() { echo hi; }",
            "useradd () { echo hi; }",
            "groupadd () { echo hi; }",
            "useradd(){ echo hi; }",
            "useradd()\n{\n echo hi\n}",
            // The invocation inside the definition's own segment
            // is part of the definition, not an invocation.
            "useradd() { useradd -r foo; }",
            "groupadd() { groupadd -r foo; }",
        ] {
            assert!(
                direct_user_creation_in_body(body).is_empty(),
                "must stay silent: {body}"
            );
        }
        // An invocation in the definition's body on its own line
        // is a segment of its own and still fires.
        let body = "useradd() {\n useradd -r foo\n}";
        let hits = direct_user_creation_in_body(body);
        assert_eq!(hits, vec![("useradd", "useradd -r foo".to_string())]);
    }

    #[test]
    fn direct_user_creation_substitution_scope_is_opener_only() {
        // The scope the #640 ledger entry states (narrowed with
        // the #776 wording): the substitution opener starts no
        // segment, so an interior without a separator stays
        // inside the outer segment; an interior command after a
        // separator is a segment of its own and fires, in both
        // substitution forms.
        for body in ["x=$(useradd -r foo)", "echo `useradd -r foo`"] {
            assert!(
                direct_user_creation_in_body(body).is_empty(),
                "must stay silent: {body}"
            );
        }
        for body in [
            "echo $(echo hi; useradd -r foo)",
            "echo `echo hi; useradd -r foo`",
        ] {
            let hits = direct_user_creation_in_body(body);
            assert_eq!(hits.len(), 1, "must fire: {body}");
            assert_eq!(hits[0].0, "useradd", "must fire: {body}");
        }
    }

    #[test]
    fn direct_user_creation_subshell_invocations_fire() {
        // A subshell invocation is not a definition: the `(`
        // sits before the command name.
        for (body, tool) in [
            ("(useradd -r foo)", "useradd"),
            ("( useradd -r foo )", "useradd"),
            ("(groupadd -r foo)", "groupadd"),
        ] {
            let hits = direct_user_creation_in_body(body);
            assert_eq!(hits, vec![(tool, body.to_string())], "must fire: {body}");
        }
    }
}
