//! `SystemdInstallCheck` — systemd unit scriptlet presence.
//!
//! Ported from `rpmlint/checks/SystemdInstallCheck.py`. Four findings:
//! `systemd-service-without-service_add_pre`,
//! `systemd-service-without-service_add_post`,
//! `systemd-service-without-service_del_preun`,
//! `systemd-service-without-service_del_postun`.
//!
//! A unit-named symlink is an alias (the D-Bus activation names are the
//! common case), not an independent unit: it is resolved within the package
//! and the target unit is evaluated instead, once. A symlink that resolves
//! to no shipped unit is not evaluated.
//!
//! One `del_preun`-only credit diverges from the reference's literal
//! substring predicate: a `%preun` helper line naming a `.service` unit
//! by its bare stem (the helper passes its arguments verbatim to
//! `systemctl disable --now`, which resolves a bare name to the `.service`).
//! The stem must be a whole shell word of a genuine
//! `systemd-update-helper remove-system-units` invocation, and a stem
//! carrying a dot is not bare at all. The add_pre and add_post arms
//! keep the literal predicate; del_postun credits bare stems the same way.

use std::path::Path;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::{is_reg, is_symlink};

use super::shared::script_body_or_prog;
use librpm::Tag;

pub struct SystemdInstallCheck {
    unit_regex: Regex,
    unit_dir: String,
}

impl SystemdInstallCheck {
    pub fn new(config: &Config) -> Self {
        // The reference expands `%{_unitdir}` at import time; rpmcrab has no
        // macro expansion, so the directory comes from configuration.
        let unit_dir = config
            .configuration
            .get("SystemdUnitDir")
            .and_then(|v| v.as_str())
            .unwrap_or("/usr/lib/systemd/system")
            .to_string();
        let unit_regex = Regex::new(&format!(
            r"^{}.+[^@]\.(service|socket|target|path)$",
            fancy_regex::escape(&unit_dir)
        ))
        .expect("unit regex");
        Self {
            unit_regex,
            unit_dir,
        }
    }

    /// The unit types the reference checks (compiled once in [`Self::new`];
    /// the directory comes from configuration, so this cannot be a static).
    fn unit_regex(&self) -> &Regex {
        &self.unit_regex
    }

    /// `(finding, ok)` for one unit file against the four scriptlets.
    ///
    /// `pre_direct` records whether the candidate sits directly under the
    /// unit directory: a path below a subdirectory (a `.wants` or
    /// `.requires` enablement link, or any other subdir entry) is not a
    /// unit definition systemd loads from the unit directory, so it draws
    /// no `add_pre` finding. The other three findings are evaluated for
    /// it unchanged.
    ///
    /// `statically_enabled` is true when the package ships a symlink
    /// under `<unitdir>/*.wants/` resolving to this unit: systemd
    /// enables such a unit by the symlink itself, so no install call
    /// is owed for it.
    fn check_unit(
        basename: &str,
        pre_direct: bool,
        pre: &str,
        post: &str,
        preun: &str,
        postun: &str,
        statically_enabled: bool,
    ) -> Vec<&'static str> {
        let escaped = fancy_regex::escape(basename);
        // install-system-units itself runs `systemctl preset` on the
        // units it is given, so a %post line that presets or enables
        // this unit performs the same operation (enable is stronger
        // than preset). Other verbs, other units, and %posttrans earn
        // no credit: only the %post scriptlet is examined here.
        let manual_re = Regex::new(&format!(
            r"\bsystemctl\b.*\b(enable|preset)\b.*(?<![\w:.@-]){}(?![\w:.@-])",
            escaped
        ))
        .expect("manual systemctl pattern");
        let patterns = [
            (
                format!(
                    r"systemd-update-helper mark-install-system-units .*{}",
                    escaped
                ),
                pre,
                "systemd-service-without-service_add_pre",
            ),
            (
                format!(r"systemd-update-helper install-system-units .*{}", escaped),
                post,
                "systemd-service-without-service_add_post",
            ),
            (
                format!(r"systemd-update-helper remove-system-units .*{}", escaped),
                preun,
                "systemd-service-without-service_del_preun",
            ),
            (
                format!(
                    r"systemd-update-helper mark-restart-system-units .*{}",
                    escaped
                ),
                postun,
                "systemd-service-without-service_del_postun",
            ),
        ];
        let mut missing = Vec::new();
        for (pattern, script, finding) in &patterns {
            if *finding == "systemd-service-without-service_add_pre" && !pre_direct {
                continue;
            }
            let re = Regex::new(pattern).expect("unit pattern");
            let mut present = script.lines().any(|line| is_match(&re, line));
            // The del_preun bare-stem credit: the add_pre and add_post
            // arms keep the literal-substring predicate above.
            if !present && *finding == "systemd-service-without-service_del_preun" {
                present = Self::bare_stem_removed(basename, script);
            }
            if present {
                continue;
            }
            // The add_post credits apply to this arm only: the
            // other three scriptlets keep the reference behaviour.
            if *finding == "systemd-service-without-service_add_post" {
                if statically_enabled {
                    continue;
                }
                if script
                    .lines()
                    .any(|line| Self::manual_line_credits(line, &manual_re))
                {
                    continue;
                }
            }
            // Del_postun-only credits, none of which apply to the sibling
            // tags: the reference accepts
            // `%service_del_postun_without_restart`, and a bare service
            // stem in a mark-restart line marks the unit (see
            // `postun_marks_bare_service`).
            if *finding == "systemd-service-without-service_del_postun"
                && (postun.lines().any(|l| l.trim() == ":")
                    || Self::postun_marks_bare_service(basename, postun))
            {
                continue;
            }
            missing.push(*finding);
        }
        missing
    }

    /// Whether one %post line manually enables or presets a unit in
    /// system scope: full-line comments never credit, and a
    /// scope-changing flag moves the operation elsewhere, so it never
    /// credits the system unit. The scope test runs over the shared
    /// tokenizer's words, so a flag inside a comment or a quoted word
    /// counts exactly as the shell would see it: a trailing `# --user`
    /// comment denies nothing, a quoted `'--user'` still scopes away,
    /// and a remote-machine flag (`-H`, `--host`, `-M`, `--machine`,
    /// with or without `=value`) scopes away like `--user` does. The
    /// pattern itself runs against the comment-stripped line, so a
    /// commented-out systemctl invocation never credits.
    fn manual_line_credits(line: &str, manual_re: &Regex) -> bool {
        if line.trim_start().starts_with('#') {
            return false;
        }
        if Self::shell_words(line).iter().any(|(word, _, _)| {
            matches!(
                word.as_str(),
                "--user" | "--global" | "-H" | "-M" | "--host" | "--machine"
            ) || word.starts_with("--host=")
                || word.starts_with("--machine=")
        }) {
            return false;
        }
        is_match(manual_re, Self::strip_comment(line))
    }

    /// The line up to a `#` comment start: `#` begins a comment only
    /// at the start of a word (line start, after whitespace, or after
    /// a shell operator) and never inside quotes, so `foo#bar` keeps
    /// its `#` while `foo # bar` drops everything from the `#`.
    fn strip_comment(line: &str) -> &str {
        let bytes = line.as_bytes();
        let mut quote: Option<u8> = None;
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            match quote {
                Some(q) => {
                    if b == q {
                        quote = None;
                    }
                }
                None => {
                    if b == b'"' || b == b'\'' {
                        quote = Some(b);
                    } else if b == b'#'
                        && (i == 0
                            || bytes[i - 1].is_ascii_whitespace()
                            || matches!(
                                bytes[i - 1],
                                b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>'
                            ))
                    {
                        return &line[..i];
                    }
                }
            }
            i += 1;
        }
        line
    }

    /// Whether `stem` is a bare name systemctl resolves with the default
    /// `.service` suffix. Only a suffix-less stem gains `.service`:
    /// systemctl appends the suffix only when the name has no dot, so
    /// any dotted stem names a unit of its own suffix (or is invalid),
    /// never the `.service` unit of that name (`foo.timer` is the timer,
    /// and `foo.bar` names no `.service` unit). No unit-type suffix
    /// list is consulted.
    fn stem_is_bare(stem: &str) -> bool {
        !stem.contains('.')
    }

    /// Split a scriptlet line into shell words. Each word is flagged as
    /// starting a command (line start or just after a command separator)
    /// and as a redirection target (the word after a redirection
    /// operator, which names no argument). ASCII whitespace only splits
    /// words; the operators `; & | ( )` separate words, single- and
    /// double-quoted spans are one word with quotes stripped, and `#`
    /// at the start of a word drops the rest of the line as a comment.
    /// An unterminated quote drops the whole line: the line would not
    /// execute as written, so it credits nothing. A redirection operator
    /// with a digit prefix (`2>`) drops the digit word with it, and the
    /// operator's target is flagged rather than starting a command, so
    /// arguments after a redirection still count.
    /// Backslash is an ordinary word character: escapes are not
    /// interpreted, and a backslash-newline continuation is never joined,
    /// since tokenization is per-line and cannot see the next line.
    fn shell_words(line: &str) -> Vec<(String, bool, bool)> {
        fn push_word(
            words: &mut Vec<(String, bool, bool)>,
            cur: &mut String,
            word_command: bool,
            word_target: bool,
            at_command: &mut bool,
        ) {
            let word = std::mem::take(cur);
            *at_command = false;
            words.push((word, word_command, word_target));
        }
        let chars: Vec<char> = line.chars().collect();
        let mut words: Vec<(String, bool, bool)> = Vec::new();
        let mut cur = String::new();
        let mut in_word = false;
        let mut at_command = true;
        let mut word_command = false;
        let mut word_target = false;
        let mut quote: Option<char> = None;
        let mut redir_op = false;
        let mut redir_target_next = false;
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if let Some(q) = quote {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
                i += 1;
                continue;
            }
            if redir_op {
                match c {
                    '<' | '>' | '&' => {
                        i += 1;
                        continue;
                    }
                    c if c.is_ascii_whitespace() => {
                        redir_op = false;
                        redir_target_next = true;
                        i += 1;
                        continue;
                    }
                    _ => {
                        redir_op = false;
                        redir_target_next = true;
                        continue;
                    }
                }
            }
            match c {
                '\'' | '"' => {
                    if !in_word {
                        word_command = at_command && !redir_target_next;
                        word_target = redir_target_next;
                        redir_target_next = false;
                        in_word = true;
                        at_command = false;
                    }
                    quote = Some(c);
                    i += 1;
                }
                '#' if !in_word => break,
                c if c.is_ascii_whitespace() => {
                    if in_word {
                        push_word(
                            &mut words,
                            &mut cur,
                            word_command,
                            word_target,
                            &mut at_command,
                        );
                        in_word = false;
                    }
                    i += 1;
                }
                ';' | '&' | '|' | '(' | ')' => {
                    if in_word {
                        push_word(
                            &mut words,
                            &mut cur,
                            word_command,
                            word_target,
                            &mut at_command,
                        );
                        in_word = false;
                    }
                    redir_target_next = false;
                    at_command = true;
                    i += 1;
                }
                '<' | '>' => {
                    if in_word {
                        if cur.chars().all(|d| d.is_ascii_digit()) {
                            // File-descriptor prefix: dropped with the
                            // operator, never an argument.
                            cur.clear();
                            in_word = false;
                        } else {
                            push_word(
                                &mut words,
                                &mut cur,
                                word_command,
                                word_target,
                                &mut at_command,
                            );
                            in_word = false;
                        }
                    }
                    redir_target_next = false;
                    redir_op = true;
                    i += 1;
                }
                _ => {
                    if !in_word {
                        word_command = at_command && !redir_target_next;
                        word_target = redir_target_next;
                        redir_target_next = false;
                        in_word = true;
                        at_command = false;
                    }
                    cur.push(c);
                    i += 1;
                }
            }
        }
        if quote.is_some() {
            return Vec::new();
        }
        if in_word {
            push_word(
                &mut words,
                &mut cur,
                word_command,
                word_target,
                &mut at_command,
            );
        }
        words
    }

    /// Whether a genuine `systemd-update-helper <verb>` invocation on this
    /// line names `stem` as an argument. The helper word must start a
    /// command and be followed by the verb as its own word in the same
    /// command, so a bare verb substring (another command, a comment, a
    /// longer word, a verb after an operator) never counts, and every
    /// invocation on the line is examined. Arguments end at the next
    /// command; redirection targets are skipped, not counted. A helper
    /// word spelled with an absolute directory prefix counts
    /// (`/usr/lib/systemd/systemd-update-helper` is the same helper); a
    /// relative-path spelling does not. Arguments are checked while
    /// scanning, without collecting them.
    fn helper_names_stem(line: &str, verb: &str, stem: &str) -> bool {
        let words = Self::shell_words(line);
        let mut i = 0;
        while i < words.len() {
            let (word, command, _) = &words[i];
            let is_helper = word == "systemd-update-helper"
                || (word.starts_with('/') && word.ends_with("/systemd-update-helper"));
            if *command
                && is_helper
                && i + 1 < words.len()
                && words[i + 1].0 == verb
                && !words[i + 1].1
            {
                let mut j = i + 2;
                while j < words.len() && !words[j].1 {
                    if !words[j].2 && words[j].0 == stem {
                        return true;
                    }
                    j += 1;
                }
                i = j;
            } else {
                i += 1;
            }
        }
        false
    }

    /// Whether a `mark-restart-system-units` line in `%postun` names a
    /// `.service` unit by its bare stem: a genuine helper invocation
    /// naming the stem as its own shell word, with no dot in the stem.
    /// Other unit types get no such credit, since a bare name never
    /// resolves to them.
    fn postun_marks_bare_service(basename: &str, postun: &str) -> bool {
        let Some(stem) = basename.strip_suffix(".service") else {
            return false;
        };
        if !Self::stem_is_bare(stem) {
            return false;
        }
        postun
            .lines()
            .any(|line| Self::helper_names_stem(line, "mark-restart-system-units", stem))
    }

    /// Whether a `%preun` helper line removes `basename` by its bare
    /// stem: a genuine `systemd-update-helper remove-system-units`
    /// invocation naming the stem as its own shell word, with no dot in
    /// the stem. Only `.service` units: a bare stem for a socket, target
    /// or path resolves to the `.service` of that name, a different unit,
    /// so those firings stay real.
    fn bare_stem_removed(basename: &str, preun: &str) -> bool {
        let Some(stem) = basename.strip_suffix(".service") else {
            return false;
        };
        if !Self::stem_is_bare(stem) {
            return false;
        }
        preun
            .lines()
            .any(|line| Self::helper_names_stem(line, "remove-system-units", stem))
    }
}

impl Check for SystemdInstallCheck {
    fn name(&self) -> &'static str {
        "SystemdInstallCheck"
    }

    /// This check never emits errors (its only emission site passes
    /// `Level::Warning`), so `--errors-only` skips it.
    fn max_severity(&self) -> Level {
        Level::Warning
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let unit_re = self.unit_regex();
        let pre = script_body_or_prog(pkg, Tag::PREIN, Tag::PREINPROG);
        let post = script_body_or_prog(pkg, Tag::POSTIN, Tag::POSTINPROG);
        let preun = script_body_or_prog(pkg, Tag::PREUN, Tag::PREUNPROG);
        let postun = script_body_or_prog(pkg, Tag::POSTUN, Tag::POSTUNPROG);

        // The reference walks pkg.files in order without sorting or deduping.
        //
        // A unit-named symlink is resolved within the package
        // (`Pkg::readlink`) and the target is the candidate instead, so an
        // alias draws no findings of its own and several aliases to one
        // target evaluate it once (deduplicated by resolved path, walk
        // order preserved). A link whose target is a shipped regular file
        // that is not itself a unit still names a unit -- systemd loads
        // that content under the link's name -- so the link stays the
        // candidate. A link resolving to no shipped regular file (dangling,
        // cyclic, or a mask link to /dev/null) names no evaluable unit and
        // is skipped; the dangling-symlink findings own that defect.
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut units: Vec<(String, bool)> = Vec::new();
        for file in &pkg.files {
            if !is_match(unit_re, &file.name) {
                continue;
            }
            let candidate = if is_symlink(file.mode) {
                match pkg.readlink(file) {
                    Some(target) if is_match(unit_re, &target.name) => target,
                    Some(target) if is_reg(target.mode) => file,
                    _ => continue,
                }
            } else {
                file
            };
            if !seen.insert(candidate.name.as_str()) {
                continue;
            }
            let pre_direct = candidate
                .name
                .strip_prefix(&format!("{}/", self.unit_dir))
                .map(|rest| !rest.contains('/'))
                .unwrap_or(true);
            let basename = Path::new(&candidate.name)
                .file_name()
                .map(|b| b.to_string_lossy().into_owned())
                .unwrap_or_default();
            units.push((basename, pre_direct));
        }

        // Basenames of units statically enabled by a shipped wants
        // symlink: a symlink directly under `<unitdir>/*.wants/` whose
        // target resolves within the package. A regular file in a wants
        // directory, a wants link outside the unit directory, a link
        // nested below a wants directory, and a link resolving to no
        // shipped file earn no credit. The credit is keyed by the link's
        // basename: systemd enables the name the link carries, so a
        // wants link for another unit never credits this one. With no
        // units found, there is nothing to credit.
        let wants_prefix = format!("{}/", self.unit_dir);
        let mut statically_enabled: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        if !units.is_empty() {
            for file in &pkg.files {
                if !is_symlink(file.mode) {
                    continue;
                }
                // Parent-directory scope: the link must sit directly in
                // a `.wants` directory directly under the unit directory;
                // a `.wants` segment deeper in the path earns nothing.
                let Some((parent, link_basename)) = file.name.rsplit_once('/') else {
                    continue;
                };
                let Some(wants_dir) = parent.strip_prefix(&wants_prefix) else {
                    continue;
                };
                if wants_dir.contains('/') || !wants_dir.ends_with(".wants") {
                    continue;
                }
                if pkg.readlink(file).is_some() {
                    statically_enabled.insert(link_basename);
                }
            }
        }

        for (basename, pre_direct) in &units {
            for finding in Self::check_unit(
                basename,
                *pre_direct,
                &pre,
                &post,
                &preun,
                &postun,
                statically_enabled.contains(basename.as_str()),
            ) {
                add_info(out, Level::Warning, pkg, finding, &[basename]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_present_is_quiet() {
        let script = "systemd-update-helper mark-install-system-units foo.service\n\
                      systemd-update-helper install-system-units foo.service\n\
                      systemd-update-helper remove-system-units foo.service\n\
                      systemd-update-helper mark-restart-system-units foo.service";
        let missing = SystemdInstallCheck::check_unit(
            "foo.service",
            true,
            script,
            script,
            script,
            script,
            false,
        );
        assert!(missing.is_empty(), "{missing:?}");
    }

    #[test]
    fn missing_pre_is_flagged() {
        let missing = SystemdInstallCheck::check_unit("foo.service", true, "", "", "", "", false);
        assert_eq!(missing.len(), 4);
        assert!(missing.contains(&"systemd-service-without-service_add_pre"));
    }

    #[test]
    fn postun_without_restart_is_accepted() {
        let missing =
            SystemdInstallCheck::check_unit("foo.service", true, "", "", "", ":\n", false);
        assert!(!missing.contains(&"systemd-service-without-service_del_postun"));
        assert_eq!(missing.len(), 3);
    }

    #[test]
    fn postun_bare_service_stem_is_accepted() {
        let postun = "systemd-update-helper mark-restart-system-units pmcd pmlogger || :";
        let missing =
            SystemdInstallCheck::check_unit("pmcd.service", true, "", "", "", postun, false);
        assert!(!missing.contains(&"systemd-service-without-service_del_postun"));
        assert_eq!(missing.len(), 3);
    }

    #[test]
    fn postun_quoted_bare_stem_is_credited() {
        let postun = "systemd-update-helper mark-restart-system-units \"pmcd\" || :";
        let missing =
            SystemdInstallCheck::check_unit("pmcd.service", true, "", "", "", postun, false);
        assert!(!missing.contains(&"systemd-service-without-service_del_postun"));
    }

    #[test]
    fn postun_bare_instantiated_template_stem_is_accepted() {
        let postun = "systemd-update-helper mark-restart-system-units foo@bar";
        let missing =
            SystemdInstallCheck::check_unit("foo@bar.service", true, "", "", "", postun, false);
        assert!(!missing.contains(&"systemd-service-without-service_del_postun"));
    }

    #[test]
    fn postun_bare_stem_near_misses_still_fire() {
        // Longer name sharing the stem.
        let missing = SystemdInstallCheck::check_unit(
            "foo.service",
            true,
            "",
            "",
            "",
            "systemd-update-helper mark-restart-system-units foobar.service",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_postun"));
        // Different suffix: marking the timer does not mark the service.
        let missing = SystemdInstallCheck::check_unit(
            "foo.service",
            true,
            "",
            "",
            "",
            "systemd-update-helper mark-restart-system-units foo.timer",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_postun"));
        // Bare names never resolve to non-service types.
        let missing = SystemdInstallCheck::check_unit(
            "foo.socket",
            true,
            "",
            "",
            "",
            "systemd-update-helper mark-restart-system-units foo",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_postun"));
        // Template stem names the template, not the instance.
        let missing = SystemdInstallCheck::check_unit(
            "foo@bar.service",
            true,
            "",
            "",
            "",
            "systemd-update-helper mark-restart-system-units foo@",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_postun"));
    }

    #[test]
    fn postun_bare_stem_helper_prefix_and_boundaries() {
        // Echo of the bare action name does not credit.
        let missing = SystemdInstallCheck::check_unit(
            "pmcd.service",
            true,
            "",
            "",
            "",
            "echo mark-restart-system-units pmcd",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_postun"));
        // Longer action spelling does not credit.
        let missing = SystemdInstallCheck::check_unit(
            "pmcd.service",
            true,
            "",
            "",
            "",
            "systemd-update-helper mark-restart-system-units-foo pmcd",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_postun"));
        // Shell operators end the invocation, so a stem after one is a separate command and does not credit.
        let missing = SystemdInstallCheck::check_unit(
            "pmcd.service",
            true,
            "",
            "",
            "",
            "systemd-update-helper mark-restart-system-units foo;pmcd || :",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_postun"));
        // Commas separate nothing: a comma-glued stem does not credit.
        let missing = SystemdInstallCheck::check_unit(
            "pmcd.service",
            true,
            "",
            "",
            "",
            "systemd-update-helper mark-restart-system-units foo,pmcd",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_postun"));
        let missing = SystemdInstallCheck::check_unit(
            "pmcd.service",
            true,
            "",
            "",
            "",
            "systemd-update-helper mark-restart-system-units ,pmcd",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_postun"));
        // The helper is invoked by path in real scriptlets.
        let missing = SystemdInstallCheck::check_unit(
            "pmcd.service",
            true,
            "",
            "",
            "",
            "/usr/lib/systemd/systemd-update-helper mark-restart-system-units pmcd",
            false,
        );
        assert!(!missing.contains(&"systemd-service-without-service_del_postun"));
        // Any dotted stem names no .service unit, so foo.bar does not
        // credit even though its suffix is not a unit type.
        let missing = SystemdInstallCheck::check_unit(
            "foo.bar.service",
            true,
            "",
            "",
            "",
            "systemd-update-helper mark-restart-system-units foo.bar",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_postun"));
    }

    #[test]
    fn sibling_tags_ignore_bare_stems() {
        let script = "systemd-update-helper mark-install-system-units foo\n\
                      systemd-update-helper install-system-units foo\n\
                      systemd-update-helper remove-system-units foobar\n\
                      systemd-update-helper mark-restart-system-units foo";
        let missing = SystemdInstallCheck::check_unit(
            "foo.service",
            true,
            script,
            script,
            script,
            script,
            false,
        );
        assert!(!missing.contains(&"systemd-service-without-service_del_postun"));
        assert!(missing.contains(&"systemd-service-without-service_add_pre"));
        assert!(missing.contains(&"systemd-service-without-service_add_post"));
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        assert_eq!(missing.len(), 3);
    }

    #[test]
    fn socket_unit_is_ignored_by_regex() {
        let check = SystemdInstallCheck::new(&Config::default());
        let re = check.unit_regex();
        assert!(!is_match(re, "/usr/lib/systemd/system/foo@.service"));
        assert!(is_match(re, "/usr/lib/systemd/system/foo.service"));
    }

    #[test]
    fn unit_dir_comes_from_config() {
        let mut table = toml::Table::new();
        table.insert(
            "SystemdUnitDir".to_string(),
            toml::Value::String("/run/systemd/system".to_string()),
        );
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let check = SystemdInstallCheck::new(&config);
        let re = check.unit_regex();
        assert!(is_match(re, "/run/systemd/system/foo.service"));
        assert!(!is_match(re, "/usr/lib/systemd/system/foo.service"));
    }

    use crate::check::Check;
    use crate::filter::Filter;
    use crate::pkg::pkgfile::PkgFile;

    /// The wpa-shaped fixture header: scriptlets carrying all four
    /// systemd-update-helper calls for `w720.service`. With `files` given,
    /// the header's file list is replaced wholesale.
    fn alias_pkg(files: Option<Vec<PkgFile>>) -> Pkg {
        let rpm = format!(
            "{}/../../tests/parity/pkg/inputs/w6-systemd-alias-1.0-1.noarch.rpm",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut pkg = Pkg::open_no_extract(Path::new(&rpm)).expect("open alias fixture");
        if let Some(files) = files {
            pkg.files = files;
        }
        pkg
    }

    fn reg(name: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o100644,
            ..Default::default()
        }
    }

    fn link(name: &str, target: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            mode: 0o120777,
            linkto: target.to_string(),
            ..Default::default()
        }
    }

    fn run(pkg: &Pkg) -> Vec<(String, String)> {
        let config = Config::default();
        let mut check = SystemdInstallCheck::new(&config);
        let mut out = Filter::new(&config, crate::color::Color::for_tty(false)).expect("filter");
        check.check_binary(pkg, &config, &mut out);
        out.results().to_vec()
    }

    /// Findings of this check naming `detail` (a unit basename).
    fn on(results: &[(String, String)], detail: &str) -> usize {
        results
            .iter()
            .filter(|(_, line)| {
                line.contains("systemd-service-without-service_") && line.contains(detail)
            })
            .count()
    }

    const UNIT: &str = "/usr/lib/systemd/system";

    #[test]
    fn dbus_alias_fixture_is_quiet() {
        // The shipped shape: an equipped unit plus two D-Bus alias symlinks
        // to it. The aliases are not independent units.
        let pkg = alias_pkg(None);
        let results = run(&pkg);
        assert!(results.is_empty(), "{results:?}");
    }

    #[test]
    fn alias_to_unequipped_target_fires_once_on_the_target() {
        let pkg = alias_pkg(Some(vec![
            link(&format!("{UNIT}/a1.service"), "bare720.service"),
            link(&format!("{UNIT}/a2.service"), "bare720.service"),
            reg(&format!("{UNIT}/bare720.service")),
        ]));
        let results = run(&pkg);
        assert_eq!(results.len(), 4, "{results:?}");
        assert_eq!(on(&results, "bare720.service"), 4);
        assert_eq!(on(&results, "a1.service"), 0);
        assert_eq!(on(&results, "a2.service"), 0);
    }

    #[test]
    fn dangling_alias_is_not_evaluated() {
        let pkg = alias_pkg(Some(vec![link(
            &format!("{UNIT}/dangling720.service"),
            "missing720.service",
        )]));
        let results = run(&pkg);
        assert!(results.is_empty(), "{results:?}");
    }

    #[test]
    fn mask_link_is_not_evaluated() {
        let pkg = alias_pkg(Some(vec![link(
            &format!("{UNIT}/masked720.service"),
            "/dev/null",
        )]));
        let results = run(&pkg);
        assert!(results.is_empty(), "{results:?}");
    }

    #[test]
    fn alias_chain_resolves_to_the_equipped_target() {
        let pkg = alias_pkg(Some(vec![
            reg(&format!("{UNIT}/w720.service")),
            link(&format!("{UNIT}/mid720.service"), "w720.service"),
            link(&format!("{UNIT}/top720.service"), "mid720.service"),
        ]));
        let results = run(&pkg);
        assert!(results.is_empty(), "{results:?}");
    }

    #[test]
    fn unit_link_to_a_non_unit_file_is_evaluated_under_its_own_name() {
        let pkg = alias_pkg(Some(vec![
            link(
                &format!("{UNIT}/odd720.service"),
                "/usr/share/w720/odd.conf",
            ),
            reg("/usr/share/w720/odd.conf"),
        ]));
        let results = run(&pkg);
        assert_eq!(results.len(), 4, "{results:?}");
        assert_eq!(on(&results, "odd720.service"), 4);
    }

    #[test]
    fn unrelated_symlink_does_not_suppress_a_real_unit() {
        let pkg = alias_pkg(Some(vec![
            reg(&format!("{UNIT}/bare720.service")),
            reg("/usr/libexec/w720tool-real"),
            link("/usr/bin/w720tool", "../libexec/w720tool-real"),
        ]));
        let results = run(&pkg);
        assert_eq!(results.len(), 4, "{results:?}");
        assert_eq!(on(&results, "bare720.service"), 4);
    }

    #[test]
    fn alias_cycle_is_not_evaluated() {
        let pkg = alias_pkg(Some(vec![
            link(&format!("{UNIT}/loop1.service"), "loop2.service"),
            link(&format!("{UNIT}/loop2.service"), "loop1.service"),
        ]));
        let results = run(&pkg);
        assert!(results.is_empty(), "{results:?}");
    }
    /// Per-tag count for a detail in `check_binary` results.
    fn on_tag(results: &[(String, String)], tag: &str, detail: &str) -> usize {
        results
            .iter()
            .filter(|(check, line)| check == tag && line.contains(detail))
            .count()
    }

    #[test]
    fn non_direct_candidate_suppresses_add_pre_only() {
        let missing = SystemdInstallCheck::check_unit("foo.service", false, "", "", "", "", false);
        assert!(!missing.contains(&"systemd-service-without-service_add_pre"));
        assert!(missing.contains(&"systemd-service-without-service_add_post"));
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        assert!(missing.contains(&"systemd-service-without-service_del_postun"));
        assert_eq!(missing.len(), 3, "{missing:?}");
    }

    #[test]
    fn wants_link_duplicate_suppresses_add_pre_and_add_post() {
        // The dracut shape: a direct unit-dir link to a shipped non-unit
        // file, plus the same unit name as a `.wants` enablement link.
        // The direct candidate still fires `add_pre`; the `.wants`
        // candidate fires the other three findings except `add_post`,
        // which the shipped `.wants` symlink itself credits for both
        // candidates (same basename).
        let pkg = alias_pkg(Some(vec![
            reg("/usr/lib/dracut/modules.d/77dracut-systemd/dracut-cmdline.service"),
            link(
                &format!("{UNIT}/dracut-cmdline.service"),
                "../../dracut/modules.d/77dracut-systemd/dracut-cmdline.service",
            ),
            link(
                &format!("{UNIT}/initrd.target.wants/dracut-cmdline.service"),
                "../dracut-cmdline.service",
            ),
        ]));
        let results = run(&pkg);
        assert_eq!(results.len(), 5, "{results:?}");
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_pre",
                "dracut-cmdline.service"
            ),
            1
        );
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_post",
                "dracut-cmdline.service"
            ),
            0
        );
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_del_preun",
                "dracut-cmdline.service"
            ),
            2
        );
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_del_postun",
                "dracut-cmdline.service"
            ),
            2
        );
    }

    #[test]
    fn subdir_unit_file_suppresses_add_pre_only() {
        // The blog shape: the only candidate is a regular file below a
        // `.wants` directory, not a unit definition directly under the
        // unit directory. No `add_pre` finding; the other three stand.
        let pkg = alias_pkg(Some(vec![reg(&format!(
            "{UNIT}/systemd-ask-password-blog.service.wants/systemd-vconsole-setup.service"
        ))]));
        let results = run(&pkg);
        assert_eq!(results.len(), 3, "{results:?}");
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_pre",
                "systemd-vconsole-setup.service"
            ),
            0
        );
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_post",
                "systemd-vconsole-setup.service"
            ),
            1
        );
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_del_preun",
                "systemd-vconsole-setup.service"
            ),
            1
        );
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_del_postun",
                "systemd-vconsole-setup.service"
            ),
            1
        );
    }

    #[test]
    fn wants_alias_to_shipped_unit_still_fires_add_pre() {
        // Near miss: a `.wants` link that resolves to a shipped direct
        // unit is deduped onto that unit, whose candidate is direct, so
        // `add_pre` still fires. Suppression is judged on the candidate
        // path, not on the link that led to it.
        let pkg = alias_pkg(Some(vec![
            reg(&format!("{UNIT}/bare720.service")),
            link(
                &format!("{UNIT}/multi-user.target.wants/bare720.service"),
                "../bare720.service",
            ),
        ]));
        let results = run(&pkg);
        assert_eq!(results.len(), 3, "{results:?}");
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_pre",
                "bare720.service"
            ),
            1
        );
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_post",
                "bare720.service"
            ),
            0
        );
    }

    #[test]
    fn manual_preset_credits_add_post_only() {
        let post = "/usr/bin/systemctl --no-reload preset foo.service || :";
        let missing = SystemdInstallCheck::check_unit("foo.service", true, "", post, "", "", false);
        assert_eq!(missing.len(), 3, "{missing:?}");
        assert!(!missing.contains(&"systemd-service-without-service_add_post"));
        assert!(missing.contains(&"systemd-service-without-service_add_pre"));
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        assert!(missing.contains(&"systemd-service-without-service_del_postun"));
    }

    #[test]
    fn manual_enable_with_flags_credits_add_post_only() {
        let post = "/usr/bin/systemctl --force enable foo.service || :";
        let missing = SystemdInstallCheck::check_unit("foo.service", true, "", post, "", "", false);
        assert_eq!(missing.len(), 3, "{missing:?}");
        assert!(!missing.contains(&"systemd-service-without-service_add_post"));
    }

    #[test]
    fn manual_handling_of_other_unit_does_not_credit() {
        let post = "systemctl enable bar.service";
        let missing = SystemdInstallCheck::check_unit("foo.service", true, "", post, "", "", false);
        assert!(missing.contains(&"systemd-service-without-service_add_post"));
    }

    #[test]
    fn manual_scope_flags_in_comments_and_quotes() {
        // A scope flag in a trailing comment denies nothing: the
        // operation itself runs in system scope.
        let post = "systemctl preset foo.service # --user";
        let missing = SystemdInstallCheck::check_unit("foo.service", true, "", post, "", "", false);
        assert!(!missing.contains(&"systemd-service-without-service_add_post"));
        // A quoted scope flag still scopes away: the shell strips the
        // quotes before systemctl sees the flag.
        let post = "systemctl preset '--user' foo.service";
        let missing = SystemdInstallCheck::check_unit("foo.service", true, "", post, "", "", false);
        assert!(missing.contains(&"systemd-service-without-service_add_post"));
        // A commented-out invocation never credits.
        let post = "echo hi # systemctl preset foo.service";
        let missing = SystemdInstallCheck::check_unit("foo.service", true, "", post, "", "", false);
        assert!(missing.contains(&"systemd-service-without-service_add_post"));
        // A `#` inside quotes is not a comment start.
        let post = "systemctl preset 'foo#bar.service'";
        let missing =
            SystemdInstallCheck::check_unit("foo#bar.service", true, "", post, "", "", false);
        assert!(!missing.contains(&"systemd-service-without-service_add_post"));
    }

    #[test]
    fn manual_remote_machine_flags_do_not_credit() {
        for post in [
            "systemctl -H remote preset foo.service",
            "systemctl --host=remote preset foo.service",
            "systemctl -M container preset foo.service",
            "systemctl --machine=container enable foo.service",
        ] {
            let missing =
                SystemdInstallCheck::check_unit("foo.service", true, "", post, "", "", false);
            assert!(
                missing.contains(&"systemd-service-without-service_add_post"),
                "{post} must not credit: {missing:?}"
            );
        }
    }

    #[test]
    fn manual_is_enabled_does_not_credit() {
        let post = "systemctl --quiet is-enabled foo.service";
        let missing = SystemdInstallCheck::check_unit("foo.service", true, "", post, "", "", false);
        assert!(missing.contains(&"systemd-service-without-service_add_post"));
    }

    #[test]
    fn static_enable_credits_add_post_only() {
        let missing = SystemdInstallCheck::check_unit("foo.service", true, "", "", "", "", true);
        assert_eq!(missing.len(), 3, "{missing:?}");
        assert!(!missing.contains(&"systemd-service-without-service_add_post"));
        let missing = SystemdInstallCheck::check_unit("foo.service", true, "", "", "", "", false);
        assert_eq!(missing.len(), 4, "{missing:?}");
    }

    #[test]
    fn wants_symlink_credits_add_post_only() {
        let pkg = alias_pkg(Some(vec![
            reg(&format!("{UNIT}/want720.service")),
            link(
                &format!("{UNIT}/multi-user.target.wants/want720.service"),
                "../want720.service",
            ),
        ]));
        let results = run(&pkg);
        assert_eq!(results.len(), 3, "{results:?}");
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_post",
                "want720.service"
            ),
            0
        );
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_pre",
                "want720.service"
            ),
            1
        );
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_del_preun",
                "want720.service"
            ),
            1
        );
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_del_postun",
                "want720.service"
            ),
            1
        );
    }

    #[test]
    fn wants_symlink_for_other_unit_does_not_credit() {
        // The other unit's target is shipped: the wants credit lands on
        // the other basename, so want720 still fires add_post. Without
        // the shipped target the link would dangle and the credit logic
        // would never run.
        let pkg = alias_pkg(Some(vec![
            reg(&format!("{UNIT}/want720.service")),
            reg(&format!("{UNIT}/other720.service")),
            link(
                &format!("{UNIT}/multi-user.target.wants/other720.service"),
                "../other720.service",
            ),
        ]));
        let results = run(&pkg);
        assert_eq!(results.len(), 7, "{results:?}");
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_post",
                "want720.service"
            ),
            1
        );
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_post",
                "other720.service"
            ),
            0
        );
    }

    #[test]
    fn wants_regular_file_does_not_credit() {
        let pkg = alias_pkg(Some(vec![reg(&format!(
            "{UNIT}/some720.service.wants/want720.service"
        ))]));
        let results = run(&pkg);
        // The regular file below a `.wants` directory is not a direct
        // candidate, so it draws no `add_pre` finding; `add_post` still
        // fires because a regular file earns no wants credit.
        assert_eq!(results.len(), 3, "{results:?}");
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_pre",
                "want720.service"
            ),
            0
        );
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_post",
                "want720.service"
            ),
            1
        );
    }

    #[test]
    fn wants_symlink_outside_unit_dir_does_not_credit() {
        // The outside link's target is shipped: the readlink succeeds,
        // so only the outside-unit-dir guard blocks the credit. Without
        // the shipped target the link would dangle and the guard would
        // never run.
        let pkg = alias_pkg(Some(vec![
            reg(&format!("{UNIT}/want720.service")),
            reg("/usr/lib/systemd/user/want720.service"),
            link(
                "/usr/lib/systemd/user/sockets.target.wants/want720.service",
                "../want720.service",
            ),
        ]));
        let results = run(&pkg);
        assert_eq!(results.len(), 4, "{results:?}");
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_post",
                "want720.service"
            ),
            1
        );
    }

    #[test]
    fn wants_link_credits_link_name_not_target_name() {
        // A wants link named differently from its target credits the
        // link's name: systemd enables the name the link carries. The
        // target unit itself still fires add_post, while the
        // link-named unit is credited.
        let pkg = alias_pkg(Some(vec![
            reg(&format!("{UNIT}/want720.service")),
            reg(&format!("{UNIT}/renamed720.service")),
            link(
                &format!("{UNIT}/multi-user.target.wants/renamed720.service"),
                "../want720.service",
            ),
        ]));
        let results = run(&pkg);
        assert_eq!(results.len(), 7, "{results:?}");
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_post",
                "want720.service"
            ),
            1
        );
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_post",
                "renamed720.service"
            ),
            0
        );
    }

    #[test]
    fn wants_link_nested_below_wants_dir_does_not_credit() {
        // A link below a nested wants directory is not directly in a
        // wants directory under the unit dir, so it earns no credit
        // even though its target is shipped.
        let pkg = alias_pkg(Some(vec![
            reg(&format!("{UNIT}/want720.service")),
            link(
                &format!("{UNIT}/multi-user.target.wants/sub/want720.service"),
                "../../want720.service",
            ),
        ]));
        let results = run(&pkg);
        assert_eq!(results.len(), 4, "{results:?}");
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_post",
                "want720.service"
            ),
            1
        );
    }

    #[test]
    fn manual_comment_line_does_not_credit() {
        let post = "# systemctl enable foo.service";
        let missing = SystemdInstallCheck::check_unit("foo.service", true, "", post, "", "", false);
        assert!(missing.contains(&"systemd-service-without-service_add_post"));
    }

    #[test]
    fn manual_user_scope_does_not_credit() {
        for post in [
            "systemctl --user enable foo.service",
            "systemctl --global enable foo.service",
        ] {
            let missing =
                SystemdInstallCheck::check_unit("foo.service", true, "", post, "", "", false);
            assert!(
                missing.contains(&"systemd-service-without-service_add_post"),
                "{post}: {missing:?}"
            );
        }
    }

    #[test]
    fn manual_unit_name_boundaries() {
        // A longer name sharing the stem, a suffixed name, a
        // hyphen-joined name, and a foreign command name are all
        // different units and earn no credit.
        for post in [
            "systemctl enable myfoo.service",
            "systemctl enable foo.service.bak",
            "systemctl enable prefix-foo.service",
            "foosystemctl enable foo.service",
        ] {
            let missing =
                SystemdInstallCheck::check_unit("foo.service", true, "", post, "", "", false);
            assert!(
                missing.contains(&"systemd-service-without-service_add_post"),
                "{post}: {missing:?}"
            );
        }
    }

    /// `del_preun` credits live only on that arm: the other three arms
    /// keep the literal-substring predicate.
    fn missing_with(preun: &str) -> Vec<&'static str> {
        SystemdInstallCheck::check_unit("foo.service", true, "", "", preun, "", false)
    }

    #[test]
    fn bare_stem_service_is_credited() {
        let missing = missing_with("systemd-update-helper remove-system-units foo || :");
        assert!(
            !missing.contains(&"systemd-service-without-service_del_preun"),
            "{missing:?}"
        );
        assert_eq!(missing.len(), 3);
    }

    #[test]
    fn bare_stem_socket_is_not_credited() {
        let missing = SystemdInstallCheck::check_unit(
            "foo.socket",
            true,
            "",
            "",
            "systemd-update-helper remove-system-units foo || :",
            "",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
    }

    #[test]
    fn bare_stem_target_is_not_credited() {
        let missing = SystemdInstallCheck::check_unit(
            "foo.target",
            true,
            "",
            "",
            "systemd-update-helper remove-system-units foo || :",
            "",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
    }

    #[test]
    fn bare_stem_path_is_not_credited() {
        let missing = SystemdInstallCheck::check_unit(
            "foo.path",
            true,
            "",
            "",
            "systemd-update-helper remove-system-units foo || :",
            "",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
    }

    #[test]
    fn longer_full_name_does_not_credit_shorter_unit() {
        let missing = missing_with("systemd-update-helper remove-system-units foobar.service || :");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
    }

    #[test]
    fn longer_stem_does_not_credit_shorter_unit() {
        let missing = missing_with("systemd-update-helper remove-system-units foobar || :");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
    }

    #[test]
    fn no_argument_helper_does_not_credit() {
        // The atuin-server shape: a helper call with no unit argument
        // removes nothing.
        let missing = missing_with("systemd-update-helper remove-system-units || :");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
    }

    #[test]
    fn quoted_bare_stem_is_credited() {
        let missing = missing_with("systemd-update-helper remove-system-units \"foo\" || :");
        assert!(
            !missing.contains(&"systemd-service-without-service_del_preun"),
            "{missing:?}"
        );
    }

    #[test]
    fn stem_only_in_comment_is_not_credited() {
        let missing = missing_with("systemd-update-helper remove-system-units bar # foo");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
    }

    #[test]
    fn backslash_continuation_is_not_joined() {
        let missing = missing_with("systemd-update-helper remove-system-units \\\nfoo.service");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
    }

    #[test]
    fn helper_prefix_is_required() {
        // A bare verb substring is not a helper call: another command,
        // a longer word, and a full-comment line all fail to credit.
        let missing = missing_with("echo systemd-update-helper remove-system-units foo");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        let missing = missing_with("xsystemd-update-helper remove-system-units foo");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        let missing = missing_with("# systemd-update-helper remove-system-units foo");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        // A directory-prefixed helper spelling counts: same helper.
        let missing =
            missing_with("/usr/lib/systemd/systemd-update-helper remove-system-units foo");
        assert!(
            !missing.contains(&"systemd-service-without-service_del_preun"),
            "{missing:?}"
        );
    }

    #[test]
    fn shell_operators_and_commas_tokenize() {
        // Operators separate words: foo before && or || credits.
        let missing = missing_with("systemd-update-helper remove-system-units foo&&bar || :");
        assert!(
            !missing.contains(&"systemd-service-without-service_del_preun"),
            "{missing:?}"
        );
        // A comma is not a shell operator: foo,bar is one word, and a
        // trailing comma is part of the word, so neither credits foo.
        let missing = missing_with("systemd-update-helper remove-system-units foo,bar");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        let missing = missing_with("systemd-update-helper remove-system-units foo,");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        // A comment after an operator drops the rest of the line, but
        // the words before it still count.
        let missing = missing_with("systemd-update-helper remove-system-units foo;# foo");
        assert!(
            !missing.contains(&"systemd-service-without-service_del_preun"),
            "{missing:?}"
        );
    }

    #[test]
    fn quoted_stems_and_unterminated_quote() {
        let missing = missing_with("systemd-update-helper remove-system-units 'foo' || :");
        assert!(
            !missing.contains(&"systemd-service-without-service_del_preun"),
            "{missing:?}"
        );
        // An unterminated quote drops the partial word: the line would
        // not execute as written, so it credits nothing.
        let missing = missing_with("systemd-update-helper remove-system-units \"foo || :");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
    }

    #[test]
    fn dotted_stem_with_known_suffix_is_not_bare() {
        // foo.timer names the timer, not foo.timer.service.
        let missing = SystemdInstallCheck::check_unit(
            "foo.timer.service",
            true,
            "",
            "",
            "systemd-update-helper remove-system-units foo.timer",
            "",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        // Any dotted stem names no .service unit: foo.bar does not
        // name foo.bar.service.
        let missing = SystemdInstallCheck::check_unit(
            "foo.bar.service",
            true,
            "",
            "",
            "systemd-update-helper remove-system-units foo.bar",
            "",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
    }

    #[test]
    fn dotted_stem_with_known_suffix_is_not_bare_for_postun() {
        let missing = SystemdInstallCheck::check_unit(
            "foo.timer.service",
            true,
            "",
            "",
            "",
            "systemd-update-helper mark-restart-system-units foo.timer",
            false,
        );
        assert!(missing.contains(&"systemd-service-without-service_del_postun"));
    }

    #[test]
    fn tokenizer_edges() {
        // An unterminated quote drops the whole line, including words
        // completed before the quote: the line would not execute.
        let missing = missing_with("systemd-update-helper remove-system-units foo \"bar");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        // A verb after an operator is a new command, not this helper's
        // verb.
        let missing = missing_with("systemd-update-helper ; remove-system-units foo");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        let missing = missing_with("systemd-update-helper || remove-system-units foo");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        // Redirections neither start a command nor end the argument
        // list: arguments after the target still count, and the target
        // itself never counts as a stem.
        let missing = missing_with("systemd-update-helper remove-system-units foo > /dev/null");
        assert!(
            !missing.contains(&"systemd-service-without-service_del_preun"),
            "{missing:?}"
        );
        let missing = missing_with("systemd-update-helper remove-system-units > /dev/null foo");
        assert!(
            !missing.contains(&"systemd-service-without-service_del_preun"),
            "{missing:?}"
        );
        let missing = missing_with("systemd-update-helper remove-system-units foo>/dev/null");
        assert!(
            !missing.contains(&"systemd-service-without-service_del_preun"),
            "{missing:?}"
        );
        let missing = missing_with("systemd-update-helper remove-system-units foo 2>/dev/null");
        assert!(
            !missing.contains(&"systemd-service-without-service_del_preun"),
            "{missing:?}"
        );
        let missing = missing_with("systemd-update-helper remove-system-units > foo");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        // Non-ASCII whitespace does not split words.
        let missing = missing_with("systemd-update-helper remove-system-units\u{a0}foo");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
    }

    #[test]
    fn relative_path_helper_does_not_credit() {
        // Only a bare helper name or an absolute directory-prefixed
        // spelling counts; a relative-path spelling may be an impostor.
        let missing = missing_with("foo/systemd-update-helper remove-system-units foo");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        let missing = missing_with("./systemd-update-helper remove-system-units foo");
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
    }

    #[test]
    fn all_four_fire_without_helpers() {
        // No helper names the unit, so every arm fires: the del_preun
        // credit applies only to a genuine bare-stem helper line.
        let missing = SystemdInstallCheck::check_unit("foo.service", true, "", "", "", "", false);
        assert_eq!(missing.len(), 4);
    }

    /// Run the check over a fixture opened with payload extraction, so
    /// unit content is visible to the check.
    fn run_extracted(rpm_name: &str) -> Vec<(String, String)> {
        let rpm = format!(
            "{}/../../tests/parity/pkg/inputs/{}",
            env!("CARGO_MANIFEST_DIR"),
            rpm_name
        );
        let scratch = tempfile::tempdir().expect("scratch");
        let pkg = Pkg::open(Path::new(&rpm), scratch.path(), true).expect("open fixture");
        run(&pkg)
    }

    #[test]
    fn has_install_fixture_still_fires_del_preun() {
        // w6si.service carries [Install] and its %preun is absent, so
        // del_preun fires: no helper names it.
        let results = run_extracted("w6-systemd-install-1.0-1.noarch.rpm");
        assert_eq!(results.len(), 2, "{results:?}");
        assert!(results.iter().any(|(_, line)| {
            line.contains("systemd-service-without-service_del_preun")
                && line.contains("w6si.service")
        }));
        assert!(results.iter().any(|(_, line)| {
            line.contains("systemd-service-without-service_del_postun")
                && line.contains("w6si.service")
        }));
    }

    #[test]
    fn no_install_fixture_units_fire_del_preun_and_del_postun() {
        // w6ni.service ships no [Install] section, w6wi.service ships
        // one; both lack %preun/%postun. The no-[Install] credit was
        // dropped as unsound (remove-system-units also stops the unit,
        // and a unit without [Install] can still be running at erase
        // time), so both units fire del_preun as well as del_postun.
        let results = run_extracted("w6-systemd-noinstall-1.0-1.noarch.rpm");
        assert_eq!(results.len(), 4, "{results:?}");
        assert!(results.iter().any(|(_, line)| {
            line.contains("systemd-service-without-service_del_preun")
                && line.contains("w6ni.service")
        }));
        assert!(results.iter().any(|(_, line)| {
            line.contains("systemd-service-without-service_del_postun")
                && line.contains("w6ni.service")
        }));
        assert!(results.iter().any(|(_, line)| {
            line.contains("systemd-service-without-service_del_preun")
                && line.contains("w6wi.service")
        }));
        assert!(results.iter().any(|(_, line)| {
            line.contains("systemd-service-without-service_del_postun")
                && line.contains("w6wi.service")
        }));
    }

    #[test]
    fn planted_unit_without_wants_fires_all_four() {
        // A unit with no helper lines fires all four findings.
        let pkg = alias_pkg(Some(vec![reg(&format!("{UNIT}/planted.service"))]));
        let results = run(&pkg);
        assert_eq!(results.len(), 4, "{results:?}");
        assert_eq!(on(&results, "planted.service"), 4);
    }

    #[test]
    fn planted_unit_with_wants_entry_fires_del_preun() {
        // The unit candidate fires del_preun (no helper names it), and
        // the wants entry itself is a second candidate firing the other
        // three findings (its add_pre is suppressed as non-direct).
        let pkg = alias_pkg(Some(vec![
            reg(&format!("{UNIT}/planted.service")),
            reg(&format!("{UNIT}/multi-user.target.wants/planted.service")),
        ]));
        let results = run(&pkg);
        assert_eq!(results.len(), 7, "{results:?}");
        assert_eq!(on(&results, "planted.service"), 7);
    }

    #[test]
    fn planted_unit_with_alias_wants_fires_del_preun() {
        let pkg = alias_pkg(Some(vec![
            reg(&format!("{UNIT}/planted.service")),
            link(&format!("{UNIT}/planted-alias.service"), "planted.service"),
            reg(&format!(
                "{UNIT}/multi-user.target.wants/planted-alias.service"
            )),
        ]));
        let results = run(&pkg);
        assert_eq!(results.len(), 7, "{results:?}");
        assert_eq!(on(&results, "planted.service"), 4);
        assert_eq!(on(&results, "planted-alias.service"), 3);
    }

    #[test]
    fn no_install_fixture_without_extraction_still_fires_del_preun() {
        // Without extraction the fixture units fire del_preun as well as
        // del_postun, exactly as with extraction: no unit content is
        // read, so extraction changes nothing for this check.
        let rpm = format!(
            "{}/../../tests/parity/pkg/inputs/w6-systemd-noinstall-1.0-1.noarch.rpm",
            env!("CARGO_MANIFEST_DIR")
        );
        let pkg = Pkg::open_no_extract(Path::new(&rpm)).expect("open fixture");
        let results = run(&pkg);
        assert_eq!(results.len(), 4, "{results:?}");
        assert!(results.iter().any(|(_, line)| {
            line.contains("systemd-service-without-service_del_preun")
                && line.contains("w6ni.service")
        }));
        assert!(results.iter().any(|(_, line)| {
            line.contains("systemd-service-without-service_del_preun")
                && line.contains("w6wi.service")
        }));
    }
}
