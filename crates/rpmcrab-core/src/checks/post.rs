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

pub struct PostCheck {
    valid_shells: Vec<String>,
    empty_shells: Vec<String>,
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

    fn percent_regex() -> Regex {
        Regex::new(r"(?m)^[^#]*%+\{?\w{3,}").expect("static regex")
    }
    fn bracket_regex() -> Regex {
        Regex::new(r"(?m)^[^#]*if\s+[^ :\]]\]").expect("static regex")
    }
    fn home_regex() -> Regex {
        Regex::new(r"(?m)[^a-zA-Z]+~/|\$\{?HOME(\W|$)").expect("static regex")
    }
    fn dangerous_regex() -> Regex {
        Regex::new(
            r"(?m)(^|[;`|]|&&|$\()\s*(?:\S*/s?bin/)?(cp|mv|ln|tar|rpm|chmod|chown|rm|cpio|install|perl|userdel|groupdel)\s",
        )
        .expect("static regex")
    }
    fn selinux_regex() -> Regex {
        Regex::new(r"(?m)(^|[;`|]|&&|$\()\s*(?:\S*/s?bin/)?(chcon|runcon)\s").expect("static regex")
    }
    fn single_command_regex() -> Regex {
        Regex::new(r"^[ \n]*([^ \n]+)[ \n]*$").expect("static regex")
    }
    fn tmp_regex() -> Regex {
        Regex::new(r"(?m)^[^#]*\s(/var)?/tmp").expect("static regex")
    }
    fn bogus_var_regex() -> Regex {
        Regex::new(r"(\$\{?RPM_BUILD_(ROOT|DIR)}?)").expect("static regex")
    }

    /// `sh -n` / `perl -wc` syntax check via subprocess. `None` when the
    /// interpreter is unavailable (skipped, not an error).
    fn syntax_ok(prog: &str, args: &[&str], script: &str) -> Option<bool> {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("rpmcrab-postcheck-{}", std::process::id()));
        std::fs::write(&path, script).ok()?;
        let result = Command::new(prog).args(args).arg(&path).output().ok();
        std::fs::remove_file(&path).ok();
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
            if is_match(&Self::percent_regex(), script) {
                out.push((Level::Warning, finding("percent-in"), vec![]));
            }
            if is_match(&Self::bracket_regex(), script) {
                out.push((Level::Warning, finding("spurious-bracket-in"), vec![]));
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
                let menu_re =
                    Regex::new(r"^/usr/lib/menu/|^/etc/menu-methods/|^/usr/share/applications/")
                        .expect("static regex");
                if !files.iter().any(|f| is_match(&menu_re, f)) {
                    out.push((
                        Level::Error,
                        finding("update-menus-without-menu-file-in"),
                        vec![],
                    ));
                }
            }
            if is_match(&Self::tmp_regex(), script) {
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
            if is_match(&Self::home_regex(), script) {
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

        if prog == "/usr/bin/perl" {
            if let Some(ok) = Self::syntax_ok(prog, &["-wc"], script)
                && !ok
            {
                out.push((Level::Error, finding("perl-syntax-error-in"), vec![]));
            }
        } else if prog.ends_with("sh")
            && !prog.is_empty()
            && let Some(m) = Self::single_command_regex()
                .captures(script)
                .ok()
                .flatten()
                .and_then(|c| c.get(1))
        {
            out.push((
                Level::Warning,
                finding("one-line-command-in"),
                vec![m.as_str().to_string()],
            ));
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

impl Check for PostCheck {
    fn name(&self) -> &'static str {
        "PostCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        // (script tag, prog tag, macro name, is list) mirroring
        // Pkg.SCRIPT_TAGS. Trigger scriptlets store parallel arrays.
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
                if !postin.contains(f) && !prein.contains(f) {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "postin-without-ghost-file-creation",
                        &[f],
                    );
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
            valid_shells: vec!["/bin/sh".to_string(), "/usr/bin/perl".to_string()],
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
    fn empty_script_skips_content_checks() {
        // The reference gates check_aux on `if script:`; an empty body only
        // produces the empty-<tag> warning, never content findings.
        let found = check().check_scriptlet("/bad/sh", "", "%post", &[], &[]);
        assert!(found.is_empty());
    }

    #[test]
    fn percent_without_brace_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "echo %foo", "%post", &[], &[]);
        assert!(found.iter().any(|(_, f, _)| f == "percent-in-%post"));
    }

    #[test]
    fn percent_with_brace_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "echo %{foo}", "%post", &[], &[]);
        assert!(found.iter().any(|(_, f, _)| f == "percent-in-%post"));
    }

    #[test]
    fn single_line_command_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "/usr/bin/update-foo", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, d)| f == "one-line-command-in-%post"
                    && d == &vec!["/usr/bin/update-foo".to_string()])
        );
    }

    #[test]
    fn multi_word_command_is_not_one_line_command() {
        // The reference capture is [^ \n]+: a command with arguments is
        // not a one-line command.
        let found =
            check().check_scriptlet("/bin/sh", "/usr/bin/update-foo --bar", "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "one-line-command-in-%post")
        );
    }

    #[test]
    fn multi_line_script_is_not_one_line_command() {
        // No (?m): the reference only flags a script that is a single
        // command on its only line.
        let found = check().check_scriptlet("/bin/sh", "/usr/bin/a\n/usr/bin/b", "%post", &[], &[]);
        assert!(
            !found
                .iter()
                .any(|(_, f, _)| f == "one-line-command-in-%post")
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

    #[test]
    fn tmp_use_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "echo hi > /tmp/foo", "%post", &[], &[]);
        assert!(found.iter().any(|(_, f, _)| f == "use-tmp-in-%post"));
    }

    #[test]
    fn home_use_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "echo ~/foo", "%post", &[], &[]);
        assert!(found.iter().any(|(_, f, _)| f == "use-of-home-in-%post"));
    }

    #[test]
    fn bogus_var_is_flagged() {
        let found = check().check_scriptlet("/bin/sh", "echo $RPM_BUILD_ROOT", "%post", &[], &[]);
        assert!(
            found
                .iter()
                .any(|(_, f, _)| f == "bogus-variable-use-in-%post")
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
                .any(|(_, f, _)| f == "update-menus-without-menu-file-in-%post")
        );
    }

    #[test]
    fn parity_fixture_matches_reference() {
        // Pinned against reference rpmlint 2.10.0 (PostCheck.py at 84848c0):
        // the fixture produces exactly these two findings, in this order.
        let rpm_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/postcheck-parity-1.0-1.noarch.rpm");
        let pkg = Pkg::open(&rpm_path, &std::env::temp_dir()).expect("open fixture pkg");
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = PostCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let findings: Vec<(String, String)> = out
            .results()
            .iter()
            .map(|(name, _)| (name.clone(), String::new()))
            .collect();
        let names: Vec<&str> = findings.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["percent-in-%pre", "percent-in-%postun"]);
    }
}
