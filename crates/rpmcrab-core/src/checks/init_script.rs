//! `InitScriptCheck` — SysV init scripts must follow the LSB and chkconfig
//! conventions.
//!
//! Ported from `rpmlint/checks/InitScriptCheck.py`. Findings:
//! `init-script-non-executable`, `init-script-name-with-dot`,
//! `init-script-without-chkconfig-postin`, `postin-without-chkconfig`,
//! `init-script-without-chkconfig-preun`, `preun-without-chkconfig`,
//! `read-error`, `redundant-lsb-keyword`, `missing-lsb-keyword`,
//! `malformed-line-in-lsb-comment-block`, `unknown-lsb-keyword`,
//! `no-default-runlevel`, `service-default-enabled`, `incoherent-subsys`,
//! `no-status-entry`, `no-reload-entry`, `no-chkconfig-line`,
//! `subsys-not-used`, `subsys-unsupported`, `incoherent-init-script-name`.

use std::collections::HashMap;
use std::path::Path;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use librpm::Tag;

const LSB_KEYWORDS: &[&str] = &[
    "Provides",
    "Required-Start",
    "Required-Stop",
    "Should-Start",
    "Should-Stop",
    "Default-Start",
    "Default-Stop",
    "Short-Description",
    "Description",
];

const RECOMMENDED_LSB_KEYWORDS: &[&str] = &[
    "Provides",
    "Required-Start",
    "Required-Stop",
    "Default-Stop",
    "Short-Description",
];

/// Python's `str(OSError)` for the `read-error` detail: `[Errno 13] Permission
/// denied`. Rust's `Display` renders `Permission denied (os error 13)`.
fn os_error_detail(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => {
            let msg = e.to_string();
            let suffix = format!(" (os error {code})");
            let msg = msg.strip_suffix(&suffix).unwrap_or(&msg);
            format!("[Errno {code}] {msg}")
        }
        None => e.to_string(),
    }
}

pub struct InitScriptCheck {
    use_deflevels: bool,
    use_subsys: bool,
    chkconfig_content_re: Regex,
    subsys_re: Regex,
    chkconfig_re: Regex,
    status_re: Regex,
    reload_re: Regex,
    lsb_tags_re: Regex,
    lsb_cont_re: Regex,
    var_re: Regex,
}

impl InitScriptCheck {
    pub fn new(config: &Config) -> Self {
        let get_bool = |key: &str, default: bool| {
            config
                .configuration
                .get(key)
                .and_then(toml::Value::as_bool)
                .unwrap_or(default)
        };
        Self {
            use_deflevels: get_bool("UseDefaultRunlevels", true),
            use_subsys: get_bool("UseVarLockSubsys", true),
            chkconfig_content_re: Regex::new(r"^\s*#\s*chkconfig:\s*([-0-9]+)\s+[-0-9]+\s+[-0-9]+")
                .expect("static regex"),
            subsys_re: Regex::new(r#"/var/lock/subsys/([^/\"\'\s;&|]+)"#).expect("static regex"),
            chkconfig_re: Regex::new(r"(?m)^[^#]*(chkconfig|add-service|del-service)")
                .expect("static regex"),
            status_re: Regex::new(r"(?m)^[^#]*status").expect("static regex"),
            reload_re: Regex::new(r"(?m)^[^#]*reload").expect("static regex"),
            lsb_tags_re: Regex::new(r"^# ([\w-]+):\s*(.*?)\s*$").expect("static regex"),
            lsb_cont_re: Regex::new("^#(?:\t|  )(.*?)\\s*$").expect("static regex"),
            var_re: Regex::new(r"^(.*)\${?(\w+)}?(.*)$").expect("static regex"),
        }
    }

    /// The value of shell variable `var` in `script`, with nested references
    /// substituted. `None` on self-reference (infinite loop guard).
    fn shell_var_value(&self, var: &str, script: &str) -> Option<String> {
        let assign_re = Regex::new(&format!(
            r"(?m)\b{}\s*=\s*(.+)\s*(#.*)*$",
            fancy_regex::escape(var)
        ))
        .ok()?;
        let caps = assign_re.captures(script).ok().flatten()?;
        let value = caps.get(1)?.as_str();
        // Infinite loop guard: the value references the variable itself.
        if let Some(var_caps) = self.var_re.captures(value).ok().flatten()
            && var_caps.get(2).map(|m| m.as_str()) == Some(var)
        {
            return None;
        }
        Some(self.substitute_shell_vars(value, script))
    }

    /// Substitute `${var}`/`$var` references in `val` using `script`.
    fn substitute_shell_vars(&self, val: &str, script: &str) -> String {
        let Some(caps) = self.var_re.captures(val).ok().flatten() else {
            return val.to_string();
        };
        let var_name = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let value = self.shell_var_value(var_name, script).unwrap_or_default();
        let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let suffix = caps.get(3).map(|m| m.as_str()).unwrap_or("");
        format!("{prefix}{value}") + &self.substitute_shell_vars(suffix, script)
    }
}

impl Check for InitScriptCheck {
    fn name(&self) -> &'static str {
        "InitScriptCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }

        let mut initscripts: Vec<String> = Vec::new();
        for file in &pkg.files {
            let fname = file.name.as_str();
            if !fname.starts_with("/etc/init.d/") && !fname.starts_with("/etc/rc.d/init.d/") {
                continue;
            }
            let basename = Path::new(fname)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            initscripts.push(basename.clone());

            if file.mode & 0o500 != 0o500 {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "init-script-non-executable",
                    &[fname],
                );
            }
            if basename.contains('.') {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "init-script-name-with-dot",
                    &[fname],
                );
            }

            // chkconfig calls in %post and %preun. The reference is
            // `pkg[POSTIN] or pkg.scriptprog(POSTINPROG)`: the body wins.
            let postin_full =
                crate::checks::shared::script_body_or_prog(pkg, Tag::POSTIN, Tag::POSTINPROG);
            if postin_full.is_empty() {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "init-script-without-chkconfig-postin",
                    &[fname],
                );
            } else if !is_match(&self.chkconfig_re, &postin_full) {
                add_info(out, Level::Error, pkg, "postin-without-chkconfig", &[fname]);
            }

            let preun_full =
                crate::checks::shared::script_body_or_prog(pkg, Tag::PREUN, Tag::PREUNPROG);
            if preun_full.is_empty() {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "init-script-without-chkconfig-preun",
                    &[fname],
                );
            } else if !is_match(&self.chkconfig_re, &preun_full) {
                add_info(out, Level::Error, pkg, "preun-without-chkconfig", &[fname]);
            }

            let content = match std::fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(e) => {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "read-error",
                        &[&os_error_detail(&e)],
                    );
                    continue;
                }
            };

            let mut status_found = false;
            let mut reload_found = false;
            let mut chkconfig_content_found = false;
            let mut subsys_found = false;
            let mut in_lsb_tag = false;
            let mut in_lsb_description = false;
            let mut lastline = String::new();
            let mut lsb_tags: HashMap<String, Vec<String>> = HashMap::new();

            for raw_line in content.lines() {
                let mut line = raw_line.to_string();
                if line.starts_with("### BEGIN INIT INFO") {
                    in_lsb_tag = true;
                    continue;
                }
                if line.ends_with("### END INIT INFO") {
                    in_lsb_tag = false;
                    // Sorted: one finding per keyword, all sharing (check,
                    // level), so emission order would otherwise be random.
                    let mut kws: Vec<&String> = lsb_tags.keys().collect();
                    kws.sort();
                    for kw in kws {
                        if lsb_tags[kw].len() != 1 {
                            add_info(out, Level::Error, pkg, "redundant-lsb-keyword", &[kw]);
                        }
                    }
                    for kw in RECOMMENDED_LSB_KEYWORDS {
                        if !lsb_tags.contains_key(*kw) {
                            add_info(
                                out,
                                Level::Warning,
                                pkg,
                                "missing-lsb-keyword",
                                &[&format!("{kw} in {fname}")],
                            );
                        }
                    }
                }
                if in_lsb_tag {
                    if lastline.ends_with('\\') {
                        line = format!("{lastline}{line}");
                    } else if let Some(caps) = self.lsb_tags_re.captures(&line).ok().flatten() {
                        let tag = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                        let value = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
                        if !tag.starts_with("X-") && !LSB_KEYWORDS.contains(&tag) {
                            add_info(out, Level::Error, pkg, "unknown-lsb-keyword", &[&line]);
                        } else {
                            in_lsb_description = tag == "Description";
                            lsb_tags.entry(tag.to_string()).or_default().push(value);
                        }
                    } else if let Some(caps) = self.lsb_cont_re.captures(&line).ok().flatten() {
                        // in_lsb_description implies the Description entry exists
                        // (it is set when the Description tag is seen).
                        if in_lsb_description
                            && let Some(vals) = lsb_tags.get_mut("Description")
                            && let Some(last) = vals.last_mut()
                        {
                            last.push(' ');
                            last.push_str(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
                        } else {
                            in_lsb_description = false;
                            add_info(
                                out,
                                Level::Error,
                                pkg,
                                "malformed-line-in-lsb-comment-block",
                                &[&line],
                            );
                        }
                    } else {
                        in_lsb_description = false;
                        add_info(
                            out,
                            Level::Error,
                            pkg,
                            "malformed-line-in-lsb-comment-block",
                            &[&line],
                        );
                    }
                    lastline = line.clone();
                }

                if !status_found && is_match(&self.status_re, &line) {
                    status_found = true;
                }
                if !reload_found && is_match(&self.reload_re, &line) {
                    reload_found = true;
                }
                if let Some(caps) = self.chkconfig_content_re.captures(&line).ok().flatten() {
                    chkconfig_content_found = true;
                    let runlevels = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    if self.use_deflevels {
                        if runlevels == "-" {
                            add_info(out, Level::Warning, pkg, "no-default-runlevel", &[fname]);
                        }
                    } else if runlevels != "-" {
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "service-default-enabled",
                            &[fname],
                        );
                    }
                }
                if let Some(caps) = self.subsys_re.captures(&line).ok().flatten() {
                    subsys_found = true;
                    let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    if self.use_subsys && name != basename {
                        let mut error = true;
                        // The reference picks W/E from the raw `$var` token
                        // and emits that token (or the `}`-truncated name),
                        // never the substituted value, and never suppresses
                        // on an empty substitution.
                        let mut detail = name.to_string();
                        if name.starts_with('$') {
                            if self.substitute_shell_vars(name, &content) == basename {
                                error = false;
                            }
                        } else if let Some(i) = name.find('}') {
                            let short = &name[..i];
                            detail = short.to_string();
                            error = short != basename;
                        }
                        if error && !detail.is_empty() {
                            let level = if detail.starts_with('$') {
                                Level::Warning
                            } else {
                                Level::Error
                            };
                            add_info(out, level, pkg, "incoherent-subsys", &[fname, &detail]);
                        }
                    }
                }
            }

            if lsb_tags
                .get("Default-Start")
                .is_some_and(|v| v.iter().any(|s| !s.is_empty()))
            {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "service-default-enabled",
                    &[fname],
                );
            }
            if !status_found {
                add_info(out, Level::Error, pkg, "no-status-entry", &[fname]);
            }
            if !reload_found {
                add_info(out, Level::Warning, pkg, "no-reload-entry", &[fname]);
            }
            if !chkconfig_content_found {
                add_info(out, Level::Error, pkg, "no-chkconfig-line", &[fname]);
            }
            if !subsys_found && self.use_subsys {
                add_info(out, Level::Error, pkg, "subsys-not-used", &[fname]);
            } else if subsys_found && !self.use_subsys {
                add_info(out, Level::Error, pkg, "subsys-unsupported", &[fname]);
            }
        }

        if initscripts.len() == 1 {
            let base = pkg
                .name
                .to_lowercase()
                .strip_suffix("-sysvinit")
                .map(str::to_string)
                .unwrap_or_else(|| pkg.name.to_lowercase());
            let goodnames = [base.clone(), format!("{base}d")];
            if !goodnames.contains(&initscripts[0]) {
                // The reference prints `str()` of the 2-tuple goodnames.
                let want = crate::checks::shared::python_str_tuple(&[
                    goodnames[0].as_str(),
                    goodnames[1].as_str(),
                ]);
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "incoherent-init-script-name",
                    &[&initscripts[0], &want],
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::color::Color;
    use crate::pkg::pkgfile::PkgFile;

    fn checker() -> InitScriptCheck {
        InitScriptCheck::new(&Config::default())
    }

    #[test]
    fn chkconfig_line_is_detected() {
        let check = checker();
        assert!(is_match(
            &check.chkconfig_content_re,
            "# chkconfig: 345 85 15"
        ));
    }

    #[test]
    fn chkconfig_line_with_dash_runlevels() {
        let check = checker();
        let caps = check
            .chkconfig_content_re
            .captures("# chkconfig: - 85 15")
            .ok()
            .flatten()
            .expect("matches");
        assert_eq!(caps.get(1).map(|m| m.as_str()), Some("-"));
    }

    #[test]
    fn lsb_tag_line_parses() {
        let check = checker();
        let caps = check
            .lsb_tags_re
            .captures("# Provides: foo")
            .ok()
            .flatten()
            .expect("matches");
        assert_eq!(caps.get(1).map(|m| m.as_str()), Some("Provides"));
        assert_eq!(caps.get(2).map(|m| m.as_str()), Some("foo"));
    }

    #[test]
    fn subsys_path_extracts_name() {
        let check = checker();
        let caps = check
            .subsys_re
            .captures("touch /var/lock/subsys/mydaemon")
            .ok()
            .flatten()
            .expect("matches");
        assert_eq!(caps.get(1).map(|m| m.as_str()), Some("mydaemon"));
    }

    #[test]
    fn shell_var_value_resolves_simple_assignment() {
        let check = checker();
        let script = "NAME=mydaemon\necho $NAME\n";
        assert_eq!(
            check.shell_var_value("NAME", script),
            Some("mydaemon".to_string())
        );
    }

    #[test]
    fn shell_var_value_self_reference_is_none() {
        let check = checker();
        let script = "NAME=$NAME\n";
        assert_eq!(check.shell_var_value("NAME", script), None);
    }

    #[test]
    fn parity_fixture_matches_reference() {
        use crate::color::Color;

        // Pinned against reference rpmlint 2.10.0 (InitScriptCheck.py at
        // 84848c0), verified in an openSUSE container: the fixture ships an
        // init script plus %post/%preun bodies WITH -p interpreters. The
        // bodies (which call chkconfig) win over the interpreters, so the
        // reference emits nothing. B2: preferring the -p interpreter would
        // false-positive E postin-without-chkconfig and E
        // preun-without-chkconfig.
        let rpm = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/parity/pkg/inputs/parity-1.0-1.noarch.rpm"
        );
        let tmp = tempfile::tempdir().expect("tmpdir");
        let dir = tmp.path();
        let pkg =
            crate::pkg::Pkg::open(std::path::Path::new(rpm), dir, true).expect("fixture opens");
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = InitScriptCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let rendered: Vec<String> = out.results().iter().map(|(_, line)| line.clone()).collect();
        assert!(rendered.is_empty(), "{rendered:?}");
    }

    #[test]
    fn redundant_lsb_keywords_have_deterministic_order() {
        // Three duplicate LSB keywords: without sorting, the HashMap iteration
        // order would randomize the finding sequence across runs.
        let tmp = tempfile::tempdir().expect("tmpdir");
        let dir = tmp.path();
        let script = dir.join("order");
        std::fs::write(
            &script,
            "#!/bin/sh\n### BEGIN INIT INFO\n# Provides: order\n# Provides: order2\n# Description: foo\n# Description: bar\n# Required-Start: $remote_fs\n# Required-Start: $syslog\n### END INIT INFO\n",
        )
        .expect("write script");

        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, dir, true).expect("open fixture pkg");
        pkg.files = vec![PkgFile {
            name: "/etc/init.d/order".to_string(),
            path: script.to_string_lossy().into_owned(),
            mode: 0o100755,
            ..Default::default()
        }];

        let run = || {
            let config = Config::default();
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            let mut check = InitScriptCheck::new(&config);
            check.check_binary(&pkg, &config, &mut out);
            out.results().to_vec()
        };
        let first = run();
        let second = run();
        assert_eq!(first, second, "finding order must be deterministic");

        let keywords: Vec<&str> = first
            .iter()
            .filter(|(n, _)| n == "redundant-lsb-keyword")
            .map(|(_, line)| line.rsplit(' ').next().unwrap_or(""))
            .collect();
        assert_eq!(keywords, vec!["Description", "Provides", "Required-Start"]);
    }

    /// B6: `incoherent-subsys` takes its level and detail from the raw
    /// `$var` token, never the substituted value, and an empty
    /// substitution does not suppress the finding. Verified against
    /// InitScriptCheck.py:171-191 (rpmlint 2.10.0).
    ///
    /// Expected lines are pinned verbatim instead of parsed back into
    /// fields: re-deriving the level from the rendered text (e.g.
    /// `contains(": W: ")` defaulting to `E`) is what would misread an
    /// `I:` level as `E`. Pinning the whole line pins the package
    /// prefix, the level letter, the finding name, the fname detail and
    /// the emission order in one assertion.
    #[test]
    fn incoherent_subsys_level_and_detail_come_from_raw_token() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let dir = tmp.path();

        // (script body, expected rendered lines, in emission order)
        let cases: &[(&str, Vec<&str>)] = &[
            // $NAME resolves to otherdaemon: W, raw token in detail.
            (
                "#!/bin/sh\nNAME=otherdaemon\ntouch /var/lock/subsys/$NAME\n",
                vec!["mydaemon.noarch: W: incoherent-subsys /etc/init.d/mydaemon $NAME"],
            ),
            // Literal mismatch: E, the name itself.
            (
                "#!/bin/sh\ntouch /var/lock/subsys/wrongname\n",
                vec!["mydaemon.noarch: E: incoherent-subsys /etc/init.d/mydaemon wrongname"],
            ),
            // ${NAME} resolves to the basename: quiet.
            (
                "#!/bin/sh\nNAME=mydaemon\ntouch /var/lock/subsys/${NAME}\n",
                vec![],
            ),
            // $UNSET resolves to "": still emitted, W, raw token.
            (
                "#!/bin/sh\ntouch /var/lock/subsys/$UNSET\n",
                vec!["mydaemon.noarch: W: incoherent-subsys /etc/init.d/mydaemon $UNSET"],
            ),
            // Empty raw token: `}` truncates to "", suppressed by the
            // `if error and len(name)` guard (InitScriptCheck.py:189).
            ("#!/bin/sh\ntouch /var/lock/subsys/}\n", vec![]),
            // Two findings: emission order follows the script lines.
            (
                "#!/bin/sh\nNAME=otherdaemon\ntouch /var/lock/subsys/$NAME\ntouch /var/lock/subsys/wrongname\n",
                vec![
                    "mydaemon.noarch: W: incoherent-subsys /etc/init.d/mydaemon $NAME",
                    "mydaemon.noarch: E: incoherent-subsys /etc/init.d/mydaemon wrongname",
                ],
            ),
        ];

        for (i, (body, expected)) in cases.iter().enumerate() {
            let script = dir.join(format!("case{i}"));
            std::fs::write(&script, body).expect("write script");
            let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
            let mut pkg = Pkg::open(&rpm, dir, true).expect("open fixture pkg");
            pkg.name = "mydaemon".to_string();
            pkg.files = vec![PkgFile {
                name: "/etc/init.d/mydaemon".to_string(),
                path: script.to_string_lossy().into_owned(),
                mode: 0o100755,
                ..Default::default()
            }];

            let config = Config::default();
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            let mut check = InitScriptCheck::new(&config);
            check.check_binary(&pkg, &config, &mut out);
            let found: Vec<(&str, &str)> = out
                .results()
                .iter()
                .filter(|(n, _)| n == "incoherent-subsys")
                .map(|(n, line)| (n.as_str(), line.as_str()))
                .collect();
            let want: Vec<(&str, &str)> = expected
                .iter()
                .map(|line| ("incoherent-subsys", *line))
                .collect();
            assert_eq!(found, want, "case {i} body:\n{body}");
        }
    }
}
