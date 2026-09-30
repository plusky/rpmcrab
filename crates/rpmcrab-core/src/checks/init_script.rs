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
                    add_info(out, Level::Warning, pkg, "read-error", &[&e.to_string()]);
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
                    for (kw, vals) in &lsb_tags {
                        if vals.len() != 1 {
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
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "incoherent-init-script-name",
                    &[&initscripts[0], &format!("{goodnames:?}")],
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
