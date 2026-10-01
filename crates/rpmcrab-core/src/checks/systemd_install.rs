//! `SystemdInstallCheck` — systemd unit scriptlet presence.
//!
//! Ported from `rpmlint/checks/SystemdInstallCheck.py`. Four findings:
//! `systemd-service-without-service_add_pre`,
//! `systemd-service-without-service_add_post`,
//! `systemd-service-without-service_del_preun`,
//! `systemd-service-without-service_del_postun`.

use std::path::Path;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

use super::shared::script_body_or_prog;
use librpm::Tag;

pub struct SystemdInstallCheck {
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
        Self { unit_dir }
    }

    /// The unit types the reference checks.
    fn unit_regex(&self) -> Regex {
        Regex::new(&format!(
            r"^{}.+[^@]\.(service|socket|target|path)$",
            fancy_regex::escape(&self.unit_dir)
        ))
        .expect("static regex")
    }

    /// `(finding, ok)` for one unit file against the four scriptlets.
    fn check_unit(
        basename: &str,
        pre: &str,
        post: &str,
        preun: &str,
        postun: &str,
    ) -> Vec<&'static str> {
        let escaped = fancy_regex::escape(basename);
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
            let re = Regex::new(pattern).expect("unit pattern");
            if !script.lines().any(|line| is_match(&re, line)) {
                // The reference accepts `%service_del_postun_without_restart`.
                if *finding == "systemd-service-without-service_del_postun"
                    && postun.lines().any(|l| l.trim() == ":")
                {
                    continue;
                }
                missing.push(*finding);
            }
        }
        missing
    }
}

impl Check for SystemdInstallCheck {
    fn name(&self) -> &'static str {
        "SystemdInstallCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let unit_re = self.unit_regex();
        let pre = script_body_or_prog(pkg, Tag::PREIN, Tag::PREINPROG);
        let post = script_body_or_prog(pkg, Tag::POSTIN, Tag::POSTINPROG);
        let preun = script_body_or_prog(pkg, Tag::PREUN, Tag::PREUNPROG);
        let postun = script_body_or_prog(pkg, Tag::POSTUN, Tag::POSTUNPROG);

        // The reference walks pkg.files in order without sorting or deduping.
        let units: Vec<String> = pkg
            .files
            .iter()
            .map(|f| f.name.as_str())
            .filter(|n| is_match(&unit_re, n))
            .map(|n| {
                Path::new(n)
                    .file_name()
                    .map(|b| b.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
            .collect();

        for basename in &units {
            for finding in Self::check_unit(basename, &pre, &post, &preun, &postun) {
                add_info(out, Level::Error, pkg, finding, &[basename]);
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
        let missing =
            SystemdInstallCheck::check_unit("foo.service", script, script, script, script);
        assert!(missing.is_empty(), "{missing:?}");
    }

    #[test]
    fn missing_pre_is_flagged() {
        let missing = SystemdInstallCheck::check_unit("foo.service", "", "", "", "");
        assert_eq!(missing.len(), 4);
        assert!(missing.contains(&"systemd-service-without-service_add_pre"));
    }

    #[test]
    fn postun_without_restart_is_accepted() {
        let missing = SystemdInstallCheck::check_unit("foo.service", "", "", "", ":\n");
        assert!(!missing.contains(&"systemd-service-without-service_del_postun"));
        assert_eq!(missing.len(), 3);
    }

    #[test]
    fn socket_unit_is_ignored_by_regex() {
        let check = SystemdInstallCheck::new(&Config::default());
        let re = check.unit_regex();
        assert!(!is_match(&re, "/usr/lib/systemd/system/foo@.service"));
        assert!(is_match(&re, "/usr/lib/systemd/system/foo.service"));
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
        assert!(is_match(&re, "/run/systemd/system/foo.service"));
        assert!(!is_match(&re, "/usr/lib/systemd/system/foo.service"));
    }
}
