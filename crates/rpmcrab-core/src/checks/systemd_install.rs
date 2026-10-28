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
    fn check_unit(
        basename: &str,
        pre_direct: bool,
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
            if *finding == "systemd-service-without-service_add_pre" && !pre_direct {
                continue;
            }
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
            units.push((
                Path::new(&candidate.name)
                    .file_name()
                    .map(|b| b.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                pre_direct,
            ));
        }

        for (basename, pre_direct) in &units {
            for finding in Self::check_unit(basename, *pre_direct, &pre, &post, &preun, &postun) {
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
        let missing =
            SystemdInstallCheck::check_unit("foo.service", true, script, script, script, script);
        assert!(missing.is_empty(), "{missing:?}");
    }

    #[test]
    fn missing_pre_is_flagged() {
        let missing = SystemdInstallCheck::check_unit("foo.service", true, "", "", "", "");
        assert_eq!(missing.len(), 4);
        assert!(missing.contains(&"systemd-service-without-service_add_pre"));
    }

    #[test]
    fn postun_without_restart_is_accepted() {
        let missing = SystemdInstallCheck::check_unit("foo.service", true, "", "", "", ":\n");
        assert!(!missing.contains(&"systemd-service-without-service_del_postun"));
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
        let missing = SystemdInstallCheck::check_unit("foo.service", false, "", "", "", "");
        assert!(!missing.contains(&"systemd-service-without-service_add_pre"));
        assert!(missing.contains(&"systemd-service-without-service_add_post"));
        assert!(missing.contains(&"systemd-service-without-service_del_preun"));
        assert!(missing.contains(&"systemd-service-without-service_del_postun"));
        assert_eq!(missing.len(), 3, "{missing:?}");
    }

    #[test]
    fn wants_link_duplicate_suppresses_add_pre_only() {
        // The dracut shape: a direct unit-dir link to a shipped non-unit
        // file, plus the same unit name as a `.wants` enablement link.
        // The direct candidate still fires `add_pre`; the `.wants`
        // candidate fires the other three findings unchanged.
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
        assert_eq!(results.len(), 7, "{results:?}");
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
            2
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
        assert_eq!(results.len(), 4, "{results:?}");
        assert_eq!(
            on_tag(
                &results,
                "systemd-service-without-service_add_pre",
                "bare720.service"
            ),
            1
        );
    }
}
