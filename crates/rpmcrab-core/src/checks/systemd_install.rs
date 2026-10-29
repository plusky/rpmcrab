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
        let manual_re = Regex::new(&format!(r"systemctl.*\b(enable|preset)\b.*{}", escaped))
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
            if script.lines().any(|line| is_match(&re, line)) {
                continue;
            }
            // The add_post credits apply to this arm only: the
            // other three scriptlets keep the reference behaviour.
            if *finding == "systemd-service-without-service_add_post" {
                if statically_enabled {
                    continue;
                }
                if script.lines().any(|line| is_match(&manual_re, line)) {
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

    /// Whether a `mark-restart-system-units` line in `%postun` names a
    /// `.service` unit by its bare stem. The helper passes each argument
    /// verbatim to `systemctl set-property`, and systemctl appends
    /// `.service` to a suffix-less name, so `mark-restart-system-units
    /// foo` marks `foo.service` exactly as the suffixed spelling does.
    /// Only a whole whitespace-separated argument counts: a longer name
    /// sharing the stem, a different suffix, or a template stem does
    /// not. Other unit types get no such credit, since a bare name
    /// never resolves to them.
    fn postun_marks_bare_service(basename: &str, postun: &str) -> bool {
        let Some(stem) = basename.strip_suffix(".service") else {
            return false;
        };
        postun.lines().any(|line| {
            let Some((_, args)) = line.split_once("mark-restart-system-units") else {
                return false;
            };
            args.split_whitespace().any(|arg| {
                arg.trim_matches(|c| c == ';' || c == ',' || c == '|' || c == '"' || c == '\'')
                    == stem
            })
        })
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

        // Basenames of units statically enabled by a shipped wants
        // symlink: a symlink under `<unitdir>/*.wants/` whose target
        // resolves within the package to a unit file. A regular file
        // in a wants directory, a wants link outside the unit
        // directory, and a link resolving to no shipped file earn no
        // credit. Only the resolved target's basename is credited, so
        // a wants link for another unit never credits this one.
        let wants_prefix = format!("{}/", self.unit_dir);
        let mut statically_enabled: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        for file in &pkg.files {
            if !is_symlink(file.mode) {
                continue;
            }
            if !file.name.starts_with(&wants_prefix) {
                continue;
            }
            if !file.name.split('/').any(|seg| seg.ends_with(".wants")) {
                continue;
            }
            if let Some(target) = pkg.readlink(file)
                && let Some(basename) = target.name.rsplit('/').next()
            {
                statically_enabled.insert(basename);
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
    fn sibling_tags_ignore_bare_stems() {
        let script = "systemd-update-helper mark-install-system-units foo\n\
                      systemd-update-helper install-system-units foo\n\
                      systemd-update-helper remove-system-units foo\n\
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
    fn wants_link_duplicate_suppresses_add_pre_only() {
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
        let pkg = alias_pkg(Some(vec![
            reg(&format!("{UNIT}/want720.service")),
            link(
                &format!("{UNIT}/multi-user.target.wants/other720.service"),
                "../other720.service",
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
        let pkg = alias_pkg(Some(vec![
            reg(&format!("{UNIT}/want720.service")),
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
}
