//! `AlternativesCheck` — update-alternatives / libalternatives usage.
//!
//! Ported from `rpmlint/checks/AlternativesCheck.py`. Findings:
//! `package-supports-libalternatives`, `alts-requirement-missed`,
//! `libalternatives-directory-not-exists`, `empty-libalternatives-directory`,
//! `libalternatives-conf-not-found`, `wrong-entry-format`,
//! `multiple-entries`, `binary-entry-value-not-found`, `double-entries`,
//! `man-entry-value-not-found`, `wrong-tag-found`,
//! `wrong-or-missed-binary-entry`, `package-supports-update-alternatives`,
//! `update-alternatives-requirement-missing`,
//! `update-alternatives-post-call-missing`,
//! `update-alternatives-postun-call-missing`, `alternative-link-missing`,
//! `alternative-link-not-ghost`, `alternative-generic-name-missing`,
//! `alternative-generic-name-not-symlink`.

use std::path::Path;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::is_symlink;
use librpm::Tag;

pub struct AlternativesCheck;

impl AlternativesCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    fn requirement_regex() -> Regex {
        Regex::new(r"^(/usr/s?bin/|%\{?_s?bindir\}?/)?update-alternatives$").expect("static regex")
    }

    fn install_regex() -> Regex {
        Regex::new(r"--install\s+(?P<link>\S+)\s+(?P<name>\S+)\s+(\S+)\s+(\S+)")
            .expect("static regex")
    }

    fn slave_regex() -> Regex {
        Regex::new(r"--slave\s+(?P<link>\S+)\s+(\S+)\s+(\S+)").expect("static regex")
    }

    /// Normalize a scriptlet: join backslash-newlines, strip quotes, keep
    /// only lines mentioning `update-alternatives`.
    fn normalize_script(script: &str) -> Vec<String> {
        let script = script.replace("\\\n", "");
        let script = script.replace(['"', '\''], "");
        script
            .lines()
            .map(str::trim)
            .filter(|l| l.contains("update-alternatives"))
            .map(str::to_string)
            .collect()
    }

    /// `(install_binaries: link -> name, slave_binaries: [link])`.
    fn find_binaries(lines: &[String]) -> (Vec<(String, String)>, Vec<String>) {
        let install_re = Self::install_regex();
        let slave_re = Self::slave_regex();
        let mut install = Vec::new();
        let mut slaves = Vec::new();
        for line in lines {
            if let Some(caps) = install_re.captures(line).ok().flatten() {
                let link = caps
                    .get(1)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                let name = caps
                    .get(2)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                install.push((link, name));
            }
            for caps in slave_re.captures_iter(line).flatten() {
                if let Some(m) = caps.get(1) {
                    slaves.push(m.as_str().to_string());
                }
            }
        }
        (install, slaves)
    }

    /// Validate the `%post` phase. Returns the install binaries found.
    fn check_post_phase(lines: &[String]) -> Result<Vec<(String, String)>, &'static str> {
        if lines.is_empty() {
            return Err("update-alternatives-post-call-missing");
        }
        let (install, _) = Self::find_binaries(lines);
        if install.is_empty() {
            return Err("update-alternatives-post-call-missing");
        }
        Ok(install)
    }

    /// Binaries from `install` missing a `--remove` line in postun.
    fn check_postun_phase(lines: &[String], install: &[(String, String)]) -> Vec<String> {
        if lines.is_empty() {
            return install.iter().map(|(_, n)| n.clone()).collect();
        }
        let mut missing: Vec<String> = install.iter().map(|(_, n)| n.clone()).collect();
        for binary in missing.clone() {
            let re = Regex::new(&format!(r"--remove\s+{}\b", fancy_regex::escape(&binary)))
                .expect("remove pattern");
            if lines.iter().any(|l| is_match(&re, l)) {
                missing.retain(|b| b != &binary);
            }
        }
        missing
    }

    /// The libalternatives file-list checks (directory presence, conf content).
    fn check_libalternatives_filelist(pkg: &Pkg, out: &mut Filter) {
        for pkgfile in &pkg.files {
            if pkgfile.linkto == "alts" {
                let dir_name = format!(
                    "/usr/share/libalternatives/{}",
                    Path::new(&pkgfile.name)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                );
                if !pkg.files.iter().any(|f| f.name == dir_name) {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "libalternatives-directory-not-exists",
                        &[&dir_name],
                    );
                } else {
                    let conf_re =
                        Regex::new(&format!("^{}/.*\\.conf$", fancy_regex::escape(&dir_name)))
                            .expect("conf pattern");
                    if !pkg.files.iter().any(|f| is_match(&conf_re, &f.name)) {
                        add_info(
                            out,
                            Level::Error,
                            pkg,
                            "empty-libalternatives-directory",
                            &[&dir_name],
                        );
                    }
                }
            }
        }

        let conf_re =
            Regex::new(r"^/usr/share/libalternatives/[^/]+/.*\.conf$").expect("static regex");
        for pkgfile in &pkg.files {
            if !is_match(&conf_re, &pkgfile.name) {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&pkgfile.path) else {
                let level = if pkgfile.is_ghost() {
                    Level::Info
                } else {
                    Level::Error
                };
                add_info(
                    out,
                    level,
                    pkg,
                    "libalternatives-conf-not-found",
                    &[&pkgfile.name],
                );
                continue;
            };
            let mut bin_found = false;
            let mut man_found = false;
            for (line_nr, line) in content.lines().enumerate() {
                let line_nr_str = format!("Line: {line_nr}");
                let parts: Vec<&str> = line.split('=').map(str::trim).collect();
                if parts.len() != 2 {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "wrong-entry-format",
                        &[&pkgfile.name, &line_nr_str],
                    );
                    continue;
                }
                let (key, value) = (parts[0], parts[1]);
                match key {
                    "binary" => {
                        if bin_found {
                            add_info(
                                out,
                                Level::Error,
                                pkg,
                                "multiple-entries",
                                &[&pkgfile.name, &line_nr_str],
                            );
                            continue;
                        }
                        bin_found = pkg
                            .files
                            .iter()
                            .any(|f| f.name.contains("bin/") && f.name.ends_with(value));
                        if !bin_found {
                            add_info(
                                out,
                                Level::Warning,
                                pkg,
                                "binary-entry-value-not-found",
                                &[&pkgfile.name, &line_nr_str],
                            );
                        }
                    }
                    "man" => {
                        if man_found {
                            add_info(
                                out,
                                Level::Error,
                                pkg,
                                "double-entries",
                                &[&pkgfile.name, &line_nr_str],
                            );
                            continue;
                        }
                        for man in value.split(',') {
                            let man = man.trim();
                            let found = pkg.files.iter().any(|f| {
                                f.name.starts_with("/usr/share/man/") && f.name.contains(man)
                            });
                            if !found {
                                add_info(
                                    out,
                                    Level::Warning,
                                    pkg,
                                    "man-entry-value-not-found",
                                    &[&pkgfile.name, &line_nr_str],
                                );
                            }
                        }
                        man_found = true;
                    }
                    "group" | "options" => {}
                    _ => {
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "wrong-tag-found",
                            &[&pkgfile.name, &line_nr_str],
                        );
                    }
                }
            }
            if !bin_found {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "wrong-or-missed-binary-entry",
                    &[&pkgfile.name],
                );
            }
        }
    }
}

impl Check for AlternativesCheck {
    fn name(&self) -> &'static str {
        "AlternativesCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        // libalternatives
        let has_libalts = pkg
            .files
            .iter()
            .any(|f| f.name.starts_with("/usr/share/libalternatives/"))
            || pkg
                .requires
                .iter()
                .chain(pkg.prereq.iter())
                .any(|r| r.name == "alts");
        if has_libalts {
            add_info(
                out,
                Level::Info,
                pkg,
                "package-supports-libalternatives",
                &[],
            );
            if !pkg
                .requires
                .iter()
                .chain(pkg.prereq.iter())
                .any(|r| r.name == "alts")
            {
                add_info(out, Level::Error, pkg, "alts-requirement-missed", &[]);
            }
            Self::check_libalternatives_filelist(pkg, out);
        }

        let post = pkg.tag_str(Tag::POSTIN).unwrap_or_default();
        let postun = pkg.tag_str(Tag::POSTUN).unwrap_or_default();

        let has_ua = pkg
            .files
            .iter()
            .any(|f| f.name.starts_with("/etc/alternatives"))
            || post.contains("update-alternatives")
            || postun.contains("update-alternatives");
        if !has_ua {
            return;
        }
        add_info(
            out,
            Level::Info,
            pkg,
            "package-supports-update-alternatives",
            &[],
        );

        if !pkg
            .prereq
            .iter()
            .any(|r| is_match(&Self::requirement_regex(), &r.name))
        {
            add_info(
                out,
                Level::Error,
                pkg,
                "update-alternatives-requirement-missing",
                &[],
            );
        }

        let post_lines = Self::normalize_script(&post);
        let install = match Self::check_post_phase(&post_lines) {
            Ok(install) => install,
            Err(finding) => {
                add_info(out, Level::Error, pkg, finding, &[]);
                Vec::new()
            }
        };

        let postun_lines = Self::normalize_script(&postun);
        if postun_lines.is_empty() && post_lines.is_empty() {
            add_info(
                out,
                Level::Error,
                pkg,
                "update-alternatives-postun-call-missing",
                &[],
            );
        } else {
            for binary in Self::check_postun_phase(&postun_lines, &install) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "update-alternatives-postun-call-missing",
                    &[&binary],
                );
            }
        }

        // File list validation.
        let (_, slaves) = Self::find_binaries(&post_lines);
        let file_names: Vec<&str> = pkg.files.iter().map(|f| f.name.as_str()).collect();
        for binary in install
            .iter()
            .map(|(l, _)| l.as_str())
            .chain(slaves.iter().map(String::as_str))
        {
            let etc_alt = format!(
                "/etc/alternatives/{}",
                Path::new(binary)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            );
            if !file_names.contains(&etc_alt.as_str()) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "alternative-link-missing",
                    &[&etc_alt],
                );
            } else if !pkg.ghost_files.iter().any(|g| g == &etc_alt) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "alternative-link-not-ghost",
                    &[&etc_alt],
                );
            }
            match pkg.files.iter().find(|f| f.name == binary) {
                None => add_info(
                    out,
                    Level::Error,
                    pkg,
                    "alternative-generic-name-missing",
                    &[binary],
                ),
                Some(pf) if !is_symlink(pf.mode) => add_info(
                    out,
                    Level::Error,
                    pkg,
                    "alternative-generic-name-not-symlink",
                    &[binary],
                ),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_line_is_parsed() {
        let lines =
            vec!["update-alternatives --install /usr/bin/foo foo /usr/bin/foo-1.0 10".to_string()];
        let (install, slaves) = AlternativesCheck::find_binaries(&lines);
        assert_eq!(
            install,
            vec![("/usr/bin/foo".to_string(), "foo".to_string())]
        );
        assert!(slaves.is_empty());
    }

    #[test]
    fn slave_lines_are_parsed() {
        let lines = vec!["update-alternatives --install /usr/bin/foo foo /usr/bin/foo-1.0 10 --slave /usr/bin/bar bar /usr/bin/bar-1.0".to_string()];
        let (install, slaves) = AlternativesCheck::find_binaries(&lines);
        assert_eq!(install.len(), 1);
        assert_eq!(slaves, vec!["/usr/bin/bar".to_string()]);
    }

    #[test]
    fn normalize_joins_continuations_and_strips_quotes() {
        let script = "update-alternatives \\\n  --install \"/usr/bin/foo\" foo /usr/bin/foo-1.0 10\necho done\n";
        let lines = AlternativesCheck::normalize_script(script);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("--install /usr/bin/foo"));
        assert!(!lines[0].contains('"'));
    }

    #[test]
    fn empty_post_reports_missing() {
        assert!(AlternativesCheck::check_post_phase(&[]).is_err());
    }

    #[test]
    fn post_without_install_reports_missing() {
        let lines = vec!["update-alternatives --remove foo /usr/bin/foo-1.0".to_string()];
        assert!(AlternativesCheck::check_post_phase(&lines).is_err());
    }

    #[test]
    fn postun_missing_remove_is_found() {
        let install = vec![("/usr/bin/foo".to_string(), "foo".to_string())];
        let missing = AlternativesCheck::check_postun_phase(&[], &install);
        assert_eq!(missing, vec!["foo".to_string()]);
    }

    #[test]
    fn postun_with_remove_is_quiet() {
        let install = vec![("/usr/bin/foo".to_string(), "foo".to_string())];
        let lines = vec!["update-alternatives --remove foo /usr/bin/foo-1.0".to_string()];
        let missing = AlternativesCheck::check_postun_phase(&lines, &install);
        assert!(missing.is_empty());
    }

    #[test]
    fn requirement_regex_matches_paths() {
        let re = AlternativesCheck::requirement_regex();
        assert!(is_match(&re, "update-alternatives"));
        assert!(is_match(&re, "/usr/bin/update-alternatives"));
        assert!(!is_match(&re, "update-alternatives-foo"));
    }
}
