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
use crate::pkg::pkgfile::{is_reg, is_symlink};
use librpm::Tag;
use std::sync::OnceLock;

pub struct AlternativesCheck;

static LIBALTERNATIVES_CONF_RE: OnceLock<Regex> = OnceLock::new();
fn libalternatives_conf_re() -> &'static Regex {
    LIBALTERNATIVES_CONF_RE.get_or_init(|| {
        Regex::new(r"^/usr/share/libalternatives/[^/]+/.*\.conf$").expect("static regex")
    })
}

/// One extracted alternative registration: `(link, name)`, where `name`
/// is the alternative name update-alternatives keys the
/// `/etc/alternatives` link by.
type LinkName = (String, String);

impl AlternativesCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    fn requirement_regex() -> &'static Regex {
        static REQUIREMENT_REGEX: OnceLock<Regex> = OnceLock::new();
        REQUIREMENT_REGEX.get_or_init(|| {
            Regex::new(r"^(/usr/s?bin/|%\{?_s?bindir\}?/)?update-alternatives$")
                .expect("static regex")
        })
    }

    fn install_regex() -> &'static Regex {
        static INSTALL_REGEX: OnceLock<Regex> = OnceLock::new();
        INSTALL_REGEX.get_or_init(|| {
            Regex::new(r"--install\s+(?P<link>\S+)\s+(?P<name>\S+)\s+(\S+)\s+(\S+)")
                .expect("static regex")
        })
    }

    fn slave_regex() -> &'static Regex {
        static SLAVE_REGEX: OnceLock<Regex> = OnceLock::new();
        SLAVE_REGEX.get_or_init(|| {
            Regex::new(r"--slave\s+(?P<link>\S+)\s+(\S+)\s+(\S+)").expect("static regex")
        })
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

    /// `(install_binaries: link -> name, slave_binaries: link -> name)`.
    fn find_binaries(lines: &[String]) -> (Vec<LinkName>, Vec<LinkName>) {
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
                // The reference keys install_binaries by link: a repeated
                // --install for the same link overwrites, it never duplicates.
                if let Some(entry) = install.iter_mut().find(|(l, _)| *l == link) {
                    entry.1 = name;
                } else {
                    install.push((link, name));
                }
            }
            for caps in slave_re.captures_iter(line).flatten() {
                if let Some(m) = caps.get(1) {
                    let name = caps
                        .get(2)
                        .map(|n| n.as_str().to_string())
                        .unwrap_or_default();
                    slaves.push((m.as_str().to_string(), name));
                }
            }
        }
        (install, slaves)
    }

    /// Whether an extracted alternative link still carries a shell
    /// variable reference (`$i`, `${lib}`, `$bin`): the `--install` /
    /// `--slave` line sits inside a shell loop, so the link is a
    /// template, not a literal path -- no shipped file can carry that
    /// name. The file-list validation below looks links up in the
    /// package's file list literally, so it cannot judge a template;
    /// the phase checks keep using the install set unchanged.
    fn link_is_template(link: &str) -> bool {
        link.contains('$')
    }

    /// Whether the package actually registers an alternative with
    /// update-alternatives: it ships an `/etc/alternatives` entry, or
    /// its `%post` installs (or slaves) at least one link — the install
    /// set computed by this check itself. A package whose scriptlets
    /// only mention the tool to remove or inspect legacy registrations
    /// (the post-libalternatives cleanup shape: `--remove`,
    /// `--remove-all`, `--display`) registers nothing, so the
    /// informational `package-supports-update-alternatives` marker
    /// does not apply to it. The presence gate and every error finding
    /// are unaffected: they still run for such packages.
    fn registers_update_alternatives(
        has_etc_alternatives: bool,
        install: &[(String, String)],
        slaves: &[(String, String)],
    ) -> bool {
        has_etc_alternatives || !install.is_empty() || !slaves.is_empty()
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
            // The terminator cannot be `\b`: a name ending in a non-word
            // character (tolua++) has no word boundary before the
            // whitespace that follows it, so the reference's pattern
            // never credits its --remove line. Require the name to end
            // the token instead — whitespace, a command separator, a
            // closing paren (a --remove inside a command substitution
            // can end the line), or end of line — which also refuses
            // the reference's false credit for a name that is a proper
            // prefix of the removed one (tolua+ is not removed by a
            // tolua++ line).
            let name = fancy_regex::escape(&binary);
            let re = Regex::new(&format!(r"--remove\s+{}(?=\s|$|[;|&)])", name))
                .expect("remove pattern");
            if lines.iter().any(|l| is_match(&re, l)) {
                missing.retain(|b| b != &binary);
            }
        }
        missing
    }

    /// The `%postun` phase: report what `%post` installed that `%postun`
    /// never removes (the bare package-level finding when `%postun` has
    /// no update-alternatives line at all). An empty install set stays
    /// silent: there is no removal for `%postun` to owe, where the
    /// reference reports the bare finding unconditionally — vacuous for
    /// packages whose `%post` only cleans up legacy registrations and
    /// for packages present only through shipped `/etc/alternatives`
    /// files.
    fn check_postun(pkg: &Pkg, postun: &str, install: &[(String, String)], out: &mut Filter) {
        if install.is_empty() {
            return;
        }
        let postun_lines = Self::normalize_script(postun);
        if postun_lines.is_empty() {
            add_info(
                out,
                Level::Error,
                pkg,
                "update-alternatives-postun-call-missing",
                &[],
            );
            return;
        }
        for binary in Self::check_postun_phase(&postun_lines, install) {
            add_info(
                out,
                Level::Error,
                pkg,
                "update-alternatives-postun-call-missing",
                &[&binary],
            );
        }
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
                    // The reference interpolates dir_name raw into the pattern
                    // (no escaping), so a package-chosen symlink basename can
                    // make it an invalid regex -- AlternativesCheck.py:216
                    // raises re.error there. A package must not be able to
                    // panic the linter, so an uncompilable pattern skips this
                    // one finding instead of aborting the run (ledgered as
                    // alternatives-regex-from-package-path).
                    if let Ok(conf_re) = Regex::new(&format!("^{}/.*.conf$", dir_name))
                        && !pkg.files.iter().any(|f| is_match(&conf_re, &f.name))
                    {
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

        let conf_re = libalternatives_conf_re();
        for pkgfile in &pkg.files {
            if !is_match(conf_re, &pkgfile.name) {
                continue;
            }
            // The reference checks existence, not readability: a read error
            // on an existing file is not "not found".
            if !Path::new(&pkgfile.path).exists() {
                // If the parent directory was not extracted either, the whole
                // subtree is missing — an extraction artifact (e.g. ENOSPC),
                // not a packaging error. Skip instead of firing a false
                // positive (issue #406).
                if let Some(parent) = Path::new(&pkgfile.path).parent()
                    && !parent.exists()
                {
                    continue;
                }
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
            let Ok(content) = std::fs::read_to_string(&pkgfile.path) else {
                continue;
            };
            let mut bin_found = false;
            // Whether any `binary=` line was seen at all: presence and
            // satisfaction are separate questions (issue #931).
            let mut bin_seen = false;
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
                        bin_seen = true;
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
                        // A file at exactly the entry's path satisfies
                        // the entry wherever it lives: libalternatives
                        // targets commonly sit in /usr/libexec, outside
                        // every bin/ path (issue #811). The reference's
                        // bin/ suffix rule covers the remaining shapes,
                        // and a path resolving through the package's own
                        // symlinks to a shipped file satisfies it too
                        // (issue #932).
                        bin_found = pkg.files.iter().any(|f| {
                            f.name == value || (f.name.contains("bin/") && f.name.ends_with(value))
                        }) || Self::binary_entry_resolves_in_package(pkg, value);
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
                            // The reference resets per man entry
                            // (AlternativesCheck.py:264-271): after the
                            // line, man_found holds only the last
                            // entry's result.
                            man_found = false;
                            if pkg.files.iter().any(|f| {
                                f.name.starts_with("/usr/share/man/") && f.name.contains(man)
                            }) {
                                man_found = true;
                            } else {
                                add_info(
                                    out,
                                    Level::Warning,
                                    pkg,
                                    "man-entry-value-not-found",
                                    &[&pkgfile.name, &line_nr_str],
                                );
                            }
                        }
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
            // The summary finding reports a binary entry that was
            // declared but not satisfied; a conf that never declared
            // one (a man-only libalternatives group) has no binary
            // entry to miss (issue #931).
            if bin_seen && !bin_found {
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

    /// Whether a `binary=` entry path resolves, through the package's
    /// own symlink entries, to a regular file the package ships (issue
    /// #932).
    /// libalternatives resolves the entry path on the installed
    /// system, where a directory symlink shipped by the package (the
    /// JDK layout: `/usr/lib64/jvm/java-11-openjdk` pointing at
    /// `java-11-openjdk-11`) puts the shipped file at the entry path.
    /// A resolution landing outside the package's file set earns no
    /// credit, and neither does a walk that never lands (a symlink
    /// cycle), so targets shipped by sibling packages and genuinely
    /// absent targets keep firing. The walk canonicalises the value
    /// the way the kernel resolves it, so a doubled leading slash in
    /// the value (`binary=//usr/bin/...`, as the SUSE python
    /// packaging macros emit it) names the shipped file too.
    fn binary_entry_resolves_in_package(pkg: &Pkg, value: &str) -> bool {
        if !value.starts_with('/') {
            return false;
        }
        let Some(resolved) = Self::resolve_through_package_symlinks(pkg, value) else {
            return false;
        };
        pkg.files
            .iter()
            .any(|f| f.name == resolved && is_reg(f.mode))
    }

    /// Follow package-shipped symlinks at every prefix of `path` and
    /// return the path the walk lands on, or `None` when the walk
    /// exhausts the hop bound (the kernel's MAXSYMLINKS): exhaustion
    /// means the resolution cycles (the kernel's ELOOP), so there is
    /// no landing path to credit. Each substitution restarts the scan
    /// at the leftmost symlink prefix, mirroring component-wise path
    /// resolution.
    fn resolve_through_package_symlinks(pkg: &Pkg, path: &str) -> Option<String> {
        // `normalize_path` preserves a leading `//` (POSIX leaves its
        // meaning implementation-defined); the kernel resolves it to
        // the single-slash path on Linux, so collapse it before
        // comparing against shipped file names.
        fn canonical(path: &str) -> String {
            let n = crate::pkg::normalize_path(path);
            match n.strip_prefix("//") {
                Some(rest) => format!("/{rest}"),
                None => n,
            }
        }
        let mut current = canonical(path);
        for _ in 0..40 {
            let comps: Vec<&str> = current.split('/').filter(|c| !c.is_empty()).collect();
            let mut substituted: Option<String> = None;
            for i in 1..=comps.len() {
                let prefix = format!("/{}", comps[..i].join("/"));
                let Some(link) = pkg
                    .files
                    .iter()
                    .find(|f| f.name == prefix && is_symlink(f.mode) && !f.linkto.is_empty())
                else {
                    continue;
                };
                let joined = if link.linkto.starts_with('/') {
                    link.linkto.clone()
                } else {
                    match prefix.rfind('/') {
                        Some(0) => format!("/{}", link.linkto),
                        Some(idx) => format!("{}/{}", &prefix[..idx], link.linkto),
                        None => link.linkto.clone(),
                    }
                };
                let rest = comps[i..].join("/");
                substituted = Some(if rest.is_empty() {
                    joined
                } else {
                    format!("{joined}/{rest}")
                });
                break;
            }
            match substituted {
                Some(next) => current = canonical(&next),
                None => return Some(current),
            }
        }
        None
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

        let has_etc_alternatives = pkg
            .files
            .iter()
            .any(|f| f.name.starts_with("/etc/alternatives"));
        let has_ua = has_etc_alternatives
            || post.contains("update-alternatives")
            || postun.contains("update-alternatives");
        if !has_ua {
            return;
        }
        let post_lines = Self::normalize_script(&post);
        let (install_binaries, slaves) = Self::find_binaries(&post_lines);
        if Self::registers_update_alternatives(has_etc_alternatives, &install_binaries, &slaves) {
            add_info(
                out,
                Level::Info,
                pkg,
                "package-supports-update-alternatives",
                &[],
            );
        }

        if !pkg
            .prereq
            .iter()
            .any(|r| is_match(Self::requirement_regex(), &r.name))
        {
            add_info(
                out,
                Level::Error,
                pkg,
                "update-alternatives-requirement-missing",
                &[],
            );
        }

        let install = match Self::check_post_phase(&post_lines) {
            Ok(install) => install,
            Err(finding) => {
                add_info(out, Level::Error, pkg, finding, &[]);
                Vec::new()
            }
        };

        Self::check_postun(pkg, &postun, &install, out);

        // File list validation: the reference walks slaves before installs.
        // Template links (shell loops) name no literal path, so the
        // literal file-list lookups skip them; their concrete expansions
        // are the package's own shipped files, judged when a literal
        // --install line names them.
        let (_, slaves) = Self::find_binaries(&post_lines);
        let file_names: Vec<&str> = pkg.files.iter().map(|f| f.name.as_str()).collect();
        for (binary, name) in slaves
            .iter()
            .chain(install.iter())
            .filter(|entry| !Self::link_is_template(&entry.0))
        {
            let binary = binary.as_str();
            let name = name.as_str();
            let link_base = Path::new(binary)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let etc_alt = format!("/etc/alternatives/{link_base}");
            if !file_names.contains(&etc_alt.as_str()) {
                // update-alternatives keys the link it creates by the
                // registration's name, not by the generic link's basename;
                // when the two differ the package ships the link under
                // its registered name (arch-suffixed provider names,
                // renamed session links, slave names). A %ghost at
                // /etc/alternatives/<name> for the same registration is
                // the link this finding looks for, so it is credited.
                // The reference derives the path from the basename and
                // fires anyway (ledgered divergence).
                let named_alt = format!("/etc/alternatives/{name}");
                let shipped_under_name = name != link_base
                    && file_names.contains(&named_alt.as_str())
                    && pkg.ghost_files.iter().any(|g| g == &named_alt);
                if !shipped_under_name {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "alternative-link-missing",
                        &[&etc_alt],
                    );
                }
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
    use crate::color::Color;
    use crate::pkg::pkgfile::PkgFile;

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
        assert_eq!(
            slaves,
            vec![("/usr/bin/bar".to_string(), "bar".to_string())]
        );
    }

    #[test]
    fn template_link_is_detected() {
        // Loop-carried spellings seen in the corpus: db48-utils ($i),
        // compatlibopenblas (${lib}), python-ctranslate2 ($bin).
        assert!(AlternativesCheck::link_is_template("/usr/bin/db_$i"));
        assert!(AlternativesCheck::link_is_template("/usr/lib64/${lib}"));
        assert!(AlternativesCheck::link_is_template("/usr/bin/$bin"));
        assert!(!AlternativesCheck::link_is_template("/usr/bin/foo"));
        assert!(!AlternativesCheck::link_is_template(
            "/usr/share/man/man1/foo.1.gz"
        ));
    }

    #[test]
    fn template_install_line_extracts_template_link() {
        // The extraction itself is unchanged (the phase checks judge the
        // install set as before); only the file-list lookups skip it.
        let lines = vec![
            "update-alternatives --install /usr/bin/$bin $bin /usr/bin/$bin-3.13 1313".to_string(),
        ];
        let (install, slaves) = AlternativesCheck::find_binaries(&lines);
        assert_eq!(
            install,
            vec![("/usr/bin/$bin".to_string(), "$bin".to_string())]
        );
        assert!(slaves.is_empty());
    }

    #[test]
    fn supports_marker_needs_a_registration() {
        let install = vec![("/usr/bin/foo".to_string(), "foo".to_string())];
        let slaves = vec![("/usr/bin/bar".to_string(), "bar".to_string())];
        // A shipped /etc/alternatives entry is a registration even
        // when %post installs nothing (the sibling-split shape).
        assert!(AlternativesCheck::registers_update_alternatives(
            true,
            &[],
            &[]
        ));
        // An --install in %post registers; so does a lone --slave.
        assert!(AlternativesCheck::registers_update_alternatives(
            false,
            &install,
            &[]
        ));
        assert!(AlternativesCheck::registers_update_alternatives(
            false,
            &[],
            &slaves
        ));
        // Scriptlet mentions that only remove or inspect legacy
        // registrations register nothing: no marker.
        assert!(!AlternativesCheck::registers_update_alternatives(
            false,
            &[],
            &[]
        ));
    }

    #[test]
    fn cleanup_only_post_install_set_is_empty() {
        // The decidable core of the supports marker: the check's own
        // parser finds no install or slave in a cleanup-only %post.
        let lines = vec![
            "if [ -x /usr/sbin/update-alternatives ]; then".to_string(),
            "update-alternatives --display foo >/dev/null 2>&1 && update-alternatives --remove-all foo"
                .to_string(),
            "update-alternatives --remove foo /usr/bin/foo-1.0".to_string(),
        ];
        let (install, slaves) = AlternativesCheck::find_binaries(&lines);
        assert!(install.is_empty());
        assert!(slaves.is_empty());
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
    fn postun_remove_of_plus_suffixed_name_is_credited() {
        let install = vec![("/usr/bin/tolua++".to_string(), "tolua++".to_string())];
        let lines = vec!["update-alternatives --remove tolua++ /usr/bin/toluapp-5.1".to_string()];
        let missing = AlternativesCheck::check_postun_phase(&lines, &install);
        assert!(missing.is_empty());
    }

    #[test]
    fn postun_remove_paren_terminated_is_credited() {
        let install = vec![("/usr/bin/foo".to_string(), "foo".to_string())];
        let lines = vec!["x=$(update-alternatives --remove foo)".to_string()];
        let missing = AlternativesCheck::check_postun_phase(&lines, &install);
        assert!(missing.is_empty());
    }

    #[test]
    fn postun_remove_of_longer_name_does_not_credit_prefix() {
        let install = vec![("/usr/bin/tolua+".to_string(), "tolua+".to_string())];
        let lines = vec!["update-alternatives --remove tolua++ /usr/bin/toluapp-5.1".to_string()];
        let missing = AlternativesCheck::check_postun_phase(&lines, &install);
        assert_eq!(missing, vec!["tolua+".to_string()]);
    }

    #[test]
    fn postun_remove_of_suffixed_word_name_does_not_credit() {
        let install = vec![("/usr/bin/foo".to_string(), "foo".to_string())];
        let lines = vec!["update-alternatives --remove foo2 /usr/bin/foo2-1.0".to_string()];
        let missing = AlternativesCheck::check_postun_phase(&lines, &install);
        assert_eq!(missing, vec!["foo".to_string()]);
    }

    fn postun_results(postun: &str, install: &[(&str, &str)]) -> Vec<(String, String)> {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkg = libalternatives_pkg(dir.path(), &[]);
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let install: Vec<(String, String)> = install
            .iter()
            .map(|(l, n)| (l.to_string(), n.to_string()))
            .collect();
        AlternativesCheck::check_postun(&pkg, postun, &install, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn postun_phase_silent_when_post_installed_nothing() {
        // Presence without an install (a cleanup-only %post, or only
        // shipped /etc/alternatives files): no removal is owed however
        // %postun looks.
        let results = postun_results("", &[]);
        assert!(!has(&results, "update-alternatives-postun-call-missing"));
        let results = postun_results("update-alternatives --remove foo /usr/bin/foo-1.0", &[]);
        assert!(!has(&results, "update-alternatives-postun-call-missing"));
    }

    #[test]
    fn postun_phase_reports_when_install_is_never_removed() {
        let results = postun_results("", &[("/usr/bin/foo", "foo")]);
        assert_eq!(
            results
                .iter()
                .filter(|(n, _)| n == "update-alternatives-postun-call-missing")
                .count(),
            1
        );
        let results = postun_results(
            "update-alternatives --remove bar /usr/bin/bar-1.0",
            &[("/usr/bin/foo", "foo")],
        );
        assert!(has(&results, "update-alternatives-postun-call-missing"));
    }

    fn libalternatives_pkg(dir: &std::path::Path, confs: &[(&str, &str)]) -> Pkg {
        // `confs`: (conf file name, conf content). Writes each conf under
        // usr/share/libalternatives/<stem>/ and wires up the binary and man
        // files the entries point at, so only the findings under test fire.
        let mut pkg = Pkg::open(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm"),
            &std::env::temp_dir(),
            true,
        )
        .expect("open fixture pkg");
        pkg.name = "alternatives-test".to_string();
        pkg.files.clear();
        for (conf_name, content) in confs {
            let stem = conf_name.trim_end_matches(".conf");
            let rel = format!("usr/share/libalternatives/{stem}/{conf_name}");
            let path = dir.join(&rel);
            std::fs::create_dir_all(path.parent().unwrap()).expect("mkdirs");
            std::fs::write(&path, content).expect("write conf");
            pkg.files.push(PkgFile {
                name: format!("/{rel}"),
                path: path.to_string_lossy().into_owned(),
                mode: 0o100644,
                ..Default::default()
            });
            let bin = format!("/usr/bin/{stem}");
            pkg.files.push(PkgFile {
                name: bin,
                mode: 0o100755,
                ..Default::default()
            });
            let man = format!("/usr/share/man/man1/{stem}.1.gz");
            pkg.files.push(PkgFile {
                name: man,
                mode: 0o100644,
                ..Default::default()
            });
        }
        pkg
    }

    fn findings_for(pkg: &Pkg) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = AlternativesCheck::new(&config);
        check.check_binary(pkg, &config, &mut out);
        out.results().to_vec()
    }

    fn has(results: &[(String, String)], name: &str) -> bool {
        results.iter().any(|(n, _)| n == name)
    }

    /// `man_found` resets for every `.conf` file (like the reference),
    /// so two files each with one `man` line are not `double-entries`.
    #[test]
    fn man_found_resets_per_conf_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let conf = |stem: &str| {
            (
                format!("{stem}.conf"),
                format!("binary = /usr/bin/{stem}\nman = {stem}.1\n"),
            )
        };
        let a = conf("foo-a");
        let b = conf("foo-b");
        let pkg = libalternatives_pkg(dir.path(), &[(&a.0, &a.1), (&b.0, &b.1)]);
        let results = findings_for(&pkg);
        assert!(
            !has(&results, "double-entries"),
            "man_found leaked across conf files: {results:?}"
        );
    }

    /// The other direction: two `man` lines in one file still fire.
    #[test]
    fn double_man_entries_in_one_file_still_fire() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkg = libalternatives_pkg(
            dir.path(),
            &[(
                "foo.conf",
                "binary = /usr/bin/foo\nman = foo.1\nman = foo.1\n",
            )],
        );
        let results = findings_for(&pkg);
        assert!(
            has(&results, "double-entries"),
            "expected double-entries: {results:?}"
        );
    }

    /// The reference resets `man_found` per man entry, so after a
    /// `man=` line it holds only the last entry's result: a second `man=`
    /// line following a line whose last man was missing is validated, not
    /// reported as `double-entries`.
    #[test]
    fn man_found_holds_only_the_last_entry_result() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkg = libalternatives_pkg(
            dir.path(),
            &[(
                "foo.conf",
                "binary = /usr/bin/foo\nman = missing.1\nman = foo.1\n",
            )],
        );
        let results = findings_for(&pkg);
        assert!(
            !has(&results, "double-entries"),
            "second man= line falsely reported as double-entries: {results:?}"
        );
        // Pin the finding detail, not just the name: the missing entry is
        // on line 2 of foo.conf.
        let detail = results
            .iter()
            .find(|(n, _)| n == "man-entry-value-not-found")
            .map(|(_, d)| d.clone())
            .expect("missing man entry was not validated");
        assert!(
            detail.contains("foo.conf"),
            "detail should pin foo.conf, got: {detail}"
        );
    }

    /// Two `man=` lines whose entries are both missing each warn: the
    /// reference validates every line (AlternativesCheck.py:264-271 resets
    /// `man_found` per entry, so after a line it holds only the last
    /// entry's result). A second line must not be swallowed as
    /// `double-entries` when the previous line's last entry was also
    /// missing -- the missing entry would go unreported.
    #[test]
    fn two_missing_man_lines_warn_per_entry_not_double_entries() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkg = libalternatives_pkg(
            dir.path(),
            &[(
                "foo.conf",
                "binary = /usr/bin/foo\nman = missing-one.1\nman = missing-two.1\n",
            )],
        );
        let results = findings_for(&pkg);
        let warnings: Vec<&(String, String)> = results
            .iter()
            .filter(|(n, _)| n == "man-entry-value-not-found")
            .collect();
        assert_eq!(
            warnings.len(),
            2,
            "expected one warning per missing man entry, got {results:?}"
        );
        // FREEZE THE OUTPUT: pin both whole rendered lines, including the
        // per-line `Line: N` component the contains-based asserts could not
        // see -- a constant line number must fail this test.
        let expected = [
            "alternatives-test.noarch: W: man-entry-value-not-found /usr/share/libalternatives/foo/foo.conf Line: 1",
            "alternatives-test.noarch: W: man-entry-value-not-found /usr/share/libalternatives/foo/foo.conf Line: 2",
        ];
        for (i, (name, line)) in warnings.iter().enumerate() {
            assert_eq!(name, "man-entry-value-not-found");
            assert_eq!(line.as_str(), expected[i], "frozen output line {i}");
        }
        assert!(
            !has(&results, "double-entries"),
            "double-entries must not fire when the previous line's last man \
             was also missing: {results:?}"
        );
    }

    /// A package-chosen symlink basename with an unbalanced bracket makes the
    /// libalternatives conf pattern uncompilable (the reference raises
    /// `re.error` at `AlternativesCheck.py:216`); the check must skip the one
    /// finding instead of panicking (ledgered as
    /// `alternatives-regex-from-package-path`).
    #[test]
    fn invalid_regex_from_package_path_skips_finding() {
        let dir = tempfile::tempdir().expect("tmpdir");
        // The dummy conf makes has_libalts true so the libalternatives
        // file-list checks run at all.
        let mut pkg =
            libalternatives_pkg(dir.path(), &[("dummy.conf", "binary = /usr/bin/dummy\n")]);
        pkg.files.push(PkgFile {
            name: "/usr/bin/w6[cmd".to_string(),
            mode: 0o120777,
            linkto: "alts".to_string(),
            ..Default::default()
        });
        // The directory itself must exist for the conf-pattern branch to run.
        pkg.files.push(PkgFile {
            name: "/usr/share/libalternatives/w6[cmd".to_string(),
            mode: 0o040755,
            ..Default::default()
        });
        // Must not panic; the uncompilable pattern skips the finding.
        let results = findings_for(&pkg);
        assert!(
            !has(&results, "empty-libalternatives-directory"),
            "uncompilable pattern should skip the finding: {results:?}"
        );
    }

    #[test]
    fn requirement_regex_matches_paths() {
        let re = AlternativesCheck::requirement_regex();
        assert!(is_match(re, "update-alternatives"));
        assert!(is_match(re, "/usr/bin/update-alternatives"));
        assert!(!is_match(re, "update-alternatives-foo"));
    }

    /// `alts-requirement-missed`: a package shipping libalternatives content
    /// without an `alts` requirement. The `libalternatives_pkg` helper wires
    /// no requirement, so the finding fires; the level and empty detail are
    /// pinned.
    #[test]
    fn alts_requirement_missed_fires_without_alts_require() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkg = libalternatives_pkg(dir.path(), &[("foo.conf", "binary = /usr/bin/foo\n")]);
        let results = findings_for(&pkg);
        let missed: Vec<&(String, String)> = results
            .iter()
            .filter(|(n, _)| n == "alts-requirement-missed")
            .collect();
        assert_eq!(
            missed.len(),
            1,
            "expected alts-requirement-missed: {results:?}"
        );
        assert_eq!(
            missed[0].1.as_str(),
            "alternatives-test.noarch: E: alts-requirement-missed",
            "level/name",
        );
    }

    /// `libalternatives-directory-not-exists`: a symlink with `linkto == "alts"`
    /// whose `/usr/share/libalternatives/<basename>` directory is absent.
    #[test]
    fn libalternatives_directory_not_exists_fires() {
        let dir = tempfile::tempdir().expect("tmpdir");
        // The dummy conf makes has_libalts true so the file-list checks run.
        let mut pkg =
            libalternatives_pkg(dir.path(), &[("dummy.conf", "binary = /usr/bin/dummy\n")]);
        pkg.files.push(PkgFile {
            name: "/usr/bin/lonely".to_string(),
            mode: 0o120777,
            linkto: "alts".to_string(),
            ..Default::default()
        });
        let results = findings_for(&pkg);
        let missing: Vec<&(String, String)> = results
            .iter()
            .filter(|(n, _)| n == "libalternatives-directory-not-exists")
            .collect();
        assert_eq!(
            missing.len(),
            1,
            "expected libalternatives-directory-not-exists: {results:?}"
        );
        assert!(
            missing[0].1.starts_with(
                "alternatives-test.noarch: E: libalternatives-directory-not-exists \
                 /usr/share/libalternatives/lonely"
            ),
            "level/name/detail: {}",
            missing[0].1
        );
    }

    /// `empty-libalternatives-directory`: the libalternatives directory exists
    /// but holds no `.conf` file. The directory-not-exists finding must not
    /// fire alongside it.
    #[test]
    fn empty_libalternatives_directory_fires() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut pkg =
            libalternatives_pkg(dir.path(), &[("dummy.conf", "binary = /usr/bin/dummy\n")]);
        pkg.files.push(PkgFile {
            name: "/usr/bin/lonely".to_string(),
            mode: 0o120777,
            linkto: "alts".to_string(),
            ..Default::default()
        });
        pkg.files.push(PkgFile {
            name: "/usr/share/libalternatives/lonely".to_string(),
            mode: 0o040755,
            ..Default::default()
        });
        let results = findings_for(&pkg);
        let empty: Vec<&(String, String)> = results
            .iter()
            .filter(|(n, _)| n == "empty-libalternatives-directory")
            .collect();
        assert_eq!(
            empty.len(),
            1,
            "expected exactly one empty-libalternatives-directory: {results:?}"
        );
        assert!(
            !has(&results, "libalternatives-directory-not-exists"),
            "directory exists, so not-exists must not fire: {results:?}"
        );
        let line = results
            .iter()
            .find(|(n, _)| n == "empty-libalternatives-directory")
            .map(|(_, l)| l.as_str())
            .unwrap();
        assert!(
            line.starts_with(
                "alternatives-test.noarch: E: empty-libalternatives-directory \
                 /usr/share/libalternatives/lonely"
            ),
            "level/name/detail: {line}"
        );
    }

    /// `libalternatives-conf-not-found`: a `.conf` under libalternatives whose
    /// on-disk path does not exist — Error for a real file, Info for a ghost.
    #[test]
    fn libalternatives_conf_not_found_fires() {
        use crate::pkg::pkgfile::RPMFILE_GHOST;

        let dir = tempfile::tempdir().expect("tmpdir");
        let mut pkg =
            libalternatives_pkg(dir.path(), &[("dummy.conf", "binary = /usr/bin/dummy\n")]);
        pkg.files.push(PkgFile {
            name: "/usr/share/libalternatives/gone/gone.conf".to_string(),
            path: dir
                .path()
                .join("does-not-exist.conf")
                .to_string_lossy()
                .into_owned(),
            mode: 0o100644,
            ..Default::default()
        });
        pkg.files.push(PkgFile {
            name: "/usr/share/libalternatives/ghosted/ghosted.conf".to_string(),
            path: dir
                .path()
                .join("does-not-exist-either.conf")
                .to_string_lossy()
                .into_owned(),
            mode: 0o100644,
            flags: RPMFILE_GHOST,
            ..Default::default()
        });
        let results = findings_for(&pkg);
        let not_found: Vec<&(String, String)> = results
            .iter()
            .filter(|(n, _)| n == "libalternatives-conf-not-found")
            .collect();
        assert_eq!(
            not_found.len(),
            2,
            "expected real + ghost conf-not-found: {results:?}"
        );
        let real = not_found
            .iter()
            .find(|(_, l)| l.contains("/gone/gone.conf"))
            .expect("real-file entry");
        assert!(
            real.1.starts_with(
                "alternatives-test.noarch: E: libalternatives-conf-not-found \
                 /usr/share/libalternatives/gone/gone.conf"
            ),
            "real file is Error: {}",
            real.1
        );
        let ghost = not_found
            .iter()
            .find(|(_, l)| l.contains("/ghosted/ghosted.conf"))
            .expect("ghost entry");
        assert!(
            ghost
                .1
                .starts_with("alternatives-test.noarch: I: libalternatives-conf-not-found"),
            "ghost file is Info: {}",
            ghost.1
        );
    }

    /// `libalternatives-conf-not-found` does NOT fire when the parent
    /// directory is also missing from disk: the whole subtree failed to
    /// extract (e.g. ENOSPC during the container audit, issue #406), so the
    /// missing conf is an extraction artifact, not a packaging error.
    #[test]
    fn libalternatives_conf_not_found_skipped_when_parent_dir_missing() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut pkg =
            libalternatives_pkg(dir.path(), &[("dummy.conf", "binary = /usr/bin/dummy\n")]);
        // The conf path and its parent directory both do not exist on disk.
        let missing_dir = dir.path().join("no-such-dir");
        pkg.files.push(PkgFile {
            name: "/usr/share/libalternatives/nodir/nodir.conf".to_string(),
            path: missing_dir
                .join("nodir.conf")
                .to_string_lossy()
                .into_owned(),
            mode: 0o100644,
            ..Default::default()
        });
        let results = findings_for(&pkg);
        let not_found: Vec<&(String, String)> = results
            .iter()
            .filter(|(n, _)| n == "libalternatives-conf-not-found")
            .collect();
        assert_eq!(
            not_found.len(),
            0,
            "conf-not-found must not fire when the parent dir was not extracted: {results:?}"
        );
    }

    /// Ghost variant: the extraction-artifact guard `continue`s before the
    /// `is_ghost()` branch, so a ghost conf whose parent dir is also missing
    /// is skipped rather than reported as Info.
    #[test]
    fn libalternatives_conf_not_found_skipped_for_ghost_when_parent_dir_missing() {
        use crate::pkg::pkgfile::RPMFILE_GHOST;

        let dir = tempfile::tempdir().expect("tmpdir");
        let mut pkg =
            libalternatives_pkg(dir.path(), &[("dummy.conf", "binary = /usr/bin/dummy\n")]);
        // The ghost conf path and its parent directory both do not exist.
        let missing_dir = dir.path().join("no-such-dir");
        pkg.files.push(PkgFile {
            name: "/usr/share/libalternatives/nodir-ghost/nodir-ghost.conf".to_string(),
            path: missing_dir
                .join("nodir-ghost.conf")
                .to_string_lossy()
                .into_owned(),
            mode: 0o100644,
            flags: RPMFILE_GHOST,
            ..Default::default()
        });
        let results = findings_for(&pkg);
        let not_found: Vec<&(String, String)> = results
            .iter()
            .filter(|(n, _)| n == "libalternatives-conf-not-found")
            .collect();
        assert_eq!(
            not_found.len(),
            0,
            "ghost conf-not-found must not fire when the parent dir was not extracted: {results:?}"
        );
    }

    /// `wrong-tag-found`, `wrong-entry-format`, `binary-entry-value-not-found`:
    /// conf content validation. Mirrors the reference's borked-conf shapes
    /// (test_alternatives.py:92).
    #[test]
    fn conf_content_validations_fire() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkg = libalternatives_pkg(
            dir.path(),
            &[(
                "borked.conf",
                "binary = /usr/bin/nowhere\nbogus = 1\nnot a kv line\n",
            )],
        );
        let results = findings_for(&pkg);
        for name in [
            "binary-entry-value-not-found",
            "wrong-tag-found",
            "wrong-entry-format",
        ] {
            let count = results.iter().filter(|(n, _)| n == name).count();
            assert_eq!(count, 1, "expected exactly one {name}: {results:?}");
        }
        let line = |name: &str| {
            results
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, l)| l.as_str())
                .unwrap()
        };
        assert!(
            line("binary-entry-value-not-found")
                .starts_with("alternatives-test.noarch: W: binary-entry-value-not-found"),
            "warning level: {}",
            line("binary-entry-value-not-found")
        );
        assert!(
            line("wrong-tag-found").starts_with("alternatives-test.noarch: W: wrong-tag-found"),
            "warning level: {}",
            line("wrong-tag-found")
        );
        assert!(
            line("wrong-entry-format")
                .starts_with("alternatives-test.noarch: E: wrong-entry-format"),
            "error level: {}",
            line("wrong-entry-format")
        );
    }

    /// A `binary=` entry pointing at a file the package ships outside
    /// every bin/ path (salt keeps its libalternatives targets in
    /// /usr/libexec/salt/) satisfies the entry: neither
    /// `binary-entry-value-not-found` nor `wrong-or-missed-binary-entry`
    /// fires (issue #811).
    #[test]
    fn binary_entry_found_at_exact_libexec_path() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut pkg = libalternatives_pkg(
            dir.path(),
            &[("salt.conf", "binary=/usr/libexec/salt/salt-3.13\n")],
        );
        for f in pkg.files.iter_mut() {
            if f.name == "/usr/bin/salt" {
                f.name = "/usr/libexec/salt/salt-3.13".to_string();
            }
        }
        let results = findings_for(&pkg);
        for name in [
            "binary-entry-value-not-found",
            "wrong-or-missed-binary-entry",
        ] {
            assert!(
                !has(&results, name),
                "{name} must not fire when the entry target is shipped: {results:?}"
            );
        }
    }

    /// The exact-path acceptance does not silence genuine misses: a
    /// `binary=` entry whose libexec target the package does not ship
    /// still draws both findings (issue #811).
    #[test]
    fn binary_entry_missing_at_libexec_path_still_fires() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkg = libalternatives_pkg(
            dir.path(),
            &[("salt.conf", "binary=/usr/libexec/salt/absent-3.13\n")],
        );
        let results = findings_for(&pkg);
        for name in [
            "binary-entry-value-not-found",
            "wrong-or-missed-binary-entry",
        ] {
            let count = results.iter().filter(|(n, _)| n == name).count();
            assert_eq!(count, 1, "expected exactly one {name}: {results:?}");
        }
    }

    /// A libalternatives group may register only a man page: a conf
    /// whose lines carry no `binary=` entry has no binary entry to
    /// miss, so neither binary finding fires (issue #931).
    #[test]
    fn man_only_conf_draws_no_binary_findings() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkg = libalternatives_pkg(dir.path(), &[("foo.conf", "man = foo.1\n")]);
        let results = findings_for(&pkg);
        for name in [
            "binary-entry-value-not-found",
            "wrong-or-missed-binary-entry",
        ] {
            assert!(
                !has(&results, name),
                "{name} must not fire for a man-only conf: {results:?}"
            );
        }
    }

    /// Silencing the summary finding for a man-only conf does not
    /// silence the conf's man validation (issue #931).
    #[test]
    fn man_only_conf_with_missing_man_still_warns_for_the_man() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkg = libalternatives_pkg(dir.path(), &[("foo.conf", "man = absent.1\n")]);
        let results = findings_for(&pkg);
        assert!(
            has(&results, "man-entry-value-not-found"),
            "missing man entry must still be reported: {results:?}"
        );
        assert!(
            !has(&results, "wrong-or-missed-binary-entry"),
            "man-only conf must not draw the binary summary: {results:?}"
        );
    }

    /// A `binary=` entry whose path reaches its shipped file through
    /// a directory symlink the package itself ships (the JDK layout)
    /// satisfies the entry: neither binary finding fires (issue #932).
    #[test]
    fn binary_entry_through_shipped_dir_symlink_is_credited() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut pkg = libalternatives_pkg(
            dir.path(),
            &[(
                "jar.conf",
                "binary=/usr/lib64/jvm/java-11-openjdk/bin/jar\n",
            )],
        );
        pkg.files.push(PkgFile {
            name: "/usr/lib64/jvm/java-11-openjdk".to_string(),
            mode: 0o120777,
            linkto: "java-11-openjdk-11".to_string(),
            ..Default::default()
        });
        pkg.files.push(PkgFile {
            name: "/usr/lib64/jvm/java-11-openjdk-11/bin/jar".to_string(),
            mode: 0o100755,
            ..Default::default()
        });
        let results = findings_for(&pkg);
        for name in [
            "binary-entry-value-not-found",
            "wrong-or-missed-binary-entry",
        ] {
            assert!(
                !has(&results, name),
                "{name} must not fire when the entry resolves through a                  shipped dir symlink: {results:?}"
            );
        }
    }

    /// The same credit with an absolute symlink target (issue #932).
    #[test]
    fn binary_entry_through_absolute_dir_symlink_is_credited() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut pkg = libalternatives_pkg(
            dir.path(),
            &[(
                "jar.conf",
                "binary=/usr/lib64/jvm/java-11-openjdk/bin/jar\n",
            )],
        );
        pkg.files.push(PkgFile {
            name: "/usr/lib64/jvm/java-11-openjdk".to_string(),
            mode: 0o120777,
            linkto: "/usr/lib64/jvm/java-11-openjdk-11".to_string(),
            ..Default::default()
        });
        pkg.files.push(PkgFile {
            name: "/usr/lib64/jvm/java-11-openjdk-11/bin/jar".to_string(),
            mode: 0o100755,
            ..Default::default()
        });
        let results = findings_for(&pkg);
        for name in [
            "binary-entry-value-not-found",
            "wrong-or-missed-binary-entry",
        ] {
            assert!(
                !has(&results, name),
                "{name} must not fire when the entry resolves through an                  absolute dir symlink: {results:?}"
            );
        }
    }

    /// Resolution follows a chain: a directory symlink whose target
    /// climbs with `..`, landing on a file that is itself a symlink
    /// to the shipped entry (issue #932).
    #[test]
    fn binary_entry_through_symlink_chain_is_credited() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut pkg = libalternatives_pkg(
            dir.path(),
            &[("jar.conf", "binary=/usr/lib/jvm/default/bin/jar\n")],
        );
        pkg.files.push(PkgFile {
            name: "/usr/lib/jvm/default".to_string(),
            mode: 0o120777,
            linkto: "../jvm/java-11-openjdk-11".to_string(),
            ..Default::default()
        });
        pkg.files.push(PkgFile {
            name: "/usr/lib/jvm/java-11-openjdk-11/bin/jar".to_string(),
            mode: 0o120777,
            linkto: "jar-11".to_string(),
            ..Default::default()
        });
        pkg.files.push(PkgFile {
            name: "/usr/lib/jvm/java-11-openjdk-11/bin/jar-11".to_string(),
            mode: 0o100755,
            ..Default::default()
        });
        let results = findings_for(&pkg);
        for name in [
            "binary-entry-value-not-found",
            "wrong-or-missed-binary-entry",
        ] {
            assert!(
                !has(&results, name),
                "{name} must not fire when the entry resolves through a                  symlink chain: {results:?}"
            );
        }
    }

    /// The symlink credit stops at the package boundary: the entry
    /// resolves through the shipped directory symlink to a file the
    /// package does not ship, so both findings still fire (issue
    /// #932).
    #[test]
    fn binary_entry_through_dir_symlink_to_unshipped_file_still_fires() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut pkg = libalternatives_pkg(
            dir.path(),
            &[(
                "jar.conf",
                "binary=/usr/lib64/jvm/java-11-openjdk/bin/jar\n",
            )],
        );
        pkg.files.push(PkgFile {
            name: "/usr/lib64/jvm/java-11-openjdk".to_string(),
            mode: 0o120777,
            linkto: "java-11-openjdk-11".to_string(),
            ..Default::default()
        });
        pkg.files.push(PkgFile {
            name: "/usr/lib64/jvm/java-11-openjdk-11/bin/javac".to_string(),
            mode: 0o100755,
            ..Default::default()
        });
        let results = findings_for(&pkg);
        for name in [
            "binary-entry-value-not-found",
            "wrong-or-missed-binary-entry",
        ] {
            let count = results.iter().filter(|(n, _)| n == name).count();
            assert_eq!(count, 1, "expected exactly one {name}: {results:?}");
        }
    }

    /// A symlink cycle never resolves: the walk terminates and the
    /// entry keeps both findings (issue #932).
    #[test]
    fn binary_entry_through_symlink_loop_still_fires() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut pkg = libalternatives_pkg(
            dir.path(),
            &[("jar.conf", "binary=/usr/lib/jvm/loop/bin/jar\n")],
        );
        pkg.files.push(PkgFile {
            name: "/usr/lib/jvm/loop".to_string(),
            mode: 0o120777,
            linkto: "loop2".to_string(),
            ..Default::default()
        });
        pkg.files.push(PkgFile {
            name: "/usr/lib/jvm/loop2".to_string(),
            mode: 0o120777,
            linkto: "loop".to_string(),
            ..Default::default()
        });
        let results = findings_for(&pkg);
        for name in [
            "binary-entry-value-not-found",
            "wrong-or-missed-binary-entry",
        ] {
            let count = results.iter().filter(|(n, _)| n == name).count();
            assert_eq!(count, 1, "expected exactly one {name}: {results:?}");
        }
    }

    /// The resolver credit requires a regular file: an entry whose
    /// path resolves through a shipped directory symlink onto a
    /// directory the package ships is not satisfied, so both
    /// findings still fire (issue #938).
    #[test]
    fn binary_entry_resolving_to_directory_still_fires() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut pkg = libalternatives_pkg(
            dir.path(),
            &[("jar.conf", "binary=/usr/lib64/jvm/java-11-openjdk/bin\n")],
        );
        pkg.files.push(PkgFile {
            name: "/usr/lib64/jvm/java-11-openjdk".to_string(),
            mode: 0o120777,
            linkto: "java-11-openjdk-11".to_string(),
            ..Default::default()
        });
        pkg.files.push(PkgFile {
            name: "/usr/lib64/jvm/java-11-openjdk-11/bin".to_string(),
            mode: 0o040755,
            ..Default::default()
        });
        let results = findings_for(&pkg);
        for name in [
            "binary-entry-value-not-found",
            "wrong-or-missed-binary-entry",
        ] {
            let count = results.iter().filter(|(n, _)| n == name).count();
            assert_eq!(count, 1, "expected exactly one {name}: {results:?}");
        }
    }

    /// A cycle whose walk happens to land on a shipped file's name
    /// when the hop bound runs out earns no credit: the resolution
    /// never lands (the kernel's ELOOP), so both findings still
    /// fire (issue #938).
    #[test]
    fn binary_entry_through_cycle_landing_on_shipped_name_still_fires() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mut pkg = libalternatives_pkg(
            dir.path(),
            &[("jar.conf", "binary=/usr/lib/jvm/a/bin/jar\n")],
        );
        for (name, linkto) in [
            ("/usr/lib/jvm/a", "b"),
            ("/usr/lib/jvm/b", "c"),
            ("/usr/lib/jvm/c", "a"),
        ] {
            pkg.files.push(PkgFile {
                name: name.to_string(),
                mode: 0o120777,
                linkto: linkto.to_string(),
                ..Default::default()
            });
        }
        pkg.files.push(PkgFile {
            name: "/usr/lib/jvm/b/bin/jar".to_string(),
            mode: 0o100755,
            ..Default::default()
        });
        let results = findings_for(&pkg);
        for name in [
            "binary-entry-value-not-found",
            "wrong-or-missed-binary-entry",
        ] {
            let count = results.iter().filter(|(n, _)| n == name).count();
            assert_eq!(count, 1, "expected exactly one {name}: {results:?}");
        }
    }

    /// A `binary=` value spelled with a doubled leading slash (the
    /// SUSE python packaging macros emit `binary=//usr/bin/...`)
    /// resolves to the file the package ships at the single-slash
    /// path, so neither binary finding fires (issue #932).
    #[test]
    fn binary_entry_with_doubled_leading_slash_is_credited() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let pkg = libalternatives_pkg(dir.path(), &[("foo.conf", "binary=//usr/bin/foo\n")]);
        let results = findings_for(&pkg);
        for name in [
            "binary-entry-value-not-found",
            "wrong-or-missed-binary-entry",
        ] {
            assert!(
                !has(&results, name),
                "{name} must not fire for a doubled-slash entry naming a                  shipped file: {results:?}"
            );
        }
    }
}
