//! `MenuCheck` — legacy menu file validation.
//!
//! Ported from `rpmlint/checks/MenuCheck.py`. The reference preprocesses
//! menu files with `/lib/cpp`; this port does the equivalent natively
//! (strip `#` comment lines, join backslash continuations) so no subprocess
//! is needed.

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

use super::shared::script_body_or_prog;
use crate::pkg::pkgfile::is_reg;
use librpm::Tag;
use std::sync::OnceLock;

pub struct MenuCheck {
    valid_sections: Vec<String>,
    standard_needs: Vec<String>,
    icon_paths: Vec<(String, String, String)>,
    launchers: Vec<(String, Regex, Vec<String>)>,
    icon_ext_regex: Regex,
}

impl MenuCheck {
    pub fn new(config: &Config) -> Self {
        let get_str_list = |key: &str| {
            config
                .configuration
                .get(key)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        // Sort explicitly: the toml table order is serialization-dependent,
        // while the reference walks IconPath in config-file order. The
        // resulting emission order is ledgered as a deliberate divergence.
        let icon_paths: Vec<(String, String, String)> = config
            .configuration
            .get("IconPath")
            .and_then(|v| v.as_table())
            .map(|t| {
                t.iter()
                    .map(|(k, v)| {
                        let path = v
                            .get("path")
                            .and_then(|p| p.as_str())
                            .unwrap_or("")
                            .to_string();
                        let typ = v
                            .get("type")
                            .and_then(|p| p.as_str())
                            .unwrap_or("")
                            .to_string();
                        (k.clone(), path, typ)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let launchers: Vec<(String, Regex, Vec<String>)> = config
            .configuration
            .get("MenuLaunchers")
            .and_then(|v| v.as_table())
            .map(|t| {
                t.iter()
                    .filter_map(|(k, v)| {
                        let regexp = v.get("regexp")?.as_str()?;
                        let binaries = v
                            .get("binaries")
                            .and_then(|b| b.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str().map(str::to_string))
                                    .collect()
                            })
                            .unwrap_or_default();
                        // A malformed regexp in rpmlintrc must not panic the
                        // linter; skip it, as tags.rs does for Filters.
                        Some((k.clone(), Regex::new(regexp).ok()?, binaries))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let icon_ext = config
            .configuration
            .get("IconFilename")
            .and_then(|v| v.as_str())
            .unwrap_or(r".*\.png$");
        Self {
            valid_sections: get_str_list("ValidMenuSections"),
            standard_needs: get_str_list("ExtraMenuNeeds"),
            icon_paths,
            launchers,
            // Same reasoning as the launcher regexps: an uncompilable value
            // from rpmlintrc degrades to matching nothing rather than aborting
            // the run.
            icon_ext_regex: Regex::new(icon_ext).unwrap_or_else(|_| Regex::new("$^").unwrap()),
        }
    }

    /// Native equivalent of the reference's `/lib/cpp` preprocessing: drop
    /// `#` comment lines and join backslash continuations.
    fn preprocess(content: &str) -> String {
        let mut out = String::new();
        let mut pending = String::new();
        for line in content.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') && pending.is_empty() {
                continue;
            }
            if let Some(stripped) = line.strip_suffix('\\') {
                pending.push_str(stripped);
            } else {
                pending.push_str(line);
                out.push_str(&pending);
                out.push('\n');
                pending.clear();
            }
        }
        if !pending.is_empty() {
            out.push_str(&pending);
            out.push('\n');
        }
        out
    }

    fn menu_file_regex() -> &'static Regex {
        static MENU_FILE_REGEX: OnceLock<Regex> = OnceLock::new();
        MENU_FILE_REGEX
            .get_or_init(|| Regex::new(r"^/usr/lib/menu/([^/]+)$").expect("static regex"))
    }
    fn old_menu_file_regex() -> &'static Regex {
        static OLD_MENU_FILE_REGEX: OnceLock<Regex> = OnceLock::new();
        OLD_MENU_FILE_REGEX.get_or_init(|| {
            Regex::new(r"^/usr/share/(gnome/apps|applnk)/([^/]+)$").expect("static regex")
        })
    }
    fn xpm_ext_regex() -> &'static Regex {
        static XPM_EXT_REGEX: OnceLock<Regex> = OnceLock::new();
        XPM_EXT_REGEX.get_or_init(|| {
            Regex::new(r"/usr/share/icons/(mini/|large/).*\.xpm$").expect("static regex")
        })
    }
    fn update_menus_regex() -> &'static Regex {
        static UPDATE_MENUS_REGEX: OnceLock<Regex> = OnceLock::new();
        UPDATE_MENUS_REGEX
            .get_or_init(|| Regex::new(r"(?m)^[^#]*update-menus").expect("static regex"))
    }
}

impl Check for MenuCheck {
    fn name(&self) -> &'static str {
        "MenuCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let mut menus: Vec<String> = Vec::new();
        let none_regex = MENU_NONE_RE.get_or_init(|| Regex::new("None\",").expect("static regex"));

        for pkgfile in &pkg.files {
            let fname = pkgfile.name.as_str();
            let mode = pkgfile.mode;
            if let Some(caps) = Self::menu_file_regex().captures(fname).ok().flatten() {
                let basename = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if !is_reg(mode) {
                    add_info(out, Level::Error, pkg, "non-file-in-menu-dir", &[fname]);
                } else {
                    if basename != pkg.name {
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "non-coherent-menu-filename",
                            &[fname],
                        );
                    }
                    if mode & 0o444 != 0o444 {
                        add_info(out, Level::Error, pkg, "non-readable-menu-file", &[fname]);
                    }
                    if mode & 0o111 != 0 {
                        add_info(out, Level::Error, pkg, "executable-menu-file", &[fname]);
                    }
                    menus.push(fname.to_string());
                }
            } else if Self::old_menu_file_regex()
                .captures(fname)
                .ok()
                .flatten()
                .is_some()
            {
                if is_reg(mode) {
                    add_info(out, Level::Error, pkg, "old-menu-entry", &[fname]);
                }
            } else {
                if is_match(Self::xpm_ext_regex(), fname)
                    && is_reg(mode)
                    && pkg.grep(none_regex, fname).is_none()
                {
                    add_info(out, Level::Warning, pkg, "non-transparent-xpm", &[fname]);
                }
            }
            if fname.starts_with("/usr/lib64/menu") {
                add_info(out, Level::Error, pkg, "menu-in-wrong-dir", &[fname]);
            }
        }

        if menus.is_empty() {
            return;
        }

        let postin = script_body_or_prog(pkg, Tag::POSTIN, Tag::POSTINPROG);
        if postin.is_empty() {
            add_info(out, Level::Error, pkg, "menu-without-postin", &[]);
        } else if !is_match(Self::update_menus_regex(), &postin) {
            add_info(out, Level::Error, pkg, "postin-without-update-menus", &[]);
        }
        let postun = script_body_or_prog(pkg, Tag::POSTUN, Tag::POSTUNPROG);
        if postun.is_empty() {
            add_info(out, Level::Error, pkg, "menu-without-postun", &[]);
        } else if !is_match(Self::update_menus_regex(), &postun) {
            add_info(out, Level::Error, pkg, "postun-without-update-menus", &[]);
        }

        let file_names: Vec<&str> = pkg.files.iter().map(|f| f.name.as_str()).collect();
        let req_names: Vec<&str> = pkg.req_names.iter().map(String::as_str).collect();

        for f in &menus {
            let content = pkg.read_file(f);
            let text = Self::preprocess(&content);
            for line in text.lines() {
                if !line.starts_with('?') {
                    continue;
                }
                self.check_menu_line(pkg, out, f, line, &file_names, &req_names);
            }
        }
    }
}

/// MenuCheck.py:158 tests `title[0] != title[0].upper()` -- "is the first
/// character not already capitalised", which is not `is_lowercase`: a title
/// starting with a digit, `_` or an uncased symbol has no case and is quiet.
fn title_is_capitalized(title: &str) -> bool {
    title
        .chars()
        .next()
        .is_none_or(|c| c.to_uppercase().collect::<String>() == c.to_string())
}

static MENU_PACKAGE_RE: OnceLock<Regex> = OnceLock::new();
static MENU_COMMAND_RE: OnceLock<Regex> = OnceLock::new();
static MENU_LONGTITLE_RE: OnceLock<Regex> = OnceLock::new();
static MENU_TITLE_RE: OnceLock<Regex> = OnceLock::new();
static MENU_NEEDS_RE: OnceLock<Regex> = OnceLock::new();
static MENU_SECTION_RE: OnceLock<Regex> = OnceLock::new();
static MENU_ICON_RE: OnceLock<Regex> = OnceLock::new();
static MENU_VERSION_RE: OnceLock<Regex> = OnceLock::new();
static MENU_XDG_RE: OnceLock<Regex> = OnceLock::new();
static MENU_NONE_RE: OnceLock<Regex> = OnceLock::new();

impl MenuCheck {
    /// Check a menu title for capitalization, version, and slashes.
    fn check_title(
        &self,
        pkg: &Pkg,
        out: &mut Filter,
        version_re: &Regex,
        title: &str,
        long: bool,
    ) {
        // MenuCheck.py:158 tests `title[0] != title[0].upper()`, i.e. "is the
        // first character not already capitalised". That is not `is_lowercase`:
        // a title starting with a digit, `_` or an uncased symbol has no case
        // and is not a finding.
        if !title_is_capitalized(title) {
            add_info(
                out,
                Level::Warning,
                pkg,
                if long {
                    "menu-longtitle-not-capitalized"
                } else {
                    "menu-title-not-capitalized"
                },
                &[title],
            );
        }
        if is_match(version_re, title) {
            add_info(
                out,
                Level::Warning,
                pkg,
                if long {
                    "version-in-menu-longtitle"
                } else {
                    "version-in-menu-title"
                },
                &[title],
            );
        }
        if !long && title.contains('/') {
            add_info(out, Level::Error, pkg, "invalid-title", &[title]);
        }
    }

    /// Check one `?package(...)` menu entry line.
    fn check_menu_line(
        &self,
        pkg: &Pkg,
        out: &mut Filter,
        fname: &str,
        line: &str,
        files: &[&str],
        req_names: &[&str],
    ) {
        let package_re = MENU_PACKAGE_RE
            .get_or_init(|| Regex::new(r"\?package\((.*)\):").expect("static regex"));
        let command_re = MENU_COMMAND_RE.get_or_init(|| {
            Regex::new(r#"command=(?:"([^"]+)"|([^ \t]+))"#).expect("static regex")
        });
        let longtitle_re = MENU_LONGTITLE_RE.get_or_init(|| {
            Regex::new(r#"longtitle=(?:"([^"]+)"|([^ \t]+))"#).expect("static regex")
        });
        let title_re = MENU_TITLE_RE.get_or_init(|| {
            Regex::new(r#"["\s]title=(?:"([^"]+)"|([^ \t]+))"#).expect("static regex")
        });
        let needs_re = MENU_NEEDS_RE
            .get_or_init(|| Regex::new(r#"needs=("[^"]+"|([^ \t"]+))"#).expect("static regex"));
        let section_re = MENU_SECTION_RE
            .get_or_init(|| Regex::new(r#"section=("[^"]+"|([^ \t"]+))"#).expect("static regex"));
        let icon_re =
            MENU_ICON_RE.get_or_init(|| Regex::new(r#"icon="?([^" ]+)"#).expect("static regex"));
        let version_re = MENU_VERSION_RE
            .get_or_init(|| Regex::new(r"([0-9.][0-9.]+)($|\s)").expect("static regex"));
        let xdg_re =
            MENU_XDG_RE.get_or_init(|| Regex::new(r#"xdg="?([^" ]+)"#).expect("static regex"));

        match package_re.captures(line).ok().flatten() {
            Some(caps) => {
                let package = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if package != pkg.name {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "incoherent-package-value-in-menu",
                        &[package, fname],
                    );
                }
            }
            None => {
                add_info(out, Level::Info, pkg, "unable-to-parse-menu-entry", &[line]);
            }
        }

        let mut command: Option<String> = None;
        match command_re.captures(line).ok().flatten() {
            Some(caps) => {
                let cmd_line = caps
                    .get(1)
                    .or_else(|| caps.get(2))
                    .map(|m| m.as_str())
                    .unwrap_or("");
                let mut parts = cmd_line.split_whitespace();
                let mut cmd = parts.next().unwrap_or("").to_string();
                for (launcher_name, launcher_re, binaries) in &self.launchers {
                    let _ = launcher_name;
                    if !is_match(launcher_re, &cmd) {
                        continue;
                    }
                    if !binaries.is_empty() {
                        let found = ["/bin/", "/usr/bin/", "/usr/X11R6/bin/"]
                            .iter()
                            .any(|d| files.contains(&format!("{d}{cmd}").as_str()))
                            || binaries.iter().any(|b| req_names.contains(&b.as_str()));
                        if !found {
                            add_info(
                                out,
                                Level::Error,
                                pkg,
                                "use-of-launcher-in-menu-but-no-requires-on",
                                &[&binaries[0]],
                            );
                        }
                    }
                    cmd = parts.next().unwrap_or("").to_string();
                    break;
                }
                if cmd.starts_with('/') {
                    if !files.contains(&cmd.as_str()) {
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "menu-command-not-in-package",
                            &[&cmd],
                        );
                    }
                } else if !["/bin/", "/usr/bin/", "/usr/X11R6/bin/"]
                    .iter()
                    .any(|d| files.contains(&format!("{d}{cmd}").as_str()))
                {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "menu-command-not-in-package",
                        &[&cmd],
                    );
                }
                command = Some(cmd);
            }
            None => {
                add_info(out, Level::Warning, pkg, "missing-menu-command", &[]);
            }
        }

        match longtitle_re.captures(line).ok().flatten() {
            Some(caps) => {
                let title = caps
                    .get(1)
                    .or_else(|| caps.get(2))
                    .map(|m| m.as_str())
                    .unwrap_or("");
                self.check_title(pkg, out, version_re, title, true);
            }
            None => {
                add_info(out, Level::Error, pkg, "no-longtitle-in-menu", &[fname]);
            }
        }
        // The reference passes the parsed title (possibly None) as the
        // `no-icon-in-menu` detail; a missing title is a falsy detail that
        // the filter drops at print time.
        let title: Option<String> = match title_re.captures(line).ok().flatten() {
            Some(caps) => {
                let title = caps
                    .get(1)
                    .or_else(|| caps.get(2))
                    .map(|m| m.as_str())
                    .unwrap_or("");
                self.check_title(pkg, out, version_re, title, false);
                Some(title.to_string())
            }
            None => {
                add_info(out, Level::Error, pkg, "no-title-in-menu", &[fname]);
                None
            }
        };

        let mut needs = String::new();
        match needs_re.captures(line).ok().flatten() {
            Some(caps) => {
                let raw = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                needs = raw.trim_matches('"').to_lowercase();
                if ["x11", "text", "wm"].contains(&needs.as_str()) {
                    match section_re.captures(line).ok().flatten() {
                        Some(scaps) => {
                            let section = scaps
                                .get(1)
                                .map(|m| m.as_str().trim_matches('"'))
                                .unwrap_or("");
                            if command.is_some()
                                && !self.valid_sections.iter().any(|s| s == section)
                            {
                                add_info(
                                    out,
                                    Level::Error,
                                    pkg,
                                    "invalid-menu-section",
                                    &[section, fname],
                                );
                            }
                        }
                        None => {
                            add_info(
                                out,
                                Level::Info,
                                pkg,
                                "unable-to-parse-menu-section",
                                &[line],
                            );
                        }
                    }
                } else if !self.standard_needs.iter().any(|n| n == &needs) {
                    add_info(out, Level::Info, pkg, "strange-needs", &[&needs, fname]);
                }
            }
            None => {
                add_info(out, Level::Info, pkg, "unable-to-parse-menu-needs", &[line]);
            }
        }

        match icon_re.captures(line).ok().flatten() {
            Some(caps) => {
                let icon = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if !is_match(&self.icon_ext_regex, icon) {
                    add_info(out, Level::Warning, pkg, "invalid-menu-icon-type", &[icon]);
                }
                if icon.starts_with('/') && needs == "x11" {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "hardcoded-path-in-menu-icon",
                        &[icon],
                    );
                } else {
                    for (_, path, typ) in &self.icon_paths {
                        if !files.contains(&format!("{path}{icon}").as_str()) {
                            add_info(
                                out,
                                Level::Error,
                                pkg,
                                &format!("{typ}-icon-not-in-package"),
                                &[icon, fname],
                            );
                        }
                    }
                }
            }
            None => match &title {
                Some(t) => add_info(out, Level::Warning, pkg, "no-icon-in-menu", &[t]),
                None => add_info(out, Level::Warning, pkg, "no-icon-in-menu", &[]),
            },
        }

        match xdg_re.captures(line).ok().flatten() {
            Some(caps) => {
                let val = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if val.to_lowercase() != "true" {
                    add_info(out, Level::Error, pkg, "non-xdg-migrated-menu", &[]);
                }
            }
            None => {
                add_info(out, Level::Error, pkg, "non-xdg-migrated-menu", &[]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preprocess_strips_comments() {
        let content = "# comment\n?package(foo): needs=\"x11\"\n";
        let out = MenuCheck::preprocess(content);
        assert!(!out.contains("# comment"));
        assert!(out.contains("?package(foo)"));
    }

    #[test]
    fn preprocess_joins_continuations() {
        let content = "?package(foo): \\\n  needs=\"x11\"\n";
        let out = MenuCheck::preprocess(content);
        assert!(out.contains("?package(foo):   needs=\"x11\""));
    }

    #[test]
    fn menu_file_regex_matches() {
        let re = MenuCheck::menu_file_regex();
        let caps = re.captures("/usr/lib/menu/foo").ok().flatten().unwrap();
        assert_eq!(caps.get(1).map(|m| m.as_str()), Some("foo"));
        assert!(re.captures("/usr/lib/menu/a/b").ok().flatten().is_none());
    }

    #[test]
    fn uncased_first_character_is_not_a_capitalization_finding() {
        // These all have a first character with no case, so the reference is
        // quiet; only a genuinely lowercase first letter is a finding.
        for t in ["3D Tool", "_internal", "9lives", "¿Qué", "Ünicode"] {
            assert!(title_is_capitalized(t), "{t} should not be a finding");
        }
        assert!(!title_is_capitalized("lowercase title"));
        assert!(!title_is_capitalized("also lowercase"));
    }
}

#[cfg(test)]
mod menu_icon_xdg_tests {
    use super::*;
    use crate::color::Color;

    /// Config with the menu lists populated so a well-formed entry is quiet.
    fn menu_test_config() -> Config {
        let table: toml::Table =
            toml::from_str("ValidMenuSections = [\"Apps\"]\nExtraMenuNeeds = [\"x11\"]\n")
                .expect("parse test config");
        let mut config = Config {
            configuration: table,
            ..Default::default()
        };
        config.finalize().unwrap();
        config
    }

    fn menu_test_pkg() -> Pkg {
        let mut pkg = Pkg::open(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm"),
            &std::env::temp_dir(),
            true,
        )
        .expect("open fixture pkg");
        pkg.name = "menu-test".to_string();
        pkg.arch = "noarch".to_string();
        pkg
    }

    /// Drive the `icon=`/`xdg=` emission path for one menu entry line and
    /// return the rendered findings in emission order.
    fn menu_line_findings(icon: &str, xdg: &str) -> Vec<(String, String)> {
        let config = menu_test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = MenuCheck::new(&config);
        let pkg = menu_test_pkg();
        let line = format!(
            "?package(menu-test): needs=\"x11\" section=\"Apps\" command=/usr/bin/menu-test \
             title=\"Menu Test\" longtitle=\"Menu Test Long\" icon={icon} xdg={xdg}"
        );
        check.check_menu_line(
            &pkg,
            &mut out,
            "menu-test",
            &line,
            &["/usr/bin/menu-test"],
            &[],
        );
        out.results().to_vec()
    }

    fn rendered(name: &str, level: &str, detail: &str) -> (String, String) {
        let line = if detail.is_empty() {
            format!("menu-test.noarch: {level}: {name}")
        } else {
            format!("menu-test.noarch: {level}: {name} {detail}")
        };
        (name.to_string(), line)
    }

    /// #62 claimed the port's `icon_re`/`xdg_re` required a trailing `"`
    /// the reference regexes lack. They don't: the `"` before the raw
    /// string's closing `"#` is the terminator, not part of the pattern, so
    /// the port already matches the reference byte-for-byte
    /// (`icon="?([^" ]+)` / `xdg="?([^" ]+)`). This pins that unquoted
    /// values parse instead of falling through to the spurious
    /// `no-icon-in-menu` (Warning) / `non-xdg-migrated-menu` (Error).
    #[test]
    fn unquoted_icon_and_xdg_are_quiet() {
        let findings = menu_line_findings("foo.png", "true");
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    /// An unquoted icon still goes through icon validation: a bad extension
    /// fires `invalid-menu-icon-type`, not the spurious `no-icon-in-menu`.
    #[test]
    fn unquoted_icon_with_bad_extension_is_validated() {
        let findings = menu_line_findings("foo.xpm", "true");
        assert_eq!(
            findings,
            [rendered("invalid-menu-icon-type", "W", "foo.xpm")]
        );
    }

    /// An unquoted non-true xdg value still fires `non-xdg-migrated-menu`.
    #[test]
    fn unquoted_xdg_false_still_fires() {
        let findings = menu_line_findings("foo.png", "false");
        assert_eq!(findings, [rendered("non-xdg-migrated-menu", "E", "")]);
    }

    /// Quoted values always matched; pin that they keep behaving the same.
    #[test]
    fn quoted_icon_and_xdg_behave_as_before() {
        let findings = menu_line_findings("\"foo.png\"", "\"true\"");
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
        let findings = menu_line_findings("\"foo.xpm\"", "\"true\"");
        assert_eq!(
            findings,
            [rendered("invalid-menu-icon-type", "W", "foo.xpm")]
        );
        let findings = menu_line_findings("\"foo.png\"", "\"false\"");
        assert_eq!(findings, [rendered("non-xdg-migrated-menu", "E", "")]);
    }
}
