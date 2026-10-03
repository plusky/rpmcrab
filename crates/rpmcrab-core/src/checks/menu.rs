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

    fn menu_file_regex() -> Regex {
        Regex::new(r"^/usr/lib/menu/([^/]+)$").expect("static regex")
    }
    fn old_menu_file_regex() -> Regex {
        Regex::new(r"^/usr/share/(gnome/apps|applnk)/([^/]+)$").expect("static regex")
    }
    fn xpm_ext_regex() -> Regex {
        Regex::new(r"/usr/share/icons/(mini/|large/).*\.xpm$").expect("static regex")
    }
    fn update_menus_regex() -> Regex {
        Regex::new(r"(?m)^[^#]*update-menus").expect("static regex")
    }
}

impl Check for MenuCheck {
    fn name(&self) -> &'static str {
        "MenuCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let mut menus: Vec<String> = Vec::new();
        let none_regex = Regex::new("None\",").expect("static regex");

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
                if is_match(&Self::xpm_ext_regex(), fname)
                    && is_reg(mode)
                    && pkg.grep(&none_regex, fname).is_none()
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
        } else if !is_match(&Self::update_menus_regex(), &postin) {
            add_info(out, Level::Error, pkg, "postin-without-update-menus", &[]);
        }
        let postun = script_body_or_prog(pkg, Tag::POSTUN, Tag::POSTUNPROG);
        if postun.is_empty() {
            add_info(out, Level::Error, pkg, "menu-without-postun", &[]);
        } else if !is_match(&Self::update_menus_regex(), &postun) {
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
        let package_re = Regex::new(r"\?package\((.*)\):").expect("static regex");
        let command_re = Regex::new(r#"command=(?:"([^"]+)"|([^ \t"]+))"#).expect("static regex");
        let longtitle_re =
            Regex::new(r#"longtitle=(?:"([^"]+)"|([^ \t"]+))"#).expect("static regex");
        let title_re = Regex::new(r#"["\s]title=(?:"([^"]+)"|([^ \t"]+))"#).expect("static regex");
        let needs_re = Regex::new(r#"needs=("[^"]+"|([^ \t"]+))"#).expect("static regex");
        let section_re = Regex::new(r#"section=("[^"]+"|([^ \t"]+))"#).expect("static regex");
        let icon_re = Regex::new(r#"icon="?([^" ]+)"#).expect("static regex");
        let version_re = Regex::new(r"([0-9.][0-9.]+)($|\s)").expect("static regex");
        let xdg_re = Regex::new(r#"xdg="?([^" ]+)"#).expect("static regex");

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
                // Deliberate divergence (ledgered in tests/parity/divergences.toml):
                // the reference raises IndexError here -- a whitespace-only quoted
                // command, or a single-token command matching a launcher regexp,
                // aborts the whole run with exit 3. The port reports
                // `menu-command-not-in-package` with an empty detail instead, so
                // one malformed entry does not forfeit the rest of the package.
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
                    // Same divergence as above: a launcher-only single token
                    // becomes the empty command rather than an IndexError.
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
                self.check_title(pkg, out, &version_re, title, true);
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
                self.check_title(pkg, out, &version_re, title, false);
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

    /// Drive one menu entry line through `check_menu_line` with the bundled
    /// config, returning the `(finding, rendered line)` pairs in emission order.
    fn menu_line_results(line: &str) -> Vec<(String, String)> {
        let rpm = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/w6-menulegacy-1.0-1.noarch.rpm");
        let scratch = tempfile::tempdir().unwrap();
        let pkg = Pkg::open(&rpm, scratch.path(), true).unwrap();
        let config = crate::config::load_bundled();
        let check = MenuCheck::new(&config);
        let mut out = Filter::new(&config, crate::color::Color::for_tty(false)).unwrap();
        let files: Vec<&str> = pkg.files.iter().map(|f| f.name.as_str()).collect();
        let req_names: Vec<&str> = pkg.req_names.iter().map(String::as_str).collect();
        check.check_menu_line(
            &pkg,
            &mut out,
            "/usr/lib/menu/w6-menulegacy",
            line,
            &files,
            &req_names,
        );
        out.results().to_vec()
    }

    /// MenuCheck.py:137 does `command = command_line[1]` once a launcher regexp
    /// matches, so a single-token command that is itself a launcher raises
    /// IndexError; MenuCheck.py:118 raises the same way on a whitespace-only
    /// quoted command. Both abort the whole reference run with exit 3. The port
    /// deliberately reports `menu-command-not-in-package` with an empty detail
    /// instead (see the divergence ledger). Pin the full emission path: no
    /// panic, the finding name and level, the empty detail, and everything
    /// else `check_menu_line` emits after `command = Some(cmd)`.
    #[test]
    fn degenerate_launcher_command_reports_instead_of_crashing() {
        // `soundwrapper` is a bundled MenuLaunchers entry with no binaries, so
        // the launcher arm is exercised without a companion
        // `use-of-launcher-in-menu-but-no-requires-on` finding.
        for line in [
            r#"?package(w6-menulegacy): command="soundwrapper""#,
            r#"?package(w6-menulegacy): command=" ""#,
        ] {
            let results = menu_line_results(line);
            let finding = results
                .iter()
                .find(|(check, _)| check == "menu-command-not-in-package")
                .unwrap_or_else(|| panic!("{line}: no menu-command-not-in-package in {results:?}"));
            // An empty detail contributes nothing to the rendered line.
            assert_eq!(
                finding.1, "w6-menulegacy.noarch: W: menu-command-not-in-package",
                "{line}"
            );
            let names: Vec<&str> = results.iter().map(|(check, _)| check.as_str()).collect();
            assert_eq!(
                names,
                [
                    "menu-command-not-in-package",
                    "no-longtitle-in-menu",
                    "no-title-in-menu",
                    "unable-to-parse-menu-needs",
                    "no-icon-in-menu",
                    "non-xdg-migrated-menu",
                ],
                "{line}: full emission after `command = Some(cmd)`: {results:?}"
            );
        }
    }

    /// The reference's bare alternative excludes `"` (`[^ \t"]+`), so
    /// `command=foo"bar` parses the command as `foo`. Without the fix the
    /// port captured `foo"bar`.
    #[test]
    fn bare_command_stops_at_embedded_quote() {
        let results = menu_line_results(r#"?package(w6-menulegacy): command=foo"bar"#);
        let finding = results
            .iter()
            .find(|(check, _)| check == "menu-command-not-in-package")
            .unwrap_or_else(|| panic!("no menu-command-not-in-package in {results:?}"));
        assert_eq!(
            finding.1,
            "w6-menulegacy.noarch: W: menu-command-not-in-package foo"
        );
    }

    /// Same class divergence on `longtitle=` and `title=`: the bare alternative
    /// must stop at an embedded quote, matching the reference.
    #[test]
    fn bare_longtitle_and_title_stop_at_embedded_quote() {
        let results = menu_line_results(r#"?package(w6-menulegacy): longtitle=foo"bar"#);
        let finding = results
            .iter()
            .find(|(check, _)| check == "menu-longtitle-not-capitalized")
            .unwrap_or_else(|| panic!("no menu-longtitle-not-capitalized in {results:?}"));
        assert_eq!(
            finding.1,
            "w6-menulegacy.noarch: W: menu-longtitle-not-capitalized foo"
        );

        let results = menu_line_results(r#"?package(w6-menulegacy): title=foo"bar"#);
        let finding = results
            .iter()
            .find(|(check, _)| check == "menu-title-not-capitalized")
            .unwrap_or_else(|| panic!("no menu-title-not-capitalized in {results:?}"));
        assert_eq!(
            finding.1,
            "w6-menulegacy.noarch: W: menu-title-not-capitalized foo"
        );
    }
}
