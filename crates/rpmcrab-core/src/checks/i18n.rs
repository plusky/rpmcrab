//! `I18NCheck` — locale directory, man page locale and `%lang` checks.
//!
//! Covers the reference's `add_info` call sites in
//! `rpmlint/checks/I18NCheck.py`, except its trailing-language
//! `no-dependency-on` site, which the port does not emit. The
//! `incorrect-i18n-tag-*` and `incorrect-locale-*` finding names are
//! dynamic (suffixed with the corrected code), the rest are static:
//! `incorrect-locale-subdir`, `invalid-lc-messages-dir`,
//! `invalid-locale-man-dir`, `file-not-in-%lang`, `subfile-not-in-%lang`.

use fancy_regex::Regex;
use librpm::Tag;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use std::sync::OnceLock;

#[path = "i18n_codes.rs"]
mod codes;

/// Incorrect locale code => correct code (`INCORRECT_LOCALES`).
const INCORRECT_LOCALES: &[(&str, &str)] = &[
    ("in", "id"),
    ("in_ID", "id_ID"),
    ("iw", "he"),
    ("iw_IL", "he_IL"),
    ("gr", "el"),
    ("gr_GR", "el_GR"),
    ("cz", "cs"),
    ("cz_CZ", "cs_CZ"),
    // 'lug' is valid, but we standardize on 2 letter codes
    ("lug", "lg"),
    ("en_UK", "en_GB"),
];

/// `EXCEPTION_DIRS`: locale subdirs that are never flagged.
const EXCEPTION_DIRS: &[&str] = &[
    "C",
    "POSIX",
    "CP1251",
    "CP1255",
    "CP1256",
    "ISO-8859-1",
    "ISO-8859-2",
    "ISO-8859-3",
    "ISO-8859-4",
    "ISO-8859-5",
    "ISO-8859-6",
    "ISO-8859-7",
    "ISO-8859-8",
    "ISO-8859-9",
    "ISO-8859-9E",
    "ISO-8859-10",
    "ISO-8859-13",
    "ISO-8859-14",
    "ISO-8859-15",
    "KOI8-R",
    "KOI8-U",
    "UTF-8",
    "default",
];

static LOCALE_REGEX: OnceLock<Regex> = OnceLock::new();
fn locale_regex() -> &'static Regex {
    LOCALE_REGEX.get_or_init(|| Regex::new(r"^(/usr/share/locale/([^/]+))/").expect("static regex"))
}

static CORRECT_SUBDIR_REGEX: OnceLock<Regex> = OnceLock::new();
fn correct_subdir_regex() -> &'static Regex {
    CORRECT_SUBDIR_REGEX.get_or_init(|| {
        Regex::new(r"^(([a-z][a-z]([a-z])?(_[A-Z][A-Z])?)([.@].*$)?)$").expect("static regex")
    })
}

static LC_MESSAGES_REGEX: OnceLock<Regex> = OnceLock::new();
fn lc_messages_regex() -> &'static Regex {
    LC_MESSAGES_REGEX.get_or_init(|| {
        Regex::new(r"/usr/share/locale/([^/]+)/LC_MESSAGES/.*(mo|po)$").expect("static regex")
    })
}

static MAN_REGEX: OnceLock<Regex> = OnceLock::new();
fn man_regex() -> &'static Regex {
    MAN_REGEX.get_or_init(|| {
        Regex::new(r"/usr(?:/share)?/man/([^/]+)/man[0-9n][^/]*/[^/]+$").expect("static regex")
    })
}

fn is_language(code: &str) -> bool {
    codes::LANGUAGES.binary_search(&code).is_ok()
}

fn is_country(code: &str) -> bool {
    codes::COUNTRIES.binary_search(&code).is_ok()
}

/// `is_valid_lang` from the reference: a bare code, or `lang_COUNTRY` with
/// both halves known. Any `@modifier`/`.charset` suffix is stripped first.
fn is_valid_lang(lang: &str) -> bool {
    let base = lang.split(['@', '.']).next().unwrap_or("");
    if is_language(base) {
        return true;
    }
    let Some(ix) = base.find('_') else {
        return false;
    };
    is_country(&base[ix + 1..]) && is_language(&base[..ix])
}

fn incorrect_locale(code: &str) -> Option<&str> {
    INCORRECT_LOCALES
        .iter()
        .find(|(bad, _)| *bad == code)
        .map(|(_, good)| *good)
}

/// Capture group `group` of the first match. A regex engine failure is logged
/// at debug level and reported as no match, mirroring `checks::is_match`.
fn capture<'t>(re: &Regex, text: &'t str, group: usize) -> Option<&'t str> {
    match re.captures(text) {
        Ok(Some(caps)) => caps.get(group).map(|m| m.as_str()),
        Ok(None) => None,
        Err(e) => {
            log::debug!("regex engine error: {e}");
            None
        }
    }
}

/// What the LC_MESSAGES/man probe found for one file.
struct LocaleProbe<'a> {
    /// Error finding for a locale dir the ISO data does not know.
    invalid: Option<&'static str>,
    /// The locale subdir when the file counts as locale data for `%lang`.
    subdir: Option<&'a str>,
}

/// The `lc_messages_regex`/`man_regex` half of the file loop, verbatim: an
/// LC_MESSAGES match always counts for `%lang`; a man match only does when
/// its locale is invalid (a valid one is fine and stays quiet).
fn probe_locale_file<'a>(lc_re: &Regex, man_re: &Regex, file: &'a str) -> LocaleProbe<'a> {
    if let Some(dir) = capture(lc_re, file, 1) {
        return LocaleProbe {
            invalid: (!is_valid_lang(dir)).then_some("invalid-lc-messages-dir"),
            subdir: Some(dir),
        };
    }
    if let Some(dir) = capture(man_re, file, 1) {
        return if is_valid_lang(dir) {
            LocaleProbe {
                invalid: None,
                subdir: None,
            }
        } else {
            LocaleProbe {
                invalid: Some("invalid-locale-man-dir"),
                subdir: Some(dir),
            }
        };
    }
    LocaleProbe {
        invalid: None,
        subdir: None,
    }
}

pub struct I18NCheck;

impl I18NCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// `--explain` descriptions for the dynamic `incorrect-i18n-tag-*` and
    /// `incorrect-locale-*` findings, one per corrected code in
    /// `INCORRECT_LOCALES`. The reference ships no descriptions for these;
    /// the port describes them so `--explain` never prints "Unknown message".
    pub fn register_error_details(out: &mut Filter) {
        for (_, correct) in INCORRECT_LOCALES {
            out.set_error_detail(
                &format!("incorrect-i18n-tag-{correct}"),
                format!(
                    "The i18n tag uses the incorrect locale code. Replace it with `{correct}`."
                ),
            );
            out.set_error_detail(
                &format!("incorrect-locale-{correct}"),
                format!(
                    "The file is installed under a directory with the incorrect locale code. Rename it to use `{correct}`."
                ),
            );
        }
    }

    /// Pure core over mockable inputs: `(path, lang)` files and header
    /// i18n tags. Returns
    /// `(level, finding, details)` in emission order.
    fn collect(files: &[(&str, &str)], i18n_tags: &[&str]) -> Vec<(Level, String, Vec<String>)> {
        let locale_re = locale_regex();
        let subdir_re = correct_subdir_regex();
        let lc_re = lc_messages_regex();
        let man_re = man_regex();

        let mut out = Vec::new();

        for tag in i18n_tags {
            if let Some(correct) = incorrect_locale(tag) {
                out.push((
                    Level::Error,
                    format!("incorrect-i18n-tag-{correct}"),
                    vec![(*tag).to_string()],
                ));
            }
        }

        let mut ordered: Vec<(&str, &str)> = files.to_vec();
        ordered.sort_by(|a, b| a.0.cmp(b.0));

        // Webapps keep locale files outside %lang dirs; detected via an
        // apache configuration file, as in the reference.
        let webapp = ordered
            .iter()
            .any(|(f, _)| f.starts_with("/etc/apache2/") || f.starts_with("/etc/httpd/conf.d/"));

        // Each locale subdir is checked only once.
        let mut seen_locales: Vec<&str> = Vec::new();
        for (file, lang) in &ordered {
            if let Some(locale) = capture(locale_re, file, 2)
                && !seen_locales.contains(&locale)
            {
                seen_locales.push(locale);
                match capture(subdir_re, locale, 2) {
                    None if !EXCEPTION_DIRS.contains(&locale) => out.push((
                        Level::Error,
                        "incorrect-locale-subdir".to_string(),
                        vec![(*file).to_string()],
                    )),
                    Some(lang_part) => {
                        if let Some(correct) = incorrect_locale(lang_part) {
                            out.push((
                                Level::Error,
                                format!("incorrect-locale-{correct}"),
                                vec![(*file).to_string()],
                            ));
                        }
                    }
                    _ => {}
                }
            }

            let probe = probe_locale_file(lc_re, man_re, file);
            if let Some(finding) = probe.invalid {
                out.push((Level::Error, finding.to_string(), vec![(*file).to_string()]));
            }
            // The `.mo` trigger covers only the standard locale tree,
            // `/usr/share/locale`: the tree the LC_MESSAGES probe is
            // anchored in and the only one `%find_lang` handles.
            // Applications shipping `.mo` files in private trees
            // (LibreOffice, Python site-packages, ...) load them
            // themselves, and `%lang` marks there would let
            // install-time language filtering strip product data
            // (#480). The probe trigger is already tree-anchored.
            if ((file.ends_with(".mo") && file.starts_with("/usr/share/locale/"))
                || probe.subdir.is_some())
                && lang.is_empty()
                && !webapp
            {
                out.push((
                    Level::Warning,
                    "file-not-in-%lang".to_string(),
                    vec![(*file).to_string()],
                ));
            }
        }

        // A file under a %lang-tagged dir entry without the tag itself.
        // `main_dir` holds the previous *file* path, so this only fires when
        // a dir entry carrying %lang precedes files below it, as in the
        // reference (`is_prefix(main_dir + '/', f)`).
        let mut main_dir = "";
        let mut main_lang = "";
        for (file, lang) in &ordered {
            if !main_lang.is_empty() && lang.is_empty() && file.starts_with(&format!("{main_dir}/"))
            {
                out.push((
                    Level::Error,
                    "subfile-not-in-%lang".to_string(),
                    vec![(*file).to_string()],
                ));
            }
            if main_lang != *lang {
                main_dir = file;
                main_lang = lang;
            }
        }

        out
    }
}

impl Check for I18NCheck {
    fn name(&self) -> &'static str {
        "I18NCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        Self::register_error_details(out);
        let i18n_tags = pkg.tag_str_array(Tag::HEADERI18NTABLE);
        let files: Vec<(&str, &str)> = pkg
            .files
            .iter()
            .map(|f| (f.name.as_str(), f.lang.as_str()))
            .collect();
        let tag_refs: Vec<&str> = i18n_tags.iter().map(String::as_str).collect();
        for (level, check, details) in Self::collect(&files, &tag_refs) {
            let detail_refs: Vec<&str> = details.iter().map(String::as_str).collect();
            add_info(out, level, pkg, &check, &detail_refs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;
    use crate::pkg::pkgfile::PkgFile;

    fn names(findings: &[(Level, String, Vec<String>)]) -> Vec<&str> {
        findings.iter().map(|(_, n, _)| n.as_str()).collect()
    }

    #[test]
    fn malformed_locale_subdir_is_reported_once() {
        let findings = I18NCheck::collect(
            &[
                ("/usr/share/locale/xx-yy/LC_MESSAGES/a.mo", ""),
                ("/usr/share/locale/xx-yy/LC_MESSAGES/b.mo", ""),
            ],
            &[],
        );
        let subdir: Vec<_> = findings
            .iter()
            .filter(|(_, n, _)| n == "incorrect-locale-subdir")
            .collect();
        assert_eq!(subdir.len(), 1, "{findings:?}");
        assert_eq!(
            subdir[0].2,
            vec!["/usr/share/locale/xx-yy/LC_MESSAGES/a.mo"]
        );
    }

    #[test]
    fn sane_locale_subdir_is_quiet() {
        let findings = I18NCheck::collect(&[("/usr/share/locale/de/LC_MESSAGES/a.mo", "de")], &[]);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn exception_dirs_are_quiet() {
        for dir in ["C", "POSIX", "UTF-8", "ISO-8859-15"] {
            let path = format!("/usr/share/locale/{dir}");
            let findings = I18NCheck::collect(&[(path.as_str(), "")], &[]);
            assert!(findings.is_empty(), "{dir}: {findings:?}");
        }
    }

    #[test]
    fn incorrect_locale_code_is_remapped() {
        let findings = I18NCheck::collect(&[("/usr/share/locale/in/LC_MESSAGES/a.mo", "in")], &[]);
        // "in" is syntactically fine, so no incorrect-locale-subdir; the
        // mapping fires, and since "in" is not a real ISO code the semantic
        // check fires too. The %lang tag keeps the warning away.
        assert_eq!(
            names(&findings),
            vec!["incorrect-locale-id", "invalid-lc-messages-dir"],
            "{findings:?}"
        );
        assert_eq!(findings[0].2, vec!["/usr/share/locale/in/LC_MESSAGES/a.mo"]);
    }

    #[test]
    fn incorrect_i18n_header_tag_is_remapped() {
        let findings = I18NCheck::collect(&[], &["iw_IL", "de"]);
        assert_eq!(names(&findings), vec!["incorrect-i18n-tag-he_IL"]);
        assert_eq!(findings[0].2, vec!["iw_IL"]);
    }

    #[test]
    fn unknown_lc_messages_dir_is_invalid() {
        let findings = I18NCheck::collect(&[("/usr/share/locale/xx/LC_MESSAGES/a.mo", "")], &[]);
        // "xx" is syntactically a valid subdir, so only the semantic checks fire.
        assert_eq!(
            names(&findings),
            vec!["invalid-lc-messages-dir", "file-not-in-%lang"],
            "{findings:?}"
        );
    }

    #[test]
    fn unknown_man_dir_is_invalid() {
        let findings = I18NCheck::collect(&[("/usr/share/man/xx/man1/foo.1", "")], &[]);
        assert_eq!(
            names(&findings),
            vec!["invalid-locale-man-dir", "file-not-in-%lang"],
            "{findings:?}"
        );
    }

    #[test]
    fn known_man_dir_is_quiet() {
        let findings = I18NCheck::collect(&[("/usr/share/man/de/man1/foo.1", "")], &[]);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn mo_file_without_lang_warns() {
        let findings = I18NCheck::collect(&[("/usr/share/locale/de/LC_MESSAGES/a.mo", "")], &[]);
        assert_eq!(names(&findings), vec!["file-not-in-%lang"]);
    }

    #[test]
    fn mo_file_with_lang_is_quiet() {
        let findings = I18NCheck::collect(&[("/usr/share/locale/de/LC_MESSAGES/a.mo", "de")], &[]);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn mo_file_in_private_tree_is_quiet() {
        // Applications ship `.mo` files in private trees and load them
        // themselves; only the standard locale tree is `%find_lang`
        // territory, so untagged files there stay quiet (#480).
        for path in [
            "/usr/lib/python3.13/site-packages/foo/locale/de/LC_MESSAGES/foo.mo",
            "/usr/share/libreoffice/share/locale/de/LC_MESSAGES/foo.mo",
            "/usr/share/kvirc/5.2/locale/about_de.mo",
        ] {
            let findings = I18NCheck::collect(&[(path, "")], &[]);
            assert!(findings.is_empty(), "{path}: {findings:?}");
        }
    }

    #[test]
    fn mo_file_in_locale_tree_outside_lc_messages_still_warns() {
        // The restriction is tree-level, not LC_MESSAGES-only: an
        // untagged `.mo` anywhere under /usr/share/locale warns.
        let findings = I18NCheck::collect(&[("/usr/share/locale/de/foo.mo", "")], &[]);
        assert_eq!(names(&findings), vec!["file-not-in-%lang"]);
    }

    #[test]
    fn mo_file_in_private_tree_with_lang_is_quiet() {
        let findings = I18NCheck::collect(
            &[(
                "/usr/lib/python3.13/site-packages/foo/locale/de/LC_MESSAGES/foo.mo",
                "de",
            )],
            &[],
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn webapp_locale_files_are_quiet() {
        let findings = I18NCheck::collect(
            &[
                ("/etc/apache2/foo.conf", ""),
                ("/usr/share/locale/de/LC_MESSAGES/a.mo", ""),
            ],
            &[],
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn untagged_file_below_lang_dir_errors() {
        let findings = I18NCheck::collect(
            &[
                ("/usr/share/locale/de", "de"),
                ("/usr/share/locale/de/LC_MESSAGES/a.mo", ""),
            ],
            &[],
        );
        assert!(
            names(&findings).contains(&"subfile-not-in-%lang"),
            "{findings:?}"
        );
    }

    #[test]
    fn killed_locales_dependency_finding_stays_absent() {
        // The trailing-language `no-dependency-on` emission is removed
        // (#534): the `locales-<lang>` packages it demanded are Mandriva's
        // locale model and no package named `locales-<lang>` exists. These
        // are the package-name shapes that used to fire.
        for name in ["foo-de", "foo-cs", "foo-doc", "foo-qaa-qtz"] {
            let mut pkg = Pkg::open_no_extract(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm")
                    .as_path(),
            )
            .expect("open fixture shell");
            pkg.name = name.to_string();
            pkg.files = vec![];
            let config = Config::default();
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            let mut check = I18NCheck::new(&config);
            check.check_binary(&pkg, &config, &mut out);
            assert!(
                !out.results().iter().any(|(n, _)| n == "no-dependency-on"),
                "{name}: {:?}",
                out.results()
            );
        }
    }

    #[test]
    fn plain_package_name_is_quiet() {
        let findings = I18NCheck::collect(&[], &[]);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn valid_languages() {
        for lang in [
            "de",
            "de_DE",
            "de_DE.UTF-8",
            "pt_BR",
            "sr@latin",
            "zh_CN",
            "en",
        ] {
            assert!(is_valid_lang(lang), "{lang}");
        }
    }

    #[test]
    fn invalid_languages() {
        for lang in ["xx", "de_XX", "xx_DE", "", "de-DE"] {
            assert!(!is_valid_lang(lang), "{lang}");
        }
    }

    #[test]
    fn check_binary_emits_mo_without_lang() {
        // Entry glue: `check_binary()` maps `pkg.files` into `collect()`.
        // A valid-locale `.mo` file with no `%lang` tag warns, so neutering
        // the body to `()` must fail this test.
        let mut pkg = Pkg::open_no_extract(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm")
                .as_path(),
        )
        .expect("open fixture shell");
        pkg.name = "foo".to_string();
        let path = "/usr/share/locale/de/LC_MESSAGES/a.mo";
        pkg.files = vec![PkgFile {
            name: path.to_string(),
            path: path.to_string(),
            mode: 0o100644,
            ..Default::default()
        }];
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = I18NCheck::new(&config);
        check.check_binary(&pkg, &config, &mut out);
        assert!(
            out.results().iter().any(|(n, _)| n == "file-not-in-%lang"),
            "results: {:?}",
            out.results()
        );
    }
}
