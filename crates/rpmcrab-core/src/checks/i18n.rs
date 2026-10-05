//! `I18NCheck` — locale directory, man page locale and language-pack checks.
//!
//! Ported from `rpmlint/checks/I18NCheck.py`. Eight `add_info` sites; the
//! `incorrect-i18n-tag-*` and `incorrect-locale-*` finding names are dynamic
//! (suffixed with the corrected code), the rest are static:
//! `incorrect-locale-subdir`, `invalid-lc-messages-dir`,
//! `invalid-locale-man-dir`, `file-not-in-%lang`, `subfile-not-in-%lang`,
//! `no-dependency-on`.

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

/// The language suffix of a `-lang` package name, mirroring the reference's
/// `-('aa'|…|'qaa-qtz')$` alternation over all of `LANGUAGES`.
///
/// Every code but one contains no `-`, so the alternation matches exactly
/// when the text after the final `-` is a code. The single exception is
/// `qaa-qtz` — a private-use *range* entry, not a real code — matched
/// literally here.
fn trailing_language(name: &str) -> Option<&str> {
    if let Some(prefix) = name.strip_suffix("qaa-qtz")
        && prefix.ends_with('-')
    {
        return Some("qaa-qtz");
    }
    let (_, suffix) = name.rsplit_once('-')?;
    is_language(suffix).then_some(suffix)
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

    /// Pure core over mockable inputs: `(path, lang)` files, header i18n
    /// tags, require names and the package name. Returns
    /// `(level, finding, details)` in emission order.
    fn collect(
        files: &[(&str, &str)],
        i18n_tags: &[&str],
        requires: &[&str],
        name: &str,
    ) -> Vec<(Level, String, Vec<String>)> {
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
            if (file.ends_with(".mo") || probe.subdir.is_some()) && lang.is_empty() && !webapp {
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

        if let Some(lang) = trailing_language(name) {
            let locales = format!("locales-{lang}");
            if locales != name && !requires.contains(&locales.as_str()) {
                out.push((Level::Error, "no-dependency-on".to_string(), vec![locales]));
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
        let i18n_tags = pkg.tag_str_array(Tag::HEADERI18NTABLE);
        let files: Vec<(&str, &str)> = pkg
            .files
            .iter()
            .map(|f| (f.name.as_str(), f.lang.as_str()))
            .collect();
        let requires: Vec<&str> = pkg.requires.iter().map(|d| d.name.as_str()).collect();
        let tag_refs: Vec<&str> = i18n_tags.iter().map(String::as_str).collect();
        for (level, check, details) in Self::collect(&files, &tag_refs, &requires, &pkg.name) {
            let detail_refs: Vec<&str> = details.iter().map(String::as_str).collect();
            add_info(out, level, pkg, &check, &detail_refs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            &[],
            "foo",
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
        let findings = I18NCheck::collect(
            &[("/usr/share/locale/de/LC_MESSAGES/a.mo", "de")],
            &[],
            &[],
            "foo",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn exception_dirs_are_quiet() {
        for dir in ["C", "POSIX", "UTF-8", "ISO-8859-15"] {
            let path = format!("/usr/share/locale/{dir}");
            let findings = I18NCheck::collect(&[(path.as_str(), "")], &[], &[], "foo");
            assert!(findings.is_empty(), "{dir}: {findings:?}");
        }
    }

    #[test]
    fn incorrect_locale_code_is_remapped() {
        let findings = I18NCheck::collect(
            &[("/usr/share/locale/in/LC_MESSAGES/a.mo", "in")],
            &[],
            &[],
            "foo",
        );
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
        let findings = I18NCheck::collect(&[], &["iw_IL", "de"], &[], "foo");
        assert_eq!(names(&findings), vec!["incorrect-i18n-tag-he_IL"]);
        assert_eq!(findings[0].2, vec!["iw_IL"]);
    }

    #[test]
    fn unknown_lc_messages_dir_is_invalid() {
        let findings = I18NCheck::collect(
            &[("/usr/share/locale/xx/LC_MESSAGES/a.mo", "")],
            &[],
            &[],
            "foo",
        );
        // "xx" is syntactically a valid subdir, so only the semantic checks fire.
        assert_eq!(
            names(&findings),
            vec!["invalid-lc-messages-dir", "file-not-in-%lang"],
            "{findings:?}"
        );
    }

    #[test]
    fn unknown_man_dir_is_invalid() {
        let findings = I18NCheck::collect(&[("/usr/share/man/xx/man1/foo.1", "")], &[], &[], "foo");
        assert_eq!(
            names(&findings),
            vec!["invalid-locale-man-dir", "file-not-in-%lang"],
            "{findings:?}"
        );
    }

    #[test]
    fn known_man_dir_is_quiet() {
        let findings = I18NCheck::collect(&[("/usr/share/man/de/man1/foo.1", "")], &[], &[], "foo");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn mo_file_without_lang_warns() {
        let findings = I18NCheck::collect(
            &[("/usr/share/locale/de/LC_MESSAGES/a.mo", "")],
            &[],
            &[],
            "foo",
        );
        assert_eq!(names(&findings), vec!["file-not-in-%lang"]);
    }

    #[test]
    fn mo_file_with_lang_is_quiet() {
        let findings = I18NCheck::collect(
            &[("/usr/share/locale/de/LC_MESSAGES/a.mo", "de")],
            &[],
            &[],
            "foo",
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
            &[],
            "foo",
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
            &[],
            "foo",
        );
        assert!(
            names(&findings).contains(&"subfile-not-in-%lang"),
            "{findings:?}"
        );
    }

    #[test]
    fn lang_package_without_locales_dependency_errors() {
        let findings = I18NCheck::collect(&[], &[], &[], "foo-de");
        assert_eq!(names(&findings), vec!["no-dependency-on"]);
        assert_eq!(findings[0].2, vec!["locales-de"]);
    }

    #[test]
    fn lang_package_with_locales_dependency_is_quiet() {
        let findings = I18NCheck::collect(&[], &[], &["locales-de"], "foo-de");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn locales_package_itself_is_quiet() {
        let findings = I18NCheck::collect(&[], &[], &[], "locales-de");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn plain_package_name_is_quiet() {
        let findings = I18NCheck::collect(&[], &[], &[], "foo");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn hyphenated_range_code_matches_literally() {
        // `qaa-qtz` is the only LANGUAGES entry containing '-'; the
        // reference alternation matches it verbatim at the end of the name.
        let findings = I18NCheck::collect(&[], &[], &[], "foo-qaa-qtz");
        assert_eq!(names(&findings), vec!["no-dependency-on"]);
        assert_eq!(findings[0].2, vec!["locales-qaa-qtz"]);
    }

    #[test]
    fn trailing_language_detection() {
        assert_eq!(trailing_language("foo-de"), Some("de"));
        assert_eq!(trailing_language("foo-de_DE"), None);
        assert_eq!(trailing_language("foo"), None);
        assert_eq!(trailing_language("de"), None);
        assert_eq!(trailing_language("foo-"), None);
        assert_eq!(trailing_language("-de"), Some("de"));
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
}
