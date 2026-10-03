//! `TagsCheck`: header tag validation, ported from rpmlint's `TagsCheck.py`.
//!
//! Covers the reference's `add_info` call sites: unexpanded macros,
//! packager/version/release/epoch, dependencies, name, summary, description,
//! group, buildhost, changelog, license, URL, obsoletes/provides, and the
//! filename coherence check.
//!
//! The i18n summary/description loops are fully implemented, including
//! `spelling-error` via the `spellbook` crate (pure Rust, Hunspell-compatible).
//! In mini-mode the spellchecker is disabled, matching the reference.

use std::path::Path;

use fancy_regex::Regex;
use librpm::{OwnedTagData, Tag};

use super::is_match;
use super::shared::{devel_regex, lib_package_regex, macro_regex};
use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::dep::{DepInfo, version_to_string};

/// `invalid_version_regex`: `([0-9](?:rc|alpha|beta|pre).*)`, case-insensitive.
fn invalid_version_regex() -> Regex {
    Regex::new(r"(?i)([0-9](?:rc|alpha|beta|pre).*)").expect("static regex")
}

/// `lib_devel_number_regex`: `^lib(.*?)([0-9.]+)(_[0-9.]+)?-devel`.
fn lib_devel_number_regex() -> Regex {
    Regex::new(r"^lib(.*?)([0-9.]+)(_[0-9.]+)?-devel").expect("static regex")
}

/// Words that may start a summary in lowercase (`CAPITALIZED_IGNORE_LIST`).
const CAPITALIZED_IGNORE_LIST: &[&str] = &["jQuery", "openSUSE", "wxWidgets", "a", "an", "uWSGI"];

/// Sentence-ending punctuation for `name-repeated-in-summary`.
const PUNCT: &str = ".,:;!?";

/// Escape a string for literal use in a regex.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if matches!(
            ch,
            '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// RPM sense flags (`rpmds.h`).
const RPMSENSE_LESS: u32 = 2;
const RPMSENSE_GREATER: u32 = 4;
const RPMSENSE_EQUAL: u32 = 8;

/// 1995-01-01 UTC, the oldest sane changelog timestamp.
const OLDEST_CHANGELOG_TIMESTAMP: i64 = 788_918_400;

/// `TagsCheck`, ported from `rpmlint/checks/TagsCheck.py`.
pub struct TagsCheck {
    valid_groups: Vec<String>,
    valid_licenses: Vec<String>,
    invalid_requires: Vec<Regex>,
    packager_regex: Option<Regex>,
    extension_regex: Option<Regex>,
    use_version_in_changelog: bool,
    invalid_url_regex: Option<Regex>,
    forbidden_words_regex: Option<Regex>,
    valid_buildhost_regex: Option<Regex>,
    use_epoch: bool,
    max_line_len: usize,
    valid_license_exceptions: Vec<String>,
    macro_re: Regex,
    devel_re: Regex,
    lib_devel_number_re: Regex,
    lib_package_re: Regex,
    invalid_version_re: Regex,
    changelog_version_re: Regex,
    changelog_text_version_re: Regex,
    devel_number_re: Regex,
    leading_space_re: Regex,
    license_exception_re: Regex,
    pkg_config_re: Regex,
    tag_re: Regex,
    spellchecker: Option<crate::spellcheck::Spellchecker>,
}

impl TagsCheck {
    pub fn new(config: &Config) -> Self {
        let tbl = &config.configuration;
        let get_str = |k: &str| {
            tbl.get(k)
                .and_then(toml::Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        let get_strings = |k: &str| {
            tbl.get(k)
                .and_then(toml::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        let get_bool = |k: &str| tbl.get(k).and_then(toml::Value::as_bool).unwrap_or(false);

        let packager = get_str("Packager");
        let release_ext = get_str("ReleaseExtension");
        let invalid_url = get_str("InvalidURL");
        let forbidden_words = get_str("ForbiddenWords");
        let valid_buildhost = get_str("ValidBuildHost");

        Self {
            valid_groups: get_strings("ValidGroups"),
            valid_licenses: get_strings("ValidLicenses"),
            invalid_requires: get_strings("InvalidRequires")
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect(),
            packager_regex: (!packager.is_empty())
                .then(|| Regex::new(&packager).ok())
                .flatten(),
            extension_regex: (!release_ext.is_empty())
                .then(|| Regex::new(&release_ext).ok())
                .flatten(),
            use_version_in_changelog: get_bool("UseVersionInChangelog"),
            invalid_url_regex: (!invalid_url.is_empty())
                .then(|| Regex::new(&format!("(?i){invalid_url}")).ok())
                .flatten(),
            forbidden_words_regex: (!forbidden_words.is_empty())
                .then(|| Regex::new(&format!("(?i)({forbidden_words})")).ok())
                .flatten(),
            valid_buildhost_regex: (!valid_buildhost.is_empty())
                .then(|| Regex::new(&valid_buildhost).ok())
                .flatten(),
            use_epoch: get_bool("UseEpoch"),
            max_line_len: tbl
                .get("MaxLineLength")
                .and_then(toml::Value::as_integer)
                .unwrap_or(79) as usize,
            valid_license_exceptions: get_strings("ValidLicenseExceptions"),
            macro_re: macro_regex(),
            devel_re: devel_regex(),
            lib_devel_number_re: lib_devel_number_regex(),
            lib_package_re: lib_package_regex(),
            invalid_version_re: invalid_version_regex(),
            changelog_version_re: Regex::new(r"[^>]([^ >]+)\s*$").expect("static regex"),
            changelog_text_version_re: Regex::new(r"^\s*-\s*((\d+:)?[\w\.]+-[\w\.]+)").expect("static regex"),
            devel_number_re: Regex::new(r"(.*?)([0-9.]+)(_[0-9.]+)?-devel").expect("static regex"),
            leading_space_re: Regex::new(r"^\s+").expect("static regex"),
            license_exception_re: Regex::new(r"([^(\s]+)\s(?:WITH|with)\s([^)\s]+)").expect("static regex"),
            pkg_config_re: Regex::new(r"^/usr/(?:lib\d*|share)/pkgconfig/").expect("static regex"),
            tag_re: Regex::new(r"(?i)^((?:Auto(?:Req|Prov|ReqProv)|Build(?:Arch(?:itectures)?|Root)|(?:Build)?Conflicts|(?:Build)?(?:Pre)?Requires|Copyright|(?:CVS|SVN)Id|Dist(?:ribution|Tag|URL)|DocDir|(?:Build)?Enhances|Epoch|Exclude(?:Arch|OS)|Exclusive(?:Arch|OS)|Group|Icon|License|Name|No(?:Patch|Source)|Obsoletes|Packager|Patch\d*|Prefix(?:es)?|Provides|(?:Build)?Recommends|Release|RHNPlatform|Serial|Source\d*|(?:Build)?Suggests|Summary|(?:Build)?Supplements|(?:Bug)?URL|Vendor|Version)(?:\([^)]+\))?:)\s*\S").expect("static regex"),
            spellchecker: if config.mini_mode {
                None
            } else {
                crate::spellcheck::Spellchecker::new()
            },
        }
    }

    /// `_unexpanded_macros`: warn for each `%macro` in a tag value. Accepts a
    /// list (issue #16); skips `%XX` URL escapes when `is_url`.
    fn unexpanded_macros(
        &self,
        out: &mut Filter,
        pkg: &Pkg,
        tagname: &str,
        values: &[String],
        is_url: bool,
    ) {
        for val in values {
            for m in self
                .macro_re
                .find_iter(val)
                .filter_map(|r| r.ok())
                .map(|m| m.as_str())
            {
                if is_url && is_match(&Regex::new(r"(?i)^%[0-9A-F][0-9A-F]$").expect("static"), m) {
                    continue;
                }
                add_info(out, Level::Warning, pkg, "unexpanded-macro", &[tagname, m]);
            }
        }
    }

    fn unexpanded_macro(&self, out: &mut Filter, pkg: &Pkg, tagname: &str, value: &str) {
        self.unexpanded_macros(out, pkg, tagname, &[value.to_string()], false);
    }
}

impl TagsCheck {
    /// The reference `check()`: runs for binary and source packages alike.
    fn run(&self, pkg: &Pkg, out: &mut Filter) {
        let header = pkg.header();
        let tag_str = |t| crate::pkg::tags::str_tag(header, t).unwrap_or_default();
        let epoch: Option<i64> = match header.get_owned(Tag::EPOCH) {
            Some(OwnedTagData::Int32(v)) => v.into_iter().next().map(|e| e as i64),
            _ => None,
        };
        let group = pkg.tag_str(Tag::GROUP).unwrap_or_default();
        let buildhost = tag_str(Tag::BUILDHOST);
        let langs = crate::pkg::tags::str_array(header, Tag::HEADERI18NTABLE);
        let summary = tag_str(Tag::SUMMARY);
        let description = tag_str(Tag::DESCRIPTION);
        let changelog: Vec<String> = crate::pkg::tags::str_array(header, Tag::CHANGELOGNAME);
        let rpm_license = tag_str(Tag::LICENSE);
        let name = pkg.name.clone();
        let deps: Vec<DepInfo> = pkg.requires.iter().chain(&pkg.prereq).cloned().collect();
        let is_devel = is_match(&self.devel_re, &name);
        let is_source = pkg.is_source;

        // Words ignored by the (unimplemented) spellchecker: file path
        // components plus dependency names.
        let mut ignored_words: Vec<String> = Vec::new();
        for f in &pkg.files {
            ignored_words.extend(f.name.split('/').map(str::to_string));
        }
        for dep in pkg
            .provides
            .iter()
            .chain(&pkg.requires)
            .chain(&pkg.conflicts)
            .chain(&pkg.obsoletes)
        {
            ignored_words.push(dep.name.clone());
        }

        self.check_invalid_packager(pkg, out, &tag_str(Tag::PACKAGER));
        self.check_version(pkg, out, &tag_str(Tag::VERSION));
        self.check_release(pkg, out, &tag_str(Tag::RELEASE));
        self.check_epoch(pkg, out, epoch);
        self.check_no_epoch_in_tags(pkg, out);
        self.check_dependencies(pkg, out, &deps, is_devel, is_source);
        self.unexpanded_macro(out, pkg, "Name", &name);
        self.check_name(pkg, out);
        self.check_summary_tag(pkg, out, &summary, &langs, &ignored_words);
        self.check_description_tag(pkg, out, &description, &summary, &langs, &ignored_words);
        self.check_group(pkg, out, &group);
        self.check_buildhost(pkg, out, &buildhost);
        self.check_changelog(pkg, out, &changelog);
        self.check_license(pkg, out, &rpm_license);
        self.check_url(pkg, out);

        let prov_names: Vec<&str> = pkg.provides.iter().map(|d| d.name.as_str()).collect();
        self.check_obsolete_not_provided(pkg, out, &prov_names);

        for dep in &pkg.obsoletes {
            let value = format_require(dep);
            self.unexpanded_macro(out, pkg, &format!("Obsoletes {value}"), &value);
        }

        self.check_useless_provides(pkg, out);
        self.check_forbidden_controlchar(pkg, out);
        self.check_self_obsoletion(pkg, out);
        self.check_non_coherent_filename(pkg, out);

        for (tagname, tag) in [
            ("Distribution", Tag::DISTRIBUTION),
            ("DistTag", Tag::DISTTAG),
            ("ExcludeArch", Tag::EXCLUDEARCH),
            ("ExcludeOS", Tag::EXCLUDEOS),
            ("Vendor", Tag::VENDOR),
        ] {
            let res = tag_str(tag);
            self.unexpanded_macro(out, pkg, tagname, &res);
        }
    }

    fn check_invalid_packager(&self, pkg: &Pkg, out: &mut Filter, packager: &str) {
        if !packager.is_empty() {
            self.unexpanded_macro(out, pkg, "Packager", packager);
            if let Some(re) = &self.packager_regex
                && !re.is_match(packager).unwrap_or(true)
            {
                add_info(out, Level::Warning, pkg, "invalid-packager", &[packager]);
            }
        } else {
            add_info(out, Level::Error, pkg, "no-packager-tag", &[]);
        }
    }

    fn check_version(&self, pkg: &Pkg, out: &mut Filter, version: &str) {
        if !version.is_empty() {
            self.unexpanded_macro(out, pkg, "Version", version);
            if is_match(&self.invalid_version_re, version) {
                add_info(out, Level::Error, pkg, "invalid-version", &[version]);
            }
        } else {
            add_info(out, Level::Error, pkg, "no-version-tag", &[]);
        }
    }

    fn check_release(&self, pkg: &Pkg, out: &mut Filter, release: &str) {
        if !release.is_empty() {
            self.unexpanded_macro(out, pkg, "Release", release);
            if let Some(re) = &self.extension_regex
                && !re.is_match(release).unwrap_or(true)
            {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "not-standard-release-extension",
                    &[release],
                );
            }
        } else {
            add_info(out, Level::Error, pkg, "no-release-tag", &[]);
        }
    }

    fn check_epoch(&self, pkg: &Pkg, out: &mut Filter, epoch: Option<i64>) {
        match epoch {
            None => {
                if self.use_epoch {
                    add_info(out, Level::Error, pkg, "no-epoch-tag", &[]);
                }
            }
            Some(e) => {
                if e > 99 {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "unreasonable-epoch",
                        &[&e.to_string()],
                    );
                }
            }
        }
    }

    fn check_no_epoch_in_tags(&self, pkg: &Pkg, out: &mut Filter) {
        if !self.use_epoch {
            return;
        }
        let tags: &[(&str, &[DepInfo])] = &[
            ("obsoletes", &pkg.obsoletes),
            ("conflicts", &pkg.conflicts),
            ("provides", &pkg.provides),
            ("recommends", &pkg.recommends),
            ("suggests", &pkg.suggests),
            ("enhances", &pkg.enhances),
            ("supplements", &pkg.supplements),
        ];
        for (tagname, deps) in tags {
            for dep in *deps {
                // versioned without epoch
                if dep.version.is_some() && dep.epoch.is_none() {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        &format!("no-epoch-in-{tagname}"),
                        &[&format_require(dep)],
                    );
                }
            }
        }
    }

    /// `_check_multiple_dependencies(pkg, deps, is_devel, is_source)` — the
    /// parameter order matters (issue #1483/#1485).
    fn check_dependencies(
        &self,
        pkg: &Pkg,
        out: &mut Filter,
        deps: &[DepInfo],
        is_devel: bool,
        is_source: bool,
    ) {
        let mut devel_depend = false;
        for dep in deps {
            let value = format_require(dep);
            if self.use_epoch
                && dep.version.is_some()
                && dep.epoch.is_none()
                && !dep.name.starts_with("rpmlib(")
            {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "no-epoch-in-dependency",
                    &[&value],
                );
            }
            // Issue #1443/#1444: check every requirement, not just the first.
            for req in &self.invalid_requires {
                if is_match(req, &dep.name) {
                    add_info(out, Level::Error, pkg, "invalid-dependency", &[&dep.name]);
                }
            }
            if dep.name.starts_with("/usr/local/") {
                add_info(out, Level::Error, pkg, "invalid-dependency", &[&dep.name]);
            }
            if is_source {
                if is_match(&self.lib_devel_number_re, &dep.name) {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "invalid-build-requires",
                        &[&dep.name],
                    );
                }
            } else if !is_devel {
                if !devel_depend && is_match(&self.devel_re, &dep.name) {
                    add_info(out, Level::Error, pkg, "devel-dependency", &[&dep.name]);
                    devel_depend = true;
                }
                // Issue #1091: replicate the fuzzy lib heuristic exactly.
                if dep.flags == 0
                    && let Ok(Some(caps)) = self.lib_package_re.captures(&dep.name)
                    && caps.get(1).is_none()
                {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "explicit-lib-dependency",
                        &[&dep.name],
                    );
                }
            }
            if dep.flags == RPMSENSE_EQUAL && dep.release.is_some() {
                add_info(out, Level::Warning, pkg, "requires-on-release", &[&value]);
            }
            self.unexpanded_macro(out, pkg, &format!("dependency {value}"), &value);
        }
    }
}

/// `formatRequire`: `name [<|>|= version]`.
fn format_require(dep: &DepInfo) -> String {
    let mut s = dep.name.clone();
    if dep.flags & (RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL) != 0 {
        s.push(' ');
        if dep.flags & RPMSENSE_LESS != 0 {
            s.push('<');
        }
        if dep.flags & RPMSENSE_GREATER != 0 {
            s.push('>');
        }
        if dep.flags & RPMSENSE_EQUAL != 0 {
            s.push('=');
        }
        s.push(' ');
        s.push_str(&dep.evr_string());
    }
    s
}

/// Compare two EVRs with rpm's segmented algorithm: -1/0/1.
fn compare_evr(
    e1: Option<i64>,
    v1: Option<&str>,
    r1: Option<&str>,
    e2: Option<i64>,
    v2: Option<&str>,
    r2: Option<&str>,
) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    // Epoch: missing sorts before present; numeric compare otherwise.
    // (rpmlint stringifies None epochs, but None-vs-None and the numeric
    // cases below cover the self-obsoletion use.)
    match (e1, e2) {
        (None, None) => {}
        (None, Some(_)) => return Ordering::Less,
        (Some(_), None) => return Ordering::Greater,
        (Some(a), Some(b)) => match a.cmp(&b) {
            Ordering::Equal => {}
            ord => return ord,
        },
    }
    match librpm::version::vercmp(v1.unwrap_or(""), v2.unwrap_or("")) {
        Ordering::Equal => {}
        ord => return ord,
    }
    librpm::version::vercmp(r1.unwrap_or(""), r2.unwrap_or(""))
}

/// `rangeCompare`: does `prov` satisfy the `req` requirement? Implements
/// Tom's #1599 exemption: a merge-pattern Obsoletes (`<=`/`=` at or below the
/// provided EVR) never matches the package itself.
fn range_compare(req: &DepInfo, prov: &DepInfo) -> bool {
    use std::cmp::Ordering;
    if req.name != prov.name {
        return false;
    }
    // Issue #1599: package-merge pattern. An upper-bounded requirement at or
    // below the provided EVR only matches older releases of a merged-away
    // package, never the package itself.
    if (req.flags == (RPMSENSE_LESS | RPMSENSE_EQUAL) || req.flags == RPMSENSE_EQUAL)
        && compare_evr(
            req.epoch,
            req.version.as_deref(),
            req.release.as_deref(),
            prov.epoch,
            prov.version.as_deref(),
            prov.release.as_deref(),
        ) != Ordering::Greater
    {
        return false;
    }
    // Unversioned satisfies everything.
    if prov.flags == 0 || req.flags == 0 {
        return true;
    }
    let (e, v, r) = (prov.epoch, prov.version.as_deref(), prov.release.as_deref());
    let (reqe, reqv, reqr) = (req.epoch, req.version.as_deref(), req.release.as_deref());
    // Drop the provided release when the requirement has none, so
    // `foo = 1:3.0.0` matches `foo = 1:3.0.0-15`.
    let r = if reqr.is_none() { None } else { r };
    let v = if reqv.is_none() { None } else { v };
    let reqr = if r.is_none() { None } else { reqr };
    let rc = compare_evr(e, v, r, reqe, reqv, reqr);
    // Flag shorthands from the reference: GT=4, GE=12, EQ=8, LE=10, LT=2.
    let (reqf, f) = (req.flags, prov.flags);
    if rc == Ordering::Greater {
        if reqf == 4 || reqf == 12 {
            return true;
        }
        if reqf == 8 && (f == 10 || f == 2) {
            return true;
        }
        if (reqf == 10 || reqf == 2 || reqf == 8) && (f == 10 || f == 2) {
            return true;
        }
    }
    if rc == Ordering::Equal {
        if reqf == 4 && (f == 4 || f == 12) {
            return true;
        }
        if reqf == 12 && (f == 4 || f == 12 || f == 8 || f == 10) {
            return true;
        }
        if reqf == 8 && (f == 8 || f == 12 || f == 10) {
            return true;
        }
        if reqf == 10 && (f == 8 || f == 10 || f == 2 || f == 12) {
            return true;
        }
        if reqf == 2 && (f == 10 || f == 2) {
            return true;
        }
    }
    if rc == Ordering::Less {
        if (reqf == 4 || reqf == 12 || reqf == 8) && (f == 4 || f == 12) {
            return true;
        }
        if reqf == 10 || reqf == 2 {
            return true;
        }
    }
    false
}

impl TagsCheck {
    fn check_name(&self, pkg: &Pkg, out: &mut Filter) {
        let name = pkg.name.as_str();
        if name.is_empty() {
            add_info(out, Level::Error, pkg, "no-name-tag", &[]);
            return;
        }
        let is_devel = is_match(&self.devel_re, name);
        if is_devel && !pkg.is_source {
            let base = match self
                .devel_re
                .captures(name)
                .ok()
                .flatten()
                .and_then(|c| c.get(1))
            {
                Some(m) => m.as_str().to_string(),
                None => return,
            };
            let mut has_so = false;
            let mut has_pc = false;
            for f in &pkg.files {
                if f.name.ends_with(".so") {
                    has_so = true;
                }
                if is_match(&self.pkg_config_re, &f.name) && f.name.ends_with(".pc") {
                    has_pc = true;
                }
            }
            if has_so {
                let base_or_libs = format!("{base}*/{base}-libs/lib{base}*");
                let re_str = format!(
                    r"^(lib)?{}(\\-libs)?[\\d_-]*(\\(\\w+-\\d+\\))?$",
                    regex_escape(&base)
                );
                let base_or_libs_re = Regex::new(&re_str).expect("static regex");
                let mut dep_match: Option<&DepInfo> = None;
                for d in pkg.requires.iter().chain(&pkg.prereq) {
                    if is_match(&base_or_libs_re, &d.name) {
                        dep_match = Some(d);
                        break;
                    }
                }
                let header = pkg.header();
                let version = crate::pkg::tags::str_tag(header, Tag::VERSION).unwrap_or_default();
                let epoch: Option<i64> = match header.get_owned(Tag::EPOCH) {
                    Some(OwnedTagData::Int32(v)) => v.into_iter().next().map(|e| e as i64),
                    _ => None,
                };
                if let (Some(dep), true) = (dep_match, !version.is_empty()) {
                    let exp = (epoch, Some(version.as_str()), None);
                    let sexp = version_to_string(exp.0, exp.1, exp.2);
                    if dep.flags == 0 {
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "no-version-dependency-on",
                            &[&base_or_libs, &sexp],
                        );
                    } else if (dep.epoch, dep.version.as_deref()) != (exp.0, exp.1) {
                        let v = version_to_string(dep.epoch, dep.version.as_deref(), None);
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "missing-dependency-on",
                            &[&format!("{base_or_libs} = {v}")],
                        );
                    }
                }
                match self.devel_number_re.captures(name).ok().flatten() {
                    None => {
                        add_info(out, Level::Warning, pkg, "no-major-in-name", &[name]);
                    }
                    Some(caps) => {
                        let prov = if caps.get(3).is_some() {
                            format!("{}{}-devel", &caps[1], &caps[2])
                        } else {
                            format!("{}-devel", &caps[1])
                        };
                        if !pkg.provides.iter().any(|p| p.name == prov) {
                            add_info(out, Level::Warning, pkg, "no-provides", &[&prov]);
                        }
                    }
                }
            }
            if has_pc {
                let found = pkg
                    .provides
                    .iter()
                    .any(|p| p.name.starts_with("pkgconfig("));
                if !found {
                    add_info(out, Level::Error, pkg, "no-pkg-config-provides", &[]);
                }
            }
        }
    }

    /// `None` for the `C`/`C.UTF-8` locales (issue #538): the language is not
    /// a useful detail there.
    fn lang_for_error(lang: &str) -> Option<&str> {
        if lang == "C" || lang == "C.UTF-8" {
            None
        } else {
            Some(lang)
        }
    }

    fn check_summary_tag(
        &self,
        pkg: &Pkg,
        out: &mut Filter,
        summary: &str,
        langs: &[String],
        ignored: &[String],
    ) {
        if summary.is_empty() {
            add_info(out, Level::Error, pkg, "no-summary-tag", &[]);
            return;
        }
        if langs.is_empty() {
            self.unexpanded_macro(out, pkg, "Summary", summary);
        } else {
            for lang in langs {
                let s = self.lang_string(pkg, Tag::SUMMARY, lang);
                self.check_summary(pkg, out, &s, lang, ignored);
            }
        }
    }

    /// Read a tag in a specific language. The `C` locale is the header default;
    /// other locales are selected from the raw i18n table.
    fn lang_string(&self, pkg: &Pkg, tag: Tag, lang: &str) -> String {
        let header = pkg.header();
        if lang == "C" || lang == "C.UTF-8" {
            return crate::pkg::tags::str_tag(header, tag).unwrap_or_default();
        }
        let table = crate::pkg::tags::str_array(header, Tag::HEADERI18NTABLE);
        if let Some(idx) = table.iter().position(|l| l == lang)
            && let Some(OwnedTagData::I18NStr(v)) = header.get_owned_with_options(
                tag,
                librpm::package::GetOptions {
                    raw: true,
                    ..Default::default()
                },
            )
        {
            return v.get(idx).cloned().unwrap_or_default();
        }
        String::new()
    }

    fn check_summary(
        &self,
        pkg: &Pkg,
        out: &mut Filter,
        summary: &str,
        lang: &str,
        ignored: &[String],
    ) {
        self.unexpanded_macro(out, pkg, &format!("Summary({lang})"), summary);
        // Spellcheck via `spellbook`; skipped in mini-mode (checker is None).
        if let Some(checker) = &self.spellchecker {
            for (word, suggestions) in checker.check(summary, &pkg.name, ignored) {
                let sug = if suggestions.is_empty() {
                    String::new()
                } else {
                    format!(" -> {}", suggestions.join(", "))
                };
                let detail = format!("Summary({lang}) {word}{sug}");
                add_info(out, Level::Error, pkg, "spelling-error", &[&detail]);
            }
        }
        let lang_err = Self::lang_for_error(lang);
        if summary.contains('\n') || summary.contains('\r') {
            let mut d: Vec<&str> = Vec::new();
            if let Some(l) = lang_err {
                d.push(l);
            }
            add_info(out, Level::Error, pkg, "summary-on-multiple-lines", &d);
        }
        let first_word = summary.split(' ').next().unwrap_or("");
        let capitalized = summary
            .chars()
            .next()
            .map(|c| c.is_uppercase())
            .unwrap_or(false);
        if !capitalized && !CAPITALIZED_IGNORE_LIST.contains(&first_word) {
            let mut d: Vec<&str> = Vec::new();
            if let Some(l) = lang_err {
                d.push(l);
            }
            d.push(summary);
            add_info(out, Level::Warning, pkg, "summary-not-capitalized", &d);
        }
        if summary.ends_with('.') {
            let mut d: Vec<&str> = Vec::new();
            if let Some(l) = lang_err {
                d.push(l);
            }
            d.push(summary);
            add_info(out, Level::Warning, pkg, "summary-ended-with-dot", &d);
        }
        if summary.len() > self.max_line_len {
            let mut d: Vec<&str> = Vec::new();
            if let Some(l) = lang_err {
                d.push(l);
            }
            d.push(summary);
            add_info(out, Level::Error, pkg, "summary-too-long", &d);
        }
        if is_match(&self.leading_space_re, summary) {
            let mut d: Vec<&str> = Vec::new();
            if let Some(l) = lang_err {
                d.push(l);
            }
            d.push(summary);
            add_info(out, Level::Error, pkg, "summary-has-leading-spaces", &d);
        }
        if let Some(re) = &self.forbidden_words_regex
            && let Ok(Some(m)) = re.find(summary)
        {
            let mut d: Vec<&str> = Vec::new();
            if let Some(l) = lang_err {
                d.push(l);
            }
            d.push(m.as_str());
            add_info(out, Level::Warning, pkg, "summary-use-invalid-word", &d);
        }
        if !pkg.name.is_empty() {
            let sepchars = format!(r"[\s{PUNCT}]");
            let pat = format!(r"(?:^|\s)({})(?:{sepchars}|$)", regex_escape(&pkg.name));
            if let Ok(re) = Regex::new(&format!("(?i){pat}"))
                && let Ok(Some(caps)) = re.captures(summary)
                && let Some(m) = caps.get(1)
            {
                let mut d: Vec<&str> = Vec::new();
                if let Some(l) = lang_err {
                    d.push(l);
                }
                d.push(m.as_str());
                add_info(out, Level::Warning, pkg, "name-repeated-in-summary", &d);
            }
        }
    }

    fn check_description_tag(
        &self,
        pkg: &Pkg,
        out: &mut Filter,
        description: &str,
        summary: &str,
        langs: &[String],
        ignored: &[String],
    ) {
        if description.is_empty() {
            add_info(out, Level::Error, pkg, "no-description-tag", &[]);
            return;
        }
        if langs.is_empty() {
            self.unexpanded_macro(out, pkg, "%description", description);
        } else {
            for lang in langs {
                let d = self.lang_string(pkg, Tag::DESCRIPTION, lang);
                self.check_description(pkg, out, &d, lang, ignored);
            }
        }
        if description.len() < summary.len() {
            add_info(
                out,
                Level::Warning,
                pkg,
                "description-shorter-than-summary",
                &[],
            );
        }
    }

    fn check_description(
        &self,
        pkg: &Pkg,
        out: &mut Filter,
        description: &str,
        lang: &str,
        ignored: &[String],
    ) {
        self.unexpanded_macro(out, pkg, &format!("%description -l {lang}"), description);
        // Spellcheck via `spellbook`; skipped in mini-mode (checker is None).
        if let Some(checker) = &self.spellchecker {
            for (word, suggestions) in checker.check(description, &pkg.name, ignored) {
                let sug = if suggestions.is_empty() {
                    String::new()
                } else {
                    format!(" -> {}", suggestions.join(", "))
                };
                let detail = format!("%description -l {lang} {word}{sug}");
                add_info(out, Level::Error, pkg, "spelling-error", &[&detail]);
            }
        }
        let lang_err = Self::lang_for_error(lang);
        for line in description.split('\n') {
            // Strip a trailing \r for length purposes? The reference uses
            // splitlines() which strips all line boundaries; len() is on the
            // stripped line.
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.len() > self.max_line_len {
                let mut d: Vec<&str> = Vec::new();
                if let Some(l) = lang_err {
                    d.push(l);
                }
                d.push(line);
                add_info(out, Level::Error, pkg, "description-line-too-long", &d);
            }
            if let Some(re) = &self.forbidden_words_regex
                && let Ok(Some(m)) = re.find(line)
            {
                let mut d: Vec<&str> = Vec::new();
                if let Some(l) = lang_err {
                    d.push(l);
                }
                d.push(m.as_str());
                add_info(out, Level::Warning, pkg, "description-use-invalid-word", &d);
            }
            if let Ok(Some(caps)) = self.tag_re.captures(line)
                && let Some(m) = caps.get(1)
            {
                let mut d: Vec<&str> = Vec::new();
                if let Some(l) = lang_err {
                    d.push(l);
                }
                d.push(m.as_str());
                add_info(out, Level::Warning, pkg, "tag-in-description", &d);
            }
        }
    }

    fn check_group(&self, pkg: &Pkg, out: &mut Filter, group: &str) {
        // Issue #611: `no-group-tag` does execute; implement as-is.
        self.unexpanded_macro(out, pkg, "Group", group);
        if group.is_empty() {
            add_info(out, Level::Error, pkg, "no-group-tag", &[]);
        } else if pkg.name.ends_with("-devel") && !group.starts_with("Development/") {
            add_info(
                out,
                Level::Warning,
                pkg,
                "devel-package-with-non-devel-group",
                &[group],
            );
        } else if !self.valid_groups.is_empty() && !self.valid_groups.contains(&group.to_string()) {
            add_info(out, Level::Warning, pkg, "non-standard-group", &[group]);
        }
    }

    fn check_buildhost(&self, pkg: &Pkg, out: &mut Filter, buildhost: &str) {
        self.unexpanded_macro(out, pkg, "BuildHost", buildhost);
        if buildhost.is_empty() {
            add_info(out, Level::Error, pkg, "no-buildhost-tag", &[]);
        } else if let Some(re) = &self.valid_buildhost_regex
            && !re.is_match(buildhost).unwrap_or(true)
        {
            add_info(out, Level::Warning, pkg, "invalid-buildhost", &[buildhost]);
        }
    }
}

impl TagsCheck {
    fn check_changelog(&self, pkg: &Pkg, out: &mut Filter, changelog: &[String]) {
        let header = pkg.header();
        let version = crate::pkg::tags::str_tag(header, Tag::VERSION).unwrap_or_default();
        let release = crate::pkg::tags::str_tag(header, Tag::RELEASE).unwrap_or_default();
        let name = pkg.name.as_str();
        let epoch: Option<i64> = match header.get_owned(Tag::EPOCH) {
            Some(OwnedTagData::Int32(v)) => v.into_iter().next().map(|e| e as i64),
            _ => None,
        };
        if changelog.is_empty() {
            add_info(out, Level::Error, pkg, "no-changelogname-tag", &[]);
            return;
        }
        let clt: Vec<String> = crate::pkg::tags::str_array(header, Tag::CHANGELOGTEXT);
        if self.use_version_in_changelog {
            let mut found: Option<String> = None;
            if let Ok(Some(caps)) = self.changelog_version_re.captures(&changelog[0]) {
                found = caps.get(1).map(|m| m.as_str().to_string());
            } else if !clt.is_empty()
                && let Ok(Some(caps)) = self.changelog_text_version_re.captures(&clt[0])
            {
                found = caps.get(1).map(|m| m.as_str().to_string());
            }
            match found {
                None => {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "no-version-in-last-changelog",
                        &[],
                    );
                }
                Some(ret) => {
                    if !version.is_empty() && !release.is_empty() {
                        let srpm =
                            crate::pkg::tags::str_tag(header, Tag::SOURCERPM).unwrap_or_default();
                        let srpm_base = srpm
                            .strip_suffix(".src.rpm")
                            .or_else(|| srpm.strip_suffix(".rpm"))
                            .unwrap_or(&srpm);
                        if srpm_base == format!("{name}-{version}-{release}") {
                            let mut expected = vec![format!("{version}-{release}")];
                            if let Some(e) = epoch {
                                expected[0] = format!("{e}:{}", expected[0]);
                            }
                            // Issue #856: the reference does not account for
                            // `%{?dist}` in Release; replicate as-is.
                            if let Some(re) = &self.extension_regex {
                                expected.push(re.replace_all(&expected[0], "").to_string());
                            }
                            if !expected.contains(&ret) {
                                let exp_str = if expected.len() == 1 {
                                    expected[0].clone()
                                } else {
                                    format!("{:?}", expected)
                                };
                                add_info(
                                    out,
                                    Level::Warning,
                                    pkg,
                                    "incoherent-version-in-changelog",
                                    &[&ret, &exp_str],
                                );
                            }
                        }
                    }
                }
            }
        }
        let mut combined: Vec<String> = changelog.to_vec();
        combined.extend(clt.iter().cloned());
        for entry in &combined {
            if let Some(bad) = has_forbidden_controlchars(entry) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "forbidden-controlchar-found",
                    &[&format!("%changelog : {bad}")],
                );
                break;
            }
        }
        let times = crate::pkg::tags::int32_array(header, Tag::CHANGELOGTIME);
        if let Some(&first) = times.first() {
            let mut clt_time = first as i64 - 26 * 3600;
            if clt_time < OLDEST_CHANGELOG_TIMESTAMP {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "changelog-time-overflow",
                    &[&format_date(clt_time)],
                );
            } else {
                clt_time = first as i64;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                if clt_time > now {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "changelog-time-in-future",
                        &[&format_date(clt_time)],
                    );
                }
            }
        }
    }

    /// Split a license expression into leaf licenses, respecting parentheses.
    ///
    /// `(GPLv2 or GPLv3) and (GPLv2+ with exceptions)` becomes
    /// `["GPLv2", "GPLv3", "GPLv2+ with exceptions"]`: a fully parenthesized
    /// expression is unwrapped one layer at a time, and `and`/`or` (either
    /// case, the reference's operator set) split at the top level only, so a
    /// `with` inside one group never leaks into the exception match of
    /// another group.
    fn split_license_leaves(text: &str) -> Vec<String> {
        let text = text.trim();
        if text.is_empty() {
            return Vec::new();
        }
        if let Some(inner) = Self::strip_enclosing_parens(text) {
            return Self::split_license_leaves(inner);
        }
        let chars: Vec<(usize, char)> = text.char_indices().collect();
        let mut parts = Vec::new();
        let mut depth = 0usize;
        let mut start = 0usize;
        let mut k = 0usize;
        while k < chars.len() {
            let (i, c) = chars[k];
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth = depth.saturating_sub(1);
            } else if depth == 0
                && (i == 0 || text[..i].ends_with(char::is_whitespace))
                && let Some(op_len) = Self::match_bool_op(&text[i..])
            {
                parts.push(text[start..i].trim());
                start = i + op_len;
                while k < chars.len() && chars[k].0 < start {
                    k += 1;
                }
                continue;
            }
            k += 1;
        }
        if parts.is_empty() {
            return vec![text.to_string()];
        }
        parts.push(text[start..].trim());
        let mut leaves = Vec::new();
        for part in parts {
            if !part.is_empty() {
                leaves.extend(Self::split_license_leaves(part));
            }
        }
        leaves
    }

    /// If `s` is wrapped in a single balanced paren pair, return the inside.
    fn strip_enclosing_parens(s: &str) -> Option<&str> {
        let s = s.trim();
        if s.len() < 2 || !s.starts_with('(') || !s.ends_with(')') {
            return None;
        }
        let mut depth = 0i32;
        for (i, c) in s.char_indices() {
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
                if depth == 0 && i != s.len() - 1 {
                    return None;
                }
            }
        }
        (depth == 0).then(|| &s[1..s.len() - 1])
    }

    /// Length of a boolean operator at the start of `s` (`and`/`or`, either
    /// case), requiring whitespace after it. The caller ensures whitespace
    /// (or the start) before it.
    fn match_bool_op(s: &str) -> Option<usize> {
        for op in ["and", "or", "AND", "OR"] {
            if let Some(rest) = s.strip_prefix(op)
                && rest.starts_with(char::is_whitespace)
            {
                return Some(op.len());
            }
        }
        None
    }

    /// Split `"<license> WITH <exception>"`; returns `(license, exception)`.
    fn split_license_exception(&self, text: &str) -> (String, String) {
        match self.license_exception_re.captures(text).ok().flatten() {
            Some(caps) => (
                caps.get(1)
                    .map(|m| m.as_str().trim().to_string())
                    .unwrap_or_default(),
                caps.get(2)
                    .map(|m| m.as_str().trim().to_string())
                    .unwrap_or_default(),
            ),
            None => (text.trim().to_string(), String::new()),
        }
    }

    fn check_license(&self, pkg: &Pkg, out: &mut Filter, rpm_license: &str) {
        if rpm_license.is_empty() {
            add_info(out, Level::Error, pkg, "no-license", &[]);
            return;
        }
        let mut valid_license = true;
        if !self.valid_licenses.contains(&rpm_license.to_string()) {
            // Each leaf is validated on its own: the old whole-string
            // exception match replaced the license string with just the
            // pre-WITH part, silently dropping every other leaf (and any
            // trailing `and MIT`-style tail) from validation.
            for leaf in Self::split_license_leaves(rpm_license) {
                let (lic, lexception) = self.split_license_exception(&leaf);
                if !lexception.is_empty() {
                    // SPDX allows "<license> WITH <license-exception>"
                    if !self.valid_license_exceptions.contains(&lexception) {
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "invalid-license-exception",
                            &[&lexception],
                        );
                        valid_license = false;
                    }
                }
                let lic = if lexception.is_empty() { leaf } else { lic };
                if !lic.is_empty() && !self.valid_licenses.contains(&lic) {
                    add_info(out, Level::Warning, pkg, "invalid-license", &[&lic]);
                    valid_license = false;
                }
            }
        }
        if !valid_license {
            self.unexpanded_macro(out, pkg, "License", rpm_license);
        }
    }

    fn check_url(&self, pkg: &Pkg, out: &mut Filter) {
        let header = pkg.header();
        for (tagname, tag) in [
            ("URL", Tag::URL),
            ("DistURL", Tag::DISTURL),
            ("BugURL", Tag::BUGURL),
        ] {
            let url = crate::pkg::tags::str_tag(header, tag).unwrap_or_default();
            self.unexpanded_macros(out, pkg, tagname, std::slice::from_ref(&url), true);
            if !url.is_empty() {
                let (scheme, netloc) = split_url(&url);
                let bad_scheme = !["http", "https", "ftp", "obs"].contains(&scheme.as_str());
                if scheme.is_empty()
                    || netloc.is_empty()
                    || !netloc.contains('.')
                    || bad_scheme
                    || self
                        .invalid_url_regex
                        .as_ref()
                        .is_some_and(|re| is_match(re, &url))
                {
                    add_info(out, Level::Warning, pkg, "invalid-url", &[tagname, &url]);
                }
            } else if tagname == "URL" {
                add_info(out, Level::Warning, pkg, "no-url-tag", &[]);
            }
        }
    }

    fn check_obsolete_not_provided(&self, pkg: &Pkg, out: &mut Filter, prov_names: &[&str]) {
        for obs in &pkg.obsoletes {
            if !prov_names.contains(&obs.name.as_str()) {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "obsolete-not-provided",
                    &[&obs.name],
                );
            }
        }
    }

    fn check_useless_provides(&self, pkg: &Pkg, out: &mut Filter) {
        let mut no_version: std::collections::BTreeSet<&str> = Default::default();
        let mut versioned: std::collections::BTreeSet<&str> = Default::default();
        for prov in &pkg.provides {
            if prov.name.starts_with("debuginfo(") {
                continue;
            }
            if prov.evr_string().is_empty() {
                no_version.insert(prov.name.as_str());
            } else {
                versioned.insert(prov.name.as_str());
            }
        }
        for prov in no_version {
            if versioned.contains(prov) {
                add_info(out, Level::Error, pkg, "useless-provides", &[prov]);
            }
        }
    }

    fn check_forbidden_controlchar(&self, pkg: &Pkg, out: &mut Filter) {
        let tags: &[(&str, &[DepInfo])] = &[
            ("Provides", &pkg.provides),
            ("Conflicts", &pkg.conflicts),
            ("Obsoletes", &pkg.obsoletes),
            ("Supplements", &pkg.supplements),
            ("Suggests", &pkg.suggests),
            ("Enhances", &pkg.enhances),
            ("Recommends", &pkg.recommends),
        ];
        for (tagname, deps) in tags {
            for dep in *deps {
                if let Some(bad) = has_forbidden_controlchars(&format_require(dep)) {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "forbidden-controlchar-found",
                        &[&format!("{tagname}: {bad}")],
                    );
                }
                let value = format_require(dep);
                self.unexpanded_macro(out, pkg, &format!("{tagname} {value}"), &value);
            }
        }
        for dep in pkg.requires.iter().chain(&pkg.prereq) {
            if let Some(bad) = has_forbidden_controlchars(&format_require(dep)) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "forbidden-controlchar-found",
                    &[&format!("Requires: {bad}")],
                );
            }
        }
    }

    fn check_self_obsoletion(&self, pkg: &Pkg, out: &mut Filter) {
        if pkg.obsoletes.is_empty() {
            return;
        }
        for prov in &pkg.provides {
            for obs in &pkg.obsoletes {
                if range_compare(obs, prov) {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "self-obsoletion",
                        &[&format!(
                            "{} obsoletes {}",
                            format_require(obs),
                            format_require(prov)
                        )],
                    );
                }
            }
        }
    }

    fn check_non_coherent_filename(&self, pkg: &Pkg, out: &mut Filter) {
        let header = pkg.header();
        let version = crate::pkg::tags::str_tag(header, Tag::VERSION).unwrap_or_default();
        let release = crate::pkg::tags::str_tag(header, Tag::RELEASE).unwrap_or_default();
        // `%{_build_name_fmt}` is `%{ARCH}/%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}.rpm`;
        // the reference takes the basename. `pkg.arch` is already `src`/`nosrc`
        // for source packages.
        let expected = format!("{}-{}-{}.{}.rpm", pkg.name, version, release, pkg.arch);
        let basename = Path::new(&pkg.filename)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if basename != expected {
            add_info(
                out,
                Level::Warning,
                pkg,
                "non-coherent-filename",
                &[&basename, &expected],
            );
        }
    }
}

/// `has_forbidden_controlchars`: any char < 32 other than tab/LF/CR.
fn has_forbidden_controlchars(s: &str) -> Option<&str> {
    if s.chars()
        .any(|c| (c as u32) < 32 && !matches!(c, '\t' | '\n' | '\r'))
    {
        Some(s)
    } else {
        None
    }
}

/// Split a URL into `(scheme, netloc)`, lowercasing the scheme.
fn split_url(url: &str) -> (String, String) {
    match url.find("://") {
        Some(i) => {
            let scheme = url[..i].to_lowercase();
            let rest = &url[i + 3..];
            let netloc = rest.split('/').next().unwrap_or("").to_string();
            (scheme, netloc)
        }
        None => (String::new(), String::new()),
    }
}

/// Format a Unix timestamp as `YYYY-MM-DD` (UTC).
fn format_date(ts: i64) -> String {
    // Days since epoch, Howard Hinnant's algorithm.
    let days = ts.div_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", y + if m <= 2 { 1 } else { 0 }, m, d)
}

impl Check for TagsCheck {
    fn name(&self) -> &'static str {
        "TagsCheck"
    }

    /// The reference defines only `check()`, so it runs for source and binary
    /// packages alike; no `check_binary`/`check_source` split.
    fn check(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        self.run(pkg, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;

    fn test_config() -> Config {
        // Minimal config with the keys TagsCheck reads.
        let mut config = Config::default();
        let tbl = &mut config.configuration;
        tbl.insert(
            "UseVersionInChangelog".to_string(),
            toml::Value::Boolean(true),
        );
        tbl.insert("UseEpoch".to_string(), toml::Value::Boolean(false));
        tbl.insert("MaxLineLength".to_string(), toml::Value::Integer(79));
        tbl.insert("ValidGroups".to_string(), toml::Value::Array(vec![]));
        tbl.insert("ValidLicenses".to_string(), toml::Value::Array(vec![]));
        tbl.insert(
            "ValidLicenseExceptions".to_string(),
            toml::Value::Array(vec![]),
        );
        tbl.insert("InvalidRequires".to_string(), toml::Value::Array(vec![]));
        config.finalize().expect("fixture config");
        config
    }

    fn fixture_pkg(name: &str) -> Pkg {
        // Hand-built fixture RPMs in tests/parity/pkg/inputs/, not distro
        // packages. The llvm21-gold corpus is reserved for parity tests.
        let rpm_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs")
            .join(name);
        Pkg::open(&rpm_path, &std::env::temp_dir(), true).expect("open fixture pkg")
    }

    fn run_check(pkg: &Pkg) -> Vec<(String, String)> {
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = TagsCheck::new(&config);
        check.check(pkg, &config, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn tags_check_runs_on_fixture() {
        let pkg = fixture_pkg("fcprobe-1-1.noarch.rpm");
        let results = run_check(&pkg);
        for (name, line) in &results {
            eprintln!("GOT: {}: {}", name, line);
        }
        // Smoke test: the check runs and emits well-formed findings.
        // Uses a hand-built fixture, not the llvm21-gold corpus (reserved
        // for parity tests).
        for (name, line) in &results {
            assert!(!name.is_empty(), "finding name: {line}");
            assert!(
                line.contains(": E: ") || line.contains(": W: "),
                "level: {line}"
            );
        }
    }

    #[test]
    fn format_require_matches_reference() {
        let dep = DepInfo {
            name: "foo".to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        };
        assert_eq!(format_require(&dep), "foo");
        let dep = DepInfo {
            name: "foo".to_string(),
            flags: RPMSENSE_EQUAL,
            epoch: None,
            version: Some("1.0".to_string()),
            release: Some("2".to_string()),
        };
        assert_eq!(format_require(&dep), "foo = 1.0-2");
        let dep = DepInfo {
            name: "bar".to_string(),
            flags: RPMSENSE_LESS | RPMSENSE_EQUAL,
            epoch: Some(1),
            version: Some("2.0".to_string()),
            release: None,
        };
        assert_eq!(format_require(&dep), "bar <= 1:2.0");
    }

    #[test]
    fn range_compare_implements_1599_exemption() {
        // Provides: merged = 1.6.1, Obsoletes: merged <= 1.6.1 -> no match
        let prov = DepInfo {
            name: "merged".to_string(),
            flags: RPMSENSE_EQUAL,
            epoch: None,
            version: Some("1.6.1".to_string()),
            release: None,
        };
        let obs = DepInfo {
            name: "merged".to_string(),
            flags: RPMSENSE_LESS | RPMSENSE_EQUAL,
            epoch: None,
            version: Some("1.6.1".to_string()),
            release: None,
        };
        assert!(!range_compare(&obs, &prov), "merge pattern must not match");
        // Provides: mergedeq = 1.6.1, Obsoletes: mergedeq = 1.6.1 -> no match
        let prov = DepInfo {
            name: "mergedeq".to_string(),
            flags: RPMSENSE_EQUAL,
            epoch: None,
            version: Some("1.6.1".to_string()),
            release: None,
        };
        let obs = DepInfo {
            name: "mergedeq".to_string(),
            flags: RPMSENSE_EQUAL,
            epoch: None,
            version: Some("1.6.1".to_string()),
            release: None,
        };
        assert!(
            !range_compare(&obs, &prov),
            "pinned merge pattern must not match"
        );
        // Provides: selfobs = 1.0, Obsoletes: selfobs (unversioned) -> match
        let prov = DepInfo {
            name: "selfobs".to_string(),
            flags: RPMSENSE_EQUAL,
            epoch: None,
            version: Some("1.0".to_string()),
            release: None,
        };
        let obs = DepInfo {
            name: "selfobs".to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        };
        assert!(
            range_compare(&obs, &prov),
            "unversioned obsoletes must match"
        );
        // Provides: higher = 1.6.1, Obsoletes: higher <= 2.0 -> match (range covers package)
        let prov = DepInfo {
            name: "higher".to_string(),
            flags: RPMSENSE_EQUAL,
            epoch: None,
            version: Some("1.6.1".to_string()),
            release: None,
        };
        let obs = DepInfo {
            name: "higher".to_string(),
            flags: RPMSENSE_LESS | RPMSENSE_EQUAL,
            epoch: None,
            version: Some("2.0".to_string()),
            release: None,
        };
        assert!(range_compare(&obs, &prov), "range beyond EVR must match");
        // Provides: lower = 1.6.1, Obsoletes: lower < 1.6.1 -> no match
        let prov = DepInfo {
            name: "lower".to_string(),
            flags: RPMSENSE_EQUAL,
            epoch: None,
            version: Some("1.6.1".to_string()),
            release: None,
        };
        let obs = DepInfo {
            name: "lower".to_string(),
            flags: RPMSENSE_LESS,
            epoch: None,
            version: Some("1.6.1".to_string()),
            release: None,
        };
        assert!(!range_compare(&obs, &prov), "strictly-below must not match");
    }

    #[test]
    fn has_forbidden_controlchars_detects() {
        assert!(has_forbidden_controlchars("foo\x01bar").is_some());
        assert!(has_forbidden_controlchars("foo\tbar\n").is_none());
        assert!(has_forbidden_controlchars("normal").is_none());
    }

    #[test]
    fn lang_for_error_drops_c_locales() {
        // Issue #538: no stray "C" in name-repeated-in-summary.
        assert_eq!(TagsCheck::lang_for_error("C"), None);
        assert_eq!(TagsCheck::lang_for_error("C.UTF-8"), None);
        assert_eq!(TagsCheck::lang_for_error("de"), Some("de"));
    }

    fn license_test_config() -> Config {
        // Like test_config but with populated license lists.
        let mut config = Config::default();
        let tbl = &mut config.configuration;
        tbl.insert(
            "UseVersionInChangelog".to_string(),
            toml::Value::Boolean(true),
        );
        tbl.insert("UseEpoch".to_string(), toml::Value::Boolean(false));
        tbl.insert("MaxLineLength".to_string(), toml::Value::Integer(79));
        tbl.insert("ValidGroups".to_string(), toml::Value::Array(vec![]));
        tbl.insert(
            "ValidLicenses".to_string(),
            toml::Value::Array(
                ["GPLv2", "GPLv3", "GPLv2+", "GPL-2.0-only", "MIT"]
                    .into_iter()
                    .map(|s| toml::Value::String(s.to_string()))
                    .collect(),
            ),
        );
        tbl.insert(
            "ValidLicenseExceptions".to_string(),
            toml::Value::Array(vec![toml::Value::String(
                "Classpath-exception-2.0".to_string(),
            )]),
        );
        tbl.insert("InvalidRequires".to_string(), toml::Value::Array(vec![]));
        config.finalize().expect("fixture config");
        config
    }

    fn license_findings(license: &str) -> Vec<(String, String)> {
        let config = license_test_config();
        let pkg = fixture_pkg("fcprobe-1-1.noarch.rpm");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = TagsCheck::new(&config);
        check.check_license(&pkg, &mut out, license);
        out.results().to_vec()
    }

    #[test]
    fn license_leaves_respect_parens() {
        assert_eq!(
            TagsCheck::split_license_leaves("(GPLv2 or GPLv3) and (GPLv2+ with exceptions)"),
            vec!["GPLv2", "GPLv3", "GPLv2+ with exceptions"],
        );
        assert_eq!(
            TagsCheck::split_license_leaves("((GPLv2 or GPLv3) and MIT)"),
            vec!["GPLv2", "GPLv3", "MIT"],
        );
        assert_eq!(
            TagsCheck::split_license_leaves("GPLv2 AND GPLv3"),
            vec!["GPLv2", "GPLv3"],
        );
        assert_eq!(TagsCheck::split_license_leaves("MIT"), vec!["MIT"]);
        // `or` inside a word is not an operator.
        assert_eq!(
            TagsCheck::split_license_leaves("GPL-2.0-or-later"),
            vec!["GPL-2.0-or-later"],
        );
        // Multi-byte input must not panic on slicing.
        assert_eq!(
            TagsCheck::split_license_leaves("GPLv2é or MIT"),
            vec!["GPLv2é", "MIT"],
        );
    }

    #[test]
    fn license_paren_groups_yield_clean_findings() {
        let results = license_findings("(GPLv2 or GPLv3) and (GPLv2+ with exceptions)");
        for (name, line) in &results {
            eprintln!("GOT: {name}: {line}");
        }
        // The exception is genuinely unknown, so it is still reported, but
        // with a clean token: no paren may leak into any detail.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "invalid-license-exception");
        assert_eq!(
            results[0].1,
            "fcprobe.noarch: W: invalid-license-exception exceptions"
        );
    }

    #[test]
    fn license_invalid_leaf_in_paren_group_is_reported() {
        // The old whole-string exception match replaced the license string
        // with just the pre-WITH part, silently dropping every other leaf.
        let results = license_findings("(BogusLicense or GPLv3) and (GPLv2+ with exceptions)");
        for (name, line) in &results {
            eprintln!("GOT: {name}: {line}");
        }
        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&"invalid-license"),
            "BogusLicense must be flagged"
        );
        assert!(names.contains(&"invalid-license-exception"));
        let bad: Vec<_> = results
            .iter()
            .filter(|(n, _)| n == "invalid-license")
            .collect();
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].1, "fcprobe.noarch: W: invalid-license BogusLicense");
    }

    #[test]
    fn license_trailing_tail_after_with_is_validated() {
        // `and MIT` after a WITH expression used to be dropped entirely.
        let results =
            license_findings("GPL-2.0-only WITH Classpath-exception-2.0 and BogusLicense");
        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["invalid-license"]);
    }

    #[test]
    fn license_valid_with_exception_is_silent() {
        let results = license_findings("GPL-2.0-only WITH Classpath-exception-2.0");
        assert!(results.is_empty(), "unexpected: {results:?}");
    }

    #[test]
    fn license_plain_invalid_is_reported() {
        let results = license_findings("BogusLicense-1.0");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "invalid-license");
        assert_eq!(
            results[0].1,
            "fcprobe.noarch: W: invalid-license BogusLicense-1.0"
        );
    }
}
