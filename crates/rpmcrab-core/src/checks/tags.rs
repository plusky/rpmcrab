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
//!
//! One finding is run-scoped: `obsolete-not-provided` is judged in
//! `after_checks`, because a name a package obsoletes may be provided
//! by a sibling subpackage of the same build. The sibling credit
//! applies only when the run holds the build's source package
//! (header name-version-release plus `.src.rpm`/`.nosrc.rpm` equals
//! the binaries' `SOURCERPM`) — the shape an OBS lint run over a
//! finished build takes. On any partial or single-package input
//! every candidate fires, exactly the per-package verdict.

use fancy_regex::Regex;
use librpm::Tag;

use super::is_match;
use super::shared::{
    binary_source_key, devel_infix_regex, devel_regex, devel_underscore_regex,
    explicit_lib_package_regex, macro_regex, source_package_keys,
};
use super::spdx::suggest_licenses;
use crate::check::{Check, add_info, make_finding};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::dep::{
    DepInfo, RPMSENSE_EQUAL, RPMSENSE_FIND_REQUIRES, RPMSENSE_GREATER, RPMSENSE_LESS,
    version_to_string,
};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// Words that may start a summary in lowercase (`CAPITALIZED_IGNORE_LIST`).
const CAPITALIZED_IGNORE_LIST: &[&str] = &[
    "jQuery",
    "openSUSE",
    "wxWidgets",
    "a",
    "an",
    "uWSGI",
    "xSGE",
    "oneAPI",
];

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

/// 1995-01-01 UTC, the oldest sane changelog timestamp.
const OLDEST_CHANGELOG_TIMESTAMP: i64 = 788_918_400;

/// `TagsCheck`, ported from `rpmlint/checks/TagsCheck.py`.
pub struct TagsCheck {
    valid_licenses: Vec<String>,
    invalid_requires: Vec<Regex>,
    /// Upstream rpmlint#180: bot/invalid changelog authors, from the
    /// `InvalidChangelogAuthors` config regex list.
    invalid_changelog_authors: Vec<Regex>,
    invalid_url_regex: Option<Regex>,
    use_epoch: bool,
    max_line_len: usize,
    valid_license_exceptions: Vec<String>,
    macro_re: Regex,
    devel_re: Regex,
    lib_package_re: Regex,
    leading_space_re: Regex,
    license_exception_re: Regex,
    pkg_config_re: Regex,
    tag_re: Regex,
    spellchecker: Option<crate::spellcheck::Spellchecker>,
    /// `SOURCERPM` spellings of the source packages the run holds.
    obs_sources: HashSet<String>,
    /// Build keys in first-seen order, so the deferred
    /// `obsolete-not-provided` findings follow package lint order.
    obs_order: Vec<String>,
    obs_builds: HashMap<String, ObsoleteBuild>,
    /// Candidates of binary packages that carry no `SOURCERPM` key:
    /// they belong to no build the run can judge and always fire.
    obs_unkeyed: Vec<ObsoleteCandidate>,
}

/// One `obsolete-not-provided` candidate of a binary package: an
/// Obsoletes name the package's own Provides do not carry.
struct ObsoleteCandidate {
    pkg_name: String,
    arch: String,
    name: String,
}

/// Everything one build contributes to the run-scoped
/// `obsolete-not-provided` verdict.
#[derive(Default)]
struct ObsoleteBuild {
    /// Provides names of every package of the build the run holds.
    provides: HashSet<String>,
    /// The build's candidates, in package lint order.
    candidates: Vec<ObsoleteCandidate>,
}

/// Cross-package state, exported per package and merged before
/// `after_checks` (`rpmlint#1595`).
struct ObsoleteState {
    sources: HashSet<String>,
    order: Vec<String>,
    builds: HashMap<String, ObsoleteBuild>,
    unkeyed: Vec<ObsoleteCandidate>,
}

static URL_ESCAPE_RE: OnceLock<Regex> = OnceLock::new();

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

        let invalid_url = get_str("InvalidURL");

        Self {
            valid_licenses: get_strings("ValidLicenses"),
            invalid_requires: get_strings("InvalidRequires")
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect(),
            invalid_changelog_authors: get_strings("InvalidChangelogAuthors")
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect(),
            invalid_url_regex: (!invalid_url.is_empty())
                .then(|| Regex::new(&format!("(?i){invalid_url}")).ok())
                .flatten(),
            use_epoch: get_bool("UseEpoch"),
            max_line_len: tbl
                .get("MaxLineLength")
                .and_then(toml::Value::as_integer)
                .unwrap_or(79) as usize,
            valid_license_exceptions: get_strings("ValidLicenseExceptions"),
            macro_re: macro_regex().clone(),
            devel_re: devel_regex().clone(),
            lib_package_re: explicit_lib_package_regex().clone(),
            leading_space_re: Regex::new(r"^\s+").expect("static regex"),
            license_exception_re: Regex::new(r"([^(\s]+)\s(?:WITH|with)\s([^)\s]+)").expect("static regex"),
            pkg_config_re: Regex::new(r"^/usr/(?:lib\d*|share)/pkgconfig/").expect("static regex"),
            tag_re: Regex::new(r"(?i)^((?:Auto(?:Req|Prov|ReqProv)|Build(?:Arch(?:itectures)?|Root)|(?:Build)?Conflicts|(?:Build)?(?:Pre)?Requires|Copyright|(?:CVS|SVN)Id|Dist(?:ribution|Tag|URL)|DocDir|(?:Build)?Enhances|Epoch|Exclude(?:Arch|OS)|Exclusive(?:Arch|OS)|Group|Icon|License|Name|No(?:Patch|Source)|Obsoletes|Packager|Patch\d*|Prefix(?:es)?|Provides|(?:Build)?Recommends|Release|RHNPlatform|Serial|Source\d*|(?:Build)?Suggests|Summary|(?:Build)?Supplements|(?:Bug)?URL|Vendor|Version)(?:\([^)]+\))?:)\s*\S").expect("static regex"),
            spellchecker: if config.mini_mode {
                None
            } else {
                crate::spellcheck::Spellchecker::new()
            },
            obs_sources: HashSet::new(),
            obs_order: Vec::new(),
            obs_builds: HashMap::new(),
            obs_unkeyed: Vec::new(),
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
                if is_url
                    && is_match(
                        URL_ESCAPE_RE.get_or_init(|| {
                            Regex::new(r"(?i)^%[0-9A-F][0-9A-F]$").expect("static")
                        }),
                        m,
                    )
                {
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
        let tag_str = |t| pkg.tag_str(t).unwrap_or_default();
        let epoch: Option<i64> = pkg.tag_i64(Tag::EPOCH);
        let group = pkg.tag_str(Tag::GROUP).unwrap_or_default();
        let buildhost = tag_str(Tag::BUILDHOST);
        let langs = pkg.tag_str_array(Tag::HEADERI18NTABLE);
        let summary = tag_str(Tag::SUMMARY);
        let description = tag_str(Tag::DESCRIPTION);
        let changelog: Vec<String> = pkg.tag_str_array(Tag::CHANGELOGNAME);
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
            // Rich `(a or b)` expressions contribute their referenced names,
            // not the raw expression string.
            ignored_words.extend(dep.leaf_names());
        }

        self.check_packager(pkg, out, &tag_str(Tag::PACKAGER));
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

        // A source package's `obsolete-not-provided` verdict is its
        // own header's and is emitted here, as the reference emits it;
        // a binary package's verdict is deferred to `after_checks`,
        // where the run-scoped sibling credit is judged.
        if pkg.is_source {
            let prov_names: Vec<&str> = pkg.provides.iter().map(|d| d.name.as_str()).collect();
            self.check_obsolete_not_provided(pkg, out, &prov_names);
        }

        // Obsoletes are probed for unexpanded macros in check_forbidden_controlchar.
        self.check_useless_provides(pkg, out);
        self.check_forbidden_controlchar(pkg, out);
        self.check_self_obsoletion(pkg, out);

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

    fn check_packager(&self, pkg: &Pkg, out: &mut Filter, packager: &str) {
        if !packager.is_empty() {
            self.unexpanded_macro(out, pkg, "Packager", packager);
        }
    }

    fn check_version(&self, pkg: &Pkg, out: &mut Filter, version: &str) {
        if !version.is_empty() {
            self.unexpanded_macro(out, pkg, "Version", version);
        } else {
            add_info(out, Level::Error, pkg, "no-version-tag", &[]);
        }
    }

    fn check_release(&self, pkg: &Pkg, out: &mut Filter, release: &str) {
        if !release.is_empty() {
            self.unexpanded_macro(out, pkg, "Release", release);
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
                if !self.use_epoch {
                    add_info(out, Level::Error, pkg, "epoch-tag", &[&e.to_string()]);
                }
                if self.use_epoch && e > 99 {
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
        // Devel packages whose name does not end in the devel keyword
        // must not trip devel-dependency or explicit-lib-dependency
        // (the reference only matches the suffix form):
        // - biarch/flavored packages carry the keyword as a
        //   hyphen-delimited component (`-devel-32bit`, `-devel-doc`,
        //   `-debug-libs`, ...); the reference misfires on 242 such
        //   packages in Tumbleweed;
        // - pattern packages append the flavour to the component with
        //   an underscore instead (`patterns-kde-devel_qt5`). The
        //   underscore form is credited only for `patterns-*` names:
        //   elsewhere a keyword-underscore component can be part of an
        //   ordinary word (`ruby4.0-rubygem-debug_inspector`);
        // - JDK `*-jmods` packages are the JDK's development modules,
        //   split out of the corresponding `-devel` package.
        // The dependency-side class from plusky/rpmcrab#283 is handled
        // per leaf in the devel-dependency predicate below.
        let requirer_is_component_devel = is_match(devel_infix_regex(), &pkg.name)
            || (pkg.name.starts_with("patterns-") && is_match(devel_underscore_regex(), &pkg.name))
            || pkg.name.ends_with("-jmods");
        // The requirer-side half of the cross-family credit (#861),
        // classified once per package: the per-leaf test then only
        // parses the leaf.
        let family_requirer = family_requirer(&pkg.name);
        // The generated-soname package-name sets are consulted only
        // by the explicit-lib-dependency predicate, and only for a
        // leaf that passes that predicate's decidable guards; they
        // are built on the first such leaf rather than for every
        // package (#888). The second set is the self-provided credit.
        let mut generated_lib_names: Option<(
            std::collections::HashSet<String>,
            std::collections::HashSet<String>,
        )> = None;
        for dep in deps {
            let value = format_require(dep);
            // Rich `(a or b)` expressions (RPM >= 4.13): run the name and
            // version analyses against each referenced leaf instead of the
            // raw expression string. A plain dependency yields exactly one
            // leaf identical to the dep itself, so behavior is unchanged.
            for leaf in dep.leaves() {
                let leaf_value = leaf.display();
                if self.use_epoch
                    && leaf.version.is_some()
                    && leaf.epoch.is_none()
                    && !leaf.name.starts_with("rpmlib(")
                {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "no-epoch-in-dependency",
                        &[&leaf_value],
                    );
                }
                // Issue #1443/#1444: check every requirement, not just the first.
                for req in &self.invalid_requires {
                    if is_match(req, &leaf.name) {
                        add_info(out, Level::Error, pkg, "invalid-dependency", &[&leaf.name]);
                    }
                }
                if leaf.name.starts_with("/usr/local/") {
                    add_info(out, Level::Error, pkg, "invalid-dependency", &[&leaf.name]);
                }
                if !is_source && !is_devel {
                    // Same-family cross pairs are credited (issue #861):
                    // a cross toolchain's own target sys-root devel
                    // package is the toolchain's runtime data, not a
                    // host devel dependency. The credit is per leaf, so
                    // a credited leaf does not consume the latch: a
                    // later uncredited devel requirement still fires.
                    // Two more per-leaf credits:
                    // - a `python3<NN>-*-headers` leaf is a runtime
                    //   Python module, not a header package (issue
                    //   #283, upstream rpmlint #1091: e.g.
                    //   python313-django-cors-headers ships only .py
                    //   files); interpreter headers live in
                    //   `python3<NN>-devel`;
                    // - a `*-rebuild` package is an empty anchor whose
                    //   single requirement exists to trigger rebuilds;
                    //   its `-source` requirement (the source tree it
                    //   rebuilds against, e.g. perf-rebuild on
                    //   kernel-source) is the package's purpose.
                    if !devel_depend
                        && !requirer_is_component_devel
                        && is_match(&self.devel_re, &leaf.name)
                        && !family_requirer.credits(&leaf.name)
                        && !python_module_headers_leaf(&leaf.name)
                        && !rebuild_source_anchor(&pkg.name, &leaf.name)
                    {
                        add_info(out, Level::Error, pkg, "devel-dependency", &[&leaf.name]);
                        devel_depend = true;
                    }
                    // Deliberate narrowing of the #1091 fuzzy lib heuristic:
                    // the reference's unanchored suffix alternative fires on
                    // any name ending in "lib" (e.g. appstream-glib), which
                    // is not a library. openSUSE names library packages
                    // lib*, so only lib*-prefixed names count here; this
                    // knowingly silences non-lib* true positives like
                    // Requires: zlib, where the reference is right.
                    // Component-shaped devel requirers are devel packages,
                    // so their lib requirements must not trip this either.
                    // Capability names are not library package names either
                    // (#753): symbol capabilities in the SUSE
                    // lib<name>__<symbol> namespace (libuuid1 provides
                    // libuuid__uuid_generate_time_cont, which uuidd
                    // requires to restart against the new libuuid after an
                    // update — a deliberate ABI pin, not a package rpm
                    // should be left to find), and qualified capabilities
                    // such as libzypp(econf) or libclc(llvm23). The
                    // separators are decidable: plain library package
                    // names contain neither "__" nor "(", and carry no
                    // qualifier — the qualifier reaches the check
                    // structured on the leaf, so a capability embedded
                    // in a rich expression is recognised the same way
                    // as a top-level one. The reference fires on both
                    // forms.
                    // The harm the finding names is redundancy (#851):
                    // an explicit requirement is only unneeded when the
                    // package's own binaries already generate a soname
                    // dependency on the same library. The generated
                    // dependencies sit in the same header (marked
                    // RPMSENSE_FIND_REQUIRES) and the library package
                    // they belong to follows the shared-library naming
                    // convention, so the duplication is decidable here:
                    // the explicit name must be a conventional package
                    // name for one of the generated sonames. Everything
                    // else is load-bearing: ctypes-loaded libraries
                    // generate no soname dependency at all, and tool,
                    // data and flavour companion packages (-tools,
                    // -data, libopenblas_pthreads0) are not the
                    // conventional name of the library they accompany,
                    // so they stay silent. The reference fires on all
                    // of them.
                    // A generated soname dependency the package itself
                    // provides is not a dependency on the library
                    // package: rpm resolves it against the package's
                    // own provides, so an explicit requirement naming
                    // that package is the only expression of it and
                    // cannot duplicate the generated one (the
                    // libptscotch MPI flavours ship the serial
                    // libscotch in their own prefix, provide its
                    // soname, and still name libscotch7_0 for the
                    // system copy). Names derived only from such
                    // self-provided sonames are credited.
                    if !requirer_is_component_devel
                        && leaf.flags == 0
                        && leaf.qualifier.is_none()
                        && !leaf.name.contains("__")
                        && !leaf.name.contains('(')
                    {
                        let generated_lib_names = generated_lib_names.get_or_insert_with(|| {
                            generated_soname_package_names(deps, &pkg.provides)
                        });
                        if generated_lib_names.0.contains(leaf.name.as_str())
                            && !generated_lib_names.1.contains(leaf.name.as_str())
                            && let Ok(Some(caps)) = self.lib_package_re.captures(&leaf.name)
                            && caps.get(1).is_none()
                        {
                            add_info(
                                out,
                                Level::Error,
                                pkg,
                                "explicit-lib-dependency",
                                &[&leaf.name],
                            );
                        }
                    }
                }
            }
            self.unexpanded_macro(out, pkg, &format!("dependency {value}"), &value);
        }
    }
}

/// The library package names this package's own generated (find-requires)
/// dependencies already reach, under the openSUSE shared-library naming
/// convention — the full-version mapping BinariesCheck's shlib-policy
/// guard uses: stem and version dots fold to underscores, so
/// `libfoo.so.10.0.0` is provided by `libfoo10_0_0` (or `libfoo-10_0_0`),
/// `libgame2-1.9.so.10.0.0` by `libgame2-1_9-10_0_0`, and a version
/// carried in the stem alone (`libdb-4.8.so`) by `libdb-4_8`. The
/// major-only form is not a candidate: `libfoo10` is not a name the
/// mapping derives from `libfoo.so.10.0.0`. Computed from the package's
/// own header alone — generated dependencies carry
/// `RPMSENSE_FIND_REQUIRES`, explicit ones do not — so no cross-package
/// data is needed. The bare `lib<stem>` form is deliberately not a
/// candidate: it names a different package in practice (the `libnbd`
/// tools package vs the `libnbd0` library package), so it proves
/// nothing about redundancy.
/// The second returned set is the self-provided credit: package
/// names whose every deriving generated soname is among the package's
/// own provides, so the generated dependency resolves against the
/// package itself and never reaches the named library package.
fn generated_soname_package_names(
    deps: &[DepInfo],
    provides: &[DepInfo],
) -> (
    std::collections::HashSet<String>,
    std::collections::HashSet<String>,
) {
    let mut names = std::collections::HashSet::new();
    let mut self_names = std::collections::HashSet::new();
    let mut external_names = std::collections::HashSet::new();
    let provide_names: std::collections::HashSet<&str> =
        provides.iter().map(|d| d.name.as_str()).collect();
    for dep in deps {
        if dep.flags & RPMSENSE_FIND_REQUIRES == 0 {
            continue;
        }
        // A generated soname dependency carries its arch qualifier in
        // the name (`libfoo.so.1()(64bit)`); the soname ends before it.
        let soname = dep.name.split('(').next().unwrap_or("");
        let Some((head, tail)) = soname.split_once(".so") else {
            continue;
        };
        if !head.starts_with("lib") || head == "lib" {
            continue;
        }
        let stem = head.replace('.', "_");
        // A trailing `-<version>` segment of the head is the package
        // version the SLPP construction folds into the stem
        // (`libdb-4.8`, `libgame2-1.9`); a trailing segment that does
        // not start with a digit is part of the stem's own name.
        let pkgversion = head.rsplit_once('-').and_then(|(_, segment)| {
            (segment.starts_with(|c: char| c.is_ascii_digit())
                && segment.chars().all(|c| c.is_ascii_digit() || c == '.'))
            .then_some(segment)
        });
        // The soversion after `.so`, when present, is a dotted digit
        // run; its package form folds the dots to underscores.
        let soversion = tail.strip_prefix('.').and_then(|rest| {
            let version: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect::<String>()
                .trim_end_matches('.')
                .to_string();
            (!version.is_empty()).then(|| version.replace('.', "_"))
        });
        let mut derived: Vec<String> = Vec::new();
        match (pkgversion, soversion) {
            // `libfoo.so.10.0.0` -> `libfoo10_0_0`, `libfoo-10_0_0`.
            (None, Some(version)) => {
                derived.push(format!("{stem}{version}"));
                derived.push(format!("{stem}-{version}"));
            }
            // `libgame2-1.9.so.10.0.0` -> `libgame2-1_9-10_0_0`: with a
            // package version in the stem the SLPP form is the dash one.
            (Some(_), Some(version)) => {
                derived.push(format!("{stem}-{version}"));
            }
            // `libdb-4.8.so` -> `libdb-4_8`: the stem already carries
            // the whole version.
            (Some(_), None) => {
                derived.push(stem);
            }
            // A version-less soname (`libfoo.so`) names no package.
            (None, None) => {}
        }
        // A generated dependency whose raw name is among the package's
        // own provides resolves against the package itself, not
        // against the library package the derived names belong to.
        if provide_names.contains(dep.name.as_str()) {
            self_names.extend(derived.iter().cloned());
        } else {
            external_names.extend(derived.iter().cloned());
        }
        names.extend(derived);
    }
    // The credit set: names whose every deriving generated soname is
    // self-provided. A name also derived from an external soname is
    // not credited: that soname's dependency does reach the library
    // package, so an explicit requirement on it still duplicates.
    let credit: std::collections::HashSet<String> =
        self_names.difference(&external_names).cloned().collect();
    (names, credit)
}

/// The sys-root leaf of a `cross-...` package name: the target and
/// libc of a `cross-<target>-<libc>-devel` package, where the libc
/// component is `glibc` or `newlib` — the target C libraries whose
/// devel package is a cross toolchain's sys-root. Any other
/// `cross-...` devel-matching name (`-foo-devel`, `-foo-static`,
/// `-binutils-devel`, the compiler's own `-devel`) is an ordinary
/// devel requirement, not a sys-root leaf.
fn cross_sysroot_leaf(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix("cross-")?;
    for libc in ["glibc", "newlib"] {
        if let Some(target) = rest.strip_suffix(&format!("-{libc}-devel")) {
            return (!target.is_empty()).then_some((target, libc));
        }
    }
    None
}

/// The target of a `cross-<target>-<tool...>` compiler package name:
/// the components before the tool component, where the tool is the
/// first `gcc` / `gcc<version>` component. Tool names may carry
/// further components (`gcc13-bootstrap`), so the target is what
/// precedes the tool, not all but the last component. A cross
/// package with no gcc tool component (a target runtime package,
/// binutils, ...) is not a compiler requirer here.
fn cross_compiler_target(name: &str) -> Option<String> {
    let rest = name.strip_prefix("cross-")?;
    let components: Vec<&str> = rest.split('-').collect();
    let tool = components.iter().position(|c| {
        c.strip_prefix("gcc")
            .is_some_and(|v| v.is_empty() || v.bytes().all(|b| b.is_ascii_digit()))
    })?;
    (tool > 0).then(|| components[..tool].join("-"))
}

/// The MinGW family of a package name: `mingw32` or `mingw64`, the
/// bitness component both sides of a MinGW pair carry first.
fn mingw_family(name: &str) -> Option<&str> {
    let first = name.split('-').next()?;
    (name.contains('-') && (first == "mingw32" || first == "mingw64")).then_some(first)
}

/// Whether `leaf` is a `python3<NN>-*-headers` name. In the
/// versioned-Python namespace such a name is a runtime Python module
/// (e.g. `python313-django-cors-headers` ships only `.py` files), not a
/// header package; the interpreter's headers live in `python3<NN>-devel`.
fn python_module_headers_leaf(leaf: &str) -> bool {
    let Some(rest) = leaf.strip_prefix("python3") else {
        return false;
    };
    let digits = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
    digits > 0 && rest[digits..].starts_with('-') && leaf.ends_with("-headers")
}

/// Whether `requirer` is a `*-rebuild` anchor package and `leaf` the
/// `-source` tree it triggers rebuilds against (e.g. `perf-rebuild`
/// on `kernel-source`).
fn rebuild_source_anchor(requirer: &str, leaf: &str) -> bool {
    requirer.ends_with("-rebuild") && leaf.ends_with("-source")
}

/// The requirer-side half of the cross-family credit (issue #861),
/// classified once per package, so the per-leaf test only parses
/// the leaf.
enum FamilyRequirer {
    /// A cross compiler package: the target it builds for, with any
    /// trailing `-elf` component stripped, and the libc the pair
    /// carries — `Some` only for the `-elf` spelling, which is
    /// the newlib toolchain.
    Cross {
        target: String,
        libc: Option<&'static str>,
    },
    /// A MinGW package: its bitness family (`mingw32` or `mingw64`).
    Mingw(String),
    /// A package of neither family.
    Neither,
}

/// Classify a package name as a cross-family requirer: a cross
/// compiler (`cross-<target>-gcc...`, the tool may carry further
/// components, `gcc13-bootstrap`) or a MinGW package.
fn family_requirer(name: &str) -> FamilyRequirer {
    if name.starts_with("cross-") {
        return match cross_compiler_target(name) {
            Some(target) => {
                let elf_base = target.strip_suffix("-elf").map(str::to_string);
                match elf_base {
                    Some(base) => FamilyRequirer::Cross {
                        target: base,
                        libc: Some("newlib"),
                    },
                    None => FamilyRequirer::Cross { target, libc: None },
                }
            }
            None => FamilyRequirer::Neither,
        };
    }
    match mingw_family(name) {
        Some(family) => FamilyRequirer::Mingw(family.to_string()),
        None => FamilyRequirer::Neither,
    }
}

impl FamilyRequirer {
    /// Whether `leaf` is this requirer's target sys-root devel
    /// package (issue #861). The `devel-dependency` harm model is a
    /// runtime package dragging host development files onto end
    /// systems; within one cross toolchain family the direction is
    /// reversed, because the target sys-root devel package is the
    /// compiler's runtime data.
    ///
    /// The credit is narrow — a genuine sys-root leaf only:
    /// - For a cross requirer the leaf is that target's sys-root
    ///   package, `cross-<target>-<libc>-devel` with libc `glibc` or
    ///   `newlib`. The bare-metal `-elf` spelling (the measured
    ///   family is riscv64-elf) spells the target with a trailing
    ///   `-elf` component the sys-root packages drop (riscv64-elf
    ///   pairs with riscv64); the strip mirrors that leaf-side
    ///   spelling, so it applies by spelling, not by measured
    ///   family, and `-none` is never stripped — the sys-root
    ///   packages keep it in the target
    ///   (`cross-arm-none-newlib-devel`), so an `arm` leaf never
    ///   pairs with an `arm-none` requirer. The `-elf` spelling is
    ///   the newlib toolchain, so for `-elf` requirers the libc is
    ///   part of the pair: the stripped form credits only a newlib
    ///   leaf, and `cross-riscv64-elf-gcc13` on
    ///   `cross-riscv64-glibc-devel` keeps firing. A requirer name
    ///   without the `-elf` spelling carries no libc component, so
    ///   its matching is on the target alone and either libc leaf
    ///   on that target credits: `cross-riscv64-gcc13` on
    ///   `cross-riscv64-newlib-devel` stays silent alongside its
    ///   glibc leaf. Both libc spellings occur among the
    ///   non-`-elf` families (glibc for the Linux targets, newlib
    ///   for amdgcn, arm-none, nvptx and rx), so the target alone
    ///   is the decidable predicate there; the collision is pinned
    ///   by `devel_dependency_cross_family_non_elf_libc_collision_is_silent`.
    /// - MinGW requirers pair only with the same bitness family's
    ///   sys-root leaves: `<bitness>-headers` and
    ///   `<bitness>-winpthreads-devel`.
    ///
    /// Everything else keeps firing: any other same-target devel
    /// match (a library's `-devel`/`-static`, binutils-devel, the
    /// compiler's own devel package), a runtime package requiring
    /// its own devel package, a different target's sys-root devel
    /// package, the wrong libc's sys-root package for an `-elf`
    /// requirer, a host devel package required by a cross package, a
    /// cross devel package required by a host package, a cross
    /// requirer on a MinGW leaf, a MinGW requirer on a cross leaf,
    /// and the other MinGW bitness.
    fn credits(&self, leaf: &str) -> bool {
        match self {
            FamilyRequirer::Cross { target, libc } => {
                let Some((leaf_target, leaf_libc)) = cross_sysroot_leaf(leaf) else {
                    return false;
                };
                target.as_str() == leaf_target && libc.is_none_or(|l| l == leaf_libc)
            }
            FamilyRequirer::Mingw(family) => {
                mingw_family(leaf) == Some(family.as_str())
                    && (leaf == format!("{family}-headers")
                        || leaf == format!("{family}-winpthreads-devel"))
            }
            FamilyRequirer::Neither => false,
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
    // `foo = 1:3.0.0` matches `foo = 1:3.0.0-15`. (#1599 returns false
    // before this matters for EQ/LE requirements at or below the
    // provider; the drop bites for the other flag shapes.)
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
                    r"^(lib)?{}(\-libs)?[\d_-]*(\(\w+\-\d+\))?$",
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
                let version = pkg.tag_str(Tag::VERSION).unwrap_or_default();
                let epoch: Option<i64> = pkg.tag_i64(Tag::EPOCH);
                if let (Some(dep), true) = (dep_match, !version.is_empty()) {
                    let exp = (epoch, Some(version.as_str()), None);
                    let sexp = version_to_string(exp.0, exp.1, exp.2);
                    // A lower bound at an ancestor version is not a pin to
                    // a different version: the same-build library satisfies
                    // it, and the bound names the base version the package
                    // version extends with a further dot component.
                    let lower_bound_at_ancestor = dep.epoch == epoch
                        && dep.flags & RPMSENSE_GREATER != 0
                        && dep.flags & RPMSENSE_LESS == 0
                        && dep.version.as_deref().is_some_and(|v| {
                            !v.is_empty()
                                && version
                                    .strip_prefix(v)
                                    .is_some_and(|rest| rest.starts_with('.'))
                        });
                    if dep.flags == 0 {
                        add_info(
                            out,
                            Level::Warning,
                            pkg,
                            "no-version-dependency-on",
                            &[&base_or_libs, &sexp],
                        );
                    } else if (dep.epoch, dep.version.as_deref()) != (exp.0, exp.1)
                        && !lower_bound_at_ancestor
                    {
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
                let s = pkg.tag_i18n_str(Tag::SUMMARY, lang);
                self.check_summary(pkg, out, &s, lang, ignored);
            }
        }
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
        // Spellcheck via `spellbook`; skipped in mini-mode (checker is
        // None) and for languages the checker has no dictionary for.
        if let Some(checker) = &self.spellchecker
            && crate::spellcheck::spellcheckable_language(lang)
        {
            for (word, suggestions) in checker.check(summary, &pkg.name, ignored) {
                let sug = if suggestions.is_empty() {
                    String::new()
                } else {
                    format!(" -> {}", suggestions.join(", "))
                };
                let detail = format!("Summary({lang}) {word}{sug}");
                add_info(out, Level::Warning, pkg, "spelling-error", &[&detail]);
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
        // A trailing possessive matches a listed brand ("wxWidgets's"
        // -> "wxWidgets"). The stripped form is not consulted for
        // article bases (a/an/the), so "a's"/"an's"/"the's" still warn
        // as the reference does.
        let first_word_base = first_word.strip_suffix("'s").unwrap_or(first_word);
        let stripped_exempt = !matches!(first_word_base, "a" | "an" | "the")
            && CAPITALIZED_IGNORE_LIST.contains(&first_word_base);
        // Reference parity: `summary[0] != summary[0].upper()` warns only
        // when the first char is actually lowercase; digits and other
        // non-letters never warn. Unicode titlecase letters (e.g. U+01C5)
        // warn too, so compare against the uppercase form rather than
        // `is_lowercase()`.
        let lowercase_first = summary
            .chars()
            .next()
            .map(|c| c.to_uppercase().next() != Some(c))
            .unwrap_or(false);
        if lowercase_first && !CAPITALIZED_IGNORE_LIST.contains(&first_word) && !stripped_exempt {
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
        // The reference counts characters (Python `len` on a str), not
        // UTF-8 bytes; a multibyte summary measures the same here.
        if summary.chars().count() > self.max_line_len {
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
                let d = pkg.tag_i18n_str(Tag::DESCRIPTION, lang);
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
        // Spellcheck via `spellbook`; skipped in mini-mode (checker is
        // None) and for languages the checker has no dictionary for.
        if let Some(checker) = &self.spellchecker
            && crate::spellcheck::spellcheckable_language(lang)
        {
            for (word, suggestions) in checker.check(description, &pkg.name, ignored) {
                let sug = if suggestions.is_empty() {
                    String::new()
                } else {
                    format!(" -> {}", suggestions.join(", "))
                };
                let detail = format!("%description -l {lang} {word}{sug}");
                add_info(out, Level::Warning, pkg, "spelling-error", &[&detail]);
            }
        }
        let lang_err = Self::lang_for_error(lang);
        for line in description.split('\n') {
            // Strip a trailing \r for length purposes? The reference uses
            // splitlines() which strips all line boundaries; len() is on the
            // stripped line and counts characters (codepoints), not UTF-8
            // bytes.
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.chars().count() > self.max_line_len {
                let mut d: Vec<&str> = Vec::new();
                if let Some(l) = lang_err {
                    d.push(l);
                }
                d.push(line);
                add_info(out, Level::Warning, pkg, "description-line-too-long", &d);
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
        // Group tag itself is obsolete (openSUSE dropped it); only the
        // generic unexpanded-macro probe remains.
        self.unexpanded_macro(out, pkg, "Group", group);
    }

    fn check_buildhost(&self, pkg: &Pkg, out: &mut Filter, buildhost: &str) {
        self.unexpanded_macro(out, pkg, "BuildHost", buildhost);
        if buildhost.is_empty() {
            add_info(out, Level::Error, pkg, "no-buildhost-tag", &[]);
        }
    }
}

impl TagsCheck {
    /// Upstream rpmlint#180: bot accounts (e.g. `opensuse-packaging@`)
    /// in changelog authors hide who to contact and can generate list
    /// mail. One warning per offending entry.
    fn check_changelog_authors(&self, pkg: &Pkg, out: &mut Filter, changelog: &[String]) {
        if self.invalid_changelog_authors.is_empty() {
            return;
        }
        for entry in changelog {
            if self
                .invalid_changelog_authors
                .iter()
                .any(|re| is_match(re, entry))
            {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "invalid-changelog-author",
                    &[entry],
                );
            }
        }
    }

    fn check_changelog(&self, pkg: &Pkg, out: &mut Filter, changelog: &[String]) {
        if changelog.is_empty() {
            add_info(out, Level::Error, pkg, "no-changelogname-tag", &[]);
            return;
        }
        self.check_changelog_authors(pkg, out, changelog);
        let clt: Vec<String> = pkg.tag_str_array(Tag::CHANGELOGTEXT);
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
        let times = pkg.tag_int32_array(Tag::CHANGELOGTIME);
        if let Some(&first) = times.first() {
            // Roll back 26h to cover timezone differences, mirroring the
            // reference (TagsCheck.py): the largest tz gap is 26h (Howland
            // Islands vs Line Islands). Both comparisons below use the
            // rolled-back value.
            let clt_time = first as i64 - 26 * 3600;
            if clt_time < OLDEST_CHANGELOG_TIMESTAMP {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "changelog-time-overflow",
                    &[&format_date(clt_time)],
                );
            } else {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                if changelog_in_future(first as i64, now) {
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

    /// Split a license expression into the leaf pieces the validator
    /// checks. The cut points are the reference's (`license_regex`:
    /// parentheses and whitespace-surrounded `and`/`or`/`AND`/`OR`), but a
    /// parenthesis cuts at any depth: the reference's `\(([^)]+)\)` group
    /// alternative stops at the first `)`, so a nested group leaks
    /// fragments of its inner text (`(GPL-2.0-only`, a bare `)`) as pieces
    /// of their own (issue #864). Here the pieces of a nested expression
    /// are the bare leaves inside it, however deep the nesting goes.
    ///
    /// Pieces are stripped and empties dropped, like the reference's
    /// `split_license`. A bare `()` survives as a literal piece (the
    /// reference reports `invalid-license ()` for it); a whitespace-only
    /// group vanishes, like the reference's empty-split filtering. When no
    /// piece survives at all -- an expression of only parentheses and
    /// operators -- the expression is kept whole as one piece so malformed
    /// input is reported rather than silently accepted; the single
    /// exception is the whitespace-only group, which the reference drops.
    ///
    /// Iterative and linear, so adversarial nesting terminates instead of
    /// hanging.
    fn split_license(text: &str) -> Vec<String> {
        let mut parts: Vec<&str> = Vec::new();
        let mut start = 0usize;
        let mut i = 0usize;
        while i < text.len() {
            let rest = &text[i..];
            // A bare `()` is a literal piece, not a group.
            if rest.starts_with('(') && rest[1..].starts_with(')') {
                parts.push(text[start..i].trim());
                parts.push("()");
                i += 2;
                start = i;
                continue;
            }
            if rest.starts_with('(') || rest.starts_with(')') {
                parts.push(text[start..i].trim());
                i += 1;
                start = i;
                continue;
            }
            // `\s(?:and|or|AND|OR)\s`
            let mut advanced = false;
            if let Some((_, c)) = rest.char_indices().next()
                && c.is_whitespace()
            {
                let after_ws = &rest[c.len_utf8()..];
                for op in ["and", "or", "AND", "OR"] {
                    if let Some(after_op) = after_ws.strip_prefix(op)
                        && let Some((_, tc)) = after_op.char_indices().next()
                        && tc.is_whitespace()
                    {
                        parts.push(text[start..i].trim());
                        i += c.len_utf8() + op.len() + tc.len_utf8();
                        start = i;
                        advanced = true;
                        break;
                    }
                }
            }
            if !advanced {
                i += rest.chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            }
        }
        parts.push(text[start..].trim());
        let pieces: Vec<String> = parts
            .into_iter()
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect();
        if !pieces.is_empty() {
            return pieces;
        }
        // Nothing survived: report the expression whole unless it is the
        // whitespace-only group the reference drops.
        let trimmed = text.trim();
        let inner = trimmed.strip_prefix('(').and_then(|t| t.strip_suffix(')'));
        let whitespace_only_group =
            matches!(inner, Some(inner) if !inner.contains('(') && inner.trim().is_empty());
        if trimmed.is_empty() || whitespace_only_group {
            Vec::new()
        } else {
            vec![trimmed.to_string()]
        }
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
        // Did-you-mean suggestions are the port's own Info finding, not the
        // reference's: cap them per package so a pathological License tag
        // with thousands of invalid ids cannot burn minutes in edit-distance
        // computation. The invalid-license findings themselves are untouched.
        let mut spellchecks_emitted = 0;
        const MAX_SPELLCHECK_SUGGESTIONS: usize = 10;
        if !self.valid_licenses.contains(&rpm_license.to_string()) {
            // Each piece the split yields is a bare leaf and is validated
            // on its own. Deliberate asymmetry, not parity: the
            // WITH-exception match runs per piece, so on the WITH
            // dimension it reports strictly more than the reference, in
            // the safer direction. The reference matches it against the
            // whole string and then validates only the pre-WITH part,
            // silently dropping sibling pieces (see divergences.toml).
            for piece in Self::split_license(rpm_license) {
                let (lic, lexception) = self.split_license_exception(&piece);
                // SPDX allows "<license> WITH <license-exception>"
                if !lexception.is_empty() && !self.valid_license_exceptions.contains(&lexception) {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "invalid-license-exception",
                        &[&lexception],
                    );
                    valid_license = false;
                }
                let lic = if lexception.is_empty() { piece } else { lic };
                if lic.is_empty() || self.valid_licenses.contains(&lic) {
                    continue;
                }
                // An error outright (issue #699): a license string
                // that fails SPDX validation is a legal metadata
                // defect in itself. The reference emits W; the port
                // previously reached E only via shipped scoring
                // (issue #594). Near-miss spellings are the separate
                // I-level spellcheck tag's job.
                add_info(out, Level::Error, pkg, "invalid-license", &[&lic]);
                if spellchecks_emitted < MAX_SPELLCHECK_SUGGESTIONS {
                    spellchecks_emitted += 1;
                    let suggestions = suggest_licenses(&lic, 3);
                    if !suggestions.is_empty() {
                        add_info(
                            out,
                            Level::Info,
                            pkg,
                            "invalid-license-spellcheck",
                            &[&format!("{lic}: {}", suggestions.join(", "))],
                        );
                    }
                }
                valid_license = false;
            }
        }
        if !valid_license {
            self.unexpanded_macro(out, pkg, "License", rpm_license);
        }
    }

    fn check_url(&self, pkg: &Pkg, out: &mut Filter) {
        for (tagname, tag) in [
            ("URL", Tag::URL),
            ("DistURL", Tag::DISTURL),
            ("BugURL", Tag::BUGURL),
        ] {
            let url = pkg.tag_str(tag).unwrap_or_default();
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

    fn obs_build_mut(&mut self, key: &str) -> &mut ObsoleteBuild {
        if !self.obs_builds.contains_key(key) {
            self.obs_order.push(key.to_string());
            self.obs_builds
                .insert(key.to_string(), ObsoleteBuild::default());
        }
        self.obs_builds.get_mut(key).expect("just inserted")
    }

    /// Record one package's contribution to the run-scoped
    /// `obsolete-not-provided` verdict: a source package opens its
    /// build's gate; a binary package contributes its Provides names
    /// and the Obsoletes its own Provides do not carry as candidates.
    fn accumulate_obsolete(&mut self, pkg: &Pkg) {
        if pkg.is_source {
            for key in source_package_keys(pkg) {
                self.obs_sources.insert(key);
            }
            return;
        }
        let own: HashSet<&str> = pkg.provides.iter().map(|d| d.name.as_str()).collect();
        let candidates: Vec<ObsoleteCandidate> = pkg
            .obsoletes
            .iter()
            .filter(|obs| !own.contains(obs.name.as_str()))
            .map(|obs| ObsoleteCandidate {
                pkg_name: pkg.name.clone(),
                arch: pkg.arch.clone(),
                name: obs.name.clone(),
            })
            .collect();
        match binary_source_key(pkg) {
            Some(key) => {
                let build = self.obs_build_mut(&key);
                build
                    .provides
                    .extend(pkg.provides.iter().map(|d| d.name.clone()));
                build.candidates.extend(candidates);
            }
            None => self.obs_unkeyed.extend(candidates),
        }
    }

    fn check_obsolete_not_provided(&self, pkg: &Pkg, out: &mut Filter, prov_names: &[&str]) {
        for obs in &pkg.obsoletes {
            // Plain names: rpm rejects rich dependencies in both Obsoletes
            // and Provides (`No rich dependencies allowed for this type`),
            // so leaf expansion is unreachable here.
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
        // EVRs per name, as the parsed (epoch, version, release) tuple
        // (both sides were built with `string_to_version`) — no
        // `evr_string()` allocation. The check fires only when a name
        // appears in both unversioned and versioned form.
        type Evr<'a> = (Option<i64>, Option<&'a str>, Option<&'a str>);
        fn evr_of(prov: &DepInfo) -> Evr<'_> {
            (prov.epoch, prov.version.as_deref(), prov.release.as_deref())
        }
        fn is_unversioned(evr: &Evr) -> bool {
            evr.0.is_none() && evr.1.is_none()
        }
        let mut pkg_evrs: std::collections::BTreeMap<&str, std::collections::BTreeSet<Evr>> =
            Default::default();
        for prov in &pkg.provides {
            if prov.name.starts_with("debuginfo(") {
                continue;
            }
            pkg_evrs
                .entry(prov.name.as_str())
                .or_default()
                .insert(evr_of(prov));
        }
        let candidates: Vec<&str> = pkg_evrs
            .iter()
            .filter(|(_, evrs)| {
                evrs.iter().any(is_unversioned) && evrs.iter().any(|e| !is_unversioned(e))
            })
            .map(|(name, _)| *name)
            .collect();
        if candidates.is_empty() {
            // No duplicated name: skip the FILEPROVIDE walk entirely.
            return;
        }
        // Generator attribution, from the header's per-file provides
        // (FILEPROVIDE): the dependency generators record the provides
        // they derived from each shipped file. Attribution is per
        // (name, EVR): a pair is the generator's doing only when every
        // EVR the package carries for the name is file-covered, so a
        // hand-written `perl(Foo) = 2.0` alongside a generated
        // `perl(Foo) = 1.0` stays an error. Generator
        // pairs are warnings; a duplicate
        // involving a manual provide stays an error.
        let mut gen_evrs: std::collections::BTreeMap<&str, std::collections::BTreeSet<Evr>> =
            Default::default();
        for file in &pkg.files {
            for prov in &file.provides {
                gen_evrs
                    .entry(prov.name.as_str())
                    .or_default()
                    .insert(evr_of(prov));
            }
        }
        for name in candidates {
            let generated = gen_evrs
                .get(name)
                .is_some_and(|file_evrs| pkg_evrs[name].iter().all(|evr| file_evrs.contains(evr)));
            if generated {
                add_info(out, Level::Warning, pkg, "useless-provides", &[name]);
            } else {
                add_info(out, Level::Error, pkg, "useless-provides", &[name]);
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

    /// A versioned Obsoletes entry that matches a Provides entry of the same
    /// name without reaching beyond the provided EVR is the documented
    /// package-merge pattern (e.g. `Provides: foo = 1.6.1` with
    /// `Obsoletes: foo <= 1.6.1`) and is not reported.
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

/// Whether a changelog timestamp is in the future, after the reference's
/// 26h timezone rollback (TagsCheck.py). `now` is a parameter so the rollback
/// stays unit-testable without depending on the wall clock.
fn changelog_in_future(changelog_time: i64, now: i64) -> bool {
    changelog_time - 26 * 3600 > now
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
    fn check(&mut self, pkg: &Pkg, config: &Config, out: &mut Filter) {
        // `-v`/`--explain` descriptions, mirroring the reference's
        // `__init__` dict which installs them unconditionally.
        Self::register_error_details(config, out);
        self.run(pkg, out);
        self.accumulate_obsolete(pkg);
    }

    /// The deferred `obsolete-not-provided` verdict: a candidate is
    /// credited only when its build is source-complete in this
    /// run -- the run holds the build's source package, and source
    /// presence is the whole gate: the build's full package closure
    /// is not checked -- and a package of the build provides the
    /// obsoleted name under its exact spelling. Every other
    /// candidate fires, so source-absent (partial) and
    /// single-package runs report exactly the per-package verdict.
    fn after_checks(&mut self, _config: &Config, out: &mut Filter) {
        for cand in &self.obs_unkeyed {
            emit_obsolete_not_provided(out, cand);
        }
        for key in &self.obs_order {
            let build = &self.obs_builds[key];
            let complete = self.obs_sources.contains(key);
            for cand in &build.candidates {
                if complete && build.provides.contains(&cand.name) {
                    continue;
                }
                emit_obsolete_not_provided(out, cand);
            }
        }
    }

    fn reset(&mut self) {
        self.obs_sources.clear();
        self.obs_order.clear();
        self.obs_builds.clear();
        self.obs_unkeyed.clear();
    }

    fn export_state(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        Some(Box::new(ObsoleteState {
            sources: std::mem::take(&mut self.obs_sources),
            order: std::mem::take(&mut self.obs_order),
            builds: std::mem::take(&mut self.obs_builds),
            unkeyed: std::mem::take(&mut self.obs_unkeyed),
        }))
    }

    fn import_state(&mut self, state: Box<dyn std::any::Any + Send>) {
        if let Ok(mut state) = state.downcast::<ObsoleteState>() {
            self.obs_sources.extend(state.sources.drain());
            self.obs_unkeyed.append(&mut state.unkeyed);
            for key in std::mem::take(&mut state.order) {
                let Some(data) = state.builds.remove(&key) else {
                    continue;
                };
                match self.obs_builds.get_mut(&key) {
                    Some(mine) => {
                        mine.provides.extend(data.provides);
                        mine.candidates.extend(data.candidates);
                    }
                    None => {
                        self.obs_order.push(key.clone());
                        self.obs_builds.insert(key, data);
                    }
                }
            }
        }
    }
}

/// Emit one deferred `obsolete-not-provided` finding, with the
/// package context the per-package emission derives.
fn emit_obsolete_not_provided(out: &mut Filter, cand: &ObsoleteCandidate) {
    out.add_info(make_finding(
        &cand.pkg_name,
        &cand.arch,
        Level::Warning,
        "obsolete-not-provided",
        vec![cand.name.clone()],
        None,
    ));
}

impl TagsCheck {
    /// `error_details` for `--explain`, mirroring the `__init__` dict
    /// (`TagsCheck.py:54-62`).
    pub fn register_error_details(config: &Config, out: &mut Filter) {
        let _tbl = &config.configuration;
        for tag in [
            "obsoletes",
            "conflicts",
            "provides",
            "recommends",
            "suggests",
            "enhances",
            "supplements",
        ] {
            // Python `str.capitalize()` on these lowercase tags.
            let capitalized = tag[..1].to_uppercase() + &tag[1..];
            out.set_error_detail(
                &format!("no-epoch-in-{tag}"),
                format!("Your package contains a versioned {capitalized} entry without an Epoch."),
            );
        }
    }
}

#[cfg(test)]
impl TagsCheck {
    /// Install the inline test-dictionary spellchecker for the
    /// spelling-error emission test. The Mac has no system hunspell
    /// dictionaries, so `Spellchecker::new()` finds nothing there; the
    /// inline dictionary (same words as spellcheck.rs's own tests) keeps
    /// the test hermetic on every machine.
    fn set_test_spellchecker(&mut self) {
        self.spellchecker = crate::spellcheck::Spellchecker::from_strings(
            "SET UTF-8\n",
            "5\nhello\nworld\ntest\npackage\ncheck\n",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;
    use std::path::Path;

    fn test_config() -> Config {
        test_config_with(None)
    }

    fn test_config_with(release_extension: Option<&str>) -> Config {
        // Minimal config with the keys TagsCheck reads.
        let mut config = Config::default();
        let tbl = &mut config.configuration;
        tbl.insert("UseEpoch".to_string(), toml::Value::Boolean(false));
        tbl.insert("MaxLineLength".to_string(), toml::Value::Integer(79));
        tbl.insert("ValidLicenses".to_string(), toml::Value::Array(vec![]));
        tbl.insert(
            "ValidLicenseExceptions".to_string(),
            toml::Value::Array(vec![]),
        );
        tbl.insert("InvalidRequires".to_string(), toml::Value::Array(vec![]));
        if let Some(ext) = release_extension {
            tbl.insert(
                "ReleaseExtension".to_string(),
                toml::Value::String(ext.to_string()),
            );
        }
        config.finalize().expect("fixture config");
        config
    }

    /// Open a fixture RPM, extracting into a unique tempdir (kept alive by
    /// the caller) rather than the shared `temp_dir()`: concurrent runs must
    /// not share one extraction directory.
    fn fixture_pkg(name: &str) -> (tempfile::TempDir, Pkg) {
        // Hand-built fixture RPMs in tests/parity/pkg/inputs/, not distro
        // packages. The llvm21-gold corpus is reserved for parity tests.
        let rpm_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs")
            .join(name);
        let tmp = tempfile::tempdir().expect("tmpdir for fixture extraction");
        let pkg = match Pkg::open(&rpm_path, tmp.path(), true) {
            Ok(pkg) => pkg,
            Err(e) => panic!("open fixture pkg {rpm_path:?}: {e:?}"),
        };
        (tmp, pkg)
    }

    fn run_check(pkg: &Pkg) -> Vec<(String, String)> {
        let config = test_config();
        run_check_with(&config, pkg)
    }

    fn run_check_with(config: &Config, pkg: &Pkg) -> Vec<(String, String)> {
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        let mut check = TagsCheck::new(config);
        check.check(pkg, config, &mut out);
        check.after_checks(config, &mut out);
        out.results().to_vec()
    }

    /// Run one check instance over several packages in order, then
    /// the deferred verdicts (`after_checks`).
    fn run_check_multi(config: &Config, pkgs: &[Pkg]) -> Vec<(String, String)> {
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        let mut check = TagsCheck::new(config);
        for pkg in pkgs {
            check.check(pkg, config, &mut out);
        }
        check.after_checks(config, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn tags_check_runs_on_fixture() {
        let (_tmp, pkg) = fixture_pkg("fcprobe-1-1.noarch.rpm");
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
                line.contains(": E: ") || line.contains(": W: ") || line.contains(": I: "),
                "level: {line}"
            );
        }
    }

    #[test]
    fn changelog_in_future_applies_tz_rollback() {
        let now = 1_700_000_000;
        // Up to 26h ahead of now is a timezone artifact, not a future date.
        assert!(!changelog_in_future(now + 3600, now));
        assert!(!changelog_in_future(now + 26 * 3600, now));
        // Beyond 26h is genuinely in the future.
        assert!(changelog_in_future(now + 26 * 3600 + 1, now));
        assert!(!changelog_in_future(now - 3600, now));
    }

    /// Copy a fixture RPM with its first CHANGELOGTIME rewritten, returning
    /// the tempdir (kept alive by the caller) and the patched path. The
    /// patched bytes live in a unique tempdir, never a fixed `temp_dir()`
    /// path: two concurrent runs must not share one file. The emission path
    /// reads the timestamp from the package header, which librpm exposes
    /// read-only, so the test patches the header bytes of a copy: lead (96B),
    /// signature header, then the main header's index entry for tag 1080
    /// (CHANGELOGTIME, INT32). Opening skips digest verification, so the
    /// in-place rewrite needs no fixup. The reference rejects the rewritten
    /// digests, so it cannot arbitrate these runs.
    fn patch_changelog_time(
        fixture: &str,
        new_time: i64,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        const TAG_CHANGELOGTIME: u32 = 1080;
        const TYPE_INT32: u32 = 4;
        let src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs")
            .join(fixture);
        let mut bytes = std::fs::read(&src).expect("read fixture rpm");
        assert_eq!(&bytes[0..4], b"\xed\xab\xee\xdb", "rpm lead magic");
        let u32_at = |off: usize| u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap());
        // Skip the signature header to the main header (8-byte aligned).
        let mut off = 96;
        assert_eq!(
            &bytes[off..off + 3],
            b"\x8e\xad\xe8",
            "signature header magic"
        );
        off += 16 + u32_at(off + 8) as usize * 16 + u32_at(off + 12) as usize;
        off = off.div_ceil(8) * 8;
        // Find CHANGELOGTIME in the main header index, rewrite its first value.
        assert_eq!(&bytes[off..off + 3], b"\x8e\xad\xe8", "main header magic");
        let count = u32_at(off + 8) as usize;
        let data = off + 16 + count * 16;
        let mut patched = false;
        for i in 0..count {
            let e = off + 16 + i * 16;
            if u32_at(e) == TAG_CHANGELOGTIME && u32_at(e + 4) == TYPE_INT32 {
                let at = data + u32_at(e + 8) as usize;
                bytes[at..at + 4].copy_from_slice(&(new_time as u32).to_be_bytes());
                patched = true;
                break;
            }
        }
        assert!(patched, "CHANGELOGTIME missing in {fixture}");
        let tmp = tempfile::tempdir().expect("tmpdir for patched rpm");
        // Keep the fixture's own filename.
        let rpm_path = tmp.path().join(fixture);
        std::fs::write(&rpm_path, &bytes).expect("write patched rpm");
        (tmp, rpm_path)
    }

    fn wall_now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock")
            .as_secs() as i64
    }

    /// The #126 fix, comparison half: 1h ahead of now is a timezone artifact,
    /// so the rolled-back comparison stays quiet through the real emission path.
    /// The positive control shares the emission code path: the same fixture
    /// patched 30h ahead must emit exactly one changelog-time-in-future. If
    /// the emission branch ever dies, the control fails instead of the quiet
    /// assertion passing vacuously.
    #[test]
    fn changelog_one_hour_ahead_emits_nothing() {
        let (_tmp, tmp) = patch_changelog_time("w6-tmpfiles-1.0-1.noarch.rpm", wall_now() + 3600);
        let pkg = Pkg::open_no_extract(&tmp).expect("open patched pkg");
        let results = run_check(&pkg);
        assert!(
            results
                .iter()
                .all(|(name, _)| name != "changelog-time-in-future"),
            "unexpected findings: {results:?}"
        );
        let (_tmp2, tmp2) =
            patch_changelog_time("w6-tmpfiles-1.0-1.noarch.rpm", wall_now() + 30 * 3600);
        let future_pkg = Pkg::open_no_extract(&tmp2).expect("open future pkg");
        let future_results = run_check(&future_pkg);
        let hits: Vec<_> = future_results
            .iter()
            .filter(|(name, _)| name.as_str() == "changelog-time-in-future")
            .collect();
        assert_eq!(hits.len(), 1, "positive control failed: {hits:?}");
    }

    /// The #126 fix, detail half: the emitted finding pins name, level and the
    /// rolled-back date. 30h ahead fires; the detail is the timestamp minus 26h.
    #[test]
    fn changelog_time_in_future_pins_name_level_and_detail() {
        let first = wall_now() + 30 * 3600;
        let (_tmp, tmp) = patch_changelog_time("w6-tmpfiles-1.0-1.noarch.rpm", first);
        let pkg = Pkg::open_no_extract(&tmp).expect("open patched pkg");
        let results = run_check(&pkg);
        let hits: Vec<_> = results
            .iter()
            .filter(|(name, _)| name.as_str() == "changelog-time-in-future")
            .collect();
        assert_eq!(hits.len(), 1, "expected one finding: {results:?}");
        // Whole-line pin: the package prefix, level letter, finding name and
        // rolled-back date in one assertion, so no added field goes unnoticed.
        assert_eq!(
            hits[0].1,
            format!(
                "w6-tmpfiles.noarch: E: changelog-time-in-future {}",
                format_date(first - 26 * 3600)
            ),
            "unexpected line"
        );
    }

    // Upstream rpmlint#180: bot/invalid changelog authors.
    fn authors_config(authors: &[&str]) -> Config {
        let mut config = test_config();
        config.configuration.insert(
            "InvalidChangelogAuthors".to_string(),
            toml::Value::Array(
                authors
                    .iter()
                    .map(|s| toml::Value::String(s.to_string()))
                    .collect(),
            ),
        );
        config
    }

    fn authors_fixture() -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/changelog-author-fixture-1.0-1.noarch.rpm");
        // Header only: the check reads CHANGELOGNAME, no payload needed.
        Pkg::open_no_extract(&rpm).expect("open fixture")
    }

    #[test]
    fn invalid_changelog_author_warns_on_bot_entries() {
        // The fixture carries two bot entries and one human entry.
        let config = authors_config(&[
            "opensuse-packaging@opensuse\\.org",
            "nobody@fedoraproject\\.org",
            "nobody@mageia\\.org",
            ".*@example\\.com",
        ]);
        let pkg = authors_fixture();
        let results = run_check_with(&config, &pkg);
        let hits: Vec<_> = results
            .iter()
            .filter(|(name, _)| name.as_str() == "invalid-changelog-author")
            .collect();
        assert_eq!(hits.len(), 2, "expected two findings: {results:?}");
        assert_eq!(
            hits[0].1,
            "changelog-author-fixture.noarch: W: invalid-changelog-author \
             openSUSE Packaging <opensuse-packaging@opensuse.org> - 1.0-1",
            "name, level and detail"
        );
        assert_eq!(
            hits[1].1,
            "changelog-author-fixture.noarch: W: invalid-changelog-author \
             Example Bot <bot@example.com> - 1.0-1",
            "name, level and detail"
        );
    }

    #[test]
    fn invalid_changelog_author_empty_list_is_quiet() {
        let config = authors_config(&[]);
        let pkg = authors_fixture();
        let results = run_check_with(&config, &pkg);
        assert!(
            !results
                .iter()
                .any(|(name, _)| name.as_str() == "invalid-changelog-author"),
            "unexpected: {results:?}"
        );
    }

    #[test]
    fn invalid_changelog_author_list_is_config_driven() {
        // Only the example.com pattern configured: the opensuse-packaging
        // entry stays quiet.
        let config = authors_config(&[".*@example\\.com"]);
        let pkg = authors_fixture();
        let results = run_check_with(&config, &pkg);
        let hits: Vec<_> = results
            .iter()
            .filter(|(name, _)| name.as_str() == "invalid-changelog-author")
            .collect();
        assert_eq!(hits.len(), 1, "expected one finding: {results:?}");
        assert!(
            hits[0].1.contains("bot@example.com"),
            "detail: {}",
            hits[0].1
        );
    }

    #[test]
    fn invalid_changelog_author_bad_regex_is_skipped() {
        // An uncompilable pattern must not kill the check: the valid
        // patterns still apply (same policy as InvalidRequires).
        let config = authors_config(&["(unclosed", "opensuse-packaging@opensuse.org"]);
        let pkg = authors_fixture();
        let results = run_check_with(&config, &pkg);
        let hits: Vec<_> = results
            .iter()
            .filter(|(name, _)| name.as_str() == "invalid-changelog-author")
            .collect();
        assert_eq!(hits.len(), 1, "expected one finding: {results:?}");
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

    /// A `range_compare` matrix row: requirement flags + EVR, provider
    /// flags + EVR, and the expected verdict.
    type MatrixCase = (u32, Option<&'static str>, u32, Option<&'static str>, bool);

    /// Flag/ordering matrix for [`range_compare`]: every arm of the
    /// Greater/Equal/Less dispatch on both flag sides, plus the unversioned,
    /// name-mismatch and release-drop paths. GT=4, GE=12, EQ=8, LE=10, LT=2.
    #[test]
    fn range_compare_flag_ordering_matrix() {
        use RPMSENSE_EQUAL as EQ;
        use RPMSENSE_GREATER as GT;
        use RPMSENSE_LESS as LT;
        const GE: u32 = GT | EQ;
        const LE: u32 = LT | EQ;
        // (req flags, req EVR, prov flags, prov EVR, expected).
        let cases: &[MatrixCase] = &[
            // Unversioned satisfies everything (prov side).
            (EQ, Some("2.0"), 0, None, true),
            // Unversioned satisfies everything (req side).
            (0, None, EQ, Some("1.0"), true),
            // Provided greater: GT/GE match, EQ/LE/LT do not (prov EQ).
            (GT, Some("1.0"), EQ, Some("2.0"), true),
            (GE, Some("1.0"), EQ, Some("2.0"), true),
            (EQ, Some("1.0"), EQ, Some("2.0"), false),
            (LE, Some("1.0"), EQ, Some("2.0"), false),
            (LT, Some("1.0"), EQ, Some("2.0"), false),
            // Provided greater against LT prov: LT matches via arm 3
            // (the LE row is #1599-shadowed: at-or-below never matches).
            (LE, Some("1.0"), LT, Some("2.0"), false),
            (LT, Some("1.0"), LT, Some("2.0"), true),
            (EQ, Some("1.0"), LT, Some("2.0"), false),
            // Provided equal: each flag only matches its set.
            (GT, Some("1.0"), GT, Some("1.0"), true),
            (GT, Some("1.0"), EQ, Some("1.0"), false),
            (GE, Some("1.0"), LT, Some("1.0"), false),
            (GE, Some("1.0"), EQ, Some("1.0"), true),
            (EQ, Some("1.0"), LE, Some("1.0"), false),
            (EQ, Some("1.0"), EQ, Some("1.0"), false),
            (LE, Some("1.0"), EQ, Some("1.0"), false),
            (LE, Some("1.0"), LE, Some("1.0"), false),
            (LT, Some("1.0"), LT, Some("1.0"), true),
            (LT, Some("1.0"), EQ, Some("1.0"), false),
            // Provided less: GT/GE/EQ match GT/GE provs; LE/LT match all.
            (GT, Some("2.0"), GT, Some("1.0"), true),
            (GT, Some("2.0"), EQ, Some("1.0"), false),
            (EQ, Some("2.0"), EQ, Some("1.0"), false),
            (EQ, Some("2.0"), GT, Some("1.0"), true),
            (LE, Some("2.0"), EQ, Some("1.0"), true),
            (LT, Some("2.0"), LT, Some("1.0"), true),
            // Dropped provided release matches releaseless requirement.
            // (#1599 shadows this for EQ/LE requirements at or below the
            // provider -- those return false above -- so the drop only
            // bites for GT/GE/LT requirements.)
            (EQ, Some("1.0"), EQ, Some("1.0-15"), false),
            // The drop pinned where it bites: without it rc is Greater
            // and a GT requirement matches; with it rc is Equal and an
            // EQ provider does not.
            (GT, Some("1.0"), EQ, Some("1.0-15"), false),
            // Epoch decides before version.
            (GE, Some("0:1.0"), GE, Some("1:1.0"), true),
            (EQ, Some("0:2.0"), EQ, Some("1:1.0"), false),
        ];
        // Name mismatch never matches, whatever the flags.
        assert!(!range_compare(
            &make_dep("foo", EQ, Some("1.0")),
            &make_dep("bar", EQ, Some("1.0"))
        ));
        for (i, (reqf, reqe, f, e, expected)) in cases.iter().enumerate() {
            let req = make_dep("foo", *reqf, *reqe);
            let prov = make_dep("foo", *f, *e);
            assert_eq!(
                range_compare(&req, &prov),
                *expected,
                "case {i}: req {reqf}/{reqe:?} vs prov {f}/{e:?}"
            );
        }
    }

    /// Date boundaries for [`format_date`] (Howard Hinnant's algorithm):
    /// epoch, pre-epoch negatives, leap days, month/year wraps, far future.
    #[test]
    fn format_date_boundaries() {
        let cases: &[(i64, &str)] = &[
            (0, "1970-01-01"),
            (86400, "1970-01-02"),
            (-86400, "1969-12-31"),
            (-1, "1969-12-31"),
            (951782400, "2000-02-29"),
            (951868800, "2000-03-01"),
            (1709164800, "2024-02-29"),
            (1709251200, "2024-03-01"),
            (1672531199, "2022-12-31"),
            (1672531200, "2023-01-01"),
            (1767225600, "2026-01-01"),
            (4102444800, "2100-01-01"),
            (4107542400, "2100-03-01"),
        ];
        for (ts, expected) in cases {
            assert_eq!(&format_date(*ts), expected, "ts {ts}");
        }
    }

    /// Build a [`DepInfo`] from an optional `epoch:version-release` string.
    fn make_dep(name: &str, flags: u32, evr: Option<&str>) -> DepInfo {
        let (epoch, version, release) = match evr {
            Some(s) => crate::pkg::dep::string_to_version(s),
            None => (None, None, None),
        };
        DepInfo {
            name: name.to_string(),
            flags,
            epoch,
            version,
            release,
        }
    }

    /// Run the full check with the fixture's Provides/Obsoletes replaced,
    /// returning the emitted `self-obsoletion` findings.
    fn self_obsoletion_results(provides: DepInfo, obsoletes: DepInfo) -> Vec<(String, String)> {
        let (_tmp, mut pkg) = fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.provides = vec![provides];
        pkg.obsoletes = vec![obsoletes];
        run_check(&pkg)
            .into_iter()
            .filter(|(name, _)| name == "self-obsoletion")
            .collect()
    }

    /// Emission-path port of Tom's upstream `test_self_obsoletion` (#1599):
    /// the documented merge pattern stays silent, unversioned self-Obsoletes
    /// and overreaching ranges still warn with name, level and detail pinned.
    #[test]
    fn self_obsoletion_merge_pattern_is_silent() {
        // Provides: merged = 1.6.1, Obsoletes: merged <= 1.6.1
        let prov = make_dep("merged", RPMSENSE_EQUAL, Some("1.6.1"));
        let obs = make_dep("merged", RPMSENSE_LESS | RPMSENSE_EQUAL, Some("1.6.1"));
        assert!(
            self_obsoletion_results(prov, obs).is_empty(),
            "merge pattern must not warn"
        );
        // Pinned to exactly the provided EVR: same legitimate shape.
        let prov = make_dep("mergedeq", RPMSENSE_EQUAL, Some("1.6.1"));
        let obs = make_dep("mergedeq", RPMSENSE_EQUAL, Some("1.6.1"));
        assert!(
            self_obsoletion_results(prov, obs).is_empty(),
            "pinned merge pattern must not warn"
        );
    }

    #[test]
    fn self_obsoletion_unversioned_and_overreaching_still_warn() {
        // Unversioned Obsoletes genuinely obsoletes the package itself.
        let prov = make_dep("selfobs", RPMSENSE_EQUAL, Some("1.0"));
        let obs = make_dep("selfobs", 0, None);
        assert_eq!(
            self_obsoletion_results(prov, obs),
            [(
                "self-obsoletion".to_string(),
                "fcprobe.noarch: W: self-obsoletion selfobs obsoletes selfobs = 1.0".to_string(),
            )],
            "unversioned self-obsoletes must warn"
        );
        // Range reaching beyond the provided EVR covers the package itself.
        let prov = make_dep("higher", RPMSENSE_EQUAL, Some("1.6.1"));
        let obs = make_dep("higher", RPMSENSE_LESS | RPMSENSE_EQUAL, Some("2.0"));
        assert_eq!(
            self_obsoletion_results(prov, obs),
            [(
                "self-obsoletion".to_string(),
                "fcprobe.noarch: W: self-obsoletion higher <= 2.0 obsoletes higher = 1.6.1"
                    .to_string(),
            )],
            "overreaching range must warn"
        );
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
        tbl.insert("UseEpoch".to_string(), toml::Value::Boolean(false));
        tbl.insert("MaxLineLength".to_string(), toml::Value::Integer(79));
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
        let (_tmp, pkg) = fixture_pkg("fcprobe-1-1.noarch.rpm");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = TagsCheck::new(&config);
        check.check_license(&pkg, &mut out, license);
        out.results().to_vec()
    }

    fn invalid_license_findings(results: Vec<(String, String)>) -> Vec<(String, String)> {
        // The `invalid-license-spellcheck` info finding accompanies every
        // invalid-license error; these tests pin the error itself. The
        // total is asserted so an unexpected extra finding cannot slip past
        // the filter unnoticed.
        for (name, _) in &results {
            assert!(
                name == "invalid-license" || name == "invalid-license-spellcheck",
                "unexpected finding: {name}"
            );
        }
        results
            .into_iter()
            .filter(|(n, _)| n == "invalid-license")
            .collect()
    }

    #[test]
    fn license_split_yields_bare_leaves() {
        // Parentheses cut at any depth and boolean operators split, so
        // the pieces are the bare leaves inside: no parenthesis fragment
        // survives.
        assert_eq!(
            TagsCheck::split_license("(GPLv2 or GPLv3) and (GPLv2+ with exceptions)"),
            vec!["GPLv2", "GPLv3", "GPLv2+ with exceptions"],
        );
        assert_eq!(
            TagsCheck::split_license("((GPLv2 or GPLv3) and MIT)"),
            vec!["GPLv2", "GPLv3", "MIT"],
        );
        assert_eq!(
            TagsCheck::split_license("GPLv2 AND GPLv3"),
            vec!["GPLv2", "GPLv3"],
        );
        assert_eq!(TagsCheck::split_license("MIT"), vec!["MIT"]);
        // `or` inside a word is not an operator.
        assert_eq!(
            TagsCheck::split_license("GPL-2.0-or-later"),
            vec!["GPL-2.0-or-later"],
        );
        // Multi-byte input must not panic on slicing.
        assert_eq!(
            TagsCheck::split_license("GPLv2\u{e9} or MIT"),
            vec!["GPLv2\u{e9}", "MIT"],
        );
        // Nested groups (issue #864): the libQt5Help5 expression splits
        // into its bare leaves, the WITH tail staying one piece for the
        // exception match.
        assert_eq!(
            TagsCheck::split_license(
                "(LGPL-3.0-only OR (GPL-2.0-only OR GPL-3.0-or-later)) AND GPL-3.0-only WITH Qt-GPL-exception-1.0"
            ),
            vec![
                "LGPL-3.0-only",
                "GPL-2.0-only",
                "GPL-3.0-or-later",
                "GPL-3.0-only WITH Qt-GPL-exception-1.0",
            ],
        );
        // Unbalanced parens are structural too: the leaf inside is what
        // gets validated, never a fragment.
        assert_eq!(TagsCheck::split_license("((GPLv2))"), vec!["GPLv2"]);
        assert_eq!(TagsCheck::split_license("((GPLv2)"), vec!["GPLv2"]);
        assert_eq!(TagsCheck::split_license("(GPLv2))"), vec!["GPLv2"]);
        assert_eq!(TagsCheck::split_license("()"), vec!["()"]);
        assert!(TagsCheck::split_license("( )").is_empty());
        // A dangling trailing operator is never a cut point (the
        // operator cuts need whitespace on both sides), so it stays
        // glued to the tail piece and the malformed text is what is
        // reported (helvum's shape).
        assert_eq!(TagsCheck::split_license("MIT AND"), vec!["MIT AND"]);
        assert_eq!(
            TagsCheck::split_license("GPLv2 AND MIT AND"),
            vec!["GPLv2", "MIT AND"]
        );
    }

    #[test]
    fn license_paren_groups_yield_clean_findings() {
        // Two WITH expressions in separate paren groups: the old
        // whole-string exception match saw only the first, silently
        // dropping the second.
        let results = license_findings("(GPLv2+ with exceptions) and (MIT with BogusException)");
        for (name, line) in &results {
            eprintln!("GOT: {name}: {line}");
        }
        // Both exceptions are reported, each with a clean token: no paren
        // may leak into any detail.
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "invalid-license-exception");
        assert_eq!(
            results[0].1,
            "fcprobe.noarch: W: invalid-license-exception exceptions"
        );
        assert_eq!(results[1].0, "invalid-license-exception");
        assert_eq!(
            results[1].1,
            "fcprobe.noarch: W: invalid-license-exception BogusException"
        );
    }

    #[test]
    fn license_empty_paren_group_is_reported() {
        // The reference reports `W: invalid-license ()` for an empty
        // group: the leaf must not vanish.
        let errors = invalid_license_findings(license_findings("()"));
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].1, "fcprobe.noarch: E: invalid-license ()");
        let errors = invalid_license_findings(license_findings("MIT and ()"));
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].1, "fcprobe.noarch: E: invalid-license ()");
        // A whitespace-only group vanishes, like the reference's
        // empty-split filtering.
        assert!(license_findings("( )").is_empty());
    }

    #[test]
    fn license_deeply_nested_parens_terminates() {
        // Adversarial nesting: the split is iterative and linear, so this
        // terminates instead of hanging or overflowing the stack.
        let text = format!("({}MIT{})", "(".repeat(10_000), ")".repeat(10_000));
        assert_eq!(TagsCheck::split_license(&text), vec!["MIT"]);
        // No closing paren at all: still linear, and the expression is
        // kept whole so it is reported rather than silently accepted.
        let text = "(".repeat(10_000);
        assert_eq!(TagsCheck::split_license(&text), vec![text]);
    }

    #[test]
    fn license_nested_parens_report_the_bare_leaf() {
        // Issue #864: the reference's regex split turns `((GPLv2))` into
        // the fragments `(GPLv2` and `)`; the nesting-aware split
        // validates the bare leaf instead. (GPLv2 itself is in the
        // fixture list, so an unknown id stands inside the parens.)
        for text in ["((GPLv9))", "((GPLv9)", "(GPLv9))"] {
            let errors = invalid_license_findings(license_findings(text));
            assert_eq!(errors.len(), 1, "{text}");
            assert_eq!(errors[0].1, "fcprobe.noarch: E: invalid-license GPLv9");
        }
        // A nested group of valid leaves is silent: no fragment of the
        // inner group is reported.
        assert!(license_findings("(GPL-2.0-only OR (GPLv2 OR GPLv3)) AND MIT").is_empty());
        // Groups written with spaces inside the parens split the same.
        assert!(license_findings("( (MIT OR GPLv2) AND GPLv3 )").is_empty());
        // One invalid leaf deep inside nesting is reported once, bare.
        let errors = invalid_license_findings(license_findings("(MIT OR (GPLv9 OR GPLv3))"));
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].1, "fcprobe.noarch: E: invalid-license GPLv9");
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
        assert_eq!(bad[0].1, "fcprobe.noarch: E: invalid-license BogusLicense");
    }

    #[test]
    fn license_trailing_tail_after_with_is_validated() {
        // `and MIT` after a WITH expression used to be dropped entirely.
        let results =
            license_findings("GPL-2.0-only WITH Classpath-exception-2.0 and BogusLicense");
        let errors = invalid_license_findings(results);
        let names: Vec<&str> = errors.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["invalid-license"]);
    }

    #[test]
    fn license_valid_with_exception_is_silent() {
        let results = license_findings("GPL-2.0-only WITH Classpath-exception-2.0");
        assert!(results.is_empty(), "unexpected: {results:?}");
    }

    #[test]
    fn license_plain_invalid_is_reported() {
        let errors = invalid_license_findings(license_findings("BogusLicense-1.0"));
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, "invalid-license");
        assert_eq!(
            errors[0].1,
            "fcprobe.noarch: E: invalid-license BogusLicense-1.0"
        );
    }

    #[test]
    fn invalid_license_emits_spellcheck_suggestions() {
        // Upstream rpm-software-management/rpmlint#818: did-you-mean for
        // invalid licenses. Info-level so it can never break a build.
        let results = license_findings("GPL-2.0-or-latr");
        assert_eq!(
            results,
            vec![
                (
                    "invalid-license".to_string(),
                    "fcprobe.noarch: E: invalid-license GPL-2.0-or-latr".to_string(),
                ),
                (
                    "invalid-license-spellcheck".to_string(),
                    "fcprobe.noarch: I: invalid-license-spellcheck GPL-2.0-or-latr: GPL-2.0-or-later, GPL-1.0-or-later, GPL-3.0-or-later"
                        .to_string(),
                ),
            ]
        );
    }

    #[test]
    fn invalid_license_spellcheck_omits_cross_family_guesses() {
        // `MPL-2.0-or-later` is not an SPDX id, so the error stands,
        // but the closest IDs by edit distance are GPL-family: a
        // suggestion that changes licence family is not emitted.
        let results = license_findings("MPL-2.0-or-later");
        assert_eq!(
            results,
            vec![(
                "invalid-license".to_string(),
                "fcprobe.noarch: E: invalid-license MPL-2.0-or-later".to_string(),
            )]
        );
    }

    #[test]
    fn invalid_license_spellcheck_matches_upstream_example() {
        // The #818 reporter's own example: "Apache 2" should point at Apache-2.0.
        let results = license_findings("Apache 2");
        assert_eq!(
            results
                .iter()
                .find(|(n, _)| n == "invalid-license-spellcheck")
                .map(|(_, l)| l.as_str()),
            Some(
                "fcprobe.noarch: I: invalid-license-spellcheck Apache 2: Apache-2.0, Apache-1.0, Apache-1.1"
            ),
        );
    }
    // Per-finding emission pins for the mechanical tag findings. Each test
    // opens a hand-built fixture RPM from tests/parity/pkg/inputs/tags-*.rpm
    // (built by build-tags-emission-pins.sh, never a distro package) and
    // asserts the finding name, level, and detail through the real emission
    // path. The Summary/Description content checks only run when the RPM
    // carries HEADERI18NTABLE (like the reference); rpmbuild writes
    // RPMTAG_HEADERI18NTABLE=["C"] itself, which TagsCheck requires before
    // running Summary/Description content checks.

    fn tag_hits<'a>(results: &'a [(String, String)], name: &str) -> Vec<&'a (String, String)> {
        results.iter().filter(|(n, _)| n == name).collect()
    }

    fn run_check_with_spellcheck(pkg: &Pkg) -> Vec<(String, String)> {
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = TagsCheck::new(&config);
        check.set_test_spellchecker();
        check.check(pkg, &config, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn summary_too_long_emits() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-longsummary-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        let hits = tag_hits(&results, "summary-too-long");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(
            hits[0].1,
            "tags-emission-pins-longsummary.noarch: E: summary-too-long This is a deliberately overlong summary that stretches well past seventy nine characters"
        );
    }

    #[test]
    fn summary_length_counts_characters_not_bytes() {
        // Reference parity (#577): the length limit counts characters,
        // not UTF-8 bytes. A summary of <=79 characters stays quiet
        // however many bytes it occupies; 80 characters fire.
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-longsummary-1.0-1.noarch.rpm");
        let config = test_config();
        let check = TagsCheck::new(&config);
        // 41 characters, 81 bytes: within the limit.
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_summary(
            &pkg,
            &mut out,
            &format!("S{}", "\u{e9}".repeat(40)),
            "C",
            &[],
        );
        let results = out.results().to_vec();
        assert!(
            tag_hits(&results, "summary-too-long").is_empty(),
            "multibyte summary within the character limit must stay quiet: {results:?}"
        );
        // 80 characters, 159 bytes: fires.
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_summary(
            &pkg,
            &mut out,
            &format!("S{}", "\u{e9}".repeat(79)),
            "C",
            &[],
        );
        let results = out.results().to_vec();
        let hits = tag_hits(&results, "summary-too-long");
        assert_eq!(hits.len(), 1, "all: {results:?}");
    }

    #[test]
    fn summary_not_capitalized_and_ended_with_dot_emit() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-badsummary-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        let summary = "lowercase summary that ends with a dot.";
        for name in ["summary-not-capitalized", "summary-ended-with-dot"] {
            let hits = tag_hits(&results, name);
            assert_eq!(hits.len(), 1, "{name}: {results:?}");
            assert_eq!(
                hits[0].1,
                format!("tags-emission-pins-badsummary.noarch: W: {name} {summary}")
            );
        }
    }

    #[test]
    fn summary_not_capitalized_ignores_digit_leading() {
        // Reference parity: `summary[0] != summary[0].upper()` only warns
        // when the first char is actually lowercase; a digit (or other
        // non-letter) first char never warns.
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-badsummary-1.0-1.noarch.rpm");
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = TagsCheck::new(&config);
        for summary in ["389 Directory Server", "7zip archiver"] {
            check.check_summary(&pkg, &mut out, summary, "C", &[]);
        }
        let results = out.results().to_vec();
        assert!(
            results.iter().all(|(n, _)| n != "summary-not-capitalized"),
            "digit-leading summary must not warn: {results:?}"
        );
    }

    #[test]
    fn summary_not_capitalized_still_warns_on_lowercase() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-badsummary-1.0-1.noarch.rpm");
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = TagsCheck::new(&config);
        check.check_summary(&pkg, &mut out, "lowercase summary", "C", &[]);
        let results = out.results().to_vec();
        let hits: Vec<_> = results
            .iter()
            .filter(|(n, _)| n == "summary-not-capitalized")
            .collect();
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(
            hits[0].1,
            "tags-emission-pins-badsummary.noarch: W: summary-not-capitalized lowercase summary"
        );
    }

    #[test]
    fn summary_not_capitalized_ignores_extended_list_entries() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-badsummary-1.0-1.noarch.rpm");
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = TagsCheck::new(&config);
        for summary in ["xSGE display manager", "oneAPI Level Zero loader"] {
            check.check_summary(&pkg, &mut out, summary, "C", &[]);
        }
        let results = out.results().to_vec();
        assert!(
            results.iter().all(|(n, _)| n != "summary-not-capitalized"),
            "extended list entries must not warn: {results:?}"
        );
    }

    #[test]
    fn summary_not_capitalized_strips_possessive_before_lookup() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-badsummary-1.0-1.noarch.rpm");
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = TagsCheck::new(&config);
        check.check_summary(&pkg, &mut out, "wxWidgets's ribbon", "C", &[]);
        let results = out.results().to_vec();
        assert!(
            results.iter().all(|(n, _)| n != "summary-not-capitalized"),
            "listed brand possessive must not warn: {results:?}"
        );
    }

    #[test]
    fn summary_not_capitalized_unlisted_possessive_still_warns() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-badsummary-1.0-1.noarch.rpm");
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let check = TagsCheck::new(&config);
        check.check_summary(&pkg, &mut out, "foo's bar", "C", &[]);
        let results = out.results().to_vec();
        let hits: Vec<_> = results
            .iter()
            .filter(|(n, _)| n == "summary-not-capitalized")
            .collect();
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(
            hits[0].1,
            "tags-emission-pins-badsummary.noarch: W: summary-not-capitalized foo's bar"
        );
    }

    #[test]
    fn summary_not_capitalized_dropped_and_article_possessives_still_warn() {
        // Dropped list entries ("the", "libreport's") and article
        // possessives ("a's"/"an's"/"the's") must warn as the reference does.
        for summary in [
            "the quick brown fox",
            "the's book",
            "a's book",
            "an's book",
            "libreport's plugin",
            "libreport plugin",
        ] {
            let (_tmp, pkg) = fixture_pkg("tags-emission-pins-badsummary-1.0-1.noarch.rpm");
            let config = test_config();
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            let check = TagsCheck::new(&config);
            check.check_summary(&pkg, &mut out, summary, "C", &[]);
            let results = out.results().to_vec();
            let hits: Vec<_> = results
                .iter()
                .filter(|(n, _)| n == "summary-not-capitalized")
                .collect();
            assert_eq!(hits.len(), 1, "summary {summary:?}: {results:?}");
            assert_eq!(
                hits[0].1,
                format!(
                    "tags-emission-pins-badsummary.noarch: W: summary-not-capitalized {summary}"
                )
            );
        }
    }

    #[test]
    fn summary_on_multiple_lines_emits() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-multiline-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        let hits = tag_hits(&results, "summary-on-multiple-lines");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(
            hits[0].1,
            "tags-emission-pins-multiline.noarch: E: summary-on-multiple-lines"
        );
    }

    #[test]
    fn no_description_tag_emits() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-nodesc-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        let hits = tag_hits(&results, "no-description-tag");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(
            hits[0].1,
            "tags-emission-pins-nodesc.noarch: E: no-description-tag"
        );
    }

    #[test]
    fn description_line_too_long_emits() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-longdesc-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        let hits = tag_hits(&results, "description-line-too-long");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(
            hits[0].1,
            "tags-emission-pins-longdesc.noarch: W: description-line-too-long This is a ridiculously long description line that definitely exceeds seventy nine characters."
        );
    }

    #[test]
    fn description_length_counts_characters_not_bytes() {
        // Reference parity (#577): the length limit counts characters,
        // not UTF-8 bytes. Lines of <=79 characters stay quiet however
        // many bytes they occupy; an 80-character line fires.
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-longdesc-1.0-1.noarch.rpm");
        let config = test_config();
        let check = TagsCheck::new(&config);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        // 41 characters, 123 bytes (the karukan/VFlib3 shape: Japanese
        // description lines the byte count flagged as too long).
        check.check_description(&pkg, &mut out, &"\u{3042}".repeat(41), "C", &[]);
        // 79 characters, 80 bytes: exactly at the limit.
        check.check_description(
            &pkg,
            &mut out,
            &format!("{}\u{e9}", "a".repeat(78)),
            "C",
            &[],
        );
        let results = out.results().to_vec();
        assert!(
            tag_hits(&results, "description-line-too-long").is_empty(),
            "multibyte lines within the character limit must stay quiet: {results:?}"
        );
        // 80 characters, 240 bytes: fires.
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_description(&pkg, &mut out, &"\u{3042}".repeat(80), "C", &[]);
        let results = out.results().to_vec();
        let hits = tag_hits(&results, "description-line-too-long");
        assert_eq!(hits.len(), 1, "all: {results:?}");
    }

    #[test]
    fn tag_in_description_emits() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-tagdesc-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        let hits = tag_hits(&results, "tag-in-description");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(
            hits[0].1,
            "tags-emission-pins-tagdesc.noarch: W: tag-in-description Name:"
        );
    }

    #[test]
    fn spelling_error_emits() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-spell-1.0-1.noarch.rpm");
        let results = run_check_with_spellcheck(&pkg);
        let hits = tag_hits(&results, "spelling-error");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.starts_with(
                "tags-emission-pins-spell.noarch: W: spelling-error %description -l C packag"
            ),
            "line: {}",
            hits[0].1
        );
    }

    #[test]
    fn spelling_skips_language_without_dictionary() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-spell-1.0-1.noarch.rpm");
        let config = test_config();
        let mut check = TagsCheck::new(&config);
        check.set_test_spellchecker();
        // A language the checker has no dictionary for is not checked.
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_description(&pkg, &mut out, "hello wrld", "de", &[]);
        let results = out.results().to_vec();
        assert!(
            tag_hits(&results, "spelling-error").is_empty(),
            "all: {results:?}"
        );
        // The same text in the C locale is checked.
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_description(&pkg, &mut out, "hello wrld", "C", &[]);
        let results = out.results().to_vec();
        assert_eq!(
            tag_hits(&results, "spelling-error").len(),
            1,
            "all: {results:?}"
        );
    }

    #[test]
    fn spelling_summary_skips_language_without_dictionary() {
        // The summary branch of the language gate, symmetric to the
        // description pin (issue #1155).
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-spell-1.0-1.noarch.rpm");
        let config = test_config();
        let mut check = TagsCheck::new(&config);
        check.set_test_spellchecker();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_summary(&pkg, &mut out, "hello wrld", "de", &[]);
        let results = out.results().to_vec();
        assert!(
            tag_hits(&results, "spelling-error").is_empty(),
            "all: {results:?}"
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_summary(&pkg, &mut out, "hello wrld", "C", &[]);
        let results = out.results().to_vec();
        assert_eq!(
            tag_hits(&results, "spelling-error").len(),
            1,
            "all: {results:?}"
        );
    }

    #[test]
    fn obsolete_not_provided_emits() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-obsolete-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        let hits = tag_hits(&results, "obsolete-not-provided");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(
            hits[0].1,
            "tags-emission-pins-obsolete.noarch: W: obsolete-not-provided tags-old-pin"
        );
    }

    /// An fcprobe-derived binary package of the `fcprobe-1-1` build
    /// (the fixture header's `SOURCERPM`), renamed, with the given
    /// Provides/Obsoletes name lists.
    fn build_pkg(name: &str, provides: &[&str], obsoletes: &[&str]) -> (tempfile::TempDir, Pkg) {
        let (tmp, mut pkg) = fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.name = name.to_string();
        pkg.arch = "x86_64".to_string();
        pkg.provides = provides.iter().map(|n| make_dep(n, 0, None)).collect();
        pkg.obsoletes = obsoletes.iter().map(|n| make_dep(n, 0, None)).collect();
        (tmp, pkg)
    }

    /// The fcprobe fixture header as the build's source package: the
    /// source identity derived from its name/version/release is
    /// `fcprobe-1-1.src.rpm`, the `SOURCERPM` every `build_pkg`
    /// binary carries. Its own Obsoletes are cleared so it
    /// contributes no findings of its own.
    fn build_src() -> (tempfile::TempDir, Pkg) {
        let (tmp, mut pkg) = fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.is_source = true;
        pkg.obsoletes = Vec::new();
        (tmp, pkg)
    }

    #[test]
    fn obsolete_sibling_credit_on_complete_build() {
        let config = test_config();
        let (_t0, src) = build_src();
        // The fan-out shape: several subpackages obsolete a name only
        // one sibling provides.
        let (_t1, a) = build_pkg("pkg-a", &[], &["oldname"]);
        let (_t2, b) = build_pkg("pkg-b", &[], &["oldname"]);
        let (_t3, provider) = build_pkg("pkg-rt", &["oldname"], &[]);
        let results = run_check_multi(&config, &[src, a, b, provider]);
        let hits = tag_hits(&results, "obsolete-not-provided");
        assert!(hits.is_empty(), "complete build must credit: {results:?}");
    }

    #[test]
    fn obsolete_sibling_name_bearer_credited_on_complete_build() {
        let config = test_config();
        let (_t0, src) = build_src();
        let (_t1, a) = build_pkg("pkg-snmp", &[], &["pkg-base"]);
        let (_t2, bearer) = build_pkg("pkg-base", &["pkg-base"], &[]);
        let results = run_check_multi(&config, &[src, a, bearer]);
        let hits = tag_hits(&results, "obsolete-not-provided");
        assert!(
            hits.is_empty(),
            "sibling bearing the name must credit: {results:?}"
        );
    }

    #[test]
    fn obsolete_sibling_no_credit_on_partial_build() {
        let config = test_config();
        let (_t1, a) = build_pkg("pkg-a", &[], &["oldname"]);
        let (_t2, provider) = build_pkg("pkg-rt", &["oldname"], &[]);
        // No source package in the run: the build is not judged
        // complete, so the candidate fires as the per-package verdict.
        let results = run_check_multi(&config, &[a, provider]);
        let hits = tag_hits(&results, "obsolete-not-provided");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(hits[0].1, "pkg-a.x86_64: W: obsolete-not-provided oldname");
    }

    #[test]
    fn obsolete_single_package_still_fires() {
        let (_t1, pkg) = build_pkg("pkg-a", &["selfname"], &["selfname", "oldname"]);
        let results = run_check(&pkg);
        let hits = tag_hits(&results, "obsolete-not-provided");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(hits[0].1, "pkg-a.x86_64: W: obsolete-not-provided oldname");
    }

    #[test]
    fn obsolete_case_mismatch_sibling_does_not_credit() {
        let config = test_config();
        let (_t0, src) = build_src();
        let (_t1, a) = build_pkg("pkg-a", &[], &["oldname"]);
        let (_t2, provider) = build_pkg("pkg-rt", &["OldName"], &[]);
        let results = run_check_multi(&config, &[src, a, provider]);
        let hits = tag_hits(&results, "obsolete-not-provided");
        assert_eq!(
            hits.len(),
            1,
            "case differs: not the solver's name: {results:?}"
        );
    }

    #[test]
    fn obsolete_separator_mismatch_sibling_does_not_credit() {
        let config = test_config();
        let (_t0, src) = build_src();
        let (_t1, a) = build_pkg("pkg-a", &[], &["old-name"]);
        let (_t2, provider) = build_pkg("pkg-rt", &["old_name"], &[]);
        let results = run_check_multi(&config, &[src, a, provider]);
        let hits = tag_hits(&results, "obsolete-not-provided");
        assert_eq!(
            hits.len(),
            1,
            "separator differs: not the solver's name: {results:?}"
        );
    }

    #[test]
    fn obsolete_unrelated_sibling_provide_does_not_credit() {
        let config = test_config();
        let (_t0, src) = build_src();
        let (_t1, a) = build_pkg("pkg-a", &[], &["oldname"]);
        let (_t2, provider) = build_pkg("pkg-rt", &["othername"], &[]);
        let results = run_check_multi(&config, &[src, a, provider]);
        let hits = tag_hits(&results, "obsolete-not-provided");
        assert_eq!(
            hits.len(),
            1,
            "a different name must not credit: {results:?}"
        );
    }

    #[test]
    fn obsolete_foreign_source_does_not_open_the_gate() {
        let config = test_config();
        let (_t0, mut src) = build_src();
        // A source package of another build: its derived keys name
        // that build, not this one.
        src.name = "otherbuild".to_string();
        let (_t1, a) = build_pkg("pkg-a", &[], &["oldname"]);
        let (_t2, provider) = build_pkg("pkg-rt", &["oldname"], &[]);
        let results = run_check_multi(&config, &[src, a, provider]);
        let hits = tag_hits(&results, "obsolete-not-provided");
        assert_eq!(
            hits.len(),
            1,
            "foreign build's source must not credit: {results:?}"
        );
    }

    #[test]
    fn obsolete_credit_survives_state_export() {
        let config = test_config();
        let (_t0, src) = build_src();
        let (_t1, a) = build_pkg("pkg-a", &[], &["oldname"]);
        let (_t2, provider) = build_pkg("pkg-rt", &["oldname"], &[]);
        // A worker sees the source package and the provider; the
        // main instance sees the obsoleter and merges the worker's
        // exported state before `after_checks` (rpmlint#1595).
        let mut worker_out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut worker = TagsCheck::new(&config);
        worker.check(&src, &config, &mut worker_out);
        worker.check(&provider, &config, &mut worker_out);
        let state = worker.export_state().expect("run-scope state");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = TagsCheck::new(&config);
        check.import_state(state);
        check.check(&a, &config, &mut out);
        check.after_checks(&config, &mut out);
        let results = out.results().to_vec();
        let hits = tag_hits(&results, "obsolete-not-provided");
        assert!(hits.is_empty(), "merged state must credit: {results:?}");
    }

    #[test]
    fn obsolete_reset_drops_the_run() {
        let config = test_config();
        let (_t0, src) = build_src();
        let (_t1, a) = build_pkg("pkg-a", &[], &["oldname"]);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = TagsCheck::new(&config);
        check.check(&src, &config, &mut out);
        check.check(&a, &config, &mut out);
        check.reset();
        check.after_checks(&config, &mut out);
        let results = out.results().to_vec();
        let hits = tag_hits(&results, "obsolete-not-provided");
        assert!(
            hits.is_empty(),
            "reset must drop the run's state: {results:?}"
        );
    }

    #[test]
    fn no_pkg_config_provides_emits() {
        let (_tmp, mut pkg) = fixture_pkg("tags-emission-pins-pcreq-devel-1.0-1.noarch.rpm");
        // rpmbuild auto-generates pkgconfig() provides for the .pc file;
        // drop them so the missing-provide path is exercised.
        pkg.provides = vec![];
        let results = run_check(&pkg);
        let hits = tag_hits(&results, "no-pkg-config-provides");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(
            hits[0].1,
            "tags-emission-pins-pcreq-devel.noarch: E: no-pkg-config-provides"
        );
    }

    /// Negative pin for the removed `invalid-version` finding: the
    /// badversion fixture's `0pre` version stays silent, and
    /// `cargo test` (not just the reference-coverage auditor) must catch
    /// a re-add.
    #[test]
    fn killed_invalid_version_stays_absent() {
        let (_tmp, pkg) = fixture_pkg("tags-badversion-0pre-1.noarch.rpm");
        let results = run_check(&pkg);
        assert!(
            tag_hits(&results, "invalid-version").is_empty(),
            "must stay silent: {results:?}"
        );
    }

    /// Negative pins for the removed `invalid-packager` and
    /// `invalid-buildhost` findings: with both patterns set to match
    /// nothing, the badversion fixture's packager and buildhost stay
    /// silent.
    #[test]
    fn killed_invalid_packager_and_buildhost_stay_absent() {
        let (_tmp, pkg) = fixture_pkg("tags-badversion-0pre-1.noarch.rpm");
        let mut config = test_config_with(None);
        config.configuration.insert(
            "Packager".to_string(),
            toml::Value::String("^$".to_string()),
        );
        config.configuration.insert(
            "ValidBuildHost".to_string(),
            toml::Value::String("^$".to_string()),
        );
        config.finalize().expect("fixture config");
        let results = run_check_with(&config, &pkg);
        assert!(
            tag_hits(&results, "invalid-packager").is_empty(),
            "must stay silent: {results:?}"
        );
        assert!(
            tag_hits(&results, "invalid-buildhost").is_empty(),
            "must stay silent: {results:?}"
        );
    }

    /// Negative pin for the removed
    /// `incoherent-version-in-changelog` finding: the badver fixture's
    /// changelog version (1.15.2) differs from its version (1.15.1) and
    /// stays silent.
    #[test]
    fn killed_incoherent_version_in_changelog_stays_absent() {
        let (_tmp, pkg) = fixture_pkg("distrelease-badver-1.15.1-3.fc42.noarch.rpm");
        let results = run_check(&pkg);
        assert!(
            tag_hits(&results, "incoherent-version-in-changelog").is_empty(),
            "must stay silent: {results:?}"
        );
    }

    /// Negative pin for the removed `non-coherent-filename` finding: a
    /// copy of the fcprobe fixture under a name that does not match its
    /// name/version/release stays silent.
    #[test]
    fn killed_non_coherent_filename_stays_absent() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let bytes = std::fs::read(&src).expect("read fixture");
        let tmp = tempfile::tempdir().expect("tmpdir for renamed rpm");
        let rpm_path = tmp.path().join("renamed-9.9-9.noarch.rpm");
        std::fs::write(&rpm_path, &bytes).expect("write renamed rpm");
        let pkg = Pkg::open(&rpm_path, tmp.path(), true).expect("open renamed pkg");
        let results = run_check(&pkg);
        assert!(
            tag_hits(&results, "non-coherent-filename").is_empty(),
            "must stay silent: {results:?}"
        );
    }

    #[test]
    fn unreasonable_epoch_emits() {
        let (_tmp, pkg) = fixture_pkg("tags-highepoch-1.0-1.noarch.rpm");
        let config = test_config_with_epoch(true);
        let results = run_check_with(&config, &pkg);
        let hits = tag_hits(&results, "unreasonable-epoch");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(
            hits[0].1,
            "tags-highepoch.noarch: W: unreasonable-epoch 100"
        );
    }

    #[test]
    fn unreasonable_epoch_gated_when_use_epoch_false() {
        // Default config has UseEpoch=false: the Epoch already fires
        // E epoch-tag, and the warning must not ride along.
        let (_tmp, pkg) = fixture_pkg("tags-highepoch-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        assert!(
            tag_hits(&results, "unreasonable-epoch").is_empty(),
            "must stay silent: {results:?}"
        );
        assert_eq!(tag_hits(&results, "epoch-tag").len(), 1, "all: {results:?}");
    }

    #[test]
    fn forbidden_controlchar_in_changelog_emits() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-badchangelog-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        let hits = tag_hits(&results, "forbidden-controlchar-found");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": E: forbidden-controlchar-found"),
            "line: {}",
            hits[0].1
        );
        assert!(hits[0].1.contains("%changelog"), "line: {}", hits[0].1);
    }

    /// Negative pin for the deleted `not-standard-release-extension` finding:
    /// the port must stay silent where the reference would fire, and
    /// `cargo test` (not just the reference-coverage auditor) must catch
    /// a re-add.
    #[test]
    fn killed_not_standard_release_extension_stays_absent() {
        // The deleted test drove ReleaseExtension='hello$' on fcprobe; the
        // release no longer warns.
        let (_tmp, pkg) = fixture_pkg("fcprobe-1-1.noarch.rpm");
        let config = test_config_with(Some("hello$"));
        let results = run_check_with(&config, &pkg);
        assert!(
            tag_hits(&results, "not-standard-release-extension").is_empty(),
            "must stay silent: {results:?}"
        );
    }

    /// Negative pin for the deleted `no-group-tag` finding: a package with
    /// an empty Group tag must stay silent, and `cargo test` (not just the
    /// reference-coverage auditor) must catch a re-add.
    #[test]
    fn killed_no_group_tag_stays_absent() {
        // The filescheck fixtures ship no Group tag at all.
        let (_tmp, pkg) = fixture_pkg("filescheck-depmod-missing-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        assert!(
            tag_hits(&results, "no-group-tag").is_empty(),
            "must stay silent: {results:?}"
        );
    }

    /// Negative pin for the deleted `devel-package-with-non-devel-group`
    /// finding: a -devel package outside Development/ must stay silent,
    /// and `cargo test` (not just the reference-coverage auditor) must
    /// catch a re-add.
    #[test]
    fn killed_devel_package_with_non_devel_group_stays_absent() {
        // tags-group-devel is grouped as System/Libraries; the old emission fired
        // on exactly this shape.
        let (_tmp, pkg) = fixture_pkg("tags-group-devel-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        assert!(
            tag_hits(&results, "devel-package-with-non-devel-group").is_empty(),
            "must stay silent: {results:?}"
        );
    }

    fn test_config_with_epoch(use_epoch: bool) -> Config {
        // Same minimal keys as test_config_with, with an explicit UseEpoch.
        let mut config = Config::default();
        let tbl = &mut config.configuration;
        tbl.insert("UseEpoch".to_string(), toml::Value::Boolean(use_epoch));
        tbl.insert("MaxLineLength".to_string(), toml::Value::Integer(79));
        tbl.insert("ValidLicenses".to_string(), toml::Value::Array(vec![]));
        tbl.insert(
            "ValidLicenseExceptions".to_string(),
            toml::Value::Array(vec![]),
        );
        tbl.insert("InvalidRequires".to_string(), toml::Value::Array(vec![]));
        config.finalize().expect("fixture config");
        config
    }

    fn test_config_with_removed_keys() -> Config {
        // Same minimal keys as test_config_with_epoch, plus the removed
        // TagsCheck keys at values that fired the old findings.
        let mut config = Config::default();
        let tbl = &mut config.configuration;
        tbl.insert("UseEpoch".to_string(), toml::Value::Boolean(false));
        tbl.insert("MaxLineLength".to_string(), toml::Value::Integer(79));
        tbl.insert("ValidLicenses".to_string(), toml::Value::Array(vec![]));
        tbl.insert(
            "ValidLicenseExceptions".to_string(),
            toml::Value::Array(vec![]),
        );
        tbl.insert("InvalidRequires".to_string(), toml::Value::Array(vec![]));
        tbl.insert(
            "ForbiddenWords".to_string(),
            toml::Value::String("probe".to_string()),
        );
        tbl.insert(
            "UseVersionInChangelog".to_string(),
            toml::Value::Boolean(true),
        );
        config.finalize().expect("fixture config");
        config
    }

    #[test]
    fn epoch_tag_emits_when_use_epoch_false() {
        let (_tmp, pkg) = fixture_pkg("tags-highepoch-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        let hits = tag_hits(&results, "epoch-tag");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(hits[0].1, "tags-highepoch.noarch: E: epoch-tag 100");
    }

    #[test]
    fn epoch_tag_emits_for_small_epoch() {
        // Epoch 1 fires epoch-tag without unreasonable-epoch, isolating
        // the !use_epoch gate from the e > 99 gate.
        let (_tmp, pkg) = fixture_pkg("tags-smallepoch-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        let hits = tag_hits(&results, "epoch-tag");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(hits[0].1, "tags-smallepoch.noarch: E: epoch-tag 1");
        assert!(
            tag_hits(&results, "unreasonable-epoch").is_empty(),
            "must stay silent: {results:?}"
        );
    }

    #[test]
    fn epoch_tag_emits_for_explicit_zero() {
        // Explicit Epoch: 0 fires epoch-tag: the gate is the
        // presence of the tag (Some(0)), not its value, so zero
        // earns no exemption. An absent epoch would report
        // no-epoch-tag instead under UseEpoch, never epoch-tag.
        let (_tmp, pkg) = fixture_pkg("tags-zeroepoch-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        let hits = tag_hits(&results, "epoch-tag");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert_eq!(hits[0].1, "tags-zeroepoch.noarch: E: epoch-tag 0");
        assert!(
            tag_hits(&results, "unreasonable-epoch").is_empty(),
            "must stay silent: {results:?}"
        );
    }

    /// Negative pin for the deleted `summary-use-invalid-word` finding:
    /// a summary matching the configured ForbiddenWords must stay silent,
    /// and `cargo test` (not just the reference-coverage auditor) must
    /// catch a re-add.
    #[test]
    fn killed_summary_use_invalid_word_stays_absent() {
        // fcprobe's summary contains "probe", the configured word.
        let (_tmp, pkg) = fixture_pkg("fcprobe-1-1.noarch.rpm");
        let config = test_config_with_removed_keys();
        let results = run_check_with(&config, &pkg);
        assert!(
            tag_hits(&results, "summary-use-invalid-word").is_empty(),
            "must stay silent: {results:?}"
        );
    }

    /// Negative pin for the deleted `description-use-invalid-word`
    /// finding: a description line matching the configured
    /// ForbiddenWords must stay silent.
    #[test]
    fn killed_description_use_invalid_word_stays_absent() {
        // fcprobe's description contains "Probe", matching case-insensitively.
        let (_tmp, pkg) = fixture_pkg("fcprobe-1-1.noarch.rpm");
        let config = test_config_with_removed_keys();
        let results = run_check_with(&config, &pkg);
        assert!(
            tag_hits(&results, "description-use-invalid-word").is_empty(),
            "must stay silent: {results:?}"
        );
    }

    /// Negative pin for the deleted `no-version-in-last-changelog`
    /// finding: a last changelog entry without a version must stay
    /// silent even with UseVersionInChangelog set.
    #[test]
    fn killed_no_version_in_last_changelog_stays_absent() {
        let (_tmp, pkg) = fixture_pkg("tags-nochangelogversion-1.0-1.noarch.rpm");
        let config = test_config_with_removed_keys();
        let results = run_check_with(&config, &pkg);
        assert!(
            tag_hits(&results, "no-version-in-last-changelog").is_empty(),
            "must stay silent: {results:?}"
        );
    }

    #[test]
    fn epoch_tag_silent_when_use_epoch_true() {
        let (_tmp, pkg) = fixture_pkg("tags-highepoch-1.0-1.noarch.rpm");
        let config = test_config_with_epoch(true);
        let results = run_check_with(&config, &pkg);
        let hits = tag_hits(&results, "epoch-tag");
        assert_eq!(hits.len(), 0, "all: {results:?}");
    }

    #[test]
    fn epoch_tag_silent_without_epoch() {
        let (_tmp, pkg) = fixture_pkg("tags-emission-pins-1.0-1.noarch.rpm");
        let results = run_check(&pkg);
        let hits = tag_hits(&results, "epoch-tag");
        assert_eq!(hits.len(), 0, "all: {results:?}");
    }
}

#[cfg(test)]
mod rich_dep_emission_tests {
    use super::*;
    use crate::color::Color;
    use crate::pkg::dep::{DepInfo, RPMSENSE_EQUAL};
    use std::path::Path;

    fn rich_dep(name: &str) -> DepInfo {
        // What `gather_requires` produces for a rich header entry: the
        // whole expression in the name, flags 0, no EVR (verified against
        // rpm 6.1.0: `(foo or bar)` -> name=`(foo or bar)`, flags=0).
        DepInfo {
            name: name.to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        }
    }

    fn rich_test_config(invalid_requires: &[&str], use_epoch: bool) -> Config {
        let mut config = Config::default();
        let tbl = &mut config.configuration;
        tbl.insert("UseEpoch".to_string(), toml::Value::Boolean(use_epoch));
        tbl.insert("MaxLineLength".to_string(), toml::Value::Integer(79));
        tbl.insert("ValidLicenses".to_string(), toml::Value::Array(vec![]));
        tbl.insert(
            "ValidLicenseExceptions".to_string(),
            toml::Value::Array(vec![]),
        );
        tbl.insert(
            "InvalidRequires".to_string(),
            toml::Value::Array(
                invalid_requires
                    .iter()
                    .map(|s| toml::Value::String(s.to_string()))
                    .collect(),
            ),
        );
        config.finalize().expect("fixture config");
        config
    }

    fn rich_fixture_pkg(name: &str) -> Pkg {
        let rpm_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs")
            .join(name);
        Pkg::open(&rpm_path, &std::env::temp_dir(), true).expect("open fixture pkg")
    }

    fn run(pkg: &Pkg, config: &Config) -> Vec<(String, String)> {
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        let mut check = TagsCheck::new(config);
        check.check(pkg, config, &mut out);
        out.results().to_vec()
    }

    fn named<'a>(results: &'a [(String, String)], name: &str) -> Vec<&'a (String, String)> {
        results.iter().filter(|(n, _)| n == name).collect()
    }

    /// Emission-level pin for the two-locale fixture (plusky's #258 review).
    ///
    /// TagsCheck must run clean over the fixture in every locale: the
    /// fixture's localized fields are all well-formed, so the emission set
    /// is exactly these five fixture-hygiene findings. A de-locale
    /// regression in `tag_i18n_str` (e.g. reverting the `extensions: false`
    /// fix) resolves the de summary to the empty string, which trips
    /// `W: summary-not-capitalized de` -- verified by mutation. Pinning the
    /// full set catches that without depending on a firing finding.
    ///
    /// `mini_mode` keeps the test hermetic: the spellchecker degrades
    /// gracefully when no system hunspell dictionary exists, so without it
    /// the emission set would depend on the host (GitHub's Ubuntu images
    /// flag the German words, a bare Mac does not).
    #[test]
    fn tags_check_emission_on_two_locale_fixture() {
        let pkg = rich_fixture_pkg("i18n-two-locale-1.0-1.noarch.rpm");
        let mut config = rich_test_config(&[], false);
        config.mini_mode = true;
        let results = run(&pkg, &config);
        let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "invalid-license",
                "invalid-license-spellcheck",
                "no-url-tag"
            ],
            "unexpected emissions: {results:?}"
        );
        assert_eq!(
            results[0].1, "i18n-two-locale.noarch: E: invalid-license MIT",
            "level and detail pinned on the rendered line"
        );
    }

    /// Explicit negative pin for the deleted `no-packager-tag` finding:
    /// i18n-two-locale ships no Packager tag, so the exact-list assertion
    /// above already pins the absence; this names it for the auditor.
    #[test]
    fn killed_no_packager_tag_stays_absent() {
        let pkg = rich_fixture_pkg("i18n-two-locale-1.0-1.noarch.rpm");
        let mut config = rich_test_config(&[], false);
        config.mini_mode = true;
        let results = run(&pkg, &config);
        assert!(
            !results.iter().any(|(n, _)| n == "no-packager-tag"),
            "must stay silent: {results:?}"
        );
    }

    #[test]
    fn deeply_nested_header_does_not_crash_check() {
        // Regression: `gather_requires` copies REQUIRENAME verbatim, so a
        // package-controlled header string with thousands of nested parens
        // drove the recursive parser into a stack overflow (SIGABRT) inside
        // the check. Past the depth budget the expression degrades to the
        // raw name, so the full check stays silent and alive.
        let evil = format!("{}a{}", "(".repeat(2000), ")".repeat(2000));
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires.push(rich_dep(&evil));
        let config = rich_test_config(&["^badpkg$"], false);
        let results = run(&pkg, &config);
        assert!(
            named(&results, "invalid-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn invalid_dependency_matches_rich_leaf() {
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires.push(rich_dep("(badpkg or goodpkg)"));
        let config = rich_test_config(&["^badpkg$"], false);
        let results = run(&pkg, &config);
        let hits = named(&results, "invalid-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": E: invalid-dependency"),
            "line: {}",
            hits[0].1
        );
        assert!(hits[0].1.ends_with(" badpkg"), "line: {}", hits[0].1);
    }

    #[test]
    fn devel_dependency_matches_rich_leaf() {
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        assert!(
            !is_match(devel_regex(), &pkg.name),
            "fixture must not be a devel package"
        );
        pkg.requires.push(rich_dep("(somelib-devel or plainx)"));
        let config = rich_test_config(&[], false);
        let results = run(&pkg, &config);
        let hits = named(&results, "devel-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": E: devel-dependency"),
            "line: {}",
            hits[0].1
        );
        assert!(hits[0].1.ends_with(" somelib-devel"), "line: {}", hits[0].1);
    }

    #[test]
    fn devel_dependency_biarch_devel_requirer_is_silent() {
        // Biarch/flavored devel packages carry the devel keyword as a
        // hyphen-delimited component rather than a name suffix. They are
        // devel packages, so requiring devel files must not trip
        // devel-dependency.
        let config = rich_test_config(&[], false);
        for (requirer, dep) in [
            ("libgcrypt-devel-32bit", "libgcrypt-devel"),
            ("qwt6-qt5-devel-doc", "qwt6-qt5-devel"),
            ("dapl-debug-libs", "dapl-debug"),
            ("mumps-mvapich2-devel-static-compat", "mumps-devel-static"),
        ] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.name = requirer.to_string();
            pkg.requires = vec![plain_dep(dep)];
            let results = run(&pkg, &config);
            assert!(
                named(&results, "devel-dependency").is_empty(),
                "requirer {requirer}: {results:?}"
            );
        }
    }

    #[test]
    fn devel_dependency_python_module_headers_leaf_is_silent() {
        // In the versioned-Python namespace a `*-headers` name is a
        // runtime Python module, not a header package (issue #283,
        // upstream rpmlint #1091). The credit is on the leaf, so it
        // holds for any requirer.
        let config = rich_test_config(&[], false);
        for (requirer, dep) in [
            ("python313-sortinghat", "python313-django-cors-headers"),
            ("python314-sortinghat", "python314-django-cors-headers"),
            ("some-tool", "python313-kiss-headers"),
        ] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.name = requirer.to_string();
            pkg.requires = vec![plain_dep(dep)];
            let results = run(&pkg, &config);
            assert!(
                named(&results, "devel-dependency").is_empty(),
                "requirer {requirer} dep {dep}: {results:?}"
            );
        }
    }

    #[test]
    fn devel_dependency_python_headers_near_misses_still_fire() {
        let config = rich_test_config(&[], false);
        for (requirer, dep) in [
            // The interpreter's own devel package is a real devel leaf.
            ("python313-sortinghat", "python313-devel"),
            // No version digits: outside the versioned-Python namespace.
            ("sortinghat", "python3-django-cors-headers"),
            // Non-Python `-headers` packages are genuine header packages.
            ("some-tool", "suse-libsgx-headers"),
            ("some-tool", "vulkan-headers"),
        ] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.name = requirer.to_string();
            pkg.requires = vec![plain_dep(dep)];
            let results = run(&pkg, &config);
            let hits = named(&results, "devel-dependency");
            assert_eq!(hits.len(), 1, "requirer {requirer} dep {dep}: {results:?}");
            assert!(hits[0].1.ends_with(dep), "line: {}", hits[0].1);
        }
        // A credited leaf does not consume the latch: a later real
        // devel requirement still fires.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.name = "python313-sortinghat".to_string();
        pkg.requires = vec![
            plain_dep("python313-django-cors-headers"),
            plain_dep("glibc-devel"),
        ];
        let results = run(&pkg, &config);
        let hits = named(&results, "devel-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(hits[0].1.ends_with(" glibc-devel"), "line: {}", hits[0].1);
    }

    #[test]
    fn devel_dependency_rebuild_source_anchor_is_silent() {
        // `*-rebuild` packages are empty anchors; their `-source`
        // requirement is the tree they trigger rebuilds against.
        let config = rich_test_config(&[], false);
        for (requirer, dep) in [
            ("perf-rebuild", "kernel-source"),
            ("cpupower-rebuild", "kernel-source"),
        ] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.name = requirer.to_string();
            pkg.requires = vec![plain_dep(dep)];
            let results = run(&pkg, &config);
            assert!(
                named(&results, "devel-dependency").is_empty(),
                "requirer {requirer}: {results:?}"
            );
        }
    }

    #[test]
    fn devel_dependency_rebuild_near_misses_still_fire() {
        let config = rich_test_config(&[], false);
        for (requirer, dep) in [
            // A `-rebuild` anchor on a real devel package still fires.
            ("perf-rebuild", "glibc-devel"),
            // A non-anchor requirer on a source tree still fires.
            ("some-tool", "kernel-source"),
            // `-debugsource` is not the `-source` anchor leaf.
            ("perf-rebuild", "glibc-debugsource"),
        ] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.name = requirer.to_string();
            pkg.requires = vec![plain_dep(dep)];
            let results = run(&pkg, &config);
            let hits = named(&results, "devel-dependency");
            assert_eq!(hits.len(), 1, "requirer {requirer} dep {dep}: {results:?}");
            assert!(hits[0].1.ends_with(dep), "line: {}", hits[0].1);
        }
        // The credited anchor leaf does not consume the latch.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.name = "perf-rebuild".to_string();
        pkg.requires = vec![plain_dep("kernel-source"), plain_dep("glibc-devel")];
        let results = run(&pkg, &config);
        let hits = named(&results, "devel-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(hits[0].1.ends_with(" glibc-devel"), "line: {}", hits[0].1);
    }

    #[test]
    fn devel_dependency_jmods_requirer_is_silent() {
        // JDK jmods are development modules split out of the `-devel`
        // package they require.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.name = "java-21-openjdk-jmods".to_string();
        pkg.requires = vec![plain_dep("java-21-openjdk-devel")];
        let config = rich_test_config(&[], false);
        let results = run(&pkg, &config);
        assert!(
            named(&results, "devel-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn devel_dependency_jmods_near_misses_still_fire() {
        let config = rich_test_config(&[], false);
        for requirer in ["java-21-openjdk-headless", "some-jmod"] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.name = requirer.to_string();
            pkg.requires = vec![plain_dep("java-21-openjdk-devel")];
            let results = run(&pkg, &config);
            let hits = named(&results, "devel-dependency");
            assert_eq!(hits.len(), 1, "requirer {requirer}: {results:?}");
        }
    }

    #[test]
    fn devel_dependency_patterns_underscore_devel_requirer_is_silent() {
        // Pattern packages carry the devel flavour as an
        // underscore-appended component.
        let config = rich_test_config(&[], false);
        for (requirer, dep) in [
            ("patterns-kde-devel_qt5", "libqt5-qtbase-common-devel"),
            ("patterns-kde-devel_qt6", "qt6-base-common-devel"),
        ] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.name = requirer.to_string();
            pkg.requires = vec![plain_dep(dep)];
            let results = run(&pkg, &config);
            assert!(
                named(&results, "devel-dependency").is_empty(),
                "requirer {requirer}: {results:?}"
            );
        }
    }

    #[test]
    fn devel_dependency_underscore_near_misses_still_fire() {
        let config = rich_test_config(&[], false);
        for requirer in [
            // Keyword-underscore inside an ordinary word, not a
            // patterns flavour component.
            "ruby4.0-rubygem-debug_inspector",
            // Underscore flavour but not a pattern package.
            "foo-devel_bar",
        ] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.name = requirer.to_string();
            pkg.requires = vec![plain_dep("somelib-devel")];
            let results = run(&pkg, &config);
            let hits = named(&results, "devel-dependency");
            assert_eq!(hits.len(), 1, "requirer {requirer}: {results:?}");
        }
    }

    #[test]
    fn devel_dependency_plain_devel_require_still_fires() {
        // A genuine runtime package requiring a devel package still trips
        // the finding.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        assert!(
            !is_match(devel_regex(), &pkg.name),
            "fixture must not be a devel package"
        );
        pkg.requires = vec![plain_dep("somelib-devel")];
        let config = rich_test_config(&[], false);
        let results = run(&pkg, &config);
        let hits = named(&results, "devel-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": E: devel-dependency"),
            "line: {}",
            hits[0].1
        );
        assert!(hits[0].1.ends_with(" somelib-devel"), "line: {}", hits[0].1);
    }

    #[test]
    fn devel_dependency_cross_family_pairs_are_silent() {
        // Issue #861: within one cross toolchain family the target
        // sys-root devel package is the compiler's runtime data, so a
        // same-family pair must not trip devel-dependency. The pairs
        // are the measured Factory population (sweep
        // run-20261022-857d5ece), plus the multi-component tool
        // spelling (gcc13-bootstrap) from review probes.
        // The winpthreads pairs are pinned without a measured
        // instance: no winpthreads pair occurs in the sweep
        // population (its MinGW packages require headers only); the
        // credit covers them because the leaf set is the bitness
        // family's sys-root pair by construction.
        let config = rich_test_config(&[], false);
        for (requirer, dep) in [
            ("cross-aarch64-gcc13", "cross-aarch64-glibc-devel"),
            ("cross-aarch64-gcc13-bootstrap", "cross-aarch64-glibc-devel"),
            (
                "cross-riscv64-elf-gcc13-bootstrap",
                "cross-riscv64-newlib-devel",
            ),
            ("cross-amdgcn-gcc13", "cross-amdgcn-newlib-devel"),
            ("cross-arm-none-gcc14", "cross-arm-none-newlib-devel"),
            ("cross-hppa-gcc14", "cross-hppa-glibc-devel"),
            ("cross-loongarch64-gcc14", "cross-loongarch64-glibc-devel"),
            ("cross-nvptx-gcc7", "cross-nvptx-newlib-devel"),
            ("cross-ppc64le-gcc13", "cross-ppc64le-glibc-devel"),
            ("cross-riscv64-elf-gcc13", "cross-riscv64-newlib-devel"),
            ("cross-riscv64-gcc13", "cross-riscv64-glibc-devel"),
            ("cross-rx-gcc15", "cross-rx-newlib-devel"),
            ("cross-s390x-gcc16", "cross-s390x-glibc-devel"),
            ("mingw32-cross-gcc", "mingw32-headers"),
            ("mingw32-cross-gcc-bootstrap", "mingw32-headers"),
            ("mingw32-runtime", "mingw32-headers"),
            ("mingw32-gcc", "mingw32-winpthreads-devel"),
            ("mingw64-cross-gcc", "mingw64-headers"),
            ("mingw64-cross-gcc-bootstrap", "mingw64-headers"),
            ("mingw64-runtime", "mingw64-headers"),
            ("mingw64-gcc", "mingw64-winpthreads-devel"),
        ] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.name = requirer.to_string();
            pkg.requires = vec![plain_dep(dep)];
            let results = run(&pkg, &config);
            assert!(
                named(&results, "devel-dependency").is_empty(),
                "requirer {requirer} dep {dep}: {results:?}"
            );
        }
    }

    #[test]
    fn devel_dependency_cross_family_non_elf_libc_collision_is_silent() {
        // A requirer name without the `-elf` spelling carries no
        // libc component, so its matching is on the target alone and
        // either libc leaf on that target credits. This pins the
        // collision explicitly: cross-riscv64-gcc13's measured pair
        // is the glibc leaf, and the newlib leaf on the same target
        // stays silent too (likewise in the other direction, a
        // newlib-family target crediting its glibc leaf). The `-elf`
        // spelling is the only name form that encodes a libc, and
        // there the libc is part of the pair — see the near-miss
        // pin for cross-riscv64-elf-gcc13 on the glibc leaf.
        let config = rich_test_config(&[], false);
        for (requirer, dep) in [
            ("cross-riscv64-gcc13", "cross-riscv64-newlib-devel"),
            ("cross-aarch64-gcc13", "cross-aarch64-newlib-devel"),
            ("cross-arm-none-gcc14", "cross-arm-none-glibc-devel"),
            ("cross-rx-gcc15", "cross-rx-glibc-devel"),
        ] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.name = requirer.to_string();
            pkg.requires = vec![plain_dep(dep)];
            let results = run(&pkg, &config);
            assert!(
                named(&results, "devel-dependency").is_empty(),
                "requirer {requirer} dep {dep}: {results:?}"
            );
        }
    }

    #[test]
    fn devel_dependency_cross_family_rich_leaf_is_silent() {
        // The credit applies per rich-dep leaf, like the finding.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.name = "cross-aarch64-gcc13".to_string();
        pkg.requires = vec![rich_dep("(cross-aarch64-glibc-devel or plainx)")];
        let config = rich_test_config(&[], false);
        let results = run(&pkg, &config);
        assert!(
            named(&results, "devel-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn devel_dependency_cross_family_near_misses_still_fire() {
        // The credit is a genuine sys-root leaf only: a different
        // target's sys-root devel package, a same-target devel match
        // that is not a sys-root leaf (a library's -static, binutils'
        // or the compiler's own -devel), a runtime package requiring
        // its own devel package, the wrong libc's sys-root package
        // for an -elf (newlib) toolchain, a MinGW library devel
        // package, a target that is only a prefix of the other
        // side's target (in either direction), a host devel package
        // required by a cross package, a cross devel package required
        // by a host package, a cross requirer on a MinGW leaf, a
        // MinGW requirer on a cross leaf, and the other MinGW
        // bitness all keep firing.
        let config = rich_test_config(&[], false);
        for (requirer, dep) in [
            ("cross-aarch64-gcc13", "cross-s390x-glibc-devel"),
            ("cross-aarch64-gcc13", "cross-aarch64-foo-static"),
            ("cross-aarch64-gcc13", "cross-aarch64-binutils-devel"),
            ("cross-aarch64-gcc13", "cross-aarch64-gcc13-devel"),
            ("cross-aarch64-glibc", "cross-aarch64-glibc-devel"),
            ("cross-riscv64-elf-gcc13", "cross-riscv64-glibc-devel"),
            ("mingw64-gcc", "mingw64-foo-devel"),
            ("mingw32-runtime", "mingw32-foo-devel"),
            ("cross-arm-none-gcc14", "cross-arm-glibc-devel"),
            ("cross-arm-gcc13", "cross-arm-none-newlib-devel"),
            ("cross-riscv64-elf-gcc13", "cross-aarch64-glibc-devel"),
            ("cross-aarch64-gcc13", "glibc-devel"),
            ("cross-aarch64-gcc13", "mingw64-headers"),
            ("someapp", "cross-aarch64-glibc-devel"),
            ("someapp", "mingw64-headers"),
            ("mingw32-cross-gcc", "mingw64-headers"),
            ("mingw64-gcc", "zlib-devel"),
            ("mingw64-cross-gcc", "cross-aarch64-glibc-devel"),
        ] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.name = requirer.to_string();
            pkg.requires = vec![plain_dep(dep)];
            let results = run(&pkg, &config);
            let hits = named(&results, "devel-dependency");
            assert_eq!(hits.len(), 1, "requirer {requirer} dep {dep}: {results:?}");
            assert!(
                hits[0].1.ends_with(&format!(" {dep}")),
                "requirer {requirer}: line: {}",
                hits[0].1
            );
        }
    }

    #[test]
    fn devel_dependency_credited_leaf_does_not_consume_the_latch() {
        // The credit is per leaf: a same-family sys-root devel
        // requirement followed by a host devel requirement still
        // fires, on the host leaf.
        let config = rich_test_config(&[], false);
        for (requirer, credited, host) in [
            (
                "cross-aarch64-gcc13",
                "cross-aarch64-glibc-devel",
                "somelib-devel",
            ),
            ("mingw64-runtime", "mingw64-headers", "zlib-devel"),
        ] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.name = requirer.to_string();
            pkg.requires = vec![plain_dep(credited), plain_dep(host)];
            let results = run(&pkg, &config);
            let hits = named(&results, "devel-dependency");
            assert_eq!(hits.len(), 1, "requirer {requirer}: {results:?}");
            assert!(
                hits[0].1.ends_with(&format!(" {host}")),
                "requirer {requirer}: line: {}",
                hits[0].1
            );
        }
    }

    #[test]
    fn cross_family_spelling_rules_900() {
        // The pair predicate's spelling rules, pinned directly. The
        // `-elf` strip is by spelling — any `-elf` target, not
        // only the measured riscv64-elf family — and the `-elf`
        // pair carries its newlib libc; a requirer without the
        // `-elf` spelling credits either libc on its target; `-none`
        // is never stripped, because the sys-root packages keep it
        // in the target.
        let credits = |requirer: &str, leaf: &str| family_requirer(requirer).credits(leaf);
        assert!(credits(
            "cross-riscv64-elf-gcc13",
            "cross-riscv64-newlib-devel"
        ));
        assert!(credits("cross-mips-elf-gcc12", "cross-mips-newlib-devel"));
        assert!(!credits("cross-mips-elf-gcc12", "cross-mips-glibc-devel"));
        assert!(credits("cross-riscv64-gcc13", "cross-riscv64-newlib-devel"));
        assert!(credits("cross-riscv64-gcc13", "cross-riscv64-glibc-devel"));
        assert!(!credits("cross-arm-none-gcc14", "cross-arm-newlib-devel"));
        assert!(credits(
            "cross-arm-none-gcc14",
            "cross-arm-none-newlib-devel"
        ));
        // The two families never credit across, and the MinGW leaf
        // set is bitness-exact.
        assert!(credits("mingw64-gcc", "mingw64-winpthreads-devel"));
        assert!(!credits("mingw64-gcc", "mingw32-winpthreads-devel"));
        assert!(!credits("cross-aarch64-gcc13", "mingw64-headers"));
        assert!(!credits("mingw64-cross-gcc", "cross-aarch64-glibc-devel"));
        assert!(!credits("someapp", "cross-aarch64-glibc-devel"));
    }

    #[test]
    fn devel_infix_regex_matches_components_not_substrings() {
        // The infix keyword must be hyphen-delimited: `foo-develx` and
        // `foo-mydevel` are not devel packages.
        for name in [
            "libgcrypt-devel-32bit",
            "qwt-devel-doc",
            "dapl-debug-libs",
            "foo-headers-x",
            "foo-static-y",
        ] {
            assert!(is_match(devel_infix_regex(), name), "name {name}");
        }
        for name in [
            "foo-develx",
            "foo-mydevel",
            "foo-profile",
            "python3-foo",
            "libfoo2",
        ] {
            assert!(!is_match(devel_infix_regex(), name), "name {name}");
        }
    }

    /// Negative pin for the removed `requires-on-release` finding: a
    /// rich dependency whose leaf pins a release stays silent.
    #[test]
    fn killed_requires_on_release_stays_absent() {
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires.push(rich_dep("(relfoo = 1.0-2 or relbar)"));
        let config = rich_test_config(&[], false);
        let results = run(&pkg, &config);
        assert!(
            named(&results, "requires-on-release").is_empty(),
            "must stay silent: {results:?}"
        );
    }

    #[test]
    fn no_epoch_in_dependency_uses_leaf_constraint() {
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires.push(rich_dep("(epochfoo >= 1.0 or plainy)"));
        let config = rich_test_config(&[], true);
        let results = run(&pkg, &config);
        let hits = named(&results, "no-epoch-in-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": W: no-epoch-in-dependency"),
            "line: {}",
            hits[0].1
        );
        assert!(
            hits[0].1.ends_with(" epochfoo >= 1.0"),
            "line: {}",
            hits[0].1
        );
    }

    #[test]
    fn qualifier_name_matches_literally_like_reference() {
        // `qux(meta)` keeps its literal name for analyses (the reference
        // matches the raw string too); the qualifier is only additionally
        // structured on the leaf.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires.push(rich_dep("qux(meta)"));
        let config = rich_test_config(&["^qux$"], false);
        let results = run(&pkg, &config);
        assert!(
            named(&results, "invalid-dependency").is_empty(),
            "all: {results:?}"
        );
        let config = rich_test_config(&["^qux\\(meta\\)$"], false);
        let results = run(&pkg, &config);
        let hits = named(&results, "invalid-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(hits[0].1.ends_with(" qux(meta)"), "line: {}", hits[0].1);
    }
    // Per-finding emission pins for the dependency-shape findings, via
    // field mutation on the hand-built fcprobe fixture (never a distro
    // package): the header stays real, only the dep under test is synthetic.

    fn plain_dep(name: &str) -> DepInfo {
        DepInfo {
            name: name.to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        }
    }

    fn generated_dep(name: &str) -> DepInfo {
        DepInfo {
            name: name.to_string(),
            flags: RPMSENSE_FIND_REQUIRES,
            epoch: None,
            version: None,
            release: None,
        }
    }

    fn versioned_dep(name: &str, version: &str) -> DepInfo {
        DepInfo {
            name: name.to_string(),
            flags: RPMSENSE_EQUAL,
            epoch: None,
            version: Some(version.to_string()),
            release: None,
        }
    }

    fn flagged_dep(name: &str, flags: u32, version: &str) -> DepInfo {
        DepInfo {
            name: name.to_string(),
            flags,
            epoch: None,
            version: Some(version.to_string()),
            release: None,
        }
    }

    fn so_file() -> crate::pkg::pkgfile::PkgFile {
        crate::pkg::pkgfile::PkgFile {
            name: "/usr/lib64/libtags-missingdep.so".to_string(),
            path: "/usr/lib64/libtags-missingdep.so".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn useless_provides_emits() {
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.provides = vec![plain_dep("selfprov"), versioned_dep("selfprov", "1.0")];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "useless-provides");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": E: useless-provides"),
            "line: {}",
            hits[0].1
        );
        assert!(hits[0].1.ends_with(" selfprov"), "line: {}", hits[0].1);
    }

    fn provides_file(path: &str, provides: Vec<DepInfo>) -> crate::pkg::pkgfile::PkgFile {
        crate::pkg::pkgfile::PkgFile {
            name: path.to_string(),
            path: path.to_string(),
            provides,
            ..Default::default()
        }
    }

    #[test]
    fn useless_provides_generator_pair_is_warning() {
        // Both forms of the duplicated name are attributed to shipped
        // files (FILEPROVIDE): the pair is the dependency generator's
        // doing, so it is a warning. The detail stays
        // the name only, so severity pairing against the reference
        // (same detail at E) works.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.provides = vec![plain_dep("perl(Foo)"), versioned_dep("perl(Foo)", "1.0")];
        pkg.files = vec![
            provides_file(
                "/usr/lib/perl5/Foo.pm",
                vec![versioned_dep("perl(Foo)", "1.0")],
            ),
            provides_file("/usr/lib/perl5/Foo/Bar.pm", vec![plain_dep("perl(Foo)")]),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "useless-provides");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": W: useless-provides"),
            "line: {}",
            hits[0].1
        );
        assert!(hits[0].1.ends_with(" perl(Foo)"), "line: {}", hits[0].1);
    }

    #[test]
    fn useless_provides_manual_evr_alongside_generated_stays_error() {
        // The generated pair (unversioned + = 1.0) is file-covered, but
        // the package also carries a hand-written = 2.0 for the same
        // name: a duplicate involving a manual provide stays an error.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.provides = vec![
            plain_dep("perl(Foo)"),
            versioned_dep("perl(Foo)", "1.0"),
            versioned_dep("perl(Foo)", "2.0"),
        ];
        pkg.files = vec![
            provides_file(
                "/usr/lib/perl5/Foo.pm",
                vec![versioned_dep("perl(Foo)", "1.0")],
            ),
            provides_file("/usr/lib/perl5/Foo/Bar.pm", vec![plain_dep("perl(Foo)")]),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "useless-provides");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": E: useless-provides"),
            "line: {}",
            hits[0].1
        );
        assert!(hits[0].1.ends_with(" perl(Foo)"), "line: {}", hits[0].1);
    }

    #[test]
    fn useless_provides_evr_mismatch_stays_error() {
        // Boundary pin: the versioned package EVR (= 2.0) is not the
        // file-covered EVR (= 1.0), so name-only attribution must not
        // downgrade the finding.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.provides = vec![plain_dep("perl(Foo)"), versioned_dep("perl(Foo)", "2.0")];
        pkg.files = vec![
            provides_file(
                "/usr/lib/perl5/Foo.pm",
                vec![versioned_dep("perl(Foo)", "1.0")],
            ),
            provides_file("/usr/lib/perl5/Foo/Bar.pm", vec![plain_dep("perl(Foo)")]),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "useless-provides");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": E: useless-provides"),
            "line: {}",
            hits[0].1
        );
        assert!(hits[0].1.ends_with(" perl(Foo)"), "line: {}", hits[0].1);
    }

    #[test]
    fn useless_provides_unattributed_unversioned_stays_error() {
        // Only the versioned form is file-attributed: the unversioned
        // form is a hand-written provide, so the pair stays an error
        // even though the name looks like a generator name.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.provides = vec![plain_dep("perl(Foo)"), versioned_dep("perl(Foo)", "1.0")];
        pkg.files = vec![provides_file(
            "/usr/lib/perl5/Foo.pm",
            vec![versioned_dep("perl(Foo)", "1.0")],
        )];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "useless-provides");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": E: useless-provides"),
            "line: {}",
            hits[0].1
        );
        assert!(hits[0].1.ends_with(" perl(Foo)"), "line: {}", hits[0].1);
    }

    #[test]
    fn useless_provides_unattributed_versioned_stays_error() {
        // Only the unversioned form is file-attributed (the generator
        // extracted no version from the shipped files): the versioned
        // form is hand-written, so the pair stays an error.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.provides = vec![plain_dep("perl(Foo)"), versioned_dep("perl(Foo)", "1.0")];
        pkg.files = vec![provides_file(
            "/usr/lib/perl5/Foo.pm",
            vec![plain_dep("perl(Foo)")],
        )];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "useless-provides");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": E: useless-provides"),
            "line: {}",
            hits[0].1
        );
        assert!(hits[0].1.ends_with(" perl(Foo)"), "line: {}", hits[0].1);
    }

    #[test]
    fn useless_provides_version_only_is_silent() {
        // The sharp edge from the reference test: a versioned-only
        // self-provide is legitimate and must stay silent.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.provides = vec![versioned_dep("fuse-common", "1.0")];
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "useless-provides").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn check_group_with_macro_emits() {
        // Kills the neutered-`check_group` mutant (and, through it, the
        // `unexpanded_macro(s)` neuters): the Group value reaches the macro
        // probe directly, no header needed.
        let pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        let config = rich_test_config(&[], false);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        TagsCheck::new(&config).check_group(&pkg, &mut out, "Amusements %foo");
        let results = out.results().to_vec();
        let hits = named(&results, "unexpanded-macro");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": W: unexpanded-macro"),
            "line: {}",
            hits[0].1
        );
        assert!(hits[0].1.contains("Group"), "line: {}", hits[0].1);
        assert!(hits[0].1.ends_with(" %foo"), "line: {}", hits[0].1);
    }

    #[test]
    fn obsoletes_macro_emitted_once() {
        // An Obsoletes entry carrying macros emits one finding per macro:
        // the entry is probed for unexpanded macros in exactly one place.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        // A second entry proves per-entry probing survived the dedup:
        // each entry's macros still emit, exactly once each.
        pkg.obsoletes = vec![
            DepInfo {
                name: "foo".to_string(),
                flags: RPMSENSE_LESS,
                epoch: None,
                version: Some("%{version}".to_string()),
                release: Some("%{release}".to_string()),
            },
            DepInfo {
                name: "bar".to_string(),
                flags: RPMSENSE_LESS,
                epoch: None,
                version: Some("%{version}".to_string()),
                release: None,
            },
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        let obs: Vec<_> = named(&results, "unexpanded-macro")
            .into_iter()
            .filter(|(_, line)| line.contains("Obsoletes foo <"))
            .collect();
        assert_eq!(obs.len(), 2, "all: {results:?}");
        let bar: Vec<_> = named(&results, "unexpanded-macro")
            .into_iter()
            .filter(|(_, line)| line.contains("Obsoletes bar <"))
            .collect();
        assert_eq!(bar.len(), 1, "all: {results:?}");
    }

    #[test]
    fn check_no_epoch_in_tags_emits() {
        // Kills the neutered-`check_no_epoch_in_tags` mutant: a versioned
        // obsoletion without epoch must warn when UseEpoch holds.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.obsoletes = vec![versioned_dep("oldpkg", "1.0")];
        let results = run(&pkg, &rich_test_config(&[], true));
        let hits = named(&results, "no-epoch-in-obsoletes");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": W: no-epoch-in-obsoletes"),
            "line: {}",
            hits[0].1
        );
    }

    #[test]
    fn explicit_lib_dependency_emits() {
        // #851: the explicit name is the conventional package name of a
        // soname the package's own binaries already generate a dependency
        // on, so the explicit requirement duplicates it and fires.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![plain_dep("libfoo1"), generated_dep("libfoo.so.1()(64bit)")];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "explicit-lib-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": E: explicit-lib-dependency"),
            "line: {}",
            hits[0].1
        );
        assert!(hits[0].1.ends_with(" libfoo1"), "line: {}", hits[0].1);
    }

    #[test]
    fn explicit_lib_dependency_dash_form_fires() {
        // The `lib<stem>-<major>` spelling of the convention
        // (libsqlite3-0 provides libsqlite3.so.0) is the same redundancy.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libsqlite3-0"),
            generated_dep("libsqlite3.so.0()(64bit)"),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "explicit-lib-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(hits[0].1.ends_with(" libsqlite3-0"), "line: {}", hits[0].1);
    }

    #[test]
    fn explicit_lib_dependency_dotted_soversion_fires() {
        // #885 review: a dotted soversion maps by the full version,
        // dots to underscores — libfoo.so.10.0.0 is provided by
        // libfoo10_0_0 (the SLPP construction BinariesCheck uses), so
        // an explicit requirement on that name duplicates the
        // dependency the package's own binaries already generate.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libfoo10_0_0"),
            generated_dep("libfoo.so.10.0.0()(64bit)"),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "explicit-lib-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(hits[0].1.ends_with(" libfoo10_0_0"), "line: {}", hits[0].1);
    }

    #[test]
    fn explicit_lib_dependency_dotted_soversion_dash_form_fires() {
        // The dash spelling of the same full-version name.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libfoo-10_0_0"),
            generated_dep("libfoo.so.10.0.0()(64bit)"),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "explicit-lib-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(hits[0].1.ends_with(" libfoo-10_0_0"), "line: {}", hits[0].1);
    }

    #[test]
    fn explicit_lib_dependency_major_only_name_for_dotted_soversion_is_silent() {
        // #885 review: libfoo10 is the name the major-only extraction
        // derives from libfoo.so.10.0.0, but no SLPP package carries
        // it — the full-version mapping derives libfoo10_0_0 — so the
        // requirement proves no redundancy and stays silent.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libfoo10"),
            generated_dep("libfoo.so.10.0.0()(64bit)"),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "explicit-lib-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn explicit_lib_dependency_stem_version_package_fires() {
        // #885 review, the libdb shape: the version sits in the stem
        // and the soname carries no soversion of its own — libdb-4.8.so
        // is provided by libdb-4_8, dots folded to underscores.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libdb-4_8"),
            generated_dep("libdb-4.8.so()(64bit)"),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "explicit-lib-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(hits[0].1.ends_with(" libdb-4_8"), "line: {}", hits[0].1);
    }

    #[test]
    fn explicit_lib_dependency_without_generated_soname_is_silent() {
        // #851, the ctypes class: python-libnacl requires libsodium26
        // precisely because no binary links libsodium — no generated
        // soname dependency exists for it, so the explicit requirement
        // is the only expression of a real dependency. A generated
        // dependency on an unrelated library (libc) does not make it
        // redundant either: the match is by library, not by presence.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libsodium26"),
            generated_dep("libc.so.6()(64bit)"),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "explicit-lib-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn explicit_lib_dependency_tools_package_is_silent() {
        // #851: clevis-luks requires libpwquality-tools because it
        // invokes the tools at runtime. Even with a generated soname
        // dependency on the library itself, the -tools package is not
        // the library package, so the requirement is not redundant.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libpwquality-tools"),
            generated_dep("libpwquality.so.1()(64bit)"),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "explicit-lib-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn explicit_lib_dependency_data_companion_is_silent() {
        // #851: fcitx5-libthai requires libthai-data, the data companion
        // of the library its binaries link. The companion carries no
        // soname and is not the library package, so linking the library
        // does not make the data requirement redundant.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libthai-data"),
            generated_dep("libthai.so.0()(64bit)"),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "explicit-lib-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn explicit_lib_dependency_flavoured_package_is_silent() {
        // #851: the explicit name pins a flavour of the library
        // (libopenblas_pthreads0, not libopenblas0): the generated
        // soname dependency is satisfiable by any flavour, so the pin
        // carries information the soname dependency does not.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libopenblas_pthreads0"),
            generated_dep("libopenblas.so.0()(64bit)"),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "explicit-lib-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn explicit_lib_dependency_bare_stem_package_is_silent() {
        // #851: the bare lib<stem> name is a different package from the
        // library package (the libnbd tools package vs libnbd0, which
        // provides libnbd.so.0), so a generated soname dependency does
        // not make a requirement on it redundant.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![plain_dep("libnbd"), generated_dep("libnbd.so.0()(64bit)")];
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "explicit-lib-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn explicit_lib_dependency_nss_module_is_silent() {
        // #851: icmpinfo/ntpsec/uucp require libnss_usrfiles2, an NSS
        // module package glibc loads at runtime. Their binaries link
        // glibc only; nothing generates a dependency on the module's
        // soname, so the explicit requirement stands alone.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libnss_usrfiles2"),
            generated_dep("libc.so.6()(64bit)"),
            generated_dep("ld-linux-x86-64.so.2()(64bit)"),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "explicit-lib-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn explicit_lib_dependency_versioned_so_is_silent() {
        // The #1091 fuzzy-lib heuristic: a versioned .so leaf is not an
        // explicit unversioned lib dependency.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![plain_dep("libexplicit.so.2")];
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "explicit-lib-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn explicit_lib_dependency_non_lib_suffix_is_silent() {
        // appstream-glib is required for its appstream-util binary, not
        // its library; the reference fires on the "lib" suffix, we do not.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![plain_dep("appstream-glib")];
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "explicit-lib-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn explicit_lib_dependency_symbol_capability_is_silent() {
        // #753: lib<name>__<symbol> is a symbol capability provided by a
        // library package, not a library package name. uuidd requires
        // libuuid__uuid_generate_time_cont in exactly this shape to pin
        // the libuuid ABI across updates (a seamless-restart requirement,
        // documented in the spec); the reference fires on it, we
        // deliberately do not.
        let config = rich_test_config(&[], false);
        for cap in [
            "libuuid__uuid_generate_time_cont",
            "libfoo__some_exported_symbol",
        ] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.requires = vec![plain_dep(cap)];
            let results = run(&pkg, &config);
            assert!(
                named(&results, "explicit-lib-dependency").is_empty(),
                "capability {cap}: {results:?}"
            );
        }
    }

    #[test]
    fn explicit_lib_dependency_qualified_capability_is_silent() {
        // #753: qualified capabilities are capability names, not package
        // names — a package name cannot contain "(". libzypp(econf)
        // selects the econf flavour of libzypp; libclc(llvm23) the
        // llvm23 build of libclc. The reference fires on both, we
        // deliberately do not.
        let config = rich_test_config(&[], false);
        for cap in ["libzypp(econf)", "libclc(llvm23)"] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.requires = vec![plain_dep(cap)];
            let results = run(&pkg, &config);
            assert!(
                named(&results, "explicit-lib-dependency").is_empty(),
                "capability {cap}: {results:?}"
            );
        }
    }

    #[test]
    fn explicit_lib_dependency_rich_qualified_capability_is_silent() {
        // #753: inside a rich expression the qualifier is structured on
        // the leaf and the leaf name is the bare "libzypp", which the
        // "(" name test cannot see; the qualifier test keeps the
        // rich-embedded spelling as silent as the top-level one. The
        // reference fires on it.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![rich_dep("(libzypp(econf) or foo)")];
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "explicit-lib-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn explicit_lib_dependency_rich_symbol_capability_is_silent() {
        // #753: a symbol capability inside a rich expression is the
        // same capability as the top-level spelling pinned above.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![rich_dep("(libuuid__uuid_generate_time_cont or foo)")];
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "explicit-lib-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn explicit_lib_dependency_rich_plain_lib_still_fires() {
        // A plain unversioned library package name inside a rich
        // expression is still an explicit lib dependency: the leaves
        // are analysed individually, exactly like top-level names.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            rich_dep("(libfoo1 or foo)"),
            generated_dep("libfoo.so.1()(64bit)"),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "explicit-lib-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(hits[0].1.ends_with(" libfoo1"), "line: {}", hits[0].1);
    }

    #[test]
    fn explicit_lib_dependency_biarch_devel_requirer_is_silent() {
        // Same requirer-side class as devel-dependency: a biarch/flavored
        // devel package is a devel package, so its lib requirements must
        // not trip explicit-lib-dependency either.
        let config = rich_test_config(&[], false);
        for requirer in [
            "libgcrypt-devel-32bit",
            "qwt6-qt5-devel-doc",
            "dapl-debug-libs",
        ] {
            let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
            pkg.name = requirer.to_string();
            pkg.requires = vec![plain_dep("libgcrypt")];
            let results = run(&pkg, &config);
            assert!(
                named(&results, "explicit-lib-dependency").is_empty(),
                "requirer {requirer}: {results:?}"
            );
        }
    }

    #[test]
    fn missing_dependency_on_lower_bound_at_ancestor_version_is_silent() {
        // The readline shape: the package version extends the bound
        // version with a further dot component (8.3 under 8.3.6), and
        // the bound is a lower bound the same-build library satisfies.
        // The i18n fixture carries version 1.0, so the bound is 1.
        for flags in [RPMSENSE_GREATER | RPMSENSE_EQUAL, RPMSENSE_GREATER] {
            let mut pkg = rich_fixture_pkg("i18n-two-locale-1.0-1.noarch.rpm");
            pkg.name = "tags-missingdep-devel".to_string();
            pkg.files.push(so_file());
            pkg.requires = vec![flagged_dep("tags-missingdep-libs", flags, "1")];
            let results = run(&pkg, &rich_test_config(&[], false));
            assert!(
                named(&results, "missing-dependency-on").is_empty(),
                "flags {flags}: {results:?}"
            );
        }
    }

    #[test]
    fn missing_dependency_on_exact_pin_at_ancestor_version_still_fires() {
        // An exact pin to the ancestor version is a claim about the
        // library's version, not a floor: it keeps firing.
        let mut pkg = rich_fixture_pkg("i18n-two-locale-1.0-1.noarch.rpm");
        pkg.name = "tags-missingdep-devel".to_string();
        pkg.files.push(so_file());
        pkg.requires = vec![versioned_dep("tags-missingdep-libs", "1")];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "missing-dependency-on");
        assert_eq!(hits.len(), 1, "all: {results:?}");
    }

    #[test]
    fn missing_dependency_on_upper_bound_at_ancestor_version_still_fires() {
        // An upper bound at the ancestor version excludes the package's
        // own version, so it keeps firing.
        let mut pkg = rich_fixture_pkg("i18n-two-locale-1.0-1.noarch.rpm");
        pkg.name = "tags-missingdep-devel".to_string();
        pkg.files.push(so_file());
        pkg.requires = vec![flagged_dep(
            "tags-missingdep-libs",
            RPMSENSE_LESS | RPMSENSE_EQUAL,
            "1",
        )];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "missing-dependency-on");
        assert_eq!(hits.len(), 1, "all: {results:?}");
    }

    #[test]
    fn missing_dependency_on_lower_bound_off_ancestor_still_fires() {
        // 1.1 under 1.15.1 is a string prefix, not a dot-boundary one,
        // and a lower bound there excludes the package's own version.
        let mut pkg = rich_fixture_pkg("distrelease-1.15.1-3.fc42.noarch.rpm");
        pkg.name = "tags-missingdep-devel".to_string();
        pkg.files.push(so_file());
        pkg.requires = vec![flagged_dep(
            "tags-missingdep-libs",
            RPMSENSE_GREATER | RPMSENSE_EQUAL,
            "1.1",
        )];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "missing-dependency-on");
        assert_eq!(hits.len(), 1, "all: {results:?}");
    }

    #[test]
    fn missing_dependency_on_lower_bound_epoch_mismatch_still_fires() {
        // The epoch must match too: a bound on a different epoch line
        // names a different EVR even at an ancestor version.
        let mut pkg = rich_fixture_pkg("i18n-two-locale-1.0-1.noarch.rpm");
        pkg.name = "tags-missingdep-devel".to_string();
        pkg.files.push(so_file());
        pkg.requires = vec![DepInfo {
            name: "tags-missingdep-libs".to_string(),
            flags: RPMSENSE_GREATER | RPMSENSE_EQUAL,
            epoch: Some(1),
            version: Some("1".to_string()),
            release: None,
        }];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "missing-dependency-on");
        assert_eq!(hits.len(), 1, "all: {results:?}");
    }

    #[test]
    fn missing_dependency_on_emits() {
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.name = "tags-missingdep-devel".to_string();
        pkg.files.push(so_file());
        pkg.requires = vec![versioned_dep("tags-missingdep-libs", "2.0")];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "missing-dependency-on");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": W: missing-dependency-on"),
            "line: {}",
            hits[0].1
        );
        assert!(
            hits[0]
                .1
                .ends_with("tags-missingdep*/tags-missingdep-libs/libtags-missingdep* = 2.0"),
            "line: {}",
            hits[0].1
        );
    }

    /// Negative pin for the deliberately removed `no-major-in-name`
    /// finding (issue #531): the shape that fired pre-removal -- an
    /// unnumbered `-devel` package shipping a `.so`, exactly the
    /// construction above -- so re-adding the emission fails here under
    /// plain `cargo test`.
    #[test]
    fn killed_no_major_in_name_stays_absent() {
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.name = "tags-missingdep-devel".to_string();
        pkg.files.push(so_file());
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "no-major-in-name").is_empty(),
            "must stay silent: {results:?}"
        );
    }

    #[test]
    fn no_version_dependency_on_emits() {
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.name = "tags-missingdep-devel".to_string();
        pkg.files.push(so_file());
        pkg.requires = vec![plain_dep("tags-missingdep-libs")];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "no-version-dependency-on");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0]
                .1
                .ends_with("tags-missingdep*/tags-missingdep-libs/libtags-missingdep* 1"),
            "line: {}",
            hits[0].1
        );
    }

    #[test]
    fn forbidden_controlchar_in_requires_emits() {
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![plain_dep("foo\x01bar")];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "forbidden-controlchar-found");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains(": E: forbidden-controlchar-found"),
            "line: {}",
            hits[0].1
        );
        assert!(
            hits[0].1.contains("Requires: foo\x01bar"),
            "line: {}",
            hits[0].1
        );
    }

    #[test]
    fn forbidden_controlchar_in_provides_emits() {
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.provides = vec![plain_dep("bar\x02baz")];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "forbidden-controlchar-found");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(
            hits[0].1.contains("Provides: bar\x02baz"),
            "line: {}",
            hits[0].1
        );
    }

    #[test]
    fn explicit_lib_dependency_cond_is_lib_is_silent() {
        // (gtk3-tools if libgtk-3-0): the condition libgtk-3-0 is a predicate,
        // not a requirement, so explicit-lib-dependency must not fire for it.
        // The then-branch gtk3-tools is not a lib, so no finding at all.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![plain_dep("(gtk3-tools if libgtk-3-0)")];
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "explicit-lib-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn explicit_lib_dependency_then_is_lib_fires() {
        // (libfoo if bar): the then-branch libfoo IS a real conditional
        // requirement, so explicit-lib-dependency fires (ledgered divergence
        // from the reference, which is silent on the whole string).
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("(libfoo1 if bar)"),
            generated_dep("libfoo.so.1()(64bit)"),
        ];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "explicit-lib-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
    }

    #[test]
    fn explicit_lib_dependency_self_provided_soname_is_silent() {
        // The libptscotch shape: the package ships the library itself
        // (in its MPI prefix) and provides the soname, so the
        // generated dependency resolves against its own provides and
        // never reaches libscotch7_0; the explicit requirement on that
        // name is the only expression of it, not a duplicate.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libfoo7_0"),
            generated_dep("libfoo.so.7.0()(64bit)"),
        ];
        pkg.provides = vec![plain_dep("libfoo.so.7.0()(64bit)")];
        let results = run(&pkg, &rich_test_config(&[], false));
        assert!(
            named(&results, "explicit-lib-dependency").is_empty(),
            "all: {results:?}"
        );
    }

    #[test]
    fn explicit_lib_dependency_self_provided_other_soname_still_fires() {
        // Providing an unrelated soname does not credit the name: the
        // generated dependency on libfoo.so.7.0 still reaches the
        // library package, so the explicit requirement duplicates it.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libfoo7_0"),
            generated_dep("libfoo.so.7.0()(64bit)"),
        ];
        pkg.provides = vec![plain_dep("libbar.so.9()(64bit)")];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "explicit-lib-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(hits[0].1.ends_with(" libfoo7_0"), "line: {}", hits[0].1);
    }

    #[test]
    fn explicit_lib_dependency_package_name_provide_still_fires() {
        // Providing the library package's name (a virtual provide) is
        // not providing the soname: the generated soname dependency
        // still reaches the library package.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libfoo7_0"),
            generated_dep("libfoo.so.7.0()(64bit)"),
        ];
        pkg.provides = vec![plain_dep("libfoo7_0")];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "explicit-lib-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(hits[0].1.ends_with(" libfoo7_0"), "line: {}", hits[0].1);
    }

    #[test]
    fn explicit_lib_dependency_unqualified_soname_provide_still_fires() {
        // The generated dependency carries its arch qualifier
        // (libfoo.so.7.0()(64bit)); a provide of the bare soname does
        // not satisfy it in rpm's resolution, so it does not credit.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libfoo7_0"),
            generated_dep("libfoo.so.7.0()(64bit)"),
        ];
        pkg.provides = vec![plain_dep("libfoo.so.7.0")];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "explicit-lib-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(hits[0].1.ends_with(" libfoo7_0"), "line: {}", hits[0].1);
    }

    #[test]
    fn explicit_lib_dependency_mixed_self_and_external_soname_still_fires() {
        // libfoo-7_0 is derived from two generated sonames: the
        // self-provided libfoo.so.7.0 and the external libfoo-7.0.so
        // (stem-version shape). The external derivation reaches the
        // library package, so the name keeps firing.
        let mut pkg = rich_fixture_pkg("fcprobe-1-1.noarch.rpm");
        pkg.requires = vec![
            plain_dep("libfoo-7_0"),
            generated_dep("libfoo.so.7.0()(64bit)"),
            generated_dep("libfoo-7.0.so()(64bit)"),
        ];
        pkg.provides = vec![plain_dep("libfoo.so.7.0()(64bit)")];
        let results = run(&pkg, &rich_test_config(&[], false));
        let hits = named(&results, "explicit-lib-dependency");
        assert_eq!(hits.len(), 1, "all: {results:?}");
        assert!(hits[0].1.ends_with(" libfoo-7_0"), "line: {}", hits[0].1);
    }
}
