//! Shared check helpers (`docs/DESIGN.md` §7.2).
//!
//! Path/mode predicates, tag readers, and regexes that two or more checks
//! would otherwise each write. A new check reuses these; new shared logic
//! goes here, not in the check.

use fancy_regex::Regex;

use crate::pkg::Pkg;
use crate::pkg::pkgfile::PkgFile;
use std::sync::OnceLock;

/// The run-scope key of a binary package: its `SOURCERPM` header
/// value (the `Pkg.source_rpm` field carries the same value when the
/// header was read through it). Run-scoped checks group the packages
/// of one build by this key; a package without one belongs to no
/// build the run can judge.
pub(crate) fn binary_source_key(pkg: &Pkg) -> Option<String> {
    if let Some(srpm) = pkg.tag_str(librpm::Tag::SOURCERPM)
        && !srpm.is_empty()
    {
        return Some(srpm);
    }
    pkg.source_rpm.clone().filter(|s| !s.is_empty())
}

/// The `SOURCERPM` spellings a source package answers to: its header
/// name-version-release plus the `.src.rpm` / `.nosrc.rpm` suffix. A
/// run-scoped check judges a build only when the run holds a source
/// package whose spelling equals the build's key — file names are
/// not consulted, only header identity.
pub(crate) fn source_package_keys(pkg: &Pkg) -> Vec<String> {
    let version = pkg.tag_str(librpm::Tag::VERSION).unwrap_or_default();
    let release = pkg.tag_str(librpm::Tag::RELEASE).unwrap_or_default();
    [".src.rpm", ".nosrc.rpm"]
        .iter()
        .map(|ext| format!("{}-{}-{}{}", pkg.name, version, release, ext))
        .collect()
}

/// Whether a package file entry is a `%ghost`: the header flag on
/// the entry and the package's ghost list are two spellings of the
/// same fact, and either marks the entry as not shipped content.
pub(crate) fn is_ghost_file(pkg: &Pkg, file: &PkgFile) -> bool {
    file.is_ghost() || pkg.ghost_files.iter().any(|g| g == &file.name)
}

/// Lexically normalise an absolute path: `.` components drop out,
/// `..` resolves against the components before it (and above the
/// root is dropped), duplicate slashes collapse. Pure string
/// manipulation — no filesystem access.
pub(crate) fn normalise_absolute_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

/// `AbstractCheck.macro_regex`: `%+[{(]?[a-zA-Z_]\w{2,}[)}]?`.
static MACRO_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn macro_regex() -> &'static Regex {
    MACRO_REGEX.get_or_init(|| Regex::new(r"%+[{(]?[a-zA-Z_]\w{2,}[)}]?").expect("static regex"))
}

/// `FilesCheck.devel_regex`: `(.*)-(debug(info|source)?|devel|headers|source|static|prof)$`.
static DEVEL_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn devel_regex() -> &'static Regex {
    DEVEL_REGEX.get_or_init(|| {
        Regex::new(r"(.*)-(debug(info|source)?|devel|headers|source|static|prof)$")
            .expect("static regex")
    })
}

/// Devel keyword as a hyphen-delimited component (`-devel-32bit`,
/// `-devel-doc`, `-debug-libs`, ...) rather than a name suffix.
/// Biarch/flavored devel packages are devel packages, so their own
/// requirements must not trip `devel-dependency` or
/// `explicit-lib-dependency`; the reference only matches the suffix form.
static DEVEL_INFIX_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn devel_infix_regex() -> &'static Regex {
    DEVEL_INFIX_REGEX.get_or_init(|| {
        Regex::new(r"(.*)-(debug(info|source)?|devel|headers|source|static|prof)-")
            .expect("static regex")
    })
}

/// Devel keyword as an underscore-flavoured component
/// (`patterns-kde-devel_qt5`): the patterns naming scheme appends the
/// flavour to the devel component with an underscore instead of a
/// hyphen. TagsCheck credits this form for `patterns-*` requirers.
static DEVEL_UNDERSCORE_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn devel_underscore_regex() -> &'static Regex {
    DEVEL_UNDERSCORE_REGEX.get_or_init(|| {
        Regex::new(r"(.*)-(debug(info|source)?|devel|headers|source|static|prof)_")
            .expect("static regex")
    })
}

/// `lib_package_regex`: `(?:^(?:compat-)?lib.*?(\.so.*)?|libs?[\d-]*)$`, case-insensitive.
static LIB_PACKAGE_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn lib_package_regex() -> &'static Regex {
    LIB_PACKAGE_REGEX.get_or_init(|| {
        Regex::new(r"(?i)(?:^(?:compat-)?lib.*?(\.so.*)?|libs?[\d-]*)$").expect("static regex")
    })
}

/// `explicit_lib_package_regex`: start-anchored variant of
/// `lib_package_regex`, for `explicit-lib-dependency` only. The
/// reference's unanchored `libs?[\d-]*` alternative matches any
/// dependency name *ending* in "lib" (e.g. `appstream-glib`), which is
/// not a library at all. Per openSUSE naming policy library packages
/// are named `lib*`; anchoring to that prefix keeps genuine `libfoo`
/// findings while silencing the suffix false positives. This knowingly
/// silences non-`lib*` true positives like `Requires: zlib`, where the
/// reference is right.
static EXPLICIT_LIB_PACKAGE_REGEX: OnceLock<Regex> = OnceLock::new();
pub fn explicit_lib_package_regex() -> &'static Regex {
    EXPLICIT_LIB_PACKAGE_REGEX.get_or_init(|| {
        Regex::new(r"(?i)(?:^(?:compat-)?lib.*?(\.so.*)?|^libs?[\d-]*)$").expect("static regex")
    })
}

/// The reference's `pkg[tag] or pkg.scriptprog(prog)`: the scriptlet body
/// wins whenever it is non-empty; an empty body falls back to the `-p`
/// interpreter string. This is the one place that choice is made -- every
/// check that needs a scriptlet goes through this helper instead of
/// open-coding the choice (see the `scriptlet_choice` test).
pub(crate) fn script_body_or_prog(pkg: &Pkg, tag: librpm::Tag, prog: librpm::Tag) -> String {
    let body = pkg.tag_str(tag).unwrap_or_default();
    if body.is_empty() {
        pkg.scriptprog(prog)
    } else {
        body
    }
}

/// How a caller resolves the one corner where the two
/// `SOURCE_DATE_EPOCH` consumers disagree: BUILDHOST is
/// `reproducible` but the header carries no BUILDTIME.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReproducibleNoBuildtime {
    /// No SDE is known. The environment value applies to every
    /// package in a run, so it cannot stand in for the value this
    /// package's own header would have carried.
    Unknown,
    /// The environment value is the SDE in effect.
    UseEnvironment,
}

/// The package's SOURCE_DATE_EPOCH as epoch seconds, when one is
/// known per package. A package whose BUILDHOST is `reproducible`
/// was built by the configuration that sets
/// `%use_source_date_epoch_as_buildtime`, so its BUILDTIME is the
/// SOURCE_DATE_EPOCH; a missing BUILDTIME there leaves no known
/// value, because the `SOURCE_DATE_EPOCH` environment variable
/// applies to every package in the run, not to this package.
/// Otherwise the environment variable, when set to an integer, is
/// the only known value; with neither, there is nothing to compare
/// embedded timestamps against.
pub(crate) fn source_date_epoch_seconds(pkg: &Pkg) -> Option<i64> {
    resolve_source_date_epoch(
        pkg.tag_str(librpm::Tag::BUILDHOST).as_deref(),
        pkg.tag_i64(librpm::Tag::BUILDTIME),
        env_source_date_epoch(),
        ReproducibleNoBuildtime::Unknown,
    )
}

/// The package's `SOURCE_DATE_EPOCH`, when one is in effect.
///
/// Sourcing order (issue #1180): the package header wins. Under the
/// Factory build configuration (`%use_source_date_epoch_as_buildtime Y`
/// together with `%_buildhost reproducible`) BUILDTIME is the package's
/// own SDE, and the header value is per-package where the environment
/// variable applies to every package in a run. When the header route
/// does not apply -- including a `reproducible` BUILDHOST with no
/// BUILDTIME -- fall back to `$SOURCE_DATE_EPOCH` from the linter's
/// environment. When neither is available there is no SDE in effect
/// and callers keep their default behaviour.
pub fn source_date_epoch(pkg: &Pkg) -> Option<time::OffsetDateTime> {
    source_date_epoch_from_parts(
        pkg.tag_str(librpm::Tag::BUILDHOST).as_deref(),
        pkg.tag_i64(librpm::Tag::BUILDTIME),
        env_source_date_epoch(),
    )
}

/// The pure form of [`source_date_epoch`], so tests can pin the
/// matrix without crafting a package header.
fn source_date_epoch_from_parts(
    buildhost: Option<&str>,
    buildtime: Option<i64>,
    env_sde: Option<i64>,
) -> Option<time::OffsetDateTime> {
    resolve_source_date_epoch(
        buildhost,
        buildtime,
        env_sde,
        ReproducibleNoBuildtime::UseEnvironment,
    )
    .and_then(|e| time::OffsetDateTime::from_unix_timestamp(e).ok())
}

/// The sourcing rule both SDE consumers share: BUILDTIME counts as
/// the SDE only when BUILDHOST is exactly `reproducible`; in every
/// other case the environment value (already parsed, `None` when
/// unset or unparsable) rules. The `reproducible`-without-BUILDTIME
/// corner is the caller's `missing` policy.
fn resolve_source_date_epoch(
    buildhost: Option<&str>,
    buildtime: Option<i64>,
    env_sde: Option<i64>,
    missing: ReproducibleNoBuildtime,
) -> Option<i64> {
    match (buildhost, buildtime) {
        (Some("reproducible"), Some(buildtime)) if buildtime >= 0 => Some(buildtime),
        // A negative BUILDTIME is no value: it would make every
        // embedded timestamp read as after the epoch.
        (Some("reproducible"), Some(_)) => None,
        (Some("reproducible"), None) => match missing {
            ReproducibleNoBuildtime::Unknown => None,
            ReproducibleNoBuildtime::UseEnvironment => env_sde,
        },
        _ => env_sde,
    }
}

/// `$SOURCE_DATE_EPOCH` from the environment, parsed once per
/// process. A value that is not a valid epoch is ignored, as if
/// unset.
fn env_source_date_epoch() -> Option<i64> {
    static ENV_SDE: OnceLock<Option<i64>> = OnceLock::new();
    *ENV_SDE.get_or_init(|| {
        parse_env_source_date_epoch(std::env::var("SOURCE_DATE_EPOCH").ok().as_deref())
    })
}

/// The pure parse behind [`env_source_date_epoch`]: the
/// reproducible-builds value is a non-negative decimal integer,
/// digits only -- no sign and no surrounding whitespace. Anything
/// else is no value; a negative epoch in particular would turn the
/// embedded-timestamp comparisons into mass positives.
fn parse_env_source_date_epoch(raw: Option<&str>) -> Option<i64> {
    raw.and_then(parse_source_date_epoch_value)
}

/// A `SOURCE_DATE_EPOCH` value per the reproducible-builds spec: a
/// non-negative decimal integer, digits only -- no sign and no
/// surrounding whitespace. Anything else is no value.
fn parse_source_date_epoch_value(v: &str) -> Option<i64> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse::<i64>().ok()
}

/// One scriptlet of a package: its `%`-label, its interpreter (the `-p`
/// program string, empty when the header carries none) and one body.
/// Checks that scan scriptlets take their slots from here instead of each
/// walking `SCRIPT_TAGS`; which slots a check reads, and which
/// interpreters it acts on, stays the check's own business.
pub(crate) struct ScriptletSlot {
    pub label: &'static str,
    pub prog: String,
    pub body: String,
}

/// The package's scriptlets for the given `SCRIPT_TAGS` labels, in table
/// order. A slot with several bodies (the trigger slots) yields one entry
/// per body; the `*PROG` tag is a parallel array there, so body `i` pairs
/// with prog `i`. A slot whose prog array has no entry for a body falls
/// back to the joined `scriptprog` string (the single-body slots store
/// their interpreter that way).
pub(crate) fn scriptlets_for(pkg: &Pkg, labels: &[&str]) -> Vec<ScriptletSlot> {
    let mut slots = Vec::new();
    for (body_tag, prog_tag, label) in crate::pkg::SCRIPT_TAGS {
        if !labels.contains(label) {
            continue;
        }
        let progs = pkg.tag_str_array(*prog_tag);
        for (idx, body) in pkg.tag_str_array(*body_tag).into_iter().enumerate() {
            let prog = progs
                .get(idx)
                .cloned()
                .unwrap_or_else(|| pkg.scriptprog(*prog_tag));
            slots.push(ScriptletSlot { label, prog, body });
        }
    }
    slots
}

/// Python `repr()` of a string: single quotes unless the string contains `'`
/// (then double quotes, like Python), with backslashes, the active quote and
/// control characters escaped. The reference interpolates `str(list)` into
/// finding details; Rust's `{:?}` would print `["a", "b"]` instead, and a
/// hand-rolled `'{s}'` breaks on quote/backslash paths (plusky/rpmcrab#107).
pub fn python_str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            _ => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python `str()` of a list of strings: `['a', 'b']`.
pub fn python_str_list(items: &[&str]) -> String {
    let inner: Vec<String> = items.iter().map(|s| python_str_repr(s)).collect();
    format!("[{}]", inner.join(", "))
}

/// Python `str()` of a tuple of strings: `('a', 'b')`.
pub fn python_str_tuple(items: &[&str]) -> String {
    let inner: Vec<String> = items.iter().map(|s| python_str_repr(s)).collect();
    format!("({})", inner.join(", "))
}

/// Whether `name` belongs to the MinGW cross family: `mingw32-*` or
/// `mingw64-*`. The family carries its own lint config (`mingw32.toml`,
/// installed into the Factory lint environment by the
/// mingw32/64-filesystem packages), and the checks that config covers
/// gate on this predicate (issues #511, #522).
pub fn is_mingw_package(name: &str) -> bool {
    name.starts_with("mingw32-") || name.starts_with("mingw64-")
}

/// The base arch of `arch`: a hwcaps subarch string carries its
/// microarchitecture level as a trailing `_v<level>` component
/// (`x86_64_v3`, `x86_64_v4`) and builds for the base arch, so its
/// packages ship files under the base arch's libdirs. Any string
/// without such a component is its own base arch.
pub fn base_arch(arch: &str) -> &str {
    match arch.rsplit_once('_') {
        Some((base, level))
            if level.len() > 1
                && level.as_bytes()[0] == b'v'
                && level[1..].bytes().all(|b| b.is_ascii_digit()) =>
        {
            base
        }
        _ => arch,
    }
}

/// Whether `arch` is a 64-bit RPM arch, whose native libdir is lib64
/// (`/usr/lib64`, `/lib64`). A hwcaps subarch counts as its base arch
/// (`x86_64_v3` is 64-bit). Every other arch counts as 32-bit, whose
/// native libdir is `/usr/lib` + `/lib`.
pub fn is_64bit_arch(arch: &str) -> bool {
    matches!(
        base_arch(arch),
        "x86_64"
            | "aarch64"
            | "ppc64"
            | "ppc64le"
            | "s390x"
            | "riscv64"
            | "loongarch64"
            | "ia64"
            | "mips64"
            | "mips64el"
            | "sparc64"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::check::Check;
    use crate::checks::files::FilesCheck;
    use crate::color::Color;
    use crate::config::Config;
    use crate::filter::Filter;

    #[test]
    fn script_body_or_prog_falls_back_on_empty_body() {
        // Fixture: %post -p /bin/sh with a present-but-empty body,
        // %preun -p /bin/sh with content.
        let rpm_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/scriptlet-empty-post-1.0-1.noarch.rpm");
        let pkg = Pkg::open(&rpm_path, &std::env::temp_dir(), true).expect("open fixture pkg");
        // An empty body falls through to the -p interpreter string.
        assert_eq!(
            script_body_or_prog(&pkg, librpm::Tag::POSTIN, librpm::Tag::POSTINPROG),
            "/bin/sh"
        );
        // A non-empty body wins over the interpreter.
        assert!(
            script_body_or_prog(&pkg, librpm::Tag::PREUN, librpm::Tag::PREUNPROG)
                .contains("echo preun-body")
        );
    }

    #[test]
    fn source_date_epoch_reproducible_buildhost_names_buildtime() {
        // The env value is deliberately different: under a reproducible
        // BUILDHOST the BUILDTIME is the SOURCE_DATE_EPOCH, full stop.
        assert_eq!(
            resolve_source_date_epoch(
                Some("reproducible"),
                Some(111),
                Some(222),
                ReproducibleNoBuildtime::Unknown
            ),
            Some(111)
        );
        assert_eq!(
            resolve_source_date_epoch(
                Some("reproducible"),
                Some(111),
                None,
                ReproducibleNoBuildtime::Unknown
            ),
            Some(111)
        );
    }

    #[test]
    fn source_date_epoch_reproducible_without_buildtime_is_unknown() {
        // No fallback to the environment: the reproducible configuration
        // guarantees a BUILDTIME, so its absence leaves nothing known.
        assert_eq!(
            resolve_source_date_epoch(
                Some("reproducible"),
                None,
                Some(222),
                ReproducibleNoBuildtime::Unknown
            ),
            None
        );
    }

    #[test]
    fn source_date_epoch_other_buildhost_uses_environment() {
        assert_eq!(
            resolve_source_date_epoch(
                Some("builder.example.com"),
                Some(111),
                Some(222),
                ReproducibleNoBuildtime::Unknown
            ),
            Some(222)
        );
        assert_eq!(
            resolve_source_date_epoch(None, Some(111), Some(222), ReproducibleNoBuildtime::Unknown),
            Some(222)
        );
    }

    #[test]
    fn source_date_epoch_other_buildhost_without_environment_is_unknown() {
        assert_eq!(
            resolve_source_date_epoch(
                Some("builder.example.com"),
                Some(111),
                None,
                ReproducibleNoBuildtime::Unknown
            ),
            None
        );
        assert_eq!(
            resolve_source_date_epoch(None, None, None, ReproducibleNoBuildtime::Unknown),
            None
        );
    }

    #[test]
    fn source_date_epoch_negative_or_padded_values_are_unknown() {
        // The reproducible-builds value is a non-negative decimal
        // integer: a sign, a negative value or padding is no value,
        // on the environment path and the header path alike.
        assert_eq!(parse_env_source_date_epoch(Some("-222")), None);
        assert_eq!(parse_env_source_date_epoch(Some("+222")), None);
        assert_eq!(parse_env_source_date_epoch(Some(" 222")), None);
        assert_eq!(parse_env_source_date_epoch(Some("222 ")), None);
        assert_eq!(parse_env_source_date_epoch(Some("222")), Some(222));
        assert_eq!(
            resolve_source_date_epoch(
                Some("reproducible"),
                Some(-1),
                Some(222),
                ReproducibleNoBuildtime::UseEnvironment
            ),
            None
        );
    }

    #[test]
    fn source_date_epoch_unparsable_environment_is_unknown() {
        assert_eq!(parse_env_source_date_epoch(Some("abc")), None);
        assert_eq!(parse_env_source_date_epoch(Some("")), None);
        assert_eq!(parse_env_source_date_epoch(None), None);
        assert_eq!(parse_env_source_date_epoch(Some("222")), Some(222));
    }

    #[test]
    fn source_date_epoch_reproducible_without_buildtime_diverges_by_policy() {
        // The same header state resolves differently per caller, by
        // design: the per-package consumer treats the SDE as unknown,
        // the run-environment consumer uses the environment value.
        assert_eq!(
            resolve_source_date_epoch(
                Some("reproducible"),
                None,
                Some(222),
                ReproducibleNoBuildtime::Unknown
            ),
            None
        );
        assert_eq!(
            resolve_source_date_epoch(
                Some("reproducible"),
                None,
                Some(222),
                ReproducibleNoBuildtime::UseEnvironment
            ),
            Some(222)
        );
    }

    #[test]
    fn macro_regex_matches_unexpanded_macro() {
        // Regression: files.rs had \\w (double-escaped) which matched a
        // literal backslash-w instead of word characters. This fails if the
        // broken form is restored.
        let re = macro_regex();
        assert!(re.is_match("%{foo}").unwrap_or(false));
        assert!(re.is_match("%foo").unwrap_or(false));
        assert!(!re.is_match("plain").unwrap_or(true));
    }

    #[test]
    fn lib_package_regex_matches_lib_names() {
        let re = lib_package_regex();
        assert!(re.is_match("libfoo").unwrap_or(false));
        assert!(re.is_match("lib64").unwrap_or(false));
        assert!(!re.is_match("foo").unwrap_or(true));
    }

    #[test]
    fn explicit_lib_package_regex_anchors_to_lib_prefix() {
        let re = explicit_lib_package_regex();
        assert!(re.is_match("libfoo").unwrap_or(false));
        assert!(re.is_match("lib64").unwrap_or(false));
        assert!(re.is_match("compat-libfoo").unwrap_or(false));
        // Suffix-only matches are not libraries: the reference fires on
        // these, we deliberately do not.
        assert!(!re.is_match("appstream-glib").unwrap_or(true));
        assert!(!re.is_match("glib2").unwrap_or(true));
        assert!(!re.is_match("foo").unwrap_or(true));
        // A versioned .so leaf still captures group 1 (stays silent).
        let caps = re.captures("libfoo.so.2").unwrap().unwrap();
        assert!(caps.get(1).is_some());
    }

    #[test]
    fn script_body_or_prog_prefers_body_over_interpreter() {
        // B2: the reference is `pkg[POSTIN] or pkg.scriptprog(POSTINPROG)` --
        // the body wins. The ldconfig fixture has a %post body plus
        // `%post -p /sbin/ldconfig`; returning the interpreter here would be
        // the inverted precedence.
        let rpm = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/parity/pkg/inputs/ldconfig-test-1.0-1.noarch.rpm"
        );
        let dir = std::env::temp_dir().join("rpmcrab-script-body-or-prog");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let pkg =
            crate::pkg::Pkg::open(std::path::Path::new(rpm), &dir, true).expect("fixture opens");
        let body = script_body_or_prog(&pkg, librpm::Tag::POSTIN, librpm::Tag::POSTINPROG);
        assert!(
            !body.contains("/sbin/ldconfig"),
            "body won, not the -p interpreter: {body:?}"
        );
        assert!(!body.is_empty(), "fixture has a %post body");
    }

    #[test]
    fn python_str_list_matches_python_repr() {
        // B9: the reference prints Python repr (['a']), not Rust Debug (["a"]).
        assert_eq!(python_str_list(&["a"]), "['a']");
        assert_eq!(python_str_list(&["a", "b"]), "['a', 'b']");
        assert_eq!(python_str_list(&[]), "[]");
    }

    #[test]
    fn python_str_repr_matches_python() {
        assert_eq!(python_str_repr("plain"), "'plain'");
        assert_eq!(python_str_repr("/bin/it's"), r#""/bin/it's""#);
        assert_eq!(python_str_repr("/bin/bs\\x"), r"'/bin/bs\\x'");
        assert_eq!(python_str_repr("both'and\"q"), r#"'both\'and"q'"#);
        assert_eq!(
            python_str_list(&["/bin/it's", "/bin/bs\\x"]),
            r#"["/bin/it's", '/bin/bs\\x']"#
        );
    }

    #[test]
    fn python_str_tuple_matches_python_repr() {
        // B9: the reference prints str of a tuple (('a', 'ad')).
        assert_eq!(python_str_tuple(&["a", "ad"]), "('a', 'ad')");
    }

    #[test]
    fn shared_regexes_have_no_double_escaping() {
        // Regression: files.rs had \\.so, [\\d-], and \\w (double-escaped
        // in raw strings). The Debug format escapes backslashes, so a correct
        // single-backslash pattern appears as \\ in debug output, while a
        // double-backslash (broken) pattern appears as \\\\. This fails
        // if the broken forms are restored.
        let macro_dbg = format!("{:?}", macro_regex());
        let lib_dbg = format!("{:?}", lib_package_regex());
        assert!(
            !macro_dbg.contains("\\\\"),
            "macro_regex double-escaped: {macro_dbg}"
        );
        assert!(
            !lib_dbg.contains("\\\\"),
            "lib_package_regex double-escaped: {lib_dbg}"
        );
    }

    fn test_config() -> Config {
        // Load the bundled defaults so the check sees the same configuration
        // as the real binary (empty Config::default would leave regexes like
        // MetaPackageRegexp empty, matching everything).
        let defaults: toml::Table = toml::from_str(include_str!("../../data/configdefaults.toml"))
            .expect("parse configdefaults");
        Config {
            configuration: defaults,
            ..Default::default()
        }
    }

    #[test]
    fn ldconfig_p_interpreter_satisfies_check() {
        // #1602: %post -p /sbin/ldconfig with a body that does not call
        // ldconfig must NOT emit postin-without-ldconfig. The fixture RPM has
        // a .so file and scriptlets whose -p interpreter is /sbin/ldconfig.
        // Reverting to the stub scriptprog (or the reference body-only search)
        // makes this fail.
        let rpm = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/parity/pkg/inputs/ldconfig-test-1.0-1.noarch.rpm"
        );
        let dir = std::env::temp_dir().join("rpmcrab-ldconfig-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let pkg = Pkg::open(std::path::Path::new(rpm), &dir, true).expect("open fixture");
        assert_eq!(pkg.scriptprog(librpm::Tag::POSTINPROG), "/sbin/ldconfig");

        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = FilesCheck::new(&config);
        check.check(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            !names.contains(&"postin-without-ldconfig"),
            "unexpected postin-without-ldconfig: {names:?}"
        );
        assert!(
            !names.contains(&"postun-without-ldconfig"),
            "unexpected postun-without-ldconfig: {names:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod sde_tests {
    use super::source_date_epoch_from_parts;

    // 2026-10-28 09:30:00 UTC.
    const SDE: i64 = 1_793_179_800;

    #[test]
    fn reproducible_header_wins_over_env() {
        let got = source_date_epoch_from_parts(Some("reproducible"), Some(SDE), Some(1)).unwrap();
        assert_eq!(got.unix_timestamp(), SDE);
        assert_eq!((got.hour(), got.minute(), got.second()), (9, 30, 0));
    }

    #[test]
    fn reproducible_header_without_env() {
        let got = source_date_epoch_from_parts(Some("reproducible"), Some(SDE), None).unwrap();
        assert_eq!(got.unix_timestamp(), SDE);
    }

    #[test]
    fn other_buildhost_falls_back_to_env() {
        // A BUILDTIME under any other BUILDHOST is a wall-clock build
        // time, not SDE: the environment value rules.
        let got =
            source_date_epoch_from_parts(Some("buildhost.example"), Some(SDE), Some(42)).unwrap();
        assert_eq!(got.unix_timestamp(), 42);
    }

    #[test]
    fn reproducible_without_buildtime_falls_back_to_env() {
        let got = source_date_epoch_from_parts(Some("reproducible"), None, Some(42)).unwrap();
        assert_eq!(got.unix_timestamp(), 42);
    }

    #[test]
    fn no_source_no_sde() {
        assert!(source_date_epoch_from_parts(Some("buildhost.example"), Some(SDE), None).is_none());
        assert!(source_date_epoch_from_parts(None, None, None).is_none());
    }

    #[test]
    fn out_of_range_epoch_is_no_sde() {
        assert!(source_date_epoch_from_parts(Some("reproducible"), Some(i64::MAX), None).is_none());
    }
}
