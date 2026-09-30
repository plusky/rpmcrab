//! Dependency information, mirroring rpmlint's `DepInfo` and the
//! `stringToVersion`/`versionToString` helpers (`rpmlint/pkg.py`).

/// A dependency edge: name, raw `RPMSENSE_*` flags, and the parsed EVR.
///
/// rpmlint's `DepInfo` version part is a `(epoch, version, release)` tuple;
/// here it is three fields. `epoch` is an integer or `None`, `version`/
/// `release` strings or `None` (matching `stringToVersion`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepInfo {
    pub name: String,
    pub flags: u32,
    pub epoch: Option<i64>,
    pub version: Option<String>,
    pub release: Option<String>,
}

impl DepInfo {
    /// The EVR in `[epoch:]version[-release]` form (rpmlint `versionToString`).
    pub fn evr_string(&self) -> String {
        version_to_string(self.epoch, self.version.as_deref(), self.release.as_deref())
    }
}

/// rpmlint's `stringToVersion`: parse `[epoch:]version[-release]`.
/// A non-numeric epoch is ignored; an empty version part becomes `None`.
pub fn string_to_version(s: &str) -> (Option<i64>, Option<String>, Option<String>) {
    if s.is_empty() {
        return (None, None, None);
    }
    let colon = s.find(':');
    let epoch = colon.and_then(|idx| s[..idx].parse::<i64>().ok());
    let i = colon.map_or(0, |idx| idx + 1);
    let rest = &s[i..];
    match rest.find('-') {
        Some(j) => {
            let version = &rest[..j];
            let release = &rest[j + 1..];
            (
                epoch,
                (!version.is_empty()).then(|| version.to_string()),
                Some(release.to_string()),
            )
        }
        None => (epoch, (!rest.is_empty()).then(|| rest.to_string()), None),
    }
}

/// rpmlint's `versionToString`: render an EVR tuple back to a string.
pub fn version_to_string(
    epoch: Option<i64>,
    version: Option<&str>,
    release: Option<&str>,
) -> String {
    let mut ret = String::new();
    if let Some(e) = epoch {
        ret.push_str(&format!("{e}:"));
    }
    if let Some(v) = version {
        ret.push_str(v);
        if let Some(r) = release.filter(|r| !r.is_empty()) {
            ret.push('-');
            ret.push_str(r);
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_to_version_matches_rpmlint() {
        assert_eq!(string_to_version(""), (None, None, None));
        assert_eq!(
            string_to_version("1.2.3"),
            (None, Some("1.2.3".to_string()), None)
        );
        assert_eq!(
            string_to_version("1.2.3-4"),
            (None, Some("1.2.3".to_string()), Some("4".to_string()))
        );
        assert_eq!(
            string_to_version("1:1.2.3-4"),
            (Some(1), Some("1.2.3".to_string()), Some("4".to_string()))
        );
        // garbage epoch is ignored
        assert_eq!(
            string_to_version("x:1.2.3"),
            (None, Some("1.2.3".to_string()), None)
        );
        // bare colon -> empty version part -> None
        assert_eq!(string_to_version(":"), (None, None, None));
        assert_eq!(string_to_version("1:"), (Some(1), None, None));
    }

    #[test]
    fn version_to_string_roundtrips() {
        assert_eq!(
            version_to_string(Some(1), Some("1.2.3"), Some("4")),
            "1:1.2.3-4"
        );
        assert_eq!(version_to_string(None, Some("1.2.3"), None), "1.2.3");
        assert_eq!(version_to_string(None, None, None), "");
    }
}

/// `rpmlint.pkg.parse_deps`: split a dependency line into `(name, version)`
/// pairs. The version is `Some` exactly when the dep is versioned (the
/// reference's `flags != 0`); only its presence is ever read (`unversioned`),
/// never the value.
pub fn parse_deps(line: &str) -> Vec<(String, Option<String>)> {
    let mut tokens: Vec<&str> = line
        .trim()
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|t| !t.is_empty())
        .collect();
    // Drop a trailing line-continuation backslash from a multi-line macro
    // definition (`pkg.py:310-311`).
    if tokens.last().is_some_and(|t| *t == "\\") {
        tokens.pop();
    }

    let mut prcos = Vec::new();
    // The reference accumulates `prco` as [name], [name, flags],
    // [name, flags, evr]; only the name and "is versioned" survive here.
    let mut prco: Vec<String> = Vec::new();
    for token in tokens {
        match prco.len() {
            0 => prco.push(token.to_string()),
            1 => {
                if token.starts_with(['=', '<', '>']) {
                    prco.push(String::new());
                } else {
                    prcos.push((prco.pop().unwrap(), None));
                    prco.push(token.to_string());
                }
            }
            _ => {
                let name = prco[0].clone();
                prcos.push((name, Some(token.to_string())));
                prco.clear();
            }
        }
    }
    match prco.len() {
        // A dangling version operator (`Requires: foo >=`): versioned, but
        // the version token is missing. `Some` marks versioned-ness; the
        // value is never read.
        2 => prcos.push((prco[0].clone(), Some(String::new()))),
        1 => prcos.push((prco.pop().unwrap(), None)),
        _ => {}
    }
    prcos
}

/// `rpmlint.pkg.has_forbidden_controlchars` on a string: the string itself
/// when it holds a control character other than tab, LF or CR, else `None`.
pub fn has_forbidden_controlchars(s: &str) -> Option<String> {
    if s.bytes().any(|c| c < 32 && c != 9 && c != 10 && c != 13) {
        Some(s.to_string())
    } else {
        None
    }
}

/// `has_forbidden_controlchars` on a `parse_deps` list. The reference recurses
/// into the list but returns after the first item, so only the first dep's
/// name is ever examined; mirrored here so findings stay identical.
pub fn has_forbidden_controlchars_deps(deps: &[(String, Option<String>)]) -> Option<String> {
    deps.first()
        .and_then(|(name, _)| has_forbidden_controlchars(name))
}

#[cfg(test)]
mod parse_deps_tests {
    use super::*;

    #[test]
    fn plain_names_are_unversioned() {
        assert_eq!(
            parse_deps("foo bar"),
            vec![("foo".to_string(), None), ("bar".to_string(), None),]
        );
    }

    #[test]
    fn versioned_dep_keeps_its_version() {
        assert_eq!(
            parse_deps("foo >= 1.0, bar"),
            vec![
                ("foo".to_string(), Some("1.0".to_string())),
                ("bar".to_string(), None),
            ]
        );
    }

    #[test]
    fn trailing_backslash_is_dropped() {
        assert_eq!(
            parse_deps("foo bar \\"),
            vec![("foo".to_string(), None), ("bar".to_string(), None),]
        );
    }

    #[test]
    fn dangling_operator_is_versioned_without_version() {
        // `Requires: foo >=`: the reference sets flags but no EVR, so
        // `unversioned` (flags == 0) does not yield it.
        assert_eq!(
            parse_deps("foo >="),
            vec![("foo".to_string(), Some(String::new()))]
        );
    }

    #[test]
    fn empty_line_parses_to_nothing() {
        assert!(parse_deps("").is_empty());
        assert!(parse_deps("   ").is_empty());
    }

    #[test]
    fn controlchars_found_in_string() {
        assert_eq!(
            has_forbidden_controlchars("a\x01b"),
            Some("a\x01b".to_string())
        );
        assert_eq!(has_forbidden_controlchars("a\tb\nc\rd"), None);
        assert_eq!(has_forbidden_controlchars("plain"), None);
    }

    #[test]
    fn controlchars_in_deps_only_look_at_the_first_name() {
        // Mirrors the reference's return-after-first-item: the bad second
        // dep is not reported.
        let deps = vec![("foo".to_string(), None), ("b\x01ar".to_string(), None)];
        assert_eq!(has_forbidden_controlchars_deps(&deps), None);
        let deps = vec![("f\x01oo".to_string(), None)];
        assert_eq!(
            has_forbidden_controlchars_deps(&deps),
            Some("f\x01oo".to_string())
        );
        let empty: Vec<(String, Option<String>)> = Vec::new();
        assert_eq!(has_forbidden_controlchars_deps(&empty), None);
    }
}
