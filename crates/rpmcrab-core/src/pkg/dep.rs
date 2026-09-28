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
