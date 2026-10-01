//! Shared infrastructure for the file-attribute whitelist checks.
//!
//! Ported from `rpmlint/checks/FileMetadataCheck.py`. The reference's
//! `FileMetadataCheck` is only ever used as a base class (`DeviceFilesCheck`
//! and `WorldWritableCheck`) and never runs on its own, so this module holds
//! the shared pieces — the `FileMeta` file view, the `stat.filemode`
//! rendering, and the whitelist verification — without registering a check.

use crate::config::Config;
use crate::pkg::pkgfile::PkgFile;

/// Attribute keys a whitelist file entry may carry. The reference resolves
/// them with `getattr`, so an unknown key dies with `AttributeError`; it is
/// rejected here instead (see the ledger).
const KNOWN_ATTRS: &[&str] = &[
    "path",
    "owner",
    "group",
    "mode",
    "device_major",
    "device_minor",
];

/// `stat.filemode`: the 10-character symbolic mode string (`-rw-r--r--`).
pub fn filemode(mode: u32) -> String {
    let mut out = String::with_capacity(10);
    out.push(match mode & 0o170000 {
        0o040000 => 'd',
        0o020000 => 'c',
        0o060000 => 'b',
        0o100000 => '-',
        0o010000 => 'p',
        0o120000 => 'l',
        0o140000 => 's',
        _ => '?',
    });
    out.push(if mode & 0o400 != 0 { 'r' } else { '-' });
    out.push(if mode & 0o200 != 0 { 'w' } else { '-' });
    out.push(match (mode & 0o100 != 0, mode & 0o4000 != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        _ => '-',
    });
    out.push(if mode & 0o040 != 0 { 'r' } else { '-' });
    out.push(if mode & 0o020 != 0 { 'w' } else { '-' });
    out.push(match (mode & 0o010 != 0, mode & 0o2000 != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        _ => '-',
    });
    out.push(if mode & 0o004 != 0 { 'r' } else { '-' });
    out.push(if mode & 0o002 != 0 { 'w' } else { '-' });
    out.push(match (mode & 0o001 != 0, mode & 0o1000 != 0) {
        (true, true) => 't',
        (false, true) => 'T',
        (true, false) => 'x',
        _ => '-',
    });
    out
}

/// glibc `major()`: the device major number of a 32-bit `dev_t`, which is
/// what RPM stores in `rdev`.
pub fn device_major(rdev: u32) -> i64 {
    ((rdev >> 8) & 0xfff) as i64
}

/// glibc `minor()`: the device minor number of a 32-bit `dev_t`.
pub fn device_minor(rdev: u32) -> i64 {
    ((rdev & 0xff) | ((rdev >> 12) & 0xffffff00)) as i64
}

/// The file attributes the whitelist checks compare, mirroring the
/// reference's `FileMeta`.
#[derive(Debug)]
pub struct FileMeta<'a> {
    pub path: &'a str,
    pub owner: &'a str,
    pub group: &'a str,
    pub mode: String,
    pub device_major: i64,
    pub device_minor: i64,
}

impl<'a> FileMeta<'a> {
    pub fn new(file: &'a PkgFile) -> Self {
        Self {
            path: &file.name,
            owner: &file.user,
            group: &file.group,
            mode: filemode(file.mode),
            device_major: device_major(file.rdev),
            device_minor: device_minor(file.rdev),
        }
    }
}

/// One `[[XWhitelist]]` table: which packages it applies to and the
/// whitelisted files.
pub struct Whitelist {
    package: Option<String>,
    packages: Vec<String>,
    files: Vec<WhitelistedFile>,
}

/// One `[[XWhitelist.files]]` table. `attrs` keeps TOML document order: the
/// reference reports the first mismatch in that order.
struct WhitelistedFile {
    path: String,
    attrs: Vec<(String, toml::Value)>,
}

/// Parse the `key` whitelist from the config, mirroring the reference's
/// `verify_whitelists`. Malformed entries are logged and skipped instead of
/// crashing the run the way the reference's `KeyError`/`AttributeError` do.
pub fn load_whitelists(config: &Config, key: &str, required: &[&str]) -> Vec<Whitelist> {
    let Some(list) = config
        .configuration
        .get(key)
        .and_then(toml::Value::as_array)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in list {
        let Some(table) = item.as_table() else {
            log::error!("{key}: whitelist entry is not a table, skipping");
            continue;
        };
        let has_package = table.contains_key("package");
        let has_packages = table.contains_key("packages");
        if has_package == has_packages {
            log::error!(
                "{key}: whitelist entry needs exactly one of \"package\"/\"packages\", skipping"
            );
            continue;
        }
        let package = table.get("package").and_then(toml::Value::as_str);
        if has_package && package.is_none() {
            log::error!("{key}: \"package\" must be a string, skipping entry");
            continue;
        }
        if has_packages
            && table
                .get("packages")
                .and_then(toml::Value::as_array)
                .is_none()
        {
            log::error!("{key}: \"packages\" must be an array, skipping entry");
            continue;
        }
        let mut packages = Vec::new();
        let mut packages_ok = true;
        if let Some(arr) = table.get("packages").and_then(toml::Value::as_array) {
            for v in arr {
                match v.as_str() {
                    Some(entry) => packages.push(entry.to_string()),
                    None => {
                        log::error!("{key}: \"packages\" entries must be strings, skipping entry");
                        packages_ok = false;
                        break;
                    }
                }
            }
        }
        if !packages_ok {
            continue;
        }
        let Some(files) = table.get("files").and_then(toml::Value::as_array) else {
            log::error!("{key}: whitelist entry has no \"files\" list, skipping");
            continue;
        };
        let mut wfiles = Vec::new();
        let mut valid = true;
        for f in files {
            let Some(ft) = f.as_table() else {
                log::error!("{key}: whitelist file entry is not a table, skipping entry");
                valid = false;
                break;
            };
            if let Some(missing) = required.iter().find(|k| !ft.contains_key(**k)) {
                log::error!("{key}: whitelist file entry misses \"{missing}\", skipping entry");
                valid = false;
                break;
            }
            if let Some(unknown) = ft.keys().find(|k| !KNOWN_ATTRS.contains(&k.as_str())) {
                log::error!("{key}: unknown whitelist attribute \"{unknown}\", skipping entry");
                valid = false;
                break;
            }
            wfiles.push(WhitelistedFile {
                path: ft["path"].as_str().unwrap_or_default().to_string(),
                attrs: ft.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            });
        }
        if !valid {
            continue;
        }
        out.push(Whitelist {
            package: package.map(str::to_string),
            packages,
            files: wfiles,
        });
    }
    out
}

/// The kind of whitelist violation for one file: one variant per emitted
/// finding, so the caller maps it to a literal finding name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictKind {
    /// The file is absent from the whitelist (`{prefix}-unauthorized-file`).
    UnauthorizedFile,
    /// A whitelisted attribute differs (`{prefix}-mismatched-attrs`).
    MismatchedAttrs,
}

/// One whitelist verdict: the violation kind, the file, and the optional detail.
#[derive(Debug)]
pub struct Verdict {
    pub kind: VerdictKind,
    pub filename: String,
    pub detail: Option<String>,
}

/// Check `files` against the whitelists, mirroring the reference's
/// `check_files`: every file starts as unauthorized, then the whitelist
/// matching the package with the fewest errors wins.
pub fn verify_files(whitelists: &[Whitelist], pkg_name: &str, files: &[FileMeta]) -> Vec<Verdict> {
    let mut best = verify_against(&[], files);
    for wl in whitelists {
        let applies =
            wl.package.as_deref() == Some(pkg_name) || wl.packages.iter().any(|p| p == pkg_name);
        if !applies {
            continue;
        }
        let errors = verify_against(&wl.files, files);
        if errors.len() <= best.len() {
            best = errors;
        }
    }
    best
}

fn verify_against(files: &[WhitelistedFile], metas: &[FileMeta]) -> Vec<Verdict> {
    let mut out = Vec::new();
    for meta in metas {
        match files.iter().find(|f| f.path == meta.path) {
            None => out.push(Verdict {
                kind: VerdictKind::UnauthorizedFile,
                filename: meta.path.to_string(),
                detail: None,
            }),
            Some(entry) => {
                if let Some((key, expected, has)) = entry.first_mismatch(meta) {
                    out.push(Verdict {
                        kind: VerdictKind::MismatchedAttrs,
                        filename: meta.path.to_string(),
                        detail: Some(format!("expected \"{key}\": {expected}, has: {has}")),
                    });
                }
            }
        }
    }
    out
}

impl WhitelistedFile {
    /// The first attribute whose whitelisted value differs, in TOML document
    /// order — `(key, expected, actual)`.
    fn first_mismatch(&self, meta: &FileMeta) -> Option<(String, String, String)> {
        for (key, value) in &self.attrs {
            let (actual, matches) = match key.as_str() {
                "path" => (meta.path.to_owned(), value.as_str() == Some(meta.path)),
                "owner" => (meta.owner.to_owned(), value.as_str() == Some(meta.owner)),
                "group" => (meta.group.to_owned(), value.as_str() == Some(meta.group)),
                "mode" => (
                    meta.mode.clone(),
                    value.as_str() == Some(meta.mode.as_str()),
                ),
                "device_major" => (
                    meta.device_major.to_string(),
                    value.as_integer() == Some(meta.device_major),
                ),
                "device_minor" => (
                    meta.device_minor.to_string(),
                    value.as_integer() == Some(meta.device_minor),
                ),
                // Unknown keys are rejected when parsing, so this only fires if
                // `KNOWN_ATTRS` and this match diverge. Log loudly and treat the
                // key as matching rather than panicking a production run.
                key => {
                    log::error!("unknown whitelist attribute \"{key}\", treating as match");
                    (value_repr(value), true)
                }
            };
            if !matches {
                return Some((key.clone(), value_repr(value), actual));
            }
        }
        None
    }
}

/// How the reference's `f'...{value}...'` renders a TOML value.
fn value_repr(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => {
            if f.fract() == 0.0 && f.is_finite() {
                format!("{f:.1}")
            } else {
                format!("{f}")
            }
        }
        toml::Value::Boolean(b) => {
            if *b {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        _ => format!("{value:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filemode_renders_known_modes() {
        // Values taken from the reference's own test config and tests.
        assert_eq!(filemode(0o60660), "brw-rw----");
        assert_eq!(filemode(0o20660), "crw-rw----");
        assert_eq!(filemode(0o41777), "drwxrwxrwt");
        assert_eq!(filemode(0o100644), "-rw-r--r--");
        assert_eq!(filemode(0o40755), "drwxr-xr-x");
        assert_eq!(filemode(0o100755), "-rwxr-xr-x");
    }

    #[test]
    fn filemode_renders_setuid_setgid_sticky() {
        assert_eq!(filemode(0o104755), "-rwsr-xr-x");
        assert_eq!(filemode(0o102755), "-rwxr-sr-x");
        assert_eq!(filemode(0o101755), "-rwxr-xr-t");
        assert_eq!(filemode(0o104644), "-rwSr--r--");
        assert_eq!(filemode(0o101644), "-rw-r--r-T");
    }

    #[test]
    fn filemode_renders_special_types() {
        assert_eq!(filemode(0o120777), "lrwxrwxrwx");
        assert_eq!(filemode(0o140777), "srwxrwxrwx");
        assert_eq!(filemode(0o010777), "prwxrwxrwx");
    }

    #[test]
    fn device_numbers_follow_glibc() {
        assert_eq!((device_major(5), device_minor(5)), (0, 5));
        // makedev(8, 1) == 0x801
        assert_eq!((device_major(0x801), device_minor(0x801)), (8, 1));
        // makedev(1, 3)
        assert_eq!((device_major(0x103), device_minor(0x103)), (1, 3));
    }

    const DEVICE_REQUIRED: &[&str] = &[
        "path",
        "owner",
        "group",
        "mode",
        "device_minor",
        "device_major",
    ];
    const WW_REQUIRED: &[&str] = &["path", "owner", "group", "mode"];

    fn test_config() -> Config {
        // Mirrors test/configs/test.config from the reference tests.
        let table: toml::Table = toml::from_str(
            r#"
[[DeviceFilesWhitelist]]
package = "dummy"
[[DeviceFilesWhitelist.files]]
path = '/dev/sdb1'
mode = "crw-rw----"
owner = "root"
group = "tty"
device_minor = 12
device_major = 55
[[WorldWritableWhitelist]]
package = "dummy"
[[WorldWritableWhitelist.files]]
path = '/tempus'
mode = "drw-rw---t"
owner = "root"
group = "tty"
"#,
        )
        .expect("parse test whitelists");
        Config {
            configuration: table,
            ..Default::default()
        }
    }

    fn test_device_whitelists() -> Vec<Whitelist> {
        load_whitelists(&test_config(), "DeviceFilesWhitelist", DEVICE_REQUIRED)
    }

    fn test_ww_whitelists() -> Vec<Whitelist> {
        load_whitelists(&test_config(), "WorldWritableWhitelist", WW_REQUIRED)
    }

    fn meta(
        path: &str,
        mode: &str,
        owner: &str,
        group: &str,
        major: i64,
        minor: i64,
    ) -> FileMeta<'static> {
        // Leak the strings: the test only needs the values to live long enough.
        let leak = |s: &str| -> &'static str { Box::leak(s.to_string().into_boxed_str()) };
        FileMeta {
            path: leak(path),
            owner: leak(owner),
            group: leak(group),
            mode: mode.to_string(),
            device_major: major,
            device_minor: minor,
        }
    }

    #[test]
    fn first_mismatch_follows_toml_document_order() {
        // The reference test pins `mode` as the reported key even though
        // `device_major` also mismatches: `path` matches, `mode` is next.
        let whitelists = test_device_whitelists();
        let files = [meta("/dev/sdb1", "brw-rw----", "root", "tty", 0, 5)];
        let verdicts = verify_files(&whitelists, "dummy", &files);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].kind, VerdictKind::MismatchedAttrs);
        assert_eq!(verdicts[0].filename, "/dev/sdb1");
        assert_eq!(
            verdicts[0].detail.as_deref(),
            Some("expected \"mode\": crw-rw----, has: brw-rw----")
        );
    }

    #[test]
    fn unknown_file_is_unauthorized() {
        let whitelists = test_device_whitelists();
        let files = [meta("/dev/mydevice", "brw-rw----", "root", "root", 0, 5)];
        let verdicts = verify_files(&whitelists, "dummy", &files);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].kind, VerdictKind::UnauthorizedFile);
        assert_eq!(verdicts[0].filename, "/dev/mydevice");
        assert!(verdicts[0].detail.is_none());
    }

    #[test]
    fn fully_matching_file_is_quiet() {
        let whitelists = test_device_whitelists();
        let files = [meta("/dev/sdb1", "crw-rw----", "root", "tty", 55, 12)];
        let verdicts = verify_files(&whitelists, "dummy", &files);
        assert!(verdicts.is_empty(), "{verdicts:?}");
    }

    #[test]
    fn whitelist_for_another_package_does_not_apply() {
        let whitelists = test_device_whitelists();
        let files = [meta("/dev/sdb1", "crw-rw----", "root", "tty", 55, 12)];
        let verdicts = verify_files(&whitelists, "other", &files);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].kind, VerdictKind::UnauthorizedFile);
    }

    #[test]
    fn world_writable_mismatch_reports_mode() {
        let whitelists = test_ww_whitelists();
        let files = [meta("/tempus", "drwxr-xr-t", "root", "root", 0, 0)];
        let verdicts = verify_files(&whitelists, "dummy", &files);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].kind, VerdictKind::MismatchedAttrs);
        assert_eq!(
            verdicts[0].detail.as_deref(),
            Some("expected \"mode\": drw-rw---t, has: drwxr-xr-t")
        );
    }

    #[test]
    fn malformed_whitelist_entries_are_skipped() {
        let table: toml::Table = toml::from_str(
            r#"
[[DeviceFilesWhitelist]]
packages = ["a", "b"]
package = "c"
[[DeviceFilesWhitelist.files]]
path = '/dev/x'
"#,
        )
        .expect("parse");
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        // Both `package` and `packages`: rejected.
        let parsed = load_whitelists(
            &config,
            "DeviceFilesWhitelist",
            &["path", "owner", "group", "mode"],
        );
        assert!(parsed.is_empty());
    }

    #[test]
    fn whitelist_entry_with_unknown_key_is_skipped() {
        let table: toml::Table = toml::from_str(
            r#"
[[DeviceFilesWhitelist]]
package = "dummy"
[[DeviceFilesWhitelist.files]]
path = '/dev/x'
mode = "crw-rw----"
owner = "root"
group = "root"
device_minor = 1
device_major = 2
bogus = "nope"
"#,
        )
        .expect("parse");
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let parsed = load_whitelists(
            &config,
            "DeviceFilesWhitelist",
            &[
                "path",
                "owner",
                "group",
                "mode",
                "device_minor",
                "device_major",
            ],
        );
        assert!(parsed.is_empty());
    }
}
