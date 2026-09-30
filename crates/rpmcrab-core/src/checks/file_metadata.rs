//! `FileMetadataCheck` — validate file owner/group/mode against whitelists.
//!
//! Ported from `rpmlint/checks/FileMetadataCheck.py`. Two findings:
//! `{prefix}-unauthorized-file` and `{prefix}-mismatched-attrs`.
//!
//! The check is configured via `FileMetadataWhitelist` (a list of whitelist
//! entries, each with `package`/`packages` and `files` with `path`, `owner`,
//! `group`, `mode`, `device_major`, `device_minor`). The `prefix` comes from
//! the check configuration.

use std::collections::HashMap;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::{PkgFile, filemode};

/// The file metadata view, mirroring the reference's `FileMeta`.
struct FileMeta {
    owner: String,
    group: String,
    mode: String,
    device_major: u32,
    device_minor: u32,
}

impl FileMeta {
    fn new(pkgfile: &PkgFile) -> Self {
        // `os.major`/`os.minor` on the `rdev`. These are the glibc macros
        // for 32-bit dev_t.
        let rdev = pkgfile.rdev;
        let major = (rdev >> 8) & 0xfff;
        let minor = (rdev & 0xff) | ((rdev >> 12) & 0xfff00);
        Self {
            owner: pkgfile.user.clone(),
            group: pkgfile.group.clone(),
            mode: filemode(pkgfile.mode),
            device_major: major,
            device_minor: minor,
        }
    }

    /// Returns `(finding, detail)` when `entry` disagrees, `None` otherwise.
    fn validation_error(
        &self,
        entry: &HashMap<String, String>,
        prefix: &str,
    ) -> Option<(String, String)> {
        for (key, expected) in entry {
            if key == "path" {
                continue;
            }
            let actual = match key.as_str() {
                "owner" => self.owner.clone(),
                "group" => self.group.clone(),
                "mode" => self.mode.clone(),
                "device_major" => self.device_major.to_string(),
                "device_minor" => self.device_minor.to_string(),
                _ => continue,
            };
            if &actual != expected {
                return Some((
                    format!("{prefix}-mismatched-attrs"),
                    format!("expected \"{key}\": {expected}, has: {actual}"),
                ));
            }
        }
        None
    }
}

pub struct FileMetadataCheck {
    prefix: String,
    whitelists: Vec<Whitelist>,
}

struct Whitelist {
    packages: Vec<String>,
    files: Vec<HashMap<String, String>>,
}

impl FileMetadataCheck {
    pub fn new(config: &Config) -> Self {
        let prefix = config
            .configuration
            .get("FileMetadataPrefix")
            .and_then(toml::Value::as_str)
            .unwrap_or("file-metadata")
            .to_string();

        let whitelists = config
            .configuration
            .get("FileMetadataWhitelist")
            .and_then(toml::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Self::parse_whitelist)
                    .collect()
            })
            .unwrap_or_default();

        Self { prefix, whitelists }
    }

    fn parse_whitelist(v: &toml::Value) -> Option<Whitelist> {
        let table = v.as_table()?;
        let mut packages = Vec::new();
        if let Some(pkg) = table.get("package").and_then(toml::Value::as_str) {
            packages.push(pkg.to_string());
        }
        if let Some(pkgs) = table.get("packages").and_then(toml::Value::as_array) {
            for p in pkgs {
                if let Some(s) = p.as_str() {
                    packages.push(s.to_string());
                }
            }
        }
        let files = table
            .get("files")
            .and_then(toml::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| {
                        f.as_table().map(|t| {
                            t.iter()
                                .map(|(k, v)| {
                                    let val = match v {
                                        toml::Value::String(s) => s.clone(),
                                        toml::Value::Integer(i) => i.to_string(),
                                        _ => String::new(),
                                    };
                                    (k.clone(), val)
                                })
                                .collect()
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Whitelist { packages, files })
    }

    fn matches_pkg(&self, whitelist: &Whitelist, pkg_name: &str) -> bool {
        whitelist.packages.iter().any(|p| p == pkg_name)
    }

    /// Verify `files` against `whitelist`, returning `(finding, path, detail)` errors.
    fn verify_whitelist(
        &self,
        whitelist: &Whitelist,
        files: &HashMap<String, FileMeta>,
    ) -> Vec<(String, String, Option<String>)> {
        let mut errors = Vec::new();
        for (filename, meta) in files {
            if let Some(entry) = whitelist
                .files
                .iter()
                .find(|e| e.get("path") == Some(filename))
            {
                if let Some((finding, detail)) = meta.validation_error(entry, &self.prefix) {
                    errors.push((finding, filename.clone(), Some(detail)));
                }
            } else {
                errors.push((
                    format!("{}-unauthorized-file", self.prefix),
                    filename.clone(),
                    None,
                ));
            }
        }
        errors
    }
}

impl Check for FileMetadataCheck {
    fn name(&self) -> &'static str {
        "FileMetadataCheck"
    }

    fn check(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        // Build the FileMeta map for all files in the package.
        let files: HashMap<String, FileMeta> = pkg
            .files
            .iter()
            .map(|f| (f.name.clone(), FileMeta::new(f)))
            .collect();

        // Start with "unauthorized for all" as the worst case.
        let empty = Whitelist {
            packages: Vec::new(),
            files: Vec::new(),
        };
        let mut best_errors = self.verify_whitelist(&empty, &files);

        for whitelist in &self.whitelists {
            if self.matches_pkg(whitelist, &pkg.name) {
                let errors = self.verify_whitelist(whitelist, &files);
                if errors.len() <= best_errors.len() {
                    best_errors = errors;
                }
            }
        }

        for (finding, filename, detail) in best_errors {
            let details: Vec<&str> = match &detail {
                Some(d) => vec![filename.as_str(), d.as_str()],
                None => vec![filename.as_str()],
            };
            add_info(out, Level::Error, pkg, &finding, &details);
        }
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn filemode_format() {
        // Spot-check the filemode helper via FileMeta.
        let mut f = PkgFile::default();
        f.name = "/usr/bin/foo".to_string();
        f.user = "root".to_string();
        f.group = "root".to_string();
        f.mode = 0o100755;
        f.rdev = 0;
        let meta = FileMeta::new(&f);
        assert_eq!(meta.mode, "-rwxr-xr-x");
        assert_eq!(meta.owner, "root");
    }

    #[test]
    fn device_major_minor() {
        let mut f = PkgFile::default();
        f.name = "/dev/null".to_string();
        f.rdev = 0x0103; // major 1, minor 3
        let meta = FileMeta::new(&f);
        assert_eq!(meta.device_major, 1);
        assert_eq!(meta.device_minor, 3);
    }
}
