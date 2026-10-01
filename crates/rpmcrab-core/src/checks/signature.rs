//! `SignatureCheck` — PGP signature presence and validity.
//!
//! Ported from `rpmlint/checks/SignatureCheck.py`. Three findings:
//! `no-signature`, `unknown-key`, `invalid-signature`.
//!
//! Like the reference, this shells out to `rpm -Kv` and parses its output.

use std::process::Command;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct SignatureCheck {
    rpm_bin: String,
}

impl SignatureCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            rpm_bin: "rpm".to_string(),
        }
    }

    /// Test hook: point the check at a fake `rpm` executable.
    #[cfg(test)]
    fn with_rpm_bin(rpm_bin: &str) -> Self {
        Self {
            rpm_bin: rpm_bin.to_string(),
        }
    }

    /// Run `rpm -Kv` on the package file, returning `(returncode, output)`.
    /// The reference lets the `FileNotFoundError` propagate when `rpm`
    /// cannot be run; panic here for the same fail-loud behaviour.
    fn check_signature(&self, pkg: &Pkg) -> (i32, String) {
        let output = Command::new(&self.rpm_bin)
            .args(["-Kv", &pkg.filename])
            .env("LC_ALL", "C")
            .output()
            .unwrap_or_else(|e| {
                panic!(
                    "SignatureCheck: failed to run `{}` -Kv on {}: {e}",
                    self.rpm_bin, pkg.filename
                )
            });
        // The reference merges stderr into stdout and runs under
        // `en_US.UTF-8`; see the parity ledger.
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        if text.ends_with('\n') {
            text.pop();
        }
        (output.status.code().unwrap_or(-1), text)
    }

    fn any_sig_regex() -> Regex {
        Regex::new(r"[Ss]ignature|\(sha1\) dsa|\(sha1\) rsa").expect("signature regex")
    }

    fn nokey_sig_regex() -> Regex {
        Regex::new(r"[Ss]ignature, key ID ([\w\d]*): NOKEY").expect("nokey regex")
    }

    fn invalid_sig_regex() -> Regex {
        Regex::new(r"invalid OpenPGP signature").expect("invalid sig regex")
    }
}

impl Check for SignatureCheck {
    fn name(&self) -> &'static str {
        "SignatureCheck"
    }

    fn check(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let (retcode, output) = self.check_signature(pkg);

        // No signature at all.
        if !is_match(&Self::any_sig_regex(), &output) {
            add_info(out, Level::Error, pkg, "no-signature", &[]);
            return;
        }

        // Unknown key (NOKEY) without an invalid signature.
        if retcode == 1 {
            if let Some(caps) = Self::nokey_sig_regex().captures(&output).ok().flatten() {
                let key_id = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if !is_match(&Self::invalid_sig_regex(), &output) {
                    add_info(out, Level::Error, pkg, "unknown-key", &[key_id]);
                }
            }
            // Invalid signature.
            if is_match(&Self::invalid_sig_regex(), &output) {
                add_info(out, Level::Error, pkg, "invalid-signature", &[]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn fixture_pkg() -> Pkg {
        let rpm = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let header = librpm::PackageHeader::from_file(
            &rpm,
            Some(&librpm::verify::VerifyOptions::skip_verification()),
        )
        .expect("open fixture header");
        let mut pkg = Pkg::installed(header).expect("build installed package");
        pkg.name = "testpkg".to_string();
        pkg
    }

    /// A fake `rpm` executable printing `output` and exiting with `code`.
    fn fake_rpm(dir: &std::path::Path, name: &str, output: &str, code: i32) -> String {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create fake rpm");
        writeln!(f, "#!/bin/sh").unwrap();
        // No single quotes in the test outputs, so plain quoting is safe.
        writeln!(f, "printf '%s' '{output}'").unwrap();
        writeln!(f, "exit {code}").unwrap();
        let mut perms = f.metadata().unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn run_check(pkg: &Pkg, rpm_bin: &str) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SignatureCheck::with_rpm_bin(rpm_bin);
        check.check(pkg, &config, &mut out);
        out.results().to_vec()
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        dir
    }

    #[test]
    fn no_signature_reported() {
        let dir = tmpdir("rpmcrab-sig-nosig");
        let rpm = fake_rpm(&dir, "rpm", "test.rpm: digests OK", 0);
        let pkg = fixture_pkg();
        let results = run_check(&pkg, &rpm);
        assert_eq!(results.len(), 1, "{results:?}");
        assert_eq!(results[0].0, "no-signature");
        assert!(
            results[0].1.starts_with("testpkg.noarch: E: no-signature"),
            "error level: {}",
            results[0].1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_key_reported() {
        let dir = tmpdir("rpmcrab-sig-nokey");
        let rpm = fake_rpm(
            &dir,
            "rpm",
            "test.rpm: RSA/SHA256 Signature, key ID abc123: NOKEY",
            1,
        );
        let pkg = fixture_pkg();
        let results = run_check(&pkg, &rpm);
        assert_eq!(results.len(), 1, "{results:?}");
        assert_eq!(results[0].0, "unknown-key");
        assert!(
            results[0].1.contains("abc123"),
            "key id detail: {}",
            results[0].1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_signature_reported() {
        let dir = tmpdir("rpmcrab-sig-invalid");
        let rpm = fake_rpm(&dir, "rpm", "test.rpm: invalid OpenPGP signature", 1);
        let pkg = fixture_pkg();
        let results = run_check(&pkg, &rpm);
        assert_eq!(results.len(), 1, "{results:?}");
        assert_eq!(results[0].0, "invalid-signature");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn valid_signature_no_findings() {
        let dir = tmpdir("rpmcrab-sig-ok");
        let rpm = fake_rpm(
            &dir,
            "rpm",
            "test.rpm: RSA/SHA256 Signature, key ID abc123: OK",
            0,
        );
        let pkg = fixture_pkg();
        let results = run_check(&pkg, &rpm);
        assert!(results.is_empty(), "{results:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[should_panic(expected = "failed to run")]
    fn missing_rpm_binary_panics() {
        let pkg = fixture_pkg();
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SignatureCheck::with_rpm_bin("/nonexistent/rpm-binary-xyz");
        check.check(&pkg, &config, &mut out);
    }

    #[test]
    fn any_sig_matches() {
        let re = SignatureCheck::any_sig_regex();
        assert!(is_match(
            &re,
            "foo.rpm: RSA/SHA256 Signature, key ID abc123: OK"
        ));
        assert!(is_match(&re, "foo.rpm: (sha1) dsa sha1 md5 gpg OK"));
        assert!(!is_match(&re, "foo.rpm: digests OK"));
    }

    #[test]
    fn nokey_extracts_key_id() {
        let re = SignatureCheck::nokey_sig_regex();
        let caps = re
            .captures("foo.rpm: RSA/SHA256 Signature, key ID abc123: NOKEY")
            .ok()
            .flatten()
            .expect("match");
        assert_eq!(caps.get(1).map(|m| m.as_str()), Some("abc123"));
    }

    #[test]
    fn invalid_sig_matches() {
        let re = SignatureCheck::invalid_sig_regex();
        assert!(is_match(&re, "foo.rpm: invalid OpenPGP signature"));
        assert!(!is_match(
            &re,
            "foo.rpm: RSA/SHA256 Signature, key ID abc: OK"
        ));
    }
}
