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

pub struct SignatureCheck;

impl SignatureCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// Run `rpm -Kv` on the package file, returning `(returncode, output)`.
    /// Returns `None` when `rpm` cannot be run.
    fn check_signature(pkg: &Pkg) -> Option<(i32, String)> {
        let output = Command::new("rpm")
            .args(["-Kv", &pkg.filename])
            .env("LC_ALL", "C")
            .output()
            .ok()?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        if text.ends_with('\n') {
            text.pop();
        }
        Some((output.status.code().unwrap_or(-1), text))
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
        let Some((retcode, output)) = Self::check_signature(pkg) else {
            return;
        };

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
