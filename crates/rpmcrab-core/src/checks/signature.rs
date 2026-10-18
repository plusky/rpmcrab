//! `SignatureCheck` — PGP signature validity.
//!
//! Ported from `rpmlint/checks/SignatureCheck.py`. Two findings:
//! `unknown-key`, `invalid-signature`.
//!
//! Verification runs in-process through librpm: the package file is
//! re-read with signature verification enabled against the rpmdb keyring
//! (the header read in `Pkg` skips verification, as rpmlint's does).
//! Only the signature verdict is consumed — digest checks are masked
//! out, so a package is judged by its signature alone even when its
//! stored digests are damaged. The key ID reported for `unknown-key` is
//! read from the signature packet's issuer field and formatted as the
//! low 32 bits in lowercase hex, the way `rpm -Kv` prints it.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use librpm::keyring::Keyring;
use librpm::verify::{VerificationFlags, VerifyOptions};
use librpm::{PackageHeader, RpmErrorKind};

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct SignatureCheck {
    /// Keyring to verify against; `None` verifies against the rpmdb
    /// keyring.
    keyring: Option<Keyring>,
}

/// The structured outcome of one verified header read.
enum Verdict {
    /// Every signature verified.
    Verified,
    /// A signature's key is not in the keyring.
    NoKey,
    /// Signature verification failed.
    Failed,
    /// The file could not be read as a package at all.
    Unreadable,
}

impl SignatureCheck {
    pub fn new(_config: &Config) -> Self {
        Self { keyring: None }
    }

    /// Test hook: verify against `keyring` instead of the rpmdb keyring.
    #[cfg(test)]
    fn with_keyring(keyring: Keyring) -> Self {
        Self {
            keyring: Some(keyring),
        }
    }

    /// Re-read the package header with signature verification enabled
    /// and digest checks masked out, and classify the result.
    fn verify(&self, path: &Path) -> Verdict {
        // The keyring autoload in the verified read needs librpm
        // configured; opening the package normally did this already.
        let _ = crate::pkg::init();
        // rpmlog reports every non-clean signature verdict while the
        // read runs (NOKEY at warning, BAD at error); the structured
        // result carries the same information, so the read runs with
        // rpmlog masked down to critical. The mask is process-global,
        // hence the serialisation across worker threads.
        static VERIFY_LOCK: Mutex<()> = Mutex::new(());
        let _guard = VERIFY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _mask = RpmlogMask::hush();
        self.verify_read(path)
    }

    fn verify_read(&self, path: &Path) -> Verdict {
        let mut options = VerifyOptions::new().flags(VerificationFlags::mask_nodigests());
        if let Some(keyring) = &self.keyring {
            options = options.keyring(keyring.clone());
        }
        match PackageHeader::from_file(path, Some(&options)) {
            Ok(_) => Verdict::Verified,
            Err(RpmErrorKind::NoKey) => Verdict::NoKey,
            // `NotTrusted` is not produced for OpenPGP signatures under
            // the rpmdb keyring model (an absent key reports `NoKey`);
            // classify it with the other verification failures.
            Err(RpmErrorKind::Fail) | Err(RpmErrorKind::NotTrusted) => Verdict::Failed,
            Err(_) => Verdict::Unreadable,
        }
    }
}

/// RAII guard for the rpmlog mask: `hush` narrows it to critical-only
/// and dropping restores librpm's default (messages up to notice).
struct RpmlogMask;

impl RpmlogMask {
    fn hush() -> Self {
        librpm::logging::set_verbosity(librpm::logging::LogLevel::Critical);
        Self
    }
}

impl Drop for RpmlogMask {
    fn drop(&mut self) {
        librpm::logging::set_verbosity(librpm::logging::LogLevel::Notice);
    }
}

/// Signature-header tags carrying OpenPGP signatures: `RPMSIGTAG_DSA`
/// (267), `RPMSIGTAG_RSA` (268), `RPMSIGTAG_PGP` (1002), `RPMSIGTAG_GPG`
/// (1005) and `RPMSIGTAG_PGP5` (1006).
const SIG_TAGS: [u32; 5] = [267, 268, 1002, 1005, 1006];

/// The RPM lead magic (`0xEDABEEDB`).
const LEAD_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];

/// The header structure magic (`0x8EADE8`).
const HEADER_MAGIC: [u8; 3] = [0x8e, 0xad, 0xe8];

fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Read the OpenPGP signature blobs out of the package's signature
/// header, in header index order. Empty when the file is not an RPM or
/// carries no OpenPGP signatures. Only the lead and the signature
/// header are read; the payload is never touched.
fn signature_blobs(path: &Path) -> Vec<Vec<u8>> {
    let mut blobs = Vec::new();
    let Ok(mut file) = File::open(path) else {
        return blobs;
    };
    let mut lead = [0u8; 96];
    if file.read_exact(&mut lead).is_err() || lead[0..4] != LEAD_MAGIC {
        return blobs;
    }
    let mut preamble = [0u8; 16];
    if file.read_exact(&mut preamble).is_err() || preamble[0..3] != HEADER_MAGIC {
        return blobs;
    }
    let nindex = be_u32(&preamble[8..12]) as usize;
    let store_size = be_u32(&preamble[12..16]) as usize;
    // Real signature headers hold a handful of entries; the bound keeps
    // a garbage preamble from sizing a huge allocation.
    if nindex > 1024 {
        return blobs;
    }
    let mut index = vec![0u8; nindex * 16];
    if file.read_exact(&mut index).is_err() {
        return blobs;
    }
    let store_start = 96 + 16 + nindex as u64 * 16;
    for entry in index.as_chunks::<16>().0 {
        let tag = be_u32(&entry[0..4]);
        let entry_type = be_u32(&entry[4..8]);
        let offset = be_u32(&entry[8..12]) as usize;
        let count = be_u32(&entry[12..16]) as usize;
        // Type 7 is BIN; for BIN entries the count is a byte count.
        if !SIG_TAGS.contains(&tag) || entry_type != 7 {
            continue;
        }
        let Some(end) = offset.checked_add(count) else {
            continue;
        };
        if end > store_size {
            continue;
        }
        // Signature blobs are hundreds of bytes; the bound keeps a
        // garbage count from sizing a huge allocation, since the
        // store size it was checked against comes from the same
        // untrusted preamble.
        if count > 65_536 {
            continue;
        }
        let mut blob = vec![0u8; count];
        if file
            .seek(SeekFrom::Start(store_start + offset as u64))
            .is_err()
        {
            continue;
        }
        if file.read_exact(&mut blob).is_ok() {
            blobs.push(blob);
        }
    }
    blobs
}

/// A parsed OpenPGP signature packet.
struct SigPacket {
    /// The issuer key ID from the packet, when it carries one.
    issuer: Option<[u8; 8]>,
}

/// A byte cursor with bounds-checked reads.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(count)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(be_u32(self.take(4)?))
    }
}

/// Read an OpenPGP length (the one/two/five-octet form used by packet
/// headers and subpackets). Partial body lengths are rejected: stored
/// signature packets do not use them.
fn pgp_length(cur: &mut Cursor<'_>) -> Option<usize> {
    match cur.u8()? {
        first @ 0..=191 => Some(first as usize),
        first @ 192..=223 => {
            let second = cur.u8()?;
            Some(((first as usize - 192) << 8) + second as usize + 192)
        }
        255 => Some(cur.u32()? as usize),
        _ => None,
    }
}

/// Parse one OpenPGP signature packet. `None` when the packet is
/// structurally invalid (bad framing, truncation, an unsupported
/// version, malformed MPIs) — the case librpm reports as an invalid
/// OpenPGP signature, as opposed to a well-formed signature that merely
/// fails verification.
fn parse_sig_packet(blob: &[u8]) -> Option<SigPacket> {
    let mut cur = Cursor::new(blob);
    let first = cur.u8()?;
    if first & 0x80 == 0 {
        return None;
    }
    let body = if first & 0x40 != 0 {
        // New format: the low six bits are the packet tag (2 = signature).
        if first & 0x3f != 2 {
            return None;
        }
        let len = pgp_length(&mut cur)?;
        cur.take(len)?
    } else {
        // Old format: bits 5-2 are the packet tag, bits 1-0 the length form.
        if (first >> 2) & 0x0f != 2 {
            return None;
        }
        match first & 0x03 {
            0 => {
                let len = cur.u8()? as usize;
                cur.take(len)?
            }
            1 => {
                let len = cur.u16()? as usize;
                cur.take(len)?
            }
            2 => {
                let len = cur.u32()? as usize;
                cur.take(len)?
            }
            _ => {
                // Indeterminate length: the packet runs to the end of
                // the blob.
                &cur.buf[cur.pos..]
            }
        }
    };
    parse_sig_body(body)
}

fn parse_sig_body(body: &[u8]) -> Option<SigPacket> {
    let mut cur = Cursor::new(body);
    match cur.u8()? {
        3 => {
            // The hashed-material length is fixed at 5 for version 3.
            if cur.u8()? != 5 {
                return None;
            }
            cur.take(1)?; // signature type
            cur.take(4)?; // creation time
            let issuer: [u8; 8] = cur.take(8)?.try_into().expect("8 bytes");
            cur.take(1)?; // public-key algorithm
            cur.take(1)?; // hash algorithm
            cur.take(2)?; // left 16 bits of the hash
            parse_mpis(&mut cur)?;
            Some(SigPacket {
                issuer: Some(issuer),
            })
        }
        version @ 4..=6 => {
            cur.take(1)?; // signature type
            cur.take(1)?; // public-key algorithm
            cur.take(1)?; // hash algorithm
            // Version 6 sizes its subpacket areas with u32 lengths.
            let wide = version == 6;
            let hashed_len = if wide {
                cur.u32()? as usize
            } else {
                cur.u16()? as usize
            };
            let hashed = cur.take(hashed_len)?;
            let unhashed_len = if wide {
                cur.u32()? as usize
            } else {
                cur.u16()? as usize
            };
            let unhashed = cur.take(unhashed_len)?;
            cur.take(2)?; // left 16 bits of the hash
            parse_mpis(&mut cur)?;
            let issuer =
                issuer_from_subpackets(unhashed).or_else(|| issuer_from_subpackets(hashed));
            Some(SigPacket { issuer })
        }
        _ => None,
    }
}

/// Consume the packet's MPIs: at least one must be present and every
/// one must fit inside the packet.
fn parse_mpis(cur: &mut Cursor<'_>) -> Option<()> {
    let mut count = 0;
    while cur.remaining() > 0 {
        let bits = cur.u16()? as usize;
        cur.take(bits.div_ceil(8))?;
        count += 1;
    }
    if count == 0 { None } else { Some(()) }
}

/// Find the issuer key ID in a subpacket area: the issuer subpacket
/// (type 16) directly, or the low 64 bits of the issuer fingerprint
/// subpacket (type 33). A malformed area yields `None`.
fn issuer_from_subpackets(area: &[u8]) -> Option<[u8; 8]> {
    let mut cur = Cursor::new(area);
    let mut from_fingerprint = None;
    while cur.remaining() > 0 {
        let len = pgp_length(&mut cur)?;
        if len == 0 {
            return None;
        }
        let subpacket = cur.take(len)?;
        let (kind, body) = subpacket.split_first()?;
        match kind {
            16 if body.len() == 8 => return Some(body.try_into().expect("8 bytes")),
            33 if body.len() > 1 => {
                // Body: one version byte, then the fingerprint.
                let fingerprint = &body[1..];
                if fingerprint.len() >= 8 {
                    from_fingerprint = Some(
                        fingerprint[fingerprint.len() - 8..]
                            .try_into()
                            .expect("8 bytes"),
                    );
                }
            }
            _ => {}
        }
    }
    from_fingerprint
}

/// Format an issuer key ID the way `rpm -Kv` prints it: the low 32
/// bits, lowercase hex.
fn key_id_string(issuer: &[u8; 8]) -> String {
    issuer[4..]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Check for SignatureCheck {
    fn name(&self) -> &'static str {
        "SignatureCheck"
    }

    fn check(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let path = Path::new(&pkg.filename);
        let blobs = signature_blobs(path);
        if blobs.is_empty() {
            return;
        }
        let parsed: Vec<Option<SigPacket>> =
            blobs.iter().map(|blob| parse_sig_packet(blob)).collect();
        let any_corrupt = parsed.iter().any(|packet| packet.is_none());
        match self.verify(path) {
            Verdict::Verified | Verdict::Unreadable => {}
            Verdict::NoKey => {
                // `rpm -Kv` prints the NOKEY line and the invalid
                // signature text together for a package holding both a
                // keyless signature and a corrupt one, and the
                // reference reports only the corrupt one — an
                // unparsable packet therefore takes precedence here
                // too.
                if any_corrupt {
                    add_info(out, Level::Error, pkg, "invalid-signature", &[]);
                } else if let Some(issuer) =
                    parsed.iter().flatten().find_map(|packet| packet.issuer)
                {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "unknown-key",
                        &[&key_id_string(&issuer)],
                    );
                }
            }
            Verdict::Failed => {
                // A well-formed signature that fails verification (bad
                // digest of the signed data, wrong key) is silent, as
                // are digest failures; only an unparsable signature
                // packet is reported.
                if any_corrupt {
                    add_info(out, Level::Error, pkg, "invalid-signature", &[]);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;
    use librpm::keyring::PubKey;

    /// The low-32-bit key ID of the fixture signing key, as printed by
    /// `rpm -Kv`. Regenerating the fixtures with
    /// `build-signature-fixtures.sh` creates a new key; the script
    /// prints the new value to put here.
    const EXPECTED_KEY_ID: &str = "fc85304d";

    fn inputs() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/parity/pkg/inputs")
    }

    fn fixture_pkg(rpm_name: &str) -> Pkg {
        let path = inputs().join(rpm_name);
        let mut pkg = Pkg::installed_from_file(&path);
        // `installed_from_file` models an rpmdb-installed package, whose
        // filename is not the fixture path; the check re-reads the file,
        // so point it at the fixture.
        pkg.filename = path.to_string_lossy().into_owned();
        pkg
    }

    /// A keyring holding only the fixture signing key.
    fn test_keyring() -> Keyring {
        let raw = std::fs::read(inputs().join("signature-testkey.gpg")).expect("read test key");
        let mut keyring = Keyring::new();
        keyring
            .add_key(&PubKey::new(&raw).expect("test key parses"))
            .expect("test key added");
        keyring
    }

    /// Which keyring a test run verifies against.
    enum KeyringChoice {
        /// A keyring holding only the fixture signing key.
        TestKey,
        /// An empty keyring: every signature reports as keyless.
        Empty,
        /// The production path: the rpmdb keyring.
        System,
    }

    fn run_check(pkg: &Pkg, choice: KeyringChoice) -> Vec<(String, String)> {
        // librpm's OpenPGP backend keeps process-global state, and
        // concurrent first use from several test threads can corrupt a
        // verdict, so keyring construction and the verified read run
        // serially within this module.
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = match choice {
            KeyringChoice::TestKey => SignatureCheck::with_keyring(test_keyring()),
            KeyringChoice::Empty => SignatureCheck::with_keyring(Keyring::new()),
            KeyringChoice::System => SignatureCheck::new(&config),
        };
        check.check(pkg, &config, &mut out);
        out.results().to_vec()
    }

    fn finding_names(results: &[(String, String)]) -> Vec<&str> {
        results.iter().map(|(name, _)| name.as_str()).collect()
    }

    #[test]
    fn signed_with_key_verifies_quiet() {
        let pkg = fixture_pkg("signature-signed-1.0-1.noarch.rpm");
        let results = run_check(&pkg, KeyringChoice::TestKey);
        assert!(results.is_empty(), "{results:?}");
    }

    #[test]
    fn signed_without_key_reports_unknown_key() {
        let pkg = fixture_pkg("signature-signed-1.0-1.noarch.rpm");
        let results = run_check(&pkg, KeyringChoice::Empty);
        assert_eq!(finding_names(&results), ["unknown-key"], "{results:?}");
        assert!(
            results[0].1.contains(EXPECTED_KEY_ID),
            "key id detail: {}",
            results[0].1
        );
    }

    #[test]
    fn signed_default_keyring_reports_unknown_key() {
        // The production path: the rpmdb keyring. The fixture key is a
        // throwaway test key that no rpmdb contains, so the signature
        // reports as keyless.
        let pkg = fixture_pkg("signature-signed-1.0-1.noarch.rpm");
        let results = run_check(&pkg, KeyringChoice::System);
        assert_eq!(finding_names(&results), ["unknown-key"], "{results:?}");
        assert!(
            results[0].1.contains(EXPECTED_KEY_ID),
            "key id detail: {}",
            results[0].1
        );
    }

    #[test]
    fn unsigned_stays_silent() {
        let pkg = fixture_pkg("signature-unsigned-1.0-1.noarch.rpm");
        for choice in [
            KeyringChoice::TestKey,
            KeyringChoice::Empty,
            KeyringChoice::System,
        ] {
            let results = run_check(&pkg, choice);
            assert!(results.is_empty(), "{results:?}");
        }
    }

    /// Negative pin for the deleted `no-signature` finding: an unsigned
    /// RPM must stay silent, and `cargo test` (not just the
    /// reference-coverage auditor) must catch a re-add.
    #[test]
    fn killed_no_signature_stays_absent() {
        let pkg = fixture_pkg("signature-unsigned-1.0-1.noarch.rpm");
        let results = run_check(&pkg, KeyringChoice::Empty);
        assert!(
            !results.iter().any(|(name, _)| name == "no-signature"),
            "must stay silent: {results:?}"
        );
        assert!(results.is_empty(), "{results:?}");
    }

    #[test]
    fn corrupt_packet_reports_invalid_signature() {
        // The framing byte of the signature packet is flipped, so the
        // packet no longer parses. `rpm -Kv` reports such a package
        // with the invalid-signature text whether or not the signing
        // key is at hand.
        let pkg = fixture_pkg("signature-corrupt-1.0-1.noarch.rpm");
        for choice in [KeyringChoice::TestKey, KeyringChoice::Empty] {
            let results = run_check(&pkg, choice);
            assert_eq!(
                finding_names(&results),
                ["invalid-signature"],
                "{results:?}"
            );
        }
    }

    #[test]
    fn bad_math_signature_stays_silent_with_key() {
        // One byte inside the RSA MPI is flipped: the packet parses,
        // verification fails. `rpm -Kv` prints a BAD line, which the
        // reference's patterns do not match, so this stays silent.
        let pkg = fixture_pkg("signature-badsig-1.0-1.noarch.rpm");
        let results = run_check(&pkg, KeyringChoice::TestKey);
        assert!(results.is_empty(), "{results:?}");
    }

    #[test]
    fn bad_math_signature_without_key_reports_unknown_key() {
        // Key lookup precedes the signature math: without the key the
        // tampered signature still reports as keyless.
        let pkg = fixture_pkg("signature-badsig-1.0-1.noarch.rpm");
        let results = run_check(&pkg, KeyringChoice::Empty);
        assert_eq!(finding_names(&results), ["unknown-key"], "{results:?}");
    }

    #[test]
    fn broken_payload_keeps_signature_verdicts() {
        // A flipped payload byte breaks the payload digests only; the
        // header signature still verifies (or reports keyless) exactly
        // like the intact package.
        let pkg = fixture_pkg("signature-brokenpayload-1.0-1.noarch.rpm");
        let results = run_check(&pkg, KeyringChoice::TestKey);
        assert!(results.is_empty(), "{results:?}");
        let results = run_check(&pkg, KeyringChoice::Empty);
        assert_eq!(finding_names(&results), ["unknown-key"], "{results:?}");
    }

    #[test]
    fn bad_digest_keeps_signature_verdicts() {
        // One hex digit of the stored header SHA256 is flipped. The
        // digest check fails, but the signature itself is intact, so
        // the signature verdicts are unchanged. This pins digest checks
        // being masked out of the verified read: with them enabled the
        // read fails wholesale and the keyless case below goes silent.
        let pkg = fixture_pkg("signature-baddigest-1.0-1.noarch.rpm");
        let results = run_check(&pkg, KeyringChoice::TestKey);
        assert!(results.is_empty(), "{results:?}");
        let results = run_check(&pkg, KeyringChoice::Empty);
        assert_eq!(finding_names(&results), ["unknown-key"], "{results:?}");
        assert!(
            results[0].1.contains(EXPECTED_KEY_ID),
            "key id detail: {}",
            results[0].1
        );
    }

    #[test]
    fn blobs_come_from_the_signature_header() {
        let signed = signature_blobs(&inputs().join("signature-signed-1.0-1.noarch.rpm"));
        assert_eq!(signed.len(), 1);
        let packet = parse_sig_packet(&signed[0]).expect("fixture packet parses");
        let issuer = packet.issuer.expect("fixture packet has an issuer");
        assert_eq!(key_id_string(&issuer), EXPECTED_KEY_ID);

        let unsigned = signature_blobs(&inputs().join("signature-unsigned-1.0-1.noarch.rpm"));
        assert!(unsigned.is_empty());

        let corrupt = signature_blobs(&inputs().join("signature-corrupt-1.0-1.noarch.rpm"));
        assert_eq!(corrupt.len(), 1);
        assert!(parse_sig_packet(&corrupt[0]).is_none());
    }

    /// Build a new-format version 4 signature packet around the given
    /// hashed/unhashed areas and one MPI.
    fn v4_packet(unhashed: &[u8]) -> Vec<u8> {
        let mut body = vec![4u8, 0, 1, 8]; // version, type, RSA, SHA256
        body.extend_from_slice(&0u16.to_be_bytes()); // no hashed area
        body.extend_from_slice(&(unhashed.len() as u16).to_be_bytes());
        body.extend_from_slice(unhashed);
        body.extend_from_slice(&[0xab, 0xcd]); // left 16 bits of the hash
        body.extend_from_slice(&16u16.to_be_bytes()); // MPI: 16 bits
        body.extend_from_slice(&[0x12, 0x34]);
        let mut packet = vec![0xc2u8, body.len() as u8];
        packet.extend_from_slice(&body);
        packet
    }

    #[test]
    fn v4_issuer_subpacket_is_read() {
        let mut issuer_subpacket = vec![9u8, 16];
        issuer_subpacket.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let packet = v4_packet(&issuer_subpacket);
        let parsed = parse_sig_packet(&packet).expect("packet parses");
        assert_eq!(parsed.issuer, Some([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(key_id_string(&[1, 2, 3, 4, 5, 6, 7, 8]), "05060708");
    }

    #[test]
    fn v4_issuer_fingerprint_fallback() {
        // Type 33: version byte + 20-byte v4 fingerprint; the key ID is
        // its low 64 bits.
        let mut subpacket = vec![22u8, 33, 4];
        subpacket.extend_from_slice(&[0xaa; 12]);
        subpacket.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let packet = v4_packet(&subpacket);
        let parsed = parse_sig_packet(&packet).expect("packet parses");
        assert_eq!(parsed.issuer, Some([1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn v3_packet_issuer_is_read() {
        let mut body = vec![3u8, 5, 2];
        body.extend_from_slice(&[0; 4]); // creation time
        body.extend_from_slice(&[0xaa; 8]); // key ID
        body.extend_from_slice(&[1, 8]); // RSA, SHA256
        body.extend_from_slice(&[0xab, 0xcd]);
        body.extend_from_slice(&16u16.to_be_bytes());
        body.extend_from_slice(&[0x12, 0x34]);
        // Old format, tag 2, two-byte length: 0x80 | (2 << 2) | 1.
        let mut packet = vec![0x89u8];
        packet.extend_from_slice(&(body.len() as u16).to_be_bytes());
        packet.extend_from_slice(&body);
        let parsed = parse_sig_packet(&packet).expect("packet parses");
        assert_eq!(parsed.issuer, Some([0xaa; 8]));
    }

    #[test]
    fn oversized_signature_blob_is_skipped() {
        // A BIN signature entry whose count exceeds the blob cap is
        // skipped without allocating for it, and a following
        // in-bounds entry is still read.
        use std::io::Write as _;
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("oversized.rpm");
        let oversized = 65_537u32;
        let small: [u8; 4] = [1, 2, 3, 4];
        let store_size = oversized + small.len() as u32;
        let mut data = Vec::new();
        let mut lead = [0u8; 96];
        lead[0..4].copy_from_slice(&LEAD_MAGIC);
        data.extend_from_slice(&lead);
        let mut preamble = [0u8; 16];
        preamble[0..3].copy_from_slice(&HEADER_MAGIC);
        preamble[8..12].copy_from_slice(&2u32.to_be_bytes());
        preamble[12..16].copy_from_slice(&store_size.to_be_bytes());
        data.extend_from_slice(&preamble);
        for (offset, count) in [(0u32, oversized), (oversized, small.len() as u32)] {
            data.extend_from_slice(&1002u32.to_be_bytes());
            data.extend_from_slice(&7u32.to_be_bytes());
            data.extend_from_slice(&offset.to_be_bytes());
            data.extend_from_slice(&count.to_be_bytes());
        }
        data.resize(data.len() + oversized as usize, 0);
        data.extend_from_slice(&small);
        std::fs::File::create(&path)
            .expect("create fixture")
            .write_all(&data)
            .expect("write fixture");
        assert_eq!(signature_blobs(&path), vec![small.to_vec()]);
    }

    #[test]
    fn malformed_packets_do_not_parse() {
        // The corrupt-fixture case: tag byte with the high bit clear.
        assert!(parse_sig_packet(&[0x76, 0x00, 0x00]).is_none());
        // Not a signature tag.
        assert!(parse_sig_packet(&[0xc9, 0x00]).is_none());
        // Truncated inside the MPI.
        let mut packet = v4_packet(&[]);
        packet.truncate(packet.len() - 1);
        assert!(parse_sig_packet(&packet).is_none());
        // Unsupported version.
        let mut packet = v4_packet(&[]);
        packet[2] = 9;
        assert!(parse_sig_packet(&packet).is_none());
        // Version 3 with a hashed-material length other than 5.
        assert!(parse_sig_packet(&[0x89, 0, 4, 3, 4, 2, 0]).is_none());
    }
}
