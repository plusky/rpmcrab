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

/// The per-blob size cap for signature blobs: signature blobs are
/// hundreds of bytes, and the cap bounds the allocation a garbage
/// count from the untrusted preamble can size.
const MAX_BLOB_BYTES: usize = 65_536;

/// The total size cap across all signature blobs in one header: the
/// cap bounds the total read work for one package.
const MAX_TOTAL_BLOB_BYTES: usize = 1_048_576;

/// The signature blobs read from a package's signature header, plus
/// the header's signature presence: `has_entries` records that the
/// header carries OpenPGP signature entries, and `has_unreadable`
/// records that at least one such entry stayed unreadable.
#[derive(Debug, Default, PartialEq, Eq)]
struct SignatureBlobs {
    /// The readable signature blobs, in header index order.
    blobs: Vec<Vec<u8>>,
    /// The header carries at least one OpenPGP signature entry.
    has_entries: bool,
    /// At least one signature entry stayed unreadable: its range
    /// falls outside the header store, its size exceeds a size cap,
    /// or its file read failed.
    has_unreadable: bool,
}

/// Read the OpenPGP signature blobs out of the package's signature
/// header, in header index order. Only the lead and the signature
/// header are read; the result reports the header's signature
/// presence alongside the readable blobs.
fn signature_blobs(path: &Path) -> SignatureBlobs {
    let mut result = SignatureBlobs::default();
    let Ok(mut file) = File::open(path) else {
        return result;
    };
    let mut lead = [0u8; 96];
    if file.read_exact(&mut lead).is_err() || lead[0..4] != LEAD_MAGIC {
        return result;
    }
    let mut preamble = [0u8; 16];
    if file.read_exact(&mut preamble).is_err() || preamble[0..3] != HEADER_MAGIC {
        return result;
    }
    let nindex = be_u32(&preamble[8..12]) as usize;
    let store_size = be_u32(&preamble[12..16]) as usize;
    // Real signature headers hold a handful of entries; the bound keeps
    // a garbage preamble from sizing a huge allocation.
    if nindex > 1024 {
        return result;
    }
    let mut index = vec![0u8; nindex * 16];
    if file.read_exact(&mut index).is_err() {
        return result;
    }
    let store_start = 96 + 16 + nindex as u64 * 16;
    let mut total_bytes = 0usize;
    for entry in index.as_chunks::<16>().0 {
        let tag = be_u32(&entry[0..4]);
        let entry_type = be_u32(&entry[4..8]);
        let offset = be_u32(&entry[8..12]) as usize;
        let count = be_u32(&entry[12..16]) as usize;
        // Type 7 is BIN; for BIN entries the count is a byte count.
        if !SIG_TAGS.contains(&tag) || entry_type != 7 {
            continue;
        }
        result.has_entries = true;
        let Some(end) = offset.checked_add(count) else {
            result.has_unreadable = true;
            continue;
        };
        if end > store_size {
            result.has_unreadable = true;
            continue;
        }
        if count > MAX_BLOB_BYTES {
            result.has_unreadable = true;
            continue;
        }
        if total_bytes.saturating_add(count) > MAX_TOTAL_BLOB_BYTES {
            result.has_unreadable = true;
            continue;
        }
        let mut blob = vec![0u8; count];
        if file
            .seek(SeekFrom::Start(store_start + offset as u64))
            .is_err()
        {
            result.has_unreadable = true;
            continue;
        }
        if file.read_exact(&mut blob).is_ok() {
            total_bytes += count;
            result.blobs.push(blob);
        } else {
            result.has_unreadable = true;
        }
    }
    result
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
    // A length-delimited packet consumes the whole blob exactly; the
    // indeterminate-length form runs to the end of the blob by
    // definition and satisfies full consumption directly.
    let mut length_delimited = true;
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
                length_delimited = false;
                &cur.buf[cur.pos..]
            }
        }
    };
    if length_delimited && cur.pos != blob.len() {
        return None;
    }
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
            // A malformed subpacket area makes the whole packet
            // malformed; a well-formed area yields its issuer, which
            // the unhashed area takes precedence in providing.
            let issuer = issuer_from_subpackets(unhashed)?.or(issuer_from_subpackets(hashed)?);
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
/// subpacket (type 33). The outer `Option` reports the area's
/// well-formedness — `None` for a malformed area (a bad length, a
/// truncated subpacket) — and the inner `Option` carries the issuer
/// a well-formed area provides. Every subpacket in the area is
/// validated, so malformed trailing subpackets report as malformed
/// even when an earlier subpacket already provided an issuer.
fn issuer_from_subpackets(area: &[u8]) -> Option<Option<[u8; 8]>> {
    let mut cur = Cursor::new(area);
    let mut issuer = None;
    let mut from_fingerprint = None;
    while cur.remaining() > 0 {
        let len = pgp_length(&mut cur)?;
        if len == 0 {
            return None;
        }
        let subpacket = cur.take(len)?;
        let (kind, body) = subpacket.split_first()?;
        match kind {
            16 if body.len() == 8 => {
                if issuer.is_none() {
                    issuer = Some(body.try_into().expect("8 bytes"));
                }
            }
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
    Some(issuer.or(from_fingerprint))
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
        let sig = signature_blobs(path);
        // Signature presence drives the verified read: a package whose
        // header carries signature entries runs the read even when
        // every blob stayed unreadable, and an unreadable entry counts
        // with the unparsable packets below.
        if !sig.has_entries {
            return;
        }
        let parsed: Vec<Option<SigPacket>> = sig
            .blobs
            .iter()
            .map(|blob| parse_sig_packet(blob))
            .collect();
        let any_corrupt = sig.has_unreadable || parsed.iter().any(|packet| packet.is_none());
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
        assert_eq!(signed.blobs.len(), 1);
        assert!(signed.has_entries);
        assert!(!signed.has_unreadable);
        let packet = parse_sig_packet(&signed.blobs[0]).expect("fixture packet parses");
        let issuer = packet.issuer.expect("fixture packet has an issuer");
        assert_eq!(key_id_string(&issuer), EXPECTED_KEY_ID);

        let unsigned = signature_blobs(&inputs().join("signature-unsigned-1.0-1.noarch.rpm"));
        assert!(unsigned.blobs.is_empty());
        assert!(!unsigned.has_entries);
        assert!(!unsigned.has_unreadable);

        let corrupt = signature_blobs(&inputs().join("signature-corrupt-1.0-1.noarch.rpm"));
        assert_eq!(corrupt.blobs.len(), 1);
        assert!(corrupt.has_entries);
        assert!(parse_sig_packet(&corrupt.blobs[0]).is_none());
    }

    /// Write a synthetic package holding only a lead and a signature
    /// header: `entries` are `(tag, offset, count)` BIN entries and
    /// `store` is the header store the entries index into. The
    /// returned tempdir keeps the file alive.
    fn write_signature_header(
        entries: &[(u32, u32, u32)],
        store: &[u8],
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        use std::io::Write as _;
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("synthetic.rpm");
        let mut data = Vec::new();
        let mut lead = [0u8; 96];
        lead[0..4].copy_from_slice(&LEAD_MAGIC);
        data.extend_from_slice(&lead);
        let mut preamble = [0u8; 16];
        preamble[0..3].copy_from_slice(&HEADER_MAGIC);
        preamble[8..12].copy_from_slice(&(entries.len() as u32).to_be_bytes());
        preamble[12..16].copy_from_slice(&(store.len() as u32).to_be_bytes());
        data.extend_from_slice(&preamble);
        for &(tag, offset, count) in entries {
            data.extend_from_slice(&tag.to_be_bytes());
            data.extend_from_slice(&7u32.to_be_bytes());
            data.extend_from_slice(&offset.to_be_bytes());
            data.extend_from_slice(&count.to_be_bytes());
        }
        data.extend_from_slice(store);
        std::fs::File::create(&path)
            .expect("create fixture")
            .write_all(&data)
            .expect("write fixture");
        (dir, path)
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

    /// Build a new-format version 4 signature packet with explicit
    /// hashed and unhashed subpacket areas and one MPI.
    fn v4_packet_with_areas(hashed: &[u8], unhashed: &[u8]) -> Vec<u8> {
        let mut body = vec![4u8, 0, 1, 8]; // version, type, RSA, SHA256
        body.extend_from_slice(&(hashed.len() as u16).to_be_bytes());
        body.extend_from_slice(hashed);
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
        // in-bounds entry is still read. The skipped entry still
        // records signature presence and unreadability.
        let oversized = 65_537u32;
        let small: [u8; 4] = [1, 2, 3, 4];
        let mut store = vec![0u8; oversized as usize];
        store.extend_from_slice(&small);
        let (_dir, path) = write_signature_header(
            &[(1002, 0, oversized), (1002, oversized, small.len() as u32)],
            &store,
        );
        let sig = signature_blobs(&path);
        assert_eq!(sig.blobs, vec![small.to_vec()]);
        assert!(sig.has_entries);
        assert!(sig.has_unreadable);
    }

    #[test]
    fn unreadable_only_signature_still_counts_as_signed() {
        // The only signature entry exceeds the blob cap: no blob is
        // readable, and the header still counts as signed.
        let oversized = 65_537u32;
        let store = vec![0u8; oversized as usize];
        let (_dir, path) = write_signature_header(&[(1002, 0, oversized)], &store);
        let sig = signature_blobs(&path);
        assert!(sig.blobs.is_empty());
        assert!(sig.has_entries);
        assert!(sig.has_unreadable);
    }

    #[test]
    fn out_of_bounds_signature_still_counts_as_signed() {
        // The only signature entry ranges past the end of the store:
        // no blob is readable, and the header still counts as signed.
        let (_dir, path) = write_signature_header(&[(1002, 0, 100)], &[0u8; 10]);
        let sig = signature_blobs(&path);
        assert!(sig.blobs.is_empty());
        assert!(sig.has_entries);
        assert!(sig.has_unreadable);
    }

    #[test]
    fn header_without_signature_entries_counts_as_unsigned() {
        // A header holding only a non-signature BIN entry carries no
        // signature presence.
        let (_dir, path) = write_signature_header(&[(1000, 0, 4)], &[1, 2, 3, 4]);
        let sig = signature_blobs(&path);
        assert!(sig.blobs.is_empty());
        assert!(!sig.has_entries);
        assert!(!sig.has_unreadable);
    }

    #[test]
    fn total_blob_bytes_are_capped() {
        // Sixteen entries at the per-blob cap fill the total cap
        // exactly; the seventeenth entry counts as unreadable.
        let per_blob = MAX_BLOB_BYTES as u32;
        let entries: Vec<(u32, u32, u32)> =
            (0..17u32).map(|i| (1002, i * per_blob, per_blob)).collect();
        let store = vec![0u8; 17 * MAX_BLOB_BYTES];
        let (_dir, path) = write_signature_header(&entries, &store);
        let sig = signature_blobs(&path);
        assert_eq!(sig.blobs.len(), 16);
        assert!(sig.has_entries);
        assert!(sig.has_unreadable);
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

    #[test]
    fn trailing_bytes_after_a_packet_are_rejected() {
        // Near miss: the exact packet parses.
        let packet = v4_packet(&[]);
        assert!(parse_sig_packet(&packet).is_some());
        // Firing: one trailing byte after a new-format packet.
        let mut with_trailing = packet.clone();
        with_trailing.push(0);
        assert!(parse_sig_packet(&with_trailing).is_none());
        // Firing: a whole second packet as trailing bytes.
        let mut doubled = packet.clone();
        doubled.extend_from_slice(&packet);
        assert!(parse_sig_packet(&doubled).is_none());
        // Firing: trailing bytes after an old-format packet.
        let mut body = vec![3u8, 5, 2];
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(&[0xaa; 8]);
        body.extend_from_slice(&[1, 8]);
        body.extend_from_slice(&[0xab, 0xcd]);
        body.extend_from_slice(&16u16.to_be_bytes());
        body.extend_from_slice(&[0x12, 0x34]);
        let mut old_packet = vec![0x89u8];
        old_packet.extend_from_slice(&(body.len() as u16).to_be_bytes());
        old_packet.extend_from_slice(&body);
        assert!(parse_sig_packet(&old_packet).is_some());
        old_packet.push(0xff);
        assert!(parse_sig_packet(&old_packet).is_none());
    }

    #[test]
    fn malformed_subpacket_area_is_a_malformed_packet() {
        // Truncated subpacket: the length promises nine bytes and
        // only the type byte follows.
        assert!(parse_sig_packet(&v4_packet(&[9, 16])).is_none());
        // Zero-length subpacket.
        assert!(parse_sig_packet(&v4_packet(&[0])).is_none());
        // Truncated five-octet length: the marker promises four more
        // bytes and two follow.
        assert!(parse_sig_packet(&v4_packet(&[255, 0, 0])).is_none());
        // Malformed hashed area: the same truncation on the hashed
        // side makes the packet malformed too.
        assert!(parse_sig_packet(&v4_packet_with_areas(&[9, 16], &[])).is_none());
        // Malformed bytes after a valid issuer subpacket: the whole
        // area is validated, so the trailing truncation still makes
        // the packet malformed.
        let mut area = vec![9u8, 16];
        area.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        area.extend_from_slice(&[5, 1]);
        assert!(parse_sig_packet(&v4_packet(&area)).is_none());
    }

    #[test]
    fn well_formed_issuerless_area_parses_without_an_issuer() {
        // Near miss: an empty area is well-formed and issuer-less.
        let parsed = parse_sig_packet(&v4_packet(&[])).expect("empty area parses");
        assert_eq!(parsed.issuer, None);
        // Near miss: a well-formed subpacket of an unrelated type is
        // well-formed and issuer-less.
        let parsed = parse_sig_packet(&v4_packet(&[1, 0])).expect("unknown subpacket parses");
        assert_eq!(parsed.issuer, None);
        // Direct split pin: a well-formed issuer-less area and a
        // malformed area report distinctly.
        assert_eq!(issuer_from_subpackets(&[]), Some(None));
        assert_eq!(issuer_from_subpackets(&[9, 16]), None);
        assert_eq!(
            issuer_from_subpackets(&[9, 16, 1, 2, 3, 4, 5, 6, 7, 8]),
            Some(Some([1, 2, 3, 4, 5, 6, 7, 8]))
        );
    }
}
