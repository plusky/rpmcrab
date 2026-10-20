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
//!
//! Signature packets are parsed with sequoia-openpgp's low-level
//! packet parser: the parse classifies each signature blob — a
//! structurally invalid packet is the `invalid-signature` case —
//! and yields the issuer the key ID is read from.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use librpm::keyring::Keyring;
use librpm::verify::{VerificationFlags, VerifyOptions};
use librpm::{PackageHeader, RpmErrorKind};

use openpgp::packet::Signature;
use openpgp::packet::signature::subpacket::{SubpacketArea, SubpacketValue};
use openpgp::parse::Parse as _;
use openpgp::{Packet, PacketPile};
use sequoia_openpgp as openpgp;

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
        // hence the serialisation: verified reads run one at a time
        // even under `-j` parallelism, and while one runs, librpm
        // diagnostics from other checks running concurrently are
        // masked along with it — rpmlog offers no per-read sink, so
        // the global mask is the only way to keep the duplicate
        // verdict text out of the report. The lock scopes to this
        // check's verified reads only: other checks are not locked
        // and keep running, and the lock is released as soon as the
        // read returns.
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
        // The read runs under `guarded`, like `Pkg::open`'s read:
        // librpm's decoders can panic on a malformed header, and the
        // contained panic becomes `Unreadable` here instead of
        // unwinding through the verification lock in `verify`.
        let read = crate::pkg::guarded(|| {
            PackageHeader::from_file(path, Some(&options)).map_err(|source| {
                crate::pkg::PkgError::Open {
                    path: path.to_path_buf(),
                    source,
                }
            })
        });
        match read {
            Ok(_) => Verdict::Verified,
            Err(crate::pkg::PkgError::Open {
                source: RpmErrorKind::NoKey,
                ..
            }) => Verdict::NoKey,
            // `NotTrusted` is not produced for OpenPGP signatures under
            // the rpmdb keyring model (an absent key reports `NoKey`);
            // classify it with the other verification failures.
            Err(crate::pkg::PkgError::Open {
                source: RpmErrorKind::Fail | RpmErrorKind::NotTrusted,
                ..
            }) => Verdict::Failed,
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

/// Parse one OpenPGP signature packet with sequoia-openpgp's packet
/// parser. `None` when the packet is structurally invalid (bad
/// framing, truncation, an unsupported version, malformed MPIs or
/// subpacket areas) — the case librpm reports as an invalid OpenPGP
/// signature, as opposed to a well-formed signature that merely
/// fails verification. The blob holds exactly one packet: each RPM
/// signature entry carries a single signature.
fn parse_sig_packet(blob: &[u8]) -> Option<SigPacket> {
    let pile = PacketPile::from_bytes(blob).ok()?;
    let mut children = pile.into_children();
    let sig = match (children.next(), children.next()) {
        (Some(Packet::Signature(sig)), None) => sig,
        _ => return None,
    };
    Some(SigPacket {
        issuer: issuer_of(&sig),
    })
}

/// The issuer key ID of a parsed signature packet. The unhashed
/// subpacket area provides it first — within one area an issuer
/// subpacket wins over the issuer-fingerprint subpacket, whose low
/// 64 bits the key ID is — then the hashed area. Version 3 packets
/// carry the key ID in the packet body, where the parser surfaces
/// it with the packet's issuers.
fn issuer_of(sig: &Signature) -> Option<[u8; 8]> {
    fn area_issuer(area: &SubpacketArea) -> Option<[u8; 8]> {
        let mut issuer = None;
        let mut from_fingerprint = None;
        for subpacket in area.iter() {
            // A subpacket whose value cannot be read as an issuer is
            // skipped, uniformly for both issuer kinds: it neither
            // aborts the scan of the rest of the area nor panics, so
            // a later well-formed subpacket still provides the issuer.
            match subpacket.value() {
                SubpacketValue::Issuer(key_id) => {
                    if issuer.is_none()
                        && let Ok(key_id) = key_id.as_bytes().try_into()
                    {
                        issuer = Some(key_id);
                    }
                }
                SubpacketValue::IssuerFingerprint(fingerprint) => {
                    let bytes = fingerprint.as_bytes();
                    if bytes.len() >= 8
                        && let Ok(key_id) = bytes[bytes.len() - 8..].try_into()
                    {
                        from_fingerprint = Some(key_id);
                    }
                }
                _ => {}
            }
        }
        issuer.or(from_fingerprint)
    }

    if sig.version() == 3 {
        return sig
            .issuers()
            .next()
            .and_then(|key_id| key_id.as_bytes().try_into().ok());
    }
    area_issuer(sig.unhashed_area())
        .or_else(|| area_issuer(sig.hashed_area()))
        .or_else(|| {
            sig.issuers()
                .next()
                .and_then(|key_id| key_id.as_bytes().try_into().ok())
        })
}

/// Format an issuer key ID the way `rpm -Kv` prints it: the low 32
/// bits, lowercase hex.
fn key_id_string(issuer: &[u8; 8]) -> String {
    issuer[4..]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The details `unknown-key` reports carry: one key ID per distinct
/// issuer among the parsed packets, in packet order, and no detail
/// when no packet provides an issuer — the reference's NOKEY pattern
/// fires with an empty key ID for an issuer-less signature too, so
/// the report in `check` is unconditional and only its details vary.
/// A package can carry several signatures; the verified read's
/// `NoKey` verdict does not say which signature's key is missing, so
/// each issuer gets its own report in `check` and the missing key is
/// never silently attributed to the first packet's issuer alone.
fn unknown_key_details(parsed: &[Option<SigPacket>]) -> Vec<String> {
    let mut details = Vec::new();
    for packet in parsed.iter().flatten() {
        if let Some(issuer) = packet.issuer {
            let key_id = key_id_string(&issuer);
            if !details.contains(&key_id) {
                details.push(key_id);
            }
        }
    }
    details
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
                } else {
                    let details = unknown_key_details(&parsed);
                    if details.is_empty() {
                        add_info(out, Level::Error, pkg, "unknown-key", &[]);
                    } else {
                        // One report per distinct issuer, mirroring
                        // the one NOKEY line per signature `rpm -Kv`
                        // prints.
                        for detail in &details {
                            add_info(out, Level::Error, pkg, "unknown-key", &[detail.as_str()]);
                        }
                    }
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
        body.extend_from_slice(&[0x92, 0x34]);
        assert!(body.len() < 192, "helpers emit the one-octet length form");
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
        body.extend_from_slice(&[0x92, 0x34]);
        assert!(body.len() < 192, "helpers emit the one-octet length form");
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
        body.extend_from_slice(&[0x92, 0x34]);
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
        body.extend_from_slice(&[0x92, 0x34]);
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
    fn wrong_length_issuer_subpackets_are_malformed() {
        // Type 16 with a 7-byte body: the issuer subpacket carries
        // exactly the 8-byte key ID, so a shorter body is malformed,
        // not issuer-less.
        let mut area = vec![8u8, 16];
        area.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7]);
        assert!(parse_sig_packet(&v4_packet(&area)).is_none());
        // Type 16 with a 9-byte body: over-long is malformed too.
        let mut area = vec![10u8, 16];
        area.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert!(parse_sig_packet(&v4_packet(&area)).is_none());
        // Type 33 carrying only the version byte: the fingerprint is
        // absent, so the low 64 bits the key ID needs are missing.
        assert!(parse_sig_packet(&v4_packet(&[2, 33, 4])).is_none());
        // Type 33 with a 4-byte fingerprint: truncated below the low
        // 64 bits.
        let area = [6u8, 33, 4, 0xaa, 0xbb, 0xcc, 0xdd];
        assert!(parse_sig_packet(&v4_packet(&area)).is_none());
        // A truncated type 33 after a valid issuer subpacket still
        // makes the whole area malformed.
        let mut area = vec![9u8, 16];
        area.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        area.extend_from_slice(&[2, 33, 4]);
        assert!(parse_sig_packet(&v4_packet(&area)).is_none());
        // Type 33 whose fingerprint is exactly 8 bytes: the subpacket
        // carries the full fingerprint (20 bytes for version 4), so a
        // fingerprint cut down to the key ID alone is malformed too.
        let mut area = vec![10u8, 33, 4];
        area.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(parse_sig_packet(&v4_packet(&area)).is_none());
        // Near miss: a type 33 with the full fingerprint parses, and
        // the key ID is its low 64 bits.
        let mut area = vec![22u8, 33, 4];
        area.extend_from_slice(&[0xaa; 12]);
        area.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let parsed = parse_sig_packet(&v4_packet(&area)).expect("packet parses");
        assert_eq!(parsed.issuer, Some([1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn v5_relabeled_packet_does_not_parse() {
        // A signature packet relabeled to the nonexistent version 5
        // is structurally invalid (ledgered tightening, #779 D5).
        let mut packet = v4_packet(&[]);
        packet[2] = 5;
        assert!(parse_sig_packet(&packet).is_none());
    }

    #[test]
    fn indeterminate_length_packet_does_not_parse() {
        // Old-format header with the indeterminate length form
        // (ledgered tightening, #779 D5): stored signature packets
        // are length-delimited.
        let mut body = vec![3u8, 5, 2];
        body.extend_from_slice(&[0; 4]); // creation time
        body.extend_from_slice(&[0xaa; 8]); // key ID
        body.extend_from_slice(&[1, 8]); // RSA, SHA256
        body.extend_from_slice(&[0xab, 0xcd]);
        body.extend_from_slice(&16u16.to_be_bytes());
        body.extend_from_slice(&[0x92, 0x34]);
        // Old format, tag 2, indeterminate length: 0x80 | (2 << 2) | 3.
        let mut packet = vec![0x8bu8];
        packet.extend_from_slice(&body);
        assert!(parse_sig_packet(&packet).is_none());
    }

    #[test]
    fn noncanonical_mpi_packet_does_not_parse() {
        // An MPI whose declared bit length exceeds the value's actual
        // bit length (0x1234 is a 13-bit value) is not the canonical
        // MPI encoding (ledgered tightening, #779 D5 family).
        let mut packet = v4_packet(&[]);
        let len = packet.len();
        packet[len - 2] = 0x12;
        packet[len - 1] = 0x34;
        assert!(parse_sig_packet(&packet).is_none());
    }

    #[test]
    fn critical_bit_issuer_subpackets_are_read() {
        // Subpacket types carry the critical flag in the type octet's
        // top bit (0x90 = issuer, 0xA1 = issuer fingerprint); the
        // issuer is read through it (#737 item 1).
        let mut area = vec![9u8, 0x90];
        area.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let parsed = parse_sig_packet(&v4_packet(&area)).expect("packet parses");
        assert_eq!(parsed.issuer, Some([1, 2, 3, 4, 5, 6, 7, 8]));
        let mut area = vec![22u8, 0xa1, 4];
        area.extend_from_slice(&[0xaa; 12]);
        area.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let parsed = parse_sig_packet(&v4_packet(&area)).expect("packet parses");
        assert_eq!(parsed.issuer, Some([1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn zero_bit_mpi_packet_parses() {
        // A zero-bit MPI is the canonical encoding of the value zero
        // and parses (#737 item 4); the packet's issuer still reads.
        let mut area = vec![9u8, 16];
        area.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut body = vec![4u8, 0, 1, 8]; // version, type, RSA, SHA256
        body.extend_from_slice(&0u16.to_be_bytes()); // no hashed area
        body.extend_from_slice(&(area.len() as u16).to_be_bytes());
        body.extend_from_slice(&area);
        body.extend_from_slice(&[0xab, 0xcd]); // left 16 bits of the hash
        body.extend_from_slice(&0u16.to_be_bytes()); // MPI: 0 bits, no bytes
        assert!(body.len() < 192, "helpers emit the one-octet length form");
        let mut packet = vec![0xc2u8, body.len() as u8];
        packet.extend_from_slice(&body);
        let parsed = parse_sig_packet(&packet).expect("packet parses");
        assert_eq!(parsed.issuer, Some([1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn chunked_length_packet_does_not_parse() {
        // New-format partial (chunked) body lengths are a streaming
        // encoding; a stored signature packet is length-delimited, so
        // the chunked form (two chunks of 16 and 8 bytes plus the
        // final zero-length chunk, carrying the 24-byte helper body)
        // classifies with the malformed packets.
        let packet = v4_packet(&{
            let mut area = vec![9u8, 16];
            area.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
            area
        });
        let body = &packet[2..];
        assert_eq!(body.len(), 24);
        let mut chunked = vec![0xc2u8, 228]; // partial chunk: 2^(228-224) = 16 bytes
        chunked.extend_from_slice(&body[..16]);
        chunked.push(227); // partial chunk: 2^(227-224) = 8 bytes
        chunked.extend_from_slice(&body[16..]);
        chunked.push(0); // final chunk: 0 bytes
        assert!(parse_sig_packet(&chunked).is_none());
    }

    #[test]
    fn missing_file_verified_read_is_unreadable() {
        let config = Config::default();
        let check = SignatureCheck::new(&config);
        let missing = inputs().join("signature-no-such-file.rpm");
        assert!(matches!(check.verify(&missing), Verdict::Unreadable));
    }

    #[test]
    fn unknown_key_details_without_an_issuer_are_empty() {
        // Issuer-less packets (empty or unrelated subpacket areas)
        // carry no detail; the `unknown-key` report itself is
        // unconditional in `check`, so an empty detail list is the
        // issuer-less outcome, not silence.
        let issuerless = [Some(SigPacket { issuer: None })];
        assert_eq!(unknown_key_details(&issuerless), Vec::<String>::new());
        assert_eq!(unknown_key_details(&[]), Vec::<String>::new());
        // An issuer later in the list still names the key.
        let mixed = [
            Some(SigPacket { issuer: None }),
            Some(SigPacket {
                issuer: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            }),
        ];
        assert_eq!(unknown_key_details(&mixed), ["05060708".to_string()]);
        // Several signatures: every distinct issuer is named, in
        // packet order, with duplicates collapsed — the missing key
        // is not attributed to the first packet alone.
        let multi = [
            Some(SigPacket {
                issuer: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            }),
            Some(SigPacket {
                issuer: Some([0xaa; 8]),
            }),
            Some(SigPacket {
                issuer: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            }),
        ];
        assert_eq!(
            unknown_key_details(&multi),
            ["05060708".to_string(), "aaaaaaaa".to_string()]
        );
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
        // A malformed area and a well-formed one report distinctly
        // at the packet level too.
        assert!(parse_sig_packet(&v4_packet(&[9, 16])).is_none());
        let parsed =
            parse_sig_packet(&v4_packet(&[9, 16, 1, 2, 3, 4, 5, 6, 7, 8])).expect("packet parses");
        assert_eq!(parsed.issuer, Some([1, 2, 3, 4, 5, 6, 7, 8]));
    }
}
