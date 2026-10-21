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
//! Extraction reads both signature storage forms: the classic
//! signature-header tags, each carrying one raw signature packet,
//! and the v6 `RPMSIGTAG_OPENPGP` entry, a string array whose
//! strings are base64-encoded signature packets. A packet already
//! collected from either form is not collected again and does not
//! count toward the total size cap again, so a signature stored in
//! both forms is classified once.
//!
//! Signature packets are parsed with sequoia-openpgp's low-level
//! packet parser: the parse classifies each signature blob — a
//! structurally invalid packet is the `invalid-signature` case —
//! and yields the issuer the key ID is read from.

use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use base64::Engine as _;
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

/// The v6 signature entry: `RPMSIGTAG_OPENPGP` (278), a STRING_ARRAY
/// whose strings are base64-encoded OpenPGP signature packets, one
/// string per signature — the form `rpmsign` from rpm 6.x writes.
const OPENPGP_TAG: u32 = 278;

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

/// The raw-text size cap for the `RPMSIGTAG_OPENPGP` entries of one
/// header: base64 text runs 4/3 the size of the packets it encodes,
/// so text exceeding twice the total blob cap would decode past
/// that cap anyway; the bound keeps the entries' reads in the same
/// order as the decoded data they can yield. Each entry's span is
/// charged against the bound as it is read, so the text read for
/// one package stays within the bound however many entries the
/// header carries.
const MAX_CONTAINER_BYTES: usize = 2 * MAX_TOTAL_BLOB_BYTES;

/// The encoded-length cap for one `RPMSIGTAG_OPENPGP` string:
/// base64 writes four characters per three bytes, so a packet at
/// the per-blob cap encodes to this many characters, and a longer
/// string is rejected on its encoded length alone, before decoding.
const MAX_ENCODED_BLOB_BYTES: usize = 4 * MAX_BLOB_BYTES.div_ceil(3);

/// The signature blobs read from a package's signature header, plus
/// the header's signature presence: `has_entries` records that the
/// header carries OpenPGP signature entries, and `has_unreadable`
/// records that at least one such entry stayed unreadable.
#[derive(Debug, Default, PartialEq, Eq)]
struct SignatureBlobs {
    /// The readable signature blobs, in header index order.
    blobs: Vec<Vec<u8>>,
    /// The membership index of `blobs`: the collected blobs as a
    /// set, so testing a further blob against the collected ones
    /// does not scan the vector.
    seen: HashSet<Vec<u8>>,
    /// The header carries at least one OpenPGP signature entry.
    has_entries: bool,
    /// At least one signature entry stayed unreadable: its range
    /// falls outside the header store, its size exceeds a size cap
    /// or is zero, or its file read failed.
    has_unreadable: bool,
}

impl SignatureBlobs {
    /// Whether the identical blob is already collected.
    fn contains(&self, blob: &[u8]) -> bool {
        self.seen.contains(blob)
    }

    /// Collect a blob the caller has found new and charged against
    /// the totals: it joins `blobs` in header order and `seen`
    /// alongside, keeping the two in step.
    fn collect(&mut self, blob: Vec<u8>) {
        self.seen.insert(blob.clone());
        self.blobs.push(blob);
    }
}

/// The running totals the size caps are charged against while a
/// signature header is read: the decoded packet bytes (against
/// `MAX_TOTAL_BLOB_BYTES`) and the OPENPGP entries' raw span bytes
/// (against `MAX_CONTAINER_BYTES`).
#[derive(Debug, Default)]
struct SizeTotals {
    total_bytes: usize,
    span_bytes: usize,
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
    let mut totals = SizeTotals::default();
    for entry in index.as_chunks::<16>().0 {
        let tag = be_u32(&entry[0..4]);
        let entry_type = be_u32(&entry[4..8]);
        let offset = be_u32(&entry[8..12]) as usize;
        let count = be_u32(&entry[12..16]) as usize;
        if tag == OPENPGP_TAG && entry_type == 8 {
            // Type 8 is STRING_ARRAY; for the OPENPGP entry the
            // count is the number of base64 strings.
            read_openpgp_entry(
                &mut file,
                store_start,
                store_size,
                offset,
                count,
                &mut totals,
                &mut result,
            );
            continue;
        }
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
        // A zero-count entry carries no packet bytes: it counts
        // toward the unreadable side instead of collecting an
        // empty blob.
        if count == 0 {
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
        if file.read_exact(&mut blob).is_err() {
            result.has_unreadable = true;
            continue;
        }
        // A packet already collected — from an earlier classic entry
        // or the OPENPGP entry — is not collected again and does not
        // count toward the total cap again.
        if result.contains(&blob) {
            continue;
        }
        if totals.total_bytes.saturating_add(count) > MAX_TOTAL_BLOB_BYTES {
            result.has_unreadable = true;
            continue;
        }
        totals.total_bytes += count;
        result.collect(blob);
    }
    result
}

/// Read one `RPMSIGTAG_OPENPGP` entry: `count` NUL-terminated base64
/// strings starting at `offset` in the header store. Each string
/// decodes to one signature packet, which joins the collected blobs
/// unless the identical packet is already there. A string that
/// does not terminate within the entry's readable span, exceeds
/// the encoded-length cap, is not valid base64, or decodes past a
/// size cap or to an empty packet counts toward the entry's
/// unreadable side, the same outcome an unreadable classic entry
/// produces. The entry's span is charged to the span total as it
/// is read; an entry whose span would carry that total past
/// `MAX_CONTAINER_BYTES` counts as unreadable and is not read. A
/// zero-count entry counts as unreadable and is not read either,
/// mirroring a zero-count classic entry.
fn read_openpgp_entry(
    file: &mut File,
    store_start: u64,
    store_size: usize,
    offset: usize,
    count: usize,
    totals: &mut SizeTotals,
    result: &mut SignatureBlobs,
) {
    result.has_entries = true;
    // A zero-count entry carries no strings: it counts toward the
    // unreadable side and is not read, the outcome a zero-count
    // classic entry produces.
    if count == 0 {
        result.has_unreadable = true;
        return;
    }
    if offset > store_size {
        result.has_unreadable = true;
        return;
    }
    let span = (store_size - offset).min(MAX_CONTAINER_BYTES);
    if totals.span_bytes.saturating_add(span) > MAX_CONTAINER_BYTES {
        result.has_unreadable = true;
        return;
    }
    let mut raw = vec![0u8; span];
    if file
        .seek(SeekFrom::Start(store_start + offset as u64))
        .is_err()
        || file.read_exact(&mut raw).is_err()
    {
        result.has_unreadable = true;
        return;
    }
    totals.span_bytes += span;
    let mut pos = 0usize;
    for _ in 0..count {
        let Some(nul) = raw[pos..].iter().position(|&b| b == 0) else {
            result.has_unreadable = true;
            return;
        };
        let text = &raw[pos..pos + nul];
        pos += nul + 1;
        if text.len() > MAX_ENCODED_BLOB_BYTES {
            result.has_unreadable = true;
            continue;
        }
        let Ok(packet) = base64::engine::general_purpose::STANDARD.decode(text) else {
            result.has_unreadable = true;
            continue;
        };
        // An empty packet carries no signature: the string counts
        // toward the unreadable side instead of collecting an
        // empty blob.
        if packet.is_empty() {
            result.has_unreadable = true;
            continue;
        }
        if packet.len() > MAX_BLOB_BYTES {
            result.has_unreadable = true;
            continue;
        }
        // A packet already collected — from an earlier string or a
        // classic entry — is not collected again and does not count
        // toward the total cap again.
        if result.contains(&packet) {
            continue;
        }
        if totals.total_bytes.saturating_add(packet.len()) > MAX_TOTAL_BLOB_BYTES {
            result.has_unreadable = true;
            continue;
        }
        totals.total_bytes += packet.len();
        result.collect(packet);
    }
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
    /// `build-signature-fixtures.sh` creates new keys; the script
    /// prints the new values to put here.
    const EXPECTED_KEY_ID: &str = "c5395b5e";

    /// The low-32-bit key ID of the second fixture signing key: the
    /// stacked fixture carries one signature from each fixture key.
    const EXPECTED_KEY_ID_2: &str = "7cbec8b5";

    /// The low-32-bit key ID of the first OPENPGP fixture signing
    /// key, as the check reports it. Regenerating the fixtures with
    /// `build-signature-openpgp-fixtures.sh` creates new keys; the
    /// script prints the new values to put here.
    const EXPECTED_OPENPGP_KEY_ID: &str = "3d3f5948";

    /// The low-32-bit key ID of the second OPENPGP fixture signing
    /// key, which signs only the dual-signature fixture.
    const EXPECTED_OPENPGP_KEY2_ID: &str = "c96e0115";

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
        keyring_with(&["signature-testkey.gpg"])
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

    /// librpm's OpenPGP backend keeps process-global state, and
    /// concurrent first use from several test threads can corrupt a
    /// verdict, so keyring construction and the verified read run
    /// serially within this module.
    static LOCK: Mutex<()> = Mutex::new(());

    fn run_check(pkg: &Pkg, choice: KeyringChoice) -> Vec<(String, String)> {
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
    fn stacked_signatures_report_each_issuer() {
        // The stacked fixture carries signatures from two distinct
        // keys (the header signature at tag 268 from the fixture
        // key, the legacy PGP signature at tag 1002 from the second
        // key) and the keyring holds neither: one `unknown-key`
        // report per distinct issuer, each with its own key ID, in
        // packet order — a regression to first-issuer-only
        // reporting fails this with a single report.
        let pkg = fixture_pkg("signature-stacked-1.0-1.noarch.rpm");
        let results = run_check(&pkg, KeyringChoice::Empty);
        assert_eq!(
            finding_names(&results),
            ["unknown-key", "unknown-key"],
            "{results:?}"
        );
        assert!(
            results[0].1.contains(EXPECTED_KEY_ID),
            "first detail: {}",
            results[0].1
        );
        assert!(
            results[1].1.contains(EXPECTED_KEY_ID_2),
            "second detail: {}",
            results[1].1
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
        let typed: Vec<(u32, u32, u32, u32)> = entries
            .iter()
            .map(|&(tag, offset, count)| (tag, 7, offset, count))
            .collect();
        write_typed_signature_header(&typed, store)
    }

    /// Write a synthetic package like `write_signature_header`, with
    /// an explicit entry type per entry: `entries` are
    /// `(tag, type, offset, count)`.
    fn write_typed_signature_header(
        entries: &[(u32, u32, u32, u32)],
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
        for &(tag, entry_type, offset, count) in entries {
            data.extend_from_slice(&tag.to_be_bytes());
            data.extend_from_slice(&entry_type.to_be_bytes());
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
        // Each entry's bytes differ, so identical-packet dedupe
        // cannot mask the total accounting this test pins.
        let store: Vec<u8> = (0..17u8)
            .flat_map(|fill| vec![fill; MAX_BLOB_BYTES])
            .collect();
        let (_dir, path) = write_signature_header(&entries, &store);
        let sig = signature_blobs(&path);
        assert_eq!(sig.blobs.len(), 16);
        assert!(sig.has_entries);
        assert!(sig.has_unreadable);
    }

    #[test]
    fn duplicate_classic_signature_counts_once() {
        // The same packet under two classic tags is collected once.
        let packet = v4_packet(&[0, 2, 0, 0, 5, 5, 5, 5, 5, 5, 5, 5]);
        let len = packet.len() as u32;
        let (_dir, path) = write_signature_header(&[(268, 0, len), (1002, 0, len)], &packet);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(!blobs.has_unreadable);
        assert_eq!(blobs.blobs, [packet]);
    }

    #[test]
    fn repeated_classic_signature_does_not_consume_the_total_cap() {
        // Seventeen classic entries naming the same packet at the
        // per-blob cap: the packet is collected once, and the
        // repeats neither fill the total cap nor count as unreadable.
        let per_blob = MAX_BLOB_BYTES as u32;
        let entries: Vec<(u32, u32, u32)> = (0..17).map(|_| (1002, 0, per_blob)).collect();
        let store = vec![0x89u8; MAX_BLOB_BYTES];
        let (_dir, path) = write_signature_header(&entries, &store);
        let sig = signature_blobs(&path);
        assert_eq!(sig.blobs.len(), 1);
        assert!(sig.has_entries);
        assert!(!sig.has_unreadable);
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

    /// A keyring holding the given OPENPGP fixture keys.
    fn keyring_with(files: &[&str]) -> Keyring {
        let mut keyring = Keyring::new();
        for name in files {
            let raw = std::fs::read(inputs().join(name)).expect("read fixture key");
            keyring
                .add_key(&PubKey::new(&raw).expect("fixture key parses"))
                .expect("fixture key added");
        }
        keyring
    }

    /// Run the check against a keyring holding `key_files`. The
    /// OPENPGP fixtures are signed with their own keys, so they do
    /// not go through `run_check`'s keyring choices.
    fn run_check_openpgp(pkg: &Pkg, key_files: &[&str]) -> Vec<(String, String)> {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SignatureCheck::with_keyring(keyring_with(key_files));
        check.check(pkg, &config, &mut out);
        out.results().to_vec()
    }

    /// Whether the linked librpm reads the v6 OPENPGP signature
    /// entry: librpm from rpm 6 verifies those signatures, so the
    /// container-only fixture reports `NoKey` against an empty
    /// keyring; an older librpm sees no signatures in the package at
    /// all and the verified read comes back clean. The check-level
    /// expectations for the container-only and dual fixtures branch
    /// on this; the extraction assertions pin the behaviour this
    /// crate controls on every platform.
    fn librpm_reads_openpgp_container() -> bool {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let check = SignatureCheck::with_keyring(Keyring::new());
        matches!(
            check.verify(&inputs().join("signature-openpgp-1.0-1.noarch.rpm")),
            Verdict::NoKey
        )
    }

    /// Base64-encode `bytes` the way `rpmsign` writes the OPENPGP
    /// entry's strings.
    fn base64_of(bytes: &[u8]) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .encode(bytes)
            .into_bytes()
    }

    #[test]
    fn openpgp_container_only_extracts_its_signature() {
        // The container-only fixture carries one signature in the v6
        // entry and none in the classic tags; extraction returns the
        // decoded packet, which parses and names the fixture key.
        let blobs = signature_blobs(&inputs().join("signature-openpgp-1.0-1.noarch.rpm"));
        assert!(blobs.has_entries);
        assert!(!blobs.has_unreadable);
        assert_eq!(blobs.blobs.len(), 1);
        let parsed = parse_sig_packet(&blobs.blobs[0]).expect("container packet parses");
        assert_eq!(
            key_id_string(&parsed.issuer.expect("issuer present")),
            EXPECTED_OPENPGP_KEY_ID
        );
    }

    #[test]
    fn openpgp_dual_extracts_two_distinct_signatures() {
        let blobs = signature_blobs(&inputs().join("signature-openpgp-dual-1.0-1.noarch.rpm"));
        assert!(blobs.has_entries);
        assert!(!blobs.has_unreadable);
        assert_eq!(blobs.blobs.len(), 2);
        let mut ids: Vec<String> = blobs
            .blobs
            .iter()
            .map(|b| {
                let parsed = parse_sig_packet(b).expect("container packet parses");
                key_id_string(&parsed.issuer.expect("issuer present"))
            })
            .collect();
        ids.sort();
        assert_eq!(ids, [EXPECTED_OPENPGP_KEY_ID, EXPECTED_OPENPGP_KEY2_ID]);
    }

    #[test]
    fn openpgp_mixed_counts_a_shared_signature_once() {
        // The mixed fixture stores the same signature in the classic
        // tag and in the container; extraction returns it once.
        let blobs = signature_blobs(&inputs().join("signature-openpgp-mixed-1.0-1.noarch.rpm"));
        assert!(blobs.has_entries);
        assert!(!blobs.has_unreadable);
        assert_eq!(blobs.blobs.len(), 1);
        let parsed = parse_sig_packet(&blobs.blobs[0]).expect("mixed packet parses");
        assert_eq!(
            key_id_string(&parsed.issuer.expect("issuer present")),
            EXPECTED_OPENPGP_KEY_ID
        );
    }

    #[test]
    fn openpgp_entry_reads_each_of_its_strings() {
        // Two distinct packets as two base64 strings in one entry.
        let first = v4_packet(&[0, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]);
        let second = v4_packet(&[0, 2, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2]);
        let mut store = base64_of(&first);
        store.push(0);
        store.extend_from_slice(&base64_of(&second));
        store.push(0);
        let (_dir, path) = write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 2)], &store);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(!blobs.has_unreadable);
        assert_eq!(blobs.blobs, [first, second]);
    }

    #[test]
    fn openpgp_duplicate_of_a_classic_signature_counts_once() {
        // The same packet in a classic tag and in the container.
        let packet = v4_packet(&[0, 2, 0, 0, 3, 3, 3, 3, 3, 3, 3, 3]);
        let mut store = Vec::new();
        store.extend_from_slice(&base64_of(&packet));
        store.push(0);
        store.extend_from_slice(&packet);
        let classic_offset = (base64_of(&packet).len() + 1) as u32;
        let (_dir, path) = write_typed_signature_header(
            &[
                (268, 7, classic_offset, packet.len() as u32),
                (OPENPGP_TAG, 8, 0, 1),
            ],
            &store,
        );
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(!blobs.has_unreadable);
        assert_eq!(blobs.blobs, [packet]);
    }

    #[test]
    fn openpgp_string_that_is_not_base64_is_unreadable() {
        let store = b"not base64!\0".to_vec();
        let (_dir, path) = write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 1)], &store);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(blobs.has_unreadable);
        assert!(blobs.blobs.is_empty());
    }

    #[test]
    fn openpgp_string_without_a_terminator_is_unreadable() {
        let store = base64_of(&v4_packet(&[0, 2, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4]));
        let (_dir, path) = write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 1)], &store);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(blobs.has_unreadable);
        assert!(blobs.blobs.is_empty());
    }

    #[test]
    fn openpgp_entry_with_a_binary_type_is_not_an_entry() {
        // A 278 entry typed BIN is skipped like a wrong-typed classic
        // entry: it is not a signature entry at all.
        let store = vec![0u8; 16];
        let (_dir, path) = write_typed_signature_header(&[(OPENPGP_TAG, 7, 0, 16)], &store);
        let blobs = signature_blobs(&path);
        assert!(!blobs.has_entries);
        assert!(!blobs.has_unreadable);
        assert!(blobs.blobs.is_empty());
    }

    #[test]
    fn openpgp_packet_past_the_blob_cap_is_unreadable() {
        let packet = vec![0x89u8; MAX_BLOB_BYTES + 1];
        let mut store = base64_of(&packet);
        store.push(0);
        let (_dir, path) = write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 1)], &store);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(blobs.has_unreadable);
        assert!(blobs.blobs.is_empty());
    }

    #[test]
    fn openpgp_packet_at_the_blob_cap_is_collected() {
        // A packet of exactly the per-blob cap encodes to exactly
        // the encoded-length cap and is collected: the gate rejects
        // only strings that decode past the cap.
        let packet = vec![0x89u8; MAX_BLOB_BYTES];
        let mut store = base64_of(&packet);
        store.push(0);
        let (_dir, path) = write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 1)], &store);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(!blobs.has_unreadable);
        assert_eq!(blobs.blobs, [packet]);
    }

    #[test]
    fn openpgp_string_past_the_encoded_cap_is_unreadable() {
        // A string past the encoded-length cap decodes past the
        // per-blob cap whatever its content; it counts as unreadable
        // and the following string is still read.
        let packet = v4_packet(&[0, 2, 0, 0, 6, 6, 6, 6, 6, 6, 6, 6]);
        let mut store = vec![b'A'; MAX_ENCODED_BLOB_BYTES + 4];
        store.push(0);
        store.extend_from_slice(&base64_of(&packet));
        store.push(0);
        let (_dir, path) = write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 2)], &store);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(blobs.has_unreadable);
        assert_eq!(blobs.blobs, [packet]);
    }

    #[test]
    fn openpgp_repeated_packet_does_not_consume_the_total_cap() {
        // Seventeen strings encoding the same packet at the
        // per-blob cap: the packet is collected once, and the
        // repeats neither fill the total cap nor count as unreadable.
        let packet = vec![0x89u8; MAX_BLOB_BYTES];
        let mut store = Vec::new();
        for _ in 0..17 {
            store.extend_from_slice(&base64_of(&packet));
            store.push(0);
        }
        let (_dir, path) = write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 17)], &store);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(!blobs.has_unreadable);
        assert_eq!(blobs.blobs, [packet]);
    }

    #[test]
    fn openpgp_entry_reads_strings_past_a_total_cap_overflow() {
        // The classic path marks an entry past the total cap
        // unreadable and reads the entries after it; the container
        // path does the same with its strings. After the overflow
        // the remaining strings are still read: the trailing empty
        // string is read and counts as unreadable, because it
        // decodes to an empty packet and an empty packet is
        // rejected rather than collected.
        let mut store = Vec::new();
        for fill in 0..17u8 {
            store.extend_from_slice(&base64_of(&vec![fill; MAX_BLOB_BYTES]));
            store.push(0);
        }
        store.push(0);
        let (_dir, path) = write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 18)], &store);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(blobs.has_unreadable);
        assert_eq!(blobs.blobs.len(), 16);
        assert!(blobs.blobs.iter().all(|blob| !blob.is_empty()));
    }

    #[test]
    fn openpgp_packets_past_the_total_cap_are_unreadable() {
        // Seventeen distinct packets at the per-blob cap in one
        // entry: the first sixteen fill the total cap exactly, and
        // the seventeenth counts as unreadable and is not collected.
        let mut store = Vec::new();
        for fill in 0..17u8 {
            store.extend_from_slice(&base64_of(&vec![fill; MAX_BLOB_BYTES]));
            store.push(0);
        }
        let (_dir, path) = write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 17)], &store);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(blobs.has_unreadable);
        assert_eq!(blobs.blobs.len(), 16);
    }

    #[test]
    fn openpgp_empty_string_is_unreadable() {
        // An empty string next to a readable one: the packet is
        // collected and the empty string counts as unreadable,
        // because it decodes to an empty packet.
        let packet = v4_packet(&[0, 2, 0, 0, 7, 7, 7, 7, 7, 7, 7, 7]);
        let mut store = base64_of(&packet);
        store.push(0);
        store.push(0);
        let (_dir, path) = write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 2)], &store);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(blobs.has_unreadable);
        assert_eq!(blobs.blobs, [packet]);

        // An entry whose only string is empty collects nothing.
        let (_dir, path) = write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 1)], &[0]);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(blobs.has_unreadable);
        assert!(blobs.blobs.is_empty());
    }

    #[test]
    fn classic_zero_count_entry_is_unreadable() {
        // A zero-count classic entry carries no packet bytes: it
        // counts as unreadable instead of collecting an empty
        // blob, and the readable entry next to it is collected.
        let packet = v4_packet(&[0, 2, 0, 0, 8, 8, 8, 8, 8, 8, 8, 8]);
        let len = packet.len() as u32;
        let (_dir, path) = write_signature_header(&[(1002, 0, 0), (268, 0, len)], &packet);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(blobs.has_unreadable);
        assert_eq!(blobs.blobs, [packet]);
    }

    #[test]
    fn openpgp_zero_count_entry_is_unreadable() {
        // A zero-count OPENPGP entry carries no strings: it counts
        // as unreadable instead of being read, and the readable
        // entry next to it is collected, the classic zero-count
        // outcome on the container path.
        let packet = v4_packet(&[0, 2, 0, 0, 11, 11, 11, 11, 11, 11, 11, 11]);
        let mut store = base64_of(&packet);
        store.push(0);
        let (_dir, path) =
            write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 0), (OPENPGP_TAG, 8, 0, 1)], &store);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(blobs.has_unreadable);
        assert_eq!(blobs.blobs, [packet]);

        // A lone zero-count entry collects nothing.
        let (_dir, path) = write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 0)], &store);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(blobs.has_unreadable);
        assert!(blobs.blobs.is_empty());

        // A zero-count entry charges nothing against the container
        // span bound either: the entry after it is read in full
        // even when its own span reaches the bound, which a charge
        // for the zero-count entry would already have exhausted.
        let packet = v4_packet(&[0, 2, 0, 0, 11, 11, 11, 11, 11, 11, 11, 11]);
        let mut store = base64_of(&packet);
        store.push(0);
        // Filler the second entry never scans (its count is one
        // string): it only stretches that entry's span to the bound.
        store.resize(MAX_CONTAINER_BYTES + 64, 0xaa);
        let (_dir, path) =
            write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 0), (OPENPGP_TAG, 8, 0, 1)], &store);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(blobs.has_unreadable);
        assert_eq!(blobs.blobs, [packet]);
    }

    #[test]
    fn openpgp_span_reads_share_one_container_bound() {
        // Two OPENPGP entries: the first entry's span reaches the
        // container bound (its store runs past it), so the second
        // entry's span would carry the charged total past the
        // bound — the second entry counts as unreadable and is
        // not read, while the first entry's packet is collected.
        let first = v4_packet(&[0, 2, 0, 0, 9, 9, 9, 9, 9, 9, 9, 9]);
        let second = v4_packet(&[0, 2, 0, 0, 10, 10, 10, 10, 10, 10, 10, 10]);
        let mut store = base64_of(&first);
        store.push(0);
        // Filler the first entry never scans (its count is one
        // string): it only stretches the first entry's span.
        store.resize(MAX_CONTAINER_BYTES + 64, 0xaa);
        let second_offset = store.len() as u32;
        store.extend_from_slice(&base64_of(&second));
        store.push(0);
        let (_dir, path) = write_typed_signature_header(
            &[(OPENPGP_TAG, 8, 0, 1), (OPENPGP_TAG, 8, second_offset, 1)],
            &store,
        );
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(blobs.has_unreadable);
        assert_eq!(blobs.blobs, [first]);

        // The second entry on its own is read and collected.
        let mut store = base64_of(&second);
        store.push(0);
        let (_dir, path) = write_typed_signature_header(&[(OPENPGP_TAG, 8, 0, 1)], &store);
        let blobs = signature_blobs(&path);
        assert!(blobs.has_entries);
        assert!(!blobs.has_unreadable);
        assert_eq!(blobs.blobs, [second]);
    }

    #[test]
    fn openpgp_container_only_with_key_is_quiet() {
        let pkg = fixture_pkg("signature-openpgp-1.0-1.noarch.rpm");
        let results = run_check_openpgp(&pkg, &["signature-openpgp-testkey.gpg"]);
        assert_eq!(results, Vec::<(String, String)>::new());
    }

    #[test]
    fn openpgp_container_only_without_key_reports_unknown_key() {
        let pkg = fixture_pkg("signature-openpgp-1.0-1.noarch.rpm");
        let results = run_check_openpgp(&pkg, &[]);
        if librpm_reads_openpgp_container() {
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].0, "unknown-key");
            assert!(results[0].1.contains(EXPECTED_OPENPGP_KEY_ID));
        } else {
            assert_eq!(results, Vec::<(String, String)>::new());
        }
    }

    #[test]
    fn openpgp_container_only_matches_its_classic_control() {
        // The control carries the same key's signature in the classic
        // tag only: with the key both are quiet, without it both
        // report the same unknown key.
        let control = fixture_pkg("signature-openpgp-classic-1.0-1.noarch.rpm");
        let control_results = run_check_openpgp(&control, &[]);
        assert_eq!(control_results.len(), 1);
        assert_eq!(control_results[0].0, "unknown-key");
        assert!(control_results[0].1.contains(EXPECTED_OPENPGP_KEY_ID));
        let control_with_key = run_check_openpgp(&control, &["signature-openpgp-testkey.gpg"]);
        assert_eq!(control_with_key, Vec::<(String, String)>::new());

        let container = fixture_pkg("signature-openpgp-1.0-1.noarch.rpm");
        if librpm_reads_openpgp_container() {
            let container_results = run_check_openpgp(&container, &[]);
            assert_eq!(container_results, control_results);
        }
    }

    #[test]
    fn openpgp_container_only_default_keyring_reports_unknown_key() {
        let pkg = fixture_pkg("signature-openpgp-1.0-1.noarch.rpm");
        let results = run_check(&pkg, KeyringChoice::System);
        if librpm_reads_openpgp_container() {
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].0, "unknown-key");
            assert!(results[0].1.contains(EXPECTED_OPENPGP_KEY_ID));
        } else {
            assert_eq!(results, Vec::<(String, String)>::new());
        }
    }

    #[test]
    fn openpgp_mixed_with_key_is_quiet() {
        let pkg = fixture_pkg("signature-openpgp-mixed-1.0-1.noarch.rpm");
        let results = run_check_openpgp(&pkg, &["signature-openpgp-testkey.gpg"]);
        assert_eq!(results, Vec::<(String, String)>::new());
    }

    #[test]
    fn openpgp_mixed_without_key_reports_one_unknown_key() {
        // The signature sits in both storage forms; the finding names
        // its key once, not once per form.
        let pkg = fixture_pkg("signature-openpgp-mixed-1.0-1.noarch.rpm");
        let results = run_check_openpgp(&pkg, &[]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "unknown-key");
        assert!(results[0].1.contains(EXPECTED_OPENPGP_KEY_ID));
    }

    #[test]
    fn openpgp_dual_without_key_reports_each_issuer() {
        let pkg = fixture_pkg("signature-openpgp-dual-1.0-1.noarch.rpm");
        let results = run_check_openpgp(&pkg, &[]);
        if librpm_reads_openpgp_container() {
            assert_eq!(results.len(), 2);
            assert_eq!(results[0].0, "unknown-key");
            assert!(results[0].1.contains(EXPECTED_OPENPGP_KEY_ID));
            assert_eq!(results[1].0, "unknown-key");
            assert!(results[1].1.contains(EXPECTED_OPENPGP_KEY2_ID));
        } else {
            assert_eq!(results, Vec::<(String, String)>::new());
        }
    }

    #[test]
    fn openpgp_dual_with_both_keys_is_quiet() {
        let pkg = fixture_pkg("signature-openpgp-dual-1.0-1.noarch.rpm");
        let results = run_check_openpgp(
            &pkg,
            &[
                "signature-openpgp-testkey.gpg",
                "signature-openpgp-testkey2.gpg",
            ],
        );
        assert_eq!(results, Vec::<(String, String)>::new());
    }
}
