//! `SourceCheck` — validate the files in a source package.
//!
//! Ported from `rpmlint/checks/SourceCheck.py`. Four findings:
//! `inconsistent-file-extension`, `strange-permission` and
//! `source-not-compressed` (warnings), `multiple-specfiles` (error).

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::is_match;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct SourceCheck {
    compress_ext: String,
    valid_src_perms: Vec<u128>,
    ext_magic: Vec<(String, String, Regex)>,
    spec_file: Option<String>,
}

impl SourceCheck {
    /// `error_details` for `--explain`, mirroring `source_details_dict`
    /// (`SourceCheck.py:28-33`) installed in `__init__`.
    pub fn register_error_details(config: &Config, out: &mut Filter) {
        let compress_ext = config
            .configuration
            .get("CompressExtension")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("SourceCheck: CompressExtension must be a string"));
        out.set_error_detail(
            "source-not-compressed",
            Self::not_compressed_detail(compress_ext),
        );
    }

    fn not_compressed_detail(compress_ext: &str) -> String {
        format!(
            "A source archive or file in your package is not compressed using the {compress_ext}\ncompression method (doesn't have the {compress_ext} extension)."
        )
    }

    pub fn new(config: &Config) -> Self {
        // The reference reads `config.configuration['CompressExtension']`
        // and raises `KeyError` when it is absent; defaulting to `""` would
        // render a mangled description, so this panics just as loudly.
        let compress_ext = config
            .configuration
            .get("CompressExtension")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("SourceCheck: CompressExtension must be a string"))
            .to_string();
        // The reference runs `[int(value, 8) for value in
        // config.configuration['ValidSrcPerms']]` and dies on a missing key
        // or a bad entry. Substituting an empty list instead would emit
        // `strange-permission` for every file, so this panics just as loudly.
        let valid_src_perms: Vec<u128> = match config.configuration.get("ValidSrcPerms") {
            Some(toml::Value::Array(entries)) => entries
                .iter()
                .map(|v| match v.as_str().and_then(parse_octal) {
                    Some(perm) => perm,
                    None => panic!("SourceCheck: ValidSrcPerms entry {v} is not valid octal"),
                })
                .collect(),
            _ => panic!("SourceCheck: ValidSrcPerms must be an array of octal strings"),
        };
        // `re.match(pattern, magic, re.IGNORECASE)`: anchored at the start.
        let ext_magic = [
            ("xz", "XZ compressed"),
            ("gz", "gzip compressed"),
            ("tgz", "gzip compressed"),
            ("bz2", "bzip2 compressed"),
            ("zst", "(ZSTD|Zstandard) compressed"),
            ("zstd", "(ZSTD|Zstandard) compressed"),
            ("zip", "Zip archive data"),
        ]
        .into_iter()
        .map(|(ext, pattern)| {
            (
                ext.to_string(),
                pattern.to_string(),
                Regex::new(&format!("(?i)^{pattern}")).expect("static regex"),
            )
        })
        .collect();
        Self {
            compress_ext,
            valid_src_perms,
            ext_magic,
            spec_file: None,
        }
    }

    /// The per-file findings: `inconsistent-file-extension`,
    /// `strange-permission` and `source-not-compressed`, in reference order.
    fn file_findings(
        &self,
        fname: &str,
        mode: u32,
        magic: &str,
    ) -> Vec<(Level, &'static str, Vec<String>)> {
        let mut out = Vec::new();
        if !magic.is_empty() {
            let ext = fname.rsplit('.').next().unwrap_or(fname);
            match self.ext_magic.iter().find(|(e, _, _)| e == ext) {
                Some((_, pattern, re)) if !is_match(re, magic) => {
                    out.push((
                        Level::Warning,
                        "inconsistent-file-extension",
                        vec![format!(
                            "file {} magic {} does not match {}",
                            py_repr(fname),
                            py_repr(magic),
                            py_repr(pattern)
                        )],
                    ));
                }
                _ => {}
            }
        }
        let perm = mode & 0o7777;
        if !self.valid_src_perms.contains(&(perm as u128)) {
            out.push((
                Level::Warning,
                "strange-permission",
                vec![fname.to_string(), format!("{perm:o}")],
            ));
        }
        // The reference's `source_regex = re.compile(r'\.(tar|tgz)$')`: without
        // `re.MULTILINE`, `$` also matches before a trailing newline, so
        // `foo.tar\n` fires there. `fancy_regex` has no such `$`, hence the
        // one-newline strip, which is exactly equivalent for this pattern.
        let stem = fname.strip_suffix('\n').unwrap_or(fname);
        if (stem.ends_with(".tar") || stem.ends_with(".tgz"))
            && !self.compress_ext.is_empty()
            && !fname.ends_with(self.compress_ext.as_str())
        {
            out.push((
                Level::Warning,
                "source-not-compressed",
                vec![self.compress_ext.clone(), fname.to_string()],
            ));
        }
        out
    }

    /// `multiple-specfiles`: the second `.spec` seen reports the first.
    /// State resets between packages via [`Check::reset`].
    fn check_specfile(&mut self, fname: &str) -> Option<(String, String)> {
        if !fname.ends_with(".spec") {
            return None;
        }
        match &self.spec_file {
            Some(first) => Some((first.clone(), fname.to_string())),
            None => {
                self.spec_file = Some(fname.to_string());
                None
            }
        }
    }
}

/// The reference's `int(value, 8)`, faithfully: surrounding whitespace is
/// stripped, exactly one ASCII sign is allowed (a second sign is a
/// `ValueError`, not a double negation), the `0o`/`0O` prefix is optional,
/// PEP 515 underscores are allowed between digits and directly after the
/// prefix, and any Unicode decimal digit (`Py_UNICODE_TODECIMAL`) below the
/// base is accepted — so `int('٦٤٤', 8)` is 420.
///
/// The value is unbounded like the reference's: magnitudes beyond `u128`
/// saturate at `u128::MAX` (ledgered as `kind = "detail"` — the saturated
/// value can never equal a real file mode, which is the only comparison
/// this value feeds). Digits past the saturation point are still validated:
/// trailing garbage makes this return `None`, and `SourceCheck::new` panics
/// on `None` — the reference's `int(value, 8)` raises `ValueError` on the
/// same input, so both die on the bad entry instead of silently accepting it.
fn parse_octal(s: &str) -> Option<u128> {
    let s = s.trim();
    let (s, neg) = match s.as_bytes().first() {
        Some(b'-') => (&s[1..], true),
        Some(b'+') => (&s[1..], false),
        _ => (s, false),
    };
    if s.as_bytes()
        .first()
        .is_some_and(|b| *b == b'+' || *b == b'-')
    {
        return None;
    }
    let (s, after_prefix) = match s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        Some(rest) => (rest, true),
        None => (s, false),
    };
    let mut value: u128 = 0;
    // An underscore may follow the prefix or a digit, never anything else.
    let mut underscore_ok = after_prefix;
    // u64: the counter now runs past saturation over the whole string,
    // so a u32 could overflow (and panic a debug build) on an absurdly long entry.
    let mut digits = 0u64;
    // Once the magnitude overflows u128 the value saturates, but every
    // remaining digit is still validated: the reference raises ValueError
    // for trailing garbage regardless of the leading magnitude.
    let mut saturated = false;
    for c in s.chars() {
        if c == '_' {
            if !underscore_ok {
                return None;
            }
            underscore_ok = false;
            continue;
        }
        let d = unicode_octal_digit(c)?;
        underscore_ok = true;
        digits += 1;
        if !saturated {
            value = match value.checked_mul(8).and_then(|v| v.checked_add(d as u128)) {
                Some(v) => v,
                None => {
                    saturated = true;
                    u128::MAX
                }
            };
        }
    }
    if digits == 0 || !underscore_ok {
        return None;
    }
    if saturated {
        // The magnitude alone already exceeds u128, so the sign is moot:
        // saturation wins exactly as the old immediate return did.
        return Some(u128::MAX);
    }
    Some(if neg { value.wrapping_neg() } else { value })
}

/// A Unicode decimal digit's value when below 8, like CPython's
/// `Py_UNICODE_TODECIMAL` restricted to the base.
fn unicode_octal_digit(c: char) -> Option<u32> {
    let v = unicode_decimal_value(c)?;
    (v < 8).then_some(v)
}

/// The decimal value of any Unicode decimal-digit character, mirroring
/// CPython's `Py_UNICODE_TODECIMAL`. Each arm is one digit block laid out
/// 0-9 in order; characters outside these blocks are not decimal digits.
fn unicode_decimal_value(c: char) -> Option<u32> {
    let c = c as u32;
    let base = match c {
        0x0030..=0x0039 => 0x0030,    // ASCII
        0x0660..=0x0669 => 0x0660,    // Arabic-Indic
        0x06F0..=0x06F9 => 0x06F0,    // Extended Arabic-Indic
        0x07C0..=0x07C9 => 0x07C0,    // NKo
        0x0966..=0x096F => 0x0966,    // Devanagari
        0x09E6..=0x09EF => 0x09E6,    // Bengali
        0x0A66..=0x0A6F => 0x0A66,    // Gurmukhi
        0x0AE6..=0x0AEF => 0x0AE6,    // Gujarati
        0x0B66..=0x0B6F => 0x0B66,    // Oriya
        0x0BE6..=0x0BEF => 0x0BE6,    // Tamil
        0x0C66..=0x0C6F => 0x0C66,    // Telugu
        0x0CE6..=0x0CEF => 0x0CE6,    // Kannada
        0x0D66..=0x0D6F => 0x0D66,    // Malayalam
        0x0DE6..=0x0DEF => 0x0DE6,    // Sinhala
        0x0E50..=0x0E59 => 0x0E50,    // Thai
        0x0ED0..=0x0ED9 => 0x0ED0,    // Lao
        0x0F20..=0x0F29 => 0x0F20,    // Tibetan
        0x1040..=0x1049 => 0x1040,    // Myanmar
        0x1090..=0x1099 => 0x1090,    // Myanmar Shan
        0x17E0..=0x17E9 => 0x17E0,    // Khmer
        0x1810..=0x1819 => 0x1810,    // Mongolian
        0x1946..=0x194F => 0x1946,    // Limbu
        0x19D0..=0x19D9 => 0x19D0,    // New Tai Lue
        0x1A80..=0x1A89 => 0x1A80,    // Tai Tham Hora
        0x1A90..=0x1A99 => 0x1A90,    // Tai Tham Tham
        0x1B50..=0x1B59 => 0x1B50,    // Balinese
        0x1BB0..=0x1BB9 => 0x1BB0,    // Sundanese
        0x1C50..=0x1C59 => 0x1C50,    // Ol Chiki
        0xA620..=0xA629 => 0xA620,    // Vai
        0xA8D0..=0xA8D9 => 0xA8D0,    // Saurashtra
        0xA900..=0xA909 => 0xA900,    // Kayah Li
        0xA9D0..=0xA9D9 => 0xA9D0,    // Javanese
        0xA9F0..=0xA9F9 => 0xA9F0,    // Myanmar Tai Laing
        0xAA50..=0xAA59 => 0xAA50,    // Cham
        0xABF0..=0xABF9 => 0xABF0,    // Meetei Mayek
        0xFF10..=0xFF19 => 0xFF10,    // Fullwidth
        0x104A0..=0x104A9 => 0x104A0, // Osmanya
        0x11066..=0x1106F => 0x11066, // Brahmi
        0x110F0..=0x110F9 => 0x110F0, // Sora Sompeng
        0x11136..=0x1113F => 0x11136, // Chakma
        0x111D0..=0x111D9 => 0x111D0, // Mahajani
        0x112F0..=0x112F9 => 0x112F0, // Khudawadi
        0x11450..=0x11459 => 0x11450, // Newa
        0x114D0..=0x114D9 => 0x114D0, // Tirhuta
        0x11650..=0x11659 => 0x11650, // Modi
        0x116C0..=0x116C9 => 0x116C0, // Takri
        0x11730..=0x11739 => 0x11730, // Ahom
        0x118E0..=0x118E9 => 0x118E0, // Warang Citi
        0x11C50..=0x11C59 => 0x11C50, // Sharada
        0x11D50..=0x11D59 => 0x11D50, // Masaram Gondi
        0x11DA0..=0x11DA9 => 0x11DA0, // Gunjala Gondi
        0x16A60..=0x16A69 => 0x16A60, // Mro
        0x16B50..=0x16B59 => 0x16B50, // Pahawh Hmong
        0x1D7CE..=0x1D7D7 => 0x1D7CE, // Mathematical Bold
        0x1D7D8..=0x1D7E1 => 0x1D7D8, // Mathematical Double-Struck
        0x1D7E2..=0x1D7EB => 0x1D7E2, // Mathematical Sans-Serif
        0x1D7EC..=0x1D7F5 => 0x1D7EC, // Mathematical Sans-Serif Bold
        0x1D7F6..=0x1D7FF => 0x1D7F6, // Mathematical Monospace
        0x1E950..=0x1E959 => 0x1E950, // Adlam
        _ => return None,
    };
    Some(c - base)
}

/// Python's `repr()` for `str`, for the `inconsistent-file-extension` detail
/// (the reference interpolates `{fname!r}`). Single quotes unless the string
/// contains `'` and no `"`, escaping the quote in use and the backslash,
/// with the C0 controls CPython names (`\\n`, `\\r`, `\\t`, else `\\xNN`).
fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

impl Check for SourceCheck {
    fn name(&self) -> &'static str {
        "SourceCheck"
    }

    fn check_source(&mut self, pkg: &Pkg, config: &Config, out: &mut Filter) {
        Self::register_error_details(config, out);
        for f in &pkg.files {
            for (level, check, details) in self.file_findings(&f.name, f.mode, &f.magic) {
                let refs: Vec<&str> = details.iter().map(String::as_str).collect();
                add_info(out, level, pkg, check, &refs);
            }
            if let Some((first, second)) = self.check_specfile(&f.name) {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "multiple-specfiles",
                    &[&first, &second],
                );
            }
        }
    }

    fn reset(&mut self) {
        self.spec_file = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checker() -> SourceCheck {
        let table: toml::Table = toml::from_str(
            r#"
CompressExtension = "gz"
ValidSrcPerms = ["0o644", "0o755"]
"#,
        )
        .expect("parse test config");
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        SourceCheck::new(&config)
    }

    #[test]
    fn matching_extension_and_magic_is_quiet() {
        let c = checker();
        let found = c.file_findings("foo.tar.gz", 0o100644, "gzip compressed data, from Unix");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn mismatched_magic_is_reported() {
        let c = checker();
        let found = c.file_findings("foo.tar.xz", 0o100644, "gzip compressed data");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Warning);
        assert_eq!(found[0].1, "inconsistent-file-extension");
        assert_eq!(
            found[0].2,
            vec!["file 'foo.tar.xz' magic 'gzip compressed data' does not match 'XZ compressed'"]
        );
    }

    #[test]
    fn magic_match_is_case_insensitive() {
        let c = checker();
        let found = c.file_findings("foo.zip", 0o100644, "zip archive data, at least v2.0");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn unknown_extension_is_not_checked() {
        let c = checker();
        let found = c.file_findings("README", 0o100644, "ASCII text");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn empty_magic_is_not_checked() {
        let c = checker();
        let found = c.file_findings("foo.tar.gz", 0o100644, "");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn strange_permission_is_reported_in_octal() {
        let c = checker();
        let found = c.file_findings("foo.tar.gz", 0o100600, "gzip compressed data");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Warning);
        assert_eq!(found[0].1, "strange-permission");
        assert_eq!(found[0].2, vec!["foo.tar.gz", "600"]);
    }

    #[test]
    fn uncompressed_tarball_is_reported() {
        let c = checker();
        let found = c.file_findings("foo.tar", 0o100644, "POSIX tar archive");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Warning);
        assert_eq!(found[0].1, "source-not-compressed");
        assert_eq!(found[0].2, vec!["gz", "foo.tar"]);
    }

    #[test]
    fn tgz_counts_as_compressed_for_gz() {
        // `endswith("gz")`: the reference accepts `.tgz` for `CompressExtension = "gz"`.
        let c = checker();
        let found = c.file_findings("foo.tgz", 0o100644, "gzip compressed data");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn second_specfile_reports_the_first() {
        let mut c = checker();
        assert!(c.check_specfile("foo.spec").is_none());
        assert!(c.check_specfile("bar.spec").is_some());
        let (first, second) = c.check_specfile("bar.spec").unwrap();
        assert_eq!((first.as_str(), second.as_str()), ("foo.spec", "bar.spec"));
        c.reset();
        assert!(c.check_specfile("bar.spec").is_none());
    }

    #[test]
    fn parse_octal_matches_python_int_base_8() {
        assert_eq!(parse_octal("0o644"), Some(0o644));
        assert_eq!(parse_octal("644"), Some(0o644));
        assert_eq!(parse_octal("0o755"), Some(0o755));
        assert_eq!(parse_octal("0O755"), Some(0o755));
        // `int(v, 8)` strips whitespace and accepts a single sign.
        assert_eq!(parse_octal("  644\t"), Some(0o644));
        assert_eq!(parse_octal("+0o644"), Some(0o644));
        assert_eq!(parse_octal("-644"), Some(0o644u128.wrapping_neg()));
        // A second sign is a ValueError, not a double negation.
        assert_eq!(parse_octal("++644"), None);
        assert_eq!(parse_octal("-+644"), None);
        assert_eq!(parse_octal("+-644"), None);
        assert_eq!(parse_octal("+"), None);
        assert_eq!(parse_octal("-"), None);
        // PEP 515 underscores: between digits and after the prefix only.
        assert_eq!(parse_octal("0o6_44"), Some(0o644));
        assert_eq!(parse_octal("6_4_4"), Some(0o644));
        assert_eq!(parse_octal("0o_644"), Some(0o644));
        assert_eq!(parse_octal("_644"), None);
        assert_eq!(parse_octal("644_"), None);
        assert_eq!(parse_octal("6__44"), None);
        assert_eq!(parse_octal("0o_"), None);
        assert_eq!(parse_octal("+_644"), None);
        // Non-ASCII decimal digits below the base are accepted.
        assert_eq!(parse_octal("\u{0666}\u{0664}\u{0664}"), Some(0o644));
        assert_eq!(parse_octal("\u{FF16}\u{FF14}\u{FF14}"), Some(0o644));
        // ...but 8 and 9 are not octal digits in any script.
        assert_eq!(parse_octal("\u{0668}\u{0664}\u{0664}"), None);
        assert_eq!(parse_octal("0o8"), None);
        assert_eq!(parse_octal("8"), None);
        // Unbounded magnitude, like the reference's arbitrary precision.
        assert_eq!(parse_octal("0o777777777777"), Some(0o777777777777));
        assert_eq!(
            parse_octal(&format!("0o{}", "7".repeat(22))),
            Some(73786976294838206463)
        );
        assert_eq!(parse_octal("bogus"), None);
        assert_eq!(parse_octal(""), None);
        assert_eq!(parse_octal("0o"), None);
    }

    #[test]
    fn parse_octal_saturates_beyond_u128() {
        // The ledger documents saturation at u128::MAX where the reference
        // keeps arbitrary precision; Python accepts the input, so pin the
        // port's documented behaviour.
        assert_eq!(
            parse_octal(&format!("0o{}", "7".repeat(50))),
            Some(u128::MAX)
        );
        // The exact boundary still parses precisely, not via saturation.
        assert_eq!(
            parse_octal("0o3777777777777777777777777777777777777777777"),
            Some(u128::MAX)
        );
    }

    #[test]
    fn parse_octal_overflow_still_validates_trailing_digits() {
        // The overflow arm used to return Some(u128::MAX) immediately,
        // abandoning validation of the remaining digits; the reference
        // raises ValueError for every one of these (plusky's #123 review).
        let huge = format!("0o{}", "7".repeat(43));
        for tail in ["9", "8", "_", "0x1"] {
            assert_eq!(parse_octal(&format!("{huge}{tail}")), None, "tail {tail:?}");
        }
        // Valid digits past the saturation point still saturate, ...
        assert_eq!(parse_octal(&format!("{huge}7")), Some(u128::MAX));
        assert_eq!(parse_octal(&format!("{huge}_7")), Some(u128::MAX));
        // ... and saturation wins over the sign, as the old early return did.
        assert_eq!(
            parse_octal(&format!("-0o{}", "7".repeat(50))),
            Some(u128::MAX)
        );
    }

    #[test]
    fn py_repr_matches_python() {
        assert_eq!(py_repr("foo.tar.xz"), "'foo.tar.xz'");
        // Apostrophe without a double quote: double quotes, like `repr`.
        assert_eq!(py_repr("it's.tar.xz"), "\"it's.tar.xz\"");
        // Double quote alone: single quotes, inner quote untouched.
        assert_eq!(py_repr("say \"hi\".tar.xz"), "'say \"hi\".tar.xz'");
        // Both: single quotes with the apostrophe escaped.
        assert_eq!(
            py_repr("it's \"quoted\".tar.xz"),
            "'it\\'s \"quoted\".tar.xz'"
        );
        assert_eq!(py_repr("back\\slash"), "'back\\\\slash'");
        assert_eq!(py_repr("a\nb\tc\rd"), "'a\\nb\\tc\\rd'");
        assert_eq!(py_repr("a\x00b"), "'a\\x00b'");
    }

    #[test]
    fn detail_switches_to_double_quotes_for_apostrophe() {
        // `repr("it's.tar.xz")` is `"it's.tar.xz"`: the reference uses `!r`.
        let c = checker();
        let found = c.file_findings("it's.tar.xz", 0o100644, "gzip compressed data");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, Level::Warning);
        assert_eq!(
            found[0].2,
            vec![
                "file \"it's.tar.xz\" magic 'gzip compressed data' does not match 'XZ compressed'"
            ]
        );
    }

    #[test]
    fn detail_escapes_quote_and_backslash_in_magic() {
        // libmagic output embeds filenames; quotes and backslashes must not
        // pass through raw the way hardcoded single quotes would allow.
        let c = checker();
        let found = c.file_findings("foo.tar.xz", 0o100644, "it's a \\weird\nmagic");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].2,
            vec![
                "file 'foo.tar.xz' magic \"it's a \\\\weird\\nmagic\" does not match 'XZ compressed'"
            ]
        );
    }

    #[test]
    #[should_panic(expected = "ValidSrcPerms must be an array")]
    fn missing_valid_src_perms_panics() {
        // The reference raises KeyError; an empty list would flag every file.
        let table: toml::Table =
            toml::from_str("CompressExtension = \"gz\"").expect("parse test config");
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = SourceCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "CompressExtension must be a string")]
    fn missing_compress_extension_panics() {
        // The reference raises KeyError on `config.configuration['CompressExtension']`;
        // defaulting to "" would render a mangled description.
        let table: toml::Table =
            toml::from_str("ValidSrcPerms = [\"0o644\"]").expect("parse test config");
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = SourceCheck::new(&config);
    }

    #[test]
    #[should_panic(expected = "not valid octal")]
    fn unparsable_valid_src_perms_entry_panics() {
        // The reference raises ValueError; dropping the entry would flag
        // every file with `strange-permission`.
        let table: toml::Table =
            toml::from_str("CompressExtension = \"gz\"\nValidSrcPerms = [\"bogus\"]")
                .expect("parse test config");
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let _ = SourceCheck::new(&config);
    }

    #[test]
    fn trailing_newline_still_matches_source_regex() {
        // The reference's `source_regex.search` uses `$`, which matches
        // before a trailing newline; `ends_with(".tar")` would stay silent.
        let c = checker();
        let found = c.file_findings("foo.tar\n", 0o100644, "POSIX tar archive");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, "source-not-compressed");
    }

    #[test]
    fn check_source_entry_point_emits_per_file_findings() {
        // Kills M8-prime (zero files iterated) and M15 (per-file findings
        // dropped): the whole `check_source` body must run for findings
        // to reach the `Filter`.
        use std::path::Path;

        use crate::color::Color;
        use crate::pkg::pkgfile::PkgFile;

        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        let mut pkg = Pkg::open(&rpm, &std::env::temp_dir(), true).expect("open fixture pkg");
        pkg.files = vec![PkgFile {
            name: "bogus.gz".to_string(),
            mode: 0o100644,
            magic: "ASCII text".to_string(),
            ..Default::default()
        }];
        let table: toml::Table =
            toml::from_str("CompressExtension = \"gz\"\nValidSrcPerms = [\"0o644\", \"0o755\"]")
                .expect("parse test config");
        let config = Config {
            configuration: table,
            ..Default::default()
        };
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = SourceCheck::new(&config);
        check.check_source(&pkg, &config, &mut out);
        let names: Vec<&str> = out.results().iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["inconsistent-file-extension"]);
    }
}
