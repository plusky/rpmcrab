//! `ErlangCheck` — BEAM files must carry debug info and be built from a
//! recognizable source tree.
//!
//! Ported from `rpmlint/checks/ErlangCheck.py`. Findings:
//! `beam-compile-info-missed`, `beam-compiled-without-debuginfo`,
//! `beam-was-not-recompiled`, `pybeam-failed`.
//!
//! The reference uses `pybeam`; this is a minimal native BEAM reader: it
//! parses the `FOR1` container, locates the `CInf` chunk, and decodes just
//! enough of the Erlang external term format to read the `options` and
//! `source` entries and to classify the `Dbgi` chunk's payload.

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

/// A decoded Erlang external term, limited to what compile info needs.
#[derive(Debug, Clone, PartialEq)]
enum Term {
    Atom(String),
    Binary(Vec<u8>),
    List(Vec<Term>),
    Tuple(Vec<Term>),
    Map(Vec<(Term, Term)>),
    Other,
}

/// Maximum nesting depth [`TermParser`] accepts. Compile info is a
/// flat list of `{key, value}` pairs, so real BEAM files nest only a
/// few levels; the cap keeps a crafted file from overflowing the
/// stack through recursive terms.
const MAX_TERM_DEPTH: usize = 128;

struct TermParser<'a> {
    data: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> TermParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            depth: 0,
        }
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let b = self.data.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.bytes(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.bytes(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Decode an atom carried by a Latin-1 tag (`ATOM_EXT`,
    /// `SMALL_ATOM_EXT`): each byte is the codepoint of the same value,
    /// so the decode cannot fail.
    fn atom_latin1(&mut self, len: usize) -> Option<Term> {
        let b = self.bytes(len)?;
        Some(Term::Atom(b.iter().map(|&byte| char::from(byte)).collect()))
    }

    /// Decode an atom carried by a UTF-8 tag (`ATOM_UTF8_EXT`,
    /// `SMALL_ATOM_UTF8_EXT`): bytes that are not valid UTF-8 fail the
    /// parse, matching pybeam's strict decode.
    fn atom_utf8(&mut self, len: usize) -> Option<Term> {
        let b = self.bytes(len)?;
        let s = String::from_utf8(b.to_vec()).ok()?;
        Some(Term::Atom(s))
    }

    /// Decode one external term. A term nested deeper than
    /// [`MAX_TERM_DEPTH`] fails to parse (returns `None`).
    fn parse_term(&mut self) -> Option<Term> {
        if self.depth >= MAX_TERM_DEPTH {
            return None;
        }
        self.depth += 1;
        let term = self.parse_term_inner();
        self.depth -= 1;
        term
    }

    fn parse_term_inner(&mut self) -> Option<Term> {
        match self.byte()? {
            // SMALL_INTEGER_EXT
            97 => {
                self.byte()?;
                Some(Term::Other)
            }
            // INTEGER_EXT
            98 => {
                self.bytes(4)?;
                Some(Term::Other)
            }
            // ATOM_EXT (latin-1)
            100 => {
                let len = self.u16()? as usize;
                self.atom_latin1(len)
            }
            // SMALL_TUPLE_EXT
            104 => {
                let arity = self.byte()? as usize;
                let mut elems = Vec::with_capacity(arity);
                for _ in 0..arity {
                    elems.push(self.parse_term()?);
                }
                Some(Term::Tuple(elems))
            }
            // LARGE_TUPLE_EXT
            105 => {
                let arity = self.u32()? as usize;
                let mut elems = Vec::with_capacity(arity.min(1024));
                for _ in 0..arity {
                    elems.push(self.parse_term()?);
                }
                Some(Term::Tuple(elems))
            }
            // NIL_EXT
            106 => Some(Term::List(Vec::new())),
            // STRING_EXT
            107 => {
                let len = self.u16()? as usize;
                let b = self.bytes(len)?;
                Some(Term::Binary(b.to_vec()))
            }
            // LIST_EXT
            108 => {
                let len = self.u32()? as usize;
                let mut elems = Vec::with_capacity(len.min(1024));
                for _ in 0..len {
                    elems.push(self.parse_term()?);
                }
                // Tail; NIL is the common case. The tail is discarded,
                // so an improper list decodes as its proper prefix and a
                // 2-element improper list counts as a pair below.
                // Impropriety is deliberately not modelled: OTP emits
                // proper lists, so the difference is reachable only by
                // crafted files.
                let _tail = self.parse_term()?;
                Some(Term::List(elems))
            }
            // BINARY_EXT
            109 => {
                let len = self.u32()? as usize;
                let b = self.bytes(len)?;
                Some(Term::Binary(b.to_vec()))
            }
            // SMALL_ATOM_EXT (latin-1)
            115 => {
                let len = self.byte()? as usize;
                self.atom_latin1(len)
            }
            // ATOM_UTF8_EXT
            118 => {
                let len = self.u16()? as usize;
                self.atom_utf8(len)
            }
            // SMALL_ATOM_UTF8_EXT
            119 => {
                let len = self.byte()? as usize;
                self.atom_utf8(len)
            }
            // MAP_EXT
            116 => {
                let arity = self.u32()? as usize;
                let mut pairs = Vec::with_capacity(arity.min(1024));
                for _ in 0..arity {
                    let k = self.parse_term()?;
                    let v = self.parse_term()?;
                    pairs.push((k, v));
                }
                Some(Term::Map(pairs))
            }
            // FLOAT_EXT (old), NEW_FLOAT_EXT
            70 => {
                self.bytes(31)?;
                Some(Term::Other)
            }
            99 => {
                self.bytes(8)?;
                Some(Term::Other)
            }
            _ => None,
        }
    }
}

/// Whether the Python value pybeam decodes this term to could be a
/// `dict()` key: atoms, binaries and the scalar `Other` terms are
/// hashable, lists and maps are not, and a tuple is hashable only if
/// every element is.
fn is_hashable(term: &Term) -> bool {
    match term {
        Term::List(_) | Term::Map(_) => false,
        Term::Tuple(elems) => elems.iter().all(is_hashable),
        _ => true,
    }
}

/// Whether every map in the term could be built by pybeam. pybeam
/// decodes the whole chunk into Python objects, building a `dict` for
/// every map wherever it nests — as a pair key or value, inside
/// another map's value, or under a list or tuple — and building a
/// dict raises `TypeError` on an unhashable key, so one bad key
/// anywhere fails the whole parse, even in a value that the pair
/// handling would discard unread.
fn map_keys_hashable(term: &Term) -> bool {
    match term {
        Term::Map(pairs) => pairs
            .iter()
            .all(|(k, v)| is_hashable(k) && map_keys_hashable(k) && map_keys_hashable(v)),
        Term::List(elems) | Term::Tuple(elems) => elems.iter().all(map_keys_hashable),
        _ => true,
    }
}

/// The compile info from a BEAM file: `(options, source)`.
struct CompileInfo {
    options: Option<Vec<String>>,
    source: Option<String>,
}

/// Read the `CInf` chunk of a BEAM file and decode its compile info.
fn read_compile_info(path: &str) -> Result<Option<CompileInfo>, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    // FOR1 header: "FOR1" + u32 size + "BEAM".
    if data.len() < 12 || &data[0..4] != b"FOR1" || &data[8..12] != b"BEAM" {
        return Err("not a BEAM file".to_string());
    }
    let mut pos = 12;
    let mut cinf: Option<&[u8]> = None;
    while pos + 8 <= data.len() {
        let name = &data[pos..pos + 4];
        let size = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
            as usize;
        pos += 8;
        let end = pos.saturating_add(size).min(data.len());
        if name == b"CInf" {
            cinf = Some(&data[pos..end]);
            break;
        }
        // Chunks are 4-byte aligned.
        pos = end + (4 - end % 4) % 4;
    }
    // A missing CInf chunk is not a parse error: pybeam returns None for
    // `compileinfo`, and the reference emits `beam-compile-info-missed`.
    let Some(cinf) = cinf else {
        return Ok(None);
    };
    if cinf.is_empty() || cinf[0] != 131 {
        return Err("bad external term version".to_string());
    }
    let mut parser = TermParser::new(&cinf[1..]);
    let term = parser
        .parse_term()
        .ok_or_else(|| "term parse failed".to_string())?;
    // pybeam builds every map in the chunk during decode (see
    // `map_keys_hashable`), before the pairs below are read.
    if !map_keys_hashable(&term) {
        return Err("compile info key is not hashable".to_string());
    }

    // Compile info is a list of {Key, Value} tuples (older) or a map (newer).
    let pairs: Vec<(Term, Term)> = match term {
        Term::List(items) => {
            let mut pairs = Vec::with_capacity(items.len());
            for item in items {
                let (k, v) = match item {
                    Term::Tuple(mut elems) | Term::List(mut elems) if elems.len() == 2 => {
                        let v = elems.pop().unwrap();
                        let k = elems.pop().unwrap();
                        (k, v)
                    }
                    // pybeam builds `dict(cinf)` from the list, and
                    // `dict()` accepts any 2-element sequence as a pair:
                    // a 2-byte binary is a sequence of two integers and
                    // a 2-character atom a sequence of two characters;
                    // neither can match an atom key, so both are kept
                    // as a pair of opaque terms.
                    Term::Binary(b) if b.len() == 2 => (Term::Other, Term::Other),
                    Term::Atom(s) if s.chars().count() == 2 => (Term::Other, Term::Other),
                    // A map is a sequence of its keys for `dict()`: a
                    // 2-entry map element is the pair of its two keys,
                    // and its values play no part.
                    Term::Map(mut entries) if entries.len() == 2 => {
                        let v = entries.pop().unwrap().0;
                        let k = entries.pop().unwrap().0;
                        (k, v)
                    }
                    // An element that is not a 2-element sequence
                    // raises in `dict(cinf)` there; the reference
                    // reports `pybeam-failed` for the file.
                    _ => return Err("compile info entry is not a pair".to_string()),
                };
                // `dict()` raises TypeError on an unhashable key (a
                // list, a map, or a tuple holding one), so such a key
                // is a parse failure here too.
                if !is_hashable(&k) {
                    return Err("compile info key is not hashable".to_string());
                }
                pairs.push((k, v));
            }
            pairs
        }
        Term::Map(pairs) => {
            // The top-level map form is held to the same key rule:
            // pybeam builds a Python dict from the chunk, which raises
            // on an unhashable key before the reference reads anything.
            if pairs.iter().any(|(k, _)| !is_hashable(k)) {
                return Err("compile info key is not hashable".to_string());
            }
            pairs
        }
        // The chunk is present but holds no compile info structure:
        // pybeam raises when it builds a dict from such a term, so
        // this is a parse failure, not missed compile info.
        _ => return Err("compile info is not a list or map".to_string()),
    };

    let mut options = None;
    let mut source = None;
    for (k, v) in pairs {
        let key = match k {
            Term::Atom(s) => s,
            _ => continue,
        };
        match key.as_str() {
            "options" => {
                if let Term::List(items) = v {
                    let opts = items
                        .into_iter()
                        .filter_map(|t| match t {
                            Term::Atom(s) => Some(s),
                            _ => None,
                        })
                        .collect();
                    options = Some(opts);
                }
            }
            "source" => {
                // The source path is UTF-8 in any current BEAM file,
                // so bytes that are not valid UTF-8 are garbage:
                // decoding them with replacement characters would
                // corrupt the build-dir comparison and the reported
                // path, so the parse fails instead.
                let s = match v {
                    Term::Binary(b) => {
                        String::from_utf8(b).map_err(|_| "source is not valid UTF-8".to_string())?
                    }
                    Term::Atom(s) => s,
                    _ => continue,
                };
                source = Some(s);
            }
            _ => {}
        }
    }
    Ok(Some(CompileInfo { options, source }))
}

/// The payload of the first chunk named `name` in the BEAM file at
/// `path`, or `None` when the file is unreadable, too short to hold
/// the `FOR1` header, or has no such chunk.
fn chunk_payload(path: &str, name: &[u8; 4]) -> Option<Vec<u8>> {
    let data = std::fs::read(path).ok()?;
    if data.len() < 12 {
        return None;
    }
    let mut pos = 12;
    while pos + 8 <= data.len() {
        let cname = &data[pos..pos + 4];
        let size = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
            as usize;
        pos += 8;
        let end = pos.saturating_add(size).min(data.len());
        if cname == name {
            return Some(data[pos..end].to_vec());
        }
        pos = end + (4 - end % 4) % 4;
    }
    None
}

/// True when the BEAM file has a `Dbgi` (debug info) chunk.
fn has_dbgi_chunk(path: &str) -> bool {
    chunk_payload(path, b"Dbgi").is_some()
}

/// Parse one term off `parser` and report whether it is the atom
/// `none`; `None` when the term does not parse.
fn term_is_none_atom(parser: &mut TermParser) -> Option<bool> {
    match parser.parse_term()? {
        Term::Atom(a) => Some(a == "none"),
        _ => Some(false),
    }
}

/// True when the BEAM file's `Dbgi` chunk holds an actual debug-info
/// payload. The chunk is the external term `{debug_info_v1, Backend,
/// Data}`; a compile that generated no debug info still writes the
/// chunk, with `Data` as the placeholder atom `none` (the Elixir
/// backend's shape) or the tuple `{none, Options}` (the Erlang
/// backend's shape). Any other `Data` head — a list of abstract
/// forms, an `{elixir_v1, Map}` tuple, a map — is the payload
/// itself. Only the head of `Data` is classified, never the whole
/// payload; an unparsable chunk earns no credit.
fn has_real_dbgi_payload(path: &str) -> bool {
    let Some(payload) = chunk_payload(path, b"Dbgi") else {
        return false;
    };
    if payload.first() != Some(&131) {
        return false;
    }
    let body = &payload[1..];
    // A COMPRESSED_EXT tag wraps the whole term when compression
    // pays off; inflate it so the term head can be read.
    let inflated;
    let term: &[u8] = if body.first() == Some(&80) {
        use std::io::Read as _;
        let Some(rest) = body.get(5..) else {
            return false;
        };
        let mut out = Vec::new();
        if flate2::read::ZlibDecoder::new(rest)
            .read_to_end(&mut out)
            .is_err()
        {
            return false;
        }
        inflated = out;
        &inflated
    } else {
        body
    };
    let mut parser = TermParser::new(term);
    let arity = match parser.byte() {
        Some(104) => parser.byte().map(usize::from),
        Some(105) => parser.u32().map(|n| n as usize),
        _ => None,
    };
    if arity != Some(3) {
        return false;
    }
    match parser.parse_term() {
        Some(Term::Atom(a)) if a == "debug_info_v1" => {}
        _ => return false,
    }
    if !matches!(parser.parse_term(), Some(Term::Atom(_))) {
        return false;
    }
    let head = parser.pos;
    match parser.byte() {
        // An atom: the placeholder iff it is `none`.
        Some(100 | 115 | 118 | 119) => {
            parser.pos = head;
            matches!(term_is_none_atom(&mut parser), Some(false))
        }
        // A tuple: the placeholder iff its first element is `none`.
        Some(tag @ (104 | 105)) => {
            let arity = if tag == 104 {
                parser.byte().map(usize::from)
            } else {
                parser.u32().map(|n| n as usize)
            };
            match arity {
                Some(0) => true,
                Some(_) => matches!(term_is_none_atom(&mut parser), Some(false)),
                None => false,
            }
        }
        // Any other head is a payload term, not a placeholder.
        Some(_) => true,
        None => false,
    }
}

pub struct ErlangCheck {
    source_re: Regex,
}

impl ErlangCheck {
    pub fn new(config: &Config) -> Self {
        // The reference compiles %_builddir into the regex; without macro
        // expansion available here, match the OBS default build dir.
        let build_dir = config
            .configuration
            .get("ErlangBuildDir")
            .and_then(toml::Value::as_str)
            .unwrap_or("/home/abuild/rpmbuild/BUILD");
        // An empty value would make `\A` match every path and silently disable
        // the check; the reference cannot produce this (rpm always expands
        // %_builddir), so fail loudly on the misconfiguration.
        if build_dir.is_empty() {
            panic!("ErlangBuildDir must not be empty");
        }
        Self {
            // `re.match` anchors at the start of the string.
            source_re: Regex::new(&format!("\\A{}", fancy_regex::escape(build_dir)))
                .expect("static regex"),
        }
    }
}

impl Check for ErlangCheck {
    fn name(&self) -> &'static str {
        "ErlangCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }
        for file in &pkg.files {
            let fname = file.name.as_str();
            if !fname.ends_with(".beam") {
                continue;
            }
            let compile_info = match read_compile_info(&file.path) {
                Ok(info) => info,
                Err(_) => {
                    add_info(out, Level::Error, pkg, "pybeam-failed", &[fname]);
                    continue;
                }
            };
            let Some(info) = compile_info else {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "beam-compile-info-missed",
                    &[fname],
                );
                continue;
            };

            // Beams built with `deterministic` omit options/source; fall back
            // to the Dbgi chunk for the debug-info check.
            let has_debug_info = match &info.options {
                None => has_dbgi_chunk(&file.path),
                // The options alone do not settle it: a compiler that
                // generates debug info without an Erlang `debug_info`
                // option — Elixir's records its Core Erlang options
                // instead — omits the atom while the payload is
                // present, so a real `Dbgi` payload counts too.
                Some(options) => {
                    options.iter().any(|o| o == "debug_info") || has_real_dbgi_payload(&file.path)
                }
            };
            if !has_debug_info {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "beam-compiled-without-debuginfo",
                    &[fname],
                );
            }

            if let Some(source) = &info.source
                && !crate::checks::is_match(&self.source_re, source)
            {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "beam-was-not-recompiled",
                    &[fname, source],
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal BEAM file holding the given chunks.
    fn beam_with_chunks(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"FOR1");
        out.extend_from_slice(&[0, 0, 0, 0]); // patched below
        out.extend_from_slice(b"BEAM");
        for (name, payload) in chunks {
            out.extend_from_slice(*name);
            out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            out.extend_from_slice(payload);
            while out.len() % 4 != 0 {
                out.push(0);
            }
        }
        let size = (out.len() - 8) as u32;
        out[4..8].copy_from_slice(&size.to_be_bytes());
        out
    }

    /// Build a minimal BEAM file with a CInf chunk holding the given
    /// external-term payload.
    fn beam_with_cinf(payload: &[u8]) -> Vec<u8> {
        beam_with_chunks(&[(b"CInf", payload)])
    }

    /// Every atom tag the parser accepts: the Latin-1 pair
    /// (`ATOM_EXT`, `SMALL_ATOM_EXT`) and the UTF-8 pair
    /// (`ATOM_UTF8_EXT`, `SMALL_ATOM_UTF8_EXT`). Tests build their
    /// atoms through each tag in turn so no tag's decode can drift
    /// from its sibling's unnoticed.
    const ATOM_TAGS: [u8; 4] = [100, 115, 118, 119];
    /// The Latin-1 atom tags (`ATOM_EXT`, `SMALL_ATOM_EXT`).
    const LATIN1_ATOM_TAGS: [u8; 2] = [100, 115];
    /// The UTF-8 atom tags (`ATOM_UTF8_EXT`, `SMALL_ATOM_UTF8_EXT`).
    const UTF8_ATOM_TAGS: [u8; 2] = [118, 119];

    /// Append an atom encoded with `tag`: the long forms (100, 118)
    /// carry a u16 length, the small forms (115, 119) a u8 length.
    fn push_atom(t: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
        t.push(tag);
        match tag {
            100 | 118 => t.extend_from_slice(&(bytes.len() as u16).to_be_bytes()),
            115 | 119 => t.push(bytes.len() as u8),
            _ => panic!("not an atom tag: {tag}"),
        }
        t.extend_from_slice(bytes);
    }

    /// External term for `[{options, [debug_info]}, {source, <<"/home/abuild/rpmbuild/BUILD/foo">>}]`
    /// with every atom encoded via `atom_tag`.
    fn compile_info_term(atom_tag: u8) -> Vec<u8> {
        let mut t = vec![131];
        // LIST_EXT, len 2
        t.extend_from_slice(&[108, 0, 0, 0, 2]);
        // {options, [debug_info]}
        t.extend_from_slice(&[104, 2]); // SMALL_TUPLE_EXT arity 2
        push_atom(&mut t, atom_tag, b"options");
        t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT len 1
        push_atom(&mut t, atom_tag, b"debug_info");
        t.push(106); // NIL tail
        // {source, Binary}
        let source = b"/home/abuild/rpmbuild/BUILD/foo.erl";
        t.extend_from_slice(&[104, 2]);
        push_atom(&mut t, atom_tag, b"source");
        t.extend_from_slice(&[109]); // BINARY_EXT
        t.extend_from_slice(&(source.len() as u32).to_be_bytes());
        t.extend_from_slice(source);
        t.push(106); // NIL tail
        t
    }

    #[test]
    fn term_parser_reads_compile_info() {
        for tag in ATOM_TAGS {
            let term = compile_info_term(tag);
            assert_eq!(term[0], 131);
            let mut parser = TermParser::new(&term[1..]);
            let parsed = parser.parse_term().expect("parses");
            match parsed {
                Term::List(items) => assert_eq!(items.len(), 2),
                other => panic!("expected list, got {other:?}"),
            }
        }
    }

    #[test]
    fn beam_chunk_walking_finds_cinf() {
        for tag in ATOM_TAGS {
            let tmp = tempfile::tempdir().expect("tmpdir");
            let path = tmp.path().join("test.beam");
            std::fs::write(&path, beam_with_cinf(&compile_info_term(tag))).unwrap();
            let info = read_compile_info(path.to_str().unwrap())
                .expect("reads")
                .expect("has compile info");
            assert!(
                info.options
                    .expect("options")
                    .contains(&"debug_info".to_string())
            );
            assert_eq!(
                info.source.as_deref(),
                Some("/home/abuild/rpmbuild/BUILD/foo.erl")
            );
        }
    }

    #[test]
    fn garbage_is_not_a_beam_file() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("garbage.beam");
        std::fs::write(&path, b"not a beam file at all").unwrap();
        assert!(read_compile_info(path.to_str().unwrap()).is_err());
    }

    #[test]
    fn missing_cinf_means_compile_info_missed() {
        // B4: a missing CInf chunk is not a parse failure. pybeam returns
        // None for `compileinfo`, so the reference emits
        // `beam-compile-info-missed` (W), not `pybeam-failed` (E).
        let mut beam = beam_with_cinf(&compile_info_term(119));
        // Corrupt the chunk name.
        beam[12..16].copy_from_slice(b"XXXX");
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("nocinf.beam");
        std::fs::write(&path, &beam).unwrap();
        assert!(
            read_compile_info(path.to_str().unwrap())
                .expect("reads")
                .is_none()
        );
    }

    /// B5: `source_re` is anchored like the reference's `re.match`: a path
    /// merely *containing* the build dir must not match.
    #[test]
    fn source_re_is_anchored_to_build_dir() {
        let check = ErlangCheck::new(&Config::default());
        // The OBS default build dir.
        assert!(crate::checks::is_match(
            &check.source_re,
            "/home/abuild/rpmbuild/BUILD/foo-1.0/src/foo.erl"
        ));
        // Contains the build dir but does not start with it: must not match.
        assert!(!crate::checks::is_match(
            &check.source_re,
            "/home/user/home/abuild/rpmbuild/BUILD/foo-1.0/src/foo.erl"
        ));
        // A local ~/rpmbuild/BUILD path must not match the OBS default.
        assert!(!crate::checks::is_match(
            &check.source_re,
            "/home/user/rpmbuild/BUILD/foo-1.0/src/foo.erl"
        ));
    }

    /// B5: the expected build dir comes from the `ErlangBuildDir` config
    /// key, so a local build tree can be matched by setting it.
    #[test]
    fn source_re_follows_erlang_build_dir_config() {
        use toml::Value;
        let mut config = Config::default();
        config.configuration.insert(
            "ErlangBuildDir".to_string(),
            Value::String("/home/user/rpmbuild/BUILD".to_string()),
        );
        let check = ErlangCheck::new(&config);
        assert!(crate::checks::is_match(
            &check.source_re,
            "/home/user/rpmbuild/BUILD/foo-1.0/src/foo.erl"
        ));
        assert!(!crate::checks::is_match(
            &check.source_re,
            "/home/abuild/rpmbuild/BUILD/foo-1.0/src/foo.erl"
        ));
    }

    /// A CInf chunk whose term parses but is neither the {key, value}
    /// list nor the map form is malformed compile info: pybeam raises
    /// when it builds a dict from such a term, so this is a parse
    /// failure (`pybeam-failed`), not missed compile info.
    #[test]
    fn misshapen_compile_info_term_fails() {
        let bare_tuple = {
            let mut t = vec![131, 104, 2];
            t.extend_from_slice(&[119, 7]);
            t.extend_from_slice(b"options");
            t.extend_from_slice(&[108, 0, 0, 0, 1]);
            t.extend_from_slice(&[119, 10]);
            t.extend_from_slice(b"debug_info");
            t.push(106);
            t
        };
        let bare_binary = {
            let mut t = vec![131, 109, 0, 0, 0, 3];
            t.extend_from_slice(b"foo");
            t
        };
        let payloads: Vec<Vec<u8>> = vec![
            vec![131, 119, 3, 102, 111, 111], // a bare atom
            vec![131, 97, 42],                // a bare integer
            bare_tuple,                       // one {key, value} pair, no list
            bare_binary,                      // a bare binary
        ];
        for payload in payloads {
            let tmp = tempfile::tempdir().expect("tmpdir");
            let path = tmp.path().join("bad.beam");
            std::fs::write(&path, beam_with_cinf(&payload)).unwrap();
            assert!(
                read_compile_info(path.to_str().unwrap()).is_err(),
                "payload {payload:?} must fail"
            );
        }
    }

    /// External term for `[{options, [debug_info]}, junk]`: a valid pair
    /// followed by an element that is not a pair at all.
    fn compile_info_with_non_pair_term() -> Vec<u8> {
        let mut t = vec![131];
        // LIST_EXT, len 2
        t.extend_from_slice(&[108, 0, 0, 0, 2]);
        // {options, [debug_info]}
        t.extend_from_slice(&[104, 2]); // SMALL_TUPLE_EXT arity 2
        t.extend_from_slice(&[119, 7]); // SMALL_ATOM_UTF8_EXT "options"
        t.extend_from_slice(b"options");
        t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT len 1
        t.extend_from_slice(&[119, 10]);
        t.extend_from_slice(b"debug_info");
        t.push(106); // NIL tail
        // junk
        t.extend_from_slice(&[119, 4]); // SMALL_ATOM_UTF8_EXT "junk"
        t.extend_from_slice(b"junk");
        t.push(106); // NIL tail
        t
    }

    /// A compile-info element that is not a {Key, Value} pair fails the
    /// whole chunk: pybeam builds `dict(cinf)`, which raises on such an
    /// element, and the reference reports `pybeam-failed`. Dropping the
    /// element instead would silently accept a chunk the reference
    /// rejects.
    #[test]
    fn non_pair_compile_info_entry_fails() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("nonpair.beam");
        std::fs::write(&path, beam_with_cinf(&compile_info_with_non_pair_term())).unwrap();
        assert_eq!(
            read_compile_info(path.to_str().unwrap()).err().as_deref(),
            Some("compile info entry is not a pair")
        );
    }

    /// A tuple of the wrong arity is not a pair either, and fails the
    /// same way.
    #[test]
    fn non_pair_tuple_compile_info_entry_fails() {
        let mut t = vec![131];
        // LIST_EXT, len 1
        t.extend_from_slice(&[108, 0, 0, 0, 1]);
        // {options, [debug_info], extra}
        t.extend_from_slice(&[104, 3]); // SMALL_TUPLE_EXT arity 3
        t.extend_from_slice(&[119, 7]);
        t.extend_from_slice(b"options");
        t.extend_from_slice(&[108, 0, 0, 0, 1]);
        t.extend_from_slice(&[119, 10]);
        t.extend_from_slice(b"debug_info");
        t.push(106); // NIL tail
        t.extend_from_slice(&[119, 5]);
        t.extend_from_slice(b"extra");
        t.push(106); // NIL tail
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("tup3.beam");
        std::fs::write(&path, beam_with_cinf(&t)).unwrap();
        assert_eq!(
            read_compile_info(path.to_str().unwrap()).err().as_deref(),
            Some("compile info entry is not a pair")
        );
    }

    /// A 2-element list element is a pair too: `dict(cinf)` accepts any
    /// 2-element sequence, so `[options, [debug_info]]` written as a
    /// list rather than a tuple is accepted by the reference and its
    /// options are read.
    #[test]
    fn list_pair_compile_info_entry_is_accepted() {
        let mut t = vec![131];
        // LIST_EXT, len 1
        t.extend_from_slice(&[108, 0, 0, 0, 1]);
        // [options, [debug_info]] as a list
        t.extend_from_slice(&[108, 0, 0, 0, 2]);
        t.extend_from_slice(&[119, 7]);
        t.extend_from_slice(b"options");
        t.extend_from_slice(&[108, 0, 0, 0, 1]);
        t.extend_from_slice(&[119, 10]);
        t.extend_from_slice(b"debug_info");
        t.push(106); // NIL tail
        t.push(106); // NIL tail
        t.push(106); // NIL tail
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("listpair.beam");
        std::fs::write(&path, beam_with_cinf(&t)).unwrap();
        let info = read_compile_info(path.to_str().unwrap())
            .expect("2-element list entry is a pair")
            .expect("compile info present");
        assert_eq!(
            info.options.expect("options read"),
            vec!["debug_info".to_string()]
        );
    }

    /// A 2-byte binary element is a 2-element sequence of integers for
    /// `dict(cinf)`, so it is accepted as a pair (its integer key can
    /// never match an atom key).
    #[test]
    fn two_byte_binary_compile_info_entry_is_accepted() {
        let mut t = vec![131];
        // LIST_EXT, len 1
        t.extend_from_slice(&[108, 0, 0, 0, 1]);
        // BINARY_EXT, len 2
        t.extend_from_slice(&[109, 0, 0, 0, 2, 1, 2]);
        t.push(106); // NIL tail
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("binpair.beam");
        std::fs::write(&path, beam_with_cinf(&t)).unwrap();
        let info = read_compile_info(path.to_str().unwrap())
            .expect("2-byte binary entry is a pair")
            .expect("compile info present");
        // The opaque pair leaks nothing: its integer key matches no
        // atom key, so neither options nor source is set.
        assert!(info.options.is_none());
        assert!(info.source.is_none());
    }

    /// The 3-byte binary is the negative boundary of the 2-byte case:
    /// a 3-element sequence raises in `dict(cinf)`, so the chunk fails.
    #[test]
    fn three_byte_binary_compile_info_entry_fails() {
        let mut t = vec![131];
        // LIST_EXT, len 1
        t.extend_from_slice(&[108, 0, 0, 0, 1]);
        // BINARY_EXT, len 3
        t.extend_from_slice(&[109, 0, 0, 0, 3, 1, 2, 3]);
        t.push(106); // NIL tail
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("bin3.beam");
        std::fs::write(&path, beam_with_cinf(&t)).unwrap();
        assert_eq!(
            read_compile_info(path.to_str().unwrap()).err().as_deref(),
            Some("compile info entry is not a pair")
        );
    }

    /// A 2-character atom element is a 2-element sequence for
    /// `dict(cinf)` (`dict(['ab']) == {'a': 'b'}`), so it is accepted
    /// as an opaque pair whose one-character halves match no atom key.
    #[test]
    fn two_char_atom_compile_info_entry_is_accepted() {
        let mut t = vec![131];
        // LIST_EXT, len 1
        t.extend_from_slice(&[108, 0, 0, 0, 1]);
        t.extend_from_slice(&[119, 2]); // SMALL_ATOM_UTF8_EXT "ab"
        t.extend_from_slice(b"ab");
        t.push(106); // NIL tail
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("atompair.beam");
        std::fs::write(&path, beam_with_cinf(&t)).unwrap();
        let info = read_compile_info(path.to_str().unwrap())
            .expect("2-char atom entry is a pair")
            .expect("compile info present");
        assert!(info.options.is_none());
        assert!(info.source.is_none());
    }

    /// A 2-entry map element is a pair of its two keys for `dict()`
    /// (which iterates the map's keys); its values play no part, and
    /// neither key here matches an atom key of interest.
    #[test]
    fn two_entry_map_compile_info_entry_is_accepted() {
        let mut t = vec![131];
        // LIST_EXT, len 1
        t.extend_from_slice(&[108, 0, 0, 0, 1]);
        // MAP_EXT, arity 2: {"ab" => 1, "cd" => 2}
        t.extend_from_slice(&[116, 0, 0, 0, 2]);
        t.extend_from_slice(&[119, 2]);
        t.extend_from_slice(b"ab");
        t.extend_from_slice(&[97, 1]); // SMALL_INTEGER_EXT
        t.extend_from_slice(&[119, 2]);
        t.extend_from_slice(b"cd");
        t.extend_from_slice(&[97, 2]);
        t.push(106); // NIL tail
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("mappair.beam");
        std::fs::write(&path, beam_with_cinf(&t)).unwrap();
        let info = read_compile_info(path.to_str().unwrap())
            .expect("2-entry map entry is a pair")
            .expect("compile info present");
        assert!(info.options.is_none());
        assert!(info.source.is_none());
    }

    /// A pair whose key `dict()` cannot hash (a list, or a list inside
    /// the top-level map form) raises TypeError there, so the chunk
    /// fails instead of the key being silently dropped by the
    /// atom-key match.
    #[test]
    fn unhashable_compile_info_key_fails() {
        // [{[1, 2], 3}]: a tuple pair with a list key.
        let list_key_pair = {
            let mut t = vec![131];
            t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1
            t.extend_from_slice(&[104, 2]); // SMALL_TUPLE_EXT arity 2
            t.extend_from_slice(&[108, 0, 0, 0, 2]); // LIST_EXT, len 2
            t.extend_from_slice(&[97, 1]);
            t.extend_from_slice(&[97, 2]);
            t.push(106); // NIL tail (key list)
            t.extend_from_slice(&[97, 3]);
            t.push(106); // NIL tail (outer list)
            t
        };
        // {[1] => 2}: the map form with a list key.
        let list_key_map = {
            let mut t = vec![131];
            t.extend_from_slice(&[116, 0, 0, 0, 1]); // MAP_EXT, arity 1
            t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1
            t.extend_from_slice(&[97, 1]);
            t.push(106); // NIL tail (key list)
            t.extend_from_slice(&[97, 2]);
            t
        };
        for payload in [list_key_pair, list_key_map] {
            let tmp = tempfile::tempdir().expect("tmpdir");
            let path = tmp.path().join("unhashable.beam");
            std::fs::write(&path, beam_with_cinf(&payload)).unwrap();
            assert_eq!(
                read_compile_info(path.to_str().unwrap()).err().as_deref(),
                Some("compile info key is not hashable"),
                "payload {payload:?} must fail"
            );
        }
    }

    /// A 2-entry map element is a pair of its two keys for `dict()`,
    /// but pybeam builds the inner map first: both of its keys must
    /// be hashable there, not only the one that becomes the pair key.
    /// `{<<"options">> => 1, [1] => 2}` raises while the inner dict
    /// is built, so the chunk fails even though the outer key (the
    /// binary) is hashable.
    #[test]
    fn two_entry_map_with_unhashable_second_key_fails() {
        let mut t = vec![131];
        t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1
        t.extend_from_slice(&[116, 0, 0, 0, 2]); // MAP_EXT, arity 2
        t.extend_from_slice(&[109, 0, 0, 0, 7]); // BINARY_EXT, len 7
        t.extend_from_slice(b"options");
        t.extend_from_slice(&[97, 1]); // SMALL_INTEGER_EXT
        t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1: the key [1]
        t.extend_from_slice(&[97, 1]);
        t.push(106); // NIL tail (key list)
        t.extend_from_slice(&[97, 2]);
        t.push(106); // NIL tail (outer list)
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("mapsecondkey.beam");
        std::fs::write(&path, beam_with_cinf(&t)).unwrap();
        assert_eq!(
            read_compile_info(path.to_str().unwrap()).err().as_deref(),
            Some("compile info key is not hashable")
        );
    }

    /// The same 2-entry map with both keys hashable stays accepted:
    /// `{<<"options">> => 1, source => 2}` is a pair of a binary and
    /// an atom, neither of which the pair handling reads as a key of
    /// interest, but building the inner dict is legal there.
    #[test]
    fn two_entry_map_with_hashable_keys_is_accepted() {
        let mut t = vec![131];
        t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1
        t.extend_from_slice(&[116, 0, 0, 0, 2]); // MAP_EXT, arity 2
        t.extend_from_slice(&[109, 0, 0, 0, 7]); // BINARY_EXT, len 7
        t.extend_from_slice(b"options");
        t.extend_from_slice(&[97, 1]); // SMALL_INTEGER_EXT
        t.extend_from_slice(&[119, 6]); // SMALL_ATOM_UTF8_EXT "source"
        t.extend_from_slice(b"source");
        t.extend_from_slice(&[97, 2]);
        t.push(106); // NIL tail (outer list)
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("maphashablekeys.beam");
        std::fs::write(&path, beam_with_cinf(&t)).unwrap();
        let info = read_compile_info(path.to_str().unwrap())
            .expect("2-entry map with hashable keys is a pair")
            .expect("compile info present");
        assert!(info.options.is_none());
        assert!(info.source.is_none());
    }

    /// A map nested in a pair value is built by pybeam during decode,
    /// before `dict(cinf)` runs: `[{options, #{[1] => 2}}]` raises
    /// `TypeError` there even though the value is never used as a
    /// key. The same holds for a map nested in a top-level map value,
    /// in a list value, and in a discarded inner-map value.
    #[test]
    fn nested_map_with_unhashable_key_fails() {
        // [{options, #{[1] => 2}}]
        let in_pair_value = {
            let mut t = vec![131];
            t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1
            t.extend_from_slice(&[104, 2]); // SMALL_TUPLE_EXT arity 2
            t.extend_from_slice(&[119, 7]);
            t.extend_from_slice(b"options");
            t.extend_from_slice(&[116, 0, 0, 0, 1]); // MAP_EXT, arity 1
            t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1: the key [1]
            t.extend_from_slice(&[97, 1]);
            t.push(106); // NIL tail (key list)
            t.extend_from_slice(&[97, 2]);
            t.push(106); // NIL tail (outer list)
            t
        };
        // #{options => #{[1] => 2}}
        let in_top_map_value = {
            let mut t = vec![131];
            t.extend_from_slice(&[116, 0, 0, 0, 1]); // MAP_EXT, arity 1
            t.extend_from_slice(&[119, 7]);
            t.extend_from_slice(b"options");
            t.extend_from_slice(&[116, 0, 0, 0, 1]); // MAP_EXT, arity 1
            t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1: the key [1]
            t.extend_from_slice(&[97, 1]);
            t.push(106); // NIL tail (key list)
            t.extend_from_slice(&[97, 2]);
            t
        };
        // [{options, [#{[1] => 2}]}]
        let in_list_value = {
            let mut t = vec![131];
            t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1
            t.extend_from_slice(&[104, 2]); // SMALL_TUPLE_EXT arity 2
            t.extend_from_slice(&[119, 7]);
            t.extend_from_slice(b"options");
            t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1
            t.extend_from_slice(&[116, 0, 0, 0, 1]); // MAP_EXT, arity 1
            t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1: the key [1]
            t.extend_from_slice(&[97, 1]);
            t.push(106); // NIL tail (key list)
            t.extend_from_slice(&[97, 2]);
            t.push(106); // NIL tail (value list)
            t.push(106); // NIL tail (outer list)
            t
        };
        // [#{a => #{[1] => 2}, b => 1}]: the bad map sits in a value
        // of the 2-entry map element, which the pair handling drops.
        let in_discarded_map_value = {
            let mut t = vec![131];
            t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1
            t.extend_from_slice(&[116, 0, 0, 0, 2]); // MAP_EXT, arity 2
            t.extend_from_slice(&[119, 1]);
            t.extend_from_slice(b"a");
            t.extend_from_slice(&[116, 0, 0, 0, 1]); // MAP_EXT, arity 1
            t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1: the key [1]
            t.extend_from_slice(&[97, 1]);
            t.push(106); // NIL tail (key list)
            t.extend_from_slice(&[97, 2]);
            t.extend_from_slice(&[119, 1]);
            t.extend_from_slice(b"b");
            t.extend_from_slice(&[97, 1]);
            t.push(106); // NIL tail (outer list)
            t
        };
        for payload in [
            in_pair_value,
            in_top_map_value,
            in_list_value,
            in_discarded_map_value,
        ] {
            let tmp = tempfile::tempdir().expect("tmpdir");
            let path = tmp.path().join("nestedmap.beam");
            std::fs::write(&path, beam_with_cinf(&payload)).unwrap();
            assert_eq!(
                read_compile_info(path.to_str().unwrap()).err().as_deref(),
                Some("compile info key is not hashable"),
                "payload {payload:?} must fail"
            );
        }
    }

    /// A nested map whose keys are all hashable decodes fine:
    /// `[{options, #{a => 1}}]` parses (the map value is simply not
    /// the list of option atoms the reader looks for).
    #[test]
    fn nested_map_with_hashable_keys_is_accepted() {
        let mut t = vec![131];
        t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1
        t.extend_from_slice(&[104, 2]); // SMALL_TUPLE_EXT arity 2
        t.extend_from_slice(&[119, 7]);
        t.extend_from_slice(b"options");
        t.extend_from_slice(&[116, 0, 0, 0, 1]); // MAP_EXT, arity 1
        t.extend_from_slice(&[119, 1]);
        t.extend_from_slice(b"a");
        t.extend_from_slice(&[97, 1]);
        t.push(106); // NIL tail (outer list)
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("nestedok.beam");
        std::fs::write(&path, beam_with_cinf(&t)).unwrap();
        let info = read_compile_info(path.to_str().unwrap())
            .expect("nested map with hashable keys parses")
            .expect("compile info present");
        assert!(info.options.is_none());
        assert!(info.source.is_none());
    }

    /// End to end: a BEAM file whose CInf chunk is not a pair list
    /// surfaces from `check_binary` as exactly one `pybeam-failed` at
    /// Error, not as missed compile info or silence.
    #[test]
    fn check_binary_reports_pybeam_failed_at_error() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let beam_path = tmp.path().join("bad.beam");
        std::fs::write(
            &beam_path,
            beam_with_cinf(&compile_info_with_non_pair_term()),
        )
        .unwrap();
        let rpm = format!(
            "{}/../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut pkg =
            Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture header");
        pkg.files = vec![crate::pkg::pkgfile::PkgFile {
            name: "/usr/lib/erlang/lib/foo/ebin/bad.beam".to_string(),
            path: beam_path.to_string_lossy().into_owned(),
            ..Default::default()
        }];
        let config = Config::default();
        let mut check = ErlangCheck::new(&config);
        let mut out = Filter::new(&config, crate::color::Color::for_tty(false)).unwrap();
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results();
        assert_eq!(results.len(), 1, "exactly one finding: {results:?}");
        assert_eq!(results[0].0, "pybeam-failed");
        assert!(
            results[0].1.contains(": E: pybeam-failed"),
            "the finding renders at Error: {}",
            results[0].1
        );
    }

    /// External term for `[{options, [warn_unused_vars]}, {source, <<"/home/abuild/rpmbuild/BUILD/foo">>}]`:
    /// compile info whose options do NOT record `debug_info`.
    fn compile_info_term_without_debug_info() -> Vec<u8> {
        let mut t = vec![131];
        t.extend_from_slice(&[108, 0, 0, 0, 2]); // LIST_EXT, len 2
        t.extend_from_slice(&[104, 2]); // {options, [warn_unused_vars]}
        push_atom(&mut t, 119, b"options");
        t.extend_from_slice(&[108, 0, 0, 0, 1]);
        push_atom(&mut t, 119, b"warn_unused_vars");
        t.push(106); // NIL tail
        t.extend_from_slice(&[104, 2]); // {source, Binary}
        push_atom(&mut t, 119, b"source");
        let source = b"/home/abuild/rpmbuild/BUILD/foo.erl";
        t.extend_from_slice(&[109]); // BINARY_EXT
        t.extend_from_slice(&(source.len() as u32).to_be_bytes());
        t.extend_from_slice(source);
        t.push(106); // NIL tail
        t
    }

    /// `{debug_info_v1, erl_abstract_code, {none, [warn_unused_vars]}}`:
    /// the Dbgi placeholder an Erlang compile without debug info writes.
    fn dbgi_erlang_placeholder() -> Vec<u8> {
        let mut t = vec![131, 104, 3];
        push_atom(&mut t, 119, b"debug_info_v1");
        push_atom(&mut t, 119, b"erl_abstract_code");
        t.extend_from_slice(&[104, 2]);
        push_atom(&mut t, 119, b"none");
        t.extend_from_slice(&[108, 0, 0, 0, 1]);
        push_atom(&mut t, 119, b"warn_unused_vars");
        t.push(106);
        t
    }

    /// `{debug_info_v1, elixir_erl, none}`: the Dbgi placeholder an
    /// Elixir compile without debug info writes.
    fn dbgi_elixir_placeholder() -> Vec<u8> {
        let mut t = vec![131, 104, 3];
        push_atom(&mut t, 119, b"debug_info_v1");
        push_atom(&mut t, 119, b"elixir_erl");
        push_atom(&mut t, 119, b"none");
        t
    }

    /// `{debug_info_v1, erl_abstract_code, [{attribute, 1, module, foo}]}`:
    /// a real Erlang debug-info payload (abstract forms).
    fn dbgi_erlang_real() -> Vec<u8> {
        let mut t = vec![131, 104, 3];
        push_atom(&mut t, 119, b"debug_info_v1");
        push_atom(&mut t, 119, b"erl_abstract_code");
        t.extend_from_slice(&[108, 0, 0, 0, 1]); // [{attribute, 1, module, foo}]
        t.extend_from_slice(&[104, 4]);
        push_atom(&mut t, 119, b"attribute");
        t.extend_from_slice(&[97, 1]); // SMALL_INTEGER_EXT
        push_atom(&mut t, 119, b"module");
        push_atom(&mut t, 119, b"foo");
        t.push(106); // NIL tail
        t
    }

    /// `{debug_info_v1, elixir_erl, {elixir_v1, #{}}}`: a real Elixir
    /// debug-info payload.
    fn dbgi_elixir_real() -> Vec<u8> {
        let mut t = vec![131, 104, 3];
        push_atom(&mut t, 119, b"debug_info_v1");
        push_atom(&mut t, 119, b"elixir_erl");
        t.extend_from_slice(&[104, 2]);
        push_atom(&mut t, 119, b"elixir_v1");
        t.extend_from_slice(&[116, 0, 0, 0, 0]); // MAP_EXT, empty
        t
    }

    /// Wrap an external term (including its 131 version byte) in the
    /// COMPRESSED_EXT form: `[131, 80, uncompressed-size, zlib...]`.
    fn compressed_term(payload: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&payload[1..]).expect("compress");
        let zipped = enc.finish().expect("finish compression");
        let mut t = vec![131, 80];
        t.extend_from_slice(&((payload.len() - 1) as u32).to_be_bytes());
        t.extend_from_slice(&zipped);
        t
    }

    #[test]
    fn dbgi_placeholder_shapes_earn_no_credit() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let wrong_head = {
            let mut t = vec![131, 104, 3];
            push_atom(&mut t, 119, b"not_debug_info");
            push_atom(&mut t, 119, b"erl_abstract_code");
            push_atom(&mut t, 119, b"none");
            t
        };
        for (name, payload) in [
            ("erlang placeholder", dbgi_erlang_placeholder()),
            ("elixir placeholder", dbgi_elixir_placeholder()),
            (
                "compressed placeholder",
                compressed_term(&dbgi_erlang_placeholder()),
            ),
            ("garbage", vec![131, 1, 2, 3]),
            ("wrong head atom", wrong_head),
        ] {
            let path = tmp.path().join("x.beam");
            std::fs::write(&path, beam_with_chunks(&[(b"Dbgi", &payload)])).unwrap();
            assert!(
                !has_real_dbgi_payload(path.to_str().unwrap()),
                "{name} must not count as debug info"
            );
        }
        // No Dbgi chunk at all.
        let path = tmp.path().join("none.beam");
        std::fs::write(&path, beam_with_cinf(&compile_info_term(119))).unwrap();
        assert!(!has_real_dbgi_payload(path.to_str().unwrap()));
    }

    #[test]
    fn dbgi_real_payload_shapes_earn_credit() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        for (name, payload) in [
            ("erlang abstract forms", dbgi_erlang_real()),
            ("elixir v1 data", dbgi_elixir_real()),
            ("compressed real", compressed_term(&dbgi_erlang_real())),
        ] {
            let path = tmp.path().join("x.beam");
            std::fs::write(&path, beam_with_chunks(&[(b"Dbgi", &payload)])).unwrap();
            assert!(
                has_real_dbgi_payload(path.to_str().unwrap()),
                "{name} must count as debug info"
            );
        }
    }

    /// Run `ErlangCheck` over one synthetic BEAM file and return the
    /// finding ids it produced.
    fn finding_ids_for_beam(bytes: &[u8]) -> Vec<String> {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let beam_path = tmp.path().join("mod.beam");
        std::fs::write(&beam_path, bytes).unwrap();
        let rpm = format!(
            "{}/../../tests/parity/cases/parity/input/parity-1.0-1.noarch.rpm",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut pkg =
            Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture header");
        pkg.files = vec![crate::pkg::pkgfile::PkgFile {
            name: "/usr/lib/erlang/lib/foo/ebin/mod.beam".to_string(),
            path: beam_path.to_string_lossy().into_owned(),
            ..Default::default()
        }];
        let config = Config::default();
        let mut check = ErlangCheck::new(&config);
        let mut out = Filter::new(&config, crate::color::Color::for_tty(false)).unwrap();
        check.check_binary(&pkg, &config, &mut out);
        out.results().iter().map(|(id, _)| id.to_string()).collect()
    }

    /// Compile info without the `debug_info` option plus a Dbgi chunk
    /// holding a real payload: the file carries debug info even
    /// though the recorded options do not say so (the shape of
    /// Elixir-compiled beams in rabbitmq-server's plugin set).
    #[test]
    fn real_dbgi_payload_silences_without_debuginfo() {
        for payload in [dbgi_elixir_real(), dbgi_erlang_real()] {
            let beam = beam_with_chunks(&[
                (b"CInf", &compile_info_term_without_debug_info()),
                (b"Dbgi", &payload),
            ]);
            assert_eq!(finding_ids_for_beam(&beam), Vec::<String>::new());
        }
    }

    /// Near misses: the same compile info, but the Dbgi chunk holds
    /// only the compiler's no-debug-info placeholder (or garbage, or
    /// nothing) — the finding must still fire.
    #[test]
    fn placeholder_dbgi_still_reports_without_debuginfo() {
        for payload in [
            Some(dbgi_erlang_placeholder()),
            Some(dbgi_elixir_placeholder()),
            Some(vec![131, 1, 2, 3]),
            None,
        ] {
            let beam = match &payload {
                Some(payload) => beam_with_chunks(&[
                    (b"CInf", &compile_info_term_without_debug_info()),
                    (b"Dbgi", payload),
                ]),
                None => beam_with_cinf(&compile_info_term_without_debug_info()),
            };
            assert_eq!(
                finding_ids_for_beam(&beam),
                vec!["beam-compiled-without-debuginfo".to_string()],
                "dbgi {payload:?} must still report"
            );
        }
    }

    /// A crafted CInf of nothing but nested SMALL_TUPLE wrappers used
    /// to recurse once per level and overflow the stack. The depth cap
    /// must turn it into a plain parse failure (`pybeam-failed`).
    #[test]
    fn deeply_nested_term_fails_instead_of_overflowing() {
        let mut payload = vec![131u8];
        for _ in 0..200_000 {
            payload.extend_from_slice(&[104, 1]); // SMALL_TUPLE_EXT, arity 1
        }
        payload.push(106); // NIL
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("deep.beam");
        std::fs::write(&path, beam_with_cinf(&payload)).unwrap();
        assert!(read_compile_info(path.to_str().unwrap()).is_err());
    }

    /// Terms nested far past anything a real BEAM carries, but within
    /// the depth cap, still parse.
    #[test]
    fn nested_term_within_depth_cap_parses() {
        let mut payload = vec![131u8];
        for _ in 0..64 {
            payload.extend_from_slice(&[104, 1]); // SMALL_TUPLE_EXT, arity 1
        }
        payload.push(106); // NIL
        let mut parser = TermParser::new(&payload[1..]);
        let mut term = parser.parse_term().expect("parses");
        for _ in 0..64 {
            match term {
                Term::Tuple(mut elems) => {
                    assert_eq!(elems.len(), 1);
                    term = elems.pop().unwrap();
                }
                other => panic!("expected tuple, got {other:?}"),
            }
        }
        assert_eq!(term, Term::List(Vec::new()));
    }

    /// External term nested `levels` deep: `levels - 1` nested
    /// SMALL_TUPLE wrappers around a NIL leaf, so the leaf is parsed by
    /// the `levels`-th nested `parse_term` call.
    fn nested_tuple_payload(levels: usize) -> Vec<u8> {
        let mut payload = vec![131u8];
        for _ in 0..levels.saturating_sub(1) {
            payload.extend_from_slice(&[104, 1]); // SMALL_TUPLE_EXT, arity 1
        }
        payload.push(106); // NIL
        payload
    }

    #[test]
    fn term_at_max_depth_parses() {
        // `parse_term` refuses a term once the nesting depth reaches
        // `MAX_TERM_DEPTH`, so a term nested exactly that deep is the
        // deepest one that still parses.
        let payload = nested_tuple_payload(MAX_TERM_DEPTH);
        let mut parser = TermParser::new(&payload[1..]);
        assert!(
            parser.parse_term().is_some(),
            "term at MAX_TERM_DEPTH must parse"
        );
    }

    #[test]
    fn term_past_max_depth_fails_to_parse() {
        let payload = nested_tuple_payload(MAX_TERM_DEPTH + 1);
        let mut parser = TermParser::new(&payload[1..]);
        assert!(
            parser.parse_term().is_none(),
            "term at MAX_TERM_DEPTH + 1 must not parse"
        );
    }

    #[test]
    fn term_past_max_depth_reports_term_parse_failed() {
        // The depth refusal surfaces through `read_compile_info` as the
        // `term parse failed` error (the check reports it as
        // `pybeam-failed`); a term that parses but is not compile info
        // fails with a different error, so the text pins the failure to
        // the depth cap.
        let payload = nested_tuple_payload(MAX_TERM_DEPTH + 1);
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("toodeep.beam");
        std::fs::write(&path, beam_with_cinf(&payload)).unwrap();
        let err = read_compile_info(path.to_str().unwrap())
            .err()
            .expect("must fail");
        assert_eq!(err, "term parse failed");
    }

    /// Build the external term for `[{options, [debug_info]}]` with the
    /// `options` key encoded via the UTF-8 atom tag `tag`, holding
    /// bytes that are not valid UTF-8 (`opti\xffons`).
    fn bad_utf8_key_term(tag: u8) -> Vec<u8> {
        let mut t = vec![131];
        t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT, len 1
        t.extend_from_slice(&[104, 2]); // SMALL_TUPLE_EXT arity 2
        push_atom(&mut t, tag, b"opti\xffons");
        t.extend_from_slice(&[108, 0, 0, 0, 1]); // LIST_EXT len 1
        push_atom(&mut t, tag, b"debug_info");
        t.push(106); // NIL tail (options list)
        t.push(106); // NIL tail (outer list)
        t
    }

    #[test]
    fn invalid_utf8_atom_fails_the_parse() {
        // pybeam decodes the UTF-8 atom tags strictly, so a CInf term
        // holding an atom that is not valid UTF-8 makes the reference
        // report pybeam-failed; the parse must fail here too instead of
        // decoding the atom with replacement characters. Each UTF-8
        // tag is pinned in turn: a lossy decode on either one alone
        // fails this test.
        for tag in UTF8_ATOM_TAGS {
            let tmp = tempfile::tempdir().expect("tmpdir");
            let path = tmp.path().join("badatom.beam");
            std::fs::write(&path, beam_with_cinf(&bad_utf8_key_term(tag))).unwrap();
            assert!(
                read_compile_info(path.to_str().unwrap()).is_err(),
                "tag {tag}"
            );
        }
    }

    #[test]
    fn valid_utf8_atoms_parse() {
        // A multibyte UTF-8 atom is valid input and survives the strict
        // decode unchanged, under either UTF-8 atom tag.
        for tag in UTF8_ATOM_TAGS {
            let mut t = vec![131];
            t.extend_from_slice(&[108, 0, 0, 0, 1]);
            t.extend_from_slice(&[104, 2]);
            push_atom(&mut t, tag, b"options");
            t.extend_from_slice(&[108, 0, 0, 0, 2]); // LIST_EXT len 2
            push_atom(&mut t, tag, b"debug_info");
            push_atom(&mut t, tag, "café".as_bytes());
            t.push(106);
            t.push(106);
            let tmp = tempfile::tempdir().expect("tmpdir");
            let path = tmp.path().join("utf8.beam");
            std::fs::write(&path, beam_with_cinf(&t)).unwrap();
            let info = read_compile_info(path.to_str().unwrap())
                .expect("reads")
                .expect("has compile info");
            let options = info.options.expect("options");
            assert!(options.contains(&"debug_info".to_string()), "tag {tag}");
            assert!(options.contains(&"café".to_string()), "tag {tag}");
        }
    }

    #[test]
    fn latin1_atom_decodes_as_latin1() {
        // The non-UTF-8 atom tags carry Latin-1: byte 0xE9 is the
        // character é, not part of a UTF-8 sequence. pybeam decodes
        // these tags as Latin-1, so a Latin-1 source atom comes through
        // as the characters its bytes name. Each Latin-1 tag is pinned
        // in turn: a UTF-8 decode on either one alone fails this test.
        let source: &[u8] = b"/home/abuild/rpmbuild/BUILD/caf\xe9.erl";
        for tag in LATIN1_ATOM_TAGS {
            let mut t = vec![131];
            t.extend_from_slice(&[108, 0, 0, 0, 1]);
            t.extend_from_slice(&[104, 2]);
            t.extend_from_slice(&[119, 6]);
            t.extend_from_slice(b"source");
            push_atom(&mut t, tag, source);
            t.push(106);
            let tmp = tempfile::tempdir().expect("tmpdir");
            let path = tmp.path().join("latin1.beam");
            std::fs::write(&path, beam_with_cinf(&t)).unwrap();
            let info = read_compile_info(path.to_str().unwrap())
                .expect("reads")
                .expect("has compile info");
            assert_eq!(
                info.source.as_deref(),
                Some("/home/abuild/rpmbuild/BUILD/café.erl"),
                "tag {tag}"
            );
        }
    }

    #[test]
    fn source_binary_with_invalid_utf8_fails_the_parse() {
        // The source path is UTF-8 in any current BEAM file, so a
        // binary holding bytes that are not valid UTF-8 is garbage:
        // the parse fails (pybeam-failed) instead of decoding the
        // path with replacement characters.
        let source: &[u8] = b"/home/abuild/rpmbuild/BUILD/bad\xffname.erl";
        let mut t = vec![131];
        t.extend_from_slice(&[108, 0, 0, 0, 1]);
        t.extend_from_slice(&[104, 2]);
        t.extend_from_slice(&[119, 6]);
        t.extend_from_slice(b"source");
        t.push(109); // BINARY_EXT
        t.extend_from_slice(&(source.len() as u32).to_be_bytes());
        t.extend_from_slice(source);
        t.push(106);
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("badsource.beam");
        std::fs::write(&path, beam_with_cinf(&t)).unwrap();
        assert!(read_compile_info(path.to_str().unwrap()).is_err());
    }

    #[test]
    fn source_binary_with_valid_utf8_parses() {
        // A multibyte UTF-8 source path in a binary survives the
        // strict decode unchanged.
        let source = "/home/abuild/rpmbuild/BUILD/caf\u{e9}.erl";
        let mut t = vec![131];
        t.extend_from_slice(&[108, 0, 0, 0, 1]);
        t.extend_from_slice(&[104, 2]);
        t.extend_from_slice(&[119, 6]);
        t.extend_from_slice(b"source");
        t.push(109); // BINARY_EXT
        t.extend_from_slice(&(source.len() as u32).to_be_bytes());
        t.extend_from_slice(source.as_bytes());
        t.push(106);
        let tmp = tempfile::tempdir().expect("tmpdir");
        let path = tmp.path().join("utf8source.beam");
        std::fs::write(&path, beam_with_cinf(&t)).unwrap();
        let info = read_compile_info(path.to_str().unwrap())
            .expect("reads")
            .expect("has compile info");
        assert_eq!(info.source.as_deref(), Some(source));
    }
}
