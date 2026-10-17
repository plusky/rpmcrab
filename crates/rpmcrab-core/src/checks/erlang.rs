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
//! `source` entries.

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
                // Tail; NIL is the common case.
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

    // Compile info is a list of {Key, Value} tuples (older) or a map (newer).
    let pairs: Vec<(Term, Term)> = match term {
        Term::List(items) => items
            .into_iter()
            .filter_map(|t| match t {
                Term::Tuple(mut elems) if elems.len() == 2 => {
                    let v = elems.pop().unwrap();
                    let k = elems.pop().unwrap();
                    Some((k, v))
                }
                _ => None,
            })
            .collect(),
        Term::Map(pairs) => pairs,
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

/// True when the BEAM file has a `Dbgi` (debug info) chunk.
fn has_dbgi_chunk(path: &str) -> bool {
    let Ok(data) = std::fs::read(path) else {
        return false;
    };
    if data.len() < 12 {
        return false;
    }
    let mut pos = 12;
    while pos + 8 <= data.len() {
        let name = &data[pos..pos + 4];
        if name == b"Dbgi" {
            return true;
        }
        let size = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
            as usize;
        pos += 8;
        let end = pos.saturating_add(size).min(data.len());
        pos = end + (4 - end % 4) % 4;
    }
    false
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
                Some(options) => options.iter().any(|o| o == "debug_info"),
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

    /// Build a minimal BEAM file with a CInf chunk holding the given
    /// external-term payload.
    fn beam_with_cinf(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"FOR1");
        out.extend_from_slice(&[0, 0, 0, 0]); // patched below
        out.extend_from_slice(b"BEAM");
        out.extend_from_slice(b"CInf");
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        let size = (out.len() - 8) as u32;
        out[4..8].copy_from_slice(&size.to_be_bytes());
        out
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
