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

struct TermParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> TermParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
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

    fn atom_bytes(&mut self, len: usize) -> Option<Term> {
        let b = self.bytes(len)?;
        Some(Term::Atom(String::from_utf8_lossy(b).into_owned()))
    }

    fn parse_term(&mut self) -> Option<Term> {
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
                self.atom_bytes(len)
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
            // SMALL_ATOM_EXT / SMALL_ATOM_UTF8_EXT
            115 | 119 => {
                let len = self.byte()? as usize;
                self.atom_bytes(len)
            }
            // ATOM_UTF8_EXT
            118 => {
                let len = self.u16()? as usize;
                self.atom_bytes(len)
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
        _ => return Ok(None),
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
                let s = match v {
                    Term::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
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

    /// External term for `[{options, [debug_info]}, {source, <<"/home/abuild/rpmbuild/BUILD/foo">>}]`.
    fn compile_info_term() -> Vec<u8> {
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
        // {source, Binary}
        let source = b"/home/abuild/rpmbuild/BUILD/foo.erl";
        t.extend_from_slice(&[104, 2]);
        t.extend_from_slice(&[119, 6]);
        t.extend_from_slice(b"source");
        t.extend_from_slice(&[109]); // BINARY_EXT
        t.extend_from_slice(&(source.len() as u32).to_be_bytes());
        t.extend_from_slice(source);
        t.push(106); // NIL tail
        t
    }

    #[test]
    fn term_parser_reads_compile_info() {
        let term = compile_info_term();
        assert_eq!(term[0], 131);
        let mut parser = TermParser::new(&term[1..]);
        let parsed = parser.parse_term().expect("parses");
        match parsed {
            Term::List(items) => assert_eq!(items.len(), 2),
            other => panic!("expected list, got {other:?}"),
        }
    }

    #[test]
    fn beam_chunk_walking_finds_cinf() {
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-erlang-test.beam");
        std::fs::write(&path, beam_with_cinf(&compile_info_term())).unwrap();
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
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn garbage_is_not_a_beam_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-erlang-garbage.beam");
        std::fs::write(&path, b"not a beam file at all").unwrap();
        assert!(read_compile_info(path.to_str().unwrap()).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_cinf_means_compile_info_missed() {
        // B4: a missing CInf chunk is not a parse failure. pybeam returns
        // None for `compileinfo`, so the reference emits
        // `beam-compile-info-missed` (W), not `pybeam-failed` (E).
        let mut beam = beam_with_cinf(&compile_info_term());
        // Corrupt the chunk name.
        beam[12..16].copy_from_slice(b"XXXX");
        let dir = std::env::temp_dir();
        let path = dir.join("rpmcrab-erlang-nocinf.beam");
        std::fs::write(&path, &beam).unwrap();
        assert!(
            read_compile_info(path.to_str().unwrap())
                .expect("reads")
                .is_none()
        );
        std::fs::remove_file(&path).ok();
    }
}
