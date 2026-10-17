//! C14N 1.0 canonicalization backing the `xml` file digester.
//!
//! Mirrors `xml.etree.ElementTree.canonicalize(from_file=...,
//! strip_text=True)` (the reference `XmlDigester.parse_content`): inclusive
//! C14N 1.0 over the whole document, comments and the XML declaration
//! dropped, whitespace-only text nodes removed except under in-scope
//! `xml:space="preserve"`, processing instructions kept.

use std::collections::HashMap;
use std::rc::Rc;

use quick_xml::XmlVersion;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// The `xml` prefix is implicitly bound and never rendered as a declaration.
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// Total bytes general-entity expansion may produce across one document.
/// This is an intentional absolute ceiling on the expanded size, not a
/// ratio: the reference parser (expat) instead limits amplification --
/// the ratio of expanded size to input size, once an activation
/// threshold is passed -- so it imposes no fixed expanded-byte limit.
/// Entities in real configuration files expand to a tiny fraction of
/// this, so the cap only bites on crafted internal subsets.
const MAX_ENTITY_EXPANSION_BYTES: usize = 8 * 1024 * 1024;

/// A canonicalized attribute: `(namespaced, namespace URI, local name)` sort
/// key plus the original key/value for emission.
type SortedAttr = (bool, Vec<u8>, Vec<u8>, String, String);

/// Canonicalize the XML file at `path`, returning the UTF-8 canonical bytes
/// the digest is computed over. Malformed input is an error.
pub(crate) fn canonicalize_file(path: &str) -> Result<Vec<u8>, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&data);
    let text = std::str::from_utf8(data).map_err(|_| "not valid UTF-8".to_string())?;
    Canonicalizer::new().canonicalize(text)
}

struct Canonicalizer {
    out: Vec<u8>,
    /// In-scope namespace bindings; one frame per open element.
    /// `(None, uri)` is the default namespace.
    scope: Vec<Vec<(Option<String>, String)>>,
    /// Bindings already rendered on an ancestor; parallel to `scope`.
    rendered: Vec<Vec<(Option<String>, String)>>,
    /// In-scope `xml:space` handling, one frame per open element, parallel
    /// to `scope`: `true` while `xml:space="preserve"` is in effect.
    space_preserve: Vec<bool>,
    /// General entities from the internal DTD subset.
    entities: HashMap<String, Rc<str>>,
    /// Cumulative bytes produced by general-entity expansion so far.
    expanded_bytes: usize,
    /// Processing instructions seen before the document element.
    prolog_pis: Vec<(String, String)>,
    /// Coalesced character data not yet emitted.
    pending_text: String,
    /// A reference was coalesced into `pending_text` while outside the
    /// document element. Such a reference is character data by event,
    /// even when it expands to whitespace, so `flush_text` must not
    /// apply its literal-whitespace allowance to it.
    pending_ref_outside_root: bool,
    seen_root: bool,
    seen_doctype: bool,
    depth: usize,
    version_1_1: bool,
}

impl Canonicalizer {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            scope: Vec::new(),
            rendered: Vec::new(),
            entities: HashMap::new(),
            expanded_bytes: 0,
            prolog_pis: Vec::new(),
            pending_text: String::new(),
            pending_ref_outside_root: false,
            space_preserve: Vec::new(),
            seen_root: false,
            seen_doctype: false,
            depth: 0,
            version_1_1: false,
        }
    }

    fn canonicalize(mut self, text: &str) -> Result<Vec<u8>, String> {
        let mut reader = Reader::from_str(text);
        reader.config_mut().trim_text(false);
        let mut buf = Vec::new();
        loop {
            let ev = reader
                .read_event_into(&mut buf)
                .map_err(|e| format!("XML parse error: {e}"))?;
            match ev {
                Event::Eof => break,
                Event::Decl(e) => {
                    if let Ok(v) = e.version() {
                        self.version_1_1 = v.trim() == "1.1";
                    }
                }
                Event::DocType(e) => {
                    if self.seen_root {
                        return Err("XML parse error: junk after document element".to_string());
                    }
                    if self.seen_doctype {
                        return Err("XML parse error: multiple DOCTYPE declarations".to_string());
                    }
                    self.seen_doctype = true;
                    self.parse_doctype_entities(&e);
                }
                // Comments neither emit nor break text coalescing.
                Event::Comment(_) => {}
                Event::PI(e) => self.emit_pi(&e)?,
                Event::GeneralRef(e) => self.push_ref(&e)?,
                Event::Start(e) => {
                    if self.seen_root && self.depth == 0 {
                        return Err("XML parse error: junk after document element".to_string());
                    }
                    let name = e.name().as_ref().to_string();
                    let attrs = collect_attrs(&e)?;
                    self.flush_prolog_pis();
                    self.flush_text()?;
                    self.seen_root = true;
                    self.start_element(&name, &attrs, false)?;
                    self.depth += 1;
                }
                Event::Empty(e) => {
                    if self.seen_root && self.depth == 0 {
                        return Err("XML parse error: junk after document element".to_string());
                    }
                    let name = e.name().as_ref().to_string();
                    let attrs = collect_attrs(&e)?;
                    self.flush_prolog_pis();
                    self.flush_text()?;
                    self.seen_root = true;
                    self.start_element(&name, &attrs, true)?;
                }
                Event::End(e) => {
                    let owned = e.name();
                    let name: &str = owned.as_ref();
                    self.flush_text()?;
                    self.out.extend_from_slice(b"</");
                    self.out.extend_from_slice(name.as_bytes());
                    self.out.extend_from_slice(b">");
                    self.scope.pop();
                    self.rendered.pop();
                    self.space_preserve.pop();
                    self.depth -= 1;
                }
                Event::Text(e) => {
                    self.pending_text
                        .push_str(&e.xml_content(self.xml_version()));
                }
                Event::CData(e) => {
                    self.pending_text
                        .push_str(&e.xml_content(self.xml_version()));
                }
            }
            buf.clear();
        }
        if !self.seen_root {
            return Err("XML parse error: no document element".to_string());
        }
        if self.depth > 0 {
            return Err("XML parse error: unclosed element".to_string());
        }
        self.flush_text()?;
        Ok(self.out)
    }

    fn xml_version(&self) -> XmlVersion {
        if self.version_1_1 {
            XmlVersion::Explicit1_1
        } else {
            XmlVersion::Implicit1_0
        }
    }

    /// Emit the coalesced character data. Whitespace is stripped (the
    /// `strip_text=True` behaviour) except while `xml:space="preserve"` is
    /// in scope, which the reference keeps verbatim. Outside the document
    /// element only whitespace may appear; anything else is not
    /// well-formed.
    fn flush_text(&mut self) -> Result<(), String> {
        validate_xml_chars(&self.pending_text)?;
        if self.depth == 0
            && (self.pending_ref_outside_root
                || !self
                    .pending_text
                    .trim_matches(|c| matches!(c, ' ' | '\t' | '\n' | '\r'))
                    .is_empty())
        {
            return Err(if self.seen_root {
                "XML parse error: junk after document element".to_string()
            } else {
                "XML parse error: content before document element".to_string()
            });
        }
        let preserve = self.space_preserve.last().copied().unwrap_or(false);
        let text = if preserve {
            self.pending_text.as_str()
        } else {
            self.pending_text.trim()
        };
        if !text.is_empty() {
            let mut escaped = Vec::new();
            escape_text(&mut escaped, text);
            self.out.append(&mut escaped);
        }
        self.pending_text.clear();
        self.pending_ref_outside_root = false;
        Ok(())
    }

    /// Resolve one entity/character reference and append the result.
    /// Predefined and character references are terminal; general entities
    /// expand recursively.
    fn push_ref(&mut self, name: &str) -> Result<(), String> {
        if self.depth == 0 {
            self.pending_ref_outside_root = true;
        }
        if let Some(num) = name.strip_prefix('#') {
            self.pending_text.push(decode_char_ref(num)?);
        } else if let Some(value) = resolve_predefined_entity(name) {
            self.pending_text.push_str(value);
        } else if let Some(value) = self.entities.get(name).cloned() {
            let (expanded, _) = self.expand_entities(&value, 8)?;
            self.charge_expansion(expanded.len())?;
            self.pending_text.push_str(&expanded);
        } else {
            return Err(format!("undefined entity {name:?}"));
        }
        Ok(())
    }

    /// `<?target data?>\n` per prolog PI, emitted ahead of the root element.
    fn flush_prolog_pis(&mut self) {
        for (target, data) in std::mem::take(&mut self.prolog_pis) {
            emit_pi_bytes(&mut self.out, &target, &data);
            self.out.extend_from_slice(b"\n");
        }
    }

    /// Route a PI: prolog buffer, epilog (`\n<?...?>`), or inline.
    fn emit_pi(&mut self, raw: &str) -> Result<(), String> {
        self.flush_text()?;
        let (target, data) = split_pi(raw);
        if !self.seen_root {
            self.prolog_pis.push((target, data));
        } else if self.depth == 0 {
            self.out.extend_from_slice(b"\n");
            emit_pi_bytes(&mut self.out, &target, &data);
        } else {
            emit_pi_bytes(&mut self.out, &target, &data);
        }
        Ok(())
    }

    /// Look up `prefix` (`None` = default namespace) innermost-first.
    fn resolve(&self, prefix: Option<&str>) -> Option<&str> {
        if prefix == Some("xml") {
            return Some(XML_NS);
        }
        self.scope
            .iter()
            .rev()
            .flatten()
            .find(|(p, _)| p.as_deref() == prefix)
            .map(|(_, uri)| uri.as_str())
    }

    /// Look up the nearest rendered binding; unrendered means "no namespace".
    fn rendered_ns(&self, prefix: Option<&str>) -> &str {
        self.rendered
            .iter()
            .rev()
            .flatten()
            .find(|(p, _)| p.as_deref() == prefix)
            .map(|(_, uri)| uri.as_str())
            .unwrap_or("")
    }

    fn start_element(
        &mut self,
        qname: &str,
        attrs: &[(String, String)],
        empty: bool,
    ) -> Result<(), String> {
        let mut scope_frame: Vec<(Option<String>, String)> = Vec::new();
        let mut regular: Vec<(String, String)> = Vec::new();
        for (key, value) in attrs {
            if key == "xmlns" {
                let (uri, added) = self.expand_entities(value, 8)?;
                self.charge_expansion(added)?;
                validate_xml_chars(&uri)?;
                push_decl(&mut scope_frame, None, &uri)?;
            } else if let Some(p) = key.strip_prefix("xmlns:") {
                if p == "xml" {
                    return Err(
                        "XML parse error: reserved prefix (xml) must not be rebound".to_string()
                    );
                }
                let (uri, added) = self.expand_entities(value, 8)?;
                self.charge_expansion(added)?;
                validate_xml_chars(&uri)?;
                push_decl(&mut scope_frame, Some(p), &uri)?;
            } else {
                regular.push((key.clone(), value.clone()));
            }
        }

        // The element's own declarations are in scope for its own name.
        self.scope.push(scope_frame);
        // The `xml` prefix is never rebindable, so the literal qname is the
        // whole check; any other value (or none) inherits the parent scope.
        let preserve = regular
            .iter()
            .find(|(key, _)| *key == "xml:space")
            .map(|(_, value)| value == "preserve")
            .unwrap_or_else(|| self.space_preserve.last().copied().unwrap_or(false));
        self.space_preserve.push(preserve);
        let result = self.emit_element(qname, &regular, empty);
        if result.is_err() {
            self.scope.pop();
            self.space_preserve.pop();
        }
        result
    }

    fn emit_element(
        &mut self,
        qname: &str,
        regular: &[(String, String)],
        empty: bool,
    ) -> Result<(), String> {
        let (prefix, _local) = split_qname(qname);
        // Declarations to render: visibly-utilized bindings whose rendered
        // ancestor binding differs. The `xml` prefix is implicitly bound.
        let mut decls: Vec<(Option<String>, String)> = Vec::new();
        let need_decl = |this: &Self,
                         decls: &mut Vec<(Option<String>, String)>,
                         pfx: Option<&str>|
         -> Result<(), String> {
            if pfx == Some("xml") {
                return Ok(());
            }
            // No default namespace in scope means "no namespace", not an error.
            // A binding counts as rendered only if an ancestor emitted it;
            // otherwise the effective rendered binding is "no namespace".
            let uri = match pfx {
                None => self.resolve(None).unwrap_or(""),
                Some(_) => this
                    .resolve(pfx)
                    .ok_or_else(|| format!("XML parse error: unbound prefix {pfx:?}"))?,
            };
            if this.rendered_ns(pfx) != uri && !decls.iter().any(|(p, _)| p.as_deref() == pfx) {
                decls.push((pfx.map(str::to_string), uri.to_string()));
            }
            Ok(())
        };
        if prefix.is_none() {
            need_decl(self, &mut decls, None)?;
        } else {
            need_decl(self, &mut decls, prefix)?;
        }
        // C14N sorts unprefixed attributes by name first, then prefixed
        // ones by (namespace URI, local name).
        let mut sorted: Vec<SortedAttr> = Vec::new();
        for (key, value) in regular.iter() {
            let (aprefix, local) = split_qname(key);
            if aprefix == Some("xml") {
                sorted.push((
                    true,
                    XML_NS.as_bytes().to_vec(),
                    local.as_bytes().to_vec(),
                    key.clone(),
                    value.clone(),
                ));
            } else if let Some(ap) = aprefix {
                let uri = self
                    .resolve(Some(ap))
                    .ok_or_else(|| format!("XML parse error: unbound prefix {ap:?}"))?;
                need_decl(self, &mut decls, Some(ap))?;
                sorted.push((
                    true,
                    uri.as_bytes().to_vec(),
                    local.as_bytes().to_vec(),
                    key.clone(),
                    value.clone(),
                ));
            } else {
                sorted.push((
                    false,
                    Vec::new(),
                    local.as_bytes().to_vec(),
                    key.clone(),
                    value.clone(),
                ));
            }
        }
        sorted.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
        let mut seen: Vec<(bool, Vec<u8>, Vec<u8>)> = Vec::new();
        for (namespaced, uri, local, _, _) in &sorted {
            let key = (*namespaced, uri.clone(), local.clone());
            if seen.contains(&key) {
                return Err("XML parse error: duplicate attribute".to_string());
            }
            seen.push(key);
        }
        // Default namespace declaration first, then by prefix.
        decls.sort_by(|a, b| a.0.cmp(&b.0));

        self.out.extend_from_slice(b"<");
        self.out.extend_from_slice(qname.as_bytes());
        for (pfx, uri) in &decls {
            match pfx {
                None => self.out.extend_from_slice(b" xmlns=\""),
                Some(p) => {
                    self.out.extend_from_slice(b" xmlns:");
                    self.out.extend_from_slice(p.as_bytes());
                    self.out.extend_from_slice(b"=\"");
                }
            }
            escape_attr(&mut self.out, uri);
            self.out.extend_from_slice(b"\"");
        }
        for (_, _, _, key, value) in &sorted {
            // Literal tab/newline become spaces (XML CDATA-type
            // normalization); character references survive as characters.
            let normalized = eol_normalize(value).replace(['\t', '\n'], " ");
            let (expanded, added) = self.expand_entities(&normalized, 8)?;
            self.charge_expansion(added)?;
            validate_xml_chars(&expanded)?;
            self.out.extend_from_slice(b" ");
            self.out.extend_from_slice(key.as_bytes());
            self.out.extend_from_slice(b"=\"");
            escape_attr(&mut self.out, &expanded);
            self.out.extend_from_slice(b"\"");
        }
        self.out.extend_from_slice(b">");

        self.rendered.push(decls);
        if empty {
            self.out.extend_from_slice(b"</");
            self.out.extend_from_slice(qname.as_bytes());
            self.out.extend_from_slice(b">");
            self.scope.pop();
            self.rendered.pop();
            self.space_preserve.pop();
        }
        Ok(())
    }

    /// Charge one general-entity production to the cumulative expansion
    /// budget, rejecting the document once the budget is exceeded.
    fn charge_expansion(&mut self, len: usize) -> Result<(), String> {
        self.expanded_bytes = self.expanded_bytes.saturating_add(len);
        if self.expanded_bytes > MAX_ENTITY_EXPANSION_BYTES {
            return Err("entity expansion too large".to_string());
        }
        Ok(())
    }

    /// Expand predefined, character and internal-subset general entities in
    /// `raw`. Predefined/character references are terminal (their expansion
    /// is not rescanned); general entities expand recursively. Returns the
    /// expanded text plus the number of bytes general-entity productions
    /// contributed to it, each production counted once at its outermost
    /// reference: plain text passing through costs nothing and nested
    /// productions are not billed again at every level. Callers charge
    /// that count (or, for a text reference, the whole production) to
    /// `expanded_bytes`. A single expansion whose own productions exceed
    /// the budget is rejected here, before the amplified text is built.
    fn expand_entities(&mut self, raw: &str, depth: u8) -> Result<(String, usize), String> {
        if depth == 0 {
            return Err("entity expansion too deep".to_string());
        }
        if !raw.contains('&') {
            return Ok((raw.to_string(), 0));
        }
        let mut out = String::with_capacity(raw.len());
        let mut added = 0usize;
        let mut i = 0;
        while i < raw.len() {
            if raw.as_bytes()[i] == b'&' {
                let rest = &raw[i + 1..];
                let Some(semi) = rest.find(';') else {
                    return Err("unterminated entity reference".to_string());
                };
                let pat = &rest[..semi];
                if let Some(num) = pat.strip_prefix('#') {
                    out.push(decode_char_ref(num)?);
                } else if let Some(value) = resolve_predefined_entity(pat) {
                    out.push_str(value);
                } else if let Some(value) = self.entities.get(pat).cloned() {
                    let (expanded, _) = self.expand_entities(&value, depth - 1)?;
                    added = added.saturating_add(expanded.len());
                    if added > MAX_ENTITY_EXPANSION_BYTES {
                        return Err("entity expansion too large".to_string());
                    }
                    out.push_str(&expanded);
                } else {
                    return Err(format!("undefined entity {pat:?}"));
                }
                i += 1 + semi + 1;
            } else {
                let ch = raw[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
        Ok((out, added))
    }

    /// Collect `<!ENTITY name "value">` declarations from the internal
    /// DTD subset. Parameter entities are skipped. Works on bytes
    /// throughout: name/value slices are only taken between ASCII
    /// delimiters (UTF-8 continuation bytes never match one) and the
    /// fallthrough steps over a whole character, so no index can land
    /// inside a multi-byte character.
    fn parse_doctype_entities(&mut self, inner: &str) {
        let bytes = inner.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i..].starts_with(b"<!--") {
                match inner[i..].find("-->") {
                    Some(end) => i += end + 3,
                    None => break,
                }
                continue;
            }
            if bytes[i..].starts_with(b"<!ENTITY") {
                i += "<!ENTITY".len();
                i = skip_ws(inner, i);
                if i < bytes.len() && bytes[i] == b'%' {
                    i = skip_decl(inner, i);
                    continue;
                }
                let start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                    i += 1;
                }
                let name = &inner[start..i];
                i = skip_ws(inner, i);
                if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                    let quote = bytes[i];
                    i += 1;
                    let vstart = i;
                    while i < bytes.len() && bytes[i] != quote {
                        i += 1;
                    }
                    let value = &inner[vstart..i];
                    if i < bytes.len() {
                        i += 1;
                    }
                    if !name.is_empty() {
                        self.entities.insert(name.to_string(), Rc::from(value));
                    }
                }
                continue;
            }
            i += inner[i..].chars().next().map_or(1, char::len_utf8);
        }
    }
}

/// Collect raw `(key, value)` attribute pairs from a start/empty tag.
fn collect_attrs(e: &quick_xml::events::BytesStart) -> Result<Vec<(String, String)>, String> {
    let mut attrs = Vec::new();
    for attr in e.attributes() {
        let attr = attr.map_err(|e| format!("XML parse error: {e}"))?;
        let key: &str = attr.key.as_ref();
        let value: &str = &attr.value;
        attrs.push((key.to_string(), value.to_string()));
    }
    Ok(attrs)
}

/// Push an `xmlns` declaration, rejecting a duplicate prefix in one tag.
fn push_decl(
    frame: &mut Vec<(Option<String>, String)>,
    prefix: Option<&str>,
    value: &str,
) -> Result<(), String> {
    if frame.iter().any(|(p, _)| p.as_deref() == prefix) {
        return Err("XML parse error: duplicate namespace declaration".to_string());
    }
    frame.push((prefix.map(str::to_string), value.to_string()));
    Ok(())
}

/// Split `prefix:local` on the first colon.
fn split_qname(qname: &str) -> (Option<&str>, &str) {
    match qname.find(':') {
        Some(i) => (Some(&qname[..i]), &qname[i + 1..]),
        None => (None, qname),
    }
}

/// Split PI content into `(target, data)`; the data's leading whitespace is
/// collapsed to the single separating space on emission.
fn split_pi(raw: &str) -> (String, String) {
    let mut parts = raw.splitn(2, [' ', '\t', '\n', '\r']);
    let target = parts.next().unwrap_or("").to_string();
    let data = parts.next().unwrap_or("").trim_start().to_string();
    (target, data)
}

fn emit_pi_bytes(out: &mut Vec<u8>, target: &str, data: &str) {
    out.extend_from_slice(b"<?");
    out.extend_from_slice(target.as_bytes());
    if !data.is_empty() {
        out.extend_from_slice(b" ");
        out.extend_from_slice(data.as_bytes());
    }
    out.extend_from_slice(b"?>");
}

/// XML line-ending normalization: CRLF and CR become LF.
fn eol_normalize(s: &str) -> String {
    if !s.contains('\r') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push('\n');
        } else {
            out.push(c);
        }
    }
    out
}

fn decode_char_ref(num: &str) -> Result<char, String> {
    // The `CharRef` production admits only decimal digits, or hex
    // digits after a lowercase `x`: check the digit class first,
    // because the integer parsers below also accept a leading `+`.
    let n = if let Some(hex) = num.strip_prefix('x') {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("invalid character reference &#{num};"));
        }
        u32::from_str_radix(hex, 16)
    } else {
        if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("invalid character reference &#{num};"));
        }
        num.parse::<u32>()
    }
    .map_err(|_| format!("invalid character reference &#{num};"))?;
    if !is_xml_char(n) {
        return Err(format!("invalid character reference &#{num};"));
    }
    char::from_u32(n).ok_or_else(|| format!("invalid character reference &#{num};"))
}

/// Whether `n` is in the XML `Char` production. Validation always uses
/// the XML 1.0 production, whatever version the document declares: the
/// reference parser (expat) applies the 1.0 `Char` rules even to XML 1.1
/// documents, so admitting the C0 controls other than tab, LF and CR for
/// a declared 1.1 document would diverge from it. NUL and the
/// non-characters U+FFFE and U+FFFF are excluded as well.
fn is_xml_char(n: u32) -> bool {
    matches!(
        n,
        0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
    )
}

/// Reject literal characters outside the XML `Char` production.
/// Character references are validated by `decode_char_ref`; literal text
/// and attribute values would otherwise reach the output unchecked,
/// where the reference parser rejects e.g. a literal vertical tab.
fn validate_xml_chars(s: &str) -> Result<(), String> {
    if let Some(c) = s.chars().find(|&c| !is_xml_char(c as u32)) {
        return Err(format!(
            "XML parse error: invalid character U+{:04X} in content",
            c as u32
        ));
    }
    Ok(())
}

fn escape_text(out: &mut Vec<u8>, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            _ => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

fn escape_attr(out: &mut Vec<u8>, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '"' => out.extend_from_slice(b"&quot;"),
            '\t' => out.extend_from_slice(b"&#x9;"),
            '\n' => out.extend_from_slice(b"&#xA;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            _ => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

/// Skip XML whitespace from `i`.
fn skip_ws(s: &str, mut i: usize) -> usize {
    while i < s.len() && matches!(s.as_bytes()[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// Skip one `<!...>` declaration, respecting quoted sections.
fn skip_decl(s: &str, mut i: usize) -> usize {
    let mut quote = None;
    while i < s.len() {
        let b = s.as_bytes()[i];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
        } else if b == b'"' || b == b'\'' {
            quote = Some(b);
        } else if b == b'>' {
            return i + 1;
        }
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(text: &str) -> Result<String, String> {
        Canonicalizer::new()
            .canonicalize(text)
            .map(|v| String::from_utf8(v).expect("canonical output is UTF-8"))
    }

    /// Internal subset where each entity holds ten references to the
    /// previous one, so `&lg;` amplifies the 10-byte seed by 10^7.
    fn laughs_doctype() -> String {
        let mut dtd = String::from("<!ENTITY lol \"0123456789\">");
        let names = ["lol", "la", "lb", "lc", "ld", "le", "lf", "lg"];
        for w in names.windows(2) {
            let body = format!("&{};", w[0]).repeat(10);
            dtd.push_str(&format!("<!ENTITY {} \"{}\">", w[1], body));
        }
        dtd
    }

    #[test]
    fn entity_expansion_is_capped() {
        let xml = format!(
            "<?xml version=\"1.0\"?><!DOCTYPE r [{}]><r>&lg;</r>",
            laughs_doctype()
        );
        let err = canon(&xml).expect_err("amplified expansion must be rejected");
        assert!(err.contains("too large"), "unexpected error: {err}");
    }

    #[test]
    fn entity_expansion_under_the_cap_still_works() {
        let xml = "<!DOCTYPE r [<!ENTITY base \"0123456789\">\
            <!ENTITY sub \"&base;&base;&base;&base;\">]><r>&sub;</r>";
        assert_eq!(
            canon(xml).unwrap(),
            "<r>0123456789012345678901234567890123456789</r>"
        );
    }

    #[test]
    fn legitimate_dtd_entities_expand_in_text_and_attributes() {
        // A dbus-style configuration file defining a path prefix once and
        // referencing it in both character data and an attribute value.
        let xml = "<!DOCTYPE busconfig [<!ENTITY share \"/usr/share/dbus-1\">]>\
            <busconfig><includedir>&share;/system.d</includedir>\
            <service dir=\"&share;/services\"/></busconfig>";
        let out = canon(xml).unwrap();
        assert!(out.contains("/usr/share/dbus-1/system.d"), "{out}");
        assert!(out.contains("dir=\"/usr/share/dbus-1/services\""), "{out}");
    }

    #[test]
    fn multiple_roots_are_rejected() {
        for xml in ["<a/><b/>", "<a></a><b></b>", "<a/> <b/>"] {
            let err = canon(xml).expect_err("a second root must be rejected");
            assert!(
                err.contains("junk after document element"),
                "{xml}: unexpected error: {err}"
            );
        }
    }

    #[test]
    fn content_outside_the_root_is_rejected() {
        assert!(canon("<a/>junk").is_err());
        assert!(canon("junk<a/>").is_err());
        // Whitespace, comments and PIs around the root stay legal.
        assert!(canon("  <a/> \n <!--c--> <?p d?> ").is_ok());
    }

    #[test]
    fn invalid_character_references_are_rejected() {
        for num in ["0", "x0", "xB", "x1F", "xFFFE", "xFFFF", "xD800", "x110000"] {
            let in_text = format!("<a>&#{num};</a>");
            assert!(canon(&in_text).is_err(), "{in_text} must be rejected");
            let in_attr = format!("<a x=\"&#{num};\"/>");
            assert!(canon(&in_attr).is_err(), "{in_attr} must be rejected");
        }
        // Reached through a general entity as well.
        let via_entity = "<!DOCTYPE a [<!ENTITY e \"&#x0;\">]><a>&e;</a>";
        assert!(canon(via_entity).is_err());
    }

    #[test]
    fn valid_character_references_still_decode() {
        assert_eq!(canon("<a>&#x41;&#65;</a>").unwrap(), "<a>AA</a>");
        assert_eq!(canon("<a>&#x1F600;</a>").unwrap(), "<a>\u{1F600}</a>");
        // A tab reference in an attribute value survives as `&#x9;`.
        assert_eq!(canon("<a x=\"&#x9;\"/>").unwrap(), "<a x=\"&#x9;\"></a>");
    }

    #[test]
    fn xml_1_1_control_references_are_rejected_like_the_reference() {
        // The reference (expat) applies the XML 1.0 `Char` production even
        // to documents declaring version 1.1, so C0 control references are
        // rejected there too, in text and in attributes alike.
        for num in ["x0", "xB", "x1F"] {
            let in_text = format!("<?xml version=\"1.1\"?><a>&#{num};</a>");
            assert!(canon(&in_text).is_err(), "{in_text} must be rejected");
            let in_attr = format!("<?xml version=\"1.1\"?><a x=\"&#{num};\"/>");
            assert!(canon(&in_attr).is_err(), "{in_attr} must be rejected");
        }
        // Ordinary references in a 1.1 document still decode.
        assert_eq!(
            canon("<?xml version=\"1.1\"?><a>&#x41;</a>").unwrap(),
            "<a>A</a>"
        );
    }

    #[test]
    fn flat_repeated_entity_references_are_capped() {
        // No nesting at all: one 8000-byte entity referenced 1300 times in
        // a row would produce 10,400,000 bytes. The outermost production
        // of each reference is charged, so the budget still bites.
        let entity = "A".repeat(8000);
        let refs = "&a;".repeat(1300);
        let in_text = format!("<!DOCTYPE r [<!ENTITY a \"{entity}\">]><r>{refs}</r>");
        let err = canon(&in_text).expect_err("flat repeated refs must be rejected");
        assert!(err.contains("too large"), "unexpected error: {err}");
        let in_attr = format!("<!DOCTYPE r [<!ENTITY a \"{entity}\">]><r x=\"{refs}\"/>");
        let err = canon(&in_attr).expect_err("flat repeated refs in an attribute must be rejected");
        assert!(err.contains("too large"), "unexpected error: {err}");
    }

    #[test]
    fn doctype_after_the_root_is_rejected() {
        for xml in [
            "<a/><!DOCTYPE x []>",
            "<a></a><!DOCTYPE x [<!ENTITY e \"v\">]>",
        ] {
            let err = canon(xml).expect_err("a post-root DOCTYPE must be rejected");
            assert!(
                err.contains("junk after document element"),
                "{xml}: unexpected error: {err}"
            );
        }
    }

    #[test]
    fn doctype_with_multibyte_characters_does_not_panic() {
        // Non-ASCII DOCTYPE name: the entity scanner steps over the
        // multi-byte `é` whole instead of slicing inside it.
        assert_eq!(canon("<!DOCTYPE café []><café/>").unwrap(), "<café></café>");
        // Multi-byte character in an ATTLIST default value.
        assert!(canon("<!DOCTYPE r [<!ATTLIST e a CDATA \"é\">]><r/>").is_ok());
        // A multi-byte entity value still expands.
        assert_eq!(
            canon("<!DOCTYPE r [<!ENTITY e \"café\">]><r>&e;</r>").unwrap(),
            "<r>café</r>"
        );
    }

    #[test]
    fn plain_attribute_text_is_not_charged_as_expansion() {
        // Over 8 MiB of entity-free attribute text expands nothing, so
        // the expansion budget must not reject it.
        let plain = "A".repeat(MAX_ENTITY_EXPANSION_BYTES + 1);
        let xml = format!("<r x=\"{plain}\"/>");
        assert!(canon(&xml).is_ok());
    }

    #[test]
    fn nested_entity_productions_are_charged_once() {
        // `b` produces 3 MiB via `a`; two references to `b` in one
        // attribute produce 6 MiB — under the cap when each production
        // is charged once, over it when nested productions are billed
        // again at every level.
        let seed = "A".repeat(3 * 1024 * 1024);
        let xml =
            format!("<!DOCTYPE r [<!ENTITY a \"{seed}\"><!ENTITY b \"&a;\">]><r x=\"&b;&b;\"/>");
        let out = canon(&xml).expect("singly-charged nested expansion must be accepted");
        assert_eq!(out.len(), "<r x=\"\"></r>".len() + 6 * 1024 * 1024);
    }

    #[test]
    fn second_doctype_in_the_prolog_is_rejected() {
        for xml in [
            "<!DOCTYPE a []><!DOCTYPE b []><r/>",
            "<!DOCTYPE a []><!DOCTYPE b [<!ENTITY e \"v\">]><r>&e;</r>",
        ] {
            let err = canon(xml).expect_err("a second DOCTYPE must be rejected");
            assert!(
                err.contains("multiple DOCTYPE"),
                "{xml}: unexpected error: {err}"
            );
        }
    }

    #[test]
    fn non_xml_whitespace_outside_the_root_is_rejected() {
        // Only XML whitespace may surround the root; a no-break space is
        // content, not whitespace, whatever Unicode trimming says.
        assert!(canon("\u{a0}<a/>").is_err());
        assert!(canon("<a/>\u{a0}").is_err());
        assert!(canon(" \t\r\n<a/> \n").is_ok());
    }

    #[test]
    fn plus_prefixed_character_references_are_rejected() {
        // The `CharRef` production allows only digits after `#` (or
        // hex digits after `#x`); a `+` sign is not part of either,
        // and the integer parsers used here would otherwise accept
        // one. Cf. `appdata.rs::has_undefined_entity`.
        for num in ["+65", "x+41"] {
            let in_text = format!("<a>&#{num};</a>");
            assert!(canon(&in_text).is_err(), "{in_text} must be rejected");
            let in_attr = format!("<a x=\"&#{num};\"/>");
            assert!(canon(&in_attr).is_err(), "{in_attr} must be rejected");
        }
    }

    #[test]
    fn whitespace_references_outside_the_root_are_rejected() {
        // A reference outside the root is judged by the event, not by
        // its expanded text: even a reference expanding to plain
        // whitespace is content there, where literal whitespace is
        // the only character data allowed.
        assert!(canon("&#32;<a/>").is_err());
        assert!(canon("<a/>&#x20;").is_err());
        let entity = "<!DOCTYPE a [<!ENTITY e \" \">]>";
        assert!(canon(&format!("{entity}&e;<a/>")).is_err());
        assert!(canon(&format!("{entity}<a/>&e;")).is_err());
        // Literal whitespace around the root stays legal, and a
        // whitespace reference inside the root still decodes.
        assert!(canon(" \t\r\n<a/> \n").is_ok());
        assert_eq!(canon("<a>x&#32;y</a>").unwrap(), "<a>x y</a>");
    }

    #[test]
    fn uppercase_x_character_references_are_rejected() {
        // The `CharRef` production spells the hex marker with a
        // lowercase `x` only; the reference rejects `&#X41;`.
        assert!(canon("<a>&#X41;</a>").is_err());
        assert!(canon("<a x=\"&#X41;\"/>").is_err());
    }

    #[test]
    fn literal_non_characters_are_rejected() {
        assert!(canon("<a>\u{b}</a>").is_err());
        assert!(canon("<a x=\"\u{b}\"/>").is_err());
        assert!(canon("<a>\u{fffe}</a>").is_err());
    }

    #[test]
    fn pre_root_entity_text_is_reported_as_before_the_root() {
        let xml = "<!DOCTYPE a [<!ENTITY e \"junk\">]>&e;<a/>";
        let err = canon(xml).expect_err("pre-root entity text must be rejected");
        assert!(
            err.contains("content before document element"),
            "unexpected error: {err}"
        );
    }
}
