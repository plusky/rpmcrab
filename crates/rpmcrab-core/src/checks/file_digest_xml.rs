//! C14N 1.0 canonicalization backing the `xml` file digester.
//!
//! Mirrors `xml.etree.ElementTree.canonicalize(from_file=...,
//! strip_text=True)` (the reference `XmlDigester.parse_content`): inclusive
//! C14N 1.0 over the whole document, comments and the XML declaration
//! dropped, whitespace-only text nodes removed except under in-scope
//! `xml:space="preserve"`, processing instructions kept.

use std::collections::HashMap;

use quick_xml::XmlVersion;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// The `xml` prefix is implicitly bound and never rendered as a declaration.
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

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
    entities: HashMap<String, String>,
    /// Processing instructions seen before the document element.
    prolog_pis: Vec<(String, String)>,
    /// Coalesced character data not yet emitted.
    pending_text: String,
    seen_root: bool,
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
            prolog_pis: Vec::new(),
            pending_text: String::new(),
            space_preserve: Vec::new(),
            seen_root: false,
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
                Event::DocType(e) => self.parse_doctype_entities(&e),
                // Comments neither emit nor break text coalescing.
                Event::Comment(_) => {}
                Event::PI(e) => self.emit_pi(&e),
                Event::GeneralRef(e) => self.push_ref(&e)?,
                Event::Start(e) => {
                    let name = e.name().as_ref().to_string();
                    let attrs = collect_attrs(&e)?;
                    self.flush_prolog_pis();
                    self.seen_root = true;
                    self.flush_text();
                    self.start_element(&name, &attrs, false)?;
                    self.depth += 1;
                }
                Event::Empty(e) => {
                    let name = e.name().as_ref().to_string();
                    let attrs = collect_attrs(&e)?;
                    self.flush_prolog_pis();
                    self.seen_root = true;
                    self.flush_text();
                    self.start_element(&name, &attrs, true)?;
                }
                Event::End(e) => {
                    let owned = e.name();
                    let name: &str = owned.as_ref();
                    self.flush_text();
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
        self.flush_text();
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
    /// in scope, which the reference keeps verbatim.
    fn flush_text(&mut self) {
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
    }

    /// Resolve one entity/character reference and append the result.
    /// Predefined and character references are terminal; general entities
    /// expand recursively.
    fn push_ref(&mut self, name: &str) -> Result<(), String> {
        if let Some(num) = name.strip_prefix('#') {
            self.pending_text.push(decode_char_ref(num)?);
        } else if let Some(value) = resolve_predefined_entity(name) {
            self.pending_text.push_str(value);
        } else if let Some(value) = self.entities.get(name).cloned() {
            let expanded = self.expand_entities(&value, 8)?;
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
    fn emit_pi(&mut self, raw: &str) {
        self.flush_text();
        let (target, data) = split_pi(raw);
        if !self.seen_root {
            self.prolog_pis.push((target, data));
        } else if self.depth == 0 {
            self.out.extend_from_slice(b"\n");
            emit_pi_bytes(&mut self.out, &target, &data);
        } else {
            emit_pi_bytes(&mut self.out, &target, &data);
        }
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
                let uri = self.expand_entities(value, 8)?;
                push_decl(&mut scope_frame, None, &uri)?;
            } else if let Some(p) = key.strip_prefix("xmlns:") {
                if p == "xml" {
                    return Err(
                        "XML parse error: reserved prefix (xml) must not be rebound".to_string()
                    );
                }
                let uri = self.expand_entities(value, 8)?;
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
            .map(|(_, value)| value.trim() == "preserve")
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
            let expanded = self.expand_entities(&normalized, 8)?;
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

    /// Expand predefined, character and internal-subset general entities in
    /// `raw`. Predefined/character references are terminal (their expansion
    /// is not rescanned); general entities expand recursively.
    fn expand_entities(&self, raw: &str, depth: u8) -> Result<String, String> {
        if depth == 0 {
            return Err("entity expansion too deep".to_string());
        }
        if !raw.contains('&') {
            return Ok(raw.to_string());
        }
        let mut out = String::with_capacity(raw.len());
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
                } else if let Some(value) = self.entities.get(pat) {
                    out.push_str(&self.expand_entities(value, depth - 1)?);
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
        Ok(out)
    }

    /// Collect `<!ENTITY name "value">` declarations from the internal
    /// DTD subset. Parameter entities are skipped.
    fn parse_doctype_entities(&mut self, inner: &str) {
        let mut i = 0;
        while i < inner.len() {
            if inner[i..].starts_with("<!--") {
                match inner[i..].find("-->") {
                    Some(end) => i += end + 3,
                    None => break,
                }
                continue;
            }
            if inner[i..].starts_with("<!ENTITY") {
                i += "<!ENTITY".len();
                i = skip_ws(inner, i);
                if inner[i..].starts_with('%') {
                    i = skip_decl(inner, i);
                    continue;
                }
                let start = i;
                while i < inner.len()
                    && !inner.as_bytes()[i].is_ascii_whitespace()
                    && inner.as_bytes()[i] != b'>'
                {
                    i += 1;
                }
                let name = &inner[start..i];
                i = skip_ws(inner, i);
                if i < inner.len() && (inner.as_bytes()[i] == b'"' || inner.as_bytes()[i] == b'\'')
                {
                    let quote = inner.as_bytes()[i];
                    i += 1;
                    let vstart = i;
                    while i < inner.len() && inner.as_bytes()[i] != quote {
                        i += 1;
                    }
                    let value = &inner[vstart..i];
                    if i < inner.len() {
                        i += 1;
                    }
                    if !name.is_empty() {
                        self.entities.insert(name.to_string(), value.to_string());
                    }
                }
                continue;
            }
            i += 1;
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
    let n = if let Some(hex) = num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
        u32::from_str_radix(hex, 16)
    } else {
        num.parse::<u32>()
    }
    .map_err(|_| format!("invalid character reference &#{num};"))?;
    char::from_u32(n).ok_or_else(|| format!("invalid character reference &#{num};"))
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
