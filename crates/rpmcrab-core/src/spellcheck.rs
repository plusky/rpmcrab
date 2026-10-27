//! Spellchecking via the `spellbook` crate (pure Rust, Hunspell-compatible).
//!
//! Mirrors rpmlint's `spellcheck.py`: loads the en_US dictionary from the
//! system hunspell paths, checks words in Summary/Description, and degrades
//! gracefully when the dictionary is absent. Package descriptions are
//! en_US text, so en_US is the only dictionary consulted and British
//! spellings are findings. One deliberate extension sits on top of the
//! system dictionary: the bundled supplementary vocabulary
//! (`data/spelling-wordlist.txt`) is added to it.

use std::path::Path;

use fancy_regex::Regex;
use std::sync::LazyLock;

/// Sentence-break: start-of-text or sentence-ending punctuation followed by
/// optional whitespace, tested against the up-to-3 chars preceding a word
/// (mirrors spellcheck.py:21).
static SENTENCE_BREAK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(^|[.:;!?])\s*$").expect("static regex"));

/// Standard hunspell dictionary locations.
const DICT_PATHS: &[&str] = &[
    "/usr/share/hunspell",
    "/usr/share/myspell",
    "/opt/homebrew/share/hunspell",
];

/// The bundled supplementary vocabulary, one entry per line (`#` lines
/// are comments); an entry may carry hunspell affix flags covering its
/// derivations. Added to the system dictionary at load: the words are
/// established vocabulary that package prose uses correctly and the
/// system dictionary lacks, so reporting them was noise.
const SUPPLEMENTARY_WORDS: &str = include_str!("../data/spelling-wordlist.txt");

/// Well-known generic TLDs, for recognising a bare host (no scheme) as
/// a URL. Country-code TLDs are absent on purpose: the reference checks
/// the labels of `example.co.uk`-style hosts individually, and file
/// extensions that collide with a country code (`readme.md`) stay
/// checked either way.
const URL_TLDS: &[&str] = &[
    "aero", "app", "asia", "biz", "com", "coop", "dev", "edu", "gov", "info", "int", "io", "jobs",
    "mil", "mobi", "museum", "name", "net", "org", "post", "pro", "tel", "travel", "xxx",
];

/// Environment variable that disables spellbook's ngram suggester when
/// set (any value), mirroring the presence-based
/// `CONFIG_DISABLE_AUTOLOADING` switch in config.rs. The ngram
/// suggester's candidate set depends on per-process hash state, so
/// suggestion membership is not reproducible across processes; the
/// test harness sets this so spelling output is deterministic under
/// test. Production runs leave it unset and keep the full ngram
/// suggestions.
const DISABLE_NGRAM_SUGGESTIONS_ENV: &str = "RPMCRAB_DISABLE_NGRAM_SUGGESTIONS";

/// The production default for the ngram suggester: on, unless
/// `DISABLE_NGRAM_SUGGESTIONS_ENV` is set.
fn ngram_suggestions_enabled() -> bool {
    std::env::var_os(DISABLE_NGRAM_SUGGESTIONS_ENV).is_none()
}

/// A spellchecker, or `None` if no dictionary was found.
pub struct Spellchecker {
    dict: spellbook::Dictionary<DictionaryBuildHasher>,
    /// Whether spellbook's ngram suggester contributes suggestions.
    /// On unless disabled (see `DISABLE_NGRAM_SUGGESTIONS_ENV`); the
    /// switch shapes suggestions only, never which words are flagged.
    ngram_suggestions: bool,
}

/// `BuildHasher` for the spellbook dictionary: FNV-1a over 64-bit
/// arithmetic only.
///
/// spellbook's ngram suggester scans the word list in hash-bucket
/// order and cuts tied candidates off in that order, so the kept
/// suggestions are a function of the dictionary's hash values. Those
/// values must be a pure function of the dictionary bytes on every
/// target: a randomly seeded hasher makes them depend on the process
/// seed, and `foldhash::fast`'s folded multiply computes a different
/// function on 32-bit targets than on 64-bit ones. FNV-1a uses only
/// XOR and wrapping `u64` multiplication, so its output — and with
/// it the scan order — is identical on 32- and 64-bit targets.
#[derive(Clone, Default)]
struct DictionaryBuildHasher;

/// FNV-1a hasher (see `DictionaryBuildHasher`).
struct Fnv1aHasher(u64);

impl std::hash::BuildHasher for DictionaryBuildHasher {
    type Hasher = Fnv1aHasher;

    fn build_hasher(&self) -> Fnv1aHasher {
        Fnv1aHasher(0xcbf2_9ce4_8422_2325)
    }
}

impl std::hash::Hasher for Fnv1aHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 ^= u64::from(byte);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    // The default integer writes serialise with the target's width
    // and endianness; funnel them through fixed-width little-endian
    // encodings so no hash input depends on the target.
    fn write_u8(&mut self, n: u8) {
        self.write(&[n]);
    }

    fn write_u16(&mut self, n: u16) {
        self.write(&n.to_le_bytes());
    }

    fn write_u32(&mut self, n: u32) {
        self.write(&n.to_le_bytes());
    }

    fn write_u64(&mut self, n: u64) {
        self.write(&n.to_le_bytes());
    }

    fn write_u128(&mut self, n: u128) {
        self.write(&n.to_le_bytes());
    }

    fn write_usize(&mut self, n: usize) {
        self.write_u64(n as u64);
    }

    fn write_i8(&mut self, n: i8) {
        self.write_u8(n as u8);
    }

    fn write_i16(&mut self, n: i16) {
        self.write(&n.to_le_bytes());
    }

    fn write_i32(&mut self, n: i32) {
        self.write(&n.to_le_bytes());
    }

    fn write_i64(&mut self, n: i64) {
        self.write(&n.to_le_bytes());
    }

    fn write_i128(&mut self, n: i128) {
        self.write(&n.to_le_bytes());
    }

    fn write_isize(&mut self, n: isize) {
        self.write_i64(n as i64);
    }
}

/// Build the dictionary with `DictionaryBuildHasher`, so the
/// suggester's scan order is a pure function of the dictionary bytes.
fn build_dictionary(
    aff: &str,
    dic: &str,
) -> Result<spellbook::Dictionary<DictionaryBuildHasher>, spellbook::ParseDictionaryError> {
    spellbook::Dictionary::new_with_hasher(aff, dic, DictionaryBuildHasher)
}

/// Load one language's dictionary from the standard paths.
fn load_dictionary(lang: &str) -> Option<spellbook::Dictionary<DictionaryBuildHasher>> {
    for dir in DICT_PATHS {
        let aff = Path::new(dir).join(format!("{lang}.aff"));
        let dic = Path::new(dir).join(format!("{lang}.dic"));
        let (Ok(aff_s), Ok(dic_s)) = (std::fs::read_to_string(&aff), std::fs::read_to_string(&dic))
        else {
            continue;
        };
        if let Ok(dict) = build_dictionary(&aff_s, &dic_s) {
            return Some(dict);
        }
    }
    None
}

/// Add the bundled supplementary vocabulary to `dict`. An entry the
/// dictionary's affix parser rejects is skipped: the bundled list is
/// pinned by a unit test, so a bad entry fails the test suite, never
/// a user run.
fn add_supplementary_words(dict: &mut spellbook::Dictionary<DictionaryBuildHasher>) {
    for line in SUPPLEMENTARY_WORDS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let _ = dict.add(line);
    }
}

impl Spellchecker {
    /// Try to load the en_US dictionary from standard paths.
    /// Returns `None` if not found (graceful degradation).
    pub fn new() -> Option<Self> {
        let mut dict = load_dictionary("en_US")?;
        add_supplementary_words(&mut dict);
        Some(Self {
            dict,
            ngram_suggestions: ngram_suggestions_enabled(),
        })
    }

    /// Build from inline dictionary strings (for tests). Defaults to
    /// production behaviour (ngram suggester on).
    #[cfg(test)]
    pub(crate) fn from_strings(aff: &str, dic: &str) -> Option<Self> {
        build_dictionary(aff, dic).ok().map(|dict| Self {
            dict,
            ngram_suggestions: true,
        })
    }

    /// Add the bundled supplementary vocabulary (for tests: `new()` is
    /// the only production caller).
    #[cfg(test)]
    pub(crate) fn with_supplementary_words(mut self) -> Self {
        add_supplementary_words(&mut self.dict);
        self
    }

    /// Whether the dictionary accepts the word.
    fn accepts(&self, word: &str) -> bool {
        self.dict.check(word)
    }

    /// Override the ngram-suggester switch (for tests).
    #[cfg(test)]
    pub(crate) fn with_ngram_suggestions(mut self, enabled: bool) -> Self {
        self.ngram_suggestions = enabled;
        self
    }

    /// Check text for misspellings, returning (word, suggestions) pairs.
    /// Mirrors the reference's filtering: skips emails, URLs, WikiWords,
    /// capitalized words not at sentence start, all-uppercase words,
    /// ignored words, and package name matches.
    pub fn check(
        &self,
        text: &str,
        pkg_name: &str,
        ignored_words: &[String],
    ) -> Vec<(String, Vec<String>)> {
        let mut result = Vec::new();
        let mut warned = std::collections::HashSet::new();

        // Normalize whitespace like the reference.
        let normalized: String = text.split_whitespace().collect::<Vec<_>>().join(" ");

        let upper_name = pkg_name.to_uppercase();
        let upper_parts: Vec<String> = upper_name.split('-').map(str::to_string).collect();
        let ignored_upper: Vec<String> = ignored_words.iter().map(|w| w.to_uppercase()).collect();

        // Simple word tokenizer with positions for sentence-break detection.
        let words = tokenize(&normalized);

        // Spans the reference never checks: its checker filters URLs
        // and email addresses out before checking (spellcheck.py's
        // URLFilter and EmailFilter), so their words are not findings.
        let spans = skippable_spans(&normalized);

        for (word, byte_offset) in words.iter() {
            if warned.contains(*word) {
                continue;
            }

            // Skip words inside a URL or email address, and WikiWords
            // (CamelCase).
            let word_end = *byte_offset + word.len();
            if spans
                .iter()
                .any(|(s, e)| *byte_offset < *e && *s < word_end)
                || is_wiki_word(word)
            {
                continue;
            }

            // Skip words with digits adjacent (reference digit tokenizing workaround).
            if has_digit_adjacent(&normalized, *byte_offset, word_end) {
                continue;
            }

            if self.accepts(word) {
                continue;
            }
            warned.insert(word.to_string());

            // Skip capitalized words not at sentence start.
            if starts_uppercase(word) && !at_sentence_start(&normalized, *byte_offset) {
                continue;
            }

            // Skip all-uppercase words.
            let upper = word.to_uppercase();
            if *word == upper {
                continue;
            }

            // Skip ignored words.
            if ignored_upper.iter().any(|w| w == &upper) {
                continue;
            }

            // Skip package name matches. The possessive of a name part
            // is a match too ("django's" for the django package): the
            // reference adds each part's possessive to its skip list.
            let bare = upper.strip_suffix("'S").unwrap_or(&upper);
            if upper_name.contains(&upper) || upper_parts.iter().any(|p| p == &upper || p == bare) {
                continue;
            }

            let mut suggestions = Vec::new();
            if self.ngram_suggestions {
                // The production path, exactly as before the switch
                // existed: spellbook's default suggester, ngram
                // candidates included.
                self.dict.suggest(word, &mut suggestions);
            } else {
                // Test-only path: drop the ngram candidates, whose
                // set membership is not reproducible across processes.
                self.dict
                    .suggester()
                    .with_ngram_suggestions(false)
                    .suggest(word, &mut suggestions);
            }
            // Sort before truncating so the kept suggestions are in a
            // canonical order.
            suggestions.sort();
            suggestions.truncate(3);
            result.push((word.to_string(), suggestions));
        }

        result
    }
}

/// Split text into (word, byte_offset) pairs, keeping only alphabetic
/// sequences with apostrophes. Apostrophes at a token's edges are
/// quoting, not part of the word, and are trimmed (the reference's
/// tokenizer does the same); an all-apostrophe run yields no token.
fn tokenize(text: &str) -> Vec<(&str, usize)> {
    let mut words = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        if c.is_alphabetic() || c == '\'' {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            push_token(&mut words, text, s, i);
            start = None;
        }
    }
    if let Some(s) = start {
        push_token(&mut words, text, s, text.len());
    }
    words
}

fn push_token<'a>(words: &mut Vec<(&'a str, usize)>, text: &'a str, start: usize, end: usize) {
    let raw = &text[start..end];
    let trimmed = raw.trim_matches('\'');
    if trimmed.is_empty() {
        return;
    }
    let offset = start + (raw.len() - raw.trim_start_matches('\'').len());
    words.push((trimmed, offset));
}

/// Byte spans of the whitespace-normalized text that hold a URL or an
/// email address.
fn skippable_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        if c == ' ' {
            if let Some(s) = start.take()
                && is_skippable_chunk(&text[s..i])
            {
                spans.push((s, i));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start
        && is_skippable_chunk(&text[s..])
    {
        spans.push((s, text.len()));
    }
    spans
}

/// Whether one whitespace-delimited chunk is a URL or an email
/// address: a scheme URL, a `www.` host, an address with a dotted
/// domain part, or a bare host whose last label is a well-known TLD —
/// each optionally followed by a port, a path, a query or a fragment.
fn is_skippable_chunk(chunk: &str) -> bool {
    let chunk = chunk.trim_matches(|c: char| !(c.is_alphanumeric() || "@.:/_-+%~#?=&".contains(c)));
    if chunk.contains("://") {
        return true;
    }
    if chunk.to_lowercase().starts_with("www.") {
        return true;
    }
    if let Some((_, domain)) = chunk.split_once('@') {
        return domain.contains('.');
    }
    let host = chunk.split('/').next().unwrap_or("");
    // The host part ends at a port, a query or a fragment, and a
    // trailing dot belongs to the written form, not to the last label.
    let host = host.split([':', '?', '#']).next().unwrap_or("");
    let host = host.trim_end_matches('.');
    match host.rsplit_once('.') {
        Some((_, tld)) => URL_TLDS.contains(&tld.to_lowercase().as_str()),
        None => false,
    }
}

/// Whether `lang` (an entry of the header i18n table) is checked
/// against the en_US dictionary: the `C` locale and English strings.
/// Any other language is not checked at all — the reference consults
/// a dictionary for the text's own language and stays silent when it
/// has none, while this checker holds only en_US, so checking a
/// translation against it flags ordinary prose wholesale.
pub fn spellcheckable_language(lang: &str) -> bool {
    lang == "C" || lang.starts_with("C.") || lang.starts_with("en")
}

fn is_wiki_word(word: &str) -> bool {
    // CamelCase: an uppercase letter after the first character
    // (e.g. "HelloWorld"), not just a leading capital like "Wrld".
    word.chars().skip(1).any(|c| c.is_uppercase())
}

fn starts_uppercase(word: &str) -> bool {
    word.chars().next().is_some_and(|c| c.is_uppercase())
}

fn at_sentence_start(text: &str, byte_offset: usize) -> bool {
    // Take the up-to-3 characters preceding the word, mirroring
    // `checker.leading_context(3)` in spellcheck.py:99, and test against
    // the sentence-break rule from spellcheck.py:21.
    let mut start = byte_offset.saturating_sub(3);
    while start < byte_offset && !text.is_char_boundary(start) {
        start += 1;
    }
    let context = &text[start..byte_offset];
    SENTENCE_BREAK_RE.is_match(context).unwrap_or(false)
}

/// Whether the character immediately before or after a token's span
/// is a digit. The tokenizer splits on digits, so `utf8` yields the
/// token `utf` and `20th` the token `th`; neither fragment is a word
/// anyone wrote, and the reference skips an error whose leading or
/// trailing context is a digit for exactly this reason.
fn has_digit_adjacent(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    before.is_some_and(|c| c.is_ascii_digit()) || after.is_some_and(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_AFF: &str = "SET UTF-8\n";

    /// The pinned en_US affix rules for the flags the bundled wordlist
    /// uses (S, D, G, M, N, P, R, Y, Z), copied from the pinned
    /// dictionary's .aff so flagged entries parse and derive in tests
    /// exactly as in production.
    const TEST_AFF_WITH_AFFIXES: &str = "SET UTF-8\n\
SFX S Y 4\n\
SFX S y ies [^aeiou]y\n\
SFX S 0 s [aeiou]y\n\
SFX S 0 es [sxzh]\n\
SFX S 0 s [^sxzhy]\n\
SFX D Y 4\n\
SFX D 0 d e\n\
SFX D y ied [^aeiou]y\n\
SFX D 0 ed [^ey]\n\
SFX D 0 ed [aeiou]y\n\
SFX G Y 2\n\
SFX G e ing e\n\
SFX G 0 ing [^e]\n\
SFX R Y 4\n\
SFX R 0 r e\n\
SFX R y ier [^aeiou]y\n\
SFX R 0 er [aeiou]y\n\
SFX R 0 er [^ey]\n\
SFX Z Y 4\n\
SFX Z 0 rs e\n\
SFX Z y iers [^aeiou]y\n\
SFX Z 0 ers [aeiou]y\n\
SFX Z 0 ers [^ey]\n\
SFX Y Y 1\n\
SFX Y 0 ly .\n\
SFX P Y 3\n\
SFX P y iness [^aeiou]y\n\
SFX P 0 ness [aeiou]y\n\
SFX P 0 ness [^y]\n\
SFX M Y 1\n\
SFX M 0 's .\n\
SFX N Y 3\n\
SFX N e ion e\n\
SFX N y ication y\n\
SFX N 0 en [^ey]\n";
    const TEST_DIC: &str = "5\nhello\nworld\ntest\npackage\ncheck\n";

    fn test_checker() -> Spellchecker {
        Spellchecker::from_strings(TEST_AFF, TEST_DIC).expect("test dictionary")
    }

    #[test]
    fn misspelled_word_is_reported() {
        let checker = test_checker();
        let result = checker.check("hello wrld", "testpkg", &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "wrld");
    }

    #[test]
    fn correct_words_pass() {
        let checker = test_checker();
        let result = checker.check("hello world", "testpkg", &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn wikiword_skipped() {
        let checker = test_checker();
        let result = checker.check("HelloWorld", "testpkg", &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn all_uppercase_skipped() {
        let checker = test_checker();
        let result = checker.check("WRLD", "testpkg", &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn ignored_words_skipped() {
        let checker = test_checker();
        let ignored = vec!["wrld".to_string()];
        let result = checker.check("hello wrld", "testpkg", &ignored);
        assert!(result.is_empty());
    }

    #[test]
    fn package_name_skipped() {
        let checker = test_checker();
        let result = checker.check("mypackage", "mypackage", &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn repeated_word_reported_once() {
        let checker = test_checker();
        let result = checker.check("wrld wrld wrld", "testpkg", &[]);
        assert_eq!(result.len(), 1);
    }

    /// The synthetic dictionary for the suggestion pins: every
    /// distinct permutation of "preun" and of "preun" with one doubled
    /// letter, plus "preen" — a dense neighbourhood of tied candidates
    /// around the probes.
    fn preun_neighbourhood_dic() -> String {
        fn next_permutation(v: &mut [char]) -> bool {
            let n = v.len();
            if n < 2 {
                return false;
            }
            let mut i = n - 2;
            loop {
                if v[i] < v[i + 1] {
                    break;
                }
                if i == 0 {
                    return false;
                }
                i -= 1;
            }
            let mut j = n - 1;
            while v[j] <= v[i] {
                j -= 1;
            }
            v.swap(i, j);
            v[i + 1..].reverse();
            true
        }

        let mut stems: Vec<String> = vec!["preen".to_string()];
        let base: Vec<char> = "preun".chars().collect();
        let mut v = base.clone();
        v.sort_unstable();
        loop {
            stems.push(v.iter().collect());
            if !next_permutation(&mut v) {
                break;
            }
        }
        for d in base {
            let mut v: Vec<char> = "preun".chars().collect();
            v.push(d);
            v.sort_unstable();
            loop {
                stems.push(v.iter().collect());
                if !next_permutation(&mut v) {
                    break;
                }
            }
        }
        stems.sort();
        stems.dedup();
        let mut dic = format!("{}\n", stems.len());
        for stem in &stems {
            dic.push_str(stem);
            dic.push('\n');
        }
        dic
    }

    #[test]
    fn suggestions_are_identical_across_checker_instances() {
        // The word list in `preun_neighbourhood_dic` concentrates stems
        // in the probes' letter neighbourhood, so spellbook's ngram
        // suggester faces large sets of tied candidates at its internal
        // cut-offs. Checker instances built from identical dictionary
        // bytes must still keep identical suggestions: with a randomly
        // seeded dictionary hasher they do not, because the suggester
        // scans the word list in per-process hash order.
        let dic = preun_neighbourhood_dic();

        let probes = ["preum", "prenux", "preunx", "prenuq", "preuq", "preunm"];
        let first = Spellchecker::from_strings(TEST_AFF, &dic).expect("synthetic dictionary");
        let expected: Vec<Vec<(String, Vec<String>)>> = probes
            .iter()
            .map(|probe| first.check(probe, "testpkg", &[]))
            .collect();
        assert!(
            expected.iter().any(|result| !result.is_empty()),
            "probes must yield suggestions for the comparison to mean anything"
        );
        // Pin two probes' concrete output as well: a suggester that
        // degenerated would still agree with itself across instances.
        assert_eq!(
            expected[0],
            vec![("preum".to_string(), vec!["preune".to_string()])],
            "concrete suggestions for preum changed"
        );
        assert_eq!(
            expected[2],
            vec![(
                "preunx".to_string(),
                vec![
                    "preeun".to_string(),
                    "preun".to_string(),
                    "preuun".to_string()
                ]
            )],
            "concrete suggestions for preunx changed"
        );
        for _ in 0..16 {
            let checker = Spellchecker::from_strings(TEST_AFF, &dic).expect("synthetic dictionary");
            for (probe, want) in probes.iter().zip(&expected) {
                assert_eq!(
                    &checker.check(probe, "testpkg", &[]),
                    want,
                    "suggestions for {probe} differ between checker instances"
                );
            }
        }
    }

    #[test]
    fn ngram_suggestions_are_on_by_default() {
        // The production configuration: the ngram suggester
        // contributes suggestions. Both constructors default to on;
        // `Spellchecker::new` additionally honours
        // RPMCRAB_DISABLE_NGRAM_SUGGESTIONS, pinned by
        // `new_env_switch_tracks_the_disable_variable` below.
        assert!(test_checker().ngram_suggestions);
        let synthetic = Spellchecker::from_strings(TEST_AFF, &preun_neighbourhood_dic())
            .expect("synthetic dictionary");
        assert!(synthetic.ngram_suggestions);
    }

    #[test]
    fn ngram_disabled_suggestions_are_the_deterministic_edit_set() {
        let dic = preun_neighbourhood_dic();
        let probes = ["preum", "prenux", "preunx", "prenuq", "preuq", "preunm"];
        let checker = Spellchecker::from_strings(TEST_AFF, &dic)
            .expect("synthetic dictionary")
            .with_ngram_suggestions(false);
        assert!(!checker.ngram_suggestions);
        let expected: Vec<Vec<(String, Vec<String>)>> = probes
            .iter()
            .map(|probe| checker.check(probe, "testpkg", &[]))
            .collect();
        assert!(
            expected.iter().any(|result| !result.is_empty()),
            "probes must yield suggestions for the comparison to mean anything"
        );
        // Concrete pins for the edit-only sets. With the ngram
        // suggester on, "preum" additionally gains "preune" and
        // "preunx" gains "preeun"/"preuun" (the cross-instance test
        // above pins those); off, only the candidates the edit
        // generators reach remain, and that set is reproducible.
        assert_eq!(
            expected[0],
            vec![("preum".to_string(), Vec::<String>::new())],
            "ngram-disabled suggestions for preum changed"
        );
        assert_eq!(
            expected[1],
            vec![("prenux".to_string(), vec!["prenu".to_string()])],
            "ngram-disabled suggestions for prenux changed"
        );
        assert_eq!(
            expected[2],
            vec![("preunx".to_string(), vec!["preun".to_string()])],
            "ngram-disabled suggestions for preunx changed"
        );
        assert_eq!(
            expected[3],
            vec![("prenuq".to_string(), vec!["prenu".to_string()])],
            "ngram-disabled suggestions for prenuq changed"
        );
        assert_eq!(
            expected[4],
            vec![("preuq".to_string(), Vec::<String>::new())],
            "ngram-disabled suggestions for preuq changed"
        );
        assert_eq!(
            expected[5],
            vec![("preunm".to_string(), vec!["preun".to_string()])],
            "ngram-disabled suggestions for preunm changed"
        );
        // Reproducibility of this edit set across processes is pinned
        // by `ngram_disabled_suggestions_are_identical_across_processes`
        // below: instances in one process share the per-process state
        // issue #688 is about, so same-process agreement proves nothing.
        // The switch shapes suggestions only: the flagged words are
        // identical with the ngram suggester on or off.
        let on = Spellchecker::from_strings(TEST_AFF, &dic)
            .expect("synthetic dictionary")
            .with_ngram_suggestions(true);
        for (probe, off_result) in probes.iter().zip(&expected) {
            let on_result = on.check(probe, "testpkg", &[]);
            let on_words: Vec<&str> = on_result.iter().map(|(w, _)| w.as_str()).collect();
            let off_words: Vec<&str> = off_result.iter().map(|(w, _)| w.as_str()).collect();
            assert_eq!(
                on_words, off_words,
                "flagged words for {probe} must not depend on the ngram switch"
            );
        }
    }

    #[test]
    fn invalid_dictionary_returns_none() {
        let result = Spellchecker::from_strings("invalid", "invalid");
        assert!(result.is_none());
    }

    #[test]
    fn capitalized_misspelling_at_sentence_start_is_reported() {
        // "Wrld" is capitalized and at the start: must be reported.
        // Fails against the stub (which always returned false).
        let checker = test_checker();
        let result = checker.check("Wrld hello", "testpkg", &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "Wrld");
    }

    #[test]
    fn capitalized_misspelling_after_period_is_reported() {
        // "Wrld" follows ". ": at sentence start, must be reported.
        let checker = test_checker();
        let result = checker.check("hello world. Wrld test", "testpkg", &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "Wrld");
    }

    #[test]
    fn capitalized_misspelling_mid_sentence_is_skipped() {
        // "Wrld" is capitalized but mid-sentence: must be skipped
        // (reference treats it as a proper noun).
        let checker = test_checker();
        let result = checker.check("hello Wrld test", "testpkg", &[]);
        assert!(result.is_empty());
    }

    /// Render check results on one line: `word:sugg,sugg` entries
    /// joined by spaces (an empty string when nothing was flagged).
    fn format_check_results(results: &[(String, Vec<String>)]) -> String {
        results
            .iter()
            .map(|(word, suggestions)| format!("{word}:{}", suggestions.join(",")))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Marker that turns `ngram_disabled_child_dump` from a no-op
    /// (when the suite runs it directly) into the child half of the
    /// cross-process determinism pin.
    const NGRAM_DUMP_CHILD_ENV: &str = "RPMCRAB_TEST_NGRAM_DUMP_CHILD";

    /// Child half of the cross-process pin: prints the ngram-disabled
    /// probe results, one `PROBE` line per probe, for the parent test
    /// to compare across two spawned processes. Does nothing unless
    /// spawned by the parent with `NGRAM_DUMP_CHILD_ENV` set.
    #[test]
    fn ngram_disabled_child_dump() {
        if std::env::var_os(NGRAM_DUMP_CHILD_ENV).is_none() {
            return;
        }
        let checker = Spellchecker::from_strings(TEST_AFF, &preun_neighbourhood_dic())
            .expect("synthetic dictionary")
            .with_ngram_suggestions(false);
        for probe in ["preum", "prenux", "preunx", "prenuq", "preuq", "preunm"] {
            println!(
                "PROBE {}",
                format_check_results(&checker.check(probe, "testpkg", &[]))
            );
        }
    }

    #[test]
    fn ngram_disabled_suggestions_are_identical_across_processes() {
        // Issue #688 is per-process hash state: checker instances in
        // one process can agree while separate processes diverge, so
        // the in-process agreement loops cannot pin reproducibility.
        // Run the ngram-disabled checker in two fresh processes and
        // pin that their probe output is identical — and identical to
        // the in-process edit set.
        let probes = ["preum", "prenux", "preunx", "prenuq", "preuq", "preunm"];
        let checker = Spellchecker::from_strings(TEST_AFF, &preun_neighbourhood_dic())
            .expect("synthetic dictionary")
            .with_ngram_suggestions(false);
        let expected: Vec<String> = probes
            .iter()
            .map(|probe| format_check_results(&checker.check(probe, "testpkg", &[])))
            .collect();

        let exe = std::env::current_exe().expect("test binary path");
        let dump = || -> Vec<String> {
            let out = std::process::Command::new(&exe)
                .args(["ngram_disabled_child_dump", "--nocapture"])
                .env(NGRAM_DUMP_CHILD_ENV, "1")
                .output()
                .expect("spawn child test process");
            assert!(
                out.status.success(),
                "child dump failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|line| line.strip_prefix("PROBE ").map(str::to_string))
                .collect()
        };
        let first = dump();
        assert_eq!(
            first.len(),
            probes.len(),
            "child must dump every probe: {first:?}"
        );
        let second = dump();
        assert_eq!(
            first, second,
            "ngram-disabled suggestions differ across processes"
        );
        assert_eq!(
            first, expected,
            "child processes disagree with the in-process edit set"
        );
    }

    #[test]
    fn dictionary_hasher_output_is_target_independent() {
        // FNV-1a over fixed encodings: these constants hold on every
        // target because the implementation uses only u64 wrapping
        // arithmetic (see DictionaryBuildHasher). A hasher whose
        // output depends on the target's pointer width — foldhash's
        // folded multiply — cannot satisfy them on both widths.
        use std::hash::BuildHasher;
        assert_eq!(
            DictionaryBuildHasher.hash_one("preun"),
            0x60a9_adb5_d0dc_7fee
        );
        assert_eq!(
            DictionaryBuildHasher.hash_one(42usize),
            0xff3a_dd6b_3789_daef
        );
    }

    /// Marker that turns `new_env_switch_child` from a no-op (when
    /// the suite runs it directly) into the child half of the
    /// env-switch pin.
    const NEW_ENV_SWITCH_CHILD_ENV: &str = "RPMCRAB_TEST_NEW_ENV_SWITCH_CHILD";

    /// Child half of the env-switch pin: asserts, in a fresh process,
    /// that the ngram switch state tracks
    /// `RPMCRAB_DISABLE_NGRAM_SUGGESTIONS`. The switch function is
    /// asserted unconditionally; where a system dictionary is
    /// installed (CI installs the pinned pair), `Spellchecker::new`'s
    /// wiring of the switch into the checker is asserted as well.
    /// Does nothing unless spawned by the parent with
    /// `NEW_ENV_SWITCH_CHILD_ENV` set.
    #[test]
    fn new_env_switch_child() {
        if std::env::var_os(NEW_ENV_SWITCH_CHILD_ENV).is_none() {
            return;
        }
        // The literal name, not the constant: the name is the
        // contract the binary harness sets, and reading it through
        // the constant here would let a typo in the constant pass.
        let disabled = std::env::var_os("RPMCRAB_DISABLE_NGRAM_SUGGESTIONS").is_some();
        assert_eq!(
            ngram_suggestions_enabled(),
            !disabled,
            "the ngram switch must track {DISABLE_NGRAM_SUGGESTIONS_ENV}"
        );
        if let Some(checker) = Spellchecker::new() {
            assert_eq!(
                checker.ngram_suggestions, !disabled,
                "Spellchecker::new must carry the env switch into the checker"
            );
            println!("ENV_SWITCH=full");
        } else {
            println!("ENV_SWITCH=function-only");
        }
    }

    #[test]
    fn new_env_switch_tracks_the_disable_variable() {
        // The env switch behind `Spellchecker::new` was untested: an
        // inverted condition or a typo in the variable name would have
        // passed silently. Mutating the variable in-process would race
        // parallel tests, so both branches run in spawned child
        // processes — variable removed, then variable set.
        let exe = std::env::current_exe().expect("test binary path");
        for disabled in [false, true] {
            let mut cmd = std::process::Command::new(&exe);
            cmd.args(["new_env_switch_child", "--nocapture"])
                .env(NEW_ENV_SWITCH_CHILD_ENV, "1");
            if disabled {
                cmd.env("RPMCRAB_DISABLE_NGRAM_SUGGESTIONS", "1");
            } else {
                cmd.env_remove("RPMCRAB_DISABLE_NGRAM_SUGGESTIONS");
            }
            let out = cmd.output().expect("spawn child test process");
            assert!(
                out.status.success(),
                "env-switch child (disabled={disabled}) failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                String::from_utf8_lossy(&out.stdout).contains("ENV_SWITCH="),
                "child must report its mode (disabled={disabled})"
            );
        }
    }

    #[test]
    fn url_and_email_words_are_not_checked() {
        // The reference filters URLs and email addresses out before
        // checking; none of their parts are findings.
        let checker = test_checker();
        let text = "hello https://qwargl.example.com/x www.qwargl.org test \
                    bob@qwargl.net package docs.qwargl.io/en check";
        assert!(checker.check(text, "testpkg", &[]).is_empty());
        // The same word outside a URL is still reported.
        let result = checker.check("hello qwargl world", "testpkg", &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "qwargl");
    }

    #[test]
    fn bare_hosts_with_port_query_fragment_or_trailing_dot_are_skipped() {
        // The host rule reads the last label as the TLD: a trailing
        // dot, a port, a query or a fragment after the host does not
        // defeat it (issue #941).
        let checker = test_checker();
        let text = "hello docs.qwargl.io. docs.qwargl.io:8080 docs.qwargl.io?x=1 \
                    docs.qwargl.io#part docs.qwargl.io:8080/en check";
        assert!(checker.check(text, "testpkg", &[]).is_empty());
    }

    #[test]
    fn dotted_filenames_are_still_checked() {
        // Only hosts are skipped: a dotted file name's parts are
        // checked, like the reference checks them.
        let checker = test_checker();
        let result = checker.check("test qwargl.toml check", "testpkg", &[]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "qwargl");
        assert_eq!(result[1].0, "toml");
    }

    #[test]
    fn quoted_words_are_checked_without_their_quotes() {
        let checker = test_checker();
        let result = checker.check("hello 'wrld' world", "testpkg", &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "wrld");
        let result = checker.check("hello wrld' world", "testpkg", &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "wrld");
    }

    #[test]
    fn supplementary_words_are_accepted() {
        // The bundled wordlist is production vocabulary: with it, the
        // words package prose uses correctly stop being findings.
        let checker = test_checker().with_supplementary_words();
        assert!(
            checker
                .check("hello backend world", "testpkg", &[])
                .is_empty()
        );
        assert!(
            checker
                .check("hello subpackage world", "testpkg", &[])
                .is_empty()
        );
        // Sentence-initial capitalised form of a listed word.
        assert!(
            checker
                .check("Backend hello world", "testpkg", &[])
                .is_empty()
        );
        // A word the list does not carry is still reported.
        let result = checker.check("hello wrld", "testpkg", &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "wrld");
    }

    #[test]
    fn every_supplementary_word_parses_and_is_accepted() {
        // Pins the bundled file: every entry must parse as a dictionary
        // line and its stem must be accepted once added (a typo'd entry
        // would silently do nothing in production). Flagged entries
        // resolve against the affix rules of the dictionary they join,
        // so this checker carries the pinned en_US rules for the flags
        // the list uses.
        let mut checker =
            Spellchecker::from_strings(TEST_AFF_WITH_AFFIXES, TEST_DIC).expect("test dictionary");
        for line in SUPPLEMENTARY_WORDS.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            assert!(
                checker.dict.add(line).is_ok(),
                "supplementary entry {line:?} does not parse"
            );
            let stem = line.split('/').next().unwrap_or(line);
            assert!(
                checker.accepts(stem),
                "supplementary entry {line:?} not accepted"
            );
        }
    }

    #[test]
    fn supplementary_affix_flags_cover_derivations() {
        // One flagged entry covers its regular derivations, so the
        // bundled list names stems rather than every written form.
        let checker = Spellchecker::from_strings(TEST_AFF_WITH_AFFIXES, TEST_DIC)
            .expect("test dictionary")
            .with_supplementary_words();
        for word in [
            "backends",       // backend + S
            "filesystems",    // filesystem + S
            "deserialized",   // deserialize + D
            "deserializing",  // deserialize + G
            "deduplication",  // deduplicate + N
            "autocompletion", // autocomplete + N
            "namespaces",     // namespace + S
            "scriptlets",     // scriptlet + S
        ] {
            assert!(checker.accepts(word), "derivation {word:?} not accepted");
        }
        // The flags grant the paradigms of the listed stems only:
        // British spellings and genuine misspellings stay findings.
        for word in [
            "behaviour",
            "deserialise",
            "analyse",
            "labelling",
            "adaptor",
            "informations",
            "libary",
        ] {
            assert!(!checker.accepts(word), "word {word:?} must stay flagged");
        }
    }

    #[test]
    fn british_spelling_is_flagged() {
        // Package descriptions are en_US text: a British spelling is a
        // finding (the tags check reports spelling findings at warning
        // level), so packagers fix the prose to en_US. The checker
        // carries the supplementary vocabulary, so this also pins that
        // the wordlist does not accept British spellings.
        let checker = test_checker().with_supplementary_words();
        for word in ["behaviour", "analyse", "labelling", "adaptor"] {
            let text = format!("hello {word} world");
            let result = checker.check(&text, "testpkg", &[]);
            assert_eq!(result.len(), 1, "word {word:?}: {result:?}");
            assert_eq!(result[0].0, word);
        }
    }
}
