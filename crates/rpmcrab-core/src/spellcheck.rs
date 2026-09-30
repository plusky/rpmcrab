//! Spellchecking via the `spellbook` crate (pure Rust, Hunspell-compatible).
//!
//! Mirrors rpmlint's `spellcheck.py`: loads the en_US dictionary from the
//! system hunspell paths, checks words in Summary/Description, and degrades
//! gracefully when the dictionary is absent.

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

/// A spellchecker, or `None` if no dictionary was found.
pub struct Spellchecker {
    dict: spellbook::Dictionary,
}

impl Spellchecker {
    /// Try to load the en_US dictionary from standard paths.
    /// Returns `None` if not found (graceful degradation).
    pub fn new() -> Option<Self> {
        for dir in DICT_PATHS {
            let aff = Path::new(dir).join("en_US.aff");
            let dic = Path::new(dir).join("en_US.dic");
            let (Ok(aff_s), Ok(dic_s)) =
                (std::fs::read_to_string(&aff), std::fs::read_to_string(&dic))
            else {
                continue;
            };
            if let Ok(dict) = spellbook::Dictionary::new(&aff_s, &dic_s) {
                return Some(Self { dict });
            }
        }
        None
    }

    /// Build from inline dictionary strings (for tests).
    #[cfg(test)]
    fn from_strings(aff: &str, dic: &str) -> Option<Self> {
        spellbook::Dictionary::new(aff, dic)
            .ok()
            .map(|dict| Self { dict })
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

        for (word, byte_offset) in words.iter() {
            if warned.contains(*word) {
                continue;
            }

            // Skip emails, URLs, WikiWords (CamelCase).
            if is_email(word) || is_url(word) || is_wiki_word(word) {
                continue;
            }

            // Skip words with digits adjacent (reference digit tokenizing workaround).
            if has_digit_adjacent(&normalized, word) {
                continue;
            }

            if self.dict.check(word) {
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

            // Skip package name matches.
            if upper_name.contains(&upper) || upper_parts.iter().any(|p| p == &upper) {
                continue;
            }

            let mut suggestions = Vec::new();
            self.dict.suggest(word, &mut suggestions);
            suggestions.truncate(3);
            result.push((word.to_string(), suggestions));
        }

        result
    }
}

/// Split text into (word, byte_offset) pairs, keeping only alphabetic
/// sequences with apostrophes.
fn tokenize(text: &str) -> Vec<(&str, usize)> {
    let mut words = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        if c.is_alphabetic() || c == '\'' {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            words.push((&text[s..i], s));
            start = None;
        }
    }
    if let Some(s) = start {
        words.push((&text[s..], s));
    }
    words
}

fn is_email(word: &str) -> bool {
    word.contains('@') && word.contains('.')
}

fn is_url(word: &str) -> bool {
    word.starts_with("http://") || word.starts_with("https://") || word.starts_with("www.")
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

fn has_digit_adjacent(_text: &str, word: &str) -> bool {
    // Simplified: skip words containing digits.
    word.chars().any(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_AFF: &str = "SET UTF-8\n";
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
}
