//! Spellchecking via the `spellbook` crate (pure Rust, Hunspell-compatible).
//!
//! Mirrors rpmlint's `spellcheck.py`: loads the en_US dictionary from the
//! system hunspell paths, checks words in Summary/Description, and degrades
//! gracefully when the dictionary is absent.

use std::path::Path;

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
            if let (Ok(aff_s), Ok(dic_s)) = (
                std::fs::read_to_string(&aff),
                std::fs::read_to_string(&dic),
            ) {
                if let Ok(dict) = spellbook::Dictionary::new(&aff_s, &dic_s) {
                    return Some(Self { dict });
                }
            }
        }
        None
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

        for (i, word) in words.iter().enumerate() {
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
            if starts_uppercase(word) && !at_sentence_start(&normalized, word, i) {
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

/// Split text into words, keeping only alphabetic sequences with apostrophes.
fn tokenize(text: &str) -> Vec<&str> {
    let mut words = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        if c.is_alphabetic() || c == '\'' {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            words.push(&text[s..i]);
            start = None;
        }
    }
    if let Some(s) = start {
        words.push(&text[s..]);
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
    // CamelCase: contains both upper and lower, starts uppercase.
    let has_upper = word.chars().any(|c| c.is_uppercase());
    let has_lower = word.chars().any(|c| c.is_lowercase());
    word.chars().next().is_some_and(|c| c.is_uppercase()) && has_upper && has_lower
}

fn starts_uppercase(word: &str) -> bool {
    word.chars().next().is_some_and(|c| c.is_uppercase())
}

fn at_sentence_start(_text: &str, _word: &str, _index: usize) -> bool {
    // Simplified: check if previous non-space char is sentence-ending.
    // For now, conservatively return false (skip capitalized words).
    // TODO: implement proper sentence-break detection.
    false
}

fn has_digit_adjacent(_text: &str, word: &str) -> bool {
    // Simplified: skip words containing digits.
    word.chars().any(|c| c.is_ascii_digit())
}
