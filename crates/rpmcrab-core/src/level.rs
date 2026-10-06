//! The three finding levels. The letter is part of the frozen wire format.

use crate::color::Color;

/// Severity of a finding. `E`/`W`/`I` are the bytes that appear in output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Level {
    Error,
    Warning,
    Info,
}

impl Level {
    /// Parse a severity-override value (upstream rpmlint#1335): `E`/`W`/`I`
    /// or the long forms `error`/`warning`/`info`, case-insensitive.
    pub fn parse(s: &str) -> Option<Level> {
        match s.trim().to_ascii_lowercase().as_str() {
            "e" | "error" => Some(Level::Error),
            "w" | "warning" => Some(Level::Warning),
            "i" | "info" => Some(Level::Info),
            _ => None,
        }
    }

    /// The single-letter form printed in the finding line.
    pub fn letter(self) -> char {
        match self {
            Level::Error => 'E',
            Level::Warning => 'W',
            Level::Info => 'I',
        }
    }

    /// The level's colour, as rpmlint assigns it (`E` red, `W` yellow, `I` bold).
    pub(crate) fn color(self, c: &Color) -> &'static str {
        match self {
            Level::Error => c.red,
            Level::Warning => c.yellow,
            Level::Info => c.bold,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_letters_and_names_case_insensitively() {
        assert_eq!(Level::parse("E"), Some(Level::Error));
        assert_eq!(Level::parse("w"), Some(Level::Warning));
        assert_eq!(Level::parse("I"), Some(Level::Info));
        assert_eq!(Level::parse("error"), Some(Level::Error));
        assert_eq!(Level::parse("Warning"), Some(Level::Warning));
        assert_eq!(Level::parse("INFO"), Some(Level::Info));
        assert_eq!(Level::parse("  e  "), Some(Level::Error));
        assert_eq!(Level::parse("bogus"), None);
        assert_eq!(Level::parse(""), None);
    }
}
