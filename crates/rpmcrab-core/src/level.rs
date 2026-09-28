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
