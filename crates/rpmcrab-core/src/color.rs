//! Terminal colour, mirroring rpmlint's `Color` class (`color.py`).
//!
//! The whole class collapses to empty strings when `sys.stdout.isatty()` is
//! false, so a piped run emits no escape codes at all. This is observable in
//! the frozen output (the sort key reads the level token off the rendered
//! line, so colour state changes the byte order — see `docs/DESIGN.md` §4.4).

/// The four codes rpmlint uses. Empty strings when not a tty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    pub bold: &'static str,
    pub red: &'static str,
    pub yellow: &'static str,
    pub reset: &'static str,
}

impl Color {
    /// The colour table for a tty (`is_tty = true`) or a pipe (`false`).
    pub fn for_tty(is_tty: bool) -> Self {
        if is_tty {
            Self {
                bold: "\x1b[1m",
                red: "\x1b[31m",
                yellow: "\x1b[33m",
                reset: "\x1b[0m",
            }
        } else {
            Self {
                bold: "",
                red: "",
                yellow: "",
                reset: "",
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn piped_has_no_codes() {
        let c = Color::for_tty(false);
        assert_eq!(c.red, "");
        assert_eq!(c.reset, "");
    }
}
