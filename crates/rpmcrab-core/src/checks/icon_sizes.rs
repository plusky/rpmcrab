//! `IconSizesCheck` — icons in fixed-size directories must match that size.
//!
//! Ported from `rpmlint/checks/IconSizesCheck.py`. One finding:
//! `wrong-icon-size`.

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct IconSizesCheck {
    file_size_re: Regex,
    info_size_re: Regex,
}

impl IconSizesCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            file_size_re: Regex::new(r"/icons/[^/]+/(?P<x>\d+)x(?P<y>\d+)/").expect("static regex"),
            info_size_re: Regex::new(r"(?P<x>\d+) x (?P<y>\d+)").expect("static regex"),
        }
    }

    /// `(name, expected, actual)` for icons whose libmagic-reported size
    /// differs from the fixed-size directory by more than 2px in either
    /// dimension. `files` yields `(name, magic)` pairs.
    fn wrong_sizes<'a>(
        &self,
        files: impl Iterator<Item = (&'a str, &'a str)>,
    ) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        for (fname, magic) in files {
            if fname.contains("/animations/") {
                continue;
            }
            let (Ok(Some(fcaps)), Ok(Some(mcaps))) = (
                self.file_size_re.captures(fname),
                self.info_size_re.captures(magic),
            ) else {
                continue;
            };
            let dim = |caps: &fancy_regex::Captures<'_, str>, key: &str| {
                caps.name(key).and_then(|m| m.as_str().parse::<i64>().ok())
            };
            match (
                dim(&fcaps, "x"),
                dim(&fcaps, "y"),
                dim(&mcaps, "x"),
                dim(&mcaps, "y"),
            ) {
                (Some(fx), Some(fy), Some(mx), Some(my))
                    if (fx - mx).abs() > 2 || (fy - my).abs() > 2 =>
                {
                    out.push((
                        fname.to_string(),
                        format!("{fx}x{fy}"),
                        format!("{mx}x{my}"),
                    ));
                }
                _ => {}
            }
        }
        out
    }
}

impl Check for IconSizesCheck {
    fn name(&self) -> &'static str {
        "IconSizesCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let files = pkg
            .files
            .iter()
            .map(|f| (f.name.as_str(), f.magic.as_str()));
        for (fname, expected, actual) in self.wrong_sizes(files) {
            add_info(
                out,
                Level::Error,
                pkg,
                "wrong-icon-size",
                &[&fname, "expected:", &expected, "actual:", &actual],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn checker() -> IconSizesCheck {
        IconSizesCheck::new(&Config::default())
    }

    #[test]
    fn matching_icon_is_quiet() {
        let c = checker();
        let found = c.wrong_sizes(
            [(
                "/usr/share/icons/hicolor/48x48/apps/foo.png",
                "PNG image data, 48 x 48",
            )]
            .into_iter(),
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn mismatched_icon_is_reported() {
        let c = checker();
        let found = c.wrong_sizes(
            [(
                "/usr/share/icons/hicolor/48x48/apps/foo.png",
                "PNG image data, 32 x 32",
            )]
            .into_iter(),
        );
        assert_eq!(
            found,
            vec![(
                "/usr/share/icons/hicolor/48x48/apps/foo.png".to_string(),
                "48x48".to_string(),
                "32x32".to_string()
            )]
        );
    }

    #[test]
    fn two_pixel_tolerance_is_quiet() {
        let c = checker();
        let found = c.wrong_sizes(
            [(
                "/usr/share/icons/hicolor/48x48/apps/foo.png",
                "PNG image data, 46 x 50",
            )]
            .into_iter(),
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn three_pixel_difference_is_reported() {
        let c = checker();
        let found = c.wrong_sizes(
            [(
                "/usr/share/icons/hicolor/48x48/apps/foo.png",
                "PNG image data, 44 x 48",
            )]
            .into_iter(),
        );
        assert_eq!(found.len(), 1, "{found:?}");
    }

    #[test]
    fn animations_are_skipped() {
        let c = checker();
        let found = c.wrong_sizes(
            [(
                "/usr/share/icons/hicolor/48x48/animations/foo.png",
                "PNG image data, 16 x 16",
            )]
            .into_iter(),
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn non_icon_paths_are_skipped() {
        let c = checker();
        let found = c.wrong_sizes([("/usr/bin/foo", "PNG image data, 16 x 16")].into_iter());
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn files_without_magic_size_are_skipped() {
        let c = checker();
        let found =
            c.wrong_sizes([("/usr/share/icons/hicolor/48x48/apps/foo.png", "data")].into_iter());
        assert!(found.is_empty(), "{found:?}");
    }
}
