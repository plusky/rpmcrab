//! Pluggable report renderers behind `--format` (upstream rpmlint#109).
//!
//! Human text is the default and its byte shape is frozen (pinned by the
//! `report` golden tests); JSON is the single machine format, rendered
//! from the same structured findings (`Filter::findings`) so every
//! format agrees on what the run found. The [`Renderer`] trait stays
//! pluggable so a second machine format (SARIF, not JUnit) can be added
//! later as a new impl without touching the dispatch.

use crate::lint::Lint;

/// Everything a renderer needs, borrowed from the finished [`Lint`] run.
pub struct RenderContext<'a> {
    pub lint: &'a Lint,
    pub prog: &'a str,
    pub version: &'a str,
    pub header_packages: usize,
    pub time_report: bool,
    pub duration_secs: f64,
}

/// A `--format` report renderer: one per machine or human format.
pub trait Renderer {
    /// The `--format` value selecting this renderer.
    fn name(&self) -> &'static str;
    /// Render the finished run.
    fn render(&self, ctx: &RenderContext) -> String;
}

/// Human-readable text report (default). Byte shape is frozen; see
/// [`Lint::render`].
pub struct TextRenderer;

/// Machine-readable JSON report; see [`Lint::render_json`].
pub struct JsonRenderer;

/// The renderer for a `--format`/`OutputFormat` value, or `None` for an
/// unknown one (the caller falls back to text, like the config loader).
pub fn renderer_for(format: &str) -> Option<Box<dyn Renderer>> {
    match format {
        "text" => Some(Box::new(TextRenderer)),
        "json" => Some(Box::new(JsonRenderer)),
        _ => None,
    }
}

impl Renderer for TextRenderer {
    fn name(&self) -> &'static str {
        "text"
    }

    fn render(&self, ctx: &RenderContext) -> String {
        ctx.lint.render(
            ctx.prog,
            ctx.version,
            ctx.header_packages,
            ctx.time_report,
            ctx.duration_secs,
        )
    }
}

impl Renderer for JsonRenderer {
    fn name(&self) -> &'static str {
        "json"
    }

    fn render(&self, ctx: &RenderContext) -> String {
        ctx.lint.render_json(
            ctx.prog,
            ctx.version,
            ctx.header_packages,
            ctx.duration_secs,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;
    use crate::config::Config;

    fn empty_ctx<'a>(lint: &'a Lint) -> RenderContext<'a> {
        RenderContext {
            lint,
            prog: "rpmcrab",
            version: "2.10.0",
            header_packages: 1,
            time_report: false,
            duration_secs: 0.5,
        }
    }

    #[test]
    fn renderer_for_resolves_all_formats() {
        assert_eq!(renderer_for("text").unwrap().name(), "text");
        assert_eq!(renderer_for("json").unwrap().name(), "json");
        assert!(renderer_for("yaml").is_none());
    }

    #[test]
    fn text_and_json_renderers_match_lint_methods() {
        // The pluggable layer must not change the two existing formats:
        // text stays byte-frozen, json stays as #133 shipped it.
        let config = Config::default();
        let lint = Lint::new(config, Vec::new(), Color::for_tty(false), 80).unwrap();
        let ctx = empty_ctx(&lint);
        assert_eq!(
            TextRenderer.render(&ctx),
            lint.render("rpmcrab", "2.10.0", 1, false, 0.5),
        );
        assert_eq!(
            JsonRenderer.render(&ctx),
            lint.render_json("rpmcrab", "2.10.0", 1, 0.5),
        );
    }
}
