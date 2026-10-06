//! Pluggable report renderers behind `--format` (upstream rpmlint#109).
//!
//! Human text is the default and its byte shape is frozen (pinned by the
//! `report` golden tests); JSON is the single machine format, rendered
//! from the same structured findings (`Filter::findings`) so every
//! format agrees on what the run found. The [`Renderer`] trait stays
//! pluggable so a second machine format (SARIF, not JUnit) can be added
//! later as a new impl without touching the dispatch.

use crate::finding::Finding;
use crate::level::Level;
use crate::lint::Lint;
use crate::report;

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

/// Human-readable text report (default). Byte shape is frozen, pinned by
/// the `report` golden tests.
///
/// The order is the reference's: results, banner, reports, footer
/// (`lint.py:94-118`). The header and footer count different things:
/// `header_packages` is the CLI *argument* count (`len(installed) +
/// len(rpmfile)`, `lint.py:242`), while the footer counts the packages
/// actually validated.
pub struct TextRenderer;

/// Machine-readable JSON report (upstream rpmlint#1156): the same
/// findings as the text report, as a JSON document.
///
/// Findings are sorted by `(check, level)` descending, mirroring the
/// text report's order; the summary carries the footer's counters and
/// the process exit code.
///
/// `duration_secs` is wall-clock time and varies between runs; golden
/// tests should ignore or redact it. Fatal per-package diagnostics are
/// printed to stderr (exit code 3) and never appear in the document.
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
        let lint = ctx.lint;
        let mut out = String::new();
        out.push_str(&report::header(&report::HeaderParams {
            prog: ctx.prog,
            version: ctx.version,
            conf_files: &lint.config().conf_files,
            rpmlintrc: &lint.config().rpmlintrc_display,
            no_checks: lint.config().checks.len(),
            no_packages: ctx.header_packages,
            color: &lint.color,
            width: lint.width,
        }));
        out.push_str(&lint.filter().render_results(lint.config()));
        if lint.aborted() {
            out.push_str(&report::abort_banner(
                lint.filter().score,
                lint.config().badness_threshold,
                &lint.color,
                lint.width,
            ));
        }
        if ctx.time_report {
            out.push_str(&lint.time_report());
        }
        out.push_str(&report::footer(&report::FooterParams {
            packages: lint.packages_checked(),
            specfiles: lint.specfiles_checked,
            errors: lint.filter().printed(Level::Error),
            warnings: lint.filter().printed(Level::Warning),
            filtered: lint.filter().filtered_out,
            score: lint.filter().score,
            duration_secs: ctx.duration_secs,
            aborted: lint.aborted(),
            color: &lint.color,
            width: lint.width,
        }));
        out
    }
}

impl Renderer for JsonRenderer {
    fn name(&self) -> &'static str {
        "json"
    }

    fn render(&self, ctx: &RenderContext) -> String {
        let lint = ctx.lint;
        let mut findings: Vec<&Finding> = lint.filter().findings().iter().collect();
        findings.sort_by_key(|f| std::cmp::Reverse((f.check.clone(), f.level.letter())));
        let doc = serde_json::json!({
            "program": ctx.prog,
            "version": ctx.version,
            "packages": ctx.header_packages,
            "checks": lint.config().checks.len(),
            "duration_secs": ctx.duration_secs,
            "findings": findings.iter().map(|f| f.json_value()).collect::<Vec<_>>(),
            "summary": {
                "errors": lint.filter().printed(Level::Error),
                "warnings": lint.filter().printed(Level::Warning),
                "filtered": lint.filter().filtered_out,
                "score": lint.filter().score,
                "aborted": lint.aborted(),
                "exit_code": lint.exit_code(),
            },
        });
        let mut out = serde_json::to_string_pretty(&doc).expect("findings are JSON-serializable");
        out.push('\n');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_for_resolves_all_formats() {
        assert_eq!(renderer_for("text").unwrap().name(), "text");
        assert_eq!(renderer_for("json").unwrap().name(), "json");
        assert!(renderer_for("yaml").is_none());
    }
}
