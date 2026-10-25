//! Defect-pattern presentation, end to end (issue #959): a full
//! `Lint` run whose findings mix member tags with a non-member pins
//! the JSON class field, the JSON summary count, and the text
//! summary line.

use std::path::Path;

use rpmcrab_core::check::{Check, SyntheticCheck};
use rpmcrab_core::color::Color;
use rpmcrab_core::config;
use rpmcrab_core::level::Level;
use rpmcrab_core::lint::Lint;
use rpmcrab_core::worker::Task;

/// A run whose canned findings mix two member tags with a non-member:
/// the class presentation counts and marks exactly the members.
fn run_with_mixed_findings(format: &str) -> String {
    let mut config = config::load_bundled();
    config.checks = vec!["BinariesCheck".to_string()];
    let canned = vec![
        (
            Level::Error,
            "call-to-mktemp",
            vec!["/usr/bin/foo".to_string()],
        ),
        (
            Level::Warning,
            "binary-or-shlib-calls-gethostbyname",
            vec!["/usr/bin/foo".to_string()],
        ),
        (
            Level::Warning,
            "no-soname",
            vec!["/usr/lib64/libfoo.so".to_string()],
        ),
    ];
    let make_checks = || {
        vec![Box::new(SyntheticCheck::new(
            "SyntheticCheck",
            "foo",
            Some("x86_64"),
            canned.clone(),
        )) as Box<dyn Check>]
    };
    let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/parity/cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm");
    let mut lint = Lint::new(config, make_checks(), Color::for_tty(false), 80).unwrap();
    lint.check_batch(vec![Task::File(rpm)], 1, &make_checks, true);
    lint.render_report(format, "rpmcrab", env!("CARGO_PKG_VERSION"), 1, false, 0.1)
}

#[test]
fn text_report_counts_member_findings_in_a_summary_line() {
    let out = run_with_mixed_findings("text");
    assert!(
        out.contains("defect-pattern findings: 2\n"),
        "no per-class summary line:\n{out}"
    );
    // The footer's own line keeps its frozen shape.
    assert!(
        out.contains("1 errors, 2 warnings, 0 filtered; has taken 0.1 s"),
        "footer changed shape:\n{out}"
    );
}

#[test]
fn json_report_marks_members_and_counts_the_class() {
    let out = run_with_mixed_findings("json");
    let doc: serde_json::Value = serde_json::from_str(&out).expect("JSON document");
    let findings = doc["findings"].as_array().expect("findings array");
    let class_of = |tag: &str| {
        findings
            .iter()
            .find(|f| f["check"] == tag)
            .unwrap_or_else(|| panic!("{tag} finding present"))
            .get("class")
            .cloned()
    };
    assert_eq!(
        class_of("call-to-mktemp"),
        Some(serde_json::json!("defect-pattern"))
    );
    assert_eq!(
        class_of("binary-or-shlib-calls-gethostbyname"),
        Some(serde_json::json!("defect-pattern"))
    );
    assert_eq!(class_of("no-soname"), None);
    assert_eq!(doc["summary"]["classes"]["defect-pattern"], 2);
}
