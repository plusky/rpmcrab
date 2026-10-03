//! Hot-path benchmarks for the regex OnceLock fix.
//!
//! Profiling (samply, 33 LibreOffice RPMs) showed Regex::new per call was
//! ~18% of total runtime. These benchmarks exercise the file-classification
//! hot path with synthetic paths; they are informational for CI (not gated
//! on absolute time). The hard regression guard is the unit test
//! `regex_factories_are_fast` in binaries.rs.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fancy_regex::Regex;
use std::hint::black_box;
use std::sync::OnceLock;

static USR_LIB: OnceLock<Regex> = OnceLock::new();
static SO: OnceLock<Regex> = OnceLock::new();
static BIN: OnceLock<Regex> = OnceLock::new();

fn usr_lib() -> &'static Regex {
    USR_LIB.get_or_init(|| Regex::new(r"^/usr/lib(64)?/").expect("static"))
}
fn so() -> &'static Regex {
    SO.get_or_init(|| Regex::new(r"/lib(64)?/[^/]+\.so(\.[0-9]+)*$").expect("static"))
}
fn bin() -> &'static Regex {
    BIN.get_or_init(|| Regex::new(r"^(/usr(/X11R6)?)?/s?bin/").expect("static"))
}

fn synthetic_paths(n: usize) -> Vec<String> {
    let templates = [
        "/usr/lib64/libfoo.so.1",
        "/usr/bin/bar",
        "/etc/baz.conf",
        "/usr/share/doc/qux/README",
        "/usr/lib/python3.12/site-packages/mod.py",
    ];
    (0..n)
        .map(|i| format!("{}{}", templates[i % templates.len()], i))
        .collect()
}

fn classify(paths: &[String]) -> usize {
    let mut hits = 0;
    for p in paths {
        if usr_lib().is_match(p).unwrap_or(false) {
            hits += 1;
        }
        if so().is_match(p).unwrap_or(false) {
            hits += 1;
        }
        if bin().is_match(p).unwrap_or(false) {
            hits += 1;
        }
    }
    hits
}

fn bench_classify(c: &mut Criterion) {
    let mut group = c.benchmark_group("classify");
    for n in [1_000, 10_000] {
        let paths = synthetic_paths(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &paths, |b, paths| {
            b.iter(|| black_box(classify(black_box(paths))))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_classify);
criterion_main!(benches);
