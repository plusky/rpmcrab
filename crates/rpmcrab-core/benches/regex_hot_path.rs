//! Hot-path benchmarks for the regex OnceLock fix.
//!
//! Profiling (samply, 33 LibreOffice RPMs) showed Regex::new per call was
//! ~18% of total runtime. These benchmarks exercise the file-classification
//! hot path with synthetic paths; they are informational for CI (not gated
//! on absolute time). The hard regression guard is the unit test
//! `regex_factories_are_fast` in binaries.rs.
//!
//! The benchmarks call the production factories, not bench-local copies:
//! a regression to per-call `Regex::new` in production must show up here.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rpmcrab_core::checks::binaries::{bin_regex, so_regex, usr_lib_regex};
use std::hint::black_box;

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
        // Call the factory per path, as production does: caching the
        // `&'static Regex` in a local would hide a per-call regression.
        if usr_lib_regex().is_match(p).unwrap_or(false) {
            hits += 1;
        }
        if so_regex().is_match(p).unwrap_or(false) {
            hits += 1;
        }
        if bin_regex().is_match(p).unwrap_or(false) {
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
