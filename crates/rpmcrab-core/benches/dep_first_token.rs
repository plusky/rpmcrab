//! Micro-benchmark for the `first_dep_token` manual first-token scan.
//!
//! `first_dep_token` is called once per raw dependency line on the
//! forbidden-controlchar fast path in the spec checks. The former
//! implementation allocated a full token `Vec` via `split_dep_tokens` just to
//! take the first token; the scan stops at the first token boundary instead.
//! Synthetic dep lines; informational for CI (not gated on absolute time) —
//! the differential unit test `first_dep_token_matches_full_tokenizer` in
//! dep.rs is the behavior guard.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rpmcrab_core::pkg::dep::first_dep_token;
use std::hint::black_box;

/// The former implementation, kept verbatim as the comparison baseline.
fn baseline_first_dep_token(line: &str) -> Option<&str> {
    fn split_dep_tokens(line: &str) -> Vec<&str> {
        let mut tokens: Vec<&str> = Vec::new();
        let mut start: Option<usize> = None;
        let mut depth = 0u32;
        for (i, c) in line.char_indices() {
            match c {
                '(' => {
                    start.get_or_insert(i);
                    depth += 1;
                }
                ')' => {
                    start.get_or_insert(i);
                    depth = depth.saturating_sub(1);
                }
                _ if (c.is_whitespace() || c == ',') && depth == 0 => {
                    if let Some(s) = start.take() {
                        tokens.push(&line[s..i]);
                    }
                }
                _ => {
                    start.get_or_insert(i);
                }
            }
        }
        if let Some(s) = start {
            tokens.push(&line[s..]);
        }
        tokens
    }
    split_dep_tokens(line).into_iter().next()
}

/// Synthetic dep lines: short first tokens (the common case) with tails of
/// `n` extra deps, the shape where skipping the full tokenization wins.
fn synthetic_lines(n: usize) -> Vec<String> {
    let firsts = [
        "libfoo",
        "libbar >= 1.2",
        "(liba or libb)",
        "pkgconfig(libx)",
    ];
    (0..200)
        .map(|i| {
            let mut line = firsts[i % firsts.len()].to_string();
            for j in 0..n {
                line.push_str(&format!(", dep{j} >= 1.{j}"));
            }
            line
        })
        .collect()
}

fn count_some(lines: &[String], f: fn(&str) -> Option<&str>) -> usize {
    let mut hits = 0;
    for line in lines {
        if f(black_box(line)).is_some() {
            hits += 1;
        }
    }
    hits
}

fn bench_first_token(c: &mut Criterion) {
    let mut group = c.benchmark_group("first_dep_token");
    for n in [10, 100] {
        let lines = synthetic_lines(n);
        group.bench_with_input(BenchmarkId::new("baseline", n), &lines, |b, lines| {
            b.iter(|| black_box(count_some(black_box(lines), baseline_first_dep_token)))
        });
        group.bench_with_input(BenchmarkId::new("scan", n), &lines, |b, lines| {
            b.iter(|| black_box(count_some(black_box(lines), first_dep_token)))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_first_token);
criterion_main!(benches);
