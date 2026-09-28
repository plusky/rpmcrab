//! Generator for man pages and shell completions.
//!
//! Built only with `--features gen`; it shares the clap `Command` definition
//! with the shipped binary so the two can never drift. Output is written under
//! `crates/rpmcrab/{man,completions}` and is checked in; CI fails if a clap
//! change leaves the committed assets stale (the assets-drift job).

#![forbid(unsafe_code)]

fn main() {
    // TODO(M1): build the shared clap Command and emit man + completions into
    // the directory named by argv[1].
    eprintln!("rpmcrab-gen: not implemented yet (M1)");
}
