//! Generator for man pages and shell completions.
//!
//! Built only with `--features gen`; it shares the clap `Command` definition
//! with the shipped binary (see [`rpmcrab::cli_command`]) so the two can never
//! drift. Output is written under `crates/rpmcrab/{man,completions}` and is
//! checked in; CI fails if a clap change leaves the committed assets stale
//! (the assets-drift job).
//!
//! Usage: `cargo run -p rpmcrab --features gen --bin rpmcrab-gen -- <out-dir>`
//! (defaults to `crates/rpmcrab` when run from the workspace root).

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use clap_complete::Shell;

fn main() {
    let root = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("crates/rpmcrab"));
    let mut cmd = rpmcrab::cli_command();

    let man_dir = root.join("man");
    fs::create_dir_all(&man_dir).expect("create man dir");
    let man_path = man_dir.join("rpmcrab.1");
    let mut man_file = fs::File::create(&man_path).expect("create man page");
    clap_mangen::Man::new(cmd.clone())
        .title("rpmcrab")
        .section("1")
        .render(&mut man_file)
        .expect("render man page");

    let completions_dir = root.join("completions");
    fs::create_dir_all(&completions_dir).expect("create completions dir");
    for (shell, ext) in [
        (Shell::Bash, "bash"),
        (Shell::Zsh, "zsh"),
        (Shell::Fish, "fish"),
    ] {
        let path = completions_dir.join(format!("rpmcrab.{ext}"));
        let mut file = fs::File::create(&path).expect("create completion file");
        clap_complete::generate(shell, &mut cmd, "rpmcrab", &mut file);
    }

    println!(
        "wrote {} and 3 completions under {}",
        man_path.display(),
        root.display()
    );
}
