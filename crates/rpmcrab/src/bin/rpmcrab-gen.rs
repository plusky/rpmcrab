//! Generator for man pages and shell completions.
//!
//! Built only with `--features gen`; it shares the clap `Command` definition
//! with the shipped binary (see [`rpmcrab::cli_command`]) so the two can never
//! drift. Output is written under `crates/rpmcrab/{man,completions}` and is
//! checked in; CI fails if a clap change leaves the committed assets stale
//! (the assets-drift job). An `EXIT STATUS` section documenting the frozen
//! exit codes (`docs/DESIGN.md` §4.6) is appended after rendering, because
//! `clap_mangen` has no custom-section support.
//!
//! Usage: `cargo run -p rpmcrab --features gen --bin rpmcrab-gen -- <out-dir>`
//! (defaults to `crates/rpmcrab` when run from the workspace root).

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use clap_complete::Shell;

/// `EXIT STATUS` postamble for the man page: the frozen exit-code contract
/// from `docs/DESIGN.md` §4.6. A static string, never derived from runtime
/// state, so the generated asset stays a pure function of the source.
const EXIT_STATUS_ROFF: &str = r#".SH EXIT STATUS
.TP
\fB0\fR
Clean run, or warnings and infos only. In the default permissive mode errors
scored at or under the threshold also exit 0, as do bare invocation,
\fB\-\-help\fR, \fB\-p\fR and \fB\-e\fR.
.TP
\fB2\fR
Nonexistent positional path or \fB\-c\fR path.
.TP
\fB3\fR
A package could not be read (reported; the run continues with the rest).
.TP
\fB4\fR
Unparsable TOML configuration.
.TP
\fB64\fR
\fB\-s\fR/\fB\-\-strict\fR was passed and an error was found.
.TP
\fB65\fR
\fB\-s\fR/\fB\-\-strict\fR was passed and every error was a strict promotion.
.TP
\fB66\fR
Badness score exceeded the threshold.
.TP
\fB130\fR
Interrupted (SIGINT).
"#;

fn main() {
    let root = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("crates/rpmcrab"));
    let mut cmd = rpmcrab::cli_command();

    let man_dir = root.join("man");
    fs::create_dir_all(&man_dir).expect("create man dir");
    let man_path = man_dir.join("rpmcrab.1");
    let mut rendered = Vec::new();
    clap_mangen::Man::new(cmd.clone())
        .title("rpmcrab")
        .section("1")
        .render(&mut rendered)
        .expect("render man page");
    let mut man_page = String::from_utf8(rendered).expect("man page is UTF-8");
    // The exit codes are frozen contract (DESIGN.md §4.6) with external
    // consumers, so they belong in the man page; clap_mangen cannot render a
    // custom section, hence the postamble before the trailing VERSION section.
    assert!(
        man_page.matches(".SH VERSION").count() == 1,
        "expected a single VERSION section marker"
    );
    man_page = man_page.replacen(".SH VERSION", &format!("{EXIT_STATUS_ROFF}.SH VERSION"), 1);
    fs::write(&man_path, man_page).expect("write man page");

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
