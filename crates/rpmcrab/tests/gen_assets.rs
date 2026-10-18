//! The checked-in man page and shell completions are generated from the same
//! clap `Command` as the shipped binary; this pins that the committed assets
//! cover the live flag set, so a new flag without regenerated assets fails
//! loudly here even before the CI drift job runs.

use std::path::PathBuf;

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn long_flags() -> Vec<String> {
    rpmcrab::cli_command()
        .get_arguments()
        // `ArgAction::Version` args render in the man page's VERSION section,
        // not OPTIONS, so they are covered separately.
        .filter(|a| !matches!(a.get_action(), clap::ArgAction::Version))
        // Hidden args are internal (the `--__diverted-json` hand-back of
        // a diverted JSON run); the generator excludes them from the man
        // page by design, so they are not part of the covered flag set.
        .filter(|a| !a.is_hide_set())
        .filter_map(|a| a.get_long().map(|long| format!("--{long}")))
        .collect()
}

#[test]
fn man_page_covers_every_long_flag() {
    let man =
        std::fs::read_to_string(crate_dir().join("man/rpmcrab.1")).expect("man page is checked in");
    assert!(man.contains("rpmcrab"), "man page names the binary");
    for flag in long_flags() {
        // Roff escapes hyphens, so `--config` renders as `\-\-config`.
        let roff = flag.replace("-", "\\-");
        assert!(man.contains(&roff), "man page is missing {flag}");
    }
}

#[test]
fn completions_are_present_and_name_the_binary() {
    for name in ["rpmcrab.bash", "rpmcrab.zsh", "rpmcrab.fish"] {
        let content = std::fs::read_to_string(crate_dir().join("completions").join(name))
            .unwrap_or_else(|_| panic!("{name} is checked in"));
        assert!(!content.trim().is_empty(), "{name} is empty");
        assert!(
            content.contains("rpmcrab"),
            "{name} does not mention rpmcrab"
        );
    }
}

#[test]
fn completions_hide_internal_args() {
    // Hidden args are internal plumbing (the `--__diverted-json`
    // hand-back of a diverted JSON run); the generator filters them
    // out of the completions command, so they must never be
    // advertised to a shell user.
    let hidden: Vec<String> = rpmcrab::cli_command()
        .get_arguments()
        .filter(|a| a.is_hide_set())
        .filter_map(|a| a.get_long().map(|long| format!("--{long}")))
        .collect();
    assert!(
        !hidden.is_empty(),
        "the CLI has a hidden arg to keep hidden"
    );
    for name in ["rpmcrab.bash", "rpmcrab.zsh", "rpmcrab.fish"] {
        let content = std::fs::read_to_string(crate_dir().join("completions").join(name))
            .unwrap_or_else(|_| panic!("{name} is checked in"));
        for flag in &hidden {
            assert!(
                !content.contains(flag.as_str()),
                "{name} advertises the hidden {flag}"
            );
        }
    }
}

#[test]
fn man_page_documents_exit_status() {
    let man =
        std::fs::read_to_string(crate_dir().join("man/rpmcrab.1")).expect("man page is checked in");
    assert!(
        man.contains(".SH EXIT STATUS"),
        "man page has an EXIT STATUS section"
    );
    // The exit-code contract (docs/DESIGN.md §4.6, revised by #699:
    // 65 and 66 no longer exist).
    for code in ["0", "2", "3", "4", "64", "130"] {
        assert!(
            man.contains(&format!("\\fB{code}\\fR")),
            "man page is missing exit code {code}"
        );
    }
    for code in ["65", "66"] {
        assert!(
            !man.contains(&format!("\\fB{code}\\fR")),
            "man page still documents removed exit code {code}"
        );
    }
}

#[test]
fn man_page_has_no_machine_derived_defaults() {
    // `-j/--jobs` defaults to the machine's parallelism at runtime; the
    // rendered default must never be baked into the checked-in asset, or the
    // drift check fails on every machine with a different core count.
    let man =
        std::fs::read_to_string(crate_dir().join("man/rpmcrab.1")).expect("man page is checked in");
    for line in man.lines() {
        if line.contains("\\-\\-jobs") {
            assert!(
                !line.contains("[default:"),
                "jobs line bakes in a runtime default: {line}"
            );
        }
    }
}
