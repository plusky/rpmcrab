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
