//! Revert-check for the pinned hunspell dictionaries: the spellcheck
//! tests are only reproducible because
//! `scripts/install-hunspell-dicts.sh` fetches one pinned upstream
//! commit and verifies the downloaded bytes against recorded sha256
//! sums. If the pin or the verification is dropped (a revert to
//! fetching a moving branch), this test fails instead of the
//! suggestion output silently drifting with upstream.

use std::path::Path;

fn script() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/install-hunspell-dicts.sh");
    std::fs::read_to_string(&path).expect("read scripts/install-hunspell-dicts.sh")
}

#[test]
fn hunspell_dicts_script_stays_pinned_and_verified() {
    let script = script();
    assert!(
        script.contains("dict_commit=\"6feecdc45bb14d46b4273f2cf6c0e3491cbee276\""),
        "the dictionaries must stay pinned to one upstream commit"
    );
    for sum in [
        "c7a8c4d08c29d237880844b1623099f59092602f189be38ce3912e457ff38bc1",
        "fa070979b1c5448bd7ab66eb6acb616d306f92879eb4218bc16ee35d39a608ee",
    ] {
        assert!(script.contains(sum), "recorded sha256 sum {sum} is missing");
    }
    assert!(
        script.contains("verify_checksum"),
        "downloads must be verified against the recorded sums"
    );
}
