//! Forbids open-coding the scriptlet body-vs-interpreter choice outside
//! `checks::shared`.
//!
//! The reference's rule is `pkg[tag] or pkg.scriptprog(prog)`: the body wins
//! whenever it is non-empty. `checks::shared::script_body_or_prog` is the one
//! implementation of that rule; a second hand-written choice already shipped
//! inverted once (the Wave 4 `init_script.rs`: prog won, the body was
//! discarded, and every `%post -p /bin/sh` package with an init script got a
//! false-positive `postin-without-chkconfig`). Same source-scanning shape as
//! `check_registry.rs`: any `*PROG` tag read or `scriptprog` call in a check
//! file other than `shared.rs` must either go through the shared helper or be
//! on the explicit allow-list of legitimate direct reads below. A new direct
//! read fails here until it is deliberately allow-listed with its reason.

use std::path::PathBuf;

fn checks_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/checks")
}

/// Lines that read a `*PROG` tag without going through
/// `script_body_or_prog`, each with the reason it is not a body-vs-prog
/// choice. Keyed by trimmed line text (not line numbers) so moves do not
/// rot it, but any edit forces a deliberate re-allow-listing.
fn allowed_direct_reads() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "let postin_prog = pkg.scriptprog(librpm::Tag::POSTINPROG);",
            "files.rs ldconfig check: reads the interpreter to test whether \
             it *is* ldconfig; the body-vs-prog choice itself goes through \
             script_body_or_prog (st.postin)",
        ),
        (
            "let postun_prog = pkg.scriptprog(librpm::Tag::POSTUNPROG);",
            "files.rs ldconfig check: same as above, for %postun",
        ),
        (
            "(Tag::PREIN, Tag::PREINPROG, \"%pre\", false),",
            "post.rs scriptlet table: declarative (script, prog, macro, is_list) \
             mapping mirroring Pkg.SCRIPT_TAGS; both tags are read, no \
             body-vs-prog choice is made here",
        ),
        (
            "(Tag::POSTIN, Tag::POSTINPROG, \"%post\", false),",
            "post.rs scriptlet table: same as above",
        ),
        (
            "(Tag::PREUN, Tag::PREUNPROG, \"%preun\", false),",
            "post.rs scriptlet table: same as above",
        ),
        (
            "(Tag::POSTUN, Tag::POSTUNPROG, \"%postun\", false),",
            "post.rs scriptlet table: same as above",
        ),
        (
            "(Tag::PRETRANS, Tag::PRETRANSPROG, \"%pretrans\", false),",
            "post.rs scriptlet table: same as above",
        ),
        (
            "(Tag::POSTTRANS, Tag::POSTTRANSPROG, \"%posttrans\", false),",
            "post.rs scriptlet table: same as above",
        ),
        (
            "Tag::TRIGGERSCRIPTPROG,",
            "post.rs scriptlet table (multi-line tuple): same as above",
        ),
        (
            "Tag::VERIFYSCRIPTPROG,",
            "post.rs scriptlet table (multi-line tuple): same as above",
        ),
        (
            "Tag::FILETRIGGERSCRIPTPROG,",
            "post.rs scriptlet table (multi-line tuple): same as above",
        ),
        (
            "Tag::TRANSFILETRIGGERSCRIPTPROG,",
            "post.rs scriptlet table (multi-line tuple): same as above",
        ),
        (
            "let prog = pkg.scriptprog(prog_tag);",
            "post.rs: reads both script and prog tags to pass to check_scriptlet; \
             not a body-vs-prog choice",
        ),
    ]
}

/// A `*PROG` tag token: all-caps identifier ending in PROG
/// (`POSTINPROG`, `PREUNPROG`, ...).
fn is_prog_token(token: &str) -> bool {
    token.len() > 4
        && token.ends_with("PROG")
        && token
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn line_chooses_scriptlet(line: &str) -> bool {
    if line.contains("script_body_or_prog") {
        // Delegates the choice to the shared helper: the thing we want.
        return false;
    }
    if line.contains("scriptprog") {
        return true;
    }
    // Tokenize on non-identifier characters and look for *PROG tag tokens.
    let mut token = String::new();
    let mut found = false;
    for c in line.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_alphanumeric() || c == '_' {
            token.push(c);
        } else {
            if is_prog_token(&token) {
                found = true;
                break;
            }
            token.clear();
        }
    }
    found
}

#[test]
fn no_check_open_codes_the_scriptlet_choice() {
    let allowed = allowed_direct_reads();
    let dir = checks_dir();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("read src/checks")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
        .filter(|p| p.file_name().and_then(|n| n.to_str()) != Some("shared.rs"))
        .collect();
    entries.sort();
    assert!(!entries.is_empty(), "no check files found in src/checks");

    let mut violations = Vec::new();
    for path in entries {
        let src = std::fs::read_to_string(&path).expect("read check file");
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        // A script_body_or_prog(...) call may span lines (rustfmt); the
        // *PROG tokens on its continuation lines are arguments to the
        // helper, not an open-coded choice. Track the call's paren depth.
        let mut helper_depth: i32 = 0;
        for (i, line) in src.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue; // a doc reference to the rule is not a choice
            }
            if helper_depth == 0 {
                if let Some(pos) = line.find("script_body_or_prog") {
                    let mut d = 0;
                    let mut opened = false;
                    for c in line[pos + "script_body_or_prog".len()..].chars() {
                        if c == '(' {
                            d += 1;
                            opened = true;
                        } else if c == ')' {
                            d -= 1;
                        }
                    }
                    if opened && d > 0 {
                        helper_depth = d;
                        continue;
                    }
                }
            } else {
                for c in line.chars() {
                    if c == '(' {
                        helper_depth += 1;
                    } else if c == ')' {
                        helper_depth -= 1;
                    }
                }
                continue;
            }
            if !line_chooses_scriptlet(line) {
                continue;
            }
            if allowed.iter().any(|(l, _)| *l == trimmed) {
                continue;
            }
            violations.push(format!("{name}:{}: {trimmed}", i + 1));
        }
    }
    assert!(
        violations.is_empty(),
        "scriptlet body-vs-interpreter choice open-coded outside checks::shared \
         (use shared::script_body_or_prog; allow-list a legitimate direct read \
         with its reason if this is one):\n  {}",
        violations.join("\n  ")
    );
}
