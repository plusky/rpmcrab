#!/usr/bin/env python3
"""Fail-closed tests for scripts/check-rust-layering.sh.

The table-header regex must match a forbidden dependency only as a
table header (`[dependencies.<name>]`, including dev- and
target-qualified spellings) and never as a bare mention elsewhere:
before the grouping fix, the ungrouped alternation in
forbidden_table expanded to top-level alternatives, so any line
mentioning e.g. clap_complete matched whether or not it was a header.

Run:  python3 scripts/test_check_rust_layering.py
"""

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SCRIPT = os.path.join(HERE, "check-rust-layering.sh")

NAMES = ["clap", "clap_complete", "clap_mangen", "tracing-subscriber", "rpmcrab"]
HEADER_FORMS = [
    "[dependencies.{name}]",
    "[dev-dependencies.{name}]",
    "[target.'cfg(unix)'.dependencies.{name}]",
]


def _run_full(manifest):
    """Run the gate against a synthetic manifest; return the process."""
    with tempfile.TemporaryDirectory() as tmp:
        core = os.path.join(tmp, "crates", "rpmcrab-core")
        os.makedirs(core)
        with open(os.path.join(core, "Cargo.toml"), "w", encoding="utf-8") as fh:
            fh.write(manifest)
        return subprocess.run(
            ["bash", SCRIPT], cwd=tmp, capture_output=True, text=True
        )


def _run(manifest):
    """Run the gate against a synthetic manifest; return its exit code."""
    return _run_full(manifest).returncode


def test_table_headers_fail():
    """Every forbidden name as a table header, in every spelling, fails."""
    for name in NAMES:
        for form in HEADER_FORMS:
            manifest = "[package]\nname = \"rpmcrab-core\"\n\n" + form.format(name=name) + "\n"
            rc = _run(manifest)
            assert rc == 1, (name, form, rc)


def test_table_headers_with_whitespace_around_dot_fail():
    """TOML dotted keys allow whitespace around the dot, so
    `[dependencies . <name>]` (and the one-sided variants) must fail
    like the tight spelling."""
    forms = [
        "[dependencies . {name}]",
        "[dependencies. {name}]",
        "[dependencies .{name}]",
        "[dev-dependencies . {name}]",
        "[target.'cfg(unix)'.dependencies . {name}]",
    ]
    for name in NAMES:
        for form in forms:
            manifest = "[package]\nname = \"rpmcrab-core\"\n\n" + form.format(name=name) + "\n"
            rc = _run(manifest)
            assert rc == 1, (name, form, rc)


def test_renamed_dependencies_fail():
    """A Cargo rename (`alias = { package = "<name>", ... }`, a
    `[dependencies.alias]` table with a `package = "<name>"` line, or a
    multi-line inline table) must fail like the plain spelling: the
    dependency is the forbidden crate under another key."""
    for name in NAMES:
        forms = [
            f'alias = {{ package = "{name}", version = "1" }}\n',
            f'alias = {{ version = "1", package = "{name}" }}\n',
            f"[dependencies.alias]\npackage = \"{name}\"\nversion = \"1\"\n",
            f"alias = {{\n  package = \"{name}\",\n  version = \"1\",\n}}\n",
            f"alias = {{ package = '{name}', version = '1' }}\n",
        ]
        for form in forms:
            manifest = "[package]\nname = \"rpmcrab-core\"\n\n" + form
            proc = _run_full(manifest)
            assert proc.returncode == 1, (name, form, proc.stdout, proc.stderr)


def test_renamed_clean_and_comment_mentions_pass():
    """A rename of an unrelated crate passes, and a `package =` line in
    a comment is not a dependency."""
    manifest = (
        "[package]\nname = \"rpmcrab-core\"\n\n"
        'alias = { package = "serde", version = "1" }\n'
    )
    assert _run(manifest) == 0, manifest
    manifest = (
        "[package]\nname = \"rpmcrab-core\"\n\n"
        '# myclap = { package = "clap" }\n'
        "[dependencies]\nserde = \"1\"\n"
    )
    assert _run(manifest) == 0, manifest


def test_bare_mention_passes():
    """A bare mention of a forbidden name outside a header passes."""
    manifest = (
        "[package]\nname = \"rpmcrab-core\"\n\n"
        "# clap_complete is a CLI concern, kept out of the core crate\n"
        "[dependencies]\nserde = \"1\"\n"
    )
    assert _run(manifest) == 0, manifest


def test_clean_manifest_passes():
    """An unrelated dependency table passes."""
    manifest = (
        "[package]\nname = \"rpmcrab-core\"\n\n"
        "[dependencies]\nserde = \"1\"\n"
    )
    assert _run(manifest) == 0, manifest


def test_real_manifest_passes():
    """The gate still passes on the real core manifest."""
    proc = subprocess.run(
        ["bash", SCRIPT], cwd=REPO, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001 - an unexpected exception is a failure too
            failed += 1
            print(f"FAIL {t.__name__}: unexpected {type(e).__name__}: {e}")
        else:
            print(f"ok {t.__name__}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
