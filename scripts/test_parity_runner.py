#!/usr/bin/env python3
"""Pinning tests for scripts/parity-runner.py.

The differ is the enforcement core of the parity contract: a difference
between rpmcrab and the reference passes only when a divergences.toml
entry accounts for it. Each test guards one attribution rule; removing
the rule makes the test fail.

Run:  python3 scripts/test_parity_runner.py
"""

import hashlib
import importlib.util
import os
import sys
import tempfile
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location(
        "parity_runner", os.path.join(HERE, "parity-runner.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


runner = _load()

HEADER_REF = [
    "=" * 28 + " rpmlint session starts " + "=" * 28,
    "rpmlint: 2.10.0",
    "configuration:",
    "    <XDG>/rpmlint/opensuse.toml",
    "checks: 43, packages: 1",
]
HEADER_PORT = [
    "=" * 28 + " rpmcrab session starts " + "=" * 28,
    "rpmcrab: 0.3.1",
    "configuration:",
    "    <builtin>",
    "checks: 45, packages: 1",
]


def session(header, findings, footer_counts, banner=False):
    lines = list(header) + [""]
    lines += findings
    if banner:
        lines.append("-" * 16 + " Badness 10000 exceeds threshold 999, "
                               "aborting. " + "-" * 16)
    errors, warnings = footer_counts
    lines.append(f" 1 packages and 0 specfiles checked; {errors} errors, "
                 f"{warnings} warnings, 0 filtered; "
                 "has taken <DURATION> s ")
    return "\n".join(lines) + "\n"


def entry(check, kind, case="global", reason=""):
    return {"case": case, "check": check, "kind": kind,
            "reason": reason, "since": "0.1.0"}


def ledger(entries, module_of=None):
    return runner.Ledger(entries, module_of or {})


def diff(ref_text, port_text, led, ref_exit=0, port_exit=0):
    return runner.diff_outputs("case", runner.parse_output(ref_text),
                               runner.parse_output(port_text),
                               ref_exit, port_exit, led)


def unattributed(diffs):
    return [d.text for d in diffs if not d.attributed]


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

def test_parse_output():
    text = session(HEADER_REF, [
        "pkg.noarch: E: some-finding (Badness: 10) /path detail",
        "pkg.spec:33: W: other-finding",
    ], (1, 1), banner=True)
    p = runner.parse_output(text)
    assert p.header == HEADER_REF
    assert p.findings == [("pkg.noarch", "E", "some-finding", "/path detail"),
                          ("pkg.spec:33", "W", "other-finding", "")]
    assert p.footer_counts == (1, 1)
    assert p.banner is True
    assert p.other == []


def test_sanitize_and_enchant_strip():
    subs = [("/venv", "<VENV>"), ("/xdg", "<XDG>")]
    out = runner.sanitize("/venv/bin has taken 0.25 s", subs)
    assert out == "<VENV>/bin has taken <DURATION> s"
    text = "warning: x\n(none): W: unable to init enchant, disabled.\nlast\n"
    assert runner.strip_enchant(text) == "warning: x\nlast\n"
    # A trailing blank line survives the strip byte-for-byte.
    assert runner.strip_enchant("warning: x\n\n") == "warning: x\n\n"


# ---------------------------------------------------------------------------
# finding differences and their attribution rules
# ---------------------------------------------------------------------------

def test_equal_outputs_have_no_diffs():
    text = session(HEADER_REF, ["pkg.noarch: W: f-one /a"], (0, 1))
    assert diff(text, text, ledger([])) == []


def test_header_diff_needs_session_entry():
    ref = session(HEADER_REF, [], (0, 0))
    port = session(HEADER_PORT, [], (0, 0))
    assert unattributed(diff(ref, port, ledger([])))
    led = ledger([entry("session-header", "behaviour")])
    assert not unattributed(diff(ref, port, led))


def test_severity_diff_needs_severity_entry():
    ref = session(HEADER_REF, ["pkg.spec: W: no-%check-section"], (0, 1))
    port = session(HEADER_PORT, ["pkg.spec: I: no-%check-section"], (0, 0))
    led = ledger([entry("session-header", "behaviour"),
                  entry("report", "behaviour"),
                  entry("no-%check-section", "behaviour")])
    assert unattributed(diff(ref, port, led))
    led.entries.append(entry("no-%check-section", "severity"))
    assert not unattributed(diff(ref, port, led))


def test_presence_diff_attributed_by_name_and_module():
    ref = session(HEADER_REF, ["pkg.noarch: E: gone-finding /a"], (1, 0))
    port = session(HEADER_PORT, [], (0, 0))
    assert unattributed(diff(ref, port, ledger(
        [entry("session-header", "behaviour"),
         entry("report", "behaviour")])))
    by_name = ledger([entry("session-header", "behaviour"),
                      entry("report", "behaviour"),
                      entry("gone-finding", "missing")])
    assert not unattributed(diff(ref, port, by_name))
    by_module = ledger([entry("session-header", "behaviour"),
                        entry("report", "behaviour"),
                        entry("FilesCheck", "behaviour")],
                       module_of={"gone-finding": "FilesCheck"})
    assert not unattributed(diff(ref, port, by_module))
    # A detail-kind entry does not account for a presence difference.
    wrong_kind = ledger([entry("session-header", "behaviour"),
                         entry("report", "behaviour"),
                         entry("gone-finding", "detail")])
    assert unattributed(diff(ref, port, wrong_kind))


def test_only_in_rpmcrab_not_attributed_by_missing_entry():
    # A `missing` entry records that the port does not emit the finding;
    # it cannot account for the finding appearing in the port's output —
    # that is exactly the regression shape the ledger must catch.
    ref = session(HEADER_REF, [], (0, 0))
    port = session(HEADER_PORT, ["pkg.noarch: W: new-finding /a"], (0, 1))
    base = [entry("session-header", "behaviour"),
            entry("report", "behaviour")]
    led = ledger(base + [entry("new-finding", "missing")])
    assert unattributed(diff(ref, port, led))
    for kind in ("behaviour", "limitation"):
        led = ledger(base + [entry("new-finding", kind)])
        assert not unattributed(diff(ref, port, led))


def test_entry_without_check_attributes_nothing():
    # An entry missing its `check` key accounts for nothing: with the
    # finding unknown to the module map, a None check would otherwise
    # compare equal to the None module and attribute it anyway.
    ref = session(HEADER_REF, ["pkg.noarch: E: unknown-finding /a"], (1, 0))
    port = session(HEADER_PORT, [], (0, 0))
    malformed = {"case": "global", "kind": "missing",
                 "reason": "", "since": "0.1.0"}
    led = ledger([entry("session-header", "behaviour"),
                  entry("report", "behaviour"), malformed])
    assert unattributed(diff(ref, port, led))


def test_detail_diff_attributed_by_detail_entry():
    ref = session(HEADER_REF, ["pkg.noarch: E: f /a (sha256 digest)"], (1, 0))
    port = session(HEADER_PORT, ["pkg.noarch: E: f /a"], (1, 0))
    led = ledger([entry("session-header", "behaviour"),
                  entry("FileDigestCheck", "detail")],
                 module_of={"f": "FileDigestCheck"})
    assert not unattributed(diff(ref, port, led))
    plain = ledger([entry("session-header", "behaviour")])
    assert unattributed(diff(ref, port, plain))


def test_templated_finding_attributed_by_reason_mention():
    ref = session(HEADER_REF, [], (0, 0))
    port = session(HEADER_PORT, [
        "pkg.noarch: E: daemon-activation-in-%post chkconfig --add"], (1, 0))
    led = ledger([
        entry("session-header", "behaviour"),
        entry("report", "behaviour"),
        entry("PostCheck", "behaviour",
              reason="New port-only Error: ... emits E "
                     "daemon-activation-in-<scriptlet> with the invoked "
                     "command as detail.")])
    assert not unattributed(diff(ref, port, led))


def test_reason_mention_from_another_finding_does_not_attribute():
    # A severity entry for a different finding that names this one in
    # passing (as a comparable class) does not account for its difference.
    ref = session(HEADER_REF, ["pkg.spec: W: no-%check-section"], (0, 1))
    port = session(HEADER_PORT, ["pkg.spec: I: no-%check-section"], (0, 0))
    led = ledger([
        entry("session-header", "behaviour"),
        entry("report", "behaviour"),
        entry("install-file-in-docs", "severity",
              reason="Comparable tidiness classes already sit at Info "
                     "(no-manual-page-for-binary, no-%check-section, "
                     "dangling-relative-symlink).")],
        module_of={"install-file-in-docs": "DocCheck",
                   "no-%check-section": "SpecCheck"})
    assert unattributed(diff(ref, port, led))


def test_exit_and_footer_attributed_by_report_entry():
    ref = session(HEADER_REF, ["pkg.noarch: E: f /a"], (1, 0), banner=True)
    port = session(HEADER_PORT, ["pkg.noarch: E: f /a"], (1, 0))
    led = ledger([entry("session-header", "behaviour"),
                  entry("f", "behaviour")])
    texts = unattributed(diff(ref, port, led, ref_exit=66, port_exit=64))
    assert texts  # banner, footer and exit are all still open
    led.entries.append(entry("report", "behaviour"))
    assert not unattributed(diff(ref, port, led, ref_exit=66, port_exit=64))


def test_port_banner_is_never_attributed():
    ref = session(HEADER_REF, [], (0, 0))
    port = session(HEADER_PORT, [], (0, 0), banner=True)
    led = ledger([entry("session-header", "behaviour"),
                  entry("report", "behaviour")])
    assert unattributed(diff(ref, port, led))


# ---------------------------------------------------------------------------
# stderr differences
# ---------------------------------------------------------------------------

def test_stderr_progress_lines_attributed_other_lines_not():
    led = ledger([entry("worker/report", "behaviour")])
    diffs = runner.diff_stderr("dbus-parity", "",
                               "checking a.noarch (1 of 2)\n", led)
    assert not unattributed(diffs)
    diffs = runner.diff_stderr("dbus-parity", "", "gcc: boom\n", led)
    assert unattributed(diffs)


# ---------------------------------------------------------------------------
# rpmcrab's own output contract
# ---------------------------------------------------------------------------

def test_port_contract():
    def parsed(findings, counts):
        return runner.parse_output(session(HEADER_PORT, findings, counts))

    ok = parsed(["pkg.noarch: E: f /a"], (1, 0))
    assert runner.port_contract_diffs(ok, 64) == []
    assert runner.port_contract_diffs(ok, 0)  # E present, exit 0
    assert runner.port_contract_diffs(ok, 3)  # outside {0, 64}
    bad_counts = parsed(["pkg.noarch: E: f /a"], (0, 0))
    assert runner.port_contract_diffs(bad_counts, 64)
    dup_header = list(HEADER_PORT)
    dup_header.insert(4, "    <builtin>")
    p = runner.parse_output(session(dup_header, [], (0, 0)))
    assert runner.port_contract_diffs(p, 0)


def test_extraction_abort_pattern():
    assert runner.extraction_aborted(
        ("", "(none): E: fatal error while reading x.rpm: Command "
             "'rpm2archive - | tar -xz' returned non-zero", 3))
    assert not runner.extraction_aborted(("", "some other error", 3))


def test_runner_pins_unitdir_in_scratch_home():
    # The reference expands %{_unitdir} at import time and matches no
    # unit files where the host rpm leaves it undefined; the runner
    # pins it in the scratch HOME both subprocesses run under.
    with tempfile.TemporaryDirectory() as td:
        runner.Runner("ref", "bin", td)
        with open(os.path.join(td, "home", ".rpmmacros")) as fh:
            assert fh.read() == "%_unitdir /usr/lib/systemd/system\n"


def test_unpinned_input_file_fails_the_case():
    # The runner copies the whole input directory into both runs, so a
    # file meta.toml does not pin would influence them unverified; the
    # case fails on it before anything runs.
    with tempfile.TemporaryDirectory() as td:
        case_dir = os.path.join(td, "cases", "pin-case")
        os.makedirs(os.path.join(case_dir, "input"))
        payload = b"fake rpm bytes"
        with open(os.path.join(case_dir, "input", "a.rpm"), "wb") as fh:
            fh.write(payload)
        with open(os.path.join(case_dir, "input", "stray.rpm"), "wb") as fh:
            fh.write(b"unpinned")
        meta = ('argv = ["a.rpm"]\n\n[[input]]\nfile = "a.rpm"\n'
                f'sha256 = "{hashlib.sha256(payload).hexdigest()}"\n')
        with open(os.path.join(case_dir, "meta.toml"), "w") as fh:
            fh.write(meta)
        old = runner.CASES_DIR
        runner.CASES_DIR = os.path.join(td, "cases")
        try:
            res = runner.check_case("pin-case", None, ledger([]), td)
        finally:
            runner.CASES_DIR = old
        assert res.status == "FAIL"
        assert any("unpinned" in d.text for d in res.unattributed)


def test_default_binary_never_falls_back_to_debug():
    # A stale target/debug build must not silently become the binary
    # under test: the default is the just-built release binary only.
    with tempfile.TemporaryDirectory() as td:
        def fake_bin(relpath):
            path = os.path.join(td, relpath)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write("#!/bin/sh\n")
            os.chmod(path, 0o755)
            return path

        fake_bin(os.path.join("target", "debug", "rpmcrab"))
        old = runner.REPO_ROOT
        runner.REPO_ROOT = td
        try:
            assert runner.default_port_bin() is None
            fresh = fake_bin(os.path.join("target", "release", "rpmcrab"))
            assert runner.default_port_bin() == fresh
        finally:
            runner.REPO_ROOT = old


# ---------------------------------------------------------------------------
# module map construction
# ---------------------------------------------------------------------------

def test_module_map_records_description_keys():
    with tempfile.TemporaryDirectory() as td:
        ref_dir = os.path.join(td, "ref")
        port_desc = os.path.join(td, "port-desc")
        os.makedirs(port_desc)
        with open(os.path.join(port_desc, "FilesCheck.toml"), "w") as fh:
            fh.write('some-finding = "text"\n')
        assert runner.build_module_map(ref_dir, port_desc) == {
            "some-finding": "FilesCheck"}
        # A missing descriptions directory is tolerated.
        assert runner.build_module_map(
            ref_dir, os.path.join(td, "nope")) == {}


def test_malformed_description_fails_module_map_build():
    # A description file that does not parse must fail loudly, not be
    # skipped: a skipped file silently drops its check's findings from
    # the module map, and their differences then surface unattributed
    # with no pointer at the cause.
    with tempfile.TemporaryDirectory() as td:
        port_desc = os.path.join(td, "port-desc")
        os.makedirs(port_desc)
        with open(os.path.join(port_desc, "Broken.toml"), "w") as fh:
            fh.write('key = "unterminated\n')
        try:
            runner.build_module_map(os.path.join(td, "ref"), port_desc)
        except tomllib.TOMLDecodeError:
            pass
        else:
            raise AssertionError(
                "malformed description did not fail the module-map build")


def main():
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        fn()
        print(f"ok {name}")
    print(f"{len(tests)} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
