#!/usr/bin/env python3
"""Fail-closed tests for the assembly in generate-divergences-ledger.py.

Each test guards a failure mode that would silently corrupt the
ledger: owner files assembling out of order scrambles the aggregate,
a block edited in transit breaks the verbatim-entry guarantee, and a
source whose blocks and parsed entries disagree (a fused entry) must
fail at generation time rather than drift the committed file. Stray
tables and unknown owners fail the same way.

Run:  python3 scripts/test_generate_divergences_ledger.py
"""

import importlib.util
import os
import sys
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location(
        "gen_divergences_ledger",
        os.path.join(HERE, "generate-divergences-ledger.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen = _load()

ENTRY_A = (
    '[[divergence]]\n'
    'case = "global"\n'
    'check = "alpha-finding"\n'
    'kind = "behaviour"\n'
    'reason = "alpha reason"\n'
    'since = "0.1.0"\n'
)
ENTRY_B = (
    '[[divergence]]\n'
    'case = "global"\n'
    'check = "beta-finding"\n'
    'kind = "missing"\n'
    'reason = "beta is not emitted"\n'
    'since = "0.2.0"\n'
    'upstream = "https://example.invalid/1"\n'
)


def _src(tmp, files):
    src = Path(tmp) / "src"
    src.mkdir(exist_ok=True)
    for name, text in files.items():
        (src / name).write_text(text, encoding="utf-8")
    return src


def test_assemble_orders_owner_files_by_name():
    """Owner files assemble in filename order, whatever the entry
    content: BetaCheck's entries precede alpha.toml's."""
    with tempfile.TemporaryDirectory() as tmp:
        src = _src(tmp, {
            "alpha.toml": "# header\n\n" + ENTRY_A,
            "BetaCheck.toml": "# header\n\n" + ENTRY_B,
        })
        text, count = gen.assemble(src)
    assert count == 2
    assert text.index("beta-finding") < text.index("alpha-finding")


def test_assemble_preserves_blocks_verbatim():
    """Entry blocks reach the aggregate byte-for-byte, in file order."""
    with tempfile.TemporaryDirectory() as tmp:
        src = _src(tmp, {
            "OneCheck.toml": "# header\n\n" + ENTRY_A + "\n" + ENTRY_B,
        })
        text, count = gen.assemble(src)
    assert count == 2
    assert ENTRY_A.rstrip("\n") in text
    assert ENTRY_B.rstrip("\n") in text
    assert text.index("alpha-finding") < text.index("beta-finding")


def test_assemble_stamps_and_parses():
    """The output carries the generated stamp and parses back to the
    source entries."""
    import tomllib
    with tempfile.TemporaryDirectory() as tmp:
        src = _src(tmp, {"OneCheck.toml": ENTRY_A})
        text, _ = gen.assemble(src)
    assert text.startswith(gen.STAMP)
    entries = tomllib.loads(text)["divergence"]
    assert [e["check"] for e in entries] == ["alpha-finding"]


def test_assemble_rejects_fused_source():
    """A source whose block count and entry count disagree fails.
    The spaced header (`[[ divergence ]]`) parses as an entry but is
    invisible to the block extractor — the shape that assembles
    silently when the count guard is gone. The duplicate-key block
    is the fused shape a hand merge produces; it fails as a
    ValueError too."""
    spaced = (
        '[[ divergence ]]\n'
        'case = "global"\n'
        'check = "alpha-finding"\n'
        'kind = "behaviour"\n'
        'reason = "alpha reason"\n'
        'since = "0.1.0"\n'
    )
    with tempfile.TemporaryDirectory() as tmp:
        src = _src(tmp, {"OneCheck.toml": spaced})
        try:
            gen.assemble(src)
        except ValueError as exc:
            assert "blocks but" in str(exc)
        else:
            raise AssertionError(
                "spaced-header source assembled without an error")
    fused = (
        '[[divergence]]\n'
        'case = "global"\n'
        'check = "alpha-finding"\n'
        'kind = "behaviour"\n'
        'reason = "alpha reason"\n'
        'since = "0.1.0"\n'
        'check = "beta-finding"\n'
    )
    with tempfile.TemporaryDirectory() as tmp:
        src = _src(tmp, {"OneCheck.toml": fused})
        try:
            gen.assemble(src)
        except ValueError:
            return
    raise AssertionError("fused source assembled without an error")


def test_assemble_rejects_dropped_first_header():
    """An entry whose [[divergence]] header was dropped leaves its
    fields as top-level keys: the source fails instead of silently
    losing the entry."""
    dropped = ENTRY_A.split("\n", 1)[1]
    with tempfile.TemporaryDirectory() as tmp:
        src = _src(tmp, {"OneCheck.toml": dropped})
        try:
            gen.assemble(src)
        except ValueError:
            return
    raise AssertionError("headerless entry assembled without an error")


def test_assemble_rejects_stray_tables():
    """A top-level key or an interleaved [other] table rides
    nowhere: both fail instead of being dropped or copied into the
    aggregate."""
    shapes = (
        'stray = "x"\n\n' + ENTRY_A,
        ENTRY_A + '\n[other]\nkey = "x"\n',
    )
    for shape in shapes:
        with tempfile.TemporaryDirectory() as tmp:
            src = _src(tmp, {"OneCheck.toml": shape})
            try:
                gen.assemble(src)
            except ValueError:
                continue
        raise AssertionError("stray table assembled without an error")


def test_assemble_rejects_unknown_owner():
    """With the owner set given, a source owned by no registered
    check or listed run topic fails; a registered owner assembles."""
    with tempfile.TemporaryDirectory() as tmp:
        src = _src(tmp, {"Bogus.toml": ENTRY_A})
        try:
            gen.assemble(src, owners=gen.known_owners())
        except ValueError as exc:
            assert "Bogus" in str(exc)
        else:
            raise AssertionError("Bogus.toml assembled without an error")
    with tempfile.TemporaryDirectory() as tmp:
        src = _src(tmp, {"FilesCheck.toml": ENTRY_A})
        _, count = gen.assemble(src, owners=gen.known_owners())
        assert count == 1


def _run_main(tmp, check):
    src = _src(tmp, {"FilesCheck.toml": "# header\n\n" + ENTRY_A})
    ledger = Path(tmp) / "divergences.toml"
    old_src, old_ledger = gen.SRC_DIR, gen.LEDGER
    gen.SRC_DIR, gen.LEDGER = src, ledger
    try:
        rc = gen.main(["--check"] if check else [])
    finally:
        gen.SRC_DIR, gen.LEDGER = old_src, old_ledger
    return rc, ledger


def test_main_write_then_check_clean():
    """Write mode produces the aggregate; --check on it exits 0."""
    with tempfile.TemporaryDirectory() as tmp:
        rc, ledger = _run_main(tmp, check=False)
        assert rc == 0 and ledger.exists()
        rc, _ = _run_main(tmp, check=True)
        assert rc == 0


def test_main_check_drift_returns_one():
    """A committed aggregate that differs from the sources is drift:
    --check exits 1."""
    with tempfile.TemporaryDirectory() as tmp:
        rc, ledger = _run_main(tmp, check=False)
        assert rc == 0
        ledger.write_text(ledger.read_text(encoding="utf-8") + "\n",
                          encoding="utf-8")
        rc, _ = _run_main(tmp, check=True)
        assert rc == 1


def main():
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:
            failed += 1
            print(f"FAIL {name}: {exc!r}")
        else:
            print(f"ok   {name}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
