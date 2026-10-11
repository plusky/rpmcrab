#!/usr/bin/env python3
"""Fail-closed tests for scripts/sync-upstream-whitelists.py.

Each test guards a failure mode from the #417 reviews: the slfo lxd data
loss, the blocklist-bypassing regexes, silent upstream deletions, the
deduped-file skip, and the PROVENANCE pin handling. Removing the loud
failure makes the test fail.

Run:  python3 scripts/test_sync_upstream_whitelists.py
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(HERE, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sync = _load("sync_whitelists", "sync-upstream-whitelists.py")
gen = _load("gen_distro_configs", "generate-distro-configs.py")

_LEAP_ONLY, _MANAGED, _BY_FLAVOR = sync._load_generator_sets()
sync.WHITELIST_FILES = _MANAGED


SURVIVOR = '[[FileDigestGroup]]\npackage = "kept"\npath = "/y"\n'

LXD = (
    '[[FileDigestGroup]]\n'
    'package = "lxd"\n'
    'type = "sysctl"\n'
    '[FileDigestGroup.digests]\n'
    'path = "/usr/lib/sysctl.d/60-lxd.conf"\n'
)

SYSCTL_HEADER = "# sysctl whitelist\n\n"


def test_sync_sets_match_generator():
    """The sync tool must track the generator's sets, never hand-copy them."""
    assert set(sync.WHITELIST_FILES) == set(gen.SYNC_MANAGED_FILES)
    assert set(sync.WHITELIST_FILES) == set(_MANAGED)


def test_lxd_kept_for_slfo():
    """lxd is still shipped in SLE 16: the slfo sync must not strip it."""
    local = SYSCTL_HEADER + LXD
    changed, new, added, updated, removed, skipped = sync.plan_merge(
        local, SYSCTL_HEADER + LXD, {"lxd"}, "slfo", set())
    assert not changed, (added, removed, skipped)
    assert new is None
    assert skipped == []


def test_lxd_dropped_for_opensuse():
    """lxd is gone from Factory: the opensuse sync still drops it."""
    local = SYSCTL_HEADER + LXD
    changed, new, added, updated, removed, skipped = sync.plan_merge(
        local, SYSCTL_HEADER + SURVIVOR, {"lxd"}, "opensuse", set())
    assert changed
    assert "lxd" not in new
    assert removed == ["[[FileDigestGroup]] for lxd"]
    assert updated == []
    # A local-only stanza surfacing as a removal is not a blocklist skip.
    assert skipped == []


def test_partial_blocklist_stanza_kept():
    """A stanza is dropped only when ALL its packages are blocklisted."""
    stanza = (
        '[[FileDigestGroup]]\n'
        'packages = ["live-pkg", "snapd"]\n'
        'path = "/x"\n'
    )
    changed, new, added, updated, removed, skipped = sync.plan_merge(
        SYSCTL_HEADER, SYSCTL_HEADER + stanza, {"snapd"}, "opensuse", set())
    assert changed
    assert added == 1
    assert '"live-pkg"' in new
    assert skipped == []


def test_all_blocklisted_stanza_dropped_reports_only_blocklisted():
    stanza = (
        '[[FileDigestGroup]]\n'
        'packages = ["snapd", "lxd"]\n'
        'path = "/x"\n'
    )
    # Upstream-only blocklisted stanza: skipped, never (re)introduced.
    changed, new, added, updated, removed, skipped = sync.plan_merge(
        SYSCTL_HEADER, SYSCTL_HEADER + stanza, {"snapd", "lxd"},
        "opensuse", set())
    assert not changed
    assert sorted(skipped) == ["lxd", "snapd"]
    # Local-only blocklisted stanza: a removal, not a skip.
    changed, new, added, updated, removed, skipped = sync.plan_merge(
        SYSCTL_HEADER + stanza, SYSCTL_HEADER + SURVIVOR, {"snapd", "lxd"},
        "opensuse", set())
    assert changed
    assert removed == ["[[FileDigestGroup]] for snapd, lxd"]
    assert updated == []
    assert skipped == []


def test_package_re_trailing_comment():
    """`package = "x" # comment` must still match (generator parity)."""
    stanza = '[[G]]\npackage = "snapd" # trailing comment\npath = "/x"\n'
    assert sync._stanza_packages(stanza) == ("snapd",)


def test_packages_re_multiline():
    """Multiline `packages = [...]` arrays must parse (DOTALL parity)."""
    stanza = '[[G]]\npackages = [\n  "aaa",\n  "bbb",\n]\npath = "/x"\n'
    assert sync._stanza_packages(stanza) == ("aaa", "bbb")


def test_comment_attaches_to_following_stanza():
    """Deleting stanza N-1 must not eat stanza N's leading comment."""
    local = (
        SYSCTL_HEADER
        + '[[G]]\npackage = "aaa"\npath = "/x"\n'
        + '\n# keep me with bbb\n'
        + '[[G]]\npackage = "bbb"\npath = "/y"\n'
    )
    upstream = SYSCTL_HEADER + '[[G]]\npackage = "bbb"\npath = "/y"\n'
    changed, new, added, updated, removed, skipped = sync.plan_merge(
        local, upstream, set(), "opensuse", set())
    assert changed
    assert "# keep me with bbb" in new
    assert '"bbb"' in new
    assert '"aaa"' not in new
    assert removed == ["[[G]] for aaa"]
    assert updated == []


def test_upstream_deletions_reported():
    """Removed stanzas are returned for the log/PR body, never silent."""
    local = SYSCTL_HEADER + LXD
    survivor = '[[FileDigestGroup]]\npackage = "kept"\npath = "/y"\n'
    changed, new, added, updated, removed, skipped = sync.plan_merge(
        local, SYSCTL_HEADER + survivor, set(), "opensuse", set())
    assert changed
    assert removed == ["[[FileDigestGroup]] for lxd"]
    assert updated == []
    assert '"kept"' in new
    assert updated == []


def test_in_place_update_is_not_a_deletion():
    """A hash bump on the same (table, package) reads as updated, not removed."""
    old = ("[[FileDigestGroup]]\npackage = \"foo\"\n"
           "hash = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n")
    new_stanza = ("[[FileDigestGroup]]\npackage = \"foo\"\n"
                  "hash = \"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\"\n")
    changed, new, added, updated, removed, skipped = sync.plan_merge(
        SYSCTL_HEADER + old, SYSCTL_HEADER + new_stanza,
        set(), "opensuse", set())
    assert changed
    assert added == 1
    assert removed == []
    assert updated == ["[[FileDigestGroup]] for foo (content updated)"]
    assert "BBBB" in new


def test_packageless_stanza_added_is_counted():
    """A new stanza without package info still counts as added."""
    stanza = "[[FileDigestGroup]]\npath = \"/x\"\n"
    changed, new, added, updated, removed, skipped = sync.plan_merge(
        SYSCTL_HEADER, SYSCTL_HEADER + stanza, set(), "opensuse", set())
    assert changed
    assert added == 1
    assert 'path = "/x"' in new
    # ... and an identical one is not re-added.
    changed, new, added, updated, removed, skipped = sync.plan_merge(
        SYSCTL_HEADER + stanza, SYSCTL_HEADER + stanza,
        set(), "opensuse", set())
    assert not changed
    assert added == 0


def test_regenerate_rs_tracks_dedup():
    """Materializing a slfo file must flip its manifest entry to slfo/."""
    import pathlib
    import tempfile
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "opensuse").mkdir()
    (d / "slfo").mkdir()
    (d / "opensuse" / "cron-whitelist.toml").write_text("[[G]]\npackage = \"a\"\n")
    rs_path = d / "distro_files_generated.rs"
    rs_path.write_text("stale")
    gen_mod = sync._load_generator_module()
    old_rs, gen_mod.GENERATED_RS = gen_mod.GENERATED_RS, rs_path
    try:
        assert sync.regenerate_rs(gen_mod, d) is True  # stale -> rewritten
        assert sync.regenerate_rs(gen_mod, d) is False  # absent == deduped
        (d / "slfo" / "cron-whitelist.toml").write_text("[[G]]\npackage = \"b\"\n")
        assert sync.regenerate_rs(gen_mod, d) is True
        rs = rs_path.read_text()
        assert '"../data/distro/slfo/cron-whitelist.toml"' in rs
        (d / "slfo" / "cron-whitelist.toml").write_text("[[G]]\npackage = \"a\"\n")
        assert sync.regenerate_rs(gen_mod, d) is True
        rs = rs_path.read_text()
        assert '"../data/distro/opensuse/cron-whitelist.toml"' in rs
    finally:
        gen_mod.GENERATED_RS = old_rs


def test_empty_packages_list_is_not_blocklisted():
    """`packages = []` matches the generator: kept, never silently dropped."""
    stanza = "[[G]]\npackages = []\npath = \"/x\"\n"
    changed, new, added, updated, removed, skipped = sync.plan_merge(
        SYSCTL_HEADER, SYSCTL_HEADER + stanza, set(), "opensuse", set())
    assert changed
    assert added == 1
    assert removed == [] and skipped == []


def test_header_only_upstream_raises():
    """Header/comment-only upstream must fail closed, not wipe the file."""
    try:
        sync.plan_merge(SYSCTL_HEADER + LXD, SYSCTL_HEADER, set(),
                        "opensuse", set())
    except RuntimeError as e:
        assert "no stanzas" in str(e), e
    else:
        raise AssertionError("header-only upstream did not raise")


def test_rewrite_keeps_single_blank_line():
    """Rewritten files separate stanzas with exactly one blank line."""
    local = (SYSCTL_HEADER
             + '[[G]]\npackage = "aaa"\npath = "/x"\n'
             + '\n# keep me with bbb\n'
             + '[[G]]\npackage = "bbb"\npath = "/y"\n')
    upstream = (SYSCTL_HEADER
                + '[[G]]\npackage = "bbb"\npath = "/y"\n'
                + '[[G]]\npackage = "ccc"\npath = "/z"\n')
    changed, new, added, updated, removed, skipped = sync.plan_merge(
        local, upstream, set(), "opensuse", set())
    assert changed
    assert "\n\n\n" not in new, repr(new)
    assert "# keep me with bbb\n[[G]]\npackage = \"bbb\"" in new


def test_branch_override_validation():
    """Unknown --branch flavors fail with usage error, not silent defaults."""
    import io
    from contextlib import redirect_stderr
    old_argv = sys.argv
    try:
        for bad in ("opensuse=a,foo=b", "opensuse=a,bar"):
            sys.argv = ["sync", "--branch", bad, "--dry-run"]
            try:
                with redirect_stderr(io.StringIO()):
                    sync.main()
            except SystemExit as e:
                assert e.code == 2, (bad, e.code)
            else:
                raise AssertionError(f"--branch {bad!r} did not fail")
    finally:
        sys.argv = old_argv


def test_empty_upstream_raises():
    """An empty upstream response must fail closed, not delete everything."""
    try:
        sync.plan_merge(SYSCTL_HEADER + LXD, "\n", set(), "opensuse", set())
    except RuntimeError as e:
        assert "empty upstream" in str(e), e
    else:
        raise AssertionError("empty upstream did not raise")


def test_missing_slfo_stays_deduped_when_identical():
    """A deduped (absent) slfo file is materialized only on divergence."""
    base = SYSCTL_HEADER + LXD
    changed, new, added, updated, removed, skipped = sync.plan_merge(
        base, SYSCTL_HEADER + LXD, set(), "slfo", set())
    assert not changed


def test_provenance_pin_update_replaces_and_appends():
    """Sync-owned pin lines are replaced in place, missing ones appended."""
    import pathlib
    import tempfile
    d = tempfile.mkdtemp()
    prov = os.path.join(d, "PROVENANCE")
    with open(prov, "w") as f:
        f.write("# opensuse: opensuse @ AAA (2026-01-01)\n"
                "# opensuse-whitelists: opensuse @ OLD (2025-01-01)\n")
    old, sync.PROVENANCE_FILE = sync.PROVENANCE_FILE, pathlib.Path(prov)
    try:
        sync.update_provenance_pins(
            {"opensuse": ("opensuse", "NEW" + "0" * 37, "2026-10-11"),
             "slfo": ("opensuse-slfo-main", "S" + "1" * 39, "2026-10-11")})
        text = open(prov).read()
    finally:
        sync.PROVENANCE_FILE = old
    assert "OLD" not in text
    assert text.count("-whitelists:") == 2
    assert "# slfo-whitelists: opensuse-slfo-main @ " in text


def test_generator_rewrite_pins_roundtrip():
    """--refresh persists pins into the script or the PR rots on --check."""
    import re
    import tempfile
    with open(os.path.join(HERE, "generate-distro-configs.py")) as f:
        src = f.read()
    m = re.search(r'"opensuse": \(\s*"([0-9a-f]{40})",\s*"(\d{4}-\d{2}-\d{2})",',
                  src)
    sha = m.group(1)
    d = tempfile.mkdtemp()
    path = sync.Path(os.path.join(d, "gen.py"))
    path.write_text(src)
    gen.rewrite_pins(path, {"opensuse": ("f" * 40, "2026-12-31")})
    out = path.read_text()
    assert "f" * 40 in out and "2026-12-31" in out
    assert sha not in out
    # Idempotent: rewriting the same pins again is a no-op diff.
    gen.rewrite_pins(path, {"opensuse": ("f" * 40, "2026-12-31")})
    assert path.read_text() == out


def test_provenance_strip_keeps_rest():
    text = ("# opensuse: opensuse @ AAA (2026-01-01)\n"
            "# opensuse-whitelists: opensuse @ BBB (2026-10-09)\n"
            "# slfo-whitelists: opensuse-slfo-main @ CCC (2026-06-18)\n"
            "# Extra Filters appended\n")
    stripped = gen.strip_sync_owned_provenance(text)
    assert "-whitelists:" not in stripped
    assert "# opensuse: opensuse @ AAA (2026-01-01)" in stripped
    assert "# Extra Filters appended" in stripped


def test_provenance_strip_drops_dedup_section():
    """The TIP-flavoured dedup section is sync-owned for --check purposes."""
    text = ("# opensuse: opensuse @ AAA (2026-01-01)\n"
            "#\n"
            "# Pruned Filters entries:\n"
            "#\n"
            "# SLFO files byte-identical to openSUSE (not vendored twice;\n"
            "# the generated Rust consts fall back to the openSUSE copy):\n"
            "#   slfo/cron-whitelist.toml\n")
    stripped = gen.strip_sync_owned_provenance(text)
    assert "byte-identical" not in stripped
    assert "slfo/cron-whitelist.toml" not in stripped
    assert "# opensuse: opensuse @ AAA (2026-01-01)" in stripped
    assert "# Pruned Filters entries:" in stripped


def test_check_rs_deduped_prefers_disk_for_managed():
    """--check follows on-disk dedup for sync-managed files only."""
    import pathlib
    import tempfile
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "opensuse").mkdir()
    (d / "slfo").mkdir()
    (d / "opensuse" / "cron-whitelist.toml").write_text("same")
    (d / "opensuse" / "licenses.toml").write_text("same")
    # Managed file materialized on disk (TIP divergence): stays slfo/.
    (d / "slfo" / "cron-whitelist.toml").write_text("diverged")
    got = gen.check_rs_deduped(["cron-whitelist.toml", "licenses.toml"], d)
    assert "cron-whitelist.toml" not in got
    assert "licenses.toml" in got
    # Reconverged on disk: falls back even though PINS regen dedups nothing.
    (d / "slfo" / "cron-whitelist.toml").write_text("same")
    got = gen.check_rs_deduped([], d)
    assert "cron-whitelist.toml" in got


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
