#!/usr/bin/env python3
"""Tests for scripts/watch-upstream-configs.py.

Hermetic: the generator module loads for real (its tables are the
contract the watch mirrors), but every network seam — tip resolution,
commit enumeration and generate() itself — is stubbed, and the shipped
tree is a temp dir. The git-range test builds a throwaway repository
so the local-checkout path runs end to end. Each test guards a way the
watch could misreport: crying drift on sync-owned files, losing the
commit list, or signalling the wrong CHANGED value to the workflow.

Run:  python3 scripts/test_watch_upstream_configs.py
"""

import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location(
        "watch_upstream_configs", os.path.join(HERE, "watch-upstream-configs.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


watch = _load()
gen = watch.gen


def _git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_commits_in_range_git():
    """Local-checkout enumeration: chronological commits, config files
    filtered to the vendored subtree, no compare URL."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "watch@example.invalid")
        _git(repo, "config", "user.name", "Watch Test")
        cfg = repo / "configs" / "openSUSE"
        cfg.mkdir(parents=True)
        (cfg / "users-groups.toml").write_text("a = 1\n", encoding="utf-8")
        (repo / "README").write_text("x\n", encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "base")
        base = _git(repo, "rev-parse", "HEAD")
        (cfg / "users-groups.toml").write_text("a = 2\n", encoding="utf-8")
        _git(repo, "commit", "-qam", "bump users-groups")
        (repo / "README").write_text("y\n", encoding="utf-8")
        _git(repo, "commit", "-qam", "unrelated readme change")
        tip = _git(repo, "rev-parse", "HEAD")

        commits, files, url, total = watch.commits_in_range(base, tip, repo)
        assert total == 2 and len(commits) == 2, commits
        assert commits[0]["subject"] == "bump users-groups", commits
        assert commits[1]["subject"] == "unrelated readme change", commits
        assert len(commits[0]["date"]) == 10, commits
        assert files == ["configs/openSUSE/users-groups.toml"], files
        assert url is None


def _fake_generate(files, provenance):
    def fake_generate(ref_dir=None, pins=None):
        result = {
            "opensuse": {
                "sha": "0" * 40,
                "date": "2026-01-01",
                "branch": "opensuse",
                "files": files,
            }
        }
        return (
            result,
            provenance,
            [],
            [],
            [],
            sorted(files),
            [],
            [],
            [],
            [],
            [],
            [],
            [],
        )

    return fake_generate


def test_compute_drift_ownership_split():
    """Drift covers generator-owned files and the pin line of
    PROVENANCE; a sync-managed file and the sync-owned whitelist pin
    line never read as drift."""
    files = {
        "opensuse.toml": "new text\n",
        "users-groups.toml": "same text\n",
        "cron-whitelist.toml": "regenerated sync text\n",
    }
    provenance = "# opensuse: opensuse @ tip (2026-01-01)\n# opensuse-whitelists: opensuse @ tip (2026-01-01)\n"
    with tempfile.TemporaryDirectory() as tmp:
        distro = Path(tmp)
        flavor_dir = distro / "opensuse"
        flavor_dir.mkdir()
        (flavor_dir / "opensuse.toml").write_text("old text\n", encoding="utf-8")
        (flavor_dir / "users-groups.toml").write_text(
            "same text\n", encoding="utf-8"
        )
        (flavor_dir / "cron-whitelist.toml").write_text(
            "shipped sync text\n", encoding="utf-8"
        )
        (distro / "PROVENANCE").write_text(
            "# opensuse: opensuse @ pin (2025-01-01)\n"
            "# opensuse-whitelists: opensuse @ other (2025-06-01)\n",
            encoding="utf-8",
        )
        rs_path = Path(tmp) / "distro_files_generated.rs"
        rs_path.write_text(gen.emit_rs(sorted(files)), encoding="utf-8")
        with mock.patch.object(gen, "generate", _fake_generate(files, provenance)), \
            mock.patch.object(gen, "DISTRO_DIR", distro), \
            mock.patch.object(gen, "GENERATED_RS", rs_path):
            drift = watch.compute_drift(None, {"opensuse": ("0" * 40, "2026-01-01")})
    labels = [label for label, _ in drift]
    assert labels == ["opensuse/opensuse.toml", "PROVENANCE"], labels


def test_compute_drift_clean_tree():
    """A regenerated tree identical to the shipped one reports no drift
    (the delta layer has cancelled, or upstream changed nothing the
    generator emits)."""
    files = {"opensuse.toml": "same\n", "cron-whitelist.toml": "sync\n"}
    provenance = "# opensuse: opensuse @ pin (2025-01-01)\n"
    with tempfile.TemporaryDirectory() as tmp:
        distro = Path(tmp)
        flavor_dir = distro / "opensuse"
        flavor_dir.mkdir()
        for name, text in files.items():
            (flavor_dir / name).write_text(text, encoding="utf-8")
        (distro / "PROVENANCE").write_text(provenance, encoding="utf-8")
        rs_path = Path(tmp) / "distro_files_generated.rs"
        rs_path.write_text(gen.emit_rs(sorted(files)), encoding="utf-8")
        with mock.patch.object(gen, "generate", _fake_generate(files, provenance)), \
            mock.patch.object(gen, "DISTRO_DIR", distro), \
            mock.patch.object(gen, "GENERATED_RS", rs_path):
            drift = watch.compute_drift(None, {"opensuse": ("0" * 40, "2026-01-01")})
    assert drift == [], drift


def _run_main(argv, env_extra=None):
    env = dict(os.environ)
    env.pop("GITHUB_OUTPUT", None)
    if env_extra:
        env.update(env_extra)
    with mock.patch.object(sys, "argv", argv), mock.patch.dict(
        os.environ, env, clear=True
    ):
        return watch.main()


def test_main_no_movement():
    """Tips equal to the pins: exit 0 and changed=false signalled."""
    pin_sha, pin_date, _branch = next(iter(gen.PINS.values()))
    with tempfile.TemporaryDirectory() as tmp:
        gh_out = Path(tmp) / "github-output"
        with mock.patch.object(
            watch, "resolve_tip", lambda branch, ref_dir: (pin_sha, pin_date)
        ):
            rc = _run_main(
                ["watch-upstream-configs.py"],
                {"GITHUB_OUTPUT": str(gh_out)},
            )
        assert rc == 0
        assert gh_out.read_text(encoding="utf-8") == "changed=false\n"


def test_main_reports_drift():
    """A moved tip: the report file carries the commit list and the
    drifted files, and changed=true is signalled."""
    old_sha, _old_date, _branch = next(iter(gen.PINS.values()))
    new_sha = "f" * 40
    commits = [
        {
            "sha": new_sha,
            "date": "2026-01-02",
            "subject": "add the new service stanza",
            "url": "https://example.invalid/commit",
        }
    ]
    with tempfile.TemporaryDirectory() as tmp:
        gh_out = Path(tmp) / "github-output"
        report = Path(tmp) / "report.md"
        with mock.patch.object(
            watch, "resolve_tip", lambda branch, ref_dir: (new_sha, "2026-01-02")
        ), mock.patch.object(
            watch,
            "commits_in_range",
            lambda old, new, ref_dir: (
                commits,
                ["configs/openSUSE/opensuse.toml"],
                "https://example.invalid/compare",
                1,
            ),
        ), mock.patch.object(
            watch,
            "compute_drift",
            lambda ref_dir, tip_pins: [("opensuse/opensuse.toml", "diff body")],
        ):
            rc = _run_main(
                [
                    "watch-upstream-configs.py",
                    "--report-file",
                    str(report),
                ],
                {"GITHUB_OUTPUT": str(gh_out)},
            )
        assert rc == 0
        assert gh_out.read_text(encoding="utf-8") == "changed=true\n"
        text = report.read_text(encoding="utf-8")
        assert "add the new service stanza" in text, text
        assert "`opensuse/opensuse.toml`" in text, text
        assert old_sha[:12] in text and new_sha[:12] in text, text


def test_render_report_caps_commit_list():
    """Long ranges are capped in the body; the overflow line carries
    the remainder count and the compare link."""
    commits = [
        {
            "sha": f"{i:040x}",
            "date": "2026-01-01",
            "subject": f"commit {i}",
            "url": None,
        }
        for i in range(watch.COMMIT_LIST_CAP + 10)
    ]
    movement = {
        "flavor": "opensuse",
        "branch": "opensuse",
        "old_sha": "a" * 40,
        "old_date": "2025-01-01",
        "new_sha": "b" * 40,
        "new_date": "2026-01-01",
        "commits": commits,
        "config_files": [],
        "compare_url": "https://example.invalid/compare",
        "total_commits": len(commits),
        "commits_error": None,
    }
    text = watch.render_report([movement], [])
    assert text.count("commit ") == watch.COMMIT_LIST_CAP, text
    assert "and 10 more commits" in text, text
    assert "https://example.invalid/compare" in text, text


def main():
    tests = [
        (name, fn)
        for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn)
    ]
    for name, fn in tests:
        fn()
        print(f"ok {name}")
    print(f"{len(tests)} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
