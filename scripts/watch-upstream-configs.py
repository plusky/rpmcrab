#!/usr/bin/env python3
"""Report upstream rpmlint movement past the vendored distro-config pins.

The vendored distro configs (crates/rpmcrab-core/data/distro/) are
generated from upstream rpmlint at the commits pinned in
scripts/generate-distro-configs.py (PINS). This watch resolves the
current tip of each pinned upstream branch, regenerates the flavour at
the tip through the generator's own pipeline, and diffs the result
against the shipped tree. The generator's delta layer (the EXTRA, DROP,
PRUNE and RETARGET tables plus the Factory digest adjudications) applies
to the regenerated tree exactly as it applies to the shipped one, so
every reported difference originates upstream.

Files the daily upstream-whitelist-sync job owns (SYNC_MANAGED_FILES in
the generator) advance at branch tip on their own cadence and are
excluded from the comparison, mirroring the generator's --check split;
the PROVENANCE comparison likewise drops the sync-owned whitelist pin
lines on both sides.

The report names the upstream commits in the pin range (pin..tip) and
the vendored files a refresh rewrites, so the refresh stays a reviewed,
mechanical step: the monthly distro-config-sync job opens it as a PR,
and the refresh procedure in the generator's header documents the
manual path.

Usage:
    scripts/watch-upstream-configs.py [--ref-dir DIR] [--report-file PATH]

    --ref-dir    resolve tips, fetch configs and list commits from a
                 local rpmlint checkout instead of the GitHub API (the
                 branch and both pin-range endpoints must exist in it).
    --report-file
                 write the Markdown drift report to PATH as well as
                 printing it (the weekly CI job files it as the
                 tracking issue's body/comment).

Exit 0 on every completed watch, drift or no drift. Signals drift via
stdout (CHANGED=true/false plus one watch-summary line per moved
flavour) and $GITHUB_OUTPUT (changed=true/false) for workflow
consumption. Resolution or generation failures raise and fail the run:
a watch that cannot see upstream says so loudly instead of reporting
the pins as current.
"""

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Commits listed per flavour before the report points at the compare
# view for the remainder.
COMMIT_LIST_CAP = 50
# Size budget for the embedded per-file diffs: issue bodies are capped
# at 65536 characters, and the diff detail is the only unbounded part
# of the report.
DIFF_BUDGET_CHARS = 30000


def _load_generator_module():
    spec = importlib.util.spec_from_file_location(
        "gen_distro_configs", HERE / "generate-distro-configs.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# The generator is the source of truth for the pins, the vendored file
# set and the sync-ownership split; the watch loads all three from it.
gen = _load_generator_module()


def resolve_tip(branch, ref_dir):
    """Current (sha, date) of an upstream branch.

    Without a ref dir this is the generator's own resolver (the GitHub
    API); with one, the branch ref in the local checkout.
    """
    if ref_dir is None:
        return gen.latest_upstream_sha(branch)
    for ref in (branch, f"origin/{branch}"):
        out = subprocess.run(
            [
                "git",
                "-C",
                str(ref_dir),
                "rev-parse",
                "--verify",
                "--quiet",
                f"{ref}^{{commit}}",
            ],
            capture_output=True,
            text=True,
        )
        if out.returncode == 0:
            sha = out.stdout.strip()
            date = subprocess.run(
                ["git", "-C", str(ref_dir), "log", "-1", "--format=%cs", sha],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            return sha, date
    raise RuntimeError(f"branch {branch!r} not found in checkout {ref_dir}")


def _commit_entry(sha, date, subject, url):
    return {"sha": sha, "date": date, "subject": subject, "url": url}


def commits_in_range(old, new, ref_dir):
    """Upstream commits in old..new and the config files they changed.

    Returns (commits, config_files, compare_url, total): commits are
    chronological dicts {sha, date, subject, url}; config_files is the
    sorted set of paths under configs/openSUSE/ that differ between the
    range endpoints; compare_url is the GitHub compare view (None for
    a local checkout); total is the full commit count (the API list is
    the compare response's page, capped by GitHub at 250 commits).
    """
    if ref_dir is not None:
        out = subprocess.run(
            [
                "git",
                "-C",
                str(ref_dir),
                "log",
                "--reverse",
                "--format=%H%x1f%cs%x1f%s",
                f"{old}..{new}",
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        commits = []
        for line in out.splitlines():
            sha, date, subject = line.split("\x1f", 2)
            commits.append(_commit_entry(sha, date, subject, None))
        files = subprocess.run(
            [
                "git",
                "-C",
                str(ref_dir),
                "diff",
                "--name-only",
                old,
                new,
                "--",
                "configs/openSUSE/",
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
        return commits, sorted(files), None, len(commits)
    url = (
        f"https://api.github.com/repos/{gen.UPSTREAM_REPO}"
        f"/compare/{old}...{new}"
    )
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "rpmcrab-upstream-config-watch",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.load(resp)
    commits = [
        _commit_entry(
            c["sha"],
            c["commit"]["committer"]["date"][:10],
            c["commit"]["message"].splitlines()[0]
            if c["commit"]["message"]
            else "",
            c["html_url"],
        )
        for c in data.get("commits", [])
    ]
    files = sorted(
        {
            f["filename"]
            for f in data.get("files", [])
            if f["filename"].startswith("configs/openSUSE/")
        }
    )
    return commits, files, data.get("html_url"), data.get(
        "total_commits", len(commits)
    )


def compute_drift(ref_dir, tip_pins):
    """Regenerate at the tip pins; diff the generator-owned artefacts.

    Returns [(label, unified diff)] in a stable order. Sync-managed
    whitelist files are skipped (the daily sync owns them at tip), and
    the PROVENANCE comparison strips the sync-owned whitelist pin
    lines on both sides — the same ownership split as the generator's
    --check, whose diff labels this mirrors.
    """
    (
        result,
        provenance,
        _pruned_log,
        _pkg_pruned_log,
        _pie_pruned_log,
        files_out,
        _dropped_log,
        _retargeted_log,
        _scoped_log,
        _deduped_log,
        _threshold_log,
        _added_log,
        _adjudicated_log,
    ) = gen.generate(ref_dir=ref_dir, pins=tip_pins)

    drift = []
    for flavor, data in result.items():
        for filename in sorted(data["files"]):
            if filename in gen.SYNC_MANAGED_FILES:
                continue
            label = f"{flavor}/{filename}"
            shipped_path = gen.DISTRO_DIR / flavor / filename
            if not shipped_path.exists():
                drift.append((label, f"missing vendored file: {label}"))
                continue
            shipped = shipped_path.read_text(encoding="utf-8")
            if shipped != data["files"][filename]:
                drift.append(
                    (
                        label,
                        gen._diff_text(
                            f"vendored/{label}",
                            shipped,
                            f"generated-at-tip/{label}",
                            data["files"][filename],
                        ),
                    )
                )
    shipped_prov_path = gen.DISTRO_DIR / "PROVENANCE"
    if not shipped_prov_path.exists():
        drift.append(("PROVENANCE", "missing vendored file: PROVENANCE"))
    else:
        shipped_prov = gen.strip_sync_owned_provenance(
            shipped_prov_path.read_text(encoding="utf-8")
        )
        tip_prov = gen.strip_sync_owned_provenance(provenance)
        if shipped_prov != tip_prov:
            drift.append(
                (
                    "PROVENANCE",
                    gen._diff_text(
                        "vendored/PROVENANCE",
                        shipped_prov,
                        "generated-at-tip/PROVENANCE",
                        tip_prov,
                    ),
                )
            )
    want_rs = gen.emit_rs(gen.check_rs_files(files_out, gen.DISTRO_DIR))
    have_rs = (
        gen.GENERATED_RS.read_text(encoding="utf-8")
        if gen.GENERATED_RS.exists()
        else ""
    )
    if have_rs != want_rs:
        drift.append(
            (
                "src/distro_files_generated.rs",
                gen._diff_text(
                    "vendored/src/distro_files_generated.rs",
                    have_rs,
                    "generated/src/distro_files_generated.rs",
                    want_rs,
                ),
            )
        )
    return drift


def render_report(movements, drift):
    """Markdown drift report: the tracking issue's body/comment text.

    movements: [{flavor, branch, old_sha, old_date, new_sha, new_date,
    commits, config_files, compare_url, total_commits, commits_error}]
    drift: [(label, diff)] from compute_drift.
    """
    lines = [
        "## Upstream distro-config drift",
        "",
        "Upstream rpmlint moved past the vendored distro-config pins. "
        "Regenerating the vendored flavour at the upstream tip through "
        "scripts/generate-distro-configs.py rewrites the files listed "
        "below; the generator's delta layer applies to both trees, so "
        "each listed difference originates upstream.",
        "",
        "| Flavour | Branch | Pinned | Upstream tip |",
        "| --- | --- | --- | --- |",
    ]
    for m in movements:
        lines.append(
            f"| {m['flavor']} | {m['branch']} | `{m['old_sha'][:12]}` "
            f"({m['old_date']}) | `{m['new_sha'][:12]}` ({m['new_date']}) |"
        )
    for m in movements:
        lines += ["", f"### Upstream commits: {m['flavor']} ({m['branch']})", ""]
        if m["commits_error"]:
            lines.append(
                f"Commit list unavailable ({m['commits_error']}); the pin "
                f"range is `{m['old_sha'][:12]}..{m['new_sha'][:12]}`."
            )
        else:
            for c in m["commits"][:COMMIT_LIST_CAP]:
                if c["url"]:
                    lines.append(
                        f"- [`{c['sha'][:12]}`]({c['url']}) "
                        f"{c['subject']} ({c['date']})"
                    )
                else:
                    lines.append(
                        f"- `{c['sha'][:12]}` {c['subject']} ({c['date']})"
                    )
            listed = min(len(m["commits"]), COMMIT_LIST_CAP)
            extra = m["total_commits"] - listed
            if extra > 0:
                where = (
                    f" — full list: {m['compare_url']}"
                    if m["compare_url"]
                    else ""
                )
                lines.append(f"- … and {extra} more commits{where}")
            elif m["compare_url"]:
                lines.append(f"- Compare view: {m['compare_url']}")
        if m["config_files"]:
            lines += [
                "",
                "Config files changed upstream under `configs/openSUSE/`:",
                "",
            ]
            lines += [f"- `{f}`" for f in m["config_files"]]
    lines += ["", f"### Vendored files a refresh rewrites ({len(drift)})", ""]
    lines += [f"- `{label}`" for label, _ in drift]
    budget = DIFF_BUDGET_CHARS
    shown = 0
    for label, diff in drift:
        block = (
            f"\n<details>\n<summary>Diff: {label}</summary>\n\n"
            f"```diff\n{diff}\n```\n\n</details>"
        )
        if len(block) > budget:
            break
        lines.append(block)
        budget -= len(block)
        shown += 1
    if shown < len(drift):
        lines.append(
            f"\nDiff detail for the remaining {len(drift) - shown} file(s) "
            "is not shown here; the refresh PR carries the full diff."
        )
    lines += [
        "",
        "Refresh path: the monthly distro-config-sync job opens the "
        "refresh PR at the new pins; the manual procedure (the generator "
        "run, the generator test suite and the severity-inventory "
        "regeneration) is documented in scripts/generate-distro-configs.py.",
        "",
        "Produced by the weekly upstream-config-watch job.",
    ]
    return "\n".join(lines) + "\n"


def _signal_changed(changed):
    # Signal via GITHUB_OUTPUT for workflow consumption
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"changed={'true' if changed else 'false'}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ref-dir", help="local rpmlint checkout instead of GitHub")
    ap.add_argument(
        "--report-file",
        help="write the Markdown drift report to this path (drift only)",
    )
    args = ap.parse_args()
    ref_dir = Path(args.ref_dir) if args.ref_dir else None

    movements = []
    tip_pins = {}
    for flavor, (sha, date, branch) in gen.PINS.items():
        tip_sha, tip_date = resolve_tip(branch, ref_dir)
        tip_pins[flavor] = (tip_sha, tip_date)
        if tip_sha != sha:
            movements.append(
                {
                    "flavor": flavor,
                    "branch": branch,
                    "old_sha": sha,
                    "old_date": date,
                    "new_sha": tip_sha,
                    "new_date": tip_date,
                }
            )

    if not movements:
        pins_desc = ", ".join(
            f"{flavor} @ {sha[:12]}"
            for flavor, (sha, _date, _branch) in gen.PINS.items()
        )
        print(
            "watch-summary: no upstream movement past the vendored pins "
            f"({pins_desc})"
        )
        print("CHANGED=false")
        _signal_changed(False)
        return 0

    for m in movements:
        try:
            commits, config_files, compare_url, total = commits_in_range(
                m["old_sha"], m["new_sha"], ref_dir
            )
            m.update(
                commits=commits,
                config_files=config_files,
                compare_url=compare_url,
                total_commits=total,
                commits_error=None,
            )
        except Exception as e:
            # Enumeration degrades; the drift report stands on the
            # regeneration diff, and the failure is named in it.
            m.update(
                commits=[],
                config_files=[],
                compare_url=None,
                total_commits=0,
                commits_error=f"{type(e).__name__}: {e}",
            )

    drift = compute_drift(ref_dir, tip_pins)
    report = render_report(movements, drift)
    print(report)
    for m in movements:
        print(
            f"watch-summary: {m['flavor']}: {m['branch']} "
            f"{m['old_sha'][:12]}..{m['new_sha'][:12]} "
            f"commits={m['total_commits']} drifted-files={len(drift)}"
        )
    print("CHANGED=true")
    if args.report_file:
        Path(args.report_file).write_text(report, encoding="utf-8")
    _signal_changed(True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
