#!/usr/bin/env python3
"""Generate the vendored systemd preset data for rpmcrab.

Fetches the system preset files shipped by the SUSE preset packages
from their src.opensuse.org pool mirrors and emits one ordered rule
file per flavour under ``crates/rpmcrab-core/data/presets/``. The
check (``SystemdInstallCheck``) consults these files offline at scan
time; no network fetch happens during a scan. Refreshing the data is
a human-reviewed PR, never an auto-commit: the monthly
``systemd-presets-staleness`` CI job runs this script in ``--check``
mode and fails with the diff when the vendored data goes stale.

Fetch route: the OBS API requires authentication even for public
packages, so the script fetches from the public pool git mirrors
instead. The mirror content was verified byte-identical to the OBS
package sources (branding-openSUSE, common-SUSE, branding-SLE, and
both common-SUSE revisions). Generation always reads from git, in CI
and locally alike, so a mirror sync lag can only delay the staleness
signal, never fake one.

Sources (install names verified against the package specs):

- opensuse (branch ``factory``):
    pool/systemd-presets-branding-openSUSE/default-openSUSE.preset
        -> 90-default-openSUSE.preset
    pool/systemd-presets-common-suse/default-SUSE.preset
        -> 95-default-SUSE.preset
    pool/systemd-presets-common-suse/99-default-disable.preset
        -> 99-default-disable.preset
- slfo (branch ``slfo-main``):
    pool/systemd-presets-branding-SLE/default-SLE.preset
        -> 90-default-SLE.preset
    pool/systemd-presets-common-suse/default-SUSE.preset
        -> 95-default-SUSE.preset
    pool/systemd-presets-common-suse/99-default-disable.preset
        -> 99-default-disable.preset

Preset semantics (systemd.preset(5)): files apply in lexicographic
install-name order; within a file, lines apply top to bottom; the
first rule matching a unit decides whether it is enabled. A rule
pattern uses shell-style wildcards. A template pattern
(``foo@.service``) with trailing instance names expands to one rule
per instance (``foo@bar.service``, ...). Comments (first
non-whitespace character ``#`` or ``;``) and blank lines are ignored.

Usage:
    scripts/generate-systemd-presets.py [--check] [--git-base URL]

    --check      regenerate in memory and diff against the committed
                 files; exit 1 with a unified diff on any divergence.
                 A fetch or parse failure exits 2 with the error.
    --git-base   pool git base URL (default https://src.opensuse.org/pool).
"""

import argparse
import difflib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

GIT_BASE = "https://src.opensuse.org/pool"
REPO = Path(__file__).resolve().parent.parent
OUT_DIR = REPO / "crates" / "rpmcrab-core" / "data" / "presets"

# (pool repo, branch, source file, install name), in install-name order.
SOURCES = {
    "opensuse": [
        ("systemd-presets-branding-openSUSE", "factory", "default-openSUSE.preset", "90-default-openSUSE.preset"),
        ("systemd-presets-common-suse", "factory", "default-SUSE.preset", "95-default-SUSE.preset"),
        ("systemd-presets-common-suse", "factory", "99-default-disable.preset", "99-default-disable.preset"),
    ],
    "slfo": [
        ("systemd-presets-branding-SLE", "slfo-main", "default-SLE.preset", "90-default-SLE.preset"),
        ("systemd-presets-common-suse", "slfo-main", "default-SUSE.preset", "95-default-SUSE.preset"),
        ("systemd-presets-common-suse", "slfo-main", "99-default-disable.preset", "99-default-disable.preset"),
    ],
}


class FetchError(Exception):
    """A preset source could not be fetched."""


class PresetParseError(Exception):
    """A preset source does not parse."""


def clone_repo(git_base, repo, branch, dest):
    """Shallow-clone one branch; return its HEAD commit."""
    url = f"{git_base}/{repo}"
    try:
        subprocess.run(
            ["git", "clone", "-q", "--depth", "1", "--branch", branch, url, str(dest)],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        head = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = getattr(exc, "stderr", "") or exc
        raise FetchError(f"cloning {url} (branch {branch}) failed: {detail}") from exc
    return head.stdout.strip()


def parse_preset_file(text, install_name):
    """Parse one preset file into [(action, pattern)] in file order.

    Comments and blank lines are dropped. A template pattern with
    trailing instance names expands to one rule per instance.
    Anything else malformed fails loudly: silently guessing at
    preset policy would wrongly credit units at scan time.
    """
    rules = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        words = line.split()
        if len(words) < 2:
            raise PresetParseError(f"{install_name}:{lineno}: expected '<action> <pattern>', got {raw!r}")
        action, pattern, instances = words[0], words[1], words[2:]
        if action not in ("enable", "disable"):
            raise PresetParseError(
                f"{install_name}:{lineno}: unknown directive {action!r} (want enable/disable)"
            )
        if instances:
            # Instance names are valid only for a bare template pattern:
            # exactly one '@' with nothing between it and the suffix.
            head, sep, tail = pattern.partition("@")
            if not sep or not tail.startswith(".") or "@" in tail:
                raise PresetParseError(
                    f"{install_name}:{lineno}: instance names {instances!r} "
                    f"given for non-template pattern {pattern!r}"
                )
            for instance in instances:
                rules.append((action, f"{head}@{instance}{tail}"))
        else:
            rules.append((action, pattern))
    return rules


def toml_escape(value):
    """Escape a string for a TOML basic string (patterns are unit names)."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_flavour(flavour, entries):
    """Render one generated data file.

    entries: [(install_name, provenance, [(action, pattern)])] in
    install-name order. The emitted rule order is the evaluation
    order: first match wins.
    """
    lines = [
        "# Generated by scripts/generate-systemd-presets.py — do not edit by hand.",
        "#",
        "# Sources (pool git mirrors, verified byte-identical to the OBS package sources):",
    ]
    for install_name, provenance, _ in entries:
        lines.append(f"#   {provenance} -> {install_name}")
    lines += [
        "#",
        "# Preset semantics (systemd.preset(5)): files apply in lexicographic",
        "# install-name order; within a file, lines apply top to bottom; the",
        "# first rule matching a unit decides whether it is enabled.",
        "",
    ]
    for install_name, _, rules in entries:
        for action, pattern in rules:
            lines.append("[[SystemdPresetRule]]")
            lines.append(f'file = "{toml_escape(install_name)}"')
            lines.append(f'action = "{action}"')
            lines.append(f'pattern = "{toml_escape(pattern)}"')
    return "\n".join(lines) + "\n"


def generate(git_base):
    """Generate {flavour: (filename, text)} for every flavour."""
    result = {}
    with tempfile.TemporaryDirectory(prefix="rpmcrab-presets-") as tmp:
        clones = {}
        for flavour, sources in SOURCES.items():
            install_names = [install for *_, install in sources]
            if install_names != sorted(install_names):
                raise PresetParseError(
                    f"{flavour}: sources are not in install-name order: {install_names}"
                )
            entries = []
            for repo, branch, source_file, install_name in sources:
                key = (repo, branch)
                if key not in clones:
                    dest = Path(tmp) / f"{repo}-{branch}"
                    head = clone_repo(git_base, repo, branch, dest)
                    clones[key] = (dest, head)
                dest, head = clones[key]
                path = dest / source_file
                if not path.exists():
                    raise FetchError(f"{repo}@{branch}: {source_file} not found in the clone")
                rules = parse_preset_file(path.read_text(encoding="utf-8"), install_name)
                provenance = f"{repo}@{branch}:{source_file} (commit {head})"
                entries.append((install_name, provenance, rules))
            result[flavour] = (f"{flavour}.toml", render_flavour(flavour, entries))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="diff only, do not write")
    parser.add_argument("--git-base", default=GIT_BASE, help="pool git base URL")
    args = parser.parse_args(argv)
    try:
        result = generate(args.git_base)
    except (FetchError, PresetParseError) as exc:
        print(f"generate-systemd-presets: error: {exc}", file=sys.stderr)
        return 2
    failures = []
    for flavour, (filename, text) in result.items():
        target = OUT_DIR / filename
        if args.check:
            have = target.read_text(encoding="utf-8") if target.exists() else ""
            if have != text:
                failures.append(filename)
                diff = difflib.unified_diff(
                    have.splitlines(),
                    text.splitlines(),
                    fromfile=f"committed/{filename}",
                    tofile=f"generated/{filename}",
                    lineterm="",
                )
                print("\n".join(diff))
        else:
            OUT_DIR.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            rules = text.count("[[SystemdPresetRule]]")
            print(f"wrote {target} ({rules} rules)")
    if failures:
        print(
            "generate-systemd-presets: stale vendored preset data: "
            + ", ".join(failures)
            + " (regenerate with scripts/generate-systemd-presets.py and land via PR)",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
