#!/usr/bin/env python3
"""Flag stale entries in the Python bytecode magic table.

The checker compares a .pyc header's first word, masked to 16 bits,
against `crates/rpmcrab-core/data/python-magic-values.toml`. A table
value is the low 16 bits of the version's CPython `MAGIC_NUMBER`:
up to 3.13 the upstream spelling is
`MAGIC_NUMBER = (N).to_bytes(2, 'little') + b'\\r\\n'` in
`Lib/importlib/_bootstrap_external.py`; from 3.14 it is the
`PYC_MAGIC_NUMBER` define in `Include/internal/pycore_magic_number.h`,
which is the same two-byte value.

The sweep needs no remembering: it probes CPython release branches
upward from 3.8 and stops at the first branch that does not exist,
so a newly cut release branch is picked up automatically. The
`main` branch is deliberately excluded: its magic is a moving target
during the development cycle, and the table gains the entry when the
release branch is cut.

Verdicts, per probed version:

- MISSING: the version is absent from the table.
- STALE-VALUE: the version is present but its list does not contain
  the branch-head magic. A version's list may hold several magics
  (3.7 shipped five across its development cycle); only the
  branch-head value is required to be present.

The table is cumulative: entries for versions with no probed branch
are carried and never flagged for removal.

Comparison is on BASE values. The checker adds one for exactly
versions 3.0 and 3.1 at check time; that adjustment is not baked
into the table and is not applied here.

Exit status is 0 when every probed version is covered, 1 when any
version is MISSING or STALE-VALUE, 2 when the check could not be
completed (network failure, an unreadable or invalid table, or an
upstream layout the script does not recognise). Table edits stay
human-reviewed: this script never edits the table itself.

Only a bootstrap 404 stops the sweep: a missing header for an
existing branch is an unrecognised layout, not a missing branch,
so it fails the check instead of silently ending the probe run.

Table rows are validated strictly at load: each entry needs a
major.minor version string and a non-empty list of integer magics
in the low-16-bit range, and versions must not repeat.
"""

import argparse
import re
import sys
import tomllib
import urllib.error
import urllib.request

BASE_URL = "https://raw.githubusercontent.com/python/cpython"

TO_BYTES_RE = re.compile(
    r"MAGIC_NUMBER\s*=\s*\((\d+)\)\.to_bytes\(2,\s*['\"]little['\"]\)"
)
PYC_DEFINE_RE = re.compile(r"#define\s+PYC_MAGIC_NUMBER\s+(\d+)")


class BranchMissing(Exception):
    """A CPython release branch does not exist (HTTP 404)."""


class FetchError(Exception):
    """A fetch failed for a reason other than a missing branch."""


def fetch_text(url, timeout=30):
    """Fetch a URL, retrying once on a transient failure.

    Raises BranchMissing on HTTP 404, FetchError otherwise.
    """
    last_error = None
    for _attempt in range(2):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                return response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise BranchMissing(url) from exc
            last_error = exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last_error = exc
    raise FetchError(f"fetching {url} failed: {last_error}")


def derive_magic(version, fetch, base_url=BASE_URL):
    """Branch-head magic value for a CPython release version.

    `version` is "3.12" style. `fetch` is a callable taking a URL
    and returning its text, raising BranchMissing or FetchError.
    Returns the low-16-bit table value.
    """
    branch = version
    bootstrap_url = (
        f"{base_url}/{branch}/Lib/importlib/_bootstrap_external.py"
    )
    # A bootstrap 404 propagates: the branch does not exist, and the
    # sweep stops. Any other fetch failure propagates as FetchError.
    bootstrap = fetch(bootstrap_url)
    match = TO_BYTES_RE.search(bootstrap)
    if match:
        return int(match.group(1))
    header_url = (
        f"{base_url}/{branch}/Include/internal/pycore_magic_number.h"
    )
    try:
        header = fetch(header_url)
    except BranchMissing as exc:
        # The branch exists (its bootstrap fetched); a missing header
        # is an unrecognised layout, not a missing branch. Converting
        # it keeps a later version from reporting falsely clean when
        # the sweep would otherwise stop here.
        raise FetchError(
            f"header missing for existing branch CPython {version}"
        ) from exc
    match = PYC_DEFINE_RE.search(header)
    if match:
        return int(match.group(1))
    raise FetchError(
        f"no recognised magic-number spelling for CPython {version}"
    )


_VERSION_RE = re.compile(r"^\d+\.\d+$")


def load_table(path):
    """Table file path -> {version string: [magic, ...]}.

    Rows are validated strictly: each entry needs a major.minor
    version string and a non-empty list of integer magics in the
    low-16-bit range, and versions must not repeat (like the Rust
    table loader). Raises ValueError on any violation, OSError or
    TOMLDecodeError on unreadable input.
    """
    with open(path, "rb") as fh:
        parsed = tomllib.load(fh)
    table = {}
    for entry in parsed.get("version", []):
        if not isinstance(entry, dict):
            raise ValueError(f"table entry is not a table: {entry!r}")
        version = entry.get("version")
        magics = entry.get("magics")
        if not isinstance(version, str) or not _VERSION_RE.match(version):
            raise ValueError(
                f"table entry has no major.minor version: {entry!r}"
            )
        if version in table:
            raise ValueError(f"duplicate table entry for version {version}")
        if not isinstance(magics, list) or not magics:
            raise ValueError(f"table entry for {version} has no magics list")
        for magic in magics:
            if not isinstance(magic, int) or isinstance(magic, bool):
                raise ValueError(
                    f"table entry for {version} has non-integer magic: {magic!r}"
                )
            if not 0 <= magic <= 0xFFFF:
                raise ValueError(
                    f"table entry for {version} has out-of-range magic: {magic}"
                )
        table[version] = list(magics)
    if not table:
        raise ValueError("table carries no version entries")
    return table


def probe_versions(fetch, from_minor=8, cap_minor=60, base_url=BASE_URL):
    """Branch-head magics for release branches from 3.<from_minor>.

    Stops at the first branch that does not exist. Returns a list
    of (version, head magic) in ascending order.
    """
    probed = []
    for minor in range(from_minor, cap_minor + 1):
        version = f"3.{minor}"
        try:
            magic = derive_magic(version, fetch, base_url)
        except BranchMissing:
            break
        probed.append((version, magic))
    return probed


def check(table, probed):
    """Probed versions -> findings [(version, kind, detail)].

    Kinds are MISSING and STALE-VALUE; an empty list means clean.
    Table entries with no probed branch are never reported.
    """
    findings = []
    for version, head_magic in probed:
        magics = table.get(version)
        if magics is None:
            findings.append(
                (version, "MISSING", "no table entry for this version")
            )
        elif head_magic not in magics:
            findings.append(
                (
                    version,
                    "STALE-VALUE",
                    f"table lists {magics}, branch head is {head_magic}",
                )
            )
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--table",
        default="crates/rpmcrab-core/data/python-magic-values.toml",
        help="magic table file to check",
    )
    parser.add_argument(
        "--from-minor",
        type=int,
        default=8,
        help="first 3.x branch to probe (default: 8)",
    )
    parser.add_argument(
        "--base-url",
        default=BASE_URL,
        help="CPython raw-content base URL (tests and mirrors)",
    )
    args = parser.parse_args(argv)

    try:
        table = load_table(args.table)
    except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
        print(f"INDETERMINATE: {exc}", file=sys.stderr)
        return 2
    try:
        probed = probe_versions(
            fetch_text, from_minor=args.from_minor, base_url=args.base_url
        )
    except FetchError as exc:
        print(f"INDETERMINATE: {exc}", file=sys.stderr)
        return 2
    if not probed:
        print("INDETERMINATE: no CPython branches probed", file=sys.stderr)
        return 2
    findings = check(table, probed)
    flagged = {version for version, _kind, _detail in findings}
    for version, _magic in probed:
        if version not in flagged:
            print(f"OK {version}")
    for version, kind, detail in findings:
        print(f"{kind} {version}: {detail}")
    if findings:
        print(f"{len(findings)} stale version(s) in {args.table}")
        return 1
    print(
        f"clean: {len(probed)} probed version(s) covered, "
        f"{len(table)} table entries carried"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
