#!/usr/bin/env python3
"""Regenerate the SPDX license ID list in crates/rpmcrab-core/src/checks/spdx.rs.

Fetches spdx/license-list-data's ``json/licenses.json``, takes the
non-deprecated license IDs, and splices them into ``spdx.rs`` between the
GENERATED markers, stamping the list's release version. The checked-in file
stays the build's source of truth; this script runs by hand and in the
monthly spdx-sync CI job, never at build time.

Usage:
    scripts/generate-spdx-list.py [--json PATH] [--check]
"""

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SPDX_RS = REPO / "crates/rpmcrab-core/src/checks/spdx.rs"
DEFAULT_URL = (
    "https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json"
)
VERSION_RE = re.compile(r"(?m)^/// SPDX license list version: \S+$")
BEGIN_MARKER = "    // BEGIN GENERATED SPDX IDs\n"
END_MARKER = "    // END GENERATED SPDX IDs\n"


def load_data(url, json_path):
    if json_path:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
    else:
        with urllib.request.urlopen(url, timeout=60) as resp:
            data = json.load(resp)
    version = data["licenseListVersion"]
    ids = sorted(
        lic["licenseId"]
        for lic in data["licenses"]
        if not lic.get("isDeprecatedLicenseId")
    )
    return version, ids


def render_list(ids):
    for i in ids:
        # SPDX IDs are ASCII without quotes or backslashes, so a plain
        # quoted literal is byte-identical to what json.dumps would emit.
        assert i.isascii() and '"' not in i and "\\" not in i, i
    return "".join(f'    "{i}",\n' for i in ids)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", help="use a local licenses.json instead of downloading")
    ap.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if spdx.rs would change, without writing",
    )
    args = ap.parse_args()

    version, ids = load_data(DEFAULT_URL, args.json)

    text = SPDX_RS.read_text(encoding="utf-8")
    new_text, n = VERSION_RE.subn(
        f"/// SPDX license list version: {version}", text, count=1
    )
    if n != 1:
        sys.exit("error: version stamp line not found in spdx.rs")
    begin = new_text.index(BEGIN_MARKER) + len(BEGIN_MARKER)
    end = new_text.index(END_MARKER)
    new_text = new_text[:begin] + render_list(ids) + new_text[end:]

    if args.check:
        if new_text != text:
            print("spdx.rs is stale: run scripts/generate-spdx-list.py")
            return 1
        print(f"spdx.rs is current (SPDX license list {version})")
        return 0
    SPDX_RS.write_text(new_text, encoding="utf-8")
    print(f"wrote {len(ids)} IDs from SPDX license list {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
