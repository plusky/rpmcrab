#!/usr/bin/env bash
# Install the LibreOffice en_US hunspell dictionaries into a target directory.
#
# Spellcheck tests need real hunspell dictionaries; the en_US pair comes from
# the LibreOffice dictionaries repository (the same source openSUSE packages
# from). The fetch fails on HTTP errors instead of writing an error page as
# a dictionary file.
#
# cgit.freedesktop.org intermittently answers 503 and drops connections, so
# each file is fetched from the GitHub mirror of the same repository first,
# with cgit as the fallback. If every source fails, the script fails.
#
# Usage: scripts/install-hunspell-dicts.sh <target-dir>
set -euo pipefail

target_dir="${1:?usage: install-hunspell-dicts.sh <target-dir>}"

sources=(
    "https://raw.githubusercontent.com/LibreOffice/dictionaries/master/en"
    "https://cgit.freedesktop.org/libreoffice/dictionaries/plain/en"
)

fetch() {
    local file="$1"
    local base
    for base in "${sources[@]}"; do
        if curl -fsSL --retry 3 -o "$target_dir/$file" "$base/$file"; then
            return 0
        fi
        echo "warning: fetching $file from $base failed" >&2
    done
    echo "error: could not fetch $file from any source" >&2
    return 1
}

mkdir -p "$target_dir"
fetch en_US.aff
fetch en_US.dic
