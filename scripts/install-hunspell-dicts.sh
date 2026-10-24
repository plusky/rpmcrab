#!/usr/bin/env bash
# Install the LibreOffice en_US and en_GB hunspell dictionaries into a target
# directory.
#
# Spellcheck tests need real hunspell dictionaries; the pairs come from
# the LibreOffice dictionaries repository (the same source openSUSE packages
# from).
#
# The pair is pinned to commit 6feecdc45bb14d46b4273f2cf6c0e3491cbee276 of
# that repository and verified against the sha256 sums recorded below:
# suggestion output depends on the exact dictionary bytes, so the bytes must
# never drift with an upstream branch. The GitHub mirror is tried first and
# cgit.freedesktop.org second; a source only succeeds when the downloaded
# bytes match the recorded sums. If no source serves the pinned bytes, the
# script fails.
#
# Usage: scripts/install-hunspell-dicts.sh <target-dir>
set -euo pipefail

target_dir="${1:?usage: install-hunspell-dicts.sh <target-dir>}"

dict_commit="6feecdc45bb14d46b4273f2cf6c0e3491cbee276"
aff_sha256="c7a8c4d08c29d237880844b1623099f59092602f189be38ce3912e457ff38bc1"
dic_sha256="fa070979b1c5448bd7ab66eb6acb616d306f92879eb4218bc16ee35d39a608ee"
gb_aff_sha256="c9dfcd5c8ced460579630ec6ed50f29ea9e967b5430026a2b0380daabea51b22"
gb_dic_sha256="140c2d9804b380c943a57437dc608de736c1cbdfa0d65438f8ea1dce54013b8b"

# Verify "<sum>  <path>" lines on stdin. sha256sum on Linux; shasum -a 256
# is the same check where sha256sum is absent (macOS). With neither tool
# available the verification fails loudly rather than passing unverified.
# The lines go through a temp file because not every sha256sum reads the
# check list from stdin.
verify_checksum() {
    local sums_file
    sums_file="$(mktemp)"
    cat > "$sums_file"
    local rc=0
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c "$sums_file" || rc=$?
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c "$sums_file" || rc=$?
    else
        echo "error: neither sha256sum nor shasum is available to verify the pinned dictionaries" >&2
        rc=1
    fi
    rm -f "$sums_file"
    return "$rc"
}

fetch() {
    local file="$1"
    local sum="$2"
    local url
    for url in \
        "https://raw.githubusercontent.com/LibreOffice/dictionaries/${dict_commit}/en/${file}" \
        "https://cgit.freedesktop.org/libreoffice/dictionaries/plain/en/${file}?id=${dict_commit}"; do
        if curl -fsSL --retry 3 --connect-timeout 10 --max-time 120 -o "$target_dir/$file" "$url" \
            && echo "$sum  $target_dir/$file" | verify_checksum >/dev/null; then
            return 0
        fi
        rm -f "$target_dir/$file"
        echo "warning: $file from $url failed or mismatched the pinned checksum" >&2
    done
    echo "error: could not fetch a verified $file from any source" >&2
    return 1
}

mkdir -p "$target_dir"
fetch en_US.aff "$aff_sha256"
fetch en_US.dic "$dic_sha256"
fetch en_GB.aff "$gb_aff_sha256"
fetch en_GB.dic "$gb_dic_sha256"
