#!/usr/bin/env bash
# Install the LibreOffice en_US hunspell dictionaries into a target directory.
#
# Spellcheck tests need real hunspell dictionaries; the en_US pair comes from
# the LibreOffice dictionaries repository (the same source openSUSE packages
# from). The fetch fails on HTTP errors instead of writing an error page as
# a dictionary file.
#
# Usage: scripts/install-hunspell-dicts.sh <target-dir>
set -euo pipefail

target_dir="${1:?usage: install-hunspell-dicts.sh <target-dir>}"

mkdir -p "$target_dir"
curl -fsSL --retry 3 -o "$target_dir/en_US.aff" https://cgit.freedesktop.org/libreoffice/dictionaries/plain/en/en_US.aff
curl -fsSL --retry 3 -o "$target_dir/en_US.dic" https://cgit.freedesktop.org/libreoffice/dictionaries/plain/en/en_US.dic
