# Release corpus benchmark

End-to-end rpmcrab timing on a pinned RPM set, run on every release and
uploaded as a release artifact. Informational only — never a gate.

## Corpus (pinned)

`manifest.toml` — 25 RPMs (~446 MB) from **openSUSE Leap 16.0** (not
Tumbleweed: Leap release URLs are stable for years, Tumbleweed is rolling
and URLs rot). Each entry carries name, version, URL, size, and the sha512
from repodata.

Coverage: large binaries (kernel-default, chromium, firefox, libreoffice),
systemd units (systemd, NetworkManager), python packaging (python313-base,
python313-pip), perl packaging (perl, perl-DBI), desktop files + appdata
(gimp, kate, vlc), and small utilities (bash, curl, git, …).

The RPMs are **not** vendored in git. The benchmark downloads them and
verifies every sha512; a stale URL fails loudly instead of silently
timing a different corpus.

## Running

```sh
./bench.sh download   # fetch + verify (skips present+valid files)
./bench.sh run        # 3 timed runs, summary JSON on stdout
./bench.sh all        # download + run
```

Env overrides: `RPMCRAB_BIN` (default: `../../target/release/rpmcrab`),
`RESULTS_DIR`.

## Output

One JSON object: median wall-clock over 3 runs, per-run times, corpus
metadata (manifest path, RPM count, MB), and runner metadata (OS, CPU
model, core count, date, rpmcrab git SHA).

## CI

`.github/workflows/release.yml` runs this after the build on every release
(tag push and manual dispatch). `continue-on-error: true` — a benchmark
failure never blocks the release. The summary JSON is uploaded as a
release artifact alongside the tarballs.

## Interpreting results

Wall-clock on shared runners is noisy. Compare medians across releases as
a trend; do not gate on single-run deltas. The corpus is fixed, so a
sustained shift between releases is signal, not noise.
