# Release corpus benchmark

End-to-end rpmcrab timing on a pinned RPM set, run on every release.
The release workflow runs it as an A/B regression gate: this release's
binary is timed against the previous release's binary on the same
runner, and a significant regression fails the release job.

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

## The A/B gate

`bench.sh ab` times two binaries over the corpus:

- **Candidate** — the binary this release run built (`RPMCRAB_BIN`).
- **Baseline** — the previous release's binary (`BASELINE_BIN`); the
  workflow fetches it from that release's assets.

Timing runs per package, interleaved: each round walks the corpus and
runs baseline and candidate back to back on every package, alternating
the order round by round so steady drift during a round lands on both
sides. The default is 5 paired rounds (`AB_ROUNDS`); each package's
score on each side is the median of its samples.

An A/A calibration pass then times the baseline against itself for 3
paired rounds (`AA_ROUNDS`). The verdict computation runs identically
on the calibration pair, and its geomean ratio's distance from 1.0 is
the **A/A spread**: the noise floor of this measurement on this runner.

### Verdict

The gate fails when any rule trips:

- **Geomean rule** — the geomean of the per-package ratios
  (candidate / baseline), minus 1, exceeds **both** 0.10 (a geomean
  ratio of 1.10) **and** 3× the A/A spread. On a quiet runner the 10%
  line binds; on a noisy runner the spread widens and absorbs the
  moves the measurement cannot attribute.
- **Run-validity rule** — every timed run records its exit status.
  Completed lint runs return 0 or 64 (an error printed). A signal
  death, a timeout (300 s per package run by default; `ab.py
  --run-timeout` adjusts it), or any other status renders a fail
  verdict naming the run, and a candidate median under 0.01 s against
  a baseline median of at least 0.05 s fails as startup noise rather
  than a completed run over the package.
- **Per-package rule** — any single package's ratio exceeds 2.0 while
  its median also grows by at least 0.25 s. The absolute floor keeps
  sub-second packages out of the rule: doubling a 0.1 s package is a
  0.1 s delta, inside the noise this gate is built to ignore.

With no baseline binary the verdict is **no-baseline** and the gate
passes: the first gated release has nothing to compare against, and
the workflow reaches this state only when no previous release exists.
A named-but-missing baseline binary, a failed corpus download, and a
corpus that fails sha512 verification each fail the job before any
timing happens — the gate renders verdicts only from measurements it
actually took.

## Running

```sh
./bench.sh download   # fetch + verify (skips present+valid files)
./bench.sh run        # single binary: 3 timed runs, summary JSON
./bench.sh all        # download + run
BASELINE_BIN=/path/to/previous/rpmcrab BASELINE_TAG=v0.3.0 ./bench.sh ab
```

Env overrides: `RPMCRAB_BIN` (default: `../../target/release/rpmcrab`),
`BASELINE_BIN`, `BASELINE_TAG`, `AB_ROUNDS`, `AA_ROUNDS`, `RESULTS_DIR`
(workflow only).

Direct `ab.py` use with `--baseline` requires `--rpms-dir` (the
verified corpus directory); omitting it is a usage error.

`ab.py` holds the timing engine and the verdict computation.
`test-ab.py` pins the verdict rules against synthetic timing data:
`python3 test-ab.py`.

## Output

`run`/`all` print one JSON object: median wall-clock over 3 runs,
per-run times, corpus metadata (manifest path, RPM count, MB), and
runner metadata (OS, CPU model, core count, date, rpmcrab git SHA).

`ab` prints one JSON object:

- `packages`: per-package baseline median, candidate median, and ratio;
- `geomean_ratio`: the geomean of the per-package ratios;
- `aa_geomean_ratio` and `aa_spread`: the calibration pair's geomean
  and its distance from 1.0;
- `thresholds`: the constants the verdict applied;
- `verdict` (`pass`, `fail`, or `no-baseline`) and `reasons`: one entry
  per rule that tripped — empty on a pass, each entry naming the rule
  and the numbers that tripped it.

## CI

`.github/workflows/release.yml` runs the gate after the build on every
release run (tag push and manual dispatch). The baseline step resolves
the newest published release whose tag differs from the run's tag and
downloads its x86_64 binary from the release assets. The release job
depends on the benchmark job, so a fail verdict blocks publication.
The verdict JSON is uploaded as a workflow artifact on every run, and
on tag runs it rides the release-create call, landing on the GitHub
release as the asset `benchmark-<version>.json` alongside the tarballs.

## Interpreting a verdict

A fail names the rule that tripped in `reasons`, and the per-package
table shows where the time moved. `aa_spread` records how much motion
the runner's own noise produces on an identical pair: a spread close
to the geomean excess marks a measurement at its noise floor, where a
re-run is the informative next step.
