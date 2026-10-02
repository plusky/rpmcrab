# LibreOffice corpus benchmark: rpmcrab vs reference rpmlint

Times a full lint run of both tools over every LibreOffice RPM from
openSUSE Tumbleweed oss, and compares finding counts.

## Inputs (pinned)

- `manifest.tsv` — the exact RPM set: name, repo-relative path, size,
  checksum type + value (sha512 from repodata). Re-running `bench.sh
  download` fetches only missing/corrupt files and verifies every hash.
- Tumbleweed snapshot pinned via repodata primary hash
  `1368e289…fd6e-primary.xml.zst` (recorded in `results.json`).
  Tumbleweed is rolling: if the snapshot moves, hash verification fails
  loudly instead of silently benchmarking a different corpus.

## Running

```sh
./bench.sh download          # fetch + verify 152 RPMs (~425 MB)
./bench.sh rpmcrab            # time rpmcrab -> JSON on stdout
./bench.sh rpmlint            # time reference rpmlint -> JSON on stdout
./bench.sh all                # download + both, combined JSON
```

Env overrides: `RPMCRAB_BIN`, `RPMLINT_REF_DIR` (reference checkout),
`RPMLINT_PYTHON` (python with rpmlint deps; point at a wrapper script for
containers), `MIRROR`, `RESULTS_DIR`. See header of `bench.sh`.

`run_rpmlint.py` is the container entry point used for the reference
(`sys.path` insert + `rpmlint.cli:lint`).

## Reference environment (what the baseline needed)

The reference does not run standalone; on a clean
`opensuse/tumbleweed` container these had to be installed before it
completed a run without fatal errors:

- python3 + `python3-rpm python3-pybeam python3-pyxdg python3-tomli-w
  python3-zstandard python3-enchant python3-magic python3-packaging`
- `checkbashisms desktop-file-utils AppStream groff binutils dash`

It was invoked with `-c <ref>/configs/openSUSE` (the whole config
directory, not a single file — single-file mode fails with
`KeyError: 'SystemdTmpfiles'`).

rpmcrab was run with the **same** config dir (`-c .../configs/openSUSE`).
Without it rpmcrab's builtin `Filters = []` applies and it reports ~49k
findings the reference filters out — the comparison is meaningless
unless both sides use the same config.

rpmcrab also needs `rpm2archive`/`rpm2cpio` on PATH.

## Methodology caveat (not parity evidence)

The reference checkout used here (`c0c9cf20`, opensuse branch) is NOT the
corpus pin (`84848c05`), and the reference is invoked with
`-c <ref>/configs/openSUSE` whereas `capture-parity.sh` uses
`XDG_CONFIG_HOME=$ref/xdg`. The config surface differs, so benchmark
numbers are performance evidence only and must not be cited as parity
evidence.

## Results 2026-10-02 (fourteen-mbp, M1 Pro, 10 CPUs)

See `results.json`. Headline: 152 RPMs / 424.7 MB.

| tool | wall | errors | warnings | filtered |
|---|---|---|---|---|
| rpmcrab (default jobs) | 93.9 s | 365 | 3949 | 49312 |
| rpmcrab -j1 | 372.1 s | 365 | 3949 | 49312 |
| reference rpmlint | 146.7 s | 141 | 3951 | 49380 |

Wall-clock speedup (default): **1.56x**. Per core, the reference is
**2.54x faster** than rpmcrab -j1 — rpmcrab wins wall-clock only through
10-way parallelism.

Finding counts are otherwise at near-parity (all warning tags match
exactly except 2 `potential-bashisms`; all error tags match except the
two gaps below).

### Parity gaps found (worth filing)

1. **ldconfig false positives — 216 extra errors** (54 files x 4 tags:
   `library-without-ldconfig-postin/postun`,
   `postin/postun-without-ldconfig`). rpmcrab's
   `crates/rpmcrab-core/src/checks/files.rs` gates on
   `fname.contains(".so")`; the reference requires the full `lib_regex`
   (`/lib(?:64)?/lib…\.so(\.…)?$`). Fires on e.g.
   `…/libbasegfxlo.so-gdb.py`.
2. **zero-length `__init__.py` — 8 extra errors.** Reference exempts via
   `normal_zero_length_regex` (`/__init__\.py$`, `/py.typed$`,
   `.dist-info/REQUESTED$`, `/gem.build_complete$`, `/.nosearch$`,
   `^/etc/security/console.apps/`); rpmcrab doesn't.
3. **`potential-bashisms` — 2 warnings missing** in rpmcrab (not
   investigated).

## CI considerations

- **Download**: 425 MB / ~10 min on first run (mirror-dependent; the
  download.opensuse.org redirector stalled on large files in testing —
  a direct mirror was faster). Cache `rpms/` between runs (actions/cache
  keyed on `manifest.tsv` hash); with a warm cache the download step is
  seconds (hash verification only).
- **RPM set**: Tumbleweed is rolling. Options: (a) keep the pinned
  manifest and let hash verification fail when the snapshot rotates,
  then refresh the manifest deliberately; (b) vendor the 152 RPMs as a
  release artifact / cache. (a) is cheaper and self-alarming.
- **Runtime**: ~4 min total on a 10-core runner (94s + 147s sequential).
  Run the two tools sequentially, never in parallel (CPU contention
  skews wall-clock).
- **Reference in CI**: needs the container + tool installs above (~2
  min) or a prebuilt image with the deps baked in. The image must be
  version-pinned (tumbleweed moves).
- **Flakiness**: wall-clock is noisy on shared runners. Mitigations:
  track trends over runs rather than hard thresholds; pin runner size;
  report speedup as informational, fail only on finding-count drift
  (deterministic: both rpmcrab runs produced byte-identical counts).
- **What to assert**: finding counts per severity (exact match, modulo
  the two known gaps until fixed); time as informational trend.
- No workflow YAML written yet — decision pending.
