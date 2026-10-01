# rpmcrab design — the compatibility contract

Status: draft (M0). This document **records deliberate decisions**. It is the
specification for rpmcrab; the roadmap lives in the milestones and issues,
never here. When a decision changes, edit this file in the same change and say
why.

The reference implementation is `rpmlint` **2.10.0** (openSUSE flavour,
`checks: 43`), CPython, GPL-2.0-or-later, at
`rpm-software-management/rpmlint`. rpmcrab is a drop-in replacement rewritten
in Rust. This file defines, precisely, what "drop-in" means.

---

## 1. Purpose and scope

rpmcrab runs identically to rpmlint: same command line, same TOML
configuration, same `rpmlintrc` filters, and the same frozen output and
exit-code contract that external tooling already consumes. It is **not** a
bug-for-bug port. Upstream false positives and never-firing checks are fixed,
and every fix is recorded in a machine-enforced ledger
(`tests/parity/divergences.toml`). Behavioural divergence is permitted whenever
it makes sense — from the first check port — with every departure recorded in
the ledger; the output wire format is permanent.

The governing principle: **freeze the output, diverge the findings.** The
bytes that leave the process are a contract; the set of findings a check
produces is not.

---

## 2. Non-goals

- **Not a general RPM build tool.** rpmcrab lints; it does not build, sign or
  install packages.
- **Not a dynamic check plugin host.** rpmlint can `importlib` an arbitrary
  Python module named in `Checks`. rpmcrab cannot load third-party check code
  at runtime; see §7.3. This is a deliberate, recorded departure.
- **Not a library for embedding** (yet). `rpmcrab-core` is a crate so the
  binary and the tests can share it, not a public API commitment.
- **Not bit-identical to upstream bugs.** Where rpmlint is wrong, rpmcrab is
  right, with a ledger entry.
- **Not a port of the `rpmdiff` companion binary.** `rpmdiff` diffs two RPM
  files' metadata for humans; it is a separate binary outside the lint
  pipeline, and nothing in openSUSE automation consumes it — OBS build
  comparison runs `build-compare`'s `pkg-diff.sh`, which does deeper,
  build-noise-normalized content comparison and is intentionally
  dependency-free. Porting `rpmdiff` would serve no consumer.

---

## 3. Decision log

| # | Decision | Choice | Reason |
|---|----------|--------|--------|
| 1 | Crate name | `rpmcrab` | Free on crates.io; no Rust rpmlint exists. |
| 2 | Repository | `plusky/rpmcrab` | Personal workspace, scarabeusiv as collaborator. Transfer to an org is a later, non-breaking decision. |
| 3 | RPM backend | `librpm` FFI | See §3.1. |
| 4 | Parity rule | Freeze output, diverge findings | External consumers grep the output. |
| 5 | Licence | GPL-2.0-or-later | Matches rpmlint; config/description data carries over unambiguously. |
| 6 | Package source | Sum type (`PkgSource`), not flag fields | §7.5 — illegal source states unrepresentable. |
| 7 | Spec model | Separate `SpecPkg`; `check_spec` arrives with it | §7.5 — the reference dispatches on `FakePkg`, not `is_source`. |
| 8 | Named durations | One insertion-ordered type | §7.5 — `Pkg.timers` and the lint accumulator share it. |
| 9 | Check execution | Parallel by package (`-j`), deterministic reassembly | §8 — the unit of parallelism is the package; findings reassemble into the frozen order. |
| 10 | Precision measurement | Distro-scale set; procedure defined before Wave 1's first promotion | §5.1 — hand cases pin the surface, they cannot measure FP rates. |

### 3.1 RPM backend

**Chosen: `librpm` FFI** — the `rpm-software-management/librpm.rs` binding,
`librpm` 0.6.0, MPL-2.0. It exposes the whole RPM-reading surface a linter
needs: the header (`package::PackageHeader`), the file list (`files::Files`,
wrapping `rpmfiles`), the rpmdb (`db::Db::{find, find_glob, find_regex}`), EVR
comparison (`version::{vercmp, Version}`), and dependency info
(`dep::{Dependencies, DepFlags}`). Wrapping librpm 1:1 mirrors rpmlint, which is
itself a thin wrapper over librpm via rpm-python.

**Costs, all accepted.** `librpm-sys` generates bindings with bindgen, so the
build requires the RPM development headers (`rpm-devel` / `librpm-dev`, plus
`rpm.pc`) on every host and CI runner; the binary links `librpm`/`librpmio` at
runtime (present on any RPM distro); and on macOS the Homebrew `rpm` formula
provides librpm, so the `rust-macos` CI leg builds and tests natively there.
`unsafe_code = "forbid"` still holds in `rpmcrab-core`: only the safe
binding API is used, and `unsafe` stays inside the `librpm`/`librpm-sys`
crates.

**Rejected: pure Rust (`rpm` + `rpm-version`).** The `rpm` crate parses the
format layer but declares the rpmdb a non-goal and implements no RPM
dependency/rich-dependency semantics, so it would have forced a second, weaker
RPM model plus `rpm -q`/`rpm2archive` subprocesses for the rest. The earlier
draft chose it to stay static and `unsafe`-free; that trade is no longer worth
it now that the binding is known to cover the whole surface.

**Extraction caveat.** `librpm`'s safe `archive::PackageReader` returns zero
entries for the compressed payloads that are all real-world RPMs — it omits the
`Fdopen(fdi, "r.<compressor>")` step `rpm2archive` performs. Payload extraction
therefore shells out to `rpm2archive | tar -xz` (§7.4) rather than using that
API, which also matches rpmlint's own extraction byte for byte.

**Escape hatch.** If the binding proves too incomplete, the header/file layers
can move to the `rpm` crate behind a feature; not in the default build.

### 3.2 The reference is the openSUSE flavour, not upstream

The contract target is **openSUSE rpmlint 2.10.0** — the `opensuse` branch of
`rpm-software-management/rpmlint`, which is what openSUSE builds and
`rpmlint-mini` ship. It is **not** upstream `main`. The openSUSE branch carries
behavioural patches on top of upstream; where it diverges, the **openSUSE
behaviour is the contract**. The reference is **pinned** to commit `84848c0` by
`scripts/setup-rpmlint-ref.sh`, and every captured case records that SHA in
`meta.toml` (`reference_sha`) — a floating clone is not a frozen reference.

Catalogued from the full `main..opensuse` diff, including the patches *inside*
existing checks:

**Process / plumbing patches** (`cli.py`, `config.py`, `lint.py`, `pkg.py`,
`filter.py`):

- **Forced `--permissive`** unless `-s/--strict` (`cli.py`) — see §4.6.
- **rpmlintrc auto-loading rewrite** (`lint.py`) — OBS `SOURCES` dirs, multiple
  files, different messages — see §4.8.
- **`--mini-mode` / `-m` flag + `mini_mode` config** (`cli.py`, `config.py`) —
  the `rpmlint-mini` wrapper contract. See §4.10.
- **Skip-rpmlint-on-rpmlint guard** (`lint.py`): any positional matching
  `/home/abuild/rpmbuild/RPMS/noarch/rpmlint-\d` prints
  `Skipping rpmlint for rpmlint package!` and exits 0.
- **Description `#VAR#` templating** (`filter.py`,
  `_replace_description_variables`): `#WORD#` tokens in error descriptions are
  recursively expanded. A `#VAR#` with no matching description key raises
  `KeyError`, and a circular reference raises `ValueError` — both **crash the
  linter**, and rpmcrab reproduces the crash (no divergence entry).
- **Extraction stderr always suppressed** (`pkg.py`): the `rpm2archive`/cpio
  extraction stderr is `DEVNULL` even in verbose mode.

**Check-internal patches** (these change *findings*, so each wants a corpus
case or an explicit ledger entry):

- `BinariesCheck`: `missing-call-to-setgroups-before-setuid` severity is
  **flipped** — openSUSE emits `E if is_uid else W`, upstream `W if is_uid
  else E`. This touches the frozen E/W taxonomy.
- `BinariesCheck`: `binary-in-etc` also fires under `/usr/etc/`.
- `DBusPolicyCheck`: new `E: dbus-policy-allow-wildcard` (bsc#1220215) and
  `W: dbus-policy-allow-receive`.
- `PAMModulesCheck`: ghost files now emit `E: pam-ghost-module` instead of
  being skipped.
- `SpecCheck`: new `E: obsolete-suse-version-check` / `E:
  invalid-suse-version-check` from `%suse_version` comparisons.
- `TagsCheck`: the `obs` scheme is now accepted by `invalid-url`.
- `FilesCheck`: `/var/spool/mail` dropped from `STANDARD_DIRS`.
- `LogrotateCheck`: `/usr/etc/logrotate.d/` is now also accepted.

**The extra checks** (see §7.3, §8): the flavour enables **11 openSUSE-only
check modules** (`BrandingPolicyCheck`, `DeviceFilesCheck`, `FileDigestCheck`,
`FilelistCheck`, `KMPPolicyCheck`, `PolkitCheck`, `SUIDPermissionsCheck`,
`SystemdInstallCheck`, `SystemdTmpfilesCheck`, `WorldWritableCheck`,
`AtomicUpdateCheck`) **plus 4 pre-existing checks it merely switches on**
(`BashismsCheck`, `TmpFilesCheck`, `SysVInitOnSystemdCheck`,
`SharedLibraryPolicyCheck`). Note `FileMetadataCheck.py` exists in the tree but
is **not** in `opensuse.toml`'s `Checks` — it is dormant and runs nothing; do
not port it.

Python-version compat shims (`tomllib`→`tomli`, `importlib.metadata`
fallbacks) have no behavioural impact for a Rust port.

---

## 4. The frozen surface

These are **byte-identical to openSUSE rpmlint 2.10.0 and permanent.** Changing
any of them is a breaking change. The `parity` CI job enforces them against the
corpus (§6).

### 4.1 The finding line

```
{filename}{arch}:{line} {L}: {check}{badness}{details}\n
```

- `filename` = `Path(package.name).name` (the `Name:` tag for binaries, the
  spec filename for `.spec`).
- `arch` = `.{arch}` where arch ∈ {real arch, `src`, `nosrc`, absent}.
- `line` = `{n}:` only for spec linting; omitted for binary findings.
- `L` ∈ {`E`, `W`, `I`}.
- `check` is space-free (rpmlint raises otherwise).
- `badness` = ` (Badness: {n})` **only when n > 1**, positioned after the check
  name and before details.
- `details` = each non-empty detail prefixed with a single space, concatenated.

Examples that must reproduce exactly:

```
clang21-devel.aarch64: E: zero-length /usr/include/clang/Basic/DiagnosticAnalysisEnums.inc
llvm21.src: E: unused-rpmlintrc-filter "devel-file-in-non-devel-package .*/usr/include/.*"
qdmr.spec:24: W: mixed-use-of-spaces-and-tabs (spaces: line 24, tab: line 2)
llvm21-gold.aarch64: E: suse-zypp-packageand packageand(clang21:binutils)
```

### 4.2 The filter-match string

`Filters` regexes run against the **de-coloured** line, in the same layout as
the printed line but **without** the `(Badness: N)` column and without any
description:

```
{filename}{arch}:{line} {L}: {check}{details}
```

Matching is **unanchored `re.search`** over that whole string. This is the
de-facto wire format; every `addFilter` in the wild targets it.

**Regex engine.** rpmlint compiles `Filters` with Python `re`, which supports
lookahead, lookbehind and backreferences. The Rust `regex` crate deliberately
rejects those constructs, so using it would silently change which existing
filters compile and match — a parity break on the frozen surface. rpmcrab
therefore uses **`fancy-regex`** (pure Rust, unsafe-free), which wraps `regex`
for the fast path and falls back to a backtracking engine for the fancy
constructs. The backtracking cost is accepted: filter matching runs once per
finding and is not the hot path, and rpmlint itself does a linear regex sweep
per finding. Catastrophic-backtracking filters are a pre-existing user input,
not a new attack surface.

### 4.3 Suppression is applied at emit time

A finding suppressed by a filter is invisible to the footer **and** the exit
code — it is dropped before the badness total and the per-level counters are
incremented, not merely hidden from stdout. The three mechanisms, applied in
order at emit time:

1. `BlockedFilters` — exact check-name equality → the finding is *unfilterable*.
2. `FilterErrorTitles` — exact check-name equality → suppressed.
3. `Filters` — unanchored regex over the match string → suppressed, and the
   pattern is recorded as *used* (for the unused-filter audit).

### 4.4 Sort order

Findings sort on the key `(check_name, level_token)` with `reverse=True`
(`filter.py` `__diag_sortkey`), so check names group **reverse-alphabetically**.
The level token is the second whitespace-separated field of the (possibly
coloured) line, which makes the within-check severity order **tty-dependent**:

- **Piped** (no tty — the case build tooling and this corpus exercise): the
  tokens are the bare `W:` / `I:` / `E:`, and descending byte order gives
  **W > I > E**.
- **On a tty**: the tokens carry ANSI colour codes (`\033[33mW:`, `\033[31mE:`,
  `\033[1mI:`), and descending byte order gives **W > E > I**.

The sort is **stable** (Python `list.sort`), so within equal `(check, level)`
keys the package insertion order is preserved.

### 4.5 Header, footer, banner

- Session header: `============================ rpmlint session starts ============================`
  (rule width honours `$COLUMNS`, else the tty, else 80), then the version
  line, a `configuration:` block listing each loaded config indented four
  spaces, an optional `rpmlintrc:` block, then `checks: N, packages: M`.
- Footer: `{p} packages and {s} specfiles checked; {E} errors, {W} warnings, {f} filtered, {b} badness; has taken {t:.1f} s`,
  space-padded inside an `=`-rule. `I:` findings are counted nowhere in the
  footer and contribute `0` badness.
- Abort banner, printed before the time report, **matched verbatim by build
  tooling**:

  ```
  ------------------------- Badness {b} exceeds threshold {t}, aborting. ----
  ```

### 4.6 Exit codes

**The openSUSE build forces `--permissive` unless `-s/--strict` is passed**
(`cli.py:171-175`, a SUSE-only patch marked "TODO: remove once OBS integration
is done"; upstream `main` has no such patch). This is the single most
load-bearing exit-code fact: on openSUSE, **ordinary errors do not fail the
run** — only badness over the threshold does. It is why `osc build` can produce
RPMs and print `E:` findings yet still "succeed", and why consumers grep the
`exceeds threshold, aborting.` banner rather than trusting the exit code.

| Situation | Code |
|-----------|-----:|
| Clean, or warnings / infos only | 0 |
| **Errors, score ≤ threshold (the default — forced permissive)** | **0** |
| `-s/--strict` passed (no forced permissive): any error | 64 |
| `-s/--strict` passed, and every error was a strict promotion | 65 |
| Badness over `BadnessThreshold` (> 0) — fires regardless of permissive | 66 |
| Internal crash reading a package | 3 (fatal-continue: reported, run continues, `rpmlint#1595`) |
| Nonexistent positional or `-c` path | 2 |
| Unparsable TOML config | 4 |
| Bare invocation / `--help` | 0 (prints help) |
| `-p` / `-e` | 0 |
| SIGINT | 130 |

The badness branch (`score > threshold` → 66) is evaluated **before** the
permissive error branch, so 66 fires even in the default permissive mode. The
`64`-vs-`65` split is reachable only under `-s` and is preserved. On openSUSE,
passing `-P` explicitly is a no-op (permissive is already forced). A fatal
per-package result dominates: if any package failed to open, the exit code is
3 even when the badness threshold also fired — the batch ran to completion,
so the unreadable input is the load-bearing fact.

### 4.7 Configuration semantics

- **TOML only.** No ini parser (removed upstream in 2.0.0).
- Search order: packaged `configdefaults.toml`; then `<xdg_config_dir>/rpmlint/*toml`
  (glob is `*toml`, **not** `*.toml`), `sorted()`; then `-c/--config` (file, or
  directory → `*.toml`). Then a **stable** 3-way sort: `configdefaults` → 0,
  other → 1, name containing `.override.` → 2.
- Merge is recursive. **Lists union-append + dedup** for normal files but are
  **replaced wholesale** for `*.override.*` files; scalars are overwritten by
  later files. This is why `Checks` accumulates to 43.
- Autoloading disabled by `CONFIG_DISABLE_AUTOLOADING` and
  `PYTEST_XDIST_TESTRUNUID`.

### 4.8 `rpmlintrc`

Two directives only, recognised by regex: `addFilter(r"…")` and
`setBadness('name', N)`. `setBadness` values land in `Scoring` as **strings**
and are `int()`-ed later (observable via `-p`).

**Auto-discovery is an openSUSE rewrite of upstream** (`lint.py`, `+-` diff).
When no `-r/--rpmlintrc` is given, and unless `PYTEST_XDIST_TESTRUNUID` is set:

1. **SUSE build locations are searched first, always** (not just for a single
   positional): `/home/abuild/rpmbuild/SOURCES` and `/usr/src/packages/SOURCES/`,
   each globbed for `*.rpmlintrc` then `*-rpmlintrc`, sorted. This is why OBS
   builds pick up `$SOURCES/<pkg>-rpmlintrc`.
2. Only if that found nothing **and** exactly one positional file/dir was given,
   that argument's directory is globbed (`*.rpmlintrc` then `*-rpmlintrc`,
   sorted).
3. **Multiple rpmlintrc files are all loaded**, with a stderr warning
   `There are multiple items to be loaded: …`. (Upstream instead refuses and
   prints `…ignoring them…` — a real message-text difference.)

The session header then prints a `rpmlintrc:` line followed by each loaded file
indented four spaces (upstream prints a single `rpmlintrc: <file>`).

### 4.9 Badness

There is no severity→badness table. Per-check via `[Scoring]`
(`filter.py:124-131`): if the check is in `Scoring`, `badness =
int(Scoring[check])`, and the level is **remapped in both directions** — to `E`
when badness > 0, **and downgraded from `E` to `W` when the configured badness
is 0**. If the check is not in `Scoring`: `E` → badness 1, `W`/`I` → badness 0.
`--strict` then forces the level to `E` and increments the promoted counter but
does **not** add badness. `BadnessThreshold` default is `-1` (abort branch
dead); openSUSE sets `999`.

### 4.10 CLI flags

The CLI is the deliberate exception to §3.2's contract rule: it follows
Tom's rpmlint PR #1595, not the `opensuse` branch's option design. The pinned
branch's option surface carries illogical aliases (`--file`, `--info`) and a
misleading `--profile`; straightening them is a designed divergence, ledgered
per flag. Positionals (with per-arg `*`/`?` globbing, re-expanded and
sorted, only `.rpm`/`.spm`/`.spec`), `-V/--version`, `-c/--config`,
`-e/--explain`, `-r/--rpmlintrc` (repeatable), `-v/--verbose`,
`-p/--print-config`, `-i/--installed`, `-t/--time-report`,
`-j/--jobs` (default: machine parallelism; `≤ 0` coerces to 1; capped at the task count and machine parallelism),
`--ignore-unused-rpmlintrc`, `--checks`, `-s/--strict`, `-P/--permissive`
(mutually exclusive with `-s`). Deliberately **not** accepted: `-T/--profile`
(removed upstream by #1595 as misleading) and the illogical `--file`/`--info`
aliases (straightened to `-r`/`-v`).
The SUSE-only **`-m/--mini-mode`** is a real flag (absent upstream; added in
`46f9d302`, PR #678) that sets `config.mini_mode`. It makes `TagsCheck` skip
the enchant spellchecker and `SpecCheck` skip `_check_specfile_error` and
`_check_invalid_url` (`SpecCheck.py:226-228`). The `rpmlint-mini` wrapper
always passes it (`rpmlint.real --mini-mode --time-report "$@"`), so it is live
in every bootstrap build root. rpmcrab must accept the flag and port the three
guards: accepting-and-ignoring would emit `spelling-error` / `specfile-error` /
`invalid-url` findings that real rpmlint suppresses. A port that rejects the
flag breaks `rpmlint-mini` outright.

### 4.11 Flavors

The reference maintains separate git branches for distribution flavors
(`opensuse`, `opensuse-slfo-1.2`, `opensuse-slfo-main`). rpmcrab does not
branch; flavor-specific behavior is controlled by a single config key.

- **Key:** `Flavor` (top-level TOML key, case-insensitive value).
- **Values:** `"opensuse"` (default), `"slfo"`.
- **Semantics:** Unknown values warn and fall back to `"opensuse"`
  (defensive: fail closed on config the code does not understand).
- **No auto-detection.** rpmcrab lints arbitrary packages, often cross-distro
  (a Tumbleweed host linting SLFO packages). Flavor is a property of the
  *target*, not the host, so it is explicit config.

Checks read `config.is_slfo()` at the decision point. Severity flips are
expressed as a level variable, not duplicated emit calls.

**Verified SLFO divergences.** Each candidate divergence from the SLFO
branches was verified against upstream history before being accepted. Three
of the four candidates turned out to be branch staleness or removed checks,
not real flavor divergences:

| # | Candidate | Verdict | Reason |
|---|-----------|---------|--------|
| 1 | `post-without-tmpfile-creation` (new W finding) | **REJECTED** | Removed upstream in 2025-12-09 (issue #1374): the `%tmpfiles` macro is now a noop via systemd triggers; the check fires false positives on correct packages. SLFO branches are stale. Do not implement. |
| 2 | `binary-in-etc` flags `/usr/etc/` | **REJECTED** | The `/usr/etc/` coverage was added to opensuse on 2025-06-06 (mgerstner PR #1357), after the SLFO branches forked (2025-02-04). SLFO is stale; the opensuse behavior is correct. Do not gate. |
| 3 | `file-contains-date-and-time` / `file-contains-current-date` W→E | **QUESTIONABLE** | Plausible (immutable images need reproducibility) but undocumented: no upstream issue, no commit message justifying the severity flip. Held for Tom's decision. |
| 4 | LogrotateCheck drops `/usr/etc/logrotate.d/` | **REJECTED** | Same staleness as #2: `/usr/etc/` support added to opensuse after the SLFO fork. Do not gate. |

The already-landed `missing-call-to-setgroups-before-setuid` severity flip
(PR #37, upstream #1462) matches the SLFO form but is implemented
unconditionally with a ledger entry — it is a bugfix, not a flavor gate.

If #3 is approved, the divergence matrix is:

| Check | Finding | opensuse | slfo |
|-------|---------|----------|------|
| `checks::buildroot` (when ported) | `file-contains-date-and-time` | W | E |
| `checks::buildroot` (when ported) | `file-contains-current-date` | W | E |

Each gated divergence gets a `[[divergence]]` ledger entry (§6.2) recording
`flavor = "slfo"`.

---

## 5. The diverging surface

These **may** change. Each change is its own commit plus a ledger entry (§6)
plus, where one exists, a linked upstream issue.

- **Which checks fire, and at what severity.** False positives are removed;
  false negatives are added. New findings count as divergence, not regression.
- **`--json`** — the single most valuable *additive* feature. rpmlint has no
  machine-readable output (long-open RFEs), so every consumer greps human text.
  A stable JSON stream is new surface, added without touching the text format.
- **A real man page.** rpmlint has none (upstream #1077, open since 2023);
  rpmcrab ships one, generated from the CLI definition by `rpmcrab-gen`
  and drift-checked in CI.
- **Spellcheck backend.** `pyenchant` has no direct Rust equivalent; the
  `spelling-error` check's backend is free to differ or to degrade gracefully.
- **`--time-report` cosmetics** (not consumed by tooling).
- **The program-identity banner.** The session-starts banner and version line
  are parameterized by `argv[0]` so the binary can be installed as `rpmlint`.
  Confirmed at M1.

### 5.1 The divergence philosophy

Direction agreed in the RFC (#2), refined 2026-09-28: **divergence is not
version-gated.** rpmcrab may diverge from rpmlint's findings whenever it makes
sense — from the first check port — provided every departure is recorded in the
ledger (§6) with justification. What does not move is the frozen output
contract (§4): the wire format, exit codes, sort order and config semantics
that consumers depend on. A change to *that* is a deliberate major-version
decision, not a routine divergence.

**Why the corpus still matters.** Relaxing the parity requirement does not make
the corpus optional — it is what lets us *measure* per-check false-positive
rates across the distro, so "when it makes sense" is evidence, not vibes. A
check lands with its parity case; where rpmcrab deliberately differs, the
ledger entry records the measured or argued reason.

**Error-fast, but run to completion.** The goal is cold hard facts, not fuzzy
warnings. Every check carries a **measured precision bar** (its FP rate on the
corpus): what measures clean is promoted to error and fails the build; what
does not is demoted or deleted. There is no permanent warning purgatory. But
the linter always **runs to completion** — the whole-report contract and the
footer summary are frozen precisely so batch fixing works; aborting at the
first error breaks that for no gain.

**Hold W/I to the same bar.** Fuzzy warnings are actively harmful to AI
consumers — an agent handed a maybe-warning "fixes" things that are not broken
and generates churn a human must review. The `E`/`W`/`I` taxonomy stays frozen
(the output contract), but `W`/`I` are held to the same precision bar and the
noisy ones are cut, not kept.

**Package-level filtering.** Filtering is scoped per-package and driven by
which checks are enabled, so local and OBS builds stop drifting apart ("always
follow the strictest of the two"). What fails the build is decided by config
(`opensuse.toml`), and the FP bar is enforced in CI so regressions cannot sneak
back in.

**The precision bar needs a distro-scale set.** Hand-written parity cases pin
the frozen surface; they cannot measure a false-positive rate. Promoting a
check to error (or demoting/deleting it) requires its FP rate measured on a
defined distro-scale package set, with the procedure recorded before Wave 1's
first promotion. Until then, no promotion happens.

---

## 6. The parity corpus and the divergence ledger

This is the mechanism that makes "don't reproduce bugs, don't silently break"
enforceable.

### 6.1 Corpus layout

`tests/parity/` holds cases. Each case is a directory with the input(s) (an
`.rpm` or `.spec`, pinned by sha256), the config set, the exact `argv`, and the
expected `stdout`/`stderr`/exit code. A `manifest.toml` indexes them with a
discriminator:

- `kind = "captured"` — expected output comes **only** from running real
  rpmlint 2.10.0, recorded by `scripts/capture-parity.sh` (which sanitizes
  hosts/paths and runs a hard leak gate). Captured expectations are **never
  hand-edited** — hand-editing turns a parity test into a snapshot test that
  catches nothing.
- `kind = "synthetic"` — a fabricated package identity plus a hand-written
  expectation. Used at M1 to prove the renderer byte-for-byte before any real
  check exists.

### 6.2 The ledger

`tests/parity/divergences.toml` is machine-enforced. The `parity` CI job runs
rpmcrab on each case and diffs. Any difference is either:

- a recorded entry — `{ case, check, reason, upstream-issue, since }` — or
- a **failure**.

You cannot ship a behavioural change without writing down why. This is the
executable form of "records deliberate decisions".

---

## 7. Architecture

### 7.1 Crates

Virtual workspace, `resolver = "2"`, members under `crates/`, `[lints]
workspace = true`, `unsafe_code = "forbid"`, no `[workspace.dependencies]`.

- **`rpmcrab-core`** — the domain, no CLI concern. RPM model (via `librpm`),
  config loader+merger, filter/suppress engine, scoring, the report renderer,
  the check registry and all checks, and the external-tool probes.
- **`rpmcrab`** — lib + bin. The clap CLI replicating every rpmlint flag, the
  exit-code mapping, signal handling, and the feature-gated `rpmcrab-gen`
  generator, which emits the man page and shell completions checked in under
  `crates/rpmcrab/{man,completions}` (drift enforced by the `assets-drift`
  CI job). The assets are generated, committed and drift-checked but not yet
  installed by any packaging step — `release.yml` ships the binary only;
  wiring them into the tarball/spec is a pending packaging decision, recorded
  here so it is not implicit.

Dependency direction is one-way (`rpmcrab → rpmcrab-core`), enforced by
`scripts/check-rust-layering.sh`.

### 7.2 Check registry

Checks are keyed by the **exact Python module name** (`FilesCheck`,
`TagsCheck`, …) so a `Checks = ["FilesCheck", …]` list in TOML resolves by
name, unchanged. The default `Checks` list mirrors `configdefaults.toml`.

*Convention, decided; applies from the first check port.* Shared check
helpers — path/mode predicates, tag readers, anything two checks would
otherwise each write — live in one shared module. A new check reuses them;
new shared logic goes there, not in the check. The 43 ports must not invent
43 variants of the same predicate.

### 7.3 openSUSE checks and the plugin departure

openSUSE appends 15 checks (`BrandingPolicyCheck`, `FilelistCheck`,
`PolkitCheck`, …) that exist only in its tree. rpmcrab **vendors** them under
`checks::opensuse` with the same names, **excluded** from the default list, so
the shipped `opensuse.toml` appends them unmodified and the run still prints
`checks: 43`.

**Departure:** rpmcrab cannot `importlib` an arbitrary third-party check
module. A check not built in cannot be registered. This is recorded because it
is a real loss of rpmlint capability, accepted because a stable Rust plugin ABI
is not worth the cost for a lint-rule interface. If a genuine need for external
checks appears, revisit as an additive feature.

### 7.4 External tools

Header, file-list and rpmdb reads go through **`librpm`** (§3.1), not a
subprocess. **Payload extraction** shells out to `rpm2archive | tar -xz`
(fallback `rpm2cpio | cpio -id`), exactly as rpmlint does — the binding's
`archive::PackageReader` is unusable for compressed payloads (§3.1).
ELF binary analysis uses the pure-Rust `goblin` crate (section/program
headers, dynamic section, symbols) and `gimli` for DWARF, not `readelf`/`ldd`/
`objdump` subprocesses — faster, no binutils dependency, and more reliable
than text parsing. `checkbashisms`, `desktop-file-validate`, `appstreamcli`
and `file` are invoked as subprocesses on extracted files, matching rpmlint's
own dependencies (they are already `Requires:` of the openSUSE package). All
invocations go through shared quoting/path helpers with golden tests.

### 7.5 The package model

*Status: decided and implemented. `PkgSource` landed with PR #20; the
`dir_name`/`extracted`/`tempdir` fields are gone.*

`Pkg` is the binary-RPM model (file-backed or installed). *Where its bytes
come from* is a closed set, so it is represented as one: a `PkgSource` sum
type, not separate fields whose combinations the type system cannot check.
The variants follow the situations the reference actually distinguishes, so
the reference's `extracted` flag is a total function of the variant — no flag
field remains:

- `Extracted { dir, tempdir }` — payload unpacked into an owned tempdir
  (removed on drop);
- `Installed` — an installed package (`extracted` true);
- `LiveRoot` — a file package with `ExtractDir='/'` (`extracted` false);
- `CleanedUp` — the tempdir was dropped; reads fail to `''`, exactly as the
  reference's post-cleanup reads do.

`Installed` and `LiveRoot` both read from the live filesystem, but they stay
separate variants because the reference reports different `extracted` values
for them — collapsing them would reintroduce the flag the sum type exists to
remove. Nothing outside the `pkg` module distinguishes the states by field
inspection, so a read can never silently fall back to the host filesystem
again.

The `.spec` model is a **separate struct**, not more `Option` fields on `Pkg`.
A spec is text with line numbers, not an RPM with a payload, and the reference
keeps them as separate classes (`Pkg` vs `FakePkg`) with a separate dispatch
hook: `check_spec` is dispatched on holding a `FakePkg`, *not* on `is_source`
(which is about src.rpms). The lint loop dispatches on
`enum Package { Rpm(Pkg), Spec(SpecPkg) }`, and the `Check` trait gains
`check_spec` with that milestone. Decided now so `Pkg` never grows a second
personality when `SpecCheck` is ported.

There is one named-durations type (insertion-ordered, like the reference's
dict): `Pkg.timers` and the lint loop's accumulator share it.

---

## 8. The 43-check inventory and wave plan

43 checks run on openSUSE: 28 in `configdefaults.toml` plus the 15 that
`opensuse.toml` appends. They are ported in waves ordered by blast radius, each
landing with a parity case and a divergence entry if any:

1. **Wave 1:** `TagsCheck`, `FilesCheck` (the two largest, the ones openSUSE
   cares most about). **Done** (PRs #27, #28, #29).
2. **Wave 2:** `BinariesCheck`, `SpecCheck`.
3. **Wave 3:** the rest of the 28.
4. **Wave 4:** the openSUSE 15.

`add_info` has 475 call sites / 417 distinct tag names upstream; the port
tracks tag-name parity per check. `SpecCheck` also needs `FakePkg`, the
`.spec` model, which is deferred to its own milestone; until then a `.spec`
input is refused with exit 3 rather than silently ignored (ledgered). The
`Check` trait's `check_spec` hook arrives with it, because the reference
dispatches it on holding a `FakePkg` rather than on `is_source`.

A check that panics is contained per package: the package becomes a fatal
result (reported, exit 3 after the batch) and the run continues with the
remaining packages. Swallowing the panic entirely would present incomplete
coverage as a clean run, so the fatal line and the exit code keep the bug
visible; aborting the whole batch on one package's bug would forfeit the
rest. The status differs from the reference's (3 rather than 1 with a
traceback) and is ledgered.

*Decided and implemented.* Throughput matters: checks run in parallel, one
package per worker thread (`-j`, defaulting to machine parallelism); the
`&mut self` + `reset()` trait shape is preserved because each worker owns its
check set and resets it between packages. Findings reassemble deterministically
into the frozen order (task-index order, then the frozen sort), so the pool is
a scheduling detail, not a behaviour change.

---

## 9. Versioning and release

`[workspace.package] version` is the single source of truth. **0.x** until the
output contract is proven substitutable (M4), **1.0** at that point. Findings
may diverge at any version (§5.1), so the version tracks the stability of the
*output contract*, not the set of findings — 1.0 means "substitutable", not
"bug-for-bug identical". A change to the frozen output contract itself would be
a deliberate major-version bump. The CLI changes in this cycle (threading,
fatal-continue, flag straightening) stay at **0.1.0**: they are the designed
pre-1.0 direction, and 1.0 still marks the substitutability milestone, not the
absence of divergence. This avoids `rpmcrab 1.x` masquerading as
`rpmlint 2.x` for packagers. Bare `X.Y.Z` tags, no `v`. Distribution is
primarily the OBS package (`rpmcrab`, plus an `rpmcrab-mini` build-root flavour
mirroring `rpmlint-mini`); crates.io is the secondary channel — `rpmcrab-core`
is published early (M1) to reserve the name. The release workflow ships a
single `x86_64-unknown-linux-gnu` asset; macOS builds work (§3.1) but no macOS
release asset is planned.

---

## 10. Security

`unsafe_code = "forbid"` workspace-wide. The sensitive surface is RPM header /
payload parsing of untrusted packages and subprocess execution on paths derived
from package contents; both go through helpers with golden tests. `cargo-deny`
(advisories + licence + source) and CodeQL run in CI. See `SECURITY.md`.

---

## 11. Open questions

1. **Program-identity banner** — the exact parameterization by `argv[0]`
   (confirm at M1).
2. **Spellcheck backend** — decided at Wave 1: degrades gracefully by
   default (`spelling-error` is not emitted; ledgered in
   `tests/parity/divergences.toml`).
3. **rpmdb read fidelity** — confirm `rpm -q` output gives every tag the
   installed-mode checks need, or whether a small ndb reader is warranted later
   (spike at M2).
