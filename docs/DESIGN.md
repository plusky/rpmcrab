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
(`tests/parity/divergences.toml`). Behavioural divergence is deferred to a
later major version; the output wire format is permanent.

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

---

## 3. Decision log

| # | Decision | Choice | Reason |
|---|----------|--------|--------|
| 1 | Crate name | `rpmcrab` | Free on crates.io; no Rust rpmlint exists. |
| 2 | Repository | `plusky/rpmcrab` | Personal workspace, scarabeusiv as collaborator. Transfer to an org is a later, non-breaking decision. |
| 3 | RPM backend | Pure Rust (`rpm` + `rpm-version`) | See §3.1. |
| 4 | Parity rule | Freeze output, diverge findings | External consumers grep the output. |
| 5 | Licence | GPL-2.0-or-later | Matches rpmlint; config/description data carries over unambiguously. |

### 3.1 RPM backend

**Chosen: pure Rust.** `rpm` 0.28 for the format layer (header region, the 328
`RPMTAG_*` tag constants in both directions, payload + cpio including RPM's
stripped `07070X`, all nine scriptlet tags, per-file metadata) and
`rpm-version` 0.5 for EVR/NEVRA ordering (identical to RPM's sort algorithm).

**Rejected alternative: `librpm` FFI.** The `librpm` crate (0.6.0, now under
`rpm-software-management`, MPL-2.0) advertises rpmdb query and version
comparison, but its own README states that only the SQLite backend is tested,
BerkeleyDB is dropped, and "SUSE variants … are not currently tested". The
primary target's rpmdb is **ndb**, not SQLite, so `-i/--installed` via `librpm`
is unproven on the platform that matters most. FFI also collides with the
workspace-wide `unsafe_code = "forbid"`, needs librpm headers at build time and
`librpm.so` at runtime in every build root, and blocks a static binary.

**The one feature that needs the rpmdb** — `-i/--installed` — does not need
librpm at all. It is served by shelling out to `rpm -q` (guaranteed present
wherever rpmlint runs, read-only, same header data), exactly as rpmlint already
shells out to `readelf`/`objdump`/`ldd`. This keeps the whole tree `unsafe`-
free and statically linkable.

**Escape hatch.** If rich/boolean dependency *evaluation* (AND/OR/IF/ELSE)
becomes genuinely required, `librpm` can be added later behind a non-default
feature as an additive, non-breaking change. It is not in the default build.

### 3.2 The reference is the openSUSE flavour, not upstream

The contract target is **openSUSE rpmlint 2.10.0** — the `opensuse` branch of
`rpm-software-management/rpmlint` (checked at `84848c0`), which is what
openSUSE builds and `rpmlint-mini` ship. It is **not** upstream `main`. The
openSUSE branch carries behavioural patches on top of upstream; where it
diverges, the **openSUSE behaviour is the contract**. Catalogued from the
`main..opensuse` diff:

- **Forced `--permissive`** unless `-s/--strict` (`cli.py`) — see §4.6.
- **rpmlintrc auto-loading rewrite** (`lint.py`) — OBS `SOURCES` dirs, multiple
  files, different messages — see §4.8.
- **`--mini-mode` / `-m` flag + `mini_mode` config** (`cli.py`, `config.py`) —
  the `rpmlint-mini` wrapper contract. See §4.10.
- **Skip-rpmlint-on-rpmlint guard** (`lint.py`): any positional matching
  `/home/abuild/rpmbuild/RPMS/noarch/rpmlint-\d` prints
  `Skipping rpmlint for rpmlint package!` and exits 0, so the rpmlint package
  build does not recurse into a modified-config rpmlint-mini.
- **Description `#VAR#` templating** (`filter.py`,
  `_replace_description_variables`): `#WORD#` tokens in error descriptions are
  recursively expanded from other description entries; affects `-v` output.
- **Extraction stderr always suppressed** (`pkg.py`): the `rpm2archive`/cpio
  extraction stderr is `DEVNULL` even in verbose mode (upstream shows it under
  `-v`).
- **15 extra check modules** plus `filedigestcheck.py` and `permissions.py`
  helpers (§7.3, §8).
- Python-version compat shims (`tomllib`→`tomli`, `importlib.metadata`
  fallbacks) — no behavioural impact for a Rust port.

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
| Internal crash reading a package | 3 (unless `-v`, then re-raise → 1) |
| Nonexistent positional or `-c` path | 2 |
| Unparsable TOML config | 4 |
| Bare invocation / `--help` | 0 (prints help) |
| `-p` / `-e` | 0 |
| SIGINT | 130 |

The badness branch (`score > threshold` → 66) is evaluated **before** the
permissive error branch, so 66 fires even in the default permissive mode. The
`64`-vs-`65` split is reachable only under `-s` and is preserved. On openSUSE,
passing `-P` explicitly is a no-op (permissive is already forced).

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

Every flag rpmlint 2.10.0 accepts, with aliases, is accepted: positionals
(with per-arg `*`/`?` globbing, re-expanded and sorted, only `.rpm`/`.spm`/
`.spec`), `-V/--version`, `-c/--config`, `-e/--explain`, `-r/--rpmlintrc` +
`--file` (repeatable), `-v/--verbose` + `--info`, `-p/--print-config`,
`-i/--installed`, `-t/--time-report`, `-T/--profile`, `--ignore-unused-rpmlintrc`,
`--checks`, `-s/--strict`, `-P/--permissive` (mutually exclusive with `-s`).
The SUSE-only **`-m/--mini-mode`** is a real flag (absent upstream; added in
`46f9d302`, PR #678) that sets `config.mini_mode`. It makes `TagsCheck` skip
the enchant spellchecker and `SpecCheck` skip `_check_specfile_error` and
`_check_invalid_url` (`SpecCheck.py:226-228`). The `rpmlint-mini` wrapper
always passes it (`rpmlint.real --mini-mode --time-report "$@"`), so it is live
in every bootstrap build root. rpmcrab must accept the flag and port the three
guards: accepting-and-ignoring would emit `spelling-error` / `specfile-error` /
`invalid-url` findings that real rpmlint suppresses. A port that rejects the
flag breaks `rpmlint-mini` outright.

---

## 5. The diverging surface

These **may** change. Each change is its own commit plus a ledger entry (§6)
plus, where one exists, a linked upstream issue.

- **Which checks fire, and at what severity.** False positives are removed;
  false negatives are added. New findings count as divergence, not regression.
- **`--json`** — the single most valuable *additive* feature. rpmlint has no
  machine-readable output (long-open RFEs), so every consumer greps human text.
  A stable JSON stream is new surface, added without touching the text format.
- **A real man page.** rpmlint has none (upstream #1077, open since 2023).
- **`-T/--profile`.** There is no cProfile in Rust. The flag is accepted, a
  one-line note points at `--time-report`, and the process exits 0.
- **Spellcheck backend.** `pyenchant` has no direct Rust equivalent; the
  `spelling-error` check's backend is free to differ or to degrade gracefully.
- **`--time-report` cosmetics** (not consumed by tooling).
- **The program-identity banner.** The session-starts banner and version line
  are parameterized by `argv[0]` so the binary can be installed as `rpmlint`.
  Confirmed at M1.

### 5.1 The divergence philosophy (post-parity)

Direction agreed in the RFC (#2). It governs M5 and later; it does **not**
change the M0–M4 parity work, which is what makes this measurable.

**Why parity first.** Full 1:1 parity at 1.0 is what makes the drop-in claim
credible, and the parity corpus is what lets us *measure* per-check
false-positive rates across the whole distro. Strictening — including
revisiting exit codes toward saner options — is a 2.0 decision, and the corpus
is the instrument that makes it safe rather than guesswork.

**Error-fast, but run to completion.** Once parity is proven, the goal is cold
hard facts, not fuzzy warnings. Every check carries a **measured precision
bar** (its FP rate on the corpus): what measures clean is promoted to error and
fails the build; what does not is demoted or deleted. There is no permanent
warning purgatory. But the linter always **runs to completion** — the
whole-report contract and the footer summary are frozen precisely so batch
fixing works; aborting at the first error breaks that for no gain.

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

- **`rpmcrab-core`** — the domain, no CLI concern. RPM model (via `rpm`),
  config loader+merger, filter/suppress engine, scoring, the report renderer,
  the check registry and all checks, and the external-tool probes.
- **`rpmcrab`** — lib + bin. The clap CLI replicating every rpmlint flag, the
  exit-code mapping, signal handling, and the feature-gated `rpmcrab-gen`
  generator for man pages and completions.

Dependency direction is one-way (`rpmcrab → rpmcrab-core`), enforced by
`scripts/check-rust-layering.sh`.

### 7.2 Check registry

Checks are keyed by the **exact Python module name** (`FilesCheck`,
`TagsCheck`, …) so a `Checks = ["FilesCheck", …]` list in TOML resolves by
name, unchanged. The default `Checks` list mirrors `configdefaults.toml`.

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

`readelf`, `objdump`, `ldd`, `checkbashisms`, `desktop-file-validate`,
`appstreamcli`, `file`, and `rpm -q` are invoked as subprocesses, matching
rpmlint's own dependencies (they are already `Requires:` of the openSUSE
package). All invocations go through shared quoting/path helpers with golden
tests.

---

## 8. The 43-check inventory and wave plan

43 checks run on openSUSE: upstream's 29 plus the 15 openSUSE appends. They are
ported in waves ordered by blast radius, each landing with a parity case and a
divergence entry if any:

1. **Wave 1:** `TagsCheck`, `FilesCheck` (the two largest, the ones openSUSE
   cares most about).
2. **Wave 2:** `BinariesCheck`, `SpecCheck`.
3. **Wave 3:** the rest of upstream's 29.
4. **Wave 4:** the openSUSE 15.

`add_info` has 475 call sites / 417 distinct tag names upstream; the port
tracks tag-name parity per check.

---

## 9. Versioning and release

`[workspace.package] version` is the single source of truth. **0.x** until
parity is proven (M4), **1.0** at drop-in parity, behavioural divergence
permitted from **2.0**. This avoids `rpmcrab 1.x` masquerading as `rpmlint 2.x`
for packagers. Bare `X.Y.Z` tags, no `v`. Distribution is primarily the OBS
package (`rpmcrab`, plus an `rpmcrab-mini` build-root flavour mirroring
`rpmlint-mini`); crates.io is the secondary channel — `rpmcrab-core` is
published early (M1) to reserve the name.

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
2. **Spellcheck backend** — whether `spelling-error` keeps a live backend or
   degrades gracefully by default (decide by Wave 1).
3. **rpmdb read fidelity** — confirm `rpm -q` output gives every tag the
   installed-mode checks need, or whether a small ndb reader is warranted later
   (spike at M2).
