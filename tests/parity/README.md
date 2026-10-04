# The parity corpus

This directory is the executable form of the compatibility contract in
[`docs/DESIGN.md`](../../docs/DESIGN.md). It pins how **reference rpmlint
2.10.0** behaves on real inputs so that rpmcrab can be proven a drop-in
replacement — and so that every place it *deliberately* differs is written
down.

Two things live here:

- **`cases/`** — one directory per captured behaviour, with the input(s), the
  exact `argv`, and the normalized expected `stdout`/`stderr`/exit code.
- **`divergences.toml`** — the ledger of deliberate departures. A difference
  between rpmcrab and the reference is either a recorded entry here or a test
  failure. There is no third option.

## Why it exists

"Don't reproduce rpmlint's bugs, but don't silently break its consumers." Both
halves are enforced mechanically: the cases catch *accidental* drift from the
frozen surface, and the ledger forces every *intentional* drift to be
justified — with the upstream issue/PR linked when the divergence is
tracked there (`upstream` is optional by decision; see `docs/DESIGN.md` §6.2).

## Case layout

```
cases/<name>/
  meta.toml          kind, rpmlint version, argv, flavour, provenance, input sha256
  input/             the .rpm / .spec inputs (pinned by sha256 in meta.toml)
  expected/
    stdout           normalized expected stdout
    stderr           normalized expected stderr
    exit             the process exit code, as a bare integer
```

`meta.toml`:

```toml
kind = "captured"            # "captured" | "synthetic"
rpmlint = "2.10.0"           # reference version that produced `expected/`
reference_sha = "84848c0…"   # the pinned rpmlint commit (see setup-rpmlint-ref.sh)
flavour = "openSUSE"         # config flavour; see "The overlay trap" below
checks = 43                  # reference check count under the openSUSE overlay
argv = ["llvm21-gold-….rpm"] # exactly what was passed (basenames); no config arg (see below)
captured = "2026-09-28"

[source]
description = "openSUSE Factory llvm21 build, llvm21-gold subpackage"
# origin = "…"               # optional: build URL / log path the case came from

[tools]
present = ["checkbashisms", "dash", …]  # external tools available at capture

[[input]]
file = "llvm21-gold-21.1.8-9.2.aarch64.rpm"
sha256 = "…"
```

`reference_sha` pins the reference commit that produced `expected/` — a
floating clone is not a frozen reference. `[tools].present` records the
external-tool set at capture time for provenance; nothing reads it yet, so a
degraded capture is not automatically detected.

### `captured` vs `synthetic`

- **`captured`** cases get their `expected/` **only** from running reference
  rpmlint, via `scripts/capture-parity.sh`. Captured expectations are **never
  hand-edited** — hand-editing turns a parity test into a snapshot test that
  catches nothing. If a captured case is wrong, re-capture it.
- **`synthetic`** cases hand-write both the input package identity and the
  expected output. They exist to prove the renderer byte-for-byte at M1 before
  any real check exists.

### Input size policy

Inputs are committed only when small (rule of thumb: under ~1 MB) — the corpus
must not bloat the git history with large binary RPMs. A case whose input is
larger records the input's `sha256` and a fetchable source in `meta.toml` and
does **not** commit the bytes; the runner (M1+) fetches it on demand. Prefer
small packages that still exercise the path under test (e.g. `liblto21`, 64 K,
covers the exit-66 badness abort).

## The overlay trap

`meta.toml` records `flavour = "openSUSE"` and an `argv` with no config
argument. That is not an omission: `scripts/capture-parity.sh` runs the
reference with `XDG_CONFIG_HOME` pointed at the openSUSE overlay
(`.parity-ref/xdg`), so the check set is ambient, not in argv. The captured
`expected/` only means something under that overlay.

Three different check sets, three different outputs:

| Runner | Checks |
|---|---|
| Reference rpmlint, defaults | 28 |
| rpmcrab, defaults | 33 (adds `SharedLibraryPolicyCheck`, `BrandingPolicyCheck`, `DeviceFilesCheck`, `KMPPolicyCheck`, `WorldWritableCheck`) |
| Reference under the openSUSE overlay — what the cases pin | 43 |

`meta.toml` records the pinned count as `checks = 43`. A port-side runner
**must** load the same overlay — the port resolves config pyxdg-style, so
`XDG_CONFIG_HOME=.parity-ref/xdg` reproduces it — or every comparison it
makes is meaningless. Run the port under its own 33-check default config and
the fixtures diverge heavily; that divergence is the config, not the port.

## Normalization

Expected output is normalized so it is stable across hosts and runs. The
capture script applies these rules at capture time; the parity runner (M1+)
applies the identical rules to rpmcrab's actual output before diffing:

| Non-deterministic bytes | Normalized to |
|---|---|
| `has taken 0.1 s` (footer) and `--time-report` durations | `has taken <DURATION> s` |
| Reference venv path in the `configuration:` header | `<VENV>` |
| Reference XDG config path in the `configuration:` header | `<XDG>` |
| `(none): W: unable to init enchant, spellchecking disabled.` (stderr) | **stripped** (enchant is optional; its absence is host-dependent, not rpmcrab) |
| Any host path, build root, home dir, or username | rejected by the **leak gate** |

The leak gate (`scripts/capture-parity.sh`) fails the capture if any
host-specific path or identity survives normalization. A case that leaks is
fixed, not committed.

## The divergence ledger

`divergences.toml` is read by the parity runner. Each entry:

```toml
[[divergence]]
case = "global"               # only "global" is defined so far
check = "no-soname"           # the finding (or area) that differs
kind = "behaviour"            # one of the kinds below
reason = "why the port differs, and why the difference is deliberate"
upstream = "https://github.com/rpm-software-management/rpmlint/issues/780"  # optional
since = "0.2.0"               # rpmcrab version that introduced the divergence
```

The schema is enforced by `crates/rpmcrab-core/tests/divergences_ledger.rs`:
`case`, `check`, `kind`, `reason` and `since` are required (and `case` must be
`"global"` for now); `upstream` is optional. Whether entries must link an
upstream issue is still undecided (rpmcrab#56) — do not treat it as settled.

`kind` is one of:

| kind | meaning |
|---|---|
| `missing` | the finding or check is absent entirely; the reason must say what is missing and why |
| `behaviour` | a deliberate behavioural departure (an adopted bug fix, or an intentional difference with justification) |
| `severity` | the finding fires at a different severity than the reference |
| `detail` | the finding fires with different detail wording than the reference |
| `limitation` | a divergence that genuinely cannot be implemented in the Rust port |

`limitation` is the narrowest kind and must not become a bucket for unfinished
work: the ledger guard exempts it from the "reason must say what is absent"
discipline that `missing` entries follow, so a real gap filed as `limitation`
would carry no accounting at all. "Not implemented" is not "cannot be
implemented" — file those as `behaviour`.

An empty ledger means rpmcrab is byte-identical to the reference on every case.
Every non-empty entry is a reviewed, deliberate decision.

## Capturing a new case

```sh
scripts/setup-rpmlint-ref.sh                 # build the reference env (once)
XDG_CONFIG_HOME=.parity-ref/xdg \
  scripts/capture-parity.sh <name> <input.rpm|spec> [-- extra rpmlint args]
```

Then fill in `cases/<name>/meta.toml`'s `[source] description`, review the
diff, and commit. External tools rpmlint shells out to (`checkbashisms`,
`dash`, `desktop-file-validate`, `readelf`, `objdump`, `ldd`, `file`) must be
on `PATH` — the setup script warns about any that are missing.

## Reference coverage audit

`scripts/audit-reference-coverage.py` statically audits that every finding
the reference *can* emit is either emitted by the port or recorded in the
ledger. It parses `rpmlint/checks/*.py` with `ast`, resolves each
`add_info` finding name through literals, concatenation, `%`-templates,
f-strings, and variable bindings (including cross-module `self.prefix`,
dict subscripts, and TOML data), and does the same for the port's
`crates/rpmcrab-core/src/checks/*.rs` via `format!` templates and `let`
bindings.

```sh
python3 scripts/audit-reference-coverage.py [REF_PATH]
```

A finding counts as ledgered when its check module has a `kind = "missing"`
entry (unported checks), or its name appears in a divergence entry's reason
text. Sites the resolver cannot handle are reported as UNRESOLVED, never
silently dropped.
