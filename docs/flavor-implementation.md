# Flavor: Implementation

**Status:** Landed. One vendored data set ships — the SUSE flavour's —
and the `Flavor` key with its gating helpers carries flavour-specific
behaviour.

## The mechanism

`Config.flavor` holds the selected flavour
(`crates/rpmcrab-core/src/config.rs`):

- The `Flavor` top-level TOML key sets it; values are case-insensitive.
- `"opensuse"` is the default; `"slfo"` is recognised; unknown values
  warn and fall back to `"opensuse"`.
- A pre-pass over the config file layers reads the key before the
  vendored layer is chosen, so the pre-pass and `Config::finalize()`
  agree on the selection for every input.
- `Config::is_slfo()` reports the selection, and the parity ledger's
  `divergence_applies()` applies a ledger entry's `flavor` key against
  it, so flavour-gated divergences stay expressible in code and in the
  ledger.

## The vendored data set

`scripts/generate-distro-configs.py` vendors the distro data from
upstream rpmlint's `opensuse` branch at a pinned commit into
`crates/rpmcrab-core/data/distro/opensuse/`, and
`crates/rpmcrab-core/src/distro_files_generated.rs` embeds that set as
`DISTRO_OPENSUSE_FILES`. Every recognised `Flavor` value selects this
set: the SUSE flavour's data serves openSUSE, SLFO and SLE targets.

The set carries the generator's extras on top of upstream:
`XinetdDepCheck` and `PAMModulesCheck` in `Checks`, the MinGW
`Filters` (the reference loads them from the mingw-filesystem
packages' rpmlintrc files) and the 59 `BlockedFilters`. Its security
data covers the varlink locations and `/usr/etc/sudoers.d`, and its
digest records carry the hash sets Factory ships:
`DIGEST_ADJUDICATIONS` in the generator holds the records adjudicated
from Factory corpus content, applied at generation time and by the
daily whitelist sync, so the vendored records carry the Factory
hashes by construction.

Three jobs keep the set current: `distro-config-sync` refreshes the
vendored files from upstream monthly, with the drift job comparing
the tree against the generator's output at the pins;
`upstream-whitelist-sync` merges new whitelist stanzas from the
upstream branch tip daily; and `upstream-config-watch` regenerates
the set at the upstream tip weekly and reports the difference — the
upstream commits in the pin range and the files a refresh rewrites —
on a tracking issue, so upstream movement between refreshes is
visible as it lands.

## Gating pattern

Checks branch at the decision point on `config.is_slfo()`. For
severity flips, the level is a variable rather than a duplicated emit
call:

```rust
let level = if config.is_slfo() { Level::Error } else { Level::Warning };
```

Each gated divergence gets a `[[divergence]]` entry in the
emitting check's file in `crates/rpmcrab-core/data/divergences/`
(regenerated into `tests/parity/divergences.toml`) with
`flavor = "slfo"` recorded, so corpus diffs stay legible.

## Severity decisions the audit settled

The SLFO-branch audit (§4.11, issue #714) verified each candidate
divergence against upstream history and Factory content. The date
findings (`file-contains-date-and-time`, `file-contains-current-date`)
are Warning under every flavour: the audit's promotion to Error
(issue #759) was reversed by issue #1180, whose re-measurement uses
the check's own read path — the #759 count included ELF stamps that
path can never see, and stamps honouring SOURCE_DATE_EPOCH, which the
findings now exempt. `AtomicUpdateCheck` runs in the
bundled defaults and in the vendored config (issue #698):
transactional updates are mandatory for the whole SUSE family.
