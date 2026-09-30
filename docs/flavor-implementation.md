# SLFO Flavor: Implementation Sketch

**Status:** Design proposal for Tom's review. No code changes yet.

This document sketches how the `Flavor` config key (§4.11) would be
implemented when the first flavor-gated check lands. It is not a
specification; the implementing PR may deviate where the code demands it.

## Config plumbing

In `crates/rpmcrab-core/src/config.rs`:

```rust
/// Distribution flavor for flavor-gated check behavior.
/// `"opensuse"` (default) or `"slfo"`. Unknown values warn and
/// fall back to `"opensuse"`.
pub flavor: String,
```

Derived in `Config::finalize()` from the merged TOML table:

```rust
let flavor = table
    .get("Flavor")
    .and_then(|v| v.as_str())
    .unwrap_or("opensuse")
    .to_ascii_lowercase();
let flavor = match flavor.as_str() {
    "opensuse" | "slfo" => flavor,
    other => {
        eprintln!("warning: unknown Flavor {other:?}, falling back to \"opensuse\"");
        "opensuse".to_string()
    }
};
```

Helper, next to the existing config predicates:

```rust
impl Config {
    /// True when the `slfo` flavor is selected.
    pub fn is_slfo(&self) -> bool {
        self.flavor == "slfo"
    }
}
```

No trait changes: `Config` (or `&Config`) is already passed to every check's
`check` / `check_binary` entry points.

## Gating pattern

At the decision point, branch on `config.is_slfo()`. For severity flips,
make the level a variable rather than duplicating the emit call:

```rust
// checks/buildroot.rs (when ported)
let level = if config.is_slfo() { Level::Error } else { Level::Warning };
if self.istoday.is_match(data) {
    if self.looksliketime.is_match(data) {
        out.add_info(level, pkg, "file-contains-date-and-time", filename);
    } else {
        out.add_info(level, pkg, "file-contains-current-date", filename);
    }
}
```

For path-prefix differences, gate the prefix list:

```rust
// (illustrative; the /usr/etc LogrotateCheck/BinariesCheck divergences
// were REJECTED as staleness — see §4.11 — and are shown here only
// as the pattern, not as planned work)
let etc_prefixes: &[&str] = if config.is_slfo() {
    &["/etc/"]
} else {
    &["/etc/", "/usr/etc/"]
};
```

## Ledger entries

Each gated divergence gets a `[[divergence]]` entry in
`tests/parity/divergences.toml`, with the flavor recorded so corpus diffs
stay legible:

```toml
[[divergence]]
case = "buildroot"
finding = "file-contains-date-and-time"
flavor = "slfo"
kind = "behaviour"
reason = "Severity is Error under Flavor=\"slfo\" (immutable images require reproducible builds); Warning otherwise, matching the frozen 2.10.0 opensuse reference."
```

The corpus runner (§6) runs in the default `"opensuse"` flavor, so the
ledger remains the record of intentional departures from the reference.

## What is explicitly out of scope

- **No `slfo-1.2` vs `slfo-main` distinction.** The check-level divergences
  are identical in both branches; 1.2 is simply older. One `"slfo"` value
  covers both.
- **No gating for `AtomicUpdateCheck`.** It exists in opensuse too; port it
  unconditionally when its wave lands.
- **No gating for the three REJECTED candidates** (§4.11): they are
  staleness or removed checks, not flavor behavior.
- **No auto-detection** (no `/etc/os-release` sniffing). Flavor is a
  property of the lint target, not the host.

## Open question for Tom

Divergence #3 (`file-contains-date-and-time` / `file-contains-current-date`
W→E) is marked QUESTIONABLE in §4.11: the immutable-reproducibility
rationale is plausible but undocumented upstream. If rejected, the `Flavor`
key still ships (the mechanism is sound and future flavors will need it),
but the divergence matrix stays empty until a verified divergence lands.
