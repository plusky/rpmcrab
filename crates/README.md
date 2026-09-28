# Crate roles and the dependency rules between them.

`rpmcrab` is a Cargo **virtual workspace**: there is no root package. Each
member is an independent crate with its own `Cargo.toml`, version and MSRV, and
publishes on its own.

| Crate | Role |
|-------|------|
| [`rpmcrab-core`](rpmcrab-core) | The domain: the RPM model, TOML config loader+merger, the filter/suppress engine, scoring, the report renderer, the check registry and all checks, and the external-tool probes. Contains **no CLI concern** — no clap, no tracing-subscriber, no exit-code policy. |
| [`rpmcrab`](rpmcrab) | The binary: clap CLI replicating every rpmlint flag, the exit-code mapping, signal handling, and the feature-gated `rpmcrab-gen` generator for man pages and shell completions. Ships a lib target so the pipeline can be driven end-to-end by integration tests. |

## Dependency direction

```
rpmcrab  ──depends on──▶  rpmcrab-core
```

The direction is **acyclic and one-way**. `rpmcrab-core` must not depend on
`rpmcrab`, on `clap`, on `tracing-subscriber`, or on any CLI concern; the
report renderer and every check live in `-core` so they are testable without a
terminal. `rpmcrab` must not re-implement command algorithms that belong in
`-core`. This is enforced by `scripts/check-rust-layering.sh`, which runs in
the local gate (`make check`) and in CI.

## Why each member restates dependency versions

There is deliberately **no `[workspace.dependencies]` table** in the root
manifest. Path dependencies carry an explicit `version = "X.Y.Z"` so that
`cargo-deny`'s `wildcards = "deny"` accepts them, and so that each crate's
manifest is a complete, self-contained statement of what it needs. The cost —
dep-version drift is a per-crate edit — is accepted.

## Versioning

`[workspace.package] version` is the single source of truth. `0.x` until parity
is proven (M4), `1.0` at drop-in parity, behavioural divergence permitted from
`2.0`. This avoids `rpmcrab 1.x` masquerading as `rpmlint 2.x` for packagers.
