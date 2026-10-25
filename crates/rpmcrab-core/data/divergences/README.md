# Divergence ledger sources

These files hold the parity ledger's entries, one file per owner. A
check's entries live in the file named after it (`FilesCheck.toml`,
`TagsCheck.toml`, …), and a finding's entry files under the check that
emits the finding. Entries keyed by a run topic live in a file named
after the topic (`pkg-layer.toml`, `config.toml`,
`session-header.toml`, …).

`scripts/generate-divergences-ledger.py` assembles these sources —
owner files in name order, entries in file order within an owner —
into `tests/parity/divergences.toml`, the aggregate the parity
runner, the ledger tests and the coverage audit read. Adding or
editing an entry means editing the owner's file here and re-running
the generator; the `divergences-ledger-drift` CI job runs the
generator with `--check` and fails when the committed aggregate is
behind the sources.

The entry schema (`case`, `check`, `kind`, `reason`, `since`, with
optional `upstream` and `flavor`) is documented in
`tests/parity/README.md` and enforced over the aggregate by
`crates/rpmcrab-core/tests/divergences_ledger.rs`.
