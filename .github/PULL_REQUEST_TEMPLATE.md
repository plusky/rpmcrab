## What

<!-- One or two sentences. Details belong in the commit message and, for
     contract changes, in docs/DESIGN.md + the ledger sources in
     crates/rpmcrab-core/data/divergences/ (regenerated into
     tests/parity/divergences.toml). -->

## Contract impact

- [ ] Does not touch the frozen surface (`docs/DESIGN.md` §4), **or**
- [ ] It does, and `docs/DESIGN.md` + the ledger sources in `crates/rpmcrab-core/data/divergences/` are updated in the same change (aggregate regenerated)

## Checklist

- [ ] `make check` passes locally
- [ ] Branch diff reviewed before opening (open-code-review / `ocr delegate` recommended, another review is fine)
- [ ] Both maintainers requested as reviewers (see CODEOWNERS)
