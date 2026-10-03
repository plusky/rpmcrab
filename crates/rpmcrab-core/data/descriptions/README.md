# Staged error descriptions — not yet wired

The six `*.toml` files in this directory are **staged, not live**. They hold
the reference's per-check error descriptions, captured whole so that the
M2 `--explain` work (`TODO(M2)` in `crates/rpmcrab/src/lib.rs`) has
byte-verified source material to wire up instead of re-capturing it. Their
presence here does **not** mean descriptions are implemented.

Provenance, verified against the pinned reference (`84848c0`):

- `IconSizesCheck.toml`, `MixedOwnershipCheck.toml`, `PAMModulesCheck.toml`,
  `ZyppSyntaxCheck.toml` — byte-identical to the reference
  `rpmlint/descriptions/` files of the same name.
- `XinetdDepCheck.toml` — byte-identical to the reference's
  `descriptions/CheckForXinetd.toml`, renamed to the module name.
- `I18NCheck.toml` — the reference file plus the `incorrect-locale-subdir`
  block that `checks/i18n.rs` emits.
- `ConfigFilesCheck.toml` — the reference file, except `non-etc-or-var-file-marked-as-conffile`
  carries the reword from upstream #1606 (drop `%config` named as an option),
  staged ahead of the reference per the fix-in-port rule.

Nothing references these files: no `include_str!` points at this directory
(the only mention is a comment in `crates/rpmcrab-core/src/term.rs` tests),
and `[Descriptions]` in `crates/rpmcrab-core/data/configdefaults.toml` is
still the empty upstream stub. Descriptions currently reach the renderer
only via `set_error_detail` (e.g. `SpecCheck`).
