# Error descriptions

The `*.toml` files in this directory hold the reference's per-check error
descriptions, wired into `Filter::error_details` by
`rpmcrab_core::describe::staged_descriptions` (mirroring
`filter.py::_load_descriptions`): the files merge in sorted-name order and
`#VAR#` placeholders resolve recursively against the merged table, exactly
like `filter.py::_replace_description_variables`.

Provenance, verified against the pinned reference (`84848c0`):

- `BinariesCheck.toml` — the pinned reference file, minus the
  `shared-library-not-executable` entry dropped with the check in #267, plus
  the restored `shared-library-without-dependency-information` entry (copied
  verbatim from the pre-deletion upstream file; upstream removed entry and
  check in `cf619f717bc3`).
- `IconSizesCheck.toml`, `MixedOwnershipCheck.toml`, `PAMModulesCheck.toml`,
  `ZipCheck.toml`, `ZyppSyntaxCheck.toml` — byte-identical to the reference
  `rpmlint/descriptions/` files of the same name.
- `XinetdDepCheck.toml` — byte-identical to the reference's
  `descriptions/CheckForXinetd.toml`, renamed to the module name.
- `I18NCheck.toml` — the reference file plus the `incorrect-locale-subdir`
  block that `checks/i18n.rs` emits.
- `ConfigFilesCheck.toml` — the reference file, except
  `non-etc-or-var-file-marked-as-conffile` carries the reword from upstream
  #1606 (drop `%config` named as an option), staged ahead of the reference
  per the fix-in-port rule. Ledgered in `tests/parity/divergences.toml`.
- `Variables.toml` — the reference file, plus the `SUFFIX` entry lifted from
  the reference's `descriptions/FileMetadataCheck.toml` (the port stages the
  device/world-writable descriptions separately, but the `#SUFFIX#`
  references stay).

Checks whose description file is not staged yet have no wired description:
`--explain` and `-v` report "Unknown message" for their ids, the same text
the reference prints when a description is genuinely missing.
