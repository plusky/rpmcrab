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
- `XinetdDepCheck.toml` — the reference's `descriptions/CheckForXinetd.toml`,
  renamed to the module name, plus the port-only `deprecated-xinetd-config`
  entry (ledgered in `tests/parity/divergences.toml`).
- `CheckForXinetd.toml` — byte-identical to the reference file of the same
  name (its content is duplicated by `XinetdDepCheck.toml`; the merge keeps
  the identical later copy).
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
- `TagsCheck.toml` — the pinned reference file, with the `useless-provides`
  entry reworded per upstream rpmlint#427 (the versioned and unversioned
  symbols are provided at once claim is not always accurate: duplicate
  versioned provides trigger the check too), staged ahead of the reference
  per the fix-in-port rule; minus the `non-standard-group`,
  `no-group-tag`, and `devel-package-with-non-devel-group` entries, dropped
  with the deliberately-removed findings. Ledgered in `tests/parity/divergences.toml`.
- `DeviceFilesCheck.toml`, `WorldWritableCheck.toml` — the entries carved
  out of the reference's `FileMetadataCheck.toml`, normalized to the
  reference's single-line form: the carved files used `"""` blocks, whose
  trailing newline the reference's entries do not have.
- `BuildRootAndDateCheck.toml` — the mechanical union of the reference's
  `descriptions/BuildDateCheck.toml` and `descriptions/BuildRootCheck.toml`
  (entries byte-identical); the port merged the two reference checks into
  one, so a single file named after the port check keeps the check-name to
  TOML mapping total. Ledgered in `tests/parity/divergences.toml`.
- `SpecCheck.toml` — the reference file, plus two port-only entries:
  `conditional-source-or-patch` (upstream rpmlint#45) and
  `translated-description` (upstream rpmlint#2). The reference has no
  such findings, so `--explain` would print `Unknown message` for them;
  minus the six entries dropped with their deliberately-removed findings
  (`no-buildroot-tag`, `hardcoded-path-in-buildroot-tag`,
  `%ifarch-applied-patch`, `unversioned-explicit-provides`,
  `unversioned-explicit-obsoletes`, `setup-not-quiet`); and the
  `use-of-RPM_SOURCE_DIR`
  entry reworded (the reference's `$RPM_BUILD_ROOT` advice is wrong).
  Ledgered in `tests/parity/divergences.toml`.
- `AlternativesCheck.toml`, `FileDigestCheck.toml`, `FilelistCheck.toml`,
  `FilesCheck.toml`, `KMPPolicyCheck.toml`,
  `LogrotateCheck.toml`, `MenuCheck.toml`, `MenuXDGCheck.toml`,
  `PythonCheck.toml`, `SharedLibraryPolicyCheck.toml`, `SpecCheck.toml`
  (besides its two port-only entries above), `SystemdTmpfilesCheck.toml`,
  `TagsCheck.toml` — the reference files with English/logic fixes to
  individual entries (copy-paste errors naming the wrong package, wrong
  scriptlet phase, self-contradictory sentences, ungrammatical wording);
  each fix is a deliberate `kind="detail"` divergence, ledgered in
  `tests/parity/divergences.toml`.
- Every other `*.toml` file — byte-identical to the reference
  `rpmlint/descriptions/` file of the same name.

Every check the registry can build now has description coverage: a staged
`<Name>.toml` — or, for `FHSCheck` and `PostCheck`, details registered in
code, mirroring the reference which ships no TOML for those two either
(`fhs_details_dict` / `post_details_dict` installed in each check's
`__init__`). Enforced by
`describe::tests::every_registered_check_has_description_coverage`, so the
gap cannot silently reopen.
