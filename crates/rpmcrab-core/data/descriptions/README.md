# Error descriptions

The `*.toml` files in this directory hold the reference's per-check error
descriptions, wired into `Filter::error_details` by
`rpmcrab_core::describe::staged_descriptions` (mirroring
`filter.py::_load_descriptions`): the files merge in sorted-name order and
`#VAR#` placeholders resolve recursively against the merged table, exactly
like `filter.py::_replace_description_variables`.

Provenance, verified against the pinned reference (`84848c0`):

- `BinariesCheck.toml` — the pinned reference file, minus the
  `shared-library-not-executable` entry dropped with the check in #267 and
  the `invalid-ldconfig-symlink`, `invalid-soname`,
  `only-non-binary-in-usr-lib` entries dropped with the findings
  (openSUSE: "Doesn't seem to make sense") and the
  `missing-mandatory-optflags` entry dropped with the finding in #645, plus
  the restored `shared-library-without-dependency-information` entry (copied
  verbatim from the pre-deletion upstream file; upstream removed entry and
  check in `cf619f717bc3`), plus five port-only hardening entries: the
  four rpmcrab#17 ones (`missing-fortify`, `missing-stack-protector`,
  `missing-relro`, `partial-relro`) and `missing-cf-protection`
  (rpmcrab#667). The reference has no such findings, so `--explain`
  would print `Unknown message` for them; ledgered in
  `tests/parity/divergences.toml`.
- `IconSizesCheck.toml`, `MixedOwnershipCheck.toml`, `PAMModulesCheck.toml`,
  `ZyppSyntaxCheck.toml` — byte-identical to the reference
  `rpmlint/descriptions/` files of the same name.
- `ZipCheck.toml` — the reference file, minus the `jar-not-indexed` and
  `uncompressed-zip` entries dropped with the findings (negligible value).
- `SharedLibraryPolicyCheck.toml` — the reference file, plus the port-only
  `shlib-devel-unversioned-requires` entry. The reference has no such
  finding, so `--explain` would print `Unknown message` for it; ledgered in
  `tests/parity/divergences.toml`.
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
  per the fix-in-port rule, and `conffile-without-noreplace-flag` carries
  the reword ruled in rpmcrab#556 (both `%config` forms valid; the text
  lays out the .rpmsave/.rpmnew upgrade semantics and asks for a per-file
  choice instead of prescribing `noreplace`), plus the port-only
  `usr-etc-file-marked-as-conffile` entry (rpmcrab#712; the reference
  has no UsrEtc finding, so `--explain` would print `Unknown message`
  for it there). Ledgered in `tests/parity/divergences.toml`.
- `Variables.toml` — the reference file, plus the `SUFFIX` entry lifted from
  the reference's `descriptions/FileMetadataCheck.toml` (the port stages the
  device/world-writable descriptions separately, but the `#SUFFIX#`
  references stay).
- `TagsCheck.toml` — the pinned reference file, with the `useless-provides`
  entry reworded per upstream rpmlint#427 (the versioned and unversioned
  symbols are provided at once claim is not always accurate: duplicate
  versioned provides trigger the check too), staged ahead of the reference
  per the fix-in-port rule; minus the `non-standard-group`,
  `no-group-tag`, `devel-package-with-non-devel-group`,
  `no-major-in-name`, `incoherent-version-in-changelog`,
  `invalid-buildhost`, `invalid-packager`, `invalid-version`,
  `non-coherent-filename` and `requires-on-release` entries, dropped
  with the deliberately-removed findings. Ledgered in
  `tests/parity/divergences.toml`.
- `DeviceFilesCheck.toml`, `WorldWritableCheck.toml` — the entries carved
  out of the reference's `FileMetadataCheck.toml`, normalized to the
  reference's single-line form: the carved files used `"""` blocks, whose
  trailing newline the reference's entries do not have.
- `BuildRootAndDateCheck.toml` — the mechanical union of the reference's
  `descriptions/BuildDateCheck.toml` and `descriptions/BuildRootCheck.toml`
  (entries byte-identical); the port merged the two reference checks into
  one, so a single file named after the port check keeps the check-name to
  TOML mapping total. Ledgered in `tests/parity/divergences.toml`.
- `SpecCheck.toml` — the reference file, plus three port-only entries:
  `translated-description` (upstream rpmlint#2), `license-file-as-doc`
  and `no-license-file-in-spec` (#821). The reference has no such
  findings, so `--explain` would print `Unknown message` for them;
  minus the eleven entries dropped with their deliberately-removed findings
  (`no-buildroot-tag`, `hardcoded-path-in-buildroot-tag`,
  `%ifarch-applied-patch`, `unversioned-explicit-provides`,
  `unversioned-explicit-obsoletes`, `setup-not-quiet`,
  `lib-package-without-%mklibname`, `configure-without-libdir-spec`,
  `use-of-RPM_SOURCE_DIR`, `hardcoded-library-path`,
  `mixed-use-of-spaces-and-tabs`).
  Ledgered in `tests/parity/divergences.toml`.
- `AlternativesCheck.toml`, `FileDigestCheck.toml`, `FilelistCheck.toml`
  (minus the dropped `filelist-forbidden-xinetd-configuration` entry),
  `FilesCheck.toml`, `KMPPolicyCheck.toml`,
  `LogrotateCheck.toml`, `MenuCheck.toml`, `MenuXDGCheck.toml`,
  `SUIDPermissionsCheck.toml`,
  `PythonCheck.toml`, `SpecCheck.toml`
  (besides its one port-only entry above, minus the dropped
  `hardcoded-prefix-tag` and `lib-package-without-%mklibname` entries),
  `SystemdTmpfilesCheck.toml`,
  `TagsCheck.toml` (minus the dropped `invalid-build-requires`,
  `no-provides`, and `no-major-in-name` entries) — the reference files
  with English/logic fixes to individual entries (copy-paste errors
  naming the wrong package, wrong
  scriptlet phase, self-contradictory sentences, ungrammatical wording);
  each fix is a deliberate `kind="detail"` divergence, ledgered in
  `tests/parity/divergences.toml`.
- `SharedLibraryPolicyCheck.toml` — the reference file, plus the
  port-only `shlib-policy-obsoletes-sibling` and
  `shlib-policy-etc-payload` entries. The reference has no
  such findings, so `--explain` would print `Unknown message` for them;
  ledgered in `tests/parity/divergences.toml`.
- `FilesCheck.toml` — the reference file, minus the `outside-libdir-files`
  entry (openSUSE: "Doesn't seem to make sense") dropped with
  the findings, and minus the port-only `zero-length` entry dropped with
  the deliberately removed `zero-length` finding (issue #479), and minus
  the `cross-directory-hard-link`, `file-not-utf8`,
  `log-files-without-logrotate`, `no-documentation`, `non-readable`,
  `non-standard-dir-perm`, `non-standard-executable-perm`,
  `perl-temp-file`, `setgid-binary`, `setuid-binary` and
  `symlink-crontab-file` entries dropped
  with their deliberately-removed findings (issue #883). Plus the
  port-only `manpage-dangling-so-ref`, `sysconfig-fillup-usage`,
  `systemd-preset-packaged` and `symlink-loop` entries: the reference has no such findings, so `--explain` would
  print `Unknown message` for them; ledgered in
  `tests/parity/divergences.toml`.
- `SourceCheck.toml` — the reference file, minus the
  `multiple-specfiles` entry dropped with the deliberately-removed
  finding (issue #883). Ledgered in `tests/parity/divergences.toml`.
- Every other `*.toml` file — byte-identical to the reference
  `rpmlint/descriptions/` file of the same name.

Every check the registry can build now has description coverage: a staged
`<Name>.toml` — or, for `FHSCheck` and `PostCheck`, details registered in
code, mirroring the reference which ships no TOML for those two either
(`fhs_details_dict` / `post_details_dict` installed in each check's
`__init__`). Enforced by
`describe::tests::every_registered_check_has_description_coverage`, so the
gap cannot silently reopen.
