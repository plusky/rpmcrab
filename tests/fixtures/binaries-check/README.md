# BinariesCheck test fixture

A tiny RPM containing prebuilt ELF binaries with known properties, used by
the `binaries_check_fixture` test in `crates/rpmcrab-core/src/checks/binaries.rs`.

## Contents

| File | Properties | Expected findings |
|------|------------|-------------------|
| `/usr/lib64/libbad.so.1` | Executable stack (`GNU_STACK RWE`), no SONAME | `executable-stack`, `no-soname` |
| `/usr/lib64/libgood.so.1` | Non-executable stack, `SONAME=libgood.so.1` | (absence: no `executable-stack`, no `no-soname`) |
| `/usr/bin/setuidbin` | Mode 4755, calls `setgid()` and `setuid()` but not `setgroups()` | `missing-call-to-setgroups-before-setuid` at **Error** |
| `/usr/bin/rpathbin` | `RUNPATH=/opt/custom/lib` | `binary-or-shlib-defines-rpath` |
| `/usr/bin/truncated` | 64-byte truncated ELF (header only) | `readelf-failed` |

The `setuidbin` case pins the #1462 severity flip: the reference reports this
finding at Warning for setuid binaries (backwards); rpmcrab reports Error for
setuid binaries and Warning otherwise.

## Regeneration

```bash
bash tests/fixtures/binaries-check/build.sh
```

Needs `podman` and `rpmbuild`. The binaries are compiled in an openSUSE
Tumbleweed container so they are genuine Linux ELFs regardless of host OS.
The container architecture (currently aarch64) does not matter — goblin
parses all ELF types and the findings are architecture-independent.

CI rebuilds the fixtures weekly and on fixture changes
(`.github/workflows/fixtures-rebuild.yml`), failing if a rebuild breaks or
the rebuilt RPM differs from the committed one.

## Dangling DT_GNU_HASH fixture

A second RPM, `input/rpmcrab-binaries-dangling-gnuhash-1.0-1.<arch>.rpm`,
used by `dangling_dt_gnu_hash_still_emits_hash_findings` in
`crates/rpmcrab-core/src/checks/binaries.rs`. It contains one shared library
(`/usr/lib64/libdangling-stripped.so.1`) whose `.hash` and `.gnu.hash`
sections were removed with objcopy, leaving the `DT_GNU_HASH` (and
`DT_HASH`) dynamic entries dangling. Expected findings:
`missing-hash-section` at **Error** and `missing-gnu-hash-section` at
**Warning**; no `readelf-failed` (the port retries goblin's parse
permissively on this shape, like the reference which never inspects the
hash table).

Regenerate with:

```bash
bash tests/fixtures/binaries-check/build-dangling-gnuhash.sh
```
