# A package whose file name is not valid UTF-8

librpm 0.6's decoders **panic** on header data that is not valid UTF-8:
`string_array` does `str::from_utf8(..).expect(..)` and `FileEntry::path` does
`.to_str().expect("file path is not UTF-8")`. Every header read goes through
them, so a package like this one aborts the whole run — a Rust panic, status
101, no report at all.

The reference reads the same package without trouble: it decodes leniently and
carries on (verified against the pinned reference — it reports
`no-signature`, `no-packager-tag`, `no-changelogname-tag`, … and exits 0). For a
non-UTF-8 name in `FILENAMES` the reference additionally reports
`filename-not-utf8`, a finding rpmcrab cannot produce while the safe API panics.

So this is a **robustness fixture, not a parity case**: it is deliberately not in
`tests/parity/cases/`, because rpmcrab cannot lint it. It pins the containment —
`(none): E: fatal error while reading …` and exit 3, the same one line and status
the reference emits for a package it cannot read (`lint.py:293-297`).

## How it was made

`rpmbuild` refuses to create one (`error: Package …: invalid utf-8 encoding in
Basenames`), which is why legacy packages with such names are rare. So:

1. `build.sh` builds a plain, **unsigned** noarch RPM with one normal file.
2. It then rewrites the base name `placeholder.txt` in place to
   `placeh\xfflder.txt`. `0xff` never forms valid UTF-8, and the substitution is
   the same length, so every offset in the header stays valid.
3. Finally it recomputes the header digests, which the signature region stores
   as lowercase hex, and patches them back — so the package is internally
   consistent and the *only* anomaly is the file name.

Regenerate with `bash tests/fixtures/nonutf8-basename/build.sh` (needs
`rpmbuild`; output lands in `input/`). The rebuild is functionally identical
but not byte-identical: rpm orders the signature index entries differently
between runs, so the digest fields land at different offsets and the sha256
below changes. Re-check the sha after regenerating.

`rpm -K` reports `DIGESTS NOT OK` for this package, and that is expected: the
package-level digest covers the whole file and was computed before the header
was rewritten. The *header* digests, which is what reading needs, are correct —
`rpm -qpl` and the reference both read it.

## Provenance

```toml
kind = "synthetic"
rpmlint = "2.10.0"
reference_sha = "84848c05c5571c22274a55ff9afdfe6d88c67dc9"
flavour = "openSUSE"
captured = "2026-09-29"

[[input]]
file = "rpmcrab-nonutf8-1-1.noarch.rpm"
sha256 = "bd271ceb0c98da4cc9cd510339d7ce0d77837203b221a88543c00400929469de"
```
