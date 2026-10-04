# Test fixture RPMs

This directory contains **hand-built fixture RPMs** for unit tests. These are
NOT distro packages — they are minimal RPMs crafted specifically for testing,
each exercising a particular check behavior.

## Fixtures

| File | Purpose |
|------|---------|
| `fcprobe-1-1.noarch.rpm` | Hand-built binary-bearing RPM for smoke tests |
| `filescheck-depmod-*.rpm` | depmod scriptlet variants (ok/wrong/missing) |
| `filescheck-devel-1.0-1.noarch.rpm` | devel package file placement |
| `filescheck-deps-ok-1.0-1.noarch.rpm` | Dependency checks |
| `filescheck-installinfo-*.rpm` | install-info scriptlet variants |
| `filescheck-scripts-1.0-1.noarch.rpm` | Scriptlet content checks |
| `postcheck-pretrans-lua-1.0-1.noarch.rpm` | `%pretrans -p <lua>` stays silent (pretrans-not-lua, #140) |
| `ldconfig-test-1.0-1.noarch.rpm` | ldconfig scriptlet handling (#1602) |
| `dbus-parity-1.0-1.noarch.rpm` | DBusPolicyCheck: two `<policy>` elements, one send-allow + one deny-only (issue #58 B1); toxml() detail (B3) |
| `parity-1.0-1.noarch.rpm` | InitScriptCheck: init script + `%post`/`%preun` bodies with `-p` interpreters — body wins (issue #58 B2) |
| `libnodoc-test-1.0-1.noarch.rpm` | lib package without docs |
| `liboutsidelib-test-1.0-1.noarch.rpm` | lib package with non-lib files |
| `unexpandedmacro-test-1.0-1.noarch.rpm` | Unexpanded macros in filenames |
| `richdep-fixture-1.0-1.noarch.rpm` | Rich deps `(foo or bar)`, `(baz >= 1.0 with baz < 2.0)`, nested, `qux(meta)` (#49/#429) |

## Regeneration

These were built with `rpmbuild`. See individual build scripts where present.
To rebuild, use an openSUSE container with `rpm-build` installed.

## Distinction from corpus

Real distro packages for parity testing live in `tests/parity/cases/`
(e.g., `llvm21-gold`). Those are reserved for parity tests that validate
output against the reference implementation. Unit tests should use the
fixtures here, never the corpus.
