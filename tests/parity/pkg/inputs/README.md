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
| `ldconfig-test-1.0-1.noarch.rpm` | ldconfig scriptlet handling (#1602) |
| `libnodoc-test-1.0-1.noarch.rpm` | lib package without docs |
| `liboutsidelib-test-1.0-1.noarch.rpm` | lib package with non-lib files |
| `unexpandedmacro-test-1.0-1.noarch.rpm` | Unexpanded macros in filenames |

## Regeneration

These were built with `rpmbuild`. See individual build scripts where present.
To rebuild, use an openSUSE container with `rpm-build` installed.

## Distinction from corpus

Real distro packages for parity testing live in `tests/parity/cases/`
(e.g., `llvm21-gold`). Those are reserved for parity tests that validate
output against the reference implementation. Unit tests should use the
fixtures here, never the corpus.
