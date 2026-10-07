# Test fixture RPMs

This directory contains **hand-built fixture RPMs** for unit tests. These are
NOT distro packages — they are minimal RPMs crafted specifically for testing,
each exercising a particular check behavior.

## Fixtures

| File | Purpose |
|  | Rich deps , , nested,  (#49/#429) |
|  | incorrect-fsf-address whole-file scan (upstream rpmlint#40): wrong address inside/past the 2048-byte window, plus a silent control |
|------|---------|
| `fcprobe-1-1.noarch.rpm` | Hand-built binary-bearing RPM for smoke tests |
| `filescheck-devel-1.0-1.noarch.rpm` | devel package file placement |
| `filescheck-deps-ok-1.0-1.noarch.rpm` | Dependency checks |
| `filescheck-scripts-1.0-1.noarch.rpm` | Scriptlet content checks |
| `w6-sourced-script-1.0-1.noarch.rpm` | sourced-script-with-shebang: profile.d scripts with/without shebang, executable variant, .pm control |
| `postcheck-pretrans-lua-1.0-1.noarch.rpm` | `%pretrans -p <lua>` stays silent (pretrans-not-lua, #140) |
| `ldconfig-test-1.0-1.noarch.rpm` | ldconfig scriptlet handling (#1602) |
| `dbus-parity-1.0-1.noarch.rpm` | DBusPolicyCheck: two `<policy>` elements, one send-allow + one deny-only (issue #58 B1); toxml() detail (B3) |
| `parity-1.0-1.noarch.rpm` | CLI exit-code tests: package with 2 errors for the strict/permissive paths |
| `libnodoc-test-1.0-1.noarch.rpm` | lib package without docs |
| `liboutsidelib-test-1.0-1.noarch.rpm` | lib package with non-lib files |
| `unexpandedmacro-test-1.0-1.noarch.rpm` | Unexpanded macros in filenames |
| `richdep-fixture-1.0-1.noarch.rpm` | Rich deps `(foo or bar)`, `(baz >= 1.0 with baz < 2.0)`, nested, `qux(meta)` (#49/#429) |
| `fsf-address-fixture-1.0-1.noarch.rpm` | incorrect-fsf-address whole-file scan (upstream rpmlint#40): wrong address inside/past the 2048-byte window, plus a silent control |
| `i18n-two-locale-1.0-1.noarch.rpm` | SUMMARY/DESCRIPTION in C and de: two-entry HEADERI18NTABLE for Pkg::tag_i18n_str (follow-up to #248) |
