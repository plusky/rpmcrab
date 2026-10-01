#!/usr/bin/env python3
"""Pinning tests for scripts/audit-reference-coverage.py.

Each test guards a resolver capability whose absence silently defeated
the audit in the past: removing the capability makes the test fail.

Run:  python3 scripts/test_audit_reference_coverage.py
"""

import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location(
        "audit_ref_cov", os.path.join(HERE, "audit-reference-coverage.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


audit = _load()


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


# ---------------------------------------------------------------------------
# script_tags: all ten reference script tags
# ---------------------------------------------------------------------------

SCRIPT_TAGS_PY = """\
import rpm
SCRIPT_TAGS = [
    (rpm.RPMTAG_PREIN, rpm.RPMTAG_PREINPROG, '%pre'),
    (rpm.RPMTAG_POSTIN, rpm.RPMTAG_POSTINPROG, '%post'),
    (rpm.RPMTAG_PREUN, rpm.RPMTAG_PREUNPROG, '%preun'),
    (rpm.RPMTAG_POSTUN, rpm.RPMTAG_POSTUNPROG, '%postun'),
    (rpm.RPMTAG_TRIGGERSCRIPTS, rpm.RPMTAG_TRIGGERSCRIPTPROG, '%trigger'),
    (rpm.RPMTAG_PRETRANS, rpm.RPMTAG_PRETRANSPROG, '%pretrans'),
    (rpm.RPMTAG_POSTTRANS, rpm.RPMTAG_POSTTRANSPROG, '%posttrans'),
    (rpm.RPMTAG_VERIFYSCRIPT, rpm.RPMTAG_VERIFYSCRIPTPROG, '%verifyscript'),
    # file triggers: rpm >= 4.12.90
    (getattr(rpm, 'RPMTAG_FILETRIGGERSCRIPTS', 5066),
     getattr(rpm, 'RPMTAG_FILETRIGGERSCRIPTPROG', 5067),
     '%filetrigger'),
    (getattr(rpm, 'RPMTAG_TRANSFILETRIGGERSCRIPTS', 5076),
     getattr(rpm, 'RPMTAG_TRANSFILETRIGGERSCRIPTPROG', 5077),
     '%transfiletrigger'),
]
"""

EXPECTED_TAGS = ["%pre", "%post", "%preun", "%postun", "%trigger",
                 "%pretrans", "%posttrans", "%verifyscript",
                 "%filetrigger", "%transfiletrigger"]


def test_script_tags_finds_all_ten():
    # The old regex read 8 of 10: the multi-line file-trigger tuples
    # carry commas inside getattr(), so [^,]+ never reached the third
    # element -- 28 findings silently escaped the audit.
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "pkg.py"), SCRIPT_TAGS_PY)
        tags = audit.script_tags(d)
    assert tags == EXPECTED_TAGS, tags


# ---------------------------------------------------------------------------
# Reference side: the four grep-missing add_info shapes (#51)
# ---------------------------------------------------------------------------

REF_MODULE_PY = """\
from rpmlint.checks.AbstractCheck import AbstractCheck


class ShapeCheck(AbstractCheck):
    def check_binary(self, pkg):
        # 1. multi-line add_info: the name sits on the continuation line
        self.output.add_info('W', pkg,
                             'multiline-name-on-continuation')
        # 2. concatenation
        self.output.add_info('E', pkg, 'concat-' + 'name')
        # 3. %-template
        self.output.add_info('E', pkg, 'percent-%s-name' % 'middle')
        # 4. *msg splat: the name lives in a tuple assigned lines earlier
        # (real shape: the level is explicit, the name is tuple element 1)
        msg = (pkg, 'splat-name-from-tuple', 'detail')
        self.output.add_info('E', *msg)
"""


def test_reference_grep_missing_shapes():
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "checks", "ShapeCheck.py"), REF_MODULE_PY)
        findings, unresolved, nmods = audit.audit_reference(d)
    names = {n for _, n in findings}
    assert "multiline-name-on-continuation" in names, sorted(names)
    assert "concat-name" in names, sorted(names)
    assert "percent-*-name" in names, sorted(names)
    assert "splat-name-from-tuple" in names, sorted(names)
    assert not unresolved, unresolved


# ---------------------------------------------------------------------------
# Port side: the closure-template format! shape (PostCheck)
# ---------------------------------------------------------------------------

PORT_RS = """\
struct Out;
struct P;
fn add_info(out: &mut Out, level: i32, pkg: &str, name: &str, details: &[&str]) {}
impl P {
    fn check_scriptlet(&self, tag: &str) -> Vec<(i32, String)> {
        let finding = |f: &str| format!("{f}-{tag}");
        let mut out = Vec::new();
        out.push((1, finding("invalid-shell-in")));
        out
    }
    fn check_empty(&self, tag: &str) -> Option<(i32, String)> {
        Some((1, format!("empty-{tag}")))
    }
    fn check_binary(&self) {
        let mut emit = |level: i32, finding: &str| {
            add_info(&mut Out, level, "pkg", finding, &[]);
        };
        for (level, finding) in
            self.check_scriptlet("x")
        {
            emit(level, &finding);
        }
        if let Some((level, finding)) = self.check_empty("x") {
            emit(level, &finding);
        }
    }
}
"""


def test_port_closure_template_format():
    # PostCheck's `let finding = |f: &str| format!("{f}-{tag}")`: without
    # closure-call resolution the port side misses every finding built
    # through it -- 113 false-positive gaps.
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "post.rs"), PORT_RS)
        templates, unresolved = audit.audit_port(d)
    assert not unresolved, unresolved
    assert "invalid-shell-in-*" in templates, sorted(templates)
    assert "empty-*" in templates, sorted(templates)




# ---------------------------------------------------------------------------
# NEW-2: a starred call resolving to nothing is UNRESOLVED, not resolved
# ---------------------------------------------------------------------------

REF_STAR_EMPTY_PY = """\
from rpmlint.checks.AbstractCheck import AbstractCheck


class StarEmptyCheck(AbstractCheck):
    def check_binary(self, pkg, msg):
        # *msg is a parameter: unresolvable here, so this call site must be
        # reported, never silently treated as resolved with zero names.
        self.output.add_info('E', *msg)
"""


def test_starred_call_resolving_to_nothing_is_unresolved():
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "checks", "StarEmptyCheck.py"), REF_STAR_EMPTY_PY)
        findings, unresolved, nmods = audit.audit_reference(d)
    assert not findings, sorted(findings)
    assert len(unresolved) == 1, unresolved
    assert unresolved[0][0] == "StarEmptyCheck", unresolved

def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
        else:
            print(f"ok {t.__name__}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
