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


def _raise_oserror(path):
    raise OSError(path)


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
        by_module, unresolved = audit.audit_port(d)
    assert not unresolved, unresolved
    templates = by_module["post"]
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


# ---------------------------------------------------------------------------
# NEW-6: the reference-side emission call shape is a closed list
# ---------------------------------------------------------------------------

def _real_reference_pkgdir():
    """The pinned rpmlint tree when available, else None (skip the test).

    CI clones the reference to /tmp/rpmlint-ref before running this file,
    so the pin is live there; a bare `make auditor-test` skips gracefully.
    """
    cands = []
    env = os.environ.get("RPMLINT_REF")
    if env:
        cands += [os.path.join(env, "rpmlint-src", "rpmlint"),
                  os.path.join(env, "rpmlint-src"),
                  os.path.join(env, "rpmlint"), env]
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cands += [os.path.join(root, ".parity-ref", "rpmlint-src", "rpmlint"),
              os.path.join(root, ".parity-ref", "rpmlint-src"),
              os.path.join(root, ".parity-ref"),
              "/tmp/rpmlint-ref"]
    for c in cands:
        if os.path.isdir(os.path.join(c, "checks")):
            return c
        nested = os.path.join(c, "rpmlint")
        if os.path.isdir(os.path.join(nested, "checks")):
            return nested
    return None


def test_reference_output_call_shapes_are_closed():
    # audit_reference visits `self.output.add_info(...)` calls and nothing
    # else. If rpmlint ever reports findings through another output method,
    # the resolver would silently miss every such finding; fail loudly.
    # (`self.output.error_details` reads are data, not emission.)
    import ast as _ast
    pkgdir = _real_reference_pkgdir()
    if pkgdir is None:
        print("skip test_reference_output_call_shapes_are_closed: "
              "no reference tree")
        return
    checkdir = os.path.join(pkgdir, "checks")
    bad = []
    for fn in sorted(os.listdir(checkdir)):
        if not fn.endswith(".py"):
            continue
        tree = _ast.parse(
            open(os.path.join(checkdir, fn), encoding="utf-8").read())
        for node in _ast.walk(tree):
            if (isinstance(node, _ast.Call)
                    and isinstance(node.func, _ast.Attribute)
                    and isinstance(node.func.value, _ast.Attribute)
                    and isinstance(node.func.value.value, _ast.Name)
                    and node.func.value.value.id == "self"
                    and node.func.value.attr == "output"
                    and node.func.attr != "add_info"):
                bad.append(f"{fn}:{node.lineno}: "
                           f"self.output.{node.func.attr}(...)")
    assert not bad, bad


# ---------------------------------------------------------------------------
# NEW-7: GLOBAL_SELF_ATTRS must not silently merge conflicting values
# ---------------------------------------------------------------------------

SELF_ATTR_MOD_A = """\
from rpmlint.checks.AbstractCheck import AbstractCheck


class AttrACheck(AbstractCheck):
    def __init__(self, config, output):
        super().__init__(config, output)
        self.prefix = "aaa"
        self.kind = "same"
"""

SELF_ATTR_MOD_B = """\
from rpmlint.checks.AbstractCheck import AbstractCheck


class AttrBCheck(AbstractCheck):
    def __init__(self, config, output):
        super().__init__(config, output)
        self.prefix = "bbb"
        self.kind = "same"
"""

SELF_ATTR_MOD_C = """\
from rpmlint.checks.AbstractCheck import AbstractCheck


class AttrCCheck(AbstractCheck):
    def __init__(self, config, output):
        super().__init__(config, output)
        self.kind = "different"
"""


def _self_attr_collisions(files):
    mods = []
    with tempfile.TemporaryDirectory() as d:
        for name, text in files.items():
            _write(os.path.join(d, "checks", name), text)
        for name in sorted(files):
            path = os.path.join(d, "checks", name)
            mods.append(audit.RefModule(path, name[:-3], d))
        return audit.self_attr_collisions(mods)


def test_self_attr_union_allows_only_deliberate_prefix():
    # `prefix` differs per module by design (the base class resolves the
    # subclasses' prefixes through the union); every other attr agrees.
    collisions = _self_attr_collisions({"ACheck.py": SELF_ATTR_MOD_A,
                                       "BCheck.py": SELF_ATTR_MOD_B})
    assert collisions == [], collisions


def test_self_attr_union_rejects_silent_collision():
    collisions = _self_attr_collisions({"ACheck.py": SELF_ATTR_MOD_A,
                                       "CCheck.py": SELF_ATTR_MOD_C})
    assert [a for a, _ in collisions] == ["kind"], collisions


def test_self_attr_collision_fails_the_audit():
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "checks", "ACheck.py"), SELF_ATTR_MOD_A)
        _write(os.path.join(d, "checks", "CCheck.py"), SELF_ATTR_MOD_C)
        findings, unresolved, nmods = audit.audit_reference(d)
    assert any(m == "(self-attrs)" for m, _, _ in unresolved), unresolved


# ---------------------------------------------------------------------------
# Wildcard covers are scoped to the check that owns them
# ---------------------------------------------------------------------------

CHECK_RS = """\
pub fn build(name: &str, config: &Config) -> Option<Box<dyn Check>> {
    match name {
        "PostCheck" => Some(Box::new(crate::checks::post::PostCheck::new(config))),
        "FilesCheck" => Some(Box::new(crate::checks::files::FilesCheck::new(
            config,
        ))),
        // The module path is on its own line here, which is what the wrapping
        // arms in the real check.rs look like.
        "MixedOwnershipCheck" => Some(Box::new(
            crate::checks::mixed_ownership::MixedOwnershipCheck::new(config),
        )),
        _ => None,
    }
}

pub fn load(config: &Config) -> Vec<Box<dyn Check>> {
    load_with(config, |name| build(name, config))
}
"""


def test_port_check_map_reads_build_arms_across_line_breaks():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "check.rs")
        _write(path, CHECK_RS)
        got = audit.port_check_map(path)
    # 9 of the 31 real arms put the module path on its own line; a regex that
    # cannot cross the newline silently leaves those checks unmapped.
    assert got == {"PostCheck": "post", "FilesCheck": "files",
                   "MixedOwnershipCheck": "mixed_ownership"}, got


def test_wildcard_from_another_module_does_not_cover():
    # PostCheck's `empty-*` used to cover every `empty-` finding in the tree,
    # so a new unported FilesCheck finding called `empty-a-thing` was invisible.
    by_module = {"post": {"empty-*"}, "files": set()}
    flat = {"empty-*"}
    cmap = {"PostCheck": "post", "FilesCheck": "files"}
    assert audit.covers_finding("PostCheck", "empty-sources", by_module, flat, cmap)
    assert not audit.covers_finding(
        "FilesCheck", "empty-a-brand-new-filescheck-finding", by_module, flat, cmap)


def test_exact_cover_still_counts_from_any_module():
    # A literal name cannot be ambiguous, so cross-module exact emission stays
    # legal: binaries.rs emits readelf-failed for SharedLibraryPolicyCheck and
    # shared_library_policy.rs emits it for BinariesCheck. The owner here
    # deliberately lacks the template, so this only passes via the exact-global
    # branch and would fail as a false gap if that branch were removed.
    # readelf-failed is emitted by binaries.rs, but the owning module of
    # SharedLibraryPolicyCheck is shared_library_policy, which does not emit it.
    # Only the exact-global branch can cover it, so this fails if that branch
    # goes away.
    by_module = {"binaries": {"readelf-failed"}}
    flat = {"readelf-failed"}
    cmap = {"SharedLibraryPolicyCheck": "shared_library_policy"}
    assert audit.covers_finding(
        "SharedLibraryPolicyCheck", "readelf-failed", by_module, flat, cmap)


def test_unmapped_module_keeps_unscoped_cover():
    # Checks with no build() arm yet ship in unmerged branches; they must not
    # start reporting gaps they never reported before.
    by_module = {"post": {"empty-*"}}
    flat = {"empty-*"}
    assert audit.covers_finding("MenuCheck", "empty-sources", by_module, flat, {})
    assert not audit.covers_finding(
        "MenuCheck", "menu-recently-used-xbel", by_module, flat, {})


# ---------------------------------------------------------------------------
# PORT_MODULE_ALIASES: arm-less checks that still get scoped
# ---------------------------------------------------------------------------

ALIASED = {"post": {"empty-*"}, "device_files": {"device-unauthorized-file"},
           "world_writable": set()}
ALIASED_FLAT = {"empty-*", "device-unauthorized-file"}


def test_abstract_base_is_scoped_to_its_concrete_modules():
    # FileMetadataCheck has no build() arm and never will: it is an abstract
    # base whose verdict engine (checks/file_metadata.rs) is registered as
    # DeviceFilesCheck and WorldWritableCheck. Unscoped, post.rs's `empty-*`
    # masked `empty-mutant-filemeta` added to FileMetadataCheck.py -- the
    # exact hole the aliases close.
    assert audit.PORT_MODULE_ALIASES.get("FileMetadataCheck") == (
        "device_files", "world_writable")
    assert not audit.covers_finding(
        "FileMetadataCheck", "empty-mutant-filemeta", ALIASED,
        ALIASED_FLAT, {})
    assert audit.covers_finding(
        "FileMetadataCheck", "device-unauthorized-file", ALIASED,
        ALIASED_FLAT, {})


def test_alias_does_not_leak_another_modules_wildcard():
    # A mapped check still may not borrow a wildcard from a module that has
    # nothing to do with it -- scoping must not become a licence.
    assert not audit.covers_finding(
        "FileMetadataCheck", "empty-sources", ALIASED, ALIASED_FLAT, {})


def test_alias_is_not_a_general_exemption():
    # Every other arm-less check keeps the unscoped fallback, which is what
    # UNSCOPED discloses. BuildRootAndDateCheck is genuinely unported, so a
    # new `empty-` finding there is still masked -- disclosed, not fixed.
    assert "BuildRootAndDateCheck" not in audit.PORT_MODULE_ALIASES
    assert audit.covers_finding(
        "BuildRootAndDateCheck", "empty-mutant-bradc",
        {"post": {"empty-*"}}, {"empty-*"}, {})


def test_exact_match_still_wins_for_an_aliased_check():
    # The exact-match branch runs before scoping, so an aliased check keeps
    # the readelf-failed style cross-module exact emission.
    assert audit.covers_finding(
        "FileMetadataCheck", "device-mismatched-attrs",
        {"binaries": {"device-mismatched-attrs"}},
        {"device-mismatched-attrs"}, {})


def test_aliased_check_is_no_longer_reported_as_unscoped():
    # UNSCOPED is the disclosure; the alias has to clear it or the report
    # keeps advertising an exposure that no longer exists.
    mods = {"FileMetadataCheck", "BuildRootAndDateCheck", "PostCheck"}
    cmap = {"PostCheck": "post"}
    assert audit.unscoped_modules(mods, cmap) == {"BuildRootAndDateCheck"}


def test_alias_covers_nothing_when_its_modules_emit_nothing():
    # A mapping to a module that emits nothing must not silently widen to the
    # unscoped fallback -- an empty result is a gap, which is the loud side.
    assert not audit.covers_finding(
        "FileMetadataCheck", "empty-mutant-filemeta",
        {"post": {"empty-*"}}, {"empty-*"}, {})


# ---------------------------------------------------------------------------
# Dynamic emission sites: the resolver table and its extractors
# ---------------------------------------------------------------------------

BASHISMS_RS = """\
pub struct BashismsCheck {
    use_early_fail: bool,
}

impl BashismsCheck {
    fn classify_bashisms(dash_code: Option<i32>, bashisms_code: Option<i32>) -> Vec<&'static str> {
        let mut out = Vec::new();
        match dash_code {
            Some(2) => out.push("bin-sh-syntax-error"),
            Some(127) | None => return out,
            _ => {}
        }
        if bashisms_code == Some(1) {
            out.push("potential-bashisms");
        }
        let unrelated = "not-a-finding";
        out
    }

    fn check_bashisms(&self, path: &str) -> Vec<&'static str> {
        out.push("potential-bashisms")
    }
}
"""


def test_classify_bashisms_resolves_both_names():
    # commit aa4e2d7 taught audit_port to read bashisms.rs's `warning`
    # variable back through classify_bashisms; without it the two names were
    # UNRESOLVED and the findings only stayed covered by luck.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "bashisms.rs")
        _write(path, BASHISMS_RS)
        src = open(path, encoding="utf-8").read()
    assert audit.fn_push_literals(src, "classify_bashisms") == [
        "bin-sh-syntax-error", "potential-bashisms"]


def test_classify_bashisms_is_scoped_to_the_named_function():
    # The sibling check_bashisms also pushes a name; scanning it too would
    # credit the resolver with findings it never reads. The function-name
    # lookup must be exact, so a prefix collision does not widen the body.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "bashisms.rs")
        _write(path, BASHISMS_RS)
        src = open(path, encoding="utf-8").read()
    got = audit.fn_push_literals(src, "classify_bashisms")
    assert "not-a-finding" not in got, got
    assert len(got) == 2, got


ALTERNATIVES_RS = """\
impl AlternativesCheck {
    fn check_post_phase(lines: &[String]) -> Result<Vec<(String, String)>, &'static str> {
        if lines.is_empty() {
            return Err("update-alternatives-post-call-missing");
        }
        let unrelated = "not-a-finding";
        Ok(vec![])
    }
}
"""


def test_check_post_phase_resolves_its_err_literal():
    # alternatives.rs emits `finding` from an Err(..) returned by
    # check_post_phase; the site is only resolvable through the Err literal.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "alternatives.rs")
        _write(path, ALTERNATIVES_RS)
        src = open(path, encoding="utf-8").read()
    assert audit.fn_err_literals(src, "check_post_phase") == [
        "update-alternatives-post-call-missing"]


SYSTEMD_INSTALL_RS = """\
impl SystemdInstallCheck {
    fn check_unit(
        basename: &str,
        pre: &str,
        post: &str,
        preun: &str,
        postun: &str,
    ) -> Vec<&'static str> {
        let escaped = fancy_regex::escape(basename);
        let patterns = [
            (
                format!(r"systemd-update-helper mark-install-system-units .*{}", escaped),
                pre,
                "systemd-service-without-service_add_pre",
            ),
            (
                format!(r"systemd-update-helper install-system-units .*{}", escaped),
                post,
                "systemd-service-without-service_add_post",
            ),
            (
                format!(r"systemd-update-helper remove-system-units .*{}", escaped),
                preun,
                "systemd-service-without-service_del_preun",
            ),
            (
                format!(r"systemd-update-helper mark-restart-system-units .*{}", escaped),
                postun,
                "systemd-service-without-service_del_postun",
            ),
        ];
        let mut missing = Vec::new();
        for (pattern, script, finding) in &patterns {
            let re = Regex::new(pattern).expect("unit pattern");
            if !script.lines().any(|line| is_match(&re, line)) {
                if *finding == "systemd-service-without-service_del_postun"
                    && postun.lines().any(|l| l.trim() == ":")
                {
                    continue;
                }
                missing.push(*finding);
            }
        }
        missing
    }
}
"""


def test_systemd_check_unit_resolves_all_four_findings():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "systemd_install.rs")
        _write(path, SYSTEMD_INSTALL_RS)
        src = open(path, encoding="utf-8").read()
    assert sorted(set(audit.fn_finding_literals(src, "check_unit"))) == [
        "systemd-service-without-service_add_post",
        "systemd-service-without-service_add_pre",
        "systemd-service-without-service_del_postun",
        "systemd-service-without-service_del_preun"]


def test_systemd_check_unit_drops_non_finding_literals():
    # The raw body scan also yields the four regex templates and the
    # "unit pattern" expect message. Those are wildcard-free, so
    # covers_finding counts them for EVERY module -- an exact template is a
    # global masking hole, and one named `unit pattern` would silence a real
    # reference finding of that name. fn_finding_literals is what keeps them
    # out; dropping them cannot hide a finding, only surface one.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "systemd_install.rs")
        _write(path, SYSTEMD_INSTALL_RS)
        src = open(path, encoding="utf-8").read()
    raw = set(audit._fn_body_literals(src, "check_unit"))
    got = set(audit.fn_finding_literals(src, "check_unit"))
    assert "unit pattern" in raw and ":" in raw, raw
    assert not got & {"unit pattern", ":",
                      r"systemd-update-helper install-system-units .*{}"}
    assert raw - got == {
        "unit pattern", ":",
        r"systemd-update-helper mark-install-system-units .*{}",
        r"systemd-update-helper install-system-units .*{}",
        r"systemd-update-helper remove-system-units .*{}",
        r"systemd-update-helper mark-restart-system-units .*{}"}


def test_finding_name_filter_matches_every_reference_finding():
    # The filter must not drop a name the reference really uses: rpmlint
    # finding names use '-' and '%' (bogus-variable-use-in-%post), '*'
    # (*-file-ghost), '_' and capitals (use-of-RPM_SOURCE_DIR).
    try:
        ref = audit.resolve_ref_dir(None)
    except SystemExit:
        # resolve_ref_dir exits rather than returning a missing path, and CI
        # runs the auditor tests before the reference is fetched.
        return  # no pinned reference checkout; the fixtures above still pin it
    if not os.path.isdir(ref):
        return  # no pinned reference checkout; the fixtures above still pin it
    findings, _, _ = audit.audit_reference(ref)
    bad = sorted({n for _, n in findings
                  if not audit._FINDING_NAME_RE.match(n)})
    assert bad == [], bad


MENU_XDG_RS = """\
impl MenuXDGCheck {
    fn parse_desktop(content: &str, filename: &str) -> Result<DesktopSections, ParseError> {
        let mut sections: DesktopSections = HashMap::new();
        for line in content.lines() {
            if line.starts_with('[') {
                let end = line.find(']').ok_or_else(|| {
                    if current.is_none() {
                        (
                            Level::Error,
                            "desktopfile-missing-header",
                            vec![filename.to_string()],
                        )
                    } else {
                        (
                            Level::Error,
                            "invalid-desktopfile",
                            vec![filename.to_string()],
                        )
                    }
                })?;
            }
        }
        Ok(sections)
    }
}
"""


def test_parse_desktop_resolves_err_tuple_literals():
    # menu_xdg.rs reports through ok_or_else(|| { (Level::Error, "name", ..) }),
    # so it is fn_err_literals' bare-tuple arm -- not the Err((..)) one -- that
    # makes these two names resolvable at all.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "menu_xdg.rs")
        _write(path, MENU_XDG_RS)
        src = open(path, encoding="utf-8").read()
    assert sorted(set(audit.fn_err_literals(src, "parse_desktop"))) == [
        "desktopfile-missing-header", "invalid-desktopfile"]


ERR_TUPLE_RS = """\
impl MenuXDGCheck {
    fn parse_desktop(content: &str) -> Result<DesktopSections, ParseError> {
        if content.is_empty() {
            return Err((Level::Error, "invalid-desktopfile", vec![filename]));
        }
        Ok(DesktopSections::new())
    }
}
"""


def test_err_tuple_form_is_resolved_too():
    # The other tuple shape fn_err_literals accepts: Err((Level, "name", ..)).
    # Bare tuples are common enough that the bare-tuple arm alone would mask a
    # regression here, so the Err((..)) arm needs its own pin.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "menu_xdg.rs")
        _write(path, ERR_TUPLE_RS)
        src = open(path, encoding="utf-8").read()
    assert audit.fn_err_literals(src, "parse_desktop") == ["invalid-desktopfile"]


MENU_XDG_CHECK_BINARY = """
    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        for filename in &pkg.files {
            let content = String::new();
            match Self::parse_desktop(&content, filename) {
                Ok(_) => {}
                Err((level, finding, refs)) => {
                    add_info(out, level, pkg, finding, &refs);
                }
            }
        }
    }
"""


def test_menu_xdg_dynamic_site_resolves_both_names():
    with tempfile.TemporaryDirectory() as d:
        checks = os.path.join(d, "checks")
        _write(os.path.join(checks, "menu_xdg.rs"),
               MENU_XDG_RS + MENU_XDG_CHECK_BINARY)
        by_module, unresolved = audit.audit_port(checks)
    assert by_module["menu_xdg"] == {"desktopfile-missing-header",
                                      "invalid-desktopfile"}, by_module
    assert unresolved == [], unresolved


FILELIST_TOML = """\
[FileCheck-dev]
File = /dev/*
Message = "file-not-in-lang"
"""


def test_rust_filelist_messages_reads_the_embedded_toml():
    # filelist.rs emits `rule.message`, which is populated at build time from
    # the include_str!'d TOML. The auditor has to find that file via
    # dirname(dirname(port_dir))/data, two levels above the checks dir.
    with tempfile.TemporaryDirectory() as d:
        port_dir = os.path.join(d, "src", "checks")
        os.makedirs(port_dir)
        _write(os.path.join(d, "data", "FilelistCheck.toml"), FILELIST_TOML)
        assert audit.rust_filelist_messages(port_dir) == ["file-not-in-lang"]


def test_rust_filelist_messages_absent_toml_is_empty_not_fatal():
    # _read already turns a missing file into "", so the guard is invisible
    # unless the read really raises -- which is what an absent include_str!
    # would do if the embed ever moved. Force the failure mode so the guard
    # is pinned rather than merely present.
    original = audit._read
    audit._read = _raise_oserror
    try:
        with tempfile.TemporaryDirectory() as d:
            port_dir = os.path.join(d, "src", "checks")
            os.makedirs(port_dir)
            assert audit.rust_filelist_messages(port_dir) == []
    finally:
        audit._read = original


# ---------------------------------------------------------------------------
# The dynamic_sites table has no silent fallback
# ---------------------------------------------------------------------------

ALT_CHECK_BINARY = """
    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let post_lines = Vec::new();
        let install = match Self::PRODUCER(&post_lines) {
            Ok(install) => install,
            Err(finding) => {
                add_info(out, Level::Error, pkg, finding, &[]);
                return;
            }
        };
    }
"""


def _port(files):
    """audit_port over a synthetic checks dir."""
    with tempfile.TemporaryDirectory() as d:
        checks = os.path.join(d, "checks")
        for name, text in files.items():
            _write(os.path.join(checks, name), text)
        return audit.audit_port(checks)


def _alt_port(producer):
    return _port({"alternatives.rs":
                  ALTERNATIVES_RS.replace("check_post_phase", producer)
                  + ALT_CHECK_BINARY.replace("PRODUCER", producer)})


def test_dynamic_site_resolves_through_the_named_producer():
    by_module, unresolved = _alt_port("check_post_phase")
    assert by_module["alternatives"] == {"update-alternatives-post-call-missing"}
    assert unresolved == [], unresolved


def test_renamed_producer_makes_the_site_unresolved():
    # The property the table must have: no defaulting. Rename the producing
    # function and the name is NOT silently covered by anything -- it turns
    # into an UNRESOLVED entry, which exits 1 and says "review by hand".
    by_module, unresolved = _alt_port("check_post_phase_v2")
    assert by_module["alternatives"] == set(), by_module["alternatives"]
    assert len(unresolved) == 1, unresolved
    assert unresolved[0][0] == "alternatives.rs", unresolved
    assert unresolved[0][2] == "finding", unresolved


BASHISMS_CHECK_BINARY = """
    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        for pkgfile in &pkg.files {
            let warnings = self.check_bashisms(&pkgfile.name);
            for warning in warnings.clone() {
                add_info(out, Level::Warning, pkg, warning, &[&pkgfile.name]);
            }
        }
    }
"""


def test_bashisms_dynamic_site_resolves_both_names():
    by_module, unresolved = _port({"bashisms.rs":
                                   BASHISMS_RS + BASHISMS_CHECK_BINARY})
    assert by_module["bashisms"] == {"bin-sh-syntax-error",
                                     "potential-bashisms"}, by_module
    assert unresolved == [], unresolved


SYSTEMD_CHECK_BINARY = """
    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let (pre, post, preun, postun) = ("", "", "", "");
        for basename in &pkg.files {
            for finding in Self::check_unit(basename, &pre, &post, &preun, &postun) {
                add_info(out, Level::Error, pkg, finding, &[basename]);
            }
        }
    }
"""


def test_systemd_dynamic_site_resolves_findings_and_nothing_else():
    # End to end through audit_port, so the table entry and the filter are
    # pinned together: the four findings arrive, the expect message and the
    # regex templates do not.
    by_module, unresolved = _port({"systemd_install.rs":
                                   SYSTEMD_INSTALL_RS + SYSTEMD_CHECK_BINARY})
    assert by_module["systemd_install"] == {
        "systemd-service-without-service_add_pre",
        "systemd-service-without-service_add_post",
        "systemd-service-without-service_del_preun",
        "systemd-service-without-service_del_postun"}, by_module
    assert unresolved == [], unresolved


def test_renamed_systemd_producer_makes_the_site_unresolved():
    by_module, unresolved = _port({"systemd_install.rs":
                                   SYSTEMD_INSTALL_RS.replace(
                                       "check_unit", "check_unit_v2")
                                   + SYSTEMD_CHECK_BINARY})
    assert by_module["systemd_install"] == set(), by_module["systemd_install"]
    assert [u[2] for u in unresolved] == ["finding"], unresolved


def test_stale_check_catches_name_keyed_entry():
    # The staleness check must mark an entry stale when the port emits the
    # finding of a kind="missing" ledger entry. The corpus pins the shape:
    # all 6 current missing entries are keyed by finding name (case
    # "global") -- there is no module-keyed missing entry, so the test
    # drives the mechanism with the real ledger rather than a synthetic
    # module set. (The module arm of the disjunction has no live data
    # behind it; nothing here pretends otherwise.)
    mod = _load()
    ledger = mod.load_ledger(os.path.join(
        os.path.dirname(HERE), "tests", "parity", "divergences.toml"))
    missing = [e for e in ledger if e.get("kind") == "missing"]
    names = {e.get("check") for e in missing}
    assert names == {
        "inaccessible-filename",
        "lengthy-symlink",
        "info-files-without-install-info-postin",
        "info-files-without-install-info-postun",
        "sourced-script-with-shebang",
        "symlink-contains-up-and-down-segments",
    }, names
    assert all(e.get("case") == "global" for e in missing), [
        (e.get("case"), e.get("check")) for e in missing]
    # missing_modules exactly as main() builds it (shared helper, so drift
    # in either direction breaks this test).
    missing_modules = mod.missing_check_names(ledger)
    for name in sorted(names):
        # A finding whose NAME matches a name-keyed missing entry, but whose
        # MODULE does not, IS stale (with exact pattern).
        assert mod.is_stale_entry(
            "SomeOtherCheck", name, missing_modules, {name}
        ), f"name-keyed match should be stale: {name}"
    # A wildcard template must not count even when it literally equals the
    # finding name: only exact non-wildcard patterns mark an entry stale.
    # This pins the "*" not in p guard -- deleting it makes this fail, while
    # the old form (template "inaccessible-*" vs name "inaccessible-filename")
    # passed vacuously since p == name was already false.
    star_name = "inaccessible-filen*me"
    assert not mod.is_stale_entry(
        "SomeOtherCheck", star_name, missing_modules | {star_name}, {star_name}
    ), f"wildcard template should not mark stale: {star_name}"


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
