#!/usr/bin/env python3
"""AST-based reference-coverage audit (rpmcrab #51).

For every ``rpmlint/checks/*.py`` module in the pinned reference tree, parse
it with :mod:`ast`, visit every ``add_info`` call, and resolve the finding
name (argument 3) through string literals, ``+`` concatenation, ``%``
templates, f-strings, and local/class variable bindings -- including the
shapes that line-oriented tools cannot see:

* ``add_info('E', *msg)`` where the name lives in a tuple assigned lines
  earlier (``python-bytecode-wrong-magic-value``),
* ``f'{self.prefix}-unauthorized-file'`` where the prefix is set by a
  *subclass* in another module (``device-*`` / ``world-writable-*``),
* names built from module dicts (``ERRS[...]``), TOML data
  (``FilelistCheck.toml`` ``Message``), config tables (``IconPath``), and
  generator yields (``BashismsCheck``).

The port's finding-name set (``crates/rpmcrab-core/src/checks/*.rs``) is
resolved the same way: string literals plus ``format!`` templates, through
``let`` bindings, conditionals, and tuple-returning helpers. A reference
name is *covered* when a port pattern matches it, where ``*`` on either
side is a wildcard for a dynamic part.

Output is exactly "reference names absent from the port AND unledgered":
a finding counts as ledgered when its check module has a ``kind =
"missing"`` entry in ``tests/parity/divergences.toml``, or its name
appears in a divergence entry's reason text.

Two traps are encoded, both found the hard way:

* The reference's own ``descriptions/*.toml`` is NOT authoritative:
  ``enchant-dictionary-not-found``, ``private-shared-object-provides`` and
  ``postun-without-install-info`` appear there but are emitted nowhere in
  ``rpmlint/checks/*.py``. The audit is driven off ``add_info`` calls, and
  descriptions are never consulted.
* Prefix-derived names only resolve because the base class
  (``FileMetadataCheck.py``) is included in the pass *and* ``self.prefix``
  assignments are collected across all check modules.

Three more decisions are encoded deliberately, not by default:

* ``kind = "missing"`` keeps its coarse granularity: "missing" means no
  check in the port emits any finding of that module. The failure mode a
  finer grain (``ported_since``, per-name absence) would guard against --
  an entry going stale after the finding is ported -- is caught harder: a
  ``kind = "missing"`` entry whose module has a finding the port emits is
  a STALE LEDGER hard error. A bookkeeping field would only record the
  claim; the auditor verifies it.
* The ledger never overrides the port, and the port never overrides the
  ledger: a finding that is both ledgered-missing and ported is a
  STALE LEDGER hard error (exit 1), forcing a human to delete or correct
  the entry. Either side silently winning would reintroduce the exact
  blind spot this tool exists to close.
* The resolver's closed assumptions are pinned, not defaulted: the
  reference-side emission shape (``self.output.add_info``) and the
  cross-module ``self.<attr>`` union each have a test that fails loudly
  if the assumption stops holding (NEW-6/NEW-7).

A call site the resolver cannot handle is reported as UNRESOLVED, never
silently dropped: an audit that hides what it cannot see is worse than
no audit.

Usage:
    python3 scripts/audit-reference-coverage.py [REF_PATH]
        [--port DIR] [--ledger FILE]

    REF_PATH defaults to the ``scripts/setup-rpmlint-ref.sh`` layout
    (``<repo>/.parity-ref/rpmlint-src``); the ``RPMLINT_REF`` environment
    variable (the ``scripts/capture-parity.sh`` convention: the reference
    *env* dir holding ``rpmlint-src/``) is honored when no argument is
    given. A checkout root and a package dir are both accepted.

Requires Python 3.11+ (``tomllib``).

Exit codes: 0 = no gaps and nothing unresolved; 1 = gaps or unresolved
sites need review; 2 = usage / IO / parse error.
"""

import ast
import os
import re
import sys

try:
    import tomllib
except ImportError:  # pragma: no cover
    sys.stderr.write("error: audit-reference-coverage.py needs Python 3.11+ (tomllib)\n")
    sys.exit(2)


# ---------------------------------------------------------------------------
# Small value model for the resolvers.
#
# A resolved "string" is a template where "*" stands for a dynamic part
# (a loop variable, an unknown value, a %-spec). Two templates match when
# the port pattern covers the reference template (see `covers`).
# ---------------------------------------------------------------------------

class S:
    """A string template, possibly containing "*" wildcards."""
    __slots__ = ("t",)

    def __init__(self, t):
        self.t = t

    def __repr__(self):
        return f"S({self.t!r})"

    def __hash__(self):
        return hash(self.t)

    def __eq__(self, other):
        return isinstance(other, S) and self.t == other.t


class D:
    """A dict literal: keys are plain strings, values are value-sets."""
    __slots__ = ("d",)

    def __init__(self, d):
        self.d = d  # {str: set[Val]}


class Seq:
    """A list or tuple literal."""
    __slots__ = ("items", "is_tuple")

    def __init__(self, items, is_tuple):
        self.items = items  # [set[Val]]
        self.is_tuple = is_tuple


class ConfigTable:
    """self.config.configuration['Name'] -- resolved from the reference TOML."""
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name


UNKNOWN = object()  # sentinel for "a value we cannot resolve"


def as_strings(vals):
    """Project a value-set down to string templates."""
    out = set()
    for v in vals:
        if isinstance(v, S):
            out.add(v.t)
    return out


def template_regex(t):
    """A template with "*" wildcards -> regex matching the whole string."""
    return re.compile("".join(".*" if c == "*" else re.escape(c) for c in t) + r"\Z")


def covers(port_t, ref_t):
    """Does port template `port_t` cover reference template `ref_t`?

    Approximate subsumption: match the port pattern against the reference
    template with each "*" replaced by a sentinel no literal name character
    can produce, so only a ".*" in the port pattern matches it.
    """
    probe = ref_t.replace("*", "\x00")
    return template_regex(port_t).match(probe) is not None


def port_check_map(check_rs):
    """Reference check name -> owning port module, from check::build()'s arms.

    check.rs is the port's own registration point, so this cannot drift from
    the code: an arm exists for a check exactly when the check is
    constructible. Returns None when the file or build() cannot be located,
    so the caller can tell "no arms" from "could not look" -- an empty map
    would silently restore the unscoped matching this exists to prevent.
    """
    try:
        with open(check_rs, encoding="utf-8") as f:
            src = f.read()
    except OSError:
        return None
    start = src.find("pub fn build(")
    end = src.find("pub fn load(", start) if start >= 0 else -1
    if start < 0 or end < 0:
        return None
    # Slice into arms first, then look for the module path inside each arm. A
    # single regex over the whole body would let its gap cross a `=>` and
    # attribute one arm to the next arm's module.
    headers = list(re.finditer(r'"([A-Za-z0-9_]+)"\s*=>', src[start:end]))
    out = {}
    for i, h in enumerate(headers):
        stop = headers[i + 1].start() if i + 1 < len(headers) else len(src[start:end])
        mod = re.search(r"crate::checks::([a-z0-9_]+)::", src[start + h.end():start + stop])
        if mod:
            out[h.group(1)] = mod.group(1)
    return out


# Reference checks that structurally cannot own a `check::build()` arm, so
# `port_check_map` can never report them, mapped to the port modules that
# actually emit their findings. FileMetadataCheck is an abstract base in the
# reference: checks/file_metadata.py holds the shared verdict engine and is
# registered as two concrete checks, DeviceFilesCheck and WorldWritableCheck.
# Without an entry it fell into the unscoped fallback forever, where
# post.rs's `empty-*` masked a new FileMetadataCheck finding (VERIFIED).
# This is the same explicit mapping the exact-match branch already gives
# readelf-failed, not a general exemption: anything absent here still falls
# back and is still reported as UNSCOPED.
PORT_MODULE_ALIASES = {
    "FileMetadataCheck": ("device_files", "world_writable"),
}


def covers_finding(module, name, by_module, flat, check_map):
    """Is reference finding `name` of `module` covered by the port?

    A wildcard-free port template is unambiguous -- the name matches
    literally -- so it counts wherever it lives. A wildcard is not:
    `PostCheck`'s `empty-*` would otherwise mask a new, genuinely unported
    `empty-` finding of any other check. A wildcard therefore only counts
    from the check's own module, which comes from `check::build()`'s arms
    or, for the few checks that cannot have one, from
    PORT_MODULE_ALIASES. Remaining arm-less checks (they ship in branches
    that have not merged yet) keep the old unscoped behaviour, and are
    reported so the fallback stays visible.
    """
    if any("*" not in p and covers(p, name) for p in flat):
        return True
    owner = check_map.get(module)
    if owner is None:
        owners = PORT_MODULE_ALIASES.get(module)
        if owners is not None:
            return any(covers(p, name) for m in owners
                       for p in by_module.get(m, ()))
        return any(covers(p, name) for p in flat)
    return any(covers(p, name) for p in by_module.get(owner, ()))


def unscoped_modules(finding_modules, check_map):
    """Checks whose findings fall back to matching every port pattern.

    Arm-less and not aliased is the exposure: a wildcard from anywhere can
    still mask a finding added to one of these. A check is listed whether or
    not any of its findings happen to be covered, so a check that never
    reports a gap stays visible.
    """
    return (set(finding_modules) - set(check_map)) - set(PORT_MODULE_ALIASES)


# ---------------------------------------------------------------------------
# printf-style ("%" operator) and format! template handling
# ---------------------------------------------------------------------------

_PCT_RE = re.compile(
    r"%%"                      # literal percent
    r"|%\([^)]+\)[diuoxXeEfFgGcrsa]"   # %(name)s mapping keys
    r"|%[#0\- +]*\d*(?:\.\d+)?[hlL]*[diuoxXeEfFgGcrsa]"  # plain conversions
)


def printf_template(fmt):
    """'no-%%%s-section' -> 'no-%*-section' (%% becomes a literal %)."""
    out = []
    i = 0
    for m in _PCT_RE.finditer(fmt):
        tok = m.group(0)
        out.append(fmt[i:m.start()])
        out.append("%" if tok == "%%" else "*")
        i = m.end()
    out.append(fmt[i:])
    return "".join(out)


def format_macro_template(tmpl):
    """Rust format! template -> "*" template ('{{'/'}}' are literal braces)."""
    out = []
    i, n = 0, len(tmpl)
    while i < n:
        c = tmpl[i]
        if c == "{" and i + 1 < n and tmpl[i + 1] == "{":
            out.append("{")
            i += 2
        elif c == "}" and i + 1 < n and tmpl[i + 1] == "}":
            out.append("}")
            i += 2
        elif c == "{":
            j = tmpl.find("}", i)
            if j == -1:
                out.append(c)
                i += 1
            else:
                out.append("*")
                i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


_RUST_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "0": "\0"}


def rust_unescape(s):
    out = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n and s[i + 1] in _RUST_ESCAPES:
            out.append(_RUST_ESCAPES[s[i + 1]])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Reference-tree location
# ---------------------------------------------------------------------------

def repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _is_pkgdir(p):
    return os.path.isdir(os.path.join(p, "checks"))


def resolve_ref_dir(arg):
    """Accept a package dir (has checks/), a clone root (has rpmlint/checks/),
    the RPMLINT_REF env dir, or the setup-rpmlint-ref.sh default layout."""
    cands = []
    if arg:
        cands.append(arg)
    env = os.environ.get("RPMLINT_REF")
    if env and not arg:
        cands += [os.path.join(env, "rpmlint-src", "rpmlint"),
                  os.path.join(env, "rpmlint-src"),
                  os.path.join(env, "rpmlint"),
                  env]
    if not arg and not env:
        root = repo_root()
        cands += [os.path.join(root, ".parity-ref", "rpmlint-src", "rpmlint"),
                  os.path.join(root, ".parity-ref", "rpmlint-src"),
                  os.path.join(root, ".parity-ref")]
    for c in cands:
        if _is_pkgdir(c):
            return c
        nested = os.path.join(c, "rpmlint")
        if _is_pkgdir(nested):
            return nested
    sys.stderr.write(
        "error: no reference tree found (tried: %s)\n"
        "hint: run scripts/setup-rpmlint-ref.sh, set RPMLINT_REF, or pass the path\n"
        % ", ".join(cands))
    sys.exit(2)


# ---------------------------------------------------------------------------
# Reference config tables (for config-driven finding names)
# ---------------------------------------------------------------------------

def _read(p):
    try:
        with open(p, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def config_table_values(pkgdir, table, key=None):
    """Extract values from [Table] / [Table."entry"] sections of the
    reference config (configdefaults.toml plus the openSUSE overlay).

    Returns {'entries': [section names], 'kv': {entry: {k: v}}} for dotted
    subtables. Only the shapes the checks use are supported (IconPath,
    WarnOnFunction); anything else yields no values, which the caller
    reports rather than silently dropping.
    """
    cands = [os.path.join(pkgdir, "configdefaults.toml")]
    overlay = os.path.join(os.path.dirname(pkgdir.rstrip(os.sep)), "configs", "openSUSE")
    if os.path.isdir(overlay):
        cands += sorted(os.path.join(overlay, f) for f in os.listdir(overlay)
                        if f.endswith(".toml"))
    entries, kv = [], {}
    for path in cands:
        text = _read(path)
        cur = None
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = re.match(r"\[(%s)\." % re.escape(table)
                         + r"(?:\"([^\"]+)\"|([^\]]+))\]" % (), s)
            if m:
                cur = (m.group(2) or m.group(3)).strip()
                if cur not in entries:
                    entries.append(cur)
                kv.setdefault(cur, {})
                continue
            if s.startswith("["):
                cur = None
                continue
            if cur is not None:
                km = re.match(r"([A-Za-z0-9_]+)\s*=\s*\"([^\"]*)\"", s)
                if km:
                    kv[cur][km.group(1)] = km.group(2)
    if key is None:
        return entries
    return [kv[e][key] for e in entries if key in kv[e]]


def filelist_messages(pkgdir):
    """All Message values from checks/FilelistCheck.toml."""
    text = _read(os.path.join(pkgdir, "checks", "FilelistCheck.toml"))
    return re.findall(r'^\s*Message\s*=\s*"([^"]+)"', text, re.M)



def rust_filelist_messages(port_dir):
    """All Message values from the port's FilelistCheck.toml.

    The Rust FilelistCheck reads its rules from an embedded TOML
    (include_str!("../../data/FilelistCheck.toml")); the `rule.message`
    values are the finding names it emits.
    """
    # port_dir is crates/rpmcrab-core/src/checks; the TOML lives at
    # crates/rpmcrab-core/data/FilelistCheck.toml (include_str!("../../data/..."))
    import os as _os
    toml_path = _os.path.join(
        _os.path.dirname(_os.path.dirname(port_dir)), "data", "FilelistCheck.toml")
    try:
        text = _read(toml_path)
    except OSError:
        return []
    return re.findall(r'^\s*Message\s*=\s*"([^"]+)"', text, re.M)

def fn_err_literals(src, fn_name):
    """String literals in Err("...") within the named Rust function.

    For `match Self::f(...) { Err(x) => add_info(..., x, ...) }` sites where
    the finding flows through a Result's error value.
    """
    # Find fn <name>(
    m = re.search(r"fn\s+" + re.escape(fn_name) + r"\s*\(", src)
    if not m:
        return []
    # Find the opening brace of the body
    brace = src.find("{", m.end())
    if brace == -1:
        return []
    depth = 0
    end = brace
    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    body = src[brace:end + 1]
    # Find Err("literal") and Err((level, "literal", ...)) tuple forms.
    found = re.findall(r"Err\(\s*\"([^\"]+)\"", body)
    # Tuple form: Err((Level::Error, "name", ...)) - second element
    for m in re.finditer(r"Err\(\s*\(\s*[\w:]+\s*,\s*\"([^\"]+)\"", body):
        found.append(m.group(1))
    # Bare tuple return: (Level::Error, "name", ...) - second element
    for m in re.finditer(r"\(\s*Level::[\w]+\s*,\s*\"([^\"]+)\"", body):
        if m.group(1) not in found:
            found.append(m.group(1))
    return found


def fn_push_literals(src, fn_name):
    """String literals in out.push("...") within the named Rust function.

    For sites where findings accumulate in a Vec via push.
    """
    m = re.search(r"fn\s+" + re.escape(fn_name) + r"\s*\(", src)
    if not m:
        return []
    brace = src.find("{", m.end())
    if brace == -1:
        return []
    depth = 0
    end = brace
    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    body = src[brace:end + 1]
    found = re.findall(r"\.push\(\s*\"([^\"]+)\"", body)
    return found

def _fn_body_literals(src, fn_name):
    """All quoted string literals in the named function body."""
    m = re.search(r"fn\s+" + re.escape(fn_name) + r"\s*\(", src)
    if not m:
        return []
    brace = src.find("{", m.end())
    if brace == -1:
        return []
    depth = 0
    end = brace
    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    body = src[brace:end + 1]
    return re.findall(r"\"([^\"]+)\"", body)


_FINDING_NAME_RE = re.compile(r"^[A-Za-z0-9_.%*-]+$")


def fn_finding_literals(src, fn_name):
    """`_fn_body_literals` minus the literals that are not finding names.

    check_unit keeps its four findings in the same body as its regex
    templates ("systemd-update-helper install-system-units .*{}") and its
    expect message ("unit pattern"). An exact template counts for every
    module, so each stray one is a global masking hole for a reference
    finding that happens to share the name. rpmlint finding names are drawn
    from a narrow alphabet (letters, digits, '-', '%', '*', '_', '.'); all
    648 distinct reference names fit it and none of the strays do. It fails
    safe: a literal that ever stops fitting can only add a GAPS entry, never
    hide one.
    """
    return [l for l in _fn_body_literals(src, fn_name)
            if _FINDING_NAME_RE.match(l)]

def fn_describe_tuple_literals(src, fn_name):
    """String literals in the second position of ``(Level::*, "name", ...)``
    tuple expressions within the named Rust function.

    For helpers that return a ``(level, name, details)`` triple in one
    match arm per variant, with the name flowing into ``add_info``
    (``DuplicatesCheck::describe``). One match cannot mispair with
    itself, so the auditor only needs the name set -- variant pairing is
    pinned by the test. Fails safe: an unrecognized shape yields nothing
    and the call site goes UNRESOLVED.
    """
    m = re.search(r"fn\s+" + re.escape(fn_name) + r"\s*\(", src)
    if not m:
        return []
    brace = src.find("{", m.end())
    if brace == -1:
        return []
    depth = 0
    end = brace
    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    body = src[brace:end + 1]
    return re.findall(r"\(\s*Level::\w+\s*,\s*\"([^\"]+)\"", body)


def script_tags(pkgdir):
    """The '%pre'/'%post'/... tags: third elements of Pkg.SCRIPT_TAGS.

    Parsed with :mod:`ast`: the file-trigger tuples span lines and their
    first two elements contain commas, so a regex misses them (8 of 10).
    """
    text = _read(os.path.join(pkgdir, "pkg.py"))
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "SCRIPT_TAGS"
                   for t in node.targets):
            continue
        if not isinstance(node.value, ast.List):
            continue
        tags = []
        for elt in node.value.elts:
            if (isinstance(elt, ast.Tuple) and len(elt.elts) >= 3
                    and isinstance(elt.elts[2], ast.Constant)
                    and isinstance(elt.elts[2].value, str)):
                tags.append(elt.elts[2].value)
        return tags
    return []


# ---------------------------------------------------------------------------
# Reference module analysis
# ---------------------------------------------------------------------------

class RefModule:
    def __init__(self, path, modname, pkgdir):
        self.path = path
        self.modname = modname
        self.pkgdir = pkgdir
        with open(path, encoding="utf-8") as f:
            self.source = f.read()
        self.tree = ast.parse(self.source, path)
        self.mod_vars = {}    # name -> set of values (flow-insensitive union)
        self.self_attrs = {}  # attr -> set of values, from self.attr = ...
        self.funcs = {}       # name -> FunctionDef
        self._raw_cache = {}
        self._locals_cache = {}
        self._collect()

    def _add(self, d, k, vals):
        d.setdefault(k, set()).update(vals)

    def _collect(self):
        for node in self.tree.body:
            if isinstance(node, ast.FunctionDef):
                self.funcs[node.name] = node
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Assign):
                        vals = resolve_expr(sub.value, self, None)
                        for t in sub.targets:
                            if isinstance(t, ast.Name):
                                self._add(self.mod_vars, t.id, vals)
                            elif (isinstance(t, ast.Attribute)
                                  and isinstance(t.value, ast.Name)
                                  and t.value.id == "self"):
                                self._add(self.self_attrs, t.attr, vals)
                    elif isinstance(sub, ast.AnnAssign) and sub.value is not None:
                        vals = resolve_expr(sub.value, self, None)
                        t = sub.target
                        if isinstance(t, ast.Name):
                            self._add(self.mod_vars, t.id, vals)
            elif isinstance(node, ast.ClassDef):
                for sub in node.body:
                    if isinstance(sub, ast.FunctionDef):
                        self.funcs[sub.name] = sub
                        for ssub in ast.walk(sub):
                            if isinstance(ssub, ast.Assign):
                                vals = resolve_expr(ssub.value, self, None)
                                for t in ssub.targets:
                                    if (isinstance(t, ast.Attribute)
                                            and isinstance(t.value, ast.Name)
                                            and t.value.id == "self"):
                                        self._add(self.self_attrs, t.attr, vals)
                    elif isinstance(sub, ast.Assign):
                        vals = resolve_expr(sub.value, self, None)
                        for t in sub.targets:
                            if isinstance(t, ast.Name):
                                self._add(self.mod_vars, t.id, vals)
            elif isinstance(node, ast.Assign):
                vals = resolve_expr(node.value, self, None)
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self._add(self.mod_vars, t.id, vals)

    def func_locals(self, func, resolving=frozenset()):
        """Flow-insensitive local bindings of a function: name -> value set.

        Two-phase: raw assignment nodes are cached per function, then
        resolved on demand with `resolving` guarding cyclic bindings
        (``x = y`` / ``y = x`` terminates instead of recursing forever).
        The common (acyclic) case is cached per function.
        """
        if func is None:
            return {}
        if not resolving:
            key = id(func)
            if key not in self._locals_cache:
                self._locals_cache[key] = self._func_locals_uncached(func, frozenset())
            return self._locals_cache[key]
        return self._func_locals_uncached(func, resolving)

    def _func_locals_uncached(self, func, resolving):
        out = {}
        for name, nodes in self.raw_locals(func).items():
            vals = set()
            for node in nodes:
                vals.update(self._resolve_raw(node, func, resolving, name))
            out[name] = vals
        return out

    def raw_locals(self, func):
        """Raw (unresolved) assignment value nodes per local name."""
        key = id(func)
        if key not in self._raw_cache:
            raw = {}
            for node in ast.walk(func):
                if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                        and isinstance(node.value.func, ast.Attribute)
                        and node.value.func.attr == "append"
                        and isinstance(node.value.func.value, ast.Name)
                        and node.value.args):
                    # X.append(v): X accumulates v (BinariesCheck's
                    # forbidden_calls)
                    raw.setdefault(node.value.func.value.id, []).append(
                        node.value.args[0])
                elif isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            raw.setdefault(t.id, []).append(node.value)
                        elif isinstance(t, ast.Subscript):
                            base = t.value
                            if (isinstance(base, ast.Attribute)
                                    and isinstance(base.value, ast.Name)
                                    and base.value.id == "self"):
                                raw.setdefault(f"self.{base.attr}[]", []).append(node.value)
                elif isinstance(node, ast.AnnAssign) and node.value is not None:
                    if isinstance(node.target, ast.Name):
                        raw.setdefault(node.target.id, []).append(node.value)
            self._raw_cache[key] = raw
        return self._raw_cache[key]

    def _resolve_raw(self, node, func, resolving, name):
        key = (id(func), name)
        if key in resolving:
            return set()
        return resolve_expr(node, self, func, resolving=resolving | {key})

    def string_yields(self, funcname):
        """String templates yielded by a (generator) method."""
        func = self.funcs.get(funcname)
        out = set()
        if func is None:
            return out
        for node in ast.walk(func):
            if isinstance(node, ast.Yield):
                for v in resolve_expr(node.value, self, func):
                    if isinstance(v, S):
                        out.add(v.t)
        return out

    def method_returns(self, funcname, depth=0):
        """Value-sets returned by a method (one level of self-call tracing)."""
        if depth > 1:
            return set()
        func = self.funcs.get(funcname)
        out = set()
        if func is None:
            return out
        for node in ast.walk(func):
            if isinstance(node, ast.Return) and node.value is not None:
                out.update(resolve_expr(node.value, self, func, depth=depth))
        return out


# Filled after all modules are parsed: attr -> set of values, unioned across
# every check module, so a base class sees its subclasses' self.prefix.
GLOBAL_SELF_ATTRS = {}


# Attributes deliberately unioned across check modules: `self.prefix` is
# set per subclass (device, world-writable, ...) and the base class
# resolves it through the union. Any other attribute taking different
# literal values in different modules would merge silently into one set,
# which is a bug, not a feature.
DELIBERATE_ATTR_UNIONS = frozenset({"prefix"})


def self_attr_collisions(modules):
    """Non-deliberate `self.<attr>` value conflicts across check modules.

    Returns [(attr, {module: sorted values})] for every attribute outside
    DELIBERATE_ATTR_UNIONS where two modules resolve to different literal
    value sets. An empty set means "unknown" (config-driven, parameter) and
    never collides: only differing literal sets are reported.
    """
    by_attr = {}
    for m in modules:
        for attr, vals in m.self_attrs.items():
            by_attr.setdefault(attr, {})[m.modname] = {
                v.t for v in vals if isinstance(v, S)}
    out = []
    for attr in sorted(by_attr):
        if attr in DELIBERATE_ATTR_UNIONS:
            continue
        literal = {m: v for m, v in by_attr[attr].items() if v}
        if len({frozenset(v) for v in literal.values()}) > 1:
            out.append((attr, {m: sorted(v)
                              for m, v in sorted(literal.items())}))
    return out


def resolve_expr(node, mod, func, depth=0, resolving=frozenset()):
    """Resolve an AST expression to a set of values (S/D/Seq/ConfigTable/...).
    `func` is the enclosing FunctionDef or None (module scope)."""
    if node is None:
        return set()
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return {S(node.value)}
        return set()
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        out = set()
        for l in resolve_expr(node.left, mod, func, depth, resolving=resolving):
            for r in resolve_expr(node.right, mod, func, depth, resolving=resolving):
                if isinstance(l, S) and isinstance(r, S):
                    # a "*" on either side stays a wildcard
                    out.add(S((l.t + r.t)))
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        out = set()
        for l in resolve_expr(node.left, mod, func, depth, resolving=resolving):
            if isinstance(l, S):
                out.add(S(printf_template(l.t)))
        return out
    if isinstance(node, ast.JoinedStr):
        parts = [""]
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts = [p + v.value for p in parts]
            elif isinstance(v, ast.FormattedValue):
                vals = resolve_expr(v.value, mod, func, depth, resolving=resolving)
                strs = as_strings(vals) or {"*"}
                parts = [p + s for p in parts for s in strs]
            else:
                parts = [p + "*" for p in parts]
        return {S(p) for p in parts}
    if isinstance(node, ast.Name):
        if (id(func), node.id) in resolving:
            return set()
        if func is not None:
            loc = mod.func_locals(func, resolving)
            if node.id in loc:
                return loc[node.id]
        if node.id in mod.mod_vars:
            return mod.mod_vars[node.id]
        return set()
    if isinstance(node, ast.Attribute):
        # self.<attr>
        if isinstance(node.value, ast.Name) and node.value.id == "self":
            vals = GLOBAL_SELF_ATTRS.get(node.attr, set())
            if vals:
                return set(vals)
            return {S("*")}
        # Pkg.SCRIPT_TAGS: a list of 3-tuples; only element 2 (the
        # '%pre'/'%post'/... name) is statically known
        if (isinstance(node.value, ast.Name) and node.value.id == "Pkg"
                and node.attr == "SCRIPT_TAGS"):
            tags = script_tags(mod.pkgdir)
            if tags:
                return {Seq([{Seq([set(), set(), {S(t)}], True)} for t in tags],
                            is_tuple=False)}
            return set()
        return set()
    if isinstance(node, ast.Subscript):
        return resolve_subscript(node, mod, func, depth, resolving)
    if isinstance(node, ast.Tuple):
        return {Seq([resolve_expr(e, mod, func, depth, resolving=resolving) for e in node.elts], True)}
    if isinstance(node, ast.List):
        return {Seq([resolve_expr(e, mod, func, depth, resolving=resolving) for e in node.elts], False)}
    if isinstance(node, ast.Dict):
        d = {}
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                d[k.value] = resolve_expr(v, mod, func, depth, resolving=resolving)
        return {D(d)}
    if isinstance(node, ast.Call):
        return resolve_call(node, mod, func, depth, resolving)
    if isinstance(node, ast.IfExp):
        out = resolve_expr(node.body, mod, func, depth, resolving=resolving)
        out.update(resolve_expr(node.orelse, mod, func, depth, resolving=resolving))
        return out
    if isinstance(node, ast.Starred):
        return resolve_expr(node.value, mod, func, depth, resolving=resolving)
    return set()


def resolve_call(node, mod, func, depth, resolving=frozenset()):
    f = node.func
    # self.config.configuration['X']
    if (isinstance(f, ast.Attribute) and f.attr == "get"
            and isinstance(f.value, ast.Attribute)
            and f.value.attr == "configuration"):
        return set()
    # <X>.values() on a config table -> its row dicts
    if isinstance(f, ast.Attribute) and f.attr == "values":
        for v in resolve_expr(f.value, mod, func, depth, resolving=resolving):
            if isinstance(v, ConfigTable):
                return {D({k: {S(x)} for k, x in row.items()})
                        for row in config_table_rows(mod.pkgdir, v.name)}
        return set()
    # list(<gen>) / tuple(<gen>) / sorted(...) / set(...) -- best effort
    if isinstance(f, ast.Name) and f.id in ("list", "tuple", "sorted", "set", "frozenset"):
        if node.args:
            return resolve_expr(node.args[0], mod, func, depth, resolving=resolving)
    return set()


def config_table_rows(pkgdir, table):
    cands = [os.path.join(pkgdir, "configdefaults.toml")]
    overlay = os.path.join(os.path.dirname(pkgdir.rstrip(os.sep)), "configs", "openSUSE")
    if os.path.isdir(overlay):
        cands += sorted(os.path.join(overlay, f) for f in os.listdir(overlay)
                        if f.endswith(".toml"))
    rows, cur = [], None
    for path in cands:
        text = _read(path)
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = re.match(r"\[" + re.escape(table) + r"\.\"([^\"]+)\"\]", s) or \
                re.match(r"\[" + re.escape(table) + r"\.([^\]]+)\]", s)
            if m:
                cur = {}
                rows.append(cur)
                continue
            if s.startswith("["):
                cur = None
                continue
            if cur is not None:
                km = re.match(r"([A-Za-z0-9_]+)\s*=\s*\"([^\"]*)\"", s)
                if km:
                    cur[km.group(1)] = km.group(2)
    return rows


def resolve_subscript(node, mod, func, depth, resolving=frozenset()):
    base_vals = resolve_expr(node.value, mod, func, depth, resolving=resolving)
    sl = node.slice
    key = None
    if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
        key = sl.value
    out = set()
    for b in base_vals:
        if isinstance(b, D):
            if key is not None and key in b.d:
                out.update(b.d[key])
            elif key is None:
                for v in b.d.values():
                    out.update(v)
        elif isinstance(b, Seq):
            if isinstance(sl, ast.Constant) and isinstance(sl.value, int):
                idx = sl.value
                if 0 <= idx < len(b.items):
                    out.update(b.items[idx])
            elif not isinstance(sl, ast.Constant):
                # variable index over a tuple of known shape: union
                for item in b.items:
                    out.update(item)
        elif b is UNKNOWN:
            out.add(S("*"))
    # self.config.configuration['Table'] pattern
    v = node.value
    if (isinstance(v, ast.Attribute) and v.attr == "configuration"
            and isinstance(v.value, ast.Attribute) and v.value.attr == "config"
            and isinstance(v.value.value, ast.Name) and v.value.value.id == "self"
            and key):
        return {ConfigTable(key)}
    # A loop variable as the subscript base (MenuCheck's value['type']):
    # resolve what the loop yields, then subscript that.
    if not out and isinstance(node.value, ast.Name) and func is not None:
        vals, ok = loop_var_values(mod, func, node.value.id, resolving)
        if ok:
            for v in vals:
                if isinstance(v, D):
                    if key is not None and key in v.d:
                        out.update(v.d[key])
                    elif key is None:
                        for vv in v.d.values():
                            out.update(vv)
    # check['Message'] in FilelistCheck: the TOML holds the names
    if key == "Message" and mod.modname == "FilelistCheck":
        return {S(m) for m in filelist_messages(mod.pkgdir)}
    # Pkg.SCRIPT_TAGS[i]
    if (isinstance(v, ast.Attribute) and isinstance(v.value, ast.Name)
            and v.value.id == "Pkg" and v.attr == "SCRIPT_TAGS"):
        tags = script_tags(mod.pkgdir)
        if isinstance(sl, ast.Constant) and isinstance(sl.value, int):
            idx = sl.value
            if 0 <= idx < len(tags):
                return {S(tags[idx])}
        return {S(t) for t in tags}
    # self.<attr>[<key>] where the attr was subscript-assigned from a
    # generator: self.file_cache[md5] = list(self.check_bashisms(...))
    if (isinstance(v, ast.Attribute) and isinstance(v.value, ast.Name)
            and v.value.id == "self" and func is not None):
        loc = mod.func_locals(func, resolving)
        vals = loc.get(f"self.{v.attr}[]", set())
        for val in vals:
            if isinstance(val, Seq):
                for item in val.items:
                    out.update(item)
            elif isinstance(val, S):
                out.add(val)
    return out


def _for_loops(text):
    """Yield (target, iterable, header_end) for each `for` loop in `text`.

    The iterable may sit on the line after `in` (rustfmt wraps long
    headers); `header_end` is the offset just past `in`."""
    for m in re.finditer(r"\bfor\s+(\([^)]*\)|[A-Za-z_][A-Za-z0-9_]*)\s+in\b", text):
        rest = text[m.end():]
        it = re.split(r"[;{]", rest.split("\n", 1)[0], maxsplit=1)[0].strip()
        if not it and "\n" in rest:
            nxt = rest.split("\n", 1)[1].split("\n", 1)[0]
            it = re.split(r"[;{]", nxt, maxsplit=1)[0].strip()
        if it:
            yield m.group(1), it, m.end()


def _loop_body_span(src, header_end):
    """(start, end) of the loop body whose `for...in` header ends at
    `header_end`; end is exclusive. Empty span when no body is found."""
    i, n = header_end, len(src)
    depth = 0
    instr, esc, q = False, False, None
    while i < n:
        ch = src[i]
        if instr:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == q:
                instr = False
        elif ch in "\"'":
            instr, q = True, ch
        elif ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "{" and depth == 0:
            inner = _brace_body(src, i)
            return (i, i + 2 + len(inner))
        elif ch == ";" and depth == 0:
            break
        i += 1
    return (header_end, header_end)


def loop_var_values(mod, func, target_name, resolving=frozenset()):
    """Resolve a for-loop target name. Returns (values, resolved_ok):
    `resolved_ok` is False when no binding loop was found or the iterable
    is unresolvable; an empty values set with ok=True means the loop
    genuinely yields no names (e.g. an empty config table)."""
    key = (id(func), target_name, "loop")
    if key in resolving:
        return set(), False
    resolving = resolving | {key}
    out = set()
    if func is None:
        return out, False
    found = False
    for node in ast.walk(func):
        if not isinstance(node, ast.For):
            continue
        # collect (name, index) for tuple targets
        targets = []
        t = node.target
        if isinstance(t, ast.Name) and t.id == target_name:
            targets.append((t.id, None))
        elif isinstance(t, ast.Tuple):
            for i, e in enumerate(t.elts):
                if isinstance(e, ast.Name) and e.id == target_name:
                    targets.append((e.id, i))
        if not targets:
            continue
        found = True
        it = node.iter
        vals = resolve_expr(it, mod, func, resolving=resolving)
        for _, idx in targets:
            for v in vals:
                if isinstance(v, Seq):
                    if idx is None:
                        for item in v.items:
                            out.update(item)
                    elif 0 <= idx < len(v.items):
                        out.update(v.items[idx])
                elif isinstance(v, D):
                    # for k, v in dict.items()
                    if isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute) \
                            and it.func.attr == "items":
                        if idx == 0:
                            out.update({S(k) for k in v.d})
                        elif idx == 1:
                            for vv in v.d.values():
                                out.update(vv)
                    elif isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute) \
                            and it.func.attr == "values" and idx is None:
                        # for v in dict.values(): the target binds each
                        # value; keep the dicts so `v['key']` subscripts
                        # resolve (MenuCheck's value['type']).
                        out.add(v)
                    elif idx is None or idx == 0:
                        out.update({S(k) for k in v.d})
                elif isinstance(v, ConfigTable):
                    # for k, v in <table>.items(): keys are the finding names
                    if isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute) \
                            and it.func.attr == "items" and (idx is None or idx == 0):
                        out.update({S(k) for k in config_table_values(mod.pkgdir, v.name)})
        # generator-driven loop: for x in self.method(...) / cached call
        meth = generator_method(it, mod, func, resolving)
        if meth:
            out.update(S(s) for s in mod.string_yields(meth))
        if not out and isinstance(t, ast.Tuple):
            # Last resort: tuple literals in the module with a matching shape
            # (FileMetadataCheck's `message`, unpacked from appended tuples).
            # Only string-shaped elements are candidates.
            n, idx = len(t.elts), targets[0][1]
            for sub in ast.walk(mod.tree):
                if isinstance(sub, ast.Tuple) and len(sub.elts) == n:
                    out.update(as_s(sub.elts[idx], mod, func, resolving))
    return out, found


def as_s(node, mod, func, resolving=frozenset()):
    return {v for v in resolve_expr(node, mod, func, resolving=resolving) if isinstance(v, S)}


def generator_method(iter_node, mod=None, func=None, resolving=frozenset()):
    """If the loop iterates a generator method's results, return its name."""
    n = iter_node
    # list(self.method(...))
    if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id in ("list", "tuple", "sorted", "set") and n.args):
        n = n.args[0]
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
        recv = n.func.value
        if isinstance(recv, ast.Name) and recv.id == "self":
            return n.func.attr
    # self.cache[k], where self.cache[k] = list(self.method(...))
    # (BashismsCheck's file_cache)
    if (isinstance(n, ast.Subscript) and mod is not None and func is not None
            and isinstance(n.value, ast.Attribute)
            and isinstance(n.value.value, ast.Name)
            and n.value.value.id == "self"):
        for raw in mod.raw_locals(func).get(f"self.{n.value.attr}[]", []):
            m = raw
            if (isinstance(m, ast.Call) and isinstance(m.func, ast.Name)
                    and m.func.id in ("list", "tuple", "sorted", "set") and m.args):
                m = m.args[0]
            if (isinstance(m, ast.Call) and isinstance(m.func, ast.Attribute)
                    and isinstance(m.func.value, ast.Name)
                    and m.func.value.id == "self"):
                return m.func.attr
    return None


def subscript_of_loop_var(mod, func, name, index, resolving=frozenset()):
    """`name[<index>]` where `name` is a for-loop target: resolve the loop's
    iterable and take element <index> of each iteration value."""
    out = set()
    tree = func if func is not None else mod.tree
    for node in ast.walk(tree):
        if not isinstance(node, ast.For):
            continue
        t = node.target
        if not (isinstance(t, ast.Name) and t.id == name):
            continue
        for v in resolve_expr(node.iter, mod, func, resolving=resolving):
            if not isinstance(v, Seq):
                continue
            for item in v.items:
                for u in item:
                    if isinstance(u, Seq) and 0 <= index < len(u.items):
                        out.update(s.t for s in u.items[index] if isinstance(s, S))
                    elif isinstance(u, S) and index == 0:
                        out.add(u.t)
    return out


def call_site_arg(mod, funcname, param_index, resolving=frozenset()):
    """Intra-module call sites of self.<funcname>: resolve the argument at
    `param_index` in the caller's scope (PostCheck's `tag` parameter, fed
    by `tag[2]` over `Pkg.SCRIPT_TAGS`)."""
    out = set()
    for node in ast.walk(mod.tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == funcname):
            continue
        recv = node.func.value
        if not (isinstance(recv, ast.Name) and recv.id == "self"):
            continue
        # self.m(...) drops the receiver: args[0] is the second parameter
        aidx = param_index - 1 if param_index else 0
        if aidx >= len(node.args):
            continue
        caller = enclosing_func(mod.tree, node)
        arg = node.args[aidx]
        strs = as_strings(resolve_expr(arg, mod, caller))
        if strs:
            out.update(strs)
            continue
        base = arg.value if isinstance(arg, ast.Subscript) else arg
        if isinstance(base, ast.Name):
            if isinstance(arg, ast.Subscript) and isinstance(arg.slice, ast.Constant) \
                    and isinstance(arg.slice.value, int):
                out.update(subscript_of_loop_var(mod, caller, base.id,
                                                 arg.slice.value, resolving))
            else:
                vals, ok = loop_var_values(mod, caller, base.id, resolving)
                if ok:
                    out.update(v.t for v in vals if isinstance(v, S))
    return out


def resolve_name_fallback(mod, func, name, resolving):
    """Resolve a bare Name that normal lookup missed: a parameter (trace to
    the caller's argument) or a for-loop variable. Returns (names, ok)."""
    out = set()
    if func is not None:
        parnames = [a.arg for a in func.args.args]
        if name in parnames:
            out.update(call_site_arg(mod, func.name, parnames.index(name), resolving))
            return out, True
        vals, ok = loop_var_values(mod, func, name, resolving)
        if ok:
            out.update(v.t for v in vals if isinstance(v, S))
            return out, True
    return out, False


def resolve_name_arg(mod, node, func, resolving):
    """Resolve an add_info name argument to (templates, ok), with
    parameter/loop-variable fallbacks for names normal lookup misses
    (PostCheck's `'empty-' + tag`)."""
    vals = resolve_expr(node, mod, func, resolving=resolving)
    strs = as_strings(vals)
    if strs:
        return set(strs), True
    if isinstance(node, ast.Name):
        return resolve_name_fallback(mod, func, node.id, resolving)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        l, l_ok = resolve_name_arg(mod, node.left, func, resolving)
        r, r_ok = resolve_name_arg(mod, node.right, func, resolving)
        if l_ok and r_ok:
            return {a + b for a in l for b in r}, True
    return set(), False


def resolve_add_info_name(mod, call, func, resolving=frozenset()):
    """Resolve one add_info call's finding-name argument to (templates, ok)."""
    args = call.args
    starred = [a for a in args if isinstance(a, ast.Starred)]
    if starred:
        # add_info('E', *msg): the name is element 1 of the tuple. An
        # empty resolution is UNRESOLVED, never silently dropped.
        out = set()
        for st in starred:
            for v in resolve_expr(st.value, mod, func):
                if isinstance(v, Seq) and len(v.items) > 1:
                    out.update(s for s in v.items[1] if isinstance(s, S))
        return {s.t for s in out}, bool(out)
    if len(args) < 3:
        return set(), False
    return resolve_name_arg(mod, args[2], func, resolving)


def audit_reference(pkgdir):
    """Returns (findings, unresolved).

    findings: {(module, template)}; unresolved: [(module, lineno, source)].
    """
    checkdir = os.path.join(pkgdir, "checks")
    modules = []
    for fn in sorted(os.listdir(checkdir)):
        if not fn.endswith(".py"):
            continue
        modules.append(RefModule(os.path.join(checkdir, fn), fn[:-3], pkgdir))
    global GLOBAL_SELF_ATTRS
    GLOBAL_SELF_ATTRS = {}
    for m in modules:
        for attr, vals in m.self_attrs.items():
            GLOBAL_SELF_ATTRS.setdefault(attr, set()).update(vals)

    findings, unresolved = set(), []
    for attr, mods in self_attr_collisions(modules):
        detail = ", ".join(f"{m}={v}" for m, v in mods.items())
        unresolved.append((
            "(self-attrs)", 0,
            f"self.{attr} takes different values across modules "
            f"({detail}): not a deliberate union; resolve by hand",
        ))
    for mod in modules:
        for node in ast.walk(mod.tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add_info"):
                continue
            func = enclosing_func(mod.tree, node)
            names, ok = resolve_add_info_name(mod, node, func)
            if ok:
                for n in names:
                    findings.add((mod.modname, n))
            else:
                seg = ast.get_source_segment(mod.source, node) or "<source unavailable>"
                unresolved.append((mod.modname, node.lineno,
                                   " ".join(seg.split())[:160]))
        # `FileMetadataCheck.get_validation_error` builds its finding name as
    # `f'{prefix}-mismatched-attrs'` from a FUNCTION PARAMETER, not
    # `self.prefix`, so the resolver cannot reach it and the name arrives as
    # `*-mismatched-attrs`. The concrete prefixes are the two subclasses'
    # `self.prefix` values, already unioned above; expand with them so the name
    # is checkable instead of permanently un-auditable.
    prefixes = sorted(v.t for v in GLOBAL_SELF_ATTRS.get("prefix", ()))
    if prefixes:
        for mod in modules:
            for node in ast.walk(mod.tree):
                if (isinstance(node, ast.JoinedStr)
                        and any(isinstance(v, ast.FormattedValue)
                                and isinstance(v.value, ast.Name)
                                and v.value.id == "prefix" for v in node.values)):
                    tmpl = printf_template(ast.unparse(node))
                    # ast.unparse keeps the f-prefix and quotes; the template
                    # helpers all expect a bare string.
                    for q in ("'", '"'):
                        if tmpl.startswith("f" + q) and tmpl.endswith(q):
                            tmpl = tmpl[2:-1]
                            break
                    for pre in prefixes:
                        findings.add((mod.modname, tmpl.replace("{prefix}", pre)))
                    # The wildcard form is superseded by the concrete names.
                    findings.discard((mod.modname, tmpl.replace("{prefix}", "*")))

    return findings, unresolved, len(modules)


def enclosing_func(tree, node):
    best = None
    for sub in ast.walk(tree):
        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if sub.lineno <= node.lineno <= (sub.end_lineno or sub.lineno):
                if best is None or sub.lineno >= best.lineno:
                    best = sub
    return best


# ---------------------------------------------------------------------------
# Port side (crates/rpmcrab-core/src/checks/*.rs)
# ---------------------------------------------------------------------------

def match_paren(s, i):
    """Index just past the `)` matching the `(` at i; -1 if unbalanced."""
    assert s[i] == "("
    depth = 0
    instr = None
    j = i
    n = len(s)
    while j < n:
        c = s[j]
        if instr:
            if c == "\\":
                j += 2
                continue
            if c == instr:
                instr = None
        elif c in "'\"":
            instr = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return -1


def match_brace(s, i):
    """Index just past the `}` matching the `{` at i; -1 if unbalanced."""
    assert s[i] == "{"
    depth = 0
    instr = None
    j = i
    n = len(s)
    while j < n:
        c = s[j]
        if instr:
            if c == "\\":
                j += 2
                continue
            if c == instr:
                instr = None
        elif c in "'\"":
            instr = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return -1


def split_top_level(s):
    """Split on top-level commas, respecting nesting and string literals."""
    args, depth, cur = [], 0, []
    instr, esc, q = False, False, None
    for ch in s:
        if instr:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == q:
                instr = False
        elif ch in "\"'":
            instr, q = True, ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    args.append("".join(cur).strip())
    return args


def find_calls(src, names):
    """Yield (name, args_source, lineno, offset) for each macro-style call."""
    for m in re.finditer(r"(?<!fn\s)\b(" + "|".join(names) + r")\s*\(", src):
        start = m.end()
        depth, i = 1, start
        instr, esc, q = False, False, None
        while i < len(src) and depth:
            ch = src[i]
            if instr:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == q:
                    instr = False
            elif ch in "\"'":
                instr, q = True, ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        yield m.group(1), src[start:i - 1], src.count("\n", 0, m.start()) + 1, m.start()


def rust_string_literal(s):
    m = re.match(r'^"((?:[^"\\]|\\.)*)"$', s, re.S)
    return rust_unescape(m.group(1)) if m else None


def resolve_rs_name(expr, src, seen=None, scope=None, call_pos=None,
                    scope_off=0):
    """Resolve a Rust name argument to templates. Returns (templates, ok).

    `scope` is the enclosing function body; `let` bindings are resolved
    inside it first (the binding before the use), then file-wide.
    `scope_off` is the body's offset in `src` (for absolute positions).
    """
    if seen is None:
        seen = set()
    if scope is None:
        scope = src
        scope_off = 0
    e = expr.strip()
    if e.startswith("&"):
        e = e[1:].strip()
    lit = rust_string_literal(e)
    if lit is not None:
        return {lit}, True
    m = re.match(r'format!\s*\(\s*"((?:[^"\\]|\\.)*)"', e, re.S)
    if m:
        return {format_macro_template(rust_unescape(m.group(1)))}, True
    if e == "None":
        # Option::None contributes no finding names
        return set(), True
    m = re.match(r"^Some\((.*)\)$", e, re.S)
    if m:
        return resolve_rs_name(m.group(1).strip(), src, seen, scope,
                               call_pos, scope_off=scope_off)
    m = re.match(r"^(.*)\.then_some\(\s*(.*)\s*\)$", e, re.S)
    if m and m.group(1).strip():
        return resolve_rs_name(m.group(2).strip(), src, seen, scope,
                               call_pos, scope_off=scope_off)
    m = re.match(r"^(?:[A-Za-z_][\w]*::)?make_finding\s*\((.*)\)$", e, re.S)
    if m:
        # Self::make_finding(pkg, arch, level, name, details): the finding
        # name is the 4th argument (library_dependency's
        # out.add_info(Self::make_finding(..., "name", ...))).
        inner = split_top_level(m.group(1))
        if len(inner) > 3:
            return resolve_rs_name(inner[3].strip(), src, seen, scope,
                                   call_pos, scope_off=scope_off)
        return set(), False
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(", e)
    if m:
        # `name(args)` through a closure variable: substitute the resolved
        # actuals for the closure's parameters (PostCheck's
        # `let finding = |f: &str| format!("{f}-{tag}")`). Anything that is
        # not a closure call keeps the old (unresolved) behavior.
        argstr, end = _paren_argstr(e, m.end() - 1)
        if argstr is not None and end == len(e):
            t, ok = resolve_closure_call(m.group(1), argstr, src, seen,
                                         scope, call_pos, scope_off)
            if ok:
                return t, True
    if e.startswith("match "):
        # match x { pat => EXPR, ... }: resolve each arm's expression.
        # Find the brace-enclosed body, then split arms on top-level commas.
        mbody = re.search(r"\{", e)
        if not mbody:
            return set(), False
        depth = 0
        start = mbody.start()
        end = start
        for i in range(start, len(e)):
            if e[i] == "{":
                depth += 1
            elif e[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if depth != 0:
            return set(), False
        body = e[start + 1:end]
        # Split on top-level commas to get arms.
        arms = []
        depth = 0
        cur = ""
        for ch in body:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            if ch == "," and depth == 0:
                arms.append(cur)
                cur = ""
            else:
                cur += ch
        if cur.strip():
            arms.append(cur)
        out = set()
        for arm in arms:
            if "=>" not in arm:
                continue
            rhs = arm.split("=>", 1)[1].strip()
            t, ok = resolve_rs_name(rhs, src, seen, scope,
                                    scope_off=scope_off)
            if not ok:
                return set(), False
            out.update(t)
        if out:
            return out, True
        return set(), False
    if e.startswith("if "):
        # if cond { A } else { B }
        parts = re.findall(r"\{([^{}]*)\}", e)
        out = set()
        for p in parts:
            t, ok = resolve_rs_name(p.strip(), src, seen, scope,
                                     scope_off=scope_off)
            if not ok:
                return set(), False
            out.update(t)
        if out:
            return out, True
        return set(), False
    # variable
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", e):
        if e in seen:
            return set(), False
        seen = seen | {e}
        rhs = find_let_rhs(scope, e) or find_let_rhs(src, e)
        if rhs is not None:
            if "WarnOnFunction" in rhs:
                # config-driven finding names; empty under the openSUSE config
                return set(), True
            t, ok = resolve_rs_name(rhs, src, seen, scope, call_pos,
                                    scope_off=scope_off)
            if ok:
                return t, True
            # The binding does not resolve (a closure definition, or a
            # binding from another function): fall through to the
            # closure-parameter / loop / if-let paths instead of failing.
        # closure parameter: let [mut ]clo = |..., name: &str, ...| ...
        # (only when the use sits inside the closure body; a use outside
        # binds to something else, e.g. a shadowing loop variable).
        # Every call site is resolved: different calls may pass different
        # bindings (emit's for-loop call vs its if-let call).
        rel_pos = call_pos - scope_off if call_pos is not None else None
        call_args = [(a, scope_off + c)
                     for a, c in find_closure_call_args(scope, e, rel_pos)]
        if not call_args and call_pos is not None:
            call_args = list(find_closure_call_args(src, e, call_pos))
        if call_args:
            out, any_ok = set(), False
            for arg, aoff in call_args:
                if arg.strip() == e:
                    continue
                # `seen - {e}`: the call-site argument may legitimately
                # reuse the parameter's name for a different (shadowing)
                # binding.
                t, ok = resolve_rs_name(arg, src, seen - {e}, scope,
                                        call_pos=aoff, scope_off=scope_off)
                if ok:
                    any_ok = True
                    out.update(t)
            if any_ok:
                return out, True
            # All call args failed: the loop search below starts from the
            # first call site (a closure parameter shadowed by its
            # call-site variable searches from past the closure body).
            lpos = call_args[0][1]
        else:
            lpos = call_pos
        # loop over a helper's results: for [(]name[,...)] in ...
        if lpos is not None:
            tup = find_loop_source(src, e, lpos)
            if tup is not None:
                return tup, True
        # `if let Some(v) = <expr>` bindings (i18n's probe.invalid)
        if call_pos is not None:
            fvals = resolve_if_let_some(src, e, call_pos, seen)
            if fvals is not None:
                return fvals, True
        return set(), False
    # <expr>.to_string() / .to_owned() / .as_str() / .clone()
    m = re.match(r"^(.*)\.(?:to_string|to_owned|as_str|clone)\(\)$", e, re.S)
    if m:
        return resolve_rs_name(m.group(1), src, seen, scope, call_pos,
                               scope_off=scope_off)
    # struct field: base.field -> the literals ever assigned to `field:`
    # in the constructor `base` was built with
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)$", e)
    if m:
        return resolve_struct_field(src, m.group(1), m.group(2), call_pos,
                                    seen)
    return set(), False


def resolve_if_let_some(src, name, call_pos, seen):
    """`if let Some(name) = <expr>` (or `if let Some((a, name)) = <expr>`)
    nearest before call_pos: resolve <expr>.

    Returns a template set, or None when no such binding exists."""
    text = src[:call_pos]
    best, best_idx = None, None
    for m in re.finditer(r"if\s+let\s+Some\(\s*" + re.escape(name)
                         + r"\s*\)\s*=\s*", text):
        best, best_idx = m, None
    for m in re.finditer(r"if\s+let\s+Some\(\s*\(([^)]*)\)\s*\)\s*=\s*", text):
        parts = [p.strip().lstrip("&") for p in m.group(1).split(",")]
        if name in parts and (best is None or m.start() >= best.start()):
            best, best_idx = m, parts.index(name)
    if best is None:
        return None
    em = re.match(r"\s*([^{\n;]+)", text[best.end():])
    if not em:
        return None
    expr = em.group(1).strip()
    if not expr or expr == name:
        return None
    if best_idx is not None:
        # Tuple destructuring: the name is element best_idx. A
        # self.method(...) scrutinee resolves through the method's
        # returned Some((...)) tuples.
        mm = re.match(r"(?:self\s*\.\s*|Self::)([A-Za-z_][A-Za-z0-9_]*)\s*\(", expr)
        if mm:
            return _method_some_tuple_elem(src, mm.group(1), best_idx, seen)
        return None
    t, ok = resolve_rs_name(expr, src, seen, call_pos=call_pos)
    return t if ok else None


def _method_some_tuple_elem(src, method, idx, seen):
    """Element `idx` of the `Some((...))` tuples returned by `fn method`.

    Returns a template set, or None when nothing resolves."""
    fm = re.search(r"\bfn\s+" + re.escape(method) + r"\b[^{]*\{", src)
    if not fm:
        return None
    body = _brace_body(src, fm.end() - 1)
    out = set()
    for m in re.finditer(r"\bSome\s*\(", body):
        argstr, end = _paren_argstr(body, m.end() - 1)
        if argstr is None:
            continue
        inner = argstr.strip()
        if inner.startswith("(") and inner.endswith(")"):
            inner = inner[1:-1]
            elems = split_top_level(inner)
        elif idx == 0:
            elems = [inner]
        else:
            continue
        if idx < len(elems):
            t, ok = resolve_rs_name(elems[idx].strip(), body, seen)
            if ok:
                out.update(t)
    return out if out else None


def resolve_struct_field(src, base, field, call_pos, seen):
    """Literals assigned to `field:` in struct literals inside the function
    that built `base` (`let base = ctor(...)`). Returns (templates, ok)."""
    text = src[:call_pos] if call_pos is not None else src
    rhs = find_let_rhs(text, base)
    if rhs is None:
        return set(), False
    m = re.match(r"(?:Self::|self\.)?([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                 rhs.strip())
    if not m:
        return set(), False
    fdef = re.search(r"\bfn\s+" + re.escape(m.group(1)) + r"\b[^{]*\{", src)
    if not fdef:
        return set(), False
    body = _brace_body(src, fdef.end() - 1)
    out, found = set(), False
    for sm in re.finditer(r"[A-Za-z_][A-Za-z0-9_]*\s*\{", body):
        lit = _brace_body(body, sm.end() - 1)
        for part in split_top_level(lit):
            km = re.match(r"\s*" + re.escape(field) + r"\s*:", part)
            if km:
                t, ok = resolve_rs_name(part[km.end():].strip(), src, seen)
                if ok:
                    out.update(t)
                    found = True
    return out, found


def find_let_rhs(src, name):
    """RHS of the last `let <name> [: ty] = <rhs>;` in `src`, paren-aware
    for multiline initializers."""
    found = None
    for m in re.finditer(r"\blet\s+(?:mut\s+)?" + re.escape(name)
                         + r"\s*(?::\s*[^=;]+?)?=\s*", src):
        start = m.end()
        depth, i = 0, start
        instr, esc, q = False, False, None
        while i < len(src):
            ch = src[i]
            if instr:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == q:
                    instr = False
            elif ch in "\"'":
                instr, q = True, ch
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == ";" and depth == 0:
                found = src[start:i].strip()
                break
            i += 1
    return found


def find_closure_call_args(src, param, use_pos=None):
    """`let [mut ]clo = |..., param: &str, ...| ...` then `clo(a0, a1, ...)`:
    return [(actual argument, call offset)] passed for `param`, one per
    call site.

    When `use_pos` (an offset into `src`) is given, only a closure whose
    body contains the use qualifies: a use outside the body refers to a
    different binding (e.g. a loop variable the parameter shadows)."""
    out = []
    for m in re.finditer(r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\|([^|]*)\|", src):
        clo, params = m.group(1), [p.strip() for p in m.group(2).split(",")]
        pnames = []
        for p in params:
            pm = re.match(r"(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:", p)
            pnames.append(pm.group(1) if pm else None)
        if param not in pnames:
            continue
        if use_pos is not None:
            bstart, bend = _closure_body_span(src, m.end())
            if not (bstart <= use_pos < bend):
                continue
        idx = pnames.index(param)
        for callname, argstr, _, coff in find_calls(src, [clo]):
            if callname != clo:
                continue
            args = split_top_level(argstr)
            if idx < len(args):
                out.append((args[idx], coff))
    return out


def _closure_body_span(src, pos):
    """(start, end) of the closure body beginning at `pos` (just past the
    closing `|` of the parameter list); end is exclusive."""
    i, n = pos, len(src)
    while i < n and src[i] in " \t\n\r":
        i += 1
    if i < n and src[i] == "{":
        inner = _brace_body(src, i)
        return (i, i + 2 + len(inner))
    depth, j = i, i
    instr, esc, q = False, False, None
    while j < n:
        ch = src[j]
        if instr:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == q:
                instr = False
        elif ch in "\"'":
            instr, q = True, ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == ";" and depth == 0:
            return (i, j)
        j += 1
    return (i, n)


def _paren_argstr(e, open_idx):
    """Inner text of the paren at `open_idx` and the index just past its
    matching closer; (None, -1) when unbalanced. String-aware."""
    depth, i, n = 0, open_idx, len(e)
    instr, esc, q = False, False, None
    while i < n:
        ch = e[i]
        if instr:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == q:
                instr = False
        elif ch in "\"'":
            instr, q = True, ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return e[open_idx + 1:i], i + 1
        i += 1
    return None, -1


def resolve_closure_call(name, argstr, src, seen, scope, call_pos, scope_off):
    """`name(args)` where `name` is bound to a closure: resolve the closure
    body with each parameter substituted by its resolved actual argument.

    Handles the PostCheck shape `let finding = |f: &str|
    format!("{f}-{tag}")` called as `finding("invalid-shell-in")`:
    placeholders naming a closure parameter expand to the actual
    argument's templates; anything else is `*` as usual.
    Returns (templates, ok)."""
    rhs = find_let_rhs(scope, name) or find_let_rhs(src, name)
    if rhs is None:
        return set(), False
    cm = re.match(r"^(?:move\s+)?\|([^|]*)\|\s*(.+)$", rhs.strip(), re.S)
    if not cm:
        return set(), False
    pnames = []
    for p in cm.group(1).split(","):
        pm = re.match(r"(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::.*)?$", p.strip())
        pnames.append(pm.group(1) if pm else None)
    arg_tpls = []
    for a in split_top_level(argstr):
        t, ok = resolve_rs_name(a.strip(), src, seen, scope, call_pos,
                                scope_off=scope_off)
        if not ok:
            return set(), False
        arg_tpls.append(t)
    return _substitute_closure_body(cm.group(2).strip(), pnames, arg_tpls)


def _substitute_closure_body(body, pnames, arg_tpls):
    """Resolve a closure body with parameters bound to resolved actuals.

    Only `format!` bodies are handled: a `{placeholder}` naming a closure
    parameter expands to the actual argument's templates; any other
    placeholder is `*` (the usual treatment for dynamic parts)."""
    m = re.match(r'format!\s*\(\s*"((?:[^"\\\\]|\\\\.)*)"', body, re.S)
    if not m:
        return set(), False
    tmpl = rust_unescape(m.group(1))
    results = {""}
    i, n = 0, len(tmpl)
    while i < n:
        c = tmpl[i]
        if c == "{" and i + 1 < n and tmpl[i + 1] == "{":
            results = {r + "{" for r in results}
            i += 2
        elif c == "}" and i + 1 < n and tmpl[i + 1] == "}":
            results = {r + "}" for r in results}
            i += 2
        elif c == "{":
            j = tmpl.find("}", i)
            if j == -1:
                results = {r + c for r in results}
                i += 1
                continue
            ident = tmpl[i + 1:j].split(":")[0].strip()
            if ident in pnames:
                idx = pnames.index(ident)
                repl = arg_tpls[idx] if idx < len(arg_tpls) and arg_tpls[idx] else {"*"}
            else:
                repl = {"*"}
            results = {r + s for r in results for s in repl}
            i = j + 1
        else:
            results = {r + c for r in results}
            i += 1
    return results, True


def _brace_body(src, open_idx):
    """Source inside the brace at open_idx (which points at '{')."""
    depth, i = 0, open_idx
    instr, esc, q = False, False, None
    while i < len(src):
        ch = src[i]
        if instr:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == q:
                instr = False
        elif ch in "\"'":
            instr, q = True, ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[open_idx + 1:i]
        i += 1
    return src[open_idx + 1:]


def find_loop_source(src, name, call_pos):
    """The `for` loop before `call_pos` whose target binds `name`: resolve
    its iterable to a helper method and collect the finding-name elements
    the method pushes (string literals and `format!` templates).

    Handles `for name in ...`, `for (a, name, b) in ...`, and iterables of
    the shape `Self::method(`, `self.method(`, or a variable bound to one.
    A `WarnOnFunction`-derived iterable resolves to the empty set (the
    config table is empty under the openSUSE config).
    """
    text = src[:call_pos]
    best = None
    for target, iterexpr, hend in _for_loops(text):
        if target.startswith("("):
            parts = [p.strip().lstrip("&") for p in target[1:-1].split(",")]
            if name not in parts:
                continue
            idx = parts.index(name)
        elif target == name:
            idx = None
        else:
            continue
        best = (idx, iterexpr, hend)
    if best is None:
        return None
    idx, iterexpr, hend = best
    # The use must sit inside the loop body: a use past the closing brace
    # binds to something else (e.g. a later `if let` shadowing the name).
    bstart, bend = _loop_body_span(src, hend)
    if not (bstart <= call_pos < bend):
        return None

    method = None
    m = re.match(r"(?:Self|self|[A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)", iterexpr)
    if m and re.match(r"[A-Za-z_][A-Za-z0-9_]*::", iterexpr):
        method = m.group(1)
    else:
        m = re.match(r"self\.([A-Za-z_][A-Za-z0-9_]*)", iterexpr)
        if m:
            method = m.group(1)
        else:
            vm = re.match(r"&?([A-Za-z_][A-Za-z0-9_]*)", iterexpr)
            if vm:
                rhs = find_let_rhs(text, vm.group(1))
                if rhs is None:
                    # match binding: Ok(findings) => ... / Some(x) => ...
                    mm = re.search(r"(?:Ok|Some|Err)\s*\(\s*"
                                   + re.escape(vm.group(1)) + r"\s*\)\s*=>",
                                   text)
                    if mm:
                        # The enclosing `match`: the last `match` before mm
                        # whose `{` opens before mm (avoids inner matches
                        # like the closure's `match line`).
                        mstart = -1
                        scrut = None
                        for mmt in re.finditer(r"\bmatch\b", text[:mm.start()]):
                            bpos = text.find("{", mmt.end())
                            if 0 <= bpos < mm.start():
                                mstart = mmt.start()
                                # the scrutinee: between `match` and the arm
                                # block's `{` (the old first-paren slice broke
                                # on `match Self::check_bytes(&bytes, ...)`).
                                scrut = text[mmt.end():bpos].strip()
                        if mstart >= 0 and scrut:
                            rhs = scrut
                if rhs is None:
                    return None
                if "WarnOnFunction" in rhs:
                    return set()
                # Vec built by pushing from another loop:
                # trace the push back to the source loop's iterable
                if re.match(r"(?:mut\s+)?Vec::new\(\)", rhs.strip()):
                    for pm in re.finditer(r"\b" + re.escape(vm.group(1))
                                          + r"\.push\s*\(", text):
                        # enclosing for loop of this push
                        ftext = text[:pm.start()]
                        last_iter = None
                        for _, f_it, _ in _for_loops(ftext):
                            last_iter = f_it
                        if last_iter:
                            src_iter = last_iter.strip().lstrip("&").strip()
                            src_rhs = find_let_rhs(text, src_iter)
                            # follow one level of indirection (forbidden_tbl)
                            if src_rhs and "WarnOnFunction" not in src_rhs:
                                for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", src_rhs):
                                    w_rhs = find_let_rhs(text, w)
                                    if w_rhs and "WarnOnFunction" in w_rhs:
                                        return set()
                            if src_rhs and "WarnOnFunction" in src_rhs:
                                return set()
                    return None
                m2 = re.search(r"(?:Self|self)::([A-Za-z_][A-Za-z0-9_]*)", rhs)
                if m2:
                    method = m2.group(1)
                else:
                    return None
            else:
                return None
    if method is None:
        return None
    fm = re.search(r"\bfn\s+" + re.escape(method) + r"\b[^{]*\{", src)
    if not fm:
        return None
    body_off = fm.end()  # _brace_body returns src[open_idx+1:]
    body = _brace_body(src, fm.end() - 1)
    templates = set()
    for _, argstr, _, coff in find_calls(body, ["push"]):
        args = split_top_level(argstr)
        if not args:
            continue
        first = args[0].strip()
        cpos = body_off + coff
        if idx is None:
            # for name in ...: push("lit") / push(format!(...))
            t, ok = resolve_rs_name(first, src, call_pos=cpos)
            if ok:
                templates.update(t)
        else:
            # for (a, name, b) in ...: push((..., name-elem, ...))
            inner = first
            if inner.startswith("(") and inner.endswith(")"):
                inner = inner[1:-1]
            elems = split_top_level(inner)
            if idx < len(elems):
                t, ok = resolve_rs_name(elems[idx], src, call_pos=cpos)
                if ok:
                    templates.update(t)
    if not templates:
        # The method just forwards to another Self::method (pkg_config's
        # check_bytes -> check_content): follow it. Only when there are
        # no pushes of its own -- a method that merely *calls* helpers
        # (Self::percent_regex()) still owns its findings.
        fwd = re.search(r"Self::([A-Za-z_][A-Za-z0-9_]*)\s*\(", body)
        if fwd and fwd.group(1) != method:
            return find_loop_source_via_method(src, fwd.group(1), idx)
    return templates if templates else None


def find_loop_source_via_method(src, method, idx, seen=None):
    """Helper for find_loop_source: collect pushed literals from a method,
    following Self::method forwarding (including via extend)."""
    if seen is None:
        seen = set()
    if method in seen:
        return None
    seen = seen | {method}
    fm = re.search(r"\bfn\s+" + re.escape(method) + r"\b[^{]*\{", src)
    if not fm:
        return None
    body = _brace_body(src, fm.end() - 1)
    # Follow forwarding: Self::other(...) directly or via out.extend(...)
    for fwd in re.finditer(r"Self::([A-Za-z_][A-Za-z0-9_]*)\s*\(", body):
        if fwd.group(1) not in seen:
            res = find_loop_source_via_method(src, fwd.group(1), idx, seen)
            if res:
                return res
    # Also follow out.extend(Self::method(...)) explicitly
    for ext in re.finditer(r"\.extend\s*\(\s*Self::([A-Za-z_][A-Za-z0-9_]*)\s*\(", body):
        if ext.group(1) not in seen:
            res = find_loop_source_via_method(src, ext.group(1), idx, seen)
            if res:
                return res
    body_off = fm.end()  # _brace_body returns src[open_idx+1:]
    templates = set()
    for _, argstr, _, coff in find_calls(body, ["push"]):
        args = split_top_level(argstr)
        if not args:
            continue
        first = args[0].strip()
        cpos = body_off + coff
        if idx is None:
            t, ok = resolve_rs_name(first, src, call_pos=cpos)
            if ok:
                templates.update(t)
        else:
            inner = first
            if inner.startswith("(") and inner.endswith(")"):
                inner = inner[1:-1]
            elems = split_top_level(inner)
            if idx < len(elems):
                t, ok = resolve_rs_name(elems[idx], src, call_pos=cpos)
                if ok:
                    templates.update(t)
    return templates if templates else None


def enclosing_fn_body(src, pos):
    """Body of the `fn` enclosing `pos` (brace-matched), or the whole src."""
    best = None
    for m in re.finditer(r"\bfn\s+[A-Za-z_][A-Za-z0-9_]*\b[^{]*\{", src[:pos]):
        best = m
    if best is None:
        return src
    return _brace_body(src, best.end() - 1)


def enclosing_fn_span(src, pos):
    """(body, start_offset) of the `fn` enclosing `pos`."""
    best = None
    for m in re.finditer(r"\bfn\s+[A-Za-z_][A-Za-z0-9_]*\b[^{]*\{", src[:pos]):
        best = m
    if best is None:
        return src, 0
    body_start = best.end()  # just after the '{'
    body = _brace_body(src, best.end() - 1)
    # _brace_body returns content inside braces; find its start
    start = src.find(body, best.end() - 1)
    return body, start if start >= 0 else best.end()


def find_rs_wrappers(src):
    """Local methods that forward a finding name to add_info/spec_add_info
    (spec.rs's `fn info`). Returns {wrapper_name: (call_arg_index, body_span)}
    so callers treat `x.wrapper(...)` as emission sites and skip the
    forwarding call inside the wrapper body."""
    out = {}
    for m in re.finditer(r"fn\s+([A-Za-z_][\w]*)\s*\(", src):
        wname = m.group(1)
        pstart = m.end() - 1
        pend = match_paren(src, pstart)
        if pend < 0:
            continue
        pnames = [p.split(":")[0].strip().lstrip("mut ").lstrip("&").strip()
                  for p in split_top_level(src[pstart + 1:pend])]
        bstart = src.find("{", pend)
        if bstart < 0:
            continue
        bend = match_brace(src, bstart)
        if bend < 0:
            continue
        body = src[bstart:bend]
        for callname, argstr, _, _ in find_calls(body, ["add_info", "spec_add_info"]):
            args = split_top_level(argstr)
            nidx = 4 if callname == "spec_add_info" else 3
            if len(args) <= nidx:
                continue
            na = args[nidx].strip().lstrip("&").strip()
            if na in pnames:
                pidx = pnames.index(na)
                is_method = bool(pnames) and pnames[0] == "self"
                out[wname] = (pidx - (1 if is_method else 0), (bstart, bend))
                break
    return out


def find_push_templates(src):
    """`vec.push((Level::X, "finding-name", ...))` emission sites.

    Some checks accumulate findings as tuples in a Vec and drain it into
    add_info later (dbus_policy's check_allow/check_deny). The tuple's
    second element is the finding name. Returns (templates, receiver_vars).
    Non-literal second elements (attrs.push((key, val))) are ignored.
    """
    templates, receivers = set(), set()
    for _, argstr, _, coff in find_calls(src, ["push"]):
        rm = re.search(r"([A-Za-z_][\w]*)\.\s*$", src[:coff])
        if not rm:
            continue
        args = split_top_level(argstr)
        if not args:
            continue
        tup = args[0].strip()
        if tup.startswith("(") and tup.endswith(")"):
            tup = tup[1:-1]
        elems = split_top_level(tup)
        if len(elems) >= 2:
            lit = rust_string_literal(elems[1].strip())
            if lit is not None:
                templates.add(lit)
                receivers.add(rm.group(1))
    return templates, receivers


def is_push_drain(src, expr, call_pos, push_receivers):
    """Is `expr` a loop variable draining a tuple-push vec?

    `add_info(out, level, pkg, finding, ...)` where `finding` comes from
    `for (level, finding, detail) in findings` and `findings` is fed by
    tuple-push sites: the push sites already yielded the names, so there
    is nothing new to resolve at the drain call.
    """
    e = expr.strip().lstrip("&").strip()
    if not re.match(r"^[A-Za-z_][\w]*$", e):
        return False
    text = src[:call_pos]
    iterexpr = None
    for target, it, _ in _for_loops(text):
        if target.startswith("("):
            parts = [p.strip().lstrip("&") for p in target[1:-1].split(",")]
            if e not in parts:
                continue
        elif target != e:
            continue
        iterexpr = it
    if iterexpr is None:
        return False
    return iterexpr.lstrip("&").strip() in push_receivers


def audit_port(checks_dir):
    """Returns (by_module, unresolved).

    by_module: {port module name: set of "*" templates it emits}. Kept per
    module so a wildcard can be attributed to the check that owns it.
    """
    by_module, unresolved = {}, []
    for fn in sorted(os.listdir(checks_dir)):
        if not fn.endswith(".rs") or fn == "mod.rs":
            continue
        path = os.path.join(checks_dir, fn)
        with open(path, encoding="utf-8") as f:
            src = f.read()
        templates = set()
        # Tuple-push emission sites (dbus_policy): the finding names live
        # in the pushed tuples; the later add_info drain just forwards them.
        push_t, push_receivers = find_push_templates(src)
        templates.update(push_t)
        wrappers = find_rs_wrappers(src)
        wspans = [span for _, span in wrappers.values()]
        call_names = ["add_info", "spec_add_info"] + list(wrappers)
        for callname, argstr, lineno, coff in find_calls(src, call_names):
            if any(wb <= coff <= we for wb, we in wspans):
                continue  # the forwarding call inside a wrapper body
            if callname in wrappers:
                idx = wrappers[callname][0]
            else:
                idx = 4 if callname == "spec_add_info" else 3
            args = split_top_level(argstr)
            scope = enclosing_fn_body(src, coff)
            scope_off = enclosing_fn_span(src, coff)[1]
            if len(args) <= idx:
                # e.g. out.add_info(Self::make_finding(..., "name", ...)):
                # the name lives inside the single constructor argument.
                t, ok = resolve_rs_name(argstr.strip(), src, scope=scope,
                                        call_pos=coff, scope_off=scope_off)
                if ok:
                    templates.update(t)
                else:
                    unresolved.append((fn, lineno, "(missing name arg)"))
                continue
            # filelist.rs emits via rule.message, populated from the
            # embedded FilelistCheck.toml; resolve statically.
            arg = args[idx].strip()
            if fn == "filelist.rs" and arg in ("rule.message", "&rule.message"):
                msgs = rust_filelist_messages(os.path.dirname(path))
                if msgs:
                    templates.update(msgs)
                    continue
            # Dynamic emission sites: resolve via the producing function.
            # (file, variable) -> (function, extractor)
            dynamic_sites = {
                ("alternatives.rs", "finding"): ("check_post_phase", fn_err_literals),
                ("bashisms.rs", "warning"): ("classify_bashisms", fn_push_literals),
                ("duplicates.rs", "name"): ("describe", fn_describe_tuple_literals),
                ("menu_xdg.rs", "finding"): ("parse_desktop", fn_err_literals),
                ("systemd_install.rs", "finding"): ("check_unit", fn_finding_literals),
            }
            site_key = (fn, arg)
            if site_key in dynamic_sites:
                func_name, extractor = dynamic_sites[site_key]
                if extractor is not None:
                    found = extractor(src, func_name)
                else:
                    found = _fn_body_literals(src, func_name)
                if found:
                    templates.update(found)
                    continue
            t, ok = resolve_rs_name(args[idx], src,
                                     scope=scope,
                                     call_pos=coff,
                                     scope_off=scope_off)
            if ok:
                templates.update(t)
            elif is_push_drain(src, args[idx], coff, push_receivers):
                continue
            else:
                seg = " ".join(args[idx].split())[:120]
                unresolved.append((fn, lineno, seg))
        by_module[fn[:-3]] = templates
    return by_module, unresolved


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

def load_ledger(path):
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return data.get("divergence", [])


def is_ledgered(module, name, entries):
    """The #51/#57 contract: ledgered if the name appears in a divergence
    entry's reason text, or the check module has a kind = "missing" entry."""
    for e in entries:
        kind, check = e.get("kind"), e.get("check", "")
        if kind == "missing" and (check == module or check == name):
            return True
        reason = e.get("reason", "")
        if reason and template_regex(name).search(reason):
            return True
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def missing_check_names(entries):
    """Names of checks with kind="missing" ledger entries. Shared by main()
    and the test suite so drift in the construction is caught."""
    return {e.get("check") for e in entries if e.get("kind") == "missing"}


def is_stale_entry(module, name, missing_modules, port_templates):
    """Whether a ledger entry is stale: the check is marked missing but the
    port now implements it with an exact (non-wildcard) pattern for this
    finding.

    Both the module AND the finding name are checked against missing_modules:
    all 2 kind="missing" entries are currently keyed by finding name
    (inaccessible-filename, lengthy-symlink). Dropping the name half of the
    disjunction would let a name-keyed entry whose finding the port now emits
    go undetected.
    """
    return (module in missing_modules or name in missing_modules) and any(
        "*" not in p and p == name for p in port_templates
    )


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    opts = {a.split("=")[0]: (a.split("=", 1)[1] if "=" in a else True)
            for a in argv[1:] if a.startswith("--")}
    ref = resolve_ref_dir(args[0] if args else None)
    root = repo_root()
    port_dir = opts.get("--port", os.path.join(
        root, "crates", "rpmcrab-core", "src", "checks"))
    ledger_path = opts.get("--ledger", os.path.join(
        root, "tests", "parity", "divergences.toml"))
    if not os.path.isdir(port_dir):
        sys.stderr.write(f"error: port checks dir not found: {port_dir}\n")
        return 2

    findings, unresolved, nmods = audit_reference(ref)
    by_module, port_unresolved = audit_port(port_dir)
    port_templates = set().union(*by_module.values()) if by_module else set()
    check_map = port_check_map(os.path.join(os.path.dirname(port_dir), "check.rs"))
    if not check_map:
        # An empty map sends every check down the unscoped fallback, which is
        # the masking hole this scoping closes. Fail loudly instead of
        # reporting a clean audit that means nothing.
        sys.stderr.write(
            f"error: no check::build() arms parsed from "
            f"{os.path.join(os.path.dirname(port_dir), 'check.rs')}; wildcard "
            "scoping would be silently disabled\n")
        return 2
    entries = load_ledger(ledger_path)

    gaps, ledgered, stale = [], [], []
    # A check is unmapped regardless of whether any of its findings happen to be
    # covered, so derive this before the loop rather than while iterating.
    unscoped = unscoped_modules({module for module, _ in findings}, check_map)
    missing_modules = missing_check_names(entries)
    for module, name in sorted(findings):
        if covers_finding(module, name, by_module, port_templates, check_map):
            # A kind="missing" entry must not be able to silence a module the
            # port has since implemented: that hides every future regression in
            # it behind an entry written before the port existed.
            # Only an EXACT port pattern counts here. A wildcard template such
            # as `empty-*` "covers" every `empty-` name, including ones no port
            # check emits, so it would report staleness that is not there.
            if is_stale_entry(module, name, missing_modules, port_templates):
                stale.append((module, name))
            continue
        if is_ledgered(module, name, entries):
            ledgered.append((module, name))
        else:
            gaps.append((module, name))

    print("Reference coverage audit")
    print("========================")
    print(f"reference : {ref}")
    print(f"port      : {port_dir}")
    print(f"ledger    : {ledger_path}")
    print(f"modules scanned: {nmods}; reference findings: {len(findings)}; "
          f"port patterns: {len(port_templates)}")
    print()
    if unscoped:
        print(f"UNSCOPED ({len(unscoped)}): no check::build() arm, so their "
              "findings are matched against every port pattern -- a wildcard "
              "can still mask a finding added to one of these")
        for module in sorted(unscoped):
            print(f"  {module}")
        print()
    if gaps:
        print(f"GAPS ({len(gaps)}): reference findings absent from the port "
              "and unledgered -- these need action")
        for module, name in gaps:
            print(f"  {name}  [{module}.py]")
        print()
    else:
        print("GAPS (0): none -- every reference finding is ported or ledgered")
        print()
    if unresolved or port_unresolved:
        print(f"UNRESOLVED ({len(unresolved) + len(port_unresolved)}): sites the "
              "resolver could not handle -- review by hand, never ignore")
        for module, lineno, seg in unresolved:
            print(f"  ref  {module}.py:{lineno}: {seg}")
        for fn, lineno, seg in port_unresolved:
            print(f"  port {fn}:{lineno}: {seg}")
        print()
    print(f"ledgered but absent from port: {len(ledgered)} "
          "(deliberate, recorded)")
    if opts.get("--verbose"):
        for module, name in ledgered:
            print(f"  {name}  [{module}.py]")

    if stale:
        print()
        print(f"STALE LEDGER ({len(stale)}): findings a kind=\"missing\" entry "
              "claims are unported but the port emits. Delete the entry.")
        for module, name in stale:
            print(f"  {name}  [{module}.py]")
        print()

    if gaps or unresolved or port_unresolved or stale:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
