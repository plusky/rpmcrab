#!/usr/bin/env python3
"""Dump rpmlint's `Pkg` abstraction as diffable JSON — the M2 parity oracle.

Run with the reference venv's python (it has `import rpm`):

    scripts/capture-pkg-dump.py [rpm ...]

The reference environment is built by scripts/setup-rpmlint-ref.sh; set
RPMLINT_REF to override `.parity-ref/` in the repo root. Output goes to
tests/parity/pkg/<basename>.json.

The dump is only valid for the rpmlint and librpm that produced it, so every
file records provenance (`reference_sha`, `rpmlint`, `librpm`, `capture_host`,
`captured`). A librpm skew silently invalidates the harness otherwise.
"""
import datetime
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import traceback

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF = os.environ.get('RPMLINT_REF', os.path.join(REPO, '.parity-ref'))
OUTDIR = os.path.join(REPO, 'tests', 'parity', 'pkg')

sys.path.insert(0, os.path.join(REF, 'rpmlint-src'))
from rpmlint.pkg import Pkg, SCRIPT_TAGS  # noqa: E402

DEP_ATTRS = [
    'requires', 'prereq', 'provides', 'conflicts', 'obsoletes',
    'recommends', 'suggests', 'enhances', 'supplements',
]


def s(v):
    if isinstance(v, bytes):
        return v.decode('utf-8', 'replace')
    return v


def provenance():
    import magic  # noqa: E402  (libmagic version, present in the reference venv)
    import rpm  # noqa: E402  (system binding, present in the reference venv)

    try:
        with open(os.path.join(REF, 'REF_SHA')) as fh:
            sha = fh.read().strip()
    except OSError:
        sha = 'UNKNOWN'
    version = subprocess.run(
        [sys.executable, '-c', 'import rpmlint.version as v; print(v.__version__)'],
        capture_output=True, text=True, check=False,
    ).stdout.strip() or 'UNKNOWN'
    # The `magic` field is libmagic's output, so the libmagic version is part of
    # the contract. The capture host itself is redacted — this repo is public.
    return {
        'rpmlint': version,
        'reference_sha': sha,
        'librpm': rpm.__version__,
        'libmagic': magic.version(),
        'captured': datetime.date.today().isoformat(),
    }


def dep_to_dict(d):
    name, flags, evr = d
    epoch, version, release = evr if evr is not None else (None, None, None)
    return {
        'name': s(name),
        'flags': int(flags),
        'epoch': epoch,
        'version': s(version),
        'release': s(release),
    }


def fileclass_array(pkg):
    """The raw FILECLASS strings, by file position. `_calc_magic` overwrites
    `PkgFile.magic` with its own output, so the raw class is read back from the
    header to tell a populated class from a libmagic lookup."""
    import rpm  # noqa: E402

    try:
        arr = pkg.header[rpm.RPMTAG_FILECLASS]
    except (KeyError, TypeError):
        return []
    return [s(x) for x in arr] if arr else []


def file_to_dict(f, fileclass):
    mode = int(f.mode)
    return {
        'name': s(f.name),
        # The real path is host-specific; record the deterministic form rpmlint
        # computes (`normpath(join(dir_name, name.lstrip('/')))`).
        'path': os.path.normpath(os.path.join('<DIR>', f.name.lstrip('/'))),
        'flags': int(f.flags),
        'mode': mode,
        'user': s(f.user),
        'group': s(f.group),
        'linkto': s(f.linkto),
        'size': f.size,
        'md5': s(f.md5),
        'mtime': f.mtime,
        'rdev': f.rdev,
        'inode': f.inode,
        'lang': s(f.lang),
        'fileclass': fileclass,
        'magic': s(f.magic),
        'filecaps': s(f.filecaps),
        'is_config': bool(f.is_config),
        'is_doc': bool(f.is_doc),
        'is_ghost': bool(f.is_ghost),
        'is_noreplace': bool(f.is_noreplace),
        'is_missingok': bool(f.is_missingok),
        'is_dir': stat.S_ISDIR(mode),
        'is_symlink': stat.S_ISLNK(mode),
        'is_reg': stat.S_ISREG(mode),
        'filemode': stat.filemode(mode),
        'suid': bool(mode & 0o4000),
        'sgid': bool(mode & 0o2000),
    }


def build_dump(pkg):
    doc = {'meta': provenance()}
    doc.update({
        'name': s(pkg.name),
        'arch': s(pkg.arch),
        'is_source': bool(pkg.is_source),
        'is_no_source': bool(pkg.is_no_source),
        # The reference stores the as-passed path; record it path-shaped with
        # the host directory redacted.
        'filename': '<DIR>/' + os.path.basename(pkg.filename),
        'dir_name': '<DIR>',
    })
    for attr in DEP_ATTRS:
        doc[attr] = [dep_to_dict(d) for d in getattr(pkg, attr)]
    fileclasses = fileclass_array(pkg)
    doc['files'] = [
        file_to_dict(f, fileclasses[i] if i < len(fileclasses) else '')
        for i, f in enumerate(pkg.files.values())
    ]
    doc['doc_files'] = sorted(s(n) for n in pkg.doc_files)
    doc['config_files'] = sorted(s(n) for n in pkg.config_files)
    doc['ghost_files'] = sorted(s(n) for n in pkg.ghost_files)
    doc['noreplace_files'] = sorted(s(n) for n in pkg.noreplace_files)
    doc['missingok_files'] = sorted(s(n) for n in pkg.missingok_files)
    scriptlets = {}
    for s_tag, p_tag, label in SCRIPT_TAGS:
        text = pkg[s_tag]
        scriptlets[label] = {
            'exists': bool(text),
            'prog': s(pkg.scriptprog(p_tag)),
        }
    doc['scriptlets'] = scriptlets
    return doc


def dump_one(path, outname):
    td = tempfile.mkdtemp(prefix='pkgdump.', dir='/tmp')
    pkg = None
    try:
        pkg = Pkg(path, td)
        doc = build_dump(pkg)
    finally:
        if pkg is not None:
            try:
                pkg.cleanup()
            except Exception:
                pass
        shutil.rmtree(td, ignore_errors=True)
    out = os.path.join(OUTDIR, outname)
    with open(out, 'w') as fh:
        json.dump(doc, fh, indent=2)
        fh.write('\n')
    return doc, out


def main(argv):
    # Each arg is `input-rpm:output-case.json`.
    specs = argv[1:] or []
    os.makedirs(OUTDIR, exist_ok=True)
    failures = 0
    for spec in specs:
        rpm_path, _, outname = spec.partition(':')
        if not outname:
            failures += 1
            print(f'ERROR: bad spec {spec!r}: expected <input-rpm>:<output-case.json>')
            continue
        if not os.path.exists(rpm_path):
            failures += 1
            print(f'ERROR {os.path.basename(rpm_path)}: no such file: {rpm_path}')
            continue
        try:
            doc, out = dump_one(rpm_path, outname)
            print(f'OK    {outname}: files={len(doc["files"])} -> {out}')
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f'ERROR {outname}: {type(exc).__name__}: {exc}')
            traceback.print_exc()
    print(f'SUMMARY dumped={len(specs) - failures} failed={failures}')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
