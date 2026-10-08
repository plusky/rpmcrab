#!/usr/bin/env python3
"""Fail-closed tests for the filelist verification in generate-distro-configs.py.

Each test guards a failure mode that would silently defeat the moved-path
guard: removing the loud failure makes the test fail. The curl-failure test
is the automated version of the manual bogus-URL proof - a failed download
must raise, never return an empty hit set that prunes everything the guard
verifies.

Run:  python3 scripts/test_generate_distro_configs.py
"""

import importlib.util
import os
import sys
import urllib.error
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location(
        "gen_distro_configs", os.path.join(HERE, "generate-distro-configs.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen = _load()

_REPOMD = (
    '<?xml version="1.0"?>'
    '<repomd><data type="filelists">'
    '<location href="repodata/abc-filelists.xml.zst"/>'
    "</data></repomd>"
)


def _repomd_response():
    resp = mock.MagicMock()
    resp.read.return_value = _REPOMD.encode("utf-8")
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


def _http_error(code):
    return urllib.error.HTTPError("http://r/repomd.xml", code, "err", {}, None)


class _FakePipe:
    def __init__(self, data=b""):
        self._data = data

    def read(self):
        return self._data

    def close(self):
        pass


class _FakePopen:
    def __init__(self, rc, stderr=b""):
        self.stdin = _FakePipe()
        self.stdout = _FakePipe()
        self.stderr = _FakePipe(stderr)
        self._rc = rc

    def wait(self):
        return self._rc


def _pipeline(curl_rc=0, zstd_rc=0, curl_err=b"", zstd_err=b"",
              grep_rc=1, grep_stdout="", grep_stderr=""):
    """Patch Popen/run to simulate the curl | zstd -dc | grep pipeline."""
    def fake_popen(argv, **kwargs):
        if argv[0] == "curl":
            return _FakePopen(curl_rc, stderr=curl_err)
        assert argv[0] == "zstd", argv
        return _FakePopen(zstd_rc, stderr=zstd_err)

    grep_result = mock.Mock()
    grep_result.returncode = grep_rc
    grep_result.stdout = grep_stdout
    grep_result.stderr = grep_stderr
    run_calls = []

    def fake_run(argv, **kwargs):
        run_calls.append(argv)
        return grep_result

    return (
        mock.patch.object(gen.subprocess, "Popen", fake_popen),
        mock.patch.object(gen.subprocess, "run", fake_run),
        run_calls,
    )


def _filelist_hits(paths, cache):
    return gen._filelist_hits(
        paths, "http://r/repomd.xml", "http://r/", cache, "Tumbleweed")


# ---------------------------------------------------------------------------
# Fail-closed: every pipeline stage must raise, never return empty hits
# ---------------------------------------------------------------------------

def test_curl_failure_raises():
    """A failed download must raise, not silently prune everything."""
    popen_patch, run_patch, _ = _pipeline(
        curl_rc=28, curl_err=b"curl: (28) Operation timed out")
    with mock.patch.object(gen.urllib.request, "urlopen",
                           return_value=_repomd_response()), \
            popen_patch, run_patch:
        try:
            _filelist_hits(["/usr/bin/foo"], {})
        except RuntimeError as e:
            assert "curl rc=28" in str(e), str(e)
            assert "timed out" in str(e), str(e)
        else:
            raise AssertionError("curl failure did not raise")


def test_zstd_failure_raises_with_stderr():
    popen_patch, run_patch, _ = _pipeline(
        zstd_rc=1, zstd_err=b"zstd: /*stdin*\\: not in zstd format")
    with mock.patch.object(gen.urllib.request, "urlopen",
                           return_value=_repomd_response()), \
            popen_patch, run_patch:
        try:
            _filelist_hits(["/usr/bin/foo"], {})
        except RuntimeError as e:
            assert "zstd rc=1" in str(e), str(e)
            assert "not in zstd format" in str(e), str(e)
        else:
            raise AssertionError("zstd failure did not raise")


def test_grep_failure_raises():
    popen_patch, run_patch, _ = _pipeline(grep_rc=2, grep_stderr="grep: boom")
    with mock.patch.object(gen.urllib.request, "urlopen",
                           return_value=_repomd_response()), \
            popen_patch, run_patch:
        try:
            _filelist_hits(["/usr/bin/foo"], {})
        except RuntimeError as e:
            assert "grep failed (rc=2)" in str(e), str(e)
        else:
            raise AssertionError("grep failure did not raise")


def test_repomd_without_filelists_raises():
    resp = mock.MagicMock()
    resp.read.return_value = b"<repomd></repomd>"
    resp.__enter__.return_value = resp
    with mock.patch.object(gen.urllib.request, "urlopen", return_value=resp):
        try:
            _filelist_hits(["/usr/bin/foo"], {})
        except RuntimeError as e:
            assert "filelists entry not found" in str(e), str(e)
        else:
            raise AssertionError("missing filelists entry did not raise")


# ---------------------------------------------------------------------------
# repomd.xml fetch retries
# ---------------------------------------------------------------------------

def test_repomd_no_sleep_after_final_attempt():
    """The backoff sleeps between attempts, never after the last one."""
    sleeps = []
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=_http_error(503)) as urlopen_mock, \
            mock.patch.object(gen.time, "sleep",
                              side_effect=lambda s: sleeps.append(s)):
        try:
            _filelist_hits(["/usr/bin/foo"], {})
        except RuntimeError as e:
            assert "after retries" in str(e), str(e)
        else:
            raise AssertionError("repomd 503s did not raise")
    assert urlopen_mock.call_count == 4, urlopen_mock.call_count
    assert sleeps == [15, 30, 45], sleeps


def test_repomd_retries_urlerror_then_succeeds():
    popen_patch, run_patch, _ = _pipeline(
        grep_rc=0, grep_stdout=">/usr/bin/foo<\n")
    calls = []

    def flaky(req, timeout=None):
        calls.append(1)
        if len(calls) < 3:
            raise urllib.error.URLError("Temporary failure in name resolution")
        return _repomd_response()

    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=flaky), \
            mock.patch.object(gen.time, "sleep"), \
            popen_patch, run_patch:
        hits = _filelist_hits(["/usr/bin/foo"], {})
    assert hits == {"/usr/bin/foo"}, hits
    assert len(calls) == 3, calls


def test_repomd_retries_timeout_then_succeeds():
    popen_patch, run_patch, _ = _pipeline(
        grep_rc=0, grep_stdout=">/usr/bin/foo<\n")
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=[TimeoutError("timed out"),
                                        _repomd_response()]) as urlopen_mock, \
            mock.patch.object(gen.time, "sleep"), \
            popen_patch, run_patch:
        hits = _filelist_hits(["/usr/bin/foo"], {})
    assert hits == {"/usr/bin/foo"}, hits
    assert urlopen_mock.call_count == 2, urlopen_mock.call_count


def test_repomd_4xx_raises_immediately():
    """Client errors are not retried."""
    sleeps = []
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=_http_error(404)) as urlopen_mock, \
            mock.patch.object(gen.time, "sleep",
                              side_effect=lambda s: sleeps.append(s)):
        try:
            _filelist_hits(["/usr/bin/foo"], {})
        except urllib.error.HTTPError as e:
            assert e.code == 404, e.code
        else:
            raise AssertionError("404 did not raise")
    assert urlopen_mock.call_count == 1, urlopen_mock.call_count
    assert sleeps == [], sleeps


# ---------------------------------------------------------------------------
# happy path: exact-match hits and per-run caching
# ---------------------------------------------------------------------------

def test_filelist_hits_and_cache():
    popen_patch, run_patch, run_calls = _pipeline(
        grep_rc=0, grep_stdout=">/usr/bin/foo<\n>/usr/bin/other<\n")
    with mock.patch.object(gen.urllib.request, "urlopen",
                           return_value=_repomd_response()) as urlopen_mock, \
            popen_patch, run_patch:
        cache = {}
        hits = _filelist_hits(["/usr/bin/foo", "/usr/bin/baz"], cache)
        assert hits == {"/usr/bin/foo"}, hits
        assert cache == {"/usr/bin/baz": False, "/usr/bin/foo": True}, cache
        argv = run_calls[0]
        assert argv[:3] == ["grep", "-F", "-o"], argv
        assert ">/usr/bin/foo<" in argv and ">/usr/bin/baz<" in argv, argv
        # A second call for cached paths performs no fetch at all.
        hits2 = _filelist_hits(["/usr/bin/foo"], cache)
        assert hits2 == {"/usr/bin/foo"}, hits2
        assert urlopen_mock.call_count == 1, urlopen_mock.call_count


# ---------------------------------------------------------------------------
# unknown flavor
# ---------------------------------------------------------------------------

def test_unknown_flavor_names_valid_flavors():
    try:
        gen.prune_pie_paths("", [], "bogus")
    except RuntimeError as e:
        msg = str(e)
        assert "bogus" in msg, msg
        assert "opensuse" in msg and "slfo" in msg, msg
    else:
        raise AssertionError("unknown flavor did not raise")


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
        except Exception as e:  # noqa: BLE001 - an unexpected exception is a failure too
            failed += 1
            print(f"FAIL {t.__name__}: unexpected {type(e).__name__}: {e}")
        else:
            print(f"ok {t.__name__}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
