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


def _repomd_with_href(href):
    """A repomd.xml response with the given filelists href.

    Lets a test vary the href per fetch: with a constant href the
    stale-mirror tests only prove the repomd *fetch* counts, not that the
    retry loop actually uses each cycle's fresh href.
    """
    resp = mock.MagicMock()
    resp.read.return_value = (
        '<?xml version="1.0"?>'
        '<repomd><data type="filelists">'
        '<location href="%s"/>'
        "</data></repomd>" % href
    ).encode("utf-8")
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
            mock.patch.object(gen.time, "sleep"), \
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
            mock.patch.object(gen.time, "sleep"), \
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
            mock.patch.object(gen.time, "sleep"), \
            popen_patch, run_patch:
        try:
            _filelist_hits(["/usr/bin/foo"], {})
        except gen.GrepError as e:
            assert "grep failed (rc=2)" in str(e), str(e)
        else:
            raise AssertionError("grep failure did not raise")


def test_grep_failure_raises_without_retry():
    """A deterministic grep failure (rc=2) raises at once, no backoff.

    GrepError is not a RuntimeError, so the stale-mirror retry loop lets
    it through: no second repomd fetch, no sleeps - retry cannot fix a
    failure a fresh mirror would reproduce identically.
    """
    popen_patch, run_patch, _ = _pipeline(grep_rc=2, grep_stderr="grep: boom")
    urlopen_calls = []

    def fake_urlopen(*args, **kwargs):
        urlopen_calls.append(args)
        return _repomd_response()

    sleeps = []
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=fake_urlopen), \
            mock.patch.object(gen.time, "sleep",
                              side_effect=lambda s: sleeps.append(s)), \
            popen_patch, run_patch:
        try:
            _filelist_hits(["/usr/bin/foo"], {})
        except gen.GrepError as e:
            assert "grep failed (rc=2)" in str(e), str(e)
        else:
            raise AssertionError("grep failure did not raise")
    assert len(urlopen_calls) == 1, urlopen_calls
    assert sleeps == [], sleeps


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
            assert (
                str(e)
                == "repomd.xml fetch failed for Tumbleweed after retries: HTTP Error 503: err"
            ), str(e)
        else:
            raise AssertionError("repomd 503s did not raise")
    assert urlopen_mock.call_count == gen._REPOMD_ATTEMPTS, urlopen_mock.call_count
    assert sleeps == gen._REPOMD_BACKOFF, sleeps


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


def test_repomd_retries_incomplete_read_and_conn_reset():
    """IncompleteRead and ConnectionResetError are transient mid-transfer
    failures and must be retried like URLError/TimeoutError."""
    import http.client

    popen_patch, run_patch, _ = _pipeline(
        grep_rc=0, grep_stdout=">/usr/bin/foo<\n")
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=[http.client.IncompleteRead("partial", 10),
                                        ConnectionResetError("reset"),
                                        _repomd_response()]) as urlopen_mock, \
            mock.patch.object(gen.time, "sleep"), \
            popen_patch, run_patch:
        hits = _filelist_hits(["/usr/bin/foo"], {})
    assert hits == {"/usr/bin/foo"}, hits
    assert urlopen_mock.call_count == 3, urlopen_mock.call_count


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


# ---------------------------------------------------------------------------
# Leap 16.0 repomd sha512 verification (follow-up to #334)
# ---------------------------------------------------------------------------

_LEAP16_REPOMD_TMPL = (
    '<?xml version="1.0"?>'
    '<repomd><data type="primary">'
    '{checksum}'
    '<location href="repodata/primary.xml.zst"/>'
    '</data></repomd>'
)

_LEAP16_PRIMARY_PAYLOAD = b"fake primary.xml payload"
_LEAP16_PRIMARY_XML = b"<name>foo</name><name>bar</name>"


def _leap16_repomd(checksum_hex=None):
    checksum = (
        f'<checksum type="sha512">{checksum_hex}</checksum>'
        if checksum_hex else ''
    )
    return _LEAP16_REPOMD_TMPL.format(checksum=checksum).encode('utf-8')


def _read_once(data):
    resp = mock.MagicMock()
    resp.read = mock.Mock(side_effect=[data, b''])
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


class _FakeZstdStdout:
    def __init__(self, data):
        self._data = data

    def read(self, n=-1):
        if n is None or n < 0:
            chunk, self._data = self._data, b''
        else:
            chunk, self._data = self._data[:n], self._data[n:]
        return chunk

    def close(self):
        pass


class _FakeZstd:
    returncode = 0

    def __init__(self, xml):
        self.stdout = _FakeZstdStdout(xml)

    def wait(self):
        return 0


def _leap16_run(repomd, payload):
    """Run _leap16_binary_names with mocked network and zstd."""
    gen._leap16_binary_names_cache = None
    with mock.patch.object(gen.shutil, 'which', return_value='/usr/bin/zstd'), \
            mock.patch.object(gen.urllib.request, 'urlopen',
                              side_effect=[_read_once(repomd),
                                            _read_once(payload)]), \
            mock.patch.object(gen.subprocess, 'Popen',
                              lambda *a, **k: _FakeZstd(_LEAP16_PRIMARY_XML)):
        return gen._leap16_binary_names()


def test_leap16_sha512_good_returns_names():
    """A matching sha512 lets the names through."""
    import hashlib
    sha = hashlib.sha512(_LEAP16_PRIMARY_PAYLOAD).hexdigest()
    names = _leap16_run(_leap16_repomd(sha), _LEAP16_PRIMARY_PAYLOAD)
    assert names == {'foo', 'bar'}, names


def test_leap16_sha512_corrupt_raises():
    """A tampered download must raise, never silently verify."""
    try:
        _leap16_run(_leap16_repomd('0' * 128), _LEAP16_PRIMARY_PAYLOAD)
    except RuntimeError as e:
        assert 'sha512 mismatch' in str(e), str(e)
    else:
        raise AssertionError('corrupt download did not raise')


def test_leap16_sha512_missing_raises():
    """A repomd without the checksum must raise, not skip verification."""
    try:
        _leap16_run(_leap16_repomd(), _LEAP16_PRIMARY_PAYLOAD)
    except RuntimeError as e:
        assert 'sha512' in str(e), str(e)
    else:
        raise AssertionError('missing sha512 did not raise')


# ---------------------------------------------------------------------------
# stale mirror: repomd.xml fine, filelists 404 -> fresh repomd per cycle
# ---------------------------------------------------------------------------

def test_filelist_stale_mirror_retries_with_fresh_repomd():
    """A 404ing filelist is retried with a fresh repomd fetch per cycle.

    Each cycle's repomd fetch gets its own MirrorBrain redirect, so the
    retry can land on a synced mirror. The href varies per cycle and the
    curl URL list is asserted, proving the fresh href is actually *used*
    rather than the fetch count just going up.
    """
    hrefs = ["repodata/cycle-1-filelists.xml.zst",
             "repodata/cycle-2-filelists.xml.zst"]
    curl_urls = []

    def fake_popen(argv, **kwargs):
        if argv[0] == "curl":
            curl_urls.append(argv[-1])
            if len(curl_urls) == 1:
                return _FakePopen(
                    22, stderr=b"curl: (22) The requested URL returned error: 404")
            return _FakePopen(0)
        assert argv[0] == "zstd", argv
        return _FakePopen(0)

    urlopen_calls = []

    def fake_urlopen(*args, **kwargs):
        urlopen_calls.append(args)
        return _repomd_with_href(hrefs[len(urlopen_calls) - 1])

    grep_result = mock.Mock()
    grep_result.returncode = 0
    grep_result.stdout = ">/usr/bin/foo<\n"
    grep_result.stderr = ""

    sleeps = []
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=fake_urlopen) as urlopen_mock, \
            mock.patch.object(gen.subprocess, "Popen", fake_popen), \
            mock.patch.object(gen.subprocess, "run",
                              return_value=grep_result), \
            mock.patch.object(gen.time, "sleep",
                              side_effect=lambda s: sleeps.append(s)):
        hits = _filelist_hits(["/usr/bin/foo"], {})
    assert hits == {"/usr/bin/foo"}, hits
    # fresh repomd.xml fetch per cycle (new mirror redirect)
    assert urlopen_mock.call_count == 2, urlopen_mock.call_count
    # ... and each cycle's curl used that cycle's fresh href
    assert curl_urls == ["http://r/" + h for h in hrefs], curl_urls
    assert sleeps == [gen._FILELIST_BACKOFF[0]], sleeps


def test_filelist_stale_mirror_exhausts_cycles_then_raises():
    """Persistent filelist 404s raise only after every cycle is exhausted.

    The href varies per cycle so the test also proves every cycle
    re-parsed and used its own fresh repomd's href.
    """
    hrefs = ["repodata/cycle-%d-filelists.xml.zst" % n
             for n in range(1, gen._FILELIST_CYCLES + 1)]
    curl_urls = []

    def fake_popen(argv, **kwargs):
        if argv[0] == "curl":
            curl_urls.append(argv[-1])
            return _FakePopen(
                22, stderr=b"curl: (22) The requested URL returned error: 404")
        return _FakePopen(0)

    urlopen_calls = []

    def fake_urlopen(*args, **kwargs):
        urlopen_calls.append(args)
        return _repomd_with_href(hrefs[len(urlopen_calls) - 1])

    grep_result = mock.Mock()
    grep_result.returncode = 1
    grep_result.stdout = ""
    grep_result.stderr = ""

    sleeps = []
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=fake_urlopen), \
            mock.patch.object(gen.subprocess, "Popen", fake_popen), \
            mock.patch.object(gen.subprocess, "run",
                              return_value=grep_result), \
            mock.patch.object(gen.time, "sleep",
                              side_effect=lambda s: sleeps.append(s)):
        try:
            _filelist_hits(["/usr/bin/foo"], {})
        except RuntimeError as e:
            msg = str(e)
            assert "after %d attempts" % gen._FILELIST_CYCLES in msg, msg
            assert "curl rc=22" in msg, msg
        else:
            raise AssertionError("exhausted filelist cycles did not raise")
    assert len(curl_urls) == gen._FILELIST_CYCLES, curl_urls
    assert curl_urls == ["http://r/" + h for h in hrefs], curl_urls
    assert sleeps == gen._FILELIST_BACKOFF, sleeps

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
