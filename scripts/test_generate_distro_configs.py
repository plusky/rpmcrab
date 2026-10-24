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
        except gen.FetchExhausted as e:
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
        except gen.FetchExhausted as e:
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
        except gen.FetchExhausted as e:
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
# pie-path pruning: pass-through
# ---------------------------------------------------------------------------

def test_prune_pie_paths_passes_unlisted_paths_through():
    """Paths outside PRUNE_PIE_PATHS survive untouched and unlogged."""
    text = 'PieExecutables = [\n    "/usr/bin/some-tool",\n]\n'
    log = []
    out = gen.prune_pie_paths(text, log)
    assert out == text, out
    assert log == [], log


# ---------------------------------------------------------------------------
# Tumbleweed repomd sha512 verification (follow-up to #334)
# ---------------------------------------------------------------------------

_PRIMARY_REPOMD_TMPL = (
    '<?xml version="1.0"?>'
    '<repomd><data type="primary">'
    '{checksum}'
    '<location href="repodata/primary.xml.zst"/>'
    '</data></repomd>'
)

_PRIMARY_PAYLOAD = b"fake primary.xml payload"
_PRIMARY_XML = b"<name>foo</name><name>bar</name>"


def _primary_repomd(checksum_hex=None):
    checksum = (
        f'<checksum type="sha512">{checksum_hex}</checksum>'
        if checksum_hex else ''
    )
    return _PRIMARY_REPOMD_TMPL.format(checksum=checksum).encode('utf-8')


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


def _primary_run(repomd, payload):
    """Run _tw_binary_names with mocked network and zstd.

    The urlopen fake dispatches on the URL and never runs out of
    responses: a failed primary download is retried over fresh repomd
    fetches, so a two-response side-effect list no longer suffices.
    """
    gen._tw_binary_names_cache = None

    def fake_urlopen(req, timeout=None):
        if req.full_url.endswith('repomd.xml'):
            return _read_once(repomd)
        return _read_once(payload)

    with mock.patch.object(gen.shutil, 'which', return_value='/usr/bin/zstd'), \
            mock.patch.object(gen.urllib.request, 'urlopen',
                              side_effect=fake_urlopen), \
            mock.patch.object(gen.subprocess, 'Popen',
                              lambda *a, **k: _FakeZstd(_PRIMARY_XML)), \
            mock.patch.object(gen.time, 'sleep'):
        return gen._tw_binary_names()


def test_primary_sha512_good_returns_names():
    """A matching sha512 lets the names through."""
    import hashlib
    sha = hashlib.sha512(_PRIMARY_PAYLOAD).hexdigest()
    names = _primary_run(_primary_repomd(sha), _PRIMARY_PAYLOAD)
    assert names == {'foo', 'bar'}, names


def test_primary_sha512_corrupt_raises():
    """A tampered download must raise, never silently verify."""
    try:
        _primary_run(_primary_repomd('0' * 128), _PRIMARY_PAYLOAD)
    except gen.FetchExhausted as e:
        assert 'sha512 mismatch' in str(e), str(e)
    else:
        raise AssertionError('corrupt download did not raise')


def test_primary_sha512_missing_raises():
    """A repomd without the checksum must raise, not skip verification."""
    try:
        _primary_run(_primary_repomd(), _PRIMARY_PAYLOAD)
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
        except gen.FetchExhausted as e:
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


# ---------------------------------------------------------------------------
# fallback mirror: MirrorBrain keeps redirecting to the same stale mirror
# ---------------------------------------------------------------------------

def _doso_filelist_hits(paths, cache):
    return gen._filelist_hits(
        paths,
        "https://download.opensuse.org/tumbleweed/repo/oss/repodata/repomd.xml",
        "https://download.opensuse.org/tumbleweed/repo/oss/",
        cache,
        "Tumbleweed",
    )


def test_filelist_fallback_mirror_after_cycles_exhausted():
    """Persistent MirrorBrain 404s fall back to the hardcoded mirror.

    The repomd fetch succeeds everywhere (only the filelist 404s), so the
    failure is the stale-mirror signature; after the retry cycles are
    exhausted one cycle runs against ftp.gwdg.de and succeeds.
    """
    curl_urls = []
    repomd_urls = []

    def fake_urlopen(req, **kwargs):
        repomd_urls.append(req.full_url)
        return _repomd_response()

    def fake_popen(argv, **kwargs):
        assert argv[0] in ("curl", "zstd"), argv
        if argv[0] == "curl":
            url = argv[-1]
            curl_urls.append(url)
            if "ftp.gwdg.de" in url:
                return _FakePopen(0)
            return _FakePopen(
                22, stderr=b"curl: (22) The requested URL returned error: 404")
        return _FakePopen(0)

    grep_result = mock.Mock()
    grep_result.returncode = 0
    grep_result.stdout = ">/usr/bin/foo<\n"
    grep_result.stderr = ""

    with mock.patch.object(gen.urllib.request, "urlopen", fake_urlopen), \
            mock.patch.object(gen.subprocess, "Popen", fake_popen), \
            mock.patch.object(gen.subprocess, "run",
                              return_value=grep_result), \
            mock.patch.object(gen.time, "sleep"):
        hits = _doso_filelist_hits(["/usr/bin/foo"], {})
    assert hits == {"/usr/bin/foo"}, hits
    # all MirrorBrain cycles failed before the fallback was tried
    assert curl_urls.count(
        "https://download.opensuse.org/tumbleweed/repo/oss/"
        "repodata/abc-filelists.xml.zst") == gen._FILELIST_CYCLES, curl_urls
    assert any("ftp.gwdg.de" in u for u in curl_urls), curl_urls
    # the repomd re-fetch for the fallback cycle went to the GWDG mirror
    assert any("ftp.gwdg.de" in u for u in repomd_urls), repomd_urls


def test_filelist_fallback_mirror_failure_still_raises():
    """A broken fallback mirror still fails loudly, never prunes silently."""
    curl_urls = []

    def fake_popen(argv, **kwargs):
        assert argv[0] in ("curl", "zstd"), argv
        if argv[0] == "curl":
            curl_urls.append(argv[-1])
            return _FakePopen(
                22, stderr=b"curl: (22) The requested URL returned error: 404")
        return _FakePopen(0)

    grep_result = mock.Mock()
    grep_result.returncode = 1
    grep_result.stdout = ""
    grep_result.stderr = ""

    with mock.patch.object(gen.urllib.request, "urlopen",
                           return_value=_repomd_response()), \
            mock.patch.object(gen.subprocess, "Popen", fake_popen), \
            mock.patch.object(gen.subprocess, "run",
                              return_value=grep_result), \
            mock.patch.object(gen.time, "sleep"):
        try:
            _doso_filelist_hits(["/usr/bin/foo"], {})
        except gen.FetchExhausted as e:
            msg = str(e)
            # the fallback counts as an attempt too
            assert "after %d attempts" % (gen._FILELIST_CYCLES + 1) in msg, msg
            assert "curl rc=22" in msg, msg
            # the fallback mirror was actually tried before giving up
            assert any("ftp.gwdg.de" in u for u in curl_urls), curl_urls
        else:
            raise AssertionError("broken fallback mirror did not raise")


def test_filelist_no_fallback_for_unknown_base():
    """Non-download.opensuse.org bases keep raise-after-cycles behavior."""
    def fake_popen(argv, **kwargs):
        assert argv[0] in ("curl", "zstd"), argv
        if argv[0] == "curl":
            return _FakePopen(
                22, stderr=b"curl: (22) The requested URL returned error: 404")
        return _FakePopen(0)

    grep_result = mock.Mock()
    grep_result.returncode = 1
    grep_result.stdout = ""
    grep_result.stderr = ""

    with mock.patch.object(gen.urllib.request, "urlopen",
                           return_value=_repomd_response()), \
            mock.patch.object(gen.subprocess, "Popen", fake_popen), \
            mock.patch.object(gen.subprocess, "run",
                              return_value=grep_result), \
            mock.patch.object(gen.time, "sleep"):
        try:
            gen._filelist_hits(["/usr/bin/foo"], "http://r/repomd.xml",
                               "http://r/", {}, "Tumbleweed")
        except gen.FetchExhausted as e:
            assert "after %d attempts" % gen._FILELIST_CYCLES in str(e), e
        else:
            raise AssertionError("did not raise")


# ---------------------------------------------------------------------------
# stale mirror: repomd.xml fine, primary.xml 404 -> fresh repomd per cycle
# ---------------------------------------------------------------------------

_TW_PRIMARY_PAYLOAD = b"fake tw primary payload"
_TW_PRIMARY_XML = b"<name>twfoo</name><name>twbar</name>"


def _tw_repomd(href):
    import hashlib
    sha = hashlib.sha512(_TW_PRIMARY_PAYLOAD).hexdigest()
    return (
        '<?xml version="1.0"?>'
        '<repomd><data type="primary">'
        '<checksum type="sha512">%s</checksum>'
        '<location href="%s"/>'
        "</data></repomd>" % (sha, href)
    ).encode("utf-8")


def _tw_run(primary):
    """Run _tw_binary_names with mocked network and zstd.

    `primary(url)` answers the primary.xml fetches (a response or an
    exception). The repomd href varies per fetch, so the recorded
    primary URLs prove each cycle used its own fresh repomd. Returns
    (names, urls, sleeps, error): names is None when the run raised, in
    which case error holds the exception.
    """
    gen._tw_binary_names_cache = None
    urls = []
    repomd_fetches = []

    def fake_urlopen(req, timeout=None):
        url = req.full_url
        urls.append(url)
        if url.endswith("repomd.xml"):
            repomd_fetches.append(url)
            return _read_once(
                _tw_repomd(
                    "repodata/cycle%d-primary.xml.zst" % len(repomd_fetches)))
        return primary(url)

    sleeps = []
    names, error = None, None
    with mock.patch.object(gen.shutil, "which", return_value="/usr/bin/zstd"), \
            mock.patch.object(gen.urllib.request, "urlopen",
                              side_effect=fake_urlopen), \
            mock.patch.object(gen.subprocess, "Popen",
                              lambda *a, **k: _FakeZstd(_TW_PRIMARY_XML)), \
            mock.patch.object(gen.time, "sleep",
                              side_effect=lambda s: sleeps.append(s)):
        try:
            names = gen._tw_binary_names()
        except Exception as e:  # noqa: BLE001 - returned for assertion
            error = e
    return names, urls, sleeps, error


def test_primary_stale_mirror_retries_with_fresh_repomd():
    """A 404ing primary archive is retried with a fresh repomd fetch.

    The stale-mirror signature behind the distro-config-drift flakes:
    repomd.xml fetches fine but the primary archive it references 404s
    on the mirror MirrorBrain redirected to. The next cycle's fresh
    repomd fetch gets a new redirect and the download succeeds. The
    href varies per cycle and the primary URL list is asserted, proving
    the retry actually uses each cycle's fresh href.
    """
    primary_urls = []

    def primary(url):
        primary_urls.append(url)
        if len(primary_urls) == 1:
            raise _http_error(404)
        return _read_once(_TW_PRIMARY_PAYLOAD)

    names, _, sleeps, error = _tw_run(primary)
    assert error is None, error
    assert names == {"twfoo", "twbar"}, names
    assert primary_urls == [
        "https://download.opensuse.org/tumbleweed/repo/oss/"
        "repodata/cycle1-primary.xml.zst",
        "https://download.opensuse.org/tumbleweed/repo/oss/"
        "repodata/cycle2-primary.xml.zst",
    ], primary_urls
    assert sleeps == [gen._PRIMARY_BACKOFF[0]], sleeps


def test_primary_urlerror_then_succeeds():
    """A network error on the primary download is retried like a 404."""
    primary_urls = []

    def primary(url):
        primary_urls.append(url)
        if len(primary_urls) == 1:
            raise urllib.error.URLError("Temporary failure in name resolution")
        return _read_once(_TW_PRIMARY_PAYLOAD)

    names, _, sleeps, error = _tw_run(primary)
    assert error is None, error
    assert names == {"twfoo", "twbar"}, names
    assert len(primary_urls) == 2, primary_urls
    assert sleeps == [gen._PRIMARY_BACKOFF[0]], sleeps


def test_primary_stale_mirror_exhausts_cycles_and_fallback_then_raises():
    """Persistent primary 404s raise only after cycles + fallback mirror.

    Retrying cannot help when MirrorBrain keeps redirecting to the
    same stale mirror, so the last attempt goes to ftp.gwdg.de; a
    failure there still fails loudly, never prunes silently.
    """
    primary_urls = []

    def primary(url):
        primary_urls.append(url)
        raise _http_error(404)

    names, _, sleeps, error = _tw_run(primary)
    assert names is None, names
    assert isinstance(error, gen.FetchExhausted), error
    msg = str(error)
    # the fallback mirror counts as an attempt too
    assert "after %d attempts" % (gen._PRIMARY_CYCLES + 1) in msg, msg
    assert "404" in msg, msg
    assert len(primary_urls) == gen._PRIMARY_CYCLES + 1, primary_urls
    assert any("ftp.gwdg.de" in u for u in primary_urls), primary_urls
    assert sleeps == gen._PRIMARY_BACKOFF, sleeps


def test_append_extra_checks_lands_inside_checks_list():
    """The extra Checks must land inside `Checks = [...]`, nowhere else.

    Appending to the wrong list (or outside any list) would either enable
    nothing or corrupt the vendored config; the drift check compares bytes,
    so this pins the shape the generator emits.
    """
    text = (
        'Checks = [\n'
        '    "BashismsCheck",\n'
        ']\n'
        'Filters = [\n'
        "    ' some-filter ',\n"
        ']\n'
    )
    out = gen.append_extra_checks(text, gen.EXTRA_CHECKS)
    checks_part, filters_part = out.split("Filters = [", 1)
    for check in ("XinetdDepCheck", "PAMModulesCheck"):
        assert f'"{check}",' in checks_part, checks_part
        assert check not in filters_part, filters_part
        # The entry is inside the list: it precedes the closing bracket.
        assert checks_part.index(f'"{check}",') < checks_part.index("]"), checks_part
    assert gen.EXTRA_CHECKS == ["XinetdDepCheck", "PAMModulesCheck"], gen.EXTRA_CHECKS


def test_append_extra_checks_without_checks_list_raises():
    """A config with no Checks list must fail loudly, never pass silently.

    Silently skipping the append would ship a vendored config in which the
    deliberately enabled check is missing again.
    """
    try:
        gen.append_extra_checks("Filters = [\n]\n", ["XinetdDepCheck", "PAMModulesCheck"])
    except AssertionError:
        return
    raise AssertionError("append_extra_checks accepted a document with no Checks list")


def test_remove_excluded_checks_drops_entry_and_explains():
    """The excluded Checks must vanish from `Checks = [...]` only.

    The drift check compares bytes, so this pins the shape the generator
    emits: the entry is gone, an explanation comment sits inside the list
    at the same spot, and a same-named string in another list survives.
    """
    text = (
        'Checks = [\n'
        '    "BashismsCheck",\n'
        '    "AtomicUpdateCheck",\n'
        '    "ZipCheck",\n'
        ']\n'
        'Filters = [\n'
        "    'AtomicUpdateCheck',\n"
        ']\n'
    )
    out = gen.remove_excluded_checks(text, ["AtomicUpdateCheck"])
    checks_part, filters_part = out.split("Filters = [", 1)
    assert '"AtomicUpdateCheck",' not in checks_part, checks_part
    assert "EXCLUDED_CHECKS" in checks_part, checks_part
    # The comment is inside the list: it precedes the closing bracket.
    assert checks_part.index("EXCLUDED_CHECKS") < checks_part.index("]"), checks_part
    assert "AtomicUpdateCheck" in filters_part, filters_part
    assert gen.EXCLUDED_CHECKS == [], gen.EXCLUDED_CHECKS


def test_remove_excluded_checks_without_entry_raises():
    """A Checks list missing the excluded check must fail loudly.

    Silently passing would ship an opensuse config in which the check
    still runs -- the exact outcome the exclusion exists to prevent.
    """
    try:
        gen.remove_excluded_checks('Checks = [\n    "ZipCheck",\n]\n', ["AtomicUpdateCheck"])
    except AssertionError:
        return
    raise AssertionError("remove_excluded_checks accepted a Checks list without the excluded check")


def test_retarget_filters_rewrites_moved_targets():
    """RETARGET_FILTERS lines are rewritten in place inside Filters.

    The exemption is kept (ldconfig is static by design; skel dotdirs are
    deliberate), only the moved path changes; the proven-dead neighbours
    are pruned via PRUNE_RAW in the same pass; unrelated lines survive
    byte-identical.
    """
    text = (
        'Filters = [\n'
        "    '^filesystem\\..*: hidden-file-or-dir /etc/skel/.config',\n"
        "    '.* statically-linked-binary /sbin/ldconfig',\n"
        "    '.* statically-linked-binary /sbin/init',\n"
        "    'glibc\\.\\S+: \\w: statically-linked-binary /usr/sbin/glibc_post_upgrade',\n"
        "    'unstripped-binary-or-object',\n"
        ']\n'
    )
    pruned, dropped, retargeted = [], [], []
    out = gen.prune_stale_filters(text, set(), pruned, dropped, retargeted)
    assert '/usr/etc/skel/.config' in out, out
    assert 'hidden-file-or-dir /etc/skel/.config' not in out, out
    assert "'.* statically-linked-binary /usr/sbin/ldconfig'," in out, out
    assert '/sbin/init' not in out, out
    assert 'glibc_post_upgrade' not in out, out
    assert "    'unstripped-binary-or-object',\n" in out, out
    assert len(retargeted) == 2, retargeted
    assert len(pruned) == 2, pruned
    assert dropped == [], dropped


def test_retarget_filters_byte_exact_only():
    """A reworded line is NOT rewritten: matching is byte-exact, so an
    upstream reword stops the retarget and the sync surfaces the line
    for a fresh audit instead of the rewrite silently widening.
    """
    text = (
        'Filters = [\n'
        "    '.* statically-linked-binary  /sbin/ldconfig',\n"
        ']\n'
    )
    pruned, dropped, retargeted = [], [], []
    out = gen.prune_stale_filters(text, set(), pruned, dropped, retargeted)
    assert out == text, out
    assert retargeted == [], retargeted


def test_prune_stale_filters_drops_orphaned_group_comment():
    """A comment heading only dropped entries is dropped with them.

    The comment headed exactly the pruned entry; leaving it behind
    would strand it over the next group. One adjacent blank separator
    goes with it, so the surviving groups keep the file's spacing.
    """
    text = (
        'Filters = [\n'
        "    'kept-entry',\n"
        '\n'
        '# Doomed group\n'
        "    'no-buildroot-tag',\n"
        '\n'
        '# Kept group\n'
        "    'unstripped-binary-or-object',\n"
        ']\n'
    )
    pruned, dropped, retargeted = [], [], []
    out = gen.prune_stale_filters(text, set(), pruned, dropped, retargeted)
    assert out == (
        'Filters = [\n'
        "    'kept-entry',\n"
        '\n'
        '# Kept group\n'
        "    'unstripped-binary-or-object',\n"
        ']\n'
    ), out
    assert len(pruned) == 1, pruned


def test_prune_stale_filters_keeps_shared_group_comment():
    """A comment heading a retained entry stays when a sibling drops."""
    text = (
        'Filters = [\n'
        '# Shared group\n'
        "    'no-buildroot-tag',\n"
        "    'unstripped-binary-or-object',\n"
        ']\n'
    )
    pruned, dropped, retargeted = [], [], []
    out = gen.prune_stale_filters(text, set(), pruned, dropped, retargeted)
    assert out == (
        'Filters = [\n'
        '# Shared group\n'
        "    'unstripped-binary-or-object',\n"
        ']\n'
    ), out
    assert len(pruned) == 1, pruned


def test_prune_stale_filters_drops_filter_error_titles():
    """FilterErrorTitles lines referencing killed findings are pruned
    like Filters lines: the cross-directory-hard-link suppression
    lives in that list, not in Filters."""
    text = (
        'FilterErrorTitles = [\n'
        "    'cross-directory-hard-link',\n"
        "    'live-title',\n"
        ']\n'
    )
    pruned, dropped, retargeted = [], [], []
    out = gen.prune_stale_filters(text, {"live-title"}, pruned, dropped, retargeted)
    assert 'cross-directory-hard-link' not in out, out
    assert "    'live-title',\n" in out, out
    assert len(pruned) == 1 and 'cross-directory-hard-link' in pruned[0], pruned
    assert pruned[0].startswith("FilterErrorTitles:"), pruned


def test_add_filters_inserts_after_anchor():
    """ADD_FILTERS entries land immediately after their anchor line.

    The exemption is new (upstream ships no .cache line), so it is
    inserted behind the sibling it belongs with, in the anchor's own
    indentation and quote style; unrelated lines survive byte-identical.
    """
    text = (
        'Filters = [\n'
        "    '^filesystem\\..*: hidden-file-or-dir /usr/etc/skel/.config',\n"
        "    '^filesystem\\..*: hidden-file-or-dir /usr/etc/skel/.local',\n"
        "    '^filesystem\\..*: hidden-file-or-dir /tmp/.X11-unix',\n"
        "    '^filesystem\\..*: hidden-file-or-dir /usr/etc/skel/.fonts',\n"
        ']\n'
    )
    added = []
    out = gen.add_filters(text, added)
    assert out == (
        'Filters = [\n'
        "    '^filesystem\\..*: hidden-file-or-dir /usr/etc/skel/.config',\n"
        "    '^filesystem\\..*: hidden-file-or-dir /usr/etc/skel/.local',\n"
        "    '^filesystem\\..*: hidden-file-or-dir /usr/etc/skel/.cache',\n"
        "    '^filesystem\\..*: hidden-file-or-dir /tmp/.X11-unix',\n"
        "    '^filesystem\\..*: hidden-file-or-dir /usr/etc/skel/.fonts',\n"
        ']\n'
    ), out
    assert len(added) == 1, added
    assert '/usr/etc/skel/.cache' in added[0], added


def test_add_filters_skips_line_upstream_now_ships():
    """A pattern already present in Filters is not duplicated: when
    upstream starts shipping the exemption itself, the insertion steps
    aside instead of emitting the line twice.
    """
    text = (
        'Filters = [\n'
        "    '^filesystem\\..*: hidden-file-or-dir /usr/etc/skel/.local',\n"
        "    '^filesystem\\..*: hidden-file-or-dir /usr/etc/skel/.cache',\n"
        ']\n'
    )
    added = []
    out = gen.add_filters(text, added)
    assert out == text, out
    assert added == [], added


def test_add_filters_missing_anchor_raises():
    """An anchor upstream reworded or dropped fails generation loudly:
    the exemption must never be silently stranded or land in the wrong
    place. Matching is byte-exact, so a trailing-space variant of the
    anchor does not count.
    """
    text = (
        'Filters = [\n'
        "    '^filesystem\\..*: hidden-file-or-dir /usr/etc/skel/.local ',\n"
        ']\n'
    )
    try:
        gen.add_filters(text, [])
    except AssertionError:
        return
    raise AssertionError("add_filters accepted a Filters list without the anchor")


def test_add_filters_ignores_blocked_filters():
    """The anchor is only honoured inside Filters: BlockedFilters
    entries are exact-match guards, so an anchor there does not count
    and the missing Filters anchor still raises.
    """
    text = (
        'BlockedFilters = [\n'
        "    '^filesystem\\..*: hidden-file-or-dir /usr/etc/skel/.local',\n"
        ']\n'
        'Filters = [\n'
        "    ' dangerous-command.*',\n"
        ']\n'
    )
    try:
        gen.add_filters(text, [])
    except AssertionError:
        return
    raise AssertionError("add_filters took the anchor from BlockedFilters")


def test_drop_live_filters_drops_kernel_modules_line():
    """The kernel-modules filter is dropped via DROP_LIVE_FILTERS.

    The check is config-gated off in both implementations
    (KernelModuleRPMsOK defaults to true), so the line can never match;
    the drop is unconditional \u2014 the finding staying in the tree is
    the point of this table, unlike PRUNE_CANDIDATES.
    """
    text = (
        'Filters = [\n'
        "    'kernel-modules-not-in-kernel-packages',\n"
        "    'unstripped-binary-or-object',\n"
        ']\n'
    )
    pruned, dropped, retargeted = [], [], []
    out = gen.prune_stale_filters(
        text, {"kernel-modules-not-in-kernel-packages"}, pruned, dropped, retargeted)
    assert 'kernel-modules-not-in-kernel-packages' not in out, out
    assert "    'unstripped-binary-or-object',\n" in out, out
    assert len(dropped) == 1, dropped
    assert 'kernel-modules-not-in-kernel-packages' in dropped[0], dropped
    assert pruned == [] and retargeted == [], (pruned, retargeted)
# ---------------------------------------------------------------------------
# assert_kept_filters: the recorded KEEP decisions survive regeneration
# ---------------------------------------------------------------------------

def _kept_config_text():
    """A synthetic opensuse.toml carrying every KEEP_FILTERS pattern."""
    lines = ["Filters = [\n"]
    for pattern in gen.KEEP_FILTERS:
        lines.append(f"    '{pattern}',\n")
    lines.append("]\n")
    return "".join(lines)


def test_keep_filters_table_is_the_ratified_set():
    """KEEP_FILTERS carries exactly the one surviving finding
    suppression (` prereq-use`) plus the 2 package-class filters."""
    assert set(gen.KEEP_FILTERS) == {
        " prereq-use",
        r"^qa\S+: [EWI]:",
        r"^\S*(?:INTERNAL|internal)\.\S+: [EWI]:",
    }


def test_assert_kept_filters_logs_every_survivor():
    kept = gen.assert_kept_filters(_kept_config_text())
    assert len(kept) == len(gen.KEEP_FILTERS), kept
    filters = [e for e in kept if e.startswith("Filters:")]
    assert len(filters) == len(gen.KEEP_FILTERS), kept


def test_assert_kept_filters_raises_and_names_the_missing():
    text = _kept_config_text().replace("    ' prereq-use',\n", "")
    try:
        gen.assert_kept_filters(text)
    except AssertionError as exc:
        assert " prereq-use" in str(exc), exc
    else:
        raise AssertionError("a missing kept pattern must raise")


def test_assert_kept_filters_substring_survival():
    """A kept pattern survives inside a broader scoped entry."""
    text = _kept_config_text().replace(
        "    ' prereq-use',\n",
        "    'somepkg prereq-use scoped',\n",
    )
    kept = gen.assert_kept_filters(text)
    assert any("prereq-use" in e for e in kept), kept


def test_assert_kept_filters_accepts_the_vendored_config():
    """The checked-in vendored config carries every kept pattern."""
    vendored = (
        os.path.join(os.path.dirname(HERE), "crates", "rpmcrab-core",
                     "data", "distro", "opensuse", "opensuse.toml")
    )
    with open(vendored, encoding="utf-8") as fh:
        kept = gen.assert_kept_filters(fh.read())
    assert len(kept) == len(gen.KEEP_FILTERS), kept


# ---------------------------------------------------------------------------
# scope_filters: bare entries narrowed to their recorded rationale
# ---------------------------------------------------------------------------

def test_scope_filters_rewrites_bare_entry():
    """The bare entry is replaced by its scoped form, in place, and logged.

    If the rewrite silently stopped firing (upstream rewords the line, the
    matcher stops recognising it), the vendored config would ship the
    blanket filter again with no trace — the log assertion guards that.
    """
    scoped, _reason = gen.SCOPE_FILTERS["no-ldconfig-symlink"]
    text = (
        "Filters = [\n"
        "    'use-tmp-in-',\n"
        "    'no-ldconfig-symlink',\n"
        "    'description-line-too-long',\n"
        "]\n"
    )
    log = []
    out = gen.scope_filters(text, log)
    assert f"    '{scoped}',\n" in out, out
    assert "'no-ldconfig-symlink',\n" not in out, out
    assert "'use-tmp-in-',\n" in out and "'description-line-too-long',\n" in out, out
    assert len(log) == 1 and "no-ldconfig-symlink" in log[0], log


def test_scope_filters_leaves_scoped_and_compound_entries_alone():
    """Only a line whose entire pattern is the bare entry is rewritten.

    An already-scoped entry or a compound pattern embedding the finding
    name expresses a different (already deliberate) scope; rewriting it
    would corrupt upstream's text.
    """
    text = (
        "Filters = [\n"
        "    'no-ldconfig-symlink /usr/lib/modules',\n"
        "    '.*no-ldconfig-symlink.*',\n"
        "]\n"
    )
    log = []
    out = gen.scope_filters(text, log)
    assert out == text, out
    assert log == [], log


def test_scope_filters_matches_whitespace_padded_bare_entry():
    """A bare entry padded inside its quotes still counts as the bare entry.

    The strip lives at this call site only: raw_filter_pattern itself
    stays byte-exact for prune_stale_filters' PRUNE_RAW matching.
    """
    scoped, _reason = gen.SCOPE_FILTERS["no-ldconfig-symlink"]
    text = (
        "Filters = [\n"
        "    ' no-ldconfig-symlink ',\n"
        "]\n"
    )
    log = []
    out = gen.scope_filters(text, log)
    assert f"    '{scoped}',\n" in out, out
    assert len(log) == 1 and "no-ldconfig-symlink" in log[0], log


def test_scope_filters_leaves_blocked_filters_and_other_lists_alone():
    """BlockedFilters and unrelated lists are never rewritten.

    BlockedFilters entries are matched by exact string equality, not as
    regex patterns, so rewriting one to the scoped pattern would make it
    unmatchable and silently drop the guard it names.
    """
    text = (
        "BlockedFilters = [\n"
        "    'no-ldconfig-symlink',\n"
        "]\n"
        "SomeOtherList = [\n"
        "    'no-ldconfig-symlink',\n"
        "]\n"
    )
    log = []
    out = gen.scope_filters(text, log)
    assert out == text, out
    assert log == [], log


def test_scope_filters_rewrites_bare_read_error_entry():
    """The bare read-error entry is replaced by its ENOENT-scoped form.

    Same guard as the ldconfig rewrite test: if the rewrite silently
    stopped firing (upstream rewords the line, the matcher stops
    recognising it), the vendored config would ship the blanket filter
    again with no trace — the log assertion guards that.
    """
    scoped, _reason = gen.SCOPE_FILTERS["read-error"]
    text = (
        "Filters = [\n"
        "    ' non-standard-dir-perm ',\n"
        "    ' read-error ',\n"
        "    ' non-readable ',\n"
        "]\n"
    )
    log = []
    out = gen.scope_filters(text, log)
    assert f"    '{scoped}',\n" in out, out
    assert "' read-error ',\n" not in out, out
    assert "' non-standard-dir-perm ',\n" in out, out
    assert "' non-readable ',\n" in out, out
    assert len(log) == 1 and "read-error" in log[0], log


def test_scope_filters_read_error_pattern_matches_enoent_detail_only():
    """The scoped read-error pattern keys on the ENOENT detail.

    The measured class (issue #579) is the bindir-shebang peek opening
    a symlink whose target is a %ghost placeholder: the rendered
    detail is the io::Error text 'No such file or directory
    (os error 2)'. A read failure with any other errno — what a
    genuine tool or package defect looks like — must NOT match, so
    it surfaces instead of being eaten by the narrowed filter.

    The level is not pinned to W: either: Filter::add_info promotes
    the level before building the match string, so under --strict or
    a [SeverityOverrides] entry the same ENOENT line renders with
    E: and must still match (the \w: convention the sibling
    no-ldconfig-symlink scoping already uses).
    """
    import re

    scoped, _reason = gen.SCOPE_FILTERS["read-error"]
    filtered = [
        "arptables.x86_64: W: read-error No such file or directory (os error 2)",
        "arptables.x86_64: E: read-error No such file or directory (os error 2)",
        "python313-impacket.noarch: W: read-error No such file or directory (os error 2)",
        "ca-certificates.noarch: W: read-error No such file or directory (os error 2)",
    ]
    visible = [
        "foo.x86_64: W: read-error Permission denied (os error 13)",
        "foo.x86_64: W: read-error Is a directory (os error 21)",
        "foo.x86_64: W: read-error Input/output error (os error 5)",
        "foo.x86_64: W: read-error Too many levels of symbolic links (os error 40)",
    ]
    for line in filtered:
        assert re.search(scoped, line), line
    for line in visible:
        assert not re.search(scoped, line), line


# ---------------------------------------------------------------------------
# scope_filters: bare entries narrowed to their recorded rationale
# ---------------------------------------------------------------------------

def test_scope_filters_rewrites_bare_entry_symlink():
    """The bare entry is replaced by its scoped form, in place, and logged.

    If the rewrite silently stopped firing (upstream rewords the line, the
    matcher stops recognising it), the vendored config would ship the
    blanket filter again with no trace \u2014 the log assertion guards that.
    """
    scoped, _reason = gen.SCOPE_FILTERS["symlink-should-be-relative"]
    text = (
        "Filters = [\n"
        "    'use-tmp-in-',\n"
        "    ' symlink-should-be-relative ',\n"
        "    'description-line-too-long',\n"
        "]\n"
    )
    log = []
    out = gen.scope_filters(text, log)
    assert f"    '{scoped}',\n" in out, out
    assert "' symlink-should-be-relative ',\n" not in out, out
    assert "'use-tmp-in-',\n" in out and "'description-line-too-long',\n" in out, out
    assert len(log) == 1 and "symlink-should-be-relative" in log[0], log


def test_scope_filters_leaves_scoped_and_compound_entries_alone_symlink():
    """Only a line whose entire pattern is the bare entry is rewritten.

    An already-scoped entry or a compound pattern embedding the finding
    name expresses a different (already deliberate) scope; rewriting it
    would corrupt upstream's text.
    """
    text = (
        "Filters = [\n"
        "    'symlink-should-be-relative /usr/lib/modules',\n"
        "    '.*symlink-should-be-relative.*',\n"
        "]\n"
    )
    log = []
    out = gen.scope_filters(text, log)
    assert out == text, out
    assert log == [], log


def test_scope_filters_matches_unpadded_bare_entry():
    """The bare entry without padding inside its quotes is rewritten too.

    raw_filter_pattern keeps the pattern byte-exact for PRUNE_RAW; the
    strip that makes padded and unpadded forms equivalent lives in
    scope_filters only.
    """
    scoped, _reason = gen.SCOPE_FILTERS["symlink-should-be-relative"]
    text = (
        "Filters = [\n"
        "    'symlink-should-be-relative',\n"
        "]\n"
    )
    log = []
    out = gen.scope_filters(text, log)
    assert f"    '{scoped}',\n" in out, out
    assert len(log) == 1 and "symlink-should-be-relative" in log[0], log


def test_scope_filters_leaves_blocked_filters_and_other_lists_alone_symlink():
    """BlockedFilters and unrelated lists are never rewritten.

    BlockedFilters entries are matched by exact string equality, not as
    regex patterns, so rewriting one to the scoped pattern would make it
    unmatchable and silently drop the guard it names.
    """
    text = (
        "BlockedFilters = [\n"
        "    ' symlink-should-be-relative ',\n"
        "]\n"
        "SomeOtherList = [\n"
        "    ' symlink-should-be-relative ',\n"
        "]\n"
    )
    log = []
    out = gen.scope_filters(text, log)
    assert out == text, out
    assert log == [], log


def test_scope_filters_scoped_pattern_matches_alternatives_targets_only():
    """The scoped pattern matches the rendered line by its target argument.

    The scope is the finding's second path (the link target), not the
    package name or the link location: alternatives endpoints stay
    filtered wherever they are shipped from, and a hand-authored link
    anywhere else \u2014 including a link that itself lives under
    /etc/alternatives but points out of it \u2014 surfaces.
    """
    import re

    scoped, _reason = gen.SCOPE_FILTERS["symlink-should-be-relative"]
    filtered = [
        "python313-impacket.noarch: W: symlink-should-be-relative "
        "/usr/bin/impacket-GetADUsers /etc/alternatives/impacket-GetADUsers",
        "python313-csvkit.noarch: W: symlink-should-be-relative "
        "/usr/share/man/man1/csvlook.1.gz /etc/alternatives/csvlook.1.gz",
    ]
    visible = [
        "gavl.x86_64: W: symlink-should-be-relative "
        "/usr/share/licenses/gavl/COPYING /usr/share/automake-1.18/COPYING",
        "texlive-scripts-bin.x86_64: W: symlink-should-be-relative "
        "/usr/bin/texhash /usr/libexec/mktex/public",
        "cloud-netconfig-azure.noarch: W: symlink-should-be-relative "
        "/etc/udev/rules.d/75-persistent-net-generator.rules /dev/null",
        "foo.x86_64: W: symlink-should-be-relative "
        "/etc/alternatives/editor /usr/bin/vim",
    ]
    for line in filtered:
        assert re.search(scoped, line), line
    for line in visible:
        assert not re.search(scoped, line), line


def test_dedupe_filters_drops_exact_duplicates():
    """Byte-identical Filters lines collapse to the first occurrence.

    Upstream's filesystem exception block repeats the var-run/var-lock
    and .gnupg lines; the filter engine suppresses on ANY match, so the
    repeats can never change an outcome. Everything else — including the
    first occurrences and unrelated lines — survives byte-identical and
    in place.
    """
    text = (
        'Filters = [\n'
        "    '^filesystem\\..*: dir-or-file-in-var-run',\n"
        "    '^filesystem\\..*: dir-or-file-in-var-lock',\n"
        "    '^filesystem\\..*: dir-or-file-in-var-tmp',\n"
        "    '^filesystem\\..*: dir-or-file-in-var-run',\n"
        "    '^filesystem\\..*: dir-or-file-in-var-lock',\n"
        "    '^filesystem\\..*: hidden-file-or-dir /root/.gnupg',\n"
        "    '^filesystem\\..*: hidden-file-or-dir /root/.gnupg',\n"
        "    ' dangerous-command.*',\n"
        ']\n'
    )
    deduped = []
    out = gen.dedupe_filters(text, deduped)
    assert out == (
        'Filters = [\n'
        "    '^filesystem\\..*: dir-or-file-in-var-run',\n"
        "    '^filesystem\\..*: dir-or-file-in-var-lock',\n"
        "    '^filesystem\\..*: dir-or-file-in-var-tmp',\n"
        "    '^filesystem\\..*: hidden-file-or-dir /root/.gnupg',\n"
        "    ' dangerous-command.*',\n"
        ']\n'
    ), out
    assert len(deduped) == 3, deduped
    assert all('duplicate' in entry for entry in deduped), deduped


def test_dedupe_filters_drops_subsumed_literal():
    """The narrower prereq-use line is dropped, the broader kept.

    Both lines are plain literals naming the same finding, and
    ' prereq-use ' strictly contains ' prereq-use': every rendered line
    the narrower pattern matches also matches the broader one, so the
    narrower line suppresses nothing the broader does not. Dropping the
    broader instead would unfilter findings whose tag ends the line —
    this test fails if the direction is ever inverted.
    """
    text = (
        'Filters = [\n'
        "    ' prereq-use',\n"
        "    ' file-not-utf8',\n"
        "    ' prereq-use ',\n"
        ']\n'
    )
    deduped = []
    out = gen.dedupe_filters(text, deduped)
    assert out == (
        'Filters = [\n'
        "    ' prereq-use',\n"
        "    ' file-not-utf8',\n"
        ']\n'
    ), out
    assert len(deduped) == 1, deduped
    assert "' prereq-use '" in deduped[0], deduped
    assert "' prereq-use'" in deduped[0], deduped


def test_dedupe_filters_keeps_scoped_and_regex_lines():
    """Subsumption never touches compound scopes or regex patterns.

    'ibcs2 non-standard-dir-in-usr ...' textually contains the blanket
    ' non-standard-dir-in-usr ' literal, but it is a package-scoped
    exception, not the bare finding: dropping it would erase the
    recorded per-package exception for if the blanket line is ever
    revisited. Literals naming different findings and regex patterns
    whose text contains another pattern are likewise kept.
    """
    text = (
        'Filters = [\n'
        "    ' non-standard-dir-in-usr ',  # handled by CheckFilelist.py\n"
        "    'ibcs2 non-standard-dir-in-usr i486-sysv4',\n"
        "    'shlibs5 non-standard-dir-in-usr i486-linux-libc5',\n"
        "    ' prereq-use',\n"
        "    ' file-not-utf8',\n"
        "    '.*file-not-utf8.*',\n"
        ']\n'
    )
    deduped = []
    out = gen.dedupe_filters(text, deduped)
    assert out == text, out
    assert deduped == [], deduped


def test_dedupe_filters_idempotent():
    """A second dedupe pass over the output drops nothing.

    --check regenerates from upstream each time, but the vendored files
    are also the input to by-hand verification of the filter passes;
    a non-idempotent step would make the checked-in files unstable
    under re-application.
    """
    text = (
        'Filters = [\n'
        "    '^filesystem\\..*: dir-or-file-in-var-run',\n"
        "    '^filesystem\\..*: dir-or-file-in-var-run',\n"
        "    ' prereq-use',\n"
        "    ' prereq-use ',\n"
        ']\n'
    )
    once = gen.dedupe_filters(text, [])
    deduped = []
    twice = gen.dedupe_filters(once, deduped)
    assert twice == once, twice
    assert deduped == [], deduped


def test_dedupe_filters_ignores_blocked_filters():
    """BlockedFilters is never deduped: its entries are matched as exact
    finding names, not patterns, so 'permissions-incorrect' does not
    cover 'permissions-incorrect-owner' and a repeated name is a set
    member, not a redundant regex. Pattern rules must not leak across.
    """
    text = (
        'BlockedFilters = [\n'
        "    'permissions-incorrect',\n"
        "    'permissions-incorrect-owner',\n"
        "    'permissions-incorrect',\n"
        ']\n'
        'Filters = [\n'
        "    'permissions-incorrect',\n"
        ']\n'
    )
    deduped = []
    out = gen.dedupe_filters(text, deduped)
    assert out == text, out
    assert deduped == [], deduped


def test_retarget_filters_spells_crontabs_tag_in_full():
    """The missing-dependency-to-cron pattern is rewritten to the plural
    tag the check emits; the singular only ever matched as a substring
    prefix of it. A reworded (double-space) line is not rewritten —
    byte-exact matching surfaces it for a fresh audit instead.
    """
    text = (
        'Filters = [\n'
        "    '^filesystem\\..*: missing-dependency-to-cron',\n"
        "    '^filesystem\\..*:  missing-dependency-to-cron',\n"
        ']\n'
    )
    pruned, dropped, retargeted = [], [], []
    out = gen.prune_stale_filters(text, set(), pruned, dropped, retargeted)
    assert "'^filesystem\\..*: missing-dependency-to-crontabs'," in out, out
    assert "'^filesystem\\..*:  missing-dependency-to-cron'," in out, out
    assert len(retargeted) == 1, retargeted
    assert 'missing-dependency-to-crontabs' in retargeted[0], retargeted
def test_drop_live_filters_drops_executable_config_line():
    """The executable-marked-as-config-file filter is dropped via
    DROP_LIVE_FILTERS (ruling in issue #557).

    The vendored line carries a leading space (' executable-...'):
    pure_finding_pattern strips it, and the drop is unconditional --
    the finding becoming visible is the point of this table.
    """
    text = (
        'Filters = [\n'
        "    ' executable-marked-as-config-file',\n"
        "    'unstripped-binary-or-object',\n"
        ']\n'
    )
    pruned, dropped, retargeted = [], [], []
    out = gen.prune_stale_filters(
        text, {"executable-marked-as-config-file"}, pruned, dropped, retargeted)
    assert 'executable-marked-as-config-file' not in out, out
    assert "    'unstripped-binary-or-object',\n" in out, out
    assert len(dropped) == 1, dropped
    assert 'executable-marked-as-config-file' in dropped[0], dropped
    assert pruned == [] and retargeted == [], (pruned, retargeted)

def test_drop_live_filters_drops_description_line_too_long_line():
    """The description-line-too-long filter is dropped via
    DROP_LIVE_FILTERS (ruling in issue #578).

    The bare line sits in upstream's bnc#456048 kernel-module block,
    but the KMP class measures empty on the Factory corpus (14 prose
    lines, none from the actual *-kmp srcpkgs); the drop is
    unconditional -- the 5,089 genuine findings becoming visible is
    the point of this table.
    """
    text = (
        'Filters = [\n'
        "    'description-line-too-long',\n"
        "    'unstripped-binary-or-object',\n"
        ']\n'
    )
    pruned, dropped, retargeted = [], [], []
    out = gen.prune_stale_filters(
        text, {"description-line-too-long"}, pruned, dropped, retargeted)
    assert 'description-line-too-long' not in out, out
    assert "    'unstripped-binary-or-object',\n" in out, out
    assert len(dropped) == 1, dropped
    assert 'description-line-too-long' in dropped[0], dropped
    assert pruned == [] and retargeted == [], (pruned, retargeted)

def test_drop_live_filters_drops_usr_local_line():
    """The dir-or-file-in-usr-local filter is dropped via
    DROP_LIVE_FILTERS (ruling in issue #583).

    The check is a port of FilesCheck with a measured misfire
    rate of 0/45 on the Factory corpus; the suppressed set is
    two deliberate carriers (filesystem's %ghost /usr/local
    skeleton tree, reproducible-faketools' /usr/local/bin
    PATH-shadowing wrappers) whose exceptions belong in per-package
    rpmlintrc. The drop is unconditional -- the findings becoming
    visible is the point of this table; since the %ghost exemption
    (issue #643) only reproducible-faketools' 25 real-payload
    lines still fire (issue #654). The line under test is
    upstream's verbatim shape, padding and fossil comment
    included.
    """
    text = (
        'Filters = [\n'
        "    ' dir-or-file-in-usr-local ',  # handled by CheckFilelist.py\n"
        "    'unstripped-binary-or-object',\n"
        ']\n'
    )
    pruned, dropped, retargeted = [], [], []
    out = gen.prune_stale_filters(
        text, {"dir-or-file-in-usr-local"}, pruned, dropped, retargeted)
    assert 'dir-or-file-in-usr-local' not in out, out
    assert "    'unstripped-binary-or-object',\n" in out, out
    assert len(dropped) == 1, dropped
    assert 'dir-or-file-in-usr-local' in dropped[0], dropped
    assert pruned == [] and retargeted == [], (pruned, retargeted)


def test_drop_live_filters_drops_non_standard_dir_in_usr_line():
    """The non-standard-dir-in-usr filter is dropped via
    DROP_LIVE_FILTERS (ruling in issue #582).

    The FHSCheck fix whitelists the sanctioned /usr directories in
    the check itself (/usr/etc, the MinGW sysroots, X11R6 and the
    measured cross-toolchain target sysroots), so the blanket's
    measured set is sanctioned practice at the source and what the
    tag can still fire on -- a genuinely novel /usr top-level
    directory -- fires unsuppressed. The drop is unconditional.
    The line under test is upstream's verbatim shape, padding and
    fossil comment included; the three dormant scoped exceptions
    for the same finding are separate deliberate keeps and must
    survive untouched. The fixture's dir-or-file-in-usr-local line
    is dropped as well (issue #583 added it to the same table), so
    it is asserted gone, with both drops logged.
    """
    text = (
        'Filters = [\n'
        "    ' dir-or-file-in-usr-local ',  # handled by CheckFilelist.py\n"
        "    ' non-standard-dir-in-usr ',  # handled by CheckFilelist.py\n"
        "    'non-standard-dir-in-usr openwin',\n"
        "    'ibcs2 non-standard-dir-in-usr i486-sysv4',\n"
        "    'shlibs5 non-standard-dir-in-usr i486-linux-libc5',\n"
        ']\n'
    )
    pruned, dropped, retargeted = [], [], []
    out = gen.prune_stale_filters(
        text, {"non-standard-dir-in-usr"}, pruned, dropped, retargeted)
    assert "    ' non-standard-dir-in-usr ',  #" not in out, out
    assert "    ' dir-or-file-in-usr-local ',  # handled by CheckFilelist.py\n" not in out, out
    assert "    'non-standard-dir-in-usr openwin',\n" in out, out
    assert "    'ibcs2 non-standard-dir-in-usr i486-sysv4',\n" in out, out
    assert "    'shlibs5 non-standard-dir-in-usr i486-linux-libc5',\n" in out, out
    assert len(dropped) == 2, dropped
    assert 'dir-or-file-in-usr-local' in dropped[0], dropped
    assert 'non-standard-dir-in-usr' in dropped[1], dropped
    assert pruned == [] and retargeted == [], (pruned, retargeted)


# ---------------------------------------------------------------------------
# strip_badness_threshold / no vendored scoring (issue #699)
# ---------------------------------------------------------------------------

def test_drop_live_filters_drops_fsf_address_line():
    """The incorrect-fsf-address blanket filter is dropped via
    DROP_LIVE_FILTERS (ruling in issue #883).

    The vendored line is space-anchored on both sides
    (' incorrect-fsf-address '): pure_finding_pattern strips the
    padding, and the drop is unconditional. The scoped sibling under
    the same upstream comment is a compound pattern and stays, so
    the comment block heading both stays too.
    """
    text = (
        'Filters = [\n'
        "# Too noisy, and usually not something downstream packagers can fix\n"
        "    ' incorrect-fsf-address ',\n"
        "    ' static-library-without-debuginfo /usr/lib(?:64)?/ghc-[\\d.]+/',\n"
        ']\n'
    )
    pruned, dropped, retargeted = [], [], []
    out = gen.prune_stale_filters(
        text, {"incorrect-fsf-address"}, pruned, dropped, retargeted)
    assert 'incorrect-fsf-address' not in out, out
    assert 'static-library-without-debuginfo' in out, out
    assert '# Too noisy' in out, out
    assert len(dropped) == 1, dropped
    assert 'incorrect-fsf-address' in dropped[0], dropped
    assert pruned == [] and retargeted == [], (pruned, retargeted)


def test_drop_live_filters_drops_dangerous_command_family_line():
    """The dangerous-command family filter is dropped via
    DROP_LIVE_FILTERS (ruling in issue #883).

    The vendored line is a pattern, not a name: ' dangerous-command.*'
    hides the whole dangerous-command-in-%<section> family.
    pure_finding_pattern strips the trailing '.*' and returns the
    stem 'dangerous-command', which is the DROP key. A compound line
    naming one section stays: the drop takes the blanket only.
    """
    text = (
        'Filters = [\n'
        "    ' dangerous-command.*',\n"
        "    'somepkg\\..*: dangerous-command-in-%post /bin/rm',\n"
        "    'unstripped-binary-or-object',\n"
        ']\n'
    )
    pruned, dropped, retargeted = [], [], []
    out = gen.prune_stale_filters(
        text, {"dangerous-command"}, pruned, dropped, retargeted)
    assert ' dangerous-command.*' not in out, out
    assert 'dangerous-command-in-%post' in out, out
    assert 'unstripped-binary-or-object' in out, out
    assert len(dropped) == 1, dropped
    assert 'dangerous-command' in dropped[0], dropped
    assert pruned == [] and retargeted == [], (pruned, retargeted)


def test_strip_badness_threshold_drops_only_the_key_line():
    """The BadnessThreshold line goes; every other line survives
    byte-exact, and the removal is logged for the provenance."""
    text = "Version = 3\nBadnessThreshold = 999\nFlavor = \"opensuse\"\n"
    log = []
    out = gen.strip_badness_threshold(text, "opensuse", log)
    assert out == "Version = 3\nFlavor = \"opensuse\"\n", out
    assert len(log) == 1 and "999" in log[0] and "opensuse" in log[0], log


def test_strip_badness_threshold_is_idempotent():
    text = "BadnessThreshold = 999\nVersion = 3\n"
    once = gen.strip_badness_threshold(text, "opensuse", [])
    twice = gen.strip_badness_threshold(once, "opensuse", [])
    assert once == twice == "Version = 3\n", (once, twice)


def test_scoring_is_not_vendored():
    """No [Scoring] table ships (issue #699): neither upstream's
    scoring.toml nor the rpmlint-strict layer is in the bundle, so no
    shipped config can promote or demote a finding's level."""
    for flavor, files in gen.FILES.items():
        assert "scoring.toml" not in files, (flavor, files)
        assert "scoring-strict.override.toml" not in files, (flavor, files)


def test_append_systemd_preset_packages_before_first_table_after_blank_line():
    """The key lands at the end of the preamble, before the first table.

    At the end of the document it would fall inside the trailing
    [Descriptions] table and never reach the check. A blank line already
    before the header separates the inserted block, so the block's own
    leading blank line is dropped: exactly one blank line remains.
    """
    text = 'Version = 3\n\n[Descriptions]\nfoo = "x"\n'
    out = gen.append_systemd_preset_packages(text, ["a", "b"])
    assert out == (
        'Version = 3\n'
        '\n'
        '# Packages allowed to ship systemd preset files (not from upstream;\n'
        '# see SYSTEMD_PRESET_PACKAGES in scripts/generate-distro-configs.py).\n'
        'SystemdPresetPackages = [\n'
        '    "a",\n'
        '    "b",\n'
        ']\n'
        '[Descriptions]\n'
        'foo = "x"\n'
    ), out


def test_append_systemd_preset_packages_before_first_table_without_blank_line():
    """No blank line before the header: the block brings its own, so the
    key still starts a fresh paragraph instead of gluing onto the last
    preamble line."""
    text = 'Version = 3\n[Descriptions]\n'
    out = gen.append_systemd_preset_packages(text, ["a"])
    assert out == (
        'Version = 3\n'
        '\n'
        '# Packages allowed to ship systemd preset files (not from upstream;\n'
        '# see SYSTEMD_PRESET_PACKAGES in scripts/generate-distro-configs.py).\n'
        'SystemdPresetPackages = [\n'
        '    "a",\n'
        ']\n'
        '[Descriptions]\n'
    ), out


def test_append_systemd_preset_packages_appends_at_eof_without_table():
    """A document with no table header gets the block at the end, and a
    missing trailing newline at EOF is supplied first."""
    block = (
        '\n'
        '# Packages allowed to ship systemd preset files (not from upstream;\n'
        '# see SYSTEMD_PRESET_PACKAGES in scripts/generate-distro-configs.py).\n'
        'SystemdPresetPackages = [\n'
        '    "a",\n'
        ']\n'
    )
    assert gen.append_systemd_preset_packages('Version = 3\n', ["a"]) == 'Version = 3\n' + block
    assert gen.append_systemd_preset_packages('Version = 3', ["a"]) == 'Version = 3\n' + block



def test_extra_filters_carry_their_provenance_reasons():
    """Each EXTRA_FILTERS entry pairs its pattern with the
    reason the generator logs for it in PROVENANCE: the mingw entries
    keep their rpmlintrc attribution."""
    reasons = dict(gen.EXTRA_FILTERS)
    assert len(reasons) == len(gen.EXTRA_FILTERS)
    for pattern, reason in gen.EXTRA_FILTERS:
        assert pattern and reason, (pattern, reason)
    mingw_reasons = [
        reason
        for pattern, reason in gen.EXTRA_FILTERS
        if pattern.startswith("^mingw")
    ]
    assert mingw_reasons == ["mingw -filesystem packages' rpmlintrc"] * 2, mingw_reasons


def test_apply_digest_adjudications_rewrites_cups_record():
    """The Factory-adjudicated cups.conf record replaces the stale hash.

    Pins the vendored stanza shape the function walks:
    [[FileDigestGroup.digests]] sub-tables with path/hash lines.
    """
    text = (
        '[[FileDigestGroup]]\n'
        'package = "cups"\n'
        'type = "dbus"\n'
        '[[FileDigestGroup.digests]]\n'
        'path = "/usr/share/dbus-1/system.d/cups.conf"\n'
        'hash = "013f81b330170be3629bae66b26828beb6a6e7885c0f00e50c971acc1816a0d7"\n'
        'digester = "xml"\n'
        '\n'
        '[[FileDigestGroup]]\n'
        'package = "upower"\n'
        'type = "dbus"\n'
        '[[FileDigestGroup.digests]]\n'
        'path = "/usr/share/dbus-1/system.d/org.freedesktop.UPower.conf"\n'
        'hash = "aaaa"\n'
        'digester = "xml"\n'
    )
    out, log = gen.apply_digest_adjudications(text, "dbus-services.toml")
    assert "1bbed8c1ecac00e546a3659235855aa2e88ec1142b3908b3d662e68ad4e664fe" in out, out
    assert "013f81b330170be3" not in out, out
    assert 'hash = "aaaa"' in out, out  # other records untouched
    assert len(log) == 1 and "cups" in log[0], log
    # Idempotent, and a no-op for files without adjudicated records.
    out2, log2 = gen.apply_digest_adjudications(out, "dbus-services.toml")
    assert out2 == out and log2 == [], (out2, log2)
    out3, log3 = gen.apply_digest_adjudications(text, "sysctl-whitelist.toml")
    assert out3 == text and log3 == [], (out3, log3)


# ---------------------------------------------------------------------------
# fetch exhaustion: a dedicated exit code, never confused with drift
# ---------------------------------------------------------------------------

def test_fetch_github_5xx_raises_fetch_exhausted():
    """A GitHub 5xx is an upstream outage: FetchExhausted, so --check
    reports it as infrastructure instead of failing."""
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=_http_error(503)):
        try:
            gen.fetch_github("0" * 40, "opensuse.toml")
        except gen.FetchExhausted as e:
            assert "503" in str(e), str(e)
        else:
            raise AssertionError("GitHub 503 did not raise FetchExhausted")


def test_fetch_github_urlerror_raises_fetch_exhausted():
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=urllib.error.URLError("no route")):
        try:
            gen.fetch_github("0" * 40, "opensuse.toml")
        except gen.FetchExhausted:
            pass
        else:
            raise AssertionError("GitHub URLError did not raise FetchExhausted")


def test_fetch_github_4xx_raises_http_error():
    """A 404 for a pinned file is deterministic (the pin is wrong): the
    raw HTTPError propagates, never FetchExhausted."""
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=_http_error(404)):
        try:
            gen.fetch_github("0" * 40, "opensuse.toml")
        except urllib.error.HTTPError as e:
            assert e.code == 404, e.code
        else:
            raise AssertionError("GitHub 404 did not raise")


def test_fetch_github_429_and_408_raise_fetch_exhausted():
    """GitHub rate limiting (429) and a server-side request timeout
    (408) are transient upstream conditions, like a 5xx: FetchExhausted,
    never a raw HTTPError that would fail the run as drift."""
    for code in (429, 408):
        with mock.patch.object(gen.urllib.request, "urlopen",
                               side_effect=_http_error(code)):
            try:
                gen.fetch_github("0" * 40, "opensuse.toml")
            except gen.FetchExhausted as e:
                assert str(code) in str(e), str(e)
            else:
                raise AssertionError(
                    "GitHub %d did not raise FetchExhausted" % code)


def test_fetch_github_transient_errors_raise_fetch_exhausted():
    """Every type in the shared transient tuple maps to FetchExhausted
    on the GitHub path, including the ones raised mid-response
    (SSLError, BadStatusLine) and at connect time (refused/aborted,
    broken pipe)."""
    import http.client
    import ssl
    transient = [
        ConnectionRefusedError("refused"),
        ConnectionAbortedError("aborted"),
        BrokenPipeError("broken pipe"),
        ssl.SSLError("ssl error"),
        http.client.BadStatusLine("bad status line"),
    ]
    for err in transient:
        with mock.patch.object(gen.urllib.request, "urlopen",
                               side_effect=err):
            try:
                gen.fetch_github("0" * 40, "opensuse.toml")
            except gen.FetchExhausted:
                pass
            else:
                raise AssertionError(
                    "GitHub %r did not raise FetchExhausted" % (err,))


def test_package_present_obs_429_raises_fetch_exhausted():
    """A rate-limited OBS source API leaves presence unverifiable:
    FetchExhausted, like a 5xx."""
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=_http_error(429)):
        try:
            gen.package_present("rate-limited-probe")
        except gen.FetchExhausted as e:
            assert "429" in str(e), str(e)
        else:
            raise AssertionError("OBS 429 did not raise FetchExhausted")


def test_repomd_429_is_retried_then_succeeds():
    """A 429 from a mirror is transient for the repomd loop too: the
    attempt is recorded and retried, not raised as a client error."""
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=[_http_error(429),
                                        _repomd_response()]), \
            mock.patch.object(gen.time, "sleep"):
        assert "repomd" in gen._fetch_repomd_xml(
            "http://r/repomd.xml", "probe")


def test_repomd_429_exhausts_to_fetch_exhausted():
    """A mirror that keeps answering 429 spends the retry budget and
    ends at FetchExhausted."""
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=_http_error(429)), \
            mock.patch.object(gen.time, "sleep"):
        try:
            gen._fetch_repomd_xml("http://r/repomd.xml", "probe")
        except gen.FetchExhausted as e:
            assert "429" in str(e), str(e)
        else:
            raise AssertionError("repomd 429 did not raise FetchExhausted")


def test_package_present_obs_5xx_raises_fetch_exhausted():
    """An OBS source API 503 leaves presence unverifiable: FetchExhausted
    instead of a raw traceback or a silent 'absent'."""
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=_http_error(503)):
        try:
            gen.package_present("fetch-exhausted-probe")
        except gen.FetchExhausted as e:
            assert "503" in str(e), str(e)
        else:
            raise AssertionError("OBS 503 did not raise FetchExhausted")


def test_package_present_obs_404_uses_repodata():
    """A 404 from the source API still means 'check the binary repodata':
    presence there counts, absence everywhere is a plain False."""
    with mock.patch.object(gen.urllib.request, "urlopen",
                           side_effect=_http_error(404)), \
            mock.patch.object(gen, "_tw_binary_names",
                              return_value={"present-in-repodata-probe"}):
        assert gen.package_present("present-in-repodata-probe") is True
        assert gen.package_present("absent-everywhere-probe") is False


def _run_main_check(side_effect=None, return_value=None):
    """Run main() --check with generate() stubbed; return (rc, stderr)."""
    import contextlib
    import io

    err = io.StringIO()
    with mock.patch.object(sys, "argv",
                           ["generate-distro-configs.py", "--check"]), \
            mock.patch.object(gen, "generate", side_effect=side_effect,
                              return_value=return_value), \
            contextlib.redirect_stderr(err), \
            contextlib.redirect_stdout(io.StringIO()):
        rc = gen.main()
    return rc, err.getvalue()


def test_main_fetch_exhausted_returns_dedicated_code():
    """An exhausted upstream fetch exits EXIT_FETCH_EXHAUSTED with the
    fetch-exhausted marker on stderr, so the drift job can map the run
    to neutral."""
    rc, err = _run_main_check(
        side_effect=gen.FetchExhausted("upstream is down"))
    assert rc == gen.EXIT_FETCH_EXHAUSTED, rc
    assert rc not in (0, 1, 2), rc
    assert "fetch-exhausted:" in err, err
    assert "upstream is down" in err, err


def test_main_other_errors_are_not_neutral():
    """Only FetchExhausted takes the neutral path: a RuntimeError (local
    error, malformed data) or a GrepError (deterministic pipeline
    failure) inside generate() propagates and fails as before."""
    for boom in (RuntimeError("local boom"), gen.GrepError("grep rc=2")):
        try:
            _run_main_check(side_effect=boom)
        except type(boom) as e:
            assert e is boom, e
        else:
            raise AssertionError("%r did not propagate" % (boom,))


def _generate_return(provenance):
    empty = []
    return (
        {},
        provenance,
        empty, empty, empty,
        list(gen.FILES["opensuse"]),
        empty, empty, empty, empty, empty, empty, empty,
    )


def test_main_check_clean_returns_zero():
    """A generation matching the vendored files exits 0."""
    provenance = (gen.DISTRO_DIR / "PROVENANCE").read_text(encoding="utf-8")
    rc, err = _run_main_check(return_value=_generate_return(provenance))
    assert rc == 0, (rc, err)


def test_main_check_drift_returns_one():
    """A generation differing from the vendored files exits 1 - drift,
    never the fetch-exhausted code."""
    provenance = (gen.DISTRO_DIR / "PROVENANCE").read_text(encoding="utf-8")
    ret = list(_generate_return(provenance))
    ret[1] = provenance + "\n# tampered provenance\n"
    rc, err = _run_main_check(return_value=tuple(ret))
    assert rc == 1, (rc, err)
    assert "drift: PROVENANCE" in err, err


if __name__ == "__main__":
    sys.exit(main())
