"""Agent-side Layer-A locks for the OpenPhish primitive (#275).

FEED-1/PERM-8: _check_openphish matches on URL HOST equality/suffix, not a raw
substring — a structure-only candidate sharing a substring with an unrelated feed
URL is no longer phantom-promoted to HIGH.
FEED-3: a feed download failure does not serve an empty 'clean' cache for the
full hour; it returns feed_available=False (UNSWEPT) and re-fetches.
FEED-5: _check_openphish returns the matched URL as analyst evidence.

Fictitious brand only (lumenfield.test / sol.test).
"""

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.typosquat_detect import TyposquatDetectTool


def _seed_cache(tool, urls):
    tool._openphish_cache = set(urls)
    tool._openphish_cache_time = time.time()


class TestOpenphishHostMatch:
    def setup_method(self):
        self.tool = TyposquatDetectTool()

    def test_substring_in_unrelated_url_does_not_match(self):
        # FEED-1/PERM-8: the brand appears only as a substring (a query-param
        # value) of an UNRELATED feed URL whose host is evil.test.
        _seed_cache(self.tool, ['http://evil.test/login?next=lumenfield.test'])
        matched, available = asyncio.run(self.tool._check_openphish('lumenfield.test'))
        assert matched is None
        assert available is True

    def test_host_equality_matches_and_returns_url(self):
        url = 'http://lumenfield.test/secure/login'
        _seed_cache(self.tool, [url])
        matched, available = asyncio.run(self.tool._check_openphish('lumenfield.test'))
        assert matched == url      # FEED-5 evidence
        assert available is True

    def test_subdomain_suffix_matches(self):
        url = 'https://secure.lumenfield.test/x'
        _seed_cache(self.tool, [url])
        matched, _ = asyncio.run(self.tool._check_openphish('lumenfield.test'))
        assert matched == url

    def test_unrelated_host_no_match(self):
        _seed_cache(self.tool, ['http://sol.test/login'])
        matched, _ = asyncio.run(self.tool._check_openphish('lumenfield.test'))
        assert matched is None


class TestOpenphishCacheHonesty:
    def setup_method(self):
        self.tool = TyposquatDetectTool()
        self._orig = asyncio.create_subprocess_exec

    def teardown_method(self):
        asyncio.create_subprocess_exec = self._orig

    def test_download_failure_no_prior_cache_is_unavailable_not_clean(self, monkeypatch):
        async def boom(*a, **k):
            raise RuntimeError('curl failed')

        monkeypatch.setattr(asyncio, 'create_subprocess_exec', boom)
        feed, available = asyncio.run(self.tool._load_openphish_feed())
        assert feed == set()
        assert available is False
        # FEED-3 — the empty result is NOT cached under the 1h TTL.
        assert self.tool._openphish_cache is None
        # _check_openphish then reports UNSWEPT, not clean.
        matched, avail = asyncio.run(self.tool._check_openphish('lumenfield.test'))
        assert matched is None and avail is False

    def test_empty_body_is_not_cached_clean(self, monkeypatch):
        # FEED-3 — curl SUCCEEDS but returns an empty body (rate-limit/empty page):
        # must be treated as a failure, NOT cached as an empty 'clean' feed.
        class _FakeProc:
            async def communicate(self):
                return (b'', b'')

        async def fake_exec(*a, **k):
            return _FakeProc()

        monkeypatch.setattr(asyncio, 'create_subprocess_exec', fake_exec)
        feed, available = asyncio.run(self.tool._load_openphish_feed())
        assert feed == set()
        assert available is False
        assert self.tool._openphish_cache is None  # not poisoned with empty-clean

    def test_download_failure_serves_prior_good_cache_stale(self, monkeypatch):
        # Prior good cache exists but is past TTL; a failed re-fetch serves it
        # stale-but-good rather than going dark.
        self.tool._openphish_cache = {'http://lumenfield.test/login'}
        self.tool._openphish_cache_time = time.time() - 4000  # expired

        async def boom(*a, **k):
            raise RuntimeError('curl failed')

        monkeypatch.setattr(asyncio, 'create_subprocess_exec', boom)
        feed, available = asyncio.run(self.tool._load_openphish_feed())
        assert 'http://lumenfield.test/login' in feed
        assert available is True
