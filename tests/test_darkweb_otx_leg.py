"""Agent-side Layer-A lock for the OTX feed leg (#1621).

Two defects, one lock:

1. TUPLE UNPACK. `upstream_request` returns `(response, meta)`
   (`agent/lib/integration_credentials.py`), and every other caller in the tree
   unpacks it. `_query_otx` bound the tuple to a bare `resp` and then read
   `resp.status` / `resp.json()` / `resp.release()`, so the FIRST statement after
   the await raised `AttributeError: 'tuple' object has no attribute 'status'`
   straight into the leg's broad `except Exception`. The leg returned `[]` for
   every input — 100% dark.

2. NO SOURCE STATUS. `_query_otx` was the only feed leg that never called
   `_mark_source_status`, so that total blindness was byte-identical, on the
   tool output, to a genuinely clean sweep (FEED-2 / HONESTY-1). Sibling legs
   (`_query_urlhaus`, `_query_threatfox`, `_query_pastebin`, `_query_cavalier`)
   have recorded a per-source status for exactly this reason.

The leg is dormant on `ENABLE_OTX=false` (the default), which is why this never
surfaced — but `ENABLE_OTX=true` reads like a safe ops toggle. `ENABLE_OTX` is a
module-level constant read at IMPORT time, so these tests patch the module
attribute rather than the environment.

Drives the REAL `_query_otx` through the REAL `upstream_request` against a
mocked aiohttp session, so the (response, meta) contract is genuinely exercised
rather than mocked away. Fictitious brand only (sol.test).
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import tools.darkweb_monitor as td
from tools.darkweb_monitor import DarkWebMonitorTool

DOMAIN = 'sol.test'

PULSES = {
    'pulse_info': {
        'pulses': [
            {
                'id': 'pulse-1',
                'name': 'Credential phishing kit targeting sol.test',
                'description': 'Kit harvesting logins for sol.test.',
                'tags': ['phishing', 'credential'],
                'references': ['https://example.test/report'],
                'created': '2026-07-01T00:00:00Z',
            },
            {
                'id': 'pulse-2',
                'name': 'C2 infrastructure referencing sol.test',
                'description': '',
                'tags': ['malware', 'c2'],
                'created': '2026-07-02T00:00:00Z',
            },
        ],
    },
}


class _FakeResp:
    """aiohttp.ClientResponse-shaped enough for upstream_request + the leg."""

    def __init__(self, status, payload=None):
        self.status = status
        self._payload = payload if payload is not None else {}
        self.released = False
        self.headers = {}

    async def json(self, **_kwargs):
        return self._payload

    async def text(self):
        return ''

    async def release(self):
        self.released = True


class _FakeSession:
    """Records the request so the OTX auth header can be asserted."""

    def __init__(self, resp):
        self._resp = resp
        self.calls = []

    async def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self._resp


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def tool():
    t = DarkWebMonitorTool()
    t._source_status = {}
    return t


@pytest.fixture(autouse=True)
def _otx_enabled(monkeypatch):
    """ENABLE_OTX is resolved at import time — patch the module attribute."""
    monkeypatch.setattr(td, 'ENABLE_OTX', True)


@pytest.fixture(autouse=True)
def _no_integration(monkeypatch):
    """No OTX_API integration → the leg takes its anonymous / env-key path.

    Keeps the lease + reconcile ledger out of the picture so the test asserts
    the HTTP leg only. The quota path has its own case below.
    """

    async def _raise(*_a, **_k):
        raise td.IntegrationCredentialsError('no integration')

    monkeypatch.setattr(td, 'checkout_provider', _raise)
    monkeypatch.delenv('OTX_API_KEY', raising=False)


class TestOtxSuccess:
    def test_200_with_pulses_returns_results_and_marks_swept(self, tool):
        # THE REGRESSION: with the tuple bound to a bare `resp`, this returned
        # [] and recorded nothing at all.
        sess = _FakeSession(_FakeResp(200, PULSES))
        out = _run(tool._query_otx(sess, DOMAIN))

        assert tool._source_status['otx'] == 'swept'
        assert len(out) == 2
        by_id = {r['sourceId']: r for r in out}
        assert by_id['pulse-1']['matchType'] == 'CREDENTIAL_LEAK'
        assert by_id['pulse-1']['severity'] == 'HIGH'
        assert by_id['pulse-2']['matchType'] == 'MALWARE_C2'
        assert all(r['source'] == 'THREAT_INTEL_FEED' for r in out)
        assert all(r['sourceName'] == 'AlienVault OTX' for r in out)
        # The domain really was the queried indicator.
        assert DOMAIN in sess.calls[0][1]

    def test_api_key_travels_in_the_otx_header(self, tool, monkeypatch):
        monkeypatch.setenv('OTX_API_KEY', 'otx-key-123')
        sess = _FakeSession(_FakeResp(200, PULSES))
        _run(tool._query_otx(sess, DOMAIN))
        assert sess.calls[0][2]['headers']['X-OTX-API-KEY'] == 'otx-key-123'

    def test_200_with_no_pulses_is_a_genuine_clean_sweep(self, tool):
        out = _run(tool._query_otx(_FakeSession(_FakeResp(200, {})), DOMAIN))
        assert out == []
        assert tool._source_status['otx'] == 'swept'


class TestOtxFailureIsNotClean:
    """A non-200 must be distinguishable from 'not listed anywhere'."""

    def test_404_is_error_not_clean(self, tool):
        out = _run(tool._query_otx(_FakeSession(_FakeResp(404)), DOMAIN))
        assert out == []
        assert tool._source_status['otx'] == 'error_http_404'

    def test_400_is_error_not_clean(self, tool):
        out = _run(tool._query_otx(_FakeSession(_FakeResp(400)), DOMAIN))
        assert out == []
        assert tool._source_status['otx'] == 'error_http_400'

    def test_403_is_unswept_needkey_not_clean(self, tool):
        out = _run(tool._query_otx(_FakeSession(_FakeResp(403)), DOMAIN))
        assert out == []
        assert tool._source_status['otx'] == 'unswept_needkey'

    def test_transport_exception_is_error_not_clean(self, tool):
        class _Boom:
            async def request(self, *a, **k):
                raise RuntimeError('boom')

        out = _run(tool._query_otx(_Boom(), DOMAIN))
        assert out == []
        assert tool._source_status['otx'] == 'error'

    def test_unparseable_200_body_is_error_not_swept(self, tool):
        class _BadJson(_FakeResp):
            async def json(self, **_kwargs):
                raise ValueError('not json')

        out = _run(tool._query_otx(_FakeSession(_BadJson(200)), DOMAIN))
        assert out == []
        # A 200 whose body cannot be read is NOT a clean sweep.
        assert tool._source_status['otx'] == 'error'


class TestOtxNotRun:
    """A leg that never ran is unswept — also not clean."""

    def test_disabled_flag_is_unswept_not_clean(self, tool, monkeypatch):
        monkeypatch.setattr(td, 'ENABLE_OTX', False)
        sess = _FakeSession(_FakeResp(200, PULSES))
        out = _run(tool._query_otx(sess, DOMAIN))
        assert out == []
        assert tool._source_status['otx'] == 'unswept_disabled'
        assert sess.calls == []  # short-circuits before any call

    def test_quota_block_is_unswept_not_clean(self, tool, monkeypatch):
        async def _quota(*_a, **_k):
            raise td.QuotaExceededError('OTX_API', retry_after=60)

        monkeypatch.setattr(td, 'checkout_provider', _quota)
        sess = _FakeSession(_FakeResp(200, PULSES))
        out = _run(tool._query_otx(sess, DOMAIN))
        assert out == []
        assert tool._source_status['otx'] == 'unswept_quota'
        assert sess.calls == []
