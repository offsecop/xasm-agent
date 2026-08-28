"""#1504 — Serper vendor-blink retry-on-empty locks (lib seam).

Serper intermittently returns HTTP 200 with zero organic results for a query
that has results (live-verified: 0, 10, 9, 6 across four consecutive calls).
These locks pin the bounded retry contract at `dispatch_serper`:
  - empty page 1 is retried up to EMPTY_PAGE1_MAX_RETRIES, each attempt a
    FULL checkout→POST→reconcile bracket (metering never bypassed);
  - a non-empty page 1 passes through with zero extra calls;
  - an empty page > 1 is NEVER retried (normal loop-until-dry tail);
  - the shared per-sweep budget halts retries once exhausted;
  - the blink is observable (`empty_retries` per page, aggregated into
    `execute_serp_queries` diagnostics).

FICTITIOUS brand (Lumenfield) only, per the synthetic-data principle.
All transport is mocked — no live calls, no real keys.
"""
import asyncio
import os
import sys
from typing import cast

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import aiohttp

import lib.serper_search as serper_lib
from lib.serper_search import (
    dispatch_serper,
    execute_serp_queries,
    new_empty_retry_budget,
    EMPTY_PAGE1_MAX_RETRIES,
    EMPTY_RETRY_SWEEP_BUDGET,
)

_NULL_SESSION = cast('aiohttp.ClientSession', None)

_HIT = {'organic': [{'link': 'https://blog.example.test/lumenfield-review',
                     'title': 'Lumenfield review', 'snippet': 's'}]}
_EMPTY = {'organic': []}


class _FakeResp:
    def __init__(self, status, payload=None):
        self.status = status
        self._payload = payload or {}

    async def json(self):
        return self._payload

    async def release(self):
        return None


def _patch(monkeypatch, payload_sequence, calls, reconciles):
    """Wire checkout/upstream/reconcile fakes. `payload_sequence` is consumed
    one per upstream POST (last entry repeats)."""
    seq = list(payload_sequence)

    async def _checkout(provider_key, requested_units=1, session=None):
        return {'apiKey': 'sk-live-serper', 'leaseToken': 'lease-1'}

    async def _reconcile(provider_key, lease_token, **kw):
        reconciles.append(kw.get('success'))
        return None

    async def _upstream(session, method, url, **kw):
        calls.append(kw['json_body'])
        payload = seq.pop(0) if len(seq) > 1 else seq[0]
        return _FakeResp(200, payload), {}

    monkeypatch.setattr(serper_lib, 'checkout_provider', _checkout)
    monkeypatch.setattr(serper_lib, 'reconcile_call', _reconcile)
    monkeypatch.setattr(serper_lib, 'upstream_request', _upstream)
    monkeypatch.setattr(serper_lib, 'EMPTY_RETRY_BACKOFF_SECONDS', 0)


class TestDispatchRetryOnEmpty:
    def test_empty_page1_retried_then_recovers(self, monkeypatch):
        calls, reconciles = [], []
        _patch(monkeypatch, [_EMPTY, _HIT], calls, reconciles)
        res = asyncio.run(dispatch_serper('"Lumenfield" review', 1, _NULL_SESSION))
        assert len(res['hits']) == 1                     # recovered hits returned
        assert res['empty_retries'] == 1                 # the blink is observable
        assert len(calls) == 2                           # exactly one retry
        assert len(reconciles) == 2                      # EVERY attempt reconciled

    def test_empty_page1_capped_at_max_retries(self, monkeypatch):
        calls, reconciles = [], []
        _patch(monkeypatch, [_EMPTY], calls, reconciles)
        res = asyncio.run(dispatch_serper('"Lumenfield" review', 1, _NULL_SESSION))
        assert res['hits'] == []                         # genuine empty still reported
        assert res['empty_retries'] == EMPTY_PAGE1_MAX_RETRIES
        assert len(calls) == 1 + EMPTY_PAGE1_MAX_RETRIES  # bounded, never forever
        assert len(reconciles) == len(calls)

    def test_nonempty_page1_no_extra_calls(self, monkeypatch):
        calls, reconciles = [], []
        _patch(monkeypatch, [_HIT], calls, reconciles)
        res = asyncio.run(dispatch_serper('"Lumenfield" review', 1, _NULL_SESSION))
        assert len(res['hits']) == 1
        assert 'empty_retries' not in res                # untouched fast path
        assert len(calls) == 1

    def test_empty_page_gt1_never_retried(self, monkeypatch):
        calls, reconciles = [], []
        _patch(monkeypatch, [_EMPTY], calls, reconciles)
        res = asyncio.run(dispatch_serper('"Lumenfield" review', 2, _NULL_SESSION))
        assert res['hits'] == []
        assert 'empty_retries' not in res                # dry tail is normal
        assert len(calls) == 1

    def test_unswept_page1_not_retried(self, monkeypatch):
        calls, reconciles = [], []

        async def _checkout(provider_key, requested_units=1, session=None):
            return {'apiKey': 'sk-live-serper', 'leaseToken': 'lease-1'}

        async def _reconcile(provider_key, lease_token, **kw):
            reconciles.append(kw.get('success'))
            return None

        async def _upstream(session, method, url, **kw):
            calls.append(kw['json_body'])
            return _FakeResp(500, {}), {}

        monkeypatch.setattr(serper_lib, 'checkout_provider', _checkout)
        monkeypatch.setattr(serper_lib, 'reconcile_call', _reconcile)
        monkeypatch.setattr(serper_lib, 'upstream_request', _upstream)
        monkeypatch.setattr(serper_lib, 'EMPTY_RETRY_BACKOFF_SECONDS', 0)
        res = asyncio.run(dispatch_serper('"Lumenfield" review', 1, _NULL_SESSION))
        assert res['unswept'] is True                    # failure path unchanged
        assert 'empty_retries' not in res
        assert len(calls) == 1

    def test_shared_sweep_budget_halts_retries(self, monkeypatch):
        calls, reconciles = [], []
        _patch(monkeypatch, [_EMPTY], calls, reconciles)
        budget = {'remaining': 1}

        async def _run():
            a = await dispatch_serper('"Lumenfield" q1', 1, _NULL_SESSION,
                                      empty_retry_budget=budget)
            b = await dispatch_serper('"Lumenfield" q2', 1, _NULL_SESSION,
                                      empty_retry_budget=budget)
            return a, b

        a, b = asyncio.run(_run())
        assert a['empty_retries'] == 1                   # budget allowed one
        assert 'empty_retries' not in b                  # then exhausted → no retry
        assert budget['remaining'] == 0
        assert len(calls) == 3                           # q1×2 + q2×1

    def test_fresh_budget_matches_constant(self):
        assert new_empty_retry_budget() == {'remaining': EMPTY_RETRY_SWEEP_BUDGET}


class TestSweepDiagnostics:
    def test_empty_retries_aggregated_and_sweep_still_swept(self):
        async def _dispatch(query, page):
            # A page-1 that stayed empty after the bounded retries — the sweep
            # must still be swept:true with the blink counters populated.
            return {'hits': [], 'unswept': False, 'empty_retries': 2}

        res = asyncio.run(execute_serp_queries(
            [{'query': '"Lumenfield" review', 'kind': 'pinpoint', 'cohort': 'review'}],
            _dispatch=_dispatch,
        ))
        assert res['swept'] is True
        assert res['status'] == 'swept'
        assert res['diagnostics']['emptyRetriedPages'] == 1
        assert res['diagnostics']['emptyRetriesUsed'] == 2

    def test_no_retries_means_zero_counters(self):
        async def _dispatch(query, page):
            return {'hits': [{'url': 'https://blog.example.test/a'}], 'unswept': False}

        res = asyncio.run(execute_serp_queries(
            [{'query': '"Lumenfield" review', 'kind': 'pinpoint', 'cohort': 'review'}],
            _dispatch=_dispatch,
        ))
        assert res['diagnostics']['emptyRetriedPages'] == 0
        assert res['diagnostics']['emptyRetriesUsed'] == 0


if __name__ == '__main__':
    pytest.main([__file__, '-q'])
