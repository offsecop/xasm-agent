"""#1143 — quota-disciplined bounded pagination loop (lib/sc_paginated_search).

Locks the loop's flood/billing invariants:
  - one checkout+reconcile per page; a FIRED page bills 1 unit (SC bills error
    responses too), a cache hit bills 0;
  - the cursor is forwarded page-to-page under the vendor's REAL param name;
  - quota exhaustion MID-RUN parks the sweep (partial results, meta.quotaBlocked)
    instead of error-storming; page-1 exhaustion keeps the hard contract;
  - `cursor_param=None` (threads) can never loop;
  - the `limit` budget and an empty page stop the loop early.
"""

import unittest
from unittest import mock

import lib.sc_paginated_search as scp
from lib.integration_credentials import QuotaExceededError


def _lease():
    return {
        'apiKey': 'sk-live-test',
        'leaseToken': 'lease-1',
        'baseUrl': 'https://api.example.test',
        'timeoutSeconds': 5,
        'tenantId': 'tenant-1',
        'cacheNamespaceTtls': {},
        'cacheTtlSeconds': 60,
    }


class _FakeResp:
    def __init__(self, status, payload):
        self.status = status
        self._payload = payload

    async def json(self):
        return self._payload

    async def text(self):
        return str(self._payload)


class _FakeSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _quota_error():
    try:
        return QuotaExceededError(
            provider_key='SCRAPECREATORS', retry_after=5,
            period_resets_at=None, cap=None, current_usage=None,
        )
    except TypeError:
        return QuotaExceededError('SCRAPECREATORS')


class PaginatedScSearchTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.reconciles = []

        async def fake_reconcile(provider, token, **kw):
            self.reconciles.append(kw)

        self.patches = [
            mock.patch.object(scp, 'reconcile_call', side_effect=fake_reconcile),
            mock.patch.object(scp.aiohttp, 'ClientSession', return_value=_FakeSession()),
            mock.patch.object(scp.aiohttp, 'ClientTimeout', return_value=None),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def _patch_checkout(self, side_effect):
        p = mock.patch.object(scp, 'checkout_provider', side_effect=side_effect)
        p.start()
        self.addCleanup(p.stop)

    def _patch_upstream(self, pages):
        """pages: list of (resp, call_meta) returned per successive call."""
        calls = []

        async def fake_upstream(session, method, url, **kw):
            calls.append(kw)
            return pages[len(calls) - 1]

        p = mock.patch.object(scp, 'upstream_request', side_effect=fake_upstream)
        p.start()
        self.addCleanup(p.stop)
        return calls

    async def test_paginates_forwards_cursor_and_bills_each_fired_page(self):
        async def ok_checkout(provider, requested_units=1):
            return _lease()

        self._patch_checkout(ok_checkout)
        calls = self._patch_upstream([
            (_FakeResp(200, {'posts': [{'id': 'a'}], 'after': 'c1'}),
             {'cache_hit': False, 'cache_stale': False, 'fetched_at': 't1'}),
            (_FakeResp(200, {'posts': [{'id': 'b'}], 'after': 'c2'}),
             {'cache_hit': False, 'cache_stale': False, 'fetched_at': 't2'}),
            (_FakeResp(200, {'posts': [{'id': 'c'}]}),
             {'cache_hit': False, 'cache_stale': False, 'fetched_at': 't3'}),
        ])

        res = await scp.paginated_sc_search(
            tool_name='t', path='/v1/x/search', base_params={'query': 'q'},
            cache_namespace='x',
            extract_items=lambda d: list(d.get('posts', [])),
            cursor_param='after', max_pages=3, limit=50,
        )

        self.assertEqual(res['kind'], 'ok')
        self.assertEqual([i['id'] for i in res['items']], ['a', 'b', 'c'])
        # cursor forwarded under the REAL vendor param name from page 2 on
        self.assertNotIn('after', calls[0]['params'])
        self.assertEqual(calls[1]['params']['after'], 'c1')
        self.assertEqual(calls[2]['params']['after'], 'c2')
        # 3 fired pages → 3 reconciles of 1 unit each
        self.assertEqual([r['units'] for r in self.reconciles], [1, 1, 1])
        self.assertEqual(res['meta']['pagesFired'], 3)

    async def test_quota_mid_run_parks_with_partial_results(self):
        state = {'n': 0}

        async def checkout(provider, requested_units=1):
            state['n'] += 1
            if state['n'] >= 2:
                raise _quota_error()
            return _lease()

        self._patch_checkout(checkout)
        self._patch_upstream([
            (_FakeResp(200, {'posts': [{'id': 'a'}], 'after': 'c1'}),
             {'cache_hit': False, 'cache_stale': False}),
        ])

        res = await scp.paginated_sc_search(
            tool_name='t', path='/p', base_params={'query': 'q'},
            cache_namespace='x',
            extract_items=lambda d: list(d.get('posts', [])),
            cursor_param='after', max_pages=3, limit=50,
        )
        self.assertEqual(res['kind'], 'ok')  # PARTIAL success, not an error storm
        self.assertEqual(len(res['items']), 1)
        self.assertTrue(res['meta'].get('quotaBlocked'))

    async def test_quota_on_first_page_keeps_hard_contract(self):
        async def checkout(provider, requested_units=1):
            raise _quota_error()

        self._patch_checkout(checkout)
        res = await scp.paginated_sc_search(
            tool_name='t', path='/p', base_params={},
            cache_namespace='x', extract_items=lambda d: [],
            cursor_param='after', max_pages=3, limit=50,
        )
        self.assertEqual(res['kind'], 'quota_exceeded')

    async def test_cache_hit_bills_zero_units(self):
        async def ok_checkout(provider, requested_units=1):
            return _lease()

        self._patch_checkout(ok_checkout)
        self._patch_upstream([
            (_FakeResp(200, {'posts': [{'id': 'a'}]}),
             {'cache_hit': True, 'cache_stale': False}),
        ])
        res = await scp.paginated_sc_search(
            tool_name='t', path='/p', base_params={'query': 'q'},
            cache_namespace='x',
            extract_items=lambda d: list(d.get('posts', [])),
            cursor_param='after', max_pages=2, limit=50,
        )
        self.assertEqual(res['kind'], 'ok')
        self.assertEqual([r['units'] for r in self.reconciles], [0])
        self.assertTrue(res['meta']['cacheHit'])

    async def test_none_cursor_param_forces_single_call(self):
        async def ok_checkout(provider, requested_units=1):
            return _lease()

        self._patch_checkout(ok_checkout)
        calls = self._patch_upstream([
            (_FakeResp(200, {'posts': [{'id': 'a'}], 'cursor': 'more'}),
             {'cache_hit': False, 'cache_stale': False}),
        ])
        res = await scp.paginated_sc_search(
            tool_name='t', path='/p', base_params={'query': 'q'},
            cache_namespace='x',
            extract_items=lambda d: list(d.get('posts', [])),
            cursor_param=None, max_pages=5, limit=50,
        )
        self.assertEqual(res['kind'], 'ok')
        self.assertEqual(len(calls), 1)

    async def test_limit_budget_stops_the_loop(self):
        async def ok_checkout(provider, requested_units=1):
            return _lease()

        self._patch_checkout(ok_checkout)
        calls = self._patch_upstream([
            (_FakeResp(200, {'posts': [{'id': str(i)} for i in range(10)],
                             'after': 'c1'}),
             {'cache_hit': False, 'cache_stale': False}),
        ])
        res = await scp.paginated_sc_search(
            tool_name='t', path='/p', base_params={'query': 'q'},
            cache_namespace='x',
            extract_items=lambda d: list(d.get('posts', [])),
            cursor_param='after', max_pages=5, limit=10,
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(res['items']), 10)

    async def test_stub_key_refuses_and_bills_zero(self):
        async def stub_checkout(provider, requested_units=1):
            lease = _lease()
            lease['apiKey'] = scp.STUB_API_KEY
            return lease

        self._patch_checkout(stub_checkout)
        res = await scp.paginated_sc_search(
            tool_name='t', path='/p', base_params={},
            cache_namespace='x', extract_items=lambda d: [],
            cursor_param='after', max_pages=3, limit=50,
        )
        self.assertEqual(res['kind'], 'stub_mode_blocked')
        self.assertEqual([r['units'] for r in self.reconciles], [0])


if __name__ == '__main__':
    unittest.main()
