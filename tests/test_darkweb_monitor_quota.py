"""
Unit tests for the T2.8c retrofit: confirm darkweb_monitor's
_query_github / _query_otx / _query_intelx now go through checkout
+ reconcile.

Run:
    python -m unittest tests.test_darkweb_monitor_quota -v
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(THIS_DIR)
TOOLS_DIR = os.path.join(AGENT_DIR, 'tools')
for d in (AGENT_DIR, TOOLS_DIR):
    if d not in sys.path:
        sys.path.insert(0, d)

from tools.darkweb_monitor import DarkWebMonitorTool  # noqa: E402
from lib.integration_credentials import (  # noqa: E402
    IntegrationCredentialsError,
    QuotaExceededError,
)


def _ctx_manager(resp):
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=resp)
    cm.__aexit__ = AsyncMock(return_value=None)
    return cm


def _response(status, json_data=None, text_data=""):
    resp = MagicMock()
    resp.status = status
    resp.json = AsyncMock(return_value=json_data or {})
    resp.text = AsyncMock(return_value=text_data)
    return resp


def _session_for_otx_or_intelx(responses):
    session = MagicMock()
    it = iter(responses)
    session.get = MagicMock(side_effect=lambda *a, **kw: _ctx_manager(next(it)))
    session.post = MagicMock(side_effect=lambda *a, **kw: _ctx_manager(next(it)))
    return session


class TestQueryOtxQuota(unittest.IsolatedAsyncioTestCase):
    async def test_lease_then_reconcile_on_success(self):
        tool = DarkWebMonitorTool()

        otx_resp = _response(200, json_data={
            'pulse_info': {
                'pulses': [
                    {'id': 'p1', 'name': 'pulse 1', 'description': 'desc', 'tags': ['malware'], 'created': '2026-01-01T00:00:00Z'},
                ],
            },
        })
        session = _session_for_otx_or_intelx([otx_resp])

        with patch(
            'tools.darkweb_monitor.ENABLE_OTX',
            True,
        ), patch(
            'tools.darkweb_monitor.upstream_request',
            # #1621 — upstream_request returns a (response, meta) TUPLE. This
            # mock used to return a bare response, mirroring the buggy call site
            # instead of the real contract, which is why the OTX unpack defect
            # survived with a green quota lock.
            new=AsyncMock(return_value=(otx_resp, {'cache_hit': False})),
        ), patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(return_value={
                'apiKey': 'otx-key', 'leaseToken': 'lease-otx', 'periodResetsAt': 't'
            }),
        ) as mock_checkout, patch(
            'tools.darkweb_monitor.reconcile_call',
            new=AsyncMock(),
        ) as mock_reconcile:
            results = await tool._query_otx(session, 'example.com')

        mock_checkout.assert_awaited_once_with('OTX_API', requested_units=1)
        mock_reconcile.assert_awaited_once()
        rc = mock_reconcile.await_args
        self.assertEqual(rc.args[0], 'OTX_API')
        self.assertEqual(rc.args[1], 'lease-otx')
        self.assertTrue(rc.kwargs.get('success'))
        self.assertEqual(len(results), 1)

    async def test_quota_exceeded_returns_empty(self):
        tool = DarkWebMonitorTool()
        with patch(
            'tools.darkweb_monitor.ENABLE_OTX',
            True,
        ), patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(side_effect=QuotaExceededError('OTX_API', retry_after=60)),
        ), patch(
            'tools.darkweb_monitor.reconcile_call',
            new=AsyncMock(),
        ) as mock_reconcile:
            results = await tool._query_otx(MagicMock(), 'example.com')

        self.assertEqual(results, [])
        mock_reconcile.assert_not_awaited()


class TestQueryGithubQuota(unittest.IsolatedAsyncioTestCase):
    async def test_lease_then_reconcile_on_success(self):
        tool = DarkWebMonitorTool()

        # _query_github does multiple requests; respond OK to all.
        responses = [
            _response(200, json_data={'items': []})
            for _ in range(20)
        ]
        session = _session_for_otx_or_intelx(responses)

        with patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(return_value={
                'apiKey': 'github-token', 'leaseToken': 'lease-gh', 'periodResetsAt': 't'
            }),
        ) as mock_checkout, patch(
            'tools.darkweb_monitor.reconcile_call',
            new=AsyncMock(),
        ) as mock_reconcile:
            # Use simple patterns list; _extract_search_terms uses domain by default.
            results = await tool._query_github(session, 'example.com', patterns=[])

        # #348 — checkout reserves the per-scan call ceiling (_GH_MAX_UNITS_PER_SCAN
        # = 4 terms × (1 repo + 2 keyword + 4 qualifier) = 28), not a hardcoded 1.
        mock_checkout.assert_awaited_once_with('GITHUB_SEARCH', requested_units=28)
        mock_reconcile.assert_awaited_once()
        rc = mock_reconcile.await_args
        self.assertEqual(rc.args[0], 'GITHUB_SEARCH')
        self.assertEqual(rc.args[1], 'lease-gh')

    async def test_quota_exceeded_returns_empty(self):
        tool = DarkWebMonitorTool()
        with patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(side_effect=QuotaExceededError('GITHUB_SEARCH', retry_after=60)),
        ), patch(
            'tools.darkweb_monitor.reconcile_call',
            new=AsyncMock(),
        ) as mock_reconcile:
            results = await tool._query_github(MagicMock(), 'example.com', patterns=[])

        self.assertEqual(results, [])
        mock_reconcile.assert_not_awaited()


class TestQueryGitlabQuota(unittest.IsolatedAsyncioTestCase):
    """#1489 — _query_gitlab resolves its token via checkout_provider
    ('GITLAB_SEARCH'), falls back to the env GITLAB_TOKEN, reconciles the
    real blob-search call count, and still degrades honestly
    (_mark_source_status) when neither token source exists."""

    async def test_lease_then_reconcile_on_success(self):
        tool = DarkWebMonitorTool()
        tool._source_status = {}

        # One 200 blob-list response per search term. NB: the _response
        # helper coerces falsy json_data to {}, so use a single benign blob
        # dict (no brand match -> dropped by the keep/drop gate).
        responses = [_response(200, json_data=[{}]) for _ in range(10)]
        session = _session_for_otx_or_intelx(responses)

        with patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(return_value={
                'apiKey': 'gitlab-token', 'leaseToken': 'lease-gl', 'periodResetsAt': 't'
            }),
        ) as mock_checkout, patch(
            'tools.darkweb_monitor.reconcile_call',
            new=AsyncMock(),
        ) as mock_reconcile, patch(
            'tools.darkweb_monitor.asyncio.sleep',
            new=AsyncMock(),  # short-circuit the 0.5s inter-call sleep
        ):
            results = await tool._query_gitlab(session, 'example.com', patterns=[])

        # Checkout reserves the per-scan ceiling (≤4 terms × 1 blob search).
        mock_checkout.assert_awaited_once_with('GITLAB_SEARCH', requested_units=4)
        mock_reconcile.assert_awaited_once()
        rc = mock_reconcile.await_args
        self.assertEqual(rc.args[0], 'GITLAB_SEARCH')
        self.assertEqual(rc.args[1], 'lease-gl')
        self.assertTrue(rc.kwargs.get('success'))
        # Reconciled units = real calls issued, not the reserved ceiling.
        self.assertGreaterEqual(rc.kwargs.get('units'), 1)
        self.assertLessEqual(rc.kwargs.get('units'), 4)
        self.assertEqual(results, [])
        self.assertEqual(tool._source_status.get('gitlab'), 'swept')

    async def test_quota_exceeded_returns_empty_and_marks_status(self):
        tool = DarkWebMonitorTool()
        tool._source_status = {}
        with patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(side_effect=QuotaExceededError('GITLAB_SEARCH', retry_after=60)),
        ), patch(
            'tools.darkweb_monitor.reconcile_call',
            new=AsyncMock(),
        ) as mock_reconcile:
            results = await tool._query_gitlab(MagicMock(), 'example.com', patterns=[])

        self.assertEqual(results, [])
        mock_reconcile.assert_not_awaited()
        # Honest degrade — a capped sweep is never a silent false clean.
        self.assertEqual(tool._source_status.get('gitlab'), 'unswept_quota')

    async def test_env_fallback_when_no_integration(self):
        tool = DarkWebMonitorTool()
        tool._source_status = {}
        responses = [_response(200, json_data=[{}]) for _ in range(10)]
        session = _session_for_otx_or_intelx(responses)

        with patch.dict(os.environ, {'GITLAB_TOKEN': 'env-gitlab-token'}), patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(side_effect=IntegrationCredentialsError('no integration')),
        ), patch(
            'tools.darkweb_monitor.reconcile_call',
            new=AsyncMock(),
        ) as mock_reconcile, patch(
            'tools.darkweb_monitor.asyncio.sleep',
            new=AsyncMock(),
        ):
            results = await tool._query_gitlab(session, 'example.com', patterns=[])

        # No lease → no reconcile; sweep proceeded on the env token.
        mock_reconcile.assert_not_awaited()
        self.assertEqual(results, [])
        self.assertEqual(tool._source_status.get('gitlab'), 'swept')
        # The env token reached the request headers (PRIVATE-TOKEN scheme).
        _, first_kwargs = session.get.call_args_list[0]
        self.assertEqual(
            first_kwargs.get('headers', {}).get('PRIVATE-TOKEN'),
            'env-gitlab-token',
        )

    async def test_no_token_anywhere_degrades_honestly(self):
        tool = DarkWebMonitorTool()
        tool._source_status = {}
        session = MagicMock()

        with patch.dict(os.environ, {'GITLAB_TOKEN': ''}), patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(side_effect=IntegrationCredentialsError('no integration')),
        ), patch(
            'tools.darkweb_monitor.reconcile_call',
            new=AsyncMock(),
        ) as mock_reconcile:
            results = await tool._query_gitlab(session, 'example.com', patterns=[])

        self.assertEqual(results, [])
        session.get.assert_not_called()
        mock_reconcile.assert_not_awaited()
        self.assertEqual(tool._source_status.get('gitlab'), 'unswept_needkey')


class TestQueryIntelxQuota(unittest.IsolatedAsyncioTestCase):
    async def test_lease_then_reconcile_phonebook_path(self):
        tool = DarkWebMonitorTool()

        # Phonebook flow: search returns id, then result returns selectors.
        responses = [
            _response(200, json_data={'id': 'srch-1'}),
            _response(200, json_data={'selectors': []}),
        ]
        session = _session_for_otx_or_intelx(responses)

        with patch(
            'tools.darkweb_monitor.ENABLE_INTELX',
            True,
        ), patch(
            'tools.darkweb_monitor.checkout_provider',
            # Empty apiKey simulates "integration configured but no key" —
            # service routes to free phonebook tier.
            new=AsyncMock(return_value={
                'apiKey': '', 'leaseToken': 'lease-ix', 'periodResetsAt': 't'
            }),
        ) as mock_checkout, patch(
            'tools.darkweb_monitor.reconcile_call',
            new=AsyncMock(),
        ) as mock_reconcile, patch(
            'tools.darkweb_monitor.asyncio.sleep',
            new=AsyncMock(),  # short-circuit the 2s sleep
        ):
            results = await tool._query_intelx(session, 'example.com')

        mock_checkout.assert_awaited_once_with('INTELX', requested_units=1)
        mock_reconcile.assert_awaited_once()
        rc = mock_reconcile.await_args
        self.assertEqual(rc.args[0], 'INTELX')
        self.assertEqual(rc.args[1], 'lease-ix')
        self.assertTrue(rc.kwargs.get('success'))

    async def test_quota_exceeded_returns_empty(self):
        tool = DarkWebMonitorTool()
        with patch(
            'tools.darkweb_monitor.ENABLE_INTELX',
            True,
        ), patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(side_effect=QuotaExceededError('INTELX', retry_after=60)),
        ), patch(
            'tools.darkweb_monitor.reconcile_call',
            new=AsyncMock(),
        ) as mock_reconcile:
            results = await tool._query_intelx(MagicMock(), 'example.com')

        self.assertEqual(results, [])
        mock_reconcile.assert_not_awaited()


class TestQueryCavalierQuota(unittest.IsolatedAsyncioTestCase):
    """#1604 — _query_cavalier leases CAVALIER quota (keyless vendor: the
    Integration row is the enable switch + cap surface), reconciles the real
    call count, degrades honestly, and — the load-bearing part — keeps the
    employee-side and client-side populations SEPARATE."""

    # A trimmed but shape-faithful Cavalier payload. SYNTHETIC: fictitious
    # brand on a .test domain. employees is small + STALE; users is large +
    # RECENT — the exact shape that would misreport as one big number.
    PAYLOAD = {
        'total': 4902,
        'employees': 3,
        'users': 4899,
        'last_employee_compromised': '2020-03-01T00:00:00.000Z',
        'last_user_compromised': '2026-07-21T08:42:48.339Z',
        'stealerFamilies': {'total': 4902, 'RedLine': 300, 'Lumma': 120},
        'employeePasswords': {'totalPass': 3, 'too_weak': {'qty': 2, 'perc': 66}},
        'userPasswords': {'totalPass': 4899, 'weak': {'qty': 1000, 'perc': 20}},
        'data': {
            'employees_urls': [
                # NB: the middle entry carries the REAL vendor serialization
                # artifact observed live (embedded quote + comma).
                {'occurrence': 3, 'type': 'Employee', 'url': 'https://sso.lumenfield.test/login'},
                {'occurrence': 1, 'type': 'Employee', 'url': 'login.lumenfield.test",'},
            ],
            'clients_urls': [
                {'occurrence': 900, 'type': 'Client', 'url': 'https://www.lumenfield.test/account'},
            ],
        },
    }

    async def test_employee_and_client_sides_stay_separate(self):
        tool = DarkWebMonitorTool()
        tool._source_status = {}
        session = _session_for_otx_or_intelx([_response(200, json_data=self.PAYLOAD)])

        with patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(return_value={'apiKey': None, 'leaseToken': 'lease-cav'}),
        ) as mock_checkout, patch(
            'tools.darkweb_monitor.reconcile_call',
            new=AsyncMock(),
        ) as mock_reconcile:
            results = await tool._query_cavalier(session, 'lumenfield.test')

        mock_checkout.assert_awaited_once_with('CAVALIER', requested_units=1)
        rc = mock_reconcile.await_args
        self.assertEqual(rc.args[0], 'CAVALIER')
        self.assertEqual(rc.args[1], 'lease-cav')
        self.assertTrue(rc.kwargs.get('success'))
        self.assertEqual(rc.kwargs.get('units'), 1)
        self.assertEqual(tool._source_status.get('cavalier'), 'swept')

        # TWO records — one per population, never a combined "4902 compromised".
        self.assertEqual(len(results), 2)
        by_kind = {r['metadata']['infostealer']['kind']: r for r in results}
        self.assertEqual(set(by_kind), {'employee', 'client'})

        emp = by_kind['employee']
        cli = by_kind['client']
        self.assertEqual(emp['metadata']['infostealer']['machineCount'], 3)
        self.assertEqual(cli['metadata']['infostealer']['machineCount'], 4899)
        # Distinct dedup anchors so the two sides persist independently.
        self.assertNotEqual(emp['sourceUrl'], cli['sourceUrl'])
        self.assertNotEqual(emp['sourceId'], cli['sourceId'])
        # Stale employee side must NOT scream; recent client side is MEDIUM.
        self.assertEqual(emp['severity'], 'LOW')
        self.assertEqual(cli['severity'], 'MEDIUM')
        # The client record must never claim staff / perimeter compromise: it
        # says "customer device(s)", explicitly denies a perimeter breach, and
        # mentions the employee side only to keep the two populations apart.
        self.assertIn('customer device', cli['contentSnippet'].lower())
        self.assertNotIn('staff', cli['contentSnippet'].lower())
        self.assertIn('not a breach', cli['contentSnippet'].lower())
        # ...and the employee record must not fold the customer volume in.
        self.assertIn('staff', emp['contentSnippet'].lower())
        self.assertNotIn('4899', emp['contentSnippet'])
        # No emails / raw passwords are available on the free tier.
        for r in results:
            self.assertNotIn('email', r['metadata'])
            self.assertNotIn('password', r['metadata'])

    async def test_vendor_host_artifacts_are_sanitized(self):
        tool = DarkWebMonitorTool()
        tool._source_status = {}
        session = _session_for_otx_or_intelx([_response(200, json_data=self.PAYLOAD)])

        with patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(return_value={'leaseToken': 'lease-cav'}),
        ), patch('tools.darkweb_monitor.reconcile_call', new=AsyncMock()):
            results = await tool._query_cavalier(session, 'lumenfield.test')

        emp = next(r for r in results if r['metadata']['infostealer']['kind'] == 'employee')
        urls = [u['url'] for u in emp['metadata']['capturedLoginUrls']]
        self.assertIn('login.lumenfield.test', urls)  # quote+comma stripped
        for u in urls:
            self.assertNotIn('"', u)
            self.assertNotIn(',', u)

    async def test_recent_employee_side_bands_high(self):
        tool = DarkWebMonitorTool()
        tool._source_status = {}
        payload = dict(self.PAYLOAD)
        payload['last_employee_compromised'] = (
            datetime.now(timezone.utc) - timedelta(days=5)
        ).isoformat()
        session = _session_for_otx_or_intelx([_response(200, json_data=payload)])

        with patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(return_value={'leaseToken': 'lease-cav'}),
        ), patch('tools.darkweb_monitor.reconcile_call', new=AsyncMock()):
            results = await tool._query_cavalier(session, 'lumenfield.test')

        emp = next(r for r in results if r['metadata']['infostealer']['kind'] == 'employee')
        self.assertEqual(emp['severity'], 'HIGH')

    async def test_no_integration_marks_not_configured(self):
        tool = DarkWebMonitorTool()
        tool._source_status = {}
        with patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(side_effect=IntegrationCredentialsError('no integration')),
        ), patch(
            'tools.darkweb_monitor.reconcile_call', new=AsyncMock(),
        ) as mock_reconcile:
            results = await tool._query_cavalier(MagicMock(), 'lumenfield.test')

        self.assertEqual(results, [])
        mock_reconcile.assert_not_awaited()
        # Honest degrade — never a silent clean.
        self.assertEqual(tool._source_status.get('cavalier'), 'unswept_not_configured')

    async def test_quota_exceeded_marks_unswept_quota(self):
        tool = DarkWebMonitorTool()
        tool._source_status = {}
        with patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(side_effect=QuotaExceededError('CAVALIER', retry_after=30)),
        ), patch(
            'tools.darkweb_monitor.reconcile_call', new=AsyncMock(),
        ) as mock_reconcile:
            results = await tool._query_cavalier(MagicMock(), 'lumenfield.test')

        self.assertEqual(results, [])
        mock_reconcile.assert_not_awaited()
        self.assertEqual(tool._source_status.get('cavalier'), 'unswept_quota')

    async def test_zero_counts_emit_no_records(self):
        tool = DarkWebMonitorTool()
        tool._source_status = {}
        payload = {'employees': 0, 'users': 0}
        session = _session_for_otx_or_intelx([_response(200, json_data=payload)])

        with patch(
            'tools.darkweb_monitor.checkout_provider',
            new=AsyncMock(return_value={'leaseToken': 'lease-cav'}),
        ), patch('tools.darkweb_monitor.reconcile_call', new=AsyncMock()):
            results = await tool._query_cavalier(session, 'lumenfield.test')

        self.assertEqual(results, [])
        # A genuinely clean posture IS swept — distinct from unswept/not configured.
        self.assertEqual(tool._source_status.get('cavalier'), 'swept')


if __name__ == '__main__':
    unittest.main()
