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
from unittest.mock import AsyncMock, MagicMock, patch

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(THIS_DIR)
TOOLS_DIR = os.path.join(AGENT_DIR, 'tools')
for d in (AGENT_DIR, TOOLS_DIR):
    if d not in sys.path:
        sys.path.insert(0, d)

from tools.darkweb_monitor import DarkWebMonitorTool  # noqa: E402
from lib.integration_credentials import QuotaExceededError  # noqa: E402


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
            new=AsyncMock(return_value=otx_resp),
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

        mock_checkout.assert_awaited_once_with('GITHUB_SEARCH', requested_units=1)
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


if __name__ == '__main__':
    unittest.main()
