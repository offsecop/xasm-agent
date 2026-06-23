"""
Unit tests for the T2.8c retrofit: confirm threat_feed_poll's OTX path
now goes through checkout + reconcile, while non-OTX paths skip the
seam (public unauthenticated feeds).

Run:
    python -m unittest tests.test_threat_feed_poll_quota -v
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

from tools.threat_feed_poll import ThreatFeedPollTool  # noqa: E402
from lib.integration_credentials import QuotaExceededError  # noqa: E402


class TestThreatFeedPollOtxQuota(unittest.IsolatedAsyncioTestCase):
    async def test_otx_leases_and_reconciles(self):
        tool = ThreatFeedPollTool()

        with patch(
            'tools.threat_feed_poll.checkout_provider',
            new=AsyncMock(return_value={
                'apiKey': 'otx-key',
                'leaseToken': 'lease-tfp-otx',
                'periodResetsAt': 't',
            }),
        ) as mock_checkout, patch(
            'tools.threat_feed_poll.reconcile_call',
            new=AsyncMock(),
        ) as mock_reconcile, patch.object(
            tool, 'run', return_value={
                'success': True,
                'output': {'indicators': [], 'total_fetched': 0, 'new_count': 0, 'feed_type': 'OTX'},
            },
        ) as mock_run:
            result = await tool.execute({
                'feedType': 'OTX',
                'feedUrl': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
            })

        self.assertTrue(result['success'])
        mock_checkout.assert_awaited_once_with('OTX_API', requested_units=1)
        mock_reconcile.assert_awaited_once()
        rc = mock_reconcile.await_args
        self.assertEqual(rc.args[0], 'OTX_API')
        self.assertEqual(rc.args[1], 'lease-tfp-otx')
        # The lease's apiKey should have been merged into params before run().
        run_params = mock_run.call_args.args[0]
        self.assertEqual(run_params.get('apiKey'), 'otx-key')

    async def test_otx_quota_exceeded_returns_429_response(self):
        tool = ThreatFeedPollTool()
        with patch(
            'tools.threat_feed_poll.checkout_provider',
            new=AsyncMock(side_effect=QuotaExceededError('OTX_API', retry_after=120)),
        ), patch(
            'tools.threat_feed_poll.reconcile_call',
            new=AsyncMock(),
        ) as mock_reconcile:
            result = await tool.execute({
                'feedType': 'OTX',
                'feedUrl': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
            })

        self.assertFalse(result['success'])
        self.assertEqual(result['error'], 'quota_exceeded')
        self.assertEqual(result['retryAfter'], 120)
        mock_reconcile.assert_not_awaited()

    async def test_abuse_ch_does_not_lease(self):
        """Non-OTX paths must skip the quota seam entirely — those are
        public feeds without per-tenant rate-limit concerns."""
        tool = ThreatFeedPollTool()
        with patch(
            'tools.threat_feed_poll.checkout_provider',
            new=AsyncMock(),
        ) as mock_checkout, patch(
            'tools.threat_feed_poll.reconcile_call',
            new=AsyncMock(),
        ) as mock_reconcile, patch.object(
            tool, 'run', return_value={'success': True, 'output': {'indicators': []}},
        ):
            result = await tool.execute({
                'feedType': 'ABUSE_CH',
                'feedUrl': 'https://urlhaus.abuse.ch/feeds/recent/',
            })

        self.assertTrue(result['success'])
        mock_checkout.assert_not_awaited()
        mock_reconcile.assert_not_awaited()


if __name__ == '__main__':
    unittest.main()
