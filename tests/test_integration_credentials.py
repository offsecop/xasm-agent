"""
Unit tests for agent/lib/integration_credentials.py

DRP→ASM migration T2.6: validates checkout_provider() + reconcile_call().

Run from the agent/ directory:
    python -m unittest tests.test_integration_credentials -v

These tests mock the aiohttp session at the manager level — no real HTTP
calls are made.
"""

import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# Ensure agent/ is on sys.path so `lib.integration_credentials` imports
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(THIS_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from lib.integration_credentials import (  # noqa: E402
    checkout_provider,
    reconcile_call,
    QuotaExceededError,
    IntegrationAuthError,
    IntegrationServerError,
)


def _make_response(status: int, json_data=None, text_data: str = "", headers=None):
    """Build a MagicMock that mimics aiohttp's response context manager."""
    resp = MagicMock()
    resp.status = status
    resp.json = AsyncMock(return_value=json_data or {})
    resp.text = AsyncMock(return_value=text_data)
    resp.headers = headers or {}
    return resp


def _make_session_post(resp):
    """Wrap a response in a context-manager-returning session.post mock."""
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=resp)
    cm.__aexit__ = AsyncMock(return_value=None)
    session = MagicMock()
    session.post = MagicMock(return_value=cm)
    session.close = AsyncMock()
    return session


def _patch_backend_config():
    """Patch _resolve_backend_config to return a fixed test config."""
    return patch(
        'lib.integration_credentials._resolve_backend_config',
        return_value={
            'api_url': 'http://backend:3001/api',
            'agent_api_key': 'test-agent-key',
        },
    )


class TestCheckoutProvider(unittest.IsolatedAsyncioTestCase):
    async def test_checkout_200_returns_apikey_and_lease(self):
        resp = _make_response(
            200,
            json_data={
                'apiKey': 'upstream-secret-key',
                'leaseToken': 'lease-abc-123',
                'periodResetsAt': '2026-06-14T00:00:00.000Z',
            },
        )
        session = _make_session_post(resp)

        with _patch_backend_config():
            result = await checkout_provider(
                'HIKER_API', requested_units=2, session=session,
            )

        self.assertEqual(result['apiKey'], 'upstream-secret-key')
        self.assertEqual(result['leaseToken'], 'lease-abc-123')
        self.assertEqual(result['periodResetsAt'], '2026-06-14T00:00:00.000Z')

        # Confirm the request shape: correct URL, headers, and body.
        call = session.post.call_args
        self.assertEqual(
            call.args[0],
            'http://backend:3001/api/integrations/HIKER_API/checkout',
        )
        self.assertEqual(call.kwargs['headers']['X-API-Key'], 'test-agent-key')
        self.assertEqual(call.kwargs['json'], {'requestedUnits': 2})

    async def test_checkout_429_raises_quota_exceeded(self):
        resp = _make_response(
            429,
            json_data={
                'providerKey': 'TWITTERAPI_IO',
                'cap': 1000,
                'currentUsage': 1000,
                'retryAfter': 120,
                'periodResetsAt': '2026-06-14T00:00:00.000Z',
            },
            headers={'Retry-After': '120'},
        )
        session = _make_session_post(resp)

        with _patch_backend_config():
            with self.assertRaises(QuotaExceededError) as cm:
                await checkout_provider(
                    'TWITTERAPI_IO', requested_units=1, session=session,
                )

        err = cm.exception
        self.assertEqual(err.provider_key, 'TWITTERAPI_IO')
        self.assertEqual(err.retry_after, 120)
        self.assertEqual(err.cap, 1000)
        self.assertEqual(err.current_usage, 1000)
        self.assertEqual(err.period_resets_at, '2026-06-14T00:00:00.000Z')

    async def test_checkout_401_raises_auth_error(self):
        resp = _make_response(401, text_data='Unauthorized')
        session = _make_session_post(resp)

        with _patch_backend_config():
            with self.assertRaises(IntegrationAuthError):
                await checkout_provider(
                    'HIKER_API', session=session,
                )

    async def test_checkout_500_raises_server_error(self):
        resp = _make_response(500, text_data='Internal Server Error')
        session = _make_session_post(resp)

        with _patch_backend_config():
            with self.assertRaises(IntegrationServerError):
                await checkout_provider(
                    'HIKER_API', session=session,
                )

    async def test_checkout_uppercases_provider(self):
        resp = _make_response(
            200,
            json_data={
                'apiKey': 'k',
                'leaseToken': 't',
                'periodResetsAt': '2026-06-14T00:00:00.000Z',
            },
        )
        session = _make_session_post(resp)

        with _patch_backend_config():
            await checkout_provider('hiker_api', session=session)

        url = session.post.call_args.args[0]
        self.assertIn('/HIKER_API/checkout', url)


class TestReconcileCall(unittest.IsolatedAsyncioTestCase):
    async def test_reconcile_200_success(self):
        resp = _make_response(200, json_data={'ok': True})
        session = _make_session_post(resp)

        with _patch_backend_config():
            await reconcile_call(
                'HIKER_API',
                'lease-abc-123',
                units=5,
                cost_usd=0.01,
                success=True,
                session=session,
            )

        call = session.post.call_args
        self.assertEqual(
            call.args[0],
            'http://backend:3001/api/integrations/HIKER_API/reconcile',
        )
        body = call.kwargs['json']
        self.assertEqual(body['leaseToken'], 'lease-abc-123')
        self.assertEqual(body['units'], 5)
        self.assertEqual(body['costUsd'], 0.01)
        self.assertTrue(body['success'])

    async def test_reconcile_failure_does_not_raise(self):
        resp = _make_response(500, text_data='internal err')
        session = _make_session_post(resp)

        # Must not raise — reconcile failures are non-fatal.
        with _patch_backend_config():
            await reconcile_call(
                'HIKER_API',
                'lease-abc-123',
                success=True,
                session=session,
            )

    async def test_reconcile_transport_error_swallowed(self):
        session = MagicMock()
        # session.post raises directly
        session.post = MagicMock(side_effect=RuntimeError("connection refused"))
        session.close = AsyncMock()

        with _patch_backend_config():
            # Must not raise
            await reconcile_call(
                'HIKER_API',
                'lease-abc-123',
                success=False,
                error_code='upstream_500',
                session=session,
            )

    async def test_reconcile_omits_optional_fields(self):
        resp = _make_response(200, json_data={'ok': True})
        session = _make_session_post(resp)

        with _patch_backend_config():
            await reconcile_call(
                'INTELX', 'lease-xyz', success=True, session=session,
            )

        body = session.post.call_args.kwargs['json']
        self.assertNotIn('units', body)
        self.assertNotIn('costUsd', body)
        self.assertNotIn('errorCode', body)


if __name__ == '__main__':
    unittest.main()
