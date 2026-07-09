"""#519 — AI browser login must self-bound with an overall wall-clock budget.

The internal sub-timeouts (per-navigation, per-LLM call, per-MFA round) are
individually bounded, but their SUM had no cap: a slow vision LLM/relay or a
multi-round MFA flow could wedge the tool until the agent's hard per-job
watchdog killed it, cancelling every downstream step with no usable result.

These tests prove the wrapper aborts a wedged login PROMPTLY and returns a
STRUCTURED failure (so downstream steps can proceed) instead of hanging.
"""
import asyncio
import os
import sys
import time
import unittest

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(THIS_DIR)
TOOLS_DIR = os.path.join(AGENT_DIR, 'tools')
for d in (AGENT_DIR, TOOLS_DIR):
    if d not in sys.path:
        sys.path.insert(0, d)

from tools.browser_login_ai import BrowserLoginAiTool, _coerce_float  # noqa: E402


class TestCoerceFloat(unittest.TestCase):
    def test_defaults_coercion_and_guards(self):
        self.assertEqual(_coerce_float(None, 300.0), 300.0)      # missing → default
        self.assertEqual(_coerce_float('420', 300.0), 420.0)     # numeric string
        self.assertEqual(_coerce_float(180, 300.0), 180.0)       # int
        self.assertEqual(_coerce_float(0, 300.0), 300.0)         # non-positive → default
        self.assertEqual(_coerce_float(-5, 300.0), 300.0)
        self.assertEqual(_coerce_float('nope', 300.0), 300.0)    # unparseable → default


class TestAiLoginOverallBudget(unittest.IsolatedAsyncioTestCase):
    async def test_overall_budget_aborts_a_wedged_login_with_structured_failure(self):
        tool = BrowserLoginAiTool()

        async def _hang(*args, **kwargs):
            await asyncio.sleep(30)  # would wedge far past the budget
            return {'success': True, 'cookies': [{'name': 'x'}]}

        tool._ai_driven_login = _hang  # type: ignore[assignment]

        started = time.monotonic()
        result = await tool.execute({
            'loginUrl': 'http://vulnlab.test/login',
            'username': 'user',
            'password': 'pass',
            'overallTimeoutSeconds': 1,
            'headless': True,
        })
        elapsed = time.monotonic() - started

        # Returned promptly — did NOT wedge to the 30s sleep.
        self.assertLess(elapsed, 10)
        # Structured failure usable by the workflow engine (not a hang, not a
        # bare string spread into character-indexed keys).
        self.assertEqual(result.get('status'), 'FAILED')
        self.assertFalse(result.get('session_valid'))
        self.assertIn('overall time budget', result.get('error', ''))
        self.assertEqual(result.get('cookies'), [])
        self.assertNotIn('0', result)  # not a spread string

    async def test_login_ceiling_caps_a_huge_job_watchdog(self):
        # A login must never inherit a long SCAN watchdog (e.g. 3200s for a
        # nuclei full scan). With a huge `_job_timeout_seconds`, the
        # login-appropriate ceiling governs — the login fails in minutes, not ~an
        # hour. Here the ceiling is squeezed to ~1s to prove it caps, not the
        # 3200s watchdog (which would otherwise mean a ~3180s budget).
        tool = BrowserLoginAiTool()

        async def _hang(*args, **kwargs):
            await asyncio.sleep(30)

        tool._ai_driven_login = _hang  # type: ignore[assignment]

        started = time.monotonic()
        result = await tool.execute({
            'loginUrl': 'http://vulnlab.test/login',
            'username': 'user',
            'password': 'pass',
            '_job_timeout_seconds': 3200,     # huge scan watchdog
            'aiLoginMaxOverallSeconds': 1,    # login ceiling caps the budget
        })
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 10)  # capped at ~1s, NOT watchdog-20 (~3180s)
        self.assertEqual(result.get('status'), 'FAILED')
        self.assertIn('overall time budget', result.get('error', ''))

    async def test_missing_credentials_skip_short_circuits_before_budget(self):
        # The optional-auth skip path must remain intact (no creds → clean skip).
        tool = BrowserLoginAiTool()
        result = await tool.execute({'loginUrl': 'http://vulnlab.test/login'})
        self.assertTrue(result.get('success'))
        self.assertTrue(result.get('skipped'))


if __name__ == '__main__':
    unittest.main()
