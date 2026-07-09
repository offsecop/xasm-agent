"""#907 — the optional AI-login step must not require loginUrl.

An `authentication:ai_browser_login` step is an *optional* auth step in the
platform "Programmatic Web DAST" template. On an unauthenticated run it carries
no loginUrl/credentials, so it must SKIP gracefully with success — otherwise the
required-param check fails the job and the whole PROGRAMMATIC chain halts.
"""

import asyncio
import os
import sys
import unittest

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(THIS_DIR)
TOOLS_DIR = os.path.join(AGENT_DIR, 'tools')
for d in (AGENT_DIR, TOOLS_DIR):
    if d not in sys.path:
        sys.path.insert(0, d)

from tools.browser_login_ai import BrowserLoginAiTool  # noqa: E402


class TestBrowserLoginAiOptionalLoginUrl907(unittest.TestCase):
    def test_loginurl_is_not_required_in_schema(self):
        # loginUrl must be optional so validate_parameters() lets an
        # unauthenticated job through to execute()'s graceful skip.
        self.assertEqual(BrowserLoginAiTool().schema.get('required'), [])

    def test_execute_skips_gracefully_without_loginurl(self):
        result = asyncio.run(BrowserLoginAiTool().execute({'target': 'https://example.test'}))
        self.assertTrue(result.get('success'))
        self.assertTrue(result.get('skipped'))
        self.assertFalse(result.get('authenticated'))
        self.assertEqual(result.get('cookies'), [])

    def test_execute_skips_when_loginurl_present_but_no_credentials(self):
        # Existing behaviour preserved: loginUrl but no creds also skips.
        result = asyncio.run(
            BrowserLoginAiTool().execute({'loginUrl': 'https://example.test/login'})
        )
        self.assertTrue(result.get('success'))
        self.assertTrue(result.get('skipped'))


if __name__ == '__main__':
    unittest.main()
