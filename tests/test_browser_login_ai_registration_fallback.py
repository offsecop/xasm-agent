import os
import sys
import unittest

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(THIS_DIR)
TOOLS_DIR = os.path.join(AGENT_DIR, 'tools')
for d in (AGENT_DIR, TOOLS_DIR):
    if d not in sys.path:
        sys.path.insert(0, d)

from tools.browser_login_ai import (  # noqa: E402
    build_registration_candidate_urls,
    registration_fallback_allowed,
)


class TestBrowserLoginAiRegistrationFallback(unittest.TestCase):
    def test_registration_requires_explicit_profile_instruction(self):
        self.assertFalse(registration_fallback_allowed(None))
        self.assertFalse(registration_fallback_allowed('Log in with the supplied credentials.'))
        self.assertTrue(
            registration_fallback_allowed(
                'If the account does not exist, navigate to registration and create a new account.'
            )
        )

    def test_registration_candidates_stay_same_origin_and_deduplicate(self):
        urls = build_registration_candidate_urls(
            'https://vulnbank.org/login',
            ['/register', 'https://evil.example/register', '/register/'],
        )

        self.assertEqual(urls[0], 'https://vulnbank.org/register')
        self.assertNotIn('https://evil.example/register', urls)
        self.assertEqual(len(urls), len({url.rstrip('/') for url in urls}))


if __name__ == '__main__':
    unittest.main()
