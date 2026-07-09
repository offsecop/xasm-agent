"""#523 — httpx:probe must normalize URL-style inputs so they probe as reliably
as bare hosts.

httpx (v1.6.x) silently emits nothing for a scheme-qualified URL that lacks an
explicit port (`http://host`), so URL inputs produced empty `urls`/`targets`
with success=true and broke downstream web chains, while bare hosts worked. The
normalizer adds the scheme's default port to such URLs and strips it back off
the emitted URLs so URL-input and host-input chains converge.
"""
import os
import sys
import unittest

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(THIS_DIR)
TOOLS_DIR = os.path.join(AGENT_DIR, 'tools')
for d in (AGENT_DIR, TOOLS_DIR):
    if d not in sys.path:
        sys.path.insert(0, d)

from tools.httpx_probe import _normalize_httpx_target, _strip_default_port  # noqa: E402


class TestHttpxTargetNormalize(unittest.TestCase):
    def test_scheme_url_without_port_gets_default_port(self):
        self.assertEqual(_normalize_httpx_target('http://vulnbank.test'), 'http://vulnbank.test:80')
        self.assertEqual(_normalize_httpx_target('https://vulnbank.test'), 'https://vulnbank.test:443')

    def test_paths_userinfo_and_explicit_ports_are_preserved(self):
        self.assertEqual(_normalize_httpx_target('http://x/login'), 'http://x:80/login')
        self.assertEqual(_normalize_httpx_target('http://u:p@x'), 'http://u:p@x:80')
        self.assertEqual(_normalize_httpx_target('http://x:8080'), 'http://x:8080')

    def test_bare_hosts_pass_through_for_auto_probe(self):
        self.assertEqual(_normalize_httpx_target('vulnbank.test'), 'vulnbank.test')
        self.assertEqual(_normalize_httpx_target('vulnbank.test:80'), 'vulnbank.test:80')

    def test_blank_targets_drop_out(self):
        self.assertIsNone(_normalize_httpx_target(''))
        self.assertIsNone(_normalize_httpx_target('   '))
        self.assertIsNone(_normalize_httpx_target(None))

    def test_strip_default_port_reverses_for_clean_output(self):
        self.assertEqual(_strip_default_port('http://vulnbank.test:80'), 'http://vulnbank.test')
        self.assertEqual(_strip_default_port('https://vulnbank.test:443'), 'https://vulnbank.test')
        self.assertEqual(_strip_default_port('http://x:8080'), 'http://x:8080')  # non-default kept

    def test_url_input_and_host_input_converge(self):
        # A URL input, after normalize→probe→strip, yields the same clean target
        # a bare-host input would emit — the core #523 invariant.
        normalized = _normalize_httpx_target('http://vulnbank.test')
        self.assertEqual(_strip_default_port(normalized), 'http://vulnbank.test')


if __name__ == '__main__':
    unittest.main()
