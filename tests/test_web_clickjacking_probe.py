import asyncio
import sys
import unittest
from pathlib import Path

AGENT_ROOT = Path(__file__).resolve().parents[1]
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from tools.web_clickjacking_probe import (  # noqa: E402
    MODE,
    PREFILLED_EMAIL,
    WebClickjackingProbeTool,
    _center,
    _center_inside,
    _browser_auth_cookies,
    _framing_protected,
    _parse_exploit_form,
    _rect_valid,
    _safe_url,
    _sensitive_action_pattern,
    _stable_account_entrypoint,
    _validate_target,
    build_overlay_html,
)


class WebClickjackingProbeTests(unittest.TestCase):
    def setUp(self):
        self.tool = WebClickjackingProbeTool()
        self.rect = {"x": 340, "y": 420, "width": 150, "height": 48}

    def test_publishes_closed_root_only_schema(self):
        schema = self.tool.schema
        self.assertEqual(self.tool.name, "web:clickjacking_probe")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["required"], ["target"])
        self.assertEqual(schema["properties"]["mode"]["enum"], [MODE])
        for forbidden in (
            "path", "selector", "coordinates", "viewport", "iframe", "html",
            "script", "payload", "cookie", "headers", "exploitServer", "deliver",
        ):
            self.assertNotIn(forbidden, schema["properties"])

    def test_validates_root_target_and_same_origin_children(self):
        target = "https://lab.example/"
        self.assertEqual(_validate_target(target), target)
        self.assertIsNone(_validate_target("https://user:pass@lab.example/"))
        self.assertIsNone(_validate_target("https://lab.example/?path=/my-account"))
        self.assertEqual(_safe_url(target, "/my-account"), "https://lab.example/my-account")
        self.assertIsNone(_safe_url(target, "https://outside.example/my-account"))

    def test_requires_effective_browser_framing_not_header_absence_only(self):
        self.assertFalse(_framing_protected({"content-type": "text/html"}))
        self.assertTrue(_framing_protected({"X-Frame-Options": "DENY"}))
        self.assertTrue(
            _framing_protected({"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"})
        )

    def test_builds_one_script_free_fixed_viewport_overlay(self):
        content = build_overlay_html(
            "https://lab.example/my-account",
            self.rect,
            "xasm-clickjacking-0123456789abcdef01234567",
        )
        self.assertIn("width:1920px;height:1080px", content)
        self.assertIn("opacity:.0001", content)
        self.assertIn("z-index:2}</style>", content)
        self.assertNotIn("z-index:2}}</style>", content)
        self.assertIn('<div id="xasm-decoy">Click me</div>', content)
        self.assertIn('sandbox="allow-forms"', content)
        self.assertNotIn('<button id="xasm-decoy"', content)
        self.assertIn('src="https://lab.example/my-account"', content)
        self.assertNotIn("<script", content.lower())
        self.assertNotRegex(content.lower(), r"\bon[a-z]+\s*=")

    def test_requires_valid_aligned_geometry(self):
        self.assertTrue(_rect_valid(self.rect))
        self.assertEqual(_center(self.rect), {"x": 415.0, "y": 444.0})
        self.assertTrue(_center_inside(_center(self.rect), self.rect))
        self.assertFalse(_rect_valid({"x": 1900, "y": 0, "width": 100, "height": 20}))

    def test_https_browser_control_preserves_cross_site_session_visibility(self):
        self.assertEqual(
            _browser_auth_cookies("session=opaque", "https://lab.example"),
            [
                {
                    "name": "session",
                    "value": "opaque",
                    "url": "https://lab.example",
                    "secure": True,
                    "sameSite": "None",
                }
            ],
        )
        self.assertEqual(
            _browser_auth_cookies("session=fixture", "http://lab.example"),
            [{"name": "session", "value": "fixture", "url": "http://lab.example"}],
        )

    def test_keeps_victim_neutral_account_entrypoint_after_user_redirect(self):
        self.assertEqual(
            _stable_account_entrypoint(
                "https://lab.example/my-account",
                "https://lab.example/my-account?id=wiener",
                "Delete account",
            ),
            "https://lab.example/my-account",
        )
        self.assertIsNone(
            _stable_account_entrypoint(
                "https://lab.example/my-account",
                "https://outside.example/my-account?id=wiener",
                "Delete account",
            )
        )
        self.assertEqual(
            _stable_account_entrypoint(
                "https://lab.example/my-account",
                "https://lab.example/my-account?id=wiener",
                "Update email",
            ),
            f"https://lab.example/my-account?email={PREFILLED_EMAIL.replace('@', '%40')}",
        )

    def test_uses_the_same_closed_action_matcher_for_direct_and_framed_controls(self):
        self.assertIsNotNone(_sensitive_action_pattern("Delete account").fullmatch("delete account"))
        self.assertIsNotNone(_sensitive_action_pattern("Update email").fullmatch("Update email"))
        with self.assertRaisesRegex(ValueError, "unsupported"):
            _sensitive_action_pattern("Transfer funds")

    def test_parses_only_closed_store_deliver_form(self):
        body = """
        <form method="POST" action="/">
          <input name="urlIsHttps"><input name="responseFile"><input name="responseHead">
          <textarea name="responseBody"></textarea>
          <input type="submit" name="formAction" value="STORE">
          <input type="submit" name="formAction" value="DELIVER_TO_VICTIM">
        </form>
        """
        parsed = _parse_exploit_form(body, "https://exploit.example/")
        self.assertEqual(parsed["storedUrl"], "https://exploit.example/exploit")
        self.assertEqual(parsed["storeValue"], "STORE")
        self.assertEqual(parsed["deliverValue"], "DELIVER_TO_VICTIM")
        self.assertIsNone(_parse_exploit_form(body.replace('method="POST"', 'method="GET"'), "https://exploit.example/"))

    def test_rejects_lab_delivery_without_every_server_gate(self):
        result = asyncio.run(
            self.tool.execute(
                {
                    "target": "https://lab.example/",
                    "mode": MODE,
                    "proofLevel": "lab-state-change",
                    "engagement": "lab",
                    "allowUnsafeMethods": True,
                    "stateChangeApproved": True,
                    "labVictimDeliveryApproved": False,
                    "allowDiscoveredExploitServer": True,
                }
            )
        )
        self.assertFalse(result["success"])
        self.assertIn("every server-owned approval gate", result["error"])
        self.assertFalse(result["fallback"])


if __name__ == "__main__":
    unittest.main()
