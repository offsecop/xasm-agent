import json
import unittest

from tools.origami_client_secret_scan import (
    _build_secret_finding,
    _classify_google_key_response,
    _google_test_headers,
    _safe_secret_record,
    _scan_assets_for_secrets,
    _secret_fingerprint,
)


GOOGLE_API_KEY = "AIza" + ("A" * 35)


class OrigamiClientSecretScanTests(unittest.TestCase):
    def test_google_api_key_is_redacted_from_records_and_finding(self):
        assets = [
            {
                "url": "https://example.test/static/app.js",
                "finalUrl": "https://example.test/static/app.js",
                "status": 200,
                "headers": {"Content-Type": "application/javascript"},
                "assetType": "javascript",
                "text": f"window.__config = {{ googleKey: '{GOOGLE_API_KEY}' }};",
            }
        ]

        matches = _scan_assets_for_secrets(assets)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["type"], "google_api_key")

        google_test = {
            "fingerprint": _secret_fingerprint(GOOGLE_API_KEY),
            "maskedValue": "AIzaAA...[REDACTED]...AAAA",
            "status": "accepted",
            "httpStatus": 200,
            "reason": "Key was accepted by the Google Discovery API.",
            "endpoint": "https://www.googleapis.com/discovery/v1/apis?key=[REDACTED_GOOGLE_API_KEY]",
            "request": "GET /discovery/v1/apis?key=[REDACTED_GOOGLE_API_KEY] HTTP/1.1",
            "response": "HTTP/1.1 200\n\n{}",
        }

        record = _safe_secret_record(matches[0], google_test)
        finding = _build_secret_finding(matches[0], google_test)
        serialized = json.dumps({"record": record, "finding": finding})

        self.assertNotIn(GOOGLE_API_KEY, serialized)
        self.assertIn("[REDACTED]", serialized)
        self.assertEqual(record["googleApiKeyTest"]["status"], "accepted")
        self.assertEqual(finding["info"]["severity"], "medium")

    def test_google_api_key_response_classification(self):
        self.assertEqual(_classify_google_key_response(200, "{}")[0], "accepted")
        self.assertEqual(
            _classify_google_key_response(400, "API key not valid. Please pass a valid API key.")[0],
            "invalid",
        )
        self.assertEqual(_classify_google_key_response(403, "API_KEY_SERVICE_BLOCKED")[0], "restricted")

    def test_google_api_key_test_headers_do_not_forward_target_auth(self):
        headers = _google_test_headers(
            {
                "User-Agent": "target-agent",
                "Cookie": "session=secret",
                "Authorization": "Bearer secret",
                "X-Api-Key": "secret",
            }
        )

        self.assertEqual(headers["User-Agent"], "target-agent")
        self.assertEqual(headers["Accept"], "application/json,*/*;q=0.8")
        self.assertNotIn("Cookie", headers)
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("X-Api-Key", headers)


if __name__ == "__main__":
    unittest.main()
