import json
import unittest
from unittest import mock

import tools.origami_client_secret_scan as mod
from tools.origami_client_secret_scan import (
    TIER_CRITICAL,
    TIER_HIGH,
    TIER_INFO,
    TIER_LOW,
    TIER_MEDIUM,
    _PROJECT_NUMBER_RE,
    _assert_no_raw_google_key,
    _build_secret_finding,
    _classify_google_key_response,
    _google_test_headers,
    _rtdb_top_level_keys,
    _safe_secret_record,
    _sanitize_scope_details,
    _scan_assets_for_secrets,
    _secret_fingerprint,
    _service_reachable,
    _tier_severity_for_scope,
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


# ===========================================================================
# #769 — deep Google-API capability + Firebase enumeration
# ===========================================================================
class OrigamiDeepGoogleScopeTests(unittest.TestCase):
    def test_tier_free_apis_only_is_info(self):
        # fonts / pagespeed / books are free — no cost-abuse — so INFO.
        scope = {"services": [{"service_id": "fonts", "reachable": True}, {"service_id": "pagespeed", "reachable": True}], "firebase": {}}
        self.assertEqual(_tier_severity_for_scope(scope), TIER_INFO)

    def test_tier_maps_family_is_low(self):
        # An UNRESTRICTED intended-client-side key (whole maps family incl.
        # geolocation/places, + translation) is cost-abuse at worst → LOW.
        for svc in ("maps-static", "geocoding", "directions", "geolocation", "places", "translation"):
            scope = {"services": [{"service_id": svc, "reachable": True}], "firebase": {}}
            self.assertEqual(_tier_severity_for_scope(scope), TIER_LOW, svc)

    def test_tier_geolocation_plus_places_is_low(self):
        # The real segurosmultiples shape — maps/geolocation only → LOW, not MEDIUM.
        scope = {"services": [{"service_id": "geolocation", "reachable": True}, {"service_id": "places", "reachable": True}], "firebase": {}}
        self.assertEqual(_tier_severity_for_scope(scope), TIER_LOW)

    def test_tier_ai_family_is_medium(self):
        scope = {"services": [{"service_id": "gen-language", "reachable": True}, {"service_id": "vision", "reachable": True}], "firebase": {}}
        self.assertEqual(_tier_severity_for_scope(scope), TIER_MEDIUM)

    def test_tier_secret_manager_is_critical(self):
        scope = {"services": [{"service_id": "maps-static", "reachable": True}, {"service_id": "secret-manager", "reachable": True}], "firebase": {}}
        self.assertEqual(_tier_severity_for_scope(scope), TIER_CRITICAL)

    def test_tier_firebase_rtdb_open_is_critical(self):
        scope = {"services": [{"service_id": "fonts", "reachable": True}], "firebase": {"rtdb_access": "OPEN"}}
        self.assertEqual(_tier_severity_for_scope(scope), TIER_CRITICAL)

    def test_tier_firebase_authenticated_plus_storage_is_high(self):
        scope = {"services": [], "firebase": {"rtdb_access": "AUTHENTICATED", "storage_listable": True}}
        self.assertEqual(_tier_severity_for_scope(scope), TIER_HIGH)

    def test_tier_bigquery_is_high(self):
        scope = {"services": [{"service_id": "bigquery", "reachable": True}], "firebase": {}}
        self.assertEqual(_tier_severity_for_scope(scope), TIER_HIGH)

    def test_tier_nothing_reachable_is_info(self):
        scope = {"services": [{"service_id": "secret-manager", "reachable": False}], "firebase": {"rtdb_access": "SECURED"}}
        self.assertEqual(_tier_severity_for_scope(scope), TIER_INFO)

    def test_service_reachable_only_200(self):
        self.assertTrue(_service_reachable(200))
        self.assertFalse(_service_reachable(403))
        self.assertFalse(_service_reachable(400))
        self.assertFalse(_service_reachable(None))

    def test_project_number_extraction_regex(self):
        m = _PROJECT_NUMBER_RE.search("The API ... is not enabled for project 836575658406 has not been used")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "836575658406")

    def test_rtdb_top_level_keys_names_only(self):
        self.assertEqual(sorted(_rtdb_top_level_keys('{"users": true, "config": true}')), ["config", "users"])
        self.assertEqual(_rtdb_top_level_keys("[1,2,3]"), [])
        self.assertEqual(_rtdb_top_level_keys("not json"), [])
        self.assertEqual(_rtdb_top_level_keys(None), [])

    def test_sanitize_scope_caps_lists(self):
        scope = {"firebase": {
            "topLevelKeys": [f"k{i}" for i in range(50)],
            "collections": [f"c{i}" for i in range(50)],
            "sampleFiles": [f"f{i}" for i in range(50)],
        }}
        out = _sanitize_scope_details(scope)
        self.assertEqual(len(out["firebase"]["topLevelKeys"]), 10)
        self.assertEqual(len(out["firebase"]["collections"]), 10)
        self.assertEqual(len(out["firebase"]["sampleFiles"]), 5)

    def test_assert_no_raw_google_key_scrubs_nested(self):
        key = "AIza" + ("C" * 35)
        cleaned = _assert_no_raw_google_key({"a": {"b": f"leak {key} here"}, "list": [key]})
        serialized = json.dumps(cleaned)
        self.assertNotIn(key, serialized)
        self.assertIn("[REDACTED_GOOGLE_API_KEY]", serialized)

    def test_deep_severity_and_scope_flow_into_finding(self):
        raw = "AIza" + ("D" * 35)
        assets = [{
            "url": "https://x.test/a.js", "finalUrl": "https://x.test/a.js",
            "status": 200, "headers": {}, "assetType": "javascript", "text": f'k="{raw}"',
        }]
        matches = _scan_assets_for_secrets(assets)
        deep_test = {
            "status": "accepted", "httpStatus": 200, "reason": "deep", "severity": "critical",
            "scope": {"tier": "critical",
                      "services": [{"service_id": "secret-manager", "reachable": True}],
                      "firebase": {"rtdb_access": "OPEN", "topLevelKeys": ["users"]}},
        }
        finding = _build_secret_finding(matches[0], deep_test)
        self.assertEqual(finding["info"]["severity"], "critical")
        self.assertEqual(finding["evidence"]["googleApiKeyTest"]["scope"]["tier"], "critical")
        self.assertEqual(finding["evidence"]["googleApiKeyTest"]["scope"]["firebase"]["topLevelKeys"], ["users"])
        self.assertNotIn(raw, json.dumps(finding))


class OrigamiAggressiveGateTests(unittest.IsolatedAsyncioTestCase):
    """The deep phase must ONLY arm under aggressive=true + engagement=lab."""

    async def _run(self, params):
        raw = "AIza" + ("B" * 35)
        shallow_calls, deep_calls = [], []

        async def fake_fetch(session, url, *, method="GET", headers=None, data=None, max_bytes=2_000_000):
            return {"url": url, "status": 200,
                    "headers": {"Content-Type": "application/javascript"},
                    "text": f'var k="{raw}";', "truncated": False}

        async def fake_shallow(session, key, *, headers):
            shallow_calls.append(key)
            return {"fingerprint": _secret_fingerprint(key), "maskedValue": "m",
                    "status": "accepted", "httpStatus": 200, "reason": "r",
                    "endpoint": "e", "request": "q", "response": "s"}

        async def fake_deep(session, key, *, headers, max_services=12):
            deep_calls.append((key, max_services))
            return {"fingerprint": _secret_fingerprint(key), "maskedValue": "m",
                    "status": "accepted", "httpStatus": 200, "reason": "deep",
                    "endpoint": "e", "severity": "critical",
                    "scope": {"tier": "critical", "services": [], "project": {}, "firebase": {}}}

        with mock.patch.object(mod, "fetch_text", fake_fetch), \
             mock.patch.object(mod, "_test_google_api_key", fake_shallow), \
             mock.patch.object(mod, "_deep_test_google_api_key", fake_deep):
            tool = mod.OrigamiClientSecretScanTool()
            result = await tool.execute(dict(params))
        return result, shallow_calls, deep_calls

    async def test_off_aggressive_uses_shallow_only(self):
        _, shallow, deep = await self._run({"target": "https://app.lumenfield.test/main.js"})
        self.assertEqual(len(deep), 0)
        self.assertEqual(len(shallow), 1)

    async def test_aggressive_without_lab_stays_shallow(self):
        _, shallow, deep = await self._run(
            {"target": "https://app.lumenfield.test/main.js", "aggressive": True, "engagement": "prod"}
        )
        self.assertEqual(len(deep), 0)
        self.assertEqual(len(shallow), 1)

    async def test_aggressive_lab_arms_deep_and_flows_severity(self):
        result, shallow, deep = await self._run(
            {"target": "https://app.lumenfield.test/main.js", "aggressive": True,
             "engagement": "lab", "maxServicesPerKey": 8}
        )
        self.assertEqual(len(shallow), 0)
        self.assertEqual(len(deep), 1)
        self.assertEqual(deep[0][1], 8)  # maxServicesPerKey propagated
        findings = result.get("findings") or []
        self.assertTrue(any(f["info"]["severity"] == "critical" for f in findings))


class OrigamiFirebaseSamplingTests(unittest.IsolatedAsyncioTestCase):
    """#769 sqlmap-parity — bounded raw proof-of-impact samples from OPEN services."""

    def test_rtdb_sample_caps_records(self):
        big = json.dumps({f"k{i}": {"v": i} for i in range(10)})
        s = mod._rtdb_sample(big)
        self.assertEqual(len(s), mod.SAMPLE_MAX_RECORDS)
        self.assertIsNone(mod._rtdb_sample("not json"))
        self.assertEqual(mod._rtdb_sample(json.dumps([1, 2, 3, 4, 5])), [1, 2, 3])

    async def test_rtdb_open_captures_bounded_sample(self):
        async def fake_fetch(session, url, *, method="GET", headers=None, data=None, max_bytes=2_000_000):
            if "shallow=true" in url and "orderBy" not in url:
                return {"status": 200, "text": json.dumps({"users": True, "orders": True, "config": True})}
            if "orderBy" in url:
                return {"status": 200, "text": json.dumps({f"rec{i}": {"pii": f"data{i}"} for i in range(8)})}
            return {"status": 404, "text": ""}

        with mock.patch.object(mod, "fetch_text", fake_fetch):
            res = await mod._firebase_rtdb_shallow(None, "demo-proj", None)
        self.assertEqual(res["access"], "OPEN")
        self.assertIn("users", res["topLevelKeys"])
        self.assertIsNotNone(res["sample"])
        self.assertEqual(len(res["sample"]), mod.SAMPLE_MAX_RECORDS)

    async def test_rtdb_secured_yields_no_sample(self):
        async def fake_fetch(session, url, *, method="GET", headers=None, data=None, max_bytes=2_000_000):
            return {"status": 401, "text": "Permission denied"}

        with mock.patch.object(mod, "fetch_text", fake_fetch):
            res = await mod._firebase_rtdb_shallow(None, "demo-proj", None)
        self.assertEqual(res["access"], "SECURED")
        self.assertIsNone(res["sample"])

    async def test_firestore_open_captures_sample_docs(self):
        docs = {"documents": [
            {"name": "projects/p/databases/(default)/documents/users/u1", "fields": {"email": {"stringValue": "a@b.test"}}},
            {"name": "projects/p/databases/(default)/documents/users/u2", "fields": {"email": {"stringValue": "c@d.test"}}},
        ]}

        async def fake_fetch(session, url, *, method="GET", headers=None, data=None, max_bytes=2_000_000):
            return {"status": 200, "text": json.dumps(docs)}

        with mock.patch.object(mod, "fetch_text", fake_fetch):
            res = await mod._firestore_collections(None, "k", "demo-proj", {})
        self.assertTrue(res["open"])
        self.assertEqual(res["collections"], ["users"])
        self.assertEqual(len(res["sample"]), 2)
        self.assertEqual(res["sample"][0]["collection"], "users")
        self.assertIn("email", res["sample"][0]["fields"])

    async def test_storage_listable_captures_file_metadata(self):
        items = {"items": [{"name": f"f{i}.jpg", "size": str(i * 100), "contentType": "image/jpeg"} for i in range(8)]}

        async def fake_fetch(session, url, *, method="GET", headers=None, data=None, max_bytes=2_000_000):
            return {"status": 200, "text": json.dumps(items)}

        with mock.patch.object(mod, "fetch_text", fake_fetch):
            res = await mod._firebase_storage(None, "demo-proj")
        self.assertTrue(res["listable"])
        self.assertEqual(res["itemCount"], 8)
        self.assertEqual(len(res["sampleFiles"]), mod.SAMPLE_MAX_FILES)
        self.assertEqual(len(res["sample"]), mod.SAMPLE_MAX_FILES)
        self.assertEqual(res["sample"][0]["contentType"], "image/jpeg")


if __name__ == "__main__":
    unittest.main()
