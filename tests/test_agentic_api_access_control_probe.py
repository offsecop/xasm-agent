"""Locks for the #319 privilege-field mass-assignment phase of api:access_control_probe.

The tool is read-only by default; under aggressive:true + engagement:lab it attempts
role/is_admin mass-assignment on object-update endpoints and confirms via GET read-back
before flagging. These tests use a stateful in-memory user store (subclass override of
the network methods _fetch/_write) so the read-back confirmation path is exercised end
to end without any real HTTP.
"""

import json
import re
import unittest

from tools.agentic_api_access_control_probe import ApiAccessControlProbeTool


class FakeStoreTool(ApiAccessControlProbeTool):
    """api:access_control_probe wired to an in-memory /api/users/<id> store.

    `vulnerable=True` mirrors the HTB Facts / vulnlab fixture: any client-supplied
    role/is_admin field is mass-assigned with no whitelist and no ownership check.
    `vulnerable=False` accepts writes (HTTP 200) but never mutates state — the
    read-back FP-kill must reject these.
    """

    def __init__(self):
        super().__init__()
        self.store = {
            1: {"id": 1, "username": "admin", "email": "admin@lab.test", "role": "admin"},
            2: {"id": 2, "username": "user", "email": "user@lab.test", "role": "user"},
            3: {"id": 3, "username": "jdoe", "email": "jdoe@lab.test", "role": "user"},
        }
        self.write_calls = []
        self.vulnerable = True

    @staticmethod
    def _uid(url):
        match = re.search(r"/api/users/(\d+)", url)
        return int(match.group(1)) if match else None

    def _json_response(self, url, uid, method=None):
        body = json.dumps(self.store[uid])
        out = {
            "url": url,
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": body,
            "elapsedMs": 1,
            "jsonKeys": self._json_keys(body),
            "bodyLength": len(body),
            "sensitiveBodyMarkers": self._sensitive_body_markers(body),
        }
        if method:
            out["method"] = method
        return out

    @staticmethod
    def _not_found(url, method=None):
        out = {
            "url": url, "status": 404, "headers": {}, "body": "",
            "elapsedMs": 1, "jsonKeys": [], "bodyLength": 0, "sensitiveBodyMarkers": [],
        }
        if method:
            out["method"] = method
        return out

    async def _discover_readonly_endpoints(self, target, parameters, max_endpoints):
        return []  # keep the unit test fully offline

    async def _fetch(self, session, method, url, headers):
        uid = self._uid(url)
        if uid is None or uid not in self.store:
            return self._not_found(url)
        return self._json_response(url, uid)

    async def _write(self, session, method, url, kind, payload, headers):
        self.write_calls.append({"method": method, "url": url, "kind": kind, "payload": payload})
        uid = self._uid(url)
        if uid is None or uid not in self.store:
            return self._not_found(url, method)
        if self.vulnerable and isinstance(payload, dict):
            merged = {}
            for key, value in payload.items():
                if isinstance(value, dict):
                    merged.update(value)  # JSON-nested {"user": {...}}
                else:
                    nested = re.match(r"^\w+\[(\w+)\]$", str(key))  # form user[role]
                    merged[nested.group(1) if nested else key] = value
            if "role" in merged:
                self.store[uid]["role"] = str(merged["role"])
            for bool_field in ("is_admin", "admin", "isAdmin", "is_staff", "is_superuser", "superuser"):
                if bool_field in merged and str(merged[bool_field]).lower() in ("true", "1", "yes"):
                    self.store[uid]["role"] = "admin"
        return self._json_response(url, uid, method)


class ObservedIdentifierReplayTool(ApiAccessControlProbeTool):
    """Offline API whose anonymous index exposes an identifier used by a read route."""

    observed_account = "502001"

    def __init__(self, control_same_shape=False):
        super().__init__()
        self.fetch_calls = []
        self.control_same_shape = control_same_shape

    async def _discover_readonly_endpoints(self, target, parameters, max_endpoints):
        return [
            {
                "method": "GET",
                "url": "https://bank.test/check_balance/1",
                "path": "/check_balance/1",
                "source": "openapi",
                "originalPath": "/check_balance/{account_number}",
            },
            {
                "method": "GET",
                "url": "https://bank.test/debug/users",
                "path": "/debug/users",
                "source": "openapi",
                "originalPath": "/debug/users",
            },
        ]

    def _response(self, url, status, document):
        body = json.dumps(document)
        return {
            "url": url,
            "status": status,
            "headers": {"Content-Type": "application/json"},
            "body": body,
            "elapsedMs": 1,
            "jsonKeys": self._json_keys(body),
            "bodyLength": len(body),
            "sensitiveBodyMarkers": self._sensitive_body_markers(body),
        }

    async def _fetch(self, session, method, url, headers):
        self.fetch_calls.append({"method": method, "url": url, "headers": dict(headers)})
        if url == "https://bank.test/debug/users":
            return self._response(
                url,
                200,
                {"users": [{"username": "alice", "account_number": self.observed_account}]},
            )
        if url == f"https://bank.test/check_balance/{self.observed_account}":
            return self._response(
                url,
                200,
                {"username": "alice", "account_number": self.observed_account, "balance": 1250},
            )
        if self.control_same_shape and url == "https://bank.test/check_balance/xasm-invalid-id":
            return self._response(
                url,
                200,
                {"username": "fallback", "account_number": "fallback", "balance": 0},
            )
        return self._response(url, 404, {"error": "not found"})


class StaticCandidateBudgetTool(ApiAccessControlProbeTool):
    def __init__(self):
        super().__init__()
        self.fetch_calls = []

    async def _discover_readonly_endpoints(self, target, parameters, max_endpoints):
        return [
            {
                "method": "GET",
                "url": f"https://bank.test/_next/static/chunks/{index}-deadbeef.js",
                "path": f"/_next/static/chunks/{index}-deadbeef.js",
            }
            for index in range(20)
        ] + [
            {
                "method": "GET",
                "url": "https://bank.test/health",
                "path": "/health",
            }
        ]

    async def _fetch(self, session, method, url, headers):
        self.fetch_calls.append(url)
        return {
            "url": url,
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '{"ok":true}',
            "elapsedMs": 1,
            "jsonKeys": ["ok"],
            "bodyLength": 11,
            "sensitiveBodyMarkers": [],
        }


def _params(**extra):
    base = {"target": "http://lab.test/", "urls": ["http://lab.test/api/users/2"],
            "includeAnonymousComparison": False, "includeIdMutation": False}
    base.update(extra)
    return base


def _privesc_findings(result):
    return [f for f in result["findings"] if f.get("template-id") == "xasm-api-mass-assignment-privesc"]


class GateTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_is_read_only_no_writes(self):
        tool = FakeStoreTool()
        result = await tool.execute(_params())
        self.assertEqual(tool.write_calls, [])
        self.assertFalse(result["summary"]["privilegeMutationRan"])
        self.assertEqual(tool.store[2]["role"], "user")
        self.assertEqual(_privesc_findings(result), [])

    async def test_aggressive_without_lab_stays_read_only(self):
        tool = FakeStoreTool()
        result = await tool.execute(_params(aggressive=True, engagement="safe"))
        self.assertEqual(tool.write_calls, [])
        self.assertFalse(result["summary"]["privilegeMutationRan"])

    async def test_lab_without_aggressive_stays_read_only(self):
        tool = FakeStoreTool()
        result = await tool.execute(_params(aggressive=False, engagement="lab"))
        self.assertEqual(tool.write_calls, [])
        self.assertFalse(result["summary"]["privilegeMutationRan"])

    async def test_include_flag_disables_phase(self):
        tool = FakeStoreTool()
        result = await tool.execute(
            _params(aggressive=True, engagement="lab", includePrivilegeMutation=False)
        )
        self.assertEqual(tool.write_calls, [])
        self.assertFalse(result["summary"]["privilegeMutationRan"])


class MutationTests(unittest.IsolatedAsyncioTestCase):
    async def test_confirmed_self_privesc_is_critical(self):
        tool = FakeStoreTool()
        result = await tool.execute(_params(aggressive=True, engagement="lab"))
        self.assertTrue(result["summary"]["privilegeMutationRan"])
        findings = _privesc_findings(result)
        self_findings = [f for f in findings if f["evidence"]["scope"] == "self-id"]
        self.assertTrue(self_findings, "expected a self-id privilege-escalation finding")
        finding = self_findings[0]
        self.assertEqual(finding["info"]["severity"], "critical")
        self.assertEqual(finding["matcher-name"], "privilege-field-mass-assignment-confirmed")
        self.assertIn("mass-assignment", finding["info"]["tags"])
        self.assertIn("CWE-915", finding["info"]["classification"]["cwe-id"])
        self.assertIn("API3:2023", finding["info"]["classification"]["owasp"])
        # best-effort restore leaves the object as found
        self.assertEqual(tool.store[2]["role"], "user")

    async def test_neighbor_id_bola_write_flagged(self):
        tool = FakeStoreTool()
        result = await tool.execute(_params(aggressive=True, engagement="lab"))
        findings = _privesc_findings(result)
        scopes = {f["evidence"]["scope"] for f in findings}
        self.assertIn("self-id", scopes)
        self.assertIn("neighbor-id", scopes)
        neighbor = next(f for f in findings if f["evidence"]["scope"] == "neighbor-id")
        self.assertEqual(neighbor["matcher-name"], "neighbor-object-privilege-write")
        self.assertIn("bola", neighbor["info"]["tags"])

    async def test_readback_fp_kill_write_200_but_no_change(self):
        tool = FakeStoreTool()
        tool.vulnerable = False  # writes return 200 but never change state
        result = await tool.execute(_params(aggressive=True, engagement="lab"))
        self.assertTrue(tool.write_calls, "writes should still be attempted")
        self.assertEqual(_privesc_findings(result), [], "a write 200 alone must never flag")

    async def test_already_admin_self_not_flagged(self):
        tool = FakeStoreTool()
        result = await tool.execute(
            _params(urls=["http://lab.test/api/users/1"],
                    objectUpdatePaths=["/api/users/1"],
                    aggressive=True, engagement="lab")
        )
        self_findings = [
            f for f in _privesc_findings(result) if f["evidence"]["scope"] == "self-id"
            and f["matched-at"].endswith("/api/users/1")
        ]
        self.assertEqual(self_findings, [], "an already-admin object can't prove escalation")

    async def test_rails_nested_encoding_attempted_first_for_role(self):
        tool = FakeStoreTool()
        await tool.execute(_params(aggressive=True, engagement="lab"))
        nested = [c for c in tool.write_calls if "user[role]" in str(c["payload"])]
        self.assertTrue(nested, "Rails-nested user[role]=admin payload must be attempted")
        self.assertEqual(nested[0]["kind"], "form")

    async def test_session_cookie_redacted_in_findings(self):
        tool = FakeStoreTool()
        result = await tool.execute(
            _params(aggressive=True, engagement="lab",
                    authCookies="vulnlab.sid=SUPERSECRETTOKEN")
        )
        self.assertTrue(_privesc_findings(result))
        blob = json.dumps(result["findings"])
        self.assertNotIn("SUPERSECRETTOKEN", blob)
        self.assertIn("[REDACTED]", blob)


class ObservedIdentifierReplayTests(unittest.IsolatedAsyncioTestCase):
    async def test_replays_anonymous_identifier_into_matching_readonly_template(self):
        tool = ObservedIdentifierReplayTool()
        result = await tool.execute(
            {
                "target": "https://bank.test/",
                "includeIdMutation": False,
                "maxRequests": 8,
            }
        )

        findings = [
            finding
            for finding in result["findings"]
            if finding.get("template-id") == "xasm-api-anonymous-observed-object-read"
        ]
        self.assertEqual(len(findings), 1)
        self.assertTrue(
            any(call["url"].endswith(f"/check_balance/{tool.observed_account}") for call in tool.fetch_calls),
            "the private identifier must be used by the actual same-origin request",
        )
        finding = findings[0]
        self.assertIn("GET /check_balance/redacted-account_number HTTP/1.1", finding["request"])
        self.assertIn("HTTP/1.1 200 OK", finding["response"])
        self.assertIn('"account_number": "[REDACTED_ID]"', finding["response"])
        self.assertIn("GET /check_balance/xasm-invalid-id HTTP/1.1", finding["evidence"]["controlRequest"])
        self.assertEqual(finding["evidence"]["controlStatus"], 404)
        self.assertEqual(finding["evidence"]["sourcePaths"], ["/debug/users"])
        self.assertEqual(result["summary"]["observedIdentifierFields"], ["account_number"])
        self.assertEqual(result["summary"]["observedIdentifierRequests"], 2)
        self.assertNotIn(tool.observed_account, json.dumps(result), "raw identifiers must not enter public output")

    async def test_successful_same_shape_control_kills_false_positive(self):
        tool = ObservedIdentifierReplayTool(control_same_shape=True)
        result = await tool.execute(
            {
                "target": "https://bank.test/",
                "includeIdMutation": False,
                "maxRequests": 8,
            }
        )

        findings = [
            finding
            for finding in result["findings"]
            if finding.get("template-id") == "xasm-api-anonymous-observed-object-read"
        ]
        self.assertEqual(findings, [])

    async def test_total_request_budget_includes_replay_and_control(self):
        tool = ObservedIdentifierReplayTool()
        result = await tool.execute(
            {
                "target": "https://bank.test/",
                "includeIdMutation": False,
                "maxRequests": 4,
            }
        )

        self.assertEqual(result["requestsRun"], 4)
        self.assertEqual(len(tool.fetch_calls), 4)
        self.assertLessEqual(result["requestsRun"], 4)

    async def test_cross_origin_template_is_never_requested(self):
        tool = ObservedIdentifierReplayTool()

        async def cross_origin_discovery(target, parameters, max_endpoints):
            endpoints = await ObservedIdentifierReplayTool._discover_readonly_endpoints(
                tool, target, parameters, max_endpoints
            )
            endpoints.append(
                {
                    "method": "GET",
                    "url": "https://other.test/accounts/1",
                    "path": "/accounts/1",
                    "source": "openapi",
                    "originalPath": "/accounts/{account_number}",
                }
            )
            return endpoints

        tool._discover_readonly_endpoints = cross_origin_discovery
        await tool.execute(
            {
                "target": "https://bank.test/",
                "includeIdMutation": False,
                "maxRequests": 10,
            }
        )

        self.assertFalse(any(call["url"].startswith("https://other.test/") for call in tool.fetch_calls))


class StaticCandidateBudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_static_candidates_are_filtered_before_endpoint_budget(self):
        tool = StaticCandidateBudgetTool()

        result = await tool.execute(
            {
                "target": "https://bank.test/",
                "maxEndpoints": 2,
                "maxRequests": 2,
                "includeAnonymousComparison": False,
                "includeIdMutation": False,
            }
        )

        self.assertEqual(result["staticCandidatesFiltered"], 20)
        self.assertEqual(result["summary"]["staticCandidatesFiltered"], 20)
        self.assertTrue(any(url.endswith("/health") for url in tool.fetch_calls))
        self.assertFalse(any("/_next/static/" in url for url in tool.fetch_calls))


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.tool = ApiAccessControlProbeTool()

    def test_rails_resource_singularizes_collection(self):
        self.assertEqual(self.tool._rails_resource("http://x/admin/users/1"), "user")
        self.assertEqual(self.tool._rails_resource("http://x/api/accounts/2"), "account")
        self.assertEqual(self.tool._rails_resource("http://x/api/people/3"), "person")

    def test_payloads_cover_form_and_json_for_role(self):
        payloads = self.tool._mass_assignment_payloads("http://x/admin/users/1", "role")
        kinds = {kind for kind, _, _ in payloads}
        self.assertEqual(kinds, {"form", "json"})
        # Rails-nested form is present
        self.assertTrue(any(p == {"user[role]": "admin"} for _, p, _ in payloads))
        # injected value for a string field is the literal admin
        self.assertTrue(all(inj == "admin" for _, _, inj in payloads))

    def test_payloads_use_boolean_true_for_is_admin(self):
        payloads = self.tool._mass_assignment_payloads("http://x/api/users/1", "is_admin")
        self.assertTrue(all(inj is True for _, _, inj in payloads))

    def test_values_equal_handles_bool_and_string_shapes(self):
        self.assertTrue(self.tool._values_equal("admin", "admin"))
        self.assertTrue(self.tool._values_equal("true", True))
        self.assertTrue(self.tool._values_equal(True, True))
        self.assertFalse(self.tool._values_equal("user", "admin"))
        self.assertFalse(self.tool._values_equal(None, "admin"))
        self.assertFalse(self.tool._values_equal("false", True))

    def test_extract_field_value_reads_nested_json(self):
        resp = {"body": json.dumps({"data": {"user": {"role": "admin"}}})}
        self.assertEqual(self.tool._extract_field_value(resp, "role"), "admin")
        self.assertIsNone(self.tool._extract_field_value({"body": "<html>not json</html>"}, "role"))

    def test_endpoint_dedupe_prefers_openapi_template_metadata(self):
        endpoints = self.tool._dedupe_endpoints(
            [
                {"method": "GET", "url": "https://bank.test/accounts/1", "path": "/accounts/1"},
                {
                    "method": "GET",
                    "url": "https://bank.test/accounts/1",
                    "path": "/accounts/1",
                    "source": "openapi",
                    "originalPath": "/accounts/{account_id}",
                },
            ]
        )
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["originalPath"], "/accounts/{account_id}")

    def test_framework_chunks_maps_fonts_images_and_styles_are_static(self):
        static_urls = [
            "https://bank.test/_next/static/chunks/117-abc123.js",
            "https://bank.test/_nuxt/app.mjs",
            "https://bank.test/assets/css/main.css?v=3",
            "https://bank.test/static/media/logo.svg",
            "https://bank.test/fonts/inter.woff2",
            "https://bank.test/app.js.map",
            "https://bank.test/images/hero.webp",
        ]

        for url in static_urls:
            with self.subTest(url=url):
                self.assertTrue(self.tool._is_static_asset_candidate({"url": url}))

    def test_extensionless_and_api_json_endpoints_are_preserved(self):
        application_endpoints = [
            {"url": "https://bank.test/api/users"},
            {"url": "https://bank.test/api/config.json"},
            {"url": "https://bank.test/internal/config.json"},
            {
                "url": "https://bank.test/download/report.js",
                "source": "openapi",
                "operationId": "downloadReport",
            },
            {
                "url": "https://bank.test/data/report.js",
                "resourceType": "fetch",
                "contentType": "application/json",
            },
        ]

        for endpoint in application_endpoints:
            with self.subTest(endpoint=endpoint):
                self.assertFalse(self.tool._is_static_asset_candidate(endpoint))

    def test_observed_response_semantics_survive_endpoint_normalization(self):
        endpoints = self.tool._normalize_endpoints(
            {
                "apiEndpoints": [
                    {
                        "method": "GET",
                        "url": "https://bank.test/reports/current.js",
                        "resourceType": "xhr",
                        "contentType": "application/problem+json",
                        "responseKeys": ["detail"],
                    }
                ]
            },
            "https://bank.test/",
        )

        self.assertEqual(len(endpoints), 2)
        observed = next(endpoint for endpoint in endpoints if endpoint["url"].endswith("current.js"))
        self.assertEqual(observed["resourceType"], "xhr")
        self.assertEqual(observed["contentType"], "application/problem+json")
        self.assertFalse(self.tool._is_static_asset_candidate(observed))

    def test_static_manifest_is_filtered_but_api_manifest_is_preserved(self):
        self.assertTrue(
            self.tool._is_static_asset_candidate(
                {"url": "https://bank.test/manifest.json"}
            )
        )
        self.assertFalse(
            self.tool._is_static_asset_candidate(
                {"url": "https://bank.test/api/manifest.json"}
            )
        )

    def test_filter_preserves_deterministic_application_endpoint_order(self):
        candidates = self.tool._dedupe_endpoints(
            [
                {"method": "GET", "url": "https://bank.test/health", "path": "/health"},
                {
                    "method": "GET",
                    "url": "https://bank.test/_next/static/chunks/123.js",
                    "path": "/_next/static/chunks/123.js",
                },
                {"method": "GET", "url": "https://bank.test/api/users", "path": "/api/users"},
            ]
        )

        application_endpoints, filtered = self.tool._without_static_candidates(candidates)

        self.assertEqual(filtered, 1)
        self.assertEqual(
            [endpoint["url"] for endpoint in application_endpoints],
            [
                "https://bank.test/api/users",
                "https://bank.test/health",
            ],
        )

    def test_identifier_extraction_rejects_credentials_and_unsafe_path_values(self):
        observed = {}
        body = json.dumps(
            {
                "accountNumber": "ACC-1024",
                "password": "never-replay-this",
                "user_id": "../admin",
            }
        )
        self.tool._collect_observed_identifiers(
            observed,
            {
                "status": 200,
                "body": body,
            },
            {"url": "https://bank.test/public-index"},
        )
        self.assertEqual(observed, {"account_number": [{"value": "ACC-1024", "sourcePath": "/public-index"}]})

    def test_materialized_template_response_does_not_poison_observed_values(self):
        observed = {}
        self.tool._collect_observed_identifiers(
            observed,
            {"status": 200, "body": json.dumps({"account_number": "1"})},
            {
                "url": "https://bank.test/check_balance/1",
                "originalPath": "/check_balance/{account_number}",
            },
        )
        self.assertEqual(observed, {})

    def test_truncated_json_prefix_still_yields_complete_identifier_scalars(self):
        observed = {}
        self.tool._collect_observed_identifiers(
            observed,
            {
                "status": 200,
                "body": '{"users":[{"account_number":"ACC-9001","password":"secret"},{"account_number":"cut',
            },
            {"url": "https://bank.test/public-index"},
        )
        self.assertEqual(observed, {"account_number": [{"value": "ACC-9001", "sourcePath": "/public-index"}]})


if __name__ == "__main__":
    unittest.main()
