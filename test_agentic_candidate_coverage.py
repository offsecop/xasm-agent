import unittest
import asyncio

from tools.agentic_param_exploit_probe import ParamExploitProbeTool
from tools.agentic_api_access_control_probe import ApiAccessControlProbeTool
from tools.agentic_decision_plan_next import DecisionPlanNextTool
from tools.agentic_exploitation_queue import ExploitationQueueTool
from tools.agentic_exploit_chain import _build_login_candidates, _normalize_form
from tools.nuclei_full_scan import (
    DEFAULT_CATEGORY_TIMEOUT_SECONDS,
    MAX_CATEGORY_TIMEOUT_SECONDS,
    MIN_CATEGORY_TIMEOUT_SECONDS,
    NucleiFullScanTool,
    coerce_category_timeout_seconds,
)


class AgenticCandidateCoverageTests(unittest.IsolatedAsyncioTestCase):
    def test_generated_merchant_login_precedes_observed_forms(self):
        candidates = _build_login_candidates(
            "https://vulnbank.org/",
            ["https://vulnbank.org/login"],
            [
                {
                    "action": "/login",
                    "method": "POST",
                    "fields": [
                        {"name": "email", "type": "email"},
                        {"name": "password", "type": "password"},
                    ],
                }
            ],
            [],
            True,
        )

        self.assertGreaterEqual(len(candidates), 2)
        self.assertEqual(
            candidates[0]["url"],
            "https://vulnbank.org/api/v1/merchants/login",
        )
        self.assertEqual(candidates[0]["shapes"], [("email", "password")])

    def test_string_form_fields_normalize_to_login_shape(self):
        normalized = _normalize_form(
            "https://vulnbank.org/",
            {
                "action": "/api/v1/merchants/login",
                "method": "POST",
                "fields": ["email", "password"],
            },
        )
        candidates = _build_login_candidates(
            "https://vulnbank.org/",
            [],
            [normalized],
            [],
            False,
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["url"], "https://vulnbank.org/api/v1/merchants/login")
        self.assertEqual(candidates[0]["shapes"], [("email", "password")])

    async def test_api_probe_augments_supplied_endpoint_lists_with_discovery(self):
        tool = ApiAccessControlProbeTool()

        async def fake_discovery(target, parameters, max_endpoints):
            return [
                {
                    "method": "GET",
                    "url": "https://vulnbank.org/graphql",
                    "path": "/graphql",
                    "source": "discovered",
                }
            ]

        async def fake_fetch(session, method, url, headers):
            return {
                "url": url,
                "status": 404,
                "headers": {},
                "body": "{}",
                "elapsedMs": 1,
                "jsonKeys": [],
                "bodyLength": 2,
                "sensitiveBodyMarkers": [],
            }

        tool._discover_readonly_endpoints = fake_discovery
        tool._fetch = fake_fetch

        result = await tool.execute(
            {
                "target": "https://vulnbank.org/",
                "apiEndpoints": [
                    "/api/v1/users",
                    "/api/v1/accounts",
                    "/api/v1/transactions",
                ],
                "maxEndpoints": 20,
                "maxRequests": 20,
            }
        )

        urls = {probe["url"] for probe in result["probes"]}
        self.assertIn("https://vulnbank.org/graphql", urls)

    def test_api_probe_public_sensitive_signal_includes_sanitized_http_evidence(self):
        tool = ApiAccessControlProbeTool()
        endpoint = {
            "method": "GET",
            "url": "https://vulnbank.org/api/bill-categories",
            "source": "traffic_capture",
        }
        auth_response = {
            "url": endpoint["url"],
            "status": 200,
            "headers": {"Content-Type": "application/json", "Set-Cookie": "sid=server-secret"},
            "body": '{"email":"admin@example.com","card":"4111111111111111","items":[{"id":1}]}',
            "elapsedMs": 12,
            "jsonKeys": ["email", "card", "items", "items.id"],
            "bodyLength": 75,
            "sensitiveBodyMarkers": ["card", "email"],
        }
        anonymous_response = {
            **auth_response,
            "headers": {"Content-Type": "application/json"},
            "elapsedMs": 10,
        }

        finding = tool._anonymous_visibility_finding(
            endpoint,
            auth_response,
            anonymous_response,
            {"Cookie": "sid=client-secret", "Accept": "application/json"},
            {"Accept": "application/json"},
        )

        self.assertIsNotNone(finding)
        evidence = finding["evidence"]
        self.assertIn("GET /api/bill-categories HTTP/1.1", evidence["request"])
        self.assertIn("Cookie: [REDACTED]", evidence["request"])
        self.assertIn("HTTP/1.1 200 OK", evidence["response"])
        self.assertIn("GET /api/bill-categories HTTP/1.1", evidence["anonymousRequest"])
        self.assertIn("HTTP/1.1 200 OK", evidence["anonymousResponse"])
        self.assertNotIn("client-secret", evidence["request"])
        self.assertNotIn("server-secret", evidence["response"])
        self.assertNotIn("4111111111111111", evidence["anonymousResponse"])
        self.assertIn("[REDACTED_CARD]", evidence["anonymousResponse"])
        self.assertEqual(evidence["authStatus"], 200)
        self.assertEqual(evidence["anonymousStatus"], 200)
        self.assertEqual(evidence["shapeSimilarity"], 1.0)

    async def test_decision_plan_prioritizes_evidence_backed_exploit_chain(self):
        tool = DecisionPlanNextTool()

        result = await tool.execute(
            {
                "target": "https://vulnbank.org/",
                "riskTolerance": "aggressive",
                "observations": {
                    "forms": [
                        {
                            "action": "https://vulnbank.org/login",
                            "method": "POST",
                            "fields": [
                                {"name": "email", "type": "email"},
                                {"name": "password", "type": "password"},
                            ],
                        }
                    ],
                    "apiEndpoints": [
                        {
                            "method": "GET",
                            "url": "https://vulnbank.org/api/accounts/1",
                            "path": "/api/accounts/1",
                            "pathParameters": ["id"],
                        },
                        {
                            "method": "POST",
                            "url": "https://vulnbank.org/api/transfers",
                            "path": "/api/transfers",
                        },
                    ],
                    "graphql": [{"url": "https://vulnbank.org/graphql"}],
                    "hypotheses": [
                        {
                            "type": "auth_bypass_or_login_sqli",
                            "priority": 88,
                            "url": "https://vulnbank.org/login",
                        },
                        {
                            "type": "idor_bola",
                            "priority": 80,
                            "url": "https://vulnbank.org/api/accounts/1",
                        },
                    ],
                },
            }
        )

        tools = [action["tool"] for action in result["nextActions"]]
        self.assertIn("exploit:chain", tools)
        self.assertIn("api:access_control_probe", tools)
        self.assertIn("curl:request", tools)
        self.assertLess(tools.index("exploit:chain"), tools.index("nuclei:web_scan"))
        self.assertGreaterEqual(result["observationSummary"]["loginForms"], 1)
        self.assertGreaterEqual(result["observationSummary"]["writeApiEndpoints"], 1)
        self.assertTrue(result["attackChainCandidates"])
        self.assertIn("evidence-driven", result["summary"])

    async def test_exploitation_queue_turns_surface_into_candidate_followups(self):
        tool = ExploitationQueueTool()

        result = await tool.execute(
            {
                "target": "https://vulnbank.org/",
                "riskTolerance": "aggressive",
                "forms": [
                    {
                        "action": "https://vulnbank.org/login",
                        "method": "POST",
                        "fields": [
                            {"name": "email", "type": "email"},
                            {"name": "password", "type": "password"},
                        ],
                    }
                ],
                "apiEndpoints": [
                    {
                        "method": "GET",
                        "url": "https://vulnbank.org/api/accounts/1",
                        "path": "/api/accounts/1",
                        "pathParameters": ["id"],
                    },
                    {
                        "method": "POST",
                        "url": "https://vulnbank.org/api/transfers",
                        "path": "/api/transfers",
                    },
                ],
                "parameterizedUrls": [
                    "https://vulnbank.org/view?file=invoice.pdf",
                    "https://vulnbank.org/redirect?url=https://example.com",
                    "https://vulnbank.org/search?q=test",
                ],
                "graphql": [{"url": "https://vulnbank.org/graphql"}],
                "cves": [
                    {
                        "id": "CVE-2025-30218",
                        "library": "nextjs",
                        "version": "14.2.25",
                        "severity": "medium",
                    }
                ],
            }
        )

        self.assertTrue(result["success"])
        candidate_types = {candidate["type"] for candidate in result["candidates"]}
        self.assertIn("login_form", candidate_types)
        self.assertIn("idor_candidate", candidate_types)
        self.assertIn("sensitive_api", candidate_types)
        self.assertIn("file_path_candidate", candidate_types)
        self.assertIn("open_redirect_candidate", candidate_types)
        self.assertIn("reflection_candidate", candidate_types)
        self.assertIn("graphql_endpoint", candidate_types)
        self.assertIn("js_dependency_cve", candidate_types)

        tools = {action["tool"] for action in result["nextActions"]}
        self.assertIn("exploit:chain", tools)
        self.assertIn("api:access_control_probe", tools)
        self.assertIn("lfi:file_exposure_probe", tools)
        self.assertIn("param:exploit_probe", tools)
        self.assertIn("cve:runtime_probe", tools)
        self.assertIn("dalfox:xss_scan", tools)
        self.assertTrue(result["attackChainCandidates"])

    async def test_decision_plan_consumes_exploitation_queue_candidates(self):
        queue = ExploitationQueueTool()
        candidates = await queue.execute(
            {
                "target": "https://vulnbank.org/",
                "riskTolerance": "aggressive",
                "apiEndpoints": [
                    {
                        "method": "GET",
                        "url": "https://vulnbank.org/api/users/1",
                        "path": "/api/users/1",
                    }
                ],
                "parameterizedUrls": ["https://vulnbank.org/download?file=../../etc/passwd"],
                "cves": [{"id": "CVE-2025-30218", "library": "nextjs", "version": "14.2.25"}],
            }
        )

        planner = DecisionPlanNextTool()
        result = await planner.execute(
            {
                "target": "https://vulnbank.org/",
                "riskTolerance": "aggressive",
                "observations": {
                    "exploitationCandidates": candidates["candidates"],
                },
            }
        )

        tools = [action["tool"] for action in result["nextActions"]]
        self.assertGreaterEqual(result["observationSummary"]["exploitationCandidates"], 1)
        self.assertIn("api:access_control_probe", tools)
        self.assertIn("lfi:file_exposure_probe", tools)
        self.assertIn("cve:runtime_probe", tools)
        self.assertTrue(any(chain.get("candidateId") for chain in result["attackChainCandidates"]))

    async def test_decision_plan_uses_authenticated_session_as_follow_up_signal(self):
        tool = DecisionPlanNextTool()

        result = await tool.execute(
            {
                "target": "https://vulnbank.org/",
                "riskTolerance": "low",
                "observations": {
                    "authContext": {
                        "hasSession": True,
                        "requiresAuthenticatedReplay": True,
                        "authenticatedReplayAttemptedTools": ["browser:map_app"],
                    },
                    "apiEndpoints": [
                        {"method": "GET", "url": "https://vulnbank.org/api/me", "path": "/api/me"}
                    ],
                },
            }
        )

        tools = [action["tool"] for action in result["nextActions"]]
        self.assertIn("api:discover", tools)
        self.assertIn("api:access_control_probe", tools)
        self.assertTrue(result["observationSummary"]["authSessionEstablished"])
        self.assertIn("Next evidence-driven tools", result["autonomousReasoningBrief"])

    def test_nuclei_full_scan_exposes_bounded_category_timeout(self):
        tool = NucleiFullScanTool()

        self.assertEqual(
            tool.schema["properties"]["categoryTimeoutSeconds"]["default"],
            DEFAULT_CATEGORY_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            coerce_category_timeout_seconds(None),
            DEFAULT_CATEGORY_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            coerce_category_timeout_seconds(1),
            MIN_CATEGORY_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            coerce_category_timeout_seconds(9999),
            MAX_CATEGORY_TIMEOUT_SECONDS,
        )

    async def test_param_exploit_form_submission_timeout_is_nonfatal(self):
        class TimeoutSession:
            def post(self, *args, **kwargs):
                raise asyncio.TimeoutError()

        tool = ParamExploitProbeTool()
        result = await tool._submit_form(
            TimeoutSession(),
            {},
            "https://vulnbank.org/login",
            {"username": "xasm", "password": "xasm"},
        )

        self.assertEqual(result["status"], 0)
        self.assertIn("timed out", result["error"])


if __name__ == "__main__":
    unittest.main()
