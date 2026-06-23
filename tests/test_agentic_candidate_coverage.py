import unittest
import asyncio

from tools.agentic_param_exploit_probe import ParamExploitProbeTool
from tools.agentic_api_access_control_probe import ApiAccessControlProbeTool, COMMON_READONLY_API_PATHS
from tools.agentic_decision_plan_next import DecisionPlanNextTool
from tools.agentic_exploitation_queue import ExploitationQueueTool
from tools.agentic_exploit_chain import _build_login_candidates, _build_no_auth_candidates, _normalize_form
from tools.retirejs_scan import _build_aggregate_finding
from tools.web_security_controls_probe import WebSecurityControlsProbeTool
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
        self.assertIn("GET /api/bill-categories HTTP/1.1", finding["request"])
        self.assertIn("HTTP/1.1 200 OK", finding["response"])
        self.assertNotIn("Cookie:", finding["request"])
        self.assertIn("anonymous_status=200", finding["matchedContent"])

    def test_web_security_controls_promotes_sanitized_http_evidence(self):
        tool = WebSecurityControlsProbeTool()
        page = {
            "url": "https://example.test/dashboard",
            "status": 200,
            "headers": {"Content-Type": "text/html", "Set-Cookie": "sid=super-secret; Path=/"},
            "request": "GET /dashboard HTTP/1.1\nHost: example.test\nCookie: sid=super-secret",
            "response": "HTTP/1.1 200 OK\nContent-Type: text/html\nSet-Cookie: sid=super-secret; Path=/",
        }

        findings = tool._header_findings(page)

        self.assertTrue(findings)
        finding = findings[0]
        self.assertIn("GET /dashboard HTTP/1.1", finding["request"])
        self.assertIn("HTTP/1.1 200 OK", finding["response"])
        self.assertNotIn("super-secret", finding["request"])
        self.assertNotIn("super-secret", finding["response"])
        self.assertIn("status=200", finding["matchedContent"])

    def test_retirejs_aggregate_promotes_script_fetch_evidence(self):
        finding = _build_aggregate_finding(
            "nextjs",
            "14.2.25",
            {
                "url": "https://example.test/_next/static/chunks/main.js",
                "finalUrl": "https://example.test/_next/static/chunks/main.js",
                "status": 200,
                "headers": {"Content-Type": "application/javascript", "Set-Cookie": "sid=secret"},
                "text": "/* nextjs 14.2.25 */ const token='should-not-be-public-but-redacted';",
            },
            [
                {
                    "severity": "low",
                    "identifiers": {
                        "CVE": ["CVE-2025-30218"],
                        "summary": "Next.js may leak x-middleware-subrequest-id to external hosts",
                    },
                }
            ],
            source="retirejs",
        )

        self.assertIn("GET /_next/static/chunks/main.js HTTP/1.1", finding["request"])
        self.assertIn("HTTP/1.1 200 OK", finding["response"])
        self.assertIn("nextjs@14.2.25", finding["matchedContent"])
        self.assertIn("CVE-2025-30218", finding["matchedContent"])
        self.assertNotIn("sid=secret", finding["response"])

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

    async def test_exploitation_queue_flags_business_logic_surface(self):
        tool = ExploitationQueueTool()

        result = await tool.execute(
            {
                "target": "https://vulnbank.org/",
                "riskTolerance": "aggressive",
                "apiEndpoints": [
                    {
                        "method": "GET",
                        "url": "https://vulnbank.org/api/transactions/1",
                        "path": "/api/transactions/1",
                    },
                    {
                        "method": "POST",
                        "url": "https://vulnbank.org/api/v1/payments/charge",
                        "path": "/api/v1/payments/charge",
                    },
                    {
                        "method": "GET",
                        "url": "https://vulnbank.org/api/v1/merchants/me",
                        "path": "/api/v1/merchants/me",
                    },
                ],
                "parameterizedUrls": [
                    "https://vulnbank.org/api/transactions?account_number=1001&amount=10",
                    "https://vulnbank.org/api/users/1?role=user&is_admin=false",
                ],
            }
        )

        candidate_types = {candidate["type"] for candidate in result["candidates"]}
        self.assertIn("business_logic_api", candidate_types)
        self.assertIn("business_logic_parameter", candidate_types)
        self.assertIn("payment_amount_candidate", candidate_types)
        self.assertIn("mass_assignment_candidate", candidate_types)

        tools = {action["tool"] for action in result["nextActions"]}
        self.assertIn("api:access_control_probe", tools)
        self.assertIn("vuln:chain_probe", tools)
        self.assertIn("param:exploit_probe", tools)
        self.assertIn("exploit:chain", tools)

        action_by_tool = {action["tool"]: action for action in result["nextActions"]}
        vuln_params = action_by_tool["vuln:chain_probe"]["parameters"]
        vuln_endpoint_urls = {endpoint["url"] for endpoint in vuln_params["apiEndpoints"]}
        self.assertIn("https://vulnbank.org/api/v1/payments/charge", vuln_endpoint_urls)
        self.assertTrue(any(candidate["type"] == "payment_amount_candidate" for candidate in action_by_tool["vuln:chain_probe"]["topCandidates"]))
        api_params = action_by_tool["api:access_control_probe"]["parameters"]
        self.assertTrue(api_params["includeAnonymousComparison"])
        self.assertTrue(api_params["includeIdMutation"])
        self.assertIn("https://vulnbank.org/api/v1/merchants/me", {endpoint["url"] for endpoint in api_params["apiEndpoints"]})

    async def test_exploitation_queue_flags_sensitive_openapi_paths_for_chain_probe(self):
        tool = ExploitationQueueTool()

        result = await tool.execute(
            {
                "target": "https://vulnbank.org/",
                "riskTolerance": "aggressive",
                "apiEndpoints": [
                    {
                        "method": "GET",
                        "url": "https://vulnbank.org/latest/meta-data/iam/security-credentials/vulnbank-role",
                        "path": "/latest/meta-data/iam/security-credentials/vulnbank-role",
                        "source": "openapi",
                    },
                    {
                        "method": "GET",
                        "url": "https://vulnbank.org/api/ai/system-info",
                        "path": "/api/ai/system-info",
                        "source": "openapi",
                    },
                    {
                        "method": "GET",
                        "url": "https://vulnbank.org/internal/config.json",
                        "path": "/internal/config.json",
                        "source": "openapi",
                    },
                ],
            }
        )

        self.assertTrue(result["success"])
        sensitive_candidates = [
            candidate
            for candidate in result["candidates"]
            if candidate["type"] == "sensitive_api"
        ]
        self.assertGreaterEqual(len(sensitive_candidates), 3)
        self.assertTrue(
            any("latest/meta-data/iam/security-credentials" in candidate["url"] for candidate in sensitive_candidates)
        )
        for candidate in sensitive_candidates:
            self.assertIn("api:access_control_probe", candidate["recommendedTools"])
            self.assertIn("vuln:chain_probe", candidate["recommendedTools"])

        tools = {action["tool"] for action in result["nextActions"]}
        self.assertIn("api:access_control_probe", tools)
        self.assertIn("vuln:chain_probe", tools)

        action_by_tool = {action["tool"]: action for action in result["nextActions"]}
        api_urls = {endpoint["url"] for endpoint in action_by_tool["api:access_control_probe"]["parameters"]["apiEndpoints"]}
        chain_urls = {endpoint["url"] for endpoint in action_by_tool["vuln:chain_probe"]["parameters"]["apiEndpoints"]}
        self.assertIn("https://vulnbank.org/latest/meta-data/iam/security-credentials/vulnbank-role", api_urls)
        self.assertIn("https://vulnbank.org/internal/config.json", chain_urls)

        api_probe = ApiAccessControlProbeTool()
        self.assertTrue(
            api_probe._sensitive_endpoint(
                "https://vulnbank.org/latest/meta-data/iam/security-credentials/vulnbank-role"
            )
        )

    async def test_exploitation_queue_promotes_openapi_body_shapes_to_active_candidates(self):
        tool = ExploitationQueueTool()

        result = await tool.execute(
            {
                "target": "https://vulnbank.org/",
                "riskTolerance": "aggressive",
                "apiEndpoints": [
                    {
                        "method": "POST",
                        "url": "https://vulnbank.org/api/v1/payments/charge",
                        "path": "/api/v1/payments/charge",
                        "originalPath": "/api/v1/payments/charge",
                        "source": "openapi",
                        "operationId": "chargePayment",
                        "requestBodyKeys": ["account_number", "amount", "currency"],
                        "requestBodyContentTypes": ["application/json"],
                    },
                    {
                        "method": "PATCH",
                        "url": "https://vulnbank.org/api/v1/users/1",
                        "path": "/api/v1/users/1",
                        "originalPath": "/api/v1/users/{id}",
                        "source": "openapi",
                        "operationId": "updateUser",
                        "pathParameters": ["id"],
                        "requestBodyKeys": ["email", "role", "is_admin", "credit_limit"],
                    },
                    {
                        "method": "POST",
                        "url": "https://vulnbank.org/api/auth/reset-password",
                        "path": "/api/auth/reset-password",
                        "source": "openapi",
                        "operationId": "resetPassword",
                        "requestBodyKeys": ["email", "token", "new_password"],
                    },
                ],
            }
        )

        self.assertTrue(result["success"])
        candidate_types = {candidate["type"] for candidate in result["candidates"]}
        self.assertIn("openapi_write_operation", candidate_types)
        self.assertIn("payment_amount_candidate", candidate_types)
        self.assertIn("mass_assignment_candidate", candidate_types)
        self.assertIn("auth_recovery_candidate", candidate_types)
        self.assertIn("business_logic_parameter", candidate_types)

        mass_assignment = next(candidate for candidate in result["candidates"] if candidate["type"] == "mass_assignment_candidate")
        self.assertEqual(mass_assignment["operationId"], "updateUser")
        self.assertIn("role", mass_assignment["requestBodyKeys"])
        self.assertTrue(mass_assignment["fields"])

        tools = {action["tool"] for action in result["nextActions"]}
        self.assertIn("api:access_control_probe", tools)
        self.assertIn("vuln:chain_probe", tools)
        self.assertIn("param:exploit_probe", tools)
        self.assertIn("exploit:chain", tools)

        action_by_tool = {action["tool"]: action for action in result["nextActions"]}
        chain_params = action_by_tool["vuln:chain_probe"]["parameters"]
        chain_endpoint = next(
            endpoint
            for endpoint in chain_params["apiEndpoints"]
            if endpoint["url"] == "https://vulnbank.org/api/v1/payments/charge"
        )
        self.assertEqual(chain_endpoint["requestBodyKeys"], ["account_number", "amount", "currency"])
        self.assertEqual(chain_endpoint["operationId"], "chargePayment")
        param_params = action_by_tool["param:exploit_probe"]["parameters"]
        self.assertTrue(param_params["includeOpenApiPostFormChecks"])

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

    async def test_decision_plan_prioritizes_business_logic_candidates(self):
        planner = DecisionPlanNextTool()

        result = await planner.execute(
            {
                "target": "https://vulnbank.org/",
                "riskTolerance": "aggressive",
                "observations": {
                    "exploitationCandidates": [
                        {
                            "id": "cand-business",
                            "type": "business_logic_api",
                            "title": "Business endpoint",
                            "url": "https://vulnbank.org/api/transactions/1",
                            "risk": "HIGH",
                        },
                        {
                            "id": "cand-reset",
                            "type": "auth_recovery_candidate",
                            "title": "Auth recovery endpoint",
                            "url": "https://vulnbank.org/reset-password",
                            "risk": "HIGH",
                            "recommendedTools": [
                                "param:exploit_probe",
                                "web:security_controls_probe",
                            ],
                        },
                    ],
                },
            }
        )

        tools = [action["tool"] for action in result["nextActions"]]
        self.assertIn("api:access_control_probe", tools)
        self.assertIn("vuln:chain_probe", tools)
        self.assertIn("param:exploit_probe", tools)
        self.assertIn("exploit:chain", tools)
        self.assertLess(tools.index("api:access_control_probe"), tools.index("param:discover"))

    async def test_decision_plan_treats_openapi_write_candidates_as_state_changing_followup(self):
        planner = DecisionPlanNextTool()

        result = await planner.execute(
            {
                "target": "https://vulnbank.org/",
                "riskTolerance": "aggressive",
                "observations": {
                    "exploitationCandidates": [
                        {
                            "id": "cand-openapi-write",
                            "type": "openapi_write_operation",
                            "title": "OpenAPI PATCH user",
                            "url": "https://vulnbank.org/api/v1/users/1",
                            "method": "PATCH",
                            "risk": "HIGH",
                            "confidence": 0.84,
                            "recommendedTools": [
                                "api:access_control_probe",
                                "vuln:chain_probe",
                                "param:exploit_probe",
                                "exploit:chain",
                            ],
                        }
                    ],
                },
            }
        )

        tools = [action["tool"] for action in result["nextActions"]]
        self.assertIn("state_changing_api_candidate", result["observationSummary"]["hypothesisCategories"])
        self.assertIn("api:access_control_probe", tools)
        self.assertIn("vuln:chain_probe", tools)
        self.assertIn("param:exploit_probe", tools)
        self.assertIn("exploit:chain", tools)

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
        self.assertIn("POST /login HTTP/1.1", result["request"])
        self.assertIn("password=[REDACTED]", result["request"])
        self.assertIn("HTTP/1.1 N/A", result["response"])
        self.assertIn("timed out", result["response"])

    def test_param_exploit_finding_promotes_http_evidence(self):
        tool = ParamExploitProbeTool()

        finding = tool._finding(
            template_id="xasm-reflected-xss-evidence",
            name="Reflected XSS Evidence",
            severity="medium",
            matched_at="https://vulnbank.org/search?q=xasmxss",
            description="Parameter reflects payload fragments.",
            remediation="Encode reflected input.",
            matcher_name="raw-xss-payload-reflection",
            extracted=["<svg/onload=confirm(1337)>"],
            evidence={
                "request": "GET /search?q=xasmxss HTTP/1.1\nHost: vulnbank.org",
                "response": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<svg/onload=confirm(1337)>",
                "matchedContent": "<svg/onload=confirm(1337)>",
            },
        )

        self.assertEqual(finding["request"], "GET /search?q=xasmxss HTTP/1.1\nHost: vulnbank.org")
        self.assertIn("HTTP/1.1 200 OK", finding["response"])
        self.assertEqual(finding["matchedContent"], "<svg/onload=confirm(1337)>")

    def test_api_probe_common_readonly_paths_include_financial_surface(self):
        self.assertIn("/api/transactions/1", COMMON_READONLY_API_PATHS)
        self.assertIn("/api/bill-categories", COMMON_READONLY_API_PATHS)
        self.assertIn("/api/v1/merchants/me", COMMON_READONLY_API_PATHS)

    def test_exploit_chain_generated_no_auth_candidates_include_vulnbank_business_routes(self):
        candidates, skipped = _build_no_auth_candidates(
            "https://vulnbank.org/",
            [],
            [],
            allow_generated=True,
            allow_unsafe_methods=False,
        )

        urls = {candidate["url"] for candidate in candidates}
        self.assertIn("https://vulnbank.org/api/transactions/1", urls)
        self.assertIn("https://vulnbank.org/api/bill-categories", urls)
        self.assertIn("https://vulnbank.org/api/v1/merchants/me", urls)
        self.assertTrue(all(candidate["method"] in {"GET", "HEAD"} for candidate in candidates))
        self.assertTrue(any(item["method"] == "POST" for item in skipped))


if __name__ == "__main__":
    unittest.main()
