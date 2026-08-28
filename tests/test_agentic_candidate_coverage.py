import unittest
import asyncio

from tools.agentic_param_exploit_probe import ParamExploitProbeTool
from tools.agentic_param_discover import ParamDiscoverTool
from tools.agentic_api_access_control_probe import ApiAccessControlProbeTool, COMMON_READONLY_API_PATHS
from tools.agentic_decision_plan_next import DecisionPlanNextTool
from tools.agentic_exploitation_queue import ExploitationQueueTool
from tools._agentic_exploration_common import (
    NATIVE_PROBE_PATH_CANDIDATES_KEY,
    NATIVE_PROBE_PRIVATE_CANDIDATES_KEY,
    extract_html_map,
)
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
    async def test_url_only_cart_setup_routes_to_native_race_probe_without_private_values(self):
        mapped = extract_html_map(
            """
            <html><body>
              <form action="/cart" method="POST" enctype="application/x-www-form-urlencoded">
                <input type="hidden" name="productId" value="1">
                <input type="hidden" name="redir" value="PRODUCT">
                <input type="number" name="quantity" value="1">
              </form>
            </body></html>
            """,
            "https://shop.example.test/product?productId=1",
        )
        tool = ExploitationQueueTool()

        result = await tool.execute(
            {
                "target": "https://shop.example.test/",
                "forms": mapped["forms"],
                "riskTolerance": "high",
                "engagement": "lab",
                "allowUnsafeMethods": True,
            }
        )

        action = next(
            item
            for item in result["nextActions"]
            if item["tool"] == "web:race_condition_probe"
        )
        self.assertEqual(action["nativeProbe"]["status"], "READY")
        self.assertEqual(action["nativeProbe"]["adapterId"], "web:race_condition_probe")
        self.assertEqual(action["candidateTypes"], ["race_cart_setup_form"])
        self.assertEqual(
            action["candidateIds"],
            [mapped["forms"][0]["nativeProbeCandidateId"]],
        )
        self.assertNotIn("productId=1", str(action))

    async def test_non_portswigger_url_only_discovery_routes_absolute_url_form_to_ssrf(self):
        mapped = extract_html_map(
            """
            <html><body>
              <form action="/fetch/preview" method="POST" enctype="application/x-www-form-urlencoded">
                <input type="hidden" name="documentId" value="42">
                <input type="text" name="resource" value="https://cdn.fixture.invalid/document/42">
              </form>
            </body></html>
            """,
            "https://fixture.example/",
        )
        tool = ExploitationQueueTool()

        result = await tool.execute(
            {
                "target": "https://fixture.example/",
                "forms": mapped["forms"],
            }
        )

        action = next(
            item for item in result["nextActions"] if item["tool"] == "web:ssrf_probe"
        )
        self.assertEqual(action["nativeProbe"]["status"], "READY")
        self.assertEqual(action["candidateTypes"], ["absolute_url_form_field"])
        self.assertEqual(
            action["candidateIds"],
            [mapped["forms"][0]["nativeProbeCandidateId"]],
        )
        public_output = str(
            {
                key: value
                for key, value in mapped.items()
                if key != NATIVE_PROBE_PRIVATE_CANDIDATES_KEY
            }
        )
        self.assertNotIn("cdn.fixture.invalid", public_output)
        self.assertNotIn("cdn.fixture.invalid", str(action))

    async def test_observed_query_artifacts_route_bounded_dalfox_and_sqlmap(self):
        discovered = await ParamDiscoverTool().execute(
            {
                "target": "https://fixture.example/",
                "urls": [
                    "https://fixture.example/search?q=private-marker",
                    "https://fixture.example/products?category=Gifts",
                ],
                "discoverFromTarget": False,
            }
        )
        public_discovery = {
            key: value
            for key, value in discovered.items()
            if key != NATIVE_PROBE_PRIVATE_CANDIDATES_KEY
        }
        self.assertNotIn("private-marker", str(public_discovery))
        self.assertNotIn("Gifts", str(public_discovery))

        queued = await ExploitationQueueTool().execute(
            {
                "target": "https://fixture.example/",
                "parameterizedUrls": discovered["urlsWithParams"],
                "interestingParameters": discovered["interestingParameters"],
                "queryCandidates": discovered["queryCandidates"],
                "riskTolerance": "high",
                "engagement": "aggressive",
            }
        )
        dalfox = next(
            action
            for action in queued["nextActions"]
            if action["tool"] == "dalfox:xss_scan"
        )
        browser_dom = next(
            action
            for action in queued["nextActions"]
            if action["tool"] == "browser:dom_probe"
        )
        sqlmap = next(
            action
            for action in queued["nextActions"]
            if action["tool"] == "sqlmap:detection_scan"
        )
        self.assertEqual(dalfox["nativeProbe"]["status"], "READY")
        self.assertEqual(dalfox["candidateTypes"], ["reflection_candidate"])
        self.assertEqual(browser_dom["nativeProbe"]["status"], "READY")
        self.assertEqual(browser_dom["candidateTypes"], ["dom_xss_candidate"])
        self.assertEqual(len(browser_dom["candidateIds"]), 1)
        self.assertEqual(sqlmap["nativeProbe"]["status"], "READY")
        self.assertEqual(sqlmap["candidateTypes"], ["sql_injection_candidate"])
        self.assertNotIn("private-marker", str(queued))
        self.assertNotIn("Gifts", str(queued))

    async def test_sqlmap_query_route_requires_aggressive_posture(self):
        discovered = await ParamDiscoverTool().execute(
            {
                "target": "https://fixture.example/",
                "urls": ["https://fixture.example/products?id=1"],
                "discoverFromTarget": False,
            }
        )
        queued = await ExploitationQueueTool().execute(
            {
                "target": "https://fixture.example/",
                "parameterizedUrls": discovered["urlsWithParams"],
                "queryCandidates": discovered["queryCandidates"],
                "riskTolerance": "low",
            }
        )
        self.assertFalse(
            any(
                action["tool"] == "sqlmap:detection_scan"
                for action in queued["nextActions"]
            )
        )

    async def test_documented_path_artifacts_are_prioritized_for_native_sqlmap(self):
        path_candidates = [
            {
                "url": "https://fixture.example/transactions/{account_number}",
                "method": "GET",
                "contentType": "application/x-www-form-urlencoded",
                "fields": [
                    {
                        "name": "account_number",
                        "type": "path",
                        "valueSource": "documented-path",
                    }
                ],
                "parameterNames": ["account_number"],
                "nativeProbeCandidateId": "cand-1111111111111111",
            },
            {
                "url": "https://fixture.example/check_balance/{account_number}",
                "method": "GET",
                "contentType": "application/x-www-form-urlencoded",
                "fields": [
                    {
                        "name": "account_number",
                        "type": "path",
                        "valueSource": "documented-path",
                    }
                ],
                "parameterNames": ["account_number"],
                "nativeProbeCandidateId": "cand-2222222222222222",
            },
        ]

        queued = await ExploitationQueueTool().execute(
            {
                "target": "https://fixture.example/",
                NATIVE_PROBE_PATH_CANDIDATES_KEY: path_candidates,
                "riskTolerance": "high",
                "engagement": "aggressive",
            }
        )

        sqlmap = next(
            action
            for action in queued["nextActions"]
            if action["tool"] == "sqlmap:detection_scan"
        )
        self.assertEqual(sqlmap["nativeProbe"]["status"], "READY")
        self.assertEqual(
            sqlmap["candidateIds"],
            ["cand-1111111111111111", "cand-2222222222222222"],
        )
        self.assertEqual(sqlmap["parameters"], {"target": "https://fixture.example/"})
        self.assertNotIn("/transactions/1", str(queued))

    def test_html_map_splits_public_metadata_from_private_form_baselines(self):
        mapped = extract_html_map(
            """
            <form action="/product/stock" method="POST">
              <input type="hidden" name="productId" value="1">
              <input type="hidden" name="csrfToken" value="framework-secret-123">
              <input type="email" name="email" value="person@example.test">
              <select name="storeId"><option value="2" selected>Paris</option></select>
            </form>
            """,
            "https://shop.example.test/",
        )

        form = mapped["forms"][0]
        candidate_id = form["nativeProbeCandidateId"]
        self.assertRegex(candidate_id, r"^cand-[a-f0-9]{16}$")
        self.assertNotIn("framework-secret-123", str(form))
        self.assertNotIn("person@example.test", str(form))
        private = mapped[NATIVE_PROBE_PRIVATE_CANDIDATES_KEY][0]
        self.assertEqual(private["candidateId"], candidate_id)
        self.assertEqual(private["fields"]["csrfToken"], "framework-secret-123")
        self.assertEqual(private["fields"]["email"], "person@example.test")
        self.assertEqual(private["fields"]["storeId"], "2")

    def test_html_map_extracts_inline_url_search_parameters(self):
        mapped = extract_html_map(
            """
            <a href="/blog">Blog</a>
            <script>
              const current = new URL(window.location.href);
              current.searchParams.set('q', 'browser-only-value');
              const params = new URLSearchParams(window.location.search);
              const page = params.get('page');
            </script>
            """,
            "https://example.test/blog",
        )

        self.assertEqual(mapped["inlineQueryParameters"], ["q", "page"])
        self.assertEqual(mapped["parameterizedUrls"], ["https://example.test/blog?q=&page="])
        self.assertNotIn("browser-only-value", str(mapped))

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

    def test_api_probe_promotes_anonymous_sensitive_json_baseline(self):
        tool = ApiAccessControlProbeTool()
        endpoint = {
            "method": "GET",
            "url": "https://example.test/api/system-info",
            "source": "openapi",
        }
        body = '{"system_info":{"system_prompt":"internal instruction","database_access":true},"status":"ok"}'
        response = {
            "url": endpoint["url"],
            "status": 200,
            "headers": {"Content-Type": "application/json", "Set-Cookie": "sid=server-secret"},
            "body": body,
            "elapsedMs": 10,
            "jsonKeys": tool._json_keys(body),
            "bodyLength": len(body),
            "sensitiveBodyMarkers": tool._sensitive_body_markers(body),
        }

        finding = tool._anonymous_sensitive_baseline_finding(
            endpoint,
            response,
            {"Accept": "application/json"},
        )

        self.assertIsNotNone(finding)
        self.assertEqual(finding["template-id"], "xasm-api-anonymous-sensitive-data-exposure")
        self.assertEqual(finding["info"]["classification"]["cwe-id"], ["CWE-200", "CWE-862"])
        self.assertIn("GET /api/system-info HTTP/1.1", finding["request"])
        self.assertIn("HTTP/1.1 200 OK", finding["response"])
        self.assertIn('\"system_prompt\":[REDACTED]', finding["response"])
        self.assertNotIn("internal instruction", finding["response"])
        self.assertNotIn("server-secret", finding["response"])
        self.assertIn("database_access", finding["matchedContent"])

    def test_api_probe_does_not_promote_public_metadata_baseline(self):
        tool = ApiAccessControlProbeTool()
        endpoint = {
            "method": "GET",
            "url": "https://example.test/api/status",
            "source": "openapi",
        }
        body = '{"status":"ok","version":"1.2.3","documentation":"/api/docs"}'
        response = {
            "url": endpoint["url"],
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": body,
            "elapsedMs": 5,
            "jsonKeys": tool._json_keys(body),
            "bodyLength": len(body),
            "sensitiveBodyMarkers": tool._sensitive_body_markers(body),
        }

        finding = tool._anonymous_sensitive_baseline_finding(endpoint, response, {})

        self.assertIsNone(finding)

    def test_api_probe_promotes_and_redacts_truncated_sensitive_json(self):
        tool = ApiAccessControlProbeTool()
        endpoint = {
            "method": "GET",
            "url": "https://example.test/debug/users",
            "source": "dirsearch:quick",
        }
        body = (
            '{"users":[{"id":1,"email":"alice@example.test",'
            '"password_hash":"$2b$12$raw-sensitive-hash","role":"admin"},'
        )
        response = {
            "url": endpoint["url"],
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": body,
            "elapsedMs": 10,
            "jsonKeys": tool._json_keys(body),
            "bodyLength": 250_000,
            "sensitiveBodyMarkers": tool._sensitive_body_markers(body),
        }

        self.assertIn("password_hash", response["jsonKeys"])
        finding = tool._anonymous_sensitive_baseline_finding(endpoint, response, {})

        self.assertIsNotNone(finding)
        self.assertIn("GET /debug/users HTTP/1.1", finding["request"])
        self.assertIn('"password_hash":[REDACTED]', finding["response"])
        self.assertNotIn("raw-sensitive-hash", finding["response"])
        self.assertNotIn("alice@example.test", finding["response"])

    def test_api_probe_redacts_identity_and_financial_baseline_values(self):
        tool = ApiAccessControlProbeTool()
        endpoint = {
            "method": "GET",
            "url": "https://example.test/debug/users",
            "source": "openapi",
        }
        body = (
            '{"users":[{"username":"alice","account_number":"502001",'
            '"balance":1250,"role":"admin"}]}'
        )
        response = {
            "url": endpoint["url"],
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": body,
            "elapsedMs": 10,
            "jsonKeys": tool._json_keys(body),
            "bodyLength": len(body),
            "sensitiveBodyMarkers": tool._sensitive_body_markers(body),
        }

        finding = tool._anonymous_sensitive_baseline_finding(endpoint, response, {})

        self.assertIsNotNone(finding)
        self.assertIn('"account_number":"[REDACTED]"', finding["response"])
        self.assertNotIn("502001", finding["response"])
        self.assertNotIn("alice", finding["response"])
        self.assertNotIn("1250", finding["response"])
        self.assertNotIn('"role":"admin"', finding["response"])

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

        action_by_tool = {action["tool"]: action for action in result["nextActions"]}
        dalfox_decision = action_by_tool["dalfox:xss_scan"]["nativeProbe"]
        self.assertEqual(dalfox_decision["version"], 1)
        self.assertEqual(dalfox_decision["status"], "BLOCKED")
        self.assertEqual(
            dalfox_decision["reasonCode"],
            "ADAPTER_NOT_IMPLEMENTED",
        )
        self.assertTrue(dalfox_decision["candidateIds"])
        self.assertNotIn("parameters", dalfox_decision)
        self.assertFalse(action_by_tool["dalfox:xss_scan"]["autonomousReady"])

    async def test_exploitation_queue_preserves_sanitized_form_default_signals(self):
        tool = ExploitationQueueTool()

        result = await tool.execute(
            {
                "target": "https://shop.example.test/",
                "forms": [
                    {
                        "action": "/product/stock",
                        "method": "POST",
                        "contentType": "application/x-www-form-urlencoded",
                        "fields": [
                            {
                                "name": "stockApi",
                                "type": "text",
                                "hasDefault": True,
                                "valueLength": 42,
                                "valueKind": "absolute-http-url",
                                "valueSource": "html-default",
                                "value": "https://must-not-survive.example/internal",
                            }
                        ],
                    }
                ],
            }
        )

        candidate = next(
            item
            for item in result["candidates"]
            if item["type"] == "state_changing_form"
        )
        self.assertEqual(candidate["contentType"], "application/x-www-form-urlencoded")
        self.assertEqual(
            candidate["fields"],
            [
                {
                    "name": "stockApi",
                    "type": "text",
                    "hasDefault": True,
                    "valueLength": 42,
                    "valueKind": "absolute-http-url",
                    "valueSource": "html-default",
                }
            ],
        )
        self.assertNotIn("must-not-survive.example", str(result))

        ssrf_candidate = next(
            item
            for item in result["candidates"]
            if item["type"] == "absolute_url_form_field"
        )
        self.assertEqual(ssrf_candidate["recommendedTools"], ["web:ssrf_probe"])
        ssrf_action = next(
            action
            for action in result["nextActions"]
            if action["tool"] == "web:ssrf_probe"
        )
        self.assertEqual(ssrf_action["nativeProbe"]["status"], "BLOCKED")
        self.assertEqual(
            ssrf_action["nativeProbe"]["reasonCode"],
            "ADAPTER_NOT_IMPLEMENTED",
        )

    async def test_exploitation_queue_preserves_opaque_artifact_candidate_id(self):
        tool = ExploitationQueueTool()
        artifact_candidate_id = "cand-0123456789abcdef"

        result = await tool.execute(
            {
                "target": "https://shop.example.test/",
                "forms": [
                    {
                        "action": "/product/stock",
                        "method": "POST",
                        "contentType": "application/x-www-form-urlencoded",
                        "nativeProbeCandidateId": artifact_candidate_id,
                        "fields": [
                            {
                                "name": "stockApi",
                                "type": "text",
                                "hasDefault": True,
                                "valueLength": 42,
                                "valueKind": "absolute-http-url",
                            }
                        ],
                    }
                ],
            }
        )

        native_action = next(
            action
            for action in result["nextActions"]
            if action["tool"] == "web:security_controls_probe"
        )
        self.assertIn(artifact_candidate_id, native_action["candidateIds"])
        self.assertNotIn("value", str(native_action["nativeProbe"]))

        ssrf_action = next(
            action
            for action in result["nextActions"]
            if action["tool"] == "web:ssrf_probe"
        )
        self.assertTrue(ssrf_action["autonomousReady"])
        self.assertEqual(
            ssrf_action["nativeProbe"],
            {
                "version": 1,
                "status": "READY",
                "adapterId": "web:ssrf_probe",
                "resolverVersion": 1,
                "candidateIds": [artifact_candidate_id],
                "candidateKinds": ["absolute_url_form_field"],
                "confidence": 0.96,
                "source": "exploitation-queue",
            },
        )
        self.assertNotIn("value", str(ssrf_action["nativeProbe"]))

    async def test_absolute_url_metadata_takes_ssrf_precedence_without_a_urlish_field_name(self):
        tool = ExploitationQueueTool()
        artifact_candidate_id = "cand-fedcba9876543210"

        result = await tool.execute(
            {
                "target": "https://fixture.example/",
                "forms": [
                    {
                        "action": "/lookup",
                        "method": "POST",
                        "contentType": "application/x-www-form-urlencoded; charset=UTF-8",
                        "nativeProbeCandidateId": artifact_candidate_id,
                        "fields": [
                            {
                                "name": "resource",
                                "type": "text",
                                "hasDefault": True,
                                "valueKind": "absolute-http-url",
                            }
                        ],
                    }
                ],
            }
        )

        ssrf_candidate = next(
            candidate
            for candidate in result["candidates"]
            if candidate["type"] == "absolute_url_form_field"
        )
        self.assertEqual(ssrf_candidate["confidence"], 0.92)
        ssrf_action = next(
            action for action in result["nextActions"] if action["tool"] == "web:ssrf_probe"
        )
        self.assertEqual(ssrf_action["nativeProbe"]["status"], "READY")
        self.assertNotIn("web:xxe_probe", [
            action["tool"] for action in result["nextActions"]
        ])

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
