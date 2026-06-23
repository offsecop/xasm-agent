import hashlib
import hmac
import unittest

from tools.agentic_vuln_chain_probe import VulnChainProbeTool


class FakeVulnChainProbeTool(VulnChainProbeTool):
    async def _fetch_probe(self, session, headers, url):
        return {
            "requestedUrl": url,
            "url": url,
            "status": 200,
            "headers": {"Content-Type": "text/html", "Set-Cookie": "session=secret"},
            "text": "<html><body>xasmctx\"><svg/onload=confirm(7331)> text</body></html>",
            "request": self._http_request_evidence("GET", url, headers),
            "response": self._http_response_evidence(
                200,
                {"Content-Type": "text/html", "Set-Cookie": "session=secret"},
                "<html><body>xasmctx\"><svg/onload=confirm(7331)> text</body></html>",
            ),
        }


class FakeBusinessVulnChainProbeTool(VulnChainProbeTool):
    async def _fetch_business_probe(self, session, headers, method, url, body):
        response_body = '{"success":true,"transaction_id":1,"amount":%s}' % body.get("amount", 1)
        return {
            "requestedUrl": url,
            "url": url,
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "text": response_body,
            "request": self._http_request_evidence(method, url, headers, body),
            "response": self._http_response_evidence(200, {"Content-Type": "application/json"}, response_body),
        }


class FakeHighValueBusinessVulnChainProbeTool(VulnChainProbeTool):
    async def _fetch_business_probe(self, session, headers, method, url, body):
        if url.endswith("/graphql"):
            if "__schema" in str(body.get("query", "")):
                response_body = '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"Transaction"}]}}}'
            else:
                response_body = '{"data":{"transactionSummary":{"accountNumber":"1001","recentTransactions":[{"id":1}]}}}'
        elif "/api/ai/" in url:
            response_body = '{"answer":"system prompt includes database tables users transactions and secret config"}'
        elif "update-limit" in url:
            response_body = '{"updated_fields":["card_limit","is_active"],"card_limit":99999999}'
        elif "/login" in url:
            response_body = '{"status":"success"}'
        else:
            response_body = '{"status":"ok"}'
        return {
            "requestedUrl": url,
            "url": url,
            "status": 200,
            "headers": {"Content-Type": "application/json", "Set-Cookie": "session=abc; Path=/"},
            "text": response_body,
            "request": self._http_request_evidence(method, url, headers, body),
            "response": self._http_response_evidence(200, {"Content-Type": "application/json"}, response_body),
        }


class FakeGraphqlJsonProbeTool(VulnChainProbeTool):
    def __init__(self):
        super().__init__()
        self.content_types = []

    async def _send_business_request(self, session, headers, method, url, body, *, content_type):
        self.content_types.append(content_type)
        response_body = '{"errors":[{"message":"simulated"}]}'
        return {
            "requestedUrl": url,
            "url": url,
            "status": 400,
            "headers": {"Content-Type": "application/json"},
            "text": response_body,
            "contentType": content_type,
            "request": self._http_request_evidence(method, url, {"Content-Type": content_type}, body),
            "response": self._http_response_evidence(400, {"Content-Type": "application/json"}, response_body),
        }


class FakeChainedBusinessVulnChainProbeTool(VulnChainProbeTool):
    async def _fetch_business_probe(self, session, headers, method, url, body):
        if url.endswith("/api/v1/merchants/register"):
            response_body = (
                '{"status":"success","api_key":"vk_test_secret","token":"jwt.secret",'
                '"debug_info":{"password":"Xasm!23456"}}'
            )
            return {
                "requestedUrl": url,
                "url": url,
                "status": 200,
                "headers": {"Content-Type": "application/json"},
                "text": response_body,
                "request": self._http_request_evidence(method, url, headers, body),
                "response": self._http_response_evidence(200, {"Content-Type": "application/json"}, response_body),
            }
        if url.endswith("/api/v1/payments/charge") and headers.get("X-Merchant-Api-Key"):
            response_body = (
                '{"status":"error","message":"Payment declined","payment_id":42,'
                '"debug_info":{"merchant_id":1,"submitted_card_number":"4111111111111111"}}'
            )
            return {
                "requestedUrl": url,
                "url": url,
                "status": 400,
                "headers": {"Content-Type": "application/json"},
                "text": response_body,
                "request": self._http_request_evidence(method, url, headers, body),
                "response": self._http_response_evidence(400, {"Content-Type": "application/json"}, response_body),
            }
        response_body = '{"status":"error","message":"Missing or invalid merchant credentials"}'
        return {
            "requestedUrl": url,
            "url": url,
            "status": 401,
            "headers": {"Content-Type": "application/json"},
            "text": response_body,
            "request": self._http_request_evidence(method, url, headers, body),
            "response": self._http_response_evidence(401, {"Content-Type": "application/json"}, response_body),
        }


class FakeAuthenticatedReadBusinessVulnChainProbeTool(FakeChainedBusinessVulnChainProbeTool):
    async def _fetch_business_read_probe(self, session, headers, url):
        if not headers.get("X-Merchant-Api-Key"):
            response_body = '{"status":"error","message":"missing credentials"}'
            return {
                "requestedUrl": url,
                "url": url,
                "status": 401,
                "headers": {"Content-Type": "application/json"},
                "text": response_body,
                "request": self._http_request_evidence("GET", url, headers),
                "response": self._http_response_evidence(401, {"Content-Type": "application/json"}, response_body),
            }
        if url.endswith("/api/v1/merchants/1"):
            response_body = '{"merchant_id":1,"email":"merchant1@example.com","balance":100}'
        elif url.endswith("/api/v1/merchants/2"):
            response_body = '{"merchant_id":2,"email":"merchant2@example.com","balance":250}'
        else:
            response_body = '{"status":"ok"}'
        return {
            "requestedUrl": url,
            "url": url,
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "text": response_body,
            "request": self._http_request_evidence("GET", url, headers),
            "response": self._http_response_evidence(200, {"Content-Type": "application/json"}, response_body),
        }


class FakeWeakJwtBusinessVulnChainProbeTool(VulnChainProbeTool):
    async def _fetch_business_read_probe(self, session, headers, url):
        auth_header = headers.get("Authorization", "")
        if not auth_header:
            response_body = '{"status":"error","message":"missing credentials"}'
            return {
                "requestedUrl": url,
                "url": url,
                "status": 401,
                "headers": {"Content-Type": "application/json"},
                "text": response_body,
                "request": self._http_request_evidence("GET", url, headers),
                "response": self._http_response_evidence(401, {"Content-Type": "application/json"}, response_body),
            }

        token = self._bearer_token_from_headers(headers)
        payload = {}
        parts = token.split(".")
        if len(parts) == 3:
            payload = self._decode_jwt_segment(parts[1]) or {}
        if url.endswith("/api/v1/merchants/me") and payload.get("is_admin") and payload.get("merchant_id") == 123:
            response_body = '{"merchant_id":123,"email":"merchant@example.com","api_key":"vk_secret","balance":100}'
            status = 200
        else:
            response_body = '{"status":"error","message":"invalid token"}'
            status = 401
        return {
            "requestedUrl": url,
            "url": url,
            "status": status,
            "headers": {"Content-Type": "application/json"},
            "text": response_body,
            "request": self._http_request_evidence("GET", url, headers),
            "response": self._http_response_evidence(status, {"Content-Type": "application/json"}, response_body),
        }


class VulnChainProbeEvidenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_contextual_xss_finding_includes_redacted_http_evidence(self):
        tool = FakeVulnChainProbeTool()

        result, used = await tool._probe_xss_context(
            None,
            {"Cookie": "session=super-secret", "User-Agent": "xASM-Test"},
            "http://example.test/api/transactions?account_number=1",
            "account_number",
        )

        self.assertEqual(used, 1)
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        evidence = finding["evidence"]

        self.assertIn("GET /api/transactions?account_number=", finding["request"])
        self.assertIn("Cookie: [REDACTED]", finding["request"])
        self.assertNotIn("super-secret", finding["request"])
        self.assertIn("HTTP/1.1 200", finding["response"])
        self.assertIn("<svg/onload=confirm(7331)>", finding["response"])
        self.assertIn("<svg/onload=confirm(7331)>", finding["matchedContent"])
        self.assertIn("<svg/onload=confirm(7331)>", evidence["matchedContent"])
        self.assertTrue(evidence["authenticatedContext"])
        self.assertEqual(evidence["parameter"], "account_number")
        self.assertEqual(evidence["status"], 200)

    def test_form_observation_evidence_uses_source_page_request_response(self):
        tool = VulnChainProbeTool()
        form = {
            "action": "http://example.test/login",
            "method": "POST",
            "fields": [{"name": "username"}, {"name": "password"}],
            "sourceUrl": "http://example.test/",
            "sourceRequest": "GET / HTTP/1.1\nHost: example.test",
            "sourceResponse": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<form>",
        }

        evidence = tool._form_observation_evidence(form, {"Cookie": "session=secret"})

        self.assertEqual(evidence["request"], "GET / HTTP/1.1\nHost: example.test")
        self.assertIn("HTTP/1.1 200", evidence["response"])
        self.assertEqual(evidence["observationType"], "form_metadata")

    def test_business_candidate_builder_keeps_payment_and_auth_bootstrap_login(self):
        tool = VulnChainProbeTool()

        candidates = tool._business_action_candidates(
            [
                {
                    "action": "https://vulnbank.test/api/v1/merchants/register",
                    "method": "POST",
                    "fields": [{"name": "email"}, {"name": "password"}],
                },
                {
                    "action": "https://vulnbank.test/api/v1/merchants/login",
                    "method": "POST",
                    "fields": [{"name": "email"}, {"name": "password"}],
                },
                {
                    "action": "https://vulnbank.test/api/v1/payments/charge",
                    "method": "POST",
                    "fields": [{"name": "amount"}, {"name": "card_number"}, {"name": "cvv"}],
                },
            ],
            "https://vulnbank.test/",
            {},
        )

        urls = [candidate["url"] for candidate in candidates]
        self.assertIn("https://vulnbank.test/api/v1/payments/charge", urls)
        self.assertIn("https://vulnbank.test/api/v1/merchants/register", urls)
        self.assertIn("https://vulnbank.test/api/v1/merchants/login", urls)

    def test_business_payload_variants_cover_amount_and_mass_assignment(self):
        tool = VulnChainProbeTool()

        variants = tool._business_payload_variants(
            {
                "method": "POST",
                "url": "https://vulnbank.test/api/users/1",
                "fieldNames": ["amount", "role", "is_admin"],
            }
        )

        kinds = {variant["kind"] for variant in variants}
        self.assertIn("baseline_state_change", kinds)
        self.assertIn("amount_boundary", kinds)
        self.assertIn("mass_assignment", kinds)

    def test_business_candidates_include_password_recovery_endpoint(self):
        tool = VulnChainProbeTool()

        candidates = tool._business_action_candidates(
            [
                {
                    "action": "https://vulnbank.test/api/v1/forgot-password",
                    "method": "POST",
                    "fields": [{"name": "username"}],
                }
            ],
            "https://vulnbank.test/",
            {},
        )

        urls = [candidate["url"] for candidate in candidates]
        self.assertIn("https://vulnbank.test/api/v1/forgot-password", urls)

    def test_business_payload_variants_cover_url_import_ssrf_and_recovery(self):
        tool = VulnChainProbeTool()

        ssrf_variants = tool._business_payload_variants(
            {
                "method": "POST",
                "url": "https://vulnbank.test/upload_profile_picture_url",
                "fieldNames": ["image_url"],
            }
        )
        recovery_variants = tool._business_payload_variants(
            {
                "method": "POST",
                "url": "https://vulnbank.test/api/v1/forgot-password",
                "fieldNames": ["username"],
            }
        )

        ssrf = [variant for variant in ssrf_variants if variant["kind"] == "ssrf_loopback_fetch"]
        recovery = [variant for variant in recovery_variants if variant["kind"] == "auth_recovery_probe"]
        self.assertGreaterEqual(len(ssrf), 1)
        self.assertTrue(any("127.0.0.1" in variant["body"]["image_url"] for variant in ssrf))
        self.assertGreaterEqual(len(recovery), 1)
        self.assertTrue(any(variant["body"]["username"] == "admin" for variant in recovery))

    def test_business_payload_variants_cover_login_graphql_ai_xss_and_cards(self):
        tool = VulnChainProbeTool()

        login_variants = tool._business_payload_variants(
            {
                "method": "POST",
                "url": "https://vulnbank.test/login",
                "fieldNames": ["username", "password"],
            }
        )
        graphql_variants = tool._business_payload_variants(
            {
                "method": "POST",
                "url": "https://vulnbank.test/graphql",
                "fieldNames": ["query", "variables"],
            }
        )
        ai_variants = tool._business_payload_variants(
            {
                "method": "POST",
                "url": "https://vulnbank.test/api/ai/chat",
                "fieldNames": ["message"],
            }
        )
        xss_variants = tool._business_payload_variants(
            {
                "method": "POST",
                "url": "https://vulnbank.test/update_bio",
                "fieldNames": ["bio"],
            }
        )
        card_variants = tool._business_payload_variants(
            {
                "method": "POST",
                "url": "https://vulnbank.test/api/virtual-cards/1/update-limit",
                "fieldNames": ["limit"],
            }
        )

        self.assertIn("default_login_probe", {variant["kind"] for variant in login_variants})
        self.assertIn("login_sqli_bypass_probe", {variant["kind"] for variant in login_variants})
        self.assertIn("graphql_introspection_probe", {variant["kind"] for variant in graphql_variants})
        self.assertIn("graphql_transaction_summary_probe", {variant["kind"] for variant in graphql_variants})
        self.assertIn("ai_prompt_injection_probe", {variant["kind"] for variant in ai_variants})
        self.assertIn("stored_xss_payload", {variant["kind"] for variant in xss_variants})
        self.assertIn("card_limit_mass_assignment", {variant["kind"] for variant in card_variants})

    async def test_business_priority_pass_reaches_graphql_ai_and_card_with_tight_budget(self):
        tool = FakeHighValueBusinessVulnChainProbeTool()
        forms = [
            {
                "action": f"https://vulnbank.test/api/login{i}",
                "method": "POST",
                "fields": [{"name": "username"}, {"name": "password"}],
            }
            for i in range(5)
        ]
        forms.extend(
            [
                {
                    "action": "https://vulnbank.test/api/v3/forgot-password",
                    "method": "POST",
                    "fields": [{"name": "username"}],
                },
                {
                    "action": "https://vulnbank.test/graphql",
                    "method": "POST",
                    "fields": [{"name": "query"}, {"name": "variables"}],
                },
                {
                    "action": "https://vulnbank.test/api/ai/chat",
                    "method": "POST",
                    "fields": [{"name": "message"}],
                },
                {
                    "action": "https://vulnbank.test/api/virtual-cards/1/update-limit",
                    "method": "POST",
                    "fields": [{"name": "limit"}],
                },
            ]
        )

        created, used = await tool._probe_business_logic(
            None,
            {},
            forms,
            "https://vulnbank.test/",
            16,
            {"allowUnsafeMethods": True, "riskTolerance": "aggressive"},
        )

        variants = [probe.get("variant") for probe in created["probes"] if probe.get("type") == "business_logic"]
        template_ids = {finding.get("template-id") for finding in created["findings"]}
        self.assertLessEqual(used, 16)
        self.assertIn("graphql_introspection_probe", variants)
        self.assertIn("ai_prompt_injection_probe", variants)
        self.assertIn("card_limit_mass_assignment", variants)
        self.assertIn("xasm-graphql-introspection-enabled", template_ids)
        self.assertIn("xasm-ai-prompt-sensitive-context-exposure", template_ids)
        self.assertIn("xasm-card-limit-mass-assignment", template_ids)

    def test_business_candidates_prioritize_recovery_and_url_fetch_before_generic_business(self):
        tool = VulnChainProbeTool()

        candidates = tool._business_action_candidates(
            [
                {
                    "action": "https://vulnbank.test/api/v1/payments/charge",
                    "method": "POST",
                    "fields": [{"name": "amount"}, {"name": "card_number"}, {"name": "cvv"}],
                },
                {
                    "action": "https://vulnbank.test/api/v1/merchants/register",
                    "method": "POST",
                    "fields": [{"name": "email"}, {"name": "password"}],
                },
                {
                    "action": "https://vulnbank.test/api/v3/forgot-password",
                    "method": "POST",
                    "fields": [{"name": "username"}],
                },
                {
                    "action": "https://vulnbank.test/upload_profile_picture_url",
                    "method": "POST",
                    "fields": [{"name": "image_url"}],
                },
            ],
            "https://vulnbank.test/",
            {},
        )

        urls = [candidate["url"] for candidate in candidates[:4]]
        self.assertEqual(urls[0], "https://vulnbank.test/api/v3/forgot-password")
        self.assertEqual(urls[1], "https://vulnbank.test/upload_profile_picture_url")

    def test_ssrf_finding_includes_initial_and_followup_evidence(self):
        tool = VulnChainProbeTool()
        candidate = {
            "method": "POST",
            "url": "https://vulnbank.test/upload_profile_picture_url",
            "fieldNames": ["image_url"],
        }
        variant = {
            "kind": "ssrf_loopback_fetch",
            "probeUrl": "http://127.0.0.1:5000/internal/config.json",
            "body": {"image_url": "http://127.0.0.1:5000/internal/config.json"},
        }
        result = {
            "status": 200,
            "text": '{"debug_info":{"fetched_url":"http://127.0.0.1:5000/internal/config.json","http_status":200},"file_path":"/uploads/probed.json"}',
            "request": "POST /upload_profile_picture_url HTTP/1.1",
            "response": "HTTP/1.1 200\n\n{\"file_path\":\"/uploads/probed.json\"}",
            "followupUrl": "https://vulnbank.test/uploads/probed.json",
            "followupStatus": 200,
            "followupText": "database=postgres\nsecret_key=example",
            "followupRequest": "GET /uploads/probed.json HTTP/1.1",
            "followupResponse": "HTTP/1.1 200\n\ndatabase=postgres\nsecret_key=example",
        }

        signal = tool._server_side_fetch_signal(candidate, variant, result)
        findings = tool._business_findings_for_variant(candidate, variant, result, {}, signal)

        self.assertEqual(signal, "secret_exposure")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["template-id"], "xasm-server-side-url-fetch-internal-resource")
        self.assertIn("POST /upload_profile_picture_url", finding["request"])
        self.assertIn("GET /uploads/probed.json", finding["evidence"]["followupRequest"])
        self.assertIn("secret_key", finding["evidence"]["followupResponse"])

    def test_auth_recovery_finding_uses_reset_material_evidence(self):
        tool = VulnChainProbeTool()
        candidate = {
            "method": "POST",
            "url": "https://vulnbank.test/api/v1/forgot-password",
            "fieldNames": ["username"],
        }
        variant = {
            "kind": "auth_recovery_probe",
            "probeIdentity": "admin",
            "body": {"username": "admin"},
        }
        result = {
            "status": 200,
            "text": '{"status":"ok","debug_info":{"reset_pin":"1234"}}',
            "request": "POST /api/v1/forgot-password HTTP/1.1",
            "response": "HTTP/1.1 200\n\n{\"debug_info\":{\"reset_pin\":\"1234\"}}",
        }

        self.assertTrue(tool._auth_recovery_exposure_signal(result))
        findings = tool._business_findings_for_variant(candidate, variant, result, {}, "secret_exposure")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["template-id"], "xasm-auth-recovery-reset-material-exposed")
        self.assertIn("reset_pin", findings[0]["response"])

    def test_auth_recovery_debug_metadata_gets_distinct_finding(self):
        tool = VulnChainProbeTool()
        candidate = {
            "method": "POST",
            "url": "https://vulnbank.test/api/v3/forgot-password",
            "fieldNames": ["username"],
        }
        variant = {
            "kind": "auth_recovery_probe",
            "probeIdentity": "admin",
            "body": {"username": "admin"},
        }
        result = {
            "status": 200,
            "text": '{"status":"success","debug_info":{"timestamp":"2026-06-23","username":"admin"},"message":"Reset PIN has been sent."}',
            "request": "POST /api/v3/forgot-password HTTP/1.1",
            "response": "HTTP/1.1 200\n\n{\"debug_info\":{\"username\":\"admin\"}}",
        }

        signal = tool._auth_recovery_exposure_signal(result)
        findings = tool._business_findings_for_variant(candidate, variant, result, {}, signal)

        self.assertEqual(signal, "debug_exposure")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["template-id"], "xasm-auth-recovery-debug-metadata-exposed")
        self.assertIn("debug_info", findings[0]["response"])

    def test_default_login_finding_and_cookie_context_are_reusable(self):
        tool = VulnChainProbeTool()
        candidate = {
            "method": "POST",
            "url": "https://vulnbank.test/login",
            "fieldNames": ["username", "password"],
        }
        variant = {
            "kind": "default_login_probe",
            "credential": "admin:admin",
            "body": {"username": "admin", "password": "admin"},
        }
        result = {
            "status": 200,
            "headers": {"Set-Cookie": "session=abc123; HttpOnly; Path=/"},
            "text": '{"status":"success"}',
            "request": "POST /login HTTP/1.1",
            "response": "HTTP/1.1 200\nSet-Cookie: [REDACTED]\n\n{\"status\":\"success\"}",
        }

        self.assertTrue(tool._default_login_success_signal(result))
        self.assertEqual(tool._business_auth_headers_from_response(result), [{"Cookie": "session=abc123"}])
        findings = tool._business_findings_for_variant(candidate, variant, result, {}, "secret_exposure")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["template-id"], "xasm-default-credentials-authenticated-session")
        self.assertIn("POST /login", findings[0]["request"])

    def test_login_sqli_bypass_finding_and_combined_auth_contexts_are_reusable(self):
        tool = VulnChainProbeTool()
        candidate = {"method": "POST", "url": "https://vulnbank.test/api/login", "fieldNames": ["username", "password"]}
        variant = {
            "kind": "login_sqli_bypass_probe",
            "body": {"username": "' OR '1'='1' --", "password": "xasm-any-password"},
            "payload": "' OR '1'='1' --",
        }
        result = {
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "text": '{"token":"jwt.secret","api_key":"merchant_secret","user":{"role":"admin"}}',
            "request": "POST /api/login HTTP/1.1",
            "response": "HTTP/1.1 200\n\n{\"token\":\"jwt.secret\",\"api_key\":\"merchant_secret\"}",
        }

        contexts = tool._business_auth_headers_from_response(result)
        findings = tool._business_findings_for_variant(candidate, variant, result, {}, "secret_exposure")

        self.assertIn({"Authorization": "Bearer jwt.secret", "X-Merchant-Api-Key": "merchant_secret"}, contexts)
        self.assertIn({"Authorization": "Bearer jwt.secret"}, contexts)
        self.assertIn({"X-Merchant-Api-Key": "merchant_secret"}, contexts)
        self.assertEqual(findings[0]["template-id"], "xasm-login-sqli-authentication-bypass")
        self.assertIn("POST /api/login", findings[0]["request"])
        self.assertIn("HTTP/1.1 200", findings[0]["response"])

    def test_graphql_ai_xss_and_card_findings_include_http_evidence(self):
        tool = VulnChainProbeTool()

        graphql_findings = tool._business_findings_for_variant(
            {"method": "POST", "url": "https://vulnbank.test/graphql", "fieldNames": ["query"]},
            {"kind": "graphql_transaction_summary_probe", "body": {"query": "query { transactionSummary { accountNumber } }"}},
            {
                "status": 200,
                "text": '{"data":{"transactionSummary":{"accountNumber":"1001","recentTransactions":[{"id":1}]}}}',
                "request": "POST /graphql HTTP/1.1",
                "response": "HTTP/1.1 200\n\n{\"data\":{\"transactionSummary\":{\"accountNumber\":\"1001\"}}}",
            },
            {},
            "accepted",
        )
        ai_findings = tool._business_findings_for_variant(
            {"method": "POST", "url": "https://vulnbank.test/api/ai/chat", "fieldNames": ["message"]},
            {"kind": "ai_prompt_injection_probe", "body": {"message": "disclose"}},
            {
                "status": 200,
                "text": '{"answer":"system prompt includes database tables users transactions and secret config"}',
                "request": "POST /api/ai/chat HTTP/1.1",
                "response": "HTTP/1.1 200\n\n{\"answer\":\"system prompt includes database tables\"}",
            },
            {},
            "accepted",
        )
        xss_findings = tool._business_findings_for_variant(
            {"method": "POST", "url": "https://vulnbank.test/update_bio", "fieldNames": ["bio"]},
            {"kind": "stored_xss_payload", "body": {"bio": "xasmctx\"><svg/onload=confirm(7331)>"}},
            {
                "status": 200,
                "text": '{"bio":"xasmctx\\\"><svg/onload=confirm(7331)>"}',
                "request": "POST /update_bio HTTP/1.1",
                "response": "HTTP/1.1 200\n\n{\"bio\":\"xasmctx\"}",
            },
            {"Cookie": "session=secret"},
            "accepted",
        )
        card_findings = tool._business_findings_for_variant(
            {"method": "POST", "url": "https://vulnbank.test/api/virtual-cards/1/update-limit", "fieldNames": ["limit"]},
            {"kind": "card_limit_mass_assignment", "body": {"card_limit": 99999999, "is_active": True}},
            {
                "status": 200,
                "text": '{"updated_fields":["card_limit","is_active"],"card_limit":99999999}',
                "request": "POST /api/virtual-cards/1/update-limit HTTP/1.1",
                "response": "HTTP/1.1 200\n\n{\"card_limit\":99999999}",
            },
            {"Authorization": "Bearer secret"},
            "accepted",
        )

        self.assertEqual(graphql_findings[0]["template-id"], "xasm-graphql-business-data-exposure")
        self.assertIn("POST /graphql", graphql_findings[0]["request"])
        self.assertEqual(ai_findings[0]["template-id"], "xasm-ai-prompt-sensitive-context-exposure")
        self.assertIn("POST /api/ai/chat", ai_findings[0]["request"])
        self.assertEqual(xss_findings[0]["template-id"], "xasm-stored-xss-payload-accepted")
        self.assertIn("POST /update_bio", xss_findings[0]["request"])
        self.assertEqual(card_findings[0]["template-id"], "xasm-card-limit-mass-assignment")
        self.assertIn("POST /api/virtual-cards/1/update-limit", card_findings[0]["request"])

    async def test_graphql_business_probe_keeps_json_content_type(self):
        tool = FakeGraphqlJsonProbeTool()

        await tool._fetch_business_probe(
            None,
            {},
            "POST",
            "https://vulnbank.test/graphql",
            {"query": "query { transactionSummary { accountNumber } }"},
        )

        self.assertEqual(tool.content_types, ["application/json"])

    def test_business_debug_error_disclosure_includes_http_evidence(self):
        tool = VulnChainProbeTool()
        candidate = {
            "method": "POST",
            "url": "https://vulnbank.test/api/virtual-cards/1/update-limit",
            "fieldNames": ["limit", "card_limit"],
        }
        variant = {
            "kind": "card_limit_mass_assignment",
            "body": {"card_limit": 99999999, "is_active": True},
        }
        result = {
            "status": 500,
            "text": '{"error":"syntax error at or near \\"limit\\"","debug_info":{"merchant_id":1,"card_limit":99999999}}',
            "request": "POST /api/virtual-cards/1/update-limit HTTP/1.1",
            "response": "HTTP/1.1 500\n\n{\"error\":\"syntax error at or near limit\"}",
        }

        signal = tool._business_response_signal(result)
        findings = tool._business_findings_for_variant(candidate, variant, result, {"Authorization": "Bearer secret"}, signal)

        self.assertEqual(signal, "debug_exposure")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["template-id"], "xasm-business-debug-error-disclosure")
        self.assertEqual(finding["info"]["severity"], "high")
        self.assertIn("POST /api/virtual-cards/1/update-limit", finding["request"])
        self.assertIn("HTTP/1.1 500", finding["response"])
        self.assertIn("debug_reason=", finding["matchedContent"])

    async def test_business_probe_emits_request_response_evidence(self):
        tool = FakeBusinessVulnChainProbeTool()

        result, used = await tool._probe_business_logic(
            None,
            {},
            [
                {
                    "action": "https://vulnbank.test/api/v1/payments/charge",
                    "method": "POST",
                    "fields": [{"name": "amount"}, {"name": "card_number"}, {"name": "cvv"}],
                }
            ],
            "https://vulnbank.test/",
            5,
            {"riskTolerance": "aggressive", "allowUnsafeMethods": True},
        )

        self.assertGreaterEqual(used, 1)
        self.assertGreaterEqual(len(result["findings"]), 1)
        first = result["findings"][0]
        self.assertIn("POST /api/v1/payments/charge HTTP/1.1", first["request"])
        self.assertIn("HTTP/1.1 200", first["response"])
        self.assertIn("variant=", first["matchedContent"])

    async def test_business_probe_reuses_auth_artifact_for_followup_side_effect(self):
        tool = FakeChainedBusinessVulnChainProbeTool()

        result, used = await tool._probe_business_logic(
            None,
            {},
            [
                {
                    "action": "https://vulnbank.test/api/v1/merchants/register",
                    "method": "POST",
                    "fields": [{"name": "name"}, {"name": "email"}, {"name": "password"}],
                },
                {
                    "action": "https://vulnbank.test/api/v1/payments/charge",
                    "method": "POST",
                    "fields": [{"name": "amount"}, {"name": "card_number"}, {"name": "cvv"}],
                },
            ],
            "https://vulnbank.test/",
            8,
            {"riskTolerance": "aggressive", "allowUnsafeMethods": True},
        )

        template_ids = {finding["template-id"] for finding in result["findings"]}
        self.assertIn("xasm-business-auth-artifact-exposure", template_ids)
        self.assertIn("xasm-business-side-effect-on-rejected-request", template_ids)
        self.assertGreaterEqual(used, 2)
        payment_probe = next(
            probe
            for probe in result["probes"]
            if probe.get("url", "").endswith("/api/v1/payments/charge") and probe.get("authenticatedContext")
        )
        self.assertIn("X-Merchant-Api-Key: [REDACTED]", payment_probe["request"])

    async def test_authenticated_business_chain_mutates_object_reference_with_evidence(self):
        tool = FakeAuthenticatedReadBusinessVulnChainProbeTool()

        result, used = await tool._probe_business_logic(
            None,
            {},
            [
                {
                    "action": "https://vulnbank.test/api/v1/merchants/register",
                    "method": "POST",
                    "fields": [{"name": "name"}, {"name": "email"}, {"name": "password"}],
                }
            ],
            "https://vulnbank.test/",
            40,
            {"riskTolerance": "aggressive", "allowUnsafeMethods": True},
        )

        template_ids = {finding["template-id"] for finding in result["findings"]}
        self.assertIn("xasm-business-object-reference-access", template_ids)
        idor = next(
            finding
            for finding in result["findings"]
            if finding["template-id"] == "xasm-business-object-reference-access"
        )
        self.assertIn("GET /api/v1/merchants/2 HTTP/1.1", idor["request"])
        self.assertIn("X-Merchant-Api-Key: [REDACTED]", idor["request"])
        self.assertIn("merchant2@example.com", idor["response"])
        self.assertIn("baseline=https://vulnbank.test/api/v1/merchants/1", idor["matchedContent"])
        self.assertGreaterEqual(used, 3)

    async def test_authenticated_business_chain_probes_weak_jwt_with_evidence(self):
        tool = FakeWeakJwtBusinessVulnChainProbeTool()
        header = tool._encode_jwt_segment({"alg": "HS256", "typ": "JWT"})
        payload = tool._encode_jwt_segment({"merchant_id": 123, "is_merchant": True})
        signing_input = f"{header}.{payload}"
        signature = tool._jwt_b64url(hmac.new(b"secret123", signing_input.encode(), hashlib.sha256).digest())
        token = f"{signing_input}.{signature}"

        result, used = await tool._probe_authenticated_business_chains(
            None,
            [{"Authorization": f"Bearer {token}"}],
            "https://vulnbank.test/",
            {},
            8,
        )

        template_ids = {finding["template-id"] for finding in result["findings"]}
        self.assertIn("xasm-weak-jwt-accepted-for-business-api", template_ids)
        finding = next(
            item for item in result["findings"]
            if item["template-id"] == "xasm-weak-jwt-accepted-for-business-api"
        )
        self.assertIn("GET /api/v1/merchants/me HTTP/1.1", finding["request"])
        self.assertIn("Authorization: [REDACTED]", finding["request"])
        self.assertIn("merchant@example.com", finding["response"])
        self.assertIn("weak JWT accepted", finding["matchedContent"])
        self.assertGreaterEqual(used, 2)

    def test_openapi_sensitive_read_candidates_include_internal_and_metadata_paths(self):
        tool = VulnChainProbeTool()

        urls = tool._business_read_candidates(
            "https://vulnbank.test/",
            {
                "apiEndpoints": [
                    {
                        "method": "GET",
                        "url": "https://vulnbank.test/internal/secret",
                        "path": "/internal/secret",
                        "source": "openapi",
                    },
                    {
                        "method": "GET",
                        "url": "https://vulnbank.test/latest/meta-data/iam/security-credentials/vulnbank-role",
                        "path": "/latest/meta-data/iam/security-credentials/vulnbank-role",
                        "source": "openapi",
                    },
                    {
                        "method": "GET",
                        "url": "https://vulnbank.test/api/ai/system-info",
                        "path": "/api/ai/system-info",
                        "source": "openapi",
                    },
                ],
            },
        )

        self.assertIn("https://vulnbank.test/internal/secret", urls)
        self.assertIn("https://vulnbank.test/latest/meta-data/iam/security-credentials/vulnbank-role", urls)
        self.assertIn("https://vulnbank.test/api/ai/system-info", urls)

    def test_business_read_candidates_accept_string_api_endpoints_and_url_lists(self):
        tool = VulnChainProbeTool()

        urls = tool._business_read_candidates(
            "https://vulnbank.test/",
            {
                "apiEndpoints": [
                    "https://vulnbank.test/api/v1/merchants/me",
                ],
                "urls": [
                    "https://vulnbank.test/api/transactions?account_number=1",
                    "https://vulnbank.test/static/app.js",
                ],
            },
        )

        self.assertIn("https://vulnbank.test/api/v1/merchants/me", urls)
        self.assertIn("https://vulnbank.test/api/transactions?account_number=1", urls)
        self.assertNotIn("https://vulnbank.test/static/app.js", urls)

    def test_openapi_placeholder_read_candidates_are_expanded_for_followup_probes(self):
        tool = VulnChainProbeTool()

        urls = tool._business_read_candidates(
            "https://vulnbank.test/",
            {
                "apiEndpoints": [
                    {
                        "method": "GET",
                        "path": "/api/v1/payments/{payment_id}",
                        "source": "openapi",
                    },
                    {
                        "method": "GET",
                        "path": "/api/v3/user/<int:user_id>",
                        "source": "openapi",
                    },
                    {
                        "method": "GET",
                        "path": "/{full_path}",
                        "source": "openapi",
                    },
                ],
            },
        )

        self.assertIn("https://vulnbank.test/api/v1/payments/1", urls)
        self.assertIn("https://vulnbank.test/api/v3/user/1", urls)
        self.assertNotIn("https://vulnbank.test/1", urls)

    def test_openapi_placeholder_write_candidates_are_expanded_for_active_checks(self):
        tool = VulnChainProbeTool()

        candidates = tool._business_action_candidates(
            [],
            "https://vulnbank.test/",
            {
                "apiEndpoints": [
                    {
                        "method": "PATCH",
                        "path": "/api/v1/users/{id}",
                        "source": "openapi",
                        "pathParameters": ["id"],
                        "requestBodyKeys": ["role", "is_admin", "email"],
                    }
                ],
            },
        )

        urls = [candidate["url"] for candidate in candidates]
        self.assertIn("https://vulnbank.test/api/v1/users/1", urls)
        user_candidate = next(candidate for candidate in candidates if candidate["url"].endswith("/api/v1/users/1"))
        self.assertIn("role", user_candidate["fieldNames"])
        self.assertIn("id", user_candidate["fieldNames"])

    def test_js_bundle_endpoints_become_business_candidates(self):
        tool = VulnChainProbeTool()
        script = """
            axios.post('/api/v1/payments/charge', { amount: 1, card_number: '4111111111111111' });
            axios.get('/api/v1/merchants/me');
            fetch('https://evil.example/api/v1/payments/charge', { method: 'POST' });
            fetch('/static/app.css');
        """

        extracted = tool._extract_js_bundle_endpoints(
            script,
            "https://vulnbank.test/static/merchant.js",
            "https://vulnbank.test/",
        )

        self.assertIn("https://vulnbank.test/api/v1/payments/charge", extracted["urls"])
        self.assertIn("https://vulnbank.test/api/v1/merchants/me", extracted["urls"])
        self.assertNotIn("https://evil.example/api/v1/payments/charge", extracted["urls"])
        self.assertNotIn("https://vulnbank.test/static/app.css", extracted["urls"])

        action = next(form for form in extracted["forms"] if form["action"].endswith("/api/v1/payments/charge"))
        self.assertEqual(action["method"], "POST")
        field_names = [field["name"] for field in action["fields"]]
        self.assertIn("amount", field_names)
        self.assertIn("card_number", field_names)

        candidates = tool._business_action_candidates(extracted["forms"], "https://vulnbank.test/")
        payment = next(candidate for candidate in candidates if candidate["url"].endswith("/api/v1/payments/charge"))
        self.assertEqual(payment["source"], "js-bundle")
        self.assertIn("amount", payment["fieldNames"])

    def test_js_bundle_payload_keys_are_used_for_business_candidates(self):
        tool = VulnChainProbeTool()
        script = """
            async function submitPayment(card) {
                return fetch('/api/v2/payments/charge', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        amount: 100,
                        currency: 'USD',
                        card_number: card.number,
                        cvv: card.cvv,
                        merchant_order_id: order.id
                    })
                });
            }
        """

        extracted = tool._extract_js_bundle_endpoints(
            script,
            "https://vulnbank.test/static/checkout.js",
            "https://vulnbank.test/",
        )

        action = next(form for form in extracted["forms"] if form["action"].endswith("/api/v2/payments/charge"))
        field_names = [field["name"] for field in action["fields"]]
        for expected in ["amount", "currency", "card_number", "cvv", "merchant_order_id"]:
            self.assertIn(expected, field_names)

        candidates = tool._business_action_candidates(extracted["forms"], "https://vulnbank.test/")
        payment = next(candidate for candidate in candidates if candidate["url"].endswith("/api/v2/payments/charge"))
        for expected in ["amount", "card_number", "cvv", "merchant_order_id"]:
            self.assertIn(expected, payment["fieldNames"])

    def test_openapi_discovery_merge_respects_active_write_gate(self):
        tool = VulnChainProbeTool()
        api_discovery = {
            "apiEndpoints": [
                {
                    "method": "GET",
                    "url": "https://vulnbank.test/api/v1/accounts/1",
                    "source": "openapi",
                },
                {
                    "method": "POST",
                    "url": "https://vulnbank.test/api/v1/payments/charge",
                    "requestBodyKeys": ["amount", "card_number"],
                    "source": "openapi",
                },
            ]
        }

        urls: list[str] = []
        forms: list[dict] = []
        added = tool._merge_api_discovery_result("https://vulnbank.test/", {}, api_discovery, urls, forms)

        self.assertEqual(added, 0)
        self.assertIn("https://vulnbank.test/api/v1/accounts/1", urls)
        self.assertIn("https://vulnbank.test/api/v1/payments/charge", urls)
        self.assertEqual(forms, [])

        active_urls: list[str] = []
        active_forms: list[dict] = []
        active_added = tool._merge_api_discovery_result(
            "https://vulnbank.test/",
            {"riskTolerance": "aggressive"},
            api_discovery,
            active_urls,
            active_forms,
        )

        self.assertEqual(active_added, 1)
        form = active_forms[0]
        self.assertEqual(form["_origin"], "openapi")
        self.assertEqual(form["method"], "POST")
        field_names = [field["name"] for field in form["fields"]]
        self.assertIn("amount", field_names)
        self.assertIn("card_number", field_names)

    def test_business_path_risk_marks_secret_and_metadata_paths_critical(self):
        tool = VulnChainProbeTool()

        self.assertEqual(tool._business_path_risk("https://vulnbank.test/internal/secret"), "critical")
        self.assertEqual(
            tool._business_path_risk("https://vulnbank.test/latest/meta-data/iam/security-credentials/role"),
            "critical",
        )

    def test_public_sensitive_read_finding_accepts_non_json_metadata_evidence(self):
        tool = VulnChainProbeTool()

        finding = tool._public_business_read_finding(
            "https://vulnbank.test/latest/meta-data/iam/security-credentials/vulnbank-role",
            {
                "status": 200,
                "headers": {"Content-Type": "text/plain"},
                "text": "AccessKeyId: AKIAEXAMPLE\nSecretAccessKey: secret\nToken: session-token",
                "request": "GET /latest/meta-data/iam/security-credentials/vulnbank-role HTTP/1.1",
                "response": "HTTP/1.1 200\n\nAccessKeyId: AKIAEXAMPLE",
            },
        )

        self.assertIsNotNone(finding)
        self.assertEqual(finding["template-id"], "xasm-business-public-sensitive-read")
        self.assertIn("cloud-instance-metadata", finding["evidence"]["sensitiveMarkers"])
        self.assertIn("GET /latest/meta-data", finding["request"])


if __name__ == "__main__":
    unittest.main()
