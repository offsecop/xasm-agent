import json
import re
import socket
import unittest
from urllib.parse import parse_qs, urlsplit

from aiohttp import web

from tools.web_cors_probe import (
    LAB_LABELS,
    LAB_PROOF,
    MODE,
    RUNTIME_LABELS,
    RUNTIME_PROOF,
    WebCorsProbeTool,
    _PinnedOrigin,
)


COOKIE = "session=server-owned-cookie-secret"
AUTHORIZATION = "Bearer server-owned-authorization-secret"
API_KEY = "synthetic-cors-api-key-5cf38a7be1"


class _Server:
    def __init__(self, app):
        self.app = app
        self.runner = None

    async def __aenter__(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        return site._server.sockets[0].getsockname()[1]

    async def __aexit__(self, exc_type, exc, tb):
        await self.runner.cleanup()


class _LocalCorsTool(WebCorsProbeTool):
    async def _resolve_origin(self, url):
        scheme, hostname, port = self._origin_parts(url)
        return _PinnedOrigin(scheme, hostname, port, socket.AF_INET, "127.0.0.1")

    @staticmethod
    def _origin_parts(url):
        parsed = urlsplit(url)
        return (
            parsed.scheme,
            parsed.hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )


def _fixture(
    *,
    cors_mode="reflect",
    acac=True,
    body_drift=False,
    endpoint_redirect=False,
    anonymous_leak=False,
    off_origin_link=False,
):
    state = {
        "requests": [],
        "solved": False,
        "stored": "",
        "receipts": {},
        "attacker_origins": [],
        "account_calls": 0,
    }
    app = web.Application()

    def target_host(request):
        return request.host.split(":", 1)[0] == "cors-fixture.lab"

    def exploit_host(request):
        return request.host.split(":", 1)[0] == "cors-exploit-fixture.lab"

    def is_authenticated(request):
        return request.headers.get("Cookie") == COOKIE

    def cors_headers(origin):
        if not origin:
            return []
        if origin.endswith(".xasm-cors.invalid") and origin not in state["attacker_origins"]:
            state["attacker_origins"].append(origin)
        reflected = origin
        if cors_mode == "wildcard":
            reflected = "*"
        elif cors_mode == "fixed":
            reflected = "https://fixed.example"
        elif cors_mode == "one-origin" and origin.endswith(".xasm-cors.invalid"):
            if state["attacker_origins"] and origin != state["attacker_origins"][0]:
                return []
        values = [("Access-Control-Allow-Origin", reflected)]
        if cors_mode == "duplicate":
            values.append(("Access-Control-Allow-Origin", reflected))
        if acac:
            values.append(("Access-Control-Allow-Credentials", "true"))
        return values

    async def handler(request):
        state["requests"].append(
            {
                "host": request.host,
                "method": request.method,
                "path": request.path_qs,
                "cookie": request.headers.get("Cookie"),
                "authorization": request.headers.get("Authorization"),
                "origin": request.headers.get("Origin"),
            }
        )
        if target_host(request):
            if request.path == "/":
                marker = "is-solved" if state["solved"] else "is-notsolved"
                evil = "<a href='http://evil.invalid/steal'>evil</a>" if off_origin_link else ""
                return web.Response(
                    text=(
                        f"<html><body class='{marker}'>"
                        "<a href='/my-account'>My account</a>"
                        f"<a href='http://cors-exploit-fixture.lab:{request.url.port}/'>"
                        "Go to exploit server</a>"
                        f"{evil}</body></html>"
                    ),
                    content_type="text/html",
                )
            if request.path.startswith("/.xasm-cors-negative-"):
                return web.Response(status=404, text="not found")
            if request.path == "/my-account":
                if not is_authenticated(request):
                    return web.Response(status=401, text="unauthorized")
                return web.Response(
                    text=(
                        "<html><script>fetch('/accountDetails',{credentials:'include'})"
                        ".then(r=>r.json())</script></html>"
                    ),
                    content_type="text/html",
                )
            if request.path == "/accountDetails":
                if endpoint_redirect:
                    return web.Response(status=302, headers={"Location": "/login"})
                if not is_authenticated(request) and not anonymous_leak:
                    return web.json_response({"error": "authentication required"}, status=401)
                state["account_calls"] += 1
                value = API_KEY
                if body_drift and request.headers.get("Origin", "").endswith(".xasm-cors.invalid"):
                    if state["account_calls"] % 2 == 0:
                        value = API_KEY + "-drift"
                response = web.json_response(
                    {
                        "username": "fixture-user",
                        "email": "fixture.user@example.test",
                        "apiKey": value,
                    }
                )
                for name, header_value in cors_headers(request.headers.get("Origin")):
                    response.headers.add(name, header_value)
                return response
            if request.path == "/submitSolution" and request.method == "POST":
                data = await request.post()
                correct = data.get("answer") == API_KEY
                if correct:
                    state["solved"] = True
                return web.json_response({"correct": correct, "solved": state["solved"]})
            return web.Response(status=404, text="not found")

        if exploit_host(request):
            if request.path == "/" and request.method == "GET":
                return web.Response(
                    text=(
                        "<html><a href='/log'>Access log</a>"
                        "<form method='POST' action='/'>"
                        "<input name='urlIsHttps' value='on'>"
                        "<input name='responseFile' value='/exploit'>"
                        "<textarea name='responseHead'>HTTP/1.1 200 OK</textarea>"
                        "<textarea name='responseBody'>placeholder</textarea>"
                        "<button name='formAction' value='STORE'>Store</button>"
                        "<button name='formAction' value='DELIVER_TO_VICTIM'>Deliver</button>"
                        "</form></html>"
                    ),
                    content_type="text/html",
                )
            if request.path == "/" and request.method == "POST":
                data = await request.post()
                action = data.get("formAction")
                if action == "STORE":
                    state["stored"] = data.get("responseBody", "")
                    return web.Response(text="stored")
                if action == "DELIVER_TO_VICTIM" and data.get("responseBody") == state["stored"]:
                    return web.Response(status=302, headers={"Location": "/deliver-to-victim"})
                return web.Response(status=400, text="bad action")
            if request.path == "/deliver-to-victim" and request.method == "GET":
                nonce_match = re.search(
                    r"const xasmNonce='(xasm-cors-[0-9a-f]{32})'", state["stored"]
                )
                if not nonce_match:
                    return web.Response(status=400, text="missing nonce")
                receipt = "receipt-" + nonce_match.group(1)
                state["receipts"][receipt] = {
                    "nonce": nonce_match.group(1),
                    "value": API_KEY,
                }
                return web.Response(status=302, headers={"Location": "/"})
            if request.path == "/exploit":
                if not state["stored"]:
                    return web.Response(status=404, text="missing")
                return web.Response(text=state["stored"], content_type="text/html")
            if request.path == "/log":
                links = "".join(
                    f"<p>{record['nonce']} [REDACTED] "
                    f"<a href='/exfil-value?receipt={receipt}'>receipt</a></p>"
                    for receipt, record in state["receipts"].items()
                )
                return web.Response(text=links, content_type="text/html")
            if request.path == "/exfil-value":
                receipt = request.query.get("receipt", "")
                record = state["receipts"].pop(receipt, None)
                if record is None:
                    return web.Response(status=404, text="gone")
                return web.json_response(record)
            return web.Response(status=404, text="not found")

        return web.Response(status=421, text="unknown host")

    app.router.add_route("*", "/{tail:.*}", handler)
    return app, state


def _runtime_parameters(port, **overrides):
    result = {
        "target": f"http://cors-fixture.lab:{port}/",
        "mode": MODE,
        "proofLevel": RUNTIME_PROOF,
        "engagement": "standard",
        "discoverFromTarget": True,
        "discoveryPageBudget": 5,
        "candidateBudget": 6,
        "requestBudget": 32,
        "maxResponseBytes": 96_000,
        "stopAfterFirstFinding": True,
        "authCookies": COOKIE,
        "authHeaders": {"Authorization": AUTHORIZATION},
    }
    result.update(overrides)
    return result


def _lab_parameters(port, **overrides):
    result = _runtime_parameters(
        port,
        proofLevel=LAB_PROOF,
        engagement="lab",
        requestBudget=48,
        allowUnsafeMethods=True,
        stateChangeApproved=True,
        labDeliveryApproved=True,
        solutionSubmitApproved=True,
        allowDiscoveredExploitServer=True,
    )
    result.update(overrides)
    return result


class WebCorsProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tool = _LocalCorsTool()

    def test_schema_is_closed_and_public_request_shape_is_not_model_controlled(self):
        schema = self.tool.schema
        self.assertEqual(self.tool.name, "web:cors_probe")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["required"], ["target"])
        self.assertEqual(schema["properties"]["mode"]["enum"], [MODE])
        self.assertEqual(schema["properties"]["discoveryPageBudget"]["maximum"], 5)
        self.assertEqual(schema["properties"]["candidateBudget"]["maximum"], 6)
        self.assertEqual(schema["properties"]["requestBudget"]["maximum"], 48)
        self.assertEqual(schema["properties"]["maxResponseBytes"]["maximum"], 96_000)
        for forbidden in (
            "endpoint", "path", "origin", "headers", "cookie", "exploitServer",
            "payload", "answer",
        ):
            self.assertNotIn(forbidden, schema["properties"])
        for key in (
            "proofLevel", "engagement", "discoverFromTarget", "discoveryPageBudget",
            "candidateBudget", "requestBudget", "maxResponseBytes", "stopAfterFirstFinding",
            "allowUnsafeMethods", "stateChangeApproved", "labDeliveryApproved",
            "solutionSubmitApproved", "allowDiscoveredExploitServer",
        ):
            self.assertTrue(schema["properties"][key]["x-workflow-owned"])
        self.assertTrue(schema["properties"]["authCookies"]["x-hidden"])
        self.assertTrue(schema["properties"]["authHeaders"]["x-hidden"])

    async def test_positive_runtime_proves_two_origins_with_exact_evidence_order(self):
        app, state = _fixture()
        async with _Server(app) as port:
            result = await self.tool.execute(_runtime_parameters(port))
        self.assertTrue(result["success"])
        self.assertTrue(result["verified"])
        self.assertFalse(result["fallback"])
        self.assertEqual(result["proofLevel"], RUNTIME_PROOF)
        self.assertEqual(result["total_findings"], 1)
        verification = result["verification"]
        self.assertEqual(verification["sensitiveField"], "apiKey")
        self.assertTrue(verification["anonymousControlDenied"])
        self.assertTrue(verification["actualResponseStable"])
        self.assertNotEqual(
            verification["attackerOriginPrimary"], verification["attackerOriginSecondary"]
        )
        self.assertEqual(
            [step["label"] for step in verification["corsEvidence"]["steps"]],
            list(RUNTIME_LABELS),
        )
        for step in verification["corsEvidence"]["steps"]:
            self.assertEqual(
                set(step),
                {
                    "label", "url", "request", "requestSha256", "response",
                    "responseSha256", "responseBodySha256", "responseBodyLength",
                    "responseStatus", "responseExcerptTruncated", "authContextSha256",
                },
            )
            self.assertFalse(step["responseExcerptTruncated"])
        self.assertIsNone(
            verification["corsEvidence"]["steps"][3]["authContextSha256"]
        )
        sensitive_body = verification["corsEvidence"]["steps"][4]["response"].split(
            "\r\n\r\n", 1
        )[1]
        self.assertEqual(list(json.loads(sensitive_body)), ["apiKey"])
        self.assertTrue(all(row["method"] == "GET" for row in state["requests"]))

    async def test_cookie_auth_is_required_and_authorization_alone_is_insufficient(self):
        result = await self.tool.execute(
            {
                "target": "https://example.test/",
                "authHeaders": {"Authorization": AUTHORIZATION},
            }
        )
        self.assertFalse(result["success"])
        self.assertIn("cookie", result["error"])
        self.assertNotIn(AUTHORIZATION, json.dumps(result))

    async def test_missing_acac_fails_closed(self):
        await self._assert_no_finding(acac=False)

    async def test_wildcard_acao_fails_closed(self):
        await self._assert_no_finding(cors_mode="wildcard")

    async def test_fixed_acao_fails_closed(self):
        await self._assert_no_finding(cors_mode="fixed")

    async def test_duplicate_acao_fails_closed(self):
        await self._assert_no_finding(cors_mode="duplicate")

    async def test_only_one_attacker_origin_fails_closed(self):
        await self._assert_no_finding(cors_mode="one-origin")

    async def test_authenticated_body_drift_fails_closed(self):
        await self._assert_no_finding(body_drift=True)

    async def test_redirected_endpoint_fails_closed_without_following(self):
        app, state = _fixture(endpoint_redirect=True)
        async with _Server(app) as port:
            result = await self.tool.execute(_runtime_parameters(port))
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])
        self.assertFalse(any(row["path"] == "/login" for row in state["requests"]))

    async def test_off_origin_discovery_links_are_never_requested(self):
        app, state = _fixture(off_origin_link=True)
        async with _Server(app) as port:
            result = await self.tool.execute(_runtime_parameters(port))
        self.assertTrue(result["verified"])
        self.assertFalse(any("evil.invalid" in row["host"] for row in state["requests"]))

    async def test_anonymous_sensitive_body_is_not_confidentiality_proof(self):
        await self._assert_no_finding(anonymous_leak=True)

    async def test_secret_email_cookie_authorization_and_set_cookie_are_not_serialized(self):
        app, _state = _fixture()
        async with _Server(app) as port:
            result = await self.tool.execute(_runtime_parameters(port))
        serialized = json.dumps(result)
        self.assertTrue(result["verified"])
        self.assertNotIn(API_KEY, serialized)
        self.assertNotIn("fixture.user@example.test", serialized)
        self.assertNotIn(COOKIE, serialized)
        self.assertNotIn(AUTHORIZATION, serialized)
        self.assertNotIn("Cookie:", serialized)
        self.assertNotIn("Authorization:", serialized)
        self.assertRegex(
            serialized,
            r"\[REDACTED sha256=[0-9a-f]{64} len=[0-9]+\]",
        )
        self.assertEqual(result["verification"]["sensitiveValueSha256"], self._sha(API_KEY))

    async def test_positive_fixture_lab_flow_uses_exact_suffix_and_three_posts(self):
        app, state = _fixture()
        async with _Server(app) as port:
            result = await self.tool.execute(_lab_parameters(port))
        self.assertTrue(result["success"])
        self.assertTrue(result["verified"])
        verification = result["verification"]
        self.assertTrue(verification["labSolvedTransition"])
        self.assertEqual(verification["stateChangingRequestCount"], 4)
        self.assertEqual(
            verification["stateChangingMethods"], ["POST", "POST", "GET", "POST"]
        )
        self.assertRegex(verification["exfilNonceSha256"], r"^[0-9a-f]{64}$")
        labels = [step["label"] for step in verification["corsEvidence"]["steps"]]
        self.assertEqual(labels, [*RUNTIME_LABELS, *LAB_LABELS])
        by_label = {
            step["label"]: step for step in verification["corsEvidence"]["steps"]
        }
        for label in (
            "lab-exploit-server-discovery",
            "lab-exploit-store",
            "lab-exploit-content-control",
            "lab-exploit-deliver",
            "lab-exploit-delivery-follow",
            "lab-exfil-log",
        ):
            self.assertIsNone(by_label[label]["authContextSha256"])
        self.assertEqual(urlsplit(by_label["lab-exfil-log"]["url"]).path, "/log")
        self.assertEqual(by_label["lab-exfil-log"]["response"].count("[REDACTED sha256="), 1)
        submit = by_label["lab-solution-submit"]
        submit_head, submit_body = submit["request"].split("\r\n\r\n", 1)
        declared_length = int(
            re.search(r"(?im)^Content-Length:\s*(\d+)$", submit_head).group(1)
        )
        self.assertEqual(declared_length, len(submit_body.encode()))
        self.assertEqual(submit["response"].split("\r\n\r\n", 1)[1], '{"correct":true}')
        self.assertEqual(
            verification["exfilValueSha256"], verification["solutionAnswerSha256"]
        )
        posts = [row for row in state["requests"] if row["method"] == "POST"]
        self.assertEqual(len(posts), 3)
        self.assertEqual([row["path"] for row in posts], ["/", "/", "/submitSolution"])
        self.assertTrue(state["solved"])
        serialized = json.dumps(result)
        self.assertNotIn(API_KEY, serialized)
        self.assertNotIn(COOKIE, serialized)
        self.assertNotIn(AUTHORIZATION, serialized)
        self.assertFalse(
            any(
                row["cookie"] or row["authorization"]
                for row in state["requests"]
                if row["host"].startswith("cors-exploit-fixture.lab")
            )
        )

    async def test_each_lab_gate_is_mandatory(self):
        gates = (
            "allowUnsafeMethods",
            "stateChangeApproved",
            "labDeliveryApproved",
            "solutionSubmitApproved",
            "allowDiscoveredExploitServer",
        )
        for gate in gates:
            with self.subTest(gate=gate):
                parameters = _lab_parameters(65530)
                parameters[gate] = False
                result = await self.tool.execute(parameters)
                self.assertFalse(result["success"])
                self.assertFalse(result["fallback"])

    async def _assert_no_finding(self, **fixture_options):
        app, _state = _fixture(**fixture_options)
        async with _Server(app) as port:
            result = await self.tool.execute(_runtime_parameters(port))
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])
        self.assertFalse(result["fallback"])
        self.assertEqual(result["findings"], [])

    @staticmethod
    def _sha(value):
        import hashlib

        return hashlib.sha256(value.encode()).hexdigest()


if __name__ == "__main__":
    unittest.main()
