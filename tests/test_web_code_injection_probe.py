import hashlib
import json
import re
import unittest

from aiohttp import web

from tools.web_code_injection_probe import (
    EVIDENCE_LABELS,
    LAB_PROOF,
    MODE,
    RUNTIME_PROOF,
    WebCodeInjectionProbeTool,
)


BOOTSTRAP_COOKIE = "fixture_session=fixture-bootstrap-secret"
WORKFLOW_COOKIE = "fixture_session=workflow-owned-secret"


class _Server:
    def __init__(self, app):
        self.app = app
        self.runner = None

    async def __aenter__(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}/"

    async def __aexit__(self, exc_type, exc, tb):
        await self.runner.cleanup()


def _fixture(
    *,
    candidate=True,
    require_auth=False,
    set_cookie=True,
    catch_all=False,
    arithmetic_type="int",
    builtins_enabled=True,
    stable_arithmetic=True,
    stable_builtins=True,
    stable_baseline=True,
    unsafe_candidate=False,
    cross_origin_candidate=False,
):
    state = {"solved": False, "requests": [], "expressions": [], "counts": {}}
    app = web.Application()

    def allowed(request):
        return not require_auth or request.headers.get("Cookie") == WORKFLOW_COOKIE

    def with_cookie(response):
        if set_cookie:
            response.headers["Set-Cookie"] = BOOTSTRAP_COOKIE + "; Path=/; HttpOnly"
        return response

    async def root(request):
        state["requests"].append((request.method, request.path_qs, request.headers.get("Cookie")))
        if not allowed(request):
            return web.Response(status=401)
        marker = "is-solved" if state["solved"] else "is-notsolved"
        if cross_origin_candidate:
            link = "<a href='http://evil.invalid/evaluate?expression=7%2A6'>calc</a>"
        elif unsafe_candidate:
            link = "<a href='/admin/evaluate?expression=7%2A6'>calc</a>"
        elif candidate:
            link = "<a href='/evaluate?expression=7%2A6&locale=en'>calc</a>"
        else:
            link = ""
        return with_cookie(
            web.Response(
                text=f"<html><body class='{marker}'>{link}</body></html>",
                content_type="text/html",
            )
        )

    async def evaluate(request):
        state["requests"].append((request.method, request.path_qs, request.headers.get("Cookie")))
        if not allowed(request):
            return web.Response(status=401)
        if request.query.get("locale") != "en":
            return web.json_response({"error": "unrelated parameter changed"}, status=400)
        expression = request.query.get("expression", "")
        state["expressions"].append(expression)
        state["counts"][expression] = state["counts"].get(expression, 0) + 1
        if expression == "7*6":
            value = 42 if stable_baseline or state["counts"][expression] == 1 else 41
            return web.json_response({"result": value, "resultType": "int"})
        arithmetic = re.fullmatch(r"\(([0-9]+)\*([0-9]+)\)\+([0-9]+)", expression)
        builtins = re.fullmatch(
            r"__import__\('builtins'\)\.str\(\(([0-9]+)\*([0-9]+)\)\+([0-9]+)\)",
            expression,
        )
        if arithmetic:
            left, right, addend = map(int, arithmetic.groups())
            value = left * right + addend
            if not stable_arithmetic and state["counts"][expression] > 1:
                value += 1
            result = str(value) if arithmetic_type == "str" else value
            return web.json_response({"result": result, "resultType": arithmetic_type})
        if builtins and builtins_enabled:
            left, right, addend = map(int, builtins.groups())
            value = left * right + addend
            if not stable_builtins and state["counts"][expression] > 1:
                value += 1
            state["solved"] = True
            return web.json_response({"result": str(value), "resultType": "str"})
        return web.json_response({"error": "expression rejected"}, status=400)

    async def fallback(request):
        state["requests"].append((request.method, request.path_qs, request.headers.get("Cookie")))
        if catch_all:
            return web.Response(text="catch all")
        return web.Response(status=404, text="not found")

    app.router.add_get("/", root)
    app.router.add_get("/evaluate", evaluate)
    app.router.add_route("*", "/{tail:.*}", fallback)
    return app, state


class WebCodeInjectionProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tool = WebCodeInjectionProbeTool()

    def test_schema_is_closed_and_only_target_is_model_controlled(self):
        schema = self.tool.schema
        self.assertEqual(self.tool.name, "web:code_injection_probe")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["required"], ["target"])
        self.assertEqual(schema["properties"]["mode"]["enum"], [MODE])
        self.assertEqual(
            schema["properties"]["proofLevel"]["enum"],
            [RUNTIME_PROOF, LAB_PROOF],
        )
        for name, definition in schema["properties"].items():
            if name != "target":
                self.assertTrue(definition.get("x-workflow-owned"), name)
        for forbidden in (
            "endpoint",
            "path",
            "parameter",
            "expression",
            "payload",
            "language",
            "module",
            "function",
            "file",
            "command",
            "headers",
            "cookie",
            "rawRequest",
        ):
            self.assertNotIn(forbidden, schema["properties"])

    async def test_runtime_root_only_proves_typed_python_builtins_evaluation(self):
        app, state = _fixture(set_cookie=False)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertTrue(result["verified"])
        self.assertFalse(result["fallback"])
        self.assertEqual(result["proofLevel"], RUNTIME_PROOF)
        verification = result["verification"]
        self.assertEqual(verification["language"], "python")
        self.assertTrue(verification["undefinedControlRejected"])
        self.assertTrue(verification["arithmeticEvaluated"])
        self.assertTrue(verification["pythonBuiltinsEvaluated"])
        self.assertTrue(verification["builtinsRepeatStable"])
        self.assertTrue(verification["baselineReplayStable"])
        self.assertEqual(verification["stateChangingMethods"], [])
        self.assertEqual(result["requestCount"], 9)
        steps = verification["codeInjectionEvidence"]["steps"]
        self.assertEqual([step["label"] for step in steps], list(EVIDENCE_LABELS))
        self.assertEqual(steps[4]["resultType"], "int")
        self.assertEqual(steps[6]["resultType"], "str")
        self.assertEqual(steps[4]["resultValue"], steps[6]["resultValue"])
        self.assertTrue(all(method == "GET" for method, _path, _cookie in state["requests"]))
        self.assertRegex(state["expressions"][1], r"^xasm_[0-9a-f]{24}$")
        self.assertRegex(state["expressions"][4], r"^__import__\('builtins'\)\.str")

    async def test_lab_proof_records_independent_solved_transition(self):
        app, _state = _fixture(set_cookie=False)
        async with _Server(app) as target:
            result = await self.tool.execute(
                {"target": target, "proofLevel": LAB_PROOF, "engagement": "lab"}
            )
        self.assertTrue(result["verified"])
        self.assertTrue(result["verification"]["labSolvedTransition"])
        self.assertEqual(result["requestCount"], 10)
        self.assertEqual(
            result["verification"]["codeInjectionEvidence"]["steps"][-1]["label"],
            "lab-solved-confirmation",
        )

    async def test_bootstrap_cookie_is_reused_but_never_serialized(self):
        app, state = _fixture()
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        expected_digest = hashlib.sha256(BOOTSTRAP_COOKIE.encode()).hexdigest()
        marker = f"[REDACTED sha256={expected_digest} len={len(BOOTSTRAP_COOKIE)}]"
        self.assertTrue(result["verified"])
        self.assertEqual(result["sessionSource"], "target-bootstrap-cookie")
        self.assertEqual(result["verification"]["authContextSha256"], expected_digest)
        serialized = json.dumps(result)
        self.assertNotIn("fixture-bootstrap-secret", serialized)
        steps = result["verification"]["codeInjectionEvidence"]["steps"]
        self.assertIn("Set-Cookie: " + marker + "\r\n\r\n", steps[0]["response"])
        self.assertNotIn("Cookie:", steps[0]["request"])
        self.assertTrue(
            all(cookie == BOOTSTRAP_COOKIE for _method, _path, cookie in state["requests"][1:])
        )

    async def test_workflow_owned_auth_is_used_but_not_serialized(self):
        app, _state = _fixture(require_auth=True, set_cookie=False)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target, "authCookies": WORKFLOW_COOKIE})
        self.assertTrue(result["verified"])
        self.assertEqual(result["sessionSource"], "workflow-auth-context")
        self.assertNotIn("workflow-owned-secret", json.dumps(result))
        self.assertIn("Cookie: [REDACTED sha256=", json.dumps(result))

    async def test_missing_unsafe_or_cross_origin_candidate_fails_closed(self):
        for options in (
            {"candidate": False},
            {"unsafe_candidate": True},
            {"cross_origin_candidate": True},
        ):
            app, state = _fixture(set_cookie=False, **options)
            async with _Server(app) as target:
                result = await self.tool.execute({"target": target})
            self.assertTrue(result["success"])
            self.assertFalse(result["verified"])
            self.assertEqual(result["findings"], [])
            self.assertEqual(len(state["requests"]), 2)

    async def test_every_semantic_control_is_required(self):
        for options in (
            {"arithmetic_type": "str"},
            {"builtins_enabled": False},
            {"stable_arithmetic": False},
            {"stable_builtins": False},
            {"stable_baseline": False},
        ):
            app, _state = _fixture(set_cookie=False, **options)
            async with _Server(app) as target:
                result = await self.tool.execute({"target": target})
            self.assertTrue(result["success"], options)
            self.assertFalse(result["verified"], options)
            self.assertEqual(result["findings"], [], options)

    async def test_random_route_catch_all_stops_before_expression_payloads(self):
        app, state = _fixture(catch_all=True, set_cookie=False)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])
        self.assertEqual(result["requestCount"], 2)
        self.assertEqual(state["expressions"], [])

    async def test_rejects_non_root_target_and_invalid_lab_policy(self):
        query = await self.tool.execute({"target": "https://example.test/?expr=7*6"})
        path = await self.tool.execute({"target": "https://example.test/calc"})
        lab = await self.tool.execute(
            {"target": "https://example.test/", "proofLevel": LAB_PROOF, "engagement": "standard"}
        )
        self.assertFalse(query["success"])
        self.assertFalse(path["success"])
        self.assertFalse(lab["success"])


if __name__ == "__main__":
    unittest.main()
