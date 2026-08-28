import hashlib
import json
import re
import unittest

from aiohttp import web

from tools.web_xpath_injection_probe import (
    EVIDENCE_LABELS,
    LAB_PROOF,
    MODE,
    RUNTIME_PROOF,
    WebXPathInjectionProbeTool,
)


BOOTSTRAP_COOKIE = "session=fixture-bootstrap-secret"
WORKFLOW_COOKIE = "session=workflow-owned-secret"


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
    repair_matches=True,
    true_control_matches=True,
    false_empty=True,
    expanded=True,
    stable_repeat=True,
    replay_matches=True,
    unsafe_candidate=False,
    cross_origin_candidate=False,
):
    state = {
        "solved": False,
        "requests": [],
        "categories": [],
        "expansionCalls": 0,
    }
    app = web.Application()

    def allowed(request):
        return not require_auth or request.headers.get("Cookie") == WORKFLOW_COOKIE

    def products(ids):
        return "<html><body>" + "".join(
            f"<article><a href='/product?productId={item}'>Product {item}</a></article>"
            for item in ids
        ) + "</body></html>"

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
            link = "<a href='http://evil.invalid/filter?category=Gifts'>Gifts</a>"
        elif unsafe_candidate:
            link = "<a href='/login?category=Gifts'>Gifts</a>"
        elif candidate:
            link = "<a href='/filter?category=Gifts&locale=en'>Gifts</a>"
        else:
            link = ""
        return with_cookie(
            web.Response(
                text=f"<html><body class='{marker}'>{link}</body></html>",
                content_type="text/html",
            )
        )

    async def filter_handler(request):
        state["requests"].append((request.method, request.path_qs, request.headers.get("Cookie")))
        if not allowed(request):
            return web.Response(status=401)
        if request.query.get("locale") != "en":
            return web.Response(status=400, text="unrelated parameter changed")
        category = request.query.get("category", "")
        state["categories"].append(category)
        if category == "Gifts":
            ids = [1, 2] if replay_matches or state["categories"].count("Gifts") == 1 else [1]
            return web.Response(text=products(ids))
        if category == "Gifts'":
            return web.Response(status=500, text="XPathException: invalid expression")
        if category == "Gifts' and '1'='1":
            return web.Response(text=products([1, 2] if repair_matches else [1]))
        if category == "Gifts' and string-length('x')=2 and '1'='1":
            return web.Response(text=products([] if false_empty else [1]))
        if category == "Gifts' and string-length('x')=1 and '1'='1":
            return web.Response(text=products([1, 2] if true_control_matches else [1]))
        if category == "Gifts' or string-length('x')=1 or '1'='2":
            state["expansionCalls"] += 1
            ids = [1, 2, 3, 4, 5] if expanded else [1, 2, 3]
            if not stable_repeat and state["expansionCalls"] > 1:
                ids = [1, 2, 3, 4]
            if expanded:
                state["solved"] = True
            return web.Response(text=products(ids))
        return web.Response(text=products([]))

    async def product(_request):
        return web.Response(text="product")

    async def fallback(request):
        state["requests"].append((request.method, request.path_qs, request.headers.get("Cookie")))
        if catch_all:
            return web.Response(text="catch all")
        return web.Response(status=404, text="not found")

    app.router.add_get("/", root)
    app.router.add_get("/filter", filter_handler)
    app.router.add_get("/product", product)
    app.router.add_route("*", "/{tail:.*}", fallback)
    return app, state


class WebXPathInjectionProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tool = WebXPathInjectionProbeTool()

    def test_schema_is_closed_and_only_target_is_model_controlled(self):
        schema = self.tool.schema
        self.assertEqual(self.tool.name, "web:xpath_injection_probe")
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
            "value",
            "payload",
            "truePayload",
            "falsePayload",
            "method",
            "body",
            "headers",
            "cookie",
            "wordlist",
            "function",
        ):
            self.assertNotIn(forbidden, schema["properties"])

    async def test_runtime_root_only_proves_xpath_specific_stable_expansion(self):
        app, state = _fixture(set_cookie=False)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertTrue(result["verified"])
        self.assertFalse(result["fallback"])
        self.assertEqual(result["mode"], MODE)
        self.assertEqual(result["proofLevel"], RUNTIME_PROOF)
        self.assertEqual(result["total_findings"], 1)
        verification = result["verification"]
        self.assertEqual(verification["baselineEntityCount"], 2)
        self.assertEqual(verification["falseEntityCount"], 0)
        self.assertEqual(verification["trueControlEntityCount"], 2)
        self.assertEqual(verification["resultEntityCount"], 5)
        self.assertEqual(verification["expandedEntityCount"], 3)
        self.assertTrue(verification["xpathStringLengthFunctionProven"])
        self.assertTrue(verification["dnsResolvedOnce"])
        self.assertTrue(verification["freshConnectionPerRequest"])
        self.assertFalse(verification["redirectsFollowed"])
        self.assertEqual(verification["stateChangingMethods"], [])
        steps = verification["xpathEvidence"]["steps"]
        self.assertEqual([step["label"] for step in steps], list(EVIDENCE_LABELS))
        self.assertEqual(result["requestCount"], 10)
        self.assertTrue(all(method == "GET" for method, _path, _cookie in state["requests"]))
        self.assertEqual(
            state["categories"],
            [
                "Gifts",
                "Gifts'",
                "Gifts' and '1'='1",
                "Gifts' and string-length('x')=2 and '1'='1",
                "Gifts' and string-length('x')=1 and '1'='1",
                "Gifts' or string-length('x')=1 or '1'='2",
                "Gifts' or string-length('x')=1 or '1'='2",
                "Gifts",
            ],
        )
        for step in steps:
            self.assertIn("\r\n\r\n", step["request"], step["label"])
            self.assertIn("\r\n\r\n", step["response"], step["label"])
        for step in steps[2:]:
            self.assertEqual(step["entityKeys"], sorted(step["entityKeys"]))
            expected = hashlib.sha256("\n".join(step["entityKeys"]).encode()).hexdigest()
            self.assertEqual(step["entityFingerprintSha256"], expected)

    async def test_lab_proof_requires_and_records_solved_transition(self):
        app, _state = _fixture(set_cookie=False)
        async with _Server(app) as target:
            result = await self.tool.execute(
                {"target": target, "proofLevel": LAB_PROOF, "engagement": "lab"}
            )
        self.assertTrue(result["verified"])
        self.assertTrue(result["verification"]["labSolvedTransition"])
        self.assertEqual(result["requestCount"], 11)
        self.assertEqual(
            result["verification"]["xpathEvidence"]["steps"][-1]["label"],
            "lab-solved-confirmation",
        )

    async def test_bootstrap_cookie_is_reused_with_matching_markers_and_crlf(self):
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
        steps = result["verification"]["xpathEvidence"]["steps"]
        self.assertIn("Set-Cookie: " + marker + "\r\n\r\n", steps[0]["response"])
        self.assertNotIn("Cookie:", steps[0]["request"])
        self.assertRegex(
            steps[1]["request"],
            re.escape("Cookie: " + marker) + r"\r\n\r\n$",
        )
        self.assertTrue(
            all(cookie == BOOTSTRAP_COOKIE for _method, _path, cookie in state["requests"][1:])
        )

    async def test_workflow_owned_auth_is_used_but_never_serialized(self):
        app, _state = _fixture(require_auth=True, set_cookie=False)
        async with _Server(app) as target:
            result = await self.tool.execute(
                {"target": target, "authCookies": WORKFLOW_COOKIE}
            )
        self.assertTrue(result["verified"])
        self.assertEqual(result["sessionSource"], "workflow-auth-context")
        serialized = json.dumps(result)
        self.assertNotIn("workflow-owned-secret", serialized)
        self.assertIn("Cookie: [REDACTED sha256=", serialized)

    async def test_missing_or_unsafe_candidate_fails_closed(self):
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
            self.assertFalse(result["fallback"])
            self.assertEqual(result["findings"], [])
            self.assertEqual(len(state["requests"]), 2)

    async def test_every_differential_control_is_required(self):
        cases = (
            {"repair_matches": False},
            {"true_control_matches": False},
            {"false_empty": False},
            {"expanded": False},
            {"stable_repeat": False},
            {"replay_matches": False},
        )
        for options in cases:
            app, _state = _fixture(set_cookie=False, **options)
            async with _Server(app) as target:
                result = await self.tool.execute({"target": target})
            self.assertTrue(result["success"], options)
            self.assertFalse(result["verified"], options)
            self.assertEqual(result["findings"], [], options)

    async def test_random_route_catch_all_stops_before_xpath_payloads(self):
        app, state = _fixture(catch_all=True, set_cookie=False)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])
        self.assertEqual(result["requestCount"], 2)
        self.assertEqual(state["categories"], [])

    async def test_rejects_non_root_target_and_lab_tier_without_lab_engagement(self):
        query = await self.tool.execute(
            {"target": "https://example.test/?category=Gifts"}
        )
        path = await self.tool.execute({"target": "https://example.test/products"})
        lab = await self.tool.execute(
            {
                "target": "https://example.test/",
                "proofLevel": LAB_PROOF,
                "engagement": "standard",
            }
        )
        self.assertFalse(query["success"])
        self.assertFalse(path["success"])
        self.assertFalse(lab["success"])


if __name__ == "__main__":
    unittest.main()
