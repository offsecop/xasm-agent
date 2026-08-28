import json
import unittest

from aiohttp import web

from tools.web_nosql_injection_probe import (
    LAB_PROOF,
    MODE,
    RUNTIME_PROOF,
    WebNoSqlInjectionProbeTool,
)


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


def _fixture(*, candidate=True, expanded=True, repair_matches=True, require_auth=False, catch_all=False):
    state = {"solved": False, "requests": []}
    app = web.Application()

    def allowed(request):
        return not require_auth or request.headers.get("Cookie") == "session=server-owned-secret"

    def products(ids):
        return "<html><body>" + "".join(
            f"<article><a href='/product?productId={item}'>Product {item}</a></article>"
            for item in ids
        ) + "</body></html>"

    async def root(request):
        state["requests"].append((request.method, request.path_qs))
        if not allowed(request):
            return web.Response(status=401)
        marker = "is-solved" if state["solved"] else "is-notsolved"
        link = "<a href='/filter?category=Gifts'>Gifts</a>" if candidate else ""
        return web.Response(text=f"<html><body class='{marker}'>{link}</body></html>")

    async def filter_handler(request):
        state["requests"].append((request.method, request.path_qs))
        if not allowed(request):
            return web.Response(status=401)
        category = request.query.get("category", "")
        if category == "Gifts":
            return web.Response(text=products([1, 2, 3]))
        if category == "Gifts'":
            return web.Response(status=500, text="MongoServerError: $where SyntaxError")
        if category == "Gifts'+'":
            return web.Response(text=products([1, 2, 3] if repair_matches else [1]))
        if category == "Gifts'&&'1'=='2":
            return web.Response(text=products([]))
        if category == "Gifts'||'1'=='1":
            ids = [1, 2, 3, 4, 5, 6] if expanded else [1, 2, 3]
            if expanded:
                state["solved"] = True
            return web.Response(text=products(ids))
        return web.Response(text=products([]))

    async def product(_request):
        return web.Response(text="product")

    async def fallback(request):
        state["requests"].append((request.method, request.path_qs))
        return web.Response(text="catch all") if catch_all else web.Response(status=404, text="not found")

    app.router.add_get("/", root)
    app.router.add_get("/filter", filter_handler)
    app.router.add_get("/product", product)
    app.router.add_route("*", "/{tail:.*}", fallback)
    return app, state


class WebNoSqlInjectionProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tool = WebNoSqlInjectionProbeTool()

    def test_schema_is_closed_and_model_cannot_choose_request_shape(self):
        schema = self.tool.schema
        self.assertEqual(self.tool.name, "web:nosql_injection_probe")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["required"], ["target"])
        self.assertEqual(schema["properties"]["mode"]["enum"], [MODE])
        for forbidden in (
            "endpoint", "path", "parameter", "value", "payload", "truePayload",
            "falsePayload", "method", "body", "headers", "cookie", "wordlist",
        ):
            self.assertNotIn(forbidden, schema["properties"])

    async def test_runtime_root_only_proves_stable_expansion(self):
        app, state = _fixture()
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertTrue(result["verified"])
        self.assertFalse(result["fallback"])
        self.assertEqual(result["mode"], MODE)
        self.assertEqual(result["proofLevel"], RUNTIME_PROOF)
        self.assertEqual(result["total_findings"], 1)
        self.assertEqual(result["verification"]["baselineEntityCount"], 3)
        self.assertEqual(result["verification"]["trueEntityCount"], 6)
        self.assertEqual(result["verification"]["expandedEntityCount"], 3)
        labels = [step["label"] for step in result["verification"]["nosqlEvidence"]["steps"]]
        self.assertEqual(
            labels,
            [
                "nosql-root-baseline",
                "nosql-route-negative-control",
                "nosql-parameter-baseline",
                "nosql-syntax-break-control",
                "nosql-syntax-repair-control",
                "nosql-boolean-false-control",
                "nosql-boolean-true-proof",
                "nosql-boolean-true-repeat",
                "nosql-baseline-replay",
            ],
        )
        self.assertTrue(all(method == "GET" for method, _path in state["requests"]))

    async def test_lab_proof_requires_and_records_solved_transition(self):
        app, _state = _fixture()
        async with _Server(app) as target:
            result = await self.tool.execute(
                {"target": target, "proofLevel": LAB_PROOF, "engagement": "lab"}
            )
        self.assertTrue(result["verified"])
        self.assertTrue(result["verification"]["labSolvedTransition"])
        self.assertEqual(
            result["verification"]["nosqlEvidence"]["steps"][-1]["label"],
            "lab-solved-confirmation",
        )

    async def test_server_owned_auth_is_used_but_not_serialized(self):
        app, _state = _fixture(require_auth=True)
        async with _Server(app) as target:
            result = await self.tool.execute(
                {"target": target, "authCookies": "session=server-owned-secret"}
            )
        self.assertTrue(result["verified"])
        serialized = json.dumps(result)
        self.assertNotIn("server-owned-secret", serialized)
        self.assertNotIn("Cookie:", serialized)
        self.assertRegex(result["verification"]["authContextSha256"], r"^[0-9a-f]{64}$")

    async def test_missing_observed_filter_returns_verified_no_finding(self):
        app, _state = _fixture(candidate=False)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])
        self.assertFalse(result["fallback"])
        self.assertEqual(result["findings"], [])

    async def test_repaired_syntax_must_reproduce_baseline(self):
        app, _state = _fixture(repair_matches=False)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])

    async def test_true_predicate_must_expand_entities(self):
        app, _state = _fixture(expanded=False)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])

    async def test_random_route_catch_all_fails_closed_before_payloads(self):
        app, state = _fixture(catch_all=True)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])
        self.assertEqual(len(state["requests"]), 2)

    async def test_rejects_query_target_and_lab_tier_without_lab_engagement(self):
        bad_target = await self.tool.execute({"target": "https://example.test/?category=Gifts"})
        self.assertFalse(bad_target["success"])
        bad_tier = await self.tool.execute(
            {"target": "https://example.test/", "proofLevel": LAB_PROOF, "engagement": "standard"}
        )
        self.assertFalse(bad_tier["success"])


if __name__ == "__main__":
    unittest.main()
