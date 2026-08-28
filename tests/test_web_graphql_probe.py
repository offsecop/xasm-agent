import hashlib
import json
import unittest

from aiohttp import web

from tools.web_graphql_probe import (
    LAB_PROOF,
    MODE,
    RUNTIME_PROOF,
    WebGraphqlProbeTool,
)


SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {
                "fields": [
                    {
                        "name": "getAllBlogPosts",
                        "args": [],
                        "type": {
                            "kind": "LIST",
                            "name": None,
                            "ofType": {"kind": "OBJECT", "name": "BlogPost"},
                        },
                    },
                    {
                        "name": "getBlogPost",
                        "args": [
                            {
                                "name": "id",
                                "type": {"kind": "SCALAR", "name": "Int"},
                            }
                        ],
                        "type": {"kind": "OBJECT", "name": "BlogPost"},
                    },
                ]
            },
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "BlogPost",
                    "fields": [
                        {"name": "id", "type": {"kind": "SCALAR", "name": "Int"}},
                        {"name": "isPrivate", "type": {"kind": "SCALAR", "name": "Boolean"}},
                        {"name": "postPassword", "type": {"kind": "SCALAR", "name": "String"}},
                    ],
                }
            ],
        }
    }
}


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


def _fixture(*, leak=True, public_private=False, unstable=False, catch_all=False):
    secret = "fixture-private-post-password-9284"
    state = {"solved": False, "submits": 0, "direct_reads": 0}
    app = web.Application()

    async def root(_request):
        marker = "is-solved" if state["solved"] else "is-notsolved"
        status = "Solved" if state["solved"] else "Not solved"
        return web.Response(
            text=f"<html><body class='{marker}'>GraphQL lab: {status}</body></html>"
        )

    async def graphql(request):
        if request.path != "/graphql" and not catch_all:
            return web.Response(status=404, text="missing")
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"errors": [{"message": "bad request"}]}, status=400)
        query = body.get("query", "")
        if "XasmFingerprint" in query:
            return web.json_response({"data": {"__typename": "Query"}})
        if "XasmNegative" in query:
            return web.json_response(
                {"data": None, "errors": [{"message": "Cannot query field"}]}, status=400
            )
        if "XasmSchema" in query:
            return web.json_response(SCHEMA)
        if "XasmList" in query:
            rows = [{"id": 1}, {"id": 2}]
            if public_private:
                rows.append({"id": 3})
            return web.json_response({"data": {"getAllBlogPosts": rows}})
        if "XasmDirect" in query:
            object_id = int((body.get("variables") or {}).get("x", -1))
            if object_id == 3:
                state["direct_reads"] += 1
                value = secret + ("-changed" if unstable and state["direct_reads"] > 1 else "")
                item = {"id": 3, "isPrivate": True, "postPassword": value if leak else None}
                return web.json_response({"data": {"getBlogPost": item}})
            return web.json_response({"data": {"getBlogPost": None}})
        return web.json_response({"errors": [{"message": "unsupported"}]}, status=400)

    async def submit(request):
        state["submits"] += 1
        payload = await request.post()
        correct = payload.get("answer") == secret
        state["solved"] = correct
        return web.json_response({"correct": correct})

    app.router.add_get("/", root)
    app.router.add_post("/submitSolution", submit)
    app.router.add_post("/{tail:.*}", graphql)
    return app, state, secret


class GraphqlProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tool = WebGraphqlProbeTool()

    def test_schema_is_closed_target_only_and_fixed_mode(self):
        schema = self.tool.schema
        self.assertEqual(self.tool.name, "web:graphql_probe")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["required"], ["target"])
        self.assertEqual(schema["properties"]["mode"]["enum"], [MODE])
        self.assertEqual(
            schema["properties"]["proofLevel"]["enum"],
            [RUNTIME_PROOF, LAB_PROOF],
        )
        for forbidden in (
            "path", "endpoint", "query", "document", "variables", "field",
            "id", "headers", "cookie", "token", "mutation", "answer",
        ):
            self.assertNotIn(forbidden, schema["properties"])

    async def test_url_only_runtime_proves_omitted_private_sensitive_object(self):
        app, state, secret = _fixture()
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})

        self.assertTrue(result["success"])
        self.assertTrue(result["verified"])
        self.assertFalse(result["fallback"])
        verification = result["verification"]
        self.assertEqual(result["proofLevel"], RUNTIME_PROOF)
        self.assertEqual(verification["proofLevel"], RUNTIME_PROOF)
        self.assertTrue(verification["omittedFromList"])
        self.assertTrue(verification["repeatStable"])
        self.assertTrue(verification["nonexistentControlRejected"])
        self.assertEqual(verification["privacySemantic"], "explicit-private-boolean")
        self.assertEqual(verification["sensitiveValue"]["sha256"], hashlib.sha256(secret.encode()).hexdigest())
        self.assertEqual(verification["sensitiveValue"]["masked"], f"<redacted:{len(secret)}-chars>")
        labels = [step["label"] for step in verification["graphqlEvidence"]["steps"]]
        self.assertEqual(
            labels,
            [
                "graphql-fingerprint", "graphql-negative-control", "graphql-introspection",
                "graphql-list-control", "graphql-direct-not-found-control",
                "graphql-direct-private-proof", "graphql-direct-private-repeat",
            ],
        )
        serialized = json.dumps(result)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("set-cookie", serialized.lower())
        expected_marker = (
            f"[REDACTED sha256={hashlib.sha256(secret.encode()).hexdigest()} "
            f"len={len(secret)}]"
        )
        self.assertIn(expected_marker, verification["graphqlEvidence"]["steps"][5]["response"])
        self.assertRegex(
            verification["graphqlEvidence"]["steps"][1]["request"].splitlines()[0],
            r"^POST /\.xasm-graphql-negative-[0-9a-f]{24} HTTP/1\.1$",
        )
        for step in verification["graphqlEvidence"]["steps"]:
            self.assertEqual(step["requestSha256"], hashlib.sha256(step["request"].encode()).hexdigest())
            self.assertEqual(step["responseSha256"], hashlib.sha256(step["response"].encode()).hexdigest())
            self.assertFalse(step["responseExcerptTruncated"])
        self.assertFalse(state["solved"])
        self.assertEqual(state["submits"], 0)

    async def test_lab_finalizer_is_server_gated_and_never_persists_answer(self):
        app, state, secret = _fixture()
        async with _Server(app) as target:
            result = await self.tool.execute(
                {
                    "target": target,
                    "proofLevel": LAB_PROOF,
                    "engagement": "lab",
                    "allowUnsafeMethods": True,
                    "stateChangeApproved": True,
                    "solutionSubmitApproved": True,
                }
            )
        self.assertTrue(result["verified"])
        self.assertEqual(result["verification"]["proofLevel"], LAB_PROOF)
        self.assertFalse(result["verification"]["solvedBefore"])
        self.assertTrue(result["verification"]["solvedAfter"])
        self.assertTrue(result["verification"]["effectTriggered"])
        self.assertTrue(result["verification"]["labSolvedTransition"])
        self.assertEqual(state["submits"], 1)
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(
            [s["label"] for s in result["verification"]["graphqlEvidence"]["steps"]][-3:],
            ["lab-unsolved-control", "lab-solution-submit", "lab-solved-confirmation"],
        )

    async def test_lab_flags_do_not_submit_in_runtime_tier(self):
        app, state, _secret = _fixture()
        async with _Server(app) as target:
            result = await self.tool.execute(
                {
                    "target": target,
                    "proofLevel": RUNTIME_PROOF,
                    "engagement": "lab",
                    "allowUnsafeMethods": True,
                    "stateChangeApproved": True,
                    "solutionSubmitApproved": True,
                }
            )
        self.assertTrue(result["verified"])
        self.assertEqual(state["submits"], 0)

    async def test_introspection_alone_or_null_sensitive_value_is_not_finding(self):
        app, _state, _secret = _fixture(leak=False)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])
        self.assertEqual(result["findings"], [])
        self.assertFalse(result["fallback"])

    async def test_object_in_public_list_is_not_an_authz_differential(self):
        app, _state, _secret = _fixture(public_private=True)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertFalse(result["verified"])
        self.assertEqual(result["findings"], [])

    async def test_unstable_sensitive_value_is_not_proof(self):
        app, _state, _secret = _fixture(unstable=True)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertFalse(result["verified"])
        self.assertEqual(result["findings"], [])

    async def test_target_rejects_credentials_query_and_fragment(self):
        for target in (
            "https://u:p@example.test/", "https://example.test/?query=x", "https://example.test/#x",
        ):
            with self.subTest(target=target):
                result = await self.tool.execute({"target": target})
                self.assertFalse(result["success"])


if __name__ == "__main__":
    unittest.main()
