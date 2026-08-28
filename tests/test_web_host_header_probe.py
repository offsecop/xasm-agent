import json
import unittest

from aiohttp import web

from tools.web_host_header_probe import (
    MODE,
    HostHeaderProbeTool,
    build_finding,
    validate_parameters,
)


class _TestServer:
    def __init__(self, app):
        self.app = app
        self.runner = None

    async def __aenter__(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}/host-header-lab"

    async def __aexit__(self, exc_type, exc, tb):
        await self.runner.cleanup()


def _fixture(*, trust_forwarded=False, catch_all_admin=False):
    state = {"solved": False, "hosts": []}
    app = web.Application()

    async def status(_request):
        marker = "Solved" if state["solved"] else "Not solved"
        return web.Response(text=f"<html><h1>Host Header Lab</h1><p>{marker}</p></html>")

    async def robots(_request):
        return web.Response(text="User-agent: *\nDisallow: /admin\n")

    async def admin(request):
        host = request.headers.get("Host", "")
        forwarded = request.headers.get("X-Forwarded-Host", "")
        state["hosts"].append((host, forwarded))
        allowed = forwarded == "localhost" if trust_forwarded else host == "localhost"
        if not allowed:
            return web.Response(status=403, text="Admin only available to local users")
        state["solved"] = True
        return web.Response(
            text=(
                "<!doctype html><title>Administration Dashboard</title>"
                "<h1>Admin panel</h1><p>User management</p>"
            )
        )

    async def missing(request):
        if catch_all_admin and request.headers.get("Host") == "localhost":
            return web.Response(
                text="<title>Administration Dashboard</title><h1>Admin panel</h1>"
            )
        return web.Response(status=404, text="missing")

    app.router.add_get("/host-header-lab", status)
    app.router.add_get("/robots.txt", robots)
    app.router.add_get("/admin", admin)
    app.router.add_route("*", "/{tail:.*}", missing)
    return app, state


class HostHeaderProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tool = HostHeaderProbeTool()

    def test_schema_is_url_only_and_closed(self):
        schema = self.tool.schema
        self.assertEqual(self.tool.name, "web:host_header_probe")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["required"], ["target"])
        self.assertEqual(schema["properties"]["mode"]["enum"], [MODE])
        for forbidden in (
            "headers",
            "cookies",
            "host",
            "path",
            "payload",
            "rawRequest",
            "internalRange",
            "wordlist",
        ):
            self.assertNotIn(forbidden, schema["properties"])

    def test_parameter_validation_rejects_credentials_query_and_oversized_budget(self):
        self.assertEqual(
            validate_parameters(
                {
                    "target": "https://app.example/",
                    "mode": MODE,
                    "engagement": "lab",
                    "hostHeaderOverrideApproved": True,
                }
            ),
            (True, ""),
        )
        self.assertFalse(
            validate_parameters({"target": "https://user:pass@app.example/"})[0]
        )
        self.assertFalse(
            validate_parameters({"target": "https://app.example/?next=/admin"})[0]
        )
        self.assertFalse(
            validate_parameters(
                {
                    "target": "https://app.example/",
                    "engagement": "lab",
                    "hostHeaderOverrideApproved": True,
                    "requestBudget": 25,
                }
            )[0]
        )

    def test_parameter_validation_requires_engagement_and_server_approval(self):
        self.assertFalse(validate_parameters({"target": "https://app.example/"})[0])
        self.assertTrue(
            validate_parameters(
                {"target": "https://app.example/", "engagement": "standard"}
            )[0]
        )
        self.assertFalse(
            validate_parameters(
                {
                    "target": "https://app.example/",
                    "engagement": "lab",
                    "hostHeaderOverrideApproved": False,
                }
            )[0]
        )

    async def test_standard_engagement_is_a_zero_request_noop(self):
        result = await self.tool.execute(
            {
                "target": "https://app.example/",
                "engagement": "standard",
                "hostHeaderOverrideApproved": False,
            }
        )

        self.assertTrue(result["success"])
        self.assertTrue(result["skipped"])
        self.assertEqual(result["requestCount"], 0)
        self.assertEqual(result["findings"], [])

    async def test_root_url_discovers_and_confirms_repeated_host_auth_bypass(self):
        app, state = _fixture()
        async with _TestServer(app) as target:
            result = await self.tool.execute(
                {
                    "target": target,
                    "engagement": "lab",
                    "hostHeaderOverrideApproved": True,
                }
            )

        self.assertTrue(result["success"])
        self.assertTrue(result["verified"])
        self.assertFalse(result["fallback"])
        self.assertEqual(result["total_findings"], 1)
        verification = result["verification"]
        self.assertEqual(verification["variant"], "host-localhost")
        self.assertEqual(verification["canonicalStatus"], 403)
        self.assertEqual(verification["overrideStatus"], 200)
        self.assertTrue(verification["repeatControlsStable"])
        self.assertTrue(verification["catchAllRejected"])
        self.assertTrue(verification["labSolvedTransition"])
        labels = [
            step["label"] for step in verification["httpEvidence"]["steps"]
        ]
        self.assertEqual(
            labels,
            [
                "canonical-control-1",
                "canonical-control-2",
                "host-override-proof",
                "host-override-repeat",
                "host-override-negative-control",
                "canonical-replay-denied",
                "solved-confirmation",
            ],
        )
        finding = result["findings"][0]
        self.assertEqual(finding["info"]["classification"]["cwe-id"], ["CWE-346"])
        self.assertIn("GET /admin HTTP/1.1", finding["request"])
        self.assertIn("Host: localhost", finding["request"])
        self.assertIn("HTTP/1.1 200", finding["response"])
        self.assertTrue(state["solved"])

    async def test_forwarded_host_ladder_runs_without_caller_supplied_header(self):
        app, _state = _fixture(trust_forwarded=True)
        async with _TestServer(app) as target:
            result = await self.tool.execute(
                {
                    "target": target,
                    "engagement": "lab",
                    "hostHeaderOverrideApproved": True,
                }
            )

        self.assertTrue(result["verified"])
        self.assertEqual(
            result["verification"]["variant"], "x-forwarded-host-localhost"
        )
        proof = result["findings"][0]["request"]
        self.assertIn("Host: 127.0.0.1:", proof)
        self.assertIn("X-Forwarded-Host: localhost", proof)

    async def test_spa_or_admin_catch_all_is_rejected(self):
        app, _state = _fixture(catch_all_admin=True)
        async with _TestServer(app) as target:
            result = await self.tool.execute(
                {
                    "target": target,
                    "engagement": "lab",
                    "hostHeaderOverrideApproved": True,
                }
            )

        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])
        self.assertEqual(result["findings"], [])
        self.assertFalse(result["fallback"])

    async def test_status_change_or_admin_words_without_denial_are_not_proof(self):
        app = web.Application()
        app.router.add_get(
            "/",
            lambda _r: web.Response(
                text="<title>Administration Dashboard</title><h1>Admin panel</h1>"
            ),
        )
        app.router.add_get("/robots.txt", lambda _r: web.Response(text="Disallow: /admin"))
        app.router.add_get(
            "/admin",
            lambda _r: web.Response(
                text="<title>Administration Dashboard</title><h1>Admin panel</h1>"
            ),
        )
        app.router.add_route("*", "/{tail:.*}", lambda _r: web.Response(status=404))
        async with _TestServer(app) as target:
            result = await self.tool.execute(
                {
                    "target": target,
                    "engagement": "lab",
                    "hostHeaderOverrideApproved": True,
                }
            )

        self.assertFalse(result["verified"])
        self.assertNotIn("localhost", json.dumps(result))

    def test_finding_uses_the_exact_sanitized_proof_pair(self):
        verification = {
            "matchedUrl": "https://app.example/admin",
            "httpEvidence": {
                "steps": [
                    {
                        "label": "host-override-proof",
                        "request": "GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
                        "response": "HTTP/1.1 200 OK\r\n\r\nAdmin panel",
                    }
                ]
            },
        }
        finding = build_finding("https://app.example/", verification)
        self.assertEqual(
            finding["request"], verification["httpEvidence"]["steps"][0]["request"]
        )
        self.assertEqual(
            finding["response"], verification["httpEvidence"]["steps"][0]["response"]
        )


if __name__ == "__main__":
    unittest.main()
