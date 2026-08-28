import json
import unittest

from aiohttp import web

from tools.web_information_disclosure_probe import (
    LAB_PROOF,
    MODE,
    WebInformationDisclosureProbeTool,
)


class _TestServer:
    def __init__(self, app):
        self.app = app
        self.runner = None
        self.site = None

    async def __aenter__(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await self.site.start()
        port = self.site._server.sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}"

    async def __aexit__(self, exc_type, exc, tb):
        await self.runner.cleanup()


class WebInformationDisclosureProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tool = WebInformationDisclosureProbeTool()

    def test_schema_is_closed_and_has_no_caller_auth_or_solution_inputs(self):
        schema = self.tool.schema
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["required"], ["target"])
        for forbidden in (
            "headers",
            "cookie",
            "answer",
            "solutionPath",
            "endpointPath",
            "payload",
            "expectedMarker",
        ):
            self.assertNotIn(forbidden, schema["properties"])

    async def test_root_only_discovers_debug_secret_and_redacts_every_output_field(self):
        raw_secret = "synthetic-secret-value-9a8b7c6d"
        app = web.Application()
        app.router.add_get(
            "/",
            lambda _r: web.Response(
                text='<html><a href="/cgi-bin/phpinfo.php">Debug</a></html>',
                content_type="text/html",
            ),
        )
        app.router.add_get(
            "/cgi-bin/phpinfo.php",
            lambda _r: web.Response(
                text=(
                    "<html><h1>PHP Version 8.3</h1><table>"
                    f"<tr><td>SECRET_KEY</td><td>{raw_secret}</td></tr>"
                    "</table></html>"
                ),
                content_type="text/html",
            ),
        )
        app.router.add_route("*", "/{tail:.*}", lambda _r: web.Response(status=404, text="missing"))

        async with _TestServer(app) as target:
            result = await self.tool.execute({"target": target})

        serialized = json.dumps(result)
        self.assertTrue(result["success"])
        self.assertTrue(result["verified"])
        self.assertFalse(result["fallback"])
        self.assertEqual(result["verification"]["leakKind"], "secret_key")
        self.assertEqual(result["total_findings"], 1)
        self.assertNotIn(raw_secret, serialized)
        self.assertIn("sha256", serialized)
        finding = result["findings"][0]
        self.assertIn("GET /cgi-bin/phpinfo.php HTTP/1.1", finding["request"])
        self.assertIn("HTTP/1.1 200", finding["response"])
        self.assertIn("[REDACTED", finding["response"])
        self.assertTrue(finding["evidence"]["httpTransactions"])

    async def test_root_only_discovers_debug_link_inside_html_comment(self):
        raw_secret = "commented-debug-secret-112233"
        app = web.Application()
        app.router.add_get(
            "/",
            lambda _r: web.Response(
                text="<html><!-- <a href=/cgi-bin/phpinfo.php>Debug</a> --></html>",
                content_type="text/html",
            ),
        )
        app.router.add_get(
            "/cgi-bin/phpinfo.php",
            lambda _r: web.Response(
                text=f"<html><h1>PHP Version 8.3</h1>SECRET_KEY={raw_secret}</html>",
                content_type="text/html",
            ),
        )
        app.router.add_route("*", "/{tail:.*}", lambda _r: web.Response(status=404, text="missing"))

        async with _TestServer(app) as target:
            result = await self.tool.execute({"target": target})

        serialized = json.dumps(result, sort_keys=True)
        self.assertTrue(result["success"])
        self.assertTrue(result["verified"])
        self.assertEqual(result["verification"]["matchedUrl"], f"{target}/cgi-bin/phpinfo.php")
        self.assertNotIn(raw_secret, serialized)
        self.assertIn("GET /cgi-bin/phpinfo.php HTTP/1.1", result["findings"][0]["request"])

    async def test_debug_secret_after_initial_response_chunk_is_detected(self):
        raw_secret = "late-chunk-secret-778899"
        app = web.Application()
        app.router.add_get("/", lambda _r: web.Response(text='<a href="/debug">Debug</a>'))

        async def chunked_debug(request):
            response = web.StreamResponse(status=200, headers={"Content-Type": "text/html"})
            await response.prepare(request)
            await response.write(b"<html><h1>PHP Version 8.3</h1>" + b"x" * 70000)
            await response.write(f"\nSECRET_KEY={raw_secret}</html>".encode())
            await response.write_eof()
            return response

        app.router.add_get("/debug", chunked_debug)
        app.router.add_route("*", "/{tail:.*}", lambda _r: web.Response(status=404, text="missing"))

        async with _TestServer(app) as target:
            result = await self.tool.execute({"target": target, "maxResponseBytes": 100000})

        serialized = json.dumps(result, sort_keys=True)
        self.assertTrue(result["verified"])
        self.assertEqual(result["verification"]["leakKind"], "secret_key")
        self.assertNotIn(raw_secret, serialized)
        self.assertIn("[REDACTED", result["findings"][0]["response"])

    async def test_debug_response_redacts_incidental_server_cookie_values(self):
        raw_secret = "debug-secret-0011223344"
        raw_cookie = "server-created-session-cookie-556677"
        app = web.Application()
        app.router.add_get("/", lambda _r: web.Response(text='<a href="/debug">Debug</a>'))
        app.router.add_get(
            "/debug",
            lambda _r: web.Response(
                text=(
                    "<html><h1>PHP Version 8.3</h1>"
                    f"<div>SECRET_KEY={raw_secret}</div>"
                    f"<div>HTTP_COOKIE session={raw_cookie}</div>"
                    f"<div>$_COOKIE['session'] {raw_cookie}</div></html>"
                ),
            ),
        )
        app.router.add_route("*", "/{tail:.*}", lambda _r: web.Response(status=404, text="missing"))

        async with _TestServer(app) as target:
            result = await self.tool.execute({"target": target})

        serialized = json.dumps(result, sort_keys=True)
        self.assertTrue(result["verified"])
        self.assertNotIn(raw_secret, serialized)
        self.assertNotIn(raw_cookie, serialized)
        self.assertIn("[REDACTED:session-sha256=", serialized)

    async def test_lab_finalizer_uses_secret_in_memory_and_persists_only_hash(self):
        raw_secret = "lab-secret-value-aa11bb22cc33"
        state = {"solved": False, "submits": 0}
        app = web.Application()

        async def root(_request):
            status = "is-solved" if state["solved"] else "is-notsolved"
            return web.Response(
                text=(
                    f'<html><div class="widgetcontainer-lab-status {status}"></div>'
                    '<a href="/debug">Debug</a></html>'
                ),
                content_type="text/html",
            )

        async def submit(request):
            state["submits"] += 1
            data = await request.post()
            state["solved"] = data.get("answer") == raw_secret
            return web.json_response({"correct": state["solved"]})

        app.router.add_get("/", root)
        app.router.add_get(
            "/debug",
            lambda _r: web.Response(text=f"Environment Variables SECRET_KEY={raw_secret}"),
        )
        app.router.add_post("/submitSolution", submit)
        app.router.add_route("*", "/{tail:.*}", lambda _r: web.Response(status=404, text="missing"))

        async with _TestServer(app) as target:
            result = await self.tool.execute(
                {
                    "target": target,
                    "proofLevel": LAB_PROOF,
                    "engagement": "lab",
                    "allowUnsafeMethods": True,
                    "stateChangeApproved": True,
                    "solutionSubmitApproved": True,
                },
            )

        serialized = json.dumps(result)
        self.assertTrue(result["verified"])
        self.assertEqual(state["submits"], 1)
        self.assertFalse(result["verification"]["solvedBefore"])
        self.assertTrue(result["verification"]["effectTriggered"])
        self.assertTrue(result["verification"]["solvedAfter"])
        self.assertNotIn(raw_secret, serialized)
        self.assertIn("answer=[REDACTED:value-sha256=", serialized)
        self.assertGreaterEqual(len(result["findings"][0]["observedTranscript"]), 3)

    async def test_standard_runtime_never_submits_solution(self):
        state = {"submits": 0}
        app = web.Application()
        app.router.add_get(
            "/",
            lambda _r: web.Response(text='<html><a href="/debug">Debug</a></html>'),
        )
        app.router.add_get(
            "/debug",
            lambda _r: web.Response(text="SECRET_KEY=runtime-secret-aa11bb22"),
        )

        async def submit(_request):
            state["submits"] += 1
            return web.json_response({"correct": True})

        app.router.add_post("/submitSolution", submit)
        app.router.add_route("*", "/{tail:.*}", lambda _r: web.Response(status=404, text="missing"))
        async with _TestServer(app) as target:
            result = await self.tool.execute(
                {
                    "target": target,
                    "allowUnsafeMethods": True,
                    "stateChangeApproved": True,
                    "solutionSubmitApproved": True,
                },
            )
        self.assertTrue(result["verified"])
        self.assertEqual(state["submits"], 0)

    async def test_runtime_injected_auth_values_never_enter_transcripts(self):
        raw_secret = "runtime-debug-secret-445566"
        private_header = "workflow-owned-header-value-778899"
        private_cookie = "session=workflow-owned-cookie-001122"
        app = web.Application()
        app.router.add_get(
            "/",
            lambda _r: web.Response(text='<html><a href="/debug">Debug</a></html>'),
        )
        app.router.add_get(
            "/debug",
            lambda _r: web.Response(text=f"SECRET_KEY={raw_secret}"),
        )
        app.router.add_route("*", "/{tail:.*}", lambda _r: web.Response(status=404, text="missing"))

        async with _TestServer(app) as target:
            result = await self.tool.execute(
                {
                    "target": target,
                    "authHeaders": {"X-Approved-Session": private_header},
                    "authCookies": private_cookie,
                },
            )

        serialized = json.dumps(result)
        self.assertTrue(result["verified"])
        self.assertNotIn(raw_secret, serialized)
        self.assertNotIn(private_header, serialized)
        self.assertNotIn(private_cookie, serialized)

    async def test_verbose_error_requires_clean_baseline_and_two_stable_mutations(self):
        calls = []
        app = web.Application()
        app.router.add_get(
            "/",
            lambda _r: web.Response(
                text='<html><a href="/product?productId=1">Product</a></html>',
                content_type="text/html",
            ),
        )

        async def product(request):
            value = request.query.get("productId")
            calls.append(value)
            if value == "1":
                return web.Response(text="Product one")
            return web.Response(
                status=500,
                text=(
                    "java.lang.NumberFormatException\n"
                    "at com.example.ProductAction.execute(ProductAction.java:42)\n"
                    "Apache Struts 2 2.3.31"
                ),
            )

        app.router.add_get("/product", product)
        app.router.add_route("*", "/{tail:.*}", lambda _r: web.Response(status=404, text="missing"))
        async with _TestServer(app) as target:
            result = await self.tool.execute({"target": target})

        self.assertTrue(result["verified"])
        self.assertEqual(result["verification"]["leakKind"], "verbose_error")
        self.assertIn("1", calls)
        self.assertIn("x", calls)
        self.assertIn("xasm-invalid", calls)
        transactions = result["findings"][0]["observedTranscript"]
        self.assertEqual([t["label"] for t in transactions[:3]], [
            "clean-baseline", "stable-confirmation", "disclosure-proof",
        ])

    async def test_robots_directory_listing_chain_finds_backup_source_and_redacts_password(self):
        raw_password = "Synthetic-Db-Pass-4433!"
        app = web.Application()
        app.router.add_get("/", lambda _r: web.Response(text="<html>shop</html>"))
        app.router.add_get("/robots.txt", lambda _r: web.Response(text="Disallow: /backup"))
        app.router.add_get(
            "/backup/",
            lambda _r: web.Response(
                text='<html><title>Index of /backup</title><a href="Product.java.bak">file</a></html>'
            ),
        )
        app.router.add_get(
            "/backup/Product.java.bak",
            lambda _r: web.Response(
                text=f'public class Product {{ String password = "{raw_password}"; }}'
            ),
        )
        app.router.add_route("*", "/{tail:.*}", lambda _r: web.Response(status=404, text="missing"))
        async with _TestServer(app) as target:
            result = await self.tool.execute({"target": target})

        serialized = json.dumps(result)
        self.assertTrue(result["verified"])
        self.assertEqual(result["verification"]["leakKind"], "backup_secret")
        self.assertNotIn(raw_password, serialized)
        self.assertIn("GET /backup/Product.java.bak", result["findings"][0]["request"])

    async def test_spa_catch_all_200_does_not_create_a_finding(self):
        body = '<html><title>Example SPA</title><div id="root"></div></html>'
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", lambda _r: web.Response(text=body))
        async with _TestServer(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])
        self.assertEqual(result["findings"], [])
        self.assertFalse(result["fallback"])

    async def test_cross_origin_debug_link_is_ignored(self):
        external_hits = {"count": 0}
        external = web.Application()

        async def external_debug(_request):
            external_hits["count"] += 1
            return web.Response(text="SECRET_KEY=must-not-be-fetched-112233")

        external.router.add_get("/debug", external_debug)
        async with _TestServer(external) as external_target:
            app = web.Application()
            app.router.add_get(
                "/",
                lambda _r: web.Response(text=f'<html><a href="{external_target}/debug">Debug</a></html>'),
            )
            app.router.add_route("*", "/{tail:.*}", lambda _r: web.Response(status=404, text="missing"))
            async with _TestServer(app) as target:
                result = await self.tool.execute({"target": target})

        self.assertFalse(result["verified"])
        self.assertEqual(external_hits["count"], 0)

    async def test_source_map_requires_embedded_original_source(self):
        source_map = {"version": 3, "sources": ["src/app.ts"], "sourcesContent": ["export const x = 1;"]}
        app = web.Application()
        app.router.add_get("/", lambda _r: web.Response(text='<html><script src="/app.js"></script></html>'))
        app.router.add_get("/app.js", lambda _r: web.Response(text="console.log(1);\n//# sourceMappingURL=app.js.map"))
        app.router.add_get("/app.js.map", lambda _r: web.json_response(source_map))
        app.router.add_route("*", "/{tail:.*}", lambda _r: web.Response(status=404, text="missing"))
        async with _TestServer(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["verified"])
        self.assertEqual(result["verification"]["leakKind"], "source_map")

    async def test_request_budget_is_hard_clamped(self):
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", lambda _r: web.Response(status=404, text="missing"))
        async with _TestServer(app) as target:
            result = await self.tool.execute({"target": target, "requestBudget": 1})
        self.assertLessEqual(result["summary"]["requestCount"], 8)
        self.assertEqual(self.tool._budget, 8)


if __name__ == "__main__":
    unittest.main()
