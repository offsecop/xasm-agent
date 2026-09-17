import json
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import urlparse

from aiohttp import web

from tools._browser_spa_traversal import (
    HARD_MAX_OUTPUT_BYTES,
    SpaTraversalBudget,
    SpaTraversalIncomplete,
    compact_json_bytes,
    enforce_public_output_cap,
    spa_traversal_budget,
    traverse_bounded_spa,
)
from tools._browser_scoped_context import SERVER_BROWSER_ORIGIN_POLICY_KEY
from tools.agentic_browser_map import BrowserMapAppTool
from tools.agentic_browser_traffic_capture import BrowserTrafficCaptureTool


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


def _spa_html(external_origin: str = "") -> str:
    external_probe = (
        f"fetch('{external_origin}/blocked', {{credentials: 'include'}}).catch(() => undefined);"
        if external_origin
        else ""
    )
    return f"""<!doctype html>
<html><head><title>Synthetic SPA</title></head>
<body><main id="app"></main>
<script>
const app = document.getElementById('app');
function api(path) {{ return fetch(path).catch(() => undefined); }}
function render(path) {{
  if (path === '/profile') {{
    app.innerHTML = `
      <h1>Profile</h1>
      <form action="/profile/search" method="GET">
        <input name="customer" type="search" placeholder="Search customers">
        <button type="submit">Submit search</button>
      </form>
      <button type="button" role="tab" aria-controls="settings-panel">Settings tab</button>
      <button type="button">Delete account</button>
      <section id="settings-panel"></section>`;
    api('/api/profile');
    {external_probe}
    app.querySelector('input[type=search]').addEventListener('input', (event) =>
      api('/api/search?q=' + encodeURIComponent(event.target.value)));
    return;
  }}
  app.innerHTML = `<h1>Home</h1><a href="/profile" data-route="profile">Profile</a>`;
  api('/api/root');
}}
document.addEventListener('click', (event) => {{
  const link = event.target.closest('a[data-route]');
  if (link) {{
    event.preventDefault();
    history.pushState({{}}, '', link.getAttribute('href'));
    render(location.pathname);
    return;
  }}
  const tab = event.target.closest('[role=tab][aria-controls]');
  if (tab) {{
    event.preventDefault();
    document.getElementById('settings-panel').innerHTML =
      `<form action="/settings/save" method="POST"><input name="timezone"></form>`;
    api('/api/settings');
  }}
}});
document.addEventListener('submit', (event) => {{
  event.preventDefault();
  fetch('/api/forbidden-submit', {{method: 'POST'}});
}});
render(location.pathname);
</script></body></html>"""


def _auth_loss_html() -> str:
    return """<!doctype html><html><body><main id="app">
<a href="/private" data-route="private">Private</a></main>
<script>
document.addEventListener('click', (event) => {
  const link = event.target.closest('a[data-route]');
  if (!link) return;
  event.preventDefault();
  history.pushState({}, '', '/private');
  document.getElementById('app').innerHTML = '<h1>Private route</h1>';
  fetch('/api/private');
});
</script></body></html>"""


def _origin(value: str) -> str:
    parsed = urlparse(value)
    return f"{parsed.scheme}://{parsed.netloc}"


def _origin_policy(target: str, *secondary: str):
    primary = _origin(target)
    return {
        "version": 1,
        "primaryOrigin": primary,
        "allowedOrigins": sorted({primary, *(_origin(item) for item in secondary)}),
        "requireExactOrigin": True,
        "stripCrossOriginAuthHeaders": True,
    }


class BrowserSpaBudgetTests(unittest.TestCase):
    def test_browser_snapshot_never_serializes_live_form_values(self):
        source = (Path(__file__).resolve().parents[1] / "tools" / "_browser_spa_traversal.py").read_text()
        self.assertNotIn('value: successful ?', source)
        self.assertNotIn('String(i.value || \'\').slice', source)
        self.assertIn('hasValue: Boolean(i.value)', source)

    def test_zero_interactions_and_depth_are_preserved_and_hard_caps_apply(self):
        budget = spa_traversal_budget(
            {
                "maxPages": 999,
                "maxDepth": 0,
                "maxInteractions": 0,
                "timeoutSeconds": 999,
                "maxOutputBytes": 999999,
            },
            default_interactions=12,
            default_timeout_seconds=45,
        )
        self.assertEqual(budget.max_pages, 40)
        self.assertEqual(budget.max_depth, 0)
        self.assertEqual(budget.max_interactions, 0)
        self.assertEqual(budget.deadline_seconds, 180)
        self.assertEqual(budget.max_output_bytes, HARD_MAX_OUTPUT_BYTES)

    def test_public_output_cap_preserves_valid_shape_and_reports_omissions(self):
        output = {
            "success": True,
            "coverageStatus": "CONFIRMED",
            "coverageReason": "BOUNDED_SPA_TRAVERSAL_COMPLETED",
            "coverage": {"truncated": False, "truncatedBy": [], "omittedArtifacts": 0},
            "summary": {"truncated": False},
            "xhrRequests": [
                {
                    "url": f"https://app.example.test/api/{index}",
                    "responseSample": "x" * 3000,
                    "requestSample": "y" * 1000,
                }
                for index in range(8)
            ],
            "_nativeProbePrivateCandidates": [{"value": "private-transport"}],
        }
        enforce_public_output_cap(
            output,
            8192,
            removable_lists=("xhrRequests",),
            private_keys=("_nativeProbePrivateCandidates",),
        )
        public = {
            key: value
            for key, value in output.items()
            if key != "_nativeProbePrivateCandidates"
        }
        self.assertLessEqual(compact_json_bytes(public), 8192)
        self.assertTrue(output["coverage"]["truncated"])
        self.assertIn("maxOutputBytes", output["coverage"]["truncatedBy"])
        self.assertGreater(output["coverage"]["omittedArtifacts"], 0)
        self.assertEqual(
            output["_nativeProbePrivateCandidates"],
            [{"value": "private-transport"}],
        )

    def test_both_browser_tools_publish_the_bounded_contract(self):
        for tool in (BrowserMapAppTool(), BrowserTrafficCaptureTool()):
            properties = tool.schema["properties"]
            self.assertEqual(properties["maxPages"]["default"], 12)
            self.assertEqual(properties["maxDepth"]["default"], 3)
            self.assertEqual(properties["maxOutputBytes"]["default"], 49152)


class BrowserSpaDeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def test_deadline_before_pending_root_returns_typed_incomplete(self):
        budget = SpaTraversalBudget(
            max_pages=4,
            max_depth=2,
            max_interactions=4,
            deadline_seconds=1,
            max_output_bytes=8192,
        )
        with patch(
            "tools._browser_spa_traversal.time.monotonic",
            side_effect=[0.0, 2.0, 2.0],
        ), self.assertRaises(SpaTraversalIncomplete) as raised:
            await traverse_bounded_spa(
                object(),
                object(),
                "https://app.example.test/",
                budget,
            )
        self.assertEqual(raised.exception.reason, "SPA_TRAVERSAL_DEADLINE_EXCEEDED")
        self.assertEqual(raised.exception.partial["coverageStatus"], "INCOMPLETE")
        self.assertFalse(raised.exception.partial["exhaustiveWithinBounds"])


class BrowserSpaTraversalTests(unittest.IsolatedAsyncioTestCase):
    async def _spa_app(self, external_origin: str = ""):
        counters = {
            "root": 0,
            "profile": 0,
            "settings": 0,
            "search": 0,
            "submit": 0,
        }

        async def page(_request):
            return web.Response(text=_spa_html(external_origin), content_type="text/html")

        async def count(request):
            name = request.match_info["name"]
            counters[name] += 1
            return web.json_response({"source": name, "ok": True})

        async def forbidden_submit(_request):
            counters["submit"] += 1
            return web.json_response({"unexpected": True})

        app = web.Application()
        app.router.add_get("/", page)
        app.router.add_get("/profile", page)
        app.router.add_get("/api/{name:root|profile|settings|search}", count)
        app.router.add_post("/api/forbidden-submit", forbidden_submit)
        return app, counters

    async def test_map_aggregates_lazy_routes_forms_with_route_provenance(self):
        app, counters = await self._spa_app()
        async with _TestServer(app) as target:
            output = await BrowserMapAppTool().execute(
                {
                    "target": target,
                    "maxPages": 6,
                    "maxDepth": 3,
                    "maxInteractions": 12,
                    "timeoutSeconds": 30,
                }
            )

        self.assertTrue(output["success"], output)
        self.assertEqual(output["coverageStatus"], "CONFIRMED")
        self.assertEqual(output["coverageReason"], "BOUNDED_SPA_TRAVERSAL_COMPLETED")
        self.assertGreaterEqual(output["summary"]["visitedStates"], 3)
        actions = {form["action"]: form for form in output["forms"]}
        self.assertIn(f"{target}/profile/search", actions)
        self.assertIn(f"{target}/settings/save", actions)
        self.assertEqual(actions[f"{target}/profile/search"]["routeUrl"], f"{target}/profile")
        self.assertEqual(actions[f"{target}/settings/save"]["routeUrl"], f"{target}/profile")
        self.assertEqual(counters["submit"], 0)
        self.assertFalse(output["coverage"]["truncated"])

    async def test_traffic_aggregates_lazy_api_calls_dedupes_and_never_submits(self):
        external_hits = {"count": 0}

        async def external(_request):
            external_hits["count"] += 1
            return web.json_response({"outside": True})

        external_app = web.Application()
        external_app.router.add_get("/blocked", external)
        async with _TestServer(external_app) as external_origin:
            app, counters = await self._spa_app(external_origin)
            async with _TestServer(app) as target:
                output = await BrowserTrafficCaptureTool().execute(
                    {
                        "target": target,
                        "maxPages": 8,
                        "maxDepth": 3,
                        "maxInteractions": 16,
                        "timeoutSeconds": 35,
                        "searchTerms": ["bounded"],
                    }
                )

        self.assertTrue(output["success"], output)
        urls = {row["url"]: row for row in output["xhrRequests"]}
        self.assertIn(f"{target}/api/profile", urls)
        self.assertIn(f"{target}/api/settings", urls)
        self.assertTrue(any(url.startswith(f"{target}/api/search?") for url in urls))
        self.assertIn(f"{target}/profile", urls[f"{target}/api/profile"]["observedAtRoutes"])
        self.assertEqual(len([url for url in urls if url == f"{target}/api/root"]), 1)
        self.assertEqual(counters["submit"], 0)
        self.assertEqual(external_hits["count"], 0)
        public = {
            key: value
            for key, value in output.items()
            if key != "_nativeProbePrivateCandidates"
        }
        self.assertLessEqual(
            len(json.dumps(public, separators=(",", ":")).encode("utf-8")),
            output["coverage"]["maxOutputBytes"],
        )

    async def test_authorized_secondary_api_is_captured_without_forwarding_auth_headers(self):
        observed_headers = {}

        async def external(request):
            observed_headers.update(dict(request.headers))
            return web.json_response(
                {"outside": False, "authorized": True},
                headers={
                    "Access-Control-Allow-Origin": request.headers.get("Origin", "*"),
                    "Access-Control-Allow-Credentials": "true",
                },
            )

        external_app = web.Application()
        external_app.router.add_get("/blocked", external)
        async with _TestServer(external_app) as external_origin:
            app, _counters = await self._spa_app(external_origin)
            async with _TestServer(app) as target:
                output = await BrowserTrafficCaptureTool().execute(
                    {
                        "target": target,
                        SERVER_BROWSER_ORIGIN_POLICY_KEY: _origin_policy(
                            target, external_origin
                        ),
                        "headers": {
                            "Authorization": "Bearer primary-only",
                            "X-Access-Token": "primary-only",
                            "X-Test": "preserved",
                        },
                        "cookieJar": [
                            {
                                "name": "session",
                                "value": "native-domain-cookie",
                                "path": "/",
                                "sameSite": "Lax",
                            }
                        ],
                        "maxPages": 6,
                        "maxDepth": 2,
                        "maxInteractions": 8,
                        "timeoutSeconds": 30,
                    }
                )

        self.assertTrue(output["success"], output)
        self.assertTrue(
            any(row["url"] == f"{external_origin}/blocked" for row in output["xhrRequests"]),
            output,
        )
        lowered_headers = {key.lower(): value for key, value in observed_headers.items()}
        self.assertNotIn("authorization", lowered_headers)
        self.assertNotIn("x-access-token", lowered_headers)
        self.assertEqual(lowered_headers.get("x-test"), "preserved")
        self.assertIn("session=native-domain-cookie", lowered_headers.get("cookie", ""))
        self.assertGreaterEqual(
            output["scopeMetadata"]["strippedCrossOriginAuthHeaders"], 2
        )

    async def test_page_and_depth_caps_report_omitted_states(self):
        app, _counters = await self._spa_app()
        async with _TestServer(app) as target:
            page_capped = await BrowserMapAppTool().execute(
                {
                    "target": target,
                    "maxPages": 1,
                    "maxDepth": 3,
                    "maxInteractions": 12,
                    "timeoutSeconds": 30,
                }
            )
            depth_capped = await BrowserMapAppTool().execute(
                {
                    "target": target,
                    "maxPages": 6,
                    "maxDepth": 0,
                    "maxInteractions": 12,
                    "timeoutSeconds": 30,
                }
            )
            interaction_capped = await BrowserMapAppTool().execute(
                {
                    "target": target,
                    "maxPages": 6,
                    "maxDepth": 3,
                    "maxInteractions": 0,
                    "timeoutSeconds": 30,
                }
            )

        for output, reason in (
            (page_capped, "maxPages"),
            (depth_capped, "maxDepth"),
            (interaction_capped, "maxInteractions"),
        ):
            self.assertTrue(output["success"], output)
            self.assertEqual(output["coverageStatus"], "CONFIRMED")
            self.assertEqual(output["coverageReason"], "BOUNDED_SPA_CAP_REACHED")
            self.assertTrue(output["coverage"]["truncated"])
            self.assertIn(reason, output["coverage"]["truncatedBy"])
            self.assertGreater(output["coverage"]["omittedStates"], 0)
            self.assertFalse(output["coverage"]["exhaustiveWithinBounds"])

    async def test_authenticated_xhr_loss_is_typed_incomplete(self):
        async def root(_request):
            return web.Response(text=_auth_loss_html(), content_type="text/html")

        async def denied(_request):
            return web.Response(status=401, text="login required")

        app = web.Application()
        app.router.add_get("/", root)
        app.router.add_get("/api/private", denied)
        async with _TestServer(app) as target:
            output = await BrowserMapAppTool().execute(
                {
                    "target": target,
                    "cookieJar": [{"name": "session", "value": "synthetic", "path": "/"}],
                    "maxPages": 4,
                    "maxDepth": 2,
                    "maxInteractions": 4,
                    "timeoutSeconds": 25,
                }
            )

        self.assertFalse(output["success"], output)
        self.assertEqual(output["coverageStatus"], "INCOMPLETE")
        self.assertEqual(output["coverageReason"], "AUTHENTICATION_LOST_HTTP_401")
        self.assertFalse(output["exhaustiveWithinBounds"])
        self.assertNotIn("storage_state", json.dumps(output).lower())


if __name__ == "__main__":
    unittest.main()
