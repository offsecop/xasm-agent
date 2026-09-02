import unittest
from unittest.mock import AsyncMock, patch

from aiohttp import web

from tools.agentic_browser_map import (
    BROWSER_CONTEXT_SCOPE_OPTIONS,
    BrowserMapAppTool,
    same_websocket_origin,
)
from tools.katana_crawl import (
    KATANA_JSONL_RECORD_MAX_BYTES,
    KATANA_RAW_EVIDENCE_MAX_BYTES,
    KatanaCrawlTool,
    KatanaStreamCollector,
    bounded_katana_timeout,
    classify_katana_coverage,
    exact_origin_scope_options,
    is_same_origin_url,
    is_successful_root_observation,
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


class KatanaCoverageVerdictTests(unittest.TestCase):
    def test_katana_timer_reserves_completion_time_below_agent_watchdog(self):
        self.assertEqual(
            bounded_katana_timeout(
                {"_job_timeout_seconds": 180},
                180,
            ),
            150,
        )
        self.assertEqual(
            bounded_katana_timeout(
                {"_job_timeout_seconds": 180},
                30,
            ),
            30,
        )
        self.assertEqual(bounded_katana_timeout({}, 180), 180)

    def test_katana_scope_is_locked_to_the_exact_authorized_origin(self):
        options = exact_origin_scope_options("https://App.Example.test:8443/start")

        self.assertEqual(options[:2], ["-fs", "fqdn"])
        self.assertEqual(options.count("-fs"), 1)
        self.assertEqual(options.count("-cs"), 1)
        scope = options[options.index("-cs") + 1]
        self.assertRegex("https://app.example.test:8443/inside", scope)
        self.assertNotRegex("https://sibling.example.test:8443/inside", scope)
        self.assertNotRegex("https://app.example.test:9443/inside", scope)
        self.assertNotRegex("http://app.example.test:8443/inside", scope)

        self.assertTrue(
            is_same_origin_url(
                "https://app.example.test:8443/start",
                "https://app.example.test:8443/inside",
            )
        )
        self.assertFalse(
            is_same_origin_url(
                "https://app.example.test:8443/start",
                "https://app.example.test:9443/inside",
            )
        )

    def test_urls_are_confirmed_even_when_another_origin_failed(self):
        self.assertEqual(
            classify_katana_coverage(
                ["https://target.test/"],
                has_errors=True,
                root_reachable=True,
            ),
            ("CONFIRMED", "PARTIAL_URL_INVENTORY_OBSERVED"),
        )

    def test_root_reachability_requires_the_exact_requested_endpoint(self):
        target = "https://Example.test"
        self.assertTrue(is_successful_root_observation(target, "https://example.test/", 200))
        self.assertTrue(is_successful_root_observation(target, "https://example.test/#fragment", "204"))
        self.assertFalse(is_successful_root_observation(target, None, 200))
        self.assertFalse(is_successful_root_observation(target, "https://example.test/docs", 200))
        self.assertFalse(is_successful_root_observation(target, "https://other.test/", 200))
        self.assertFalse(is_successful_root_observation(target, "https://example.test/", None))

    def test_empty_errors_are_incomplete(self):
        self.assertEqual(
            classify_katana_coverage([], has_errors=True, root_reachable=False),
            ("INCOMPLETE", "CRAWL_ERRORS_WITHOUT_URL_EVIDENCE"),
        )

    def test_empty_success_requires_root_reachability(self):
        self.assertEqual(
            classify_katana_coverage([], has_errors=False, root_reachable=True),
            ("COMPLETE_NO_FINDING", "ROOT_REACHABLE_NO_URLS_DISCOVERED"),
        )
        self.assertEqual(
            classify_katana_coverage([], has_errors=False, root_reachable=False),
            ("INCOMPLETE", "NO_REACHABILITY_OR_URL_EVIDENCE"),
        )


class _FakeKatanaProcess:
    def __init__(self, stdout, pid=4242):
        self._stdout = stdout
        self.stdout = None
        self.stderr = None
        self.pid = pid
        self.returncode = 0

    async def communicate(self):
        return self._stdout, b""

    async def wait(self):
        return self.returncode


class _ReadableBytes:
    def __init__(self, value):
        self.value = value

    async def read(self, *_args):
        value, self.value = self.value, b""
        return value


class _TimedOutKatanaProcess:
    def __init__(self, stdout, pid=4343):
        self.stdout = _ReadableBytes(stdout)
        self.stderr = _ReadableBytes(b"")
        self.pid = pid
        self.returncode = None

    async def communicate(self):
        raise AssertionError("wait_for is expected to inject the timeout")

    async def wait(self):
        return self.returncode


async def _close_awaitable_and_raise_timeout(awaitable, **_kwargs):
    close = getattr(awaitable, "close", None)
    if callable(close):
        close()
    raise TimeoutError


class KatanaMultiOriginQualityTests(unittest.IsolatedAsyncioTestCase):
    def test_stream_collector_caps_raw_bytes_and_drops_one_oversized_record(self):
        collector = KatanaStreamCollector("https://target.test/", 10)
        oversized = b'{"response":{"body":"' + (
            b"x" * KATANA_JSONL_RECORD_MAX_BYTES
        ) + b'"}}\n'
        valid = (
            b'{"request":{"endpoint":"https://target.test/ok"},'
            b'"response":{"status_code":200}}\n'
        )

        for offset in range(0, len(oversized + valid), 32_768):
            collector.feed((oversized + valid)[offset:offset + 32_768])
        collector.finish()

        self.assertEqual(collector.urls, ["https://target.test/ok"])
        self.assertEqual(collector.oversized_records, 1)
        self.assertGreaterEqual(collector.records_dropped, 1)
        self.assertLessEqual(
            len(collector.raw_output().encode("utf-8")),
            KATANA_RAW_EVIDENCE_MAX_BYTES,
        )

    async def test_partial_origin_errors_are_preserved_with_usable_urls(self):
        good = (
            b'{"request":{"endpoint":"http://one.test/"},'
            b'"response":{"status_code":200}}\n'
        )
        partial = b'{"error":"connection refused"}\n'
        with patch(
            "tools.katana_crawl.asyncio.create_subprocess_exec",
            side_effect=[_FakeKatanaProcess(good), _FakeKatanaProcess(partial)],
        ) as spawn, patch(
            "tools.katana_crawl.process_reaper.register_group"
        ) as register_group:
            output = await KatanaCrawlTool()._crawl_multiple_targets(
                ["http://one.test/", "https://two.test/"],
                depth=2,
                max_urls=100,
                headers_file=None,
                cookie=None,
                agent=None,
                parameters={},
            )

        self.assertEqual(spawn.call_count, 2)
        self.assertTrue(all(call.kwargs["start_new_session"] for call in spawn.call_args_list))
        self.assertEqual(register_group.call_count, 2)
        self.assertTrue(all("-or" in call.args for call in spawn.call_args_list))
        self.assertTrue(all("-ob" in call.args for call in spawn.call_args_list))

        self.assertEqual(output["coverageStatus"], "CONFIRMED")
        self.assertEqual(output["coverageReason"], "PARTIAL_URL_INVENTORY_OBSERVED")
        self.assertEqual(output["urls"], ["http://one.test/"])
        self.assertEqual(
            output["partialErrors"],
            ["https://two.test/: CRAWL_ERRORS_WITHOUT_URL_EVIDENCE"],
        )

    async def test_single_target_timeout_tears_down_only_registered_group_and_keeps_partial_output(self):
        partial = (
            b'{"request":{"endpoint":"http://one.test/"},'
            b'"response":{"status_code":200}}\n'
        )
        process = _TimedOutKatanaProcess(partial)
        terminate_group = AsyncMock()
        with patch(
            "tools.katana_crawl.asyncio.create_subprocess_exec",
            return_value=process,
        ) as spawn, patch(
            "tools.katana_crawl.asyncio.wait_for",
            side_effect=_close_awaitable_and_raise_timeout,
        ), patch(
            "tools.katana_crawl.process_reaper.register_group"
        ) as register_group, patch(
            "tools.katana_crawl.process_reaper.terminate_group",
            terminate_group,
        ):
            output = await KatanaCrawlTool().execute(
                {"target": "http://one.test/", "crawlTimeoutSeconds": 30}
            )

        self.assertTrue(spawn.call_args.kwargs["start_new_session"])
        self.assertIn("-or", spawn.call_args.args)
        self.assertIn("-ob", spawn.call_args.args)
        register_group.assert_called_once_with(process)
        terminate_group.assert_awaited_once_with(process)
        self.assertEqual(output["coverageStatus"], "CONFIRMED")
        self.assertEqual(output["coverageReason"], "TIMEOUT_WITH_PARTIAL_URL_EVIDENCE")
        self.assertTrue(output["rootReachable"])
        self.assertEqual(output["urls"], ["http://one.test/"])

    async def test_multi_target_timeout_tears_down_registered_group_and_keeps_partial_output(self):
        partial = (
            b'{"request":{"endpoint":"http://one.test/inside"},'
            b'"response":{"status_code":200}}\n'
        )
        process = _TimedOutKatanaProcess(partial)
        terminate_group = AsyncMock()
        with patch(
            "tools.katana_crawl.asyncio.create_subprocess_exec",
            return_value=process,
        ) as spawn, patch(
            "tools.katana_crawl.asyncio.wait_for",
            side_effect=_close_awaitable_and_raise_timeout,
        ), patch(
            "tools.katana_crawl.process_reaper.register_group"
        ) as register_group, patch(
            "tools.katana_crawl.process_reaper.terminate_group",
            terminate_group,
        ):
            output = await KatanaCrawlTool()._crawl_multiple_targets(
                ["http://one.test/"],
                depth=2,
                max_urls=100,
                headers_file=None,
                cookie=None,
                agent=None,
                parameters={},
            )

        self.assertTrue(spawn.call_args.kwargs["start_new_session"])
        register_group.assert_called_once_with(process)
        terminate_group.assert_awaited_once_with(process)
        self.assertEqual(output["coverageStatus"], "CONFIRMED")
        self.assertEqual(output["coverageReason"], "PARTIAL_URL_INVENTORY_OBSERVED")
        self.assertEqual(output["urls"], ["http://one.test/inside"])
        self.assertTrue(output["perTarget"][0]["partialResults"])
        self.assertIn("http://one.test/: timeout", output["partialErrors"])

class BrowserMapCoverageVerdictTests(unittest.IsolatedAsyncioTestCase):
    def test_browser_context_blocks_service_workers(self):
        self.assertEqual(BROWSER_CONTEXT_SCOPE_OPTIONS, {"service_workers": "block"})

    def test_websocket_origin_requires_matching_transport_host_and_effective_port(self):
        self.assertTrue(
            same_websocket_origin(
                "http://App.Example.test/path",
                "ws://app.example.test/socket",
            )
        )
        self.assertTrue(
            same_websocket_origin(
                "https://app.example.test:8443/path",
                "wss://APP.EXAMPLE.TEST:8443/socket",
            )
        )
        self.assertFalse(
            same_websocket_origin(
                "https://app.example.test/path",
                "ws://app.example.test/socket",
            )
        )
        self.assertFalse(
            same_websocket_origin(
                "https://app.example.test/path",
                "wss://app.example.test:8443/socket",
            )
        )
        self.assertFalse(
            same_websocket_origin(
                "https://app.example.test/path",
                "wss://outside.example.test/socket",
            )
        )

    async def test_browser_map_blocks_cross_origin_websocket_before_handshake(self):
        connections = {"same_origin": 0, "cross_origin": 0}

        async def websocket_handler(request, counter):
            websocket = web.WebSocketResponse()
            await websocket.prepare(request)
            connections[counter] += 1
            await websocket.close()
            return websocket

        external_app = web.Application()
        external_app.router.add_get(
            "/outside",
            lambda request: websocket_handler(request, "cross_origin"),
        )
        async with _TestServer(external_app) as external:
            external_websocket = external.replace("http://", "ws://", 1)
            source_app = web.Application()
            source_app.router.add_get(
                "/same",
                lambda request: websocket_handler(request, "same_origin"),
            )
            source_app.router.add_get(
                "/",
                lambda _request: web.Response(
                    text=(
                        "<html><body>WebSocket scope fixture"
                        "<script>"
                        "new WebSocket('ws://' + location.host + '/same');"
                        f"new WebSocket('{external_websocket}/outside');"
                        "</script></body></html>"
                    ),
                    content_type="text/html",
                ),
            )
            async with _TestServer(source_app) as target:
                output = await BrowserMapAppTool().execute(
                    {
                        "target": target,
                        "maxInteractions": 0,
                        "timeoutSeconds": 20,
                    }
                )

        self.assertTrue(output["success"], output)
        self.assertEqual(connections["same_origin"], 1)
        self.assertEqual(connections["cross_origin"], 0)

    async def test_http_fallback_proves_root_reachability(self):
        app = web.Application()
        app.router.add_get(
            "/",
            lambda _request: web.Response(
                text='<html><a href="/docs">Docs</a></html>',
                content_type="text/html",
            ),
        )
        async with _TestServer(app) as target:
            output = await BrowserMapAppTool()._http_fallback(
                target,
                {},
                "synthetic browser failure",
            )

        self.assertTrue(output["success"])
        self.assertTrue(output["verified"])
        self.assertEqual(output["coverageStatus"], "CONFIRMED")
        self.assertEqual(output["coverageReason"], "HTTP_ROOT_FETCH_COMPLETED")
        self.assertEqual(output["status"], 200)
        self.assertIn(f"{target}/docs", output["links"])

    async def test_http_fallback_blocks_cross_origin_redirect(self):
        destination_app = web.Application()
        destination_app.router.add_get("/outside", lambda _request: web.Response(text="outside"))
        async with _TestServer(destination_app) as destination:
            source_app = web.Application()
            source_app.router.add_get(
                "/",
                lambda _request: web.HTTPFound(location=f"{destination}/outside"),
            )
            async with _TestServer(source_app) as target:
                output = await BrowserMapAppTool()._http_fallback(
                    target,
                    {},
                    "synthetic browser failure",
                )

        self.assertFalse(output["success"])
        self.assertFalse(output["verified"])
        self.assertEqual(output["coverageStatus"], "INCOMPLETE")
        self.assertEqual(output["coverageReason"], "CROSS_ORIGIN_REDIRECT_BLOCKED")
        self.assertEqual(output["redirectTarget"], f"{destination}/outside")


if __name__ == "__main__":
    unittest.main()
