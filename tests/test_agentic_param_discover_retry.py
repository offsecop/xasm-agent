import unittest
from unittest.mock import AsyncMock, patch

import aiohttp

from tools.agentic_param_discover import ParamDiscoverTool


class ParamDiscoverRetryTests(unittest.IsolatedAsyncioTestCase):
    def test_page_fetch_queue_dedupes_fragments_but_preserves_queries(self):
        tool = ParamDiscoverTool()

        urls = tool._page_fetch_urls(
            [
                "https://example.test/",
                "https://example.test/#hero",
                "https://example.test/#features",
                "https://example.test/search?q=one#result",
                "https://example.test/search?q=two",
                "https://outside.example/ignored",
            ],
            "https://example.test/",
            20,
        )

        self.assertEqual(
            urls,
            [
                "https://example.test/",
                "https://example.test/search?q=one",
                "https://example.test/search?q=two",
            ],
        )

    async def test_retries_transient_status_and_maps_page_surface(self):
        tool = ParamDiscoverTool()
        html = """
        <html><body><a href="/next">Next</a>
        <form method="GET" action="/search"><input name="q"></form>
        </body></html>
        """
        responses = [
            {"url": "https://example.test/search", "status": 503, "text": "temporary"},
            {"url": "https://example.test/search", "status": 200, "text": html},
        ]

        with patch(
            "tools.agentic_param_discover.fetch_text",
            new=AsyncMock(side_effect=responses),
        ) as fetch:
            mapped, coverage = await tool._fetch_page_map(
                object(),
                "https://example.test/search?token=private",
                {"Cookie": "private"},
                800_000,
            )

        self.assertEqual(fetch.await_count, 2)
        self.assertIsNotNone(mapped)
        self.assertEqual(mapped["links"], ["https://example.test/next"])
        self.assertEqual(len(mapped["forms"]), 1)
        self.assertEqual(coverage["attempts"], 2)
        self.assertEqual(coverage["outcome"], "mapped")
        self.assertEqual(coverage["mappedForms"], 1)
        self.assertEqual(coverage["url"], "https://example.test/search")
        self.assertNotIn("private", str(coverage))

    async def test_terminal_4xx_is_not_retried(self):
        tool = ParamDiscoverTool()
        with patch(
            "tools.agentic_param_discover.fetch_text",
            new=AsyncMock(
                return_value={
                    "url": "https://example.test/restricted",
                    "status": 403,
                    "text": "denied",
                }
            ),
        ) as fetch:
            mapped, coverage = await tool._fetch_page_map(
                object(),
                "https://example.test/restricted",
                {},
                800_000,
            )

        self.assertIsNone(mapped)
        self.assertEqual(fetch.await_count, 1)
        self.assertEqual(coverage["status"], 403)
        self.assertEqual(coverage["attempts"], 1)
        self.assertEqual(coverage["outcome"], "terminal_http")

    async def test_network_failure_is_bounded_and_sanitized(self):
        tool = ParamDiscoverTool()
        error = aiohttp.ClientConnectionError("secret upstream detail")
        with patch(
            "tools.agentic_param_discover.fetch_text",
            new=AsyncMock(side_effect=[error, error]),
        ) as fetch:
            mapped, coverage = await tool._fetch_page_map(
                object(),
                "https://user:password@example.test/page?api_key=private",
                {"Authorization": "Bearer private"},
                800_000,
            )

        self.assertIsNone(mapped)
        self.assertEqual(fetch.await_count, 2)
        self.assertEqual(coverage["attempts"], 2)
        self.assertEqual(coverage["outcome"], "fetch_error")
        self.assertEqual(coverage["errorClass"], "connection_error")
        self.assertEqual(coverage["url"], "https://example.test/page")
        self.assertNotIn("secret", str(coverage))
        self.assertNotIn("password", str(coverage))
        self.assertNotIn("private", str(coverage))

    async def test_cross_origin_redirect_is_not_mapped(self):
        tool = ParamDiscoverTool()
        with patch(
            "tools.agentic_param_discover.fetch_text",
            new=AsyncMock(
                return_value={
                    "url": "https://outside.example/landing",
                    "status": 200,
                    "text": '<form action="/external"><input name="secret"></form>',
                }
            ),
        ) as fetch:
            mapped, coverage = await tool._fetch_page_map(
                object(),
                "https://example.test/redirect",
                {},
                800_000,
            )

        self.assertIsNone(mapped)
        self.assertEqual(fetch.await_count, 1)
        self.assertEqual(coverage["outcome"], "cross_origin_redirect")
        self.assertEqual(coverage["mappedForms"], 0)
        self.assertNotIn("outside.example", str(coverage))


if __name__ == "__main__":
    unittest.main()
