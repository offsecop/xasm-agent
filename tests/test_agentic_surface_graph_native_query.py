import unittest
from unittest.mock import AsyncMock, patch

from tools._agentic_exploration_common import (
    NATIVE_PROBE_PRIVATE_CANDIDATES_KEY,
    NATIVE_PROBE_QUERY_CANDIDATES_KEY,
)
from tools.agentic_exploitation_queue import ExploitationQueueTool
from tools.agentic_surface_graph import SurfaceGraphTool


class SurfaceGraphNativeQueryTests(unittest.IsolatedAsyncioTestCase):
    async def test_observed_query_is_redacted_and_routes_dalfox(self):
        private_value = "private-reflection-marker"
        fetched = {
            "url": "https://fixture.example/",
            "status": 200,
            "text": (
                "<html><body>"
                f'<a href="/search?q={private_value}">Search</a>'
                "</body></html>"
            ),
        }

        with patch(
            "tools.agentic_surface_graph.fetch_text",
            new=AsyncMock(return_value=fetched),
        ):
            graph = await SurfaceGraphTool().execute(
                {
                    "target": "https://fixture.example/",
                    "maxPages": 1,
                    "includeKnownFiles": False,
                }
            )

        query_candidates = graph[NATIVE_PROBE_QUERY_CANDIDATES_KEY]
        self.assertEqual(len(query_candidates), 1)
        self.assertEqual(
            graph["surfaceGraph"][NATIVE_PROBE_QUERY_CANDIDATES_KEY],
            query_candidates,
        )
        self.assertEqual(graph["summary"]["nativeQueryCandidates"], 1)
        self.assertIn(
            private_value,
            str(graph[NATIVE_PROBE_PRIVATE_CANDIDATES_KEY]),
        )
        public_output = {
            key: value
            for key, value in graph.items()
            if key != NATIVE_PROBE_PRIVATE_CANDIDATES_KEY
        }
        self.assertNotIn(private_value, str(public_output))

        queued = await ExploitationQueueTool().execute(
            {
                "target": "https://fixture.example/",
                "surfaceGraph": graph["surfaceGraph"],
                "riskTolerance": "high",
                "engagement": "aggressive",
            }
        )
        dalfox = next(
            action
            for action in queued["nextActions"]
            if action["tool"] == "dalfox:xss_scan"
        )
        self.assertTrue(dalfox["autonomousReady"])
        self.assertEqual(dalfox["nativeProbe"]["status"], "READY")
        self.assertEqual(dalfox["nativeProbe"]["adapterId"], "dalfox:xss_scan")
        self.assertEqual(dalfox["candidateTypes"], ["reflection_candidate"])
        self.assertEqual(
            dalfox["candidateIds"],
            [query_candidates[0]["nativeProbeCandidateId"]],
        )


if __name__ == "__main__":
    unittest.main()
