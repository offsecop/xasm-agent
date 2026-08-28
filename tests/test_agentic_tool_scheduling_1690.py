import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from tools.agentic_exploit_chain import ExploitChainTool
from tools.agentic_exploitation_queue import ExploitationQueueTool
from tools.dirsearch_quick import DirsearchQuickTool


class _ProgressRecorder:
    def __init__(self):
        self.progress = []
        self.output = []

    def report_progress(self, current_operation, current_target, items_processed, total_items):
        self.progress.append(
            {
                "current_operation": current_operation,
                "current_target": current_target,
                "items_processed": items_processed,
                "total_items": total_items,
            }
        )

    def append_output(self, message):
        self.output.append(message)


class _SlowProcess:
    def __init__(self):
        self.pid = 12345
        self.killed = False

    async def communicate(self):
        await asyncio.sleep(60)

    def kill(self):
        self.killed = True

    async def wait(self):
        return -9


class _CompletedProcess:
    def __init__(self):
        self.pid = 23456
        self.returncode = 0

    async def communicate(self):
        return b"", b""


class AgenticToolScheduling1690Tests(unittest.IsolatedAsyncioTestCase):
    async def test_exploit_chain_false_disables_api_rediscovery(self):
        tool = ExploitChainTool()
        supplied = {
            "method": "GET",
            "url": "https://app.example.test/api/me",
        }

        with patch(
            "tools.agentic_api_discover.ApiDiscoverTool.execute",
            new_callable=AsyncMock,
        ) as discover:
            endpoints = await tool._discover_api_endpoints(
                "https://app.example.test/",
                {
                    "apiEndpoints": [supplied],
                    "discoverApiEndpoints": False,
                },
            )

        discover.assert_not_awaited()
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["method"], supplied["method"])
        self.assertEqual(endpoints[0]["url"], supplied["url"])
        self.assertIn("discoverApiEndpoints", tool.schema["properties"])

    async def test_exploit_chain_does_not_accept_legacy_or_string_authority_flags(self):
        result = await ExploitChainTool().execute(
            {
                "target": "https://app.example.test/",
                "aggressive": True,
                "modules": ["jwt"],
                "discoverApiEndpoints": False,
                "allowFallbackCandidates": True,
                "allowDefaultCredentialProbe": True,
                "allowStateChanging": True,
                "enableDefaultCredentialProbe": "true",
                "allowGeneratedCandidates": "true",
                "allowUnsafeMethods": "true",
                "maxCredAttempts": 50,
            }
        )

        stats = result["candidateStats"]
        self.assertFalse(stats["generatedCandidateMode"])
        self.assertFalse(stats["defaultCredentialProbeEnabled"])
        self.assertFalse(stats["unsafeMethodsAllowed"])

    async def test_exploit_chain_returns_content_free_partial_deadline_metadata(self):
        tool = ExploitChainTool()

        async def slow_discovery(*_args, **_kwargs):
            await asyncio.sleep(60)

        with patch(
            "tools.agentic_exploit_chain._coerce_timeout_seconds",
            return_value=0.001,
        ), patch.object(tool, "_discover_api_endpoints", side_effect=slow_discovery):
            result = await tool.execute(
                {
                    "target": "https://secret.example.test/",
                    "aggressive": True,
                    "modules": ["graphql"],
                }
            )

        self.assertFalse(result["success"])
        self.assertTrue(result["timedOut"])
        self.assertTrue(result["partial"])
        metrics = result["executionMetrics"]
        self.assertEqual(
            set(metrics),
            {"elapsedMs", "timeoutSeconds", "deadlineExceeded", "candidateCount"},
        )
        self.assertNotIn("secret.example.test", json.dumps(metrics))

    def test_exploitation_queue_prioritizes_dedicated_probe_and_keeps_authority_off(self):
        queue = ExploitationQueueTool()
        candidate = {
            "id": "cand-xxe",
            "type": "xxe_candidate",
            "title": "XML endpoint",
            "url": "https://app.example.test/product/stock",
            "method": "POST",
            "source": "form",
            "risk": "HIGH",
            "confidence": 0.9,
            "reason": "XML request body observed",
            "recommendedTools": ["exploit:chain", "web:xxe_probe"],
            "evidenceExpected": "request and response delta",
            "requiresAggressive": False,
        }

        actions = queue._build_next_actions(
            "https://app.example.test/", [candidate], aggressive=True
        )
        tools = [action["tool"] for action in actions]
        self.assertLess(tools.index("web:xxe_probe"), tools.index("exploit:chain"))

        chain = next(action for action in actions if action["tool"] == "exploit:chain")
        params = chain["parameters"]
        self.assertFalse(params["discoverApiEndpoints"])
        self.assertFalse(params["enableDefaultCredentialProbe"])
        self.assertEqual(params["maxCredAttempts"], 0)
        self.assertFalse(params["allowGeneratedCandidates"])
        self.assertFalse(params["allowGeneratedLoginPaths"])
        self.assertFalse(params["allowUnsafeMethods"])

    async def test_dirsearch_honors_sub_300_deadline_and_redacts_progress_metadata(self):
        tool = DirsearchQuickTool()
        agent = _ProgressRecorder()
        captured_timeouts = []

        async def fake_scan(**kwargs):
            captured_timeouts.append(kwargs["timeout_seconds"])
            return {
                "target": kwargs["target"],
                "endpoints": [],
                "urls": [],
                "totalEndpoints": 0,
                "timedOut": False,
                "partial": False,
            }

        with patch.object(tool, "_scan_single_target", side_effect=fake_scan):
            result = await tool.execute(
                {
                    "target": "https://secret.example.test/",
                    "timeoutSeconds": 2,
                    "_agent": agent,
                }
            )

        self.assertTrue(result["success"])
        self.assertEqual(result["timeoutSeconds"], 2)
        self.assertEqual(len(captured_timeouts), 1)
        self.assertGreater(captured_timeouts[0], 0)
        self.assertLessEqual(captured_timeouts[0], 2)
        self.assertNotIn("secret.example.test", json.dumps(agent.progress))

    async def test_dirsearch_returns_explicit_partial_timeout(self):
        tool = DirsearchQuickTool()
        process = _SlowProcess()

        with patch(
            "tools.dirsearch_quick.asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=process),
        ):
            result = await tool._scan_single_target(
                target="https://app.example.test/",
                extensions="php",
                headers_file=None,
                cookie=None,
                wordlist=None,
                agent=None,
                execution_metrics={},
                timeout_seconds=0.001,
            )

        self.assertTrue(process.killed)
        self.assertTrue(result["timedOut"])
        self.assertTrue(result["partial"])
        self.assertIn("elapsedMs", result)

    async def test_dirsearch_uses_runtime_supported_json_and_header_options(self):
        tool = DirsearchQuickTool()
        process = _CompletedProcess()
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as headers:
            headers.write("Authorization: [REDACTED]\n")
            headers_file = headers.name
        try:
            with patch(
                "tools.dirsearch_quick.asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=process),
            ) as spawn:
                await tool._scan_single_target(
                    target="https://app.example.test/",
                    extensions="php",
                    headers_file=headers_file,
                    cookie=None,
                    wordlist=None,
                    agent=None,
                    execution_metrics={},
                    timeout_seconds=1,
                )

            command = list(spawn.await_args.args)
            self.assertIn("-O", command)
            self.assertEqual(command[command.index("-O") + 1], "json")
            self.assertIn("-q", command)
            self.assertIn("--headers-file", command)
            self.assertNotIn("--format=json", command)
            self.assertNotIn("--header-list", command)
        finally:
            os.remove(headers_file)

    async def test_dirsearch_deadline_preserves_partial_results_as_bounded_completion(self):
        tool = DirsearchQuickTool()

        async def partial_scan(**kwargs):
            return {
                "target": kwargs["target"],
                "endpoints": [{"url": f'{kwargs["target"]}admin', "status_code": 200}],
                "urls": [f'{kwargs["target"]}admin'],
                "totalEndpoints": 1,
                "timedOut": True,
                "partial": True,
            }

        with patch.object(tool, "_scan_single_target", side_effect=partial_scan):
            result = await tool.execute(
                {
                    "target": "https://app.example.test/",
                    "timeoutSeconds": 1,
                }
            )

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "PARTIAL_TIMEOUT")
        self.assertTrue(result["timedOut"])
        self.assertTrue(result["partial"])
        self.assertFalse(result["coverageComplete"])
        self.assertEqual(result["totalEndpoints"], 1)


if __name__ == "__main__":
    unittest.main()
