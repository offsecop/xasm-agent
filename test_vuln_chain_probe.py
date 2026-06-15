import unittest

from tools.agentic_vuln_chain_probe import VulnChainProbeTool


class FakeVulnChainProbeTool(VulnChainProbeTool):
    async def _fetch_probe(self, session, headers, url):
        return {
            "requestedUrl": url,
            "url": url,
            "status": 200,
            "headers": {"Content-Type": "text/html", "Set-Cookie": "session=secret"},
            "text": "<html><body>xasmctx\"><svg/onload=confirm(7331)> text</body></html>",
            "request": self._http_request_evidence("GET", url, headers),
            "response": self._http_response_evidence(
                200,
                {"Content-Type": "text/html", "Set-Cookie": "session=secret"},
                "<html><body>xasmctx\"><svg/onload=confirm(7331)> text</body></html>",
            ),
        }


class VulnChainProbeEvidenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_contextual_xss_finding_includes_redacted_http_evidence(self):
        tool = FakeVulnChainProbeTool()

        result, used = await tool._probe_xss_context(
            None,
            {"Cookie": "session=super-secret", "User-Agent": "xASM-Test"},
            "http://example.test/api/transactions?account_number=1",
            "account_number",
        )

        self.assertEqual(used, 1)
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        evidence = finding["evidence"]

        self.assertIn("GET /api/transactions?account_number=", finding["request"])
        self.assertIn("Cookie: [REDACTED]", finding["request"])
        self.assertNotIn("super-secret", finding["request"])
        self.assertIn("HTTP/1.1 200", finding["response"])
        self.assertIn("<svg/onload=confirm(7331)>", finding["response"])
        self.assertIn("<svg/onload=confirm(7331)>", finding["matchedContent"])
        self.assertIn("<svg/onload=confirm(7331)>", evidence["matchedContent"])
        self.assertTrue(evidence["authenticatedContext"])
        self.assertEqual(evidence["parameter"], "account_number")
        self.assertEqual(evidence["status"], 200)

    def test_form_observation_evidence_uses_source_page_request_response(self):
        tool = VulnChainProbeTool()
        form = {
            "action": "http://example.test/login",
            "method": "POST",
            "fields": [{"name": "username"}, {"name": "password"}],
            "sourceUrl": "http://example.test/",
            "sourceRequest": "GET / HTTP/1.1\nHost: example.test",
            "sourceResponse": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<form>",
        }

        evidence = tool._form_observation_evidence(form, {"Cookie": "session=secret"})

        self.assertEqual(evidence["request"], "GET / HTTP/1.1\nHost: example.test")
        self.assertIn("HTTP/1.1 200", evidence["response"])
        self.assertEqual(evidence["observationType"], "form_metadata")


if __name__ == "__main__":
    unittest.main()
