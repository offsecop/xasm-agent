import unittest

from tools._agentic_exploration_common import forbidden_host_routing_header
from tools.curl_request import CurlRequestTool
from tools.web_http_request_sequence import HttpRequestSequenceTool


class GenericHostHeaderGuardTests(unittest.IsolatedAsyncioTestCase):
    def test_detects_every_reserved_host_routing_header_case_insensitively(self):
        for name in (
            "Host",
            "X-Forwarded-Host",
            "X-Host",
            "X-Forwarded-Server",
            "Forwarded",
            "X-Original-Host",
            ":authority",
        ):
            with self.subTest(name=name):
                self.assertEqual(
                    forbidden_host_routing_header({name.swapcase(): "localhost"}),
                    name.lower(),
                )

    async def test_curl_rejects_host_override_before_running_curl(self):
        output = await CurlRequestTool().execute(
            {
                "url": "https://example.test/",
                "headers": {"HOST": "localhost"},
            }
        )

        self.assertFalse(output["success"])
        self.assertEqual(output["code"], "HOST_ROUTING_HEADER_FORBIDDEN")
        self.assertIn("web:host_header_probe", output["error"])

    async def test_curl_rejects_crlf_header_smuggling(self):
        output = await CurlRequestTool().execute(
            {
                "url": "https://example.test/",
                "headers": {"X-Test": "ok\r\nHost: localhost"},
            }
        )

        self.assertFalse(output["success"])
        self.assertEqual(output["code"], "HOST_ROUTING_HEADER_FORBIDDEN")

    async def test_sequence_rejects_forwarded_override_before_running_curl(self):
        output = await HttpRequestSequenceTool().execute(
            {
                "sequence": [
                    {
                        "url": "https://example.test/admin",
                        "headers": {"Forwarded": "host=localhost"},
                    }
                ]
            }
        )

        self.assertFalse(output["success"])
        self.assertEqual(output["code"], "HOST_ROUTING_HEADER_FORBIDDEN")
        self.assertIn("web:host_header_probe", output["error"])

    async def test_sequence_rejects_server_injected_routing_header(self):
        output = await HttpRequestSequenceTool().execute(
            {
                "sequence": [{"url": "https://example.test/admin"}],
                "authHeaders": {"X-Forwarded-Host": "localhost"},
            }
        )

        self.assertFalse(output["success"])
        self.assertEqual(output["code"], "HOST_ROUTING_HEADER_FORBIDDEN")

    async def test_curl_rejects_graphql_mutation_or_subscription_over_get(self):
        for document in (
            'mutation{deleteUser(id:1){id}}',
            'subscription{events{id}}',
        ):
            with self.subTest(document=document):
                from urllib.parse import quote

                output = await CurlRequestTool().execute(
                    {"url": "https://example.test/api?query=" + quote(document)}
                )
                self.assertFalse(output["success"])
                self.assertEqual(output["code"], "GRAPHQL_GET_WRITE_FORBIDDEN")

    async def test_sequence_rejects_graphql_mutation_over_get(self):
        output = await HttpRequestSequenceTool().execute(
            {
                "sequence": [
                    {
                        "url": "https://example.test/graphql?query=mutation%7BdeleteUser%7Bid%7D%7D",
                        "method": "GET",
                    }
                ]
            }
        )
        self.assertFalse(output["success"])
        self.assertEqual(output["code"], "GRAPHQL_GET_WRITE_FORBIDDEN")


if __name__ == "__main__":
    unittest.main()
