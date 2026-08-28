import json
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import urlsplit

from tools.web_http_request_sequence import (
    SERVER_POLICY_KEY,
    HttpRequestSequenceTool,
    _RequestSequencePolicy,
)


class _SequenceHandler(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, _format, *_args):
        return

    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        for key, value in headers or []:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        type(self).seen.append(
            {
                "method": "GET",
                "path": self.path,
                "host": self.headers.get("Host"),
                "cookie": self.headers.get("Cookie"),
                "authorization": self.headers.get("Authorization"),
            }
        )
        if self.path == "/start":
            self._send(
                200,
                b'{"csrfToken":"csrf-secret-token","next":"/use"}',
                [
                    ("Content-Type", "application/json"),
                    ("Set-Cookie", "session=server-secret-token; Path=/; HttpOnly"),
                ],
            )
        elif self.path == "/redirect":
            self._send(302, headers=[("Location", "/final")])
        elif self.path == "/cross-origin":
            host, port = self.server.server_address
            self._send(302, headers=[("Location", f"http://localhost:{port}/final")])
        elif self.path == "/large":
            self._send(200, b"x" * 1024)
        elif self.path == "/unexpected":
            self._send(201, b"created")
        elif self.path == "/html-form":
            self._send(
                200,
                (
                    b'<html><head><meta name="csrf-meta" content="meta-secret-value">'
                    b'</head><body><input type="hidden" name="csrf" '
                    b'value="html-secret-value"></body></html>'
                ),
                [("Content-Type", "text/html")],
            )
        elif self.path == "/domain-cookie":
            self._send(
                200,
                b"cookie-set",
                [("Set-Cookie", "wide=domain-secret-value; Domain=.example.test; Path=/")],
            )
        elif self.path.startswith("/echo-query"):
            self._send(200, self.path.encode("utf-8"))
        else:
            self._send(200, b"final")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        type(self).seen.append(
            {
                "method": "POST",
                "path": self.path,
                "host": self.headers.get("Host"),
                "cookie": self.headers.get("Cookie"),
                "authorization": self.headers.get("Authorization"),
                "body": body,
            }
        )
        if (
            "csrf-secret-token" in body
            and "session=server-secret-token" in (self.headers.get("Cookie") or "")
        ):
            self._send(
                200,
                b'{"accepted":true,"sessionToken":"response-secret-token"}',
                [("Content-Type", "application/json")],
            )
        else:
            self._send(403, b"denied")


class HttpRequestSequencePolicyTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _SequenceHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        _SequenceHandler.seen = []

    def policy(self, *, origins=None, max_bytes=200_000, ip_ranges=None):
        return {
            "version": 1,
            "allowedOrigins": origins or [self.origin],
            "allowedIpRanges": ["127.0.0.1/32"] if ip_ranges is None else ip_ranges,
            "allowedPortRanges": [
                {"from": self.server.server_port, "to": self.server.server_port}
            ],
            "maxRedirects": 3,
            "maxSteps": 50,
            "maxResponseBytes": max_bytes,
            "requirePerHopValidation": True,
        }

    async def test_private_policy_is_required_but_not_exposed_in_public_schema(self):
        tool = HttpRequestSequenceTool()
        self.assertNotIn(SERVER_POLICY_KEY, tool.schema["properties"])

        output = await tool.execute({"sequence": [{"url": self.origin + "/"}]})

        self.assertFalse(output["success"])
        self.assertEqual(output["code"], "SERVER_REQUEST_SEQUENCE_POLICY_REQUIRED")
        self.assertEqual(_SequenceHandler.seen, [])

    def test_target_only_public_origin_accepts_public_dns_without_ranges(self):
        policy = _RequestSequencePolicy.parse(
            {
                "version": 1,
                "allowedOrigins": ["https://public.example"],
                "allowedIpRanges": [],
                "allowedPortRanges": [],
                "maxRedirects": 3,
                "maxSteps": 50,
                "maxResponseBytes": 200_000,
                "requirePerHopValidation": True,
            }
        )
        with patch(
            "tools.web_http_request_sequence.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ],
        ):
            hop = policy.validate_and_resolve("https://public.example/path")

        self.assertEqual(hop.connect_ip, "93.184.216.34")
        self.assertEqual(hop.port, 443)

    def test_exact_public_origin_is_not_constrained_by_an_unrelated_scope_cidr(self):
        policy = _RequestSequencePolicy.parse(
            {
                "version": 1,
                "allowedOrigins": ["https://public.example"],
                "allowedIpRanges": ["10.0.0.0/8"],
                "allowedPortRanges": [],
                "maxRedirects": 3,
                "maxSteps": 50,
                "maxResponseBytes": 200_000,
                "requirePerHopValidation": True,
            }
        )
        with patch(
            "tools.web_http_request_sequence.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ],
        ):
            hop = policy.validate_and_resolve("https://public.example/path")

        self.assertEqual(hop.connect_ip, "93.184.216.34")

    def test_target_only_policy_rejects_private_dns_without_explicit_range(self):
        policy = _RequestSequencePolicy.parse(
            {
                "version": 1,
                "allowedOrigins": ["https://private.example"],
                "allowedIpRanges": [],
                "allowedPortRanges": [],
                "maxRedirects": 3,
                "maxSteps": 50,
                "maxResponseBytes": 200_000,
                "requirePerHopValidation": True,
            }
        )
        with patch(
            "tools.web_http_request_sequence.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 443))
            ],
        ):
            with self.assertRaisesRegex(ValueError, "explicit server-approved range"):
                policy.validate_and_resolve("https://private.example/path")

    def test_dynamic_origin_can_be_authorized_by_explicit_ip_and_port_ranges(self):
        policy = _RequestSequencePolicy.parse(
            {
                "version": 1,
                "allowedOrigins": [],
                "allowedIpRanges": ["93.184.216.0/24"],
                "allowedPortRanges": [{"from": 443, "to": 443}],
                "maxRedirects": 3,
                "maxSteps": 50,
                "maxResponseBytes": 200_000,
                "requirePerHopValidation": True,
            }
        )
        with patch(
            "tools.web_http_request_sequence.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ],
        ):
            hop = policy.validate_and_resolve("https://captured.example/path")

        self.assertEqual(hop.origin, "https://captured.example")
        self.assertEqual(hop.connect_ip, "93.184.216.34")

    def test_metadata_address_is_denied_even_when_cidr_is_explicit(self):
        policy = _RequestSequencePolicy.parse(
            {
                "version": 1,
                "allowedOrigins": ["http://metadata.example"],
                "allowedIpRanges": ["100.100.100.200/32"],
                "allowedPortRanges": [],
                "maxRedirects": 3,
                "maxSteps": 50,
                "maxResponseBytes": 200_000,
                "requirePerHopValidation": True,
            }
        )
        with patch(
            "tools.web_http_request_sequence.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("100.100.100.200", 80))
            ],
        ):
            with self.assertRaisesRegex(ValueError, "forbidden address class"):
                policy.validate_and_resolve("http://metadata.example/latest/meta-data")

    def test_ipv4_mapped_metadata_address_is_always_denied(self):
        policy = _RequestSequencePolicy.parse(
            {
                "version": 1,
                "allowedOrigins": ["http://mapped-metadata.example"],
                "allowedIpRanges": ["::ffff:100.100.100.200/128"],
                "allowedPortRanges": [],
                "maxRedirects": 3,
                "maxSteps": 50,
                "maxResponseBytes": 200_000,
                "requirePerHopValidation": True,
            }
        )
        with patch(
            "tools.web_http_request_sequence.socket.getaddrinfo",
            return_value=[
                (
                    socket.AF_INET6,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    ("::ffff:100.100.100.200", 80, 0, 0),
                )
            ],
        ):
            with self.assertRaisesRegex(ValueError, "forbidden address class"):
                policy.validate_and_resolve(
                    "http://mapped-metadata.example/latest/meta-data"
                )

    async def test_stateful_cookie_capture_and_template_are_internal_and_sanitized(self):
        output = await HttpRequestSequenceTool().execute(
            {
                "sequence": [
                    {
                        "url": self.origin + "/start",
                        "capture": {"csrf": "$.json.csrfToken"},
                    },
                    {
                        "method": "POST",
                        "url": self.origin + "/use",
                        "headers": {"Content-Type": "application/json"},
                        "body": '{"csrf":"{{$.responses[0].captures.csrf}}"}',
                        "expectedStatus": 200,
                    },
                ],
                "authCookies": "seed=seed-secret-value",
                "authHeaders": {
                    "Authorization": "Bearer auth-secret-value",
                    "X-Private-Context": "opaque-custom-secret",
                },
                "allowUnsafeMethods": True,
                SERVER_POLICY_KEY: self.policy(),
            }
        )

        self.assertTrue(output["success"], output)
        self.assertEqual(len(output["transcript"]), 2)
        self.assertEqual(len(output["responses"]), 2)
        self.assertIn("session=server-secret-token", _SequenceHandler.seen[1]["cookie"])
        self.assertIn("seed=seed-secret-value", _SequenceHandler.seen[1]["cookie"])
        self.assertEqual(_SequenceHandler.seen[1]["authorization"], "Bearer auth-secret-value")
        serialized = json.dumps(output)
        for secret in (
            "csrf-secret-token",
            "server-secret-token",
            "seed-secret-value",
            "auth-secret-value",
            "response-secret-token",
            "opaque-custom-secret",
        ):
            self.assertNotIn(secret, serialized)
        self.assertIn("{{capture:step-0-csrf}}", serialized)
        self.assertEqual(
            output["transcript"][1]["request"]["headers"]["Authorization"],
            "***REDACTED***",
        )

    async def test_reads_are_bounded_and_report_truncation(self):
        output = await HttpRequestSequenceTool().execute(
            {
                "sequence": [{"url": self.origin + "/large"}],
                SERVER_POLICY_KEY: self.policy(max_bytes=64),
            }
        )

        self.assertTrue(output["success"], output)
        self.assertTrue(output["transcript"][0]["truncated"])
        self.assertEqual(output["transcript"][0]["bodyBytes"], 64)
        self.assertEqual(len(output["transcript"][0]["body"]), 64)

    async def test_query_credentials_are_redacted_from_request_and_echoed_response(self):
        output = await HttpRequestSequenceTool().execute(
            {
                "sequence": [
                    {
                        "url": self.origin
                        + "/echo-query?access_token=query-secret-value"
                    }
                ],
                SERVER_POLICY_KEY: self.policy(),
            }
        )

        self.assertTrue(output["success"], output)
        serialized = json.dumps(output)
        self.assertNotIn("query-secret-value", serialized)
        self.assertIn("<redacted-runtime-secret>", serialized)

    async def test_auth_and_cookie_session_do_not_leak_to_another_origin(self):
        localhost_origin = f"http://localhost:{self.server.server_port}"
        output = await HttpRequestSequenceTool().execute(
            {
                "sequence": [
                    {"url": self.origin + "/start"},
                    {"url": localhost_origin + "/final"},
                ],
                "authCookies": "seed=seed-secret-value",
                "authHeaders": {"Authorization": "Bearer auth-secret-value"},
                SERVER_POLICY_KEY: self.policy(
                    origins=[self.origin, localhost_origin],
                    ip_ranges=["127.0.0.0/8", "::1/128"],
                ),
            }
        )

        self.assertTrue(output["success"], output)
        self.assertEqual(len(_SequenceHandler.seen), 2)
        self.assertEqual(
            _SequenceHandler.seen[0]["authorization"], "Bearer auth-secret-value"
        )
        self.assertIn("seed=seed-secret-value", _SequenceHandler.seen[0]["cookie"])
        self.assertIsNone(_SequenceHandler.seen[1]["authorization"])
        self.assertIsNone(_SequenceHandler.seen[1]["cookie"])
        serialized = json.dumps(output)
        self.assertNotIn("seed-secret-value", serialized)
        self.assertNotIn("auth-secret-value", serialized)

    async def test_burst_keeps_one_transcript_entry_per_logical_step(self):
        output = await HttpRequestSequenceTool().execute(
            {
                "sequence": [
                    {
                        "url": self.origin + "/final",
                        "burst": {"count": 3, "sync": "BARRIER"},
                    }
                ],
                SERVER_POLICY_KEY: self.policy(),
            }
        )

        self.assertTrue(output["success"], output)
        self.assertEqual(len(output["transcript"]), 1)
        self.assertEqual(len(output["transcript"][0]["burstResults"]), 3)
        self.assertTrue(
            all(result["success"] for result in output["transcript"][0]["burstResults"])
        )
        self.assertEqual(len(output["responses"]), 1)

    async def test_same_origin_redirect_succeeds_and_cross_origin_redirect_fails(self):
        same_origin = await HttpRequestSequenceTool().execute(
            {
                "sequence": [{"url": self.origin + "/redirect"}],
                SERVER_POLICY_KEY: self.policy(),
            }
        )
        self.assertTrue(same_origin["success"], same_origin)
        self.assertEqual(same_origin["transcript"][0]["status"], 200)
        self.assertEqual(len(same_origin["transcript"][0]["redirects"]), 1)

        localhost_origin = f"http://localhost:{self.server.server_port}"
        cross_origin = await HttpRequestSequenceTool().execute(
            {
                "sequence": [{"url": self.origin + "/cross-origin"}],
                SERVER_POLICY_KEY: self.policy(
                    origins=[self.origin, localhost_origin],
                    ip_ranges=["127.0.0.0/8", "::1/128"],
                ),
            }
        )
        self.assertFalse(cross_origin["success"])
        self.assertIn("same-origin", cross_origin["error"])

    async def test_dns_rebinding_is_revalidated_before_the_pinned_connection(self):
        allowed = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", self.server.server_port))
        ]
        rebound = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", self.server.server_port))
        ]
        with patch(
            "tools.web_http_request_sequence.socket.getaddrinfo",
            side_effect=[allowed, rebound],
        ):
            output = await HttpRequestSequenceTool().execute(
                {
                    "sequence": [{"url": self.origin + "/redirect"}],
                    SERVER_POLICY_KEY: self.policy(),
                }
            )

        self.assertFalse(output["success"])
        self.assertIn("forbidden address class", output["error"])
        self.assertEqual([request["path"] for request in _SequenceHandler.seen], ["/redirect"])

    async def test_transport_failure_is_not_reported_as_success(self):
        probe_socket = socket.socket()
        probe_socket.bind(("127.0.0.1", 0))
        closed_port = probe_socket.getsockname()[1]
        probe_socket.close()
        origin = f"http://127.0.0.1:{closed_port}"
        policy = self.policy(origins=[origin])
        policy["allowedPortRanges"] = [{"from": closed_port, "to": closed_port}]

        output = await HttpRequestSequenceTool().execute(
            {
                "sequence": [{"url": origin + "/"}],
                SERVER_POLICY_KEY: policy,
            }
        )

        self.assertFalse(output["success"])
        self.assertIn("HTTP transport failed", output["error"])
        self.assertFalse(output["transcript"][0]["success"])

    async def test_expected_status_mismatch_fails_and_pads_remaining_transcript(self):
        output = await HttpRequestSequenceTool().execute(
            {
                "sequence": [
                    {
                        "url": self.origin + "/unexpected",
                        "expectedStatus": 200,
                    },
                    {"url": self.origin + "/final"},
                    {"url": self.origin + "/final"},
                ],
                SERVER_POLICY_KEY: self.policy(),
            }
        )

        self.assertFalse(output["success"], output)
        self.assertEqual(len(output["transcript"]), 3)
        self.assertEqual(output["transcript"][0]["code"], "EXPECTED_STATUS_MISMATCH")
        self.assertFalse(output["transcript"][0]["success"])
        for skipped in output["transcript"][1:]:
            self.assertEqual(skipped["executionStatus"], "SKIPPED")
            self.assertEqual(skipped["reasonCode"], "NOT_EXECUTED")
        self.assertEqual([request["path"] for request in _SequenceHandler.seen], ["/unexpected"])

    async def test_html_capture_is_bounded_internal_and_exposed_only_as_placeholders(self):
        output = await HttpRequestSequenceTool().execute(
            {
                "sequence": [
                    {
                        "url": self.origin + "/html-form",
                        "capture": {
                            "csrf": "$.html.inputs.csrf.value",
                            "meta": "$.html.meta.csrf-meta.content",
                        },
                    },
                    {
                        "url": self.origin
                        + "/echo-query?csrf={{$.responses[0].captures.csrf}}"
                        + "&meta={{$.responses[0].captures.meta}}",
                    },
                ],
                SERVER_POLICY_KEY: self.policy(),
            }
        )

        self.assertTrue(output["success"], output)
        self.assertIn("html-secret-value", _SequenceHandler.seen[1]["path"])
        self.assertIn("meta-secret-value", _SequenceHandler.seen[1]["path"])
        serialized = json.dumps(output)
        self.assertNotIn("html-secret-value", serialized)
        self.assertNotIn("meta-secret-value", serialized)
        self.assertIn("{{capture:step-0-csrf}}", serialized)
        self.assertIn("{{capture:step-0-meta}}", serialized)

    async def test_domain_cookie_is_bound_to_exact_issuing_origin(self):
        app_origin = f"http://app.example.test:{self.server.server_port}"
        api_origin = f"http://api.example.test:{self.server.server_port}"
        resolved = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", self.server.server_port))
        ]
        with patch(
            "tools.web_http_request_sequence.socket.getaddrinfo",
            return_value=resolved,
        ):
            output = await HttpRequestSequenceTool().execute(
                {
                    "sequence": [
                        {"url": app_origin + "/domain-cookie"},
                        {"url": api_origin + "/final"},
                    ],
                    SERVER_POLICY_KEY: self.policy(
                        origins=[app_origin, api_origin],
                        ip_ranges=["127.0.0.1/32"],
                    ),
                }
            )

        self.assertTrue(output["success"], output)
        self.assertEqual(len(_SequenceHandler.seen), 2)
        self.assertIsNone(_SequenceHandler.seen[1]["cookie"])
        self.assertNotIn("domain-secret-value", json.dumps(output))


if __name__ == "__main__":
    unittest.main()
