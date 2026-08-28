import asyncio
import hashlib
import json
import re
import unittest
from urllib.parse import parse_qs, urlsplit

from tools.web_header_injection_probe import (
    EVIDENCE_LABELS,
    LAB_PROOF,
    MODE,
    PROOF_HEADER,
    RUNTIME_PROOF,
    WebHeaderInjectionProbeTool,
)


BOOTSTRAP_COOKIE = "header_session=fixture-bootstrap-secret"
WORKFLOW_COOKIE = "header_session=workflow-owned-secret"


class _RawHeaderServer:
    def __init__(
        self,
        *,
        candidate=True,
        vulnerable=True,
        require_auth=False,
        set_cookie=True,
        catch_all=False,
        duplicate=False,
    ):
        self.candidate = candidate
        self.vulnerable = vulnerable
        self.require_auth = require_auth
        self.set_cookie = set_cookie
        self.catch_all = catch_all
        self.duplicate = duplicate
        self.requests = []
        self.solved = {}
        self.proof_counts = {}
        self.server = None

    async def __aenter__(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        port = self.server.sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}/"

    async def __aexit__(self, exc_type, exc, tb):
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
            lines = raw.decode("iso-8859-1").split("\r\n")
            method, target, _version = lines[0].split(" ", 2)
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    name, value = line.split(":", 1)
                    headers[name.lower()] = value.strip()
            cookie = headers.get("cookie", "")
            self.requests.append((method, target, cookie))
            if self.require_auth and cookie != WORKFLOW_COOKIE:
                await self._respond(writer, 401, "unauthorized")
                return
            parsed = urlsplit(target)
            if parsed.path == "/":
                session = cookie or BOOTSTRAP_COOKIE
                marker = "is-solved" if self.solved.get(session) else "is-notsolved"
                link = "<a href='/redirect?next=welcome&locale=en'>continue</a>" if self.candidate else ""
                extra = [("Set-Cookie", BOOTSTRAP_COOKIE + "; Path=/; HttpOnly")] if self.set_cookie else []
                await self._respond(writer, 200, f"<html><body class='{marker}'>{link}</body></html>", extra)
                return
            if parsed.path == "/redirect":
                query = parse_qs(parsed.query, keep_blank_values=True)
                if query.get("locale") != ["en"]:
                    await self._respond(writer, 400, "locale required")
                    return
                value = query.get("next", [""])[0]
                rendered = value
                injected = []
                match = re.fullmatch(r"welcome\r\nX-Xasm-Crlf-Proof: ([0-9a-f]{24})", value)
                if self.vulnerable and match:
                    nonce = match.group(1)
                    rendered = "welcome"
                    injected.append((PROOF_HEADER, nonce))
                    if self.duplicate:
                        injected.append((PROOF_HEADER, nonce))
                    session = cookie or "anonymous"
                    key = (session, nonce)
                    self.proof_counts[key] = self.proof_counts.get(key, 0) + 1
                    if self.proof_counts[key] >= 2:
                        self.solved[session if cookie else BOOTSTRAP_COOKIE] = True
                else:
                    rendered = rendered.replace("\r", "\\r").replace("\n", "\\n")
                await self._respond(writer, 302, "redirecting", [("X-Reflected", rendered), *injected])
                return
            await self._respond(writer, 200 if self.catch_all else 404, "catch all" if self.catch_all else "not found")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def _respond(self, writer, status, body, extra=()):
        encoded = body.encode()
        reason = {200: "OK", 302: "Found", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found"}.get(status, "Xasm")
        lines = [
            f"HTTP/1.1 {status} {reason}",
            "Content-Type: text/html; charset=utf-8",
            *[f"{name}: {value}" for name, value in extra],
            f"Content-Length: {len(encoded)}",
            "Cache-Control: no-store",
            "Connection: close",
            "",
            "",
        ]
        writer.write("\r\n".join(lines).encode("iso-8859-1") + encoded)
        await writer.drain()


class WebHeaderInjectionProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tool = WebHeaderInjectionProbeTool()

    def test_schema_is_closed_and_only_target_is_model_controlled(self):
        schema = self.tool.schema
        self.assertEqual(self.tool.name, "web:header_injection_probe")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["required"], ["target"])
        self.assertEqual(schema["properties"]["mode"]["enum"], [MODE])
        for name, definition in schema["properties"].items():
            if name != "target":
                self.assertTrue(definition.get("x-workflow-owned"), name)
        for forbidden in (
            "endpoint", "path", "parameter", "payload", "header", "headerName",
            "headerValue", "cookie", "recipient", "logRecord", "rawRequest",
        ):
            self.assertNotIn(forbidden, schema["properties"])

    async def test_runtime_root_only_proves_stable_crlf_header(self):
        fixture = _RawHeaderServer(set_cookie=False)
        async with fixture as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertTrue(result["verified"])
        self.assertFalse(result["fallback"])
        self.assertEqual(result["proofLevel"], RUNTIME_PROOF)
        verification = result["verification"]
        self.assertTrue(verification["literalControlRejected"])
        self.assertTrue(verification["lfOnlyControlRejected"])
        self.assertTrue(verification["crOnlyControlRejected"])
        self.assertTrue(verification["crlfHeaderCreated"])
        self.assertTrue(verification["crlfRepeatStable"])
        self.assertEqual(result["requestCount"], 9)
        steps = verification["headerInjectionEvidence"]["steps"]
        self.assertEqual([step["label"] for step in steps], list(EVIDENCE_LABELS))
        self.assertIn("X-Xasm-Crlf-Proof:", steps[6]["response"])
        self.assertTrue(all(method == "GET" for method, _path, _cookie in fixture.requests))

    async def test_lab_proof_records_independent_solved_transition(self):
        fixture = _RawHeaderServer(set_cookie=False)
        async with fixture as target:
            result = await self.tool.execute(
                {"target": target, "proofLevel": LAB_PROOF, "engagement": "lab"}
            )
        self.assertTrue(result["verified"])
        self.assertTrue(result["verification"]["labSolvedTransition"])
        self.assertEqual(result["requestCount"], 10)
        self.assertEqual(
            result["verification"]["headerInjectionEvidence"]["steps"][-1]["label"],
            "lab-solved-confirmation",
        )

    async def test_bootstrap_cookie_is_reused_but_never_serialized(self):
        fixture = _RawHeaderServer()
        async with fixture as target:
            result = await self.tool.execute({"target": target})
        expected = hashlib.sha256(BOOTSTRAP_COOKIE.encode()).hexdigest()
        self.assertTrue(result["verified"])
        self.assertEqual(result["sessionSource"], "target-bootstrap-cookie")
        self.assertEqual(result["verification"]["authContextSha256"], expected)
        serialized = json.dumps(result)
        self.assertNotIn("fixture-bootstrap-secret", serialized)
        self.assertIn("Set-Cookie: [REDACTED sha256=", serialized)
        self.assertTrue(all(cookie == BOOTSTRAP_COOKIE for _m, _p, cookie in fixture.requests[1:]))

    async def test_workflow_auth_is_used_but_not_serialized(self):
        fixture = _RawHeaderServer(require_auth=True, set_cookie=False)
        async with fixture as target:
            result = await self.tool.execute({"target": target, "authCookies": WORKFLOW_COOKIE})
        self.assertTrue(result["verified"])
        self.assertNotIn("workflow-owned-secret", json.dumps(result))
        self.assertIn("Cookie: [REDACTED sha256=", json.dumps(result))

    async def test_missing_safe_or_ambiguous_candidate_fails_closed(self):
        for fixture in (
            _RawHeaderServer(candidate=False, set_cookie=False),
            _RawHeaderServer(vulnerable=False, set_cookie=False),
            _RawHeaderServer(duplicate=True, set_cookie=False),
            _RawHeaderServer(catch_all=True, set_cookie=False),
        ):
            async with fixture as target:
                result = await self.tool.execute({"target": target})
            self.assertTrue(result["success"])
            self.assertFalse(result["verified"])
            self.assertEqual(result["findings"], [])

    async def test_invalid_target_and_policy_fail_closed(self):
        for parameters in (
            {"target": "file:///etc/passwd"},
            {"target": "http://example.test/path"},
            {"target": "http://example.test/?q=x"},
            {"target": "http://example.test/", "mode": "arbitrary"},
            {"target": "http://example.test/", "proofLevel": LAB_PROOF, "engagement": "standard"},
            {"target": "http://example.test/", "discoverFromTarget": False},
        ):
            result = await self.tool.execute(parameters)
            self.assertFalse(result["success"])
            self.assertFalse(result["verified"])
            self.assertFalse(result["fallback"])


if __name__ == "__main__":
    unittest.main()
