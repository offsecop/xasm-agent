import base64
import hashlib
import json
import re
import unittest

from aiohttp import WSMsgType, web

from tools.web_websocket_probe import (
    CANONICAL_MESSAGE,
    LAB_PROOF,
    MODE,
    RUNTIME_PROOF,
    RUNTIME_LABELS,
    LAB_LABELS,
    XSS_PAYLOAD,
    WebWebSocketProbeTool,
    _encode_client_frame,
    decode_client_text_frame,
)


BOOTSTRAP_COOKIE = "session=fixture-bootstrap-secret"


class _Server:
    def __init__(self, app):
        self.app = app
        self.runner = None

    async def __aenter__(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}/"

    async def __aexit__(self, exc_type, exc, tb):
        await self.runner.cleanup()


def _fixture(
    *,
    websocket_source=True,
    external_script=False,
    cross_origin=False,
    accept_random_upgrade=False,
    set_cookie=True,
    send_ping=False,
):
    state = {
        "solved": False,
        "textFrames": [],
        "cookies": [],
        "origins": [],
        "paths": [],
    }
    app = web.Application()

    def with_cookie(response):
        if set_cookie:
            response.headers["Set-Cookie"] = BOOTSTRAP_COOKIE + "; Path=/; HttpOnly"
        return response

    async def root(request):
        state["paths"].append(request.path)
        marker = "is-solved" if state["solved"] else "is-notsolved"
        label = "Solved" if state["solved"] else "Not solved"
        return with_cookie(
            web.Response(
                text=(
                    f"<html><body class='{marker}'><a href='/chat'>Live chat</a>"
                    f"<p>{label}</p></body></html>"
                ),
                content_type="text/html",
            )
        )

    async def chat(request):
        state["paths"].append(request.path)
        ws = web.WebSocketResponse(autoping=False, compress=False)
        ready = ws.can_prepare(request)
        if not ready.ok:
            if external_script:
                script = "<script src='/static/chat-client.js'></script>"
            elif not websocket_source:
                script = "<script>window.chatReady=true</script>"
            elif cross_origin:
                script = "<script>new WebSocket('ws://evil.invalid/chat')</script>"
            else:
                script = (
                    "<script>var socket=new WebSocket('ws://' + window.location.host + '/chat');"
                    "socket.send(JSON.stringify({message:document.querySelector('input').value}));"
                    "</script>"
                )
            return web.Response(text=f"<html><body>{script}</body></html>")

        state["cookies"].append(request.headers.get("Cookie"))
        state["origins"].append(request.headers.get("Origin"))
        await ws.prepare(request)
        if send_ping:
            await ws.ping(b"bounded-ping")
        async for message in ws:
            if message.type == WSMsgType.TEXT:
                state["textFrames"].append(message.data)
                parsed = json.loads(message.data)
                await ws.send_str(
                    json.dumps({"user": "You", "content": parsed.get("message", "")})
                )
                if message.data == CANONICAL_MESSAGE:
                    state["solved"] = True
            elif message.type == WSMsgType.PING:
                await ws.pong(message.data)
            elif message.type in {WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.ERROR}:
                break
        return ws

    async def script(request):
        state["paths"].append(request.path)
        return web.Response(
            text=(
                "const socket=new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') "
                "+ location.host + '/chat');"
                "socket.send(JSON.stringify({message:document.querySelector('input').value}));"
            ),
            content_type="application/javascript",
        )

    async def fallback(request):
        state["paths"].append(request.path)
        if accept_random_upgrade and request.headers.get("Upgrade", "").lower() == "websocket":
            ws = web.WebSocketResponse(autoping=False, compress=False)
            await ws.prepare(request)
            await ws.close()
            return ws
        return web.Response(status=404, text="not found")

    app.router.add_get("/", root)
    app.router.add_get("/chat", chat)
    app.router.add_get("/static/chat-client.js", script)
    app.router.add_route("*", "/{tail:.*}", fallback)
    return app, state


def _lab_args(target):
    return {
        "target": target,
        "mode": MODE,
        "proofLevel": LAB_PROOF,
        "engagement": "lab",
        "clientTextFrameBudget": 1,
        "handshakeBudget": 3,
        "allowActiveWebSocketFrames": True,
        "stateChangeApproved": True,
        "labVictimInteractionApproved": True,
    }


class WebWebSocketProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tool = WebWebSocketProbeTool()

    def test_schema_is_closed_and_only_target_is_model_controlled(self):
        schema = self.tool.schema
        self.assertEqual(self.tool.name, "web:websocket_probe")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["required"], ["target"])
        self.assertEqual(schema["properties"]["mode"]["enum"], [MODE])
        self.assertEqual(
            schema["properties"]["proofLevel"]["enum"],
            [RUNTIME_PROOF, LAB_PROOF],
        )
        self.assertEqual(schema["properties"]["handshakeBudget"]["maximum"], 3)
        self.assertEqual(schema["properties"]["clientTextFrameBudget"]["maximum"], 1)
        self.assertEqual(schema["properties"]["maxFrameBytes"]["default"], 4096)
        for name, definition in schema["properties"].items():
            if name != "target":
                self.assertTrue(definition.get("x-workflow-owned"), name)
        for forbidden in (
            "path",
            "wsPath",
            "websocketUrl",
            "origin",
            "payload",
            "frame",
            "message",
            "headers",
            "cookie",
            "credentials",
            "rawRequest",
        ):
            self.assertNotIn(forbidden, schema["properties"])

    async def test_runtime_discovers_and_validates_but_sends_zero_application_frames(self):
        app, state = _fixture()
        async with _Server(app) as target:
            result = await self.tool.execute(
                {
                    "target": target,
                    "handshakeBudget": 3,
                    "clientTextFrameBudget": 0,
                }
            )
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])
        self.assertFalse(result["fallback"])
        self.assertEqual(result["proofLevel"], RUNTIME_PROOF)
        self.assertEqual(result["findings"], [])
        self.assertEqual(state["textFrames"], [])
        verification = result["verification"]
        self.assertEqual(verification["clientTextFrameCount"], 0)
        self.assertEqual(verification["stateChangingMethods"], [])
        self.assertTrue(verification["handshakeValidated"])
        self.assertTrue(verification["secWebSocketAcceptValidated"])
        self.assertTrue(verification["negativeUpgradeRejected"])
        self.assertTrue(verification["dnsResolvedOnce"])
        self.assertTrue(verification["freshConnectionPerHandshake"])
        self.assertFalse(verification["redirectsFollowed"])
        self.assertEqual(
            [step["label"] for step in verification["websocketEvidence"]["steps"]],
            list(RUNTIME_LABELS),
        )

    async def test_bootstrap_cookie_is_used_with_matching_markers_and_never_serialized(self):
        app, state = _fixture()
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target, "clientTextFrameBudget": 0})
        self.assertEqual(result["sessionSource"], "target-bootstrap-cookie")
        self.assertEqual(result["verification"]["sessionSource"], "target-bootstrap-cookie")
        expected_digest = hashlib.sha256(BOOTSTRAP_COOKIE.encode()).hexdigest()
        self.assertEqual(result["verification"]["authContextSha256"], expected_digest)
        serialized = json.dumps(result)
        self.assertNotIn("fixture-bootstrap-secret", serialized)
        steps = result["verification"]["websocketEvidence"]["steps"]
        marker = f"[REDACTED sha256={expected_digest} len={len(BOOTSTRAP_COOKIE)}]"
        self.assertIn("Set-Cookie: " + marker, steps[0]["response"])
        self.assertIn("Cookie: " + marker, steps[2]["request"])
        self.assertIn("Cookie: " + marker, steps[3]["request"])
        self.assertRegex(
            steps[0]["response"],
            re.escape("Set-Cookie: " + marker) + r"\r\n\r\n",
        )
        for step in steps:
            self.assertIn("\r\n\r\n", step["request"], step["label"])
            self.assertIn("\r\n\r\n", step["response"], step["label"])
        self.assertRegex(
            steps[1]["request"],
            re.escape("Cookie: " + marker) + r"\r\n\r\n$",
        )
        self.assertRegex(
            steps[2]["request"],
            re.escape("Cookie: " + marker) + r"\r\n(?:[^\r\n]+\r\n)*\r\n$",
        )
        self.assertTrue(all(cookie == BOOTSTRAP_COOKIE for cookie in state["cookies"]))

    async def test_lab_sends_exactly_one_masked_text_frame_and_proves_solved(self):
        app, state = _fixture(send_ping=True)
        async with _Server(app) as target:
            result = await self.tool.execute(_lab_args(target))
        self.assertTrue(result["success"])
        self.assertTrue(result["verified"])
        self.assertFalse(result["fallback"])
        self.assertEqual(state["textFrames"], [CANONICAL_MESSAGE])
        verification = result["verification"]
        self.assertEqual(verification["clientTextFrameCount"], 1)
        self.assertEqual(verification["stateChangingFrameCount"], 1)
        self.assertEqual(verification["stateChangingMethods"], ["WS_TEXT"])
        self.assertTrue(verification["clientFramesMasked"])
        self.assertTrue(verification["payloadEchoedUnescaped"])
        self.assertTrue(verification["labSolvedTransition"])
        self.assertEqual(
            [step["label"] for step in verification["websocketEvidence"]["steps"]],
            [*RUNTIME_LABELS, *LAB_LABELS],
        )
        proof = verification["websocketEvidence"]["steps"][4]
        client_frame = base64.b64decode(proof["clientFrameBase64"], validate=True)
        self.assertEqual(decode_client_text_frame(client_frame), CANONICAL_MESSAGE)
        self.assertEqual(proof["clientFrameLength"], len(client_frame))
        self.assertEqual(proof["clientFrameSha256"], hashlib.sha256(client_frame).hexdigest())
        server_frame = base64.b64decode(proof["serverFrameBase64"], validate=True)
        self.assertTrue(server_frame)
        self.assertEqual(server_frame[0], 0x81)
        self.assertEqual(server_frame[1] & 0x80, 0)
        self.assertEqual(proof["serverFrameLength"], len(server_frame))
        self.assertEqual(proof["serverFrameSha256"], hashlib.sha256(server_frame).hexdigest())
        self.assertIn(">>> WS_TEXT\r\n" + CANONICAL_MESSAGE, proof["request"])
        self.assertIn("<<< WS_TEXT\r\n", proof["response"])
        self.assertIn(XSS_PAYLOAD, proof["response"])
        self.assertEqual(proof["decodedServerText"], proof["serverText"])
        self.assertEqual(result["total_findings"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["info"]["severity"], "high")
        self.assertEqual(finding["info"]["classification"]["cwe-id"], ["CWE-79"])
        self.assertEqual(finding["request"], proof["request"])
        self.assertEqual(finding["response"], proof["response"])

    async def test_lab_requires_every_server_owned_gate_and_exact_frame_budget(self):
        target = "https://example.test/"
        for omitted in (
            "allowActiveWebSocketFrames",
            "stateChangeApproved",
            "labVictimInteractionApproved",
        ):
            args = _lab_args(target)
            args.pop(omitted)
            result = await self.tool.execute(args)
            self.assertFalse(result["success"], omitted)
        runtime_with_frame = await self.tool.execute(
            {"target": target, "clientTextFrameBudget": 1}
        )
        self.assertFalse(runtime_with_frame["success"])
        lab_without_frame = _lab_args(target)
        lab_without_frame["clientTextFrameBudget"] = 0
        self.assertFalse((await self.tool.execute(lab_without_frame))["success"])

    async def test_does_not_fallback_to_chat_without_observed_websocket_source(self):
        app, state = _fixture(websocket_source=False)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])
        self.assertIn("no observed", result["verification"]["reason"])
        self.assertEqual(state["textFrames"], [])
        self.assertEqual(result["requestCount"], 2)

    async def test_rejects_cross_origin_websocket_candidate(self):
        app, state = _fixture(cross_origin=True)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])
        self.assertEqual(state["textFrames"], [])
        self.assertEqual(result["requestCount"], 2)

    async def test_random_upgrade_catch_all_fails_closed_before_valid_handshake(self):
        app, state = _fixture(accept_random_upgrade=True)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])
        self.assertIn("random WebSocket upgrade", result["verification"]["reason"])
        self.assertEqual(state["textFrames"], [])
        self.assertEqual(
            [step["label"] for step in result["verification"]["websocketEvidence"]["steps"]],
            list(RUNTIME_LABELS[:3]),
        )

    async def test_external_script_discovery_retains_linked_client_page_transcript(self):
        app, _state = _fixture(external_script=True)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        step = result["verification"]["websocketEvidence"]["steps"][1]
        self.assertTrue(step["clientPageUrl"].endswith("/chat"))
        self.assertTrue(step["discoverySourceUrl"].endswith("/static/chat-client.js"))
        self.assertIn("/static/chat-client.js", step["clientPageEvidence"]["response"])
        self.assertIn("new WebSocket", step["response"])

    async def test_workflow_auth_context_remains_server_owned(self):
        app, _state = _fixture(set_cookie=False)
        async with _Server(app) as target:
            result = await self.tool.execute(
                {
                    "target": target,
                    "authCookies": "session=workflow-secret",
                    "authHeaders": {"Authorization": "Bearer workflow-token"},
                }
            )
        self.assertEqual(result["sessionSource"], "workflow-auth-context")
        expected = hashlib.sha256(
            b"cookie:session=workflow-secret\nauthorization:Bearer workflow-token"
        ).hexdigest()
        self.assertEqual(result["verification"]["authContextSha256"], expected)
        serialized = json.dumps(result)
        self.assertNotIn("workflow-secret", serialized)
        self.assertNotIn("workflow-token", serialized)

    async def test_rejects_non_root_query_credentials_and_fragment(self):
        for target in (
            "https://example.test/chat",
            "https://example.test/?x=1",
            "https://user:pass@example.test/",
            "https://example.test/#fragment",
        ):
            result = await self.tool.execute({"target": target})
            self.assertFalse(result["success"], target)

    def test_client_frame_decoder_rejects_unmasked_and_trailing_bytes(self):
        payload = CANONICAL_MESSAGE.encode()
        unmasked = bytes((0x81, len(payload))) + payload
        with self.assertRaises(ValueError):
            decode_client_text_frame(unmasked)
        valid = _encode_client_frame(0x1, payload, mask=b"abcd")
        self.assertEqual(decode_client_text_frame(valid), CANONICAL_MESSAGE)
        with self.assertRaises(ValueError):
            decode_client_text_frame(valid + b"trailing")


if __name__ == "__main__":
    unittest.main()
