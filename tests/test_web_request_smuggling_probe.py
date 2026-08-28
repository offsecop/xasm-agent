import asyncio
import re

import pytest

from tools.web_request_smuggling_probe import (
    RequestSmugglingProbeTool,
    build_cl_te_attack,
    build_http_evidence_step,
    build_nuclei_finding,
    build_te_cl_attack,
    read_http_response,
    response_declares_connection_close,
    sanitize_evidence_text,
    validate_probe_parameters,
    verify_gpost_signal,
)


def _parameters(**overrides):
    params = {
        "target": "https://lab.test/",
        "variant": "cl-te",
        "engagement": "lab",
        "allowUnsafeMethods": True,
    }
    params.update(overrides)
    return params


def _response(status, body, headers=None):
    headers = headers or []
    return {
        "status": status,
        "headerText": f"HTTP/1.1 {status} Test"
        + "".join(f"\r\n{name}: {value}" for name, value in headers),
        "headers": headers,
        "body": body,
        "bodyBytes": body.encode(),
    }


def _wire_parts(request):
    head, body = request.split(b"\r\n\r\n", 1)
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        name, value = line.split(b":", 1)
        headers[name.decode().lower()] = value.decode().strip()
    return head, headers, body


def test_registration_and_schema_expose_only_classic_bounded_variants():
    tool = RequestSmugglingProbeTool()

    assert tool.name == "web:request_smuggling_probe"
    assert tool.metadata["category"] == "exploit-test"
    assert tool.schema["properties"]["variant"]["enum"] == ["cl-te", "te-cl"]
    assert "rawRequest" not in tool.schema["properties"]
    assert "smuggledRequest" not in tool.schema["properties"]
    assert "pauseSeconds" not in tool.schema["properties"]


def test_validation_requires_explicit_high_risk_engagement_and_safe_headers():
    assert validate_probe_parameters(_parameters()) == (True, "")
    assert validate_probe_parameters(_parameters(engagement="standard"))[0] is False
    assert validate_probe_parameters(_parameters(allowUnsafeMethods=False))[0] is False
    assert validate_probe_parameters(_parameters(variant="h2-cl"))[0] is False
    assert validate_probe_parameters(_parameters(target="https://user:pass@lab.test/"))[0] is False
    assert validate_probe_parameters(_parameters(headers={"Transfer-Encoding": "chunked"}))[0] is False
    assert validate_probe_parameters(_parameters(headers={"X-Test": "ok\r\nInjected: yes"}))[0] is False


def test_cl_te_builder_preserves_exact_six_byte_body():
    request = build_cl_te_attack("/search?q=x", "lab.test")
    _head, headers, body = _wire_parts(request)

    assert request.startswith(b"POST /search?q=x HTTP/1.1\r\n")
    assert headers["content-length"] == "6"
    assert headers["transfer-encoding"] == "chunked"
    assert body == b"0\r\n\r\nG"
    assert int(headers["content-length"]) == len(body)


def test_te_cl_builder_computes_chunk_and_outer_content_lengths_from_bytes():
    request = build_te_cl_attack("/", "lab.test")
    _head, headers, body = _wire_parts(request)
    size_line, chunk_and_terminator = body.split(b"\r\n", 1)
    chunk_size = int(size_line, 16)
    smuggled = chunk_and_terminator[:chunk_size]

    assert headers["content-length"] == str(len(size_line) + 2)
    assert headers["transfer-encoding"] == "chunked"
    assert smuggled.startswith(b"GPOST / HTTP/1.1\r\nHost: lab.test\r\n")
    assert chunk_and_terminator[chunk_size:] == b"\r\n0\r\n\r\n"


@pytest.mark.asyncio
async def test_response_reader_preserves_status_headers_and_body():
    reader = asyncio.StreamReader()
    reader.feed_data(
        b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 25\r\n\r\n"
        b"Unrecognized method GPOST"
    )
    reader.feed_eof()

    response = await read_http_response(reader, 3)

    assert response["status"] == 403
    assert response["body"] == "Unrecognized method GPOST"
    assert ("Content-Type", "text/plain") in response["headers"]


def test_gpost_proof_requires_clean_baseline_and_follow_up_parser_error():
    baseline = _response(200, "home")
    attack = _response(200, "home")
    follow_up = _response(403, "Unrecognized method GPOST")

    proof = verify_gpost_signal(baseline, attack, follow_up)

    assert proof == {
        "verified": True,
        "baselineStatus": 200,
        "attackStatus": 200,
        "followUpStatus": 403,
        "marker": "GPOST",
        "markerAbsentFromBaseline": True,
        "markerObservedInAttack": False,
        "proofSignal": "gpost-parser-error",
    }
    assert verify_gpost_signal(_response(200, "GPOST"), attack, follow_up)["verified"] is False
    assert verify_gpost_signal(baseline, attack, _response(403, "generic forbidden"))["verified"] is False
    assert verify_gpost_signal(_response(500, "error"), attack, follow_up)["verified"] is False


def test_connection_close_detection_uses_explicit_connection_token_only():
    assert response_declares_connection_close(
        _response(200, "home", [("Connection", "keep-alive, close")])
    )
    assert not response_declares_connection_close(
        _response(200, "home", [("Connection", "keep-alive")])
    )


def test_http_evidence_redacts_request_and_response_secrets():
    request = (
        b"POST / HTTP/1.1\r\nHost: lab.test\r\nCookie: session=live-cookie\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    response = _response(
        200,
        '{"session":"live-cookie"}',
        [("Set-Cookie", "session=live-cookie"), ("Content-Type", "application/json")],
    )

    step = build_http_evidence_step("clean-baseline", request, response, ("live-cookie",))

    assert "live-cookie" not in str(step)
    assert f"Cookie: <redacted-runtime-secret>" in step["request"]
    assert f"Set-Cookie: <redacted-runtime-secret>" in step["response"]
    assert len(step["requestSha256"]) == 64
    assert len(step["responseBodySha256"]) == 64
    assert "live-cookie" not in sanitize_evidence_text(str(response), ("live-cookie",))


def test_finding_shape_is_cwe_444_and_keeps_typed_proof():
    verification = {
        "verified": True,
        "variant": "cl-te",
        "proofSignal": "gpost-parser-error",
    }
    finding = build_nuclei_finding("https://lab.test/", verification)

    assert finding["template-id"] == "xasm-http-request-smuggling-verified"
    assert finding["info"]["classification"]["cwe-id"] == ["CWE-444"]
    assert finding["evidence"] is verification


@pytest.mark.asyncio
async def test_execute_emits_three_redacted_request_response_steps(monkeypatch):
    connection_count = 0

    async def read_request(reader):
        head = await reader.readuntil(b"\r\n\r\n")
        match = re.search(br"(?im)^Content-Length:\s*(\d+)\s*$", head)
        body = await reader.readexactly(int(match.group(1))) if match else b""
        return head + body

    async def handler(reader, writer):
        nonlocal connection_count
        connection_count += 1
        if connection_count == 1:
            await read_request(reader)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nhome")
            await writer.drain()
            writer.close()
            return

        await read_request(reader)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\nhome")
        await writer.drain()
        await read_request(reader)
        body = b"Unrecognized method GPOST"
        writer.write(
            b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await RequestSmugglingProbeTool().execute(
            _parameters(
                target=f"http://127.0.0.1:{port}/",
                authCookies="session=live-cookie",
            )
        )
    finally:
        server.close()
        await server.wait_closed()

    assert result["success"] is True
    assert result["fallback"] is False
    assert result["verification"]["requestCount"] == 3
    assert result["verification"]["followUpConnection"] == "same-client-connection"
    assert result["verification"]["proofSignal"] == "gpost-parser-error"
    assert [step["label"] for step in result["verification"]["httpEvidence"]["steps"]] == [
        "clean-baseline",
        "smuggling-attack",
        "verification-follow-up",
    ]
    assert "Transfer-Encoding: chunked" in result["verification"]["httpEvidence"]["steps"][1]["request"]
    assert "Unrecognized method GPOST" in result["verification"]["httpEvidence"]["steps"][2]["response"]
    assert "live-cookie" not in str(result)


@pytest.mark.asyncio
async def test_execute_reopens_follow_up_after_explicit_front_end_close():
    connection_count = 0

    async def read_request(reader):
        head = await reader.readuntil(b"\r\n\r\n")
        match = re.search(br"(?im)^Content-Length:\s*(\d+)\s*$", head)
        body = await reader.readexactly(int(match.group(1))) if match else b""
        return head + body

    async def handler(reader, writer):
        nonlocal connection_count
        connection_count += 1
        await read_request(reader)
        if connection_count < 3:
            body = b"home"
            status = b"HTTP/1.1 200 OK"
        else:
            body = b"Unrecognized method GPOST"
            status = b"HTTP/1.1 403 Forbidden"
        writer.write(
            status
            + b"\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await RequestSmugglingProbeTool().execute(
            _parameters(target=f"http://127.0.0.1:{port}/")
        )
    finally:
        server.close()
        await server.wait_closed()

    assert result["success"] is True
    assert result["verification"]["requestCount"] == 3
    assert result["verification"]["followUpConnection"] == (
        "new-client-connection-after-front-end-close"
    )
    assert connection_count == 3
