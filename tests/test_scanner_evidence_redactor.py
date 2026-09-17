from pathlib import Path

import pytest

from agent_core_rest import Agent
from lib.scanner_evidence_redactor import (
    REDACTED_RUNTIME_SECRET,
    redact_agent_result,
    redact_scanner_evidence,
)


def test_structured_and_raw_evidence_redaction_preserves_xss_html():
    xss = "<img/src/onerror=.1|alert`2132`>"
    canaries = [
        "header-canary-2132", "cookie-canary-2132", "query-canary-2132",
        "body-canary-2132", "json-canary-2132", "curl-canary-2132",
    ]
    output = {
        "headers": {"Authorization": "Bearer header-canary-2132", "Content-Type": "text/html"},
        "request_headers": [
            {"name": "Authorization", "value": "Bearer header-canary-2132"},
            {"name": "Accept", "value": "text/html"},
        ],
        "cookies": [
            {"name": "sid", "value": "cookie-canary-2132", "domain": "target.test"},
        ],
        "request": (
            "POST /login?access_token=query-canary-2132 HTTP/1.1\r\n"
            "Cookie: sid=cookie-canary-2132\r\n\r\n"
            f"password=body-canary-2132&q={xss}"
        ),
        "response": f'HTTP/1.1 200 OK\r\n\r\n{{"token":"json-canary-2132","html":"{xss}"}}',
        "curl": "curl -u user:curl-canary-2132 https://target.test/",
        "payload": xss,
    }

    safe = redact_scanner_evidence(output)
    serialized = repr(safe)
    for canary in canaries:
        assert canary not in serialized
    assert REDACTED_RUNTIME_SECRET in serialized
    assert safe["headers"]["Content-Type"] == "text/html"
    assert xss in serialized


def test_redaction_is_idempotent_and_auth_exchange_is_preserved():
    raw = {
        "request": "GET /?token=secret-query&api_key=[REDACTED] HTTP/1.1\nAuthorization: Bearer secret-value",
        "matchedContent": "token=[JWT_REDACTED]; api_key=[REDACTED]",
        "payload": "<svg/onload=alert(1)>",
    }
    first = redact_scanner_evidence(raw)
    assert redact_scanner_evidence(first) == first
    assert first["matchedContent"] == "token=[JWT_REDACTED]; api_key=[REDACTED]"
    assert redact_agent_result("nuclei:dast_scan", raw) == first

    auth_result = {"cookies": "sid=runtime-session"}
    assert redact_agent_result("authentication:ai_browser_login", auth_result) is auth_result


@pytest.mark.asyncio
async def test_auth_result_is_never_written_to_replay_spool():
    job_id = "redaction-canary-2132"
    spool = Path("/tmp/agent_queue") / f"{job_id}.json"
    spool.unlink(missing_ok=True)

    agent = Agent.__new__(Agent)
    await agent.queue_result(
        job_id,
        {"cookies": "sid=runtime-session"},
        tool_name="authentication:ai_browser_login",
    )

    assert not spool.exists()
