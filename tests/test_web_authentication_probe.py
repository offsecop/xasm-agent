import re

import pytest
from aiohttp import web

from tools.web_authentication_probe import (
    AuthenticationProbeTool,
    REDACTED_RUNTIME_SECRET,
    build_http_evidence_step,
    extract_form_token,
    sanitize_evidence_text,
    validate_probe_parameters,
)


def _parameters(**overrides):
    params = {
        "target": "https://lab.test/",
        "mode": "mfa-simple-bypass",
        "loginPath": "/login",
        "protectedPath": "/my-account?id=carlos",
        "mfaPath": "/login2",
        "usernameField": "username",
        "passwordField": "password",
        "csrfField": "csrf",
        "username": "carlos",
        "password": "approved-password",
        "accountMarker": "Your username is: carlos",
        "engagement": "lab",
        "allowUnsafeMethods": True,
        "timeoutSeconds": 10,
    }
    params.update(overrides)
    return params


def test_registration_and_schema_expose_only_the_bounded_mfa_mode():
    tool = AuthenticationProbeTool()

    assert tool.name == "web:authentication_probe"
    assert tool.metadata["category"] == "auth"
    assert tool.schema["properties"]["mode"]["enum"] == ["mfa-simple-bypass"]
    assert tool.schema["properties"]["password"]["x-hidden"] is True
    assert "mfaCode" not in tool.schema["properties"]
    assert "wordlist" not in tool.schema["properties"]


def test_validation_requires_explicit_lab_authorization_and_complete_contract():
    assert validate_probe_parameters(_parameters()) == (True, "")
    assert validate_probe_parameters(_parameters(engagement="standard"))[0] is False
    assert validate_probe_parameters(_parameters(allowUnsafeMethods=False))[0] is False
    assert validate_probe_parameters(_parameters(password=""))[0] is False
    assert validate_probe_parameters(_parameters(accountMarker="x"))[0] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("loginPath", "https://evil.test/login"),
        ("protectedPath", "//evil.test/account"),
        ("mfaPath", "/login2#skip"),
        ("usernameField", "user\r\nX-Test"),
        ("csrfField", "csrf field"),
    ],
)
def test_validation_rejects_path_escape_and_invalid_field_names(field, value):
    assert validate_probe_parameters(_parameters(**{field: value}))[0] is False


def test_csrf_extraction_matches_the_named_input_only():
    body = (
        '<input type="hidden" name="other" value="wrong">'
        '<input value="csrf-live-123" type="hidden" name="csrf">'
    )

    assert extract_form_token(body, "csrf") == "csrf-live-123"
    assert extract_form_token(body, "missing") is None


def test_sanitizer_redacts_headers_form_values_html_tokens_and_exact_secrets():
    raw = (
        "Cookie: session=live-session\n"
        "Set-Cookie: session=new-session\n\n"
        "username=carlos&password=approved-password&csrf=csrf-live-123\n"
        '<input name="csrf" value="csrf-live-123">'
    )
    safe = sanitize_evidence_text(raw, ("approved-password", "csrf-live-123", "live-session"))

    assert "approved-password" not in safe
    assert "csrf-live-123" not in safe
    assert "live-session" not in safe
    assert "new-session" not in safe
    assert safe.count(REDACTED_RUNTIME_SECRET) >= 4


def test_http_evidence_hashes_the_sanitized_transcripts():
    class Headers:
        def getall(self, name, default):
            return {
                "Content-Type": ["text/html"],
                "Location": ["/login2"],
                "Set-Cookie": ["session=live-session"],
            }.get(name, default)

    step = build_http_evidence_step(
        "first-factor",
        "POST",
        "https://lab.test/login",
        "username=carlos&password=approved-password&csrf=csrf-live-123",
        "session=live-session",
        {
            "status": 302,
            "reason": "Found",
            "headers": Headers(),
            "body": "",
            "truncated": False,
        },
        ("approved-password", "csrf-live-123", "live-session"),
    )

    assert step["label"] == "first-factor"
    assert step["responseStatus"] == 302
    assert re.fullmatch(r"[0-9a-f]{64}", step["requestSha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", step["responseSha256"])
    assert "approved-password" not in str(step)
    assert "live-session" not in str(step)
    assert "\r\n\r\nusername=carlos" in step["request"]
    assert f"Cookie: {REDACTED_RUNTIME_SECRET}\r\n" in step["request"]
    assert f"Set-Cookie: {REDACTED_RUNTIME_SECRET}\r\n\r\n" in step["response"]


@pytest.mark.asyncio
async def test_execute_proves_mfa_bypass_in_exactly_three_requests_with_redacted_evidence():
    calls = []

    async def login(request):
        calls.append((request.method, request.path_qs))
        if request.method == "GET":
            response = web.Response(
                text='<form><input type="hidden" name="csrf" value="csrf-live-123"></form>',
                content_type="text/html",
            )
            response.set_cookie("session", "pre-auth-session", httponly=True)
            return response

        form = await request.post()
        assert form["username"] == "carlos"
        assert form["password"] == "approved-password"
        assert form["csrf"] == "csrf-live-123"
        response = web.Response(status=302, headers={"Location": "/login2"})
        response.set_cookie("session", "password-stage-session", httponly=True)
        return response

    async def account(request):
        calls.append((request.method, request.path_qs))
        if request.cookies.get("session") != "password-stage-session":
            return web.Response(status=401, text="login required")
        return web.Response(text="<h1>Your username is: carlos</h1>", content_type="text/html")

    app = web.Application()
    app.router.add_route("*", "/login", login)
    app.router.add_get("/my-account", account)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    try:
        output = await AuthenticationProbeTool().execute(
            _parameters(target=f"http://127.0.0.1:{port}/")
        )
    finally:
        await runner.cleanup()

    assert output["success"] is True
    assert output["fallback"] is False
    assert output["verification"]["verified"] is True
    assert output["verification"]["requestCount"] == 3
    assert output["verification"]["mfaSubmitted"] is False
    assert [step["label"] for step in output["verification"]["httpEvidence"]["steps"]] == [
        "login-page",
        "first-factor",
        "protected-resource-bypass",
    ]
    assert calls == [
        ("GET", "/login"),
        ("POST", "/login"),
        ("GET", "/my-account?id=carlos"),
    ]
    assert "/login2" not in [path for _, path in calls]
    assert output["findings"][0]["info"]["classification"]["cwe-id"] == ["CWE-287"]
    evidence = str(output["verification"]["httpEvidence"])
    for secret in (
        "approved-password",
        "csrf-live-123",
        "pre-auth-session",
        "password-stage-session",
    ):
        assert secret not in evidence


@pytest.mark.asyncio
async def test_execute_fails_closed_when_protected_marker_is_absent():
    async def login(request):
        if request.method == "GET":
            return web.Response(text='<input name="csrf" value="csrf-live-123">')
        return web.Response(status=302, headers={"Location": "/login2"})

    async def account(_request):
        return web.Response(text="MFA required")

    app = web.Application()
    app.router.add_route("*", "/login", login)
    app.router.add_get("/my-account", account)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    try:
        output = await AuthenticationProbeTool().execute(
            _parameters(target=f"http://127.0.0.1:{port}/")
        )
    finally:
        await runner.cleanup()

    assert output["success"] is False
    assert output["fallback"] is False
    assert output["requestCount"] == 3
    assert output["findings"] == []
    assert "account marker" in output["error"]
