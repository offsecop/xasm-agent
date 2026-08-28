import re

import pytest
from aiohttp import web

from tools.web_access_control_probe import (
    AccessControlProbeTool,
    REDACTED_RUNTIME_SECRET,
    build_http_evidence_step,
    extract_secret_after_marker,
    validate_probe_parameters,
)


def _parameters(**overrides):
    params = {
        "target": "https://lab.test/",
        "mode": "idor-redirect-leak",
        "loginPath": "/login",
        "ownPath": "/my-account?id=wiener",
        "foreignPath": "/my-account?id=carlos",
        "denialPath": "/login",
        "solutionPath": "/submitSolution",
        "usernameField": "username",
        "passwordField": "password",
        "csrfField": "csrf",
        "solutionField": "answer",
        "username": "wiener",
        "password": "approved-password",
        "ownMarker": "Your username is: wiener",
        "foreignMarker": "Your username is: carlos",
        "secretLabel": "Your API Key is:",
        "solutionSuccessMarker": '"correct":true',
        "engagement": "lab",
        "allowUnsafeMethods": True,
        "timeoutSeconds": 10,
    }
    params.update(overrides)
    return params


def test_registration_and_schema_expose_only_the_bounded_redirect_leak_mode():
    tool = AccessControlProbeTool()

    assert tool.name == "web:access_control_probe"
    assert tool.metadata["category"] == "auth"
    assert tool.schema["properties"]["mode"]["enum"] == ["idor-redirect-leak"]
    assert tool.schema["properties"]["password"]["x-hidden"] is True
    assert "wordlist" not in tool.schema["properties"]
    assert "maxIds" not in tool.schema["properties"]


def test_validation_requires_explicit_authorization_and_distinct_markers():
    assert validate_probe_parameters(_parameters()) == (True, "")
    assert validate_probe_parameters(_parameters(engagement="standard"))[0] is False
    assert validate_probe_parameters(_parameters(allowUnsafeMethods=False))[0] is False
    assert validate_probe_parameters(_parameters(password=""))[0] is False
    assert validate_probe_parameters(_parameters(ownMarker="same", foreignMarker="same"))[0] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("loginPath", "https://evil.test/login"),
        ("foreignPath", "//evil.test/account"),
        ("solutionPath", "/submit#skip"),
        ("solutionField", "answer\r\nX-Test"),
        ("csrfField", "csrf field"),
    ],
)
def test_validation_rejects_path_escape_and_invalid_field_names(field, value):
    assert validate_probe_parameters(_parameters(**{field: value}))[0] is False


def test_secret_extraction_is_literal_bounded_and_html_aware():
    body = "<p>Your API Key is: </p><strong>foreign-key-123456</strong>"

    assert extract_secret_after_marker(body, "Your API Key is:") == "foreign-key-123456"
    assert extract_secret_after_marker(body, "Missing marker:") is None
    assert extract_secret_after_marker("Your API Key is: short", "Your API Key is:") is None


def test_http_evidence_redacts_cookie_and_leaked_value_before_hashing():
    class Headers:
        def getall(self, name, default):
            return {
                "Content-Type": ["text/html"],
                "Location": ["/login"],
                "Set-Cookie": ["session=live-session"],
            }.get(name, default)

    step = build_http_evidence_step(
        "foreign-object-redirect-leak",
        "GET",
        "https://lab.test/my-account?id=carlos",
        "",
        "session=live-session",
        {
            "status": 302,
            "reason": "Found",
            "headers": Headers(),
            "body": "Your username is: carlos; Your API Key is: foreign-key-123456",
            "truncated": False,
        },
        ("live-session", "foreign-key-123456"),
    )

    assert re.fullmatch(r"[0-9a-f]{64}", step["requestSha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", step["responseSha256"])
    assert "foreign-key-123456" not in str(step)
    assert "live-session" not in str(step)
    assert REDACTED_RUNTIME_SECRET in step["response"]


@pytest.mark.asyncio
async def test_execute_proves_redirect_body_idor_in_exactly_five_requests():
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
        assert form["username"] == "wiener"
        assert form["password"] == "approved-password"
        assert form["csrf"] == "csrf-live-123"
        response = web.Response(status=302, headers={"Location": "/my-account?id=wiener"})
        response.set_cookie("session", "authenticated-session", httponly=True)
        return response

    async def account(request):
        calls.append((request.method, request.path_qs))
        if request.cookies.get("session") != "authenticated-session":
            return web.Response(status=401, text="login required")
        if request.query.get("id") == "wiener":
            return web.Response(
                text="Your username is: wiener; Your API Key is: own-key-12345678",
                content_type="text/html",
            )
        return web.Response(
            status=302,
            headers={"Location": "/login"},
            text="Your username is: carlos; Your API Key is: foreign-key-123456",
            content_type="text/html",
        )

    async def submit_solution(request):
        calls.append((request.method, request.path_qs))
        form = await request.post()
        if form.get("answer") == "foreign-key-123456":
            return web.Response(text='{"correct":true}', content_type="application/json")
        return web.Response(text='{"correct":false}', content_type="application/json")

    app = web.Application()
    app.router.add_route("*", "/login", login)
    app.router.add_get("/my-account", account)
    app.router.add_post("/submitSolution", submit_solution)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    try:
        output = await AccessControlProbeTool().execute(
            _parameters(target=f"http://127.0.0.1:{port}/")
        )
    finally:
        await runner.cleanup()

    assert output["success"] is True
    assert output["fallback"] is False
    proof = output["verification"]
    assert proof["verified"] is True
    assert proof["requestCount"] == 5
    assert proof["ownSecretSha256"] != proof["foreignSecretSha256"]
    assert proof["foreignSecretSha256"] == proof["submittedValueSha256"]
    assert [step["label"] for step in proof["httpEvidence"]["steps"]] == [
        "login-page",
        "low-priv-login",
        "own-object-baseline",
        "foreign-object-redirect-leak",
        "solution-submit",
    ]
    assert calls == [
        ("GET", "/login"),
        ("POST", "/login"),
        ("GET", "/my-account?id=wiener"),
        ("GET", "/my-account?id=carlos"),
        ("POST", "/submitSolution"),
    ]
    assert output["findings"][0]["info"]["classification"]["cwe-id"] == [
        "CWE-639",
        "CWE-862",
    ]
    evidence = str(proof["httpEvidence"])
    for secret in (
        "approved-password",
        "csrf-live-123",
        "pre-auth-session",
        "authenticated-session",
        "own-key-12345678",
        "foreign-key-123456",
    ):
        assert secret not in evidence


@pytest.mark.asyncio
async def test_execute_fails_closed_when_foreign_response_lacks_marker():
    async def login(request):
        if request.method == "GET":
            return web.Response(text='<input name="csrf" value="csrf-live-123">')
        return web.Response(status=302, headers={"Location": "/my-account?id=wiener"})

    async def account(request):
        if request.query.get("id") == "wiener":
            return web.Response(text="Your username is: wiener; Your API Key is: own-key-12345678")
        return web.Response(
            status=302,
            headers={"Location": "/login"},
            text="access denied",
        )

    app = web.Application()
    app.router.add_route("*", "/login", login)
    app.router.add_get("/my-account", account)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    try:
        output = await AccessControlProbeTool().execute(
            _parameters(target=f"http://127.0.0.1:{port}/")
        )
    finally:
        await runner.cleanup()

    assert output["success"] is False
    assert output["fallback"] is False
    assert output["requestCount"] == 4
    assert output["findings"] == []
    assert "redirect-body leak" in output["error"]
