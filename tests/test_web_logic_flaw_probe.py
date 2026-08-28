import re

import pytest
from aiohttp import web

from tools.web_authentication_probe import REDACTED_RUNTIME_SECRET
from tools.web_logic_flaw_probe import (
    LogicFlawProbeTool,
    build_http_evidence_step,
    validate_probe_parameters,
)


def _parameters(**overrides):
    params = {
        "target": "https://lab.test/",
        "mode": "workflow-finalizer-skip",
        "proofLevel": "lab-state-change",
        "baselinePath": "/",
        "loginPath": "/login",
        "loginRedirectPath": "/my-account?id=wiener",
        "addPath": "/cart",
        "addRedirectPath": "/product?productId=1",
        "guardedStepPath": "/cart/checkout",
        "finalizerPath": "/cart/order-confirmation?order-confirmed=true",
        "usernameField": "username",
        "passwordField": "password",
        "csrfField": "csrf",
        "productField": "productId",
        "productValue": "1",
        "quantityField": "quantity",
        "quantityValue": "1",
        "redirectField": "redir",
        "redirectValue": "PRODUCT",
        "username": "wiener",
        "password": "approved-password",
        "unsolvedMarker": "Not solved",
        "solvedMarker": "Solved",
        "productMarker": "Configured Target Product",
        "finalResultMarker": "Order confirmation",
        "engagement": "lab",
        "allowUnsafeMethods": True,
        "timeoutSeconds": 10,
    }
    params.update(overrides)
    return params


def test_registration_and_schema_expose_only_the_bounded_finalizer_skip_mode():
    tool = LogicFlawProbeTool()

    assert tool.name == "web:logic_flaw_probe"
    assert tool.metadata["category"] == "exploit-test"
    assert tool.schema["properties"]["mode"]["enum"] == ["workflow-finalizer-skip"]
    assert tool.schema["properties"]["password"]["x-hidden"] is True
    assert "sequence" not in tool.schema["properties"]
    assert "repeatCount" not in tool.schema["properties"]


def test_validation_requires_explicit_authorization_and_distinct_guarded_path():
    assert validate_probe_parameters(_parameters()) == (True, "")
    assert validate_probe_parameters(_parameters(engagement="standard"))[0] is False
    assert validate_probe_parameters(_parameters(allowUnsafeMethods=False))[0] is False
    assert validate_probe_parameters(_parameters(password=""))[0] is False
    assert (
        validate_probe_parameters(
            _parameters(guardedStepPath="/cart/order-confirmation?order-confirmed=true")
        )[0]
        is False
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("loginPath", "https://evil.test/login"),
        ("addPath", "//evil.test/cart"),
        ("finalizerPath", "/confirm#skip"),
        ("productField", "product\r\nX-Test"),
        ("csrfField", "csrf field"),
    ],
)
def test_validation_rejects_path_escape_and_invalid_field_names(field, value):
    assert validate_probe_parameters(_parameters(**{field: value}))[0] is False


def test_validation_keeps_optional_redirect_field_and_value_consistent():
    assert validate_probe_parameters(_parameters(redirectField=None, redirectValue=None))[0] is True
    assert validate_probe_parameters(_parameters(redirectField=None))[0] is False
    assert validate_probe_parameters(_parameters(redirectValue=None))[0] is False


def test_http_evidence_redacts_cookie_password_and_csrf_before_hashing():
    class Headers:
        def getall(self, name, default):
            return {
                "Content-Type": ["text/html"],
                "Location": ["/my-account?id=wiener"],
                "Set-Cookie": ["session=live-session"],
            }.get(name, default)

    step = build_http_evidence_step(
        "approved-login",
        "POST",
        "https://lab.test/login",
        "username=wiener&password=approved-password&csrf=csrf-live-123",
        "session=live-session",
        {
            "status": 302,
            "reason": "Found",
            "headers": Headers(),
            "body": "redirect",
            "truncated": False,
        },
        ("approved-password", "csrf-live-123", "live-session"),
    )

    assert re.fullmatch(r"[0-9a-f]{64}", step["requestSha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", step["responseSha256"])
    assert "approved-password" not in str(step)
    assert "csrf-live-123" not in str(step)
    assert "live-session" not in str(step)
    assert REDACTED_RUNTIME_SECRET in step["request"]


@pytest.mark.asyncio
async def test_execute_proves_guarded_step_bypass_in_exactly_six_requests():
    calls = []
    carts = {}
    state = {"solved": False}

    async def baseline(request):
        calls.append((request.method, request.path_qs))
        status = "Solved" if state["solved"] else "Not solved"
        return web.Response(
            text=(
                f"<span>{status}</span><p>Configured &quot;Target&quot; Product</p>"
                + ("<p>Order confirmation</p>" if state["solved"] else "")
            ),
            content_type="text/html",
        )

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

    async def cart(request):
        calls.append((request.method, request.path_qs))
        assert request.cookies.get("session") == "authenticated-session"
        form = await request.post()
        assert dict(form) == {
            "productId": "1",
            "quantity": "1",
            "redir": "PRODUCT",
        }
        carts["authenticated-session"] = form["productId"]
        return web.Response(status=302, headers={"Location": "/product?productId=1"})

    async def finalizer(request):
        calls.append((request.method, request.path_qs))
        session = request.cookies.get("session")
        if carts.get(session) != "1":
            return web.Response(status=400, text="missing cart")
        state["solved"] = True
        return web.Response(
            text="<h1>Opaque completed response</h1>",
            content_type="text/html",
        )

    async def guarded_step(_request):
        raise AssertionError("the configured guarded step must never be requested")

    app = web.Application()
    app.router.add_get("/", baseline)
    app.router.add_route("*", "/login", login)
    app.router.add_post("/cart", cart)
    app.router.add_post("/cart/checkout", guarded_step)
    app.router.add_get("/cart/order-confirmation", finalizer)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    try:
        output = await LogicFlawProbeTool().execute(
            _parameters(
                target=f"http://127.0.0.1:{port}/",
                productMarker='Configured "Target" Product',
            )
        )
    finally:
        await runner.cleanup()

    assert output["success"] is True
    assert output["fallback"] is False
    proof = output["verification"]
    assert proof["verified"] is True
    assert proof["requestCount"] == 6
    assert proof["confirmationStatus"] == 200
    assert proof["productMarkerStep"] == "unsolved-baseline"
    assert proof["finalResultMarkerStep"] == "solved-confirmation"
    assert proof["guardedStepRequested"] is False
    assert proof["solvedBefore"] is False
    assert proof["solvedAfter"] is True
    assert [step["label"] for step in proof["httpEvidence"]["steps"]] == [
        "unsolved-baseline",
        "login-page",
        "approved-login",
        "state-add",
        "guarded-step-bypass-finalizer",
        "solved-confirmation",
    ]
    assert calls == [
        ("GET", "/"),
        ("GET", "/login"),
        ("POST", "/login"),
        ("POST", "/cart"),
        ("GET", "/cart/order-confirmation?order-confirmed=true"),
        ("GET", "/"),
    ]
    assert output["findings"][0]["info"]["classification"]["cwe-id"] == ["CWE-841"]
    evidence = str(proof["httpEvidence"])
    for secret in (
        "approved-password",
        "csrf-live-123",
        "pre-auth-session",
        "authenticated-session",
    ):
        assert secret not in evidence


@pytest.mark.asyncio
async def test_execute_fails_closed_when_post_finalizer_confirmation_lacks_solved_marker():
    async def baseline(_request):
        return web.Response(text="Not solved")

    async def login(request):
        if request.method == "GET":
            return web.Response(text='<input name="csrf" value="csrf-live-123">')
        return web.Response(status=302, headers={"Location": "/my-account?id=wiener"})

    async def cart(_request):
        return web.Response(status=302, headers={"Location": "/product?productId=1"})

    async def finalizer(_request):
        return web.Response(text="Order confirmation Configured Target Product")

    app = web.Application()
    app.router.add_get("/", baseline)
    app.router.add_route("*", "/login", login)
    app.router.add_post("/cart", cart)
    app.router.add_get("/cart/order-confirmation", finalizer)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    try:
        output = await LogicFlawProbeTool().execute(
            _parameters(target=f"http://127.0.0.1:{port}/")
        )
    finally:
        await runner.cleanup()

    assert output["success"] is False
    assert output["fallback"] is False
    assert output["requestCount"] == 6
    assert output["findings"] == []
    assert "solved transition" in output["error"]
