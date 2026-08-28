import hashlib
import html
import re
from urllib.parse import urlencode, urljoin, urlsplit

import aiohttp
import pytest
from aiohttp import web

from tools.web_csrf_probe import (
    CsrfProbeTool,
    LAB_EXPECTED_STEP_LABELS,
    REDACTED_RUNTIME_SECRET,
    RUNTIME_EXPECTED_STEP_LABELS,
    build_delivery_control_selector,
    build_http_evidence_step,
    build_referer_absent_poc,
    build_runtime_source_url,
    canonicalize_form_newlines,
    find_state_form,
    validate_probe_parameters,
)


def test_http_evidence_redacts_every_cookie_carrier_before_output():
    original_cookie = "session=original-secret"
    serialized_cookie = "legacy_profile=serialized-secret"
    step = build_http_evidence_step(
        "approved-login",
        "POST",
        "https://app.test/login",
        "username=user&password=approved-password",
        original_cookie,
        {
            "status": 302,
            "reason": "Found",
            "headers": {
                "Location": "/account",
                "Set-Cookie": [original_cookie, serialized_cookie],
            },
            "body": "",
            "truncated": False,
        },
        ("approved-password",),
    )

    assert step["request"].count(f"Cookie: {REDACTED_RUNTIME_SECRET}") == 1
    assert step["response"].count(f"Set-Cookie: {REDACTED_RUNTIME_SECRET}") == 2
    assert "original-secret" not in str(step)
    assert "serialized-secret" not in str(step)


def _parameters(**overrides):
    params = {
        "target": "https://lab.test/",
        "exploitServer": "https://exploit.test/",
        "mode": "referer-absent-delivery",
        "proofLevel": "lab-state-change",
        "loginPath": "/login",
        "accountPath": "/my-account?id=wiener",
        "actionPath": "/my-account/change-email",
        "exploitStorePath": "/",
        "exploitResourcePath": "/exploit",
        "usernameField": "username",
        "passwordField": "password",
        "loginCsrfField": "csrf",
        "stateField": "email",
        "username": "wiener",
        "password": "approved-password",
        "stateValue": "xasm-csrf-proof@example.net",
        "accountMarker": "Your username is: wiener",
        "unsolvedMarker": "<p>Not solved</p>",
        "solvedMarker": "<p>Solved</p>",
        "exploitHttpsField": "urlIsHttps",
        "exploitFileField": "responseFile",
        "exploitHeadField": "responseHead",
        "exploitBodyField": "responseBody",
        "exploitActionField": "formAction",
        "exploitHttpsValue": "on",
        "exploitStoreValue": "STORE",
        "exploitDeliverValue": "DELIVER_TO_VICTIM",
        "engagement": "lab",
        "allowUnsafeMethods": True,
        "stateChangeApproved": True,
        "timeoutSeconds": 10,
    }
    params.update(overrides)
    return params


def _runtime_parameters(**overrides):
    params = _parameters(
        proofLevel="runtime-browser-state-change",
        engagement="aggressive",
    )
    for key in (
        "exploitServer",
        "exploitStorePath",
        "exploitResourcePath",
        "unsolvedMarker",
        "solvedMarker",
        "exploitHttpsField",
        "exploitFileField",
        "exploitHeadField",
        "exploitBodyField",
        "exploitActionField",
        "exploitHttpsValue",
        "exploitStoreValue",
        "exploitDeliverValue",
    ):
        params.pop(key)
    params.update(overrides)
    return params


def test_registration_and_schema_expose_only_bounded_delivery_mode():
    tool = CsrfProbeTool()

    assert tool.name == "web:csrf_probe"
    assert tool.metadata["category"] == "exploit-test"
    assert tool.schema["additionalProperties"] is False
    assert tool.schema["properties"]["mode"]["enum"] == ["referer-absent-delivery"]
    assert tool.schema["properties"]["proofLevel"]["enum"] == [
        "lab-state-change",
        "runtime-browser-state-change",
    ]
    assert "proofLevel" in tool.schema["required"]
    assert tool.schema["properties"]["password"]["x-hidden"] is True
    assert "exploitBody" not in tool.schema["properties"]
    assert "javascript" not in tool.schema["properties"]
    tier_guard = tool.schema["allOf"][0]
    lab_required = set(tier_guard["then"]["required"])
    runtime_forbidden = {
        tuple(candidate["required"])[0]
        for candidate in tier_guard["else"]["not"]["anyOf"]
    }
    assert tier_guard["if"]["properties"]["proofLevel"]["const"] == "lab-state-change"
    assert lab_required == runtime_forbidden
    assert {"exploitServer", "unsolvedMarker", "solvedMarker"} <= lab_required


@pytest.mark.asyncio
async def test_playwright_response_result_supports_api_response_headers_property():
    class ApiResponseFixture:
        status = 200
        status_text = "OK"
        headers = {"content-type": "text/plain"}

        async def body(self):
            return b"bounded"

    result = await CsrfProbeTool()._playwright_response_result(ApiResponseFixture())

    assert result == {
        "status": 200,
        "reason": "OK",
        "headers": {"content-type": "text/plain"},
        "body": "bounded",
        "truncated": False,
    }


def test_validation_requires_authorization_two_origins_and_unambiguous_markers():
    assert validate_probe_parameters(_parameters()) == (True, "")
    assert validate_probe_parameters(_parameters(engagement="standard"))[0] is False
    assert validate_probe_parameters(_parameters(allowUnsafeMethods=False))[0] is False
    assert validate_probe_parameters(_parameters(password=""))[0] is False
    assert (
        validate_probe_parameters(_parameters(exploitServer="https://lab.test/exploit/"))[0]
        is False
    )


def test_runtime_validation_has_no_exploit_host_or_lab_markers_and_rejects_smuggling():
    assert validate_probe_parameters(_runtime_parameters()) == (True, "")
    for field, value in (
        ("exploitServer", "https://exploit.test/"),
        ("exploitStorePath", "/"),
        ("unsolvedMarker", "Not solved"),
        ("solvedMarker", "Solved"),
    ):
        valid, reason = validate_probe_parameters(_runtime_parameters(**{field: value}))
        assert valid is False
        assert "only allowed" in reason

    assert validate_probe_parameters(_runtime_parameters(stateChangeApproved=False))[0] is False
    missing = _runtime_parameters()
    missing.pop("proofLevel")
    assert validate_probe_parameters(missing)[0] is False
    assert validate_probe_parameters(
        _runtime_parameters(proofLevel="runtime-browser-statechange")
    )[0] is False
    assert (
        validate_probe_parameters(
            _parameters(unsolvedMarker="solved", solvedMarker="already solved")
        )[0]
        is False
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("loginPath", "https://evil.test/login"),
        ("actionPath", "//evil.test/change"),
        ("exploitStorePath", "/store#skip"),
        ("stateField", "csrf_token"),
        ("exploitActionField", "action\r\nX-Test"),
        ("stateValue", '<script>alert(1)</script>'),
    ],
)
def test_validation_rejects_path_field_and_payload_escape(field, value):
    assert validate_probe_parameters(_parameters(**{field: value}))[0] is False


def test_state_form_requires_exact_post_action_state_field_and_no_token():
    page = (
        '<form action="/other" method="post"><input name="email"></form>'
        '<form action="/my-account/change-email" method="POST">'
        '<input type="email" name="email"></form>'
    )
    result = find_state_form(
        page,
        "https://lab.test/my-account?id=wiener",
        "https://lab.test/my-account/change-email",
        "email",
    )

    assert result == {
        "valid": True,
        "action": "https://lab.test/my-account/change-email",
        "method": "POST",
        "fieldNames": ["email"],
        "tokenFields": [],
    }

    token_result = find_state_form(
        '<form action="/my-account/change-email" method="post">'
        '<input name="email"><input name="csrf_token"></form>',
        "https://lab.test/my-account",
        "https://lab.test/my-account/change-email",
        "email",
    )
    assert token_result["valid"] is False
    assert token_result["tokenFields"] == ["csrf_token"]


def test_generated_poc_is_deterministic_single_action_and_suppresses_referer():
    poc = build_referer_absent_poc(
        "https://lab.test/my-account/change-email",
        "email",
        "xasm-csrf-proof@example.net",
    )

    assert '<meta name="referrer" content="no-referrer">' in poc
    assert 'action="https://lab.test/my-account/change-email"' in poc
    assert 'name="email" value="xasm-csrf-proof@example.net"' in poc
    assert "document.forms[0].submit()" in poc
    assert poc.count("<form ") == 1
    assert "wiener" not in poc
    assert "web-security-academy" not in poc


def test_runtime_source_url_preserves_http_or_https_to_avoid_mixed_content():
    assert (
        build_runtime_source_url("http://target.test/")
        == "http://target.test:65534/xasm-csrf-proof"
    )
    assert (
        build_runtime_source_url("https://target.test:65534/")
        == "https://target.test:65533/xasm-csrf-proof"
    )


def test_delivery_selector_accepts_only_button_or_submit_input():
    selector = build_delivery_control_selector("formAction", "DELIVER_TO_VICTIM")

    assert selector == (
        'button[name="formAction"][value="DELIVER_TO_VICTIM"], '
        'input[type="submit"][name="formAction"][value="DELIVER_TO_VICTIM"]'
    )


def test_browser_form_newlines_are_canonicalized_without_changing_poc_hash_input():
    original = "head\r\nline\nbody\rend"

    assert canonicalize_form_newlines(original) == "head\r\nline\r\nbody\r\nend"
    assert original == "head\r\nline\nbody\rend"


class FixtureBrowserCsrfProbe(CsrfProbeTool):
    async def _browser_deliver(self, exploit_url, action_field, deliver_value, timeout):
        timeout_config = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=timeout_config) as session:
            load = await self._request(session, "GET", exploit_url)
            form_body = self.fixture_delivery_body
            delivered = await self._request(session, "POST", exploit_url, form_body)
            location = delivered["headers"].get("Location")
            outcome_url = urljoin(exploit_url, location)
            outcome = await self._request(session, "GET", outcome_url)
        return {
            "browserUsed": True,
            "loadMethod": "GET",
            "loadUrl": exploit_url,
            "loadBody": "",
            "loadResponse": load,
            "deliveryMethod": "POST",
            "deliveryUrl": exploit_url,
            "deliveryBody": form_body,
            "deliveryResponse": delivered,
            "outcomeMethod": "GET",
            "outcomeUrl": outcome_url,
            "outcomeBody": "",
            "outcomeResponse": outcome,
        }


class FixtureRuntimeCsrfProbe(CsrfProbeTool):
    async def _browser_runtime_flow(
        self,
        target,
        urls,
        fields,
        username,
        password,
        state_value,
        account_marker,
        login_csrf_field,
        _poc_body,
        timeout,
    ):
        timeout_config = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(
            timeout=timeout_config,
            cookie_jar=aiohttp.CookieJar(unsafe=True),
        ) as session:
            login_page = await self._request(session, "GET", urls["login"])
            token = "csrf-live-123"
            login_body = urlencode(
                {
                    fields["usernameField"]: username,
                    fields["passwordField"]: password,
                    login_csrf_field: token,
                }
            )
            login_response = await self._request(
                session, "POST", urls["login"], login_body
            )
            account_response = await self._request(session, "GET", urls["account"])
            state_form = find_state_form(
                account_response["body"],
                urls["account"],
                urls["action"],
                fields["stateField"],
            )
            delivery_body = urlencode({fields["stateField"]: state_value})
            delivery_response = await self._request(
                session, "POST", urls["action"], delivery_body
            )
            confirmation = await self._request(session, "GET", urls["account"])
        cookie = "session=authenticated-session"
        source_origin = build_runtime_source_url(target).rsplit("/", 1)[0]
        return {
            "loginPageCookie": "",
            "loginPage": login_page,
            "loginCsrfToken": token,
            "loginBody": login_body,
            "loginCookie": "session=pre-auth-session",
            "loginResponse": login_response,
            "accountCookie": cookie,
            "accountResponse": account_response,
            "stateForm": state_form,
            "deliveryBody": delivery_body,
            "deliveryHeaders": {
                "Origin": source_origin,
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": cookie,
            },
            "deliveryResponse": delivery_response,
            "confirmationCookie": cookie,
            "confirmation": confirmation,
            "auxiliaryRequests": 1,
        }


@pytest.mark.asyncio
async def test_runtime_execute_captures_real_target_post_and_state_confirmation_in_five_steps():
    state = {"value": None, "calls": []}

    async def login(request):
        state["calls"].append((request.method, request.path_qs))
        if request.method == "GET":
            response = web.Response(
                text='<form><input name="csrf" value="csrf-live-123"></form>'
            )
            response.set_cookie("session", "pre-auth-session")
            return response
        form = await request.post()
        assert form["username"] == "wiener"
        assert form["password"] == "approved-password"
        assert form["csrf"] == "csrf-live-123"
        response = web.Response(status=302, headers={"Location": "/landing"})
        response.set_cookie("session", "authenticated-session")
        return response

    async def account(request):
        state["calls"].append((request.method, request.path_qs))
        assert request.cookies.get("session") == "authenticated-session"
        changed = f"<p>{state['value']}</p>" if state["value"] else ""
        return web.Response(
            text=(
                "<h1>Your username is: wiener</h1>"
                '<form action="/my-account/change-email" method="POST">'
                '<input name="email"></form>'
                + changed
            )
        )

    async def action(request):
        state["calls"].append((request.method, request.path_qs))
        assert request.cookies.get("session") == "authenticated-session"
        state["value"] = (await request.post())["email"]
        return web.Response(status=302, headers={"Location": "/my-account?id=wiener"})

    app = web.Application()
    app.router.add_route("*", "/login", login)
    app.router.add_get("/my-account", account)
    app.router.add_post("/my-account/change-email", action)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    target = f"http://127.0.0.1:{port}/"

    try:
        output = await FixtureRuntimeCsrfProbe().execute(
            _runtime_parameters(target=target)
        )
    finally:
        await runner.cleanup()

    assert output["success"] is True
    assert output["requestCount"] == 5
    proof = output["verification"]
    assert proof["proofLevel"] == "runtime-browser-state-change"
    assert proof["stateChanged"] is True
    assert proof["stateValueAbsentBefore"] is True
    assert proof["stateValuePresentAfter"] is True
    assert [step["label"] for step in proof["httpEvidence"]["steps"]] == list(
        RUNTIME_EXPECTED_STEP_LABELS
    )
    assert "exploitServer" not in proof
    assert "unsolvedMarker" not in proof
    assert "solvedAfter" not in proof
    browser_request = proof["httpEvidence"]["steps"][3]["request"]
    assert "Origin: http://127.0.0.1:65534" in browser_request
    assert "Referer:" not in browser_request
    assert "Cookie: <redacted-runtime-secret>" in browser_request
    assert state["calls"] == [
        ("GET", "/login"),
        ("POST", "/login"),
        ("GET", "/my-account?id=wiener"),
        ("POST", "/my-account/change-email"),
        ("GET", "/my-account?id=wiener"),
    ]
    evidence = str(proof["httpEvidence"])
    for secret in (
        "approved-password",
        "csrf-live-123",
        "pre-auth-session",
        "authenticated-session",
    ):
        assert secret not in evidence


@pytest.mark.asyncio
async def test_execute_proves_browser_delivered_csrf_in_exactly_nine_transactions():
    state = {"solved": False, "stored": {}, "calls": []}

    async def root(request):
        state["calls"].append(("target", request.method, request.path_qs))
        marker = "<p>Solved</p>" if state["solved"] else "<p>Not solved</p>"
        return web.Response(text=marker, content_type="text/html")

    async def login(request):
        state["calls"].append(("target", request.method, request.path_qs))
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
        state["calls"].append(("target", request.method, request.path_qs))
        if request.cookies.get("session") != "authenticated-session":
            return web.Response(status=401, text="login required")
        return web.Response(
            text=(
                "<h1>Your username is: wiener</h1>"
                '<form action="/my-account/change-email" method="POST">'
                '<input name="email" type="email"></form>'
            ),
            content_type="text/html",
        )

    target_app = web.Application()
    target_app.router.add_get("/", root)
    target_app.router.add_route("*", "/login", login)
    target_app.router.add_get("/my-account", account)
    target_runner = web.AppRunner(target_app)
    await target_runner.setup()
    target_site = web.TCPSite(target_runner, "127.0.0.1", 0)
    await target_site.start()
    target_port = target_site._server.sockets[0].getsockname()[1]
    target_url = f"http://127.0.0.1:{target_port}/"

    def exploit_page():
        fields = state["stored"]
        controls = "".join(
            f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value)}">'
            for key, value in fields.items()
            if key != "responseBody"
        )
        return (
            '<form method="POST" action="/">'
            + controls
            + f'<textarea name="responseBody">{html.escape(fields.get("responseBody", ""))}</textarea>'
            + '<input type="submit" name="formAction" value="DELIVER_TO_VICTIM">'
            + "</form>"
        )

    async def exploit(request):
        state["calls"].append(("exploit", request.method, request.path_qs))
        if request.method == "GET":
            if request.query.get("message") == "delivered":
                return web.Response(
                    text="<form method='POST'>Exploit server</form>",
                    content_type="text/html",
                )
            return web.Response(text=exploit_page(), content_type="text/html")
        form = {key: value for key, value in (await request.post()).items()}
        if form.get("formAction") == "STORE":
            state["stored"] = form
            return web.Response(text=exploit_page(), content_type="text/html")
        if form.get("formAction") == "DELIVER_TO_VICTIM":
            expected_poc = build_referer_absent_poc(
                f"{target_url}my-account/change-email",
                "email",
                "xasm-csrf-proof@example.net",
            )
            assert form["responseBody"] == canonicalize_form_newlines(expected_poc)
            state["solved"] = True
            return web.Response(status=302, headers={"Location": "/?message=delivered"})
        return web.Response(status=400, text="unknown action")

    exploit_app = web.Application()
    exploit_app.router.add_route("*", "/", exploit)
    exploit_runner = web.AppRunner(exploit_app)
    await exploit_runner.setup()
    exploit_site = web.TCPSite(exploit_runner, "127.0.0.1", 0)
    await exploit_site.start()
    exploit_port = exploit_site._server.sockets[0].getsockname()[1]
    exploit_url = f"http://127.0.0.1:{exploit_port}/"

    tool = FixtureBrowserCsrfProbe()
    expected_poc = build_referer_absent_poc(
        f"{target_url}my-account/change-email",
        "email",
        "xasm-csrf-proof@example.net",
    )
    tool.fixture_delivery_body = urlencode(
        {
            "urlIsHttps": "on",
            "responseFile": "/exploit",
            "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8",
            "responseBody": canonicalize_form_newlines(expected_poc),
            "formAction": "DELIVER_TO_VICTIM",
        }
    )

    try:
        output = await tool.execute(
            _parameters(
                target=target_url,
                exploitServer=exploit_url,
            )
        )
    finally:
        await target_runner.cleanup()
        await exploit_runner.cleanup()

    assert output["success"] is True
    assert output["fallback"] is False
    proof = output["verification"]
    assert proof["verified"] is True
    assert proof["browserDelivery"] is True
    assert proof["solvedBefore"] is False
    assert proof["solvedAfter"] is True
    assert proof["requestCount"] == 9
    assert proof["pocSha256"] == hashlib.sha256(expected_poc.encode()).hexdigest()
    assert [step["label"] for step in proof["httpEvidence"]["steps"]] == list(
        LAB_EXPECTED_STEP_LABELS
    )
    assert state["calls"] == [
        ("target", "GET", "/"),
        ("target", "GET", "/login"),
        ("target", "POST", "/login"),
        ("target", "GET", "/my-account?id=wiener"),
        ("exploit", "POST", "/"),
        ("exploit", "GET", "/"),
        ("exploit", "POST", "/"),
        ("exploit", "GET", "/?message=delivered"),
        ("target", "GET", "/"),
    ]
    assert output["findings"][0]["info"]["classification"]["cwe-id"] == ["CWE-352"]
    evidence = str(proof["httpEvidence"])
    assert "xasm-csrf-proof@example.net" in evidence
    for secret in (
        "approved-password",
        "csrf-live-123",
        "pre-auth-session",
        "authenticated-session",
    ):
        assert secret not in evidence
    assert REDACTED_RUNTIME_SECRET in evidence


@pytest.mark.asyncio
async def test_execute_fails_closed_when_target_is_already_solved():
    async def root(_request):
        return web.Response(text="<p>Solved</p>")

    target_app = web.Application()
    target_app.router.add_get("/", root)
    target_runner = web.AppRunner(target_app)
    await target_runner.setup()
    target_site = web.TCPSite(target_runner, "127.0.0.1", 0)
    await target_site.start()
    target_port = target_site._server.sockets[0].getsockname()[1]

    exploit_app = web.Application()
    exploit_app.router.add_get("/", root)
    exploit_runner = web.AppRunner(exploit_app)
    await exploit_runner.setup()
    exploit_site = web.TCPSite(exploit_runner, "127.0.0.1", 0)
    await exploit_site.start()
    exploit_port = exploit_site._server.sockets[0].getsockname()[1]

    try:
        output = await FixtureBrowserCsrfProbe().execute(
            _parameters(
                target=f"http://127.0.0.1:{target_port}/",
                exploitServer=f"http://127.0.0.1:{exploit_port}/",
            )
        )
    finally:
        await target_runner.cleanup()
        await exploit_runner.cleanup()

    assert output["success"] is False
    assert output["fallback"] is False
    assert output["requestCount"] == 1
    assert output["findings"] == []
    assert "unsolved state" in output["error"]
