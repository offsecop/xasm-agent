import unittest

from tools._browser_scoped_context import (
    BrowserCoverageIncomplete,
    MAX_AUTH_BOOTSTRAP_NAVIGATION_HOPS,
    SERVER_BROWSER_ORIGIN_POLICY_KEY,
    attach_auth_loss_watch,
    browser_extra_headers,
    create_scoped_browser_context,
    incomplete_output,
    normalize_browser_cookie,
    parse_cookie_header,
    validate_authenticated_navigation,
)
from tools.browser_login_ai import serialize_login_cookie_jar


TARGET = "https://app.example.test/protected"


def _origin_policy(*origins, authentication_origin=None):
    return {
        "version": 2,
        "primaryOrigin": "https://app.example.test",
        "allowedOrigins": sorted(origins or ("https://app.example.test",)),
        "authenticationBootstrapOrigin": authentication_origin,
        "requireExactOrigin": True,
        "requireFinalPrimaryOrigin": True,
        "stripCrossOriginAuthHeaders": True,
    }


class _Route:
    def __init__(self, url, navigation=False, headers=None):
        self.request = type(
            "Request",
            (),
            {
                "url": url,
                "is_navigation_request": lambda _self: navigation,
                "frame": type("Frame", (), {"parent_frame": None})(),
                "headers": headers or {},
            },
        )()
        self.continued = False
        self.continue_headers = None
        self.aborted = False
        self.abort_reason = None

    async def continue_(self, **kwargs):
        self.continued = True
        self.continue_headers = kwargs.get("headers")

    async def abort(self, reason):
        self.aborted = True
        self.abort_reason = reason


class _Context:
    def __init__(self):
        self.routes = []
        self.websocket_handler = None
        self.cookies = []

    async def route(self, _pattern, handler):
        self.routes.append(handler)

    async def route_web_socket(self, _pattern, handler):
        self.websocket_handler = handler

    async def add_cookies(self, cookies):
        self.cookies.extend(cookies)


class _Browser:
    def __init__(self):
        self.kwargs = None
        self.context = _Context()

    async def new_context(self, **kwargs):
        self.kwargs = kwargs
        return self.context


class _WebSocket:
    def __init__(self, url):
        self.url = url
        self.connected = False
        self.closed = False

    def connect_to_server(self):
        self.connected = True

    async def close(self, **_kwargs):
        self.closed = True


class _Locator:
    def __init__(self, count):
        self._count = count

    async def count(self):
        return self._count


class _Page:
    def __init__(self, url, password_count=0, login_form_count=0):
        self.url = url
        self.password_count = password_count
        self.login_form_count = login_form_count
        self.handlers = {}

    def locator(self, selector):
        if selector == 'input[type="password"]':
            return _Locator(self.password_count)
        return _Locator(self.login_form_count)

    def on(self, event, handler):
        self.handlers[event] = handler


class BrowserScopedContextTests(unittest.IsolatedAsyncioTestCase):
    async def test_policy_rejects_malicious_shape_and_near_miss_origin(self):
        for policy in (
            {
                **_origin_policy("https://app.example.test"),
                "allowedOrigins": ["https://app.example.test/path"],
            },
            {
                **_origin_policy("https://app.example.test"),
                "callerControlled": True,
            },
            {
                **_origin_policy("https://app.example.test"),
                "version": True,
            },
            {
                **_origin_policy("https://app.example.test"),
                "authenticationBootstrapOrigin": ["https://login.example.test"],
            },
            {
                **_origin_policy("https://app.example.test"),
                "authenticationBootstrapOrigin": "https://login.example.test/path",
            },
            {
                **_origin_policy("https://app.example.test"),
                "authenticationBootstrapOrigin": "https://app.example.test",
            },
            {
                **_origin_policy(
                    "https://app.example.test",
                    "https://login.example.test",
                ),
                "authenticationBootstrapOrigin": "https://login.example.test",
            },
            {
                **_origin_policy("https://app.example.test"),
                "authenticationOrigins": ["https://login.example.test"],
            },
        ):
            with self.assertRaises(BrowserCoverageIncomplete) as raised:
                await create_scoped_browser_context(
                    _Browser(),
                    TARGET,
                    {SERVER_BROWSER_ORIGIN_POLICY_KEY: policy},
                )
            self.assertEqual(raised.exception.reason, "INVALID_BROWSER_ORIGIN_POLICY")

    async def test_policy_accepts_absent_or_null_single_auth_bootstrap_origin(self):
        absent = _origin_policy("https://app.example.test")
        absent.pop("authenticationBootstrapOrigin")
        for policy in (
            absent,
            _origin_policy("https://app.example.test"),
            _origin_policy(
                "https://app.example.test",
                authentication_origin="https://login.example.test",
            ),
        ):
            scoped = await create_scoped_browser_context(
                _Browser(),
                TARGET,
                {SERVER_BROWSER_ORIGIN_POLICY_KEY: policy},
            )
            self.assertEqual(scoped.scope_metadata()["policyVersion"], 2)
            self.assertFalse(scoped.url_is_authentication("not-an-http-url"))

    async def test_unrelated_cookie_domain_is_rejected_but_allowed_cookie_keeps_attributes(self):
        browser = _Browser()
        scoped = await create_scoped_browser_context(
            browser,
            TARGET,
            {
                SERVER_BROWSER_ORIGIN_POLICY_KEY: _origin_policy(
                    "https://api.example.test",
                    "https://app.example.test",
                ),
                "cookieJar": [
                    {
                        "name": "session",
                        "value": "opaque",
                        "domain": ".example.test",
                        "path": "/protected",
                        "secure": True,
                        "sameSite": "Strict",
                    },
                    {
                        "name": "unrelated",
                        "value": "must-not-install",
                        "domain": ".invalid.test",
                        "path": "/",
                    },
                ],
            },
        )

        self.assertEqual(scoped.installed_cookie_count, 1)
        self.assertEqual(scoped.rejected_cookie_count, 1)
        self.assertEqual(browser.context.cookies[0]["path"], "/protected")
        self.assertEqual(browser.context.cookies[0]["sameSite"], "Strict")
        self.assertEqual(browser.context.cookies[0]["domain"], ".example.test")

    async def test_authorized_secondary_origin_is_not_navigation_authority(self):
        browser = _Browser()
        scoped = await create_scoped_browser_context(
            browser,
            TARGET,
            {
                SERVER_BROWSER_ORIGIN_POLICY_KEY: _origin_policy(
                    "https://api.example.test",
                    "https://app.example.test",
                )
            },
        )
        secondary_navigation = _Route(
            "https://api.example.test/login",
            navigation=True,
        )
        await browser.context.routes[0](secondary_navigation)
        self.assertTrue(secondary_navigation.aborted)
        self.assertEqual(len(scoped.blocked_navigation_urls), 1)

    async def test_server_attested_auth_origin_allows_bounded_login_bootstrap(self):
        browser = _Browser()
        scoped = await create_scoped_browser_context(
            browser,
            TARGET,
            {
                SERVER_BROWSER_ORIGIN_POLICY_KEY: _origin_policy(
                    "https://app.example.test",
                    authentication_origin="https://login.example.test",
                ),
                "cookieJar": [
                    {
                        "name": "idp-session",
                        "value": "opaque",
                        "domain": "login.example.test",
                        "path": "/",
                        "secure": True,
                    }
                ],
                "authHeaders": {"Authorization": "Bearer primary-only"},
            },
        )

        initial_primary_navigation = _Route(TARGET, navigation=True)
        await browser.context.routes[0](initial_primary_navigation)
        self.assertTrue(initial_primary_navigation.continued)

        auth_navigation = _Route(
            "https://login.example.test/connect/authorize",
            navigation=True,
            headers={
                "Authorization": "Bearer must-not-cross",
                "Referer": "https://app.example.test/protected?session=secret",
                "Accept": "text/html",
                "Cookie": "native-cookie-semantics",
            },
        )
        await browser.context.routes[0](auth_navigation)

        self.assertTrue(auth_navigation.continued)
        self.assertFalse(auth_navigation.aborted)
        self.assertNotIn("Authorization", auth_navigation.continue_headers)
        self.assertNotIn("Referer", auth_navigation.continue_headers)
        self.assertEqual(auth_navigation.continue_headers["Accept"], "text/html")
        self.assertIn("Cookie", auth_navigation.continue_headers)
        self.assertEqual(scoped.installed_cookie_count, 1)
        self.assertEqual(scoped.scope_metadata()["authenticationOriginCount"], 1)
        self.assertFalse(
            scoped.url_is_authorized("https://login.example.test/connect/authorize")
        )

        auth_subresource = _Route(
            "https://login.example.test/assets/login.js",
            headers={"Referer": "https://login.example.test/connect/authorize"},
        )
        await browser.context.routes[0](auth_subresource)
        self.assertTrue(auth_subresource.continued)
        self.assertNotIn("Referer", auth_subresource.continue_headers)

        primary_return = _Route(TARGET, navigation=True)
        await browser.context.routes[0](primary_return)
        self.assertTrue(primary_return.continued)
        self.assertTrue(scoped.auth_bootstrap_sealed)

        await validate_authenticated_navigation(
            scoped,
            _Page(TARGET),
            type("Response", (), {"status": 200})(),
            TARGET,
        )

    async def test_auth_origin_terminal_page_is_typed_incomplete(self):
        browser = _Browser()
        scoped = await create_scoped_browser_context(
            browser,
            TARGET,
            {
                SERVER_BROWSER_ORIGIN_POLICY_KEY: _origin_policy(
                    "https://app.example.test",
                    authentication_origin="https://login.example.test",
                ),
                "authCookies": "session=opaque",
            },
        )

        await browser.context.routes[0](_Route(TARGET, navigation=True))
        await browser.context.routes[0](
            _Route("https://login.example.test/account/login", navigation=True)
        )

        with self.assertRaises(BrowserCoverageIncomplete) as raised:
            await validate_authenticated_navigation(
                scoped,
                _Page(
                    "https://login.example.test/account/login?code=secret#access_token",
                    password_count=1,
                ),
                type("Response", (), {"status": 200})(),
                TARGET,
            )
        self.assertEqual(raised.exception.reason, "AUTH_BOOTSTRAP_TERMINAL_AUTH_ORIGIN")
        output = incomplete_output(
            TARGET,
            raised.exception,
            final_url="https://login.example.test/account/login?code=secret#access_token",
            scoped=scoped,
        )
        self.assertEqual(output["finalUrl"], "https://login.example.test/account/login")
        self.assertNotIn("secret", str(output))
        self.assertNotIn("access_token", str(output))

    async def test_auth_origin_is_rejected_without_auth_material(self):
        browser = _Browser()
        scoped = await create_scoped_browser_context(
            browser,
            TARGET,
            {
                SERVER_BROWSER_ORIGIN_POLICY_KEY: _origin_policy(
                    "https://app.example.test",
                    authentication_origin="https://login.example.test",
                )
            },
        )
        await browser.context.routes[0](_Route(TARGET, navigation=True))
        auth_navigation = _Route(
            "https://login.example.test/account/login",
            navigation=True,
        )
        await browser.context.routes[0](auth_navigation)
        self.assertTrue(auth_navigation.aborted)
        self.assertEqual(len(scoped.blocked_navigation_urls), 1)

    async def test_auth_origin_requires_initial_primary_and_active_document(self):
        browser = _Browser()
        scoped = await create_scoped_browser_context(
            browser,
            TARGET,
            {
                SERVER_BROWSER_ORIGIN_POLICY_KEY: _origin_policy(
                    "https://app.example.test",
                    authentication_origin="https://login.example.test",
                ),
                "authCookies": "session=opaque",
            },
        )

        premature_subresource = _Route("https://login.example.test/assets/login.js")
        await browser.context.routes[0](premature_subresource)
        self.assertTrue(premature_subresource.aborted)

        premature_navigation = _Route(
            "https://login.example.test/connect/authorize",
            navigation=True,
        )
        await browser.context.routes[0](premature_navigation)
        self.assertTrue(premature_navigation.aborted)
        self.assertEqual(
            scoped.blocked_navigation_reason,
            "AUTH_BOOTSTRAP_INITIAL_PRIMARY_REQUIRED",
        )

    async def test_auth_origin_never_becomes_websocket_authority(self):
        browser = _Browser()
        await create_scoped_browser_context(
            browser,
            TARGET,
            {
                SERVER_BROWSER_ORIGIN_POLICY_KEY: _origin_policy(
                    "https://app.example.test",
                    authentication_origin="https://login.example.test",
                ),
                "authCookies": "session=opaque",
            },
        )
        await browser.context.routes[0](_Route(TARGET, navigation=True))
        await browser.context.routes[0](
            _Route("https://login.example.test/connect/authorize", navigation=True)
        )

        websocket = _WebSocket("wss://login.example.test/socket")
        await browser.context.websocket_handler(websocket)

        self.assertFalse(websocket.connected)
        self.assertTrue(websocket.closed)

    async def test_primary_return_seals_bootstrap_and_rejects_reentry_and_auth_resources(self):
        browser = _Browser()
        scoped = await create_scoped_browser_context(
            browser,
            TARGET,
            {
                SERVER_BROWSER_ORIGIN_POLICY_KEY: _origin_policy(
                    "https://app.example.test",
                    authentication_origin="https://login.example.test",
                ),
                "authCookies": "session=opaque",
            },
        )

        await browser.context.routes[0](_Route(TARGET, navigation=True))
        await browser.context.routes[0](
            _Route("https://login.example.test/connect/authorize", navigation=True)
        )
        active_resource = _Route("https://login.example.test/assets/login.js")
        await browser.context.routes[0](active_resource)
        self.assertTrue(active_resource.continued)

        await browser.context.routes[0](_Route(TARGET, navigation=True))
        self.assertTrue(scoped.auth_bootstrap_sealed)

        stale_resource = _Route("https://login.example.test/assets/late.js")
        await browser.context.routes[0](stale_resource)
        self.assertTrue(stale_resource.aborted)

        reentry = _Route(
            "https://login.example.test/connect/authorize",
            navigation=True,
        )
        await browser.context.routes[0](reentry)
        self.assertTrue(reentry.aborted)
        self.assertEqual(scoped.blocked_navigation_reason, "AUTH_BOOTSTRAP_REENTRY_BLOCKED")

    async def test_auth_bootstrap_navigation_hop_cap_fails_closed(self):
        browser = _Browser()
        scoped = await create_scoped_browser_context(
            browser,
            TARGET,
            {
                SERVER_BROWSER_ORIGIN_POLICY_KEY: _origin_policy(
                    "https://app.example.test",
                    authentication_origin="https://login.example.test",
                ),
                "authCookies": "session=opaque",
            },
        )
        await browser.context.routes[0](_Route(TARGET, navigation=True))

        for hop in range(MAX_AUTH_BOOTSTRAP_NAVIGATION_HOPS):
            route = _Route(
                f"https://login.example.test/redirect/{hop}",
                navigation=True,
            )
            await browser.context.routes[0](route)
            self.assertTrue(route.continued)

        over_limit = _Route(
            "https://login.example.test/redirect/overflow",
            navigation=True,
        )
        await browser.context.routes[0](over_limit)
        self.assertTrue(over_limit.aborted)
        self.assertEqual(
            scoped.blocked_navigation_reason,
            "AUTH_BOOTSTRAP_HOP_LIMIT_EXCEEDED",
        )
        self.assertEqual(
            scoped.scope_metadata()["authenticationBootstrapHopCount"],
            MAX_AUTH_BOOTSTRAP_NAVIGATION_HOPS,
        )

    def test_cookie_attributes_and_equals_are_preserved(self):
        cookie = normalize_browser_cookie(
            {
                "name": "session",
                "value": "opaque=value==",
                "domain": ".example.test",
                "path": "/protected",
                "secure": True,
                "httpOnly": True,
                "sameSite": "lax",
                "expiry": 2_000_000_000,
            },
            TARGET,
        )
        self.assertEqual(cookie["value"], "opaque=value==")
        self.assertEqual(cookie["domain"], ".example.test")
        self.assertEqual(cookie["path"], "/protected")
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httpOnly"])
        self.assertEqual(cookie["sameSite"], "Lax")
        self.assertEqual(cookie["expires"], 2_000_000_000)

        parsed, rejected = parse_cookie_header("session=opaque=value==; csrf=two", TARGET)
        self.assertEqual(rejected, 0)
        self.assertEqual(parsed[0]["value"], "opaque=value==")

    def test_invalid_cookie_names_and_control_chars_are_rejected(self):
        self.assertIsNone(normalize_browser_cookie({"name": "bad name", "value": "x"}, TARGET))
        self.assertIsNone(
            normalize_browser_cookie({"name": "session", "value": "x\r\nInjected: yes"}, TARGET)
        )
        self.assertIsNone(normalize_browser_cookie({"name": "session", "value": "x\0y"}, TARGET))
        self.assertIsNone(
            normalize_browser_cookie(
                {"name": "session", "value": "x", "domain": "example.test\r\n"},
                TARGET,
            )
        )
        self.assertIsNone(
            normalize_browser_cookie(
                {"name": "session", "value": "x", "path": "/ok\0bad"},
                TARGET,
            )
        )

    def test_login_serialization_never_includes_storage_state(self):
        rows = serialize_login_cookie_jar(
            [
                {
                    "name": "session",
                    "value": "opaque=value==",
                    "domain": ".example.test",
                    "path": "/",
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "None",
                    "expires": -1,
                }
            ],
            TARGET,
        )
        self.assertEqual(rows[0]["expiry"], -1)
        self.assertNotIn("storage_state", rows[0])
        self.assertNotIn("localStorage", rows[0])

    async def test_context_installs_native_cookies_and_blocks_cross_origin(self):
        browser = _Browser()
        scoped = await create_scoped_browser_context(
            browser,
            TARGET,
            {
                "cookieJar": [
                    {
                        "name": "session",
                        "value": "opaque=value==",
                        "domain": ".example.test",
                        "path": "/protected",
                        "secure": True,
                        "httpOnly": True,
                        "sameSite": "Lax",
                        "expiry": -1,
                    }
                ],
                "headers": {
                    "Cookie": "caller=must-not-be-an-extra-header",
                    "Authorization": "Bearer scoped",
                },
                SERVER_BROWSER_ORIGIN_POLICY_KEY: _origin_policy(
                    "https://api.example.test",
                    "https://app.example.test",
                ),
            },
        )

        self.assertEqual(browser.kwargs["service_workers"], "block")
        self.assertNotIn("Cookie", browser.kwargs["extra_http_headers"])
        self.assertEqual(browser.kwargs["extra_http_headers"]["Authorization"], "Bearer scoped")
        self.assertEqual(browser.context.cookies[0]["value"], "opaque=value==")
        self.assertTrue(browser.context.cookies[0]["httpOnly"])

        same = _Route("https://app.example.test/api/me")
        await browser.context.routes[0](same)
        self.assertTrue(same.continued)

        secondary = _Route(
            "https://api.example.test/v1/me",
            headers={
                "Authorization": "Bearer must-not-cross",
                "X-Access-Token": "must-not-cross",
                "Referer": "https://app.example.test/protected?session=must-not-cross",
                "Accept": "application/json",
                "Cookie": "native-cookie-semantics",
            },
        )
        await browser.context.routes[0](secondary)
        self.assertTrue(secondary.continued)
        self.assertNotIn("Authorization", secondary.continue_headers)
        self.assertNotIn("X-Access-Token", secondary.continue_headers)
        self.assertNotIn("Referer", secondary.continue_headers)
        self.assertEqual(secondary.continue_headers["Accept"], "application/json")
        self.assertIn("Cookie", secondary.continue_headers)

        near_miss = _Route("https://api.example.test.evil.invalid/collect")
        await browser.context.routes[0](near_miss)
        self.assertTrue(near_miss.aborted)

        outside = _Route("https://tracker.invalid/collect?secret=do-not-report", navigation=True)
        await browser.context.routes[0](outside)
        self.assertTrue(outside.aborted)
        self.assertEqual(len(scoped.blocked_navigation_urls), 1)
        self.assertNotIn("tracker.invalid", scoped.blocked_navigation_urls[0])
        self.assertEqual(scoped.scope_metadata()["blockedRequestCount"], 2)
        self.assertEqual(scoped.scope_metadata()["strippedCrossOriginAuthHeaders"], 3)

    async def test_auth_loss_is_typed_incomplete(self):
        browser = _Browser()
        scoped = await create_scoped_browser_context(
            browser,
            TARGET,
            {"authCookies": "session=opaque=value=="},
        )
        navigation = type("Response", (), {"status": 401})()
        with self.assertRaises(BrowserCoverageIncomplete) as raised:
            await validate_authenticated_navigation(
                scoped,
                _Page(TARGET),
                navigation,
                TARGET,
            )
        self.assertEqual(raised.exception.reason, "AUTHENTICATION_LOST_HTTP_401")

        with self.assertRaises(BrowserCoverageIncomplete) as raised:
            await validate_authenticated_navigation(
                scoped,
                _Page("https://app.example.test/login", password_count=1),
                type("Response", (), {"status": 200})(),
                TARGET,
            )
        self.assertEqual(raised.exception.reason, "AUTHENTICATION_LOST_LOGIN_FORM")

    async def test_auth_path_without_login_ui_is_not_false_auth_loss(self):
        browser = _Browser()
        scoped = await create_scoped_browser_context(
            browser,
            TARGET,
            {"authCookies": "session=opaque=value=="},
        )

        await validate_authenticated_navigation(
            scoped,
            _Page("https://app.example.test/auth/callback"),
            type("Response", (), {"status": 200})(),
            TARGET,
        )

    async def test_same_origin_xhr_auth_failure_is_incomplete_but_image_failure_is_not(self):
        browser = _Browser()
        scoped = await create_scoped_browser_context(
            browser,
            TARGET,
            {"authCookies": "session=opaque=value=="},
        )
        page = _Page(TARGET)
        attach_auth_loss_watch(scoped, page)

        def response(url, status, resource_type):
            request = type(
                "Request",
                (),
                {
                    "resource_type": resource_type,
                    "is_navigation_request": lambda _self: False,
                    "frame": type("Frame", (), {"parent_frame": None})(),
                },
            )()
            return type(
                "Response",
                (),
                {"url": url, "status": status, "request": request},
            )()

        page.handlers["response"](
            response("https://app.example.test/assets/private.png", 403, "image")
        )
        await validate_authenticated_navigation(
            scoped,
            page,
            type("Response", (), {"status": 200})(),
            TARGET,
        )

        page.handlers["response"](
            response("https://app.example.test/api/me", 401, "fetch")
        )
        with self.assertRaises(BrowserCoverageIncomplete) as raised:
            await validate_authenticated_navigation(
                scoped,
                page,
                type("Response", (), {"status": 200})(),
                TARGET,
            )
        self.assertEqual(raised.exception.reason, "AUTHENTICATION_LOST_HTTP_401")

    def test_cookie_header_is_removed_from_generic_headers_case_insensitively(self):
        headers = browser_extra_headers(
            {
                "headers": {"cookie": "secret", "X-Test": "ok"},
                "authCookies": "session=secret",
            }
        )
        self.assertNotIn("Cookie", headers)
        self.assertNotIn("cookie", headers)
        self.assertEqual(headers["X-Test"], "ok")


if __name__ == "__main__":
    unittest.main()
