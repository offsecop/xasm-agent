import unittest

from tools._browser_scoped_context import (
    BrowserCoverageIncomplete,
    SERVER_BROWSER_ORIGIN_POLICY_KEY,
    attach_auth_loss_watch,
    browser_extra_headers,
    create_scoped_browser_context,
    normalize_browser_cookie,
    parse_cookie_header,
    validate_authenticated_navigation,
)
from tools.browser_login_ai import serialize_login_cookie_jar


TARGET = "https://app.example.test/protected"


def _origin_policy(*origins):
    return {
        "version": 1,
        "primaryOrigin": "https://app.example.test",
        "allowedOrigins": sorted(origins or ("https://app.example.test",)),
        "requireExactOrigin": True,
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

    async def continue_(self, **kwargs):
        self.continued = True
        self.continue_headers = kwargs.get("headers")

    async def abort(self, _reason):
        self.aborted = True


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
        ):
            with self.assertRaises(BrowserCoverageIncomplete) as raised:
                await create_scoped_browser_context(
                    _Browser(),
                    TARGET,
                    {SERVER_BROWSER_ORIGIN_POLICY_KEY: policy},
                )
            self.assertEqual(raised.exception.reason, "INVALID_BROWSER_ORIGIN_POLICY")

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
                "Accept": "application/json",
                "Cookie": "native-cookie-semantics",
            },
        )
        await browser.context.routes[0](secondary)
        self.assertTrue(secondary.continued)
        self.assertNotIn("Authorization", secondary.continue_headers)
        self.assertNotIn("X-Access-Token", secondary.continue_headers)
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
        self.assertEqual(scoped.scope_metadata()["strippedCrossOriginAuthHeaders"], 2)

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
