"""
Agentic browser mapping tool.

This is an observation-first browser tool: it maps pages, forms, buttons,
SPA-style modal surfaces, scripts, and safe navigation candidates without
submitting forms or pressing risky state-changing controls.
"""

from typing import Any, Dict
from urllib.parse import urljoin, urlparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    NATIVE_PROBE_PRIVATE_CANDIDATES_KEY,
    RISKY_CLICK_WORDS,
    build_native_probe_form_contract,
    extract_html_map,
    fetch_text,
    normalize_url,
    parse_headers,
    same_origin,
)


BROWSER_CONTEXT_SCOPE_OPTIONS = {"service_workers": "block"}


def same_websocket_origin(base: str, candidate: str) -> bool:
    """Match a page origin to its WebSocket transport equivalent."""
    try:
        page = urlparse(base)
        websocket = urlparse(candidate)
        expected_scheme = {"http": "ws", "https": "wss"}.get(page.scheme.lower())
        if not expected_scheme or websocket.scheme.lower() != expected_scheme:
            return False

        def effective_port(parsed: Any, secure: bool) -> int:
            return int(parsed.port) if parsed.port else (443 if secure else 80)

        return (
            (page.hostname or "").lower() == (websocket.hostname or "").lower()
            and effective_port(page, page.scheme.lower() == "https")
            == effective_port(websocket, websocket.scheme.lower() == "wss")
        )
    except (TypeError, ValueError):
        return False


class BrowserMapAppTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "browser:map_app"

    @property
    def description(self) -> str:
        return "Maps a web application with a headless browser: links, forms, inputs, buttons, scripts, modal login surfaces, and safe SPA navigation observations."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL to map"},
                "url": {"type": "string", "description": "Alias for target"},
                "maxInteractions": {"type": "integer", "default": 12},
                "timeoutSeconds": {"type": "integer", "default": 45},
                "safeInteract": {"type": "boolean", "default": True},
                "cookie": {"type": "string"},
                "authCookies": {"type": "string"},
                "headers": {"type": "object"},
                "authHeaders": {"type": "object"},
            },
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
        }

    @property
    def metadata(self):
        return {
            "category": "agentic-recon",
            "phase": 2,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["urls", "forms", "navigation_map"],
            "chainable_after": ["authentication:"],
            "chainable_before": ["js:", "api:", "param:", "katana:", "nuclei:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        target = normalize_url(parameters.get("target") or parameters.get("url"))
        agent = parameters.get("_agent")
        if not target:
            return {"success": False, "error": "target is required", "target": target}

        timeout_seconds = max(10, min(int(parameters.get("timeoutSeconds") or 45), 120))
        max_interactions = max(0, min(int(parameters.get("maxInteractions") or 12), 50))
        safe_interact = bool(parameters.get("safeInteract", True))

        if agent:
            agent.report_progress("Mapping application with browser", target, 0, None)

        try:
            from playwright.async_api import async_playwright
            from lib.process_reaper import close_browser_safe
        except Exception as exc:
            return await self._http_fallback(target, parameters, f"Playwright unavailable: {exc}")

        browser = None
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage"],
                )
                context = await browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers=parse_headers(parameters),
                    **BROWSER_CONTEXT_SCOPE_OPTIONS,
                )

                async def keep_requests_in_scope(route):
                    request_url = route.request.url
                    if request_url.startswith(("about:", "blob:", "data:")) or same_origin(
                        target, request_url
                    ):
                        await route.continue_()
                    else:
                        await route.abort("blockedbyclient")

                # The fallback is selected automatically by the coordinator,
                # so redirects and subresources must remain on the exact
                # authorized origin rather than silently expanding scope.
                await context.route("**/*", keep_requests_in_scope)

                async def keep_websockets_in_scope(websocket):
                    if same_websocket_origin(target, websocket.url):
                        websocket.connect_to_server()
                    else:
                        await websocket.close(
                            code=1008,
                            reason="cross-origin websocket blocked by authorized scope",
                        )

                # HTTP routing does not cover WebSocket handshakes. Register
                # this before creating a page so no script gets an unbounded
                # connection window during initial navigation.
                await context.route_web_socket("**/*", keep_websockets_in_scope)
                page = await context.new_page()
                page.set_default_timeout(timeout_seconds * 1000)
                navigation = await page.goto(
                    target,
                    wait_until="domcontentloaded",
                    timeout=timeout_seconds * 1000,
                )
                await page.wait_for_timeout(1000)
                if not same_origin(target, page.url):
                    raise RuntimeError(f"cross-origin navigation blocked: {page.url}")

                snapshot = await page.evaluate(
                    """() => {
                      const text = (el) => (el.innerText || el.textContent || '').trim().replace(/\\s+/g, ' ').slice(0, 160);
                      return {
                        title: document.title || '',
                        url: location.href,
                        links: Array.from(document.querySelectorAll('a[href]')).map(a => new URL(a.getAttribute('href'), location.href).href).slice(0, 250),
                        scripts: Array.from(document.querySelectorAll('script[src]')).map(s => new URL(s.getAttribute('src'), location.href).href).slice(0, 250),
                        forms: Array.from(document.forms).map(f => ({
                          action: new URL(f.getAttribute('action') || location.href, location.href).href,
                          method: (f.getAttribute('method') || 'GET').toUpperCase(),
                          contentType: (f.getAttribute('enctype') || 'application/x-www-form-urlencoded').toLowerCase(),
                          fields: Array.from(f.querySelectorAll('input, textarea, select')).map(i => {
                            const type = (i.getAttribute('type') || i.tagName || 'text').toLowerCase();
                            const successful = !['checkbox', 'radio'].includes(type) || Boolean(i.checked);
                            return {
                              name: i.getAttribute('name') || i.id || '',
                              type,
                              value: successful ? String(i.value || '').slice(0, 4096) : null,
                              valueSource: i.tagName === 'SELECT' ? 'selected-option' : 'browser-default',
                            };
                          }).filter(i => i.name || ['password','email','search','file'].includes(i.type)),
                        })).slice(0, 100),
                        buttons: Array.from(document.querySelectorAll('button, [role=button], input[type=button], input[type=submit], a')).map((b, index) => ({
                          index,
                          label: text(b) || b.getAttribute('aria-label') || b.getAttribute('value') || '',
                          tag: b.tagName.toLowerCase(),
                          href: b.href || b.getAttribute('href') || '',
                          type: b.getAttribute('type') || '',
                        })).filter(b => b.label || b.href).slice(0, 200),
                        inputs: Array.from(document.querySelectorAll('input, textarea, select')).map(i => ({name: i.getAttribute('name') || i.id || '', type: (i.getAttribute('type') || i.tagName || 'text').toLowerCase()})).slice(0, 200),
                      };
                    }"""
                )

                interactions = []
                if safe_interact and max_interactions > 0:
                    locators = await page.locator("button, [role=button], a").all()
                    for index, locator in enumerate(locators[: max_interactions * 3]):
                        if len(interactions) >= max_interactions:
                            break
                        try:
                            label = (await locator.inner_text(timeout=800)).strip()
                            href = await locator.get_attribute("href", timeout=800)
                            lowered = label.lower()
                            if any(word in lowered for word in RISKY_CLICK_WORDS):
                                continue
                            if href and not same_origin(target, page.url if href.startswith("#") else href):
                                continue
                            before_url = page.url
                            before_forms = len(await page.locator("form").all())
                            await locator.click(timeout=1200, no_wait_after=True)
                            await page.wait_for_timeout(700)
                            after_url = page.url
                            after_forms = len(await page.locator("form").all())
                            interactions.append(
                                {
                                    "label": label[:120],
                                    "beforeUrl": before_url,
                                    "afterUrl": after_url,
                                    "openedModalOrForm": after_forms > before_forms or after_url == before_url,
                                    "formCountAfter": after_forms,
                                }
                            )
                            if after_url != before_url and same_origin(target, after_url):
                                await page.go_back(wait_until="domcontentloaded", timeout=3000)
                                await page.wait_for_timeout(300)
                        except Exception:
                            continue

                await context.close()
                await close_browser_safe(browser)

                form_contract = build_native_probe_form_contract(
                    snapshot.get("forms", []),
                    source="browser:map_app",
                )
                same_origin_links = [u for u in snapshot.get("links", []) if same_origin(target, u)]
                map_result = {
                    "success": True,
                    "coverageStatus": "CONFIRMED",
                    "coverageReason": "BROWSER_ROOT_DOCUMENT_LOADED",
                    "verified": True,
                    "target": target,
                    "finalUrl": snapshot.get("url"),
                    "status": navigation.status if navigation else None,
                    "title": snapshot.get("title"),
                    "links": same_origin_links,
                    "externalLinks": [u for u in snapshot.get("links", []) if not same_origin(target, u)][:100],
                    "scripts": snapshot.get("scripts", []),
                    "forms": form_contract["forms"],
                    NATIVE_PROBE_PRIVATE_CANDIDATES_KEY: form_contract[
                        NATIVE_PROBE_PRIVATE_CANDIDATES_KEY
                    ],
                    "buttons": snapshot.get("buttons", []),
                    "inputs": snapshot.get("inputs", []),
                    "safeInteractions": interactions,
                    "summary": {
                        "sameOriginLinks": len(same_origin_links),
                        "forms": len(snapshot.get("forms", [])),
                        "buttons": len(snapshot.get("buttons", [])),
                        "scripts": len(snapshot.get("scripts", [])),
                        "modalLikeInteractions": sum(1 for item in interactions if item.get("openedModalOrForm")),
                    },
                }
                if agent:
                    agent.append_output(
                        f"[browser:map_app] links={map_result['summary']['sameOriginLinks']} forms={map_result['summary']['forms']} modalLike={map_result['summary']['modalLikeInteractions']}"
                    )
                    agent.report_progress("Browser mapping completed", target, 1, 1)
                return map_result
        except Exception as exc:
            await close_browser_safe(browser)
            return await self._http_fallback(target, parameters, f"browser mapping failed: {exc}")

    async def _http_fallback(self, target: str, parameters: Dict[str, Any], reason: str) -> Dict[str, Any]:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as session:
            current_url = target
            redirects = []
            fetched = None
            for _ in range(6):
                fetched = await fetch_text(
                    session,
                    current_url,
                    headers=parse_headers(parameters),
                    allow_redirects=False,
                )
                status = int(fetched.get("status") or 0)
                response_headers = fetched.get("headers") or {}
                location = next(
                    (
                        value
                        for key, value in response_headers.items()
                        if str(key).lower() == "location"
                    ),
                    None,
                )
                if status not in {301, 302, 303, 307, 308} or not location:
                    break
                next_url = urljoin(current_url, str(location))
                if not same_origin(target, next_url):
                    return {
                        "success": False,
                        "coverageStatus": "INCOMPLETE",
                        "coverageReason": "CROSS_ORIGIN_REDIRECT_BLOCKED",
                        "verified": False,
                        "target": target,
                        "finalUrl": current_url,
                        "status": status,
                        "redirectTarget": next_url,
                        "redirects": redirects,
                        "fallback": True,
                        "fallbackReason": reason,
                        "error": "redirect left the authorized origin",
                    }
                redirects.append(next_url)
                current_url = next_url
            else:
                return {
                    "success": False,
                    "coverageStatus": "INCOMPLETE",
                    "coverageReason": "REDIRECT_LIMIT_EXCEEDED",
                    "verified": False,
                    "target": target,
                    "finalUrl": current_url,
                    "redirects": redirects,
                    "fallback": True,
                    "fallbackReason": reason,
                    "error": "same-origin redirect limit exceeded",
                }
        assert fetched is not None
        mapped = extract_html_map(fetched.get("text", ""), fetched.get("url") or target)
        return {
            "success": True,
            "coverageStatus": "CONFIRMED",
            "coverageReason": "HTTP_ROOT_FETCH_COMPLETED",
            "verified": True,
            "target": target,
            "finalUrl": fetched.get("url"),
            "status": fetched.get("status"),
            "redirects": redirects,
            "fallback": True,
            "fallbackReason": reason,
            **mapped,
            "summary": {
                "sameOriginLinks": len([u for u in mapped.get("links", []) if same_origin(target, u)]),
                "forms": len(mapped.get("forms", [])),
                "buttons": len(mapped.get("buttons", [])),
                "scripts": len(mapped.get("scripts", [])),
            },
        }


def get_tool():
    return BrowserMapAppTool()
