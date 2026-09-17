"""
Agentic browser mapping tool.

This is an observation-first browser tool: it maps pages, forms, buttons,
SPA-style modal surfaces, scripts, and safe navigation candidates without
submitting forms or pressing risky state-changing controls.
"""

from typing import Any, Dict
from urllib.parse import urljoin

import aiohttp

from plugin_interface import ToolPlugin
from tools._browser_scoped_context import (
    BROWSER_CONTEXT_SCOPE_OPTIONS,  # noqa: F401 - legacy public test/import surface
    BrowserCoverageIncomplete,
    attach_auth_loss_watch,
    browser_origin_policy,
    browser_scope_metadata,
    create_scoped_browser_context,
    has_browser_auth_material,
    incomplete_output,
    same_websocket_origin,  # noqa: F401 - legacy public test/import surface
    validate_authenticated_navigation,
)
from tools._browser_spa_traversal import (
    enforce_public_output_cap,
    merge_incomplete_output,
    spa_traversal_budget,
    traverse_bounded_spa,
)
from tools._agentic_exploration_common import (
    NATIVE_PROBE_PRIVATE_CANDIDATES_KEY,
    build_native_probe_form_contract,
    extract_html_map,
    fetch_text,
    normalize_url,
    parse_headers,
    same_origin,
)


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
                "maxPages": {"type": "integer", "default": 12},
                "maxDepth": {"type": "integer", "default": 3},
                "timeoutSeconds": {"type": "integer", "default": 45},
                "maxOutputBytes": {"type": "integer", "default": 49152},
                "safeInteract": {"type": "boolean", "default": True},
                "cookie": {"type": "string"},
                "authCookies": {"type": "string"},
                "cookieJar": {
                    "type": "array",
                    "items": {"type": "object"},
                    "x-hidden": True,
                    "x-workflow-owned": True,
                },
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
        try:
            browser_origin_policy(parameters, target)
        except BrowserCoverageIncomplete as exc:
            return incomplete_output(target, exc)

        timeout_seconds = max(10, min(int(parameters.get("timeoutSeconds") or 45), 120))
        budget = spa_traversal_budget(
            parameters,
            default_interactions=12,
            default_timeout_seconds=timeout_seconds,
        )
        safe_interact = bool(parameters.get("safeInteract", True))

        if agent:
            agent.report_progress("Mapping application with browser", target, 0, None)

        try:
            from playwright.async_api import async_playwright
            from lib.process_reaper import close_browser_safe
        except Exception as exc:
            return await self._http_fallback(target, parameters, f"Playwright unavailable: {exc}")

        browser = None
        scoped = None
        page = None
        navigation = None
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage"],
                )
                scoped = await create_scoped_browser_context(browser, target, parameters)
                context = scoped.context
                page = await context.new_page()
                attach_auth_loss_watch(scoped, page)
                page.set_default_timeout(timeout_seconds * 1000)
                navigation = await page.goto(
                    target,
                    wait_until="domcontentloaded",
                    timeout=timeout_seconds * 1000,
                )
                await page.wait_for_timeout(1000)
                await validate_authenticated_navigation(scoped, page, navigation, target)
                if not same_origin(target, page.url):
                    raise BrowserCoverageIncomplete(
                        "CROSS_ORIGIN_REDIRECT_BLOCKED",
                        "cross-origin navigation was blocked by the exact-origin policy",
                    )

                traversal = await traverse_bounded_spa(
                    page,
                    scoped,
                    target,
                    budget,
                    root_navigation=navigation,
                    safe_interact=safe_interact,
                )
                final_url = getattr(page, "url", None)

                await context.close()
                await close_browser_safe(browser)

                form_contract = build_native_probe_form_contract(
                    traversal.get("forms", []),
                    source="browser:map_app",
                )
                for public_form, observed_form in zip(
                    form_contract["forms"],
                    traversal.get("forms", []),
                ):
                    public_form["routeUrl"] = observed_form.get("routeUrl")
                same_origin_links = list(traversal.get("links") or [])
                visited_states = list(traversal.get("visitedStates") or [])
                routes = list(
                    dict.fromkeys(
                        str(item.get("routeUrl") or "")
                        for item in visited_states
                        if item.get("routeUrl")
                    )
                )
                first_state = visited_states[0] if visited_states else {}
                coverage_status = str(traversal.get("coverageStatus") or "INCOMPLETE")
                map_result = {
                    "success": coverage_status != "INCOMPLETE",
                    "coverageStatus": coverage_status,
                    "coverageReason": traversal.get("coverageReason"),
                    "verified": coverage_status != "INCOMPLETE",
                    "target": target,
                    "finalUrl": final_url,
                    "status": navigation.status if navigation else None,
                    "title": first_state.get("title"),
                    "links": same_origin_links,
                    "externalLinks": traversal.get("externalLinks", []),
                    "scripts": traversal.get("scripts", []),
                    "forms": form_contract["forms"],
                    NATIVE_PROBE_PRIVATE_CANDIDATES_KEY: form_contract[
                        NATIVE_PROBE_PRIVATE_CANDIDATES_KEY
                    ],
                    "buttons": traversal.get("buttons", []),
                    "inputs": traversal.get("inputs", []),
                    "safeInteractions": traversal.get("safeInteractions", []),
                    "visitedStates": visited_states,
                    "routes": routes,
                    "linkObservations": traversal.get("linkObservations", []),
                    "scriptObservations": traversal.get("scriptObservations", []),
                    "scopeMetadata": scoped.scope_metadata(),
                    "coverage": {
                        key: traversal.get(key)
                        for key in (
                            "exhaustiveWithinBounds",
                            "truncated",
                            "truncatedBy",
                            "omittedStates",
                            "omittedArtifacts",
                            "pagesObserved",
                            "interactionsUsed",
                            "interactionFailures",
                            "candidatesObserved",
                            "elapsedMs",
                            "artifactBytes",
                            "budget",
                        )
                    },
                    "summary": {
                        "sameOriginLinks": len(same_origin_links),
                        "forms": len(form_contract["forms"]),
                        "buttons": len(traversal.get("buttons", [])),
                        "scripts": len(traversal.get("scripts", [])),
                        "modalLikeInteractions": sum(
                            1
                            for item in traversal.get("safeInteractions", [])
                            if item.get("openedModalOrForm")
                        ),
                        "visitedStates": traversal.get("pagesObserved", 0),
                        "routes": len(routes),
                        "interactions": traversal.get("interactionsUsed", 0),
                        "truncated": bool(traversal.get("truncated")),
                        "omittedStates": traversal.get("omittedStates", 0),
                    },
                }
                if agent:
                    agent.append_output(
                        f"[browser:map_app] links={map_result['summary']['sameOriginLinks']} forms={map_result['summary']['forms']} modalLike={map_result['summary']['modalLikeInteractions']}"
                    )
                    agent.report_progress("Browser mapping completed", target, 1, 1)
                return enforce_public_output_cap(
                    map_result,
                    budget.max_output_bytes,
                    removable_lists=(
                        "externalLinks",
                        "buttons",
                        "inputs",
                        "scriptObservations",
                        "linkObservations",
                        "scripts",
                        "links",
                        "safeInteractions",
                        "visitedStates",
                        "routes",
                        "forms",
                    ),
                    private_keys=(NATIVE_PROBE_PRIVATE_CANDIDATES_KEY,),
                )
        except BrowserCoverageIncomplete as exc:
            await close_browser_safe(browser)
            return merge_incomplete_output(
                incomplete_output(
                    target,
                    exc,
                    final_url=getattr(page, "url", None),
                    status=getattr(navigation, "status", None),
                    scoped=scoped,
                ),
                exc,
            )
        except Exception as exc:
            if scoped and scoped.authenticated and scoped.blocked_navigation_urls:
                await close_browser_safe(browser)
                return incomplete_output(
                    target,
                    BrowserCoverageIncomplete(
                        "AUTHENTICATION_LOST_REDIRECT",
                        "authenticated navigation redirected outside the authorized origin",
                    ),
                    final_url=getattr(page, "url", None),
                    scoped=scoped,
                )
            await close_browser_safe(browser)
            return await self._http_fallback(target, parameters, f"browser mapping failed: {exc}")

    async def _http_fallback(self, target: str, parameters: Dict[str, Any], reason: str) -> Dict[str, Any]:
        policy = browser_origin_policy(parameters, target)
        if has_browser_auth_material(parameters):
            return incomplete_output(
                target,
                BrowserCoverageIncomplete(
                    "BROWSER_REQUIRED_FOR_NATIVE_COOKIE_SESSION",
                    "Playwright is required to preserve authenticated cookie semantics",
                ),
            )
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
                if not policy.url_is_primary(next_url):
                    return {
                        "success": False,
                        "coverageStatus": "INCOMPLETE",
                        "coverageReason": "CROSS_ORIGIN_REDIRECT_BLOCKED",
                        "verified": False,
                        "target": target,
                        "finalUrl": current_url,
                        "status": status,
                        "redirects": redirects,
                        "fallback": True,
                        "fallbackReason": reason,
                        "error": "redirect left the authorized origin",
                        "scopeMetadata": browser_scope_metadata(
                            policy,
                            blocked_urls=[next_url],
                            blocked_navigation_count=1,
                        ),
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
        blocked_urls = []
        for key in ("links", "scripts", "stylesheets", "parameterizedUrls"):
            values = list(mapped.get(key) or [])
            mapped[key] = [value for value in values if policy.url_is_authorized(str(value))]
            blocked_urls.extend(
                str(value) for value in values if not policy.url_is_authorized(str(value))
            )
        forms = list(mapped.get("forms") or [])
        mapped["forms"] = [
            form
            for form in forms
            if isinstance(form, dict)
            and policy.url_is_authorized(str(form.get("action") or ""))
        ]
        blocked_urls.extend(
            str(form.get("action") or "")
            for form in forms
            if isinstance(form, dict)
            and not policy.url_is_authorized(str(form.get("action") or ""))
        )
        private_candidates = list(
            mapped.get(NATIVE_PROBE_PRIVATE_CANDIDATES_KEY) or []
        )
        mapped[NATIVE_PROBE_PRIVATE_CANDIDATES_KEY] = [
            candidate
            for candidate in private_candidates
            if isinstance(candidate, dict)
            and policy.url_is_authorized(str(candidate.get("url") or ""))
        ]
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
            "scopeMetadata": browser_scope_metadata(
                policy,
                blocked_urls=blocked_urls,
            ),
            "summary": {
                "sameOriginLinks": len([u for u in mapped.get("links", []) if same_origin(target, u)]),
                "forms": len(mapped.get("forms", [])),
                "buttons": len(mapped.get("buttons", [])),
                "scripts": len(mapped.get("scripts", [])),
            },
        }


def get_tool():
    return BrowserMapAppTool()
