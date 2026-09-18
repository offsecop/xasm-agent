"""
Browser traffic capture for agentic web exploration.

This tool complements the DOM map by observing the API traffic a SPA actually
uses. It stays read-oriented: navigation, safe UI clicks, and search-like input
only. Captured endpoint metadata is redacted before it is returned to the
coordinator.
"""

import asyncio
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urljoin, urlparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._browser_scoped_context import (
    BrowserCoverageIncomplete,
    ScopedBrowserContext,
    attach_auth_loss_watch,
    browser_origin_policy,
    browser_scope_metadata,
    create_scoped_browser_context,
    has_browser_auth_material,
    incomplete_output,
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
    dedupe_keep_order,
    discover_site_metadata_urls,
    extract_html_map,
    fetch_text,
    normalize_url,
    parse_headers,
    redact_headers,
    same_origin,
)


API_PATH_RE = re.compile(r"/(?:api|rest|graphql|v\d+|rpc|users?|customers?|orders?|baskets?|carts?)(?:/|$)", re.I)
SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "csrf-token", "x-csrf-token"}
TOKEN_RE = re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|[A-Za-z0-9_\-]{32,})")


class BrowserTrafficCaptureTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "browser:traffic_capture"

    @property
    def description(self) -> str:
        return (
            "Uses a headless browser to capture exact-authorized-origin XHR/fetch/API traffic, "
            "storage keys, cookies, and parameterized endpoints for follow-up API "
            "access-control and IDOR probes."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "maxInteractions": {"type": "integer", "default": 14},
                "maxPages": {"type": "integer", "default": 12},
                "maxDepth": {"type": "integer", "default": 3},
                "timeoutSeconds": {"type": "integer", "default": 60},
                "maxOutputBytes": {"type": "integer", "default": 49152},
                "safeInteract": {"type": "boolean", "default": True},
                "fillSearchInputs": {"type": "boolean", "default": True},
                "searchTerms": {"type": "array", "items": {"type": "string"}, "default": ["juice", "test", "admin"]},
                "maxRequests": {"type": "integer", "default": 250},
                "maxBodyBytes": {"type": "integer", "default": 12000},
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
            "output_type": ["api_endpoints", "browser_traffic", "storage_keys"],
            "chainable_after": ["authentication:", "browser:map_app"],
            "chainable_before": ["api:", "param:", "surface:", "curl:", "nuclei:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        target = normalize_url(parameters.get("target") or parameters.get("url"))
        if not target:
            return {"success": False, "error": "target is required", "target": target}
        try:
            browser_origin_policy(parameters, target)
        except BrowserCoverageIncomplete as exc:
            return incomplete_output(target, exc)

        agent = parameters.get("_agent")
        timeout_seconds = max(15, min(int(parameters.get("timeoutSeconds") or 60), 180))
        budget = spa_traversal_budget(
            parameters,
            default_interactions=14,
            default_timeout_seconds=timeout_seconds,
        )
        max_requests = max(20, min(int(parameters.get("maxRequests") or 250), 1000))
        max_body_bytes = max(1000, min(int(parameters.get("maxBodyBytes") or 12000), 80000))

        if agent:
            agent.report_progress("Capturing browser API traffic", target, 0, None)

        try:
            from playwright.async_api import async_playwright
            from lib.process_reaper import close_browser_safe
        except Exception as exc:
            return await self._http_fallback(target, parameters, f"Playwright unavailable: {exc}")

        browser = None
        scoped = None
        page = None
        navigation = None
        records: List[Dict[str, Any]] = []
        request_meta: Dict[int, Dict[str, Any]] = {}
        response_tasks: List[asyncio.Task] = []
        capture_state = {"omittedRequests": 0}

        def record_request(request: Any) -> None:
            if len(records) >= max_requests:
                return
            try:
                url = str(request.url)
                if scoped is None or not scoped.url_is_authorized(url):
                    return
                try:
                    route_url = str(request.frame.url or "")
                except Exception:
                    route_url = ""
                meta = {
                    "method": str(request.method or "GET").upper(),
                    "url": url,
                    "resourceType": str(request.resource_type or ""),
                    "requestHeaders": redact_headers(dict(request.headers or {})),
                    "postDataSample": self._redact_text(request.post_data or "")[:1000],
                    "routeUrl": route_url if same_origin(target, route_url) else str(getattr(page, "url", target)),
                }
                request_meta[id(request)] = meta
            except Exception:
                return

        async def record_response(response: Any) -> None:
            if len(records) >= max_requests:
                capture_state["omittedRequests"] += 1
                return
            try:
                request = response.request
                url = str(response.url)
                if scoped is None or not scoped.url_is_authorized(url):
                    return
                method = str(request.method or "GET").upper()
                resource_type = str(request.resource_type or "")
                if resource_type not in {"xhr", "fetch"} and not self._looks_api(url):
                    return

                headers = {}
                try:
                    headers = await response.all_headers()
                except Exception:
                    headers = dict(getattr(response, "headers", {}) or {})

                content_type = str(headers.get("content-type") or headers.get("Content-Type") or "")
                body_sample = ""
                response_keys: List[str] = []
                if self._is_textual_content(content_type):
                    try:
                        raw = await response.body()
                        body_sample = self._redact_text(raw[:max_body_bytes].decode("utf-8", errors="replace").replace("\0", ""))
                        response_keys = self._json_keys(body_sample)
                    except Exception:
                        body_sample = ""

                meta = request_meta.get(id(request), {})
                record = {
                    "method": method,
                    "url": url,
                    "path": self._path_with_query_shape(url),
                    "status": int(response.status),
                    "resourceType": resource_type,
                    "contentType": content_type.split(";")[0].strip(),
                    "queryParameters": [name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)],
                    "requestBodyKeys": self._request_body_keys(meta.get("postDataSample", "")),
                    "responseKeys": response_keys,
                    "requestHeaders": meta.get("requestHeaders") or redact_headers(dict(request.headers or {})),
                    "responseHeaders": redact_headers(headers),
                    "requestSample": meta.get("postDataSample", ""),
                    "responseSample": body_sample[:2500],
                    "apiLike": self._looks_api(url),
                    "routeUrl": meta.get("routeUrl") or str(getattr(page, "url", target)),
                }
                if len(records) >= max_requests:
                    capture_state["omittedRequests"] += 1
                    return
                records.append(record)
            except Exception:
                return

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
                scoped = await create_scoped_browser_context(browser, target, parameters)
                context = scoped.context
                page = await context.new_page()
                attach_auth_loss_watch(scoped, page)
                page.set_default_timeout(timeout_seconds * 1000)
                page.on("request", record_request)
                page.on("response", lambda response: response_tasks.append(asyncio.create_task(record_response(response))))

                navigation = await page.goto(
                    target,
                    wait_until="domcontentloaded",
                    timeout=timeout_seconds * 1000,
                )
                await validate_authenticated_navigation(scoped, page, navigation, target)
                await self._quiet_network(page, timeout_seconds)

                search_terms = parameters.get("searchTerms")
                search_term = (
                    str(search_terms[0])[:80]
                    if isinstance(search_terms, list) and search_terms
                    else "test"
                )
                traversal = await traverse_bounded_spa(
                    page,
                    scoped,
                    target,
                    budget,
                    root_navigation=navigation,
                    safe_interact=bool(parameters.get("safeInteract", True)),
                    fill_search_inputs=bool(parameters.get("fillSearchInputs", True)),
                    search_term=search_term,
                )

                if response_tasks:
                    await asyncio.gather(*response_tasks, return_exceptions=True)

                storage = await self._storage_summary(page)
                form_contract = build_native_probe_form_contract(
                    traversal.get("forms", []),
                    source="browser:traffic_capture",
                )
                for public_form, observed_form in zip(
                    form_contract["forms"],
                    traversal.get("forms", []),
                ):
                    public_form["routeUrl"] = observed_form.get("routeUrl")
                traversal["forms"] = form_contract["forms"]
                traversal[NATIVE_PROBE_PRIVATE_CANDIDATES_KEY] = form_contract[
                    NATIVE_PROBE_PRIVATE_CANDIDATES_KEY
                ]
                await context.close()
                await close_browser_safe(browser)

            output = self._build_output(
                target,
                traversal,
                records,
                storage,
                agent,
                omitted_requests=int(capture_state["omittedRequests"]),
                scope_metadata=scoped.scope_metadata(),
            )
            # Authenticated browser material stays inside the native Playwright
            # cookie jar/header context.  Do not replay it through aiohttp,
            # whose redirect semantics are outside the exact-origin router.
            if not has_browser_auth_material(parameters):
                await self._enrich_with_site_metadata(
                    output,
                    target,
                    parameters,
                    scoped,
                )
            return enforce_public_output_cap(
                output,
                budget.max_output_bytes,
                removable_lists=(
                    "xhrRequests",
                    "siteMapUrls",
                    "parameterizedUrls",
                    "interactionDiagnostics",
                    "linkObservations",
                    "scriptObservations",
                    "visitedStates",
                    "routes",
                    "apiEndpoints",
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
            return await self._http_fallback(target, parameters, f"browser traffic capture failed: {exc}")

    async def _quiet_network(self, page: Any, timeout_seconds: int) -> None:
        try:
            await page.wait_for_load_state("networkidle", timeout=max(3000, min(timeout_seconds * 1000, 12000)))
        except Exception:
            await page.wait_for_timeout(1200)

    async def _storage_summary(self, page: Any) -> Dict[str, Any]:
        try:
            return await page.evaluate(
                """() => {
                  const summarize = (store) => Array.from({length: store.length}, (_, index) => {
                    const key = store.key(index);
                    const value = key ? store.getItem(key) || '' : '';
                    return {
                      key,
                      valueLength: value.length,
                      tokenLike: /^eyJ/.test(value) || value.length > 80,
                      jsonLike: /^[\\[{]/.test(value.trim())
                    };
                  }).filter(Boolean).slice(0, 80);
                  return {
                    localStorage: summarize(window.localStorage),
                    sessionStorage: summarize(window.sessionStorage),
                    cookieCount: document.cookie ? document.cookie.split(';').filter(Boolean).length : 0,
                    cookieNames: document.cookie ? document.cookie.split(';').map(c => c.split('=')[0].trim()).filter(Boolean).slice(0, 80) : []
                  };
                }"""
            )
        except Exception:
            return {"localStorage": [], "sessionStorage": [], "cookieCount": 0, "cookieNames": []}

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
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=30)) as session:
            current_url = target
            fetched = None
            redirects: List[str] = []
            for _ in range(6):
                fetched = await fetch_text(
                    session,
                    current_url,
                    headers=parse_headers(parameters),
                    max_bytes=900_000,
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
                    output = incomplete_output(
                        target,
                        BrowserCoverageIncomplete(
                            "CROSS_ORIGIN_REDIRECT_BLOCKED",
                            "redirect left the authorized origin",
                        ),
                        final_url=current_url,
                        status=status,
                    )
                    output["scopeMetadata"] = browser_scope_metadata(
                        policy,
                        blocked_urls=[next_url],
                        blocked_navigation_count=1,
                    )
                    return output
                redirects.append(next_url)
                current_url = next_url
            else:
                return incomplete_output(
                    target,
                    BrowserCoverageIncomplete(
                        "REDIRECT_LIMIT_EXCEEDED",
                        "same-origin redirect limit exceeded",
                    ),
                    final_url=current_url,
                )
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
        # Authenticated fallback is rejected above. Metadata discovery here is
        # anonymous and therefore cannot leak session headers on redirects.
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=25)) as session:
            site_map_urls = await discover_site_metadata_urls(
                session,
                target,
                headers=parse_headers(parameters),
                max_urls=500,
            )
        blocked_urls.extend(
            str(value)
            for value in site_map_urls
            if not policy.url_is_authorized(str(value))
        )
        site_map_urls = [
            value for value in site_map_urls if policy.url_is_authorized(str(value))
        ]
        api_links = [url for url in mapped.get("links", []) + mapped.get("scripts", []) if self._looks_api(url)]
        api_endpoints = [self._endpoint_from_url("GET", url, None) for url in dedupe_keep_order(api_links, 80)]
        parameterized_urls = [
            url
            for url in mapped.get("links", []) + site_map_urls
            if "?" in url and same_origin(target, url)
        ]
        return {
            "success": True,
            "target": target,
            "fallback": True,
            "fallbackReason": reason,
            "finalUrl": fetched.get("url"),
            "status": fetched.get("status"),
            "apiEndpoints": api_endpoints,
            "xhrRequests": [],
            "siteMapUrls": site_map_urls,
            "parameterizedUrls": dedupe_keep_order(parameterized_urls, 300),
            "forms": mapped.get("forms", []),
            NATIVE_PROBE_PRIVATE_CANDIDATES_KEY: mapped.get(
                NATIVE_PROBE_PRIVATE_CANDIDATES_KEY,
                [],
            ),
            "storage": {"localStorage": [], "sessionStorage": [], "cookieCount": 0, "cookieNames": []},
            "scopeMetadata": browser_scope_metadata(
                policy,
                blocked_urls=blocked_urls,
            ),
            "summary": {
                "apiEndpoints": len(api_endpoints),
                "xhrRequests": 0,
                "siteMapUrls": len(site_map_urls),
                "parameterizedUrls": len(dedupe_keep_order(parameterized_urls, 300)),
                "storageKeys": 0,
            },
            "recommendations": ["Playwright was unavailable; run browser:traffic_capture on an agent with browser support for SPA API traffic."],
        }

    def _build_output(
        self,
        target: str,
        html_map: Dict[str, Any],
        records: List[Dict[str, Any]],
        storage: Dict[str, Any],
        agent: Any,
        *,
        omitted_requests: int = 0,
        scope_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        xhr_requests = self._dedupe_records(
            [r for r in records if r.get("resourceType") in {"xhr", "fetch"} or r.get("apiLike")]
        )
        endpoint_keys = []
        endpoints = []
        for record in xhr_requests:
            endpoint = self._endpoint_from_url(str(record.get("method") or "GET"), str(record.get("url") or ""), record)
            key = f"{endpoint['method']} {endpoint['path']}"
            if key in endpoint_keys:
                continue
            endpoint_keys.append(key)
            endpoints.append(endpoint)

        parameterized_urls = dedupe_keep_order(
            [str(r.get("url")) for r in xhr_requests if r.get("queryParameters")]
            + [str(form.get("action")) for form in html_map.get("forms", []) if "?" in str(form.get("action") or "")],
            250,
        )
        recommendations = []
        if endpoints:
            recommendations.append("Pass apiEndpoints to api:access_control_probe to test public/private API boundaries and IDOR-like object references.")
        if parameterized_urls:
            recommendations.append("Pass parameterizedUrls to param:exploit_probe for bounded LFI, redirect, XSS, SQLi, CRLF, and command evidence probes.")
        if storage.get("localStorage") or storage.get("sessionStorage"):
            recommendations.append("Inspect token-like storage keys during authenticated testing; do not expose token values in reports.")

        output = {
            "success": html_map.get("coverageStatus") != "INCOMPLETE",
            "coverageStatus": html_map.get("coverageStatus"),
            "coverageReason": html_map.get("coverageReason"),
            "verified": html_map.get("coverageStatus") != "INCOMPLETE",
            "target": target,
            "finalUrl": (html_map.get("visitedStates") or [{}])[-1].get("routeUrl"),
            "title": (html_map.get("visitedStates") or [{}])[0].get("title"),
            "apiEndpoints": endpoints[:300],
            "xhrRequests": xhr_requests[:300],
            "siteMapUrls": [],
            "parameterizedUrls": parameterized_urls,
            "forms": html_map.get("forms", []),
            NATIVE_PROBE_PRIVATE_CANDIDATES_KEY: html_map.get(
                NATIVE_PROBE_PRIVATE_CANDIDATES_KEY,
                [],
            ),
            "storage": storage,
            "visitedStates": html_map.get("visitedStates", []),
            "routes": list(
                dict.fromkeys(
                    str(item.get("routeUrl") or "")
                    for item in html_map.get("visitedStates", [])
                    if item.get("routeUrl")
                )
            ),
            "linkObservations": html_map.get("linkObservations", []),
            "scriptObservations": html_map.get("scriptObservations", []),
            "interactionDiagnostics": html_map.get("interactionDiagnostics", []),
            "scopeMetadata": scope_metadata or {},
            "coverage": {
                key: html_map.get(key)
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
                    "blockersObserved",
                    "blockersAcknowledged",
                    "navigationFallbacks",
                    "elapsedMs",
                    "artifactBytes",
                    "budget",
                )
            },
            "summary": {
                "apiEndpoints": len(endpoints),
                "xhrRequests": len(xhr_requests),
                "siteMapUrls": 0,
                "parameterizedUrls": len(parameterized_urls),
                "forms": len(html_map.get("forms", [])),
                "localStorageKeys": len(storage.get("localStorage", [])),
                "sessionStorageKeys": len(storage.get("sessionStorage", [])),
                "cookieNames": len(storage.get("cookieNames", [])),
                "visitedStates": html_map.get("pagesObserved", 0),
                "routes": len(
                    {
                        str(item.get("routeUrl") or "")
                        for item in html_map.get("visitedStates", [])
                        if item.get("routeUrl")
                    }
                ),
                "interactions": html_map.get("interactionsUsed", 0),
                "blockersAcknowledged": html_map.get(
                    "blockersAcknowledged", 0
                ),
                "navigationFallbacks": html_map.get("navigationFallbacks", 0),
                "truncated": bool(html_map.get("truncated")) or omitted_requests > 0,
                "omittedStates": html_map.get("omittedStates", 0),
                "omittedRequests": omitted_requests,
            },
            "recommendations": recommendations,
        }
        if omitted_requests:
            output["coverage"]["truncated"] = True
            output["coverage"]["exhaustiveWithinBounds"] = False
            truncated_by = output["coverage"].setdefault("truncatedBy", [])
            if "maxRequests" not in truncated_by:
                truncated_by.append("maxRequests")
            if output["coverageStatus"] != "INCOMPLETE":
                output["coverageStatus"] = "CONFIRMED"
                output["coverageReason"] = "BOUNDED_SPA_CAP_REACHED"
        if agent:
            summary = output["summary"]
            agent.append_output(
                f"[browser:traffic_capture] apiEndpoints={summary['apiEndpoints']} xhr={summary['xhrRequests']} params={summary['parameterizedUrls']}"
            )
            agent.report_progress("Browser API traffic capture completed", target, 1, 1)
        return output

    def _dedupe_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: List[Dict[str, Any]] = []
        by_key: Dict[str, Dict[str, Any]] = {}
        for record in records:
            key = json.dumps(
                [
                    record.get("method"),
                    record.get("url"),
                    record.get("status"),
                    record.get("resourceType"),
                    record.get("requestBodyKeys"),
                    record.get("responseKeys"),
                ],
                sort_keys=True,
                separators=(",", ":"),
            )
            route_url = str(record.get("routeUrl") or "")
            if key in by_key:
                routes = by_key[key].setdefault("observedAtRoutes", [])
                if route_url and route_url not in routes:
                    routes.append(route_url)
                continue
            row = dict(record)
            row["observedAtRoutes"] = [route_url] if route_url else []
            by_key[key] = row
            deduped.append(row)
        return deduped

    async def _enrich_with_site_metadata(
        self,
        output: Dict[str, Any],
        target: str,
        parameters: Dict[str, Any],
        scoped: ScopedBrowserContext,
    ) -> None:
        connector = aiohttp.TCPConnector(ssl=False)
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=25)) as session:
                site_map_urls = await discover_site_metadata_urls(
                    session,
                    target,
                    headers=parse_headers(parameters),
                    max_urls=500,
                )
        except Exception:
            site_map_urls = []
        rejected = [
            value
            for value in site_map_urls
            if not scoped.url_is_authorized(str(value))
        ]
        for value in rejected:
            scoped.note_blocked_url(str(value))
        site_map_urls = [
            value
            for value in site_map_urls
            if scoped.url_is_authorized(str(value))
        ]
        output["scopeMetadata"] = scoped.scope_metadata()
        if not site_map_urls:
            return
        output["siteMapUrls"] = site_map_urls
        output["parameterizedUrls"] = dedupe_keep_order(
            list(output.get("parameterizedUrls") or []) + [url for url in site_map_urls if "?" in url],
            300,
        )
        output.setdefault("summary", {})["siteMapUrls"] = len(site_map_urls)
        output["summary"]["parameterizedUrls"] = len(output.get("parameterizedUrls") or [])
        output.setdefault("recommendations", []).append(
            "Use siteMapUrls as crawl seeds when the homepage is generated from public JSON or sitemap metadata."
        )

    def _endpoint_from_url(self, method: str, url: str, record: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        parsed = urlparse(url)
        return {
            "method": method.upper(),
            "url": url,
            "path": self._path_with_query_shape(url),
            "pathOnly": parsed.path or "/",
            "queryParameters": [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)],
            "status": record.get("status") if record else None,
            "resourceType": record.get("resourceType") if record else None,
            "contentType": record.get("contentType") if record else None,
            "requestBodyKeys": record.get("requestBodyKeys") if record else [],
            "responseKeys": record.get("responseKeys") if record else [],
            "observedAtRoutes": record.get("observedAtRoutes") if record else [],
            "sensitiveHint": self._sensitive_hint(url),
        }

    def _path_with_query_shape(self, url: str) -> str:
        parsed = urlparse(url)
        names = [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        if names:
            return f"{parsed.path or '/'}?{'&'.join(f'{name}=*' for name in names)}"
        return parsed.path or "/"

    def _looks_api(self, url: str) -> bool:
        parsed = urlparse(str(url))
        return bool(API_PATH_RE.search(parsed.path or "")) or parsed.path.endswith((".json", ".graphql"))

    def _sensitive_hint(self, url: str) -> bool:
        lowered = urlparse(str(url)).path.lower()
        return any(marker in lowered for marker in ["user", "account", "order", "basket", "cart", "profile", "admin", "token", "wallet"])

    def _is_textual_content(self, content_type: str) -> bool:
        lowered = str(content_type or "").lower()
        return any(marker in lowered for marker in ["json", "text", "javascript", "xml", "html", "graphql"])

    def _json_keys(self, body_sample: str) -> List[str]:
        try:
            parsed = json.loads(body_sample)
        except Exception:
            return []
        keys: List[str] = []

        def walk(value: Any, prefix: str = "") -> None:
            if len(keys) >= 60:
                return
            if isinstance(value, dict):
                for key, child in value.items():
                    key_path = f"{prefix}.{key}" if prefix else str(key)
                    keys.append(key_path)
                    walk(child, key_path)
            elif isinstance(value, list) and value:
                walk(value[0], prefix)

        walk(parsed)
        return dedupe_keep_order(keys, 60)

    def _request_body_keys(self, body_sample: str) -> List[str]:
        if not body_sample:
            return []
        try:
            parsed = json.loads(body_sample)
            if isinstance(parsed, dict):
                return list(parsed.keys())[:60]
        except Exception:
            pass
        return [name for name, _ in parse_qsl(body_sample, keep_blank_values=True)][:60]

    def _redact_text(self, value: str) -> str:
        if not value:
            return ""
        redacted = str(value)
        for header in SENSITIVE_HEADER_NAMES:
            redacted = re.sub(rf"({re.escape(header)}\s*[=:]\s*)[^&\s,;]+", r"\1***REDACTED***", redacted, flags=re.I)
        return TOKEN_RE.sub(lambda match: f"{match.group(0)[:6]}...{match.group(0)[-4:]}", redacted)


def get_tool():
    return BrowserTrafficCaptureTool()
