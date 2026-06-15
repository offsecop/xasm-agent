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
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urljoin, urlparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    RISKY_CLICK_WORDS,
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
            "Uses a headless browser to capture same-origin XHR/fetch/API traffic, "
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
                "timeoutSeconds": {"type": "integer", "default": 60},
                "safeInteract": {"type": "boolean", "default": True},
                "fillSearchInputs": {"type": "boolean", "default": True},
                "searchTerms": {"type": "array", "items": {"type": "string"}, "default": ["juice", "test", "admin"]},
                "maxRequests": {"type": "integer", "default": 250},
                "maxBodyBytes": {"type": "integer", "default": 12000},
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
            "output_type": ["api_endpoints", "browser_traffic", "storage_keys"],
            "chainable_after": ["authentication:", "browser:map_app"],
            "chainable_before": ["api:", "param:", "surface:", "curl:", "nuclei:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        target = normalize_url(parameters.get("target") or parameters.get("url"))
        if not target:
            return {"success": False, "error": "target is required", "target": target}

        agent = parameters.get("_agent")
        timeout_seconds = max(15, min(int(parameters.get("timeoutSeconds") or 60), 180))
        max_interactions = max(0, min(int(parameters.get("maxInteractions") or 14), 60))
        max_requests = max(20, min(int(parameters.get("maxRequests") or 250), 1000))
        max_body_bytes = max(1000, min(int(parameters.get("maxBodyBytes") or 12000), 80000))

        if agent:
            agent.report_progress("Capturing browser API traffic", target, 0, None)

        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            return await self._http_fallback(target, parameters, f"Playwright unavailable: {exc}")

        browser = None
        records: List[Dict[str, Any]] = []
        request_meta: Dict[int, Dict[str, Any]] = {}
        response_tasks: List[asyncio.Task] = []

        def record_request(request: Any) -> None:
            if len(records) >= max_requests:
                return
            try:
                url = str(request.url)
                if not same_origin(target, url) and not self._looks_api(url):
                    return
                meta = {
                    "method": str(request.method or "GET").upper(),
                    "url": url,
                    "resourceType": str(request.resource_type or ""),
                    "requestHeaders": redact_headers(dict(request.headers or {})),
                    "postDataSample": self._redact_text(request.post_data or "")[:1000],
                }
                request_meta[id(request)] = meta
            except Exception:
                return

        async def record_response(response: Any) -> None:
            if len(records) >= max_requests:
                return
            try:
                request = response.request
                url = str(response.url)
                if not same_origin(target, url):
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
                }
                records.append(record)
            except Exception:
                return

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
                context = await browser.new_context(ignore_https_errors=True, extra_http_headers=parse_headers(parameters))
                page = await context.new_page()
                page.set_default_timeout(timeout_seconds * 1000)
                page.on("request", record_request)
                page.on("response", lambda response: response_tasks.append(asyncio.create_task(record_response(response))))

                await page.goto(target, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
                await self._quiet_network(page, timeout_seconds)

                if bool(parameters.get("fillSearchInputs", True)):
                    await self._exercise_search_inputs(page, parameters)
                    await self._quiet_network(page, min(timeout_seconds, 20))

                if bool(parameters.get("safeInteract", True)) and max_interactions > 0:
                    await self._safe_interactions(page, target, max_interactions)
                    await self._quiet_network(page, min(timeout_seconds, 20))

                if response_tasks:
                    await asyncio.gather(*response_tasks, return_exceptions=True)

                storage = await self._storage_summary(page)
                html_map = await page.evaluate(
                    """() => ({
                      title: document.title || '',
                      url: location.href,
                      forms: Array.from(document.forms).map(f => ({
                        action: new URL(f.getAttribute('action') || location.href, location.href).href,
                        method: (f.getAttribute('method') || 'GET').toUpperCase(),
                        fields: Array.from(f.querySelectorAll('input, textarea, select')).map(i => ({
                          name: i.getAttribute('name') || i.id || '',
                          type: (i.getAttribute('type') || i.tagName || 'text').toLowerCase()
                        })).filter(i => i.name || ['password','email','search','file'].includes(i.type)),
                      })).slice(0, 100)
                    })"""
                )
                await context.close()
                await browser.close()

            output = self._build_output(target, html_map, records, storage, agent)
            await self._enrich_with_site_metadata(output, target, parameters)
            return output
        except Exception as exc:
            if browser:
                try:
                    await browser.close()
                except Exception:
                    pass
            return await self._http_fallback(target, parameters, f"browser traffic capture failed: {exc}")

    async def _quiet_network(self, page: Any, timeout_seconds: int) -> None:
        try:
            await page.wait_for_load_state("networkidle", timeout=max(3000, min(timeout_seconds * 1000, 12000)))
        except Exception:
            await page.wait_for_timeout(1200)

    async def _exercise_search_inputs(self, page: Any, parameters: Dict[str, Any]) -> None:
        search_terms = parameters.get("searchTerms")
        if not isinstance(search_terms, list) or not search_terms:
            search_terms = ["juice", "test", "admin"]
        term = str(search_terms[0])[:80]
        selectors = [
            'input[type="search"]',
            'input[name*="search" i]',
            'input[id*="search" i]',
            'input[placeholder*="search" i]',
            'input[name="q"]',
            'input[name="query"]',
        ]
        for selector in selectors:
            try:
                locator = page.locator(selector).first
                if await locator.count() == 0:
                    continue
                await locator.fill(term, timeout=1200)
                await locator.press("Enter", timeout=1200)
                return
            except Exception:
                continue

    async def _safe_interactions(self, page: Any, target: str, max_interactions: int) -> None:
        clicked = 0
        locators = await page.locator("button, [role=button], a").all()
        for locator in locators[: max_interactions * 4]:
            if clicked >= max_interactions:
                break
            try:
                label = (await locator.inner_text(timeout=700)).strip()[:120]
                href = await locator.get_attribute("href", timeout=700)
                lowered = label.lower()
                if any(word in lowered for word in RISKY_CLICK_WORDS):
                    continue
                if href and not href.startswith("#") and not same_origin(target, urljoin(page.url, href)):
                    continue
                before_url = page.url
                await locator.click(timeout=1300, no_wait_after=True)
                clicked += 1
                await page.wait_for_timeout(600)
                if page.url != before_url and same_origin(target, page.url):
                    try:
                        await page.go_back(wait_until="domcontentloaded", timeout=3000)
                    except Exception:
                        pass
            except Exception:
                continue

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
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=30)) as session:
            fetched = await fetch_text(session, target, headers=parse_headers(parameters), max_bytes=900_000)
        mapped = extract_html_map(fetched.get("text", ""), fetched.get("url") or target)
        site_map_urls = await discover_site_metadata_urls(session, target, headers=parse_headers(parameters), max_urls=500)
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
            "storage": {"localStorage": [], "sessionStorage": [], "cookieCount": 0, "cookieNames": []},
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
    ) -> Dict[str, Any]:
        same_origin_records = [r for r in records if same_origin(target, str(r.get("url") or ""))]
        xhr_requests = [r for r in same_origin_records if r.get("resourceType") in {"xhr", "fetch"} or r.get("apiLike")]
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
            "success": True,
            "target": target,
            "finalUrl": html_map.get("url"),
            "title": html_map.get("title"),
            "apiEndpoints": endpoints[:300],
            "xhrRequests": xhr_requests[:300],
            "siteMapUrls": [],
            "parameterizedUrls": parameterized_urls,
            "forms": html_map.get("forms", []),
            "storage": storage,
            "summary": {
                "apiEndpoints": len(endpoints),
                "xhrRequests": len(xhr_requests),
                "siteMapUrls": 0,
                "parameterizedUrls": len(parameterized_urls),
                "forms": len(html_map.get("forms", [])),
                "localStorageKeys": len(storage.get("localStorage", [])),
                "sessionStorageKeys": len(storage.get("sessionStorage", [])),
                "cookieNames": len(storage.get("cookieNames", [])),
            },
            "recommendations": recommendations,
        }
        if agent:
            summary = output["summary"]
            agent.append_output(
                f"[browser:traffic_capture] apiEndpoints={summary['apiEndpoints']} xhr={summary['xhrRequests']} params={summary['parameterizedUrls']}"
            )
            agent.report_progress("Browser API traffic capture completed", target, 1, 1)
        return output

    async def _enrich_with_site_metadata(self, output: Dict[str, Any], target: str, parameters: Dict[str, Any]) -> None:
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
