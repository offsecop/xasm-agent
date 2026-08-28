"""
Passive parameter discovery and classification for agentic exploration.
"""

import os
import tempfile
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    NATIVE_PROBE_PRIVATE_CANDIDATES_KEY,
    NATIVE_PROBE_QUERY_CANDIDATES_KEY,
    build_native_probe_query_contract,
    classify_parameters,
    dedupe_keep_order,
    extract_html_map,
    fetch_text,
    normalize_url,
    parse_headers,
    run_process,
    sanitize_native_probe_public_url,
    same_origin,
)


class ParamDiscoverTool(ToolPlugin):
    _TRANSIENT_PAGE_STATUSES = {408, 425, 429, *range(500, 600)}

    @property
    def name(self) -> str:
        return "param:discover"

    @property
    def description(self) -> str:
        return "Passively extracts and classifies parameters from URLs/forms, with optional bounded Arjun probing for hidden parameters."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "urls": {"type": "array", "items": {"type": "string"}},
                "forms": {"type": "array", "items": {"type": "object"}},
                "activeArjun": {"type": "boolean", "default": False},
                "discoverFromTarget": {"type": "boolean", "default": True},
                "maxPages": {"type": "integer", "default": 20},
                "maxTargets": {"type": "integer", "default": 10},
                "cookie": {"type": "string"},
                "authCookies": {"type": "string"},
                "headers": {"type": "object"},
                "authHeaders": {"type": "object"},
            },
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}, {"required": ["urls"]}],
        }

    @property
    def metadata(self):
        return {
            "category": "agentic-recon",
            "phase": 2,
            "domain": ["web", "api"],
            "input_type": ["url", "urls", "forms"],
            "output_type": ["parameters", "urls_with_params"],
            "chainable_after": ["browser:", "js:", "katana:", "waybackurls:"],
            "chainable_before": ["dalfox:", "sqlmap:", "nuclei:", "curl:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        urls: List[str] = []
        if isinstance(parameters.get("urls"), list):
            urls.extend(str(u) for u in parameters["urls"] if u)
        target = parameters.get("target") or parameters.get("url")
        if target:
            urls.insert(0, normalize_url(target))
        if not urls:
            return {"success": False, "error": "target/url or urls is required"}

        forms = parameters.get("forms") if isinstance(parameters.get("forms"), list) else []
        private_probe_candidates: List[Dict[str, Any]] = []
        page_fetches: List[Dict[str, Any]] = []
        if bool(parameters.get("discoverFromTarget", True)) and target:
            discovered = await self._discover_from_target(normalize_url(target), parameters)
            urls.extend(discovered.get("urls", []))
            forms.extend(discovered.get("forms", []))
            page_fetches.extend(discovered.get("pageFetches", []))
            private_probe_candidates.extend(
                discovered.get(NATIVE_PROBE_PRIVATE_CANDIDATES_KEY, [])
            )

        max_targets = max(1, min(int(parameters.get("maxTargets") or 50), 200))
        urls = dedupe_keep_order(urls, max_targets)
        query_origin = normalize_url(target or urls[0])
        same_origin_query_urls = [
            url for url in urls if same_origin(query_origin, url)
        ]
        query_contract = build_native_probe_query_contract(
            same_origin_query_urls,
            source="param:discover",
        )
        private_probe_candidates.extend(
            query_contract.get(NATIVE_PROBE_PRIVATE_CANDIDATES_KEY, [])
        )
        public_urls = [
            sanitize_native_probe_public_url(url) if "?" in url else url
            for url in urls
        ]
        passive = classify_parameters(public_urls, forms)

        arjun_results = []
        if bool(parameters.get("activeArjun", False)):
            for url in public_urls[:max_targets]:
                headers_file = None
                cmd = ["arjun", "-u", url, "-m", "GET", "--stable", "-oJ", "-"]
                cookie = parameters.get("cookie") or parameters.get("authCookies")
                if cookie:
                    fd, headers_file = tempfile.mkstemp(prefix="xasm_arjun_headers_", suffix=".txt")
                    with os.fdopen(fd, "w") as f:
                        f.write(f"Cookie: {cookie}\n")
                    cmd.extend(["--headers", headers_file])
                try:
                    output = await run_process(cmd, timeout=120)
                    arjun_results.append({"url": url, **output})
                finally:
                    if headers_file:
                        try:
                            os.unlink(headers_file)
                        except OSError:
                            pass

        recommendations = []
        for item in passive.get("interestingParameters", []):
            cats = item.get("categories", [])
            if "search_xss_candidate" in cats:
                recommendations.append({"tool": "dalfox:xss_scan", "url": item.get("url"), "reason": f"parameter {item.get('name')} looks search/reflection related"})
            if "idor_candidate" in cats:
                recommendations.append({"tool": "curl:request", "url": item.get("url"), "reason": f"parameter {item.get('name')} looks object-reference related"})
            if "redirect_or_ssrf" in cats:
                recommendations.append({"tool": "nuclei:dast_scan", "url": item.get("url"), "reason": f"parameter {item.get('name')} may accept URLs/redirects"})
            if "file_path_candidate" in cats:
                recommendations.append({"tool": "nuclei:dast_scan", "url": item.get("url"), "reason": f"parameter {item.get('name')} may influence file/path handling"})

        return {
            "success": True,
            "targets": public_urls,
            "forms": forms[:200],
            "pageFetches": page_fetches[:200],
            NATIVE_PROBE_QUERY_CANDIDATES_KEY: query_contract.get(
                NATIVE_PROBE_QUERY_CANDIDATES_KEY, []
            ),
            NATIVE_PROBE_PRIVATE_CANDIDATES_KEY: private_probe_candidates[:250],
            **passive,
            "activeArjun": arjun_results,
            "recommendations": recommendations[:100],
            "summary": {
                "urlsAnalyzed": len(urls),
                "urlsWithParams": len(passive.get("urlsWithParams", [])),
                "parameters": passive.get("parameterCount", 0),
                "interesting": len(passive.get("interestingParameters", [])),
                "formFields": len(passive.get("formFields", [])),
                "recommendations": len(recommendations),
                "nativeQueryCandidates": len(
                    query_contract.get(NATIVE_PROBE_QUERY_CANDIDATES_KEY, [])
                ),
                "pagesFetched": sum(
                    1 for item in page_fetches if item.get("outcome") == "mapped"
                ),
                "pagesFailed": sum(
                    1 for item in page_fetches if item.get("outcome") != "mapped"
                ),
                "pageFetchAttempts": sum(
                    int(item.get("attempts") or 0) for item in page_fetches
                ),
            },
        }

    def _public_page_url(self, value: str) -> str:
        try:
            parsed = urlparse(str(value or ""))
            host = parsed.hostname or ""
            if not host:
                return ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            if parsed.port:
                host = f"{host}:{parsed.port}"
            return urlunparse((parsed.scheme, host, parsed.path or "/", "", "", ""))
        except (TypeError, ValueError):
            return ""

    def _fetch_error_class(self, error: Exception) -> str:
        if isinstance(error, aiohttp.ClientConnectionError):
            return "connection_error"
        if isinstance(error, aiohttp.ClientError):
            return "client_error"
        if isinstance(error, TimeoutError):
            return "timeout"
        if isinstance(error, OSError):
            return "network_error"
        return "fetch_error"

    def _page_fetch_urls(
        self,
        urls: List[str],
        target: str,
        max_pages: int,
    ) -> List[str]:
        output: List[str] = []
        seen = set()
        for value in urls:
            try:
                parsed = urlparse(str(value or ""))
                fetch_url = urlunparse(parsed._replace(fragment=""))
            except (TypeError, ValueError):
                continue
            if not fetch_url or not same_origin(target, fetch_url) or fetch_url in seen:
                continue
            seen.add(fetch_url)
            output.append(fetch_url)
            if len(output) >= max_pages:
                break
        return output

    async def _fetch_page_map(
        self,
        session: aiohttp.ClientSession,
        url: str,
        headers: Dict[str, str],
        max_bytes: int,
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        public_url = self._public_page_url(url)
        attempts = 0
        for attempt in range(1, 3):
            attempts = attempt
            try:
                fetched = await fetch_text(
                    session,
                    url,
                    headers=headers,
                    max_bytes=max_bytes,
                )
            except (aiohttp.ClientError, TimeoutError, OSError) as error:
                if attempt == 1:
                    continue
                return None, {
                    "url": public_url,
                    "status": 0,
                    "attempts": attempts,
                    "outcome": "fetch_error",
                    "errorClass": self._fetch_error_class(error),
                    "mappedLinks": 0,
                    "mappedForms": 0,
                    "mappedQueryUrls": 0,
                }
            except Exception as error:
                return None, {
                    "url": public_url,
                    "status": 0,
                    "attempts": attempts,
                    "outcome": "fetch_error",
                    "errorClass": self._fetch_error_class(error),
                    "mappedLinks": 0,
                    "mappedForms": 0,
                    "mappedQueryUrls": 0,
                }

            status = int(fetched.get("status") or 0)
            if status in self._TRANSIENT_PAGE_STATUSES and attempt == 1:
                continue
            if not 200 <= status < 400:
                return None, {
                    "url": public_url,
                    "status": status,
                    "attempts": attempts,
                    "outcome": (
                        "transient_http"
                        if status in self._TRANSIENT_PAGE_STATUSES
                        else "terminal_http"
                    ),
                    "errorClass": None,
                    "mappedLinks": 0,
                    "mappedForms": 0,
                    "mappedQueryUrls": 0,
                }
            if not same_origin(url, str(fetched.get("url") or url)):
                return None, {
                    "url": public_url,
                    "status": status,
                    "attempts": attempts,
                    "outcome": "cross_origin_redirect",
                    "errorClass": None,
                    "mappedLinks": 0,
                    "mappedForms": 0,
                    "mappedQueryUrls": 0,
                }

            try:
                mapped = extract_html_map(
                    fetched.get("text", ""),
                    fetched.get("url") or url,
                )
            except Exception:
                return None, {
                    "url": public_url,
                    "status": status,
                    "attempts": attempts,
                    "outcome": "parse_error",
                    "errorClass": "parse_error",
                    "mappedLinks": 0,
                    "mappedForms": 0,
                    "mappedQueryUrls": 0,
                }
            return mapped, {
                "url": public_url,
                "status": status,
                "attempts": attempts,
                "outcome": "mapped",
                "errorClass": None,
                "mappedLinks": len(mapped.get("links", [])),
                "mappedForms": len(mapped.get("forms", [])),
                "mappedQueryUrls": len(mapped.get("parameterizedUrls", [])),
            }

        return None, {
            "url": public_url,
            "status": 0,
            "attempts": attempts,
            "outcome": "fetch_error",
            "errorClass": "fetch_error",
            "mappedLinks": 0,
            "mappedForms": 0,
            "mappedQueryUrls": 0,
        }

    async def _discover_from_target(self, target: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        max_pages = max(1, min(int(parameters.get("maxPages") or 20), 50))
        urls: List[str] = [target]
        forms: List[Dict[str, Any]] = []
        page_fetches: List[Dict[str, Any]] = []
        private_probe_candidates: List[Dict[str, Any]] = []
        headers = parse_headers(parameters)
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as session:
            mapped, coverage = await self._fetch_page_map(
                session,
                target,
                headers,
                1_000_000,
            )
            page_fetches.append(coverage)
            if mapped:
                urls.extend([u for u in mapped.get("links", []) if same_origin(target, u)])
                urls.extend([u for u in mapped.get("parameterizedUrls", []) if same_origin(target, u)])
                forms.extend(mapped.get("forms", []))
                private_probe_candidates.extend(
                    mapped.get(NATIVE_PROBE_PRIVATE_CANDIDATES_KEY, [])
                )
            else:
                return {
                    "urls": urls,
                    "forms": forms,
                    "pageFetches": page_fetches,
                    NATIVE_PROBE_PRIVATE_CANDIDATES_KEY: private_probe_candidates,
                }

            for url in self._page_fetch_urls(urls, target, max_pages):
                if url == target or not same_origin(target, url):
                    continue
                mapped, coverage = await self._fetch_page_map(
                    session,
                    url,
                    headers,
                    800_000,
                )
                page_fetches.append(coverage)
                if mapped:
                    urls.extend([u for u in mapped.get("links", []) if same_origin(target, u)])
                    urls.extend([u for u in mapped.get("parameterizedUrls", []) if same_origin(target, u)])
                    forms.extend(mapped.get("forms", []))
                    private_probe_candidates.extend(
                        mapped.get(NATIVE_PROBE_PRIVATE_CANDIDATES_KEY, [])
                    )

        return {
            "urls": dedupe_keep_order(urls, max_pages * 20),
            "forms": forms[:200],
            "pageFetches": page_fetches[:max_pages],
            NATIVE_PROBE_PRIVATE_CANDIDATES_KEY: private_probe_candidates[:250],
        }


def get_tool():
    return ParamDiscoverTool()
