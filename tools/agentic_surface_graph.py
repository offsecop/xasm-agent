"""
Build a compact attack-surface graph for agentic web testing.

This is intentionally not a vulnerability scanner. It consolidates links,
forms, scripts, parameters, interesting paths, and likely follow-up hypotheses
so later tools can test the right things instead of blindly scanning the root.
"""

import re
from typing import Any, Dict, Iterable, List, Set
from urllib.parse import parse_qsl, urljoin, urlparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    classify_parameters,
    dedupe_keep_order,
    extract_html_map,
    extract_js_intel,
    fetch_text,
    normalize_url,
    parse_headers,
    same_origin,
)


SENSITIVE_PATH_HINTS = [
    "admin",
    "login",
    "signin",
    "logout",
    "account",
    "bank",
    "profile",
    "settings",
    "password",
    "reset",
    "upload",
    "download",
    "api",
    "graphql",
    "debug",
    "config",
]

STATE_CHANGING_WORDS = {
    "add",
    "create",
    "delete",
    "remove",
    "save",
    "submit",
    "update",
    "transfer",
    "pay",
    "withdraw",
    "deposit",
}


class SurfaceGraphTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "surface:graph"

    @property
    def description(self) -> str:
        return "Builds a unified web attack-surface graph from crawlable pages, forms, scripts, parameters, robots.txt, and sitemap.xml."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "urls": {"type": "array", "items": {"type": "string"}},
                "maxPages": {"type": "integer", "default": 45},
                "maxScripts": {"type": "integer", "default": 12},
                "includeKnownFiles": {"type": "boolean", "default": True},
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
            "domain": ["web"],
            "input_type": ["url", "urls"],
            "output_type": ["surface_graph", "hypotheses", "urls", "forms"],
            "chainable_after": ["browser:", "katana:"],
            "chainable_before": ["param:", "vuln:", "nuclei:", "dirsearch:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        target = normalize_url(parameters.get("target") or parameters.get("url") or "")
        seed_urls: List[str] = []
        if isinstance(parameters.get("urls"), list):
            seed_urls.extend(str(u) for u in parameters["urls"] if u)
        if target:
            seed_urls.insert(0, target)
        if not seed_urls:
            return {"success": False, "error": "target/url or urls is required"}

        base = target or seed_urls[0]
        max_pages = max(1, min(int(parameters.get("maxPages") or 45), 120))
        max_scripts = max(0, min(int(parameters.get("maxScripts") or 12), 40))
        headers = parse_headers(parameters)
        agent = parameters.get("_agent")

        pages: List[Dict[str, Any]] = []
        all_urls: List[str] = []
        scripts: List[str] = []
        forms: List[Dict[str, Any]] = []
        js_routes: List[str] = []
        api_paths: List[str] = []
        graphql_hints: List[str] = []
        potential_secrets: List[Dict[str, Any]] = []

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as session:
            queue = dedupe_keep_order([u for u in seed_urls if self._allowed(base, u)], max_pages)
            if bool(parameters.get("includeKnownFiles", True)):
                known = await self._fetch_known_files(session, headers, base)
                queue.extend(known)
            queue = dedupe_keep_order(queue, max_pages * 4)

            visited: Set[str] = set()
            cursor = 0
            while cursor < len(queue) and len(visited) < max_pages:
                url = queue[cursor]
                cursor += 1
                if url in visited or not self._allowed(base, url):
                    continue
                try:
                    fetched = await fetch_text(session, url, headers=headers, max_bytes=1_200_000)
                    mapped = extract_html_map(fetched.get("text", ""), fetched.get("url") or url)
                except Exception:
                    continue

                visited.add(url)
                page_links = [u for u in mapped.get("links", []) if self._allowed(base, u)]
                page_scripts = [u for u in mapped.get("scripts", []) if self._allowed(base, u)]
                page_forms = mapped.get("forms", [])
                all_urls.extend([url, *page_links])
                scripts.extend(page_scripts)
                forms.extend(page_forms)
                queue.extend(page_links)
                pages.append(
                    {
                        "url": fetched.get("url") or url,
                        "status": fetched.get("status"),
                        "title": mapped.get("title"),
                        "links": len(page_links),
                        "forms": len(page_forms),
                        "scripts": len(page_scripts),
                        "sensitiveHints": self._sensitive_hints(url, mapped),
                    }
                )
                if agent:
                    agent.report_progress("Building attack surface graph", url, len(visited), max_pages)

            for script_url in dedupe_keep_order(scripts, max_scripts):
                try:
                    fetched = await fetch_text(session, script_url, headers=headers, max_bytes=1_000_000)
                    intel = extract_js_intel(fetched.get("text", ""), script_url)
                    js_routes.extend([u for u in intel.get("routes", []) if self._allowed(base, u)])
                    api_paths.extend([u for u in intel.get("apiPaths", []) if self._allowed(base, u)])
                    graphql_hints.extend([u for u in intel.get("graphqlHints", []) if self._allowed(base, u)])
                    potential_secrets.extend(intel.get("potentialSecrets", []))
                except Exception:
                    continue

        all_urls = dedupe_keep_order([*all_urls, *js_routes, *api_paths, *graphql_hints], 1000)
        forms = self._dedupe_forms(forms)
        classified = classify_parameters(all_urls, forms)
        hypotheses = self._build_hypotheses(base, all_urls, forms, classified, pages)
        graph = {
            "pages": pages[:250],
            "urls": all_urls[:1000],
            "parameterizedUrls": classified.get("urlsWithParams", []),
            "forms": forms[:250],
            "scripts": dedupe_keep_order(scripts, 250),
            "apiPaths": dedupe_keep_order(api_paths, 200),
            "graphqlHints": dedupe_keep_order(graphql_hints, 30),
            "parameters": classified.get("parameters", {}),
            "interestingParameters": classified.get("interestingParameters", []),
            "sensitivePaths": self._sensitive_paths(all_urls),
            "potentialSecrets": potential_secrets[:50],
        }
        return {
            "success": True,
            "target": base,
            "surfaceGraph": graph,
            "urls": graph["urls"],
            "forms": graph["forms"],
            "hypotheses": hypotheses,
            "summary": {
                "pagesFetched": len(pages),
                "urls": len(graph["urls"]),
                "parameterizedUrls": len(graph["parameterizedUrls"]),
                "forms": len(graph["forms"]),
                "scripts": len(graph["scripts"]),
                "apiPaths": len(graph["apiPaths"]),
                "hypotheses": len(hypotheses),
            },
        }

    async def _fetch_known_files(
        self,
        session: aiohttp.ClientSession,
        headers: Dict[str, str],
        base: str,
    ) -> List[str]:
        parsed = urlparse(base)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        candidates = [f"{origin}/robots.txt", f"{origin}/sitemap.xml"]
        discovered: List[str] = []
        for url in candidates:
            try:
                fetched = await fetch_text(session, url, headers=headers, max_bytes=400_000)
                text = fetched.get("text", "")
                if url.endswith("/robots.txt"):
                    for match in re.finditer(r"(?im)^\s*(?:allow|disallow|sitemap):\s*(\S+)", text):
                        value = match.group(1).strip()
                        if value.lower().startswith("http"):
                            discovered.append(value)
                        elif value.startswith("/"):
                            discovered.append(urljoin(origin, value))
                else:
                    discovered.extend(re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.I))
            except Exception:
                continue
        return [u for u in dedupe_keep_order(discovered, 100) if self._allowed(base, u)]

    def _allowed(self, base: str, candidate: str) -> bool:
        return same_origin(base, candidate)

    def _dedupe_forms(self, forms: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        output = []
        for form in forms or []:
            # W.37 — defensive isinstance guard.
            if not isinstance(form, dict):
                continue
            fields = form.get("fields") if isinstance(form.get("fields"), list) else []
            field_sig = ",".join(sorted(str(f.get("name") or "") for f in fields if isinstance(f, dict)))
            key = f"{form.get('method')}|{form.get('action')}|{field_sig}"
            if key in seen:
                continue
            seen.add(key)
            output.append(form)
        return output

    def _sensitive_hints(self, url: str, mapped: Dict[str, Any]) -> List[str]:
        text = " ".join(
            [
                url,
                str(mapped.get("title") or ""),
                " ".join(str(b.get("label") or "") for b in mapped.get("buttons", []) if isinstance(b, dict)),
            ]
        ).lower()
        return [hint for hint in SENSITIVE_PATH_HINTS if hint in text][:8]

    def _sensitive_paths(self, urls: Iterable[str]) -> List[Dict[str, Any]]:
        rows = []
        for url in urls:
            lowered = url.lower()
            hints = [hint for hint in SENSITIVE_PATH_HINTS if hint in lowered]
            if hints:
                rows.append({"url": url, "hints": hints[:5]})
        return rows[:200]

    def _build_hypotheses(
        self,
        base: str,
        urls: List[str],
        forms: List[Dict[str, Any]],
        classified: Dict[str, Any],
        pages: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        hypotheses: List[Dict[str, Any]] = []
        for row in classified.get("interestingParameters", []):
            categories = set(row.get("categories") or [])
            name = row.get("name")
            url = row.get("url")
            if "file_path_candidate" in categories:
                hypotheses.append(self._hypothesis("lfi_path_traversal", 95, url, f"Parameter `{name}` controls file/page content."))
            if "redirect_or_ssrf" in categories:
                hypotheses.append(self._hypothesis("open_redirect_or_ssrf", 90, url, f"Parameter `{name}` accepts a redirect/URL-like value."))
            if "search_xss_candidate" in categories:
                hypotheses.append(self._hypothesis("reflected_xss", 70, url, f"Parameter `{name}` is search/text-like and may reflect input."))
            if "idor_candidate" in categories:
                hypotheses.append(self._hypothesis("idor_bola", 60, url, f"Parameter `{name}` looks like an object identifier."))

        for form in forms:
            # W.37 — defensive isinstance guard.
            if not isinstance(form, dict):
                continue
            fields = form.get("fields") if isinstance(form.get("fields"), list) else []
            names = {str(f.get("name") or "").lower() for f in fields if isinstance(f, dict)}
            types = {str(f.get("type") or "").lower() for f in fields if isinstance(f, dict)}
            action = str(form.get("action") or base)
            method = str(form.get("method") or "GET").upper()
            if "password" in types or any("pass" in name for name in names):
                hypotheses.append(self._hypothesis("auth_bypass_or_login_sqli", 88, action, "Login-like form discovered."))
            if method in {"POST", "PUT", "PATCH"} and not (names & {"csrf", "_csrf", "csrf_token", "authenticity_token"}):
                hypotheses.append(self._hypothesis("missing_csrf_token", 65, action, "State-changing form has no obvious CSRF token."))
            if any(any(word in name for word in STATE_CHANGING_WORDS) for name in names):
                hypotheses.append(self._hypothesis("state_changing_form", 55, action, "Form fields suggest a state-changing operation."))

        for page in pages:
            hints = page.get("sensitiveHints") or []
            if hints:
                hypotheses.append(
                    self._hypothesis(
                        "sensitive_surface",
                        50,
                        page.get("url"),
                        f"Sensitive surface hints: {', '.join(hints[:5])}.",
                    )
                )

        deduped: Dict[str, Dict[str, Any]] = {}
        for h in sorted(hypotheses, key=lambda item: item["priority"], reverse=True):
            key = f"{h['type']}|{h.get('url')}"
            deduped.setdefault(key, h)
        return list(deduped.values())[:120]

    def _hypothesis(self, kind: str, priority: int, url: Any, reason: str) -> Dict[str, Any]:
        return {"type": kind, "priority": priority, "url": str(url or ""), "reason": reason}


def get_tool():
    return SurfaceGraphTool()
