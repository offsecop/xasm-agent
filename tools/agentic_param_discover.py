"""
Passive parameter discovery and classification for agentic exploration.
"""

import os
import tempfile
from typing import Any, Dict, List

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    classify_parameters,
    dedupe_keep_order,
    extract_html_map,
    fetch_text,
    normalize_url,
    parse_headers,
    run_process,
    same_origin,
)


class ParamDiscoverTool(ToolPlugin):
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
        if bool(parameters.get("discoverFromTarget", True)) and target:
            discovered = await self._discover_from_target(normalize_url(target), parameters)
            urls.extend(discovered.get("urls", []))
            forms.extend(discovered.get("forms", []))

        max_targets = max(1, min(int(parameters.get("maxTargets") or 50), 200))
        urls = dedupe_keep_order(urls, max_targets)
        passive = classify_parameters(urls, forms)

        arjun_results = []
        if bool(parameters.get("activeArjun", False)):
            for url in urls[:max_targets]:
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
            "targets": urls,
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
            },
        }

    async def _discover_from_target(self, target: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        max_pages = max(1, min(int(parameters.get("maxPages") or 20), 50))
        urls: List[str] = [target]
        forms: List[Dict[str, Any]] = []
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as session:
            try:
                fetched = await fetch_text(session, target, headers=parse_headers(parameters), max_bytes=1_000_000)
                mapped = extract_html_map(fetched.get("text", ""), fetched.get("url") or target)
                urls.extend([u for u in mapped.get("links", []) if same_origin(target, u)])
                forms.extend(mapped.get("forms", []))
            except Exception:
                return {"urls": urls, "forms": forms}

            for url in list(dedupe_keep_order(urls, max_pages)):
                if url == target or not same_origin(target, url):
                    continue
                try:
                    fetched = await fetch_text(session, url, headers=parse_headers(parameters), max_bytes=800_000)
                    mapped = extract_html_map(fetched.get("text", ""), fetched.get("url") or url)
                    urls.extend([u for u in mapped.get("links", []) if same_origin(target, u)])
                    forms.extend(mapped.get("forms", []))
                except Exception:
                    continue

        return {"urls": dedupe_keep_order(urls, max_pages * 20), "forms": forms[:200]}


def get_tool():
    return ParamDiscoverTool()
