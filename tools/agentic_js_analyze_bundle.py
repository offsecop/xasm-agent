"""
JavaScript bundle analysis for agentic exploration.
"""

from typing import Any, Dict, List
from urllib.parse import urljoin

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    extract_html_map,
    extract_js_intel,
    fetch_text,
    normalize_url,
    parse_headers,
    same_origin,
)


class JsAnalyzeBundleTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "js:analyze_bundle"

    @property
    def description(self) -> str:
        return "Analyzes same-origin JavaScript bundles for routes, API paths, GraphQL hints, exploitability hypotheses, and likely exposed client-side secrets."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "scripts": {"type": "array", "items": {"type": "string"}},
                "maxScripts": {"type": "integer", "default": 12},
                "maxBytesPerScript": {"type": "integer", "default": 1000000},
                "cookie": {"type": "string"},
                "authCookies": {"type": "string"},
                "headers": {"type": "object"},
                "authHeaders": {"type": "object"},
            },
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}, {"required": ["scripts"]}],
        }

    @property
    def metadata(self):
        return {
            "category": "agentic-recon",
            "phase": 2,
            "domain": ["web"],
            "input_type": ["url", "urls"],
            "output_type": ["routes", "api_paths", "api_endpoints", "hypotheses", "secrets"],
            "chainable_after": ["browser:", "katana:"],
            "chainable_before": ["api:", "param:", "curl:", "nuclei:", "exploit:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        target = normalize_url(parameters.get("target") or parameters.get("url") or "")
        scripts: List[str] = []
        if isinstance(parameters.get("scripts"), list):
            scripts = [str(s) for s in parameters["scripts"] if s]
        max_scripts = max(1, min(int(parameters.get("maxScripts") or 12), 50))
        max_bytes = max(50_000, min(int(parameters.get("maxBytesPerScript") or 1_000_000), 3_000_000))
        agent = parameters.get("_agent")

        if not target and not scripts:
            return {"success": False, "error": "target/url or scripts is required"}

        if agent:
            agent.report_progress("Analyzing JavaScript bundles", target or "script list", 0, None)

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=60, connect=10, sock_read=20),
        ) as session:
            if target and not scripts:
                fetched = await fetch_text(session, target, headers=parse_headers(parameters), max_bytes=1_000_000)
                mapped = extract_html_map(fetched.get("text", ""), fetched.get("url") or target)
                scripts = mapped.get("scripts", [])
            scripts = [urljoin(target, s) if target else s for s in scripts]
            scripts = [s for s in scripts if not target or same_origin(target, s)]
            scripts = scripts[:max_scripts]

            aggregate = {
                "urls": [],
                "routes": [],
                "apiPaths": [],
                "apiEndpoints": [],
                "graphqlHints": [],
                "potentialSecrets": [],
                "hypotheses": [],
                "interestingParameters": [],
            }
            script_results = []
            for index, script_url in enumerate(scripts):
                try:
                    fetched = await fetch_text(session, script_url, headers=parse_headers(parameters), max_bytes=max_bytes)
                    intel = extract_js_intel(fetched.get("text", ""), fetched.get("url") or script_url)
                    script_results.append(
                        {
                            "url": script_url,
                            "status": fetched.get("status"),
                            "bytes": len(fetched.get("text") or ""),
                            "truncated": fetched.get("truncated"),
                            "routeCount": len(intel["routes"]),
                            "apiPathCount": len(intel["apiPaths"]),
                            "apiEndpointCount": len(intel.get("apiEndpoints", [])),
                            "hypothesisCount": len(intel.get("hypotheses", [])),
                            "secretCount": len(intel["potentialSecrets"]),
                        }
                    )
                    for key in aggregate:
                        aggregate[key].extend(intel[key])
                    if agent:
                        agent.report_progress("Analyzing JavaScript bundles", script_url, index + 1, len(scripts))
                except Exception as exc:
                    script_results.append({"url": script_url, "error": str(exc)})

        for key in ("urls", "routes", "apiPaths", "graphqlHints"):
            seen = set()
            aggregate[key] = [x for x in aggregate[key] if not (x in seen or seen.add(x))][:500]
        for key in ("apiEndpoints", "hypotheses", "interestingParameters"):
            seen = set()
            deduped = []
            for item in aggregate[key]:
                marker = str(item.get("url") or item.get("endpoint") or item.get("category") or item) if isinstance(item, dict) else str(item)
                if marker in seen:
                    continue
                seen.add(marker)
                deduped.append(item)
            aggregate[key] = deduped[:500]
        aggregate["potentialSecrets"] = aggregate["potentialSecrets"][:100]

        result = {
            "success": True,
            "target": target,
            "scriptsAnalyzed": script_results,
            **aggregate,
            "summary": {
                "scripts": len(script_results),
                "routes": len(aggregate["routes"]),
                "apiPaths": len(aggregate["apiPaths"]),
                "apiEndpoints": len(aggregate["apiEndpoints"]),
                "graphqlHints": len(aggregate["graphqlHints"]),
                "potentialSecrets": len(aggregate["potentialSecrets"]),
                "hypotheses": len(aggregate["hypotheses"]),
                "interestingParameters": len(aggregate["interestingParameters"]),
            },
        }
        if agent:
            agent.append_output(
                f"[js:analyze_bundle] scripts={result['summary']['scripts']} apiPaths={result['summary']['apiPaths']} routes={result['summary']['routes']} hypotheses={result['summary']['hypotheses']}"
            )
        return result


def get_tool():
    return JsAnalyzeBundleTool()
