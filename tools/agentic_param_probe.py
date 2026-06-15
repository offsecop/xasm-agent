"""
Safe targeted parameter probes for agentic exploration.

This tool turns passive URL intelligence into bounded evidence checks. It only
uses GET requests, keeps traffic on the authorized origin, and does not submit
forms or run destructive payloads.
"""

import hashlib
import time
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    classify_parameters,
    dedupe_keep_order,
    discover_site_metadata_urls,
    extract_html_map,
    fetch_text,
    normalize_url,
    parse_headers,
    same_origin,
)


REDIRECT_PARAM_NAMES = {"url", "next", "redirect", "return", "continue", "callback", "dest", "destination", "redir"}
FILE_PARAM_NAMES = {"file", "path", "template", "page", "include", "content", "doc", "document", "view"}
LFI_PAYLOADS = [
    "../WEB-INF/web.xml",
    "../../WEB-INF/web.xml",
    "../../../WEB-INF/web.xml",
    "../../../../WEB-INF/web.xml",
    "../etc/passwd",
    "../../etc/passwd",
]
LFI_MARKERS = [
    "<web-app",
    "</web-app>",
    "<servlet",
    "web-app_",
    "root:x:0:0:",
    "[boot loader]",
]


class ParamProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "param:probe"

    @property
    def description(self) -> str:
        return "Runs safe GET-only probes for parameterized URLs, including open redirect and local file inclusion/path traversal evidence checks."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "urls": {"type": "array", "items": {"type": "string"}},
                "forms": {"type": "array", "items": {"type": "object"}},
                "discoverFromTarget": {"type": "boolean", "default": True},
                "includeBrowserTrafficDiscovery": {"type": "boolean", "default": True},
                "maxPages": {"type": "integer", "default": 25},
                "maxUrls": {"type": "integer", "default": 80},
                "maxProbes": {"type": "integer", "default": 80},
                "externalProbeUrl": {"type": "string", "default": "https://example.com/xasm-open-redirect"},
                "includeReflectionChecks": {"type": "boolean", "default": False},
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
            "phase": 3,
            "domain": ["web"],
            "input_type": ["url", "urls"],
            "output_type": ["findings", "parameter_probe_results"],
            "chainable_after": ["browser:", "katana:", "param:"],
            "chainable_before": ["nuclei:", "dalfox:", "sqlmap:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        target = normalize_url(parameters.get("target") or parameters.get("url") or "")
        urls: List[str] = []
        if isinstance(parameters.get("urls"), list):
            urls.extend(str(u) for u in parameters["urls"] if u)
        if target:
            urls.insert(0, target)
        if not urls:
            return {"success": False, "error": "target/url or urls is required"}

        agent = parameters.get("_agent")
        max_urls = max(1, min(int(parameters.get("maxUrls") or 80), 300))
        max_probes = max(1, min(int(parameters.get("maxProbes") or 80), 300))
        forms = parameters.get("forms") if isinstance(parameters.get("forms"), list) else []

        if bool(parameters.get("discoverFromTarget", True)) and target:
            discovered = await self._discover_from_target(target, parameters)
            urls.extend(discovered["urls"])
            forms.extend(discovered["forms"])

        urls = [u for u in dedupe_keep_order(urls, max_urls) if self._is_authorized_url(target or urls[0], u)]
        classified = classify_parameters(urls, forms)
        candidate_urls = classified.get("urlsWithParams", [])

        if agent:
            agent.report_progress("Probing parameterized URLs", target or urls[0], 0, max_probes)

        findings: List[Dict[str, Any]] = []
        probes: List[Dict[str, Any]] = []
        connector = aiohttp.TCPConnector(ssl=False)
        headers = parse_headers(parameters)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as session:
            probe_count = 0
            for url in candidate_urls:
                for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
                    if probe_count >= max_probes:
                        break
                    lower = name.lower()
                    if lower in REDIRECT_PARAM_NAMES:
                        created, result_count = await self._probe_open_redirect(
                            session,
                            headers,
                            url,
                            name,
                            str(parameters.get("externalProbeUrl") or "https://example.com/xasm-open-redirect"),
                        )
                        probe_count += result_count
                        probes.extend(created["probes"])
                        findings.extend(created["findings"])
                    if lower in FILE_PARAM_NAMES:
                        created, result_count = await self._probe_lfi(session, headers, url, name)
                        probe_count += result_count
                        probes.extend(created["probes"])
                        findings.extend(created["findings"])
                    if bool(parameters.get("includeReflectionChecks", False)) and probe_count < max_probes:
                        created, result_count = await self._probe_reflection(session, headers, url, name)
                        probe_count += result_count
                        probes.extend(created["probes"])
                        findings.extend(created["findings"])
                    if agent:
                        agent.report_progress("Probing parameterized URLs", url, probe_count, max_probes)
                if probe_count >= max_probes:
                    break

        findings = self._dedupe_findings(findings)
        raw_output = "\n".join(self._finding_line(f) for f in findings)
        return {
            "success": True,
            "target": target,
            "candidateUrls": candidate_urls,
            "parameters": classified.get("parameters", {}),
            "interestingParameters": classified.get("interestingParameters", []),
            "probes": probes[:500],
            "findings": findings,
            "total_findings": len(findings),
            "findings_delivered": len(findings),
            "tool": "param:probe",
            "rawOutput": raw_output,
            "summary": {
                "urlsAnalyzed": len(urls),
                "candidateUrls": len(candidate_urls),
                "probesRun": len(probes),
                "findings": len(findings),
            },
        }

    async def _discover_from_target(self, target: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        max_pages = max(1, min(int(parameters.get("maxPages") or 25), 60))
        urls: List[str] = [target]
        forms: List[Dict[str, Any]] = []
        headers = parse_headers(parameters)
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as session:
            urls.extend(await discover_site_metadata_urls(session, target, headers=headers, max_urls=max_pages * 20))
            fetched_pages = set()
            cursor = 0
            while cursor < len(urls) and len(fetched_pages) < max_pages:
                url = urls[cursor]
                cursor += 1
                if url in fetched_pages or not self._is_authorized_url(target, url):
                    continue
                try:
                    fetched = await fetch_text(session, url, headers=headers, max_bytes=800_000)
                    mapped = extract_html_map(fetched.get("text", ""), fetched.get("url") or url)
                except Exception:
                    continue
                fetched_pages.add(url)
                urls.extend([u for u in mapped.get("links", []) if self._is_authorized_url(target, u)])
                forms.extend(mapped.get("forms", []))

        if bool(parameters.get("includeBrowserTrafficDiscovery", True)):
            browser_discovered = await self._discover_from_browser_traffic(target, parameters)
            urls.extend(browser_discovered["urls"])
            forms.extend(browser_discovered["forms"])

        return {"urls": dedupe_keep_order(urls, max_pages * 20), "forms": forms[:200]}

    async def _discover_from_browser_traffic(self, target: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        try:
            from tools.agentic_browser_traffic_capture import BrowserTrafficCaptureTool

            traffic = await BrowserTrafficCaptureTool().execute(
                {
                    **parameters,
                    "_agent": None,
                    "target": target,
                    "maxInteractions": min(int(parameters.get("maxInteractions") or 10), 15),
                    "timeoutSeconds": min(int(parameters.get("timeoutSeconds") or 45), 75),
                    "maxRequests": min(int(parameters.get("maxRequests") or 180), 250),
                    "safeInteract": True,
                    "fillSearchInputs": True,
                }
            )
        except Exception:
            return {"urls": [], "forms": []}

        urls: List[str] = []
        if isinstance(traffic, dict):
            urls.extend(str(u) for u in traffic.get("parameterizedUrls", []) if u)
            for endpoint in traffic.get("apiEndpoints", []) or []:
                if isinstance(endpoint, dict) and endpoint.get("url"):
                    urls.append(str(endpoint["url"]))
            for request in traffic.get("xhrRequests", []) or []:
                if isinstance(request, dict) and request.get("url"):
                    urls.append(str(request["url"]))
            forms = traffic.get("forms") if isinstance(traffic.get("forms"), list) else []
        else:
            forms = []
        return {
            "urls": [u for u in dedupe_keep_order(urls, 250) if self._is_authorized_url(target, u)],
            "forms": forms[:120],
        }

    async def _probe_open_redirect(
        self,
        session: aiohttp.ClientSession,
        headers: Dict[str, str],
        url: str,
        param: str,
        external_url: str,
    ) -> Tuple[Dict[str, List[Dict[str, Any]]], int]:
        findings: List[Dict[str, Any]] = []
        probes: List[Dict[str, Any]] = []
        probe_targets = [
            self._replace_param(url, param, external_url),
            self._replace_param(url, param, f"//{urlparse(external_url).netloc}/xasm-open-redirect"),
        ]
        for probe_url in probe_targets:
            try:
                async with session.get(probe_url, headers=headers, allow_redirects=False) as response:
                    location = response.headers.get("Location", "")
                    status = response.status
                    probes.append({"type": "open_redirect", "url": probe_url, "status": status, "location": location})
                    if 300 <= status < 400 and self._location_points_to(location, external_url):
                        findings.append(
                            self._finding(
                                template_id="xasm-open-redirect",
                                name="Open Redirect",
                                severity="medium",
                                matched_at=probe_url,
                                description=f"Parameter `{param}` redirects users to an attacker-controlled external URL.",
                                remediation="Validate redirect destinations against an allowlist of trusted same-origin paths.",
                                matcher_name="external-location-header",
                                extracted=[location],
                            )
                        )
                    elif status < 500:
                        body = await response.text(errors="replace")
                        sink_markers = self._client_redirect_sink_markers(body, param)
                        if sink_markers:
                            probes[-1]["clientSideRedirectSink"] = sink_markers
                            findings.append(
                                self._finding(
                                    template_id="xasm-client-side-open-redirect",
                                    name="Client-Side Open Redirect",
                                    severity="medium",
                                    matched_at=probe_url,
                                    description=(
                                        f"Parameter `{param}` is read by client-side JavaScript and used in a "
                                        "browser navigation sink."
                                    ),
                                    remediation=(
                                        "Do not build navigation destinations directly from URL parameters. "
                                        "Validate destinations against a same-origin allowlist."
                                    ),
                                    matcher_name="client-side-location-sink",
                                    extracted=sink_markers,
                                )
                            )
            except Exception as exc:
                probes.append({"type": "open_redirect", "url": probe_url, "error": str(exc)[:200]})
        return {"findings": findings, "probes": probes}, len(probe_targets)

    async def _probe_lfi(
        self,
        session: aiohttp.ClientSession,
        headers: Dict[str, str],
        url: str,
        param: str,
    ) -> Tuple[Dict[str, List[Dict[str, Any]]], int]:
        findings: List[Dict[str, Any]] = []
        probes: List[Dict[str, Any]] = []
        for payload in LFI_PAYLOADS:
            probe_url = self._replace_param(url, param, payload)
            try:
                async with session.get(probe_url, headers=headers, allow_redirects=True) as response:
                    body = await response.text(errors="replace")
                    lowered = body.lower()
                    markers = [m for m in LFI_MARKERS if m.lower() in lowered]
                    probes.append({"type": "lfi", "url": probe_url, "status": response.status, "markers": markers[:5]})
                    if response.status < 500 and markers:
                        findings.append(
                            self._finding(
                                template_id="xasm-lfi-path-traversal",
                                name="Local File Inclusion / Path Traversal",
                                severity="high",
                                matched_at=probe_url,
                                description=f"Parameter `{param}` appears to include local files when traversal payloads are supplied.",
                                remediation="Restrict file inclusion to server-side allowlisted identifiers and normalize paths before access.",
                                matcher_name="sensitive-file-marker",
                                extracted=markers[:5],
                            )
                        )
                        break
            except Exception as exc:
                probes.append({"type": "lfi", "url": probe_url, "error": str(exc)[:200]})
        return {"findings": findings, "probes": probes}, len(probes)

    async def _probe_reflection(
        self,
        session: aiohttp.ClientSession,
        headers: Dict[str, str],
        url: str,
        param: str,
    ) -> Tuple[Dict[str, List[Dict[str, Any]]], int]:
        token = f"xasm-reflect-{int(time.time())}"
        probe_url = self._replace_param(url, param, token)
        probes: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        try:
            async with session.get(probe_url, headers=headers, allow_redirects=True) as response:
                body = await response.text(errors="replace")
                reflected = token in body
                probes.append({"type": "reflection", "url": probe_url, "status": response.status, "reflected": reflected})
                if reflected:
                    findings.append(
                        self._finding(
                            template_id="xasm-reflected-parameter",
                            name="Reflected Parameter",
                            severity="info",
                            matched_at=probe_url,
                            description=f"Parameter `{param}` is reflected in the HTTP response. This is evidence for targeted XSS testing, not a confirmed XSS by itself.",
                            remediation="Contextually encode reflected input and validate input handling.",
                            matcher_name="sentinel-reflection",
                            extracted=[token],
                        )
                    )
        except Exception as exc:
            probes.append({"type": "reflection", "url": probe_url, "error": str(exc)[:200]})
        return {"findings": findings, "probes": probes}, 1

    def _replace_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = [(name, value if name == param else current) for name, current in query]
        return urlunparse(parsed._replace(query=urlencode(replaced, doseq=True, safe="/:"), fragment=""))

    def _is_authorized_url(self, target: str, candidate: str) -> bool:
        return same_origin(target, candidate)

    def _location_points_to(self, location: str, external_url: str) -> bool:
        if not location:
            return False
        parsed = urlparse(location if not location.startswith("//") else f"https:{location}")
        expected = urlparse(external_url)
        return parsed.netloc.lower() == expected.netloc.lower()

    def _client_redirect_sink_markers(self, body: str, param: str) -> List[str]:
        lowered = (body or "").lower()
        param_markers = [
            f'"{param.lower()}="',
            f"'{param.lower()}='",
            f"searchparams.get('{param.lower()}')",
            f'searchparams.get("{param.lower()}")',
            f"getparameter('{param.lower()}')",
            f'getparameter("{param.lower()}")',
        ]
        reads_param = any(marker in lowered for marker in param_markers)
        navigation_markers = [
            "window.location",
            "location.href",
            "location.assign",
            "location.replace",
            "window.open",
        ]
        navigation_sinks = [marker for marker in navigation_markers if marker in lowered]
        if reads_param and navigation_sinks:
            return [*navigation_sinks[:3], f"query-param:{param}"]
        return []

    def _finding(
        self,
        *,
        template_id: str,
        name: str,
        severity: str,
        matched_at: str,
        description: str,
        remediation: str,
        matcher_name: str,
        extracted: List[str],
    ) -> Dict[str, Any]:
        return {
            "template-id": template_id,
            "templateID": template_id,
            "matched-at": matched_at,
            "matched": matched_at,
            "host": matched_at,
            "matcher-name": matcher_name,
            "extracted-results": extracted,
            "info": {
                "name": name,
                "severity": severity,
                "description": description,
                "remediation": remediation,
            },
        }

    def _dedupe_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: Dict[str, Dict[str, Any]] = {}
        for finding in findings:
            key = self._finding_dedupe_key(finding)
            deduped.setdefault(key, finding)
        return list(deduped.values())

    def _finding_dedupe_key(self, finding: Dict[str, Any]) -> str:
        matched_at = str(finding.get("matched-at") or "")
        parsed = urlparse(matched_at)
        param_names = ",".join(sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}))
        normalized = urlunparse(parsed._replace(query=param_names, fragment=""))
        raw_key = f"{finding.get('template-id')}|{normalized}"
        return hashlib.sha256(raw_key.encode("utf-8", errors="ignore")).hexdigest()

    def _finding_line(self, finding: Dict[str, Any]) -> str:
        info = finding.get("info") or {}
        return f"[{str(info.get('severity', 'info')).upper()}] {info.get('name')} - {finding.get('matched-at')}"


def get_tool():
    return ParamProbeTool()
