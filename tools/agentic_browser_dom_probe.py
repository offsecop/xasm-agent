"""Fail-closed browser proof for DOM-based XSS.

The tool executes one exact, same-origin GET PoC containing a benign numeric
``alert``/``confirm`` marker.  It deliberately exposes no arbitrary browser
action or JavaScript-evaluation interface.  Static source/sink matches are
hypotheses; a finding is emitted only when a fresh browser also observes the
marker (or an unsolved-to-solved transition) and both sides of the taint flow
occur in the same bounded script record.
"""

import re
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit, urlunsplit

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import normalize_url, parse_headers, same_origin


SOURCE_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("location", re.compile(r"\blocation\.(?:search|hash|href|pathname)\b", re.I)),
    ("document-url", re.compile(r"\bdocument\.(?:URL|documentURI|baseURI|referrer)\b", re.I)),
    ("document-cookie", re.compile(r"\bdocument\.cookie\b", re.I)),
    ("window-name", re.compile(r"\bwindow\.name\b", re.I)),
    ("web-message", re.compile(r"(?:\b(?:event|e)\.data\b|\bpostMessage\b|\bonmessage\b)", re.I)),
    ("storage", re.compile(r"\b(?:localStorage|sessionStorage)\b", re.I)),
)

SINK_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("document.write", re.compile(r"\bdocument\.write(?:ln)?\s*\(", re.I)),
    ("html-injection", re.compile(r"(?:\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\()", re.I)),
    ("code-execution", re.compile(r"(?:\beval\s*\(|\bFunction\s*\(|\bsetTimeout\s*\()", re.I)),
    ("location", re.compile(r"(?:\b(?:window\.)?location(?:\.href)?\s*=|\.location\.(?:assign|replace)\s*\()", re.I)),
    ("jquery-href", re.compile(r"\.attr\s*\(\s*['\"]href['\"]", re.I)),
    ("element-src", re.compile(r"\.src\s*=", re.I)),
    ("document-cookie", re.compile(r"\bdocument\.cookie\s*=", re.I)),
)

FORBIDDEN_PAYLOAD_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("network fetch", re.compile(r"\bfetch\s*\(", re.I)),
    ("XMLHttpRequest", re.compile(r"\bXMLHttpRequest\b", re.I)),
    ("sendBeacon", re.compile(r"\bsendBeacon\s*\(", re.I)),
    ("WebSocket", re.compile(r"\bWebSocket\s*\(", re.I)),
    ("cookie access", re.compile(r"\bdocument\.cookie\b", re.I)),
    ("storage access", re.compile(r"\b(?:localStorage|sessionStorage|indexedDB)\b", re.I)),
)

SOURCE_RANK = {
    "location": 0,
    "document-url": 1,
    "window-name": 2,
    "web-message": 3,
    "storage": 4,
    "document-cookie": 5,
}

SINK_RANK = {
    "document.write": 0,
    "html-injection": 1,
    "location": 2,
    "jquery-href": 3,
    "element-src": 4,
    "code-execution": 5,
    "document-cookie": 6,
}


def _decoded_url(value: str) -> str:
    decoded = str(value or "")
    for _ in range(3):
        next_value = unquote_plus(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def validate_benign_marker_target(target: str, expected_marker: str) -> Tuple[bool, str]:
    """Validate that the exact target carries only the supported benign proof."""
    try:
        parsed = urlsplit(target)
    except Exception:
        return False, "target is not a valid URL"
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False, "target must be an HTTP(S) URL"

    marker = str(expected_marker or "").strip()
    if not re.fullmatch(r"\d{1,10}", marker):
        return False, "expectedMarker must be a 1-10 digit benign marker"

    decoded = _decoded_url(target)
    marker_re = re.compile(rf"\b(?:alert|confirm)\s*\(\s*{re.escape(marker)}\s*\)", re.I)
    if not marker_re.search(decoded):
        return False, f"target must contain alert({marker}) or confirm({marker})"
    for label, pattern in FORBIDDEN_PAYLOAD_PATTERNS:
        if pattern.search(decoded):
            return False, f"target contains forbidden {label} primitive"
    return True, ""


def build_baseline_url(target: str, parameter: str) -> str:
    """Remove only the injected query parameter and fragment from the PoC URL."""
    parsed = urlsplit(target)
    remaining = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key != parameter]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(remaining, doseq=True), ""))


def _excerpt(line: str, limit: int = 220) -> str:
    compact = re.sub(r"\s+", " ", line).strip()
    return compact if len(compact) <= limit else compact[: limit - 3] + "..."


def extract_taint_candidates(script_records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Return bounded source/sink lines and require a same-script linkage."""
    sources: List[Dict[str, Any]] = []
    sinks: List[Dict[str, Any]] = []
    source_scripts = set()
    sink_scripts = set()

    for index, record in enumerate(list(script_records)[:24]):
        script_id = str(record.get("url") or record.get("id") or f"inline:{index}")[:220]
        text = str(record.get("text") or "")[:20_000]
        for line_number, line in enumerate(text.splitlines()[:800], start=1):
            for label, pattern in SOURCE_PATTERNS:
                if len(sources) >= 12:
                    break
                if pattern.search(line):
                    sources.append({"kind": label, "script": script_id, "line": line_number, "excerpt": _excerpt(line)})
                    source_scripts.add(script_id)
            for label, pattern in SINK_PATTERNS:
                if len(sinks) >= 12:
                    break
                if pattern.search(line):
                    sinks.append({"kind": label, "script": script_id, "line": line_number, "excerpt": _excerpt(line)})
                    sink_scripts.add(script_id)

    linked_scripts = sorted(source_scripts.intersection(sink_scripts))[:8]
    linked_pairs = [
        (source, sink)
        for source in sources
        for sink in sinks
        if source["script"] == sink["script"]
    ]
    if linked_pairs:
        preferred_source, preferred_sink = min(
            linked_pairs,
            key=lambda pair: (
                SOURCE_RANK.get(str(pair[0].get("kind")), 99),
                SINK_RANK.get(str(pair[1].get("kind")), 99),
                str(pair[0].get("script")),
                int(pair[0].get("line") or 0),
                int(pair[1].get("line") or 0),
            ),
        )
        sources = [preferred_source, *[item for item in sources if item is not preferred_source]]
        sinks = [preferred_sink, *[item for item in sinks if item is not preferred_sink]]
    return {
        "sourceCandidates": sources,
        "sinkCandidates": sinks,
        "linkedSourceSink": bool(linked_scripts),
        "linkedScripts": linked_scripts,
    }


def verification_is_confirmed(verification: Dict[str, Any]) -> bool:
    sources = verification.get("sourceCandidates")
    sinks = verification.get("sinkCandidates")
    execution_proof = bool(verification.get("markerMatched")) or (
        verification.get("solvedBefore") is False and verification.get("solvedAfter") is True
    )
    return bool(
        verification.get("browserExecuted")
        and verification.get("fallback") is False
        and verification.get("solvedBefore") is False
        and isinstance(sources, list)
        and sources
        and isinstance(sinks, list)
        and sinks
        and verification.get("linkedSourceSink") is True
        and execution_proof
    )


def build_nuclei_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    source = str(verification["sourceCandidates"][0].get("kind") or "browser source")
    sink = str(verification["sinkCandidates"][0].get("kind") or "DOM sink")
    return {
        "template-id": "xasm-dom-based-browser-verified",
        "info": {
            "name": f"Verified DOM-Based XSS: {source} to {sink}",
            "severity": "high",
            "description": "A browser-executed benign marker confirmed attacker-controlled client data reaching a dangerous DOM sink.",
            "remediation": "Avoid routing untrusted browser sources into HTML or JavaScript sinks; use safe DOM APIs and context-appropriate encoding.",
            "classification": {"cwe-id": ["CWE-79"]},
        },
        "type": "http",
        "host": target,
        "matched-at": target,
        "matcher-name": "browser-executed-dom-marker",
        "evidence": verification,
    }


def _cookie_rows(raw: str, target: str) -> List[Dict[str, str]]:
    parsed = urlsplit(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    rows: List[Dict[str, str]] = []
    for part in str(raw or "").split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name:
            rows.append({"name": name[:200], "value": value[:4096], "url": base_url})
    return rows[:50]


class BrowserDomProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "browser:dom_probe"

    @property
    def description(self) -> str:
        return (
            "Executes one exact same-origin GET PoC in a fresh browser and confirms DOM-based XSS "
            "only with a benign marker plus linked client-side source and sink evidence."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Exact same-origin GET PoC URL"},
                "url": {"type": "string", "description": "Alias for target"},
                "parameter": {"type": "string", "description": "Attacker-controlled source parameter"},
                "expectedMarker": {"type": "string", "default": "1337"},
                "timeoutSeconds": {"type": "integer", "default": 45},
                "waitMs": {"type": "integer", "default": 900},
                "cookie": {"type": "string"},
                "authCookies": {"type": "string"},
                "headers": {"type": "object"},
                "authHeaders": {"type": "object", "x-hidden": True},
            },
            "required": ["parameter"],
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 4,
            "domain": ["web"],
            "input_type": ["url_with_params"],
            "output_type": ["findings"],
            "chainable_after": ["browser:map_app", "js:analyze_bundle", "param:discover"],
            "chainable_before": [],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm one DOM source-to-sink flow with a benign browser marker",
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        target = normalize_url(parameters.get("target") or parameters.get("url"))
        parameter = str(parameters.get("parameter") or "").strip()
        marker = str(parameters.get("expectedMarker") or "1337").strip()
        if not target or not parameter:
            return {"success": False, "fallback": False, "errorCode": "INVALID_ARGUMENT", "error": "target/url and parameter are required"}

        valid, reason = validate_benign_marker_target(target, marker)
        if not valid:
            return {"success": False, "fallback": False, "target": target, "errorCode": "UNSAFE_OR_INVALID_POC", "error": reason}

        baseline_url = build_baseline_url(target, parameter)
        if baseline_url == target:
            return {"success": False, "fallback": False, "target": target, "errorCode": "PARAMETER_NOT_PRESENT", "error": "parameter must be present in the PoC query"}

        timeout_seconds = max(10, min(int(parameters.get("timeoutSeconds") or 45), 90))
        wait_ms = max(200, min(int(parameters.get("waitMs") or 900), 3000))
        agent = parameters.get("_agent")
        if agent:
            agent.report_progress("Executing bounded DOM proof", target, 0, 1)

        try:
            from playwright.async_api import async_playwright
            from lib.process_reaper import close_browser_safe
        except Exception as exc:
            return {
                "success": False,
                "fallback": False,
                "target": target,
                "baselineUrl": baseline_url,
                "errorCode": "BROWSER_UNAVAILABLE",
                "error": f"Playwright unavailable: {exc}",
            }

        browser = None
        context = None
        blocked_requests: List[Dict[str, str]] = []
        dialogs: List[Dict[str, str]] = []
        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage"],
                )
                context = await browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers=parse_headers(parameters),
                )
                cookies = _cookie_rows(parameters.get("authCookies") or parameters.get("cookie") or "", target)
                if cookies:
                    await context.add_cookies(cookies)

                async def guard(route: Any, request: Any) -> None:
                    method = str(request.method or "GET").upper()
                    if method != "GET" or not same_origin(target, str(request.url)):
                        if len(blocked_requests) < 20:
                            blocked_requests.append({"method": method, "url": str(request.url)[:500]})
                        await route.abort()
                        return
                    await route.continue_()

                await context.route("**/*", guard)
                page = await context.new_page()
                page.set_default_timeout(timeout_seconds * 1000)

                async def on_dialog(dialog: Any) -> None:
                    if len(dialogs) < 8:
                        dialogs.append({"type": str(dialog.type), "message": str(dialog.message)[:200], "origin": str(page.url)[:500]})
                    await dialog.dismiss()

                page.on("dialog", on_dialog)

                await page.goto(baseline_url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
                await page.wait_for_timeout(wait_ms)
                solved_before = await self._is_solved(page)
                if solved_before:
                    return {
                        "success": False,
                        "fallback": False,
                        "target": target,
                        "baselineUrl": baseline_url,
                        "errorCode": "PRE_SOLVED_TARGET",
                        "error": "baseline was already solved; fresh proof is required",
                    }

                dialogs.clear()
                await page.goto(target, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
                await page.wait_for_timeout(wait_ms)
                final_url = str(page.url)
                scripts = await self._collect_scripts(page)
                taint = extract_taint_candidates(scripts)

                marker_dialogs = [
                    item for item in dialogs
                    if item.get("message", "").strip() == marker and same_origin(target, item.get("origin", ""))
                ]

                await page.goto(baseline_url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
                await page.wait_for_timeout(wait_ms)
                solved_after = await self._is_solved(page)

                verification = {
                    "verified": False,
                    "browserExecuted": True,
                    "fallback": False,
                    "parameter": parameter[:200],
                    "expectedMarker": marker,
                    "markerMatched": bool(marker_dialogs),
                    "markerOrigin": marker_dialogs[0]["origin"] if marker_dialogs else None,
                    "dialogMessages": [item.get("message", "") for item in dialogs[:8]],
                    "solvedBefore": False,
                    "solvedAfter": bool(solved_after),
                    "solvedTransition": not solved_before and bool(solved_after),
                    "blockedRequests": blocked_requests,
                    **taint,
                }
                verification["verified"] = verification_is_confirmed(verification)
                findings = [build_nuclei_finding(target, verification)] if verification["verified"] else []
                result = {
                    "success": True,
                    "target": target,
                    "baselineUrl": baseline_url,
                    "finalUrl": final_url,
                    "fallback": False,
                    "verification": verification,
                    "findings": findings,
                    "summary": {
                        "verified": bool(verification["verified"]),
                        "sources": len(taint["sourceCandidates"]),
                        "sinks": len(taint["sinkCandidates"]),
                        "findings": len(findings),
                    },
                    "findings_delivered": len(findings),
                }
                if agent:
                    agent.append_output(
                        f"[browser:dom_probe] verified={result['summary']['verified']} sources={result['summary']['sources']} sinks={result['summary']['sinks']} findings={len(findings)}"
                    )
                    agent.report_progress("DOM proof completed", target, 1, 1)
                return result
        except Exception as exc:
            return {
                "success": False,
                "fallback": False,
                "target": target,
                "baselineUrl": baseline_url,
                "errorCode": "BROWSER_PROBE_FAILED",
                "error": f"browser DOM probe failed: {exc}",
            }
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass
            if browser is not None:
                try:
                    await close_browser_safe(browser)
                except Exception:
                    pass

    @staticmethod
    async def _is_solved(page: Any) -> bool:
        return bool(
            await page.evaluate(
                """() => Boolean(
                  document.querySelector('.academyLabBanner.is-solved, .widgetcontainer-lab-status.is-solved, [data-lab-status="solved"]') ||
                  /\bsolved\b/i.test((document.querySelector('.academyLabBanner, .widgetcontainer-lab-status') || {}).textContent || '')
                )"""
            )
        )

    @staticmethod
    async def _collect_scripts(page: Any) -> List[Dict[str, str]]:
        return await page.evaluate(
            """async () => {
              const rows = [];
              const scripts = Array.from(document.scripts).slice(0, 24);
              for (let index = 0; index < scripts.length; index += 1) {
                const script = scripts[index];
                if (!script.src) {
                  rows.push({id: `inline:${index}`, url: `inline:${index}`, text: (script.textContent || '').slice(0, 20000)});
                  continue;
                }
                try {
                  const url = new URL(script.src, location.href);
                  if (url.origin !== location.origin) continue;
                  const response = await fetch(url.href, {credentials: 'include', method: 'GET'});
                  rows.push({id: url.href, url: url.href, text: (await response.text()).slice(0, 20000)});
                } catch (_) {}
              }
              return rows;
            }"""
        )


def get_tool() -> BrowserDomProbeTool:
    return BrowserDomProbeTool()
