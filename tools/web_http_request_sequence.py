"""
Multi-step HTTP request sequence tool for agentic active probing.

Phase 3 (PR E.1) of the code-assisted-pentest roadmap. Used by the
Business-Logic Pentester to execute the approved `multi_step_probe_plan`
artifact: ordered HttpStep[] with `dependsOn` JSONPath substitution and
optional burst{count, sync} race-window probes.

Approval-gated via the `multi_step_probe_plan` ApprovalScope (PR E.2);
the dispatcher seam 5 verifies the `probePlanId` snapshotHash before
allowing the call to proceed (PR E.4 revert-plan enforcement).

Session re-use: the dispatcher's auth-enrichment seam injects
`authCookies` / `cookie` / `authHeaders` derived from the workflow's
existing AuthContext. The tool propagates them verbatim into every
step — never re-logins between steps.

Default burst cap is 10 concurrent requests. Higher counts (up to 50)
require the parent plan to declare `burstApproved=true` (set by the
dispatcher after operator approves the plan with explicit
`burst.count > 10`).
"""

import asyncio
import json
import re
import time
from typing import Any, Dict, List, Optional

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import redact_headers, run_process


# Default per-step timeout (seconds) and burst caps.
DEFAULT_TIMEOUT = 20
MAX_TIMEOUT = 120
DEFAULT_BURST_CAP = 10
MAX_BURST_CAP = 50
MAX_STEPS = 50
MAX_RESPONSE_BYTES = 200_000

# Methods allowed at the tool level. The dispatcher's seam 5 + the
# multi_step_probe_plan approval gate is the primary authorization
# surface; this is a defense-in-depth guard.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ALL_METHODS = SAFE_METHODS | MUTATING_METHODS

# Simple {{path.to.value}} substitution against the accumulated
# responses[] list. Each capture is `$.responses[i].path.to.value`.
# We support the dotted-path subset of JSONPath — full RFC 9535 is
# overkill for the BLP probe-plan templating contract.
TEMPLATE_RE = re.compile(r"\{\{\s*([\w$.\[\]]+)\s*\}\}")


class HttpRequestSequenceTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:http_request_sequence"

    @property
    def description(self) -> str:
        return (
            "Executes an ordered HttpStep[] with optional burst race-window "
            "probes and dependsOn JSONPath substitution from prior responses. "
            "Used by the Business-Logic Pentester to validate multi-step "
            "invariant violations against the running target. Operator must "
            "approve the parent multi_step_probe_plan before any step fires."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "sequence": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_STEPS,
                    "items": {
                        "type": "object",
                        "properties": {
                            "method": {"type": "string"},
                            "url": {"type": "string"},
                            "headers": {"type": "object"},
                            "body": {"type": "string"},
                            "burst": {
                                "type": "object",
                                "properties": {
                                    "count": {
                                        "type": "integer",
                                        "minimum": 2,
                                        "maximum": MAX_BURST_CAP,
                                    },
                                    "sync": {"type": "string", "enum": ["BARRIER"]},
                                },
                            },
                            "expectedStatus": {"type": "integer"},
                            "capture": {"type": "object"},
                        },
                        "required": ["url"],
                    },
                },
                "authCookies": {"type": "string"},
                "cookie": {"type": "string"},
                "authHeaders": {"type": "object"},
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "burstApproved": {"type": "boolean", "default": False},
                "probePlanId": {"type": "string"},
                # W.33.B.7 finalization (FP-elim gap 3) — structural
                # backlink to the upstream code finding that motivated
                # this probe. When set, the backend ingestion post-hook
                # synthesizes `upstreamCodeFindingMatch` automatically
                # so the code↔runtime correlation no longer depends on
                # the LLM coordinator manually threading the link. The
                # agent tool itself does not consume this field — it's
                # forwarded to the job parameters and read by
                # `IngestionService.processBusinessLogicFindings`.
                "sourceFindingId": {"type": "string"},
                # W.33.B.7 — structural opt-in to the BLP / HYBRID
                # ingestion path. When true, the backend treats this
                # sequence's output through the BLP evidence floor
                # validator and stamps `evidenceClass='HYBRID'` on the
                # emitted findings. Required when `sourceFindingId` is
                # set (the link is only meaningful for findings that
                # carry the HYBRID treatment).
                "annotateForBlp": {"type": "boolean", "default": False},
                # W.33.B.7 — structural backlink shape used by
                # IngestionService.linkUpstreamCodeFinding. Either set
                # this directly or set sourceFindingId and let the
                # backend pre-hook synthesize the match.
                "upstreamCodeFindingMatch": {
                    "type": "object",
                    "properties": {
                        "sourceFilePath": {"type": "string"},
                        "sourceLineRange": {"type": "array"},
                        "commitSha": {"type": "string"},
                        "enclosingHandler": {"type": "string"},
                    },
                },
                "invariantId": {"type": "string"},
                "invariantEvidence": {"type": "object"},
                "findingTitle": {"type": "string"},
                "findingDescription": {"type": "string"},
                "findingSeverity": {"type": "string"},
            },
            "required": ["sequence"],
        }

    @property
    def metadata(self):
        return {
            "category": "http.sequence",
            "phase": 3,
            "domain": ["web"],
            "input_type": ["multi_step_probe_plan"],
            "output_type": ["http_transcript"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        sequence: List[Dict[str, Any]] = parameters.get("sequence") or []
        if not isinstance(sequence, list) or len(sequence) == 0:
            return {"success": False, "error": "sequence must be a non-empty array"}
        if len(sequence) > MAX_STEPS:
            return {
                "success": False,
                "error": f"sequence exceeds MAX_STEPS={MAX_STEPS}",
            }

        burst_approved = bool(parameters.get("burstApproved", False))
        allow_unsafe_methods = bool(parameters.get("allowUnsafeMethods", False))
        auth_cookies = parameters.get("authCookies") or parameters.get("cookie")
        auth_headers = parameters.get("authHeaders") or {}
        if not isinstance(auth_headers, dict):
            auth_headers = {}

        responses: List[Dict[str, Any]] = []
        transcript: List[Dict[str, Any]] = []
        anomalies: List[str] = []
        started = time.time()

        for i, step in enumerate(sequence):
            try:
                resolved = self._resolve_template(step, responses)
            except Exception as exc:
                anomalies.append(f"step[{i}].dependsOn unresolved: {exc}")
                transcript.append({"stepIndex": i, "error": str(exc)})
                break

            method = str(resolved.get("method") or "GET").upper()
            if method not in ALL_METHODS:
                anomalies.append(f"step[{i}].method invalid: {method}")
                break
            if method not in SAFE_METHODS and not allow_unsafe_methods:
                return {
                    "success": False,
                    "error": f"step[{i}].method {method} requires allowUnsafeMethods=true",
                    "safeMethods": sorted(SAFE_METHODS),
                }

            burst = resolved.get("burst")
            if isinstance(burst, dict):
                count = int(burst.get("count") or DEFAULT_BURST_CAP)
                if count > DEFAULT_BURST_CAP and not burst_approved:
                    return {
                        "success": False,
                        "error": (
                            f"burst.count={count} exceeds default cap {DEFAULT_BURST_CAP}; "
                            "parent multi_step_probe_plan must set burstApproved=true via "
                            "the per-plan approval flow"
                        ),
                        "code": "BURST_LIMIT_EXCEEDED",
                    }
                if count > MAX_BURST_CAP:
                    return {
                        "success": False,
                        "error": f"burst.count={count} exceeds hard cap {MAX_BURST_CAP}",
                        "code": "BURST_LIMIT_EXCEEDED",
                    }
                # Execute burst with asyncio.Barrier to start all requests
                # within the same tick (race-window confirmation).
                burst_results = await self._execute_burst(
                    resolved, count, auth_cookies, auth_headers
                )
                transcript.append({"stepIndex": i, "burstResults": burst_results})
                # Record the first successful response for downstream
                # dependsOn substitution.
                first_ok = next(
                    (r for r in burst_results if r.get("success") is True), None
                )
                responses.append(first_ok or burst_results[0])
            else:
                result = await self._execute_one(
                    resolved, auth_cookies, auth_headers
                )
                transcript.append({"stepIndex": i, **result})
                responses.append(result)
                expected = resolved.get("expectedStatus")
                if isinstance(expected, int) and result.get("status") != expected:
                    anomalies.append(
                        f"step[{i}] status={result.get('status')} != expected {expected}"
                    )

        duration_ms = int((time.time() - started) * 1000)
        return {
            "success": True,
            "transcript": transcript,
            "responses": responses,
            "summary": {
                "totalSteps": len(transcript),
                "anomalies": anomalies,
                "durationMs": duration_ms,
                "allowUnsafeMethods": allow_unsafe_methods,
            },
        }

    # ────────────────────────────────────────────────────────────────
    # Internals
    # ────────────────────────────────────────────────────────────────

    def _resolve_template(
        self, step: Dict[str, Any], responses: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Replace {{$.responses[i].foo.bar}} placeholders against `responses`."""
        as_json = json.dumps(step)
        def sub(match: re.Match) -> str:
            path = match.group(1)
            return str(self._jsonpath(path, {"responses": responses}))
        rendered = TEMPLATE_RE.sub(sub, as_json)
        return json.loads(rendered)

    def _jsonpath(self, path: str, root: Any) -> Any:
        # Strip the optional leading $.
        path = path.lstrip("$").lstrip(".")
        cursor = root
        for part in re.findall(r"\w+|\[\d+\]", path):
            if part.startswith("[") and part.endswith("]"):
                idx = int(part[1:-1])
                if not isinstance(cursor, list) or idx >= len(cursor):
                    raise ValueError(f"index {part} out of range in {path}")
                cursor = cursor[idx]
            else:
                if not isinstance(cursor, dict) or part not in cursor:
                    raise ValueError(f"key {part} not found in {path}")
                cursor = cursor[part]
        return cursor

    async def _execute_one(
        self,
        step: Dict[str, Any],
        auth_cookies: Optional[str],
        auth_headers: Dict[str, Any],
    ) -> Dict[str, Any]:
        url = step.get("url")
        if not url:
            return {"success": False, "error": "step missing url"}
        method = str(step.get("method") or "GET").upper()
        body = step.get("body")
        headers: Dict[str, Any] = {}
        headers.update(auth_headers)
        step_headers = step.get("headers")
        if isinstance(step_headers, dict):
            headers.update(step_headers)
        timeout_seconds = min(
            max(int(step.get("timeoutSeconds") or DEFAULT_TIMEOUT), 3),
            MAX_TIMEOUT,
        )

        cmd = [
            "curl",
            "--silent",
            "--show-error",
            "--max-time",
            str(timeout_seconds),
            "--connect-timeout",
            "8",
            "--request",
            method,
            "--include",
        ]
        if auth_cookies:
            cmd += ["--cookie", auth_cookies]
        for hk, hv in headers.items():
            cmd += ["--header", f"{hk}: {hv}"]
        if body and method in MUTATING_METHODS:
            cmd += ["--data-binary", str(body)]
        cmd.append(url)

        # Truncate output for budget.
        try:
            proc = await run_process(cmd, max_bytes=MAX_RESPONSE_BYTES)
        except Exception as exc:  # pragma: no cover
            return {"success": False, "error": str(exc), "url": url, "method": method}

        stdout = proc.get("stdout", "")
        # Crude status parse from `HTTP/1.1 NNN ...` first line.
        status_match = re.match(r"HTTP/[\d.]+\s+(\d{3})", stdout)
        status = int(status_match.group(1)) if status_match else None

        # Header / body split on first blank line.
        split_idx = stdout.find("\r\n\r\n")
        header_block = stdout[:split_idx] if split_idx > -1 else ""
        body_block = stdout[split_idx + 4 :] if split_idx > -1 else stdout
        body_block = body_block[: MAX_RESPONSE_BYTES // 4]

        return {
            "success": proc.get("returncode", 0) == 0,
            "url": url,
            "method": method,
            "status": status,
            "headers": redact_headers(header_block),
            "body": body_block,
        }

    async def _execute_burst(
        self,
        step: Dict[str, Any],
        count: int,
        auth_cookies: Optional[str],
        auth_headers: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        # Use asyncio.Barrier (Python 3.11+) — falls back to asyncio.Event
        # for older runtimes. The barrier guarantees all N requests start
        # within ~5ms, which is the race-window confirmation primitive.
        try:
            barrier = asyncio.Barrier(count)  # type: ignore[attr-defined]
            async def one_with_barrier():
                await barrier.wait()
                return await self._execute_one(step, auth_cookies, auth_headers)
            tasks = [asyncio.create_task(one_with_barrier()) for _ in range(count)]
        except AttributeError:
            ev = asyncio.Event()
            async def one_with_event():
                await ev.wait()
                return await self._execute_one(step, auth_cookies, auth_headers)
            tasks = [asyncio.create_task(one_with_event()) for _ in range(count)]
            ev.set()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [
            r if isinstance(r, dict) else {"success": False, "error": str(r)}
            for r in results
        ]
