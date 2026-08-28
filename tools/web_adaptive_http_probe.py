"""Bounded, artifact-driven adaptive HTTP probing.

The public call supplies only the workflow target.  Executable requests come
from a private, server-owned plan envelope hydrated immediately
before dispatch.  This module intentionally performs no model calls: it runs a
closed five-request GET differential and emits compact, sanitized proof for the
backend to verify independently.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import re
import time
from collections import Counter
from dataclasses import replace
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, quote, unquote, urlsplit

from plugin_interface import ToolPlugin
from tools.web_http_request_sequence import (
    SERVER_POLICY_KEY,
    _OpaqueHttpSession,
    _PolicyError,
    _RequestSequencePolicy,
    _TranscriptSanitizer,
    _canonical_origin,
    _has_unsafe_graphql_get,
    _redact_transcript_headers,
)


SERVER_PLAN_KEY = "_serverAdaptiveProbePlan"
PLAN_TEMPLATE_ID = "scalar-syntax-repair-v1"

EXPECTED_LABELS = (
    "baseline",
    "benign-control",
    "syntax-break",
    "syntax-repair",
    "baseline-replay",
)
ARTIFACT_KINDS = {"html-form", "request-candidate"}
SURFACE_CLASSES = {"api", "form", "parameterized-url"}
EXPECTED_BUDGETS: Dict[str, int] = {
    "maxCatalogCandidates": 20,
    "maxProbeUnits": 10,
    "maxRequests": 50,
    "maxResponseBytes": 65_536,
    "maxTotalResponseBytes": 2_097_152,
    "maxEvidenceBodyBytes": 8_192,
    "maxRuntimeMs": 90_000,
    "maxRedirects": 3,
    "requestsPerOriginPerSecond": 2,
    "concurrency": 1,
}

_PLAN_KEYS = {"version", "templateId", "origin", "units", "skipped", "budgets"}
_UNIT_KEYS = {
    "unitId",
    "candidateId",
    "artifactKind",
    "surfaceClass",
    "parameterName",
    "requests",
}
_REQUEST_KEYS = {"label", "method", "url"}
_SKIPPED_KEYS = {"candidateId", "reasonCode"}
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\[\]-]{0,127}$")
_ERROR_MARKERS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "SQL_SYNTAX",
        re.compile(
            r"(?:sql(?:ite)?\s+(?:syntax|parse)\s+error|sqlstate\[|"
            r"unterminated\s+(?:quoted\s+string|quotation)|"
            r"syntax\s+error\s+at\s+or\s+near|"
            r"you have an error in your sql syntax|ora-\d{4,5}|"
            r"unclosed quotation mark)",
            re.IGNORECASE,
        ),
    ),
    (
        "QUERY_PARSER",
        re.compile(
            r"(?:parse\s+error|parser\s+error|unexpected\s+(?:token|character)|"
            r"invalid\s+(?:query|expression|filter|regular expression)|"
            r"query(?:string)?\s+syntax\s+error)",
            re.IGNORECASE,
        ),
    ),
    (
        "UNHANDLED_EXCEPTION",
        re.compile(
            r"(?:traceback \(most recent call last\)|stack trace|"
            r"uncaught\s+[a-z0-9_.]+exception|internal server error\s*[:\-]\s*"
            r"[a-z0-9_.]+exception)",
            re.IGNORECASE,
        ),
    ),
)


class _EnvelopeError(ValueError):
    """Malformed private envelope; safe to expose as a bounded denial."""


class _ProbeRequest(NamedTuple):
    label: str
    method: str
    url: str


class _ProbeUnit(NamedTuple):
    unit_id: str
    candidate_id: str
    artifact_kind: str
    surface_class: str
    parameter_name: str
    requests: Tuple[_ProbeRequest, ...]


class _ProbePlan(NamedTuple):
    origin: str
    units: Tuple[_ProbeUnit, ...]
    skipped: Tuple[Dict[str, str], ...]


def _exact_keys(value: Dict[str, Any], expected: set[str], field: str) -> None:
    if set(value) != expected:
        raise _EnvelopeError(f"{field} must contain exactly {sorted(expected)}")


def _safe_string(value: Any, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise _EnvelopeError(f"{field} is invalid")
    return value


def _parse_plan(raw: Any) -> _ProbePlan:
    if not isinstance(raw, dict):
        raise _EnvelopeError(f"{SERVER_PLAN_KEY} is required")
    _exact_keys(raw, _PLAN_KEYS, SERVER_PLAN_KEY)
    if raw.get("version") != 1 or raw.get("templateId") != PLAN_TEMPLATE_ID:
        raise _EnvelopeError("server adaptive plan must use scalar-syntax-repair-v1 v1")
    budgets = raw.get("budgets")
    if budgets != EXPECTED_BUDGETS:
        raise _EnvelopeError("server adaptive plan budgets diverge from the closed v1 caps")

    origin_raw = raw.get("origin")
    try:
        origin, _host, _port = _canonical_origin(origin_raw)
    except _PolicyError as exc:
        raise _EnvelopeError(f"server adaptive plan origin is invalid: {exc}") from exc
    if origin_raw != origin:
        raise _EnvelopeError("server adaptive plan origin must be canonical")

    raw_units = raw.get("units")
    if (
        not isinstance(raw_units, list)
        or len(raw_units) == 0
        or len(raw_units) > EXPECTED_BUDGETS["maxProbeUnits"]
    ):
        raise _EnvelopeError("server adaptive plan units must contain 1..10 entries")
    units: List[_ProbeUnit] = []
    unit_ids: set[str] = set()
    candidate_ids: set[str] = set()
    total_requests = 0
    for index, item in enumerate(raw_units):
        field = f"{SERVER_PLAN_KEY}.units[{index}]"
        if not isinstance(item, dict):
            raise _EnvelopeError(f"{field} must be an object")
        _exact_keys(item, _UNIT_KEYS, field)
        unit_id = _safe_string(item.get("unitId"), _ID_RE, f"{field}.unitId")
        candidate_id = _safe_string(item.get("candidateId"), _ID_RE, f"{field}.candidateId")
        if unit_id in unit_ids or candidate_id in candidate_ids:
            raise _EnvelopeError("server adaptive plan unitId/candidateId values must be unique")
        unit_ids.add(unit_id)
        candidate_ids.add(candidate_id)
        artifact_kind = str(item.get("artifactKind") or "")
        surface_class = str(item.get("surfaceClass") or "")
        parameter_name = _safe_string(
            item.get("parameterName"), _SAFE_NAME_RE, f"{field}.parameterName"
        )
        if artifact_kind not in ARTIFACT_KINDS:
            raise _EnvelopeError(f"{field}.artifactKind is invalid")
        if surface_class not in SURFACE_CLASSES:
            raise _EnvelopeError(f"{field}.surfaceClass is invalid")

        raw_requests = item.get("requests")
        if not isinstance(raw_requests, list) or len(raw_requests) != len(EXPECTED_LABELS):
            raise _EnvelopeError(f"{field}.requests must contain the closed five-request template")
        requests: List[_ProbeRequest] = []
        observed_labels: List[str] = []
        for request_index, request in enumerate(raw_requests):
            request_field = f"{field}.requests[{request_index}]"
            if not isinstance(request, dict):
                raise _EnvelopeError(f"{request_field} must be an object")
            _exact_keys(request, _REQUEST_KEYS, request_field)
            label = str(request.get("label") or "")
            method = str(request.get("method") or "").upper()
            url = request.get("url")
            if method != "GET":
                raise _EnvelopeError(f"{request_field}.method must be GET")
            if not isinstance(url, str):
                raise _EnvelopeError(f"{request_field}.url must be a string")
            if _has_unsafe_graphql_get(url):
                raise _EnvelopeError(
                    f"{request_field}.url contains a GraphQL write document"
                )
            try:
                request_origin, _request_host, _request_port = _canonical_origin(url)
            except _PolicyError as exc:
                raise _EnvelopeError(f"{request_field}.url is invalid: {exc}") from exc
            if request_origin != origin:
                raise _EnvelopeError(f"{request_field}.url must remain on the plan origin")
            observed_labels.append(label)
            requests.append(_ProbeRequest(label=label, method=method, url=url))
        if tuple(observed_labels) != EXPECTED_LABELS:
            raise _EnvelopeError(f"{field}.requests labels/order diverge from the closed template")
        if requests[0].url != requests[-1].url:
            raise _EnvelopeError(f"{field}.baseline replay must equal the baseline URL")
        total_requests += len(requests)
        units.append(
            _ProbeUnit(
                unit_id=unit_id,
                candidate_id=candidate_id,
                artifact_kind=artifact_kind,
                surface_class=surface_class,
                parameter_name=parameter_name,
                requests=tuple(requests),
            )
        )

    if total_requests > EXPECTED_BUDGETS["maxRequests"]:
        raise _EnvelopeError("server adaptive plan requests exceed the v1 cap")

    raw_skipped = raw.get("skipped")
    if not isinstance(raw_skipped, list) or len(raw_skipped) > 20:
        raise _EnvelopeError("server adaptive plan skipped must contain at most 20 entries")
    skipped: List[Dict[str, str]] = []
    skipped_ids: set[str] = set()
    for index, item in enumerate(raw_skipped):
        field = f"{SERVER_PLAN_KEY}.skipped[{index}]"
        if not isinstance(item, dict):
            raise _EnvelopeError(f"{field} must be an object")
        _exact_keys(item, _SKIPPED_KEYS, field)
        candidate_id = _safe_string(item.get("candidateId"), _ID_RE, f"{field}.candidateId")
        reason = str(item.get("reasonCode") or "")
        if candidate_id in candidate_ids or candidate_id in skipped_ids:
            raise _EnvelopeError("server adaptive plan candidate routing must be unique")
        if not _ID_RE.fullmatch(reason):
            raise _EnvelopeError(f"{field}.reason is invalid")
        skipped_ids.add(candidate_id)
        skipped.append({"candidateId": candidate_id, "reasonCode": reason})

    if len(candidate_ids) + len(skipped_ids) > EXPECTED_BUDGETS["maxCatalogCandidates"]:
        raise _EnvelopeError("server adaptive plan references exceed the catalog cap")
    return _ProbePlan(origin=origin, units=tuple(units), skipped=tuple(skipped))


def _status_error(code: str, message: str) -> Dict[str, Any]:
    return {
        "success": False,
        "coverageStatus": "INCOMPLETE",
        "code": code,
        "error": message,
    }


def _request_parameter_values(requests: Sequence[_ProbeRequest], parameter_name: str) -> List[str]:
    values: List[str] = []
    for request in requests:
        for key, value in parse_qsl(urlsplit(request.url).query, keep_blank_values=True):
            if key == parameter_name and value not in values:
                values.append(value)
    paths = [
        [unquote(segment) for segment in urlsplit(request.url).path.split("/")]
        for request in requests
    ]
    maximum_parts = max((len(parts) for parts in paths), default=0)
    for index in range(maximum_parts):
        at_index = [parts[index] if index < len(parts) else "" for parts in paths]
        if len(set(at_index)) <= 1:
            continue
        for value in at_index:
            if value and value not in values:
                values.append(value)
    return values


def _reflection_neutralized_body(body: Any, values: Sequence[str], sanitizer: _TranscriptSanitizer) -> str:
    text = sanitizer.sanitize_text(body)
    variants: set[str] = set()
    for raw_value in values:
        value = str(raw_value)
        variants.update(
            {
                value,
                unquote(value),
                quote(value, safe=""),
                quote(value, safe="", encoding="utf-8").lower(),
                html.escape(value, quote=True),
                html.escape(unquote(value), quote=True),
                json.dumps(value)[1:-1],
            }
        )
    for variant in sorted((item for item in variants if item), key=len, reverse=True):
        text = re.sub(re.escape(variant), "<probe-value>", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip()
    return text[: EXPECTED_BUDGETS["maxEvidenceBodyBytes"]]


def _similarity(left: str, right: str) -> float:
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    def trigrams(value: str) -> Counter[str]:
        if len(value) < 3:
            return Counter({value: 1})
        return Counter(value[index : index + 3] for index in range(len(value) - 2))

    left_grams = trigrams(left)
    right_grams = trigrams(right)
    overlap = sum((left_grams & right_grams).values())
    return (2.0 * overlap) / (sum(left_grams.values()) + sum(right_grams.values()))


def _error_families(body: str) -> List[str]:
    return [family for family, pattern in _ERROR_MARKERS if pattern.search(body)]


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


class WebAdaptiveHttpProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:adaptive_http_probe"

    @property
    def description(self) -> str:
        return (
            "Executes a server-owned, GET-only five-request scalar differential over "
            "observed HTTP candidates. Requests are deterministic, stateful, IP-pinned, "
            "same-origin, rate-limited, and returned as sanitized Request/Response proof."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "format": "uri"},
                "engagement": {
                    "type": "string",
                    "enum": ["standard", "aggressive", "lab", "ctf"],
                },
                "allowUnsafeMethods": {"type": "boolean"},
                "authCookies": {"type": "string", "x-private": True},
                "cookie": {"type": "string", "x-private": True},
                "authHeaders": {"type": "object", "x-private": True},
                SERVER_PLAN_KEY: {"type": "object", "x-private": True},
                SERVER_POLICY_KEY: {"type": "object", "x-private": True},
            },
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 3,
            "domain": ["web", "api"],
            "input_type": ["url", "request_candidate_artifact"],
            "output_type": ["coverage", "http_transcript", "proof"],
            "chainable_after": ["decision:exploitation_queue", "browser:", "api:"],
            "chainable_before": ["decision:"],
            "lifecycle_phase": "exploit-test",
            "primary_purpose": "Execute a bounded server-owned HTTP differential",
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        if parameters.get("allowUnsafeMethods") not in (None, False):
            return _status_error(
                "UNSAFE_METHODS_FORBIDDEN",
                "web:adaptive_http_probe is GET-only and rejects unsafe-method authority",
            )
        raw_plan = parameters.get(SERVER_PLAN_KEY)
        try:
            plan = _parse_plan(raw_plan)
        except _EnvelopeError as exc:
            return _status_error(
                "SERVER_ADAPTIVE_PROBE_ENVELOPE_REQUIRED"
                if raw_plan is None
                else "SERVER_ADAPTIVE_PROBE_ENVELOPE_DENY",
                str(exc),
            )

        target = parameters.get("target")
        try:
            target_origin, _target_host, _target_port = _canonical_origin(target)
        except _PolicyError as exc:
            return _status_error("TARGET_INVALID", str(exc))
        if target_origin != plan.origin:
            return _status_error(
                "SERVER_ADAPTIVE_PROBE_ENVELOPE_DENY",
                "public target origin diverges from the server adaptive plan",
            )

        raw_policy = parameters.get(SERVER_POLICY_KEY)
        try:
            policy = _RequestSequencePolicy.parse(raw_policy)
        except _PolicyError as exc:
            return _status_error(
                "SERVER_REQUEST_SEQUENCE_POLICY_REQUIRED"
                if raw_policy is None
                else "SERVER_REQUEST_SEQUENCE_POLICY_DENY",
                str(exc),
            )
        if (
            policy.max_redirects != EXPECTED_BUDGETS["maxRedirects"]
            or policy.max_steps != EXPECTED_BUDGETS["maxRequests"]
            or policy.max_response_bytes != EXPECTED_BUDGETS["maxResponseBytes"]
        ):
            return _status_error(
                "SERVER_REQUEST_SEQUENCE_POLICY_DENY",
                "server transport policy diverges from the closed adaptive v1 caps",
            )

        auth_headers = parameters.get("authHeaders") or {}
        if not isinstance(auth_headers, dict):
            return _status_error("AUTH_ENVELOPE_DENY", "authHeaders must be an object")
        auth_cookies = parameters.get("authCookies") or parameters.get("cookie")
        if auth_cookies and any(ch in str(auth_cookies) for ch in "\r\n"):
            return _status_error("AUTH_ENVELOPE_DENY", "auth cookie contains a line break")

        sanitizer = _TranscriptSanitizer()
        try:
            session = _OpaqueHttpSession(plan.origin, auth_cookies, auth_headers, sanitizer)
        except _PolicyError as exc:
            return _status_error("SERVER_REQUEST_SEQUENCE_POLICY_DENY", str(exc))

        started = time.monotonic()
        deadline = started + (EXPECTED_BUDGETS["maxRuntimeMs"] / 1000.0)
        min_interval = 1.0 / EXPECTED_BUDGETS["requestsPerOriginPerSecond"]
        next_request_at = started
        total_response_bytes = 0
        requests_run = 0
        units_attempted = 0
        outcomes: List[Dict[str, Any]] = []
        stop_reason: Optional[str] = None

        for unit_index, unit in enumerate(plan.units):
            units_attempted += 1
            exchanges: List[Dict[str, Any]] = []
            unit_incomplete: Optional[str] = None
            for request in unit.requests:
                now = time.monotonic()
                if requests_run >= EXPECTED_BUDGETS["maxRequests"]:
                    unit_incomplete = stop_reason = "REQUEST_BUDGET_EXHAUSTED"
                    break
                remaining_bytes = EXPECTED_BUDGETS["maxTotalResponseBytes"] - total_response_bytes
                if remaining_bytes <= 0:
                    unit_incomplete = stop_reason = "RESPONSE_BYTE_BUDGET_EXHAUSTED"
                    break
                wait_seconds = max(0.0, next_request_at - now)
                if now + wait_seconds + 3.0 > deadline:
                    unit_incomplete = stop_reason = "RUNTIME_BUDGET_EXHAUSTED"
                    break
                if wait_seconds:
                    await asyncio.sleep(wait_seconds)
                request_started = time.monotonic()
                per_request_policy = replace(
                    policy,
                    max_redirects=min(policy.max_redirects, EXPECTED_BUDGETS["maxRedirects"]),
                    max_response_bytes=min(
                        policy.max_response_bytes,
                        EXPECTED_BUDGETS["maxResponseBytes"],
                        remaining_bytes,
                    ),
                )
                raw_result = await self._execute_one(
                    session,
                    per_request_policy,
                    request,
                    min(20, max(3, int(deadline - request_started))),
                )
                raw_result["_elapsedMs"] = int(
                    (time.monotonic() - request_started) * 1000
                )
                requests_run += 1
                next_request_at = request_started + min_interval
                body_bytes = int(raw_result.get("bodyBytes") or 0)
                total_response_bytes += max(0, body_bytes)
                if raw_result.get("success") is not True:
                    unit_incomplete = "HTTP_EXECUTION_FAILED"
                    break
                exchange = self._sanitize_exchange(request, raw_result, sanitizer)
                exchanges.append(exchange)
                if raw_result.get("truncated") is True:
                    unit_incomplete = "RESPONSE_TRUNCATED"
                    break
                if time.monotonic() > deadline:
                    unit_incomplete = stop_reason = "RUNTIME_BUDGET_EXHAUSTED"
                    break

            if unit_incomplete:
                outcomes.append(
                    self._incomplete_outcome(unit, exchanges, unit_incomplete)
                )
                for remaining in plan.units[unit_index + 1 :]:
                    outcomes.append(self._incomplete_outcome(remaining, [], "NOT_EXECUTED"))
                if stop_reason is None:
                    stop_reason = unit_incomplete
                break

            outcome = self._classify_unit(unit, exchanges, sanitizer)
            outcomes.append(outcome)

        elapsed_ms = min(
            int((time.monotonic() - started) * 1000),
            EXPECTED_BUDGETS["maxRuntimeMs"],
        )
        planned_requests = sum(len(unit.requests) for unit in plan.units)
        represented_response_bytes = sum(
            int(exchange["response"].get("bodyLength") or 0)
            for outcome in outcomes
            for exchange in outcome.get("evidence", {}).get("exchanges") or []
        )
        if stop_reason is None:
            first_incomplete = next(
                (
                    outcome
                    for outcome in outcomes
                    if outcome.get("status") == "INCOMPLETE"
                ),
                None,
            )
            if first_incomplete is not None:
                stop_reason = str(first_incomplete.get("reasonCode") or "INCOMPLETE")
        complete = (
            stop_reason is None
            and requests_run == planned_requests
            and all(outcome.get("status") != "INCOMPLETE" for outcome in outcomes)
        )
        has_confirmed = any(
            outcome.get("status") == "CONFIRMED" for outcome in outcomes
        )
        skipped_by_reason: Dict[str, int] = {}
        for skipped in plan.skipped:
            reason = skipped["reasonCode"]
            skipped_by_reason[reason] = skipped_by_reason.get(reason, 0) + 1
        for outcome in outcomes:
            if outcome.get("status") in {"INCOMPLETE", "SKIPPED"}:
                reason = str(outcome.get("reasonCode") or "UNKNOWN")
                skipped_by_reason[reason] = skipped_by_reason.get(reason, 0) + 1

        # `success` is the agent/job protocol status, not the evidence coverage
        # status.  Once the closed server-owned plan has been accepted and the
        # executor has returned bounded, structurally complete outcomes, the
        # Job must be terminal COMPLETED even when one or more units are
        # INCOMPLETE.  Otherwise the agent runtime stores the entire structured
        # output as a failed Job and the backend proof gate never gets a chance
        # to preserve independently CONFIRMED sibling outcomes.
        return {
            "success": True,
            "version": 1,
            "templateId": PLAN_TEMPLATE_ID,
            "coverageStatus": (
                "INCOMPLETE"
                if not complete
                else ("CONFIRMED" if has_confirmed else "COMPLETE_NO_FINDING")
            ),
            "orderedUnitIds": [unit.unit_id for unit in plan.units],
            "coverage": {
                "candidatesReferenced": len(plan.units) + len(plan.skipped),
                "eligibleCandidates": len(plan.units),
                "probeUnitsPlanned": len(plan.units),
                "probeUnitsAttempted": units_attempted,
                "requestsPlanned": planned_requests,
                "requestsRun": requests_run,
                "responseBytesRead": max(
                    total_response_bytes, represented_response_bytes
                ),
                "durationMs": elapsed_ms,
                "stopReason": stop_reason,
                "skippedByReason": skipped_by_reason,
            },
            "outcomes": outcomes,
        }

    async def _execute_one(
        self,
        session: _OpaqueHttpSession,
        policy: _RequestSequencePolicy,
        request: _ProbeRequest,
        timeout_seconds: int,
    ) -> Dict[str, Any]:
        step = {
            "method": "GET",
            "url": request.url,
            "headers": {
                "Accept": "text/html,application/json;q=0.9,*/*;q=0.5",
                "User-Agent": "xASM-adaptive-http-probe/1.0",
            },
            "timeoutSeconds": timeout_seconds,
        }
        try:
            return await asyncio.to_thread(session.request, step, policy)
        except _PolicyError as exc:
            return {
                "success": False,
                "code": "SERVER_REQUEST_SEQUENCE_POLICY_DENY",
                "error": str(exc),
                "url": request.url,
                "method": "GET",
                "requestHeaders": step["headers"],
            }
        except Exception as exc:  # pragma: no cover - defensive transport seam
            return {
                "success": False,
                "code": "HTTP_EXECUTION_FAILED",
                "error": f"HTTP executor failed: {exc}",
                "url": request.url,
                "method": "GET",
                "requestHeaders": step["headers"],
            }

    def _sanitize_exchange(
        self,
        request: _ProbeRequest,
        result: Dict[str, Any],
        sanitizer: _TranscriptSanitizer,
    ) -> Dict[str, Any]:
        sanitizer.add_structured_secrets("adaptive-response", result.get("body"))
        request_headers = _redact_transcript_headers(result.get("requestHeaders"))
        response_headers = _redact_transcript_headers(result.get("headers"))
        sanitized_body = sanitizer.sanitize_text(result.get("body"))
        body_bytes = sanitized_body.encode("utf-8", errors="replace")
        evidence_truncated = len(body_bytes) > EXPECTED_BUDGETS["maxEvidenceBodyBytes"]
        if evidence_truncated:
            sanitized_body = body_bytes[: EXPECTED_BUDGETS["maxEvidenceBodyBytes"]].decode(
                "utf-8", errors="ignore"
            )
        # The URL is the already validated server-owned plan identity.  It must
        # remain byte-for-byte stable so the backend can bind evidence to the
        # immutable plan; secret-bearing URL candidates are excluded upstream.
        safe_url = request.url
        exchange: Dict[str, Any] = {
            "label": request.label,
            "request": {
                "method": "GET",
                "url": safe_url,
                "headers": {
                    key: sanitizer.sanitize_text(value)
                    for key, value in request_headers.items()
                },
                "bodyLength": 0,
            },
            "response": {
                "status": result.get("status"),
                "headers": {
                    key: sanitizer.sanitize_text(value)
                    for key, value in response_headers.items()
                },
                "body": sanitized_body,
                "bodySha256": _sha256(sanitized_body),
                "bodyLength": (
                    len(body_bytes)
                    if evidence_truncated
                    else len(sanitized_body.encode("utf-8", errors="replace"))
                ),
                "truncated": bool(result.get("truncated")) or evidence_truncated,
                "elapsedMs": max(0, int(result.get("_elapsedMs") or 0)),
            },
        }
        return exchange

    def _classify_unit(
        self,
        unit: _ProbeUnit,
        exchanges: List[Dict[str, Any]],
        sanitizer: _TranscriptSanitizer,
    ) -> Dict[str, Any]:
        if any(exchange["response"].get("truncated") for exchange in exchanges):
            first_truncated = next(
                index
                for index, exchange in enumerate(exchanges)
                if exchange["response"].get("truncated")
            )
            return self._incomplete_outcome(
                unit, exchanges[:first_truncated], "EVIDENCE_BODY_TRUNCATED"
            )
        values = _request_parameter_values(unit.requests, unit.parameter_name)
        bodies = {
            exchange["label"]: _reflection_neutralized_body(
                exchange["response"].get("body"), values, sanitizer
            )
            for exchange in exchanges
        }
        baseline = bodies["baseline"]
        benign = bodies["benign-control"]
        syntax_break = bodies["syntax-break"]
        syntax_repair = bodies["syntax-repair"]
        replay = bodies["baseline-replay"]
        similarities = {
            "baselineReplay": _similarity(baseline, replay),
            "benignControl": _similarity(baseline, benign),
            "syntaxBreak": _similarity(baseline, syntax_break),
            "syntaxRepair": _similarity(baseline, syntax_repair),
        }
        baseline_stable = similarities["baselineReplay"] >= 0.95
        benign_stable = similarities["benignControl"] >= 0.90
        repair_recovered = similarities["syntaxRepair"] >= 0.90
        break_material = similarities["syntaxBreak"] < 0.75
        baseline_errors = set(_error_families(baseline) + _error_families(benign))
        break_errors = set(_error_families(syntax_break))
        novel_errors = sorted(break_errors - baseline_errors)
        error_family = novel_errors[0] if novel_errors else None
        baseline_status = exchanges[0]["response"].get("status")
        break_status = exchanges[2]["response"].get("status")
        status_only = (
            similarities["syntaxBreak"] >= 0.75
            and break_status != baseline_status
        )
        confirmed = bool(
            baseline_stable
            and benign_stable
            and repair_recovered
            and break_material
            and novel_errors
        )
        signal = bool(
            not confirmed
            and baseline_stable
            and benign_stable
            and repair_recovered
            and break_material
        )
        status = "CONFIRMED" if confirmed else ("SIGNAL" if signal else "NO_DIFFERENTIAL")
        return {
            "unitId": unit.unit_id,
            "candidateId": unit.candidate_id,
            "templateId": PLAN_TEMPLATE_ID,
            "status": status,
            "differential": {
                "baselineReplayStable": baseline_stable,
                "benignEquivalent": benign_stable,
                "syntaxBreakChangedBody": break_material,
                "syntaxRepairRecovered": repair_recovered,
                "statusOnly": status_only,
                "errorFamily": error_family,
            },
            "evidence": {"exchanges": exchanges},
        }

    def _incomplete_outcome(
        self,
        unit: _ProbeUnit,
        exchanges: List[Dict[str, Any]],
        reason: str,
    ) -> Dict[str, Any]:
        return {
            "unitId": unit.unit_id,
            "candidateId": unit.candidate_id,
            "templateId": PLAN_TEMPLATE_ID,
            "status": "INCOMPLETE",
            "reasonCode": reason,
            "evidence": {"exchanges": exchanges},
        }
