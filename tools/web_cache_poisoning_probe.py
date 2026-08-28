"""Fail-closed web-cache-poisoning confirmation primitives.

The first mode proves one narrow cache-key discrepancy: an origin honors a
URL-encoded parameter in a GET body while the shared cache keys only on the
query string. The tool retains a bounded four-transaction proof and never
confirms from reflection or cache headers alone.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from html import unescape
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import urlencode, urljoin, urlsplit

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import read_limited
from tools.web_authentication_probe import (
    ALLOWED_ENGAGEMENTS,
    MAX_EVIDENCE_CHARS,
    MAX_RESPONSE_BYTES,
    _field_name,
    _http_target,
    _path_and_query,
    _relative_path,
    sanitize_evidence_text,
)


ALLOWED_MODES = {"fat-get-query-body"}
# #1648 — two-tier proof. The runtime tier proves the vulnerability from its own
# evidence and needs no PortSwigger status page; the lab tier brackets it with the
# unsolved -> solved transition for calibration. Before this, the transition was
# mandatory at BOTH layers, so a confirmed finding on a customer application was
# impossible by construction.
ALLOWED_PROOF_LEVELS = {"runtime-cache-poison", "lab-state-change"}
STATE_CHANGE_ENGAGEMENTS = {"lab", "ctf"}
_STATE_CHANGE_PARAMETERS = {
    "statusPath",
    "unsolvedMarker",
    "solvedMarker",
}
RUNTIME_EXPECTED_STEP_LABELS = (
    "poison-cache-miss",
    "clean-cache-hit",
)
LAB_EXPECTED_STEP_LABELS = (
    "unsolved-baseline",
    *RUNTIME_EXPECTED_STEP_LABELS,
    "solved-confirmation",
)
EXPECTED_STEP_LABELS_BY_PROOF_LEVEL = {
    "runtime-cache-poison": RUNTIME_EXPECTED_STEP_LABELS,
    "lab-state-change": LAB_EXPECTED_STEP_LABELS,
}
# Back-compat alias; equals the lab shape.
EXPECTED_STEP_LABELS = LAB_EXPECTED_STEP_LABELS
MAX_MARKER_CHARS = 512
MAX_VALUE_CHARS = 256
MAX_TOTAL_WAIT_MS = 100_000
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}$")


def response_contains_marker(body: str, marker: str) -> bool:
    return marker in body or marker in unescape(body)


def cache_header_matches(headers: Any, name: str, marker: str) -> bool:
    value = str(headers.get(name) or "")
    return marker.lower() in value.lower()


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    target = _http_target(parameters.get("target") or parameters.get("url"))
    if not target:
        return False, "target must be a credential-free HTTP(S) base URL without query or fragment"
    if str(parameters.get("mode") or "").lower() not in ALLOWED_MODES:
        return False, "mode must be fat-get-query-body"
    if str(parameters.get("engagement") or "").lower() not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"

    # #1648 — tier resolution. No defaulting: an unrecognised value is rejected so
    # a typo cannot silently downgrade or upgrade the assertions.
    proof_level = str(parameters.get("proofLevel") or "").lower()
    if proof_level not in ALLOWED_PROOF_LEVELS:
        return False, "proofLevel must be runtime-cache-poison or lab-state-change"
    if proof_level == "lab-state-change":
        if str(parameters.get("engagement") or "").lower() not in STATE_CHANGE_ENGAGEMENTS:
            return False, "lab-state-change requires engagement lab or ctf"
    else:
        # The runtime tier must REJECT lab material rather than ignore it, or a
        # caller could believe a transition was proven when nothing checked it.
        unexpected = sorted(_STATE_CHANGE_PARAMETERS.intersection(parameters))
        if unexpected:
            return False, f"{unexpected[0]} is only allowed for proofLevel=lab-state-change"

    for key in ("statusPath", "cachePath"):
        if not _relative_path(parameters.get(key)):
            return False, f"{key} must be a bounded same-origin relative path"
    if not _field_name(parameters.get("bodyField")):
        return False, "bodyField must be a valid form-field name"

    body_value = str(parameters.get("bodyValue") or "")
    if (
        not body_value
        or len(body_value) > MAX_VALUE_CHARS
        or "\r" in body_value
        or "\n" in body_value
        or "\0" in body_value
    ):
        return False, "bodyValue is required, bounded, and must not contain control-line characters"

    markers = {
        key: str(parameters.get(key) or "")
        for key in ("unsolvedMarker", "solvedMarker", "cleanMarker", "poisonMarker")
    }
    for key, value in markers.items():
        if len(value) < 3 or len(value) > MAX_MARKER_CHARS:
            return False, f"{key} must contain 3 to {MAX_MARKER_CHARS} characters"
    if markers["unsolvedMarker"] == markers["solvedMarker"]:
        return False, "unsolvedMarker and solvedMarker must be distinct"
    if markers["cleanMarker"] == markers["poisonMarker"]:
        return False, "cleanMarker and poisonMarker must be distinct"

    cache_header = str(parameters.get("cacheStatusHeader") or "")
    if not _HEADER_NAME.fullmatch(cache_header):
        return False, "cacheStatusHeader must be a valid bounded HTTP header name"
    for key in ("cacheMissMarker", "cacheHitMarker"):
        value = str(parameters.get(key) or "")
        if not value or len(value) > 80 or "\r" in value or "\n" in value:
            return False, f"{key} must be a bounded single-line value"

    integer_ranges = {
        "expectedStatus": (200, 399, 200),
        "maxPoisonAttempts": (1, 45, 40),
        "retryDelayMs": (100, 2_000, 1_000),
        "maxSolveChecks": (1, 30, 20),
        "solvePollIntervalMs": (100, 2_000, 1_000),
        "timeoutSeconds": (3, 30, 15),
    }
    parsed: Dict[str, int] = {}
    for key, (minimum, maximum, default) in integer_ranges.items():
        try:
            value = int(parameters.get(key) if parameters.get(key) is not None else default)
        except (TypeError, ValueError):
            return False, f"{key} must be an integer"
        if value < minimum or value > maximum:
            return False, f"{key} must be between {minimum} and {maximum}"
        parsed[key] = value
    total_wait_ms = (
        max(0, parsed["maxPoisonAttempts"] - 1) * parsed["retryDelayMs"]
        + max(0, parsed["maxSolveChecks"] - 1) * parsed["solvePollIntervalMs"]
    )
    if total_wait_ms > MAX_TOTAL_WAIT_MS:
        return False, "combined retry and solve-poll wait budget must not exceed 100 seconds"
    return True, ""


def _request_transcript(method: str, url: str, body: str) -> str:
    parsed = urlsplit(url)
    lines = [
        f"{method} {_path_and_query(url)} HTTP/1.1",
        f"Host: {parsed.netloc}",
        "User-Agent: xASM-Agentic-Cache-Poisoning-Probe/1.0",
        "Accept: text/html,application/xhtml+xml,application/javascript,application/json",
    ]
    if body:
        lines.extend(
            [
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body.encode('utf-8'))}",
            ]
        )
    return sanitize_evidence_text(
        "\r\n".join(lines) + "\r\n\r\n" + body,
        (),
        MAX_EVIDENCE_CHARS,
    )


def _response_transcript(
    response: Dict[str, Any],
    cache_status_header: str,
    secret_values: Iterable[Any] = (),
) -> str:
    lines = [f"HTTP/1.1 {response['status']} {response['reason']}"]
    included = {
        "content-type",
        "cache-control",
        "cache-status",
        "cf-cache-status",
        "x-cache",
        "x-cache-hits",
        "age",
        "vary",
        cache_status_header.lower(),
    }
    for name, value in response["headers"].items():
        if str(name).lower() in included:
            lines.append(f"{name}: {value}")
    raw = "\r\n".join(lines) + "\r\n\r\n" + str(response.get("body") or "")
    return sanitize_evidence_text(raw, secret_values, MAX_EVIDENCE_CHARS)


def build_http_evidence_step(
    label: str,
    method: str,
    url: str,
    body: str,
    response: Dict[str, Any],
    cache_status_header: str,
) -> Dict[str, Any]:
    request = _request_transcript(method, url, body)
    response_text = _response_transcript(response, cache_status_header)
    return {
        "label": label,
        "request": request,
        "requestSha256": hashlib.sha256(request.encode("utf-8")).hexdigest(),
        "response": response_text,
        "responseSha256": hashlib.sha256(response_text.encode("utf-8")).hexdigest(),
        "responseStatus": int(response.get("status") or 0),
        "responseBodyLength": len(str(response.get("body") or "").encode("utf-8")),
        "responseExcerptTruncated": bool(response.get("truncated")),
    }


def build_nuclei_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "template-id": "xasm-fat-get-cache-poisoning-verified",
        "matcher-name": "fat-get-query-body-cache-key-discrepancy",
        "type": "http",
        "host": target,
        "matched-at": str(verification.get("cacheUrl") or target),
        "info": {
            "name": "Verified Web Cache Poisoning via Fat GET",
            "severity": "high",
            "description": (
                "The origin honored a parameter supplied in a GET request body while the "
                "shared cache keyed the response without that body. A subsequent clean GET "
                "was served the attacker-controlled response from cache."
            ),
            "remediation": (
                "Reject request bodies on GET endpoints, derive responses only from inputs "
                "included in the cache key, and configure the cache to avoid storing responses "
                "that vary on unkeyed request data. Purge affected cache entries."
            ),
            "classification": {"cwe-id": ["CWE-349"]},
        },
        "evidence": verification,
    }


class CachePoisoningProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:cache_poisoning_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms a bounded fat-GET cache-key discrepancy by retaining an unsolved "
            "baseline, a body-bearing GET accepted on cache miss, a payload-free GET "
            "serving the poison on cache hit, and a solved confirmation."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Authorized application base URL"},
                "url": {"type": "string", "description": "Alias for target"},
                "mode": {"type": "string", "enum": sorted(ALLOWED_MODES)},
                "proofLevel": {"type": "string", "enum": sorted(ALLOWED_PROOF_LEVELS)},
                "statusPath": {"type": "string"},
                "cachePath": {"type": "string"},
                "bodyField": {"type": "string"},
                "bodyValue": {"type": "string"},
                "unsolvedMarker": {"type": "string"},
                "solvedMarker": {"type": "string"},
                "cleanMarker": {"type": "string"},
                "poisonMarker": {"type": "string"},
                "cacheStatusHeader": {"type": "string"},
                "cacheMissMarker": {"type": "string"},
                "cacheHitMarker": {"type": "string"},
                "expectedStatus": {"type": "integer", "minimum": 200, "maximum": 399},
                "maxPoisonAttempts": {"type": "integer", "minimum": 1, "maximum": 45},
                "retryDelayMs": {"type": "integer", "minimum": 100, "maximum": 2_000},
                "maxSolveChecks": {"type": "integer", "minimum": 1, "maximum": 30},
                "solvePollIntervalMs": {
                    "type": "integer",
                    "minimum": 100,
                    "maximum": 2_000,
                },
                "engagement": {
                    "type": "string",
                    "enum": ["standard", *sorted(ALLOWED_ENGAGEMENTS)],
                },
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "timeoutSeconds": {"type": "integer", "minimum": 3, "maximum": 30},
            },
                        # #1648 — `required` holds only the tier-INDEPENDENT fields; the
            # lab-only ones are conditionally required AND conditionally
            # forbidden by the allOf below (same shape as web_ssti_probe.py).
            "required": [
                "mode",
                "proofLevel",
                "cachePath",
                "bodyField",
                "bodyValue",
                "cleanMarker",
                "poisonMarker",
                "cacheStatusHeader",
                "cacheMissMarker",
                "cacheHitMarker",
                "engagement",
                "allowUnsafeMethods",
            ],
            "allOf": [
                {
                    "if": {"properties": {"proofLevel": {"const": "lab-state-change"}}},
                    "then": {"required": sorted(_STATE_CHANGE_PARAMETERS)},
                    "else": {
                        "not": {
                            "anyOf": [
                                {"required": [field]}
                                for field in sorted(_STATE_CHANGE_PARAMETERS)
                            ]
                        }
                    },
                }
            ],

            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 4,
            "domain": ["web"],
            "input_type": ["url", "cache", "workflow"],
            "output_type": ["findings", "cache_poisoning_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm a fat-GET cache-key discrepancy",
            "secondary_purposes": [],
        }

    async def _request(
        self,
        session: aiohttp.ClientSession,
        url: str,
        body: Optional[str] = None,
    ) -> Dict[str, Any]:
        headers = {
            "User-Agent": "xASM-Agentic-Cache-Poisoning-Probe/1.0",
            "Accept": "text/html,application/xhtml+xml,application/javascript,application/json",
        }
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        async with session.request(
            "GET",
            url,
            headers=headers,
            data=body,
            allow_redirects=False,
        ) as response:
            raw = await read_limited(response.content, MAX_RESPONSE_BYTES + 1)
            truncated = len(raw) > MAX_RESPONSE_BYTES
            raw = raw[:MAX_RESPONSE_BYTES]
            return {
                "status": response.status,
                "reason": str(response.reason or "")[:100],
                "headers": response.headers,
                "body": raw.decode("utf-8", errors="replace").replace("\0", ""),
                "truncated": truncated,
            }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        valid, reason = validate_probe_parameters(parameters)
        if not valid:
            return {"success": False, "fallback": False, "error": reason, "findings": []}

        target = _http_target(parameters.get("target") or parameters.get("url"))
        assert target is not None
        proof_level = str(parameters["proofLevel"]).lower()
        is_lab = proof_level == "lab-state-change"
        step_labels = EXPECTED_STEP_LABELS_BY_PROOF_LEVEL[proof_level]
        status_path = str(parameters["statusPath"]) if is_lab else ""
        cache_path = str(parameters["cachePath"])
        status_url = urljoin(target, status_path) if is_lab else ""
        cache_url = urljoin(target, cache_path)
        body_field = str(parameters["bodyField"])
        body_value = str(parameters["bodyValue"])
        poison_body = urlencode({body_field: body_value})
        unsolved_marker = str(parameters["unsolvedMarker"]) if is_lab else ""
        solved_marker = str(parameters["solvedMarker"]) if is_lab else ""
        clean_marker = str(parameters["cleanMarker"])
        poison_marker = str(parameters["poisonMarker"])
        cache_status_header = str(parameters["cacheStatusHeader"])
        cache_miss_marker = str(parameters["cacheMissMarker"])
        cache_hit_marker = str(parameters["cacheHitMarker"])
        expected_status = int(parameters.get("expectedStatus") or 200)
        max_poison_attempts = int(parameters.get("maxPoisonAttempts") or 40)
        retry_delay_ms = int(parameters.get("retryDelayMs") or 1_000)
        max_solve_checks = int(parameters.get("maxSolveChecks") or 20)
        solve_poll_interval_ms = int(parameters.get("solvePollIntervalMs") or 1_000)
        timeout = int(parameters.get("timeoutSeconds") or 15)

        request_count = 0
        poison_attempts = 0
        clean_checks = 0
        solve_checks = 0
        evidence_steps = []
        accepted_poison: Optional[Dict[str, Any]] = None
        clean_hit: Optional[Dict[str, Any]] = None
        confirmation: Optional[Dict[str, Any]] = None
        timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))

        try:
            async with aiohttp.ClientSession(
                timeout=timeout_config,
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                # #1648 — the unsolved baseline exists only on the lab tier; a
                # real application has no such status page.
                if is_lab:
                    baseline = await self._request(session, status_url)
                    request_count += 1
                    if (
                        baseline["truncated"]
                        or baseline["status"] != 200
                        or not response_contains_marker(baseline["body"], unsolved_marker)
                        or response_contains_marker(baseline["body"], solved_marker)
                    ):
                        raise ValueError(
                            "clean baseline did not prove the configured unsolved state"
                        )
                    evidence_steps.append(
                        build_http_evidence_step(
                            step_labels[0],
                            "GET",
                            status_url,
                            "",
                            baseline,
                            cache_status_header,
                        )
                    )

                for attempt in range(max_poison_attempts):
                    poison_attempts += 1
                    poison_response = await self._request(session, cache_url, poison_body)
                    request_count += 1
                    poison_accepted = (
                        not poison_response["truncated"]
                        and poison_response["status"] == expected_status
                        and cache_header_matches(
                            poison_response["headers"],
                            cache_status_header,
                            cache_miss_marker,
                        )
                        and response_contains_marker(poison_response["body"], poison_marker)
                        and not response_contains_marker(poison_response["body"], clean_marker)
                    )
                    if poison_accepted:
                        clean_response = await self._request(session, cache_url)
                        request_count += 1
                        clean_checks += 1
                        clean_verified = (
                            not clean_response["truncated"]
                            and clean_response["status"] == expected_status
                            and cache_header_matches(
                                clean_response["headers"],
                                cache_status_header,
                                cache_hit_marker,
                            )
                            and response_contains_marker(clean_response["body"], poison_marker)
                            and not response_contains_marker(clean_response["body"], clean_marker)
                        )
                        if clean_verified:
                            accepted_poison = poison_response
                            clean_hit = clean_response
                            break
                    if attempt + 1 < max_poison_attempts:
                        await asyncio.sleep(retry_delay_ms / 1_000)

                if accepted_poison is None or clean_hit is None:
                    raise ValueError(
                        "no bounded poison-miss followed by a payload-free poisoned cache-hit was observed"
                    )
                evidence_steps.append(
                    build_http_evidence_step(
                        "poison-cache-miss",
                        "GET",
                        cache_url,
                        poison_body,
                        accepted_poison,
                        cache_status_header,
                    )
                )
                evidence_steps.append(
                    build_http_evidence_step(
                        "clean-cache-hit",
                        "GET",
                        cache_url,
                        "",
                        clean_hit,
                        cache_status_header,
                    )
                )

                # #1648 — the solved confirmation is lab-tier only. On a real
                # application the poisoning proof above IS the finding.
                if is_lab:
                    for check in range(max_solve_checks):
                        solve_checks += 1
                        candidate = await self._request(session, status_url)
                        request_count += 1
                        if (
                            not candidate["truncated"]
                            and candidate["status"] == 200
                            and response_contains_marker(candidate["body"], solved_marker)
                            and not response_contains_marker(candidate["body"], unsolved_marker)
                        ):
                            confirmation = candidate
                            break
                        if check + 1 < max_solve_checks:
                            await asyncio.sleep(solve_poll_interval_ms / 1_000)

                    if confirmation is None:
                        raise ValueError(
                            "cache proof succeeded but the configured solved transition "
                            "was not observed"
                        )
                    evidence_steps.append(
                        build_http_evidence_step(
                            "solved-confirmation",
                            "GET",
                            status_url,
                            "",
                            confirmation,
                            cache_status_header,
                        )
                    )
        except Exception as exc:
            return {
                "success": False,
                "fallback": False,
                "error": str(exc)[:500],
                "requestCount": request_count,
                "poisonAttempts": poison_attempts,
                "cleanChecks": clean_checks,
                "solveChecks": solve_checks,
                "findings": [],
            }

        verification = {
            "verified": True,
            "fallback": False,
            "mode": str(parameters["mode"]).lower(),
            "proofLevel": proof_level,
            "target": target,
            "engagement": str(parameters["engagement"]).lower(),
            "cachePath": cache_path,
            "bodyField": body_field,
            "bodyValue": body_value,
            "cleanMarker": clean_marker,
            "poisonMarker": poison_marker,
            "cacheStatusHeader": cache_status_header,
            "cacheMissMarker": cache_miss_marker,
            "cacheHitMarker": cache_hit_marker,
            "expectedStatus": expected_status,
            "maxPoisonAttempts": max_poison_attempts,
            "retryDelayMs": retry_delay_ms,
            "maxSolveChecks": max_solve_checks,
            "solvePollIntervalMs": solve_poll_interval_ms,
            "requestCount": request_count,
            "poisonAttempts": poison_attempts,
            "cleanChecks": clean_checks,
            "solveChecks": solve_checks,
            "poisonAcceptedOnMiss": True,
            "cleanRequestHadBody": False,
            "cleanPoisonServedOnHit": True,
            "cacheUrl": cache_url,
            "httpEvidence": {"version": 1, "steps": evidence_steps},
        }
        # #1648 — lab-only proof material is added ONLY on the lab tier; the
        # backend rejects a runtime-tier proof that carries any of it.
        if is_lab:
            verification.update(
                {
                    "statusPath": status_path,
                    "unsolvedMarker": unsolved_marker,
                    "solvedMarker": solved_marker,
                    "solvedBefore": False,
                    "solvedAfter": True,
                }
            )
        finding = build_nuclei_finding(target, verification)
        return {
            "success": True,
            "fallback": False,
            "target": target,
            "requestCount": request_count,
            "verification": verification,
            "findings": [finding],
        }
