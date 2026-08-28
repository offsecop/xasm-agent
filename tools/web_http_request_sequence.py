"""
Multi-step HTTP request sequence tool for agentic active probing.

Phase 3 (PR E.1) of the code-assisted-pentest roadmap. Used by the
Business-Logic Pentester to execute the approved `multi_step_probe_plan`
artifact: ordered HttpStep[] with `dependsOn` JSONPath substitution and
optional burst{count, sync} race-window probes.

Approval-gated via the `multi_step_probe_plan` ApprovalScope (PR E.2);
the dispatcher seam 5 verifies the `probePlanId` snapshotHash before
allowing the call to proceed (PR E.4 revert-plan enforcement).

Session re-use: the dispatcher's auth-enrichment seam injects
`authCookies` / `cookie` / `authHeaders` derived from the workflow's
existing AuthContext. The tool keeps them in an opaque, origin-bound
cookie/auth session and never re-logins between steps.

Default burst cap is 10 concurrent requests. Higher counts (up to 50)
require the parent plan to declare `burstApproved=true` (set by the
dispatcher after operator approves the plan with explicit
`burst.count > 10`).
"""

import asyncio
import copy
import http.client
import http.cookiejar
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from email.message import Message
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urljoin, urlsplit
from urllib.request import Request

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    forbidden_host_routing_header,
    redact_headers,
)


# Default per-step timeout (seconds) and burst caps.
DEFAULT_TIMEOUT = 20
MAX_TIMEOUT = 120
DEFAULT_BURST_CAP = 10
MAX_BURST_CAP = 50
MAX_STEPS = 50
MAX_RESPONSE_BYTES = 200_000
MAX_REDIRECTS = 10
MAX_TRANSCRIPT_BODY_BYTES = 50_000
MAX_HTML_CAPTURE_ELEMENTS = 256
MAX_HTML_CAPTURE_ATTRIBUTES = 32
MAX_CAPTURE_VALUE_BYTES = 4_096
SERVER_POLICY_KEY = "_serverRequestSequencePolicy"

# Methods allowed at the tool level. The dispatcher's seam 5 + the
# multi_step_probe_plan approval gate is the primary authorization
# surface; this is a defense-in-depth guard.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ALL_METHODS = SAFE_METHODS | MUTATING_METHODS

# Simple {{path.to.value}} substitution against the accumulated
# responses[] list. Each capture is `$.responses[i].path.to.value`.
# We support the dotted-path subset of JSONPath — full RFC 9535 is
# overkill for the BLP probe-plan templating contract.
TEMPLATE_RE = re.compile(r"\{\{\s*([\w$.\[\]]+)\s*\}\}")
SENSITIVE_JSON_VALUE_RE = re.compile(
    r'("[^"\r\n]*(?:csrf|token|session|cookie|authorization|password|secret|api[_-]?key)'
    r'[^"\r\n]*"\s*:\s*")([^"\r\n]+)(")',
    re.IGNORECASE,
)
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"((?:^|[?&;])[^=&#;\s]*(?:csrf|token|session|cookie|authorization|password|secret|api[_-]?key)"
    r"[^=&#;\s]*=)([^&#;\s]+)",
    re.IGNORECASE,
)
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
SENSITIVE_KEY_RE = re.compile(
    r"(?:authorization|cookie|csrf|token|password|secret|credential|api[-_]?key|auth(?:entication)?)",
    re.IGNORECASE,
)
METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.aws.internal",
    "instance-data.ec2.internal",
}
METADATA_ADDRESSES = {
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("168.63.129.16"),
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("192.0.0.192"),
    ipaddress.ip_address("fd00:ec2::254"),
}


class _PolicyError(ValueError):
    """Fail-closed policy/SSRF validation error safe to return to the Job."""


def _bounded_int(value: Any, *, minimum: int, maximum: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _PolicyError(f"{field} must be an integer")
    if value < minimum or value > maximum:
        raise _PolicyError(f"{field} must be between {minimum} and {maximum}")
    return value


def _canonical_origin(url: str) -> Tuple[str, str, int]:
    if (
        not isinstance(url, str)
        or not url
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in url)
    ):
        raise _PolicyError(
            "URL must be a non-empty HTTP(S) string without control characters"
        )
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise _PolicyError(f"invalid URL: {exc}") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise _PolicyError("URL must use http or https and include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise _PolicyError("URL userinfo is forbidden")
    host = parsed.hostname.rstrip(".").lower()
    if not host or "%" in host:
        raise _PolicyError("URL hostname is invalid")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise _PolicyError("URL hostname is invalid") from exc
    effective_port = port or (443 if scheme == "https" else 80)
    if effective_port < 1 or effective_port > 65535:
        raise _PolicyError("URL port is invalid")
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    origin = f"{scheme}://{display_host}"
    if effective_port != default_port:
        origin += f":{effective_port}"
    return origin, host, effective_port


@dataclass(frozen=True)
class _ValidatedHop:
    url: str
    origin: str
    scheme: str
    host: str
    port: int
    connect_ip: str


@dataclass(frozen=True)
class _RequestSequencePolicy:
    allowed_origins: frozenset[str]
    allowed_ip_ranges: Tuple[ipaddress._BaseNetwork, ...]
    allowed_port_ranges: Tuple[Tuple[int, int], ...]
    max_redirects: int
    max_steps: int
    max_response_bytes: int

    @classmethod
    def parse(cls, raw: Any) -> "_RequestSequencePolicy":
        if not isinstance(raw, dict):
            raise _PolicyError(f"{SERVER_POLICY_KEY} is required")
        if raw.get("version") != 1:
            raise _PolicyError("server request-sequence policy version must be 1")
        if raw.get("requirePerHopValidation") is not True:
            raise _PolicyError("server policy must require per-hop validation")

        raw_origins = raw.get("allowedOrigins")
        if not isinstance(raw_origins, list) or len(raw_origins) > 64:
            raise _PolicyError("allowedOrigins must contain at most 64 origins")
        origins = set()
        for raw_origin in raw_origins:
            origin, _host, _port = _canonical_origin(raw_origin)
            if raw_origin != origin:
                raise _PolicyError("allowedOrigins must contain canonical origins")
            origins.add(origin)

        raw_ip_ranges = raw.get("allowedIpRanges")
        if not isinstance(raw_ip_ranges, list) or len(raw_ip_ranges) > 128:
            raise _PolicyError("allowedIpRanges must contain at most 128 CIDRs")
        ip_ranges: List[ipaddress._BaseNetwork] = []
        for value in raw_ip_ranges:
            if not isinstance(value, str):
                raise _PolicyError("allowedIpRanges entries must be CIDR strings")
            try:
                ip_ranges.append(ipaddress.ip_network(value.strip(), strict=False))
            except ValueError as exc:
                raise _PolicyError(f"invalid allowedIpRanges entry: {value}") from exc

        if not origins and not ip_ranges:
            raise _PolicyError(
                "server policy must contain an allowed origin or IP range"
            )

        raw_port_ranges = raw.get("allowedPortRanges")
        if not isinstance(raw_port_ranges, list) or len(raw_port_ranges) > 64:
            raise _PolicyError("allowedPortRanges must contain at most 64 ranges")
        port_ranges: List[Tuple[int, int]] = []
        for value in raw_port_ranges:
            if not isinstance(value, dict):
                raise _PolicyError("allowedPortRanges entries must be {from,to} objects")
            start = _bounded_int(
                value.get("from"),
                minimum=1,
                maximum=65535,
                field="allowedPortRanges.from",
            )
            end = _bounded_int(
                value.get("to"),
                minimum=1,
                maximum=65535,
                field="allowedPortRanges.to",
            )
            if start > end:
                raise _PolicyError("allowedPortRanges.from cannot exceed .to")
            port_ranges.append((start, end))

        return cls(
            allowed_origins=frozenset(origins),
            allowed_ip_ranges=tuple(ip_ranges),
            allowed_port_ranges=tuple(port_ranges),
            max_redirects=_bounded_int(
                raw.get("maxRedirects"),
                minimum=0,
                maximum=MAX_REDIRECTS,
                field="maxRedirects",
            ),
            max_steps=_bounded_int(
                raw.get("maxSteps"),
                minimum=1,
                maximum=MAX_STEPS,
                field="maxSteps",
            ),
            max_response_bytes=_bounded_int(
                raw.get("maxResponseBytes"),
                minimum=1,
                maximum=MAX_RESPONSE_BYTES,
                field="maxResponseBytes",
            ),
        )

    def validate_and_resolve(self, url: str) -> _ValidatedHop:
        origin, host, port = _canonical_origin(url)
        origin_allowed = origin in self.allowed_origins
        if not origin_allowed and not self.allowed_ip_ranges:
            raise _PolicyError(f"origin is outside server-approved scope: {origin}")
        if host in METADATA_HOSTS:
            raise _PolicyError(f"metadata destination is forbidden: {host}")
        if self.allowed_port_ranges and not any(
            start <= port <= end for start, end in self.allowed_port_ranges
        ):
            raise _PolicyError(f"port is outside server-approved scope: {port}")
        try:
            addrinfo = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise _PolicyError(f"DNS resolution failed for {host}") from exc
        addresses = sorted({entry[4][0].split("%", 1)[0] for entry in addrinfo})
        if not addresses:
            raise _PolicyError(f"DNS resolution returned no addresses for {host}")
        for address in addresses:
            try:
                parsed_ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise _PolicyError(f"DNS returned an invalid address for {host}") from exc
            address_variants = [parsed_ip]
            if isinstance(parsed_ip, ipaddress.IPv6Address) and parsed_ip.ipv4_mapped:
                address_variants.append(parsed_ip.ipv4_mapped)
            if any(
                candidate.is_unspecified
                or candidate.is_multicast
                or candidate.is_link_local
                or candidate in METADATA_ADDRESSES
                for candidate in address_variants
            ):
                raise _PolicyError(f"DNS returned a forbidden address class for {host}")
            explicitly_allowed = any(
                candidate.version == network.version and candidate in network
                for candidate in address_variants
                for network in self.allowed_ip_ranges
            )
            if not origin_allowed and not explicitly_allowed:
                raise _PolicyError(f"DNS address is outside server-approved scope for {host}")
            if not parsed_ip.is_global and not explicitly_allowed:
                raise _PolicyError(
                    f"non-public DNS address requires an explicit server-approved range for {host}"
                )
        parsed = urlsplit(url)
        return _ValidatedHop(
            url=url,
            origin=origin,
            scheme=parsed.scheme.lower(),
            host=host,
            port=port,
            connect_ip=addresses[0],
        )


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, connect_ip: str, timeout: int):
        super().__init__(host, port=port, timeout=timeout)
        self._connect_ip = connect_ip

    def connect(self) -> None:
        self.sock = _connect_pinned_socket(self._connect_ip, self.port, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, connect_ip: str, timeout: int):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._connect_ip = connect_ip

    def connect(self) -> None:
        raw_socket = _connect_pinned_socket(self._connect_ip, self.port, self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def _connect_pinned_socket(connect_ip: str, port: int, timeout: int) -> socket.socket:
    """Connect to a validated numeric address without a second DNS lookup."""
    parsed_ip = ipaddress.ip_address(connect_ip)
    family = socket.AF_INET6 if parsed_ip.version == 6 else socket.AF_INET
    raw_socket = socket.socket(family, socket.SOCK_STREAM)
    raw_socket.settimeout(timeout)
    destination: Any = (
        (connect_ip, port, 0, 0) if family == socket.AF_INET6 else (connect_ip, port)
    )
    try:
        raw_socket.connect(destination)
        return raw_socket
    except Exception:
        raw_socket.close()
        raise


class _CookieResponseAdapter:
    def __init__(self, url: str, headers: Sequence[Tuple[str, str]]):
        self._url = url
        self._headers = Message()
        for key, value in headers:
            self._headers.add_header(key, value)

    def info(self) -> Message:
        return self._headers

    def geturl(self) -> str:
        return self._url


class _TranscriptSanitizer:
    def __init__(self) -> None:
        self._secrets: Dict[str, Tuple[str, bool]] = {}
        self._lock = threading.RLock()

    def add_secret(self, name: str, value: Any, *, strict: bool = False) -> None:
        text = str(value or "")
        if not text:
            return
        with self._lock:
            previous = self._secrets.get(text)
            self._secrets[text] = (
                f"{{{{capture:{name}}}}}", strict or bool(previous and previous[1])
            )

    def add_structured_secrets(self, prefix: str, value: Any) -> None:
        text = str(value or "")
        for index, match in enumerate(SENSITIVE_JSON_VALUE_RE.finditer(text)):
            self.add_secret(f"{prefix}-json-{index}", match.group(2), strict=True)
        for index, match in enumerate(SENSITIVE_ASSIGNMENT_RE.finditer(text)):
            self.add_secret(
                f"{prefix}-assignment-{index}", match.group(2), strict=True
            )
        for index, match in enumerate(BEARER_RE.finditer(text)):
            bearer_value = match.group(0).split(None, 1)
            if len(bearer_value) == 2:
                self.add_secret(
                    f"{prefix}-bearer-{index}", bearer_value[1], strict=True
                )

    def sanitize_text(self, value: Any) -> str:
        text = str(value or "")
        with self._lock:
            secrets = sorted(self._secrets.items(), key=lambda item: len(item[0]), reverse=True)
        for secret, (placeholder, strict) in secrets:
            if strict or len(secret) >= 8:
                text = text.replace(secret, placeholder)
            else:
                text = re.sub(
                    rf"(?<![A-Za-z0-9]){re.escape(secret)}(?![A-Za-z0-9])",
                    lambda _match: placeholder,
                    text,
                )
        text = BEARER_RE.sub("Bearer <redacted-runtime-secret>", text)
        text = SENSITIVE_JSON_VALUE_RE.sub(r'\1<redacted-runtime-secret>\3', text)
        text = SENSITIVE_ASSIGNMENT_RE.sub(r"\1<redacted-runtime-secret>", text)
        return text


class _BoundedHtmlCaptureParser(HTMLParser):
    """Closed HTML capture view; never executes markup or arbitrary selectors."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements_seen = 0
        self.view: Dict[str, Any] = {
            "inputs": {},
            "meta": {},
            "byId": {},
        }

    @staticmethod
    def _bounded(value: Any) -> str:
        raw = str(value or "").encode("utf-8", errors="replace")
        return raw[:MAX_CAPTURE_VALUE_BYTES].decode("utf-8", errors="ignore")

    def handle_starttag(
        self, tag: str, attrs: List[Tuple[str, Optional[str]]]
    ) -> None:
        if self.elements_seen >= MAX_HTML_CAPTURE_ELEMENTS:
            return
        self.elements_seen += 1
        normalized = {
            str(key).lower(): self._bounded(value)
            for key, value in attrs[:MAX_HTML_CAPTURE_ATTRIBUTES]
            if key
        }
        tag_name = str(tag or "").lower()
        element_id = normalized.get("id")
        if element_id and element_id not in self.view["byId"]:
            self.view["byId"][element_id] = dict(normalized)
        if tag_name == "input":
            name = normalized.get("name") or element_id
            if name and name not in self.view["inputs"]:
                self.view["inputs"][name] = dict(normalized)
                # Compact compatibility path: $.html.csrf resolves the first
                # matching input's value without exposing a general CSS engine.
                self.view.setdefault(name, normalized.get("value", ""))
        elif tag_name == "meta":
            name = normalized.get("name") or normalized.get("property") or element_id
            if name and name not in self.view["meta"]:
                self.view["meta"][name] = dict(normalized)
                self.view.setdefault(name, normalized.get("content", ""))


def _bounded_html_capture_view(body: Any) -> Dict[str, Any]:
    parser = _BoundedHtmlCaptureParser()
    raw = str(body or "").encode("utf-8", errors="replace")
    parser.feed(raw[:MAX_RESPONSE_BYTES].decode("utf-8", errors="ignore"))
    parser.close()
    return parser.view


def _redact_transcript_headers(headers: Any) -> Dict[str, str]:
    normalized = {
        str(key): str(value) for key, value in (headers or {}).items()
    } if isinstance(headers, dict) else {}
    redacted = redact_headers(normalized)
    for key in list(redacted):
        if SENSITIVE_KEY_RE.search(key):
            redacted[key] = "***REDACTED***"
    return redacted


class _OpaqueHttpSession:
    """Internal cookie/auth session. Runtime secrets never leave this object raw."""

    def __init__(
        self,
        anchor_url: str,
        auth_cookies: Optional[str],
        auth_headers: Dict[str, Any],
        sanitizer: _TranscriptSanitizer,
    ) -> None:
        self.anchor_origin, anchor_host, _anchor_port = _canonical_origin(anchor_url)
        self._auth_headers = {str(key): str(value) for key, value in auth_headers.items()}
        # One CookieJar per exact origin. RFC domain cookies remain useful for
        # paths on the issuing origin, but can never widen session authority to
        # a second allowed origin/subdomain in the same probe plan.
        self._jars: Dict[str, http.cookiejar.CookieJar] = {}
        self._jar_lock = threading.RLock()
        self.sanitizer = sanitizer
        for key, value in self._auth_headers.items():
            # Every auth-enrichment header is server-owned credential
            # material, including deployments that use a custom header name.
            sanitizer.add_secret(f"auth-header-{key.lower()}", value, strict=True)
        if auth_cookies:
            self._seed_cookies(anchor_url, anchor_host, str(auth_cookies))

    def _seed_cookies(self, anchor_url: str, host: str, raw_cookie: str) -> None:
        secure = urlsplit(anchor_url).scheme.lower() == "https"
        for index, segment in enumerate(raw_cookie.split(";")):
            if "=" not in segment:
                continue
            name, value = segment.split("=", 1)
            name = name.strip()
            value = value.strip()
            if not name or any(ch in name for ch in "\r\n\t "):
                continue
            self.sanitizer.add_secret(f"cookie-{index}", value, strict=True)
            cookie = http.cookiejar.Cookie(
                version=0,
                name=name,
                value=value,
                port=None,
                port_specified=False,
                domain=host,
                domain_specified=False,
                domain_initial_dot=False,
                path="/",
                path_specified=True,
                secure=secure,
                expires=None,
                discard=True,
                comment=None,
                comment_url=None,
                rest={"HttpOnly": None},
                rfc2109=False,
            )
            with self._jar_lock:
                self._jar_for_origin(self.anchor_origin).set_cookie(cookie)

    def _jar_for_origin(self, origin: str) -> http.cookiejar.CookieJar:
        jar = self._jars.get(origin)
        if jar is None:
            jar = http.cookiejar.CookieJar()
            self._jars[origin] = jar
        return jar

    def _cookie_header_for(self, url: str) -> Optional[str]:
        origin, _host, _port = _canonical_origin(url)
        request = Request(url)
        with self._jar_lock:
            jar = self._jars.get(origin)
            if jar is None:
                return None
            jar.add_cookie_header(request)
        return request.get_header("Cookie")

    def _extract_cookies(self, url: str, headers: Sequence[Tuple[str, str]]) -> None:
        origin, _host, _port = _canonical_origin(url)
        request = Request(url)
        response = _CookieResponseAdapter(url, headers)
        for key, value in headers:
            if key.lower() == "set-cookie":
                # Register only the value portion. The transcript separately
                # redacts the entire Set-Cookie header.
                first_pair = value.split(";", 1)[0]
                if "=" in first_pair:
                    with self._jar_lock:
                        cookie_index = len(self._jar_for_origin(origin))
                    self.sanitizer.add_secret(
                        f"set-cookie-{cookie_index}",
                        first_pair.split("=", 1)[1],
                        strict=True,
                    )
        with self._jar_lock:
            self._jar_for_origin(origin).extract_cookies(response, request)

    def _headers_for(self, url: str, step_headers: Any) -> Dict[str, str]:
        origin, _host, _port = _canonical_origin(url)
        headers: Dict[str, str] = {}
        # Authentication enrichment is origin-bound. Even a server-approved
        # second origin does not inherit Authorization from the login origin.
        if origin == self.anchor_origin:
            headers.update(self._auth_headers)
        if isinstance(step_headers, dict):
            headers.update({str(key): str(value) for key, value in step_headers.items()})
        cookie = self._cookie_header_for(url)
        if cookie and not any(key.lower() == "cookie" for key in headers):
            headers["Cookie"] = cookie
        return headers

    def request(
        self,
        step: Dict[str, Any],
        policy: _RequestSequencePolicy,
    ) -> Dict[str, Any]:
        current_url = str(step.get("url") or "")
        method = str(step.get("method") or "GET").upper()
        body: Optional[str] = (
            str(step.get("body"))
            if step.get("body") is not None and method in MUTATING_METHODS
            else None
        )
        timeout_seconds = min(
            max(int(step.get("timeoutSeconds") or DEFAULT_TIMEOUT), 3), MAX_TIMEOUT
        )
        redirect_chain: List[Dict[str, Any]] = []
        initial_origin, _host, _port = _canonical_origin(current_url)

        for redirect_index in range(policy.max_redirects + 1):
            hop = policy.validate_and_resolve(current_url)
            if hop.origin != initial_origin:
                raise _PolicyError("redirect changed origin; same-origin redirects are required")
            headers = self._headers_for(current_url, step.get("headers"))
            forbidden_header = forbidden_host_routing_header(headers)
            if forbidden_header:
                raise _PolicyError(f"request header {forbidden_header} is forbidden")
            self.sanitizer.add_structured_secrets("request-url", current_url)
            self.sanitizer.add_structured_secrets("request-body", body)
            for key, value in headers.items():
                if SENSITIVE_KEY_RE.search(key):
                    self.sanitizer.add_secret(
                        f"request-header-{key.lower()}", value, strict=True
                    )
            parsed = urlsplit(current_url)
            target = parsed.path or "/"
            if parsed.query:
                target += f"?{parsed.query}"
            connection: http.client.HTTPConnection
            if hop.scheme == "https":
                connection = _PinnedHTTPSConnection(
                    hop.host, hop.port, hop.connect_ip, timeout_seconds
                )
            else:
                connection = _PinnedHTTPConnection(
                    hop.host, hop.port, hop.connect_ip, timeout_seconds
                )
            try:
                wire_body = body.encode("utf-8") if body is not None else None
                connection.request(method, target, body=wire_body, headers=headers)
                response = connection.getresponse()
                status = int(response.status)
                raw_headers = [(str(key), str(value)) for key, value in response.getheaders()]
                raw_body = response.read(policy.max_response_bytes + 1)
            except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
                return {
                    "success": False,
                    "error": f"HTTP transport failed: {exc}",
                    "url": current_url,
                    "method": method,
                    "requestHeaders": headers,
                    "redirects": redirect_chain,
                }
            finally:
                connection.close()

            truncated = len(raw_body) > policy.max_response_bytes
            if truncated:
                raw_body = raw_body[: policy.max_response_bytes]
            body_text = raw_body.decode("utf-8", errors="replace").replace("\0", "")
            self._extract_cookies(current_url, raw_headers)
            header_map: Dict[str, str] = {}
            for key, value in raw_headers:
                header_map[key] = f"{header_map[key]}, {value}" if key in header_map else value

            location = next(
                (value for key, value in raw_headers if key.lower() == "location"),
                None,
            )
            if status in REDIRECT_STATUSES and location:
                if redirect_index >= policy.max_redirects:
                    return {
                        "success": False,
                        "error": f"redirect limit exceeded ({policy.max_redirects})",
                        "url": current_url,
                        "method": method,
                        "status": status,
                        "headers": header_map,
                        "body": body_text,
                        "requestHeaders": headers,
                        "redirects": redirect_chain,
                        "truncated": truncated,
                    }
                next_url = urljoin(current_url, location)
                next_origin, _next_host, _next_port = _canonical_origin(next_url)
                if next_origin != hop.origin:
                    raise _PolicyError("redirect changed origin; same-origin redirects are required")
                redirect_chain.append(
                    {"status": status, "url": current_url, "location": next_url}
                )
                if status == 303 or (status in {301, 302} and method == "POST"):
                    method = "GET"
                    body = None
                current_url = next_url
                continue

            return {
                "success": True,
                "url": current_url,
                "method": method,
                "status": status,
                "headers": header_map,
                "body": body_text,
                "bodyBytes": len(raw_body),
                "truncated": truncated,
                "requestHeaders": headers,
                "requestBody": body or "",
                "redirects": redirect_chain,
            }

        return {
            "success": False,
            "error": "redirect processing failed",
            "url": current_url,
            "method": method,
        }


def _has_unsafe_graphql_get(url: Any) -> bool:
    try:
        values = parse_qs(urlsplit(str(url or "")).query, keep_blank_values=True).get(
            "query", []
        )
    except (TypeError, ValueError):
        return False
    return any(
        re.search(r"\b(?:mutation|subscription)\b", str(value), re.IGNORECASE)
        for value in values
    )


class HttpRequestSequenceTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:http_request_sequence"

    @property
    def description(self) -> str:
        return (
            "Executes an ordered HttpStep[] with optional burst race-window "
            "probes and dependsOn JSONPath substitution from prior responses. "
            "Used by the Business-Logic Pentester to validate multi-step "
            "invariant violations against the running target. Operator must "
            "approve the parent multi_step_probe_plan before any step fires."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "sequence": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_STEPS,
                    "items": {
                        "type": "object",
                        "properties": {
                            "method": {"type": "string"},
                            "url": {"type": "string"},
                            "headers": {"type": "object"},
                            "body": {"type": "string"},
                            "burst": {
                                "type": "object",
                                "properties": {
                                    "count": {
                                        "type": "integer",
                                        "minimum": 2,
                                        "maximum": MAX_BURST_CAP,
                                    },
                                    "sync": {"type": "string", "enum": ["BARRIER"]},
                                },
                            },
                            "expectedStatus": {"type": "integer"},
                            "capture": {"type": "object"},
                        },
                        "required": ["url"],
                    },
                },
                "authCookies": {"type": "string"},
                "cookie": {"type": "string"},
                "authHeaders": {"type": "object"},
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "burstApproved": {"type": "boolean", "default": False},
                "probePlanId": {"type": "string"},
                # W.33.B.7 finalization (FP-elim gap 3) — structural
                # backlink to the upstream code finding that motivated
                # this probe. When set, the backend ingestion post-hook
                # synthesizes `upstreamCodeFindingMatch` automatically
                # so the code↔runtime correlation no longer depends on
                # the LLM coordinator manually threading the link. The
                # agent tool itself does not consume this field — it's
                # forwarded to the job parameters and read by
                # `IngestionService.processBusinessLogicFindings`.
                "sourceFindingId": {"type": "string"},
                # W.33.B.7 — structural opt-in to the BLP / HYBRID
                # ingestion path. When true, the backend treats this
                # sequence's output through the BLP evidence floor
                # validator and stamps `evidenceClass='HYBRID'` on the
                # emitted findings. Required when `sourceFindingId` is
                # set (the link is only meaningful for findings that
                # carry the HYBRID treatment).
                "annotateForBlp": {"type": "boolean", "default": False},
                # W.33.B.7 — structural backlink shape used by
                # IngestionService.linkUpstreamCodeFinding. Either set
                # this directly or set sourceFindingId and let the
                # backend pre-hook synthesize the match.
                "upstreamCodeFindingMatch": {
                    "type": "object",
                    "properties": {
                        "sourceFilePath": {"type": "string"},
                        "sourceLineRange": {"type": "array"},
                        "commitSha": {"type": "string"},
                        "enclosingHandler": {"type": "string"},
                    },
                },
                "invariantId": {"type": "string"},
                "invariantEvidence": {"type": "object"},
                "findingTitle": {"type": "string"},
                "findingDescription": {"type": "string"},
                "findingSeverity": {"type": "string"},
            },
            "required": ["sequence"],
        }

    @property
    def metadata(self):
        return {
            "category": "http.sequence",
            "phase": 3,
            "domain": ["web"],
            "input_type": ["multi_step_probe_plan"],
            "output_type": ["http_transcript"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        sequence: List[Dict[str, Any]] = parameters.get("sequence") or []
        if not isinstance(sequence, list) or len(sequence) == 0:
            return {"success": False, "error": "sequence must be a non-empty array"}
        if len(sequence) > MAX_STEPS:
            return {
                "success": False,
                "error": f"sequence exceeds MAX_STEPS={MAX_STEPS}",
            }

        burst_approved = bool(parameters.get("burstApproved", False))
        allow_unsafe_methods = bool(parameters.get("allowUnsafeMethods", False))
        auth_cookies = parameters.get("authCookies") or parameters.get("cookie")
        auth_headers = parameters.get("authHeaders") or {}
        if not isinstance(auth_headers, dict):
            auth_headers = {}
        if auth_cookies and ("\r" in str(auth_cookies) or "\n" in str(auth_cookies)):
            return {
                "success": False,
                "error": "auth cookie contains a forbidden line break",
                "code": "HOST_ROUTING_HEADER_FORBIDDEN",
            }
        forbidden_auth_header = forbidden_host_routing_header(auth_headers)
        if forbidden_auth_header:
            return {
                "success": False,
                "error": (
                    f"auth header {forbidden_auth_header} is reserved; use "
                    "web:host_header_probe for bounded Host-routing tests"
                ),
                "code": "HOST_ROUTING_HEADER_FORBIDDEN",
            }

        # Preserve all public unsafe-method / plan gates before consulting the
        # private transport policy. This keeps model arguments as descriptors:
        # they can further restrict a call, but cannot replace the envelope.
        for i, raw_step in enumerate(sequence):
            if not isinstance(raw_step, dict):
                return {"success": False, "error": f"step[{i}] must be an object"}
            forbidden_step_header = forbidden_host_routing_header(raw_step.get("headers"))
            if forbidden_step_header:
                return {
                    "success": False,
                    "error": (
                        f"step[{i}] header {forbidden_step_header} is reserved; use "
                        "web:host_header_probe for bounded Host-routing tests"
                    ),
                    "code": "HOST_ROUTING_HEADER_FORBIDDEN",
                }
            method = str(raw_step.get("method") or "GET").upper()
            if method not in ALL_METHODS:
                return {"success": False, "error": f"step[{i}].method invalid: {method}"}
            if method == "GET" and _has_unsafe_graphql_get(raw_step.get("url")):
                return {
                    "success": False,
                    "error": f"step[{i}] GraphQL mutation/subscription over GET is forbidden",
                    "code": "GRAPHQL_GET_WRITE_FORBIDDEN",
                }
            if method not in SAFE_METHODS and not allow_unsafe_methods:
                return {
                    "success": False,
                    "error": f"step[{i}].method {method} requires allowUnsafeMethods=true",
                    "safeMethods": sorted(SAFE_METHODS),
                }
            burst = raw_step.get("burst")
            if isinstance(burst, dict):
                try:
                    count = int(burst.get("count") or DEFAULT_BURST_CAP)
                except (TypeError, ValueError):
                    return {"success": False, "error": f"step[{i}].burst.count must be an integer"}
                if count < 2 or count > MAX_BURST_CAP:
                    return {
                        "success": False,
                        "error": f"burst.count={count} is outside 2..{MAX_BURST_CAP}",
                        "code": "BURST_LIMIT_EXCEEDED",
                    }
                if count > DEFAULT_BURST_CAP and not burst_approved:
                    return {
                        "success": False,
                        "error": (
                            f"burst.count={count} exceeds default cap {DEFAULT_BURST_CAP}; "
                            "parent multi_step_probe_plan must set burstApproved=true via "
                            "the per-plan approval flow"
                        ),
                        "code": "BURST_LIMIT_EXCEEDED",
                    }

        raw_policy = parameters.get(SERVER_POLICY_KEY)
        try:
            policy = _RequestSequencePolicy.parse(raw_policy)
        except _PolicyError as exc:
            return {
                "success": False,
                "error": str(exc),
                "code": (
                    "SERVER_REQUEST_SEQUENCE_POLICY_REQUIRED"
                    if raw_policy is None
                    else "SERVER_REQUEST_SEQUENCE_POLICY_DENY"
                ),
            }
        if len(sequence) > policy.max_steps:
            return {
                "success": False,
                "error": f"sequence exceeds server-approved maxSteps={policy.max_steps}",
                "code": "SERVER_REQUEST_SEQUENCE_POLICY_DENY",
            }

        internal_responses: List[Dict[str, Any]] = []
        responses: List[Dict[str, Any]] = []
        transcript: List[Dict[str, Any]] = []
        anomalies: List[str] = []
        sanitizer = _TranscriptSanitizer()
        session: Optional[_OpaqueHttpSession] = None
        failure: Optional[str] = None
        started = time.time()

        for i, step in enumerate(sequence):
            try:
                resolved = self._resolve_template(step, internal_responses)
            except Exception as exc:
                anomalies.append(f"step[{i}].dependsOn unresolved: {exc}")
                transcript.append({"stepIndex": i, "error": str(exc)})
                failure = str(exc)
                break

            forbidden_step_header = forbidden_host_routing_header(resolved.get("headers"))
            if forbidden_step_header:
                failure = (
                    f"step[{i}] header {forbidden_step_header} is reserved; use "
                    "web:host_header_probe for bounded Host-routing tests"
                )
                anomalies.append(failure)
                transcript.append(
                    {
                        "stepIndex": i,
                        "success": False,
                        "error": failure,
                        "code": "HOST_ROUTING_HEADER_FORBIDDEN",
                    }
                )
                break

            method = str(resolved.get("method") or "GET").upper()
            if method not in ALL_METHODS:
                anomalies.append(f"step[{i}].method invalid: {method}")
                transcript.append({"stepIndex": i, "error": f"invalid method: {method}"})
                failure = f"invalid method: {method}"
                break
            if method == "GET" and _has_unsafe_graphql_get(resolved.get("url")):
                failure = f"step[{i}] GraphQL mutation/subscription over GET is forbidden"
                anomalies.append(failure)
                transcript.append(
                    {
                        "stepIndex": i,
                        "success": False,
                        "error": failure,
                        "code": "GRAPHQL_GET_WRITE_FORBIDDEN",
                    }
                )
                break
            if method not in SAFE_METHODS and not allow_unsafe_methods:
                failure = f"step[{i}].method {method} requires allowUnsafeMethods=true"
                anomalies.append(failure)
                transcript.append(
                    {
                        "stepIndex": i,
                        "success": False,
                        "error": failure,
                        "safeMethods": sorted(SAFE_METHODS),
                    }
                )
                break

            url = resolved.get("url")
            if not isinstance(url, str) or not url:
                transcript.append({"stepIndex": i, "error": "step missing url"})
                failure = "step missing url"
                break
            if session is None:
                try:
                    # Construction is network-free. The request performs the
                    # one authoritative resolve/validate immediately before
                    # opening its IP-pinned connection.
                    session = _OpaqueHttpSession(
                        url, auth_cookies, auth_headers, sanitizer
                    )
                except _PolicyError as exc:
                    transcript.append(
                        {"stepIndex": i, "success": False, "error": str(exc)}
                    )
                    failure = str(exc)
                    break

            burst = resolved.get("burst")
            if isinstance(burst, dict):
                count = int(burst.get("count") or DEFAULT_BURST_CAP)
                burst_results = await self._execute_burst(resolved, count, session, policy)
                first_ok = next(
                    (r for r in burst_results if r.get("success") is True), None
                )
                selected = first_ok or burst_results[0]
                try:
                    captures = self._capture_response(
                        resolved.get("capture"), selected, sanitizer, i
                    )
                except (TypeError, ValueError) as exc:
                    public_burst = [
                        self._sanitize_result(result, sanitizer)
                        for result in burst_results
                    ]
                    transcript.append(
                        {
                            "stepIndex": i,
                            "burstResults": public_burst,
                            "error": f"capture failed: {exc}",
                        }
                    )
                    failure = f"step[{i}] capture failed: {exc}"
                    anomalies.append(failure)
                    break
                internal_responses.append(self._template_response(selected, captures))
                public_burst = [self._sanitize_result(result, sanitizer) for result in burst_results]
                public_selected = self._sanitize_result(selected, sanitizer, captures)
                transcript.append({"stepIndex": i, "burstResults": public_burst})
                responses.append(public_selected)
                if any(result.get("success") is not True for result in burst_results):
                    failure = f"step[{i}] burst contained failed requests"
                    anomalies.append(failure)
                    break
                expected = resolved.get("expectedStatus")
                if isinstance(expected, int) and selected.get("status") != expected:
                    failure = (
                        f"step[{i}] status={selected.get('status')} != expected {expected}"
                    )
                    transcript[-1]["success"] = False
                    transcript[-1]["error"] = failure
                    transcript[-1]["code"] = "EXPECTED_STATUS_MISMATCH"
                    anomalies.append(failure)
                    break
            else:
                result = await self._execute_one(resolved, session, policy)
                try:
                    captures = self._capture_response(
                        resolved.get("capture"), result, sanitizer, i
                    )
                except (TypeError, ValueError) as exc:
                    public_result = self._sanitize_result(result, sanitizer)
                    transcript.append(
                        {
                            "stepIndex": i,
                            **public_result,
                            "error": f"capture failed: {exc}",
                        }
                    )
                    responses.append(public_result)
                    failure = f"step[{i}] capture failed: {exc}"
                    anomalies.append(failure)
                    break
                internal_responses.append(self._template_response(result, captures))
                public_result = self._sanitize_result(result, sanitizer, captures)
                transcript.append({"stepIndex": i, **public_result})
                responses.append(public_result)
                if result.get("success") is not True:
                    failure = str(result.get("error") or f"step[{i}] request failed")
                    anomalies.append(failure)
                    break
                expected = resolved.get("expectedStatus")
                if isinstance(expected, int) and result.get("status") != expected:
                    failure = (
                        f"step[{i}] status={result.get('status')} != expected {expected}"
                    )
                    transcript[-1]["success"] = False
                    transcript[-1]["error"] = failure
                    transcript[-1]["code"] = "EXPECTED_STATUS_MISMATCH"
                    anomalies.append(failure)
                    break

        if len(transcript) < len(sequence):
            safe_reason = sanitizer.sanitize_text(failure or "prior step failed")
            for skipped_index in range(len(transcript), len(sequence)):
                transcript.append(
                    {
                        "stepIndex": skipped_index,
                        "success": False,
                        "executionStatus": "SKIPPED",
                        "reasonCode": "NOT_EXECUTED",
                        "error": f"not executed after fail-closed stop: {safe_reason}",
                    }
                )

        duration_ms = int((time.time() - started) * 1000)
        return {
            "success": failure is None,
            **({"error": failure} if failure else {}),
            "transcript": transcript,
            "responses": responses,
            "summary": {
                "totalSteps": len(transcript),
                "anomalies": anomalies,
                "durationMs": duration_ms,
                "allowUnsafeMethods": allow_unsafe_methods,
            },
        }

    # ────────────────────────────────────────────────────────────────
    # Internals
    # ────────────────────────────────────────────────────────────────

    def _resolve_template(
        self, step: Dict[str, Any], responses: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Replace {{$.responses[i].foo.bar}} placeholders against `responses`."""
        root = {"responses": responses}

        def resolve(value: Any) -> Any:
            if isinstance(value, dict):
                return {key: resolve(item) for key, item in value.items()}
            if isinstance(value, list):
                return [resolve(item) for item in value]
            if not isinstance(value, str):
                return value
            full_match = TEMPLATE_RE.fullmatch(value)
            if full_match:
                return copy.deepcopy(self._jsonpath(full_match.group(1), root))
            return TEMPLATE_RE.sub(
                lambda match: str(self._jsonpath(match.group(1), root)), value
            )

        return resolve(step)

    def _jsonpath(self, path: str, root: Any) -> Any:
        # Strip the optional leading $.
        path = path.lstrip("$").lstrip(".")
        cursor = root
        for part in re.findall(r"[^.\[\]]+|\[\d+\]", path):
            if part.startswith("[") and part.endswith("]"):
                idx = int(part[1:-1])
                if not isinstance(cursor, list) or idx >= len(cursor):
                    raise ValueError(f"index {part} out of range in {path}")
                cursor = cursor[idx]
            else:
                if not isinstance(cursor, dict) or part not in cursor:
                    raise ValueError(f"key {part} not found in {path}")
                cursor = cursor[part]
        return cursor

    def _capture_response(
        self,
        capture: Any,
        result: Dict[str, Any],
        sanitizer: _TranscriptSanitizer,
        step_index: int,
    ) -> Dict[str, Any]:
        if not isinstance(capture, dict) or result.get("success") is not True:
            return {}
        try:
            parsed_json = json.loads(str(result.get("body") or ""))
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed_json = None
        view = {
            "status": result.get("status"),
            "url": result.get("url"),
            "headers": result.get("headers") or {},
            "body": result.get("body") or "",
            "json": parsed_json,
            "html": _bounded_html_capture_view(result.get("body")),
        }
        captures: Dict[str, Any] = {}
        for raw_name, raw_path in capture.items():
            name = str(raw_name or "")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name):
                raise ValueError(f"invalid capture name: {name}")
            if not isinstance(raw_path, str) or not raw_path.startswith("$"):
                raise ValueError(f"capture {name} must use a JSONPath string")
            path = raw_path
            # Compatibility: a capture against $.body.foo means the parsed
            # JSON body; $.body alone still captures the raw response body.
            if path.startswith("$.body.") and parsed_json is not None:
                path = "$.json." + path[len("$.body.") :]
            value = self._jsonpath(path, view)
            if isinstance(value, (dict, list)):
                value = json.dumps(value, sort_keys=True, separators=(",", ":"))
            elif value is None:
                value = ""
            else:
                value = str(value)
            captures[name] = value
            sanitizer.add_secret(f"step-{step_index}-{name}", value)
        return captures

    def _template_response(
        self, result: Dict[str, Any], captures: Dict[str, Any]
    ) -> Dict[str, Any]:
        try:
            parsed_json = json.loads(str(result.get("body") or ""))
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed_json = None
        return {
            "success": result.get("success") is True,
            "url": result.get("url"),
            "method": result.get("method"),
            "status": result.get("status"),
            "headers": result.get("headers") or {},
            "body": result.get("body") or "",
            "json": parsed_json,
            "captures": captures,
        }

    def _sanitize_result(
        self,
        result: Dict[str, Any],
        sanitizer: _TranscriptSanitizer,
        captures: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        public: Dict[str, Any] = {
            key: value
            for key, value in result.items()
            if key not in {"requestHeaders", "requestBody", "headers", "body"}
        }
        if "url" in public:
            public["url"] = sanitizer.sanitize_text(public["url"])
        response_headers = _redact_transcript_headers(result.get("headers"))
        request_headers = _redact_transcript_headers(result.get("requestHeaders"))
        public["headers"] = {
            key: sanitizer.sanitize_text(value) for key, value in response_headers.items()
        }
        public["request"] = {
            "method": result.get("method"),
            "url": sanitizer.sanitize_text(result.get("url")),
            "headers": {
                key: sanitizer.sanitize_text(value) for key, value in request_headers.items()
            },
            "body": sanitizer.sanitize_text(result.get("requestBody")),
        }
        sanitized_body = sanitizer.sanitize_text(result.get("body"))
        body_bytes = sanitized_body.encode("utf-8", errors="replace")
        excerpt_truncated = len(body_bytes) > MAX_TRANSCRIPT_BODY_BYTES
        if excerpt_truncated:
            sanitized_body = body_bytes[:MAX_TRANSCRIPT_BODY_BYTES].decode(
                "utf-8", errors="ignore"
            )
        public["body"] = sanitized_body
        public["transcriptBodyTruncated"] = excerpt_truncated
        public["redirects"] = [
            {
                "status": item.get("status"),
                "url": sanitizer.sanitize_text(item.get("url")),
                "location": sanitizer.sanitize_text(item.get("location")),
            }
            for item in result.get("redirects") or []
        ]
        if captures:
            public["captures"] = {
                name: sanitizer.sanitize_text(value) for name, value in captures.items()
            }
        return public

    async def _execute_one(
        self,
        step: Dict[str, Any],
        session: _OpaqueHttpSession,
        policy: _RequestSequencePolicy,
    ) -> Dict[str, Any]:
        try:
            return await asyncio.to_thread(session.request, step, policy)
        except _PolicyError as exc:
            return {
                "success": False,
                "error": str(exc),
                "code": "SERVER_REQUEST_SEQUENCE_POLICY_DENY",
                "url": step.get("url"),
                "method": str(step.get("method") or "GET").upper(),
            }
        except Exception as exc:  # pragma: no cover - defensive executor seam
            return {
                "success": False,
                "error": f"HTTP executor failed: {exc}",
                "url": step.get("url"),
                "method": str(step.get("method") or "GET").upper(),
            }

    async def _execute_burst(
        self,
        step: Dict[str, Any],
        count: int,
        session: _OpaqueHttpSession,
        policy: _RequestSequencePolicy,
    ) -> List[Dict[str, Any]]:
        # Use asyncio.Barrier (Python 3.11+) — falls back to asyncio.Event
        # for older runtimes. The barrier guarantees all N requests start
        # within ~5ms, which is the race-window confirmation primitive.
        try:
            barrier = asyncio.Barrier(count)  # type: ignore[attr-defined]
            async def one_with_barrier():
                await barrier.wait()
                return await self._execute_one(step, session, policy)
            tasks = [asyncio.create_task(one_with_barrier()) for _ in range(count)]
        except AttributeError:
            ev = asyncio.Event()
            async def one_with_event():
                await ev.wait()
                return await self._execute_one(step, session, policy)
            tasks = [asyncio.create_task(one_with_event()) for _ in range(count)]
            ev.set()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [
            r if isinstance(r, dict) else {"success": False, "error": str(r)}
            for r in results
        ]
