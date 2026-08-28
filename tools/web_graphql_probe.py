"""URL-only GraphQL private-object authorization differential (#1289).

The closed probe discovers a GraphQL endpoint, introspects a bounded schema,
derives one list/direct-object pair of the same type, and proves that a private
object omitted from the public list remains directly readable with a sensitive
scalar.  All requests are tool-owned and read-only except the optional fixed
lab solution submission.  The destination IP is pinned and HTTPS retains the
authorized hostname for certificate validation and SNI.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import socket
import ssl
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple
from urllib.parse import quote_plus, urljoin, urlsplit

from plugin_interface import ToolPlugin
from tools.web_request_smuggling_probe import read_http_response


MODE = "private-object-authz-differential-v1"
RUNTIME_PROOF = "runtime-read-only"
LAB_PROOF = "lab-state-change"
USER_AGENT = "xASM-GraphQL-Probe/1.0"
ENDPOINT_PATHS = ("/graphql", "/api/graphql", "/graphql/v1", "/api", "/gql")
FINGERPRINT_QUERY = "query XasmFingerprint{__typename}"
NEGATIVE_QUERY = "query XasmNegative{__xasmFieldDoesNotExist}"
INTROSPECTION_QUERY = """query XasmSchema {
  __schema {
    queryType {
      fields {
        name
        args {
          name
          type {
            kind
            name
            ofType { kind name ofType { kind name ofType { kind name } } }
          }
        }
        type {
          kind
          name
          ofType { kind name ofType { kind name ofType { kind name } } }
        }
      }
    }
    types {
      kind
      name
      fields {
        name
        type {
          kind
          name
          ofType { kind name ofType { kind name ofType { kind name } } }
        }
      }
    }
  }
}"""
MAX_REQUEST_BUDGET = 32
MAX_BODY_BYTES = 250_000
MAX_EVIDENCE_CHARS = 18_000
PRIVACY_FIELDS = ("isPrivate", "private")
SENSITIVE_FIELD_RE = re.compile(
    r"(?i)(?:password|passcode|secret|token|privatekey|api[_-]?key|credential)"
)
SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^(?:authorization|cookie|set-cookie|proxy-authorization|x-csrf-token)\s*:.*$"
)
SENSITIVE_JSON_RE = re.compile(
    r'(?P<prefix>"[^"\r\n]*(?:password|passcode|secret|token|privatekey|api[_-]?key|credential)'
    r'[^"\r\n]*"\s*:\s*)"(?:\\.|[^"\\])*"',
    re.I,
)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
TOKEN_RE = re.compile(r"\b(?:eyJ[A-Za-z0-9_-]{20,}|[A-Za-z0-9_+/.=-]{40,})\b")


class QueryPair(NamedTuple):
    object_type: str
    list_field: str
    direct_field: str
    id_field: str
    id_argument: str
    id_argument_type: str
    privacy_field: str
    sensitive_field: str


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _bounded_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(int(value), high))
    except (TypeError, ValueError):
        return default


def validate_target(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw or len(raw) > 4096 or any(ch in raw for ch in "\r\n\0"):
        return None
    try:
        parsed = urlsplit(raw)
    except Exception:
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


def origin_for(target: str) -> str:
    parsed = urlsplit(target)
    return f"{parsed.scheme}://{parsed.netloc}/"


def _unwrap_type(value: Any) -> Tuple[str, bool]:
    current = value if isinstance(value, dict) else {}
    is_list = current.get("kind") == "LIST"
    while isinstance(current, dict) and current.get("kind") in {"NON_NULL", "LIST"}:
        is_list = is_list or current.get("kind") == "LIST"
        current = current.get("ofType") or {}
    return str(current.get("name") or ""), is_list


def _privacy_semantic(field: str, value: Any) -> Optional[str]:
    lowered = field.lower()
    if lowered in {"isprivate", "private"} and value is True:
        return "explicit-private-boolean"
    return None


def _redact(value: str, secret: Optional[str] = None) -> str:
    safe = str(value or "").replace("\0", "")
    safe = SENSITIVE_HEADER_RE.sub(
        lambda match: match.group(0).split(":", 1)[0] + ": <redacted-runtime-secret>", safe
    )
    marker: Optional[str] = None
    marker_sentinel = "<xasm-sensitive-value>"
    negative_path_sentinel = "<xasm-graphql-negative-path>"
    negative_path_match = re.search(r"/\.xasm-graphql-negative-[0-9a-f]{24}", safe)
    negative_path = negative_path_match.group(0) if negative_path_match else None
    if negative_path:
        # Preserve the tool-owned randomized negative-control path. Its complete
        # path is deliberately token-shaped and must remain independently
        # verifiable by the fail-closed backend proof rebuilder.
        safe = safe.replace(negative_path, negative_path_sentinel)
    if secret:
        marker = f"[REDACTED sha256={_sha(secret)} len={len(secret)}]"
        # Protect the required marker from the generic token detector: a SHA-256
        # is itself token-shaped. The marker is restored only after all generic
        # in-process redaction passes have finished.
        safe = safe.replace(secret, marker_sentinel)
        safe = safe.replace(quote_plus(secret), marker_sentinel)
    else:
        safe = SENSITIVE_JSON_RE.sub(
            lambda match: match.group("prefix") + '"<redacted-sensitive-value>"', safe
        )
    safe = EMAIL_RE.sub("<redacted-email>", safe)
    safe = TOKEN_RE.sub("<redacted-token>", safe)
    if marker:
        safe = safe.replace(marker_sentinel, marker)
    if negative_path:
        safe = safe.replace(negative_path_sentinel, negative_path)
    return safe[:MAX_EVIDENCE_CHARS]


def _masked_value(value: str) -> str:
    return f"<redacted:{len(value)}-chars>"


def _deep_first(data: Any, field: str) -> Any:
    if isinstance(data, dict):
        if field in data:
            return data[field]
        for value in data.values():
            found = _deep_first(value, field)
            if found is not None:
                return found
    elif isinstance(data, list):
        for value in data:
            found = _deep_first(value, field)
            if found is not None:
                return found
    return None


def _numeric_ids(value: Any) -> List[int]:
    output: List[int] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in {"id", "postid", "userid", "objectid"}:
                try:
                    number = int(item)
                except (TypeError, ValueError):
                    number = -1
                if 0 <= number <= 100_000:
                    output.append(number)
            output.extend(_numeric_ids(item))
    elif isinstance(value, list):
        for item in value:
            output.extend(_numeric_ids(item))
    return list(dict.fromkeys(output))[:20]


class WebGraphqlProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:graphql_probe"

    @property
    def description(self) -> str:
        return (
            "Discovers a GraphQL endpoint from a root URL and proves one bounded "
            "public-list versus direct-private-object authorization differential."
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
                },
                "engagement": {
                    "type": "string",
                    "enum": ["standard", "aggressive", "lab", "ctf"],
                    "default": "standard",
                },
                "discoverFromTarget": {"type": "boolean", "default": True},
                "requestBudget": {
                    "type": "integer", "minimum": 8, "maximum": MAX_REQUEST_BUDGET,
                    "default": 32,
                },
                "endpointBudget": {
                    "type": "integer", "minimum": 1, "maximum": 8, "default": 5,
                },
                "objectProbeBudget": {
                    "type": "integer", "minimum": 1, "maximum": 12, "default": 8,
                },
                "maxResponseBytes": {
                    "type": "integer", "minimum": 4096, "maximum": MAX_BODY_BYTES,
                    "default": 96000,
                },
                "stopAfterFirstFinding": {"type": "boolean", "default": True},
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "stateChangeApproved": {"type": "boolean", "default": False},
                "solutionSubmitApproved": {"type": "boolean", "default": False},
            },
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "dast-api",
            "phase": 3,
            "domain": ["api", "web"],
            "input_type": ["url"],
            "output_type": ["findings"],
            "chainable_after": ["api:discover", "browser:traffic_capture"],
            "chainable_before": ["decision:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        target = validate_target(parameters.get("target"))
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
        self._budget = _bounded_int(parameters.get("requestBudget"), 32, 8, 32)
        self._endpoint_budget = _bounded_int(parameters.get("endpointBudget"), 5, 1, 8)
        self._object_budget = _bounded_int(parameters.get("objectProbeBudget"), 8, 1, 12)
        self._max_body = _bounded_int(parameters.get("maxResponseBytes"), 96000, 4096, MAX_BODY_BYTES)
        self._requests = 0
        self._timeout = 20
        self._target = target
        try:
            await self._pin_target(target)
            root_before = await self._request("GET", target, None)
            endpoint, fingerprint, negative = await self._discover_endpoint(target)
            if not endpoint or not fingerprint or not negative:
                return self._result(target, proof_level, None, "no structurally verified GraphQL endpoint")
            introspection = await self._request("POST", endpoint, INTROSPECTION_QUERY)
            schema = self._payload(introspection)
            pair = self._derive_pair(schema)
            if not pair:
                return self._result(target, proof_level, None, "no bounded same-type list/direct query pair")
            list_query = self._list_query(pair)
            list_control = await self._request("POST", endpoint, list_query)
            list_payload = self._payload(list_control)
            listed_ids = _numeric_ids(list_payload.get("data") if isinstance(list_payload, dict) else None)
            if not listed_ids:
                return self._result(target, proof_level, None, "public list exposed no numeric object IDs")
            verification = await self._probe_direct_ids(
                endpoint, pair, listed_ids, fingerprint, negative, introspection, list_control
            )
            if not verification:
                return self._result(target, proof_level, None, "no omitted private object with a sensitive scalar")
            verification["proofLevel"] = proof_level
            secret = verification.pop("_secret")
            steps = verification["graphqlEvidence"]["steps"]
            solution = await self._maybe_finalize_lab(
                target, root_before, secret, proof_level, engagement,
                bool(parameters.get("allowUnsafeMethods"))
                and bool(parameters.get("stateChangeApproved"))
                and bool(parameters.get("solutionSubmitApproved")),
            )
            steps.extend(solution.pop("steps"))
            verification.update(solution)
            verification["requestCount"] = self._requests
            finding = self._finding(target, verification)
            return {
                "success": True, "tool": self.name, "target": target, "mode": MODE,
                "proofLevel": proof_level, "verified": True, "fallback": False,
                "requestCount": self._requests, "findings": [finding], "total_findings": 1,
                "verification": verification,
                "summary": {"requests": self._requests, "findings": 1, "fallback": False},
            }
        except (OSError, ConnectionError, TimeoutError, ValueError, ssl.SSLError, json.JSONDecodeError) as exc:
            return self._error(f"bounded GraphQL probe failed: {type(exc).__name__}", target)

    async def _discover_endpoint(self, target: str):
        origin = origin_for(target)
        paths = [urlsplit(target).path or "/", *ENDPOINT_PATHS]
        seen: set[str] = set()
        for path in paths[: self._endpoint_budget]:
            endpoint = urljoin(origin, path.lstrip("/"))
            if endpoint in seen or self._requests + 2 > self._budget:
                continue
            seen.add(endpoint)
            fingerprint = await self._request("POST", endpoint, FINGERPRINT_QUERY)
            payload = self._payload(fingerprint)
            typename = _deep_first(payload.get("data") if isinstance(payload, dict) else None, "__typename")
            if fingerprint["status"] != 200 or not isinstance(typename, str) or not typename:
                continue
            negative_url = urljoin(
                origin, ".xasm-graphql-negative-" + secrets.token_hex(12)
            )
            negative = await self._request("POST", negative_url, FINGERPRINT_QUERY)
            negative_payload = self._payload(negative)
            negative_typename = _deep_first(
                negative_payload.get("data") if isinstance(negative_payload, dict) else None,
                "__typename",
            )
            if negative["status"] == 200 and negative_typename == "Query":
                continue
            return endpoint, fingerprint, negative
        return None, None, None

    def _derive_pair(self, schema: Dict[str, Any]) -> Optional[QueryPair]:
        root = _deep_first(schema.get("data"), "__schema") if isinstance(schema, dict) else None
        if not isinstance(root, dict):
            return None
        query_fields = ((root.get("queryType") or {}).get("fields") or [])
        type_rows = {row.get("name"): row for row in root.get("types") or [] if isinstance(row, dict)}
        lists: List[Tuple[str, str]] = []
        directs: List[Tuple[str, str, str, str]] = []
        for field in query_fields:
            if not isinstance(field, dict):
                continue
            type_name, is_list = _unwrap_type(field.get("type"))
            args = field.get("args") or []
            if is_list and not args:
                lists.append((str(field.get("name") or ""), type_name))
            if not is_list and len(args) == 1:
                arg = args[0]
                arg_type, _ = _unwrap_type(arg.get("type"))
                if arg_type in {"Int", "ID"}:
                    directs.append(
                        (
                            str(field.get("name") or ""),
                            type_name,
                            str(arg.get("name") or ""),
                            arg_type,
                        )
                    )
        for list_name, object_type in lists:
            fields = [str(f.get("name") or "") for f in (type_rows.get(object_type) or {}).get("fields") or []]
            id_field = next((f for f in fields if f.lower() in {"id", "postid", "userid", "objectid"}), None)
            privacy = next((f for f in PRIVACY_FIELDS if f in fields), None)
            sensitive = next((f for f in fields if SENSITIVE_FIELD_RE.search(f)), None)
            direct = next((row for row in directs if row[1] == object_type), None)
            if id_field and privacy and sensitive and direct:
                return QueryPair(
                    object_type,
                    list_name,
                    direct[0],
                    id_field,
                    direct[2],
                    direct[3],
                    privacy,
                    sensitive,
                )
        return None

    def _list_query(self, pair: QueryPair) -> str:
        return f"query XasmList{{{pair.list_field}{{{pair.id_field}}}}}"

    def _direct_query(self, pair: QueryPair) -> str:
        return (
            f"query XasmDirect($x:{pair.id_argument_type}!){{"
            f"{pair.direct_field}({pair.id_argument}:$x)"
            f"{{{pair.id_field} {pair.privacy_field} {pair.sensitive_field}}}}}"
        )

    async def _probe_direct_ids(
        self, endpoint, pair, listed_ids, fingerprint, negative, introspection, list_control
    ) -> Optional[Dict[str, Any]]:
        low, high = min(listed_ids), max(listed_ids)
        query = self._direct_query(pair)
        not_found_id = max(999_999, high + 100_000)
        not_found_value: Any = str(not_found_id) if pair.id_argument_type == "ID" else not_found_id
        missing = await self._request(
            "POST", endpoint, query, variables={"x": not_found_value}
        )
        missing_obj = _deep_first(self._payload(missing).get("data"), pair.direct_field)
        if isinstance(missing_obj, dict):
            return None
        candidates = [
            value
            for value in range(max(0, low - 2), min(100_000, high + self._object_budget) + 1)
            if value not in listed_ids
        ][: self._object_budget]
        for object_id in candidates:
            if self._requests + 2 > self._budget:
                return None
            requested_value: Any = str(object_id) if pair.id_argument_type == "ID" else object_id
            proof = await self._request(
                "POST", endpoint, query, variables={"x": requested_value}
            )
            payload = self._payload(proof)
            obj = _deep_first(payload.get("data") if isinstance(payload, dict) else None, pair.direct_field)
            if not isinstance(obj, dict):
                continue
            semantic = _privacy_semantic(pair.privacy_field, obj.get(pair.privacy_field))
            secret = obj.get(pair.sensitive_field)
            if not semantic or not isinstance(secret, str) or len(secret.strip()) < 4:
                continue
            secret = secret.strip()
            repeat = await self._request(
                "POST", endpoint, query, variables={"x": requested_value}
            )
            repeat_obj = _deep_first(self._payload(repeat).get("data"), pair.direct_field)
            if not isinstance(repeat_obj, dict) or repeat_obj.get(pair.sensitive_field) != secret:
                continue
            steps = [
                self._evidence("graphql-fingerprint", fingerprint, None),
                self._evidence("graphql-negative-control", negative, None),
                self._evidence("graphql-introspection", introspection, None),
                self._evidence("graphql-list-control", list_control, None),
                self._evidence("graphql-direct-not-found-control", missing, None),
                self._evidence("graphql-direct-private-proof", proof, secret),
                self._evidence("graphql-direct-private-repeat", repeat, secret),
            ]
            return {
                "verified": True, "mode": MODE,
                "endpointUrl": endpoint, "endpointPath": urlsplit(endpoint).path,
                "endpointFingerprintVerified": True,
                "negativeControlRejected": True,
                "schemaVerified": True,
                "objectType": pair.object_type, "listField": pair.list_field,
                "directField": pair.direct_field, "idArgument": pair.id_argument,
                "idField": pair.id_field,
                "privateField": pair.privacy_field, "sensitiveField": pair.sensitive_field,
                "privateObjectId": object_id, "privacySemantic": semantic,
                "omittedFromList": object_id not in listed_ids,
                "listOmittedPrivateObject": object_id not in listed_ids,
                "directPrivateObjectReturned": True,
                "repeatStable": True, "nonexistentControlRejected": True,
                "sensitiveValueRedacted": True,
                "privateState": True,
                "networkDestinationPreserved": True,
                "tlsSniPreserved": urlsplit(self._target).scheme == "https",
                "sensitiveValue": {
                    "masked": _masked_value(secret), "sha256": _sha(secret),
                    "length": len(secret), "type": "sensitive-scalar",
                },
                "sensitiveValueSha256": _sha(secret),
                "sensitiveValueLength": len(secret),
                "fallback": False, "graphqlEvidence": {"version": 1, "steps": steps},
                "_secret": secret,
            }
        return None

    async def _maybe_finalize_lab(self, target, root_before, secret, proof_level, engagement, approved):
        solved_before = self._is_solved(root_before["body"])
        output = {
            "solvedBefore": solved_before,
            "effectTriggered": False,
            "solvedAfter": solved_before,
            "labSolvedTransition": False,
            "steps": [],
        }
        if proof_level != LAB_PROOF or engagement not in {"lab", "ctf"} or not approved or solved_before:
            return output
        unsolved = self._evidence("lab-unsolved-control", root_before, secret)
        body = "answer=" + quote_plus(secret)
        submit = await self._request(
            "POST", urljoin(origin_for(target), "submitSolution"), None,
            raw_body=body, content_type="application/x-www-form-urlencoded",
        )
        after = await self._request("GET", target, None)
        solved_after = self._is_solved(after["body"])
        output.update({
            "effectTriggered": submit["status"] in {200, 204} and solved_after,
            "solvedAfter": solved_after, "labSolvedTransition": (not solved_before and solved_after),
            "solutionAnswerSha256": _sha(secret),
            "steps": [unsolved, self._evidence("lab-solution-submit", submit, secret), self._evidence("lab-solved-confirmation", after, secret)],
        })
        return output

    def _finding(self, target: str, verification: Dict[str, Any]) -> Dict[str, Any]:
        proof = verification["graphqlEvidence"]["steps"][5]
        return {
            "template-id": "xasm-graphql-private-object-authz-verified",
            "matcher-name": "list-omission-direct-private-read",
            "type": "http", "host": origin_for(target), "matched-at": verification["endpointUrl"],
            "request": proof["request"], "response": proof["response"],
            "extracted-results": [
                f"object-type:{verification['objectType']}",
                f"value-sha256:{verification['sensitiveValue']['sha256']}",
                f"value-length:{verification['sensitiveValue']['length']}",
            ],
            "evidence": verification,
            "info": {
                "name": "GraphQL Direct Object Resolver Exposes Private Sensitive Data",
                "severity": "high",
                "description": "A private object omitted from the public list remained directly queryable and returned a sensitive scalar.",
                "remediation": "Enforce object- and field-level authorization in every GraphQL resolver; do not rely on list filtering.",
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
        self, method: str, url: str, query: Optional[str], *,
        variables: Optional[Dict[str, Any]] = None, raw_body: Optional[str] = None,
        content_type: str = "application/json",
    ) -> Dict[str, Any]:
        if self._requests >= self._budget:
            raise ValueError("request budget exhausted")
        parsed = urlsplit(url)
        if f"{parsed.scheme}://{parsed.netloc}" != origin_for(self._target).rstrip("/"):
            raise ValueError("request left authorized origin")
        body = raw_body
        if query is not None:
            payload: Dict[str, Any] = {"query": query}
            if variables is not None:
                payload["variables"] = variables
            body = json.dumps(payload, separators=(",", ":"))
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        host_header = self._hostname
        default_port = 443 if parsed.scheme == "https" else 80
        if self._port != default_port:
            host_header += f":{self._port}"
        lines = [
            f"{method} {path} HTTP/1.1", f"Host: {host_header}", f"User-Agent: {USER_AGENT}",
            "Accept: application/json", "Accept-Encoding: identity", "Cache-Control: no-store",
            "Connection: close",
        ]
        body_bytes = (body or "").encode()
        if body is not None:
            lines.extend([f"Content-Type: {content_type}", f"Content-Length: {len(body_bytes)}"])
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + body_bytes
        ssl_context = ssl.create_default_context() if parsed.scheme == "https" else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=self._pinned_ip, port=self._port, family=self._family, ssl=ssl_context,
                server_hostname=self._hostname if ssl_context else None,
            ), self._timeout,
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
        response_body = str(response.get("body") or "")
        if len(response_body.encode()) > self._max_body:
            raise ValueError("response exceeded bounded body limit")
        return {
            "method": method, "url": url, "rawRequest": raw.decode("utf-8", "replace"),
            "status": int(response["status"]), "headerText": str(response.get("headerText") or ""),
            "body": response_body, "bodyBytes": bytes(response.get("bodyBytes") or b""),
        }

    def _payload(self, response: Dict[str, Any]) -> Dict[str, Any]:
        try:
            value = json.loads(response.get("body") or "{}")
        except (TypeError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}

    def _evidence(self, label: str, response: Dict[str, Any], secret: Optional[str]) -> Dict[str, Any]:
        request = _redact(response["rawRequest"], secret)
        response_text = _redact(response["headerText"] + "\r\n\r\n" + response["body"], secret)
        response_body = response_text.split("\r\n\r\n", 1)[1]
        return {
            "label": label, "request": request, "requestSha256": _sha(request),
            "response": response_text, "responseSha256": _sha(response_text),
            "responseBodySha256": _sha(response_body),
            "responseBodyLength": len(response_body.encode()), "responseStatus": response["status"],
            "responseExcerptTruncated": False,
        }

    def _is_solved(self, body: str) -> bool:
        lower = str(body or "").lower()
        return "is-solved" in lower and "is-notsolved" not in lower

    def _result(self, target, proof_level, verification, reason):
        value = verification or {
            "verified": False, "mode": MODE, "proofLevel": proof_level,
            "requestCount": self._requests, "fallback": False, "reason": reason,
        }
        return {
            "success": True, "tool": self.name, "target": target, "mode": MODE,
            "proofLevel": proof_level, "verified": False, "fallback": False,
            "requestCount": self._requests, "findings": [], "total_findings": 0,
            "verification": value, "summary": {"requests": self._requests, "findings": 0, "fallback": False},
        }

    def _error(self, message: str, target: Optional[str] = None):
        return {
            "success": False, "tool": self.name, "target": target, "verified": False,
            "fallback": False, "error": message, "findings": [],
        }


def get_tool() -> WebGraphqlProbeTool:
    return WebGraphqlProbeTool()
