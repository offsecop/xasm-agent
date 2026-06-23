"""
Read-only API access-control probes for agentic exploration.

The tool consumes endpoints observed by browser:traffic_capture and performs
bounded GET/HEAD comparisons: authenticated vs anonymous visibility and simple
object-id mutations. It does not run write verbs unless the operator explicitly
adds future support.
"""

import json
import re
import time
from http import HTTPStatus
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    dedupe_keep_order,
    extract_html_map,
    extract_js_intel,
    fetch_text,
    normalize_url,
    parse_headers,
    read_limited,
    same_origin,
)


SAFE_METHODS = {"GET", "HEAD"}
ID_PARAM_NAMES = {
    "id",
    "uid",
    "user",
    "userid",
    "user_id",
    "account",
    "accountid",
    "account_id",
    "order",
    "orderid",
    "order_id",
    "basket",
    "basketid",
    "cart",
    "cartid",
    "transaction",
    "transactionid",
    "transaction_id",
    "payment",
    "paymentid",
    "payment_id",
    "bill",
    "billid",
    "bill_id",
    "biller",
    "billerid",
    "biller_id",
    "card",
    "cardid",
    "card_id",
    "merchant",
    "merchantid",
    "merchant_id",
    "reservation",
    "reservationid",
    "reservation_id",
    "reference",
    "ref",
}
SENSITIVE_PATH_MARKERS = {
    "admin",
    "api_key",
    "apikey",
    "account",
    "accounts",
    "basket",
    "bill",
    "biller",
    "billers",
    "bills",
    "cart",
    "card",
    "cards",
    "config",
    "debug",
    "diagnostic",
    "diagnostics",
    "customer",
    "customers",
    "internal",
    "invoice",
    "iam",
    "metadata",
    "meta-data",
    "merchant",
    "merchants",
    "order",
    "orders",
    "payment",
    "payments",
    "profile",
    "reservation",
    "reservations",
    "secret",
    "secrets",
    "settings",
    "system-info",
    "token",
    "transaction",
    "transactions",
    "transfer",
    "transfers",
    "user",
    "users",
    "virtual",
    "wallet",
}
SENSITIVE_BODY_MARKERS = {
    "account_number",
    "amount",
    "accessKeyId",
    "access_key_id",
    "apiKey",
    "api_key",
    "aws_access_key_id",
    "aws_secret_access_key",
    "email",
    "password",
    "role",
    "token",
    "admin",
    "ssn",
    "credit",
    "card",
    "balance",
    "address",
    "phone",
    "merchant",
    "pin",
    "private_key",
    "routing",
    "secret_access_key",
    "secret_key",
    "session_token",
    "transaction",
}
COMMON_READONLY_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/docs",
    "/api/users",
    "/api/user",
    "/api/me",
    "/api/profile",
    "/api/account",
    "/api/accounts",
    "/api/accounts/1",
    "/api/check_balance?account_number=1001",
    "/api/orders",
    "/api/transactions",
    "/api/transactions/1",
    "/api/bill-categories",
    "/api/billers",
    "/api/billers/1",
    "/api/bills",
    "/api/bills/1",
    "/api/cards",
    "/api/cards/1",
    "/api/virtual-cards",
    "/api/virtual-cards/1",
    "/api/payments",
    "/api/payments/1",
    "/api/merchants",
    "/api/merchants/1",
    "/api/v1/merchants/me",
    "/api/v1/merchants/1",
    "/api/v1/payments",
    "/api/v1/payments/1",
    "/api/config",
    "/api/internal/config",
    "/api/internal/secret",
    "/api/ai/system-info",
    "/api/system-info",
    "/internal/secret",
    "/internal/config.json",
    "/latest/meta-data/",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/meta-data/iam/security-credentials/vulnbank-role",
    "/sup3r_s3cr3t_admin",
    "/api/cart",
    "/api/basket",
    "/rest/user/whoami",
    "/rest/products/search?q=",
    "/rest/basket/1",
    "/graphql",
    "/compliance",
]


class ApiAccessControlProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "api:access_control_probe"

    @property
    def description(self) -> str:
        return (
            "Runs bounded read-only API authorization probes using observed endpoints: "
            "anonymous-vs-auth visibility checks and simple IDOR/BOLA candidate mutations."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "apiEndpoints": {"type": "array", "items": {"type": ["object", "string"]}},
                "urls": {"type": "array", "items": {"type": "string"}},
                "maxEndpoints": {"type": "integer", "default": 80},
                "maxRequests": {"type": "integer", "default": 160},
                "includeAnonymousComparison": {"type": "boolean", "default": True},
                "includeIdMutation": {"type": "boolean", "default": True},
                "includeDiscoveredReadOnly": {"type": "boolean", "default": True},
                "cookie": {"type": "string"},
                "authCookies": {"type": "string"},
                "headers": {"type": "object"},
                "authHeaders": {"type": "object"},
            },
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}, {"required": ["apiEndpoints"]}, {"required": ["urls"]}],
        }

    @property
    def metadata(self):
        return {
            "category": "agentic-recon",
            "phase": 4,
            "domain": ["web", "api"],
            "input_type": ["url", "api_endpoints"],
            "output_type": ["findings", "api_access_control_probe_results"],
            "chainable_after": ["browser:traffic_capture", "api:discover", "param:discover"],
            "chainable_before": ["curl:", "nuclei:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        target = normalize_url(parameters.get("target") or parameters.get("url") or "")
        endpoints = self._normalize_endpoints(parameters, target)
        if not target and endpoints:
            target = self._origin(endpoints[0]["url"])
        if not target:
            return {"success": False, "error": "target or endpoint URL is required"}

        max_endpoints = max(1, min(int(parameters.get("maxEndpoints") or 80), 300))
        max_requests = max(1, min(int(parameters.get("maxRequests") or 160), 500))
        include_discovered = bool(parameters.get("includeDiscoveredReadOnly", True))
        if target and include_discovered and len(endpoints) < max_endpoints:
            endpoints.extend(await self._discover_readonly_endpoints(target, parameters, max_endpoints))
        endpoints = self._dedupe_endpoints([e for e in endpoints if self._is_authorized_endpoint(target, e)])[:max_endpoints]
        if not endpoints:
            return {
                "success": True,
                "target": target,
                "endpointsChecked": 0,
                "requestsRun": 0,
                "findings": [],
                "summary": {"endpointsChecked": 0, "requestsRun": 0, "findings": 0},
                "recommendations": ["No same-origin GET/HEAD API endpoints were supplied. Run browser:traffic_capture first."],
            }

        agent = parameters.get("_agent")
        if agent:
            agent.report_progress("Running API access-control probes", target, 0, max_requests)

        auth_headers = parse_headers(parameters)
        anonymous_headers = self._anonymous_headers(auth_headers)
        has_auth_context = self._has_auth_context(auth_headers)
        findings: List[Dict[str, Any]] = []
        probes: List[Dict[str, Any]] = []
        request_count = 0

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=18)) as session:
            for endpoint in endpoints:
                if request_count >= max_requests:
                    break
                url = endpoint["url"]
                method = endpoint["method"]
                auth_response = await self._fetch(session, method, url, auth_headers)
                request_count += 1
                probes.append(self._probe_record("baseline_auth" if has_auth_context else "baseline", endpoint, auth_response))

                if bool(parameters.get("includeAnonymousComparison", True)) and has_auth_context and request_count < max_requests:
                    anon_response = await self._fetch(session, method, url, anonymous_headers)
                    request_count += 1
                    probes.append(self._probe_record("anonymous_compare", endpoint, anon_response))
                    finding = self._anonymous_visibility_finding(
                        endpoint,
                        auth_response,
                        anon_response,
                        auth_headers,
                        anonymous_headers,
                    )
                    if finding:
                        findings.append(finding)

                if bool(parameters.get("includeIdMutation", True)) and request_count < max_requests:
                    mutations = self._mutated_urls(url)
                    for mutated_url in mutations[:4]:
                        if request_count >= max_requests:
                            break
                        mutated_response = await self._fetch(session, method, mutated_url, auth_headers)
                        request_count += 1
                        probes.append(self._probe_record("id_mutation", {**endpoint, "url": mutated_url}, mutated_response))
                        finding = self._idor_candidate_finding(endpoint, auth_response, mutated_url, mutated_response, auth_headers)
                        if finding:
                            findings.append(finding)
                            break

                if agent:
                    agent.report_progress("Running API access-control probes", url, request_count, max_requests)

        findings = self._dedupe_findings(findings)
        raw_output = "\n".join(self._finding_line(finding) for finding in findings)
        return {
            "success": True,
            "target": target,
            "tool": "api:access_control_probe",
            "endpointsChecked": len(endpoints),
            "requestsRun": request_count,
            "probes": probes[:500],
            "findings": findings,
            "total_findings": len(findings),
            "findings_delivered": len(findings),
            "rawOutput": raw_output,
            "summary": {
                "endpointsChecked": len(endpoints),
                "requestsRun": request_count,
                "findings": len(findings),
                "findingTypes": self._finding_type_counts(findings),
                "authContextDetected": has_auth_context,
            },
        }

    def _normalize_endpoints(self, parameters: Dict[str, Any], target: str) -> List[Dict[str, str]]:
        candidates: List[Any] = []
        if isinstance(parameters.get("apiEndpoints"), list):
            candidates.extend(parameters["apiEndpoints"])
        if isinstance(parameters.get("urls"), list):
            candidates.extend(parameters["urls"])
        if target:
            candidates.append(target)

        endpoints: List[Dict[str, str]] = []
        base = target or ""
        for candidate in candidates:
            method = "GET"
            url = ""
            if isinstance(candidate, dict):
                method = str(candidate.get("method") or "GET").upper()
                url = str(candidate.get("url") or candidate.get("target") or candidate.get("href") or "")
                if not url and candidate.get("path"):
                    url = urljoin(base, str(candidate.get("path")))
                source = str(candidate.get("source") or candidate.get("_origin") or "")
                original_path = str(candidate.get("originalPath") or candidate.get("path") or "")
                operation_id = str(candidate.get("operationId") or "")
            else:
                value = str(candidate or "").strip()
                match = re.match(r"^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+(.+)$", value, re.I)
                if match:
                    method = match.group(1).upper()
                    url = match.group(2).strip()
                else:
                    url = value
                source = ""
                original_path = ""
                operation_id = ""
            if not url:
                continue
            if url.startswith("/"):
                url = urljoin(base, url)
            url = normalize_url(url)
            endpoint = {"method": method, "url": url, "path": self._path_shape(url)}
            if source:
                endpoint["source"] = source
            if original_path:
                endpoint["originalPath"] = original_path
            if operation_id:
                endpoint["operationId"] = operation_id
            endpoints.append(endpoint)

        deduped: List[Dict[str, str]] = []
        seen = set()
        for endpoint in endpoints:
            key = f"{endpoint['method']} {endpoint['path']}"
            if key in seen:
                continue
            seen.add(key)
            deduped.append(endpoint)
        return sorted(deduped, key=self._endpoint_priority, reverse=True)

    def _dedupe_endpoints(self, endpoints: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
        output: List[Dict[str, str]] = []
        seen = set()
        for endpoint in sorted(endpoints, key=self._endpoint_priority, reverse=True):
            key = f"{endpoint.get('method', 'GET')} {endpoint.get('path') or self._path_shape(endpoint.get('url', ''))}"
            if key in seen:
                continue
            seen.add(key)
            output.append(endpoint)
        return output

    async def _discover_readonly_endpoints(
        self,
        target: str,
        parameters: Dict[str, Any],
        max_endpoints: int,
    ) -> List[Dict[str, str]]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        urls: List[str] = [urljoin(base, path) for path in COMMON_READONLY_API_PATHS]
        spec_endpoints: List[Dict[str, str]] = []
        headers = parse_headers(parameters)
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=45)) as session:
            try:
                fetched = await fetch_text(session, target, headers=headers, max_bytes=900_000)
                mapped = extract_html_map(fetched.get("text", ""), fetched.get("url") or target)
                urls.extend(mapped.get("links", []))
                scripts = [url for url in mapped.get("scripts", []) if same_origin(target, url)][:10]
                for script_url in scripts:
                    try:
                        script = await fetch_text(session, script_url, headers=headers, max_bytes=900_000)
                        intel = extract_js_intel(script.get("text", ""), script.get("url") or script_url)
                        urls.extend(intel.get("apiPaths", []))
                        urls.extend([url for url in intel.get("routes", []) if self._looks_api_path(url)])
                    except Exception:
                        continue
            except Exception:
                pass

        # Swagger/OpenAPI documents are higher-signal than guessed API roots.
        # Pull parsed read-only endpoints into this probe so a target with
        # /swagger.json or /v3/api-docs is tested even if the SPA did not issue
        # the relevant XHR during browser traffic capture.
        try:
            from tools.agentic_api_discover import ApiDiscoverTool

            api_params = {
                key: value
                for key, value in parameters.items()
                if key not in {"_agent", "apiEndpoints", "urls"}
            }
            api_discovery = await ApiDiscoverTool().execute(
                {
                    **api_params,
                    "target": target,
                    "maxCandidates": min(int(parameters.get("maxApiSpecCandidates") or 80), 120),
                    "maxEndpoints": max_endpoints,
                }
            )
            if isinstance(api_discovery, dict):
                for endpoint in api_discovery.get("apiEndpoints", []) or []:
                    if not isinstance(endpoint, dict):
                        continue
                    method = str(endpoint.get("method") or "GET").upper()
                    url = endpoint.get("url")
                    if method in SAFE_METHODS and url:
                        urls.append(str(url))
                        spec_endpoints.append({
                            "method": method,
                            "url": normalize_url(str(url)),
                            "path": self._path_shape(normalize_url(str(url))),
                            "source": str(endpoint.get("source") or "openapi"),
                            "originalPath": str(endpoint.get("originalPath") or endpoint.get("path") or ""),
                            "operationId": str(endpoint.get("operationId") or ""),
                        })
        except Exception:
            pass

        endpoints = [
            {"method": "GET", "url": normalize_url(url), "path": self._path_shape(normalize_url(url))}
            for url in urls
        ]
        endpoints.extend(spec_endpoints)
        output: List[Dict[str, str]] = []
        seen = set()
        for endpoint in sorted(endpoints, key=self._endpoint_priority, reverse=True):
            if not same_origin(target, endpoint["url"]):
                continue
            key = endpoint["path"]
            if key in seen:
                continue
            seen.add(key)
            output.append(endpoint)
            if len(output) >= max_endpoints:
                break
        return output

    def _is_authorized_endpoint(self, target: str, endpoint: Dict[str, str]) -> bool:
        method = str(endpoint.get("method") or "GET").upper()
        url = str(endpoint.get("url") or "")
        return method in SAFE_METHODS and same_origin(target, url)

    async def _fetch(self, session: aiohttp.ClientSession, method: str, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
        started = time.monotonic()
        try:
            async with session.request(method, url, headers=headers, allow_redirects=False) as response:
                raw = await read_limited(response.content, 250_001)
                if len(raw) > 250_000:
                    raw = raw[:250_000]
                body = raw.decode("utf-8", errors="replace").replace("\0", "")
                return {
                    "url": str(response.url),
                    "status": response.status,
                    "headers": dict(response.headers),
                    "body": body,
                    "elapsedMs": int((time.monotonic() - started) * 1000),
                    "jsonKeys": self._json_keys(body),
                    "bodyLength": len(body),
                    "sensitiveBodyMarkers": self._sensitive_body_markers(body),
                }
        except Exception as exc:
            return {
                "url": url,
                "status": 0,
                "headers": {},
                "body": "",
                "elapsedMs": int((time.monotonic() - started) * 1000),
                "error": str(exc)[:300],
                "jsonKeys": [],
                "bodyLength": 0,
                "sensitiveBodyMarkers": [],
            }

    def _anonymous_visibility_finding(
        self,
        endpoint: Dict[str, str],
        auth_response: Dict[str, Any],
        anon_response: Dict[str, Any],
        auth_headers: Dict[str, str],
        anonymous_headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        if not self._is_success(auth_response) or not self._is_success(anon_response):
            return None
        if auth_response.get("bodyLength", 0) < 20 or anon_response.get("bodyLength", 0) < 20:
            return None
        if not self._sensitive_endpoint(endpoint["url"]) and not anon_response.get("sensitiveBodyMarkers"):
            return None
        similarity = self._shape_similarity(auth_response, anon_response)
        if similarity < 0.45:
            return None
        severity = "high" if anon_response.get("sensitiveBodyMarkers") else "medium"
        sensitive_markers = anon_response.get("sensitiveBodyMarkers") or []
        return self._finding(
            template_id="xasm-api-public-sensitive-data-signal",
            name="Publicly Accessible Sensitive API Signal",
            severity=severity,
            matched_at=endpoint["url"],
            description=(
                "An API endpoint returned a successful response both with and without "
                "the authenticated context, and the response shape/path suggests sensitive data."
            ),
            remediation="Require authorization checks for the endpoint and verify anonymous users cannot read tenant/user data.",
            matcher_name="anonymous-auth-response-shape",
            extracted=[
                f"auth_status={auth_response.get('status')}",
                f"anonymous_status={anon_response.get('status')}",
                f"shape_similarity={similarity:.2f}",
                f"sensitive_markers={','.join(sensitive_markers)}",
            ],
            evidence=self._anonymous_comparison_evidence(
                endpoint,
                auth_response,
                anon_response,
                auth_headers,
                anonymous_headers,
                similarity,
                sensitive_markers,
            ),
        )

    def _idor_candidate_finding(
        self,
        endpoint: Dict[str, str],
        baseline: Dict[str, Any],
        mutated_url: str,
        mutated_response: Dict[str, Any],
        auth_headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        if not self._is_success(baseline) or not self._is_success(mutated_response):
            return None
        if baseline.get("bodyLength") == mutated_response.get("bodyLength") and baseline.get("body") == mutated_response.get("body"):
            return None
        if self._shape_similarity(baseline, mutated_response) < 0.35:
            return None
        if not self._sensitive_endpoint(endpoint["url"]) and not mutated_response.get("sensitiveBodyMarkers"):
            return None
        return self._finding(
            template_id="xasm-api-idor-bola-candidate",
            name="API IDOR/BOLA Candidate",
            severity="medium",
            matched_at=mutated_url,
            description=(
                "A neighboring object reference returned a successful, similarly shaped response. "
                "This is a strong lead for broken object-level authorization and should be confirmed with a second identity."
            ),
            remediation="Validate object ownership server-side for every resource lookup and test with multiple users.",
            matcher_name="mutated-object-reference-success",
            extracted=[
                f"baseline={endpoint['url']}",
                f"mutated={mutated_url}",
                f"baseline_status={baseline.get('status')}",
                f"mutated_status={mutated_response.get('status')}",
                f"mutated_markers={','.join(mutated_response.get('sensitiveBodyMarkers') or [])}",
            ],
            evidence={
                "request": self._format_http_request(endpoint.get("method") or "GET", mutated_url, auth_headers),
                "response": self._format_http_response(mutated_response),
                "baselineRequest": self._format_http_request(endpoint.get("method") or "GET", endpoint["url"], auth_headers),
                "baselineResponse": self._format_http_response(baseline),
                "baselineUrl": endpoint["url"],
                "mutatedUrl": mutated_url,
                "baselineStatus": baseline.get("status"),
                "mutatedStatus": mutated_response.get("status"),
            },
        )

    def _mutated_urls(self, url: str) -> List[str]:
        parsed = urlparse(url)
        mutations: List[str] = []

        parts = [part for part in parsed.path.split("/") if part]
        for index, part in enumerate(parts):
            if re.fullmatch(r"\d{1,12}", part):
                value = int(part)
                for delta in (-1, 1, 2):
                    candidate_parts = parts[:]
                    candidate_parts[index] = str(max(0, value + delta))
                    mutations.append(urlunparse(parsed._replace(path="/" + "/".join(candidate_parts))))

        query = parse_qsl(parsed.query, keep_blank_values=True)
        for name, value in query:
            if name.lower() in ID_PARAM_NAMES or name.lower().endswith("_id"):
                if re.fullmatch(r"\d{1,12}", value or ""):
                    number = int(value)
                    for delta in (-1, 1, 2):
                        replaced = [(n, str(max(0, number + delta)) if n == name else v) for n, v in query]
                        mutations.append(urlunparse(parsed._replace(query=urlencode(replaced))))

        return dedupe_keep_order([u for u in mutations if u != url], 20)

    def _anonymous_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        output = {}
        for key, value in headers.items():
            if key.lower() in {"authorization", "cookie", "x-api-key", "x-auth-token"}:
                continue
            output[key] = value
        return output

    def _has_auth_context(self, headers: Dict[str, str]) -> bool:
        return any(key.lower() in {"authorization", "cookie", "x-api-key", "x-auth-token"} and value for key, value in headers.items())

    def _endpoint_priority(self, endpoint: Dict[str, str]) -> int:
        url = endpoint["url"]
        score = 0
        if self._sensitive_endpoint(url):
            score += 80
        if self._mutated_urls(url):
            score += 60
        if parse_qsl(urlparse(url).query, keep_blank_values=True):
            score += 30
        if re.search(r"/(?:api|rest|graphql|v\d+)(?:/|$)", urlparse(url).path, re.I):
            score += 20
        return score

    def _looks_api_path(self, url: str) -> bool:
        return bool(re.search(r"/(?:api|rest|graphql|v\d+|rpc)(?:/|$)", urlparse(str(url)).path, re.I))

    def _sensitive_endpoint(self, url: str) -> bool:
        path = urlparse(url).path.lower()
        parts = {part.lower() for part in re.split(r"[^A-Za-z0-9_]+", path) if part}
        if parts & SENSITIVE_PATH_MARKERS:
            return True
        return bool(
            re.search(
                r"/(?:latest/meta-data|meta-data|iam/security-credentials|system-info|internal|secrets?|debug|diagnostics?|config)(?:/|$)",
                path,
                re.I,
            )
        )

    def _sensitive_body_markers(self, body: str) -> List[str]:
        lowered = body.lower()
        markers = []
        for marker in SENSITIVE_BODY_MARKERS:
            if marker.lower() in lowered:
                markers.append(marker)
        return sorted(markers)[:20]

    def _shape_similarity(self, left: Dict[str, Any], right: Dict[str, Any]) -> float:
        left_keys = set(left.get("jsonKeys") or [])
        right_keys = set(right.get("jsonKeys") or [])
        if left_keys or right_keys:
            union = left_keys | right_keys
            if not union:
                return 0.0
            return len(left_keys & right_keys) / len(union)
        left_len = int(left.get("bodyLength") or 0)
        right_len = int(right.get("bodyLength") or 0)
        if not left_len or not right_len:
            return 0.0
        return min(left_len, right_len) / max(left_len, right_len)

    def _is_success(self, response: Dict[str, Any]) -> bool:
        return 200 <= int(response.get("status") or 0) < 300

    def _json_keys(self, body: str) -> List[str]:
        try:
            parsed = json.loads(body)
        except Exception:
            return []
        keys: List[str] = []

        def walk(value: Any, prefix: str = "") -> None:
            if len(keys) >= 80:
                return
            if isinstance(value, dict):
                for key, child in value.items():
                    key_path = f"{prefix}.{key}" if prefix else str(key)
                    keys.append(key_path)
                    walk(child, key_path)
            elif isinstance(value, list) and value:
                walk(value[0], prefix)

        walk(parsed)
        return dedupe_keep_order(keys, 80)

    def _path_shape(self, url: str) -> str:
        parsed = urlparse(url)
        names = [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        if names:
            return f"{parsed.path or '/'}?{'&'.join(f'{name}=*' for name in names)}"
        return parsed.path or "/"

    def _origin(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""

    def _probe_record(self, probe_type: str, endpoint: Dict[str, str], response: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": probe_type,
            "method": endpoint.get("method"),
            "url": endpoint.get("url"),
            "source": endpoint.get("source"),
            "originalPath": endpoint.get("originalPath"),
            "operationId": endpoint.get("operationId"),
            "status": response.get("status"),
            "elapsedMs": response.get("elapsedMs"),
            "bodyLength": response.get("bodyLength"),
            "jsonKeys": (response.get("jsonKeys") or [])[:20],
            "sensitiveBodyMarkers": response.get("sensitiveBodyMarkers") or [],
            "error": response.get("error"),
        }

    def _anonymous_comparison_evidence(
        self,
        endpoint: Dict[str, str],
        auth_response: Dict[str, Any],
        anon_response: Dict[str, Any],
        auth_headers: Dict[str, str],
        anonymous_headers: Dict[str, str],
        similarity: float,
        sensitive_markers: List[str],
    ) -> Dict[str, Any]:
        method = endpoint.get("method") or "GET"
        url = endpoint["url"]
        return {
            "request": self._format_http_request(method, url, auth_headers),
            "response": self._format_http_response(auth_response),
            "anonymousRequest": self._format_http_request(method, url, anonymous_headers),
            "anonymousResponse": self._format_http_response(anon_response),
            "authStatus": auth_response.get("status"),
            "anonymousStatus": anon_response.get("status"),
            "shapeSimilarity": round(similarity, 3),
            "sensitiveMarkers": sensitive_markers,
            "evidenceNote": (
                "Authenticated and anonymous requests both returned successful, similarly shaped responses. "
                "Sensitive values are redacted, but field names and status/body shape are preserved for review."
            ),
        }

    def _format_http_request(self, method: str, url: str, headers: Dict[str, str]) -> str:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        lines = [f"{str(method or 'GET').upper()} {path} HTTP/1.1"]
        request_headers = dict(headers or {})
        if parsed.netloc and not any(key.lower() == "host" for key in request_headers):
            request_headers = {"Host": parsed.netloc, **request_headers}
        for key, value in self._redact_headers(request_headers).items():
            lines.append(f"{key}: {value}")
        return "\n".join(lines)

    def _format_http_response(self, response: Dict[str, Any]) -> str:
        status = int(response.get("status") or 0)
        reason = ""
        if status:
            try:
                reason = HTTPStatus(status).phrase
            except ValueError:
                reason = "Unknown"
        lines = [f"HTTP/1.1 {status or 'N/A'}{f' {reason}' if reason else ''}"]
        headers = self._redact_headers(response.get("headers") or {})
        for key, value in list(headers.items())[:30]:
            lines.append(f"{key}: {value}")
        body = self._redact_body(str(response.get("body") or ""))
        if body:
            lines.extend(["", body])
        if response.get("error"):
            lines.extend(["", f"Error: {response.get('error')}"])
        return "\n".join(lines)

    def _redact_headers(self, headers: Dict[str, Any]) -> Dict[str, str]:
        sensitive = {
            "authorization",
            "cookie",
            "set-cookie",
            "proxy-authorization",
            "x-api-key",
            "x-auth-token",
            "x-csrf-token",
            "x-xsrf-token",
        }
        redacted: Dict[str, str] = {}
        for key, value in (headers or {}).items():
            text = ", ".join(map(str, value)) if isinstance(value, (list, tuple)) else str(value)
            redacted[str(key)] = "[REDACTED]" if str(key).lower() in sensitive else text[:500]
        return redacted

    def _redact_body(self, body: str, limit: int = 4000) -> str:
        if not body:
            return ""
        text = body.replace("\0", "")
        text = re.sub(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "[REDACTED_JWT]", text)
        text = re.sub(
            r"(?i)(\"?(?:password|passwd|pwd|token|access_token|refresh_token|api_?key|secret|ssn)\"?\s*[:=]\s*)(\"[^\"]*\"|[^,\s}\]]+)",
            r"\1[REDACTED]",
            text,
        )
        text = re.sub(r"\b(?:\d[ -]*?){13,19}\b", "[REDACTED_CARD]", text)
        text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", text)

        def mask_email(match: re.Match) -> str:
            local = match.group(1)
            domain = match.group(2)
            visible = local[:1] if local else "x"
            return f"{visible}***@{domain}"

        text = re.sub(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", mask_email, text)
        if len(text) > limit:
            return text[:limit] + "\n...[truncated]"
        return text

    def _finding(
        self,
        *,
        template_id: str,
        name: str,
        severity: str,
        matched_at: str,
        description: str,
        remediation: str,
        matcher_name: str,
        extracted: List[str],
        evidence: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        finding = {
            "template-id": template_id,
            "template": template_id,
            "template-url": "agentic://api-access-control-probe",
            "type": "http",
            "host": self._origin(matched_at),
            "matched-at": matched_at,
            "matcher-name": matcher_name,
            "extracted-results": extracted[:20],
            "info": {
                "name": name,
                "author": ["xasm-agentic"],
                "tags": ["agentic", "api", "authorization", "idor"],
                "severity": severity,
                "description": description,
                "remediation": remediation,
                "classification": {"cwe-id": ["CWE-862", "CWE-639"], "owasp": ["API1:2023", "API5:2023"]},
            },
            "severity": severity,
            "timestamp": int(time.time()),
        }
        if evidence:
            finding["evidence"] = evidence
            request = evidence.get("anonymousRequest") or evidence.get("request")
            response = evidence.get("anonymousResponse") or evidence.get("response")
            if request:
                finding["request"] = request
            if response:
                finding["response"] = response
            matched_content = "\n".join(str(item) for item in extracted[:12] if item)
            if matched_content:
                finding["matched-content"] = matched_content
                finding["matchedContent"] = matched_content
        return finding

    def _dedupe_findings(self, findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        output = []
        for finding in findings:
            key = (finding.get("template-id"), finding.get("matched-at"), finding.get("matcher-name"))
            if key in seen:
                continue
            seen.add(key)
            output.append(finding)
        return output

    def _finding_type_counts(self, findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in findings:
            key = str(finding.get("template-id") or "unknown")
            counts[key] = counts.get(key, 0) + 1
        return counts

    def _finding_line(self, finding: Dict[str, Any]) -> str:
        info = finding.get("info") or {}
        return f"{finding.get('template-id')} [{info.get('severity', finding.get('severity'))}] {info.get('name')} at {finding.get('matched-at')}"


def get_tool():
    return ApiAccessControlProbeTool()
