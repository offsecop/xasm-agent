"""
Read-only API access-control probes for agentic exploration.

The tool consumes endpoints observed by browser:traffic_capture and performs
bounded GET/HEAD comparisons: authenticated vs anonymous visibility, simple
object-id mutations, and a private replay of identifiers observed in JSON into
matching OpenAPI path templates. It does not run write verbs unless the operator
explicitly enables the lab-only privilege-mutation phase.
"""

import json
import re
import time
from http import HTTPStatus
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlparse, urlunparse

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
PATH_PARAM_RE = re.compile(r"\{([^{}]+)\}")
TRUNCATED_JSON_SCALAR_RE = re.compile(
    r'"(?P<key>[A-Za-z0-9_.-]{1,80})"\s*:\s*'
    r'(?P<value>"(?:\\.|[^"\\])*"|-?\d{1,128})(?=\s*[,}\]])'
)
OBSERVED_IDENTIFIER_REQUEST_BUDGET = 6
OBSERVED_IDENTIFIER_VALUES_PER_FIELD = 4
OBSERVED_IDENTIFIER_FIELD_LIMIT = 24
STATIC_ASSET_EXTENSIONS = {
    ".avif",
    ".bmp",
    ".cjs",
    ".css",
    ".eot",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".less",
    ".map",
    ".mjs",
    ".mp3",
    ".mp4",
    ".ogg",
    ".otf",
    ".png",
    ".sass",
    ".scss",
    ".svg",
    ".ttf",
    ".wav",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
}
STATIC_JSON_BASENAMES = {
    "asset-manifest.json",
    "build-manifest.json",
    "manifest.json",
    "package.json",
    "react-loadable-manifest.json",
    "routes-manifest.json",
}
FRAMEWORK_STATIC_PATH_RE = re.compile(
    r"/(?:_next/static|_next/image|_nuxt|static/(?:chunks|css|js|media)|"
    r"assets/(?:css|js|fonts?|images?)|dist|webpack)(?:/|$)",
    re.I,
)
ID_PARAM_NAMES = {
    "id",
    "uid",
    "user",
    "userid",
    "user_id",
    "account",
    "accountid",
    "account_id",
    "account_number",
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
IDENTIFIER_NUMBER_PREFIXES = {
    "account",
    "bill",
    "card",
    "customer",
    "invoice",
    "merchant",
    "order",
    "payment",
    "reference",
    "reservation",
    "transaction",
    "user",
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
ANONYMOUS_CRITICAL_JSON_KEYS = {
    "api_key",
    "apikey",
    "aws_access_key_id",
    "aws_secret_access_key",
    "connection_string",
    "credential",
    "credentials",
    "database_access",
    "password",
    "password_hash",
    "private_key",
    "secret",
    "secret_access_key",
    "secret_key",
    "session_token",
    "ssn",
    "system_prompt",
}
ANONYMOUS_FINANCIAL_JSON_KEYS = {
    "account_number",
    "balance",
    "card_number",
    "credit_card",
    "from_account",
    "routing_number",
    "to_account",
    "transactions",
}
ANONYMOUS_IDENTITY_OR_PRIVILEGE_JSON_KEYS = {
    "admin",
    "email",
    "is_admin",
    "role",
    "user",
    "user_id",
    "username",
    "users",
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

# --- Privilege-field mass-assignment (gated active-write phase, #319) ---------
# These run ONLY under aggressive:true + engagement:lab. The read-only path above
# is unchanged when the gate is off (safe by default).
WRITE_METHODS = ["PATCH", "PUT", "POST"]
# Privilege/role attributes an attacker tries to set via mass-assignment. "role"
# is a string field (-> "admin"); the rest are boolean-ish (-> true).
DEFAULT_PRIVILEGE_FIELDS = [
    "role",
    "is_admin",
    "admin",
    "isAdmin",
    "is_staff",
    "is_superuser",
    "superuser",
]
PRIVILEGE_ELEVATED_STRING = "admin"
# High-signal object-update paths probed under the aggressive gate so a target
# that did not surface its update endpoint during recon is still exercised
# (mirrors HTB Facts `/admin/users/{id}`).
COMMON_OBJECT_UPDATE_PATHS = [
    "/admin/users/1",
    "/admin/users/2",
    "/api/users/1",
    "/api/users/2",
    "/api/v1/users/1",
    "/users/1",
    "/api/user",
    "/api/me",
    "/api/profile",
    "/api/account",
    "/account",
    "/profile",
]
# Single-object path shapes that are strong mass-assignment candidates even when
# the GET body does not surface a privilege field (it may be write-only).
OBJECT_UPDATE_PATH_RE = re.compile(
    r"/(?:admin/)?(?:users?|accounts?|members?|profiles?|people)(?:/\d+)?/?$",
    re.I,
)


class ApiAccessControlProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "api:access_control_probe"

    @property
    def description(self) -> str:
        return (
            "Runs bounded API authorization probes using observed endpoints: anonymous-vs-auth "
            "visibility checks and IDOR/BOLA candidate reads. Under aggressive:true + "
            "engagement:lab it additionally attempts role/is_admin mass-assignment writes on "
            "object-update endpoints (self + neighbor id) with GET read-back confirmation."
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
                "includeAnonymousBaselineAssessment": {
                    "type": "boolean",
                    "default": True,
                    "description": "Promote high-confidence sensitive JSON returned without authentication.",
                },
                "includeIdMutation": {"type": "boolean", "default": True},
                "includeDiscoveredReadOnly": {"type": "boolean", "default": True},
                "cookie": {"type": "string"},
                "authCookies": {"type": "string"},
                "headers": {"type": "object"},
                "authHeaders": {"type": "object"},
                "aggressive": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable active-write probes. Must be paired with engagement:'lab'.",
                },
                "engagement": {
                    "type": "string",
                    "enum": ["safe", "lab"],
                    "default": "safe",
                    "description": "Safety gate. 'lab' (+aggressive) unlocks privilege-field mass-assignment writes.",
                },
                "includePrivilegeMutation": {
                    "type": "boolean",
                    "default": True,
                    "description": "Run the role/is_admin mass-assignment phase (only fires under aggressive+lab).",
                },
                "maxMutationRequests": {
                    "type": "integer",
                    "default": 60,
                    "description": "Upper bound on write/read-back requests in the mass-assignment phase.",
                },
                "privilegeFields": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Override the privilege fields to mass-assign (default: role/is_admin/admin/...).",
                },
                "objectUpdatePaths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Explicit object-update endpoints to test for mass-assignment.",
                },
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
            # --- canonical taxonomy (#559) ---
            "taxonomy_domain": ["api", "web"],
            "lifecycle_phase": "assessment",
            "purpose_count": "multi",
            "primary_purpose": "API broken-access-control assessment (IDOR/BOLA)",
            "secondary_purposes": [
                {"mode": "idor", "purpose": "object-level authorization probe on resource identifiers"},
                {"mode": "bola", "purpose": "function/endpoint-level authorization probe across roles"},
            ],
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
        authorized_endpoints = self._dedupe_endpoints(
            [e for e in endpoints if self._is_authorized_endpoint(target, e)]
        )
        endpoints, static_candidates_filtered = self._without_static_candidates(
            authorized_endpoints
        )
        endpoints = endpoints[:max_endpoints]
        if not endpoints:
            return {
                "success": True,
                "target": target,
                "endpointsChecked": 0,
                "requestsRun": 0,
                "staticCandidatesFiltered": static_candidates_filtered,
                "findings": [],
                "summary": {
                    "endpointsChecked": 0,
                    "requestsRun": 0,
                    "findings": 0,
                    "staticCandidatesFiltered": static_candidates_filtered,
                },
                "recommendations": ["No same-origin GET/HEAD API endpoints were supplied. Run browser:traffic_capture first."],
            }

        agent = parameters.get("_agent")
        if agent:
            agent.report_progress("Running API access-control probes", target, 0, max_requests)

        auth_headers = parse_headers(parameters)
        anonymous_headers = self._anonymous_headers(auth_headers)
        has_auth_context = self._has_auth_context(auth_headers)
        aggressive = bool(parameters.get("aggressive", False))
        engagement = str(parameters.get("engagement") or "safe").lower()
        privilege_phase_enabled = (
            aggressive
            and engagement == "lab"
            and bool(parameters.get("includePrivilegeMutation", True))
        )
        findings: List[Dict[str, Any]] = []
        probes: List[Dict[str, Any]] = []
        request_count = 0
        observed_identifiers: Dict[str, List[Dict[str, str]]] = {}
        templated_endpoints = [
            endpoint
            for endpoint in endpoints
            if endpoint.get("method") == "GET" and self._template_parameter_names(endpoint)
        ]
        replay_reserve = 0
        if templated_endpoints and max_requests >= 4:
            replay_reserve = min(
                OBSERVED_IDENTIFIER_REQUEST_BUDGET,
                max(2, max_requests // 5),
            )
        baseline_request_limit = max_requests - replay_reserve

        connector = aiohttp.TCPConnector(ssl=False)
        # DummyCookieJar: pin the operator-supplied auth cookie for the whole probe.
        # Without it the shared jar captures Set-Cookie from crawled endpoints (e.g.
        # a target's /logout clearing the session), which then overrides the supplied
        # auth header and silently drops the authenticated context mid-scan — breaking
        # the anonymous-vs-auth diff and the privilege-mutation read-back.
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=18),
            cookie_jar=aiohttp.DummyCookieJar(),
        ) as session:
            for endpoint in endpoints:
                if request_count >= baseline_request_limit:
                    break
                url = endpoint["url"]
                method = endpoint["method"]
                auth_response = await self._fetch(session, method, url, auth_headers)
                request_count += 1
                probes.append(self._probe_record("baseline_auth" if has_auth_context else "baseline", endpoint, auth_response))
                anonymous_observation = auth_response if not has_auth_context else None

                if not has_auth_context and bool(parameters.get("includeAnonymousBaselineAssessment", True)):
                    finding = self._anonymous_sensitive_baseline_finding(endpoint, auth_response, anonymous_headers)
                    if finding:
                        findings.append(finding)

                if (
                    bool(parameters.get("includeAnonymousComparison", True))
                    and has_auth_context
                    and request_count < baseline_request_limit
                ):
                    anon_response = await self._fetch(session, method, url, anonymous_headers)
                    request_count += 1
                    probes.append(self._probe_record("anonymous_compare", endpoint, anon_response))
                    anonymous_observation = anon_response
                    finding = self._anonymous_visibility_finding(
                        endpoint,
                        auth_response,
                        anon_response,
                        auth_headers,
                        anonymous_headers,
                    )
                    if finding:
                        findings.append(finding)

                if anonymous_observation is not None:
                    self._collect_observed_identifiers(
                        observed_identifiers,
                        anonymous_observation,
                        endpoint,
                    )

                if bool(parameters.get("includeIdMutation", True)) and request_count < baseline_request_limit:
                    mutations = self._mutated_urls(url)
                    for mutated_url in mutations[:4]:
                        if request_count >= baseline_request_limit:
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

            replay_findings, replay_probes, replay_requests = await self._run_observed_identifier_replay(
                session=session,
                target=target,
                endpoints=templated_endpoints,
                observed_identifiers=observed_identifiers,
                anonymous_headers=anonymous_headers,
                request_budget=min(replay_reserve, max_requests - request_count),
                agent=agent,
            )
            findings.extend(replay_findings)
            probes.extend(replay_probes)
            request_count += replay_requests

            if privilege_phase_enabled:
                mutation_findings = await self._run_privilege_mutation_phase(
                    session, target, endpoints, auth_headers, parameters, agent,
                )
                findings.extend(mutation_findings)

        findings = self._dedupe_findings(findings)
        raw_output = "\n".join(self._finding_line(finding) for finding in findings)
        return {
            "success": True,
            "target": target,
            "tool": "api:access_control_probe",
            "endpointsChecked": len(endpoints),
            "requestsRun": request_count,
            "staticCandidatesFiltered": static_candidates_filtered,
            "probes": probes[:500],
            "findings": findings,
            "total_findings": len(findings),
            "findings_delivered": len(findings),
            "rawOutput": raw_output,
            "summary": {
                "endpointsChecked": len(endpoints),
                "requestsRun": request_count,
                "staticCandidatesFiltered": static_candidates_filtered,
                "findings": len(findings),
                "findingTypes": self._finding_type_counts(findings),
                "authContextDetected": has_auth_context,
                "privilegeMutationRan": privilege_phase_enabled,
                "observedIdentifierFields": sorted(observed_identifiers.keys()),
                "observedIdentifierRequests": replay_requests,
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
            if isinstance(candidate, dict):
                for metadata_key in (
                    "resourceType",
                    "contentType",
                    "status",
                    "apiLike",
                    "responseKeys",
                    "requestBodyKeys",
                ):
                    if candidate.get(metadata_key) is not None:
                        endpoint[metadata_key] = candidate[metadata_key]
            endpoints.append(endpoint)

        deduped: List[Dict[str, str]] = []
        seen = set()
        for endpoint in sorted(endpoints, key=self._endpoint_sort_key, reverse=True):
            key = f"{endpoint['method']} {endpoint['path']}"
            if key in seen:
                continue
            seen.add(key)
            deduped.append(endpoint)
        return sorted(deduped, key=self._endpoint_sort_key, reverse=True)

    def _dedupe_endpoints(self, endpoints: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
        output: List[Dict[str, str]] = []
        seen = set()
        # Keep application endpoints ahead of delivery assets so callers that
        # apply a bounded slice do not let numbered chunks displace real routes.
        for endpoint in sorted(
            endpoints,
            key=lambda item: (
                0 if self._is_static_asset_candidate(item) else 1,
                self._endpoint_sort_key(item),
            ),
            reverse=True,
        ):
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
        # DummyCookieJar (see execute()): preserve the supplied auth cookie so a
        # crawled /logout does not deauth discovery mid-pass.
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=45),
            cookie_jar=aiohttp.DummyCookieJar(),
        ) as session:
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

        generic_endpoints = [
            {"method": "GET", "url": normalize_url(url), "path": self._path_shape(normalize_url(url))}
            for url in urls
        ]
        # Prefer the OpenAPI-rich record when the same concrete URL was also
        # collected as a generic URL. Its originalPath is required for a safe,
        # name-matched identifier replay.
        endpoints = list(spec_endpoints)
        endpoints.extend(generic_endpoints)
        output: List[Dict[str, str]] = []
        seen = set()
        # This intermediate discovery list is bounded too. Rank application
        # candidates first so static chunks cannot fill the cap before the
        # pre-request filter in execute().
        for endpoint in sorted(
            endpoints,
            key=lambda item: (
                0 if self._is_static_asset_candidate(item) else 1,
                self._endpoint_sort_key(item),
            ),
            reverse=True,
        ):
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

    def _collect_observed_identifiers(
        self,
        output: Dict[str, List[Dict[str, str]]],
        response: Dict[str, Any],
        endpoint: Dict[str, str],
    ) -> None:
        if not self._is_success(response):
            return
        # A value returned by the same path template after its OpenAPI sample
        # was materialized (typically `1`) is not an independently observed
        # identifier. Replaying it would only reinforce the synthetic seed and
        # can crowd real identifiers from list/index responses out of the cap.
        if self._template_parameter_names(endpoint):
            return
        source_path = urlparse(str(endpoint.get("url") or "")).path or "/"
        total_values = sum(len(values) for values in output.values())
        visited = 0

        def add_identifier(field_name: str, value: Any) -> None:
            nonlocal total_values
            canonical = self._canonical_identifier_name(field_name)
            identifier = self._safe_identifier_value(value)
            if not canonical or not identifier or not self._is_identifier_name(canonical):
                return
            bucket = output.setdefault(canonical, [])
            if any(item.get("value") == identifier for item in bucket):
                return
            if len(bucket) >= OBSERVED_IDENTIFIER_VALUES_PER_FIELD:
                return
            bucket.append({"value": identifier, "sourcePath": source_path})
            total_values += 1

        def walk(value: Any, field_name: str = "", depth: int = 0) -> None:
            nonlocal total_values, visited
            if depth > 8 or visited >= 300 or total_values >= OBSERVED_IDENTIFIER_FIELD_LIMIT:
                return
            visited += 1
            if isinstance(value, dict):
                for key, child in list(value.items())[:80]:
                    walk(child, str(key), depth + 1)
                return
            if isinstance(value, list):
                for child in value[:20]:
                    walk(child, field_name, depth + 1)
                return

            add_identifier(field_name, value)

        body = str(response.get("body") or "")
        try:
            walk(json.loads(body))
            return
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

        # _fetch deliberately caps bodies at 250 KB. A large JSON list can be
        # cut mid-document, so parse only complete key/scalar pairs from the
        # bounded prefix instead of raising the cap or accepting arbitrary text.
        for match in TRUNCATED_JSON_SCALAR_RE.finditer(body):
            if total_values >= OBSERVED_IDENTIFIER_FIELD_LIMIT:
                break
            raw_value = match.group("value")
            try:
                parsed_value = json.loads(raw_value)
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
            add_identifier(match.group("key"), parsed_value)

    async def _run_observed_identifier_replay(
        self,
        *,
        session: aiohttp.ClientSession,
        target: str,
        endpoints: List[Dict[str, str]],
        observed_identifiers: Dict[str, List[Dict[str, str]]],
        anonymous_headers: Dict[str, str],
        request_budget: int,
        agent: Any,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int]:
        findings: List[Dict[str, Any]] = []
        probes: List[Dict[str, Any]] = []
        requests_run = 0
        if request_budget < 2 or not observed_identifiers:
            return findings, probes, requests_run

        for endpoint in endpoints:
            if requests_run + 2 > request_budget:
                break
            candidates = self._observed_identifier_candidates(endpoint, observed_identifiers)
            for candidate in candidates:
                if requests_run + 2 > request_budget:
                    break
                observed_url = candidate["url"]
                control_url = candidate["controlUrl"]
                if not same_origin(target, observed_url) or not same_origin(target, control_url):
                    continue

                observed_response = await self._fetch(session, "GET", observed_url, anonymous_headers)
                control_response = await self._fetch(session, "GET", control_url, anonymous_headers)
                requests_run += 2

                public_endpoint = {
                    **endpoint,
                    "method": "GET",
                    "url": candidate["publicUrl"],
                }
                public_control = {
                    **endpoint,
                    "method": "GET",
                    "url": candidate["publicControlUrl"],
                }
                observed_probe = self._probe_record(
                    "observed_identifier_replay",
                    public_endpoint,
                    observed_response,
                )
                observed_probe["identifierFields"] = candidate["fields"]
                observed_probe["sourcePaths"] = candidate["sourcePaths"]
                if observed_probe.get("error"):
                    observed_probe["error"] = self._redact_sensitive_values(
                        str(observed_probe["error"]),
                        candidate["values"],
                    )
                control_probe = self._probe_record(
                    "observed_identifier_control",
                    public_control,
                    control_response,
                )
                control_probe["identifierFields"] = candidate["fields"]
                probes.extend([observed_probe, control_probe])

                finding = self._observed_identifier_finding(
                    endpoint=public_endpoint,
                    control_url=candidate["publicControlUrl"],
                    observed_response=observed_response,
                    control_response=control_response,
                    anonymous_headers=anonymous_headers,
                    identifier_fields=candidate["fields"],
                    identifier_values=candidate["values"],
                    source_paths=candidate["sourcePaths"],
                )
                if finding:
                    findings.append(finding)

                if agent:
                    agent.report_progress(
                        "Replaying observed API identifiers",
                        candidate["publicUrl"],
                        requests_run,
                        request_budget,
                    )

        return findings, probes, requests_run

    def _observed_identifier_candidates(
        self,
        endpoint: Dict[str, str],
        observed_identifiers: Dict[str, List[Dict[str, str]]],
    ) -> List[Dict[str, Any]]:
        original_path = str(endpoint.get("originalPath") or "")
        parameter_names = self._template_parameter_names(endpoint)
        if not original_path or not parameter_names:
            return []

        value_sets: List[List[Dict[str, str]]] = []
        canonical_names: List[str] = []
        for name in parameter_names:
            canonical = self._canonical_identifier_name(name)
            values = observed_identifiers.get(canonical) or []
            if not values:
                return []
            canonical_names.append(canonical)
            value_sets.append(values)

        candidates: List[Dict[str, Any]] = []
        candidate_count = min(2, max(len(values) for values in value_sets))
        endpoint_url = urlparse(str(endpoint.get("url") or ""))
        origin = self._origin(str(endpoint.get("url") or ""))
        if not origin:
            return []

        for index in range(candidate_count):
            concrete_path = original_path
            public_path = original_path
            control_path = original_path
            selected_values: List[str] = []
            source_paths: List[str] = []
            for raw_name, canonical, values in zip(parameter_names, canonical_names, value_sets):
                selected = values[index % len(values)]
                selected_value = selected["value"]
                selected_values.append(selected_value)
                source_paths.append(selected["sourcePath"])
                token = "{" + raw_name + "}"
                concrete_path = concrete_path.replace(token, quote(selected_value, safe="-._~"))
                public_path = public_path.replace(token, f"redacted-{canonical}")
                control_path = control_path.replace(token, "xasm-invalid-id")

            observed_url = normalize_url(urljoin(origin + "/", concrete_path.lstrip("/")))
            public_url = normalize_url(urljoin(origin + "/", public_path.lstrip("/")))
            control_url = normalize_url(urljoin(origin + "/", control_path.lstrip("/")))
            if endpoint_url.query:
                observed_url = urlunparse(urlparse(observed_url)._replace(query=endpoint_url.query))
                control_url = urlunparse(urlparse(control_url)._replace(query=endpoint_url.query))
                public_query = urlencode(
                    [
                        (name, "redacted-value" if value else "")
                        for name, value in parse_qsl(endpoint_url.query, keep_blank_values=True)
                    ]
                )
                public_url = urlunparse(urlparse(public_url)._replace(query=public_query))
                public_control_url = urlunparse(urlparse(control_url)._replace(query=public_query))
            else:
                public_control_url = control_url
            if observed_url == str(endpoint.get("url") or ""):
                continue
            candidates.append(
                {
                    "url": observed_url,
                    "publicUrl": public_url,
                    "controlUrl": control_url,
                    "publicControlUrl": public_control_url,
                    "fields": canonical_names,
                    "values": selected_values,
                    "sourcePaths": dedupe_keep_order(source_paths, 8),
                }
            )
        return candidates

    def _observed_identifier_finding(
        self,
        *,
        endpoint: Dict[str, str],
        control_url: str,
        observed_response: Dict[str, Any],
        control_response: Dict[str, Any],
        anonymous_headers: Dict[str, str],
        identifier_fields: List[str],
        identifier_values: List[str],
        source_paths: List[str],
    ) -> Optional[Dict[str, Any]]:
        if not self._is_success(observed_response) or observed_response.get("bodyLength", 0) < 20:
            return None
        if not self._sensitive_endpoint(endpoint["url"]) and not observed_response.get("sensitiveBodyMarkers"):
            return None
        control_similarity = self._shape_similarity(observed_response, control_response)
        if self._is_success(control_response) and control_similarity >= 0.35:
            return None

        severity = "high" if observed_response.get("sensitiveBodyMarkers") else "medium"
        return self._finding(
            template_id="xasm-api-anonymous-observed-object-read",
            name="Anonymous Object Read via Observed Identifier",
            severity=severity,
            matched_at=endpoint["url"],
            description=(
                "A read-only API path accepted an identifier learned from a separate anonymous JSON response "
                "and returned sensitive object data, while an invalid control did not return an equivalent object."
            ),
            remediation=(
                "Require object-level authorization on every resource lookup and avoid exposing reusable object "
                "identifiers through anonymous discovery endpoints."
            ),
            matcher_name="anonymous-observed-identifier-control-diff",
            extracted=[
                f"identifier_fields={','.join(identifier_fields)}",
                f"source_paths={','.join(source_paths)}",
                f"observed_status={observed_response.get('status')}",
                f"control_status={control_response.get('status')}",
                f"control_shape_similarity={control_similarity:.2f}",
                f"sensitive_markers={','.join(observed_response.get('sensitiveBodyMarkers') or [])}",
            ],
            evidence={
                "request": self._format_http_request("GET", endpoint["url"], anonymous_headers),
                "response": self._format_http_response(
                    observed_response,
                    identifier_fields=identifier_fields,
                    identifier_values=identifier_values,
                ),
                "controlRequest": self._format_http_request("GET", control_url, anonymous_headers),
                "controlResponse": self._format_http_response(control_response),
                "observedIdentifierFields": identifier_fields,
                "sourcePaths": source_paths,
                "observedStatus": observed_response.get("status"),
                "controlStatus": control_response.get("status"),
                "controlShapeSimilarity": round(control_similarity, 3),
                "evidenceNote": (
                    "The identifier was retained only in agent memory. Public evidence preserves the route, "
                    "status, and response shape with identifier values redacted."
                ),
            },
        )

    def _template_parameter_names(self, endpoint: Dict[str, str]) -> List[str]:
        original_path = str(endpoint.get("originalPath") or "")
        return dedupe_keep_order(PATH_PARAM_RE.findall(original_path), 8)

    def _canonical_identifier_name(self, value: str) -> str:
        text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or "").strip())
        return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")

    def _is_identifier_name(self, canonical: str) -> bool:
        compact = canonical.replace("_", "")
        known_compact = {name.replace("_", "") for name in ID_PARAM_NAMES}
        if canonical in ID_PARAM_NAMES or compact in known_compact:
            return True
        if canonical.endswith(("_id", "_uid", "_uuid")):
            return True
        if canonical.endswith("_number"):
            return canonical[: -len("_number")] in IDENTIFIER_NUMBER_PREFIXES
        return False

    def _safe_identifier_value(self, value: Any) -> Optional[str]:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return None
        text = str(value).strip()
        if not text or len(text) > 128 or text.lower() in {"none", "null", "undefined"}:
            return None
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,127}", text):
            return None
        return text

    def _is_authorized_endpoint(self, target: str, endpoint: Dict[str, str]) -> bool:
        method = str(endpoint.get("method") or "GET").upper()
        url = str(endpoint.get("url") or "")
        return method in SAFE_METHODS and same_origin(target, url)

    def _is_static_asset_candidate(self, endpoint: Dict[str, Any]) -> bool:
        """Return true only for high-confidence delivery assets, not API routes.

        Explicit API contracts and observed XHR/fetch JSON responses win over a
        filename heuristic. This keeps legitimate endpoints such as
        `/api/export.json` while dropping framework chunks before they consume
        the bounded authorization-probe budget.
        """
        source = str(endpoint.get("source") or "").strip().lower()
        if source in {"openapi", "swagger", "api-spec", "graphql"}:
            return False
        if endpoint.get("operationId") or PATH_PARAM_RE.search(str(endpoint.get("originalPath") or "")):
            return False

        parsed = urlparse(str(endpoint.get("url") or ""))
        path = unquote(parsed.path or "/").lower()
        content_type = str(endpoint.get("contentType") or "").lower()
        resource_type = str(endpoint.get("resourceType") or "").lower()
        observed_application_response = (
            resource_type in {"xhr", "fetch"}
            and any(marker in content_type for marker in ("json", "graphql", "xml", "problem+"))
        )
        if observed_application_response:
            return False

        if FRAMEWORK_STATIC_PATH_RE.search(path):
            return True

        basename = path.rstrip("/").rsplit("/", 1)[-1]
        if basename in STATIC_JSON_BASENAMES:
            return not self._looks_api_path(str(endpoint.get("url") or ""))

        suffix = "." + basename.rsplit(".", 1)[-1] if "." in basename else ""
        if suffix not in STATIC_ASSET_EXTENSIONS:
            return False
        return True

    def _without_static_candidates(
        self, endpoints: Iterable[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], int]:
        application_endpoints: List[Dict[str, Any]] = []
        filtered = 0
        for endpoint in endpoints:
            if self._is_static_asset_candidate(endpoint):
                filtered += 1
            else:
                application_endpoints.append(endpoint)
        return application_endpoints, filtered

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

    def _anonymous_sensitive_baseline_finding(
        self,
        endpoint: Dict[str, str],
        response: Dict[str, Any],
        anonymous_headers: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        if not self._is_success(response) or response.get("bodyLength", 0) < 20:
            return None

        json_keys = [str(key).lower() for key in response.get("jsonKeys") or []]
        if not json_keys:
            return None
        key_parts = {
            part
            for key in json_keys
            for part in re.split(r"[^a-z0-9_]+", key)
            if part
        }
        critical = sorted(key_parts & ANONYMOUS_CRITICAL_JSON_KEYS)
        financial = sorted(key_parts & ANONYMOUS_FINANCIAL_JSON_KEYS)
        identity_or_privilege = sorted(key_parts & ANONYMOUS_IDENTITY_OR_PRIVILEGE_JSON_KEYS)
        if not critical and not (financial and identity_or_privilege):
            return None

        matched_keys = dedupe_keep_order(critical + financial + identity_or_privilege, 20)
        severity = "high" if critical else "medium"
        method = endpoint.get("method") or "GET"
        url = endpoint["url"]
        redacted_response = self._format_http_response(response, redact_json_fields=matched_keys)
        evidence = {
            "request": self._format_http_request(method, url, anonymous_headers),
            "response": redacted_response,
            "anonymousRequest": self._format_http_request(method, url, anonymous_headers),
            "anonymousResponse": redacted_response,
            "anonymousStatus": response.get("status"),
            "sensitiveJsonKeys": matched_keys,
            "evidenceNote": (
                "A request without authentication returned a successful JSON response containing "
                "high-confidence sensitive field names. Values are redacted where required."
            ),
        }
        return self._finding(
            template_id="xasm-api-anonymous-sensitive-data-exposure",
            name="Anonymous Sensitive API Data Exposure",
            severity=severity,
            matched_at=url,
            description=(
                "An unauthenticated API request returned a successful JSON response containing "
                "credential, configuration, identity, privilege, or financial data fields."
            ),
            remediation=(
                "Require authentication and object/function authorization before returning sensitive API data. "
                "Return only the minimum fields required by authorized clients."
            ),
            matcher_name="anonymous-sensitive-json-baseline",
            extracted=[
                f"anonymous_status={response.get('status')}",
                f"sensitive_json_keys={','.join(matched_keys)}",
            ],
            evidence=evidence,
            tags=["agentic", "api", "exposure", "authorization"],
            classification={"cwe-id": ["CWE-200", "CWE-862"], "owasp": ["API1:2023", "API3:2023"]},
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

    # ---- Privilege-field mass-assignment (gated active-write, #319) ----------

    async def _run_privilege_mutation_phase(
        self,
        session: aiohttp.ClientSession,
        target: str,
        endpoints: List[Dict[str, str]],
        auth_headers: Dict[str, str],
        parameters: Dict[str, Any],
        agent: Any,
    ) -> List[Dict[str, Any]]:
        """aggressive+lab only: attempt role/is_admin mass-assignment on object-update
        endpoints (self + neighbor id) and confirm via GET read-back before flagging."""
        privilege_fields = [
            str(f) for f in (parameters.get("privilegeFields") or DEFAULT_PRIVILEGE_FIELDS) if str(f).strip()
        ]
        budget = max(1, min(int(parameters.get("maxMutationRequests") or 60), 200))
        candidates = self._object_update_candidates(target, endpoints, parameters)
        if agent:
            agent.append_output(
                f"[api:access_control] aggressive+lab — probing {len(candidates)} object-update "
                f"candidate(s) for privilege-field mass-assignment"
            )
        findings: List[Dict[str, Any]] = []
        used = 0
        seen_targets: set = set()
        for candidate in candidates:
            if used >= budget:
                break
            # self id + up to two numeric neighbors (BOLA-write on another id)
            urls_to_test = [(candidate, False)]
            for neighbor in self._neighbor_object_urls(candidate)[:2]:
                urls_to_test.append((neighbor, True))
            for url, is_neighbor in urls_to_test:
                if used >= budget:
                    break
                if url in seen_targets:
                    continue
                seen_targets.add(url)
                used_now, finding = await self._attempt_mass_assignment(
                    session, url, privilege_fields, auth_headers, is_neighbor, budget - used,
                )
                used += used_now
                if finding:
                    findings.append(finding)
                    if agent:
                        agent.append_output(
                            f"[api:access_control] CONFIRMED privilege mass-assignment at {url} "
                            f"({'neighbor-id' if is_neighbor else 'self-id'})"
                        )
        return findings

    def _object_update_candidates(
        self, target: str, endpoints: List[Dict[str, str]], parameters: Dict[str, Any]
    ) -> List[str]:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        raw: List[str] = []
        for path in parameters.get("objectUpdatePaths") or []:
            raw.append(urljoin(base, str(path)))
        # observed object-shaped endpoints carry the most signal
        for endpoint in endpoints:
            url = str(endpoint.get("url") or "")
            if url and OBJECT_UPDATE_PATH_RE.search(urlparse(url).path or ""):
                raw.append(url)
        # built-in object-update pack (covers targets that did not surface theirs)
        for path in COMMON_OBJECT_UPDATE_PATHS:
            raw.append(urljoin(base, path))
        output: List[str] = []
        seen = set()
        for url in raw:
            nurl = normalize_url(url)
            if not same_origin(target, nurl) or nurl in seen:
                continue
            seen.add(nurl)
            output.append(nurl)
            if len(output) >= 16:
                break
        return output

    def _neighbor_object_urls(self, url: str) -> List[str]:
        """Numeric-id neighbors of a single-object URL (reuses _mutated_urls logic)."""
        return [u for u in self._mutated_urls(url) if u != url]

    async def _attempt_mass_assignment(
        self,
        session: aiohttp.ClientSession,
        url: str,
        privilege_fields: List[str],
        auth_headers: Dict[str, str],
        is_neighbor: bool,
        remaining_budget: int,
    ) -> Tuple[int, Optional[Dict[str, Any]]]:
        used = 0
        # Baseline read — pre-write privilege value + proves the object is readable.
        before = await self._fetch(session, "GET", url, auth_headers)
        used += 1
        if int(before.get("status") or 0) in (0, 401, 403, 404, 405):
            return used, None
        # An already-privileged object can't demonstrate escalation (no observable
        # state change) — skip it. This is both an FP-kill and a budget guard so an
        # already-admin neighbor does not starve the real candidates.
        if self._object_already_privileged(before, privilege_fields):
            return used, None
        max_object_writes = min(remaining_budget, 18)
        object_writes = 0
        for field in privilege_fields:
            before_val = self._extract_field_value(before, field)
            elevated = True if field.lower() != "role" else PRIVILEGE_ELEVATED_STRING
            if self._values_equal(before_val, elevated):
                continue
            for kind, payload, injected in self._mass_assignment_payloads(url, field):
                if used >= remaining_budget or object_writes >= max_object_writes:
                    return used, None
                write_resp, w_used = await self._write_with_fallback(session, url, kind, payload, auth_headers)
                used += w_used
                object_writes += w_used
                if not self._write_accepted(write_resp):
                    continue
                method = str(write_resp.get("method") or "PATCH")
                # Read-back confirmation (THE FP-kill): the privilege field must
                # actually flip to the injected value vs the pre-write baseline.
                after = await self._fetch(session, "GET", url, auth_headers)
                used += 1
                after_val = self._extract_field_value(after, field)
                confirmed = self._values_equal(after_val, injected) and not self._values_equal(before_val, injected)
                if not confirmed:
                    # Weaker signal: the write response echoes the elevated value.
                    if not self._body_contains_field_value(write_resp, field, injected):
                        continue
                severity = "critical" if confirmed else "high"
                finding = self._mass_assignment_finding(
                    url=url, method=method, field=field, kind=kind, payload=payload,
                    injected=injected, before=before, write_resp=write_resp, after=after,
                    auth_headers=auth_headers, is_neighbor=is_neighbor,
                    confirmed=confirmed, severity=severity,
                )
                # Best-effort restore to leave the target as found.
                if confirmed and before_val is not None:
                    await self._write(
                        session, method, url, kind,
                        self._restore_payload(field, before_val, kind), auth_headers,
                    )
                    used += 1
                return used, finding
        return used, None

    def _object_already_privileged(self, response: Dict[str, Any], privilege_fields: List[str]) -> bool:
        role = self._extract_field_value(response, "role")
        if role is not None and str(role).strip().lower() in ("admin", "administrator", "superadmin", "root"):
            return True
        for field in privilege_fields:
            if field.lower() == "role":
                continue
            value = self._extract_field_value(response, field)
            if value is True:
                return True
            if value is not None and str(value).strip().lower() in ("true", "1", "yes"):
                return True
        return False

    async def _write_with_fallback(
        self, session: aiohttp.ClientSession, url: str, kind: str, payload: Any, headers: Dict[str, str],
    ) -> Tuple[Dict[str, Any], int]:
        """Try PATCH; escalate to PUT/POST only when the verb is rejected (405/501)."""
        used = 0
        resp: Dict[str, Any] = {}
        for method in WRITE_METHODS:
            resp = await self._write(session, method, url, kind, payload, headers)
            used += 1
            if int(resp.get("status") or 0) not in (405, 501):
                return resp, used
        return resp, used

    def _mass_assignment_payloads(self, url: str, field: str) -> List[Tuple[str, Any, Any]]:
        """(encoding, payload, injected_value) tuples covering Rails-nested form,
        flat form, and JSON encodings for a single privilege field."""
        is_bool = field.lower() != "role"
        injected: Any = True if is_bool else PRIVILEGE_ELEVATED_STRING
        flat_value = "true" if is_bool else PRIVILEGE_ELEVATED_STRING
        resource = self._rails_resource(url)
        payloads: List[Tuple[str, Any, Any]] = []
        if resource:
            payloads.append(("form", {f"{resource}[{field}]": flat_value}, injected))  # user[role]=admin
        payloads.append(("form", {field: flat_value}, injected))                        # role=admin
        payloads.append(("json", {field: injected}, injected))                          # {"role":"admin"}
        if resource:
            payloads.append(("json", {resource: {field: injected}}, injected))          # {"user":{"role":"admin"}}
        return payloads

    def _rails_resource(self, url: str) -> str:
        parts = [p for p in urlparse(url).path.split("/") if p and not re.fullmatch(r"\d+", p)]
        if not parts:
            return ""
        last = parts[-1].lower()
        singular = {
            "users": "user", "accounts": "account", "members": "member",
            "profiles": "profile", "people": "person",
        }
        if last in singular:
            return singular[last]
        return last[:-1] if last.endswith("s") and len(last) > 1 else last

    def _restore_payload(self, field: str, before_val: Any, kind: str) -> Any:
        if kind == "json":
            return {field: before_val}
        if isinstance(before_val, bool):
            return {field: "true" if before_val else "false"}
        return {field: "" if before_val is None else str(before_val)}

    async def _write(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        kind: str,
        payload: Any,
        headers: Dict[str, str],
    ) -> Dict[str, Any]:
        started = time.monotonic()
        kwargs: Dict[str, Any] = {"headers": dict(headers or {}), "allow_redirects": False}
        if kind == "json":
            kwargs["json"] = payload
        else:
            kwargs["data"] = payload  # aiohttp form-encodes the dict incl. user[role] keys
        try:
            async with session.request(method, url, **kwargs) as response:
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
                    "method": method,
                }
        except Exception as exc:
            return {
                "url": url, "status": 0, "headers": {}, "body": "",
                "elapsedMs": int((time.monotonic() - started) * 1000),
                "error": str(exc)[:300], "jsonKeys": [], "bodyLength": 0, "method": method,
            }

    def _write_accepted(self, resp: Dict[str, Any]) -> bool:
        status = int(resp.get("status") or 0)
        return status in (200, 201, 202, 204) or 300 <= status < 400

    def _extract_field_value(self, response: Dict[str, Any], field: str) -> Any:
        """Value of `field` from a JSON response body, else None (HTML/non-JSON)."""
        try:
            data = json.loads(str(response.get("body") or ""))
        except Exception:
            return None
        return self._find_field(data, field.lower())

    def _find_field(self, value: Any, field_lower: str, depth: int = 0) -> Any:
        if depth > 6:
            return None
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).lower() == field_lower and not isinstance(child, (dict, list)):
                    return child
            for child in value.values():
                found = self._find_field(child, field_lower, depth + 1)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for item in value[:10]:
                found = self._find_field(item, field_lower, depth + 1)
                if found is not None:
                    return found
        return None

    def _values_equal(self, a: Any, b: Any) -> bool:
        if a is None:
            return False
        if isinstance(b, bool):
            if isinstance(a, bool):
                return a == b
            return str(a).strip().lower() in (("true", "1", "yes") if b else ("false", "0", "no"))
        return str(a).strip().lower() == str(b).strip().lower()

    def _body_contains_field_value(self, resp: Dict[str, Any], field: str, injected: Any) -> bool:
        body = str(resp.get("body") or "").lower()
        if not body:
            return False
        val = ("true" if injected is True else str(injected)).lower()
        return field.lower() in body and val in body

    def _format_http_request_body(
        self, method: str, url: str, headers: Dict[str, str], kind: str, payload: Any
    ) -> str:
        base = self._format_http_request(method, url, headers)
        if kind == "json":
            ctype = "application/json"
            body = json.dumps(payload)
        else:
            ctype = "application/x-www-form-urlencoded"
            body = "&".join(f"{k}={v}" for k, v in (payload or {}).items())
        return f"{base}\nContent-Type: {ctype}\nContent-Length: {len(body)}\n\n{body}"

    def _mass_assignment_finding(
        self, *, url, method, field, kind, payload, injected, before, write_resp, after,
        auth_headers, is_neighbor, confirmed, severity,
    ) -> Dict[str, Any]:
        injected_disp = "true" if injected is True else str(injected)
        kind_disp = "rails-nested/form" if kind == "form" else "json"
        if is_neighbor:
            name = "API Privilege Mass-Assignment on Neighbor Object (BOLA-write)"
            matcher = "neighbor-object-privilege-write"
            extra = (
                "An unprivileged session set a privilege field on ANOTHER object id "
                "(broken object-level authorization on write)."
            )
            extra_tag = "bola"
        else:
            name = "API Privilege-Field Mass-Assignment (Privilege Escalation)"
            matcher = "privilege-field-mass-assignment-confirmed"
            extra = (
                "An unprivileged session escalated its own privilege field via "
                "mass-assignment on an object-update endpoint."
            )
            extra_tag = "privesc"
        confirm_note = (
            "a GET read-back confirms the field flipped to the injected value"
            if confirmed
            else "the write was accepted and its response echoed the elevated value (read-back inconclusive)"
        )
        before_val = self._extract_field_value(before, field)
        after_val = self._extract_field_value(after, field)
        finding = self._finding(
            template_id="xasm-api-mass-assignment-privesc",
            name=name,
            severity=severity,
            matched_at=url,
            description=(
                f"{extra} A {method} to {url} with `{field}={injected_disp}` ({kind_disp}) "
                f"was accepted and {confirm_note}. Mass-assignment of privilege attributes "
                f"(CWE-915) lets a low-privileged user grant themselves an elevated role."
            ),
            remediation=(
                "Whitelist assignable attributes server-side (strong parameters / DTO allow-lists); "
                "never bind client-supplied role/is_admin fields; enforce object ownership and "
                "role-change authorization on every update."
            ),
            matcher_name=matcher,
            extracted=[
                f"endpoint={url}",
                f"method={method}",
                f"field={field}",
                f"injected={injected_disp}",
                f"encoding={kind_disp}",
                f"before={'<none>' if before_val is None else before_val}",
                f"after={'<none>' if after_val is None else after_val}",
                f"confirmation={'read-back' if confirmed else 'response-echo'}",
                f"scope={'neighbor-id' if is_neighbor else 'self-id'}",
            ],
            evidence={
                "request": self._format_http_request_body(method, url, auth_headers, kind, payload),
                "response": self._format_http_response(write_resp),
                "readbackRequest": self._format_http_request("GET", url, auth_headers),
                "readbackResponse": self._format_http_response(after),
                "field": field,
                "injectedValue": injected_disp,
                "beforeValue": None if before_val is None else str(before_val),
                "afterValue": None if after_val is None else str(after_val),
                "confirmed": confirmed,
                "scope": "neighbor-id" if is_neighbor else "self-id",
            },
        )
        info = finding.get("info") or {}
        tags = list(info.get("tags") or [])
        for tag in ("mass-assignment", "privilege-escalation", extra_tag):
            if tag not in tags:
                tags.append(tag)
        info["tags"] = tags
        info["classification"] = {"cwe-id": ["CWE-915", "CWE-639"], "owasp": ["API3:2023", "API1:2023"]}
        finding["info"] = info
        return finding

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

    def _endpoint_sort_key(self, endpoint: Dict[str, str]) -> Tuple[int, int, int]:
        original_path = str(endpoint.get("originalPath") or "")
        return (
            self._endpoint_priority(endpoint),
            1 if PATH_PARAM_RE.search(original_path) else 0,
            1 if str(endpoint.get("source") or "").lower() == "openapi" else 0,
        )

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
            # Responses are intentionally bounded before analysis. Large JSON
            # documents therefore arrive as a valid prefix but cannot be parsed
            # as a complete document. Recover only structural key names from
            # that prefix; never retain values in this fallback path.
            return dedupe_keep_order(
                re.findall(r'"((?:\\.|[^"\\]){1,120})"\s*:', body),
                80,
            )
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

    def _format_http_response(
        self,
        response: Dict[str, Any],
        redact_json_fields: Optional[Iterable[str]] = None,
        *,
        identifier_fields: Optional[List[str]] = None,
        identifier_values: Optional[List[str]] = None,
    ) -> str:
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
            lines.append(f"{key}: {self._redact_sensitive_values(value, identifier_values or [])}")
        body = str(response.get("body") or "")
        if redact_json_fields:
            body = self._redact_json_fields(body, redact_json_fields)
        body = self._redact_identifier_body(
            body,
            identifier_fields or [],
            identifier_values or [],
        )
        body = self._redact_body(body)
        if body:
            lines.extend(["", body])
        if response.get("error"):
            lines.extend(["", f"Error: {response.get('error')}"])
        return "\n".join(lines)

    def _redact_json_fields(self, body: str, field_names: Iterable[str]) -> str:
        fields = {
            str(field).strip().lower()
            for field in field_names
            if str(field).strip()
        }
        if not body or not fields:
            return body

        try:
            parsed = json.loads(body)
        except Exception:
            # Large responses may be a bounded JSON prefix. Redact scalar field
            # values in that prefix without attempting to repair or retain it.
            alternation = "|".join(re.escape(field) for field in sorted(fields, key=len, reverse=True))
            return re.sub(
                rf'(?i)("(?:{alternation})"\s*:\s*)("(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?|true|false|null)',
                r'\1"[REDACTED]"',
                body,
            )

        def redact(value: Any) -> Any:
            if isinstance(value, dict):
                output: Dict[str, Any] = {}
                for key, child in value.items():
                    if str(key).lower() in fields and not isinstance(child, (dict, list)):
                        output[key] = "[REDACTED]"
                    else:
                        output[key] = redact(child)
                return output
            if isinstance(value, list):
                return [redact(item) for item in value]
            return value

        return json.dumps(redact(parsed), ensure_ascii=False, separators=(",", ":"))

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

    def _redact_identifier_body(
        self,
        body: str,
        identifier_fields: List[str],
        identifier_values: List[str],
    ) -> str:
        if not body or (not identifier_fields and not identifier_values):
            return body
        canonical_fields = {self._canonical_identifier_name(field) for field in identifier_fields}
        sensitive_values = {str(value) for value in identifier_values if str(value)}

        try:
            document = json.loads(body)

            def redact(value: Any, field_name: str = "") -> Any:
                if isinstance(value, dict):
                    return {key: redact(child, str(key)) for key, child in value.items()}
                if isinstance(value, list):
                    return [redact(child, field_name) for child in value]
                canonical = self._canonical_identifier_name(field_name)
                if canonical in canonical_fields or str(value) in sensitive_values:
                    return "[REDACTED_ID]"
                return value

            body = json.dumps(redact(document), ensure_ascii=False)
        except Exception:
            pass

        for value in sorted(sensitive_values, key=len, reverse=True):
            body = self._redact_sensitive_values(body, [value])
        return body

    def _redact_sensitive_values(self, text: str, sensitive_values: List[str]) -> str:
        output = str(text or "")
        for value in sorted({str(value) for value in sensitive_values if str(value)}, key=len, reverse=True):
            output = re.sub(
                rf"(?<![A-Za-z0-9._~-]){re.escape(value)}(?![A-Za-z0-9._~-])",
                "[REDACTED_ID]",
                output,
            )
        return output

    def _redact_body(self, body: str, limit: int = 4000) -> str:
        if not body:
            return ""
        text = body.replace("\0", "")
        text = re.sub(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "[REDACTED_JWT]", text)
        text = re.sub(
            r"(?i)(\"?(?:password(?:_hash)?|passwd|pwd|token|access_token|refresh_token|api_?key|secret(?:_access_key|_key)?|session_token|aws_(?:access_key_id|secret_access_key)|credential(?:s)?|ssn|system_prompt|database_access|connection_string|private_key)\"?\s*[:=]\s*)(\"[^\"]*\"|[^,\s}\]]+)",
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
        tags: Optional[List[str]] = None,
        classification: Optional[Dict[str, Any]] = None,
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
                "tags": tags or ["agentic", "api", "authorization", "idor"],
                "severity": severity,
                "description": description,
                "remediation": remediation,
                "classification": classification or {"cwe-id": ["CWE-862", "CWE-639"], "owasp": ["API1:2023", "API5:2023"]},
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
