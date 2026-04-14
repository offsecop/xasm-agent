"""
API Fuzzer Tool
Fuzz API endpoints based on OpenAPI specification to discover vulnerabilities.
Performs boundary testing, injection testing, BOLA/IDOR detection, info disclosure,
and rate limit analysis using pure Python (requests library).
"""

import asyncio
import json
import re
import string
import time
import uuid
from typing import Any, Dict, List, Optional
from plugin_interface import ToolPlugin

import requests


# ---------------------------------------------------------------------------
# Payload definitions
# ---------------------------------------------------------------------------

BOUNDARY_PAYLOADS_STRING = [
    "",
    None,
    "A" * 10000,
    "!@#$%^&*()",
    "\u00e9\u00e0\u00fc\u00f1\u00df\u2603\u2764\ufe0f",
    123,
    ["unexpected", "array"],
    {"unexpected": "object"},
]

BOUNDARY_PAYLOADS_NUMBER = [
    "",
    None,
    -1,
    0,
    2147483647,
    -2147483648,
    99999999999999,
    1.7976931348623157e308,
    "not_a_number",
]

BOUNDARY_PAYLOADS_BOOLEAN = [
    "",
    None,
    "yes",
    2,
    "true",
]

SQL_INJECTION_PAYLOADS = [
    "' OR 1=1--",
    '1; DROP TABLE users--',
    '" OR ""="',
    "1' AND '1'='1",
    "' UNION SELECT NULL--",
    "1 OR 1=1",
    "'; WAITFOR DELAY '0:0:5'--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "'-alert(1)-'",
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "; sleep 5",
    "| id",
]

SQL_ERROR_PATTERNS = re.compile(
    r"(sql syntax|mysql|sqlite|postgresql|ora-\d|syntax error|"
    r"unclosed quotation|unterminated string|"
    r"you have an error in your sql|"
    r"quoted string not properly terminated|"
    r"pg::error|pgerror|"
    r"microsoft ole db|odbc sql server driver)",
    re.IGNORECASE,
)

COMMAND_OUTPUT_PATTERNS = re.compile(
    r"(root:.*:0:0|uid=\d+\(|total \d+\s+drwx|"
    r"/bin/(ba)?sh|/usr/sbin|"
    r"daemon:x:|nobody:x:)",
    re.IGNORECASE,
)

INFO_DISCLOSURE_PATTERNS = re.compile(
    r"(traceback \(most recent|stack trace|"
    r"at [a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\(|"
    r"exception in thread|"
    r"internal server error|"
    r"/usr/local/|/home/|/var/www/|C:\\\\|"
    r"x-powered-by|server:\s*(apache|nginx|iis|express|gunicorn)|"
    r"DJANGO_SETTINGS_MODULE|"
    r"database error|db_host|db_password|"
    r"debug\s*=\s*true|DEBUG_MODE|"
    r"phpinfo\(\)|"
    r"wp-config\.php|"
    r"secret.key|api.key|private.key)",
    re.IGNORECASE,
)

CWE_MAP = {
    "boundary": "CWE-20",
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "command_injection": "CWE-78",
    "bola": "CWE-639",
    "info_disclosure": "CWE-200",
    "rate_limit": "CWE-770",
}

SEVERITY_MAP = {
    "sql_injection": "critical",
    "command_injection": "critical",
    "xss": "high",
    "bola": "high",
    "boundary": "medium",
    "info_disclosure": "medium",
    "rate_limit": "low",
}


class ApiFuzzerTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "api_fuzzer:fuzz"

    @property
    def description(self) -> str:
        return "Fuzz API endpoints based on OpenAPI specification to discover vulnerabilities"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "specContent": {
                    "type": "object",
                    "description": "The OpenAPI specification as a JSON object",
                    "x-widget": "json-editor",
                },
                "baseUrl": {
                    "type": "string",
                    "description": "Base URL of the target API (e.g., https://api.example.com)",
                },
                "authHeaders": {
                    "type": "object",
                    "description": "Headers for authentication (e.g., {\"Authorization\": \"Bearer xxx\"})",
                    "x-hidden": True,
                },
                "fuzzModes": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": [
                            "boundary",
                            "injection",
                            "bola",
                            "info_disclosure",
                            "rate_limit",
                        ],
                    },
                    "description": "Which fuzz modes to run",
                },
                "maxEndpoints": {
                    "type": "integer",
                    "description": "Max endpoints to fuzz (default: 50)",
                },
                "maxRequestsPerEndpoint": {
                    "type": "integer",
                    "description": "Max requests per endpoint (default: 20)",
                },
                "rateLimit": {
                    "type": "number",
                    "description": "Delay between requests in seconds (default: 0.1)",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Per-request timeout in seconds (default: 10)",
                },
            },
            "required": ["specContent", "baseUrl", "fuzzModes"],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "api_security",
            "phase": 5,
            "domain": ["api"],
            "input_type": ["api_spec"],
            "output_type": ["findings"],
            "chainable_after": ["httpx:probe", "katana:crawl_depth1"],
            "chainable_before": [],
        }

    # ------------------------------------------------------------------
    # Main execute
    # ------------------------------------------------------------------

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        spec_content = parameters.get("specContent")
        base_url = parameters.get("baseUrl", "").rstrip("/")
        auth_headers = parameters.get("authHeaders") or {}
        fuzz_modes = parameters.get("fuzzModes", [])
        max_endpoints = parameters.get("maxEndpoints", 50)
        max_requests = parameters.get("maxRequestsPerEndpoint", 20)
        rate_limit = parameters.get("rateLimit", 0.1)
        req_timeout = parameters.get("timeout", 10)
        agent = parameters.get("_agent")

        if not spec_content:
            return {"success": False, "error": "specContent is required"}
        if not base_url:
            return {"success": False, "error": "baseUrl is required"}
        if not fuzz_modes:
            return {"success": False, "error": "fuzzModes is required and must not be empty"}

        # Parse spec content if it's a string
        if isinstance(spec_content, str):
            try:
                spec_content = json.loads(spec_content)
            except json.JSONDecodeError as e:
                return {"success": False, "error": f"Invalid JSON in specContent: {e}"}

        try:
            endpoints = self._parse_endpoints(spec_content)
        except Exception as e:
            return {"success": False, "error": f"Failed to parse OpenAPI spec: {e}"}

        if not endpoints:
            return {
                "success": False,
                "error": "No endpoints found in OpenAPI specification",
            }

        # Cap endpoints
        endpoints = endpoints[:max_endpoints]
        total_endpoints = len(endpoints)

        print(f"[api_fuzzer] Parsed {total_endpoints} endpoints, modes: {fuzz_modes}")

        if agent:
            agent.report_progress(
                current_operation="Starting API fuzzing",
                current_target=base_url,
                items_processed=0,
                total_items=total_endpoints,
            )

        all_findings: List[Dict[str, Any]] = []
        total_requests = 0
        endpoints_tested = 0

        for ep_idx, endpoint in enumerate(endpoints):
            method = endpoint["method"]
            path = endpoint["path"]
            full_label = f"{method.upper()} {path}"

            if agent:
                agent.report_progress(
                    current_operation=f"Fuzzing {full_label}",
                    current_target=base_url,
                    items_processed=ep_idx,
                    total_items=total_endpoints,
                )

            consecutive_failures = 0

            for mode in fuzz_modes:
                if consecutive_failures >= 3:
                    print(f"[api_fuzzer] Skipping {full_label} - 3+ consecutive failures")
                    break

                if len(all_findings) >= 2000:
                    break

                try:
                    mode_findings, mode_requests, mode_failures = await self._run_fuzz_mode(
                        mode=mode,
                        endpoint=endpoint,
                        base_url=base_url,
                        auth_headers=auth_headers,
                        max_requests=max_requests,
                        rate_limit=rate_limit,
                        req_timeout=req_timeout,
                    )
                    all_findings.extend(mode_findings)
                    total_requests += mode_requests
                    consecutive_failures = mode_failures if mode_failures >= 3 else 0
                except Exception as e:
                    print(f"[api_fuzzer] Error in mode {mode} for {full_label}: {e}")
                    consecutive_failures += 1

            endpoints_tested += 1

            if len(all_findings) >= 2000:
                print("[api_fuzzer] Reached 2000 findings cap")
                break

        # Cap findings
        total_found = len(all_findings)
        if total_found > 2000:
            all_findings = all_findings[:2000]

        # Build raw output (cap at 5MB)
        raw_output = self._build_raw_output(all_findings)

        if agent:
            agent.report_progress(
                current_operation="API fuzzing completed",
                current_target=base_url,
                items_processed=endpoints_tested,
                total_items=endpoints_tested,
            )

        print(
            f"[api_fuzzer] Complete: {endpoints_tested} endpoints, "
            f"{total_requests} requests, {total_found} findings"
        )

        return {
            "success": True,
            "output": {
                "findings": all_findings,
                "total_findings": total_found,
                "tool": "api_fuzzer",
                "scan_type": "fuzz",
                "endpoints_tested": endpoints_tested,
                "requests_sent": total_requests,
            },
            "raw_output": raw_output,
        }

    # ------------------------------------------------------------------
    # OpenAPI spec parsing
    # ------------------------------------------------------------------

    def _parse_endpoints(self, spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract endpoints from an OpenAPI 2.x / 3.x spec."""
        endpoints: List[Dict[str, Any]] = []
        paths = spec.get("paths", {})

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in ("get", "post", "put", "patch", "delete", "head", "options"):
                if method not in path_item:
                    continue
                operation = path_item[method]
                if not isinstance(operation, dict):
                    continue

                params = self._extract_parameters(operation, path_item)
                body_schema = self._extract_request_body(operation, spec)

                endpoints.append(
                    {
                        "method": method,
                        "path": path,
                        "parameters": params,
                        "body_schema": body_schema,
                        "operation_id": operation.get("operationId", ""),
                    }
                )

        return endpoints

    def _extract_parameters(
        self, operation: Dict, path_item: Dict
    ) -> List[Dict[str, Any]]:
        """Extract query, path, and header parameters."""
        params: List[Dict[str, Any]] = []
        raw_params = list(path_item.get("parameters", [])) + list(
            operation.get("parameters", [])
        )
        seen = set()
        for p in raw_params:
            if not isinstance(p, dict):
                continue
            key = (p.get("name", ""), p.get("in", ""))
            if key in seen:
                continue
            seen.add(key)
            schema = p.get("schema", {})
            params.append(
                {
                    "name": p.get("name", ""),
                    "in": p.get("in", "query"),
                    "required": p.get("required", False),
                    "type": schema.get("type", p.get("type", "string")),
                    "format": schema.get("format", p.get("format", "")),
                }
            )
        return params

    def _extract_request_body(
        self, operation: Dict, spec: Dict
    ) -> Optional[Dict[str, Any]]:
        """Extract request body schema (OAS 3.x or Swagger 2.x body param)."""
        # OAS 3.x
        rb = operation.get("requestBody", {})
        if isinstance(rb, dict):
            content = rb.get("content", {})
            for ct in ("application/json", "application/x-www-form-urlencoded"):
                if ct in content:
                    schema = content[ct].get("schema", {})
                    return self._resolve_schema(schema, spec)

        # Swagger 2.x body parameter
        for p in operation.get("parameters", []):
            if isinstance(p, dict) and p.get("in") == "body":
                schema = p.get("schema", {})
                return self._resolve_schema(schema, spec)

        return None

    def _resolve_schema(
        self, schema: Dict[str, Any], spec: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Resolve $ref references one level deep."""
        if "$ref" in schema:
            ref_path = schema["$ref"]  # e.g. "#/definitions/User" or "#/components/schemas/User"
            parts = ref_path.lstrip("#/").split("/")
            resolved = spec
            for part in parts:
                resolved = resolved.get(part, {})
            return resolved if isinstance(resolved, dict) else schema
        return schema

    # ------------------------------------------------------------------
    # Build URL with path params filled in
    # ------------------------------------------------------------------

    def _build_url(
        self,
        base_url: str,
        path: str,
        path_params: Optional[Dict[str, Any]] = None,
    ) -> str:
        resolved = path
        if path_params:
            for pname, pval in path_params.items():
                resolved = resolved.replace(f"{{{pname}}}", str(pval))
        # Fill remaining path placeholders with dummy values
        resolved = re.sub(r"\{([^}]+)\}", "1", resolved)
        return f"{base_url}{resolved}"

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    async def _send_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Optional[Dict] = None,
        json_body: Any = None,
        timeout: int = 10,
    ) -> Optional[requests.Response]:
        try:
            resp = await asyncio.to_thread(
                requests.request,
                method=method.upper(),
                url=url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            return resp
        except requests.RequestException:
            return None

    # ------------------------------------------------------------------
    # Fuzz mode dispatcher
    # ------------------------------------------------------------------

    async def _run_fuzz_mode(
        self,
        mode: str,
        endpoint: Dict[str, Any],
        base_url: str,
        auth_headers: Dict[str, str],
        max_requests: int,
        rate_limit: float,
        req_timeout: int,
    ) -> tuple:
        """Run a single fuzz mode against an endpoint.

        Returns (findings, requests_count, consecutive_failures).
        """
        if mode == "boundary":
            return await self._fuzz_boundary(
                endpoint, base_url, auth_headers, max_requests, rate_limit, req_timeout
            )
        elif mode == "injection":
            return await self._fuzz_injection(
                endpoint, base_url, auth_headers, max_requests, rate_limit, req_timeout
            )
        elif mode == "bola":
            return await self._fuzz_bola(
                endpoint, base_url, auth_headers, max_requests, rate_limit, req_timeout
            )
        elif mode == "info_disclosure":
            return await self._fuzz_info_disclosure(
                endpoint, base_url, auth_headers, max_requests, rate_limit, req_timeout
            )
        elif mode == "rate_limit":
            return await self._fuzz_rate_limit(
                endpoint, base_url, auth_headers, max_requests, rate_limit, req_timeout
            )
        return [], 0, 0

    # ------------------------------------------------------------------
    # Boundary mode
    # ------------------------------------------------------------------

    async def _fuzz_boundary(
        self,
        endpoint: Dict,
        base_url: str,
        auth_headers: Dict,
        max_requests: int,
        rate_limit: float,
        req_timeout: int,
    ) -> tuple:
        findings = []
        req_count = 0
        consecutive_fail = 0
        method = endpoint["method"]
        path = endpoint["path"]
        label = f"{method.upper()} {path}"

        # Determine fuzzable parameters
        fuzz_targets = self._get_fuzz_targets(endpoint)

        for target_name, target_type, target_location in fuzz_targets:
            if req_count >= max_requests:
                break

            payloads = self._get_boundary_payloads(target_type)

            for payload in payloads:
                if req_count >= max_requests:
                    break

                url, query_params, body = self._prepare_request(
                    base_url, endpoint, target_name, target_location, payload
                )

                headers = {"Content-Type": "application/json", **auth_headers}
                resp = await self._send_request(
                    method, url, headers, params=query_params,
                    json_body=body, timeout=req_timeout,
                )
                req_count += 1
                await asyncio.sleep(rate_limit)

                if resp is None:
                    consecutive_fail += 1
                    if consecutive_fail >= 3:
                        return findings, req_count, consecutive_fail
                    continue
                consecutive_fail = 0

                # Detect issues
                resp_text = resp.text[:5000]
                if resp.status_code >= 500:
                    findings.append(
                        self._make_finding(
                            title=f"Server Error on boundary input in {label} - parameter: {target_name}",
                            severity="medium",
                            description=(
                                f"Sending a boundary value ({self._payload_label(payload)}) to parameter "
                                f"'{target_name}' caused a {resp.status_code} server error. "
                                "The API does not properly validate or handle edge-case inputs."
                            ),
                            evidence={
                                "endpoint": label,
                                "parameter": target_name,
                                "payload": self._payload_label(payload),
                                "response_status": resp.status_code,
                                "response_snippet": resp_text[:500],
                                "fuzz_mode": "boundary",
                            },
                            recommendation="Implement input validation and proper error handling for all parameters.",
                            cwe=CWE_MAP["boundary"],
                        )
                    )
                # Check for stack traces in any response
                if INFO_DISCLOSURE_PATTERNS.search(resp_text):
                    findings.append(
                        self._make_finding(
                            title=f"Stack Trace / Debug Info on boundary input in {label} - parameter: {target_name}",
                            severity="medium",
                            description=(
                                f"Boundary input ({self._payload_label(payload)}) to parameter "
                                f"'{target_name}' exposed debug or internal information in the response."
                            ),
                            evidence={
                                "endpoint": label,
                                "parameter": target_name,
                                "payload": self._payload_label(payload),
                                "response_status": resp.status_code,
                                "response_snippet": resp_text[:500],
                                "fuzz_mode": "boundary",
                            },
                            recommendation="Ensure error responses do not leak internal details such as stack traces or file paths.",
                            cwe=CWE_MAP["info_disclosure"],
                        )
                    )

        return findings, req_count, consecutive_fail

    # ------------------------------------------------------------------
    # Injection mode
    # ------------------------------------------------------------------

    async def _fuzz_injection(
        self,
        endpoint: Dict,
        base_url: str,
        auth_headers: Dict,
        max_requests: int,
        rate_limit: float,
        req_timeout: int,
    ) -> tuple:
        findings = []
        req_count = 0
        consecutive_fail = 0
        method = endpoint["method"]
        path = endpoint["path"]
        label = f"{method.upper()} {path}"

        fuzz_targets = self._get_fuzz_targets(endpoint)

        injection_sets = [
            ("sql_injection", SQL_INJECTION_PAYLOADS),
            ("xss", XSS_PAYLOADS),
            ("command_injection", COMMAND_INJECTION_PAYLOADS),
        ]

        for target_name, _target_type, target_location in fuzz_targets:
            for inj_type, payloads in injection_sets:
                for payload in payloads:
                    if req_count >= max_requests:
                        break

                    url, query_params, body = self._prepare_request(
                        base_url, endpoint, target_name, target_location, payload
                    )

                    headers = {"Content-Type": "application/json", **auth_headers}
                    resp = await self._send_request(
                        method, url, headers, params=query_params,
                        json_body=body, timeout=req_timeout,
                    )
                    req_count += 1
                    await asyncio.sleep(rate_limit)

                    if resp is None:
                        consecutive_fail += 1
                        if consecutive_fail >= 3:
                            return findings, req_count, consecutive_fail
                        continue
                    consecutive_fail = 0

                    resp_text = resp.text[:5000]
                    detected = False

                    if inj_type == "sql_injection" and SQL_ERROR_PATTERNS.search(resp_text):
                        detected = True
                    elif inj_type == "xss" and str(payload) in resp_text:
                        detected = True
                    elif inj_type == "command_injection" and COMMAND_OUTPUT_PATTERNS.search(resp_text):
                        detected = True

                    # Also flag 500 errors on injection payloads
                    if resp.status_code >= 500 and inj_type == "sql_injection":
                        detected = True

                    if detected:
                        sev = SEVERITY_MAP.get(inj_type, "high")
                        inj_label = inj_type.replace("_", " ").title()
                        findings.append(
                            self._make_finding(
                                title=f"{inj_label} in {label} - parameter: {target_name}",
                                severity=sev,
                                description=(
                                    f"A {inj_label} payload was sent to parameter '{target_name}' "
                                    f"and the response indicates potential vulnerability. "
                                    f"Payload: {payload}"
                                ),
                                evidence={
                                    "endpoint": label,
                                    "parameter": target_name,
                                    "payload": str(payload),
                                    "response_status": resp.status_code,
                                    "response_snippet": resp_text[:500],
                                    "fuzz_mode": "injection",
                                },
                                recommendation=self._injection_recommendation(inj_type),
                                cwe=CWE_MAP.get(inj_type, "CWE-74"),
                            )
                        )

                if req_count >= max_requests:
                    break
            if req_count >= max_requests:
                break

        return findings, req_count, consecutive_fail

    # ------------------------------------------------------------------
    # BOLA mode
    # ------------------------------------------------------------------

    async def _fuzz_bola(
        self,
        endpoint: Dict,
        base_url: str,
        auth_headers: Dict,
        max_requests: int,
        rate_limit: float,
        req_timeout: int,
    ) -> tuple:
        findings = []
        req_count = 0
        consecutive_fail = 0
        method = endpoint["method"]
        path = endpoint["path"]
        label = f"{method.upper()} {path}"

        # Only fuzz endpoints with path parameters
        path_params = [
            p for p in endpoint["parameters"] if p["in"] == "path"
        ]
        if not path_params:
            return findings, req_count, consecutive_fail

        # First, make a baseline request with a default ID
        baseline_url = self._build_url(base_url, path)
        headers = {"Content-Type": "application/json", **auth_headers}
        baseline_resp = await self._send_request(
            method, baseline_url, headers, timeout=req_timeout
        )
        req_count += 1
        await asyncio.sleep(rate_limit)

        if baseline_resp is None:
            return findings, req_count, 1

        for param in path_params:
            pname = param["name"]
            ptype = param.get("type", "string")

            # Generate BOLA test values
            test_values = []
            if ptype in ("integer", "number"):
                test_values = [0, 2, 999999, -1]
            else:
                # Could be UUID or string ID
                test_values = [
                    "00000000-0000-0000-0000-000000000000",
                    "test",
                    "admin",
                    "1",
                    "999999",
                ]

            for val in test_values:
                if req_count >= max_requests:
                    break

                test_path = path.replace(f"{{{pname}}}", str(val))
                test_url = f"{base_url}{test_path}"

                resp = await self._send_request(
                    method, test_url, headers, timeout=req_timeout
                )
                req_count += 1
                await asyncio.sleep(rate_limit)

                if resp is None:
                    consecutive_fail += 1
                    if consecutive_fail >= 3:
                        return findings, req_count, consecutive_fail
                    continue
                consecutive_fail = 0

                # If we get 200 with a modified ID, it's a potential BOLA
                if resp.status_code == 200 and resp.text.strip():
                    resp_text = resp.text[:5000]
                    findings.append(
                        self._make_finding(
                            title=f"Potential BOLA/IDOR in {label} - parameter: {pname}",
                            severity="high",
                            description=(
                                f"Accessing {method.upper()} {test_path} with a modified '{pname}' "
                                f"value ({val}) returned HTTP 200 with a non-empty body. "
                                "This may indicate broken object-level authorization (BOLA/IDOR)."
                            ),
                            evidence={
                                "endpoint": label,
                                "parameter": pname,
                                "payload": str(val),
                                "response_status": resp.status_code,
                                "response_snippet": resp_text[:500],
                                "fuzz_mode": "bola",
                            },
                            recommendation=(
                                "Implement proper object-level authorization checks. "
                                "Verify that the authenticated user has permission to access "
                                "the requested resource before returning data."
                            ),
                            cwe=CWE_MAP["bola"],
                        )
                    )

        return findings, req_count, consecutive_fail

    # ------------------------------------------------------------------
    # Info disclosure mode
    # ------------------------------------------------------------------

    async def _fuzz_info_disclosure(
        self,
        endpoint: Dict,
        base_url: str,
        auth_headers: Dict,
        max_requests: int,
        rate_limit: float,
        req_timeout: int,
    ) -> tuple:
        findings = []
        req_count = 0
        consecutive_fail = 0
        method = endpoint["method"]
        path = endpoint["path"]
        label = f"{method.upper()} {path}"

        headers = {"Content-Type": "application/json", **auth_headers}

        # 1. Send malformed requests to trigger error details
        malformed_payloads = [
            None,                     # Missing body
            "not json",               # Invalid JSON
            {"__proto__": "test"},    # Prototype pollution probe
            [],                       # Array instead of object
        ]

        url = self._build_url(base_url, path)

        for payload in malformed_payloads:
            if req_count >= max_requests:
                break

            if payload == "not json":
                resp = await self._send_request(
                    method, url,
                    {**headers, "Content-Type": "text/plain"},
                    timeout=req_timeout,
                )
            else:
                resp = await self._send_request(
                    method, url, headers, json_body=payload, timeout=req_timeout
                )
            req_count += 1
            await asyncio.sleep(rate_limit)

            if resp is None:
                consecutive_fail += 1
                if consecutive_fail >= 3:
                    return findings, req_count, consecutive_fail
                continue
            consecutive_fail = 0

            resp_text = resp.text[:5000]
            if INFO_DISCLOSURE_PATTERNS.search(resp_text):
                findings.append(
                    self._make_finding(
                        title=f"Information Disclosure in {label}",
                        severity="medium",
                        description=(
                            f"A malformed request to {label} returned sensitive information "
                            "such as stack traces, internal paths, or server details."
                        ),
                        evidence={
                            "endpoint": label,
                            "parameter": "request_body",
                            "payload": self._payload_label(payload),
                            "response_status": resp.status_code,
                            "response_snippet": resp_text[:500],
                            "fuzz_mode": "info_disclosure",
                        },
                        recommendation=(
                            "Configure error handling to return generic error messages. "
                            "Remove debug mode in production. Hide server version headers."
                        ),
                        cwe=CWE_MAP["info_disclosure"],
                    )
                )

        # 2. Check common debug endpoints
        debug_suffixes = ["/debug", "/trace", "/env", "/actuator", "/health"]
        for suffix in debug_suffixes:
            if req_count >= max_requests:
                break

            debug_url = f"{url.rstrip('/')}{suffix}"
            resp = await self._send_request("get", debug_url, headers, timeout=req_timeout)
            req_count += 1
            await asyncio.sleep(rate_limit)

            if resp is None:
                consecutive_fail += 1
                if consecutive_fail >= 3:
                    return findings, req_count, consecutive_fail
                continue
            consecutive_fail = 0

            if resp.status_code == 200 and len(resp.text.strip()) > 10:
                resp_text = resp.text[:5000]
                findings.append(
                    self._make_finding(
                        title=f"Debug Endpoint Accessible: {debug_url}",
                        severity="medium",
                        description=(
                            f"The debug/info endpoint {debug_url} is accessible and returned "
                            f"HTTP 200 with content. This may expose sensitive internal details."
                        ),
                        evidence={
                            "endpoint": f"GET {url.rstrip('/')}{suffix}",
                            "parameter": "N/A",
                            "payload": suffix,
                            "response_status": resp.status_code,
                            "response_snippet": resp_text[:500],
                            "fuzz_mode": "info_disclosure",
                        },
                        recommendation="Disable or restrict access to debug/diagnostic endpoints in production.",
                        cwe=CWE_MAP["info_disclosure"],
                    )
                )

        return findings, req_count, consecutive_fail

    # ------------------------------------------------------------------
    # Rate limit mode
    # ------------------------------------------------------------------

    async def _fuzz_rate_limit(
        self,
        endpoint: Dict,
        base_url: str,
        auth_headers: Dict,
        max_requests: int,
        rate_limit: float,
        req_timeout: int,
    ) -> tuple:
        findings = []
        req_count = 0
        consecutive_fail = 0
        method = endpoint["method"]
        path = endpoint["path"]
        label = f"{method.upper()} {path}"

        url = self._build_url(base_url, path)
        headers = {"Content-Type": "application/json", **auth_headers}

        rapid_count = min(20, max_requests)
        got_429 = False
        response_times = []

        for i in range(rapid_count):
            start = time.time()
            resp = await self._send_request(method, url, headers, timeout=req_timeout)
            elapsed = time.time() - start
            req_count += 1
            # No rate limit delay here - that is the point of this test

            if resp is None:
                consecutive_fail += 1
                if consecutive_fail >= 3:
                    return findings, req_count, consecutive_fail
                continue
            consecutive_fail = 0

            response_times.append(elapsed)

            if resp.status_code == 429:
                got_429 = True
                break

        if not got_429 and req_count >= rapid_count:
            # Check for response time degradation
            degradation_note = ""
            if len(response_times) >= 5:
                first_half = response_times[: len(response_times) // 2]
                second_half = response_times[len(response_times) // 2 :]
                avg_first = sum(first_half) / len(first_half)
                avg_second = sum(second_half) / len(second_half)
                if avg_second > avg_first * 2 and avg_second > 1.0:
                    degradation_note = (
                        f" Response time degradation detected: avg first half {avg_first:.2f}s, "
                        f"avg second half {avg_second:.2f}s."
                    )

            findings.append(
                self._make_finding(
                    title=f"Missing Rate Limiting on {label}",
                    severity="low",
                    description=(
                        f"Sent {rapid_count} rapid sequential requests to {label} "
                        f"without receiving HTTP 429 (Too Many Requests). "
                        f"The endpoint may lack rate limiting.{degradation_note}"
                    ),
                    evidence={
                        "endpoint": label,
                        "parameter": "N/A",
                        "payload": f"{rapid_count} rapid requests",
                        "response_status": response_times[-1] if response_times else 0,
                        "response_snippet": f"Sent {rapid_count} requests, no 429 received",
                        "fuzz_mode": "rate_limit",
                    },
                    recommendation=(
                        "Implement rate limiting (e.g., token bucket, sliding window) "
                        "to protect against abuse and denial-of-service attacks."
                    ),
                    cwe=CWE_MAP["rate_limit"],
                )
            )

        return findings, req_count, consecutive_fail

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_fuzz_targets(
        self, endpoint: Dict
    ) -> List[tuple]:
        """Return list of (name, type, location) for parameters to fuzz."""
        targets = []

        # Query and path parameters
        for p in endpoint["parameters"]:
            if p["in"] in ("query", "path", "header"):
                targets.append((p["name"], p.get("type", "string"), p["in"]))

        # Request body properties
        body_schema = endpoint.get("body_schema")
        if body_schema and isinstance(body_schema, dict):
            props = body_schema.get("properties", {})
            for prop_name, prop_def in props.items():
                prop_type = prop_def.get("type", "string") if isinstance(prop_def, dict) else "string"
                targets.append((prop_name, prop_type, "body"))

        return targets

    def _get_boundary_payloads(self, param_type: str) -> list:
        if param_type in ("integer", "number"):
            return BOUNDARY_PAYLOADS_NUMBER
        elif param_type == "boolean":
            return BOUNDARY_PAYLOADS_BOOLEAN
        else:
            return BOUNDARY_PAYLOADS_STRING

    def _prepare_request(
        self,
        base_url: str,
        endpoint: Dict,
        target_name: str,
        target_location: str,
        payload: Any,
    ) -> tuple:
        """Build URL, query params, and body for a fuzz request.

        Returns (url, query_params, body).
        """
        path = endpoint["path"]
        query_params = {}
        body = None

        if target_location == "path":
            path = path.replace(f"{{{target_name}}}", str(payload) if payload is not None else "")
            url = self._build_url(base_url, path)
        else:
            url = self._build_url(base_url, path)

        if target_location == "query":
            query_params[target_name] = payload
        elif target_location == "body":
            # Build a body with the target field set to the payload
            body_schema = endpoint.get("body_schema", {})
            body = {}
            if isinstance(body_schema, dict):
                props = body_schema.get("properties", {})
                for prop_name, prop_def in props.items():
                    if prop_name == target_name:
                        body[prop_name] = payload
                    else:
                        # Fill with default valid values
                        body[prop_name] = self._default_value(
                            prop_def.get("type", "string") if isinstance(prop_def, dict) else "string"
                        )
            else:
                body[target_name] = payload

        return url, query_params if query_params else None, body

    def _default_value(self, param_type: str) -> Any:
        if param_type in ("integer", "number"):
            return 1
        elif param_type == "boolean":
            return True
        elif param_type == "array":
            return []
        elif param_type == "object":
            return {}
        return "test"

    def _payload_label(self, payload: Any) -> str:
        if payload is None:
            return "null"
        s = str(payload)
        if len(s) > 100:
            return s[:100] + "..."
        return s

    def _make_finding(
        self,
        title: str,
        severity: str,
        description: str,
        evidence: Dict[str, Any],
        recommendation: str,
        cwe: str,
    ) -> Dict[str, Any]:
        return {
            "title": title,
            "severity": severity,
            "type": "api_vulnerability",
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "cwe": cwe,
        }

    def _injection_recommendation(self, inj_type: str) -> str:
        if inj_type == "sql_injection":
            return (
                "Use parameterized queries or prepared statements. "
                "Never concatenate user input into SQL queries. "
                "Apply input validation and use an ORM where possible."
            )
        elif inj_type == "xss":
            return (
                "Encode all user-supplied output in responses. "
                "Use Content-Security-Policy headers. "
                "Validate and sanitize input on the server side."
            )
        elif inj_type == "command_injection":
            return (
                "Avoid passing user input to system commands. "
                "Use safe APIs instead of shell execution. "
                "If shell execution is required, use allowlists and strict input validation."
            )
        return "Validate and sanitize all user input."

    def _build_raw_output(self, findings: List[Dict]) -> str:
        if not findings:
            return ""
        lines = [json.dumps(f) for f in findings]
        raw = "\n".join(lines)
        max_size = 5 * 1024 * 1024
        if len(raw) > max_size:
            raw = "\n".join(lines[:500]) + f"\n... (truncated, total {len(lines)} findings)"
        return raw


def get_tool():
    return ApiFuzzerTool()
