"""
Deterministic decision helper for agentic exploration.
"""

import json
from typing import Any, Dict, List, Set

from plugin_interface import ToolPlugin


class DecisionPlanNextTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "decision:plan_next"

    @property
    def description(self) -> str:
        return "Builds a bounded next-action plan from exploration observations so the coordinator chooses evidence-driven tools instead of a fixed scanner chain."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "goal": {"type": "string"},
                "observations": {"type": "object"},
                "riskTolerance": {"type": "string", "default": "low"},
            },
            "required": ["target"],
        }

    @property
    def metadata(self):
        return {
            "category": "agentic-recon",
            "phase": 2,
            "domain": ["web", "api"],
            "input_type": ["observations"],
            "output_type": ["plan", "next_actions"],
            "chainable_after": ["browser:", "js:", "api:", "param:", "katana:"],
            "chainable_before": ["curl:", "nuclei:", "dalfox:", "sqlmap:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        target = parameters.get("target")
        observations = parameters.get("observations") if isinstance(parameters.get("observations"), dict) else {}
        goal = parameters.get("goal") or "explore the target safely and choose evidence-driven tests"

        summary = self._summarize(observations)
        risk_tolerance = str(parameters.get("riskTolerance") or "low").lower()
        actions = self._build_actions(target, summary, risk_tolerance)
        top_actions = actions[:4]

        return {
            "success": True,
            "target": target,
            "goal": goal,
            "observationSummary": summary,
            "hypothesesToTest": summary.get("topHypotheses", []),
            "attackChainCandidates": summary.get("attackChainCandidates", []),
            "nextActions": actions,
            "autonomousReasoningBrief": self._brief(target, summary, top_actions),
            "stopConditions": [
                "Stop if the next action would leave authorized scope.",
                "Stop if authenticated session is missing for an authenticated-only area.",
                "Stop if only destructive/write testing remains and no explicit approval exists.",
            ],
            "summary": f"Generated {len(actions)} evidence-driven next actions for {target}",
        }

    def _summarize(self, observations: Dict[str, Any]) -> Dict[str, Any]:
        def value_at(path: List[str]) -> Any:
            cur: Any = observations
            for part in path:
                if not isinstance(cur, dict):
                    return None
                cur = cur.get(part)
            return cur

        def count(path: List[str]) -> int:
            cur = value_at(path)
            return len(cur) if isinstance(cur, list) else int(cur or 0) if isinstance(cur, (int, float)) else 0

        def items(path: List[str]) -> List[Any]:
            cur = value_at(path)
            return cur if isinstance(cur, list) else []

        def merge_items(paths: List[List[str]], limit: int = 240) -> List[Any]:
            seen: Set[str] = set()
            merged: List[Any] = []
            for path in paths:
                for item in items(path):
                    try:
                        key = json.dumps(item, sort_keys=True, default=str)
                    except Exception:
                        key = str(item)
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    merged.append(item)
                    if len(merged) >= limit:
                        return merged
            return merged

        forms = merge_items([["forms"], ["browser", "forms"], ["surfaceGraph", "forms"], ["surfaceSnapshot", "forms"]], 120)
        api_endpoints = merge_items(
            [
                ["apiEndpoints"],
                ["js", "apiEndpoints"],
                ["api", "apiEndpoints"],
                ["browserTraffic", "apiEndpoints"],
                ["traffic", "apiEndpoints"],
                ["surfaceGraph", "apiEndpoints"],
                ["surfaceSnapshot", "apiEndpoints"],
            ],
            300,
        )
        xhr_requests = merge_items(
            [["xhrRequests"], ["browserTraffic", "xhrRequests"], ["traffic", "xhrRequests"], ["surfaceGraph", "xhrRequests"], ["surfaceSnapshot", "xhrRequests"]],
            200,
        )
        parameterized_urls = merge_items(
            [["parameterizedUrls"], ["browserTraffic", "parameterizedUrls"], ["surfaceGraph", "parameterizedUrls"], ["surfaceSnapshot", "parameterizedUrls"]],
            220,
        )
        interesting_parameters = merge_items(
            [["interestingParameters"], ["param", "interestingParameters"], ["surfaceGraph", "interestingParameters"], ["surfaceSnapshot", "interestingParameters"]],
            180,
        )
        hypotheses = merge_items(
            [["hypotheses"], ["js", "hypotheses"], ["surfaceGraph", "hypotheses"], ["surfaceSnapshot", "hypotheses"]],
            240,
        )
        libraries = merge_items([["libraries"], ["sca", "libraries"], ["surfaceGraph", "libraries"], ["surfaceSnapshot", "libraries"]], 160)
        cves = merge_items([["cves"], ["sca", "cves"], ["surfaceGraph", "cves"], ["surfaceSnapshot", "cves"]], 180)
        graphql = merge_items(
            [["graphql"], ["graphqlHints"], ["api", "graphql"], ["surfaceGraph", "graphql"], ["surfaceSnapshot", "graphql"]],
            80,
        )
        openapi_specs = merge_items(
            [["openapiSpecs"], ["api", "openapiSpecs"], ["surfaceGraph", "openapiSpecs"], ["surfaceSnapshot", "openapiSpecs"]],
            80,
        )
        exploitation_candidates = merge_items(
            [
                ["exploitationCandidates"],
                ["candidates"],
                ["candidateQueue", "candidates"],
                ["surfaceSnapshot", "exploitationCandidates"],
                ["surfaceSnapshot", "candidateQueue", "candidates"],
            ],
            160,
        )

        def normalized_categories(hypothesis: Dict[str, Any]) -> Set[str]:
            raw_values = [
                hypothesis.get("category"),
                hypothesis.get("type"),
                *(hypothesis.get("categories") if isinstance(hypothesis.get("categories"), list) else []),
            ]
            categories = {str(value) for value in raw_values if value}
            aliases = {
                "lfi_path_traversal": "file_path_candidate",
                "path_traversal": "file_path_candidate",
                "open_redirect_or_ssrf": "open_redirect_candidate",
                "reflected_xss": "client_side_dangerous_sink",
                "idor_bola": "idor_candidate",
                "auth_bypass_or_login_sqli": "auth_bypass_candidate",
                "auth_recovery_flow": "auth_recovery_candidate",
                "business_logic_api": "business_logic_candidate",
                "business_logic_parameter": "business_logic_candidate",
                "missing_csrf_token": "missing_csrf_token",
                "merchant_api_candidate": "business_logic_candidate",
                "mass_assignment_candidate": "mass_assignment_candidate",
                "openapi_write_operation": "state_changing_api_candidate",
                "payment_amount_candidate": "business_logic_candidate",
                "state_changing_api": "state_changing_api_candidate",
                "state_changing_form": "state_changing_api_candidate",
                "sensitive_surface": "sensitive_client_route",
            }
            for category in list(categories):
                alias = aliases.get(category)
                if alias:
                    categories.add(alias)
            return categories

        category_set: Set[str] = set()
        for hypothesis in hypotheses:
            if isinstance(hypothesis, dict):
                category_set.update(normalized_categories(hypothesis))
        for candidate in exploitation_candidates:
            if isinstance(candidate, dict):
                candidate_type = candidate.get("type") or candidate.get("category")
                if candidate_type:
                    category_set.update(normalized_categories({"type": candidate_type}))
        hypothesis_categories = sorted(
            category_set
        )
        recommended_tools = sorted(
            {
                str(tool)
                for h in hypotheses
                if isinstance(h, dict)
                for tool in (h.get("recommendedTools") or [])
                if tool
            }
            | {
                str(tool)
                for c in exploitation_candidates
                if isinstance(c, dict)
                for tool in (c.get("recommendedTools") or [])
                if tool
            }
        )

        readonly_methods = {"GET", "HEAD", "OPTIONS"}
        write_api_endpoints = [
            endpoint
            for endpoint in api_endpoints
            if isinstance(endpoint, dict)
            and str(endpoint.get("method") or "GET").upper() not in readonly_methods
        ]
        templated_api_endpoints = [
            endpoint
            for endpoint in api_endpoints
            if isinstance(endpoint, dict)
            and (
                endpoint.get("pathParameters")
                or "{" in str(endpoint.get("originalPath") or endpoint.get("path") or endpoint.get("url") or "")
            )
        ]
        login_forms = [
            form for form in forms if isinstance(form, dict) and self._form_looks_like_login(form)
        ]
        auth_context = (
            observations.get("authContext")
            if isinstance(observations.get("authContext"), dict)
            else observations.get("session")
            if isinstance(observations.get("session"), dict)
            else {}
        )
        auth_session_established = bool(
            auth_context.get("hasSession")
            or auth_context.get("currentSession")
            or auth_context.get("sessionEstablished")
        )
        default_credential_hints = "default_credential_hint" in category_set or "auth_bypass_candidate" in category_set
        top_hypotheses = self._top_hypotheses(hypotheses)
        attack_chain_candidates = self._attack_chain_candidates(
            top_hypotheses,
            write_api_endpoints,
            templated_api_endpoints,
            login_forms,
            graphql,
            cves,
        )
        attack_chain_candidates = [
            *self._candidate_attack_chains(exploitation_candidates),
            *attack_chain_candidates,
        ][:10]

        return {
            "forms": len(forms) or count(["forms"]) or count(["browser", "forms"]),
            "buttons": count(["buttons"]) or count(["browser", "buttons"]),
            "apiPaths": count(["apiPaths"]) or count(["js", "apiPaths"]) or count(["api", "apiSurfaces"]),
            "apiEndpoints": len(api_endpoints),
            "writeApiEndpoints": len(write_api_endpoints),
            "templatedApiEndpoints": len(templated_api_endpoints),
            "openapiSpecs": len(openapi_specs),
            "xhrRequests": len(xhr_requests),
            "graphql": len(graphql),
            "parameters": count(["parameters"]) or count(["param", "parameters"]),
            "parameterizedUrls": len(parameterized_urls),
            "siteMapUrls": count(["siteMapUrls"]) or count(["browserTraffic", "siteMapUrls"]) or count(["traffic", "siteMapUrls"]),
            "interestingParameters": len(interesting_parameters),
            "potentialSecrets": count(["potentialSecrets"]) or count(["js", "potentialSecrets"]),
            "hypotheses": len(hypotheses),
            "hypothesisCategories": hypothesis_categories,
            "recommendedTools": recommended_tools,
            "libraries": len(libraries),
            "cves": len(cves),
            "exploitationCandidates": len(exploitation_candidates),
            "topExploitationCandidates": self._top_exploitation_candidates(exploitation_candidates),
            "loginForms": len(login_forms),
            "authSessionEstablished": auth_session_established,
            "defaultCredentialHints": default_credential_hints,
            "topHypotheses": top_hypotheses,
            "attackChainCandidates": attack_chain_candidates,
            "urls": count(["urls"]) or count(["links"]) or count(["browser", "links"]),
        }

    def _build_actions(self, target: str, summary: Dict[str, Any], risk_tolerance: str = "low") -> List[Dict[str, Any]]:
        categories = set(summary.get("hypothesisCategories") or [])
        recommended = set(summary.get("recommendedTools") or [])
        high_risk_allowed = risk_tolerance in {"high", "aggressive", "lab", "ctf"}
        actions: List[Dict[str, Any]] = [
            {
                "priority": 1,
                "tool": "browser:map_app",
                "target": target,
                "reason": "refresh browser map and detect SPA/modal surfaces before active testing",
                "hypothesis": "important routes, forms, and modal flows may be hidden from static crawling",
                "evidenceExpected": "links/forms/buttons/scripts",
                "risk": "LOW",
            }
        ]
        actions.append(
            {
                "priority": 2,
                "tool": "browser:traffic_capture",
                "target": target,
                "reason": "capture real SPA/XHR/API traffic and storage keys before selecting API authorization probes",
                "hypothesis": "client interactions expose API endpoints and request shapes that static URLs miss",
                "evidenceExpected": "XHR endpoints, methods, cookies/storage keys, parameterized URLs",
                "risk": "LOW",
            }
        )
        actions.append(
            {
                "priority": 3,
                "tool": "surface:graph",
                "target": target,
                "reason": "consolidate links, forms, scripts, parameters, known files, and sensitive path hints into one attack-surface graph",
                "hypothesis": "a ranked surface graph is needed before choosing exploit probes",
                "evidenceExpected": "ranked hypotheses with URLs, forms, and parameter categories",
                "risk": "LOW",
            }
        )
        actions.extend(self._candidate_driven_actions(target, summary, high_risk_allowed))
        if summary.get("libraries") or summary.get("cves"):
            actions.append(
                {
                    "priority": 3.2,
                    "tool": "sca:retirejs_scan",
                    "target": target,
                    "reason": "client-side libraries/CVEs were observed; consolidate vulnerable dependency evidence before exploitability triage",
                    "hypothesis": "known vulnerable JavaScript dependencies may map to exploitable runtime behavior",
                    "evidenceExpected": "library versions, CVEs/GHSAs, affected script URLs",
                    "risk": "LOW",
                }
            )
        if summary.get("authSessionEstablished"):
            actions.append(
                {
                    "priority": 3.3,
                    "tool": "api:discover",
                    "target": target,
                    "reason": "an authenticated session exists; discover gated OpenAPI/GraphQL/API surfaces before active follow-up",
                    "hypothesis": "authenticated routes expose additional API schemas and sensitive operations",
                    "evidenceExpected": "authenticated API endpoints and documentation",
                    "risk": "LOW",
                }
            )
        if categories & {"idor_candidate", "sensitive_client_route", "state_changing_api_candidate", "client_side_auth_state"} or "api:access_control_probe" in recommended:
            actions.append(
                {
                    "priority": 3.5,
                    "tool": "api:access_control_probe",
                    "target": target,
                    "reason": "JavaScript exposed sensitive/object-id/API routes; validate anonymous vs authenticated access and IDOR/BOLA behavior",
                    "hypothesis": "object-like or sensitive API routes may be readable without proper authorization",
                    "evidenceExpected": "paired authenticated/anonymous request and response evidence",
                    "risk": "MEDIUM",
                }
            )
        if categories & {"business_logic_candidate", "mass_assignment_candidate", "auth_recovery_candidate"}:
            actions.append(
                {
                    "priority": 3.45,
                    "tool": "api:access_control_probe",
                    "target": target,
                    "reason": "business-critical banking/merchant/auth surfaces were observed; validate anonymous/authenticated access and object ownership before broad scanning",
                    "hypothesis": "business APIs may expose sensitive objects or allow weak authorization boundaries",
                    "evidenceExpected": "business endpoint request/response evidence with anonymous/authenticated comparison",
                    "risk": "HIGH",
                }
            )
            actions.append(
                {
                    "priority": 3.85,
                    "tool": "vuln:chain_probe",
                    "target": target,
                    "reason": "business parameters need chained tampering checks such as amount, role, status, account, merchant, payment, and transaction identifiers",
                    "hypothesis": "business-flow parameters may be exploitable only when tested together, not by single scanners",
                    "evidenceExpected": "tamper attempt request/response proof or explicit no-proof result",
                    "risk": "HIGH",
                }
            )
        if categories & {"business_logic_candidate", "mass_assignment_candidate", "auth_recovery_candidate"} and (
            high_risk_allowed or "param:exploit_probe" in recommended
        ):
            actions.append(
                {
                    "priority": 3.88,
                    "tool": "param:exploit_probe",
                    "target": target,
                    "reason": "business/auth recovery parameters were observed; run bounded parameter abuse probes with request/response evidence",
                    "hypothesis": "amount, account, reset, session, and privilege parameters may accept unsafe values",
                    "evidenceExpected": "payload-specific request/response proof",
                    "risk": "HIGH",
                }
            )
        if categories & {"file_path_candidate"} or "lfi:file_exposure_probe" in recommended:
            actions.append(
                {
                    "priority": 3.7,
                    "tool": "lfi:file_exposure_probe",
                    "target": target,
                    "reason": "JavaScript exposed file/path-style parameters; run targeted HTTP-only LFI/path traversal validation",
                    "hypothesis": "path-controlled parameters may expose local files or container/Kubernetes secrets",
                    "evidenceExpected": "HTTP request/response snippets with validated file markers",
                    "risk": "HIGH",
                }
            )
        if categories & {"open_redirect_candidate", "client_side_dangerous_sink"} or "param:exploit_probe" in recommended:
            actions.append(
                {
                    "priority": 3.9,
                    "tool": "param:exploit_probe",
                    "target": target,
                    "reason": "JavaScript exposed redirect/query/sink signals; validate open redirect, DOM/reflection, file/path, and injection hypotheses",
                    "hypothesis": "parameterized routes may be exploitable beyond simple reflection",
                    "evidenceExpected": "payload-specific request/response proof",
                    "risk": "MEDIUM",
                }
            )
        if "client_side_dangerous_sink" in categories or "dalfox:xss_scan" in recommended or summary.get("parameterizedUrls"):
            actions.append(
                {
                    "priority": 4.1,
                    "tool": "dalfox:xss_scan",
                    "target": target,
                    "reason": "JavaScript uses browser sinks; run XSS-focused validation against parameterized candidates",
                    "hypothesis": "reflected or DOM sinks may become executable with crafted parameters",
                    "evidenceExpected": "XSS payload reflection/execution signal",
                    "risk": "MEDIUM",
                }
            )
        if "client_side_secret_signal" in categories:
            actions.append(
                {
                    "priority": 4.3,
                    "tool": "curl:request",
                    "target": target,
                    "reason": "JavaScript contains secret-like signals; retrieve minimal redacted evidence and verify exposure context",
                    "hypothesis": "secret-like strings may be exposed client-side rather than server-only",
                    "evidenceExpected": "redacted HTTP response excerpt",
                    "risk": "LOW",
                }
            )
        if high_risk_allowed and (
            summary.get("defaultCredentialHints")
            or summary.get("loginForms")
            or "exploit:chain" in recommended
            or categories & {"business_logic_candidate", "mass_assignment_candidate", "auth_recovery_candidate"}
        ):
            actions.append(
                {
                    "priority": 3.6,
                    "tool": "exploit:chain",
                    "target": target,
                    "reason": "authorized aggressive/lab engagement and login/default-credential/auth-pivot signals exist; attempt bounded validation and then authenticated follow-up",
                    "hypothesis": "default credentials or weak auth may unlock deeper authenticated testing",
                    "evidenceExpected": "login attempt outcome, captured session metadata, and follow-up targets",
                    "risk": "HIGH",
                }
            )
        if summary["apiEndpoints"] or summary["xhrRequests"]:
            actions.append(
                {
                    "priority": 4,
                    "tool": "api:access_control_probe",
                    "target": target,
                    "reason": "observed API endpoints exist; test anonymous visibility and IDOR/BOLA candidates with read-only requests",
                    "hypothesis": "observed APIs may expose sensitive data or object-level authorization gaps",
                    "evidenceExpected": "auth vs anonymous response comparison",
                    "risk": "MEDIUM",
                }
            )
        if summary["graphql"]:
            actions.append(
                {
                    "priority": 4.7,
                    "tool": "curl:request",
                    "target": target,
                    "reason": "GraphQL surface was observed; perform safe introspection or schema reachability spot-checks before broader exploitation",
                    "hypothesis": "GraphQL introspection or common queries may disclose schema/object access paths",
                    "evidenceExpected": "GraphQL status/body shape with redacted response",
                    "risk": "LOW",
                }
            )
        if summary["apiPaths"] or summary["graphql"] or summary["apiEndpoints"] or summary.get("openapiSpecs"):
            actions.append(
                {
                    "priority": 5,
                    "tool": "curl:request",
                    "target": target,
                    "reason": "spot-check discovered API/OpenAPI/GraphQL endpoints with safe GET/HEAD requests",
                    "hypothesis": "API documentation and endpoints should be reachable and shape future probes",
                    "evidenceExpected": "HTTP status, headers, and redacted body sample",
                    "risk": "LOW",
                }
            )
        else:
            actions.append(
                {
                    "priority": 5,
                    "tool": "api:discover",
                    "target": target,
                    "reason": "no API surface confirmed yet; probe common API documentation and GraphQL paths",
                    "hypothesis": "API docs or GraphQL may exist at conventional paths even if not linked",
                    "evidenceExpected": "OpenAPI/Swagger/GraphQL discovery result",
                    "risk": "LOW",
                }
            )
        if summary["parameters"] or summary["interestingParameters"] or summary["parameterizedUrls"]:
            actions.append(
                {
                    "priority": 6,
                    "tool": "param:probe",
                    "target": target,
                    "reason": "parameters exist; run safe redirect/file/path probes before broad DAST",
                    "hypothesis": "classified parameters can be tested safely before heavier scanners",
                    "evidenceExpected": "parameter classification and probe outcomes",
                    "risk": "MEDIUM",
                }
            )
            actions.append(
                {
                    "priority": 7,
                    "tool": "param:exploit_probe",
                    "target": target,
                    "reason": "turn parameter hypotheses into concrete LFI/open redirect/XSS/SQLi/command/CRLF evidence",
                    "hypothesis": "some parameter hypotheses should be confirmable with bounded payloads",
                    "evidenceExpected": "payload-specific request/response proof",
                    "risk": "MEDIUM",
                }
            )
            actions.append(
                {
                    "priority": 8,
                    "tool": "vuln:chain_probe",
                    "target": target,
                    "reason": "run chained contextual XSS, boolean SQLi, IDOR-like, and weak form-control probes after parameter evidence exists",
                    "hypothesis": "multiple weak signals may chain into higher-confidence exploitability",
                    "evidenceExpected": "chained probe results and finding deltas",
                    "risk": "MEDIUM",
                }
            )
            actions.append(
                {
                    "priority": 9,
                    "tool": "web:security_controls_probe",
                    "target": target,
                    "reason": "capture missing headers, weak cookies, mixed-content form actions, and CSRF-control gaps that affect exploitability",
                    "hypothesis": "security-control gaps may raise exploitability of discovered forms/routes",
                    "evidenceExpected": "headers, cookie flags, CSRF/control findings",
                    "risk": "LOW",
                }
            )
            actions.append(
                {
                    "priority": 10,
                    "tool": "nuclei:dast_scan",
                    "target": target,
                    "reason": "follow parameter probes with targeted DAST before broad full scan",
                    "hypothesis": "targeted templates can confirm known classes after parameter discovery",
                    "evidenceExpected": "template findings with matched requests",
                    "risk": "MEDIUM",
                }
            )
            actions.append(
                {
                    "priority": 11,
                    "tool": "dalfox:xss_scan",
                    "target": target,
                    "reason": "parameterized URLs are suitable for reflected/DOM XSS checks",
                    "risk": "MEDIUM",
                }
            )
        else:
            if summary["siteMapUrls"]:
                actions.append(
                    {
                        "priority": 6,
                        "tool": "param:probe",
                        "target": target,
                        "reason": "public sitemap/JSON metadata exposed additional application routes; crawl them for GET forms and parameterized candidates",
                        "hypothesis": "metadata-discovered routes may expose hidden parameterized pages",
                        "evidenceExpected": "new URLs/forms/parameters from metadata routes",
                        "risk": "MEDIUM",
                    }
                )
                actions.append(
                    {
                        "priority": 7,
                        "tool": "param:exploit_probe",
                        "target": target,
                        "reason": "metadata-discovered lab routes may expose vulnerable forms even when the homepage has no query strings",
                        "hypothesis": "hidden routes may contain exploitable parameters",
                        "evidenceExpected": "payload-specific request/response proof",
                        "risk": "MEDIUM",
                    }
                )
            actions.append(
                {
                    "priority": 8 if summary["siteMapUrls"] else 6,
                    "tool": "param:discover",
                    "target": target,
                    "reason": "no parameters confirmed yet; classify crawled URLs/forms before injection tools",
                    "hypothesis": "parameter discovery should precede scanner-style injection tests",
                    "evidenceExpected": "classified parameters and candidate URLs",
                    "risk": "LOW",
                }
            )
        if summary["potentialSecrets"]:
            actions.append(
                {
                    "priority": 5,
                    "tool": "curl:request",
                    "target": target,
                    "reason": "potential client-side secret signal found; retrieve only minimal evidence and avoid exposing raw secret values",
                    "hypothesis": "potential secrets need safe redacted confirmation",
                    "evidenceExpected": "redacted response excerpt",
                    "risk": "LOW",
                }
            )
        if high_risk_allowed and (
            summary["forms"]
            or summary["apiEndpoints"]
            or summary["apiPaths"]
            or summary["parameterizedUrls"]
            or summary["interestingParameters"]
        ):
            actions.append(
                {
                    "priority": 7.5,
                    "tool": "exploit:chain",
                    "target": target,
                    "reason": "authorized aggressive/lab engagement with observed forms/API/parameters; run bounded exploit-chain probes and authenticated follow-up pivots",
                    "hypothesis": "confirmed surface signals may chain into auth, API, IDOR, GraphQL, JWT, or debug-console exploit paths",
                    "evidenceExpected": "bounded exploit outcome and follow-up session/API evidence",
                    "risk": "HIGH",
                }
            )
        actions.append(
            {
                "priority": 12,
                "tool": "nuclei:web_scan",
                "target": target,
                "reason": "run broader template coverage after exploration has mapped the interesting surfaces",
                "hypothesis": "template coverage should be last, after targeted evidence-backed probes",
                "evidenceExpected": "template findings and matched evidence",
                "risk": "MEDIUM",
            }
        )
        deduped: List[Dict[str, Any]] = []
        seen_tools = set()
        for action in sorted(actions, key=lambda a: a["priority"]):
            tool = action.get("tool")
            if tool in seen_tools:
                continue
            seen_tools.add(tool)
            deduped.append(action)
            if len(deduped) >= 12:
                break
        return deduped

    def _top_exploitation_candidates(self, candidates: List[Any], limit: int = 12) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        risk_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            rows.append(
                {
                    "id": candidate.get("id"),
                    "type": candidate.get("type") or candidate.get("category"),
                    "title": candidate.get("title") or candidate.get("reason") or "exploitation candidate",
                    "url": candidate.get("url") or candidate.get("target"),
                    "method": candidate.get("method") or "GET",
                    "risk": candidate.get("risk") or "MEDIUM",
                    "confidence": candidate.get("confidence") or 0.5,
                    "recommendedTools": candidate.get("recommendedTools") if isinstance(candidate.get("recommendedTools"), list) else [],
                    "requiresAggressive": bool(candidate.get("requiresAggressive")),
                }
            )
        rows.sort(
            key=lambda row: (
                risk_weight.get(str(row.get("risk") or "").upper(), 0),
                float(row.get("confidence") or 0),
            ),
            reverse=True,
        )
        return rows[:limit]

    def _candidate_driven_actions(
        self,
        target: str,
        summary: Dict[str, Any],
        high_risk_allowed: bool,
    ) -> List[Dict[str, Any]]:
        top_candidates = summary.get("topExploitationCandidates") or []
        grouped: Dict[str, Dict[str, Any]] = {}
        priority_by_tool = {
            "exploit:chain": 3.35,
            "lfi:file_exposure_probe": 3.45,
            "cve:runtime_probe": 3.55,
            "api:access_control_probe": 3.65,
            "param:exploit_probe": 3.75,
            "vuln:chain_probe": 3.85,
            "web:security_controls_probe": 3.95,
            "curl:request": 4.2,
            "dalfox:xss_scan": 4.4,
            "nuclei:dast_scan": 4.8,
            "authentication:ai_browser_login": 5.2,
        }
        for candidate in top_candidates:
            if not isinstance(candidate, dict):
                continue
            if candidate.get("requiresAggressive") and not high_risk_allowed:
                continue
            for tool in candidate.get("recommendedTools") or []:
                row = grouped.setdefault(
                    str(tool),
                    {
                        "priority": priority_by_tool.get(str(tool), 4.9),
                        "tool": str(tool),
                        "target": target,
                        "candidateIds": [],
                        "candidateTypes": [],
                        "risk": candidate.get("risk") or "MEDIUM",
                        "reason": "",
                        "hypothesis": "",
                        "evidenceExpected": "",
                    },
                )
                if candidate.get("id"):
                    row["candidateIds"].append(candidate["id"])
                candidate_type = candidate.get("type") or "candidate"
                if candidate_type not in row["candidateTypes"]:
                    row["candidateTypes"].append(candidate_type)
                if not row["reason"]:
                    row["reason"] = f"exploitation queue recommends {tool} for {candidate.get('title') or candidate_type}"
                if not row["hypothesis"]:
                    row["hypothesis"] = f"{candidate_type} may produce stronger evidence than broad scanning"
                if not row["evidenceExpected"]:
                    row["evidenceExpected"] = "candidate-specific request/response or explicit no-proof outcome"
        actions = list(grouped.values())
        for action in actions:
            action["candidateIds"] = action["candidateIds"][:12]
            if action["candidateTypes"]:
                action["reason"] = f"{action['reason']} ({', '.join(action['candidateTypes'][:5])})"
        return actions

    def _candidate_attack_chains(self, candidates: List[Any], limit: int = 8) -> List[Dict[str, Any]]:
        chains: List[Dict[str, Any]] = []
        for candidate in self._top_exploitation_candidates(candidates, limit):
            tools = candidate.get("recommendedTools") or []
            chains.append(
                {
                    "chain": candidate.get("title") or candidate.get("type") or "exploitation candidate",
                    "signal": candidate.get("url") or candidate.get("id"),
                    "nextTool": tools[0] if tools else None,
                    "candidateId": candidate.get("id"),
                }
            )
        return chains

    def _form_looks_like_login(self, form: Dict[str, Any]) -> bool:
        fields = form.get("fields") if isinstance(form.get("fields"), list) else []
        names = {str(f.get("name") or "").lower() for f in fields if isinstance(f, dict)}
        types = {str(f.get("type") or "").lower() for f in fields if isinstance(f, dict)}
        action = str(form.get("action") or "").lower()
        return (
            "password" in types
            or any("pass" in name for name in names)
            or any(marker in action for marker in ("login", "signin", "auth", "session"))
        )

    def _top_hypotheses(self, hypotheses: List[Any], limit: int = 8) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for item in hypotheses:
            if not isinstance(item, dict):
                continue
            category = item.get("category") or item.get("type") or "hypothesis"
            rows.append(
                {
                    "category": str(category),
                    "priority": item.get("priority") or item.get("confidence") or 50,
                    "target": item.get("url") or item.get("target") or item.get("path") or item.get("source"),
                    "reason": item.get("reason") or item.get("description") or "",
                    "recommendedTools": item.get("recommendedTools") if isinstance(item.get("recommendedTools"), list) else [],
                }
            )
        rows.sort(key=lambda row: float(row.get("priority") or 0), reverse=True)
        return rows[:limit]

    def _attack_chain_candidates(
        self,
        hypotheses: List[Dict[str, Any]],
        write_api_endpoints: List[Any],
        templated_api_endpoints: List[Any],
        login_forms: List[Any],
        graphql: List[Any],
        cves: List[Any],
    ) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        if login_forms:
            candidates.append(
                {
                    "chain": "default credentials -> authenticated recon -> access-control probes",
                    "signal": f"{len(login_forms)} login-like form(s)",
                    "nextTool": "exploit:chain",
                }
            )
        if templated_api_endpoints:
            candidates.append(
                {
                    "chain": "OpenAPI path parameter -> object-id mutation -> BOLA/IDOR validation",
                    "signal": f"{len(templated_api_endpoints)} templated API endpoint(s)",
                    "nextTool": "api:access_control_probe",
                }
            )
        if write_api_endpoints:
            candidates.append(
                {
                    "chain": "state-changing API -> anonymous/authenticated delta -> sensitive operation exposure",
                    "signal": f"{len(write_api_endpoints)} write endpoint(s)",
                    "nextTool": "api:access_control_probe",
                }
            )
        if graphql:
            candidates.append(
                {
                    "chain": "GraphQL discovery -> schema introspection -> object access probing",
                    "signal": f"{len(graphql)} GraphQL signal(s)",
                    "nextTool": "curl:request",
                }
            )
        if cves:
            candidates.append(
                {
                    "chain": "vulnerable JS dependency -> runtime route correlation -> exploitability triage",
                    "signal": f"{len(cves)} CVE/GHSA signal(s)",
                    "nextTool": "cve:runtime_probe",
                }
            )
        if any(h.get("category") in {"business_logic_api", "business_logic_candidate", "business_logic_parameter", "payment_amount_candidate", "mass_assignment_candidate"} for h in hypotheses):
            candidates.append(
                {
                    "chain": "business route -> auth/object delta -> parameter tampering validation",
                    "signal": "business logic candidate",
                    "nextTool": "vuln:chain_probe",
                }
            )
        if any(h.get("category") in {"auth_recovery_candidate", "auth_recovery_flow"} for h in hypotheses):
            candidates.append(
                {
                    "chain": "auth recovery/session route -> reset/session abuse checks -> access-control validation",
                    "signal": "auth recovery candidate",
                    "nextTool": "param:exploit_probe",
                }
            )
        for hypothesis in hypotheses:
            category = str(hypothesis.get("category") or "")
            if category in {"lfi_path_traversal", "file_path_candidate"}:
                candidates.append(
                    {
                        "chain": "file/path parameter -> LFI proof -> cloud/container secret file checks",
                        "signal": hypothesis.get("target") or "path-like parameter",
                        "nextTool": "lfi:file_exposure_probe",
                    }
                )
            elif category in {"open_redirect_or_ssrf", "open_redirect_candidate"}:
                candidates.append(
                    {
                        "chain": "redirect URL parameter -> open redirect/SSRF boundary validation",
                        "signal": hypothesis.get("target") or "redirect-like parameter",
                        "nextTool": "param:exploit_probe",
                    }
                )
            if len(candidates) >= 8:
                break
        return candidates[:8]

    def _brief(self, target: str, summary: Dict[str, Any], actions: List[Dict[str, Any]]) -> str:
        signals = []
        for key, label in [
            ("apiEndpoints", "API endpoints"),
            ("writeApiEndpoints", "write APIs"),
            ("parameterizedUrls", "parameterized URLs"),
            ("hypotheses", "hypotheses"),
            ("loginForms", "login forms"),
            ("graphql", "GraphQL signals"),
            ("cves", "CVE signals"),
            ("exploitationCandidates", "queued exploitation candidates"),
        ]:
            value = summary.get(key)
            if value:
                signals.append(f"{value} {label}")
        first_actions = ", ".join(action.get("tool", "tool") for action in actions)
        signal_line = ", ".join(signals[:6]) or "limited surface signals"
        return f"{target}: {signal_line}. Next evidence-driven tools: {first_actions}."


def get_tool():
    return DecisionPlanNextTool()
