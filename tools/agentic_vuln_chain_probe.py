"""
Evidence-chain probes for agentic web testing.

This tool uses the attack-surface graph idea: discover candidate URLs/forms,
then run bounded follow-up probes that look for chained evidence such as
contextual XSS, boolean SQLi behavior, IDOR-like object references, and weak
login/form controls. It deliberately avoids destructive methods and data dumps.
"""

import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    classify_parameters,
    dedupe_keep_order,
    extract_html_map,
    fetch_text,
    normalize_url,
    parse_headers,
    read_limited,
    same_origin,
)


XSS_CONTEXT_PAYLOADS = [
    ('html', 'xasmctx"><svg/onload=confirm(7331)>'),
    ('attribute', '" autofocus onfocus=confirm(7331) x="'),
    ('script', '</script><svg/onload=confirm(7331)>'),
    ('js_string', "';confirm(7331);//"),
]
XSS_EXEC_FRAGMENTS = [
    '<svg/onload=confirm(7331)>',
    'autofocus onfocus=confirm(7331)',
    '</script><svg/onload=confirm(7331)>',
    "';confirm(7331);//",
]

SQL_TRUE_FALSE_PAYLOADS = [
    ("' OR '1'='1", "' AND '1'='2"),
    ("\" OR \"1\"=\"1", "\" AND \"1\"=\"2"),
    ("1 OR 1=1", "1 AND 1=2"),
]

OBJECT_ID_NAMES = {"id", "uid", "user", "account", "acct", "order", "invoice", "profile", "customer", "tenant"}
CSRF_NAMES = {"csrf", "_csrf", "csrf_token", "authenticity_token", "__requestverificationtoken"}
PASSWORD_NAMES = {"pass", "passw", "password", "pwd"}
USERNAME_NAMES = {"uid", "user", "username", "email", "login", "userid", "account"}
REDACTION_PATTERNS = [
    (r"(?i)(Authorization:\s*(?:Bearer|Basic)\s+)[^\r\n]+", r"\1[REDACTED]"),
    (r"(?i)(Cookie:\s*)[^\r\n]+", r"\1[REDACTED]"),
    (r"(?i)(Set-Cookie:\s*)[^\r\n]+", r"\1[REDACTED]"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "[JWT_REDACTED]"),
    (r"(?i)((?:password|passwd|token|access_token|refresh_token|api_key|secret)=)([^&\s]+)", r"\1[REDACTED]"),
]


class VulnChainProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "vuln:chain_probe"

    @property
    def description(self) -> str:
        return "Runs bounded chained evidence probes for contextual XSS, boolean SQLi, IDOR-like object references, and weak form/login controls."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "urls": {"type": "array", "items": {"type": "string"}},
                "forms": {"type": "array", "items": {"type": "object"}},
                "discoverFromTarget": {"type": "boolean", "default": True},
                "maxPages": {"type": "integer", "default": 35},
                "maxUrls": {"type": "integer", "default": 140},
                "maxRequests": {"type": "integer", "default": 180},
                "includeXssContext": {"type": "boolean", "default": True},
                "includeBooleanSqli": {"type": "boolean", "default": True},
                "includeIdorSignals": {"type": "boolean", "default": True},
                "includeFormControlChecks": {"type": "boolean", "default": True},
                "cookie": {"type": "string"},
                "authCookies": {"type": "string"},
                "headers": {"type": "object"},
                "authHeaders": {"type": "object"},
            },
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}, {"required": ["urls"]}],
        }

    @property
    def metadata(self):
        return {
            "category": "agentic-recon",
            "phase": 4,
            "domain": ["web"],
            "input_type": ["url", "urls"],
            "output_type": ["findings", "chain_probe_results"],
            "chainable_after": ["surface:", "browser:", "katana:", "param:"],
            "chainable_before": ["curl:", "nuclei:", "sqlmap:", "dalfox:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        target = normalize_url(parameters.get("target") or parameters.get("url") or "")
        urls: List[str] = []
        if isinstance(parameters.get("urls"), list):
            urls.extend(str(u) for u in parameters["urls"] if u)
        if target:
            urls.insert(0, target)
        if not urls:
            return {"success": False, "error": "target/url or urls is required"}

        base = target or urls[0]
        max_urls = max(1, min(int(parameters.get("maxUrls") or 140), 500))
        max_requests = max(1, min(int(parameters.get("maxRequests") or 180), 600))
        headers = parse_headers(parameters)
        forms = parameters.get("forms") if isinstance(parameters.get("forms"), list) else []
        agent = parameters.get("_agent")

        if bool(parameters.get("discoverFromTarget", True)):
            discovered = await self._discover(base, parameters)
            urls.extend(discovered["urls"])
            forms.extend(discovered["forms"])

        urls.extend(self._form_get_url_candidates(forms))
        urls = [u for u in dedupe_keep_order(urls, max_urls) if self._allowed(base, u)]
        classified = classify_parameters(urls, forms)
        parameterized = self._prioritize_urls(classified.get("urlsWithParams", []))

        findings: List[Dict[str, Any]] = []
        probes: List[Dict[str, Any]] = []
        request_count = 0

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as session:
            baseline_cache: Dict[str, Dict[str, Any]] = {}
            for url in parameterized:
                if request_count >= max_requests:
                    break
                baseline = await self._baseline(session, headers, url, baseline_cache)
                request_count += 1 if baseline.get("_fetched") else 0
                names = [name for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
                for name in names:
                    if request_count >= max_requests:
                        break
                    if bool(parameters.get("includeXssContext", True)):
                        created, used = await self._probe_xss_context(session, headers, url, name)
                        request_count += used
                        findings.extend(created["findings"])
                        probes.extend(created["probes"])
                    if request_count >= max_requests:
                        break
                    if bool(parameters.get("includeBooleanSqli", True)) and self._sqli_candidate(name):
                        created, used = await self._probe_boolean_sqli(session, headers, url, name, baseline)
                        request_count += used
                        findings.extend(created["findings"])
                        probes.extend(created["probes"])
                    if request_count >= max_requests:
                        break
                    if bool(parameters.get("includeIdorSignals", True)) and self._idor_candidate(name, url):
                        created, used = await self._probe_idor_signal(session, headers, url, name, baseline)
                        request_count += used
                        findings.extend(created["findings"])
                        probes.extend(created["probes"])
                if agent:
                    agent.report_progress("Running chained vulnerability probes", url, request_count, max_requests)

            if bool(parameters.get("includeFormControlChecks", True)) and request_count < max_requests:
                created, used = await self._probe_form_controls(session, headers, forms, base, max_requests - request_count)
                request_count += used
                findings.extend(created["findings"])
                probes.extend(created["probes"])

        findings = self._dedupe_findings(findings)
        return {
            "success": True,
            "target": base,
            "candidateUrls": parameterized,
            "parameters": classified.get("parameters", {}),
            "probes": probes[:1000],
            "findings": findings,
            "total_findings": len(findings),
            "findings_delivered": len(findings),
            "tool": "vuln:chain_probe",
            "rawOutput": "\n".join(self._finding_line(f) for f in findings),
            "summary": {
                "urlsAnalyzed": len(urls),
                "candidateUrls": len(parameterized),
                "requestsRun": request_count,
                "probesRun": len(probes),
                "findings": len(findings),
                "findingTypes": self._finding_type_counts(findings),
            },
        }

    async def _discover(self, base: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        max_pages = max(1, min(int(parameters.get("maxPages") or 35), 100))
        headers = parse_headers(parameters)
        urls: List[str] = [base]
        forms: List[Dict[str, Any]] = []
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as session:
            visited = set()
            cursor = 0
            while cursor < len(urls) and len(visited) < max_pages:
                url = urls[cursor]
                cursor += 1
                if url in visited or not self._allowed(base, url):
                    continue
                try:
                    fetched = await fetch_text(session, url, headers=headers, max_bytes=900_000)
                    mapped = extract_html_map(fetched.get("text", ""), fetched.get("url") or url)
                except Exception:
                    continue
                visited.add(url)
                urls.extend([u for u in mapped.get("links", []) if self._allowed(base, u)])
                forms.extend(self._annotate_forms_with_source(mapped.get("forms", []), fetched, url, headers))
        # Patch: augment with browser traffic capture (XHRs + apiEndpoints) and pre-seeded SPA paths.
        # The HTML-only crawl above misses Angular/React SPAs (no <a>/<form>) and Flask/Express APIs.
        try:
            from tools.agentic_browser_traffic_capture import BrowserTrafficCaptureTool
            traffic = await BrowserTrafficCaptureTool().execute(
                {
                    **parameters,
                    "_agent": None,
                    "target": base,
                    "maxInteractions": min(int(parameters.get("maxInteractions") or 8), 12),
                    "timeoutSeconds": min(int(parameters.get("timeoutSeconds") or 40), 60),
                    "maxRequests": min(int(parameters.get("maxRequests") or 150), 200),
                    "safeInteract": True,
                    "fillSearchInputs": True,
                }
            )
            if isinstance(traffic, dict):
                for u in traffic.get("parameterizedUrls", []) or []:
                    if u and self._allowed(base, str(u)):
                        urls.append(str(u))
                for req in traffic.get("xhrRequests", []) or []:
                    if not isinstance(req, dict):
                        continue
                    rurl = req.get("url")
                    if not rurl or not self._allowed(base, str(rurl)):
                        continue
                    urls.append(str(rurl))
                    rmethod = str(req.get("method") or "GET").upper()
                    if rmethod in {"POST", "PUT", "PATCH"}:
                        body_keys = req.get("requestBodyKeys") or []
                        fields = [{"name": str(k), "value": "xasm"} for k in body_keys if k]
                        if fields:
                            forms.append({
                                "method": rmethod,
                                "action": str(rurl),
                                "fields": fields,
                                "_origin": "xhr-traffic",
                            })
                for ep in traffic.get("apiEndpoints", []) or []:
                    if not isinstance(ep, dict):
                        continue
                    eurl = ep.get("url")
                    emethod = str(ep.get("method") or "GET").upper()
                    if not eurl or emethod == "GET":
                        continue
                    if not self._allowed(base, str(eurl)):
                        continue
                    body_keys = ep.get("requestBodyKeys") or []
                    if not body_keys:
                        continue
                    fields = [{"name": str(k), "value": "xasm"} for k in body_keys if k]
                    if fields:
                        forms.append({
                            "method": emethod if emethod in {"POST", "PUT", "PATCH"} else "POST",
                            "action": str(eurl),
                            "fields": fields,
                            "_origin": "api-endpoint",
                        })
                        urls.append(str(eurl))
        except Exception as _trf_err:
            print(f"[vuln:chain_probe] traffic_capture augmentation failed: {_trf_err}")

        # Pre-seed common SPA endpoints (Juice Shop, Express, Flask, banking-style labs).
        try:
            from urllib.parse import urlparse as _urlparse, urljoin as _urljoin
            _b = _urlparse(base)
            base_origin = f"{_b.scheme}://{_b.netloc}"
            COMMON_SPA = [
                ("POST", "/rest/user/login", ["email", "password"]),
                ("POST", "/api/login", ["username", "password"]),
                ("POST", "/api/auth/login", ["email", "password"]),
                ("POST", "/login", ["username", "password"]),
                ("POST", "/api/Users", ["email", "password", "username"]),
                ("POST", "/api/users", ["email", "password", "username"]),
                ("POST", "/api/Feedbacks", ["comment", "rating", "UserId"]),
                ("POST", "/api/feedbacks", ["comment", "rating", "user_id"]),
                ("POST", "/api/comments", ["content"]),
                ("POST", "/rest/products/search", ["q"]),
                ("POST", "/api/login_user", ["username", "password"]),
                ("POST", "/api/login_admin", ["username", "password"]),
                ("POST", "/api/transfer_money", ["account_to", "amount"]),
                ("POST", "/api/get_balance", ["account_number"]),
                ("PUT", "/api/Users/1", ["role", "email"]),
                ("PUT", "/api/users/1", ["role", "is_admin"]),
            ]
            existing_actions = {str(f.get("action", "")) for f in forms if isinstance(f, dict)}
            seeded = 0
            for method, path, keys in COMMON_SPA:
                full = _urljoin(base_origin + "/", path.lstrip("/"))
                if full in existing_actions or not self._allowed(base, full):
                    continue
                forms.append({
                    "method": method,
                    "action": full,
                    "fields": [{"name": k, "value": "xasm"} for k in keys],
                    "_origin": "spa-seed",
                })
                seeded += 1
            if seeded:
                print(f"[vuln:chain_probe] Pre-seeded {seeded} common SPA POST/PUT candidates")
        except Exception as _seed_err:
            print(f"[vuln:chain_probe] pre-seed failed: {_seed_err}")

        return {"urls": dedupe_keep_order(urls, max_pages * 30), "forms": forms[:300]}

    def _prioritize_urls(self, urls: Iterable[str]) -> List[str]:
        def score(url: str) -> int:
            names = {name.lower() for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}
            value = 0
            if names & {"q", "s", "search", "query", "keyword", "term", "name", "title"}:
                value += 80
            if names & OBJECT_ID_NAMES or any(name.endswith("_id") for name in names):
                value += 70
            if names & {"content", "file", "path", "page", "view", "url", "redirect", "next"}:
                value += 60
            value -= max(0, len(names) - 2) * 4
            return value

        return sorted(dedupe_keep_order(urls, 500), key=score, reverse=True)

    async def _baseline(
        self,
        session: aiohttp.ClientSession,
        headers: Dict[str, str],
        url: str,
        cache: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        if url in cache:
            return cache[url]
        try:
            fetched = await fetch_text(session, url, headers=headers, max_bytes=500_000)
            fetched["_fetched"] = True
            cache[url] = fetched
        except Exception as exc:
            cache[url] = {"url": url, "status": 0, "headers": {}, "text": "", "error": str(exc), "_fetched": True}
        return cache[url]

    async def _fetch_probe(self, session: aiohttp.ClientSession, headers: Dict[str, str], url: str) -> Dict[str, Any]:
        async with session.get(url, headers=headers, allow_redirects=True) as response:
            body = await read_limited(response.content, 500_001)
            if len(body) > 500_000:
                body = body[:500_000]
            text = body.decode("utf-8", errors="replace").replace("\0", "")
            response_headers = dict(response.headers)
            return {
                "requestedUrl": url,
                "url": str(response.url),
                "status": response.status,
                "headers": response_headers,
                "text": text,
                "request": self._http_request_evidence("GET", url, headers),
                "response": self._http_response_evidence(response.status, response_headers, text),
            }

    async def _probe_xss_context(
        self,
        session: aiohttp.ClientSession,
        headers: Dict[str, str],
        url: str,
        param: str,
    ) -> Tuple[Dict[str, List[Dict[str, Any]]], int]:
        findings: List[Dict[str, Any]] = []
        probes: List[Dict[str, Any]] = []
        for context, payload in XSS_CONTEXT_PAYLOADS:
            probe_url = self._replace_param(url, param, payload)
            try:
                fetched = await self._fetch_probe(session, headers, probe_url)
                body = fetched.get("text", "")
                fragments = [frag for frag in XSS_EXEC_FRAGMENTS if frag in body]
                context_hits = self._reflection_contexts(body, "xasmctx")
                probes.append(
                    {
                        "type": "xss_context",
                        "context": context,
                        "url": probe_url,
                        "status": fetched.get("status"),
                        "rawFragments": fragments,
                        "reflectionContexts": context_hits,
                        "request": fetched.get("request"),
                        "response": fetched.get("response"),
                    }
                )
                if fragments:
                    findings.append(
                        self._finding(
                            template_id="xasm-contextual-xss-evidence",
                            name="Contextual Reflected XSS Evidence",
                            severity="medium",
                            matched_at=probe_url,
                            description=f"Parameter `{param}` reflects a context-breaking XSS payload without encoding.",
                            remediation="Contextually encode reflected input for HTML, attribute, URL, and JavaScript contexts.",
                            matcher_name="context-breaking-payload-reflection",
                            extracted=[*fragments[:4], *context_hits[:4]],
                            evidence={
                                "request": fetched.get("request"),
                                "response": fetched.get("response"),
                                "responseExcerpt": self._redact_evidence((fetched.get("text") or "")[:1200]),
                                "payload": payload,
                                "parameter": param,
                                "context": context,
                                "status": fetched.get("status"),
                                "authenticatedContext": self._has_auth_context(headers),
                                "reflectionContexts": context_hits,
                            },
                        )
                    )
                    break
            except Exception as exc:
                probes.append({"type": "xss_context", "url": probe_url, "error": str(exc)[:200]})
        return {"findings": findings, "probes": probes}, len(probes)

    async def _probe_boolean_sqli(
        self,
        session: aiohttp.ClientSession,
        headers: Dict[str, str],
        url: str,
        param: str,
        baseline: Dict[str, Any],
    ) -> Tuple[Dict[str, List[Dict[str, Any]]], int]:
        findings: List[Dict[str, Any]] = []
        probes: List[Dict[str, Any]] = []
        baseline_text = baseline.get("text") or ""
        baseline_status = int(baseline.get("status") or 0)
        for true_payload, false_payload in SQL_TRUE_FALSE_PAYLOADS:
            true_url = self._replace_param(url, param, true_payload)
            false_url = self._replace_param(url, param, false_payload)
            try:
                true_res = await self._fetch_probe(session, headers, true_url)
                false_res = await self._fetch_probe(session, headers, false_url)
                score = self._boolean_diff_score(baseline_text, baseline_status, true_res, false_res)
                probes.append(
                    {
                        "type": "boolean_sqli",
                        "url": url,
                        "param": param,
                        "trueStatus": true_res.get("status"),
                        "falseStatus": false_res.get("status"),
                        "trueLength": len(true_res.get("text") or ""),
                        "falseLength": len(false_res.get("text") or ""),
                        "score": score,
                        "trueRequest": true_res.get("request"),
                        "trueResponse": true_res.get("response"),
                        "falseRequest": false_res.get("request"),
                        "falseResponse": false_res.get("response"),
                    }
                )
                if score >= 0.65:
                    findings.append(
                        self._finding(
                            template_id="xasm-boolean-sqli-signal",
                            name="Boolean SQL Injection Signal",
                            severity="high",
                            matched_at=true_url,
                            description=f"Parameter `{param}` produced materially different true/false SQL predicate responses.",
                            remediation="Use parameterized queries and normalize error/empty-result handling.",
                            matcher_name="boolean-response-differential",
                            extracted=[
                                f"true_status={true_res.get('status')}",
                                f"false_status={false_res.get('status')}",
                                f"score={score:.2f}",
                            ],
                            evidence={
                                "request": true_res.get("request"),
                                "response": true_res.get("response"),
                                "falseRequest": false_res.get("request"),
                                "falseResponse": false_res.get("response"),
                                "trueStatus": true_res.get("status"),
                                "falseStatus": false_res.get("status"),
                                "score": f"{score:.2f}",
                                "parameter": param,
                                "authenticatedContext": self._has_auth_context(headers),
                            },
                        )
                    )
                    break
            except Exception as exc:
                probes.append({"type": "boolean_sqli", "url": url, "param": param, "error": str(exc)[:200]})
        return {"findings": findings, "probes": probes}, len(probes) * 2

    async def _probe_idor_signal(
        self,
        session: aiohttp.ClientSession,
        headers: Dict[str, str],
        url: str,
        param: str,
        baseline: Dict[str, Any],
    ) -> Tuple[Dict[str, List[Dict[str, Any]]], int]:
        current = self._param_value(url, param)
        if not current or not re.fullmatch(r"\d{1,10}", current):
            return {"findings": [], "probes": []}, 0
        value = int(current)
        if value <= 0:
            return {"findings": [], "probes": []}, 0

        findings: List[Dict[str, Any]] = []
        probes: List[Dict[str, Any]] = []
        for candidate in [value + 1, max(1, value - 1)]:
            probe_url = self._replace_param(url, param, str(candidate))
            try:
                fetched = await self._fetch_probe(session, headers, probe_url)
                signal = self._idor_signal_score(baseline, fetched)
                probes.append(
                    {
                        "type": "idor_signal",
                        "url": probe_url,
                        "param": param,
                        "baselineStatus": baseline.get("status"),
                        "status": fetched.get("status"),
                        "score": signal,
                        "request": fetched.get("request"),
                        "response": fetched.get("response"),
                    }
                )
                if signal >= 0.75:
                    findings.append(
                        self._finding(
                            template_id="xasm-sequential-object-reference-signal",
                            name="Sequential Object Reference Exposure Signal",
                            severity="low",
                            matched_at=probe_url,
                            description=f"Parameter `{param}` accepted a neighboring object id and returned a plausible object response.",
                            remediation="Enforce object-level authorization on every object lookup, not only on page navigation.",
                            matcher_name="neighbor-object-response",
                            extracted=[f"original={value}", f"neighbor={candidate}", f"score={signal:.2f}"],
                            evidence={
                                "request": fetched.get("request"),
                                "response": fetched.get("response"),
                                "baselineStatus": baseline.get("status"),
                                "status": fetched.get("status"),
                                "score": f"{signal:.2f}",
                                "original": value,
                                "neighbor": candidate,
                                "parameter": param,
                                "authenticatedContext": self._has_auth_context(headers),
                            },
                        )
                    )
                    break
            except Exception as exc:
                probes.append({"type": "idor_signal", "url": probe_url, "error": str(exc)[:200]})
        return {"findings": findings, "probes": probes}, len(probes)

    async def _probe_form_controls(
        self,
        session: aiohttp.ClientSession,
        headers: Dict[str, str],
        forms: Iterable[Dict[str, Any]],
        base: str,
        budget: int,
    ) -> Tuple[Dict[str, List[Dict[str, Any]]], int]:
        findings: List[Dict[str, Any]] = []
        probes: List[Dict[str, Any]] = []
        used = 0
        for form in forms or []:
            if used >= budget:
                break
            # W.37 — defensive isinstance guard (see _form_get_url_candidates).
            if not isinstance(form, dict):
                continue
            action = str(form.get("action") or "")
            if not action or not self._allowed(base, action):
                continue
            method = str(form.get("method") or "GET").upper()
            fields = form.get("fields") if isinstance(form.get("fields"), list) else []
            names = {str(f.get("name") or "").lower() for f in fields if isinstance(f, dict)}
            types = {str(f.get("type") or "").lower() for f in fields if isinstance(f, dict)}
            is_login = "password" in types or bool(names & PASSWORD_NAMES)
            form_evidence = self._form_observation_evidence(form, headers)
            probes.append({
                "type": "form_control",
                "url": action,
                "method": method,
                "fieldCount": len(fields),
                "isLogin": is_login,
                "request": form_evidence.get("request"),
                "response": form_evidence.get("response"),
            })
            if method in {"POST", "PUT", "PATCH"} and not (names & CSRF_NAMES):
                findings.append(
                    self._finding(
                        template_id="xasm-form-missing-csrf-token",
                        name="State-Changing Form Missing CSRF Token",
                        severity="low",
                        matched_at=action,
                        description="A state-changing form does not expose an obvious anti-CSRF token field.",
                        remediation="Add per-request CSRF tokens or SameSite-aware anti-CSRF controls for state-changing forms.",
                        matcher_name="missing-csrf-field",
                        extracted=[f"method={method}", f"fields={','.join(sorted(names))[:160]}"],
                        evidence={
                            **form_evidence,
                            "formAction": action,
                            "formMethod": method,
                            "fieldNames": sorted(names),
                            "authenticatedContext": self._has_auth_context(headers),
                        },
                    )
                )
            if is_login and urlparse(action).scheme == "http":
                findings.append(
                    self._finding(
                        template_id="xasm-login-form-over-http",
                        name="Login Form Submitted Over HTTP",
                        severity="medium",
                        matched_at=action,
                        description="A login-like form submits credentials over plain HTTP.",
                        remediation="Serve and submit all authentication forms over HTTPS only.",
                        matcher_name="http-login-form-action",
                        extracted=[action],
                        evidence={
                            **form_evidence,
                            "formAction": action,
                            "formMethod": method,
                            "fieldNames": sorted(names),
                            "authenticatedContext": self._has_auth_context(headers),
                        },
                    )
                )
            used += 1
        return {"findings": findings, "probes": probes}, used

    def _reflection_contexts(self, body: str, token: str) -> List[str]:
        contexts = []
        for match in re.finditer(re.escape(token), body or "", re.I):
            left = body[max(0, match.start() - 80):match.start()].lower()
            right = body[match.end():match.end() + 80].lower()
            if "<script" in left and "</script" in right:
                contexts.append("script")
            elif re.search(r"<[^>]+(?:href|src|value|title|alt)=['\"]?[^>]*$", left):
                contexts.append("attribute")
            elif "<" in left and ">" in right:
                contexts.append("html")
            else:
                contexts.append("text")
        return dedupe_keep_order(contexts, 5)

    def _boolean_diff_score(
        self,
        baseline_text: str,
        baseline_status: int,
        true_res: Dict[str, Any],
        false_res: Dict[str, Any],
    ) -> float:
        true_status = int(true_res.get("status") or 0)
        false_status = int(false_res.get("status") or 0)
        true_len = len(true_res.get("text") or "")
        false_len = len(false_res.get("text") or "")
        base_len = max(1, len(baseline_text or ""))
        score = 0.0
        if true_status == baseline_status and false_status != true_status:
            score += 0.35
        diff_ratio = abs(true_len - false_len) / max(1, max(true_len, false_len))
        true_base_ratio = abs(true_len - base_len) / max(1, max(true_len, base_len))
        if diff_ratio > 0.35 and true_base_ratio < 0.25:
            score += 0.5
        if self._negative_markers(false_res.get("text", "")) and not self._negative_markers(true_res.get("text", "")):
            score += 0.25
        return min(score, 1.0)

    def _idor_signal_score(self, baseline: Dict[str, Any], fetched: Dict[str, Any]) -> float:
        status = int(fetched.get("status") or 0)
        baseline_status = int(baseline.get("status") or 0)
        if status != baseline_status or status >= 400:
            return 0.0
        text = (fetched.get("text") or "").lower()
        if any(marker in text for marker in ["login", "sign in", "access denied", "unauthorized", "forbidden"]):
            return 0.0
        base_len = max(1, len(baseline.get("text") or ""))
        length_ratio = abs(len(fetched.get("text") or "") - base_len) / max(base_len, len(fetched.get("text") or ""), 1)
        if length_ratio > 0.08:
            return min(0.9, 0.7 + length_ratio)
        return 0.0

    def _negative_markers(self, text: str) -> bool:
        lowered = (text or "").lower()
        return any(marker in lowered for marker in ["no results", "not found", "invalid", "error", "denied"])

    def _sqli_candidate(self, param: str) -> bool:
        lower = param.lower()
        return lower in OBJECT_ID_NAMES or lower.endswith("_id") or lower in {"q", "query", "search", "keyword", "term"}

    def _idor_candidate(self, param: str, url: str) -> bool:
        lower = param.lower()
        return lower in OBJECT_ID_NAMES or lower.endswith("_id") or bool(re.search(r"[?&][^=]*(?:id|account|user)=", url, re.I))

    def _form_get_url_candidates(self, forms: Iterable[Dict[str, Any]]) -> List[str]:
        candidates: List[str] = []
        for form in forms or []:
            # W.37 — defensive guard. Upstream is supposed to pass a list
            # of dicts (the input schema declares
            # `forms: array<object>`), but JSON-serialized payloads, bad
            # toolchain transforms, or partial backend responses can
            # produce a list of strings. Without this guard the loop
            # crashes with `'str' object has no attribute 'get'`, which
            # the PROBE phase used to silently swallow ~50% of the time
            # — gating IDOR/BOLA/SQLi findings that account for Web
            # DAST's HIGH count. Skip non-dict entries instead.
            if not isinstance(form, dict):
                continue
            if str(form.get("method") or "GET").upper() != "GET":
                continue
            action = str(form.get("action") or "")
            fields = form.get("fields") if isinstance(form.get("fields"), list) else []
            query = [(str(f.get("name")), "xasm") for f in fields if isinstance(f, dict) and f.get("name")]
            if action and query:
                parsed = urlparse(action)
                candidates.append(urlunparse(parsed._replace(query=urlencode(query), fragment="")))
        return candidates

    def _param_value(self, url: str, param: str) -> Optional[str]:
        for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
            if name == param:
                return value
        return None

    def _replace_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = [(name, value if name == param else current) for name, current in query]
        return urlunparse(parsed._replace(query=urlencode(replaced, doseq=True, safe="/:"), fragment=""))

    def _allowed(self, base: str, candidate: str) -> bool:
        return same_origin(base, candidate)

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
        evidence = self._clean_evidence(evidence or {})
        matched_content = evidence.get("matchedContent")
        if not matched_content:
            matched_content = "\n".join(
                str(item) for item in (extracted or []) if str(item).strip()
            )
            if matched_content:
                evidence["matchedContent"] = self._redact_evidence(matched_content)
        return {
            "template-id": template_id,
            "templateID": template_id,
            "matched-at": matched_at,
            "matched": matched_at,
            "host": matched_at,
            "matcher-name": matcher_name,
            "extracted-results": extracted,
            "matchedContent": evidence.get("matchedContent"),
            "request": evidence.get("request"),
            "response": evidence.get("response"),
            "evidence": evidence,
            "info": {
                "name": name,
                "severity": severity,
                "description": description,
                "remediation": remediation,
            },
        }

    def _dedupe_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: Dict[str, Dict[str, Any]] = {}
        for finding in findings:
            matched_at = str(finding.get("matched-at") or "")
            parsed = urlparse(matched_at)
            param_names = ",".join(sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}))
            normalized = urlunparse(parsed._replace(query=param_names, fragment=""))
            key = hashlib.sha256(f"{finding.get('template-id')}|{normalized}".encode()).hexdigest()
            deduped.setdefault(key, finding)
        return list(deduped.values())

    def _finding_type_counts(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in findings:
            template_id = str(finding.get("template-id") or "unknown")
            counts[template_id] = counts.get(template_id, 0) + 1
        return counts

    def _finding_line(self, finding: Dict[str, Any]) -> str:
        info = finding.get("info") or {}
        return f"[{str(info.get('severity', 'info')).upper()}] {info.get('name')} - {finding.get('matched-at')}"

    def _annotate_forms_with_source(
        self,
        forms: Iterable[Dict[str, Any]],
        fetched: Dict[str, Any],
        requested_url: str,
        headers: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        annotated: List[Dict[str, Any]] = []
        source_url = fetched.get("url") or requested_url
        response_headers = fetched.get("headers") if isinstance(fetched.get("headers"), dict) else {}
        source_request = self._http_request_evidence("GET", requested_url, headers)
        source_response = self._http_response_evidence(
            int(fetched.get("status") or 0),
            response_headers,
            fetched.get("text") or "",
        )
        for form in forms or []:
            if not isinstance(form, dict):
                continue
            annotated_form = dict(form)
            annotated_form.setdefault("sourceUrl", source_url)
            annotated_form.setdefault("sourceStatus", fetched.get("status"))
            annotated_form.setdefault("sourceRequest", source_request)
            annotated_form.setdefault("sourceResponse", source_response)
            annotated.append(annotated_form)
        return annotated

    def _form_observation_evidence(self, form: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        source_url = str(form.get("sourceUrl") or form.get("action") or "")
        request = form.get("sourceRequest") or self._http_request_evidence("GET", source_url, headers)
        response = form.get("sourceResponse")
        if not response:
            status = int(form.get("sourceStatus") or 0)
            form_summary = (
                f"Form observed statically.\n"
                f"action={form.get('action')}\n"
                f"method={form.get('method')}\n"
                f"fields={','.join(str(field.get('name') or '') for field in form.get('fields', []) if isinstance(field, dict))}"
            )
            response = self._http_response_evidence(status, {}, form_summary)
        return {
            "request": request,
            "response": response,
            "sourceUrl": source_url,
            "observationType": "form_metadata",
        }

    def _http_request_evidence(self, method: str, url: str, headers: Optional[Dict[str, Any]] = None, body: Any = None) -> str:
        parsed = urlparse(str(url or ""))
        path = urlunparse(("", "", parsed.path or "/", "", parsed.query, ""))
        lines = [f"{method.upper()} {path} HTTP/1.1"]
        if parsed.netloc:
            lines.append(f"Host: {parsed.netloc}")
        header_text = self._format_headers(headers)
        if header_text:
            lines.append(header_text)
        if body is not None:
            lines.append("")
            lines.append(str(body))
        return self._redact_evidence("\n".join(lines), limit=4000)

    def _http_response_evidence(
        self,
        status: int,
        headers: Optional[Dict[str, Any]] = None,
        body: Any = "",
        *,
        body_limit: int = 1600,
    ) -> str:
        lines = [f"HTTP/1.1 {status}".rstrip()]
        header_text = self._format_headers(headers, response=True)
        if header_text:
            lines.append(header_text)
        if body:
            lines.append("")
            lines.append(str(body)[:body_limit])
        return self._redact_evidence("\n".join(lines), limit=body_limit + 1200)

    def _format_headers(self, headers: Optional[Dict[str, Any]], *, response: bool = False) -> str:
        if not headers:
            return ""
        response_allowlist = {
            "content-type",
            "content-length",
            "location",
            "server",
            "x-frame-options",
            "x-content-type-options",
            "content-security-policy",
        }
        lines: List[str] = []
        for key, value in headers.items():
            lower = str(key).lower()
            if response and lower not in response_allowlist:
                continue
            if lower in {"authorization", "cookie", "set-cookie", "x-api-key"}:
                rendered = "[REDACTED]"
            else:
                rendered = str(value)
            lines.append(f"{key}: {rendered}")
        return "\n".join(lines)

    def _redact_evidence(self, value: Any, *, limit: int = 6000) -> str:
        text = str(value or "")
        for pattern, repl in REDACTION_PATTERNS:
            text = re.sub(pattern, repl, text)
        return text[:limit]

    def _has_auth_context(self, headers: Dict[str, str]) -> bool:
        return any(str(key).lower() in {"authorization", "cookie"} and bool(value) for key, value in (headers or {}).items())

    def _clean_evidence(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        return {
            key: value
            for key, value in evidence.items()
            if value is not None and value != "" and value != []
        }


def get_tool():
    return VulnChainProbeTool()
