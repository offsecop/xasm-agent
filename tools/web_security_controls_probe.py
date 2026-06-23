"""
Safe baseline web security-control checks for agentic DAST.

These checks complement vulnerability probes by flagging missing browser,
cookie, TLS, and form controls that materially affect exploitability.
"""

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    dedupe_keep_order,
    extract_html_map,
    fetch_text,
    normalize_url,
    parse_headers,
    redact_headers,
    same_origin,
)


CSRF_FIELD_NAMES = {"csrf", "_csrf", "csrf_token", "authenticity_token", "__requestverificationtoken"}
PASSWORD_FIELD_NAMES = {"pass", "passw", "password", "pwd"}


class WebSecurityControlsProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:security_controls_probe"

    @property
    def description(self) -> str:
        return "Checks missing browser hardening headers, weak cookies, mixed-content form actions, and state-changing forms without CSRF tokens."

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
                "maxPages": {"type": "integer", "default": 25},
                "maxUrls": {"type": "integer", "default": 80},
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
            "output_type": ["findings", "security_controls"],
            "chainable_after": ["surface:", "browser:", "katana:"],
            "chainable_before": ["nuclei:", "reporting:"],
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
        max_pages = max(1, min(int(parameters.get("maxPages") or 25), 80))
        max_urls = max(1, min(int(parameters.get("maxUrls") or 80), 200))
        headers = parse_headers(parameters)
        forms = parameters.get("forms") if isinstance(parameters.get("forms"), list) else []
        pages: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        probes: List[Dict[str, Any]] = []
        agent = parameters.get("_agent")

        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=25),
        ) as session:
            queue = dedupe_keep_order([u for u in urls if self._allowed(base, u)], max_urls)
            if bool(parameters.get("discoverFromTarget", True)):
                queue.extend([urljoin(base, "/robots.txt"), urljoin(base, "/sitemap.xml")])
            queue = dedupe_keep_order(queue, max_urls)

            visited = set()
            cursor = 0
            while cursor < len(queue) and len(visited) < max_pages:
                url = queue[cursor]
                cursor += 1
                if url in visited or not self._allowed(base, url):
                    continue
                try:
                    fetched = await fetch_text(session, url, headers=headers, max_bytes=700_000)
                except Exception:
                    continue
                visited.add(url)
                fetched_url = fetched.get("url") or url
                mapped = extract_html_map(fetched.get("text", ""), fetched_url)
                queue.extend([u for u in mapped.get("links", []) if self._allowed(base, u)])
                for form in mapped.get("forms", []):
                    if isinstance(form, dict):
                        form["sourcePage"] = fetched_url
                        form["sourceStatus"] = fetched.get("status")
                        form["sourceHeaders"] = fetched.get("headers") or {}
                forms.extend(mapped.get("forms", []))
                page = {
                    "url": fetched_url,
                    "status": fetched.get("status"),
                    "headers": fetched.get("headers", {}),
                    "title": mapped.get("title"),
                    "request": _format_request("GET", fetched_url, headers),
                    "response": _format_response(fetched.get("status"), fetched.get("headers") or {}),
                }
                pages.append(page)
                created = self._header_findings(page)
                findings.extend(created)
                probes.append(
                    {
                        "type": "security_headers",
                        "url": page["url"],
                        "status": page["status"],
                        "missing": [f["template-id"] for f in created],
                    }
                )
                cookie_findings = self._cookie_findings(page)
                findings.extend(cookie_findings)
                if agent:
                    agent.report_progress("Checking web security controls", url, len(visited), max_pages)

        form_findings, form_probes = self._form_findings(forms, base)
        findings.extend(form_findings)
        probes.extend(form_probes)
        findings = self._dedupe_findings(findings)

        return {
            "success": True,
            "target": base,
            "pages": pages[:200],
            "forms": self._dedupe_forms(forms)[:200],
            "probes": probes[:500],
            "findings": findings,
            "total_findings": len(findings),
            "findings_delivered": len(findings),
            "tool": "web:security_controls_probe",
            "rawOutput": "\n".join(self._finding_line(f) for f in findings),
            "summary": {
                "pagesChecked": len(pages),
                "formsChecked": len(self._dedupe_forms(forms)),
                "findings": len(findings),
                "findingTypes": self._finding_type_counts(findings),
            },
        }

    def _header_findings(self, page: Dict[str, Any]) -> List[Dict[str, Any]]:
        url = str(page.get("url") or "")
        headers = {str(k).lower(): str(v) for k, v in (page.get("headers") or {}).items()}
        parsed = urlparse(url)
        findings: List[Dict[str, Any]] = []
        evidence = _page_evidence(page, "response_headers")

        if parsed.scheme == "https" and "strict-transport-security" not in headers:
            findings.append(
                self._finding(
                    "xasm-missing-hsts",
                    "Missing HTTP Strict Transport Security",
                    "low",
                    url,
                    "HTTPS response does not include Strict-Transport-Security.",
                    "Set HSTS with an appropriate max-age after confirming all subresources support HTTPS.",
                    "missing-hsts",
                    [],
                    evidence,
                )
            )
        if "content-security-policy" not in headers:
            findings.append(
                self._finding(
                    "xasm-missing-csp",
                    "Missing Content Security Policy",
                    "low",
                    url,
                    "Response does not include a Content-Security-Policy header.",
                    "Add a restrictive CSP to reduce XSS impact and control script/style sources.",
                    "missing-csp",
                    [],
                    evidence,
                )
            )
        if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", "").lower():
            findings.append(
                self._finding(
                    "xasm-missing-clickjacking-protection",
                    "Missing Clickjacking Protection",
                    "low",
                    url,
                    "Response lacks X-Frame-Options and CSP frame-ancestors.",
                    "Set CSP frame-ancestors or X-Frame-Options to restrict framing.",
                    "missing-frame-protection",
                    [],
                    evidence,
                )
            )
        if "x-content-type-options" not in headers:
            findings.append(
                self._finding(
                    "xasm-missing-content-type-options",
                    "Missing X-Content-Type-Options",
                    "info",
                    url,
                    "Response lacks X-Content-Type-Options: nosniff.",
                    "Set X-Content-Type-Options: nosniff on HTML and script/style responses.",
                    "missing-nosniff",
                    [],
                    evidence,
                )
            )
        return findings

    def _cookie_findings(self, page: Dict[str, Any]) -> List[Dict[str, Any]]:
        url = str(page.get("url") or "")
        headers = page.get("headers") or {}
        raw = headers.get("Set-Cookie")
        if not raw:
            return []
        cookies = raw if isinstance(raw, list) else [raw]
        findings: List[Dict[str, Any]] = []
        evidence = _page_evidence(page, "set_cookie_flags")
        for cookie in cookies:
            cookie_text = str(cookie)
            name = cookie_text.split("=", 1)[0].strip()
            lower = cookie_text.lower()
            missing = []
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if urlparse(url).scheme == "https" and "secure" not in lower:
                missing.append("Secure")
            if "samesite" not in lower:
                missing.append("SameSite")
            if missing:
                findings.append(
                    self._finding(
                        "xasm-weak-cookie-flags",
                        "Cookie Missing Security Flags",
                        "low",
                        url,
                        f"Cookie `{name}` is missing recommended flags: {', '.join(missing)}.",
                        "Set HttpOnly, Secure, and SameSite where compatible with the application flow.",
                        "weak-cookie-flags",
                        [f"cookie={name}", f"missing={','.join(missing)}"],
                        evidence,
                    )
                )
        return findings

    def _form_findings(self, forms: Iterable[Dict[str, Any]], base: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        findings: List[Dict[str, Any]] = []
        probes: List[Dict[str, Any]] = []
        for form in self._dedupe_forms(forms):
            # W.37 — defensive isinstance guard (dedupe_forms is already
            # guarded, but a second site of attack means a second guard).
            if not isinstance(form, dict):
                continue
            action = str(form.get("action") or "")
            if not action or not self._allowed(base, action):
                continue
            method = str(form.get("method") or "GET").upper()
            fields = form.get("fields") if isinstance(form.get("fields"), list) else []
            names = {str(f.get("name") or "").lower() for f in fields if isinstance(f, dict)}
            types = {str(f.get("type") or "").lower() for f in fields if isinstance(f, dict)}
            is_password = "password" in types or bool(names & PASSWORD_FIELD_NAMES)
            probes.append({"type": "form_controls", "url": action, "method": method, "fields": sorted(names), "passwordForm": is_password})
            evidence = _form_evidence(form, action, method, sorted(names))
            if method in {"POST", "PUT", "PATCH"} and not (names & CSRF_FIELD_NAMES):
                findings.append(
                    self._finding(
                        "xasm-form-missing-csrf-token",
                        "State-Changing Form Missing CSRF Token",
                        "low",
                        action,
                        "A state-changing form has no obvious anti-CSRF token field.",
                        "Add per-request CSRF tokens or a robust SameSite-based anti-CSRF design.",
                        "missing-csrf-field",
                        [f"method={method}", f"fields={','.join(sorted(names))[:160]}"],
                        evidence,
                    )
                )
            if is_password and urlparse(action).scheme == "http":
                findings.append(
                    self._finding(
                        "xasm-login-form-over-http",
                        "Login Form Submitted Over HTTP",
                        "medium",
                        action,
                        "A password form submits credentials over plain HTTP.",
                        "Serve login pages and submit credentials over HTTPS only.",
                        "http-password-form",
                        [action],
                        evidence,
                    )
                )
        return findings, probes

    def _dedupe_forms(self, forms: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        output = []
        for form in forms or []:
            # W.37 — defensive isinstance guard.
            if not isinstance(form, dict):
                continue
            fields = form.get("fields") if isinstance(form.get("fields"), list) else []
            sig = ",".join(sorted(str(f.get("name") or "") for f in fields if isinstance(f, dict)))
            key = f"{form.get('method')}|{form.get('action')}|{sig}"
            if key in seen:
                continue
            seen.add(key)
            output.append(form)
        return output

    def _allowed(self, base: str, candidate: str) -> bool:
        return same_origin(base, candidate)

    def _finding(
        self,
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
        cleaned_evidence = _clean_evidence(evidence or {})
        finding = {
            "template-id": template_id,
            "templateID": template_id,
            "matched-at": matched_at,
            "matched": matched_at,
            "host": matched_at,
            "matcher-name": matcher_name,
            "extracted-results": extracted,
            "info": {
                "name": name,
                "severity": severity,
                "description": description,
                "remediation": remediation,
            },
        }
        if cleaned_evidence:
            finding["evidence"] = cleaned_evidence
            if cleaned_evidence.get("request"):
                finding["request"] = cleaned_evidence["request"]
            if cleaned_evidence.get("response"):
                finding["response"] = cleaned_evidence["response"]
            matched_content = cleaned_evidence.get("matchedContent") or "\n".join(str(item) for item in extracted if item)
            if matched_content:
                finding["matched-content"] = matched_content
                finding["matchedContent"] = matched_content
        return finding

    def _dedupe_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        origin_scoped_templates = {
            "xasm-missing-hsts",
            "xasm-missing-csp",
            "xasm-missing-clickjacking-protection",
            "xasm-missing-content-type-options",
        }
        seen = set()
        output = []
        for finding in findings:
            template_id = str(finding.get("template-id") or "")
            matched_at = str(finding.get("matched-at") or "")
            if template_id in origin_scoped_templates:
                parsed = urlparse(matched_at)
                scope = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else matched_at
            else:
                scope = matched_at
            key = f"{template_id}|{scope}"
            if key in seen:
                continue
            seen.add(key)
            output.append(finding)
        return output

    def _finding_type_counts(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in findings:
            template_id = str(finding.get("template-id") or "unknown")
            counts[template_id] = counts.get(template_id, 0) + 1
        return counts

    def _finding_line(self, finding: Dict[str, Any]) -> str:
        info = finding.get("info") or {}
        return f"[{str(info.get('severity', 'info')).upper()}] {info.get('name')} - {finding.get('matched-at')}"


def _page_evidence(page: Dict[str, Any], matcher: str) -> Dict[str, Any]:
    request = str(page.get("request") or "")
    response = str(page.get("response") or "")
    status = page.get("status")
    matched = f"matcher={matcher}\nstatus={status}\nurl={page.get('url')}"
    return _clean_evidence(
        {
            "request": request,
            "response": response,
            "matchedContent": matched,
            "status": status,
            "url": page.get("url"),
            "evidenceType": "http_response_headers",
        }
    )


def _form_evidence(form: Dict[str, Any], action: str, method: str, fields: List[str]) -> Dict[str, Any]:
    source_page = str(form.get("sourcePage") or action or "")
    request = _format_request("GET", source_page, {})
    response = _format_response(form.get("sourceStatus"), form.get("sourceHeaders") or {})
    matched = "\n".join(
        [
            f"observed_form_method={method}",
            f"observed_form_action={action}",
            f"observed_form_fields={','.join(fields)[:240]}",
        ]
    )
    return _clean_evidence(
        {
            "request": request,
            "response": response,
            "matchedContent": matched,
            "sourcePage": source_page,
            "formAction": action,
            "formMethod": method,
            "formFields": fields,
            "evidenceType": "observed_form_markup",
        }
    )


def _format_request(method: str, url: str, headers: Dict[str, str]) -> str:
    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        host = parsed.netloc
    except Exception:
        path = url or "/"
        host = ""
    lines = [f"{str(method or 'GET').upper()} {path} HTTP/1.1"]
    if host:
        lines.append(f"Host: {host}")
    redacted = redact_headers(headers or {})
    for key, value in redacted.items():
        if key.lower() == "host":
            continue
        lines.append(f"{key}: {_redact_text(str(value))}")
    return "\n".join(lines)


def _format_response(status: Any, headers: Dict[str, Any]) -> str:
    reason = "OK" if int(status or 0) and int(status or 0) < 400 else ""
    lines = [f"HTTP/1.1 {int(status or 0)} {reason}".rstrip()]
    redacted = redact_headers({str(k): str(v) for k, v in (headers or {}).items()})
    for key, value in redacted.items():
        lines.append(f"{key}: {_redact_text(str(value))}")
    return "\n".join(lines[:80])


def _clean_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    cleaned: Dict[str, Any] = {}
    for key, value in (evidence or {}).items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, str):
            cleaned[key] = _redact_text(value)
        elif isinstance(value, dict):
            cleaned[key] = {str(k): _redact_text(str(v)) for k, v in value.items()}
        elif isinstance(value, list):
            cleaned[key] = [_redact_text(str(item)) for item in value]
        else:
            cleaned[key] = value
    return cleaned


def _redact_text(value: str) -> str:
    text = str(value or "")
    text = re.sub(r"(?i)(authorization|cookie|set-cookie|x-api-key)\s*:\s*[^\n\r]+", r"\1: [REDACTED]", text)
    text = re.sub(r"(?i)(session|token|secret|password|passwd|pwd)=([^;,\s]+)", r"\1=[REDACTED]", text)
    return text


def get_tool():
    return WebSecurityControlsProbeTool()
