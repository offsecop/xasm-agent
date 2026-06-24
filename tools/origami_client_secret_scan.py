"""
Lightweight Origami-style client-side secret scanner.

The full Origami browser DAST tool is intentionally heavy. This tool implements
the specific DAST capability requested for agentic runs: inspect client-side
HTML/JavaScript for exposed secrets and validate Google API keys with a safe,
read-only Google discovery endpoint.
"""

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    extract_html_map,
    fetch_text,
    normalize_url,
    parse_headers,
    same_origin,
)


DEFAULT_MAX_URLS = 12
DEFAULT_MAX_SCRIPTS = 40
DEFAULT_MAX_BYTES = 2_000_000
DEFAULT_GOOGLE_KEY_TEST_LIMIT = 20


SECRET_PATTERNS = [
    {
        "type": "google_api_key",
        "label": "Google API key",
        "regex": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "severity": "medium",
        "tags": ["google-api-key", "cloud", "client-secret"],
    },
    {
        "type": "google_oauth_client_id",
        "label": "Google OAuth client ID",
        "regex": re.compile(r"\b[0-9]{6,}-[a-z0-9_-]{20,}\.apps\.googleusercontent\.com\b", re.I),
        "severity": "info",
        "tags": ["google-oauth", "client-identifier"],
    },
    {
        "type": "aws_access_key",
        "label": "AWS access key ID",
        "regex": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "severity": "high",
        "tags": ["aws", "access-key", "client-secret"],
    },
    {
        "type": "github_token",
        "label": "GitHub token",
        "regex": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,255}\b"),
        "severity": "high",
        "tags": ["github", "token", "client-secret"],
    },
    {
        "type": "slack_token",
        "label": "Slack token",
        "regex": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,120}\b"),
        "severity": "high",
        "tags": ["slack", "token", "client-secret"],
    },
    {
        "type": "jwt",
        "label": "JWT-like token",
        "regex": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "severity": "medium",
        "tags": ["jwt", "token", "client-secret"],
    },
]


class OrigamiClientSecretScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "origami:client_secret_scan"

    @property
    def description(self) -> str:
        return (
            "Lightweight Origami capability for DAST: scans client-side HTML/JS "
            "for exposed secrets and safely tests Google API keys."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "description": "Scan client-side assets for exposed secrets and validate Google API keys.",
            "properties": {
                "target": {"type": "string", "description": "Base page URL to inspect."},
                "url": {"type": "string", "description": "Alias for target."},
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Discovered page/script URLs from recon tools.",
                },
                "scripts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Explicit JavaScript URLs to scan.",
                },
                "sameOriginOnly": {
                    "type": "boolean",
                    "default": True,
                    "description": "Only fetch assets from the target origin unless explicitly disabled.",
                },
                "includeInlineScripts": {
                    "type": "boolean",
                    "default": True,
                    "description": "Scan inline script blocks from fetched pages.",
                },
                "testGoogleApiKeys": {
                    "type": "boolean",
                    "default": True,
                    "description": "Safely test Google API keys with a read-only discovery endpoint.",
                },
                "maxUrls": {"type": "integer", "default": DEFAULT_MAX_URLS},
                "maxScripts": {"type": "integer", "default": DEFAULT_MAX_SCRIPTS},
                "maxBytesPerAsset": {"type": "integer", "default": DEFAULT_MAX_BYTES},
                "maxGoogleApiKeysToTest": {"type": "integer", "default": DEFAULT_GOOGLE_KEY_TEST_LIMIT},
                "timeoutSeconds": {"type": "integer", "default": 90},
                "cookie": {"type": "string", "x-hidden": True},
                "authCookies": {"type": "string", "x-hidden": True},
                "headers": {"type": "object"},
                "authHeaders": {"type": "object"},
            },
        }

    @property
    def metadata(self):
        return {
            "category": "sca-web",
            "phase": 3,
            "domain": ["web", "javascript", "secrets", "origami"],
            "input_type": ["url", "urls", "scripts"],
            "output_type": ["findings", "secrets", "googleApiKeyTests"],
            "chainable_after": ["browser:", "katana:", "js:", "sca:"],
            "chainable_before": ["cve:", "nuclei:", "curl:", "param:", "exploit:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        target = normalize_url(parameters.get("target") or parameters.get("url") or "")
        max_urls = _bounded_int(parameters.get("maxUrls"), DEFAULT_MAX_URLS, 1, 60)
        max_scripts = _bounded_int(parameters.get("maxScripts"), DEFAULT_MAX_SCRIPTS, 1, 120)
        max_bytes = _bounded_int(parameters.get("maxBytesPerAsset"), DEFAULT_MAX_BYTES, 50_000, 5_000_000)
        timeout_seconds = _bounded_int(parameters.get("timeoutSeconds"), 90, 10, 300)
        max_google_tests = _bounded_int(
            parameters.get("maxGoogleApiKeysToTest"),
            DEFAULT_GOOGLE_KEY_TEST_LIMIT,
            0,
            100,
        )
        same_origin_only = bool(parameters.get("sameOriginOnly", True))
        include_inline_scripts = bool(parameters.get("includeInlineScripts", True))
        test_google_keys = bool(parameters.get("testGoogleApiKeys", True))
        agent = parameters.get("_agent")

        if not target and not parameters.get("urls") and not parameters.get("scripts"):
            return {
                "success": False,
                "error": "Either target, urls, or scripts parameter is required",
                "findings": [],
                "secrets": [],
            }

        headers = parse_headers(parameters)
        urls = _coerce_string_list(parameters.get("urls"))
        explicit_scripts = _coerce_string_list(parameters.get("scripts"))
        if not explicit_scripts:
            explicit_scripts = [url for url in urls if _looks_like_script_url(url)]

        if agent:
            agent.report_progress("Scanning client-side assets for secrets", target or "provided URLs", 0, None)

        connector = aiohttp.TCPConnector(ssl=False)
        page_assets: List[Dict[str, Any]] = []
        script_urls: List[str] = []
        inline_assets: List[Dict[str, Any]] = []
        fetched_scripts: List[Dict[str, Any]] = []

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout_seconds, connect=10, sock_read=30),
        ) as session:
            page_candidates = _candidate_pages(target, urls, max_urls)
            for page_url in page_candidates:
                if target and same_origin_only and not same_origin(target, page_url):
                    continue
                try:
                    fetched = await fetch_text(session, page_url, headers=headers, max_bytes=max_bytes)
                except Exception as exc:
                    page_assets.append({"url": page_url, "error": str(exc), "text": ""})
                    continue
                text = fetched.get("text") or ""
                page_asset = {
                    "url": page_url,
                    "finalUrl": fetched.get("url") or page_url,
                    "status": fetched.get("status"),
                    "headers": fetched.get("headers") or {},
                    "text": text,
                    "bytes": len(text.encode("utf-8", errors="ignore")),
                    "truncated": bool(fetched.get("truncated")),
                    "assetType": "html",
                }
                page_assets.append(page_asset)
                if int(fetched.get("status") or 0) < 400:
                    mapped = extract_html_map(text, fetched.get("url") or page_url)
                    script_urls.extend(mapped.get("scripts") or [])
                    if include_inline_scripts:
                        inline_assets.extend(_extract_inline_script_assets(text, fetched.get("url") or page_url))

            script_candidates = _dedupe(
                [
                    _resolve_url(target, value)
                    for value in [*explicit_scripts, *script_urls]
                    if value
                ],
                max_scripts,
            )
            if target and same_origin_only:
                script_candidates = [url for url in script_candidates if same_origin(target, url)]

            for index, script_url in enumerate(script_candidates):
                try:
                    fetched = await fetch_text(session, script_url, headers=headers, max_bytes=max_bytes)
                    fetched_scripts.append(
                        {
                            "url": script_url,
                            "finalUrl": fetched.get("url") or script_url,
                            "status": fetched.get("status"),
                            "headers": fetched.get("headers") or {},
                            "text": fetched.get("text") or "",
                            "bytes": len((fetched.get("text") or "").encode("utf-8", errors="ignore")),
                            "truncated": bool(fetched.get("truncated")),
                            "assetType": "javascript",
                        }
                    )
                    if agent:
                        agent.report_progress(
                            "Scanning client-side scripts for secrets",
                            script_url,
                            index + 1,
                            len(script_candidates),
                        )
                except Exception as exc:
                    fetched_scripts.append({"url": script_url, "error": str(exc), "text": "", "assetType": "javascript"})

            assets_for_scan = [*page_assets, *inline_assets, *fetched_scripts]
            secret_matches = _scan_assets_for_secrets(assets_for_scan)
            google_matches = [m for m in secret_matches if m["type"] == "google_api_key"]
            google_tests: List[Dict[str, Any]] = []
            if test_google_keys and max_google_tests > 0:
                for match in _unique_secret_matches(google_matches, max_google_tests):
                    google_tests.append(await _test_google_api_key(session, match["rawValue"], headers=headers))

        google_test_by_hash = {test["fingerprint"]: test for test in google_tests}
        findings = [
            _build_secret_finding(match, google_test_by_hash.get(match["fingerprint"]))
            for match in secret_matches
        ]
        findings = _dedupe_findings(findings)
        safe_secrets = [_safe_secret_record(match, google_test_by_hash.get(match["fingerprint"])) for match in secret_matches]
        safe_secrets = _dedupe_secret_records(safe_secrets)

        summary = {
            "pagesScanned": len([asset for asset in page_assets if asset.get("text")]),
            "scriptsScanned": len([asset for asset in fetched_scripts if asset.get("text")]),
            "inlineScriptsScanned": len(inline_assets),
            "secretsFound": len(safe_secrets),
            "findings": len(findings),
            "googleApiKeysTested": len(google_tests),
            "acceptedGoogleApiKeys": len([test for test in google_tests if test.get("status") == "accepted"]),
        }

        if agent:
            agent.append_output(
                "[origami:client_secret_scan] "
                f"pages={summary['pagesScanned']} scripts={summary['scriptsScanned']} "
                f"secrets={summary['secretsFound']} googleTests={summary['googleApiKeysTested']} "
                f"findings={summary['findings']}"
            )

        return {
            "success": True,
            "target": target,
            "assetsScanned": _safe_asset_summary([*page_assets, *inline_assets, *fetched_scripts]),
            "secrets": safe_secrets[:500],
            "googleApiKeyTests": google_tests[:200],
            "findings": findings[:500],
            "summary": summary,
            "scanner": "origami-client-secret-scan",
        }


def _candidate_pages(target: str, urls: List[str], limit: int) -> List[str]:
    pages = []
    if target:
        pages.append(target)
    for value in urls:
        resolved = _resolve_url(target, value)
        if resolved and not _looks_like_script_url(resolved):
            pages.append(resolved)
    return _dedupe(pages, limit)


def _resolve_url(target: str, value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if target:
        return urljoin(target, value)
    return normalize_url(value)


def _extract_inline_script_assets(html: str, page_url: str) -> List[Dict[str, Any]]:
    assets = []
    for index, match in enumerate(re.finditer(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>", html, re.I | re.S), 1):
        text = match.group(1) or ""
        if not text.strip():
            continue
        assets.append(
            {
                "url": f"{page_url}#inline-script-{index}",
                "finalUrl": f"{page_url}#inline-script-{index}",
                "status": 200,
                "headers": {"Content-Type": "text/html; inline script"},
                "text": text,
                "bytes": len(text.encode("utf-8", errors="ignore")),
                "truncated": False,
                "assetType": "inline-script",
            }
        )
    return assets


def _scan_assets_for_secrets(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    for asset in assets:
        text = asset.get("text") or ""
        if not text:
            continue
        for pattern in SECRET_PATTERNS:
            for match in pattern["regex"].finditer(text):
                raw = match.group(0)
                matches.append(
                    {
                        "type": pattern["type"],
                        "label": pattern["label"],
                        "severity": pattern["severity"],
                        "tags": pattern["tags"],
                        "rawValue": raw,
                        "maskedValue": _mask_secret(raw),
                        "fingerprint": _secret_fingerprint(raw),
                        "asset": asset,
                        "start": match.start(),
                        "end": match.end(),
                        "context": _redact_secrets(text[max(0, match.start() - 220): match.end() + 220]),
                    }
                )
    return matches


async def _test_google_api_key(
    session: aiohttp.ClientSession,
    key: str,
    *,
    headers: Dict[str, str],
) -> Dict[str, Any]:
    fingerprint = _secret_fingerprint(key)
    url = f"https://www.googleapis.com/discovery/v1/apis?key={key}"
    redacted_url = url.replace(key, "[REDACTED_GOOGLE_API_KEY]")
    request = (
        "GET /discovery/v1/apis?key=[REDACTED_GOOGLE_API_KEY] HTTP/1.1\n"
        "Host: www.googleapis.com\n"
        "User-Agent: xASM-AgenticExplorer/1.0"
    )
    try:
        fetched = await fetch_text(session, url, headers=_google_test_headers(headers), max_bytes=12_000)
        status_code = int(fetched.get("status") or 0)
        text = fetched.get("text") or ""
        status, reason = _classify_google_key_response(status_code, text)
        return {
            "fingerprint": fingerprint,
            "maskedValue": _mask_secret(key),
            "status": status,
            "httpStatus": status_code,
            "reason": reason,
            "endpoint": redacted_url,
            "request": request,
            "response": _format_google_response(status_code, fetched.get("headers") or {}, text),
        }
    except Exception as exc:
        return {
            "fingerprint": fingerprint,
            "maskedValue": _mask_secret(key),
            "status": "unknown",
            "httpStatus": None,
            "reason": f"Google API key test failed: {exc}",
            "endpoint": redacted_url,
            "request": request,
            "response": "",
        }


def _google_test_headers(headers: Dict[str, str]) -> Dict[str, str]:
    # Never forward target authentication material to a third-party validation endpoint.
    return {
        "User-Agent": str((headers or {}).get("User-Agent") or "xASM-AgenticExplorer/1.0"),
        "Accept": "application/json,*/*;q=0.8",
    }


def _classify_google_key_response(status_code: int, text: str) -> Tuple[str, str]:
    lower = (text or "").lower()
    if status_code == 200:
        return "accepted", "Key was accepted by the Google Discovery API."
    if status_code == 400 and ("api key not valid" in lower or "bad request" in lower):
        return "invalid", "Google rejected the key as invalid."
    if status_code == 403:
        if "api_key_service_blocked" in lower or "api key service blocked" in lower:
            return "restricted", "Google key appears restricted for this API/service."
        if "access_not_configured" in lower or "api has not been used" in lower:
            return "restricted", "Google key is valid-looking but this API is not enabled."
        return "restricted", "Google returned 403; key may be restricted."
    if status_code in {401, 404}:
        return "invalid", "Google rejected the key."
    return "unknown", f"Google returned HTTP {status_code}."


def _build_secret_finding(match: Dict[str, Any], google_test: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    asset = match["asset"]
    asset_url = asset.get("finalUrl") or asset.get("url") or ""
    severity = _severity_for_match(match, google_test)
    template_id = _safe_template_id(f"origami-client-secret-{match['type']}-{match['fingerprint']}")
    google_suffix = ""
    if google_test:
        google_suffix = f" ({google_test.get('status', 'unknown')})"
    title = f"Client-side secret exposed: {match['label']}{google_suffix}"
    description = (
        f"A {match['label']} pattern was found in a client-side asset. "
        "Secrets exposed in HTML or JavaScript can be harvested by unauthenticated users. "
    )
    if google_test:
        description += f"Google API key auto-test result: {google_test.get('status')} - {google_test.get('reason')}"
    recommendation = (
        "Remove the value from client-side code, rotate it if it grants access, and move privileged calls "
        "behind a server-side endpoint. For Google API keys, enforce API, HTTP referrer, and quota restrictions."
    )
    matched_content = "\n".join(
        [
            f"type={match['type']}",
            f"value={match['maskedValue']}",
            f"fingerprint={match['fingerprint']}",
            *( [f"google_test={google_test.get('status')} http={google_test.get('httpStatus')}"] if google_test else [] ),
            match["context"],
        ]
    )
    request = _request_line(asset_url)
    response = _format_asset_response(asset, match["context"])
    evidence: Dict[str, Any] = {
        "secretType": match["type"],
        "maskedValue": match["maskedValue"],
        "fingerprint": match["fingerprint"],
        "assetUrl": asset_url,
        "assetType": asset.get("assetType"),
        "assetStatus": asset.get("status"),
        "scanner": "origami-client-secret-scan",
        "request": request,
        "response": response,
        "matchedContent": matched_content,
    }
    if google_test:
        evidence["googleApiKeyTest"] = {
            "status": google_test.get("status"),
            "httpStatus": google_test.get("httpStatus"),
            "reason": google_test.get("reason"),
            "endpoint": google_test.get("endpoint"),
            "request": google_test.get("request"),
            "response": google_test.get("response"),
        }

    return {
        "template-id": template_id,
        "templateID": template_id,
        "host": asset_url,
        "matched": asset_url,
        "matched-at": asset_url,
        "extracted-results": [match["type"], match["maskedValue"], match["fingerprint"]],
        "matcher-name": "origami-client-secret",
        "info": {
            "name": title,
            "description": description,
            "severity": severity.lower(),
            "remediation": recommendation,
            "reference": ["https://cloud.google.com/docs/authentication/api-keys"],
            "classification": {"cwe-id": ["CWE-798"]},
            "tags": ["dast", "origami", "client-side", "secret", *match["tags"]],
        },
        "request": request,
        "response": response,
        "matched-content": matched_content,
        "matchedContent": matched_content,
        "evidence": evidence,
    }


def _severity_for_match(match: Dict[str, Any], google_test: Optional[Dict[str, Any]]) -> str:
    if match["type"] == "google_api_key" and google_test:
        if google_test.get("status") == "accepted":
            return "medium"
        if google_test.get("status") in {"restricted", "unknown"}:
            return "low"
        return "info"
    return str(match.get("severity") or "low")


def _safe_secret_record(match: Dict[str, Any], google_test: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    asset = match["asset"]
    record = {
        "type": match["type"],
        "label": match["label"],
        "maskedValue": match["maskedValue"],
        "fingerprint": match["fingerprint"],
        "assetUrl": asset.get("finalUrl") or asset.get("url"),
        "assetType": asset.get("assetType"),
        "severity": _severity_for_match(match, google_test).upper(),
        "context": match["context"],
    }
    if google_test:
        record["googleApiKeyTest"] = {
            "status": google_test.get("status"),
            "httpStatus": google_test.get("httpStatus"),
            "reason": google_test.get("reason"),
        }
    return record


def _request_line(url: str) -> str:
    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return f"GET {path} HTTP/1.1\nHost: {parsed.netloc}\nUser-Agent: xASM-AgenticExplorer/1.0"
    except Exception:
        return f"GET {url} HTTP/1.1"


def _format_asset_response(asset: Dict[str, Any], excerpt: str) -> str:
    status = int(asset.get("status") or 0)
    lines = [f"HTTP/1.1 {status}".rstrip()]
    for key, value in (asset.get("headers") or {}).items():
        lower = str(key).lower()
        if lower in {"authorization", "cookie", "set-cookie", "x-api-key"}:
            lines.append(f"{key}: [REDACTED]")
        else:
            lines.append(f"{key}: {value}")
    if excerpt:
        lines.append("")
        lines.append(excerpt)
    return "\n".join(lines[:90])


def _format_google_response(status_code: int, headers: Dict[str, Any], text: str) -> str:
    lines = [f"HTTP/1.1 {status_code}".rstrip()]
    for key, value in headers.items():
        lower = str(key).lower()
        if lower in {"authorization", "cookie", "set-cookie", "x-api-key"}:
            lines.append(f"{key}: [REDACTED]")
        else:
            lines.append(f"{key}: {value}")
    excerpt = _redact_secrets((text or "")[:1600])
    if excerpt:
        lines.append("")
        lines.append(excerpt)
    return "\n".join(lines[:90])


def _safe_asset_summary(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "url": asset.get("url"),
            "finalUrl": asset.get("finalUrl"),
            "status": asset.get("status"),
            "assetType": asset.get("assetType"),
            "bytes": asset.get("bytes", 0),
            "truncated": bool(asset.get("truncated")),
            **({"error": asset.get("error")} if asset.get("error") else {}),
        }
        for asset in assets
    ]


def _redact_secrets(text: str) -> str:
    redacted = str(text or "")
    for pattern in SECRET_PATTERNS:
        redacted = pattern["regex"].sub(lambda m: _mask_secret(m.group(0)), redacted)
    redacted = re.sub(
        r"(?i)(api[_-]?key|token|secret|password|passwd|pwd)(['\"\\s:=]+)[A-Za-z0-9._~+/=-]{8,}",
        r"\1\2[REDACTED]",
        redacted,
    )
    redacted = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{12,}", r"\1[REDACTED]", redacted)
    return redacted[:1800]


def _mask_secret(value: str) -> str:
    value = str(value or "")
    if len(value) <= 12:
        return "[REDACTED]"
    return f"{value[:6]}...[REDACTED]...{value[-4:]}"


def _secret_fingerprint(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", errors="ignore")).hexdigest()[:16]


def _unique_secret_matches(matches: Iterable[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    seen = set()
    output = []
    for match in matches:
        marker = match.get("fingerprint")
        if not marker or marker in seen:
            continue
        seen.add(marker)
        output.append(match)
        if len(output) >= limit:
            break
    return output


def _dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    output = []
    for finding in findings:
        marker = (
            finding.get("template-id"),
            finding.get("matched-at"),
        )
        if marker in seen:
            continue
        seen.add(marker)
        output.append(finding)
    return output


def _dedupe_secret_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    output = []
    for record in records:
        marker = (record.get("fingerprint"), record.get("assetUrl"))
        if marker in seen:
            continue
        seen.add(marker)
        output.append(record)
    return output


def _looks_like_script_url(value: str) -> bool:
    parsed = urlparse(str(value or ""))
    return parsed.path.lower().endswith(".js")


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value if value is not None else default)
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(number, maximum))


def _coerce_string_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(item) for item in parsed if item]
        except Exception:
            return [value] if value else []
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)] if value else []


def _dedupe(values: Iterable[str], limit: Optional[int] = None) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        value = str(value or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(value)
        if limit and len(output) >= limit:
            break
    return output


def _safe_template_id(value: str) -> str:
    safe = re.sub(r"[^a-z0-9._:-]+", "-", value.lower()).strip("-")
    return safe[:180] or "origami-client-secret"
