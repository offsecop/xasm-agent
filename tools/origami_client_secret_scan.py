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
                "aggressive": {
                    "type": "boolean",
                    "default": False,
                    "description": "With engagement=lab, ARM the deep Google-API capability + Firebase enumeration phase (active probing of the discovered key; logs the tester's IP in the key owner's Google usage).",
                },
                "engagement": {
                    "type": "string",
                    "description": "Set to 'lab' (with aggressive=true) to confirm an authorized lab/engagement target and arm the deep phase.",
                },
                "maxServicesPerKey": {
                    "type": "integer",
                    "default": 12,
                    "description": "Cap on deep capability-probe HTTP calls per API key when aggressive.",
                },
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
        # #769 — deep capability + Firebase enumeration is ARMED ONLY under the
        # existing aggressive+lab unlock (the same gate exploit:chain /
        # vuln:chain_probe use). Off aggressive ⇒ the shallow validity probe is
        # unchanged (default-on).
        aggressive = bool(parameters.get("aggressive"))
        engagement = str(parameters.get("engagement") or "").strip().lower()
        deep_google = aggressive and engagement == "lab"
        max_services_per_key = _bounded_int(parameters.get("maxServicesPerKey"), 12, 1, 40)
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
                    if deep_google:
                        google_tests.append(
                            await _deep_test_google_api_key(
                                session, match["rawValue"], headers=headers, max_services=max_services_per_key
                            )
                        )
                    else:
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


# ===========================================================================
# #769 — deep Google-API capability enumeration + Firebase exfil (structural).
#
# Ported from ../origami/google-api-validator.js. ARMED ONLY under the existing
# aggressive=true + engagement=lab unlock (see execute()). Actively probes the
# TARGET's discovered key across the Google API surface and chains Firebase
# anonymous-auth → structural reads, classifying by real capability.
#
# Evidence is STRUCTURAL ONLY: the reachable-service list + tier, Firebase
# top-level key NAMES / collection NAMES / file NAMES + counts, and project
# id/number. NEVER record contents, NEVER the raw key. Calls use the target's
# own key (not a platform credential), so this is NOT the ProviderQuotaService
# path; volume is bounded by maxServicesPerKey. Active probes originate from the
# agent's egress IP and land in the KEY OWNER's Google usage logs — hence the
# strict aggressive+lab gate. RTDB reads are ALWAYS ?shallow=true so only
# top-level key names (never values) are returned.
# ===========================================================================

TIER_INFO = "info"
TIER_LOW = "low"
TIER_MEDIUM = "medium"
TIER_HIGH = "high"
TIER_CRITICAL = "critical"

_TIER_RANK = {TIER_INFO: 0, TIER_LOW: 1, TIER_MEDIUM: 2, TIER_HIGH: 3, TIER_CRITICAL: 4}

# (service_id, method, url_template {k}=key {proj}=projectId, tier, body|None).
# Billing/PII tier prefers NON-billable list/metadata endpoints (e.g. Generative
# Language `/models` proves Gemini reachable without a paid generateContent) to
# minimise cost to the key owner.
GOOGLE_API_MATRIX = [
    # cost-abuse → INFO/LOW
    ("maps-static", "GET", "https://maps.googleapis.com/maps/api/staticmap?center=45.5,10.5&zoom=7&size=64x64&key={k}", TIER_INFO, None),
    ("geocoding", "GET", "https://maps.googleapis.com/maps/api/geocode/json?address=x&key={k}", TIER_INFO, None),
    ("timezone", "GET", "https://maps.googleapis.com/maps/api/timezone/json?location=39.6,-119.6&timestamp=1331161200&key={k}", TIER_INFO, None),
    ("directions", "GET", "https://maps.googleapis.com/maps/api/directions/json?origin=Toronto&destination=Montreal&key={k}", TIER_INFO, None),
    ("places", "GET", "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8,151.1&radius=500&type=cafe&key={k}", TIER_LOW, None),
    ("distance-matrix", "GET", "https://maps.googleapis.com/maps/api/distancematrix/json?origins=Vancouver&destinations=SF&key={k}", TIER_INFO, None),
    ("elevation", "GET", "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7,-104.9&key={k}", TIER_INFO, None),
    ("pagespeed", "GET", "https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://www.google.com&key={k}", TIER_INFO, None),
    ("fonts", "GET", "https://www.googleapis.com/webfonts/v1/webfonts?key={k}", TIER_INFO, None),
    ("translation", "GET", "https://translation.googleapis.com/language/translate/v2?key={k}&q=hi&target=es", TIER_LOW, None),
    # billing/PII → MEDIUM (non-billable list/metadata probes where possible)
    ("gen-language", "GET", "https://generativelanguage.googleapis.com/v1beta/models?key={k}", TIER_MEDIUM, None),
    ("vision", "GET", "https://vision.googleapis.com/v1/operations?key={k}", TIER_MEDIUM, None),
    ("youtube", "GET", "https://www.googleapis.com/youtube/v3/search?part=snippet&q=t&maxResults=1&key={k}", TIER_MEDIUM, None),
    ("custom-search", "GET", "https://www.googleapis.com/customsearch/v1?q=test&key={k}", TIER_MEDIUM, None),
    ("geolocation", "POST", "https://www.googleapis.com/geolocation/v1/geolocate?key={k}", TIER_MEDIUM, {"considerIp": True}),
    # infra/exfil → CRITICAL (bigquery HIGH); need {proj}
    ("resource-manager", "GET", "https://cloudresourcemanager.googleapis.com/v1/projects?key={k}", TIER_CRITICAL, None),
    ("compute-engine", "GET", "https://compute.googleapis.com/compute/v1/projects/{proj}/aggregated/instances?key={k}", TIER_CRITICAL, None),
    ("cloud-storage", "GET", "https://storage.googleapis.com/storage/v1/b?project={proj}&key={k}", TIER_CRITICAL, None),
    ("secret-manager", "GET", "https://secretmanager.googleapis.com/v1/projects/{proj}/secrets?key={k}", TIER_CRITICAL, None),
    ("bigquery", "GET", "https://bigquery.googleapis.com/bigquery/v2/projects/{proj}/datasets?key={k}", TIER_HIGH, None),
]

_PROJECT_NUMBER_RE = re.compile(r"project[s]?[\s/]+(\d{6,})\b", re.I)
_RAW_GOOGLE_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")


def _service_reachable(code: Optional[int]) -> bool:
    # A 200 proves the key is valid AND this API is enabled/reachable. Invalid
    # or unauthorized keys return 400/403 — so 200-only is the safe (no
    # false-high) capability signal.
    return code == 200


# High-cost / data-scraping APIs (billing abuse well beyond the maps family;
# not intended to be client-side) → MEDIUM.
_BILLING_ABUSE_SERVICES = {"gen-language", "vision", "speech", "youtube", "custom-search"}
# Intended-client-side, cost-abuse-only APIs. A 200 to our (non-owner-IP) probe
# means the key is NOT referrer-restricted, so it can be billed by anyone — a
# real but low-severity cost-abuse finding. A referrer-restricted key returns
# 403 here (not reachable) and correctly falls through to INFO.
_COST_ABUSE_SERVICES = {
    "maps-static", "geocoding", "timezone", "directions", "distance-matrix",
    "elevation", "places", "geolocation", "translation",
}


def _tier_severity_for_scope(scope: Dict[str, Any]) -> str:
    reachable = {s["service_id"] for s in scope.get("services", []) if s.get("reachable")}
    fb = scope.get("firebase", {}) or {}
    # CRITICAL — infra/exfil reachable, or fully-open Firebase.
    if reachable & {"resource-manager", "compute-engine", "cloud-storage", "secret-manager"}:
        return TIER_CRITICAL
    if fb.get("rtdb_access") == "OPEN" or fb.get("firestore_open"):
        return TIER_CRITICAL
    # HIGH — data access.
    if fb.get("storage_listable") or fb.get("rtdb_access") == "AUTHENTICATED" or "bigquery" in reachable:
        return TIER_HIGH
    # MEDIUM — high-cost / data-scraping APIs.
    if reachable & _BILLING_ABUSE_SERVICES:
        return TIER_MEDIUM
    # LOW — an UNRESTRICTED intended-client-side key (maps family / translation):
    # cost-abuse at worst. This is the common, correct-usage case.
    if reachable & _COST_ABUSE_SERVICES:
        return TIER_LOW
    # INFO — valid but locked down (referrer-restricted → nothing reachable), or
    # only free/no-cost APIs (fonts/pagespeed/books) enabled. The public key is
    # not externally abusable.
    return TIER_INFO


def _sanitize_scope_details(scope: Dict[str, Any]) -> Dict[str, Any]:
    # Hard-cap structural lists; strip anything that isn't a name/count.
    fb = scope.get("firebase") or {}
    if isinstance(fb.get("topLevelKeys"), list):
        fb["topLevelKeys"] = [str(k)[:80] for k in fb["topLevelKeys"][:10]]
    if isinstance(fb.get("collections"), list):
        fb["collections"] = [str(c)[:80] for c in fb["collections"][:10]]
    if isinstance(fb.get("sampleFiles"), list):
        fb["sampleFiles"] = [str(f)[:120] for f in fb["sampleFiles"][:5]]
    scope["firebase"] = fb
    return scope


def _assert_no_raw_google_key(obj: Any) -> Any:
    # Belt-and-suspenders: scrub any raw AIza… key from a serialized finding
    # before it leaves the tool, so Job.output can never carry a raw secret even
    # if a future evidence field regresses.
    try:
        serialized = json.dumps(obj)
    except Exception:
        return obj
    if _RAW_GOOGLE_KEY_RE.search(serialized):
        return json.loads(_RAW_GOOGLE_KEY_RE.sub("[REDACTED_GOOGLE_API_KEY]", serialized))
    return obj


def _rtdb_top_level_keys(text: Optional[str]) -> List[str]:
    try:
        data = json.loads(text or "null")
    except Exception:
        return []
    if isinstance(data, dict):
        return [str(k) for k in list(data.keys())[:10]]
    return []


async def _probe_google_service(
    session: aiohttp.ClientSession,
    key: str,
    hdrs: Dict[str, str],
    entry: Tuple[str, str, str, str, Optional[Dict[str, Any]]],
    project_id: Optional[str],
) -> Dict[str, Any]:
    service_id, method, url_template, tier, body = entry
    if "{proj}" in url_template and not project_id:
        return {"service_id": service_id, "tier": tier, "reachable": False, "code": None, "note": "no-project"}
    url = url_template.format(k=key, proj=project_id or "")
    try:
        data = json.dumps(body) if body is not None else None
        req_headers = dict(hdrs)
        if body is not None:
            req_headers["Content-Type"] = "application/json"
        fetched = await fetch_text(session, url, method=method, headers=req_headers, data=data, max_bytes=8000)
        code = int(fetched.get("status") or 0)
        return {"service_id": service_id, "tier": tier, "reachable": _service_reachable(code), "code": code, "_text": fetched.get("text") or ""}
    except Exception as exc:
        return {"service_id": service_id, "tier": tier, "reachable": False, "code": None, "error": str(exc)[:120]}


async def _firebase_signup(session: aiohttp.ClientSession, key: str, hdrs: Dict[str, str]) -> Dict[str, Any]:
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={key}"
    try:
        fetched = await fetch_text(
            session, url, method="POST",
            headers={**hdrs, "Content-Type": "application/json"},
            data=json.dumps({"returnSecureToken": True}), max_bytes=8000,
        )
        code = int(fetched.get("status") or 0)
        text = fetched.get("text") or ""
        if code == 200:
            try:
                tok = (json.loads(text) or {}).get("idToken")
            except Exception:
                tok = None
            return {"access": "OPEN", "idToken": tok, "_err": ""}
        low = text.lower()
        if "admin_only_operation" in low:
            return {"access": "disabled", "idToken": None, "_err": text[:1500]}
        return {"access": "restricted", "idToken": None, "_err": text[:1500]}
    except Exception as exc:
        return {"access": None, "idToken": None, "_err": str(exc)[:200]}


# Proof-of-impact sampling caps (sqlmap-parity: like dump_data, but bounded).
SAMPLE_MAX_BYTES = 4096
SAMPLE_MAX_RECORDS = 3
SAMPLE_MAX_FILES = 5


def _rtdb_sample(text: Optional[str]) -> Any:
    # Parse + hard-cap a raw RTDB sample (proof-of-impact). Truncates to
    # SAMPLE_MAX_RECORDS top-level entries so an open DB can't dump unbounded.
    try:
        data = json.loads(text or "null")
    except Exception:
        return None
    if isinstance(data, dict):
        return {k: data[k] for k in list(data.keys())[:SAMPLE_MAX_RECORDS]}
    if isinstance(data, list):
        return data[:SAMPLE_MAX_RECORDS]
    return data


async def _firebase_rtdb_shallow(session: aiohttp.ClientSession, project_id: str, id_token: Optional[str]) -> Dict[str, Any]:
    # Structure via ?shallow=true (top-level key NAMES). When OPEN/AUTHENTICATED,
    # ALSO pull a bounded raw sample (?orderBy="$key"&limitToFirst=N) as
    # proof-of-impact — mirrors sqlmap dump_data, hard-capped by bytes+records.
    for host in (f"https://{project_id}-default-rtdb.firebaseio.com", f"https://{project_id}.firebaseio.com"):
        base = f"{host}/.json?shallow=true"
        sample_qs = f'/.json?orderBy="$key"&limitToFirst={SAMPLE_MAX_RECORDS}'
        try:
            fetched = await fetch_text(session, base, max_bytes=8000)
            code = int(fetched.get("status") or 0)
            if code == 200:
                sample = None
                try:
                    s = await fetch_text(session, f"{host}{sample_qs}", max_bytes=SAMPLE_MAX_BYTES)
                    if int(s.get("status") or 0) == 200:
                        sample = _rtdb_sample(s.get("text"))
                except Exception:
                    sample = None
                return {"access": "OPEN", "topLevelKeys": _rtdb_top_level_keys(fetched.get("text")), "databaseUrl": host, "sample": sample}
            if code in (401, 403):
                if id_token:
                    fetched2 = await fetch_text(session, f"{base}&auth={id_token}", max_bytes=8000)
                    if int(fetched2.get("status") or 0) == 200:
                        sample = None
                        try:
                            s = await fetch_text(session, f"{host}{sample_qs}&auth={id_token}", max_bytes=SAMPLE_MAX_BYTES)
                            if int(s.get("status") or 0) == 200:
                                sample = _rtdb_sample(s.get("text"))
                        except Exception:
                            sample = None
                        return {"access": "AUTHENTICATED", "topLevelKeys": _rtdb_top_level_keys(fetched2.get("text")), "databaseUrl": host, "sample": sample}
                return {"access": "SECURED", "topLevelKeys": None, "databaseUrl": host, "sample": None}
        except Exception:
            continue
    return {"access": None, "topLevelKeys": None, "databaseUrl": None, "sample": None}


async def _firestore_collections(session: aiohttp.ClientSession, key: str, project_id: str, hdrs: Dict[str, str]) -> Dict[str, Any]:
    url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents?key={key}"
    try:
        fetched = await fetch_text(session, url, headers=hdrs, max_bytes=16000)
        if int(fetched.get("status") or 0) == 200:
            data = json.loads(fetched.get("text") or "{}")
            cols = []
            sample = []
            for d in data.get("documents") or []:
                parts = str(d.get("name") or "").split("/")
                if len(parts) >= 2:
                    cols.append(parts[-2])
                # Raw sample doc (proof-of-impact): collection + path tail + fields.
                if len(sample) < SAMPLE_MAX_RECORDS and d.get("fields"):
                    sample.append({
                        "collection": parts[-2] if len(parts) >= 2 else None,
                        "document": parts[-1] if parts else None,
                        "fields": d.get("fields"),
                    })
            return {"open": True, "collections": sorted(set(cols))[:10], "sample": sample or None}
    except Exception:
        pass
    return {"open": False, "collections": None, "sample": None}


async def _firebase_storage(session: aiohttp.ClientSession, project_id: str) -> Dict[str, Any]:
    url = f"https://firebasestorage.googleapis.com/v0/b/{project_id}.appspot.com/o?maxResults=10"
    try:
        fetched = await fetch_text(session, url, max_bytes=16000)
        if int(fetched.get("status") or 0) == 200:
            data = json.loads(fetched.get("text") or "{}")
            items = data.get("items") or []
            names = [str(i.get("name")) for i in items if i.get("name")][:SAMPLE_MAX_FILES]
            # Raw file metadata sample (name/size/type/updated) — the listing proof.
            sample = [
                {"name": i.get("name"), "size": i.get("size"), "contentType": i.get("contentType"), "updated": i.get("updated")}
                for i in items[:SAMPLE_MAX_FILES]
                if i.get("name")
            ]
            return {"listable": True, "itemCount": len(items), "sampleFiles": names, "sample": sample or None}
    except Exception:
        pass
    return {"listable": False, "itemCount": None, "sampleFiles": None, "sample": None}


async def _deep_test_google_api_key(
    session: aiohttp.ClientSession,
    key: str,
    *,
    headers: Dict[str, str],
    max_services: int = 12,
) -> Dict[str, Any]:
    """Deep capability + Firebase enumeration for a single Google API key.

    Returns the shallow-compatible shape PLUS `severity` (capability tier) and a
    structural `scope` block. Bounded by `max_services` deep HTTP probes.
    """
    fingerprint = _secret_fingerprint(key)
    masked = _mask_secret(key)
    hdrs = _google_test_headers(headers)
    services: List[Dict[str, Any]] = []
    error_texts: List[str] = []
    budget = max_services

    async def run(entry, project_id=None):
        nonlocal budget
        if budget <= 0:
            return None
        res = await _probe_google_service(session, key, hdrs, entry, project_id)
        if res.get("note") == "no-project":
            services.append(res)
            return None
        budget -= 1
        text = res.pop("_text", "")
        if not res.get("reachable") and text:
            error_texts.append(text[:2000])
        services.append(res)
        return res, text

    # Phase 1 — validity/discovery (shallow, high value, not budgeted).
    shallow = await _test_google_api_key(session, key, headers=headers)

    # Phase 2 — Resource Manager first (project discovery + CRITICAL signal).
    project_id: Optional[str] = None
    project_number: Optional[str] = None
    discovered: List[Dict[str, Any]] = []
    rm_entry = next((e for e in GOOGLE_API_MATRIX if e[0] == "resource-manager"), None)
    rm = await run(rm_entry) if rm_entry else None
    if rm:
        _, rm_text = rm
        try:
            projects = (json.loads(rm_text or "{}") or {}).get("projects") or []
            if projects:
                project_id = projects[0].get("projectId")
                project_number = str(projects[0].get("projectNumber") or "") or None
                discovered = [
                    {"projectId": p.get("projectId"), "projectNumber": str(p.get("projectNumber") or "")}
                    for p in projects[:5]
                ]
        except Exception:
            pass

    # Phase 3 — Firebase anonymous auth (idToken for the chain).
    firebase: Dict[str, Any] = {}
    id_token: Optional[str] = None
    if budget > 0:
        budget -= 1
        fb_auth = await _firebase_signup(session, key, hdrs)
        firebase["auth"] = fb_auth.get("access")
        id_token = fb_auth.get("idToken")
        if fb_auth.get("_err"):
            error_texts.append(fb_auth["_err"])

    # Recover a project number from any collected error body if none discovered.
    if not project_id and not project_number:
        for t in error_texts:
            m = _PROJECT_NUMBER_RE.search(t or "")
            if m:
                project_number = m.group(1)
                break
    project_identifier = project_id or project_number

    # Phase 4 — remaining capability matrix, CRITICAL/HIGH first, until budget.
    remaining = [e for e in GOOGLE_API_MATRIX if e[0] != "resource-manager"]
    remaining.sort(key=lambda e: -_TIER_RANK.get(e[3], 0))
    for entry in remaining:
        if budget <= 0:
            break
        await run(entry, project_identifier)

    # Phase 5 — Firebase structural reads (need the string projectId).
    if project_id:
        if budget > 0:
            budget -= 1
            rtdb = await _firebase_rtdb_shallow(session, project_id, id_token)
            firebase["rtdb_access"] = rtdb.get("access")
            if rtdb.get("topLevelKeys") is not None:
                firebase["topLevelKeys"] = rtdb["topLevelKeys"]
            if rtdb.get("databaseUrl"):
                firebase["databaseUrl"] = rtdb["databaseUrl"]
            if rtdb.get("sample") is not None:
                firebase["rtdb_sample"] = rtdb["sample"]
        if budget > 0:
            budget -= 1
            fs = await _firestore_collections(session, key, project_id, hdrs)
            firebase["firestore_open"] = fs.get("open")
            if fs.get("collections") is not None:
                firebase["collections"] = fs["collections"]
            if fs.get("sample") is not None:
                firebase["firestore_sample"] = fs["sample"]
        if budget > 0:
            budget -= 1
            st = await _firebase_storage(session, project_id)
            firebase["storage_listable"] = st.get("listable")
            if st.get("itemCount") is not None:
                firebase["itemCount"] = st["itemCount"]
            if st.get("sampleFiles") is not None:
                firebase["sampleFiles"] = st["sampleFiles"]
            if st.get("sample") is not None:
                firebase["storage_sample"] = st["sample"]

    scope_services = [
        {"service_id": s["service_id"], "tier": s["tier"], "reachable": bool(s.get("reachable")), "code": s.get("code")}
        for s in services
    ]
    tier = _tier_severity_for_scope({"services": scope_services, "firebase": firebase})
    scope = _sanitize_scope_details(
        {
            "tier": tier,
            "services": scope_services,
            "project": {"projectId": project_id, "projectNumber": project_number, "discoveredProjects": discovered},
            "firebase": firebase,
        }
    )
    reachable_ids = sorted([s["service_id"] for s in scope_services if s["reachable"]])
    return {
        "fingerprint": fingerprint,
        "maskedValue": masked,
        "status": shallow.get("status"),
        "httpStatus": shallow.get("httpStatus"),
        "reason": f"Deep capability scan ({tier}); reachable: {reachable_ids or 'none'}",
        "endpoint": "[REDACTED_GOOGLE_API_KEY] (deep capability scan)",
        "severity": tier,
        "scope": scope,
    }


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
        # #769 — structural capability + Firebase scope block (deep mode only).
        if google_test.get("scope"):
            evidence["googleApiKeyTest"]["scope"] = google_test["scope"]

    return _assert_no_raw_google_key({
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
    })


def _severity_for_match(match: Dict[str, Any], google_test: Optional[Dict[str, Any]]) -> str:
    if match["type"] == "google_api_key" and google_test:
        # #769 deep mode sets a capability-tiered severity directly (INFO/LOW
        # for maps-only … CRITICAL for Secret Manager / open Firebase).
        if google_test.get("severity"):
            return str(google_test["severity"])
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
