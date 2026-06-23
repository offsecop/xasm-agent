"""
Retire.js-backed client-side dependency SCA for web targets.

The tool gathers same-origin JavaScript bundles, runs Retire.js when available,
and falls back to a small deterministic fingerprint set so older agent images
still produce useful dependency hypotheses instead of failing the workflow.
"""

import json
import os
import re
import shutil
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    extract_html_map,
    fetch_text,
    normalize_url,
    parse_headers,
    run_process,
    same_origin,
)


DEFAULT_MAX_SCRIPTS = 20
DEFAULT_MAX_BYTES = 2_000_000


FALLBACK_ADVISORIES = [
    {
        "package": "jquery",
        "patterns": [
            r"jQuery JavaScript Library v([0-9]+(?:\.[0-9]+){1,3})",
            r"jquery[-.]([0-9]+(?:\.[0-9]+){1,3})(?:\.min)?\.js",
        ],
        "vulnerableBelow": "3.5.0",
        "severity": "MEDIUM",
        "cves": ["CVE-2020-11022", "CVE-2020-11023"],
        "summary": "jQuery before 3.5.0 is affected by HTML prefilter XSS issues in common unsafe usage patterns.",
        "references": ["https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"],
    },
    {
        "package": "lodash",
        "patterns": [
            r"lodash(?:\.min)?\.js[^0-9]{0,20}([0-9]+(?:\.[0-9]+){1,3})",
            r"lodash v([0-9]+(?:\.[0-9]+){1,3})",
        ],
        "vulnerableBelow": "4.17.21",
        "severity": "HIGH",
        "cves": ["CVE-2021-23337"],
        "summary": "Lodash before 4.17.21 has known command injection/prototype pollution advisory coverage.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
    },
    {
        "package": "bootstrap",
        "patterns": [
            r"Bootstrap v([0-9]+(?:\.[0-9]+){1,3})",
            r"bootstrap[-.]([0-9]+(?:\.[0-9]+){1,3})(?:\.min)?\.js",
        ],
        "vulnerableBelow": "4.3.1",
        "severity": "MEDIUM",
        "cves": ["CVE-2019-8331"],
        "summary": "Bootstrap before 4.3.1 includes XSS-prone tooltip/popover data-template handling.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-8331"],
    },
    {
        "package": "moment",
        "patterns": [
            r"//! moment\.js\s+([0-9]+(?:\.[0-9]+){1,3})",
            r"moment(?:\.min)?[-.]([0-9]+(?:\.[0-9]+){1,3})(?:\.min)?\.js",
        ],
        "vulnerableBelow": "2.29.4",
        "severity": "MEDIUM",
        "cves": ["CVE-2022-31129"],
        "summary": "Moment before 2.29.4 has ReDoS advisory coverage for crafted locale input.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-31129"],
    },
]


class RetireJsScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "sca:retirejs_scan"

    @property
    def description(self) -> str:
        return (
            "Detects vulnerable JavaScript/Next client-side dependencies from "
            "same-origin scripts using Retire.js plus deterministic fingerprints."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "description": "Scan same-origin JavaScript bundles for vulnerable client-side dependencies.",
            "required": ["target"],
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Base page URL to inspect for script tags.",
                },
                "url": {
                    "type": "string",
                    "description": "Alias for target.",
                },
                "scripts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Explicit script URLs to scan.",
                },
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Discovered page/script URLs from Katana, browser mapping, or JS analysis.",
                },
                "sameOriginOnly": {
                    "type": "boolean",
                    "default": True,
                    "description": "Only fetch scripts from the target origin.",
                },
                "maxScripts": {
                    "type": "integer",
                    "default": DEFAULT_MAX_SCRIPTS,
                    "description": "Maximum number of scripts to fetch and inspect.",
                },
                "maxBytesPerScript": {
                    "type": "integer",
                    "default": DEFAULT_MAX_BYTES,
                    "description": "Maximum bytes to read per JavaScript bundle.",
                },
                "useRetireCli": {
                    "type": "boolean",
                    "default": True,
                    "description": "Use the Retire.js CLI when available.",
                },
                "timeoutSeconds": {
                    "type": "integer",
                    "default": 90,
                    "description": "Retire.js CLI timeout.",
                },
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
            "domain": ["web", "javascript", "sca"],
            "input_type": ["url", "urls", "scripts"],
            "output_type": ["findings", "libraries", "cves"],
            "chainable_after": ["browser:", "katana:", "js:"],
            "chainable_before": ["nuclei:", "curl:", "param:", "exploit:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        target = normalize_url(parameters.get("target") or parameters.get("url") or "")
        max_scripts = _bounded_int(parameters.get("maxScripts"), DEFAULT_MAX_SCRIPTS, 1, 80)
        max_bytes = _bounded_int(parameters.get("maxBytesPerScript"), DEFAULT_MAX_BYTES, 50_000, 5_000_000)
        timeout_seconds = _bounded_int(parameters.get("timeoutSeconds"), 90, 10, 300)
        same_origin_only = bool(parameters.get("sameOriginOnly", True))
        use_retire_cli = bool(parameters.get("useRetireCli", True))
        agent = parameters.get("_agent")

        if agent:
            agent.report_progress("Collecting JavaScript bundles for SCA", target or "provided URLs", 0, None)

        headers = parse_headers(parameters)
        scripts = _coerce_string_list(parameters.get("scripts"))
        urls = _coerce_string_list(parameters.get("urls"))
        if not scripts:
            scripts = [url for url in urls if _looks_like_script_url(url)]

        fetched_scripts: List[Dict[str, Any]] = []
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=90, connect=10, sock_read=30),
        ) as session:
            if target:
                if not scripts:
                    scripts.extend(await _extract_scripts_from_page(session, target, headers, max_bytes=1_000_000))
                for page_url in [u for u in urls if not _looks_like_script_url(u)][:10]:
                    page_url = urljoin(target, page_url)
                    if same_origin_only and not same_origin(target, page_url):
                        continue
                    scripts.extend(
                        await _extract_scripts_from_page(session, page_url, headers, max_bytes=1_000_000)
                    )

            scripts = _dedupe(
                [
                    urljoin(target, script) if target else normalize_url(script)
                    for script in scripts
                    if script
                ],
                limit=max_scripts,
            )
            if target and same_origin_only:
                scripts = [script for script in scripts if same_origin(target, script)]

            for index, script_url in enumerate(scripts):
                try:
                    fetched = await fetch_text(session, script_url, headers=headers, max_bytes=max_bytes)
                    text = fetched.get("text") or ""
                    fetched_scripts.append(
                        {
                            "url": script_url,
                            "finalUrl": fetched.get("url") or script_url,
                            "status": fetched.get("status"),
                            "headers": fetched.get("headers") or {},
                            "text": text,
                            "bytes": len(text.encode("utf-8", errors="ignore")),
                            "truncated": bool(fetched.get("truncated")),
                        }
                    )
                    if agent:
                        agent.report_progress("Collecting JavaScript bundles for SCA", script_url, index + 1, len(scripts))
                except Exception as exc:
                    fetched_scripts.append({"url": script_url, "error": str(exc), "text": ""})

        cli_available = bool(shutil.which("retire"))
        retire_result: Dict[str, Any] = {
            "enabled": use_retire_cli,
            "available": cli_available,
            "used": False,
        }
        libraries: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        if use_retire_cli and cli_available and fetched_scripts:
            retire_result, retire_findings, retire_libraries = await _run_retire_cli(
                fetched_scripts,
                timeout_seconds=timeout_seconds,
            )
            findings.extend(retire_findings)
            libraries.extend(retire_libraries)

        fallback_libraries, fallback_findings = _run_fallback_fingerprints(fetched_scripts)
        libraries.extend(_new_libraries_only(libraries, fallback_libraries))
        findings.extend(_new_findings_only(findings, fallback_findings))

        scripts_analyzed = [
            {
                "url": item.get("url"),
                "finalUrl": item.get("finalUrl"),
                "status": item.get("status"),
                "bytes": item.get("bytes", 0),
                "truncated": item.get("truncated", False),
                **({"error": item.get("error")} if item.get("error") else {}),
            }
            for item in fetched_scripts
        ]

        cves = sorted(
            {
                cve
                for finding in findings
                for cve in (finding.get("info", {}).get("cve") or [])
                if isinstance(cve, str) and cve.startswith("CVE-")
            }
        )
        summary = {
            "scriptsAnalyzed": len([s for s in fetched_scripts if s.get("text")]),
            "scriptsFailed": len([s for s in fetched_scripts if s.get("error")]),
            "librariesDetected": len(libraries),
            "findings": len(findings),
            "cves": len(cves),
            "retireCliUsed": bool(retire_result.get("used")),
        }

        if agent:
            agent.append_output(
                "[sca:retirejs_scan] "
                f"scripts={summary['scriptsAnalyzed']} libraries={summary['librariesDetected']} "
                f"findings={summary['findings']} cves={summary['cves']} retireCliUsed={summary['retireCliUsed']}"
            )

        return {
            "success": True,
            "target": target,
            "scriptsAnalyzed": scripts_analyzed,
            "libraries": libraries[:500],
            "findings": findings[:500],
            "cves": cves,
            "summary": summary,
            "retire": retire_result,
        }


async def _extract_scripts_from_page(
    session: aiohttp.ClientSession,
    url: str,
    headers: Dict[str, str],
    *,
    max_bytes: int,
) -> List[str]:
    try:
        fetched = await fetch_text(session, url, headers=headers, max_bytes=max_bytes)
    except Exception:
        return []
    if int(fetched.get("status") or 0) >= 400:
        return []
    mapped = extract_html_map(fetched.get("text") or "", fetched.get("url") or url)
    return [urljoin(fetched.get("url") or url, script) for script in mapped.get("scripts", [])]


async def _run_retire_cli(
    fetched_scripts: List[Dict[str, Any]],
    *,
    timeout_seconds: int,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    with tempfile.TemporaryDirectory(prefix="xasm-retirejs-") as tmpdir:
        script_map: Dict[str, Dict[str, Any]] = {}
        for index, script in enumerate(fetched_scripts):
            text = script.get("text") or ""
            if not text:
                continue
            filename = f"script_{index:03d}.js"
            path = os.path.join(tmpdir, filename)
            with open(path, "w", encoding="utf-8", errors="replace") as handle:
                handle.write(text)
            script_map[path] = script

        if not script_map:
            return {"enabled": True, "available": True, "used": False, "reason": "no scripts fetched"}, [], []

        output_path = os.path.join(tmpdir, "retire-output.json")
        cmd = [
            "retire",
            "--path",
            tmpdir,
            "--outputformat",
            "json",
            "--outputpath",
            output_path,
        ]
        proc = await run_process(cmd, timeout=timeout_seconds)
        raw = ""
        if os.path.exists(output_path):
            with open(output_path, "r", encoding="utf-8", errors="replace") as handle:
                raw = handle.read()
        if not raw.strip():
            raw = proc.get("stdout") or ""

        parsed: Any = None
        parse_error = None
        if raw.strip():
            try:
                parsed = json.loads(raw)
            except Exception as exc:
                parse_error = str(exc)

        findings, libraries = _parse_retire_json(parsed, script_map)
        return (
            {
                "enabled": True,
                "available": True,
                "used": True,
                "returnCode": proc.get("returnCode"),
                "timedOut": bool(proc.get("timedOut")),
                "stderr": (proc.get("stderr") or "")[:1200],
                **({"parseError": parse_error} if parse_error else {}),
            },
            findings,
            libraries,
        )


def _parse_retire_json(
    parsed: Any,
    script_map: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    findings: List[Dict[str, Any]] = []
    libraries: List[Dict[str, Any]] = []
    for file_entry in _iter_retire_file_entries(parsed):
        file_path = str(file_entry.get("file") or file_entry.get("path") or "")
        script = _script_for_retire_file(file_path, script_map)
        for result in _coerce_list(file_entry.get("results")):
            package = str(result.get("component") or result.get("package") or result.get("name") or "unknown").strip()
            version = str(result.get("version") or result.get("detectedVersion") or "unknown").strip()
            libraries.append(
                {
                    "name": package,
                    "version": version,
                    "scriptUrl": script.get("url") or script.get("finalUrl"),
                    "source": "retirejs",
                }
            )
            vulnerabilities = _coerce_list(result.get("vulnerabilities"))
            if vulnerabilities:
                findings.append(
                    _build_aggregate_finding(
                        package,
                        version,
                        script,
                        vulnerabilities,
                        source="retirejs",
                    )
                )
    return findings, libraries


def _iter_retire_file_entries(parsed: Any) -> Iterable[Dict[str, Any]]:
    if parsed is None:
        return []
    if isinstance(parsed, list):
        return [entry for entry in parsed if isinstance(entry, dict)]
    if isinstance(parsed, dict):
        for key in ("data", "results", "files"):
            value = parsed.get(key)
            if isinstance(value, list):
                return [entry for entry in value if isinstance(entry, dict)]
        if "file" in parsed or "path" in parsed:
            return [parsed]
    return []


def _script_for_retire_file(file_path: str, script_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    if file_path in script_map:
        return script_map[file_path]
    base = os.path.basename(file_path)
    for path, script in script_map.items():
        if os.path.basename(path) == base:
            return script
    return {"url": file_path, "finalUrl": file_path}


def _run_fallback_fingerprints(
    fetched_scripts: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    libraries: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    for script in fetched_scripts:
        text = script.get("text") or ""
        if not text:
            continue
        for advisory in FALLBACK_ADVISORIES:
            detected_version = _detect_version(text, script.get("url") or "", advisory["patterns"])
            if not detected_version:
                continue
            library = {
                "name": advisory["package"],
                "version": detected_version,
                "scriptUrl": script.get("url") or script.get("finalUrl"),
                "source": "fingerprint",
            }
            libraries.append(library)
            if _version_lt(detected_version, advisory["vulnerableBelow"]):
                vuln = {
                    "severity": advisory["severity"].lower(),
                    "identifiers": {
                        "CVE": advisory["cves"],
                        "summary": advisory["summary"],
                    },
                    "info": advisory["references"],
                    "below": advisory["vulnerableBelow"],
                }
                findings.append(
                    _build_aggregate_finding(
                        advisory["package"],
                        detected_version,
                        script,
                        [vuln],
                        source="fingerprint",
                    )
                )
    return libraries, findings


def _build_aggregate_finding(
    package: str,
    version: str,
    script: Dict[str, Any],
    vulnerabilities: List[Dict[str, Any]],
    *,
    source: str,
) -> Dict[str, Any]:
    advisories = [_extract_advisory_detail(vuln) for vuln in vulnerabilities if isinstance(vuln, dict)]
    cves = _dedupe(
        cve
        for advisory in advisories
        for cve in advisory.get("cveIds", [])
    )
    advisory_ids = _dedupe(
        advisory_id
        for advisory in advisories
        for advisory_id in advisory.get("advisoryIds", [])
    )
    refs = _dedupe(
        ref
        for advisory in advisories
        for ref in advisory.get("references", [])
    )
    severity = _highest_severity([advisory.get("severity") for advisory in advisories])
    primary_ref = cves[0] if cves else (advisory_ids[0] if advisory_ids else f"{package}-{version}")
    template_id = _safe_template_id(f"retirejs-{package}-{version}-aggregate")
    script_url = script.get("finalUrl") or script.get("url") or ""
    response_excerpt = _excerpt_around_package(script.get("text") or "", package, version)
    request = _request_line(script_url)
    response = _format_script_response(script, response_excerpt)
    advisory_count = len(advisories)
    cve_count = len(cves)
    first_summary = _first_non_empty(advisory.get("summary") for advisory in advisories)

    cve_suffix = f" ({cve_count} CVEs)" if cve_count else (
        f" ({advisory_count} advisories)" if advisory_count else ""
    )
    matched_lines = [f"{package}@{version}"]
    if cves:
        matched_lines.append(f"CVEs: {', '.join(cves)}")
    if advisory_ids:
        matched_lines.append(f"Advisories: {', '.join(advisory_ids)}")
    if advisory_count:
        matched_lines.append(f"Retire.js advisories matched: {advisory_count}")
    if first_summary:
        matched_lines.append(f"Primary summary: {first_summary}")

    title = f"Vulnerable JavaScript dependency: {package}@{version}{cve_suffix}"
    description = (
        f"Retire.js detected {package}@{version} in a client-side JavaScript bundle "
        f"with {advisory_count} advisory match(es)"
        f"{f' and {cve_count} CVE(s)' if cve_count else ''}. "
        f"{first_summary or f'Primary reference: {primary_ref}.'}"
    )
    recommendation = (
        f"Upgrade {package} to a fixed version and rebuild/redeploy the affected JavaScript bundle. "
        "Treat this as a dependency exposure hypothesis until a runtime exploit path is confirmed."
    )

    matched_content = "\n".join(matched_lines)
    return {
        "template-id": template_id,
        "templateID": template_id,
        "host": script_url,
        "matched": script_url,
        "matched-at": script_url,
        "extracted-results": [f"{package}@{version}", *cves, *advisory_ids],
        "matcher-name": "retirejs-client-dependency",
        "info": {
            "name": title,
            "description": description,
            "severity": severity.lower(),
            "remediation": recommendation,
            "reference": refs,
            "cve": cves,
            "classification": {"cve-id": cves} if cves else {},
            "tags": ["sca", "retirejs", "javascript", "dependency", package],
        },
        "request": request,
        "response": response,
        "matched-content": matched_content,
        "matchedContent": matched_content,
        "evidence": {
            "packageName": package,
            "packageVersion": version,
            "primaryReference": primary_ref,
            "cveIds": cves,
            "advisoryIds": advisory_ids,
            "advisoryCount": advisory_count,
            "cveCount": cve_count,
            "advisories": advisories,
            "scriptUrl": script_url,
            "scriptStatus": script.get("status"),
            "scanner": source,
            "dependencyFindingType": "client_side_dependency_hypothesis",
            "runtimeExploitValidated": False,
            "request": request,
            "response": response,
            "matchedContent": matched_content,
        },
    }


def _extract_advisory_detail(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    identifiers = vulnerability.get("identifiers") if isinstance(vulnerability.get("identifiers"), dict) else {}
    cves = _coerce_string_list(
        identifiers.get("CVE")
        or identifiers.get("cve")
        or vulnerability.get("cve")
        or vulnerability.get("cves")
    )
    advisory_ids = _coerce_string_list(
        identifiers.get("GHSA")
        or identifiers.get("githubID")
        or identifiers.get("githubId")
        or identifiers.get("github_id")
        or vulnerability.get("githubID")
        or vulnerability.get("githubId")
        or vulnerability.get("github_id")
        or identifiers.get("CWE")
        or vulnerability.get("id")
    )
    refs = _coerce_string_list(vulnerability.get("info") or vulnerability.get("references"))
    summary = (
        str(identifiers.get("summary") or vulnerability.get("summary") or vulnerability.get("description") or "")
        .strip()
    )
    severity = _normalize_severity(vulnerability.get("severity"))
    detail: Dict[str, Any] = {
        "severity": severity,
        "summary": summary,
        "cveIds": cves,
        "advisoryIds": advisory_ids,
        "references": refs,
    }
    for key in ("below", "atOrAbove", "patched", "patched_versions", "vulnerable_versions"):
        if vulnerability.get(key) is not None:
            detail[key] = vulnerability.get(key)
    return _without_empty_values(detail)


def _detect_version(text: str, script_url: str, patterns: List[str]) -> Optional[str]:
    haystacks = [script_url, text[:250_000]]
    for haystack in haystacks:
        for pattern in patterns:
            match = re.search(pattern, haystack, re.IGNORECASE)
            if match:
                for group in match.groups():
                    if group:
                        return group.strip().strip("v")
    return None


def _excerpt_around_package(text: str, package: str, version: str, limit: int = 1400) -> str:
    if not text:
        return ""
    lower = text.lower()
    indexes = [idx for idx in (lower.find(package.lower()), lower.find(version.lower())) if idx >= 0]
    if not indexes:
        return text[:limit]
    center = min(indexes)
    start = max(0, center - limit // 3)
    return text[start : start + limit]


def _request_line(url: str) -> str:
    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        host = parsed.netloc
        return f"GET {path} HTTP/1.1\nHost: {host}\nUser-Agent: xASM-AgenticExplorer/1.0"
    except Exception:
        return f"GET {url} HTTP/1.1"


def _format_script_response(script: Dict[str, Any], excerpt: str) -> str:
    status = int(script.get("status") or 0)
    reason = "OK" if status and status < 400 else ""
    lines = [f"HTTP/1.1 {status} {reason}".rstrip()]
    for key, value in (script.get("headers") or {}).items():
        lower = str(key).lower()
        if lower in {"authorization", "cookie", "set-cookie", "x-api-key"}:
            lines.append(f"{key}: [REDACTED]")
        else:
            lines.append(f"{key}: {value}")
    if excerpt:
        lines.append("")
        lines.append(_redact_script_excerpt(excerpt))
    return "\n".join(lines[:90])


def _redact_script_excerpt(text: str) -> str:
    value = str(text or "")
    value = re.sub(r"(?i)(api[_-]?key|token|secret|password|passwd|pwd)(['\"\\s:=]+)[A-Za-z0-9._~+/=-]{8,}", r"\1\2[REDACTED]", value)
    value = re.sub(r"(?i)(bearer\\s+)[A-Za-z0-9._~+/=-]{12,}", r"\1[REDACTED]", value)
    return value[:1600]


def _looks_like_script_url(value: str) -> bool:
    parsed = urlparse(str(value or ""))
    return parsed.path.lower().endswith(".js")


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value if value is not None else default)
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(number, maximum))


def _coerce_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


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
    output = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(value)
        if limit and len(output) >= limit:
            break
    return output


def _normalize_severity(value: Any) -> str:
    severity = str(value or "MEDIUM").upper()
    if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return severity
    if severity == "INFORMATIONAL":
        return "INFO"
    return "MEDIUM"


def _highest_severity(values: Iterable[Any]) -> str:
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    severities = [_normalize_severity(value) for value in values if value]
    if not severities:
        return "MEDIUM"
    return max(severities, key=lambda severity: order.get(severity, 2))


def _first_non_empty(values: Iterable[Any]) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _without_empty_values(value: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: item
        for key, item in value.items()
        if item not in (None, "", []) and item != {}
    }


def _safe_template_id(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.:-]+", "-", value).strip("-").lower()
    return cleaned[:180] or "retirejs-dependency"


def _version_tuple(version: str) -> Tuple[int, ...]:
    parts = []
    for part in re.split(r"[^0-9]+", str(version)):
        if part == "":
            continue
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(0)
    return tuple(parts or [0])


def _version_lt(left: str, right: str) -> bool:
    l = list(_version_tuple(left))
    r = list(_version_tuple(right))
    width = max(len(l), len(r))
    l.extend([0] * (width - len(l)))
    r.extend([0] * (width - len(r)))
    return tuple(l) < tuple(r)


def _new_libraries_only(existing: List[Dict[str, Any]], candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = {(item.get("name"), item.get("version"), item.get("scriptUrl")) for item in existing}
    return [
        item
        for item in candidates
        if (item.get("name"), item.get("version"), item.get("scriptUrl")) not in seen
    ]


def _new_findings_only(existing: List[Dict[str, Any]], candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = {(item.get("template-id"), item.get("matched-at")) for item in existing}
    return [
        item
        for item in candidates
        if (item.get("template-id"), item.get("matched-at")) not in seen
    ]


def get_tool():
    return RetireJsScanTool()
