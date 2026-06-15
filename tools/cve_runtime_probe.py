"""
cve:runtime_probe - aggressive runtime validation for CVE hypotheses.

This tool consumes CVE signals from client-side SCA (Retire.js) and attempts
bounded, non-destructive runtime validation. It never downloads or executes
third-party exploit code. The primary validation path is local Nuclei CVE
templates, with request/response evidence preserved when the installed Nuclei
version supports it.
"""

import glob
import json
import os
import re
import shutil
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    dedupe_keep_order,
    extract_html_map,
    fetch_text,
    normalize_url,
    parse_headers,
    run_process,
    same_origin,
)


DEFAULT_MAX_CVES = 12
DEFAULT_MAX_TARGETS = 6
DEFAULT_TIMEOUT_SECONDS = 120
BOOTSTRAP_XSS_CVES = {
    "CVE-2016-10735",
    "CVE-2018-14040",
    "CVE-2018-14041",
    "CVE-2018-14042",
    "CVE-2019-8331",
    "CVE-2024-6485",
    "CVE-2025-1647",
}
ANGULARJS_CONTEXT_CVES = {
    "CVE-2018-12017",
    "CVE-2018-14732",
    "CVE-2019-10768",
    "CVE-2020-7676",
    "CVE-2022-25869",
    "CVE-2023-26116",
    "CVE-2023-26117",
    "CVE-2023-26118",
}
DOMPURIFY_CONTEXT_CVES = {
    "CVE-2024-45801",
    "CVE-2024-47875",
    "CVE-2024-48910",
    "CVE-2025-26791",
    "CVE-2026-41239",
    "CVE-2026-41240",
}
BOOTSTRAP_CONTEXT_PAGE_LIMIT = 10
BOOTSTRAP_CONTEXT_SCRIPT_LIMIT = 24
ANGULARJS_CONTEXT_PAGE_LIMIT = 10
ANGULARJS_CONTEXT_SCRIPT_LIMIT = 24
DOMPURIFY_CONTEXT_PAGE_LIMIT = 10
DOMPURIFY_CONTEXT_SCRIPT_LIMIT = 30


class CveRuntimeProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "cve:runtime_probe"

    @property
    def description(self) -> str:
        return (
            "AGGRESSIVE mode: validates observed CVE/GHSA dependency signals "
            "against the live runtime using bounded local proof probes."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "description": (
                "Validate runtime exploitability of CVE hypotheses discovered by "
                "Retire.js/SCA or JS recon. Active validation requires aggressive=true."
            ),
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Base target URL."},
                "url": {"type": "string", "description": "Alias for target."},
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Observed page/API URLs to use as candidate runtime targets.",
                },
                "scripts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Observed JavaScript bundle URLs related to the CVE signals.",
                },
                "libraries": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Dependency records from SCA.",
                },
                "findings": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Prior SCA findings carrying CVE/advisory metadata.",
                },
                "cves": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Explicit CVE IDs to validate.",
                },
                "aggressive": {
                    "type": "boolean",
                    "default": False,
                    "description": "Required for active runtime probing.",
                },
                "includeScaFallback": {
                    "type": "boolean",
                    "default": True,
                    "description": "Run Retire.js SCA first when no CVE list was supplied.",
                },
                "useNucleiTemplates": {
                    "type": "boolean",
                    "default": True,
                    "description": "Run local Nuclei CVE templates when available.",
                },
                "allowPublicExploitLookup": {
                    "type": "boolean",
                    "default": True,
                    "description": (
                        "Look up public exploit intelligence metadata for each CVE. "
                        "This never downloads or executes exploit code."
                    ),
                },
                "maxExploitReferences": {
                    "type": "integer",
                    "default": 8,
                    "description": "Maximum public exploit/intel references retained per CVE.",
                },
                "sameOriginOnly": {
                    "type": "boolean",
                    "default": True,
                    "description": "Only probe URLs on the target origin.",
                },
                "maxCves": {"type": "integer", "default": DEFAULT_MAX_CVES},
                "maxTargets": {"type": "integer", "default": DEFAULT_MAX_TARGETS},
                "timeoutSeconds": {"type": "integer", "default": DEFAULT_TIMEOUT_SECONDS},
                "cookie": {"type": "string", "x-hidden": True},
                "authCookies": {"type": "string", "x-hidden": True},
                "headers": {"type": "object"},
                "authHeaders": {"type": "object"},
            },
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "exploit-test",
            "phase": 4,
            "domain": ["web", "javascript", "cve", "dast"],
            "input_type": ["url", "urls", "scripts", "cves", "libraries"],
            "output_type": ["findings", "cves", "runtime_validation"],
            "chainable_after": ["sca:", "js:", "browser:", "katana:"],
            "chainable_before": ["curl:", "nuclei:", "code:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        target = normalize_url(parameters.get("target") or parameters.get("url") or "")
        aggressive = _coerce_bool(parameters.get("aggressive"), False)
        max_cves = _bounded_int(parameters.get("maxCves"), DEFAULT_MAX_CVES, 1, 50)
        max_targets = _bounded_int(parameters.get("maxTargets"), DEFAULT_MAX_TARGETS, 1, 20)
        timeout_seconds = _bounded_int(parameters.get("timeoutSeconds"), DEFAULT_TIMEOUT_SECONDS, 20, 600)
        same_origin_only = _coerce_bool(parameters.get("sameOriginOnly"), True)
        use_nuclei_templates = _coerce_bool(parameters.get("useNucleiTemplates"), True)
        include_sca_fallback = _coerce_bool(parameters.get("includeScaFallback"), True)
        allow_public_lookup = _coerce_bool(parameters.get("allowPublicExploitLookup"), True)
        max_exploit_refs = _bounded_int(parameters.get("maxExploitReferences"), 8, 0, 25)
        agent = parameters.get("_agent")

        if not target:
            return {"success": False, "error": "target is required", "tool": self.name}

        if not aggressive:
            return {
                "success": True,
                "skipped": True,
                "reason": "AGGRESSIVE_REQUIRED",
                "tool": self.name,
                "target": target,
                "summary": {
                    "message": "Runtime CVE validation is disabled unless engagement is aggressive/lab/ctf.",
                    "findings": 0,
                },
            }

        cve_records = _collect_cve_records(parameters)
        sca_fallback_output: Optional[Dict[str, Any]] = None
        if not cve_records and include_sca_fallback:
            if agent:
                agent.report_progress("Running SCA fallback before CVE runtime probe", target, 0, None)
            sca_fallback_output = await _run_sca_fallback(parameters, target)
            cve_records = _collect_cve_records(
                {
                    **parameters,
                    "cves": sca_fallback_output.get("cves", []) if sca_fallback_output else [],
                    "libraries": sca_fallback_output.get("libraries", []) if sca_fallback_output else [],
                    "findings": sca_fallback_output.get("findings", []) if sca_fallback_output else [],
                }
            )

        cve_ids = sorted(cve_records.keys())[:max_cves]
        candidate_targets = _candidate_targets(target, parameters, max_targets, same_origin_only)
        scripts = _coerce_string_list(parameters.get("scripts"))
        if sca_fallback_output:
            scripts = dedupe_keep_order(
                [
                    *scripts,
                    *[
                        item.get("url") or item.get("finalUrl") or item.get("scriptUrl") or ""
                        for item in _coerce_list(sca_fallback_output.get("scriptsAnalyzed"))
                        if isinstance(item, dict)
                    ],
                ],
                100,
            )

        public_exploit_intel: Dict[str, Dict[str, Any]] = {}
        if cve_ids and allow_public_lookup and max_exploit_refs > 0:
            if agent:
                agent.report_progress("Looking up public CVE exploit intelligence", target, 0, len(cve_ids))
            public_exploit_intel = await _collect_public_exploit_intel(
                cve_ids,
                max_references=max_exploit_refs,
                timeout_seconds=min(timeout_seconds, 90),
                agent=agent,
            )

        if agent:
            agent.report_progress(
                "Validating CVE runtime exploitability",
                target,
                0,
                max(1, len(cve_ids)),
            )

        findings: List[Dict[str, Any]] = []
        template_results: List[Dict[str, Any]] = []
        templates_available: List[str] = []
        templates_missing: List[str] = []
        contextual_results: List[Dict[str, Any]] = []
        contextual_findings: List[Dict[str, Any]] = []

        if cve_ids and use_nuclei_templates:
            nuclei_binary = shutil.which("nuclei")
            for index, cve_id in enumerate(cve_ids, start=1):
                if agent:
                    agent.report_progress("Running local CVE template probe", cve_id, index, len(cve_ids))
                templates = _find_local_nuclei_templates(cve_id)
                if not nuclei_binary or not templates:
                    templates_missing.append(cve_id)
                    template_results.append(
                        {
                            "cve": cve_id,
                            "status": "template_unavailable",
                            "nucleiAvailable": bool(nuclei_binary),
                        }
                    )
                    continue
                templates_available.append(cve_id)
                for template_path in templates[:3]:
                    for runtime_target in candidate_targets:
                        result, parsed_findings = await _run_nuclei_template(
                            nuclei_binary,
                            template_path,
                            runtime_target,
                            timeout_seconds=max(20, min(timeout_seconds, 180)),
                        )
                        template_results.append(
                            {
                                "cve": cve_id,
                                "target": runtime_target,
                                "template": template_path,
                                "returnCode": result.get("returnCode"),
                                "timedOut": result.get("timedOut"),
                                "findings": len(parsed_findings),
                                **({"stderr": (result.get("stderr") or "")[:600]} if result.get("stderr") else {}),
                            }
                        )
                        for raw in parsed_findings:
                            findings.append(
                                _normalize_nuclei_finding(
                                    raw,
                                    cve_id=cve_id,
                                    target=runtime_target,
                                    template_path=template_path,
                                    cve_record=cve_records.get(cve_id, {}),
                                    public_intel=public_exploit_intel.get(cve_id, {}),
                                )
                            )

        if cve_ids:
            if agent:
                agent.report_progress("Running contextual JavaScript CVE probes", target, 0, len(cve_ids))
            contextual_findings, contextual_results = await _run_contextual_js_cve_probes(
                parameters,
                target=target,
                cve_ids=cve_ids,
                cve_records=cve_records,
                candidate_targets=candidate_targets,
                scripts=scripts,
                public_exploit_intel=public_exploit_intel,
                timeout_seconds=timeout_seconds,
                same_origin_only=same_origin_only,
                agent=agent,
            )
            findings.extend(contextual_findings)

        coverage_by_cve = _build_cve_runtime_coverage(
            cve_ids=cve_ids,
            cve_records=cve_records,
            template_results=template_results,
            contextual_results=contextual_results,
            public_exploit_intel=public_exploit_intel,
        )
        runtime_exploit_validated = any(
            bool((finding.get("evidence") or {}).get("runtimeExploitValidated"))
            for finding in findings
            if isinstance(finding, dict)
        )
        runtime_context_validated = any(
            bool((finding.get("evidence") or {}).get("runtimeContextValidated"))
            for finding in findings
            if isinstance(finding, dict)
        )

        summary = {
            "cvesObserved": len(cve_ids),
            "cvesAnalyzed": len(cve_ids),
            "targetsTested": len(candidate_targets),
            "templatesAvailable": len(set(templates_available)),
            "templatesMissing": len(set(templates_missing)),
            "contextualProbesRun": len(contextual_results),
            "contextualFindings": len(contextual_findings),
            "findings": len(findings),
            "runtimeExploitValidated": runtime_exploit_validated,
            "runtimeContextValidated": runtime_context_validated,
            "externalExploitLookup": False,
            "publicExploitLookup": bool(public_exploit_intel),
            "publicExploitReferences": sum(
                len(item.get("references", [])) for item in public_exploit_intel.values()
            ),
            "cvesWithContextValidated": len(
                [item for item in coverage_by_cve if item.get("runtimeContextValidated")]
            ),
            "cvesWithExploitValidated": len(
                [item for item in coverage_by_cve if item.get("runtimeExploitValidated")]
            ),
            "cvesWithoutRuntimeValidation": len(
                [
                    item
                    for item in coverage_by_cve
                    if not item.get("runtimeContextValidated")
                    and not item.get("runtimeExploitValidated")
                ]
            ),
            "cvesWithContextProbeNoSignal": len(
                [item for item in coverage_by_cve if item.get("status") == "context_probe_no_signal"]
            ),
            "exploitCodeDownloaded": False,
            "scaFallbackUsed": bool(sca_fallback_output),
        }

        if agent:
            agent.append_output(
                "[cve:runtime_probe] "
                f"cves={summary['cvesObserved']} templates={summary['templatesAvailable']} "
                f"findings={summary['findings']} runtimeValidated={summary['runtimeExploitValidated']}"
            )

        return {
            "success": True,
            "tool": self.name,
            "target": target,
            "cves": cve_ids,
            "scripts": scripts[:100],
            "findings": findings[:500],
            "runtimeValidation": {
                "mode": "aggressive",
                "method": "public_exploit_intel_plus_local_nuclei_cve_templates_plus_contextual_js_probes",
                "templateResults": template_results[:300],
                "contextualResults": contextual_results[:100],
                "coverageByCve": coverage_by_cve[:200],
                "templatesMissing": sorted(set(templates_missing)),
                "templatesAvailable": sorted(set(templates_available)),
                "publicExploitIntel": public_exploit_intel,
                "notes": [
                    "Public exploit lookup is metadata-only; the tool does not download or execute external exploit code.",
                    "A runtime exploit finding is emitted only when a bounded runtime probe reports a positive match.",
                    "Contextual JavaScript findings require the vulnerable library to be loaded and a relevant sink or benign reflection signal to be observed on the live target.",
                ],
            },
            "summary": summary,
            **({"scaFallback": sca_fallback_output} if sca_fallback_output else {}),
        }


async def _run_sca_fallback(parameters: Dict[str, Any], target: str) -> Dict[str, Any]:
    from tools.retirejs_scan import RetireJsScanTool

    sca_params = {
        "target": target,
        "url": parameters.get("url"),
        "urls": parameters.get("urls") or [],
        "scripts": parameters.get("scripts") or [],
        "sameOriginOnly": parameters.get("sameOriginOnly", True),
        "maxScripts": min(_bounded_int(parameters.get("maxScripts"), 24, 1, 40), 40),
        "maxBytesPerScript": parameters.get("maxBytesPerScript", 2_000_000),
        "useRetireCli": True,
        "timeoutSeconds": min(_bounded_int(parameters.get("timeoutSeconds"), 90, 10, 180), 180),
        "cookie": parameters.get("cookie"),
        "authCookies": parameters.get("authCookies"),
        "headers": parameters.get("headers"),
        "authHeaders": parameters.get("authHeaders"),
    }
    return await RetireJsScanTool().execute(sca_params)


def _collect_cve_records(parameters: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    records: Dict[str, Dict[str, Any]] = {}
    payloads = [
        parameters.get("cves"),
        parameters.get("libraries"),
        parameters.get("findings"),
        parameters.get("retireFindings"),
        parameters.get("advisories"),
    ]
    for cve_id in _extract_cves(payloads):
        records.setdefault(cve_id, _new_cve_record(cve_id))

    for library in _coerce_list(parameters.get("libraries")):
        if not isinstance(library, dict):
            continue
        lib_cves = _extract_cves([library])
        for cve_id in lib_cves:
            record = records.setdefault(cve_id, _new_cve_record(cve_id))
            package = _compact_package(library)
            if package:
                record["packages"].append(package)
            script = library.get("scriptUrl") or library.get("url") or library.get("sourceUrl")
            if script:
                record["scripts"].append(str(script))
            for advisory in _coerce_list(library.get("advisories") or library.get("vulnerabilities")):
                if isinstance(advisory, dict):
                    record["advisories"].append(_compact_advisory(advisory))

    for finding in _coerce_list(parameters.get("findings")) + _coerce_list(parameters.get("retireFindings")):
        if not isinstance(finding, dict):
            continue
        for cve_id in _extract_cves([finding]):
            record = records.setdefault(cve_id, _new_cve_record(cve_id))
            evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
            info = finding.get("info") if isinstance(finding.get("info"), dict) else {}
            package = _compact_package(
                {
                    "name": evidence.get("packageName") or _package_from_title(str(info.get("name") or ""))[0],
                    "version": evidence.get("packageVersion") or _package_from_title(str(info.get("name") or ""))[1],
                    "scriptUrl": evidence.get("scriptUrl") or finding.get("matched-at") or finding.get("matched"),
                    "source": "retirejs-finding",
                }
            )
            if package:
                record["packages"].append(package)
            script = evidence.get("scriptUrl") or finding.get("matched-at") or finding.get("matched")
            if script:
                record["scripts"].append(str(script))
            for ref in _coerce_string_list(info.get("reference") or evidence.get("references")):
                record["references"].append(ref)
            for advisory in _coerce_list(evidence.get("advisories")):
                if isinstance(advisory, dict):
                    record["advisories"].append(_compact_advisory(advisory))
                    for ref in _coerce_string_list(advisory.get("references")):
                        record["references"].append(ref)
            summary = info.get("description") or info.get("name")
            if summary:
                record["summaries"].append(str(summary))

    for record in records.values():
        record["packages"] = _dedupe_dicts(record.get("packages", []))
        record["scripts"] = dedupe_keep_order(record.get("scripts", []), 50)
        record["references"] = dedupe_keep_order(record.get("references", []), 50)
        record["advisories"] = _dedupe_dicts(record.get("advisories", []))
        record["summaries"] = dedupe_keep_order(record.get("summaries", []), 50)
    return records


def _new_cve_record(cve_id: str) -> Dict[str, Any]:
    return {"cve": cve_id, "packages": [], "scripts": [], "references": [], "advisories": [], "summaries": []}


async def _collect_public_exploit_intel(
    cve_ids: List[str],
    *,
    max_references: int,
    timeout_seconds: int,
    agent: Any = None,
) -> Dict[str, Dict[str, Any]]:
    output: Dict[str, Dict[str, Any]] = {}
    searchsploit_available = shutil.which("searchsploit")
    connector = aiohttp.TCPConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=max(10, timeout_seconds), connect=8, sock_read=12)
    headers = {
        "User-Agent": "xASM-CVERuntimeProbe/1.0",
        "Accept": "application/vnd.github+json, application/json;q=0.9, */*;q=0.8",
    }
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
        for index, cve_id in enumerate(cve_ids, start=1):
            if agent:
                agent.report_progress("Collecting public exploit metadata", cve_id, index, len(cve_ids))
            references: List[Dict[str, Any]] = []
            references.extend(await _searchsploit_refs(searchsploit_available, cve_id, max_references))
            references.extend(await _nvd_refs(session, cve_id, max_references))
            references.extend(await _github_poc_refs(session, cve_id, max_references))
            references = _dedupe_reference_dicts(references, max_references)
            maturity = _exploit_maturity(references)
            output[cve_id] = {
                "cve": cve_id,
                "references": references,
                "exploitMaturity": maturity,
                "metadataOnly": True,
                "downloadedCode": False,
                "executedCode": False,
                "automaticExecutionPolicy": (
                    "Only bounded built-in probes and local scanner templates may execute. "
                    "Public PoC code is never downloaded or executed automatically."
                ),
            }
    return output


async def _searchsploit_refs(
    searchsploit_binary: Optional[str],
    cve_id: str,
    max_references: int,
) -> List[Dict[str, Any]]:
    if not searchsploit_binary or max_references <= 0:
        return []
    result = await run_process([searchsploit_binary, "--cve", cve_id, "--json"], timeout=20)
    raw = result.get("stdout") or ""
    try:
        parsed = json.loads(raw) if raw.strip() else {}
    except Exception:
        return []
    rows = []
    for key in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE", "results"):
        value = parsed.get(key) if isinstance(parsed, dict) else None
        if isinstance(value, list):
            rows.extend(value)
    refs: List[Dict[str, Any]] = []
    for row in rows[:max_references]:
        if not isinstance(row, dict):
            continue
        path = row.get("Path") or row.get("path")
        refs.append(
            {
                "source": "searchsploit",
                "title": row.get("Title") or row.get("title") or cve_id,
                "url": f"local-searchsploit:{path}" if path else "",
                "type": "public_exploit_index",
                "risk": "manual_review_required",
            }
        )
    return refs


async def _nvd_refs(
    session: aiohttp.ClientSession,
    cve_id: str,
    max_references: int,
) -> List[Dict[str, Any]]:
    if max_references <= 0:
        return []
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        async with session.get(url) as response:
            if response.status >= 400:
                return []
            parsed = await response.json(content_type=None)
    except Exception:
        return []
    refs: List[Dict[str, Any]] = []
    vulnerabilities = parsed.get("vulnerabilities") if isinstance(parsed, dict) else []
    for item in _coerce_list(vulnerabilities):
        cve = item.get("cve") if isinstance(item, dict) else {}
        raw_refs: Any = []
        if isinstance(cve, dict):
            references_value = cve.get("references")
            if isinstance(references_value, dict):
                raw_refs = references_value.get("referenceData") or []
            elif isinstance(references_value, list):
                raw_refs = references_value
        for ref in _coerce_list(raw_refs):
            if not isinstance(ref, dict):
                continue
            ref_url = str(ref.get("url") or "")
            tags = [str(tag).lower() for tag in _coerce_list(ref.get("tags"))]
            ref_type = "reference"
            if any(tag in {"exploit", "proof-of-concept", "third-party-advisory"} for tag in tags):
                ref_type = "public_exploit_reference"
            refs.append(
                {
                    "source": "nvd",
                    "title": ref.get("source") or ref_url,
                    "url": ref_url,
                    "tags": tags,
                    "type": ref_type,
                    "risk": "metadata_only",
                }
            )
            if len(refs) >= max_references:
                return refs
    return refs


async def _github_poc_refs(
    session: aiohttp.ClientSession,
    cve_id: str,
    max_references: int,
) -> List[Dict[str, Any]]:
    if max_references <= 0:
        return []
    query = f"{cve_id} poc exploit"
    url = "https://api.github.com/search/repositories"
    try:
        async with session.get(url, params={"q": query, "sort": "updated", "order": "desc", "per_page": min(max_references, 10)}) as response:
            if response.status >= 400:
                return []
            parsed = await response.json(content_type=None)
    except Exception:
        return []
    refs: List[Dict[str, Any]] = []
    for item in _coerce_list(parsed.get("items") if isinstance(parsed, dict) else []):
        if not isinstance(item, dict):
            continue
        refs.append(
            {
                "source": "github",
                "title": item.get("full_name") or item.get("name") or cve_id,
                "url": item.get("html_url") or "",
                "description": item.get("description") or "",
                "stars": item.get("stargazers_count"),
                "updatedAt": item.get("updated_at"),
                "type": "public_poc_repository",
                "risk": "manual_review_required",
            }
        )
    return refs


def _dedupe_reference_dicts(values: Iterable[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    seen = set()
    output: List[Dict[str, Any]] = []
    for value in values:
        url = str(value.get("url") or "")
        title = str(value.get("title") or "")
        key = (url.lower(), title.lower(), str(value.get("source") or ""))
        if not url and not title:
            continue
        if key in seen:
            continue
        seen.add(key)
        output.append(value)
        if len(output) >= limit:
            break
    return output


def _exploit_maturity(references: List[Dict[str, Any]]) -> str:
    if not references:
        return "none_found"
    has_local = any(ref.get("source") == "searchsploit" for ref in references)
    has_github = any(ref.get("source") == "github" for ref in references)
    has_exploit_tag = any("exploit" in _coerce_string_list(ref.get("tags")) for ref in references)
    if has_local or has_exploit_tag:
        return "public_exploit_indexed"
    if has_github:
        return "public_poc_candidate"
    return "public_references_only"


def _candidate_targets(
    target: str,
    parameters: Dict[str, Any],
    max_targets: int,
    same_origin_only: bool,
) -> List[str]:
    candidates = [target]
    for value in _coerce_string_list(parameters.get("urls")):
        url = urljoin(target, value)
        if same_origin_only and not same_origin(target, url):
            continue
        candidates.append(_origin_root(url))
        candidates.append(url)
    for value in _coerce_string_list(parameters.get("scripts")):
        url = urljoin(target, value)
        if same_origin_only and not same_origin(target, url):
            continue
        candidates.append(_origin_root(url))
    return dedupe_keep_order([normalize_url(item) for item in candidates if item], max_targets)


def _find_local_nuclei_templates(cve_id: str) -> List[str]:
    year_match = re.match(r"CVE-(\d{4})-\d{4,}$", cve_id, re.I)
    year = year_match.group(1) if year_match else ""
    roots = dedupe_keep_order(
        [
            os.environ.get("NUCLEI_TEMPLATES_DIR", ""),
            "/root/nuclei-templates",
            "/home/agent/nuclei-templates",
            "/opt/nuclei-templates",
            os.path.expanduser("~/nuclei-templates"),
        ]
    )
    exact_suffixes = [
        f"http/cves/{year}/{cve_id}.yaml",
        f"http/cves/{year}/{cve_id.lower()}.yaml",
        f"cves/{year}/{cve_id}.yaml",
        f"cves/{year}/{cve_id.lower()}.yaml",
    ]
    matches: List[str] = []
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for suffix in exact_suffixes:
            path = os.path.join(root, suffix)
            if os.path.isfile(path):
                matches.append(path)
        if not matches:
            for pattern in (
                os.path.join(root, "http", "cves", year, f"*{cve_id}*.yaml"),
                os.path.join(root, "**", f"*{cve_id}*.yaml"),
                os.path.join(root, "**", f"*{cve_id.lower()}*.yaml"),
            ):
                matches.extend(glob.glob(pattern, recursive=True)[:8])
    return dedupe_keep_order(matches, 10)


async def _run_nuclei_template(
    nuclei_binary: str,
    template_path: str,
    target: str,
    *,
    timeout_seconds: int,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    base = [
        nuclei_binary,
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-t",
        template_path,
        "-u",
        target,
        "-timeout",
        "8",
        "-retries",
        "0",
        "-rate-limit",
        "5",
    ]
    variants = [
        ["-jsonl", "-include-rr"],
        ["-jsonl"],
        ["-json", "-include-rr"],
        ["-json"],
    ]
    last_result: Dict[str, Any] = {}
    for flags in variants:
        result = await run_process([*base, *flags], timeout=timeout_seconds)
        last_result = result
        stderr = (result.get("stderr") or "").lower()
        if result.get("returnCode") not in (0, None) and (
            "unknown flag" in stderr or "unknown shorthand" in stderr or "flag provided but not defined" in stderr
        ):
            continue
        return result, _parse_nuclei_json_lines(result.get("stdout") or "")
    return last_result, _parse_nuclei_json_lines(last_result.get("stdout") or "")


def _parse_nuclei_json_lines(raw: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except Exception:
            continue
        if isinstance(parsed, dict):
            findings.append(parsed)
    return findings


def _normalize_nuclei_finding(
    raw: Dict[str, Any],
    *,
    cve_id: str,
    target: str,
    template_path: str,
    cve_record: Dict[str, Any],
    public_intel: Dict[str, Any],
) -> Dict[str, Any]:
    info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
    template_id = (
        raw.get("template-id")
        or raw.get("templateID")
        or raw.get("template")
        or f"cve-runtime-{cve_id.lower()}"
    )
    safe_template_id = _safe_id(str(template_id))
    matched_at = raw.get("matched-at") or raw.get("matched") or raw.get("host") or target
    name = info.get("name") or f"Runtime CVE validation: {cve_id}"
    severity = str(info.get("severity") or "medium").lower()
    public_refs = [
        ref.get("url")
        for ref in _coerce_list(public_intel.get("references"))
        if isinstance(ref, dict) and ref.get("url") and str(ref.get("url")).startswith("http")
    ]
    references = dedupe_keep_order(
        [
            *(_coerce_string_list(info.get("reference")) or []),
            *(cve_record.get("references", []) or []),
            *public_refs,
        ],
        20,
    )
    cves = _coerce_string_list(info.get("cve")) or [cve_id]
    request = raw.get("request") or raw.get("curl-command") or _request_line(str(matched_at))
    response = raw.get("response") or raw.get("extracted-results") or raw.get("matcher-status")
    matched_content = _format_matched_content(cve_id, cve_record, raw)
    return {
        "template-id": f"cve-runtime-{safe_template_id}",
        "templateID": f"cve-runtime-{safe_template_id}",
        "host": raw.get("host") or target,
        "matched": raw.get("matched") or matched_at,
        "matched-at": matched_at,
        "matcher-name": raw.get("matcher-name") or "local-nuclei-cve-template",
        "extracted-results": _coerce_string_list(raw.get("extracted-results")) or [cve_id],
        "info": {
            "name": f"Runtime validated CVE: {name}",
            "description": (
                f"Local runtime probe for {cve_id} matched the live target using a "
                "bounded CVE template. This upgrades the dependency signal from a "
                "package-version hypothesis to runtime evidence."
            ),
            "severity": severity,
            "remediation": (
                "Apply the vendor fix for the affected component and retest the runtime path. "
                "If this came from a client-side dependency, rebuild and redeploy the bundle."
            ),
            "reference": references,
            "cve": cves,
            "classification": {"cve-id": cves},
            "tags": dedupe_keep_order(
                [
                    "cve",
                    "runtime-validation",
                    "agentic",
                    "nuclei",
                    *[
                        str(pkg.get("name") or "").lower()
                        for pkg in cve_record.get("packages", [])
                        if isinstance(pkg, dict) and pkg.get("name")
                    ],
                ]
            ),
        },
        "evidence": {
            "cveId": cve_id,
            "runtimeExploitValidated": True,
            "runtimeProbeType": "local_nuclei_cve_template",
            "templatePath": template_path,
            "target": target,
            "packages": cve_record.get("packages", []),
            "scripts": cve_record.get("scripts", []),
            "request": _stringify_evidence(request, 6000),
            "response": _stringify_evidence(response, 8000),
            "matchedContent": matched_content,
            "externalExploitLookup": False,
            "publicExploitIntel": public_intel,
            "publicExploitLookup": bool(public_intel),
            "exploitCodeDownloaded": False,
        },
    }


def _build_cve_runtime_coverage(
    *,
    cve_ids: List[str],
    cve_records: Dict[str, Dict[str, Any]],
    template_results: List[Dict[str, Any]],
    contextual_results: List[Dict[str, Any]],
    public_exploit_intel: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    coverage: List[Dict[str, Any]] = []
    for cve_id in cve_ids:
        record = cve_records.get(cve_id, {})
        cve_template_results = [
            result for result in template_results if str(result.get("cve") or "").upper() == cve_id.upper()
        ]
        cve_context_results = [
            result
            for result in contextual_results
            if cve_id.upper() in {item.upper() for item in _coerce_string_list(result.get("cves"))}
        ]
        template_matched = any(int(result.get("findings") or 0) > 0 for result in cve_template_results)
        template_unavailable = bool(cve_template_results) and all(
            result.get("status") == "template_unavailable" for result in cve_template_results
        )
        runtime_exploit_validated = any(
            bool(result.get("runtimeExploitValidated")) for result in cve_context_results
        ) or template_matched
        runtime_context_validated = runtime_exploit_validated or any(
            bool(result.get("runtimeContextValidated")) for result in cve_context_results
        )
        builtin_probe_families = dedupe_keep_order(
            [
                str(result.get("probe") or "")
                for result in cve_context_results
                if result.get("probe")
            ],
            10,
        )
        if runtime_exploit_validated:
            status = "runtime_exploit_validated"
        elif runtime_context_validated:
            status = "runtime_context_validated"
        elif builtin_probe_families:
            status = "context_probe_no_signal"
        else:
            status = "not_runtime_validated"

        coverage.append(
            {
                "cve": cve_id,
                "status": status,
                "packages": record.get("packages", []),
                "scripts": record.get("scripts", [])[:10],
                "templateStatus": (
                    "matched"
                    if template_matched
                    else "unavailable"
                    if template_unavailable
                    else "not_run"
                    if not cve_template_results
                    else "no_match"
                ),
                "templateResults": cve_template_results[:8],
                "contextualProbeFamilies": builtin_probe_families,
                "contextualResults": cve_context_results[:8],
                "runtimeContextValidated": runtime_context_validated,
                "runtimeExploitValidated": runtime_exploit_validated,
                "publicExploitReferenceCount": len(
                    _coerce_list((public_exploit_intel.get(cve_id) or {}).get("references"))
                ),
                "exploitMaturity": (public_exploit_intel.get(cve_id) or {}).get("exploitMaturity", "not_looked_up"),
                "reason": _coverage_reason(
                    cve_id=cve_id,
                    status=status,
                    template_unavailable=template_unavailable,
                    builtin_probe_families=builtin_probe_families,
                    public_reference_count=len(
                        _coerce_list((public_exploit_intel.get(cve_id) or {}).get("references"))
                    ),
                ),
            }
        )
    return coverage


def _coverage_reason(
    *,
    cve_id: str,
    status: str,
    template_unavailable: bool,
    builtin_probe_families: List[str],
    public_reference_count: int,
) -> str:
    if status == "runtime_exploit_validated":
        return "A bounded local runtime probe produced positive request/response evidence."
    if status == "runtime_context_validated":
        return "The vulnerable package is loaded and the live runtime exposes compatible sinks, but no benign probe proved exploit execution."
    if status == "context_probe_no_signal":
        return "A built-in contextual probe ran but did not observe a compatible live sink or reflection signal."
    if template_unavailable and public_reference_count:
        return (
            f"No local Nuclei template or built-in runtime probe validated {cve_id}; "
            "public exploit intelligence was retained as metadata for analyst follow-up."
        )
    if template_unavailable:
        return f"No local Nuclei template or built-in runtime probe is available for {cve_id}."
    if builtin_probe_families:
        return "Contextual probes ran but did not produce a runtime validation finding."
    return "No matching local template or built-in contextual probe was selected for this CVE."


async def _run_contextual_js_cve_probes(
    parameters: Dict[str, Any],
    *,
    target: str,
    cve_ids: List[str],
    cve_records: Dict[str, Dict[str, Any]],
    candidate_targets: List[str],
    scripts: List[str],
    public_exploit_intel: Dict[str, Dict[str, Any]],
    timeout_seconds: int,
    same_origin_only: bool,
    agent: Any = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Run built-in contextual probes for CVEs that need app-specific evidence."""

    findings: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []

    bootstrap_cves = [
        cve_id
        for cve_id in cve_ids
        if _is_bootstrap_xss_cve(cve_id, cve_records.get(cve_id, {}))
    ]
    if bootstrap_cves:
        if agent:
            agent.report_progress(
                "Running Bootstrap contextual XSS probe",
                target,
                1,
                1,
            )
        bootstrap_findings, bootstrap_results = await _probe_bootstrap_xss_context(
            parameters,
            target=target,
            cve_ids=bootstrap_cves,
            cve_records=cve_records,
            candidate_targets=candidate_targets,
            scripts=scripts,
            public_exploit_intel=public_exploit_intel,
            timeout_seconds=timeout_seconds,
            same_origin_only=same_origin_only,
        )
        findings.extend(bootstrap_findings)
        results.extend(bootstrap_results)

    angularjs_cves = [
        cve_id
        for cve_id in cve_ids
        if _is_angularjs_runtime_cve(cve_id, cve_records.get(cve_id, {}))
    ]
    if angularjs_cves:
        if agent:
            agent.report_progress(
                "Running AngularJS contextual runtime probe",
                target,
                1,
                1,
            )
        angular_findings, angular_results = await _probe_angularjs_runtime_context(
            parameters,
            target=target,
            cve_ids=angularjs_cves,
            cve_records=cve_records,
            candidate_targets=candidate_targets,
            scripts=scripts,
            public_exploit_intel=public_exploit_intel,
            timeout_seconds=timeout_seconds,
            same_origin_only=same_origin_only,
        )
        findings.extend(angular_findings)
        results.extend(angular_results)

    dompurify_cves = [
        cve_id
        for cve_id in cve_ids
        if _is_dompurify_runtime_cve(cve_id, cve_records.get(cve_id, {}))
    ]
    if dompurify_cves:
        if agent:
            agent.report_progress(
                "Running DOMPurify contextual runtime probe",
                target,
                1,
                1,
            )
        dompurify_findings, dompurify_results = await _probe_dompurify_runtime_context(
            parameters,
            target=target,
            cve_ids=dompurify_cves,
            cve_records=cve_records,
            candidate_targets=candidate_targets,
            scripts=scripts,
            public_exploit_intel=public_exploit_intel,
            timeout_seconds=timeout_seconds,
            same_origin_only=same_origin_only,
        )
        findings.extend(dompurify_findings)
        results.extend(dompurify_results)

    return findings, results


async def _probe_bootstrap_xss_context(
    parameters: Dict[str, Any],
    *,
    target: str,
    cve_ids: List[str],
    cve_records: Dict[str, Dict[str, Any]],
    candidate_targets: List[str],
    scripts: List[str],
    public_exploit_intel: Dict[str, Dict[str, Any]],
    timeout_seconds: int,
    same_origin_only: bool,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    headers = parse_headers(parameters)
    page_urls = _page_candidate_urls(target, candidate_targets, parameters, same_origin_only)
    seed_script_urls = _script_candidate_urls(target, scripts, cve_ids, cve_records, same_origin_only)
    fetched_pages: List[Dict[str, Any]] = []
    fetched_scripts: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []

    connector = aiohttp.TCPConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=max(20, min(timeout_seconds, 120)), connect=8, sock_read=20)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
        for page_url in page_urls[:BOOTSTRAP_CONTEXT_PAGE_LIMIT]:
            fetched = await _safe_fetch_text(session, page_url, headers=headers, max_bytes=800_000)
            if not fetched:
                results.append({"probe": "bootstrap-xss-context", "url": page_url, "status": "fetch_failed"})
                continue
            fetched_pages.append({"requestedUrl": page_url, **fetched})
            mapped = extract_html_map(fetched.get("text") or "", fetched.get("url") or page_url, max_items=80)
            seed_script_urls.extend(mapped.get("scripts") or [])

        script_urls = dedupe_keep_order(
            [
                url
                for url in seed_script_urls
                if _looks_like_javascript_url(url)
                and (not same_origin_only or same_origin(target, url))
            ],
            BOOTSTRAP_CONTEXT_SCRIPT_LIMIT,
        )
        for script_url in script_urls:
            fetched = await _safe_fetch_text(session, script_url, headers=headers, max_bytes=900_000)
            if fetched:
                fetched_scripts.append({"requestedUrl": script_url, **fetched})

        reflection_proofs = await _probe_bootstrap_marker_reflection(
            session,
            page_urls[: min(6, BOOTSTRAP_CONTEXT_PAGE_LIMIT)],
            headers=headers,
        )

    context = _detect_bootstrap_xss_context(
        target=target,
        cve_ids=cve_ids,
        cve_records=cve_records,
        pages=fetched_pages,
        scripts=fetched_scripts,
        reflection_proofs=reflection_proofs,
    )
    results.append(context)

    if not context.get("findingCandidate"):
        return [], results

    finding = _normalize_bootstrap_context_finding(
        target=target,
        cve_ids=cve_ids,
        cve_records=cve_records,
        context=context,
        public_exploit_intel=public_exploit_intel,
    )
    return [finding], results


async def _probe_angularjs_runtime_context(
    parameters: Dict[str, Any],
    *,
    target: str,
    cve_ids: List[str],
    cve_records: Dict[str, Dict[str, Any]],
    candidate_targets: List[str],
    scripts: List[str],
    public_exploit_intel: Dict[str, Dict[str, Any]],
    timeout_seconds: int,
    same_origin_only: bool,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    headers = parse_headers(parameters)
    page_urls = _page_candidate_urls(target, candidate_targets, parameters, same_origin_only)
    seed_script_urls = _script_candidate_urls(target, scripts, cve_ids, cve_records, same_origin_only)
    fetched_pages: List[Dict[str, Any]] = []
    fetched_scripts: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []

    connector = aiohttp.TCPConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=max(20, min(timeout_seconds, 120)), connect=8, sock_read=20)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
        for page_url in page_urls[:ANGULARJS_CONTEXT_PAGE_LIMIT]:
            fetched = await _safe_fetch_text(session, page_url, headers=headers, max_bytes=900_000)
            if not fetched:
                results.append({"probe": "angularjs-runtime-context", "url": page_url, "status": "fetch_failed"})
                continue
            fetched_pages.append({"requestedUrl": page_url, **fetched})
            mapped = extract_html_map(fetched.get("text") or "", fetched.get("url") or page_url, max_items=100)
            seed_script_urls.extend(mapped.get("scripts") or [])

        script_urls = dedupe_keep_order(
            [
                url
                for url in seed_script_urls
                if _looks_like_javascript_url(url)
                and (not same_origin_only or same_origin(target, url))
            ],
            ANGULARJS_CONTEXT_SCRIPT_LIMIT,
        )
        for script_url in script_urls:
            fetched = await _safe_fetch_text(session, script_url, headers=headers, max_bytes=1_200_000)
            if fetched:
                fetched_scripts.append({"requestedUrl": script_url, **fetched})

        reflection_proofs = await _probe_angular_marker_reflection(
            session,
            page_urls[: min(6, ANGULARJS_CONTEXT_PAGE_LIMIT)],
            headers=headers,
        )

    context = _detect_angularjs_runtime_context(
        target=target,
        cve_ids=cve_ids,
        cve_records=cve_records,
        pages=fetched_pages,
        scripts=fetched_scripts,
        reflection_proofs=reflection_proofs,
    )
    results.append(context)

    if not context.get("findingCandidate"):
        return [], results

    finding = _normalize_angularjs_context_finding(
        target=target,
        cve_ids=cve_ids,
        cve_records=cve_records,
        context=context,
        public_exploit_intel=public_exploit_intel,
    )
    return [finding], results


async def _probe_dompurify_runtime_context(
    parameters: Dict[str, Any],
    *,
    target: str,
    cve_ids: List[str],
    cve_records: Dict[str, Dict[str, Any]],
    candidate_targets: List[str],
    scripts: List[str],
    public_exploit_intel: Dict[str, Dict[str, Any]],
    timeout_seconds: int,
    same_origin_only: bool,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    headers = parse_headers(parameters)
    page_urls = _page_candidate_urls(target, candidate_targets, parameters, same_origin_only)
    seed_script_urls = _script_candidate_urls(target, scripts, cve_ids, cve_records, same_origin_only)
    fetched_pages: List[Dict[str, Any]] = []
    fetched_scripts: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []

    connector = aiohttp.TCPConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=max(20, min(timeout_seconds, 120)), connect=8, sock_read=20)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
        for page_url in page_urls[:DOMPURIFY_CONTEXT_PAGE_LIMIT]:
            fetched = await _safe_fetch_text(session, page_url, headers=headers, max_bytes=900_000)
            if not fetched:
                results.append({"probe": "dompurify-runtime-context", "url": page_url, "status": "fetch_failed"})
                continue
            fetched_pages.append({"requestedUrl": page_url, **fetched})
            mapped = extract_html_map(fetched.get("text") or "", fetched.get("url") or page_url, max_items=120)
            seed_script_urls.extend(mapped.get("scripts") or [])

        script_urls = dedupe_keep_order(
            [
                url
                for url in seed_script_urls
                if _looks_like_javascript_url(url)
                and (not same_origin_only or same_origin(target, url))
            ],
            DOMPURIFY_CONTEXT_SCRIPT_LIMIT,
        )
        for script_url in script_urls:
            fetched = await _safe_fetch_text(session, script_url, headers=headers, max_bytes=1_500_000)
            if fetched:
                fetched_scripts.append({"requestedUrl": script_url, **fetched})

    context = _detect_dompurify_runtime_context(
        target=target,
        cve_ids=cve_ids,
        cve_records=cve_records,
        pages=fetched_pages,
        scripts=fetched_scripts,
    )
    results.append(context)

    if not context.get("findingCandidate"):
        return [], results

    finding = _normalize_dompurify_context_finding(
        target=target,
        cve_ids=cve_ids,
        cve_records=cve_records,
        context=context,
        public_exploit_intel=public_exploit_intel,
    )
    return [finding], results


async def _safe_fetch_text(
    session: aiohttp.ClientSession,
    url: str,
    *,
    headers: Dict[str, str],
    max_bytes: int,
) -> Optional[Dict[str, Any]]:
    try:
        fetched = await fetch_text(session, url, headers=headers, max_bytes=max_bytes)
    except Exception as exc:
        return {"url": url, "status": 0, "headers": {}, "text": "", "error": str(exc), "truncated": False}
    if not fetched or int(fetched.get("status") or 0) >= 500:
        return fetched
    return fetched


async def _probe_bootstrap_marker_reflection(
    session: aiohttp.ClientSession,
    page_urls: List[str],
    *,
    headers: Dict[str, str],
) -> List[Dict[str, Any]]:
    marker = "xasm_bootstrap_probe_7d6f8c"
    proofs: List[Dict[str, Any]] = []
    for page_url in page_urls:
        probe_url = _url_with_probe_marker(page_url, marker)
        if not probe_url:
            continue
        fetched = await _safe_fetch_text(session, probe_url, headers=headers, max_bytes=500_000)
        if not fetched:
            continue
        text = fetched.get("text") or ""
        if marker not in text:
            proofs.append(
                {
                    "url": probe_url,
                    "status": fetched.get("status"),
                    "marker": marker,
                    "reflected": False,
                }
            )
            continue
        proofs.append(
            {
                "url": probe_url,
                "status": fetched.get("status"),
                "marker": marker,
                "reflected": True,
                "unsafeBootstrapContext": any(
                    _is_strong_bootstrap_xss_signal(signal)
                    for signal in _bootstrap_html_signals(text, fetched.get("url") or probe_url)
                ),
                "responseExcerpt": _excerpt_around(text, marker, 1200),
                "request": _request_line(probe_url),
            }
        )
    return proofs


async def _probe_angular_marker_reflection(
    session: aiohttp.ClientSession,
    page_urls: List[str],
    *,
    headers: Dict[str, str],
) -> List[Dict[str, Any]]:
    marker = "xasm_angular_probe_1c9d2e"
    proofs: List[Dict[str, Any]] = []
    for page_url in page_urls:
        probe_url = _url_with_probe_marker(page_url, marker)
        if not probe_url:
            continue
        fetched = await _safe_fetch_text(session, probe_url, headers=headers, max_bytes=500_000)
        if not fetched:
            continue
        text = fetched.get("text") or ""
        reflected = marker in text
        angular_signals = _angular_html_signals(text, fetched.get("url") or probe_url)
        proofs.append(
            {
                "url": probe_url,
                "status": fetched.get("status"),
                "marker": marker,
                "reflected": reflected,
                "angularContext": reflected and bool(angular_signals),
                "runtimeExploitValidated": False,
                "request": _request_line(probe_url),
                "responseExcerpt": _excerpt_around(text, marker, 1200) if reflected else "",
                "angularSignals": angular_signals[:5],
            }
        )
    return proofs


def _detect_bootstrap_xss_context(
    *,
    target: str,
    cve_ids: List[str],
    cve_records: Dict[str, Dict[str, Any]],
    pages: List[Dict[str, Any]],
    scripts: List[Dict[str, Any]],
    reflection_proofs: List[Dict[str, Any]],
) -> Dict[str, Any]:
    page_signals: List[Dict[str, Any]] = []
    script_signals: List[Dict[str, Any]] = []
    bootstrap_scripts: List[Dict[str, Any]] = []

    for page in pages:
        html = page.get("text") or ""
        page_url = page.get("url") or page.get("requestedUrl") or target
        page_signals.extend(_bootstrap_html_signals(html, page_url))

    for script in scripts:
        text = script.get("text") or ""
        script_url = script.get("url") or script.get("requestedUrl") or ""
        if _script_looks_like_bootstrap(text, script_url):
            bootstrap_scripts.append(
                {
                    "url": script_url,
                    "version": _detect_bootstrap_version(text, script_url),
                    "status": script.get("status"),
                }
            )
        script_signals.extend(_bootstrap_js_signals(text, script_url))

    reflected_unsafe = [
        proof
        for proof in reflection_proofs
        if proof.get("reflected") and proof.get("unsafeBootstrapContext")
    ]
    unsafe_html_signals = [
        signal
        for signal in page_signals + script_signals
        if _is_strong_bootstrap_xss_signal(signal)
    ]
    loaded_vulnerable_package = bool(bootstrap_scripts) or any(
        _record_has_bootstrap_package(cve_records.get(cve_id, {})) for cve_id in cve_ids
    )
    finding_candidate = loaded_vulnerable_package and (bool(reflected_unsafe) or bool(unsafe_html_signals))

    confidence = 0
    if loaded_vulnerable_package:
        confidence += 30
    if unsafe_html_signals:
        confidence += 30
    if reflected_unsafe:
        confidence += 35
    if page_signals or script_signals:
        confidence += 5
    confidence = min(confidence, 95)

    return {
        "probe": "bootstrap-xss-context",
        "target": target,
        "cves": cve_ids,
        "status": "finding_candidate" if finding_candidate else "no_runtime_context",
        "findingCandidate": finding_candidate,
        "loadedVulnerablePackage": loaded_vulnerable_package,
        "runtimeExploitValidated": bool(reflected_unsafe),
        "runtimeContextValidated": bool(finding_candidate),
        "confidence": confidence,
        "pagesFetched": len(pages),
        "scriptsFetched": len(scripts),
        "bootstrapScripts": bootstrap_scripts[:10],
        "pageSignals": page_signals[:20],
        "scriptSignals": script_signals[:20],
        "reflectionProofs": reflection_proofs[:12],
        "strongSignals": reflected_unsafe[:5] or unsafe_html_signals[:5],
    }


def _bootstrap_html_signals(html: str, page_url: str) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []
    for tag in re.findall(r"<[^>]+data-(?:bs-)?toggle\s*=\s*['\"](?:tooltip|popover)['\"][^>]*>", html, re.I | re.S):
        toggle = _extract_attr_inline(tag, "data-toggle") or _extract_attr_inline(tag, "data-bs-toggle") or ""
        data_html = (_extract_attr_inline(tag, "data-html") or _extract_attr_inline(tag, "data-bs-html") or "").lower()
        data_sanitize = (
            _extract_attr_inline(tag, "data-sanitize")
            or _extract_attr_inline(tag, "data-bs-sanitize")
            or ""
        ).lower()
        has_content = bool(
            _extract_attr_inline(tag, "data-content")
            or _extract_attr_inline(tag, "data-bs-content")
            or _extract_attr_inline(tag, "title")
            or _extract_attr_inline(tag, "data-original-title")
        )
        signals.append(
            {
                "source": "html",
                "url": page_url,
                "component": toggle.lower(),
                "unsafeHtml": data_html == "true",
                "sanitizeDisabled": data_sanitize == "false",
                "untrustedContentSink": has_content,
                "snippet": _clip(tag, 500),
            }
        )
    return signals


def _bootstrap_js_signals(text: str, script_url: str) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []
    for match in re.finditer(r"\.(tooltip|popover)\s*\((?P<args>.{0,600})", text, re.I | re.S):
        component = match.group(1).lower()
        args = match.group("args") or ""
        unsafe_html = bool(re.search(r"\bhtml\s*:\s*true\b", args, re.I))
        sanitize_disabled = bool(re.search(r"\bsanitize\s*:\s*false\b", args, re.I))
        content_sink = bool(re.search(r"\b(content|title)\s*:\s*(?:function|[^,}]+location|[^,}]+document|[^,}]+innerHTML)", args, re.I))
        if unsafe_html or sanitize_disabled or content_sink:
            signals.append(
                {
                    "source": "javascript",
                    "url": script_url,
                    "component": component,
                    "unsafeHtml": unsafe_html,
                    "sanitizeDisabled": sanitize_disabled,
                    "untrustedContentSink": content_sink,
                    "snippet": _clip(match.group(0), 800),
                }
            )
    return signals


def _is_strong_bootstrap_xss_signal(signal: Dict[str, Any]) -> bool:
    if not isinstance(signal, dict):
        return False
    if signal.get("sanitizeDisabled"):
        return True
    return bool(signal.get("unsafeHtml") and signal.get("untrustedContentSink"))


def _normalize_bootstrap_context_finding(
    *,
    target: str,
    cve_ids: List[str],
    cve_records: Dict[str, Dict[str, Any]],
    context: Dict[str, Any],
    public_exploit_intel: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    runtime_exploit_validated = bool(context.get("runtimeExploitValidated"))
    primary_cve = cve_ids[0] if cve_ids else "CVE-UNKNOWN"
    package_label = _package_label_for_cves(cve_ids, cve_records) or "bootstrap"
    strong_signal = (context.get("strongSignals") or [{}])[0]
    matched_at = (
        strong_signal.get("url")
        or (context.get("bootstrapScripts") or [{}])[0].get("url")
        or target
    )
    severity = "high" if runtime_exploit_validated else "medium"
    request = strong_signal.get("request") or _request_line(str(matched_at))
    response = (
        strong_signal.get("responseExcerpt")
        or strong_signal.get("snippet")
        or _format_bootstrap_context_content(context, package_label)
    )
    references = dedupe_keep_order(
        [
            *[
                ref
                for cve_id in cve_ids
                for ref in _record_references(cve_records.get(cve_id, {}))
            ],
            *[
                ref.get("url")
                for cve_id in cve_ids
                for ref in _coerce_list((public_exploit_intel.get(cve_id, {}) or {}).get("references"))
                if isinstance(ref, dict) and ref.get("url")
            ],
        ],
        25,
    )
    title = (
        "Runtime validated Bootstrap XSS CVE exposure"
        if runtime_exploit_validated
        else "Contextual Bootstrap XSS CVE exposure"
    )
    return {
        "template-id": "cve-runtime-bootstrap-xss-context",
        "templateID": "cve-runtime-bootstrap-xss-context",
        "host": target,
        "matched": matched_at,
        "matched-at": matched_at,
        "matcher-name": "bootstrap-xss-contextual-runtime-probe",
        "extracted-results": [package_label, *cve_ids],
        "info": {
            "name": f"{title}: {package_label}",
            "description": (
                f"{package_label} is loaded by the live target and the runtime contains Bootstrap "
                "tooltip/popover HTML sinks associated with the observed CVE(s). "
                + (
                    "A benign marker was reflected into an unsafe Bootstrap context, so exploitability is runtime validated."
                    if runtime_exploit_validated
                    else "No external PoC was executed; this is a contextual runtime exposure requiring manual confirmation of attacker-controlled input reachability."
                )
            ),
            "severity": severity,
            "remediation": (
                "Upgrade Bootstrap to a fixed version, disable HTML rendering for tooltip/popover content, "
                "keep sanitization enabled, and ensure user-controlled values cannot reach title/data-content sinks."
            ),
            "reference": references,
            "cve": cve_ids,
            "classification": {"cve-id": cve_ids},
            "tags": ["cve", "runtime-context", "bootstrap", "xss", "agentic"],
        },
        "evidence": {
            "cveId": primary_cve,
            "cveIds": cve_ids,
            "packageName": "bootstrap",
            "package": package_label,
            "runtimeProbeType": "bootstrap_xss_contextual_probe",
            "runtimeExploitValidated": runtime_exploit_validated,
            "runtimeContextValidated": True,
            "confidence": context.get("confidence"),
            "target": target,
            "matchedContent": _format_bootstrap_context_content(context, package_label),
            "request": _stringify_evidence(request, 3000),
            "response": _stringify_evidence(response, 6000),
            "bootstrapScripts": context.get("bootstrapScripts", []),
            "pageSignals": context.get("pageSignals", []),
            "scriptSignals": context.get("scriptSignals", []),
            "reflectionProofs": context.get("reflectionProofs", []),
            "publicExploitIntel": {cve_id: public_exploit_intel.get(cve_id, {}) for cve_id in cve_ids},
            "publicExploitLookup": any(public_exploit_intel.get(cve_id) for cve_id in cve_ids),
            "externalExploitLookup": False,
            "exploitCodeDownloaded": False,
        },
    }


def _detect_angularjs_runtime_context(
    *,
    target: str,
    cve_ids: List[str],
    cve_records: Dict[str, Dict[str, Any]],
    pages: List[Dict[str, Any]],
    scripts: List[Dict[str, Any]],
    reflection_proofs: List[Dict[str, Any]],
) -> Dict[str, Any]:
    page_signals: List[Dict[str, Any]] = []
    script_signals: List[Dict[str, Any]] = []
    angular_scripts: List[Dict[str, Any]] = []

    for page in pages:
        html = page.get("text") or ""
        page_url = page.get("url") or page.get("requestedUrl") or target
        page_signals.extend(_angular_html_signals(html, page_url))

    for script in scripts:
        text = script.get("text") or ""
        script_url = script.get("url") or script.get("requestedUrl") or ""
        if _script_looks_like_angularjs(text, script_url):
            angular_scripts.append(
                {
                    "url": script_url,
                    "version": _detect_angularjs_version(text, script_url),
                    "status": script.get("status"),
                }
            )
        script_signals.extend(_angular_js_signals(text, script_url))

    reflected_angular_context = [
        proof
        for proof in reflection_proofs
        if proof.get("reflected") and proof.get("angularContext")
    ]
    strong_signals = [
        signal
        for signal in page_signals + script_signals
        if _is_strong_angularjs_signal(signal)
    ]
    loaded_vulnerable_package = bool(angular_scripts) or any(
        _record_has_angularjs_package(cve_records.get(cve_id, {})) for cve_id in cve_ids
    )
    finding_candidate = loaded_vulnerable_package and (bool(strong_signals) or bool(reflected_angular_context))
    runtime_exploit_validated = any(bool(proof.get("runtimeExploitValidated")) for proof in reflected_angular_context)

    confidence = 0
    if loaded_vulnerable_package:
        confidence += 30
    if strong_signals:
        confidence += 35
    if reflected_angular_context:
        confidence += 20
    if page_signals or script_signals:
        confidence += 10
    confidence = min(confidence, 95)

    return {
        "probe": "angularjs-runtime-context",
        "target": target,
        "cves": cve_ids,
        "status": "finding_candidate" if finding_candidate else "no_runtime_context",
        "findingCandidate": finding_candidate,
        "loadedVulnerablePackage": loaded_vulnerable_package,
        "runtimeExploitValidated": runtime_exploit_validated,
        "runtimeContextValidated": bool(finding_candidate),
        "confidence": confidence,
        "pagesFetched": len(pages),
        "scriptsFetched": len(scripts),
        "angularScripts": angular_scripts[:10],
        "pageSignals": page_signals[:25],
        "scriptSignals": script_signals[:25],
        "reflectionProofs": reflection_proofs[:12],
        "strongSignals": reflected_angular_context[:5] or strong_signals[:5],
    }


def _angular_html_signals(html: str, page_url: str) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []
    for tag in re.findall(r"<[^>]+\b(?:ng-|data-ng-|x-ng-|ng:)[^>]*>", html, re.I | re.S):
        attr_names = [name.lower() for name in re.findall(r"\b((?:data-|x-)?ng[-:\w]+)\s*=", tag, re.I)]
        strong_attrs = [
            name
            for name in attr_names
            if any(token in name for token in ("bind-html", "include", "init", "srcdoc"))
        ]
        signals.append(
            {
                "source": "html",
                "url": page_url,
                "component": "angular-directive",
                "directives": attr_names[:12],
                "trustedHtmlSink": any("bind-html" in name for name in attr_names),
                "templateInclude": any("include" in name for name in attr_names),
                "inlineExpression": any("init" in name for name in attr_names),
                "strong": bool(strong_attrs),
                "snippet": _clip(tag, 500),
            }
        )

    interpolation_matches = re.findall(r"{{.{0,160}?}}", html, re.S)
    if interpolation_matches:
        signals.append(
            {
                "source": "html",
                "url": page_url,
                "component": "angular-interpolation",
                "interpolationCount": min(len(interpolation_matches), 50),
                "strong": False,
                "snippet": _clip(" ".join(interpolation_matches[:4]), 500),
            }
        )
    return signals


def _angular_js_signals(text: str, script_url: str) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []
    sample = text or ""
    patterns = [
        ("sce-trust-html", r"\$sce\.trustAsHtml\s*\("),
        ("compile-service", r"\$compile\s*\("),
        ("bind-html-template", r"ng-bind-html|data-ng-bind-html"),
        ("template-url", r"\btemplateUrl\s*:"),
        ("sanitize-provider", r"\$sanitizeProvider|\$sceProvider"),
    ]
    for component, pattern in patterns:
        match = re.search(pattern, sample, re.I)
        if not match:
            continue
        signals.append(
            {
                "source": "javascript",
                "url": script_url,
                "component": component,
                "trustedHtmlSink": component in {"sce-trust-html", "bind-html-template"},
                "compileSink": component == "compile-service",
                "templateInclude": component == "template-url",
                "strong": component in {"sce-trust-html", "compile-service", "bind-html-template"},
                "snippet": _clip(_excerpt_around(sample, match.group(0), 800), 800),
            }
        )
    return signals


def _is_strong_angularjs_signal(signal: Dict[str, Any]) -> bool:
    if not isinstance(signal, dict):
        return False
    if signal.get("strong"):
        return True
    return bool(signal.get("trustedHtmlSink") or signal.get("compileSink") or signal.get("templateInclude"))


def _normalize_angularjs_context_finding(
    *,
    target: str,
    cve_ids: List[str],
    cve_records: Dict[str, Dict[str, Any]],
    context: Dict[str, Any],
    public_exploit_intel: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    runtime_exploit_validated = bool(context.get("runtimeExploitValidated"))
    primary_cve = cve_ids[0] if cve_ids else "CVE-UNKNOWN"
    package_label = _package_label_for_cves(cve_ids, cve_records) or "angularjs"
    strong_signal = (context.get("strongSignals") or [{}])[0]
    matched_at = (
        strong_signal.get("url")
        or (context.get("angularScripts") or [{}])[0].get("url")
        or target
    )
    severity = "high" if runtime_exploit_validated else "medium"
    request = strong_signal.get("request") or _request_line(str(matched_at))
    response = (
        strong_signal.get("responseExcerpt")
        or strong_signal.get("snippet")
        or _format_angularjs_context_content(context, package_label)
    )
    references = dedupe_keep_order(
        [
            *[
                ref
                for cve_id in cve_ids
                for ref in _record_references(cve_records.get(cve_id, {}))
            ],
            *[
                ref.get("url")
                for cve_id in cve_ids
                for ref in _coerce_list((public_exploit_intel.get(cve_id, {}) or {}).get("references"))
                if isinstance(ref, dict) and ref.get("url")
            ],
        ],
        25,
    )
    title = (
        "Runtime validated AngularJS CVE exposure"
        if runtime_exploit_validated
        else "Contextual AngularJS CVE exposure"
    )
    return {
        "template-id": "cve-runtime-angularjs-context",
        "templateID": "cve-runtime-angularjs-context",
        "host": target,
        "matched": matched_at,
        "matched-at": matched_at,
        "matcher-name": "angularjs-contextual-runtime-probe",
        "extracted-results": [package_label, *cve_ids],
        "info": {
            "name": f"{title}: {package_label}",
            "description": (
                f"{package_label} is loaded by the live target and the runtime contains AngularJS "
                "directives or JavaScript sinks associated with expression/template/HTML injection risk. "
                + (
                    "A benign runtime probe validated exploitability."
                    if runtime_exploit_validated
                    else "No external PoC was executed; this is contextual runtime evidence that should be manually confirmed for attacker-controlled input reachability."
                )
            ),
            "severity": severity,
            "remediation": (
                "Upgrade AngularJS to a maintained/fixed version, remove unsafe $compile/$sce.trustAsHtml flows, "
                "avoid compiling attacker-controlled templates, and validate all reflected inputs."
            ),
            "reference": references,
            "cve": cve_ids,
            "classification": {"cve-id": cve_ids},
            "tags": ["cve", "runtime-context", "angularjs", "xss", "template-injection", "agentic"],
        },
        "evidence": {
            "cveId": primary_cve,
            "cveIds": cve_ids,
            "packageName": "angularjs",
            "package": package_label,
            "runtimeProbeType": "angularjs_contextual_probe",
            "runtimeExploitValidated": runtime_exploit_validated,
            "runtimeContextValidated": True,
            "confidence": context.get("confidence"),
            "target": target,
            "matchedContent": _format_angularjs_context_content(context, package_label),
            "request": _stringify_evidence(request, 3000),
            "response": _stringify_evidence(response, 6000),
            "angularScripts": context.get("angularScripts", []),
            "pageSignals": context.get("pageSignals", []),
            "scriptSignals": context.get("scriptSignals", []),
            "reflectionProofs": context.get("reflectionProofs", []),
            "publicExploitIntel": {cve_id: public_exploit_intel.get(cve_id, {}) for cve_id in cve_ids},
            "publicExploitLookup": any(public_exploit_intel.get(cve_id) for cve_id in cve_ids),
            "externalExploitLookup": False,
            "exploitCodeDownloaded": False,
        },
    }


def _detect_dompurify_runtime_context(
    *,
    target: str,
    cve_ids: List[str],
    cve_records: Dict[str, Dict[str, Any]],
    pages: List[Dict[str, Any]],
    scripts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    page_signals: List[Dict[str, Any]] = []
    script_signals: List[Dict[str, Any]] = []
    dompurify_scripts: List[Dict[str, Any]] = []

    for page in pages:
        html = page.get("text") or ""
        page_url = page.get("url") or page.get("requestedUrl") or target
        page_signals.extend(_dompurify_html_signals(html, page_url))

    for script in scripts:
        text = script.get("text") or ""
        script_url = script.get("url") or script.get("requestedUrl") or ""
        if _script_looks_like_dompurify(text, script_url):
            dompurify_scripts.append(
                {
                    "url": script_url,
                    "version": _detect_dompurify_version(text, script_url),
                    "status": script.get("status"),
                    "request": _request_line(script_url),
                    "responseExcerpt": _excerpt_around(text, "DOMPurify", 2200),
                }
            )
        script_signals.extend(_dompurify_js_signals(text, script_url))

    strong_signals = [
        signal
        for signal in page_signals + script_signals
        if _is_strong_dompurify_signal(signal)
    ]
    loaded_vulnerable_package = bool(dompurify_scripts) or any(
        _record_has_dompurify_package(cve_records.get(cve_id, {})) for cve_id in cve_ids
    )
    finding_candidate = loaded_vulnerable_package and bool(strong_signals)

    confidence = 0
    if loaded_vulnerable_package:
        confidence += 30
    if dompurify_scripts:
        confidence += 15
    if strong_signals:
        confidence += 35
    if page_signals or script_signals:
        confidence += 10
    confidence = min(confidence, 90)

    return {
        "probe": "dompurify-runtime-context",
        "target": target,
        "cves": cve_ids,
        "status": "finding_candidate" if finding_candidate else "no_runtime_context",
        "findingCandidate": finding_candidate,
        "loadedVulnerablePackage": loaded_vulnerable_package,
        "runtimeExploitValidated": False,
        "runtimeContextValidated": bool(finding_candidate),
        "confidence": confidence,
        "pagesFetched": len(pages),
        "scriptsFetched": len(scripts),
        "dompurifyScripts": dompurify_scripts[:10],
        "pageSignals": page_signals[:25],
        "scriptSignals": script_signals[:35],
        "strongSignals": strong_signals[:8],
    }


def _dompurify_html_signals(html: str, page_url: str) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []
    for match in re.finditer(
        r"<(?:textarea|input|div|section|article|form)[^>]*(?:markdown|html|contenteditable|wysiwyg|editor|description|comment|body)[^>]*>",
        html or "",
        re.I | re.S,
    ):
        tag = match.group(0)
        signals.append(
            {
                "source": "html",
                "url": page_url,
                "component": "html-input-surface",
                "userControlledHtmlSurface": True,
                "strong": False,
                "snippet": _clip(tag, 600),
            }
        )
    if re.search(r"\b(?:swagger-ui|redoc|markdown)\b", html or "", re.I):
        signals.append(
            {
                "source": "html",
                "url": page_url,
                "component": "documentation-markdown-surface",
                "userControlledHtmlSurface": False,
                "strong": False,
                "snippet": _clip(_excerpt_around(html, "swagger", 800) or _excerpt_around(html, "markdown", 800), 800),
            }
        )
    return signals


def _dompurify_js_signals(text: str, script_url: str) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []
    sample = text or ""
    sample_lower = sample[:500_000].lower()
    dompurify_related = "dompurify" in sample_lower or "dompurify" in (script_url or "").lower()
    sanitizer_related = dompurify_related or bool(
        re.search(r"\b[A-Za-z_$][\w$]*(?:\(\))?\.sanitize\s*\(", sample, re.I)
    )
    patterns = [
        ("sanitizer-call", r"(?:DOMPurify|dompurify)\.sanitize\s*\(|\b[A-Za-z_$][\w$]*(?:\(\))?\.sanitize\s*\(|\bsanitizeHTML\s*\("),
        ("dompurify-factory", r"\bcreateDOMPurify\s*\(|\bDOMPurify\s*="),
        ("trusted-types", r"\bRETURN_TRUSTED_TYPE\b|\btrustedTypes\b"),
        ("custom-elements", r"\bCUSTOM_ELEMENT_HANDLING\b|\bADD_TAGS\b|\bADD_ATTR\b"),
        ("html-sink", r"\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML|insertAdjacentHTML)\b"),
        ("markdown-render", r"\b(?:marked|markdown|swagger-ui|redoc)\b"),
    ]
    for component, pattern in patterns:
        match = re.search(pattern, sample, re.I)
        if not match:
            continue
        signals.append(
            {
                "source": "javascript",
                "url": script_url,
                "component": component,
                "sanitizerCall": component == "sanitizer-call",
                "customSanitizerConfig": component in {"trusted-types", "custom-elements"},
                "htmlSink": component == "html-sink",
                "documentationRenderer": component == "markdown-render",
                "strong": (
                    component == "sanitizer-call"
                    or (component in {"trusted-types", "custom-elements"} and dompurify_related)
                    or (component == "html-sink" and sanitizer_related)
                ),
                "request": _request_line(script_url),
                "responseExcerpt": _excerpt_around(sample, match.group(0), 1800),
                "snippet": _clip(_excerpt_around(sample, match.group(0), 1200), 1200),
            }
        )
    return signals


def _is_strong_dompurify_signal(signal: Dict[str, Any]) -> bool:
    if not isinstance(signal, dict):
        return False
    if signal.get("strong"):
        return True
    return bool(signal.get("sanitizerCall") or signal.get("customSanitizerConfig") or signal.get("htmlSink"))


def _normalize_dompurify_context_finding(
    *,
    target: str,
    cve_ids: List[str],
    cve_records: Dict[str, Dict[str, Any]],
    context: Dict[str, Any],
    public_exploit_intel: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    primary_cve = cve_ids[0] if cve_ids else "CVE-UNKNOWN"
    package_label = _package_label_for_cves(cve_ids, cve_records) or "dompurify"
    strong_signal = (context.get("strongSignals") or [{}])[0]
    matched_at = (
        strong_signal.get("url")
        or (context.get("dompurifyScripts") or [{}])[0].get("url")
        or target
    )
    request = strong_signal.get("request") or (context.get("dompurifyScripts") or [{}])[0].get("request") or _request_line(str(matched_at))
    dompurify_excerpt = (context.get("dompurifyScripts") or [{}])[0].get("responseExcerpt")
    signal_excerpt = strong_signal.get("responseExcerpt") or strong_signal.get("snippet")
    response = _join_evidence_sections(
        [
            ("DOMPurify package/runtime excerpt", dompurify_excerpt),
            ("DOMPurify sink/config excerpt", signal_excerpt),
        ],
        fallback=_format_dompurify_context_content(context, package_label),
    )
    references = dedupe_keep_order(
        [
            *[
                ref
                for cve_id in cve_ids
                for ref in _record_references(cve_records.get(cve_id, {}))
            ],
            *[
                ref.get("url")
                for cve_id in cve_ids
                for ref in _coerce_list((public_exploit_intel.get(cve_id, {}) or {}).get("references"))
                if isinstance(ref, dict) and ref.get("url")
            ],
        ],
        30,
    )
    return {
        "template-id": "cve-runtime-dompurify-context",
        "templateID": "cve-runtime-dompurify-context",
        "host": target,
        "matched": matched_at,
        "matched-at": matched_at,
        "matcher-name": "dompurify-contextual-runtime-probe",
        "extracted-results": [package_label, *cve_ids],
        "info": {
            "name": f"Contextual DOMPurify CVE exposure: {package_label}",
            "description": (
                f"{package_label} is loaded by the live target and the runtime contains DOMPurify "
                "sanitize/configuration or HTML sink signals associated with the observed CVE(s). "
                "No external PoC was executed; this is contextual runtime evidence for analyst triage."
            ),
            "severity": "medium",
            "remediation": (
                "Upgrade DOMPurify to a fixed version, review custom sanitizer allowlists and HTML sinks, "
                "and verify attacker-controlled HTML/markdown cannot reach vulnerable sanitize paths."
            ),
            "reference": references,
            "cve": cve_ids,
            "classification": {"cve-id": cve_ids},
            "tags": ["cve", "runtime-context", "dompurify", "xss", "sanitize", "agentic"],
        },
        "evidence": {
            "cveId": primary_cve,
            "cveIds": cve_ids,
            "packageName": "dompurify",
            "package": package_label,
            "runtimeProbeType": "dompurify_contextual_probe",
            "runtimeExploitValidated": False,
            "runtimeContextValidated": True,
            "confidence": context.get("confidence"),
            "target": target,
            "matchedContent": _format_dompurify_context_content(context, package_label),
            "request": _stringify_evidence(request, 4000),
            "response": _stringify_evidence(response, 7000),
            "dompurifyScripts": context.get("dompurifyScripts", []),
            "pageSignals": context.get("pageSignals", []),
            "scriptSignals": context.get("scriptSignals", []),
            "publicExploitIntel": {cve_id: public_exploit_intel.get(cve_id, {}) for cve_id in cve_ids},
            "publicExploitLookup": any(public_exploit_intel.get(cve_id) for cve_id in cve_ids),
            "externalExploitLookup": False,
            "exploitCodeDownloaded": False,
        },
    }


def _page_candidate_urls(
    target: str,
    candidate_targets: List[str],
    parameters: Dict[str, Any],
    same_origin_only: bool,
) -> List[str]:
    urls = [target]
    urls.extend(candidate_targets)
    urls.extend(_coerce_string_list(parameters.get("urls")))
    output: List[str] = []
    for value in urls:
        url = normalize_url(urljoin(target, value))
        if not url or _looks_like_static_asset_url(url):
            continue
        if same_origin_only and not same_origin(target, url):
            continue
        output.append(url)
    return dedupe_keep_order(output, BOOTSTRAP_CONTEXT_PAGE_LIMIT * 2)


def _script_candidate_urls(
    target: str,
    scripts: List[str],
    cve_ids: List[str],
    cve_records: Dict[str, Dict[str, Any]],
    same_origin_only: bool,
) -> List[str]:
    urls = list(scripts)
    for cve_id in cve_ids:
        record = cve_records.get(cve_id, {})
        urls.extend(record.get("scripts") or [])
        for package in _coerce_list(record.get("packages")):
            if isinstance(package, dict) and package.get("scriptUrl"):
                urls.append(str(package.get("scriptUrl")))
    output: List[str] = []
    for value in urls:
        url = normalize_url(urljoin(target, value))
        if not url or not _looks_like_javascript_url(url):
            continue
        if same_origin_only and not same_origin(target, url):
            continue
        output.append(url)
    return dedupe_keep_order(output, BOOTSTRAP_CONTEXT_SCRIPT_LIMIT * 2)


def _is_bootstrap_xss_cve(cve_id: str, record: Dict[str, Any]) -> bool:
    if cve_id.upper() in BOOTSTRAP_XSS_CVES:
        return True
    blob = json.dumps(record or {}, default=str).lower()
    return "bootstrap" in blob and ("xss" in blob or "cross-site scripting" in blob)


def _record_has_bootstrap_package(record: Dict[str, Any]) -> bool:
    for package in _coerce_list(record.get("packages")):
        if isinstance(package, dict) and str(package.get("name") or "").lower() == "bootstrap":
            return True
    blob = json.dumps(record or {}, default=str).lower()
    return "bootstrap" in blob


def _script_looks_like_bootstrap(text: str, script_url: str) -> bool:
    url = (script_url or "").lower()
    sample = (text or "")[:300_000].lower()
    return (
        "bootstrap" in url
        or "bootstrap's javascript" in sample
        or "bootstrap v" in sample
        or "jquery.fn.tooltip" in sample
        or "jquery.fn.popover" in sample
        or ".fn.tooltip" in sample and ".fn.popover" in sample
    )


def _detect_bootstrap_version(text: str, script_url: str) -> Optional[str]:
    for haystack in (script_url or "", (text or "")[:120_000]):
        for pattern in (
            r"bootstrap[-.]([0-9]+(?:\.[0-9]+){1,3})(?:\.min)?\.js",
            r"bootstrap\s+v([0-9]+(?:\.[0-9]+){1,3})",
            r"Bootstrap(?:'s JavaScript)?\s+v([0-9]+(?:\.[0-9]+){1,3})",
        ):
            match = re.search(pattern, haystack, re.I)
            if match:
                return match.group(1)
    return None


def _is_angularjs_runtime_cve(cve_id: str, record: Dict[str, Any]) -> bool:
    if cve_id.upper() in ANGULARJS_CONTEXT_CVES:
        return True
    blob = json.dumps(record or {}, default=str).lower()
    return "angular" in blob and any(
        token in blob
        for token in (
            "xss",
            "cross-site scripting",
            "sandbox",
            "expression",
            "template",
            "prototype pollution",
            "sanitize",
        )
    )


def _record_has_angularjs_package(record: Dict[str, Any]) -> bool:
    for package in _coerce_list(record.get("packages")):
        if not isinstance(package, dict):
            continue
        name = str(package.get("name") or "").lower()
        if name in {"angular", "angularjs", "angular.js"} or "angular" in name:
            return True
    blob = json.dumps(record or {}, default=str).lower()
    return "angular" in blob


def _script_looks_like_angularjs(text: str, script_url: str) -> bool:
    url = (script_url or "").lower()
    sample = (text or "")[:400_000].lower()
    return (
        "angular" in url
        or "angularjs v" in sample
        or "angular.module" in sample
        or "angular.version" in sample
        or "ng-app" in sample
        or "$compile" in sample
    )


def _detect_angularjs_version(text: str, script_url: str) -> Optional[str]:
    for haystack in (script_url or "", (text or "")[:180_000]):
        for pattern in (
            r"angular(?:\.min)?[-.]([0-9]+(?:\.[0-9]+){1,3})(?:\.min)?\.js",
            r"AngularJS\s+v([0-9]+(?:\.[0-9]+){1,3})",
            r"angular\.version\s*=\s*\{[^}]*full\s*:\s*['\"]([0-9]+(?:\.[0-9]+){1,3})['\"]",
            r"full\s*:\s*['\"]([0-9]+(?:\.[0-9]+){1,3})['\"][^}]{0,160}major\s*:",
        ):
            match = re.search(pattern, haystack, re.I | re.S)
            if match:
                return match.group(1)
    return None


def _is_dompurify_runtime_cve(cve_id: str, record: Dict[str, Any]) -> bool:
    if cve_id.upper() in DOMPURIFY_CONTEXT_CVES:
        return True
    blob = json.dumps(record or {}, default=str).lower()
    return "dompurify" in blob and any(
        token in blob
        for token in (
            "xss",
            "cross-site scripting",
            "sanitize",
            "sanitizer",
            "mxc",
            "html",
            "prototype pollution",
        )
    )


def _record_has_dompurify_package(record: Dict[str, Any]) -> bool:
    for package in _coerce_list(record.get("packages")):
        if not isinstance(package, dict):
            continue
        name = str(package.get("name") or "").lower()
        if name in {"dompurify", "dom-purify"} or "dompurify" in name:
            return True
    blob = json.dumps(record or {}, default=str).lower()
    return "dompurify" in blob


def _script_looks_like_dompurify(text: str, script_url: str) -> bool:
    url = (script_url or "").lower()
    sample = (text or "")[:500_000].lower()
    return (
        "dompurify" in url
        or "dompurify" in sample
        or "dompurify.sanitize" in sample
        or "createDOMPurify".lower() in sample
        or "purify.sanitize" in sample
    )


def _detect_dompurify_version(text: str, script_url: str) -> Optional[str]:
    for haystack in (script_url or "", (text or "")[:220_000]):
        for pattern in (
            r"dompurify(?:\.min)?[-.]([0-9]+(?:\.[0-9]+){1,3})(?:\.min)?\.js",
            r"DOMPurify\s+([0-9]+(?:\.[0-9]+){1,3})",
            r"version\s*[:=]\s*['\"]([0-9]+(?:\.[0-9]+){1,3})['\"][^;\n]{0,120}DOMPurify",
            r"DOMPurify[^;\n]{0,120}version\s*[:=]\s*['\"]([0-9]+(?:\.[0-9]+){1,3})['\"]",
        ):
            match = re.search(pattern, haystack, re.I | re.S)
            if match:
                return match.group(1)
    return None


def _url_with_probe_marker(page_url: str, marker: str) -> Optional[str]:
    parsed = urlparse(page_url)
    if not parsed.scheme or not parsed.netloc:
        return None
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if pairs:
        pairs = [(key, marker) for key, _ in pairs[:8]]
    else:
        pairs = [("xasm_cve_probe", marker)]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, urlencode(pairs), parsed.fragment))


def _extract_attr_inline(tag: str, attr: str) -> Optional[str]:
    match = re.search(rf"\b{re.escape(attr)}\s*=\s*(['\"])(.*?)\1", tag, re.I | re.S)
    if match:
        return match.group(2).strip()
    match = re.search(rf"\b{re.escape(attr)}\s*=\s*([^\s>]+)", tag, re.I | re.S)
    if match:
        return match.group(1).strip()
    return None


def _looks_like_javascript_url(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    return path.endswith(".js") or ".js?" in url.lower()


def _looks_like_static_asset_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map", ".pdf", ".zip"))


def _format_bootstrap_context_content(context: Dict[str, Any], package_label: str) -> str:
    lines = [
        f"Package: {package_label}",
        f"CVEs: {', '.join(_coerce_string_list(context.get('cves')))}",
        f"Loaded vulnerable package: {context.get('loadedVulnerablePackage')}",
        f"Runtime context validated: {context.get('runtimeContextValidated')}",
        f"Runtime exploit validated: {context.get('runtimeExploitValidated')}",
        f"Confidence: {context.get('confidence')}",
    ]
    for signal in _coerce_list(context.get("strongSignals"))[:5]:
        if isinstance(signal, dict):
            lines.append(
                "Signal: "
                + ", ".join(
                    f"{key}={signal.get(key)}"
                    for key in ("source", "component", "url", "unsafeHtml", "sanitizeDisabled", "untrustedContentSink", "reflected")
                    if key in signal
                )
            )
    return "\n".join(line for line in lines if line)


def _format_angularjs_context_content(context: Dict[str, Any], package_label: str) -> str:
    lines = [
        f"Package: {package_label}",
        f"CVEs: {', '.join(_coerce_string_list(context.get('cves')))}",
        f"Loaded vulnerable package: {context.get('loadedVulnerablePackage')}",
        f"Runtime context validated: {context.get('runtimeContextValidated')}",
        f"Runtime exploit validated: {context.get('runtimeExploitValidated')}",
        f"Confidence: {context.get('confidence')}",
    ]
    for signal in _coerce_list(context.get("strongSignals"))[:5]:
        if isinstance(signal, dict):
            lines.append(
                "Signal: "
                + ", ".join(
                    f"{key}={signal.get(key)}"
                    for key in (
                        "source",
                        "component",
                        "url",
                        "trustedHtmlSink",
                        "compileSink",
                        "templateInclude",
                        "reflected",
                    )
                    if key in signal
                )
            )
    return "\n".join(line for line in lines if line)


def _format_dompurify_context_content(context: Dict[str, Any], package_label: str) -> str:
    lines = [
        f"Package: {package_label}",
        f"CVEs: {', '.join(_coerce_string_list(context.get('cves')))}",
        f"Loaded vulnerable package: {context.get('loadedVulnerablePackage')}",
        f"Runtime context validated: {context.get('runtimeContextValidated')}",
        f"Runtime exploit validated: {context.get('runtimeExploitValidated')}",
        f"Confidence: {context.get('confidence')}",
    ]
    for signal in _coerce_list(context.get("strongSignals"))[:6]:
        if isinstance(signal, dict):
            lines.append(
                "Signal: "
                + ", ".join(
                    f"{key}={signal.get(key)}"
                    for key in (
                        "source",
                        "component",
                        "url",
                        "sanitizerCall",
                        "customSanitizerConfig",
                        "htmlSink",
                        "documentationRenderer",
                    )
                    if key in signal
                )
            )
    return "\n".join(line for line in lines if line)


def _join_evidence_sections(sections: Iterable[Tuple[str, Any]], *, fallback: str = "") -> str:
    rendered: List[str] = []
    seen = set()
    for title, value in sections:
        text = _clip(value, 2500)
        if not text:
            continue
        key = text[:300]
        if key in seen:
            continue
        seen.add(key)
        rendered.append(f"## {title}\n{text}")
    return "\n\n".join(rendered) or fallback


def _package_label_for_cves(cve_ids: List[str], cve_records: Dict[str, Dict[str, Any]]) -> str:
    for cve_id in cve_ids:
        for package in _coerce_list(cve_records.get(cve_id, {}).get("packages")):
            if not isinstance(package, dict):
                continue
            name = package.get("name")
            version = package.get("version")
            if name and version:
                return f"{name}@{version}"
            if name:
                return str(name)
    return ""


def _record_references(record: Dict[str, Any]) -> List[str]:
    refs = list(record.get("references") or [])
    for advisory in _coerce_list(record.get("advisories")):
        if isinstance(advisory, dict):
            refs.extend(_coerce_string_list(advisory.get("references")))
    return dedupe_keep_order(refs, 50)


def _excerpt_around(text: str, needle: str, limit: int) -> str:
    if not text:
        return ""
    index = text.find(needle) if needle else -1
    if index < 0:
        return _clip(text, limit)
    half = max(100, limit // 2)
    return _clip(text[max(0, index - half): index + half], limit)


def _clip(value: Any, limit: int) -> str:
    text = str(value or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _extract_cves(values: Iterable[Any]) -> List[str]:
    cves: List[str] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            haystack = value
        else:
            try:
                haystack = json.dumps(value, default=str)
            except Exception:
                haystack = str(value)
        cves.extend(re.findall(r"CVE-\d{4}-\d{4,}", haystack, flags=re.I))
    return dedupe_keep_order([cve.upper() for cve in cves], 200)


def _compact_package(library: Dict[str, Any]) -> Dict[str, Any]:
    name = library.get("name") or library.get("package") or library.get("component")
    version = library.get("version") or library.get("detectedVersion")
    if not name and not version:
        return {}
    return {
        **({"name": str(name)} if name else {}),
        **({"version": str(version)} if version else {}),
        **({"scriptUrl": str(library.get("scriptUrl"))} if library.get("scriptUrl") else {}),
        **({"source": str(library.get("source"))} if library.get("source") else {}),
    }


def _compact_advisory(advisory: Dict[str, Any]) -> Dict[str, Any]:
    return {
        **({"summary": str(advisory.get("summary"))} if advisory.get("summary") else {}),
        **({"severity": str(advisory.get("severity"))} if advisory.get("severity") else {}),
        **({"cveIds": _coerce_string_list(advisory.get("cveIds") or advisory.get("cves"))} if advisory.get("cveIds") or advisory.get("cves") else {}),
        **({"references": _coerce_string_list(advisory.get("references"))} if advisory.get("references") else {}),
        **({"below": str(advisory.get("below"))} if advisory.get("below") else {}),
        **({"atOrAbove": str(advisory.get("atOrAbove"))} if advisory.get("atOrAbove") else {}),
    }


def _package_from_title(title: str) -> Tuple[Optional[str], Optional[str]]:
    match = re.search(r"dependency:\s*([A-Za-z0-9_.@/-]+)@([0-9A-Za-z_.:+~-]+)", title or "", re.I)
    if match:
        return match.group(1), match.group(2)
    match = re.search(r"\b([A-Za-z0-9_.@/-]+)@([0-9]+\.[0-9][0-9A-Za-z_.:+~-]*)", title or "")
    if match:
        return match.group(1), match.group(2)
    return None, None


def _dedupe_dicts(values: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    output: List[Dict[str, Any]] = []
    for value in values:
        if not value:
            continue
        key = json.dumps(value, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        output.append(value)
    return output


def _format_matched_content(cve_id: str, record: Dict[str, Any], raw: Dict[str, Any]) -> str:
    packages = [
        f"{pkg.get('name')}@{pkg.get('version')}"
        for pkg in record.get("packages", [])
        if isinstance(pkg, dict) and (pkg.get("name") or pkg.get("version"))
    ]
    extracted = _coerce_string_list(raw.get("extracted-results"))
    lines = [
        f"CVE: {cve_id}",
        *([f"Packages: {', '.join(packages[:8])}"] if packages else []),
        *([f"Extracted: {', '.join(extracted[:8])}"] if extracted else []),
        f"Nuclei template: {raw.get('template-id') or raw.get('templateID') or raw.get('template') or 'unknown'}",
    ]
    return "\n".join(lines)


def _request_line(url: str) -> str:
    parsed = urlparse(str(url or ""))
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return f"GET {path} HTTP/1.1\nHost: {parsed.netloc}\nUser-Agent: xASM-AgenticExplorer/1.0"


def _origin_root(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    if not parsed.scheme or not parsed.netloc:
        return normalize_url(url)
    return f"{parsed.scheme}://{parsed.netloc}/"


def _safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]+", "-", value).strip("-")[:160] or "unknown"


def _stringify_evidence(value: Any, limit: int) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, indent=2, default=str)
        except Exception:
            text = str(value)
    return text[:limit]


def _coerce_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


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
            pass
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)] if value else []


def get_tool():
    return CveRuntimeProbeTool()
